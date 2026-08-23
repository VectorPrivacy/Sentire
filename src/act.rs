//! Choosing a rung and carrying it out. The decision lives in
//! [`crate::adjudicate`] and [`crate::ladder`]; this is the one place that
//! turns it into something that happens.

use std::sync::{Arc, Mutex};

use vector_sdk::policy::Verdict;
use vector_sdk::{Community, VectorBot};

use crate::adjudicate::{self, Sentence};
use crate::config::Response;
use crate::policy::{CommunityPolicy, Powers};
use crate::store::Store;
use crate::{enforce_lock, now_ms, short, Watches};
use crate::ladder;

/// Carry out (or rehearse) one sentence.
///
/// The decision is not made here: [`select_rung`] picks the rung and
/// [`adjudicate`] rules on it. This gathers the facts, asks, and obeys — which
/// is what lets both be tested without a network, and what stops the next lane
/// reaching an action without passing them.
pub(crate) async fn enforce(
    bot: &VectorBot,
    community: &Community,
    ctx: &Ctx,
    store: &Arc<Store>,
    wires: &Watches,
    pass: &Mutex<usize>,
    v: &Verdict,
    strikes: &[ladder::Strike],
) -> vector_sdk::Result<Outcome> {
    // One sentence at a time per community. The SDK spawns a task per inbound
    // message, so without this the ceiling reads are guesses another task has
    // already invalidated.
    let gate = enforce_lock(wires, community.id());
    let _serial = gate.lock().await;
    // After the gate: waiting can span minutes, and the caller's instant would
    // measure the hourly window from the wrong moment.
    let now = now_ms();
    let id = short(community.id());
    let who = short(&v.npub);
    let why = v.why();

    let Some(response) = select_rung(&ctx.policy, ctx.powers, store, community.id(), &v.npub, strikes, now)
        .map_err(vector_sdk::Error::Other)?
    else {
        return Ok(Outcome::AlreadyAnswered);
    };

    let facts = adjudicate::Facts {
        shield: &v.shield,
        acted_this_hour: store.actions_last_hour(community.id(), now).map_err(vector_sdk::Error::Other)?,
        // Distinct PEOPLE, and not this one: the ladder climbs, so a member
        // already inside the bound must still be escalatable.
        subjects_this_hour: store
            .subjects_actioned_last_hour(community.id(), now, &v.npub)
            .map_err(vector_sdk::Error::Other)?,
        acted_this_pass: *pass.lock().unwrap_or_else(|e| e.into_inner()),
        roster: ctx.roster,
        is_me: v.npub == ctx.me,
    };

    let armed = match adjudicate::adjudicate(&ctx.policy, ctx.powers, &facts, response) {
        Sentence::Spare { why: reason } => {
            println!("[{id}] QUEUED  {who} — {why} ({reason})");
            return Ok(Outcome::Spared);
        }
        Sentence::Powerless { needs } => {
            println!("[{id}] CANNOT  {} {who} — this community grants Sentinel no {needs}", response.name());
            return Ok(Outcome::Powerless);
        }
        Sentence::Held { why: reason } => {
            println!("[{id}] HELD    {who} — {reason} reached; still owed");
            return Ok(Outcome::Held);
        }
        Sentence::Halt { ceiling, roster } => {
            println!(
                "[{id}] HALT — {ceiling} action(s) is all {}% of {roster} members allows. A human decides from here.",
                ctx.policy.limits.halt_if_over_pct
            );
            return Ok(Outcome::Halted);
        }
        Sentence::Carry { armed, .. } => armed,
    };

    let name = response.name();
    let total = ladder::total(strikes, now, ctx.policy.ladder.decay_half_life_hours);
    println!("[{id}] {} {name} {who} — {total} strike(s) — {why}", if armed { "ENFORCE" } else { "WOULD  " });

    // A rehearsal records nothing. There is one ledger, and arming wipes it —
    // so a dry run leaves no trace to be mistaken for a real answer later.
    if !armed {
        return Ok(Outcome::Acted);
    }

    // Act, THEN log. Logging first recorded a failed ban as a success: it spent
    // the ceiling and marked the member answered forever.
    let outcome = match response {
        Response::Warn => bot.dm(&v.npub).send(&warn_text(&why)).await.map(|_| ()),
        Response::DeleteAndWarn => {
            hide_cited(bot, v, id).await;
            bot.dm(&v.npub).send(&warn_text(&why)).await.map(|_| ())
        }
        Response::Kick => community.member(v.npub.clone()).kick().await,
        Response::Ban => community.member(v.npub.clone()).ban().await,
    };
    if let Err(e) = outcome {
        // Nothing happened, so nothing is recorded: the debt stands and they
        // are reachable again next pass.
        eprintln!("[{id}] {name} {who} FAILED: {e}");
        return Ok(Outcome::Failed);
    }

    store.log_action(community.id(), &v.npub, name, now, total, &why).map_err(vector_sdk::Error::Other)?;
    announce(bot, community, ctx, &format!("{name} {who} — {total} strike(s) — {why}")).await;
    *pass.lock().unwrap_or_else(|e| e.into_inner()) += 1;
    Ok(Outcome::Acted)
}

/// Hide the messages a conviction cited, once each, capped.
///
/// A message already gone is the end state this wanted, not a failure.
async fn hide_cited(bot: &VectorBot, v: &Verdict, id: &str) {
    let mut seen = std::collections::HashSet::new();
    for msg_id in v.findings.iter().flat_map(|f| f.messages.iter()).filter(|m| seen.insert((*m).clone())).take(MAX_HIDES)
    {
        if let Some(m) = bot.message(msg_id).await {
            if let Err(e) = m.hide().await {
                eprintln!("[{id}] hide {}: {e}", short(msg_id));
            }
        }
    }
}

/// A finding Sentinel reached itself, in the shape the ladder and the enforcer
/// already speak.
///
/// Confidence and proven are zero on purpose: the engine did not say this, so
/// nothing about it is replayable by another client.
pub(crate) fn own_verdict(npub: &str, shield: String, reasons: Vec<String>, findings: Vec<vector_sdk::policy::Finding>) -> Verdict {
    Verdict {
        npub: npub.to_string(),
        name: short(npub).to_string(),
        confidence: 0,
        proven: 0,
        band: "alert".into(),
        shield,
        reasons: if reasons.is_empty() { vec!["earlier findings".into()] } else { reasons },
        findings,
        messages: 0,
        tenure_secs: 0,
    }
}

/// One finding, for a lane that judged something the engine never saw.
pub(crate) fn own_finding(rule: &str, detail: &str, message_id: String) -> vector_sdk::policy::Finding {
    vector_sdk::policy::Finding {
        conviction_id: String::new(),
        policy_hash: String::new(),
        rule_id: rule.into(),
        scope: "whole".into(),
        basis: "heuristic".into(),
        severity: "severe".into(),
        stateless: false,
        rung: 0,
        hits: 1,
        weight: 0,
        detail: vec![detail.to_string()],
        messages: vec![message_id],
        citation_count: 1,
    }
}

fn warn_text(why: &str) -> String {
    format!(
        "Sentinel here. A community rule matched your recent messages: {why}. \
         This is a warning; repeated matches escalate. Reply to a moderator if you think this is wrong."
    )
}

/// Best-effort audit line into the operator's mod channel, when one is named.
pub(crate) async fn announce(bot: &VectorBot, community: &Community, ctx: &Ctx, line: &str) {
    let Some(want) = &ctx.mod_channel else { return };
    for ch in community.channels().await {
        if ch.name() == want && ch.is_readable() {
            let _ = bot.channel(ch.id()).send(line).await;
            return;
        }
    }
}

/// One community, as this pass sees it: its own rulebook, its own powers, its
/// own roster. Nothing about judging one community may leak into another.
pub(crate) struct Ctx {
    pub(crate) policy: CommunityPolicy,
    pub(crate) powers: Powers,
    pub(crate) roster: usize,
    pub(crate) me: String,
    pub(crate) mod_channel: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    Acted,
    Spared,
    Held,
    Halted,
    AlreadyAnswered,
    Powerless,
    Failed,
}

/// Which rung to answer with, given everything already on file.
///
/// Extracted so it can be driven against a real store with no network: every
/// regression in six review passes has lived in this glue rather than in the
/// pure rules underneath it, and glue nothing drives is glue nothing checks.
///
/// Each candidate is asked about the `dry` space it would actually be recorded
/// in, and skipped — not stopped at — when this community grants no power to
/// deliver it. Stopping pinned every member below a rung the community had
/// simply withheld.
#[allow(clippy::too_many_arguments)]
pub(crate) fn select_rung(
    policy: &CommunityPolicy,
    powers: Powers,
    store: &Store,
    community: &str,
    npub: &str,
    strikes: &[ladder::Strike],
    now: u64,
) -> Result<Option<Response>, String> {
    let hl = policy.ladder.decay_half_life_hours;
    let total = ladder::total(strikes, now, hl);
    let prior = store.strongest_response(community, npub)?;
    // The ladder climbs per OFFENSE, not per poll. A verdict re-reports every
    // standing conviction forever, so without this one message walks the whole
    // ladder on the clock: warn, delete, kick, ban, four polls apart.
    //
    // The answered total is aged the same way the strikes are, so the gate
    // opens again as the evidence behind it is forgiven rather than sealing
    // the member off for the life of the row.
    let answered = prior.as_ref().map(|p| ladder::decay(p.at_total, now.saturating_sub(p.at_ms), hl)).unwrap_or(0);
    if total <= answered {
        return Ok(None);
    }
    // An answer whose evidence is fully forgiven stops flooring the ladder.
    // Otherwise a kick from March leaves a light offense in October answerable
    // only by a ban — the strikes forgive and the floor never would.
    let floor = prior.as_ref().filter(|_| answered > 0).map(|p| p.response.as_str());
    Ok(ladder::next_step(&policy.ladder, total, floor, |r| powers.can_deliver(r)))
}

/// A member cited across many messages is still one sentence.
const MAX_HIDES: usize = 10;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::store::tests::mem;

    const NOW: u64 = 10_000;

    fn policy_with(arm: &str) -> CommunityPolicy {
        toml::from_str::<Config>(&format!("[arm]\n{arm}")).unwrap().for_community("aa")
    }

    /// One strike per offense; the ladder climbs as the total rises.
    #[test]
    fn the_ladder_climbs_one_rung_per_offense() {
        let store = mem();
        let p = policy_with("warn = true\ndelete = true\nkick = true\nban = true");
        let all = Powers { hide: true, kick: true, ban: true };
        let offenses = |n: u32| (0..n).map(|_| ladder::Strike { worth: 12, at_ms: NOW }).collect::<Vec<_>>();
        let pick = |s: &Store, n: u32| select_rung(&p, all, s, "c", "npub1a", &offenses(n), NOW).unwrap();

        assert_eq!(pick(&store, 1), Some(Response::Warn), "twelve points still starts at a warning");
        store.log_action("c", "npub1a", "warn", NOW, 12, "").unwrap();
        assert_eq!(pick(&store, 2), Some(Response::DeleteAndWarn));
        store.log_action("c", "npub1a", "delete_and_warn", NOW, 24, "").unwrap();
        assert_eq!(pick(&store, 3), Some(Response::Kick));
        store.log_action("c", "npub1a", "kick", NOW, 36, "").unwrap();
        assert_eq!(pick(&store, 4), Some(Response::Ban));
        store.log_action("c", "npub1a", "ban", NOW, 48, "").unwrap();
        assert_eq!(pick(&store, 5), None, "and stops at the top rather than repeating it");
    }

    /// The bug this gate exists for: a verdict re-reports every standing
    /// conviction, so without it one message walked the whole ladder on the
    /// clock — warn, delete, kick, ban, one poll apart, in under ten minutes.
    #[test]
    fn re_reading_the_same_offense_does_not_climb() {
        let store = mem();
        let p = policy_with("warn = true\ndelete = true\nkick = true\nban = true");
        let all = Powers { hide: true, kick: true, ban: true };
        let one_grave = [ladder::Strike { worth: 12, at_ms: NOW }];

        let first = select_rung(&p, all, &store, "c", "npub1a", &one_grave, NOW).unwrap();
        assert_eq!(first, Some(Response::Warn));
        store.log_action("c", "npub1a", "warn", NOW, 12, "").unwrap();

        for poll in 1..=20u64 {
            let later = NOW + poll * 90_000;
            assert_eq!(
                select_rung(&p, all, &store, "c", "npub1a", &one_grave, later).unwrap(),
                None,
                "poll {poll} answered an offense that was already answered"
            );
        }
    }

    /// The floor forgives on the same schedule as the strikes. Without this a
    /// member kicked in March is answerable only by a ban in October, however
    /// light the new offense.
    #[test]
    fn a_forgiven_floor_no_longer_blocks_a_lighter_offense() {
        let store = mem();
        let p = policy_with("warn = true\ndelete = true\nkick = true\nban = true");
        let all = Powers { hide: true, kick: true, ban: true };
        let hl = p.ladder.decay_half_life_hours * 3_600_000;

        store.log_action("c", "npub1a", "kick", NOW, 12, "").unwrap();
        let much_later = NOW + hl * 40;
        let fresh = [ladder::Strike { worth: 4, at_ms: much_later }];

        assert_eq!(
            select_rung(&p, all, &store, "c", "npub1a", &fresh, much_later).unwrap(),
            Some(Response::Warn),
            "a forgiven kick must not make a fresh minor offense unanswerable"
        );
    }

    #[test]
    fn a_withheld_permission_does_not_pin_the_ladder() {
        let store = mem();
        let p = policy_with("warn = true\ndelete = true\nkick = true\nban = true");
        let no_hiding = Powers { hide: false, kick: true, ban: true };
        store.log_action("c", "npub1a", "warn", NOW, 12, "").unwrap();
        let two_grave = [
            ladder::Strike { worth: 12, at_ms: NOW },
            ladder::Strike { worth: 12, at_ms: NOW },
        ];
        assert_eq!(
            select_rung(&p, no_hiding, &store, "c", "npub1a", &two_grave, NOW).unwrap(),
            Some(Response::Kick),
            "delete_and_warn cannot be delivered here, so the ladder goes on"
        );
    }
}
