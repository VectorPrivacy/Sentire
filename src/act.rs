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

    // Permissions only. Whether THIS verdict has anything to hide is not a
    // property of the community, and folding it in here let the ladder walk
    // past delete_and_warn into a kick for any verdict without citations — the
    // debt lane builds exactly those.
    let Some(response) = select_rung(&ctx.policy, |r| ctx.powers.can_deliver(r), store, community.id(), &v.npub, strikes, now)
        .map_err(vector_sdk::Error::Other)?
    else {
        // Three states used to collapse into one wordless return: nothing owed,
        // already answered, and every remaining rung undeliverable here. The
        // last is the one a stuck bot spends its life in.
        // Only when powerlessness is the REASON: with any ladder that has a
        // warn step, `Warn` is always deliverable, so this would otherwise fire
        // for every already-answered member of a permissionless community.
        if !ctx.powers.any() && ladder::decide(&ctx.policy.ladder, ladder::total(strikes, now, ctx.policy.ladder.decay_half_life_hours)).is_some_and(|r| r != Response::Warn) {
            println!("[{id}] CANNOT answer {who} — this community grants Sentinel no moderation powers");
        }
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

    // Act, THEN log. Logging first recorded a failed ban as a success: it spent
    // the ceiling and marked the member answered forever.
    //
    // A rehearsal does everything EXCEPT the act. It writes the same row, so
    // the ladder climbs, the ceilings fill and the operator sees the run they
    // are about to arm — recording nothing meant a dry run could only ever
    // print `WOULD warn`, and arming switched on escalation plus three
    // ceilings at once, into behaviour nobody had watched. Arming wipes the
    // slate, so the rehearsal's rows can never be mistaken for real answers.
    let outcome = if !armed {
        Ok(())
    } else {
        match response {
            Response::Warn => bot.dm(&v.npub).send(&warn_text(&why)).await.map(|_| ()),
            Response::DeleteAndWarn => {
                // A rung with nothing to hide is still spent: the warning is
                // delivered and the ladder moves on. Skipping it instead walked
                // straight to a kick, and re-proposing it forever would pin the
                // member below one. The debt lane rebuilds a verdict from the
                // ledger, which never kept the message ids.
                if cited_ids(v).is_empty() {
                    println!("[{id}] {name} {who} — nothing left to hide; the warning stands alone");
                } else {
                    hide_cited(bot, v, id).await;
                }
                bot.dm(&v.npub).send(&warn_text(&why)).await.map(|_| ())
            }
            Response::Kick => community.member(v.npub.clone()).kick().await,
            Response::Ban => community.member(v.npub.clone()).ban().await,
        }
    };
    if let Err(e) = outcome {
        // Nothing happened, so nothing is recorded: the debt stands and they
        // are reachable again next pass.
        eprintln!("[{id}] {name} {who} FAILED: {e}");
        return Ok(Outcome::Failed);
    }

    if let Err(e) = store.log_action(community.id(), &v.npub, name, now, total, &why) {
        // The act ALREADY happened. Propagating would abort the pass and
        // re-deliver it next poll — and a ban rotates the community's keys
        // every time.
        eprintln!("[{id}] {name} {who} happened but could not be recorded: {e}");
    }
    if armed {
        announce(bot, community, ctx, &format!("{name} {who} — {total} strike(s) — {why}")).await;
    }
    *pass.lock().unwrap_or_else(|e| e.into_inner()) += 1;
    Ok(Outcome::Acted)
}

/// Stamped on the findings Sentinel reaches itself, in the field the engine
/// uses for the law a conviction came under.
///
/// A POSITIVE marker, not the absence of one. The SDK parses `policy_hash` with
/// `unwrap_or_default`, so a renamed or restructured field upstream would read
/// every engine finding as Sentinel's own — promoting inference to something a
/// ladder rung may act on, which is the one direction drift must not take.
pub(crate) const OWN_POLICY: &str = "sentinel:own";

/// Whose evidence this is.
fn is_sentinels_own(f: &vector_sdk::policy::Finding) -> bool {
    f.policy_hash == OWN_POLICY
}

/// Evidence a ladder rung may act on.
///
/// The ENGINE's inference may not: a cohort conviction cites real messages, so
/// acting on what it cited would pass a sentence on evidence nobody can replay,
/// with `[arm] raid` off. Sentinel's own findings are a different thing — the
/// operator armed the lane that produced them, and a model saying an image
/// breaks a rule is the answer, not evidence toward one.
fn actionable(f: &vector_sdk::policy::Finding) -> bool {
    is_sentinels_own(f) || f.is_proven()
}

/// The messages one sentence hides: deduped, capped, and only what this rung
/// is entitled to act on.
pub(crate) fn cited_ids(v: &Verdict) -> Vec<&str> {
    let mut seen = std::collections::HashSet::new();
    v.findings
        .iter()
        .filter(|f| actionable(f))
        .flat_map(|f| f.messages.iter())
        .map(|m| m.as_str())
        .filter(|m| seen.insert(*m))
        .take(MAX_HIDES)
        .collect()
}

/// Hide what a conviction cited.
///
/// A message already gone is the end state this wanted, not a failure.
async fn hide_cited(bot: &VectorBot, v: &Verdict, id: &str) {
    let ids = cited_ids(v);
    let cited: std::collections::HashSet<&str> =
        v.findings.iter().filter(|f| actionable(f)).flat_map(|f| f.messages.iter()).map(|m| m.as_str()).collect();
    let cited = cited.len();
    if cited > ids.len() {
        // Saying so is the point: the rung is spent either way, and the ladder
        // will not come back to this evidence.
        println!("[{id}] hid {} of {cited} cited — the rest stay up", ids.len());
    }
    for msg_id in ids {
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
        policy_hash: OWN_POLICY.into(),
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

impl Ctx {
    /// Everything one community's turn depends on, gathered in one place.
    ///
    /// The roster is the caller's, because the two clocks count it differently:
    /// the sweep has just counted it, and a live lane reads what the last sweep
    /// published. Everything else is the same question asked the same way.
    pub(crate) async fn of(
        cfg: &crate::config::Config,
        community: &Community,
        me: &str,
        roster: usize,
    ) -> Ctx {
        Ctx {
            policy: cfg.for_community(community.id()),
            powers: crate::powers_of(community).await,
            roster,
            me: me.to_string(),
            mod_channel: cfg.bot.mod_channel.clone(),
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
    can_deliver: impl Fn(Response) -> bool,
    store: &Store,
    community: &str,
    npub: &str,
    strikes: &[ladder::Strike],
    now: u64,
) -> Result<Option<Response>, String> {
    let hl = policy.ladder.decay_half_life_hours;
    let total = ladder::total(strikes, now, hl);
    let answers = store.answers(community, npub)?;
    Ok(ladder::owed(
        &policy.ladder,
        total,
        answers.iter().map(|a| (a.response.as_str(), a.at_total, a.at_ms)),
        can_deliver,
        now,
        hl,
    ))
}

/// A member cited across many messages is still one sentence. Matched to the
/// engine's own per-conviction citation cap, so the bound that binds is the
/// evidence rather than an arbitrary number below it.
const MAX_HIDES: usize = 32;

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
        let pick = |s: &Store, n: u32| select_rung(&p, |r| all.can_deliver(r), s, "c", "npub1a", &offenses(n), NOW).unwrap();

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

        let first = select_rung(&p, |r| all.can_deliver(r), &store, "c", "npub1a", &one_grave, NOW).unwrap();
        assert_eq!(first, Some(Response::Warn));
        store.log_action("c", "npub1a", "warn", NOW, 12, "").unwrap();

        for poll in 1..=20u64 {
            let later = NOW + poll * 90_000;
            assert_eq!(
                select_rung(&p, |r| all.can_deliver(r), &store, "c", "npub1a", &one_grave, later).unwrap(),
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
            select_rung(&p, |r| all.can_deliver(r), &store, "c", "npub1a", &fresh, much_later).unwrap(),
            Some(Response::Warn),
            "a forgiven kick must not make a fresh minor offense unanswerable"
        );
    }

    /// An ENGINE finding: the engine stamps a policy hash on everything it
    /// reaches, which is what tells it apart from Sentinel's own.
    fn cited(basis: &str, msgs: &[&str]) -> vector_sdk::policy::Finding {
        vector_sdk::policy::Finding {
            conviction_id: format!("{basis}-{}", msgs.len()),
            policy_hash: "abc123".into(),
            rule_id: "rule".into(),
            scope: "per_message".into(),
            basis: basis.into(),
            severity: "severe".into(),
            stateless: true,
            rung: 0,
            hits: msgs.len() as u32,
            weight: 0,
            detail: vec![],
            messages: msgs.iter().map(|m| m.to_string()).collect(),
            citation_count: msgs.len() as u32,
        }
    }

    fn with(findings: Vec<vector_sdk::policy::Finding>) -> Verdict {
        own_verdict("npub1a", "none".into(), vec![], findings)
    }

    /// A cohort conviction cites real messages. Hiding what it cited let
    /// inference reach into a member's history under a rung the ladder chose —
    /// with `[arm] raid` off.
    #[test]
    fn only_proven_citations_are_hidden() {
        let v = with(vec![
            cited("deterministic", &["m1", "m2"]),
            cited("heuristic", &["m3", "m4"]),
        ]);
        assert_eq!(cited_ids(&v), vec!["m1", "m2"], "inference cites, it does not sentence");
    }

    #[test]
    fn a_message_cited_twice_is_hidden_once() {
        let v = with(vec![cited("deterministic", &["m1", "m1", "m2", "m1"])]);
        assert_eq!(cited_ids(&v), vec!["m1", "m2"]);
    }

    /// The warned member reads this, so it has to say what matched and what
    /// happens next — and must never be empty, whatever the evidence was.
    #[test]
    fn a_warning_says_what_matched_and_what_comes_next() {
        for why in ["slurs [severe] 3×", "", "no findings", "a\nmultiline\nreason"] {
            let text = warn_text(why);
            assert!(text.contains("Sentinel"), "{text}");
            assert!(text.contains("warning"), "{text}");
            assert!(text.contains("escalate"), "a warning that does not say it escalates is not one");
            assert!(text.contains("moderator"), "and it must name the way to dispute it");
            if !why.is_empty() {
                assert!(text.contains(why), "the evidence has to appear: {text}");
            }
        }
    }

    /// Upstream drift must not promote engine findings to Sentinel's own. The
    /// SDK parses this field with `unwrap_or_default`, so an absence test would
    /// read a renamed field as "mine" for everything the engine ever reached.
    #[test]
    fn an_engine_finding_with_no_policy_hash_is_still_the_engines() {
        let mut f = cited("heuristic", &["m1"]);
        f.policy_hash = String::new();
        assert!(cited_ids(&with(vec![f])).is_empty(), "an empty hash is not a claim of ownership");
    }

    #[test]
    fn sentinels_own_marker_is_what_makes_a_finding_its_own() {
        let own = own_finding("vision", "gore", "m1".into());
        assert_eq!(own.policy_hash, OWN_POLICY);
        let mut forged = own.clone();
        forged.policy_hash = "abc123".into();
        assert!(cited_ids(&with(vec![forged])).is_empty(), "and it is the marker, not the shape");
    }

    /// Sentinel's own findings are inference by basis and actionable anyway:
    /// the operator armed the lane, and a model saying an image breaks a rule
    /// is the answer rather than evidence toward one.
    #[test]
    fn sentinels_own_finding_is_acted_on_though_its_basis_is_inference() {
        let own = own_finding("vision", "gore (98%)", "m9".into());
        assert!(!own.is_proven(), "it is the model's opinion, and says so");
        assert_eq!(cited_ids(&with(vec![own])), vec!["m9"], "and Sentinel still acts on its own call");
    }

    #[test]
    fn the_hide_cap_bounds_one_sentence() {
        let many: Vec<String> = (0..100).map(|i| format!("m{i}")).collect();
        let refs: Vec<&str> = many.iter().map(|s| s.as_str()).collect();
        let v = with(vec![cited("deterministic", &refs)]);
        assert_eq!(cited_ids(&v).len(), MAX_HIDES);
    }

    /// The debt lane builds a verdict with no findings at all. Its rung must
    /// not silently hide nothing and then be recorded as delivered.
    #[test]
    fn a_verdict_with_no_findings_cites_nothing() {
        assert!(cited_ids(&with(vec![])).is_empty());
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
            select_rung(&p, |r| no_hiding.can_deliver(r), &store, "c", "npub1a", &two_grave, NOW).unwrap(),
            Some(Response::Kick),
            "delete_and_warn cannot be delivered here, so the ladder goes on"
        );
    }

    /// Write-then-read, which is the cycle the ladder actually runs in. A gate
    /// that reads only the STRONGEST answer never sees the row a lighter answer
    /// wrote, so it stays open and re-delivers the same rung every poll — for
    /// as long as the strike lives.
    #[test]
    fn an_answer_closes_the_gate_it_opened_even_when_a_stronger_one_is_on_file() {
        let store = mem();
        let p = policy_with("warn = true\ndelete = true\nkick = true\nban = true");
        let all = Powers { hide: true, kick: true, ban: true };
        let hl = p.ladder.decay_half_life_hours * 3_600_000;
        let pick = |s: &Store, strikes: &[ladder::Strike], now: u64| {
            select_rung(&p, |r| all.can_deliver(r), s, "c", "npub1a", strikes, now).unwrap()
        };

        // An old, strong answer, long since forgiven.
        store.log_action("c", "npub1a", "kick", NOW, 36, "").unwrap();
        let much_later = NOW + hl * 8;
        let light = [ladder::Strike { worth: 1, at_ms: much_later }];

        // The forgiven kick no longer floors anything, so this is a warning.
        assert_eq!(pick(&store, &light, much_later), Some(Response::Warn));
        store.log_action("c", "npub1a", "warn", much_later, 1, "").unwrap();

        // And that warning must be the last word until something new happens.
        for poll in 1..=30u64 {
            assert_eq!(
                pick(&store, &light, much_later + poll * 120_000),
                None,
                "poll {poll} re-delivered an answer already given"
            );
        }
    }

    /// The same shape with equal ranks, where the tie-break used to keep the
    /// oldest row and the new one was never read at all.
    #[test]
    fn two_answers_of_the_same_rung_do_not_reopen_each_other() {
        let store = mem();
        let p = policy_with("warn = true\ndelete = true\nkick = true\nban = true");
        let all = Powers { hide: true, kick: true, ban: true };
        let hl = p.ladder.decay_half_life_hours * 3_600_000;

        store.log_action("c", "npub1a", "warn", NOW, 12, "").unwrap();
        let later = NOW + hl * 5;
        store.log_action("c", "npub1a", "warn", later, 1, "").unwrap();

        let light = [ladder::Strike { worth: 1, at_ms: later }];
        assert_eq!(
            select_rung(&p, |r| all.can_deliver(r), &store, "c", "npub1a", &light, later + 120_000).unwrap(),
            None
        );
    }

    /// And a genuinely new offense still climbs from the answer that stands.
    #[test]
    fn a_new_offense_after_a_forgiven_kick_climbs_from_the_warning() {
        let store = mem();
        let p = policy_with("warn = true\ndelete = true\nkick = true\nban = true");
        let all = Powers { hide: true, kick: true, ban: true };
        let hl = p.ladder.decay_half_life_hours * 3_600_000;

        store.log_action("c", "npub1a", "kick", NOW, 36, "").unwrap();
        let much_later = NOW + hl * 8;
        store.log_action("c", "npub1a", "warn", much_later, 1, "").unwrap();

        let worse = [
            ladder::Strike { worth: 1, at_ms: much_later },
            ladder::Strike { worth: 12, at_ms: much_later },
        ];
        assert_eq!(
            select_rung(&p, |r| all.can_deliver(r), &store, "c", "npub1a", &worse, much_later).unwrap(),
            Some(Response::DeleteAndWarn),
            "one rung above the warning that still stands, not above the forgiven kick"
        );
    }
}

