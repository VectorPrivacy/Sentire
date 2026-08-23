//! The periodic pass: evaluate a community, answer what it convicted, and
//! contain a raid as one event rather than as N sentences.

use std::sync::{Arc, Mutex};

use vector_sdk::policy::Verdicts;
use vector_sdk::{Community, VectorBot};

use crate::adjudicate::{self};
use crate::config::{Config, RaidResponse};
use crate::policy::Powers;
use crate::store::Store;
use crate::tripwire::Tripwire;
use crate::act::{announce, enforce, own_verdict, Ctx, Outcome};
use crate::{
    conviction_id, now_ms, powers_of, roster_map, short, Pass,
    Watches,
};
use crate::raid;

/// One pass: verdicts in, strikes recorded, ladder consulted, sentences
/// rehearsed or carried out.
pub(crate) async fn sweep(
    bot: &VectorBot,
    community: &Community,
    cfg: &Config,
    store: &Arc<Store>,
    wires: &Watches,
    me: &str,
) -> vector_sdk::Result<Pass> {
    if !cfg.watches(community.id()) {
        return Ok(Pass::Held);
    }
    // Single-flight. Claimed before the corpus read, released however this
    // returns, so an error path cannot wedge the community closed. Returns
    // whether it actually RAN: a caller that lost the race must be able to give
    // its trip back rather than spend a cooldown on nothing.
    {
        let mut guard = wires.lock().unwrap_or_else(|e| e.into_inner());
        let w = guard.entry(community.id().to_string()).or_default();
        if w.sweeping {
            return Ok(Pass::Declined);
        }
        w.sweeping = true;
    }
    let _release = SweepGuard { wires: wires.clone(), community: community.id().to_string() };

    let verdicts = community.verdicts().await?;

    // A roster read that came back empty is missing data. Publishing it would
    // latch `known` on nothing, which turns every standing lookup into "absent"
    // and every percentage ceiling into no ceiling at all.
    if verdicts.all().next().is_none() {
        // The coverage line is the whole reason a quiet pass is legible, and it
        // is most needed on the pass that explains itself least.
        heartbeat(short(community.id()), &verdicts, 0, None);
        println!("[{}] roster read returned no members — holding this pass", short(community.id()));
        return Ok(Pass::Held);
    }

    let ctx_raid = cfg.for_community(community.id()).raid;
    // Publish what only the engine knows: who belongs here. The tripwire uses
    // it to ignore regulars, and the live lanes use it as their shield.
    {
        let vouched: Vec<&str> = verdicts.all().filter(|v| v.is_shielded()).map(|v| v.npub.as_str()).collect();
        let mut guard = wires.lock().unwrap_or_else(|e| e.into_inner());
        let w = guard.entry(community.id().to_string()).or_default();
        let r = ctx_raid;
        w.tripwire
            .get_or_insert_with(|| Tripwire::new(r.tripwire_accounts, r.tripwire_secs, r.tripwire_cooldown_secs))
            .trust(vouched);
        w.standing = verdicts.all().map(|v| (v.npub.clone(), v.shield.clone())).collect();
        w.known = true;
    }
    let id = short(community.id());
    let now = now_ms();
    let ctx = Ctx {
        policy: cfg.for_community(community.id()),
        powers: powers_of(community).await,
        roster: verdicts.all().count(),
        me: me.to_string(),
        mod_channel: cfg.bot.mod_channel.clone(),
    };
    let pass = Mutex::new(0usize);
    let mut convicted = 0usize;
    let mut halted = false;
    let mut handled: std::collections::HashSet<String> = std::collections::HashSet::new();

    // `all()`, not `proven()`: the shielded are filtered out upstream by
    // `proven()`, so gating on them inside that loop could never fire and the
    // operator never saw who was spared.
    for v in verdicts.all().filter(|v| v.is_proven()) {
        if v.npub == me {
            continue;
        }
        convicted += 1;
        // Before recording, exactly as the live lanes do. Recording anyway
        // built a silent backlog on members `enforce` would always spare —
        // ammunition for the day `respect_trusted` was turned off, or for any
        // path that failed to read their standing.
        if v.shield == "protected" || (v.shield == "trusted" && ctx.policy.shields.respect_trusted) {
            println!("[{id}] QUEUED  {} — {} ({})", short(&v.npub), v.why(), v.shield);
            // Handled: without this their older strikes keep them in the debt
            // loop, which names a moderator in the log every single pass.
            handled.insert(v.npub.clone());
            continue;
        }

        // Record what is NEW this poll. Verdicts re-report every standing
        // conviction, so the conviction id is the line between an offense and
        // an echo of one.
        // Which rules already charged per message. A content rule convicts at
        // BOTH scopes over the same citations, so charging the window rung too
        // billed one offense twice — and pushed three flagged links from a kick
        // to an instant ban.
        // Only rules that actually CHARGED. A stateless finding that is
        // unproven, or that cites no message, charges nothing — and still
        // suppressed its rule's window rung, so the offense went to nobody.
        let charged_per_message: std::collections::HashSet<&str> = v
            .findings
            .iter()
            // `messages` may be shorter than `citation_count`, and then the
            // per-message charges did NOT cover the evidence — so suppressing
            // the window rung charged the worst offenders the least.
            .filter(|f| f.stateless && f.is_proven() && !f.messages.is_empty() && f.citation_count as usize <= f.messages.len())
            .map(|f| f.rule_id.as_str())
            .collect();
        for f in &v.findings {
            if !f.is_proven() {
                continue; // inference never earns a strike
            }
            if !f.stateless && charged_per_message.contains(f.rule_id.as_str()) {
                continue; // the density charges already cover this evidence
            }
            let gravity = ctx.policy.gravity_of(&f.rule_id, &f.severity);
            let worth = ctx.policy.ladder.strikes.worth(gravity);
            let evidence = format!("{} [{}] {}×", f.rule_id, f.severity, f.hits);
            if f.stateless {
                // Charged per cited message, under the id the live screen would
                // have used. Whichever clock got there first wins; the other is
                // an ignored insert. Skipping these outright meant anything
                // posted while Sentinel was down was never charged at all.
                for mid in &f.messages {
                    store
                        .record(community.id(), &v.npub, &conviction_id(&f.rule_id, mid), worth, now, &evidence)
                        .map_err(vector_sdk::Error::Other)?;
                }
                continue;
            }
            store
                .record(community.id(), &v.npub, &f.conviction_id, worth, now, &evidence)
                .map_err(vector_sdk::Error::Other)?;
        }
        let strikes = store.strikes(community.id(), &v.npub).map_err(vector_sdk::Error::Other)?;
        handled.insert(v.npub.clone());
        if enforce(bot, community, &ctx, store, wires, &pass, v, &strikes).await? == Outcome::Halted {
            halted = true;
            break;
        }
    }

    // Everyone the store owes for whom the loop above did not already handle.
    // The engine reports the whole memberlist, so keying this on "the engine
    // did not report them" reached only EX-members and missed every case it was
    // written for: a vision-only offender, or anyone the `is_proven` filter
    // skipped, carrying a sentence a ceiling held or a failed action lost.
    if !halted {
        let owed = store.subjects_with_strikes(community.id()).map_err(vector_sdk::Error::Other)?;
        let roster = roster_map(wires, community.id());
        for (npub, shield) in debt_subjects(&handled, &roster, owed, me) {
            let strikes = store.strikes(community.id(), &npub).map_err(vector_sdk::Error::Other)?;
            let v = own_verdict(&npub, shield, store.evidence(community.id(), &npub).unwrap_or_default(), vec![]);
            if enforce(bot, community, &ctx, store, wires, &pass, &v, &strikes).await? == Outcome::Halted {
                halted = true;
                break;
            }
        }
    }

    for v in verdicts.unproven() {
        convicted += 1;
        println!(
            "[{id}] INFERRED {} — {} (confidence {}, proven {}) — a second judge decides",
            short(&v.npub),
            v.why(),
            v.confidence,
            v.proven
        );
    }
    // A community that just tripped the emptying guard is not one to then run
    // a bulk action against unattended.
    if halted {
        println!("[{id}] halt in force — raid containment deferred to a person");
    } else {
        contain(bot, community, &ctx, store, &verdicts, now).await?;
    }

    heartbeat(id, &verdicts, convicted, Some(&ctx.powers));
    Ok(Pass::Ran)
}

/// A raid answers to itself, not to the ladder — but it answers to the same
/// standing, powers and ceilings as everything else.
///
/// See [`raid`] for why this is the one path where inference may act, and only
/// once armed.
pub(crate) async fn contain(
    bot: &VectorBot,
    community: &Community,
    ctx: &Ctx,
    store: &Arc<Store>,
    verdicts: &Verdicts,
    now: u64,
) -> vector_sdk::Result<()> {
    if !ctx.policy.rules.raid_detection {
        return Ok(());
    }
    let id = short(community.id());
    let (suspects, response, armed) = match raid::select(verdicts, &ctx.policy, &ctx.me) {
        raid::Containment::Quiet => return Ok(()),
        raid::Containment::Halt { suspects, roster } => {
            // Claimed like any other containment: a raid stays detected for as
            // long as its evidence sits in the window, and an unclaimed halt
            // republished this line into a community channel every 90 seconds
            // for a week.
            let ttl = ctx.policy.raid.claim_ttl_secs.saturating_mul(1000);
            if store
                .claim(community.id(), &format!("halt:{}", now / 3_600_000), now, ttl)
                .map_err(vector_sdk::Error::Other)?
            {
                let line = format!(
                    "RAID HALT — {suspects} of {roster} members are over the bar, past the {}% ceiling. \
                     Containing this many is a person's call, not mine.",
                    ctx.policy.limits.halt_if_over_pct
                );
                println!("[{id}] {line}");
                announce(bot, community, ctx, &line).await;
            }
            return Ok(());
        }
        raid::Containment::WouldContain { suspects, response } => (suspects, response, false),
        raid::Containment::Contain { suspects, response } => (suspects, response, true),
    };

    // The permission this needs, before anything is claimed or announced.
    let needs = match response {
        RaidResponse::Report => None,
        RaidResponse::Kick if !ctx.powers.kick => Some("KICK"),
        RaidResponse::Ban if !ctx.powers.ban => Some("BAN"),
        _ => None,
    };
    if let Some(needs) = needs {
        println!("[{id}] CANNOT contain — this community grants Sentinel no {needs}");
        return Ok(());
    }

    let verb = response.name();
    // A ceiling that spans TIME, not one pass. `raid::select` halts only when a
    // SINGLE pass is over the bar, so a sustained false positive contained 10%
    // every two minutes and emptied the community in twenty — without the guard
    // built to prevent exactly that ever firing.
    // Containment's own bound: the ladder's hourly count excludes raid rows.
    let spent = store.actions_last_hour(community.id(), now).map_err(vector_sdk::Error::Other)?;
    // Claimed PER MEMBER, not per cohort. A wave arriving over many sweeps
    // grows the set every pass, so re-containing everyone already handled
    // means a key rotation each time.
    // Claims are scoped to armed-ness, so a rehearsal never immunises a cohort
    // against a later real containment.
    // Keyed on armed-ness AND the verb, because that is what the claim
    // prevents. Either alone left a natural rollout broken: report-then-kick
    // found every suspect already claimed and contained nobody for the TTL.
    let scope = format!("{}:{}", if armed { "armed" } else { "dry" }, verb);
    let ttl = ctx.policy.raid.claim_ttl_secs.saturating_mul(1000);
    let mut fresh: Vec<String> = Vec::new();
    for npub in &suspects {
        if store
            .claim(community.id(), &format!("{scope}:{npub}"), now, ttl)
            .map_err(vector_sdk::Error::Other)?
        {
            fresh.push(npub.clone());
        }
    }
    if fresh.is_empty() {
        return Ok(());
    }

    // Measured against what will actually be acted on, after the claims — and
    // across the HOUR. `raid::select` halts only on a single pass being over the
    // bar, so a sustained false positive contained a tenth every two minutes and
    // emptied a community in twenty without the guard ever firing.
    if let Some(ceiling) = adjudicate::roster_ceiling(&ctx.policy, ctx.roster) {
        if spent + fresh.len() > ceiling {
            let line = format!(
                "RAID HALT — {spent} contained here in the last hour, {} more over the bar, past what {}% of {} members allows. \
                 A person decides from here.",
                fresh.len(),
                ctx.policy.limits.halt_if_over_pct,
                ctx.roster
            );
            println!("[{id}] {line}");
            for npub in &fresh {
                let _ = store.release(community.id(), &format!("{scope}:{npub}"));
            }
            let ttl = ctx.policy.raid.claim_ttl_secs.saturating_mul(1000);
            if store
                .claim(community.id(), &format!("halt:{}", now / 3_600_000), now, ttl)
                .map_err(vector_sdk::Error::Other)?
            {
                announce(bot, community, ctx, &line).await;
            }
            return Ok(());
        }
    }

    let verb = response.name();
    let line = format!(
        "RAID {} — {} account(s), {verb}",
        match (armed, response) {
            (_, RaidResponse::Report) => "REPORTED (nobody touched)",
            (true, _) => "CONTAINED",
            (false, _) => "SUSPECTED (unarmed, nobody touched)",
        },
        fresh.len()
    );
    println!("[{id}] {line}");

    // Act, THEN log — the same discipline the ladder keeps. Logging first meant
    // a failed ban left an audit trail claiming a contained raid.
    let mut done: Vec<&str> = Vec::new();
    if armed && response != RaidResponse::Report {
        match response {
            RaidResponse::Kick => {
                // Kicks rotate nothing, so a loop is honest about KEYS — but
                // each one folds the control plane, so a large wave is minutes
                // inside the single-flight guard, starving every other
                // community. Bounded per pass; the rest keep no claim and are
                // picked up next time.
                for npub in fresh.iter().take(ctx.policy.raid.max_batch) {
                    match community.member(npub.clone()).kick().await {
                        Ok(()) => done.push(npub),
                        Err(e) => eprintln!("[{id}] kick {}: {e}", short(npub)),
                    }
                }
            }
            RaidResponse::Ban => {
                // ban_many, never a loop of ban(): each single ban rotates the
                // community's keys, and forty rotations strand everyone.
                // Bounded per pass like the kick path, then chunked for the
                // wire cap inside that. `max_batch` means one thing.
                let this_pass = &fresh[..fresh.len().min(ctx.policy.raid.max_batch)];
                for chunk in this_pass.chunks(raid::BAN_CHUNK) {
                    let refs: Vec<&str> = chunk.iter().map(String::as_str).collect();
                    match community.ban_many(&refs).await {
                        Ok(()) => done.extend(refs),
                        Err(e) => eprintln!("[{id}] ban batch of {}: {e}", refs.len()),
                    }
                }
            }
            RaidResponse::Report => {}
        }
        // Anything past the per-pass bound never had an action attempted.
        // Release every member the action did not actually reach. Releasing
        // only on total failure stranded the ones a partial failure missed:
        // they kept their claims and were never retried, silently.
        for npub in &fresh {
            if !done.iter().any(|d| *d == npub.as_str()) {
                let _ = store.release(community.id(), &format!("{scope}:{npub}"));
            }
        }
        if done.is_empty() {
            eprintln!("[{id}] containment failed entirely — released for retry");
            return Ok(());
        }
        if done.len() < fresh.len() {
            eprintln!("[{id}] contained {} of {} — the rest released for retry", done.len(), fresh.len());
        }
    } else {
        done = fresh.iter().map(String::as_str).collect();
    }

    // Prefixed, so a raid row is never read as a ladder response. An unarmed
    // raid stamping a bare "kick" on every suspect immunised all of them
    // against warn, delete and kick — permanently, on evidence nobody acted on.
    for npub in &done {
        store
            .log_action(community.id(), npub, &format!("raid:{verb}"), now, "raid cohort")
            .map_err(vector_sdk::Error::Other)?;
    }
    if armed {
        announce(bot, community, ctx, &line).await;
    }
    Ok(())
}

/// What the sweep looked at, whether or not it found anything.
///
/// A quiet community and a broken bot print the same thing — nothing — and that
/// is exactly how a moderation tool stays broken for months. Every pass says
/// what it read and how many people it weighed, so silence becomes a result
/// rather than an absence of one.
pub(crate) fn heartbeat(community: &str, verdicts: &Verdicts, found: usize, powers: Option<&Powers>) {
    let cov = verdicts.coverage();
    let mut shields = (0, 0, 0);
    for v in verdicts.all() {
        match v.shield.as_str() {
            "protected" => shields.0 += 1,
            "trusted" => shields.1 += 1,
            _ => shields.2 += 1,
        }
    }
    let history = if cov.is_empty() {
        // Not a clean community. An unread one.
        "NO HISTORY — nothing was judged".to_string()
    } else {
        format!(
            "{} msgs over {}h across {} channel(s){}{}",
            cov.corpus,
            cov.span_hours(),
            cov.channels,
            if cov.is_saturated() { ", WINDOW FULL (older history unread)" } else { "" },
            if cov.complete { "" } else { ", partial" },
        )
    };
    println!(
        "[{community}] swept {} member(s) — {} protected, {} trusted, {} plain — {found} convicted — {history} — {}",
        verdicts.all().count(),
        shields.0,
        shields.1,
        shields.2,
        powers.map(|p| p.describe()).unwrap_or_else(|| "powers not read this pass".into()),
    );
}

/// Who the debt loop may reach, and with what standing.
///
/// Two mistakes this exists to make untestable-by-inspection impossible: keying
/// on "the engine did not report them" reached only EX-members (the engine
/// reports the whole memberlist), and taking their standing from a lookup that
/// answers "absent" for anyone off-roster handed the gate a value meaning
/// "not shielded" for every single subject.
pub(crate) fn debt_subjects(
    handled: &std::collections::HashSet<String>,
    roster: &std::collections::HashMap<String, String>,
    owed: Vec<String>,
    me: &str,
) -> Vec<(String, String)> {
    owed.into_iter()
        .filter(|n| !handled.contains(n) && n != me)
        .filter_map(|n| roster.get(&n).cloned().map(|shield| (n, shield)))
        .collect()
}

/// Releases the single-flight claim however the sweep returns, including the
/// `?` paths — which is why this is a guard and not a flag flip at the end.
struct SweepGuard {
    wires: Watches,
    community: String,
}

impl Drop for SweepGuard {
    fn drop(&mut self) {
        if let Some(w) = self.wires.lock().unwrap_or_else(|e| e.into_inner()).get_mut(&self.community) {
            w.sweeping = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roster(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
        pairs.iter().map(|(n, s)| (n.to_string(), s.to_string())).collect()
    }

    fn the_debt_loop_reaches_current_members_the_pass_missed() {
        let r = roster(&[
            ("npub1vision", "none"),
            ("npub1trusted", "trusted"),
            ("npub1handled", "none"),
            ("npub1me", "none"),
        ]);
        let handled: std::collections::HashSet<String> = ["npub1handled".to_string()].into_iter().collect();
        let owed = vec![
            "npub1vision".to_string(),
            "npub1trusted".to_string(),
            "npub1handled".to_string(),
            "npub1me".to_string(),
            "npub1departed".to_string(),
        ];
        let got = debt_subjects(&handled, &r, owed, "npub1me");

        assert!(got.iter().any(|(n, _)| n == "npub1vision"), "the case this loop exists for");
        assert!(got.iter().any(|(n, s)| n == "npub1trusted" && s == "trusted"), "with their REAL standing");
        assert!(!got.iter().any(|(n, _)| n == "npub1handled"), "already sentenced this pass");
        assert!(!got.iter().any(|(n, _)| n == "npub1me"), "never itself");
        assert!(!got.iter().any(|(n, _)| n == "npub1departed"), "not on the roster, not ours to judge");
    }

    fn the_debt_loop_never_emits_an_unresolved_standing() {
        let r = roster(&[("a", "none"), ("b", "trusted"), ("c", "protected"), ("d", "indeterminate")]);
        let owed = vec!["a".into(), "b".into(), "c".into(), "d".into(), "gone".into()];
        for (_, shield) in debt_subjects(&Default::default(), &r, owed, "me") {
            assert!(
                matches!(shield.as_str(), "none" | "trusted" | "protected" | "indeterminate"),
                "unresolved standing {shield} reached the gate"
            );
        }
    }
}
