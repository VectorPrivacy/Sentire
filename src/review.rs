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
    conviction_id, now_ms, roster_map, short, Pass,
    Watches,
};
use crate::raid;

/// One strike this verdict earns: the id it dedups on, what it is worth, and
/// the line a person reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Charge {
    pub(crate) conviction: String,
    /// The rule this charge came from, carried rather than parsed back out of
    /// `conviction`: standing spares behavioural rules and not content ones, and
    /// the two conviction id formats do not agree on where the rule id sits.
    pub(crate) rule_id: String,
    pub(crate) worth: u32,
    pub(crate) evidence: String,
}

/// One finding in the words a member reads.
///
/// Both clocks use it, so a warning does not change vocabulary depending on
/// which one got there first — the sweep used to write `slurs [severe] 8x`
/// while the live screen wrote English.
pub(crate) fn evidence_line(f: &vector_sdk::policy::Finding) -> String {
    if f.detail.is_empty() {
        format!("Matched the \"{}\" rule", f.rule_id)
    } else {
        let words: Vec<String> = f.detail.iter().map(|d| format!("\"{d}\"")).collect();
        format!("Used {} ({} time{})", words.join(", "), f.hits, if f.hits == 1 { "" } else { "s" })
    }
}

/// Whether one finding can earn a strike at all.
///
/// Two conditions, and they answer different questions. The BASIS: inference
/// may not sentence, whatever it is convinced of. And a CITATION: a strike
/// points at something the member did, where the engine's raid aggravators
/// (an account under a day old, one that has posted twice) describe a person
/// and cite nothing — a cohort is what arms them.
pub(crate) fn chargeable(f: &vector_sdk::policy::Finding) -> bool {
    f.is_proven() && f.citation_count > 0
}

/// What one verdict charges, decided without touching the store.
///
/// Only the BASIS gates a strike: deterministic evidence charges, inference
/// never does. The member's overall score is not consulted — it answers "is
/// this enough to act on unattended", which is the ladder's question, not the
/// ledger's, and gating here meant a light rule never accumulated at all.
pub(crate) fn charges(v: &vector_sdk::policy::Verdict, policy: &crate::policy::CommunityPolicy) -> Vec<Charge> {
    // A content rule convicts at BOTH scopes over the same citations, so the
    // window rung is dropped where the per-message charges already cover the
    // evidence. `messages` shorter than `citation_count` means they do not.
    let charged_per_message: std::collections::HashSet<&str> = v
        .findings
        .iter()
        .filter(|f| f.stateless && chargeable(f) && !f.messages.is_empty() && f.citation_count as usize <= f.messages.len())
        .map(|f| f.rule_id.as_str())
        .collect();

    let mut out = Vec::new();
    for f in &v.findings {
        if !chargeable(f) {
            continue;
        }
        if !f.stateless && charged_per_message.contains(f.rule_id.as_str()) {
            continue;
        }
        let worth = policy.ladder.strikes.worth(policy.gravity_of(&f.rule_id, &f.severity));
        let evidence = evidence_line(f);
        if f.stateless {
            // Under the id the live screen would have used, so whichever clock
            // reached the message first wins and the other is an ignored insert.
            for mid in &f.messages {
                out.push(Charge {
                    conviction: conviction_id(&f.rule_id, mid),
                    rule_id: f.rule_id.clone(),
                    worth,
                    evidence: evidence.clone(),
                });
            }
            continue;
        }
        // Sentinel's OWN id, not the engine's. The engine keys a conviction on
        // the POLICY HASH, so editing any rule — or toggling
        // `shields.respect_trusted`, which rewrites every rule — re-mints every
        // standing window conviction, and INSERT OR IGNORE finds no row: the
        // whole open window is charged again at `now` and the ladder climbs a
        // rung for it. An afternoon of tuning would kick and then ban a member
        // who had done nothing since the first edit.
        //
        // The rule, the scope and the rung identify the offense. The rulebook
        // version does not — which is what the per-message id has always said.
        out.push(Charge {
            conviction: format!("win:{}:{}:{}", f.rule_id, f.scope, f.rung),
            rule_id: f.rule_id.clone(),
            worth,
            evidence,
        });
    }
    out
}

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
    let ctx = Ctx::of(cfg, community, me, verdicts.all().count()).await;
    let pass = Mutex::new(0usize);
    let mut convicted = 0usize;
    let mut halted = false;
    let mut handled: std::collections::HashSet<String> = std::collections::HashSet::new();

    // `all()`, not `proven()`: the shielded are filtered out upstream by
    // `proven()`, so gating on them inside that loop could never fire and the
    // operator never saw who was spared.
    //
    // Gated on the FINDINGS, not the member's score. `Verdict::is_proven` asks
    // whether the total is enough to act on unattended; that is the ladder's
    // question. A note-gravity rule never reaches it at any hit count, so
    // asking it here meant light rules accumulated nothing and a small offense
    // was charged only when an unrelated grave one carried the score.
    for v in verdicts.all().filter(|v| v.findings.iter().any(chargeable)) {
        if v.npub == me {
            continue;
        }
        convicted += 1;
        // Before recording, exactly as the live lanes do. Recording anyway
        // built a silent backlog on members `enforce` would always spare —
        // ammunition for the day `respect_trusted` was turned off, or for any
        // path that failed to read their standing.
        let spared_heuristics = adjudicate::spared_by_standing(&ctx.policy, &v.shield);
        let spared_content = adjudicate::spared_from_content(&v.shield);
        if let (Some(why), Some(_)) = (spared_heuristics, spared_content) {
            println!("[{id}] QUEUED  {} — {} ({why})", short(&v.npub), v.why());
            // Handled: without this their older strikes keep them in the debt
            // loop, which names a moderator in the log every single pass.
            handled.insert(v.npub.clone());
            continue;
        }

        // Per CHARGE. A trusted regular is spared the behavioural rules their
        // record earned them leniency on, and charged on the word and link
        // lists, which say what this community does not host whoever posts it.
        let kept: Vec<_> = charges(v, &ctx.policy)
            .into_iter()
            .filter(|c| {
                if ctx.policy.is_content_rule(&c.rule_id, &ctx.vision_labels) {
                    spared_content.is_none()
                } else {
                    spared_heuristics.is_none()
                }
            })
            .collect();
        if kept.is_empty() {
            println!("[{id}] QUEUED  {} — {} (standing)", short(&v.npub), v.why());
            handled.insert(v.npub.clone());
            continue;
        }
        for c in kept {
            store.record(community.id(), &v.npub, &c.conviction, c.worth, now, &c.evidence).map_err(vector_sdk::Error::Other)?;
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
        for (npub, shield) in debt_subjects(&ctx.policy, &handled, &roster, owed, me) {
            let strikes = store.strikes(community.id(), &npub).map_err(vector_sdk::Error::Other)?;
            let evidence = store.evidence(community.id(), &npub).map_err(vector_sdk::Error::Other)?;
            let v = own_verdict(&npub, shield, evidence, vec![]);
            if enforce(bot, community, &ctx, store, wires, &pass, &v, &strikes).await? == Outcome::Halted {
                halted = true;
                break;
            }
        }
    }

    for v in verdicts.unproven() {
        if v.npub == me {
            continue;
        }
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
        raid::Containment::Halt { suspects, roster, tenured } => {
            // Claimed like any other containment: a raid stays detected for as
            // long as its evidence sits in the window, and an unclaimed halt
            // republished this line into a community channel every 90 seconds
            // for a week.
            let ttl = ctx.policy.raid.claim_ttl_secs.saturating_mul(1000);
            if store
                .claim(community.id(), &format!("halt:{}", now / 3_600_000), now, ttl)
                .map_err(vector_sdk::Error::Other)?
            {
                // A cohort this deep into ESTABLISHED members is a misfire or a
                // raid that reached real people — either way a person's call.
                // Fresh raiders never bring us here, however many.
                let line = format!(
                    "RAID HALT — {tenured} established member(s) among {suspects} suspects (of {roster}) \
                     are over the bar. Removing established members in bulk is a person's call, not mine.",
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
    // Tenure of each suspect, to gate on ESTABLISHED members only — the same
    // principle as `raid::select`'s halt, applied to what THIS pass would newly
    // action. A raider's inflated roster must never raise the bar for removing
    // the raider.
    let tenure: std::collections::HashMap<&str, u64> =
        verdicts.all().map(|v| (v.npub.as_str(), v.tenure_secs)).collect();
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

    // Measured on ESTABLISHED members about to be actioned this pass — never on
    // the raider-inflated roster. Fresh accounts are contained without limit.
    let tenured_fresh = fresh
        .iter()
        .filter(|n| tenure.get(n.as_str()).copied().unwrap_or(0) >= ctx.policy.raid.protect_tenure_secs)
        .count();
    {
        if tenured_fresh > ctx.policy.limits.halt_floor {
            let line = format!(
                "RAID HALT — {tenured_fresh} established member(s) would be {verb}ed this pass, over the {} allowed. \
                 A person decides from here.",
                ctx.policy.limits.halt_floor,
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

    // Announced BEFORE, for the same reason the ladder does it: this is the
    // largest thing Sentinel can do, and doing it with no record where an
    // operator asked for one is the incident the trail exists to prevent.
    if armed && response != RaidResponse::Report && !announce(bot, community, ctx, &line).await {
        println!("[{id}] HELD — the mod channel is unreachable, and this would go unrecorded");
        for npub in &fresh {
            let _ = store.release(community.id(), &format!("{scope}:{npub}"));
        }
        return Ok(());
    }

    // A public shout in the room the raid is hitting, the moment Sentinel moves —
    // so the real members watching accounts pour in see it is being handled, not
    // that the community is being overrun unanswered. Best-effort: a failed alert
    // must never hold up the containment it announces.
    if armed && response != RaidResponse::Report {
        // Every readable public channel, not a cited-message lookup: a citation
        // can fail to resolve (the message may not be locally held yet), and an
        // alert that silently no-ops is the one message a raid most needs seen.
        let alert = "🚨 **Raid detected** — locking down and clearing out the intruders.";
        let mut posted = false;
        for ch in community.channels().await {
            if ch.is_readable() && !ch.is_private() {
                match bot.channel(ch.id()).send(alert).await {
                    Ok(_) => posted = true,
                    Err(e) => eprintln!("[{id}] raid alert to {}: {e}", &ch.id()[..8.min(ch.id().len())]),
                }
            }
        }
        if posted {
            println!("[{id}] raid alert posted");
        }
    }

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
    //
    // A rehearsal is marked as one. Arming containment does NOT wipe the slate
    // — it shares no state with the ladder — so a bare `raid:kick` written
    // while unarmed would sit in the removal count and put the first real
    // containment over its ceiling before it acted on anybody.
    let recorded = if armed && response != RaidResponse::Report {
        format!("raid:{verb}")
    } else {
        format!("raid:would-{verb}")
    };
    for npub in &done {
        store
            .log_action(community.id(), npub, &recorded, now, "raid cohort")
            .map_err(vector_sdk::Error::Other)?;
    }
    if armed && response == RaidResponse::Report {
        announce(bot, community, ctx, &line).await;
    }
    // DM the mods WHO was removed, so a human can double-check the mass-action.
    // Only for a real containment — a report or an unarmed suspicion removed
    // nobody, and the mod channel line already carried those.
    if armed && response != RaidResponse::Report && !done.is_empty() {
        crate::act::notify_mods_raid(bot, ctx, verb, &done).await;
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
    policy: &crate::policy::CommunityPolicy,
    handled: &std::collections::HashSet<String>,
    roster: &std::collections::HashMap<String, String>,
    owed: Vec<String>,
    me: &str,
) -> Vec<(String, String)> {
    owed.into_iter()
        .filter(|n| !handled.contains(n) && n != me)
        .filter_map(|n| roster.get(&n).cloned().map(|shield| (n, shield)))
        // Standing spares them wherever they are read, so sending them on to
        // `enforce` only prints that it spared them — every pass, for as long
        // as a strike row survives, which is how a moderator came to be named
        // in the log forever.
        .filter(|(_, shield)| crate::adjudicate::spared_by_standing(policy, shield).is_none())
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

    /// The population is "owed but not yet handled THIS pass", and every
    /// subject carries the standing the roster actually lists.
    #[test]
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
        let got = debt_subjects(&base(), &handled, &r, owed, "npub1me");

        assert!(got.iter().any(|(n, _)| n == "npub1vision"), "the case this loop exists for");
        assert!(!got.iter().any(|(n, _)| n == "npub1handled"), "already sentenced this pass");
        assert!(!got.iter().any(|(n, _)| n == "npub1me"), "never itself");
        assert!(!got.iter().any(|(n, _)| n == "npub1departed"), "not on the roster, not ours to judge");
        assert!(
            !got.iter().any(|(n, _)| n == "npub1trusted"),
            "standing spares them wherever they are read, so passing them on only prints that it did — \
             every pass, for as long as a strike row survives"
        );
    }

    /// And a community that has chosen to reach its regulars does reach them.
    #[test]
    fn the_debt_loop_follows_this_communitys_shield_policy() {
        let r = roster(&[("npub1trusted", "trusted")]);
        let owed = vec!["npub1trusted".to_string()];

        let sparing = base();
        assert!(debt_subjects(&sparing, &Default::default(), &r, owed.clone(), "me").is_empty());

        let mut reaching = base();
        reaching.shields.respect_trusted = false;
        assert_eq!(debt_subjects(&reaching, &Default::default(), &r, owed, "me").len(), 1);
    }

    /// Every shield this loop emits must be one the gate recognises. "absent"
    /// falls through to "not shielded", so emitting it here is a ban path.
    #[test]
    fn the_debt_loop_never_emits_an_unresolved_standing() {
        let r = roster(&[("a", "none"), ("b", "trusted"), ("c", "protected"), ("d", "indeterminate")]);
        let owed = vec!["a".into(), "b".into(), "c".into(), "d".into(), "gone".into()];
        for (_, shield) in debt_subjects(&base(), &Default::default(), &r, owed, "me") {
            assert!(
                matches!(shield.as_str(), "none" | "trusted" | "protected" | "indeterminate"),
                "unresolved standing {shield} reached the gate"
            );
        }
    }

    fn f(
        rule: &str,
        scope: &str,
        stateless: bool,
        basis: &str,
        hits: u32,
        msgs: &[&str],
        citation_count: u32,
    ) -> vector_sdk::policy::Finding {
        vector_sdk::policy::Finding {
            conviction_id: format!("{rule}:{scope}"),
            policy_hash: "hash".into(),
            rule_id: rule.into(),
            scope: scope.into(),
            basis: basis.into(),
            severity: "major".into(),
            stateless,
            rung: 0,
            hits,
            weight: 0,
            detail: vec![],
            messages: msgs.iter().map(|m| m.to_string()).collect(),
            citation_count,
        }
    }

    fn verdict(findings: Vec<vector_sdk::policy::Finding>) -> vector_sdk::policy::Verdict {
        crate::act::own_verdict("npub1a", "none".into(), vec![], findings)
    }

    fn base() -> crate::policy::CommunityPolicy {
        crate::config::Config::default().for_community("")
    }

    /// The sweep's loop filter and the charging rule must be the same
    /// question, or the loop admits members it then charges nothing for.
    #[test]
    fn the_sweep_only_visits_members_it_can_actually_charge() {
        let cases = [
            (f("cohort", "whole", false, "heuristic", 1, &[], 0), false),
            (f("fresh", "whole", false, "deterministic", 1, &[], 0), false),
            (f("slurs", "per_message", true, "deterministic", 1, &["m1"], 1), true),
            (f("rate", "per_window", false, "deterministic", 9, &["m1"], 9), true),
        ];
        for (finding, want) in cases {
            let rule = finding.rule_id.clone();
            assert_eq!(chargeable(&finding), want, "{rule}");
            let charged = !charges(&verdict(vec![finding]), &base()).is_empty();
            assert_eq!(charged, want, "{rule}: the filter and the charge disagree");
        }
    }

    /// The engine's raid aggravators describe a PERSON — an account under a
    /// day old, one that has posted twice — not an act, so they cite nothing
    /// and convict nobody on their own. Charging them made being new an
    /// offense for every member caught in a raid detection, with the raid
    /// switch off.
    #[test]
    fn a_finding_that_cites_nothing_charges_nothing() {
        let v = verdict(vec![
            f("fresh", "whole", false, "deterministic", 1, &[], 0),
            f("quiet", "whole", false, "deterministic", 1, &[], 0),
        ]);
        assert!(charges(&v, &base()).is_empty(), "a strike points at something the member did");
    }

    /// And the operator's own rules always do cite, so nothing real is lost.
    #[test]
    fn a_finding_that_cites_evidence_still_charges() {
        let v = verdict(vec![f("rate", "per_window", false, "deterministic", 20, &["m1"], 20)]);
        assert_eq!(charges(&v, &base()).len(), 1);
    }

    /// Both clocks describe an offence the same way, or a member's warning
    /// changes vocabulary depending on which one reached them first.
    #[test]
    fn both_clocks_describe_an_offence_the_same_way() {
        let mut with_detail = f("slurs", "per_message", true, "deterministic", 1, &["m1"], 1);
        with_detail.detail = vec!["badword".into()];
        assert_eq!(evidence_line(&with_detail), "Used \"badword\" (1 time)");

        with_detail.hits = 8;
        assert_eq!(evidence_line(&with_detail), "Used \"badword\" (8 times)", "plural");

        // Nothing quoted: name the rule rather than print engine vocabulary.
        let bare = f("rate", "per_window", false, "deterministic", 20, &["m1"], 20);
        assert_eq!(evidence_line(&bare), "Matched the \"rate\" rule");
        for machine in ["[", "]", "×"] {
            assert!(!evidence_line(&bare).contains(machine), "engine vocabulary reached a member");
        }
    }

    #[test]
    fn inference_never_earns_a_strike() {
        let v = verdict(vec![f("cohort", "whole", false, "heuristic", 1, &[], 0)]);
        assert!(charges(&v, &base()).is_empty(), "the engine's inference is reported, never charged");
    }

    /// A content rule convicts at BOTH scopes over the same citations, so
    /// charging the window rung too billed one offense twice.
    #[test]
    fn one_offense_is_not_billed_at_both_scopes() {
        let v = verdict(vec![
            f("slurs", "per_message", true, "deterministic", 3, &["m1", "m2", "m3"], 3),
            f("slurs", "per_window", false, "deterministic", 3, &["m1", "m2", "m3"], 3),
        ]);
        let got = charges(&v, &base());
        assert_eq!(got.len(), 3, "three messages, three charges");
        assert!(got.iter().all(|c| c.conviction.starts_with("msg:slurs:")));
    }

    /// Unless the per-message charges do NOT cover the evidence — then
    /// suppressing the window rung charged the worst offenders the least.
    #[test]
    fn the_window_rung_stands_when_the_citations_fall_short() {
        let v = verdict(vec![
            f("slurs", "per_message", true, "deterministic", 30, &["m1"], 30),
            f("slurs", "per_window", false, "deterministic", 30, &[], 30),
        ]);
        let got = charges(&v, &base());
        assert_eq!(got.len(), 2, "one cited message, plus the window rung it did not cover");
        assert!(got.iter().any(|c| c.conviction == "win:slurs:per_window:0"));
    }

    #[test]
    fn a_stateless_finding_citing_nothing_charges_nothing_and_suppresses_nothing() {
        let v = verdict(vec![
            f("slurs", "per_message", true, "deterministic", 1, &[], 1),
            f("slurs", "per_window", false, "deterministic", 1, &["m1"], 1),
        ]);
        let got = charges(&v, &base());
        assert_eq!(got.len(), 1, "the window rung is the only thing that charged");
        assert_eq!(got[0].conviction, "win:slurs:per_window:0");
    }

    /// Different rules never suppress each other.
    #[test]
    fn one_rules_per_message_charges_do_not_cover_another_rule() {
        let v = verdict(vec![
            f("slurs", "per_message", true, "deterministic", 1, &["m1"], 1),
            f("links", "per_window", false, "deterministic", 5, &["m1"], 5),
        ]);
        let got = charges(&v, &base());
        assert_eq!(got.len(), 2, "a link rule is not paid for by a word rule");
    }

    /// The engine keys a window conviction on the POLICY HASH, so editing any
    /// rule re-mints every standing one — and INSERT OR IGNORE would find no
    /// row, charge the whole open window again at `now`, and climb a rung for
    /// it. Sentinel mints its own, on the rule and scope and rung.
    #[test]
    fn a_rulebook_edit_does_not_re_charge_the_open_window() {
        let before = verdict(vec![f("rate", "per_window", false, "deterministic", 9, &["m1"], 9)]);
        let mut after_edit = before.clone();
        // Exactly what an edit changes upstream, and nothing else.
        after_edit.findings[0].conviction_id = "a-completely-different-hash".into();
        after_edit.findings[0].policy_hash = "H2".into();

        let a = charges(&before, &base());
        let b = charges(&after_edit, &base());
        assert_eq!(a, b, "the same offense under a rewritten rulebook is the same offense");
        assert!(!a[0].conviction.contains("hash"), "and the id carries no rulebook version");
    }

    /// Escalating a rung IS a new answer, though — that is the engine's design
    /// and the moment to act again.
    #[test]
    fn a_rung_escalation_is_a_new_offense() {
        let low = verdict(vec![f("rate", "per_window", false, "deterministic", 3, &["m1"], 3)]);
        let mut high = low.clone();
        high.findings[0].rung = 1;
        assert_ne!(charges(&low, &base())[0].conviction, charges(&high, &base())[0].conviction);
    }

    /// The id is what separates an offense from an echo of one, so the same
    /// verdict read twice has to mint the same ids.
    #[test]
    fn charging_is_deterministic() {
        let v = verdict(vec![
            f("slurs", "per_message", true, "deterministic", 2, &["m1", "m2"], 2),
            f("rate", "per_window", false, "deterministic", 9, &["m3"], 1),
        ]);
        let once = charges(&v, &base());
        let twice = charges(&v, &base());
        assert_eq!(once, twice);
        let ids: std::collections::HashSet<&str> = once.iter().map(|c| c.conviction.as_str()).collect();
        assert_eq!(ids.len(), once.len(), "and no id is minted twice");
    }

    /// The operator's scale, not the engine's.
    #[test]
    fn a_charge_is_worth_what_the_operator_said() {
        let mut cfg = crate::config::Config::default();
        cfg.rules.words = vec![crate::config::WordRule {
            id: "slurs".into(),
            title: String::new(), patterns: vec!["x".into()],
            gravity: crate::config::Gravity::Grave,
        }];
        let p = cfg.for_community("");
        let v = verdict(vec![f("slurs", "per_message", true, "deterministic", 1, &["m1"], 1)]);
        assert_eq!(charges(&v, &p)[0].worth, p.ladder.strikes.grave);
    }

    /// A member nothing convicted is charged nothing.
    #[test]
    fn a_clean_verdict_charges_nothing() {
        assert!(charges(&verdict(vec![]), &base()).is_empty());
    }

    /// Every charge carries a line a person can read.
    #[test]
    fn every_charge_cites_its_evidence() {
        let v = verdict(vec![f("slurs", "per_message", true, "deterministic", 2, &["m1", "m2"], 2)]);
        for c in charges(&v, &base()) {
            assert!(c.evidence.contains("slurs"), "{}", c.evidence);
            assert!(!c.conviction.is_empty());
        }
    }
}
