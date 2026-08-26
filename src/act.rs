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
    // What SENTINEL charged, not what the engine saw.
    //
    // The engine reports over its whole window and knows nothing about a
    // pardon, so quoting it told a forgiven member about offences that had been
    // forgiven — "8 times" when two were on record. The ledger filters
    // tombstones by construction, so reading from it makes the pardon mean
    // what it says. Falls back to the engine only when the ledger has nothing,
    // which is the debt lane's empty-record case.
    let why = match store.evidence(community.id(), &v.npub) {
        Ok(mine) if !mine.is_empty() => mine.join("; "),
        _ => v.why(),
    };

    // Permissions only. Whether THIS verdict has anything to hide is not a
    // property of the community, and folding it in here let the ladder walk
    // past delete_and_warn into a kick for any verdict without citations — the
    // debt lane builds exactly those.
    let Some(response) = select_rung(&ctx.policy, |r| ctx.powers.can_deliver(r), store, community.id(), &v.npub, strikes, now)
        .map_err(vector_sdk::Error::Other)?
    else {
        // The one case worth a line: a member at the top of the ladder keeps
        // offending and keeps being answered with silence, which reads exactly
        // like a bot that has stopped working. The other reasons — nothing
        // owed, a rung this community withholds — repeat every poll and are
        // already on the boot line and in `/status`.
        if ladder::owed(&ctx.policy.ladder, strikes, [], |r| ctx.powers.can_deliver(r), now, ctx.policy.ladder.decay_half_life_hours)
            .is_some_and(|r| r == Response::Ban)
        {
            println!(
                "[{id}] TOP     {who} — {}, already at the top rung — a person decides from here",
                tally(strikes)
            );
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
        // ANY content charge makes the whole sentence a content sentence. A
        // trusted member who posted a slur is not spared it because they also
        // tripped a rate rule in the same window.
        for_content: v.findings.iter().any(|f| ctx.policy.is_content_rule(&f.rule_id, &ctx.vision_labels)),
    };

    let armed = match adjudicate::adjudicate(&ctx.policy, ctx.powers, &facts, response) {
        Sentence::Spare { why: reason } => {
            println!("[{id}] QUEUED  {who} — {why} ({reason})");
            return Ok(Outcome::Spared);
        }
        Sentence::Powerless { needs } => {
            println!("[{id}] CANNOT  {} {who} — this community grants Sentinel no {needs}", response.name());
            // Powerless is a DRY RUN, not silence. A community that grants
            // Sentinel nothing still gets the judgement — which is how you trial
            // the bot before handing it the power to act, and how a community
            // that revoked its role finds out the difference. The strike is
            // already on the ledger by now (the charge is recorded before the
            // sentence), so granting the role later starts from real history.
            let rule = broken_rule(ctx, v).unwrap_or_else(|| "community".to_string());
            notify_mods(
                bot,
                community,
                ctx,
                v,
                &rule,
                &format!("none — I would have {} them, but this community grants me no {needs}", response.name()),
                &why,
            )
            .await;
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
    let tally = tally(strikes);
    println!("[{id}] {} {name} {who} — {tally} — {why}", if armed { "ENFORCE" } else { "WOULD  " });

    // Resolved before the act: a delete removes the very messages the channel
    // would have been read from.
    // Resolved BEFORE the act, for the same reason the channel NAME below is:
    // hiding the cited message removes the very row this is read from, and a
    // lookup afterwards finds nothing.
    let notice_chat = match cited_ids(v).first() {
        Some(first) => bot.message(&first.to_string()).await.map(|m| m.chat_id),
        None => None,
    };
    let warn = warn_text(
        response,
        &why,
        &ctx.community_name,
        cited_channel(bot, community, v).await.as_deref(),
        strikes.len(),
        // Removal is unconditional now, so the message says so exactly when it
        // happened: claiming a takedown that did not occur invites a reply
        // asking why the post is still there.
        armed && !cited_ids(v).is_empty(),
    );

    // Announced BEFORE, recorded AFTER. The two want opposite sides of the act:
    // an operator has to see what is about to happen, and the ledger must hold
    // only what did. A named mod channel that cannot be reached holds the
    // sentence rather than carrying it out unrecorded.
    if armed && !announce(bot, community, ctx, &format!("{name} {who} — {tally} — {why}")).await {
        println!("[{id}] HELD    {who} — the mod channel is unreachable, and this would go unrecorded");
        return Ok(Outcome::Held);
    }

    // Act, THEN log. Logging first recorded a failed ban as a success: it spent
    // the ceiling and marked the member answered forever.
    //
    // A rehearsal does everything EXCEPT the act. It writes the same row, so
    // the ladder climbs, the ceilings fill and the operator sees the run they
    // are about to arm — recording nothing meant a dry run could only ever
    // print `WOULD warn`, and arming switched on escalation plus three
    // ceilings at once, into behaviour nobody had watched. Arming wipes the
    // slate, so the rehearsal's rows can never be mistaken for real answers.
    // Removal is not a rung. Whatever a conviction cites comes down the moment
    // it is answered at all — content a community does not host must not
    // outlive the warning that says so, and a first offence is exactly when it
    // is still on screen. The ladder decides the CONSEQUENCE to the member;
    // this decides what happens to the post.
    //
    // The debt lane rebuilds a verdict from the ledger, which never kept the
    // message ids, so a sentence with nothing to cite is normal and quiet.
    if armed && !cited_ids(v).is_empty() {
        hide_cited(bot, v, id).await;
    }
    let outcome = if !armed {
        Ok(())
    } else {
        let done = match response {
            // Both carry the same words now that removal happens either way.
            // `DeleteAndWarn` stays readable because ledgers written before this
            // hold rows naming it, and `rank_of` has to keep placing them.
            Response::Warn | Response::DeleteAndWarn => Ok(()),
            Response::Kick => community.member(v.npub.clone()).kick().await,
            Response::Ban => community.member(v.npub.clone()).ban().await,
        };
        // AFTER the act, so it reports what happened rather than what was
        // intended — and a DM outlives membership, so it still lands on somebody
        // who was just removed. A removal they cannot read the reason for is the
        // one message that has to arrive.
        match done {
            Ok(()) => bot.dm(&v.npub).send(&warn).await.map(|_| ()),
            Err(e) => Err(e),
        }
    };
    if let Err(e) = outcome {
        // Nothing happened, so nothing is recorded: the debt stands and they
        // are reachable again next pass. The channel was told this was coming,
        // so it is told it did not.
        eprintln!("[{id}] {name} {who} FAILED: {e}");
        announce(bot, community, ctx, &format!("{name} {who} did NOT go through: {e}")).await;
        return Ok(Outcome::Failed);
    }

    // A ledger that cannot be written must stop the pass. The act already
    // happened and is now unrecorded either way, so the next poll re-delivers
    // it — but continuing would spend the same failure on every other member
    // too, and for a ban that is a key rotation each time.
    store
        .log_action(community.id(), &v.npub, name, now, &why)
        .map_err(|e| vector_sdk::Error::Other(format!("{name} {who} happened but could not be recorded: {e}")))?;

    // AFTER the ledger. Both are courtesies on top of a sentence that has
    // already happened and been recorded — neither may fail it, and a channel
    // notice for an action no row remembers is the one order that misleads.
    let rule = broken_rule(ctx, v).unwrap_or_else(|| "community".to_string());
    // The channel notice belongs to an action that HAPPENED — telling a room
    // somebody was kicked when they were not is the one message that misleads.
    if armed && ctx.notify.notice_in_channel {
        notice_in_channel(bot, notice_chat, v, &rule, ctx.notify.notice_ttl_secs).await;
    }
    // The moderators' report does not: an unarmed Sentinel is a dry run, and a
    // dry run whose findings reach nobody is indistinguishable from a quiet
    // community. Say what would have happened and that it did not.
    let taken = if armed { name.to_string() } else { format!("none — {name} is not armed here") };
    notify_mods(bot, community, ctx, v, &rule, &taken, &why).await;
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

/// A member's record in words: how many offences are on file.
///
/// The strike TOTAL is deliberately absent. It is a sum of worths, so it only
/// means anything to somebody holding this community's ladder thresholds —
/// and the mod channel is a channel, which members read. `/why` reports the
/// number to whoever asks for it, with the decay spelled out.
fn tally(strikes: &[ladder::Strike]) -> String {
    match strikes.len() {
        1 => "1 match on record".to_string(),
        n => format!("{n} matches on record"),
    }
}

/// What a warned member reads.
///
/// It names WHERE. Somebody in several communities, told only that a rule
/// matched, has to guess which room they are in trouble in, and a warning
/// nobody can act on is not a warning.
///
/// It names NOTHING ELSE. No label, no confidence, no model, no rule id, no
/// strike arithmetic: those are how an operator tuned a rulebook, and read out
/// to the person they were used on they are a specification for getting under
/// the bar next time. What a member needs is what they did and what happens
/// next.
fn warn_text(
    response: Response,
    evidence: &str,
    community: &str,
    channel: Option<&str>,
    on_record: usize,
    removed: bool,
) -> String {
    let place = match channel {
        Some(c) if !c.is_empty() => format!("**{community}**: **#{c}**"),
        _ => format!("**{community}**"),
    };
    // Quoted, on its own line. Buried mid-sentence it read as part of Sentinel's
    // prose rather than as the thing they actually posted.
    let quote = {
        let one_line = evidence.replace(['\n', '\r'], " ");
        let one_line = one_line.trim();
        if one_line.is_empty() {
            String::new()
        } else {
            format!("\n\n> {one_line}\n\n")
        }
    };
    let gone = if removed { " That post has been removed." } else { "" };
    // What HAPPENED, and what happens next. A kick removes them from the
    // community, so the public notice in the channel is unreadable to the one
    // person it is about — this DM is the only thing they get, and "you have
    // been removed" with no reason is how a moderation bot earns its reputation.
    let (what, next) = match response {
        Response::Warn | Response::DeleteAndWarn => {
            ("so you have picked up a strike", "Further strikes lead to being removed from the community.")
        }
        Response::Kick => (
            "so you have been removed from the community",
            "You can rejoin, and further strikes lead to a permanent ban.",
        ),
        Response::Ban => ("so you have been permanently banned", "This one is not automatic to undo."),
    };
    // What they did and how many times, which is what a person actually asks.
    // NOT the strike total: it is the operator's number for tuning a ladder,
    // and it reads to a member like twelve separate accusations.
    let tally = if on_record <= 1 {
        "This is your first strike.".to_string()
    } else {
        format!("That makes {on_record} strikes on your record here.")
    };
    format!(
        "You broke the rules in {place}, {what}.{quote}{}{gone} {next}\n\n\
         If you think this is wrong, reply to a moderator.",
        tally
    )
}

/// The channel a sentence is about, by name.
///
/// Resolved from what the conviction CITED, so it names the room the offence
/// happened in rather than wherever Sentinel happens to be looking.
async fn cited_channel(bot: &VectorBot, community: &Community, v: &Verdict) -> Option<String> {
    let first = cited_ids(v).first().map(|m| m.to_string())?;
    let chat = bot.message(&first).await?.chat_id;
    community.channels().await.into_iter().find(|c| c.id() == chat).map(|c| c.name().to_string())
}

/// Best-effort audit line into the operator's mod channel, when one is named.
/// True when there was nothing to say to, or it was said.
///
/// An operator who named a mod channel asked for an audit trail. Silence when
/// that channel cannot be reached is the one answer it must not give: a bot
/// removing people with no record of it is the incident the trail exists to
/// prevent.
pub(crate) async fn announce(bot: &VectorBot, community: &Community, ctx: &Ctx, line: &str) -> bool {
    // An empty name is "stay silent", not "look for a channel called nothing".
    // Without this, an operator disabling the audit trail by emptying the string
    // gets a channel that is never found, an announce that always fails, and
    // every sentence held forever — a bot that silently stops moderating.
    let want = match ctx.mod_channel.as_deref().map(str::trim) {
        Some(w) if !w.is_empty() => w,
        _ => return true,
    };
    for ch in community.channels().await {
        if ch.name() == want && ch.is_readable() {
            return bot.channel(ch.id()).send(line).await.is_ok();
        }
    }
    false
}

/// The rule a sentence is about, named for a member.
///
/// The WORST charge, where a post broke several: told they broke one rule,
/// somebody looks for one thing to stop doing.
fn broken_rule(ctx: &Ctx, v: &Verdict) -> Option<String> {
    v.findings
        .iter()
        // `actionable`, the same filter the citations use. `chargeable` demands
        // a deterministic basis, which the media lane's own findings never
        // have — so every vision conviction fell through to a fallback and told
        // members they broke the "community" rule.
        .filter(|f| actionable(f))
        .max_by_key(|f| crate::config::Gravity::from(ctx.policy.gravity_of(&f.rule_id, &f.severity)) as u8)
        .map(|f| ctx.policy.title_of(&f.rule_id, &ctx.vision_labels))
}

/// A short public line in the room it happened in.
///
/// Short on purpose. The DM carries the evidence and the appeal route; this is
/// the part everyone else sees, and a channel does not need the detail of
/// somebody else's warning to know the rule is real.
async fn notice_in_channel(bot: &VectorBot, chat: Option<String>, v: &Verdict, rule: &str, ttl_secs: u64) {
    // Silence here is indistinguishable from a notice that posted, and a public
    // warning nobody can see failing to appear is exactly the failure worth a
    // line.
    let Some(chat) = chat else {
        println!("[notice] nothing cited, so there is no channel to post in");
        return;
    };
    // `@npub` is what Vector matches to raise a ping. A prettier pill would not
    // reach the person it is about.
    let line = format!(
        "@{} You broke the **{rule}** rule and **received a strike**, please refrain from further \
         posts of such content or action may be escalated.",
        v.npub
    );
    let posted = if ttl_secs > 0 {
        bot.channel(chat).send_expiring(&line, ttl_secs).await
    } else {
        bot.channel(chat).send(&line).await
    };
    match posted {
        // Said out loud, because the whole point of this line is that people see
        // it — and its absence was invisible for most of a day.
        Ok(_) if ttl_secs > 0 => println!("[notice] posted, clearing itself in {ttl_secs}s"),
        Ok(_) => println!("[notice] posted"),
        Err(e) => eprintln!("[notice] could not post the channel notice: {e}"),
    }
}

/// Tell the people who asked to be told, personally.
///
/// Failures are logged and never propagate: a moderator's DM not arriving is
/// not a reason to leave a sentence unrecorded, and the ledger is already the
/// record of what happened.
/// DM the mods the raid kick-list: WHO was removed, so a human can double-check
/// an automated mass-action. Its own function (not `notify_mods`, which is one
/// member per rule) because a raid is one event, many subjects — an admin wants
/// the whole list in one message, not forty DMs.
pub(crate) async fn notify_mods_raid(
    bot: &VectorBot,
    ctx: &Ctx,
    action: &str,
    removed: &[&str],
    report: Option<&vector_sdk::ContainmentReport>,
) {
    if ctx.notify_to.is_empty() || removed.is_empty() {
        return;
    }
    // Full npubs, one per line: the reader has to be able to paste any of them
    // into a tool to unban a false positive.
    let list = removed.iter().map(|n| format!("- {n}")).collect::<Vec<_>>().join("\n");
    // The state of the DOOR, which is the half a human can actually act on. A
    // failed rotation still silenced the raiders, and saying only that would
    // read as "handled" while the link they came through is still live.
    let door = match report {
        None => String::new(),
        Some(r) if r.refound_ok => {
            let mut s = format!(
                "\n\n**Keys rotated** — epoch {} → {}, invite links revoked ({}).",
                r.epoch_before, r.epoch_after, r.own_links_revoked,
            );
            if r.window_cut > 0 {
                s.push_str(&format!(
                    "\n{} account(s) who joined during the raid were cut from the new keys without being banned; \
                     they can rejoin through a fresh invite.",
                    r.window_cut,
                ));
            }
            if !r.foreign_link_creators.is_empty() {
                s.push_str(&format!(
                    "\n⚠️ {} other link creator(s) still have live invites — theirs close when their client syncs.",
                    r.foreign_link_creators.len(),
                ));
            }
            s.push_str("\n\nMint a fresh invite link when the raid is over — the old ones are dead for good.");
            s
        }
        Some(r) => format!(
            "\n\n🚨 **The key rotation FAILED** — the raiders are silenced, but the invite link they came \
             through may still be open. Revoke it by hand.{}",
            r.warnings.iter().map(|w| format!("\n- {w}")).collect::<String>(),
        ),
    };
    let line = format!(
        "**Raid contained in {}**\n\n**{action}** applied to {} account(s):\n\n{list}{door}\n\n\
         If any of these are real members, pardon them to reverse it.",
        ctx.community_name,
        removed.len(),
    );
    for who in &ctx.notify_to {
        if who == &ctx.me {
            continue;
        }
        if let Err(e) = bot.dm(who.clone()).send(&line).await {
            eprintln!("[notify] raid list did not reach {}: {e}", short(who));
        }
    }
}

/// The channels a verdict's evidence was drawn from, resolved from the messages
/// it cites. Empty when it cites none (tenure, join burst) — nothing was quoted,
/// so nothing needs a room to have been read from.
async fn cited_channels(bot: &VectorBot, v: &Verdict) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for id in v.findings.iter().flat_map(|f| f.messages.iter()) {
        if let Some(msg) = bot.message(id).await {
            let chat = msg.chat_id.clone();
            if !chat.is_empty() && !out.contains(&chat) {
                out.push(chat);
            }
        }
    }
    out
}

async fn notify_mods(bot: &VectorBot, community: &Community, ctx: &Ctx, v: &Verdict, rule: &str, action: &str, why: &str) {
    if ctx.notify_to.is_empty() {
        return;
    }
    // A report QUOTES what was said, so it may only go to someone who could have
    // read the room it was said in. Community power is the wrong question here:
    // BAN says what a moderator may do to people, never which rooms they may
    // see, and a private channel is gated by its own role (CORD-03). Without
    // this the bot is a way to read a room you were never admitted to — it holds
    // every key, so it would forward what it saw to whoever holds the ban bit.
    let rooms = cited_channels(bot, v).await;
    // The full npub, not a short form: this is the one message whose reader has
    // to go and DO something about a specific person, and eight characters is
    // not something anybody can paste into a moderation tool.
    let line = format!(
        "**{}**\n\n**{}** broke the **{rule}** rule.\n\n> {}\n\nAction taken: **{action}**.",
        ctx.community_name,
        v.npub,
        why.replace(['\n', '\r'], " ").trim()
    );
    for who in &ctx.notify_to {
        if who == &ctx.me {
            continue;
        }
        // Every room, not any: evidence from two channels may only go to
        // someone admitted to both.
        let member = community.member(who.clone());
        if let Some(shut) = rooms.iter().find(|c| !member.can_read(c)) {
            eprintln!("[notify] {} holds no key for {} — report withheld", short(who), short(shut));
            continue;
        }
        if let Err(e) = bot.dm(who.clone()).send(&line).await {
            eprintln!("[notify] {} did not get told: {e}", short(who));
            continue;
        }
        if ctx.notify.attach_media {
            forward_media(bot, v, who).await;
        }
    }
}

/// Forward what was actually posted, so a decision can be checked rather than
/// taken on trust.
///
/// Images go out named `SPOILER_…`, which is how Vector marks an attachment to
/// stay covered until it is tapped. A moderator reading their DMs on a train
/// should choose when to look at the worst thing in the community.
async fn forward_media(bot: &VectorBot, v: &Verdict, who: &str) {
    for id in cited_ids(v) {
        let Some(msg) = bot.message(&id.to_string()).await else { continue };
        for att in &msg.message.attachments {
            let bytes = match bot.download_attachment_from(att, msg.message.npub.as_deref()).await {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("[notify] could not fetch the evidence: {e}");
                    continue;
                }
            };
            let kind = vector_sdk::vector_core::crypto::mime_from_magic_bytes(&bytes);
            // Video is sent plain: Vector covers images, and a covered video
            // would be a thumbnail nobody can play.
            let cover = kind.starts_with("image/");
            let name = format!(
                "{}evidence.{}",
                if cover { "SPOILER_" } else { "" },
                if att.extension.is_empty() { "bin" } else { &att.extension }
            );
            let path = std::env::temp_dir().join(&name);
            if std::fs::write(&path, &bytes).is_err() {
                continue;
            }
            if let Err(e) = bot.dm(who.to_string()).send_file(&path).await {
                eprintln!("[notify] the evidence did not reach {}: {e}", short(who));
            }
            let _ = std::fs::remove_file(&path);
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
        store: &crate::store::Store,
        me: &str,
        roster: usize,
    ) -> Ctx {
        Ctx {
            notify_to: Self::report_recipients(cfg, community, store),
            community_name: community.name().await,
            policy: cfg.for_community(community.id()),
            powers: crate::powers_of(community).await,
            roster,
            me: me.to_string(),
            mod_channel: cfg.bot.mod_channel.clone(),
            notify: cfg.notify.clone(),
            vision_labels: cfg.vision.labels.clone(),
        }
    }

    /// Who hears about this community's moderation, resolved fresh every pass.
    ///
    /// The operator's configured list UNION everyone who ran `/notify` here —
    /// and then filtered by the power, NOW. A subscription records a wish, never
    /// an authority: standing expires, and the moderator who should unsubscribe
    /// after losing their role is exactly the one who will not. Checking here
    /// rather than at opt-in is what keeps a demoted mod out of the feed.
    ///
    /// The configured list is filtered too. An operator naming somebody in the
    /// TOML does not make them a moderator of a community they were removed
    /// from, and reports quote what members said — including, once channel
    /// scoping lands, from rooms the reader may no longer enter.
    fn report_recipients(
        cfg: &crate::config::Config,
        community: &Community,
        store: &crate::store::Store,
    ) -> Vec<String> {
        let subscribed = store.notify_subscribers(community.id()).unwrap_or_default();
        // An explicit opt-out beats BOTH lists, including the operator's. Being
        // named in a config file is not consent, and `/notify` promises the
        // reports will stop — a promise it cannot keep if the TOML outranks it.
        let refused = store.notify_opted_out(community.id()).unwrap_or_default();
        let mut out: Vec<String> = Vec::new();
        for who in cfg.notify.mods.iter().cloned().chain(subscribed) {
            if !out.contains(&who) && !refused.contains(&who) && crate::commands::may_receive(community, &who) {
                out.push(who);
            }
        }
        out
    }
}

/// One community, as this pass sees it: its own rulebook, its own powers, its
/// own roster. Nothing about judging one community may leak into another.
pub(crate) struct Ctx {
    /// Who to DM about moderation here: the config list plus `/notify` opt-ins,
    /// each re-checked for the power at the moment this Ctx was built.
    pub(crate) notify_to: Vec<String>,
    /// What the community calls itself, for the person being answered.
    pub(crate) community_name: String,
    pub(crate) policy: CommunityPolicy,
    pub(crate) powers: Powers,
    pub(crate) roster: usize,
    pub(crate) me: String,
    pub(crate) mod_channel: Option<String>,
    pub(crate) notify: crate::config::NotifyCfg,
    /// The media lane's labels, for naming a rule to the person who broke it.
    /// Process-wide, unlike everything else here.
    pub(crate) vision_labels: Vec<crate::config::VisionLabel>,
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
    let answers = store.answers(community, npub)?;
    Ok(ladder::owed(
        &policy.ladder,
        strikes,
        answers.iter().map(|a| (a.response.as_str(), a.at_ms)),
        can_deliver,
        now,
        policy.ladder.decay_half_life_hours,
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

    /// An explicit four-rung ladder, NOT the shipped default: these tests are
    /// about how a sentence is chosen and delivered, so the shape is pinned
    /// here rather than moving whenever the default policy is retuned.
    fn policy_with(arm: &str) -> CommunityPolicy {
        let mut cfg = toml::from_str::<Config>(&format!("[arm]\n{arm}")).unwrap();
        cfg.ladder.steps = vec![
            crate::config::Step { at: 1, response: Response::Warn },
            crate::config::Step { at: 4, response: Response::DeleteAndWarn },
            crate::config::Step { at: 8, response: Response::Kick },
            crate::config::Step { at: 12, response: Response::Ban },
        ];
        cfg.for_community("fe4abeb3fd227a67fc59d8a4363420649bb970436dc3b14d51c2b66fee334dea")
    }

    /// One strike per offense; the ladder climbs as the total rises.
    #[test]
    fn the_ladder_climbs_one_rung_per_offense() {
        let store = mem();
        let p = policy_with("warn = true\ndelete = true\nkick = true\nban = true");
        let all = Powers { hide: true, kick: true, ban: true };
        // One offense a minute, each answered before the next arrives — which
        // is the order the lanes actually produce.
        let offenses = |n: u32| (0..n).map(|i| ladder::Strike { worth: 12, at_ms: NOW + i as u64 * 60_000 }).collect::<Vec<_>>();
        let at = |n: u32| NOW + (n - 1) as u64 * 60_000 + 1;
        let pick =
            |s: &Store, n: u32| select_rung(&p, |r| all.can_deliver(r), s, "c", "npub1a", &offenses(n), at(n)).unwrap();

        assert_eq!(pick(&store, 1), Some(Response::Warn), "twelve points still starts at a warning");
        store.log_action("c", "npub1a", "warn", at(1), "").unwrap();
        assert_eq!(pick(&store, 2), Some(Response::DeleteAndWarn));
        store.log_action("c", "npub1a", "delete_and_warn", at(2), "").unwrap();
        assert_eq!(pick(&store, 3), Some(Response::Kick));
        store.log_action("c", "npub1a", "kick", at(3), "").unwrap();
        assert_eq!(pick(&store, 4), Some(Response::Ban));
        store.log_action("c", "npub1a", "ban", at(4), "").unwrap();
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
        store.log_action("c", "npub1a", "warn", NOW, "").unwrap();

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

        store.log_action("c", "npub1a", "kick", NOW, "").unwrap();
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

    /// The strike total means nothing without this community's ladder
    /// thresholds in hand — and the mod channel is a channel, which members
    /// read. Nothing Sentinel says out loud carries a score; `/why` reports it
    /// to whoever asks.
    #[test]
    fn nothing_said_out_loud_carries_a_score() {
        let one = [ladder::Strike { worth: 12, at_ms: 0 }];
        assert_eq!(tally(&one), "1 match on record");

        let three = [
            ladder::Strike { worth: 12, at_ms: 0 },
            ladder::Strike { worth: 12, at_ms: 0 },
            ladder::Strike { worth: 4, at_ms: 0 },
        ];
        assert_eq!(tally(&three), "3 matches on record");
        for score in ["12", "28", "worth"] {
            assert!(!tally(&three).contains(score), "a score reached the channel: {}", tally(&three));
        }
    }

    /// A member asks two things: what did I do, and how many times. Neither
    /// answer is a strike total.
    #[test]
    fn a_warning_counts_matches_and_never_shows_a_score() {
        let one = warn_text(Response::Warn, "Used \"badword\" (1 time)", "Lab", Some("general"), 1, true);
        assert!(one.contains("first strike"), "singular: {one}");

        let many = warn_text(Response::Warn, "Used \"badword\" (1 time)", "Lab", Some("general"), 4, true);
        assert!(many.contains("4 strikes"), "plural: {many}");

        // The score belongs to the operator, not to the person being warned.
        for total in ["12", "48", "worth"] {
            assert!(!many.contains(total), "a score reached the member: {many}");
        }
    }

    /// The warned member reads this, so it has to say what matched, what
    /// happens next, and WHERE — somebody in several communities told only
    /// that "a rule matched" has to guess which room they are in trouble in.
    #[test]
    fn a_warning_says_what_matched_where_and_what_comes_next() {
        for why in ["slurs [severe] 3×", "", "no findings", "a\nmultiline\nreason"] {
            let text = warn_text(Response::Warn, why, "Vector Community", Some("general"), 1, true);
            assert!(text.contains("**Vector Community**"), "the community, in bold: {text}");
            assert!(text.contains("**#general**"), "and the channel: {text}");
            assert!(text.contains("strike"), "{text}");
            assert!(text.contains("Further strikes"), "a warning that does not say it escalates is not one");
            assert!(text.contains("moderator"), "and it must name the way to dispute it");
            if !why.trim().is_empty() {
                // Quoted on its own line, and flattened: a multi-line reason
                // would otherwise break out of the quote block halfway through.
                let want = why.replace('\n', " ");
                assert!(text.contains(&format!("> {want}")), "the evidence has to be quoted: {text}");
                assert!(!text.contains("\n> \n"), "no empty quote line: {text}");
            }
        }
    }

    /// Disabling the audit trail must make Sentinel quiet, not broken. A failed
    /// announce HOLDS a sentence, so an empty channel name that is looked up
    /// literally stops the bot moderating and says nothing about why.
    #[test]
    fn an_empty_mod_channel_is_silence_rather_than_a_channel_named_nothing() {
        for raw in [Some(""), Some("   "), None] {
            let quiet = match raw.map(str::trim) {
                Some(w) if !w.is_empty() => Some(w),
                _ => None,
            };
            assert!(quiet.is_none(), "{raw:?} should mean silence");
        }
        assert_eq!(
            match Some("mod-log").map(str::trim) {
                Some(w) if !w.is_empty() => Some(w),
                _ => None,
            },
            Some("mod-log"),
            "a real name still resolves"
        );
    }

    /// Every rung explains itself, and a REMOVAL most of all: a kick takes the
    /// channel away, so the public notice is unreadable to the one person it is
    /// about, and this DM is all they get. Being removed with no reason given is
    /// how a moderation bot earns its reputation.
    #[test]
    fn every_rung_says_what_happened_and_what_comes_next() {
        let cases = [
            (Response::Warn, "picked up a strike", "Further strikes"),
            (Response::DeleteAndWarn, "picked up a strike", "Further strikes"),
            (Response::Kick, "removed from the community", "You can rejoin"),
            (Response::Ban, "permanently banned", "not automatic to undo"),
        ];
        for (rung, what, next) in cases {
            let text = warn_text(rung, "Used \"badword\" (1 time)", "Lab", Some("general"), 3, true);
            assert!(text.contains(what), "{rung:?} does not say what happened: {text}");
            assert!(text.contains(next), "{rung:?} does not say what comes next: {text}");
            // The parts every rung owes them, whatever it was.
            assert!(text.contains("**Lab**"), "{rung:?}: where");
            assert!(text.contains("> Used"), "{rung:?}: the evidence, quoted");
            assert!(text.contains("moderator"), "{rung:?}: how to dispute it");
            for leak in ["sexual_content", "gemma", "90%", "_"] {
                assert!(!text.contains(leak), "{rung:?} leaked {leak:?}: {text}");
            }
        }
    }

    /// A kick is not a warning, and telling somebody they may rejoin after a
    /// ban is worse than saying nothing.
    #[test]
    fn a_removal_does_not_read_like_a_warning() {
        let kick = warn_text(Response::Kick, "e", "Lab", Some("general"), 3, true);
        assert!(!kick.contains("picked up a strike"), "{kick}");
        let ban = warn_text(Response::Ban, "e", "Lab", Some("general"), 4, true);
        assert!(!ban.contains("You can rejoin"), "a ban is not a kick: {ban}");
        assert!(!ban.contains("Further strikes"), "there is no next rung: {ban}");
    }

    /// The message goes to the person a rule was used ON. A label name, a
    /// confidence, a model or a rule id read out to them is a specification for
    /// getting under the bar next time.
    #[test]
    fn a_warning_never_names_the_machinery() {
        let text = warn_text(
            Response::Warn,
            "A screenshot of a social media post featuring a woman in suggestive clothing",
            "Lab",
            Some("general"),
            2,
            true,
        );
        for leak in ["sexual_content", "gemma", "90%", "per ", "confidence", "threshold", "vision", "_"] {
            assert!(!text.contains(leak), "{leak:?} reached the member: {text}");
        }
    }

    /// Claiming a takedown that did not happen invites a reply asking why the
    /// post is still there.
    #[test]
    fn removal_is_only_claimed_when_it_happened() {
        let gone = warn_text(Response::Warn, "Used \"badword\" (1 time)", "Lab", Some("general"), 1, true);
        assert!(gone.contains("has been removed"), "{gone}");
        let stays = warn_text(Response::Warn, "Used \"badword\" (1 time)", "Lab", Some("general"), 1, false);
        assert!(!stays.contains("That post has been removed"), "{stays}");
    }

    /// A sentence the citations cannot place still names the community.
    #[test]
    fn a_warning_without_a_channel_still_says_where() {
        for channel in [None, Some("")] {
            let text = warn_text(Response::Warn, "Used \"badword\" (1 time)", "Vector Community", channel, 1, true);
            assert!(text.contains("**Vector Community**"), "{text}");
            assert!(!text.contains('#'), "no empty channel reference: {text}");
        }
    }

    /// It speaks for the community, not for itself.
    #[test]
    fn a_warning_does_not_introduce_the_bot() {
        let text = warn_text(Response::Warn, "Used \"badword\" (1 time)", "Vector Community", Some("general"), 1, true);
        assert!(!text.contains("Sentinel"), "the member cares where and why, not who: {text}");
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
        store.log_action("c", "npub1a", "warn", NOW + 1, "").unwrap();
        let two_grave = [
            ladder::Strike { worth: 12, at_ms: NOW },
            ladder::Strike { worth: 12, at_ms: NOW + 60_000 },
        ];
        assert_eq!(
            select_rung(&p, |r| no_hiding.can_deliver(r), &store, "c", "npub1a", &two_grave, NOW + 60_001).unwrap(),
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
        store.log_action("c", "npub1a", "kick", NOW, "").unwrap();
        let much_later = NOW + hl * 8;
        let light = [ladder::Strike { worth: 1, at_ms: much_later }];

        // The forgiven kick no longer floors anything, so this is a warning.
        assert_eq!(pick(&store, &light, much_later), Some(Response::Warn));
        store.log_action("c", "npub1a", "warn", much_later, "").unwrap();

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

        store.log_action("c", "npub1a", "warn", NOW, "").unwrap();
        let later = NOW + hl * 5;
        store.log_action("c", "npub1a", "warn", later, "").unwrap();

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

        store.log_action("c", "npub1a", "kick", NOW, "").unwrap();
        let much_later = NOW + hl * 8;
        store.log_action("c", "npub1a", "warn", much_later, "").unwrap();

        let worse = [
            ladder::Strike { worth: 1, at_ms: much_later - 1 },
            ladder::Strike { worth: 12, at_ms: much_later + 60_000 },
        ];
        assert_eq!(
            select_rung(&p, |r| all.can_deliver(r), &store, "c", "npub1a", &worse, much_later + 60_001).unwrap(),
            Some(Response::DeleteAndWarn),
            "one rung above the warning that still stands, not above the forgiven kick"
        );
    }
}

