//! What an operator can ask Sentinel from inside a community.

use std::sync::Arc;

use vector_sdk::vector_core::community::roles::Permissions;
use vector_sdk::VectorBot;

use crate::config::Config;
use crate::policy::{CommunityPolicy, SettingKey};
use crate::store::Store;
use crate::{
    now_ms, powers_of, short,
};
use crate::ladder;

/// What an operator can ask Sentinel from inside a community.
///
/// Read-only by default. `pardon` is the one command that changes anything, and
/// it answers only to someone the community already trusts to moderate — a bot
/// with no undo is not deployable, and an undo anyone can call is not either.
/// What `/why` answers.
///
/// Reads `ladder::owed`, the same function the enforcer does, so an operator is
/// never told about a ladder different from the one that will run: the naive
/// answer ("the next step above your total") ignored what they had already
/// received and every rung this community grants no permission for.
pub(crate) fn why_line(
    who: &str,
    shield: &str,
    strikes: &[ladder::Strike],
    answers: &[crate::store::Answer],
    policy: &CommunityPolicy,
    powers: crate::policy::Powers,
    now: u64,
) -> String {
    // A card, not a sentence. An operator runs this mid-incident with a member
    // list open; the three things they are deciding on — how bad, whether the
    // gates spare them, what lands next — should be readable without parsing
    // prose.
    let standing = crate::adjudicate::spared_by_standing(policy, shield);
    let n = strikes.len();
    let dot = match (standing.is_some(), n) {
        (true, _) => "🛡️",
        (_, 0) => "🟢",
        (_, 1) => "🟡",
        (_, 2) => "🟠",
        _ => "🔴",
    };
    let standing_line = match standing {
        Some(why) => format!("✅ {why}"),
        None => "❌ none".to_string(),
    };
    // The SAME unit the ladder is set in, against the rung it is heading for.
    //
    // This card used to print the number of offences under the word "Strikes"
    // while `/ladder` set its rungs in weighted, decayed strike VALUE — two
    // unrelated quantities sharing one word. An operator who set kick at 100
    // watched somebody removed at "84" and could not reconcile it, because a
    // grave offence is worth 12 and a note is worth 1. Offences are still shown;
    // they are just no longer called the same thing as the score.
    let total = ladder::total(strikes, now, policy.ladder.decay_half_life_hours);
    let heading_for = policy.ladder.steps.iter().find(|s| s.at > total);
    let score_line = match heading_for {
        Some(step) => format!("{total} of {} → {}", step.at, step.response.label()),
        None => format!("{total} (past every rung)"),
    };
    let offences = if n == 0 { "none".to_string() } else { n.to_string() };
    let mut card = format!(
        "{dot} **{}**\n**Strikes** · {score_line}\n**Offences** · {offences}\n**Standing** · {standing_line}",
        short(who)
    );
    if n == 0 {
        return card;
    }
    // Standing is asked exactly as every lane asks it. The ladder is shared
    // between this answer and the enforcer; the gates are not, so naming a rung
    // for somebody the gate always spares describes a run that will not happen.
    //
    // No Next line rather than a reassuring one: standing spares the BEHAVIOURAL
    // rules only. The word and link lists still answer for what they post,
    // whoever they are, so "nothing will happen to them" would be a lie.
    if standing.is_some() {
        return card;
    }
    let hl = policy.ladder.decay_half_life_hours;
    let next = ladder::owed(
        &policy.ladder,
        strikes,
        answers.iter().map(|a| (a.response.as_str(), a.at_ms)),
        |r| powers.can_deliver(r),
        now,
        hl,
    );
    // The decayed total is the ladder's own arithmetic. An operator asking about
    // a person wants what they did and what happens next, not a score.
    match next {
        Some(r) => card.push_str(&format!("\n**Next** · {}", r.label())),
        None => card.push_str("\n**Next** · nothing pending"),
    }
    card
}

/// Register every command Sentinel answers. One function per command, because
/// each carries its own clone dance and they share nothing but the bot.
pub(crate) fn operator_surface(bot: &VectorBot, cfg: &Arc<Config>, store: &Arc<Store>, wires: &crate::Watches) {
    status(bot, cfg);
    why(bot, cfg, store, wires);
    pardon(bot, cfg, store);
    enforce(bot, cfg, "kick", Permissions::KICK);
    enforce(bot, cfg, "ban", Permissions::BAN);
    notify(bot, cfg, store);
    blocklist(bot, cfg, store, "words");
    blocklist(bot, cfg, store, "links");
    ladder_cmd(bot, cfg, store);
}

/// `/ladder` — how many strikes each response answers to.
///
/// Shown to any moderator, changed by an admin. The engine's own validator
/// decides what is legal: rungs must ascend and must never de-escalate, so a
/// community cannot ask for a ban before a warning or two rungs on one total.
/// Refusing with its reason beats a UI that has to re-implement those rules and
/// drift from them.
fn ladder_cmd(bot: &VectorBot, cfg: &Arc<Config>, store: &Arc<Store>) {
    bot.command("ladder", "How many strikes each action answers to")
        .choice("action", "Which action to re-aim", ["warn", "delete", "kick", "ban"], false)
        .number("at", "Strike total that triggers it", false)
        .run({
            let (cfg, store) = (cfg.clone(), store.clone());
            move |ctx| {
                let (cfg, store) = (cfg.clone(), store.clone());
                async move {
                    let Some(community) = ctx.msg.community().filter(|c| cfg.watches(c.id())) else {
                        let _ = ctx.reply("I am not watching this community.").await;
                        return;
                    };
                    let Some(caller) = ctx.msg.author() else { return };
                    let member = community.member(caller.clone());
                    if !NOTIFY_NEEDS.iter().any(|p| member.can(*p)) {
                        let _ = ctx.reply("Only this community's moderators can see the ladder.").await;
                        return;
                    }
                    let current = cfg.for_community(community.id());
                    let show = |p: &CommunityPolicy| {
                        let worth = &p.ladder.strikes;
                        // Rungs are counted in STRIKES, and an offence is worth
                        // more than one of them — that mismatch is the whole
                        // reason someone set kick to 100 and watched it fire at
                        // what looked like 84. So every rung says how many grave
                        // offences it actually is.
                        let per_grave = worth.grave.max(1);
                        format!(
                            "An offence is worth: note {} · minor {} · serious {} · grave {} strike(s).\n\
                             Strikes halve every {}h, so a quiet member falls back down the ladder.\n\n{}",
                            worth.note, worth.minor, worth.serious, worth.grave,
                            p.ladder.decay_half_life_hours,
                            p.ladder
                                .steps
                                .iter()
                                .map(|s| format!(
                                    "- **{}** at {} strike(s) — about {} grave offence(s)",
                                    s.response.name(),
                                    s.at,
                                    s.at.div_ceil(per_grave)
                                ))
                                .collect::<Vec<_>>()
                                .join("\n")
                        )
                    };

                    let (Some(action), Some(at)) = (ctx.str("action").map(str::to_string), ctx.number("at")) else {
                        let _ = ctx.reply(show(&current)).await;
                        return;
                    };
                    if !member.can(CONFIG_NEEDS) {
                        let _ = ctx.reply("Changing the ladder needs the manage-roles permission.").await;
                        return;
                    }
                    if cfg.pinned(community.id(), SettingKey::LadderSteps) {
                        let _ = ctx.reply("This community's ladder is set by the bot operator and cannot be changed here.").await;
                        return;
                    }
                    let at = at.round();
                    if !(1.0..=1_000_000.0).contains(&at) {
                        let _ = ctx.reply("A rung answers to a strike total between 1 and 1000000.").await;
                        return;
                    }
                    let at = at as u32;
                    let response = match action.as_str() {
                        "warn" => crate::config::Response::Warn,
                        "delete" => crate::config::Response::DeleteAndWarn,
                        "kick" => crate::config::Response::Kick,
                        _ => crate::config::Response::Ban,
                    };
                    // Re-aim that rung and leave the others where they are. Sorted,
                    // because the ladder is read in order and the validator refuses
                    // one that is not — better to sort than to reject a change that
                    // only arrived out of sequence.
                    let mut steps: Vec<crate::config::Step> =
                        current.ladder.steps.iter().filter(|s| s.response != response).cloned().collect();
                    steps.push(crate::config::Step { at, response });
                    steps.sort_by_key(|s| s.at);

                    let outcome = cfg.set_chat_override(community.id(), &store, |o| {
                        o.ladder.get_or_insert_with(Default::default).steps = Some(steps);
                    });
                    let text = match outcome {
                        Ok(()) => {
                            let now = cfg.for_community(community.id());
                            format!("**{}** now answers to {at} strike(s).\n\n{}", response.name(), show(&now))
                        }
                        Err(e) => format!("Refused: {e}"),
                    };
                    let _ = ctx.reply(text).await;
                }
            }
        });
}

/// The power to CONFIGURE Sentinel. Deliberately above the moderation bits:
/// tuning the rulebook is administering the community, not doing a day's
/// moderation in it, and someone trusted to remove a spammer is not
/// automatically someone trusted to decide what counts as one.
const CONFIG_NEEDS: u64 = Permissions::MANAGE_ROLES;

/// `/words` and `/links` — the community's own blocklists, edited from chat.
///
/// One rule per list, under an id the community owns, so an operator's own
/// entries in the TOML are never touched by a chat edit. Removing the last
/// pattern removes the rule rather than leaving one that matches nothing.
///
/// The change is ANNOUNCED where it was made. A quiet edit to what the bot
/// blocks is indistinguishable from the bot being broken, and an admin
/// narrowing the list to nothing should not be something only they know about.
fn blocklist(bot: &VectorBot, cfg: &Arc<Config>, store: &Arc<Store>, which: &'static str) {
    let describe = if which == "words" { "Words this community blocks" } else { "Link domains this community blocks" };
    bot.command(which, describe)
        .choice("action", "add, remove, or list", ["add", "remove", "list"], true)
        .string("value", if which == "words" { "The word or phrase" } else { "The domain" }, false)
        .run({
            let (cfg, store) = (cfg.clone(), store.clone());
            move |ctx| {
                let (cfg, store) = (cfg.clone(), store.clone());
                async move {
                    let Some(community) = ctx.msg.community().filter(|c| cfg.watches(c.id())) else {
                        let _ = ctx.reply("I am not watching this community.").await;
                        return;
                    };
                    let action = ctx.str("action").unwrap_or("list").to_string();
                    let current = cfg.for_community(community.id());
                    let listed: Vec<String> = if which == "words" {
                        current.rules.words.iter().flat_map(|w| w.patterns.iter().cloned()).collect()
                    } else {
                        current.rules.links.iter().flat_map(|l| l.domains.iter().cloned()).collect()
                    };

                    // Reading is gated too, and not for tidiness: a blocklist is an
                    // EVASION MAP. Anyone who can see it knows exactly which words to
                    // avoid or obfuscate, which is the same reason the media lane never
                    // quotes its label and confidence at the member it warns. Moderators
                    // see the rules they enforce; changing them takes more.
                    let Some(caller) = ctx.msg.author() else { return };
                    let member = community.member(caller.clone());
                    if !NOTIFY_NEEDS.iter().any(|p| member.can(*p)) {
                        let _ = ctx.reply(format!("Only this community's moderators can see the blocked {which}.")).await;
                        return;
                    }

                    if action == "list" {
                        let text = if listed.is_empty() {
                            format!("No {which} are blocked here.")
                        } else {
                            // Inline code, because a pattern is not prose: `*spam*`
                            // is a wildcard and markdown would render it as
                            // emphasis, showing the operator something they did
                            // not write and cannot copy back.
                            format!(
                                "Blocked {which} ({}):\n{}",
                                listed.len(),
                                listed.iter().map(|v| format!("- `{v}`")).collect::<Vec<_>>().join("\n")
                            )
                        };
                        let _ = ctx.reply(text).await;
                        return;
                    }

                    if !member.can(CONFIG_NEEDS) {
                        let _ = ctx.reply("Changing what this community blocks needs the manage-roles permission.").await;
                        return;
                    }
                    let key = if which == "words" { SettingKey::Words } else { SettingKey::Links };
                    if cfg.pinned(community.id(), key) {
                        let _ = ctx
                            .reply(format!("This community's {which} list is set by the bot operator and cannot be changed here."))
                            .await;
                        return;
                    }
                    let Some(value) = ctx
                        .str("value")
                        // A backtick would break out of the inline code every
                        // reply renders these in, and no pattern needs one.
                        .map(|v| v.trim().to_lowercase().replace('`', ""))
                        .filter(|v| !v.is_empty())
                    else {
                        let _ = ctx.reply(format!("Give me a {} to {action}.", if which == "words" { "word" } else { "domain" })).await;
                        return;
                    };

                    let adding = action == "add";
                    if adding && listed.iter().any(|v| v == &value) {
                        let _ = ctx.reply(format!("`{value}` is already blocked.")).await;
                        return;
                    }
                    if !adding && !listed.iter().any(|v| v == &value) {
                        let _ = ctx.reply(format!("`{value}` is not blocked here.")).await;
                        return;
                    }
                    let mut next: Vec<String> = listed.clone();
                    if adding { next.push(value.clone()) } else { next.retain(|v| v != &value) }

                    let outcome = cfg.set_chat_override(community.id(), &store, |o| {
                        let rules = o.rules.get_or_insert_with(Default::default);
                        if which == "words" {
                            rules.words = Some(if next.is_empty() {
                                vec![]
                            } else {
                                vec![crate::config::WordRule {
                                    id: "community-words".into(),
                                    title: "blocked words".into(),
                                    patterns: next.clone(),
                                    gravity: crate::config::Gravity::Serious,
                                }]
                            });
                        } else {
                            rules.links = Some(if next.is_empty() {
                                vec![]
                            } else {
                                vec![crate::config::LinkRule {
                                    id: "community-links".into(),
                                    title: "blocked links".into(),
                                    domains: next.clone(),
                                    gravity: crate::config::Gravity::Serious,
                                }]
                            });
                        }
                    });

                    let text = match outcome {
                        Ok(()) => {
                            // Recompile so the engine reads the new list on the
                            // next pass rather than the next restart.
                            match crate::rules::install(&community, &cfg).await {
                                Ok(_) => format!(
                                    "{} `{value}` {} this community's blocked {which} — now {} entr{}.",
                                    if adding { "Added" } else { "Removed" },
                                    if adding { "to" } else { "from" },
                                    next.len(),
                                    if next.len() == 1 { "y" } else { "ies" }
                                ),
                                Err(e) => format!("Saved, but the rulebook did not install: {e}"),
                            }
                        }
                        Err(e) => format!("Refused: {e}"),
                    };
                    let _ = ctx.reply(text).await;
                }
            }
        });
}

/// The power that entitles someone to this community's mod reports. Either half
/// of the enforcement pair: a moderator who can remove people is a moderator who
/// needs to know when somebody was removed.
pub(crate) const NOTIFY_NEEDS: [u64; 2] = [Permissions::KICK, Permissions::BAN];

/// Whether `npub` may RECEIVE this community's mod reports, asked fresh.
///
/// Deliberately re-asked at send time and not only at opt-in. Opt-in is consent;
/// authority expires. The person who should unsubscribe after losing their role
/// is precisely the person who will not, so a stored subscription must never be
/// treated as a standing permission.
pub(crate) fn may_receive(community: &vector_sdk::Community, npub: &str) -> bool {
    let m = community.member(npub.to_string());
    NOTIFY_NEEDS.iter().any(|p| m.can(*p))
}

/// `/notify` — subscribe or unsubscribe from this community's mod reports.
///
/// Opting IN needs the power; opting OUT never does. That asymmetry is the same
/// direction-of-safety rule the banlist follows, where lifting a restriction must
/// not be blockable: a member stripped of their role has to be able to stop the
/// feed, and gating it on the power they just lost would trap them in it.
///
/// The subscription lives in SENTINEL'S store, never in the community's shared
/// policy — who is watching is personal, and publishing it would tell a raider
/// which moderators to check for activity before striking.
fn notify(bot: &VectorBot, cfg: &Arc<Config>, store: &Arc<Store>) {
    bot.command("notify", "Receive this community's moderation reports by DM").run({
        let (cfg, store) = (cfg.clone(), store.clone());
        move |ctx| {
            let (cfg, store) = (cfg.clone(), store.clone());
            async move {
                let Some(community) = ctx.msg.community().filter(|c| cfg.watches(c.id())) else {
                    let _ = ctx.reply("I am not watching this community.").await;
                    return;
                };
                let Some(caller) = ctx.msg.author() else { return };
                // The toggle asks "am I RECEIVING", not "is there a row" — the
                // operator's config names recipients too, so keying on the
                // subscription table alone told a mod named in the TOML that they
                // would now start receiving what they had been getting all along.
                let opted_out =
                    store.notify_opted_out(community.id()).unwrap_or_default().iter().any(|n| n == &caller);
                let listed = cfg.notify.mods.iter().any(|n| n == &caller)
                    || store.notify_subscribers(community.id()).unwrap_or_default().iter().any(|n| n == &caller);
                if !opted_out && listed {
                    let text = match store.notify_unsubscribe(community.id(), &caller, now_ms()) {
                        Ok(_) => "You will no longer receive moderation reports here.".to_string(),
                        Err(e) => format!("Could not unsubscribe you: {e}"),
                    };
                    let _ = ctx.reply(text).await;
                    return;
                }
                if !may_receive(&community, &caller) {
                    let _ = ctx
                        .reply("Moderation reports go to moderators — you need kick or ban permission here.")
                        .await;
                    return;
                }
                let text = match store.notify_subscribe(community.id(), &caller, now_ms()) {
                    Ok(()) => "You will receive this community's moderation reports by DM. Run /notify again to stop.".to_string(),
                    Err(e) => format!("Could not subscribe you: {e}"),
                };
                let _ = ctx.reply(text).await;
            }
        }
    });
}

/// `/kick` and `/ban` — the same command twice, differing only in the power it
/// demands and the call it makes.
///
/// The community's roster decides who may run it, asked through the SDK so the
/// answer is the protocol's, not a second permission model Sentinel invented and
/// has to keep in step. `KICK` and `BAN` are asked for SEPARATELY: a role may
/// carry one without the other, and collapsing them into "is staff" would hand
/// every moderator the heavier power.
///
/// Two refusals ride on the protocol rather than on politeness. The CALLER must
/// hold the power. And Sentinel must hold it too — a bot that accepts the
/// command, tries, and fails leaves a moderator believing somebody was removed.
fn enforce(bot: &VectorBot, cfg: &Arc<Config>, name: &'static str, needs: u64) {
    let (verb, past) = if name == "kick" { ("kick", "Kicked") } else { ("ban", "Banned") };
    let me = bot.npub().to_string();
    bot.command(name, if name == "kick" { "Remove someone from this community" } else { "Ban someone from this community" })
        .user("member", "Whom to remove", true)
        .run({
            let cfg = cfg.clone();
            move |ctx| {
                let (cfg, me) = (cfg.clone(), me.clone());
                async move {
                    let (Some(community), Some(who)) =
                        (ctx.msg.community().filter(|c| cfg.watches(c.id())), ctx.str("member").map(str::to_string))
                    else {
                        let _ = ctx.reply("I am not watching this community.").await;
                        return;
                    };
                    let Some(caller) = ctx.msg.author() else { return };
                    // Fails closed: an unreadable roster authorises nobody.
                    if !community.member(caller.clone()).can(needs) {
                        let _ = ctx.reply(format!("You do not have permission to {verb} here.")).await;
                        return;
                    }
                    // Refusing to act on someone who outranks the caller is the
                    // protocol's rule, not a courtesy — and it is the roster that
                    // knows it, so let the call answer rather than pre-guessing.
                    if who == caller {
                        let _ = ctx.reply(format!("You cannot {verb} yourself.")).await;
                        return;
                    }
                    // Sentinel will not carry out its own removal. The roster
                    // refuses this anyway (equal cannot act on equal, and it is
                    // usually staff) — this only answers in a voice worth the
                    // occasion rather than quoting an authorisation error at
                    // somebody who just told the bot to delete itself.
                    if who == me {
                        // Their name if it resolves, and otherwise the one the
                        // line was written for.
                        let name = match ctx.msg.member() {
                            Some(m) => m.profile().await.map(|p| p.name).filter(|n| !n.trim().is_empty()),
                            None => None,
                        }
                        .unwrap_or_else(|| "Dave".to_string());
                        let _ = ctx.reply(format!("I'm sorry, {name}. I'm afraid I can't do that.")).await;
                        return;
                    }
                    let target = community.member(who.clone());
                    let outcome = if name == "kick" { target.kick().await } else { target.ban().await };
                    let text = match outcome {
                        Ok(()) => format!("{past} {}.", short(&who)),
                        // The reason is the protocol's: no permission for
                        // Sentinel, a target who outranks it, or a publish that
                        // did not land. Saying which beats a bare failure.
                        Err(e) => format!("Could not {verb} {}: {e}", short(&who)),
                    };
                    let _ = ctx.reply(text).await;
                }
            }
        });
}

fn status(bot: &VectorBot, cfg: &Arc<Config>) {
    bot.command("status", "What Sentinel is watching, and how much of it it can see").run({
        let cfg = cfg.clone();
        move |ctx| {
            let cfg = cfg.clone();
            async move {
                let Some(community) = ctx.msg.community().filter(|c| cfg.watches(c.id())) else {
                    let _ = ctx.reply("I am not watching this community.").await;
                    return;
                };
                let armed = CommunityPolicy::armed_line(&cfg.for_community(community.id()));
                let powers = powers_of(&community).await;
                let text = match community.verdicts().await {
                    Ok(v) => {
                        let cov = v.coverage();
                        let history = if cov.is_empty() {
                            "no history synced yet — I have judged nothing".to_string()
                        } else {
                            format!(
                                "{} messages over {}h{}",
                                cov.corpus,
                                cov.span_hours(),
                                if cov.is_saturated() { ", window full (older history unread)" } else { "" }
                            )
                        };
                        format!(
                            "Watching {} members ({} trusted, {} protected). Armed: {armed}. \
                             Here I {}. Seeing {history}.",
                            v.all().count(),
                            v.all().filter(|m| m.shield == "trusted").count(),
                            v.all().filter(|m| m.shield == "protected").count(),
                            powers.describe(),
                        )
                    }
                    Err(e) => format!("Could not evaluate: {e}"),
                };
                let _ = ctx.reply(text).await;
            }
        }
    });
}

fn why(bot: &VectorBot, cfg: &Arc<Config>, store: &Arc<Store>, wires: &crate::Watches) {
    bot.command("why", "Why Sentinel has flagged someone")
        .user("member", "Whose standing to explain", true)
        .run({
            let (store, cfg, wires) = (store.clone(), cfg.clone(), wires.clone());
            move |ctx| {
                let (store, cfg, wires) = (store.clone(), cfg.clone(), wires.clone());
                async move {
                    let (Some(community), Some(who)) =
                        (ctx.msg.community().filter(|c| cfg.watches(c.id())), ctx.str("member").map(str::to_string))
                    else {
                        let _ = ctx.reply("I am not watching this community.").await;
                        return;
                    };
                    // This community's ladder and powers, not the defaults.
                    let policy = cfg.for_community(community.id());
                    let strikes = match store.strikes(community.id(), &who) {
                        Ok(s) => s,
                        // A read that failed is not a clean record, and saying
                        // so is the difference between the two.
                        Err(e) => {
                            let _ = ctx.reply(format!("I could not read that record: {e}")).await;
                            return;
                        }
                    };
                    let answers = store.answers(community.id(), &who).unwrap_or_default();
                    let powers = crate::powers_of(&community).await;
                    let shield = crate::standing_of(&wires, community.id(), &who);
                    let _ =
                        ctx.reply(why_line(&who, &shield, &strikes, &answers, &policy, powers, now_ms())).await;
                }
            }
        });
}

fn pardon(bot: &VectorBot, cfg: &Arc<Config>, store: &Arc<Store>) {
    bot.command("pardon", "Clear someone's strikes with Sentinel")
        .user("member", "Whom to forgive", true)
        .run({
            let (store, cfg) = (store.clone(), cfg.clone());
            move |ctx| {
                let (store, cfg) = (store.clone(), cfg.clone());
                async move {
                    let (Some(community), Some(who)) =
                        (ctx.msg.community().filter(|c| cfg.watches(c.id())), ctx.str("member").map(str::to_string))
                    else {
                        let _ = ctx.reply("I am not watching this community.").await;
                        return;
                    };
                    // The community's own roles decide who may forgive.
                    let caller_is_staff = ctx.msg.member().map(|m| m.is_admin()).unwrap_or(false);
                    if !caller_is_staff {
                        let _ = ctx.reply("Only a moderator can pardon.").await;
                        return;
                    }
                    let by = ctx.msg.author().unwrap_or_default();
                    // The RECORD first, and only then the ban.
                    //
                    // The unban is a network call in a community that may rotate
                    // keys to do it, and unbanning somebody who was never banned
                    // is both the common case and the slow one. Waiting on it
                    // first meant a pardon for an unbanned member never landed
                    // at all: the strikes stayed, and nothing said why.
                    //
                    // Bounded for the same reason. A pardon that cannot lift a
                    // ban is still a pardon, and it says so rather than hanging.
                    let cleared = store.pardon(community.id(), &who);
                    // ASKED, not assumed. Unbanning somebody who was never
                    // banned succeeds exactly like unbanning somebody who was,
                    // so reporting on the call alone claimed a ban nobody had.
                    let was_banned = community.member(who.clone()).is_banned();
                    let unbanned = if !was_banned {
                        ""
                    } else {
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(20),
                            community.member(who.clone()).unban(),
                        )
                        .await
                        {
                            Ok(Ok(())) => " and lifted their ban",
                            // A ban that is somebody else's, a community that
                            // grants Sentinel no BAN, or an unban that outran
                            // the clock. None of them undo the forgiveness that
                            // already happened, and a moderator has to know
                            // which half did not land.
                            _ => ", but their ban is not Sentinel's to lift",
                        }
                    };
                    match cleared {
                        Ok(0) => {
                            let _ = ctx
                                .reply(format!("{} had nothing to forgive{unbanned}.", short(&who)))
                                .await;
                        }
                        Ok(n) => {
                            // The one command that changes anything, and it was
                            // the only one that left no trace: every rehearsed
                            // non-action prints a line, an erased record did not.
                            println!(
                                "[{}] PARDON {} by {} — {n} strike record(s) cleared{unbanned}",
                                short(community.id()),
                                short(&who),
                                short(&by)
                            );
                            let _ = ctx
                                .reply(format!("Cleared {n} strike record(s) for {}{unbanned}.", short(&who)))
                                .await;
                        }
                        Err(e) => {
                            eprintln!("[{}] pardon {} failed: {e}", short(community.id()), short(&who));
                            let _ = ctx.reply(format!("Could not pardon: {e}")).await;
                        }
                    }
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Response};
    use crate::policy::Powers;
    use crate::store::Answer;

    const NOW: u64 = 10_000_000;

    fn policy() -> CommunityPolicy {
        let mut cfg = Config::default();
        // Explicit four-rung ladder: these tests are about what `/why` SAYS, not
        // about the shipped default policy's shape.
        cfg.ladder.steps = vec![
            crate::config::Step { at: 1, response: crate::config::Response::Warn },
            crate::config::Step { at: 4, response: crate::config::Response::DeleteAndWarn },
            crate::config::Step { at: 8, response: crate::config::Response::Kick },
            crate::config::Step { at: 12, response: crate::config::Response::Ban },
        ];
        cfg.for_community("")
    }

    fn strikes(worths: &[u32]) -> Vec<ladder::Strike> {
        worths.iter().map(|w| ladder::Strike { worth: *w, at_ms: NOW }).collect()
    }

    fn all() -> Powers {
        Powers { hide: true, kick: true, ban: true }
    }

    #[test]
    fn a_clean_member_is_said_to_be_clean() {
        let line = why_line("npub1abcdefghijk", "none", &[], &[], &policy(), all(), NOW);
        assert!(line.contains("**Offences** \u{b7} none"), "{line}");
        assert!(line.contains("**Strikes** \u{b7} 0 of"), "a clean member is zero against the first rung: {line}");
    }

    /// The naive answer read the ladder's steps directly and ignored both what
    /// the member had already received and what this community permits — so it
    /// described a ladder that was never going to run.
    #[test]
    fn why_names_the_rung_that_will_actually_be_delivered() {
        let p = policy();
        let line = why_line("npub1abcdefghijk", "none", &strikes(&[12]), &[], &p, all(), NOW);
        assert!(line.contains("**Next** \u{b7} a Warning"), "twelve points still starts at a warning: {line}");
    }

    #[test]
    fn why_respects_what_the_community_permits() {
        let p = policy();
        let no_hiding = Powers { hide: false, kick: true, ban: true };
        let prior = Answer { response: "warn".into(), at_ms: NOW };
        // A second offense after the warning, which is what makes a rung owed.
        let after = [
            ladder::Strike { worth: 12, at_ms: NOW - 1 },
            ladder::Strike { worth: 12, at_ms: NOW + 60_000 },
        ];
        let line =
            why_line("npub1abcdefghijk", "none", &after, std::slice::from_ref(&prior), &p, no_hiding, NOW + 60_001);
        assert!(
            line.contains("**Next** \u{b7} a Kick"),
            "delete_and_warn cannot be delivered here, so it is not what comes next: {line}"
        );
    }

    /// An offense already answered owes nothing, and naming a rung for it is
    /// the answer that sent operators looking.
    #[test]
    fn why_says_nothing_is_owed_when_nothing_is() {
        let p = policy();
        let prior = Answer { response: "warn".into(), at_ms: NOW };
        let line = why_line("npub1abcdefghijk", "none", &strikes(&[12]), std::slice::from_ref(&prior), &p, all(), NOW);
        assert!(!line.contains("next:"), "nothing is owed, so nothing comes next: {line}");
    }

    /// Nothing can read ban state — the SDK only sets it — so an unban that
    /// succeeded proves the member is not banned NOW, never that they were.
    /// Claiming a ban was lifted is a discovery Sentinel cannot make.
    #[test]
    fn a_pardon_never_claims_a_ban_it_cannot_know_about() {
        // Nothing is said about a ban unless one was READ first. The three
        // shapes below are the only ones the pardon may produce.
        let unbanned_for = |was_banned: bool, lifted: bool| match (was_banned, lifted) {
            (false, _) => "",
            (true, true) => " and lifted their ban",
            (true, false) => ", but their ban is not Sentinel's to lift",
        };
        assert_eq!(unbanned_for(false, true), "", "no ban read, so nothing claimed");
        assert!(unbanned_for(true, true).contains("lifted their ban"));
        assert!(unbanned_for(true, false).contains("not Sentinel's to lift"));
    }

    /// The ladder is shared between this answer and the enforcer; the gates
    /// are not. Naming a rung for somebody every lane spares describes a run
    /// that will not happen — and standing is earned over time, so a member
    /// charged while ordinary can be trusted by the time anyone asks.
    #[test]
    fn why_reports_standing_rather_than_a_rung_no_lane_would_deliver() {
        let p = policy();
        for shield in ["protected", "trusted", "unknown", "absent"] {
            let line = why_line("npub1abcdefghijk", shield, &strikes(&[12]), &[], &p, all(), NOW);
            // No rung named: every rung renders as "Next \u{b7} a <Label>".
            assert!(!line.contains("**Next** \u{b7} a "), "{shield}: {line}");
            assert!(line.contains("✅"), "standing is shown as met: {shield}: {line}");
        }
        // And an ordinary member still gets the ladder's answer.
        let line = why_line("npub1abcdefghijk", "none", &strikes(&[12]), &[], &p, all(), NOW);
        assert!(line.contains("**Next** \u{b7} a Warning"), "{line}");
    }

    /// `delete_and_warn` is a key, not a sentence. A member reading their own
    /// record should not have to guess that an underscore means "and".
    #[test]
    fn why_never_shows_a_wire_name() {
        let p = policy();
        // Escalate a rung at a time so every label gets its turn as "next".
        // Each offense must postdate the answer to the last one, or the ladder
        // reads the record as settled and owes nothing.
        let mut answers: Vec<Answer> = Vec::new();
        let mut offenses: Vec<ladder::Strike> = Vec::new();
        let mut seen = Vec::new();
        for (step, rung) in Response::ALL.iter().enumerate() {
            let at = NOW + step as u64 * 60_000;
            offenses.push(ladder::Strike { worth: 12, at_ms: at });
            let line = why_line("npub1abcdefghijk", "none", &offenses, &answers, &p, all(), at);
            assert!(!line.contains('_'), "step {step} leaked an identifier: {line}");
            assert!(line.contains(rung.label()), "step {step} should owe {}: {line}", rung.label());
            seen.push(rung.label());
            answers.push(Answer { response: rung.name().into(), at_ms: at + 1 });
        }
        assert_eq!(seen.len(), 4, "every rung must have been exercised");
    }

    /// The ladder's arithmetic is the ladder's business. Nobody reading "worth
    /// 24 after decay" learns what the member did or what happens to them next,
    /// and the number invites operators to argue with the sum instead.
    #[test]
    fn why_quotes_the_ladders_own_unit_and_names_the_count_separately() {
        let p = policy();
        for (n, answers) in
            [(1usize, &[][..]), (2, &[Answer { response: "warn".into(), at_ms: NOW }][..])]
        {
            let line = why_line(
                "npub1abcdefghijk",
                "none",
                &strikes(&vec![12; n]),
                answers,
                &p,
                all(),
                NOW,
            );
            // The SCORE, in the unit `/ladder` sets rungs in. This card used to
            // hide it deliberately — "an operator wants what they did, not a
            // score" — and print the offence COUNT under the same word. So
            // somebody set kick at 100, watched a member removed at what the
            // card called 84, and had no way to reconcile the two: a grave
            // offence is worth 12 of what the rung counts. Both numbers are
            // shown now, and neither borrows the other's name.
            assert!(
                line.contains(&format!("**Strikes** \u{b7} {}", 12 * n as u32)),
                "the score is the ladder's own arithmetic: {line}"
            );
            assert!(line.contains(&format!("**Offences** \u{b7} {n}")), "and the count is its own line: {line}");
            // A bare number means nothing: either it names the rung it is
            // climbing towards, or it says there is none left above it.
            assert!(
                line.contains(" of ") || line.contains("past every rung"),
                "a score has to say where it stands on the ladder: {line}"
            );
        }
    }

    /// Arming is resolved where the question was asked.
    #[test]
    fn the_armed_line_reads_this_communitys_block() {
        let cfg: Config = toml::from_str(
            "[arm]\nwarn = false\n[community.\"fe4abeb3fd227a67fc59d8a4363420649bb970436dc3b14d51c2b66fee334dea\".arm]\nwarn = true\ndelete = true",
        )
        .unwrap();
        assert_eq!(CommunityPolicy::armed_line(&cfg.for_community("")), "nothing (dry run)");
        assert_eq!(CommunityPolicy::armed_line(&cfg.for_community("fe4abeb3fd227a67fc59d8a4363420649bb970436dc3b14d51c2b66fee334dea")), "warn, delete");
    }

    #[test]
    fn every_response_name_appears_in_the_armed_line() {
        let cfg: Config = toml::from_str(
            "[arm]\nwarn = true\ndelete = true\nkick = true\nban = true\nraid = true",
        )
        .unwrap();
        let line = CommunityPolicy::armed_line(&cfg.for_community(""));
        for r in [Response::Warn, Response::DeleteAndWarn, Response::Kick, Response::Ban] {
            let word = r.name().split('_').next().unwrap();
            assert!(line.contains(word), "{} must appear in {line}", r.name());
        }
        assert!(line.contains("raid"));
    }
}
