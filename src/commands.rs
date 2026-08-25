//! What an operator can ask Sentinel from inside a community.

use std::sync::Arc;

use vector_sdk::VectorBot;

use crate::config::Config;
use crate::policy::CommunityPolicy;
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
    let count = if n == 0 { "none".to_string() } else { n.to_string() };
    let standing_line = match standing {
        Some(why) => format!("✅ {why}"),
        None => "❌ none".to_string(),
    };
    let mut card = format!(
        "{dot} **{}**\n**Strikes** · {count}\n**Standing** · {standing_line}",
        short(who)
    );
    if n == 0 {
        return card;
    }
    // Standing is asked exactly as every lane asks it. The ladder is shared
    // between this answer and the enforcer; the gates are not, so naming a rung
    // for somebody the gate always spares describes a run that will not happen.
    if standing.is_some() {
        card.push_str("\n**Next** · nothing — standing answers for them");
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
        assert!(line.contains("**Strikes** \u{b7} none"), "{line}");
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
            assert!(line.contains("standing"), "{shield}: {line}");
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
    fn why_never_quotes_the_ladders_score() {
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
            for score in ["worth", "decay", "12", "24", "owed"] {
                assert!(!line.contains(score), "{n} strike(s) leaked `{score}`: {line}");
            }
            assert!(line.contains(&format!("**Strikes** \u{b7} {n}")), "{line}");
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
