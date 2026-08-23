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
    strikes: &[ladder::Strike],
    answers: &[crate::store::Answer],
    policy: &CommunityPolicy,
    powers: crate::policy::Powers,
    now: u64,
) -> String {
    if strikes.is_empty() {
        return format!("{} has no strikes with me.", short(who));
    }
    let hl = policy.ladder.decay_half_life_hours;
    let total = ladder::total(strikes, now, hl);
    let next = ladder::owed(
        &policy.ladder,
        total,
        answers.iter().map(|a| (a.response.as_str(), a.at_total, a.at_ms)),
        |r| powers.can_deliver(r),
        now,
        hl,
    );
    let owed = match next {
        Some(r) => format!("next: {}", r.name()),
        None => "nothing owed".into(),
    };
    format!(
        "{} carries {} strike record(s), worth {total} after decay — {owed}.",
        short(who),
        strikes.len()
    )
}

pub(crate) fn operator_surface(bot: &VectorBot, cfg: &Arc<Config>, store: &Arc<Store>) {
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

    bot.command("why", "Why Sentinel has flagged someone")
        .user("member", "Whose standing to explain", true)
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
                    let _ = ctx.reply(why_line(&who, &strikes, &answers, &policy, powers, now_ms())).await;
                }
            }
        });

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
                    match store.pardon(community.id(), &who) {
                        Ok(0) => {
                            let _ = ctx.reply(format!("{} had nothing to forgive.", short(&who))).await;
                        }
                        Ok(n) => {
                            // The one command that changes anything, and it was
                            // the only one that left no trace: every rehearsed
                            // non-action prints a line, an erased record did not.
                            println!(
                                "[{}] PARDON {} by {} — {n} strike record(s) cleared",
                                short(community.id()),
                                short(&who),
                                short(&by)
                            );
                            let _ = ctx.reply(format!("Cleared {n} strike record(s) for {}.", short(&who))).await;
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
        Config::default().for_community("")
    }

    fn strikes(worths: &[u32]) -> Vec<ladder::Strike> {
        worths.iter().map(|w| ladder::Strike { worth: *w, at_ms: NOW }).collect()
    }

    fn all() -> Powers {
        Powers { hide: true, kick: true, ban: true }
    }

    #[test]
    fn a_clean_member_is_said_to_be_clean() {
        let line = why_line("npub1abcdefghijk", &[], &[], &policy(), all(), NOW);
        assert!(line.contains("no strikes"), "{line}");
    }

    /// The naive answer read the ladder's steps directly and ignored both what
    /// the member had already received and what this community permits — so it
    /// described a ladder that was never going to run.
    #[test]
    fn why_names_the_rung_that_will_actually_be_delivered() {
        let p = policy();
        let line = why_line("npub1abcdefghijk", &strikes(&[12]), &[], &p, all(), NOW);
        assert!(line.contains("next: warn"), "twelve points still starts at a warning: {line}");
    }

    #[test]
    fn why_respects_what_the_community_permits() {
        let p = policy();
        let no_hiding = Powers { hide: false, kick: true, ban: true };
        let prior = Answer { response: "warn".into(), at_total: 12, at_ms: NOW };
        let line = why_line("npub1abcdefghijk", &strikes(&[12, 12]), std::slice::from_ref(&prior), &p, no_hiding, NOW);
        assert!(
            line.contains("next: kick"),
            "delete_and_warn cannot be delivered here, so it is not what comes next: {line}"
        );
    }

    /// An offense already answered owes nothing, and saying "next step at 4"
    /// while nothing is owed is the answer that sent operators looking.
    #[test]
    fn why_says_nothing_is_owed_when_nothing_is() {
        let p = policy();
        let prior = Answer { response: "warn".into(), at_total: 12, at_ms: NOW };
        let line = why_line("npub1abcdefghijk", &strikes(&[12]), std::slice::from_ref(&prior), &p, all(), NOW);
        assert!(line.contains("nothing owed"), "{line}");
    }

    #[test]
    fn why_reports_the_decayed_total_not_the_raw_one() {
        let p = policy();
        let hl = p.ladder.decay_half_life_hours * 3_600_000;
        let old = vec![ladder::Strike { worth: 12, at_ms: NOW }];
        let line = why_line("npub1abcdefghijk", &old, &[], &p, all(), NOW + hl);
        assert!(line.contains("worth 6 "), "one half-life halves it: {line}");
    }

    /// Arming is resolved where the question was asked.
    #[test]
    fn the_armed_line_reads_this_communitys_block() {
        let cfg: Config = toml::from_str(
            "[arm]\nwarn = false\n[community.\"aa\".arm]\nwarn = true\ndelete = true",
        )
        .unwrap();
        assert_eq!(CommunityPolicy::armed_line(&cfg.for_community("")), "nothing (dry run)");
        assert_eq!(CommunityPolicy::armed_line(&cfg.for_community("aa")), "warn, delete");
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
