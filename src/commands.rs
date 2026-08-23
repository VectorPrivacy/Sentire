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
                    // This community's ladder, not the defaults.
                    let ladder = cfg.for_community(community.id()).ladder;
                    let half_life = ladder.decay_half_life_hours;
                    let strikes = store.strikes(community.id(), &who).unwrap_or_default();
                    if strikes.is_empty() {
                        let _ = ctx.reply(format!("{} has no strikes with me.", short(&who))).await;
                        return;
                    }
                    let total = ladder::total(&strikes, now_ms(), half_life);
                    let next = ladder.steps.iter().find(|s| s.at > total).map(|s| format!(", next step at {}", s.at));
                    let _ = ctx
                        .reply(format!(
                            "{} carries {} strike record(s), worth {total} after decay{}.",
                            short(&who),
                            strikes.len(),
                            next.unwrap_or_default()
                        ))
                        .await;
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
                    match store.pardon(community.id(), &who) {
                        Ok(0) => {
                            let _ = ctx.reply(format!("{} had nothing to forgive.", short(&who))).await;
                        }
                        Ok(n) => {
                            let _ = ctx.reply(format!("Cleared {n} strike record(s) for {}.", short(&who))).await;
                        }
                        Err(e) => {
                            let _ = ctx.reply(format!("Could not pardon: {e}")).await;
                        }
                    }
                }
            }
        });
}
