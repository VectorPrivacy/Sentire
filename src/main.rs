//! Sentinel: a moderation bot for Vector communities.
//!
//! Two judges, one enforcer. vector-core's policy engine judges text, a vision
//! model judges media, and Sentinel alone decides the sentence: warn, delete,
//! kick, ban — on a strike ladder the operator tunes, with decay built in.
//!
//! Dry-run is the resting state. Every action class arms separately in
//! `sentinel.toml`, and until one is armed its sentences are rehearsed and
//! printed, never carried out.
//!
//! ```sh
//! SENTINEL_NSEC=nsec1… cargo run                 # ./sentinel.toml if present
//! SENTINEL_NSEC=nsec1… cargo run -- my.toml      # or an explicit config
//! ```

mod config;
mod ladder;
mod rules;
mod store;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use vector_sdk::policy::{Verdict, Verdicts};
use vector_sdk::{Community, VectorBot};

use config::{Config, Gravity, Response};
use store::Store;

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

#[tokio::main]
async fn main() -> vector_sdk::Result<()> {
    let config_path = std::env::args().nth(1).unwrap_or_else(|| "sentinel.toml".into());
    let cfg = match Config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config refused: {e}");
            std::process::exit(1);
        }
    };
    let nsec = std::env::var(&cfg.bot.nsec_env)
        .unwrap_or_else(|_| panic!("set {} to Sentinel's nsec", cfg.bot.nsec_env));
    let store = Arc::new(Store::open("sentinel.db").map_err(vector_sdk::Error::Other)?);

    let bot = VectorBot::builder().nsec(nsec).public().build().await?;
    println!("Sentinel online as {}", bot.npub());
    let armed: Vec<&str> = [
        (cfg.arm.warn, "warn"),
        (cfg.arm.delete, "delete"),
        (cfg.arm.kick, "kick"),
        (cfg.arm.ban, "ban"),
        (cfg.arm.raid, "raid"),
    ]
    .iter()
    .filter_map(|(on, name)| on.then_some(*name))
    .collect();
    if armed.is_empty() {
        println!("DRY RUN — every action is rehearsed and printed, nobody is touched.\n");
    } else {
        println!("ARMED: {} — everything else stays dry.\n", armed.join(", "));
    }

    let me = bot.npub().to_string();
    let communities: Vec<Community> = bot
        .communities()
        .await
        .into_iter()
        .filter(|c| {
            cfg.bot.communities.iter().any(|want| want == "*" || want == c.id())
        })
        .collect();
    if communities.is_empty() {
        println!("Not a member of any watched community yet. Invite Sentinel from the Vector app.");
    }
    for c in &communities {
        match rules::install(c, &cfg).await {
            Ok(what) => println!("watching {} — {what}", &c.id()[..12]),
            Err(e) => eprintln!("watching {} — rulebook rejected: {e}", &c.id()[..12]),
        }
    }

    operator_surface(&bot, &cfg, &store);

    // The sweep runs beside the listener rather than instead of it: slash
    // commands arrive through the inbound stream, so a bot that only loops on
    // verdicts can be watched but never asked anything.
    let poll = Duration::from_secs(cfg.bot.poll_secs.max(90));
    {
        let (bot, store) = (bot.clone(), store.clone());
        tokio::spawn(async move {
            loop {
                for c in &communities {
                    if let Err(e) = sweep(&bot, c, &cfg, &store, &me).await {
                        eprintln!("{}: {e}", &c.id()[..12]);
                    }
                }
                tokio::time::sleep(poll).await;
            }
        });
    }

    bot.on_message(|_bot, _msg| async move {}).await?;
    Ok(())
}

/// What an operator can ask Sentinel from inside a community.
///
/// Read-only by default. `pardon` is the one command that changes anything, and
/// it answers only to someone the community already trusts to moderate — a bot
/// with no undo is not deployable, and an undo anyone can call is not either.
fn operator_surface(bot: &VectorBot, cfg: &Config, store: &Arc<Store>) {
    let armed = format!(
        "{}{}{}{}{}",
        if cfg.arm.warn { "warn " } else { "" },
        if cfg.arm.delete { "delete " } else { "" },
        if cfg.arm.kick { "kick " } else { "" },
        if cfg.arm.ban { "ban " } else { "" },
        if cfg.arm.raid { "raid " } else { "" },
    );
    let armed = if armed.trim().is_empty() { "nothing (dry run)".to_string() } else { armed.trim().to_string() };

    bot.command("status", "What Sentinel is watching, and how much of it it can see").run({
        let armed = armed.clone();
        move |ctx| {
            let armed = armed.clone();
            async move {
                let Some(community) = ctx.msg.community() else {
                    let _ = ctx.reply("Ask me this inside a community.").await;
                    return;
                };
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
                            "Watching {} members ({} trusted, {} protected). Armed: {armed}. Seeing {history}.",
                            v.all().count(),
                            v.all().filter(|m| m.shield == "trusted").count(),
                            v.all().filter(|m| m.shield == "protected").count(),
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
            let store = store.clone();
            let half_life = cfg.ladder.decay_half_life_hours;
            let ladder = cfg.ladder.clone();
            move |ctx| {
                let (store, ladder) = (store.clone(), ladder.clone());
                async move {
                    let (Some(community), Some(who)) = (ctx.msg.community(), ctx.str("member").map(str::to_string))
                    else {
                        let _ = ctx.reply("Ask me this inside a community, naming a member.").await;
                        return;
                    };
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
            let store = store.clone();
            move |ctx| {
                let store = store.clone();
                async move {
                    let (Some(community), Some(who)) = (ctx.msg.community(), ctx.str("member").map(str::to_string))
                    else {
                        let _ = ctx.reply("Ask me this inside a community, naming a member.").await;
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

/// One pass: verdicts in, strikes recorded, ladder consulted, sentences
/// rehearsed or carried out.
async fn sweep(
    bot: &VectorBot,
    community: &Community,
    cfg: &Config,
    store: &Arc<Store>,
    me: &str,
) -> vector_sdk::Result<()> {
    let verdicts = community.verdicts().await?;
    let id = &community.id()[..12];
    let now = now_ms();
    let roster = verdicts.all().count();

    let mut acted_this_run = 0usize;
    let mut convicted = 0usize;

    for v in verdicts.proven() {
        convicted += 1;
        if v.npub == me {
            continue;
        }
        if v.is_shielded() && (v.shield == "protected" || cfg.shields.respect_trusted) {
            println!("[{id}] QUEUED  {} — {} (shield {})", short(&v.npub), v.why(), v.shield);
            continue;
        }

        // Record what is NEW this poll. Verdicts re-report every standing
        // conviction, so the conviction id is the line between an offense and
        // an echo of one.
        let mut fresh = false;
        for f in &v.findings {
            if !f.is_proven() {
                continue; // inference never earns a strike
            }
            let gravity = cfg.gravity_of(&f.rule_id).unwrap_or(Gravity::from_severity(&f.severity));
            let worth = cfg.ladder.strikes.worth(gravity);
            let evidence = format!("{} [{}] {}×", f.rule_id, f.severity, f.hits);
            fresh |= store
                .record(community.id(), &v.npub, &f.conviction_id, worth, now, &evidence)
                .map_err(vector_sdk::Error::Other)?;
        }
        if !fresh {
            continue; // nothing new: whatever was owed has been answered already
        }

        let strikes = store.strikes(community.id(), &v.npub).map_err(vector_sdk::Error::Other)?;
        let total = ladder::total(&strikes, now, cfg.ladder.decay_half_life_hours);
        let Some(response) = ladder::decide(&cfg.ladder, total) else { continue };

        // Ceilings before anything else: a bug must not empty a community.
        if acted_this_run >= cfg.limits.max_actions_per_run {
            println!("[{id}] HELD    {} — run ceiling reached", short(&v.npub));
            continue;
        }
        let last_hour = store.actions_last_hour(now).map_err(vector_sdk::Error::Other)?;
        if last_hour >= cfg.limits.max_actions_per_hour {
            println!("[{id}] HELD    {} — hourly ceiling reached", short(&v.npub));
            continue;
        }
        if roster > 0 && (acted_this_run + 1) * 100 > cfg.limits.halt_if_over_pct as usize * roster {
            println!(
                "[{id}] HALT — this pass would touch more than {}% of {} members. A human decides from here.",
                cfg.limits.halt_if_over_pct, roster
            );
            break;
        }

        acted_this_run += 1;
        enforce(bot, community, cfg, store, v, response, total, now).await?;
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
    if verdicts.raid_detected() {
        println!("[{id}] RAID SUSPECTED — containment is not in this build; a human decides");
    }

    heartbeat(id, &verdicts, convicted);
    Ok(())
}

/// Carry a sentence out, or rehearse it. Armed per action class; a dry pass
/// logs the rehearsal so the ladder does not re-sentence every poll.
#[allow(clippy::too_many_arguments)]
async fn enforce(
    bot: &VectorBot,
    community: &Community,
    cfg: &Config,
    store: &Arc<Store>,
    v: &Verdict,
    response: Response,
    total: u32,
    now: u64,
) -> vector_sdk::Result<()> {
    let id = &community.id()[..12];
    let why = v.why();

    // One response per standing: if the last answer to this member was already
    // this rung or higher, this poll adds nothing new to say.
    if let Some(prev) = store.last_response(community.id(), &v.npub).map_err(vector_sdk::Error::Other)? {
        let rank = |r: &str| match r {
            "warn" => 1,
            "delete_and_warn" => 2,
            "kick" => 3,
            "ban" => 4,
            _ => 0,
        };
        let this = match response {
            Response::Warn => 1,
            Response::DeleteAndWarn => 2,
            Response::Kick => 3,
            Response::Ban => 4,
        };
        if rank(&prev) >= this {
            return Ok(());
        }
    }

    let (name, armed): (&str, bool) = match response {
        Response::Warn => ("warn", cfg.arm.warn),
        Response::DeleteAndWarn => ("delete_and_warn", cfg.arm.delete),
        Response::Kick => ("kick", cfg.arm.kick),
        Response::Ban => ("ban", cfg.arm.ban),
    };
    let mode = if armed { "ENFORCE" } else { "WOULD  " };
    println!("[{id}] {mode} {name} {} — {total} strike(s) — {why}", short(&v.npub));
    store
        .log_action(community.id(), &v.npub, name, !armed, now, &why)
        .map_err(vector_sdk::Error::Other)?;
    announce(bot, community, cfg, &format!("{} {} — {total} strike(s) — {why}", if armed { name } else { "would" }, short(&v.npub))).await;
    if !armed {
        return Ok(());
    }

    match response {
        Response::Warn => {
            let _ = bot.dm(&v.npub).send(&warn_text(&why)).await;
        }
        Response::DeleteAndWarn => {
            for msg_id in v.findings.iter().flat_map(|f| f.messages.iter()) {
                if let Some(m) = bot.message(msg_id).await {
                    if let Err(e) = m.hide().await {
                        eprintln!("[{id}] hide {msg_id}: {e}");
                    }
                }
            }
            let _ = bot.dm(&v.npub).send(&warn_text(&why)).await;
        }
        Response::Kick => {
            community.member(v.npub.clone()).kick().await?;
        }
        Response::Ban => {
            community.member(v.npub.clone()).ban().await?;
        }
    }
    Ok(())
}

fn warn_text(why: &str) -> String {
    format!(
        "Sentinel here. A community rule matched your recent messages: {why}. \
         This is a warning; repeated matches escalate. Reply to a moderator if you think this is wrong."
    )
}

/// Best-effort audit line into the operator's mod channel, when one is named.
async fn announce(bot: &VectorBot, community: &Community, cfg: &Config, line: &str) {
    let Some(want) = &cfg.bot.mod_channel else { return };
    for ch in community.channels().await {
        if ch.name() == want && ch.is_readable() {
            let _ = bot.channel(ch.id()).send(line).await;
            return;
        }
    }
}

fn short(npub: &str) -> &str {
    &npub[..12.min(npub.len())]
}

/// What the sweep looked at, whether or not it found anything.
///
/// A quiet community and a broken bot print the same thing — nothing — and that
/// is exactly how a moderation tool stays broken for months. Every pass says
/// what it read and how many people it weighed, so silence becomes a result
/// rather than an absence of one.
fn heartbeat(community: &str, verdicts: &Verdicts, found: usize) {
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
        "[{community}] swept {} member(s) — {} protected, {} trusted, {} plain — {found} convicted — {history}",
        verdicts.all().count(),
        shields.0,
        shields.1,
        shields.2,
    );
}
