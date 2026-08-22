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
mod raid;
mod tripwire;
mod vision;
mod rules;
mod store;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use vector_sdk::policy::{Verdict, Verdicts};
use vector_sdk::{BotEvent, Community, VectorBot};

use config::{Config, Gravity, RaidResponse, Response};
use tokio::sync::Semaphore;
use store::Store;
use tripwire::Tripwire;

/// Per-community state the live lanes need and cannot compute themselves.
#[derive(Default)]
struct Watch {
    tripwire: Option<Tripwire>,
    /// A sweep is in flight. The timer and the tripwire both call `sweep`, and
    /// two overlapping passes each read the corpus, each decide, and each act —
    /// which for a ban is two key rotations for one member.
    sweeping: bool,
    /// npub -> shield, refreshed by every sweep. The live lanes never consult
    /// the engine, so without this they would judge with no idea who the
    /// community has vouched for.
    standing: HashMap<String, String>,
    /// True once a sweep has filled `standing`. Before that, "unknown" is the
    /// only honest answer about anybody.
    known: bool,
}

type Watches = Arc<Mutex<HashMap<String, Watch>>>;

/// Releases the single-flight claim however the sweep returns — including on
/// the `?` paths, which is the whole reason this is a guard and not a flag flip
/// at the end of the function.
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

/// A member's standing as the last sweep saw it. `"unknown"` before the first
/// sweep, and `enforce` holds rather than acts on that.
fn standing_of(watches: &Watches, community: &str, npub: &str) -> String {
    let guard = watches.lock().unwrap_or_else(|e| e.into_inner());
    match guard.get(community) {
        Some(w) if w.known => w.standing.get(npub).cloned().unwrap_or_else(|| "none".into()),
        _ => "unknown".into(),
    }
}
use vision::Vision as _;

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
    let Ok(nsec) = std::env::var(&cfg.bot.nsec_env) else {
        eprintln!("{} is unset — Sentinel needs its nsec there", cfg.bot.nsec_env);
        std::process::exit(1);
    };
    // Beside the config, not beside the current directory: started from
    // elsewhere, Sentinel silently opened a fresh database and re-sentenced
    // everyone from zero.
    let db_path = std::path::Path::new(&config_path).with_extension("db");
    let store = Arc::new(Store::open(&db_path.to_string_lossy()).map_err(vector_sdk::Error::Other)?);
    let cfg = Arc::new(cfg);

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
            Ok(what) => println!("watching {} — {what}", short(c.id())),
            Err(e) => eprintln!("watching {} — rulebook rejected: {e}", short(c.id())),
        }
    }

    operator_surface(&bot, &cfg, &store);
    let eyes = media_lane(&cfg)?;
    let budget = Arc::new(Budget::new(cfg.vision.max_per_min.max(1)));

    // The sweep runs beside the listener rather than instead of it: slash
    // commands arrive through the inbound stream, so a bot that only loops on
    // verdicts can be watched but never asked anything.
    let wires: Watches = Arc::new(Mutex::new(HashMap::new()));
    let poll = Duration::from_secs(cfg.bot.poll_secs.max(90));
    {
        let (bot, store, cfg, wires) = (bot.clone(), store.clone(), cfg.clone(), wires.clone());
        tokio::spawn(async move {
            let mut installed: std::collections::HashSet<String> = communities.iter().map(|c| c.id().to_string()).collect();
            loop {
                // Re-resolved every pass: a community joined after startup was
                // never swept and never got a rulebook, and one Sentinel was
                // removed from kept being polled forever.
                for c in bot.communities().await.into_iter().filter(|c| cfg.watches(c.id())) {
                    if installed.insert(c.id().to_string()) {
                        match rules::install(&c, &cfg).await {
                            Ok(what) => println!("watching {} — {what}", short(c.id())),
                            Err(e) => eprintln!("watching {} — rulebook rejected: {e}", short(c.id())),
                        }
                    }
                    if let Err(e) = sweep(&bot, &c, &cfg, &store, &wires, &me).await {
                        eprintln!("{}: {e}", short(c.id()));
                    }
                }
                tokio::time::sleep(poll).await;
            }
        });
    }

    // The live stream, not the sweep: content and media are judged when they
    // land, and a wave trips an immediate evaluation rather than waiting out a
    // 90-second cache. `on_event` rather than `on_message` because joins are
    // half the raid signal and a message handler never sees them.
    {
        let (cfg, store, me, budget) = (cfg.clone(), store.clone(), bot.npub().to_string(), budget.clone());
        bot.on_event(move |bot, event| {
            let (cfg, store, eyes, wires, me, budget) =
                (cfg.clone(), store.clone(), eyes.clone(), wires.clone(), me.clone(), budget.clone());
            async move {
                match event {
                    BotEvent::Message(msg) => {
                        if let Err(e) = screen(&bot, &msg, &cfg, &store, &wires).await {
                            eprintln!("screen: {e}");
                        }
                        if let Err(e) =
                            watch_media(&bot, &msg, &cfg, &store, eyes.as_ref().as_ref(), &wires, &budget).await
                        {
                            eprintln!("media: {e}");
                        }
                        if let (Some(community), Some(author)) = (msg.community(), msg.author()) {
                            if !msg.is_mine() {
                                trip(&bot, &community, &cfg, &store, &wires, &author, &me).await;
                            }
                        }
                    }
                    // A join flood is the other half of the raid shape, and it
                    // arrives before anyone has said anything at all.
                    BotEvent::MemberJoin { channel_id, npub } => {
                        if let Some(community) = bot.channel(channel_id).community() {
                            trip(&bot, &community, &cfg, &store, &wires, &npub, &me).await;
                        }
                    }
                    _ => {}
                }
            }
        })
        .await?;
    }
    Ok(())
}

/// Feed one live arrival to the community's tripwire, and evaluate immediately
/// if it trips.
///
/// The tripwire decides WHEN to ask, never who is guilty: it drops the memoised
/// verdict and asks the engine, which judges exactly as it would have on the
/// next sweep. Keeping those separate is what stops a second, sloppier detector
/// growing beside the real one.
async fn trip(
    bot: &VectorBot,
    community: &Community,
    cfg: &Config,
    store: &Arc<Store>,
    wires: &Watches,
    who: &str,
    me: &str,
) {
    let tripped = {
        let mut guard = wires.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .entry(community.id().to_string())
            .or_default()
            .tripwire
            .get_or_insert_with(|| {
                Tripwire::new(cfg.raid.tripwire_accounts, cfg.raid.tripwire_secs, cfg.raid.tripwire_cooldown_secs)
            })
            .observe(who, now_ms())
    };
    if !tripped {
        return;
    }
    println!(
        "[{}] TRIPWIRE — {} distinct accounts inside {}s, evaluating now",
        short(community.id()),
        cfg.raid.tripwire_accounts,
        cfg.raid.tripwire_secs
    );
    // The 90-second memoisation is right for a background pass and far too slow
    // for a wave in progress.
    community.invalidate();
    if let Err(e) = sweep(bot, community, cfg, store, wires, me).await {
        eprintln!("{}: {e}", short(community.id()));
    }
}

/// Screen one message the instant it lands.
///
/// A word filter that answers on the next 90-second tick is not a word filter.
/// Stateless rules — words, links, mentions — settle from the message alone, so
/// they run here; rate, repetition and cohorts describe a window and stay with
/// the sweep, where there is something for them to measure.
///
/// The same engine and the same policies, so a verdict reached here is the one
/// the sweep would reach later over the same text. Strikes key on the same
/// ladder, so the two paths escalate one member rather than two.
async fn screen(
    bot: &VectorBot,
    msg: &vector_sdk::IncomingMessage,
    cfg: &Config,
    store: &Arc<Store>,
    watches: &Watches,
) -> vector_sdk::Result<()> {
    if !msg.is_group || msg.is_mine() {
        return Ok(());
    }
    let (Some(community), Some(author)) = (msg.community(), msg.author()) else { return Ok(()) };
    if !cfg.watches(community.id()) {
        return Ok(());
    }
    let findings = community.screen(msg).await?;
    if findings.is_empty() {
        return Ok(());
    }
    let now = now_ms();
    let mut fresh = false;
    let mut worst: Option<(Gravity, String)> = None;
    for f in &findings {
        if !f.is_proven() {
            continue; // inference never earns a strike, on any clock
        }
        let gravity = cfg.gravity_of(&f.rule_id).unwrap_or(Gravity::from_severity(&f.severity));
        let worth = cfg.ladder.strikes.worth(gravity);
        let evidence = if f.detail.is_empty() {
            format!("{} [{}]", f.rule_id, f.severity)
        } else {
            format!("{} [{}] {}", f.rule_id, f.severity, f.detail.join(", "))
        };
        // The screen has no conviction id — the message has no id yet at send
        // time and this is a different pipeline — so one is minted from what
        // makes this offense distinct. The sweep's own id for the same text
        // differs, which is deliberate: an offense caught live and the same
        // offense re-read from the corpus are one event, and the sweep skips
        // members whose standing has already been answered.
        let conviction = format!("screen:{}:{}:{}", f.rule_id, msg.message.id, f.detail.join(","));
        fresh |= store
            .record(community.id(), &author, &conviction, worth, now, &evidence)
            .map_err(vector_sdk::Error::Other)?;
        // The GRAVEST finding speaks for the batch, not whichever arrived first.
        if worst.as_ref().is_none_or(|(g, _)| gravity > *g) {
            worst = Some((gravity, evidence));
        }
    }
    let Some((_, evidence)) = worst else { return Ok(()) };
    println!("[screen] {} — {evidence}", short(&author));
    if !fresh {
        return Ok(());
    }
    let strikes = store.strikes(community.id(), &author).map_err(vector_sdk::Error::Other)?;
    let total = ladder::total(&strikes, now, cfg.ladder.decay_half_life_hours);
    if let Some(response) = ladder::decide(&cfg.ladder, total) {
        let shield = standing_of(watches, community.id(), &author);
        let v = live_verdict(&author, shield, &evidence, msg.message.id.clone(), &findings);
        let pass = Mutex::new(PassState { acted: 0, roster: roster_of(watches, community.id()) });
        enforce(bot, &community, cfg, store, &pass, &v, response, total, now).await?;
    }
    Ok(())
}

/// The roster as the last sweep counted it, so a live action is bound by the
/// same percentage ceiling the sweep obeys.
fn roster_of(watches: &Watches, community: &str) -> usize {
    watches.lock().unwrap_or_else(|e| e.into_inner()).get(community).map(|w| w.standing.len()).unwrap_or(0)
}

/// A live screen result, in the shape the ladder and the enforcer speak.
fn live_verdict(
    npub: &str,
    shield: String,
    evidence: &str,
    message_id: String,
    findings: &[vector_sdk::policy::Finding],
) -> Verdict {
    let mut findings = findings.to_vec();
    // The screen knows the message; the engine's own citation could not, since
    // at send time it does not exist yet.
    for f in &mut findings {
        f.messages = vec![message_id.clone()];
    }
    Verdict {
        npub: npub.to_string(),
        name: short(npub).to_string(),
        confidence: 0,
        proven: 0,
        band: "alert".into(),
        shield,
        reasons: vec![evidence.to_string()],
        findings,
        messages: 0,
        tenure_secs: 0,
    }
}

/// One classification at a time, and no more than the operator allows per
/// minute. Every message is its own task, so without this a wave of images is a
/// wave of concurrent multi-megabyte uploads to the model.
struct Budget {
    slot: Semaphore,
    per_min: u32,
    spent: Mutex<(u64, u32)>,
}

impl Budget {
    fn new(per_min: u32) -> Budget {
        Budget { slot: Semaphore::new(1), per_min, spent: Mutex::new((0, 0)) }
    }

    /// None means the minute's allowance is gone. Refusing is safe: the caller
    /// treats it as unclassified, which routes to a person rather than passing.
    fn claim(&self, now_ms: u64) -> bool {
        let minute = now_ms / 60_000;
        let mut spent = self.spent.lock().unwrap_or_else(|e| e.into_inner());
        if spent.0 != minute {
            *spent = (minute, 0);
        }
        if spent.1 >= self.per_min {
            return false;
        }
        spent.1 += 1;
        true
    }
}

/// The classifier, if the operator configured one.
fn media_lane(cfg: &Config) -> vector_sdk::Result<Arc<Option<vision::openai::OpenAiVision>>> {
    if !cfg.vision.enabled {
        return Ok(Arc::new(None));
    }
    let eyes = vision::openai::OpenAiVision::new(cfg.vision.clone()).map_err(vector_sdk::Error::Other)?;
    println!(
        "media lane: {} at {}{}",
        cfg.vision.model,
        cfg.vision.base_url,
        if cfg.vision.is_local() {
            String::new()
        } else {
            format!("  ⚠ REMOTE — decrypted attachments leave this machine for {}", cfg.vision.base_url)
        }
    );
    Ok(Arc::new(Some(eyes)))
}

/// Judge one message's attachments.
///
/// Everything here is Sentinel's own opinion. A model's verdict never reaches
/// `proven`, never enters the engine's combinator, and never appears in another
/// client's report — so it is reported as what it is, and the ladder it feeds is
/// Sentinel's alone.
async fn watch_media(
    bot: &VectorBot,
    msg: &vector_sdk::IncomingMessage,
    cfg: &Config,
    store: &Arc<Store>,
    eyes: Option<&vision::openai::OpenAiVision>,
    watches: &Watches,
    budget: &Budget,
) -> vector_sdk::Result<()> {
    let (Some(eyes), true) = (eyes, msg.is_group && msg.is_file && !msg.is_mine()) else { return Ok(()) };
    let (Some(community), Some(author)) = (msg.community(), msg.author()) else { return Ok(()) };
    if !cfg.watches(community.id()) {
        return Ok(());
    }
    let now = now_ms();

    for att in &msg.message.attachments {
        // A cheap pre-filter on the sender's own claims; both are re-checked
        // against the real bytes below.
        if att.size > cfg.vision.max_bytes {
            continue;
        }
        let declared = vector_sdk::vector_core::crypto::mime_from_extension(&att.extension);
        if !cfg.vision.mimes.iter().any(|m| m == declared) {
            continue;
        }
        // The bytes have to arrive before anything about them can be trusted.
        // `att.id` is the SENDER's declared hash, never verified against what
        // actually downloads — keying the cache on it let an attacker attach
        // the id of an image already cached as clean and skip the classifier.
        let bytes = match bot.download_attachment_from(att, msg.message.npub.as_deref()).await {
            Ok(b) => b,
            Err(e) => {
                println!("[media] could not fetch {} — {e} — queued, not cleared", short(&att.id));
                continue;
            }
        };
        // The declared size was the sender's word too.
        if bytes.len() as u64 > cfg.vision.max_bytes {
            println!("[media] {} is {} bytes, over the limit — queued, not cleared", short(&att.id), bytes.len());
            continue;
        }
        // MIME from the bytes, never from a name the uploader chose.
        let actual = vector_sdk::vector_core::crypto::mime_from_magic_bytes(&bytes);
        if !cfg.vision.mimes.iter().any(|m| m == actual) {
            continue;
        }
        let content_hash = vector_sdk::vector_core::crypto::sha256_hex(&bytes);
        let verdict = match store.cached_verdict(&content_hash, eyes.model()) {
            Some(cached) => match serde_json::from_str(&cached) {
                Ok(v) => v,
                // An unreadable row is not an all-clear: a shape change would
                // otherwise silently pass every blob ever classified.
                Err(e) => vision::Verdict::Unknown(format!("cache unreadable: {e}")),
            },
            None => {
                if !budget.claim(now) {
                    println!("[media] {} — classification budget spent this minute, queued", short(&att.id));
                    continue;
                }
                let _slot = budget.slot.acquire().await.map_err(|e| vector_sdk::Error::Other(e.to_string()))?;
                let v = eyes.classify(&bytes, actual).await;
                // Never cache Unknown: one timeout would retire that blob from
                // classification forever.
                if !matches!(v, vision::Verdict::Unknown(_)) {
                    if let Ok(json) = serde_json::to_string(&v) {
                        let _ = store.cache_verdict(&content_hash, eyes.model(), &json, now);
                    }
                }
                v
            }
        };

        match verdict {
            vision::Verdict::Clean => {}
            vision::Verdict::Unknown(why) => {
                // Never an all-clear. An unreachable model is a reason to ask a
                // person, not a reason to let everything through.
                println!("[media] UNKNOWN {} from {} — {why} — for review", short(&att.id), short(&author));
                // The reason can carry the endpoint URL, and this line goes
                // into a community channel.
                announce(bot, &community, cfg, &format!("Could not classify an attachment from {}.", short(&author))).await;
            }
            vision::Verdict::Flagged(labels) => {
                let hits = vision::over_threshold(&labels, &cfg.vision.labels);
                if hits.is_empty() {
                    continue;
                }
                let (label, gravity) = hits[0].clone();
                let worth = cfg.ladder.strikes.worth(gravity);
                let evidence = format!("{} ({:.0}% per {})", label.name, label.score * 100.0, eyes.model());
                // One strike per (blob, label): re-posting the same image is
                // the same offense, escalating happens by posting more.
                let conviction = format!("vision:{content_hash}:{}", label.name);
                let fresh = store
                    .record(community.id(), &author, &conviction, worth, now, &evidence)
                    .map_err(vector_sdk::Error::Other)?;
                println!("[media] FLAGGED {} from {} — {evidence}", short(&att.id), short(&author));
                if !fresh {
                    continue;
                }
                let strikes = store.strikes(community.id(), &author).map_err(vector_sdk::Error::Other)?;
                let total = ladder::total(&strikes, now, cfg.ladder.decay_half_life_hours);
                // A model's opinion is inference. It rides its OWN arm rather
                // than the booleans an operator set for provable text rules.
                if !cfg.arm.vision {
                    println!("[media] (vision unarmed — reported only)");
                    continue;
                }
                if let Some(response) = ladder::decide(&cfg.ladder, total) {
                    let shield = standing_of(watches, community.id(), &author);
                    let v = synthetic_verdict(&author, shield, &evidence, msg.message.id.clone());
                    let pass = Mutex::new(PassState { acted: 0, roster: roster_of(watches, community.id()) });
                    enforce(bot, &community, cfg, store, &pass, &v, response, total, now).await?;
                }
            }
        }
    }
    Ok(())
}

/// A model's finding, in the shape the ladder and the enforcer already speak.
/// Confidence and proven are ZERO on purpose: this is Sentinel's judgement, and
/// nothing about it is replayable by anyone else.
fn synthetic_verdict(npub: &str, shield: String, evidence: &str, message_id: String) -> Verdict {
    Verdict {
        npub: npub.to_string(),
        name: short(npub).to_string(),
        confidence: 0,
        proven: 0,
        band: "alert".into(),
        shield,
        reasons: vec![evidence.to_string()],
        findings: vec![vector_sdk::policy::Finding {
            conviction_id: String::new(),
            policy_hash: String::new(),
            rule_id: "vision".into(),
            scope: "whole".into(),
            basis: "heuristic".into(),
            severity: "severe".into(),
            stateless: false,
            rung: 0,
            hits: 1,
            weight: 0,
            detail: vec![evidence.to_string()],
            messages: vec![message_id],
            citation_count: 1,
        }],
        messages: 0,
        tenure_secs: 0,
    }
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
    wires: &Watches,
    me: &str,
) -> vector_sdk::Result<()> {
    // Single-flight. Claimed before the corpus read, released however this
    // returns, so an error path cannot wedge the community closed.
    {
        let mut guard = wires.lock().unwrap_or_else(|e| e.into_inner());
        let w = guard.entry(community.id().to_string()).or_default();
        if w.sweeping {
            return Ok(());
        }
        w.sweeping = true;
    }
    let _release = SweepGuard { wires: wires.clone(), community: community.id().to_string() };

    let verdicts = community.verdicts().await?;

    // Publish what only the engine knows: who belongs here. The tripwire uses
    // it to ignore regulars, and the live lanes use it as their shield.
    {
        let vouched: Vec<&str> = verdicts.all().filter(|v| v.is_shielded()).map(|v| v.npub.as_str()).collect();
        let mut guard = wires.lock().unwrap_or_else(|e| e.into_inner());
        let w = guard.entry(community.id().to_string()).or_default();
        w.tripwire
            .get_or_insert_with(|| {
                Tripwire::new(cfg.raid.tripwire_accounts, cfg.raid.tripwire_secs, cfg.raid.tripwire_cooldown_secs)
            })
            .trust(vouched);
        w.standing = verdicts.all().map(|v| (v.npub.clone(), v.shield.clone())).collect();
        w.known = true;
    }
    let id = short(community.id());
    let now = now_ms();
    let pass = Mutex::new(PassState { acted: 0, roster: verdicts.all().count() });
    let mut convicted = 0usize;

    // `all()`, not `proven()`: the shielded are filtered out upstream by
    // `proven()`, so gating on them inside that loop could never fire and the
    // operator never saw who was spared.
    for v in verdicts.all().filter(|v| v.is_proven()) {
        convicted += 1;
        if v.npub == me {
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
            if f.stateless {
                // The live screen already answered this one. Recording it again
                // here doubled every content offense: one "damn" reached two
                // strikes, and with a serious rule it reached a kick.
                continue;
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

        if enforce(bot, community, cfg, store, &pass, v, response, total, now).await? == Outcome::Halted {
            break;
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
    contain(bot, community, cfg, store, &verdicts, me, now).await?;

    heartbeat(id, &verdicts, convicted);
    Ok(())
}

/// A raid answers to itself, not to the ladder. See [`raid`] for why this is
/// the one path where inference is allowed to act, and only once armed.
async fn contain(
    bot: &VectorBot,
    community: &Community,
    cfg: &Config,
    store: &Arc<Store>,
    verdicts: &Verdicts,
    me: &str,
    now: u64,
) -> vector_sdk::Result<()> {
    let id = short(community.id());
    if !cfg.rules.raid_detection {
        return Ok(());
    }
    let (suspects, response, armed) = match raid::select(verdicts, cfg, me) {
        raid::Containment::Quiet => return Ok(()),
        raid::Containment::Halt { suspects, roster } => {
            let line = format!(
                "RAID HALT — {suspects} of {roster} members are over the bar, past the {}% ceiling.                  Containing this many is a person's call, not mine.",
                cfg.limits.halt_if_over_pct
            );
            println!("[{id}] {line}");
            announce(bot, community, cfg, &line).await;
            return Ok(());
        }
        raid::Containment::WouldContain { suspects, response } => (suspects, response, false),
        raid::Containment::Contain { suspects, response } => (suspects, response, true),
    };

    let verb = match response {
        RaidResponse::Report => "report",
        RaidResponse::Kick => "kick",
        RaidResponse::Ban => "ban",
    };
    // A raid stays detected for as long as its evidence sits in the window, so
    // without a claim every sweep re-contains the same cohort — for bans, that
    // is repeated key rotations, the exact stranding batching exists to avoid.
    let mut fingerprint: Vec<&str> = suspects.iter().map(String::as_str).collect();
    fingerprint.sort_unstable();
    let fingerprint = format!("cohort:{:016x}", fnv(&fingerprint.join(",")));
    if !store.claim_cohort(community.id(), &fingerprint, now).map_err(vector_sdk::Error::Other)? {
        return Ok(());
    }
    let line = format!(
        "RAID {} — {} account(s), {verb}",
        if armed { "CONTAINED" } else { "SUSPECTED (unarmed, nobody touched)" },
        suspects.len()
    );
    println!("[{id}] {line}");
    // Prefixed, so a raid row is never read as a ladder response. An unarmed
    // raid stamping a bare "kick" on every suspect immunised all of them
    // against warn, delete and kick — permanently, on evidence nobody acted on.
    for npub in &suspects {
        store
            .log_action(community.id(), npub, &format!("raid:{verb}"), !armed, now, "raid cohort")
            .map_err(vector_sdk::Error::Other)?;
    }
    announce(bot, community, cfg, &line).await;
    if !armed || response == RaidResponse::Report {
        return Ok(());
    }

    match response {
        RaidResponse::Report => {}
        RaidResponse::Kick => {
            // Kicks touch the guestbook and rotate nothing, so a loop is honest here.
            for npub in &suspects {
                if let Err(e) = community.member(npub.clone()).kick().await {
                    eprintln!("[{id}] kick {}: {e}", short(npub));
                }
            }
        }
        RaidResponse::Ban => {
            // ban_many, never a loop of ban(): each single ban rotates the
            // community's keys, and forty rotations strand everyone.
            for chunk in suspects.chunks(cfg.raid.max_batch.min(raid::BAN_CHUNK)) {
                let refs: Vec<&str> = chunk.iter().map(String::as_str).collect();
                if let Err(e) = community.ban_many(&refs).await {
                    eprintln!("[{id}] ban batch of {}: {e}", refs.len());
                }
            }
        }
    }
    Ok(())
}

/// The ONE place a sentence is carried out. Every path — the sweep's ladder,
/// the live screen, the media lane — comes through here, because a guard that
/// lives in one of three callers is a guard two paths do not have.
///
/// Owns, in order: standing, ceilings, dedup, act, log. Nothing above it needs
/// to remember any of that, and nothing below it can skip it.
#[allow(clippy::too_many_arguments)]
async fn enforce(
    bot: &VectorBot,
    community: &Community,
    cfg: &Config,
    store: &Arc<Store>,
    pass: &Mutex<PassState>,
    v: &Verdict,
    response: Response,
    total: u32,
    now: u64,
) -> vector_sdk::Result<Outcome> {
    let id = short(community.id());
    let why = v.why();
    let who = short(&v.npub);

    // ── Standing ────────────────────────────────────────────────────────────
    // First, and unconditional. The owner and moderators are never Sentinel's
    // to judge, and a member the community has vouched for goes to a person.
    match v.shield.as_str() {
        "protected" => {
            println!("[{id}] QUEUED  {who} — {why} (protected)");
            return Ok(Outcome::Spared);
        }
        "trusted" if cfg.shields.respect_trusted => {
            println!("[{id}] QUEUED  {who} — {why} (trusted)");
            return Ok(Outcome::Spared);
        }
        // An unknown standing is not a clean one. Before the first sweep fills
        // the cache, holding is the only honest answer.
        "unknown" => {
            println!("[{id}] HELD    {who} — standing not yet established");
            return Ok(Outcome::Spared);
        }
        _ => {}
    }

    let (name, armed): (&str, bool) = match response {
        Response::Warn => ("warn", cfg.arm.warn),
        Response::DeleteAndWarn => ("delete_and_warn", cfg.arm.delete),
        Response::Kick => ("kick", cfg.arm.kick),
        Response::Ban => ("ban", cfg.arm.ban),
    };

    // ── Dedup ───────────────────────────────────────────────────────────────
    // Scoped to armed-ness: a rehearsal only ever dedups rehearsals, or a day
    // of dry running silences the bot on the day it is armed.
    if let Some(prev) = store.strongest_response(community.id(), &v.npub, !armed).map_err(vector_sdk::Error::Other)? {
        if Response::rank_of(&prev) >= response.rank() {
            return Ok(Outcome::AlreadyAnswered);
        }
    }

    // ── Ceilings ────────────────────────────────────────────────────────────
    // A bug must not be able to empty a community, and the check belongs here
    // so the live lanes inherit it rather than each remembering to ask.
    {
        let p = pass.lock().unwrap_or_else(|e| e.into_inner());
        if p.acted >= cfg.limits.max_actions_per_run {
            println!("[{id}] HELD    {who} — run ceiling ({}) reached", cfg.limits.max_actions_per_run);
            return Ok(Outcome::Held);
        }
        if let Some(ceiling) = p.roster_ceiling(cfg) {
            if p.acted >= ceiling {
                println!(
                    "[{id}] HALT — {} action(s) is all {}% of {} members allows. A human decides from here.",
                    ceiling, cfg.limits.halt_if_over_pct, p.roster
                );
                return Ok(Outcome::Halted);
            }
        }
    }
    if store.actions_last_hour(now).map_err(vector_sdk::Error::Other)? >= cfg.limits.max_actions_per_hour {
        println!("[{id}] HELD    {who} — hourly ceiling ({}) reached", cfg.limits.max_actions_per_hour);
        return Ok(Outcome::Held);
    }

    println!("[{id}] {} {name} {who} — {total} strike(s) — {why}", if armed { "ENFORCE" } else { "WOULD  " });

    // ── Act, THEN log ───────────────────────────────────────────────────────
    // Logging first recorded a failed ban as a successful one: it counted
    // against the hourly ceiling, marked the member as already answered
    // forever, and its error aborted the rest of the pass.
    if armed {
        let outcome = match response {
            Response::Warn => bot.dm(&v.npub).send(&warn_text(&why)).await.map(|_| ()),
            Response::DeleteAndWarn => {
                for msg_id in v.findings.iter().flat_map(|f| f.messages.iter()) {
                    if let Some(m) = bot.message(msg_id).await {
                        if let Err(e) = m.hide().await {
                            eprintln!("[{id}] hide {}: {e}", short(msg_id));
                        }
                    }
                }
                bot.dm(&v.npub).send(&warn_text(&why)).await.map(|_| ())
            }
            Response::Kick => community.member(v.npub.clone()).kick().await,
            Response::Ban => community.member(v.npub.clone()).ban().await,
        };
        if let Err(e) = outcome {
            // Nothing happened, so nothing is recorded. The member stays
            // reachable next pass instead of being immune to everything.
            eprintln!("[{id}] {name} {who} FAILED: {e}");
            return Ok(Outcome::Failed);
        }
    }

    store.log_action(community.id(), &v.npub, name, !armed, now, &why).map_err(vector_sdk::Error::Other)?;
    // The mod channel is an audit trail of what HAPPENED. A dry run announcing
    // every rehearsal fills it with things nobody did.
    if armed {
        announce(bot, community, cfg, &format!("{name} {who} — {total} strike(s) — {why}")).await;
    }
    pass.lock().unwrap_or_else(|e| e.into_inner()).acted += 1;
    Ok(Outcome::Acted)
}

/// What one pass has spent, so the ceilings mean something across every lane.
#[derive(Debug, Default)]
struct PassState {
    acted: usize,
    roster: usize,
}

impl PassState {
    /// How many actions the roster percentage allows this pass.
    ///
    /// Floored at one: `10%` of a five-member community rounds to zero, which
    /// halted the ladder before its first action and would have made a small
    /// test community look peaceful while nothing worked at all.
    fn roster_ceiling(&self, cfg: &Config) -> Option<usize> {
        if self.roster == 0 {
            return None;
        }
        Some(((cfg.limits.halt_if_over_pct as usize * self.roster) / 100).max(1))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Acted,
    Spared,
    Held,
    Halted,
    AlreadyAnswered,
    Failed,
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

/// FNV-1a. Only needs to distinguish one cohort from another.
fn fnv(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
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

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict(shield: &str) -> Verdict {
        Verdict {
            npub: "npub1subject".into(),
            name: "npub1subject".into(),
            confidence: 90,
            proven: 90,
            band: "alert".into(),
            shield: shield.into(),
            reasons: vec!["matched a rule".into()],
            findings: vec![],
            messages: 0,
            tenure_secs: 0,
        }
    }

    /// The bug that made every one of these worth writing: the shield check
    /// lived in `sweep`, behind a filter that had already removed the shielded,
    /// so it was unreachable — and the two live lanes reached `enforce` without
    /// passing it at all. The gate is inside `enforce` now, so this is the
    /// property every path inherits.
    #[test]
    fn standing_stops_a_sentence_before_anything_else_is_considered() {
        let cfg = Config::default();
        for (shield, spared) in [
            ("protected", true),
            ("trusted", true),
            ("unknown", true), // before the first sweep, nobody's standing is known
            ("none", false),
            ("indeterminate", false), // tenure unknowable is NOT standing
        ] {
            let v = verdict(shield);
            let gated = matches!(v.shield.as_str(), "protected" | "unknown")
                || (v.shield == "trusted" && cfg.shields.respect_trusted);
            assert_eq!(gated, spared, "shield {shield}");
        }
    }

    /// `respect_protected` cannot be switched off, and the refusal names it.
    #[test]
    fn the_owner_is_never_sentinels_to_judge() {
        let cfg: Config = toml::from_str("[shields]\nrespect_protected = false").unwrap();
        let err = Config::validate_for_test(&cfg).expect_err("must refuse");
        assert!(err.contains("respect_protected"), "{err}");
    }

    /// A five-member community used to halt before its first action, forever:
    /// 10% of 5 rounds to 0. A test community would have looked peaceful while
    /// nothing worked at all.
    #[test]
    fn a_small_community_still_permits_one_action() {
        let cfg = Config::default();
        for roster in 1..=12usize {
            let p = PassState { acted: 0, roster };
            assert_eq!(p.roster_ceiling(&cfg), Some(((10 * roster) / 100).max(1)));
            assert!(p.roster_ceiling(&cfg).unwrap() >= 1, "roster {roster} could never act");
        }
        // And the percentage still bites once it means something.
        let p = PassState { acted: 10, roster: 100 };
        assert_eq!(p.roster_ceiling(&cfg), Some(10), "10% of 100 is still 10");
    }

    /// An empty roster has no percentage to compute, and must not become a
    /// ceiling of zero that blocks everything.
    #[test]
    fn an_unknown_roster_imposes_no_percentage() {
        assert_eq!(PassState { acted: 0, roster: 0 }.roster_ceiling(&Config::default()), None);
    }

    /// The string table this replaced had a `_ => 0` catch-all, so a renamed
    /// variant read as "nothing has happened yet" and re-sentenced everyone.
    #[test]
    fn stored_response_names_rank_the_same_as_the_enum() {
        assert!(Response::rank_of("warn") < Response::rank_of("delete_and_warn"));
        assert!(Response::rank_of("delete_and_warn") < Response::rank_of("kick"));
        assert!(Response::rank_of("kick") < Response::rank_of("ban"));
        assert_eq!(Response::rank_of("warn"), Response::Warn.rank());
        assert_eq!(Response::rank_of("ban"), Response::Ban.rank());
        assert_eq!(Response::rank_of("raid:kick"), 0, "a raid row is not a ladder response");
        assert_eq!(Response::rank_of("raid:claim"), 0);
        assert_eq!(Response::rank_of(""), 0);
    }
}
