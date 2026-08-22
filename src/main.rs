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

mod adjudicate;
mod config;
mod ladder;
mod policy;
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

use adjudicate::Sentence;
use config::{Config, Gravity, RaidResponse, Response};
use policy::{CommunityPolicy, Powers};
use tokio::sync::Semaphore;
use store::Store;
use tripwire::Tripwire;

/// Per-community state the live lanes need and cannot compute themselves.
#[derive(Default)]
struct Watch {
    tripwire: Option<Tripwire>,
    /// Held across the whole of one sentence. The SDK spawns a task per
    /// inbound message, so without this forty concurrent screens each read
    /// `acted_this_hour = 0`, each pass the ceiling, and each act — the guard
    /// voided during exactly the event it exists for. A tokio mutex, because
    /// it is deliberately held across the kick/ban await.
    enforcing: Arc<tokio::sync::Mutex<()>>,
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

/// If the sweep task ever unwinds, say so loudly rather than degrading into a
/// bot that enforces on a frozen roster.
struct SweepTaskGuard;

impl Drop for SweepTaskGuard {
    fn drop(&mut self) {
        eprintln!("FATAL: the sweep task stopped. Sentinel cannot refresh standing; exiting.");
        std::process::exit(1);
    }
}

/// One community's turn to sentence. Everything from reading the ceilings to
/// writing the row happens under this, so the read is a reservation rather than
/// a guess that another task has already invalidated.
fn enforce_lock(wires: &Watches, community: &str) -> Arc<tokio::sync::Mutex<()>> {
    wires
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(community.to_string())
        .or_default()
        .enforcing
        .clone()
}

/// A member's standing as the last sweep saw it. `"unknown"` before the first
/// sweep, and `enforce` holds rather than acts on that.
fn standing_of(watches: &Watches, community: &str, npub: &str) -> String {
    let guard = watches.lock().unwrap_or_else(|e| e.into_inner());
    match guard.get(community) {
        // Present in the roster the last sweep read: that IS their standing.
        Some(w) if w.known => w.standing.get(npub).cloned().unwrap_or_else(|| "absent".into()),
        _ => "unknown".into(),
    }
}

/// A member the last sweep never saw — joined since, or the roster is stale.
/// Their standing is not knowable from the cache, so ask the community's own
/// roles before treating them as ordinary.
fn resolve_absent(shield: String, msg: &vector_sdk::IncomingMessage) -> String {
    if shield != "absent" {
        return shield;
    }
    match msg.member() {
        Some(m) if m.is_admin() => "protected".into(),
        _ => "none".into(),
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
        .filter(|c| cfg.watches(c.id()))
        .collect();
    if communities.is_empty() {
        println!("Not a member of any watched community yet. Invite Sentinel from the Vector app.");
    }
    let mut installed_at_boot: std::collections::HashSet<String> = std::collections::HashSet::new();
    for c in &communities {
        let powers = powers_of(c).await;
        match rules::install(c, &cfg).await {
            Ok(what) => {
                installed_at_boot.insert(c.id().to_string());
                println!("watching {} — {what} — {}", short(c.id()), powers.describe());
            }
            Err(e) => eprintln!("watching {} — rulebook rejected: {e} — retrying next pass", short(c.id())),
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
        let installed_at_boot = installed_at_boot;
        tokio::spawn(async move {
            let mut installed: std::collections::HashSet<String> = installed_at_boot;
            // Unsupervised, a panic here kills the sweep silently and leaves the
            // live lanes enforcing against a standing cache that never updates
            // again. Losing the sweep is worse than stopping.
            let _guard = SweepTaskGuard;
            loop {
                // Re-resolved every pass: a community joined after startup was
                // never swept and never got a rulebook, and one Sentinel was
                // removed from kept being polled forever.
                let mine: Vec<Community> =
                    bot.communities().await.into_iter().filter(|c| cfg.watches(c.id())).collect();
                // Forget the ones Sentinel has left, so a re-invite reinstalls.
                installed.retain(|id| mine.iter().any(|c| c.id() == id));
                for c in mine {
                    // Marked installed only on SUCCESS. Inserting first meant a
                    // transient failure at boot left that community watched with
                    // no rulebook forever, printing a healthy heartbeat.
                    if !installed.contains(c.id()) {
                        let powers = powers_of(&c).await;
                        match rules::install(&c, &cfg).await {
                            Ok(what) => {
                                installed.insert(c.id().to_string());
                                println!("watching {} — {what} — {}", short(c.id()), powers.describe());
                            }
                            Err(e) => eprintln!("watching {} — rulebook rejected: {e} — retrying next pass", short(c.id())),
                        }
                    }
                    if let Err(e) = sweep(&bot, &c, &cfg, &store, &wires, &me).await {
                        eprintln!("{}: {e}", short(c.id()));
                    }
                }
                // The store holds every community's history, so the janitor
                // keeps the LONGEST memory any of them asked for. Pruning on the
                // default forgave a long-memory community early and deleted the
                // record of what had already been done there.
                let widest = cfg
                    .community
                    .values()
                    .filter_map(|o| o.ladder.as_ref().and_then(|l| l.decay_half_life_hours))
                    .chain(std::iter::once(cfg.ladder.decay_half_life_hours))
                    .max()
                    .unwrap_or(cfg.ladder.decay_half_life_hours);
                let horizon =
                    now_ms().saturating_sub(widest.saturating_mul(3_600_000).saturating_mul(32));
                if let Err(e) = store.prune(horizon) {
                    eprintln!("prune: {e}");
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
                        if let Err(e) = screen(&bot, &msg, &cfg, &store, &wires, &me).await {
                            eprintln!("screen: {e}");
                        }
                        if let Err(e) =
                            watch_media(&bot, &msg, &cfg, &store, eyes.as_ref().as_ref(), &wires, &budget, &me).await
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
    // The only path that was not scoped. Anyone can invite Sentinel (it builds
    // `.public()`), and a join flood there reached the whole ladder against
    // policies Sentinel never installed.
    if !cfg.watches(community.id()) {
        return;
    }
    let cid = community.id().to_string();
    let tripped = {
        let mut guard = wires.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .entry(cid.clone())
            .or_default()
            .tripwire
            .get_or_insert_with(|| {
                let r = cfg.for_community(&cid).raid;
                Tripwire::new(r.tripwire_accounts, r.tripwire_secs, r.tripwire_cooldown_secs)
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
    me: &str,
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
    let policy = cfg.for_community(community.id());
    // Standing BEFORE recording. The live screen sees one message, so a
    // long-tenured regular reads as untrusted there — and their strikes piled
    // up invisibly while `enforce` spared them, ready to fire all at once if
    // `respect_trusted` were ever turned off.
    let shield = resolve_absent(standing_of(watches, community.id(), &author), msg);
    if matches!(shield.as_str(), "protected" | "unknown") || (shield == "trusted" && policy.shields.respect_trusted) {
        return Ok(());
    }
    let mut fresh = false;
    let mut worst: Option<(Gravity, String)> = None;
    for f in &findings {
        if !f.is_proven() {
            continue; // inference never earns a strike, on any clock
        }
        let gravity = policy.gravity_of(&f.rule_id, &f.severity);
        let worth = policy.ladder.strikes.worth(gravity);
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
        // The same id the sweep mints, so whichever clock arrives first wins.
        let conviction = conviction_id(&f.policy_hash, &f.rule_id, &msg.message.id);
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
    let total = ladder::total(&strikes, now, policy.ladder.decay_half_life_hours);
    let ctx = live_ctx(cfg, &community, watches, me, false).await;
    if let Some(response) = ladder::decide(&ctx.policy.ladder, total) {
        let v = live_verdict(&author, shield, &evidence, msg.message.id.clone(), &findings);
        enforce(bot, &community, &ctx, store, watches, &Mutex::new(0), &v, response, total, now).await?;
    }
    Ok(())
}

/// One community's context for a live lane. Its rulebook and its powers, same
/// as the sweep resolves — a message arriving is not a reason to judge it by
/// somebody else's standards.
async fn live_ctx(cfg: &Config, community: &Community, watches: &Watches, me: &str, from_vision: bool) -> Ctx {
    Ctx {
        policy: cfg.for_community(community.id()),
        powers: powers_of(community).await,
        roster: roster_of(watches, community.id()),
        me: me.to_string(),
        mod_channel: cfg.bot.mod_channel.clone(),
        from_vision,
    }
}

/// What this community actually permits. Read, never assumed.
async fn powers_of(community: &Community) -> Powers {
    community.capabilities().map(|c| Powers::from_capabilities(&c)).unwrap_or_default()
}

/// The roster as the last sweep counted it, so a live action is bound by the
/// same percentage ceiling the sweep obeys.
/// One offense, one id, whichever clock reaches it first.
fn conviction_id(policy_hash: &str, rule_id: &str, message_id: &str) -> String {
    format!("msg:{policy_hash}:{rule_id}:{message_id}")
}

/// The roster as the last sweep counted it, so a live action is bound by the
/// same percentage ceiling the sweep obeys.
fn roster_of(watches: &Watches, community: &str) -> usize {
    watches.lock().unwrap_or_else(|e| e.into_inner()).get(community).map(|w| w.standing.len()).unwrap_or(0)
}

/// Media that was never judged. Silence here is a way to slip something past:
/// twenty junk images exhaust the minute's budget and the twenty-first is
/// dropped with nothing said. One line per minute-bucket, so a flood is one
/// message rather than a hundred.
#[allow(clippy::too_many_arguments)]
async fn unclassified(
    bot: &VectorBot,
    community: &Community,
    cfg: &Config,
    store: &Arc<Store>,
    watches: &Watches,
    me: &str,
    now: u64,
    att_id: &str,
    why: &str,
) {
    println!("[media] UNJUDGED {} — {why} — for review", short(att_id));
    let bucket = format!("unjudged:{}", now / 60_000);
    if store.claim_cohort(community.id(), &bucket, now, 3_600_000).unwrap_or(false) {
        let ctx = live_ctx(cfg, community, watches, me, true).await;
        announce(bot, community, &ctx, "Attachments arrived faster than I could check them — some were not judged.").await;
    }
}

/// A member the store owes for, with no engine finding of their own — the
/// ladder is the entire case.
fn carried_verdict(npub: &str, shield: String) -> Verdict {
    Verdict {
        npub: npub.to_string(),
        name: short(npub).to_string(),
        confidence: 0,
        proven: 0,
        band: "alert".into(),
        shield,
        reasons: vec!["carrying strikes from an earlier finding".into()],
        findings: vec![],
        messages: 0,
        tenure_secs: 0,
    }
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

    /// False means the minute's allowance is gone. Refusing is safe: the caller
    /// treats it as unclassified, which routes to a person rather than passing.
    fn claim(&self) -> bool {
        // Its OWN clock. A caller-supplied timestamp read before a slow
        // download let two tasks with different stale minutes reset each
        // other's bucket, so the counter never accumulated and the cap bounded
        // nothing.
        let minute = now_ms() / 60_000;
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
    me: &str,
) -> vector_sdk::Result<()> {
    let (Some(eyes), true) = (eyes, msg.is_group && msg.is_file && !msg.is_mine()) else { return Ok(()) };
    let (Some(community), Some(author)) = (msg.community(), msg.author()) else { return Ok(()) };
    if !cfg.watches(community.id()) {
        return Ok(());
    }
    // Before ANY byte is fetched. Nothing here could be acted on for a shielded
    // member, and classifying anyway decrypted their private images and — with
    // a remote endpoint — shipped them off the machine to produce a verdict
    // that is then thrown away.
    let shield = resolve_absent(standing_of(watches, community.id(), &author), msg);
    let policy = cfg.for_community(community.id());
    if matches!(shield.as_str(), "protected" | "unknown")
        || (shield == "trusted" && policy.shields.respect_trusted)
    {
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
                unclassified(bot, &community, cfg, store, watches, me, now, &att.id, &format!("{e}")).await;
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
                let Ok(_slot) = budget.slot.try_acquire() else {
                    // Contention is not a reason to wait with megabytes pinned
                    // in memory. Unclassified routes to a person, which is the
                    // safe answer — but it must SAY so, or a wave of junk
                    // images is a way to slip one past unnoticed.
                    unclassified(bot, &community, cfg, store, watches, me, now, &att.id, "classifier busy").await;
                    continue;
                };
                if !budget.claim() {
                    unclassified(bot, &community, cfg, store, watches, me, now, &att.id, "budget spent this minute").await;
                    continue;
                }
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
                let _ = &why;
                // Never an all-clear. An unreachable model is a reason to ask a
                // person, not a reason to let everything through.
                println!("[media] UNKNOWN {} from {} — {why} — for review", short(&att.id), short(&author));
                // The reason can carry the endpoint URL, and this line goes
                // into a community channel.
                announce(bot, &community, &live_ctx(cfg, &community, watches, me, true).await, &format!("Could not classify an attachment from {}.", short(&author))).await;
            }
            vision::Verdict::Flagged(labels) => {
                let hits = vision::over_threshold(&labels, &cfg.vision.labels);
                if hits.is_empty() {
                    continue;
                }
                let (label, gravity) = hits[0].clone();
                let worth = policy.ladder.strikes.worth(gravity);
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
                let total = ladder::total(&strikes, now, policy.ladder.decay_half_life_hours);
                let ctx = live_ctx(cfg, &community, watches, me, true).await;
                if let Some(response) = ladder::decide(&ctx.policy.ladder, total) {
                    let v = synthetic_verdict(&author, shield.clone(), &evidence, msg.message.id.clone());
                    enforce(bot, &community, &ctx, store, watches, &Mutex::new(0), &v, response, total, now).await?;
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
fn operator_surface(bot: &VectorBot, cfg: &Arc<Config>, store: &Arc<Store>) {
    /// Resolved where the question was ASKED. Reporting the top-level config
    /// answered "Armed: nothing (dry run)" in a community armed to ban.
    fn armed_line(p: &CommunityPolicy) -> String {
        let armed: String = [
            (p.arm.warn, "warn "),
            (p.arm.delete, "delete "),
            (p.arm.kick, "kick "),
            (p.arm.ban, "ban "),
            (p.arm.raid, "raid "),
            (p.arm.vision, "vision "),
        ]
        .iter()
        .filter(|(on, _)| *on)
        .map(|(_, n)| *n)
        .collect();
        if armed.trim().is_empty() { "nothing (dry run)".into() } else { armed.trim().to_string() }
    }

    bot.command("status", "What Sentinel is watching, and how much of it it can see").run({
        let cfg = cfg.clone();
        move |ctx| {
            let cfg = cfg.clone();
            async move {
                let Some(community) = ctx.msg.community() else {
                    let _ = ctx.reply("Ask me this inside a community.").await;
                    return;
                };
                let armed = armed_line(&cfg.for_community(community.id()));
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
                    let (Some(community), Some(who)) = (ctx.msg.community(), ctx.str("member").map(str::to_string))
                    else {
                        let _ = ctx.reply("Ask me this inside a community, naming a member.").await;
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
    if !cfg.watches(community.id()) {
        return Ok(());
    }
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
        from_vision: false,
    };
    let pass = Mutex::new(0usize);
    let mut convicted = 0usize;
    let mut halted = false;

    // `all()`, not `proven()`: the shielded are filtered out upstream by
    // `proven()`, so gating on them inside that loop could never fire and the
    // operator never saw who was spared.
    for v in verdicts.all().filter(|v| v.is_proven()) {
        if v.npub == me {
            continue;
        }
        convicted += 1;

        // Record what is NEW this poll. Verdicts re-report every standing
        // conviction, so the conviction id is the line between an offense and
        // an echo of one.
        // Which rules already charged per message. A content rule convicts at
        // BOTH scopes over the same citations, so charging the window rung too
        // billed one offense twice — and pushed three flagged links from a kick
        // to an instant ban.
        let charged_per_message: std::collections::HashSet<&str> =
            v.findings.iter().filter(|f| f.stateless).map(|f| f.rule_id.as_str()).collect();
        let mut fresh = false;
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
                    fresh |= store
                        .record(community.id(), &v.npub, &conviction_id(&f.policy_hash, &f.rule_id, mid), worth, now, &evidence)
                        .map_err(vector_sdk::Error::Other)?;
                }
                continue;
            }
            fresh |= store
                .record(community.id(), &v.npub, &f.conviction_id, worth, now, &evidence)
                .map_err(vector_sdk::Error::Other)?;
        }
        // Deliberately NOT gated on "anything new this poll": a sentence the
        // last pass could not carry out — a ceiling, a failed ban, a permission
        // Sentinel did not have — left no record, so re-checking only on a NEW
        // offense meant the debt was silently forgotten. `adjudicate` already
        // refuses to answer the same standing twice, so re-asking is cheap and
        // correct.
        let _ = fresh;

        let strikes = store.strikes(community.id(), &v.npub).map_err(vector_sdk::Error::Other)?;
        let total = ladder::total(&strikes, now, ctx.policy.ladder.decay_half_life_hours);
        let Some(response) = ladder::decide(&ctx.policy.ladder, total) else { continue };

        if enforce(bot, community, &ctx, store, wires, &pass, v, response, total, now).await? == Outcome::Halted {
            halted = true;
            break;
        }
    }

    // Everyone the store owes for, whom the engine did not report. A vision-only
    // offender, or one whose live strikes never lifted their engine score, is
    // invisible to the loop above — so a sentence held by a ceiling or lost to a
    // failed action had nothing that would ever retry it.
    if !halted {
        let horizon = now.saturating_sub(
            ctx.policy.ladder.decay_half_life_hours.saturating_mul(3_600_000).saturating_mul(32),
        );
        let seen: std::collections::HashSet<&str> = verdicts.all().map(|v| v.npub.as_str()).collect();
        for npub in store.subjects_with_strikes(community.id(), horizon).map_err(vector_sdk::Error::Other)? {
            if seen.contains(npub.as_str()) || npub == me {
                continue;
            }
            let strikes = store.strikes(community.id(), &npub).map_err(vector_sdk::Error::Other)?;
            let total = ladder::total(&strikes, now, ctx.policy.ladder.decay_half_life_hours);
            let Some(response) = ladder::decide(&ctx.policy.ladder, total) else { continue };
            let shield = standing_of(wires, community.id(), &npub);
            let v = carried_verdict(&npub, shield);
            if enforce(bot, community, &ctx, store, wires, &pass, &v, response, total, now).await? == Outcome::Halted {
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

    heartbeat(id, &verdicts, convicted, &ctx.powers);
    Ok(())
}

/// A raid answers to itself, not to the ladder — but it answers to the same
/// standing, powers and ceilings as everything else.
///
/// See [`raid`] for why this is the one path where inference may act, and only
/// once armed.
async fn contain(
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
                .claim_cohort(community.id(), &format!("halt:{}", now / 3_600_000), now, ttl)
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

    // Claimed PER MEMBER, not per cohort. A wave arriving over many sweeps
    // grows the set every pass, so a whole-set fingerprint re-contained
    // everyone already handled — which for bans is a key rotation each time.
    // Claims are scoped to armed-ness, so a rehearsal never immunises a cohort
    // against a later real containment.
    let scope = if armed { "live" } else { "dry" };
    let ttl = ctx.policy.raid.claim_ttl_secs.saturating_mul(1000);
    let mut fresh: Vec<String> = Vec::new();
    for npub in &suspects {
        if store
            .claim_cohort(community.id(), &format!("{scope}:{npub}"), now, ttl)
            .map_err(vector_sdk::Error::Other)?
        {
            fresh.push(npub.clone());
        }
    }
    if fresh.is_empty() {
        return Ok(());
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
                for chunk in fresh.chunks(ctx.policy.raid.max_batch.min(raid::BAN_CHUNK)) {
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
                let _ = store.release_cohort(community.id(), &format!("{scope}:{npub}"));
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
    let touched = armed && response != RaidResponse::Report;
    for npub in &done {
        store
            .log_action(community.id(), npub, &format!("raid:{verb}"), !touched, now, "raid cohort")
            .map_err(vector_sdk::Error::Other)?;
    }
    if armed {
        announce(bot, community, ctx, &line).await;
    }
    Ok(())
}

/// Carry out (or rehearse) whatever [`adjudicate`] decided.
///
/// The decision is NOT made here. This gathers the facts, asks, and obeys —
/// which is what lets a test prove a gate exists without a network, and what
/// stops the next lane reaching an action without passing one.
#[allow(clippy::too_many_arguments)]
async fn enforce(
    bot: &VectorBot,
    community: &Community,
    ctx: &Ctx,
    store: &Arc<Store>,
    wires: &Watches,
    pass: &Mutex<usize>,
    v: &Verdict,
    response: Response,
    total: u32,
    now: u64,
) -> vector_sdk::Result<Outcome> {
    let gate = enforce_lock(wires, community.id());
    let _serial = gate.lock().await;
    let id = short(community.id());
    let why = v.why();
    let who = short(&v.npub);

    // The SAME armed-ness the sentence will be carried out under. Computing it
    // differently here scoped the dedup lookup to the wrong `dry` space, so a
    // vision rehearsal was deduped against real kicks.
    let from_vision = ctx.from_vision;
    let armed_class = adjudicate::armed_for(&ctx.policy, response, from_vision);
    // Answers decay with the strikes they answered: `32` halvings is where a
    // strike reaches zero, so beyond that there is nothing left to have
    // answered for.
    let horizon = now.saturating_sub(ctx.policy.ladder.decay_half_life_hours.saturating_mul(3_600_000).saturating_mul(32));
    let prior = store
        .strongest_response(community.id(), &v.npub, !armed_class, horizon)
        .map_err(vector_sdk::Error::Other)?;
    let facts = adjudicate::Facts {
        shield: &v.shield,
        prior: prior.as_deref(),
        acted_this_pass: *pass.lock().unwrap_or_else(|e| e.into_inner()),
        // Scoped the same way the dedup lookup is. Counting only real actions
        // meant a full dry run never hit a ceiling, so the operator rehearsed a
        // run that looked nothing like the armed one.
        acted_this_hour: store
            .actions_last_hour(community.id(), !armed_class, now)
            .map_err(vector_sdk::Error::Other)?,
        roster: ctx.roster,
        is_me: v.npub == ctx.me,
        from_vision,
    };

    let (response, armed) = match adjudicate::adjudicate(&ctx.policy, ctx.powers, &facts, response) {
        Sentence::Spare { why: reason } => {
            println!("[{id}] QUEUED  {who} — {why} ({reason})");
            return Ok(Outcome::Spared);
        }
        Sentence::Answered => return Ok(Outcome::AlreadyAnswered),
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
        Sentence::Carry { response, armed } => (response, armed),
    };

    let name = response.name();
    println!("[{id}] {} {name} {who} — {total} strike(s) — {why}", if armed { "ENFORCE" } else { "WOULD  " });

    // Act, THEN log. Logging first recorded a failed ban as a success: it
    // counted against the ceiling and marked the member answered forever.
    if armed {
        let outcome = match response {
            Response::Warn => bot.dm(&v.npub).send(&warn_text(&why)).await.map(|_| ()),
            Response::DeleteAndWarn => {
                // Capped: a member cited across fifty messages is one sentence,
                // not fifty round trips inside one decision.
                let mut hidden = std::collections::HashSet::new();
                for msg_id in v
                    .findings
                    .iter()
                    .filter(|f| f.is_proven())
                    .flat_map(|f| f.messages.iter())
                    .filter(|m| hidden.insert((*m).clone()))
                    .take(MAX_HIDES)
                {
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
            // Nothing happened, so nothing is recorded — the debt stands and
            // the member is reachable again next pass.
            eprintln!("[{id}] {name} {who} FAILED: {e}");
            return Ok(Outcome::Failed);
        }
    }

    store.log_action(community.id(), &v.npub, name, !armed, now, &why).map_err(vector_sdk::Error::Other)?;
    // The mod channel is an audit trail of what HAPPENED; a dry run announcing
    // every rehearsal fills it with things nobody did.
    if armed {
        announce(bot, community, ctx, &format!("{name} {who} — {total} strike(s) — {why}")).await;
    }
    *pass.lock().unwrap_or_else(|e| e.into_inner()) += 1;
    Ok(Outcome::Acted)
}

/// A member cited across many messages is still one sentence.
const MAX_HIDES: usize = 10;

/// One community, as this pass sees it: its own rulebook, its own powers, its
/// own roster. Nothing about judging one community may leak into another.
struct Ctx {
    policy: CommunityPolicy,
    powers: Powers,
    roster: usize,
    me: String,
    mod_channel: Option<String>,
    /// Provenance, carried rather than sniffed. Reading it back off a rule id
    /// let an operator route a rule named "vision" through the wrong switch.
    from_vision: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Acted,
    Spared,
    Held,
    Halted,
    AlreadyAnswered,
    Powerless,
    Failed,
}

fn warn_text(why: &str) -> String {
    format!(
        "Sentinel here. A community rule matched your recent messages: {why}. \
         This is a warning; repeated matches escalate. Reply to a moderator if you think this is wrong."
    )
}

/// Best-effort audit line into the operator's mod channel, when one is named.
async fn announce(bot: &VectorBot, community: &Community, ctx: &Ctx, line: &str) {
    let Some(want) = &ctx.mod_channel else { return };
    for ch in community.channels().await {
        if ch.name() == want && ch.is_readable() {
            let _ = bot.channel(ch.id()).send(line).await;
            return;
        }
    }
}

/// Never panics on a short string, which a remote peer can supply.
fn short(s: &str) -> &str {
    let mut end = 12.min(s.len());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// What the sweep looked at, whether or not it found anything.
///
/// A quiet community and a broken bot print the same thing — nothing — and that
/// is exactly how a moderation tool stays broken for months. Every pass says
/// what it read and how many people it weighed, so silence becomes a result
/// rather than an absence of one.
fn heartbeat(community: &str, verdicts: &Verdicts, found: usize, powers: &Powers) {
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
        powers.describe(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every gate now lives in `adjudicate`, which is a pure function tested
    /// against itself rather than against a restatement of its rules. What is
    /// left here is the glue those gates depend on.
    #[test]
    fn a_short_string_never_panics_however_a_peer_supplies_it() {
        // A remote peer chooses attachment ids and message ids. Slicing them
        // raw used to panic mid-handler, and the panic unwound the event
        // closure BEFORE the tripwire ran — an attacker could hide a raid
        // behind one one-byte field.
        for s in ["", "a", "abcdefghijk", "abcdefghijkl", &"x".repeat(200), "aaaaaaaaaa日本", "日"] {
            assert!(short(s).len() <= 12);
        }
        assert_eq!(short("abcdefghijklmnop"), "abcdefghijkl");
        // A byte index inside a multi-byte character panics; back off to a boundary.
        assert_eq!(short("aaaaaaaaaa日本"), "aaaaaaaaaa");
    }

    /// Both clocks must mint the SAME id for one offense, or it is charged
    /// twice — and if either skips it on the assumption the other has it, an
    /// offense during downtime is charged by nobody.
    #[test]
    fn one_offense_has_one_id_whichever_clock_reaches_it() {
        let a = conviction_id("policy1", "slurs", "msg1");
        assert_eq!(a, conviction_id("policy1", "slurs", "msg1"));
        assert_ne!(a, conviction_id("policy1", "slurs", "msg2"), "a second message is a second offense");
        assert_ne!(a, conviction_id("policy1", "links", "msg1"), "a different rule is a different offense");
        assert_ne!(a, conviction_id("policy2", "slurs", "msg1"), "and a different law is too");
    }
}
