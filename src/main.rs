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

/// Marks a deliberate stop, so the sweep guard does not read a clean shutdown
/// as a crash.
struct ShutdownFlag;

impl Drop for ShutdownFlag {
    fn drop(&mut self) {
        SHUTTING_DOWN.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// If the sweep task ever unwinds, say so loudly rather than degrading into a
/// bot that enforces on a frozen roster.
struct SweepTaskGuard;

static SHUTTING_DOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

impl Drop for SweepTaskGuard {
    fn drop(&mut self) {
        if SHUTTING_DOWN.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }
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
        match rules::install(c, &cfg, &store).await {
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
                        match rules::install(&c, &cfg, &store).await {
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
                // A tombstone only works while it outlives the EVIDENCE window,
                // and a claim only while it outlives its TTL. Pruning on the
                // half-life alone deleted a pardon 32 hours after it was given,
                // and the engine promptly re-reported the conviction.
                let ids: Vec<String> = cfg.community.keys().cloned().chain(std::iter::once(String::new())).collect();
                let keep_ms = ids
                    .iter()
                    .map(|id| {
                        let p = cfg.for_community(id);
                        let decay = p.ladder.decay_half_life_hours.saturating_mul(3_600_000).saturating_mul(32);
                        let window = p.rules.window_hours.saturating_mul(3_600_000);
                        let claims = p.raid.claim_ttl_secs.saturating_mul(1000);
                        decay.max(window).max(claims)
                    })
                    .max()
                    .unwrap_or(0);
                let horizon = now_ms().saturating_sub(keep_ms);
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
        // Anything after the listener returns is a deliberate stop, not a crash.
    let _shutdown = ShutdownFlag;
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

    let r = cfg.for_community(&cid).raid;
    println!(
        "[{}] TRIPWIRE — {} distinct accounts inside {}s, evaluating now",
        short(community.id()),
        r.tripwire_accounts,
        r.tripwire_secs
    );
    // The 90-second memoisation is right for a background pass and far too slow
    // for a wave in progress.
    community.invalidate();
    match sweep(bot, community, cfg, store, wires, me).await {
        // Only a genuine race gives the trip back. Checking `sweeping`
        // beforehand was itself a race: both handlers could see false and the
        // loser still lost its trip.
        Ok(Pass::Declined) => untrip(wires, community.id()),
        Ok(_) => {}
        Err(e) => eprintln!("{}: {e}", short(community.id())),
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
        let conviction = conviction_id(&f.rule_id, &msg.message.id);
        fresh |= store
            .record(community.id(), &author, &conviction, worth, now, &evidence, "")
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
    if ladder::decide(&ctx.policy.ladder, total).is_some() {
        let v = live_verdict(&author, shield, &evidence, msg.message.id.clone(), &findings);
        enforce(bot, &community, &ctx, store, watches, &Mutex::new(0), &v, &strikes).await?;
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

/// One offense, one id, whichever clock reaches it first.
fn conviction_id(rule_id: &str, message_id: &str) -> String {
    // Deliberately WITHOUT the policy hash. The rule and the message identify
    // the offense; the rulebook version does not. Including it meant editing
    // one pattern re-keyed every conviction in the open evidence window — so
    // the strikes landed again at full worth stamped `now`, roughly doubling
    // every total, and every pardon tombstone pointed at an id nothing would
    // mint again.
    format!("msg:{rule_id}:{message_id}")
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

/// Who the debt loop may reach, and with what standing.
///
/// Two mistakes this exists to make untestable-by-inspection impossible: keying
/// on "the engine did not report them" reached only EX-members (the engine
/// reports the whole memberlist), and taking their standing from a lookup that
/// answers "absent" for anyone off-roster handed the gate a value meaning
/// "not shielded" for every single subject.
fn debt_subjects(
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

/// Return a spent trip, so the cooldown is not burnt on an evaluation that
/// never happened.
fn untrip(watches: &Watches, community: &str) {
    if let Some(w) = watches.lock().unwrap_or_else(|e| e.into_inner()).get_mut(community) {
        if let Some(t) = w.tripwire.as_mut() {
            t.forget_last_trip();
        }
    }
}

/// The roster as the last sweep read it: npub to standing. Empty when no sweep
/// has completed, which `debt_subjects` treats as "nobody is ours to sentence".
fn roster_of_community(watches: &Watches, community: &str) -> std::collections::HashMap<String, String> {
    watches
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(community)
        .filter(|w| w.known)
        .map(|w| w.standing.clone())
        .unwrap_or_default()
}

/// A member the store owes for, with no engine finding of their own — the
/// ladder is the entire case.
fn carried_verdict(npub: &str, shield: String, evidence: Vec<String>) -> Verdict {
    Verdict {
        npub: npub.to_string(),
        name: short(npub).to_string(),
        confidence: 0,
        proven: 0,
        band: "alert".into(),
        shield,
        // Named, not "carrying strikes from an earlier finding" — that reached
        // the member verbatim as the reason a rule matched them.
        reasons: if evidence.is_empty() { vec!["earlier findings".into()] } else { evidence },
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
        // A pre-filter on the sender's own claims, so it is a REFUSAL to look
        // rather than a clean answer: declaring an oversize or odd-typed
        // attachment must not be a way to have it never judged in silence.
        if att.size > cfg.vision.max_bytes {
            unclassified(bot, &community, cfg, store, watches, me, now, &att.id, "declared over the size limit").await;
            continue;
        }
        let declared = vector_sdk::vector_core::crypto::mime_from_extension(&att.extension);
        if !cfg.vision.mimes.iter().any(|m| m == declared) {
            // Voice notes, video and PDFs are ordinary traffic, not evasion.
            // Announcing them filled the mod channel every minute.
            println!("[media] {} — a type I do not judge", short(&att.id));
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
            unclassified(bot, &community, cfg, store, watches, me, now, &att.id, "over the size limit").await;
            continue;
        }
        // MIME from the bytes, never from a name the uploader chose.
        let actual = vector_sdk::vector_core::crypto::mime_from_magic_bytes(&bytes);
        if !cfg.vision.mimes.iter().any(|m| m == actual) {
            // The name said one thing and the bytes another. Dropping that in
            // silence is the same hole as a timeout reading as clean.
            unclassified(bot, &community, cfg, store, watches, me, now, &att.id, "not a type I can judge").await;
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
                // Never an all-clear. An unreachable model is a reason to ask a
                // person, not a reason to let everything through — and it goes
                // through the same rate limit as every other unjudged blob, or
                // a model answering in prose is N publishes into a channel.
                unclassified(bot, &community, cfg, store, watches, me, now, &att.id, &why).await;
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
                    // Sentinel's own id, stable and rulebook-free: stamped ''
                    // so a rules edit cannot tombstone it. The id is identical
                    // next pass, so a tombstone would erase it for good.
                    .record(community.id(), &author, &conviction, worth, now, &evidence, "")
                    .map_err(vector_sdk::Error::Other)?;
                println!("[media] FLAGGED {} from {} — {evidence}", short(&att.id), short(&author));
                if !fresh {
                    continue;
                }
                let strikes = store.strikes(community.id(), &author).map_err(vector_sdk::Error::Other)?;
                let total = ladder::total(&strikes, now, policy.ladder.decay_half_life_hours);
                // The verdict is what matters from here; N handlers queued on
                // the community gate must not each pin megabytes.
                drop(bytes);
                let ctx = live_ctx(cfg, &community, watches, me, true).await;
                if ladder::decide(&ctx.policy.ladder, total).is_some() {
                    let v = synthetic_verdict(&author, shield.clone(), &evidence, msg.message.id.clone());
                    enforce(bot, &community, &ctx, store, watches, &Mutex::new(0), &v, &strikes).await?;
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
                let Some(community) = ctx.msg.community().filter(|c| cfg.watches(c.id())) else {
                    let _ = ctx.reply("I am not watching this community.").await;
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

/// One pass: verdicts in, strikes recorded, ladder consulted, sentences
/// rehearsed or carried out.
async fn sweep(
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
    let policy_fp = rules::fingerprint(cfg, community.id());
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
                        .record(community.id(), &v.npub, &conviction_id(&f.rule_id, mid), worth, now, &evidence, "")
                        .map_err(vector_sdk::Error::Other)?;
                }
                continue;
            }
            store
                .record(community.id(), &v.npub, &f.conviction_id, worth, now, &evidence, &policy_fp)
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
        let horizon = now.saturating_sub(
            ctx.policy.ladder.decay_half_life_hours.saturating_mul(3_600_000).saturating_mul(32),
        );
        let owed = store.subjects_with_strikes(community.id(), horizon).map_err(vector_sdk::Error::Other)?;
        let roster = roster_of_community(wires, community.id());
        for (npub, shield) in debt_subjects(&handled, &roster, owed, me) {
            let strikes = store.strikes(community.id(), &npub).map_err(vector_sdk::Error::Other)?;
            let v = carried_verdict(&npub, shield, store.evidence(community.id(), &npub).unwrap_or_default());
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

/// What one sweep did. `Held` means it ran and found nothing it could work
/// with; `Declined` means another sweep already had the community. Only the
/// second is a reason to give a trip back — treating them alike meant a failing
/// roster read zeroed the cooldown and cost a full corpus evaluation PER
/// MESSAGE during exactly the wave the cooldown exists for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pass {
    Ran,
    Held,
    Declined,
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

    let verb = response.name();
    let touched = armed && response != RaidResponse::Report;
    // A ceiling that spans TIME, not one pass. `raid::select` halts only when a
    // SINGLE pass is over the bar, so a sustained false positive contained 10%
    // every two minutes and emptied the community in twenty — without the guard
    // built to prevent exactly that ever firing.
    let spent = store
        .raid_actions_last_hour(community.id(), !touched, now)
        .map_err(vector_sdk::Error::Other)?;
    // Claimed PER MEMBER, not per cohort. A wave arriving over many sweeps
    // grows the set every pass, so a whole-set fingerprint re-contained
    // everyone already handled — which for bans is a key rotation each time.
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
            .claim_cohort(community.id(), &format!("{scope}:{npub}"), now, ttl)
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
                let _ = store.release_cohort(community.id(), &format!("{scope}:{npub}"));
            }
            let ttl = ctx.policy.raid.claim_ttl_secs.saturating_mul(1000);
            if store
                .claim_cohort(community.id(), &format!("halt:{}", now / 3_600_000), now, ttl)
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

/// How far back an answer still answers for anything.
fn answer_horizon(policy: &CommunityPolicy, now: u64) -> u64 {
    now.saturating_sub(policy.ladder.decay_half_life_hours.saturating_mul(3_600_000).saturating_mul(32))
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
pub fn select_rung(
    policy: &CommunityPolicy,
    powers: Powers,
    store: &Store,
    community: &str,
    npub: &str,
    strikes: &[ladder::Strike],
    from_vision: bool,
    now: u64,
) -> Result<Option<(Response, bool)>, String> {
    // Derived here, not taken: `now` and `horizon` were two parameters that
    // must agree, in the function whose seams have failed seven passes running.
    let horizon = answer_horizon(policy, now);
    // Provenance is a property of the RUNG, not of the member.
    //
    // A boolean taint over the whole member was wrong in both directions: one
    // flagged image disarmed every response against them, so the worse the
    // offense the more immune they became — and a taint that expired sooner
    // than the strike still counted meant a total only inference could reach
    // was carried out under the text switches.
    //
    // So the total is split. Whatever the PROVABLE points reach is answerable
    // under the text switches; a rung only the full total reaches leans on a
    // model's opinion and answers to `arm.vision`.
    let hl = policy.ladder.decay_half_life_hours;
    let provable = ladder::provable_total(strikes, now, hl);
    let total = ladder::total(strikes, now, hl);
    let leans_on_vision = |r: Response| {
        from_vision || ladder::decide(&policy.ladder, provable).map(|p| r.rank() > p.rank()).unwrap_or(true)
    };
    let picked = ladder::next_step(
        &policy.ladder,
        total,
        |r| store.strongest_response(community, npub, !adjudicate::armed_for(policy, r, leans_on_vision(r)), horizon),
        |r| powers.can_deliver(r),
    )?;
    Ok(picked.map(|r| (r, leans_on_vision(r))))
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
    strikes: &[ladder::Strike],
) -> vector_sdk::Result<Outcome> {
    let gate = enforce_lock(wires, community.id());
    let _serial = gate.lock().await;
    // AFTER the gate. Waiting on a contended community could span minutes, and
    // the caller's instant measured the hourly window from the wrong moment.
    let now = now_ms();
    let id = short(community.id());
    let why = v.why();
    let who = short(&v.npub);

    let horizon = answer_horizon(&ctx.policy, now);

    // Pick the rung HERE, one place, asking each candidate about the space it
    // would actually be recorded in — and take the PROVENANCE it derived back
    // with it.
    //
    // A caller that chose the rung had to guess an armed-ness for its lookup,
    // and any `[arm]` block that was not uniform made that guess wrong. Letting
    // it re-derive the provenance from its own lane was the same bug one level
    // down: the rung was chosen against one `dry` space and then armed,
    // deduped, counted and recorded in the other.
    let Some((response, from_vision)) =
        select_rung(&ctx.policy, ctx.powers, store, community.id(), &v.npub, strikes, ctx.from_vision, now)
            .map_err(vector_sdk::Error::Other)?
    else {
        // Every rung up to what they earned is already answered.
        return Ok(Outcome::AlreadyAnswered);
    };
    let armed_class = adjudicate::armed_for(&ctx.policy, response, from_vision);
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
        // Distinct PEOPLE, because the ladder climbs: one offender now spends
        // up to four rows, and a roster halt counting rows tripped on a single
        // member in a small community and took raid containment down with it.
        // EXCLUDING this member. The ladder climbs, so escalating someone
        // already inside the bound counted them again — and with a ceiling of
        // 1 (any roster under 20) the first sentence of the hour halted the
        // whole bot, the debt loop and raid containment for 58 minutes.
        subjects_this_hour: store
            .subjects_actioned_last_hour(community.id(), !armed_class, now, &v.npub)
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
        // Unreachable now the rung is chosen against the same lookup, kept as
        // a belt — and it prints, because silence is one of the two states a
        // wedged bot lives in.
        Sentence::Answered => {
            println!("[{id}] ANSWERED {who} — {} already given", response.name());
            return Ok(Outcome::AlreadyAnswered);
        }
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
    // Back off before spending anything. A permanently unreachable member cost
    // a DM round trip and a database row on every pass — inside the community's
    // lock, so it starved every other sentence there too.
    let (tries, _, last) = store
        .failure_span(community.id(), &v.npub, name, now.saturating_sub(GIVE_UP_WINDOW_MS))
        .map_err(vector_sdk::Error::Other)?;
    if tries >= MAX_FAILURES && last.is_some_and(|l| now.saturating_sub(l) < BACKOFF_MS) {
        return Ok(Outcome::Failed);
    }

    let total = ladder::total(strikes, now, ctx.policy.ladder.decay_half_life_hours);
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
                let mut failed_hides = 0usize;
                let mut attempted = 0usize;
                for msg_id in v
                    .findings
                    .iter()
                    .filter(|f| f.is_proven())
                    .flat_map(|f| f.messages.iter())
                    .filter(|m| hidden.insert((*m).clone()))
                    .take(MAX_HIDES)
                {
                    attempted += 1;
                    if let Some(m) = bot.message(msg_id).await {
                        if let Err(e) = m.hide().await {
                            eprintln!("[{id}] hide {}: {e}", short(msg_id));
                            failed_hides += 1;
                        }
                    } else {
                        // Already hidden, deleted, or expired: the end state
                        // this rung wanted. Counting it as a failure meant an
                        // offender deleting their own post pinned the ladder.
                    }
                }
                if attempted == 0 {
                    // Proven findings can cite no message at all (tenure, join
                    // burst), so this rung had nothing to delete. Say so; the
                    // ladder still records the rung, or it re-proposes forever.
                    println!("[{id}] nothing to hide for {who} — the warning is the whole sentence");
                } else if failed_hides > 0 {
                    eprintln!("[{id}] {failed_hides} of {attempted} message(s) could not be hidden");
                }
                bot.dm(&v.npub).send(&warn_text(&why)).await.map(|_| ())
            }
            Response::Kick => community.member(v.npub.clone()).kick().await,
            Response::Ban => community.member(v.npub.clone()).ban().await,
        };
        if let Err(e) = outcome {
            eprintln!("[{id}] {name} {who} FAILED: {e}");
            let _ = store.log_action(community.id(), &v.npub, &format!("failed:{name}"), !armed, now, &why);
            // After enough tries this rung is not going to land — gone,
            // outranking us, no inbox relay. Advance the floor so the ladder can
            // move PAST it: leaving it unanswered pinned the member below the
            // rung forever, which turned "unreachable" into "untouchable".
            let (tries, oldest, _) = store
                .failure_span(community.id(), &v.npub, name, now.saturating_sub(GIVE_UP_WINDOW_MS))
                .map_err(vector_sdk::Error::Other)?;
            // Three tries AND a span: a ten-minute relay wobble used to burn
            // both DM rungs in twelve minutes and eject someone who had never
            // received a word.
            let persistent = tries >= MAX_FAILURES && oldest.is_some_and(|o| now.saturating_sub(o) >= GIVE_UP_AFTER_MS);
            // And a rung nobody could deliver does not authorise a REMOVAL on
            // its own. A member Sentinel cannot talk to is a case for the mod
            // channel, not a silent kick.
            // Measured over the ANSWER horizon, not the give-up window: a member
            // whose last delivered action was seven hours ago is reachable, and
            // a six-hour lookback called them a stranger and jumped the ladder.
            let unlocks_removal = matches!(response, Response::Warn | Response::DeleteAndWarn)
                && !store.has_delivered(community.id(), &v.npub, horizon).map_err(vector_sdk::Error::Other)?;
            if persistent && !unlocks_removal {
                println!("[{id}] GAVE UP {name} {who} after {tries} tries — moving past this rung");
                let _ = store.log_action(community.id(), &v.npub, &format!("attempted:{name}"), !armed, now, &why);
            } else if persistent {
                println!("[{id}] UNREACHABLE {who} — {name} keeps failing and nothing has ever reached them");
                // Claimed like every other repeating announcement. Unbounded,
                // this was a mod-channel publish every poll forever, triggerable
                // by anyone who simply publishes no inbox relay list.
                let ttl = ctx.policy.raid.claim_ttl_secs.saturating_mul(1000);
                if store
                    .claim_cohort(community.id(), &format!("unreachable:{name}:{}", v.npub), now, ttl)
                    .map_err(vector_sdk::Error::Other)?
                {
                    announce(
                        bot,
                        community,
                        ctx,
                        &format!("Cannot reach {who}: {name} keeps failing. A person should look."),
                    )
                    .await;
                }
            }
            return Ok(Outcome::Failed);
        }
    }

    // The rung that was ADJUDICATED, always. Logging a lesser one made the
    // ladder re-propose the same rung every pass — a warning DM every poll,
    // forever, and nothing above it ever reachable.
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

/// Attempts of one sentence against one member, within [`GIVE_UP_WINDOW_MS`],
/// before Sentinel stops trying. Enough that a relay blip retries, few enough
/// that a permanently unreachable target is not a per-pass publish forever.
const MAX_FAILURES: usize = 3;

/// How far back failures are counted, and how long they must span before
/// Sentinel treats a rung as undeliverable rather than unlucky.
const GIVE_UP_WINDOW_MS: u64 = 6 * 3_600_000;
const GIVE_UP_AFTER_MS: u64 = 30 * 60_000;

/// How long to leave a failing sentence alone before trying it again.
const BACKOFF_MS: u64 = 60 * 60_000;

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
fn heartbeat(community: &str, verdicts: &Verdicts, found: usize, powers: Option<&Powers>) {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every gate now lives in `adjudicate`, which is a pure function tested
    /// against itself rather than against a restatement of its rules. What is
    /// left here is the glue those gates depend on.
    use crate::config::Config;
    use crate::store::tests::mem;

    const HORIZON: u64 = 0;
    const NOW: u64 = 10_000;

    fn policy_with(arm: &str) -> CommunityPolicy {
        toml::from_str::<Config>(&format!("[arm]\n{arm}")).unwrap().for_community("aa")
    }

    /// Every regression in five review passes lived in this glue rather than in
    /// the rules underneath it. These drive the real selection against a real
    /// store, so a rung the code picks and a rung it records cannot drift.
    #[test]
    fn the_ladder_climbs_and_stops_where_it_should() {
        let store = mem();
        let p = policy_with("warn = true\ndelete = true\nkick = true\nban = true");
        let all = Powers { hide: true, kick: true, ban: true };
        let twelve = [ladder::Strike { worth: 12, at_ms: NOW, from_vision: false }];
        let pick = |s: &Store| {
            select_rung(&p, all, s, "c", "npub1a", &twelve, false, NOW).unwrap().map(|(r, _)| r)
        };

        assert_eq!(pick(&store), Some(Response::Warn), "twelve points still starts at a warning");
        store.log_action("c", "npub1a", "warn", false, NOW, "").unwrap();
        assert_eq!(pick(&store), Some(Response::DeleteAndWarn));
        store.log_action("c", "npub1a", "delete_and_warn", false, NOW, "").unwrap();
        assert_eq!(pick(&store), Some(Response::Kick));
        store.log_action("c", "npub1a", "kick", false, NOW, "").unwrap();
        assert_eq!(pick(&store), Some(Response::Ban));
        store.log_action("c", "npub1a", "ban", false, NOW, "").unwrap();
        assert_eq!(pick(&store), None, "and stops at the top rather than repeating it");
    }

    /// The bug that silenced the whole ladder: with `[arm]` not uniform, a
    /// single lookup read one `dry` space for rungs recorded in another, so it
    /// proposed a rung that was always already answered.
    ///
    /// Validation now refuses this shape at boot (arming a class above an
    /// unarmed one makes the first real sentence the armed rung). This stays as
    /// the second line: the selection has to be right even if the config ever
    /// reaches it another way.
    #[test]
    fn a_non_uniform_arm_block_still_climbs() {
        let store = mem();
        let p = policy_with("warn = false\ndelete = false\nkick = true\nban = true");
        let all = Powers { hide: true, kick: true, ban: true };
        let twelve = [ladder::Strike { worth: 12, at_ms: NOW, from_vision: false }];
        let pick = |s: &Store| {
            select_rung(&p, all, s, "c", "npub1a", &twelve, false, NOW).unwrap().map(|(r, _)| r)
        };

        // warn is unarmed, so its rehearsal lands in the dry space.
        assert_eq!(pick(&store), Some(Response::Warn));
        store.log_action("c", "npub1a", "warn", true, NOW, "").unwrap();
        assert_eq!(pick(&store), Some(Response::DeleteAndWarn));
        store.log_action("c", "npub1a", "delete_and_warn", true, NOW, "").unwrap();
        // kick is armed, so it asks the LIVE space, which is empty.
        assert_eq!(pick(&store), Some(Response::Kick), "an armed rung is not deduped by a rehearsal");
    }

    /// A rung the community withheld must be climbed past, not stopped at.
    #[test]
    fn a_withheld_permission_does_not_pin_the_ladder() {
        let store = mem();
        let p = policy_with("warn = true\ndelete = true\nkick = true\nban = true");
        let no_hiding = Powers { hide: false, kick: true, ban: true };
        store.log_action("c", "npub1a", "warn", false, NOW, "").unwrap();
        assert_eq!(
            select_rung(&p, no_hiding, &store, "c", "npub1a", &[ladder::Strike { worth: 12, at_ms: NOW, from_vision: false }], false, NOW)
                .unwrap()
                .map(|(r, _)| r),
            Some(Response::Kick),
            "delete_and_warn cannot be delivered here, so the ladder goes on"
        );
    }

    /// Provenance follows the EVIDENCE. A total built from a model's opinion is
    /// inference wherever it is answered from — the sweep used to answer it
    /// under the text switches and really kick on a classifier's say-so.
    #[test]
    fn a_vision_strike_answers_to_the_vision_switch_from_any_lane() {
        let store = mem();
        let p = policy_with("warn = true\nkick = true\nvision = false");
        let all = Powers { hide: true, kick: true, ban: true };
        store.record("c", "npub1a", "vision:hash1:gore", 12, NOW, "gore", "").unwrap();
        // A REAL warning on file. If provenance came from the lane, the sweep
        // would read this live row, call the rung answered and climb; reading
        // the dry space (where an unarmed vision rehearsal lives) it does not.
        store.log_action("c", "npub1a", "warn", false, NOW, "").unwrap();

        // Enforced from the SWEEP, which knows nothing about the media lane.
        let seen = [ladder::Strike { worth: 12, at_ms: NOW, from_vision: true }];
        let (r, from_vision) =
            select_rung(&p, all, &store, "c", "npub1a", &seen, false, NOW).unwrap().expect("a rung");
        assert!(from_vision, "the evidence is a model's opinion wherever it is answered from");
        assert_eq!(r, Response::Warn, "the live warn answers nothing: this rung is unarmed and lives in the dry space");
        assert!(!adjudicate::armed_for(&p, r, from_vision), "so it rehearses rather than acting");
    }

    /// A rung the PROVABLE points already reach answers under the text
    /// switches; one only the full total reaches leans on a model and answers
    /// to `arm.vision`. A boolean taint got both halves wrong.
    #[test]
    fn only_the_rungs_that_lean_on_inference_answer_to_the_vision_switch() {
        let store = mem();
        let p = policy_with("warn = true\ndelete = true\nkick = true\nban = true\nvision = false");
        let all = Powers { hide: true, kick: true, ban: true };
        // Eight provable points (a kick) plus four from a model (a ban).
        let mixed = [
            ladder::Strike { worth: 8, at_ms: NOW, from_vision: false },
            ladder::Strike { worth: 4, at_ms: NOW, from_vision: true },
        ];
        let pick = |s: &Store| select_rung(&p, all, s, "c", "npub1a", &mixed, false, NOW).unwrap();

        // Warn, delete and kick are all within the provable eight, so they are
        // armed despite the member carrying media strikes.
        for expected in [Response::Warn, Response::DeleteAndWarn, Response::Kick] {
            let (r, leans) = pick(&store).expect("a rung");
            assert_eq!(r, expected);
            assert!(!leans, "{expected:?} is reached by provable points alone");
            assert!(adjudicate::armed_for(&p, r, leans), "so it is carried out");
            store.log_action("c", "npub1a", r.name(), false, NOW, "").unwrap();
        }
        // Ban is only reached with the model's four, so it answers to arm.vision.
        let (r, leans) = pick(&store).expect("a rung");
        assert_eq!(r, Response::Ban);
        assert!(leans, "only the full total reaches a ban here");
        assert!(!adjudicate::armed_for(&p, r, leans), "so it rehearses, with vision unarmed");
    }

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
        let got = debt_subjects(&handled, &r, owed, "npub1me");

        assert!(got.iter().any(|(n, _)| n == "npub1vision"), "the case this loop exists for");
        assert!(got.iter().any(|(n, s)| n == "npub1trusted" && s == "trusted"), "with their REAL standing");
        assert!(!got.iter().any(|(n, _)| n == "npub1handled"), "already sentenced this pass");
        assert!(!got.iter().any(|(n, _)| n == "npub1me"), "never itself");
        assert!(!got.iter().any(|(n, _)| n == "npub1departed"), "not on the roster, not ours to judge");
    }

    /// Every shield this loop emits must be one the gate recognises. "absent"
    /// falls through to "not shielded", so emitting it here was a ban path.
    #[test]
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
        let a = conviction_id("slurs", "msg1");
        assert_eq!(a, conviction_id("slurs", "msg1"));
        assert_ne!(a, conviction_id("slurs", "msg2"), "a second message is a second offense");
        assert_ne!(a, conviction_id("links", "msg1"), "a different rule is a different offense");
        // NOT keyed on the rulebook version: editing one pattern re-charged the
        // whole open window at full worth and stepped around every pardon.
        assert!(!a.contains("policy"), "the rulebook version is not part of the offense");
    }
}
