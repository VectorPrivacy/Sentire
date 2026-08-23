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

mod act;
mod adjudicate;
#[cfg(test)]
mod harness;
mod commands;
mod config;
mod ladder;
mod lanes;
mod policy;
mod review;
mod raid;
mod tripwire;
mod vision;
mod rules;
mod store;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use vector_sdk::{BotEvent, Community, VectorBot};

use config::Config;
use policy::Powers;
use store::Store;
use tripwire::Tripwire;

/// Per-community state the live lanes need and cannot compute themselves.
#[derive(Default)]
struct Watch {
    tripwire: Option<Tripwire>,
    /// A sweep is in flight. The timer and the tripwire both call `sweep`, and
    /// two overlapping passes each read the corpus, each decide, and each act.
    sweeping: bool,
    /// Held across one whole sentence. The SDK spawns a task per inbound
    /// message, so without this the ceiling reads are guesses another task has
    /// already invalidated.
    enforcing: Arc<tokio::sync::Mutex<()>>,
    /// npub -> shield, refreshed by every sweep. The live lanes never consult
    /// the engine, so without this they would judge with no idea who the
    /// community has vouched for.
    standing: HashMap<String, String>,
    /// True once a sweep has filled `standing`.
    known: bool,
    /// This community's share of the classifier. Per community, or twenty junk
    /// images in one room spend the minute for every other room Sentinel
    /// watches — one community's traffic deciding another's screening.
    budget: Option<Arc<crate::lanes::Budget>>,
}

type Watches = Arc<Mutex<HashMap<String, Watch>>>;

/// Read something out of one community's watch.
fn with_watch<T>(watches: &Watches, community: &str, f: impl FnOnce(&Watch) -> T) -> Option<T> {
    watches.lock().unwrap_or_else(|e| e.into_inner()).get(community).map(f)
}

/// A member's standing as the last sweep saw it.
///
/// `"unknown"` before any sweep — nobody's standing is established yet, and
/// `adjudicate` holds on that. `"absent"` when the roster was read and does not
/// list them, which a lane with the member in hand resolves via
/// [`resolve_absent`] and one without refuses outright.
fn standing_of(watches: &Watches, community: &str, npub: &str) -> String {
    with_watch(watches, community, |w| {
        if w.known {
            w.standing.get(npub).cloned().unwrap_or_else(|| "absent".into())
        } else {
            "unknown".into()
        }
    })
    .unwrap_or_else(|| "unknown".into())
}

/// A member the last sweep never saw — joined since, or the roster is stale.
/// Ask the community's own roles before treating them as ordinary.
///
/// Fails CLOSED. Every other unresolved standing in this codebase does, and
/// this one gates more than enforcement: an unshielded member's attachments are
/// decrypted and, with a remote endpoint, posted to somebody else's server. A
/// local read that errored is not evidence that somebody is ordinary.
fn resolve_absent(shield: String, msg: &vector_sdk::IncomingMessage) -> String {
    if shield != "absent" {
        return shield;
    }
    match msg.member() {
        Some(m) => match m.try_is_admin() {
            Ok(true) => "protected".into(),
            Ok(false) => "none".into(),
            Err(_) => "unknown".into(),
        },
        None => "unknown".into(),
    }
}

/// The roster as the last sweep counted it, so a live action is bound by the
/// same percentage ceiling the sweep obeys.
fn roster_size(watches: &Watches, community: &str) -> usize {
    with_watch(watches, community, |w| if w.known { w.standing.len() } else { 0 }).unwrap_or(0)
}

/// The roster as a map, for the debt loop — which has no member in hand and so
/// must refuse anyone it does not list.
fn roster_map(watches: &Watches, community: &str) -> HashMap<String, String> {
    with_watch(watches, community, |w| if w.known { w.standing.clone() } else { HashMap::new() }).unwrap_or_default()
}

/// If the sweep task ever unwinds, say so loudly rather than degrading into a
/// bot that enforces on a roster that will never update again.
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

/// Marks a deliberate stop, so the sweep guard does not read a clean shutdown
/// as a crash.
struct ShutdownFlag;

impl ShutdownFlag {
    fn arm(self) {}
}

impl Drop for ShutdownFlag {
    fn drop(&mut self) {
        SHUTTING_DOWN.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// This community's classifier budget, made on first use.
fn budget_of(watches: &Watches, community: &str, per_min: u32) -> Arc<crate::lanes::Budget> {
    watches
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(community.to_string())
        .or_default()
        .budget
        .get_or_insert_with(|| Arc::new(crate::lanes::Budget::new(per_min.max(1))))
        .clone()
}

/// One community's turn to sentence.
fn enforce_lock(wires: &Watches, community: &str) -> Arc<tokio::sync::Mutex<()>> {
    wires.lock().unwrap_or_else(|e| e.into_inner()).entry(community.to_string()).or_default().enforcing.clone()
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
    introduce(&bot, &cfg.bot.profile).await;

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
        wipe_on_arming_change(&cfg, c, &store);
        match rules::install(c, &cfg).await {
            Ok(what) => {
                installed_at_boot.insert(c.id().to_string());
                // Arming is per community, so it is reported per community.
                // One global line said "nobody is touched" in a process that
                // was about to ban people.
                println!(
                    "watching {} — {what} — {} — armed: {}",
                    short(c.id()),
                    powers.describe(),
                    cfg.for_community(c.id()).armed_line()
                );
            }
            Err(e) => eprintln!("watching {} — rulebook rejected: {e} — retrying next pass", short(c.id())),
        }
    }

    let wires: Watches = Arc::new(Mutex::new(HashMap::new()));
    commands::operator_surface(&bot, &cfg, &store, &wires);
    let eyes = lanes::media_lane(&cfg)?;


    // The sweep runs beside the listener rather than instead of it: slash
    // commands arrive through the inbound stream, so a bot that only loops on
    // verdicts can be watched but never asked anything.
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
                        wipe_on_arming_change(&cfg, &c, &store);
                        match rules::install(&c, &cfg).await {
                            Ok(what) => {
                                installed.insert(c.id().to_string());
                                println!("watching {} — {what} — {}", short(c.id()), powers.describe());
                            }
                            Err(e) => eprintln!("watching {} — rulebook rejected: {e} — retrying next pass", short(c.id())),
                        }
                    }
                    if let Err(e) = review::sweep(&bot, &c, &cfg, &store, &wires, &me).await {
                        eprintln!("{}: {e}", short(c.id()));
                    }
                }
                // One store, every community: keep the LONGEST memory any of
                // them asked for. A tombstone only works while it outlives the
                // evidence window, and a claim while it outlives its TTL.
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
        let (cfg, store, me) = (cfg.clone(), store.clone(), bot.npub().to_string());
    bot.on_event(move |bot, event| {
            let (cfg, store, eyes, wires, me) =
                (cfg.clone(), store.clone(), eyes.clone(), wires.clone(), me.clone());
            async move {
                match event {
                    BotEvent::Message(msg) => {
                        // COUNTED first, EVALUATED last. The three lanes run in
                        // order in one task and the media lane waits on a
                        // permit held across a download, so an arrival counted
                        // after it would be stamped at release time — one
                        // classification apart, and a wave of images could
                        // never look like a wave. The evaluation a trip asks
                        // for reads a whole corpus, so it goes at the end where
                        // it delays nothing.
                        let tripped = match (msg.community(), msg.author()) {
                            (Some(community), Some(author)) if !msg.is_mine() => {
                                lanes::observe_arrival(&cfg, &wires, &community, &author)
                            }
                            _ => false,
                        };
                        let sentenced = match lanes::screen(&bot, &msg, &cfg, &store, &wires, &me).await {
                            Ok(sentenced) => sentenced,
                            Err(e) => {
                                eprintln!("screen: {e}");
                                false
                            }
                        };
                        if let Err(e) = lanes::watch_media(
                            &bot,
                            &msg,
                            &cfg,
                            &store,
                            eyes.as_ref().as_ref(),
                            &wires,
                            &me,
                            sentenced,
                        )
                        .await
                        {
                            eprintln!("media: {e}");
                        }
                        if tripped {
                            if let Some(community) = msg.community() {
                                lanes::evaluate_now(&bot, &community, &cfg, &store, &wires, &me).await;
                            }
                        }
                    }
                    // A join flood is the other half of the raid shape, and it
                    // arrives before anyone has said anything at all.
                    BotEvent::MemberJoin { channel_id, npub } => {
                        if let Some(community) = bot.channel(channel_id).community() {
                            if lanes::observe_arrival(&cfg, &wires, &community, &npub) {
                                lanes::evaluate_now(&bot, &community, &cfg, &store, &wires, &me).await;
                            }
                        }
                    }
                    _ => {}
                }
            }
        })
        .await?;
    }
    // The listener returned. That is not a stop Sentinel asked for — the
    // notification stream ended under it — and exiting 0 in silence means a
    // supervisor set to restart-on-failure leaves the community unwatched.
    ShutdownFlag.arm();
    Err(vector_sdk::Error::Other(
        "the event listener stopped: Sentinel is no longer receiving messages".into(),
    ))
}

/// Arming is a fresh start.
///
/// A rehearsal records what it WOULD have done, so a member who accrued twelve
/// points of "would ban" during a dry run must not be banned the moment the
/// switch flips — they have never actually been warned. Wiping is the whole
/// reason there is one ledger rather than two.
/// Publish who Sentinel is, if that has changed.
///
/// A member who has just been warned looks up the npub that warned them, and
/// an empty profile tells them nothing — not what it is, not what it does, not
/// how to appeal. Only on a real difference: a kind-0 per restart is noise on
/// every relay that carries it.
async fn introduce(bot: &VectorBot, want: &crate::config::Profile) {
    let now = bot.fetch_profile(&bot.npub()).await;
    let same = now.as_ref().is_some_and(|p| {
        p.name == want.name && p.about == want.about && p.avatar == want.avatar && p.banner == want.banner
    });
    if same {
        return;
    }
    if bot.update_profile(&want.name, &want.avatar, &want.banner, &want.about).await {
        println!("published profile — {}", want.name);
    } else {
        eprintln!("could not publish profile; members looking up this npub will find nothing");
    }
}

/// What a wipe keys on: the LADDER's classes, in a stable order.
///
/// Raid containment keeps no strikes and no rung, and its claims are already
/// scoped by armed-ness — so including it meant switching containment on wiped
/// every member's strike history and replayed the ladder for the whole
/// community from the bottom.
fn ladder_classes(p: &crate::policy::CommunityPolicy) -> String {
    [(p.arm.warn, "warn"), (p.arm.delete, "delete"), (p.arm.kick, "kick"), (p.arm.ban, "ban")]
        .iter()
        .filter(|(on, _)| *on)
        .map(|(_, n)| *n)
        .collect::<Vec<_>>()
        .join(" ")
}

fn wipe_on_arming_change(cfg: &Config, community: &Community, store: &Arc<Store>) {
    let classes = ladder_classes(&cfg.for_community(community.id()));
    match store.note_armed(community.id(), &classes) {
        Ok(true) => println!("{} — arming changed, starting from a clean slate", short(community.id())),
        Ok(false) => {}
        Err(e) => eprintln!("{}: {e}", short(community.id())),
    }
}

/// What this community actually permits. Read, never assumed.
async fn powers_of(community: &Community) -> Powers {
    community.capabilities().map(|c| Powers::from_capabilities(&c)).unwrap_or_default()
}

/// One offense, one id, whichever clock reaches it first.
fn conviction_id(rule_id: &str, message_id: &str) -> String {
    // Deliberately WITHOUT the policy hash: the rule and the message identify
    // the offense, so editing a pattern must not re-charge the open window.
    // `review::charges` mints window ids on the same principle, because the
    // engine's own carry the hash.
    format!("msg:{rule_id}:{message_id}")
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

/// Never panics on a short string, which a remote peer can supply.
fn short(s: &str) -> &str {
    let mut end = 12.min(s.len());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every gate now lives in `adjudicate`, which is a pure function tested
    /// against itself rather than against a restatement of its rules. What is
    /// left here is the glue those gates depend on.

    #[test]
    fn a_short_string_never_panics_however_a_peer_supplies_it() {
        // A remote peer chooses attachment and message ids. A panic here
        // unwinds the event closure before the tripwire runs.
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
        // NOT keyed on the rulebook version.
        assert!(!a.contains("policy"), "the rulebook version is not part of the offense");
    }

    fn watches_with(pairs: &[(&str, &str)], known: bool) -> Watches {
        let w = Watch {
            standing: pairs.iter().map(|(n, s)| (n.to_string(), s.to_string())).collect(),
            known,
            ..Default::default()
        };
        Arc::new(Mutex::new([("c".to_string(), w)].into_iter().collect()))
    }

    /// Before any sweep has run, Sentinel knows nothing — and "nothing" must
    /// not read as "ordinary", which is the unshielded path.
    #[test]
    fn standing_is_unknown_until_a_sweep_has_filled_it() {
        let w = watches_with(&[("npub1a", "trusted")], false);
        assert_eq!(standing_of(&w, "c", "npub1a"), "unknown");
        assert_eq!(standing_of(&w, "c", "npub1nobody"), "unknown");
        // And a community nothing has ever watched.
        assert_eq!(standing_of(&w, "other", "npub1a"), "unknown");
    }

    #[test]
    fn a_filled_roster_answers_with_what_it_lists() {
        let w = watches_with(&[("npub1a", "trusted"), ("npub1b", "none")], true);
        assert_eq!(standing_of(&w, "c", "npub1a"), "trusted");
        assert_eq!(standing_of(&w, "c", "npub1b"), "none");
        assert_eq!(standing_of(&w, "c", "npub1c"), "absent", "read, and not listed");
    }

    /// The roster is what bounds the percentage ceiling, so an unfilled one
    /// must count as zero — which `adjudicate` reads as a failed read and
    /// spares, rather than as a community with no members and no ceiling.
    #[test]
    fn an_unknown_roster_counts_as_zero() {
        assert_eq!(roster_size(&watches_with(&[("a", "none")], false), "c"), 0);
        assert_eq!(roster_size(&watches_with(&[("a", "none")], true), "c"), 1);
        assert_eq!(roster_size(&watches_with(&[], true), "c"), 0);
        assert_eq!(roster_size(&watches_with(&[("a", "none")], true), "other"), 0);
    }

    /// Every community's state is its own.
    #[test]
    fn one_communitys_roster_never_answers_for_another() {
        let a = Watch { standing: [("npub1a".to_string(), "trusted".to_string())].into_iter().collect(), known: true, ..Default::default() };
        let b = Watch { standing: [("npub1a".to_string(), "none".to_string())].into_iter().collect(), known: true, ..Default::default() };
        let w: Watches = Arc::new(Mutex::new([("one".to_string(), a), ("two".to_string(), b)].into_iter().collect()));

        assert_eq!(standing_of(&w, "one", "npub1a"), "trusted");
        assert_eq!(standing_of(&w, "two", "npub1a"), "none", "the same member, judged where they are");
    }

    /// The conviction id is the line between an offense and an echo of one.
    #[test]
    fn a_conviction_id_names_exactly_one_offense() {
        let a = conviction_id("slurs", "msg1");
        assert_eq!(a, conviction_id("slurs", "msg1"), "and is stable");
        assert_ne!(a, conviction_id("slurs", "msg2"));
        assert_ne!(a, conviction_id("links", "msg1"));
        assert!(!a.contains("policy"), "the rulebook version is not part of the offense");
        // Ids the two clocks mint for the same message must match, or one
        // offense is charged twice.
        assert!(a.starts_with("msg:"), "the shape the live screen mints too");
    }

    /// Raid containment keeps no strikes and no rung, and its claims are
    /// already scoped by armed-ness — so switching it on must not wipe the
    /// text ladder's history for the whole community.
    #[test]
    fn arming_raid_does_not_wipe_the_ladders_record() {
        let store = Arc::new(crate::store::tests::mem());
        let base = "[arm]\nwarn = true\n";
        let cfg: Config = toml::from_str(base).unwrap();
        let p = cfg.for_community("c");
        let classes = ladder_classes(&p);

        store.note_armed("c", &classes).unwrap();
        store.record("c", "npub1a", "x", 4, 0, "").unwrap();

        let with_raid: Config = toml::from_str("[arm]\nwarn = true\nraid = true\n").unwrap();
        let after = ladder_classes(&with_raid.for_community("c"));
        assert_eq!(classes, after, "raid is not one of the ladder's classes");
        assert!(!store.note_armed("c", &after).unwrap(), "so nothing is wiped");
        assert_eq!(store.strikes("c", "npub1a").unwrap().len(), 1);
    }

    /// And arming a ladder class still does wipe.
    #[test]
    fn arming_a_ladder_class_still_wipes() {
        let store = Arc::new(crate::store::tests::mem());
        let before: Config = toml::from_str("[arm]\nwarn = true\n").unwrap();
        store.note_armed("c", &ladder_classes(&before.for_community("c"))).unwrap();
        store.record("c", "npub1a", "x", 4, 0, "").unwrap();

        let after: Config = toml::from_str("[arm]\nwarn = true\nkick = true\n").unwrap();
        assert!(store.note_armed("c", &ladder_classes(&after.for_community("c"))).unwrap());
        assert!(store.strikes("c", "npub1a").unwrap().is_empty());
    }
}
