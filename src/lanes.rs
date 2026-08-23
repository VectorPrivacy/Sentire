//! The live lanes: what Sentinel does the moment a message or an
//! attachment lands, and the tripwire that turns a wave into an immediate
//! evaluation.

use std::sync::{Arc, Mutex};

use vector_sdk::{Community, VectorBot};

use crate::config::{Config, Gravity};
use crate::store::Store;
use crate::tripwire::Tripwire;
use crate::vision::Vision as _;
use crate::review::sweep;
use tokio::sync::Semaphore;
use crate::act::{announce, enforce, own_finding, own_verdict, Ctx};
use crate::{
    conviction_id, now_ms, powers_of, resolve_absent, roster_size, short, standing_of, untrip, Pass,
    Watches,
};
use crate::{ladder, vision};

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
pub(crate) async fn screen(
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
    // Standing BEFORE recording: the live screen sees one message, so a
    // long-tenured regular reads as untrusted here.
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
    let ctx = live_ctx(cfg, &community, watches, me).await;
    if ladder::decide(&ctx.policy.ladder, total).is_some() {
        // The screen knows the message; an engine citation could not, since at
        // send time it does not exist yet.
        let mut findings = findings.clone();
        for f in &mut findings {
            f.messages = vec![msg.message.id.clone()];
        }
        let v = own_verdict(&author, shield, vec![evidence.clone()], findings);
        enforce(bot, &community, &ctx, store, watches, &Mutex::new(0), &v, &strikes).await?;
    }
    Ok(())
}

/// Judge one message's attachments.
///
/// Everything here is Sentinel's own opinion. A model's verdict never reaches
/// `proven`, never enters the engine's combinator, and never appears in another
/// client's report — so it is reported as what it is, and the ladder it feeds is
/// Sentinel's alone.
pub(crate) async fn watch_media(
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
            // Ordinary traffic, not evasion — announcing it floods the channel.
            println!("[media] {} — a type I do not judge", short(&att.id));
            continue;
        }
        // `att.id` is the SENDER's declared hash and is never verified, so the
        // cache keys on what actually downloaded.
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
                    .record(community.id(), &author, &conviction, worth, now, &evidence)
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
                let ctx = live_ctx(cfg, &community, watches, me).await;
                if ladder::decide(&ctx.policy.ladder, total).is_some() {
                    let v = own_verdict(
                        &author,
                        shield.clone(),
                        vec![evidence.clone()],
                        vec![own_finding("vision", &evidence, msg.message.id.clone())],
                    );
                    enforce(bot, &community, &ctx, store, watches, &Mutex::new(0), &v, &strikes).await?;
                }
            }
        }
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
pub(crate) async fn trip(
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

/// Media that was never judged. Silence here is a way to slip something past:
/// twenty junk images exhaust the minute's budget and the twenty-first is
/// dropped with nothing said. One line per minute-bucket, so a flood is one
/// message rather than a hundred.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn unclassified(
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
    if store.claim(community.id(), &bucket, now, 3_600_000).unwrap_or(false) {
        let ctx = live_ctx(cfg, community, watches, me).await;
        announce(bot, community, &ctx, "Attachments arrived faster than I could check them — some were not judged.").await;
    }
}

/// The classifier, if the operator configured one.
pub(crate) fn media_lane(cfg: &Config) -> vector_sdk::Result<Arc<Option<vision::openai::OpenAiVision>>> {
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

/// One community's context for a live lane. Its rulebook and its powers, same
/// as the sweep resolves — a message arriving is not a reason to judge it by
/// somebody else's standards.
pub(crate) async fn live_ctx(cfg: &Config, community: &Community, watches: &Watches, me: &str) -> Ctx {
    Ctx {
        policy: cfg.for_community(community.id()),
        powers: powers_of(community).await,
        roster: roster_size(watches, community.id()),
        me: me.to_string(),
        mod_channel: cfg.bot.mod_channel.clone(),
    }
}

/// One classification at a time, and no more than the operator allows per
/// minute. Every message is its own task, so without this a wave of images is a
/// wave of concurrent multi-megabyte uploads to the model.
pub(crate) struct Budget {
    pub(crate) slot: Semaphore,
    pub(crate) per_min: u32,
    pub(crate) spent: Mutex<(u64, u32)>,
}

impl Budget {
    pub(crate) fn new(per_min: u32) -> Budget {
        Budget { slot: Semaphore::new(1), per_min, spent: Mutex::new((0, 0)) }
    }

    /// False means the minute's allowance is gone. Refusing is safe: the caller
    /// treats it as unclassified, which routes to a person rather than passing.
    pub(crate) fn claim(&self) -> bool {
        // Its OWN clock: a caller's timestamp is read before a slow download,
        // and two stale minutes reset each other's bucket.
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
