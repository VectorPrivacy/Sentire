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

/// The cache key: which model was asked, and what it was asked about.
///
/// Adding a label or moving a threshold is a different question, and every
/// blob has to be asked it again.
pub(crate) fn asked_of(model: &str, cfg: &crate::config::VisionCfg) -> String {
    let mut labels: Vec<String> =
        cfg.labels.iter().map(|l| format!("{}@{}", l.name, l.threshold)).collect();
    labels.sort();
    format!("{model}?{}", labels.join(","))
}

/// What to do about one attachment, before any byte is fetched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gate {
    /// Download it and answer for its bytes.
    Fetch,
    /// Not media in any client, so nobody meets it by accident. Quiet.
    Skip,
    /// It claims to be media and is refused. A person is told, because a
    /// refusal to look must never read as a clean answer.
    Refuse(&'static str),
}

/// The pre-download decision, on the sender's own claims.
///
/// The extension is the SENDER's, so it may only decide whether something
/// could be media at all — never whether it gets judged. Clients render by
/// extension, so anything claiming to be an image or a video is fetched and
/// answered for by its bytes.
pub(crate) fn gate(extension: &str, declared_size: u64, cfg: &crate::config::VisionCfg) -> Gate {
    let declared = vector_sdk::vector_core::crypto::mime_from_extension(extension);
    if !declared.starts_with("image/") && !declared.starts_with("video/") {
        return Gate::Skip;
    }
    if declared_size > cfg.max_bytes {
        return Gate::Refuse("declared over the size limit");
    }
    Gate::Fetch
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
    // The cache remembers a verdict; `asked` remembers the QUESTION. Keyed on
    // the model alone, a blob classified before a label existed was exempt from
    // that label for good — the answer was cached, the question was not.
    let asked = asked_of(eyes.model(), &cfg.vision);
    let budget = crate::budget_of(watches, community.id(), cfg.vision.max_per_min);
    // Every flagged attachment in this message, so one post is one sentence.
    let mut flagged: Vec<String> = Vec::new();

    for att in &msg.message.attachments {
        match gate(&att.extension, att.size, &cfg.vision) {
            Gate::Skip => {
                println!("[media] {} — a type I do not judge", short(&att.id));
                continue;
            }
            Gate::Refuse(why) => {
                unclassified(bot, &community, cfg, store, watches, me, now, &att.id, why).await;
                continue;
            }
            Gate::Fetch => {}
        }
        // Held from BEFORE the fetch until the answer, so this community has
        // at most one blob resident at a time. The SDK's own cap is 256 MiB and
        // decryption copies, so N handlers fetching at once is N × that — and
        // the SDK spawns a handler per message, with 32 attachments allowed in
        // each. Waiting rather than declining: an image that has to queue still
        // gets judged, and a decline is a mod-channel line saying it was not.
        let _slot = budget.slot.acquire().await;
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
        // MIME from the bytes, never from a name the uploader chose. Whatever
        // the operator did not list goes to a person: the name claimed media,
        // so dropping it in silence is the same hole as a timeout reading clean.
        let actual = vector_sdk::vector_core::crypto::mime_from_magic_bytes(&bytes);
        if !cfg.vision.mimes.iter().any(|m| m == actual) {
            unclassified(bot, &community, cfg, store, watches, me, now, &att.id, &format!("not a type I judge ({actual})")).await;
            continue;
        }
        let content_hash = vector_sdk::vector_core::crypto::sha256_hex(&bytes);
        let verdict = match store.cached_verdict(&content_hash, &asked) {
            Some(cached) => match serde_json::from_str(&cached) {
                Ok(v) => v,
                // An unreadable row is not an all-clear: a shape change would
                // otherwise silently pass every blob ever classified.
                Err(e) => vision::Verdict::Unknown(format!("cache unreadable: {e}")),
            },
            None => {
                if !budget.claim() {
                    unclassified(bot, &community, cfg, store, watches, me, now, &att.id, "budget spent this minute").await;
                    continue;
                }
                let v = eyes.classify(&bytes, actual).await;
                // Never cache Unknown: one timeout would retire that blob from
                // classification forever.
                if !matches!(v, vision::Verdict::Unknown(_)) {
                    if let Ok(json) = serde_json::to_string(&v) {
                        let _ = store.cache_verdict(&content_hash, &asked, &json, now);
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
                if fresh {
                    flagged.push(evidence);
                }
            }
        }
    }

    // ONE sentence for the message, after every attachment has been weighed.
    // Enforcing per attachment walked the whole ladder inside a single post:
    // four flagged images were a warn, a delete, a kick and a ban.
    if flagged.is_empty() {
        return Ok(());
    }
    let strikes = store.strikes(community.id(), &author).map_err(vector_sdk::Error::Other)?;
    let total = ladder::total(&strikes, now, policy.ladder.decay_half_life_hours);
    let ctx = live_ctx(cfg, &community, watches, me).await;
    if ladder::decide(&ctx.policy.ladder, total).is_some() {
        let findings = flagged
            .iter()
            .map(|e| own_finding("vision", e, msg.message.id.clone()))
            .collect();
        let v = own_verdict(&author, shield, flagged, findings);
        enforce(bot, &community, &ctx, store, watches, &Mutex::new(0), &v, &strikes).await?;
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

/// One blob at a time per community, and no more than the operator allows per
/// minute. Every message is its own task, so without this a wave of images is a
/// wave of concurrent multi-megabyte fetches and uploads.
///
/// Per COMMUNITY. One shared budget meant twenty junk images in one room spent
/// the minute for every other room Sentinel watches.
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

#[cfg(test)]
mod tests {
    use super::*;
    use vector_sdk::vector_core::crypto::mime_from_magic_bytes;

    fn vision() -> crate::config::VisionCfg {
        crate::config::VisionCfg { max_bytes: 8 * 1024 * 1024, ..Default::default() }
    }

    /// The hole this gate exists for. A client renders by extension, so an
    /// image named for a type the operator did not list still appears inline
    /// to every member — and used to be dropped with nothing but a stdout line
    /// keyed on a hash the sender chose.
    #[test]
    fn anything_a_client_renders_inline_is_fetched_whatever_the_operator_listed() {
        let cfg = vision();
        for ext in ["bmp", "svg", "tiff", "tif", "ico", "png", "jpg", "jpeg", "gif", "webp"] {
            assert_eq!(gate(ext, 1024, &cfg), Gate::Fetch, ".{ext} renders inline and must be judged");
        }
    }

    #[test]
    fn video_is_fetched_too() {
        let cfg = vision();
        for ext in ["mp4", "webm", "mov", "mkv"] {
            assert_eq!(gate(ext, 1024, &cfg), Gate::Fetch, ".{ext} is media");
        }
    }

    /// A voice note or a document renders as a file nobody meets by accident,
    /// so skipping it is quiet rather than a mod-channel line every minute.
    #[test]
    fn things_no_client_renders_as_an_image_are_skipped_quietly() {
        let cfg = vision();
        for ext in ["ogg", "mp3", "pdf", "zip", "txt", "wav", "xyz", ""] {
            assert_eq!(gate(ext, 1024, &cfg), Gate::Skip, ".{ext} is not media a reader stumbles into");
        }
    }

    /// A refusal to LOOK must reach a person. Declaring an absurd size is
    /// otherwise a way to be skipped in silence.
    #[test]
    fn an_oversize_claim_is_refused_out_loud_not_dropped() {
        let cfg = vision();
        assert_eq!(gate("png", cfg.max_bytes + 1, &cfg), Gate::Refuse("declared over the size limit"));
        assert_eq!(gate("png", cfg.max_bytes, &cfg), Gate::Fetch, "the bound itself is allowed");
        assert_eq!(gate("mp4", u64::MAX, &cfg), Gate::Refuse("declared over the size limit"));
    }

    /// An oversize claim on something that is not media at all is still quiet:
    /// the size only matters for what would have been fetched.
    #[test]
    fn size_is_only_asked_about_media() {
        assert_eq!(gate("pdf", u64::MAX, &vision()), Gate::Skip);
    }

    /// The declared type opens the door; the BYTES decide what it is. These two
    /// must agree about the same set, or a type passes the gate and then has no
    /// answer — which is what made every video a download and a discard.
    #[test]
    fn every_default_judged_type_is_readable_from_its_bytes() {
        let cfg = vision();
        // A real EBML header carries its DocType a little way in, so the
        // sample is built rather than written out and miscounted.
        let mut webm = vec![0x1A, 0x45, 0xDF, 0xA3];
        webm.extend_from_slice(&[0u8; 20]);
        webm.extend_from_slice(b"webm");
        webm.resize(80, 0);

        let samples: Vec<(&str, Vec<u8>)> = vec![
            ("image/png", vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]),
            ("image/jpeg", vec![0xFF, 0xD8, 0xFF, 0xE0, 0, 0, 0, 0]),
            ("image/gif", b"GIF89a\0\0".to_vec()),
            ("image/webp", b"RIFF\0\0\0\0WEBP\0\0\0\0".to_vec()),
            ("video/mp4", b"\0\0\0\x20ftypisom".to_vec()),
            ("video/webm", webm),
        ];
        for want in &cfg.mimes {
            let found = samples.iter().find(|(m, _)| m == want);
            let (_, bytes) = found.unwrap_or_else(|| panic!("no sample for a default mime: {want}"));
            assert_eq!(
                mime_from_magic_bytes(bytes),
                want.as_str(),
                "{want} is in the default list but cannot be recognised from its bytes"
            );
        }
    }

    fn label(name: &str, threshold: f32) -> crate::config::VisionLabel {
        crate::config::VisionLabel { name: name.into(), threshold, gravity: crate::config::Gravity::Grave }
    }

    /// The answer was cached and the question was not, so a blob classified
    /// before a label existed was exempt from that label for good.
    #[test]
    fn changing_what_is_asked_changes_the_cache_key() {
        let mut cfg = vision();
        cfg.labels = vec![label("gore", 0.9)];
        let one = asked_of("llava", &cfg);

        cfg.labels.push(label("sexual_content", 0.9));
        let two = asked_of("llava", &cfg);
        assert_ne!(one, two, "a new label is a new question");

        cfg.labels = vec![label("gore", 0.5)];
        assert_ne!(asked_of("llava", &cfg), one, "so is a moved threshold");

        assert_ne!(asked_of("other-model", &cfg), asked_of("llava", &cfg), "and so is a different model");
    }

    /// Order in the file is not part of the question.
    #[test]
    fn the_same_labels_in_another_order_are_the_same_question() {
        let mut a = vision();
        a.labels = vec![label("gore", 0.9), label("sexual_content", 0.8)];
        let mut b = vision();
        b.labels = vec![label("sexual_content", 0.8), label("gore", 0.9)];
        assert_eq!(asked_of("llava", &a), asked_of("llava", &b));
    }

    /// The minute is per community: one room's flood must not decide another
    /// room's screening.
    #[test]
    fn each_community_spends_its_own_minute() {
        let a = Budget::new(2);
        let b = Budget::new(2);
        assert!(a.claim() && a.claim(), "its own allowance");
        assert!(!a.claim(), "and then it is spent");
        assert!(b.claim(), "which says nothing about anywhere else");
    }
}
