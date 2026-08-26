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
use crate::act::{announce, enforce, own_finding, own_verdict, Ctx, Outcome};
use crate::{
    conviction_id, now_ms, resolve_absent, roster_size, short, standing_of, untrip, Pass,
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
) -> vector_sdk::Result<bool> {
    if !msg.is_group || msg.is_mine() {
        return Ok(false);
    }
    let (Some(community), Some(author)) = (msg.community(), msg.author()) else { return Ok(false) };
    if !cfg.watches(community.id()) {
        return Ok(false);
    }
    let findings = community.screen(msg).await?;
    if findings.is_empty() {
        return Ok(false);
    }
    let now = now_ms();
    let policy = cfg.for_community(community.id());
    // Standing BEFORE recording: the live screen sees one message, so a
    // long-tenured regular reads as untrusted here.
    let shield = resolve_absent(standing_of(watches, community.id(), &author), msg);
    // Per FINDING, not per member. A trusted regular is spared the behavioural
    // rules — rate, repetition, mass tagging — because that is what their record
    // earned them; they are not spared the word and link lists, which say what
    // this community does not host regardless of who posts it.
    let spared_heuristics = crate::adjudicate::spared_by_standing(&policy, &shield).is_some();
    let spared_content = crate::adjudicate::spared_from_content(&shield).is_some();
    if spared_heuristics && spared_content {
        return Ok(false);
    }
    let findings: Vec<_> = findings
        .into_iter()
        .filter(|f| if policy.is_content_rule(&f.rule_id, &cfg.vision.labels) { !spared_content } else { !spared_heuristics })
        .collect();
    if findings.is_empty() {
        return Ok(false);
    }
    let mut fresh = false;
    let mut worst: Option<(Gravity, String)> = None;
    for f in &findings {
        // Basis only, deliberately — NOT the sweep's `chargeable`. A screened
        // finding carries no citation count because the caller supplied the
        // message: it IS the citation. The sweep needs that second condition
        // because it reads a whole corpus, where a finding can describe a
        // person rather than an act; here there is only ever one message.
        if !f.is_proven() {
            continue; // inference never earns a strike, on any clock
        }
        let gravity = policy.gravity_of(&f.rule_id, &f.severity);
        let worth = policy.ladder.strikes.worth(gravity);
        let evidence = crate::review::evidence_line(f);
        // The same id the sweep mints for this message, so whichever clock
        // reaches the offense first wins and the other is an ignored insert.
        let conviction = conviction_id(&f.rule_id, &msg.message.id);
        fresh |= store
            .record(community.id(), &author, &conviction, worth, now, &evidence)
            .map_err(vector_sdk::Error::Other)?;
        // The GRAVEST finding speaks for the batch, not whichever arrived first.
        if worst.as_ref().is_none_or(|(g, _)| gravity > *g) {
            worst = Some((gravity, evidence));
        }
    }
    let Some((_, evidence)) = worst else { return Ok(false) };
    println!("[screen] {} — {evidence}", short(&author));
    if !fresh {
        return Ok(false);
    }
    let strikes = store.strikes(community.id(), &author).map_err(vector_sdk::Error::Other)?;
    let total = ladder::total(&strikes, now, policy.ladder.decay_half_life_hours);
    let ctx = live_ctx(cfg, &community, store, watches, me).await;
    if ladder::decide(&ctx.policy.ladder, total).is_some() {
        // The screen knows the message; an engine citation could not, since at
        // send time it does not exist yet.
        let mut findings = findings.clone();
        for f in &mut findings {
            f.messages = vec![msg.message.id.clone()];
        }
        let v = own_verdict(&author, shield, vec![evidence.clone()], findings);
        let outcome = enforce(bot, &community, &ctx, store, watches, &Mutex::new(0), &v, &strikes).await?;
        return Ok(outcome == Outcome::Acted);
    }
    Ok(false)
}

/// The cache key: which model was asked, and what it was asked about.
///
/// Adding a label or moving a threshold is a different question, and every
/// blob has to be asked it again.
/// Types cut into a contact sheet rather than sent to the model whole.
///
/// Video always: no vision endpoint reads an mp4. Animated image formats too,
/// because content in frame fifty of a GIF is invisible to a model shown only
/// the first — the cheapest evasion there is. This needs no animation
/// detection: a static source has one frame and collapses to a 1x1 sheet.
pub(crate) fn sheeted(mime: &str, cfg: &crate::config::VisionCfg) -> bool {
    cfg.video.enabled && (mime.starts_with("video/") || matches!(mime, "image/gif" | "image/webp"))
}

/// `mime` is part of the question because a sheeted type is never asked about
/// directly: it is cut into a grid first, and a re-cut grid is a different set
/// of frames. A verdict cached under the old geometry answers about pixels that
/// were never sent.
pub(crate) fn asked_of(model: &str, cfg: &crate::config::VisionCfg, mime: &str) -> String {
    let mut labels: Vec<String> =
        cfg.labels.iter().map(|l| format!("{}@{}", l.name, l.threshold)).collect();
    labels.sort();
    // Keyed on the CONFIGURED grid, not the one a given clip ended up with:
    // that follows from the clip's own frame count, which is fixed for fixed
    // bytes. The configured grid is the part an operator changes.
    let cut = if sheeted(mime, cfg) {
        format!("+{}x{}@{}", cfg.video.cols, cfg.video.rows, cfg.video.tile_width)
    } else {
        String::new()
    };
    format!("{model}?{}{cut}", labels.join(","))
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
/// Fetch a LINKED image, with the guards a bot following a stranger's URL needs.
///
/// SSRF first and always: `validate_url_not_private` refuses loopback, private,
/// link-local and CGNAT space, so a member cannot use the bot as a probe into
/// whatever network it happens to run on. The cap is enforced on the BYTES as
/// they arrive, not on a Content-Length the server chose — a lying header is
/// free, and streaming past the limit is the whole attack.
///
/// Two things this cannot fix, and they are why it is a config flag: the host
/// learns the bot's IP, and it may serve clean bytes to the bot while serving
/// something else to everyone else.
pub(crate) async fn fetch_linked(url: &str, max_bytes: u64, timeout_secs: u64) -> Result<Vec<u8>, String> {
    vector_sdk::vector_core::net::validate_url_not_private(url).map_err(|e| e.to_string())?;
    let client = vector_sdk::vector_core::net::build_http_client(std::time::Duration::from_secs(timeout_secs))
        .map_err(|e| e.to_string())?;
    let resp = client.get(url).send().await.map_err(|e| format!("link unreachable: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("link answered {}", resp.status()));
    }
    let mut resp = resp;
    let mut out: Vec<u8> = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| format!("link download failed: {e}"))? {
        if out.len() as u64 + chunk.len() as u64 > max_bytes {
            return Err("link is over the size limit".to_string());
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Something in a message that might be media: an attachment, or an image a
/// member merely LINKED.
///
/// A link renders inline in the client exactly like an upload, so judging only
/// uploads left the whole surface open — post the URL instead of the file and
/// nothing looked at it.
pub(crate) enum Src<'a> {
    Att(&'a vector_sdk::vector_core::types::Attachment),
    Link(String),
}

pub(crate) struct Cand<'a> {
    /// For logging and for `unclassified`. The real cache key is always the
    /// hash of what actually arrived, never this.
    pub(crate) id: String,
    pub(crate) extension: String,
    /// The sender's word, and only used to decline early. Zero for a link,
    /// where nothing is claimed until the bytes are in hand.
    pub(crate) size: u64,
    pub(crate) src: Src<'a>,
}

/// Image and video URLs a message links, in order, deduped.
///
/// Extension-gated on purpose: following every URL a member posts to see what
/// comes back is a crawler, and this is a moderation bot. Anything whose path
/// does not name a type the operator judges is left alone.
pub(crate) fn linked_media(text: &str, cfg: &crate::config::VisionCfg) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in text.split_whitespace() {
        let candidate = raw.trim_matches(|c: char| "<>()[]{}\"',;!".contains(c));
        if !candidate.starts_with("http://") && !candidate.starts_with("https://") {
            continue;
        }
        // Path only: a query or fragment must not turn `?x=.png` into a type
        // claim, and the authority must not either.
        let after_scheme = candidate.split_once("//").map(|(_, r)| r).unwrap_or(candidate);
        let path = after_scheme.split(['?', '#']).next().unwrap_or("");
        let ext = path
            .rsplit('/')
            .next()
            .filter(|f| f.contains('.'))
            .and_then(|f| f.rsplit_once('.').map(|(_, e)| e.to_lowercase()))
            .unwrap_or_default();
        if ext.is_empty() || matches!(gate(&ext, 0, cfg), Gate::Skip) {
            continue;
        }
        let clean = candidate.to_string();
        if !out.contains(&clean) {
            out.push(clean);
        }
    }
    out
}

pub(crate) fn gate(extension: &str, declared_size: u64, cfg: &crate::config::VisionCfg) -> Gate {
    let declared = vector_sdk::vector_core::crypto::mime_from_extension(extension);
    if !declared.starts_with("image/") && !declared.starts_with("video/") {
        return Gate::Skip;
    }
    if declared.starts_with("video/") && !cfg.video.enabled {
        return Gate::Refuse("video judging is switched off");
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
    // The text screen already answered for this post: one post is one
    // sentence, so the strike is still recorded and the rung is not spent
    // twice seconds apart.
    already_sentenced: bool,
) -> vector_sdk::Result<()> {
    let (Some(eyes), true) = (eyes, msg.is_group && msg.is_file && !msg.is_mine()) else { return Ok(()) };
    let (Some(community), Some(author)) = (msg.community(), msg.author()) else { return Ok(()) };
    if !cfg.watches(community.id()) {
        return Ok(());
    }
    // Before ANY byte is fetched, and before the shield is even resolved: a
    // community the operator did not put on the vision list gets no media lane
    // at all. This is the gate that keeps a bot invited into a hundred rooms
    // from decrypting a hundred rooms' attachments and shipping them to a model.
    if !cfg.vision_enabled_for(community.id()) {
        return Ok(());
    }
    // Nothing here could be acted on for a shielded member, and classifying
    // anyway decrypted their private images and — with a remote endpoint —
    // shipped them off the machine to produce a verdict that is then thrown away.
    let shield = resolve_absent(standing_of(watches, community.id(), &author), msg);
    let policy = cfg.for_community(community.id());
    // What somebody posted is a content question, so only a role at or above
    // Sentinel's spares them from it. A trusted regular's media is judged.
    if crate::adjudicate::spared_from_content(&shield).is_some() {
        return Ok(());
    }
    let now = now_ms();
    // The cache remembers a verdict; `asked` remembers the QUESTION. Keyed on
    // the model alone, a blob classified before a label existed was exempt from
    // that label for good — the answer was cached, the question was not.
    let budget = crate::budget_of(watches, community.id(), cfg.vision.max_per_min, cfg.vision.concurrent);
    // Every flagged attachment in this message, so one post is one sentence.
    let mut flagged: Vec<(String, String)> = Vec::new();

    let mut cands: Vec<Cand> = msg
        .message
        .attachments
        .iter()
        .map(|a| Cand { id: a.id.clone(), extension: a.extension.clone(), size: a.size, src: Src::Att(a) })
        .collect();
    if cfg.vision.judge_links {
        for url in linked_media(&msg.message.content, &cfg.vision) {
            let extension =
                url.rsplit('/').next().and_then(|f| f.rsplit_once('.').map(|(_, e)| e.to_lowercase())).unwrap_or_default();
            cands.push(Cand { id: url.clone(), extension, size: 0, src: Src::Link(url) });
        }
    }

    for cand in &cands {
        let att = cand;
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
        // FETCH first, and in parallel. Waiting for the inference slot before
        // downloading meant an image posted a second after another sat untouched
        // for the whole of that model call — reported, fairly, as "it didn't
        // process". Get the bytes now; queue for the model after.
        let mut _fetching = Some(budget.fetch.acquire().await);
        // After the wait, not before it. The permit is held across a download
        // a sender can stretch, so a timestamp read at the top of the handler
        // would stamp strikes and cache rows minutes early.
        let now = now_ms();
        // `att.id` is the SENDER's declared hash and is never verified, so the
        // cache keys on what actually downloaded.
        let fetched = match &cand.src {
            Src::Att(a) => bot.download_attachment_from(a, msg.message.npub.as_deref()).await.map_err(|e| e.to_string()),
            Src::Link(url) => fetch_linked(url, cfg.vision.max_bytes, cfg.vision.timeout_secs).await,
        };
        let bytes = match fetched {
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
        // Before any sheet is cut: a hit must skip ffmpeg, not just the model.
        let asked = asked_of(eyes.model(), &cfg.vision, actual);
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
                // A clip is cut into a contact sheet before anything is asked
                // of the model: no vision endpoint reads an mp4, and sending one
                // came back Unknown forever rather than being judged.
                let sheet = if sheeted(actual, &cfg.vision) {
                    Some(vision::storyboard::build(&bytes, &content_hash, &cfg.vision.video).await)
                } else {
                    None
                };
                let (payload, shown) = match sheet {
                    Some(Ok((jpeg, board))) => {
                        println!(
                            "[media] {} — {}x{} sheet over {:.0}s",
                            short(&att.id), board.cols, board.rows, board.covers_secs
                        );
                        (jpeg, vision::Shown::Storyboard { mime: "image/jpeg", board })
                    }
                    // A clip that cannot be cut cannot be judged at all, so it
                    // reaches a person. An IMAGE still has a first frame worth
                    // showing, which beats refusing every GIF on a box with no
                    // ffmpeg — it is a weaker look, not no look.
                    Some(Err(why)) if actual.starts_with("video/") => {
                        unclassified(bot, &community, cfg, store, watches, me, now, &att.id, &why).await;
                        continue;
                    }
                    Some(Err(why)) => {
                        println!("[media] {} — no sheet ({why}); judging it as a still", short(&att.id));
                        (bytes.clone(), vision::Shown::Still { mime: actual })
                    }
                    None => (bytes.clone(), vision::Shown::Still { mime: actual }),
                };
                // The bytes are in hand and the sheet is cut; only the model is
                // scarce from here. Drop the fetch permit so the next post can
                // start downloading while this one waits its turn.
                _fetching = None;
                if budget.slot.available_permits() == 0 {
                    println!("[media] {} — downloaded, queued for the model", short(&att.id));
                }
                let _inferring = budget.slot.acquire().await;
                println!("[media] {} — asking {} ({} KiB)", short(&att.id), eyes.model(), payload.len() / 1024);
                let v = eyes.classify(&payload, shown).await;
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
            vision::Verdict::Clean { description } => {
                // ALWAYS a line. Printing only when the model volunteered a
                // description made a clean answer and a classification still in
                // flight look identical from the log, which is the one thing an
                // operator watching a live lane needs to tell apart.
                match description {
                    Some(d) => println!("[media] {} — clean: {d}", short(&att.id)),
                    None => println!("[media] {} — clean", short(&att.id)),
                }
            }
            vision::Verdict::Unknown(why) => {
                // Never an all-clear. An unreachable model is a reason to ask a
                // person, not a reason to let everything through — and it goes
                // through the same rate limit as every other unjudged blob, or
                // a model answering in prose is N publishes into a channel.
                unclassified(bot, &community, cfg, store, watches, me, now, &att.id, &why).await;
            }
            vision::Verdict::Flagged { labels, description } => {
                let hits = vision::over_threshold(&labels, &cfg.vision.labels);
                if hits.is_empty() {
                    continue;
                }
                let (label, gravity) = hits[0].clone();
                let worth = policy.ladder.strikes.worth(gravity);
                // What the RECORD holds is what the member is later quoted, so
                // it carries the description and nothing else. A label name, a
                // confidence and a model are how the operator tuned their
                // rulebook; quoting them at somebody tells them how to dress a
                // picture up to score 0.89 next time.
                //
                // The description earns its place twice over: a moderator
                // reviewing this in a year reads a line of text instead of
                // reopening the worst thing anybody posted.
                let evidence = description
                    .as_deref()
                    .map(|d| d.to_string())
                    .unwrap_or_else(|| "An image or video that broke the rules".to_string());
                // The operator's console keeps the parts the member never sees.
                let internals =
                    format!("{} ({:.0}% per {})", label.name, label.score * 100.0, eyes.model());
                // One strike per (blob, label): re-posting the same image is
                // the same offense, escalating happens by posting more.
                let conviction = format!("vision:{content_hash}:{}", label.name);
                let fresh = store
                    .record(community.id(), &author, &conviction, worth, now, &evidence)
                    .map_err(vector_sdk::Error::Other)?;
                println!("[media] FLAGGED {} from {} — {internals} — {evidence}", short(&att.id), short(&author));
                if fresh {
                    // The LABEL, carried with its evidence. Filed under one
                    // blanket id, which rule matched was lost by the time
                    // anything had to name it, and members were told they broke
                    // the "Vision" rule.
                    flagged.push((label.name.clone(), evidence));
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
    if already_sentenced {
        // Recorded, not answered: the strike stands and the next offense
        // climbs from it.
        println!("[media] {} — already answered for this post", short(&author));
        return Ok(());
    }
    let strikes = store.strikes(community.id(), &author).map_err(vector_sdk::Error::Other)?;
    let total = ladder::total(&strikes, now, policy.ladder.decay_half_life_hours);
    let ctx = live_ctx(cfg, &community, store, watches, me).await;
    if ladder::decide(&ctx.policy.ladder, total).is_some() {
        let findings = flagged
            .iter()
            .map(|(rule, e)| own_finding(rule, e, msg.message.id.clone()))
            .collect();
        let reasons = flagged.into_iter().map(|(_, e)| e).collect();
        let v = own_verdict(&author, shield, reasons, findings);
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
pub(crate) fn observe_arrival(cfg: &Config, wires: &Watches, community: &Community, who: &str) -> bool {
    // The only path that was not scoped. Anyone can invite Sentinel (it builds
    // `.public()`), and a join flood there reached the whole ladder against
    // policies Sentinel never installed.
    if !cfg.watches(community.id()) {
        return false;
    }
    let cid = community.id().to_string();
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
}

/// Evaluate a community NOW, because its tripwire went off — and again shortly
/// after if that first look sentenced nobody.
///
/// Split from the counting deliberately. `observe_arrival` is a lock and a
/// push, so it runs at arrival and the timestamps are the truth; this reads a
/// whole corpus and sentences, so it runs after the per-message lanes and
/// blocks nothing that has to be quick.
pub(crate) async fn evaluate_now(
    bot: &VectorBot,
    community: &Community,
    cfg: &Config,
    store: &Arc<Store>,
    wires: &Watches,
    me: &str,
) {
    // Pull the wave's MESSAGES before judging. The tripwire fires on the join
    // burst, which arrives on the guestbook plane ahead of the chat plane — so
    // without this the immediate eval reads a corpus of joins with no messages,
    // the cohort (which clusters on message TEXT) finds nothing, and containment
    // waits for a later sweep to ingest the spam. A raid measured in minutes
    // cannot wait a sweep. Sync every channel first, bounded so a huge backlog
    // can't stall the reaction.
    for ch in community.channels().await {
        if let Err(e) = bot.channel(ch.id()).sync(200).await {
            eprintln!("[{}] tripwire sync of {}: {e}", short(community.id()), &ch.id()[..8.min(ch.id().len())]);
        }
    }
    // A burst does not arrive together. Six accounts posting inside a second
    // reach us STAGGERED, so the first look can hold half the wave — and the
    // cohort clusters on message TEXT, needing several authors of the same line
    // before it will say anything. One look then found nothing and the next was
    // a full sweep away: measured at two minutes from first spam to containment,
    // nearly all of it spent waiting rather than deciding.
    //
    // So look again while the rest lands. These re-read a corpus the live
    // subscription has ALREADY delivered locally, so the retries cost relay
    // traffic only for the channel sync above, and they stop the moment
    // anything is convicted.
    const RETRY_DELAYS: [u64; 2] = [15, 35];
    for (attempt, delay) in std::iter::once(0).chain(RETRY_DELAYS).enumerate() {
        if delay > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
            // The wave kept landing while we waited; re-read before judging.
            for ch in community.channels().await {
                let _ = bot.channel(ch.id()).sync(200).await;
            }
        }
        // The 90-second memoisation is right for a background pass and far too slow
        // for a wave in progress.
        community.invalidate();
        let verdict = sweep(bot, community, cfg, store, wires, me).await;
        let done = matches!(verdict, Ok(Pass::Ran(n)) if n > 0);
        report(bot, community, cfg, wires, &verdict, attempt);
        // Convicted, or the community is not ours to judge — either way, stop.
        if done || matches!(verdict, Ok(Pass::Held) | Err(_)) {
            return;
        }
    }
}

/// One tripwire verdict, said once.
fn report(
    _bot: &VectorBot,
    community: &Community,
    cfg: &Config,
    wires: &Watches,
    verdict: &vector_sdk::Result<Pass>,
    attempt: usize,
) {
    let cid = community.id().to_string();
    match verdict {
        // Only a genuine race gives the trip back. Checking `sweeping`
        // beforehand was itself a race: both handlers could see false and the
        // loser still lost its trip. Said nothing either: during a long pass a
        // wave would otherwise print this line once per message.
        Ok(Pass::Declined) => untrip(wires, community.id()),
        Ok(_) => {
            let r = cfg.for_community(&cid).raid;
            let again = if attempt > 0 { format!(" (look {})", attempt + 1) } else { String::new() };
            println!(
                "[{}] TRIPWIRE{} — {} distinct accounts inside {}s",
                short(community.id()),
                again,
                r.tripwire_accounts,
                r.tripwire_secs
            );
        }
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
    // Bucketed per REASON as well as per minute: a download failure, an
    // unlisted type and a spent budget are different problems, and one line
    // covering all three tells an operator nothing about which they have.
    let bucket = format!("unjudged:{}:{}", why, now / 60_000);
    if store.claim(community.id(), &bucket, now, 3_600_000).unwrap_or(false) {
        let ctx = live_ctx(cfg, community, store, watches, me).await;
        announce(bot, community, &ctx, &format!("Some attachments were not judged — {why}.")).await;
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
    // At boot, not on the first clip. An operator who armed video judging and is
    // missing ffmpeg otherwise learns about it from a mod-channel line saying an
    // attachment went unjudged, hours later.
    if cfg.vision.video.enabled {
        match vision::storyboard::probe_tooling(&cfg.vision.video) {
            Ok(v) => println!(
                "  video: {}x{} sheets via {v}",
                cfg.vision.video.cols, cfg.vision.video.rows
            ),
            Err(e) => println!("  ⚠ video: {e} — clips will go to a person unjudged"),
        }
    } else {
        println!("  video: off — clips go to a person unjudged");
    }
    Ok(Arc::new(Some(eyes)))
}

/// One community's context for a live lane. Its rulebook and its powers, same
/// as the sweep resolves — a message arriving is not a reason to judge it by
/// somebody else's standards.
pub(crate) async fn live_ctx(cfg: &Config, community: &Community, store: &crate::store::Store, watches: &Watches, me: &str) -> Ctx {
    // The roster as the LAST SWEEP counted it: a live lane has no corpus, and a
    // ceiling measured against nothing bounds nothing.
    Ctx::of(cfg, community, store, me, roster_size(watches, community.id())).await
}

/// One blob at a time per community, and no more than the operator allows per
/// minute. Every message is its own task, so without this a wave of images is a
/// wave of concurrent multi-megabyte fetches and uploads.
///
/// Per COMMUNITY, so one room's flood cannot spend another's minute — and so
/// the resident-bytes bound is one blob per WATCHED COMMUNITY, not one overall.
/// The tripwire runs before this, or a queue here would hide a wave of images
/// from the one thing meant to catch it.
pub(crate) struct Budget {
    /// Downloads run in parallel: they are network-bound and cheap, and making
    /// them wait behind an inference meant a post sat untouched for as long as
    /// the model took on somebody else's image. Bounded anyway, because the
    /// SDK's own cap is 256 MiB and decryption copies, so this is the resident-
    /// bytes ceiling for one community.
    pub(crate) fetch: Semaphore,
    /// Inference is the scarce one — a local model answers a request at a time —
    /// so this is what actually queues. Widen it only if the endpoint can take it.
    pub(crate) slot: Semaphore,
    pub(crate) per_min: u32,
    pub(crate) spent: Mutex<(u64, u32)>,
}

impl Budget {
    /// How many blobs may be resident per community while downloading. Not the
    /// inference width: fetching four small images at once costs a few MiB and
    /// buys every one of them a head start.
    pub(crate) const FETCH_WIDTH: usize = 4;

    pub(crate) fn new(per_min: u32, concurrent: u32) -> Budget {
        Budget {
            fetch: Semaphore::new(Self::FETCH_WIDTH),
            slot: Semaphore::new(concurrent.max(1) as usize),
            per_min,
            spent: Mutex::new((0, 0)),
        }
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

    fn vis() -> crate::config::VisionCfg {
        let mut c = crate::config::VisionCfg { enabled: true, ..Default::default() };
        c.mimes = ["image/png", "image/jpeg", "image/gif", "video/mp4"].map(String::from).to_vec();
        c.video.enabled = true;
        c
    }

    /// A linked image renders inline exactly like an upload, so it has to be
    /// judged like one — posting the URL instead of the file was a clean bypass.
    #[test]
    fn a_linked_image_is_media_too() {
        let c = vis();
        let found = linked_media("look at https://example.com/pics/bad.png please", &c);
        assert_eq!(found, vec!["https://example.com/pics/bad.png"]);

        // Trailing punctuation belongs to the sentence, not the URL.
        assert_eq!(
            linked_media("see (https://example.com/a.jpg), yes", &c),
            vec!["https://example.com/a.jpg"]
        );

        // Same link twice is one fetch.
        assert_eq!(linked_media("https://e.com/a.gif https://e.com/a.gif", &c).len(), 1);

        // Types the operator does not judge are left alone: following every URL
        // a member posts is a crawler, not a moderation bot.
        assert!(linked_media("https://example.com/readme.txt", &c).is_empty());
        assert!(linked_media("https://example.com/no-extension", &c).is_empty());
        assert!(linked_media("not a link at all", &c).is_empty());

        // A query string must not be able to CLAIM a type the path does not have.
        assert!(
            linked_media("https://example.com/tracker?file=.png", &c).is_empty(),
            "the path names the type, never the query"
        );
        // ...nor a fragment.
        assert!(linked_media("https://example.com/page#a.png", &c).is_empty());
        // ...nor the host.
        assert!(linked_media("https://a.png/path", &c).is_empty(), "the authority is not the path");
    }

    /// The bot must never be usable as a probe into the network it runs on.
    #[tokio::test]
    async fn a_linked_fetch_refuses_private_space() {
        for target in [
            "http://127.0.0.1/x.png",
            "http://localhost/x.png",
            "http://192.168.1.10/x.png",
            "http://[::1]/x.png",
            "http://169.254.169.254/latest/meta-data.png",
            "file:///etc/passwd.png",
        ] {
            assert!(
                fetch_linked(target, 1024, 1).await.is_err(),
                "{target} must be refused before any request leaves this machine"
            );
        }
    }

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

    /// Audio and documents are skipped because no vision model can judge them,
    /// not because nobody sees them — a client does render audio as a player.
    /// Announcing every voice note would be a mod-channel line a minute.
    #[test]
    fn what_a_vision_model_cannot_judge_is_skipped_quietly() {
        let cfg = vision();
        for ext in ["ogg", "mp3", "pdf", "zip", "txt", "wav", "flac", "m4a", "xyz", ""] {
            assert_eq!(gate(ext, 1024, &cfg), Gate::Skip, ".{ext} is not something a vision model can judge");
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
        crate::config::VisionLabel { name: name.into(), title: String::new(), describe: String::new(), threshold, gravity: crate::config::Gravity::Grave }
    }

    /// The answer was cached and the question was not, so a blob classified
    /// before a label existed was exempt from that label for good.
    #[test]
    fn changing_what_is_asked_changes_the_cache_key() {
        let mut cfg = vision();
        cfg.labels = vec![label("gore", 0.9)];
        let one = asked_of("llava", &cfg, "image/png");

        cfg.labels.push(label("sexual_content", 0.9));
        let two = asked_of("llava", &cfg, "image/png");
        assert_ne!(one, two, "a new label is a new question");

        cfg.labels = vec![label("gore", 0.5)];
        assert_ne!(asked_of("llava", &cfg, "image/png"), one, "so is a moved threshold");

        assert_ne!(asked_of("other-model", &cfg, "image/png"), asked_of("llava", &cfg, "image/png"), "and so is a different model");
    }

    /// Same trap as the labels, one level down: a clip is never asked about
    /// directly, it is cut into a grid first. Re-cut it and the model is shown
    /// different frames, so a verdict cached under the old grid answers about
    /// pixels that were never sent.
    #[test]
    fn recutting_the_grid_changes_the_cache_key_for_video() {
        let mut cfg = vision();
        cfg.labels = vec![label("gore", 0.9)];
        let before = asked_of("llava", &cfg, "video/mp4");

        cfg.video.cols = 4;
        assert_ne!(asked_of("llava", &cfg, "video/mp4"), before, "a wider grid is a new question");

        cfg.video.cols = 3;
        cfg.video.rows = 3;
        assert_ne!(asked_of("llava", &cfg, "video/mp4"), before, "a taller grid is too");

        cfg.video.rows = 2;
        cfg.video.tile_width = 256;
        assert_ne!(asked_of("llava", &cfg, "video/mp4"), before, "and so is a coarser tile");
    }

    /// A still is not cut, so the grid is not part of ITS question — otherwise
    /// tuning video re-bills every image ever classified.
    #[test]
    fn the_grid_is_not_part_of_the_question_asked_of_a_still() {
        let mut cfg = vision();
        cfg.labels = vec![label("gore", 0.9)];
        let before = asked_of("llava", &cfg, "image/png");
        cfg.video.cols = 4;
        cfg.video.tile_width = 256;
        assert_eq!(asked_of("llava", &cfg, "image/png"), before);
    }

    /// Switching video off must not read as a clean answer for video: nobody
    /// looked, so a person is told.
    #[test]
    fn video_switched_off_is_refused_rather_than_skipped() {
        let mut cfg = vision();
        cfg.video.enabled = false;
        assert!(matches!(gate("mp4", 1024, &cfg), Gate::Refuse(_)), "silence would read as clean");
        assert_eq!(gate("png", 1024, &cfg), Gate::Fetch, "stills are unaffected");
        cfg.video.enabled = true;
        assert_eq!(gate("mp4", 1024, &cfg), Gate::Fetch);
    }

    /// Animated formats are clips in image containers, and a static one costs
    /// nothing extra: it has a single frame and collapses to a 1x1 sheet.
    #[test]
    fn animated_image_formats_are_cut_into_sheets_too() {
        let mut cfg = vision();
        for mime in ["video/mp4", "video/webm", "image/gif", "image/webp"] {
            assert!(sheeted(mime, &cfg), "{mime} hides later frames from a single look");
        }
        for mime in ["image/png", "image/jpeg"] {
            assert!(!sheeted(mime, &cfg), "{mime} is one frame by definition");
        }
        cfg.video.enabled = false;
        for mime in ["video/mp4", "image/gif", "image/webp"] {
            assert!(!sheeted(mime, &cfg), "{mime}: nothing is cut with the tooling switched off");
        }
    }

    /// The routing and the cache key have to agree about what gets cut, or a
    /// sheet is judged under a key minted for a whole file.
    #[test]
    fn the_cache_key_covers_exactly_what_gets_sheeted() {
        let mut cfg = vision();
        for mime in ["video/mp4", "image/gif", "image/webp", "image/png", "image/jpeg"] {
            let before = asked_of("llava", &cfg, mime);
            let mut wider = cfg.clone();
            wider.video.cols = 4;
            let changed = asked_of("llava", &wider, mime) != before;
            assert_eq!(changed, sheeted(mime, &cfg), "{mime}: key and routing disagree");
        }
        cfg.video.enabled = false;
        for mime in ["video/mp4", "image/gif"] {
            let before = asked_of("llava", &cfg, mime);
            let mut wider = cfg.clone();
            wider.video.cols = 4;
            assert_eq!(asked_of("llava", &wider, mime), before, "{mime}: nothing is cut, so the grid is not asked");
        }
    }

    /// Order in the file is not part of the question.
    #[test]
    fn the_same_labels_in_another_order_are_the_same_question() {
        let mut a = vision();
        a.labels = vec![label("gore", 0.9), label("sexual_content", 0.8)];
        let mut b = vision();
        b.labels = vec![label("sexual_content", 0.8), label("gore", 0.9)];
        assert_eq!(asked_of("llava", &a, "image/png"), asked_of("llava", &b, "image/png"));
    }

    /// The minute is per community: one room's flood must not decide another
    /// room's screening.
    #[test]
    fn each_community_spends_its_own_minute() {
        let a = Budget::new(2, 1);
        let b = Budget::new(2, 1);
        assert!(a.claim() && a.claim(), "its own allowance");
        assert!(!a.claim(), "and then it is spent");
        assert!(b.claim(), "which says nothing about anywhere else");
    }

    /// The two clocks gate charging differently, and they have to. A screened
    /// finding is emitted with no citation count (vector-core's
    /// `screen_message` does not set one — the caller supplied the message, so
    /// it IS the citation), while the sweep needs that condition because it
    /// reads a corpus where a finding can describe a person rather than an act.
    ///
    /// Unifying them would silently switch the text screen off entirely, so
    /// this pins the asymmetry rather than leaving it to be tidied away.
    #[test]
    fn a_screened_finding_is_charged_on_its_basis_alone() {
        let screened = vector_sdk::policy::Finding {
            conviction_id: String::new(),
            policy_hash: "abc123".into(),
            rule_id: "slurs".into(),
            scope: "per_message".into(),
            basis: "deterministic".into(),
            severity: "severe".into(),
            stateless: true,
            rung: 0,
            hits: 1,
            weight: 45,
            detail: vec!["badword".into()],
            // Both empty, exactly as screen_message emits them.
            messages: vec![],
            citation_count: 0,
        };
        assert!(screened.is_proven(), "the live screen charges on this");
        assert!(
            !crate::review::chargeable(&screened),
            "and the sweep's rule would refuse it — so the two must not be merged"
        );
    }
}
