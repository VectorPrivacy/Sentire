//! The operator's file. Everything tunable lives here: lenience, thresholds,
//! and the engine rules Sentinel runs.
//!
//! Validation is part of boot, not part of the first incident: a ladder whose
//! steps do not ascend, a gravity ordering that punishes a note harder than a
//! grave offense, or an unshielded-protected config refuses to start and names
//! the field.

use serde::{Deserialize, Serialize};

/// Every check that reads a ladder, limits or raid settings — run against the
/// FOLDED policy, so a per-community override cannot reach what the defaults
/// are refused. `whose` names the block in the error.
pub fn validate_policy(p: &crate::policy::CommunityPolicy, whose: &str) -> Result<(), String> {
    let at = |msg: String| Err(format!("{whose}: {msg}"));
    if !p.shields.respect_protected {
        return at("shields.respect_protected = false: refusing to start. \
                   The owner and moderators are never Sentinel's to judge."
            .into());
    }
    let s = &p.ladder.strikes;
    if !(s.note <= s.minor && s.minor <= s.serious && s.serious <= s.grave) {
        return at(format!(
            "ladder.strikes must not punish a lesser gravity harder: note {} <= minor {} <= serious {} <= grave {}",
            s.note, s.minor, s.serious, s.grave
        ));
    }
    if [s.note, s.minor, s.serious, s.grave].iter().any(|w| *w > 1_000_000) {
        return at("ladder.strikes over 1000000: a scale that large says nothing a smaller one does not".into());
    }
    if p.ladder.steps.is_empty() {
        return at("ladder.steps is empty: with no steps, no strike total ever answers to anything".into());
    }
    if p.ladder.steps[0].at == 0 {
        return at("ladder.steps starts at 0: that answers a total of zero, so every member is sentenced on sight".into());
    }
    for w in p.ladder.steps.windows(2) {
        if w[1].at <= w[0].at {
            return at(format!("ladder.steps must ascend: step at {} follows step at {}", w[1].at, w[0].at));
        }
        if w[1].response < w[0].response {
            return at(format!(
                "ladder.steps must not de-escalate: {:?} at {} follows {:?} at {}",
                w[1].response, w[1].at, w[0].response, w[0].at
            ));
        }
    }
    if p.ladder.decay_half_life_hours == 0 {
        return at("ladder.decay_half_life_hours = 0: strikes would never be forgiven, and the dedup horizon collapses".into());
    }
    // A year. The janitor keeps 32 half-lives, and once that reaches back past
    // the epoch the horizon saturates to zero and NOTHING is ever pruned — the
    // ledger and the classification cache grow for the life of the install,
    // with a healthy heartbeat beside them. A year is already "we do not
    // forget"; the ceiling is where the arithmetic stops working, not taste.
    if p.ladder.decay_half_life_hours > 24 * 365 {
        return at(format!(
            "ladder.decay_half_life_hours = {} is over a year. The janitor keeps 32 half-lives, and beyond this \
             that horizon runs past the epoch and pruning silently stops for every community.",
            p.ladder.decay_half_life_hours
        ));
    }
    if s.grave == 0 {
        return at("ladder.strikes.grave = 0: every offense is worth nothing, so no total ever answers to anything".into());
    }
    if p.limits.halt_if_over_pct == 0 || p.limits.halt_if_over_pct > 100 {
        return at(format!(
            "limits.halt_if_over_pct = {} — must be 1..=100 (0 would mean 'never act', which is what [arm] is for)",
            p.limits.halt_if_over_pct
        ));
    }
    if p.limits.halt_floor == 0 {
        return at("limits.halt_floor = 0: Sentinel could never answer for anybody".into());
    }
    if p.limits.max_actions_per_run == 0 || p.limits.max_actions_per_hour == 0 {
        return at("limits.max_actions_* = 0 silently disables enforcement; leave the class unarmed instead".into());
    }
    if p.raid.min_confidence > 99 {
        return at(format!(
            "raid.min_confidence = {}: confidence never reaches 100 by construction, so nothing would ever be contained",
            p.raid.min_confidence
        ));
    }
    // The floor is about what may be REMOVED. A rehearsal and report mode both
    // touch nobody, so "widen what I am shown" is a real thing to ask for while
    // watching — which is the rollout the README describes.
    if p.arm.raid && p.raid.response != RaidResponse::Report && p.raid.min_confidence < 50 {
        return at(format!(
            "raid.min_confidence = {} with containment armed to {}: a bar this low removes members over evidence \
             barely distinguishable from none. Widen it while rehearsing, or with response = \"report\".",
            p.raid.min_confidence,
            p.raid.response.name()
        ));
    }
    if p.raid.max_batch == 0 || p.raid.max_batch > 500 {
        return at(format!(
            "raid.max_batch = {}: must be 1..=500 (the wire rejects an over-cap banlist whole)",
            p.raid.max_batch
        ));
    }
    // ONE is not a rate and not a repeat: the engine's rung ladder starts at a
    // single hit, so a threshold of one convicts a member for their first
    // message. That flags everybody, which is the same as flagging nobody.
    if let Some(r) = &p.rules.rate {
        if r.enabled && r.messages < 2 {
            return at(format!(
                "rules.rate.messages = {}: one message inside {}s is not a flood, it is a member talking",
                r.messages, r.per_secs
            ));
        }
        if r.enabled && r.per_secs == 0 {
            return at("rules.rate.per_secs = 0: there is no window to count in".into());
        }
    }
    for (block, t) in [("repetition", &p.rules.repetition), ("mass_tagging", &p.rules.mass_tagging)] {
        if let Some(t) = t {
            if t.enabled && t.times < 2 {
                return at(format!("rules.{block}.times = {}: one occurrence is not a pattern", t.times));
            }
        }
    }
    if p.raid.tripwire_accounts < 2 {
        return at("raid.tripwire_accounts must be at least 2: one member talking is a conversation".into());
    }
    if p.raid.tripwire_secs == 0 || p.raid.tripwire_secs > 86_400 {
        return at("raid.tripwire_secs must be 1..=86400".into());
    }
    if p.raid.tripwire_cooldown_secs == 0 || p.raid.tripwire_cooldown_secs > 86_400 {
        return at(
            "raid.tripwire_cooldown_secs must be 1..=86400: with no cooldown every message of a wave trips a full \
             evaluation, which is the cost the tripwire exists to ration"
                .into(),
        );
    }
    if p.raid.claim_ttl_secs == 0 || p.raid.claim_ttl_secs > 30 * 86_400 {
        return at("raid.claim_ttl_secs must be 1..=2592000 (0 would re-contain the same wave every sweep)".into());
    }
    for r in &p.rules.words {
        if r.patterns.is_empty() {
            return at(format!("rules.words '{}' has no patterns", r.id));
        }
        // The matcher drops an empty needle, so the rule is configured, armed
        // and silently matches nothing.
        // The matcher strips one leading and one trailing `*`, so anything that
        // is only asterisks reduces to an empty needle and is dropped: the rule
        // is configured, armed, and matches nothing.
        if let Some(bad) = r.patterns.iter().find(|pat| pat.trim().chars().all(|c| c == '*')) {
            return at(format!("rules.words '{}' has the pattern {bad:?}, which matches nothing", r.id));
        }
    }
    for r in &p.rules.links {
        if r.domains.is_empty() {
            return at(format!("rules.links '{}' has no domains", r.id));
        }
        if let Some(bad) = r.domains.iter().find(|d| d.trim().is_empty()) {
            return at(format!("rules.links '{}' has the domain {bad:?}, which matches nothing", r.id));
        }
    }
    // The rulebook the ENGINE will accept, not the one Sentinel can describe.
    // A window over the cap, a duplicate or over-long rule id, or too many
    // patterns is rejected whole at install time — which surfaced as one
    // stderr line per pass, beside a healthy heartbeat, with the community
    // running no custom rulebook at all.
    if let Some(policy) = crate::rules::compile(p) {
        if let Err(e) = policy.build() {
            return at(format!("the engine refuses this rulebook: {e}"));
        }
    }
    Ok(())
}

/// Sentinel's own vocabulary for how bad something is. Deliberately NOT the
/// engine's `Severity`: severity is the policy author's judgement, gravity is
/// the operator's. The two map, they never silently merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Gravity {
    Note,
    Minor,
    Serious,
    Grave,
}

impl Gravity {
    /// Fallback when the operator never named a gravity for a rule: the
    /// engine severity, translated.
    /// An UNRECOGNISED severity is the least punitive answer, not the worst
    /// one. A renamed field or a missing value read as `""` and mapped to
    /// Grave, which on the default ladder is an instant ban.
    pub fn from_severity(severity: &str) -> Gravity {
        match severity {
            "severe" => Gravity::Grave,
            "major" => Gravity::Serious,
            "minor" => Gravity::Minor,
            _ => Gravity::Note,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub bot: Bot,
    pub arm: Arm,
    pub limits: Limits,
    pub rules: Rules,
    pub ladder: Ladder,
    pub shields: Shields,
    pub raid: Raid,
    pub vision: VisionCfg,
    pub notify: NotifyCfg,
    /// Per-community overrides, keyed by community id. Anything absent falls
    /// back to the blocks above, so an operator names only what differs.
    ///
    /// This layer PINS: it is applied after whatever the community set from
    /// chat, so naming a setting here takes it out of their hands.
    pub community: std::collections::HashMap<String, crate::policy::Overrides>,
    /// What communities set for THEMSELVES, from chat. Loaded from Sentinel's
    /// store at boot and updated in place as commands land, so every reader of
    /// `for_community` sees the change without the process restarting or the
    /// shared `Arc<Config>` being swapped underneath running tasks.
    ///
    /// Never parsed from the TOML — the operator's file says what the operator
    /// decided, and mixing the two would make a `/set` look like something they
    /// had written.
    #[serde(skip)]
    pub chat: std::sync::Arc<std::sync::RwLock<std::collections::HashMap<String, crate::policy::Overrides>>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Bot {
    /// Env var holding the nsec — never the key itself, in any file.
    pub nsec_env: String,
    /// Community ids to watch; `["*"]` = every one Sentinel is a member of.
    pub communities: Vec<String>,
    /// Channel NAME for the audit trail. Omit to stay silent.
    pub mod_channel: Option<String>,
    /// Seconds between sweeps. Clamped up to 90: the report is memoised for
    /// that long, so anything faster re-parses bytes it has already seen.
    pub poll_secs: u64,
    /// How Sentinel introduces itself. Published as a kind-0 at boot, and only
    /// when it differs from what is already out there — a member looking up an
    /// npub that just warned them deserves to find out what it is.
    pub profile: Profile,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Profile {
    pub name: String,
    pub about: String,
    pub avatar: String,
    pub banner: String,
}

impl Default for Profile {
    fn default() -> Self {
        Profile {
            name: "Sentire".into(),
            about: "The Guard for your Community".into(),
            avatar: String::new(),
            banner: String::new(),
        }
    }
}

impl Default for Bot {
    fn default() -> Self {
        Bot {
            nsec_env: "SENTINEL_NSEC".into(),
            communities: vec!["*".into()],
            mod_channel: None,
            poll_secs: 120,
            profile: Profile::default(),
        }
    }
}

/// Every one defaults false. Dry-run is the resting state, arming is per action
/// class — a bot that warns is not thereby a bot that bans — and changing any
/// of them clears that community's slate, so a rehearsal never becomes a
/// backlog the armed run discharges at once.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Arm {
    pub warn: bool,
    pub delete: bool,
    pub kick: bool,
    pub ban: bool,
    pub raid: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub max_actions_per_run: usize,
    pub max_actions_per_hour: usize,
    /// How many DISTINCT people Sentinel may answer for in one community in an
    /// hour, as a percentage of the roster, before it stops and asks a person.
    /// Not a rate limit — every member has their own strikes and their own
    /// rung. This is the blast radius: a misconfigured rule or a bad raid call
    /// must not be able to walk the whole memberlist.
    pub halt_if_over_pct: u32,
    /// ...but never fewer than this many people. A percentage alone is the
    /// wrong shape when a community is small: 10% of four members floors to
    /// one, so the SECOND offender in an hour deadlocks the bot — and a halt
    /// also defers raid containment and skips the debt loop.
    pub halt_floor: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_actions_per_run: 25, max_actions_per_hour: 100, halt_if_over_pct: 10, halt_floor: 3 }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Rules {
    pub window_hours: u64,
    pub window_messages: usize,
    /// Whether Sentinel acts on raid detection at all. The engine's built-in
    /// cohort rules keep running either way — this decides whether containment
    /// is consulted, so a config field that says `false` means it.
    pub raid_detection: bool,
    pub words: Vec<WordRule>,
    pub links: Vec<LinkRule>,
    pub rate: Option<RateRule>,
    pub mass_tagging: Option<ToggleRule>,
    pub repetition: Option<ToggleRule>,
}

impl Default for Rules {
    fn default() -> Self {
        Rules {
            window_hours: 168,
            window_messages: 4000,
            raid_detection: true,
            words: vec![],
            links: vec![],
            rate: None,
            mass_tagging: None,
            repetition: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WordRule {
    pub id: String,
    /// What this rule is CALLED when a member is told they broke it. The id is
    /// yours for the config and the ledger; `Slurs` reads better in a channel
    /// than `slurs_v2`. Defaults to the id, tidied.
    #[serde(default)]
    pub title: String,
    pub patterns: Vec<String>,
    pub gravity: Gravity,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinkRule {
    pub id: String,
    /// See [`WordRule::title`].
    #[serde(default)]
    pub title: String,
    pub domains: Vec<String>,
    pub gravity: Gravity,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RateRule {
    pub enabled: bool,
    /// The window messages are counted in.
    pub per_secs: u64,
    /// How many inside that window convict. The engine's rung ladder starts at
    /// ONE hit, so without this a member's first message in a minute is a
    /// flood.
    pub messages: u32,
    pub gravity: Gravity,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ToggleRule {
    pub enabled: bool,
    /// How many occurrences convict. One is not a repeat.
    pub times: u32,
    pub gravity: Gravity,
}

impl Default for RateRule {
    fn default() -> Self {
        // Ten in a minute is a flood; one is a member talking. Defaults exist
        // so `enabled = true` alone means something sane, and so a
        // per-community override can switch a block off without restating it.
        RateRule { enabled: false, per_secs: 60, messages: 10, gravity: Gravity::Minor }
    }
}

impl Default for ToggleRule {
    fn default() -> Self {
        ToggleRule { enabled: false, times: 4, gravity: Gravity::Minor }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ladder {
    /// What one offense of each gravity is worth.
    pub strikes: Strikes,
    /// A strike is worth half after this long. Forgiveness is built in, not a
    /// pardon someone has to remember to issue.
    pub decay_half_life_hours: u64,
    pub steps: Vec<Step>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Strikes {
    pub note: u32,
    pub minor: u32,
    pub serious: u32,
    pub grave: u32,
}

impl Default for Strikes {
    fn default() -> Self {
        Strikes { note: 1, minor: 2, serious: 4, grave: 12 }
    }
}

impl Strikes {
    pub fn worth(&self, g: Gravity) -> u32 {
        match g {
            Gravity::Note => self.note,
            Gravity::Minor => self.minor,
            Gravity::Serious => self.serious,
            Gravity::Grave => self.grave,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub at: u32,
    pub response: Response,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Response {
    Warn,
    DeleteAndWarn,
    Kick,
    Ban,
}

impl Response {
    /// Severity order, as one number. Derived from the enum rather than a
    /// hand-written string table: a table's catch-all was `0`, so a renamed or
    /// added variant silently read as "nothing has happened yet".
    pub fn rank(self) -> u8 {
        self as u8 + 1
    }

    /// The wire name, so the enum is the only place these strings live.
    pub fn name(self) -> &'static str {
        match self {
            Response::Warn => "warn",
            Response::DeleteAndWarn => "delete_and_warn",
            Response::Kick => "kick",
            Response::Ban => "ban",
        }
    }

    /// How a response reads to somebody who did not write the config. The wire
    /// name is a key, and `delete_and_warn` in a sentence asks a member to parse
    /// an identifier to find out what is about to happen to them.
    pub fn label(self) -> &'static str {
        match self {
            Response::Warn => "a Warning",
            Response::DeleteAndWarn => "Deletion and a Warning",
            Response::Kick => "a Kick",
            Response::Ban => "a Ban",
        }
    }

    /// Every response, for callers that must enumerate them (the store's
    /// severity ordering, tests that prove the two agree).
    pub const ALL: [Response; 4] = [Response::Warn, Response::DeleteAndWarn, Response::Kick, Response::Ban];

    /// The rank of a stored response name. `None` maps to 0 — an unrecognised
    /// row is not a prior action, which is the safe reading in both directions.
    pub fn rank_of(name: &str) -> u8 {
        Response::ALL.iter().find(|r| r.name() == name).map(|r| r.rank()).unwrap_or(0)
    }
}

impl Default for Ladder {
    fn default() -> Self {
        Ladder {
            strikes: Strikes::default(),
            decay_half_life_hours: 168,
            // Two warnings, then a kick, then a ban — against `grave` being
            // worth 12, so a serious offender is warned twice before losing
            // access. Removal of the post itself is NOT a rung: whatever a
            // conviction cites comes down the first time it is answered, so a
            // ladder step only ever decides what happens to the member.
            steps: vec![
                Step { at: 1, response: Response::Warn },
                Step { at: 36, response: Response::Kick },
                Step { at: 48, response: Response::Ban },
            ],
        }
    }
}

/// The media lane. Off by default: it ships bytes to a model, and that is a
/// decision an operator makes rather than inherits.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct VisionCfg {
    pub enabled: bool,
    /// The cap for media that is CUT INTO A SHEET first — clips and animations.
    ///
    /// `max_bytes` bounds what is sent to the model, and for a still that is the
    /// file itself. A clip is different: it becomes a contact sheet of a few
    /// hundred KiB however large the source was, so the source size is transient
    /// download and ffmpeg cost, not model cost. Holding both to one number meant
    /// an 8 MiB ceiling refused ordinary 10-50 MiB GIFs unseen — the exact media
    /// a raider reaches for.
    ///
    /// Still bounded, because the bytes are resident while they are cut: this
    /// times the fetch width is the peak for one community.
    pub max_sheeted_bytes: u64,
    /// Judge images a member LINKS, not only ones they upload.
    ///
    /// A URL renders inline in the client exactly like an upload, so with this
    /// off the whole surface is open: post the link instead of the file and
    /// nothing looks at it.
    ///
    /// It is a flag because following a stranger's URL has costs the SSRF guard
    /// cannot remove — the host learns this machine's IP, and it may serve clean
    /// bytes to the bot while serving something else to the room.
    pub judge_links: bool,
    /// How many attachments this bot judges at once, per community.
    ///
    /// The slot is held from before the download until the model answers, so at
    /// 1 a second image posted in the same second waits out the whole first
    /// inference — tens of seconds against a large local model, which reads as
    /// "it ignored my post". Raise it where the endpoint can take the
    /// concurrency; each extra slot is another blob resident and another request
    /// in flight, so it is the operator's call and not a default.
    pub concurrent: u32,
    /// Which communities the media lane runs in. `None` (the key absent) means
    /// every watched community, which is what a single-tenant bot wants.
    ///
    /// A bot watching `["*"]` is a different animal: it is in every community
    /// anyone invited it to, and the media lane is the one that costs real money
    /// and ships decrypted attachments to a model. So an operator running a
    /// public bot names the communities that get it, and everyone else still
    /// gets text rules and raid containment for nothing.
    pub communities: Option<Vec<String>>,
    /// llama.cpp's server speaks the OpenAI-compatible shape, so local and
    /// remote differ by a URL and a header, not by an implementation.
    pub base_url: String,
    pub model: String,
    /// Env var holding an API key. Empty = a local endpoint with no auth.
    pub api_key_env: String,
    /// Required for any host that is not loopback. An attachment is
    /// end-to-end encrypted right up until Sentinel decrypts it and posts it to
    /// somebody else's server, so that step is explicit or it does not happen.
    pub allow_remote: bool,
    pub timeout_secs: u64,
    pub max_bytes: u64,
    /// Classifications per minute, so a wave of images cannot become a bill or
    /// a stalled sweep.
    pub max_per_min: u32,
    /// What to send the model. Whether it can read a given type is its
    /// business, not Sentinel's: an endpoint that cannot answer for a video
    /// says so, and an unanswered attachment goes to a person.
    pub mimes: Vec<String>,
    /// A ceiling on the ANSWER. The reply is a small JSON map, so anything long
    /// is a model talking to itself — and a loop that runs to the timeout holds
    /// that community's one blob slot for the whole of it.
    #[serde(default = "default_answer_tokens")]
    pub max_answer_tokens: u32,
    /// How many times to ask before giving up on a usable answer. A model that
    /// returns prose, fences its JSON, or drops a label is asked again with the
    /// fault named. BOUNDED, not "until it complies": a model that never
    /// complies would hold the blob slot and spend the budget forever, and
    /// unjudged-and-escalated is the safe end of that.
    #[serde(default = "default_attempts")]
    pub max_attempts: u32,
    /// Sent as `reasoning_effort`. Local reasoning models otherwise spend the
    /// whole budget deliberating about a picture and answer with truncated
    /// JSON, which reads as unjudged. Empty omits the field; an endpoint that
    /// rejects it is retried once without it.
    #[serde(default = "default_reasoning_effort")]
    pub reasoning_effort: String,
    pub labels: Vec<VisionLabel>,
    #[serde(default)]
    pub video: VideoCfg,
}

fn default_answer_tokens() -> u32 {
    256
}

fn default_attempts() -> u32 {
    3
}

fn default_reasoning_effort() -> String {
    "none".into()
}

/// People to tell, personally, when Sentinel acts.
///
/// The mod channel is a room; this is a DM. An owner who is not reading the
/// channel at 3am still finds out what happened in the morning.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NotifyCfg {
    /// npubs to DM. Empty means nobody, which is the default: Sentinel does not
    /// message people who never asked it to.
    pub mods: Vec<String>,
    /// Forward what was actually posted, so the decision can be checked rather
    /// than taken on trust. Images are sent with a `SPOILER_` filename, which
    /// is how Vector marks an attachment to be revealed on tap.
    pub attach_media: bool,
    /// Post a short line in the channel the rule was broken in, naming the
    /// member. Public, brief, and says what happens next.
    pub notice_in_channel: bool,
    /// Seconds before that notice deletes itself. It has to be seen, not kept:
    /// the room learns the rule is real, and nobody is left with a permanent
    /// public record of their worst day pinned to the channel. 0 keeps it.
    #[serde(default = "default_notice_ttl")]
    pub notice_ttl_secs: u64,
}

fn default_notice_ttl() -> u64 {
    30
}

impl Default for NotifyCfg {
    fn default() -> Self {
        NotifyCfg {
            mods: Vec::new(),
            attach_media: false,
            notice_in_channel: false,
            // Not `Default::default()`: a zeroed TTL means "keep it forever",
            // which is the one value nobody would choose on purpose.
            notice_ttl_secs: default_notice_ttl(),
        }
    }
}

/// How a clip becomes something a still-image model can answer for.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VideoCfg {
    /// Off means video is refused rather than judged — which reaches a person,
    /// because a type nobody looked at is not a clean type.
    pub enabled: bool,
    /// Looked up on PATH unless given a path. Absent at startup is a warning,
    /// not a failure: images still work without it.
    pub ffmpeg: String,
    pub ffprobe: String,
    /// The grid. Frames are spread across the WHOLE clip, so more tiles buy
    /// resolution in time, and each one costs the model pixels.
    pub cols: u32,
    pub rows: u32,
    /// Width of one tile in pixels; height follows the source aspect.
    pub tile_width: u32,
    /// A wall clock on ffmpeg itself. Decoding attacker-supplied video is the
    /// one place Sentinel runs a parser it did not write.
    pub timeout_secs: u64,
    /// Longest clip to sample across. A three-hour upload spread over six tiles
    /// samples every thirty minutes, which answers for nothing.
    pub max_duration_secs: f64,
}

impl Default for VideoCfg {
    fn default() -> Self {
        VideoCfg {
            enabled: true,
            ffmpeg: "ffmpeg".into(),
            ffprobe: "ffprobe".into(),
            cols: 3,
            rows: 2,
            tile_width: 512,
            timeout_secs: 30,
            max_duration_secs: 600.0,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VisionLabel {
    pub name: String,
    /// See [`WordRule::title`]. `sexual_content` is a label a model scores;
    /// **NSFW** is what a member is told they broke.
    #[serde(default)]
    pub title: String,
    /// What this label MEANS, in the operator's own words, sent to the model
    /// with the label. A bare name is the model's guess at a community's
    /// standards; a sentence is the operator's. Optional, so a config written
    /// before this still loads — but a label without one is judged by whatever
    /// the model imagines the word covers.
    #[serde(default)]
    pub describe: String,
    /// 0.0..=1.0. A label with no threshold would flag everything.
    pub threshold: f32,
    pub gravity: Gravity,
}

impl Default for VisionCfg {
    fn default() -> Self {
        VisionCfg {
            communities: None,
            max_sheeted_bytes: 64 * 1024 * 1024,
            judge_links: true,
            concurrent: 1,
            enabled: false,
            base_url: "http://127.0.0.1:8080/v1".into(),
            model: "llava".into(),
            api_key_env: String::new(),
            allow_remote: false,
            timeout_secs: 60,
            max_bytes: 8 * 1024 * 1024,
            max_per_min: 20,
            mimes: ["image/png", "image/jpeg", "image/webp", "image/gif", "video/mp4", "video/webm"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            max_answer_tokens: default_answer_tokens(),
            max_attempts: default_attempts(),
            reasoning_effort: default_reasoning_effort(),
            labels: vec![],
            video: VideoCfg::default(),
        }
    }
}

impl VisionCfg {
    /// Does this endpoint keep the bytes on this machine?
    ///
    /// Parsed properly, not split on punctuation: `http://127.0.0.1:8080@evil.com/v1`
    /// has authority `127.0.0.1:8080@evil.com` and a HOST of `evil.com`. Reading
    /// the leading text as the host would have judged that local and shipped
    /// decrypted attachments off the machine with no warning printed.
    pub fn is_local(&self) -> bool {
        let after_scheme = self.base_url.split_once("//").map(|(_, r)| r).unwrap_or(&self.base_url);
        let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or_default();
        // Userinfo precedes the LAST '@'; the host is what follows it.
        let hostport = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);
        let host = if let Some(rest) = hostport.strip_prefix('[') {
            rest.split_once(']').map(|(h, _)| h).unwrap_or(rest)
        } else {
            hostport.rsplit_once(':').map(|(h, _)| h).unwrap_or(hostport)
        };
        matches!(host.to_ascii_lowercase().as_str(), "127.0.0.1" | "localhost" | "::1")
    }
}

/// What a detected raid answers to. Deliberately outside the ladder: a raid is
/// one event, and escalating through warnings while a hundred accounts post the
/// same line is the wrong shape.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Raid {
    /// Confidence a suspect must reach to be contained. 75 is the Alert band's
    /// floor — the engine's own word for "convinced".
    pub min_confidence: u32,
    pub response: RaidResponse,
    /// Distinct accounts that must speak (or join) inside `tripwire_secs` for
    /// Sentinel to stop waiting for the sweep and evaluate immediately. The
    /// tripwire decides WHEN to ask, never who is guilty.
    pub tripwire_accounts: usize,
    pub tripwire_secs: u64,
    /// Never re-evaluate more often than this. An evaluation is a full corpus
    /// read, and a sustained wave would otherwise ask for one per message.
    pub tripwire_cooldown_secs: u64,
    /// How long a containment claim binds. Long enough that a wave arriving
    /// over many sweeps is one event; short enough that the same accounts
    /// raiding next week are a new one.
    pub claim_ttl_secs: u64,
    /// Members per ban call. The wire caps a banlist at 500 and rejects an
    /// over-cap batch WHOLE, so a bigger wave arrives in pieces.
    pub max_batch: usize,
    /// Community tenure (seconds) above which a suspect counts as ESTABLISHED.
    ///
    /// The raid halt protects established members from a misfiring cohort — it
    /// must NEVER limit removing fresh raiders, or a raid that inflates the
    /// roster raises the very bar it has to clear (150 real members bloated to
    /// 650 by bots sails past a 50% ceiling exactly when containment matters
    /// most). Only suspects with tenure at or above this count toward
    /// `halt_floor`; anyone newer is a fresh account, contained without limit.
    pub protect_tenure_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RaidResponse {
    /// Name the cohort and touch nobody.
    Report,
    /// They can come back. Cheap to undo, and it breaks a wave.
    Kick,
    /// Terminal, and in a private community it rekeys around them.
    Ban,
}

impl RaidResponse {
    pub fn name(self) -> &'static str {
        match self {
            RaidResponse::Report => "report",
            RaidResponse::Kick => "kick",
            RaidResponse::Ban => "ban",
        }
    }
}

impl Default for Raid {
    fn default() -> Self {
        Raid {
            min_confidence: 75,
            response: RaidResponse::Kick,
            tripwire_accounts: 5,
            tripwire_secs: 30,
            tripwire_cooldown_secs: 60,
            claim_ttl_secs: 6 * 3600,
            max_batch: 100,
            // 24h: a raider joins during the raid, so community tenure of a day
            // cleanly separates them from a member who was here yesterday.
            protect_tenure_secs: 24 * 3600,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Shields {
    /// A Trusted member is queued for a human, never actioned.
    pub respect_trusted: bool,
    /// Non-negotiable. The field exists so the refusal can name it.
    pub respect_protected: bool,
}

impl Default for Shields {
    fn default() -> Self {
        Shields { respect_trusted: true, respect_protected: true }
    }
}

impl Config {
    /// Read and validate, or say exactly what is wrong. A missing file is the
    /// defaults: raid detection only, everything dry.
    pub fn load(path: &str) -> Result<Config, String> {
        let cfg: Config = match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text).map_err(|e| format!("{path}: {e}"))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Config::default(),
            Err(e) => return Err(format!("{path}: {e}")),
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// `validate` is private; this lets the binary's own tests drive the real
    /// one rather than a copy of its rules.
    #[cfg(test)]
    pub fn validate_for_test(cfg: &Config) -> Result<(), String> {
        cfg.validate()
    }

    fn validate(&self) -> Result<(), String> {
        // Every policy that will actually be USED, not just the defaults. An
        // override could otherwise set anything the checks below refuse by
        // name — a ladder starting at 0 sentences on sight, a zero half-life
        // makes strikes permanent, a zero batch panics the sweep.
        validate_policy(&self.for_community(""), "defaults")?;
        for id in self.community.keys() {
            validate_policy(&self.for_community(id), &format!("[community.\"{id}\"]"))?;
        }

        // The base policy is folded under the empty id, so a block claiming that
    // key would replace the defaults' own validation with its own — and every
    // real community, whose id is 64 hex, would go on getting the unvalidated
    // base.
    if let Some(bad) = self
        .community
        .keys()
        .find(|c| c.len() != 64 || !c.chars().all(|ch| ch.is_ascii_hexdigit()))
    {
        // A block keyed on a typo applies to nobody and says nothing, which is
        // the dangerous direction: an override written to PROTECT a community
        // leaves it judged by the defaults. The empty id is doubly wrong — it
        // is how the base policy is addressed, so a block there would replace
        // the defaults' own validation.
        return Err(format!(
            "[community.\"{bad}\"] is not a community id (64 hex characters), so the block applies to nobody"
        ));
    }
    // A watch list entry that matches nothing looks exactly like never having
    // been invited, and the boot line says the same thing for both.
    if let Some(bad) = self
        .bot
        .communities
        .iter()
        .find(|c| *c != "*" && (c.len() != 64 || !c.chars().all(|ch| ch.is_ascii_hexdigit())))
    {
        return Err(format!(
            "bot.communities lists '{bad}', which is not a community id (64 hex characters) or \"*\". \
             Sentinel would watch nothing and say only that it had not been invited."
        ));
    }
    if self.bot.communities.is_empty() {
            return Err("bot.communities is empty: Sentinel would watch nothing. Use [\"*\"] for every community.".into());
        }
        if self.vision.enabled {
            if self.vision.labels.is_empty() {
                return Err("vision.enabled with no vision.labels: the model would be asked to judge nothing".into());
            }
            for l in &self.vision.labels {
                // Scores are clamped into 0.0..=1.0, so a 0.0 threshold is
                // always met: that label would flag every image posted.
                if !(l.threshold > 0.0 && l.threshold <= 1.0) {
                    return Err(format!(
                        "vision label '{}' has threshold {} — must be greater than 0.0 and at most 1.0",
                        l.name, l.threshold
                    ));
                }
            }
            let mut seen = std::collections::HashSet::new();
            for l in &self.vision.labels {
                // `over_threshold` takes the first match, so a second entry's
                // threshold and gravity are silently ignored.
                if l.name.trim().is_empty() {
                    return Err("a vision label has no name".into());
                }
                if !seen.insert(l.name.as_str()) {
                    return Err(format!("vision label '{}' is listed twice; the second is ignored", l.name));
                }
            }
            // Every one of these turns the lane into a machine for announcing
            // that it judged nothing: configured, running, and structurally
            // unable to answer.
            if self.vision.mimes.is_empty() {
                return Err("vision.mimes is empty: nothing would ever be sent to the model".into());
            }
            // A type the byte sniffer cannot name is one Sentinel will fetch,
            // fail to identify, and route to a person — forever, for every
            // attachment of that type.
            let known = vector_sdk::vector_core::crypto::RECOGNISED_MIMES;
            if let Some(bad) = self.vision.mimes.iter().find(|m| !known.contains(&m.as_str())) {
                return Err(format!(
                    "vision.mimes lists '{bad}', which cannot be recognised from an attachment's bytes. \
                     Known types: {}",
                    known.join(", ")
                ));
            }
            if !self.vision.base_url.contains("://") {
                return Err(format!(
                    "vision.base_url '{}' has no scheme — every request would fail to build, and every \
                     attachment would route to a person",
                    self.vision.base_url
                ));
            }
            if self.vision.max_bytes == 0 {
                return Err("vision.max_bytes = 0: every attachment is refused as oversize".into());
            }
            if self.vision.max_per_min == 0 {
                return Err("vision.max_per_min = 0: the minute's allowance is spent before it starts".into());
            }
            if self.vision.timeout_secs == 0 {
                return Err("vision.timeout_secs = 0: every classification times out unanswered".into());
            }
            if self.vision.model.trim().is_empty() {
                return Err("vision.model is empty".into());
            }
            if !self.vision.is_local() && !self.vision.allow_remote {
                return Err(format!(
                    "vision.base_url {} is not loopback and vision.allow_remote is false. \
                     An attachment is end-to-end encrypted until Sentinel decrypts it and posts it \
                     to that host; say so on purpose or keep the model local.",
                    self.vision.base_url
                ));
            }
        }
        Ok(())
    }

    /// Is this community one Sentinel was told to watch? `["*"]` is every one.
    ///
    /// Scoping only the sweep meant an invite to a second community had
    /// Sentinel enforcing its ladder there against whatever policies that
    /// community happened to hold.
    pub fn watches(&self, community_id: &str) -> bool {
        self.bot.communities.iter().any(|w| w == "*" || w == community_id)
    }

    /// Load what every community set for itself into the live chat layer.
    ///
    /// Called once at boot. A row that no longer parses is skipped and named,
    /// never fatal: settings written by a newer Sentinel must not stop an older
    /// one from moderating, and reverting somebody's rules in silence is exactly
    /// the failure nobody notices.
    pub fn load_chat_layer(&self, store: &crate::store::Store) {
        let Ok(rows) = store.community_configs() else { return };
        let mut live = self.chat.write().unwrap_or_else(|e| e.into_inner());
        for (id, json) in rows {
            match serde_json::from_str::<crate::policy::Overrides>(&json) {
                Ok(o) => {
                    live.insert(id, o);
                }
                Err(e) => eprintln!("[config] {}'s settings did not parse and were skipped: {e}", &id[..8.min(id.len())]),
            }
        }
        if !live.is_empty() {
            println!("[config] {} community/communities configured from chat", live.len());
        }
    }

    /// Apply a change a community made, and persist it — validated FIRST.
    ///
    /// Order matters: a value that would not compile is refused with its reason
    /// rather than stored. Otherwise a typo takes a community's moderation off
    /// the air and the only symptom is that nothing ever happens again.
    pub fn set_chat_override(
        &self,
        community_id: &str,
        store: &crate::store::Store,
        edit: impl FnOnce(&mut crate::policy::Overrides),
    ) -> Result<(), String> {
        let mut next = self
            .chat
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(community_id)
            .cloned()
            .unwrap_or_default();
        edit(&mut next);

        // Validate the RESULT, in the same layering the bot will read it in —
        // a value that is fine alone can still be nonsense once the operator's
        // pins land on top of it.
        let mut probe = self.clone();
        probe.chat = std::sync::Arc::new(std::sync::RwLock::new(
            [(community_id.to_string(), next.clone())].into_iter().collect(),
        ));
        validate_policy(&probe.for_community(community_id), "this community")?;

        let json = serde_json::to_string(&next).map_err(|e| e.to_string())?;
        store.set_community_config(community_id, &json, crate::now_ms())?;
        self.chat.write().unwrap_or_else(|e| e.into_inner()).insert(community_id.to_string(), next);
        Ok(())
    }

    /// Whether the media lane runs in this community.
    ///
    /// Three gates, all of which must pass: the operator configured a model at
    /// all, this community is on the vision list (or there is no list), and the
    /// community's own block did not switch it off. The per-community `false` is
    /// honoured even against an explicit allowlist entry — the narrower answer
    /// wins, so turning one room off never means editing the list too.
    pub fn vision_enabled_for(&self, community_id: &str) -> bool {
        if !self.vision.enabled {
            return false;
        }
        if let Some(over) = self.community.get(community_id).and_then(|o| o.vision.as_ref()).and_then(|v| v.enabled) {
            return over;
        }
        self.vision.communities.as_ref().is_none_or(|list| list.iter().any(|c| c == "*" || c == community_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `rank_of` reads a hand-maintained table; a variant missing from it ranks
    /// 0, which means "nothing has happened yet" and re-sentences everyone.
    #[test]
    fn every_response_is_in_the_table_that_ranks_them() {
        assert_eq!(Response::ALL.len(), 4);
        for r in Response::ALL {
            assert_eq!(Response::rank_of(r.name()), r.rank(), "{r:?} is missing from ALL");
            // A raid row shares the table and must never read as a ladder
            // response: an unarmed raid stamping "kick" on every suspect would
            // immunise all of them.
            assert_eq!(Response::rank_of(&format!("raid:{}", r.name())), 0);
        }
        let mut ranks: Vec<u8> = Response::ALL.iter().map(|r| r.rank()).collect();
        ranks.dedup();
        assert_eq!(ranks.len(), 4, "two responses share a rank");
    }

    #[test]
    fn the_defaults_validate_and_are_dry() {
        let cfg = Config::default();
        assert!(cfg.validate().is_ok());
        assert!(!cfg.arm.warn && !cfg.arm.delete && !cfg.arm.kick && !cfg.arm.ban && !cfg.arm.raid);
    }

    #[test]
    fn every_refusal_names_its_field() {
        let cases: &[(&str, &str)] = &[
            ("[shields]\nrespect_protected = false", "respect_protected"),
            ("[community.\"fe4abeb3fd227a67fc59d8a4363420649bb970436dc3b14d51c2b66fee334dea\".shields]\nrespect_protected = false", "respect_protected"),
            ("[ladder]\nstrikes = { note = 5, minor = 2, serious = 4, grave = 12 }", "strikes"),
            ("[[ladder.steps]]\nat = 4\nresponse = \"warn\"\n[[ladder.steps]]\nat = 1\nresponse = \"kick\"", "ascend"),
            ("[[ladder.steps]]\nat = 1\nresponse = \"kick\"\n[[ladder.steps]]\nat = 4\nresponse = \"warn\"", "de-escalate"),
            ("[ladder]\ndecay_half_life_hours = 0", "decay_half_life_hours"),
            ("[raid]\nmin_confidence = 100", "min_confidence"),
            ("[raid]\nmax_batch = 0", "max_batch"),
            ("[raid]\nmax_batch = 900", "max_batch"),
            ("[raid]\ntripwire_accounts = 1", "tripwire_accounts"),
            ("[limits]\nhalt_if_over_pct = 0", "halt_if_over_pct"),
            ("[limits]\nhalt_if_over_pct = 200", "halt_if_over_pct"),
            ("[limits]\nmax_actions_per_run = 0", "max_actions_"),
            ("[bot]\ncommunities = []", "communities"),
            ("[[ladder.steps]]\nat = 0\nresponse = \"ban\"", "sentenced on sight"),
            ("[ladder]\nstrikes = { note = 1, minor = 2, serious = 4, grave = 9999999 }", "says nothing a smaller one does not"),
            ("[vision]\nenabled = true\n[[vision.labels]]\nname = \"g\"\nthreshold = 0.0\ngravity = \"grave\"", "greater than 0.0"),
            ("[vision]\nenabled = true", "vision.labels"),
            ("[vision]\nenabled = true\nbase_url = \"https://api.example.com/v1\"\n[[vision.labels]]\nname = \"gore\"\nthreshold = 0.9\ngravity = \"grave\"", "allow_remote"),
            ("[vision]\nenabled = true\n[[vision.labels]]\nname = \"gore\"\nthreshold = 4.0\ngravity = \"grave\"", "threshold"),
            ("[[rules.words]]\nid = \"empty\"\npatterns = []\ngravity = \"note\"", "empty"),
            // An override must not reach what the defaults are refused.
            ("[community.\"fe4abeb3fd227a67fc59d8a4363420649bb970436dc3b14d51c2b66fee334dea\".ladder]\nsteps = [{ at = 0, response = \"ban\" }]", "sentenced on sight"),
            ("[community.\"fe4abeb3fd227a67fc59d8a4363420649bb970436dc3b14d51c2b66fee334dea\".ladder]\ndecay_half_life_hours = 0", "decay_half_life_hours"),
            ("[community.\"fe4abeb3fd227a67fc59d8a4363420649bb970436dc3b14d51c2b66fee334dea\".raid]\nmax_batch = 0", "max_batch"),
            ("[community.\"fe4abeb3fd227a67fc59d8a4363420649bb970436dc3b14d51c2b66fee334dea\".limits]\nhalt_if_over_pct = 0", "halt_if_over_pct"),
            ("[community.\"fe4abeb3fd227a67fc59d8a4363420649bb970436dc3b14d51c2b66fee334dea\".raid]\ntripwire_accounts = 1", "tripwire_accounts"),
        ];
        for (toml_text, expect) in cases {
            let cfg: Config = toml::from_str(toml_text).unwrap();
            let err = cfg.validate().expect_err(toml_text);
            assert!(err.contains(expect), "{toml_text}\n-> {err}");
        }
    }

    #[test]
    fn loopback_is_recognised_and_everything_else_needs_saying_so() {
        let local = |url: &str| VisionCfg { base_url: url.into(), ..Default::default() }.is_local();
        assert!(local("http://127.0.0.1:8080/v1"));
        assert!(local("http://localhost:8080/v1"));
        assert!(local("http://[::1]:8080/v1"));
        assert!(!local("https://api.openai.com/v1"));
        assert!(!local("http://192.168.1.50:8080/v1"), "a LAN box is still somebody else's machine");
        assert!(!local("http://127.0.0.1:8080@evil.com/v1"), "userinfo must not pass for a host");
        assert!(!local("http://127.0.0.1.evil.com/v1"), "a prefix is not the host");
        assert!(local("http://LOCALHOST:8080/v1"), "case is not identity");
    }

    #[test]
    fn gravity_falls_back_to_the_engines_severity() {
        assert_eq!(Gravity::from_severity("notice"), Gravity::Note);
        assert_eq!(Gravity::from_severity("major"), Gravity::Serious);
        assert_eq!(Gravity::from_severity("severe"), Gravity::Grave);
        assert_eq!(Gravity::from_severity(""), Gravity::Note, "an unknown severity must be the LEAST punitive");
        assert_eq!(Gravity::from_severity("catastrophic"), Gravity::Note);
        // An unnamed rule defers to the engine's severity, resolved per
        // community — see policy::CommunityPolicy::gravity_of.
        let p = Config::default().for_community("fe4abeb3fd227a67fc59d8a4363420649bb970436dc3b14d51c2b66fee334dea");
        assert_eq!(p.gravity_of("nonexistent", "severe"), Gravity::Grave);
        assert_eq!(p.gravity_of("nonexistent", "nonsense"), Gravity::Note);
    }
}

#[cfg(test)]
mod unknown_key_tests {
    use super::*;

    /// One slot per community is held from before the download until the model
    /// answers, so at `concurrent = 1` a second image posted in the same second
    /// waits out the entire first inference. On a large local model that is tens
    /// of seconds of apparent silence, which is what it was reported as: "the
    /// NSFW one didn't process". It had not been dropped, only queued.
    #[test]
    fn media_concurrency_is_the_operators_to_raise() {
        let one = toml::from_str::<Config>("[vision]\nenabled = true").unwrap();
        assert_eq!(one.vision.concurrent, 1, "one at a time by default — each slot is another resident blob");

        let many = toml::from_str::<Config>("[vision]\nenabled = true\nconcurrent = 4").unwrap();
        assert_eq!(many.vision.concurrent, 4);

        // Zero would wedge the lane forever rather than pausing it, so the
        // semaphore floors it. A community with vision off says so with
        // `enabled`, never by setting the width to nothing.
        let zero = toml::from_str::<Config>("[vision]\nenabled = true\nconcurrent = 0").unwrap();
        let b = crate::lanes::Budget::new(zero.vision.max_per_min, zero.vision.concurrent);
        assert_eq!(b.slot.available_permits(), 1, "0 must floor to 1, never deadlock the lane");
        assert!(
            b.fetch.available_permits() > 1,
            "downloads run in parallel regardless: they are network-bound, and making them wait              behind an inference is what made a post look ignored"
        );
    }

    /// The media lane is the expensive one and the only one that decrypts an
    /// attachment and ships it to a model, so a bot watching `["*"]` must not
    /// run it everywhere it was invited. Text rules and raid containment stay
    /// free for everyone; this is the one thing an operator hands out by name.
    #[test]
    fn the_media_lane_runs_only_where_the_operator_named_it() {
        const A: &str = "aaaa000000000000000000000000000000000000000000000000000000000000";
        const B: &str = "bbbb000000000000000000000000000000000000000000000000000000000000";
        let parse = |t: &str| toml::from_str::<Config>(t).unwrap();

        // No list at all: every watched community, which is what a single-tenant
        // bot has always had and must keep.
        let all = parse("[vision]\nenabled = true");
        assert!(all.vision_enabled_for(A) && all.vision_enabled_for(B));

        // A list names who gets it, and by omission who does not.
        let named = parse(&format!("[vision]\nenabled = true\ncommunities = [\"{A}\"]"));
        assert!(named.vision_enabled_for(A), "named");
        assert!(!named.vision_enabled_for(B), "a community nobody named gets no media lane");

        // The master switch is still master.
        let off = parse(&format!("[vision]\nenabled = false\ncommunities = [\"{A}\"]"));
        assert!(!off.vision_enabled_for(A), "no model configured, no media lane anywhere");

        // The narrower answer wins: switching one room off must not require
        // editing the allowlist as well.
        let vetoed = parse(&format!(
            "[vision]\nenabled = true\ncommunities = [\"{A}\"]\n[community.\"{A}\".vision]\nenabled = false"
        ));
        assert!(!vetoed.vision_enabled_for(A), "the community's own block overrides the list");

        // And it can grant, too — an operator can enable one room without a list.
        let granted = parse(&format!(
            "[vision]\nenabled = true\ncommunities = []\n[community.\"{B}\".vision]\nenabled = true"
        ));
        assert!(granted.vision_enabled_for(B), "named directly");
        assert!(!granted.vision_enabled_for(A), "an empty list is not a wildcard");
    }

    /// The gate above is only worth anything if the lane asks it. This morning's
    /// bug in this same codebase was a correct function with no caller, reporting
    /// itself as clean the whole time — so the call site is pinned from source
    /// rather than trusted.
    #[test]
    fn the_media_lane_actually_asks_the_gate() {
        let src = include_str!("lanes.rs");
        let at = src.find("vision_enabled_for").expect("the media lane must consult the per-community gate");
        // And it must ask BEFORE anything is fetched: the whole point is that an
        // unnamed community's media is never decrypted, downloaded or uploaded.
        // Anchored on the candidate loop, which covers linked media as well as
        // attachments — a bypass that reached only one of the two would be the
        // same hole in a new place.
        let fetches = src.find("for cand in &cands").expect("media loop");
        assert!(at < fetches, "the gate must be asked before any media is touched");
        // The CALL SITE, not the definition — which sits above the gate and would
        // pass this trivially.
        let links = src.find("linked_media(&msg.message.content").expect("link extraction call");
        assert!(at < links, "and before a linked URL is even extracted");
    }

    /// The shipped example documented `arm.vision`, which no struct has and
    /// nothing in the crate reads. Serde dropped it, validation passed, and the
    /// media lane went on judging that community — an operator following the
    /// example believed they had turned it off.
    #[test]
    fn a_key_sentinel_does_not_know_is_a_boot_error() {
        for (text, key) in [
            ("[arm]\nwarn = true\nvision = false", "vision"),
            ("[limits]\nhalt_if_over_pc = 50", "halt_if_over_pc"),
            ("[ladder]\ndecay_half_life_hour = 72", "decay_half_life_hour"),
            ("[community.\"fe4abeb3fd227a67fc59d8a4363420649bb970436dc3b14d51c2b66fee334dea\".arm]\nraids = true", "raids"),
            // `community.*.vision.enabled` is REAL now (the operator picks which
            // communities get the media lane), so the typo case moved inside it.
            ("[community.\"fe4abeb3fd227a67fc59d8a4363420649bb970436dc3b14d51c2b66fee334dea\".vision]\nenable = false", "enable"),
            ("[rules]\nwindow_hour = 72", "window_hour"),
        ] {
            let err = toml::from_str::<Config>(text).unwrap_err().to_string();
            assert!(err.contains(key), "a typo must name itself, got: {err}");
        }
    }

    /// Values that parse, validate today, and then make the thing they
    /// configure structurally unable to do its job.
    /// Report mode touches nobody, so "show me everyone" is a real thing to
    /// ask for — the confidence floor is about what may be ACTED on.
    #[test]
    fn a_low_bar_is_allowed_when_nobody_is_touched() {
        // Rehearsing: nothing is armed, so nobody is contained whatever the bar.
        let rehearsing: Config = toml::from_str("[raid]\nmin_confidence = 0\nresponse = \"kick\"").unwrap();
        Config::validate_for_test(&rehearsing).expect("a dry run may look at everyone");

        // Armed to report: still nobody.
        let reporting: Config =
            toml::from_str("[arm]\nraid = true\n[raid]\nmin_confidence = 0\nresponse = \"report\"").unwrap();
        Config::validate_for_test(&reporting).expect("report mode may look at everyone");

        // Armed to remove: the bar is what stands between evidence and a ban.
        let kicking: Config =
            toml::from_str("[arm]\nraid = true\n[raid]\nmin_confidence = 0\nresponse = \"kick\"").unwrap();
        assert!(Config::validate_for_test(&kicking).is_err(), "removal answers to the floor");
    }

    /// The bottom-up refusal used to reject this, on the premise that an
    /// unarmed rung is never answered. A rehearsal records, so it is — the
    /// ladder climbs past the rehearsed warning and delivers the kick.
    #[test]
    fn arming_a_harsher_class_than_a_gentler_one_is_a_real_configuration() {
        for text in [
            "[arm]\nwarn = false\nkick = true",
            "[arm]\nwarn = true\ndelete = false\nban = true",
            "[arm]\nban = true",
        ] {
            let cfg: Config = toml::from_str(text).unwrap();
            Config::validate_for_test(&cfg).unwrap_or_else(|e| panic!("{text:?} must boot: {e}"));
        }
    }

    #[test]
    fn a_config_that_can_only_fail_is_refused_at_boot() {
        let label = "[[vision.labels]]\nname = \"gore\"\nthreshold = 0.9\ngravity = \"grave\"";
        let cases: &[(String, &str)] = &[
            (format!("[vision]\nenabled = true\nmimes = []\n{label}"), "mimes"),
            (format!("[vision]\nenabled = true\nmax_bytes = 0\n{label}"), "max_bytes"),
            (format!("[vision]\nenabled = true\nmax_per_min = 0\n{label}"), "max_per_min"),
            (format!("[vision]\nenabled = true\ntimeout_secs = 0\n{label}"), "timeout_secs"),
            (format!("[vision]\nenabled = true\nmodel = \"\"\n{label}"), "model"),
            (format!("[vision]\nenabled = true\nmimes = [\"image/avif\"]\n{label}"), "cannot be recognised"),
            (format!("[vision]\nenabled = true\nmimes = [\"image/heic\"]\n{label}"), "cannot be recognised"),
            (
                format!("[vision]\nenabled = true\nbase_url = \"127.0.0.1:8080/v1\"\nallow_remote = true\n{label}"),
                "no scheme",
            ),
            (format!("[vision]\nenabled = true\n{label}\n{label}"), "listed twice"),
            ("[arm]\nraid = true\n[raid]\nmin_confidence = 0\nresponse = \"kick\"".into(), "min_confidence"),
            ("[raid]\ntripwire_cooldown_secs = 0".into(), "tripwire_cooldown_secs"),
            ("[ladder]\ndecay_half_life_hours = 90000".into(), "decay_half_life_hours"),
            ("[ladder]\nstrikes = { note = 0, minor = 0, serious = 0, grave = 0 }".into(), "grave = 0"),
            ("[[rules.words]]\nid = \"x\"\npatterns = [\"\"]\ngravity = \"minor\"".into(), "matches nothing"),
            ("[[rules.words]]\nid = \"x\"\npatterns = [\"**\"]\ngravity = \"minor\"".into(), "matches nothing"),
            ("[[rules.words]]\nid = \"x\"\npatterns = [\"***\"]\ngravity = \"minor\"".into(), "matches nothing"),
            ("[[rules.links]]\nid = \"x\"\ndomains = [\"\"]\ngravity = \"minor\"".into(), "matches nothing"),
        ];
        for (text, needle) in cases {
            let cfg: Config = toml::from_str(text).unwrap_or_else(|e| panic!("{text:?} should parse: {e}"));
            match Config::validate_for_test(&cfg) {
                Ok(()) => panic!("{text:?} must be refused at boot"),
                Err(err) => assert!(err.contains(needle), "the error must name {needle}, got: {err}"),
            }
        }
    }

    /// The rulebook the ENGINE will take, not the one Sentinel can describe.
    /// These all installed as an error line per pass, beside a healthy
    /// heartbeat, with the community running no custom rulebook at all.
    #[test]
    fn a_rulebook_the_engine_refuses_is_refused_at_boot() {
        let cases: &[(&str, &str)] = &[
            ("[rules]\nwindow_hours = 2160\n[[rules.words]]\nid = \"a\"\npatterns = [\"x\"]\ngravity = \"minor\"", "engine refuses"),
            ("[rules]\nwindow_messages = 10000\n[[rules.words]]\nid = \"a\"\npatterns = [\"x\"]\ngravity = \"minor\"", "engine refuses"),
            ("[[rules.words]]\nid = \"dup\"\npatterns = [\"x\"]\ngravity = \"minor\"\n[[rules.words]]\nid = \"dup\"\npatterns = [\"y\"]\ngravity = \"minor\"", "engine refuses"),
            ("[[rules.words]]\nid = \"\"\npatterns = [\"x\"]\ngravity = \"minor\"", "engine refuses"),
        ];
        for (text, needle) in cases {
            let cfg: Config = toml::from_str(text).unwrap_or_else(|e| panic!("{text:?} should parse: {e}"));
            match Config::validate_for_test(&cfg) {
                Ok(()) => panic!("{text:?} must be refused at boot"),
                Err(e) => assert!(e.contains(needle), "the error must name {needle}, got: {e}"),
            }
        }
    }

    /// And every key the example file actually uses still parses.
    #[test]
    fn the_shipped_example_parses() {
        let text = std::fs::read_to_string("sentinel.example.toml").expect("the example ships with the crate");
        let cfg: Config = toml::from_str(&text).expect("the example Sentinel ships must load");
        Config::validate_for_test(&cfg).expect("and must validate");
    }

    /// The commented-out blocks are the part operators actually copy, and
    /// nothing checked them: the example documented an `arm.vision` key that no
    /// struct has and nothing reads, so following it turned nothing off.
    /// Uncommenting the whole file must still produce a config Sentinel accepts.
    #[test]
    fn every_commented_example_is_real_config() {
        let text = std::fs::read_to_string("sentinel.example.toml").expect("the example ships with the crate");
        let uncommented: String = text
            .lines()
            .map(|l| {
                let body = l.trim_start().strip_prefix("# ").unwrap_or(l);
                let looks_like_config = body.starts_with('[')
                    || body.split('=').next().is_some_and(|k| {
                        !k.is_empty() && k.trim().chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    }) && body.contains('=');
                if looks_like_config { body } else { "" }
            })
            .collect::<Vec<_>>()
            .join("\n");

        let cfg: Config = toml::from_str(&uncommented)
            .unwrap_or_else(|e| panic!("a commented example is not valid config: {e}"));
        Config::validate_for_test(&cfg).expect("and the example must describe a config that validates");
    }
}
