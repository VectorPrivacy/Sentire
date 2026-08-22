//! The operator's file. Everything tunable lives here: lenience, thresholds,
//! and the engine rules Sentinel runs.
//!
//! Validation is part of boot, not part of the first incident: a ladder whose
//! steps do not ascend, a gravity ordering that punishes a note harder than a
//! grave offense, or an unshielded-protected config refuses to start and names
//! the field.

use serde::Deserialize;

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
    if [s.note, s.minor, s.serious, s.grave].iter().any(|w| *w > 10_000) {
        return at("ladder.strikes over 10000: totals are summed, and absurd worths overflow rather than escalate".into());
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
    if p.limits.halt_if_over_pct == 0 || p.limits.halt_if_over_pct > 100 {
        return at(format!(
            "limits.halt_if_over_pct = {} — must be 1..=100 (0 would mean 'never act', which is what [arm] is for)",
            p.limits.halt_if_over_pct
        ));
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
    if p.raid.max_batch == 0 || p.raid.max_batch > 500 {
        return at(format!(
            "raid.max_batch = {}: must be 1..=500 (the wire rejects an over-cap banlist whole)",
            p.raid.max_batch
        ));
    }
    if p.raid.tripwire_accounts < 2 {
        return at("raid.tripwire_accounts must be at least 2: one member talking is a conversation".into());
    }
    if p.raid.tripwire_secs == 0 || p.raid.tripwire_secs > 86_400 {
        return at("raid.tripwire_secs must be 1..=86400".into());
    }
    if p.raid.tripwire_cooldown_secs > 86_400 {
        return at("raid.tripwire_cooldown_secs must be at most 86400".into());
    }
    if p.raid.claim_ttl_secs == 0 || p.raid.claim_ttl_secs > 30 * 86_400 {
        return at("raid.claim_ttl_secs must be 1..=2592000 (0 would re-contain the same wave every sweep)".into());
    }
    for r in &p.rules.words {
        if r.patterns.is_empty() {
            return at(format!("rules.words '{}' has no patterns", r.id));
        }
    }
    for r in &p.rules.links {
        if r.domains.is_empty() {
            return at(format!("rules.links '{}' has no domains", r.id));
        }
    }
    Ok(())
}

/// Sentinel's own vocabulary for how bad something is. Deliberately NOT the
/// engine's `Severity`: severity is the policy author's judgement, gravity is
/// the operator's. The two map, they never silently merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
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

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub bot: Bot,
    pub arm: Arm,
    pub limits: Limits,
    pub rules: Rules,
    pub ladder: Ladder,
    pub shields: Shields,
    pub raid: Raid,
    pub vision: VisionCfg,
    /// Per-community overrides, keyed by community id. Anything absent falls
    /// back to the blocks above, so an operator names only what differs.
    pub community: std::collections::HashMap<String, crate::policy::Overrides>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
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
}

impl Default for Bot {
    fn default() -> Self {
        Bot { nsec_env: "SENTINEL_NSEC".into(), communities: vec!["*".into()], mod_channel: None, poll_secs: 120 }
    }
}

/// Every one defaults false. Dry-run is the resting state, and arming is a
/// choice made per action class — a bot that warns is not thereby a bot that
/// bans.
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(default)]
pub struct Arm {
    pub warn: bool,
    pub delete: bool,
    pub kick: bool,
    pub ban: bool,
    pub raid: bool,
    /// A vision model's opinion is inference, and inference gets its own
    /// switch. Riding the booleans an operator set for provable text rules
    /// would let a classifier ban on evidence nobody can replay.
    pub vision: bool,
}

impl Arm {
    /// A vision finding needs BOTH its class armed and the vision switch on.
    pub fn vision_ok(self, from_vision: bool) -> bool {
        !from_vision || self.vision
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(default)]
pub struct Limits {
    pub max_actions_per_run: usize,
    pub max_actions_per_hour: usize,
    /// Acting on more than this % of the roster in one pass = stop everything
    /// and page a human. A bug must not be able to empty a community.
    pub halt_if_over_pct: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_actions_per_run: 25, max_actions_per_hour: 100, halt_if_over_pct: 10 }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
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

#[derive(Debug, Clone, Deserialize)]
pub struct WordRule {
    pub id: String,
    pub patterns: Vec<String>,
    pub gravity: Gravity,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LinkRule {
    pub id: String,
    pub domains: Vec<String>,
    pub gravity: Gravity,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateRule {
    pub enabled: bool,
    pub per_secs: u64,
    pub gravity: Gravity,
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub struct ToggleRule {
    pub enabled: bool,
    pub gravity: Gravity,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Ladder {
    /// What one offense of each gravity is worth.
    pub strikes: Strikes,
    /// A strike is worth half after this long. Forgiveness is built in, not a
    /// pardon someone has to remember to issue.
    pub decay_half_life_hours: u64,
    pub steps: Vec<Step>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(default)]
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

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub struct Step {
    pub at: u32,
    pub response: Response,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
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
            steps: vec![
                Step { at: 1, response: Response::Warn },
                Step { at: 4, response: Response::DeleteAndWarn },
                Step { at: 8, response: Response::Kick },
                Step { at: 12, response: Response::Ban },
            ],
        }
    }
}

/// The media lane. Off by default: it ships bytes to a model, and that is a
/// decision an operator makes rather than inherits.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct VisionCfg {
    pub enabled: bool,
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
    pub mimes: Vec<String>,
    pub labels: Vec<VisionLabel>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VisionLabel {
    pub name: String,
    /// 0.0..=1.0. A label with no threshold would flag everything.
    pub threshold: f32,
    pub gravity: Gravity,
}

impl Default for VisionCfg {
    fn default() -> Self {
        VisionCfg {
            enabled: false,
            base_url: "http://127.0.0.1:8080/v1".into(),
            model: "llava".into(),
            api_key_env: String::new(),
            allow_remote: false,
            timeout_secs: 60,
            max_bytes: 8 * 1024 * 1024,
            max_per_min: 20,
            mimes: ["image/png", "image/jpeg", "image/webp", "image/gif"].iter().map(|s| s.to_string()).collect(),
            labels: vec![],
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
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(default)]
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
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
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(default)]
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
            ("[community.\"x\".shields]\nrespect_protected = false", "respect_protected"),
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
            ("[ladder]\nstrikes = { note = 1, minor = 2, serious = 4, grave = 999999 }", "overflow"),
            ("[vision]\nenabled = true\n[[vision.labels]]\nname = \"g\"\nthreshold = 0.0\ngravity = \"grave\"", "greater than 0.0"),
            ("[vision]\nenabled = true", "vision.labels"),
            ("[vision]\nenabled = true\nbase_url = \"https://api.example.com/v1\"\n[[vision.labels]]\nname = \"gore\"\nthreshold = 0.9\ngravity = \"grave\"", "allow_remote"),
            ("[vision]\nenabled = true\n[[vision.labels]]\nname = \"gore\"\nthreshold = 4.0\ngravity = \"grave\"", "threshold"),
            ("[[rules.words]]\nid = \"empty\"\npatterns = []\ngravity = \"note\"", "empty"),
            // An override must not reach what the defaults are refused.
            ("[community.\"x\".ladder]\nsteps = [{ at = 0, response = \"ban\" }]", "sentenced on sight"),
            ("[community.\"x\".ladder]\ndecay_half_life_hours = 0", "decay_half_life_hours"),
            ("[community.\"x\".raid]\nmax_batch = 0", "max_batch"),
            ("[community.\"x\".limits]\nhalt_if_over_pct = 0", "halt_if_over_pct"),
            ("[community.\"x\".raid]\ntripwire_accounts = 1", "tripwire_accounts"),
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
        let p = Config::default().for_community("aa");
        assert_eq!(p.gravity_of("nonexistent", "severe"), Gravity::Grave);
        assert_eq!(p.gravity_of("nonexistent", "nonsense"), Gravity::Note);
    }
}
