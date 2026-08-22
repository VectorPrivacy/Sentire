//! The operator's file. Everything tunable lives here: lenience, thresholds,
//! and the engine rules Sentinel runs.
//!
//! Validation is part of boot, not part of the first incident: a ladder whose
//! steps do not ascend, a gravity ordering that punishes a note harder than a
//! grave offense, or an unshielded-protected config refuses to start and names
//! the field.

use serde::Deserialize;

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
#[derive(Debug, Clone, Copy, Deserialize, Default)]
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

#[derive(Debug, Clone, Copy, Deserialize)]
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

    /// The rank of a stored response name. `None` maps to 0 — an unrecognised
    /// row is not a prior action, which is the safe reading in both directions.
    pub fn rank_of(name: &str) -> u8 {
        match name {
            "warn" => Response::Warn.rank(),
            "delete_and_warn" => Response::DeleteAndWarn.rank(),
            "kick" => Response::Kick.rank(),
            "ban" => Response::Ban.rank(),
            _ => 0,
        }
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

impl Default for Raid {
    fn default() -> Self {
        Raid {
            min_confidence: 75,
            response: RaidResponse::Kick,
            tripwire_accounts: 5,
            tripwire_secs: 30,
            tripwire_cooldown_secs: 60,
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
        if !self.shields.respect_protected {
            return Err("shields.respect_protected = false: refusing to start. \
                        The owner and moderators are never Sentinel's to judge."
                .into());
        }
        let s = &self.ladder.strikes;
        if !(s.note <= s.minor && s.minor <= s.serious && s.serious <= s.grave) {
            return Err(format!(
                "ladder.strikes must not punish a lesser gravity harder: note {} <= minor {} <= serious {} <= grave {}",
                s.note, s.minor, s.serious, s.grave
            ));
        }
        if self.ladder.steps.is_empty() {
            return Err("ladder.steps is empty: with no steps, no strike total ever answers to anything".into());
        }
        if self.ladder.steps[0].at == 0 {
            return Err("ladder.steps starts at 0: that answers a total of zero, so every member is sentenced on sight".into());
        }
        let worths = [s.note, s.minor, s.serious, s.grave];
        if worths.iter().any(|w| *w > 10_000) {
            return Err("ladder.strikes over 10000: totals are summed, and absurd worths overflow rather than escalate".into());
        }
        for w in self.ladder.steps.windows(2) {
            if w[1].at <= w[0].at {
                return Err(format!("ladder.steps must ascend: step at {} follows step at {}", w[1].at, w[0].at));
            }
            if w[1].response < w[0].response {
                return Err(format!(
                    "ladder.steps must not de-escalate: {:?} at {} follows {:?} at {}",
                    w[1].response, w[1].at, w[0].response, w[0].at
                ));
            }
        }
        if self.raid.min_confidence > 99 {
            return Err(format!(
                "raid.min_confidence = {}: confidence never reaches 100 by construction, so nothing would ever be contained",
                self.raid.min_confidence
            ));
        }
        if self.raid.tripwire_accounts < 2 {
            return Err("raid.tripwire_accounts must be at least 2: one member talking is a conversation".into());
        }
        if self.raid.max_batch == 0 || self.raid.max_batch > 500 {
            return Err(format!("raid.max_batch = {}: must be 1..=500 (the wire rejects an over-cap banlist whole)", self.raid.max_batch));
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
                    "vision.base_url {} is not loopback and vision.allow_remote is false.                      An attachment is end-to-end encrypted until Sentinel decrypts it and posts it                      to that host; say so on purpose or keep the model local.",
                    self.vision.base_url
                ));
            }
        }
        if self.ladder.decay_half_life_hours == 0 {
            return Err("ladder.decay_half_life_hours = 0: strikes would vanish instantly".into());
        }
        for r in &self.rules.words {
            if r.patterns.is_empty() {
                return Err(format!("rules.words '{}' has no patterns", r.id));
            }
        }
        for r in &self.rules.links {
            if r.domains.is_empty() {
                return Err(format!("rules.links '{}' has no domains", r.id));
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

    /// The gravity the operator assigned to a rule, if they named one.
    pub fn gravity_of(&self, rule_id: &str) -> Option<Gravity> {
        if let Some(w) = self.rules.words.iter().find(|w| w.id == rule_id) {
            return Some(w.gravity);
        }
        if let Some(l) = self.rules.links.iter().find(|l| l.id == rule_id) {
            return Some(l.gravity);
        }
        match rule_id {
            "rate" => self.rules.rate.as_ref().map(|r| r.gravity),
            "mass-tagging" => self.rules.mass_tagging.map(|r| r.gravity),
            "repetition" => self.rules.repetition.map(|r| r.gravity),
            _ => None,
        }
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
            ("[ladder]\nstrikes = { note = 5, minor = 2, serious = 4, grave = 12 }", "strikes"),
            ("[[ladder.steps]]\nat = 4\nresponse = \"warn\"\n[[ladder.steps]]\nat = 1\nresponse = \"kick\"", "ascend"),
            ("[[ladder.steps]]\nat = 1\nresponse = \"kick\"\n[[ladder.steps]]\nat = 4\nresponse = \"warn\"", "de-escalate"),
            ("[ladder]\ndecay_half_life_hours = 0", "decay_half_life_hours"),
            ("[raid]\nmin_confidence = 100", "min_confidence"),
            ("[raid]\nmax_batch = 0", "max_batch"),
            ("[raid]\nmax_batch = 900", "max_batch"),
            ("[raid]\ntripwire_accounts = 1", "tripwire_accounts"),
            ("[[ladder.steps]]\nat = 0\nresponse = \"ban\"", "sentenced on sight"),
            ("[ladder]\nstrikes = { note = 1, minor = 2, serious = 4, grave = 999999 }", "overflow"),
            ("[vision]\nenabled = true\n[[vision.labels]]\nname = \"g\"\nthreshold = 0.0\ngravity = \"grave\"", "greater than 0.0"),
            ("[vision]\nenabled = true", "vision.labels"),
            ("[vision]\nenabled = true\nbase_url = \"https://api.example.com/v1\"\n[[vision.labels]]\nname = \"gore\"\nthreshold = 0.9\ngravity = \"grave\"", "allow_remote"),
            ("[vision]\nenabled = true\n[[vision.labels]]\nname = \"gore\"\nthreshold = 4.0\ngravity = \"grave\"", "threshold"),
            ("[[rules.words]]\nid = \"empty\"\npatterns = []\ngravity = \"note\"", "empty"),
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
        let cfg = Config::default();
        assert_eq!(cfg.gravity_of("nonexistent"), None, "unnamed rules defer to severity");
    }
}
