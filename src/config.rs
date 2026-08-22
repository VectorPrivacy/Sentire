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
    pub fn from_severity(severity: &str) -> Gravity {
        match severity {
            "notice" => Gravity::Note,
            "minor" => Gravity::Minor,
            "major" => Gravity::Serious,
            _ => Gravity::Grave,
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
    /// The built-in raid defaults keep running regardless; this exists so an
    /// operator can see the knob rather than wonder.
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
            ("[[rules.words]]\nid = \"empty\"\npatterns = []\ngravity = \"note\"", "empty"),
        ];
        for (toml_text, expect) in cases {
            let cfg: Config = toml::from_str(toml_text).unwrap();
            let err = cfg.validate().expect_err(toml_text);
            assert!(err.contains(expect), "{toml_text}\n-> {err}");
        }
    }

    #[test]
    fn gravity_falls_back_to_the_engines_severity() {
        assert_eq!(Gravity::from_severity("notice"), Gravity::Note);
        assert_eq!(Gravity::from_severity("major"), Gravity::Serious);
        assert_eq!(Gravity::from_severity("severe"), Gravity::Grave);
        let cfg = Config::default();
        assert_eq!(cfg.gravity_of("nonexistent"), None, "unnamed rules defer to severity");
    }
}
