//! One community's rules, thresholds and powers.
//!
//! Sentinel is invited into communities it does not own, whose standards differ
//! and whose operators trust it with different amounts. Nothing about how it
//! judges one community may leak into another: separate rulebooks, separate
//! ladders, separate arming, separate tripwires, separate strike history.
//!
//! And separate POWERS. Being a member is not being a moderator. A community
//! can hand Sentinel MANAGE_MESSAGES and withhold BAN, and a sentence it cannot
//! carry out is reported as such rather than attempted and silently dropped.

use serde::Deserialize;

use crate::config::{Arm, Config, Gravity, Ladder, Limits, Raid, Rules, Shields};

/// Everything needed to judge ONE community, with the operator's per-community
/// overrides already folded over the defaults.
#[derive(Debug, Clone)]
pub struct CommunityPolicy {
    pub arm: Arm,
    pub limits: Limits,
    pub rules: Rules,
    pub ladder: Ladder,
    pub shields: Shields,
    pub raid: Raid,
}

/// A per-community override block. Every field is optional and falls back to
/// the top-level default, so an operator names only what differs.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Overrides {
    pub arm: Option<ArmOverride>,
    pub limits: Option<LimitsOverride>,
    pub rules: Option<RulesOverride>,
    pub ladder: Option<LadderOverride>,
    pub shields: Option<ShieldsOverride>,
    pub raid: Option<RaidOverride>,
}

/// Overrides fold FIELD by field. A whole-block override reset everything the
/// operator had customised globally back to library defaults — naming one
/// tighter limit silently loosened the other two.
#[derive(Debug, Clone, Copy, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ArmOverride {
    pub warn: Option<bool>,
    pub delete: Option<bool>,
    pub kick: Option<bool>,
    pub ban: Option<bool>,
    pub raid: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct RulesOverride {
    pub window_hours: Option<u64>,
    pub window_messages: Option<usize>,
    pub raid_detection: Option<bool>,
    pub words: Option<Vec<crate::config::WordRule>>,
    pub links: Option<Vec<crate::config::LinkRule>>,
    pub rate: Option<crate::config::RateRule>,
    pub mass_tagging: Option<crate::config::ToggleRule>,
    pub repetition: Option<crate::config::ToggleRule>,
}

#[derive(Debug, Clone, Copy, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsOverride {
    pub max_actions_per_run: Option<usize>,
    pub max_actions_per_hour: Option<usize>,
    pub halt_if_over_pct: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct LadderOverride {
    pub strikes: Option<StrikesOverride>,
    pub decay_half_life_hours: Option<u64>,
    pub steps: Option<Vec<crate::config::Step>>,
}

/// Per FIELD, like every other override block.
///
/// A whole-struct swap looked like it worked: `Strikes` carries `#[serde(default)]`,
/// so `strikes = { grave = 60 }` deserialized fine and silently reset note,
/// minor and serious to the library defaults — an override that only tightened
/// producing a loosening the validator cannot see, since the result still
/// ascends.
#[derive(Debug, Clone, Copy, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct StrikesOverride {
    pub note: Option<u32>,
    pub minor: Option<u32>,
    pub serious: Option<u32>,
    pub grave: Option<u32>,
}

impl StrikesOverride {
    fn fold_into(&self, s: &mut crate::config::Strikes) {
        s.note = self.note.unwrap_or(s.note);
        s.minor = self.minor.unwrap_or(s.minor);
        s.serious = self.serious.unwrap_or(s.serious);
        s.grave = self.grave.unwrap_or(s.grave);
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ShieldsOverride {
    pub respect_trusted: Option<bool>,
    pub respect_protected: Option<bool>,
}

#[derive(Debug, Clone, Copy, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct RaidOverride {
    pub min_confidence: Option<u32>,
    pub response: Option<crate::config::RaidResponse>,
    pub tripwire_accounts: Option<usize>,
    pub tripwire_secs: Option<u64>,
    pub tripwire_cooldown_secs: Option<u64>,
    pub claim_ttl_secs: Option<u64>,
    pub max_batch: Option<usize>,
}

impl Config {
    /// This community's rulebook: the defaults, with its overrides folded over.
    pub fn for_community(&self, id: &str) -> CommunityPolicy {
        let o = self.community.get(id);
        let mut p = CommunityPolicy {
            arm: self.arm,
            limits: self.limits,
            rules: self.rules.clone(),
            ladder: self.ladder.clone(),
            shields: self.shields,
            raid: self.raid,
        };
        let Some(o) = o else { return p };
        if let Some(a) = &o.arm {
            let f = |over: Option<bool>, base: bool| over.unwrap_or(base);
            p.arm = Arm {
                warn: f(a.warn, p.arm.warn),
                delete: f(a.delete, p.arm.delete),
                kick: f(a.kick, p.arm.kick),
                ban: f(a.ban, p.arm.ban),
                raid: f(a.raid, p.arm.raid),
            };
        }
        if let Some(l) = &o.limits {
            p.limits.max_actions_per_run = l.max_actions_per_run.unwrap_or(p.limits.max_actions_per_run);
            p.limits.max_actions_per_hour = l.max_actions_per_hour.unwrap_or(p.limits.max_actions_per_hour);
            p.limits.halt_if_over_pct = l.halt_if_over_pct.unwrap_or(p.limits.halt_if_over_pct);
        }
        if let Some(l) = &o.ladder {
            if let Some(o) = &l.strikes {
                o.fold_into(&mut p.ladder.strikes);
            }
            p.ladder.decay_half_life_hours = l.decay_half_life_hours.unwrap_or(p.ladder.decay_half_life_hours);
            if let Some(steps) = &l.steps {
                p.ladder.steps = steps.clone();
            }
        }
        if let Some(sh) = &o.shields {
            p.shields.respect_trusted = sh.respect_trusted.unwrap_or(p.shields.respect_trusted);
            p.shields.respect_protected = sh.respect_protected.unwrap_or(p.shields.respect_protected);
        }
        if let Some(r) = &o.rules {
            p.rules.window_hours = r.window_hours.unwrap_or(p.rules.window_hours);
            p.rules.window_messages = r.window_messages.unwrap_or(p.rules.window_messages);
            // The loosening one: a whole-block override restored
            // `raid_detection = true` for an operator who had turned it off.
            p.rules.raid_detection = r.raid_detection.unwrap_or(p.rules.raid_detection);
            if let Some(w) = &r.words {
                p.rules.words = w.clone();
            }
            if let Some(l) = &r.links {
                p.rules.links = l.clone();
            }
            if r.rate.is_some() {
                p.rules.rate = r.rate.clone();
            }
            if r.mass_tagging.is_some() {
                p.rules.mass_tagging = r.mass_tagging;
            }
            if r.repetition.is_some() {
                p.rules.repetition = r.repetition;
            }
        }
        if let Some(r) = &o.raid {
            p.raid.min_confidence = r.min_confidence.unwrap_or(p.raid.min_confidence);
            p.raid.response = r.response.unwrap_or(p.raid.response);
            p.raid.tripwire_accounts = r.tripwire_accounts.unwrap_or(p.raid.tripwire_accounts);
            p.raid.tripwire_secs = r.tripwire_secs.unwrap_or(p.raid.tripwire_secs);
            p.raid.tripwire_cooldown_secs = r.tripwire_cooldown_secs.unwrap_or(p.raid.tripwire_cooldown_secs);
            p.raid.claim_ttl_secs = r.claim_ttl_secs.unwrap_or(p.raid.claim_ttl_secs);
            p.raid.max_batch = r.max_batch.unwrap_or(p.raid.max_batch);
        }
        p
    }
}

impl CommunityPolicy {
    /// What is armed HERE, for a log line or an operator's question.
    ///
    /// Resolved per community, always. Reading the top-level block answered
    /// "nothing (dry run)" in a community armed to ban — at boot, which is the
    /// one place an operator looks before walking away.
    pub fn armed_line(&self) -> String {
        let armed: Vec<&str> = [
            (self.arm.warn, "warn"),
            (self.arm.delete, "delete"),
            (self.arm.kick, "kick"),
            (self.arm.ban, "ban"),
            (self.arm.raid, "raid"),
        ]
        .iter()
        .filter_map(|(on, name)| on.then_some(*name))
        .collect();
        if armed.is_empty() {
            "nothing (dry run)".into()
        } else {
            armed.join(", ")
        }
    }

    /// The gravity this community assigns a rule, or the engine severity as a
    /// fallback when its operator never named one.
    pub fn gravity_of(&self, rule_id: &str, severity: &str) -> Gravity {
        if let Some(w) = self.rules.words.iter().find(|w| w.id == rule_id) {
            return w.gravity;
        }
        if let Some(l) = self.rules.links.iter().find(|l| l.id == rule_id) {
            return l.gravity;
        }
        match rule_id {
            "rate" => self.rules.rate.as_ref().map(|r| r.gravity),
            "mass-tagging" => self.rules.mass_tagging.map(|r| r.gravity),
            "repetition" => self.rules.repetition.map(|r| r.gravity),
            _ => None,
        }
        .unwrap_or_else(|| Gravity::from_severity(severity))
    }
}

/// What this community actually permits Sentinel to do. Read from its
/// capabilities, not assumed from membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Powers {
    pub hide: bool,
    pub kick: bool,
    pub ban: bool,
}

impl Powers {
    /// Read from a community's reported capabilities. Absent keys are `false`:
    /// a permission Sentinel cannot confirm is one it does not have.
    pub fn from_capabilities(caps: &serde_json::Value) -> Powers {
        Powers {
            hide: caps["manage_messages"].as_bool().unwrap_or(false),
            kick: caps["kick"].as_bool().unwrap_or(false),
            ban: caps["ban"].as_bool().unwrap_or(false),
        }
    }

    /// Can this community's grant deliver that rung? A warning is a DM and
    /// needs nothing from the community.
    pub fn can_deliver(&self, r: crate::config::Response) -> bool {
        match r {
            crate::config::Response::Warn => true,
            crate::config::Response::DeleteAndWarn => self.hide,
            crate::config::Response::Kick => self.kick,
            crate::config::Response::Ban => self.ban,
        }
    }

    /// One line for the boot log, so an operator sees what Sentinel can and
    /// cannot do somewhere before it matters.
    pub fn describe(&self) -> String {
        let mut have: Vec<&str> = Vec::new();
        for (on, name) in [(self.hide, "hide"), (self.kick, "kick"), (self.ban, "ban")] {
            if on {
                have.push(name);
            }
        }
        if have.is_empty() {
            "no moderation powers — reports only".into()
        } else {
            format!("can {}", have.join(", "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_community_without_an_override_gets_the_defaults() {
        let cfg = Config::default();
        let p = cfg.for_community("fe4abeb3fd227a67fc59d8a4363420649bb970436dc3b14d51c2b66fee334dea");
        assert_eq!(p.ladder.steps.len(), cfg.ladder.steps.len());
        assert!(!p.arm.kick);
    }

    /// The point of the whole module: one community's harshness must not reach
    /// another's members.
    #[test]
    fn an_override_applies_to_its_community_and_nowhere_else() {
        let cfg: Config = toml::from_str(
            r#"
            [community."strict".arm]
            kick = true
            [community."strict".raid]
            min_confidence = 50
            "#,
        )
        .unwrap();

        let strict = cfg.for_community("strict");
        assert!(strict.arm.kick, "the override arms this community");
        assert_eq!(strict.raid.min_confidence, 50);

        let other = cfg.for_community("relaxed");
        assert!(!other.arm.kick, "and arms nobody else");
        assert_eq!(other.raid.min_confidence, 75, "defaults are untouched next door");
    }

    /// A partial block must not reset the operator's other choices. Naming one
    /// tighter limit used to restore the library defaults for the rest.
    #[test]
    fn an_override_folds_field_by_field() {
        let cfg: Config = toml::from_str(
            r#"
            [limits]
            max_actions_per_run = 5
            max_actions_per_hour = 10
            halt_if_over_pct = 50
            [community."fe4abeb3fd227a67fc59d8a4363420649bb970436dc3b14d51c2b66fee334dea".limits]
            halt_if_over_pct = 20
            [community."fe4abeb3fd227a67fc59d8a4363420649bb970436dc3b14d51c2b66fee334dea".raid]
            response = "ban"
            "#,
        )
        .unwrap();
        let p = cfg.for_community("fe4abeb3fd227a67fc59d8a4363420649bb970436dc3b14d51c2b66fee334dea");
        assert_eq!(p.limits.halt_if_over_pct, 20, "the named field changes");
        assert_eq!(p.limits.max_actions_per_run, 5, "and the operator's others survive");
        assert_eq!(p.limits.max_actions_per_hour, 10);
        assert_eq!(p.raid.response, crate::config::RaidResponse::Ban);
        assert_eq!(p.raid.tripwire_accounts, 5, "untouched raid fields keep their defaults");
    }

    /// The loosening case: naming one rule for a community used to restore
    /// `raid_detection = true` for an operator who had turned it off globally.
    #[test]
    fn a_rules_override_keeps_the_settings_it_does_not_name() {
        let cfg: Config = toml::from_str(
            r#"
            [rules]
            window_hours = 720
            raid_detection = false
            [[community."fe4abeb3fd227a67fc59d8a4363420649bb970436dc3b14d51c2b66fee334dea".rules.words]]
            id = "theirs"
            patterns = ["blast"]
            gravity = "note"
            "#,
        )
        .unwrap();
        let p = cfg.for_community("fe4abeb3fd227a67fc59d8a4363420649bb970436dc3b14d51c2b66fee334dea");
        assert_eq!(p.rules.words.len(), 1, "their own words");
        assert_eq!(p.rules.window_hours, 720, "and the operator's window");
        assert!(!p.rules.raid_detection, "and their decision to turn raid detection off");
    }

    #[test]
    fn a_permission_that_cannot_be_confirmed_is_one_sentinel_does_not_have() {
        let none = Powers::from_capabilities(&serde_json::json!({}));
        assert_eq!(none, Powers::default());
        assert_eq!(none.describe(), "no moderation powers — reports only");

        let partial = Powers::from_capabilities(&serde_json::json!({ "manage_messages": true, "kick": true }));
        assert!(partial.hide && partial.kick && !partial.ban, "withholding BAN is a normal thing to do");
        assert_eq!(partial.describe(), "can hide, kick");
    }

    /// The shape that made this a per-field block: `strikes = { grave = 60 }`
    /// deserialized fine and silently cut the other three to the library
    /// defaults — a loosening from an override that only tightened, and one
    /// the validator cannot catch because 1 <= 2 <= 4 <= 60 still ascends.
    #[test]
    fn a_partial_strikes_override_keeps_the_rest_of_the_operators_scale() {
        let cfg: crate::config::Config = toml::from_str(
            r#"
[ladder]
strikes = { note = 4, minor = 8, serious = 16, grave = 48 }

[community."fe4abeb3fd227a67fc59d8a4363420649bb970436dc3b14d51c2b66fee334dea".ladder]
strikes = { grave = 60 }
"#,
        )
        .unwrap();

        let base = cfg.for_community("");
        assert_eq!((base.ladder.strikes.note, base.ladder.strikes.grave), (4, 48));

        let folded = cfg.for_community("fe4abeb3fd227a67fc59d8a4363420649bb970436dc3b14d51c2b66fee334dea").ladder.strikes;
        assert_eq!(folded.grave, 60, "the field the override named");
        assert_eq!(folded.note, 4, "and not one it did not");
        assert_eq!(folded.minor, 8);
        assert_eq!(folded.serious, 16);
    }

    /// An override may loosen as well as tighten.
    #[test]
    fn a_strikes_override_can_lower_a_worth_too() {
        let cfg: crate::config::Config = toml::from_str(
            "[ladder]\nstrikes = { note = 4, minor = 8, serious = 16, grave = 48 }\n\n[community.\"fe4abeb3fd227a67fc59d8a4363420649bb970436dc3b14d51c2b66fee334dea\".ladder]\nstrikes = { note = 1 }",
        )
        .unwrap();
        assert_eq!(cfg.for_community("fe4abeb3fd227a67fc59d8a4363420649bb970436dc3b14d51c2b66fee334dea").ladder.strikes.note, 1);
    }
}
