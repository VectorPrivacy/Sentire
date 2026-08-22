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
#[serde(default)]
pub struct Overrides {
    pub arm: Option<Arm>,
    pub limits: Option<Limits>,
    pub rules: Option<Rules>,
    pub ladder: Option<Ladder>,
    pub shields: Option<Shields>,
    pub raid: Option<Raid>,
}

impl Config {
    /// This community's rulebook: the defaults, with its overrides folded over.
    pub fn for_community(&self, id: &str) -> CommunityPolicy {
        let o = self.community.get(id);
        CommunityPolicy {
            arm: o.and_then(|o| o.arm).unwrap_or(self.arm),
            limits: o.and_then(|o| o.limits).unwrap_or(self.limits),
            rules: o.and_then(|o| o.rules.clone()).unwrap_or_else(|| self.rules.clone()),
            ladder: o.and_then(|o| o.ladder.clone()).unwrap_or_else(|| self.ladder.clone()),
            shields: o.and_then(|o| o.shields).unwrap_or(self.shields),
            raid: o.and_then(|o| o.raid).unwrap_or(self.raid),
        }
    }
}

impl CommunityPolicy {
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
        let p = cfg.for_community("aa");
        assert_eq!(p.ladder.steps.len(), cfg.ladder.steps.len());
        assert!(!p.arm.kick);
    }

    /// The point of the whole module: one community's harshness must not reach
    /// another's members.
    #[test]
    fn an_override_applies_to_its_community_and_nowhere_else() {
        let cfg: Config = toml::from_str(
            r#"
            [community."strict"]
            arm = { warn = true, delete = false, kick = true, ban = false, raid = false, vision = false }
            [community."strict".raid]
            min_confidence = 50
            response = "ban"
            tripwire_accounts = 3
            tripwire_secs = 30
            tripwire_cooldown_secs = 60
            max_batch = 100
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

    #[test]
    fn a_permission_that_cannot_be_confirmed_is_one_sentinel_does_not_have() {
        let none = Powers::from_capabilities(&serde_json::json!({}));
        assert_eq!(none, Powers::default());
        assert_eq!(none.describe(), "no moderation powers — reports only");

        let partial = Powers::from_capabilities(&serde_json::json!({ "manage_messages": true, "kick": true }));
        assert!(partial.hide && partial.kick && !partial.ban, "withholding BAN is a normal thing to do");
        assert_eq!(partial.describe(), "can hide, kick");
    }
}
