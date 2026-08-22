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
    pub arm: Option<ArmOverride>,
    pub limits: Option<LimitsOverride>,
    pub rules: Option<Rules>,
    pub ladder: Option<LadderOverride>,
    pub shields: Option<ShieldsOverride>,
    pub raid: Option<RaidOverride>,
}

/// Overrides fold FIELD by field. A whole-block override reset everything the
/// operator had customised globally back to library defaults — naming one
/// tighter limit silently loosened the other two.
#[derive(Debug, Clone, Copy, Deserialize, Default)]
#[serde(default)]
pub struct ArmOverride {
    pub warn: Option<bool>,
    pub delete: Option<bool>,
    pub kick: Option<bool>,
    pub ban: Option<bool>,
    pub raid: Option<bool>,
    pub vision: Option<bool>,
}

#[derive(Debug, Clone, Copy, Deserialize, Default)]
#[serde(default)]
pub struct LimitsOverride {
    pub max_actions_per_run: Option<usize>,
    pub max_actions_per_hour: Option<usize>,
    pub halt_if_over_pct: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct LadderOverride {
    pub strikes: Option<crate::config::Strikes>,
    pub decay_half_life_hours: Option<u64>,
    pub steps: Option<Vec<crate::config::Step>>,
}

#[derive(Debug, Clone, Copy, Deserialize, Default)]
#[serde(default)]
pub struct ShieldsOverride {
    pub respect_trusted: Option<bool>,
    pub respect_protected: Option<bool>,
}

#[derive(Debug, Clone, Copy, Deserialize, Default)]
#[serde(default)]
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
            rules: o.and_then(|o| o.rules.clone()).unwrap_or_else(|| self.rules.clone()),
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
                vision: f(a.vision, p.arm.vision),
            };
        }
        if let Some(l) = &o.limits {
            p.limits.max_actions_per_run = l.max_actions_per_run.unwrap_or(p.limits.max_actions_per_run);
            p.limits.max_actions_per_hour = l.max_actions_per_hour.unwrap_or(p.limits.max_actions_per_hour);
            p.limits.halt_if_over_pct = l.halt_if_over_pct.unwrap_or(p.limits.halt_if_over_pct);
        }
        if let Some(l) = &o.ladder {
            p.ladder.strikes = l.strikes.unwrap_or(p.ladder.strikes);
            p.ladder.decay_half_life_hours = l.decay_half_life_hours.unwrap_or(p.ladder.decay_half_life_hours);
            if let Some(steps) = &l.steps {
                p.ladder.steps = steps.clone();
            }
        }
        if let Some(sh) = &o.shields {
            p.shields.respect_trusted = sh.respect_trusted.unwrap_or(p.shields.respect_trusted);
            // respect_protected is refused as false at validation, so an
            // override cannot reach it either.
            p.shields.respect_protected = sh.respect_protected.unwrap_or(p.shields.respect_protected);
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
            [community."x".limits]
            halt_if_over_pct = 20
            [community."x".raid]
            response = "ban"
            "#,
        )
        .unwrap();
        let p = cfg.for_community("x");
        assert_eq!(p.limits.halt_if_over_pct, 20, "the named field changes");
        assert_eq!(p.limits.max_actions_per_run, 5, "and the operator's others survive");
        assert_eq!(p.limits.max_actions_per_hour, 10);
        assert_eq!(p.raid.response, crate::config::RaidResponse::Ban);
        assert_eq!(p.raid.tripwire_accounts, 5, "untouched raid fields keep their defaults");
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
