//! The operator's `[rules]` section, compiled into an engine policy and stored
//! locally under Sentinel's reserved id. The config file is the source of
//! truth; this translation is the only writer.

use vector_sdk::policy::{Policy, PolicyRule, Seriousness};
use vector_sdk::Community;

use crate::config::{Config, Gravity};

/// The id Sentinel's compiled policy is stored under. One writer, one slot:
/// re-running the compile replaces it rather than stacking copies.
pub const POLICY_ID: &str = "sentinel";

fn seriousness(g: Gravity) -> Seriousness {
    match g {
        Gravity::Note => Seriousness::Notice,
        Gravity::Minor => Seriousness::Minor,
        Gravity::Serious => Seriousness::Major,
        Gravity::Grave => Seriousness::Severe,
    }
}

/// Build the policy the config describes. None when the config adds no rules of
/// its own — the built-in raid defaults run regardless, and storing an empty
/// policy would be a no-op with a hash.
pub fn compile(cfg: &Config) -> Option<Policy> {
    let r = &cfg.rules;
    let mut policy = Policy::named("Sentinel");
    let mut any = false;

    for w in &r.words {
        policy = policy.rule(PolicyRule::words(&w.id, w.patterns.iter().cloned()).seriousness(seriousness(w.gravity)));
        any = true;
    }
    for l in &r.links {
        policy = policy.rule(PolicyRule::links(&l.id, l.domains.iter().cloned()).seriousness(seriousness(l.gravity)));
        any = true;
    }
    if let Some(rate) = &r.rate {
        if rate.enabled {
            policy = policy.rule(PolicyRule::rate_limit("rate", rate.per_secs).seriousness(seriousness(rate.gravity)));
            any = true;
        }
    }
    if let Some(mt) = &r.mass_tagging {
        if mt.enabled {
            policy = policy.rule(PolicyRule::mass_tagging("mass-tagging").seriousness(seriousness(mt.gravity)));
            any = true;
        }
    }
    if let Some(rep) = &r.repetition {
        if rep.enabled {
            policy = policy.rule(PolicyRule::repetition("repetition").seriousness(seriousness(rep.gravity)));
            any = true;
        }
    }
    if !any {
        return None;
    }
    Some(policy.window(r.window_hours, r.window_messages))
}

/// Install the compiled rulebook into one community's local policy store.
pub async fn install(community: &Community, cfg: &Config) -> Result<&'static str, String> {
    match compile(cfg) {
        Some(policy) => {
            community.policies().set(POLICY_ID, policy).await.map_err(|e| e.to_string())?;
            Ok("installed")
        }
        None => Ok("no custom rules — built-in raid defaults only"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_rules_section_compiles_to_nothing() {
        assert!(compile(&Config::default()).is_none());
    }

    /// The whole translation, end to end: every configured rule shape lands in
    /// a policy the engine's validator accepts.
    #[test]
    fn a_full_config_compiles_to_a_valid_policy() {
        let cfg: Config = toml::from_str(
            r#"
            [[rules.words]]
            id = "slurs"
            patterns = ["badword"]
            gravity = "grave"
            [[rules.links]]
            id = "shorteners"
            domains = ["bit.ly"]
            gravity = "serious"
            [rules.rate]
            enabled = true
            per_secs = 60
            gravity = "minor"
            [rules.mass_tagging]
            enabled = true
            gravity = "serious"
            [rules.repetition]
            enabled = true
            gravity = "minor"
            "#,
        )
        .unwrap();
        let policy = compile(&cfg).expect("five rules in, a policy out");
        let bytes = policy.build().expect("and the engine's validator accepts it");
        for id in ["slurs", "shorteners", "rate", "mass-tagging", "repetition"] {
            assert!(bytes.contains(id), "rule {id} went missing:\n{bytes}");
        }
        // The operator's gravity became the author's severity on the wire.
        assert!(bytes.contains("severe"), "grave words must land as severe");
    }

    #[test]
    fn a_disabled_toggle_stays_out_of_the_policy() {
        let cfg: Config = toml::from_str(
            "[rules.rate]\nenabled = false\nper_secs = 60\ngravity = \"minor\"",
        )
        .unwrap();
        assert!(compile(&cfg).is_none(), "disabled is absent, not present-but-off");
    }
}
