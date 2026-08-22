//! The operator's `[rules]` section, compiled into an engine policy and stored
//! locally under Sentinel's reserved id. The config file is the source of
//! truth; this translation is the only writer.

use vector_sdk::policy::{Policy, PolicyRule, Seriousness};
use vector_sdk::Community;

use crate::config::Gravity;
use crate::policy::CommunityPolicy;

/// The id Sentinel's compiled policy is stored under. One writer, one slot:
/// re-running the compile replaces it rather than stacking copies.
pub const POLICY_ID: &str = "sentinel";

/// This community's rulebook, as one short string. Stamped on every strike so
/// an amnesty is a fact about the row rather than an inference from its shape.
pub fn fingerprint(cfg: &crate::config::Config, community_id: &str) -> String {
    let rules = cfg.for_community(community_id).rules;
    format!("{:016x}", fnv(&format!("{rules:?}")))
}

/// FNV-1a. Only needs to notice a change.
fn fnv(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

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
pub fn compile(cfg: &CommunityPolicy) -> Option<Policy> {
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
pub async fn install(
    community: &Community,
    cfg: &crate::config::Config,
    store: &crate::store::Store,
) -> Result<&'static str, String> {
    // The COMMUNITY's rulebook, not the defaults. Installing the top-level one
    // everywhere meant a community's own `[rules]` override changed how
    // findings were scored while the engine went on matching somebody else's
    // rule ids — so every gravity lookup missed and quietly downgraded.
    match compile(&cfg.for_community(community.id())) {
        Some(policy) => {
            community.policies().set(POLICY_ID, policy).await.map_err(|e| e.to_string())?;
            // Retire whatever an older rulebook minted. Strikes carry the hash
            // they were charged under, so this is a fact rather than a guess —
            // and an upgrade that changes the hashing cannot forgive a
            // community's history as a side effect, because rows written before
            // the stamp existed carry '' and are never retired.
            let retired = store.retire_policy(community.id(), &fingerprint(cfg, community.id()))?;
            if retired > 0 {
                return Ok("rulebook changed — strikes it minted forgiven");
            }
            Ok("installed")
        }
        None => {
            // The config is the source of truth, so removing every rule has to
            // remove the policy. Writing nothing left the last one installed
            // and still convicting.
            let _ = community.policies().delete(POLICY_ID).await;
            Ok("no custom rules — built-in raid defaults only")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(toml_text: &str) -> CommunityPolicy {
        toml::from_str::<crate::config::Config>(toml_text).unwrap().for_community("aa")
    }

    #[test]
    fn an_empty_rules_section_compiles_to_nothing() {
        assert!(compile(&policy("")).is_none());
    }

    /// The rulebook a community gets is its own. Compiling the defaults
    /// everywhere left its gravity lookups matching nothing.
    #[test]
    fn a_community_compiles_its_own_rules() {
        let cfg: crate::config::Config = toml::from_str(
            r#"
            [[rules.words]]
            id = "house"
            patterns = ["darn"]
            gravity = "note"
            [community."strict".rules]
            [[community."strict".rules.words]]
            id = "strict-words"
            patterns = ["blast"]
            gravity = "grave"
            "#,
        )
        .unwrap();
        let strict = compile(&cfg.for_community("strict")).unwrap().build().unwrap();
        assert!(strict.contains("strict-words") && !strict.contains("house"));
        let default = compile(&cfg.for_community("other")).unwrap().build().unwrap();
        assert!(default.contains("house") && !default.contains("strict-words"));
    }

    /// The whole translation, end to end: every configured rule shape lands in
    /// a policy the engine's validator accepts.
    #[test]
    fn a_full_config_compiles_to_a_valid_policy() {
        let cfg = policy(
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
        );
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
        let cfg = policy("[rules.rate]\nenabled = false\nper_secs = 60\ngravity = \"minor\"");
        assert!(compile(&cfg).is_none(), "disabled is absent, not present-but-off");
    }
}
