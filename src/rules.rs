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

    // Shields gate BEFORE conviction, so reaching a regular has to be said in the
    // RULEBOOK — otherwise the engine spares them upstream and nothing downstream
    // ever sees a finding to weigh. The engine permits piercing only at its
    // gravest severity, so anything lighter yields to standing whatever is asked
    // here; asking anyway is a policy the validator rejects outright.
    //
    // CONTENT rules — the operator's word and link lists — pierce on their own
    // account, not on `respect_trusted`. Those lists say what this community will
    // not host whoever posts it, which is exactly what `spared_from_content`
    // already refuses to spare a trusted member from. Without piercing here that
    // refusal is unreachable code: the engine gates the finding upstream, and a
    // regular who earned standing by not behaving like a spammer may then post a
    // slur freely. Standing is leniency on BEHAVIOUR — rate, repetition, cohorts
    // — and was never meant to be a licence on content.
    // `even_for_trusted` pierces at the RULE level and lifts each rung only where
    // the engine permits it (its gravest severity), so this is safe at any
    // gravity — the validator refuses a rung that overreaches, never the rule.
    let behaviour_reach = |rule: PolicyRule| {
        if cfg.shields.respect_trusted {
            rule
        } else {
            rule.even_for_trusted()
        }
    };
    let content_reach = |rule: PolicyRule| rule.even_for_trusted();

    for w in &r.words {
        policy = policy
            .rule(content_reach(PolicyRule::words(&w.id, w.patterns.iter().cloned()).seriousness(seriousness(w.gravity))));
        any = true;
    }
    for l in &r.links {
        policy = policy
            .rule(content_reach(PolicyRule::links(&l.id, l.domains.iter().cloned()).seriousness(seriousness(l.gravity))));
        any = true;
    }
    if let Some(rate) = &r.rate {
        if rate.enabled {
            policy = policy.rule(behaviour_reach(
                PolicyRule::rate_limit("rate", rate.per_secs)
                    .at_least(rate.messages)
                    .seriousness(seriousness(rate.gravity)),
            ));
            any = true;
        }
    }
    if let Some(mt) = &r.mass_tagging {
        if mt.enabled {
            policy = policy.rule(behaviour_reach(
                PolicyRule::mass_tagging("mass-tagging").at_least(mt.times).seriousness(seriousness(mt.gravity)),
            ));
            any = true;
        }
    }
    if let Some(rep) = &r.repetition {
        if rep.enabled {
            policy = policy.rule(behaviour_reach(
                PolicyRule::repetition("repetition").at_least(rep.times).seriousness(seriousness(rep.gravity)),
            ));
            any = true;
        }
    }
    if !any {
        return None;
    }
    Some(policy.window(r.window_hours, r.window_messages))
}

/// Install the compiled rulebook into one community's local policy store.
pub async fn install(community: &Community, cfg: &crate::config::Config) -> Result<&'static str, String> {
    // The COMMUNITY's rulebook, not the defaults. Installing the top-level one
    // everywhere meant a community's own `[rules]` override changed how
    // findings were scored while the engine went on matching somebody else's
    // rule ids — so every gravity lookup missed and quietly downgraded.
    match compile(&cfg.for_community(community.id())) {
        Some(policy) => {
            community.policies().set(POLICY_ID, policy).await.map_err(|e| e.to_string())?;
            Ok("installed")
        }
        None => {
            // The config is the source of truth, so removing every rule has to
            // remove the policy. Writing nothing left the last one installed
            // and still convicting — and a swallowed failure here left it
            // installed AND its strikes forgiven, which is the worst of both.
            community.policies().delete(POLICY_ID).await.map_err(|e| e.to_string())?;
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

    /// Standing is leniency on BEHAVIOUR, never a licence on content. The engine
    /// gates a rule against a Trusted member BEFORE conviction unless the rule
    /// pierces, so a word list that does not pierce produces no finding at all —
    /// and `spared_from_content`, which already refuses to spare a trusted member
    /// from content rules, never gets a message to refuse with. That combination
    /// shipped: a member became Trusted merely by holding a role (a read-only
    /// private-channel grant is enough) and could then post a slur untouched,
    /// while every log line read "0 convicted".
    #[test]
    fn a_grave_word_list_reaches_a_trusted_member() {
        let built = compile(&policy(
            r#"
            [[rules.words]]
            id = "slurs"
            patterns = ["badword"]
            gravity = "grave"
            "#,
        ))
        .unwrap()
        .build()
        .unwrap();
        assert!(
            built.contains("\"pierces_trusted\":true"),
            "a grave word list must reach a trusted member, or standing becomes a licence to post it: {built}"
        );
    }

    /// A content rule reaches a trusted member at ANY gravity, and the rulebook
    /// stays valid while doing it: `even_for_trusted` pierces at the rule level
    /// and lifts only the rungs the engine permits (its gravest severity). An
    /// earlier attempt to gate the whole rule on severity looked safer and was
    /// wrong — it silenced every sub-grave word list against regulars.
    #[test]
    fn a_lighter_content_rule_still_reaches_and_still_validates() {
        let built = compile(&policy(
            r#"
            [[rules.links]]
            id = "shorteners"
            domains = ["bit.ly"]
            gravity = "serious"
            "#,
        ))
        .unwrap()
        .build()
        .expect("a sub-severe content rule must still produce a VALID policy");
        assert!(
            built.contains("\"pierces_trusted\":true"),
            "the rule itself reaches a regular: {built}"
        );
        assert!(
            !built.contains("\"severity\":\"major\",\"weight\":70,\"pierces_trusted\":true"),
            "but a sub-severe RUNG must not claim to pierce, or the engine rejects the rulebook"
        );
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

    /// Sentinel's gravity and the engine's severity are deliberately different
    /// vocabularies, and the map between them must be total and ordered.
    #[test]
    fn gravity_maps_onto_severity_in_order() {
        use vector_sdk::policy::Seriousness;
        let pairs = [
            (Gravity::Note, Seriousness::Notice),
            (Gravity::Minor, Seriousness::Minor),
            (Gravity::Serious, Seriousness::Major),
            (Gravity::Grave, Seriousness::Severe),
        ];
        for (g, want) in pairs {
            assert_eq!(seriousness(g), want, "{g:?}");
        }
        // And the round trip Sentinel actually performs: a severity coming back
        // from the engine maps to the gravity that produced it.
        for (g, _) in pairs {
            let severity = match seriousness(g) {
                Seriousness::Notice => "notice",
                Seriousness::Minor => "minor",
                Seriousness::Major => "major",
                Seriousness::Severe => "severe",
            };
            assert_eq!(Gravity::from_severity(severity), g, "{severity} must come back as {g:?}");
        }
    }
}
