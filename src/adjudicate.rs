//! What should happen, decided as a pure function.
//!
//! Every lane — the sweep's ladder, the live text screen, the media lane, raid
//! containment — asks this the same question and gets an answer it must obey.
//! Nothing here does I/O, so every gate below is a table test that fails if the
//! gate is removed.
//!
//! The previous shape put these checks inside the function that ACTS, which
//! meant each new lane could reach the acting without passing them, and a test
//! could only assert the rules by restating them. Splitting the decision from
//! the effect is what makes "one gate" true rather than claimed.

use crate::config::Response;
use crate::policy::{CommunityPolicy, Powers};

/// What one lane may do about one member, right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sentence {
    /// Standing protects them. A person decides from here.
    Spare { why: &'static str },
    /// This standing was already answered at this rung or above.
    Answered,
    /// A ceiling stopped it. The debt is still owed and must not be forgotten.
    Held { why: &'static str },
    /// Acting would touch too much of the community to be a moderation
    /// decision any more.
    Halt { ceiling: usize, roster: usize },
    /// This community never granted Sentinel the permission this needs.
    Powerless { needs: &'static str },
    /// Carry it out (or rehearse it, if that class is unarmed).
    Carry { response: Response, armed: bool },
}

/// Everything the decision depends on, gathered by the caller.
#[derive(Debug, Clone)]
pub struct Facts<'a> {
    /// This finding came from a vision model, not the engine. Inference gets
    /// its own switch rather than riding the booleans an operator set for
    /// provable text rules.
    pub from_vision: bool,
    /// none · trusted · protected · indeterminate · unknown
    pub shield: &'a str,
    /// The strongest response already given at this armed-ness, if any.
    pub prior: Option<&'a str>,
    pub acted_this_pass: usize,
    pub acted_this_hour: usize,
    /// Members this community has, as the last evaluation counted them.
    pub roster: usize,
    pub is_me: bool,
}

/// How many actions the roster percentage allows.
///
/// Floored at one. `10%` of a five-member community rounds to zero, which
/// halted the ladder before its first action forever — a small community looked
/// peaceful while nothing worked at all.
pub fn roster_ceiling(cfg: &CommunityPolicy, roster: usize) -> Option<usize> {
    if roster == 0 {
        return None;
    }
    Some(((cfg.limits.halt_if_over_pct as usize * roster) / 100).max(1))
}

/// Whether this class is armed for this provenance. One source of truth: the
/// caller scopes its dedup lookup by the same answer the sentence uses.
pub fn armed_for(cfg: &CommunityPolicy, response: Response, from_vision: bool) -> bool {
    cfg.arm.vision_ok(from_vision)
        && match response {
            Response::Warn => cfg.arm.warn,
            Response::DeleteAndWarn => cfg.arm.delete,
            Response::Kick => cfg.arm.kick,
            Response::Ban => cfg.arm.ban,
        }
}

/// The decision. Order matters and is the order below.
pub fn adjudicate(cfg: &CommunityPolicy, powers: Powers, facts: &Facts, response: Response) -> Sentence {
    // Sentinel is not its own subject.
    if facts.is_me {
        return Sentence::Spare { why: "self" };
    }

    // Standing, first and unconditional.
    match facts.shield {
        "protected" => return Sentence::Spare { why: "protected" },
        "trusted" if cfg.shields.respect_trusted => return Sentence::Spare { why: "trusted" },
        // Not knowing is not the same as knowing they are ordinary. Before the
        // first evaluation fills the roster, holding is the honest answer.
        // ("absent" is different: the roster IS known and they are not in it, so
        // the caller has already resolved them against the community's roles.)
        "unknown" => return Sentence::Spare { why: "standing not yet established" },
        _ => {}
    }

    // Can Sentinel even do this here? Being a member is not being a moderator,
    // and attempting what a community never granted produces a publish every
    // reader drops.
    match response {
        Response::DeleteAndWarn if !powers.hide => return Sentence::Powerless { needs: "MANAGE_MESSAGES" },
        Response::Kick if !powers.kick => return Sentence::Powerless { needs: "KICK" },
        Response::Ban if !powers.ban => return Sentence::Powerless { needs: "BAN" },
        _ => {}
    }

    // Already answered? Scoped to armed-ness by the caller, so a rehearsal only
    // ever dedups rehearsals.
    if facts.prior.map(Response::rank_of).unwrap_or(0) >= response.rank() {
        return Sentence::Answered;
    }

    // Ceilings. A bug must not be able to empty a community.
    if facts.acted_this_pass >= cfg.limits.max_actions_per_run {
        return Sentence::Held { why: "run ceiling" };
    }
    if facts.acted_this_hour >= cfg.limits.max_actions_per_hour {
        return Sentence::Held { why: "hourly ceiling" };
    }
    if let Some(ceiling) = roster_ceiling(cfg, facts.roster) {
        // Measured against the hour, not one pass: the live lanes act one
        // message at a time, and a per-pass count is always zero for them.
        if facts.acted_this_hour >= ceiling {
            return Sentence::Halt { ceiling, roster: facts.roster };
        }
    }

    Sentence::Carry { response, armed: armed_for(cfg, response, facts.from_vision) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn all_powers() -> Powers {
        Powers { hide: true, kick: true, ban: true }
    }

    fn facts() -> Facts<'static> {
        Facts {
            shield: "none",
            prior: None,
            acted_this_pass: 0,
            acted_this_hour: 0,
            roster: 100,
            is_me: false,
            from_vision: false,
        }
    }

    fn policy() -> CommunityPolicy {
        Config::default().for_community("aa")
    }

    /// The property the whole restructure exists for: no lane can reach an
    /// action against someone the community vouched for.
    #[test]
    fn standing_spares_before_anything_else_is_considered() {
        let cfg = policy();
        for (shield, spared) in [
            ("protected", true),
            ("trusted", true),
            ("unknown", true),
            ("none", false),
            // Tenure unknowable is explicitly NOT standing.
            ("indeterminate", false),
            // Resolved by the caller against the community's roles.
            ("absent", false),
        ] {
            let f = Facts { shield, ..facts() };
            let got = adjudicate(&cfg, all_powers(), &f, Response::Ban);
            assert_eq!(matches!(got, Sentence::Spare { .. }), spared, "shield {shield} -> {got:?}");
        }
    }

    #[test]
    fn trusted_can_be_reached_when_a_community_says_so() {
        let mut cfg = policy();
        cfg.shields.respect_trusted = false;
        let f = Facts { shield: "trusted", ..facts() };
        assert!(matches!(adjudicate(&cfg, all_powers(), &f, Response::Kick), Sentence::Carry { .. }));
        // Protected is never negotiable.
        let f = Facts { shield: "protected", ..facts() };
        assert!(matches!(adjudicate(&cfg, all_powers(), &f, Response::Kick), Sentence::Spare { .. }));
    }

    #[test]
    fn sentinel_never_sentences_itself() {
        let f = Facts { is_me: true, ..facts() };
        assert_eq!(adjudicate(&policy(), all_powers(), &f, Response::Ban), Sentence::Spare { why: "self" });
    }

    /// Being a member is not being a moderator.
    #[test]
    fn a_sentence_needs_the_permission_it_calls_for() {
        let cfg = policy();
        let nothing = Powers::default();
        for (r, needs) in [
            (Response::DeleteAndWarn, "MANAGE_MESSAGES"),
            (Response::Kick, "KICK"),
            (Response::Ban, "BAN"),
        ] {
            assert_eq!(adjudicate(&cfg, nothing, &facts(), r), Sentence::Powerless { needs }, "{r:?}");
        }
        // A warning is a DM, which needs nothing from the community.
        assert!(matches!(adjudicate(&cfg, nothing, &facts(), Response::Warn), Sentence::Carry { .. }));
        // And a partial grant reaches exactly as far as it goes.
        let partial = Powers { hide: true, kick: true, ban: false };
        assert!(matches!(adjudicate(&cfg, partial, &facts(), Response::Kick), Sentence::Carry { .. }));
        assert_eq!(adjudicate(&cfg, partial, &facts(), Response::Ban), Sentence::Powerless { needs: "BAN" });
    }

    /// A day of dry running must not silence the bot on the day it is armed.
    /// The caller scopes `prior` by armed-ness; this proves the ranking.
    #[test]
    fn a_standing_is_answered_once_and_escalation_still_gets_through() {
        let cfg = policy();
        let f = Facts { prior: Some("warn"), ..facts() };
        assert_eq!(adjudicate(&cfg, all_powers(), &f, Response::Warn), Sentence::Answered);
        assert!(matches!(adjudicate(&cfg, all_powers(), &f, Response::Kick), Sentence::Carry { .. }));

        // A raid row is not a ladder response and must not answer for one.
        let f = Facts { prior: Some("raid:kick"), ..facts() };
        assert!(matches!(adjudicate(&cfg, all_powers(), &f, Response::Warn), Sentence::Carry { .. }));
    }

    #[test]
    fn ceilings_hold_and_a_small_community_still_permits_one_action() {
        let cfg = policy();
        let f = Facts { acted_this_pass: cfg.limits.max_actions_per_run, ..facts() };
        assert_eq!(adjudicate(&cfg, all_powers(), &f, Response::Warn), Sentence::Held { why: "run ceiling" });

        let f = Facts { acted_this_hour: cfg.limits.max_actions_per_hour, ..facts() };
        assert_eq!(adjudicate(&cfg, all_powers(), &f, Response::Warn), Sentence::Held { why: "hourly ceiling" });

        // 10% of five rounds to zero, which used to halt everything forever.
        for roster in 1..=12usize {
            assert!(roster_ceiling(&cfg, roster).unwrap() >= 1, "roster {roster} could never act");
        }
        assert_eq!(roster_ceiling(&cfg, 0), None, "an uncounted roster imposes no percentage");
        assert_eq!(roster_ceiling(&cfg, 100), Some(10));
    }

    /// The live lanes act one message at a time, so a per-PASS count is always
    /// zero for them. The community-emptying guard has to span the hour.
    #[test]
    fn the_roster_halt_measures_the_hour_not_one_pass() {
        let cfg = policy();
        let f = Facts { roster: 40, acted_this_hour: 4, acted_this_pass: 0, ..facts() };
        assert_eq!(adjudicate(&cfg, all_powers(), &f, Response::Ban), Sentence::Halt { ceiling: 4, roster: 40 });
    }

    /// A model's opinion is inference and must not ride the switch an operator
    /// set for provable text rules. It still REHEARSES, so arming it later does
    /// not fire a backlog of sentences nothing ever answered.
    #[test]
    fn vision_answers_to_its_own_arm() {
        let mut cfg = policy();
        cfg.arm.kick = true;
        let seen = Facts { from_vision: true, ..facts() };
        assert_eq!(
            adjudicate(&cfg, all_powers(), &seen, Response::Kick),
            Sentence::Carry { response: Response::Kick, armed: false },
            "armed for text is not armed for a classifier"
        );
        cfg.arm.vision = true;
        assert_eq!(
            adjudicate(&cfg, all_powers(), &seen, Response::Kick),
            Sentence::Carry { response: Response::Kick, armed: true }
        );
    }

    /// The armed-ness that scopes the dedup lookup must be the one the sentence
    /// is carried out under, or a rehearsal is deduped against real actions.
    #[test]
    fn the_arming_a_caller_computes_matches_the_one_used() {
        let mut cfg = policy();
        cfg.arm.kick = true;
        for from_vision in [false, true] {
            let f = Facts { from_vision, ..facts() };
            let Sentence::Carry { armed, .. } = adjudicate(&cfg, all_powers(), &f, Response::Kick) else {
                panic!("expected a sentence")
            };
            assert_eq!(armed, armed_for(&cfg, Response::Kick, from_vision), "from_vision {from_vision}");
        }
    }

    #[test]
    fn arming_is_per_class_and_rehearsal_is_the_resting_state() {
        let mut cfg = policy();
        assert_eq!(
            adjudicate(&cfg, all_powers(), &facts(), Response::Kick),
            Sentence::Carry { response: Response::Kick, armed: false }
        );
        cfg.arm.kick = true;
        assert_eq!(
            adjudicate(&cfg, all_powers(), &facts(), Response::Kick),
            Sentence::Carry { response: Response::Kick, armed: true }
        );
        // Arming kick does not arm ban.
        assert_eq!(
            adjudicate(&cfg, all_powers(), &facts(), Response::Ban),
            Sentence::Carry { response: Response::Ban, armed: false }
        );
    }
}
