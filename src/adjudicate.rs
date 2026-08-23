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
    /// none · trusted · protected · indeterminate · unknown
    pub shield: &'a str,
    pub acted_this_pass: usize,
    pub acted_this_hour: usize,
    /// Distinct people actioned this hour. The roster halt reads THIS, because
    /// the ladder climbs and one member spends several rows.
    pub subjects_this_hour: usize,
    /// Members this community has, as the last evaluation counted them.
    pub roster: usize,
    pub is_me: bool,
}

/// How many DISTINCT people Sentinel may answer for here in an hour.
///
/// Not a rate limit — every member has their own strikes and their own rung.
/// This is the blast radius, so a misconfigured rule or a bad raid call cannot
/// walk the whole memberlist.
///
/// A percentage alone is the wrong shape when a community is small: 10% of four
/// members floors to one, so the SECOND offender in an hour deadlocks the bot,
/// and a halt also defers raid containment and skips the debt loop. The floor
/// keeps the protection where it matters and stops tiny communities seizing up.
/// Never more than the roster, so the guard is always expressible.
pub fn roster_ceiling(cfg: &CommunityPolicy, roster: usize) -> Option<usize> {
    if roster == 0 {
        return None;
    }
    let pct = (cfg.limits.halt_if_over_pct as usize * roster) / 100;
    Some(pct.max(cfg.limits.halt_floor).min(roster))
}

/// Whether this class is armed at all.
pub fn armed_for(cfg: &CommunityPolicy, response: Response) -> bool {
    match response {
        Response::Warn => cfg.arm.warn,
        Response::DeleteAndWarn => cfg.arm.delete,
        Response::Kick => cfg.arm.kick,
        Response::Ban => cfg.arm.ban,
    }
}

/// Does standing alone put this member out of reach here?
///
/// The ONE place the shield vocabulary lives. Every lane pre-filters before it
/// records anything, and three hand-written copies of this rule had already
/// drifted apart — the sweep's omitted `unknown` and `absent`, so it built a
/// silent backlog on members the gate would always spare.
pub fn spared_by_standing(cfg: &CommunityPolicy, shield: &str) -> Option<&'static str> {
    match shield {
        "protected" => Some("protected"),
        "trusted" if cfg.shields.respect_trusted => Some("trusted"),
        // Not knowing is not the same as knowing they are ordinary.
        "unknown" => Some("standing not yet established"),
        // The roster was read and does not list them. A caller that CAN resolve
        // this — a live lane, which has the member in hand — passes the resolved
        // value; one that cannot gets a refusal rather than a default.
        "absent" => Some("not on the roster"),
        // Known vocabulary that is not a shield here: `indeterminate` means
        // tenure could not be established, and `trusted` has already passed the
        // guard above in a community that chose to reach its regulars.
        "none" | "indeterminate" | "trusted" => None,
        // Anything else is the engine's vocabulary having moved. Falling
        // through would read a renamed shield as "not shielded", which is a
        // removal — the one direction upstream drift must never take.
        _ => Some("standing not recognised"),
    }
}

/// The decision. Order matters and is the order below.
pub fn adjudicate(cfg: &CommunityPolicy, powers: Powers, facts: &Facts, response: Response) -> Sentence {
    // Sentinel is not its own subject.
    if facts.is_me {
        return Sentence::Spare { why: "self" };
    }

    // An empty roster is a failed read, not an empty community — and with no
    // members the percentage ceiling bounds nothing at all, so the
    // community-emptying guard would be silently off.
    if facts.roster == 0 {
        return Sentence::Spare { why: "roster unknown" };
    }

    // Standing, first and unconditional.
    if let Some(why) = spared_by_standing(cfg, facts.shield) {
        return Sentence::Spare { why };
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
        // The post-action set: this member is excluded from the count, so
        // escalating someone already inside the bound is allowed while the
        // bound itself still holds. Counting them again halted the whole bot
        // on the first sentence of every hour in any small community.
        if facts.subjects_this_hour + 1 > ceiling {
            return Sentence::Halt { ceiling, roster: facts.roster };
        }
    }

    Sentence::Carry { response, armed: armed_for(cfg, response) }
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
            acted_this_pass: 0,
            acted_this_hour: 0,
            roster: 100,
            is_me: false,
            subjects_this_hour: 0,
        }
    }

    fn policy() -> CommunityPolicy {
        Config::default().for_community("fe4abeb3fd227a67fc59d8a4363420649bb970436dc3b14d51c2b66fee334dea")
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
            // The roster was read and does not list them: nobody resolved this,
            // so it fails closed. A live lane passes "none" or "protected"
            // instead, having asked the community's own roles.
            ("absent", true),
        ] {
            let f = Facts { shield, ..facts() };
            let got = adjudicate(&cfg, all_powers(), &f, Response::Ban);
            assert_eq!(matches!(got, Sentence::Spare { .. }), spared, "shield {shield} -> {got:?}");
        }
    }

    /// An empty roster is missing data, not a clean answer: with no members
    /// the percentage ceiling has nothing to bound, so it must refuse rather
    /// than permit.
    #[test]
    fn an_unread_roster_sentences_nobody() {
        let f = Facts { roster: 0, ..facts() };
        assert_eq!(
            adjudicate(&policy(), all_powers(), &f, Response::Ban),
            Sentence::Spare { why: "roster unknown" }
        );
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

    /// A member already inside the bound must still climb. Counting them halted
    /// the bot on the first sentence of every hour and took raid containment
    /// with it.
    #[test]
    fn a_member_already_inside_the_bound_can_still_be_escalated() {
        let cfg = policy();
        for roster in 1..=19usize {
            assert_eq!(roster_ceiling(&cfg, roster), Some(cfg.limits.halt_floor.min(roster)), "roster {roster}");
            let f = Facts { roster, subjects_this_hour: 0, ..facts() };
            assert!(
                matches!(adjudicate(&cfg, all_powers(), &f, Response::Kick), Sentence::Carry { .. }),
                "roster {roster} could not escalate the one member it had acted on"
            );
            // And one distinct person PAST the ceiling halts — which the floor
            // now pushes out to a sane number rather than the second offender.
            let ceiling = roster_ceiling(&cfg, roster).expect("a non-empty roster has one");
            let f = Facts { roster, subjects_this_hour: ceiling, ..facts() };
            assert!(matches!(adjudicate(&cfg, all_powers(), &f, Response::Kick), Sentence::Halt { .. }));
        }
    }

    /// The shape a live four-member lab exposed: 10% floors to one, so the
    /// SECOND distinct offender in an hour deadlocked the bot — and a halt also
    /// defers raid containment and skips the debt loop.
    #[test]
    fn a_small_community_does_not_deadlock_on_its_second_offender() {
        let cfg = policy();
        for roster in 2..=10usize {
            let f = Facts { roster, subjects_this_hour: 1, ..facts() };
            assert!(
                matches!(adjudicate(&cfg, all_powers(), &f, Response::Warn), Sentence::Carry { .. }),
                "roster {roster} halted on its second offender"
            );
        }
    }

    /// And the guard still binds where it matters: a large community is held to
    /// its percentage, not to the floor.
    #[test]
    fn a_large_community_answers_to_the_percentage() {
        let cfg = policy();
        assert_eq!(roster_ceiling(&cfg, 200), Some(20), "10% of 200");
        assert_eq!(roster_ceiling(&cfg, 1000), Some(100));
        let f = Facts { roster: 200, subjects_this_hour: 20, ..facts() };
        assert!(matches!(adjudicate(&cfg, all_powers(), &f, Response::Kick), Sentence::Halt { .. }));
    }

    /// The ceiling can never exceed the community it is protecting.
    #[test]
    fn the_ceiling_never_exceeds_the_roster() {
        let cfg = policy();
        for roster in 1..=50usize {
            let ceiling = roster_ceiling(&cfg, roster).expect("non-empty");
            assert!(ceiling <= roster, "roster {roster} allows {ceiling}");
            assert!(ceiling >= 1, "roster {roster} allows nothing");
        }
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
        let f = Facts { roster: 40, subjects_this_hour: 4, acted_this_pass: 0, ..facts() };
        assert_eq!(adjudicate(&cfg, all_powers(), &f, Response::Ban), Sentence::Halt { ceiling: 4, roster: 40 });
        // Three others plus this one is exactly the bound, so it is allowed.
        let f = Facts { roster: 40, subjects_this_hour: 3, ..facts() };
        assert!(matches!(adjudicate(&cfg, all_powers(), &f, Response::Ban), Sentence::Carry { .. }));
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

    /// Each class answers to its OWN switch, and to no other.
    #[test]
    fn every_class_reads_only_its_own_arming_switch() {
        let cases = [
            (Response::Warn, "warn"),
            (Response::DeleteAndWarn, "delete"),
            (Response::Kick, "kick"),
            (Response::Ban, "ban"),
        ];
        for (response, field) in cases {
            let cfg: Config =
                toml::from_str(&format!("[arm]\n{field} = true")).expect("a switch by name");
            let p = cfg.for_community("");
            assert!(armed_for(&p, response), "{field} must arm {response:?}");
            for (other, other_field) in cases {
                if other != response {
                    assert!(!armed_for(&p, other), "{field} must not arm {other_field}");
                }
            }
        }
    }

    /// The pre-filters every lane runs before recording anything must be the
    /// same rule as the gate that follows them. Three hand-written copies had
    /// already drifted: the sweep's omitted `unknown` and `absent`, so it built
    /// a backlog on members the gate would always spare.
    #[test]
    fn the_lane_pre_filter_and_the_gate_agree_on_every_shield() {
        let cfg = policy();
        for shield in ["protected", "trusted", "unknown", "absent", "none", "indeterminate", "renamed", ""] {
            let pre = spared_by_standing(&cfg, shield).is_some();
            let f = Facts { shield, ..facts() };
            let gate = matches!(adjudicate(&cfg, all_powers(), &f, Response::Warn), Sentence::Spare { .. });
            assert_eq!(pre, gate, "{shield}: pre-filter says {pre}, the gate says {gate}");
        }
    }

    #[test]
    fn a_community_that_reaches_its_regulars_reaches_them_in_every_lane() {
        let mut cfg = policy();
        assert!(spared_by_standing(&cfg, "trusted").is_some());
        cfg.shields.respect_trusted = false;
        assert!(spared_by_standing(&cfg, "trusted").is_none());
        assert!(spared_by_standing(&cfg, "protected").is_some(), "protected is never negotiable");
    }

    /// The whole vocabulary, in one place. A shield the gate does not know used
    /// to fall through to "not shielded", which is a removal — so an engine
    /// rename would have been a bug that only showed up as banned moderators.
    #[test]
    fn every_shield_string_is_recognised_and_an_unknown_one_spares() {
        let cfg = policy();
        for (shield, spared) in [
            ("protected", true),
            ("trusted", true),
            ("unknown", true),
            ("absent", true),
            ("none", false),
            ("indeterminate", false),
        ] {
            let f = Facts { shield, ..facts() };
            let got = adjudicate(&cfg, all_powers(), &f, Response::Ban);
            assert_eq!(
                matches!(got, Sentence::Spare { .. }),
                spared,
                "{shield} must {} be spared, got {got:?}",
                if spared { "" } else { "not" }
            );
        }

        // Anything the engine might rename to.
        for unknown in ["Trusted", "protected ", "vouched", "", "staff", "none "] {
            let f = Facts { shield: unknown, ..facts() };
            assert!(
                matches!(adjudicate(&cfg, all_powers(), &f, Response::Ban), Sentence::Spare { .. }),
                "an unrecognised shield ({unknown:?}) must spare, never remove"
            );
        }
    }

    /// The shields the ENGINE emits, taken from its own enum rather than from
    /// this file's memory of it.
    #[test]
    fn the_engines_own_shield_names_are_all_handled() {
        use vector_sdk::vector_core::community::policy::types::Shield;
        let cfg = policy();
        for shield in [Shield::None, Shield::Trusted, Shield::Protected, Shield::Indeterminate] {
            // Exactly how the console renders it for a consumer.
            let name = format!("{shield:?}").to_lowercase();
            let f = Facts { shield: &name, ..facts() };
            let got = adjudicate(&cfg, all_powers(), &f, Response::Ban);
            let spared = matches!(got, Sentence::Spare { .. });
            match shield {
                Shield::Protected | Shield::Trusted => assert!(spared, "{name} is standing"),
                Shield::None | Shield::Indeterminate => {
                    assert!(!spared, "{name} is not standing, and must not be spared as unrecognised")
                }
            }
        }
    }

    /// The community-emptying guard, across every roster size that rounds
    /// badly. A ceiling of zero halted the ladder forever; a ceiling that
    /// counted the current subject halted it on the first sentence of the hour.
    #[test]
    fn the_roster_ceiling_is_at_least_one_and_never_counts_the_subject() {
        let cfg = policy();
        for roster in 1..=200usize {
            let ceiling = roster_ceiling(&cfg, roster).expect("a non-empty roster has a ceiling");
            assert!(ceiling >= 1, "roster {roster} allows nothing at all");
            assert!(ceiling <= roster, "roster {roster} allows more than everyone");

            // The first person of the hour is always reachable.
            let f = Facts { roster, subjects_this_hour: 0, ..facts() };
            assert!(
                matches!(adjudicate(&cfg, all_powers(), &f, Response::Warn), Sentence::Carry { .. }),
                "roster {roster} cannot answer anybody"
            );

            // And someone already inside the bound can still be escalated,
            // because the ladder climbs and one member spends several rows.
            let f = Facts { roster, subjects_this_hour: ceiling - 1, ..facts() };
            assert!(
                matches!(adjudicate(&cfg, all_powers(), &f, Response::Kick), Sentence::Carry { .. }),
                "roster {roster} cannot escalate a member already inside the bound"
            );

            // One distinct person past it halts.
            let f = Facts { roster, subjects_this_hour: ceiling, ..facts() };
            assert!(
                matches!(adjudicate(&cfg, all_powers(), &f, Response::Kick), Sentence::Halt { .. }),
                "roster {roster} does not halt at its own ceiling"
            );
        }
    }

    #[test]
    fn an_empty_roster_is_a_failed_read_not_an_empty_community() {
        let cfg = policy();
        assert_eq!(roster_ceiling(&cfg, 0), None);
        let f = Facts { roster: 0, ..facts() };
        assert_eq!(adjudicate(&cfg, all_powers(), &f, Response::Warn), Sentence::Spare { why: "roster unknown" });
    }

    /// The ceilings answer in a fixed order, and each one names itself.
    #[test]
    fn each_ceiling_is_reported_as_itself() {
        let cfg = policy();
        let f = Facts { acted_this_pass: cfg.limits.max_actions_per_run, ..facts() };
        assert_eq!(adjudicate(&cfg, all_powers(), &f, Response::Warn), Sentence::Held { why: "run ceiling" });

        let f = Facts { acted_this_hour: cfg.limits.max_actions_per_hour, ..facts() };
        assert_eq!(adjudicate(&cfg, all_powers(), &f, Response::Warn), Sentence::Held { why: "hourly ceiling" });
    }

    /// Standing outranks every ceiling: a shielded member is spared whatever
    /// else is true, so no ordering change can turn a shield into a removal.
    #[test]
    fn standing_is_answered_before_anything_else() {
        let cfg = policy();
        for shield in ["protected", "trusted", "unknown", "absent"] {
            let f = Facts {
                shield,
                acted_this_pass: 9999,
                acted_this_hour: 9999,
                subjects_this_hour: 9999,
                roster: 1,
                is_me: false,
            };
            assert!(
                matches!(adjudicate(&cfg, Powers::default(), &f, Response::Ban), Sentence::Spare { .. }),
                "{shield} must be spared before any other answer"
            );
        }
    }

    /// And Sentinel outranks even that.
    #[test]
    fn sentinel_is_spared_before_standing_is_even_read() {
        let cfg = policy();
        let f = Facts { is_me: true, shield: "none", roster: 0, ..facts() };
        assert_eq!(adjudicate(&cfg, all_powers(), &f, Response::Ban), Sentence::Spare { why: "self" });
    }

    /// A permission this community never granted is named, not attempted.
    #[test]
    fn every_response_reports_the_permission_it_needs() {
        let cfg = policy();
        let none = Powers::default();
        assert_eq!(
            adjudicate(&cfg, none, &facts(), Response::DeleteAndWarn),
            Sentence::Powerless { needs: "MANAGE_MESSAGES" }
        );
        assert_eq!(adjudicate(&cfg, none, &facts(), Response::Kick), Sentence::Powerless { needs: "KICK" });
        assert_eq!(adjudicate(&cfg, none, &facts(), Response::Ban), Sentence::Powerless { needs: "BAN" });
        // A warning needs nothing but a DM.
        assert!(matches!(adjudicate(&cfg, none, &facts(), Response::Warn), Sentence::Carry { .. }));
    }

    /// Arming decides only whether it happens, never whether it is decided.
    #[test]
    fn arming_is_the_last_word_and_changes_nothing_else() {
        let mut cfg = policy();
        let dry = adjudicate(&cfg, all_powers(), &facts(), Response::Warn);
        assert_eq!(dry, Sentence::Carry { response: Response::Warn, armed: false });

        cfg.arm.warn = true;
        let live = adjudicate(&cfg, all_powers(), &facts(), Response::Warn);
        assert_eq!(live, Sentence::Carry { response: Response::Warn, armed: true });
    }
}
