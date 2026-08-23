//! Raid containment: the one path that is not the ladder.
//!
//! A raid is a single event, not forty members each earning strikes. Waiting
//! for a ladder to escalate through warnings while a hundred fresh accounts
//! post the same line is the wrong shape entirely, so a detected raid elevates
//! straight to whatever response the operator chose.
//!
//! It is also the one place Sentinel acts on INFERENCE. A cohort reads high
//! confidence and zero proven: nobody can replay it, and the engine's rule is
//! that inference may not sentence. Arming `[arm] raid` is the operator
//! overriding that deliberately, for this case, in writing. It is false by
//! default and the code below refuses to move without it.

use vector_sdk::policy::{Verdict, Verdicts};
#[cfg(test)]
use crate::config::Config;

use crate::config::RaidResponse;
use crate::policy::CommunityPolicy;

/// The engine's built-in rule that says "this member is part of the wave".
///
/// `raid_detected` is community-wide: it means a cohort exists SOMEWHERE. A
/// member's own cohort finding is the only thing that puts them in it.
///
/// This is the id the SHIPPED defaults use. A community that forks the default
/// policy and renames its cohort rule still produces cohort evidence — so
/// `raid_detected` stays true while nobody matches here and containment goes
/// quiet on a real raid. Failing to Quiet is the safe direction, and a verdict
/// exposes no cohort flag to key on instead; it is a limit, not a choice.
const COHORT_RULE: &str = "cohort";

/// Is this member part of the wave, rather than merely a high score?
///
/// The finding must be inference. Containment exists to answer what nobody can
/// replay; a deterministic conviction under the same rule id is a word rule an
/// operator happened to name `cohort`, and it answers to the ladder.
fn in_the_cohort(v: &Verdict) -> bool {
    v.findings.iter().any(|f| f.rule_id == COHORT_RULE && !f.is_proven())
}

/// What one pass decided about a suspected raid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Containment {
    /// No cohort, or nobody over the bar.
    Quiet,
    /// Suspects found, but the operator has not armed containment.
    WouldContain { suspects: Vec<String>, response: RaidResponse },
    /// Too much of the community. A bug, a false positive, or a raid so large
    /// that a person should be the one to answer it.
    Halt { suspects: usize, roster: usize },
    Contain { suspects: Vec<String>, response: RaidResponse },
}

/// Who this pass would contain. Pure: verdicts and config in, a decision out.
///
/// Shields gate here exactly as they do everywhere else. A raid is the loudest
/// reason to reach for a mass action and the worst possible time to catch a
/// regular in one.
pub fn select(verdicts: &Verdicts, cfg: &CommunityPolicy, me: &str) -> Containment {
    select_from(verdicts.all(), verdicts.raid_detected(), cfg, me)
}

/// The rule itself, over anything verdict-shaped. Split out because `Verdicts`
/// has no public constructor, and the alternative was tests exercising a
/// hand-copied twin of this function — which would keep passing if the real one
/// were deleted.
pub fn select_from<'a>(
    members: impl Iterator<Item = &'a Verdict>,
    raid_detected: bool,
    cfg: &CommunityPolicy,
    me: &str,
) -> Containment {
    if !raid_detected {
        return Containment::Quiet;
    }
    let all: Vec<&Verdict> = members.collect();
    let roster = all.len();
    let suspects: Vec<String> = all
        .iter()
        .filter(|v| v.npub != me)
        .filter(|v| !v.is_shielded())
        // In the wave, not merely loud. `raid_detected` says a cohort exists
        // somewhere; without this an ordinary member mid-ladder — someone the
        // ladder has answered with a warning — was removed as a raider the
        // moment three throwaway accounts posted the same line.
        .filter(|v| in_the_cohort(v))
        .filter(|v| v.confidence >= cfg.raid.min_confidence)
        .map(|v| v.npub.clone())
        .collect();

    if suspects.is_empty() {
        return Containment::Quiet;
    }
    // The same floor the ladder's ceiling uses. Without it, 10% of a five-member
    // community rounds to zero and ONE suspect halts containment — trivially
    // triggerable, and it flooded the mod channel every sweep.
    if let Some(ceiling) = crate::adjudicate::roster_ceiling(cfg, roster) {
        if suspects.len() > ceiling {
            return Containment::Halt { suspects: suspects.len(), roster };
        }
    }
    if cfg.arm.raid {
        Containment::Contain { suspects, response: cfg.raid.response }
    } else {
        Containment::WouldContain { suspects, response: cfg.raid.response }
    }
}

/// Ban chunk size. The wire caps a banlist at 500 entries and rejects an
/// over-cap batch WHOLE, so a wave larger than that has to arrive in pieces.
pub const BAN_CHUNK: usize = 100;

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule: &str, basis: &str) -> vector_sdk::policy::Finding {
        vector_sdk::policy::Finding {
            conviction_id: format!("{rule}-1"),
            policy_hash: String::new(),
            rule_id: rule.into(),
            scope: "whole".into(),
            basis: basis.into(),
            severity: "severe".into(),
            stateless: false,
            rung: 0,
            hits: 1,
            weight: 0,
            detail: vec![],
            messages: vec![],
            citation_count: 0,
        }
    }

    fn verdict(npub: &str, confidence: u32, shield: &str) -> Verdict {
        with_findings(npub, confidence, shield, vec![finding(COHORT_RULE, "heuristic")])
    }

    fn with_findings(
        npub: &str,
        confidence: u32,
        shield: &str,
        findings: Vec<vector_sdk::policy::Finding>,
    ) -> Verdict {
        Verdict {
            npub: npub.into(),
            name: npub.into(),
            confidence,
            proven: 0,
            band: "alert".into(),
            shield: shield.into(),
            reasons: vec![],
            findings,
            messages: 0,
            tenure_secs: 0,
        }
    }

    fn crowd(n: usize, confidence: u32, shield: &str) -> Vec<Verdict> {
        (0..n).map(|i| verdict(&format!("npub1raider{i:03}"), confidence, shield)).collect()
    }

    fn pick(rows: &[Verdict], raid: bool, cfg: &CommunityPolicy, me: &str) -> Containment {
        select_from(rows.iter(), raid, cfg, me)
    }

    fn base() -> CommunityPolicy {
        Config::default().for_community("aa")
    }

    fn permissive() -> CommunityPolicy {
        let mut cfg = base();
        cfg.limits.halt_if_over_pct = 100;
        cfg
    }

    /// The bug this filter exists for. `raid_detected` is community-wide, so
    /// three throwaway accounts posting the same line used to make every
    /// high-scoring member a raider — including someone the ladder had just
    /// answered with a warning, removed with every rung skipped.
    #[test]
    fn a_loud_member_who_is_not_in_the_cohort_is_not_contained() {
        let mut cfg = permissive();
        cfg.arm.raid = true;
        let mut rows = crowd(3, 90, "none");
        rows.push(with_findings(
            "npub1regular",
            95,
            "none",
            vec![finding("slurs", "deterministic")],
        ));

        match pick(&rows, true, &cfg, "me") {
            Containment::Contain { suspects, .. } => {
                assert_eq!(suspects.len(), 3, "the wave, and only the wave");
                assert!(
                    !suspects.iter().any(|s| s == "npub1regular"),
                    "a member the ladder is already handling is not a raider"
                );
            }
            other => panic!("expected containment of the cohort, got {other:?}"),
        }
    }

    /// Containment answers what nobody can replay. A deterministic conviction
    /// under a rule an operator happened to name `cohort` is a word rule.
    #[test]
    fn a_deterministic_cohort_rule_does_not_reach_containment() {
        let mut cfg = permissive();
        cfg.arm.raid = true;
        let rows = vec![with_findings("npub1a", 99, "none", vec![finding(COHORT_RULE, "deterministic")])];
        assert_eq!(pick(&rows, true, &cfg, "me"), Containment::Quiet);
    }

    #[test]
    fn no_cohort_is_no_raid_however_busy_the_room() {
        assert_eq!(pick(&crowd(50, 99, "none"), false, &base(), "me"), Containment::Quiet);
    }

    #[test]
    fn containment_is_rehearsed_until_it_is_armed() {
        let mut cfg = permissive();
        match pick(&crowd(10, 90, "none"), true, &cfg, "me") {
            Containment::WouldContain { suspects, .. } => assert_eq!(suspects.len(), 10),
            other => panic!("an unarmed Sentinel must only rehearse, got {other:?}"),
        }
        cfg.arm.raid = true;
        assert!(matches!(pick(&crowd(10, 90, "none"), true, &cfg, "me"), Containment::Contain { .. }));
    }

    /// The worst possible moment to catch a regular in a mass action.
    #[test]
    fn standing_survives_a_raid() {
        let mut cfg = permissive();
        cfg.arm.raid = true;
        let mut all = crowd(5, 95, "none");
        all.extend(crowd(3, 95, "trusted"));
        all.extend(crowd(1, 95, "protected"));
        match pick(&all, true, &cfg, "me") {
            Containment::Contain { suspects, .. } => assert_eq!(suspects.len(), 5, "only the unshielded"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_pass_that_would_empty_the_community_stops_and_asks() {
        let mut cfg = base();
        cfg.arm.raid = true; // even armed
        assert_eq!(
            pick(&crowd(50, 99, "none"), true, &cfg, "me"),
            Containment::Halt { suspects: 50, roster: 50 }
        );
    }

    #[test]
    fn a_quiet_cohort_below_the_bar_convicts_nobody() {
        let mut cfg = permissive();
        cfg.arm.raid = true;
        assert_eq!(pick(&crowd(10, 40, "none"), true, &cfg, "me"), Containment::Quiet);
    }

    #[test]
    fn sentinel_never_contains_itself() {
        let mut cfg = permissive();
        cfg.arm.raid = true;
        let mut all = crowd(2, 95, "none");
        all.push(verdict("npub1sentinel", 99, "none"));
        match pick(&all, true, &cfg, "npub1sentinel") {
            Containment::Contain { suspects, .. } => assert!(!suspects.iter().any(|s| s == "npub1sentinel")),
            other => panic!("{other:?}"),
        }
    }

    /// `is_shielded()` is the SDK's own predicate, and `indeterminate` is
    /// explicitly NOT standing — tenure could not be established, and such a
    /// member is judged exactly as if unshielded.
    #[test]
    fn indeterminate_is_not_standing() {
        let mut cfg = permissive();
        cfg.arm.raid = true;
        match pick(&crowd(4, 95, "indeterminate"), true, &cfg, "me") {
            Containment::Contain { suspects, .. } => assert_eq!(suspects.len(), 4),
            other => panic!("unknown tenure must not shield anyone, got {other:?}"),
        }
    }
}
