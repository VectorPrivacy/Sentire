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

use crate::config::{Config, RaidResponse};

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
pub fn select(verdicts: &Verdicts, cfg: &Config, me: &str) -> Containment {
    select_from(verdicts.all(), verdicts.raid_detected(), cfg, me)
}

/// The rule itself, over anything verdict-shaped. Split out because `Verdicts`
/// has no public constructor, and the alternative was tests exercising a
/// hand-copied twin of this function — which would keep passing if the real one
/// were deleted.
pub fn select_from<'a>(
    members: impl Iterator<Item = &'a Verdict>,
    raid_detected: bool,
    cfg: &Config,
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
        .filter(|v| v.confidence >= cfg.raid.min_confidence)
        .map(|v| v.npub.clone())
        .collect();

    if suspects.is_empty() {
        return Containment::Quiet;
    }
    if roster > 0 && suspects.len() * 100 > cfg.limits.halt_if_over_pct as usize * roster {
        return Containment::Halt { suspects: suspects.len(), roster };
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

    fn verdict(npub: &str, confidence: u32, shield: &str) -> Verdict {
        Verdict {
            npub: npub.into(),
            name: npub.into(),
            confidence,
            proven: 0,
            band: "alert".into(),
            shield: shield.into(),
            reasons: vec![],
            findings: vec![],
            messages: 0,
            tenure_secs: 0,
        }
    }

    fn crowd(n: usize, confidence: u32, shield: &str) -> Vec<Verdict> {
        (0..n).map(|i| verdict(&format!("npub1raider{i:03}"), confidence, shield)).collect()
    }

    fn pick(rows: &[Verdict], raid: bool, cfg: &Config, me: &str) -> Containment {
        select_from(rows.iter(), raid, cfg, me)
    }

    fn permissive() -> Config {
        let mut cfg = Config::default();
        cfg.limits.halt_if_over_pct = 100;
        cfg
    }

    #[test]
    fn no_cohort_is_no_raid_however_busy_the_room() {
        assert_eq!(pick(&crowd(50, 99, "none"), false, &Config::default(), "me"), Containment::Quiet);
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
        let mut cfg = Config::default();
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
