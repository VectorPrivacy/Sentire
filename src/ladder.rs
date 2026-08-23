//! Strikes in, response out. Pure: no I/O, no clock reads — time arrives as an
//! argument, which is what makes every case below a table test.

use crate::config::{Ladder, Response};

/// One recorded offense, as the ladder weighs it.
#[derive(Debug, Clone, Copy)]
pub struct Strike {
    pub worth: u32,
    pub at_ms: u64,
}

/// The decayed total: each strike is worth half after the half-life, a quarter
/// after two, never negative and never rounded up. Forgiveness is built in
/// rather than being a pardon someone has to remember to issue.
pub fn total(strikes: &[Strike], now_ms: u64, half_life_hours: u64) -> u32 {
    strikes
        .iter()
        .map(|s| decay(s.worth, now_ms.saturating_sub(s.at_ms), half_life_hours))
        // Saturating: a total that wrapped would read as almost clean, which is
        // silent UNDER-enforcement and the worse direction to fail in.
        .fold(0u32, u32::saturating_add)
}

/// One value aged by the same halving the ladder forgives strikes with.
///
/// Integer halvings: cheap, monotone, and exact at the boundaries.
pub fn decay(worth: u32, age_ms: u64, half_life_hours: u64) -> u32 {
    let half_life_ms = half_life_hours.saturating_mul(3_600_000);
    let halvings = if half_life_ms == 0 { 0 } else { age_ms / half_life_ms };
    if halvings >= 32 {
        0
    } else {
        worth >> halvings
    }
}

/// The highest step this total has reached, if any. Below the first step,
/// nothing answers to anything.
pub fn decide(ladder: &Ladder, total: u32) -> Option<Response> {
    ladder.steps.iter().rev().find(|s| total >= s.at).map(|s| s.response)
}

/// What this member is owed right now, given everything on file.
///
/// The ONE answer. The enforcer and `/why` both read it, so an operator can
/// never be told about a ladder different from the one that will run.
pub fn owed(
    l: &Ladder,
    total: u32,
    prior: Option<(&str, u32, u64)>,
    can_deliver: impl Fn(Response) -> bool,
    now_ms: u64,
    half_life_hours: u64,
) -> Option<Response> {
    // The ladder climbs per OFFENSE, not per poll. A verdict re-reports every
    // standing conviction, so without this one message walks the whole ladder
    // on the clock: warn, delete, kick, ban, four polls apart.
    //
    // The answered total is aged the same way the strikes are, so the gate
    // opens again as the evidence behind it is forgiven rather than sealing the
    // member off for the life of the row.
    let answered = prior.map(|(_, at_total, at_ms)| decay(at_total, now_ms.saturating_sub(at_ms), half_life_hours));
    if total <= answered.unwrap_or(0) {
        return None;
    }
    // An answer whose evidence is fully forgiven stops flooring the ladder.
    // Otherwise a kick from March leaves a light offense in October answerable
    // only by a ban — the strikes forgive and the floor never would.
    let floor = prior.filter(|_| answered.unwrap_or(0) > 0).map(|(name, _, _)| name);
    next_step(l, total, floor, can_deliver)
}

/// The NEXT rung to answer with, given what this member has already received.
///
/// A ladder that jumps straight to the rung a total has reached is not a
/// ladder: someone who accrued twelve points before Sentinel was armed would be
/// banned without ever having been warned, and the same is true of anyone whose
/// first observed offense is a grave one. Climbing one rung per answer means
/// every step is actually delivered, and a total that keeps rising keeps
/// climbing.
/// One ledger, so one prior: the rung above whatever they last received, no
/// higher than their total has earned, skipping anything this community grants
/// no permission to deliver.
pub fn next_step(
    ladder: &Ladder,
    total: u32,
    already: Option<&str>,
    can_deliver: impl Fn(Response) -> bool,
) -> Option<Response> {
    let reached = decide(ladder, total)?;
    let floor = already.map(Response::rank_of).unwrap_or(0);
    // The OPERATOR's rungs, in order, deduped. Walking every Response meant a
    // ladder of `[warn, ban]` still delivered a delete and a kick, and a
    // one-step `[ban]` ladder took four passes to get there.
    let mut rungs: Vec<Response> = ladder.steps.iter().map(|s| s.response).collect();
    rungs.sort_by_key(|r| r.rank());
    rungs.dedup();
    for r in rungs {
        if r.rank() > reached.rank() {
            break;
        }
        // SKIPPED, not stopped at: a community that withholds MANAGE_MESSAGES
        // would otherwise pin every member below delete_and_warn forever, with
        // kick and ban structurally unreachable.
        if !can_deliver(r) {
            continue;
        }
        if floor < r.rank() {
            return Some(r);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Gravity};

    /// Arming after a rehearsal used to fire the whole backlog at the top rung,
    /// so a member accumulated to Ban was banned without ever being warned.
    /// Every rung the same answer, which is what a uniform `[arm]` block gives.

    fn all_powers(_: Response) -> bool {
        true
    }

    #[test]
    fn the_ladder_is_climbed_one_rung_at_a_time() {
        let l = ladder();
        // Twelve points reaches Ban, but the first answer is still a warning.
        assert_eq!(next_step(&l, 12, None, all_powers), Some(Response::Warn));
        assert_eq!(next_step(&l, 12, Some("warn"), all_powers), Some(Response::DeleteAndWarn));
        assert_eq!(next_step(&l, 12, Some("delete_and_warn"), all_powers), Some(Response::Kick));
        assert_eq!(next_step(&l, 12, Some("kick"), all_powers), Some(Response::Ban));
        assert_eq!(next_step(&l, 12, Some("ban"), all_powers), None, "nothing above the top");

        // And it never climbs past what the total has actually earned.
        assert_eq!(next_step(&l, 4, Some("warn"), all_powers), Some(Response::DeleteAndWarn));
        assert_eq!(next_step(&l, 4, Some("delete_and_warn"), all_powers), None, "four points is not a kick");
        assert_eq!(next_step(&l, 0, None, all_powers), None, "and a clean member answers to nothing");

        // An unrecognised prior ranks 0, so it never blocks the first rung.
        assert_eq!(next_step(&l, 12, Some("raid:kick"), all_powers), Some(Response::Warn));
    }

    /// A rung this community cannot deliver is SKIPPED, not stopped at.
    /// Stopping pinned every member below a withheld permission forever.
    #[test]
    fn a_rung_the_community_withholds_is_climbed_past() {
        let l = ladder();
        let no_hiding = |r: Response| r != Response::DeleteAndWarn;
        assert_eq!(next_step(&l, 12, Some("warn"), no_hiding), Some(Response::Kick));
        // And a community that grants nothing answers with nothing.
        assert_eq!(next_step(&l, 12, None, |_| false), None);
    }

    /// The ladder is the operator's steps, not every response that exists.
    #[test]
    fn it_climbs_the_configured_ladder_only() {
        let mut l = ladder();
        l.steps = vec![
            crate::config::Step { at: 1, response: Response::Warn },
            crate::config::Step { at: 12, response: Response::Ban },
        ];
        assert_eq!(next_step(&l, 12, None, all_powers), Some(Response::Warn));
        assert_eq!(next_step(&l, 12, Some("warn"), all_powers), Some(Response::Ban), "no rung they never configured");
    }

    fn ladder() -> Ladder {
        Config::default().ladder
    }

    #[test]
    fn three_notes_do_not_reach_a_kick() {
        let l = ladder();
        let worth = l.strikes.worth(Gravity::Note);
        let strikes: Vec<Strike> = (0..3).map(|_| Strike { worth, at_ms: 0 }).collect();
        assert_eq!(decide(&l, total(&strikes, 0, l.decay_half_life_hours)), Some(Response::Warn));
    }

    #[test]
    fn one_grave_offense_reaches_the_top_without_skipping_the_math() {
        let l = ladder();
        let strikes = [Strike { worth: l.strikes.worth(Gravity::Grave), at_ms: 0 }];
        assert_eq!(decide(&l, total(&strikes, 0, l.decay_half_life_hours)), Some(Response::Ban));
    }

    #[test]
    fn a_clean_member_answers_to_nothing() {
        assert_eq!(decide(&ladder(), 0), None);
    }

    #[test]
    fn strikes_decay_by_halves_and_reach_zero() {
        let hl = 168u64;
        let hl_ms = hl * 3_600_000;
        let s = [Strike { worth: 8, at_ms: 0 }];
        assert_eq!(total(&s, 0, hl), 8, "fresh is full");
        assert_eq!(total(&s, hl_ms - 1, hl), 8, "just under a half-life still counts whole");
        assert_eq!(total(&s, hl_ms, hl), 4, "one half-life halves");
        assert_eq!(total(&s, 3 * hl_ms, hl), 1);
        assert_eq!(total(&s, 4 * hl_ms, hl), 0, "and it ends at zero, never below");
        assert_eq!(total(&s, u64::MAX, hl), 0, "distant past cannot overflow");
    }

    #[test]
    fn escalation_is_cumulative_across_gravities() {
        let l = ladder();
        // Two serious offenses (4 + 4 = 8) reach a kick; the same pair a
        // half-life apart (4 + 2 = 6) stays at delete_and_warn.
        let hl_ms = l.decay_half_life_hours * 3_600_000;
        let fresh = [Strike { worth: 4, at_ms: hl_ms }, Strike { worth: 4, at_ms: hl_ms }];
        assert_eq!(decide(&l, total(&fresh, hl_ms, l.decay_half_life_hours)), Some(Response::Kick));
        let spread = [Strike { worth: 4, at_ms: 0 }, Strike { worth: 4, at_ms: hl_ms }];
        assert_eq!(decide(&l, total(&spread, hl_ms, l.decay_half_life_hours)), Some(Response::DeleteAndWarn));
    }
}
