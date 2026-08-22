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
    let half_life_ms = half_life_hours.saturating_mul(3_600_000);
    strikes
        .iter()
        .map(|s| {
            let age = now_ms.saturating_sub(s.at_ms);
            // Integer halvings: cheap, monotone, and exact at the boundaries.
            let halvings = if half_life_ms == 0 { 0 } else { age / half_life_ms };
            if halvings >= 32 { 0 } else { s.worth >> halvings }
        })
        // Saturating: a total that wrapped would read as almost clean, which is
        // silent UNDER-enforcement and the worse direction to fail in.
        .fold(0u32, u32::saturating_add)
}

/// The highest step this total has reached, if any. Below the first step,
/// nothing answers to anything.
pub fn decide(ladder: &Ladder, total: u32) -> Option<Response> {
    ladder.steps.iter().rev().find(|s| total >= s.at).map(|s| s.response)
}

/// The NEXT rung to answer with, given what this member has already received.
///
/// A ladder that jumps straight to the rung a total has reached is not a
/// ladder: someone who accrued twelve points before Sentinel was armed would be
/// banned without ever having been warned, and the same is true of anyone whose
/// first observed offense is a grave one. Climbing one rung per answer means
/// every step is actually delivered, and a total that keeps rising keeps
/// climbing.
pub fn next_step(ladder: &Ladder, total: u32, already: Option<&str>) -> Option<Response> {
    let reached = decide(ladder, total)?;
    let floor = already.map(Response::rank_of).unwrap_or(0);
    ladder
        .steps
        .iter()
        .map(|s| s.response)
        .filter(|r| r.rank() > floor && r.rank() <= reached.rank())
        .min_by_key(|r| r.rank())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Gravity};

    /// Arming after a rehearsal used to fire the whole backlog at the top rung,
    /// so a member accumulated to Ban was banned without ever being warned.
    #[test]
    fn the_ladder_is_climbed_one_rung_at_a_time() {
        let l = ladder();
        // Twelve points reaches Ban, but the first answer is still a warning.
        assert_eq!(next_step(&l, 12, None), Some(Response::Warn));
        assert_eq!(next_step(&l, 12, Some("warn")), Some(Response::DeleteAndWarn));
        assert_eq!(next_step(&l, 12, Some("delete_and_warn")), Some(Response::Kick));
        assert_eq!(next_step(&l, 12, Some("kick")), Some(Response::Ban));
        assert_eq!(next_step(&l, 12, Some("ban")), None, "nothing above the top");

        // And it never climbs past what the total has actually earned.
        assert_eq!(next_step(&l, 4, Some("warn")), Some(Response::DeleteAndWarn));
        assert_eq!(next_step(&l, 4, Some("delete_and_warn")), None, "four points is not a kick");
        assert_eq!(next_step(&l, 0, None), None, "and a clean member answers to nothing");

        // An unrecognised prior ranks 0, so it never blocks the first rung.
        assert_eq!(next_step(&l, 12, Some("raid:kick")), Some(Response::Warn));
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
