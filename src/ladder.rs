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
        .sum()
}

/// The highest step this total has reached, if any. Below the first step,
/// nothing answers to anything.
pub fn decide(ladder: &Ladder, total: u32) -> Option<Response> {
    ladder.steps.iter().rev().find(|s| total >= s.at).map(|s| s.response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Gravity};

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
