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
pub fn owed<'a>(
    l: &Ladder,
    strikes: &[Strike],
    answers: impl IntoIterator<Item = (&'a str, u64)>,
    can_deliver: impl Fn(Response) -> bool,
    now_ms: u64,
    half_life_hours: u64,
) -> Option<Response> {
    let answers: Vec<(&str, u64)> = answers.into_iter().collect();

    // Has anything happened SINCE the last answer? Times, not totals: a
    // re-reported conviction keeps its original timestamp, so it is never
    // newer, while a comparison of magnitudes has to age the answered total
    // the same way the strikes age — and it cannot, because that total was a
    // sum and `>>` floors a sum more kindly than it floors its parts. Twenty
    // four notes answered with a warning silently swallowed a grave offense a
    // week later, exactly and forever.
    if let Some(last) = answers.iter().map(|(_, at)| *at).max() {
        if !strikes.iter().any(|s| s.at_ms > last) {
            return None;
        }
    }

    // Nothing to answer with below the first step.
    decide(l, total(strikes, now_ms, half_life_hours))?;

    // An answer outlives its evidence exactly as long as that evidence stands.
    // Without this a kick from March leaves a light offense in October
    // answerable only by a ban; with it, a member whose whole record has
    // decayed away starts again at a warning.
    let floor = answers
        .iter()
        .filter(|(_, at)| {
            strikes
                .iter()
                .any(|s| s.at_ms <= *at && decay(s.worth, now_ms.saturating_sub(s.at_ms), half_life_hours) > 0)
        })
        .max_by_key(|(name, _)| Response::rank_of(name))
        .map(|(name, _)| *name);

    next_step(l, total(strikes, now_ms, half_life_hours), floor, can_deliver)
}

/// The NEXT rung to answer with, given what this member has already received.
///
/// A ladder that jumps straight to the rung a total has reached is not a
/// ladder: anyone whose first observed offense is a grave one would be banned
/// without ever having been warned. So this is the rung above whatever they
/// last received, no higher than their total has earned, skipping anything this
/// community grants no permission to deliver.
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

    const HL: u64 = 168;
    const HOUR: u64 = 3_600_000;

    fn at(worth: u32, at_ms: u64) -> Strike {
        Strike { worth, at_ms }
    }

    /// The whole decision, as a table: strikes and answers in, a rung out.
    #[test]
    fn owed_answers_the_same_way_every_time() {
        let l = ladder();
        let hl = HL * HOUR;

        struct Case {
            what: &'static str,
            strikes: Vec<Strike>,
            answers: Vec<(&'static str, u64)>,
            now: u64,
            want: Option<Response>,
        }

        let cases = vec![
            Case {
                what: "nothing on file: the first answer is the bottom rung",
                strikes: vec![at(12, 0)],
                answers: vec![],
                now: 0,
                want: Some(Response::Warn),
            },
            Case {
                what: "below the first step, nothing answers to anything",
                strikes: vec![],
                answers: vec![],
                now: 0,
                want: None,
            },
            Case {
                what: "answered, and nothing new has happened",
                strikes: vec![at(12, 0)],
                answers: vec![("warn", 10)],
                now: 20,
                want: None,
            },
            Case {
                what: "a re-reported conviction keeps its time, so it is never new",
                strikes: vec![at(12, 0)],
                answers: vec![("warn", 10)],
                now: 90_000_000,
                want: None,
            },
            Case {
                what: "a new offense climbs one rung",
                strikes: vec![at(12, 0), at(12, 20)],
                answers: vec![("warn", 10)],
                now: 30,
                want: Some(Response::DeleteAndWarn),
            },
            Case {
                what: "and again",
                strikes: vec![at(12, 0), at(12, 20), at(12, 40)],
                answers: vec![("warn", 10), ("delete_and_warn", 30)],
                now: 50,
                want: Some(Response::Kick),
            },
            Case {
                what: "nothing above the top rung",
                strikes: vec![at(12, 0), at(12, 60)],
                answers: vec![("warn", 10), ("delete_and_warn", 20), ("kick", 30), ("ban", 40)],
                now: 70,
                want: None,
            },
            Case {
                what: "the grave offense that a light history used to swallow",
                strikes: {
                    let mut v: Vec<Strike> = (0..24).map(|_| at(1, 0)).collect();
                    v.push(at(12, hl));
                    v
                },
                answers: vec![("warn", 1)],
                now: hl,
                // A warning, because the notes it answered have decayed to
                // nothing and the floor goes with them. The point is that the
                // offense IS answered: it used to be swallowed for good.
                want: Some(Response::Warn),
            },
            Case {
                what: "a forgiven kick stops flooring a light offense",
                strikes: vec![at(12, 0), at(1, hl * 40)],
                answers: vec![("kick", 1)],
                now: hl * 40,
                want: Some(Response::Warn),
            },
            Case {
                what: "a standing kick still floors one",
                strikes: vec![at(12, 0), at(12, 10)],
                answers: vec![("kick", 5)],
                now: 20,
                want: Some(Response::Ban),
            },
            Case {
                what: "a prior no ladder configures floors nothing",
                strikes: vec![at(12, 0), at(12, 20)],
                answers: vec![("raid:kick", 10)],
                now: 30,
                want: Some(Response::Warn),
            },
        ];

        for c in cases {
            assert_eq!(
                owed(&l, &c.strikes, c.answers.iter().copied(), all_powers, c.now, HL),
                c.want,
                "{}",
                c.what
            );
        }
    }

    /// Whatever the record says, one call answers at most one rung above what
    /// was last delivered — so nothing can jump the ladder.
    #[test]
    fn owed_never_climbs_more_than_one_rung() {
        let l = ladder();
        for prior_rank in 0..=4u8 {
            let name = match prior_rank {
                1 => Some("warn"),
                2 => Some("delete_and_warn"),
                3 => Some("kick"),
                4 => Some("ban"),
                _ => None,
            };
            for worth in [1u32, 4, 8, 12, 50, 1000, u32::MAX / 4] {
                // A standing answer, then a fresh offense after it.
                let strikes = [at(worth, 0), at(worth, 20)];
                let answers: Vec<(&str, u64)> = name.map(|n| (n, 10u64)).into_iter().collect();
                if let Some(got) = owed(&l, &strikes, answers.iter().copied(), all_powers, 30, HL) {
                    assert!(
                        got.rank() <= prior_rank.max(1) + 1,
                        "prior {name:?} at worth {worth} answered {got:?}, which skips a rung"
                    );
                }
            }
        }
    }

    /// Absurd inputs must not panic or wrap.
    #[test]
    fn extreme_inputs_are_answered_without_arithmetic_trouble() {
        let l = ladder();
        for worth in [0, 1, u32::MAX - 1, u32::MAX] {
            for now in [0u64, 1, u64::MAX] {
                let _ = owed(&l, &[at(worth, 0)], [], all_powers, now, HL);
                let _ = owed(&l, &[at(worth, 0)], [("warn", 0u64)], all_powers, now, 1);
                let _ = owed(&l, &[at(worth, u64::MAX)], [("ban", u64::MAX)], all_powers, now, u64::MAX);
            }
        }
        // Many strikes, so the summed total saturates rather than wraps.
        let many: Vec<Strike> = (0..64).map(|_| at(u32::MAX, 0)).collect();
        let _ = owed(&l, &many, [("warn", 0u64)], all_powers, 1, HL);
    }

    /// The exact shape that used to be swallowed: an answer recorded over many
    /// small strikes ages more kindly as a SUM than its parts do individually,
    /// so comparing magnitudes silently ate a later, heavier offense — forever,
    /// because the two stayed equal at every half-life boundary.
    #[test]
    fn a_light_history_does_not_swallow_a_later_grave_offense() {
        let l = ladder();
        let hl = HL * HOUR;
        for notes in [4u32, 8, 24, 100] {
            let mut strikes: Vec<Strike> = (0..notes).map(|_| at(1, 0)).collect();
            strikes.push(at(12, hl));
            assert!(
                owed(&l, &strikes, [("warn", 1u64)], all_powers, hl, HL).is_some(),
                "{notes} notes swallowed a grave offense a week later"
            );
        }
    }

    /// And the property behind it: whatever the record, a strike that lands
    /// after the last answer is always answered by something.
    #[test]
    fn an_offense_after_the_last_answer_is_always_answered() {
        let l = ladder();
        let hl = HL * HOUR;
        for prior in ["warn", "delete_and_warn", "kick"] {
            for history in [1usize, 3, 20] {
                let mut strikes: Vec<Strike> = (0..history).map(|_| at(1, 0)).collect();
                strikes.push(at(12, hl * 2));
                assert!(
                    owed(&l, &strikes, [(prior, 1u64)], all_powers, hl * 2, HL).is_some(),
                    "prior {prior} over {history} strikes swallowed a later grave offense"
                );
            }
        }
    }

    /// A clock that steps backwards is bounded, not permanent: the offense is
    /// invisible only until one lands after the answer, and it still counts
    /// toward the total when that happens.
    #[test]
    fn a_backward_clock_delays_an_answer_rather_than_losing_it() {
        let l = ladder();
        let answered_at = 1_000_000u64;
        // The clock stepped back, so this offense reads as older than the
        // answer that preceded it.
        let stepped_back = [at(12, answered_at - 5_000), at(12, answered_at - 1_000)];
        assert_eq!(owed(&l, &stepped_back, [("warn", answered_at)], all_powers, answered_at, HL), None);

        // Once the clock has caught up, the next offense opens the gate and
        // everything it hid is in the total.
        let caught_up = [at(12, answered_at - 5_000), at(12, answered_at - 1_000), at(12, answered_at + 1)];
        assert!(owed(&l, &caught_up, [("warn", answered_at)], all_powers, answered_at + 2, HL).is_some());
    }

    /// A strike landing in the same millisecond as the answer was answered by
    /// it — that is the strike that caused it. Under-enforcing here is the
    /// safe direction, and the next offense picks it up.
    #[test]
    fn a_strike_in_the_same_millisecond_as_its_answer_is_not_new() {
        let l = ladder();
        assert_eq!(owed(&l, &[at(12, 500)], [("warn", 500u64)], all_powers, 600, HL), None);
        assert!(owed(&l, &[at(12, 500), at(12, 501)], [("warn", 500u64)], all_powers, 600, HL).is_some());
    }

    /// Decay is monotone and never negative.
    #[test]
    fn decay_only_ever_falls() {
        let mut last = u32::MAX;
        for halvings in 0..40u64 {
            let got = decay(1000, halvings * HL * HOUR, HL);
            assert!(got <= last, "decay rose from {last} to {got} at {halvings} half-lives");
            last = got;
        }
        assert_eq!(last, 0, "and reaches zero");
        assert_eq!(decay(1000, u64::MAX, HL), 0);
        assert_eq!(decay(0, 0, HL), 0);
        assert_eq!(decay(1000, 0, HL), 1000, "no age, no decay");
    }

    /// A zero half-life cannot divide by zero.
    #[test]
    fn a_zero_half_life_does_not_divide_by_zero() {
        assert_eq!(decay(12, 1_000_000, 0), 12, "nothing decays, and nothing panics");
    }
}

