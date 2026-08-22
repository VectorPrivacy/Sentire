//! The live tripwire: how Sentinel notices a wave in seconds instead of on the
//! next sweep.
//!
//! The engine's verdict is memoised for 90 seconds, which is right for a
//! background pass and far too slow for a raid in progress. Two minutes of
//! spam before anyone answers is not moderation.
//!
//! So the live stream is watched as a **trigger**, never as a judge. Many
//! distinct accounts talking at once, or many joining at once, trips this and
//! Sentinel evaluates immediately. What happens next is the engine's call as
//! always — the tripwire only decides WHEN to ask, never WHO is guilty. Keeping
//! those separate is what stops a second, sloppier detector growing here beside
//! the real one.

use std::collections::{HashMap, HashSet, VecDeque};

/// One live arrival: who, and when.
#[derive(Debug, Clone, Copy)]
struct Ping {
    /// Cheap identity — a hash of the npub, since the tripwire counts DISTINCT
    /// actors and never needs to name one.
    who: u64,
    at_ms: u64,
}

pub struct Tripwire {
    /// Distinct actors inside the window that trip it.
    threshold: usize,
    window_ms: u64,
    /// Never trip more often than this: an evaluation is a full corpus read,
    /// and a sustained raid would otherwise ask for one per message.
    cooldown_ms: u64,
    pings: VecDeque<Ping>,
    /// Distinct actors currently in the window, counted incrementally. Rebuilding
    /// this per message was O(n log n) — worst exactly when a wave arrives.
    live: HashMap<u64, usize>,
    last_trip_ms: u64,
    /// Members the engine has already vouched for, refreshed by every sweep.
    /// A raid is STRANGERS: ten regulars talking is the least raid-shaped thing
    /// there is, and counting them fires a full corpus read a minute for as
    /// long as the room stays lively.
    known: HashSet<u64>,
}

fn identity(npub: &str) -> u64 {
    // FNV-1a: distinctness is all that is needed, and it costs nothing.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in npub.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

impl Tripwire {
    pub fn new(threshold: usize, window_secs: u64, cooldown_secs: u64) -> Self {
        Tripwire {
            threshold: threshold.max(2),
            window_ms: window_secs.max(1) * 1000,
            cooldown_ms: cooldown_secs * 1000,
            pings: VecDeque::new(),
            live: HashMap::new(),
            last_trip_ms: 0,
            known: HashSet::new(),
        }
    }

    /// Replace the vouched-for set. Called after each evaluation, so the
    /// tripwire's idea of "regular" is the engine's, never its own guess.
    pub fn trust(&mut self, npubs: impl IntoIterator<Item = impl AsRef<str>>) {
        self.known = npubs.into_iter().map(|n| identity(n.as_ref())).collect();
    }

    /// Record an arrival. True means "evaluate now".
    ///
    /// A trusted member is not recorded at all: they cost nothing to ignore and
    /// they are the opposite of the signal being watched for.
    pub fn observe(&mut self, npub: &str, at_ms: u64) -> bool {
        let who = identity(npub);
        if self.known.contains(&who) {
            return false;
        }
        let cutoff = at_ms.saturating_sub(self.window_ms);
        while self.pings.front().is_some_and(|p| p.at_ms < cutoff) {
            let gone = self.pings.pop_front().expect("front was just checked");
            if let Some(n) = self.live.get_mut(&gone.who) {
                *n -= 1;
                if *n == 0 {
                    self.live.remove(&gone.who);
                }
            }
        }
        self.pings.push_back(Ping { who, at_ms });
        *self.live.entry(who).or_insert(0) += 1;

        if self.live.len() < self.threshold {
            return false;
        }
        // A sustained wave must not ask for one full evaluation per message.
        if self.last_trip_ms != 0 && at_ms.saturating_sub(self.last_trip_ms) < self.cooldown_ms {
            return false;
        }
        self.last_trip_ms = at_ms;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One person talking fast is a conversation, not a raid. The tripwire
    /// counts DISTINCT actors for exactly this reason.
    #[test]
    fn one_excited_member_never_trips_it() {
        let mut t = Tripwire::new(5, 30, 60);
        for i in 0..50 {
            assert!(!t.observe("npub1chatty", i * 100), "message {i}");
        }
    }

    #[test]
    fn five_distinct_accounts_inside_the_window_trip_it() {
        let mut t = Tripwire::new(5, 30, 60);
        for i in 0..4 {
            assert!(!t.observe(&format!("npub1raider{i}"), i * 1000));
        }
        assert!(t.observe("npub1raider4", 4000), "the fifth distinct account trips it");
    }

    /// The same five spread over an afternoon are a healthy room.
    #[test]
    fn a_slow_conversation_falls_out_of_the_window() {
        let mut t = Tripwire::new(5, 30, 60);
        for i in 0..10u64 {
            // One message per minute, against a 30s window.
            assert!(!t.observe(&format!("npub1member{i}"), i * 60_000), "minute {i}");
        }
    }

    /// An evaluation is a full corpus read. A sustained wave must not ask for
    /// one per message.
    #[test]
    fn a_sustained_wave_asks_once_per_cooldown() {
        let mut t = Tripwire::new(3, 30, 60);
        let mut trips = 0;
        for i in 0..100u64 {
            if t.observe(&format!("npub1raider{}", i % 20), i * 1000) {
                trips += 1;
            }
        }
        // 100 seconds of raid against a 60s cooldown: the opening trip and one more.
        assert_eq!(trips, 2, "one evaluation per cooldown, not one per message");
    }

    /// The case this exists for: a busy room full of regulars, plus one
    /// newcomer settling in. Nothing here is raid-shaped, and firing a full
    /// corpus read every minute for it is pure waste.
    #[test]
    fn a_lively_room_of_regulars_never_wakes_the_engine() {
        let mut t = Tripwire::new(5, 30, 60);
        let regulars: Vec<String> = (0..10).map(|i| format!("npub1regular{i}")).collect();
        t.trust(&regulars);

        for round in 0..5u64 {
            for (i, who) in regulars.iter().enumerate() {
                assert!(!t.observe(who, round * 2000 + i as u64 * 100), "regulars talking is not a raid");
            }
        }
        // And one new member casually joining in stays far under the bar.
        assert!(!t.observe("npub1newcomer", 12_000), "one unknown among ten regulars is not a wave");
    }

    /// Trust is not immunity from the tripwire's PURPOSE: strangers still count.
    #[test]
    fn regulars_do_not_hide_a_wave_happening_beside_them() {
        let mut t = Tripwire::new(5, 30, 60);
        t.trust(["npub1regular0", "npub1regular1"]);
        for i in 0..4 {
            assert!(!t.observe(&format!("npub1raider{i}"), i * 500));
            // Regular chatter interleaved changes nothing either way.
            assert!(!t.observe("npub1regular0", i * 500 + 100));
        }
        assert!(t.observe("npub1raider4", 4000), "five strangers is still five strangers");
    }

    /// The distinct count is maintained incrementally, so it has to agree with
    /// a recount after arbitrary churn.
    #[test]
    fn the_incremental_count_matches_a_recount() {
        let mut t = Tripwire::new(1000, 10, 0);
        for i in 0..500u64 {
            t.observe(&format!("npub1a{}", i % 7), i * 100);
        }
        let recount: std::collections::HashSet<u64> = t.pings.iter().map(|p| p.who).collect();
        assert_eq!(t.live.len(), recount.len(), "incremental count drifted from the truth");
        assert!(t.live.values().all(|n| *n > 0), "a zeroed actor must be removed, not kept at zero");
    }

    #[test]
    fn the_window_is_a_sliding_one_not_a_bucket() {
        let mut t = Tripwire::new(3, 10, 0);
        assert!(!t.observe("a", 0));
        assert!(!t.observe("b", 9_000));
        // `a` has aged out by now, so this is only the second distinct actor.
        assert!(!t.observe("c", 11_000));
        assert!(t.observe("d", 12_000), "b, c and d are three inside the window");
    }
}
