//! What Sentinel remembers: strikes and the actions it took. One SQLite file
//! beside the config.
//!
//! ONE ledger for rehearsals and real actions alike. Arming a class wipes the
//! community's slate, so no read ever has to ask which space a row is in.

use std::sync::Mutex;

use rusqlite::Connection;

use crate::ladder::Strike;

const SCHEMA_VERSION: i64 = 2;

const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS armed (community TEXT PRIMARY KEY, classes TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS strikes (
    community     TEXT NOT NULL,
    subject       TEXT NOT NULL,
    conviction_id TEXT NOT NULL,
    worth         INTEGER NOT NULL,
    at_ms         INTEGER NOT NULL,
    evidence      TEXT NOT NULL DEFAULT '',
    -- A forgiven strike stays as a tombstone. The engine re-reports a standing
    -- conviction for as long as its evidence sits in the window, so a deleted
    -- row is re-inserted within one poll at full worth and a fresh timestamp:
    -- the pardon would raise the total it was meant to clear.
    pardoned      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (community, subject, conviction_id)
);
CREATE TABLE IF NOT EXISTS actions (
    community TEXT NOT NULL,
    subject   TEXT NOT NULL,
    response  TEXT NOT NULL,
    at_ms     INTEGER NOT NULL,
    evidence  TEXT NOT NULL DEFAULT '',
    -- The total this answered. The ladder climbs per OFFENSE, so a rung is
    -- owed only once the total rises above the one already answered.
    at_total  INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS classifications (
    content_hash TEXT NOT NULL,
    model        TEXT NOT NULL,
    verdict      TEXT NOT NULL,
    at_ms        INTEGER NOT NULL,
    PRIMARY KEY (content_hash, model)
);
CREATE INDEX IF NOT EXISTS idx_strikes_prune ON strikes(at_ms);
CREATE INDEX IF NOT EXISTS idx_actions_subject ON actions(community, subject, at_ms);
CREATE INDEX IF NOT EXISTS idx_actions_hour ON actions(community, at_ms);";

pub struct Store {
    conn: Mutex<Connection>,
}

/// One answer already given, and the total it answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub response: String,
    pub at_total: u32,
    pub at_ms: u64,
}

impl Store {
    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn open(path: &str) -> Result<Store, String> {
        let conn = Connection::open(path).map_err(|e| format!("{path}: {e}"))?;
        conn.execute_batch(SCHEMA).map_err(|e| e.to_string())?;
        let stored: i64 = conn
            .query_row("SELECT value FROM meta WHERE key = 'schema'", [], |r| r.get(0))
            .unwrap_or(SCHEMA_VERSION);
        if stored > SCHEMA_VERSION {
            return Err(format!("{path} was written by a newer Sentinel (schema {stored} > {SCHEMA_VERSION})"));
        }
        if stored < SCHEMA_VERSION {
            // The ledger is derived state: the engine re-reports every standing
            // conviction, so a rebuilt slate costs one poll. Migrating it would
            // cost a migration path per release for nothing.
            conn.execute_batch("DROP TABLE IF EXISTS strikes; DROP TABLE IF EXISTS actions;")
                .map_err(|e| e.to_string())?;
            conn.execute_batch(SCHEMA).map_err(|e| e.to_string())?;
        }
        conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('schema', ?1)", [SCHEMA_VERSION])
            .map_err(|e| e.to_string())?;
        Ok(Store { conn: Mutex::new(conn) })
    }

    /// Record one conviction. True when it was NEW.
    ///
    /// Verdicts are cumulative — every poll re-reports every standing
    /// conviction — so the conviction id is the line between an offense and an
    /// echo of one.
    pub fn record(
        &self,
        community: &str,
        subject: &str,
        conviction_id: &str,
        worth: u32,
        at_ms: u64,
        evidence: &str,
    ) -> Result<bool, String> {
        let n = self
            .lock()
            .execute(
                "INSERT OR IGNORE INTO strikes (community, subject, conviction_id, worth, at_ms, evidence)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![community, subject, conviction_id, worth, at_ms as i64, evidence],
            )
            .map_err(|e| e.to_string())?;
        Ok(n > 0)
    }

    pub fn strikes(&self, community: &str, subject: &str) -> Result<Vec<Strike>, String> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare("SELECT worth, at_ms FROM strikes WHERE community = ?1 AND subject = ?2 AND pardoned = 0")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(rusqlite::params![community, subject], |r| {
                Ok(Strike { worth: r.get::<_, i64>(0)? as u32, at_ms: r.get::<_, i64>(1)? as u64 })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
    }

    /// What this member's strikes were for, newest first, capped.
    pub fn evidence(&self, community: &str, subject: &str) -> Result<Vec<String>, String> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare(
                "SELECT evidence, MAX(at_ms) AS t FROM strikes WHERE community = ?1 AND subject = ?2 \
                 AND pardoned = 0 AND evidence != '' GROUP BY evidence ORDER BY t DESC, evidence LIMIT 3",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(rusqlite::params![community, subject], |r| r.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        Ok(rows.flatten().collect())
    }

    /// Record an answer. `at_total` is the decayed total it answered, which is
    /// what makes the next rung owed only once the total rises above it.
    pub fn log_action(
        &self,
        community: &str,
        subject: &str,
        response: &str,
        at_ms: u64,
        at_total: u32,
        evidence: &str,
    ) -> Result<(), String> {
        self.lock()
            .execute(
                "INSERT INTO actions (community, subject, response, at_ms, at_total, evidence) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![community, subject, response, at_ms as i64, at_total, evidence],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// The strongest answer this member has already had, with the total it
    /// answered and when.
    ///
    /// Strongest, not latest: ordering by time let a later, lesser response
    /// reopen them to everything above it. Ranking happens in Rust so the
    /// severity order lives in exactly one place.
    pub fn strongest_response(&self, community: &str, subject: &str) -> Result<Option<Answer>, String> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare("SELECT response, at_total, at_ms FROM actions WHERE community = ?1 AND subject = ?2")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(rusqlite::params![community, subject], |r| {
                Ok(Answer {
                    response: r.get::<_, String>(0)?,
                    at_total: r.get::<_, i64>(1)? as u32,
                    at_ms: r.get::<_, i64>(2)? as u64,
                })
            })
            .map_err(|e| e.to_string())?;
        let mut best: Option<Answer> = None;
        for a in rows.flatten() {
            let rank = crate::config::Response::rank_of(&a.response);
            if rank > best.as_ref().map(|b| crate::config::Response::rank_of(&b.response)).unwrap_or(0) {
                best = Some(a);
            }
        }
        Ok(best)
    }

    /// Distinct people actioned here in the last hour, excluding one.
    ///
    /// People, not rows: the ladder climbs, so one member spends several rows
    /// and a row count tripped a guard sized for several members. Excluding the
    /// subject lets someone already inside the bound still be escalated.
    pub fn subjects_actioned_last_hour(
        &self,
        community: &str,
        now_ms: u64,
        except: &str,
    ) -> Result<usize, String> {
        let since = now_ms.saturating_sub(3_600_000) as i64;
        self.lock()
            .query_row(
                "SELECT COUNT(DISTINCT subject) FROM actions WHERE community = ?1 AND at_ms >= ?2 \
                 AND subject != ?3 AND response NOT LIKE 'raid:%'",
                rusqlite::params![community, since, except],
                |r| r.get::<_, i64>(0).map(|n| n as usize),
            )
            .map_err(|e| e.to_string())
    }

    pub fn actions_last_hour(&self, community: &str, now_ms: u64) -> Result<usize, String> {
        let since = now_ms.saturating_sub(3_600_000) as i64;
        self.lock()
            .query_row(
                "SELECT COUNT(*) FROM actions WHERE community = ?1 AND at_ms >= ?2 AND response NOT LIKE 'raid:%'",
                rusqlite::params![community, since],
                |r| r.get::<_, i64>(0).map(|n| n as usize),
            )
            .map_err(|e| e.to_string())
    }

    /// People CONTAINED here in the last hour.
    ///
    /// Containment's own budget. The ladder's count deliberately excludes raid
    /// rows, so reading it here measured an unrelated quantity: a raid ceiling
    /// that could never see a raid, and that a single warning switched off.
    /// Claims are excluded — a claim is a reservation, not a removal.
    pub fn contained_last_hour(&self, community: &str, now_ms: u64) -> Result<usize, String> {
        let since = now_ms.saturating_sub(3_600_000) as i64;
        self.lock()
            .query_row(
                "SELECT COUNT(DISTINCT subject) FROM actions WHERE community = ?1 AND at_ms >= ?2 \
                 AND response LIKE 'raid:%' AND response != 'raid:claim'",
                rusqlite::params![community, since],
                |r| r.get::<_, i64>(0).map(|n| n as usize),
            )
            .map_err(|e| e.to_string())
    }

    /// Everyone carrying a strike here. The sweep's own population is whatever
    /// the engine reported, which never includes a media-only offender.
    pub fn subjects_with_strikes(&self, community: &str) -> Result<Vec<String>, String> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare(
                "SELECT subject FROM strikes WHERE community = ?1 AND pardoned = 0 \
                 GROUP BY subject ORDER BY MIN(at_ms), subject",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(rusqlite::params![community], |r| r.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        Ok(rows.flatten().collect())
    }

    /// Has this member already been contained in this wave?
    ///
    /// A raid stays detected while its evidence sits in the window, so without
    /// this every sweep re-contains — which for bans is a key rotation each
    /// time. Expires, so next week's raid by the same accounts is a new event.
    pub fn claim(&self, community: &str, key: &str, at_ms: u64, ttl_ms: u64) -> Result<bool, String> {
        let conn = self.lock();
        conn.execute(
            "DELETE FROM actions WHERE community = ?1 AND subject = ?2 AND response = 'raid:claim' AND at_ms < ?3",
            rusqlite::params![community, key, at_ms.saturating_sub(ttl_ms) as i64],
        )
        .map_err(|e| e.to_string())?;
        let held: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM actions WHERE community = ?1 AND subject = ?2 AND response = 'raid:claim'",
                rusqlite::params![community, key],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if held > 0 {
            return Ok(false);
        }
        conn.execute(
            "INSERT INTO actions (community, subject, response, at_ms, evidence) VALUES (?1, ?2, 'raid:claim', ?3, '')",
            rusqlite::params![community, key, at_ms as i64],
        )
        .map_err(|e| e.to_string())?;
        Ok(true)
    }

    /// Give a claim back, so a containment that did nothing can be retried.
    pub fn release(&self, community: &str, key: &str) -> Result<(), String> {
        self.lock()
            .execute(
                "DELETE FROM actions WHERE community = ?1 AND subject = ?2 AND response = 'raid:claim'",
                rusqlite::params![community, key],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// What a model said about this blob. Keyed on the plaintext hash, so forty
    /// accounts posting one image cost a single call.
    pub fn cached_verdict(&self, content_hash: &str, model: &str) -> Option<String> {
        use rusqlite::OptionalExtension;
        self.lock()
            .query_row(
                "SELECT verdict FROM classifications WHERE content_hash = ?1 AND model = ?2",
                rusqlite::params![content_hash, model],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten()
    }

    pub fn cache_verdict(&self, content_hash: &str, model: &str, verdict: &str, at_ms: u64) -> Result<(), String> {
        self.lock()
            .execute(
                "INSERT OR REPLACE INTO classifications (content_hash, model, verdict, at_ms) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![content_hash, model, verdict, at_ms as i64],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Note what is armed here, wiping the slate if it changed.
    ///
    /// This is the whole reason there is one ledger. A rehearsal records what
    /// it WOULD have done so the operator sees the run they are arming, and
    /// arming starts clean, so nobody carries a rehearsed backlog into the run
    /// that would deliver it.
    ///
    /// ONE transaction. As two calls the destructive half came second, so a
    /// failure between them left the new arming noted and the slate never
    /// wiped — permanently, since every later boot then read no change.
    ///
    /// True when the arming changed and the slate was wiped.
    pub fn note_armed(&self, community: &str, classes: &str) -> Result<bool, String> {
        use rusqlite::OptionalExtension;
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let seen: Option<String> = tx
            .query_row("SELECT classes FROM armed WHERE community = ?1", [community], |r| r.get(0))
            .optional()
            .map_err(|e| e.to_string())?;
        let changed = seen.as_deref().is_some_and(|s| s != classes);
        if changed {
            tx.execute("DELETE FROM strikes WHERE community = ?1", [community]).map_err(|e| e.to_string())?;
            tx.execute("DELETE FROM actions WHERE community = ?1", [community]).map_err(|e| e.to_string())?;
        }
        tx.execute(
            "INSERT OR REPLACE INTO armed (community, classes) VALUES (?1, ?2)",
            rusqlite::params![community, classes],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(changed)
    }

    /// Clear one member's record. The undo an operator needs when Sentinel is
    /// wrong about somebody.
    pub fn pardon(&self, community: &str, subject: &str) -> Result<usize, String> {
        let conn = self.lock();
        // Tombstoned, not deleted. The engine re-reports a standing conviction
        // for as long as its evidence sits in the window, so a deleted row is
        // re-inserted within one poll at full worth and a fresh timestamp —
        // the pardon would raise the total it was asked to clear. `record` is
        // INSERT OR IGNORE, so the tombstone survives every later poll.
        let n = conn
            .execute(
                "UPDATE strikes SET pardoned = 1 WHERE community = ?1 AND subject = ?2 AND pardoned = 0",
                rusqlite::params![community, subject],
            )
            .map_err(|e| e.to_string())?;
        conn.execute("DELETE FROM actions WHERE community = ?1 AND subject = ?2", rusqlite::params![community, subject])
            .map_err(|e| e.to_string())?;
        // A claim keys on a scoped form of the npub, so a bare match leaves it
        // behind — and a pardoned member who keeps one can never be contained.
        conn.execute(
            "DELETE FROM actions WHERE community = ?1 AND response = 'raid:claim' \
             AND (subject = ?2 OR subject LIKE '%:' || ?2)",
            rusqlite::params![community, subject],
        )
        .map_err(|e| e.to_string())?;
        Ok(n)
    }

    /// Drop what can no longer matter. A strike past 32 halvings is worth zero
    /// and still costs a row in every total.
    pub fn prune(&self, before_ms: u64) -> Result<usize, String> {
        let conn = self.lock();
        let a = conn
            .execute("DELETE FROM strikes WHERE at_ms < ?1", [before_ms as i64])
            .map_err(|e| e.to_string())?;
        let b = conn
            .execute("DELETE FROM actions WHERE at_ms < ?1", [before_ms as i64])
            .map_err(|e| e.to_string())?;
        Ok(a + b)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn mem() -> Store {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        Store { conn: Mutex::new(conn) }
    }

    /// The dedup that keeps one swear from becoming a ban in eight minutes:
    /// every poll re-reports the same conviction, and only the first lands.
    #[test]
    fn a_reported_conviction_lands_once_however_often_it_echoes() {
        let s = mem();
        assert!(s.record("c", "npub1a", "conv1", 2, 1000, "swore").unwrap());
        for _ in 0..5 {
            assert!(!s.record("c", "npub1a", "conv1", 2, 1000, "swore").unwrap());
        }
        assert_eq!(s.strikes("c", "npub1a").unwrap().len(), 1);
        // A rung escalation mints a new id, and THAT lands.
        assert!(s.record("c", "npub1a", "conv1-rung2", 2, 2000, "kept swearing").unwrap());
        assert_eq!(s.strikes("c", "npub1a").unwrap().len(), 2);
    }

    #[test]
    fn strikes_are_scoped_to_their_community() {
        let s = mem();
        s.record("c1", "npub1a", "conv1", 4, 0, "").unwrap();
        assert!(s.strikes("c2", "npub1a").unwrap().is_empty(), "a strike elsewhere is not a strike here");
    }

    /// Ordering by time let a later, lesser response reopen a member to
    /// everything above it.
    #[test]
    fn the_strongest_response_wins_not_the_latest() {
        let s = mem();
        s.log_action("c", "npub1a", "kick", 1000, 0, "").unwrap();
        s.log_action("c", "npub1a", "warn", 2000, 0, "").unwrap();
        assert_eq!(s.strongest_response("c", "npub1a").unwrap().map(|a| a.response).as_deref(), Some("kick"));
    }

    /// Raid rows share the table and must never read as a ladder response: an
    /// unarmed raid stamping "kick" on every suspect would immunise all of them.
    #[test]
    fn a_raid_row_is_not_a_ladder_response() {
        let s = mem();
        s.log_action("c", "npub1a", "raid:kick", 0, 0, "").unwrap();
        assert_eq!(s.strongest_response("c", "npub1a").unwrap(), None);
        assert_eq!(s.actions_last_hour("c", 1000).unwrap(), 0, "and answers to its own bound");
        assert_eq!(s.contained_last_hour("c", 1000).unwrap(), 1, "which is this one");
    }

    /// The two bounds must not read each other's rows. Containment measured by
    /// the ladder's counter could never see a containment, so its ceiling was
    /// always zero-based; and one warning switched containment off for an hour.
    #[test]
    fn the_ladder_and_containment_do_not_share_a_budget() {
        let s = mem();
        s.log_action("c", "npub1a", "warn", 0, 1, "").unwrap();
        s.log_action("c", "npub1a", "delete_and_warn", 0, 2, "").unwrap();
        s.log_action("c", "npub1b", "raid:kick", 0, 0, "").unwrap();
        s.log_action("c", "npub1c", "raid:kick", 0, 0, "").unwrap();
        s.claim("c", "armed:kick:npub1d", 0, 10_000).unwrap();

        assert_eq!(s.actions_last_hour("c", 1000).unwrap(), 2, "the ladder sees only ladder rows");
        assert_eq!(s.contained_last_hour("c", 1000).unwrap(), 2, "containment sees only removals");
    }

    #[test]
    fn a_claim_holds_for_its_wave_and_expires_with_it() {
        let s = mem();
        let ttl = 10_000u64;
        assert!(s.claim("c", "kick:npub1a", 0, ttl).unwrap(), "the first claim wins");
        assert!(!s.claim("c", "kick:npub1a", 5_000, ttl).unwrap(), "and holds inside the wave");
        assert!(s.claim("c", "kick:npub1b", 0, ttl).unwrap(), "another member is their own claim");
        assert!(s.claim("c", "kick:npub1a", 20_000, ttl).unwrap(), "next week's raid is a new event");
        assert_eq!(s.strongest_response("c", "kick:npub1a").unwrap(), None, "a claim is not a response");
    }

    #[test]
    fn a_pardon_clears_everything_including_a_claim() {
        let s = mem();
        s.record("c", "npub1a", "x", 4, 0, "").unwrap();
        s.log_action("c", "npub1a", "kick", 0, 0, "").unwrap();
        s.claim("c", "kick:npub1a", 0, 10_000).unwrap();

        assert_eq!(s.pardon("c", "npub1a").unwrap(), 1);
        assert!(s.strikes("c", "npub1a").unwrap().is_empty());
        assert_eq!(
            s.strongest_response("c", "npub1a").unwrap(),
            None,
            "a pardoned member who kept a kick on file could only ever be banned next"
        );
        assert!(s.claim("c", "kick:npub1a", 0, 10_000).unwrap(), "and is containable again");
    }

    /// The whole point of a tombstone. The engine re-reports a standing
    /// conviction every poll, so a pardon that DELETED the row had it back
    /// within 90 seconds — at full worth, stamped `now`, with the action
    /// history gone. The undo re-ran the entire ladder against them.
    #[test]
    fn a_pardon_survives_the_next_poll_re_reporting_the_same_conviction() {
        let s = mem();
        s.record("c", "npub1a", "conviction-1", 12, 1_000, "words").unwrap();
        s.pardon("c", "npub1a").unwrap();
        assert!(s.strikes("c", "npub1a").unwrap().is_empty());

        // The next sweep, re-reporting exactly what it reported before.
        let fresh = s.record("c", "npub1a", "conviction-1", 12, 90_000, "words").unwrap();
        assert!(!fresh, "the tombstone is still there, so this is an echo and not an offense");
        assert!(
            s.strikes("c", "npub1a").unwrap().is_empty(),
            "a pardon the engine can undo is not a pardon"
        );
        assert!(s.subjects_with_strikes("c").unwrap().is_empty(), "and they are not owed anything");
        assert!(s.evidence("c", "npub1a").unwrap().is_empty(), "nor cited for it");
    }

    /// A pardon forgives what was done, not what comes next.
    #[test]
    fn a_pardoned_member_can_be_convicted_again() {
        let s = mem();
        s.record("c", "npub1a", "conviction-1", 12, 1_000, "words").unwrap();
        s.pardon("c", "npub1a").unwrap();
        assert!(s.record("c", "npub1a", "conviction-2", 12, 90_000, "more words").unwrap());
        assert_eq!(s.strikes("c", "npub1a").unwrap().len(), 1, "the new offense stands on its own");
    }

    /// Arming wipes the slate, which is the whole reason there is one ledger.
    #[test]
    fn a_change_of_arming_is_noticed_once() {
        let s = mem();
        assert!(!s.note_armed("c", "warn").unwrap(), "the first sight of a config is not a change");
        assert!(!s.note_armed("c", "warn").unwrap(), "and neither is seeing it again");
        assert!(s.note_armed("c", "warn kick").unwrap(), "arming a class is");
        assert!(s.note_armed("c", "warn").unwrap(), "and so is disarming one");
        assert!(!s.note_armed("other", "warn").unwrap(), "per community");
    }

    /// Arming wipes, and the wipe is the same transaction as the note — as two
    /// calls a failure between them left the arming recorded and the slate
    /// never cleared, for the life of the database.
    #[test]
    fn arming_clears_the_slate_of_that_community_only() {
        let s = mem();
        s.note_armed("c", "warn").unwrap();
        s.note_armed("other", "warn").unwrap();
        s.record("c", "npub1a", "x", 4, 0, "rehearsed").unwrap();
        s.log_action("c", "npub1a", "warn", 0, 4, "").unwrap();
        s.record("other", "npub1b", "y", 4, 0, "").unwrap();

        assert!(s.note_armed("c", "warn kick").unwrap(), "arming a class is a change");
        assert!(s.strikes("c", "npub1a").unwrap().is_empty());
        assert_eq!(s.strongest_response("c", "npub1a").unwrap(), None);
        assert_eq!(s.strikes("other", "npub1b").unwrap().len(), 1, "and only that community");
    }

    /// A tombstone is a strike row, so it must not survive a wipe: the member
    /// would be permanently unconvictable for evidence still in the window.
    #[test]
    fn arming_clears_tombstones_too() {
        let s = mem();
        s.note_armed("c", "warn").unwrap();
        s.record("c", "npub1a", "x", 4, 0, "").unwrap();
        s.pardon("c", "npub1a").unwrap();
        assert!(!s.record("c", "npub1a", "x", 4, 1, "").unwrap(), "tombstoned");

        s.note_armed("c", "warn kick").unwrap();
        assert!(s.record("c", "npub1a", "x", 4, 2, "").unwrap(), "a clean slate is clean both ways");
    }

    #[test]
    fn every_subject_with_a_strike_is_reachable() {
        let s = mem();
        s.record("c", "npub1a", "x", 4, 9_000, "").unwrap();
        s.record("c", "npub1a", "y", 4, 9_000, "").unwrap();
        s.record("other", "npub1c", "w", 4, 9_000, "").unwrap();
        assert_eq!(s.subjects_with_strikes("c").unwrap(), vec!["npub1a"], "distinct, in this community");
    }

    #[test]
    fn the_hourly_bounds_are_scoped_per_community() {
        let s = mem();
        s.log_action("c", "npub1a", "warn", 1000, 0, "").unwrap();
        s.log_action("other", "npub1b", "kick", 1000, 0, "").unwrap();
        assert_eq!(s.actions_last_hour("c", 2000).unwrap(), 1, "another community's wave does not starve this one");
        assert_eq!(s.actions_last_hour("c", 3_700_000 + 1000).unwrap(), 0, "and the hour rolls off");
        assert_eq!(s.subjects_actioned_last_hour("c", 2000, "npub1a").unwrap(), 0, "the judged member is excluded");
        assert_eq!(s.subjects_actioned_last_hour("c", 2000, "someone-else").unwrap(), 1);
    }

    #[test]
    fn a_blob_is_classified_once_per_model() {
        let s = mem();
        assert!(s.cached_verdict("hash1", "llava").is_none());
        s.cache_verdict("hash1", "llava", "clean", 0).unwrap();
        assert_eq!(s.cached_verdict("hash1", "llava").as_deref(), Some("clean"));
        assert!(s.cached_verdict("hash1", "other-model").is_none(), "another model is another opinion");
    }

    #[test]
    fn prune_drops_what_can_no_longer_matter() {
        let s = mem();
        s.record("c", "npub1a", "old", 4, 1_000, "").unwrap();
        s.record("c", "npub1a", "new", 4, 9_000, "").unwrap();
        s.log_action("c", "npub1a", "warn", 1_000, 0, "").unwrap();
        assert_eq!(s.prune(5_000).unwrap(), 2, "one strike and one action");
        assert_eq!(s.strikes("c", "npub1a").unwrap().len(), 1, "the live one stays");
    }

    /// The ledger is per community, in every direction.
    #[test]
    fn nothing_in_the_ledger_crosses_between_communities() {
        let s = mem();
        s.record("one", "npub1a", "x", 4, 0, "ev").unwrap();
        s.log_action("one", "npub1a", "kick", 0, 4, "").unwrap();

        assert!(s.strikes("two", "npub1a").unwrap().is_empty());
        assert_eq!(s.strongest_response("two", "npub1a").unwrap(), None);
        assert!(s.subjects_with_strikes("two").unwrap().is_empty());
        assert!(s.evidence("two", "npub1a").unwrap().is_empty());
        assert_eq!(s.actions_last_hour("two", 1000).unwrap(), 0);
        assert_eq!(s.contained_last_hour("two", 1000).unwrap(), 0);
        assert_eq!(s.subjects_actioned_last_hour("two", 1000, "").unwrap(), 0);
        // And the same conviction id is a fresh offense somewhere else.
        assert!(s.record("two", "npub1a", "x", 4, 0, "ev").unwrap());
    }

    /// The same id twice is an echo, not a second offense — that is the whole
    /// job of the id, since a verdict re-reports every standing conviction.
    #[test]
    fn the_same_conviction_is_recorded_once_however_often_it_is_reported() {
        let s = mem();
        assert!(s.record("c", "npub1a", "x", 4, 1_000, "first").unwrap());
        for poll in 1..=50u64 {
            assert!(!s.record("c", "npub1a", "x", 4, poll * 90_000, "again").unwrap(), "poll {poll}");
        }
        assert_eq!(s.strikes("c", "npub1a").unwrap().len(), 1);
        assert_eq!(s.strikes("c", "npub1a").unwrap()[0].at_ms, 1_000, "and keeps its ORIGINAL time");
    }

    /// Which matters: re-stamping would reset the decay clock, so an offense
    /// could never be forgiven while its evidence sat in the engine's window.
    #[test]
    fn re_reporting_does_not_reset_the_decay_clock() {
        let s = mem();
        s.record("c", "npub1a", "x", 12, 0, "").unwrap();
        let hl = 168 * 3_600_000u64;
        s.record("c", "npub1a", "x", 12, hl, "").unwrap();
        let strikes = s.strikes("c", "npub1a").unwrap();
        assert_eq!(crate::ladder::total(&strikes, hl, 168), 6, "one half-life on, it is halved");
    }

    #[test]
    fn a_hidden_hour_boundary_is_not_off_by_one() {
        let s = mem();
        let hour = 3_600_000u64;
        s.log_action("c", "npub1a", "warn", 1_000, 1, "").unwrap();
        assert_eq!(s.actions_last_hour("c", 1_000 + hour).unwrap(), 1, "exactly an hour old still counts");
        assert_eq!(s.actions_last_hour("c", 1_000 + hour + 1).unwrap(), 0, "a millisecond later it does not");
    }

    #[test]
    fn a_claim_is_scoped_and_expires() {
        let s = mem();
        let ttl = 10_000u64;
        assert!(s.claim("c", "armed:kick:npub1a", 0, ttl).unwrap());
        assert!(!s.claim("c", "armed:kick:npub1a", ttl - 1, ttl).unwrap(), "inside the wave");
        assert!(s.claim("c", "armed:kick:npub1a", ttl + 1, ttl).unwrap(), "and again once it has passed");
        assert!(s.claim("c", "armed:ban:npub1a", 0, ttl).unwrap(), "a different verb is a different claim");
        assert!(s.claim("other", "armed:kick:npub1a", 0, ttl).unwrap(), "and a different community");
    }

    /// Evidence is a person's view of the record, so it must not surface what
    /// was forgiven, and it must be stable rather than an accident of ordering.
    #[test]
    fn evidence_is_the_live_record_newest_first_and_deterministic() {
        let s = mem();
        s.record("c", "npub1a", "a", 4, 1, "oldest").unwrap();
        s.record("c", "npub1a", "b", 4, 2, "middle").unwrap();
        s.record("c", "npub1a", "c", 4, 3, "newest").unwrap();
        s.record("c", "npub1a", "d", 4, 4, "").unwrap();

        let once = s.evidence("c", "npub1a").unwrap();
        assert_eq!(once, s.evidence("c", "npub1a").unwrap(), "the same answer every time");
        assert_eq!(once.first().map(String::as_str), Some("newest"));
        assert!(!once.iter().any(|e| e.is_empty()), "a blank line cites nothing");
        assert!(once.len() <= 3, "capped");
    }

    /// A database written by a newer Sentinel must be refused, not silently
    /// written to by a build that does not know its columns.
    #[test]
    fn a_newer_database_is_refused_rather_than_downgraded() {
        let dir = std::env::temp_dir().join(format!("sentinel-newer-{}", std::process::id()));
        let path = dir.to_string_lossy().to_string();
        let _ = std::fs::remove_file(&path);

        Store::open(&path).expect("a fresh database opens");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute("UPDATE meta SET value = ?1 WHERE key = 'schema'", [SCHEMA_VERSION + 1]).unwrap();
        }
        let err = match Store::open(&path) {
            Ok(_) => panic!("a newer schema must be refused"),
            Err(e) => e,
        };
        assert!(err.contains("newer Sentinel"), "{err}");
        let _ = std::fs::remove_file(&path);
    }

    /// An OLDER database is rebuilt rather than migrated: the ledger is derived
    /// state and the engine refills it within one poll.
    #[test]
    fn an_older_database_is_rebuilt_and_keeps_what_is_not_derived() {
        let dir = std::env::temp_dir().join(format!("sentinel-older-{}", std::process::id()));
        let path = dir.to_string_lossy().to_string();
        let _ = std::fs::remove_file(&path);

        {
            let s = Store::open(&path).expect("a fresh database opens");
            s.record("c", "npub1a", "x", 4, 0, "").unwrap();
            s.cache_verdict("hash", "llava", "{}", 0).unwrap();
            s.note_armed("c", "warn").unwrap();
        }
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute("UPDATE meta SET value = 1 WHERE key = 'schema'", []).unwrap();
        }
        let s = Store::open(&path).expect("an older schema opens");
        assert!(s.strikes("c", "npub1a").unwrap().is_empty(), "the ledger is rebuilt");
        assert_eq!(s.cached_verdict("hash", "llava").as_deref(), Some("{}"), "classifications are not");
        assert!(!s.note_armed("c", "warn").unwrap(), "and neither is what is armed");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn pruning_keeps_what_is_still_inside_the_horizon() {
        let s = mem();
        s.record("c", "npub1a", "old", 4, 1_000, "").unwrap();
        s.record("c", "npub1a", "edge", 4, 5_000, "").unwrap();
        s.record("c", "npub1a", "new", 4, 9_000, "").unwrap();
        assert_eq!(s.prune(5_000).unwrap(), 1, "strictly older than the horizon");
        assert_eq!(s.strikes("c", "npub1a").unwrap().len(), 2);
    }
}
