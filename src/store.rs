//! What Sentinel remembers: strikes and the actions it took. One SQLite file
//! beside the config.
//!
//! ONE ledger for rehearsals and real actions alike. Arming a class wipes the
//! community's slate, so no read ever has to ask which space a row is in.

use std::sync::Mutex;

use rusqlite::Connection;

use crate::ladder::Strike;

const SCHEMA_VERSION: i64 = 1;

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
    PRIMARY KEY (community, subject, conviction_id)
);
CREATE TABLE IF NOT EXISTS actions (
    community TEXT NOT NULL,
    subject   TEXT NOT NULL,
    response  TEXT NOT NULL,
    at_ms     INTEGER NOT NULL,
    evidence  TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS classifications (
    content_hash TEXT NOT NULL,
    model        TEXT NOT NULL,
    verdict      TEXT NOT NULL,
    at_ms        INTEGER NOT NULL,
    PRIMARY KEY (content_hash, model)
);
CREATE INDEX IF NOT EXISTS idx_strikes_live ON strikes(community, at_ms);
CREATE INDEX IF NOT EXISTS idx_actions_subject ON actions(community, subject, at_ms);
CREATE INDEX IF NOT EXISTS idx_actions_hour ON actions(community, at_ms);";

pub struct Store {
    conn: Mutex<Connection>,
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
            .prepare("SELECT worth, at_ms FROM strikes WHERE community = ?1 AND subject = ?2")
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
                 AND evidence != '' GROUP BY evidence ORDER BY t DESC LIMIT 3",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(rusqlite::params![community, subject], |r| r.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        Ok(rows.flatten().collect())
    }

    pub fn log_action(
        &self,
        community: &str,
        subject: &str,
        response: &str,
        at_ms: u64,
        evidence: &str,
    ) -> Result<(), String> {
        self.lock()
            .execute(
                "INSERT INTO actions (community, subject, response, at_ms, evidence) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![community, subject, response, at_ms as i64, evidence],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// The strongest response this member has already had.
    ///
    /// Strongest, not latest: ordering by time let a later, lesser response
    /// reopen them to everything above it. Ranking happens in Rust so the
    /// severity order lives in exactly one place.
    pub fn strongest_response(&self, community: &str, subject: &str) -> Result<Option<String>, String> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare("SELECT response FROM actions WHERE community = ?1 AND subject = ?2")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(rusqlite::params![community, subject], |r| r.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        let mut best: Option<String> = None;
        for name in rows.flatten() {
            if crate::config::Response::rank_of(&name)
                > best.as_deref().map(crate::config::Response::rank_of).unwrap_or(0)
            {
                best = Some(name);
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

    /// Everyone carrying a strike here. The sweep's own population is whatever
    /// the engine reported, which never includes a media-only offender.
    pub fn subjects_with_strikes(&self, community: &str) -> Result<Vec<String>, String> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare(
                "SELECT subject FROM strikes WHERE community = ?1 GROUP BY subject ORDER BY MIN(at_ms)",
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

    /// Note what is armed here, and wipe the slate when it changes.
    ///
    /// This is the whole reason there is one ledger. A rehearsal writes nothing
    /// and arming starts clean, so nobody carries a backlog of sentences that
    /// were never delivered into the run that would deliver them.
    ///
    /// True when the arming changed.
    pub fn note_armed(&self, community: &str, classes: &str) -> Result<bool, String> {
        use rusqlite::OptionalExtension;
        let conn = self.lock();
        let seen: Option<String> = conn
            .query_row("SELECT classes FROM armed WHERE community = ?1", [community], |r| r.get(0))
            .optional()
            .map_err(|e| e.to_string())?;
        let changed = seen.as_deref().is_some_and(|s| s != classes);
        conn.execute(
            "INSERT OR REPLACE INTO armed (community, classes) VALUES (?1, ?2)",
            rusqlite::params![community, classes],
        )
        .map_err(|e| e.to_string())?;
        Ok(changed)
    }

    /// Forget everything this community knows about its members.
    ///
    /// This is what arming does, and it is why there is only one ledger: a
    /// rehearsal must not silence the run that follows it, and wiping is a
    /// simpler answer than keeping two of everything.
    pub fn forget(&self, community: &str) -> Result<(), String> {
        let conn = self.lock();
        conn.execute("DELETE FROM strikes WHERE community = ?1", [community]).map_err(|e| e.to_string())?;
        conn.execute("DELETE FROM actions WHERE community = ?1", [community]).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Clear one member's record. The undo an operator needs when Sentinel is
    /// wrong about somebody.
    pub fn pardon(&self, community: &str, subject: &str) -> Result<usize, String> {
        let conn = self.lock();
        let n = conn
            .execute("DELETE FROM strikes WHERE community = ?1 AND subject = ?2", rusqlite::params![community, subject])
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
        s.log_action("c", "npub1a", "kick", 1000, "").unwrap();
        s.log_action("c", "npub1a", "warn", 2000, "").unwrap();
        assert_eq!(s.strongest_response("c", "npub1a").unwrap().as_deref(), Some("kick"));
    }

    /// Raid rows share the table and must never read as a ladder response: an
    /// unarmed raid stamping "kick" on every suspect would immunise all of them.
    #[test]
    fn a_raid_row_is_not_a_ladder_response() {
        let s = mem();
        s.log_action("c", "npub1a", "raid:kick", 0, "").unwrap();
        assert_eq!(s.strongest_response("c", "npub1a").unwrap(), None);
        assert_eq!(s.actions_last_hour("c", 1000).unwrap(), 0, "and answers to its own bound");
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
        s.log_action("c", "npub1a", "kick", 0, "").unwrap();
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

    #[test]
    fn forgetting_a_community_clears_its_slate() {
        let s = mem();
        s.record("c", "npub1a", "x", 4, 0, "rehearsed").unwrap();
        s.log_action("c", "npub1a", "warn", 0, "").unwrap();
        s.record("other", "npub1b", "y", 4, 0, "").unwrap();

        s.forget("c").unwrap();
        assert!(s.strikes("c", "npub1a").unwrap().is_empty());
        assert_eq!(s.strongest_response("c", "npub1a").unwrap(), None);
        assert_eq!(s.strikes("other", "npub1b").unwrap().len(), 1, "and only that community");
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
        s.log_action("c", "npub1a", "warn", 1000, "").unwrap();
        s.log_action("other", "npub1b", "kick", 1000, "").unwrap();
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
        s.log_action("c", "npub1a", "warn", 1_000, "").unwrap();
        assert_eq!(s.prune(5_000).unwrap(), 2, "one strike and one action");
        assert_eq!(s.strikes("c", "npub1a").unwrap().len(), 1, "the live one stays");
    }
}
