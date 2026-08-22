//! What Sentinel remembers: strikes and actions, in one SQLite file beside the
//! config. This process runs unattended for months, so the schema is versioned
//! from day one.

use std::sync::Mutex;

use rusqlite::Connection;

use crate::ladder::Strike;

const SCHEMA_VERSION: i64 = 1;

const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS strikes (
    community     TEXT NOT NULL,
    subject       TEXT NOT NULL,
    conviction_id TEXT NOT NULL,
    worth         INTEGER NOT NULL,
    at_ms         INTEGER NOT NULL,
    evidence      TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (community, subject, conviction_id)
);
CREATE TABLE IF NOT EXISTS classifications (
    content_hash TEXT NOT NULL,
    model        TEXT NOT NULL,
    verdict      TEXT NOT NULL,
    at_ms        INTEGER NOT NULL,
    PRIMARY KEY (content_hash, model)
);
CREATE TABLE IF NOT EXISTS actions (
    community TEXT NOT NULL,
    subject   TEXT NOT NULL,
    response  TEXT NOT NULL,
    dry       INTEGER NOT NULL,
    at_ms     INTEGER NOT NULL,
    evidence  TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_actions_claim ON actions(community, subject, response) WHERE response = 'raid:claim';
CREATE INDEX IF NOT EXISTS idx_actions_subject ON actions(community, subject, at_ms);
CREATE INDEX IF NOT EXISTS idx_actions_at ON actions(dry, at_ms);";

/// The connection lives behind a mutex so one `Arc<Store>` serves both the
/// sweep loop and the operator's slash commands. Every method locks briefly and
/// never across an await.
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

    /// Record one conviction. Returns whether it was NEW — verdicts are
    /// cumulative, re-reporting every standing conviction on every poll, so the
    /// conviction id is the line between an offense and an echo of one.
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

    /// Every strike a member carries here, for the ladder to decay and sum.
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

    /// The audit trail, and the input to the per-hour ceiling.
    pub fn log_action(
        &self,
        community: &str,
        subject: &str,
        response: &str,
        dry: bool,
        at_ms: u64,
        evidence: &str,
    ) -> Result<(), String> {
        self.lock()
            .execute(
                "INSERT INTO actions (community, subject, response, dry, at_ms, evidence)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![community, subject, response, dry as i64, at_ms as i64, evidence],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Real (non-dry) actions in the last hour, across every community — the
    /// ceiling is per bot, since a bug is per bot.
    pub fn actions_last_hour(&self, now_ms: u64) -> Result<usize, String> {
        let since = now_ms.saturating_sub(3_600_000) as i64;
        self.lock()
            .query_row("SELECT COUNT(*) FROM actions WHERE dry = 0 AND at_ms >= ?1", [since], |r| {
                r.get::<_, i64>(0).map(|n| n as usize)
            })
            .map_err(|e| e.to_string())
    }

    /// The strongest response already taken against a member, so one standing
    /// is not re-sentenced on every poll.
    ///
    /// Scoped to `dry`, and that is load-bearing: a rehearsal must only dedup
    /// rehearsals. Sharing one column meant a day of dry running left every
    /// member marked as already answered, and arming the bot then did nothing
    /// for anyone — the operator saw silence and read it as broken.
    ///
    /// STRONGEST, not latest: ordering by time let a later, lesser response
    /// reopen a member to everything above it.
    pub fn strongest_response(&self, community: &str, subject: &str, dry: bool) -> Result<Option<String>, String> {
        use rusqlite::OptionalExtension;
        self.lock()
            .query_row(
                "SELECT response FROM actions \
                 WHERE community = ?1 AND subject = ?2 AND dry = ?3 AND response IN ('warn','delete_and_warn','kick','ban') \
                 ORDER BY CASE response WHEN 'ban' THEN 4 WHEN 'kick' THEN 3 WHEN 'delete_and_warn' THEN 2 ELSE 1 END DESC \
                 LIMIT 1",
                rusqlite::params![community, subject, dry as i64],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())
    }

    /// Has this exact cohort already been contained? A raid stays detected for
    /// as long as its evidence sits in the window, and without this every sweep
    /// re-runs the containment — which for bans means repeated key rotations,
    /// the precise stranding batching exists to avoid.
    pub fn claim_cohort(&self, community: &str, fingerprint: &str, at_ms: u64) -> Result<bool, String> {
        let n = self
            .lock()
            .execute(
                "INSERT OR IGNORE INTO actions (community, subject, response, dry, at_ms, evidence)
                 VALUES (?1, ?2, 'raid:claim', 0, ?3, 'cohort')",
                rusqlite::params![community, fingerprint, at_ms as i64],
            )
            .map_err(|e| e.to_string())?;
        Ok(n > 0)
    }

    /// What a model said about this blob last time, if anything.
    ///
    /// Keyed on the PLAINTEXT hash, so forty accounts posting one image cost a
    /// single classification. The bytes themselves are never stored: a
    /// moderation bot that fills a disk with the material it was hired to
    /// remove is a liability.
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
                "INSERT OR REPLACE INTO classifications (content_hash, verdict, model, at_ms) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![content_hash, verdict, model, at_ms as i64],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// The one command that undoes: clear a member's strikes.
    /// Clears strikes AND the action history. Leaving the history behind meant a
    /// pardoned member stayed immune to every response up to whatever they had
    /// already received — forgiven on paper, unreachable in practice.
    pub fn pardon(&self, community: &str, subject: &str) -> Result<usize, String> {
        let conn = self.lock();
        let n = conn
            .execute("DELETE FROM strikes WHERE community = ?1 AND subject = ?2", rusqlite::params![community, subject])
            .map_err(|e| e.to_string())?;
        conn.execute("DELETE FROM actions WHERE community = ?1 AND subject = ?2", rusqlite::params![community, subject])
            .map_err(|e| e.to_string())?;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem() -> Store {
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
        // A rung escalation mints a new conviction id, and THAT lands.
        assert!(s.record("c", "npub1a", "conv1-rung2", 2, 2000, "kept swearing").unwrap());
        assert_eq!(s.strikes("c", "npub1a").unwrap().len(), 2);
    }

    /// A raid of one image is one classification, not forty.
    #[test]
    fn a_blob_is_classified_once_per_model() {
        let s = mem();
        assert!(s.cached_verdict("hash1", "llava").is_none());
        s.cache_verdict("hash1", "llava", "clean", 0).unwrap();
        assert_eq!(s.cached_verdict("hash1", "llava").as_deref(), Some("clean"));
        assert!(s.cached_verdict("hash1", "other-model").is_none(), "another model is another opinion");
    }

    #[test]
    fn strikes_are_scoped_to_their_community() {
        let s = mem();
        s.record("c1", "npub1a", "conv1", 4, 0, "").unwrap();
        assert!(s.strikes("c2", "npub1a").unwrap().is_empty(), "a strike elsewhere is not a strike here");
    }

    #[test]
    fn pardon_clears_the_history_too_or_forgiveness_is_only_on_paper() {
        let s = mem();
        s.record("c", "npub1a", "x", 4, 0, "").unwrap();
        s.log_action("c", "npub1a", "kick", false, 0, "").unwrap();
        assert_eq!(s.pardon("c", "npub1a").unwrap(), 1);
        assert!(s.strikes("c", "npub1a").unwrap().is_empty());
        assert_eq!(
            s.strongest_response("c", "npub1a", false).unwrap(),
            None,
            "a pardoned member who kept a 'kick' on file could only ever be banned next"
        );
    }

    #[test]
    fn the_hourly_ceiling_counts_only_real_actions() {
        let s = mem();
        s.log_action("c", "npub1a", "warn", true, 1000, "").unwrap();
        s.log_action("c", "npub1a", "warn", false, 1000, "").unwrap();
        assert_eq!(s.actions_last_hour(2000).unwrap(), 1, "rehearsals never count against the ceiling");
        assert_eq!(s.actions_last_hour(3_700_000 + 1000).unwrap(), 0, "and the hour rolls off");
    }

    /// The trap this replaced: a day of dry running marked everyone as already
    /// answered, so arming the bot did nothing for any of them.
    #[test]
    fn a_rehearsal_only_dedups_rehearsals() {
        let s = mem();
        s.log_action("c", "npub1a", "warn", true, 1000, "").unwrap();
        assert_eq!(s.strongest_response("c", "npub1a", true).unwrap().as_deref(), Some("warn"));
        assert_eq!(s.strongest_response("c", "npub1a", false).unwrap(), None, "arming starts clean");
    }

    /// Ordering by time let a later, lesser response reopen a member to
    /// everything above it.
    #[test]
    fn the_strongest_response_wins_not_the_latest() {
        let s = mem();
        s.log_action("c", "npub1a", "kick", false, 1000, "").unwrap();
        s.log_action("c", "npub1a", "warn", false, 2000, "").unwrap();
        assert_eq!(s.strongest_response("c", "npub1a", false).unwrap().as_deref(), Some("kick"));
    }

    /// Raid rows share the actions table and must never be read as a ladder
    /// response: an unarmed raid stamping 'kick' on every suspect would
    /// immunise all of them against warn, delete and kick, permanently.
    #[test]
    fn a_raid_claim_is_not_a_ladder_response() {
        let s = mem();
        assert!(s.claim_cohort("c", "fingerprint1", 0).unwrap(), "the first claim wins");
        assert!(!s.claim_cohort("c", "fingerprint1", 5000).unwrap(), "the same cohort is contained once");
        assert!(s.claim_cohort("c", "fingerprint2", 0).unwrap(), "a different cohort is its own event");
        assert_eq!(s.strongest_response("c", "fingerprint1", false).unwrap(), None);
    }
}
