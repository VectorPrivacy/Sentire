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
CREATE TABLE IF NOT EXISTS actions (
    community TEXT NOT NULL,
    subject   TEXT NOT NULL,
    response  TEXT NOT NULL,
    dry       INTEGER NOT NULL,
    at_ms     INTEGER NOT NULL,
    evidence  TEXT NOT NULL DEFAULT ''
);";

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

    /// The most severe response already taken (or rehearsed) against a member,
    /// so one strike total does not warn on every poll forever.
    pub fn last_response(&self, community: &str, subject: &str) -> Result<Option<String>, String> {
        use rusqlite::OptionalExtension;
        self.lock()
            .query_row(
                "SELECT response FROM actions WHERE community = ?1 AND subject = ?2 ORDER BY at_ms DESC LIMIT 1",
                rusqlite::params![community, subject],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())
    }

    /// The one command that undoes: clear a member's strikes.
    pub fn pardon(&self, community: &str, subject: &str) -> Result<usize, String> {
        self.lock()
            .execute("DELETE FROM strikes WHERE community = ?1 AND subject = ?2", rusqlite::params![community, subject])
            .map(|n| n)
            .map_err(|e| e.to_string())
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

    #[test]
    fn strikes_are_scoped_to_their_community() {
        let s = mem();
        s.record("c1", "npub1a", "conv1", 4, 0, "").unwrap();
        assert!(s.strikes("c2", "npub1a").unwrap().is_empty(), "a strike elsewhere is not a strike here");
    }

    #[test]
    fn pardon_clears_and_the_hourly_ceiling_counts_only_real_actions() {
        let s = mem();
        s.record("c", "npub1a", "x", 4, 0, "").unwrap();
        assert_eq!(s.pardon("c", "npub1a").unwrap(), 1);
        assert!(s.strikes("c", "npub1a").unwrap().is_empty());

        s.log_action("c", "npub1a", "warn", true, 1000, "").unwrap();
        s.log_action("c", "npub1a", "warn", false, 1000, "").unwrap();
        assert_eq!(s.actions_last_hour(2000).unwrap(), 1, "rehearsals never count against the ceiling");
        assert_eq!(s.actions_last_hour(3_700_000 + 1000).unwrap(), 0, "and the hour rolls off");
        assert_eq!(s.last_response("c", "npub1a").unwrap().as_deref(), Some("warn"));
    }
}
