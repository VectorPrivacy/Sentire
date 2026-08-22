//! What Sentinel remembers: strikes and actions, in one SQLite file beside the
//! config. This process runs unattended for months, so the schema is versioned
//! from day one.

use std::sync::Mutex;

use rusqlite::Connection;

use crate::ladder::Strike;

const SCHEMA_VERSION: i64 = 3;

const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS strikes (
    community     TEXT NOT NULL,
    subject       TEXT NOT NULL,
    conviction_id TEXT NOT NULL,
    worth         INTEGER NOT NULL,
    at_ms         INTEGER NOT NULL,
    evidence      TEXT NOT NULL DEFAULT '',
    pardoned      INTEGER NOT NULL DEFAULT 0,
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
CREATE TABLE IF NOT EXISTS notes (key TEXT PRIMARY KEY, note TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS idx_actions_claim ON actions(community, subject, response) WHERE response = 'raid:claim';
CREATE INDEX IF NOT EXISTS idx_actions_subject ON actions(community, subject, at_ms);
CREATE INDEX IF NOT EXISTS idx_actions_at ON actions(dry, at_ms);
CREATE INDEX IF NOT EXISTS idx_actions_hour ON actions(community, dry, at_ms);
CREATE INDEX IF NOT EXISTS idx_strikes_live ON strikes(community, at_ms);";

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
            // An unreadable meta row is the OLDEST version, not the newest:
            // failing open here skipped the migration entirely and left v1's
            // raid rows in place, immunising everyone they touched.
            .query_row("SELECT value FROM meta WHERE key = 'schema'", [], |r| r.get(0))
            .unwrap_or(1);
        if stored > SCHEMA_VERSION {
            return Err(format!("{path} was written by a newer Sentinel (schema {stored} > {SCHEMA_VERSION})"));
        }
        // Asked of the schema, not inferred from a failed statement. The ALTER
        // MUST fail on a fresh database, so swallowing its error also swallowed
        // a busy lock or a full disk — and the version was written anyway, so
        // the column stayed missing and every strikes() read errored forever.
        let has_pardoned = {
            let mut stmt = conn.prepare("PRAGMA table_info(strikes)").map_err(|e| e.to_string())?;
            let cols = stmt
                .query_map([], |r| r.get::<_, String>(1))
                .map_err(|e| e.to_string())?
                .flatten()
                .any(|c| c == "pardoned");
            cols
        };
        if !has_pardoned {
            conn.execute("ALTER TABLE strikes ADD COLUMN pardoned INTEGER NOT NULL DEFAULT 0", [])
                .map_err(|e| format!("{path}: schema 3 migration failed: {e}"))?;
        }
        if stored < 2 {
            // Version 1 wrote bare "kick"/"ban" rows for UNARMED raid
            // containment. Those read as ladder responses, so every suspect of
            // a rehearsed raid is immune to warn, delete and kick — forever,
            // on evidence nobody acted on.
            conn.execute("DELETE FROM actions WHERE evidence = 'raid cohort' AND response NOT LIKE 'raid:%'", [])
                .map_err(|e| e.to_string())?;
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
            .prepare("SELECT worth, at_ms FROM strikes WHERE community = ?1 AND subject = ?2 AND pardoned = 0")
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

    /// Ladder actions in this community in the last hour, at this armed-ness.
    ///
    /// Per community, deliberately: a wave in one room must not starve the
    /// ceiling everywhere else Sentinel works. Raid rows are excluded — they
    /// carry a `raid:` prefix and answer to their own bound. Scoped by `dry`
    /// so a rehearsal exercises the ceilings too: counting only real actions
    /// meant a dry run never hit one, and arming changed behaviour the
    /// rehearsal had never shown.
    pub fn actions_last_hour(&self, community: &str, dry: bool, now_ms: u64) -> Result<usize, String> {
        let since = now_ms.saturating_sub(3_600_000) as i64;
        self.lock()
            .query_row(
                "SELECT COUNT(*) FROM actions WHERE community = ?1 AND dry = ?3 AND at_ms >= ?2 \
                 AND response NOT LIKE 'raid:%' AND response NOT LIKE 'failed:%' \
                 AND response NOT LIKE 'attempted:%'",
                rusqlite::params![community, since, dry as i64],
                |r| r.get::<_, i64>(0).map(|n| n as usize),
            )
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
    ///
    /// Bounded by `since_ms`, because a response older than the strikes it
    /// answered is not an answer to anything. Unbounded, one warning made a
    /// member permanently un-warnable and the ladder became lifetime-monotonic
    /// despite the half-life the config advertises.
    pub fn strongest_response(
        &self,
        community: &str,
        subject: &str,
        dry: bool,
        since_ms: u64,
    ) -> Result<Option<String>, String> {
        // Read every response on file and rank them in Rust. A second severity
        // table in SQL would drift from `Response` the first time a variant is
        // renamed, and the drift reads as "no prior action" — re-sentencing
        // everyone from scratch.
        let conn = self.lock();
        let mut stmt = conn
            .prepare(
                "SELECT response FROM actions WHERE community = ?1 AND subject = ?2 AND dry = ?3 AND at_ms >= ?4",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(rusqlite::params![community, subject, dry as i64, since_ms as i64], |r| r.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        let mut best: Option<String> = None;
        for name in rows.flatten() {
            if crate::config::Response::rank_of(&name) > best.as_deref().map(crate::config::Response::rank_of).unwrap_or(0) {
                best = Some(name);
            }
        }
        Ok(best)
    }

    /// What this member's live strikes were for, worst-first-ish, capped. The
    /// carried warning has no engine finding to quote, so without this it
    /// reached the member as "a rule matched: carrying strikes".
    pub fn evidence(&self, community: &str, subject: &str) -> Result<Vec<String>, String> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare(
                "SELECT evidence, MAX(at_ms) AS t FROM strikes WHERE community = ?1 AND subject = ?2 \
                 AND pardoned = 0 AND evidence != '' GROUP BY evidence ORDER BY t DESC LIMIT 3",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(rusqlite::params![community, subject], |r| r.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        Ok(rows.flatten().collect())
    }

    /// Note the rulebook this community is being judged under, and forgive its
    /// open window when it changes.
    ///
    /// The engine mints its window-rung conviction ids over the policy hash, so
    /// an operator adding one pattern re-reports every conviction in the
    /// evidence window under ids nothing has seen. Left alone those land again
    /// at full worth stamped `now` — roughly doubling every total, half of it
    /// with the decay clock reset — and step around every pardon tombstone.
    /// Returns true when the rulebook changed.
    pub fn note_policy(&self, community: &str, hash: &str) -> Result<bool, String> {
        let mut guard = self.lock();
        let conn = guard.transaction().map_err(|e| e.to_string())?;
        let key = format!("policy:{community}");
        let seen: Option<String> = {
            use rusqlite::OptionalExtension;
            conn.query_row("SELECT note FROM notes WHERE key = ?1", [&key], |r| r.get(0))
                .optional()
                .map_err(|e| e.to_string())?
        };
        let changed = seen.as_deref().is_some_and(|s| s != hash);
        if changed {
            // ONLY the ids the engine keyed on the policy hash. Sentinel's own
            // `msg:` and `vision:` ids are stable by construction, so
            // tombstoning them erased those convictions permanently —
            // INSERT OR IGNORE hit the tombstone on every later report.
            conn.execute(
                "UPDATE strikes SET pardoned = 1 WHERE community = ?1 AND pardoned = 0 \
                 AND conviction_id NOT LIKE 'msg:%' AND conviction_id NOT LIKE 'vision:%'",
                rusqlite::params![community],
            )
            .map_err(|e| e.to_string())?;
            // The ladder floor lives in `actions`, and an amnesty that leaves it
            // standing gives a previously-kicked member a total of zero and a
            // floor of `kick`: nothing until they earn a ban, which then lands
            // without a warning ever having been delivered.
            conn.execute(
                "DELETE FROM actions WHERE community = ?1 AND response NOT LIKE 'raid:%'",
                rusqlite::params![community],
            )
            .map_err(|e| e.to_string())?;
        }
        conn.execute("INSERT OR REPLACE INTO notes (key, note) VALUES (?1, ?2)", rusqlite::params![key, hash])
            .map_err(|e| e.to_string())?;
        conn.commit().map_err(|e| e.to_string())?;
        Ok(changed)
    }

    /// Distinct PEOPLE actioned here in the last hour. The roster halt bounds
    /// how much of a community may be touched, and the ladder climbs — so
    /// counting rows let one member's four rungs trip a guard sized for four
    /// members.
    pub fn subjects_actioned_last_hour(&self, community: &str, dry: bool, now_ms: u64) -> Result<usize, String> {
        let since = now_ms.saturating_sub(3_600_000) as i64;
        self.lock()
            .query_row(
                "SELECT COUNT(DISTINCT subject) FROM actions WHERE community = ?1 AND dry = ?3 \
                 AND at_ms >= ?2 AND response NOT LIKE 'raid:%' AND response NOT LIKE 'failed:%' \
                 AND response NOT LIKE 'attempted:%'",
                rusqlite::params![community, since, dry as i64],
                |r| r.get::<_, i64>(0).map(|n| n as usize),
            )
            .map_err(|e| e.to_string())
    }

    /// How many times this exact sentence has failed against this member
    /// recently. Read by `enforce` to back off: a target that can never be
    /// actioned — gone, outranking us, no inbox relay — would otherwise be
    /// retried on every pass forever.
    pub fn failures(&self, community: &str, subject: &str, name: &str, since_ms: u64) -> Result<usize, String> {
        self.lock()
            .query_row(
                "SELECT COUNT(*) FROM actions WHERE community = ?1 AND subject = ?2 \
                 AND response = ?3 AND at_ms >= ?4",
                rusqlite::params![community, subject, format!("failed:{name}"), since_ms as i64],
                |r| r.get::<_, i64>(0).map(|n| n as usize),
            )
            .map_err(|e| e.to_string())
    }

    /// Members contained here in the last hour, at this armed-ness.
    /// Containment's own bound, since `actions_last_hour` deliberately excludes
    /// `raid:%` rows. Scoped by `dry` for the same reason the ladder's count is:
    /// a rehearsal that never meets a ceiling shows the operator a run that
    /// looks nothing like the armed one.
    pub fn raid_actions_last_hour(&self, community: &str, dry: bool, now_ms: u64) -> Result<usize, String> {
        let since = now_ms.saturating_sub(3_600_000) as i64;
        self.lock()
            .query_row(
                "SELECT COUNT(*) FROM actions WHERE community = ?1 AND dry = ?3 AND at_ms >= ?2 \
                 AND response LIKE 'raid:%' AND response != 'raid:claim'",
                rusqlite::params![community, since, dry as i64],
                |r| r.get::<_, i64>(0).map(|n| n as usize),
            )
            .map_err(|e| e.to_string())
    }

    /// Has this member already been contained in this wave? A raid stays
    /// detected for as long as its evidence sits in the window, and without
    /// this every sweep re-contains — which for bans means repeated key
    /// rotations, the precise stranding batching exists to avoid.
    pub fn claim_cohort(&self, community: &str, fingerprint: &str, at_ms: u64, ttl_ms: u64) -> Result<bool, String> {
        let conn = self.lock();
        // A claim binds for `ttl_ms` and no longer. Permanent claims meant the
        // same accounts raiding next week were silently not contained — no
        // action, no log, nothing for an operator to see.
        conn.execute(
            "DELETE FROM actions WHERE community = ?1 AND subject = ?2 AND response = 'raid:claim' AND at_ms < ?3",
            rusqlite::params![community, fingerprint, at_ms.saturating_sub(ttl_ms) as i64],
        )
        .map_err(|e| e.to_string())?;
        let n = conn
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
    /// Everyone carrying a live strike here. The sweep's population is the
    /// engine's convictions, which never include a vision-only offender or a
    /// member whose live-lane strikes never lifted their engine score — so a
    /// sentence those lanes could not carry out had nothing to retry it.
    pub fn subjects_with_strikes(&self, community: &str, since_ms: u64) -> Result<Vec<String>, String> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare(
                "SELECT subject FROM strikes WHERE community = ?1 AND at_ms >= ?2 AND pardoned = 0 \
                 GROUP BY subject ORDER BY MIN(at_ms)",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(rusqlite::params![community, since_ms as i64], |r| r.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        Ok(rows.flatten().collect())
    }

    /// Drop what can no longer matter. A strike past 32 halvings is worth zero
    /// and still costs a row in every total; an action older than that answered
    /// for strikes that no longer exist. Unattended for months, this is the
    /// difference between a working database and a growing one.
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

    /// Give a claim back, so a containment that did nothing can be retried
    /// rather than marking those members handled forever.
    pub fn release_cohort(&self, community: &str, fingerprint: &str) -> Result<(), String> {
        self.lock()
            .execute(
                "DELETE FROM actions WHERE community = ?1 AND subject = ?2 AND response = 'raid:claim'",
                rusqlite::params![community, fingerprint],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Clears strikes AND the action history. Leaving the history behind meant a
    /// pardoned member stayed immune to every response up to whatever they had
    /// already received — forgiven on paper, unreachable in practice.
    pub fn pardon(&self, community: &str, subject: &str) -> Result<usize, String> {
        let mut guard = self.lock();
        // One unit: a half-applied pardon forgives on paper and leaves the
        // member immune to everything below what they already received.
        let conn = guard.transaction().map_err(|e| e.to_string())?;
        // TOMBSTONED, not deleted. A conviction id is stable for as long as its
        // evidence sits in the engine's window, so deleting the row let the very
        // next sweep re-insert it — stamped at `now`, which made the strikes
        // YOUNGER and the decayed total HIGHER than before the pardon. The one
        // control an operator needs when a bot misbehaves lasted one poll and
        // came back stronger.
        let n = conn
            .execute(
                "UPDATE strikes SET pardoned = 1 WHERE community = ?1 AND subject = ?2 AND pardoned = 0",
                rusqlite::params![community, subject],
            )
            .map_err(|e| e.to_string())?;
        conn.execute("DELETE FROM actions WHERE community = ?1 AND subject = ?2", rusqlite::params![community, subject])
            .map_err(|e| e.to_string())?;
        // Claims key on a scoped form of the npub, so a bare subject match
        // leaves them behind — and a pardoned member who keeps a raid claim can
        // never be contained again.
        conn.execute(
            "DELETE FROM actions WHERE community = ?1 AND response = 'raid:claim' AND (subject = ?2 OR subject = ?3)",
            rusqlite::params![community, format!("live:{subject}"), format!("dry:{subject}")],
        )
        .map_err(|e| e.to_string())?;
        conn.commit().map_err(|e| e.to_string())?;
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

        // The producer re-reports the same conviction all week. A deleted row
        // would be re-inserted at `now` — younger, so the total comes back
        // HIGHER than it was before the pardon.
        assert!(!s.record("c", "npub1a", "x", 4, 5_000, "").unwrap(), "a pardoned strike does not return");
        assert!(s.strikes("c", "npub1a").unwrap().is_empty(), "and stays gone");
        // A genuinely new offense still lands.
        assert!(s.record("c", "npub1a", "y", 4, 5_000, "").unwrap());
        assert_eq!(s.strikes("c", "npub1a").unwrap().len(), 1);
        assert_eq!(
            s.strongest_response("c", "npub1a", false, 0).unwrap(),
            None,
            "a pardoned member who kept a 'kick' on file could only ever be banned next"
        );
    }

    #[test]
    fn the_hourly_ceiling_is_scoped_by_community_and_armed_ness() {
        let s = mem();
        s.log_action("c", "npub1a", "warn", true, 1000, "").unwrap();
        s.log_action("c", "npub1a", "warn", false, 1000, "").unwrap();
        assert_eq!(s.actions_last_hour("c", false, 2000).unwrap(), 1, "real actions");
        assert_eq!(s.actions_last_hour("c", true, 2000).unwrap(), 1, "and rehearsals bound rehearsals");
        assert_eq!(s.actions_last_hour("c", false, 3_700_000 + 1000).unwrap(), 0, "the hour rolls off");
        s.log_action("other", "npub1b", "kick", false, 1000, "").unwrap();
        assert_eq!(s.actions_last_hour("c", false, 2000).unwrap(), 1, "another community's wave does not starve this one");
        s.log_action("c", "npub1c", "raid:kick", false, 1000, "").unwrap();
        assert_eq!(s.actions_last_hour("c", false, 2000).unwrap(), 1, "raid rows answer to their own bound");
        assert_eq!(s.raid_actions_last_hour("c", false, 2000).unwrap(), 1, "and that bound counts them");
        // A failure is not an action taken. Counting it let four undeliverable
        // warnings spend the whole community's hourly budget.
        s.log_action("c", "npub1e", "failed:warn", false, 1000, "").unwrap();
        assert_eq!(s.actions_last_hour("c", false, 2000).unwrap(), 1, "a failure spends no budget");
        assert_eq!(s.failures("c", "npub1e", "warn", 0).unwrap(), 1, "but it is counted for backoff");
        assert_eq!(s.failures("c", "npub1e", "kick", 0).unwrap(), 0, "per response");
        s.claim_cohort("c", "live:npub1d", 1000, 10_000).unwrap();
        assert_eq!(s.raid_actions_last_hour("c", false, 2000).unwrap(), 1, "a claim is not a containment");
    }

    /// The trap this replaced: a day of dry running marked everyone as already
    /// answered, so arming the bot did nothing for any of them.
    #[test]
    fn a_rehearsal_only_dedups_rehearsals() {
        let s = mem();
        s.log_action("c", "npub1a", "warn", true, 1000, "").unwrap();
        assert_eq!(s.strongest_response("c", "npub1a", true, 0).unwrap().as_deref(), Some("warn"));
        assert_eq!(s.strongest_response("c", "npub1a", false, 0).unwrap(), None, "arming starts clean");
    }

    /// Ordering by time let a later, lesser response reopen a member to
    /// everything above it.
    #[test]
    fn the_strongest_response_wins_not_the_latest() {
        let s = mem();
        s.log_action("c", "npub1a", "kick", false, 1000, "").unwrap();
        s.log_action("c", "npub1a", "warn", false, 2000, "").unwrap();
        assert_eq!(s.strongest_response("c", "npub1a", false, 0).unwrap().as_deref(), Some("kick"));
        // And an answer older than the strikes it answered is not an answer.
        assert_eq!(s.strongest_response("c", "npub1a", false, 5000).unwrap(), None, "stale responses expire");
    }

    /// Raid rows share the actions table and must never be read as a ladder
    /// response: an unarmed raid stamping 'kick' on every suspect would
    /// immunise all of them against warn, delete and kick, permanently.
    #[test]
    fn every_subject_with_a_live_strike_is_reachable() {
        let s = mem();
        s.record("c", "npub1a", "x", 4, 9_000, "").unwrap();
        s.record("c", "npub1a", "y", 4, 9_000, "").unwrap();
        s.record("c", "npub1b", "z", 4, 1_000, "").unwrap();
        s.record("other", "npub1c", "w", 4, 9_000, "").unwrap();
        let mut who = s.subjects_with_strikes("c", 5_000).unwrap();
        who.sort();
        assert_eq!(who, vec!["npub1a"], "distinct, in this community, inside the horizon");
    }

    /// Editing the rulebook re-keys every conviction the engine reports, so
    /// leaving the old strikes standing doubled every total AND stepped around
    /// every pardon.
    #[test]
    fn a_rulebook_change_forgives_the_window_rather_than_doubling_it() {
        let s = mem();
        // An engine-minted id: re-keyed by a policy change, so forgiving it is
        // the only way not to charge the same offense twice.
        s.record("c", "npub1a", "x", 4, 0, "").unwrap();
        s.log_action("c", "npub1a", "kick", false, 0, "").unwrap();
        assert!(!s.note_policy("c", "hash1").unwrap(), "the first sight of a rulebook changes nothing");
        assert_eq!(s.strikes("c", "npub1a").unwrap().len(), 1);
        assert!(!s.note_policy("c", "hash1").unwrap(), "and neither does seeing it again");

        assert!(s.note_policy("c", "hash2").unwrap(), "a different rulebook is a change");
        assert!(s.strikes("c", "npub1a").unwrap().is_empty(), "its window is forgiven, not re-charged");
        assert_eq!(s.strongest_response("c", "npub1a", false, 0).unwrap(), None, "and the floor goes with it");
    }

    /// Sentinel's own ids are stable by construction, so a rulebook change does
    /// not re-key them — tombstoning them erased those convictions for good.
    #[test]
    fn the_carried_warning_names_what_it_is_for() {
        let s = mem();
        s.record("c", "npub1a", "a", 2, 1_000, "slurs [severe] 1×").unwrap();
        s.record("c", "npub1a", "b", 2, 9_000, "links [major] 2×").unwrap();
        s.record("c", "npub1a", "c", 2, 5_000, "slurs [severe] 1×").unwrap();
        let ev = s.evidence("c", "npub1a").unwrap();
        assert_eq!(ev.first().map(String::as_str), Some("links [major] 2×"), "newest first, deduped");
        assert_eq!(ev.len(), 2);
    }

    #[test]
    fn a_rulebook_change_leaves_sentinels_own_convictions_alone() {
        let s = mem();
        s.record("c", "npub1a", "msg:slurs:evt1", 4, 0, "").unwrap();
        s.record("c", "npub1a", "vision:hash1:gore", 12, 0, "").unwrap();
        s.note_policy("c", "hash1").unwrap();
        assert!(s.note_policy("c", "hash2").unwrap());
        assert_eq!(
            s.strikes("c", "npub1a").unwrap().len(),
            2,
            "an id the rulebook never keyed must survive its change, or it can never be charged again"
        );
    }

    #[test]
    fn prune_drops_what_can_no_longer_matter() {
        let s = mem();
        s.record("c", "npub1a", "old", 4, 1_000, "").unwrap();
        s.record("c", "npub1a", "new", 4, 9_000, "").unwrap();
        s.log_action("c", "npub1a", "warn", false, 1_000, "").unwrap();
        assert_eq!(s.prune(5_000).unwrap(), 2, "one strike and one action");
        assert_eq!(s.strikes("c", "npub1a").unwrap().len(), 1, "the live one stays");
    }

    #[test]
    fn a_raid_claim_is_not_a_ladder_response() {
        let s = mem();
        let ttl = 10_000u64;
        assert!(s.claim_cohort("c", "live:npub1a", 0, ttl).unwrap(), "the first claim wins");
        assert!(!s.claim_cohort("c", "live:npub1a", 5_000, ttl).unwrap(), "and holds inside the wave");
        assert!(s.claim_cohort("c", "live:npub1b", 0, ttl).unwrap(), "another member is their own claim");
        // Next week's raid by the same accounts is a NEW event.
        assert!(s.claim_cohort("c", "live:npub1a", 20_000, ttl).unwrap(), "a claim expires with its wave");
        // A rehearsal never immunises a later real containment.
        assert!(s.claim_cohort("c", "dry:npub1a", 20_000, ttl).unwrap());
        assert_eq!(s.strongest_response("c", "live:npub1a", false, 0).unwrap(), None, "a claim is not a response");
    }

    #[test]
    fn a_pardon_clears_a_raid_claim_however_it_was_scoped() {
        let s = mem();
        s.claim_cohort("c", "live:npub1a", 0, 10_000).unwrap();
        s.pardon("c", "npub1a").unwrap();
        assert!(s.claim_cohort("c", "live:npub1a", 0, 10_000).unwrap(), "a pardoned member is containable again");
    }
}
