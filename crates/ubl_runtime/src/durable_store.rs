//! Durable SQLite boundary for WF commit, idempotency, and outbox.
//!
//! P0 goals:
//! - Single transaction for `receipts + idempotency + outbox`.
//! - Persistent idempotency replay across restarts.
//! - Outbox claim/ack/nack primitives for reliable dispatch.

use crate::idempotency::CachedResult;
use chrono::TimeZone;
use rusqlite::{params, OptionalExtension};
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::time::Duration;

const DEFAULT_DSN: &str = "file:./data/ubl.db?mode=rwc&_journal_mode=WAL";

#[derive(Debug, Clone)]
pub struct DurableStore {
    dsn: String,
}

/// GAP-15: persisted stage-secret rotation state.
#[derive(Debug, Clone)]
pub struct StageSecretsRow {
    pub current: String,
    pub prev: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CommitInput {
    pub receipt_cid: String,
    pub receipt_json: Value,
    pub did: String,
    pub kid: String,
    pub rt_hash: String,
    pub decision: String,
    pub idem_key: Option<String>,
    pub chain: Vec<String>,
    pub outbox_events: Vec<NewOutboxEvent>,
    /// Unix timestamp seconds.
    pub created_at: i64,
    /// Test hook: fail after receipts write and before idempotency/outbox.
    pub fail_after_receipt_write: bool,
}

#[derive(Debug, Clone)]
pub struct CommitResult {
    pub committed: bool,
}

#[derive(Debug, Clone)]
pub struct NewOutboxEvent {
    pub event_type: String,
    pub payload_json: Value,
}

#[derive(Debug, Clone)]
pub struct OutboxEvent {
    pub id: i64,
    pub event_type: String,
    pub payload_json: Value,
    pub attempts: i64,
    pub next_attempt_at: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum DurableError {
    #[error("sqlite: {0}")]
    Sqlite(String),
    #[error("serde: {0}")]
    Serde(String),
    #[error("idempotency_conflict: {0}")]
    IdempotencyConflict(String),
    #[error("durable_commit_failed: {0}")]
    DurableCommitFailed(String),
}

impl DurableStore {
    pub fn new(dsn: impl Into<String>) -> Result<Self, DurableError> {
        let store = Self { dsn: dsn.into() };
        store.ensure_initialized()?;
        Ok(store)
    }

    /// Build from env. Returns `None` when durability backend is not sqlite.
    pub fn from_env() -> Result<Option<Self>, DurableError> {
        let backend = std::env::var("UBL_STORE_BACKEND").unwrap_or_else(|_| "memory".to_string());
        if !backend.eq_ignore_ascii_case("sqlite") {
            return Ok(None);
        }

        let dsn = std::env::var("UBL_STORE_DSN")
            .or_else(|_| std::env::var("UBL_IDEMPOTENCY_DSN"))
            .or_else(|_| std::env::var("UBL_OUTBOX_DSN"))
            .unwrap_or_else(|_| DEFAULT_DSN.to_string());

        let store = Self { dsn };
        store.ensure_initialized()?;
        Ok(Some(store))
    }

    pub fn ensure_initialized(&self) -> Result<(), DurableError> {
        self.ensure_parent_dir()?;
        let conn = self.open_conn()?;
        self.apply_pragmas(&conn)?;
        self.create_schema(&conn)?;
        Ok(())
    }

    pub fn get_idempotent(&self, idem_key: &str) -> Result<Option<CachedResult>, DurableError> {
        let conn = self.open_conn()?;
        self.apply_pragmas(&conn)?;

        let row: Option<(String, String, String, i64)> = conn
            .query_row(
                "SELECT receipt_cid, response_json, chain_json, created_at FROM idempotency WHERE idem_key = ?1",
                params![idem_key],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()
            .map_err(|e| DurableError::Sqlite(e.to_string()))?;

        let Some((receipt_cid, response_json, chain_json, created_at)) = row else {
            return Ok(None);
        };

        let response_json: Value =
            serde_json::from_str(&response_json).map_err(|e| DurableError::Serde(e.to_string()))?;
        let chain: Vec<String> =
            serde_json::from_str(&chain_json).map_err(|e| DurableError::Serde(e.to_string()))?;
        let decision = response_json
            .get("decision")
            .and_then(|v| v.as_str())
            .unwrap_or("Allow")
            .to_string();
        let created_at = chrono::Utc
            .timestamp_opt(created_at, 0)
            .single()
            .unwrap_or_else(chrono::Utc::now)
            .to_rfc3339();

        Ok(Some(CachedResult {
            receipt_cid,
            response_json,
            decision,
            chain,
            created_at,
        }))
    }

    /// Fetch a persisted WF receipt JSON by receipt CID.
    pub fn get_receipt(&self, receipt_cid: &str) -> Result<Option<Value>, DurableError> {
        let conn = self.open_conn()?;
        self.apply_pragmas(&conn)?;

        let body_json: Option<String> = conn
            .query_row(
                "SELECT body_json FROM receipts WHERE receipt_cid = ?1",
                params![receipt_cid],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| DurableError::Sqlite(e.to_string()))?;

        let Some(body_json) = body_json else {
            return Ok(None);
        };

        let receipt_json =
            serde_json::from_str(&body_json).map_err(|e| DurableError::Serde(e.to_string()))?;
        Ok(Some(receipt_json))
    }

    pub fn commit_wf_atomically(&self, input: &CommitInput) -> Result<CommitResult, DurableError> {
        let mut conn = self.open_conn()?;
        self.apply_pragmas(&conn)?;

        let tx = conn
            .transaction()
            .map_err(|e| DurableError::DurableCommitFailed(e.to_string()))?;

        let body_json = serde_json::to_string(&input.receipt_json)
            .map_err(|e| DurableError::Serde(e.to_string()))?;

        tx.execute(
            "INSERT OR IGNORE INTO receipts (receipt_cid, body_json, created_at, did, kid, rt_hash, decision)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                input.receipt_cid,
                body_json,
                input.created_at,
                input.did,
                input.kid,
                input.rt_hash,
                input.decision,
            ],
        )
        .map_err(|e| DurableError::DurableCommitFailed(e.to_string()))?;

        if input.fail_after_receipt_write {
            return Err(DurableError::DurableCommitFailed(
                "injected failure after receipts write".to_string(),
            ));
        }

        if let Some(idem_key) = input.idem_key.as_deref() {
            self.put_idempotent_in_tx(&tx, idem_key, input)?;
        }

        for event in &input.outbox_events {
            self.enqueue_outbox_in_tx(&tx, event, input.created_at)?;
        }

        tx.commit()
            .map_err(|e| DurableError::DurableCommitFailed(e.to_string()))?;

        Ok(CommitResult { committed: true })
    }

    pub fn claim_outbox(&self, limit: usize) -> Result<Vec<OutboxEvent>, DurableError> {
        let mut conn = self.open_conn()?;
        self.apply_pragmas(&conn)?;
        let tx = conn
            .transaction()
            .map_err(|e| DurableError::Sqlite(e.to_string()))?;

        let now = chrono::Utc::now().timestamp();

        let mut stmt = tx
            .prepare(
                "SELECT id, event_type, payload_json, attempts, next_attempt_at
                 FROM outbox
                 WHERE status = 'pending' AND next_attempt_at <= ?1
                 ORDER BY id ASC
                 LIMIT ?2",
            )
            .map_err(|e| DurableError::Sqlite(e.to_string()))?;

        let rows = stmt
            .query_map(params![now, limit as i64], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            })
            .map_err(|e| DurableError::Sqlite(e.to_string()))?;

        let mut events = Vec::new();
        for row in rows {
            let (id, event_type, payload_json_raw, attempts, next_attempt_at) =
                row.map_err(|e| DurableError::Sqlite(e.to_string()))?;
            let payload_json: Value = serde_json::from_str(&payload_json_raw)
                .map_err(|e| DurableError::Serde(e.to_string()))?;
            events.push(OutboxEvent {
                id,
                event_type,
                payload_json,
                attempts,
                next_attempt_at,
            });
        }
        drop(stmt);

        for event in &events {
            tx.execute(
                "UPDATE outbox SET status = 'inflight', attempts = attempts + 1 WHERE id = ?1",
                params![event.id],
            )
            .map_err(|e| DurableError::Sqlite(e.to_string()))?;
        }

        tx.commit()
            .map_err(|e| DurableError::Sqlite(e.to_string()))?;
        Ok(events)
    }

    pub fn ack_outbox(&self, id: i64) -> Result<(), DurableError> {
        let conn = self.open_conn()?;
        self.apply_pragmas(&conn)?;
        conn.execute(
            "UPDATE outbox SET status = 'done' WHERE id = ?1",
            params![id],
        )
        .map_err(|e| DurableError::Sqlite(e.to_string()))?;
        Ok(())
    }

    pub fn nack_outbox(&self, id: i64, next_attempt_at: i64) -> Result<(), DurableError> {
        let conn = self.open_conn()?;
        self.apply_pragmas(&conn)?;
        conn.execute(
            "UPDATE outbox SET status = 'pending', next_attempt_at = ?2 WHERE id = ?1",
            params![id, next_attempt_at],
        )
        .map_err(|e| DurableError::Sqlite(e.to_string()))?;
        Ok(())
    }

    pub fn outbox_pending(&self) -> Result<i64, DurableError> {
        let conn = self.open_conn()?;
        self.apply_pragmas(&conn)?;
        conn.query_row(
            "SELECT COUNT(*) FROM outbox WHERE status = 'pending'",
            [],
            |r| r.get(0),
        )
        .map_err(|e| DurableError::Sqlite(e.to_string()))
    }

    fn put_idempotent_in_tx(
        &self,
        tx: &rusqlite::Transaction<'_>,
        idem_key: &str,
        input: &CommitInput,
    ) -> Result<(), DurableError> {
        let response_json = serde_json::to_string(&input.receipt_json)
            .map_err(|e| DurableError::Serde(e.to_string()))?;
        let chain_json =
            serde_json::to_string(&input.chain).map_err(|e| DurableError::Serde(e.to_string()))?;

        match tx.execute(
            "INSERT INTO idempotency (idem_key, receipt_cid, response_json, chain_json, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
            params![
                idem_key,
                input.receipt_cid,
                response_json,
                chain_json,
                input.created_at,
            ],
        ) {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Err(DurableError::IdempotencyConflict(format!(
                    "idempotency key already exists: {}",
                    idem_key
                )))
            }
            Err(e) => Err(DurableError::DurableCommitFailed(e.to_string())),
        }
    }

    fn enqueue_outbox_in_tx(
        &self,
        tx: &rusqlite::Transaction<'_>,
        event: &NewOutboxEvent,
        created_at: i64,
    ) -> Result<(), DurableError> {
        let payload = serde_json::to_string(&event.payload_json)
            .map_err(|e| DurableError::Serde(e.to_string()))?;
        tx.execute(
            "INSERT INTO outbox (event_type, payload_json, status, attempts, next_attempt_at, created_at)
             VALUES (?1, ?2, 'pending', 0, ?3, ?4)",
            params![event.event_type, payload, created_at, created_at],
        )
        .map_err(|e| DurableError::DurableCommitFailed(e.to_string()))?;
        Ok(())
    }

    fn open_conn(&self) -> Result<rusqlite::Connection, DurableError> {
        rusqlite::Connection::open_with_flags(
            &self.dsn,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
                | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )
        .map_err(|e| DurableError::Sqlite(e.to_string()))
    }

    fn apply_pragmas(&self, conn: &rusqlite::Connection) -> Result<(), DurableError> {
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| DurableError::Sqlite(e.to_string()))?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(|e| DurableError::Sqlite(e.to_string()))?;
        conn.busy_timeout(Duration::from_millis(5_000))
            .map_err(|e| DurableError::Sqlite(e.to_string()))?;
        Ok(())
    }

    fn create_schema(&self, conn: &rusqlite::Connection) -> Result<(), DurableError> {
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS receipts (
              receipt_cid TEXT PRIMARY KEY,
              body_json   TEXT NOT NULL,
              created_at  INTEGER NOT NULL,
              did         TEXT NOT NULL,
              kid         TEXT NOT NULL,
              rt_hash     TEXT NOT NULL,
              decision    TEXT NOT NULL CHECK (decision IN ('allow','deny'))
            );

            CREATE TABLE IF NOT EXISTS idempotency (
              idem_key      TEXT PRIMARY KEY,
              receipt_cid   TEXT NOT NULL,
              response_json TEXT NOT NULL,
              chain_json    TEXT NOT NULL,
              created_at    INTEGER NOT NULL,
              expires_at    INTEGER
            );

            CREATE TABLE IF NOT EXISTS outbox (
              id              INTEGER PRIMARY KEY AUTOINCREMENT,
              event_type      TEXT NOT NULL,
              payload_json    TEXT NOT NULL,
              status          TEXT NOT NULL CHECK (status IN ('pending','inflight','done','dead')) DEFAULT 'pending',
              attempts        INTEGER NOT NULL DEFAULT 0,
              next_attempt_at INTEGER NOT NULL,
              created_at      INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_outbox_status_next
            ON outbox (status, next_attempt_at);

            -- GAP-6: cross-restart nonce replay guard with 24h TTL
            CREATE TABLE IF NOT EXISTS seen_nonces (
              nonce      TEXT PRIMARY KEY,
              created_at INTEGER NOT NULL,
              expires_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_seen_nonces_expires
            ON seen_nonces (expires_at);

            -- GAP-15: persisted stage-secret rotation state (singleton row id=1)
            CREATE TABLE IF NOT EXISTS stage_secrets (
              id         INTEGER PRIMARY KEY CHECK (id = 1),
              current    TEXT NOT NULL,
              prev       TEXT,
              rotated_at INTEGER NOT NULL
            );
            ",
        )
        .map_err(|e| DurableError::Sqlite(e.to_string()))
    }

    /// GAP-6: insert nonce if not already seen (and not expired). Returns `true` if newly inserted.
    /// Also prunes expired nonces on each call (index-assisted, cheap).
    pub fn nonce_mark_if_new(&self, nonce: &str, ttl: Duration) -> Result<bool, DurableError> {
        let mut conn = self.open_conn()?;
        self.apply_pragmas(&conn)?;
        let tx = conn
            .transaction()
            .map_err(|e| DurableError::Sqlite(e.to_string()))?;
        let now = chrono::Utc::now().timestamp();
        let expires_at = now + ttl.as_secs().max(1) as i64;

        // Prune expired (indexed, best-effort before insert)
        tx.execute(
            "DELETE FROM seen_nonces WHERE expires_at <= ?1",
            params![now],
        )
        .map_err(|e| DurableError::Sqlite(e.to_string()))?;

        tx.execute(
            "INSERT OR IGNORE INTO seen_nonces (nonce, created_at, expires_at) VALUES (?1, ?2, ?3)",
            params![nonce, now, expires_at],
        )
        .map_err(|e| DurableError::Sqlite(e.to_string()))?;

        let inserted = tx.changes() > 0;
        tx.commit()
            .map_err(|e| DurableError::Sqlite(e.to_string()))?;
        Ok(inserted)
    }

    /// GAP-15: persist current and (optionally) previous stage secret (singleton id=1).
    pub fn put_stage_secrets(&self, current: &str, prev: Option<&str>) -> Result<(), DurableError> {
        let conn = self.open_conn()?;
        self.apply_pragmas(&conn)?;
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO stage_secrets (id, current, prev, rotated_at)
             VALUES (1, ?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET
               current    = excluded.current,
               prev       = excluded.prev,
               rotated_at = excluded.rotated_at",
            params![current, prev, now],
        )
        .map_err(|e| DurableError::Sqlite(e.to_string()))?;
        Ok(())
    }

    /// GAP-15: load persisted stage secrets (if any).
    pub fn get_stage_secrets(&self) -> Result<Option<StageSecretsRow>, DurableError> {
        let conn = self.open_conn()?;
        self.apply_pragmas(&conn)?;
        let row: Option<(String, Option<String>)> = conn
            .query_row(
                "SELECT current, prev FROM stage_secrets WHERE id = 1",
                params![],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|e| DurableError::Sqlite(e.to_string()))?;
        Ok(row.map(|(current, prev)| StageSecretsRow { current, prev }))
    }

    fn ensure_parent_dir(&self) -> Result<(), DurableError> {
        if !self.dsn.starts_with("file:") {
            return Ok(());
        }

        let raw = self.dsn.trim_start_matches("file:");
        let path_part = raw.split('?').next().unwrap_or(raw);
        if path_part.is_empty() || path_part == ":memory:" {
            return Ok(());
        }

        if let Some(parent) = Path::new(path_part).parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| DurableError::Sqlite(e.to_string()))?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dsn(file_name: &str) -> String {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.keep().join(file_name);
        format!("file:{}?mode=rwc&_journal_mode=WAL", path.display())
    }

    fn make_store(file_name: &str) -> DurableStore {
        let store = DurableStore {
            dsn: temp_dsn(file_name),
        };
        store.ensure_initialized().unwrap();
        store
    }

    fn sample_commit(idem_key: Option<&str>) -> CommitInput {
        CommitInput {
            receipt_cid: "b3:receipt-1".to_string(),
            receipt_json: serde_json::json!({"@type":"ubl/receipt", "decision":"allow", "ok":true}),
            did: "did:key:z123".to_string(),
            kid: "did:key:z123#ed25519".to_string(),
            rt_hash: "b3:runtime".to_string(),
            decision: "allow".to_string(),
            idem_key: idem_key.map(|s| s.to_string()),
            chain: vec![
                "b3:wa".to_string(),
                "b3:tr".to_string(),
                "b3:wf".to_string(),
            ],
            outbox_events: vec![NewOutboxEvent {
                event_type: "emit_receipt".to_string(),
                payload_json: serde_json::json!({"receipt_cid":"b3:receipt-1"}),
            }],
            created_at: chrono::Utc::now().timestamp(),
            fail_after_receipt_write: false,
        }
    }

    #[test]
    fn idempotency_survives_restart() {
        let dsn = temp_dsn("idem_restart.db");
        let store1 = DurableStore { dsn: dsn.clone() };
        store1.ensure_initialized().unwrap();
        let commit = sample_commit(Some("idem-key-1"));
        store1.commit_wf_atomically(&commit).unwrap();

        // "Restart": new store instance, same sqlite file
        let store2 = DurableStore { dsn };
        store2.ensure_initialized().unwrap();
        let cached = store2.get_idempotent("idem-key-1").unwrap().unwrap();
        assert_eq!(cached.receipt_cid, "b3:receipt-1");
    }

    #[test]
    fn crash_between_writes_no_dup_no_loss() {
        let store = make_store("crash.db");

        // Inject failure after receipts write but before idempotency/outbox.
        let mut failing = sample_commit(Some("idem-crash"));
        failing.fail_after_receipt_write = true;
        assert!(matches!(
            store.commit_wf_atomically(&failing),
            Err(DurableError::DurableCommitFailed(_))
        ));

        // Transaction rolled back: idempotency should not exist.
        assert!(store.get_idempotent("idem-crash").unwrap().is_none());

        // Retry succeeds and writes exactly once.
        let mut retry = sample_commit(Some("idem-crash"));
        retry.receipt_cid = "b3:receipt-crash".to_string();
        retry.outbox_events[0].payload_json = serde_json::json!({"receipt_cid":"b3:receipt-crash"});
        store.commit_wf_atomically(&retry).unwrap();
        let cached = store.get_idempotent("idem-crash").unwrap().unwrap();
        assert_eq!(cached.receipt_cid, "b3:receipt-crash");
    }

    #[test]
    fn outbox_retries_and_acks() {
        let store = make_store("outbox.db");
        let commit = sample_commit(Some("idem-outbox"));
        store.commit_wf_atomically(&commit).unwrap();

        // First claim
        let claimed1 = store.claim_outbox(10).unwrap();
        assert_eq!(claimed1.len(), 1);
        let ev = &claimed1[0];

        // Simulate failure and requeue.
        let next = chrono::Utc::now().timestamp() - 1;
        store.nack_outbox(ev.id, next).unwrap();

        // Claim again then ack.
        let claimed2 = store.claim_outbox(10).unwrap();
        assert_eq!(claimed2.len(), 1);
        store.ack_outbox(claimed2[0].id).unwrap();

        assert_eq!(store.outbox_pending().unwrap(), 0);
    }

    #[test]
    fn get_receipt_returns_persisted_json() {
        let store = make_store("receipt_get.db");
        let commit = sample_commit(Some("idem-receipt"));
        store.commit_wf_atomically(&commit).unwrap();

        let receipt = store.get_receipt("b3:receipt-1").unwrap().unwrap();
        assert_eq!(receipt["@type"], "ubl/receipt");
        assert_eq!(receipt["ok"], true);

        let missing = store.get_receipt("b3:missing").unwrap();
        assert!(missing.is_none());
    }
}
