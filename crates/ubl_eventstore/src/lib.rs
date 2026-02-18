use chrono::DateTime;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sled::IVec;
use std::path::Path;

const TREE_EVENTS: &str = "events";
const TREE_IDX_TIME: &str = "idx_time";
const TREE_IDX_WORLD: &str = "idx_world";
const TREE_IDX_STAGE: &str = "idx_stage";
const TREE_IDX_TYPE: &str = "idx_type";
const TREE_IDX_DECISION: &str = "idx_decision";
const TREE_IDX_CODE: &str = "idx_code";
const TREE_IDX_ACTOR: &str = "idx_actor";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventQuery {
    pub world: Option<String>,
    pub stage: Option<String>,
    pub decision: Option<String>,
    pub code: Option<String>,
    pub chip_type: Option<String>,
    pub actor: Option<String>,
    pub since: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRecord {
    pub event_id: String,
    pub when_ms: i64,
    pub event: Value,
}

#[derive(Debug, Clone)]
pub struct EventStore {
    db: sled::Db,
}

#[derive(Debug, thiserror::Error)]
pub enum EventStoreError {
    #[error("sled: {0}")]
    Sled(String),
    #[error("serde: {0}")]
    Serde(String),
    #[error("invalid event: {0}")]
    InvalidEvent(String),
}

impl EventStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EventStoreError> {
        let db = sled::open(path).map_err(|e| EventStoreError::Sled(e.to_string()))?;
        let store = Self { db };
        store.ensure_trees()?;
        Ok(store)
    }

    pub fn from_env() -> Result<Option<Self>, EventStoreError> {
        let enabled = std::env::var("UBL_EVENTSTORE_ENABLED")
            .ok()
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "on"))
            .unwrap_or(true);
        if !enabled {
            return Ok(None);
        }
        let path = std::env::var("UBL_EVENTSTORE_PATH").unwrap_or_else(|_| "./data/events".into());
        Self::open(path).map(Some)
    }

    fn ensure_trees(&self) -> Result<(), EventStoreError> {
        for t in [
            TREE_EVENTS,
            TREE_IDX_TIME,
            TREE_IDX_WORLD,
            TREE_IDX_STAGE,
            TREE_IDX_TYPE,
            TREE_IDX_DECISION,
            TREE_IDX_CODE,
            TREE_IDX_ACTOR,
        ] {
            self.db
                .open_tree(t)
                .map_err(|e| EventStoreError::Sled(e.to_string()))?;
        }
        Ok(())
    }

    pub fn append_event_json(&self, event: &Value) -> Result<bool, EventStoreError> {
        let record = normalize_event(event)?;
        let events = self
            .db
            .open_tree(TREE_EVENTS)
            .map_err(|e| EventStoreError::Sled(e.to_string()))?;

        let pk = record.event_id.as_bytes();
        if events
            .contains_key(pk)
            .map_err(|e| EventStoreError::Sled(e.to_string()))?
        {
            return Ok(false);
        }

        let bytes =
            serde_json::to_vec(&record.event).map_err(|e| EventStoreError::Serde(e.to_string()))?;
        events
            .insert(pk, bytes)
            .map_err(|e| EventStoreError::Sled(e.to_string()))?;

        self.insert_indexes(&record)?;
        self.db
            .flush()
            .map_err(|e| EventStoreError::Sled(e.to_string()))?;
        Ok(true)
    }

    pub fn rebuild_indexes(&self) -> Result<(), EventStoreError> {
        for tree_name in [
            TREE_IDX_TIME,
            TREE_IDX_WORLD,
            TREE_IDX_STAGE,
            TREE_IDX_TYPE,
            TREE_IDX_DECISION,
            TREE_IDX_CODE,
            TREE_IDX_ACTOR,
        ] {
            let tree = self
                .db
                .open_tree(tree_name)
                .map_err(|e| EventStoreError::Sled(e.to_string()))?;
            tree.clear()
                .map_err(|e| EventStoreError::Sled(e.to_string()))?;
        }

        let events = self
            .db
            .open_tree(TREE_EVENTS)
            .map_err(|e| EventStoreError::Sled(e.to_string()))?;
        for kv in events.iter() {
            let (_id, raw) = kv.map_err(|e| EventStoreError::Sled(e.to_string()))?;
            let event: Value =
                serde_json::from_slice(&raw).map_err(|e| EventStoreError::Serde(e.to_string()))?;
            let record = normalize_event(&event)?;
            self.insert_indexes(&record)?;
        }

        self.db
            .flush()
            .map_err(|e| EventStoreError::Sled(e.to_string()))?;
        Ok(())
    }

    pub fn query(&self, query: &EventQuery) -> Result<Vec<Value>, EventStoreError> {
        let events = self
            .db
            .open_tree(TREE_EVENTS)
            .map_err(|e| EventStoreError::Sled(e.to_string()))?;
        let idx_time = self
            .db
            .open_tree(TREE_IDX_TIME)
            .map_err(|e| EventStoreError::Sled(e.to_string()))?;

        let limit = query.limit.unwrap_or(200).clamp(1, 2_000);
        let start_ms = parse_since_to_ms(query.since.as_deref()).unwrap_or(0);
        let start_key = format!("{:020}\x1f", start_ms);

        let mut out = Vec::with_capacity(limit);
        for item in idx_time.range(start_key.as_bytes()..) {
            let (k, _v) = item.map_err(|e| EventStoreError::Sled(e.to_string()))?;
            let Some(event_id) = extract_event_id_from_index_key(&k) else {
                continue;
            };
            let Some(raw) = events
                .get(event_id.as_bytes())
                .map_err(|e| EventStoreError::Sled(e.to_string()))?
            else {
                continue;
            };
            let event: Value =
                serde_json::from_slice(&raw).map_err(|e| EventStoreError::Serde(e.to_string()))?;
            if matches_query(&event, query) {
                out.push(event);
                if out.len() >= limit {
                    break;
                }
            }
        }
        Ok(out)
    }

    fn insert_indexes(&self, record: &EventRecord) -> Result<(), EventStoreError> {
        let idx_time = self
            .db
            .open_tree(TREE_IDX_TIME)
            .map_err(|e| EventStoreError::Sled(e.to_string()))?;
        idx_time
            .insert(
                time_index_key(record.when_ms, &record.event_id),
                IVec::from(&[][..]),
            )
            .map_err(|e| EventStoreError::Sled(e.to_string()))?;

        let world = event_world(&record.event).unwrap_or_else(|| "a/system".into());
        self.insert_dim(TREE_IDX_WORLD, &world, record.when_ms, &record.event_id)?;
        if let Some(stage) = event_stage(&record.event) {
            self.insert_dim(TREE_IDX_STAGE, &stage, record.when_ms, &record.event_id)?;
        }
        if let Some(chip_type) = event_chip_type(&record.event) {
            self.insert_dim(TREE_IDX_TYPE, &chip_type, record.when_ms, &record.event_id)?;
        }
        if let Some(decision) = event_decision(&record.event) {
            self.insert_dim(
                TREE_IDX_DECISION,
                &decision,
                record.when_ms,
                &record.event_id,
            )?;
        }
        if let Some(code) = event_code(&record.event) {
            self.insert_dim(TREE_IDX_CODE, &code, record.when_ms, &record.event_id)?;
        }
        if let Some(actor) = event_actor(&record.event) {
            self.insert_dim(TREE_IDX_ACTOR, &actor, record.when_ms, &record.event_id)?;
        }

        Ok(())
    }

    fn insert_dim(
        &self,
        tree: &str,
        value: &str,
        when_ms: i64,
        event_id: &str,
    ) -> Result<(), EventStoreError> {
        let t = self
            .db
            .open_tree(tree)
            .map_err(|e| EventStoreError::Sled(e.to_string()))?;
        t.insert(dim_index_key(value, when_ms, event_id), IVec::from(&[][..]))
            .map_err(|e| EventStoreError::Sled(e.to_string()))?;
        Ok(())
    }
}

fn normalize_event(input: &Value) -> Result<EventRecord, EventStoreError> {
    let mut event = input.clone();
    let event_obj = event
        .as_object_mut()
        .ok_or_else(|| EventStoreError::InvalidEvent("event must be object".into()))?;

    if !event_obj.contains_key("@type") {
        event_obj.insert("@type".into(), Value::String("ubl/event".into()));
    }
    if !event_obj.contains_key("@ver") {
        event_obj.insert("@ver".into(), Value::String("1.0.0".into()));
    }

    let when = event_obj
        .get("when")
        .and_then(|v| v.as_str())
        .or_else(|| event_obj.get("timestamp").and_then(|v| v.as_str()))
        .ok_or_else(|| EventStoreError::InvalidEvent("missing when/timestamp".into()))?;
    let when_ms = DateTime::parse_from_rfc3339(when)
        .map_err(|e| EventStoreError::InvalidEvent(format!("invalid when: {}", e)))?
        .timestamp_millis();

    let event_id = if let Some(id) = event_obj.get("@id").and_then(|v| v.as_str()) {
        id.to_string()
    } else {
        let receipt_cid = event_obj
            .get("receipt")
            .and_then(|r| r.get("cid"))
            .and_then(|v| v.as_str())
            .or_else(|| event_obj.get("receipt_cid").and_then(|v| v.as_str()))
            .unwrap_or("none");
        let stage = event_obj
            .get("stage")
            .and_then(|v| v.as_str())
            .or_else(|| event_obj.get("pipeline_stage").and_then(|v| v.as_str()))
            .unwrap_or("UNKNOWN");
        let source = event_obj
            .get("source")
            .and_then(|v| v.as_str())
            .unwrap_or("pipeline");
        let digest = blake3::hash(format!("{}|{}|{}", receipt_cid, stage, source).as_bytes());
        format!("evt_{}", hex::encode(&digest.as_bytes()[..12]))
    };

    event_obj.insert("@id".into(), Value::String(event_id.clone()));

    Ok(EventRecord {
        event_id,
        when_ms,
        event,
    })
}

fn parse_since_to_ms(since: Option<&str>) -> Option<i64> {
    let since = since?;
    if let Ok(ts) = since.parse::<i64>() {
        return Some(ts);
    }
    DateTime::parse_from_rfc3339(since)
        .ok()
        .map(|dt| dt.timestamp_millis())
}

fn time_index_key(when_ms: i64, event_id: &str) -> Vec<u8> {
    format!("{:020}\x1f{}", when_ms, event_id).into_bytes()
}

fn dim_index_key(value: &str, when_ms: i64, event_id: &str) -> Vec<u8> {
    format!("{}\x1f{:020}\x1f{}", value, when_ms, event_id).into_bytes()
}

fn extract_event_id_from_index_key(key: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(key).ok()?;
    let mut parts = s.rsplitn(2, '\x1f');
    let id = parts.next()?;
    Some(id.to_string())
}

fn event_world(event: &Value) -> Option<String> {
    event
        .get("@world")
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
        .or_else(|| {
            event
                .get("world")
                .and_then(|v| v.as_str())
                .map(ToString::to_string)
        })
}

fn event_stage(event: &Value) -> Option<String> {
    event
        .get("stage")
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
        .or_else(|| {
            event
                .get("pipeline_stage")
                .and_then(|v| v.as_str())
                .map(ToString::to_string)
        })
}

fn event_chip_type(event: &Value) -> Option<String> {
    event
        .get("chip")
        .and_then(|v| v.get("type"))
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
        .or_else(|| {
            event
                .get("chip_type")
                .and_then(|v| v.as_str())
                .map(ToString::to_string)
        })
        .or_else(|| {
            event
                .get("receipt_type")
                .and_then(|v| v.as_str())
                .map(ToString::to_string)
        })
}

fn event_decision(event: &Value) -> Option<String> {
    event
        .get("receipt")
        .and_then(|v| v.get("decision"))
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
        .or_else(|| {
            event
                .get("decision")
                .and_then(|v| v.as_str())
                .map(ToString::to_string)
        })
}

fn event_code(event: &Value) -> Option<String> {
    event
        .get("receipt")
        .and_then(|v| v.get("code"))
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
        .or_else(|| {
            event
                .get("code")
                .and_then(|v| v.as_str())
                .map(ToString::to_string)
        })
}

fn event_actor(event: &Value) -> Option<String> {
    event
        .get("actor")
        .and_then(|v| v.get("kid"))
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
        .or_else(|| {
            event
                .get("actor")
                .and_then(|v| v.as_str())
                .map(ToString::to_string)
        })
}

fn matches_query(event: &Value, q: &EventQuery) -> bool {
    if let Some(world) = &q.world {
        if event_world(event).as_deref() != Some(world.as_str()) {
            return false;
        }
    }
    if let Some(stage) = &q.stage {
        let actual = event_stage(event).unwrap_or_default();
        if !actual.eq_ignore_ascii_case(stage) {
            return false;
        }
    }
    if let Some(decision) = &q.decision {
        let actual = event_decision(event).unwrap_or_default();
        if !actual.eq_ignore_ascii_case(decision) {
            return false;
        }
    }
    if let Some(code) = &q.code {
        if event_code(event).as_deref() != Some(code.as_str()) {
            return false;
        }
    }
    if let Some(actor) = &q.actor {
        if event_actor(event).as_deref() != Some(actor.as_str()) {
            return false;
        }
    }
    if let Some(chip_type) = &q.chip_type {
        if !matches_type_glob(event_chip_type(event).as_deref().unwrap_or(""), chip_type) {
            return false;
        }
    }

    true
}

fn matches_type_glob(actual: &str, pattern: &str) -> bool {
    if pattern.contains('*') {
        if pattern == "*" {
            return true;
        }
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.len() == 2 {
            return actual.starts_with(parts[0]) && actual.ends_with(parts[1]);
        }
        return actual.contains(parts[0]);
    }
    actual == pattern
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event(id: &str, when: &str, world: &str, stage: &str, decision: &str) -> Value {
        serde_json::json!({
            "@type": "ubl/event",
            "@ver": "1.0.0",
            "@id": id,
            "@world": world,
            "source": "pipeline",
            "stage": stage,
            "when": when,
            "chip": {"type": "ubl/document", "id": "doc-1", "ver": "1.0"},
            "receipt": {"cid": "b3:rcpt-1", "decision": decision, "code": "ok"},
            "actor": {"kid": "did:key:z1#k1"}
        })
    }

    #[test]
    fn append_dedups_by_event_id() {
        let dir = tempfile::tempdir().unwrap();
        let store = EventStore::open(dir.path()).unwrap();

        let e = sample_event(
            "evt-1",
            "2026-02-18T12:00:00.000Z",
            "a/acme/t/prod",
            "WF",
            "ALLOW",
        );
        assert!(store.append_event_json(&e).unwrap());
        assert!(!store.append_event_json(&e).unwrap());
    }

    #[test]
    fn query_filters_work() {
        let dir = tempfile::tempdir().unwrap();
        let store = EventStore::open(dir.path()).unwrap();

        let e1 = sample_event(
            "evt-1",
            "2026-02-18T12:00:00.000Z",
            "a/acme/t/prod",
            "WF",
            "ALLOW",
        );
        let e2 = sample_event(
            "evt-2",
            "2026-02-18T12:00:01.000Z",
            "a/acme/t/prod",
            "CHECK",
            "DENY",
        );
        store.append_event_json(&e1).unwrap();
        store.append_event_json(&e2).unwrap();

        let only_deny = store
            .query(&EventQuery {
                decision: Some("DENY".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(only_deny.len(), 1);
        assert_eq!(only_deny[0]["@id"], "evt-2");
    }

    #[test]
    fn rebuild_indexes_from_events() {
        let dir = tempfile::tempdir().unwrap();
        let store = EventStore::open(dir.path()).unwrap();
        let e = sample_event("evt-r", "2026-02-18T12:00:00.000Z", "a/acme", "WF", "ALLOW");
        store.append_event_json(&e).unwrap();
        store.rebuild_indexes().unwrap();

        let found = store
            .query(&EventQuery {
                world: Some("a/acme".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(found.len(), 1);
    }
}
