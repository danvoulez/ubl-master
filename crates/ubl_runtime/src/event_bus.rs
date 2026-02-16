//! Event Bus for UBL Pipeline
//!
//! In-process broadcast channel. External brokers (Iggy, etc.) can be
//! wired as modules later — the pipeline never blocks on event delivery.
//!
//! Events follow the Universal Envelope format (`@type: "ubl/event"`).
//! Each event carries `schema_version`, `idempotency_key`, and enriched
//! metadata (fuel, RB count, artifact CIDs).

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

const CHANNEL_CAPACITY: usize = 1024;

/// Current event schema version.
pub const EVENT_SCHEMA_VERSION: &str = "1.0";

/// Event bus for publishing pipeline events
pub struct EventBus {
    tx: broadcast::Sender<ReceiptEvent>,
    event_count: Arc<RwLock<u64>>,
    seen_keys: Arc<RwLock<HashSet<String>>>,
}

/// UBL Receipt Event — Universal Envelope format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptEvent {
    /// Universal Envelope: always "ubl/event"
    #[serde(rename = "@type")]
    pub at_type: String,
    /// Event subtype (e.g. "ubl.receipt.wa", "ubl.receipt.wf")
    pub event_type: String,
    /// Schema version ("1.0")
    pub schema_version: String,
    /// Idempotency key — receipt_cid (exactly-once by CID)
    pub idempotency_key: String,
    /// Receipt CID
    pub receipt_cid: String,
    /// Receipt type (chip @type)
    pub receipt_type: String,
    /// Pipeline decision (allow/deny) — present on WF events
    pub decision: Option<String>,
    /// Total pipeline duration in ms — present on WF events
    pub duration_ms: Option<i64>,
    /// RFC-3339 timestamp
    pub timestamp: String,
    /// Pipeline stage that emitted this event
    pub pipeline_stage: String,
    /// Fuel consumed by RB-VM (if applicable)
    pub fuel_used: Option<u64>,
    /// Number of RBs evaluated (if applicable)
    pub rb_count: Option<u64>,
    /// CIDs of artifacts produced/referenced
    pub artifact_cids: Vec<String>,
    /// Full receipt body
    pub metadata: serde_json::Value,

    // ── Canonical stage event fields (P1.5) ──

    /// Input CID for this stage (chip body CID or previous stage output)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_cid: Option<String>,
    /// Output CID produced by this stage
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_cid: Option<String>,
    /// BLAKE3 hash of the running binary
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_hash: Option<String>,
    /// Build metadata (rustc, os, arch, profile, git_commit)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_meta: Option<serde_json::Value>,
    /// @world anchor from the chip
    #[serde(skip_serializing_if = "Option::is_none")]
    pub world: Option<String>,
    /// Actor DID (pipeline executor)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Stage latency in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<i64>,
}

impl ReceiptEvent {
    /// Create a new event with Universal Envelope defaults.
    pub fn new(
        event_type: &str,
        receipt_cid: &str,
        receipt_type: &str,
        pipeline_stage: &str,
        metadata: serde_json::Value,
    ) -> Self {
        Self {
            at_type: "ubl/event".to_string(),
            event_type: event_type.to_string(),
            schema_version: EVENT_SCHEMA_VERSION.to_string(),
            idempotency_key: receipt_cid.to_string(),
            receipt_cid: receipt_cid.to_string(),
            receipt_type: receipt_type.to_string(),
            decision: None,
            duration_ms: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
            pipeline_stage: pipeline_stage.to_string(),
            fuel_used: None,
            rb_count: None,
            artifact_cids: vec![],
            metadata,
            input_cid: None,
            output_cid: None,
            binary_hash: None,
            build_meta: None,
            world: None,
            actor: None,
            latency_ms: None,
        }
    }
}

impl EventBus {
    /// Create new in-process event bus
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(CHANNEL_CAPACITY);
        Self {
            tx,
            event_count: Arc::new(RwLock::new(0)),
            seen_keys: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Publish a receipt event.
    /// Deduplicates by `idempotency_key` — same CID is published at most once.
    pub async fn publish_receipt(&self, event: ReceiptEvent) -> Result<(), EventBusError> {
        // Exactly-once: skip if we've already seen this idempotency_key
        {
            let mut seen = self.seen_keys.write().await;
            if !seen.insert(event.idempotency_key.clone()) {
                return Ok(()); // already published
            }
        }

        let _ = self.tx.send(event); // Ok to drop if no receivers
        let mut count = self.event_count.write().await;
        *count += 1;
        Ok(())
    }

    /// Publish without dedup (for stage-level events that share a receipt CID).
    pub async fn publish_stage_event(&self, event: ReceiptEvent) -> Result<(), EventBusError> {
        let _ = self.tx.send(event);
        let mut count = self.event_count.write().await;
        *count += 1;
        Ok(())
    }

    /// Subscribe to events
    pub fn subscribe(&self) -> broadcast::Receiver<ReceiptEvent> {
        self.tx.subscribe()
    }

    /// Total events published
    pub async fn event_count(&self) -> u64 {
        *self.event_count.read().await
    }

    /// Number of unique idempotency keys seen
    pub async fn dedup_count(&self) -> usize {
        self.seen_keys.read().await.len()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

/// Event bus errors
#[derive(Debug, thiserror::Error)]
pub enum EventBusError {
    #[error("Not connected to message broker")]
    NotConnected,
    #[error("Connection failed: {0}")]
    Connection(String),
    #[error("Failed to send message: {0}")]
    Send(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn event_has_universal_envelope() {
        let event = ReceiptEvent::new(
            "ubl.receipt.wf",
            "b3:cid123",
            "ubl/user",
            "wf",
            json!({"decision": "allow"}),
        );
        assert_eq!(event.at_type, "ubl/event");
        assert_eq!(event.schema_version, "1.0");
        assert_eq!(event.idempotency_key, "b3:cid123");
        assert_eq!(event.receipt_cid, "b3:cid123");
        assert!(event.fuel_used.is_none());
        assert!(event.rb_count.is_none());
        assert!(event.artifact_cids.is_empty());
    }

    #[tokio::test]
    async fn event_serializes_with_at_type() {
        let event = ReceiptEvent::new(
            "ubl.receipt.wa",
            "b3:abc",
            "ubl/user",
            "wa",
            json!({}),
        );
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["@type"], "ubl/event");
        assert_eq!(json["schema_version"], "1.0");
        assert_eq!(json["idempotency_key"], "b3:abc");
    }

    #[tokio::test]
    async fn publish_dedup_by_idempotency_key() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();

        let event = ReceiptEvent::new("test", "b3:same", "ubl/user", "wf", json!({}));

        // Publish twice with same idempotency_key
        bus.publish_receipt(event.clone()).await.unwrap();
        bus.publish_receipt(event.clone()).await.unwrap();

        // Only 1 should have been published
        assert_eq!(bus.event_count().await, 1);
        assert_eq!(bus.dedup_count().await, 1);

        // Receiver should get exactly 1
        let received = rx.try_recv();
        assert!(received.is_ok());
        let second = rx.try_recv();
        assert!(second.is_err()); // no second event
    }

    #[tokio::test]
    async fn publish_stage_event_no_dedup() {
        let bus = EventBus::new();

        let event = ReceiptEvent::new("test", "b3:same", "ubl/user", "wa", json!({}));

        // publish_stage_event does NOT dedup
        bus.publish_stage_event(event.clone()).await.unwrap();
        bus.publish_stage_event(event.clone()).await.unwrap();

        assert_eq!(bus.event_count().await, 2);
    }

    #[tokio::test]
    async fn event_enrichment_fields() {
        let mut event = ReceiptEvent::new("test", "b3:x", "ubl/user", "wf", json!({}));
        event.fuel_used = Some(42_000);
        event.rb_count = Some(3);
        event.artifact_cids = vec!["b3:a".into(), "b3:b".into()];
        event.decision = Some("allow".into());
        event.duration_ms = Some(55);

        assert_eq!(event.fuel_used, Some(42_000));
        assert_eq!(event.rb_count, Some(3));
        assert_eq!(event.artifact_cids.len(), 2);
        assert_eq!(event.decision.as_deref(), Some("allow"));
    }
}