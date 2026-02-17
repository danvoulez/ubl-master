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
use ubl_receipt::{
    Decision as ReceiptDecision, PipelineStage as ReceiptPipelineStage, UnifiedReceipt,
};

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

#[derive(Debug, Clone, Default)]
pub struct StageEventContext {
    pub decision: Option<String>,
    pub duration_ms: Option<i64>,
    pub world: Option<String>,
    pub input_cid: Option<String>,
    pub binary_hash: Option<String>,
    pub build_meta: Option<serde_json::Value>,
    pub actor: Option<String>,
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

    /// Build a stage event from raw receipt data and stage context.
    pub fn from_stage_receipt(
        receipt_cid: &str,
        receipt_type: &str,
        metadata: serde_json::Value,
        pipeline_stage: &str,
        ctx: StageEventContext,
    ) -> Self {
        let mut event = Self::new(
            &format!("ubl.receipt.{}", pipeline_stage),
            receipt_cid,
            receipt_type,
            pipeline_stage,
            metadata.clone(),
        );
        event.decision = ctx.decision;
        event.duration_ms = ctx.duration_ms;
        event.input_cid = ctx.input_cid;
        event.output_cid = Some(receipt_cid.to_string());
        event.binary_hash = ctx.binary_hash;
        event.build_meta = ctx.build_meta;
        event.world = ctx.world;
        event.actor = ctx.actor;
        event.latency_ms = event.duration_ms;

        // Extract fuel_used and rb_count from receipt body if present.
        if let Some(vm) = metadata.get("vm_state") {
            event.fuel_used = vm.get("fuel_used").and_then(|v| v.as_u64());
        }
        if let Some(trace) = metadata.get("policy_trace").and_then(|v| v.as_array()) {
            event.rb_count = Some(
                trace
                    .iter()
                    .flat_map(|p| {
                        p.get("rb_results")
                            .and_then(|r| r.as_array())
                            .map(|a| a.len() as u64)
                    })
                    .sum(),
            );
        }

        // Collect artifact CIDs from the receipt body if present.
        if let Some(cid) = metadata.get("body_cid").and_then(|v| v.as_str()) {
            event.artifact_cids.push(cid.to_string());
        }

        event
    }
}

impl From<&UnifiedReceipt> for ReceiptEvent {
    fn from(receipt: &UnifiedReceipt) -> Self {
        let (pipeline_stage, input_cid, output_cid, duration_ms, fuel_used, rb_count) = receipt
            .stages
            .last()
            .map(|last| {
                let rb_count = if last.policy_trace.is_empty() {
                    None
                } else {
                    Some(
                        last.policy_trace
                            .iter()
                            .map(|p| p.rb_results.len() as u64)
                            .sum(),
                    )
                };
                (
                    stage_to_wire(last.stage).to_string(),
                    Some(last.input_cid.clone()),
                    last.output_cid.clone(),
                    Some(last.duration_ms),
                    last.fuel_used,
                    rb_count,
                )
            })
            .unwrap_or_else(|| ("wf".to_string(), None, None, None, None, None));

        let mut event = ReceiptEvent::new(
            &format!("ubl.receipt.{}", pipeline_stage),
            receipt.receipt_cid.as_str(),
            &receipt.receipt_type,
            &pipeline_stage,
            receipt.to_json().unwrap_or_default(),
        );
        event.decision = Some(decision_to_wire(&receipt.decision).to_string());
        event.duration_ms = duration_ms;
        event.input_cid = input_cid;
        event.output_cid = output_cid.or_else(|| Some(receipt.receipt_cid.as_str().to_string()));
        event.fuel_used = fuel_used;
        event.rb_count = rb_count;
        event.world = Some(receipt.world.as_str().to_string());
        event.actor = Some(receipt.did.as_str().to_string());
        event.latency_ms = duration_ms;
        if let Some(rt) = &receipt.rt {
            event.binary_hash = Some(rt.binary_hash.clone());
            event.build_meta = serde_json::to_value(&rt.build).ok();
        }
        event
    }
}

fn stage_to_wire(stage: ReceiptPipelineStage) -> &'static str {
    match stage {
        ReceiptPipelineStage::Knock => "knock",
        ReceiptPipelineStage::WriteAhead => "wa",
        ReceiptPipelineStage::Check => "check",
        ReceiptPipelineStage::Transition => "tr",
        ReceiptPipelineStage::WriteFinished => "wf",
    }
}

fn decision_to_wire(decision: &ReceiptDecision) -> &'static str {
    match decision {
        ReceiptDecision::Allow => "allow",
        ReceiptDecision::Deny => "deny",
        ReceiptDecision::Require => "require",
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
    use ubl_receipt::{PipelineStage, StageExecution, UnifiedReceipt};

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
        let event = ReceiptEvent::new("ubl.receipt.wa", "b3:abc", "ubl/user", "wa", json!({}));
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

    #[test]
    fn from_stage_receipt_extracts_metrics() {
        let metadata = json!({
            "vm_state": { "fuel_used": 12345 },
            "policy_trace": [
                { "rb_results": [{}, {}] },
                { "rb_results": [{}] }
            ],
            "body_cid": "b3:artifact"
        });
        let event = ReceiptEvent::from_stage_receipt(
            "b3:tr",
            "ubl/transition",
            metadata,
            "tr",
            StageEventContext {
                decision: None,
                duration_ms: Some(42),
                world: Some("a/app/t/ten".to_string()),
                input_cid: Some("b3:wa".to_string()),
                binary_hash: Some("b3:bin".to_string()),
                build_meta: Some(json!({"rustc":"x"})),
                actor: Some("did:key:zX".to_string()),
            },
        );

        assert_eq!(event.pipeline_stage, "tr");
        assert_eq!(event.fuel_used, Some(12345));
        assert_eq!(event.rb_count, Some(3));
        assert_eq!(event.artifact_cids, vec!["b3:artifact"]);
        assert_eq!(event.input_cid.as_deref(), Some("b3:wa"));
        assert_eq!(event.output_cid.as_deref(), Some("b3:tr"));
    }

    #[test]
    fn from_unified_receipt_maps_last_stage() {
        let mut receipt =
            UnifiedReceipt::new("a/app/t/ten", "did:key:zDid", "did:key:zDid#k1", "nonce-1");
        receipt.receipt_cid = ubl_types::Cid::new_unchecked("b3:receipt");
        receipt.id = receipt.receipt_cid.as_str().to_string();
        receipt.decision = ubl_receipt::Decision::Allow;
        receipt.stages.push(StageExecution {
            stage: PipelineStage::WriteFinished,
            timestamp: "2026-02-17T00:00:00Z".to_string(),
            input_cid: "b3:tr".to_string(),
            output_cid: Some("b3:wf".to_string()),
            fuel_used: None,
            policy_trace: vec![],
            vm_sig: None,
            vm_sig_payload_cid: None,
            auth_token: "token".to_string(),
            duration_ms: 99,
        });

        let event: ReceiptEvent = (&receipt).into();
        assert_eq!(event.pipeline_stage, "wf");
        assert_eq!(event.event_type, "ubl.receipt.wf");
        assert_eq!(event.receipt_cid, "b3:receipt");
        assert_eq!(event.decision.as_deref(), Some("allow"));
        assert_eq!(event.input_cid.as_deref(), Some("b3:tr"));
        assert_eq!(event.output_cid.as_deref(), Some("b3:wf"));
        assert_eq!(event.duration_ms, Some(99));
    }
}
