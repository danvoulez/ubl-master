//! Event Bus for UBL Pipeline
//!
//! In-process broadcast channel. External brokers (Iggy, etc.) can be
//! wired as modules later — the pipeline never blocks on event delivery.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

const CHANNEL_CAPACITY: usize = 1024;

/// Event bus for publishing pipeline events
pub struct EventBus {
    tx: broadcast::Sender<ReceiptEvent>,
    event_count: Arc<RwLock<u64>>,
}

/// UBL Receipt Event for streaming
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptEvent {
    pub event_type: String,
    pub receipt_cid: String,
    pub receipt_type: String,
    pub decision: Option<String>,
    pub duration_ms: Option<i64>,
    pub timestamp: String,
    pub pipeline_stage: String,
    pub metadata: serde_json::Value,
}

impl EventBus {
    /// Create new in-process event bus
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(CHANNEL_CAPACITY);
        Self {
            tx,
            event_count: Arc::new(RwLock::new(0)),
        }
    }

    /// Publish a receipt event (never fails — drops if no subscribers)
    pub async fn publish_receipt(&self, event: ReceiptEvent) -> Result<(), EventBusError> {
        let _ = self.tx.send(event); // Ok to drop if no receivers
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