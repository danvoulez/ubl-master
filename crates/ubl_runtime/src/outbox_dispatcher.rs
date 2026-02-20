//! Durable outbox dispatcher with retry/backoff.

use crate::durable_store::{DurableError, DurableStore, OutboxEvent};
use std::future::Future;

#[derive(Clone)]
pub struct OutboxDispatcher {
    store: DurableStore,
    base_backoff_secs: i64,
    max_backoff_secs: i64,
}

impl OutboxDispatcher {
    pub fn new(store: DurableStore) -> Self {
        Self {
            store,
            base_backoff_secs: 2,
            max_backoff_secs: 300,
        }
    }

    pub fn with_backoff(mut self, base_backoff_secs: i64, max_backoff_secs: i64) -> Self {
        self.base_backoff_secs = base_backoff_secs.max(1);
        self.max_backoff_secs = max_backoff_secs.max(self.base_backoff_secs);
        self
    }

    /// Process a single outbox batch.
    ///
    /// `handler` returns `Ok(())` on delivered event, error string otherwise.
    pub fn run_once<F>(&self, limit: usize, mut handler: F) -> Result<usize, DurableError>
    where
        F: FnMut(&OutboxEvent) -> Result<(), String>,
    {
        let events = self.store.claim_outbox(limit)?;
        let mut processed = 0usize;

        for event in events {
            match handler(&event) {
                Ok(_) => self.store.ack_outbox(event.id)?,
                Err(_) => {
                    let attempts = event.attempts.saturating_add(1) as u32;
                    let factor = 2i64.saturating_pow(attempts.min(16));
                    let backoff =
                        (self.base_backoff_secs.saturating_mul(factor)).min(self.max_backoff_secs);
                    let next = chrono::Utc::now().timestamp().saturating_add(backoff);
                    self.store.nack_outbox(event.id, next)?;
                }
            }
            processed += 1;
        }

        Ok(processed)
    }

    /// Async variant of `run_once` for network delivery handlers.
    pub async fn run_once_async<F, Fut>(
        &self,
        limit: usize,
        mut handler: F,
    ) -> Result<usize, DurableError>
    where
        F: FnMut(OutboxEvent) -> Fut,
        Fut: Future<Output = Result<(), String>>,
    {
        let events = self.store.claim_outbox(limit)?;
        let mut processed = 0usize;

        for event in events {
            let event_id = event.id;
            let attempts = event.attempts;
            match handler(event).await {
                Ok(_) => self.store.ack_outbox(event_id)?,
                Err(_) => {
                    let tries = attempts.saturating_add(1) as u32;
                    let factor = 2i64.saturating_pow(tries.min(16));
                    let backoff =
                        (self.base_backoff_secs.saturating_mul(factor)).min(self.max_backoff_secs);
                    let next = chrono::Utc::now().timestamp().saturating_add(backoff);
                    self.store.nack_outbox(event_id, next)?;
                }
            }
            processed += 1;
        }

        Ok(processed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::durable_store::{CommitInput, NewOutboxEvent};
    use serde_json::json;

    fn temp_dsn(file_name: &str) -> String {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.keep().join(file_name);
        format!("file:{}?mode=rwc&_journal_mode=WAL", path.display())
    }

    fn seed_store_with_one_event(store: &DurableStore, idem_key: &str) {
        let input = CommitInput {
            receipt_cid: format!("b3:{}", idem_key),
            receipt_json: json!({"@type":"ubl/receipt","decision":"allow"}),
            did: "did:key:z123".to_string(),
            kid: "did:key:z123#ed25519".to_string(),
            rt_hash: "b3:runtime".to_string(),
            decision: "allow".to_string(),
            idem_key: Some(idem_key.to_string()),
            chain: vec!["b3:wa".into(), "b3:tr".into(), "b3:wf".into()],
            outbox_events: vec![NewOutboxEvent {
                event_type: "emit_receipt".to_string(),
                payload_json: json!({"receipt_cid": format!("b3:{}", idem_key)}),
            }],
            created_at: chrono::Utc::now().timestamp(),
            fail_after_receipt_write: false,
        };
        store.commit_wf_atomically(&input).unwrap();
    }

    #[test]
    fn dispatcher_acks_successful_delivery() {
        let store = DurableStore::new(temp_dsn("dispatcher_ack.db")).unwrap();
        seed_store_with_one_event(&store, "ack-1");
        let dispatcher = OutboxDispatcher::new(store.clone());

        let processed = dispatcher
            .run_once(8, |_event| Ok(()))
            .expect("dispatcher run");
        assert_eq!(processed, 1);
        assert_eq!(store.outbox_pending().unwrap(), 0);
    }

    #[test]
    fn dispatcher_requeues_on_failure() {
        let store = DurableStore::new(temp_dsn("dispatcher_retry.db")).unwrap();
        seed_store_with_one_event(&store, "retry-1");
        let dispatcher = OutboxDispatcher::new(store.clone()).with_backoff(1, 2);

        let processed = dispatcher
            .run_once(8, |_event| Err("boom".to_string()))
            .expect("dispatcher run");
        assert_eq!(processed, 1);
        assert_eq!(store.outbox_pending().unwrap(), 1);
    }

    #[tokio::test]
    async fn dispatcher_async_handler_acks_success() {
        let store = DurableStore::new(temp_dsn("dispatcher_async_ack.db")).unwrap();
        seed_store_with_one_event(&store, "async-ack-1");
        let dispatcher = OutboxDispatcher::new(store.clone());

        let processed = dispatcher
            .run_once_async(8, |_event| async { Ok(()) })
            .await
            .expect("dispatcher async run");
        assert_eq!(processed, 1);
        assert_eq!(store.outbox_pending().unwrap(), 0);
    }
}
