//! LLM Observer - Consumes pipeline events for AI-powered observability
//!
//! Subscribes to the in-process EventBus. In production, this will call
//! an actual LLM via the AI Passport system (Sprint 4).

use crate::event_bus::{EventBus, ReceiptEvent};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// AI Analysis of a receipt event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptAnalysis {
    pub receipt_cid: String,
    pub pipeline_stage: String,
    pub analysis_type: String,
    pub insights: Vec<String>,
    pub anomalies: Vec<String>,
    pub recommendations: Vec<String>,
    pub risk_score: f32,
    pub timestamp: String,
}

/// LLM Observer for pipeline events
pub struct LlmObserver {
    running: Arc<RwLock<bool>>,
}

impl LlmObserver {
    pub fn new() -> Self {
        Self {
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Start observing events from the bus (spawns a background task)
    pub async fn start(&self, event_bus: &EventBus) {
        let mut running = self.running.write().await;
        if *running {
            return;
        }
        *running = true;
        drop(running);

        let mut rx = event_bus.subscribe();
        let running_flag = self.running.clone();

        tokio::spawn(async move {
            while *running_flag.read().await {
                match rx.recv().await {
                    Ok(event) => {
                        let analysis = Self::analyze(&event);
                        info!(
                            stage = %analysis.pipeline_stage,
                            receipt_cid = %analysis.receipt_cid,
                            risk_score = analysis.risk_score,
                            "observer analysis"
                        );
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!(skipped = n, "observer lagged");
                    }
                    Err(_) => break, // channel closed
                }
            }
        });
    }

    fn analyze(event: &ReceiptEvent) -> ReceiptAnalysis {
        let mut risk_score: f32 = 0.1;
        let mut insights = vec![];
        let mut anomalies = vec![];
        let mut recommendations = vec![];

        match event.pipeline_stage.as_str() {
            "wf" => {
                if event.decision.as_deref() == Some("deny") {
                    insights.push("Request denied by policy".to_string());
                    anomalies.push("Security event".to_string());
                    recommendations.push("Review policy rules".to_string());
                    risk_score = 0.8;
                } else {
                    insights.push("Request allowed".to_string());
                    if let Some(d) = event.duration_ms {
                        if d > 100 {
                            anomalies.push(format!("Slow: {}ms", d));
                            risk_score += 0.3;
                        }
                    }
                }
            }
            stage => {
                insights.push(format!("Stage {} completed", stage));
            }
        }

        ReceiptAnalysis {
            receipt_cid: event.receipt_cid.clone(),
            pipeline_stage: event.pipeline_stage.clone(),
            analysis_type: format!("{}_analysis", event.pipeline_stage),
            insights,
            anomalies,
            recommendations,
            risk_score,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub async fn stop(&self) {
        let mut running = self.running.write().await;
        *running = false;
    }

    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }
}

impl Default for LlmObserver {
    fn default() -> Self {
        Self::new()
    }
}
