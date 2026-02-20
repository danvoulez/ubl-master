use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::realtime_predictability::{PolicyMode, RealtimePredictabilityMetrics};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeWindow {
    pub groups: u32,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeObserved {
    pub guessed_tiles: u64,
    pub correct_tiles: u64,
    pub corrected_tiles: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimePolicyHint {
    pub mode: PolicyMode,
    pub max_speculative_tiles_per_group: u32,
    pub prefetch_depth_groups: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimePredictabilitySidecar {
    #[serde(rename = "@type")]
    pub chip_type: String,
    #[serde(rename = "@id")]
    pub chip_id: String,
    #[serde(rename = "@ver")]
    pub chip_ver: String,
    #[serde(rename = "@world")]
    pub world: String,

    pub target_manifest: String,
    pub group_seq: u64,
    pub window: RealtimeWindow,
    pub observed: RealtimeObserved,
    pub metrics: RealtimePredictabilityMetrics,
    pub policy_hint: RealtimePolicyHint,
}

impl RealtimePredictabilitySidecar {
    pub fn from_metrics(
        chip_id: String,
        world: String,
        target_manifest: String,
        group_seq: u64,
        window: RealtimeWindow,
        observed: RealtimeObserved,
        metrics: RealtimePredictabilityMetrics,
    ) -> Self {
        let policy_hint = match metrics.mode {
            PolicyMode::AggressiveGhost => RealtimePolicyHint {
                mode: PolicyMode::AggressiveGhost,
                max_speculative_tiles_per_group: 384,
                prefetch_depth_groups: 2,
            },
            PolicyMode::Balanced => RealtimePolicyHint {
                mode: PolicyMode::Balanced,
                max_speculative_tiles_per_group: 192,
                prefetch_depth_groups: 3,
            },
            PolicyMode::DownloadFirst => RealtimePolicyHint {
                mode: PolicyMode::DownloadFirst,
                max_speculative_tiles_per_group: 32,
                prefetch_depth_groups: 6,
            },
        };

        Self {
            chip_type: "vcx/sidecar.predictability.realtime".to_string(),
            chip_id,
            chip_ver: "1.0".to_string(),
            world,
            target_manifest,
            group_seq,
            window,
            observed,
            metrics,
            policy_hint,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.chip_type != "vcx/sidecar.predictability.realtime" {
            bail!("UnexpectedRealtimeChipType({})", self.chip_type);
        }
        if self.window.groups == 0 || self.window.duration_ms == 0 {
            bail!("InvalidRealtimeWindow");
        }
        if self.observed.correct_tiles > self.observed.guessed_tiles {
            bail!("InvalidObservedCounters(correct>guessed)");
        }
        if !(0.0..=1.0).contains(&self.metrics.predictability_score) {
            bail!("InvalidPredictabilityScore");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VodRegionStrategy {
    HoldAndNoise,
    CopyPrevious,
    DownloadAggressive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VodGlobalStats {
    pub volatility_score: f64,
    pub average_shot_length_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VodRegionRule {
    pub region_id: String,
    pub tile_range_start: u32,
    pub tile_range_end: u32,
    pub strategy: VodRegionStrategy,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VodPredictabilitySidecar {
    #[serde(rename = "@type")]
    pub chip_type: String,
    #[serde(rename = "@id")]
    pub chip_id: String,
    #[serde(rename = "@ver")]
    pub chip_ver: String,
    #[serde(rename = "@world")]
    pub world: String,

    pub target_manifest: String,
    pub global_stats: VodGlobalStats,
    pub regions: Vec<VodRegionRule>,
}

impl VodPredictabilitySidecar {
    pub fn validate(&self) -> Result<()> {
        if self.chip_type != "vcx/sidecar.predictability.vod" {
            bail!("UnexpectedVodChipType({})", self.chip_type);
        }
        if !(0.0..=1.0).contains(&self.global_stats.volatility_score) {
            bail!("InvalidVodVolatilityScore");
        }
        for r in &self.regions {
            if r.tile_range_start > r.tile_range_end {
                bail!("InvalidTileRange({})", r.region_id);
            }
            if !(0.0..=1.0).contains(&r.confidence) {
                bail!("InvalidVodConfidence({})", r.region_id);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EditOperation {
    Trim {
        start_ms: u64,
        end_ms: u64,
    },
    SpliceInsert {
        at_ms: u64,
        source_manifest: String,
    },
    SwapTrackRef {
        track: String,
        from_cid: String,
        to_cid: String,
    },
    OverlayRef {
        asset_cid: String,
        x: i32,
        y: i32,
        from_ms: u64,
        to_ms: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditDecisionChip {
    #[serde(rename = "@type")]
    pub chip_type: String,
    #[serde(rename = "@id")]
    pub chip_id: String,
    #[serde(rename = "@ver")]
    pub chip_ver: String,
    #[serde(rename = "@world")]
    pub world: String,

    pub input_manifest: String,
    pub output_manifest: String,
    pub operations: Vec<EditOperation>,
    pub reencode_required: bool,
    pub editorial_receipt_cid: String,
}

impl EditDecisionChip {
    pub fn validate(&self) -> Result<()> {
        if self.chip_type != "vcx/edit.decision" {
            bail!("UnexpectedEditDecisionType({})", self.chip_type);
        }
        if self.operations.is_empty() {
            bail!("EditDecisionMustHaveOperations");
        }
        for op in &self.operations {
            match op {
                EditOperation::Trim { start_ms, end_ms } if start_ms >= end_ms => {
                    bail!("InvalidTrimRange");
                }
                EditOperation::OverlayRef { from_ms, to_ms, .. } if from_ms >= to_ms => {
                    bail!("InvalidOverlayRange");
                }
                _ => {}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::realtime_predictability::PolicyMode;

    #[test]
    fn realtime_sidecar_validation_works() {
        let sidecar = RealtimePredictabilitySidecar {
            chip_type: "vcx/sidecar.predictability.realtime".into(),
            chip_id: "b3:abc".into(),
            chip_ver: "1.0".into(),
            world: "a/episode/t/live".into(),
            target_manifest: "b3:manifest".into(),
            group_seq: 10,
            window: RealtimeWindow {
                groups: 16,
                duration_ms: 8_000,
            },
            observed: RealtimeObserved {
                guessed_tiles: 100,
                correct_tiles: 90,
                corrected_tiles: 10,
            },
            metrics: RealtimePredictabilityMetrics {
                instant_hit_rate: 0.9,
                ewma_hit_rate: 0.88,
                ewma_volatility: 0.05,
                predictability_score: 0.836,
                samples: 10,
                mode: PolicyMode::Balanced,
            },
            policy_hint: RealtimePolicyHint {
                mode: PolicyMode::Balanced,
                max_speculative_tiles_per_group: 128,
                prefetch_depth_groups: 3,
            },
        };

        sidecar.validate().unwrap();
    }

    #[test]
    fn from_metrics_assigns_mode_specific_hint() {
        let sidecar = RealtimePredictabilitySidecar::from_metrics(
            "b3:id".into(),
            "a/ep/t/live".into(),
            "b3:manifest".into(),
            12,
            RealtimeWindow {
                groups: 8,
                duration_ms: 4_000,
            },
            RealtimeObserved {
                guessed_tiles: 120,
                correct_tiles: 118,
                corrected_tiles: 2,
            },
            RealtimePredictabilityMetrics {
                instant_hit_rate: 0.983,
                ewma_hit_rate: 0.962,
                ewma_volatility: 0.01,
                predictability_score: 0.952,
                samples: 20,
                mode: PolicyMode::AggressiveGhost,
            },
        );

        assert_eq!(sidecar.policy_hint.mode, PolicyMode::AggressiveGhost);
        assert!(sidecar.policy_hint.max_speculative_tiles_per_group >= 300);
    }

    #[test]
    fn vod_sidecar_rejects_invalid_confidence() {
        let s = VodPredictabilitySidecar {
            chip_type: "vcx/sidecar.predictability.vod".into(),
            chip_id: "b3:x".into(),
            chip_ver: "1.0".into(),
            world: "a/vod".into(),
            target_manifest: "b3:m".into(),
            global_stats: VodGlobalStats {
                volatility_score: 0.2,
                average_shot_length_ms: 2000,
            },
            regions: vec![VodRegionRule {
                region_id: "r1".into(),
                tile_range_start: 0,
                tile_range_end: 10,
                strategy: VodRegionStrategy::HoldAndNoise,
                confidence: 1.2,
            }],
        };

        assert!(s.validate().is_err());
    }

    #[test]
    fn edit_decision_requires_valid_ranges() {
        let chip = EditDecisionChip {
            chip_type: "vcx/edit.decision".into(),
            chip_id: "b3:e".into(),
            chip_ver: "1.0".into(),
            world: "a/episode/t/edit".into(),
            input_manifest: "b3:in".into(),
            output_manifest: "b3:out".into(),
            operations: vec![EditOperation::Trim {
                start_ms: 2000,
                end_ms: 1000,
            }],
            reencode_required: false,
            editorial_receipt_cid: "b3:r".into(),
        };

        assert!(chip.validate().is_err());
    }
}
