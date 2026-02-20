use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy)]
pub struct PredictabilityConfig {
    pub alpha: f64,
    pub high_threshold: f64,
    pub low_threshold: f64,
    pub min_samples: u64,
}

impl Default for PredictabilityConfig {
    fn default() -> Self {
        Self {
            alpha: 0.25,
            high_threshold: 0.85,
            low_threshold: 0.60,
            min_samples: 4,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    AggressiveGhost,
    Balanced,
    DownloadFirst,
}

#[derive(Debug, Clone, Copy)]
pub struct GroupObservation {
    pub guessed_tiles: u64,
    pub correct_tiles: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RealtimePredictabilityMetrics {
    pub instant_hit_rate: f64,
    pub ewma_hit_rate: f64,
    pub ewma_volatility: f64,
    pub predictability_score: f64,
    pub samples: u64,
    pub mode: PolicyMode,
}

#[derive(Debug, Clone)]
pub struct RealtimePredictor {
    cfg: PredictabilityConfig,
    prev_hit_rate: Option<f64>,
    ewma_hit_rate: f64,
    ewma_volatility: f64,
    samples: u64,
}

impl RealtimePredictor {
    pub fn new(cfg: PredictabilityConfig) -> Self {
        Self {
            cfg,
            prev_hit_rate: None,
            ewma_hit_rate: 0.0,
            ewma_volatility: 0.0,
            samples: 0,
        }
    }

    pub fn observe(&mut self, observation: GroupObservation) -> RealtimePredictabilityMetrics {
        let guessed = observation.guessed_tiles.max(1);
        let correct = observation.correct_tiles.min(guessed);
        let instant_hit_rate = correct as f64 / guessed as f64;

        let vol = match self.prev_hit_rate {
            Some(prev) => (instant_hit_rate - prev).abs(),
            None => 0.0,
        };

        let a = self.cfg.alpha;
        if self.samples == 0 {
            self.ewma_hit_rate = instant_hit_rate;
            self.ewma_volatility = vol;
        } else {
            self.ewma_hit_rate = a * instant_hit_rate + (1.0 - a) * self.ewma_hit_rate;
            self.ewma_volatility = a * vol + (1.0 - a) * self.ewma_volatility;
        }

        self.prev_hit_rate = Some(instant_hit_rate);
        self.samples += 1;

        let raw_score = self.ewma_hit_rate * (1.0 - self.ewma_volatility);
        let predictability_score = raw_score.clamp(0.0, 1.0);

        let mode = if self.samples < self.cfg.min_samples {
            PolicyMode::Balanced
        } else if predictability_score >= self.cfg.high_threshold {
            PolicyMode::AggressiveGhost
        } else if predictability_score < self.cfg.low_threshold {
            PolicyMode::DownloadFirst
        } else {
            PolicyMode::Balanced
        };

        RealtimePredictabilityMetrics {
            instant_hit_rate,
            ewma_hit_rate: self.ewma_hit_rate,
            ewma_volatility: self.ewma_volatility,
            predictability_score,
            samples: self.samples,
            mode,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_stream_converges_to_aggressive_ghost() {
        let mut predictor = RealtimePredictor::new(PredictabilityConfig::default());

        let mut last = predictor.observe(GroupObservation {
            guessed_tiles: 100,
            correct_tiles: 94,
        });
        for _ in 0..9 {
            last = predictor.observe(GroupObservation {
                guessed_tiles: 100,
                correct_tiles: 95,
            });
        }

        assert!(last.predictability_score >= 0.85);
        assert_eq!(last.mode, PolicyMode::AggressiveGhost);
    }

    #[test]
    fn volatile_stream_falls_back_to_download_first() {
        let mut predictor = RealtimePredictor::new(PredictabilityConfig::default());

        let observations = [95, 20, 92, 18, 90, 25, 93, 15];
        let mut last = predictor.observe(GroupObservation {
            guessed_tiles: 100,
            correct_tiles: observations[0],
        });
        for value in observations.into_iter().skip(1) {
            last = predictor.observe(GroupObservation {
                guessed_tiles: 100,
                correct_tiles: value,
            });
        }

        assert!(last.predictability_score < 0.60);
        assert_eq!(last.mode, PolicyMode::DownloadFirst);
    }

    #[test]
    fn warmup_keeps_balanced_before_min_samples() {
        let mut predictor = RealtimePredictor::new(PredictabilityConfig::default());
        for _ in 0..3 {
            let m = predictor.observe(GroupObservation {
                guessed_tiles: 100,
                correct_tiles: 99,
            });
            assert_eq!(m.mode, PolicyMode::Balanced);
        }
    }
}
