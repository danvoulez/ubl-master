use serde::{Deserialize, Serialize};

/// Letter grade for a section review.
/// Ordered from worst to best for comparison.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ReviewGrade {
    #[serde(rename = "F")]  F,
    #[serde(rename = "D")]  D,
    #[serde(rename = "C")] C,
    #[serde(rename = "B-")] BMinus,
    #[serde(rename = "B")]  B,
    #[serde(rename = "B+")] BPlus,
    #[serde(rename = "A-")] AMinus,
    #[serde(rename = "A")]  A,
    #[serde(rename = "A+")] APlus,
}

impl ReviewGrade {
    /// Minimum grade to be considered ReadyForApproval without human intervention.
    pub fn passing() -> Self {
        Self::BPlus
    }

    pub fn passes(&self) -> bool {
        self >= &Self::passing()
    }
}

/// Coverage result for one outline point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewCoverage {
    pub point: String,
    /// 0–100 (UNC-1 int)
    pub score: u32,
    pub covered: bool,
}

/// Chip `ubl/book.section.review.v1` — produced by the Critic worker.
/// Keys in NRF-1 order (alphabetical).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionReview {
    #[serde(rename = "@type")]
    pub chip_type: String,
    #[serde(rename = "@ver")]
    pub chip_ver: String,
    #[serde(rename = "@world")]
    pub chip_world: String,
    /// CID of the advisory chip that called the critic LLM
    pub advisory_cid: String,
    /// Issues that must be fixed before approval (blocks ReadyForApproval)
    #[serde(default)]
    pub blocking_issues: Vec<String>,
    /// Coverage of each outline point
    pub coverage: Vec<ReviewCoverage>,
    /// Critic model used
    pub critic_model: String,
    /// Overall letter grade
    pub grade: ReviewGrade,
    /// Number of outline points not adequately covered (UNC-1 int)
    pub missing_points: u32,
    /// Project id
    pub project_id: String,
    /// CID of the receipt being reviewed
    pub receipt_cid: String,
    /// Stable section id
    pub section_id: String,
    /// Actionable suggestions for improvement
    #[serde(default)]
    pub suggested_edits: Vec<String>,
}

impl SectionReview {
    /// True if this review allows automatic promotion to ReadyForApproval.
    pub fn auto_passes(&self) -> bool {
        self.grade.passes() && self.missing_points == 0 && self.blocking_issues.is_empty()
    }
}
