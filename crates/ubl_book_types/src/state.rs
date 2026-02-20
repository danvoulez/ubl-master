use serde::{Deserialize, Serialize};

/// All possible lifecycle states for a section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SectionStatus {
    /// No generation job has been issued yet
    Pending,
    /// A generate job exists; Generator is working
    Generating,
    /// Draft exists; waiting for Critic
    DraftReadyForReview,
    /// Critic is running
    UnderReview,
    /// Critic passed; waiting for human approval
    ReadyForApproval,
    /// Critic failed but attempts remain; Revisor will re-generate
    Revising,
    /// Human approved — final
    Approved,
    /// Max attempts exhausted or human flagged — needs manual edit
    NeedsHumanEdit,
}

/// Chip `ubl/book.section.state.v1` — the authoritative state of one section.
/// Keys in NRF-1 order (alphabetical).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionState {
    #[serde(rename = "@type")]
    pub chip_type: String,
    #[serde(rename = "@ver")]
    pub chip_ver: String,
    #[serde(rename = "@world")]
    pub chip_world: String,
    /// How many generation attempts have been made (UNC-1 int)
    pub attempts: u32,
    /// Last grade from Critic (absent if not yet reviewed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_grade: Option<String>,
    /// CID of latest receipt (absent if not yet generated)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_receipt_cid: Option<String>,
    /// Project id
    pub project_id: String,
    /// Stable section id
    pub section_id: String,
    /// Current lifecycle status
    pub status: SectionStatus,
}

impl SectionState {
    pub fn new_pending(project_id: &str, section_id: &str, world: &str) -> Self {
        Self {
            chip_type: "ubl/book.section.state.v1".into(),
            chip_ver: "1.0".into(),
            chip_world: world.into(),
            attempts: 0,
            last_grade: None,
            latest_receipt_cid: None,
            project_id: project_id.into(),
            section_id: section_id.into(),
            status: SectionStatus::Pending,
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self.status, SectionStatus::Approved | SectionStatus::NeedsHumanEdit)
    }

    pub fn is_in_progress(&self) -> bool {
        matches!(
            self.status,
            SectionStatus::Generating | SectionStatus::UnderReview | SectionStatus::Revising
        )
    }
}
