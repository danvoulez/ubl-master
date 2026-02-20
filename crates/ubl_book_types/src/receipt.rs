use serde::{Deserialize, Serialize};

/// Chip `ubl/book.section.receipt.v1` — produced after successful generation.
/// Keys in NRF-1 order (alphabetical).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionReceipt {
    #[serde(rename = "@type")]
    pub chip_type: String,
    #[serde(rename = "@ver")]
    pub chip_ver: String,
    #[serde(rename = "@world")]
    pub chip_world: String,
    /// CID of the advisory chip that called the LLM
    pub advisory_cid: String,
    /// Attempt number (UNC-1 int, starts at 1)
    pub attempt: u32,
    /// Model used for generation
    pub author_model: String,
    /// CID of the generated markdown text in CAS
    pub draft_cid: String,
    /// CID of the generate job chip that triggered this
    pub generate_job_cid: String,
    /// AI Passport CID used for this generation
    pub passport_cid: String,
    /// CID of the prompt used (for reproducibility)
    pub prompt_cid: String,
    /// Project id
    pub project_id: String,
    /// CID of a review (set after critic runs)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_cid: Option<String>,
    /// Stable section id
    pub section_id: String,
    /// Tokens consumed (UNC-1 int)
    pub tokens_used: u32,
    /// Version of this receipt within the section lifecycle (UNC-1 int)
    pub version: u32,
    /// Word count of the generated text (UNC-1 int)
    pub word_count: u32,
}

impl SectionReceipt {
    pub fn new(project_id: &str, section_id: &str, world: &str, attempt: u32) -> Self {
        Self {
            chip_type: "ubl/book.section.receipt.v1".into(),
            chip_ver: "1.0".into(),
            chip_world: world.into(),
            advisory_cid: String::new(),
            attempt,
            author_model: String::new(),
            draft_cid: String::new(),
            generate_job_cid: String::new(),
            passport_cid: String::new(),
            prompt_cid: String::new(),
            project_id: project_id.into(),
            review_cid: None,
            section_id: section_id.into(),
            tokens_used: 0,
            version: attempt,
            word_count: 0,
        }
    }
}
