use serde::{Deserialize, Serialize};

/// Chip `ubl/book.section.generate.v1` — triggers generation of one section.
/// Keys in NRF-1 order (alphabetical).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionGenerateJob {
    /// UBL chip type
    #[serde(rename = "@type")]
    pub chip_type: String,
    /// UBL chip version
    #[serde(rename = "@ver")]
    pub chip_ver: String,
    /// UBL world scope
    #[serde(rename = "@world")]
    pub chip_world: String,
    /// Author model id, e.g. "claude-opus-4"
    pub author_model: String,
    /// Paths to source code files for context
    #[serde(default)]
    pub code_files: Vec<String>,
    /// Language tag
    pub language: String,
    /// Max auto-revision attempts (UNC-1 int)
    pub max_attempts: u32,
    /// Mission statement for this section
    pub mission: String,
    /// Outline points
    #[serde(default)]
    pub outline: Vec<String>,
    /// Project id
    pub project_id: String,
    /// CID of the previous receipt this revises (only set on re-generation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision_of: Option<String>,
    /// CAS CID pointing to revision instructions text (only set on re-generation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision_notes_cid: Option<String>,
    /// Stable section id: "vol01/ch01/1.1"
    pub section_id: String,
    /// Style key
    pub style: String,
    /// Section title
    pub title: String,
    /// Minimum word count (UNC-1 int)
    pub word_min: u32,
    /// Soft upper word count (UNC-1 int)
    pub word_soft_max: u32,
}

impl SectionGenerateJob {
    pub fn new(project_id: &str, section_id: &str, world: &str) -> Self {
        Self {
            chip_type: "ubl/book.section.generate.v1".into(),
            chip_ver: "1.0".into(),
            chip_world: world.into(),
            author_model: String::new(),
            code_files: vec![],
            language: "en".into(),
            max_attempts: 3,
            mission: String::new(),
            outline: vec![],
            project_id: project_id.into(),
            revision_of: None,
            revision_notes_cid: None,
            section_id: section_id.into(),
            style: String::new(),
            title: String::new(),
            word_min: 800,
            word_soft_max: 3000,
        }
    }

    pub fn is_revision(&self) -> bool {
        self.revision_of.is_some()
    }
}
