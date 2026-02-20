use serde::{Deserialize, Serialize};

/// Top-level project spec — loaded from `project.yaml`.
/// Maps to chip `ubl/book.project.v1`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectSpec {
    /// Stable identifier, e.g. "ubl-master-book"
    pub id: String,
    pub title: String,
    /// BCP-47 language tag, e.g. "en", "pt"
    pub language: String,
    /// Style key selects the base prompt template, e.g. "technical-manifesto"
    pub style: String,
    /// LLM model id used for generation, e.g. "claude-opus-4"
    pub author_model: String,
    /// LLM model id used for review, e.g. "claude-opus-4"
    pub critic_model: String,
    /// Ordered list of volumes
    pub volumes: Vec<VolumeSpec>,
}

/// A volume inside a project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeSpec {
    pub id: String,
    pub title: String,
    pub chapters: Vec<ChapterSpec>,
}

/// A chapter inside a volume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChapterSpec {
    pub id: String,
    pub title: String,
    pub sections: Vec<SectionSpec>,
}

/// A single section — the atomic unit of generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionSpec {
    /// Section id within chapter, e.g. "1.1", "3.2"
    pub id: String,
    pub title: String,
    /// One sentence: what this section must accomplish
    pub mission: String,
    /// Bullet points the section must cover (used in prompt + critic rubric)
    #[serde(default)]
    pub outline: Vec<String>,
    /// Minimum word count (UNC-1 int)
    #[serde(default = "default_word_min")]
    pub word_min: u32,
    /// Soft upper word count (UNC-1 int); generator is asked to stay under
    #[serde(default = "default_word_soft_max")]
    pub word_soft_max: u32,
    /// Max auto-revision attempts before flagging NeedsHumanEdit (UNC-1 int)
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    /// Paths to source files to include as code context (relative to repo root)
    #[serde(default)]
    pub code_files: Vec<String>,
    /// Generation priority — higher runs first (UNC-1 int)
    #[serde(default = "default_priority")]
    pub priority: u32,
}

fn default_word_min() -> u32 { 800 }
fn default_word_soft_max() -> u32 { 3000 }
fn default_max_attempts() -> u32 { 3 }
fn default_priority() -> u32 { 5 }

impl ProjectSpec {
    /// Load from a YAML file.
    pub fn from_yaml_file(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let spec: Self = serde_yaml::from_str(&content)?;
        Ok(spec)
    }

    /// Iterate over all sections in definition order.
    pub fn all_sections(&self) -> impl Iterator<Item = SectionRef<'_>> {
        self.volumes.iter().flat_map(|v| {
            v.chapters.iter().flat_map(move |c| {
                c.sections.iter().map(move |s| SectionRef {
                    volume: v,
                    chapter: c,
                    section: s,
                })
            })
        })
    }
}

/// A reference to a section within its volume/chapter context.
#[derive(Debug, Clone, Copy)]
pub struct SectionRef<'a> {
    pub volume: &'a VolumeSpec,
    pub chapter: &'a ChapterSpec,
    pub section: &'a SectionSpec,
}

impl<'a> SectionRef<'a> {
    /// Stable compound key: "vol01/ch01/1.1"
    pub fn full_id(&self) -> String {
        format!("{}/{}/{}", self.volume.id, self.chapter.id, self.section.id)
    }
}
