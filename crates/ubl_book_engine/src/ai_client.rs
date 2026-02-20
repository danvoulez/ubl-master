use anyhow::Result;

/// A simple request/response abstraction over an LLM API.
///
/// In production this maps to the Anthropic Messages API (or OpenAI).
/// In tests a `StubAiClient` returns pre-canned text without network I/O.
#[async_trait::async_trait]
pub trait AiClient: Send + Sync {
    /// Send `prompt` to the model and return the full completion text.
    async fn complete(&self, model: &str, prompt: &str) -> Result<String>;
}

// ---------------------------------------------------------------------------
// Stub implementation — deterministic, no network, useful for unit tests
// ---------------------------------------------------------------------------

/// Returns `stub_response` for every call, regardless of model or prompt.
pub struct StubAiClient {
    pub stub_response: String,
}

impl StubAiClient {
    pub fn new(response: impl Into<String>) -> Self {
        Self {
            stub_response: response.into(),
        }
    }
}

#[async_trait::async_trait]
impl AiClient for StubAiClient {
    async fn complete(&self, _model: &str, _prompt: &str) -> Result<String> {
        Ok(self.stub_response.clone())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a generation prompt for a book section.
///
/// The returned string is stored in CAS so the prompt is reproducible via CID.
pub fn build_generation_prompt(
    title: &str,
    mission: &str,
    outline: &[String],
    style: &str,
    language: &str,
    word_min: u32,
    word_soft_max: u32,
    revision_notes: Option<&str>,
) -> String {
    let mut parts = Vec::new();

    parts.push(format!(
        "You are writing a section of a book in {language} in \"{style}\" style."
    ));
    parts.push(format!("Section title: {title}"));
    parts.push(format!("Mission: {mission}"));

    if !outline.is_empty() {
        parts.push("Outline points to cover:".into());
        for (i, pt) in outline.iter().enumerate() {
            parts.push(format!("  {}. {pt}", i + 1));
        }
    }

    parts.push(format!(
        "Length: minimum {word_min} words, soft maximum {word_soft_max} words."
    ));

    if let Some(notes) = revision_notes {
        parts.push("\n--- REVISION NOTES (address all of these) ---".into());
        parts.push(notes.to_string());
        parts.push("--- END REVISION NOTES ---".into());
    }

    parts.push("\nWrite the section now. Use Markdown.".into());

    parts.join("\n")
}

/// Build a review prompt for the Critic worker.
pub fn build_review_prompt(
    title: &str,
    mission: &str,
    outline: &[String],
    draft_text: &str,
) -> String {
    let outline_str = outline
        .iter()
        .enumerate()
        .map(|(i, p)| format!("  {}. {p}", i + 1))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"You are a book editor reviewing a section draft.

Section: {title}
Mission: {mission}
Outline points:
{outline_str}

--- DRAFT ---
{draft_text}
--- END DRAFT ---

Respond with a JSON object (no markdown fence) with these keys in alphabetical order:
  advisory_notes   : string  — overall editorial commentary
  blocking_issues  : array of strings — issues that MUST be fixed before approval (empty if none)
  coverage         : array of {{ "covered": bool, "point": string, "score": 0-100 }}
  grade            : one of "A+","A","A-","B+","B","B-","C","D","F"
  missing_points   : integer — count of outline points not adequately covered
  suggested_edits  : array of strings — optional improvement suggestions
"#
    )
}
