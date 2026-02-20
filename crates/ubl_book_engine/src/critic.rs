use anyhow::{bail, Result};
use tracing::info;

use ubl_book_types::{
    ReviewCoverage, ReviewGrade, SectionReceipt, SectionReview, SectionState, SectionStatus,
};

use crate::ai_client::{build_review_prompt, AiClient};
use crate::store::{CasStore, StateStore};

/// Review one section draft.
///
/// Steps:
/// 1. Load the draft text from CAS via `receipt.draft_cid`.
/// 2. Build a review prompt.
/// 3. Call LLM with model = `critic_model`.
/// 4. Parse the JSON review from the LLM response.
/// 5. Emit a `SectionReview` chip and update `SectionState`.
pub async fn run_critic<C: CasStore, S: StateStore, A: AiClient>(
    receipt: &SectionReceipt,
    outline: &[String],
    critic_model: &str,
    cas: &mut C,
    states: &mut S,
    ai: &A,
) -> Result<SectionReview> {
    info!(
        section = %receipt.section_id,
        model  = %critic_model,
        "Critic: starting"
    );

    // Load the draft
    let draft_bytes = cas.get(&receipt.draft_cid)?;
    let draft_text = String::from_utf8(draft_bytes)?;

    // We need the section title and mission — stored in the generate job chip.
    // For simplicity the caller passes outline; title/mission come from the receipt's
    // generate_job_cid. Here we extract what we can from the receipt itself and
    // let the caller supply the outline (already available from ProjectSpec).
    let prompt = build_review_prompt(
        &receipt.section_id, // title placeholder — real impl loads the job
        &receipt.section_id, // mission placeholder
        outline,
        &draft_text,
    );

    let raw_response = ai.complete(critic_model, &prompt).await?;

    // Parse the LLM response as JSON
    let review = parse_review_response(&raw_response, receipt, critic_model, outline, cas)?;

    // Update state
    let new_status = if review.auto_passes() {
        SectionStatus::ReadyForApproval
    } else if receipt.attempt >= 3 {
        SectionStatus::NeedsHumanEdit
    } else {
        SectionStatus::Revising
    };

    let mut state = states.load(&receipt.section_id).unwrap_or_else(|| {
        SectionState::new_pending(
            &receipt.project_id,
            &receipt.section_id,
            &receipt.chip_world,
        )
    });
    state.last_grade = Some(format!("{:?}", review.grade));
    state.status = new_status;
    states.save(&state)?;

    info!(
        section = %receipt.section_id,
        grade   = ?review.grade,
        passes  = review.auto_passes(),
        "Critic: done"
    );

    Ok(review)
}

// ---------------------------------------------------------------------------
// JSON parsing
// ---------------------------------------------------------------------------

/// Raw shape we expect from the LLM's JSON response.
#[derive(serde::Deserialize)]
struct RawReviewJson {
    #[serde(default)]
    advisory_notes: String,
    #[serde(default)]
    blocking_issues: Vec<String>,
    #[serde(default)]
    coverage: Vec<RawCoverageJson>,
    grade: String,
    #[serde(default)]
    missing_points: u32,
    #[serde(default)]
    suggested_edits: Vec<String>,
}

#[derive(serde::Deserialize)]
struct RawCoverageJson {
    covered: bool,
    point: String,
    score: u32,
}

fn parse_review_response<C: CasStore>(
    raw: &str,
    receipt: &SectionReceipt,
    critic_model: &str,
    outline: &[String],
    cas: &mut C,
) -> Result<SectionReview> {
    // Strip accidental markdown code fences
    let json_str = raw
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    let parsed: RawReviewJson = serde_json::from_str(json_str)
        .map_err(|e| anyhow::anyhow!("Critic JSON parse error: {e}\nRaw: {json_str}"))?;

    let grade = parse_grade(&parsed.grade)?;

    let coverage: Vec<ReviewCoverage> = if parsed.coverage.is_empty() {
        // Synthesise coverage from outline when LLM omitted it
        outline
            .iter()
            .map(|p| ReviewCoverage {
                point: p.clone(),
                score: 0,
                covered: false,
            })
            .collect()
    } else {
        parsed
            .coverage
            .into_iter()
            .map(|c| ReviewCoverage {
                point: c.point,
                score: c.score.min(100),
                covered: c.covered,
            })
            .collect()
    };

    // Store advisory notes in CAS so the review chip links to them
    let advisory_cid = cas.put(parsed.advisory_notes.as_bytes())?;

    let review = SectionReview {
        chip_type: "ubl/book.section.review.v1".into(),
        chip_ver: "1.0".into(),
        chip_world: receipt.chip_world.clone(),
        advisory_cid,
        blocking_issues: parsed.blocking_issues,
        coverage,
        critic_model: critic_model.into(),
        grade,
        missing_points: parsed.missing_points,
        project_id: receipt.project_id.clone(),
        receipt_cid: serde_json::to_string(receipt)
            .map(|s| format!("b3:{}", blake3::hash(s.as_bytes()).to_hex()))
            .unwrap_or_default(),
        section_id: receipt.section_id.clone(),
        suggested_edits: parsed.suggested_edits,
    };

    Ok(review)
}

fn parse_grade(s: &str) -> Result<ReviewGrade> {
    match s.trim() {
        "A+" => Ok(ReviewGrade::APlus),
        "A" => Ok(ReviewGrade::A),
        "A-" => Ok(ReviewGrade::AMinus),
        "B+" => Ok(ReviewGrade::BPlus),
        "B" => Ok(ReviewGrade::B),
        "B-" => Ok(ReviewGrade::BMinus),
        "C" => Ok(ReviewGrade::C),
        "D" => Ok(ReviewGrade::D),
        "F" => Ok(ReviewGrade::F),
        other => bail!("Unknown review grade: {other}"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai_client::StubAiClient;
    use crate::store::{blake3_cid, MemCasStore, MemStateStore};
    use ubl_book_types::SectionReceipt;

    fn make_receipt(cas: &mut MemCasStore) -> SectionReceipt {
        let draft_cid = cas.put(b"This is a draft with enough content.").unwrap();
        SectionReceipt {
            chip_type: "ubl/book.section.receipt.v1".into(),
            chip_ver: "1.0".into(),
            chip_world: "a/test/t/dev".into(),
            advisory_cid: String::new(),
            attempt: 1,
            author_model: "claude-opus-4".into(),
            draft_cid,
            generate_job_cid: blake3_cid(b"job"),
            passport_cid: String::new(),
            prompt_cid: blake3_cid(b"prompt"),
            project_id: "mybook".into(),
            review_cid: None,
            section_id: "vol01/ch01/1.1".into(),
            tokens_used: 0,
            version: 1,
            word_count: 7,
        }
    }

    fn good_review_json() -> &'static str {
        r#"{
  "advisory_notes": "Well written.",
  "blocking_issues": [],
  "coverage": [
    { "covered": true,  "point": "What is X",     "score": 95 },
    { "covered": true,  "point": "Why X matters",  "score": 90 }
  ],
  "grade": "A",
  "missing_points": 0,
  "suggested_edits": []
}"#
    }

    fn bad_review_json() -> &'static str {
        r#"{
  "advisory_notes": "Needs work.",
  "blocking_issues": ["Missing code example"],
  "coverage": [
    { "covered": false, "point": "What is X",    "score": 20 },
    { "covered": false, "point": "Why X matters","score": 10 }
  ],
  "grade": "C",
  "missing_points": 2,
  "suggested_edits": ["Add a code example for X"]
}"#
    }

    #[tokio::test]
    async fn test_critic_auto_passes() {
        let mut cas = MemCasStore::default();
        let mut states = MemStateStore::default();
        let receipt = make_receipt(&mut cas);
        let ai = StubAiClient::new(good_review_json());
        let outline = vec!["What is X".into(), "Why X matters".into()];

        let review = run_critic(
            &receipt,
            &outline,
            "claude-opus-4",
            &mut cas,
            &mut states,
            &ai,
        )
        .await
        .unwrap();

        assert!(review.auto_passes());
        assert_eq!(review.grade, ReviewGrade::A);

        let state = states.load("vol01/ch01/1.1").unwrap();
        assert_eq!(state.status, SectionStatus::ReadyForApproval);
    }

    #[tokio::test]
    async fn test_critic_blocking_issues() {
        let mut cas = MemCasStore::default();
        let mut states = MemStateStore::default();
        let receipt = make_receipt(&mut cas);
        let ai = StubAiClient::new(bad_review_json());
        let outline = vec!["What is X".into(), "Why X matters".into()];

        let review = run_critic(
            &receipt,
            &outline,
            "claude-opus-4",
            &mut cas,
            &mut states,
            &ai,
        )
        .await
        .unwrap();

        assert!(!review.auto_passes());
        assert_eq!(review.grade, ReviewGrade::C);
        assert!(!review.blocking_issues.is_empty());

        let state = states.load("vol01/ch01/1.1").unwrap();
        assert_eq!(state.status, SectionStatus::Revising);
    }

    #[tokio::test]
    async fn test_critic_max_attempts_needs_human() {
        let mut cas = MemCasStore::default();
        let mut states = MemStateStore::default();
        let mut receipt = make_receipt(&mut cas);
        receipt.attempt = 3; // at the limit
        let ai = StubAiClient::new(bad_review_json());
        let outline = vec![];

        run_critic(
            &receipt,
            &outline,
            "claude-opus-4",
            &mut cas,
            &mut states,
            &ai,
        )
        .await
        .unwrap();

        let state = states.load("vol01/ch01/1.1").unwrap();
        assert_eq!(state.status, SectionStatus::NeedsHumanEdit);
    }
}
