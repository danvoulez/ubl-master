use anyhow::Result;
use tracing::info;

use ubl_book_types::{SectionGenerateJob, SectionReceipt, SectionState, SectionStatus};

use crate::ai_client::{build_generation_prompt, AiClient};
use crate::store::{blake3_cid, CasStore, StateStore};

/// Generate one section draft.
///
/// Steps:
/// 1. Build prompt from the job's fields.
/// 2. Store prompt in CAS → `prompt_cid`.
/// 3. If this is a revision, load revision notes from CAS.
/// 4. Call LLM with model = `job.author_model`.
/// 5. Store draft in CAS → `draft_cid`.
/// 6. Emit a `SectionReceipt` and update `SectionState` to `DraftReadyForReview`.
pub async fn run_generator<C: CasStore, S: StateStore, A: AiClient>(
    job: &SectionGenerateJob,
    cas: &mut C,
    states: &mut S,
    ai: &A,
) -> Result<SectionReceipt> {
    info!(
        section = %job.section_id,
        model  = %job.author_model,
        revision = job.revision_of.is_some(),
        "Generator: starting"
    );

    // Load revision notes if this is a re-generation
    let revision_notes: Option<String> = match &job.revision_notes_cid {
        Some(cid) => {
            let bytes = cas.get(cid)?;
            Some(String::from_utf8(bytes)?)
        }
        None => None,
    };

    // Build and store the prompt
    let prompt = build_generation_prompt(
        &job.title,
        &job.mission,
        &job.outline,
        &job.style,
        &job.language,
        job.word_min,
        job.word_soft_max,
        revision_notes.as_deref(),
    );
    let prompt_cid = cas.put(prompt.as_bytes())?;

    // Call the LLM
    let draft_text = ai.complete(&job.author_model, &prompt).await?;
    let word_count = count_words(&draft_text);

    // Store the draft
    let draft_cid = cas.put(draft_text.as_bytes())?;

    // Compute attempt number from current state
    let attempt = match states.load(&job.section_id) {
        Some(ref s) => s.attempts + 1,
        None => 1,
    };

    // Build the receipt chip
    let receipt = SectionReceipt {
        chip_type: "ubl/book.section.receipt.v1".into(),
        chip_ver: "1.0".into(),
        chip_world: job.chip_world.clone(),
        advisory_cid: String::new(), // filled by orchestrator if using advisories
        attempt,
        author_model: job.author_model.clone(),
        draft_cid: draft_cid.clone(),
        generate_job_cid: blake3_cid(serde_json::to_string(job)?.as_bytes()),
        passport_cid: String::new(), // filled by orchestrator
        prompt_cid,
        project_id: job.project_id.clone(),
        review_cid: None,
        section_id: job.section_id.clone(),
        tokens_used: 0, // updated by a real LLM adapter
        version: attempt,
        word_count,
    };

    // Store receipt in CAS
    let receipt_json = serde_json::to_string(&receipt)?;
    let receipt_cid = cas.put(receipt_json.as_bytes())?;

    // Advance section state
    let mut state = states.load(&job.section_id).unwrap_or_else(|| {
        SectionState::new_pending(&job.project_id, &job.section_id, &job.chip_world)
    });

    state.attempts = attempt;
    state.latest_receipt_cid = Some(receipt_cid.clone());
    state.status = SectionStatus::DraftReadyForReview;
    states.save(&state)?;

    info!(
        section = %job.section_id,
        receipt_cid = %receipt_cid,
        words = word_count,
        "Generator: done"
    );

    Ok(receipt)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn count_words(text: &str) -> u32 {
    text.split_whitespace().count() as u32
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai_client::StubAiClient;
    use crate::store::{MemCasStore, MemStateStore};
    use ubl_book_types::SectionGenerateJob;

    fn make_job() -> SectionGenerateJob {
        let mut job = SectionGenerateJob::new("mybook", "vol01/ch01/1.1", "a/test/t/dev");
        job.author_model = "claude-opus-4".into();
        job.title = "Introduction".into();
        job.mission = "Introduce the reader to the topic.".into();
        job.outline = vec!["What is X".into(), "Why X matters".into()];
        job.style = "technical".into();
        job.language = "en".into();
        job
    }

    #[tokio::test]
    async fn test_generator_happy_path() {
        let job = make_job();
        let mut cas = MemCasStore::default();
        let mut states = MemStateStore::default();
        let ai = StubAiClient::new("This is the draft text with plenty of words to pass minimum.");

        let receipt = run_generator(&job, &mut cas, &mut states, &ai)
            .await
            .unwrap();

        assert_eq!(receipt.section_id, "vol01/ch01/1.1");
        assert_eq!(receipt.project_id, "mybook");
        assert_eq!(receipt.attempt, 1);
        assert!(receipt.word_count > 0);
        assert!(!receipt.draft_cid.is_empty());
        assert!(!receipt.prompt_cid.is_empty());
    }

    #[tokio::test]
    async fn test_generator_increments_attempt() {
        let job = make_job();
        let mut cas = MemCasStore::default();
        let mut states = MemStateStore::default();
        let ai = StubAiClient::new("draft v1");

        let r1 = run_generator(&job, &mut cas, &mut states, &ai)
            .await
            .unwrap();
        assert_eq!(r1.attempt, 1);

        // Simulate Critic failing → Revising → trigger second generation
        let r2 = run_generator(&job, &mut cas, &mut states, &ai)
            .await
            .unwrap();
        assert_eq!(r2.attempt, 2);
    }

    #[tokio::test]
    async fn test_generator_state_is_draft_ready() {
        let job = make_job();
        let mut cas = MemCasStore::default();
        let mut states = MemStateStore::default();
        let ai = StubAiClient::new("some draft");

        run_generator(&job, &mut cas, &mut states, &ai)
            .await
            .unwrap();

        let state = states.load("vol01/ch01/1.1").unwrap();
        assert_eq!(state.status, SectionStatus::DraftReadyForReview);
    }
}
