pub mod ai_client;
pub mod critic;
pub mod generator;
pub mod revisor;
pub mod scheduler;
pub mod store;

pub use ai_client::{AiClient, StubAiClient};
pub use critic::run_critic;
pub use generator::run_generator;
pub use revisor::build_revision_job;
pub use scheduler::{schedule, schedule_revisions};
pub use store::{CasStore, MemCasStore, MemStateStore, StateStore};

#[cfg(test)]
mod tests {
    use super::*;
    use ubl_book_types::{ProjectSpec, SectionStatus};

    const MINI_YAML: &str = r#"
id: "demo"
title: "Demo Book"
language: "en"
style: "technical"
author_model: "claude-opus-4"
critic_model: "claude-opus-4"
volumes:
  - id: "vol01"
    title: "Volume One"
    chapters:
      - id: "ch01"
        title: "Chapter One"
        sections:
          - id: "1.1"
            title: "Hello World"
            mission: "Greet the world"
            outline:
              - "What is Hello World"
              - "Why it matters"
"#;

    fn good_review_json() -> String {
        r#"{
  "advisory_notes": "Great section.",
  "blocking_issues": [],
  "coverage": [
    { "covered": true, "point": "What is Hello World", "score": 95 },
    { "covered": true, "point": "Why it matters", "score": 90 }
  ],
  "grade": "A",
  "missing_points": 0,
  "suggested_edits": []
}"#
        .into()
    }

    /// Integration test: schedule → generate → critique → approve.
    #[tokio::test]
    async fn test_full_pipeline_happy_path() {
        let spec: ProjectSpec = serde_yaml::from_str(MINI_YAML).unwrap();
        let mut cas = MemCasStore::default();
        let mut states = MemStateStore::default();

        // 1. Schedule — should return one job
        let jobs = schedule(&spec, &states);
        assert_eq!(jobs.len(), 1);
        let job = &jobs[0];

        // 2. Generate
        let draft_ai = StubAiClient::new(
            "Hello World is the classic first program. It matters because it proves everything works.",
        );
        let receipt = run_generator(job, &mut cas, &mut states, &draft_ai)
            .await
            .unwrap();
        assert_eq!(receipt.section_id, "vol01/ch01/1.1");

        // 3. Critique
        let review_ai = StubAiClient::new(good_review_json());
        let review = run_critic(
            &receipt,
            &job.outline,
            &spec.critic_model,
            &mut cas,
            &mut states,
            &review_ai,
        )
        .await
        .unwrap();

        assert!(review.auto_passes());

        // 4. State should now be ReadyForApproval
        let state = states.load("vol01/ch01/1.1").unwrap();
        assert_eq!(state.status, SectionStatus::ReadyForApproval);
    }
}
