pub mod project;
pub mod receipt;
pub mod review;
pub mod section;
pub mod state;

pub use project::{ChapterSpec, ProjectSpec, SectionRef, SectionSpec, VolumeSpec};
pub use receipt::SectionReceipt;
pub use review::{ReviewCoverage, ReviewGrade, SectionReview};
pub use section::SectionGenerateJob;
pub use state::{SectionState, SectionStatus};

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_YAML: &str = r#"
id: "test-book"
title: "Test Book"
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
            title: "First Section"
            mission: "Explain the basics"
            outline:
              - "Point A"
              - "Point B"
          - id: "1.2"
            title: "Second Section"
            mission: "Go deeper"
            priority: 8
  - id: "vol02"
    title: "Volume Two"
    chapters:
      - id: "ch02"
        title: "Chapter Two"
        sections:
          - id: "2.1"
            title: "Third Section"
            mission: "Advanced topics"
            word_min: 2000
"#;

    #[test]
    fn test_project_spec_from_yaml() {
        let spec: ProjectSpec = serde_yaml::from_str(SAMPLE_YAML).unwrap();
        assert_eq!(spec.id, "test-book");
        assert_eq!(spec.volumes.len(), 2);
        assert_eq!(spec.volumes[0].chapters[0].sections.len(), 2);
    }

    #[test]
    fn test_all_sections_iterator() {
        let spec: ProjectSpec = serde_yaml::from_str(SAMPLE_YAML).unwrap();
        let sections: Vec<_> = spec.all_sections().collect();
        assert_eq!(sections.len(), 3);
        assert_eq!(sections[0].full_id(), "vol01/ch01/1.1");
        assert_eq!(sections[1].full_id(), "vol01/ch01/1.2");
        assert_eq!(sections[2].full_id(), "vol02/ch02/2.1");
    }

    #[test]
    fn test_section_defaults() {
        let spec: ProjectSpec = serde_yaml::from_str(SAMPLE_YAML).unwrap();
        let s = &spec.volumes[0].chapters[0].sections[0];
        assert_eq!(s.word_min, 800);
        assert_eq!(s.word_soft_max, 3000);
        assert_eq!(s.max_attempts, 3);
        assert_eq!(s.priority, 5);
    }

    #[test]
    fn test_section_priority_override() {
        let spec: ProjectSpec = serde_yaml::from_str(SAMPLE_YAML).unwrap();
        let s = &spec.volumes[0].chapters[0].sections[1];
        assert_eq!(s.priority, 8);
    }

    #[test]
    fn test_section_word_min_override() {
        let spec: ProjectSpec = serde_yaml::from_str(SAMPLE_YAML).unwrap();
        let s = &spec.volumes[1].chapters[0].sections[0];
        assert_eq!(s.word_min, 2000);
    }

    #[test]
    fn test_review_grade_ordering() {
        assert!(ReviewGrade::A > ReviewGrade::B);
        assert!(ReviewGrade::BPlus > ReviewGrade::B);
        assert!(ReviewGrade::BPlus >= ReviewGrade::passing());
        assert!(ReviewGrade::B < ReviewGrade::passing());
    }

    #[test]
    fn test_review_auto_passes() {
        let review = SectionReview {
            chip_type: "ubl/book.section.review.v1".into(),
            chip_ver: "1.0".into(),
            chip_world: "a/test/t/dev".into(),
            advisory_cid: "b3:abc".into(),
            blocking_issues: vec![],
            coverage: vec![],
            critic_model: "claude-opus-4".into(),
            grade: ReviewGrade::A,
            missing_points: 0,
            project_id: "test".into(),
            receipt_cid: "b3:def".into(),
            section_id: "vol01/ch01/1.1".into(),
            suggested_edits: vec![],
        };
        assert!(review.auto_passes());
    }

    #[test]
    fn test_review_fails_with_blocking_issues() {
        let review = SectionReview {
            chip_type: "ubl/book.section.review.v1".into(),
            chip_ver: "1.0".into(),
            chip_world: "a/test/t/dev".into(),
            advisory_cid: "b3:abc".into(),
            blocking_issues: vec!["Missing code example".into()],
            coverage: vec![],
            critic_model: "claude-opus-4".into(),
            grade: ReviewGrade::A,
            missing_points: 0,
            project_id: "test".into(),
            receipt_cid: "b3:def".into(),
            section_id: "vol01/ch01/1.1".into(),
            suggested_edits: vec![],
        };
        assert!(!review.auto_passes());
    }

    #[test]
    fn test_section_state_transitions() {
        let mut state = SectionState::new_pending("test", "vol01/ch01/1.1", "a/test/t/dev");
        assert_eq!(state.status, SectionStatus::Pending);
        assert!(!state.is_terminal());
        assert!(!state.is_in_progress());

        state.status = SectionStatus::Generating;
        assert!(state.is_in_progress());

        state.status = SectionStatus::Approved;
        assert!(state.is_terminal());
    }

    #[test]
    fn test_generate_job_is_revision() {
        let mut job = SectionGenerateJob::new("test", "vol01/ch01/1.1", "a/test/t/dev");
        assert!(!job.is_revision());
        job.revision_of = Some("b3:abc".into());
        assert!(job.is_revision());
    }

    #[test]
    fn test_chips_serialize_canonical_type() {
        let job = SectionGenerateJob::new("test", "vol01/ch01/1.1", "a/test/t/dev");
        let v = serde_json::to_value(&job).unwrap();
        assert_eq!(v["@type"], "ubl/book.section.generate.v1");

        let state = SectionState::new_pending("test", "vol01/ch01/1.1", "a/test/t/dev");
        let v = serde_json::to_value(&state).unwrap();
        assert_eq!(v["@type"], "ubl/book.section.state.v1");
    }
}
