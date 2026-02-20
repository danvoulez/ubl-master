use anyhow::Result;
use tracing::info;

use ubl_book_types::{SectionGenerateJob, SectionReview};

use crate::store::CasStore;

/// Given a failing `SectionReview`, build the revision notes string and
/// return a new `SectionGenerateJob` with `revision_of` + `revision_notes_cid` set.
///
/// The caller is responsible for checking `review.auto_passes()` before calling
/// this function. If the section is at max_attempts the caller should transition
/// it to `NeedsHumanEdit` instead.
pub fn build_revision_job<C: CasStore>(
    base_job: &SectionGenerateJob,
    review: &SectionReview,
    cas: &mut C,
    previous_receipt_cid: &str,
) -> Result<SectionGenerateJob> {
    info!(
        section = %review.section_id,
        grade   = ?review.grade,
        blocking = review.blocking_issues.len(),
        "Revisor: building revision job"
    );

    // Compile human-readable revision notes from the review
    let notes = compile_revision_notes(review);
    let revision_notes_cid = cas.put(notes.as_bytes())?;

    let mut new_job = base_job.clone();
    new_job.revision_of = Some(previous_receipt_cid.into());
    new_job.revision_notes_cid = Some(revision_notes_cid);

    Ok(new_job)
}

fn compile_revision_notes(review: &SectionReview) -> String {
    let mut lines: Vec<String> = Vec::new();

    lines.push(format!("Overall grade: {:?}", review.grade));
    lines.push(String::new());

    if !review.blocking_issues.is_empty() {
        lines.push("=== BLOCKING ISSUES (must fix) ===".into());
        for issue in &review.blocking_issues {
            lines.push(format!("- {issue}"));
        }
        lines.push(String::new());
    }

    if review.missing_points > 0 {
        lines.push(format!(
            "=== MISSING OUTLINE COVERAGE ({} point(s)) ===",
            review.missing_points
        ));
        for cov in &review.coverage {
            if !cov.covered {
                lines.push(format!(
                    "- NOT covered: {} (score {})",
                    cov.point, cov.score
                ));
            }
        }
        lines.push(String::new());
    }

    if !review.suggested_edits.is_empty() {
        lines.push("=== SUGGESTED EDITS ===".into());
        for suggestion in &review.suggested_edits {
            lines.push(format!("- {suggestion}"));
        }
    }

    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemCasStore;
    use ubl_book_types::{ReviewCoverage, ReviewGrade, SectionGenerateJob, SectionReview};

    fn make_base_job() -> SectionGenerateJob {
        let mut job = SectionGenerateJob::new("mybook", "vol01/ch01/1.1", "a/test/t/dev");
        job.author_model = "claude-opus-4".into();
        job.title = "Introduction".into();
        job.mission = "Introduce the reader.".into();
        job
    }

    fn make_failing_review() -> SectionReview {
        SectionReview {
            chip_type: "ubl/book.section.review.v1".into(),
            chip_ver: "1.0".into(),
            chip_world: "a/test/t/dev".into(),
            advisory_cid: "b3:adv".into(),
            blocking_issues: vec!["Missing code example".into()],
            coverage: vec![
                ReviewCoverage {
                    point: "What is X".into(),
                    score: 20,
                    covered: false,
                },
                ReviewCoverage {
                    point: "Why X matters".into(),
                    score: 90,
                    covered: true,
                },
            ],
            critic_model: "claude-opus-4".into(),
            grade: ReviewGrade::C,
            missing_points: 1,
            project_id: "mybook".into(),
            receipt_cid: "b3:rc1".into(),
            section_id: "vol01/ch01/1.1".into(),
            suggested_edits: vec!["Add a code example for X".into()],
        }
    }

    #[test]
    fn test_build_revision_job_sets_fields() {
        let base_job = make_base_job();
        let review = make_failing_review();
        let mut cas = MemCasStore::default();

        let revised = build_revision_job(&base_job, &review, &mut cas, "b3:receipt1").unwrap();

        assert_eq!(revised.revision_of, Some("b3:receipt1".into()));
        assert!(revised.revision_notes_cid.is_some());
    }

    #[test]
    fn test_revision_notes_contain_blocking_issues() {
        let base_job = make_base_job();
        let review = make_failing_review();
        let mut cas = MemCasStore::default();

        let revised = build_revision_job(&base_job, &review, &mut cas, "b3:rc1").unwrap();
        let notes_cid = revised.revision_notes_cid.unwrap();
        let notes_bytes = cas.get(&notes_cid).unwrap();
        let notes = String::from_utf8(notes_bytes).unwrap();

        assert!(notes.contains("Missing code example"));
        assert!(notes.contains("What is X"));
    }
}
