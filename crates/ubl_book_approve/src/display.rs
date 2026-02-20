use ubl_book_types::{SectionState, SectionStatus};

/// Print a compact summary table of all section states for a project.
pub fn print_status_table(states: &[SectionState]) {
    let mut sorted = states.to_vec();
    sorted.sort_by(|a, b| a.section_id.cmp(&b.section_id));

    println!(
        "{:<30} {:<22} {:>8}  {}",
        "SECTION", "STATUS", "ATTEMPTS", "GRADE"
    );
    println!("{}", "-".repeat(72));

    for s in &sorted {
        let grade = s.last_grade.as_deref().unwrap_or("-");
        let status_str = status_label(&s.status);
        println!(
            "{:<30} {:<22} {:>8}  {}",
            s.section_id, status_str, s.attempts, grade
        );
    }
}

fn status_label(status: &SectionStatus) -> &'static str {
    match status {
        SectionStatus::Pending => "pending",
        SectionStatus::Generating => "generating",
        SectionStatus::DraftReadyForReview => "draft_ready_for_review",
        SectionStatus::UnderReview => "under_review",
        SectionStatus::ReadyForApproval => "ready_for_approval ✓",
        SectionStatus::Revising => "revising",
        SectionStatus::Approved => "approved ✅",
        SectionStatus::NeedsHumanEdit => "needs_human_edit ⚠",
    }
}

/// Print a single section's draft text with a header.
pub fn print_draft(section_id: &str, draft_text: &str) {
    println!("\n{}", "═".repeat(72));
    println!("  DRAFT: {section_id}");
    println!("{}", "═".repeat(72));
    println!("{draft_text}");
    println!("{}", "═".repeat(72));
}

/// Print a review summary.
#[allow(dead_code)]
pub fn print_review(review: &ubl_book_types::SectionReview) {
    println!("\n  Review summary for {}", review.section_id);
    println!("  Grade        : {:?}", review.grade);
    println!("  Missing pts  : {}", review.missing_points);

    if !review.blocking_issues.is_empty() {
        println!("  Blocking:");
        for issue in &review.blocking_issues {
            println!("    ✗ {issue}");
        }
    }

    if !review.coverage.is_empty() {
        println!("  Coverage:");
        for cov in &review.coverage {
            let mark = if cov.covered { "✓" } else { "✗" };
            println!("    {mark} [{}] {}", cov.score, cov.point);
        }
    }

    if !review.suggested_edits.is_empty() {
        println!("  Suggestions:");
        for s in &review.suggested_edits {
            println!("    → {s}");
        }
    }
}
