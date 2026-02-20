use ubl_book_types::{ProjectSpec, SectionGenerateJob, SectionRef, SectionState, SectionStatus};

use crate::store::StateStore;

/// Inspect the project spec + current states and return a list of
/// `SectionGenerateJob`s that should be dispatched right now.
///
/// Ordering: sections are yielded in descending `priority` order so that
/// high-priority sections are written first.
pub fn schedule<S: StateStore>(spec: &ProjectSpec, states: &S) -> Vec<SectionGenerateJob> {
    let mut pending: Vec<(u32, SectionRef<'_>)> = spec
        .all_sections()
        .filter_map(|sec_ref| {
            let state = states.load(&sec_ref.full_id());
            let should_schedule = match &state {
                None => true, // never seen → treat as Pending
                Some(s) => matches!(s.status, SectionStatus::Pending),
            };
            if should_schedule {
                Some((sec_ref.section.priority, sec_ref))
            } else {
                None
            }
        })
        .collect();

    // Higher priority first; stable sort preserves YAML declaration order on ties
    pending.sort_by(|a, b| b.0.cmp(&a.0));

    pending
        .into_iter()
        .map(|(_, sec_ref)| {
            let mut job = SectionGenerateJob::new(
                &spec.id,
                &sec_ref.full_id(),
                &format!("a/{}/t/dev", spec.id),
            );
            job.author_model = spec.author_model.clone();
            job.language = spec.language.clone();
            job.style = spec.style.clone();
            job.title = sec_ref.section.title.clone();
            job.mission = sec_ref.section.mission.clone();
            job.outline = sec_ref.section.outline.clone();
            job.word_min = sec_ref.section.word_min;
            job.word_soft_max = sec_ref.section.word_soft_max;
            job.max_attempts = sec_ref.section.max_attempts;
            job
        })
        .collect()
}

/// Return jobs for sections currently in `Revising` state.
///
/// Callers are expected to enrich each job with `revision_of` and
/// `revision_notes_cid` from the latest review before dispatching.
pub fn schedule_revisions<S: StateStore>(
    spec: &ProjectSpec,
    states: &S,
) -> Vec<SectionGenerateJob> {
    let mut revising: Vec<(u32, SectionRef<'_>)> = spec
        .all_sections()
        .filter_map(|sec_ref| {
            let state = states.load(&sec_ref.full_id())?;
            if state.status == SectionStatus::Revising {
                Some((sec_ref.section.priority, sec_ref))
            } else {
                None
            }
        })
        .collect();

    revising.sort_by(|a, b| b.0.cmp(&a.0));

    revising
        .into_iter()
        .map(|(_, sec_ref)| {
            let state: Option<SectionState> = states.load(&sec_ref.full_id());
            let mut job = SectionGenerateJob::new(
                &spec.id,
                &sec_ref.full_id(),
                &format!("a/{}/t/dev", spec.id),
            );
            job.author_model = spec.author_model.clone();
            job.language = spec.language.clone();
            job.style = spec.style.clone();
            job.title = sec_ref.section.title.clone();
            job.mission = sec_ref.section.mission.clone();
            job.outline = sec_ref.section.outline.clone();
            job.word_min = sec_ref.section.word_min;
            job.word_soft_max = sec_ref.section.word_soft_max;
            job.max_attempts = sec_ref.section.max_attempts;
            // Link to the previous receipt
            job.revision_of = state.and_then(|s| s.latest_receipt_cid);
            job
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemStateStore;
    use ubl_book_types::ProjectSpec;

    const SAMPLE_YAML: &str = r#"
id: "mybook"
title: "My Book"
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
            title: "Intro"
            mission: "Introduce the topic"
            priority: 10
          - id: "1.2"
            title: "Deep Dive"
            mission: "Explain in depth"
            priority: 5
          - id: "1.3"
            title: "Summary"
            mission: "Wrap up"
            priority: 7
"#;

    fn load_spec() -> ProjectSpec {
        serde_yaml::from_str(SAMPLE_YAML).unwrap()
    }

    #[test]
    fn test_schedule_all_pending() {
        let spec = load_spec();
        let states = MemStateStore::default();
        let jobs = schedule(&spec, &states);

        assert_eq!(jobs.len(), 3);
        // Should be ordered by priority descending: 10, 7, 5
        // full_id() → "vol01/ch01/1.x" (no project prefix)
        assert_eq!(jobs[0].section_id, "vol01/ch01/1.1");
        assert_eq!(jobs[1].section_id, "vol01/ch01/1.3");
        assert_eq!(jobs[2].section_id, "vol01/ch01/1.2");
    }

    #[test]
    fn test_schedule_skips_non_pending() {
        let spec = load_spec();
        let mut states = MemStateStore::default();

        // Mark 1.1 as approved — use the key that schedule() will look up
        let mut s = SectionState::new_pending("mybook", "vol01/ch01/1.1", "a/mybook/t/dev");
        s.status = SectionStatus::Approved;
        states.save(&s).unwrap();

        let jobs = schedule(&spec, &states);
        assert_eq!(jobs.len(), 2);
        assert!(jobs.iter().all(|j| j.section_id != "vol01/ch01/1.1"));
    }

    #[test]
    fn test_schedule_revisions() {
        let spec = load_spec();
        let mut states = MemStateStore::default();

        // Mark 1.2 as Revising with a receipt CID
        let mut s = SectionState::new_pending("mybook", "vol01/ch01/1.2", "a/mybook/t/dev");
        s.status = SectionStatus::Revising;
        s.latest_receipt_cid = Some("b3:abc".into());
        states.save(&s).unwrap();

        let jobs = schedule_revisions(&spec, &states);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].section_id, "vol01/ch01/1.2");
        assert_eq!(jobs[0].revision_of, Some("b3:abc".into()));
    }
}
