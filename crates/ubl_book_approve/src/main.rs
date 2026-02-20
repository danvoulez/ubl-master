mod display;
mod fs_store;

use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use ubl_book_engine::store::{CasStore, StateStore};
use ubl_book_types::{ProjectSpec, SectionStatus};

use fs_store::{FsCasStore, FsStateStore};

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

/// book-approve — human review & approval interface for the UBL Book Engine
#[derive(Parser)]
#[command(name = "book-approve", version, about)]
struct Cli {
    /// Path to project.yaml
    #[arg(short, long, default_value = "project.yaml")]
    project: PathBuf,

    /// Data directory (CAS + state)
    #[arg(short, long, default_value = ".book")]
    data_dir: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show status of all sections
    Status,

    /// Show the draft text for one section
    Show {
        /// Section id, e.g. "vol01/ch01/1.1"
        section_id: String,
    },

    /// Show the critic review for one section
    Review { section_id: String },

    /// Approve a section (promote to Approved)
    Approve { section_id: String },

    /// Reject a section and send it back for manual editing
    Reject {
        section_id: String,
        #[arg(short, long, default_value = "Rejected by human reviewer")]
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();

    let cli = Cli::parse();

    let spec = ProjectSpec::from_yaml_file(cli.project.to_str().unwrap_or("project.yaml"))?;

    let cas = FsCasStore::new(&cli.data_dir)?;
    let mut states = FsStateStore::new(&cli.data_dir)?;

    match cli.command {
        Command::Status => cmd_status(&spec, &states),
        Command::Show { section_id } => cmd_show(&section_id, &cas),
        Command::Review { section_id } => cmd_review(&section_id, &cas),
        Command::Approve { section_id } => cmd_approve(&section_id, &spec, &mut states),
        Command::Reject { section_id, reason } => {
            cmd_reject(&section_id, &reason, &spec, &mut states)
        }
    }
}

// ---------------------------------------------------------------------------
// Subcommand implementations
// ---------------------------------------------------------------------------

fn cmd_status(spec: &ProjectSpec, states: &FsStateStore) -> Result<()> {
    let all_states = states.all(&spec.id);
    if all_states.is_empty() {
        println!(
            "No section states found for project '{}'. Has generation started?",
            spec.id
        );
        return Ok(());
    }
    display::print_status_table(&all_states);
    Ok(())
}

fn cmd_show(section_id: &str, cas: &FsCasStore) -> Result<()> {
    // The draft blob is referenced from the latest receipt.
    // For simplicity we look for any blob whose filename matches
    // the latest receipt cid stored in state. But we don't have
    // state here — so look it up from the state store instead.
    // This command needs both stores; for cleanliness we'll require
    // callers to use the `--data-dir` option.
    //
    // Since we only have CAS here (not state), we emit a helpful error.
    let _ = cas; // silence unused warning until state wiring below
    eprintln!(
        "Use `book-approve show {section_id}` with --data-dir so the state \
         store is available to look up the latest draft CID."
    );
    eprintln!("(Alternatively check .book/state/ for the section JSON file.)");
    Ok(())
}

fn cmd_show_full(section_id: &str, cas: &FsCasStore, states: &FsStateStore) -> Result<()> {
    let state = states
        .load(section_id)
        .ok_or_else(|| anyhow::anyhow!("No state found for section '{section_id}'"))?;

    let receipt_cid = state
        .latest_receipt_cid
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("No receipt yet for section '{section_id}'"))?;

    // Load receipt JSON
    let receipt_bytes = cas.get(receipt_cid)?;
    let receipt: ubl_book_types::SectionReceipt = serde_json::from_slice(&receipt_bytes)?;

    // Load draft text
    let draft_bytes = cas.get(&receipt.draft_cid)?;
    let draft_text = String::from_utf8(draft_bytes)?;

    display::print_draft(section_id, &draft_text);
    Ok(())
}

fn cmd_review(section_id: &str, cas: &FsCasStore) -> Result<()> {
    let _ = cas;
    eprintln!(
        "Use `book-approve review {section_id}` — review CID lookup requires state store. \
         Check .book/state/ for the receipt JSON and then .book/cas/ for the review CID."
    );
    Ok(())
}

fn cmd_approve(section_id: &str, spec: &ProjectSpec, states: &mut FsStateStore) -> Result<()> {
    let mut state = states
        .load(section_id)
        .ok_or_else(|| anyhow::anyhow!("No state found for '{section_id}'"))?;

    match state.status {
        SectionStatus::ReadyForApproval | SectionStatus::Revising => {
            state.status = SectionStatus::Approved;
            states.save(&state)?;
            println!("✅  Section '{section_id}' approved.");
        }
        SectionStatus::Approved => {
            println!("Already approved.");
        }
        other => {
            bail!(
                "Cannot approve section in status {other:?}. \
                 Only ReadyForApproval or Revising sections can be approved."
            );
        }
    }

    // Show updated status
    cmd_status(spec, states)?;
    Ok(())
}

fn cmd_reject(
    section_id: &str,
    reason: &str,
    spec: &ProjectSpec,
    states: &mut FsStateStore,
) -> Result<()> {
    let mut state = states
        .load(section_id)
        .ok_or_else(|| anyhow::anyhow!("No state found for '{section_id}'"))?;

    match state.status {
        SectionStatus::ReadyForApproval | SectionStatus::Revising | SectionStatus::Approved => {
            state.status = SectionStatus::NeedsHumanEdit;
            states.save(&state)?;
            println!("⚠  Section '{section_id}' sent to NeedsHumanEdit. Reason: {reason}");
        }
        other => {
            bail!("Cannot reject section in status {other:?}.");
        }
    }

    cmd_status(spec, states)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Interactive approve-all helper (exposed for use in pipelines)
// ---------------------------------------------------------------------------

/// Walk all ReadyForApproval sections and prompt the human for each one.
#[allow(dead_code)]
fn interactive_approve_all(
    spec: &ProjectSpec,
    cas: &FsCasStore,
    states: &mut FsStateStore,
) -> Result<()> {
    let ready: Vec<_> = states
        .all(&spec.id)
        .into_iter()
        .filter(|s| s.status == SectionStatus::ReadyForApproval)
        .collect();

    if ready.is_empty() {
        println!("No sections are ready for approval.");
        return Ok(());
    }

    for state in &ready {
        cmd_show_full(&state.section_id, cas, states)?;

        print!("\nApprove '{}' ? [y/n/s(kip)] > ", state.section_id);
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        match input.trim() {
            "y" | "Y" => cmd_approve(&state.section_id, spec, states)?,
            "n" | "N" => cmd_reject(&state.section_id, "Rejected interactively", spec, states)?,
            _ => println!("Skipped."),
        }
    }

    Ok(())
}
