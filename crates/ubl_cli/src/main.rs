//! ublx - UBL Chip-as-Code CLI

use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::sync::Arc;
use ubl_ai_nrf1::{ChipFile, to_nrf1_bytes, compute_cid};

#[derive(Parser)]
#[command(name = "ublx")]
#[command(about = "UBL Chip-as-Code CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Verify chip integrity and recompute CID
    Verify {
        #[arg(short, long)]
        chip_file: String,
    },
    /// Build .chip file to binary
    Build {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Compute and print the canonical CID (BLAKE3) of a JSON file
    Cid {
        /// Path to a JSON file
        file: String,
    },
    /// Explain a WF receipt: print RB tree with PASS/DENY per node
    Explain {
        /// CID of the receipt, or path to a receipt JSON file
        target: String,
    },
    /// Search ChipStore by type, tag, or date range
    Search {
        /// Filter by chip type (e.g. "ubl/user")
        #[arg(short = 't', long)]
        chip_type: Option<String>,
        /// Filter by tag
        #[arg(long)]
        tag: Vec<String>,
        /// Filter: created after (RFC-3339)
        #[arg(long)]
        after: Option<String>,
        /// Filter: created before (RFC-3339)
        #[arg(long)]
        before: Option<String>,
        /// Max results
        #[arg(short, long, default_value = "20")]
        limit: u64,
    },
    /// Generate receipt fixtures for integration testing
    Fixture {
        /// Output directory for fixtures
        #[arg(short, long, default_value = "fixtures")]
        output_dir: String,
        /// Number of fixtures to generate
        #[arg(short, long, default_value = "5")]
        count: usize,
    },
    /// Generate a Rich URL for a receipt
    Url {
        /// Receipt CID
        receipt_cid: String,
        /// Host for the URL
        #[arg(long, default_value = "https://ubl.example.com")]
        host: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Verify { chip_file } => cmd_verify(&chip_file)?,
        Commands::Build { input, output } => cmd_build(&input, output)?,
        Commands::Cid { file } => cmd_cid(&file)?,
        Commands::Explain { target } => cmd_explain(&target)?,
        Commands::Search { chip_type, tag, after, before, limit } => {
            cmd_search(chip_type, tag, after, before, limit).await?;
        }
        Commands::Fixture { output_dir, count } => cmd_fixture(&output_dir, count)?,
        Commands::Url { receipt_cid, host } => cmd_url(&receipt_cid, &host)?,
    }

    Ok(())
}

// ── verify ──────────────────────────────────────────────────────

fn cmd_verify(chip_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    let chip_yaml = std::fs::read_to_string(chip_file)?;
    let chip: ChipFile = serde_yaml::from_str(&chip_yaml)?;
    let compiled = chip.compile()?;

    println!("Chip verified successfully");
    println!("  Type: {}", compiled.chip_type);
    println!("  ID:   {}", compiled.logical_id);
    println!("  CID:  {}", compiled.cid);
    println!("  Size: {} bytes", compiled.nrf1_bytes.len());
    Ok(())
}

// ── build ───────────────────────────────────────────────────────

fn cmd_build(input: &str, output: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let chip_yaml = std::fs::read_to_string(input)?;
    let chip: ChipFile = serde_yaml::from_str(&chip_yaml)?;
    let compiled = chip.compile()?;

    let output_path = output.unwrap_or_else(|| format!("{}.bin", compiled.cid));
    std::fs::write(&output_path, &compiled.nrf1_bytes)?;

    println!("Compiled: {} -> {}", input, output_path);
    println!("  CID: {}", compiled.cid);
    Ok(())
}

// ── cid ─────────────────────────────────────────────────────────

fn cmd_cid(file: &str) -> Result<(), Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(file)?;
    let json: Value = serde_json::from_str(&content)?;
    let nrf_bytes = to_nrf1_bytes(&json)?;
    let cid = compute_cid(&nrf_bytes)?;
    println!("{}", cid);
    Ok(())
}

// ── explain ─────────────────────────────────────────────────────

fn cmd_explain(target: &str) -> Result<(), Box<dyn std::error::Error>> {
    // If target is a file path, read it; otherwise treat as inline JSON or CID
    let receipt_json: Value = if std::path::Path::new(target).exists() {
        let content = std::fs::read_to_string(target)?;
        serde_json::from_str(&content)?
    } else if target.starts_with('{') {
        serde_json::from_str(target)?
    } else {
        // CID-only mode: print what we know
        println!("Receipt CID: {}", target);
        println!("  (Pass a receipt JSON file for full explanation)");
        return Ok(());
    };

    // Print envelope
    println!("=== Receipt Explanation ===");
    if let Some(t) = receipt_json.get("@type").and_then(|v| v.as_str()) {
        println!("  @type: {}", t);
    }
    if let Some(d) = receipt_json.get("decision").and_then(|v| v.as_str()) {
        let marker = if d == "allow" { "ALLOW" } else { "DENY" };
        println!("  Decision: {}", marker);
    }
    if let Some(r) = receipt_json.get("reason").and_then(|v| v.as_str()) {
        println!("  Reason: {}", r);
    }

    // Print policy trace as RB tree
    if let Some(trace) = receipt_json.get("policy_trace").and_then(|v| v.as_array()) {
        println!("\n--- Policy Trace ({} policies) ---", trace.len());
        for (i, entry) in trace.iter().enumerate() {
            let policy_id = entry.get("policy_id").and_then(|v| v.as_str()).unwrap_or("?");
            let decision = entry.get("decision").and_then(|v| v.as_str()).unwrap_or("?");
            let marker = match decision {
                "allow" => "PASS",
                "deny" => "DENY",
                "require" => "REQUIRE",
                _ => decision,
            };
            println!("  [{}] {} -> {}", i + 1, policy_id, marker);

            // Print individual RB results
            if let Some(rbs) = entry.get("rb_results").and_then(|v| v.as_array()) {
                for rb in rbs {
                    let rb_id = rb.get("rb_id").and_then(|v| v.as_str()).unwrap_or("?");
                    let rb_dec = rb.get("decision").and_then(|v| v.as_str()).unwrap_or("?");
                    let rb_marker = match rb_dec {
                        "allow" => "PASS",
                        "deny" => "DENY",
                        _ => rb_dec,
                    };
                    println!("      RB {} -> {}", rb_id, rb_marker);
                }
            }
        }
    }

    // Print VM state if present
    if let Some(vm) = receipt_json.get("vm_state") {
        println!("\n--- VM State ---");
        if let Some(fuel) = vm.get("fuel_used").and_then(|v| v.as_u64()) {
            println!("  Fuel used: {}", fuel);
        }
        if let Some(steps) = vm.get("steps").and_then(|v| v.as_u64()) {
            println!("  Steps: {}", steps);
        }
    }

    // Recompute CID for verification
    let nrf_bytes = to_nrf1_bytes(&receipt_json)?;
    let cid = compute_cid(&nrf_bytes)?;
    println!("\n  Computed CID: {}", cid);

    Ok(())
}

// ── search ──────────────────────────────────────────────────────

async fn cmd_search(
    chip_type: Option<String>,
    tags: Vec<String>,
    after: Option<String>,
    before: Option<String>,
    limit: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    use ubl_chipstore::{ChipStore, InMemoryBackend, ChipQuery};

    // In a real deployment, this would connect to the running ChipStore.
    // For now, demonstrate the query API with an in-memory store.
    let backend = Arc::new(InMemoryBackend::new());
    let store = ChipStore::new(backend);

    let query = ChipQuery {
        chip_type,
        tags,
        created_after: after,
        created_before: before,
        executor_did: None,
        limit: Some(limit as usize),
        offset: None,
    };

    println!("Searching ChipStore...");
    println!("  Query: {}", serde_json::to_string_pretty(&query)?);

    let results = store.query(&query).await?;
    println!("\n  Found: {} chips (total: {})", results.chips.len(), results.total_count);

    for chip in &results.chips {
        println!("  ---");
        println!("    CID:  {}", chip.cid);
        println!("    Type: {}", chip.chip_type);
        println!("    Receipt: {}", chip.receipt_cid);
    }

    if results.total_count == 0 {
        println!("  (No chips found. In production, connect to a running ChipStore.)");
    }

    Ok(())
}

// ── fixture ─────────────────────────────────────────────────────

fn cmd_fixture(output_dir: &str, count: usize) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(output_dir)?;

    let chip_types = ["ubl/user", "ubl/token", "ubl/policy", "ubl/app", "ubl/advisory"];

    for i in 0..count {
        let chip_type = chip_types[i % chip_types.len()];
        let id = format!("fixture-{:04}", i);
        let world = "a/test/t/fixtures";

        // Generate chip body
        let chip_body = json!({
            "@type": chip_type,
            "@id": id,
            "@ver": "1.0",
            "@world": world,
            "fixture_index": i,
            "created_at": chrono::Utc::now().to_rfc3339(),
        });

        // Compute CID
        let nrf_bytes = to_nrf1_bytes(&chip_body)?;
        let cid = compute_cid(&nrf_bytes)?;

        // Generate a mock WF receipt
        let receipt = json!({
            "@type": "ubl/wf",
            "chip_cid": cid,
            "chip_type": chip_type,
            "decision": if i % 7 == 0 { "deny" } else { "allow" },
            "reason": if i % 7 == 0 { "Policy denied: fixture test" } else { "All policies passed" },
            "policy_trace": [
                {
                    "policy_id": "genesis-type-validation",
                    "decision": if i % 7 == 0 { "deny" } else { "allow" },
                    "rb_results": [
                        {
                            "rb_id": "type-allowed",
                            "decision": if i % 7 == 0 { "deny" } else { "allow" },
                            "expression": format!("TypeEquals(\"{}\")", chip_type)
                        }
                    ]
                }
            ],
            "vm_state": {
                "fuel_used": 1000 + (i as u64 * 100),
                "steps": 5 + i as u64,
                "rc_cid": format!("b3:rc-{:04}", i),
            },
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        // Write chip
        let chip_path = format!("{}/chip-{:04}.json", output_dir, i);
        std::fs::write(&chip_path, serde_json::to_string_pretty(&chip_body)?)?;

        // Write receipt
        let receipt_path = format!("{}/receipt-{:04}.json", output_dir, i);
        std::fs::write(&receipt_path, serde_json::to_string_pretty(&receipt)?)?;

        println!("  [{}/{}] {} type={} cid={}", i + 1, count, id, chip_type, &cid[..20]);
    }

    println!("\nGenerated {} chip + receipt fixture pairs in {}/", count, output_dir);
    Ok(())
}

// ── url ─────────────────────────────────────────────────────────

fn cmd_url(receipt_cid: &str, host: &str) -> Result<(), Box<dyn std::error::Error>> {
    use ubl_runtime::rich_url::HostedUrl;

    // Parse world from CID or use defaults
    let url = HostedUrl::new(
        host,
        "app",
        "tenant",
        receipt_cid,
        receipt_cid,
        "did:key:placeholder",
        "sha256:placeholder",
        "sig:placeholder",
    );

    println!("Hosted URL:");
    println!("  {}", url.to_url_string());
    println!("\nSigning payload ({} bytes):", url.signing_payload().len());
    println!("  {}", String::from_utf8_lossy(&url.signing_payload()));
    println!("\nNote: Replace placeholder DID, RT, and SIG with real values for production.");

    Ok(())
}