//! ublx - UBL Chip-as-Code CLI

use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::sync::Arc;
use ubl_ai_nrf1::{compute_cid, to_nrf1_bytes, ChipFile};

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
    /// Disassemble RB-VM bytecode to human-readable listing
    Disasm {
        /// Path to bytecode file (binary) or hex string
        input: String,
        /// Treat input as hex string instead of file path
        #[arg(long)]
        hex: bool,
    },
    /// Silicon chip compiler and disassembler
    Silicon {
        #[command(subcommand)]
        command: SiliconCommands,
    },
}

#[derive(Subcommand)]
enum SiliconCommands {
    /// Compile a silicon chip JSON to rb_vm TLV bytecode.
    ///
    /// Reads a self-contained silicon chip bundle (a JSON file with embedded
    /// bit/circuit/chip definitions) and outputs:
    ///   - the chip CID (content address of the chip body)
    ///   - the bytecode CID (content address of the compiled TLV bytes)
    ///   - the hex-encoded TLV bytecode
    ///
    /// Bundle format (single JSON file):
    ///   {
    ///     "chip":    { <ubl/silicon.chip body> },
    ///     "circuits": [ { "cid": "b3:...", "body": { <ubl/silicon.circuit body> } }, ... ],
    ///     "bits":    [ { "cid": "b3:...", "body": { <ubl/silicon.bit body> } }, ... ]
    ///   }
    Compile {
        /// Path to silicon bundle JSON file.
        /// Mutually exclusive with --from-store.
        #[arg(conflicts_with = "from_store")]
        bundle: Option<String>,
        /// Compile a chip already in the ChipStore by CID.
        /// Opens the Sled store at --store-path (default: ./data/chips).
        #[arg(long, value_name = "CHIP_CID")]
        from_store: Option<String>,
        /// Path to the Sled ChipStore directory (used with --from-store).
        #[arg(long, default_value = "./data/chips")]
        store_path: String,
        /// Print only the bytecode hex (machine-readable, no labels)
        #[arg(long)]
        hex_only: bool,
    },
    /// Disassemble silicon-compiled rb_vm TLV bytecode to human-readable listing.
    ///
    /// Accepts either a hex string or a binary bytecode file.
    Disasm {
        /// Hex string of bytecode, or path to a binary bytecode file
        input: String,
        /// Treat input as a binary file path (default: treat as hex string)
        #[arg(long)]
        file: bool,
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
        Commands::Search {
            chip_type,
            tag,
            after,
            before,
            limit,
        } => {
            cmd_search(chip_type, tag, after, before, limit).await?;
        }
        Commands::Fixture { output_dir, count } => cmd_fixture(&output_dir, count)?,
        Commands::Url { receipt_cid, host } => cmd_url(&receipt_cid, &host)?,
        Commands::Disasm { input, hex } => cmd_disasm(&input, hex)?,
        Commands::Silicon { command } => match command {
            SiliconCommands::Compile {
                bundle,
                from_store,
                store_path,
                hex_only,
            } => {
                cmd_silicon_compile(
                    bundle.as_deref(),
                    from_store.as_deref(),
                    &store_path,
                    hex_only,
                )
                .await?
            }
            SiliconCommands::Disasm { input, file } => cmd_silicon_disasm(&input, file)?,
        },
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
            let policy_id = entry
                .get("policy_id")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let decision = entry
                .get("decision")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
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
    use ubl_chipstore::{ChipQuery, ChipStore, InMemoryBackend};

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
    println!(
        "\n  Found: {} chips (total: {})",
        results.chips.len(),
        results.total_count
    );

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

    let chip_types = [
        "ubl/user",
        "ubl/token",
        "ubl/policy",
        "ubl/app",
        "ubl/advisory",
    ];

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

        println!(
            "  [{}/{}] {} type={} cid={}",
            i + 1,
            count,
            id,
            chip_type,
            &cid[..20]
        );
    }

    println!(
        "\nGenerated {} chip + receipt fixture pairs in {}/",
        count, output_dir
    );
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

// ── disasm ──────────────────────────────────────────────────────

fn cmd_disasm(input: &str, is_hex: bool) -> Result<(), Box<dyn std::error::Error>> {
    let bytecode = if is_hex {
        let clean = input.replace([' ', '\n', '\t'], "");
        hex::decode(&clean)?
    } else {
        std::fs::read(input)?
    };

    println!("=== RB-VM Disassembly ({} bytes) ===\n", bytecode.len());
    match rb_vm::disassemble(&bytecode) {
        Ok(listing) => print!("{}", listing),
        Err(e) => eprintln!("Disassembly error: {}", e),
    }
    Ok(())
}

// ── silicon compile ─────────────────────────────────────────────
//
// Bundle format (self-contained JSON):
// {
//   "chip":     { <ubl/silicon.chip body> },
//   "circuits": [ { "cid": "b3:...", "body": { <ubl/silicon.circuit body> } }, ... ],
//   "bits":     [ { "cid": "b3:...", "body": { <ubl/silicon.bit body> } }, ... ]
// }
//
// The circuit body's "bits" array and the chip body's "circuits" array use the
// bundle CIDs ("b3:...") as symbolic references.  The command:
//   1. Stores all bits → records bundle_cid → stored_cid mapping.
//   2. Rewrites each circuit's "bits" array with stored CIDs, stores circuits.
//   3. Rewrites the chip's "circuits" array with stored CIDs, stores chip.
//   4. Resolves the chip graph and compiles to rb_vm TLV bytecode.
//   5. Prints chip CID, bytecode CID, hex bytecode, and disassembly.

async fn cmd_silicon_compile(
    bundle_path: Option<&str>,
    from_store: Option<&str>,
    store_path: &str,
    hex_only: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::HashMap;
    use std::sync::Arc;
    use ubl_chipstore::{ChipStore, ExecutionMetadata, InMemoryBackend, SledBackend};
    use ubl_runtime::silicon_chip::{
        compile_chip_to_rb_vm, parse_silicon, resolve_chip_graph, SiliconRequest, TYPE_SILICON_BIT,
        TYPE_SILICON_CHIP, TYPE_SILICON_CIRCUIT,
    };
    use ubl_types::Did as TypedDid;

    // ── from-store path: open live Sled ChipStore, compile chip by CID ──
    if let Some(chip_cid) = from_store {
        let backend = Arc::new(SledBackend::new(store_path)?);
        let store = ChipStore::new(backend);

        let chip_data = store
            .get_chip(chip_cid)
            .await?
            .ok_or_else(|| format!("chip '{}' not found in store at '{}'", chip_cid, store_path))?;

        if chip_data.chip_type != TYPE_SILICON_CHIP {
            return Err(format!(
                "chip '{}' has type '{}', expected '{}'",
                chip_cid, chip_data.chip_type, TYPE_SILICON_CHIP
            )
            .into());
        }

        let chip = match parse_silicon(TYPE_SILICON_CHIP, &chip_data.chip_data)? {
            SiliconRequest::Chip(c) => c,
            _ => return Err("chip body did not parse as ubl/silicon.chip".into()),
        };

        let circuits = resolve_chip_graph(&chip, &store).await?;
        let bytecode = compile_chip_to_rb_vm(&circuits)?;

        let bc_hash = blake3::hash(&bytecode);
        let bc_cid = format!("b3:{}", hex::encode(bc_hash.as_bytes()));
        let bc_hex = hex::encode(&bytecode);

        if hex_only {
            println!("{}", bc_hex);
        } else {
            println!("=== Silicon Compile (from store) ===");
            println!();
            println!("Chip CID:            {}", chip_cid);
            println!("Store path:          {}", store_path);
            println!("Bytecode CID:        {}", bc_cid);
            println!(
                "Bytecode size:       {} bytes ({} instructions)",
                bytecode.len(),
                count_tlv_instrs(&bytecode)
            );
            println!();
            println!("=== Bytecode (hex) ===");
            println!("{}", bc_hex);
            println!();
            println!("=== Disassembly ===");
            match rb_vm::disassemble(&bytecode) {
                Ok(listing) => print!("{}", listing),
                Err(e) => eprintln!("Disassembly error: {}", e),
            }
        }
        return Ok(());
    }

    // ── bundle path: self-contained JSON ─────────────────────────
    let bundle_path = bundle_path.ok_or("provide a bundle file path or --from-store <chip_cid>")?;

    // ── parse bundle ────────────────────────────────────────────
    let bundle_str = std::fs::read_to_string(bundle_path)?;
    let bundle: Value = serde_json::from_str(&bundle_str)?;

    let chip_body = bundle
        .get("chip")
        .ok_or("bundle missing 'chip' field")?
        .clone();
    let circuits_arr = bundle
        .get("circuits")
        .and_then(|v| v.as_array())
        .ok_or("bundle missing 'circuits' array")?
        .clone();
    let bits_arr = bundle
        .get("bits")
        .and_then(|v| v.as_array())
        .ok_or("bundle missing 'bits' array")?
        .clone();

    // ── in-memory store + shared metadata ───────────────────────
    let backend = Arc::new(InMemoryBackend::new());
    let store = ChipStore::new(backend);
    let meta = ExecutionMetadata {
        runtime_version: "ublx/0.1.0".to_string(),
        execution_time_ms: 0,
        fuel_consumed: 0,
        policies_applied: vec![],
        executor_did: TypedDid::new_unchecked("did:key:ublx"),
        reproducible: true,
    };

    // ── 1. Store bits: bundle_cid → stored_cid ──────────────────
    let mut cid_map: HashMap<String, String> = HashMap::new();
    for entry in &bits_arr {
        let bundle_cid = entry
            .get("cid")
            .and_then(|v| v.as_str())
            .ok_or("bits[] entry missing 'cid'")?
            .to_string();
        let body = entry
            .get("body")
            .ok_or("bits[] entry missing 'body'")?
            .clone();
        let mut chip_data = body;
        if let Some(obj) = chip_data.as_object_mut() {
            obj.insert(
                "@type".to_string(),
                Value::String(TYPE_SILICON_BIT.to_string()),
            );
            obj.entry("@world".to_string())
                .or_insert(Value::String("a/ublx/t/cli".to_string()));
        }
        let receipt_cid = format!(
            "b3:receipt-bit-{}",
            &bundle_cid[3..].chars().take(8).collect::<String>()
        );
        let stored_cid = store
            .store_executed_chip(chip_data, receipt_cid, meta.clone())
            .await?;
        cid_map.insert(bundle_cid, stored_cid);
    }

    // ── 2. Store circuits (rewrite bits[] with stored CIDs) ──────
    for entry in &circuits_arr {
        let bundle_cid = entry
            .get("cid")
            .and_then(|v| v.as_str())
            .ok_or("circuits[] entry missing 'cid'")?
            .to_string();
        let body = entry
            .get("body")
            .ok_or("circuits[] entry missing 'body'")?
            .clone();
        let mut chip_data = body;
        if let Some(obj) = chip_data.as_object_mut() {
            obj.insert(
                "@type".to_string(),
                Value::String(TYPE_SILICON_CIRCUIT.to_string()),
            );
            obj.entry("@world".to_string())
                .or_insert(Value::String("a/ublx/t/cli".to_string()));
            // Rewrite bits[] using cid_map (bundle CID → stored CID)
            if let Some(bits_val) = obj.get("bits").and_then(|v| v.as_array()).cloned() {
                let rewritten: Vec<Value> = bits_val
                    .iter()
                    .map(|b| {
                        let s = b.as_str().unwrap_or("");
                        Value::String(cid_map.get(s).cloned().unwrap_or_else(|| s.to_string()))
                    })
                    .collect();
                obj.insert("bits".to_string(), Value::Array(rewritten));
            }
        }
        let receipt_cid = format!(
            "b3:receipt-ckt-{}",
            &bundle_cid[3..].chars().take(8).collect::<String>()
        );
        let stored_cid = store
            .store_executed_chip(chip_data, receipt_cid, meta.clone())
            .await?;
        cid_map.insert(bundle_cid, stored_cid);
    }

    // ── 3. Store chip (rewrite circuits[] with stored CIDs) ──────
    let mut chip_data = chip_body.clone();
    if let Some(obj) = chip_data.as_object_mut() {
        obj.insert(
            "@type".to_string(),
            Value::String(TYPE_SILICON_CHIP.to_string()),
        );
        obj.entry("@world".to_string())
            .or_insert(Value::String("a/ublx/t/cli".to_string()));
        if let Some(circs_val) = obj.get("circuits").and_then(|v| v.as_array()).cloned() {
            let rewritten: Vec<Value> = circs_val
                .iter()
                .map(|c| {
                    let s = c.as_str().unwrap_or("");
                    Value::String(cid_map.get(s).cloned().unwrap_or_else(|| s.to_string()))
                })
                .collect();
            obj.insert("circuits".to_string(), Value::Array(rewritten));
        }
    }
    let chip_store_cid = store
        .store_executed_chip(
            chip_data.clone(),
            "b3:receipt-chip".to_string(),
            meta.clone(),
        )
        .await?;

    // ── chip body CID = BLAKE3 content address of the raw body ───
    let chip_nrf = ubl_ai_nrf1::to_nrf1_bytes(&chip_body)?;
    let chip_content_cid = ubl_ai_nrf1::compute_cid(&chip_nrf)?;

    // ── 4. Resolve + compile ─────────────────────────────────────
    let chip = match parse_silicon(TYPE_SILICON_CHIP, &chip_data)? {
        SiliconRequest::Chip(c) => c,
        _ => return Err("chip body did not parse as ubl/silicon.chip".into()),
    };
    let circuits = resolve_chip_graph(&chip, &store).await?;
    let bytecode = compile_chip_to_rb_vm(&circuits)?;

    // ── 5. Output ────────────────────────────────────────────────
    let bc_hash = blake3::hash(&bytecode);
    let bc_cid = format!("b3:{}", hex::encode(bc_hash.as_bytes()));
    let bc_hex = hex::encode(&bytecode);

    if hex_only {
        println!("{}", bc_hex);
    } else {
        println!("=== Silicon Compile ===");
        println!();
        println!("Chip CID (content):  {}", chip_content_cid);
        println!("Store CID:           {}", chip_store_cid);
        println!("Bytecode CID:        {}", bc_cid);
        println!(
            "Bytecode size:       {} bytes ({} instructions)",
            bytecode.len(),
            count_tlv_instrs(&bytecode)
        );
        println!();
        println!("=== Bytecode (hex) ===");
        println!("{}", bc_hex);
        println!();
        println!("=== Disassembly ===");
        match rb_vm::disassemble(&bytecode) {
            Ok(listing) => print!("{}", listing),
            Err(e) => eprintln!("Disassembly error: {}", e),
        }
    }

    Ok(())
}

/// Count TLV instructions in a bytecode buffer (each is 3-byte header + payload).
fn count_tlv_instrs(bytecode: &[u8]) -> usize {
    let mut count = 0;
    let mut i = 0;
    while i + 2 < bytecode.len() {
        let len = u16::from_be_bytes([bytecode[i + 1], bytecode[i + 2]]) as usize;
        i += 3 + len;
        count += 1;
    }
    count
}

// ── silicon disasm ───────────────────────────────────────────────

fn cmd_silicon_disasm(input: &str, is_file: bool) -> Result<(), Box<dyn std::error::Error>> {
    let bytecode = if is_file {
        std::fs::read(input)?
    } else {
        let clean = input.replace([' ', '\n', '\t'], "");
        hex::decode(&clean)?
    };

    println!(
        "=== Silicon Chip Disassembly ({} bytes, {} instructions) ===\n",
        bytecode.len(),
        count_tlv_instrs(&bytecode),
    );
    match rb_vm::disassemble(&bytecode) {
        Ok(listing) => print!("{}", listing),
        Err(e) => eprintln!("Disassembly error: {}", e),
    }
    Ok(())
}
