//! ublx - UBL Chip-as-Code CLI

use clap::{Parser, Subcommand};
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
    /// Print chip metadata and policies (stub)
    Explain {
        /// CID or file to explain
        target: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Verify { chip_file } => {
            println!("🔍 Verifying chip: {}", chip_file);

            let chip_yaml = std::fs::read_to_string(&chip_file)?;
            let chip: ChipFile = serde_yaml::from_str(&chip_yaml)?;

            let compiled = chip.compile()?;

            println!("✅ Chip verified successfully");
            println!("   Type: {}", compiled.chip_type);
            println!("   ID: {}", compiled.logical_id);
            println!("   CID: {}", compiled.cid);
            println!("   Size: {} bytes", compiled.nrf1_bytes.len());
        }

        Commands::Build { input, output } => {
            println!("🔨 Building chip: {}", input);

            let chip_yaml = std::fs::read_to_string(&input)?;
            let chip: ChipFile = serde_yaml::from_str(&chip_yaml)?;

            let compiled = chip.compile()?;

            let output_path = output.unwrap_or_else(|| format!("{}.bin", compiled.cid));
            std::fs::write(&output_path, &compiled.nrf1_bytes)?;

            println!("✅ Compiled successfully");
            println!("   Input: {}", input);
            println!("   Output: {}", output_path);
            println!("   CID: {}", compiled.cid);
        }

        Commands::Cid { file } => {
            let content = std::fs::read_to_string(&file)?;
            let json: serde_json::Value = serde_json::from_str(&content)?;
            let nrf_bytes = to_nrf1_bytes(&json)?;
            let cid = compute_cid(&nrf_bytes)?;
            println!("{}", cid);
        }

        Commands::Explain { target } => {
            println!("explain: {} (not yet implemented)", target);
            println!("This will print chip metadata, policy trace, and RB tree.");
        }
    }

    Ok(())
}

// CompileError already implements std::error::Error via thiserror,
// so we can use anyhow for easier error handling