
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::Value;
use std::fs::File;
use std::fs::{create_dir_all};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use base64::Engine;

use ubl_ai_nrf1::nrf::{decode_from_slice, NrfValue};

use vcx_pack::{build_pack, cid_bytes_to_str, cid_str_to_bytes, read_and_verify_pack, MimeTag};

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Build a VCX-PACK v1 from a manifest JSON and payload blobs.
    Build {
        /// Manifest as JSON (must be NRF-1.1 compatible; use UNC-1 objects for numbers)
        #[arg(long)]
        manifest: String,
        /// Payloads as MIME=PATH (repeatable). Example: --payload application/vcx-ic0t=tile.ic0t
        #[arg(long, required = true)]
        payload: Vec<String>,
        /// Output file (.vcx)
        #[arg(long)]
        out: String,
        /// Reject any JSON numbers anywhere in the manifest (forces UNC-1 usage)
        #[arg(long, default_value_t = true)]
        strict_unc1: bool,
    },
    /// Verify pack (Merkle root + index determinism). Use --full to read payload bytes.
    Verify {
        #[arg(long)]
        input: String,
        /// Recompute payload hashes from payload bytes (slower, but strongest)
        #[arg(long, default_value_t = false)]
        full: bool,
    },
    /// List index entries
    List {
        #[arg(long)]
        input: String,
    },
    /// Extract a payload by CID (b3:...)
    Extract {
        #[arg(long)]
        input: String,
        #[arg(long)]
        cid: String,
        #[arg(long)]
        out: String,
    },
    /// Dump manifest NRF bytes to a file
    DumpManifest {
        #[arg(long)]
        input: String,
        #[arg(long)]
        out: String,
    },

    /// Convert a VCX pack into UBL-ready chips (Option A: vcx/blob chips embed bytes_b64)
    Ingest {
        /// Input pack (.vcx)
        #[arg(long)]
        input: String,
        /// Output directory (chips will be written here)
        #[arg(long)]
        out_dir: String,
        /// World override (if omitted, uses @world from manifest)
        #[arg(long)]
        world: Option<String>,
        /// Also write manifest chip JSON (default true)
        #[arg(long, default_value_t = true)]
        include_manifest: bool,
        /// If true, re-read payload bytes and validate payload_hash (slower)
        #[arg(long, default_value_t = false)]
        full_verify: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Build {
            manifest,
            payload,
            out,
            strict_unc1,
        } => cmd_build(&manifest, &payload, &out, strict_unc1),
        Cmd::Verify { input, full } => cmd_verify(&input, full),
        Cmd::List { input } => cmd_list(&input),
        Cmd::Extract { input, cid, out } => cmd_extract(&input, &cid, &out),
        Cmd::DumpManifest { input, out } => cmd_dump_manifest(&input, &out),
        Cmd::Ingest { input, out_dir, world, include_manifest, full_verify } => {
            cmd_ingest(&input, &out_dir, world.as_deref(), include_manifest, full_verify)
        }
    }
}

fn nrf_to_json(v: &NrfValue) -> Result<Value> {
    Ok(match v {
        NrfValue::Null => Value::Null,
        NrfValue::Bool(b) => Value::Bool(*b),
        NrfValue::Int(i) => Value::Number((*i).into()),
        NrfValue::String(s) => Value::String(s.clone()),
        NrfValue::Bytes(b) => {
            // Bytes should not appear inside the VCX manifest; if they do, we still provide
            // a deterministic JSON representation.
            let enc = base64::engine::general_purpose::STANDARD.encode(b);
            Value::String(format!("b64:{}", enc))
        }
        NrfValue::Array(arr) => Value::Array(arr.iter().map(nrf_to_json).collect::<Result<Vec<_>>>()?),
        NrfValue::Map(map) => {
            let mut obj = serde_json::Map::new();
            for (k, vv) in map {
                obj.insert(k.clone(), nrf_to_json(vv)?);
            }
            Value::Object(obj)
        }
    })
}

fn reorder_envelope_top_level(v: &Value) -> Result<Value> {
    let obj = v.as_object().context("expected JSON object")?;
    let mut out = serde_json::Map::new();
    // Required anchors in canonical order
    for k in ["@type", "@id", "@ver", "@world"] {
        let vv = obj.get(k).with_context(|| format!("missing anchor {}", k))?;
        out.insert(k.to_string(), vv.clone());
    }
    // Remaining fields in existing iteration order
    for (k, vv) in obj {
        if k == "@type" || k == "@id" || k == "@ver" || k == "@world" {
            continue;
        }
        out.insert(k.clone(), vv.clone());
    }
    Ok(Value::Object(out))
}

fn read_json(path: &str) -> Result<Value> {
    let f = File::open(path).with_context(|| format!("open {}", path))?;
    let v: Value = serde_json::from_reader(BufReader::new(f)).context("parse json")?;
    Ok(v)
}

fn read_payloads(specs: &[String]) -> Result<Vec<(MimeTag, Vec<u8>)>> {
    let mut out = Vec::new();
    for s in specs {
        let (mime, path) = s
            .split_once('=')
            .with_context(|| format!("payload must be MIME=PATH, got {}", s))?;
        let tag = MimeTag::from_mime(mime);
        if tag == MimeTag::Unknown {
            bail!("UnknownMime({})", mime);
        }
        let mut f = File::open(path).with_context(|| format!("open {}", path))?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        out.push((tag, buf));
    }
    Ok(out)
}

fn cmd_build(manifest_path: &str, payload_specs: &[String], out_path: &str, strict_unc1: bool) -> Result<()> {
    let manifest = read_json(manifest_path)?;
    let payloads = read_payloads(payload_specs)?;
    let f = File::create(out_path).with_context(|| format!("create {}", out_path))?;
    let mut w = BufWriter::new(f);
    let header = build_pack(&mut w, &manifest, payloads, strict_unc1)?;
    w.flush()?;
    eprintln!("ok: wrote {}", out_path);
    eprintln!("manifest bytes at {} len {}", header.manifest_off, header.manifest_len);
    eprintln!("index bytes at {} len {}", header.index_off, header.index_len);
    eprintln!("payload region at {} len {}", header.payload_off, header.payload_len);
    eprintln!("trailer at {} len {}", header.trailer_off, header.trailer_len);
    Ok(())
}

fn cmd_verify(input: &str, full: bool) -> Result<()> {
    let f = File::open(input).with_context(|| format!("open {}", input))?;
    let pack = read_and_verify_pack(BufReader::new(f), full)?;
    eprintln!("ok: pack verified");
    eprintln!("entries: {}", pack.index_entries.len());
    eprintln!("merkle root: {}", cid_bytes_to_str(&pack.merkle.root));
    Ok(())
}

fn cmd_list(input: &str) -> Result<()> {
    let f = File::open(input).with_context(|| format!("open {}", input))?;
    let pack = read_and_verify_pack(BufReader::new(f), false)?;
    println!("merkle_root {}", cid_bytes_to_str(&pack.merkle.root));
    for e in &pack.index_entries {
        println!(
            "{}\tmime_tag={:?}\tlen={}\toff={}",
            cid_bytes_to_str(&e.cid),
            e.mime_tag,
            e.payload_len,
            e.payload_off
        );
    }
    Ok(())
}

fn cmd_extract(input: &str, cid: &str, out_path: &str) -> Result<()> {
    let target = cid_str_to_bytes(cid)?;
    let mut f = File::open(input).with_context(|| format!("open {}", input))?;
    let pack = read_and_verify_pack(BufReader::new(&mut f), false)?;
    let e = pack
        .index_entries
        .iter()
        .find(|x| x.cid == target)
        .context("cid not found in index")?;
    f.seek(SeekFrom::Start(e.payload_off))?;
    let mut buf = vec![0u8; e.payload_len as usize];
    f.read_exact(&mut buf)?;
    let mut out = File::create(out_path).with_context(|| format!("create {}", out_path))?;
    out.write_all(&buf)?;
    eprintln!("ok: wrote {}", out_path);
    Ok(())
}

fn cmd_dump_manifest(input: &str, out_path: &str) -> Result<()> {
    let f = File::open(input).with_context(|| format!("open {}", input))?;
    let pack = read_and_verify_pack(BufReader::new(f), false)?;
    let mut out = File::create(out_path).with_context(|| format!("create {}", out_path))?;
    out.write_all(&pack.manifest_bytes)?;
    eprintln!("ok: wrote {}", out_path);
    Ok(())
}

fn mime_tag_to_mime(tag: MimeTag) -> &'static str {
    match tag {
        MimeTag::Ic0Tile => "application/vcx-ic0t",
        MimeTag::Opus => "audio/opus",
        MimeTag::WebVtt => "text/vtt",
        MimeTag::Sidecar => "application/vcx-sidecar",
        MimeTag::Unknown => "application/octet-stream",
    }
}

fn unc_int(v: u64) -> Value {
    serde_json::json!({"@num":"int/1","v": v.to_string()})
}

fn cmd_ingest(input: &str, out_dir: &str, world_override: Option<&str>, include_manifest: bool, full_verify: bool) -> Result<()> {
    let mut f = File::open(input).with_context(|| format!("open {}", input))?;
    let pack = read_and_verify_pack(BufReader::new(&mut f), full_verify)?;

    // Decode manifest NRF bytes back to JSON (should be pure maps/strings/ints).
    let nrf = decode_from_slice(&pack.manifest_bytes).context("decode manifest NRF")?;
    let mut manifest_json = nrf_to_json(&nrf).context("manifest NRF->JSON")?;
    if !manifest_json.is_object() {
        bail!("manifest JSON must be object");
    }

    let world = match world_override {
        Some(w) => w.to_string(),
        None => manifest_json
            .get("@world")
            .and_then(|v| v.as_str())
            .context("manifest missing @world (and no --world override)")?
            .to_string(),
    };
    if let Some(_) = world_override {
        if let Some(obj) = manifest_json.as_object_mut() {
            obj.insert("@world".to_string(), Value::String(world.clone()));
        }
    }

    // Ensure envelope key order for UBL readers that care.
    manifest_json = reorder_envelope_top_level(&manifest_json)?;

    let out_root = Path::new(out_dir);
    create_dir_all(out_root).with_context(|| format!("mkdir {}", out_dir))?;
    let blobs_dir = out_root.join("blobs");
    create_dir_all(&blobs_dir).context("mkdir blobs")?;

    // Write manifest chip
    if include_manifest {
        let manifest_path = out_root.join("manifest.json");
        let mut mf = File::create(&manifest_path).with_context(|| format!("create {:?}", manifest_path))?;
        mf.write_all(serde_json::to_string_pretty(&manifest_json)?.as_bytes())?;
    }

    // For each payload entry, read bytes and emit a vcx/blob chip.
    // Note: UBL JSON pipeline cannot represent NRF Bytes directly; we embed bytes as base64.
    // The payload CID used for dedupe is still the UBL-style CID computed as BLAKE3(NRF(Bytes(payload_raw))).
    let merkle_root = cid_bytes_to_str(&pack.merkle.root);

    let mut ndjson = String::new();
    for e in &pack.index_entries {
        f.seek(SeekFrom::Start(e.payload_off))?;
        let mut buf = vec![0u8; e.payload_len as usize];
        f.read_exact(&mut buf)?;

        // Guardrails for UBL KNOCK max body size (1MB). base64 inflates ~4/3.
        // This is a hard constraint of the current UBL HTTP ingest shape.
        let approx_json_overhead = 1024usize;
        let approx_body = approx_json_overhead + ((buf.len() + 2) / 3) * 4;
        if approx_body > 1_000_000 {
            bail!("PayloadTooLargeForChip({} bytes raw, ~{} bytes json). Split payloads smaller.", buf.len(), approx_body);
        }

        let bytes_b64 = base64::engine::general_purpose::STANDARD.encode(&buf);
        let cid = cid_bytes_to_str(&e.cid);
        let chip = serde_json::json!({
            "@type": "vcx/blob",
            "@id": cid.clone(),
            "@ver": "1.0",
            "@world": world.clone(),
            "cid": cid,
            "mime": mime_tag_to_mime(e.mime_tag),
            "size": unc_int(e.payload_len as u64),
            "bytes_b64": bytes_b64,
            "pack_merkle_root": merkle_root.clone(),
            "hash_raw_b3": format!("b3:{}", hex::encode(e.payload_hash)),
        });

        let chip_path = blobs_dir.join(format!("{}.json", cid.replace(':', "_")));
        let mut cf = File::create(&chip_path).with_context(|| format!("create {:?}", chip_path))?;
        cf.write_all(serde_json::to_string_pretty(&chip)?.as_bytes())?;
        cf.write_all(b"\n")?;

        ndjson.push_str(&serde_json::to_string(&chip)?);
        ndjson.push('\n');
    }

    let ndjson_path = out_root.join("chips.ndjson");
    let mut nf = File::create(&ndjson_path).with_context(|| format!("create {:?}", ndjson_path))?;
    nf.write_all(ndjson.as_bytes())?;

    // Write a tiny helper script (optional convenience)
    let sh_path = out_root.join("upload.sh");
    let mut sh = File::create(&sh_path).with_context(|| format!("create {:?}", sh_path))?;
    sh.write_all(b"#!/usr/bin/env bash\nset -euo pipefail\n\n")?;
    sh.write_all(b"# Example uploader: adjust GATE_URL and AUTH as needed.\n")?;
    sh.write_all(b"GATE_URL=${GATE_URL:-http://localhost:8080}\nAUTH=${AUTH:-}\n\n")?;
    if include_manifest {
        sh.write_all(b"echo \"uploading manifest...\"\n")?;
        sh.write_all(b"curl -sS -X POST \"$GATE_URL/v1/chips\" -H 'Content-Type: application/json' $AUTH --data-binary @manifest.json >/dev/null\n")?;
    }
    sh.write_all(b"echo \"uploading blobs...\"\n")?;
    sh.write_all(b"while IFS= read -r line; do\n")?;
    sh.write_all(b"  curl -sS -X POST \"$GATE_URL/v1/chips\" -H 'Content-Type: application/json' $AUTH --data-binary \"$line\" >/dev/null\n")?;
    sh.write_all(b"done < chips.ndjson\n")?;
    sh.write_all(b"echo \"done\"\n")?;

    eprintln!("ok: wrote chips to {}", out_dir);
    eprintln!("- blobs: {:?}", blobs_dir);
    if include_manifest {
        eprintln!("- manifest: {}/manifest.json", out_dir);
    }
    eprintln!("- ndjson: {}/chips.ndjson", out_dir);
    Ok(())
}
