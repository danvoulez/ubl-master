# VCX-PACK v1 (Fully UBL-compatible)

This repository contains a reference implementation of **VCX-PACK v1**, designed to be fully compatible with the **UBL** ecosystem:

- Canonical encoding: **NRF-1.1** (binary, `nrf1` magic)
- Numeric canon (in manifest JSON): **UNC-1** objects (no JSON numbers)
- CID rule for payload blobs: **CID = BLAKE3( NRF-1.1( Bytes(payload_raw) ) )**
- CID rule for structured objects (manifest): **CID = BLAKE3( NRF-1.1(value) )**

## File Layout

```
[Header 96B] [Manifest NRF bytes] [Index (binary)] [PayloadRegion] [MerkleTrailer]
```

### Header (96 bytes, LE)

- magic: `VCX1`
- version: u16 = 1
- flags: u16 (bit1 = has_merkle)
- header_len: u32 = 96
- (off,len) pairs as u64 for: manifest, index, payload_region, trailer

### ManifestBytes

- Raw NRF-1.1 bytes of a manifest JSON object converted using UBL's `json_to_nrf`.
- In `--strict-unc1` mode, the builder rejects *any* JSON numbers anywhere (forces UNC-1 usage).

### Index (binary, deterministic)

- magic `VIDX`
- version u16 = 1
- entry_len u16 (96)
- entry_count u32
- entries sorted lexicographically by `cid[32]`

Each entry stores:
- `cid_algo=1`, `cid_len=32`, `cid[32]` (raw bytes)
- mime_tag u16
- flags u16
- payload_off u64 (absolute file offset)
- payload_len u64
- payload_hash[32] = BLAKE3(payload_raw)
- padding to 96 bytes

### PayloadRegion

- Concatenation of raw payload blobs.
- Each blob is padded to 8-byte alignment.

### MerkleTrailer

- magic `VMRK`
- version u16 = 1
- leaf_count u32
- root[32]
- levels[] of full merkle tree (level 0 leaves)

Leaves commit to:
- leaf 0: manifest hash
- leaf 1: index hash
- leaf 2..: payload_hash + cid + len

## CLI

Build:

```bash
cargo run -p vcx_pack_cli -- build \
  --manifest examples/manifest.vcx.json \
  --payload application/vcx-ic0t=examples/payloads/tile0.ic0t \
  --out out.vcx \
  --strict-unc1
```

Verify:

```bash
cargo run -p vcx_pack_cli -- verify --input out.vcx
cargo run -p vcx_pack_cli -- verify --input out.vcx --full
```

List / Extract / Dump manifest:

```bash
cargo run -p vcx_pack_cli -- list --input out.vcx
cargo run -p vcx_pack_cli -- extract --input out.vcx --cid b3:... --out blob.bin
cargo run -p vcx_pack_cli -- dump-manifest --input out.vcx --out manifest.nrf
```

## UBL Ingest (Option A: vcx/blob chips embed bytes)

Convert a pack into **UBL-ready chips**:

```bash
cargo run -p vcx_pack_cli -- ingest \
  --input out.vcx \
  --out-dir out_chips
```

Outputs:

- `out_chips/manifest.json` (if present in the pack)
- `out_chips/blobs/*.json` (one `vcx/blob` chip per payload)
- `out_chips/chips.ndjson` (newline-delimited JSON for bulk upload)
- `out_chips/upload.sh` (helper script; set `GATE_URL` and `AUTH` env vars)

Notes:

- Each `vcx/blob` chip uses `@id = cid = b3:<...>` where the CID matches the pack index CID rule:
  `BLAKE3(NRF(Bytes(payload_raw)))`.
- Because the current UBL HTTP ingest expects JSON, blob bytes are embedded as `bytes_b64`.
  The tool rejects payloads that would exceed the 1MB KNOCK limit.
