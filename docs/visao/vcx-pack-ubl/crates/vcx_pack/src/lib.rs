use anyhow::{bail, Context, Result};
use blake3::Hash;
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};

use ubl_ai_nrf1::nrf::{encode_to_vec, json_to_nrf, NrfValue};

pub mod realtime_predictability;
pub mod streaming_protocol;

pub const PACK_MAGIC: &[u8; 4] = b"VCX1";
pub const MERKLE_MAGIC: &[u8; 4] = b"VMRK";
pub const INDEX_MAGIC: &[u8; 4] = b"VIDX";

pub const PACK_VERSION: u16 = 1;
pub const INDEX_VERSION: u16 = 1;
pub const MERKLE_VERSION: u16 = 1;

/// Header is always 64 bytes, little-endian.
#[derive(Debug, Clone)]
pub struct PackHeader {
    pub version: u16,
    pub flags: u16,

    pub manifest_off: u64,
    pub manifest_len: u64,

    pub index_off: u64,
    pub index_len: u64,

    pub payload_off: u64,
    pub payload_len: u64,

    pub trailer_off: u64,
    pub trailer_len: u64,
}

impl PackHeader {
    pub const LEN: u64 = 96;

    pub fn write_to<W: Write>(&self, mut w: W) -> Result<()> {
        w.write_all(PACK_MAGIC)?;
        w.write_all(&self.version.to_le_bytes())?;
        w.write_all(&self.flags.to_le_bytes())?;
        // header_len u32 (always LEN)
        w.write_all(&(Self::LEN as u32).to_le_bytes())?;

        w.write_all(&self.manifest_off.to_le_bytes())?;
        w.write_all(&self.manifest_len.to_le_bytes())?;
        w.write_all(&self.index_off.to_le_bytes())?;
        w.write_all(&self.index_len.to_le_bytes())?;
        w.write_all(&self.payload_off.to_le_bytes())?;
        w.write_all(&self.payload_len.to_le_bytes())?;
        w.write_all(&self.trailer_off.to_le_bytes())?;
        w.write_all(&self.trailer_len.to_le_bytes())?;

        // reserved / padding to LEN bytes
        let written = 4 + 2 + 2 + 4 + 8 * 8; // 76 bytes
        let pad = (Self::LEN as usize).saturating_sub(written);
        if pad > 0 {
            w.write_all(&vec![0u8; pad])?;
        }
        Ok(())
    }

    pub fn read_from<R: Read>(mut r: R) -> Result<Self> {
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)?;
        if &magic != PACK_MAGIC {
            bail!("BadMagic");
        }
        let mut u16b = [0u8; 2];
        let mut u32b = [0u8; 4];
        let mut u64b = [0u8; 8];

        r.read_exact(&mut u16b)?;
        let version = u16::from_le_bytes(u16b);
        if version != PACK_VERSION {
            bail!("UnsupportedPackVersion({})", version);
        }
        r.read_exact(&mut u16b)?;
        let flags = u16::from_le_bytes(u16b);

        r.read_exact(&mut u32b)?;
        let header_len = u32::from_le_bytes(u32b) as u64;
        if header_len != Self::LEN {
            bail!("BadHeaderLen({})", header_len);
        }

        let mut read_u64 = |r: &mut R| -> Result<u64> {
            let mut b = [0u8; 8];
            r.read_exact(&mut b)?;
            Ok(u64::from_le_bytes(b))
        };

        let manifest_off = read_u64(&mut r)?;
        let manifest_len = read_u64(&mut r)?;
        let index_off = read_u64(&mut r)?;
        let index_len = read_u64(&mut r)?;
        let payload_off = read_u64(&mut r)?;
        let payload_len = read_u64(&mut r)?;
        let trailer_off = read_u64(&mut r)?;
        let trailer_len = read_u64(&mut r)?;

        // skip remaining header padding
        let consumed = 4 + 2 + 2 + 4 + 8 * 8;
        let pad = (Self::LEN as usize).saturating_sub(consumed);
        if pad > 0 {
            let mut skip = vec![0u8; pad];
            r.read_exact(&mut skip)?;
        }

        Ok(Self {
            version,
            flags,
            manifest_off,
            manifest_len,
            index_off,
            index_len,
            payload_off,
            payload_len,
            trailer_off,
            trailer_len,
        })
    }
}

/// MIME tags are compact integers in the index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MimeTag {
    Unknown = 0,
    Ic0Tile = 1,
    Opus = 2,
    WebVtt = 3,
    Sidecar = 4,
}

impl MimeTag {
    pub fn from_mime(m: &str) -> Self {
        match m {
            "application/vcx-ic0t" => MimeTag::Ic0Tile,
            "audio/opus" => MimeTag::Opus,
            "text/vtt" | "text/webvtt" => MimeTag::WebVtt,
            "application/vcx-sidecar" => MimeTag::Sidecar,
            _ => MimeTag::Unknown,
        }
    }
}

/// Index header + entries are binary and deterministic.
#[derive(Debug, Clone)]
pub struct IndexEntry {
    pub cid: [u8; 32], // BLAKE3 hash bytes
    pub mime_tag: MimeTag,
    pub flags: u16,
    pub payload_off: u64, // absolute file offset
    pub payload_len: u64,
    pub payload_hash: [u8; 32], // BLAKE3(payload_raw)
}

impl IndexEntry {
    pub const LEN: usize = 96;

    pub fn write_to<W: Write>(&self, mut w: W) -> Result<()> {
        // cid algo + len
        w.write_all(&[1u8])?; // cid_algo: 1 = BLAKE3(NRF(Bytes(payload)))
        w.write_all(&[32u8])?;
        w.write_all(&self.cid)?;
        w.write_all(&(self.mime_tag as u16).to_le_bytes())?;
        w.write_all(&self.flags.to_le_bytes())?;
        w.write_all(&self.payload_off.to_le_bytes())?;
        w.write_all(&self.payload_len.to_le_bytes())?;
        w.write_all(&self.payload_hash)?;
        // reserved to 96 bytes
        let written = 1 + 1 + 32 + 2 + 2 + 8 + 8 + 32;
        let pad = Self::LEN - written;
        w.write_all(&vec![0u8; pad])?;
        Ok(())
    }

    pub fn read_from<R: Read>(mut r: R) -> Result<Self> {
        let mut b1 = [0u8; 1];
        r.read_exact(&mut b1)?;
        let cid_algo = b1[0];
        if cid_algo != 1 {
            bail!("UnsupportedCidAlgo({})", cid_algo);
        }
        r.read_exact(&mut b1)?;
        let cid_len = b1[0];
        if cid_len != 32 {
            bail!("BadCidLen({})", cid_len);
        }
        let mut cid = [0u8; 32];
        r.read_exact(&mut cid)?;
        let mut u16b = [0u8; 2];
        r.read_exact(&mut u16b)?;
        let mime_tag_u = u16::from_le_bytes(u16b);
        let mime_tag = match mime_tag_u {
            1 => MimeTag::Ic0Tile,
            2 => MimeTag::Opus,
            3 => MimeTag::WebVtt,
            4 => MimeTag::Sidecar,
            _ => MimeTag::Unknown,
        };
        r.read_exact(&mut u16b)?;
        let flags = u16::from_le_bytes(u16b);
        let mut u64b = [0u8; 8];
        r.read_exact(&mut u64b)?;
        let payload_off = u64::from_le_bytes(u64b);
        r.read_exact(&mut u64b)?;
        let payload_len = u64::from_le_bytes(u64b);
        let mut payload_hash = [0u8; 32];
        r.read_exact(&mut payload_hash)?;
        // skip reserved
        let written = 1 + 1 + 32 + 2 + 2 + 8 + 8 + 32;
        let pad = Self::LEN - written;
        let mut skip = vec![0u8; pad];
        r.read_exact(&mut skip)?;
        Ok(Self {
            cid,
            mime_tag,
            flags,
            payload_off,
            payload_len,
            payload_hash,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Pack {
    pub header: PackHeader,
    pub manifest_bytes: Vec<u8>,
    pub index_entries: Vec<IndexEntry>,
    pub merkle: MerkleTrailer,
}

/// Merkle trailer stores full tree levels so proofs can be derived.
#[derive(Debug, Clone)]
pub struct MerkleTrailer {
    pub root: [u8; 32],
    pub levels: Vec<Vec<[u8; 32]>>, // level 0 = leaves
}

impl MerkleTrailer {
    pub fn write_to<W: Write>(&self, mut w: W) -> Result<()> {
        w.write_all(MERKLE_MAGIC)?;
        w.write_all(&MERKLE_VERSION.to_le_bytes())?;
        w.write_all(&0u16.to_le_bytes())?; // flags
        let leaf_count: u32 = self.levels.first().map(|v| v.len()).unwrap_or(0) as u32;
        w.write_all(&leaf_count.to_le_bytes())?;
        w.write_all(&[1u8])?; // hash_algo = 1 (BLAKE3)
        w.write_all(&[0u8; 7])?; // reserved/alignment
        w.write_all(&self.root)?;

        // serialize levels
        let level_count = self.levels.len() as u32;
        w.write_all(&level_count.to_le_bytes())?;
        for lvl in &self.levels {
            w.write_all(&(lvl.len() as u32).to_le_bytes())?;
            for h in lvl {
                w.write_all(h)?;
            }
        }
        Ok(())
    }

    pub fn read_from<R: Read>(mut r: R) -> Result<Self> {
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)?;
        if &magic != MERKLE_MAGIC {
            bail!("BadMerkleMagic");
        }
        let mut u16b = [0u8; 2];
        r.read_exact(&mut u16b)?;
        let version = u16::from_le_bytes(u16b);
        if version != MERKLE_VERSION {
            bail!("UnsupportedMerkleVersion({})", version);
        }
        r.read_exact(&mut u16b)?; // flags ignore
        let mut u32b = [0u8; 4];
        r.read_exact(&mut u32b)?;
        let _leaf_count = u32::from_le_bytes(u32b);
        let mut b1 = [0u8; 1];
        r.read_exact(&mut b1)?;
        let algo = b1[0];
        if algo != 1 {
            bail!("UnsupportedMerkleAlgo({})", algo);
        }
        let mut reserved = [0u8; 7];
        r.read_exact(&mut reserved)?;
        let mut root = [0u8; 32];
        r.read_exact(&mut root)?;

        r.read_exact(&mut u32b)?;
        let level_count = u32::from_le_bytes(u32b) as usize;
        let mut levels = Vec::with_capacity(level_count);
        for _ in 0..level_count {
            r.read_exact(&mut u32b)?;
            let n = u32::from_le_bytes(u32b) as usize;
            let mut lvl = Vec::with_capacity(n);
            for _ in 0..n {
                let mut h = [0u8; 32];
                r.read_exact(&mut h)?;
                lvl.push(h);
            }
            levels.push(lvl);
        }
        Ok(Self { root, levels })
    }
}

fn align8(x: u64) -> u64 {
    (x + 7) & !7
}

/// Compute CID bytes for a structured JSON value: cid = BLAKE3(NRF-1.1(value)).
pub fn cid_for_json_value(value: &Value) -> Result<([u8; 32], String, Vec<u8>)> {
    let nrf = json_to_nrf(value)?;
    let nrf_bytes = encode_to_vec(&nrf)?;
    let h = blake3::hash(&nrf_bytes);
    Ok((
        h.as_bytes().clone(),
        format!("b3:{}", hex::encode(h.as_bytes())),
        nrf_bytes,
    ))
}

/// Compute payload CID bytes: cid = BLAKE3(NRF-1.1(Bytes(payload_raw))).
pub fn cid_for_payload_bytes(payload_raw: &[u8]) -> Result<([u8; 32], String)> {
    let nrf = NrfValue::Bytes(payload_raw.to_vec());
    let nrf_bytes = encode_to_vec(&nrf)?;
    let h = blake3::hash(&nrf_bytes);
    Ok((
        h.as_bytes().clone(),
        format!("b3:{}", hex::encode(h.as_bytes())),
    ))
}

/// Strict UNC-1 mode: reject any JSON numbers anywhere in the manifest.
/// This forces using {"@num": ...} consistently.

pub fn validate_no_json_numbers(value: &Value) -> Result<()> {
    fn walk(v: &Value, path: &mut Vec<String>, allow_dec_scale_here: bool) -> Result<()> {
        match v {
            Value::Number(n) => {
                // Only allowed in a single, very specific place: UNC-1 dec/1 scale field `s`.
                if allow_dec_scale_here && n.is_i64() {
                    return Ok(());
                }
                bail!("ManifestHasJsonNumber at {}", path.join("."));
            }
            Value::Array(a) => {
                for (i, x) in a.iter().enumerate() {
                    path.push(format!("[{}]", i));
                    walk(x, path, allow_dec_scale_here)?;
                    path.pop();
                }
            }
            Value::Object(o) => {
                // Detect UNC-1 objects: {"@num": "<tag>", ...}
                let is_dec = match o.get("@num") {
                    Some(Value::String(tag)) if tag == "dec/1" => true,
                    _ => false,
                };
                for (k, x) in o.iter() {
                    path.push(k.clone());
                    let allow_here = is_dec && k == "s";
                    walk(x, path, allow_here)?;
                    path.pop();
                }
            }
            _ => {}
        }
        Ok(())
    }
    let mut path = vec!["$".to_string()];
    walk(value, &mut path, false)
}

/// Ensure the manifest is a UBL chip (envelope anchors present), because VCX-PACK is meant
/// to plug directly into the UBL pipeline/registry.
pub fn validate_ubl_manifest_envelope(manifest_json: &Value) -> Result<()> {
    let obj = manifest_json.as_object().context("ManifestMustBeObject")?;
    if !obj.contains_key("@type") {
        bail!("ManifestMissingAnchor(@type)");
    }
    if !obj.contains_key("@id") {
        bail!("ManifestMissingAnchor(@id)");
    }
    if !obj.contains_key("@ver") {
        bail!("ManifestMissingAnchor(@ver)");
    }
    if !obj.contains_key("@world") {
        bail!("ManifestMissingAnchor(@world)");
    }
    Ok(())
}

/// Build a pack in-memory and write to the provided writer.
pub fn build_pack<W: Write + Seek>(
    mut w: W,
    manifest_json: &Value,
    payloads: Vec<(MimeTag, Vec<u8>)>,
    strict_unc1: bool,
) -> Result<PackHeader> {
    validate_ubl_manifest_envelope(manifest_json)?;
    if strict_unc1 {
        validate_no_json_numbers(manifest_json)?;
    }

    // Manifest bytes (NRF-1.1)
    let (_manifest_cid_bytes, _manifest_cid_str, manifest_bytes) =
        cid_for_json_value(manifest_json)?;

    // Prepare entries (compute CIDs and raw payload hashes)
    let mut entries: Vec<(IndexEntry, Vec<u8>)> = Vec::with_capacity(payloads.len());
    for (mime_tag, bytes) in payloads {
        let (cid_bytes, _cid_str) = cid_for_payload_bytes(&bytes)?;
        let payload_hash = blake3::hash(&bytes).as_bytes().clone();
        let e = IndexEntry {
            cid: cid_bytes,
            mime_tag,
            flags: 0,
            payload_off: 0,
            payload_len: bytes.len() as u64,
            payload_hash,
        };
        entries.push((e, bytes));
    }

    // Sort by CID bytes for deterministic index.
    entries.sort_by(|(a, _), (b, _)| a.cid.cmp(&b.cid));

    // Compute region offsets.
    let manifest_off = PackHeader::LEN;
    let manifest_len = manifest_bytes.len() as u64;
    let index_off = align8(manifest_off + manifest_len);

    // We'll build index after payload offsets are known.
    // Pre-compute index length: fixed header + N entries.
    let index_header_len = 16; // magic[4] + ver u16 + entry_len u16 + count u32 + reserved u32
    let index_len = align8((index_header_len + entries.len() * IndexEntry::LEN) as u64);
    let payload_off = align8(index_off + index_len);

    // Assign payload offsets sequentially.
    let mut cursor = payload_off;
    for (e, bytes) in entries.iter_mut() {
        e.payload_off = cursor;
        cursor = align8(cursor + bytes.len() as u64);
    }
    let payload_end = cursor;
    let payload_len = payload_end - payload_off;

    // Build index bytes
    let mut index_bytes = Vec::with_capacity(index_len as usize);
    index_bytes.extend_from_slice(INDEX_MAGIC);
    index_bytes.extend_from_slice(&INDEX_VERSION.to_le_bytes());
    index_bytes.extend_from_slice(&(IndexEntry::LEN as u16).to_le_bytes());
    index_bytes.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    index_bytes.extend_from_slice(&0u32.to_le_bytes()); // reserved
    for (e, _) in &entries {
        e.write_to(&mut index_bytes)?;
    }
    // pad to index_len
    while (index_bytes.len() as u64) < index_len {
        index_bytes.push(0);
    }

    // Build Merkle tree (leaves commit to manifest+index+payload hashes)
    let index_hash = blake3::hash(&index_bytes).as_bytes().clone();
    let manifest_hash = blake3::hash(&manifest_bytes).as_bytes().clone();

    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(2 + entries.len());

    // leaf 0: manifest
    leaves.push(hash_leaf(0, 0, &manifest_hash, manifest_len, None));
    // leaf 1: index
    leaves.push(hash_leaf(1, 1, &index_hash, index_len, None));
    // payload leaves
    for (i, (e, _)) in entries.iter().enumerate() {
        let leaf_i = 2 + i as u32;
        leaves.push(hash_leaf(
            leaf_i,
            2,
            &e.payload_hash,
            e.payload_len,
            Some(&e.cid),
        ));
    }

    let levels = build_merkle_levels(&leaves);
    let root = *levels.last().unwrap().first().unwrap();

    let trailer = MerkleTrailer { root, levels };

    // Compute trailer bytes length by serializing into a vec first.
    let mut trailer_bytes = Vec::new();
    trailer.write_to(&mut trailer_bytes)?;
    let trailer_off = align8(payload_off + payload_len);
    let trailer_len = trailer_bytes.len() as u64;

    // Fill header
    let header = PackHeader {
        version: PACK_VERSION,
        flags: 0b0010, // has_merkle
        manifest_off,
        manifest_len,
        index_off,
        index_len,
        payload_off,
        payload_len,
        trailer_off,
        trailer_len,
    };

    // Write file
    w.seek(SeekFrom::Start(0))?;
    header.write_to(&mut w)?;

    // pad to manifest_off (should already be at 64)
    let pos = w.stream_position()?;
    if pos != manifest_off {
        bail!("Internal:BadWritePos({} != {})", pos, manifest_off);
    }
    w.write_all(&manifest_bytes)?;

    // pad to index_off
    let pos = w.stream_position()?;
    if pos < index_off {
        w.write_all(&vec![0u8; (index_off - pos) as usize])?;
    }
    w.write_all(&index_bytes)?;

    // pad to payload_off
    let pos = w.stream_position()?;
    if pos < payload_off {
        w.write_all(&vec![0u8; (payload_off - pos) as usize])?;
    }

    // payloads at specified offsets
    for (e, bytes) in &entries {
        let pos = w.stream_position()?;
        if pos < e.payload_off {
            w.write_all(&vec![0u8; (e.payload_off - pos) as usize])?;
        }
        w.write_all(bytes)?;
        // align8 padding
        let pos2 = w.stream_position()?;
        let aligned = align8(pos2);
        if aligned > pos2 {
            w.write_all(&vec![0u8; (aligned - pos2) as usize])?;
        }
    }

    // trailer
    let pos = w.stream_position()?;
    if pos < trailer_off {
        w.write_all(&vec![0u8; (trailer_off - pos) as usize])?;
    }
    w.write_all(&trailer_bytes)?;

    Ok(header)
}

fn hash_leaf(
    i: u32,
    kind: u8,
    content_hash: &[u8; 32],
    content_len: u64,
    cid: Option<&[u8; 32]>,
) -> [u8; 32] {
    // kind: 0=manifest, 1=index, 2=payload
    let mut input = Vec::with_capacity(4 + 1 + 32 + 8 + 32);
    input.extend_from_slice(b"vcx-leaf/v1\0");
    input.extend_from_slice(&i.to_le_bytes());
    input.push(kind);
    input.extend_from_slice(&content_len.to_le_bytes());
    input.extend_from_slice(content_hash);
    if let Some(cid) = cid {
        input.extend_from_slice(cid);
    }
    *blake3::hash(&input).as_bytes()
}

fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(8 + 32 + 32);
    input.extend_from_slice(b"vcx-node/v1\0");
    input.extend_from_slice(left);
    input.extend_from_slice(right);
    *blake3::hash(&input).as_bytes()
}

fn build_merkle_levels(leaves: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
    let mut levels = Vec::new();
    levels.push(leaves.to_vec());
    while levels.last().unwrap().len() > 1 {
        let prev = levels.last().unwrap();
        let mut next = Vec::new();
        let mut i = 0usize;
        while i < prev.len() {
            let left = prev[i];
            let right = if i + 1 < prev.len() {
                prev[i + 1]
            } else {
                prev[i]
            };
            next.push(hash_node(&left, &right));
            i += 2;
        }
        levels.push(next);
    }
    levels
}

/// Read and minimally verify a pack. If `full` is true, recompute payload hashes from bytes.
pub fn read_and_verify_pack<R: Read + Seek>(mut r: R, full: bool) -> Result<Pack> {
    r.seek(SeekFrom::Start(0))?;
    let header = PackHeader::read_from(&mut r)?;

    // sanity: offsets increasing and within file
    let file_len = r.seek(SeekFrom::End(0))?;
    let regions = [
        ("manifest", header.manifest_off, header.manifest_len),
        ("index", header.index_off, header.index_len),
        ("payload", header.payload_off, header.payload_len),
        ("trailer", header.trailer_off, header.trailer_len),
    ];
    for (name, off, len) in regions {
        if off + len > file_len {
            bail!("RegionOutOfBounds({})", name);
        }
    }

    // read manifest
    r.seek(SeekFrom::Start(header.manifest_off))?;
    let mut manifest_bytes = vec![0u8; header.manifest_len as usize];
    r.read_exact(&mut manifest_bytes)?;

    // read index
    r.seek(SeekFrom::Start(header.index_off))?;
    let mut index_bytes = vec![0u8; header.index_len as usize];
    r.read_exact(&mut index_bytes)?;
    let (entries, parsed_index_bytes_len) = parse_index(&index_bytes)?;
    // ensure any trailing bytes after parsed_index_bytes_len are zero (padding)
    if index_bytes[parsed_index_bytes_len..]
        .iter()
        .any(|b| *b != 0)
    {
        bail!("NonZeroPaddingInIndex");
    }

    // read trailer
    r.seek(SeekFrom::Start(header.trailer_off))?;
    let mut trailer_buf = vec![0u8; header.trailer_len as usize];
    r.read_exact(&mut trailer_buf)?;
    let merkle = MerkleTrailer::read_from(&trailer_buf[..])?;

    // validate index sorted
    for i in 1..entries.len() {
        if entries[i - 1].cid > entries[i].cid {
            bail!("IndexNotSorted");
        }
    }

    // if full, recompute payload_hash from bytes and compare
    if full {
        for e in &entries {
            r.seek(SeekFrom::Start(e.payload_off))?;
            let mut buf = vec![0u8; e.payload_len as usize];
            r.read_exact(&mut buf)?;
            let h = blake3::hash(&buf).as_bytes().clone();
            if h != e.payload_hash {
                bail!("PayloadHashMismatch");
            }
        }
    }

    // recompute merkle root from manifest/index and either stored hashes or recomputed.
    let manifest_hash = blake3::hash(&manifest_bytes).as_bytes().clone();
    let index_hash = blake3::hash(&index_bytes).as_bytes().clone();
    let mut leaves = Vec::with_capacity(2 + entries.len());
    leaves.push(hash_leaf(0, 0, &manifest_hash, header.manifest_len, None));
    leaves.push(hash_leaf(1, 1, &index_hash, header.index_len, None));
    for (i, e) in entries.iter().enumerate() {
        let leaf_i = 2 + i as u32;
        leaves.push(hash_leaf(
            leaf_i,
            2,
            &e.payload_hash,
            e.payload_len,
            Some(&e.cid),
        ));
    }
    let levels = build_merkle_levels(&leaves);
    let root = *levels.last().unwrap().first().unwrap();
    if root != merkle.root {
        bail!("MerkleRootMismatch");
    }

    Ok(Pack {
        header,
        manifest_bytes,
        index_entries: entries,
        merkle,
    })
}

fn parse_index(buf: &[u8]) -> Result<(Vec<IndexEntry>, usize)> {
    if buf.len() < 16 {
        bail!("IndexTooShort");
    }
    if &buf[0..4] != INDEX_MAGIC {
        bail!("BadIndexMagic");
    }
    let ver = u16::from_le_bytes(buf[4..6].try_into().unwrap());
    if ver != INDEX_VERSION {
        bail!("UnsupportedIndexVersion({})", ver);
    }
    let entry_len = u16::from_le_bytes(buf[6..8].try_into().unwrap()) as usize;
    if entry_len != IndexEntry::LEN {
        bail!("BadEntryLen({})", entry_len);
    }
    let count = u32::from_le_bytes(buf[8..12].try_into().unwrap()) as usize;
    // reserved u32 at [12..16]
    let mut entries = Vec::with_capacity(count);
    let mut pos = 16usize;
    for _ in 0..count {
        if pos + entry_len > buf.len() {
            bail!("IndexTruncated");
        }
        let e = IndexEntry::read_from(&buf[pos..pos + entry_len])?;
        entries.push(e);
        pos += entry_len;
    }
    Ok((entries, pos))
}

/// Convert CID string "b3:<hex>" to bytes.
pub fn cid_str_to_bytes(cid: &str) -> Result<[u8; 32]> {
    let s = cid.strip_prefix("b3:").context("CidMustStartWithB3")?;
    let raw = hex::decode(s).context("BadCidHex")?;
    if raw.len() != 32 {
        bail!("BadCidLenBytes({})", raw.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// Convert CID bytes to string "b3:<hex>".
pub fn cid_bytes_to_str(cid: &[u8; 32]) -> String {
    format!("b3:{}", hex::encode(cid))
}
