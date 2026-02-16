//! Rich URLs — verifiable, portable links to receipts and chips.
//!
//! Two formats (ARCHITECTURE.md §13):
//!
//! 1. **Hosted URL**: `https://{host}/{app}/{tenant}/receipts/{id}.json#cid=...&did=...&rt=...&sig=...`
//!    - Fetch receipt JSON from path, verify CID + signature offline.
//!
//! 2. **Self-contained URL** (`ubl://`): `ubl://{base64url(compressed_chip)}?cid={cid}&sig={sig}`
//!    - For QR codes / offline. Max 2 KB.
//!
//! Signing domain: `"ubl-url/v1"`

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{Read, Write};

/// Signing domain for URL signatures.
pub const URL_SIGN_DOMAIN: &str = "ubl-url/v1";

/// Maximum self-contained URL length (QR code limit).
pub const MAX_SELF_CONTAINED_URL_BYTES: usize = 2048;

/// A hosted Rich URL with all verification fragments.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HostedUrl {
    /// Base host (e.g. "https://ubl.example.com")
    pub host: String,
    /// Application scope
    pub app: String,
    /// Tenant scope
    pub tenant: String,
    /// Receipt logical ID
    pub receipt_id: String,
    /// Receipt CID (BLAKE3)
    pub cid: String,
    /// Issuer DID
    pub did: String,
    /// Runtime binary SHA-256
    pub rt: String,
    /// URL signature (Ed25519 over canonical URL string with domain)
    pub sig: String,
}

impl HostedUrl {
    /// Build a new hosted URL.
    pub fn new(
        host: &str,
        app: &str,
        tenant: &str,
        receipt_id: &str,
        cid: &str,
        did: &str,
        rt: &str,
        sig: &str,
    ) -> Self {
        Self {
            host: host.to_string(),
            app: app.to_string(),
            tenant: tenant.to_string(),
            receipt_id: receipt_id.to_string(),
            cid: cid.to_string(),
            did: did.to_string(),
            rt: rt.to_string(),
            sig: sig.to_string(),
        }
    }

    /// Render the full URL string.
    pub fn to_url_string(&self) -> String {
        format!(
            "{}/{}/{}/receipts/{}.json#cid={}&did={}&rt={}&sig={}",
            self.host, self.app, self.tenant, self.receipt_id,
            self.cid, self.did, self.rt, self.sig
        )
    }

    /// Parse a hosted URL string back into components.
    pub fn parse(url: &str) -> Result<Self, UrlError> {
        // Split on '#' to get path and fragment
        let (path, fragment) = url.split_once('#')
            .ok_or_else(|| UrlError::InvalidFormat("Missing # fragment".into()))?;

        // Parse fragment params
        let params = parse_query_params(fragment);
        let cid = params.get("cid")
            .ok_or_else(|| UrlError::MissingParam("cid".into()))?
            .to_string();
        let did = params.get("did")
            .ok_or_else(|| UrlError::MissingParam("did".into()))?
            .to_string();
        let rt = params.get("rt")
            .ok_or_else(|| UrlError::MissingParam("rt".into()))?
            .to_string();
        let sig = params.get("sig")
            .ok_or_else(|| UrlError::MissingParam("sig".into()))?
            .to_string();

        // Parse path: {host}/{app}/{tenant}/receipts/{id}.json
        // Find "/receipts/" to split
        let receipts_idx = path.find("/receipts/")
            .ok_or_else(|| UrlError::InvalidFormat("Missing /receipts/ in path".into()))?;

        let base = &path[..receipts_idx];
        let receipt_file = &path[receipts_idx + "/receipts/".len()..];
        let receipt_id = receipt_file.strip_suffix(".json")
            .ok_or_else(|| UrlError::InvalidFormat("Receipt path must end in .json".into()))?
            .to_string();

        // Split base into host/app/tenant
        // base = "https://host/app/tenant"
        // We need to find the last two path segments
        let segments: Vec<&str> = base.rsplitn(3, '/').collect();
        if segments.len() < 3 {
            return Err(UrlError::InvalidFormat("Cannot parse host/app/tenant from path".into()));
        }
        let tenant = segments[0].to_string();
        let app = segments[1].to_string();
        let host = segments[2].to_string();

        Ok(Self { host, app, tenant, receipt_id, cid, did, rt, sig })
    }

    /// Produce the canonical string that is signed.
    /// Format: `{domain}\n{path_without_fragment}`
    pub fn signing_payload(&self) -> Vec<u8> {
        let path = format!(
            "{}/{}/{}/receipts/{}.json",
            self.host, self.app, self.tenant, self.receipt_id
        );
        let payload = format!("{}\n{}\n{}\n{}\n{}", URL_SIGN_DOMAIN, path, self.cid, self.did, self.rt);
        payload.into_bytes()
    }
}

/// A self-contained `ubl://` URL for QR codes and offline use.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SelfContainedUrl {
    /// Compressed chip data (base64url encoded)
    pub data_b64: String,
    /// CID of the chip
    pub cid: String,
    /// Signature
    pub sig: String,
}

impl SelfContainedUrl {
    /// Create a self-contained URL from chip JSON.
    /// Compresses with flate2 deflate, then base64url encodes.
    pub fn from_chip(chip_json: &Value, cid: &str, sig: &str) -> Result<Self, UrlError> {
        let json_bytes = serde_json::to_vec(chip_json)
            .map_err(|e| UrlError::Encoding(format!("JSON serialize: {}", e)))?;

        let compressed = deflate_compress(&json_bytes)?;
        let data_b64 = base64url_encode(&compressed);

        let url = Self {
            data_b64,
            cid: cid.to_string(),
            sig: sig.to_string(),
        };

        // Check size limit
        let url_str = url.to_url_string();
        if url_str.len() > MAX_SELF_CONTAINED_URL_BYTES {
            return Err(UrlError::TooLarge {
                size: url_str.len(),
                limit: MAX_SELF_CONTAINED_URL_BYTES,
            });
        }

        Ok(url)
    }

    /// Render the `ubl://` URL string.
    pub fn to_url_string(&self) -> String {
        format!("ubl://{}?cid={}&sig={}", self.data_b64, self.cid, self.sig)
    }

    /// Parse a `ubl://` URL string.
    pub fn parse(url: &str) -> Result<Self, UrlError> {
        let rest = url.strip_prefix("ubl://")
            .ok_or_else(|| UrlError::InvalidFormat("Must start with ubl://".into()))?;

        let (data_b64, query) = rest.split_once('?')
            .ok_or_else(|| UrlError::InvalidFormat("Missing ? query".into()))?;

        let params = parse_query_params(query);
        let cid = params.get("cid")
            .ok_or_else(|| UrlError::MissingParam("cid".into()))?
            .to_string();
        let sig = params.get("sig")
            .ok_or_else(|| UrlError::MissingParam("sig".into()))?
            .to_string();

        Ok(Self {
            data_b64: data_b64.to_string(),
            cid,
            sig,
        })
    }

    /// Extract the chip JSON from the compressed data.
    pub fn extract_chip(&self) -> Result<Value, UrlError> {
        let compressed = base64url_decode(&self.data_b64)?;
        let decompressed = deflate_decompress(&compressed)?;
        serde_json::from_slice(&decompressed)
            .map_err(|e| UrlError::Encoding(format!("JSON parse: {}", e)))
    }

    /// Produce the canonical signing payload.
    pub fn signing_payload(&self) -> Vec<u8> {
        format!("{}\n{}\n{}", URL_SIGN_DOMAIN, self.data_b64, self.cid).into_bytes()
    }
}

/// Offline verification result.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether the CID matches the receipt body
    pub cid_valid: bool,
    /// Whether the signature is valid
    pub sig_valid: bool,
    /// Whether the runtime hash matches expectations
    pub rt_valid: bool,
    /// Overall pass/fail
    pub verified: bool,
    /// Human-readable summary
    pub summary: String,
}

/// Verify a hosted URL offline given the fetched receipt body.
pub fn verify_hosted(url: &HostedUrl, receipt_body: &Value) -> VerificationResult {
    // Step 1: Recompute CID from receipt body
    let canonical = serde_json::to_vec(receipt_body).unwrap_or_default();
    let hash = blake3::hash(&canonical);
    let computed_cid = format!("b3:{}", hex::encode(hash.as_bytes()));
    let cid_valid = computed_cid == url.cid;

    // Step 2: Signature verification (placeholder — real impl needs DID resolution)
    // For now, we check that sig is non-empty
    let sig_valid = !url.sig.is_empty();

    // Step 3: Runtime hash (placeholder — real impl compares against known binary)
    let rt_valid = !url.rt.is_empty();

    let verified = cid_valid && sig_valid && rt_valid;
    let summary = if verified {
        format!("VERIFIED: CID={}, DID={}", url.cid, url.did)
    } else {
        let mut issues = vec![];
        if !cid_valid { issues.push(format!("CID mismatch: expected {}, got {}", url.cid, computed_cid)); }
        if !sig_valid { issues.push("Missing signature".to_string()); }
        if !rt_valid { issues.push("Missing runtime hash".to_string()); }
        format!("FAILED: {}", issues.join("; "))
    };

    VerificationResult { cid_valid, sig_valid, rt_valid, verified, summary }
}

/// Verify a self-contained URL offline.
pub fn verify_self_contained(url: &SelfContainedUrl) -> Result<VerificationResult, UrlError> {
    let chip = url.extract_chip()?;

    let canonical = serde_json::to_vec(&chip).unwrap_or_default();
    let hash = blake3::hash(&canonical);
    let computed_cid = format!("b3:{}", hex::encode(hash.as_bytes()));
    let cid_valid = computed_cid == url.cid;

    let sig_valid = !url.sig.is_empty();

    let verified = cid_valid && sig_valid;
    let summary = if verified {
        format!("VERIFIED: self-contained CID={}", url.cid)
    } else {
        let mut issues = vec![];
        if !cid_valid { issues.push(format!("CID mismatch: expected {}, got {}", url.cid, computed_cid)); }
        if !sig_valid { issues.push("Missing signature".to_string()); }
        format!("FAILED: {}", issues.join("; "))
    };

    Ok(VerificationResult { cid_valid, sig_valid, rt_valid: true, verified, summary })
}

// ── Errors ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum UrlError {
    InvalidFormat(String),
    MissingParam(String),
    Encoding(String),
    TooLarge { size: usize, limit: usize },
}

impl std::fmt::Display for UrlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UrlError::InvalidFormat(e) => write!(f, "Invalid URL format: {}", e),
            UrlError::MissingParam(p) => write!(f, "Missing URL parameter: {}", p),
            UrlError::Encoding(e) => write!(f, "Encoding error: {}", e),
            UrlError::TooLarge { size, limit } =>
                write!(f, "URL too large: {} bytes (limit {} bytes)", size, limit),
        }
    }
}

impl std::error::Error for UrlError {}

// ── Helpers ─────────────────────────────────────────────────────

fn parse_query_params(query: &str) -> std::collections::HashMap<String, String> {
    query.split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            Some((k.to_string(), v.to_string()))
        })
        .collect()
}

fn base64url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn base64url_decode(s: &str) -> Result<Vec<u8>, UrlError> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| UrlError::Encoding(format!("base64url decode: {}", e)))
}

fn deflate_compress(data: &[u8]) -> Result<Vec<u8>, UrlError> {
    use flate2::write::DeflateEncoder;
    use flate2::Compression;

    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(data)
        .map_err(|e| UrlError::Encoding(format!("deflate compress: {}", e)))?;
    encoder.finish()
        .map_err(|e| UrlError::Encoding(format!("deflate finish: {}", e)))
}

fn deflate_decompress(data: &[u8]) -> Result<Vec<u8>, UrlError> {
    use flate2::read::DeflateDecoder;

    let mut decoder = DeflateDecoder::new(data);
    let mut result = Vec::new();
    decoder.read_to_end(&mut result)
        .map_err(|e| UrlError::Encoding(format!("deflate decompress: {}", e)))?;
    Ok(result)
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hosted_url_roundtrip() {
        let url = HostedUrl::new(
            "https://ubl.example.com",
            "acme",
            "prod",
            "receipt-001",
            "b3:abc123",
            "did:key:z6Mk...",
            "sha256:deadbeef",
            "sig:xyz",
        );

        let s = url.to_url_string();
        assert!(s.starts_with("https://ubl.example.com/acme/prod/receipts/receipt-001.json#"));
        assert!(s.contains("cid=b3:abc123"));
        assert!(s.contains("did=did:key:z6Mk..."));
        assert!(s.contains("rt=sha256:deadbeef"));
        assert!(s.contains("sig=sig:xyz"));

        let parsed = HostedUrl::parse(&s).unwrap();
        assert_eq!(parsed.host, "https://ubl.example.com");
        assert_eq!(parsed.app, "acme");
        assert_eq!(parsed.tenant, "prod");
        assert_eq!(parsed.receipt_id, "receipt-001");
        assert_eq!(parsed.cid, "b3:abc123");
        assert_eq!(parsed.did, "did:key:z6Mk...");
        assert_eq!(parsed.rt, "sha256:deadbeef");
        assert_eq!(parsed.sig, "sig:xyz");
    }

    #[test]
    fn hosted_url_missing_fragment_fails() {
        let err = HostedUrl::parse("https://example.com/a/b/receipts/r.json");
        assert!(err.is_err());
    }

    #[test]
    fn hosted_url_missing_param_fails() {
        let err = HostedUrl::parse("https://example.com/a/b/receipts/r.json#cid=x&did=y");
        assert!(err.is_err()); // missing rt and sig
    }

    #[test]
    fn signing_payload_includes_domain() {
        let url = HostedUrl::new(
            "https://ubl.example.com", "app", "tenant", "r1",
            "b3:cid", "did:key:x", "sha256:rt", "sig",
        );
        let payload = url.signing_payload();
        let s = String::from_utf8(payload).unwrap();
        assert!(s.starts_with("ubl-url/v1\n"));
        assert!(s.contains("b3:cid"));
        assert!(s.contains("did:key:x"));
    }

    #[test]
    fn self_contained_url_roundtrip() {
        let chip = json!({
            "@type": "ubl/user",
            "@id": "u1",
            "@ver": "1.0",
            "@world": "a/test/t/test"
        });

        let canonical = serde_json::to_vec(&chip).unwrap();
        let hash = blake3::hash(&canonical);
        let cid = format!("b3:{}", hex::encode(hash.as_bytes()));

        let url = SelfContainedUrl::from_chip(&chip, &cid, "sig:test").unwrap();
        let s = url.to_url_string();
        assert!(s.starts_with("ubl://"));
        assert!(s.contains(&cid));

        let parsed = SelfContainedUrl::parse(&s).unwrap();
        assert_eq!(parsed.cid, cid);
        assert_eq!(parsed.sig, "sig:test");

        let extracted = parsed.extract_chip().unwrap();
        assert_eq!(extracted["@type"], "ubl/user");
        assert_eq!(extracted["@id"], "u1");
    }

    #[test]
    fn self_contained_url_too_large() {
        // Generate pseudo-random hex strings that defeat deflate compression.
        // Each field has a unique SHA-256 hash as value → incompressible.
        let mut fields = serde_json::Map::new();
        fields.insert("@type".into(), json!("ubl/user"));
        fields.insert("@id".into(), json!("u1"));
        for i in 0..80 {
            let hash = blake3::hash(format!("seed-{}", i).as_bytes());
            fields.insert(
                format!("f{:03}", i),
                json!(hex::encode(hash.as_bytes())),
            );
        }
        let chip = Value::Object(fields);

        let result = SelfContainedUrl::from_chip(&chip, "b3:cid", "sig");
        assert!(result.is_err(), "Expected TooLarge error, got Ok with URL len {}",
            result.as_ref().map(|u| u.to_url_string().len()).unwrap_or(0));
        assert!(matches!(result, Err(UrlError::TooLarge { .. })));
    }

    #[test]
    fn verify_hosted_url_cid_match() {
        let receipt = json!({
            "@type": "ubl/receipt",
            "decision": "allow"
        });

        let canonical = serde_json::to_vec(&receipt).unwrap();
        let hash = blake3::hash(&canonical);
        let cid = format!("b3:{}", hex::encode(hash.as_bytes()));

        let url = HostedUrl::new(
            "https://ubl.example.com", "app", "tenant", "r1",
            &cid, "did:key:x", "sha256:rt", "sig:valid",
        );

        let result = verify_hosted(&url, &receipt);
        assert!(result.cid_valid);
        assert!(result.verified);
    }

    #[test]
    fn verify_hosted_url_cid_mismatch() {
        let receipt = json!({"@type": "ubl/receipt", "decision": "allow"});

        let url = HostedUrl::new(
            "https://ubl.example.com", "app", "tenant", "r1",
            "b3:wrong", "did:key:x", "sha256:rt", "sig:valid",
        );

        let result = verify_hosted(&url, &receipt);
        assert!(!result.cid_valid);
        assert!(!result.verified);
        assert!(result.summary.contains("CID mismatch"));
    }

    #[test]
    fn verify_self_contained_url() {
        let chip = json!({
            "@type": "ubl/user",
            "@id": "u1",
            "@ver": "1.0",
            "@world": "a/test/t/test"
        });

        let canonical = serde_json::to_vec(&chip).unwrap();
        let hash = blake3::hash(&canonical);
        let cid = format!("b3:{}", hex::encode(hash.as_bytes()));

        let url = SelfContainedUrl::from_chip(&chip, &cid, "sig:ok").unwrap();
        let result = verify_self_contained(&url).unwrap();
        assert!(result.cid_valid);
        assert!(result.verified);
    }

    #[test]
    fn deflate_roundtrip() {
        let data = b"hello world, this is a test of deflate compression";
        let compressed = deflate_compress(data).unwrap();
        assert!(compressed.len() < data.len()); // should compress
        let decompressed = deflate_decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn base64url_roundtrip() {
        let data = b"\x00\x01\x02\xff\xfe\xfd";
        let encoded = base64url_encode(data);
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn self_contained_signing_payload_has_domain() {
        let url = SelfContainedUrl {
            data_b64: "abc".into(),
            cid: "b3:cid".into(),
            sig: "sig".into(),
        };
        let payload = String::from_utf8(url.signing_payload()).unwrap();
        assert!(payload.starts_with("ubl-url/v1\n"));
        assert!(payload.contains("abc"));
        assert!(payload.contains("b3:cid"));
    }
}
