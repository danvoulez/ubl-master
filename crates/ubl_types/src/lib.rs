//! Leaf-level newtypes for UBL.
//!
//! These types sit at the bottom of the dependency graph — every crate can
//! depend on `ubl_types` without pulling in heavy deps. They replace raw
//! `String` usage for content identifiers, decentralized identifiers, and
//! key identifiers, catching misuse at compile time.
//!
//! All types implement `Serialize`/`Deserialize` as transparent strings
//! so they are wire-compatible with existing JSON formats.

use serde::{Deserialize, Serialize};
use std::fmt;

// ── Cid ─────────────────────────────────────────────────────────────────

/// Content Identifier — `b3:<hex>` (BLAKE3 hash of NRF-1 bytes).
///
/// Invariant: always starts with `"b3:"` and contains only lowercase hex
/// after the prefix. Use `Cid::new()` for validated construction or
/// `Cid::new_unchecked()` when the source is trusted (e.g. just computed).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Cid(String);

impl Cid {
    /// Validated constructor — returns `Err` if the string doesn't match `b3:<hex>`.
    pub fn new(s: impl Into<String>) -> Result<Self, TypeParseError> {
        let s = s.into();
        if !s.starts_with("b3:") {
            return Err(TypeParseError::InvalidPrefix {
                expected: "b3:",
                got: s,
            });
        }
        let hex_part = &s[3..];
        if hex_part.is_empty() {
            return Err(TypeParseError::Empty("Cid hex part"));
        }
        if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(TypeParseError::InvalidChars {
                kind: "Cid",
                got: s,
            });
        }
        Ok(Self(s))
    }

    /// Unchecked constructor — use when the value was just computed and is
    /// known to be valid (e.g. output of `compute_cid`).
    pub fn new_unchecked(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Borrow the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Cid {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// ── Did ─────────────────────────────────────────────────────────────────

/// Decentralized Identifier — `did:<method>:<id>`.
///
/// Currently only `did:key:z...` is used in production. The constructor
/// validates the `did:` prefix but does not enforce a specific method.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Did(String);

impl Did {
    /// Validated constructor — returns `Err` if the string doesn't start with `did:`.
    pub fn new(s: impl Into<String>) -> Result<Self, TypeParseError> {
        let s = s.into();
        if !s.starts_with("did:") {
            return Err(TypeParseError::InvalidPrefix {
                expected: "did:",
                got: s,
            });
        }
        // Must have at least did:x:y (method + id)
        let parts: Vec<&str> = s.splitn(3, ':').collect();
        if parts.len() < 3 || parts[1].is_empty() || parts[2].is_empty() {
            return Err(TypeParseError::InvalidFormat {
                kind: "Did",
                expected: "did:<method>:<id>",
                got: s,
            });
        }
        Ok(Self(s))
    }

    /// Unchecked constructor — use when the value is known to be valid.
    pub fn new_unchecked(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// The DID method (e.g. `"key"` for `did:key:z...`).
    pub fn method(&self) -> &str {
        self.0.split(':').nth(1).unwrap_or("")
    }

    /// Borrow the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Did {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// ── Kid ─────────────────────────────────────────────────────────────────

/// Key Identifier — `did:key:z...#z...` (DID fragment identifying a specific key).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Kid(String);

impl Kid {
    /// Validated constructor — must contain `#` fragment.
    pub fn new(s: impl Into<String>) -> Result<Self, TypeParseError> {
        let s = s.into();
        if !s.contains('#') {
            return Err(TypeParseError::InvalidFormat {
                kind: "Kid",
                expected: "<did>#<fragment>",
                got: s,
            });
        }
        Ok(Self(s))
    }

    /// Unchecked constructor.
    pub fn new_unchecked(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// The DID part (before `#`).
    pub fn did_part(&self) -> &str {
        self.0.split('#').next().unwrap_or("")
    }

    /// The fragment part (after `#`).
    pub fn fragment(&self) -> &str {
        self.0.split('#').nth(1).unwrap_or("")
    }

    /// Borrow the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for Kid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Kid {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// ── Nonce ───────────────────────────────────────────────────────────────

/// Cryptographic nonce — 16 random bytes, hex-encoded (32 hex chars).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Nonce(String);

impl Nonce {
    /// Validated constructor — must be 32 hex chars.
    pub fn new(s: impl Into<String>) -> Result<Self, TypeParseError> {
        let s = s.into();
        if s.len() != 32 {
            return Err(TypeParseError::InvalidLength {
                kind: "Nonce",
                expected: 32,
                got: s.len(),
            });
        }
        if !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(TypeParseError::InvalidChars {
                kind: "Nonce",
                got: s,
            });
        }
        Ok(Self(s))
    }

    /// Unchecked constructor.
    pub fn new_unchecked(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Borrow the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Nonce {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// ── ChipType ────────────────────────────────────────────────────────────

/// Chip type identifier — e.g. `"ubl/document"`, `"ubl/user"`.
///
/// Must contain at least one `/` separator.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChipType(String);

impl ChipType {
    /// Validated constructor.
    pub fn new(s: impl Into<String>) -> Result<Self, TypeParseError> {
        let s = s.into();
        if !s.contains('/') {
            return Err(TypeParseError::InvalidFormat {
                kind: "ChipType",
                expected: "<namespace>/<name>",
                got: s,
            });
        }
        Ok(Self(s))
    }

    /// Unchecked constructor.
    pub fn new_unchecked(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// The namespace part (before first `/`).
    pub fn namespace(&self) -> &str {
        self.0.split('/').next().unwrap_or("")
    }

    /// The name part (after first `/`).
    pub fn name(&self) -> &str {
        self.0.split_once('/').map(|x| x.1).unwrap_or("")
    }

    /// Borrow the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for ChipType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for ChipType {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// ── World ───────────────────────────────────────────────────────────────

/// World scope — `a/<app>/t/<tenant>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct World(String);

impl World {
    /// Validated constructor — must match `a/<app>/t/<tenant>` or `a/<app>`.
    pub fn new(s: impl Into<String>) -> Result<Self, TypeParseError> {
        let s = s.into();
        if !s.starts_with("a/") {
            return Err(TypeParseError::InvalidPrefix {
                expected: "a/",
                got: s,
            });
        }
        Ok(Self(s))
    }

    /// Unchecked constructor.
    pub fn new_unchecked(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Extract app slug (between `a/` and `/t/` or end).
    pub fn app(&self) -> &str {
        let after_a = &self.0[2..]; // skip "a/"
        after_a.split("/t/").next().unwrap_or(after_a)
    }

    /// Extract tenant slug (after `/t/`), if present.
    pub fn tenant(&self) -> Option<&str> {
        self.0.split("/t/").nth(1)
    }

    /// Borrow the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for World {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for World {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// ── Errors ──────────────────────────────────────────────────────────────

/// Error returned when constructing a newtype from an invalid string.
#[derive(Debug, Clone)]
pub enum TypeParseError {
    InvalidPrefix {
        expected: &'static str,
        got: String,
    },
    InvalidFormat {
        kind: &'static str,
        expected: &'static str,
        got: String,
    },
    InvalidChars {
        kind: &'static str,
        got: String,
    },
    InvalidLength {
        kind: &'static str,
        expected: usize,
        got: usize,
    },
    Empty(&'static str),
}

impl fmt::Display for TypeParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrefix { expected, got } => {
                write!(f, "expected prefix '{}', got '{}'", expected, got)
            }
            Self::InvalidFormat {
                kind,
                expected,
                got,
            } => {
                write!(
                    f,
                    "invalid {}: expected '{}', got '{}'",
                    kind, expected, got
                )
            }
            Self::InvalidChars { kind, got } => {
                write!(f, "invalid characters in {}: '{}'", kind, got)
            }
            Self::InvalidLength {
                kind,
                expected,
                got,
            } => {
                write!(
                    f,
                    "invalid {} length: expected {}, got {}",
                    kind, expected, got
                )
            }
            Self::Empty(kind) => {
                write!(f, "{} cannot be empty", kind)
            }
        }
    }
}

impl std::error::Error for TypeParseError {}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Cid ──

    #[test]
    fn cid_valid() {
        let cid = Cid::new("b3:abcdef0123456789").unwrap();
        assert_eq!(cid.as_str(), "b3:abcdef0123456789");
        assert_eq!(format!("{}", cid), "b3:abcdef0123456789");
    }

    #[test]
    fn cid_rejects_no_prefix() {
        assert!(Cid::new("sha256:abc").is_err());
    }

    #[test]
    fn cid_rejects_empty_hex() {
        assert!(Cid::new("b3:").is_err());
    }

    #[test]
    fn cid_rejects_non_hex() {
        assert!(Cid::new("b3:xyz").is_err());
    }

    #[test]
    fn cid_unchecked_allows_anything() {
        let cid = Cid::new_unchecked("anything");
        assert_eq!(cid.as_str(), "anything");
    }

    #[test]
    fn cid_serde_roundtrip() {
        let cid = Cid::new("b3:aabb").unwrap();
        let json = serde_json::to_string(&cid).unwrap();
        assert_eq!(json, "\"b3:aabb\"");
        let back: Cid = serde_json::from_str(&json).unwrap();
        assert_eq!(cid, back);
    }

    #[test]
    fn cid_hash_eq() {
        let a = Cid::new("b3:aa").unwrap();
        let b = Cid::new("b3:aa").unwrap();
        let c = Cid::new("b3:bb").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        // Can be used as HashMap key
        let mut map = std::collections::HashMap::new();
        map.insert(a.clone(), 1);
        assert_eq!(map.get(&b), Some(&1));
    }

    // ── Did ──

    #[test]
    fn did_valid() {
        let did = Did::new("did:key:z6MkTest").unwrap();
        assert_eq!(did.method(), "key");
        assert_eq!(did.as_str(), "did:key:z6MkTest");
    }

    #[test]
    fn did_rejects_no_prefix() {
        assert!(Did::new("key:z6MkTest").is_err());
    }

    #[test]
    fn did_rejects_missing_id() {
        assert!(Did::new("did:key:").is_err());
    }

    #[test]
    fn did_rejects_missing_method() {
        assert!(Did::new("did::something").is_err());
    }

    #[test]
    fn did_serde_roundtrip() {
        let did = Did::new("did:key:z6MkTest").unwrap();
        let json = serde_json::to_string(&did).unwrap();
        let back: Did = serde_json::from_str(&json).unwrap();
        assert_eq!(did, back);
    }

    // ── Kid ──

    #[test]
    fn kid_valid() {
        let kid = Kid::new("did:key:z6Mk#z6Mk").unwrap();
        assert_eq!(kid.did_part(), "did:key:z6Mk");
        assert_eq!(kid.fragment(), "z6Mk");
    }

    #[test]
    fn kid_rejects_no_fragment() {
        assert!(Kid::new("did:key:z6Mk").is_err());
    }

    // ── Nonce ──

    #[test]
    fn nonce_valid() {
        let nonce = Nonce::new("aabbccdd11223344aabbccdd11223344").unwrap();
        assert_eq!(nonce.as_str().len(), 32);
    }

    #[test]
    fn nonce_rejects_wrong_length() {
        assert!(Nonce::new("aabb").is_err());
    }

    #[test]
    fn nonce_rejects_non_hex() {
        assert!(Nonce::new("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_err());
    }

    // ── ChipType ──

    #[test]
    fn chip_type_valid() {
        let ct = ChipType::new("ubl/document").unwrap();
        assert_eq!(ct.namespace(), "ubl");
        assert_eq!(ct.name(), "document");
    }

    #[test]
    fn chip_type_rejects_no_slash() {
        assert!(ChipType::new("plain").is_err());
    }

    #[test]
    fn chip_type_dotted_name() {
        let ct = ChipType::new("ubl/meta.register").unwrap();
        assert_eq!(ct.namespace(), "ubl");
        assert_eq!(ct.name(), "meta.register");
    }

    // ── World ──

    #[test]
    fn world_full() {
        let w = World::new("a/acme/t/prod").unwrap();
        assert_eq!(w.app(), "acme");
        assert_eq!(w.tenant(), Some("prod"));
    }

    #[test]
    fn world_app_only() {
        let w = World::new("a/acme").unwrap();
        assert_eq!(w.app(), "acme");
        assert_eq!(w.tenant(), None);
    }

    #[test]
    fn world_rejects_no_prefix() {
        assert!(World::new("acme/prod").is_err());
    }

    #[test]
    fn world_serde_roundtrip() {
        let w = World::new("a/acme/t/prod").unwrap();
        let json = serde_json::to_string(&w).unwrap();
        assert_eq!(json, "\"a/acme/t/prod\"");
        let back: World = serde_json::from_str(&json).unwrap();
        assert_eq!(w, back);
    }
}
