//! Policy lockfile — compile-time policy resolution with CID pinning.
//!
//! Per ARCHITECTURE.md §6.3:
//! - `policy.lock` maps scope levels to pinned policy CIDs
//! - TR stage verifies loaded policy CIDs match lockfile
//! - Divergence = DENY (policy drift detected)
//!
//! Format (YAML):
//! ```yaml
//! version: 1
//! policies:
//!   genesis: b3:abc123...
//!   app/acme: b3:def456...
//!   tenant/acme-prod: b3:789abc...
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A policy lockfile that pins policy CIDs per scope level.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyLock {
    /// Lockfile format version (currently 1).
    pub version: u32,
    /// Map of scope level → pinned policy CID.
    /// Keys: "genesis", "app/{slug}", "tenant/{slug}"
    pub policies: BTreeMap<String, String>,
}

/// Result of verifying loaded policies against the lockfile.
#[derive(Debug, Clone)]
pub struct LockVerification {
    pub ok: bool,
    pub mismatches: Vec<LockMismatch>,
    pub missing: Vec<String>,
    pub extra: Vec<String>,
}

/// A single mismatch between lockfile and loaded policy.
#[derive(Debug, Clone)]
pub struct LockMismatch {
    pub level: String,
    pub expected_cid: String,
    pub actual_cid: String,
}

impl PolicyLock {
    /// Create an empty lockfile.
    pub fn new() -> Self {
        Self {
            version: 1,
            policies: BTreeMap::new(),
        }
    }

    /// Pin a policy CID at a given scope level.
    pub fn pin(&mut self, level: &str, cid: &str) {
        self.policies.insert(level.to_string(), cid.to_string());
    }

    /// Parse a lockfile from YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, String> {
        // Simple YAML parser — no external dep needed for this structure.
        // Format:
        //   version: 1
        //   policies:
        //     genesis: b3:abc
        //     app/acme: b3:def
        let mut lock = PolicyLock::new();
        let mut in_policies = false;

        for line in yaml.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if trimmed.starts_with("version:") {
                let v = trimmed.trim_start_matches("version:").trim();
                lock.version = v
                    .parse::<u32>()
                    .map_err(|e| format!("invalid version: {}", e))?;
            } else if trimmed == "policies:" {
                in_policies = true;
            } else if in_policies && trimmed.contains(':') {
                // Indented key: value under policies
                let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
                if parts.len() == 2 {
                    let key = parts[0].trim().to_string();
                    let val = parts[1].trim().to_string();
                    if !val.is_empty() {
                        lock.policies.insert(key, val);
                    }
                }
            }
        }

        if lock.version != 1 {
            return Err(format!("unsupported lockfile version: {}", lock.version));
        }

        Ok(lock)
    }

    /// Serialize to YAML string.
    pub fn to_yaml(&self) -> String {
        let mut out = format!("version: {}\npolicies:\n", self.version);
        for (level, cid) in &self.policies {
            out.push_str(&format!("  {}: {}\n", level, cid));
        }
        out
    }

    /// Verify loaded policies against this lockfile.
    /// `loaded` is a map of scope level → actual CID from the policy loader.
    pub fn verify(&self, loaded: &BTreeMap<String, String>) -> LockVerification {
        let mut mismatches = Vec::new();
        let mut missing = Vec::new();
        let mut extra = Vec::new();

        // Check every pinned policy is present and matches
        for (level, expected_cid) in &self.policies {
            match loaded.get(level) {
                Some(actual_cid) => {
                    if actual_cid != expected_cid {
                        mismatches.push(LockMismatch {
                            level: level.clone(),
                            expected_cid: expected_cid.clone(),
                            actual_cid: actual_cid.clone(),
                        });
                    }
                }
                None => {
                    missing.push(level.clone());
                }
            }
        }

        // Check for loaded policies not in the lockfile
        for level in loaded.keys() {
            if !self.policies.contains_key(level) {
                extra.push(level.clone());
            }
        }

        let ok = mismatches.is_empty() && missing.is_empty();
        LockVerification {
            ok,
            mismatches,
            missing,
            extra,
        }
    }
}

impl Default for PolicyLock {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for LockVerification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.ok {
            write!(f, "policy lockfile: OK")?;
        } else {
            write!(f, "policy lockfile: DRIFT DETECTED")?;
            for m in &self.mismatches {
                write!(
                    f,
                    "\n  MISMATCH {}: expected {} got {}",
                    m.level, m.expected_cid, m.actual_cid
                )?;
            }
            for m in &self.missing {
                write!(f, "\n  MISSING {}", m)?;
            }
        }
        if !self.extra.is_empty() {
            for e in &self.extra {
                write!(f, "\n  EXTRA {} (not in lockfile)", e)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_lockfile_is_empty() {
        let lock = PolicyLock::new();
        assert_eq!(lock.version, 1);
        assert!(lock.policies.is_empty());
    }

    #[test]
    fn pin_and_verify_match() {
        let mut lock = PolicyLock::new();
        lock.pin("genesis", "b3:genesis_abc");
        lock.pin("app/acme", "b3:app_def");

        let mut loaded = BTreeMap::new();
        loaded.insert("genesis".into(), "b3:genesis_abc".into());
        loaded.insert("app/acme".into(), "b3:app_def".into());

        let result = lock.verify(&loaded);
        assert!(result.ok);
        assert!(result.mismatches.is_empty());
        assert!(result.missing.is_empty());
    }

    #[test]
    fn verify_detects_mismatch() {
        let mut lock = PolicyLock::new();
        lock.pin("genesis", "b3:expected");

        let mut loaded = BTreeMap::new();
        loaded.insert("genesis".into(), "b3:actual_different".into());

        let result = lock.verify(&loaded);
        assert!(!result.ok);
        assert_eq!(result.mismatches.len(), 1);
        assert_eq!(result.mismatches[0].level, "genesis");
        assert_eq!(result.mismatches[0].expected_cid, "b3:expected");
        assert_eq!(result.mismatches[0].actual_cid, "b3:actual_different");
    }

    #[test]
    fn verify_detects_missing() {
        let mut lock = PolicyLock::new();
        lock.pin("genesis", "b3:gen");
        lock.pin("app/acme", "b3:app");

        let mut loaded = BTreeMap::new();
        loaded.insert("genesis".into(), "b3:gen".into());
        // app/acme is missing from loaded

        let result = lock.verify(&loaded);
        assert!(!result.ok);
        assert_eq!(result.missing, vec!["app/acme"]);
    }

    #[test]
    fn verify_detects_extra() {
        let mut lock = PolicyLock::new();
        lock.pin("genesis", "b3:gen");

        let mut loaded = BTreeMap::new();
        loaded.insert("genesis".into(), "b3:gen".into());
        loaded.insert("tenant/extra".into(), "b3:extra".into());

        let result = lock.verify(&loaded);
        assert!(result.ok); // extra is a warning, not a failure
        assert_eq!(result.extra, vec!["tenant/extra"]);
    }

    #[test]
    fn yaml_roundtrip() {
        let mut lock = PolicyLock::new();
        lock.pin("genesis", "b3:abc123");
        lock.pin("app/acme", "b3:def456");
        lock.pin("tenant/acme-prod", "b3:789abc");

        let yaml = lock.to_yaml();
        let parsed = PolicyLock::from_yaml(&yaml).unwrap();
        assert_eq!(lock, parsed);
    }

    #[test]
    fn parse_yaml_with_comments() {
        let yaml = r#"
# Policy lockfile for UBL
version: 1
policies:
  genesis: b3:genesis_hash
  app/acme: b3:app_hash
  # This is a comment
  tenant/acme-prod: b3:tenant_hash
"#;
        let lock = PolicyLock::from_yaml(yaml).unwrap();
        assert_eq!(lock.policies.len(), 3);
        assert_eq!(lock.policies["genesis"], "b3:genesis_hash");
        assert_eq!(lock.policies["app/acme"], "b3:app_hash");
        assert_eq!(lock.policies["tenant/acme-prod"], "b3:tenant_hash");
    }

    #[test]
    fn reject_unsupported_version() {
        let yaml = "version: 2\npolicies:\n  genesis: b3:abc\n";
        assert!(PolicyLock::from_yaml(yaml).is_err());
    }

    #[test]
    fn display_ok() {
        let result = LockVerification {
            ok: true,
            mismatches: vec![],
            missing: vec![],
            extra: vec![],
        };
        assert_eq!(format!("{}", result), "policy lockfile: OK");
    }

    #[test]
    fn display_drift() {
        let result = LockVerification {
            ok: false,
            mismatches: vec![LockMismatch {
                level: "genesis".into(),
                expected_cid: "b3:expected".into(),
                actual_cid: "b3:actual".into(),
            }],
            missing: vec!["app/acme".into()],
            extra: vec![],
        };
        let s = format!("{}", result);
        assert!(s.contains("DRIFT DETECTED"));
        assert!(s.contains("MISMATCH genesis"));
        assert!(s.contains("MISSING app/acme"));
    }

    #[test]
    fn empty_lockfile_accepts_anything() {
        let lock = PolicyLock::new();
        let mut loaded = BTreeMap::new();
        loaded.insert("genesis".into(), "b3:anything".into());
        let result = lock.verify(&loaded);
        assert!(result.ok); // no pins = no mismatches
        assert_eq!(result.extra, vec!["genesis"]);
    }
}
