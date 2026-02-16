//! Auth as Pipeline — registration, sessions, and permissions are chips.
//!
//! Engineering principle #5: Auth IS the pipeline. No separate auth system.
//! - Registration = `ubl/user` chip
//! - Login = `ubl/token` chip
//! - Permission = policy evaluation at CHECK
//! - Blocking/permitting people = policy on a chip type
//!
//! There is no middleware. Every auth action is a chip that goes through
//! KNOCK→WA→CHECK→TR→WF. The receipt IS the proof of auth.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

// ── User Registration ───────────────────────────────────────────

/// A registered user identity — parsed from a `ubl/user` chip body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserIdentity {
    /// DID of the user (e.g. "did:key:z6Mk...")
    pub did: String,
    /// Human-readable display name
    pub display_name: String,
    /// Roles assigned to this user
    pub roles: Vec<String>,
    /// Whether the user is active
    pub active: bool,
}

/// Errors from user identity parsing.
#[derive(Debug, Clone)]
pub enum AuthError {
    MissingField(String),
    InvalidField(String),
    Unauthorized(String),
    TokenExpired,
    TokenInvalid(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::MissingField(s) => write!(f, "Missing field: {}", s),
            AuthError::InvalidField(s) => write!(f, "Invalid field: {}", s),
            AuthError::Unauthorized(s) => write!(f, "Unauthorized: {}", s),
            AuthError::TokenExpired => write!(f, "Token expired"),
            AuthError::TokenInvalid(s) => write!(f, "Invalid token: {}", s),
        }
    }
}

impl std::error::Error for AuthError {}

impl UserIdentity {
    /// Parse a user identity from a `ubl/user` chip body.
    pub fn from_chip_body(body: &Value) -> Result<Self, AuthError> {
        let did = body.get("did")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::MissingField("did".into()))?
            .to_string();

        if !did.starts_with("did:") {
            return Err(AuthError::InvalidField(format!("DID must start with 'did:': {}", did)));
        }

        let display_name = body.get("display_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::MissingField("display_name".into()))?
            .to_string();

        if display_name.is_empty() {
            return Err(AuthError::InvalidField("display_name cannot be empty".into()));
        }

        let roles = body.get("roles")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_else(|| vec!["user".to_string()]);

        let active = body.get("active")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        Ok(Self { did, display_name, roles, active })
    }

    /// Produce the canonical chip body for this user.
    pub fn to_chip_body(&self, id: &str, world: &str) -> Value {
        json!({
            "@type": "ubl/user",
            "@id": id,
            "@ver": "1.0",
            "@world": world,
            "did": self.did,
            "display_name": self.display_name,
            "roles": self.roles,
            "active": self.active,
        })
    }

    /// Check if this user has a specific role.
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// Check if this user is an admin.
    pub fn is_admin(&self) -> bool {
        self.has_role("admin")
    }
}

// ── Session Token ───────────────────────────────────────────────

/// A session token — parsed from a `ubl/token` chip body.
/// Tokens are chips: they go through the pipeline, get a receipt, and
/// the receipt CID IS the session proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionToken {
    /// DID of the user this token belongs to
    pub user_did: String,
    /// CID of the user chip that created this token
    pub user_cid: String,
    /// Token scope (what this token can do)
    pub scope: Vec<String>,
    /// Expiration timestamp (RFC-3339)
    pub expires_at: String,
    /// Key ID used to sign this token
    pub kid: String,
}

impl SessionToken {
    /// Parse a session token from a `ubl/token` chip body.
    pub fn from_chip_body(body: &Value) -> Result<Self, AuthError> {
        let user_did = body.get("user_did")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::MissingField("user_did".into()))?
            .to_string();

        let user_cid = body.get("user_cid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::MissingField("user_cid".into()))?
            .to_string();

        let scope = body.get("scope")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_else(|| vec!["read".to_string()]);

        let expires_at = body.get("expires_at")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::MissingField("expires_at".into()))?
            .to_string();

        let kid = body.get("kid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::MissingField("kid".into()))?
            .to_string();

        Ok(Self { user_did, user_cid, scope, expires_at, kid })
    }

    /// Produce the canonical chip body for this token.
    pub fn to_chip_body(&self, id: &str, world: &str) -> Value {
        json!({
            "@type": "ubl/token",
            "@id": id,
            "@ver": "1.0",
            "@world": world,
            "user_did": self.user_did,
            "user_cid": self.user_cid,
            "scope": self.scope,
            "expires_at": self.expires_at,
            "kid": self.kid,
        })
    }

    /// Check if the token has expired (compared to `now` RFC-3339 string).
    pub fn is_expired(&self, now: &str) -> bool {
        // Simple string comparison works for RFC-3339 UTC timestamps
        self.expires_at < now.to_string()
    }

    /// Check if the token has a specific scope.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scope.iter().any(|s| s == scope || s == "*")
    }
}

// ── Permission Check (at CHECK stage) ───────────────────────────

/// Permission context extracted from a chip + token for CHECK evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionContext {
    /// DID of the acting user
    pub actor_did: String,
    /// Roles of the acting user
    pub actor_roles: Vec<String>,
    /// Scopes from the session token
    pub token_scopes: Vec<String>,
    /// The chip type being submitted
    pub chip_type: String,
    /// The operation (create, update, delete)
    pub operation: String,
    /// The target world
    pub world: String,
}

impl PermissionContext {
    /// Build a permission context from user + token + chip request.
    pub fn new(
        user: &UserIdentity,
        token: &SessionToken,
        chip_type: &str,
        operation: &str,
        world: &str,
    ) -> Self {
        Self {
            actor_did: user.did.clone(),
            actor_roles: user.roles.clone(),
            token_scopes: token.scope.clone(),
            chip_type: chip_type.to_string(),
            operation: operation.to_string(),
            world: world.to_string(),
        }
    }

    /// Convert to a flat map for RB expression evaluation.
    pub fn to_eval_context(&self) -> std::collections::HashMap<String, String> {
        let mut ctx = std::collections::HashMap::new();
        ctx.insert("actor.did".to_string(), self.actor_did.clone());
        ctx.insert("actor.roles".to_string(), self.actor_roles.join(","));
        ctx.insert("token.scopes".to_string(), self.token_scopes.join(","));
        ctx.insert("chip.@type".to_string(), self.chip_type.clone());
        ctx.insert("chip.operation".to_string(), self.operation.clone());
        ctx.insert("chip.@world".to_string(), self.world.clone());
        ctx
    }

    /// Quick check: does the actor have permission for this operation?
    /// This is a convenience method — the real check happens at CHECK via RBs.
    pub fn quick_check(&self) -> Result<(), AuthError> {
        // Admin can do anything
        if self.actor_roles.contains(&"admin".to_string()) {
            return Ok(());
        }

        // Token must have matching scope
        let required_scope = match self.operation.as_str() {
            "create" => "write",
            "update" => "write",
            "delete" => "admin",
            "read" => "read",
            _ => "write",
        };

        if !self.token_scopes.iter().any(|s| s == required_scope || s == "*") {
            return Err(AuthError::Unauthorized(format!(
                "Token lacks '{}' scope for operation '{}'",
                required_scope, self.operation
            )));
        }

        Ok(())
    }
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_identity_from_chip_body() {
        let body = json!({
            "@type": "ubl/user",
            "@id": "user-001",
            "@ver": "1.0",
            "@world": "a/acme/t/prod",
            "did": "did:key:z6MkTest",
            "display_name": "Alice",
            "roles": ["admin", "user"],
            "active": true,
        });

        let user = UserIdentity::from_chip_body(&body).unwrap();
        assert_eq!(user.did, "did:key:z6MkTest");
        assert_eq!(user.display_name, "Alice");
        assert!(user.has_role("admin"));
        assert!(user.is_admin());
        assert!(user.active);
    }

    #[test]
    fn user_identity_defaults() {
        let body = json!({
            "did": "did:key:z6MkTest",
            "display_name": "Bob",
        });

        let user = UserIdentity::from_chip_body(&body).unwrap();
        assert_eq!(user.roles, vec!["user"]);
        assert!(user.active);
        assert!(!user.is_admin());
    }

    #[test]
    fn user_identity_missing_did_fails() {
        let body = json!({"display_name": "Alice"});
        assert!(UserIdentity::from_chip_body(&body).is_err());
    }

    #[test]
    fn user_identity_invalid_did_fails() {
        let body = json!({"did": "not-a-did", "display_name": "Alice"});
        let err = UserIdentity::from_chip_body(&body).unwrap_err();
        assert!(matches!(err, AuthError::InvalidField(_)));
    }

    #[test]
    fn user_identity_empty_name_fails() {
        let body = json!({"did": "did:key:z6MkTest", "display_name": ""});
        assert!(UserIdentity::from_chip_body(&body).is_err());
    }

    #[test]
    fn user_identity_roundtrip() {
        let user = UserIdentity {
            did: "did:key:z6MkTest".into(),
            display_name: "Alice".into(),
            roles: vec!["admin".into()],
            active: true,
        };

        let body = user.to_chip_body("u1", "a/acme/t/prod");
        assert_eq!(body["@type"], "ubl/user");
        assert_eq!(body["did"], "did:key:z6MkTest");

        let parsed = UserIdentity::from_chip_body(&body).unwrap();
        assert_eq!(parsed.did, user.did);
        assert_eq!(parsed.display_name, user.display_name);
    }

    #[test]
    fn session_token_from_chip_body() {
        let body = json!({
            "@type": "ubl/token",
            "@id": "tok-001",
            "@ver": "1.0",
            "@world": "a/acme/t/prod",
            "user_did": "did:key:z6MkTest",
            "user_cid": "b3:user123",
            "scope": ["read", "write"],
            "expires_at": "2026-12-31T23:59:59Z",
            "kid": "did:key:z6MkTest#v0",
        });

        let token = SessionToken::from_chip_body(&body).unwrap();
        assert_eq!(token.user_did, "did:key:z6MkTest");
        assert_eq!(token.user_cid, "b3:user123");
        assert!(token.has_scope("read"));
        assert!(token.has_scope("write"));
        assert!(!token.has_scope("admin"));
        assert!(!token.is_expired("2026-06-15T00:00:00Z"));
        assert!(token.is_expired("2027-01-01T00:00:00Z"));
    }

    #[test]
    fn session_token_missing_fields_fail() {
        let body = json!({"user_did": "did:key:x"});
        assert!(SessionToken::from_chip_body(&body).is_err());
    }

    #[test]
    fn session_token_roundtrip() {
        let token = SessionToken {
            user_did: "did:key:z6MkTest".into(),
            user_cid: "b3:user123".into(),
            scope: vec!["read".into(), "write".into()],
            expires_at: "2026-12-31T23:59:59Z".into(),
            kid: "did:key:z6MkTest#v0".into(),
        };

        let body = token.to_chip_body("t1", "a/acme/t/prod");
        assert_eq!(body["@type"], "ubl/token");

        let parsed = SessionToken::from_chip_body(&body).unwrap();
        assert_eq!(parsed.user_did, token.user_did);
        assert_eq!(parsed.scope, token.scope);
    }

    #[test]
    fn wildcard_scope_grants_everything() {
        let body = json!({
            "user_did": "did:key:x",
            "user_cid": "b3:u",
            "scope": ["*"],
            "expires_at": "2099-01-01T00:00:00Z",
            "kid": "did:key:x#v0",
        });

        let token = SessionToken::from_chip_body(&body).unwrap();
        assert!(token.has_scope("read"));
        assert!(token.has_scope("write"));
        assert!(token.has_scope("admin"));
        assert!(token.has_scope("anything"));
    }

    #[test]
    fn permission_context_quick_check_admin() {
        let user = UserIdentity {
            did: "did:key:admin".into(),
            display_name: "Admin".into(),
            roles: vec!["admin".into()],
            active: true,
        };
        let token = SessionToken {
            user_did: "did:key:admin".into(),
            user_cid: "b3:u".into(),
            scope: vec!["read".into()], // even with limited scope
            expires_at: "2099-01-01T00:00:00Z".into(),
            kid: "did:key:admin#v0".into(),
        };

        let ctx = PermissionContext::new(&user, &token, "ubl/user", "delete", "a/x/t/y");
        assert!(ctx.quick_check().is_ok()); // admin bypasses scope check
    }

    #[test]
    fn permission_context_quick_check_insufficient_scope() {
        let user = UserIdentity {
            did: "did:key:user".into(),
            display_name: "User".into(),
            roles: vec!["user".into()],
            active: true,
        };
        let token = SessionToken {
            user_did: "did:key:user".into(),
            user_cid: "b3:u".into(),
            scope: vec!["read".into()],
            expires_at: "2099-01-01T00:00:00Z".into(),
            kid: "did:key:user#v0".into(),
        };

        let ctx = PermissionContext::new(&user, &token, "ubl/user", "create", "a/x/t/y");
        assert!(ctx.quick_check().is_err()); // read scope can't create
    }

    #[test]
    fn permission_context_to_eval_context() {
        let user = UserIdentity {
            did: "did:key:z6Mk".into(),
            display_name: "Alice".into(),
            roles: vec!["user".into(), "editor".into()],
            active: true,
        };
        let token = SessionToken {
            user_did: "did:key:z6Mk".into(),
            user_cid: "b3:u".into(),
            scope: vec!["read".into(), "write".into()],
            expires_at: "2099-01-01T00:00:00Z".into(),
            kid: "did:key:z6Mk#v0".into(),
        };

        let ctx = PermissionContext::new(&user, &token, "ubl/user", "create", "a/acme/t/prod");
        let eval = ctx.to_eval_context();
        assert_eq!(eval["actor.did"], "did:key:z6Mk");
        assert_eq!(eval["actor.roles"], "user,editor");
        assert_eq!(eval["token.scopes"], "read,write");
        assert_eq!(eval["chip.@type"], "ubl/user");
        assert_eq!(eval["chip.operation"], "create");
    }
}
