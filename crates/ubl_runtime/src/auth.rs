//! Onboarding — the dependency chain for first-time entities.
//!
//! Everything is a chip. The onboarding order is:
//!   1. `ubl/app`        — defines an application scope
//!   2. `ubl/user`       — registers a human identity under an app
//!   3. `ubl/tenant`     — creates a Circle (personal/group/company)
//!   4. `ubl/membership` — links user → tenant with role (admin | member)
//!   5. `ubl/token`      — creates a session for an existing user
//!   6. `ubl/revoke`     — append-only suspension of any entity
//!
//! The chip body IS the onboarding data. It never mutates.
//! The receipt chain is what gives it authority:
//!   - chip exists + allow receipt = active
//!   - chip exists + revoke receipt = suspended
//!   - no chip = doesn't exist
//!
//! Roles are intentionally simple: admin and member.
//!   - admin: change Circle rules, invite/remove members, manage policies
//!   - member: submit chips, read own data, read shared Circle data
//!   - neither can delete anything — append-only ledger, always
//!
//! Engineering principle #5: Auth IS the pipeline. No middleware.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;

// ── Errors ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum AuthError {
    MissingField(String),
    InvalidField(String),
    Unauthorized(String),
    DependencyMissing(String),
    TokenExpired,
    TokenInvalid(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::MissingField(s) => write!(f, "Missing field: {}", s),
            AuthError::InvalidField(s) => write!(f, "Invalid field: {}", s),
            AuthError::Unauthorized(s) => write!(f, "Unauthorized: {}", s),
            AuthError::DependencyMissing(s) => write!(f, "Dependency missing: {}", s),
            AuthError::TokenExpired => write!(f, "Token expired"),
            AuthError::TokenInvalid(s) => write!(f, "Invalid token: {}", s),
        }
    }
}

impl std::error::Error for AuthError {}

// ── Role ────────────────────────────────────────────────────────

/// Two roles. That's it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Member,
}

impl Role {
    pub fn parse(s: &str) -> Result<Self, AuthError> {
        s.parse()
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Member => "member",
        }
    }
}

impl std::str::FromStr for Role {
    type Err = AuthError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "admin" => Ok(Role::Admin),
            "member" => Ok(Role::Member),
            other => Err(AuthError::InvalidField(format!(
                "Role must be 'admin' or 'member', got '{}'",
                other
            ))),
        }
    }
}

// ── 1. App Registration ─────────────────────────────────────────

/// An application scope — the first thing that must exist.
/// Defines `a/{slug}` in `@world`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRegistration {
    /// URL-safe slug (e.g. "acme", "lab512")
    pub slug: String,
    /// Human-readable name
    pub display_name: String,
    /// DID of the app owner
    pub owner_did: String,
}

impl AppRegistration {
    pub fn from_chip_body(body: &Value) -> Result<Self, AuthError> {
        let slug = body
            .get("slug")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::MissingField("slug".into()))?
            .to_string();

        if slug.is_empty() || slug.contains('/') || slug.contains(' ') {
            return Err(AuthError::InvalidField(format!(
                "slug must be non-empty, no spaces or slashes: '{}'",
                slug
            )));
        }

        let display_name = body
            .get("display_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::MissingField("display_name".into()))?
            .to_string();

        if display_name.is_empty() {
            return Err(AuthError::InvalidField(
                "display_name cannot be empty".into(),
            ));
        }

        let owner_did = body
            .get("owner_did")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::MissingField("owner_did".into()))?
            .to_string();

        if !owner_did.starts_with("did:") {
            return Err(AuthError::InvalidField(format!(
                "owner_did must start with 'did:': '{}'",
                owner_did
            )));
        }

        Ok(Self {
            slug,
            display_name,
            owner_did,
        })
    }

    pub fn to_chip_body(&self, id: &str) -> Value {
        json!({
            "@type": "ubl/app",
            "@id": id,
            "@ver": "1.0",
            "@world": format!("a/{}", self.slug),
            "slug": self.slug,
            "display_name": self.display_name,
            "owner_did": self.owner_did,
        })
    }

    /// The @world prefix this app defines.
    pub fn world_prefix(&self) -> String {
        format!("a/{}", self.slug)
    }
}

// ── 2. User Identity ────────────────────────────────────────────

/// A registered user identity — parsed from a `ubl/user` chip body.
/// The chip's @world must reference an existing app.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserIdentity {
    /// DID of the user (e.g. "did:key:z6Mk...")
    pub did: String,
    /// Human-readable display name
    pub display_name: String,
}

impl UserIdentity {
    pub fn from_chip_body(body: &Value) -> Result<Self, AuthError> {
        let did = body
            .get("did")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::MissingField("did".into()))?
            .to_string();

        if !did.starts_with("did:") {
            return Err(AuthError::InvalidField(format!(
                "DID must start with 'did:': '{}'",
                did
            )));
        }

        let display_name = body
            .get("display_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::MissingField("display_name".into()))?
            .to_string();

        if display_name.is_empty() {
            return Err(AuthError::InvalidField(
                "display_name cannot be empty".into(),
            ));
        }

        Ok(Self { did, display_name })
    }

    pub fn to_chip_body(&self, id: &str, world: &str) -> Value {
        json!({
            "@type": "ubl/user",
            "@id": id,
            "@ver": "1.0",
            "@world": world,
            "did": self.did,
            "display_name": self.display_name,
        })
    }
}

// ── 3. Tenant / Circle ──────────────────────────────────────────

/// A tenant (publicly: Circle). Personal project, group, or company.
/// Defines `a/{app}/t/{slug}` in `@world`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantCircle {
    /// URL-safe slug (e.g. "prod", "personal", "engineering")
    pub slug: String,
    /// Human-readable name
    pub display_name: String,
    /// CID of the user chip that created this Circle
    pub creator_cid: String,
}

impl TenantCircle {
    pub fn from_chip_body(body: &Value) -> Result<Self, AuthError> {
        let slug = body
            .get("slug")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::MissingField("slug".into()))?
            .to_string();

        if slug.is_empty() || slug.contains('/') || slug.contains(' ') {
            return Err(AuthError::InvalidField(format!(
                "slug must be non-empty, no spaces or slashes: '{}'",
                slug
            )));
        }

        let display_name = body
            .get("display_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::MissingField("display_name".into()))?
            .to_string();

        if display_name.is_empty() {
            return Err(AuthError::InvalidField(
                "display_name cannot be empty".into(),
            ));
        }

        let creator_cid = body
            .get("creator_cid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::MissingField("creator_cid".into()))?
            .to_string();

        if !creator_cid.starts_with("b3:") {
            return Err(AuthError::InvalidField(format!(
                "creator_cid must start with 'b3:': '{}'",
                creator_cid
            )));
        }

        Ok(Self {
            slug,
            display_name,
            creator_cid,
        })
    }

    pub fn to_chip_body(&self, id: &str, world: &str) -> Value {
        json!({
            "@type": "ubl/tenant",
            "@id": id,
            "@ver": "1.0",
            "@world": world,
            "slug": self.slug,
            "display_name": self.display_name,
            "creator_cid": self.creator_cid,
        })
    }
}

// ── 4. Membership ───────────────────────────────────────────────

/// Links a user to a tenant with a role.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Membership {
    /// CID of the user chip
    pub user_cid: String,
    /// CID of the tenant chip
    pub tenant_cid: String,
    /// Role: admin or member
    pub role: Role,
}

impl Membership {
    pub fn from_chip_body(body: &Value) -> Result<Self, AuthError> {
        let user_cid = body
            .get("user_cid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::MissingField("user_cid".into()))?
            .to_string();

        if !user_cid.starts_with("b3:") {
            return Err(AuthError::InvalidField(format!(
                "user_cid must start with 'b3:': '{}'",
                user_cid
            )));
        }

        let tenant_cid = body
            .get("tenant_cid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::MissingField("tenant_cid".into()))?
            .to_string();

        if !tenant_cid.starts_with("b3:") {
            return Err(AuthError::InvalidField(format!(
                "tenant_cid must start with 'b3:': '{}'",
                tenant_cid
            )));
        }

        let role_str = body
            .get("role")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::MissingField("role".into()))?;

        let role = Role::parse(role_str)?;

        Ok(Self {
            user_cid,
            tenant_cid,
            role,
        })
    }

    pub fn to_chip_body(&self, id: &str, world: &str) -> Value {
        json!({
            "@type": "ubl/membership",
            "@id": id,
            "@ver": "1.0",
            "@world": world,
            "user_cid": self.user_cid,
            "tenant_cid": self.tenant_cid,
            "role": self.role.as_str(),
        })
    }
}

// ── 5. Session Token ────────────────────────────────────────────

/// A session token — parsed from a `ubl/token` chip body.
/// The receipt CID IS the session proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionToken {
    /// CID of the user chip this token belongs to
    pub user_cid: String,
    /// Token scope (what this token can do)
    pub scope: Vec<String>,
    /// Expiration timestamp (RFC-3339)
    pub expires_at: String,
    /// Key ID used to sign this token
    pub kid: String,
}

impl SessionToken {
    pub fn from_chip_body(body: &Value) -> Result<Self, AuthError> {
        let user_cid = body
            .get("user_cid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::MissingField("user_cid".into()))?
            .to_string();

        if !user_cid.starts_with("b3:") {
            return Err(AuthError::InvalidField(format!(
                "user_cid must start with 'b3:': '{}'",
                user_cid
            )));
        }

        let scope = body
            .get("scope")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_else(|| vec!["read".to_string()]);

        let expires_at = body
            .get("expires_at")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::MissingField("expires_at".into()))?
            .to_string();

        let kid = body
            .get("kid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::MissingField("kid".into()))?
            .to_string();

        Ok(Self {
            user_cid,
            scope,
            expires_at,
            kid,
        })
    }

    pub fn to_chip_body(&self, id: &str, world: &str) -> Value {
        json!({
            "@type": "ubl/token",
            "@id": id,
            "@ver": "1.0",
            "@world": world,
            "user_cid": self.user_cid,
            "scope": self.scope,
            "expires_at": self.expires_at,
            "kid": self.kid,
        })
    }

    pub fn is_expired(&self, now: &str) -> bool {
        self.expires_at.as_str() < now
    }

    pub fn has_scope(&self, scope: &str) -> bool {
        self.scope.iter().any(|s| s == scope || s == "*")
    }
}

// ── 6. Revocation ───────────────────────────────────────────────

/// Append-only suspension of any entity. Nothing is deleted.
/// A revoke chip targets another chip by CID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Revocation {
    /// CID of the chip being revoked
    pub target_cid: String,
    /// Reason for revocation
    pub reason: String,
    /// CID of the actor (user chip) performing the revocation
    pub actor_cid: String,
}

impl Revocation {
    pub fn from_chip_body(body: &Value) -> Result<Self, AuthError> {
        let target_cid = body
            .get("target_cid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::MissingField("target_cid".into()))?
            .to_string();

        if !target_cid.starts_with("b3:") {
            return Err(AuthError::InvalidField(format!(
                "target_cid must start with 'b3:': '{}'",
                target_cid
            )));
        }

        let reason = body
            .get("reason")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::MissingField("reason".into()))?
            .to_string();

        if reason.is_empty() {
            return Err(AuthError::InvalidField("reason cannot be empty".into()));
        }

        let actor_cid = body
            .get("actor_cid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::MissingField("actor_cid".into()))?
            .to_string();

        if !actor_cid.starts_with("b3:") {
            return Err(AuthError::InvalidField(format!(
                "actor_cid must start with 'b3:': '{}'",
                actor_cid
            )));
        }

        Ok(Self {
            target_cid,
            reason,
            actor_cid,
        })
    }

    pub fn to_chip_body(&self, id: &str, world: &str) -> Value {
        json!({
            "@type": "ubl/revoke",
            "@id": id,
            "@ver": "1.0",
            "@world": world,
            "target_cid": self.target_cid,
            "reason": self.reason,
            "actor_cid": self.actor_cid,
        })
    }
}

// ── @world Parsing ──────────────────────────────────────────────

/// Parse a `@world` string into its app and optional tenant components.
/// Format: `a/{app}` or `a/{app}/t/{tenant}`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorldScope {
    pub app: String,
    pub tenant: Option<String>,
}

impl WorldScope {
    pub fn parse(world: &str) -> Result<Self, AuthError> {
        let parts: Vec<&str> = world.split('/').collect();

        if parts.len() < 2 || parts[0] != "a" {
            return Err(AuthError::InvalidField(format!(
                "@world must start with 'a/{{app}}': '{}'",
                world
            )));
        }

        let app = parts[1].to_string();
        if app.is_empty() {
            return Err(AuthError::InvalidField("app slug cannot be empty".into()));
        }

        let tenant = if parts.len() >= 4 && parts[2] == "t" {
            let t = parts[3].to_string();
            if t.is_empty() {
                return Err(AuthError::InvalidField(
                    "tenant slug cannot be empty".into(),
                ));
            }
            Some(t)
        } else if parts.len() == 2 {
            None
        } else {
            return Err(AuthError::InvalidField(format!(
                "@world format must be 'a/{{app}}' or 'a/{{app}}/t/{{tenant}}': '{}'",
                world
            )));
        };

        Ok(Self { app, tenant })
    }

    pub fn app_world(&self) -> String {
        format!("a/{}", self.app)
    }
}

impl std::fmt::Display for WorldScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.tenant {
            Some(t) => write!(f, "a/{}/t/{}", self.app, t),
            None => write!(f, "a/{}", self.app),
        }
    }
}

// ── Permission Context ──────────────────────────────────────────

/// Permission context for CHECK stage RB evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionContext {
    pub actor_did: String,
    pub actor_role: Role,
    pub token_scopes: Vec<String>,
    pub chip_type: String,
    pub world: String,
}

impl PermissionContext {
    pub fn to_eval_context(&self) -> std::collections::HashMap<String, String> {
        let mut ctx = std::collections::HashMap::new();
        ctx.insert("actor.did".to_string(), self.actor_did.clone());
        ctx.insert(
            "actor.role".to_string(),
            self.actor_role.as_str().to_string(),
        );
        ctx.insert("token.scopes".to_string(), self.token_scopes.join(","));
        ctx.insert("chip.@type".to_string(), self.chip_type.clone());
        ctx.insert("chip.@world".to_string(), self.world.clone());
        ctx
    }

    /// Quick permission check. Real enforcement is at CHECK via RBs.
    pub fn quick_check(&self) -> Result<(), AuthError> {
        if self.actor_role == Role::Admin {
            return Ok(());
        }

        // Members can read and write, but not admin-level operations
        let needs_admin = self.chip_type == "ubl/revoke" || self.chip_type == "ubl/membership";

        if needs_admin {
            return Err(AuthError::Unauthorized(format!(
                "'{}' requires admin role",
                self.chip_type
            )));
        }

        Ok(())
    }
}

// ── Onboarding Chip Type Registry ───────────────────────────────

/// All onboarding chip types in dependency order.
pub const ONBOARDING_TYPES: &[&str] = &[
    "ubl/app",
    "ubl/user",
    "ubl/tenant",
    "ubl/membership",
    "ubl/token",
    "ubl/revoke",
];

/// Check if a chip type is an onboarding type.
pub fn is_onboarding_type(chip_type: &str) -> bool {
    ONBOARDING_TYPES.contains(&chip_type)
}

/// Strongly-typed onboarding chip payloads.
#[derive(Debug, Clone)]
pub enum OnboardingChip {
    App(AppRegistration),
    User(UserIdentity),
    Tenant(TenantCircle),
    Membership(Membership),
    Token(SessionToken),
    Revoke(Revocation),
}

/// Parse onboarding chip payload into a typed structure.
pub fn parse_onboarding_chip(body: &Value) -> Result<Option<OnboardingChip>, AuthError> {
    let chip_type = body
        .get("@type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::MissingField("@type".into()))?;

    let parsed = match chip_type {
        "ubl/app" => Some(OnboardingChip::App(AppRegistration::from_chip_body(body)?)),
        "ubl/user" => Some(OnboardingChip::User(UserIdentity::from_chip_body(body)?)),
        "ubl/tenant" => Some(OnboardingChip::Tenant(TenantCircle::from_chip_body(body)?)),
        "ubl/membership" => Some(OnboardingChip::Membership(Membership::from_chip_body(
            body,
        )?)),
        "ubl/token" => Some(OnboardingChip::Token(SessionToken::from_chip_body(body)?)),
        "ubl/revoke" => Some(OnboardingChip::Revoke(Revocation::from_chip_body(body)?)),
        _ => None,
    };

    Ok(parsed)
}

/// Validate an onboarding chip body based on its @type.
pub fn validate_onboarding_chip(body: &Value) -> Result<(), AuthError> {
    let _ = parse_onboarding_chip(body)?;
    Ok(())
}

// ── Auth Engine ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AuthEngine;

#[derive(Debug, Clone)]
pub enum AuthValidationError {
    InvalidChip(String),
    DependencyMissing(String),
    Internal(String),
}

impl std::fmt::Display for AuthValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthValidationError::InvalidChip(s) => write!(f, "{}", s),
            AuthValidationError::DependencyMissing(s) => write!(f, "{}", s),
            AuthValidationError::Internal(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for AuthValidationError {}

impl AuthEngine {
    pub fn new() -> Self {
        Self
    }

    pub async fn validate_onboarding_dependencies(
        &self,
        onboarding: &OnboardingChip,
        body: &Value,
        world: &str,
        store: &Arc<ubl_chipstore::ChipStore>,
    ) -> Result<(), AuthValidationError> {
        match onboarding {
            // App is the root — no dependencies, but slug must be unique.
            // Requires cap.registry:init (P0.3).
            OnboardingChip::App(app) => {
                crate::capability::require_cap(body, "registry:init", world).map_err(|e| {
                    AuthValidationError::InvalidChip(format!("ubl/app capability: {}", e))
                })?;
                let existing = store
                    .query(&ubl_chipstore::ChipQuery {
                        chip_type: Some("ubl/app".to_string()),
                        tags: vec![format!("slug:{}", app.slug)],
                        created_after: None,
                        created_before: None,
                        executor_did: None,
                        limit: None,
                        offset: None,
                    })
                    .await
                    .map_err(|e| {
                        AuthValidationError::Internal(format!("ChipStore query: {}", e))
                    })?;
                for chip in &existing.chips {
                    if chip.chip_data.get("slug").and_then(|v| v.as_str())
                        == Some(app.slug.as_str())
                    {
                        // Check if this app has been revoked.
                        if !self.is_revoked(chip.cid.as_str(), store).await? {
                            return Err(AuthValidationError::InvalidChip(format!(
                                "App slug '{}' already registered",
                                app.slug
                            )));
                        }
                    }
                }
            }

            // User requires a valid app in @world.
            // First user for an app requires cap.registry:init (P0.3).
            OnboardingChip::User(_) => {
                let scope = WorldScope::parse(world)
                    .map_err(|e| AuthValidationError::InvalidChip(format!("@world: {}", e)))?;
                self.require_app_exists(&scope.app, store).await?;

                // Check if this is the first user for this app.
                let existing_users = store
                    .query(&ubl_chipstore::ChipQuery {
                        chip_type: Some("ubl/user".to_string()),
                        tags: vec![format!("app:{}", scope.app)],
                        created_after: None,
                        created_before: None,
                        executor_did: None,
                        limit: Some(1),
                        offset: None,
                    })
                    .await
                    .map_err(|e| {
                        AuthValidationError::Internal(format!("ChipStore query: {}", e))
                    })?;
                let has_user_for_app = !existing_users.chips.is_empty();
                if !has_user_for_app {
                    crate::capability::require_cap(body, "registry:init", world).map_err(|e| {
                        AuthValidationError::InvalidChip(format!(
                            "first ubl/user for app '{}' requires capability: {}",
                            scope.app, e
                        ))
                    })?;
                }
            }

            // Tenant requires: app exists + creator_cid references a valid user.
            OnboardingChip::Tenant(tenant) => {
                let scope = WorldScope::parse(world)
                    .map_err(|e| AuthValidationError::InvalidChip(format!("@world: {}", e)))?;
                self.require_app_exists(&scope.app, store).await?;
                self.require_chip_exists(&tenant.creator_cid, "ubl/user", store)
                    .await?;
            }

            // Membership requires: user_cid and tenant_cid both exist.
            // Requires cap.membership:grant (P0.4).
            OnboardingChip::Membership(membership) => {
                crate::capability::require_cap(body, "membership:grant", world).map_err(|e| {
                    AuthValidationError::InvalidChip(format!("ubl/membership capability: {}", e))
                })?;
                self.require_chip_exists(&membership.user_cid, "ubl/user", store)
                    .await?;
                self.require_chip_exists(&membership.tenant_cid, "ubl/tenant", store)
                    .await?;
            }

            // Token requires: user_cid exists.
            OnboardingChip::Token(token) => {
                self.require_chip_exists(&token.user_cid, "ubl/user", store)
                    .await?;
            }

            // Revoke requires: target_cid exists (any type) + actor_cid exists.
            // Requires cap.revoke:execute (P0.4).
            OnboardingChip::Revoke(revoke) => {
                crate::capability::require_cap(body, "revoke:execute", world).map_err(|e| {
                    AuthValidationError::InvalidChip(format!("ubl/revoke capability: {}", e))
                })?;
                if !store
                    .exists(&revoke.target_cid)
                    .await
                    .map_err(|e| AuthValidationError::Internal(format!("ChipStore: {}", e)))?
                {
                    return Err(AuthValidationError::DependencyMissing(format!(
                        "Revoke target '{}' not found",
                        revoke.target_cid
                    )));
                }
                self.require_chip_exists(&revoke.actor_cid, "ubl/user", store)
                    .await?;
            }
        }

        Ok(())
    }

    async fn require_app_exists(
        &self,
        app_slug: &str,
        store: &Arc<ubl_chipstore::ChipStore>,
    ) -> Result<(), AuthValidationError> {
        let apps = store
            .query(&ubl_chipstore::ChipQuery {
                chip_type: Some("ubl/app".to_string()),
                tags: vec![format!("slug:{}", app_slug)],
                created_after: None,
                created_before: None,
                executor_did: None,
                limit: None,
                offset: None,
            })
            .await
            .map_err(|e| AuthValidationError::Internal(format!("ChipStore: {}", e)))?;

        for chip in &apps.chips {
            if chip.chip_data.get("slug").and_then(|v| v.as_str()) == Some(app_slug)
                && !self.is_revoked(chip.cid.as_str(), store).await?
            {
                return Ok(());
            }
        }

        Err(AuthValidationError::DependencyMissing(format!(
            "App '{}' not found — register ubl/app first",
            app_slug
        )))
    }

    async fn require_chip_exists(
        &self,
        cid: &str,
        expected_type: &str,
        store: &Arc<ubl_chipstore::ChipStore>,
    ) -> Result<(), AuthValidationError> {
        let chip = store
            .get_chip(cid)
            .await
            .map_err(|e| AuthValidationError::Internal(format!("ChipStore: {}", e)))?
            .ok_or_else(|| {
                AuthValidationError::DependencyMissing(format!(
                    "{} '{}' not found",
                    expected_type, cid
                ))
            })?;

        if chip.chip_type != expected_type {
            return Err(AuthValidationError::InvalidChip(format!(
                "CID '{}' is '{}', expected '{}'",
                cid, chip.chip_type, expected_type,
            )));
        }

        if self.is_revoked(cid, store).await? {
            return Err(AuthValidationError::DependencyMissing(format!(
                "{} '{}' has been revoked",
                expected_type, cid,
            )));
        }

        Ok(())
    }

    async fn is_revoked(
        &self,
        target_cid: &str,
        store: &Arc<ubl_chipstore::ChipStore>,
    ) -> Result<bool, AuthValidationError> {
        let revocations = store
            .query(&ubl_chipstore::ChipQuery {
                chip_type: Some("ubl/revoke".to_string()),
                tags: vec![format!("target_cid:{}", target_cid)],
                created_after: None,
                created_before: None,
                executor_did: None,
                limit: Some(1),
                offset: None,
            })
            .await
            .map_err(|e| AuthValidationError::Internal(format!("ChipStore: {}", e)))?;

        Ok(!revocations.chips.is_empty())
    }
}

impl Default for AuthEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── App ─────────────────────────────────────────────────────

    #[test]
    fn app_registration_parse() {
        let body = json!({
            "@type": "ubl/app",
            "@id": "app-001",
            "@ver": "1.0",
            "@world": "a/acme",
            "slug": "acme",
            "display_name": "Acme Corp",
            "owner_did": "did:key:z6MkOwner",
        });

        let app = AppRegistration::from_chip_body(&body).unwrap();
        assert_eq!(app.slug, "acme");
        assert_eq!(app.world_prefix(), "a/acme");
    }

    #[test]
    fn app_slug_no_slashes() {
        let body = json!({"slug": "a/b", "display_name": "X", "owner_did": "did:key:z"});
        assert!(AppRegistration::from_chip_body(&body).is_err());
    }

    #[test]
    fn app_slug_no_spaces() {
        let body = json!({"slug": "my app", "display_name": "X", "owner_did": "did:key:z"});
        assert!(AppRegistration::from_chip_body(&body).is_err());
    }

    #[test]
    fn app_roundtrip() {
        let app = AppRegistration {
            slug: "lab512".into(),
            display_name: "Lab 512".into(),
            owner_did: "did:key:z6MkOwner".into(),
        };
        let body = app.to_chip_body("a1");
        assert_eq!(body["@type"], "ubl/app");
        assert_eq!(body["@world"], "a/lab512");
        let parsed = AppRegistration::from_chip_body(&body).unwrap();
        assert_eq!(parsed.slug, "lab512");
    }

    // ── User ────────────────────────────────────────────────────

    #[test]
    fn user_identity_parse() {
        let body = json!({
            "@type": "ubl/user",
            "@world": "a/acme",
            "did": "did:key:z6MkAlice",
            "display_name": "Alice",
        });
        let user = UserIdentity::from_chip_body(&body).unwrap();
        assert_eq!(user.did, "did:key:z6MkAlice");
    }

    #[test]
    fn user_missing_did_fails() {
        let body = json!({"display_name": "Alice"});
        assert!(UserIdentity::from_chip_body(&body).is_err());
    }

    #[test]
    fn user_invalid_did_fails() {
        let body = json!({"did": "not-a-did", "display_name": "Alice"});
        assert!(matches!(
            UserIdentity::from_chip_body(&body).unwrap_err(),
            AuthError::InvalidField(_)
        ));
    }

    #[test]
    fn user_empty_name_fails() {
        let body = json!({"did": "did:key:z6Mk", "display_name": ""});
        assert!(UserIdentity::from_chip_body(&body).is_err());
    }

    #[test]
    fn user_roundtrip() {
        let user = UserIdentity {
            did: "did:key:z6MkAlice".into(),
            display_name: "Alice".into(),
        };
        let body = user.to_chip_body("u1", "a/acme");
        assert_eq!(body["@type"], "ubl/user");
        let parsed = UserIdentity::from_chip_body(&body).unwrap();
        assert_eq!(parsed.did, user.did);
    }

    // ── Tenant / Circle ─────────────────────────────────────────

    #[test]
    fn tenant_parse() {
        let body = json!({
            "@type": "ubl/tenant",
            "@world": "a/acme",
            "slug": "engineering",
            "display_name": "Engineering Circle",
            "creator_cid": "b3:user123",
        });
        let tenant = TenantCircle::from_chip_body(&body).unwrap();
        assert_eq!(tenant.slug, "engineering");
        assert_eq!(tenant.creator_cid, "b3:user123");
    }

    #[test]
    fn tenant_bad_creator_cid() {
        let body = json!({
            "slug": "eng", "display_name": "Eng", "creator_cid": "not-a-cid",
        });
        assert!(TenantCircle::from_chip_body(&body).is_err());
    }

    #[test]
    fn tenant_roundtrip() {
        let t = TenantCircle {
            slug: "prod".into(),
            display_name: "Production".into(),
            creator_cid: "b3:user123".into(),
        };
        let body = t.to_chip_body("t1", "a/acme");
        assert_eq!(body["@type"], "ubl/tenant");
        let parsed = TenantCircle::from_chip_body(&body).unwrap();
        assert_eq!(parsed.slug, "prod");
    }

    // ── Membership ──────────────────────────────────────────────

    #[test]
    fn membership_parse() {
        let body = json!({
            "@type": "ubl/membership",
            "@world": "a/acme/t/prod",
            "user_cid": "b3:user123",
            "tenant_cid": "b3:tenant456",
            "role": "admin",
        });
        let m = Membership::from_chip_body(&body).unwrap();
        assert_eq!(m.role, Role::Admin);
    }

    #[test]
    fn membership_invalid_role() {
        let body = json!({
            "user_cid": "b3:u", "tenant_cid": "b3:t", "role": "superadmin",
        });
        assert!(Membership::from_chip_body(&body).is_err());
    }

    #[test]
    fn membership_roundtrip() {
        let m = Membership {
            user_cid: "b3:user123".into(),
            tenant_cid: "b3:tenant456".into(),
            role: Role::Member,
        };
        let body = m.to_chip_body("m1", "a/acme/t/prod");
        assert_eq!(body["role"], "member");
        let parsed = Membership::from_chip_body(&body).unwrap();
        assert_eq!(parsed.role, Role::Member);
    }

    // ── Token ───────────────────────────────────────────────────

    #[test]
    fn token_parse() {
        let body = json!({
            "@type": "ubl/token",
            "@world": "a/acme",
            "user_cid": "b3:user123",
            "scope": ["read", "write"],
            "expires_at": "2026-12-31T23:59:59Z",
            "kid": "did:key:z6Mk#v0",
        });
        let token = SessionToken::from_chip_body(&body).unwrap();
        assert!(token.has_scope("read"));
        assert!(token.has_scope("write"));
        assert!(!token.has_scope("admin"));
        assert!(!token.is_expired("2026-06-15T00:00:00Z"));
        assert!(token.is_expired("2027-01-01T00:00:00Z"));
    }

    #[test]
    fn token_missing_fields() {
        let body = json!({"user_cid": "b3:u"});
        assert!(SessionToken::from_chip_body(&body).is_err());
    }

    #[test]
    fn token_wildcard_scope() {
        let body = json!({
            "user_cid": "b3:u",
            "scope": ["*"],
            "expires_at": "2099-01-01T00:00:00Z",
            "kid": "did:key:x#v0",
        });
        let token = SessionToken::from_chip_body(&body).unwrap();
        assert!(token.has_scope("anything"));
    }

    #[test]
    fn token_roundtrip() {
        let token = SessionToken {
            user_cid: "b3:user123".into(),
            scope: vec!["read".into(), "write".into()],
            expires_at: "2026-12-31T23:59:59Z".into(),
            kid: "did:key:z6Mk#v0".into(),
        };
        let body = token.to_chip_body("t1", "a/acme");
        assert_eq!(body["@type"], "ubl/token");
        let parsed = SessionToken::from_chip_body(&body).unwrap();
        assert_eq!(parsed.user_cid, "b3:user123");
    }

    // ── Revocation ──────────────────────────────────────────────

    #[test]
    fn revocation_parse() {
        let body = json!({
            "@type": "ubl/revoke",
            "@world": "a/acme/t/prod",
            "target_cid": "b3:target789",
            "reason": "Policy violation",
            "actor_cid": "b3:admin001",
        });
        let r = Revocation::from_chip_body(&body).unwrap();
        assert_eq!(r.target_cid, "b3:target789");
    }

    #[test]
    fn revocation_empty_reason_fails() {
        let body = json!({
            "target_cid": "b3:t", "reason": "", "actor_cid": "b3:a",
        });
        assert!(Revocation::from_chip_body(&body).is_err());
    }

    #[test]
    fn revocation_roundtrip() {
        let r = Revocation {
            target_cid: "b3:target789".into(),
            reason: "Suspended by admin".into(),
            actor_cid: "b3:admin001".into(),
        };
        let body = r.to_chip_body("r1", "a/acme/t/prod");
        assert_eq!(body["@type"], "ubl/revoke");
        let parsed = Revocation::from_chip_body(&body).unwrap();
        assert_eq!(parsed.reason, "Suspended by admin");
    }

    // ── WorldScope ──────────────────────────────────────────────

    #[test]
    fn world_scope_app_only() {
        let w = WorldScope::parse("a/acme").unwrap();
        assert_eq!(w.app, "acme");
        assert_eq!(w.tenant, None);
        assert_eq!(w.to_string(), "a/acme");
    }

    #[test]
    fn world_scope_app_and_tenant() {
        let w = WorldScope::parse("a/acme/t/prod").unwrap();
        assert_eq!(w.app, "acme");
        assert_eq!(w.tenant, Some("prod".into()));
        assert_eq!(w.app_world(), "a/acme");
    }

    #[test]
    fn world_scope_invalid() {
        assert!(WorldScope::parse("invalid").is_err());
        assert!(WorldScope::parse("b/acme").is_err());
        assert!(WorldScope::parse("a/").is_err());
    }

    // ── Permission Context ──────────────────────────────────────

    #[test]
    fn admin_can_do_anything() {
        let ctx = PermissionContext {
            actor_did: "did:key:admin".into(),
            actor_role: Role::Admin,
            token_scopes: vec!["read".into()],
            chip_type: "ubl/revoke".into(),
            world: "a/acme/t/prod".into(),
        };
        assert!(ctx.quick_check().is_ok());
    }

    #[test]
    fn member_cannot_revoke() {
        let ctx = PermissionContext {
            actor_did: "did:key:user".into(),
            actor_role: Role::Member,
            token_scopes: vec!["read".into(), "write".into()],
            chip_type: "ubl/revoke".into(),
            world: "a/acme/t/prod".into(),
        };
        assert!(ctx.quick_check().is_err());
    }

    #[test]
    fn member_cannot_manage_membership() {
        let ctx = PermissionContext {
            actor_did: "did:key:user".into(),
            actor_role: Role::Member,
            token_scopes: vec!["*".into()],
            chip_type: "ubl/membership".into(),
            world: "a/acme/t/prod".into(),
        };
        assert!(ctx.quick_check().is_err());
    }

    #[test]
    fn member_can_submit_regular_chips() {
        let ctx = PermissionContext {
            actor_did: "did:key:user".into(),
            actor_role: Role::Member,
            token_scopes: vec!["read".into(), "write".into()],
            chip_type: "ubl/user".into(),
            world: "a/acme".into(),
        };
        assert!(ctx.quick_check().is_ok());
    }

    // ── Validate Onboarding ─────────────────────────────────────

    #[test]
    fn validate_onboarding_app() {
        let body = json!({
            "@type": "ubl/app",
            "slug": "acme",
            "display_name": "Acme",
            "owner_did": "did:key:z6Mk",
        });
        assert!(validate_onboarding_chip(&body).is_ok());
    }

    #[test]
    fn validate_onboarding_bad_user() {
        let body = json!({
            "@type": "ubl/user",
            "did": "not-a-did",
            "display_name": "Alice",
        });
        assert!(validate_onboarding_chip(&body).is_err());
    }

    #[test]
    fn parse_onboarding_chip_returns_typed_variant() {
        let body = json!({
            "@type": "ubl/membership",
            "user_cid": "b3:user",
            "tenant_cid": "b3:tenant",
            "role": "admin",
        });
        let parsed = parse_onboarding_chip(&body).unwrap();
        assert!(matches!(parsed, Some(OnboardingChip::Membership(_))));
    }

    #[test]
    fn parse_onboarding_chip_returns_none_for_non_onboarding_type() {
        let body = json!({
            "@type": "ubl/advisory",
            "hook": "post-wf",
        });
        let parsed = parse_onboarding_chip(&body).unwrap();
        assert!(parsed.is_none());
    }

    #[test]
    fn is_onboarding_type_check() {
        assert!(is_onboarding_type("ubl/app"));
        assert!(is_onboarding_type("ubl/user"));
        assert!(is_onboarding_type("ubl/tenant"));
        assert!(is_onboarding_type("ubl/membership"));
        assert!(is_onboarding_type("ubl/token"));
        assert!(is_onboarding_type("ubl/revoke"));
        assert!(!is_onboarding_type("ubl/advisory"));
        assert!(!is_onboarding_type("ubl/ai.passport"));
    }

    // ── Role ────────────────────────────────────────────────────

    #[test]
    fn role_only_two() {
        assert!(Role::parse("admin").is_ok());
        assert!(Role::parse("member").is_ok());
        assert!(Role::parse("superadmin").is_err());
        assert!(Role::parse("user").is_err());
        assert!(Role::parse("").is_err());
    }
}
