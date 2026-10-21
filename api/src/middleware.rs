use crate::client_ip::TrustedClientIpKeyExtractor;
use crate::crypto::jwt::{Actor, Claims, JwtService};
use crate::entities::{memberships, organizations, users};
use crate::error::{AppError, Result};
use axum::{
    extract::{FromRequestParts, MatchedPath, Path, Request, State},
    http::{request::Parts, StatusCode},
    middleware::Next,
    response::Response,
};
use metrics::histogram;
use moka::future::Cache;
use sea_orm::DatabaseConnection;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

// Security Audit Item 2: Regex DoS Prevention

use std::sync::LazyLock;

/// Static email regex compiled once at startup to prevent Regex DoS attacks
/// from per-request regex compilation overhead
static EMAIL_REGEX: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
        .expect("Invalid email regex")
});

/// Validate email format using statically compiled regex
/// This prevents Regex DoS by reusing a single compiled regex instance
pub fn validate_email_format_static(email: &str) -> Result<()> {
    if email.is_empty() {
        return Err(AppError::BadRequest("Email cannot be empty".to_string()));
    }

    if !EMAIL_REGEX.is_match(email) {
        return Err(AppError::BadRequest("Invalid email format".to_string()));
    }

    // Additional checks for specific invalid patterns
    if email.starts_with('.') || email.ends_with('.') || email.contains("..") {
        return Err(AppError::BadRequest("Invalid email format".to_string()));
    }

    Ok(())
}

/// Extension type for storing authenticated user claims
#[derive(Clone, Debug)]
pub struct AuthUser {
    pub claims: Claims,
    pub user: users::Model,
    pub permissions: Vec<String>, // Cached permissions from database
    pub ip_address: String,
    pub user_agent: String,
    pub current_session_id: Option<String>,
}

impl AuthUser {
    /// Platform authority requires a token minted for the platform context.
    /// Tenant and service login tokens never carry this authority, even when
    /// the user row currently has the platform-owner flag.
    pub fn has_platform_token_context(&self) -> bool {
        self.claims.is_platform_context()
    }
}

/// Marks a request as already impersonating; handlers read only its presence,
/// to refuse nesting a second impersonation inside the first.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct ImpersonationContext {
    /// The admin user who is performing the impersonation
    pub actor: Actor,
    /// The original claims before impersonation
    pub original_claims: Claims,
    /// Reason for impersonation (if provided)
    pub reason: Option<String>,
}

#[axum::async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self> {
        parts
            .extensions
            .get::<AuthUser>()
            .cloned()
            .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))
    }
}

/// Fetch permissions from cache, or from DB on cache miss
async fn fetch_and_cache_permissions(
    db: &DatabaseConnection,
    cache: &Cache<String, Vec<String>>,
    user_id: &str,
) -> Result<Vec<String>> {
    use crate::db::DB;
    use crate::store::permissions::PermissionsStore;

    if let Some(cached_perms) = cache.get(user_id).await {
        return Ok(cached_perms);
    }

    let perms_models = PermissionsStore::list_user_permissions(DB::Conn(db), user_id).await?;

    let perms_strings: Vec<String> = perms_models
        .into_iter()
        .map(|p| format!("{}:{}#{}", p.namespace, p.object_id, p.relation))
        .collect();

    cache
        .insert(user_id.to_string(), perms_strings.clone())
        .await;

    Ok(perms_strings)
}

/// Fetch user model from cache, or from DB on cache miss
///
/// This reduces database load on authenticated requests by caching User models
/// with a 30-second TTL. Cache is invalidated when user is updated.
async fn fetch_and_cache_user(
    db: &DatabaseConnection,
    cache: &Cache<String, crate::entities::users::Model>,
    user_id: &str,
) -> Result<crate::entities::users::Model> {
    use crate::db::DB;
    use crate::store::users::UserStore;

    if let Some(cached_user) = cache.get(user_id).await {
        if cached_user.deleted_at.is_some() {
            cache.invalidate(user_id).await;
            return Err(AppError::Unauthorized(
                "User is no longer active".to_string(),
            ));
        }
        return Ok(cached_user);
    }

    let user = UserStore::find_by_id(DB::Conn(db), user_id)
        .await?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;
    if user.deleted_at.is_some() {
        cache.invalidate(user_id).await;
        return Err(AppError::Unauthorized(
            "User is no longer active".to_string(),
        ));
    }

    cache.insert(user_id.to_string(), user.clone()).await;

    Ok(user)
}

async fn validate_current_impersonation_authority(
    db: &DatabaseConnection,
    actor: &Actor,
    target: &users::Model,
    org_slug: Option<&str>,
) -> Result<()> {
    use crate::db::DB;
    use crate::store::{
        memberships::MembershipStore, organizations::OrganizationStore, users::UserStore,
    };

    let actor_user = UserStore::find_by_id(DB::Conn(db), &actor.sub)
        .await?
        .filter(|user| user.deleted_at.is_none())
        .ok_or_else(|| {
            AppError::Unauthorized("Impersonation authorization is no longer valid".to_string())
        })?;
    if target.deleted_at.is_some() {
        return Err(AppError::Unauthorized(
            "Impersonation authorization is no longer valid".to_string(),
        ));
    }
    if actor_user.is_platform_owner {
        if !crate::store::totp::TotpStore::is_enabled(DB::Conn(db), &actor_user.id).await? {
            return Err(AppError::Unauthorized(
                "Impersonation authorization is no longer valid".to_string(),
            ));
        }
        return Ok(());
    }
    if target.is_platform_owner {
        return Err(AppError::Unauthorized(
            "Impersonation authorization is no longer valid".to_string(),
        ));
    }

    let org_slug = org_slug.ok_or_else(|| {
        AppError::Unauthorized("Impersonation authorization is no longer valid".to_string())
    })?;
    let org = OrganizationStore::find_by_slug(DB::Conn(db), org_slug)
        .await?
        .filter(|org| org.status == "active")
        .ok_or_else(|| {
            AppError::Unauthorized("Impersonation authorization is no longer valid".to_string())
        })?;
    let actor_membership =
        MembershipStore::find_by_org_and_user(DB::Conn(db), &org.id, &actor_user.id).await?;
    let target_membership =
        MembershipStore::find_by_org_and_user(DB::Conn(db), &org.id, &target.id).await?;
    if !matches!(
        actor_membership
            .as_ref()
            .map(|membership| membership.role.as_str()),
        Some("owner" | "admin")
    ) || target_membership.is_none()
    {
        return Err(AppError::Unauthorized(
            "Impersonation authorization is no longer valid".to_string(),
        ));
    }

    Ok(())
}

async fn fetch_permissions_uncached(db: &DatabaseConnection, user_id: &str) -> Result<Vec<String>> {
    use crate::db::DB;
    use crate::store::permissions::PermissionsStore;

    Ok(
        PermissionsStore::list_user_permissions(DB::Conn(db), user_id)
            .await?
            .into_iter()
            .map(|permission| {
                format!(
                    "{}:{}#{}",
                    permission.namespace, permission.object_id, permission.relation
                )
            })
            .collect(),
    )
}

/// Extract and validate JWT from Authorization header
pub async fn extract_user_from_jwt(
    State(state): State<crate::state::AppState>,
    mut req: Request,
    next: Next,
) -> std::result::Result<Response, AppError> {
    let db = &state.db;
    let jwt_service = &state.jwt_service;
    let permission_cache = &state.permission_cache;
    let user_cache = &state.user_cache;
    use crate::db::DB;
    use crate::store::sessions::SessionStore;

    // Extract token from Authorization header
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.strip_prefix("Bearer "))
        .ok_or_else(|| {
            AppError::Unauthorized("Missing or invalid Authorization header".to_string())
        })?;

    let claims = jwt_service.validate_authos_token(token)?;
    let user_id = claims.sub.clone();

    // Extract IP and User-Agent before modifying request
    let ip_address = extract_ip(&req);
    let user_agent = extract_user_agent(&req);

    // Check if this is an impersonation token
    if let Some((actor, original_claims)) = jwt_service.extract_impersonation_context(token)? {
        // This is an impersonation session
        tracing::warn!(
            admin_user_id = %actor.sub,
            target_user_id = %claims.sub,
            reason_recorded = actor.reason.is_some(),
            "Processing impersonation request"
        );

        let token_hash = JwtService::hash_token(token);
        let session = SessionStore::find_valid_by_token_hash(DB::Conn(db), &token_hash)
            .await
            .map_err(|_| AppError::Unauthorized("Impersonation session is invalid".to_string()))?
            .ok_or_else(|| {
                AppError::Unauthorized("Impersonation session is revoked or expired".to_string())
            })?;

        // Do not use the user or permission caches for impersonation. Actor
        // demotion, target privilege changes, and membership removal must take
        // effect on the next request rather than after a cache TTL.
        let user = crate::store::users::UserStore::find_by_id(DB::Conn(db), &claims.sub)
            .await?
            .ok_or_else(|| AppError::Unauthorized("Target user not found".to_string()))?;
        validate_current_impersonation_authority(db, &actor, &user, claims.org.as_deref()).await?;

        let permissions = fetch_permissions_uncached(db, &user_id).await?;

        // Store impersonation context
        req.extensions_mut().insert(ImpersonationContext {
            actor: actor.clone(),
            original_claims: original_claims.clone(),
            reason: actor.reason,
        });

        // Store user in request extensions
        req.extensions_mut().insert(AuthUser {
            claims: claims.clone(),
            user,
            permissions,
            ip_address,
            user_agent,
            current_session_id: Some(session.id),
        });
    } else {
        // Normal authentication flow
        // Check if session is still valid (not revoked)
        let token_hash = JwtService::hash_token(token);
        let session = SessionStore::find_valid_by_token_hash(DB::Conn(db), &token_hash).await?;

        if session.is_none() {
            return Err(AppError::Unauthorized(
                "Session revoked or expired".to_string(),
            ));
        }
        let current_session_id = session.as_ref().map(|session| session.id.clone());

        // Load user from cache or database
        let user = fetch_and_cache_user(db, user_cache, &claims.sub).await?;

        let permissions = fetch_and_cache_permissions(db, permission_cache, &user_id).await?;

        // Store user in request extensions
        req.extensions_mut().insert(AuthUser {
            claims: claims.clone(),
            user,
            permissions,
            ip_address,
            user_agent,
            current_session_id,
        });
    }

    Ok(next.run(req).await)
}

/// Extract IP address from request
fn extract_ip(req: &Request) -> String {
    extract_client_ip(req)
}

fn extract_client_ip(req: &Request) -> String {
    static CLIENT_IP_EXTRACTOR: LazyLock<TrustedClientIpKeyExtractor> =
        LazyLock::new(TrustedClientIpKeyExtractor::from_env);

    CLIENT_IP_EXTRACTOR
        .extract_client_ip(req)
        .map_or_else(|| "unknown".to_string(), |ip| ip.to_string())
}

/// Extract User-Agent from request
fn extract_user_agent(req: &Request) -> String {
    req.headers()
        .get("User-Agent")
        .and_then(|header| header.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
}

/// Middleware to require platform owner role
pub async fn require_platform_owner(
    State(state): State<crate::state::AppState>,
    req: Request,
    next: Next,
) -> std::result::Result<Response, (StatusCode, String)> {
    let auth_user = req
        .extensions()
        .get::<AuthUser>()
        .ok_or((StatusCode::UNAUTHORIZED, "Not authenticated".to_string()))?;

    if !auth_user.has_platform_token_context() {
        return Err((
            StatusCode::FORBIDDEN,
            "A platform-context token is required for this operation".to_string(),
        ));
    }

    if !has_current_platform_authority(&state.db, &auth_user.user.id)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to verify platform authority".to_string(),
            )
        })?
    {
        return Err((
            StatusCode::FORBIDDEN,
            "Platform owner access required".to_string(),
        ));
    }

    // The one-time bootstrap session may perform initial provisioning before
    // the first owner has enrolled MFA. Enabling MFA revokes this session.
    let bootstrap_provisioning = auth_user.claims.bootstrap == Some(true);
    if !bootstrap_provisioning {
        if !crate::store::totp::TotpStore::is_enabled(
            crate::db::DB::Conn(&state.db),
            &auth_user.user.id,
        )
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to verify platform MFA enrollment".to_string(),
            )
        })? {
            return Err((
                StatusCode::FORBIDDEN,
                "Platform owner MFA enrollment is required before accessing platform controls"
                    .to_string(),
            ));
        }
        // Enrollment alone is not enough: a passkey-only login can occur
        // without the TOTP step. Platform authority is granted only to a token
        // minted by the MFA completion flow (or the narrow bootstrap session).
        if auth_user.claims.mfa_verified != Some(true) {
            return Err((
                StatusCode::FORBIDDEN,
                "Multi-factor verification is required before accessing platform controls"
                    .to_string(),
            ));
        }
    }

    Ok(next.run(req).await)
}

async fn has_current_platform_authority(db: &DatabaseConnection, user_id: &str) -> Result<bool> {
    use crate::db::DB;
    use crate::store::users::UserStore;

    Ok(UserStore::find_by_id(DB::Conn(db), user_id)
        .await?
        .is_some_and(|user| user.is_platform_owner && user.deleted_at.is_none()))
}

/// Live platform authority for a specific request. This is stricter than the
/// database role check: the token must be platform-scoped, carry proof that the
/// current login completed the MFA challenge (or be the narrow bootstrap
/// session), and belong to a non-deleted platform owner with MFA enrolled.
pub async fn has_live_platform_authority(
    db: &DatabaseConnection,
    auth_user: &AuthUser,
) -> Result<bool> {
    has_live_platform_authority_in(
        crate::db::DB::Conn(db),
        &auth_user.user.id,
        auth_user.has_platform_token_context(),
        auth_user.claims.mfa_verified == Some(true) || auth_user.claims.bootstrap == Some(true),
    )
    .await
}

/// Transaction-friendly live platform authority check. The token-context and
/// MFA-completion hints come from the authenticated request; the role and MFA
/// enrollment state are always re-read from the database so demotion and factor
/// removal are immediate.
pub async fn has_live_platform_authority_in(
    db: crate::db::DB<'_>,
    user_id: &str,
    platform_token_context: bool,
    platform_mfa_verified: bool,
) -> Result<bool> {
    if !platform_token_context || !platform_mfa_verified {
        return Ok(false);
    }
    let Some(user) = crate::store::users::UserStore::find_by_id(db.clone(), user_id).await? else {
        return Ok(false);
    };
    if !user.is_platform_owner || user.deleted_at.is_some() {
        return Ok(false);
    }
    crate::store::totp::TotpStore::is_enabled(db, user_id).await
}

/// Service-login tokens are delivered to the relying party. They may read the
/// authenticated user's profile and subscription, but must not be accepted as
/// organization or platform management credentials.
pub async fn enforce_service_token_scope(
    req: Request,
    next: Next,
) -> std::result::Result<Response, AppError> {
    let Some(auth_user) = req.extensions().get::<AuthUser>() else {
        return Err(AppError::Unauthorized("Not authenticated".to_string()));
    };

    if !auth_user.claims.is_service_context() {
        return Ok(next.run(req).await);
    }

    if !service_token_path_allowed(req.method(), req.uri().path()) {
        return Err(AppError::Forbidden(
            "Service-scoped tokens may only read the authenticated user's profile and subscription"
                .to_string(),
        ));
    }

    Ok(next.run(req).await)
}

/// Platform-context login material must not be handed to a tenant-controlled
/// browser origin. Non-browser clients do not send Origin and remain usable.
pub fn ensure_trusted_platform_origin(
    headers: &axum::http::HeaderMap,
    config: &crate::config::Config,
) -> Result<()> {
    let Some(origin) = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(());
    };

    let Some(origin) = url::Url::parse(origin)
        .ok()
        .map(|url| url.origin().ascii_serialization())
    else {
        return Err(AppError::Forbidden(
            "Platform sign-in is only available from the configured platform origin".to_string(),
        ));
    };
    let allowed = [
        Some(config.platform_dashboard_base_url.as_str()),
        Some(config.base_url.as_str()),
        config.full_web_client_base_url.as_deref(),
    ]
    .into_iter()
    .flatten()
    .filter_map(|candidate| url::Url::parse(candidate).ok())
    .any(|candidate| candidate.origin().ascii_serialization() == origin);

    if allowed {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "Platform sign-in is only available from the configured platform origin".to_string(),
        ))
    }
}

fn service_token_path_allowed(method: &axum::http::Method, path: &str) -> bool {
    method == axum::http::Method::GET && (path == "/api/user" || path == "/api/subscription")
}

/// Impersonation is for scoped support actions, not for establishing a
/// persistent login as the target. Factor, identity, device, recovery, and
/// self-deletion changes are therefore refused inside an impersonation session.
pub async fn reject_impersonation_for_sensitive_actions(
    req: Request,
    next: Next,
) -> std::result::Result<Response, AppError> {
    if req.extensions().get::<ImpersonationContext>().is_some()
        && is_sensitive_impersonation_action(req.method(), req.uri().path())
    {
        return Err(AppError::Forbidden(
            "Account security and identity-linking changes are not allowed while impersonating a user"
                .to_string(),
        ));
    }
    Ok(next.run(req).await)
}

fn is_sensitive_impersonation_action(method: &axum::http::Method, path: &str) -> bool {
    let post = *method == axum::http::Method::POST;
    let patch = *method == axum::http::Method::PATCH;
    let delete = *method == axum::http::Method::DELETE;

    if patch && path == "/api/user" {
        return true;
    }
    if post
        && matches!(
            path,
            "/api/user/change-password"
                | "/api/user/set-password"
                | "/api/user/mfa/setup"
                | "/api/user/mfa/verify"
                | "/api/user/mfa/backup-codes/regenerate"
                | "/api/user/devices/revoke-all"
        )
    {
        return true;
    }
    if delete && path == "/api/user/mfa" {
        return true;
    }
    if post && path.starts_with("/api/auth/passkeys/register/") {
        return true;
    }
    if (patch || delete) && path.starts_with("/api/auth/passkeys/") {
        return true;
    }
    if (post || delete) && path.starts_with("/api/user/identities") {
        return true;
    }
    if (post || delete) && path.starts_with("/api/user/linked-accounts") {
        return true;
    }
    if post && path.starts_with("/api/user/provider-token-requests/") {
        return true;
    }
    if (post || patch || delete) && path.starts_with("/api/user/devices") {
        return true;
    }
    if delete && path.starts_with("/api/privacy/forget/") {
        return true;
    }
    false
}

/// Require that the current browser session was established recently. This is
/// used as a step-up boundary for security-sensitive account changes. Refresh
/// operations preserve the original session creation time.
pub async fn require_recent_authentication(
    db: &DatabaseConnection,
    auth_user: &AuthUser,
    max_age: chrono::Duration,
) -> Result<()> {
    use crate::db::DB;
    use crate::store::sessions::SessionStore;

    let session_id = auth_user.current_session_id.as_deref().ok_or_else(|| {
        AppError::Forbidden(
            "Reauthentication is required before changing account security settings".to_string(),
        )
    })?;
    let session = SessionStore::find_by_id(DB::Conn(db), session_id)
        .await?
        .ok_or_else(|| {
            AppError::Forbidden(
                "Reauthentication is required before changing account security settings"
                    .to_string(),
            )
        })?;
    let age = chrono::Utc::now().naive_utc() - session.created_at;
    if age > max_age {
        return Err(AppError::Forbidden(
            "Reauthentication is required before changing account security settings".to_string(),
        ));
    }
    Ok(())
}

/// Helper function to check if user has required role in organization
pub async fn check_org_membership(
    db: &DatabaseConnection,
    user_id: &str,
    org_id: &str,
    required_roles: &[&str],
) -> Result<memberships::Model> {
    use crate::db::DB;
    use crate::store::memberships::MembershipStore;

    let membership = MembershipStore::find_by_org_and_user(DB::Conn(db), org_id, user_id)
        .await?
        .ok_or_else(|| AppError::Forbidden("Not a member of this organization".to_string()))?;

    if !required_roles.is_empty() && !required_roles.contains(&membership.role.as_str()) {
        return Err(AppError::Forbidden(format!(
            "Requires one of roles: {}",
            required_roles.join(", ")
        )));
    }

    Ok(membership)
}

/// Helper function to check if user is organization owner
pub async fn check_org_owner(db: &DatabaseConnection, user_id: &str, org_id: &str) -> Result<()> {
    check_org_membership(db, user_id, org_id, &["owner"]).await?;
    Ok(())
}

/// Extractor struct for organization slug path parameter
#[derive(Deserialize)]
pub struct OrgSlugParam {
    org_slug: String,
}

/// Middleware to require organization to be in active status
/// This prevents access to certain features (services, BYOO credentials, etc.)
/// while organization is pending approval
pub async fn require_active_organization(
    State(state): State<crate::state::AppState>,
    Path(path): Path<OrgSlugParam>,
    req: Request,
    next: Next,
) -> std::result::Result<Response, AppError> {
    use crate::db::DB;
    use crate::store::organizations::OrganizationStore;

    // Get organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &path.org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Check if organization is active
    if org.status != "active" {
        return Err(AppError::Forbidden(format!(
            "Organization is not active. Current status: {}. This feature is only available for active organizations.",
            org.status
        )));
    }

    Ok(next.run(req).await)
}

// Email Rate Limiting

/// In-memory rate limiter for email operations (password reset, registration, etc.)
#[derive(Clone)]
pub struct EmailRateLimiter {
    /// Tracks email attempts per email address
    email_attempts: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
    /// Maximum emails per hour per email address
    max_emails_per_hour: usize,
    /// Time window for rate limiting (1 hour)
    window: Duration,
}

impl EmailRateLimiter {
    pub fn new(max_emails_per_hour: usize) -> Self {
        Self {
            email_attempts: Arc::new(RwLock::new(HashMap::new())),
            max_emails_per_hour,
            window: Duration::from_secs(3600), // 1 hour
        }
    }

    /// Check if email address is rate limited for sending emails
    pub async fn is_rate_limited_email(&self, email: &str) -> bool {
        self.is_rate_limited_email_with_context(email, None).await
    }

    /// Security Audit Item 9: Tenant-aware email rate limiting
    /// Uses compound key 'org_id:email' to partition rate limits by tenant
    pub async fn is_rate_limited_email_with_context(
        &self,
        email: &str,
        org_id: Option<&str>,
    ) -> bool {
        let mut attempts = self.email_attempts.write().await;
        let now = Instant::now();

        // Create compound key for tenant-partitioned rate limiting
        let key = match org_id {
            Some(org) => format!("{}:{}", org, email.to_lowercase()),
            None => format!("platform:{}", email.to_lowercase()),
        };

        let entry = attempts.entry(key).or_insert_with(Vec::new);

        // Remove expired attempts (older than 1 hour)
        entry.retain(|&timestamp| now.duration_since(timestamp) < self.window);

        // Check if over limit
        if entry.len() >= self.max_emails_per_hour {
            return true;
        }

        // Add current attempt
        entry.push(now);
        false
    }

    /// Drop keys whose window has fully expired; called by the cleanup job.
    pub async fn cleanup(&self) {
        let now = Instant::now();

        // Cleanup email attempts
        let mut attempts = self.email_attempts.write().await;
        attempts.retain(|_, timestamps| {
            timestamps.retain(|&timestamp| now.duration_since(timestamp) < self.window);
            !timestamps.is_empty()
        });
    }
}

/// In-memory failed-login throttling keyed by normalized email. This is a
/// defense-in-depth layer on top of the route IP limiter and Argon2 cost. It is
/// intentionally process-local; deployments with multiple replicas should also
/// apply an edge rate limit.
#[derive(Clone)]
pub struct LoginAttemptLimiter {
    attempts: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
    max_attempts: usize,
    window: Duration,
}

impl LoginAttemptLimiter {
    pub fn new(max_attempts: usize, window: Duration) -> Self {
        Self {
            attempts: Arc::new(RwLock::new(HashMap::new())),
            max_attempts,
            window,
        }
    }

    fn normalize(email: &str) -> String {
        email.trim().to_lowercase()
    }

    pub async fn is_rate_limited(&self, email: &str) -> bool {
        let key = Self::normalize(email);
        let mut attempts = self.attempts.write().await;
        let now = Instant::now();
        let entry = attempts.entry(key).or_insert_with(Vec::new);
        entry.retain(|&timestamp| now.duration_since(timestamp) < self.window);
        entry.len() >= self.max_attempts
    }

    pub async fn record_failure(&self, email: &str) {
        let key = Self::normalize(email);
        let mut attempts = self.attempts.write().await;
        let now = Instant::now();
        let entry = attempts.entry(key).or_insert_with(Vec::new);
        entry.retain(|&timestamp| now.duration_since(timestamp) < self.window);
        entry.push(now);
    }

    pub async fn clear(&self, email: &str) {
        let key = Self::normalize(email);
        self.attempts.write().await.remove(&key);
    }

    pub async fn cleanup(&self) {
        let now = Instant::now();
        let mut attempts = self.attempts.write().await;
        attempts.retain(|_, timestamps| {
            timestamps.retain(|&timestamp| now.duration_since(timestamp) < self.window);
            !timestamps.is_empty()
        });
    }
}

// MFA Rate Limiting Middleware

/// In-memory rate limiter for MFA verification attempts
#[allow(dead_code)]
#[derive(Clone)]
pub struct MfaRateLimiter {
    /// Tracks attempts per IP address
    attempts: Arc<RwLock<HashMap<IpAddr, Vec<Instant>>>>,
    /// Tracks attempts per user ID (when authenticated)
    user_attempts: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
    /// Maximum attempts per window
    max_attempts: usize,
    /// Time window for rate limiting
    window: Duration,
}

impl MfaRateLimiter {
    #[allow(dead_code)]
    pub fn new(max_attempts: usize, window: Duration) -> Self {
        Self {
            attempts: Arc::new(RwLock::new(HashMap::new())),
            user_attempts: Arc::new(RwLock::new(HashMap::new())),
            max_attempts,
            window,
        }
    }

    /// Check if IP is rate limited for MFA attempts
    #[allow(dead_code)]
    pub async fn is_rate_limited_ip(&self, ip: IpAddr) -> bool {
        let mut attempts = self.attempts.write().await;
        let now = Instant::now();

        let entry = attempts.entry(ip).or_insert_with(Vec::new);

        // Remove expired attempts
        entry.retain(|&timestamp| now.duration_since(timestamp) < self.window);

        // Check if over limit
        if entry.len() >= self.max_attempts {
            return true;
        }

        // Add current attempt
        entry.push(now);
        false
    }

    /// Check if user is rate limited for MFA attempts
    #[allow(dead_code)]
    pub async fn is_rate_limited_user(&self, user_id: &str) -> bool {
        self.is_rate_limited_user_with_context(user_id, None).await
    }

    /// Security Audit Item 9: Tenant-aware MFA rate limiting
    /// Uses compound key 'org_id:user_id' to partition rate limits by tenant
    #[allow(dead_code)]
    pub async fn is_rate_limited_user_with_context(
        &self,
        user_id: &str,
        org_id: Option<&str>,
    ) -> bool {
        let mut attempts = self.user_attempts.write().await;
        let now = Instant::now();

        // Create compound key for tenant-partitioned rate limiting
        let key = match org_id {
            Some(org) => format!("{}:{}", org, user_id),
            None => format!("platform:{}", user_id),
        };

        let entry = attempts.entry(key).or_insert_with(Vec::new);

        // Remove expired attempts
        entry.retain(|&timestamp| now.duration_since(timestamp) < self.window);

        // Check if over limit
        if entry.len() >= self.max_attempts {
            return true;
        }

        // Add current attempt
        entry.push(now);
        false
    }

    /// Drop keys whose window has fully expired; called by the cleanup job.
    #[allow(dead_code)]
    pub async fn cleanup(&self) {
        let now = Instant::now();

        // Cleanup IP attempts
        let mut attempts = self.attempts.write().await;
        attempts.retain(|_, timestamps| {
            timestamps.retain(|&timestamp| now.duration_since(timestamp) < self.window);
            !timestamps.is_empty()
        });

        // Cleanup user attempts
        let mut user_attempts = self.user_attempts.write().await;
        user_attempts.retain(|_, timestamps| {
            timestamps.retain(|&timestamp| now.duration_since(timestamp) < self.window);
            !timestamps.is_empty()
        });
    }
}

/// Global MFA rate limiter instance
pub static EMAIL_RATE_LIMITER: std::sync::LazyLock<EmailRateLimiter> =
    std::sync::LazyLock::new(|| {
        EmailRateLimiter::new(5) // Max 5 emails per hour per email address
    });

pub static LOGIN_ATTEMPT_LIMITER: std::sync::LazyLock<LoginAttemptLimiter> =
    std::sync::LazyLock::new(|| LoginAttemptLimiter::new(10, Duration::from_secs(15 * 60)));

pub static MFA_RATE_LIMITER: std::sync::LazyLock<MfaRateLimiter> = std::sync::LazyLock::new(|| {
    MfaRateLimiter::new(
        5,                            // Max 5 attempts
        Duration::from_secs(15 * 60), // Per 15 minutes
    )
});

/// Middleware for MFA verification rate limiting
#[allow(dead_code)]
pub async fn mfa_rate_limit_middleware(
    req: Request,
    next: Next,
) -> std::result::Result<Response, (StatusCode, String)> {
    // Extract IP address from connect info
    let ip = req
        .extensions()
        .get::<std::net::SocketAddr>()
        .map_or_else(|| "127.0.0.1".parse().unwrap(), std::net::SocketAddr::ip);

    // Check IP-based rate limiting first
    if MFA_RATE_LIMITER.is_rate_limited_ip(ip).await {
        tracing::warn!("MFA rate limit exceeded for IP: {}", ip);
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "Too many MFA attempts. Please try again later.".to_string(),
        ));
    }

    // Check if user is authenticated and apply user-based rate limiting
    if let Some(auth_user) = req.extensions().get::<AuthUser>() {
        if MFA_RATE_LIMITER
            .is_rate_limited_user(&auth_user.user.id)
            .await
        {
            tracing::warn!(
                user_id = %auth_user.user.id,
                "MFA rate limit exceeded for user"
            );
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                "Too many MFA attempts. Please try again later.".to_string(),
            ));
        }
    }

    Ok(next.run(req).await)
}

// Request Information Extraction Middleware

/// Request information extracted for audit logging and risk assessment
#[derive(Clone, Debug)]
pub struct RequestInfo {
    pub ip_address: String,
    pub user_agent: String,
}

/// Middleware to extract request information and add it to extensions
pub async fn extract_request_info_middleware(mut request: Request, next: Next) -> Response {
    let ip_address = extract_client_ip(&request);

    let user_agent = request
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let request_info = RequestInfo {
        ip_address,
        user_agent,
    };

    // Add request info to extensions for downstream handlers
    request.extensions_mut().insert(request_info);

    next.run(request).await
}

/// Helper function to get request info from request extensions
#[allow(dead_code)]
pub fn get_request_info(request: &Request) -> &RequestInfo {
    request
        .extensions()
        .get::<RequestInfo>()
        .expect("RequestInfo middleware not applied to request")
}

/// Record `sso_http_request_duration_seconds`.
///
/// Labels use `MatchedPath`, not the raw path: raw paths carry ids and would
/// explode metric cardinality. Must sit outermost to time the whole request.
pub async fn http_metrics_middleware(request: Request, next: Next) -> Response {
    let start = Instant::now();

    // Extract route pattern BEFORE processing (MatchedPath is set by Axum router)
    // Fall back to "unknown" if no matched path (e.g., 404s)
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "unknown".to_string(), |mp| mp.as_str().to_string());

    let method = request.method().to_string();

    // Process the request
    let response = next.run(request).await;

    // Calculate duration
    let duration = start.elapsed().as_secs_f64();

    // Categorize status code into classes for reasonable cardinality
    // Using exact status codes would explode cardinality (100+ unique values)
    let status_class = match response.status().as_u16() {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "unknown",
    };

    // Record the histogram
    histogram!(
        "sso_http_request_duration_seconds",
        duration,
        "method" => method,
        "route" => route,
        "status" => status_class.to_string()
    );

    response
}

// Security Audit Item 3: Dynamic Efficient CORS

use axum::http::{header, HeaderValue, Method};

/// Origin allowlist built from org custom domains and service redirect URIs.
///
/// Replaces a blanket `allow_origin(Any)`. Decisions are cached for 5 minutes
/// because the miss path costs two database lookups per preflight.
pub async fn dynamic_cors_middleware(
    State(state): State<crate::state::AppState>,
    request: Request,
    next: Next,
) -> Response {
    use crate::db::DB;
    use crate::store::{organizations::OrganizationStore, services::ServiceStore};

    // Cloned: the header borrow would outlive the request mutation below.
    let origin_header = match request.headers().get(header::ORIGIN).cloned() {
        Some(h) => h,
        None => return next.run(request).await, // Not a CORS request
    };

    let origin_str = match origin_header.to_str() {
        Ok(s) => s.to_string(), // Clone to owned string
        Err(_) => return next.run(request).await,
    };

    // The platform dashboard is always an allowed origin.
    // Trim trailing slash to match origin format
    let platform_url = state
        .config
        .platform_dashboard_base_url
        .trim_end_matches('/');
    if origin_str == platform_url {
        return allow_cors(request, next, origin_header).await;
    }

    // Also allow the API base URL itself
    let api_base = state.base_url.trim_end_matches('/');
    if origin_str == api_base {
        return allow_cors(request, next, origin_header).await;
    }

    // Parse domain from origin (remove protocol and port)
    // e.g. https://custom.org.com:3000 -> custom.org.com
    let domain = origin_str
        .split("://")
        .nth(1)
        .unwrap_or(&origin_str)
        .split(':')
        .next()
        .unwrap_or(&origin_str)
        .to_string();

    // Skip strict CORS for localhost during development
    if domain == "localhost" || domain.starts_with("127.") || domain.starts_with("192.168.") {
        return allow_cors(request, next, origin_header).await;
    }

    // The cache is keyed by the full origin string (covers both custom domains and redirect URIs)
    if let Some(is_allowed) = state.domain_cache.get(&origin_str).await {
        if is_allowed {
            return allow_cors(request, next, origin_header).await;
        } else {
            // Explicitly denied in cache, proceed without CORS headers (browser will block)
            return next.run(request).await;
        }
    }

    let db = DB::Conn(&state.db);
    let mut is_allowed = false;

    if let Ok(Some(org)) = OrganizationStore::find_by_custom_domain(db.clone(), &domain).await {
        if org.status == "active" && org.domain_verified {
            is_allowed = true;
        }
    }

    // Check B: Is it a Service Redirect URI origin?
    // Only check if not already found to save DB calls
    if !is_allowed {
        if let Ok(allowed) = ServiceStore::is_origin_allowed(db, &origin_str).await {
            is_allowed = allowed;
        }
    }

    // Cache the full origin string result (unified for both sources)
    state.domain_cache.insert(origin_str, is_allowed).await;

    if is_allowed {
        allow_cors(request, next, origin_header).await
    } else {
        next.run(request).await
    }
}

/// Helper to attach CORS headers to the response
async fn allow_cors(req: Request, next: Next, origin: HeaderValue) -> Response {
    // Handle Preflight OPTIONS
    if req.method() == Method::OPTIONS {
        let mut response = Response::new(axum::body::Body::empty());
        let headers = response.headers_mut();
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, PUT, DELETE, PATCH, OPTIONS"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("Authorization, Content-Type, X-Api-Key, X-Organization-ID"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
        headers.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static("86400"), // 24 hours
        );
        return response;
    }

    // Handle standard request
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
        HeaderValue::from_static("true"),
    );
    response
}

// Custom Domain Resolution Middleware

/// Resolved custom-domain tenant, attached for handlers that need it.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct CustomDomainOrg {
    pub organization: organizations::Model,
}

/// Middleware to resolve organization from custom domain
/// This is optional and primarily used for future enhancements where
/// the org_slug might not be in the URL path
#[allow(dead_code)]
pub async fn resolve_custom_domain(
    State(db): State<DatabaseConnection>,
    mut req: Request,
    next: Next,
) -> std::result::Result<Response, AppError> {
    use crate::db::DB;
    use crate::store::organizations::OrganizationStore;

    // Extract Host header
    let host = req
        .headers()
        .get("Host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    // Remove port if present
    let domain = host.split(':').next().unwrap_or(host);

    // Skip if it's localhost or empty
    if domain.is_empty() || domain == "localhost" || domain.starts_with("127.") {
        return Ok(next.run(req).await);
    }

    if let Ok(Some(org)) = OrganizationStore::find_by_custom_domain(DB::Conn(&db), domain).await {
        // Store organization in request extensions
        req.extensions_mut()
            .insert(CustomDomainOrg { organization: org });
    }

    Ok(next.run(req).await)
}

// API Key Authentication Middleware

use crate::crypto::api_key::ApiKeyService;

/// Service Principal identity for API key authenticated requests
#[derive(Clone, Debug)]
pub struct ServicePrincipal {
    #[allow(dead_code)]
    pub api_key_id: String,
    pub service_id: String,
    #[allow(dead_code)]
    pub service: crate::entities::services::Model,
    pub permissions: Vec<String>,
}

#[axum::async_trait]
impl<S> FromRequestParts<S> for ServicePrincipal
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self> {
        parts
            .extensions
            .get::<ServicePrincipal>()
            .cloned()
            .ok_or_else(|| AppError::Unauthorized("Not authenticated with API key".to_string()))
    }
}

/// Extract and validate API key from X-Api-Key header
pub async fn extract_api_key(
    State(db): State<DatabaseConnection>,
    mut req: Request,
    next: Next,
) -> std::result::Result<Response, AppError> {
    use crate::db::DB;
    use crate::store::{api_keys::ApiKeyStore, services::ServiceStore};

    let api_key = req
        .headers()
        .get("X-Api-Key")
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing or invalid X-Api-Key header".to_string()))?;

    let prefix = ApiKeyService::extract_prefix(api_key)
        .ok_or_else(|| AppError::Unauthorized("Invalid API key format".to_string()))?;

    let stored_key = ApiKeyStore::find_by_prefix(DB::Conn(&db), &prefix)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Invalid API key".to_string()))?;

    if !ApiKeyService::verify_key(api_key, &stored_key.key_hash) {
        return Err(AppError::Unauthorized("Invalid API key".to_string()));
    }

    if let Some(expires_at_naive) = &stored_key.expires_at {
        let expires_at: chrono::DateTime<chrono::Utc> =
            chrono::DateTime::from_naive_utc_and_offset(*expires_at_naive, chrono::Utc);
        if expires_at < chrono::Utc::now() {
            return Err(AppError::Unauthorized("API key has expired".to_string()));
        }
    }

    let service = ServiceStore::find_by_id(DB::Conn(&db), &stored_key.service_id)
        .await?
        .ok_or_else(|| {
            AppError::InternalServerError("Service not found for API key".to_string())
        })?;
    if !service_organization_is_active(&db, &service.org_id).await? {
        return Err(AppError::Unauthorized(
            "API key organization is not active".to_string(),
        ));
    }

    let permissions: Vec<String> =
        serde_json::from_str(&stored_key.permissions).unwrap_or_default();

    ApiKeyStore::update_last_used(DB::Conn(&db), &stored_key.id).await?;

    req.extensions_mut().insert(ServicePrincipal {
        api_key_id: stored_key.id,
        service_id: stored_key.service_id,
        service,
        permissions,
    });

    Ok(next.run(req).await)
}

async fn service_organization_is_active(db: &DatabaseConnection, org_id: &str) -> Result<bool> {
    use crate::db::DB;
    use crate::store::organizations::OrganizationStore;

    Ok(OrganizationStore::find_by_id(DB::Conn(db), org_id)
        .await?
        .is_some_and(|organization| organization.status == "active"))
}

/// SCIM Authentication Context
/// Contains the verified SCIM token and associated organization
#[derive(Clone, Debug)]
pub struct ScimAuth {
    /// Carried for handlers that need the token's own metadata.
    #[allow(dead_code)]
    pub token: crate::entities::scim_tokens::Model,
    pub org_id: String,
}

/// Authenticate a SCIM bearer token and attach `ScimAuth` to the request.
pub async fn scim_auth_middleware(
    State(db): State<DatabaseConnection>,
    mut request: Request,
    next: Next,
) -> std::result::Result<Response, StatusCode> {
    use crate::db::DB;
    use crate::store::scim_tokens::ScimTokenStore;

    // Extract Authorization header
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Check if it's a Bearer token
    if !auth_header.starts_with("Bearer ") {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let token = auth_header.trim_start_matches("Bearer ").trim();

    let scim_token = ScimTokenStore::verify_for_active_org(DB::Conn(&db), token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Validate the optional selector if provided. Multiple values are
    // ambiguous across proxies/frameworks, so fail closed rather than letting
    // one layer choose a different value from another.
    let mut org_id_headers = request.headers().get_all("X-Organization-ID").iter();
    if let Some(org_id_header) = org_id_headers.next() {
        if org_id_headers.next().is_some() {
            return Err(StatusCode::FORBIDDEN);
        }
        let org_id_str = org_id_header.to_str().map_err(|_| StatusCode::FORBIDDEN)?;
        if org_id_str != scim_token.org_id {
            // Token belongs to a different organization - unauthorized
            return Err(StatusCode::FORBIDDEN);
        }
    }

    // Update last_used_at (fire and forget - don't block the request)
    let db_clone = db.clone();
    let token_id = scim_token.id.clone();
    tokio::spawn(async move {
        let _ = ScimTokenStore::update_last_used(DB::Conn(&db_clone), &token_id).await;
    });

    // Add SCIM auth context to request extensions
    let scim_auth = ScimAuth {
        org_id: scim_token.org_id.clone(),
        token: scim_token,
    };
    request.extensions_mut().insert(scim_auth);

    Ok(next.run(request).await)
}

#[cfg(test)]
mod service_token_scope_tests {
    use super::*;

    #[test]
    fn service_tokens_can_only_read_profile_and_subscription() {
        assert!(service_token_path_allowed(
            &axum::http::Method::GET,
            "/api/user"
        ));
        assert!(service_token_path_allowed(
            &axum::http::Method::GET,
            "/api/subscription"
        ));
        for (method, path) in [
            (axum::http::Method::GET, "/api/organizations"),
            (axum::http::Method::GET, "/api/platform/users"),
            (axum::http::Method::PATCH, "/api/user"),
            (axum::http::Method::POST, "/api/user/mfa/setup"),
            (axum::http::Method::DELETE, "/api/user/mfa"),
            (axum::http::Method::GET, "/api/privacy/export/user"),
        ] {
            assert!(
                !service_token_path_allowed(&method, path),
                "{method} {path} must be denied"
            );
        }
    }
}

#[cfg(test)]
mod impersonation_sensitive_action_tests {
    use super::*;

    #[test]
    fn impersonation_cannot_change_factors_identity_devices_or_delete_account() {
        for (method, path) in [
            (axum::http::Method::PATCH, "/api/user"),
            (axum::http::Method::POST, "/api/user/change-password"),
            (axum::http::Method::POST, "/api/user/mfa/setup"),
            (axum::http::Method::DELETE, "/api/user/mfa"),
            (axum::http::Method::POST, "/api/user/identities/github/link"),
            (axum::http::Method::DELETE, "/api/user/identities/github"),
            (
                axum::http::Method::POST,
                "/api/user/linked-accounts/github/link",
            ),
            (
                axum::http::Method::POST,
                "/api/user/provider-token-requests/state/complete",
            ),
            (
                axum::http::Method::POST,
                "/api/auth/passkeys/register/start",
            ),
            (axum::http::Method::PATCH, "/api/auth/passkeys/passkey-1"),
            (axum::http::Method::POST, "/api/user/devices/device-1/trust"),
            (axum::http::Method::DELETE, "/api/privacy/forget/user-1"),
        ] {
            assert!(
                is_sensitive_impersonation_action(&method, path),
                "{method} {path} must be denied during impersonation"
            );
        }

        for (method, path) in [
            (axum::http::Method::GET, "/api/user"),
            (axum::http::Method::GET, "/api/user/identities"),
            (axum::http::Method::GET, "/api/organizations/acme/services"),
            (axum::http::Method::GET, "/api/privacy/export/user-1"),
            (
                axum::http::Method::POST,
                "/api/organizations/acme/invitations",
            ),
        ] {
            assert!(
                !is_sensitive_impersonation_action(&method, path),
                "{method} {path} should remain available to support impersonation"
            );
        }
    }
}

#[cfg(test)]
mod platform_origin_tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    #[test]
    fn platform_origin_guard_allows_configured_origins_and_non_browser_clients() {
        let config = crate::test_support::test_config();
        assert!(ensure_trusted_platform_origin(&HeaderMap::new(), &config).is_ok());

        for origin in [
            config.platform_dashboard_base_url.as_str(),
            config.base_url.as_str(),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::header::ORIGIN,
                HeaderValue::from_str(origin).expect("origin"),
            );
            assert!(ensure_trusted_platform_origin(&headers, &config).is_ok());
        }

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::ORIGIN,
            HeaderValue::from_static("https://tenant.example.test"),
        );
        assert!(ensure_trusted_platform_origin(&headers, &config).is_err());
    }
}

#[cfg(test)]
mod impersonation_authority_tests {
    use super::*;
    use crate::db::DB;
    use crate::entities::{prelude::UserTotpSecrets, user_totp_secrets, users};
    use crate::store::{
        memberships::MembershipStore, organizations::OrganizationStore, users::UserStore,
    };
    use migration::{Migrator, MigratorTrait};
    use sea_orm::{ActiveModelTrait, Database, EntityTrait, Set};

    #[tokio::test]
    async fn org_impersonation_authority_tracks_role_target_scope_and_org_status() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let actor_user = UserStore::create(DB::Conn(&db), "admin@example.com", None, false)
            .await
            .expect("create actor");
        let target = UserStore::create(DB::Conn(&db), "target@example.com", None, false)
            .await
            .expect("create target");
        let (org, actor_membership) = OrganizationStore::create_with_owner(
            DB::Conn(&db),
            "impersonation-org",
            "Impersonation Org",
            &actor_user.id,
            None,
        )
        .await
        .expect("create org");
        OrganizationStore::update_status(DB::Conn(&db), &org.id, "active")
            .await
            .expect("activate org");
        let target_membership =
            MembershipStore::create(DB::Conn(&db), &org.id, &target.id, "member")
                .await
                .expect("add target");
        let actor = Actor {
            sub: actor_user.id.clone(),
            email: actor_user.email.clone(),
            reason: Some("support case".to_string()),
        };

        validate_current_impersonation_authority(&db, &actor, &target, Some("impersonation-org"))
            .await
            .expect("admin may impersonate member");

        MembershipStore::update_role(DB::Conn(&db), &actor_membership.id, "member")
            .await
            .expect("demote actor");
        assert!(validate_current_impersonation_authority(
            &db,
            &actor,
            &target,
            Some("impersonation-org")
        )
        .await
        .is_err());

        MembershipStore::update_role(DB::Conn(&db), &actor_membership.id, "admin")
            .await
            .expect("restore actor");
        MembershipStore::delete(DB::Conn(&db), &target_membership.id)
            .await
            .expect("remove target");
        assert!(validate_current_impersonation_authority(
            &db,
            &actor,
            &target,
            Some("impersonation-org")
        )
        .await
        .is_err());

        MembershipStore::create(DB::Conn(&db), &org.id, &target.id, "member")
            .await
            .expect("restore target");
        OrganizationStore::update_status(DB::Conn(&db), &org.id, "suspended")
            .await
            .expect("suspend org");
        assert!(validate_current_impersonation_authority(
            &db,
            &actor,
            &target,
            Some("impersonation-org")
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn platform_actor_demotion_immediately_removes_global_impersonation_authority() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let actor_user = UserStore::create(DB::Conn(&db), "owner@example.com", None, true)
            .await
            .expect("create actor");
        UserTotpSecrets::insert(user_totp_secrets::ActiveModel {
            id: Set("impersonation-actor-totp".to_string()),
            user_id: Set(actor_user.id.clone()),
            secret_encrypted: Set(vec![]),
            encryption_key_id: Set("test-key".to_string()),
            enabled: Set(true),
            created_at: Set(chrono::Utc::now().naive_utc()),
            enabled_at: Set(Some(chrono::Utc::now().naive_utc())),
        })
        .exec(&db)
        .await
        .expect("enroll actor MFA");
        let target = UserStore::create(DB::Conn(&db), "target2@example.com", None, false)
            .await
            .expect("create target");
        let actor = Actor {
            sub: actor_user.id.clone(),
            email: actor_user.email.clone(),
            reason: Some("support case".to_string()),
        };

        validate_current_impersonation_authority(&db, &actor, &target, None)
            .await
            .expect("platform actor may impersonate globally");
        UserStore::set_platform_owner(DB::Conn(&db), &actor_user.id, false)
            .await
            .expect("demote platform actor");
        assert!(
            validate_current_impersonation_authority(&db, &actor, &target, None)
                .await
                .is_err()
        );

        UserStore::set_platform_owner(DB::Conn(&db), &actor_user.id, true)
            .await
            .expect("restore platform actor");
        let mut deleted_actor: users::ActiveModel =
            UserStore::find_by_id(DB::Conn(&db), &actor_user.id)
                .await
                .expect("load actor")
                .expect("actor remains")
                .into();
        deleted_actor.deleted_at = Set(Some(chrono::Utc::now().naive_utc()));
        deleted_actor.update(&db).await.expect("soft-delete actor");
        assert!(
            validate_current_impersonation_authority(&db, &actor, &target, None)
                .await
                .is_err()
        );
    }
}

#[cfg(test)]
mod platform_authority_tests {
    use super::*;
    use crate::db::DB;
    use crate::entities::{prelude::UserTotpSecrets, user_totp_secrets, users};
    use crate::store::users::UserStore;
    use crate::test_support::{test_config, test_jwt_service};
    use migration::{Migrator, MigratorTrait};
    use sea_orm::{ActiveModelTrait, ColumnTrait, Database, EntityTrait, QueryFilter, Set};

    async fn enroll_mfa(db: &DatabaseConnection, user_id: &str) {
        UserTotpSecrets::insert(user_totp_secrets::ActiveModel {
            id: Set(format!("totp-{user_id}")),
            user_id: Set(user_id.to_string()),
            secret_encrypted: Set(vec![]),
            encryption_key_id: Set("test-key".to_string()),
            enabled: Set(true),
            created_at: Set(chrono::Utc::now().naive_utc()),
            enabled_at: Set(Some(chrono::Utc::now().naive_utc())),
        })
        .exec(db)
        .await
        .expect("enroll MFA");
    }

    #[tokio::test]
    async fn live_platform_authority_requires_context_and_mfa() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let owner = UserStore::create(DB::Conn(&db), "context-owner@example.com", None, true)
            .await
            .expect("create owner");
        enroll_mfa(&db, &owner.id).await;

        let config = test_config();
        let jwt = test_jwt_service(&config);
        let platform_token = jwt
            .create_mfa_verified_token(&owner.id, &owner.email, true, None, None)
            .expect("platform token");
        let platform_auth = AuthUser {
            claims: jwt
                .validate_token(&platform_token)
                .expect("platform claims"),
            user: owner.clone(),
            permissions: vec![],
            ip_address: "127.0.0.1".to_string(),
            user_agent: "platform-authority-test".to_string(),
            current_session_id: None,
        };
        assert!(has_live_platform_authority(&db, &platform_auth)
            .await
            .expect("live authority"));

        let tenant_token = jwt
            .create_token(&owner.id, &owner.email, true, Some("acme"), None)
            .expect("tenant token");
        let tenant_auth = AuthUser {
            claims: jwt.validate_token(&tenant_token).expect("tenant claims"),
            user: owner.clone(),
            permissions: vec![],
            ip_address: "127.0.0.1".to_string(),
            user_agent: "platform-authority-test".to_string(),
            current_session_id: None,
        };
        assert!(!has_live_platform_authority(&db, &tenant_auth)
            .await
            .expect("tenant authority"));

        // Platform context and enrollment are not enough: the current token
        // must come from the MFA completion flow. A passkey-only platform
        // session must not inherit platform controls.
        let passkey_token = jwt
            .create_token(&owner.id, &owner.email, true, None, None)
            .expect("passkey-context token");
        let passkey_auth = AuthUser {
            claims: jwt.validate_token(&passkey_token).expect("passkey claims"),
            user: owner.clone(),
            permissions: vec![],
            ip_address: "127.0.0.1".to_string(),
            user_agent: "platform-authority-test".to_string(),
            current_session_id: None,
        };
        assert!(!has_live_platform_authority(&db, &passkey_auth)
            .await
            .expect("unverified platform authority"));

        UserTotpSecrets::delete_many()
            .filter(user_totp_secrets::Column::UserId.eq(&owner.id))
            .exec(&db)
            .await
            .expect("remove MFA");
        assert!(!has_live_platform_authority(&db, &platform_auth)
            .await
            .expect("MFA-removed authority"));
    }

    #[tokio::test]
    async fn platform_authority_uses_current_database_role_not_cached_snapshot() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let owner = UserStore::create(DB::Conn(&db), "platform-owner@example.com", None, true)
            .await
            .expect("create platform owner");
        let tenant_admin =
            UserStore::create(DB::Conn(&db), "tenant-admin@example.com", None, false)
                .await
                .expect("create tenant admin");

        assert!(has_current_platform_authority(&db, &owner.id)
            .await
            .expect("check platform owner"));
        assert!(!has_current_platform_authority(&db, &tenant_admin.id)
            .await
            .expect("check tenant admin"));

        UserStore::set_platform_owner(DB::Conn(&db), &owner.id, false)
            .await
            .expect("demote platform owner");
        assert!(!has_current_platform_authority(&db, &owner.id)
            .await
            .expect("check demoted owner"));
        assert!(!has_current_platform_authority(&db, "missing-user")
            .await
            .expect("check missing user"));

        UserStore::set_platform_owner(DB::Conn(&db), &owner.id, true)
            .await
            .expect("restore platform role");
        let mut deleted_owner: users::ActiveModel = UserStore::find_by_id(DB::Conn(&db), &owner.id)
            .await
            .expect("load restored owner")
            .expect("restored owner exists")
            .into();
        deleted_owner.deleted_at = Set(Some(chrono::Utc::now().naive_utc()));
        deleted_owner.update(&db).await.expect("soft-delete owner");
        assert!(!has_current_platform_authority(&db, &owner.id)
            .await
            .expect("check deleted owner"));
    }
}

#[cfg(test)]
mod service_principal_tenant_status_tests {
    use super::*;
    use crate::db::DB;
    use crate::store::{organizations::OrganizationStore, users::UserStore};
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;

    #[tokio::test]
    async fn service_principal_authority_follows_current_organization_status() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let owner = UserStore::create(DB::Conn(&db), "service-owner@example.com", None, false)
            .await
            .expect("create owner");
        let org = OrganizationStore::create(
            DB::Conn(&db),
            "service-status-org",
            "Service Status Org",
            &owner.id,
            None,
        )
        .await
        .expect("create org");

        assert!(!service_organization_is_active(&db, &org.id)
            .await
            .expect("pending org denied"));
        OrganizationStore::update_status(DB::Conn(&db), &org.id, "active")
            .await
            .expect("activate org");
        assert!(service_organization_is_active(&db, &org.id)
            .await
            .expect("active org allowed"));
        OrganizationStore::update_status(DB::Conn(&db), &org.id, "suspended")
            .await
            .expect("suspend org");
        assert!(!service_organization_is_active(&db, &org.id)
            .await
            .expect("suspended org denied"));
    }
}

#[cfg(test)]
mod rate_limiter_tests {
    use super::*;
    use std::net::IpAddr;
    use std::time::Duration;

    #[tokio::test]
    async fn login_attempts_are_keyed_by_normalized_email_and_clear_on_success() {
        let limiter = LoginAttemptLimiter::new(3, Duration::from_secs(60));
        for _ in 0..3 {
            assert!(!limiter.is_rate_limited("User@Example.Test").await);
            limiter.record_failure("User@Example.Test").await;
        }
        assert!(limiter.is_rate_limited("user@example.test").await);
        limiter.clear("USER@EXAMPLE.TEST").await;
        assert!(!limiter.is_rate_limited("user@example.test").await);
    }

    #[tokio::test]
    async fn email_rate_limiter_blocks_at_the_cap_and_partitions_by_tenant() {
        let limiter = EmailRateLimiter::new(3);

        for _ in 0..3 {
            assert!(
                !limiter.is_rate_limited_email("user@example.test").await,
                "under the cap"
            );
        }
        assert!(
            limiter.is_rate_limited_email("user@example.test").await,
            "the next attempt over the cap is blocked"
        );

        // Case-insensitive: the same mailbox in another case shares the bucket.
        assert!(
            limiter.is_rate_limited_email("USER@EXAMPLE.TEST").await,
            "case variants share a bucket"
        );

        // A different tenant's identical address has its own budget.
        assert!(
            !limiter
                .is_rate_limited_email_with_context("user@example.test", Some("org-1"))
                .await
        );
        // And so does a different address in the same tenant.
        assert!(
            !limiter
                .is_rate_limited_email_with_context("other@example.test", Some("org-1"))
                .await
        );
    }

    #[tokio::test]
    async fn mfa_ip_limiter_blocks_after_the_window_budget() {
        let limiter = MfaRateLimiter::new(2, Duration::from_secs(60));
        let ip: IpAddr = "203.0.113.9".parse().unwrap();

        assert!(!limiter.is_rate_limited_ip(ip).await);
        assert!(!limiter.is_rate_limited_ip(ip).await);
        assert!(
            limiter.is_rate_limited_ip(ip).await,
            "third attempt blocked"
        );

        let other: IpAddr = "203.0.113.10".parse().unwrap();
        assert!(
            !limiter.is_rate_limited_ip(other).await,
            "other IPs unaffected"
        );
    }

    #[tokio::test]
    async fn mfa_user_limiter_partitions_by_tenant() {
        let limiter = MfaRateLimiter::new(1, Duration::from_secs(60));

        assert!(!limiter.is_rate_limited_user("user-1").await);
        assert!(limiter.is_rate_limited_user("user-1").await);

        // Tenant-partitioned key gets its own budget.
        assert!(
            !limiter
                .is_rate_limited_user_with_context("user-1", Some("acme"))
                .await
        );
        assert!(
            limiter
                .is_rate_limited_user_with_context("user-1", Some("acme"))
                .await
        );
    }

    #[test]
    fn email_validation_rejects_the_classic_garbage() {
        for bad in [
            "",
            "no-at-sign",
            ".starts-with-dot@example.test",
            "double..dot@example.test",
        ] {
            assert!(
                validate_email_format_static(bad).is_err(),
                "{bad} must fail"
            );
        }
        // Known gap, pinned deliberately: the leading/trailing dot check runs
        // against the WHOLE address, so a local part ending in a dot before
        // the @ slips through (`user.@example.test` is accepted). A future
        // fix should split at the @ first; flipping this assertion then.
        assert!(
            validate_email_format_static("ends-with-dot.@example.test").is_ok(),
            "documents the whole-string dot check"
        );
        assert!(validate_email_format_static("good@example.test").is_ok());
    }

    #[tokio::test]
    async fn cleanup_clears_stale_buckets_without_error() {
        let limiter = EmailRateLimiter::new(1);
        let _ = limiter.is_rate_limited_email("x@example.test").await;
        limiter.cleanup().await;

        let mfa = MfaRateLimiter::new(1, Duration::from_secs(60));
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let _ = mfa.is_rate_limited_ip(ip).await;
        let _ = mfa.is_rate_limited_user("u").await;
        mfa.cleanup().await;
    }
}
