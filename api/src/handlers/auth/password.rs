use crate::db::transaction::with_retrying_transaction;
use crate::db::DB;
use crate::error::{AppError, Result};
use crate::handlers::auth::email_delivery::ensure_email_delivery_configured;
use crate::middleware::RequestInfo;
use crate::state::AppState;
use crate::store::{
    email_verification::EmailVerificationStore,
    identities::IdentityStore,
    invitations::InvitationStore,
    memberships::MembershipStore,
    organizations::OrganizationStore,
    password_reset::PasswordResetStore,
    services::ServiceStore,
    sessions::SessionStore,
    totp::TotpStore,
    users::UserStore,
    verified_domains::{VerifiedDomainStore, DOMAIN_LOGIN_POLICY_UPSTREAM_ONLY},
};
use axum::{
    extract::{Query, State},
    response::Html,
    Extension, Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Argon2 password hashing imports
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};

// Static dummy hash for timing attack mitigation (Security Audit Item 6)
// Used to perform password verification even when user doesn't exist,
// ensuring consistent response times regardless of email existence
static DUMMY_HASH: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(b"dummy_password_for_timing_attack_mitigation", &salt)
        .expect("Failed to generate dummy hash")
        .to_string()
});

const GENERIC_LOGIN_FAILURE: &str = "Invalid email or password";
const GENERIC_REGISTRATION_RESPONSE: &str =
    "If registration can be completed, a verification email has been sent.";
const GENERIC_PASSWORD_RESET_RESPONSE: &str =
    "If an account with that email exists, a password reset link has been sent.";
const GENERIC_VERIFICATION_RESPONSE: &str =
    "If an account with that email exists and is not verified, a verification link has been sent.";

fn generic_registration_response() -> Json<RegisterResponse> {
    Json(RegisterResponse {
        message: GENERIC_REGISTRATION_RESPONSE.to_string(),
    })
}

fn generic_password_reset_response() -> Json<ForgotPasswordResponse> {
    Json(ForgotPasswordResponse {
        message: GENERIC_PASSWORD_RESET_RESPONSE.to_string(),
    })
}

fn generic_verification_response() -> Json<ResendVerificationResponse> {
    Json(ResendVerificationResponse {
        message: GENERIC_VERIFICATION_RESPONSE.to_string(),
    })
}

// Helper function to hash JWT tokens for session tracking
pub fn hash_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

// Re-export common types
pub use crate::error::Json400;

// Re-export RefreshTokenResponse from session module for use in login/register flows
pub use super::session::RefreshTokenResponse;

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    /// Organization slug for tenant context. When provided, the user is attributed to this organization.
    pub org_slug: Option<String>,
    /// Service slug for service attribution. When provided with org_slug, creates a scoped identity.
    pub service_slug: Option<String>,
    /// Service callback URI to preserve app return context in verification links.
    pub redirect_uri: Option<String>,
    /// Caller state to preserve through hosted service callbacks.
    pub state: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyEmailQuery {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    /// Organization slug for tenant context
    pub org_slug: Option<String>,
    /// Service slug for service-scoped access (used with org_slug)
    pub service_slug: Option<String>,
    /// Service callback URI for hosted password login. Validated before tokens are returned.
    pub redirect_uri: Option<String>,
    pub saml_state: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
    pub org_slug: Option<String>, // Optional: use organization-specific SMTP
    pub service_slug: Option<String>,
    pub redirect_uri: Option<String>,
    pub state: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ForgotPasswordResponse {
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub new_password: String,
}

#[derive(Debug, Serialize)]
pub struct ResetPasswordResponse {
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct ResendVerificationRequest {
    pub email: String,
    pub org_slug: Option<String>,
    pub service_slug: Option<String>,
    pub redirect_uri: Option<String>,
    pub state: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ResendVerificationResponse {
    pub message: String,
}

fn validate_service_redirect_uri(
    redirect_uri: &str,
    service: &crate::db::models::Service,
) -> Result<()> {
    let allowed_uris_json = service.redirect_uris.as_ref().ok_or_else(|| {
        AppError::BadRequest("No redirect URIs are registered for this service".to_string())
    })?;

    let allowed_uris: Vec<String> = serde_json::from_str(allowed_uris_json)
        .map_err(|e| AppError::InternalServerError(format!("Invalid redirect_uris JSON: {}", e)))?;

    if allowed_uris.is_empty() {
        return Err(AppError::BadRequest(
            "No redirect URIs are registered for this service".to_string(),
        ));
    }

    if !allowed_uris.iter().any(|allowed| allowed == redirect_uri) {
        return Err(AppError::BadRequest(format!(
            "redirect_uri '{}' is not registered for this service",
            redirect_uri
        )));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_auth_link(
    web_client_url: &str,
    path: &str,
    token_name: &str,
    token: &str,
    org_slug: Option<&str>,
    service_slug: Option<&str>,
    redirect_uri: Option<&str>,
    state: Option<&str>,
) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair(token_name, token);

    if let Some(org_slug) = org_slug {
        serializer.append_pair("org", org_slug);
    }

    if let Some(service_slug) = service_slug {
        serializer.append_pair("service", service_slug);
    }

    if let Some(redirect_uri) = redirect_uri {
        serializer.append_pair("redirect_uri", redirect_uri);
    }

    if let Some(state) = state {
        serializer.append_pair("state", state);
    }

    format!(
        "{}/{}?{}",
        web_client_url.trim_end_matches('/'),
        path.trim_start_matches('/'),
        serializer.finish()
    )
}

async fn resolve_org_id_from_slug(
    state: &AppState,
    org_slug: Option<&str>,
) -> Result<Option<String>> {
    if let Some(slug) = org_slug {
        let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), slug)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
        Ok(Some(org.id))
    } else {
        Ok(None)
    }
}

pub(crate) async fn reject_upstream_only_local_auth(
    state: &AppState,
    email: &str,
    context_org_id: Option<&str>,
    auth_method: &str,
) -> Result<()> {
    let Some(domain) =
        VerifiedDomainStore::find_verified_by_email_domain(DB::Conn(&state.db), email).await?
    else {
        return Ok(());
    };

    let applies_to_context = context_org_id.is_none_or(|org_id| org_id == domain.org_id);

    if applies_to_context
        && domain.login_policy == DOMAIN_LOGIN_POLICY_UPSTREAM_ONLY
        && domain.upstream_provider_id.is_some()
    {
        return Err(AppError::Forbidden(format!(
            "{} is disabled for this managed domain. Use your organization's identity provider.",
            auth_method
        )));
    }

    Ok(())
}

/// POST /api/auth/register - Register a new user with email and password
pub async fn register(
    State(state): State<AppState>,
    Json400(req): Json400<RegisterRequest>,
) -> Result<Json<RegisterResponse>> {
    ensure_email_delivery_configured(&state, "account registration")?;

    // Check email rate limit BEFORE processing the request (only if rate limiting is enabled)
    // Rate limiting is disabled when DISABLE_RATE_LIMITING=true is set
    if std::env::var("DISABLE_RATE_LIMITING")
        .unwrap_or_default()
        .to_lowercase()
        != "true"
        && crate::middleware::EMAIL_RATE_LIMITER
            .is_rate_limited_email(&req.email)
            .await
    {
        tracing::warn!("Registration request rate limited");
        return Err(AppError::TooManyRequests(
            "Too many registration attempts. Please try again later.".to_string(),
        ));
    }

    // Validate email format
    if !req.email.contains('@') {
        return Err(AppError::BadRequest("Invalid email format".to_string()));
    }

    // Validate password strength (minimum 8 characters)
    if req.password.len() < 8 {
        return Err(AppError::BadRequest(
            "Password must be at least 8 characters long".to_string(),
        ));
    }

    let password_hash =
        crate::crypto::concurrency::hash_password_bounded(req.password.clone()).await?;

    // Clone values needed inside the closure
    let email = req.email.clone();
    let is_platform_owner = state.config.platform_owner_email.as_ref() == Some(&email);
    let verification_token = Uuid::new_v4().to_string();
    let org_slug = req.org_slug.clone();
    let service_slug = req.service_slug.clone();

    // Resolve org_id and service_id from slugs (if provided)
    let (issuing_org_id, issuing_service_id) = if let (Some(org_s), Some(service_s)) =
        (&org_slug, &service_slug)
    {
        // Validate that org exists
        let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), org_s)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

        // Validate that service exists within org
        let service = ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, service_s)
            .await?
            .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;

        if let Some(redirect_uri) = &req.redirect_uri {
            let service_model = crate::db::models::Service::from(service.clone());
            validate_service_redirect_uri(redirect_uri, &service_model)?;
        }

        (Some(org.id), Some(service.id))
    } else if let Some(org_s) = &org_slug {
        // Just Org slug provided (no service)
        let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), org_s)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

        (Some(org.id), None)
    } else {
        (None, None)
    };

    reject_upstream_only_local_auth(
        &state,
        &req.email,
        issuing_org_id.as_deref(),
        "Password registration",
    )
    .await?;

    // Check if user already exists (scoped to tenant if org_id is present)
    let existing_user = UserStore::find_by_email_with_context(
        DB::Conn(&state.db),
        &req.email,
        issuing_org_id.as_deref(),
    )
    .await?;

    if existing_user.is_some() {
        return Ok(generic_registration_response());
    }

    // Execute transaction with automatic retry on database contention
    let user_id = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "register_user",
        |db| {
            let email = email.clone();
            let password_hash = password_hash.clone();
            let verification_token = verification_token.clone();
            let issuing_org_id = issuing_org_id.clone();
            let issuing_service_id = issuing_service_id.clone();

            Box::pin(async move {
                // Create user within the transaction (scoped if org_id available)
                let user = if let Some(ref org_id) = issuing_org_id {
                    UserStore::create_with_org_id(db.clone(), &email, Some(password_hash), org_id)
                        .await?
                } else {
                    UserStore::create(db.clone(), &email, Some(password_hash), is_platform_owner)
                        .await?
                };
                let user_id = user.id.clone();

                // Automatically accept any pending invitations for this email
                InvitationStore::accept_all_pending_for_email(db.clone(), &email, &user_id).await?;

                // Create password identity with org/service context (if provided)
                // This ensures password users are tracked the same as OAuth users
                IdentityStore::create(
                    db.clone(),
                    &user_id,
                    "password", // provider
                    &email,     // provider_user_id (email serves as unique ID for password)
                    None,       // access_token (N/A for password)
                    None,       // refresh_token (N/A for password)
                    None,       // access_token_encrypted
                    None,       // refresh_token_encrypted
                    None,       // encryption_key_id
                    None,       // expires_at
                    None,       // scopes
                    issuing_org_id.as_deref(),
                    issuing_service_id.as_deref(),
                )
                .await?;

                // Generate email verification token
                let token_hash = hash_token(&verification_token);
                let expires_at = Utc::now() + chrono::Duration::hours(24);

                EmailVerificationStore::create(
                    db.clone(),
                    &user_id,
                    &token_hash,
                    &expires_at.naive_utc(),
                )
                .await?;

                Ok(user_id)
            })
        },
    )
    .await?;

    state.permission_cache.invalidate(&user_id).await;

    // Publish signup event for webhooks (password signup with org/service context)
    if issuing_org_id.is_some() {
        use crate::services::events::{Event, EventType};
        use serde_json::json;

        let mut event_builder = Event::builder(EventType::UserSignupSuccess)
            .actor_user_id(&user_id)
            .actor_email(&email)
            .detail("provider", json!("password"));

        if let Some(ref org_id) = issuing_org_id {
            event_builder = event_builder.org_id(org_id);
        }

        if let Some(ref service_id) = issuing_service_id {
            event_builder = event_builder.detail("service_id", json!(service_id));
        }

        let event = event_builder.build();

        let dispatcher = state.event_dispatcher.clone();
        tokio::spawn(async move {
            if let Err(e) = dispatcher.publish(event).await {
                tracing::error!("Failed to publish signup event: {}", e);
            }
        });
    }

    // Enqueue verification email to job queue (non-blocking)
    let verification_url = build_auth_link(
        &state.web_client_url,
        "/verify-email",
        "token",
        &verification_token,
        req.org_slug.as_deref(),
        req.service_slug.as_deref(),
        req.redirect_uri.as_deref(),
        req.state.as_deref(),
    );
    let email_subject = "Verify Your Email Address";
    let email_body = format!(
        "Welcome to our platform!\n\n\
        Please verify your email address by clicking the link below:\n\n\
        {}\n\n\
        This link will expire in 24 hours.\n\n\
        If you didn't create an account, you can safely ignore this email.",
        verification_url
    );

    use crate::services::job_queue::JobQueueService;
    if let Err(e) = JobQueueService::enqueue_email(
        DB::Conn(&state.db),
        &email,
        email_subject,
        &email_body,
        None, // No HTML version
    )
    .await
    {
        tracing::error!("Failed to enqueue verification email: {}", e);
        // Don't fail registration if email enqueueing fails - user can request resend
    }

    Ok(generic_registration_response())
}

/// GET /auth/verify-email - Verify email address
async fn complete_email_verification(db: DB<'_>, token_hash: &str, user_id: &str) -> Result<bool> {
    if !EmailVerificationStore::mark_as_used(db.clone(), token_hash).await? {
        return Ok(false);
    }
    UserStore::verify_email(db, user_id).await?;
    Ok(true)
}

pub async fn verify_email(
    State(state): State<AppState>,
    Query(query): Query<VerifyEmailQuery>,
) -> Result<Html<String>> {
    let token_hash = hash_token(&query.token);

    // Find and validate token
    let token_record = EmailVerificationStore::find_by_token_hash(DB::Conn(&state.db), &token_hash)
        .await?
        .ok_or_else(|| AppError::BadRequest("Invalid verification token".to_string()))?;

    if token_record.used {
        return Err(AppError::BadRequest(
            "Verification token has already been used".to_string(),
        ));
    }

    let expires_at: chrono::DateTime<Utc> =
        chrono::DateTime::from_naive_utc_and_offset(token_record.expires_at, Utc);

    if expires_at < Utc::now() {
        return Err(AppError::BadRequest(
            "Verification token has expired".to_string(),
        ));
    }

    let user_id = token_record.user_id.clone();
    let token_hash_for_transaction = token_hash.clone();
    let completed = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "complete_email_verification",
        |db| {
            let user_id = user_id.clone();
            let token_hash = token_hash_for_transaction.clone();
            Box::pin(async move { complete_email_verification(db, &token_hash, &user_id).await })
        },
    )
    .await?;
    if !completed {
        return Err(AppError::BadRequest(
            "Verification token has already been used or expired".to_string(),
        ));
    }

    Ok(Html(
        "<html><body><h1>Email Verified!</h1><p>Your email has been verified successfully. You can now log in.</p></body></html>".to_string()
    ))
}

/// POST /api/auth/login - Login with email and password
pub async fn login(
    State(state): State<AppState>,
    Extension(request_info): Extension<RequestInfo>,
    Json400(req): Json400<LoginRequest>,
) -> Result<Json<RefreshTokenResponse>> {
    // Resolve org_id from slug if provided to establish tenant context
    let context_org_id = if let Some(ref slug) = req.org_slug {
        let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), slug)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
        crate::handlers::organizations::ensure_organization_active(&state.db, &org.id).await?;
        Some(org.id)
    } else {
        None
    };

    reject_upstream_only_local_auth(
        &state,
        &req.email,
        context_org_id.as_deref(),
        "Password login",
    )
    .await?;

    // Find user by email (scoped to tenant context)
    // - If org_slug provided: WHERE email=? AND org_id=?
    // - If no org_slug: WHERE email=? AND org_id IS NULL (Platform login)
    let user_result = UserStore::find_by_email_with_context(
        DB::Conn(&state.db),
        &req.email,
        context_org_id.as_deref(),
    )
    .await?;

    // Unknown or password-less accounts verify against DUMMY_HASH so the
    // response time cannot be used to enumerate registered emails.
    let (user, password_hash, is_dummy) = match &user_result {
        Some(u) if u.deleted_at.is_none() && u.password_hash.is_some() => {
            (Some(u), u.password_hash.as_ref().unwrap().clone(), false)
        }
        _ => (user_result.as_ref(), DUMMY_HASH.clone(), true),
    };

    let is_valid =
        crate::crypto::concurrency::verify_password_bounded(req.password.clone(), password_hash)
            .await?;

    // Return error if:
    // - Password verification failed, OR
    // - We were using dummy hash (user doesn't exist or has no password)
    if !is_valid || is_dummy {
        // With an org context and a correct password, say so: the account
        // exists globally but has no identity in this organization (A6).
        // This reveals nothing without the password — the verification
        // above costs the same as a real login either way.
        if let Some(ref slug) = req.org_slug {
            if let Ok(Some(global)) =
                UserStore::find_by_email_with_context(DB::Conn(&state.db), &req.email, None).await
            {
                if global.deleted_at.is_none() {
                    if let Some(hash) = global.password_hash.as_ref() {
                        if crate::crypto::concurrency::verify_password_bounded(
                            req.password.clone(),
                            hash.clone(),
                        )
                        .await
                        .unwrap_or(false)
                        {
                            return Err(AppError::Unauthorized(format!(
                                "No account for this email address in organization '{}'",
                                slug
                            )));
                        }
                    }
                }
            }
        }
        return Err(AppError::Unauthorized(GENERIC_LOGIN_FAILURE.to_string()));
    }

    // At this point, user exists and password is valid
    let user = user.expect("User must exist when is_dummy is false");

    // Check if email is verified
    if user.email_verified_at.is_none() {
        return Err(AppError::Unauthorized(
            "Please verify your email address before logging in".to_string(),
        ));
    }

    if req.service_slug.is_some() && req.org_slug.is_none() {
        return Err(AppError::BadRequest(
            "service_slug requires org_slug".to_string(),
        ));
    }

    // Validate requested tenant/service access before issuing either a full
    // session token or an MFA pre-auth token. The MFA verifier trusts these
    // claims when completing the challenge, so they must be authorized here.
    if let Some(org_slug) = &req.org_slug {
        let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), org_slug)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

        if let Some(service_slug) = &req.service_slug {
            let service =
                ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, service_slug)
                    .await?
                    .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;

            if let Some(redirect_uri) = &req.redirect_uri {
                let service_model = crate::db::models::Service::from(service.clone());
                validate_service_redirect_uri(redirect_uri, &service_model)?;
            }

            if !user.is_platform_owner {
                let has_identity = IdentityStore::find_by_user_and_provider(
                    DB::Conn(&state.db),
                    &user.id,
                    "password",
                    Some(&org.id),
                    Some(&service.id),
                )
                .await?
                .is_some();

                if !has_identity {
                    return Err(AppError::Forbidden(
                        "You do not have access to this service".to_string(),
                    ));
                }
            }
        } else {
            if req.redirect_uri.is_some() {
                return Err(AppError::BadRequest(
                    "redirect_uri requires org_slug and service_slug".to_string(),
                ));
            }

            if !user.is_platform_owner {
                let _membership = MembershipStore::find_by_org_slug_and_user(
                    DB::Conn(&state.db),
                    org_slug,
                    &user.id,
                )
                .await?
                .ok_or_else(|| {
                    AppError::Forbidden("You are not a member of this organization".to_string())
                })?;
            }
        }
    } else if req.redirect_uri.is_some() {
        return Err(AppError::BadRequest(
            "redirect_uri requires org_slug and service_slug".to_string(),
        ));
    }

    // Run risk engine evaluation
    use crate::services::risk_engine::RiskContext;
    let risk_ctx = RiskContext {
        user_id: &user.id,
        org_id: context_org_id.as_deref(),
        ip_address: &request_info.ip_address,
        user_agent: &request_info.user_agent,
        device_cookie: None, // No device cookie available during login
    };

    let risk_assessment = state
        .risk_engine
        .evaluate(DB::Conn(&state.db), risk_ctx)
        .await?;

    // Log risk assessment
    tracing::info!(
        user_id = %user.id,
        risk_score = risk_assessment.score,
        risk_action = ?risk_assessment.action,
        risk_factors = ?risk_assessment.factors,
        "Password login risk assessment"
    );

    let mfa_enabled = TotpStore::is_enabled(DB::Conn(&state.db), &user.id).await?;

    // If MFA is enabled or risk engine requires it, return pre-auth token
    if mfa_enabled
        || matches!(
            risk_assessment.action,
            crate::services::risk_engine::RiskAction::ChallengeMFA
        )
    {
        // MFA is required - we'll verify access rights after MFA completion
        // The main token generation flow will check membership or identity as appropriate

        let preauth_token = state.jwt_service.create_mfa_preauth_token(
            &user.id,
            &user.email,
            user.is_platform_owner,
            req.org_slug.as_deref(),
            req.service_slug.as_deref(),
            req.saml_state.as_deref(),
        )?;

        return Ok(Json(RefreshTokenResponse {
            access_token: preauth_token,
            refresh_token: String::new(),
            expires_in: 300, // 5 minutes
        }));
    }

    // Handle risk engine actions
    use crate::services::risk_engine::RiskAction;
    match risk_assessment.action {
        RiskAction::Allow | RiskAction::LogOnly => {
            // Continue with normal login flow
        }
        RiskAction::ChallengeMFA => {
            // Risk engine demands MFA challenge
            // Access rights will be verified after MFA completion

            let preauth_token = state.jwt_service.create_mfa_preauth_token(
                &user.id,
                &user.email,
                user.is_platform_owner,
                req.org_slug.as_deref(),
                req.service_slug.as_deref(),
                req.saml_state.as_deref(),
            )?;

            return Ok(Json(RefreshTokenResponse {
                access_token: preauth_token,
                refresh_token: String::new(),
                expires_in: 300, // 5 minutes
            }));
        }
        RiskAction::Block => {
            tracing::warn!(
                user_id = %user.id,
                risk_score = risk_assessment.score,
                factors = ?risk_assessment.factors,
                "Password login blocked by risk engine"
            );

            return Err(AppError::Forbidden(
                "Suspicious login detected. Please contact support.".to_string(),
            ));
        }
    }

    // Note: Direct password login with SAML state (no MFA) is not supported via JSON API
    // SAML flows should use the HTML authentication page at /saml/:org/:service/authenticate
    // which redirects through OAuth providers or handles password+MFA properly

    // Check MAU limit for organization logins (billing enforcement)
    if let Some(ref org_slug) = req.org_slug {
        // Fetch org to get org_id for MAU check
        let org = crate::store::organizations::OrganizationStore::find_by_slug(
            DB::Conn(&state.db),
            org_slug,
        )
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

        crate::services::tier_enforcement::TierService::check_mau_limit(
            DB::Conn(&state.db),
            &org.id,
        )
        .await?;
    }

    // Generate JWT based on context (org_slug, service_slug, or platform owner)
    let mut login_event_org_id: Option<String> = None;
    let mut login_event_service_id: Option<String> = None;

    let token = if let Some(org_slug) = &req.org_slug {
        // Resolve org for later use
        let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), org_slug)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
        login_event_org_id = Some(org.id.clone());

        // Determine service context for JWT
        let service_slug_for_token = if let Some(service_slug) = &req.service_slug {
            // Service-scoped login (end-user login to a service)
            // This path does NOT require org membership - just identity for the service
            let service =
                ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, service_slug)
                    .await?
                    .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;

            if let Some(redirect_uri) = &req.redirect_uri {
                let service_model = crate::db::models::Service::from(service.clone());
                validate_service_redirect_uri(redirect_uri, &service_model)?;
            }

            // Verify user has identity for this org+service (unless platform owner)
            if !user.is_platform_owner {
                let has_identity = IdentityStore::find_by_user_and_provider(
                    DB::Conn(&state.db),
                    &user.id,
                    "password",
                    Some(&org.id),
                    Some(&service.id),
                )
                .await?
                .is_some();

                if !has_identity {
                    return Err(AppError::Forbidden(
                        "You do not have access to this service".to_string(),
                    ));
                }
            }

            login_event_service_id = Some(service.id.clone());
            Some(service_slug.as_str())
        } else {
            if req.redirect_uri.is_some() {
                return Err(AppError::BadRequest(
                    "redirect_uri requires org_slug and service_slug".to_string(),
                ));
            }

            // Org-level login (team member login) - requires membership
            let _membership =
                MembershipStore::find_by_org_slug_and_user(DB::Conn(&state.db), org_slug, &user.id)
                    .await?
                    .ok_or_else(|| {
                        AppError::Forbidden("You are not a member of this organization".to_string())
                    })?;
            None
        };

        state.jwt_service.create_token(
            &user.id,
            &user.email,
            user.is_platform_owner,
            Some(org_slug),
            service_slug_for_token,
        )?
    } else {
        // Platform-level login (for platform owners or users without org context)
        state
            .jwt_service
            .create_token(&user.id, &user.email, user.is_platform_owner, None, None)?
    };

    // Create session with refresh token
    let token_hash = hash_token(&token);
    let refresh_token = crate::crypto::refresh_tokens::generate();
    let now = Utc::now();
    let expires_at = now + chrono::Duration::hours(state.config.jwt_expiration_hours);
    let refresh_expires_at = now + chrono::Duration::days(30);

    // Clones for transaction
    let helper_user_id = user.id.clone();
    let helper_token_hash = token_hash.clone();
    let helper_refresh_token = refresh_token.clone();
    let helper_org_slug = req.org_slug.clone();
    let helper_service_id = login_event_service_id.clone();
    let helper_ip = request_info.ip_address.clone();
    let helper_risk_action = risk_assessment.action;

    // Generate device token outside transaction to avoid recreating it on retry if possible
    let device_token = state.risk_engine.generate_device_token(&user.id);
    let helper_device_token = device_token.clone();

    // Execute session and device creation in retrying transaction
    let _device_cookie = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "login_session_create",
        |db| {
            let user_id = helper_user_id.clone();
            let token_hash = helper_token_hash.clone();
            let refresh_token = helper_refresh_token.clone();
            let org_slug = helper_org_slug.clone();
            let service_id = helper_service_id.clone();
            let ip_address = helper_ip.clone();
            let risk_action = helper_risk_action;
            let device_token = helper_device_token.clone();

            // Capture time/expirations for inside transaction consistency
            let now = Utc::now();
            let expires_at_naive = expires_at.naive_utc();
            let refresh_expires_at_naive = refresh_expires_at.naive_utc();

            Box::pin(async move {
                validate_password_login_authority(
                    db.clone(),
                    &user_id,
                    org_slug.as_deref(),
                    service_id.as_deref(),
                )
                .await?;
                SessionStore::create(
                    db.clone(),
                    &user_id,
                    &token_hash,
                    expires_at_naive,
                    Some(&refresh_token),
                    Some(refresh_expires_at_naive),
                    org_slug.as_deref(),
                    service_id.as_deref(),
                    None,
                    None,
                    None,
                )
                .await?;

                // Generate device trust cookie if risk assessment allows
                if matches!(risk_action, RiskAction::Allow) {
                    let device_cookie_value = format!(
                        "device_token={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={}",
                        device_token,
                        90 * 24 * 3600 // 90 days in seconds
                    );

                    // Store device in database
                    use crate::store::user_devices::UserDevicesStore;
                    use sha2::{Digest, Sha256};

                    let mut hasher = Sha256::new();
                    hasher.update(device_token.as_bytes());
                    let token_hash = hex::encode(hasher.finalize());

                    let device_expires = (now + chrono::Duration::days(90)).naive_utc();

                    UserDevicesStore::create(
                        db.clone(),
                        &user_id,
                        &token_hash,
                        "Password Login Device",
                        Some(ip_address),
                        device_expires,
                    )
                    .await?;

                    Ok(Some(device_cookie_value))
                } else {
                    Ok(None)
                }
            })
        },
    )
    .await?;

    // Publish login success event for webhooks
    crate::handlers::auth::oauth::publish_login_event(
        &state.event_dispatcher,
        &user.id,
        &user.email,
        login_event_org_id.as_deref(),
        login_event_service_id.as_deref(),
        Some("password"),
    )
    .await;

    Ok(Json(RefreshTokenResponse {
        access_token: token,
        refresh_token,
        expires_in: state.config.jwt_expiration_hours * 3600,
    }))
}

async fn validate_password_login_authority(
    db: DB<'_>,
    user_id: &str,
    org_slug: Option<&str>,
    service_id: Option<&str>,
) -> Result<()> {
    let user = UserStore::find_by_id(db.clone(), user_id)
        .await?
        .filter(|user| user.deleted_at.is_none())
        .ok_or_else(|| AppError::Unauthorized(GENERIC_LOGIN_FAILURE.to_string()))?;
    let Some(org_slug) = org_slug else {
        if service_id.is_some() {
            return Err(AppError::Unauthorized(GENERIC_LOGIN_FAILURE.to_string()));
        }
        return Ok(());
    };
    let org = OrganizationStore::find_by_slug(db.clone(), org_slug)
        .await?
        .filter(|org| org.status == "active")
        .ok_or_else(|| AppError::Unauthorized(GENERIC_LOGIN_FAILURE.to_string()))?;
    if user.is_platform_owner {
        return Ok(());
    }
    if let Some(service_id) = service_id {
        let has_membership = MembershipStore::find_by_org_and_user(db.clone(), &org.id, user_id)
            .await?
            .is_some();
        let has_service_identity = IdentityStore::find_by_user_and_provider(
            db,
            user_id,
            "password",
            Some(&org.id),
            Some(service_id),
        )
        .await?
        .is_some();
        if !has_membership && !has_service_identity {
            return Err(AppError::Unauthorized(GENERIC_LOGIN_FAILURE.to_string()));
        }
    } else if MembershipStore::find_by_org_and_user(db, &org.id, user_id)
        .await?
        .is_none()
    {
        return Err(AppError::Unauthorized(GENERIC_LOGIN_FAILURE.to_string()));
    }
    Ok(())
}

/// POST /api/auth/forgot-password - Request password reset
pub async fn forgot_password(
    State(state): State<AppState>,
    Json(req): Json<ForgotPasswordRequest>,
) -> Result<Json<ForgotPasswordResponse>> {
    ensure_email_delivery_configured(&state, "password reset emails")?;

    // Check email rate limit BEFORE processing the request (only if rate limiting is enabled)
    // Rate limiting is disabled when DISABLE_RATE_LIMITING=true is set
    if std::env::var("DISABLE_RATE_LIMITING")
        .unwrap_or_default()
        .to_lowercase()
        != "true"
        && crate::middleware::EMAIL_RATE_LIMITER
            .is_rate_limited_email(&req.email)
            .await
    {
        tracing::warn!("Password reset request rate limited");
        return Err(AppError::TooManyRequests(
            "Too many password reset requests. Please try again later.".to_string(),
        ));
    }

    let org_id = resolve_org_id_from_slug(&state, req.org_slug.as_deref()).await?;
    reject_upstream_only_local_auth(&state, &req.email, org_id.as_deref(), "Password reset")
        .await?;

    if let (Some(org_slug), Some(service_slug), Some(redirect_uri)) = (
        req.org_slug.as_deref(),
        req.service_slug.as_deref(),
        req.redirect_uri.as_deref(),
    ) {
        let org_id = org_id
            .as_deref()
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
        let service = ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), org_id, service_slug)
            .await?
            .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;
        let service_model = crate::db::models::Service::from(service);
        validate_service_redirect_uri(redirect_uri, &service_model)?;
        let _ = org_slug;
    }

    // Find user by email, scoped to tenant context when provided.
    let user =
        UserStore::find_by_email_with_context(DB::Conn(&state.db), &req.email, org_id.as_deref())
            .await?;

    // Always return success to prevent email enumeration
    if user.is_none() {
        return Ok(generic_password_reset_response());
    }

    let user = user.unwrap();

    // Check if user has a password (can't reset if they only use OAuth)
    if user.password_hash.is_none() {
        return Ok(generic_password_reset_response());
    }

    // Generate password reset token
    let reset_token = Uuid::new_v4().to_string();
    let token_hash = hash_token(&reset_token);
    let expires_at = Utc::now() + chrono::Duration::hours(1);

    PasswordResetStore::create(
        DB::Conn(&state.db),
        &user.id,
        &token_hash,
        &expires_at.naive_utc(),
    )
    .await?;

    // Enqueue password reset email to job queue (non-blocking)
    let reset_url = build_auth_link(
        &state.web_client_url,
        "/reset-password",
        "token",
        &reset_token,
        req.org_slug.as_deref(),
        req.service_slug.as_deref(),
        req.redirect_uri.as_deref(),
        req.state.as_deref(),
    );
    let email_subject = "Reset Your Password";
    let email_body = format!(
        "We received a request to reset your password.\n\n\
        Click the link below to reset your password:\n\n\
        {}\n\n\
        This link will expire in 1 hour.\n\n\
        If you didn't request a password reset, you can safely ignore this email.",
        reset_url
    );

    use crate::services::job_queue::JobQueueService;
    if let Err(e) = JobQueueService::enqueue_email(
        DB::Conn(&state.db),
        &user.email,
        email_subject,
        &email_body,
        None, // No HTML version
    )
    .await
    {
        tracing::error!("Failed to enqueue password reset email: {}", e);
        // Don't fail the request - we don't want to leak info about email existence
    }

    Ok(generic_password_reset_response())
}

/// POST /api/auth/reset-password - Reset password with token
async fn complete_password_reset(
    db: DB<'_>,
    token_hash: &str,
    user_id: &str,
    password_hash: &str,
) -> Result<bool> {
    if !PasswordResetStore::mark_as_used(db.clone(), token_hash).await? {
        return Ok(false);
    }
    UserStore::update_password_hash(db.clone(), user_id, password_hash).await?;
    SessionStore::delete_all_for_user(db, user_id).await?;
    Ok(true)
}

pub async fn reset_password(
    State(state): State<AppState>,
    Json400(req): Json400<ResetPasswordRequest>,
) -> Result<Json<ResetPasswordResponse>> {
    // Validate password strength
    if req.new_password.len() < 8 {
        return Err(AppError::BadRequest(
            "Password must be at least 8 characters long".to_string(),
        ));
    }

    let token_hash = hash_token(&req.token);

    // Find and validate token
    let token_record = PasswordResetStore::find_by_token_hash(DB::Conn(&state.db), &token_hash)
        .await?
        .ok_or_else(|| AppError::BadRequest("Invalid reset token".to_string()))?;

    if token_record.used {
        return Err(AppError::BadRequest(
            "Reset token has already been used".to_string(),
        ));
    }

    let expires_at: chrono::DateTime<Utc> =
        chrono::DateTime::from_naive_utc_and_offset(token_record.expires_at, Utc);

    if expires_at < Utc::now() {
        return Err(AppError::BadRequest("Reset token has expired".to_string()));
    }

    let reset_user = UserStore::find_by_id(DB::Conn(&state.db), &token_record.user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    reject_upstream_only_local_auth(
        &state,
        &reset_user.email,
        reset_user.org_id.as_deref(),
        "Password reset",
    )
    .await?;

    let password_hash =
        crate::crypto::concurrency::hash_password_bounded(req.new_password.clone()).await?;

    // Complete all fallible CPU work before the transaction. The conditional
    // token claim, password update, and session revocation then commit or roll
    // back together.
    let user_id = token_record.user_id.clone();
    let token_hash_for_transaction = token_hash.clone();
    let password_hash_for_transaction = password_hash.clone();
    let completed = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "complete_password_reset",
        |db| {
            let user_id = user_id.clone();
            let token_hash = token_hash_for_transaction.clone();
            let password_hash = password_hash_for_transaction.clone();
            Box::pin(async move {
                complete_password_reset(db, &token_hash, &user_id, &password_hash).await
            })
        },
    )
    .await?;
    if !completed {
        return Err(AppError::BadRequest(
            "Reset token has already been used".to_string(),
        ));
    }

    Ok(Json(ResetPasswordResponse {
        message: "Password has been reset successfully. Please log in with your new password."
            .to_string(),
    }))
}

/// GET /api/auth/availability - which email-dependent flows this instance
/// can actually complete, so clients disable them up front instead of
/// failing after submit (A7).
pub async fn availability(State(state): State<AppState>) -> Json<AvailabilityResponse> {
    let email = state.email_service.is_some();
    Json(AvailabilityResponse {
        password_registration: email,
        magic_link: email,
        password_reset: email,
    })
}

#[derive(Debug, Serialize)]
pub struct AvailabilityResponse {
    pub password_registration: bool,
    pub magic_link: bool,
    pub password_reset: bool,
}

/// POST /api/auth/resend-verification - Resend verification email
pub async fn resend_verification(
    State(state): State<AppState>,
    Json(req): Json<ResendVerificationRequest>,
) -> Result<Json<ResendVerificationResponse>> {
    ensure_email_delivery_configured(&state, "verification emails")?;

    // Check email rate limit
    if std::env::var("DISABLE_RATE_LIMITING")
        .unwrap_or_default()
        .to_lowercase()
        != "true"
        && crate::middleware::EMAIL_RATE_LIMITER
            .is_rate_limited_email(&req.email)
            .await
    {
        tracing::warn!("Resend verification request rate limited");
        return Err(AppError::TooManyRequests(
            "Too many requests. Please try again later.".to_string(),
        ));
    }

    let org_id = resolve_org_id_from_slug(&state, req.org_slug.as_deref()).await?;

    if let (Some(service_slug), Some(redirect_uri), Some(org_id)) = (
        req.service_slug.as_deref(),
        req.redirect_uri.as_deref(),
        org_id.as_deref(),
    ) {
        let service = ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), org_id, service_slug)
            .await?
            .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;
        let service_model = crate::db::models::Service::from(service);
        validate_service_redirect_uri(redirect_uri, &service_model)?;
    }

    // Find user by email, scoped to tenant context when provided.
    let user =
        UserStore::find_by_email_with_context(DB::Conn(&state.db), &req.email, org_id.as_deref())
            .await?;

    // If user not found, return generic success to avoid enumeration
    if user.is_none() {
        return Ok(generic_verification_response());
    }

    let user = user.unwrap();

    // If already verified, return generic success
    if user.email_verified_at.is_some() {
        return Ok(generic_verification_response());
    }

    // Generate new verification token
    let verification_token = Uuid::new_v4().to_string();
    let token_hash = hash_token(&verification_token);
    let expires_at = Utc::now() + chrono::Duration::hours(24);

    // Create new verification record
    EmailVerificationStore::create(
        DB::Conn(&state.db),
        &user.id,
        &token_hash,
        &expires_at.naive_utc(),
    )
    .await?;

    // Enqueue verification email
    let verification_url = build_auth_link(
        &state.web_client_url,
        "/verify-email",
        "token",
        &verification_token,
        req.org_slug.as_deref(),
        req.service_slug.as_deref(),
        req.redirect_uri.as_deref(),
        req.state.as_deref(),
    );
    let email_subject = "Verify Your Email Address";
    let email_body = format!(
        "Welcome back!\n\n\
        You requested a new verification link. Please verify your email address by clicking the link below:\n\n\
        {}\n\n\
        This link will expire in 24 hours.\n\n\
        If you didn't request this email, you can safely ignore it.",
        verification_url
    );

    use crate::services::job_queue::JobQueueService;
    if let Err(e) = JobQueueService::enqueue_email(
        DB::Conn(&state.db),
        &req.email,
        email_subject,
        &email_body,
        None, // No HTML version
    )
    .await
    {
        tracing::error!("Failed to enqueue verification email: {}", e);
    }

    Ok(generic_verification_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::crypto::sso::OAuthClient;

    use crate::email::{EmailService, SmtpConfig};
    use crate::entities::users;

    use crate::audit::actor::AuditHandle;
    use crate::services::{
        events::EventDispatcher, metrics::MfaMetricsService, risk_engine::RiskEngine,
    };
    use crate::store::{
        identities::IdentityStore,
        memberships::MembershipStore,
        organizations::OrganizationStore,
        services::ServiceStore,
        sessions::SessionStore,
        upstream_providers::UpstreamProviderStore,
        verified_domains::{VerifiedDomainStore, DOMAIN_LOGIN_POLICY_UPSTREAM_ONLY},
    };
    use axum::{extract::State, Extension, Json};

    use migration::{Migrator, MigratorTrait};
    use moka::future::Cache;
    use sea_orm::{ActiveModelTrait, Database, DatabaseConnection, Set};
    use std::sync::Arc;

    struct PasswordLoginFixture {
        state: AppState,
        org_id: String,
        org_slug: String,
        service_id: String,
        service_slug: String,
        email: String,
        password: String,
    }

    use crate::test_support::test_config;

    use crate::test_support::test_jwt_service;

    use crate::test_support::setup_db;

    fn hash_password(password: &str) -> String {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .expect("hash test password")
            .to_string()
    }

    async fn create_verified_org_user(
        db: &DatabaseConnection,
        org_id: &str,
        email: &str,
        password: &str,
    ) -> users::Model {
        users::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            email: Set(email.to_string()),
            org_id: Set(Some(org_id.to_string())),
            is_platform_owner: Set(false),
            password_hash: Set(Some(hash_password(password))),
            email_verified_at: Set(Some(Utc::now().naive_utc())),
            created_at: Set(Utc::now().naive_utc()),
            updated_at: Set(None),
            deleted_at: Set(None),
        }
        .insert(db)
        .await
        .expect("create verified org user")
    }

    async fn setup_password_login_fixture() -> PasswordLoginFixture {
        let db = setup_db().await;
        let config = test_config();
        let owner = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "owner@example.com",
            crate::store::users::UserCreationOptions {
                is_platform_owner: true,
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create owner")
        .0;
        let (org, _) = OrganizationStore::create_with_owner(
            DB::Conn(&db),
            "acme",
            "Acme",
            &owner.id,
            Some("tier_enterprise"),
        )
        .await
        .expect("create org");
        OrganizationStore::update_status(DB::Conn(&db), &org.id, "active")
            .await
            .expect("activate org");
        let service = ServiceStore::create(
            DB::Conn(&db),
            &org.id,
            "portal",
            "Portal",
            "web",
            "client-portal",
        )
        .await
        .expect("create service");
        let password = "CorrectHorseBatteryStaple1!";
        let email = "member@example.com";
        let user = create_verified_org_user(&db, &org.id, email, password).await;
        MembershipStore::create(DB::Conn(&db), &org.id, &user.id, "member")
            .await
            .expect("create org membership");
        IdentityStore::create(
            DB::Conn(&db),
            &user.id,
            "password",
            email,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&org.id),
            Some(&service.id),
        )
        .await
        .expect("create service-scoped password identity");

        let jwt_service = Arc::new(test_jwt_service(&config));
        let oauth_client = Arc::new(OAuthClient::new(&config).expect("create oauth client"));
        let state = AppState {
            db: db.clone(),
            #[cfg(feature = "db_sqlite")]
            db_writer: db.clone(),
            oauth_client,
            jwt_service,
            base_url: config.base_url.clone(),
            web_client_url: config.platform_dashboard_base_url.clone(),
            full_web_client_url: config.full_web_client_base_url.clone(),
            encryption: None,
            email_service: None,
            metrics_service: Arc::new(MfaMetricsService::new(db.clone())),
            event_dispatcher: Arc::new(EventDispatcher::new(db.clone())),
            billing_provider: Arc::new(DisabledBillingProvider::new()),
            risk_engine: Arc::new(RiskEngine::new().expect("create risk engine")),
            webauthn_service: None,
            permission_cache: Cache::new(10_000),
            user_cache: Cache::new(10_000),
            domain_cache: Cache::new(10_000),
            audit_actor: AuditHandle::new(db.clone()),
            config,
        };

        PasswordLoginFixture {
            state,
            org_id: org.id,
            org_slug: org.slug,
            service_id: service.id,
            service_slug: service.slug,
            email: email.to_string(),
            password: password.to_string(),
        }
    }

    async fn password_login(
        fixture: &PasswordLoginFixture,
        org_slug: Option<&str>,
        service_slug: Option<&str>,
    ) -> Result<RefreshTokenResponse> {
        let Json(response) = login(
            State(fixture.state.clone()),
            Extension(RequestInfo {
                ip_address: "127.0.0.1".to_string(),
                user_agent: "password-login-test".to_string(),
            }),
            Json400(LoginRequest {
                email: fixture.email.clone(),
                password: fixture.password.clone(),
                org_slug: org_slug.map(str::to_string),
                service_slug: service_slug.map(str::to_string),
                redirect_uri: None,
                saml_state: None,
            }),
        )
        .await?;

        Ok(response)
    }

    async fn rejected_password_login(fixture: &PasswordLoginFixture, email: &str) -> AppError {
        login(
            State(fixture.state.clone()),
            Extension(RequestInfo {
                ip_address: "127.0.0.1".to_string(),
                user_agent: "password-enumeration-test".to_string(),
            }),
            Json400(LoginRequest {
                email: email.to_string(),
                password: "DefinitelyWrongPassword1!".to_string(),
                org_slug: Some(fixture.org_slug.clone()),
                service_slug: None,
                redirect_uri: None,
                saml_state: None,
            }),
        )
        .await
        .expect_err("login must be rejected")
    }

    fn with_inert_email_service(mut state: AppState) -> AppState {
        state.email_service = Some(Arc::new(
            EmailService::from_config(SmtpConfig {
                host: "127.0.0.1".to_string(),
                port: 1025,
                username: String::new(),
                password: String::new(),
                from_email: "auth@example.com".to_string(),
                from_name: "AuthOS test".to_string(),
            })
            .expect("create inert test email service"),
        ));
        state
    }

    async fn app_error_shape(
        error: AppError,
    ) -> (
        axum::http::StatusCode,
        axum::http::HeaderMap,
        serde_json::Value,
    ) {
        let response = axum::response::IntoResponse::into_response(error);
        let status = response.status();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("read bounded error response");
        let mut body: serde_json::Value =
            serde_json::from_slice(&body).expect("parse error response");
        assert!(body
            .as_object_mut()
            .expect("error response object")
            .remove("timestamp")
            .is_some());
        (status, headers, body)
    }

    #[tokio::test]
    async fn password_login_normalizes_absent_and_passwordless_accounts() {
        let fixture = setup_password_login_fixture().await;
        users::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            email: Set("oauth-only@example.com".to_string()),
            org_id: Set(Some(fixture.org_id.clone())),
            is_platform_owner: Set(false),
            password_hash: Set(None),
            email_verified_at: Set(Some(Utc::now().naive_utc())),
            created_at: Set(Utc::now().naive_utc()),
            updated_at: Set(None),
            deleted_at: Set(None),
        }
        .insert(&fixture.state.db)
        .await
        .expect("create passwordless account");

        let absent = rejected_password_login(&fixture, "absent@example.com").await;
        let passwordless = rejected_password_login(&fixture, "oauth-only@example.com").await;
        assert!(matches!(
            absent,
            AppError::Unauthorized(ref message) if message == GENERIC_LOGIN_FAILURE
        ));
        assert!(matches!(
            passwordless,
            AppError::Unauthorized(ref message) if message == GENERIC_LOGIN_FAILURE
        ));
        assert_eq!(
            app_error_shape(absent).await,
            app_error_shape(passwordless).await
        );
    }

    #[tokio::test]
    async fn registration_normalizes_existing_and_new_accounts() {
        let fixture = setup_password_login_fixture().await;
        let state = with_inert_email_service(fixture.state.clone());

        let mut messages = Vec::new();
        for email in [&fixture.email, "new-member@example.com"] {
            let Json(response) = register(
                State(state.clone()),
                Json400(RegisterRequest {
                    email: email.to_string(),
                    password: "RegistrationPassword1!".to_string(),
                    org_slug: Some(fixture.org_slug.clone()),
                    service_slug: Some(fixture.service_slug.clone()),
                    redirect_uri: None,
                    state: None,
                }),
            )
            .await
            .expect("registration request returns generic success");
            messages.push(response.message);
        }

        assert_eq!(messages[0], GENERIC_REGISTRATION_RESPONSE);
        assert_eq!(messages[0], messages[1]);
    }

    #[tokio::test]
    async fn password_recovery_requests_normalize_account_states() {
        let fixture = setup_password_login_fixture().await;
        let state = with_inert_email_service(fixture.state.clone());

        let mut reset_messages = Vec::new();
        for email in [fixture.email.as_str(), "absent@example.com"] {
            let Json(response) = forgot_password(
                State(state.clone()),
                Json(ForgotPasswordRequest {
                    email: email.to_string(),
                    org_slug: Some(fixture.org_slug.clone()),
                    service_slug: None,
                    redirect_uri: None,
                    state: None,
                }),
            )
            .await
            .expect("forgot-password request returns generic success");
            reset_messages.push(response.message);
        }
        assert_eq!(reset_messages[0], GENERIC_PASSWORD_RESET_RESPONSE);
        assert_eq!(reset_messages[0], reset_messages[1]);

        let mut verification_messages = Vec::new();
        for email in [fixture.email.as_str(), "another-absent@example.com"] {
            let Json(response) = resend_verification(
                State(state.clone()),
                Json(ResendVerificationRequest {
                    email: email.to_string(),
                    org_slug: Some(fixture.org_slug.clone()),
                    service_slug: None,
                    redirect_uri: None,
                    state: None,
                }),
            )
            .await
            .expect("resend-verification request returns generic success");
            verification_messages.push(response.message);
        }
        assert_eq!(verification_messages[0], GENERIC_VERIFICATION_RESPONSE);
        assert_eq!(verification_messages[0], verification_messages[1]);
    }

    #[test]
    fn public_email_workflow_messages_are_generic_and_stable() {
        assert_eq!(
            generic_registration_response().0.message,
            GENERIC_REGISTRATION_RESPONSE
        );
        assert_eq!(
            generic_password_reset_response().0.message,
            GENERIC_PASSWORD_RESET_RESPONSE
        );
        assert_eq!(
            generic_verification_response().0.message,
            GENERIC_VERIFICATION_RESPONSE
        );
    }

    #[tokio::test]
    async fn org_scoped_password_login_issues_org_claims_and_session_scope() {
        let fixture = setup_password_login_fixture().await;
        let response = password_login(&fixture, Some(&fixture.org_slug), None)
            .await
            .expect("org-scoped password login succeeds");

        let claims = fixture
            .state
            .jwt_service
            .validate_token(&response.access_token)
            .expect("validate login token");
        assert_eq!(claims.email, fixture.email);
        assert_eq!(claims.org.as_deref(), Some(fixture.org_slug.as_str()));
        assert_eq!(claims.service, None);
        assert_eq!(claims.aud.as_deref(), Some("org:acme"));

        let session = SessionStore::find_by_token_hash(
            DB::Conn(&fixture.state.db),
            &hash_token(&response.access_token),
        )
        .await
        .expect("query login session")
        .expect("login session exists");
        assert_eq!(session.org_slug.as_deref(), Some(fixture.org_slug.as_str()));
        assert_eq!(session.service_id, None);
    }

    #[tokio::test]
    async fn service_scoped_password_login_issues_service_claims_and_session_scope() {
        let fixture = setup_password_login_fixture().await;
        let response = password_login(
            &fixture,
            Some(&fixture.org_slug),
            Some(&fixture.service_slug),
        )
        .await
        .expect("service-scoped password login succeeds");

        let claims = fixture
            .state
            .jwt_service
            .validate_token(&response.access_token)
            .expect("validate login token");
        assert_eq!(claims.org.as_deref(), Some(fixture.org_slug.as_str()));
        assert_eq!(
            claims.service.as_deref(),
            Some(fixture.service_slug.as_str())
        );
        assert_eq!(claims.aud.as_deref(), Some("service:acme/portal"));

        let session = SessionStore::find_by_token_hash(
            DB::Conn(&fixture.state.db),
            &hash_token(&response.access_token),
        )
        .await
        .expect("query login session")
        .expect("login session exists");
        assert_eq!(session.org_slug.as_deref(), Some(fixture.org_slug.as_str()));
        assert_eq!(
            session.service_id.as_deref(),
            Some(fixture.service_id.as_str())
        );
    }

    #[tokio::test]
    async fn password_session_boundary_rechecks_deleted_user_and_service_entitlement() {
        let fixture = setup_password_login_fixture().await;
        let user = UserStore::find_by_email(DB::Conn(&fixture.state.db), &fixture.email)
            .await
            .unwrap()
            .unwrap();

        assert!(validate_password_login_authority(
            DB::Conn(&fixture.state.db),
            &user.id,
            Some(&fixture.org_slug),
            Some(&fixture.service_id),
        )
        .await
        .is_ok());
        IdentityStore::delete_by_user_and_service(
            DB::Conn(&fixture.state.db),
            &user.id,
            &fixture.service_id,
        )
        .await
        .unwrap();
        assert!(validate_password_login_authority(
            DB::Conn(&fixture.state.db),
            &user.id,
            Some(&fixture.org_slug),
            Some(&fixture.service_id),
        )
        .await
        .is_ok());
        MembershipStore::delete_by_org_and_user(
            DB::Conn(&fixture.state.db),
            &fixture.org_id,
            &user.id,
        )
        .await
        .unwrap();
        assert!(validate_password_login_authority(
            DB::Conn(&fixture.state.db),
            &user.id,
            Some(&fixture.org_slug),
            Some(&fixture.service_id),
        )
        .await
        .is_err());

        let user_id = user.id.clone();
        let mut deleted_user: users::ActiveModel = user.into();
        deleted_user.deleted_at = Set(Some(Utc::now().naive_utc()));
        deleted_user.update(&fixture.state.db).await.unwrap();
        assert!(validate_password_login_authority(
            DB::Conn(&fixture.state.db),
            &user_id,
            Some(&fixture.org_slug),
            None,
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn password_login_rejects_inactive_org_context() {
        let fixture = setup_password_login_fixture().await;
        OrganizationStore::update_status(DB::Conn(&fixture.state.db), &fixture.org_id, "suspended")
            .await
            .expect("suspend org");

        let error = password_login(&fixture, Some(&fixture.org_slug), None)
            .await
            .expect_err("suspended org login should fail");

        assert!(matches!(
            error,
            AppError::Forbidden(ref message) if message.contains("Organization is not active")
        ));
    }

    #[tokio::test]
    async fn password_login_rejects_upstream_only_managed_domain() {
        let fixture = setup_password_login_fixture().await;
        let provider = UpstreamProviderStore::create(
            DB::Conn(&fixture.state.db),
            "provider-1",
            &fixture.org_id,
            "acme-oidc",
            "Acme OIDC",
            "oidc",
            "client-id",
            Vec::new(),
            "test-key",
            Some("https://idp.example.com/authorize"),
            Some("https://idp.example.com/token"),
            Some("https://idp.example.com/userinfo"),
            None,
            Some("openid email profile"),
            Some("https://idp.example.com"),
            None,
        )
        .await
        .expect("create upstream provider");
        let domain = VerifiedDomainStore::create(
            DB::Conn(&fixture.state.db),
            "domain-1",
            &fixture.org_id,
            "example.com",
            "verify-token",
            Some(&provider.id),
            Some(DOMAIN_LOGIN_POLICY_UPSTREAM_ONLY),
        )
        .await
        .expect("create managed domain");
        VerifiedDomainStore::mark_verified(DB::Conn(&fixture.state.db), &domain.id)
            .await
            .expect("verify managed domain");

        let error = password_login(&fixture, Some(&fixture.org_slug), None)
            .await
            .expect_err("upstream-only managed domain should reject password login");

        assert!(matches!(
            error,
            AppError::Forbidden(ref message) if message.contains("Password login is disabled")
        ));
    }

    async fn create_upstream_only_domain(fixture: &PasswordLoginFixture) {
        let provider = UpstreamProviderStore::create(
            DB::Conn(&fixture.state.db),
            &Uuid::new_v4().to_string(),
            &fixture.org_id,
            "acme-oidc",
            "Acme OIDC",
            "oidc",
            "client-id",
            Vec::new(),
            "test-key",
            Some("https://idp.example.com/authorize"),
            Some("https://idp.example.com/token"),
            Some("https://idp.example.com/userinfo"),
            None,
            Some("openid email profile"),
            Some("https://idp.example.com"),
            None,
        )
        .await
        .expect("create upstream provider");
        let domain = VerifiedDomainStore::create(
            DB::Conn(&fixture.state.db),
            &Uuid::new_v4().to_string(),
            &fixture.org_id,
            "example.com",
            "verify-token",
            Some(&provider.id),
            Some(DOMAIN_LOGIN_POLICY_UPSTREAM_ONLY),
        )
        .await
        .expect("create managed domain");
        VerifiedDomainStore::mark_verified(DB::Conn(&fixture.state.db), &domain.id)
            .await
            .expect("verify managed domain");
    }

    #[tokio::test]
    async fn reset_password_rejects_upstream_only_managed_domain() {
        let fixture = setup_password_login_fixture().await;
        create_upstream_only_domain(&fixture).await;
        let user = UserStore::find_by_email_with_context(
            DB::Conn(&fixture.state.db),
            &fixture.email,
            Some(&fixture.org_id),
        )
        .await
        .expect("find fixture user")
        .expect("fixture user exists");
        let reset_token = "reset-token";
        PasswordResetStore::create(
            DB::Conn(&fixture.state.db),
            &user.id,
            &hash_token(reset_token),
            &(Utc::now() + chrono::Duration::hours(1)).naive_utc(),
        )
        .await
        .expect("create reset token");

        let error = reset_password(
            State(fixture.state.clone()),
            Json400(ResetPasswordRequest {
                token: reset_token.to_string(),
                new_password: "NewCorrectHorseBatteryStaple1!".to_string(),
            }),
        )
        .await
        .expect_err("upstream-only managed domain should reject password reset");

        assert!(matches!(
            error,
            AppError::Forbidden(ref message) if message.contains("Password reset is disabled")
        ));
    }

    #[tokio::test]
    async fn magic_link_guard_rejects_upstream_only_managed_domain() {
        let fixture = setup_password_login_fixture().await;
        create_upstream_only_domain(&fixture).await;

        let error = reject_upstream_only_local_auth(
            &fixture.state,
            &fixture.email,
            Some(&fixture.org_id),
            "Magic-link sign-in",
        )
        .await
        .expect_err("upstream-only managed domain should reject magic-link sign-in");

        assert!(matches!(
            error,
            AppError::Forbidden(ref message) if message.contains("Magic-link sign-in is disabled")
        ));
    }

    #[tokio::test]
    async fn email_verification_failure_rolls_back_the_one_time_claim() {
        use sea_orm::TransactionTrait;

        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        let user = UserStore::create(DB::Conn(&db), "atomic-verify@example.test", None, false)
            .await
            .unwrap();
        EmailVerificationStore::create(
            DB::Conn(&db),
            &user.id,
            "atomic-verify-hash",
            &(Utc::now() + chrono::Duration::minutes(5)).naive_utc(),
        )
        .await
        .unwrap();

        let transaction = db.begin().await.unwrap();
        assert!(complete_email_verification(
            DB::Tx(&transaction),
            "atomic-verify-hash",
            "missing-user"
        )
        .await
        .is_err());
        transaction.rollback().await.unwrap();

        assert!(
            !EmailVerificationStore::find_by_token_hash(DB::Conn(&db), "atomic-verify-hash")
                .await
                .unwrap()
                .unwrap()
                .used
        );
        assert_eq!(
            UserStore::find_by_id(DB::Conn(&db), &user.id)
                .await
                .unwrap()
                .unwrap()
                .email_verified_at,
            None
        );
    }

    #[tokio::test]
    async fn password_reset_failure_rolls_back_claim_and_password_update() {
        use sea_orm::{ConnectionTrait, TransactionTrait};

        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        let user = UserStore::create(
            DB::Conn(&db),
            "atomic-reset@example.test",
            Some("old-password-hash".to_string()),
            false,
        )
        .await
        .unwrap();
        PasswordResetStore::create(
            DB::Conn(&db),
            &user.id,
            "atomic-reset-hash",
            &(Utc::now() + chrono::Duration::minutes(5)).naive_utc(),
        )
        .await
        .unwrap();
        db.execute_unprepared("DROP TABLE sessions").await.unwrap();

        let transaction = db.begin().await.unwrap();
        assert!(complete_password_reset(
            DB::Tx(&transaction),
            "atomic-reset-hash",
            &user.id,
            "new-password-hash"
        )
        .await
        .is_err());
        transaction.rollback().await.unwrap();

        assert!(
            !PasswordResetStore::find_by_token_hash(DB::Conn(&db), "atomic-reset-hash")
                .await
                .unwrap()
                .unwrap()
                .used
        );
        assert_eq!(
            UserStore::find_by_id(DB::Conn(&db), &user.id)
                .await
                .unwrap()
                .unwrap()
                .password_hash
                .as_deref(),
            Some("old-password-hash")
        );
    }

    #[tokio::test]
    async fn password_reset_is_user_bound_and_revokes_every_target_session() {
        use crate::store::sessions::SessionStore;
        use sea_orm::TransactionTrait;

        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        let owner = UserStore::create(DB::Conn(&db), "reset-owner@example.test", None, true)
            .await
            .unwrap();
        let org_a =
            OrganizationStore::create(DB::Conn(&db), "reset-context-a", "Reset A", &owner.id, None)
                .await
                .unwrap();
        let org_b =
            OrganizationStore::create(DB::Conn(&db), "reset-context-b", "Reset B", &owner.id, None)
                .await
                .unwrap();
        let target = UserStore::create_with_org_id(
            DB::Conn(&db),
            "same-reset@example.test",
            Some("target-old".to_string()),
            &org_a.id,
        )
        .await
        .unwrap();
        let other = UserStore::create_with_org_id(
            DB::Conn(&db),
            "same-reset@example.test",
            Some("other-old".to_string()),
            &org_b.id,
        )
        .await
        .unwrap();
        let expiry = (Utc::now() + chrono::Duration::hours(1)).naive_utc();
        for (user_id, token_hash) in [
            (&target.id, "target-session-a"),
            (&target.id, "target-session-b"),
            (&other.id, "other-session"),
        ] {
            SessionStore::create(
                DB::Conn(&db),
                user_id,
                token_hash,
                expiry,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        }
        PasswordResetStore::create(
            DB::Conn(&db),
            &target.id,
            "target-reset-hash",
            &(Utc::now() + chrono::Duration::minutes(5)).naive_utc(),
        )
        .await
        .unwrap();

        let transaction = db.begin().await.unwrap();
        assert!(complete_password_reset(
            DB::Tx(&transaction),
            "target-reset-hash",
            &target.id,
            "target-new"
        )
        .await
        .unwrap());
        transaction.commit().await.unwrap();

        assert_eq!(
            UserStore::find_by_id(DB::Conn(&db), &target.id)
                .await
                .unwrap()
                .unwrap()
                .password_hash
                .as_deref(),
            Some("target-new")
        );
        assert_eq!(
            UserStore::find_by_id(DB::Conn(&db), &other.id)
                .await
                .unwrap()
                .unwrap()
                .password_hash
                .as_deref(),
            Some("other-old")
        );
        assert!(SessionStore::list_by_user(DB::Conn(&db), &target.id)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            SessionStore::list_by_user(DB::Conn(&db), &other.id)
                .await
                .unwrap()
                .len(),
            1
        );
    }
}
