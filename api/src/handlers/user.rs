use crate::crypto::mfa::MfaService;
use crate::db::transaction::{with_deadlock_retry, with_retrying_transaction};
use crate::db::DB;
use crate::encryption::EncryptionService;
use crate::entities::prelude::{TotpBackupCodes, UserDevices, UserTotpSecrets};
use crate::entities::{mfa_audit_log, totp_backup_codes, user_devices, user_totp_secrets, users};
use crate::error::{AppError, Result};
use crate::handlers::auth::email_delivery::ensure_email_delivery_configured;
use crate::handlers::auth::password::hash_token;
use crate::middleware::RequestInfo;
use crate::services::audit_builder::MfaAuditBuilder;
use crate::services::job_queue::JobQueueService;
use crate::services::permission_service::PermissionService;
use crate::state::AppState;
use crate::store::{
    email_verification::EmailVerificationStore, organizations::OrganizationStore,
    sessions::SessionStore, totp::TotpStore, user_devices::UserDevicesStore, users::UserStore,
};
use axum::{
    extract::{Extension, Query, State},
    Json,
};
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, QuerySelect, Set, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uuid::Uuid;

const ACCOUNT_SECURITY_REAUTH_WINDOW_MINUTES: i64 = 10;

#[derive(Debug, Deserialize, Default)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
    /// Required when the account has a password. The generated SDK/UI prompts
    /// for this when changing the account email.
    #[serde(default)]
    pub current_password: Option<String>,
    /// Required when MFA is enabled.
    #[serde(default)]
    pub mfa_code: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct MfaSetupRequest {
    #[serde(default)]
    pub current_password: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct MfaConfirmationRequest {
    #[serde(default)]
    pub mfa_code: Option<String>,
}

async fn verify_current_password_if_configured(
    user: &crate::entities::users::Model,
    current_password: Option<&str>,
) -> Result<()> {
    let Some(expected_hash) = user.password_hash.as_ref() else {
        return Ok(());
    };
    let password = current_password
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AppError::Forbidden("Current password is required for this account change".to_string())
        })?;
    let is_valid = crate::crypto::concurrency::verify_password_bounded(
        password.to_string(),
        expected_hash.clone(),
    )
    .await?;
    if !is_valid {
        return Err(AppError::Unauthorized(
            "Current password is incorrect".to_string(),
        ));
    }
    Ok(())
}

async fn verify_mfa_step_up(
    state: &AppState,
    user_id: &str,
    org_slug: Option<&str>,
    mfa_code: Option<&str>,
) -> Result<()> {
    if !TotpStore::is_enabled(DB::Conn(&state.db), user_id).await? {
        return Ok(());
    }
    let code = mfa_code
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AppError::Forbidden(
                "A current MFA code is required for this account change".to_string(),
            )
        })?;
    let backup_event = MfaAuditBuilder::new(user_id, "backup_code_used")
        .org_id(org_slug)
        .success(true)
        .details(Some("context:account_security_step_up"))
        .build();
    if crate::handlers::user::verify_mfa_code_with_backup_audit(
        &state.db,
        user_id,
        code,
        (&state.audit_actor, backup_event),
    )
    .await?
    .is_none()
    {
        return Err(AppError::Unauthorized("Invalid MFA code".to_string()));
    }
    state
        .audit_actor
        .log_mfa(
            MfaAuditBuilder::new(user_id, "mfa_verify_success")
                .org_id(org_slug)
                .success(true)
                .details(Some("context:account_security_step_up"))
                .build(),
        )
        .await?;
    Ok(())
}

async fn issue_post_factor_change_session(
    state: &AppState,
    auth_user: &crate::middleware::AuthUser,
    user: &crate::entities::users::Model,
) -> Result<(String, String, i64)> {
    if auth_user.claims.service.is_some() {
        return Err(AppError::Forbidden(
            "Service-scoped sessions cannot change account MFA factors".to_string(),
        ));
    }

    SessionStore::delete_all_for_user(DB::Conn(&state.db), &user.id).await?;
    let access_token = state.jwt_service.create_mfa_verified_token(
        &user.id,
        &user.email,
        user.is_platform_owner,
        auth_user.claims.org.as_deref(),
        None,
    )?;
    let refresh_token = crate::crypto::refresh_tokens::generate();
    let now = Utc::now();
    let expires_at = now + chrono::Duration::hours(state.config.jwt_expiration_hours);
    let refresh_expires_at = now + chrono::Duration::days(30);
    SessionStore::create(
        DB::Conn(&state.db),
        &user.id,
        &hash_token(&access_token),
        expires_at.naive_utc(),
        Some(&refresh_token),
        Some(refresh_expires_at.naive_utc()),
        auth_user.claims.org.as_deref(),
        None,
        None,
        Some(&auth_user.user_agent),
        Some(&auth_user.ip_address),
    )
    .await?;

    Ok((
        access_token,
        refresh_token,
        state.config.jwt_expiration_hours * 3600,
    ))
}

async fn require_account_security_reauthentication(
    state: &AppState,
    auth_user: &crate::middleware::AuthUser,
    current_password: Option<&str>,
    mfa_code: Option<&str>,
) -> Result<()> {
    crate::middleware::require_recent_authentication(
        &state.db,
        auth_user,
        chrono::Duration::minutes(ACCOUNT_SECURITY_REAUTH_WINDOW_MINUTES),
    )
    .await?;
    // Do not rely on the request's 30-second cached user snapshot for a
    // security-sensitive password check.
    let live_user = UserStore::find_by_id(DB::Conn(&state.db), &auth_user.user.id)
        .await?
        .filter(|user| user.deleted_at.is_none())
        .ok_or_else(|| AppError::Unauthorized("User is no longer active".to_string()))?;
    verify_current_password_if_configured(&live_user, current_password).await?;
    verify_mfa_step_up(
        state,
        &live_user.id,
        auth_user.claims.org.as_deref(),
        mfa_code,
    )
    .await
}

#[derive(Debug, Deserialize)]
pub struct ListDevicesQuery {
    pub page: Option<u64>,
    pub limit: Option<u64>,
    pub sort_by: Option<String>,
    pub sort_order: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RevokeDeviceRequest {
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateDeviceNameRequest {
    pub device_name: String,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub is_platform_owner: bool,
    pub email_verified_at: Option<String>,
    pub created_at: String,
    pub org: String,                   // Organization slug from JWT
    pub service: String,               // Service slug from JWT
    pub permissions: Vec<String>,      // User permissions from cache
    pub plan: Option<String>,          // Current plan name (if in org/service context)
    pub features: Option<Vec<String>>, // Plan features (if in org/service context)
}

#[derive(Debug, Serialize)]
pub struct MfaStatusResponse {
    pub enabled: bool,
    pub has_backup_codes: bool,
}

#[derive(Debug, Serialize)]
pub struct MfaSetupResponse {
    pub secret: String,
    pub qr_code_svg: String,
    pub qr_code_uri: String,
}

#[derive(Debug, Deserialize)]
pub struct MfaVerifyRequest {
    pub code: String,
}

#[derive(Debug, Serialize)]
pub struct MfaVerifyResponse {
    pub enabled: bool,
    pub backup_codes: Vec<String>,
    /// New session credentials after a factor change. The previous session is
    /// revoked so a session that enrolled or removed a factor cannot outlive
    /// the factor state it was created under.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct BackupCodesResponse {
    pub backup_codes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct UserDeviceResponse {
    pub id: String,
    pub device_name: String,
    pub first_seen_at: String,
    pub last_used_at: String,
    pub expires_at: String,
    pub registration_ip: Option<String>,
    pub risk_score: i32,
    pub is_trusted: bool,
}

async fn effective_user_permissions(
    state: &AppState,
    auth_user: &crate::middleware::AuthUser,
) -> Result<Vec<String>> {
    let mut permissions: HashSet<String> = auth_user.permissions.iter().cloned().collect();

    if let Some(org_slug) = &auth_user.claims.org {
        if let Some(org) = OrganizationStore::find_by_slug(DB::Conn(&state.db), org_slug).await? {
            for capability in PermissionService::get_user_capabilities(
                DB::Conn(&state.db),
                &org.id,
                &auth_user.user.id,
            )
            .await?
            {
                permissions.insert(capability);
            }
        }
    }

    let mut permissions = permissions.into_iter().collect::<Vec<_>>();
    permissions.sort();
    Ok(permissions)
}

#[derive(Debug, Serialize)]
pub struct ListDevicesResponse {
    pub devices: Vec<UserDeviceResponse>,
    pub total: u64,
    pub page: u64,
    pub limit: u64,
}

#[derive(Debug, Serialize)]
pub struct RevokeDeviceResponse {
    pub message: String,
    pub success: bool,
}

/// Calculate risk score for a device based on its characteristics
/// Returns a score from 0-100 where:
/// - 0-30: Low risk
/// - 31-70: Medium risk
/// - 71-100: High risk
fn calculate_device_risk_score(
    created_at: chrono::NaiveDateTime,
    last_seen_at: chrono::NaiveDateTime,
    is_trusted: bool,
    expires_at: chrono::NaiveDateTime,
) -> i32 {
    let mut risk_score = 0i32;

    // Parse timestamps
    let now = Utc::now();
    let created: chrono::DateTime<Utc> =
        chrono::DateTime::from_naive_utc_and_offset(created_at, Utc);
    let last_seen: chrono::DateTime<Utc> =
        chrono::DateTime::from_naive_utc_and_offset(last_seen_at, Utc);
    let expiry: chrono::DateTime<Utc> =
        chrono::DateTime::from_naive_utc_and_offset(expires_at, Utc);

    // Factor 1: Device age (newer devices are slightly riskier)
    let age_days = (now.timestamp() - created.timestamp()) / 86400;
    if age_days < 1 {
        risk_score += 15; // Brand new device
    } else if age_days < 7 {
        risk_score += 10; // Less than a week old
    } else if age_days < 30 {
        risk_score += 5; // Less than a month old
    }
    // Older devices get 0 points (established devices are safer)

    // Factor 2: Last activity (inactive devices are riskier)
    let inactive_days = (now.timestamp() - last_seen.timestamp()) / 86400;
    if inactive_days > 90 {
        risk_score += 30; // Inactive for 3+ months is very risky
    } else if inactive_days > 30 {
        risk_score += 20; // Inactive for 1+ month
    } else if inactive_days > 7 {
        risk_score += 10; // Inactive for 1+ week
    }

    // Factor 3: Trust status (major factor)
    if !is_trusted {
        risk_score += 25; // Untrusted devices are riskier
    }

    // Factor 4: Expiry status
    if expiry.timestamp() < now.timestamp() {
        risk_score += 20; // Expired devices should not be used
    } else {
        let days_until_expiry = (expiry.timestamp() - now.timestamp()) / 86400;
        if days_until_expiry < 7 {
            risk_score += 10; // Expiring soon
        }
    }

    // Cap at 100
    risk_score.min(100)
}

/// GET /api/user/mfa/status - Check if MFA is enabled for the authenticated user
pub async fn get_mfa_status(
    State(state): State<AppState>,
    auth_user: Option<axum::extract::Extension<crate::middleware::AuthUser>>,
) -> Result<Json<MfaStatusResponse>> {
    let auth_user = auth_user
        .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))?
        .0;

    let totp_secret = UserTotpSecrets::find()
        .filter(user_totp_secrets::Column::UserId.eq(&auth_user.user.id))
        .one(&state.db)
        .await?;

    let has_backup_codes = if totp_secret.is_some() {
        let count = TotpBackupCodes::find()
            .filter(totp_backup_codes::Column::UserId.eq(&auth_user.user.id))
            .filter(totp_backup_codes::Column::Used.eq(false))
            .count(&state.db)
            .await?;
        count > 0
    } else {
        false
    };

    Ok(Json(MfaStatusResponse {
        enabled: totp_secret.is_some_and(|s| s.enabled),
        has_backup_codes,
    }))
}

/// POST /api/user/mfa/setup - Initiate TOTP setup (generates secret and QR code)
#[axum::debug_handler]
pub async fn setup_mfa(
    State(state): State<AppState>,
    auth_user: Option<axum::extract::Extension<crate::middleware::AuthUser>>,
    request_info: Extension<RequestInfo>,
    request: Option<Json<MfaSetupRequest>>,
) -> Result<Json<MfaSetupResponse>> {
    let auth_user = auth_user
        .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))?
        .0;
    let request = request.map(|Json(request)| request).unwrap_or_default();
    let live_user = UserStore::find_by_id(DB::Conn(&state.db), &auth_user.user.id)
        .await?
        .filter(|user| user.deleted_at.is_none())
        .ok_or_else(|| AppError::Unauthorized("User is no longer active".to_string()))?;

    let existing_secret = UserTotpSecrets::find()
        .filter(user_totp_secrets::Column::UserId.eq(&auth_user.user.id))
        .one(&state.db)
        .await?;
    if existing_secret
        .as_ref()
        .is_some_and(|secret| secret.enabled)
    {
        return Err(AppError::BadRequest(
            "MFA is already enabled. Disable the current factor before enrolling a new one."
                .to_string(),
        ));
    }

    crate::middleware::require_recent_authentication(
        &state.db,
        &auth_user,
        chrono::Duration::minutes(ACCOUNT_SECURITY_REAUTH_WINDOW_MINUTES),
    )
    .await?;
    verify_current_password_if_configured(&live_user, request.current_password.as_deref()).await?;

    let mfa_service = MfaService::new();
    let secret = mfa_service.generate_totp_secret().map_err(|e| {
        AppError::InternalServerError(format!("Failed to generate TOTP secret: {}", e))
    })?;

    let qr_code_svg = mfa_service
        .generate_qr_code_svg(&secret, &live_user.email)
        .map_err(|e| AppError::InternalServerError(format!("Failed to generate QR code: {}", e)))?;
    let qr_code_uri = mfa_service
        .create_totp(&secret, &live_user.email)
        .map_err(|e| AppError::InternalServerError(format!("Failed to create TOTP: {}", e)))?
        .get_url();

    let encryption_service = EncryptionService::new().map_err(|e| {
        AppError::InternalServerError(format!("Failed to initialize encryption: {}", e))
    })?;

    let event = MfaAuditBuilder::new(&auth_user.user.id, "mfa_setup_initiated")
        .org_id(auth_user.claims.org.as_deref())
        .ip_address(Some(&request_info.ip_address))
        .user_agent(Some(request_info.user_agent.clone()))
        .success(true)
        .build();
    let transaction = state.db.begin().await?;
    if let Some(existing) = existing_secret {
        let secret_encrypted = encryption_service
            .encrypt_with_context(
                &secret,
                crate::encryption::EncryptionContext::new(
                    "user_totp_secrets",
                    &existing.id,
                    "secret_encrypted",
                ),
            )
            .map_err(|e| {
                AppError::InternalServerError(format!("Failed to encrypt secret: {}", e))
            })?;
        let mut existing_active: user_totp_secrets::ActiveModel = existing.into();
        existing_active.secret_encrypted = Set(secret_encrypted);
        existing_active.encryption_key_id = Set(encryption_service.key_id().to_string());
        existing_active.enabled = Set(false);
        existing_active.enabled_at = Set(None);
        existing_active.update(&transaction).await?;
    } else {
        let secret_id = Uuid::new_v4().to_string();
        let secret_encrypted = encryption_service
            .encrypt_with_context(
                &secret,
                crate::encryption::EncryptionContext::new(
                    "user_totp_secrets",
                    &secret_id,
                    "secret_encrypted",
                ),
            )
            .map_err(|e| {
                AppError::InternalServerError(format!("Failed to encrypt secret: {}", e))
            })?;
        let new_secret = user_totp_secrets::ActiveModel {
            id: Set(secret_id),
            user_id: Set(auth_user.user.id.clone()),
            secret_encrypted: Set(secret_encrypted),
            encryption_key_id: Set(encryption_service.key_id().to_string()),
            enabled: Set(false),
            ..Default::default()
        };
        new_secret.insert(&transaction).await?;
    }
    state
        .audit_actor
        .log_mfa_with_db(DB::Tx(&transaction), event)
        .await?;
    transaction.commit().await?;

    Ok(Json(MfaSetupResponse {
        secret,
        qr_code_svg,
        qr_code_uri,
    }))
}

/// POST /api/user/mfa/verify - Verify TOTP code and enable MFA
#[axum::debug_handler]
pub async fn verify_and_enable_mfa(
    State(state): State<AppState>,
    auth_user: Option<axum::extract::Extension<crate::middleware::AuthUser>>,
    request_info: Extension<RequestInfo>,
    Json(req): Json<MfaVerifyRequest>,
) -> Result<Json<MfaVerifyResponse>> {
    let auth_user = auth_user
        .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))?
        .0;
    let live_user = UserStore::find_by_id(DB::Conn(&state.db), &auth_user.user.id)
        .await?
        .filter(|user| user.deleted_at.is_none())
        .ok_or_else(|| AppError::Unauthorized("User is no longer active".to_string()))?;
    crate::middleware::require_recent_authentication(
        &state.db,
        &auth_user,
        chrono::Duration::minutes(ACCOUNT_SECURITY_REAUTH_WINDOW_MINUTES),
    )
    .await?;

    let totp_secret = UserTotpSecrets::find()
        .filter(user_totp_secrets::Column::UserId.eq(&auth_user.user.id))
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            AppError::BadRequest(
                "MFA not set up. Please call /api/user/mfa/setup first".to_string(),
            )
        })?;

    if totp_secret.enabled {
        return Err(AppError::BadRequest("MFA is already enabled".to_string()));
    }

    let encryption_service = EncryptionService::new().map_err(|e| {
        AppError::InternalServerError(format!("Failed to initialize encryption: {}", e))
    })?;
    let secret = encryption_service
        .decrypt_with_context(
            &totp_secret.secret_encrypted,
            crate::encryption::EncryptionContext::new(
                "user_totp_secrets",
                &totp_secret.id,
                "secret_encrypted",
            ),
        )
        .map_err(|e| AppError::InternalServerError(format!("Failed to decrypt secret: {}", e)))?;

    let mfa_service = MfaService::new();
    let is_valid = mfa_service
        .verify_totp(&secret, &req.code, &live_user.email)
        .map_err(|e| AppError::InternalServerError(format!("Failed to verify TOTP: {}", e)))?;

    if !is_valid {
        // Non-blocking audit via actor
        let event = MfaAuditBuilder::new(&auth_user.user.id, "mfa_verify_failed")
            .org_id(auth_user.claims.org.as_deref())
            .ip_address(Some(&request_info.ip_address))
            .user_agent(Some(request_info.user_agent.clone()))
            .success(false)
            .details(Some("method:totp,reason:invalid_code"))
            .build();
        state.audit_actor.log_mfa(event).await?;

        return Err(AppError::BadRequest("Invalid TOTP code".to_string()));
    }

    let backup_codes = mfa_service.generate_backup_codes();
    let formatted_codes = MfaService::format_backup_codes(&backup_codes);

    // Pre-hash all backup codes before the transaction to avoid doing work inside retry loop
    let mut backup_code_hashes: Vec<(String, String)> = Vec::new();
    for code in &backup_codes {
        let code_hash = crate::crypto::concurrency::hash_password_bounded(code.clone()).await?;
        backup_code_hashes.push((Uuid::new_v4().to_string(), code_hash));
    }

    let org_id = auth_user.claims.org.as_deref();
    let mfa_enabled_event = MfaAuditBuilder::new(&auth_user.user.id, "mfa_enabled")
        .org_id(org_id)
        .ip_address(Some(&request_info.ip_address))
        .user_agent(Some(request_info.user_agent.clone()))
        .success(true)
        .details(Some("totp"))
        .build();
    let backup_event = MfaAuditBuilder::new(&auth_user.user.id, "backup_codes_generated")
        .org_id(org_id)
        .ip_address(Some(&request_info.ip_address))
        .user_agent(Some(request_info.user_agent.clone()))
        .success(true)
        .details(Some(&format!("count:{}", backup_codes.len())))
        .build();

    let db = &state.db;
    let helper_user_id = auth_user.user.id.clone();
    let helper_totp_secret_id = totp_secret.id.clone();
    let helper_backup_hashes = backup_code_hashes.clone();

    with_retrying_transaction(
        db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "verify_and_enable_mfa",
        |db| {
            let user_id = helper_user_id.clone();
            let totp_secret_id = helper_totp_secret_id.clone();
            let backup_hashes = helper_backup_hashes.clone();
            let mfa_enabled_event = mfa_enabled_event.clone();
            let backup_event = backup_event.clone();
            let audit_actor = state.audit_actor.clone();

            Box::pin(async move {
                // Re-fetch the totp_secret inside the transaction to get fresh data
                let current_secret = UserTotpSecrets::find_by_id(&totp_secret_id)
                    .one(&db)
                    .await?
                    .ok_or_else(|| {
                        AppError::BadRequest("MFA setup expired, please retry".to_string())
                    })?;

                let mut totp_active: user_totp_secrets::ActiveModel = current_secret.into();
                totp_active.enabled = Set(true);
                totp_active.enabled_at = Set(Some(Utc::now().naive_utc()));
                totp_active.update(&db).await?;

                TotpBackupCodes::delete_many()
                    .filter(totp_backup_codes::Column::UserId.eq(&user_id))
                    .exec(&db)
                    .await?;

                let new_backup_codes = backup_hashes
                    .into_iter()
                    .map(|(id, code_hash)| totp_backup_codes::ActiveModel {
                        id: Set(id),
                        user_id: Set(user_id.clone()),
                        code_hash: Set(code_hash),
                        used: Set(false),
                        ..Default::default()
                    })
                    .collect::<Vec<_>>();
                TotpBackupCodes::insert_many(new_backup_codes)
                    .exec(&db)
                    .await?;

                audit_actor
                    .log_mfa_with_db(db.clone(), mfa_enabled_event)
                    .await?;
                audit_actor.log_mfa_with_db(db, backup_event).await?;

                Ok(())
            })
        },
    )
    .await?;

    // Publish user.mfa.enabled event for webhooks
    {
        use crate::services::events::{Event, EventType};
        use serde_json::json;

        let mut event_builder = Event::builder(EventType::UserMfaEnabled)
            .actor_user_id(&auth_user.user.id)
            .actor_email(&auth_user.user.email)
            .detail("method", json!("totp"))
            .detail("backup_codes_count", json!(backup_codes.len()));

        // Add org context if available
        if let Some(org) = &auth_user.claims.org {
            event_builder = event_builder.org_id(org);
        }

        let event = event_builder.build();

        // Fire and forget
        let dispatcher = state.event_dispatcher.clone();
        tokio::spawn(async move {
            if let Err(e) = dispatcher.publish(event).await {
                tracing::error!("Failed to publish MFA enabled event: {}", e);
            }
        });
    }

    // Enabling a factor is a security-boundary change. Revoke every prior
    // session and issue a fresh session after the factor was proven, so a
    // setup session cannot outlive the factor state it was created under.
    let (access_token, refresh_token, expires_in) =
        issue_post_factor_change_session(&state, &auth_user, &live_user).await?;

    Ok(Json(MfaVerifyResponse {
        enabled: true,
        backup_codes: formatted_codes,
        access_token: Some(access_token),
        refresh_token: Some(refresh_token),
        expires_in: Some(expires_in),
    }))
}

/// DELETE /api/user/mfa - Disable TOTP for the authenticated user
pub async fn disable_mfa(
    State(state): State<AppState>,
    auth_user: Option<axum::extract::Extension<crate::middleware::AuthUser>>,
    request_info: Extension<RequestInfo>,
    request: Option<Json<MfaConfirmationRequest>>,
) -> Result<Json<serde_json::Value>> {
    let auth_user = auth_user
        .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))?
        .0;
    let request = request.map(|Json(request)| request).unwrap_or_default();
    let live_user = UserStore::find_by_id(DB::Conn(&state.db), &auth_user.user.id)
        .await?
        .filter(|user| user.deleted_at.is_none())
        .ok_or_else(|| AppError::Unauthorized("User is no longer active".to_string()))?;

    if !TotpStore::is_enabled(DB::Conn(&state.db), &live_user.id).await? {
        return Err(AppError::BadRequest("MFA is not enabled".to_string()));
    }

    crate::middleware::require_recent_authentication(
        &state.db,
        &auth_user,
        chrono::Duration::minutes(ACCOUNT_SECURITY_REAUTH_WINDOW_MINUTES),
    )
    .await?;
    verify_mfa_step_up(
        &state,
        &auth_user.user.id,
        auth_user.claims.org.as_deref(),
        request.mfa_code.as_deref(),
    )
    .await?;

    let user_id = auth_user.user.id.clone();
    let event = MfaAuditBuilder::new(&auth_user.user.id, "mfa_disabled")
        .org_id(auth_user.claims.org.as_deref())
        .ip_address(Some(&request_info.ip_address))
        .user_agent(Some(request_info.user_agent.clone()))
        .success(true)
        .build();

    // Execute transaction with automatic retry on database contention
    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "disable_mfa",
        |db| {
            let user_id = user_id.clone();
            let event = event.clone();
            let audit_actor = state.audit_actor.clone();
            Box::pin(async move {
                UserTotpSecrets::delete_many()
                    .filter(user_totp_secrets::Column::UserId.eq(&user_id))
                    .exec(&db)
                    .await?;

                TotpBackupCodes::delete_many()
                    .filter(totp_backup_codes::Column::UserId.eq(&user_id))
                    .exec(&db)
                    .await?;

                audit_actor.log_mfa_with_db(db, event).await?;

                Ok(())
            })
        },
    )
    .await?;

    let (access_token, refresh_token, expires_in) =
        issue_post_factor_change_session(&state, &auth_user, &live_user).await?;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "MFA has been disabled",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": expires_in,
    })))
}

/// POST /api/user/mfa/backup-codes/regenerate - Regenerate backup codes
pub async fn regenerate_backup_codes(
    State(state): State<AppState>,
    auth_user: Option<axum::extract::Extension<crate::middleware::AuthUser>>,
    request_info: Extension<RequestInfo>,
    request: Option<Json<MfaConfirmationRequest>>,
) -> Result<Json<BackupCodesResponse>> {
    let auth_user = auth_user
        .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))?
        .0;
    let request = request.map(|Json(request)| request).unwrap_or_default();

    crate::middleware::require_recent_authentication(
        &state.db,
        &auth_user,
        chrono::Duration::minutes(ACCOUNT_SECURITY_REAUTH_WINDOW_MINUTES),
    )
    .await?;
    verify_mfa_step_up(
        &state,
        &auth_user.user.id,
        auth_user.claims.org.as_deref(),
        request.mfa_code.as_deref(),
    )
    .await?;

    let _totp_secret = UserTotpSecrets::find()
        .filter(user_totp_secrets::Column::UserId.eq(&auth_user.user.id))
        .filter(user_totp_secrets::Column::Enabled.eq(true))
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::BadRequest("MFA is not enabled".to_string()))?;

    let mfa_service = MfaService::new();
    let backup_codes = mfa_service.generate_backup_codes();
    let formatted_codes = MfaService::format_backup_codes(&backup_codes);

    let user_id = auth_user.user.id.clone();
    let event = MfaAuditBuilder::new(&auth_user.user.id, "backup_codes_generated")
        .org_id(auth_user.claims.org.as_deref())
        .ip_address(Some(&request_info.ip_address))
        .user_agent(Some(request_info.user_agent.clone()))
        .success(true)
        .details(Some(&format!("count:{}", backup_codes.len())))
        .build();

    // Pre-hash all backup codes before the transaction
    let mut backup_code_hashes: Vec<(String, String)> = Vec::new();
    for code in &backup_codes {
        let code_hash = crate::crypto::concurrency::hash_password_bounded(code.clone()).await?;
        backup_code_hashes.push((Uuid::new_v4().to_string(), code_hash));
    }

    // Execute transaction with automatic retry on database contention
    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "regenerate_backup_codes",
        |db| {
            let user_id = user_id.clone();
            let backup_code_hashes = backup_code_hashes.clone();
            let event = event.clone();
            let audit_actor = state.audit_actor.clone();
            Box::pin(async move {
                TotpBackupCodes::delete_many()
                    .filter(totp_backup_codes::Column::UserId.eq(&user_id))
                    .exec(&db)
                    .await?;

                let new_backup_codes = backup_code_hashes
                    .iter()
                    .map(|(id, code_hash)| totp_backup_codes::ActiveModel {
                        id: Set(id.clone()),
                        user_id: Set(user_id.clone()),
                        code_hash: Set(code_hash.clone()),
                        used: Set(false),
                        ..Default::default()
                    })
                    .collect::<Vec<_>>();
                TotpBackupCodes::insert_many(new_backup_codes)
                    .exec(&db)
                    .await?;

                audit_actor.log_mfa_with_db(db, event).await?;

                Ok(())
            })
        },
    )
    .await?;

    if let Some(current_session_id) = auth_user.current_session_id.as_deref() {
        SessionStore::delete_all_except_current(
            DB::Conn(&state.db),
            &auth_user.user.id,
            current_session_id,
        )
        .await?;
    }

    Ok(Json(BackupCodesResponse {
        backup_codes: formatted_codes,
    }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MfaVerificationMethod {
    Totp,
    BackupCode,
}

async fn claim_backup_code_with_audit(
    pool: &DatabaseConnection,
    backup_code_id: &str,
    backup_audit: (
        &crate::audit::actor::AuditHandle,
        mfa_audit_log::ActiveModel,
    ),
) -> Result<bool> {
    let transaction = pool.begin().await?;
    let claimed =
        claim_backup_code_with_audit_in_db(DB::Tx(&transaction), backup_code_id, backup_audit)
            .await?;
    if !claimed {
        transaction.rollback().await?;
        return Ok(false);
    }
    transaction.commit().await?;
    Ok(true)
}

pub(crate) async fn claim_backup_code_with_audit_in_db(
    db: DB<'_>,
    backup_code_id: &str,
    backup_audit: (
        &crate::audit::actor::AuditHandle,
        mfa_audit_log::ActiveModel,
    ),
) -> Result<bool> {
    let claimed = TotpBackupCodes::update_many()
        .filter(totp_backup_codes::Column::Id.eq(backup_code_id))
        .filter(totp_backup_codes::Column::Used.eq(false))
        .col_expr(totp_backup_codes::Column::Used, true.into())
        .col_expr(
            totp_backup_codes::Column::UsedAt,
            Utc::now().naive_utc().into(),
        )
        .exec(&db)
        .await?;
    if claimed.rows_affected != 1 {
        return Ok(false);
    }
    backup_audit.0.log_mfa_with_db(db, backup_audit.1).await?;
    Ok(true)
}

/// Verify MFA and, for a backup code, atomically claim the one-time code with
/// its durable audit event. A concurrent replay can affect zero rows and is
/// therefore rejected instead of reporting a second success.
pub(crate) async fn verify_mfa_code_candidate(
    pool: &DatabaseConnection,
    user_id: &str,
    code: &str,
) -> Result<Option<(MfaVerificationMethod, Option<String>)>> {
    let pool_clone = pool.clone();
    let user_id_clone = user_id.to_string();
    let totp_secret = with_deadlock_retry("find_totp_secret", 10, || {
        let p = &pool_clone;
        let u = user_id_clone.clone();
        async move {
            UserTotpSecrets::find()
                .filter(user_totp_secrets::Column::UserId.eq(u))
                .filter(user_totp_secrets::Column::Enabled.eq(true))
                .one(p)
                .await
        }
    })
    .await?;

    if let Some(secret_record) = totp_secret {
        let encryption_service = EncryptionService::new().map_err(|e| {
            AppError::InternalServerError(format!("Failed to initialize encryption: {}", e))
        })?;
        let secret = encryption_service
            .decrypt_with_context(
                &secret_record.secret_encrypted,
                crate::encryption::EncryptionContext::new(
                    "user_totp_secrets",
                    &secret_record.id,
                    "secret_encrypted",
                ),
            )
            .map_err(|e| {
                AppError::InternalServerError(format!("Failed to decrypt secret: {}", e))
            })?;

        // Use direct Users::find to use with_deadlock_retry
        let pool_clone = pool.clone();
        let user_id_clone = user_id.to_string();
        let user_opt = with_deadlock_retry("find_user_for_mfa", 10, || {
            let p = &pool_clone;
            let u = user_id_clone.clone();
            async move {
                users::Entity::find()
                    .filter(users::Column::Id.eq(u))
                    .one(p)
                    .await
            }
        })
        .await?;

        let user = user_opt.ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        let mfa_service = MfaService::new();

        let totp_valid = mfa_service
            .verify_totp(&secret, code, &user.email)
            .unwrap_or(false);
        if totp_valid {
            return Ok(Some((MfaVerificationMethod::Totp, None)));
        }

        let pool_clone = pool.clone();
        let user_id_clone = user_id.to_string();
        let backup_codes = with_deadlock_retry("find_backup_codes", 10, || {
            let p = &pool_clone;
            let u = user_id_clone.clone();
            async move {
                TotpBackupCodes::find()
                    .filter(totp_backup_codes::Column::UserId.eq(u))
                    .filter(totp_backup_codes::Column::Used.eq(false))
                    .all(p)
                    .await
            }
        })
        .await?;

        for backup_code in backup_codes {
            if crate::crypto::concurrency::verify_password_bounded(
                code.to_string(),
                backup_code.code_hash.clone(),
            )
            .await?
            {
                return Ok(Some((
                    MfaVerificationMethod::BackupCode,
                    Some(backup_code.id),
                )));
            }
        }
    }

    Ok(None)
}

/// Verify MFA and, for privacy/self-service callers, atomically consume a
/// matching backup code with its audit event.
pub async fn verify_mfa_code_with_backup_audit(
    pool: &DatabaseConnection,
    user_id: &str,
    code: &str,
    backup_audit: (
        &crate::audit::actor::AuditHandle,
        mfa_audit_log::ActiveModel,
    ),
) -> Result<Option<MfaVerificationMethod>> {
    let Some((method, backup_code_id)) = verify_mfa_code_candidate(pool, user_id, code).await?
    else {
        return Ok(None);
    };
    if let Some(backup_code_id) = backup_code_id {
        if !claim_backup_code_with_audit(pool, &backup_code_id, backup_audit).await? {
            return Ok(None);
        }
    }
    Ok(Some(method))
}

#[cfg(test)]
mod backup_code_claim_tests {
    use super::*;
    use crate::entities::audit_outbox;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::{Database, PaginatorTrait, TransactionTrait};

    #[test]
    fn device_list_extreme_page_and_limit_are_backend_safe() {
        let query = ListDevicesQuery {
            page: Some(u64::MAX),
            limit: Some(u64::MAX),
            sort_by: None,
            sort_order: None,
        };
        let (page, limit, offset) =
            crate::utils::pagination::one_based_u64_page(query.page, query.limit, 20, 100);
        assert_eq!(page, u64::MAX);
        assert_eq!(limit, 100);
        assert_eq!(offset, i64::MAX as u64);
    }

    #[tokio::test]
    async fn backup_code_claim_is_one_winner_and_audit_coupled() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        let user = UserStore::create(DB::Conn(&db), "backup-one-winner@example.test", None, true)
            .await
            .unwrap();
        totp_backup_codes::ActiveModel {
            id: Set("one-winner-code".to_string()),
            user_id: Set(user.id.clone()),
            code_hash: Set("unused-in-claim-test".to_string()),
            used: Set(false),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();
        let audit = crate::audit::actor::AuditHandle::without_worker(db.clone());
        let event = MfaAuditBuilder::new(&user.id, "backup_code_used")
            .success(true)
            .build();

        assert!(
            claim_backup_code_with_audit(&db, "one-winner-code", (&audit, event.clone()),)
                .await
                .unwrap()
        );
        assert!(
            !claim_backup_code_with_audit(&db, "one-winner-code", (&audit, event),)
                .await
                .unwrap()
        );

        let stored = TotpBackupCodes::find_by_id("one-winner-code")
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert!(stored.used);
        assert!(stored.used_at.is_some());
        assert_eq!(audit_outbox::Entity::find().count(&db).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn later_preauth_conflict_rolls_back_backup_code_and_its_success_audit() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        let user = UserStore::create(DB::Conn(&db), "backup-retry@example.test", None, true)
            .await
            .unwrap();
        totp_backup_codes::ActiveModel {
            id: Set("retryable-backup-code".to_string()),
            user_id: Set(user.id.clone()),
            code_hash: Set("unused-in-claim-test".to_string()),
            used: Set(false),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();
        assert!(
            crate::store::distributed_locks::DistributedLockStore::try_acquire_lock(
                DB::Conn(&db),
                "mfa-preauth:already-consumed",
                &format!("user:{}", user.id),
                300,
            )
            .await
            .unwrap()
        );

        let audit = crate::audit::actor::AuditHandle::without_worker(db.clone());
        let transaction = db.begin().await.unwrap();
        let event = MfaAuditBuilder::new(&user.id, "backup_code_used")
            .success(true)
            .build();
        assert!(claim_backup_code_with_audit_in_db(
            DB::Tx(&transaction),
            "retryable-backup-code",
            (&audit, event),
        )
        .await
        .unwrap());
        assert!(
            !crate::store::distributed_locks::DistributedLockStore::try_acquire_lock(
                DB::Tx(&transaction),
                "mfa-preauth:already-consumed",
                &format!("user:{}", user.id),
                300,
            )
            .await
            .unwrap()
        );
        transaction.rollback().await.unwrap();

        assert!(
            !TotpBackupCodes::find_by_id("retryable-backup-code")
                .one(&db)
                .await
                .unwrap()
                .unwrap()
                .used
        );
        assert_eq!(audit_outbox::Entity::find().count(&db).await.unwrap(), 0);
    }
}

// PASSWORD MANAGEMENT

#[derive(Debug, Deserialize)]
pub struct SetPasswordRequest {
    pub new_password: String,
    /// Required when MFA is enabled.
    #[serde(default)]
    pub mfa_code: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SetPasswordResponse {
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
    /// Required when MFA is enabled.
    #[serde(default)]
    pub mfa_code: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ChangePasswordResponse {
    pub message: String,
}

/// POST /api/user/change-password - Change user's password
pub async fn change_password(
    State(state): State<AppState>,
    auth_user: Option<axum::extract::Extension<crate::middleware::AuthUser>>,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<ChangePasswordResponse>> {
    let auth_user = auth_user
        .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))?
        .0;

    // Validate new password strength
    if req.new_password.len() < 8 {
        return Err(AppError::BadRequest(
            "New password must be at least 8 characters long".to_string(),
        ));
    }

    // Get current user
    let user = UserStore::find_by_id(DB::Conn(&state.db), &auth_user.claims.sub)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Check if user has a password set
    let current_password_hash = user.password_hash.as_ref().ok_or_else(|| {
        AppError::BadRequest(
            "Cannot change password for OAuth-only accounts. Please set a password first."
                .to_string(),
        )
    })?;

    let is_valid = crate::crypto::concurrency::verify_password_bounded(
        req.current_password.clone(),
        current_password_hash.clone(),
    )
    .await?;

    if !is_valid {
        return Err(AppError::Unauthorized(
            "Current password is incorrect".to_string(),
        ));
    }

    crate::middleware::require_recent_authentication(
        &state.db,
        &auth_user,
        chrono::Duration::minutes(ACCOUNT_SECURITY_REAUTH_WINDOW_MINUTES),
    )
    .await?;

    verify_mfa_step_up(
        &state,
        &user.id,
        auth_user.claims.org.as_deref(),
        req.mfa_code.as_deref(),
    )
    .await?;

    let new_password_hash =
        crate::crypto::concurrency::hash_password_bounded(req.new_password.clone()).await?;
    let user_id = user.id.clone();
    let current_session_id = auth_user.current_session_id.clone();
    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "change_password",
        |db| {
            let user_id = user_id.clone();
            let new_password_hash = new_password_hash.clone();
            let current_session_id = current_session_id.clone();
            Box::pin(async move {
                UserStore::update_password_hash(db.clone(), &user_id, &new_password_hash).await?;
                crate::store::password_reset::PasswordResetStore::delete_all_for_user(
                    db.clone(),
                    &user_id,
                )
                .await?;
                if let Some(session_id) = current_session_id.as_deref() {
                    SessionStore::delete_all_except_current(db, &user_id, session_id).await?;
                }
                Ok(())
            })
        },
    )
    .await?;

    Ok(Json(ChangePasswordResponse {
        message: "Password changed successfully".to_string(),
    }))
}

/// POST /api/user/set-password - Set password for OAuth users
/// This endpoint allows OAuth users (who don't have a password) to set one.
/// If the user already has a password, this endpoint will return an error.
pub async fn set_password(
    State(state): State<AppState>,
    auth_user: Option<axum::extract::Extension<crate::middleware::AuthUser>>,
    Json(req): Json<SetPasswordRequest>,
) -> Result<Json<SetPasswordResponse>> {
    let auth_user = auth_user
        .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))?
        .0;

    // Validate new password strength
    if req.new_password.len() < 8 {
        return Err(AppError::BadRequest(
            "Password must be at least 8 characters long".to_string(),
        ));
    }

    // Get current user
    let user = UserStore::find_by_id(DB::Conn(&state.db), &auth_user.user.id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Check if user already has a password set
    if user.password_hash.is_some() {
        return Err(AppError::BadRequest(
            "Password is already set. Use the change password endpoint instead.".to_string(),
        ));
    }

    crate::middleware::require_recent_authentication(
        &state.db,
        &auth_user,
        chrono::Duration::minutes(ACCOUNT_SECURITY_REAUTH_WINDOW_MINUTES),
    )
    .await?;
    verify_mfa_step_up(
        &state,
        &user.id,
        auth_user.claims.org.as_deref(),
        req.mfa_code.as_deref(),
    )
    .await?;

    let password_hash =
        crate::crypto::concurrency::hash_password_bounded(req.new_password.clone()).await?;
    let user_id = user.id.clone();
    let current_session_id = auth_user.current_session_id.clone();
    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "set_password",
        |db| {
            let user_id = user_id.clone();
            let password_hash = password_hash.clone();
            let current_session_id = current_session_id.clone();
            Box::pin(async move {
                UserStore::update_password_hash(db.clone(), &user_id, &password_hash).await?;
                crate::store::password_reset::PasswordResetStore::delete_all_for_user(
                    db.clone(),
                    &user_id,
                )
                .await?;
                if let Some(session_id) = current_session_id.as_deref() {
                    SessionStore::delete_all_except_current(db, &user_id, session_id).await?;
                }
                Ok(())
            })
        },
    )
    .await?;

    Ok(Json(SetPasswordResponse {
        message: "Password set successfully".to_string(),
    }))
}

/// GET /api/user - Get current user profile
pub async fn get_user(
    State(state): State<AppState>,
    auth_user: Option<axum::extract::Extension<crate::middleware::AuthUser>>,
) -> Result<Json<UserResponse>> {
    let auth_user = auth_user
        .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))?
        .0;

    let user = UserStore::find_by_id(DB::Conn(&state.db), &auth_user.user.id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Fetch plan and features if user is in an org/service context
    let (plan, features) = if let (Some(org_slug), Some(service_slug)) =
        (&auth_user.claims.org, &auth_user.claims.service)
    {
        // Fetch subscription for this user + org + service
        use crate::store::subscriptions::SubscriptionStore;
        match SubscriptionStore::get_subscription_by_user_org_service(
            DB::Conn(&state.db),
            &user.id,
            org_slug,
            service_slug,
        )
        .await?
        {
            Some(subscription) => {
                // Parse features from JSON
                let features: Vec<String> = subscription
                    .features
                    .as_ref()
                    .and_then(|f| serde_json::from_str(f).ok())
                    .unwrap_or_default();
                (Some(subscription.plan_name), Some(features))
            }
            None => (None, None),
        }
    } else {
        (None, None)
    };

    let permissions = effective_user_permissions(&state, &auth_user).await?;

    Ok(Json(UserResponse {
        id: user.id,
        email: user.email,
        // A relying party receiving a service-scoped token must not learn or
        // rely on the user's platform-admin status.
        is_platform_owner: user.is_platform_owner && auth_user.claims.service.is_none(),
        email_verified_at: user
            .email_verified_at
            .map(|dt| chrono::DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc).to_rfc3339()),
        created_at: chrono::DateTime::<Utc>::from_naive_utc_and_offset(user.created_at, Utc)
            .to_rfc3339(),
        org: auth_user.claims.org.clone().unwrap_or_default(),
        service: auth_user.claims.service.clone().unwrap_or_default(),
        permissions,
        plan,
        features,
    }))
}

/// PATCH /api/user - Update current user profile
pub async fn update_user(
    State(state): State<AppState>,
    auth_user: Option<axum::extract::Extension<crate::middleware::AuthUser>>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>> {
    let auth_user = auth_user
        .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))?
        .0;

    let user = UserStore::find_by_id(DB::Conn(&state.db), &auth_user.user.id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let mut updated_user = user.clone();
    if let Some(email) = req.email.as_deref().map(str::trim) {
        validate_email_format(email)?;
        if email == user.email {
            // Idempotent no-op; no security-sensitive change occurred.
        } else {
            // The configured platform-owner address drives bootstrap and admin
            // OAuth owner recognition. Changing it only in the database would
            // make the next restart create a second, passwordless owner for the
            // stale configured address. Platform owners must change it through
            // managed platform configuration.
            if user.is_platform_owner {
                return Err(AppError::BadRequest(
                    "Platform owner email changes must be made through managed platform configuration"
                        .to_string(),
                ));
            }
            ensure_email_delivery_configured(&state, "account email changes")?;
            require_account_security_reauthentication(
                &state,
                &auth_user,
                req.current_password.as_deref(),
                req.mfa_code.as_deref(),
            )
            .await?;

            // Check if email is already taken by another user in this scope.
            if let Some(existing_user) = UserStore::find_by_email_with_context(
                DB::Conn(&state.db),
                email,
                user.org_id.as_deref(),
            )
            .await?
            {
                if existing_user.id != user.id {
                    return Err(AppError::BadRequest("Email is already taken".to_string()));
                }
            }

            let verification_token = Uuid::new_v4().to_string();
            let verification_token_hash = hash_token(&verification_token);
            let verification_expires_at = Utc::now() + chrono::Duration::hours(24);
            let email_owned = email.to_string();
            let user_id = user.id.clone();
            let current_session_id = auth_user.current_session_id.clone();
            let db = DB::Conn(&state.db);
            updated_user = with_retrying_transaction(
                &state.db,
                #[cfg(feature = "db_sqlite")]
                &state.db_writer,
                "update_account_email",
                |db| {
                    let email = email_owned.clone();
                    let user_id = user_id.clone();
                    let verification_token_hash = verification_token_hash.clone();
                    let verification_expires_at = verification_expires_at.naive_utc();
                    let current_session_id = current_session_id.clone();
                    Box::pin(async move {
                        let updated = UserStore::update_email(db.clone(), &user_id, &email).await?;
                        EmailVerificationStore::delete_all_for_user(db.clone(), &user_id).await?;
                        crate::store::password_reset::PasswordResetStore::delete_all_for_user(
                            db.clone(),
                            &user_id,
                        )
                        .await?;
                        if let Some(session_id) = current_session_id.as_deref() {
                            SessionStore::delete_all_except_current(
                                db.clone(),
                                &user_id,
                                session_id,
                            )
                            .await?;
                        }
                        EmailVerificationStore::create(
                            db,
                            &user_id,
                            &verification_token_hash,
                            &verification_expires_at,
                        )
                        .await?;
                        Ok(updated)
                    })
                },
            )
            .await?;

            let verification_url = format!(
                "{}/verify-email?token={}",
                state.web_client_url.trim_end_matches('/'),
                verification_token
            );
            if let Err(error) = JobQueueService::enqueue_email(
                db,
                email,
                "Verify Your New Email Address",
                &format!(
                    "Confirm this email address for your AuthOS account:\n\n{verification_url}\n\nThis link expires in 24 hours."
                ),
                None,
            )
            .await
            {
                tracing::error!(user_id = %user.id, error = %error, "Failed to enqueue account email verification");
            }

            // Notify the previous address after the change commits. Best effort:
            // the new address still has to be verified before password login.
            if let Err(error) = JobQueueService::enqueue_email(
                DB::Conn(&state.db),
                &user.email,
                "Your AuthOS account email was changed",
                &format!(
                    "The email address for your AuthOS account was changed to {email}. If you did not request this change, contact your platform administrator immediately."
                ),
                None,
            )
            .await
            {
                tracing::warn!(user_id = %user.id, error = %error, "Failed to enqueue old-address security notification");
            }

            state.user_cache.invalidate(&user.id).await;

            tracing::info!(
                user_id = %user.id,
                "Account email changed; verification and old-address notification queued"
            );
        }
    }

    // Fetch plan and features if user is in an org/service context
    let (plan, features) = if let (Some(org_slug), Some(service_slug)) =
        (&auth_user.claims.org, &auth_user.claims.service)
    {
        // Fetch subscription for this user + org + service
        use crate::store::subscriptions::SubscriptionStore;
        match SubscriptionStore::get_subscription_by_user_org_service(
            DB::Conn(&state.db),
            &updated_user.id,
            org_slug,
            service_slug,
        )
        .await?
        {
            Some(subscription) => {
                // Parse features from JSON
                let features: Vec<String> = subscription
                    .features
                    .as_ref()
                    .and_then(|f| serde_json::from_str(f).ok())
                    .unwrap_or_default();
                (Some(subscription.plan_name), Some(features))
            }
            None => (None, None),
        }
    } else {
        (None, None)
    };

    let permissions = effective_user_permissions(&state, &auth_user).await?;

    Ok(Json(UserResponse {
        id: updated_user.id,
        email: updated_user.email,
        is_platform_owner: updated_user.is_platform_owner,
        email_verified_at: updated_user
            .email_verified_at
            .map(|dt| chrono::DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc).to_rfc3339()),
        created_at: chrono::DateTime::<Utc>::from_naive_utc_and_offset(
            updated_user.created_at,
            Utc,
        )
        .to_rfc3339(),
        org: auth_user.claims.org.clone().unwrap_or_default(),
        service: auth_user.claims.service.clone().unwrap_or_default(),
        permissions,
        plan,
        features,
    }))
}

/// GET /api/user/devices - List user's devices
pub async fn list_devices(
    State(state): State<AppState>,
    Extension(_request_info): Extension<RequestInfo>,
    Extension(auth_user): Extension<crate::middleware::AuthUser>,
    Query(query): Query<ListDevicesQuery>,
) -> Result<Json<ListDevicesResponse>> {
    let (page, limit, offset) =
        crate::utils::pagination::one_based_u64_page(query.page, query.limit, 20, 100);

    let db = DB::Conn(&state.db);

    // Build query with filters
    let mut devices_query =
        UserDevices::find().filter(user_devices::Column::UserId.eq(&auth_user.claims.sub));

    // Apply sorting
    match query.sort_by.as_deref() {
        Some("created_at") => {
            if query.sort_order.as_deref() == Some("desc") {
                devices_query = devices_query.order_by_desc(user_devices::Column::CreatedAt);
            } else {
                devices_query = devices_query.order_by_asc(user_devices::Column::CreatedAt);
            }
        }
        Some("last_seen_at") => {
            if query.sort_order.as_deref() == Some("desc") {
                devices_query = devices_query.order_by_desc(user_devices::Column::LastSeenAt);
            } else {
                devices_query = devices_query.order_by_asc(user_devices::Column::LastSeenAt);
            }
        }
        Some("name") => {
            if query.sort_order.as_deref() == Some("desc") {
                devices_query = devices_query.order_by_desc(user_devices::Column::Name);
            } else {
                devices_query = devices_query.order_by_asc(user_devices::Column::Name);
            }
        }
        _ => {
            // Default sort by last_seen_at desc
            devices_query = devices_query.order_by_desc(user_devices::Column::LastSeenAt);
        }
    }

    // Get total count
    let total = devices_query
        .clone()
        .into_model::<user_devices::Model>()
        .count(&db)
        .await?;

    // Get paginated results
    let devices = devices_query
        .offset(offset)
        .limit(limit)
        .into_model::<user_devices::Model>()
        .all(&db)
        .await?;

    let device_responses: Vec<UserDeviceResponse> = devices
        .into_iter()
        .map(|device: user_devices::Model| {
            let expires_at = device.expires_at;
            let is_trusted = device.is_trusted && expires_at > Utc::now().naive_utc();
            UserDeviceResponse {
                id: device.id,
                device_name: device.name.clone(),
                first_seen_at: chrono::DateTime::<Utc>::from_naive_utc_and_offset(
                    device.created_at,
                    Utc,
                )
                .to_rfc3339(),
                last_used_at: chrono::DateTime::<Utc>::from_naive_utc_and_offset(
                    device.last_seen_at,
                    Utc,
                )
                .to_rfc3339(),
                expires_at: chrono::DateTime::<Utc>::from_naive_utc_and_offset(expires_at, Utc)
                    .to_rfc3339(),
                registration_ip: device.last_ip,
                risk_score: calculate_device_risk_score(
                    device.created_at,
                    device.last_seen_at,
                    is_trusted,
                    expires_at,
                ),
                is_trusted,
            }
        })
        .collect();

    Ok(Json(ListDevicesResponse {
        devices: device_responses,
        total,
        page,
        limit,
    }))
}

/// GET /api/user/devices/:device_id - Get specific device details
pub async fn get_device(
    State(state): State<AppState>,
    Extension(_request_info): Extension<RequestInfo>,
    Extension(auth_user): Extension<crate::middleware::AuthUser>,
    axum::extract::Path(device_id): axum::extract::Path<String>,
) -> Result<Json<UserDeviceResponse>> {
    let db = DB::Conn(&state.db);

    let device = UserDevicesStore::find_by_id_and_user(db, &device_id, &auth_user.claims.sub)
        .await?
        .ok_or_else(|| AppError::NotFound("Device not found".to_string()))?;

    let expires_at = device.expires_at;
    let is_trusted = device.is_trusted && expires_at > Utc::now().naive_utc();
    Ok(Json(UserDeviceResponse {
        id: device.id,
        device_name: device.name.clone(),
        first_seen_at: chrono::DateTime::<Utc>::from_naive_utc_and_offset(device.created_at, Utc)
            .to_rfc3339(),
        last_used_at: chrono::DateTime::<Utc>::from_naive_utc_and_offset(device.last_seen_at, Utc)
            .to_rfc3339(),
        expires_at: chrono::DateTime::<Utc>::from_naive_utc_and_offset(expires_at, Utc)
            .to_rfc3339(),
        registration_ip: device.last_ip,
        risk_score: calculate_device_risk_score(
            device.created_at,
            device.last_seen_at,
            is_trusted,
            expires_at,
        ),
        is_trusted,
    }))
}

/// POST /api/user/devices/:device_id/revoke - Revoke a specific device
pub async fn revoke_device(
    State(state): State<AppState>,
    Extension(request_info): Extension<RequestInfo>,
    Extension(auth_user): Extension<crate::middleware::AuthUser>,
    axum::extract::Path(device_id): axum::extract::Path<String>,
    Json(req): Json<RevokeDeviceRequest>,
) -> Result<Json<RevokeDeviceResponse>> {
    let db = DB::Conn(&state.db);

    // Find and verify the device belongs to the user
    let device =
        UserDevicesStore::find_by_id_and_user(db.clone(), &device_id, &auth_user.claims.sub)
            .await?
            .ok_or_else(|| AppError::NotFound("Device not found".to_string()))?;

    // Delete with the owner predicate in the mutation itself so a future
    // ownership-model change cannot create a check/use gap.
    if !UserDevicesStore::delete(db.clone(), &device_id, &auth_user.claims.sub).await? {
        return Err(AppError::NotFound("Device not found".to_string()));
    }

    // Log the revocation
    tracing::info!(
        user_id = %auth_user.claims.sub,
        device_id = %device_id,
        device_name = %device.name,
        reason = ?req.reason,
        ip_address = %request_info.ip_address,
        user_agent = %request_info.user_agent,
        "Device revoked"
    );

    Ok(Json(RevokeDeviceResponse {
        message: "Device has been revoked".to_string(),
        success: true,
    }))
}

/// POST /api/user/devices/revoke-all - Revoke all devices except current
pub async fn revoke_all_devices(
    State(state): State<AppState>,
    Extension(request_info): Extension<RequestInfo>,
    Extension(auth_user): Extension<crate::middleware::AuthUser>,
) -> Result<Json<RevokeDeviceResponse>> {
    let db = DB::Conn(&state.db);

    // Get current device info if available (from user agent)
    let _current_user_agent = request_info.user_agent.clone();

    // Delete all devices except possibly the current one
    let devices = UserDevicesStore::find_by_user(db.clone(), &auth_user.claims.sub).await?;
    let now = Utc::now().naive_utc();
    let keep_device_ids = devices
        .iter()
        .filter(|device| device.last_seen_at > now && device.name.contains("Current Session"))
        .map(|device| device.id.clone())
        .collect::<Vec<_>>();
    let revoked_count = UserDevicesStore::delete_by_user_except_ids(
        db.clone(),
        &auth_user.claims.sub,
        &keep_device_ids,
    )
    .await?;

    // "Revoke all devices" is also a session-security action. Removing device
    // trust without revoking the associated sessions leaves stolen bearer
    // tokens usable.
    if let Some(current_session_id) = auth_user.current_session_id.as_deref() {
        SessionStore::delete_all_except_current(
            DB::Conn(&state.db),
            &auth_user.user.id,
            current_session_id,
        )
        .await?;
    }

    tracing::info!(
        user_id = %auth_user.claims.sub,
        revoked_count = revoked_count,
        ip_address = %request_info.ip_address,
        user_agent = %request_info.user_agent,
        "All devices and other sessions revoked except current"
    );

    Ok(Json(RevokeDeviceResponse {
        message: format!(
            "{} devices and other sessions have been revoked",
            revoked_count
        ),
        success: true,
    }))
}

/// PATCH /api/user/devices/:device_id - Update device name
pub async fn update_device_name(
    State(state): State<AppState>,
    Extension(request_info): Extension<RequestInfo>,
    Extension(auth_user): Extension<crate::middleware::AuthUser>,
    axum::extract::Path(device_id): axum::extract::Path<String>,
    Json(req): Json<UpdateDeviceNameRequest>,
) -> Result<Json<UserDeviceResponse>> {
    let db = DB::Conn(&state.db);

    // Find and verify the device belongs to the user
    let device =
        UserDevicesStore::find_by_id_and_user(db.clone(), &device_id, &auth_user.claims.sub)
            .await?
            .ok_or_else(|| AppError::NotFound("Device not found".to_string()))?;

    // Update device name
    if !UserDevicesStore::update_name(
        db.clone(),
        &device_id,
        &auth_user.claims.sub,
        &req.device_name,
    )
    .await?
    {
        return Err(AppError::NotFound("Device not found".to_string()));
    }

    let updated_device =
        UserDevicesStore::find_by_id_and_user(db.clone(), &device_id, &auth_user.claims.sub)
            .await?
            .ok_or_else(|| {
                AppError::InternalServerError("Failed to retrieve updated device".to_string())
            })?;

    tracing::info!(
        user_id = %auth_user.claims.sub,
        device_id = %device_id,
        old_name = %device.name,
        new_name = %req.device_name,
        ip_address = %request_info.ip_address,
        user_agent = %request_info.user_agent,
        "Device name updated"
    );

    let is_trusted =
        updated_device.is_trusted && updated_device.expires_at > Utc::now().naive_utc();
    Ok(Json(UserDeviceResponse {
        id: updated_device.id,
        device_name: updated_device.name.clone(),
        first_seen_at: chrono::DateTime::<Utc>::from_naive_utc_and_offset(
            updated_device.created_at,
            Utc,
        )
        .to_rfc3339(),
        last_used_at: chrono::DateTime::<Utc>::from_naive_utc_and_offset(
            updated_device.last_seen_at,
            Utc,
        )
        .to_rfc3339(),
        expires_at: chrono::DateTime::<Utc>::from_naive_utc_and_offset(
            updated_device.expires_at,
            Utc,
        )
        .to_rfc3339(),
        registration_ip: updated_device.last_ip,
        risk_score: calculate_device_risk_score(
            updated_device.created_at,
            updated_device.last_seen_at,
            is_trusted,
            updated_device.expires_at,
        ),
        is_trusted,
    }))
}

/// POST /api/user/devices/:device_id/trust - Mark a device as trusted
pub async fn trust_device(
    State(state): State<AppState>,
    Extension(request_info): Extension<RequestInfo>,
    Extension(auth_user): Extension<crate::middleware::AuthUser>,
    axum::extract::Path(device_id): axum::extract::Path<String>,
) -> Result<Json<UserDeviceResponse>> {
    let db = DB::Conn(&state.db);

    // Find and verify the device belongs to the user
    let device =
        UserDevicesStore::find_by_id_and_user(db.clone(), &device_id, &auth_user.claims.sub)
            .await?
            .ok_or_else(|| AppError::NotFound("Device not found".to_string()))?;

    // Extend device trust expiration (90 days from now)
    let expires_at = (Utc::now() + chrono::Duration::days(90)).naive_utc();
    if !UserDevicesStore::update_expires_at(
        db.clone(),
        &device_id,
        &auth_user.claims.sub,
        &expires_at,
    )
    .await?
    {
        return Err(AppError::NotFound("Device not found".to_string()));
    }

    let updated_device =
        UserDevicesStore::find_by_id_and_user(db.clone(), &device_id, &auth_user.claims.sub)
            .await?
            .ok_or_else(|| {
                AppError::InternalServerError("Failed to retrieve updated device".to_string())
            })?;

    tracing::info!(
        user_id = %auth_user.claims.sub,
        device_id = %device_id,
        device_name = %device.name,
        expires_at = %expires_at,
        ip_address = %request_info.ip_address,
        user_agent = %request_info.user_agent,
        "Device manually trusted"
    );

    let is_trusted =
        updated_device.is_trusted && updated_device.expires_at > Utc::now().naive_utc();
    Ok(Json(UserDeviceResponse {
        id: updated_device.id,
        device_name: updated_device.name.clone(),
        first_seen_at: chrono::DateTime::<Utc>::from_naive_utc_and_offset(
            updated_device.created_at,
            Utc,
        )
        .to_rfc3339(),
        last_used_at: chrono::DateTime::<Utc>::from_naive_utc_and_offset(
            updated_device.last_seen_at,
            Utc,
        )
        .to_rfc3339(),
        expires_at: chrono::DateTime::<Utc>::from_naive_utc_and_offset(
            updated_device.expires_at,
            Utc,
        )
        .to_rfc3339(),
        registration_ip: updated_device.last_ip,
        risk_score: calculate_device_risk_score(
            updated_device.created_at,
            updated_device.last_seen_at,
            is_trusted,
            updated_device.expires_at,
        ),
        is_trusted,
    }))
}

/// Validate email format - delegates to middleware's statically compiled regex
fn validate_email_format(email: &str) -> Result<()> {
    crate::middleware::validate_email_format_static(email)
}

#[cfg(test)]
mod password_route_tests {
    use super::*;
    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::crypto::jwt::JwtService;
    use crate::crypto::sso::OAuthClient;

    use crate::audit::actor::AuditHandle;
    use crate::db::DB;
    use crate::entities::{
        prelude::{EmailVerificationTokens, Sessions},
        users,
    };
    use crate::middleware::AuthUser;
    use crate::rsa_keys::GeneratedKey;
    use crate::services::{
        events::EventDispatcher, metrics::MfaMetricsService, risk_engine::RiskEngine,
    };
    use crate::state::AppState;
    use crate::store::{sessions::SessionStore, users::UserStore};
    use base64::{engine::general_purpose::STANDARD, Engine};
    use migration::{Migrator, MigratorTrait};
    use moka::future::Cache;
    use sea_orm::Database;
    use std::sync::Arc;

    use crate::test_support::test_config;

    struct Fixture {
        state: AppState,
        // OAuth-only user (no password hash).
        oauth_user: AuthUser,
        // Password user.
        pw_user: AuthUser,
        current_password: String,
    }

    async fn fixture() -> Fixture {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let config = test_config();
        let jwt_service = Arc::new({
            let rsa = GeneratedKey::generate().expect("rsa");
            JwtService::new(
                &STANDARD.encode(rsa.private_key_pem().expect("pem")),
                &STANDARD.encode(rsa.public_key_pem().expect("pem")),
                config.jwt_expiration_hours,
                "test-key",
                &config.base_url,
            )
            .expect("jwt")
        });

        let oauth_model = UserStore::create(DB::Conn(&db), "oauth-only@example.test", None, false)
            .await
            .expect("create oauth user");

        let pw_model = UserStore::create(DB::Conn(&db), "pw-user@example.test", None, false)
            .await
            .expect("create pw user");
        let current_password = "correct-horse-1".to_string();
        let hashed = crate::crypto::concurrency::hash_password_bounded(current_password.clone())
            .await
            .expect("hash");
        UserStore::update_password_hash(DB::Conn(&db), &pw_model.id, &hashed)
            .await
            .expect("set initial password");

        let state = AppState {
            db: db.clone(),
            #[cfg(feature = "db_sqlite")]
            db_writer: db.clone(),
            oauth_client: Arc::new(OAuthClient::new(&config).expect("oauth")),
            jwt_service: jwt_service.clone(),
            base_url: config.base_url.clone(),
            web_client_url: config.platform_dashboard_base_url.clone(),
            full_web_client_url: config.full_web_client_base_url.clone(),
            encryption: None,
            email_service: None,
            metrics_service: Arc::new(MfaMetricsService::new(db.clone())),
            event_dispatcher: Arc::new(EventDispatcher::new(db.clone())),
            billing_provider: Arc::new(DisabledBillingProvider::new()),
            risk_engine: Arc::new(RiskEngine::new().expect("risk")),
            webauthn_service: None,
            permission_cache: Cache::new(10_000),
            user_cache: Cache::new(10_000),
            domain_cache: Cache::new(10_000),
            audit_actor: AuditHandle::new(db.clone()),
            config,
        };

        let auth_user_for = |user: &users::Model, session_id: String| -> AuthUser {
            let token = jwt_service
                .create_token(&user.id, &user.email, false, None, None)
                .expect("token");
            AuthUser {
                claims: jwt_service.validate_token(&token).expect("claims"),
                user: user.clone(),
                permissions: vec![],
                ip_address: "127.0.0.1".to_string(),
                user_agent: "password-test".to_string(),
                current_session_id: Some(session_id),
            }
        };

        let oauth_token = jwt_service
            .create_token(&oauth_model.id, &oauth_model.email, false, None, None)
            .expect("oauth token");
        let oauth_session = SessionStore::create(
            DB::Conn(&db),
            &oauth_model.id,
            &JwtService::hash_token(&oauth_token),
            (Utc::now() + chrono::Duration::hours(1)).naive_utc(),
            None,
            None,
            None,
            None,
            None,
            Some("password-test"),
            Some("127.0.0.1"),
        )
        .await
        .expect("oauth session");
        let pw_token = jwt_service
            .create_token(&pw_model.id, &pw_model.email, false, None, None)
            .expect("pw token");
        let pw_session = SessionStore::create(
            DB::Conn(&db),
            &pw_model.id,
            &JwtService::hash_token(&pw_token),
            (Utc::now() + chrono::Duration::hours(1)).naive_utc(),
            None,
            None,
            None,
            None,
            None,
            Some("password-test"),
            Some("127.0.0.1"),
        )
        .await
        .expect("pw session");

        Fixture {
            state,
            oauth_user: auth_user_for(&oauth_model, oauth_session.id),
            pw_user: auth_user_for(&pw_model, pw_session.id),
            current_password,
        }
    }

    #[tokio::test]
    async fn unauthenticated_requests_are_refused() {
        let f = fixture().await;
        match get_user(State(f.state.clone()), None).await {
            Err(AppError::Unauthorized(_)) => {}
            other => panic!("expected unauthorized, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn set_password_rejects_weak_and_duplicate_passwords() {
        let f = fixture().await;

        // Too short.
        match set_password(
            State(f.state.clone()),
            Some(axum::Extension(f.oauth_user.clone())),
            Json(SetPasswordRequest {
                new_password: "short".to_string(),
                mfa_code: None,
            }),
        )
        .await
        {
            Err(AppError::BadRequest(message)) => assert!(message.contains("8 characters")),
            other => panic!("expected BadRequest, got {other:?}"),
        }

        // Happy path sets the first password.
        let _ = set_password(
            State(f.state.clone()),
            Some(axum::Extension(f.oauth_user.clone())),
            Json(SetPasswordRequest {
                new_password: "long-enough-1".to_string(),
                mfa_code: None,
            }),
        )
        .await
        .expect("first set");

        // Setting again is refused in favour of change-password.
        match set_password(
            State(f.state.clone()),
            Some(axum::Extension(f.oauth_user.clone())),
            Json(SetPasswordRequest {
                new_password: "another-pass-9".to_string(),
                mfa_code: None,
            }),
        )
        .await
        {
            Err(AppError::BadRequest(message)) => assert!(message.contains("already set")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn account_email_change_requires_step_up_and_clears_verification() {
        let mut f = fixture().await;
        f.state.email_service = Some(Arc::new(
            crate::email::EmailService::from_config(crate::email::SmtpConfig {
                host: "127.0.0.1".to_string(),
                port: 25,
                username: String::new(),
                password: String::new(),
                from_email: "no-reply@example.test".to_string(),
                from_name: "AuthOS Test".to_string(),
            })
            .expect("test email service"),
        ));
        let user_id = f.pw_user.user.id.clone();
        let other_token = f
            .state
            .jwt_service
            .create_token(&user_id, &f.pw_user.user.email, false, None, None)
            .expect("other token");
        SessionStore::create(
            DB::Conn(&f.state.db),
            &user_id,
            &JwtService::hash_token(&other_token),
            (Utc::now() + chrono::Duration::hours(1)).naive_utc(),
            None,
            None,
            None,
            None,
            None,
            Some("other-browser"),
            Some("127.0.0.2"),
        )
        .await
        .expect("other session");

        match update_user(
            State(f.state.clone()),
            Some(axum::Extension(f.pw_user.clone())),
            Json(UpdateUserRequest {
                email: Some("pw-user-new@example.test".to_string()),
                current_password: None,
                mfa_code: None,
            }),
        )
        .await
        {
            Err(AppError::Forbidden(message)) => assert!(message.contains("Current password")),
            other => panic!("expected step-up refusal, got {other:?}"),
        }

        let Json(updated) = update_user(
            State(f.state.clone()),
            Some(axum::Extension(f.pw_user.clone())),
            Json(UpdateUserRequest {
                email: Some("pw-user-new@example.test".to_string()),
                current_password: Some(f.current_password.clone()),
                mfa_code: None,
            }),
        )
        .await
        .expect("email change after step-up");

        assert_eq!(updated.email, "pw-user-new@example.test");
        assert!(updated.email_verified_at.is_none());
        let stored = UserStore::find_by_id(DB::Conn(&f.state.db), &user_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.email, "pw-user-new@example.test");
        assert!(stored.email_verified_at.is_none());
        assert_eq!(
            EmailVerificationTokens::find()
                .filter(crate::entities::email_verification_tokens::Column::UserId.eq(&user_id))
                .count(&f.state.db)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            Sessions::find()
                .filter(crate::entities::sessions::Column::UserId.eq(&user_id))
                .count(&f.state.db)
                .await
                .unwrap(),
            1,
            "other sessions must be revoked by an email change"
        );
    }

    #[tokio::test]
    async fn change_password_verifies_the_current_password() {
        let f = fixture().await;

        // Wrong current password.
        match change_password(
            State(f.state.clone()),
            Some(axum::Extension(f.pw_user.clone())),
            Json(ChangePasswordRequest {
                current_password: "wrong-password".to_string(),
                new_password: "brand-new-pw-1".to_string(),
                mfa_code: None,
            }),
        )
        .await
        {
            Err(AppError::Unauthorized(_)) => {}
            other => panic!("expected unauthorized, got {other:?}"),
        }

        // OAuth-only account has nothing to change.
        match change_password(
            State(f.state.clone()),
            Some(axum::Extension(f.oauth_user.clone())),
            Json(ChangePasswordRequest {
                current_password: "whatever".to_string(),
                new_password: "brand-new-pw-1".to_string(),
                mfa_code: None,
            }),
        )
        .await
        {
            Err(AppError::BadRequest(message)) => {
                assert!(message.contains("OAuth-only"))
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }

        // Correct flow succeeds and accepts the new credential.
        let Json(response) = change_password(
            State(f.state.clone()),
            Some(axum::Extension(f.pw_user.clone())),
            Json(ChangePasswordRequest {
                current_password: f.current_password.clone(),
                new_password: "brand-new-pw-1".to_string(),
                mfa_code: None,
            }),
        )
        .await
        .expect("change password");
        assert!(response.message.contains("successfully"));
    }
    #[tokio::test]
    async fn mfa_status_reports_disabled_for_fresh_users() {
        let f = fixture().await;
        let Json(status) = get_mfa_status(
            State(f.state.clone()),
            Some(axum::Extension(f.pw_user.clone())),
        )
        .await
        .expect("mfa status");
        assert!(!status.enabled);
        assert!(!status.has_backup_codes);
    }

    #[tokio::test]
    async fn unauthenticated_mfa_status_is_refused() {
        let f = fixture().await;
        match get_mfa_status(State(f.state.clone()), None).await {
            Err(AppError::Unauthorized(_)) => {}
            other => panic!("expected unauthorized, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod mfa_flow_tests {
    use super::*;

    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::crypto::sso::OAuthClient;

    use crate::middleware::AuthUser;

    use crate::audit::actor::AuditHandle;
    use crate::db::DB;
    use crate::services::{
        events::EventDispatcher, metrics::MfaMetricsService, risk_engine::RiskEngine,
    };
    use crate::state::AppState;
    use crate::store::{sessions::SessionStore, users::UserStore};
    use axum::Extension;

    use migration::{Migrator, MigratorTrait};
    use moka::future::Cache;
    use sea_orm::Database;
    use std::sync::Arc;

    use crate::test_support::test_config;

    use crate::test_support::test_jwt_service;

    fn request_info() -> Extension<RequestInfo> {
        Extension(RequestInfo {
            ip_address: "127.0.0.1".to_string(),
            user_agent: "mfa-test".to_string(),
        })
    }

    struct Fixture {
        state: AppState,
        user: AuthUser,
    }

    async fn fixture() -> Fixture {
        // MFA handlers build the encryption service from the environment.
        unsafe { std::env::set_var("ENCRYPTION_KEY", "22".repeat(32)) };

        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let config = test_config();
        let jwt_service = Arc::new(test_jwt_service(&config));

        let user_model = UserStore::create(DB::Conn(&db), "mfa@example.test", None, false)
            .await
            .expect("create user");

        let state = AppState {
            db: db.clone(),
            #[cfg(feature = "db_sqlite")]
            db_writer: db.clone(),
            oauth_client: Arc::new(OAuthClient::new(&config).expect("oauth")),
            jwt_service: jwt_service.clone(),
            base_url: config.base_url.clone(),
            web_client_url: config.platform_dashboard_base_url.clone(),
            full_web_client_url: config.full_web_client_base_url.clone(),
            encryption: None,
            email_service: None,
            metrics_service: Arc::new(MfaMetricsService::new(db.clone())),
            event_dispatcher: Arc::new(EventDispatcher::new(db.clone())),
            billing_provider: Arc::new(DisabledBillingProvider::new()),
            risk_engine: Arc::new(RiskEngine::new().expect("risk")),
            webauthn_service: None,
            permission_cache: Cache::new(10_000),
            user_cache: Cache::new(10_000),
            domain_cache: Cache::new(10_000),
            audit_actor: AuditHandle::new(db.clone()),
            config,
        };

        let token = jwt_service
            .create_token(&user_model.id, &user_model.email, false, None, None)
            .expect("token");
        let session = SessionStore::create(
            DB::Conn(&db),
            &user_model.id,
            &crate::crypto::jwt::JwtService::hash_token(&token),
            (Utc::now() + chrono::Duration::hours(1)).naive_utc(),
            None,
            None,
            None,
            None,
            None,
            Some("mfa-test"),
            Some("127.0.0.1"),
        )
        .await
        .expect("mfa session");
        let auth_user = AuthUser {
            claims: jwt_service.validate_token(&token).expect("claims"),
            user: user_model,
            permissions: vec![],
            ip_address: "127.0.0.1".to_string(),
            user_agent: "mfa-test".to_string(),
            current_session_id: Some(session.id),
        };

        Fixture {
            state,
            user: auth_user,
        }
    }

    #[tokio::test]
    async fn the_full_setup_verify_disable_lifecycle_holds() {
        unsafe { std::env::set_var("ENCRYPTION_KEY", "22".repeat(32)) };
        let f = fixture().await;

        // Setup returns a secret and QR material.
        let Json(setup) = setup_mfa(
            State(f.state.clone()),
            Some(axum::Extension(f.user.clone())),
            request_info(),
            None,
        )
        .await
        .expect("setup mfa");
        assert!(!setup.secret.is_empty());
        assert!(setup.qr_code_svg.contains("<svg"));

        // A wrong code is refused.
        match verify_and_enable_mfa(
            State(f.state.clone()),
            Some(axum::Extension(f.user.clone())),
            request_info(),
            Json(MfaVerifyRequest {
                code: "000000".to_string(),
            }),
        )
        .await
        {
            Err(AppError::BadRequest(message)) => assert!(message.contains("Invalid TOTP")),
            other => panic!("expected invalid-code refusal, got {other:?}"),
        }

        // The current valid code (computed exactly as an app would) enables MFA.
        let mfa_service = MfaService::new();
        let totp = mfa_service
            .create_totp(&setup.secret, &f.user.user.email)
            .expect("totp");
        let code = totp.generate_current().expect("generate current code");
        let Json(verified) = verify_and_enable_mfa(
            State(f.state.clone()),
            Some(axum::Extension(f.user.clone())),
            request_info(),
            Json(MfaVerifyRequest { code }),
        )
        .await
        .expect("verify and enable");
        assert!(!verified.backup_codes.is_empty());
        let new_access_token = verified.access_token.expect("post-MFA access token");
        assert!(verified.refresh_token.is_some());
        assert_eq!(
            f.state
                .jwt_service
                .validate_token(&new_access_token)
                .expect("post-MFA claims")
                .mfa_verified,
            Some(true),
            "the rotated session must carry proof of MFA completion"
        );
        let new_session = SessionStore::find_by_token_hash(
            DB::Conn(&f.state.db),
            &crate::crypto::jwt::JwtService::hash_token(&new_access_token),
        )
        .await
        .expect("load post-MFA session")
        .expect("post-MFA session exists");
        let user_after_mfa = AuthUser {
            claims: f
                .state
                .jwt_service
                .validate_token(&new_access_token)
                .expect("post-MFA claims"),
            user: f.user.user.clone(),
            permissions: vec![],
            ip_address: "127.0.0.1".to_string(),
            user_agent: "mfa-test".to_string(),
            current_session_id: Some(new_session.id),
        };

        // Active factors must be disabled before a new factor can be enrolled.
        match setup_mfa(
            State(f.state.clone()),
            Some(axum::Extension(f.user.clone())),
            request_info(),
            None,
        )
        .await
        {
            Err(AppError::BadRequest(message)) => assert!(message.contains("already enabled")),
            other => panic!("expected active-factor refusal, got {other:?}"),
        }

        // Status now reports enabled.
        let Json(status) = get_mfa_status(
            State(f.state.clone()),
            Some(axum::Extension(user_after_mfa.clone())),
        )
        .await
        .expect("status");
        assert!(status.enabled);
        assert!(status.has_backup_codes);

        // Regenerating backup codes requires enabled MFA and succeeds here.
        let regeneration_code = mfa_service
            .create_totp(&setup.secret, &f.user.user.email)
            .expect("regeneration totp")
            .generate_current()
            .expect("regeneration code");
        let Json(new_codes) = regenerate_backup_codes(
            State(f.state.clone()),
            Some(axum::Extension(user_after_mfa.clone())),
            request_info(),
            Some(Json(MfaConfirmationRequest {
                mfa_code: Some(regeneration_code),
            })),
        )
        .await
        .expect("regenerate backup codes");
        assert!(!new_codes.backup_codes.is_empty());

        // Disabling without the current factor is refused.
        match disable_mfa(
            State(f.state.clone()),
            Some(axum::Extension(user_after_mfa.clone())),
            request_info(),
            None,
        )
        .await
        {
            Err(AppError::Forbidden(message)) => assert!(message.contains("MFA code")),
            other => panic!("expected MFA step-up refusal, got {other:?}"),
        }

        // Disabling clears the secret.
        let disable_code = mfa_service
            .create_totp(&setup.secret, &f.user.user.email)
            .expect("disable totp")
            .generate_current()
            .expect("disable code");
        let Json(disabled) = disable_mfa(
            State(f.state.clone()),
            Some(axum::Extension(user_after_mfa)),
            request_info(),
            Some(Json(MfaConfirmationRequest {
                mfa_code: Some(disable_code),
            })),
        )
        .await
        .expect("disable mfa");
        assert_eq!(disabled["success"], true);
        assert!(disabled["access_token"].as_str().is_some());
        let Json(after) = get_mfa_status(
            State(f.state.clone()),
            Some(axum::Extension(f.user.clone())),
        )
        .await
        .expect("status after disable");
        assert!(!after.enabled);
    }

    #[tokio::test]
    async fn regenerating_without_enabled_mfa_is_refused() {
        unsafe { std::env::set_var("ENCRYPTION_KEY", "22".repeat(32)) };
        let f = fixture().await;
        match regenerate_backup_codes(
            State(f.state.clone()),
            Some(axum::Extension(f.user.clone())),
            request_info(),
            None,
        )
        .await
        {
            Err(AppError::BadRequest(message)) => {
                assert!(message.contains("MFA is not enabled"))
            }
            other => panic!("expected refusal, got {other:?}"),
        }
    }
}
