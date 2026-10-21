use crate::crypto::jwt::JwtService;
use crate::db::transaction::with_retrying_transaction;
use crate::db::DB;
use crate::error::{AppError, Result};
use crate::middleware::{AuthUser, RequestInfo};
use crate::services::webauthn::WebAuthnService;
use crate::state::AppState;
use crate::store::users::UserStore;
use crate::store::webauthn_challenges::WebAuthnChallengeStore;
use crate::store::{
    identities::IdentityStore, memberships::MembershipStore, organizations::OrganizationStore,
    services::ServiceStore, sessions::SessionStore, user_passkeys::UserPasskeysStore,
};
use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Json},
    Extension,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

const PASSKEY_AUTH_UNAVAILABLE: &str = "Passkey authentication is unavailable";

fn passkey_auth_unavailable() -> AppError {
    AppError::BadRequest(PASSKEY_AUTH_UNAVAILABLE.to_string())
}

fn ensure_passkey_login_allowed(action: &crate::services::risk_engine::RiskAction) -> Result<()> {
    use crate::services::risk_engine::RiskAction;
    match action {
        RiskAction::Allow | RiskAction::LogOnly => Ok(()),
        RiskAction::ChallengeMFA => Err(AppError::Forbidden(
            "Additional verification required. Please use another login method.".to_string(),
        )),
        RiskAction::Block => Err(AppError::Forbidden(
            "Suspicious login detected. Please contact support.".to_string(),
        )),
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyRegisterStartRequest {
    pub name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PasskeyRegisterStartResponse {
    pub challenge_id: String,
    pub options: CreationChallengeResponse,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyRegisterFinishRequest {
    pub challenge_id: String,
    pub credential: RegisterPublicKeyCredential,
}

#[derive(Debug, Serialize)]
pub struct PasskeyRegisterFinishResponse {
    pub success: bool,
    pub passkey_id: String,
}

#[derive(Debug, Serialize)]
pub struct UserPasskeyResponse {
    pub id: String,
    pub name: String,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub transports: Option<String>,
    pub last_used_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdatePasskeyNameRequest {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct PasskeyActionResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredPasskeyRegistration {
    registration: PasskeyRegistration,
    name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyAuthStartRequest {
    pub email: String,
    pub org_slug: Option<String>,
    pub service_slug: Option<String>,
    pub redirect_uri: Option<String>,
    pub state: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PasskeyAuthStartResponse {
    pub challenge_id: String,
    pub options: RequestChallengeResponse,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyAuthFinishRequest {
    pub challenge_id: String,
    pub credential: PublicKeyCredential,
}

#[derive(Debug, Serialize)]
pub struct PasskeyAuthFinishResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    /// Backward compatible alias for access_token.
    pub token: String,
    pub user_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_trust_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct PasskeyAuthContext {
    org_slug: Option<String>,
    service_slug: Option<String>,
    redirect_uri: Option<String>,
    state: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredPasskeyAuthentication {
    authentication: PasskeyAuthentication,
    context: Option<PasskeyAuthContext>,
}

fn redirect_uri_allowed(service: &crate::entities::services::Model, redirect_uri: &str) -> bool {
    service
        .redirect_uris
        .as_deref()
        .and_then(|uris| serde_json::from_str::<Vec<String>>(uris).ok())
        .is_some_and(|uris| !uris.is_empty() && uris.iter().any(|uri| uri == redirect_uri))
}

/// POST /auth/passkeys/register/start
/// Start passkey registration ceremony (requires authenticated user)
pub async fn register_start(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Json(req): Json<PasskeyRegisterStartRequest>,
) -> Result<impl IntoResponse> {
    let db = DB::Conn(&state.db);
    crate::middleware::require_recent_authentication(
        &state.db,
        &auth_user,
        chrono::Duration::minutes(10),
    )
    .await?;

    let user = UserStore::find_by_id(db.clone(), &auth_user.claims.sub)
        .await?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;

    let webauthn = state
        .webauthn_service
        .as_ref()
        .ok_or_else(|| {
            AppError::InternalServerError("WebAuthn service not configured".to_string())
        })?
        .as_ref();

    let existing_passkeys = WebAuthnService::load_user_passkeys(db.clone(), &user.id).await?;

    let exclude_credentials: Vec<CredentialID> = existing_passkeys
        .iter()
        .map(|p| p.cred_id().clone())
        .collect();

    let (challenge_response, passkey_reg) =
        webauthn.start_registration(&user.id, &user.email, &user.email, exclude_credentials)?;

    let display_name = req
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or("My Passkey")
        .chars()
        .take(80)
        .collect::<String>();

    let stored_registration = StoredPasskeyRegistration {
        registration: passkey_reg,
        name: Some(display_name),
    };

    let challenge_state = serde_json::to_string(&stored_registration).map_err(|e| {
        AppError::InternalServerError(format!("Failed to serialize challenge: {}", e))
    })?;

    let challenge_record =
        WebAuthnChallengeStore::create(db, &user.id, "registration", &challenge_state, 300).await?;

    Ok((
        StatusCode::OK,
        Json(PasskeyRegisterStartResponse {
            challenge_id: challenge_record.id,
            options: challenge_response,
        }),
    ))
}

/// POST /auth/passkeys/register/finish
/// Complete passkey registration ceremony (requires authenticated user)
pub async fn register_finish(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Json(req): Json<PasskeyRegisterFinishRequest>,
) -> Result<impl IntoResponse> {
    let db = DB::Conn(&state.db);
    crate::middleware::require_recent_authentication(
        &state.db,
        &auth_user,
        chrono::Duration::minutes(10),
    )
    .await?;

    let user = UserStore::find_by_id(db.clone(), &auth_user.claims.sub)
        .await?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;

    let challenge_record = WebAuthnChallengeStore::find_by_id(db.clone(), &req.challenge_id)
        .await?
        .ok_or_else(|| AppError::BadRequest("Invalid or expired challenge".to_string()))?;

    if challenge_record.user_id != user.id {
        return Err(AppError::Unauthorized(
            "Challenge does not belong to user".to_string(),
        ));
    }

    if challenge_record.challenge_type != "registration" {
        return Err(AppError::BadRequest("Invalid challenge type".to_string()));
    }

    if !WebAuthnChallengeStore::delete(db.clone(), &req.challenge_id).await? {
        return Err(AppError::BadRequest(
            "Invalid or expired challenge".to_string(),
        ));
    }

    let stored_registration: Result<StoredPasskeyRegistration> =
        serde_json::from_str(&challenge_record.challenge_state).map_err(|e| {
            AppError::InternalServerError(format!("Failed to deserialize challenge: {}", e))
        });

    let (passkey_reg, passkey_name) = match stored_registration {
        Ok(stored) => (
            stored.registration,
            stored
                .name
                .filter(|name| !name.trim().is_empty())
                .unwrap_or_else(|| "My Passkey".to_string()),
        ),
        Err(_) => {
            let legacy_reg: PasskeyRegistration =
                serde_json::from_str(&challenge_record.challenge_state).map_err(|e| {
                    AppError::InternalServerError(format!("Failed to deserialize challenge: {}", e))
                })?;
            (legacy_reg, "My Passkey".to_string())
        }
    };

    let webauthn = state
        .webauthn_service
        .as_ref()
        .ok_or_else(|| {
            AppError::InternalServerError("WebAuthn service not configured".to_string())
        })?
        .as_ref();

    let passkey = webauthn.finish_registration(&req.credential, &passkey_reg)?;

    let passkey_id =
        WebAuthnService::store_passkey(db.clone(), &user.id, &passkey, &passkey_name).await?;

    tracing::info!(
        user_id = %user.id,
        passkey_id = %passkey_id,
        "Passkey registered successfully"
    );

    Ok((
        StatusCode::OK,
        Json(PasskeyRegisterFinishResponse {
            success: true,
            passkey_id,
        }),
    ))
}

/// GET /api/auth/passkeys
/// List passkeys for the authenticated user.
pub async fn list_passkeys(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
) -> Result<Json<Vec<UserPasskeyResponse>>> {
    let passkeys =
        UserPasskeysStore::list_by_user(DB::Conn(&state.db), &auth_user.claims.sub).await?;

    Ok(Json(
        passkeys
            .into_iter()
            .map(|passkey| UserPasskeyResponse {
                id: passkey.id,
                name: passkey.name,
                backup_eligible: passkey.backup_eligible,
                backup_state: passkey.backup_state,
                transports: passkey.transports,
                last_used_at: passkey.last_used_at.map(|dt| {
                    chrono::DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc).to_rfc3339()
                }),
                created_at: chrono::DateTime::<Utc>::from_naive_utc_and_offset(
                    passkey.created_at,
                    Utc,
                )
                .to_rfc3339(),
            })
            .collect(),
    ))
}

/// PATCH /api/auth/passkeys/:passkey_id
/// Rename a passkey owned by the authenticated user.
pub async fn update_passkey_name(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(passkey_id): Path<String>,
    Json(req): Json<UpdatePasskeyNameRequest>,
) -> Result<Json<UserPasskeyResponse>> {
    let name = req.name.trim();
    if name.is_empty() {
        return Err(AppError::BadRequest(
            "Passkey name cannot be empty".to_string(),
        ));
    }
    if name.len() > 80 {
        return Err(AppError::BadRequest(
            "Passkey name cannot exceed 80 characters".to_string(),
        ));
    }

    if !UserPasskeysStore::update_name(
        DB::Conn(&state.db),
        &passkey_id,
        &auth_user.claims.sub,
        name,
    )
    .await?
    {
        return Err(AppError::NotFound("Passkey not found".to_string()));
    }

    let passkey = UserPasskeysStore::find_by_id_for_user(
        DB::Conn(&state.db),
        &passkey_id,
        &auth_user.claims.sub,
    )
    .await?
    .ok_or_else(|| AppError::NotFound("Passkey not found".to_string()))?;

    Ok(Json(UserPasskeyResponse {
        id: passkey.id,
        name: passkey.name,
        backup_eligible: passkey.backup_eligible,
        backup_state: passkey.backup_state,
        transports: passkey.transports,
        last_used_at: passkey
            .last_used_at
            .map(|dt| chrono::DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc).to_rfc3339()),
        created_at: chrono::DateTime::<Utc>::from_naive_utc_and_offset(passkey.created_at, Utc)
            .to_rfc3339(),
    }))
}

/// DELETE /api/auth/passkeys/:passkey_id
/// Delete a passkey owned by the authenticated user.
pub async fn delete_passkey(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(passkey_id): Path<String>,
) -> Result<Json<PasskeyActionResponse>> {
    let deleted =
        UserPasskeysStore::delete(DB::Conn(&state.db), &passkey_id, &auth_user.claims.sub).await?;

    if !deleted {
        return Err(AppError::NotFound("Passkey not found".to_string()));
    }

    Ok(Json(PasskeyActionResponse {
        success: true,
        message: "Passkey deleted".to_string(),
    }))
}

/// POST /auth/passkeys/authenticate/start
/// Start passkey authentication ceremony (public endpoint)
pub async fn authenticate_start(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<PasskeyAuthStartRequest>,
) -> Result<impl IntoResponse> {
    if req.org_slug.is_none() && req.service_slug.is_none() && req.redirect_uri.is_none() {
        crate::middleware::ensure_trusted_platform_origin(&headers, &state.config)?;
    }
    let db = DB::Conn(&state.db);

    let context = if req.org_slug.is_some()
        || req.service_slug.is_some()
        || req.redirect_uri.is_some()
    {
        let org_slug = req
            .org_slug
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                AppError::BadRequest("org_slug is required for scoped passkey login".to_string())
            })?;
        let service_slug = req
            .service_slug
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                AppError::BadRequest(
                    "service_slug is required for scoped passkey login".to_string(),
                )
            })?;

        let org = OrganizationStore::find_by_slug(db.clone(), org_slug)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
        crate::handlers::organizations::ensure_organization_active(&state.db, &org.id).await?;
        let service = ServiceStore::find_by_org_and_slug(db.clone(), &org.id, service_slug)
            .await?
            .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;

        if let Some(redirect_uri) = req.redirect_uri.as_deref() {
            if !redirect_uri_allowed(&service, redirect_uri) {
                return Err(AppError::BadRequest(
                    "redirect_uri is not registered for this service".to_string(),
                ));
            }
        }

        Some(PasskeyAuthContext {
            org_slug: Some(org_slug.to_string()),
            service_slug: Some(service_slug.to_string()),
            redirect_uri: req.redirect_uri.clone(),
            state: req.state.clone(),
        })
    } else {
        None
    };

    let user = if let Some(context) = &context {
        let org_slug = context.org_slug.as_deref().ok_or_else(|| {
            AppError::BadRequest("org_slug is required for scoped passkey login".to_string())
        })?;
        let org = OrganizationStore::find_by_slug(db.clone(), org_slug)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
        crate::handlers::organizations::ensure_organization_active(&state.db, &org.id).await?;

        UserStore::find_by_email_with_context(db.clone(), &req.email, Some(&org.id)).await?
    } else {
        UserStore::find_by_email_with_context(db.clone(), &req.email, None).await?
    };

    // Keep missing-user and unenrolled-user paths aligned through the same
    // passkey-table query. `None` compiles to `user_id IS NULL`, an impossible
    // typed predicate for the non-null foreign-key column, so no imported row
    // can collide with a fixed sentinel.
    let passkeys = WebAuthnService::load_user_passkeys_for_public_auth(
        db.clone(),
        user.as_ref().map(|user| user.id.as_str()),
    )
    .await?;

    if passkeys.is_empty() {
        return Err(passkey_auth_unavailable());
    }
    let user = user.ok_or_else(passkey_auth_unavailable)?;

    let webauthn = state
        .webauthn_service
        .as_ref()
        .ok_or_else(|| {
            AppError::InternalServerError("WebAuthn service not configured".to_string())
        })?
        .as_ref();

    let (challenge_response, passkey_auth) = webauthn.start_authentication(passkeys)?;

    let challenge_state = serde_json::to_string(&StoredPasskeyAuthentication {
        authentication: passkey_auth,
        context,
    })
    .map_err(|e| AppError::InternalServerError(format!("Failed to serialize challenge: {}", e)))?;

    let challenge_record =
        WebAuthnChallengeStore::create(db, &user.id, "authentication", &challenge_state, 300)
            .await?;

    Ok((
        StatusCode::OK,
        Json(PasskeyAuthStartResponse {
            challenge_id: challenge_record.id,
            options: challenge_response,
        }),
    ))
}

/// POST /auth/passkeys/authenticate/finish
/// Complete passkey authentication ceremony and issue JWT (public endpoint)
pub async fn authenticate_finish(
    State(state): State<AppState>,
    Extension(request_info): Extension<RequestInfo>,
    headers: axum::http::HeaderMap,
    Json(req): Json<PasskeyAuthFinishRequest>,
) -> Result<impl IntoResponse> {
    let db = DB::Conn(&state.db);

    let challenge_record = WebAuthnChallengeStore::find_by_id(db.clone(), &req.challenge_id)
        .await?
        .ok_or_else(|| AppError::BadRequest("Invalid or expired challenge".to_string()))?;

    if challenge_record.challenge_type != "authentication" {
        return Err(AppError::BadRequest("Invalid challenge type".to_string()));
    }

    if !WebAuthnChallengeStore::delete(db.clone(), &req.challenge_id).await? {
        return Err(AppError::BadRequest(
            "Invalid or expired challenge".to_string(),
        ));
    }

    let stored_auth: Result<StoredPasskeyAuthentication> =
        serde_json::from_str(&challenge_record.challenge_state).map_err(|e| {
            AppError::InternalServerError(format!("Failed to deserialize challenge: {}", e))
        });

    let (passkey_auth, auth_context) = match stored_auth {
        Ok(stored) => (stored.authentication, stored.context),
        Err(_) => {
            let legacy_auth: PasskeyAuthentication =
                serde_json::from_str(&challenge_record.challenge_state).map_err(|e| {
                    AppError::InternalServerError(format!("Failed to deserialize challenge: {}", e))
                })?;
            (legacy_auth, None)
        }
    };

    let webauthn = state
        .webauthn_service
        .as_ref()
        .ok_or_else(|| {
            AppError::InternalServerError("WebAuthn service not configured".to_string())
        })?
        .as_ref();

    let auth_result = webauthn.finish_authentication(&req.credential, &passkey_auth)?;

    WebAuthnService::update_passkey_after_authentication(db.clone(), &auth_result).await?;

    let user = UserStore::find_by_id(db.clone(), &challenge_record.user_id)
        .await?
        .filter(|user| user.deleted_at.is_none())
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Determine organization context for risk evaluation
    // Use the user's first (oldest) organization membership if available
    use crate::entities::{identities, memberships, prelude::Identities, prelude::Memberships};
    use sea_orm::{ColumnTrait, EntityTrait, Order, QueryFilter, QueryOrder};

    let user_membership = Memberships::find()
        .filter(memberships::Column::UserId.eq(&user.id))
        .order_by(memberships::Column::CreatedAt, Order::Asc)
        .one(&db)
        .await?;

    let (org_id_owned, service_id_owned) = if let Some(context) = &auth_context {
        if let (Some(org_slug), Some(service_slug)) = (&context.org_slug, &context.service_slug) {
            let org = OrganizationStore::find_by_slug(db.clone(), org_slug)
                .await?
                .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
            crate::handlers::organizations::ensure_organization_active(&state.db, &org.id).await?;
            let service = ServiceStore::find_by_org_and_slug(db.clone(), &org.id, service_slug)
                .await?
                .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;

            if !user.is_platform_owner {
                let has_service_identity = Identities::find()
                    .filter(identities::Column::UserId.eq(&user.id))
                    .filter(identities::Column::IssuingOrgId.eq(&org.id))
                    .filter(identities::Column::IssuingServiceId.eq(&service.id))
                    .one(&db)
                    .await?
                    .is_some();

                if !has_service_identity {
                    return Err(AppError::Forbidden(
                        "You do not have access to this service".to_string(),
                    ));
                }
            }
            (Some(org.id), Some(service.id))
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    if auth_context
        .as_ref()
        .and_then(|context| context.org_slug.as_deref())
        .is_none()
    {
        crate::middleware::ensure_trusted_platform_origin(&headers, &state.config)?;
    }

    let org_id_opt = org_id_owned
        .as_deref()
        .or_else(|| user_membership.as_ref().map(|m| m.org_id.as_str()));

    // Run risk engine evaluation
    use crate::services::risk_engine::RiskContext;
    let risk_ctx = RiskContext {
        user_id: &user.id,
        org_id: org_id_opt, // Use first organization membership if available
        ip_address: &request_info.ip_address,
        user_agent: &request_info.user_agent,
        device_cookie: None, // No device cookie available during passkey auth
    };

    let risk_assessment = state.risk_engine.evaluate(db.clone(), risk_ctx).await?;

    // Log risk assessment
    tracing::info!(
        user_id = %user.id,
        risk_score = risk_assessment.score,
        risk_action = ?risk_assessment.action,
        risk_factors = ?risk_assessment.factors,
        "Passkey authentication risk assessment"
    );

    use crate::services::risk_engine::RiskAction;
    if matches!(risk_assessment.action, RiskAction::Block) {
        tracing::warn!(
            user_id = %user.id,
            risk_score = risk_assessment.score,
            factors = ?risk_assessment.factors,
            "Passkey authentication blocked by risk engine"
        );
    }
    // A blocked/challenged attempt must not create a success event or session.
    ensure_passkey_login_allowed(&risk_assessment.action)?;

    let token = state.jwt_service.create_token(
        &user.id,
        &user.email,
        user.is_platform_owner,
        auth_context
            .as_ref()
            .and_then(|ctx| ctx.org_slug.as_deref()),
        auth_context
            .as_ref()
            .and_then(|ctx| ctx.service_slug.as_deref()),
    )?;

    let refresh_token = crate::crypto::refresh_tokens::generate();
    let token_hash = JwtService::hash_token(&token);
    let now = Utc::now();
    let expires_at = now + chrono::Duration::hours(state.config.jwt_expiration_hours);
    let refresh_expires_at = now + chrono::Duration::days(30);

    // Generate device trust material before entering the database transaction.
    let device_trust = if matches!(risk_assessment.action, RiskAction::Allow) {
        let device_token = state.risk_engine.generate_device_token(&user.id);
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(device_token.as_bytes());
        Some((
            device_token,
            hex::encode(hasher.finalize()),
            (Utc::now() + chrono::Duration::days(90)).naive_utc(),
        ))
    } else {
        None
    };
    let risk_factors_json = serde_json::to_string(&risk_assessment.factors).ok();
    let event_model = crate::entities::login_events::ActiveModel {
        id: sea_orm::Set(uuid::Uuid::new_v4().to_string()),
        user_id: sea_orm::Set(user.id.clone()),
        service_id: sea_orm::Set(service_id_owned.clone()),
        provider: sea_orm::Set("passkey".to_string()),
        ip_address: sea_orm::Set(Some(request_info.ip_address.clone())),
        user_agent: sea_orm::Set(Some(request_info.user_agent.clone())),
        risk_score: sea_orm::Set(Some(risk_assessment.score)),
        risk_factors: sea_orm::Set(risk_factors_json),
        geo_country: sea_orm::Set(None),
        geo_city: sea_orm::Set(None),
        geo_lat: sea_orm::Set(None),
        geo_long: sea_orm::Set(None),
        ..Default::default()
    };
    let session_org_slug = auth_context.as_ref().and_then(|ctx| ctx.org_slug.clone());
    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "persist_passkey_login_with_audit",
        |tx| {
            let user_id = user.id.clone();
            let token_hash = token_hash.clone();
            let refresh_token = refresh_token.clone();
            let service_id = service_id_owned.clone();
            let org_slug = session_org_slug.clone();
            let user_agent = request_info.user_agent.clone();
            let ip_address = request_info.ip_address.clone();
            let device_trust = device_trust.clone();
            let event_model = event_model.clone();
            let audit_actor = state.audit_actor.clone();
            Box::pin(async move {
                validate_passkey_login_authority(
                    tx.clone(),
                    &user_id,
                    org_slug.as_deref(),
                    service_id.as_deref(),
                )
                .await?;
                SessionStore::create(
                    tx.clone(),
                    &user_id,
                    &token_hash,
                    expires_at.naive_utc(),
                    Some(&refresh_token),
                    Some(refresh_expires_at.naive_utc()),
                    org_slug.as_deref(),
                    service_id.as_deref(),
                    None,
                    Some(&user_agent),
                    Some(&ip_address),
                )
                .await?;
                if let Some((_, device_token_hash, device_expires_at)) = device_trust {
                    crate::store::user_devices::UserDevicesStore::create(
                        tx.clone(),
                        &user_id,
                        &device_token_hash,
                        "Passkey Authentication Device",
                        Some(ip_address),
                        device_expires_at,
                    )
                    .await?;
                }
                audit_actor.log_login_with_db(tx, event_model).await?;
                Ok(())
            })
        },
    )
    .await?;

    let device_cookie_value = device_trust.map(|(token, _, _)| token);

    tracing::info!(
        user_id = %user.id,
        "Passkey authentication successful"
    );

    // Add device trust token to response for native clients
    let device_trust_token = device_cookie_value.clone();

    // Prepare response
    let response = PasskeyAuthFinishResponse {
        access_token: token.clone(),
        refresh_token,
        expires_in: state.config.jwt_expiration_hours * 3600,
        token,
        user_id: user.id,
        device_trust_token,
    };

    // For web clients, set the cookie if device trust was established
    if let Some(device_token) = device_cookie_value {
        let cookie_value = format!(
            "device_token={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={}",
            device_token,
            90 * 24 * 3600 // 90 days in seconds
        );

        let response = Json(response);
        Ok((
            StatusCode::OK,
            [(header::SET_COOKIE, cookie_value)],
            response,
        )
            .into_response())
    } else {
        Ok((StatusCode::OK, Json(response)).into_response())
    }
}

async fn validate_passkey_login_authority(
    db: DB<'_>,
    user_id: &str,
    org_slug: Option<&str>,
    service_id: Option<&str>,
) -> Result<()> {
    let user = UserStore::find_by_id(db.clone(), user_id)
        .await?
        .filter(|user| user.deleted_at.is_none())
        .ok_or_else(passkey_auth_unavailable)?;
    let Some(org_slug) = org_slug else {
        if service_id.is_some() {
            return Err(passkey_auth_unavailable());
        }
        return Ok(());
    };
    let org = OrganizationStore::find_by_slug(db.clone(), org_slug)
        .await?
        .filter(|org| org.status == "active")
        .ok_or_else(passkey_auth_unavailable)?;
    if user.is_platform_owner {
        return Ok(());
    }
    if let Some(service_id) = service_id {
        let has_membership = MembershipStore::find_by_org_and_user(db.clone(), &org.id, user_id)
            .await?
            .is_some();
        let has_service_identity =
            IdentityStore::exists_for_user_and_service_context(db, user_id, &org.id, service_id)
                .await?;
        if !has_membership && !has_service_identity {
            return Err(passkey_auth_unavailable());
        }
    } else if MembershipStore::find_by_org_and_user(db, &org.id, user_id)
        .await?
        .is_none()
    {
        return Err(passkey_auth_unavailable());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::crypto::sso::OAuthClient;

    use crate::audit::actor::AuditHandle;
    use crate::services::{
        events::EventDispatcher, metrics::MfaMetricsService, risk_engine::RiskEngine,
    };
    use crate::store::{
        organizations::OrganizationStore,
        services::ServiceStore,
        users::{UserCreationOptions, UserStore},
    };

    use migration::{Migrator, MigratorTrait};
    use moka::future::Cache;
    use sea_orm::{ActiveModelTrait, Database, Set};
    use std::sync::Arc;

    #[test]
    fn risk_gate_rejects_before_passkey_success_persistence() {
        use crate::services::risk_engine::RiskAction;

        assert!(ensure_passkey_login_allowed(&RiskAction::Allow).is_ok());
        assert!(ensure_passkey_login_allowed(&RiskAction::LogOnly).is_ok());
        assert!(matches!(
            ensure_passkey_login_allowed(&RiskAction::ChallengeMFA),
            Err(AppError::Forbidden(_))
        ));
        assert!(matches!(
            ensure_passkey_login_allowed(&RiskAction::Block),
            Err(AppError::Forbidden(_))
        ));
    }

    use crate::test_support::test_config;

    use crate::test_support::test_jwt_service;

    async fn setup_passkey_state_with_suspended_org() -> AppState {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let config = test_config();
        let owner = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "owner@example.com",
            UserCreationOptions {
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
        OrganizationStore::update_status(DB::Conn(&db), &org.id, "suspended")
            .await
            .expect("suspend org");
        ServiceStore::create(
            DB::Conn(&db),
            &org.id,
            "portal",
            "Portal",
            "web",
            "client-portal",
        )
        .await
        .expect("create service");

        let jwt_service = Arc::new(test_jwt_service(&config));
        let oauth_client = Arc::new(OAuthClient::new(&config).expect("create oauth client"));
        AppState {
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
        }
    }

    #[tokio::test]
    async fn scoped_passkey_auth_start_rejects_inactive_org_before_challenge() {
        let state = setup_passkey_state_with_suspended_org().await;

        let result = authenticate_start(
            State(state),
            axum::http::HeaderMap::new(),
            Json(PasskeyAuthStartRequest {
                email: "member@example.com".to_string(),
                org_slug: Some("acme".to_string()),
                service_slug: Some("portal".to_string()),
                redirect_uri: None,
                state: None,
            }),
        )
        .await;

        assert!(matches!(
            result,
            Err(AppError::Forbidden(ref message))
                if message.contains("Organization is not active")
        ));
    }

    #[tokio::test]
    async fn passkey_session_boundary_rechecks_deleted_user_and_service_entitlement() {
        let state = setup_passkey_state_with_suspended_org().await;
        let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), "acme")
            .await
            .unwrap()
            .unwrap();
        OrganizationStore::update_status(DB::Conn(&state.db), &org.id, "active")
            .await
            .unwrap();
        let service = ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, "portal")
            .await
            .unwrap()
            .unwrap();
        let user = UserStore::create(
            DB::Conn(&state.db),
            "passkey-member@example.test",
            None,
            false,
        )
        .await
        .unwrap();
        MembershipStore::create(DB::Conn(&state.db), &org.id, &user.id, "member")
            .await
            .unwrap();

        assert!(validate_passkey_login_authority(
            DB::Conn(&state.db),
            &user.id,
            Some(&org.slug),
            Some(&service.id),
        )
        .await
        .is_ok());
        MembershipStore::delete_by_org_and_user(DB::Conn(&state.db), &org.id, &user.id)
            .await
            .unwrap();
        assert!(validate_passkey_login_authority(
            DB::Conn(&state.db),
            &user.id,
            Some(&org.slug),
            Some(&service.id),
        )
        .await
        .is_err());

        IdentityStore::create(
            DB::Conn(&state.db),
            &user.id,
            "passkey",
            "credential-1",
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
        .unwrap();
        assert!(validate_passkey_login_authority(
            DB::Conn(&state.db),
            &user.id,
            Some(&org.slug),
            Some(&service.id),
        )
        .await
        .is_ok());
        IdentityStore::delete_by_user_and_service(DB::Conn(&state.db), &user.id, &service.id)
            .await
            .unwrap();
        assert!(validate_passkey_login_authority(
            DB::Conn(&state.db),
            &user.id,
            Some(&org.slug),
            Some(&service.id),
        )
        .await
        .is_err());

        let user_id = user.id.clone();
        let mut deleted_user: crate::entities::users::ActiveModel = user.into();
        deleted_user.deleted_at = Set(Some(Utc::now().naive_utc()));
        deleted_user.update(&state.db).await.unwrap();
        assert!(
            validate_passkey_login_authority(DB::Conn(&state.db), &user_id, None, None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn passkey_auth_start_normalizes_absent_and_unenrolled_accounts() {
        let state = setup_passkey_state_with_suspended_org().await;

        let mut errors = Vec::new();
        for email in ["absent@example.com", "owner@example.com"] {
            let result = authenticate_start(
                State(state.clone()),
                axum::http::HeaderMap::new(),
                Json(PasskeyAuthStartRequest {
                    email: email.to_string(),
                    org_slug: None,
                    service_slug: None,
                    redirect_uri: None,
                    state: None,
                }),
            )
            .await;
            let error = match result {
                Err(error) => error,
                Ok(_) => panic!("passkey start must be unavailable"),
            };

            assert!(matches!(
                error,
                AppError::BadRequest(ref message) if message == PASSKEY_AUTH_UNAVAILABLE
            ));
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
            errors.push((status, headers, body));
        }
        assert_eq!(errors[0], errors[1]);
    }

    fn auth_user_for(user: crate::entities::users::Model) -> AuthUser {
        let now = Utc::now();
        AuthUser {
            claims: crate::crypto::jwt::Claims {
                token_use: crate::crypto::jwt::TokenUse::ManagementAccess,
                sub: user.id.clone(),
                email: user.email.clone(),
                is_platform_owner: user.is_platform_owner,
                jti: uuid::Uuid::new_v4().to_string(),
                org: None,
                service: None,
                mfa_required: None,
                mfa_verified: None,
                saml_state: None,
                device_code_id: None,
                act: None,
                bootstrap: None,
                aud: Some("platform".to_string()),
                iss: Some("http://localhost:3001".to_string()),
                scope: None,
                exp: (now + chrono::Duration::hours(1)).timestamp(),
                iat: now.timestamp(),
            },
            user,
            permissions: vec![],
            ip_address: "127.0.0.1".to_string(),
            user_agent: "test".to_string(),
            current_session_id: None,
        }
    }

    #[tokio::test]
    async fn passkey_management_lists_renames_and_deletes_owned_passkeys() {
        let state = setup_passkey_state_with_suspended_org().await;
        let owner = UserStore::find_by_email(DB::Conn(&state.db), "owner@example.com")
            .await
            .expect("find owner")
            .expect("owner exists");
        let passkey = UserPasskeysStore::create(
            DB::Conn(&state.db),
            &owner.id,
            "credential-1",
            "public-key",
            None,
            "Laptop",
            true,
            false,
            Some(r#"["internal"]"#.to_string()),
        )
        .await
        .expect("create passkey");
        let auth_user = auth_user_for(owner);

        let listed = list_passkeys(State(state.clone()), Extension(auth_user.clone()))
            .await
            .expect("list passkeys")
            .0;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, passkey.id);
        assert_eq!(listed[0].name, "Laptop");
        assert!(listed[0].backup_eligible);

        let renamed = update_passkey_name(
            State(state.clone()),
            Extension(auth_user.clone()),
            Path(passkey.id.clone()),
            Json(UpdatePasskeyNameRequest {
                name: " Work laptop ".to_string(),
            }),
        )
        .await
        .expect("rename passkey")
        .0;
        assert_eq!(renamed.name, "Work laptop");

        let deleted = delete_passkey(
            State(state.clone()),
            Extension(auth_user.clone()),
            Path(passkey.id.clone()),
        )
        .await
        .expect("delete passkey")
        .0;
        assert!(deleted.success);

        let listed_after_delete = list_passkeys(State(state), Extension(auth_user))
            .await
            .expect("list after delete")
            .0;
        assert!(listed_after_delete.is_empty());
    }

    #[tokio::test]
    async fn passkey_management_rejects_invalid_or_unowned_mutations() {
        let state = setup_passkey_state_with_suspended_org().await;
        let owner = UserStore::find_by_email(DB::Conn(&state.db), "owner@example.com")
            .await
            .expect("find owner")
            .expect("owner exists");
        let other = UserStore::find_or_create_with_options(
            DB::Conn(&state.db),
            "other@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create other user")
        .0;
        let passkey = UserPasskeysStore::create(
            DB::Conn(&state.db),
            &owner.id,
            "credential-owned",
            "public-key",
            None,
            "Owner key",
            false,
            false,
            None,
        )
        .await
        .expect("create owner passkey");
        let owner_auth = auth_user_for(owner);
        let other_auth = auth_user_for(other);

        let blank_name = update_passkey_name(
            State(state.clone()),
            Extension(owner_auth.clone()),
            Path(passkey.id.clone()),
            Json(UpdatePasskeyNameRequest {
                name: "   ".to_string(),
            }),
        )
        .await;
        assert!(matches!(
            blank_name,
            Err(AppError::BadRequest(ref message))
                if message.contains("cannot be empty")
        ));

        let unowned_rename = update_passkey_name(
            State(state.clone()),
            Extension(other_auth.clone()),
            Path(passkey.id.clone()),
            Json(UpdatePasskeyNameRequest {
                name: "Stolen key".to_string(),
            }),
        )
        .await;
        assert!(matches!(
            unowned_rename,
            Err(AppError::NotFound(ref message)) if message == "Passkey not found"
        ));

        let unowned_delete = delete_passkey(
            State(state.clone()),
            Extension(other_auth),
            Path(passkey.id.clone()),
        )
        .await;
        assert!(matches!(
            unowned_delete,
            Err(AppError::NotFound(ref message)) if message == "Passkey not found"
        ));

        let still_present = UserPasskeysStore::find_by_id(DB::Conn(&state.db), &passkey.id)
            .await
            .expect("find passkey after rejected mutations")
            .expect("passkey remains");
        assert_eq!(still_present.name, "Owner key");
    }
}
