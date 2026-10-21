use crate::crypto::jwt::Claims;
use crate::db::models::User;
use crate::db::transaction::{with_deadlock_retry, with_retrying_transaction};
use crate::db::DB;
use crate::entities::users;
use crate::error::{AppError, Result};
use crate::middleware::RequestInfo;
use crate::services::audit_builder::MfaAuditBuilder;
use crate::state::AppState;
use crate::store::{
    device_codes::DeviceCodeStore, distributed_locks::DistributedLockStore,
    identities::IdentityStore, memberships::MembershipStore, organizations::OrganizationStore,
    services::ServiceStore, sessions::SessionStore, users::UserStore,
};
use axum::{extract::State, response::Response, Extension, Form, Json};
use chrono::Utc;
use serde::Deserialize;

// Re-export RefreshTokenResponse from session module
pub use super::session::RefreshTokenResponse;

// Import hash_token from password module
use super::password::hash_token;

#[derive(Debug, Deserialize)]
pub struct MfaVerifyRequest {
    pub preauth_token: String,
    pub code: String,
    pub device_code_id: Option<String>, // Optional: for device flow MFA completion
}

fn validate_device_context(claims: &Claims, requested_device_code_id: Option<&str>) -> Result<()> {
    if claims.device_code_id.as_deref() != requested_device_code_id {
        return Err(AppError::BadRequest(
            "Device authorization context is invalid or expired".to_string(),
        ));
    };
    Ok(())
}

fn validate_saml_mfa_context(
    claims: &Claims,
    requested_device_code_id: Option<&str>,
) -> Result<()> {
    if claims.saml_state.is_none()
        || claims.org.is_none()
        || claims.service.is_none()
        || claims.device_code_id.is_some()
        || requested_device_code_id.is_some()
    {
        return Err(AppError::BadRequest(
            "Invalid SAML MFA continuation".to_string(),
        ));
    }
    Ok(())
}

/// The platform admin device flow uses `org=platform` only as a signed binding
/// to the virtual `platform/admin-cli` device namespace. It is not a tenant
/// organization and must not be copied into the completed platform session.
fn completed_session_org_slug<'a>(
    claims: &'a Claims,
    requested_device_code_id: Option<&str>,
) -> Option<&'a str> {
    if requested_device_code_id.is_some()
        && claims.device_code_id.as_deref() == requested_device_code_id
        && claims.org.as_deref() == Some("platform")
        && claims.service.is_none()
    {
        None
    } else {
        claims.org.as_deref()
    }
}

struct VerifiedMfaChallenge {
    claims: Claims,
    user: User,
    backup_code_id: Option<String>,
    backup_event: crate::entities::mfa_audit_log::ActiveModel,
    success_event: crate::entities::mfa_audit_log::ActiveModel,
}

async fn validate_live_mfa_session_context(
    db: DB<'_>,
    claims: &Claims,
    requested_device_code_id: Option<&str>,
) -> Result<(crate::entities::users::Model, Option<String>)> {
    validate_device_context(claims, requested_device_code_id)?;
    let user = UserStore::find_by_id(db.clone(), &claims.sub)
        .await?
        .filter(|user| user.deleted_at.is_none())
        .ok_or_else(|| AppError::Unauthorized("User is no longer active".to_string()))?;
    if user.email != claims.email {
        return Err(AppError::Unauthorized(
            "Authentication context changed; sign in again".to_string(),
        ));
    }

    if let Some(device_code_id) = requested_device_code_id {
        let device_code = DeviceCodeStore::find_by_id(db.clone(), device_code_id)
            .await?
            .filter(|code| {
                code.status == "pending"
                    && code.user_id.as_deref() == Some(user.id.as_str())
                    && code.expires_at > Utc::now().naive_utc()
            })
            .ok_or_else(|| {
                AppError::BadRequest(
                    "Device authorization context is invalid or expired".to_string(),
                )
            })?;
        if claims.org.as_deref() != Some(device_code.org_slug.as_str()) {
            return Err(AppError::BadRequest(
                "Device authorization context is invalid or expired".to_string(),
            ));
        }
        if device_code.org_slug == "platform" && device_code.service_slug == "admin-cli" {
            if claims.service.is_some() || !user.is_platform_owner {
                return Err(AppError::Forbidden(
                    "Platform device authorization requires a current platform owner".to_string(),
                ));
            }
            return Ok((user, None));
        }
        if claims.service.as_deref() != Some(device_code.service_slug.as_str()) {
            return Err(AppError::BadRequest(
                "Device authorization context is invalid or expired".to_string(),
            ));
        }
    }

    match (claims.org.as_deref(), claims.service.as_deref()) {
        (None, None) => Ok((user, None)),
        (None, Some(_)) => Err(AppError::BadRequest(
            "Service authentication context is missing its organization".to_string(),
        )),
        (Some(org_slug), service_slug) => {
            let org = OrganizationStore::find_by_slug(db.clone(), org_slug)
                .await?
                .filter(|org| org.status == "active")
                .ok_or_else(|| AppError::Forbidden("Organization is not active".to_string()))?;
            if let Some(service_slug) = service_slug {
                let service = ServiceStore::find_by_org_and_slug(db.clone(), &org.id, service_slug)
                    .await?
                    .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;
                if !user.is_platform_owner
                    && !IdentityStore::exists_for_user_and_service_context(
                        db.clone(),
                        &user.id,
                        &org.id,
                        &service.id,
                    )
                    .await?
                {
                    return Err(AppError::Forbidden(
                        "You do not currently have access to this service".to_string(),
                    ));
                }
                if let Some(resource) =
                    crate::utils::resource_indicators::resource_from_audience(claims.aud.as_deref())
                {
                    crate::utils::resource_indicators::validate_requested_resource(
                        Some(resource),
                        service.resource_uris.as_deref(),
                    )?;
                }
                Ok((user, Some(service.id)))
            } else {
                if !user.is_platform_owner
                    && MembershipStore::find_by_org_and_user(db.clone(), &org.id, &user.id)
                        .await?
                        .is_none()
                {
                    return Err(AppError::Forbidden(
                        "You are no longer a member of this organization".to_string(),
                    ));
                }
                if crate::utils::resource_indicators::resource_from_audience(claims.aud.as_deref())
                    .is_some()
                {
                    return Err(AppError::BadRequest(
                        "Resource authentication requires a service context".to_string(),
                    ));
                }
                Ok((user, None))
            }
        }
    }
}

async fn verify_mfa_challenge(
    state: &AppState,
    request_info: &RequestInfo,
    req: &MfaVerifyRequest,
) -> Result<VerifiedMfaChallenge> {
    let claims = state
        .jwt_service
        .validate_mfa_preauth_token(&req.preauth_token)?;

    if claims.mfa_required != Some(true) {
        return Err(AppError::BadRequest(
            "Invalid pre-authentication token".to_string(),
        ));
    }

    validate_device_context(&claims, req.device_code_id.as_deref())?;

    let backup_event = MfaAuditBuilder::new(&claims.sub, "backup_code_used")
        .org_id(claims.org.as_deref())
        .ip_address(Some(&request_info.ip_address))
        .user_agent(Some(request_info.user_agent.clone()))
        .success(true)
        .build();
    let candidate =
        crate::handlers::user::verify_mfa_code_candidate(&state.db, &claims.sub, &req.code).await?;
    let Some((method, backup_code_id)) = candidate else {
        let verification_type =
            if req.code.len() == 6 && req.code.chars().all(|c| c.is_ascii_digit()) {
                "totp"
            } else {
                "backup_code"
            };
        let event = MfaAuditBuilder::new(&claims.sub, "mfa_verify_failed")
            .org_id(claims.org.as_deref())
            .ip_address(Some(&request_info.ip_address))
            .user_agent(Some(request_info.user_agent.clone()))
            .success(false)
            .details(Some(&format!(
                "method:{},reason:invalid_code",
                verification_type
            )))
            .build();
        state.audit_actor.log_mfa(event).await?;

        return Err(AppError::Unauthorized("Invalid MFA code".to_string()));
    };

    let db = &state.db;
    let user_id = claims.sub.clone();
    let user_entity = with_deadlock_retry("find_user_details", 10, || {
        let db = db.clone();
        let uid = user_id.clone();
        async move {
            use sea_orm::EntityTrait;
            users::Entity::find_by_id(uid).one(&db).await
        }
    })
    .await?
    .filter(|user| user.deleted_at.is_none())
    .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let user: User = user_entity.into();
    let verification_type = match method {
        crate::handlers::user::MfaVerificationMethod::Totp => "totp",
        crate::handlers::user::MfaVerificationMethod::BackupCode => "backup_code",
    };
    let success_event = MfaAuditBuilder::new(&claims.sub, "mfa_verify_success")
        .org_id(claims.org.as_deref())
        .ip_address(Some(&request_info.ip_address))
        .user_agent(Some(request_info.user_agent.clone()))
        .success(true)
        .details(Some(verification_type))
        .build();
    Ok(VerifiedMfaChallenge {
        claims,
        user,
        backup_code_id,
        backup_event,
        success_event,
    })
}

/// Browser-native continuation for SAML logins that require MFA. Returning the
/// actual HTML response lets the browser submit the signed assertion directly
/// to the SP instead of converting it into an unusable token sentinel.
#[axum::debug_handler]
pub async fn verify_saml_mfa(
    State(state): State<AppState>,
    Extension(request_info): Extension<RequestInfo>,
    Form(req): Form<MfaVerifyRequest>,
) -> Result<Response> {
    let unconsumed_claims = state
        .jwt_service
        .validate_mfa_preauth_token(&req.preauth_token)?;
    validate_saml_mfa_context(&unconsumed_claims, req.device_code_id.as_deref())?;

    let verified = verify_mfa_challenge(&state, &request_info, &req).await?;
    let claims = &verified.claims;
    let user = &verified.user;
    let saml_state_id = claims
        .saml_state
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("Invalid SAML MFA continuation".to_string()))?;
    let service = ServiceStore::find_by_org_slug_and_service_slug(
        DB::Conn(&state.db),
        claims.org.as_deref().unwrap_or_default(),
        claims.service.as_deref().unwrap_or_default(),
    )
    .await?
    .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;
    crate::handlers::saml::validate_saml_completion_context(
        &state,
        saml_state_id,
        &service.id,
        &user.id,
    )
    .await?;
    consume_mfa_preauth_token_with_audits(
        &state,
        claims,
        verified.backup_code_id.as_deref(),
        verified.backup_event.clone(),
        verified.success_event.clone(),
    )
    .await?;

    crate::handlers::saml::complete_saml_authentication(
        &state,
        saml_state_id,
        Some(&service.id),
        user,
    )
    .await
}

/// POST /api/auth/mfa/verify - Verify MFA code and complete authentication
#[axum::debug_handler]
pub async fn verify_mfa_login(
    State(state): State<AppState>,
    Extension(request_info): Extension<RequestInfo>,
    headers: axum::http::HeaderMap,
    Json(req): Json<MfaVerifyRequest>,
) -> Result<Json<RefreshTokenResponse>> {
    let preauth_claims = state
        .jwt_service
        .validate_mfa_preauth_token(&req.preauth_token)?;
    if preauth_claims.is_platform_context() {
        crate::middleware::ensure_trusted_platform_origin(&headers, &state.config)?;
    }
    if preauth_claims.saml_state.is_some() {
        return Err(AppError::BadRequest(
            "SAML MFA continuation must be submitted to /saml/mfa/verify".to_string(),
        ));
    }
    let verified = verify_mfa_challenge(&state, &request_info, &req).await?;
    let claims = &verified.claims;
    let user = &verified.user;
    let session_org_slug = completed_session_org_slug(claims, req.device_code_id.as_deref());

    // Generate full session JWT
    let resource = crate::utils::resource_indicators::resource_from_audience(claims.aud.as_deref());
    let resource_owned = resource.map(str::to_string);
    let token = state.jwt_service.create_mfa_verified_token_with_resource(
        &user.id,
        &user.email,
        user.is_platform_owner,
        session_org_slug,
        claims.service.as_deref(),
        resource,
    )?;

    // Create session with refresh token
    let token_hash = hash_token(&token);
    let refresh_token = crate::crypto::refresh_tokens::generate();
    let now = Utc::now();
    let expires_at = now + chrono::Duration::hours(state.config.jwt_expiration_hours);
    let refresh_expires_at = now + chrono::Duration::days(30);
    // Live tenant/service entitlement, optional device authorization, pre-auth
    // one-time claim, backup-code claim, session creation, and success audit are
    // one transaction. Any stale context or persistence failure rolls all of
    // them back together.
    let service_id = complete_mfa_login_transaction(
        &state,
        &verified,
        req.device_code_id.as_deref(),
        &token_hash,
        expires_at.naive_utc(),
        &refresh_token,
        refresh_expires_at.naive_utc(),
        resource_owned.as_deref(),
        session_org_slug,
    )
    .await?;

    // Publish login success event for webhooks (after MFA verification)
    crate::handlers::auth::oauth::publish_login_event(
        &state.event_dispatcher,
        &user.id,
        &user.email,
        claims.org.as_deref(),
        service_id.as_deref(),
        Some("mfa"),
    )
    .await;

    Ok(Json(RefreshTokenResponse {
        access_token: token,
        refresh_token,
        expires_in: state.config.jwt_expiration_hours * 3600,
    }))
}

async fn consume_mfa_preauth_token_with_audits(
    state: &AppState,
    claims: &Claims,
    backup_code_id: Option<&str>,
    backup_event: crate::entities::mfa_audit_log::ActiveModel,
    success_event: crate::entities::mfa_audit_log::ActiveModel,
) -> Result<()> {
    let now = Utc::now().timestamp();
    let ttl_seconds = (claims.exp - now).max(1);
    let lock_key = format!("mfa-preauth:{}", claims.jti);
    let owner_id = format!("user:{}", claims.sub);

    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "consume_mfa_preauth_token_with_audits",
        |db| {
            let lock_key = lock_key.clone();
            let owner_id = owner_id.clone();
            let backup_code_id = backup_code_id.map(str::to_string);
            let backup_event = backup_event.clone();
            let success_event = success_event.clone();
            let audit_actor = state.audit_actor.clone();
            Box::pin(async move {
                if let Some(backup_code_id) = backup_code_id {
                    if !crate::handlers::user::claim_backup_code_with_audit_in_db(
                        db.clone(),
                        &backup_code_id,
                        (&audit_actor, backup_event),
                    )
                    .await?
                    {
                        return Err(AppError::Unauthorized("Invalid MFA code".to_string()));
                    }
                }
                if !DistributedLockStore::try_acquire_lock(
                    db.clone(),
                    &lock_key,
                    &owner_id,
                    ttl_seconds,
                )
                .await?
                {
                    return Err(AppError::BadRequest(
                        "Invalid pre-authentication token".to_string(),
                    ));
                }
                audit_actor.log_mfa_with_db(db, success_event).await?;
                Ok(())
            })
        },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn complete_mfa_login_transaction(
    state: &AppState,
    verified: &VerifiedMfaChallenge,
    requested_device_code_id: Option<&str>,
    token_hash: &str,
    expires_at: chrono::NaiveDateTime,
    refresh_token: &str,
    refresh_expires_at: chrono::NaiveDateTime,
    resource: Option<&str>,
    session_org_slug: Option<&str>,
) -> Result<Option<String>> {
    let now = Utc::now().timestamp();
    let ttl_seconds = (verified.claims.exp - now).max(1);
    let lock_key = format!("mfa-preauth:{}", verified.claims.jti);
    let owner_id = format!("user:{}", verified.claims.sub);
    let claims = verified.claims.clone();
    let expected_platform_owner = verified.user.is_platform_owner;
    let backup_code_id = verified.backup_code_id.clone();
    let backup_event = verified.backup_event.clone();
    let success_event = verified.success_event.clone();
    let requested_device_code_id = requested_device_code_id.map(str::to_string);
    let token_hash = token_hash.to_string();
    let refresh_token = refresh_token.to_string();
    let resource = resource.map(str::to_string);
    let session_org_slug = session_org_slug.map(str::to_string);

    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "complete_mfa_login",
        |db| {
            let claims = claims.clone();
            let lock_key = lock_key.clone();
            let owner_id = owner_id.clone();
            let backup_code_id = backup_code_id.clone();
            let backup_event = backup_event.clone();
            let success_event = success_event.clone();
            let requested_device_code_id = requested_device_code_id.clone();
            let token_hash = token_hash.clone();
            let refresh_token = refresh_token.clone();
            let resource = resource.clone();
            let session_org_slug = session_org_slug.clone();
            let audit_actor = state.audit_actor.clone();
            Box::pin(async move {
                let (current_user, service_id) = validate_live_mfa_session_context(
                    db.clone(),
                    &claims,
                    requested_device_code_id.as_deref(),
                )
                .await?;
                if current_user.is_platform_owner != expected_platform_owner {
                    return Err(AppError::Unauthorized(
                        "Authentication authority changed; sign in again".to_string(),
                    ));
                }
                if let Some(backup_code_id) = backup_code_id {
                    if !crate::handlers::user::claim_backup_code_with_audit_in_db(
                        db.clone(),
                        &backup_code_id,
                        (&audit_actor, backup_event),
                    )
                    .await?
                    {
                        return Err(AppError::Unauthorized("Invalid MFA code".to_string()));
                    }
                }
                if !DistributedLockStore::try_acquire_lock(
                    db.clone(),
                    &lock_key,
                    &owner_id,
                    ttl_seconds,
                )
                .await?
                {
                    return Err(AppError::BadRequest(
                        "Invalid pre-authentication token".to_string(),
                    ));
                }
                if let Some(device_code_id) = requested_device_code_id.as_deref() {
                    if DeviceCodeStore::authorize_for_user(
                        db.clone(),
                        device_code_id,
                        &current_user.id,
                    )
                    .await?
                        != 1
                    {
                        return Err(AppError::BadRequest(
                            "Device authorization context is invalid or expired".to_string(),
                        ));
                    }
                }
                SessionStore::create(
                    db.clone(),
                    &current_user.id,
                    &token_hash,
                    expires_at,
                    Some(&refresh_token),
                    Some(refresh_expires_at),
                    session_org_slug.as_deref(),
                    service_id.as_deref(),
                    resource.as_deref(),
                    None,
                    None,
                )
                .await?;
                audit_actor.log_mfa_with_db(db, success_event).await?;
                Ok(service_id)
            })
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::jwt::TokenUse;
    use crate::store::{organizations::OrganizationStore, services::ServiceStore};
    use migration::{Migrator, MigratorTrait};
    use sea_orm::{Database, EntityTrait};

    fn claims(device_code_id: Option<&str>) -> Claims {
        Claims {
            token_use: TokenUse::MfaPreauth,
            sub: "user".to_string(),
            email: "user@example.com".to_string(),
            is_platform_owner: false,
            jti: "jti".to_string(),
            org: None,
            service: None,
            mfa_required: Some(true),
            mfa_verified: Some(false),
            saml_state: None,
            device_code_id: device_code_id.map(str::to_string),
            act: None,
            bootstrap: None,
            aud: Some("platform".to_string()),
            iss: Some("https://auth.example.com".to_string()),
            scope: None,
            exp: Utc::now().timestamp() + 300,
            iat: Utc::now().timestamp(),
        }
    }

    #[test]
    fn platform_device_binding_is_not_persisted_as_a_tenant_org() {
        let mut platform_device = claims(Some("device-code"));
        platform_device.org = Some("platform".to_string());
        assert_eq!(
            completed_session_org_slug(&platform_device, Some("device-code")),
            None
        );
        assert_eq!(
            completed_session_org_slug(&platform_device, None),
            Some("platform")
        );

        let mut service_device = claims(Some("service-device"));
        service_device.org = Some("acme".to_string());
        service_device.service = Some("portal".to_string());
        assert_eq!(
            completed_session_org_slug(&service_device, Some("service-device")),
            Some("acme")
        );
    }

    #[test]
    fn device_context_requires_exact_signed_match() {
        assert!(validate_device_context(&claims(None), None).is_ok());
        assert!(validate_device_context(&claims(Some("device-a")), Some("device-a")).is_ok());
        assert!(validate_device_context(&claims(Some("device-a")), None).is_err());
        assert!(validate_device_context(&claims(None), Some("device-a")).is_err());
        assert!(validate_device_context(&claims(Some("device-a")), Some("device-b")).is_err());
    }

    #[test]
    fn saml_mfa_context_requires_signed_state_and_exact_non_device_service_context() {
        let mut saml = claims(None);
        saml.saml_state = Some("saml-state".to_string());
        saml.org = Some("acme".to_string());
        saml.service = Some("salesforce".to_string());
        assert!(validate_saml_mfa_context(&saml, None).is_ok());

        let mut missing_state = saml.clone();
        missing_state.saml_state = None;
        assert!(validate_saml_mfa_context(&missing_state, None).is_err());

        let mut missing_service = saml.clone();
        missing_service.service = None;
        assert!(validate_saml_mfa_context(&missing_service, None).is_err());

        let mut device_bound = saml.clone();
        device_bound.device_code_id = Some("device".to_string());
        assert!(validate_saml_mfa_context(&device_bound, None).is_err());
        assert!(validate_saml_mfa_context(&saml, Some("device")).is_err());
    }

    #[tokio::test]
    async fn live_mfa_context_rejects_revoked_service_and_expired_device_authority() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let owner = UserStore::create(
            DB::Conn(&db),
            "owner@example.test",
            Some("hash".to_string()),
            false,
        )
        .await
        .expect("create user");
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
            "portal-client",
        )
        .await
        .expect("create service");
        let identity = IdentityStore::create(
            DB::Conn(&db),
            &owner.id,
            "password",
            &owner.email,
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
        .expect("create service identity");

        let mut scoped = claims(None);
        scoped.sub = owner.id.clone();
        scoped.email = owner.email.clone();
        scoped.org = Some(org.slug.clone());
        scoped.service = Some(service.slug.clone());
        scoped.aud = Some("service:acme/portal".to_string());
        assert_eq!(
            validate_live_mfa_session_context(DB::Conn(&db), &scoped, None)
                .await
                .expect("live context")
                .1
                .as_deref(),
            Some(service.id.as_str())
        );
        crate::entities::identities::Entity::delete_by_id(&identity.id)
            .exec(&db)
            .await
            .expect("revoke identity");
        assert!(matches!(
            validate_live_mfa_session_context(DB::Conn(&db), &scoped, None).await,
            Err(AppError::Forbidden(_))
        ));

        let expires_at = (Utc::now() + chrono::Duration::minutes(5)).naive_utc();
        let device = DeviceCodeStore::create(
            DB::Conn(&db),
            "device-code",
            "USER-CODE",
            "portal-client",
            &org.slug,
            &service.slug,
            &expires_at,
        )
        .await
        .expect("create device code");
        DeviceCodeStore::set_user_id(DB::Conn(&db), &device.id, &owner.id)
            .await
            .expect("bind device user");
        let mut device_claims = scoped;
        device_claims.device_code_id = Some(device.id.clone());
        assert!(matches!(
            validate_live_mfa_session_context(
                DB::Conn(&db),
                &device_claims,
                Some("different-device")
            )
            .await,
            Err(AppError::BadRequest(_))
        ));
        DeviceCodeStore::update_status(DB::Conn(&db), &device.id, "denied", Some(&owner.id))
            .await
            .expect("deny device code");
        assert!(matches!(
            validate_live_mfa_session_context(DB::Conn(&db), &device_claims, Some(&device.id))
                .await,
            Err(AppError::BadRequest(_))
        ));
    }
}
