use crate::constants::DEVICE_CODE_EXPIRE_MINUTES;
use crate::crypto::jwt::JwtService;
use crate::crypto::sso::Provider;
use crate::db::models::User;
use crate::db::transaction::with_retrying_transaction;
use crate::db::DB;
use crate::error::{AppError, Result};
use crate::state::AppState;
use crate::store::{
    device_codes::DeviceCodeStore, identities::IdentityStore, memberships::MembershipStore,
    organizations::OrganizationStore, services::ServiceStore, sessions::SessionStore,
    subscriptions::SubscriptionStore,
};
use axum::{extract::State, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const PLATFORM_ADMIN_CLI_CLIENT_ID: &str = "platform-admin-cli";
const DEVICE_USER_CODE_UNAVAILABLE: &str = "Invalid or unavailable user code";

fn unavailable_user_code() -> AppError {
    AppError::BadRequest(DEVICE_USER_CODE_UNAVAILABLE.to_string())
}

// Re-export common types for use in other modules
pub use crate::error::Json400;
pub use crate::services::device_flow::DeviceFlowService;

#[derive(Debug, Deserialize)]
pub struct DeviceCodeRequest {
    pub client_id: String,
    pub org: String,
    pub service: String,
}

#[derive(Debug, Serialize)]
pub struct DeviceCodeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: i64,
    pub interval: i64,
}

#[derive(Debug, Deserialize)]
pub struct DeviceVerifyRequest {
    pub user_code: String,
}

#[derive(Debug, Serialize)]
pub struct DeviceVerifyResponse {
    pub org_slug: String,
    pub service_slug: String,
    pub available_providers: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub client_id: String,
    pub device_code: String,
    pub grant_type: String,
    pub resource: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

/// Device Flow: Create device code
pub async fn device_code(
    State(state): State<AppState>,
    Json400(req): Json400<DeviceCodeRequest>,
) -> Result<Json<DeviceCodeResponse>> {
    // Validate input lengths to prevent database issues
    if req.client_id.len() > 500 {
        return Err(AppError::BadRequest(
            "client_id too long (max 500 characters)".to_string(),
        ));
    }
    if req.org.len() > 100 {
        return Err(AppError::BadRequest(
            "org slug too long (max 100 characters)".to_string(),
        ));
    }
    if req.service.len() > 100 {
        return Err(AppError::BadRequest(
            "service slug too long (max 100 characters)".to_string(),
        ));
    }

    // Validate characters (allow alphanumeric, hyphens, underscores)
    let valid_chars = |s: &str| -> bool {
        s.chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    };

    if !valid_chars(&req.client_id) {
        return Err(AppError::BadRequest(
            "client_id contains invalid characters".to_string(),
        ));
    }
    if !valid_chars(&req.org) {
        return Err(AppError::BadRequest(
            "org slug contains invalid characters".to_string(),
        ));
    }
    if !valid_chars(&req.service) {
        return Err(AppError::BadRequest(
            "service slug contains invalid characters".to_string(),
        ));
    }

    // Get config for platform device activation URI
    let config = crate::config::Config::from_env().map_err(AppError::InternalServerError)?;

    // Check if this is a platform-level device flow or service-level
    let verification_uri = if req.org == "platform"
        && req.service == "admin-cli"
        && req.client_id == PLATFORM_ADMIN_CLI_CLIENT_ID
    {
        // Platform-level device flow for admin CLI - use configured platform device activation URI
        format!("{}/activate", config.platform_dashboard_base_url)
    } else {
        // Service-level device flow - validate service exists
        let service = ServiceStore::find_by_client_id_and_slugs(
            DB::Conn(&state.db),
            &req.client_id,
            &req.org,
            &req.service,
        )
        .await?
        .map(crate::db::models::Service::from)
        .ok_or_else(|| AppError::BadRequest("Invalid client credentials".to_string()))?;

        service.device_activation_uri.ok_or_else(|| {
            AppError::BadRequest(
                "Device activation URI not configured for this service".to_string(),
            )
        })?
    };

    // Perform CPU-bound work here, in the parallel handler
    let device_code = DeviceFlowService::generate_device_code();
    let user_code = DeviceFlowService::generate_user_code();
    // End CPU-bound work

    // Create device code directly in the database
    let expires_at =
        (Utc::now() + chrono::Duration::minutes(DEVICE_CODE_EXPIRE_MINUTES)).naive_utc();
    let _created_device_code = DeviceCodeStore::create(
        DB::Conn(&state.db),
        &device_code,
        &user_code,
        &req.client_id,
        &req.org,
        &req.service,
        &expires_at,
    )
    .await?;

    Ok(Json(DeviceCodeResponse {
        device_code,
        user_code,
        verification_uri,
        expires_in: DEVICE_CODE_EXPIRE_MINUTES * 60, // Convert minutes to seconds
        interval: 5,                                 // Poll every 5 seconds
    }))
}

/// Device Flow: Verify user code and return context for frontend
pub async fn device_verify(
    State(state): State<AppState>,
    Json400(req): Json400<DeviceVerifyRequest>,
) -> Result<Json<DeviceVerifyResponse>> {
    // Validate user code length and format (should be "XXXX-XXXX")
    if req.user_code.len() != 9 || !req.user_code.contains('-') {
        return Err(unavailable_user_code());
    }

    // User codes should contain only characters that are easy to distinguish (alphanumeric + dash)
    let valid_chars = |s: &str| -> bool { s.chars().all(|c| c.is_alphanumeric() || c == '-') };

    if !valid_chars(&req.user_code) {
        return Err(unavailable_user_code());
    }

    // Use a fixed number of lookups and delays for every valid-format code.
    // This preserves the eventual-consistency retry window without making an
    // absent short code take a visibly different branch from an existing one.
    let mut device_code = None;
    for attempt in 0..3 {
        match DeviceFlowService::find_by_user_code(&state.db, &req.user_code).await {
            Ok(Some(dc)) => {
                if device_code.is_none() {
                    device_code = Some(dc);
                }
            }
            Ok(None) => {}
            Err(e) => return Err(e),
        }
        if attempt < 2 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    let device_code = device_code.ok_or_else(unavailable_user_code)?;

    // Check if expired
    if DeviceFlowService::is_expired(&device_code) {
        return Err(unavailable_user_code());
    }

    // Only an unclaimed pending code is available for browser activation.
    // Denied, consumed, authorized, and MFA-bound rows share the same public
    // unavailable response as an absent code.
    if device_code.status != "pending" || device_code.user_id.is_some() {
        return Err(unavailable_user_code());
    }

    // Check if this is a platform-level admin device flow
    if device_code.org_slug == "platform" && device_code.service_slug == "admin-cli" {
        // Platform-level device flow - return all available admin providers
        let available_providers = vec![
            "github".to_string(),
            "google".to_string(),
            "microsoft".to_string(),
        ];

        return Ok(Json(DeviceVerifyResponse {
            org_slug: device_code.org_slug,
            service_slug: device_code.service_slug,
            available_providers,
        }));
    }

    // Service-level device flow - fetch organization and service
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &device_code.org_slug)
        .await?
        .map(crate::db::models::Organization::from)
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    let _service =
        ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, &device_code.service_slug)
            .await?
            .map(crate::db::models::Service::from)
            .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;

    // Fetch organization OAuth credentials to see which providers are configured
    let available_providers =
        OrganizationStore::list_oauth_providers(DB::Conn(&state.db), &org.id).await?;

    // Return the context needed for the frontend to initiate the correct login flow
    Ok(Json(DeviceVerifyResponse {
        org_slug: device_code.org_slug,
        service_slug: device_code.service_slug,
        available_providers,
    }))
}

/// Device Flow: Exchange device code for token
pub async fn token_exchange(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<TokenRequest>,
) -> Result<Json<TokenResponse>> {
    // Validate grant type
    if req.grant_type != "urn:ietf:params:oauth:grant-type:device_code" {
        return Err(AppError::BadRequest("Invalid grant type".to_string()));
    }

    // Validate and get device code with retry to handle batch processing timing
    let mut device_code = None;
    for attempt in 0..3 {
        match DeviceFlowService::validate_for_token_exchange(
            &state.db,
            &req.device_code,
            &req.client_id,
        )
        .await
        {
            Ok(dc) => {
                device_code = Some(dc);
                break;
            }
            Err(e) => {
                // Only retry on "not found" type errors
                let error_msg = e.to_string().to_lowercase();
                if attempt < 2
                    && (error_msg.contains("not found")
                        || error_msg.contains("invalid")
                        || error_msg.contains("expired"))
                {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                } else {
                    return Err(e);
                }
            }
        }
    }

    let device_code =
        device_code.ok_or_else(|| AppError::BadRequest("Invalid device code".to_string()))?;
    if device_code.org_slug == "platform" && device_code.service_slug == "admin-cli" {
        crate::middleware::ensure_trusted_platform_origin(&headers, &state.config)?;
    }

    let user_id = device_code
        .user_id
        .ok_or_else(|| AppError::Unauthorized("Not authorized".to_string()))?;

    // Get user info
    let user = crate::store::users::UserStore::find_by_id(DB::Conn(&state.db), &user_id)
        .await?
        .filter(|user| user.deleted_at.is_none())
        .map(User::from)
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let login_provider = IdentityStore::get_latest_provider(DB::Conn(&state.db), &user_id)
        .await
        .ok()
        .flatten()
        .and_then(|provider| Provider::from_str(&provider).ok());
    let login_provider_key = login_provider
        .as_ref()
        .map_or("device", Provider::as_str)
        .to_string();

    // Check if this is a platform-level device flow
    if device_code.org_slug == "platform" && device_code.service_slug == "admin-cli" {
        if !user.is_platform_owner {
            return Err(AppError::Forbidden(
                "Platform device authorization requires a current platform owner".to_string(),
            ));
        }
        // Generate platform JWT for admin CLI. When MFA is enrolled, device
        // authorization can only complete through the MFA challenge, so carry
        // the signed MFA-completion marker into the CLI token. If MFA is not
        // enrolled, the token still cannot pass the platform route boundary.
        let mfa_enrolled =
            crate::store::totp::TotpStore::is_enabled(DB::Conn(&state.db), &user.id).await?;
        let token = if mfa_enrolled {
            state.jwt_service.create_mfa_verified_token(
                &user.id,
                &user.email,
                user.is_platform_owner,
                None,
                None,
            )?
        } else {
            state.jwt_service.create_token(
                &user.id,
                &user.email,
                user.is_platform_owner,
                None,
                None,
            )?
        };

        let refresh_token = crate::crypto::refresh_tokens::generate();

        // Store session with refresh token
        let token_hash = JwtService::hash_token(&token);
        let now = Utc::now();
        let expires_at = now + chrono::Duration::hours(state.config.jwt_expiration_hours);
        let refresh_expires_at = now + chrono::Duration::days(30);

        consume_device_code_create_session_and_audit(
            &state,
            &device_code.id,
            &req.client_id,
            &user_id,
            &token_hash,
            expires_at.naive_utc(),
            &refresh_token,
            refresh_expires_at.naive_utc(),
            None, // org_slug
            None, // service_id
            None, // resource
            &device_code.org_slug,
            &device_code.service_slug,
            &login_provider_key,
        )
        .await?;

        return Ok(Json(TokenResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: state.config.jwt_expiration_hours * 3600, // Convert hours to seconds
        }));
    }

    // Service-level device flow - get service and plan info
    let result = SubscriptionStore::get_service_with_subscription(
        DB::Conn(&state.db),
        &user_id,
        &device_code.org_slug,
        &device_code.service_slug,
    )
    .await?
    .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;
    let service = ServiceStore::find_by_id(DB::Conn(&state.db), &result.service_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &result.org_slug)
        .await?
        .filter(|org| org.status == "active" && org.id == service.org_id)
        .ok_or_else(|| AppError::Forbidden("Organization is not active".to_string()))?;
    validate_live_device_authority(
        DB::Conn(&state.db),
        &user.id,
        &org.slug,
        &service.slug,
        Some(&service.id),
    )
    .await?;
    let requested_resource = crate::utils::resource_indicators::validate_requested_resource(
        req.resource.as_deref(),
        service.resource_uris.as_deref(),
    )?;

    // Generate JWT
    let token = state.jwt_service.create_token_with_resource(
        &user.id,
        &user.email,
        user.is_platform_owner,
        Some(&result.org_slug),
        Some(&result.service_slug),
        requested_resource.as_deref(),
    )?;

    let refresh_token = crate::crypto::refresh_tokens::generate();

    // Store session with refresh token
    let token_hash = JwtService::hash_token(&token);
    let now = Utc::now();
    let expires_at = now + chrono::Duration::hours(state.config.jwt_expiration_hours);
    let refresh_expires_at = now + chrono::Duration::days(30);

    consume_device_code_create_session_and_audit(
        &state,
        &device_code.id,
        &req.client_id,
        &user_id,
        &token_hash,
        expires_at.naive_utc(),
        &refresh_token,
        refresh_expires_at.naive_utc(),
        Some(&result.org_slug),
        Some(&result.service_id),
        requested_resource.as_deref(),
        &device_code.org_slug,
        &device_code.service_slug,
        &login_provider_key,
    )
    .await?;

    let provider_opt = login_provider.as_ref().map(Provider::as_str);

    // Publish login success event for webhooks
    crate::handlers::auth::oauth::publish_login_event(
        &state.event_dispatcher,
        &user_id,
        &user.email,
        Some(&result.org_slug),
        Some(&result.service_id),
        provider_opt,
    )
    .await;

    Ok(Json(TokenResponse {
        access_token: token,
        token_type: "Bearer".to_string(),
        expires_in: state.config.jwt_expiration_hours * 3600, // Convert hours to seconds
    }))
}

// Helper functions

#[allow(clippy::too_many_arguments)]
async fn consume_device_code_create_session_and_audit(
    state: &AppState,
    device_code_id: &str,
    client_id: &str,
    user_id: &str,
    token_hash: &str,
    expires_at: chrono::NaiveDateTime,
    refresh_token: &str,
    refresh_expires_at: chrono::NaiveDateTime,
    org_slug: Option<&str>,
    service_id: Option<&str>,
    resource: Option<&str>,
    device_org_slug: &str,
    device_service_slug: &str,
    provider: &str,
) -> Result<()> {
    use crate::entities::login_events;
    use sea_orm::Set;

    let event_model = login_events::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        user_id: Set(user_id.to_string()),
        service_id: Set(service_id.map(str::to_string)),
        provider: Set(provider.to_string()),
        ..Default::default()
    };
    let device_code_id = device_code_id.to_string();
    let client_id = client_id.to_string();
    let user_id = user_id.to_string();
    let token_hash = token_hash.to_string();
    let refresh_token = refresh_token.to_string();
    let org_slug = org_slug.map(str::to_string);
    let service_id = service_id.map(str::to_string);
    let resource = resource.map(str::to_string);
    let device_org_slug = device_org_slug.to_string();
    let device_service_slug = device_service_slug.to_string();
    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "consume_device_code_create_session_and_audit",
        |db| {
            let device_code_id = device_code_id.clone();
            let client_id = client_id.clone();
            let user_id = user_id.clone();
            let token_hash = token_hash.clone();
            let refresh_token = refresh_token.clone();
            let org_slug = org_slug.clone();
            let service_id = service_id.clone();
            let resource = resource.clone();
            let device_org_slug = device_org_slug.clone();
            let device_service_slug = device_service_slug.clone();
            let event_model = event_model.clone();
            let audit_actor = state.audit_actor.clone();
            Box::pin(async move {
                validate_live_device_authority(
                    db.clone(),
                    &user_id,
                    &device_org_slug,
                    &device_service_slug,
                    service_id.as_deref(),
                )
                .await?;
                if !DeviceCodeStore::consume_authorized(
                    db.clone(),
                    &device_code_id,
                    &client_id,
                    &user_id,
                    &device_org_slug,
                    &device_service_slug,
                )
                .await?
                {
                    return Err(AppError::BadRequest("Invalid device code".to_string()));
                }
                SessionStore::create(
                    db.clone(),
                    &user_id,
                    &token_hash,
                    expires_at,
                    Some(&refresh_token),
                    Some(refresh_expires_at),
                    org_slug.as_deref(),
                    service_id.as_deref(),
                    resource.as_deref(),
                    None,
                    None,
                )
                .await?;
                audit_actor.log_login_with_db(db, event_model).await?;
                Ok(())
            })
        },
    )
    .await
}

async fn validate_live_device_authority(
    db: DB<'_>,
    user_id: &str,
    org_slug: &str,
    service_slug: &str,
    expected_service_id: Option<&str>,
) -> Result<()> {
    let user = crate::store::users::UserStore::find_by_id(db.clone(), user_id)
        .await?
        .filter(|user| user.deleted_at.is_none())
        .ok_or_else(|| AppError::Forbidden("Device user is no longer active".to_string()))?;
    if org_slug == "platform" && service_slug == "admin-cli" {
        if expected_service_id.is_none() && user.is_platform_owner {
            return Ok(());
        }
        return Err(AppError::Forbidden(
            "Platform device authorization requires a current platform owner".to_string(),
        ));
    }
    let service_id = expected_service_id
        .ok_or_else(|| AppError::Forbidden("Device service context is incomplete".to_string()))?;
    let org = OrganizationStore::find_by_slug(db.clone(), org_slug)
        .await?
        .filter(|org| org.status == "active")
        .ok_or_else(|| AppError::Forbidden("Organization is not active".to_string()))?;
    let service = ServiceStore::find_by_org_and_slug(db.clone(), &org.id, service_slug)
        .await?
        .filter(|service| service.id == service_id)
        .ok_or_else(|| AppError::Forbidden("Device service context changed".to_string()))?;
    if user.is_platform_owner
        || MembershipStore::find_by_org_and_user(db.clone(), &org.id, user_id)
            .await?
            .is_some()
        || IdentityStore::exists_for_user_and_service_context(db, user_id, &org.id, &service.id)
            .await?
    {
        return Ok(());
    }
    Err(AppError::Forbidden(
        "You do not currently have access to this service".to_string(),
    ))
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
    use axum::extract::State;

    use migration::{Migrator, MigratorTrait};
    use moka::future::Cache;
    use sea_orm::{ConnectionTrait, Database, EntityTrait, PaginatorTrait};
    use std::sync::Arc;

    use crate::test_support::test_config;

    use crate::test_support::test_jwt_service;

    async fn setup_state() -> AppState {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let config = test_config();
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
    async fn device_consume_and_session_roll_back_when_success_audit_fails() {
        let state = setup_state().await;
        let user = UserStore::find_or_create_with_options(
            DB::Conn(&state.db),
            "device-audit-rollback@example.test",
            UserCreationOptions {
                is_platform_owner: true,
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .0;
        let code = DeviceCodeStore::create(
            DB::Conn(&state.db),
            "device-audit-rollback",
            "AUDT-CODE",
            "audit-client",
            "platform",
            "admin-cli",
            &(Utc::now() + chrono::Duration::minutes(5)).naive_utc(),
        )
        .await
        .unwrap();
        DeviceCodeStore::set_user_id(DB::Conn(&state.db), &code.id, &user.id)
            .await
            .unwrap();
        assert_eq!(
            DeviceCodeStore::authorize_for_user(DB::Conn(&state.db), &code.id, &user.id)
                .await
                .unwrap(),
            1
        );
        state
            .db
            .execute_unprepared("DROP TABLE audit_outbox")
            .await
            .unwrap();
        let now = Utc::now();
        assert!(consume_device_code_create_session_and_audit(
            &state,
            &code.id,
            "audit-client",
            &user.id,
            "token-hash",
            (now + chrono::Duration::hours(1)).naive_utc(),
            "refresh-token",
            (now + chrono::Duration::days(30)).naive_utc(),
            None,
            None,
            None,
            "platform",
            "admin-cli",
            "device",
        )
        .await
        .is_err());

        assert_eq!(
            crate::entities::device_codes::Entity::find_by_id(&code.id)
                .one(&state.db)
                .await
                .unwrap()
                .unwrap()
                .status,
            "authorized"
        );
        assert_eq!(
            crate::entities::sessions::Entity::find()
                .count(&state.db)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn platform_device_exchange_rechecks_current_owner_authority() {
        let state = setup_state().await;
        let user = UserStore::find_or_create_with_options(
            DB::Conn(&state.db),
            "revoked-platform-device@example.test",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .0;
        let code = DeviceCodeStore::create(
            DB::Conn(&state.db),
            "revoked-platform-device-code",
            "RVKD-CODE",
            PLATFORM_ADMIN_CLI_CLIENT_ID,
            "platform",
            "admin-cli",
            &(Utc::now() + chrono::Duration::minutes(5)).naive_utc(),
        )
        .await
        .unwrap();
        DeviceCodeStore::update_status(DB::Conn(&state.db), &code.id, "authorized", Some(&user.id))
            .await
            .unwrap();

        let denied = token_exchange(
            State(state.clone()),
            axum::http::HeaderMap::new(),
            Json(TokenRequest {
                client_id: PLATFORM_ADMIN_CLI_CLIENT_ID.to_string(),
                device_code: code.device_code,
                grant_type: "urn:ietf:params:oauth:grant-type:device_code".to_string(),
                resource: None,
            }),
        )
        .await;
        assert!(matches!(denied, Err(AppError::Forbidden(_))));
        assert_eq!(
            DeviceCodeStore::find_by_id(DB::Conn(&state.db), &code.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            "authorized"
        );
        assert_eq!(
            crate::entities::sessions::Entity::find()
                .count(&state.db)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn service_device_authority_accepts_membership_or_exact_identity_and_denies_revocation() {
        let state = setup_state().await;
        let owner = UserStore::find_or_create_with_options(
            DB::Conn(&state.db),
            "device-owner@example.test",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .0;
        let (org, _) = OrganizationStore::create_with_owner(
            DB::Conn(&state.db),
            "device-entitlement",
            "Device entitlement",
            &owner.id,
            None,
        )
        .await
        .unwrap();
        OrganizationStore::update_status(DB::Conn(&state.db), &org.id, "active")
            .await
            .unwrap();
        let service = ServiceStore::create(
            DB::Conn(&state.db),
            &org.id,
            "portal",
            "Portal",
            "web",
            "device-entitlement-client",
        )
        .await
        .unwrap();
        let member = UserStore::find_or_create_with_options(
            DB::Conn(&state.db),
            "device-member@example.test",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .0;
        MembershipStore::create(DB::Conn(&state.db), &org.id, &member.id, "member")
            .await
            .unwrap();

        assert!(validate_live_device_authority(
            DB::Conn(&state.db),
            &member.id,
            &org.slug,
            &service.slug,
            Some(&service.id),
        )
        .await
        .is_ok());
        MembershipStore::delete_by_org_and_user(DB::Conn(&state.db), &org.id, &member.id)
            .await
            .unwrap();
        assert!(validate_live_device_authority(
            DB::Conn(&state.db),
            &member.id,
            &org.slug,
            &service.slug,
            Some(&service.id),
        )
        .await
        .is_err());

        IdentityStore::create(
            DB::Conn(&state.db),
            &member.id,
            "github",
            "device-member-provider-id",
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
        assert!(validate_live_device_authority(
            DB::Conn(&state.db),
            &member.id,
            &org.slug,
            &service.slug,
            Some(&service.id),
        )
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn browser_device_verify_normalizes_absent_and_expired_codes() {
        let state = setup_state().await;
        DeviceCodeStore::create(
            DB::Conn(&state.db),
            "expired-device-code",
            "ABCD-EFGH",
            "client-portal",
            "acme",
            "portal",
            &(Utc::now() - chrono::Duration::minutes(1)).naive_utc(),
        )
        .await
        .expect("create expired device code");
        let denied = DeviceCodeStore::create(
            DB::Conn(&state.db),
            "denied-device-code",
            "DENY-0000",
            "client-portal",
            "acme",
            "portal",
            &(Utc::now() + chrono::Duration::minutes(5)).naive_utc(),
        )
        .await
        .expect("create denied device code");
        DeviceCodeStore::update_status(DB::Conn(&state.db), &denied.id, "denied", None)
            .await
            .expect("deny device code");

        let mut errors = Vec::new();
        for user_code in ["WXYZ-1234", "ABCD-EFGH", "DENY-0000"] {
            let result = device_verify(
                State(state.clone()),
                Json400(DeviceVerifyRequest {
                    user_code: user_code.to_string(),
                }),
            )
            .await;
            let error = match result {
                Err(error) => error,
                Ok(_) => panic!("device verification must reject an unavailable code"),
            };

            assert!(matches!(
                error,
                AppError::BadRequest(ref message) if message == DEVICE_USER_CODE_UNAVAILABLE
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
        assert_eq!(errors[0], errors[2]);
    }

    #[tokio::test]
    async fn token_exchange_accepts_only_registered_resource() {
        use crate::entities::user_totp_secrets;
        use sea_orm::{ActiveModelTrait, Set};

        let state = setup_state().await;
        let user = UserStore::find_or_create_with_options(
            DB::Conn(&state.db),
            "device-user@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create user")
        .0;
        let (org, _) = OrganizationStore::create_with_owner(
            DB::Conn(&state.db),
            "acme",
            "Acme",
            &user.id,
            Some("tier_enterprise"),
        )
        .await
        .expect("create org");
        OrganizationStore::update_status(DB::Conn(&state.db), &org.id, "active")
            .await
            .expect("activate org");
        let service = ServiceStore::create(
            DB::Conn(&state.db),
            &org.id,
            "portal",
            "Portal",
            "web",
            "client-portal",
        )
        .await
        .expect("create service");
        let resource = "https://api.example.com/mcp";
        let resource_json = serde_json::to_string(&vec![resource]).unwrap();
        ServiceStore::update_dynamic(
            DB::Conn(&state.db),
            &org.id,
            &service.slug,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&resource_json),
        )
        .await
        .expect("set resource URIs");
        let expires_at = (Utc::now() + chrono::Duration::minutes(10)).naive_utc();
        let device_code = DeviceCodeStore::create(
            DB::Conn(&state.db),
            "device-code",
            "USER-CODE",
            "client-portal",
            &org.slug,
            &service.slug,
            &expires_at,
        )
        .await
        .expect("create device code");
        user_totp_secrets::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            user_id: Set(user.id.clone()),
            secret_encrypted: Set(vec![1, 2, 3]),
            encryption_key_id: Set("test-key".to_string()),
            enabled: Set(true),
            created_at: Set(Utc::now().naive_utc()),
            enabled_at: Set(Some(Utc::now().naive_utc())),
        }
        .insert(&state.db)
        .await
        .expect("enable MFA for device user");
        DeviceCodeStore::set_user_id(DB::Conn(&state.db), &device_code.id, &user.id)
            .await
            .expect("bind device code for MFA");
        assert_eq!(
            DeviceCodeStore::authorize_for_user(DB::Conn(&state.db), &device_code.id, &user.id,)
                .await
                .expect("complete browser MFA authorization"),
            1
        );

        let invalid = token_exchange(
            State(state.clone()),
            axum::http::HeaderMap::new(),
            Json(TokenRequest {
                client_id: "client-portal".to_string(),
                device_code: "device-code".to_string(),
                grant_type: "urn:ietf:params:oauth:grant-type:device_code".to_string(),
                resource: Some("https://other.example.com/mcp".to_string()),
            }),
        )
        .await;
        assert!(matches!(
            invalid,
            Err(AppError::BadRequest(ref message)) if message.contains("invalid_target")
        ));

        let Json(response) = token_exchange(
            State(state.clone()),
            axum::http::HeaderMap::new(),
            Json(TokenRequest {
                client_id: "client-portal".to_string(),
                device_code: "device-code".to_string(),
                grant_type: "urn:ietf:params:oauth:grant-type:device_code".to_string(),
                resource: Some(resource.to_string()),
            }),
        )
        .await
        .expect("exchange token");
        let claims = state
            .jwt_service
            .validate_token_for_audience(&response.access_token, resource)
            .expect("validate token");
        assert_eq!(claims.org.as_deref(), Some("acme"));
        assert_eq!(claims.service.as_deref(), Some("portal"));
        assert_eq!(claims.aud.as_deref(), Some(resource));
    }
}
