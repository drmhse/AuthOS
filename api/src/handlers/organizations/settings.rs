use crate::db::DB;
use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use crate::services::permission_service::{PermissionService, CAP_ORG_SETTINGS_MANAGE};
use crate::state::AppState;
use crate::store::{
    organization_oauth_credentials::OrganizationOAuthCredentialsStore,
    organizations::OrganizationStore,
};
use axum::{
    extract::{Path, State},
    Extension, Json,
};
use serde::{Deserialize, Serialize};

async fn require_settings_manager(state: &AppState, org_id: &str, user: &AuthUser) -> Result<()> {
    crate::handlers::organizations::ensure_organization_active(&state.db, org_id).await?;
    if crate::middleware::has_live_platform_authority(&state.db, user).await?
        || PermissionService::check(
            DB::Conn(&state.db),
            org_id,
            &user.user.id,
            CAP_ORG_SETTINGS_MANAGE,
        )
        .await?
    {
        return Ok(());
    }

    Err(AppError::Forbidden(
        "Insufficient permissions to manage organization settings".to_string(),
    ))
}

// OAuth Credentials Management

#[derive(Debug, Deserialize)]
pub struct SetOAuthCredentialsRequest {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Serialize)]
pub struct OAuthCredentialsResponse {
    pub provider: String,
    pub client_id: String,
    pub has_secret: bool,
}

fn validate_oauth_credentials_input(request: &SetOAuthCredentialsRequest) -> Result<()> {
    if request.client_id.trim().is_empty() {
        return Err(AppError::BadRequest(
            "OAuth client_id cannot be empty".to_string(),
        ));
    }
    if request.client_secret.trim().is_empty() {
        return Err(AppError::BadRequest(
            "OAuth client_secret cannot be empty".to_string(),
        ));
    }
    Ok(())
}

/// Set organization OAuth credentials for a provider
pub async fn set_org_oauth_credentials(
    State(state): State<AppState>,
    user: AuthUser,
    Path((org_slug, provider)): Path<(String, String)>,
    Json(req): Json<SetOAuthCredentialsRequest>,
) -> Result<Json<OAuthCredentialsResponse>> {
    // Get organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_settings_manager(&state, &org.id, &user).await?;

    // Validate provider
    if provider != "github" && provider != "google" && provider != "microsoft" {
        return Err(AppError::BadRequest(
            "Invalid provider. Must be github, google, or microsoft".to_string(),
        ));
    }
    validate_oauth_credentials_input(&req)?;

    let encryption = crate::encryption::EncryptionService::new().map_err(|e| {
        AppError::InternalServerError(format!("Encryption service unavailable: {}", e))
    })?;

    let existing = OrganizationOAuthCredentialsStore::find_by_org_and_provider(
        DB::Conn(&state.db),
        &org.id,
        &provider,
    )
    .await?;
    let credential_id = existing.as_ref().map_or_else(
        || uuid::Uuid::new_v4().to_string(),
        |credential| credential.id.clone(),
    );

    // Encrypt client secret
    let client_secret_encrypted = encryption
        .encrypt_with_context(
            &req.client_secret,
            crate::encryption::EncryptionContext::new(
                "organization_oauth_credentials",
                &credential_id,
                "client_secret_encrypted",
            ),
        )
        .map_err(|e| AppError::InternalServerError(format!("Failed to encrypt secret: {}", e)))?;

    let encryption_key_id = encryption.key_id().to_string();

    OrganizationOAuthCredentialsStore::upsert(
        DB::Conn(&state.db),
        &credential_id,
        &org.id,
        &provider,
        &req.client_id,
        client_secret_encrypted,
        &encryption_key_id,
    )
    .await?;

    Ok(Json(OAuthCredentialsResponse {
        provider,
        client_id: req.client_id,
        has_secret: true,
    }))
}

/// Get organization OAuth credentials for a provider (returns client_id only)
pub async fn get_org_oauth_credentials(
    State(state): State<AppState>,
    user: AuthUser,
    Path((org_slug, provider)): Path<(String, String)>,
) -> Result<Json<OAuthCredentialsResponse>> {
    // Get organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_settings_manager(&state, &org.id, &user).await?;

    // Validate provider
    if provider != "github" && provider != "google" && provider != "microsoft" {
        return Err(AppError::BadRequest(
            "Invalid provider. Must be github, google, or microsoft".to_string(),
        ));
    }

    // Fetch credentials
    let client_id =
        OrganizationOAuthCredentialsStore::find_client_id(DB::Conn(&state.db), &org.id, &provider)
            .await?
            .ok_or_else(|| {
                AppError::NotFound("OAuth credentials not found for this provider".to_string())
            })?;

    Ok(Json(OAuthCredentialsResponse {
        provider,
        client_id,
        has_secret: true,
    }))
}

// SMTP Configuration Management

#[derive(Debug, Deserialize)]
pub struct SetSmtpRequest {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from_email: String,
    pub from_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SmtpConfigResponse {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub from_email: String,
    pub from_name: Option<String>,
    pub configured: bool,
}

/// Set SMTP configuration for an organization
pub async fn set_org_smtp(
    State(state): State<AppState>,
    auth_user: Extension<AuthUser>,
    Path(org_slug): Path<String>,
    Json(payload): Json<SetSmtpRequest>,
) -> Result<Json<serde_json::Value>> {
    // Get organization
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_settings_manager(&state, &organization.id, &auth_user).await?;

    // Encrypt the SMTP password
    let encryption = state.encryption.as_ref().ok_or_else(|| {
        AppError::InternalServerError("Encryption service not available".to_string())
    })?;

    let encrypted_password = encryption
        .encrypt_with_context(
            &payload.password,
            crate::encryption::EncryptionContext::new(
                "organizations",
                &organization.id,
                "smtp_password_encrypted",
            ),
        )
        .map_err(|e| {
            tracing::error!("Failed to encrypt SMTP password: {}", e);
            AppError::InternalServerError("Failed to encrypt SMTP password".to_string())
        })?;

    OrganizationStore::update_smtp_config(
        DB::Conn(&state.db),
        &organization.id,
        &payload.host,
        payload.port as i64,
        &payload.username,
        encrypted_password,
        &payload.from_email,
        payload.from_name.as_deref(),
        Some(encryption.key_id()),
    )
    .await?;

    Ok(Json(serde_json::json!({
        "message": "SMTP configuration saved successfully"
    })))
}

/// Get SMTP configuration for an organization (without password)
pub async fn get_org_smtp(
    State(state): State<AppState>,
    auth_user: Extension<AuthUser>,
    Path(org_slug): Path<String>,
) -> Result<Json<SmtpConfigResponse>> {
    // Get organization
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_settings_manager(&state, &organization.id, &auth_user).await?;

    let configured = organization.smtp_host.is_some();

    Ok(Json(SmtpConfigResponse {
        host: organization.smtp_host.unwrap_or_default(),
        port: organization.smtp_port.map_or(587, |p| p as u16),
        username: organization.smtp_username.unwrap_or_default(),
        from_email: organization.smtp_from_email.unwrap_or_default(),
        from_name: organization.smtp_from_name,
        configured,
    }))
}

/// Delete SMTP configuration for an organization (revert to platform-level)
pub async fn delete_org_smtp(
    State(state): State<AppState>,
    auth_user: Extension<AuthUser>,
    Path(org_slug): Path<String>,
) -> Result<Json<serde_json::Value>> {
    // Get organization
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_settings_manager(&state, &organization.id, &auth_user).await?;

    // Clear SMTP settings
    OrganizationStore::clear_smtp_config(DB::Conn(&state.db), &organization.id).await?;

    Ok(Json(serde_json::json!({
        "message": "SMTP configuration deleted successfully. Organization will now use platform-level SMTP."
    })))
}

#[cfg(test)]
mod secret_validation_tests {
    use super::*;

    #[test]
    fn organization_oauth_credentials_require_nonempty_values() {
        for request in [
            SetOAuthCredentialsRequest {
                client_id: "".to_string(),
                client_secret: "secret".to_string(),
            },
            SetOAuthCredentialsRequest {
                client_id: "client".to_string(),
                client_secret: "  ".to_string(),
            },
        ] {
            assert!(matches!(
                validate_oauth_credentials_input(&request),
                Err(AppError::BadRequest(_))
            ));
        }
        validate_oauth_credentials_input(&SetOAuthCredentialsRequest {
            client_id: "client".to_string(),
            client_secret: "secret".to_string(),
        })
        .expect("complete confidential OAuth credentials");
    }
}

#[cfg(test)]
mod settings_tests {
    use super::*;

    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::config::Config;
    use crate::crypto::sso::OAuthClient;
    use crate::entities::users;
    use crate::middleware::AuthUser;

    use crate::audit::actor::AuditHandle;
    use crate::db::DB;
    use crate::services::{
        events::EventDispatcher, metrics::MfaMetricsService, risk_engine::RiskEngine,
    };
    use crate::state::AppState;
    use crate::store::{
        memberships::MembershipStore,
        organizations::OrganizationStore,
        users::{UserCreationOptions, UserStore},
    };
    use axum::extract::Path;

    use migration::{Migrator, MigratorTrait};
    use moka::future::Cache;
    use sea_orm::Database;
    use std::sync::Arc;

    use crate::test_support::test_jwt_service;

    struct Fixture {
        state: AppState,
        owner: AuthUser,
        member: AuthUser,
        org_slug: String,
    }

    async fn fixture() -> Fixture {
        // The settings handlers build the encryption service from the
        // environment; provide a deterministic test key for the duration.
        unsafe { std::env::set_var("ENCRYPTION_KEY", "11".repeat(32)) };

        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let config = Config {
            database_url: "sqlite::memory:".to_string(),
            ..test_config_values()
        };
        let jwt_service = Arc::new(test_jwt_service(&config));

        let owner_model = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "settings-owner@example.test",
            UserCreationOptions {
                is_platform_owner: true,
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("owner")
        .0;
        let member_model =
            UserStore::create(DB::Conn(&db), "settings-member@example.test", None, false)
                .await
                .expect("member");

        let (org, _) = OrganizationStore::create_with_owner(
            DB::Conn(&db),
            "acme",
            "Acme",
            &owner_model.id,
            None,
        )
        .await
        .expect("org");
        OrganizationStore::update_status(DB::Conn(&db), &org.id, "active")
            .await
            .expect("activate");
        MembershipStore::create(DB::Conn(&db), &org.id, &member_model.id, "member")
            .await
            .expect("membership");

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
        let auth_user_for = |user: &users::Model| -> AuthUser {
            let token = jwt_service
                .create_token(
                    &user.id,
                    &user.email,
                    user.is_platform_owner,
                    Some("acme"),
                    None,
                )
                .expect("token");
            AuthUser {
                claims: jwt_service.validate_token(&token).expect("claims"),
                user: user.clone(),
                permissions: vec![],
                ip_address: "127.0.0.1".to_string(),
                user_agent: "settings-test".to_string(),
                current_session_id: None,
            }
        };
        Fixture {
            state,
            owner: auth_user_for(&owner_model),
            member: auth_user_for(&member_model),
            org_slug: org.slug,
        }
    }

    fn test_config_values() -> Config {
        // Placeholder kept for parity with other fixtures.
        Config {
            database_url: "sqlite::memory:".to_string(),
            jwt_expiration_hours: 24,
            db_max_connections: 5,
            db_min_connections: 1,
            db_acquire_timeout_secs: 30,
            db_idle_timeout_secs: 600,
            db_max_lifetime_secs: 1800,
            platform_github_client_id: None,
            platform_github_client_secret: None,
            platform_github_redirect_uri: None,
            platform_google_client_id: None,
            platform_google_client_secret: None,
            platform_google_redirect_uri: None,
            platform_microsoft_client_id: None,
            platform_microsoft_client_secret: None,
            platform_microsoft_redirect_uri: None,
            platform_github_auth_url: None,
            platform_github_token_url: None,
            platform_github_user_api_url: None,
            platform_google_auth_url: None,
            platform_google_token_url: None,
            platform_google_user_api_url: None,
            platform_microsoft_auth_url: None,
            platform_microsoft_token_url: None,
            platform_microsoft_user_api_url: None,
            stripe_secret_key: None,
            stripe_webhook_secret: None,
            stripe_api_base_url: None,
            server_host: "127.0.0.1".to_string(),
            server_port: 3001,
            base_url: "http://localhost:3001".to_string(),
            platform_dashboard_base_url: "http://localhost:3001".to_string(),
            full_web_client_base_url: None,
            platform_owner_email: None,
            platform_owner_password: None,
            managed_config_path: None,
            managed_state_path: None,
            managed_status_path: None,
            managed_request_path: None,
            disable_rate_limiting: true,
            job_processor_interval_secs: 10,
            job_processor_batch_size: 10,
        }
    }

    #[tokio::test]
    async fn members_cannot_touch_org_settings() {
        let f = fixture().await;
        match get_org_oauth_credentials(
            State(f.state.clone()),
            f.member.clone(),
            Path((f.org_slug.clone(), "github".to_string())),
        )
        .await
        {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected forbidden, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn oauth_credentials_reject_unknown_providers_and_round_trip() {
        unsafe { std::env::remove_var("ENCRYPTION_KEY") };
        let f = fixture().await;

        match set_org_oauth_credentials(
            State(f.state.clone()),
            f.owner.clone(),
            Path((f.org_slug.clone(), "aol".to_string())),
            Json(SetOAuthCredentialsRequest {
                client_id: "cid".to_string(),
                client_secret: "secret".to_string(),
            }),
        )
        .await
        {
            Err(AppError::BadRequest(message)) => assert!(message.contains("Invalid provider")),
            other => panic!("expected BadRequest, got {other:?}"),
        }

        let Json(set) = set_org_oauth_credentials(
            State(f.state.clone()),
            f.owner.clone(),
            Path((f.org_slug.clone(), "github".to_string())),
            Json(SetOAuthCredentialsRequest {
                client_id: "cid-123".to_string(),
                client_secret: "secret-123".to_string(),
            }),
        )
        .await
        .expect("set credentials");
        assert_eq!(set.client_id, "cid-123");

        let Json(fetched) = get_org_oauth_credentials(
            State(f.state.clone()),
            f.owner.clone(),
            Path((f.org_slug.clone(), "github".to_string())),
        )
        .await
        .expect("get credentials");
        assert_eq!(fetched.client_id, "cid-123");
        assert!(fetched.has_secret, "a secret is stored but never returned");
    }
}

#[cfg(test)]
mod route_tests {
    use super::*;

    use crate::audit::actor::AuditHandle;
    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::crypto::sso::OAuthClient;
    use crate::entities::users;
    use crate::services::{
        events::EventDispatcher, metrics::MfaMetricsService, risk_engine::RiskEngine,
    };
    use crate::store::{
        memberships::MembershipStore,
        organization_roles::OrganizationRoleStore,
        users::{UserCreationOptions, UserStore},
    };
    use crate::test_support::{setup_db, test_config, test_jwt_service};
    use moka::future::Cache;
    use std::sync::Arc;

    struct Fixture {
        state: AppState,
        owner: AuthUser,
        admin: AuthUser,
        custom_manager: AuthUser,
        member: AuthUser,
        outsider: AuthUser,
        other_owner: AuthUser,
        alpha_slug: String,
        beta_id: String,
        beta_slug: String,
    }

    async fn seed_oauth_credentials(
        db: &sea_orm::DatabaseConnection,
        org_id: &str,
        provider: &str,
    ) {
        OrganizationOAuthCredentialsStore::upsert(
            DB::Conn(db),
            &uuid::Uuid::new_v4().to_string(),
            org_id,
            provider,
            "seed-client",
            vec![1, 2, 3],
            "test-key",
        )
        .await
        .expect("seed oauth credentials");
    }

    async fn fixture() -> Fixture {
        unsafe { std::env::set_var("ENCRYPTION_KEY", "44".repeat(32)) };
        let db = setup_db().await;
        let config = test_config();
        let jwt_service = Arc::new(test_jwt_service(&config));

        let owner = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "settings-route-owner@example.test",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create owner")
        .0;
        let admin = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "settings-route-admin@example.test",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create admin")
        .0;
        let custom_manager = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "settings-route-custom@example.test",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create custom manager")
        .0;
        let member = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "settings-route-member@example.test",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create member")
        .0;
        let outsider = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "settings-route-outsider@example.test",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create outsider")
        .0;
        let other_owner = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "settings-route-other-owner@example.test",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create other owner")
        .0;

        let (alpha, _) = OrganizationStore::create_with_owner(
            DB::Conn(&db),
            "settings-route-alpha",
            "Settings Route Alpha",
            &owner.id,
            Some("tier_enterprise"),
        )
        .await
        .expect("create alpha");
        let (beta, _) = OrganizationStore::create_with_owner(
            DB::Conn(&db),
            "settings-route-beta",
            "Settings Route Beta",
            &other_owner.id,
            Some("tier_enterprise"),
        )
        .await
        .expect("create beta");
        for org in [&alpha, &beta] {
            OrganizationStore::update_status(DB::Conn(&db), &org.id, "active")
                .await
                .expect("activate organization");
        }

        MembershipStore::create(DB::Conn(&db), &alpha.id, &admin.id, "admin")
            .await
            .expect("add admin");
        MembershipStore::create(DB::Conn(&db), &alpha.id, &member.id, "member")
            .await
            .expect("add member");
        OrganizationRoleStore::create(
            DB::Conn(&db),
            "settings-route-manager-role",
            &alpha.id,
            "settings-route-manager",
            "Settings Route Manager",
            None,
            serde_json::json!([CAP_ORG_SETTINGS_MANAGE]),
        )
        .await
        .expect("create settings manager role");
        MembershipStore::create(
            DB::Conn(&db),
            &alpha.id,
            &custom_manager.id,
            "settings-route-manager",
        )
        .await
        .expect("add custom manager");
        seed_oauth_credentials(&db, &beta.id, "github").await;

        let state = AppState {
            db: db.clone(),
            #[cfg(feature = "db_sqlite")]
            db_writer: db.clone(),
            oauth_client: Arc::new(OAuthClient::new(&config).expect("create oauth client")),
            jwt_service: jwt_service.clone(),
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

        let auth_user_for = |user: &users::Model| -> AuthUser {
            let token = state
                .jwt_service
                .create_token(&user.id, &user.email, false, None, None)
                .expect("create test token");
            AuthUser {
                claims: state
                    .jwt_service
                    .validate_token(&token)
                    .expect("validate test token"),
                user: user.clone(),
                permissions: vec![],
                ip_address: "127.0.0.1".to_string(),
                user_agent: "settings-route-test".to_string(),
                current_session_id: None,
            }
        };
        let owner_auth = auth_user_for(&owner);
        let admin_auth = auth_user_for(&admin);
        let custom_auth = auth_user_for(&custom_manager);
        let member_auth = auth_user_for(&member);
        let outsider_auth = auth_user_for(&outsider);
        let other_owner_auth = auth_user_for(&other_owner);

        Fixture {
            state,
            owner: owner_auth,
            admin: admin_auth,
            custom_manager: custom_auth,
            member: member_auth,
            outsider: outsider_auth,
            other_owner: other_owner_auth,
            alpha_slug: alpha.slug,
            beta_id: beta.id,
            beta_slug: beta.slug,
        }
    }

    #[tokio::test]
    async fn oauth_credential_routes_require_settings_authority_and_are_org_scoped() {
        let f = fixture().await;

        for auth in [f.owner.clone(), f.admin.clone(), f.custom_manager.clone()] {
            let Json(set) = set_org_oauth_credentials(
                State(f.state.clone()),
                auth.clone(),
                Path((f.alpha_slug.clone(), "github".to_string())),
                Json(SetOAuthCredentialsRequest {
                    client_id: "alpha-client".to_string(),
                    client_secret: "alpha-secret".to_string(),
                }),
            )
            .await
            .expect("settings manager may set credentials");
            assert_eq!(set.client_id, "alpha-client");

            let Json(fetched) = get_org_oauth_credentials(
                State(f.state.clone()),
                auth,
                Path((f.alpha_slug.clone(), "github".to_string())),
            )
            .await
            .expect("settings manager may read credentials");
            assert_eq!(fetched.client_id, "alpha-client");
            assert!(fetched.has_secret);
        }

        for auth in [f.member.clone(), f.outsider.clone(), f.other_owner.clone()] {
            assert!(matches!(
                get_org_oauth_credentials(
                    State(f.state.clone()),
                    auth.clone(),
                    Path((f.alpha_slug.clone(), "github".to_string())),
                )
                .await,
                Err(AppError::Forbidden(_))
            ));
            assert!(matches!(
                set_org_oauth_credentials(
                    State(f.state.clone()),
                    auth,
                    Path((f.alpha_slug.clone(), "github".to_string())),
                    Json(SetOAuthCredentialsRequest {
                        client_id: "denied".to_string(),
                        client_secret: "denied".to_string(),
                    }),
                )
                .await,
                Err(AppError::Forbidden(_))
            ));
        }

        // A custom settings role passes authorization before provider
        // validation.
        assert!(matches!(
            set_org_oauth_credentials(
                State(f.state.clone()),
                f.custom_manager.clone(),
                Path((f.alpha_slug.clone(), "aol".to_string())),
                Json(SetOAuthCredentialsRequest {
                    client_id: "cid".to_string(),
                    client_secret: "secret".to_string(),
                }),
            )
            .await,
            Err(AppError::BadRequest(_))
        ));

        // Cross-tenant credentials are hidden and unchanged.
        assert!(matches!(
            get_org_oauth_credentials(
                State(f.state.clone()),
                f.owner.clone(),
                Path((f.beta_slug.clone(), "github".to_string())),
            )
            .await,
            Err(AppError::Forbidden(_))
        ));
        assert!(matches!(
            set_org_oauth_credentials(
                State(f.state.clone()),
                f.owner.clone(),
                Path((f.beta_slug.clone(), "github".to_string())),
                Json(SetOAuthCredentialsRequest {
                    client_id: "cross-tenant".to_string(),
                    client_secret: "cross-tenant".to_string(),
                }),
            )
            .await,
            Err(AppError::Forbidden(_))
        ));
        let beta_credentials = OrganizationOAuthCredentialsStore::find_by_org_and_provider(
            DB::Conn(&f.state.db),
            &f.beta_id,
            "github",
        )
        .await
        .expect("load beta credentials")
        .expect("beta credentials remain");
        assert_eq!(beta_credentials.client_id, "seed-client");
    }
}
