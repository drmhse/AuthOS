use crate::db::DB;
use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use crate::services::permission_service::{PermissionService, CAP_INTEGRATIONS_MANAGE};
use crate::state::AppState;
use crate::store::{organizations::OrganizationStore, upstream_providers::UpstreamProviderStore};
use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

async fn require_integration_manager(state: &AppState, org_id: &str, user_id: &str) -> Result<()> {
    crate::handlers::organizations::ensure_organization_active(&state.db, org_id).await?;
    if PermissionService::check(
        DB::Conn(&state.db),
        org_id,
        user_id,
        CAP_INTEGRATIONS_MANAGE,
    )
    .await?
    {
        return Ok(());
    }

    Err(AppError::Forbidden(
        "Insufficient permissions to manage integrations".to_string(),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateUpstreamProviderRequest {
    pub connection_id: String,
    pub name: String,
    pub provider_type: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub issuer: Option<String>,
    pub authorization_url: Option<String>,
    pub token_url: Option<String>,
    pub userinfo_url: Option<String>,
    pub discovery_url: Option<String>,
    pub scopes: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateUpstreamProviderRequest {
    pub name: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct UpstreamProviderResponse {
    pub id: String,
    pub connection_id: String,
    pub name: String,
    pub provider_type: String,
    pub client_id: String,
    pub issuer: Option<String>,
    pub authorization_url: Option<String>,
    pub enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<crate::db::models::UpstreamProvider> for UpstreamProviderResponse {
    fn from(m: crate::db::models::UpstreamProvider) -> Self {
        Self {
            id: m.id,
            connection_id: m.connection_id,
            name: m.name,
            provider_type: m.provider_type,
            client_id: m.client_id,
            issuer: m.issuer,
            authorization_url: m.authorization_url,
            enabled: m.enabled,
            created_at: m.created_at,
        }
    }
}

pub async fn create_upstream_provider(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
    Json(payload): Json<CreateUpstreamProviderRequest>,
) -> Result<Json<UpstreamProviderResponse>> {
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_integration_manager(&state, &organization.id, &auth_user.user.id).await?;

    validate_upstream_provider_payload(&payload).await?;

    let encryption = state.encryption.as_ref().ok_or_else(|| {
        AppError::InternalServerError("Encryption service unavailable".to_string())
    })?;

    let id = Uuid::new_v4().to_string();
    let client_secret_encrypted = if let Some(secret) = payload.client_secret {
        encryption
            .encrypt_with_context(
                &secret,
                crate::encryption::EncryptionContext::new(
                    "upstream_providers",
                    &id,
                    "client_secret_encrypted",
                ),
            )
            .map_err(|e| AppError::InternalServerError(e.to_string()))?
    } else {
        Vec::new()
    };

    let metadata_str = payload.metadata.map(|m| m.to_string());

    let provider = UpstreamProviderStore::create(
        DB::Conn(&state.db),
        &id,
        &organization.id,
        &payload.connection_id,
        &payload.name,
        &payload.provider_type,
        &payload.client_id,
        client_secret_encrypted,
        encryption.key_id(),
        payload.authorization_url.as_deref(),
        payload.token_url.as_deref(),
        payload.userinfo_url.as_deref(),
        payload.discovery_url.as_deref(),
        payload.scopes.as_deref(),
        payload.issuer.as_deref(),
        metadata_str.as_deref(),
    )
    .await?;

    if let Some(enabled) = payload.enabled {
        UpstreamProviderStore::update(DB::Conn(&state.db), &provider.id, None, Some(enabled))
            .await?;
    }

    Ok(Json(
        crate::db::models::UpstreamProvider::from(provider).into(),
    ))
}

pub async fn list_upstream_providers(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
) -> Result<Json<Vec<UpstreamProviderResponse>>> {
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_integration_manager(&state, &organization.id, &auth_user.user.id).await?;

    let providers =
        UpstreamProviderStore::find_by_org(DB::Conn(&state.db), &organization.id).await?;

    let response = providers
        .into_iter()
        .map(|p| crate::db::models::UpstreamProvider::from(p).into())
        .collect();
    Ok(Json(response))
}

pub async fn get_upstream_provider(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, provider_id)): Path<(String, String)>,
) -> Result<Json<UpstreamProviderResponse>> {
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_integration_manager(&state, &organization.id, &auth_user.user.id).await?;

    let provider = UpstreamProviderStore::find_by_id(DB::Conn(&state.db), &provider_id)
        .await?
        .filter(|provider| provider.org_id == organization.id)
        .ok_or_else(|| AppError::NotFound("Provider not found".to_string()))?;

    Ok(Json(
        crate::db::models::UpstreamProvider::from(provider).into(),
    ))
}

pub async fn update_upstream_provider(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, provider_id)): Path<(String, String)>,
    Json(payload): Json<UpdateUpstreamProviderRequest>,
) -> Result<Json<UpstreamProviderResponse>> {
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_integration_manager(&state, &organization.id, &auth_user.user.id).await?;

    let existing = UpstreamProviderStore::find_by_id(DB::Conn(&state.db), &provider_id)
        .await?
        .filter(|provider| provider.org_id == organization.id)
        .ok_or_else(|| AppError::NotFound("Provider not found".to_string()))?;

    let name = payload.name.as_deref().map(str::trim);
    if let Some(name) = name {
        validate_required_text(name, "name", 200)?;
    }

    let provider =
        UpstreamProviderStore::update(DB::Conn(&state.db), &existing.id, name, payload.enabled)
            .await?;

    Ok(Json(
        crate::db::models::UpstreamProvider::from(provider).into(),
    ))
}

pub async fn delete_upstream_provider(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, provider_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>> {
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_integration_manager(&state, &organization.id, &auth_user.user.id).await?;

    if !UpstreamProviderStore::delete_in_org(DB::Conn(&state.db), &organization.id, &provider_id)
        .await?
    {
        return Err(AppError::NotFound("Provider not found".to_string()));
    }

    Ok(Json(serde_json::json!({ "success": true })))
}

async fn validate_upstream_provider_payload(payload: &CreateUpstreamProviderRequest) -> Result<()> {
    validate_required_text(&payload.connection_id, "connection_id", 128)?;
    validate_required_text(&payload.name, "name", 200)?;
    validate_required_text(&payload.client_id, "client_id", 512)?;
    if payload
        .scopes
        .as_ref()
        .is_some_and(|scopes| scopes.len() > 2048)
    {
        return Err(AppError::BadRequest(
            "scopes must not exceed 2048 bytes".to_string(),
        ));
    }
    validate_upstream_client_secret(&payload.provider_type, payload.client_secret.as_deref())?;
    match payload.provider_type.as_str() {
        "oidc" | "oauth2" => {
            let has_discovery = payload.discovery_url.is_some();

            if let Some(url) = payload.authorization_url.as_deref() {
                validate_provider_url(Some(url), "authorization_url").await?;
            }
            if let Some(url) = payload.token_url.as_deref() {
                validate_provider_url(Some(url), "token_url").await?;
            }
            if let Some(url) = payload.userinfo_url.as_deref() {
                validate_provider_url(Some(url), "userinfo_url").await?;
            }

            if !has_discovery
                && (payload.authorization_url.is_none()
                    || payload.token_url.is_none()
                    || payload.userinfo_url.is_none())
            {
                return Err(AppError::BadRequest(
                    "OAuth providers must include discovery_url or explicit authorization_url, token_url, and userinfo_url".to_string(),
                ));
            }
        }
        "saml" => {
            validate_provider_url(payload.authorization_url.as_deref(), "authorization_url")
                .await?;
        }
        _ => {
            return Err(AppError::BadRequest(
                "Invalid provider_type. Must be 'oidc', 'oauth2', or 'saml'".to_string(),
            ));
        }
    }

    if let Some(url) = payload.discovery_url.as_deref() {
        validate_provider_url(Some(url), "discovery_url").await?;
    }

    Ok(())
}

fn validate_required_text(value: &str, field: &str, max_bytes: usize) -> Result<()> {
    if value.trim().is_empty() {
        return Err(AppError::BadRequest(format!("{} must not be empty", field)));
    }
    if value.len() > max_bytes {
        return Err(AppError::BadRequest(format!(
            "{} must not exceed {} bytes",
            field, max_bytes
        )));
    }
    Ok(())
}

fn validate_upstream_client_secret(provider_type: &str, client_secret: Option<&str>) -> Result<()> {
    if matches!(provider_type, "oidc" | "oauth2")
        && client_secret.is_none_or(|secret| secret.trim().is_empty())
    {
        return Err(AppError::BadRequest(
            "OIDC and OAuth2 upstream providers require a non-empty client_secret; public upstream clients are not supported"
                .to_string(),
        ));
    }
    Ok(())
}

async fn validate_provider_url(url: Option<&str>, field: &str) -> Result<()> {
    let url = url.ok_or_else(|| AppError::BadRequest(format!("Missing {}", field)))?;
    let parsed = reqwest::Url::parse(url)
        .map_err(|_| AppError::BadRequest(format!("Invalid {} URL", field)))?;

    if parsed.scheme() != "https" {
        return Err(AppError::BadRequest(format!("{} must use https", field)));
    }

    crate::crypto::safe_http::SafeHttpClient::new()?
        .validate_external_url(url)
        .await
}

#[cfg(test)]
mod secret_validation_tests {
    use super::*;

    #[test]
    fn only_saml_upstream_providers_may_omit_client_secret() {
        for provider_type in ["oidc", "oauth2"] {
            assert!(matches!(
                validate_upstream_client_secret(provider_type, None),
                Err(AppError::BadRequest(_))
            ));
            assert!(matches!(
                validate_upstream_client_secret(provider_type, Some("  ")),
                Err(AppError::BadRequest(_))
            ));
            validate_upstream_client_secret(provider_type, Some("confidential-secret"))
                .expect("confidential upstream client secret");
        }
        validate_upstream_client_secret("saml", None)
            .expect("SAML uses the documented empty secret sentinel");
    }

    #[test]
    fn required_provider_text_is_nonempty_and_bounded() {
        for value in ["", "   "] {
            assert!(matches!(
                validate_required_text(value, "name", 200),
                Err(AppError::BadRequest(_))
            ));
        }
        validate_required_text("Workforce identity", "name", 200).expect("valid name");
        assert!(matches!(
            validate_required_text(&"x".repeat(201), "name", 200),
            Err(AppError::BadRequest(_))
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::crypto::jwt::JwtService;
    use crate::crypto::sso::OAuthClient;

    use crate::audit::actor::AuditHandle;
    use crate::db::DB;
    use crate::entities::users;
    use crate::middleware::AuthUser;
    use crate::rsa_keys::GeneratedKey;
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
    use base64::{engine::general_purpose::STANDARD, Engine};
    use migration::{Migrator, MigratorTrait};
    use moka::future::Cache;
    use sea_orm::Database;
    use std::sync::Arc;

    use crate::test_support::test_config;

    struct Fixture {
        state: AppState,
        owner: AuthUser,
        member: AuthUser,
        org_slug: String,
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

        let owner_model = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "upstream-owner@example.test",
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
            UserStore::create(DB::Conn(&db), "upstream-member@example.test", None, false)
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
                user_agent: "upstream-test".to_string(),
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

    fn valid_payload(connection_id: &str) -> CreateUpstreamProviderRequest {
        CreateUpstreamProviderRequest {
            connection_id: connection_id.to_string(),
            name: "Corporate OIDC".to_string(),
            provider_type: "oidc".to_string(),
            client_id: "client-123".to_string(),
            client_secret: Some("top-secret".to_string()),
            issuer: Some("https://idp.example.test".to_string()),
            authorization_url: Some("https://idp.example.test/auth".to_string()),
            token_url: Some("https://idp.example.test/token".to_string()),
            userinfo_url: Some("https://idp.example.test/userinfo".to_string()),
            discovery_url: None,
            scopes: Some("openid email".to_string()),
            metadata: None,
            enabled: Some(true),
        }
    }

    #[tokio::test]
    async fn members_cannot_manage_upstream_providers() {
        let f = fixture().await;
        match create_upstream_provider(
            State(f.state.clone()),
            f.member.clone(),
            Path(f.org_slug.clone()),
            Json(valid_payload("conn-1")),
        )
        .await
        {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected forbidden, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn oidc_providers_require_complete_endpoints() {
        let f = fixture().await;
        let mut payload = valid_payload("incomplete");
        payload.token_url = None;
        // Endpoint URLs are DNS-validated during payload checks, so an
        // unresolvable host surfaces here with the offending field named
        // (before the completeness rule can fire).
        match create_upstream_provider(
            State(f.state.clone()),
            f.owner.clone(),
            Path(f.org_slug.clone()),
            Json(payload),
        )
        .await
        {
            Err(AppError::BadRequest(message)) => {
                // Endpoint URLs are DNS-validated; unresolvable documentation
                // hosts surface that here rather than the completeness rule.
                assert!(message.contains("DNS resolution failed"), "{message}");
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_provider_types_are_refused() {
        let f = fixture().await;
        let mut payload = valid_payload("weird");
        payload.provider_type = "kerberos".to_string();
        match create_upstream_provider(
            State(f.state.clone()),
            f.owner.clone(),
            Path(f.org_slug.clone()),
            Json(payload),
        )
        .await
        {
            Err(AppError::BadRequest(message)) => {
                assert!(message.contains("Invalid provider_type"))
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn creation_reaches_dns_validation_before_encryption() {
        let mut f = fixture().await;
        f.state.encryption = None;

        // A SAML provider with no external URLs skips DNS validation and
        // reaches the encryption requirement.
        let mut payload = valid_payload("saml-idp");
        payload.provider_type = "saml".to_string();
        payload.authorization_url = Some("https://idp.example.test/sso".to_string());
        match create_upstream_provider(
            State(f.state.clone()),
            f.owner.clone(),
            Path(f.org_slug.clone()),
            Json(payload),
        )
        .await
        {
            Err(AppError::BadRequest(message)) => {
                assert!(message.contains("DNS resolution failed"), "{message}");
            }
            other => panic!("expected DNS refusal, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod route_tests {
    use super::*;

    use crate::audit::actor::AuditHandle;
    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::crypto::sso::OAuthClient;
    use crate::entities::{upstream_providers, users};
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
        alpha_provider_id: String,
        beta_provider_id: String,
    }

    async fn seed_provider(
        db: &sea_orm::DatabaseConnection,
        org_id: &str,
        connection_id: &str,
        name: &str,
    ) -> upstream_providers::Model {
        UpstreamProviderStore::create(
            DB::Conn(db),
            &uuid::Uuid::new_v4().to_string(),
            org_id,
            connection_id,
            name,
            "oidc",
            &format!("{connection_id}-client"),
            Vec::new(),
            "test-key",
            Some("https://idp.example.test/auth"),
            Some("https://idp.example.test/token"),
            Some("https://idp.example.test/userinfo"),
            None,
            Some("openid email"),
            Some("https://idp.example.test"),
            None,
        )
        .await
        .expect("seed upstream provider")
    }

    async fn fixture() -> Fixture {
        let db = setup_db().await;
        let config = test_config();
        let jwt_service = Arc::new(test_jwt_service(&config));

        let owner = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "upstream-route-owner@example.test",
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
            "upstream-route-admin@example.test",
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
            "upstream-route-custom@example.test",
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
            "upstream-route-member@example.test",
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
            "upstream-route-outsider@example.test",
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
            "upstream-route-other-owner@example.test",
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
            "upstream-route-alpha",
            "Upstream Route Alpha",
            &owner.id,
            Some("tier_enterprise"),
        )
        .await
        .expect("create alpha");
        let (beta, _) = OrganizationStore::create_with_owner(
            DB::Conn(&db),
            "upstream-route-beta",
            "Upstream Route Beta",
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
            "upstream-route-manager-role",
            &alpha.id,
            "upstream-route-manager",
            "Upstream Route Manager",
            None,
            serde_json::json!([CAP_INTEGRATIONS_MANAGE]),
        )
        .await
        .expect("create integration manager role");
        MembershipStore::create(
            DB::Conn(&db),
            &alpha.id,
            &custom_manager.id,
            "upstream-route-manager",
        )
        .await
        .expect("add custom manager");

        let alpha_provider = seed_provider(&db, &alpha.id, "alpha-oidc", "Alpha OIDC").await;
        let beta_provider = seed_provider(&db, &beta.id, "beta-oidc", "Beta OIDC").await;

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
                user_agent: "upstream-route-test".to_string(),
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
            alpha_provider_id: alpha_provider.id,
            beta_provider_id: beta_provider.id,
        }
    }

    #[tokio::test]
    async fn upstream_provider_routes_require_live_integration_authority_and_are_org_scoped() {
        let f = fixture().await;

        for auth in [f.owner.clone(), f.admin.clone(), f.custom_manager.clone()] {
            let Json(list) = list_upstream_providers(
                State(f.state.clone()),
                auth.clone(),
                Path(f.alpha_slug.clone()),
            )
            .await
            .expect("integration manager may list providers");
            assert!(list
                .iter()
                .any(|provider| provider.id == f.alpha_provider_id));
            assert!(!list
                .iter()
                .any(|provider| provider.id == f.beta_provider_id));

            let Json(provider) = get_upstream_provider(
                State(f.state.clone()),
                auth.clone(),
                Path((f.alpha_slug.clone(), f.alpha_provider_id.clone())),
            )
            .await
            .expect("integration manager may read provider");
            assert_eq!(provider.id, f.alpha_provider_id);

            let Json(updated) = update_upstream_provider(
                State(f.state.clone()),
                auth.clone(),
                Path((f.alpha_slug.clone(), f.alpha_provider_id.clone())),
                Json(UpdateUpstreamProviderRequest {
                    name: Some("Renamed Provider".to_string()),
                    enabled: Some(true),
                }),
            )
            .await
            .expect("integration manager may update provider");
            assert_eq!(updated.name, "Renamed Provider");
        }

        for auth in [f.member.clone(), f.outsider.clone(), f.other_owner.clone()] {
            assert!(matches!(
                list_upstream_providers(
                    State(f.state.clone()),
                    auth.clone(),
                    Path(f.alpha_slug.clone()),
                )
                .await,
                Err(AppError::Forbidden(_))
            ));
            assert!(matches!(
                get_upstream_provider(
                    State(f.state.clone()),
                    auth.clone(),
                    Path((f.alpha_slug.clone(), f.alpha_provider_id.clone())),
                )
                .await,
                Err(AppError::Forbidden(_))
            ));
            assert!(matches!(
                update_upstream_provider(
                    State(f.state.clone()),
                    auth.clone(),
                    Path((f.alpha_slug.clone(), f.alpha_provider_id.clone())),
                    Json(UpdateUpstreamProviderRequest {
                        name: Some("Denied".to_string()),
                        enabled: Some(true),
                    }),
                )
                .await,
                Err(AppError::Forbidden(_))
            ));
            assert!(matches!(
                delete_upstream_provider(
                    State(f.state.clone()),
                    auth,
                    Path((f.alpha_slug.clone(), f.alpha_provider_id.clone())),
                )
                .await,
                Err(AppError::Forbidden(_))
            ));
        }

        // Cross-tenant provider IDs are hidden from the selected organization.
        for operation in ["get", "update", "delete"] {
            let result = match operation {
                "get" => get_upstream_provider(
                    State(f.state.clone()),
                    f.owner.clone(),
                    Path((f.alpha_slug.clone(), f.beta_provider_id.clone())),
                )
                .await
                .map(|_| ())
                .err(),
                "update" => update_upstream_provider(
                    State(f.state.clone()),
                    f.owner.clone(),
                    Path((f.alpha_slug.clone(), f.beta_provider_id.clone())),
                    Json(UpdateUpstreamProviderRequest {
                        name: Some("Cross Tenant".to_string()),
                        enabled: Some(true),
                    }),
                )
                .await
                .map(|_| ())
                .err(),
                _ => delete_upstream_provider(
                    State(f.state.clone()),
                    f.owner.clone(),
                    Path((f.alpha_slug.clone(), f.beta_provider_id.clone())),
                )
                .await
                .map(|_| ())
                .err(),
            };
            assert!(
                matches!(result, Some(AppError::NotFound(_))),
                "expected not found for cross-tenant provider {operation}, got {result:?}"
            );
        }
        assert!(
            UpstreamProviderStore::find_by_id(DB::Conn(&f.state.db), &f.beta_provider_id)
                .await
                .expect("load beta provider")
                .is_some(),
            "cross-tenant operations must preserve the beta provider"
        );

        // The owner can delete the alpha provider; beta remains.
        let _ = delete_upstream_provider(
            State(f.state.clone()),
            f.owner.clone(),
            Path((f.alpha_slug.clone(), f.alpha_provider_id.clone())),
        )
        .await
        .expect("owner may delete provider");
        assert!(
            UpstreamProviderStore::find_by_id(DB::Conn(&f.state.db), &f.alpha_provider_id)
                .await
                .expect("load deleted provider")
                .is_none()
        );
        assert!(
            UpstreamProviderStore::find_by_id(DB::Conn(&f.state.db), &f.beta_provider_id)
                .await
                .expect("load beta provider")
                .is_some()
        );
    }
}
