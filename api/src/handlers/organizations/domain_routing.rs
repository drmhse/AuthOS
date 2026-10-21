use crate::db::DB;
use crate::entities::verified_domains;
use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use crate::services::domain_verification::{
    normalize_verifiable_domain, verify_dns_txt_record, verify_http_file,
};
use crate::services::permission_service::{PermissionService, CAP_INTEGRATIONS_MANAGE};
use crate::state::AppState;
use crate::store::{
    organizations::OrganizationStore,
    upstream_providers::UpstreamProviderStore,
    verified_domains::{
        VerifiedDomainStore, DOMAIN_LOGIN_POLICY_PASSWORD_ALLOWED,
        DOMAIN_LOGIN_POLICY_PASSWORD_FALLBACK_IF_PROVIDER_UNAVAILABLE,
        DOMAIN_LOGIN_POLICY_UPSTREAM_ONLY,
    },
};
use axum::{
    extract::{Path, State},
    Json,
};
use sea_orm::{ActiveModelTrait, EntityTrait, IntoActiveModel, Set};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct CreateDomainRouteRequest {
    pub domain: String,
    pub upstream_provider_id: Option<String>,
    pub login_policy: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateDomainRouteRequest {
    pub upstream_provider_id: Option<String>,
    pub login_policy: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DomainRouteResponse {
    pub id: String,
    pub domain: String,
    pub upstream_provider_id: Option<String>,
    pub login_policy: String,
    pub verification_token: String,
    pub verified: bool,
    pub verified_at: Option<chrono::NaiveDateTime>,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

fn to_response(model: verified_domains::Model) -> DomainRouteResponse {
    DomainRouteResponse {
        id: model.id,
        domain: model.domain,
        upstream_provider_id: model.upstream_provider_id,
        login_policy: model.login_policy,
        verification_token: model.verification_token,
        verified: model.verified,
        verified_at: model.verified_at,
        created_at: model.created_at,
        updated_at: model.updated_at,
    }
}

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

fn normalize_domain(domain: &str) -> Result<String> {
    normalize_verifiable_domain(domain)
}

fn validate_login_policy(policy: Option<&str>) -> Result<Option<String>> {
    let Some(policy) = policy else {
        return Ok(None);
    };

    match policy {
        DOMAIN_LOGIN_POLICY_PASSWORD_ALLOWED
        | DOMAIN_LOGIN_POLICY_UPSTREAM_ONLY
        | DOMAIN_LOGIN_POLICY_PASSWORD_FALLBACK_IF_PROVIDER_UNAVAILABLE => {
            Ok(Some(policy.to_string()))
        }
        _ => Err(AppError::BadRequest(
            "Invalid login_policy. Use password_allowed, upstream_only, or password_fallback_if_provider_unavailable".to_string(),
        )),
    }
}

async fn ensure_provider_belongs_to_org(
    state: &AppState,
    org_id: &str,
    provider_id: Option<&str>,
) -> Result<()> {
    if let Some(provider_id) = provider_id {
        let provider = UpstreamProviderStore::find_by_id(DB::Conn(&state.db), provider_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Upstream provider not found".to_string()))?;

        if provider.org_id != org_id && !UpstreamProviderStore::allows_domain_bindings(&provider) {
            return Err(AppError::NotFound(
                "Upstream provider not found".to_string(),
            ));
        }
    }

    Ok(())
}

pub async fn list_domain_routes(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
) -> Result<Json<Vec<DomainRouteResponse>>> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_integration_manager(&state, &org.id, &auth_user.user.id).await?;

    let domains = VerifiedDomainStore::find_by_org(DB::Conn(&state.db), &org.id).await?;
    Ok(Json(domains.into_iter().map(to_response).collect()))
}

pub async fn create_domain_route(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
    Json(req): Json<CreateDomainRouteRequest>,
) -> Result<Json<DomainRouteResponse>> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_integration_manager(&state, &org.id, &auth_user.user.id).await?;
    ensure_provider_belongs_to_org(&state, &org.id, req.upstream_provider_id.as_deref()).await?;
    let login_policy = validate_login_policy(req.login_policy.as_deref())?;

    let domain = normalize_domain(&req.domain)?;
    if VerifiedDomainStore::find_by_domain(DB::Conn(&state.db), &domain)
        .await?
        .is_some()
    {
        return Err(AppError::BadRequest(
            "This domain is already configured".to_string(),
        ));
    }

    let model = VerifiedDomainStore::create(
        DB::Conn(&state.db),
        &Uuid::new_v4().to_string(),
        &org.id,
        &domain,
        &Uuid::new_v4().to_string(),
        req.upstream_provider_id.as_deref(),
        login_policy.as_deref(),
    )
    .await?;

    Ok(Json(to_response(model)))
}

pub async fn update_domain_route(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, domain_id)): Path<(String, String)>,
    Json(req): Json<UpdateDomainRouteRequest>,
) -> Result<Json<DomainRouteResponse>> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_integration_manager(&state, &org.id, &auth_user.user.id).await?;
    ensure_provider_belongs_to_org(&state, &org.id, req.upstream_provider_id.as_deref()).await?;
    let login_policy = validate_login_policy(req.login_policy.as_deref())?;

    let domain = crate::entities::prelude::VerifiedDomains::find_by_id(&domain_id)
        .one(&state.db)
        .await
        .map_err(|e| AppError::InternalServerError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("Domain route not found".to_string()))?;

    if domain.org_id != org.id {
        return Err(AppError::NotFound("Domain route not found".to_string()));
    }

    let mut active = domain.into_active_model();
    active.upstream_provider_id = Set(req.upstream_provider_id);
    if let Some(login_policy) = login_policy {
        active.login_policy = Set(login_policy);
    }
    active.updated_at = Set(chrono::Utc::now().naive_utc());
    let updated = active.update(&state.db).await.map_err(|e| {
        AppError::InternalServerError(format!("Failed to update domain route: {}", e))
    })?;

    Ok(Json(to_response(updated)))
}

pub async fn verify_domain_route(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, domain_id)): Path<(String, String)>,
) -> Result<Json<DomainRouteResponse>> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_integration_manager(&state, &org.id, &auth_user.user.id).await?;

    let domain = crate::entities::prelude::VerifiedDomains::find_by_id(&domain_id)
        .one(&state.db)
        .await
        .map_err(|e| AppError::InternalServerError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("Domain route not found".to_string()))?;

    if domain.org_id != org.id {
        return Err(AppError::NotFound("Domain route not found".to_string()));
    }

    let dns_verified = verify_dns_txt_record(&domain.domain, &domain.verification_token).await;
    let http_verified = verify_http_file(&domain.domain, &domain.verification_token).await;

    if !dns_verified && !http_verified {
        return Err(AppError::BadRequest(
            "Domain verification failed. Add the DNS TXT record or HTTP verification file and try again.".to_string(),
        ));
    }

    let updated =
        VerifiedDomainStore::mark_verified_in_org(DB::Conn(&state.db), &org.id, &domain_id).await?;
    Ok(Json(to_response(updated)))
}

pub async fn delete_domain_route(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, domain_id)): Path<(String, String)>,
) -> Result<Json<()>> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_integration_manager(&state, &org.id, &auth_user.user.id).await?;

    let domain = crate::entities::prelude::VerifiedDomains::find_by_id(&domain_id)
        .one(&state.db)
        .await
        .map_err(|e| AppError::InternalServerError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("Domain route not found".to_string()))?;

    if domain.org_id != org.id {
        return Err(AppError::NotFound("Domain route not found".to_string()));
    }

    if !VerifiedDomainStore::delete_in_org(DB::Conn(&state.db), &org.id, &domain_id).await? {
        return Err(AppError::NotFound("Domain route not found".to_string()));
    }
    Ok(Json(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::crypto::jwt::Claims;
    use crate::crypto::sso::OAuthClient;

    use crate::audit::actor::AuditHandle;
    use crate::services::{
        events::EventDispatcher, metrics::MfaMetricsService, risk_engine::RiskEngine,
    };
    use crate::store::{
        organizations::OrganizationStore,
        users::{UserCreationOptions, UserStore},
    };
    use axum::extract::State;

    use migration::{Migrator, MigratorTrait};
    use moka::future::Cache;
    use sea_orm::Database;
    use std::sync::Arc;

    use crate::test_support::test_config;

    use crate::test_support::test_jwt_service;

    async fn setup_state_and_owner() -> (AppState, AuthUser, String) {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let config = test_config();
        let owner = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "owner@example.com",
            UserCreationOptions {
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
        let auth_user = AuthUser {
            claims: Claims {
                token_use: crate::crypto::jwt::TokenUse::ManagementAccess,
                sub: owner.id.clone(),
                email: owner.email.clone(),
                is_platform_owner: false,
                jti: uuid::Uuid::new_v4().to_string(),
                org: Some(org.slug.clone()),
                service: None,
                mfa_required: None,
                mfa_verified: None,
                saml_state: None,
                device_code_id: None,
                act: None,
                bootstrap: None,
                aud: Some(format!("org:{}", org.slug)),
                iss: Some(state.base_url.clone()),
                scope: None,
                exp: chrono::Utc::now().timestamp() + 3600,
                iat: chrono::Utc::now().timestamp(),
            },
            user: owner,
            permissions: vec![],
            ip_address: "127.0.0.1".to_string(),
            user_agent: "domain-route-test".to_string(),
            current_session_id: None,
        };

        (state, auth_user, org.slug)
    }

    #[test]
    fn domain_login_policy_validation_accepts_supported_values() {
        assert_eq!(validate_login_policy(None).unwrap(), None);
        assert_eq!(
            validate_login_policy(Some(DOMAIN_LOGIN_POLICY_PASSWORD_ALLOWED)).unwrap(),
            Some(DOMAIN_LOGIN_POLICY_PASSWORD_ALLOWED.to_string())
        );
        assert_eq!(
            validate_login_policy(Some(DOMAIN_LOGIN_POLICY_UPSTREAM_ONLY)).unwrap(),
            Some(DOMAIN_LOGIN_POLICY_UPSTREAM_ONLY.to_string())
        );
        assert_eq!(
            validate_login_policy(Some(
                DOMAIN_LOGIN_POLICY_PASSWORD_FALLBACK_IF_PROVIDER_UNAVAILABLE
            ))
            .unwrap(),
            Some(DOMAIN_LOGIN_POLICY_PASSWORD_FALLBACK_IF_PROVIDER_UNAVAILABLE.to_string())
        );
    }

    #[test]
    fn domain_login_policy_validation_rejects_unknown_values() {
        let error = validate_login_policy(Some("local_password_only"))
            .expect_err("unknown policy should fail");

        assert!(
            matches!(error, AppError::BadRequest(ref message) if message.contains("Invalid login_policy"))
        );
    }

    #[test]
    fn cross_org_provider_requires_domain_binding_opt_in() {
        let mut provider = crate::entities::upstream_providers::Model {
            id: "provider-1".to_string(),
            org_id: "provider-org".to_string(),
            connection_id: "okta-main".to_string(),
            name: "Okta".to_string(),
            provider_type: "oidc".to_string(),
            client_id: "client".to_string(),
            client_secret_encrypted: Vec::new(),
            encryption_key_id: "test".to_string(),
            authorization_url: None,
            token_url: None,
            userinfo_url: None,
            discovery_url: None,
            scopes: None,
            issuer: None,
            metadata: None,
            enabled: true,
            created_at: chrono::Utc::now().naive_utc(),
            updated_at: chrono::Utc::now().naive_utc(),
        };

        assert!(!UpstreamProviderStore::allows_domain_bindings(&provider));

        provider.metadata = Some(r#"{"allow_domain_bindings":true}"#.to_string());
        assert!(UpstreamProviderStore::allows_domain_bindings(&provider));
    }

    #[tokio::test]
    async fn create_and_update_domain_route_return_login_policy() {
        let (state, auth_user, org_slug) = setup_state_and_owner().await;

        let Json(created) = create_domain_route(
            State(state.clone()),
            auth_user.clone(),
            Path(org_slug.clone()),
            Json(CreateDomainRouteRequest {
                domain: "acme.com".to_string(),
                upstream_provider_id: None,
                login_policy: Some(DOMAIN_LOGIN_POLICY_UPSTREAM_ONLY.to_string()),
            }),
        )
        .await
        .expect("create domain route");

        assert_eq!(created.domain, "acme.com");
        assert_eq!(created.login_policy, DOMAIN_LOGIN_POLICY_UPSTREAM_ONLY);

        let Json(updated) = update_domain_route(
            State(state),
            auth_user,
            Path((org_slug, created.id)),
            Json(UpdateDomainRouteRequest {
                upstream_provider_id: None,
                login_policy: Some(
                    DOMAIN_LOGIN_POLICY_PASSWORD_FALLBACK_IF_PROVIDER_UNAVAILABLE.to_string(),
                ),
            }),
        )
        .await
        .expect("update domain route");

        assert_eq!(
            updated.login_policy,
            DOMAIN_LOGIN_POLICY_PASSWORD_FALLBACK_IF_PROVIDER_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn create_domain_route_allows_only_shareable_cross_org_provider() {
        let (state, auth_user, org_slug) = setup_state_and_owner().await;
        let provider_owner = UserStore::find_or_create_with_options(
            DB::Conn(&state.db),
            "provider-owner@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create provider owner")
        .0;
        let (provider_org, _) = OrganizationStore::create_with_owner(
            DB::Conn(&state.db),
            "identity-hub",
            "Identity Hub",
            &provider_owner.id,
            Some("tier_enterprise"),
        )
        .await
        .expect("create provider org");
        let shared_provider = UpstreamProviderStore::create(
            DB::Conn(&state.db),
            &Uuid::new_v4().to_string(),
            &provider_org.id,
            "okta-shared",
            "Okta Shared",
            "oidc",
            "client",
            Vec::new(),
            "test-key",
            Some("https://idp.example.com/authorize"),
            Some("https://idp.example.com/token"),
            Some("https://idp.example.com/userinfo"),
            None,
            Some("openid email profile"),
            Some("https://idp.example.com"),
            Some(r#"{"allow_domain_bindings":true}"#),
        )
        .await
        .expect("create shared provider");
        let private_provider = UpstreamProviderStore::create(
            DB::Conn(&state.db),
            &Uuid::new_v4().to_string(),
            &provider_org.id,
            "okta-private",
            "Okta Private",
            "oidc",
            "client",
            Vec::new(),
            "test-key",
            Some("https://private-idp.example.com/authorize"),
            Some("https://private-idp.example.com/token"),
            Some("https://private-idp.example.com/userinfo"),
            None,
            Some("openid email profile"),
            Some("https://private-idp.example.com"),
            None,
        )
        .await
        .expect("create private provider");

        let Json(created) = create_domain_route(
            State(state.clone()),
            auth_user.clone(),
            Path(org_slug.clone()),
            Json(CreateDomainRouteRequest {
                domain: "shared.acme.com".to_string(),
                upstream_provider_id: Some(shared_provider.id.clone()),
                login_policy: Some(DOMAIN_LOGIN_POLICY_UPSTREAM_ONLY.to_string()),
            }),
        )
        .await
        .expect("create route to shared provider");
        assert_eq!(
            created.upstream_provider_id.as_deref(),
            Some(shared_provider.id.as_str())
        );

        let private_error = create_domain_route(
            State(state),
            auth_user,
            Path(org_slug),
            Json(CreateDomainRouteRequest {
                domain: "private.acme.com".to_string(),
                upstream_provider_id: Some(private_provider.id),
                login_policy: Some(DOMAIN_LOGIN_POLICY_UPSTREAM_ONLY.to_string()),
            }),
        )
        .await
        .expect_err("private cross-org provider should be hidden");
        assert!(matches!(
            private_error,
            AppError::NotFound(ref message) if message.contains("Upstream provider not found")
        ));
    }

    #[tokio::test]
    async fn domain_route_mutations_reject_cross_org_id_and_preserve_target() {
        let (state, auth_user, org_a_slug) = setup_state_and_owner().await;
        let org_a = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_a_slug)
            .await
            .expect("lookup org A")
            .expect("org A exists");
        let owner_b = UserStore::find_or_create_with_options(
            DB::Conn(&state.db),
            "domain-owner-b@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create owner B")
        .0;
        let (org_b, _) = OrganizationStore::create_with_owner(
            DB::Conn(&state.db),
            "domain-org-b",
            "Domain Org B",
            &owner_b.id,
            Some("tier_enterprise"),
        )
        .await
        .expect("create org B");
        let target = VerifiedDomainStore::create(
            DB::Conn(&state.db),
            &Uuid::new_v4().to_string(),
            &org_b.id,
            "protected.example.com",
            "protected-token",
            None,
            Some(DOMAIN_LOGIN_POLICY_PASSWORD_ALLOWED),
        )
        .await
        .expect("create org B domain");

        assert!(matches!(
            update_domain_route(
                State(state.clone()),
                auth_user.clone(),
                Path((org_a_slug.clone(), target.id.clone())),
                Json(UpdateDomainRouteRequest {
                    upstream_provider_id: None,
                    login_policy: Some(DOMAIN_LOGIN_POLICY_UPSTREAM_ONLY.to_string()),
                }),
            )
            .await,
            Err(AppError::NotFound(_))
        ));
        assert!(matches!(
            delete_domain_route(
                State(state.clone()),
                auth_user,
                Path((org_a_slug, target.id.clone())),
            )
            .await,
            Err(AppError::NotFound(_))
        ));
        assert!(matches!(
            VerifiedDomainStore::mark_verified_in_org(DB::Conn(&state.db), &org_a.id, &target.id,)
                .await,
            Err(AppError::NotFound(_))
        ));

        let preserved = crate::entities::prelude::VerifiedDomains::find_by_id(&target.id)
            .one(&state.db)
            .await
            .expect("load protected domain")
            .expect("protected domain remains");
        assert_eq!(preserved.org_id, org_b.id);
        assert_eq!(preserved.login_policy, DOMAIN_LOGIN_POLICY_PASSWORD_ALLOWED);
        assert!(!preserved.verified);
        assert_eq!(preserved.verification_token, "protected-token");
    }

    #[tokio::test]
    async fn domain_route_mutations_reject_suspended_parent_and_preserve_state() {
        let (state, auth_user, org_slug) = setup_state_and_owner().await;
        let Json(created) = create_domain_route(
            State(state.clone()),
            auth_user.clone(),
            Path(org_slug.clone()),
            Json(CreateDomainRouteRequest {
                domain: "suspended.example.com".to_string(),
                upstream_provider_id: None,
                login_policy: Some(DOMAIN_LOGIN_POLICY_PASSWORD_ALLOWED.to_string()),
            }),
        )
        .await
        .expect("create domain before suspension");
        let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
            .await
            .expect("lookup org")
            .expect("org exists");
        OrganizationStore::update_status(DB::Conn(&state.db), &org.id, "suspended")
            .await
            .expect("suspend org");

        assert!(matches!(
            update_domain_route(
                State(state.clone()),
                auth_user.clone(),
                Path((org_slug.clone(), created.id.clone())),
                Json(UpdateDomainRouteRequest {
                    upstream_provider_id: None,
                    login_policy: Some(DOMAIN_LOGIN_POLICY_UPSTREAM_ONLY.to_string()),
                }),
            )
            .await,
            Err(AppError::Forbidden(_))
        ));
        assert!(matches!(
            delete_domain_route(
                State(state.clone()),
                auth_user,
                Path((org_slug, created.id.clone())),
            )
            .await,
            Err(AppError::Forbidden(_))
        ));

        let preserved = crate::entities::prelude::VerifiedDomains::find_by_id(&created.id)
            .one(&state.db)
            .await
            .expect("load domain")
            .expect("domain remains");
        assert_eq!(preserved.login_policy, DOMAIN_LOGIN_POLICY_PASSWORD_ALLOWED);
        assert_eq!(preserved.org_id, org.id);
    }
}
