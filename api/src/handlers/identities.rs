use crate::crypto::sso::Provider;
use crate::db::DB;
use crate::error::{AppError, Result};
use crate::handlers::auth::get_authorization_url_for_client;
use crate::state::AppState;
use crate::store::{
    identities::IdentityStore, oauth_states::OAuthStateStore,
    organization_oauth_credentials::OrganizationOAuthCredentialsStore,
    organizations::OrganizationStore, services::ServiceStore,
};
use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::Utc;
use sea_orm::DatabaseConnection;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct IdentityResponse {
    pub provider: String,
}

#[derive(Debug, Serialize)]
pub struct StartLinkResponse {
    pub authorization_url: String,
}

#[derive(Debug, Deserialize)]
pub struct StartLinkQuery {
    pub redirect_uri: Option<String>,
}

/// Helper function to determine the identity context (org_id and service_id) from auth user claims
/// Returns (issuing_org_id, issuing_service_id) based on the authentication context
async fn get_identity_context(
    db: &DatabaseConnection,
    auth_user: &crate::middleware::AuthUser,
) -> Result<(Option<String>, Option<String>)> {
    // Extract org and service from claims, treating empty strings as None
    let org_slug =
        auth_user
            .claims
            .org
            .as_ref()
            .and_then(|s| if s.is_empty() { None } else { Some(s.as_str()) });
    let service_slug = auth_user.claims.service.as_ref().and_then(|s| {
        if s.is_empty() {
            None
        } else {
            Some(s.as_str())
        }
    });

    if let (Some(org_slug), Some(service_slug)) = (org_slug, service_slug) {
        // Service context - get org_id and service_id
        // First get organization by slug
        let org = OrganizationStore::find_by_slug(DB::Conn(db), org_slug)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("Organization '{}' not found", org_slug)))?;

        let service = ServiceStore::find_by_org_and_slug(DB::Conn(db), &org.id, service_slug)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("Service '{}' not found", service_slug)))?;

        Ok((Some(service.org_id.clone()), Some(service.id)))
    } else {
        // Platform context - either None values or empty strings
        Ok((None, None))
    }
}

/// GET /api/user/identities - List all linked identities for the authenticated user
pub async fn list_identities(
    State(state): State<AppState>,
    auth_user: Option<axum::extract::Extension<crate::middleware::AuthUser>>,
) -> Result<Json<Vec<IdentityResponse>>> {
    let auth_user = auth_user
        .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))?
        .0;

    // Get identity context (org_id and service_id) for proper isolation
    let (issuing_org_id, issuing_service_id) = get_identity_context(&state.db, &auth_user).await?;

    // Fetch identities filtered by context
    let identities = IdentityStore::list_by_user_with_context(
        DB::Conn(&state.db),
        &auth_user.user.id,
        issuing_org_id.as_deref(),
        issuing_service_id.as_deref(),
    )
    .await?;

    let response: Vec<IdentityResponse> = identities
        .into_iter()
        .map(|identity| IdentityResponse {
            provider: identity.provider,
        })
        .collect();

    Ok(Json(response))
}

/// POST /api/user/identities/:provider/link - Start linking a new social account
///
/// This endpoint initiates OAuth flow to link a provider account to the authenticated user.
/// After OAuth completes, the user will be redirected to the service's redirect_uri with:
/// - ?status=success&provider={provider}&action=link (on success)
/// - ?status=error&error={message}&action=link (on failure)
pub async fn start_link(
    State(state): State<AppState>,
    Path(provider_str): Path<String>,
    Query(query): Query<StartLinkQuery>,
    auth_user: Option<axum::extract::Extension<crate::middleware::AuthUser>>,
) -> Result<Json<StartLinkResponse>> {
    let auth_user = auth_user
        .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))?
        .0;
    crate::middleware::require_recent_authentication(
        &state.db,
        &auth_user,
        chrono::Duration::minutes(10),
    )
    .await?;

    let provider = Provider::from_str(&provider_str)?;

    // Detect authentication context to determine linking strategy
    let is_service_level = matches!(
        (&auth_user.claims.org, &auth_user.claims.service),
        (Some(org), Some(service)) if !(org == "platform" && service == "admin-cli")
    );

    let (
        scopes,
        is_admin_flow,
        org_slug,
        service_slug,
        service_id,
        redirect_uri,
        auth_url,
        csrf_token,
        pkce_verifier,
    ) = if is_service_level {
        // Service-level linking: Read scopes and redirect_uris from service configuration
        let org_slug = auth_user.claims.org.as_ref().unwrap();
        let service_slug = auth_user.claims.service.as_ref().unwrap();

        let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), org_slug)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("Organization '{}' not found", org_slug)))?;

        // Get service by org_id and slug
        let service =
            ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, service_slug)
                .await?
                .ok_or_else(|| {
                    AppError::NotFound(format!("Service '{}' not found", service_slug))
                })?;

        let service_id = service.id.clone();

        // Get scopes for this provider from service entity
        let scopes_json = match provider {
            Provider::Github => &service.github_scopes,
            Provider::Microsoft => &service.microsoft_scopes,
            Provider::Google => &service.google_scopes,
            Provider::Oidc => &None, // OIDC scopes are dynamically managed
            Provider::Password => &None,
        };

        let scopes = scopes_json
            .as_ref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_else(|| {
                // Default scopes if not configured
                match provider {
                    Provider::Github => vec!["user:email".to_string()],
                    Provider::Microsoft => vec![
                        "User.Read".to_string(),
                        "email".to_string(),
                        "openid".to_string(),
                        "profile".to_string(),
                    ],
                    Provider::Google => vec![
                        "openid".to_string(),
                        "email".to_string(),
                        "profile".to_string(),
                    ],
                    Provider::Oidc => vec![
                        "openid".to_string(),
                        "email".to_string(),
                        "profile".to_string(),
                    ],
                    Provider::Password => vec![],
                }
            });

        // Parse redirect_uris to get the primary redirect
        let redirect_uris: Vec<String> = service
            .redirect_uris
            .as_ref()
            .and_then(|uris| serde_json::from_str(uris).ok())
            .unwrap_or_default();

        let base_redirect = match query.redirect_uri.as_deref() {
            Some(redirect_uri) => {
                if redirect_uris.is_empty() {
                    return Err(AppError::BadRequest(
                        "No redirect URIs are registered for this service".to_string(),
                    ));
                }

                if !redirect_uris
                    .iter()
                    .any(|allowed_uri| allowed_uri == redirect_uri)
                {
                    return Err(AppError::BadRequest(format!(
                        "redirect_uri '{}' is not registered for this service",
                        redirect_uri
                    )));
                }
                redirect_uri
            }
            None => redirect_uris.first().map(String::as_str).ok_or_else(|| {
                AppError::InternalServerError("Service has no redirect_uris configured".to_string())
            })?,
        };

        // Build redirect URL with query params for linking flow
        let redirect_uri = build_link_redirect_uri(base_redirect, provider.as_str())?;

        // Check if org has BYOO credentials for this provider
        let provider_str = provider.as_str();

        let org_credentials = OrganizationOAuthCredentialsStore::find_by_org_and_provider(
            DB::Conn(&state.db),
            &service.org_id,
            provider_str,
        )
        .await?;

        let (auth_url, csrf_token, pkce_verifier) = if let Some(_creds) = org_credentials {
            // Use BYOO credentials
            let encryption = crate::encryption::EncryptionService::new().map_err(|e| {
                AppError::InternalServerError(format!("Encryption unavailable: {}", e))
            })?;

            let custom_client =
                crate::store::organizations::OrganizationStore::get_oauth_client_for_org(
                    DB::Conn(&state.db),
                    &service.org_id,
                    provider,
                    &encryption,
                )
                .await?;

            get_authorization_url_for_client(&custom_client, provider, scopes.clone())
        } else {
            // Use platform credentials
            // Use ADMIN callback URL because that's what's registered with providers
            // (GitHub/Microsoft only allow 1 callback per app)
            let callback_url = format!(
                "{}/auth/admin/{}/callback",
                state.base_url,
                provider.as_str()
            );

            state.oauth_client.get_authorization_url_with_pkce(
                provider,
                scopes.clone(),
                Some(&callback_url),
            )?
        };

        (
            scopes,
            false,
            Some(org_slug.clone()),
            Some(service_slug.clone()),
            Some(service_id),
            redirect_uri,
            auth_url,
            csrf_token,
            pkce_verifier,
        )
    } else {
        // Platform-level linking: Use provider default scopes
        let default_scopes = match provider {
            Provider::Github => vec!["user:email".to_string()],
            Provider::Microsoft => vec![
                "User.Read".to_string(),
                "offline_access".to_string(),
                "email".to_string(),
                "openid".to_string(),
                "profile".to_string(),
            ],
            Provider::Google => vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            Provider::Oidc => vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            Provider::Password => vec![],
        };

        // Generate OAuth authorization URL with platform credentials
        // Use ADMIN callback URL because that's what's registered with providers
        // (GitHub/Microsoft only allow 1 callback per app)
        let callback_url = format!(
            "{}/auth/admin/{}/callback",
            state.base_url,
            provider.as_str()
        );

        let (auth_url, csrf_token, pkce_verifier) =
            state.oauth_client.get_authorization_url_with_pkce(
                provider,
                default_scopes.clone(),
                Some(&callback_url),
            )?;

        // For platform-level linking, use base_url + settings page
        let redirect_base = format!("{}/settings/connections", state.base_url);
        let redirect_uri = build_link_redirect_uri(&redirect_base, provider.as_str())?;

        (
            default_scopes,
            true,
            None,
            None,
            None,
            redirect_uri,
            auth_url,
            csrf_token,
            pkce_verifier,
        )
    };

    // Store OAuth state with user_id_for_linking set
    let expires_at = (Utc::now() + chrono::Duration::minutes(10)).naive_utc();
    let pkce_value = if !pkce_verifier.is_empty() {
        Some(pkce_verifier.as_str())
    } else {
        None
    };

    OAuthStateStore::create(
        DB::Conn(&state.db),
        csrf_token.secret(),
        pkce_value,
        service_id.as_deref(),
        Some(&redirect_uri),
        org_slug.as_deref(),
        service_slug.as_deref(),
        is_admin_flow,
        Some(&auth_user.user.id),
        None, // device_user_code
        None, // saml_state_id
        None, // upstream_connection_id
        Some(&scopes),
        None, // client_state
        None, // provider_token_request_state
        None, // resource
        &expires_at,
    )
    .await?;

    Ok(Json(StartLinkResponse {
        authorization_url: auth_url,
    }))
}

fn build_link_redirect_uri(base_redirect: &str, provider: &str) -> Result<String> {
    let mut redirect_url = url::Url::parse(base_redirect)
        .map_err(|_| AppError::BadRequest("Invalid redirect_uri".to_string()))?;

    redirect_url
        .query_pairs_mut()
        .append_pair("status", "success")
        .append_pair("provider", provider)
        .append_pair("action", "link");

    Ok(redirect_url.to_string())
}

/// DELETE /api/user/identities/:provider - Unlink a social account
pub async fn unlink_identity(
    State(state): State<AppState>,
    Path(provider_str): Path<String>,
    auth_user: Option<axum::extract::Extension<crate::middleware::AuthUser>>,
) -> Result<axum::http::StatusCode> {
    let auth_user = auth_user
        .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))?
        .0;

    let provider = Provider::from_str(&provider_str)?;

    // Get identity context (org_id and service_id) for proper isolation
    let (issuing_org_id, issuing_service_id) = get_identity_context(&state.db, &auth_user).await?;

    // Count identities to prevent account lockout
    let count = IdentityStore::count_by_user_with_context(
        DB::Conn(&state.db),
        &auth_user.user.id,
        issuing_org_id.as_deref(),
        issuing_service_id.as_deref(),
    )
    .await?;

    // Prevent account lockout by ensuring at least one identity remains in this context
    if count <= 1 {
        return Err(AppError::BadRequest(
            "Cannot unlink last identity. At least one identity must remain.".to_string(),
        ));
    }

    // Check if identity exists before attempting to delete
    let identity_exists = IdentityStore::find_by_user_and_provider(
        DB::Conn(&state.db),
        &auth_user.user.id,
        provider.as_str(),
        issuing_org_id.as_deref(),
        issuing_service_id.as_deref(),
    )
    .await?
    .is_some();

    if !identity_exists {
        return Err(AppError::NotFound(format!(
            "Identity for provider '{}' not found",
            provider.as_str()
        )));
    }

    IdentityStore::delete_by_user_and_provider(
        DB::Conn(&state.db),
        &auth_user.user.id,
        provider.as_str(),
        issuing_org_id.as_deref(),
        issuing_service_id.as_deref(),
    )
    .await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::crypto::jwt::JwtService;
    use crate::crypto::sso::OAuthClient;

    use crate::audit::actor::AuditHandle;
    use crate::db::DB;
    use crate::middleware::AuthUser;
    use crate::rsa_keys::GeneratedKey;
    use crate::services::{
        events::EventDispatcher, metrics::MfaMetricsService, risk_engine::RiskEngine,
    };
    use crate::state::AppState;
    use crate::store::{identities::IdentityStore, sessions::SessionStore, users::UserStore};
    use base64::{engine::general_purpose::STANDARD, Engine};
    use migration::{Migrator, MigratorTrait};
    use moka::future::Cache;
    use sea_orm::Database;
    use std::sync::Arc;

    use crate::test_support::test_config;

    struct Fixture {
        state: AppState,
        auth_user: AuthUser,
    }

    async fn fixture() -> Fixture {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let config = test_config();
        let jwt_service = Arc::new({
            let rsa = GeneratedKey::generate().expect("generate test rsa key");
            JwtService::new(
                &STANDARD.encode(rsa.private_key_pem().expect("private pem")),
                &STANDARD.encode(rsa.public_key_pem().expect("public pem")),
                config.jwt_expiration_hours,
                "test-key",
                &config.base_url,
            )
            .expect("create jwt service")
        });

        let user = UserStore::create(DB::Conn(&db), "identities@example.test", None, false)
            .await
            .expect("create user");

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

        let token = jwt_service
            .create_token(&user.id, &user.email, false, None, None)
            .expect("create token");
        let session = SessionStore::create(
            DB::Conn(&db),
            &user.id,
            &JwtService::hash_token(&token),
            (chrono::Utc::now() + chrono::Duration::hours(1)).naive_utc(),
            None,
            None,
            None,
            None,
            None,
            Some("identity-test"),
            Some("127.0.0.1"),
        )
        .await
        .expect("create session");
        let auth_user = AuthUser {
            // Claims are unused by these handlers beyond org/service context.
            claims: jwt_service.validate_token(&token).expect("validate token"),
            user,
            permissions: vec![],
            ip_address: "127.0.0.1".to_string(),
            user_agent: "identity-test".to_string(),
            current_session_id: Some(session.id),
        };
        Fixture { state, auth_user }
    }

    async fn add_identity(f: &Fixture, provider: &str) {
        IdentityStore::create(
            DB::Conn(&f.state.db),
            &f.auth_user.user.id,
            provider,
            &format!("{provider}-uid"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("seed identity");
    }

    #[tokio::test]
    async fn unauthenticated_requests_are_rejected() {
        let f = fixture().await;
        for result in [
            list_identities(State(f.state.clone()), None).await.err(),
            start_link(
                State(f.state.clone()),
                Path("github".to_string()),
                Query(StartLinkQuery { redirect_uri: None }),
                None,
            )
            .await
            .err(),
            unlink_identity(State(f.state.clone()), Path("github".to_string()), None)
                .await
                .err(),
        ] {
            match result {
                Some(AppError::Unauthorized(_)) => {}
                other => panic!("expected unauthorized, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn unknown_providers_are_rejected_before_anything_else() {
        let f = fixture().await;
        let auth = axum::Extension(f.auth_user.clone());
        match start_link(
            State(f.state.clone()),
            Path("myspace".to_string()),
            Query(StartLinkQuery { redirect_uri: None }),
            Some(auth.clone()),
        )
        .await
        {
            Err(AppError::BadRequest(message)) => assert!(message.contains("provider")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
        match unlink_identity(
            State(f.state.clone()),
            Path("myspace".to_string()),
            Some(auth),
        )
        .await
        {
            Err(AppError::BadRequest(message)) => assert!(message.contains("provider")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn listing_starts_empty_and_reflects_seeded_identities() {
        let f = fixture().await;
        let Json(empty) = list_identities(
            State(f.state.clone()),
            Some(axum::Extension(f.auth_user.clone())),
        )
        .await
        .expect("list identities");
        assert!(empty.is_empty());

        add_identity(&f, "github").await;
        add_identity(&f, "google").await;

        let Json(list) = list_identities(
            State(f.state.clone()),
            Some(axum::Extension(f.auth_user.clone())),
        )
        .await
        .expect("list identities");
        let providers: Vec<String> = list.into_iter().map(|i| i.provider).collect();
        assert!(providers.contains(&"github".to_string()));
        assert!(providers.contains(&"google".to_string()));
    }

    #[tokio::test]
    async fn linking_without_platform_credentials_is_reported_not_crashed() {
        let f = fixture().await;
        match start_link(
            State(f.state.clone()),
            Path("github".to_string()),
            Query(StartLinkQuery { redirect_uri: None }),
            Some(axum::Extension(f.auth_user.clone())),
        )
        .await
        {
            Err(AppError::BadRequest(message)) => {
                assert!(message.contains("not configured"), "{message}")
            }
            other => panic!("expected not-configured error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_last_identity_cannot_be_unlinked() {
        let f = fixture().await;
        add_identity(&f, "github").await;

        match unlink_identity(
            State(f.state.clone()),
            Path("github".to_string()),
            Some(axum::Extension(f.auth_user.clone())),
        )
        .await
        {
            Err(AppError::BadRequest(message)) => {
                assert!(message.contains("last identity"), "{message}")
            }
            other => panic!("expected last-identity guard, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn identity_management_is_scoped_to_the_authenticated_user() {
        let f = fixture().await;
        let second = UserStore::create(
            DB::Conn(&f.state.db),
            "identities-second@example.test",
            None,
            false,
        )
        .await
        .expect("create second user");
        let token = f
            .state
            .jwt_service
            .create_token(&second.id, &second.email, false, None, None)
            .expect("create second token");
        let second_auth = AuthUser {
            claims: f
                .state
                .jwt_service
                .validate_token(&token)
                .expect("validate second token"),
            user: second.clone(),
            permissions: vec![],
            ip_address: "127.0.0.1".to_string(),
            user_agent: "identity-second-test".to_string(),
            current_session_id: None,
        };

        add_identity(&f, "github").await;
        add_identity(&f, "google").await;
        IdentityStore::create(
            DB::Conn(&f.state.db),
            &second.id,
            "github",
            "second-github-uid",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("seed second user identity");

        let Json(first_list) = list_identities(
            State(f.state.clone()),
            Some(axum::Extension(f.auth_user.clone())),
        )
        .await
        .expect("list first user identities");
        assert_eq!(first_list.len(), 2);
        let Json(second_list) = list_identities(
            State(f.state.clone()),
            Some(axum::Extension(second_auth.clone())),
        )
        .await
        .expect("list second user identities");
        assert_eq!(second_list.len(), 1);

        let status = unlink_identity(
            State(f.state.clone()),
            Path("github".to_string()),
            Some(axum::Extension(f.auth_user.clone())),
        )
        .await
        .expect("unlink first user identity");
        assert_eq!(status, axum::http::StatusCode::NO_CONTENT);

        let Json(first_after) = list_identities(
            State(f.state.clone()),
            Some(axum::Extension(f.auth_user.clone())),
        )
        .await
        .expect("list first user identities after unlink");
        assert_eq!(first_after.len(), 1);
        assert_eq!(first_after[0].provider, "google");
        assert!(
            IdentityStore::find_by_user_and_provider(
                DB::Conn(&f.state.db),
                &second.id,
                "github",
                None,
                None,
            )
            .await
            .expect("load second identity")
            .is_some(),
            "unlinking the first user's identity must not affect the second user"
        );
    }

    #[tokio::test]
    async fn unlink_removes_only_the_chosen_provider() {
        let f = fixture().await;
        add_identity(&f, "github").await;
        add_identity(&f, "google").await;

        let status = unlink_identity(
            State(f.state.clone()),
            Path("github".to_string()),
            Some(axum::Extension(f.auth_user.clone())),
        )
        .await
        .expect("unlink github");
        assert_eq!(status, axum::http::StatusCode::NO_CONTENT);

        let Json(list) = list_identities(
            State(f.state.clone()),
            Some(axum::Extension(f.auth_user.clone())),
        )
        .await
        .expect("list identities");
        let providers: Vec<String> = list.into_iter().map(|i| i.provider).collect();
        assert_eq!(providers, vec!["google".to_string()]);

        // The last-identity guard fires before the existence check.
        match unlink_identity(
            State(f.state.clone()),
            Path("microsoft".to_string()),
            Some(axum::Extension(f.auth_user.clone())),
        )
        .await
        {
            Err(AppError::BadRequest(message)) => {
                assert!(message.contains("last identity"), "{message}")
            }
            other => panic!("expected last-identity guard, got {other:?}"),
        }
    }
}
