use crate::crypto::sso::{configured_basic_client, ConfiguredBasicClient, Provider};
use crate::db::transaction::with_retrying_transaction;
use crate::db::DB;
use crate::error::{AppError, Result};
use crate::handlers::auth::{
    get_authorization_url_for_client, is_supported_upstream_oauth_type,
    resolve_upstream_oidc_config,
};
use crate::middleware::AuthUser;
use crate::services::audit_builder::OrgAuditBuilder;
use crate::state::AppState;
use crate::store::{
    connected_accounts::ConnectedAccountStore, identities::IdentityStore,
    oauth_states::OAuthStateStore,
    organization_oauth_credentials::OrganizationOAuthCredentialsStore,
    organizations::OrganizationStore, provider_token_requests::ProviderTokenRequestStore,
    service_provider_grants::ServiceProviderGrantStore, services::ServiceStore,
    upstream_providers::UpstreamProviderStore,
};
use crate::utils::scopes::{parse_optional_scopes, parse_required_scopes};
use axum::{
    extract::{Path, Query, State},
    response::Redirect,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use url::Url;

#[derive(Debug, Serialize)]
pub struct ProviderDefinition {
    pub provider: String,
    pub display_name: String,
    pub provider_type: String,
    pub scopes: Vec<String>,
    pub connect_supported: bool,
}

#[derive(Debug, Serialize)]
pub struct LinkedAccountGrantResponse {
    pub id: String,
    pub service_id: String,
    pub scopes: Vec<String>,
    pub granted_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LinkedAccountResponse {
    pub id: String,
    pub provider: String,
    pub provider_user_id: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub scopes: Vec<String>,
    pub expires_at: Option<String>,
    pub status: String,
    pub grants: Vec<LinkedAccountGrantResponse>,
}

#[derive(Debug, Serialize)]
pub struct LinkedAccountsResponse {
    pub accounts: Vec<LinkedAccountResponse>,
    pub available_providers: Vec<ProviderDefinition>,
}

#[derive(Debug, Deserialize)]
pub struct GrantLinkedAccountRequest {
    pub service_id: Option<String>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ProviderTokenRequestResponse {
    pub state: String,
    pub provider: String,
    pub requested_scopes: Vec<String>,
    pub service_id: String,
    pub service_name: String,
    pub expires_at: String,
    pub accounts: Vec<LinkedAccountResponse>,
}

#[derive(Debug, Deserialize)]
pub struct CompleteProviderTokenRequest {
    pub connected_account_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CompleteProviderTokenResponse {
    pub redirect_url: String,
}

fn parse_scopes(scopes_json: &Option<String>) -> Vec<String> {
    parse_optional_scopes(scopes_json)
}

fn parse_scopes_required(scopes_json: &str) -> Vec<String> {
    parse_required_scopes(scopes_json)
}

fn has_all_scopes(available: &[String], requested: &[String]) -> bool {
    requested.iter().all(|scope| {
        available
            .iter()
            .any(|available_scope| available_scope == scope)
    })
}

fn missing_scopes(available: &[String], requested: &[String]) -> Vec<String> {
    requested
        .iter()
        .filter(|scope| {
            !available
                .iter()
                .any(|available_scope| available_scope == *scope)
        })
        .cloned()
        .collect()
}

fn build_link_redirect_uri(base_redirect: &str, provider: &str) -> Result<String> {
    let mut redirect_url = Url::parse(base_redirect)
        .map_err(|_| AppError::BadRequest("Invalid redirect_uri".to_string()))?;

    redirect_url
        .query_pairs_mut()
        .append_pair("status", "success")
        .append_pair("provider", provider)
        .append_pair("action", "link");

    Ok(redirect_url.to_string())
}

fn choose_service_redirect_uri(
    service: &crate::entities::services::Model,
    requested_redirect_uri: Option<&str>,
) -> Result<String> {
    let redirect_uris = service
        .redirect_uris
        .as_ref()
        .and_then(|uris| serde_json::from_str::<Vec<String>>(uris).ok())
        .unwrap_or_default();

    if let Some(redirect_uri) = requested_redirect_uri {
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
        return Ok(redirect_uri.to_string());
    }

    redirect_uris.first().cloned().ok_or_else(|| {
        AppError::InternalServerError("Service has no redirect_uris configured".to_string())
    })
}

async fn current_service_from_claims(
    state: &AppState,
    auth_user: &AuthUser,
) -> Result<Option<crate::entities::services::Model>> {
    let Some(org_slug) = auth_user.claims.org.as_deref().filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let Some(service_slug) = auth_user
        .claims
        .service
        .as_deref()
        .filter(|s| !s.is_empty())
    else {
        return Ok(None);
    };
    if org_slug == "platform" && service_slug == "admin-cli" {
        return Ok(None);
    }

    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
    ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, service_slug).await
}

async fn resolve_grant_service(
    state: &AppState,
    auth_user: &AuthUser,
    service_id: Option<&str>,
) -> Result<crate::entities::services::Model> {
    if let Some(current_service) = current_service_from_claims(state, auth_user).await? {
        return Ok(current_service);
    }

    let service_id =
        service_id.ok_or_else(|| AppError::BadRequest("service_id is required".to_string()))?;
    ServiceStore::find_by_id(DB::Conn(&state.db), service_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Service not found".to_string()))
}

async fn ensure_user_belongs_to_service(
    state: &AppState,
    user_id: &str,
    service_id: &str,
) -> Result<()> {
    let service = ServiceStore::find_by_id(DB::Conn(&state.db), service_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;

    let has_authenticated = IdentityStore::user_has_authenticated_with_service(
        DB::Conn(&state.db),
        user_id,
        service_id,
    )
    .await?;
    if !has_authenticated {
        return Err(AppError::Forbidden(
            "User has not authenticated with this service".to_string(),
        ));
    }

    let user = crate::store::users::UserStore::find_by_id(DB::Conn(&state.db), user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    if user.org_id.as_deref() != Some(service.org_id.as_str()) {
        return Err(AppError::Forbidden(
            "User has not authenticated with this service".to_string(),
        ));
    }

    Ok(())
}

fn built_in_service_scopes(
    service: &crate::entities::services::Model,
    provider: &str,
) -> Option<Vec<String>> {
    match provider {
        "github" => Some(parse_scopes(&service.github_scopes)),
        "google" => Some(parse_scopes(&service.google_scopes)),
        "microsoft" => Some(parse_scopes(&service.microsoft_scopes)),
        _ => None,
    }
}

async fn service_allowed_scopes(
    state: &AppState,
    service: &crate::entities::services::Model,
    provider: &str,
) -> Result<Vec<String>> {
    if let Some(scopes) = built_in_service_scopes(service, provider) {
        return Ok(scopes);
    }

    let upstream = UpstreamProviderStore::find_by_connection_id(
        DB::Conn(&state.db),
        &service.org_id,
        provider,
    )
    .await?;
    if let Some(upstream) = upstream.filter(|provider| provider.enabled) {
        return Ok(parse_scopes(&upstream.scopes));
    }

    Err(AppError::BadRequest(
        "Provider is not configured for this service".to_string(),
    ))
}

fn default_provider_scopes(provider: &str) -> Vec<String> {
    match provider {
        "github" => vec!["user:email".to_string()],
        "microsoft" => vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
            "offline_access".to_string(),
            "User.Read".to_string(),
        ],
        "google" => vec![
            "openid".to_string(),
            "email".to_string(),
            "profile".to_string(),
        ],
        _ => vec![],
    }
}

fn built_in_provider_from_key(provider: &str) -> Option<Provider> {
    match provider.to_ascii_lowercase().as_str() {
        "github" => Some(Provider::Github),
        "google" => Some(Provider::Google),
        "microsoft" => Some(Provider::Microsoft),
        _ => None,
    }
}

async fn build_upstream_oauth_client(
    state: &AppState,
    provider: &crate::entities::upstream_providers::Model,
) -> Result<ConfiguredBasicClient> {
    if !provider.enabled {
        return Err(AppError::BadRequest(
            "Upstream provider is disabled".to_string(),
        ));
    }
    if !is_supported_upstream_oauth_type(&provider.provider_type) {
        return Err(AppError::BadRequest(format!(
            "Provider type '{}' cannot be linked as an OAuth connected account",
            provider.provider_type
        )));
    }

    let oidc_config = resolve_upstream_oidc_config(provider).await?;
    let encryption = state
        .encryption
        .as_ref()
        .ok_or_else(|| AppError::InternalServerError("Encryption unavailable".to_string()))?;
    let secret = encryption
        .decrypt_with_context(
            &provider.client_secret_encrypted,
            crate::encryption::EncryptionContext::new(
                "upstream_providers",
                &provider.id,
                "client_secret_encrypted",
            ),
        )
        .map_err(|e| AppError::InternalServerError(format!("Failed to decrypt secret: {}", e)))?;

    configured_basic_client(
        provider.client_id.clone(),
        secret,
        oidc_config.authorization_url,
        oidc_config.token_url,
        format!("{}/auth/oidc/callback", state.base_url),
    )
}

async fn provider_registry(
    state: &AppState,
    service: Option<&crate::entities::services::Model>,
) -> Result<Vec<ProviderDefinition>> {
    let mut providers = vec![
        ProviderDefinition {
            provider: "github".to_string(),
            display_name: "GitHub".to_string(),
            provider_type: "oauth2".to_string(),
            scopes: service
                .and_then(|service| built_in_service_scopes(service, "github"))
                .filter(|scopes| !scopes.is_empty())
                .unwrap_or_else(|| default_provider_scopes("github")),
            connect_supported: true,
        },
        ProviderDefinition {
            provider: "google".to_string(),
            display_name: "Google".to_string(),
            provider_type: "oauth2".to_string(),
            scopes: service
                .and_then(|service| built_in_service_scopes(service, "google"))
                .filter(|scopes| !scopes.is_empty())
                .unwrap_or_else(|| default_provider_scopes("google")),
            connect_supported: true,
        },
        ProviderDefinition {
            provider: "microsoft".to_string(),
            display_name: "Microsoft".to_string(),
            provider_type: "oauth2".to_string(),
            scopes: service
                .and_then(|service| built_in_service_scopes(service, "microsoft"))
                .filter(|scopes| !scopes.is_empty())
                .unwrap_or_else(|| default_provider_scopes("microsoft")),
            connect_supported: true,
        },
    ];

    if let Some(service) = service {
        for upstream in UpstreamProviderStore::find_by_org(DB::Conn(&state.db), &service.org_id)
            .await?
            .into_iter()
            .filter(|provider| provider.enabled)
        {
            providers.push(ProviderDefinition {
                provider: upstream.connection_id,
                display_name: upstream.name,
                connect_supported: is_supported_upstream_oauth_type(&upstream.provider_type),
                provider_type: upstream.provider_type,
                scopes: parse_scopes(&upstream.scopes),
            });
        }
    }

    Ok(providers)
}

fn grant_response(
    grant: crate::entities::service_provider_grants::Model,
) -> LinkedAccountGrantResponse {
    LinkedAccountGrantResponse {
        id: grant.id,
        service_id: grant.service_id,
        scopes: parse_scopes_required(&grant.scopes),
        granted_at: DateTime::<Utc>::from_naive_utc_and_offset(grant.granted_at, Utc).to_rfc3339(),
        last_used_at: grant
            .last_used_at
            .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc).to_rfc3339()),
    }
}

fn account_response(
    account: crate::entities::connected_accounts::Model,
    grants: Vec<crate::entities::service_provider_grants::Model>,
) -> LinkedAccountResponse {
    LinkedAccountResponse {
        id: account.id,
        provider: account.provider,
        provider_user_id: account.provider_user_id,
        email: account.email,
        display_name: account.display_name,
        scopes: parse_scopes(&account.scopes),
        expires_at: account
            .expires_at
            .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc).to_rfc3339()),
        status: account.status,
        grants: grants.into_iter().map(grant_response).collect(),
    }
}

async fn active_grants_by_account(
    state: &AppState,
    user_id: &str,
    service_id: Option<&str>,
    accounts: &[crate::entities::connected_accounts::Model],
) -> Result<HashMap<String, Vec<crate::entities::service_provider_grants::Model>>> {
    let Some(service_id) = service_id else {
        return Ok(HashMap::new());
    };
    let account_ids = accounts
        .iter()
        .map(|account| account.id.clone())
        .collect::<Vec<_>>();
    let grants = ServiceProviderGrantStore::list_active_by_accounts(
        DB::Conn(&state.db),
        user_id,
        service_id,
        &account_ids,
    )
    .await?;
    let mut by_account: HashMap<String, Vec<crate::entities::service_provider_grants::Model>> =
        HashMap::new();
    for grant in grants {
        by_account
            .entry(grant.connected_account_id.clone())
            .or_default()
            .push(grant);
    }
    Ok(by_account)
}

pub async fn list_linked_accounts(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> Result<Json<LinkedAccountsResponse>> {
    let service = current_service_from_claims(&state, &auth_user).await?;
    let service_id = service.as_ref().map(|service| service.id.as_str());
    let accounts =
        ConnectedAccountStore::list_by_user(DB::Conn(&state.db), &auth_user.user.id).await?;
    let mut grants_by_account =
        active_grants_by_account(&state, &auth_user.user.id, service_id, &accounts).await?;

    let mut responses = Vec::with_capacity(accounts.len());
    for account in accounts {
        let grants = grants_by_account.remove(&account.id).unwrap_or_default();
        responses.push(account_response(account, grants));
    }

    Ok(Json(LinkedAccountsResponse {
        accounts: responses,
        available_providers: provider_registry(&state, service.as_ref()).await?,
    }))
}

pub async fn start_linked_account(
    State(state): State<AppState>,
    Path(provider_key): Path<String>,
    Query(query): Query<crate::handlers::identities::StartLinkQuery>,
    auth_user: AuthUser,
) -> Result<Json<crate::handlers::identities::StartLinkResponse>> {
    crate::middleware::require_recent_authentication(
        &state.db,
        &auth_user,
        chrono::Duration::minutes(10),
    )
    .await?;
    let service = current_service_from_claims(&state, &auth_user).await?;
    let (
        authorization_url,
        csrf_token,
        pkce_verifier,
        service_id,
        org_slug,
        service_slug,
        redirect_uri,
        upstream_connection_id,
        is_admin_flow,
        scopes,
    ) = if let Some(service) = service {
        let org = OrganizationStore::find_by_id(DB::Conn(&state.db), &service.org_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
        let base_redirect = choose_service_redirect_uri(&service, query.redirect_uri.as_deref())?;

        if let Some(provider) = built_in_provider_from_key(&provider_key) {
            let mut scopes = service_allowed_scopes(&state, &service, provider.as_str()).await?;
            if scopes.is_empty() {
                scopes = default_provider_scopes(provider.as_str());
            }
            let redirect_uri = build_link_redirect_uri(&base_redirect, provider.as_str())?;
            let callback_url = format!(
                "{}/auth/admin/{}/callback",
                state.base_url,
                provider.as_str()
            );
            let org_credentials = OrganizationOAuthCredentialsStore::find_by_org_and_provider(
                DB::Conn(&state.db),
                &service.org_id,
                provider.as_str(),
            )
            .await?;
            let (authorization_url, csrf_token, pkce_verifier) = if org_credentials.is_some() {
                let encryption = state.encryption.as_ref().ok_or_else(|| {
                    AppError::InternalServerError("Encryption service unavailable".to_string())
                })?;
                let custom_client = OrganizationStore::get_oauth_client_for_org(
                    DB::Conn(&state.db),
                    &service.org_id,
                    provider,
                    encryption,
                )
                .await?;
                get_authorization_url_for_client(&custom_client, provider, scopes.clone())
            } else {
                state.oauth_client.get_authorization_url_with_pkce(
                    provider,
                    scopes.clone(),
                    Some(&callback_url),
                )?
            };

            (
                authorization_url,
                csrf_token,
                pkce_verifier,
                Some(service.id),
                Some(org.slug),
                Some(service.slug),
                redirect_uri,
                None,
                false,
                scopes,
            )
        } else {
            let upstream = UpstreamProviderStore::find_by_connection_id(
                DB::Conn(&state.db),
                &service.org_id,
                &provider_key,
            )
            .await?
            .ok_or_else(|| AppError::NotFound("Upstream provider not found".to_string()))?;
            let mut scopes = parse_scopes(&upstream.scopes);
            if scopes.is_empty() {
                scopes = default_provider_scopes("oidc");
            }
            let client = build_upstream_oauth_client(&state, &upstream).await?;
            let (authorization_url, csrf_token, pkce_verifier) =
                get_authorization_url_for_client(&client, Provider::Oidc, scopes.clone());
            let redirect_uri = build_link_redirect_uri(&base_redirect, &provider_key)?;

            (
                authorization_url,
                csrf_token,
                pkce_verifier,
                Some(service.id),
                Some(org.slug),
                Some(service.slug),
                redirect_uri,
                Some(provider_key),
                false,
                scopes,
            )
        }
    } else {
        let provider = built_in_provider_from_key(&provider_key).ok_or_else(|| {
            AppError::BadRequest("Custom provider linking requires service context".to_string())
        })?;
        let scopes = default_provider_scopes(provider.as_str());
        let callback_url = format!(
            "{}/auth/admin/{}/callback",
            state.base_url,
            provider.as_str()
        );
        let (authorization_url, csrf_token, pkce_verifier) = state
            .oauth_client
            .get_authorization_url_with_pkce(provider, scopes.clone(), Some(&callback_url))?;
        let redirect_base = format!(
            "{}/settings/connections",
            state.web_client_url.trim_end_matches('/')
        );
        let redirect_uri = build_link_redirect_uri(&redirect_base, provider.as_str())?;

        (
            authorization_url,
            csrf_token,
            pkce_verifier,
            None,
            None,
            None,
            redirect_uri,
            None,
            true,
            scopes,
        )
    };

    let expires_at = (Utc::now() + chrono::Duration::minutes(10)).naive_utc();
    let pkce_value = if pkce_verifier.is_empty() {
        None
    } else {
        Some(pkce_verifier.as_str())
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
        None,
        None,
        upstream_connection_id.as_deref(),
        Some(&scopes),
        None,
        None,
        None,
        &expires_at,
    )
    .await?;

    Ok(Json(crate::handlers::identities::StartLinkResponse {
        authorization_url,
    }))
}

pub async fn grant_linked_account(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    auth_user: AuthUser,
    Json(req): Json<GrantLinkedAccountRequest>,
) -> Result<Json<LinkedAccountGrantResponse>> {
    let account = ConnectedAccountStore::find_active_by_id_for_user(
        DB::Conn(&state.db),
        &account_id,
        &auth_user.user.id,
    )
    .await?
    .ok_or_else(|| AppError::NotFound("Connected account not found".to_string()))?;
    let service = resolve_grant_service(&state, &auth_user, req.service_id.as_deref()).await?;
    ensure_user_belongs_to_service(&state, &auth_user.user.id, &service.id).await?;

    let allowed_scopes = service_allowed_scopes(&state, &service, &account.provider).await?;
    let requested_scopes = if req.scopes.is_empty() {
        allowed_scopes.clone()
    } else {
        req.scopes
    };
    let missing_from_service = missing_scopes(&allowed_scopes, &requested_scopes);
    if !missing_from_service.is_empty() {
        return Err(AppError::Forbidden(format!(
            "Requested scopes are not allowed for this service: {}",
            missing_from_service.join(", ")
        )));
    }

    let account_scopes = parse_scopes(&account.scopes);
    let missing_from_account = missing_scopes(&account_scopes, &requested_scopes);
    if !missing_from_account.is_empty() {
        return Err(AppError::BadRequest(format!(
            "Connected account is missing scopes and must be reauthorized: {}",
            missing_from_account.join(", ")
        )));
    }

    let grant = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "create_linked_account_grant_with_audit",
        |db| {
            let user_id = auth_user.user.id.clone();
            let service_id = service.id.clone();
            let account_id = account.id.clone();
            let provider = account.provider.clone();
            let requested_scopes = requested_scopes.clone();
            let org_id = service.org_id.clone();
            let audit_actor = state.audit_actor.clone();
            Box::pin(async move {
                let grant = ServiceProviderGrantStore::upsert(
                    db.clone(),
                    &user_id,
                    &service_id,
                    &account_id,
                    &provider,
                    &requested_scopes,
                )
                .await?;
                let event = OrgAuditBuilder::new(&org_id, Some(&user_id), "provider_grant.created")
                    .target("connected_account", &account_id)
                    .details_json(Some(json!({
                        "grant_id": &grant.id,
                        "service_id": &service_id,
                        "provider": &provider,
                        "scopes": &requested_scopes,
                    })))
                    .build();
                audit_actor.log_org_with_db(db, event).await?;
                Ok(grant)
            })
        },
    )
    .await?;

    Ok(Json(LinkedAccountGrantResponse {
        id: grant.id,
        service_id: grant.service_id,
        scopes: parse_scopes_required(&grant.scopes),
        granted_at: DateTime::<Utc>::from_naive_utc_and_offset(grant.granted_at, Utc).to_rfc3339(),
        last_used_at: None,
    }))
}

pub async fn revoke_linked_account_grant(
    State(state): State<AppState>,
    Path((account_id, service_id)): Path<(String, String)>,
    auth_user: AuthUser,
) -> Result<axum::http::StatusCode> {
    ConnectedAccountStore::find_active_by_id_for_user(
        DB::Conn(&state.db),
        &account_id,
        &auth_user.user.id,
    )
    .await?
    .ok_or_else(|| AppError::NotFound("Connected account not found".to_string()))?;
    let service = ServiceStore::find_by_id(DB::Conn(&state.db), &service_id).await?;
    let event = service.map(|service| {
        OrgAuditBuilder::new(
            &service.org_id,
            Some(&auth_user.user.id),
            "provider_grant.revoked",
        )
        .target("connected_account", &account_id)
        .details_json(Some(json!({
            "service_id": service_id,
        })))
        .build()
    });
    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "revoke_linked_account_grant_with_audit",
        |db| {
            let user_id = auth_user.user.id.clone();
            let service_id = service_id.clone();
            let account_id = account_id.clone();
            let event = event.clone();
            let audit_actor = state.audit_actor.clone();
            Box::pin(async move {
                ServiceProviderGrantStore::revoke(db.clone(), &user_id, &service_id, &account_id)
                    .await?;
                if let Some(event) = event {
                    audit_actor.log_org_with_db(db, event).await?;
                }
                Ok(())
            })
        },
    )
    .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

pub async fn revoke_linked_account(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    auth_user: AuthUser,
) -> Result<axum::http::StatusCode> {
    ConnectedAccountStore::revoke(DB::Conn(&state.db), &account_id, &auth_user.user.id).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

pub async fn get_provider_token_request(
    State(state): State<AppState>,
    Path(request_state): Path<String>,
    auth_user: AuthUser,
) -> Result<Json<ProviderTokenRequestResponse>> {
    let request = ProviderTokenRequestStore::find_active_for_user(
        DB::Conn(&state.db),
        &request_state,
        &auth_user.user.id,
    )
    .await?
    .ok_or_else(|| AppError::NotFound("Provider token request not found".to_string()))?;
    let service = ServiceStore::find_by_id(DB::Conn(&state.db), &request.service_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;
    let accounts = ConnectedAccountStore::list_by_user_and_provider(
        DB::Conn(&state.db),
        &auth_user.user.id,
        &request.provider,
    )
    .await?;
    let mut grants_by_account =
        active_grants_by_account(&state, &auth_user.user.id, Some(&service.id), &accounts).await?;
    let mut account_responses = Vec::with_capacity(accounts.len());
    for account in accounts {
        let grants = grants_by_account.remove(&account.id).unwrap_or_default();
        account_responses.push(account_response(account, grants));
    }

    Ok(Json(ProviderTokenRequestResponse {
        state: request.state,
        provider: request.provider,
        requested_scopes: parse_scopes_required(&request.requested_scopes),
        service_id: service.id,
        service_name: service.name,
        expires_at: DateTime::<Utc>::from_naive_utc_and_offset(request.expires_at, Utc)
            .to_rfc3339(),
        accounts: account_responses,
    }))
}

pub async fn complete_provider_token_request(
    State(state): State<AppState>,
    Path(request_state): Path<String>,
    auth_user: AuthUser,
    Json(req): Json<CompleteProviderTokenRequest>,
) -> Result<Json<CompleteProviderTokenResponse>> {
    let request = ProviderTokenRequestStore::find_active_for_user(
        DB::Conn(&state.db),
        &request_state,
        &auth_user.user.id,
    )
    .await?
    .ok_or_else(|| AppError::NotFound("Provider token request not found".to_string()))?;
    let service = ServiceStore::find_by_id(DB::Conn(&state.db), &request.service_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;
    ensure_user_belongs_to_service(&state, &auth_user.user.id, &request.service_id).await?;
    let requested_scopes = parse_scopes_required(&request.requested_scopes);

    let candidate_accounts = if let Some(account_id) = req.connected_account_id.as_deref() {
        vec![ConnectedAccountStore::find_active_by_id_for_user(
            DB::Conn(&state.db),
            account_id,
            &auth_user.user.id,
        )
        .await?
        .ok_or_else(|| AppError::NotFound("Connected account not found".to_string()))?]
    } else {
        ConnectedAccountStore::list_by_user_and_provider(
            DB::Conn(&state.db),
            &auth_user.user.id,
            &request.provider,
        )
        .await?
    };

    let account = candidate_accounts
        .into_iter()
        .find(|account| {
            account.provider == request.provider
                && has_all_scopes(&parse_scopes(&account.scopes), &requested_scopes)
        })
        .ok_or_else(|| {
            AppError::BadRequest(
                "No connected account satisfies the requested provider scopes".to_string(),
            )
        })?;

    let mut redirect = Url::parse(&request.redirect_uri)
        .map_err(|_| AppError::BadRequest("Invalid stored redirect_uri".to_string()))?;
    let event = OrgAuditBuilder::new(
        &service.org_id,
        Some(&auth_user.user.id),
        "provider_grant.created",
    )
    .target("connected_account", &account.id)
    .details_json(Some(json!({
        "service_id": &request.service_id,
        "provider": &request.provider,
        "scopes": &requested_scopes,
        "provider_token_request": &request.state,
    })))
    .build();
    let completed_event = OrgAuditBuilder::new(
        &service.org_id,
        Some(&auth_user.user.id),
        "provider_token_request.completed",
    )
    .target("provider_token_request", &request.state)
    .details_json(Some(json!({
        "service_id": &request.service_id,
        "provider": &request.provider,
        "connected_account_id": &account.id,
    })))
    .build();

    let request_state = request.state.clone();
    let service_id = request.service_id.clone();
    let provider = request.provider.clone();
    let user_id = auth_user.user.id.clone();
    let account_id = account.id.clone();
    let audit_actor = state.audit_actor.clone();
    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "complete_provider_token_request",
        |db| {
            let request_state = request_state.clone();
            let service_id = service_id.clone();
            let provider = provider.clone();
            let user_id = user_id.clone();
            let account_id = account_id.clone();
            let requested_scopes = requested_scopes.clone();
            let audit_actor = audit_actor.clone();
            let event = event.clone();
            let completed_event = completed_event.clone();
            Box::pin(async move {
                ProviderTokenRequestStore::complete_with_grant_and_audits_in_transaction(
                    db,
                    &audit_actor,
                    &request_state,
                    &user_id,
                    &service_id,
                    &account_id,
                    &provider,
                    &requested_scopes,
                    vec![event, completed_event],
                )
                .await
            })
        },
    )
    .await?;
    {
        let mut pairs = redirect.query_pairs_mut();
        pairs
            .append_pair("provider_grant", "success")
            .append_pair("provider", &request.provider);
        if let Some(client_state) = request.client_state.as_deref() {
            pairs.append_pair("state", client_state);
        }
    }

    Ok(Json(CompleteProviderTokenResponse {
        redirect_url: redirect.to_string(),
    }))
}

async fn create_provider_token_request_oauth_state(
    state: &AppState,
    request: &crate::entities::provider_token_requests::Model,
    linking_user_id: &str,
) -> Result<String> {
    let service = ServiceStore::find_by_id(DB::Conn(&state.db), &request.service_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;
    let org = OrganizationStore::find_by_id(DB::Conn(&state.db), &service.org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
    let requested_scopes = parse_scopes_required(&request.requested_scopes);
    let allowed_scopes = service_allowed_scopes(state, &service, &request.provider).await?;
    if !has_all_scopes(&allowed_scopes, &requested_scopes) {
        return Err(AppError::Forbidden(
            "Requested scopes are not allowed for this service".to_string(),
        ));
    }

    let mut return_url = Url::parse(&format!(
        "{}/settings/connections",
        state.web_client_url.trim_end_matches('/')
    ))
    .map_err(|_| AppError::InternalServerError("Invalid dashboard URL".to_string()))?;
    return_url
        .query_pairs_mut()
        .append_pair("provider_token_request", &request.state);

    let (authorization_url, csrf_token, pkce_verifier, upstream_connection_id) =
        if let Some(provider) = built_in_provider_from_key(&request.provider) {
            let callback_url = format!(
                "{}/auth/admin/{}/callback",
                state.base_url,
                provider.as_str()
            );
            let org_credentials = OrganizationOAuthCredentialsStore::find_by_org_and_provider(
                DB::Conn(&state.db),
                &service.org_id,
                provider.as_str(),
            )
            .await?;
            let (authorization_url, csrf_token, pkce_verifier) = if org_credentials.is_some() {
                let encryption = state.encryption.as_ref().ok_or_else(|| {
                    AppError::InternalServerError("Encryption service unavailable".to_string())
                })?;
                let custom_client = OrganizationStore::get_oauth_client_for_org(
                    DB::Conn(&state.db),
                    &service.org_id,
                    provider,
                    encryption,
                )
                .await?;
                get_authorization_url_for_client(&custom_client, provider, requested_scopes.clone())
            } else {
                state.oauth_client.get_authorization_url_with_pkce(
                    provider,
                    requested_scopes.clone(),
                    Some(&callback_url),
                )?
            };
            (authorization_url, csrf_token, pkce_verifier, None)
        } else {
            let upstream = UpstreamProviderStore::find_by_connection_id(
                DB::Conn(&state.db),
                &service.org_id,
                &request.provider,
            )
            .await?
            .ok_or_else(|| AppError::NotFound("Upstream provider not found".to_string()))?;
            let client = build_upstream_oauth_client(state, &upstream).await?;
            let (authorization_url, csrf_token, pkce_verifier) =
                get_authorization_url_for_client(&client, Provider::Oidc, requested_scopes.clone());
            (
                authorization_url,
                csrf_token,
                pkce_verifier,
                Some(request.provider.clone()),
            )
        };

    let expires_at = (Utc::now() + chrono::Duration::minutes(10)).naive_utc();
    let pkce_value = if pkce_verifier.is_empty() {
        None
    } else {
        Some(pkce_verifier.as_str())
    };
    OAuthStateStore::create(
        DB::Conn(&state.db),
        csrf_token.secret(),
        pkce_value,
        Some(&service.id),
        Some(return_url.as_str()),
        Some(&org.slug),
        Some(&service.slug),
        false,
        Some(linking_user_id),
        None,
        None,
        upstream_connection_id.as_deref(),
        Some(&requested_scopes),
        None,
        Some(&request.state),
        None,
        &expires_at,
    )
    .await?;

    Ok(authorization_url)
}

pub async fn start_provider_token_request_reauth(
    State(state): State<AppState>,
    Path(request_state): Path<String>,
) -> Result<Redirect> {
    let request = ProviderTokenRequestStore::find_active(DB::Conn(&state.db), &request_state)
        .await?
        .ok_or_else(|| AppError::NotFound("Provider token request not found".to_string()))?;

    // The provider-token request state is a short-lived bearer capability created
    // only after service API-key, service/user boundary, and scope checks pass.
    ensure_user_belongs_to_service(&state, &request.user_id, &request.service_id).await?;

    let authorization_url =
        create_provider_token_request_oauth_state(&state, &request, &request.user_id).await?;

    Ok(Redirect::to(&authorization_url))
}

pub async fn start_provider_token_request_link(
    State(state): State<AppState>,
    Path(request_state): Path<String>,
    auth_user: AuthUser,
) -> Result<Json<crate::handlers::identities::StartLinkResponse>> {
    let request = ProviderTokenRequestStore::find_active_for_user(
        DB::Conn(&state.db),
        &request_state,
        &auth_user.user.id,
    )
    .await?
    .ok_or_else(|| AppError::NotFound("Provider token request not found".to_string()))?;
    ensure_user_belongs_to_service(&state, &auth_user.user.id, &request.service_id).await?;

    let authorization_url =
        create_provider_token_request_oauth_state(&state, &request, &auth_user.user.id).await?;

    Ok(Json(crate::handlers::identities::StartLinkResponse {
        authorization_url,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::crypto::jwt::JwtService;
    use crate::crypto::sso::OAuthClient;

    use crate::audit::actor::AuditHandle;
    use crate::db::DB;
    use crate::rsa_keys::GeneratedKey;
    use crate::services::{
        events::EventDispatcher, metrics::MfaMetricsService, risk_engine::RiskEngine,
    };
    use crate::state::AppState;
    use crate::store::{connected_accounts::ConnectedAccountStore, users::UserStore};
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

        let user = UserStore::create(DB::Conn(&db), "linked@example.test", None, false)
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
        let claims = jwt_service.validate_token(&token).expect("validate token");

        Fixture {
            state,
            auth_user: AuthUser {
                claims,
                user,
                permissions: vec![],
                ip_address: "127.0.0.1".to_string(),
                user_agent: "linked-accounts-test".to_string(),
                current_session_id: None,
            },
        }
    }

    async fn seed_account(
        f: &Fixture,
        provider: &str,
    ) -> crate::entities::connected_accounts::Model {
        ConnectedAccountStore::upsert_from_oauth_details(
            DB::Conn(&f.state.db),
            None,
            &f.auth_user.user.id,
            provider,
            &format!("{provider}-uid"),
            Some(&format!("{provider}@upstream.test")),
            Some(&format!("{provider} display")),
            "access-token",
            Some("refresh-token"),
            None,
            &["read".to_string()],
        )
        .await
        .expect("seed connected account")
    }

    #[tokio::test]
    async fn listing_starts_empty_and_shows_seeded_accounts_with_providers() {
        let f = fixture().await;

        let Json(empty) = list_linked_accounts(State(f.state.clone()), f.auth_user.clone())
            .await
            .expect("list empty");
        assert!(empty.accounts.is_empty());
        assert!(!empty.available_providers.is_empty());

        seed_account(&f, "github").await;

        let Json(list) = list_linked_accounts(State(f.state.clone()), f.auth_user.clone())
            .await
            .expect("list accounts");
        assert_eq!(list.accounts.len(), 1);
        assert_eq!(list.accounts[0].provider, "github");
        assert_eq!(list.accounts[0].scopes, vec!["read".to_string()]);
    }

    #[tokio::test]
    async fn upsert_refreshes_in_place_instead_of_duplicating() {
        let f = fixture().await;
        let first = seed_account(&f, "github").await;
        let second = seed_account(&f, "github").await;
        assert_eq!(first.id, second.id, "same upstream identity, same account");

        let Json(list) = list_linked_accounts(State(f.state.clone()), f.auth_user.clone())
            .await
            .expect("list");
        assert_eq!(list.accounts.len(), 1);
    }

    #[tokio::test]
    async fn revocation_is_ownership_scoped() {
        let f = fixture().await;
        let account = seed_account(&f, "google").await;

        // Someone else's revoke attempt on their own id space is a no-op miss.
        match revoke_linked_account(
            State(f.state.clone()),
            Path("not-my-account".to_string()),
            f.auth_user.clone(),
        )
        .await
        {
            Err(AppError::NotFound(_)) => {}
            other => panic!("expected not found for foreign account, got {other:?}"),
        }

        let status = revoke_linked_account(
            State(f.state.clone()),
            Path(account.id.clone()),
            f.auth_user.clone(),
        )
        .await
        .expect("revoke own account");
        assert_eq!(status, axum::http::StatusCode::NO_CONTENT);

        // Revoked accounts no longer appear in listings.
        let Json(list) = list_linked_accounts(State(f.state.clone()), f.auth_user.clone())
            .await
            .expect("list after revoke");
        assert!(list.accounts.is_empty());
    }
}
