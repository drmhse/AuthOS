use crate::constants::OAUTH_STATE_EXPIRE_MINUTES;
use crate::crypto::jwt::JwtService;
use crate::crypto::sso::{
    configured_basic_client, oauth_http_client, ConfiguredBasicClient, Provider,
};
use crate::db::models::{DeviceCode, Service, User};
use crate::db::transaction::with_retrying_transaction;
use crate::db::DB;
use crate::error::{AppError, Result};
use crate::middleware::RequestInfo;
use crate::state::AppState;
use crate::store::{
    connected_accounts::ConnectedAccountStore, device_codes::DeviceCodeStore,
    identities::IdentityStore, memberships::MembershipStore, oauth_states::OAuthStateStore,
    organizations::OrganizationStore, provider_token_requests::ProviderTokenRequestStore,
    service_provider_grants::ServiceProviderGrantStore, services::ServiceStore,
    sessions::SessionStore, upstream_providers::UpstreamProviderStore,
};
use crate::utils::resource_indicators::validate_requested_resource;
use crate::utils::scopes::{normalize_scope_list, parse_optional_scopes, parse_required_scopes};
use axum::{
    extract::{Extension, Path, Query, State},
    response::{Html, IntoResponse, Json, Redirect, Response},
};
use chrono::Utc;
use oauth2::url;
use oauth2::{CsrfToken, PkceCodeChallenge, PkceCodeVerifier};
use sea_orm::{
    ColumnTrait, Condition, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter, Set,
};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
struct OidcDiscoveryDocument {
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    userinfo_endpoint: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedUpstreamOidcConfig {
    pub authorization_url: String,
    pub token_url: String,
    pub userinfo_url: String,
}

async fn upsert_connected_account_from_oauth(
    state: &AppState,
    user_id: &str,
    provider_key: &str,
    user_info: &crate::crypto::sso::UserInfo,
    token_details: &crate::crypto::sso::TokenDetails,
    scopes: &[String],
) -> Result<crate::entities::connected_accounts::Model> {
    ConnectedAccountStore::upsert_from_oauth_details(
        DB::Conn(&state.db),
        state.encryption.as_ref(),
        user_id,
        provider_key,
        &user_info.provider_user_id,
        Some(&user_info.email),
        user_info.name.as_deref(),
        &token_details.access_token,
        token_details.refresh_token.as_deref(),
        token_details.expires_at,
        scopes,
    )
    .await
}

async fn grant_connected_account_to_service(
    state: &AppState,
    user_id: &str,
    service_id: &str,
    provider_key: &str,
    connected_account_id: &str,
    scopes: &[String],
) -> Result<()> {
    let service = ServiceStore::find_by_id(DB::Conn(&state.db), service_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;
    use crate::services::audit_builder::OrgAuditBuilder;
    use serde_json::json;
    let event = OrgAuditBuilder::new(&service.org_id, Some(user_id), "provider_account.linked")
        .target("connected_account", connected_account_id)
        .details_json(Some(json!({
            "service_id": service_id,
            "provider": provider_key,
            "scopes": scopes,
        })))
        .build();
    let service_org_id = service.org_id.clone();
    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "grant_connected_account_to_service_with_audit",
        |db| {
            let user_id = user_id.to_string();
            let service_id = service_id.to_string();
            let service_org_id = service_org_id.clone();
            let connected_account_id = connected_account_id.to_string();
            let provider_key = provider_key.to_string();
            let scopes = scopes.to_vec();
            let event = event.clone();
            let audit_actor = state.audit_actor.clone();
            Box::pin(async move {
                validate_live_oauth_tenant_context(
                    db.clone(),
                    Some(&service_org_id),
                    None,
                    Some(&service_id),
                    None,
                    None,
                    None,
                )
                .await?;
                validate_live_oauth_user_entitlement(
                    db.clone(),
                    &user_id,
                    &service_org_id,
                    Some(&service_id),
                )
                .await?;
                ServiceProviderGrantStore::upsert(
                    db.clone(),
                    &user_id,
                    &service_id,
                    &connected_account_id,
                    &provider_key,
                    &scopes,
                )
                .await?;
                audit_actor.log_org_with_db(db, event).await?;
                Ok(())
            })
        },
    )
    .await?;
    Ok(())
}

async fn resolve_upstream_provider_for_org(
    state: &AppState,
    org_id: &str,
    connection_id: &str,
) -> Result<crate::entities::upstream_providers::Model> {
    if let Some(provider) =
        UpstreamProviderStore::find_by_connection_id(DB::Conn(&state.db), org_id, connection_id)
            .await?
    {
        return Ok(provider);
    }

    UpstreamProviderStore::find_domain_routed_by_connection_id(
        DB::Conn(&state.db),
        org_id,
        connection_id,
    )
    .await?
    .ok_or_else(|| AppError::NotFound("Upstream provider not found".to_string()))
}

fn ensure_upstream_provider_enabled(
    provider: &crate::entities::upstream_providers::Model,
) -> Result<()> {
    if provider.enabled {
        Ok(())
    } else {
        Err(AppError::BadRequest(
            "Upstream provider is disabled".to_string(),
        ))
    }
}

/// Public clients (mobile/desktop) cannot securely store secrets
/// and rely on PKCE for security instead of client_secret.
/// This matches Keycloak's "Public Client" behavior.
fn is_public_client(service_type: &str) -> bool {
    matches!(service_type, "mobile" | "desktop")
}

pub(crate) fn is_supported_upstream_oauth_type(provider_type: &str) -> bool {
    matches!(provider_type, "oidc" | "oauth2")
}

fn parse_upstream_scopes(raw: &str) -> Vec<String> {
    parse_required_scopes(raw)
}

fn parse_stored_scopes(raw: &Option<String>) -> Vec<String> {
    parse_optional_scopes(raw)
}

fn parse_required_scopes_json(raw: &str) -> Vec<String> {
    parse_required_scopes(raw)
}

fn has_all_scopes(available: &[String], requested: &[String]) -> bool {
    requested.iter().all(|scope| {
        available
            .iter()
            .any(|available_scope| available_scope == scope)
    })
}

fn normalized_granted_scopes(
    provider: Provider,
    requested_scopes: &[String],
    returned_scopes: &[String],
    refresh_token: Option<&str>,
) -> Vec<String> {
    let mut scopes = if returned_scopes.is_empty() {
        normalize_scope_list(requested_scopes)
    } else {
        normalize_scope_list(returned_scopes)
    };

    if provider == Provider::Microsoft
        && refresh_token.is_some()
        && requested_scopes
            .iter()
            .any(|scope| scope.eq_ignore_ascii_case("offline_access"))
        && !scopes
            .iter()
            .any(|scope| scope.eq_ignore_ascii_case("offline_access"))
    {
        scopes.push("offline_access".to_string());
    }

    scopes
}

fn provider_token_redirect_url(
    request: &crate::entities::provider_token_requests::Model,
) -> Result<String> {
    let mut redirect = url::Url::parse(&request.redirect_uri)
        .map_err(|_| AppError::BadRequest("Invalid stored redirect_uri".to_string()))?;
    {
        let mut pairs = redirect.query_pairs_mut();
        pairs
            .append_pair("provider_grant", "success")
            .append_pair("provider", &request.provider);
        if let Some(client_state) = request.client_state.as_deref() {
            pairs.append_pair("state", client_state);
        }
    }
    Ok(redirect.to_string())
}

fn validate_service_device_oauth_context(
    device_org_slug: &str,
    device_service_slug: &str,
    oauth_org_slug: &str,
    oauth_service_slug: &str,
) -> Result<()> {
    if device_org_slug != oauth_org_slug || device_service_slug != oauth_service_slug {
        return Err(AppError::BadRequest(
            "Device authorization context is invalid or expired".to_string(),
        ));
    }
    Ok(())
}

fn validate_platform_device_oauth_context(
    device_org_slug: &str,
    device_service_slug: &str,
    oauth_org_slug: Option<&str>,
    is_current_platform_owner: bool,
) -> Result<()> {
    if device_org_slug != "platform"
        || device_service_slug != "admin-cli"
        || oauth_org_slug != Some("platform")
        || !is_current_platform_owner
    {
        return Err(AppError::Forbidden(
            "Platform device authorization requires a current platform owner".to_string(),
        ));
    }
    Ok(())
}

async fn complete_provider_token_request_from_oauth(
    state: &AppState,
    request_state: &str,
    user_id: &str,
    provider_key: &str,
    connected_account_id: &str,
    account_scopes: &[String],
) -> Result<String> {
    let request = ProviderTokenRequestStore::find_active_for_user(
        DB::Conn(&state.db),
        request_state,
        user_id,
    )
    .await?
    .ok_or_else(|| AppError::NotFound("Provider token request not found".to_string()))?;

    if request.provider != provider_key {
        return Err(AppError::BadRequest(
            "PROVIDER_ACCOUNT_CONFLICT".to_string(),
        ));
    }
    if let Some(expected_account_id) = request.connected_account_id.as_deref() {
        if expected_account_id != connected_account_id {
            return Err(AppError::BadRequest(
                "PROVIDER_ACCOUNT_CONFLICT".to_string(),
            ));
        }
    }

    let requested_scopes = parse_required_scopes_json(&request.requested_scopes);
    if !has_all_scopes(account_scopes, &requested_scopes) {
        return Err(AppError::BadRequest(
            "PROVIDER_SCOPE_CONSENT_REQUIRED".to_string(),
        ));
    }

    let service = ServiceStore::find_by_id(DB::Conn(&state.db), &request.service_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;
    // Validate the stored redirect before consuming the one-time request.
    let redirect_url = provider_token_redirect_url(&request)?;

    use crate::services::audit_builder::OrgAuditBuilder;
    use serde_json::json;

    let grant_event =
        OrgAuditBuilder::new(&service.org_id, Some(user_id), "provider_grant.created")
            .target("connected_account", connected_account_id)
            .details_json(Some(json!({
                "service_id": &request.service_id,
                "provider": provider_key,
                "scopes": &requested_scopes,
                "provider_token_request": &request.state,
            })))
            .build();

    let completed_event = OrgAuditBuilder::new(
        &service.org_id,
        Some(user_id),
        "provider_token_request.completed",
    )
    .target("provider_token_request", &request.state)
    .details_json(Some(json!({
        "service_id": &request.service_id,
        "provider": provider_key,
        "connected_account_id": connected_account_id,
    })))
    .build();

    let request_state = request.state.clone();
    let service_id = request.service_id.clone();
    let user_id = user_id.to_string();
    let provider_key = provider_key.to_string();
    let connected_account_id = connected_account_id.to_string();
    let service_org_id = service.org_id.clone();
    let audit_actor = state.audit_actor.clone();
    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "complete_provider_token_request_from_oauth",
        |db| {
            let request_state = request_state.clone();
            let service_id = service_id.clone();
            let service_org_id = service_org_id.clone();
            let user_id = user_id.clone();
            let provider_key = provider_key.clone();
            let connected_account_id = connected_account_id.clone();
            let requested_scopes = requested_scopes.clone();
            let audit_actor = audit_actor.clone();
            let grant_event = grant_event.clone();
            let completed_event = completed_event.clone();
            Box::pin(async move {
                validate_live_oauth_tenant_context(
                    db.clone(),
                    Some(&service_org_id),
                    None,
                    Some(&service_id),
                    None,
                    None,
                    None,
                )
                .await?;
                validate_live_oauth_user_entitlement(
                    db.clone(),
                    &user_id,
                    &service_org_id,
                    Some(&service_id),
                )
                .await?;
                ProviderTokenRequestStore::complete_with_grant_and_audits_in_transaction(
                    db,
                    &audit_actor,
                    &request_state,
                    &user_id,
                    &service_id,
                    &connected_account_id,
                    &provider_key,
                    &requested_scopes,
                    vec![grant_event, completed_event],
                )
                .await
            })
        },
    )
    .await?;

    Ok(redirect_url)
}

async fn is_safe_orphan_provider_duplicate(
    db: DB<'_>,
    duplicate_user_id: &str,
    target_org_id: Option<&str>,
    target_service_id: Option<&str>,
    provider: &str,
    provider_user_id: &str,
) -> Result<bool> {
    use crate::entities::prelude::{
        ConnectedAccounts, Identities, Memberships, ServiceProviderGrants, UserPasskeys,
        UserTotpSecrets, Users,
    };
    use crate::entities::{
        connected_accounts, identities, memberships, service_provider_grants, user_passkeys,
        user_totp_secrets, users,
    };

    let Some(user) = Users::find()
        .filter(users::Column::Id.eq(duplicate_user_id))
        .one(&db)
        .await?
    else {
        return Ok(false);
    };
    if user.deleted_at.is_some()
        || user.is_platform_owner
        || user.password_hash.is_some()
        || user.email_verified_at.is_some()
    {
        return Ok(false);
    }
    if let Some(org_id) = target_org_id {
        if user.org_id.as_deref() != Some(org_id) {
            return Ok(false);
        }
    }

    let non_matching_identity_count = Identities::find()
        .filter(identities::Column::UserId.eq(duplicate_user_id))
        .filter(
            Condition::any()
                .add(identities::Column::Provider.ne(provider))
                .add(identities::Column::ProviderUserId.ne(provider_user_id)),
        )
        .count(&db)
        .await?;
    if non_matching_identity_count != 0 {
        return Ok(false);
    }

    if let Some(service_id) = target_service_id {
        let context_matches = Identities::find()
            .filter(identities::Column::UserId.eq(duplicate_user_id))
            .filter(identities::Column::Provider.eq(provider))
            .filter(identities::Column::ProviderUserId.eq(provider_user_id))
            .filter(identities::Column::IssuingServiceId.eq(service_id))
            .count(&db)
            .await?
            > 0;
        if !context_matches {
            return Ok(false);
        }
    }

    let membership_count = Memberships::find()
        .filter(memberships::Column::UserId.eq(duplicate_user_id))
        .count(&db)
        .await?;
    let passkey_count = UserPasskeys::find()
        .filter(user_passkeys::Column::UserId.eq(duplicate_user_id))
        .count(&db)
        .await?;
    let totp_count = UserTotpSecrets::find()
        .filter(user_totp_secrets::Column::UserId.eq(duplicate_user_id))
        .count(&db)
        .await?;
    let grant_count = ServiceProviderGrants::find()
        .filter(service_provider_grants::Column::UserId.eq(duplicate_user_id))
        .count(&db)
        .await?;
    let non_matching_account_count = ConnectedAccounts::find()
        .filter(connected_accounts::Column::UserId.eq(duplicate_user_id))
        .filter(
            Condition::any()
                .add(connected_accounts::Column::Provider.ne(provider))
                .add(connected_accounts::Column::ProviderUserId.ne(provider_user_id)),
        )
        .count(&db)
        .await?;

    Ok(membership_count == 0
        && passkey_count == 0
        && totp_count == 0
        && grant_count == 0
        && non_matching_account_count == 0)
}

async fn transfer_orphan_provider_duplicate(
    state: &AppState,
    duplicate_user_id: &str,
    target_user_id: &str,
    target_org_id: Option<&str>,
    target_service_id: Option<&str>,
    provider: &str,
    provider_user_id: &str,
) -> Result<bool> {
    use crate::entities::prelude::{ConnectedAccounts, Identities};
    use crate::entities::{connected_accounts, identities};

    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "transfer_orphan_provider_duplicate_with_audit",
        |db| {
            let duplicate_user_id = duplicate_user_id.to_string();
            let target_user_id = target_user_id.to_string();
            let target_org_id = target_org_id.map(str::to_string);
            let target_service_id = target_service_id.map(str::to_string);
            let provider = provider.to_string();
            let provider_user_id = provider_user_id.to_string();
            let audit_actor = state.audit_actor.clone();
            Box::pin(async move {
                if !is_safe_orphan_provider_duplicate(
                    db.clone(),
                    &duplicate_user_id,
                    target_org_id.as_deref(),
                    target_service_id.as_deref(),
                    &provider,
                    &provider_user_id,
                )
                .await?
                {
                    return Ok(false);
                }

                Identities::update_many()
                    .set(identities::ActiveModel {
                        user_id: Set(target_user_id.clone()),
                        ..Default::default()
                    })
                    .filter(identities::Column::UserId.eq(duplicate_user_id.clone()))
                    .filter(identities::Column::Provider.eq(provider.clone()))
                    .filter(identities::Column::ProviderUserId.eq(provider_user_id.clone()))
                    .exec(&db)
                    .await?;

                ConnectedAccounts::update_many()
                    .set(connected_accounts::ActiveModel {
                        user_id: Set(target_user_id.clone()),
                        updated_at: Set(chrono::Utc::now().naive_utc()),
                        ..Default::default()
                    })
                    .filter(connected_accounts::Column::UserId.eq(duplicate_user_id.clone()))
                    .filter(connected_accounts::Column::Provider.eq(provider.clone()))
                    .filter(connected_accounts::Column::ProviderUserId.eq(provider_user_id.clone()))
                    .exec(&db)
                    .await?;

                if let Some(org_id) = target_org_id {
                    use crate::services::audit_builder::OrgAuditBuilder;
                    use serde_json::json;

                    let event = OrgAuditBuilder::new(
                        &org_id,
                        Some(&target_user_id),
                        "provider_account.transferred",
                    )
                    .target("user", &duplicate_user_id)
                    .details_json(Some(json!({
                        "provider": provider,
                        "provider_user_id": provider_user_id,
                        "from_user_id": duplicate_user_id,
                        "to_user_id": target_user_id,
                        "service_id": target_service_id,
                    })))
                    .build();
                    audit_actor.log_org_with_db(db, event).await?;
                }

                Ok(true)
            })
        },
    )
    .await
}

async fn ensure_provider_account_can_link(
    state: &AppState,
    target_user_id: &str,
    target_org_id: Option<&str>,
    target_service_id: Option<&str>,
    provider: &str,
    provider_user_id: &str,
) -> Result<()> {
    let existing_identities = IdentityStore::list_any_by_provider_and_provider_user_id(
        DB::Conn(&state.db),
        provider,
        provider_user_id,
    )
    .await?;
    if existing_identities.is_empty() {
        return Ok(());
    }
    if existing_identities
        .iter()
        .any(|identity| identity.user_id == target_user_id)
    {
        return Ok(());
    }

    for existing in &existing_identities {
        if transfer_orphan_provider_duplicate(
            state,
            &existing.user_id,
            target_user_id,
            target_org_id,
            target_service_id,
            provider,
            provider_user_id,
        )
        .await?
        {
            return Ok(());
        }
    }

    let existing = &existing_identities[0];

    if let Some(org_id) = target_org_id {
        use crate::services::audit_builder::OrgAuditBuilder;
        use serde_json::json;

        let event = OrgAuditBuilder::new(org_id, Some(target_user_id), "provider_account.conflict")
            .target("user", &existing.user_id)
            .details_json(Some(json!({
                "provider": provider,
                "provider_user_id": provider_user_id,
                "existing_user_id": existing.user_id,
                "target_user_id": target_user_id,
                "service_id": target_service_id,
            })))
            .build();
        state.audit_actor.log_org(event).await?;
    }

    Err(AppError::BadRequest(
        "PROVIDER_ACCOUNT_CONFLICT".to_string(),
    ))
}

async fn ensure_provider_token_request_matches_provider_user(
    state: &AppState,
    request_state: Option<&str>,
    target_user_id: &str,
    target_service_id: &str,
    provider: &str,
    provider_email: &str,
) -> Result<()> {
    let Some(request_state) = request_state else {
        return Ok(());
    };

    let request = ProviderTokenRequestStore::find_active_for_user(
        DB::Conn(&state.db),
        request_state,
        target_user_id,
    )
    .await?
    .ok_or_else(|| AppError::NotFound("Provider token request not found".to_string()))?;

    if request.service_id != target_service_id || request.provider != provider {
        return Err(AppError::BadRequest(
            "Provider token request context mismatch".to_string(),
        ));
    }

    let has_authenticated = IdentityStore::user_has_authenticated_with_service(
        DB::Conn(&state.db),
        target_user_id,
        target_service_id,
    )
    .await?;
    if !has_authenticated {
        return Err(AppError::BadRequest(
            "Provider token request is no longer valid for this service user".to_string(),
        ));
    }

    let target_user =
        crate::store::users::UserStore::find_by_id(DB::Conn(&state.db), target_user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let service = ServiceStore::find_by_id(DB::Conn(&state.db), target_service_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;
    if target_user.org_id.as_deref() != Some(service.org_id.as_str()) {
        return Err(AppError::BadRequest(
            "Provider token request is no longer valid for this service user".to_string(),
        ));
    }

    if !target_user
        .email
        .trim()
        .eq_ignore_ascii_case(provider_email.trim())
    {
        return Err(AppError::BadRequest(
            "Provider account email does not match the requested user".to_string(),
        ));
    }

    Ok(())
}

pub(crate) async fn resolve_upstream_oidc_config(
    provider_model: &crate::entities::upstream_providers::Model,
) -> Result<ResolvedUpstreamOidcConfig> {
    let mut authorization_url = provider_model.authorization_url.clone();
    let mut token_url = provider_model.token_url.clone();
    let mut userinfo_url = provider_model.userinfo_url.clone();

    if authorization_url.is_none() || token_url.is_none() || userinfo_url.is_none() {
        let discovery_url = provider_model.discovery_url.as_ref().ok_or_else(|| {
            AppError::BadRequest(
                "OIDC provider requires discovery_url or explicit authorization_url, token_url, and userinfo_url".to_string(),
            )
        })?;

        let discovery_doc = crate::crypto::safe_http::SafeHttpClient::new()?
            .get(discovery_url)
            .await
            .map_err(|e| {
                AppError::InternalServerError(format!(
                    "Failed to fetch OIDC discovery document: {}",
                    e
                ))
            })?
            .error_for_status()
            .map_err(|e| {
                AppError::BadRequest(format!("OIDC discovery endpoint returned an error: {}", e))
            })?
            .json::<OidcDiscoveryDocument>()
            .await
            .map_err(|e| {
                AppError::InternalServerError(format!(
                    "Failed to parse OIDC discovery document: {}",
                    e
                ))
            })?;

        if authorization_url.is_none() {
            authorization_url = discovery_doc.authorization_endpoint;
        }
        if token_url.is_none() {
            token_url = discovery_doc.token_endpoint;
        }
        if userinfo_url.is_none() {
            userinfo_url = discovery_doc.userinfo_endpoint;
        }
    }

    let safe_client = crate::crypto::safe_http::SafeHttpClient::new()?;
    for (field, url) in [
        ("authorization_url", authorization_url.as_deref()),
        ("token_url", token_url.as_deref()),
        ("userinfo_url", userinfo_url.as_deref()),
    ] {
        let url = url
            .ok_or_else(|| AppError::BadRequest(format!("Missing {} for OIDC provider", field)))?;
        safe_client.validate_external_url(url).await?;
    }

    Ok(ResolvedUpstreamOidcConfig {
        authorization_url: authorization_url.ok_or_else(|| {
            AppError::BadRequest("Missing authorization_url for OIDC provider".to_string())
        })?,
        token_url: token_url.ok_or_else(|| {
            AppError::BadRequest("Missing token_url for OIDC provider".to_string())
        })?,
        userinfo_url: userinfo_url.ok_or_else(|| {
            AppError::BadRequest("Missing userinfo_url for OIDC provider".to_string())
        })?,
    })
}

// SSO Authorization Request
#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    pub org: String,
    pub service: String,
    pub redirect_uri: Option<String>,
    pub state: Option<String>,
    pub resource: Option<String>,
    pub user_code: Option<String>,
    pub saml_state: Option<String>,
    pub connection_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AdminAuthRequest {
    pub org_slug: Option<String>,
    pub user_code: Option<String>,
    pub return_to: Option<String>,
}

// SSO Callback Query Parameters
#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
    pub format: Option<String>, // If set to "json", return JSON instead of redirect
}

impl CallbackQuery {
    fn state_parameter(&self) -> Result<&str> {
        self.state
            .as_deref()
            .filter(|state| !state.is_empty())
            .ok_or_else(|| AppError::BadRequest("Missing state parameter".to_string()))
    }

    fn authorization_code(&self) -> Result<&str> {
        self.code.as_deref().ok_or_else(|| {
            AppError::BadRequest("OAuth callback did not include an authorization code".to_string())
        })
    }

    fn oauth_error(&self) -> Option<(&str, Option<&str>)> {
        self.error
            .as_deref()
            .map(|error| (error, self.error_description.as_deref()))
    }
}

/// SSO: Initiate OAuth flow
pub async fn auth_provider(
    State(state): State<AppState>,
    Path(provider_str): Path<String>,
    Query(params): Query<AuthRequest>,
) -> Result<Response> {
    let provider = Provider::from_str(&provider_str)?;

    // Get service to fetch configured scopes and validate redirect_uri
    // Get organization first, then service
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &params.org)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    let service_entity =
        ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &organization.id, &params.service)
            .await?
            .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;

    // Convert entity to db model
    let service = crate::db::models::Service {
        id: service_entity.id,
        org_id: service_entity.org_id,
        slug: service_entity.slug,
        name: service_entity.name,
        service_type: service_entity.service_type,
        client_id: service_entity.client_id,
        client_secret_hash: service_entity.client_secret_hash,
        github_scopes: service_entity.github_scopes,
        microsoft_scopes: service_entity.microsoft_scopes,
        google_scopes: service_entity.google_scopes,
        redirect_uris: service_entity.redirect_uris,
        device_activation_uri: service_entity.device_activation_uri,
        resource_uris: service_entity.resource_uris,
        saml_enabled: service_entity.saml_enabled,
        saml_entity_id: service_entity.saml_entity_id,
        saml_acs_url: service_entity.saml_acs_url,
        saml_slo_url: service_entity.saml_slo_url,
        saml_name_id_format: service_entity.saml_name_id_format,
        saml_attribute_mapping: service_entity.saml_attribute_mapping,
        saml_sign_assertions: service_entity.saml_sign_assertions,
        saml_sign_response: service_entity.saml_sign_response,
        created_at: chrono::DateTime::from_naive_utc_and_offset(service_entity.created_at, Utc),
    };

    let requested_resource =
        validate_requested_resource(params.resource.as_deref(), service.resource_uris.as_deref())?;

    // Validate redirect_uri against allowed URIs
    if let Some(redirect_uri) = &params.redirect_uri {
        validate_redirect_uri(redirect_uri, &service)?;
    }

    let scopes = get_provider_scopes(&service, provider);

    // Check if organization has custom OAuth credentials for this provider
    let org_id = &organization.id;
    let provider_str = provider.as_str();

    // Determine authorization URL and state based on whether it's an upstream connection or regular OAuth
    let (auth_url, csrf_token, pkce_verifier, upstream_conn_id) = if let Some(conn_id) =
        &params.connection_id
    {
        // Upstream Enterprise SSO (HRD) flow
        let provider_model =
            resolve_upstream_provider_for_org(&state, &organization.id, conn_id).await?;

        ensure_upstream_provider_enabled(&provider_model)?;

        if provider_model.provider_type == "saml" {
            // Upstream SAML SP flow
            let sp_entity_id = provider_model.client_id.clone();
            let idp_sso_url = provider_model.authorization_url.clone().ok_or_else(|| {
                AppError::BadRequest("Missing authorization_url (IdP SSO URL)".to_string())
            })?;
            let acs_url = format!("{}/auth/saml/callback", state.base_url);

            let (saml_request, _request_id) = super::upstream_saml::generate_authn_request(
                &sp_entity_id,
                &idp_sso_url,
                &acs_url,
            )?;

            let csrf_token = CsrfToken::new_random();
            let encoded_saml =
                url::form_urlencoded::byte_serialize(saml_request.as_bytes()).collect::<String>();
            let encoded_state =
                url::form_urlencoded::byte_serialize(csrf_token.secret().as_bytes())
                    .collect::<String>();

            let saml_url = format!(
                "{}?SAMLRequest={}&RelayState={}",
                idp_sso_url, encoded_saml, encoded_state
            );

            (saml_url, csrf_token, None, Some(conn_id.clone()))
        } else if is_supported_upstream_oauth_type(&provider_model.provider_type) {
            let oidc_config = resolve_upstream_oidc_config(&provider_model).await?;
            let encryption = state.encryption.as_ref().ok_or_else(|| {
                AppError::InternalServerError("Encryption unavailable".to_string())
            })?;
            let secret = encryption
                .decrypt_with_context(
                    &provider_model.client_secret_encrypted,
                    crate::encryption::EncryptionContext::new(
                        "upstream_providers",
                        &provider_model.id,
                        "client_secret_encrypted",
                    ),
                )
                .map_err(|e| {
                    AppError::InternalServerError(format!("Failed to decrypt secret: {}", e))
                })?;

            // Create OIDC client for this upstream provider
            let client = configured_basic_client(
                provider_model.client_id.clone(),
                secret,
                oidc_config.authorization_url,
                oidc_config.token_url,
                format!("{}/auth/oidc/callback", state.base_url),
            )?;

            let upstream_scopes: Vec<String> = provider_model.scopes.as_ref().map_or_else(
                || {
                    vec![
                        "openid".to_string(),
                        "email".to_string(),
                        "profile".to_string(),
                    ]
                },
                |s| parse_upstream_scopes(s),
            );

            let (url, csrf, verifier) =
                get_authorization_url_for_client(&client, Provider::Oidc, upstream_scopes);
            (url, csrf, Some(verifier), Some(conn_id.clone()))
        } else {
            return Err(AppError::BadRequest(format!(
                "Unsupported upstream provider type: {}",
                provider_model.provider_type
            )));
        }
    } else {
        // Regular OAuth flow (Platform or BYOO)
        let org_credentials =
            OrganizationStore::get_oauth_credentials(DB::Conn(&state.db), org_id, provider_str)
                .await?;

        let (url, csrf, verifier) = if let Some(_creds) = org_credentials {
            // Use organization's custom OAuth credentials (BYOO)
            let encryption = crate::encryption::EncryptionService::new().map_err(|e| {
                AppError::InternalServerError(format!("Encryption unavailable: {}", e))
            })?;

            let custom_client =
                crate::store::organizations::OrganizationStore::get_oauth_client_for_org(
                    DB::Conn(&state.db),
                    org_id,
                    provider,
                    &encryption,
                )
                .await?;
            get_authorization_url_for_client(&custom_client, provider, scopes.clone())
        } else {
            // Uses the ADMIN callback URL: GitHub and Microsoft allow only one
            // registered callback per app, so that route detects service context
            // from service_id and re-routes.
            let callback_url = format!("{}/auth/admin/{}/callback", state.base_url, provider_str);

            state.oauth_client.get_authorization_url_with_pkce(
                provider,
                scopes.clone(),
                Some(&callback_url),
            )?
        };
        (url, csrf, Some(verifier), None)
    };

    let expires_at = Utc::now() + chrono::Duration::minutes(OAUTH_STATE_EXPIRE_MINUTES);
    let pkce_value = pkce_verifier
        .as_deref()
        .filter(|verifier| !verifier.is_empty());

    OAuthStateStore::create(
        DB::Conn(&state.db),
        csrf_token.secret(),
        pkce_value,
        Some(&service.id),
        params.redirect_uri.as_deref(),
        Some(&params.org),
        Some(&params.service),
        false, // is_admin_flow
        None,  // user_id_for_linking
        params.user_code.as_deref(),
        params.saml_state.as_deref(),
        upstream_conn_id.as_deref(),
        Some(&scopes),
        params.state.as_deref(),
        None,
        requested_resource.as_deref(),
        &expires_at.naive_utc(),
    )
    .await?;

    Ok(Redirect::to(&auth_url).into_response())
}

pub fn get_provider_scopes(
    service: &crate::db::models::Service,
    provider: Provider,
) -> Vec<String> {
    let scopes_json = match provider {
        Provider::Github => &service.github_scopes,
        Provider::Microsoft => &service.microsoft_scopes,
        Provider::Google => &service.google_scopes,
        Provider::Oidc => &None,
        Provider::Password => &None,
    };

    scopes_json
        .as_ref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_else(|| default_scopes_for_provider(provider))
}

fn default_scopes_for_provider(provider: Provider) -> Vec<String> {
    match provider {
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
    }
}

#[derive(Debug, Deserialize)]
pub struct SamlCallbackPayload {
    #[serde(rename = "SAMLResponse")]
    pub saml_response: String,
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

/// SSO: Handle SAML callback from upstream IdP
pub async fn auth_saml_callback(
    State(state): State<AppState>,
    Extension(_request_info): Extension<RequestInfo>,
    axum::extract::Form(payload): axum::extract::Form<SamlCallbackPayload>,
) -> Result<Response> {
    let state_param = payload.relay_state.as_ref().ok_or_else(|| {
        AppError::BadRequest("Missing RelayState (state) in SAML callback".to_string())
    })?;

    let oauth_state = OAuthStateStore::find_by_state(DB::Conn(&state.db), state_param)
        .await?
        .ok_or_else(|| AppError::BadRequest("Invalid or expired state parameter".to_string()))?;

    // Atomically consume state. A concurrent callback that loaded the same
    // row must lose here and cannot continue processing the assertion.
    OAuthStateStore::delete(DB::Conn(&state.db), state_param)
        .await
        .map_err(|_| AppError::BadRequest("Invalid or expired state parameter".to_string()))?;

    let conn_id = oauth_state.upstream_connection_id.as_ref().ok_or_else(|| {
        AppError::InternalServerError("Missing connection context in state".to_string())
    })?;

    let organization = OrganizationStore::find_by_slug(
        DB::Conn(&state.db),
        oauth_state.org_slug.as_ref().ok_or_else(|| {
            AppError::InternalServerError("Missing org context in state".to_string())
        })?,
    )
    .await?
    .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    let provider = resolve_upstream_provider_for_org(&state, &organization.id, conn_id).await?;

    let provider_model_struct: crate::db::models::UpstreamProvider = provider.into();
    let _saml_user = super::upstream_saml::process_saml_response(
        &state,
        &payload.saml_response,
        &provider_model_struct,
    )
    .await?;

    // Unreachable: process_saml_response fails closed until upstream assertion
    // signature verification exists. Session issuance stays absent rather than
    // stubbed so no relying party can mistake a placeholder for a real login.
    Err(AppError::ServiceUnavailable(
        "Upstream SAML login is not available".to_string(),
    ))
}

/// SSO: Handle OAuth callback
pub async fn auth_callback(
    State(state): State<AppState>,
    Extension(request_info): Extension<RequestInfo>,
    Path(provider_str): Path<String>,
    Query(callback): Query<CallbackQuery>,
) -> Result<Response> {
    // Wrap the main logic to catch errors and handle them appropriately
    match auth_callback_impl(state, request_info, provider_str, callback).await {
        Ok(response) => Ok(response),
        Err(e) => {
            // Log the error
            tracing::error!("OAuth callback error: {}", e);

            // Return a simple HTML error page
            let error_message = match &e {
                AppError::OAuth(msg) => msg.clone(),
                AppError::BadRequest(msg) => msg.clone(),
                AppError::Unauthorized(msg) => msg.clone(),
                _ => "Authentication failed".to_string(),
            };

            // Simple HTML escaping for error message
            let escaped_error = error_message
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;")
                .replace('\'', "&#x27;");

            let html = format!(
                r#"
                <!DOCTYPE html>
                <html>
                <head><title>Authentication Failed</title></head>
                <body>
                    <h1>Authentication Failed</h1>
                    <p>Error: {}</p>
                    <p>Please try again or contact support.</p>
                </body>
                </html>
                "#,
                escaped_error
            );

            Ok((axum::http::StatusCode::BAD_REQUEST, Html(html)).into_response())
        }
    }
}

/// Internal implementation of OAuth callback that can return errors
async fn auth_callback_impl(
    state: AppState,
    request_info: RequestInfo,
    provider_str: String,
    callback: CallbackQuery,
) -> Result<Response> {
    let provider = Provider::from_str(&provider_str)?;

    // Load config (needed for user info fetching later)
    let config = crate::config::Config::from_env().map_err(AppError::InternalServerError)?;

    // OAuth callbacks are never accepted without the state issued at the start
    // of the flow. Preserve the optional wrapper below for the existing flow
    // context plumbing after requiring a concrete state here.
    let state_param = callback.state_parameter()?;
    let oauth_state: Option<crate::db::models::OAuthState> =
        OAuthStateStore::find_by_state(DB::Conn(&state.db), state_param)
            .await?
            .map(Into::into);

    // Clean up OAuth state immediately to prevent replay attacks
    // We extract all needed info first, then delete the state before token exchange
    OAuthStateStore::delete(DB::Conn(&state.db), state_param)
        .await
        .map_err(|_| AppError::BadRequest("Invalid or expired state parameter".to_string()))?;

    // Validate that we have a valid OAuth state (required for SSO flows)
    // If state was provided but not found (expired or invalid), reject the request
    if callback.state.is_some() && oauth_state.is_none() {
        return Err(AppError::BadRequest(
            "Invalid or expired state parameter".to_string(),
        ));
    }

    if let Some((error, description)) = callback.oauth_error() {
        if let Some(ref oauth_ctx) = oauth_state {
            if let Some(ref redirect_uri) = oauth_ctx.redirect_uri {
                return redirect_oauth_error_to_uri(redirect_uri, error, description);
            }
        }

        return Err(AppError::OAuth(description.unwrap_or(error).to_string()));
    }

    let callback_code = callback.authorization_code()?.to_string();

    // Exchange code with PKCE verifier to get full token details
    // Check if we should use organization's BYOO credentials
    let pkce_verifier = oauth_state
        .as_ref()
        .and_then(|s| s.pkce_verifier.as_deref())
        .filter(|verifier| !verifier.is_empty());

    // Determine issuing context (org_id and service_id) for proper identity isolation
    let (token_details, issuing_org_id, issuing_service_id) = if let Some(ref oauth_ctx) =
        oauth_state
    {
        if let Some(ref conn_id) = oauth_ctx.upstream_connection_id {
            // Upstream Enterprise SSO flow
            let organization = OrganizationStore::find_by_slug(
                DB::Conn(&state.db),
                oauth_ctx.org_slug.as_ref().ok_or_else(|| {
                    AppError::InternalServerError("Missing org_slug in OAuth state".to_string())
                })?,
            )
            .await?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

            let provider_model =
                resolve_upstream_provider_for_org(&state, &organization.id, conn_id).await?;

            ensure_upstream_provider_enabled(&provider_model)?;

            let oidc_config = resolve_upstream_oidc_config(&provider_model).await?;
            let encryption = state.encryption.as_ref().ok_or_else(|| {
                AppError::InternalServerError("Encryption unavailable".to_string())
            })?;
            let secret = encryption
                .decrypt_with_context(
                    &provider_model.client_secret_encrypted,
                    crate::encryption::EncryptionContext::new(
                        "upstream_providers",
                        &provider_model.id,
                        "client_secret_encrypted",
                    ),
                )
                .map_err(|e| {
                    AppError::InternalServerError(format!("Failed to decrypt secret: {}", e))
                })?;

            let client = configured_basic_client(
                provider_model.client_id.clone(),
                secret,
                oidc_config.authorization_url,
                oidc_config.token_url,
                format!("{}/auth/oidc/callback", state.base_url),
            )?;

            let details =
                exchange_custom_code(&client, Provider::Oidc, &callback_code, pkce_verifier)
                    .await?;

            (details, Some(organization.id), oauth_ctx.service_id.clone())
        } else if let Some(ref service_id) = oauth_ctx.service_id {
            // Service flow - get org_id from service and use service credentials
            let service: crate::db::models::Service =
                ServiceStore::find_by_id(DB::Conn(&state.db), service_id)
                    .await?
                    .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?
                    .into();

            // Security: Enforce PKCE for public clients (mobile/desktop)
            // These clients cannot securely store client_secret, so PKCE is mandatory
            if is_public_client(&service.service_type) && pkce_verifier.is_none() {
                return Err(AppError::BadRequest(
                        "PKCE is required for public clients (mobile/desktop). Include code_verifier in your authorization request.".to_string()
                    ));
            }

            let org_id = service.org_id.clone();

            // Check for BYOO credentials for this organization
            let provider_str = provider.as_str();

            let org_credentials = OrganizationStore::get_oauth_credentials(
                DB::Conn(&state.db),
                &org_id,
                provider_str,
            )
            .await?;

            let details = if let Some(_creds) = org_credentials {
                // Use organization's custom OAuth credentials for token exchange
                let encryption = crate::encryption::EncryptionService::new().map_err(|e| {
                    AppError::InternalServerError(format!("Encryption unavailable: {}", e))
                })?;

                let custom_client =
                    crate::store::organizations::OrganizationStore::get_oauth_client_for_org(
                        DB::Conn(&state.db),
                        &org_id,
                        provider,
                        &encryption,
                    )
                    .await?;

                exchange_custom_code(&custom_client, provider, &callback_code, pkce_verifier)
                    .await?
            } else {
                // Fall back to platform credentials for this service
                state
                    .oauth_client
                    .exchange_code_with_details(provider, &callback_code, pkce_verifier)
                    .await?
            };

            (details, Some(org_id), Some(service_id.clone()))
        } else if let Some(ref org_slug) = oauth_ctx.org_slug {
            // Legacy org-based flow (no service_id) - use org credentials but no service isolation
            let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), org_slug)
                .await?
                .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

            let org_id = org.id.clone();
            let provider_str = provider.as_str();

            let org_credentials = OrganizationStore::get_oauth_credentials(
                DB::Conn(&state.db),
                &org_id,
                provider_str,
            )
            .await?;

            let details = if let Some(_creds) = org_credentials {
                // Use organization's custom OAuth credentials for token exchange
                let encryption = crate::encryption::EncryptionService::new().map_err(|e| {
                    AppError::InternalServerError(format!("Encryption unavailable: {}", e))
                })?;

                let custom_client =
                    crate::store::organizations::OrganizationStore::get_oauth_client_for_org(
                        DB::Conn(&state.db),
                        &org_id,
                        provider,
                        &encryption,
                    )
                    .await?;

                exchange_custom_code(&custom_client, provider, &callback_code, pkce_verifier)
                    .await?
            } else {
                // Fall back to platform credentials
                state
                    .oauth_client
                    .exchange_code_with_details(provider, &callback_code, pkce_verifier)
                    .await?
            };

            (details, Some(org_id), None)
        } else {
            // No service or org context - platform credentials
            let details = state
                .oauth_client
                .exchange_code_with_details(provider, &callback_code, pkce_verifier)
                .await?;
            (details, None, None)
        }
    } else {
        // No oauth state - platform credentials
        let details = state
            .oauth_client
            .exchange_code_with_details(provider, &callback_code, pkce_verifier)
            .await?;
        (details, None, None)
    };

    let user_info = if provider == Provider::Oidc {
        // Handle OIDC user info fetching (requires fetching provider model again)
        let oauth_ctx = oauth_state.as_ref().ok_or_else(|| {
            AppError::BadRequest("Missing OAuth state for OIDC provider".to_string())
        })?;

        let conn_id = oauth_ctx.upstream_connection_id.as_ref().ok_or_else(|| {
            AppError::BadRequest("Missing upstream connection ID for OIDC provider".to_string())
        })?;

        let org_slug = oauth_ctx.org_slug.as_ref().ok_or_else(|| {
            AppError::InternalServerError("Missing org_slug in OAuth state".to_string())
        })?;

        let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), org_slug)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

        let provider_model =
            resolve_upstream_provider_for_org(&state, &organization.id, conn_id).await?;

        ensure_upstream_provider_enabled(&provider_model)?;

        // Fetch user info using provider's userinfo_url
        let oidc_config = resolve_upstream_oidc_config(&provider_model).await?;
        let userinfo_url = oidc_config.userinfo_url;

        let resp = crate::crypto::safe_http::SafeHttpClient::new()?
            .get_with_owned_headers(
                &userinfo_url,
                vec![(
                    "Authorization".to_string(),
                    format!("Bearer {}", token_details.access_token),
                )],
            )
            .await
            .map_err(|e| {
                AppError::InternalServerError(format!("Failed to fetch user info: {}", e))
            })?;

        if !resp.status().is_success() {
            return Err(AppError::InternalServerError(format!(
                "User info request failed with status: {}",
                resp.status()
            )));
        }

        #[derive(serde::Deserialize)]
        struct OidcUserInfo {
            sub: String,
            email: Option<String>,
            name: Option<String>,
        }

        let info: OidcUserInfo = resp.json().await.map_err(|e| {
            AppError::InternalServerError(format!("Failed to parse user info: {}", e))
        })?;

        crate::crypto::sso::UserInfo {
            provider_user_id: info.sub,
            email: info.email.ok_or_else(|| {
                AppError::BadRequest("Email not provided by OIDC provider".to_string())
            })?,
            name: info.name,
        }
    } else {
        // Standard providers
        get_provider_user_info(provider, &token_details.access_token, &config).await?
    };

    // OAuth state proves what was selected when authorization started, not
    // that the tenant is still permitted to complete authentication now.
    // Re-authorize before any user, identity, grant, or session mutation.
    validate_live_oauth_tenant_context(
        DB::Conn(&state.db),
        issuing_org_id.as_deref(),
        oauth_state
            .as_ref()
            .and_then(|context| context.org_slug.as_deref()),
        issuing_service_id.as_deref(),
        oauth_state
            .as_ref()
            .and_then(|context| context.service_slug.as_deref()),
        oauth_state
            .as_ref()
            .and_then(|context| context.redirect_uri.as_deref()),
        oauth_state
            .as_ref()
            .and_then(|context| context.resource.as_deref()),
    )
    .await?;

    let requested_scopes = oauth_state
        .as_ref()
        .map(|ctx| parse_stored_scopes(&ctx.requested_scopes))
        .unwrap_or_default();
    let effective_scopes = normalized_granted_scopes(
        provider,
        &requested_scopes,
        &token_details.scopes,
        token_details.refresh_token.as_deref(),
    );

    // Check if this is a linking flow (user_id_for_linking is set)
    if let Some(ref oauth_ctx) = oauth_state {
        if let Some(ref linking_user_id) = oauth_ctx.user_id_for_linking {
            // This is a linking flow - link the new provider to the existing user
            let provider_key = oauth_ctx
                .upstream_connection_id
                .as_deref()
                .filter(|_| provider == Provider::Oidc)
                .unwrap_or_else(|| provider.as_str());

            if let Some(service_id) = issuing_service_id.as_deref() {
                ensure_provider_token_request_matches_provider_user(
                    &state,
                    oauth_ctx.provider_token_request_state.as_deref(),
                    linking_user_id,
                    service_id,
                    provider_key,
                    &user_info.email,
                )
                .await?;
            }

            ensure_provider_account_can_link(
                &state,
                linking_user_id,
                issuing_org_id.as_deref(),
                issuing_service_id.as_deref(),
                provider.as_str(),
                &user_info.provider_user_id,
            )
            .await?;

            validate_live_oauth_linking_user(
                DB::Conn(&state.db),
                linking_user_id,
                issuing_org_id.as_deref(),
                issuing_service_id.as_deref(),
            )
            .await?;

            // Create or update identity for the linking user
            IdentityStore::upsert_with_details(
                DB::Conn(&state.db),
                state.encryption.as_ref(),
                linking_user_id,
                provider.as_str(),
                &user_info.provider_user_id,
                &token_details.access_token,
                token_details.refresh_token.as_deref(),
                token_details.expires_at,
                &effective_scopes,
                issuing_org_id.as_deref(),
                issuing_service_id.as_deref(),
            )
            .await?;

            let connected_account = upsert_connected_account_from_oauth(
                &state,
                linking_user_id,
                provider_key,
                &user_info,
                &token_details,
                &effective_scopes,
            )
            .await?;
            if let Some(request_state) = oauth_ctx.provider_token_request_state.as_deref() {
                let redirect_url = complete_provider_token_request_from_oauth(
                    &state,
                    request_state,
                    linking_user_id,
                    provider_key,
                    &connected_account.id,
                    &effective_scopes,
                )
                .await?;
                return Ok(Redirect::to(&redirect_url).into_response());
            }
            if let Some(service_id) = issuing_service_id.as_deref() {
                grant_connected_account_to_service(
                    &state,
                    linking_user_id,
                    service_id,
                    provider_key,
                    &connected_account.id,
                    &effective_scopes,
                )
                .await?;
            }

            // Redirect to frontend callback URL
            // redirect_uri already contains query params: ?status=success&provider=X&action=link
            let redirect_url = oauth_ctx.redirect_uri.as_ref().ok_or_else(|| {
                AppError::InternalServerError(
                    "No redirect_uri in oauth state for linking flow".to_string(),
                )
            })?;
            return Ok(Redirect::to(redirect_url).into_response());
        }
    }

    // Normal login flow - find or create user
    // Normal login flow - find or create user (scoped to tenant)
    let (user_model, was_created) = if let Some(ref org_id) = issuing_org_id {
        // Tenant-scoped lookup
        let existing = crate::store::users::UserStore::find_by_email_with_context(
            DB::Conn(&state.db),
            &user_info.email,
            Some(org_id),
        )
        .await?;

        if let Some(u) = existing {
            if u.deleted_at.is_some() {
                return Err(AppError::Unauthorized(
                    "OAuth user is no longer active".to_string(),
                ));
            }
            (u, false)
        } else {
            // Create scoped user
            let u = crate::store::users::UserStore::create_with_org_id(
                DB::Conn(&state.db),
                &user_info.email,
                None,
                org_id,
            )
            .await?;
            (u, true)
        }
    } else {
        // Platform-scoped lookup (issuing_org_id is None)
        // matches behavior of find_or_create but explicitly using the context logic if we wanted,
        // strictly speaking find_or_create calls create() which defaults org_id to NULL, which is what we want for platform users.
        let result =
            crate::store::users::UserStore::find_or_create(DB::Conn(&state.db), &user_info.email)
                .await?;
        if result.0.deleted_at.is_some() {
            return Err(AppError::Unauthorized(
                "OAuth user is no longer active".to_string(),
            ));
        }
        result
    };
    let user: User = user_model.into();

    // Run risk engine evaluation for existing users (skip for new users)
    let risk_assessment = if !was_created {
        use crate::services::risk_engine::RiskContext;
        let risk_ctx = RiskContext {
            user_id: &user.id,
            org_id: issuing_org_id.as_deref(),
            ip_address: &request_info.ip_address,
            user_agent: &request_info.user_agent,
            device_cookie: None, // No device cookie available during OAuth callback
        };

        let assessment = state
            .risk_engine
            .evaluate(DB::Conn(&state.db), risk_ctx)
            .await?;

        // Log risk assessment
        tracing::info!(
            user_id = %user.id,
            provider = %provider.as_str(),
            risk_score = assessment.score,
            risk_action = ?assessment.action,
            risk_factors = ?assessment.factors,
            "OAuth login risk assessment"
        );

        Some(assessment)
    } else {
        None
    };

    // Publish signup event if user was just created
    if was_created {
        use crate::services::events::{Event, EventType};
        use serde_json::json;

        let mut event_builder = Event::builder(EventType::UserSignupSuccess)
            .actor_user_id(&user.id)
            .actor_email(&user_info.email);

        if let Some(org_id) = &issuing_org_id {
            event_builder = event_builder.org_id(org_id);
        }

        if let Some(service_id) = &issuing_service_id {
            event_builder = event_builder.detail("service_id", json!(service_id));
        }

        event_builder = event_builder.detail("provider", json!(provider.as_str()));

        let event = event_builder.build();

        // Fire and forget
        let dispatcher = state.event_dispatcher.clone();
        tokio::spawn(async move {
            if let Err(e) = dispatcher.publish(event).await {
                tracing::error!("Failed to publish signup event: {}", e);
            }
        });
    }

    // Update identity with full token details
    IdentityStore::upsert_with_details(
        DB::Conn(&state.db),
        state.encryption.as_ref(),
        &user.id,
        provider.as_str(),
        &user_info.provider_user_id,
        &token_details.access_token,
        token_details.refresh_token.as_deref(),
        token_details.expires_at,
        &effective_scopes,
        issuing_org_id.as_deref(),
        issuing_service_id.as_deref(),
    )
    .await?;
    let connected_provider_key = oauth_state
        .as_ref()
        .and_then(|oauth_ctx| oauth_ctx.upstream_connection_id.as_deref())
        .filter(|_| provider == Provider::Oidc)
        .unwrap_or_else(|| provider.as_str());
    let connected_account = upsert_connected_account_from_oauth(
        &state,
        &user.id,
        connected_provider_key,
        &user_info,
        &token_details,
        &effective_scopes,
    )
    .await?;
    if let Some(service_id) = issuing_service_id.as_deref() {
        grant_connected_account_to_service(
            &state,
            &user.id,
            service_id,
            connected_provider_key,
            &connected_account.id,
            &effective_scopes,
        )
        .await?;
    }

    // SAML assertion issuance is an authentication completion, so it must pass
    // the same risk and MFA gates as the ordinary OAuth login path. Do not
    // consume the one-time SAML state until those gates have completed.
    if let Some(ref oauth_ctx) = oauth_state {
        if let Some(ref saml_state_id) = oauth_ctx.saml_state_id {
            let mfa_enabled = is_mfa_enabled(&state.db, &user.id).await?;
            let risk_action = risk_assessment.as_ref().map(|assessment| assessment.action);

            match saml_login_gate(risk_action, mfa_enabled) {
                SamlLoginGate::Block => {
                    tracing::warn!(
                        user_id = %user.id,
                        provider = %provider.as_str(),
                        saml_state_id = %saml_state_id,
                        "SAML login blocked by risk engine before assertion issuance"
                    );
                    return Ok((
                        axum::http::StatusCode::FORBIDDEN,
                        Html(
                            "<!DOCTYPE html><html><head><title>Login Blocked</title></head><body><h1>Login Suspended</h1><p>For security reasons, this login attempt was blocked.</p></body></html>"
                                .to_string(),
                        ),
                    )
                        .into_response());
                }
                SamlLoginGate::ChallengeMfa => {
                    let preauth_token = state.jwt_service.create_mfa_preauth_token_with_resource(
                        &user.id,
                        &user.email,
                        user.is_platform_owner,
                        oauth_ctx.org_slug.as_deref(),
                        oauth_ctx.service_slug.as_deref(),
                        Some(saml_state_id),
                        oauth_ctx.resource.as_deref(),
                    )?;
                    return Ok(crate::handlers::saml::saml_mfa_challenge_response(
                        &preauth_token,
                    ));
                }
                SamlLoginGate::Complete => {
                    return crate::handlers::saml::complete_saml_authentication(
                        &state,
                        saml_state_id,
                        oauth_ctx.service_id.as_deref(),
                        &user,
                    )
                    .await;
                }
            }
        }
    }

    // Handle device flow completion
    if let Some(ref oauth_ctx) = oauth_state {
        if oauth_ctx.redirect_uri.is_none()
            && (oauth_ctx.org_slug.is_some() || oauth_ctx.service_slug.is_some())
        {
            // This is a device flow callback - find and update the device code
            if let (Some(org_slug), Some(service_slug)) =
                (&oauth_ctx.org_slug, &oauth_ctx.service_slug)
            {
                let user_code = oauth_ctx.device_user_code.as_ref().ok_or_else(|| {
                    AppError::BadRequest("Device flow requires user_code binding".to_string())
                })?;
                let device_code: Option<DeviceCode> =
                    DeviceCodeStore::find_pending_by_user_code(DB::Conn(&state.db), user_code)
                        .await?
                        .map(Into::into);

                if let Some(dc) = device_code {
                    validate_service_device_oauth_context(
                        &dc.org_slug,
                        &dc.service_slug,
                        org_slug,
                        service_slug,
                    )?;
                    // Check if user has MFA enabled
                    let mfa_enabled = is_mfa_enabled(&state.db, &user.id).await?;

                    if !mfa_enabled {
                        // No MFA - authorize the device code immediately
                        DeviceCodeStore::authorize(DB::Conn(&state.db), &dc.id, &user.id).await?;
                    } else {
                        // MFA enabled - store user_id but don't authorize yet
                        // The device will remain pending until MFA is completed
                        DeviceCodeStore::set_user_id(DB::Conn(&state.db), &dc.id, &user.id).await?;

                        // Redirect to MFA challenge with device flow context
                        // Create pre-auth token with device context
                        let preauth_token = state
                            .jwt_service
                            .create_mfa_preauth_token_for_device_with_resource(
                                &user.id,
                                &user.email,
                                user.is_platform_owner,
                                Some(org_slug),
                                Some(service_slug),
                                oauth_ctx.resource.as_deref(),
                                &dc.id,
                            )?;

                        // Get the device activation URI for redirect
                        let service = ServiceStore::find_by_org_slug_and_service_slug(
                            DB::Conn(&state.db),
                            org_slug,
                            service_slug,
                        )
                        .await?
                        .map(crate::db::models::Service::from);

                        let base_activation_uri = service
                            .and_then(|s| s.device_activation_uri)
                            .ok_or_else(|| {
                                AppError::InternalServerError(
                                    "Device activation URI not configured for this service"
                                        .to_string(),
                                )
                            })?;

                        let mut mfa_url = url::Url::parse(&base_activation_uri).map_err(|_| {
                            AppError::InternalServerError(
                                "Invalid device activation URI configured".to_string(),
                            )
                        })?;

                        // Redirect to MFA challenge page with pre-auth token and device code info
                        mfa_url.set_path("/activate/mfa-challenge");
                        mfa_url
                            .query_pairs_mut()
                            .append_pair("preauth_token", &preauth_token)
                            .append_pair("device_code_id", &dc.id)
                            .append_pair("user_code", &dc.user_code);

                        return Ok(Redirect::to(mfa_url.as_str()).into_response());
                    }
                }

                // This is a device flow completion - redirect to service's success page
                // Get service to find device activation URI
                let service = ServiceStore::find_by_org_slug_and_service_slug(
                    DB::Conn(&state.db),
                    org_slug,
                    service_slug,
                )
                .await?
                .map(crate::db::models::Service::from);

                // Use the service's configured device activation URI
                let base_activation_uri = service
                    .and_then(|s| s.device_activation_uri)
                    .ok_or_else(|| {
                        AppError::InternalServerError(
                            "Device activation URI not configured for this service".to_string(),
                        )
                    })?;

                // Create success redirect URL with token
                let mut success_url = url::Url::parse(&base_activation_uri).map_err(|_| {
                    AppError::InternalServerError(
                        "Invalid device activation URI configured".to_string(),
                    )
                })?;

                // Set path to success page and include status and token
                success_url.set_path("/activate/success");
                success_url
                    .query_pairs_mut()
                    .append_pair("status", "success")
                    .append_pair("device_flow", "true");

                return Ok(Redirect::to(success_url.as_str()).into_response());
            }
        }
    }

    // If redirect_uri provided, issue JWT and redirect
    if let Some(ref oauth_ctx) = oauth_state {
        if let Some(ref redirect_uri) = oauth_ctx.redirect_uri {
            // Get service info for JWT
            let service_slug = if let (Some(org), Some(svc)) =
                (&oauth_ctx.org_slug, &oauth_ctx.service_slug)
            {
                // Get service
                let service =
                    ServiceStore::find_by_org_slug_and_service_slug(DB::Conn(&state.db), org, svc)
                        .await?
                        .map(crate::db::models::Service::from);

                if let Some(service) = service {
                    // Validate redirect_uri again before redirecting
                    validate_redirect_uri(redirect_uri, &service)?;
                    Some(svc.clone())
                } else {
                    None
                }
            } else {
                None
            };

            // Check if user has MFA enabled
            let mfa_enabled = is_mfa_enabled(&state.db, &user.id).await?;

            // Handle risk engine actions for existing users
            if let Some(risk_assessment) = risk_assessment {
                use crate::services::risk_engine::RiskAction;
                match risk_assessment.action {
                    RiskAction::ChallengeMFA => {
                        // Risk engine demands MFA challenge
                        let preauth_token =
                            state.jwt_service.create_mfa_preauth_token_with_resource(
                                &user.id,
                                &user.email,
                                user.is_platform_owner,
                                oauth_ctx.org_slug.as_deref(),
                                service_slug.as_deref(),
                                oauth_ctx.saml_state_id.as_deref(),
                                oauth_ctx.resource.as_deref(),
                            )?;

                        // Redirect with pre-auth token and mfa_required flag
                        let redirect_url = hosted_service_mfa_redirect_uri(
                            &state.base_url,
                            redirect_uri,
                            &preauth_token,
                            oauth_ctx.org_slug.as_deref(),
                            service_slug.as_deref(),
                            oauth_ctx.client_state.as_deref(),
                        )?;
                        return Ok(Redirect::to(&redirect_url).into_response());
                    }
                    RiskAction::Block => {
                        tracing::warn!(
                            user_id = %user.id,
                            provider = %provider.as_str(),
                            risk_score = risk_assessment.score,
                            factors = ?risk_assessment.factors,
                            "OAuth login blocked by risk engine"
                        );

                        // Return error page instead of redirect
                        let html = r#"
                            <!DOCTYPE html>
                            <html>
                            <head><title>Login Blocked</title></head>
                            <body>
                                <h1>Login Suspended</h1>
                                <p>For security reasons, we've temporarily suspended this login attempt.</p>
                                <p>Please contact support if this continues to occur.</p>
                            </body>
                            </html>
                            "#
                        .to_string();
                        return Ok((axum::http::StatusCode::FORBIDDEN, Html(html)).into_response());
                    }
                    RiskAction::Allow | RiskAction::LogOnly => {
                        // Continue with normal flow
                    }
                }
            }

            if mfa_enabled {
                // User has MFA enabled - create pre-auth token instead of full session
                let preauth_token = state.jwt_service.create_mfa_preauth_token_with_resource(
                    &user.id,
                    &user.email,
                    user.is_platform_owner,
                    oauth_ctx.org_slug.as_deref(),
                    service_slug.as_deref(),
                    oauth_ctx.saml_state_id.as_deref(),
                    oauth_ctx.resource.as_deref(),
                )?;

                // Redirect with pre-auth token and mfa_required flag
                let redirect_url = hosted_service_mfa_redirect_uri(
                    &state.base_url,
                    redirect_uri,
                    &preauth_token,
                    oauth_ctx.org_slug.as_deref(),
                    service_slug.as_deref(),
                    oauth_ctx.client_state.as_deref(),
                )?;
                return Ok(Redirect::to(&redirect_url).into_response());
            }

            // MFA not enabled - proceed with normal token issuance

            // Check MAU limit for organization logins (billing enforcement)
            if let Some(ref org_id) = issuing_org_id {
                crate::services::tier_enforcement::TierService::check_mau_limit(
                    DB::Conn(&state.db),
                    org_id,
                )
                .await?;
            }

            let jwt = state.jwt_service.create_token_with_resource(
                &user.id,
                &user.email,
                user.is_platform_owner,
                oauth_ctx.org_slug.as_deref(),
                service_slug.as_deref(),
                oauth_ctx.resource.as_deref(),
            )?;

            let refresh_token = crate::crypto::refresh_tokens::generate();

            // Store session with refresh token
            let token_hash = JwtService::hash_token(&jwt);
            let now = Utc::now();
            let expires_at = now + chrono::Duration::hours(config.jwt_expiration_hours);
            let refresh_expires_at = now + chrono::Duration::days(30);

            create_oauth_session_with_login_audit(
                &state,
                &user.id,
                &token_hash,
                expires_at.naive_utc(),
                &refresh_token,
                refresh_expires_at.naive_utc(),
                oauth_ctx.org_slug.as_deref(),
                oauth_ctx.service_id.as_deref(),
                service_slug.as_deref(),
                oauth_ctx.resource.as_deref(),
                provider,
            )
            .await?;

            // Publish login success event for webhooks
            publish_login_event(
                &state.event_dispatcher,
                &user.id,
                &user.email,
                oauth_ctx.org_slug.as_deref(),
                oauth_ctx.service_id.as_deref(),
                Some(provider.as_str()),
            )
            .await;

            // Check if JSON response is requested (to avoid header overflow in API flows)
            if callback.format.as_ref().is_some_and(|f| f == "json") {
                // Return JSON response instead of redirect for API flows
                use serde_json::json;
                let response_body = json!({
                    "access_token": jwt,
                    "refresh_token": refresh_token,
                    "token_type": "Bearer"
                });
                return Ok(Json(response_body).into_response());
            }

            // SECURITY FIX: Use Fragment (#) instead of Query (?)
            // This prevents tokens from being sent to the server in the redirect request
            // and keeps them strictly client-side.
            let redirect_url = service_token_redirect_uri(
                redirect_uri,
                &jwt,
                &refresh_token,
                oauth_ctx.client_state.as_deref(),
            )?;
            return Ok(Redirect::to(&redirect_url).into_response());
        }
    }

    // No redirect_uri - show HTML success page
    let html = format!(
        r#"
        <!DOCTYPE html>
        <html>
        <head><title>Authentication Successful</title></head>
        <body>
            <h1>Authentication Successful</h1>
            <p>User: {}</p>
            <p>Provider: {}</p>
        </body>
        </html>
        "#,
        user_info.email,
        provider.as_str()
    );

    Ok(Html(html).into_response())
}

/// Admin Auth: Initiate OAuth flow for platform/org admin login
pub async fn auth_admin_provider(
    State(state): State<AppState>,
    Path(provider_str): Path<String>,
    Query(params): Query<AdminAuthRequest>,
) -> Result<Response> {
    let provider = Provider::from_str(&provider_str)?;

    // Build admin OAuth client dynamically using PLATFORM_* credentials
    let config = crate::config::Config::from_env().map_err(AppError::InternalServerError)?;

    let admin_oauth_client = create_admin_oauth_client(&config, provider)?;

    // Use default admin scopes based on provider
    let scopes = default_scopes_for_provider(provider);

    // Generate authorization URL with PKCE.
    let (auth_url, csrf_token, pkce_verifier) =
        get_admin_authorization_url(&admin_oauth_client, provider, scopes.clone());

    let lite_return_to = normalize_lite_return_to(params.return_to.as_deref())?;

    // Store OAuth state with is_admin_flow = true
    let expires_at = Utc::now() + chrono::Duration::minutes(OAUTH_STATE_EXPIRE_MINUTES);
    let pkce_value = if !pkce_verifier.is_empty() {
        Some(pkce_verifier)
    } else {
        None
    };

    let is_admin_flow = true;
    OAuthStateStore::create(
        DB::Conn(&state.db),
        csrf_token.secret(),
        pkce_value.as_deref(),
        None, // service_id
        None, // redirect_uri
        params.org_slug.as_deref(),
        None, // service_slug
        is_admin_flow,
        None, // user_id_for_linking
        params.user_code.as_deref(),
        None, // saml_state_id
        None, // upstream_connection_id
        Some(&scopes),
        lite_return_to.as_deref(), // client_state
        None,
        None,
        &expires_at.naive_utc(),
    )
    .await?;

    Ok(Redirect::to(&auth_url).into_response())
}

/// Admin Auth: Handle OAuth callback for admin login
pub async fn auth_admin_callback(
    State(state): State<AppState>,
    Extension(request_info): Extension<RequestInfo>,
    Path(provider_str): Path<String>,
    Query(callback): Query<CallbackQuery>,
) -> Result<Response> {
    // Load config early so we can use it for error redirects
    let config = crate::config::Config::from_env().map_err(AppError::InternalServerError)?;

    // Wrap the main logic to catch errors and redirect to frontend with error info
    match auth_admin_callback_impl(state, request_info, provider_str, callback).await {
        Ok(response) => Ok(response),
        Err(e) => {
            // Log the error
            tracing::error!("OAuth callback error: {}", e);

            // Redirect to frontend with error information
            let error_message = match &e {
                AppError::OAuth(msg) => msg.clone(),
                AppError::BadRequest(msg) => msg.clone(),
                AppError::Unauthorized(msg) => msg.clone(),
                _ => "Authentication failed".to_string(),
            };

            let redirect_base = format!("{}/callback", config.platform_dashboard_base_url);
            let mut redirect_url = url::Url::parse(&redirect_base).map_err(|_| {
                AppError::InternalServerError("Invalid platform admin redirect URI".to_string())
            })?;

            redirect_url
                .query_pairs_mut()
                .append_pair("error", "oauth_error")
                .append_pair("error_description", &error_message);

            Ok(Redirect::to(redirect_url.as_str()).into_response())
        }
    }
}

/// Internal implementation of admin callback that can return errors
async fn auth_admin_callback_impl(
    state: AppState,
    request_info: RequestInfo,
    provider_str: String,
    callback: CallbackQuery,
) -> Result<Response> {
    let provider = Provider::from_str(&provider_str)?;
    let config = crate::config::Config::from_env().map_err(AppError::InternalServerError)?;

    // Get OAuth state and verify it's an admin flow
    let oauth_state = if let Some(ref state_param) = callback.state {
        OAuthStateStore::find_by_state(DB::Conn(&state.db), state_param)
            .await?
            .map(crate::db::models::OAuthState::from)
    } else {
        None
    };

    let oauth_state =
        oauth_state.ok_or_else(|| AppError::BadRequest("Invalid state parameter".to_string()))?;
    let lite_return_to = if oauth_state.is_admin_flow {
        normalize_lite_return_to(oauth_state.client_state.as_deref())?
    } else {
        None
    };

    if let Some((error, description)) = callback.oauth_error() {
        if let Some(ref state_param) = callback.state {
            OAuthStateStore::delete(DB::Conn(&state.db), state_param)
                .await
                .map_err(|_| AppError::BadRequest("Invalid state parameter".to_string()))?;
        }

        if !oauth_state.is_admin_flow {
            if let Some(ref redirect_uri) = oauth_state.redirect_uri {
                return redirect_oauth_error_to_uri(redirect_uri, error, description);
            }
        }

        if let Some(return_to) = lite_return_to.as_deref() {
            return redirect_oauth_error_to_lite(&state.base_url, return_to, error, description);
        }

        return redirect_oauth_error_to_platform(&config, error, description);
    }

    // Detect flow type based on OAuth state
    // Service flows (end-user login) use admin callback when platform credentials are used
    // because that's what's registered in provider consoles (GitHub/Microsoft only allow 1 callback)
    if !oauth_state.is_admin_flow {
        // This is not an admin flow - check if it's a valid service flow
        if oauth_state.service_id.is_some() {
            // Service context present - this is an end-user login via admin callback
            // Clean up OAuth state first
            if let Some(ref state_param) = callback.state {
                OAuthStateStore::delete(DB::Conn(&state.db), state_param)
                    .await
                    .map_err(|_| AppError::BadRequest("Invalid state parameter".to_string()))?;
            }
            // Delegate to service flow handler
            let redirect_uri = oauth_state.redirect_uri.clone();
            let service_response = handle_service_flow_via_admin_callback(
                state,
                request_info,
                provider_str,
                callback,
                oauth_state,
            )
            .await;

            return match service_response {
                Ok(response) => Ok(response),
                Err(err) => {
                    if let Some(redirect_uri) = redirect_uri {
                        let message = oauth_error_message(&err);
                        redirect_oauth_error_to_uri(
                            &redirect_uri,
                            "oauth_error",
                            Some(message.as_str()),
                        )
                    } else {
                        Err(err)
                    }
                }
            };
        }
        // No service context and not admin - invalid
        return Err(AppError::BadRequest("Not an admin flow".to_string()));
    }

    // Clean up OAuth state immediately to prevent replay attacks
    // Do this before token exchange so even if exchange fails, state cannot be reused
    if let Some(ref state_param) = callback.state {
        OAuthStateStore::delete(DB::Conn(&state.db), state_param)
            .await
            .map_err(|_| AppError::BadRequest("Invalid state parameter".to_string()))?;
    }

    // Build admin OAuth client with PLATFORM_* credentials
    let admin_oauth_client = create_admin_oauth_client(&config, provider)?;

    // Exchange code with PKCE verifier
    let pkce_verifier = oauth_state
        .pkce_verifier
        .as_deref()
        .filter(|verifier| !verifier.is_empty());
    let callback_code = callback.authorization_code()?.to_string();
    let token_details =
        exchange_admin_code(&admin_oauth_client, provider, &callback_code, pkce_verifier).await?;

    // Get user info from provider (standalone, not using OAuth client)
    let user_info = get_provider_user_info(provider, &token_details.access_token, &config).await?;
    let requested_scopes = parse_stored_scopes(&oauth_state.requested_scopes);
    let effective_scopes = normalized_granted_scopes(
        provider,
        &requested_scopes,
        &token_details.scopes,
        token_details.refresh_token.as_deref(),
    );

    // Find or create user with platform owner detection for admin OAuth
    let (user_model, was_created) = crate::store::users::UserStore::find_or_create_admin_oauth(
        DB::Conn(&state.db),
        &user_info.email,
        config.platform_owner_email.as_deref(),
    )
    .await?;
    let user: User = user_model.into();

    // Publish signup event if user was just created (admin OAuth flow)
    if was_created {
        use crate::services::events::{Event, EventType};
        use serde_json::json;

        let mut event_builder = Event::builder(EventType::UserSignupSuccess)
            .actor_user_id(&user.id)
            .actor_email(&user_info.email);

        if let Some(org_slug) = &oauth_state.org_slug {
            event_builder = event_builder.org_id(org_slug);
        }

        event_builder = event_builder.detail("provider", json!(provider.as_str()));
        event_builder = event_builder.detail("flow_type", json!("admin"));

        let event = event_builder.build();

        // Fire and forget
        let dispatcher = state.event_dispatcher.clone();
        tokio::spawn(async move {
            if let Err(e) = dispatcher.publish(event).await {
                tracing::error!("Failed to publish signup event: {}", e);
            }
        });
    }

    // Update identity (admin flow always uses platform credentials, so issuing_org_id and issuing_service_id are None)
    IdentityStore::upsert_with_details(
        DB::Conn(&state.db),
        state.encryption.as_ref(),
        &user.id,
        provider.as_str(),
        &user_info.provider_user_id,
        &token_details.access_token,
        token_details.refresh_token.as_deref(),
        token_details.expires_at,
        &effective_scopes,
        None,
        None,
    )
    .await?;

    // Check if this is a device flow completion - prioritize this over normal web login
    if let Some(ref user_code) = oauth_state.device_user_code {
        // Find the specific device code by user_code
        let device_code =
            DeviceCodeStore::find_pending_by_user_code(DB::Conn(&state.db), user_code).await?;

        if let Some(dc) = device_code {
            validate_platform_device_oauth_context(
                &dc.org_slug,
                &dc.service_slug,
                oauth_state.org_slug.as_deref(),
                user.is_platform_owner,
            )?;
            // Check if user has MFA enabled
            let mfa_enabled = is_mfa_enabled(&state.db, &user.id).await?;

            if !mfa_enabled {
                // No MFA - authorize the device code immediately
                DeviceCodeStore::authorize(DB::Conn(&state.db), &dc.id, &user.id).await?;
            } else {
                // MFA enabled - store user_id but don't authorize yet
                DeviceCodeStore::set_user_id(DB::Conn(&state.db), &dc.id, &user.id).await?;

                // Redirect to MFA challenge with device flow context
                let preauth_token = state.jwt_service.create_mfa_preauth_token_for_device(
                    &user.id,
                    &user.email,
                    user.is_platform_owner,
                    oauth_state.org_slug.as_deref(),
                    None,
                    &dc.id,
                )?;

                // Determine redirect URL based on org/service for MFA challenge
                let mfa_redirect_url = if dc.org_slug == "platform"
                    && dc.service_slug == "admin-cli"
                {
                    // Platform admin CLI - redirect to platform admin frontend MFA challenge
                    platform_device_mfa_redirect_url(
                        &config.platform_dashboard_base_url,
                        &preauth_token,
                        &dc.id,
                        &dc.user_code,
                    )
                } else {
                    // Service-level device flow - redirect to service's MFA challenge page
                    let service = ServiceStore::find_by_org_slug_and_service_slug(
                        DB::Conn(&state.db),
                        &dc.org_slug,
                        &dc.service_slug,
                    )
                    .await?
                    .map(crate::db::models::Service::from);

                    let base_activation_uri = service
                        .and_then(|s| s.device_activation_uri)
                        .ok_or_else(|| {
                            AppError::InternalServerError(
                                "Device activation URI not configured for this service".to_string(),
                            )
                        })?;

                    let mut mfa_url = url::Url::parse(&base_activation_uri).map_err(|_| {
                        AppError::InternalServerError(
                            "Invalid device activation URI configured".to_string(),
                        )
                    })?;

                    mfa_url.set_path("/activate/mfa-challenge");
                    mfa_url
                        .query_pairs_mut()
                        .append_pair("preauth_token", &preauth_token)
                        .append_pair("device_code_id", &dc.id)
                        .append_pair("user_code", &dc.user_code);

                    mfa_url.to_string()
                };

                return Ok(Redirect::to(&mfa_redirect_url).into_response());
            }

            // Device code is now authorized (or pending MFA) - determine success redirect URL
            let redirect_url = if dc.org_slug == "platform" && dc.service_slug == "admin-cli" {
                // Platform admin CLI device flow - redirect to platform admin frontend
                format!(
                    "{}/callback?device_flow_status=success",
                    config.platform_dashboard_base_url
                )
            } else {
                // Service-level device flow - get service's device activation URI
                let service: Option<Service> = ServiceStore::find_by_org_slug_and_service_slug(
                    DB::Conn(&state.db),
                    &dc.org_slug,
                    &dc.service_slug,
                )
                .await?
                .map(std::convert::Into::into);

                let base_activation_uri: String = service
                    .and_then(|s| s.device_activation_uri)
                    .ok_or_else(|| {
                        AppError::InternalServerError(
                            "Device activation URI not configured for this service".to_string(),
                        )
                    })?;

                let mut success_url = url::Url::parse(&base_activation_uri).map_err(|_| {
                    AppError::InternalServerError(
                        "Invalid device activation URI configured".to_string(),
                    )
                })?;

                success_url.set_path("/activate/success");
                success_url
                    .query_pairs_mut()
                    .append_pair("status", "success")
                    .append_pair("device_flow", "true");

                success_url.to_string()
            };

            return Ok(Redirect::to(&redirect_url).into_response());
        }
    }

    // If not a device flow, proceed with normal web login decision logic
    // Check if user has MFA enabled
    let mfa_enabled = is_mfa_enabled(&state.db, &user.id).await?;

    // Load config for redirect URL
    let config = crate::config::Config::from_env().map_err(AppError::InternalServerError)?;

    if mfa_enabled {
        // User has MFA enabled - create pre-auth token instead of full session
        let preauth_token = state.jwt_service.create_mfa_preauth_token(
            &user.id,
            &user.email,
            user.is_platform_owner,
            oauth_state.org_slug.as_deref(),
            None, // service_slug is always None for admin flows
            None, // saml_state is not used in admin flows
        )?;

        // Redirect with pre-auth token and mfa_required flag
        let redirect_url = if let Some(return_to) = lite_return_to.as_deref() {
            lite_callback_redirect_uri(
                &state.base_url,
                Some(return_to),
                &[("preauth_token", &preauth_token), ("mfa_required", "true")],
            )?
        } else {
            format!(
                "{}/callback#preauth_token={}&mfa_required=true",
                config.platform_dashboard_base_url, preauth_token
            )
        };
        return Ok(Redirect::to(&redirect_url).into_response());
    }

    // MFA not enabled - proceed with normal token issuance
    let jwt = if user.is_platform_owner {
        // Create Platform JWT (no org or service claims)
        state
            .jwt_service
            .create_token(&user.id, &user.email, true, None, None)?
    } else if let Some(org_slug) = &oauth_state.org_slug {
        // Check if user is a member of the requested organization
        let membership =
            MembershipStore::find_by_org_slug_and_user(DB::Conn(&state.db), org_slug, &user.id)
                .await?;

        if membership.is_some() {
            // Create Org Management JWT (org claim present, service claim null)
            state
                .jwt_service
                .create_token(&user.id, &user.email, false, Some(org_slug), None)?
        } else {
            // User is not a member - issue basic JWT so they can access signup page
            state
                .jwt_service
                .create_token(&user.id, &user.email, false, None, None)?
        }
    } else {
        // Generic Admin Login (No org_slug provided):
        // Check if the user belongs to any organizations.
        let first_org_slug =
            MembershipStore::get_first_org_slug(DB::Conn(&state.db), &user.id).await?;

        if let Some(ref org_slug) = first_org_slug {
            // User is a member of at least one org. Issue a token for the first one.
            state
                .jwt_service
                .create_token(&user.id, &user.email, false, Some(org_slug), None)?
        } else {
            // User is not a member of any org: Issue a basic JWT to prompt for creation.
            state
                .jwt_service
                .create_token(&user.id, &user.email, false, None, None)?
        }
    };

    let refresh_token = crate::crypto::refresh_tokens::generate();

    // Store session with refresh token
    let token_hash = JwtService::hash_token(&jwt);
    let now = Utc::now();
    let expires_at = now + chrono::Duration::hours(config.jwt_expiration_hours);
    let refresh_expires_at = now + chrono::Duration::days(30);

    SessionStore::create(
        DB::Conn(&state.db),
        &user.id,
        &token_hash,
        expires_at.naive_utc(),
        Some(&refresh_token),
        Some(refresh_expires_at.naive_utc()),
        oauth_state.org_slug.as_deref(),
        None,
        None,
        None,
        None,
    )
    .await?;

    // Publish login success event for webhooks (admin login via platform OAuth)
    publish_login_event(
        &state.event_dispatcher,
        &user.id,
        &user.email,
        oauth_state.org_slug.as_deref(),
        None,
        Some(provider.as_str()),
    )
    .await;

    // Check if JSON response is requested (to avoid header overflow in API flows)
    if callback.format.as_ref().is_some_and(|f| f == "json") {
        // Return JSON response instead of redirect for API flows
        use serde_json::json;
        let response_body = json!({
            "access_token": jwt,
            "refresh_token": refresh_token,
            "token_type": "Bearer"
        });
        return Ok(Json(response_body).into_response());
    }

    // SECURITY FIX: Use Fragment (#) instead of Query (?)
    // Redirect to platform admin frontend with both tokens in fragment
    let redirect_url = if let Some(return_to) = lite_return_to.as_deref() {
        lite_callback_redirect_uri(
            &state.base_url,
            Some(return_to),
            &[("access_token", &jwt), ("refresh_token", &refresh_token)],
        )?
    } else {
        format!(
            "{}/callback#access_token={}&refresh_token={}",
            config.platform_dashboard_base_url, jwt, refresh_token
        )
    };
    Ok(Redirect::to(&redirect_url).into_response())
}

fn platform_device_mfa_redirect_url(
    dashboard_base_url: &str,
    preauth_token: &str,
    device_code_id: &str,
    user_code: &str,
) -> String {
    format!(
        "{dashboard_base_url}/callback#mfa_required=true&preauth_token={preauth_token}&device_code_id={device_code_id}&user_code={user_code}"
    )
}

/// Handle service flow (end-user login) that came through admin callback
/// This happens when a service uses platform credentials (no BYOO) because
/// GitHub/Microsoft only allow a single callback URL per OAuth app
async fn handle_service_flow_via_admin_callback(
    state: AppState,
    request_info: RequestInfo,
    provider_str: String,
    callback: CallbackQuery,
    oauth_state: crate::db::models::OAuthState,
) -> Result<Response> {
    let provider = Provider::from_str(&provider_str)?;

    // OAuth state was already validated and deleted by the caller

    // Load config
    let config = crate::config::Config::from_env().map_err(AppError::InternalServerError)?;

    // Get service BEFORE token exchange to check PKCE requirement
    let service_id = oauth_state.service_id.as_ref().ok_or_else(|| {
        AppError::InternalServerError("Missing service_id in OAuth state".to_string())
    })?;

    let service: crate::db::models::Service =
        ServiceStore::find_by_id(DB::Conn(&state.db), service_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?
            .into();

    validate_live_oauth_tenant_context(
        DB::Conn(&state.db),
        Some(&service.org_id),
        oauth_state.org_slug.as_deref(),
        Some(service_id),
        oauth_state.service_slug.as_deref(),
        oauth_state.redirect_uri.as_deref(),
        oauth_state.resource.as_deref(),
    )
    .await?;

    // Security: Enforce PKCE for public clients (mobile/desktop)
    // These clients cannot securely store client_secret, so PKCE is mandatory
    let pkce_verifier = oauth_state
        .pkce_verifier
        .as_deref()
        .filter(|verifier| !verifier.is_empty());
    if is_public_client(&service.service_type) && pkce_verifier.is_none() {
        return Err(AppError::BadRequest(
            "PKCE is required for public clients (mobile/desktop). Include code_verifier in your authorization request.".to_string()
        ));
    }

    // Use platform credentials for token exchange (same client as admin)
    let admin_oauth_client = create_admin_oauth_client(&config, provider)?;
    let callback_code = callback.authorization_code()?.to_string();
    let token_details =
        exchange_admin_code(&admin_oauth_client, provider, &callback_code, pkce_verifier).await?;

    let user_info = get_provider_user_info(provider, &token_details.access_token, &config).await?;
    let requested_scopes = parse_stored_scopes(&oauth_state.requested_scopes);
    let effective_scopes = normalized_granted_scopes(
        provider,
        &requested_scopes,
        &token_details.scopes,
        token_details.refresh_token.as_deref(),
    );

    let org_id = service.org_id.clone();

    if let Some(linking_user_id) = oauth_state.user_id_for_linking.as_deref() {
        ensure_provider_token_request_matches_provider_user(
            &state,
            oauth_state.provider_token_request_state.as_deref(),
            linking_user_id,
            service_id,
            provider.as_str(),
            &user_info.email,
        )
        .await?;

        ensure_provider_account_can_link(
            &state,
            linking_user_id,
            Some(&org_id),
            Some(service_id),
            provider.as_str(),
            &user_info.provider_user_id,
        )
        .await?;

        validate_live_oauth_linking_user(
            DB::Conn(&state.db),
            linking_user_id,
            Some(&org_id),
            Some(service_id),
        )
        .await?;

        IdentityStore::upsert_with_details(
            DB::Conn(&state.db),
            state.encryption.as_ref(),
            linking_user_id,
            provider.as_str(),
            &user_info.provider_user_id,
            &token_details.access_token,
            token_details.refresh_token.as_deref(),
            token_details.expires_at,
            &effective_scopes,
            Some(&org_id),
            Some(service_id),
        )
        .await?;

        let connected_account = upsert_connected_account_from_oauth(
            &state,
            linking_user_id,
            provider.as_str(),
            &user_info,
            &token_details,
            &effective_scopes,
        )
        .await?;
        if let Some(request_state) = oauth_state.provider_token_request_state.as_deref() {
            let redirect_url = complete_provider_token_request_from_oauth(
                &state,
                request_state,
                linking_user_id,
                provider.as_str(),
                &connected_account.id,
                &effective_scopes,
            )
            .await?;
            return Ok(Redirect::to(&redirect_url).into_response());
        }
        grant_connected_account_to_service(
            &state,
            linking_user_id,
            service_id,
            provider.as_str(),
            &connected_account.id,
            &effective_scopes,
        )
        .await?;

        let redirect_uri = oauth_state.redirect_uri.as_ref().ok_or_else(|| {
            AppError::InternalServerError(
                "No redirect_uri in oauth state for linking flow".to_string(),
            )
        })?;
        return Ok(Redirect::to(redirect_uri).into_response());
    }

    // Create/find TENANT-SCOPED user (not platform user)
    let existing = crate::store::users::UserStore::find_by_email_with_context(
        DB::Conn(&state.db),
        &user_info.email,
        Some(&org_id),
    )
    .await?;

    let (user_model, was_created) = if let Some(u) = existing {
        if u.deleted_at.is_some() {
            return Err(AppError::Unauthorized(
                "OAuth user is no longer active".to_string(),
            ));
        }
        (u, false)
    } else {
        let u = crate::store::users::UserStore::create_with_org_id(
            DB::Conn(&state.db),
            &user_info.email,
            None,
            &org_id,
        )
        .await?;
        (u, true)
    };
    let user: User = user_model.into();

    let risk_assessment = if !was_created {
        use crate::services::risk_engine::RiskContext;
        let risk_ctx = RiskContext {
            user_id: &user.id,
            org_id: Some(&org_id),
            ip_address: &request_info.ip_address,
            user_agent: &request_info.user_agent,
            device_cookie: None,
        };

        let assessment = state
            .risk_engine
            .evaluate(DB::Conn(&state.db), risk_ctx)
            .await?;

        tracing::info!(
            user_id = %user.id,
            provider = %provider.as_str(),
            risk_score = assessment.score,
            risk_action = ?assessment.action,
            risk_factors = ?assessment.factors,
            "OAuth login risk assessment"
        );

        Some(assessment)
    } else {
        None
    };

    // Publish signup event if user was just created
    if was_created {
        use crate::services::events::{Event, EventType};
        use serde_json::json;

        let event = Event::builder(EventType::UserSignupSuccess)
            .actor_user_id(&user.id)
            .actor_email(&user_info.email)
            .org_id(&org_id)
            .detail("service_id", json!(service_id))
            .detail("provider", json!(provider.as_str()))
            .build();

        let dispatcher = state.event_dispatcher.clone();
        tokio::spawn(async move {
            if let Err(e) = dispatcher.publish(event).await {
                tracing::error!("Failed to publish signup event: {}", e);
            }
        });
    }

    // Update identity with org/service context
    IdentityStore::upsert_with_details(
        DB::Conn(&state.db),
        state.encryption.as_ref(),
        &user.id,
        provider.as_str(),
        &user_info.provider_user_id,
        &token_details.access_token,
        token_details.refresh_token.as_deref(),
        token_details.expires_at,
        &effective_scopes,
        Some(&org_id),
        Some(service_id),
    )
    .await?;
    let connected_account = upsert_connected_account_from_oauth(
        &state,
        &user.id,
        provider.as_str(),
        &user_info,
        &token_details,
        &effective_scopes,
    )
    .await?;
    grant_connected_account_to_service(
        &state,
        &user.id,
        service_id,
        provider.as_str(),
        &connected_account.id,
        &effective_scopes,
    )
    .await?;

    // Check if redirect_uri provided
    let redirect_uri = oauth_state.redirect_uri.as_ref().ok_or_else(|| {
        AppError::InternalServerError("No redirect_uri in oauth state".to_string())
    })?;

    // Validate redirect_uri against service's allowed URIs
    validate_redirect_uri(redirect_uri, &service)?;

    // Check MAU limit for organization logins (billing enforcement)
    crate::services::tier_enforcement::TierService::check_mau_limit(DB::Conn(&state.db), &org_id)
        .await?;

    let mfa_enabled = is_mfa_enabled(&state.db, &user.id).await?;

    if let Some(risk_assessment) = risk_assessment {
        use crate::services::risk_engine::RiskAction;
        match risk_assessment.action {
            RiskAction::ChallengeMFA => {
                let preauth_token = state.jwt_service.create_mfa_preauth_token_with_resource(
                    &user.id,
                    &user.email,
                    user.is_platform_owner,
                    oauth_state.org_slug.as_deref(),
                    oauth_state.service_slug.as_deref(),
                    oauth_state.saml_state_id.as_deref(),
                    oauth_state.resource.as_deref(),
                )?;

                let redirect_url = hosted_service_mfa_redirect_uri(
                    &state.base_url,
                    redirect_uri,
                    &preauth_token,
                    oauth_state.org_slug.as_deref(),
                    oauth_state.service_slug.as_deref(),
                    oauth_state.client_state.as_deref(),
                )?;
                return Ok(Redirect::to(&redirect_url).into_response());
            }
            RiskAction::Block => {
                let html = r#"
                    <!DOCTYPE html>
                    <html>
                    <head><title>Login Blocked</title></head>
                    <body>
                        <h1>Login Suspended</h1>
                        <p>For security reasons, we've temporarily suspended this login attempt.</p>
                        <p>Please contact support if this continues to occur.</p>
                    </body>
                    </html>
                "#;
                return Ok((axum::http::StatusCode::FORBIDDEN, Html(html)).into_response());
            }
            RiskAction::Allow | RiskAction::LogOnly => {}
        }
    }

    if mfa_enabled {
        let preauth_token = state.jwt_service.create_mfa_preauth_token_with_resource(
            &user.id,
            &user.email,
            user.is_platform_owner,
            oauth_state.org_slug.as_deref(),
            oauth_state.service_slug.as_deref(),
            oauth_state.saml_state_id.as_deref(),
            oauth_state.resource.as_deref(),
        )?;

        let redirect_url = hosted_service_mfa_redirect_uri(
            &state.base_url,
            redirect_uri,
            &preauth_token,
            oauth_state.org_slug.as_deref(),
            oauth_state.service_slug.as_deref(),
            oauth_state.client_state.as_deref(),
        )?;
        return Ok(Redirect::to(&redirect_url).into_response());
    }

    // Issue JWT with org/service claims
    let service_slug = oauth_state.service_slug.as_deref();
    let jwt = state.jwt_service.create_token_with_resource(
        &user.id,
        &user.email,
        user.is_platform_owner,
        oauth_state.org_slug.as_deref(),
        service_slug,
        oauth_state.resource.as_deref(),
    )?;

    let refresh_token = crate::crypto::refresh_tokens::generate();

    // Store session with refresh token
    let token_hash = JwtService::hash_token(&jwt);
    let now = Utc::now();
    let expires_at = now + chrono::Duration::hours(config.jwt_expiration_hours);
    let refresh_expires_at = now + chrono::Duration::days(30);

    create_oauth_session_with_login_audit(
        &state,
        &user.id,
        &token_hash,
        expires_at.naive_utc(),
        &refresh_token,
        refresh_expires_at.naive_utc(),
        oauth_state.org_slug.as_deref(),
        Some(service_id),
        oauth_state.service_slug.as_deref(),
        oauth_state.resource.as_deref(),
        provider,
    )
    .await?;

    // Publish login success event for webhooks
    publish_login_event(
        &state.event_dispatcher,
        &user.id,
        &user.email,
        oauth_state.org_slug.as_deref(),
        Some(service_id),
        Some(provider.as_str()),
    )
    .await;

    // Check if JSON response is requested
    if callback.format.as_ref().is_some_and(|f| f == "json") {
        use serde_json::json;
        let response_body = json!({
            "access_token": jwt,
            "refresh_token": refresh_token,
            "token_type": "Bearer"
        });
        return Ok(Json(response_body).into_response());
    }

    // Redirect to service's redirect_uri with tokens in fragment
    let redirect_url = service_token_redirect_uri(
        redirect_uri,
        &jwt,
        &refresh_token,
        oauth_state.client_state.as_deref(),
    )?;
    Ok(Redirect::to(&redirect_url).into_response())
}

// Helper functions for admin OAuth

/// Unified OAuth client builder to reduce code duplication.
/// Creates an OAuth2 BasicClient for any provider with the given credentials and callback URI.
fn build_oauth_client(
    provider: Provider,
    client_id: String,
    client_secret: String,
    callback_uri: String,
    config: &crate::config::Config,
) -> Result<ConfiguredBasicClient> {
    let (auth_url, token_url) = match provider {
        Provider::Github => (
            config
                .platform_github_auth_url
                .clone()
                .unwrap_or_else(|| "https://github.com/login/oauth/authorize".to_string()),
            config
                .platform_github_token_url
                .clone()
                .unwrap_or_else(|| "https://github.com/login/oauth/access_token".to_string()),
        ),
        Provider::Google => (
            config
                .platform_google_auth_url
                .clone()
                .unwrap_or_else(|| "https://accounts.google.com/o/oauth2/v2/auth".to_string()),
            config
                .platform_google_token_url
                .clone()
                .unwrap_or_else(|| "https://oauth2.googleapis.com/token".to_string()),
        ),
        Provider::Microsoft => (
            config
                .platform_microsoft_auth_url
                .clone()
                .unwrap_or_else(|| {
                    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize".to_string()
                }),
            config
                .platform_microsoft_token_url
                .clone()
                .unwrap_or_else(|| {
                    "https://login.microsoftonline.com/common/oauth2/v2.0/token".to_string()
                }),
        ),
        Provider::Oidc => {
            return Err(AppError::InternalServerError(
                "OIDC not supported in build_oauth_client".to_string(),
            ));
        }
        Provider::Password => {
            return Err(AppError::InternalServerError(
                "Password provider not supported in build_oauth_client".to_string(),
            ));
        }
    };

    configured_basic_client(client_id, client_secret, auth_url, token_url, callback_uri)
}

fn create_admin_oauth_client(
    config: &crate::config::Config,
    provider: Provider,
) -> Result<ConfiguredBasicClient> {
    let (client_id, client_secret) = match provider {
        Provider::Github => {
            let client_id = config.platform_github_client_id.as_ref()
                .ok_or_else(|| AppError::BadRequest(
                    "GitHub OAuth provider is not configured. Please set PLATFORM_GITHUB_CLIENT_ID and PLATFORM_GITHUB_CLIENT_SECRET environment variables.".to_string()
                ))?;
            let client_secret = config.platform_github_client_secret.as_ref()
                .ok_or_else(|| AppError::BadRequest(
                    "GitHub OAuth provider is not configured. Please set PLATFORM_GITHUB_CLIENT_ID and PLATFORM_GITHUB_CLIENT_SECRET environment variables.".to_string()
                ))?;
            (client_id.clone(), client_secret.clone())
        }
        Provider::Google => {
            let client_id = config.platform_google_client_id.as_ref()
                .ok_or_else(|| AppError::BadRequest(
                    "Google OAuth provider is not configured. Please set PLATFORM_GOOGLE_CLIENT_ID and PLATFORM_GOOGLE_CLIENT_SECRET environment variables.".to_string()
                ))?;
            let client_secret = config.platform_google_client_secret.as_ref()
                .ok_or_else(|| AppError::BadRequest(
                    "Google OAuth provider is not configured. Please set PLATFORM_GOOGLE_CLIENT_ID and PLATFORM_GOOGLE_CLIENT_SECRET environment variables.".to_string()
                ))?;
            (client_id.clone(), client_secret.clone())
        }
        Provider::Microsoft => {
            let client_id = config.platform_microsoft_client_id.as_ref()
                .ok_or_else(|| AppError::BadRequest(
                    "Microsoft OAuth provider is not configured. Please set PLATFORM_MICROSOFT_CLIENT_ID and PLATFORM_MICROSOFT_CLIENT_SECRET environment variables.".to_string()
                ))?;
            let client_secret = config.platform_microsoft_client_secret.as_ref()
                .ok_or_else(|| AppError::BadRequest(
                    "Microsoft OAuth provider is not configured. Please set PLATFORM_MICROSOFT_CLIENT_ID and PLATFORM_MICROSOFT_CLIENT_SECRET environment variables.".to_string()
                ))?;
            (client_id.clone(), client_secret.clone())
        }
        Provider::Oidc => {
            return Err(AppError::BadRequest(
                "OIDC provider not supported for admin login".to_string(),
            ));
        }
        Provider::Password => {
            return Err(AppError::BadRequest(
                "Password provider not supported for admin login".to_string(),
            ));
        }
    };

    // Admin callback URL - this is what's registered in provider consoles
    let callback_uri = format!(
        "{}/auth/admin/{}/callback",
        config.base_url,
        provider.as_str()
    );

    build_oauth_client(provider, client_id, client_secret, callback_uri, config)
}

fn get_admin_authorization_url(
    client: &ConfiguredBasicClient,
    provider: Provider,
    scopes: Vec<String>,
) -> (String, CsrfToken, String) {
    use oauth2::Scope;

    let scopes_oauth: Vec<Scope> = scopes.into_iter().map(Scope::new).collect();

    // Generate PKCE challenge for all OAuth/OIDC providers.
    let (pkce_challenge, pkce_verifier) = if matches!(
        provider,
        Provider::Github | Provider::Google | Provider::Microsoft | Provider::Oidc
    ) {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        (Some(challenge), Some(verifier))
    } else {
        (None, None)
    };

    let mut auth_request = client
        .authorize_url(CsrfToken::new_random)
        .add_scopes(scopes_oauth);

    if let Some(challenge) = pkce_challenge {
        auth_request = auth_request.set_pkce_challenge(challenge);
    }

    let (auth_url, csrf_token) = auth_request.url();

    let verifier_secret = pkce_verifier
        .map(|v| v.secret().clone())
        .unwrap_or_default();

    (auth_url.to_string(), csrf_token, verifier_secret)
}

async fn exchange_admin_code(
    client: &ConfiguredBasicClient,
    _provider: Provider,
    code: &str,
    pkce_verifier: Option<&str>,
) -> Result<crate::crypto::sso::TokenDetails> {
    use oauth2::{AuthorizationCode, TokenResponse};

    let mut token_request = client.exchange_code(AuthorizationCode::new(code.to_string()));

    if let Some(verifier) = pkce_verifier {
        token_request =
            token_request.set_pkce_verifier(PkceCodeVerifier::new(verifier.to_string()));
    }

    let token = token_request
        .request_async(&oauth_http_client)
        .await
        .map_err(|e| AppError::OAuth(format!("Token exchange failed: {}", e)))?;

    let expires_at = token
        .expires_in()
        .map(|duration| Utc::now() + chrono::Duration::seconds(duration.as_secs() as i64));

    let scopes = token
        .scopes()
        .map(|scopes| scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        .unwrap_or_default();

    Ok(crate::crypto::sso::TokenDetails {
        access_token: token.access_token().secret().clone(),
        refresh_token: token.refresh_token().map(|rt| rt.secret().clone()),
        expires_at,
        scopes,
    })
}

async fn exchange_custom_code(
    client: &ConfiguredBasicClient,
    _provider: Provider,
    code: &str,
    pkce_verifier: Option<&str>,
) -> Result<crate::crypto::sso::TokenDetails> {
    use oauth2::{AuthorizationCode, TokenResponse};

    let mut token_request = client.exchange_code(AuthorizationCode::new(code.to_string()));

    if let Some(verifier) = pkce_verifier {
        token_request =
            token_request.set_pkce_verifier(PkceCodeVerifier::new(verifier.to_string()));
    }

    let token = token_request
        .request_async(&oauth_http_client)
        .await
        .map_err(|e| AppError::OAuth(format!("Token exchange failed: {}", e)))?;

    let expires_at = token
        .expires_in()
        .map(|duration| Utc::now() + chrono::Duration::seconds(duration.as_secs() as i64));

    let scopes = token
        .scopes()
        .map(|scopes| scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        .unwrap_or_default();

    Ok(crate::crypto::sso::TokenDetails {
        access_token: token.access_token().secret().clone(),
        refresh_token: token.refresh_token().map(|rt| rt.secret().clone()),
        expires_at,
        scopes,
    })
}

// Helper functions for BYOO (Bring Your Own OAuth)

fn validate_redirect_uri(redirect_uri: &str, service: &crate::db::models::Service) -> Result<()> {
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

fn redirect_uri_with_fragment(redirect_uri: &str, pairs: &[(&str, &str)]) -> Result<String> {
    let mut url = url::Url::parse(redirect_uri)
        .map_err(|_| AppError::BadRequest("Invalid redirect_uri".to_string()))?;
    let mut existing: Vec<(String, String)> = url
        .fragment()
        .map(|fragment| {
            url::form_urlencoded::parse(fragment.as_bytes())
                .into_owned()
                .collect()
        })
        .unwrap_or_default();

    existing.retain(|(key, _)| !pairs.iter().any(|(pair_key, _)| pair_key == key));
    existing.extend(
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string())),
    );

    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in existing {
        serializer.append_pair(&key, &value);
    }
    url.set_fragment(Some(&serializer.finish()));
    Ok(url.to_string())
}

fn service_token_redirect_uri(
    redirect_uri: &str,
    access_token: &str,
    refresh_token: &str,
    client_state: Option<&str>,
) -> Result<String> {
    let mut pairs = vec![
        ("access_token", access_token),
        ("refresh_token", refresh_token),
    ];
    if let Some(client_state) = client_state {
        pairs.push(("state", client_state));
    }
    redirect_uri_with_fragment(redirect_uri, &pairs)
}

fn hosted_service_mfa_redirect_uri(
    authos_base_url: &str,
    service_redirect_uri: &str,
    preauth_token: &str,
    org_slug: Option<&str>,
    service_slug: Option<&str>,
    client_state: Option<&str>,
) -> Result<String> {
    let mut url = url::Url::parse(authos_base_url)
        .map_err(|_| AppError::InternalServerError("Invalid AuthOS base URL".to_string()))?;
    url.set_path("/callback");
    url.set_query(None);
    url.set_fragment(None);
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("redirect_uri", service_redirect_uri);
        if let Some(org_slug) = org_slug {
            query.append_pair("org", org_slug);
        }
        if let Some(service_slug) = service_slug {
            query.append_pair("service", service_slug);
        }
        if let Some(client_state) = client_state {
            query.append_pair("state", client_state);
        }
    }
    let mut fragment = url::form_urlencoded::Serializer::new(String::new());
    fragment
        .append_pair("preauth_token", preauth_token)
        .append_pair("mfa_required", "true");
    url.set_fragment(Some(&fragment.finish()));
    Ok(url.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SamlLoginGate {
    Block,
    ChallengeMfa,
    Complete,
}

fn saml_login_gate(
    risk_action: Option<crate::services::risk_engine::RiskAction>,
    mfa_enabled: bool,
) -> SamlLoginGate {
    use crate::services::risk_engine::RiskAction;

    match risk_action {
        Some(RiskAction::Block) => SamlLoginGate::Block,
        Some(RiskAction::ChallengeMFA) => SamlLoginGate::ChallengeMfa,
        Some(RiskAction::Allow | RiskAction::LogOnly) | None if mfa_enabled => {
            SamlLoginGate::ChallengeMfa
        }
        Some(RiskAction::Allow | RiskAction::LogOnly) | None => SamlLoginGate::Complete,
    }
}

fn redirect_oauth_error_to_uri(
    redirect_uri: &str,
    error: &str,
    description: Option<&str>,
) -> Result<Response> {
    let mut redirect_url = url::Url::parse(redirect_uri)
        .map_err(|_| AppError::InternalServerError("Invalid OAuth redirect URI".to_string()))?;

    redirect_url
        .query_pairs_mut()
        .append_pair("error", error)
        .append_pair("error_description", description.unwrap_or(error));

    Ok(Redirect::to(redirect_url.as_str()).into_response())
}

fn redirect_oauth_error_to_platform(
    config: &crate::config::Config,
    error: &str,
    description: Option<&str>,
) -> Result<Response> {
    let redirect_base = format!("{}/callback", config.platform_dashboard_base_url);
    redirect_oauth_error_to_uri(&redirect_base, error, description)
}

fn redirect_oauth_error_to_lite(
    base_url: &str,
    return_to: &str,
    error: &str,
    description: Option<&str>,
) -> Result<Response> {
    let redirect_base = format!("{}/callback", base_url.trim_end_matches('/'));
    let mut redirect_url = url::Url::parse(&redirect_base)
        .map_err(|_| AppError::InternalServerError("Invalid Lite callback URI".to_string()))?;

    redirect_url
        .query_pairs_mut()
        .append_pair("redirect", return_to)
        .append_pair("error", error)
        .append_pair("error_description", description.unwrap_or(error));

    Ok(Redirect::to(redirect_url.as_str()).into_response())
}

fn normalize_lite_return_to(value: Option<&str>) -> Result<Option<String>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };

    let is_internal_path = value.starts_with('/') && !value.starts_with("//");
    let has_control_chars = value.chars().any(|ch| matches!(ch, '\0' | '\n' | '\r'));
    if !is_internal_path || has_control_chars {
        return Err(AppError::BadRequest("Invalid return_to path".to_string()));
    }

    Ok(Some(value.to_string()))
}

fn lite_callback_redirect_uri(
    base_url: &str,
    return_to: Option<&str>,
    pairs: &[(&str, &str)],
) -> Result<String> {
    let redirect_base = format!("{}/callback", base_url.trim_end_matches('/'));
    let mut url = url::Url::parse(&redirect_base)
        .map_err(|_| AppError::InternalServerError("Invalid Lite callback URI".to_string()))?;

    if let Some(return_to) = return_to {
        url.query_pairs_mut().append_pair("redirect", return_to);
    }

    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        serializer.append_pair(key, value);
    }
    url.set_fragment(Some(&serializer.finish()));
    Ok(url.to_string())
}

fn oauth_error_message(error: &AppError) -> String {
    match error {
        AppError::OAuth(message)
        | AppError::BadRequest(message)
        | AppError::Unauthorized(message)
        | AppError::Forbidden(message) => message.clone(),
        _ => "Authentication failed".to_string(),
    }
}

pub fn get_authorization_url_for_client(
    client: &ConfiguredBasicClient,
    provider: Provider,
    scopes: Vec<String>,
) -> (String, CsrfToken, String) {
    use oauth2::Scope;

    let scopes_oauth: Vec<Scope> = scopes.into_iter().map(Scope::new).collect();

    // Generate PKCE challenge for all OAuth/OIDC providers.
    let (pkce_challenge, pkce_verifier) = if matches!(
        provider,
        Provider::Github | Provider::Google | Provider::Microsoft | Provider::Oidc
    ) {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        (Some(challenge), Some(verifier))
    } else {
        (None, None)
    };

    let mut auth_request = client
        .authorize_url(CsrfToken::new_random)
        .add_scopes(scopes_oauth);

    if let Some(challenge) = pkce_challenge {
        auth_request = auth_request.set_pkce_challenge(challenge);
    }

    let (auth_url, csrf_token) = auth_request.url();

    let verifier_secret = pkce_verifier
        .map(|v| v.secret().clone())
        .unwrap_or_default();

    (auth_url.to_string(), csrf_token, verifier_secret)
}

fn require_google_verified_email(verified_email: Option<bool>) -> Result<()> {
    if verified_email == Some(true) {
        return Ok(());
    }

    Err(AppError::OAuth(
        "Google account email is not verified".to_string(),
    ))
}

/// GitHub's `/user` email field is not an authorization assertion. Always
/// resolve the verified primary address (or a verified exact match for the
/// public address) from `/user/emails`, which requires the `user:email` scope.
fn select_github_verified_email(
    public_email: Option<&str>,
    emails: &[(String, bool, bool)],
) -> Option<String> {
    if let Some((email, _, _)) = emails
        .iter()
        .find(|(_, primary, verified)| *primary && *verified)
    {
        return Some(email.clone());
    }
    let public_email = public_email?;
    emails
        .iter()
        .find(|(email, _, verified)| *verified && email.eq_ignore_ascii_case(public_email))
        .map(|(email, _, _)| email.clone())
}

/// Get user info from provider (standalone, not using OAuth client for BYOO isolation)
async fn get_provider_user_info(
    provider: Provider,
    access_token: &str,
    config: &crate::config::Config,
) -> Result<crate::crypto::sso::UserInfo> {
    use serde::de::DeserializeOwned;
    use serde::Deserialize;

    async fn fetch_json<T: DeserializeOwned>(
        client: &crate::crypto::safe_http::SafeHttpClient,
        url: &str,
        access_token: &str,
        include_user_agent: bool,
    ) -> Result<T> {
        let mut headers = vec![(
            "Authorization".to_string(),
            format!("Bearer {access_token}"),
        )];
        if include_user_agent {
            headers.push(("User-Agent".to_string(), "AuthOS".to_string()));
        }

        let response = client.get_with_owned_headers(url, headers).await?;
        let (status, body) = crate::crypto::safe_http::SafeHttpClient::read_body_limited(
            response,
            crate::crypto::safe_http::MAX_OAUTH_RESPONSE_BYTES,
        )
        .await?;
        if !status.is_success() {
            return Err(AppError::OAuth(format!(
                "OAuth provider user-info request failed with status {status}"
            )));
        }

        serde_json::from_slice(&body)
            .map_err(|_| AppError::OAuth("OAuth provider returned invalid user info".to_string()))
    }

    let client = crate::crypto::safe_http::SafeHttpClient::new()?;

    match provider {
        Provider::Github => {
            #[derive(Deserialize)]
            struct GithubUser {
                id: u64,
                email: Option<String>,
                name: Option<String>,
            }

            #[derive(Deserialize)]
            struct GithubEmail {
                email: String,
                primary: bool,
                verified: bool,
            }

            let user: GithubUser = fetch_json(
                &client,
                &config.get_github_user_api_url(),
                access_token,
                true,
            )
            .await?;
            let emails: Vec<GithubEmail> = fetch_json(
                &client,
                &config.get_github_user_emails_api_url(),
                access_token,
                true,
            )
            .await?;
            let email_claims = emails
                .into_iter()
                .map(|email| (email.email, email.primary, email.verified))
                .collect::<Vec<_>>();
            let email = select_github_verified_email(user.email.as_deref(), &email_claims)
                .ok_or_else(|| AppError::OAuth("No verified email found".to_string()))?;

            Ok(crate::crypto::sso::UserInfo {
                provider_user_id: user.id.to_string(),
                email,
                name: user.name,
            })
        }
        Provider::Google => {
            #[derive(Deserialize)]
            struct GoogleUser {
                id: String,
                email: String,
                name: Option<String>,
                #[serde(alias = "email_verified")]
                verified_email: Option<bool>,
            }

            let user: GoogleUser = fetch_json(
                &client,
                &config.get_google_user_api_url(),
                access_token,
                false,
            )
            .await?;

            require_google_verified_email(user.verified_email)?;

            Ok(crate::crypto::sso::UserInfo {
                provider_user_id: user.id,
                email: user.email,
                name: user.name,
            })
        }
        Provider::Microsoft => {
            #[derive(Deserialize)]
            struct MicrosoftUser {
                id: String,
                #[serde(rename = "userPrincipalName")]
                user_principal_name: Option<String>,
                mail: Option<String>,
                #[serde(rename = "displayName")]
                name: Option<String>,
            }

            let user: MicrosoftUser = fetch_json(
                &client,
                &config.get_microsoft_user_api_url(),
                access_token,
                false,
            )
            .await?;

            // UPN is the account's sign-in identifier. Prefer it over the
            // mutable `mail` attribute, which a tenant administrator can set
            // independently of the login identity.
            let email = user.user_principal_name.or(user.mail).ok_or_else(|| {
                AppError::OAuth("Microsoft user profile did not include an email".to_string())
            })?;

            Ok(crate::crypto::sso::UserInfo {
                provider_user_id: user.id,
                email,
                name: user.name,
            })
        }
        Provider::Oidc => Err(AppError::BadRequest(
            "OIDC not supported in generic get_provider_user_info".to_string(),
        )),
        Provider::Password => Err(AppError::BadRequest(
            "Password provider not supported in generic get_provider_user_info".to_string(),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
async fn create_oauth_session_with_login_audit(
    state: &AppState,
    user_id: &str,
    token_hash: &str,
    expires_at: chrono::NaiveDateTime,
    refresh_token: &str,
    refresh_expires_at: chrono::NaiveDateTime,
    org_slug: Option<&str>,
    service_id: Option<&str>,
    service_slug: Option<&str>,
    resource: Option<&str>,
    provider: Provider,
) -> Result<()> {
    use crate::entities::login_events;
    use sea_orm::Set;
    use uuid::Uuid;

    let event_model = login_events::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        user_id: Set(user_id.to_string()),
        service_id: Set(service_id.map(str::to_string)),
        provider: Set(provider.as_str().to_string()),
        ..Default::default()
    };
    let user_id = user_id.to_string();
    let token_hash = token_hash.to_string();
    let refresh_token = refresh_token.to_string();
    let org_slug = org_slug.map(str::to_string);
    let service_id = service_id.map(str::to_string);
    let service_slug = service_slug.map(str::to_string);
    let resource = resource.map(str::to_string);
    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "create_oauth_session_with_login_audit",
        |db| {
            let user_id = user_id.clone();
            let token_hash = token_hash.clone();
            let refresh_token = refresh_token.clone();
            let org_slug = org_slug.clone();
            let service_id = service_id.clone();
            let service_slug = service_slug.clone();
            let resource = resource.clone();
            let event_model = event_model.clone();
            let audit_actor = state.audit_actor.clone();
            Box::pin(async move {
                validate_live_oauth_tenant_context(
                    db.clone(),
                    None,
                    org_slug.as_deref(),
                    service_id.as_deref(),
                    service_slug.as_deref(),
                    None,
                    resource.as_deref(),
                )
                .await?;
                if let Some(org_slug) = org_slug.as_deref() {
                    let org = OrganizationStore::find_by_slug(db.clone(), org_slug)
                        .await?
                        .filter(|org| org.status == "active")
                        .ok_or_else(|| {
                            AppError::Unauthorized("OAuth organization is not active".to_string())
                        })?;
                    validate_live_oauth_user_entitlement(
                        db.clone(),
                        &user_id,
                        &org.id,
                        service_id.as_deref(),
                    )
                    .await?;
                } else {
                    validate_live_oauth_linking_user(db.clone(), &user_id, None, None).await?;
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

async fn validate_live_oauth_tenant_context(
    db: DB<'_>,
    expected_org_id: Option<&str>,
    expected_org_slug: Option<&str>,
    expected_service_id: Option<&str>,
    expected_service_slug: Option<&str>,
    expected_redirect_uri: Option<&str>,
    expected_resource: Option<&str>,
) -> Result<()> {
    if expected_org_id.is_none() && expected_org_slug.is_none() {
        if expected_service_id.is_some() {
            return Err(AppError::Unauthorized(
                "OAuth service context is missing its organization".to_string(),
            ));
        }
        return Ok(());
    }

    let org = if let Some(org_id) = expected_org_id {
        OrganizationStore::find_by_id(db.clone(), org_id).await?
    } else {
        OrganizationStore::find_by_slug(
            db.clone(),
            expected_org_slug.expect("checked organization context"),
        )
        .await?
    }
    .filter(|org| org.status == "active")
    .ok_or_else(|| AppError::Unauthorized("OAuth organization is not active".to_string()))?;

    if expected_org_id.is_some_and(|org_id| org.id != org_id)
        || expected_org_slug.is_some_and(|org_slug| org.slug != org_slug)
    {
        return Err(AppError::Unauthorized(
            "OAuth organization context changed".to_string(),
        ));
    }

    if let Some(service_id) = expected_service_id {
        let service = ServiceStore::find_by_id(db, service_id)
            .await?
            .filter(|service| service.org_id == org.id)
            .ok_or_else(|| {
                AppError::Unauthorized(
                    "OAuth service does not belong to the selected organization".to_string(),
                )
            })?;
        if expected_service_slug.is_some_and(|slug| service.slug != slug) {
            return Err(AppError::Unauthorized(
                "OAuth service context changed".to_string(),
            ));
        }
        let service: crate::db::models::Service = service.into();
        if let Some(redirect_uri) = expected_redirect_uri {
            validate_redirect_uri(redirect_uri, &service)?;
        }
        validate_requested_resource(expected_resource, service.resource_uris.as_deref())?;
    } else if expected_service_slug.is_some()
        || expected_redirect_uri.is_some()
        || expected_resource.is_some()
    {
        return Err(AppError::Unauthorized(
            "OAuth service context is incomplete".to_string(),
        ));
    }

    Ok(())
}

async fn validate_live_oauth_user_entitlement(
    db: DB<'_>,
    user_id: &str,
    org_id: &str,
    service_id: Option<&str>,
) -> Result<()> {
    let user = crate::store::users::UserStore::find_by_id(db.clone(), user_id)
        .await?
        .filter(|user| user.deleted_at.is_none())
        .ok_or_else(|| AppError::Unauthorized("OAuth user is no longer active".to_string()))?;
    if user.is_platform_owner
        || MembershipStore::find_by_org_and_user(db.clone(), org_id, user_id)
            .await?
            .is_some()
    {
        return Ok(());
    }
    if let Some(service_id) = service_id {
        if IdentityStore::exists_for_user_and_service_context(db, user_id, org_id, service_id)
            .await?
        {
            return Ok(());
        }
    }
    Err(AppError::Unauthorized(
        "OAuth user no longer has tenant entitlement".to_string(),
    ))
}

async fn validate_live_oauth_linking_user(
    db: DB<'_>,
    user_id: &str,
    org_id: Option<&str>,
    service_id: Option<&str>,
) -> Result<()> {
    if let Some(org_id) = org_id {
        return validate_live_oauth_user_entitlement(db, user_id, org_id, service_id).await;
    }
    crate::store::users::UserStore::find_by_id(db, user_id)
        .await?
        .filter(|user| user.deleted_at.is_none())
        .ok_or_else(|| AppError::Unauthorized("OAuth user is no longer active".to_string()))?;
    Ok(())
}

/// Helper function to publish login success event
pub async fn publish_login_event(
    event_dispatcher: &Arc<crate::services::events::EventDispatcher>,
    user_id: &str,
    user_email: &str,
    org_id: Option<&str>,
    service_id: Option<&str>,
    provider: Option<&str>,
) {
    use crate::services::events::{Event, EventType};
    use serde_json::json;

    let mut event_builder = Event::builder(EventType::UserLoginSuccess)
        .actor_user_id(user_id)
        .actor_email(user_email);

    if let Some(org) = org_id {
        event_builder = event_builder.org_id(org);
    }

    if let Some(svc) = service_id {
        event_builder = event_builder.detail("service_id", json!(svc));
    }

    if let Some(prov) = provider {
        event_builder = event_builder.detail("provider", json!(prov));
    }

    let event = event_builder.build();

    // Fire and forget
    let dispatcher = event_dispatcher.clone();
    tokio::spawn(async move {
        if let Err(e) = dispatcher.publish(event).await {
            tracing::error!("Failed to publish login event: {}", e);
        }
    });
}

/// Check if a user has MFA enabled
async fn is_mfa_enabled(pool: &DatabaseConnection, user_id: &str) -> Result<bool> {
    crate::store::totp::TotpStore::is_enabled(DB::Conn(pool), user_id).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::config::Config;
    use crate::crypto::sso::OAuthClient;
    use crate::entities::provider_token_requests;

    use crate::audit::actor::AuditHandle;
    use crate::services::{
        events::EventDispatcher, metrics::MfaMetricsService, risk_engine::RiskEngine,
    };
    use crate::store::{
        users::{UserCreationOptions, UserStore},
        verified_domains::VerifiedDomainStore,
    };
    use axum::http::header::LOCATION;

    use chrono::{Duration, Utc};
    use migration::{Migrator, MigratorTrait};
    use moka::future::Cache;
    use sea_orm::{
        ActiveModelTrait, ConnectionTrait, Database, EntityTrait, PaginatorTrait, QueryFilter,
    };
    use std::sync::Arc;

    #[test]
    fn device_oauth_completion_requires_exact_stored_context_and_current_owner() {
        assert!(validate_service_device_oauth_context("acme", "portal", "acme", "portal").is_ok());
        assert!(
            validate_service_device_oauth_context("other", "portal", "acme", "portal").is_err()
        );
        assert!(validate_service_device_oauth_context("acme", "other", "acme", "portal").is_err());

        assert!(validate_platform_device_oauth_context(
            "platform",
            "admin-cli",
            Some("platform"),
            true,
        )
        .is_ok());
        assert!(validate_platform_device_oauth_context(
            "platform",
            "admin-cli",
            Some("platform"),
            false,
        )
        .is_err());
        assert!(
            validate_platform_device_oauth_context("acme", "portal", Some("platform"), true,)
                .is_err()
        );
    }
    use uuid::Uuid;

    #[tokio::test]
    async fn oauth_completion_reauthorizes_active_exact_tenant_service_and_registered_targets() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        let owner = UserStore::create(
            DB::Conn(&db),
            "oauth-context-owner@example.test",
            None,
            true,
        )
        .await
        .unwrap();
        let org_a = OrganizationStore::create(
            DB::Conn(&db),
            "oauth-context-a",
            "OAuth context A",
            &owner.id,
            None,
        )
        .await
        .unwrap();
        let org_b = OrganizationStore::create(
            DB::Conn(&db),
            "oauth-context-b",
            "OAuth context B",
            &owner.id,
            None,
        )
        .await
        .unwrap();
        OrganizationStore::update_status(DB::Conn(&db), &org_a.id, "active")
            .await
            .unwrap();
        OrganizationStore::update_status(DB::Conn(&db), &org_b.id, "active")
            .await
            .unwrap();
        let service_a = ServiceStore::create(
            DB::Conn(&db),
            &org_a.id,
            "portal-a",
            "Portal A",
            "web",
            "oauth-context-client-a",
        )
        .await
        .unwrap();
        let service_b = ServiceStore::create(
            DB::Conn(&db),
            &org_b.id,
            "portal-b",
            "Portal B",
            "web",
            "oauth-context-client-b",
        )
        .await
        .unwrap();
        let mut service_a_active: crate::entities::services::ActiveModel = service_a.clone().into();
        service_a_active.redirect_uris = Set(Some(
            serde_json::json!(["https://client.example.test/callback"]).to_string(),
        ));
        service_a_active.resource_uris = Set(Some(
            serde_json::json!(["https://api.example.test/"]).to_string(),
        ));
        let service_a = service_a_active.update(&db).await.unwrap();

        assert!(validate_live_oauth_tenant_context(
            DB::Conn(&db),
            Some(&org_a.id),
            Some(&org_a.slug),
            Some(&service_a.id),
            Some(&service_a.slug),
            Some("https://client.example.test/callback"),
            Some("https://api.example.test/")
        )
        .await
        .is_ok());
        assert!(validate_live_oauth_tenant_context(
            DB::Conn(&db),
            Some(&org_a.id),
            Some(&org_a.slug),
            Some(&service_b.id),
            Some(&service_b.slug),
            Some("https://client.example.test/callback"),
            None
        )
        .await
        .is_err());
        assert!(validate_live_oauth_tenant_context(
            DB::Conn(&db),
            Some(&org_a.id),
            Some(&org_a.slug),
            Some(&service_a.id),
            Some("substituted-service"),
            Some("https://attacker.example.test/callback"),
            Some("https://attacker.example.test/")
        )
        .await
        .is_err());

        OrganizationStore::update_status(DB::Conn(&db), &org_a.id, "suspended")
            .await
            .unwrap();
        assert!(validate_live_oauth_tenant_context(
            DB::Conn(&db),
            Some(&org_a.id),
            Some(&org_a.slug),
            Some(&service_a.id),
            Some(&service_a.slug),
            Some("https://client.example.test/callback"),
            Some("https://api.example.test/")
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn suspended_tenant_session_completion_leaves_session_and_audit_unchanged() {
        let state = setup_oauth_state().await;
        let user = UserStore::create(
            DB::Conn(&state.db),
            "oauth-suspended-user@example.test",
            None,
            false,
        )
        .await
        .unwrap();
        let org = OrganizationStore::create(
            DB::Conn(&state.db),
            "oauth-suspended",
            "OAuth suspended",
            &user.id,
            None,
        )
        .await
        .unwrap();
        let service = ServiceStore::create(
            DB::Conn(&state.db),
            &org.id,
            "portal",
            "Portal",
            "web",
            "oauth-suspended-client",
        )
        .await
        .unwrap();
        OrganizationStore::update_status(DB::Conn(&state.db), &org.id, "suspended")
            .await
            .unwrap();
        let before_audits = crate::entities::login_events::Entity::find()
            .count(&state.db)
            .await
            .unwrap();
        let now = Utc::now();

        assert!(create_oauth_session_with_login_audit(
            &state,
            &user.id,
            "suspended-token-hash",
            (now + Duration::hours(1)).naive_utc(),
            "suspended-refresh-token",
            (now + Duration::days(30)).naive_utc(),
            Some(&org.slug),
            Some(&service.id),
            Some(&service.slug),
            None,
            Provider::Github,
        )
        .await
        .is_err());
        assert_eq!(
            crate::entities::sessions::Entity::find()
                .count(&state.db)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            crate::entities::login_events::Entity::find()
                .count(&state.db)
                .await
                .unwrap(),
            before_audits
        );
    }

    #[tokio::test]
    async fn deleted_user_session_completion_leaves_session_and_audit_unchanged() {
        let state = setup_oauth_state().await;
        let user = UserStore::create(
            DB::Conn(&state.db),
            "oauth-deleted-user@example.test",
            None,
            false,
        )
        .await
        .unwrap();
        let mut deleted_user: crate::entities::users::ActiveModel = user.clone().into();
        deleted_user.deleted_at = Set(Some(Utc::now().naive_utc()));
        deleted_user.update(&state.db).await.unwrap();
        let before_audits = crate::entities::login_events::Entity::find()
            .count(&state.db)
            .await
            .unwrap();
        let now = Utc::now();

        assert!(create_oauth_session_with_login_audit(
            &state,
            &user.id,
            "deleted-token-hash",
            (now + Duration::hours(1)).naive_utc(),
            "deleted-refresh-token",
            (now + Duration::days(30)).naive_utc(),
            None,
            None,
            None,
            None,
            Provider::Github,
        )
        .await
        .is_err());
        assert_eq!(
            crate::entities::sessions::Entity::find()
                .count(&state.db)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            crate::entities::login_events::Entity::find()
                .count(&state.db)
                .await
                .unwrap(),
            before_audits
        );
    }

    #[tokio::test]
    async fn oauth_session_rolls_back_when_success_audit_cannot_enqueue() {
        let state = setup_oauth_state().await;
        let user = UserStore::find_or_create_with_options(
            DB::Conn(&state.db),
            "oauth-audit-rollback@example.test",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .0;
        state
            .db
            .execute_unprepared("DROP TABLE audit_outbox")
            .await
            .unwrap();

        let now = Utc::now();
        assert!(create_oauth_session_with_login_audit(
            &state,
            &user.id,
            "token-hash",
            (now + Duration::hours(1)).naive_utc(),
            "refresh-token",
            (now + Duration::days(30)).naive_utc(),
            None,
            None,
            None,
            None,
            Provider::Github,
        )
        .await
        .is_err());
        assert_eq!(
            crate::entities::sessions::Entity::find()
                .count(&state.db)
                .await
                .unwrap(),
            0
        );
    }

    #[test]
    fn saml_login_gate_blocks_or_challenges_before_assertion_issuance() {
        use crate::services::risk_engine::RiskAction;

        assert_eq!(
            saml_login_gate(Some(RiskAction::Block), false),
            SamlLoginGate::Block
        );
        assert_eq!(
            saml_login_gate(Some(RiskAction::Block), true),
            SamlLoginGate::Block
        );
        assert_eq!(
            saml_login_gate(Some(RiskAction::ChallengeMFA), false),
            SamlLoginGate::ChallengeMfa
        );
        assert_eq!(
            saml_login_gate(Some(RiskAction::Allow), true),
            SamlLoginGate::ChallengeMfa
        );
        assert_eq!(
            saml_login_gate(Some(RiskAction::LogOnly), false),
            SamlLoginGate::Complete
        );
        assert_eq!(saml_login_gate(None, false), SamlLoginGate::Complete);
    }

    #[test]
    fn callback_requires_nonempty_state() {
        for state in [None, Some(String::new())] {
            let callback = CallbackQuery {
                code: Some("authorization-code".to_string()),
                state,
                error: None,
                error_description: None,
                format: None,
            };
            assert!(matches!(
                callback.state_parameter(),
                Err(AppError::BadRequest(_))
            ));
        }

        let callback = CallbackQuery {
            code: Some("authorization-code".to_string()),
            state: Some("issued-state".to_string()),
            error: None,
            error_description: None,
            format: None,
        };
        assert_eq!(callback.state_parameter().unwrap(), "issued-state");
    }

    fn test_config() -> Config {
        Config {
            platform_github_client_id: Some("github-client".to_string()),
            platform_github_client_secret: Some("github-secret".to_string()),
            platform_github_auth_url: Some("https://idp.example.com/github/authorize".to_string()),
            platform_github_token_url: Some("https://idp.example.com/github/token".to_string()),
            ..crate::test_support::test_config()
        }
    }

    use crate::test_support::test_jwt_service;

    async fn setup_oauth_state() -> AppState {
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

    async fn create_org_service(
        state: &AppState,
        org_slug: &str,
        org_name: &str,
        service_slug: &str,
        redirect_uris: Option<&str>,
        resource_uris: Option<&str>,
    ) -> (
        crate::entities::organizations::Model,
        crate::entities::services::Model,
    ) {
        let owner = UserStore::find_or_create_with_options(
            DB::Conn(&state.db),
            &format!("owner-{}@example.com", org_slug),
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
            DB::Conn(&state.db),
            org_slug,
            org_name,
            &owner.id,
            Some("tier_enterprise"),
        )
        .await
        .expect("create org");
        let service = ServiceStore::create_with_options(
            DB::Conn(&state.db),
            &Uuid::new_v4().to_string(),
            &org.id,
            service_slug,
            "Portal",
            "web",
            &format!("client-{}", service_slug),
            "secret-hash",
            None,
            None,
            None,
            redirect_uris,
            None,
            resource_uris,
        )
        .await
        .expect("create service");

        (org, service)
    }

    fn oauth_state_from_redirect(location: &str) -> String {
        let parsed = url::Url::parse(location).expect("parse redirect");
        parsed
            .query_pairs()
            .find_map(|(key, value)| {
                (key == "state" || key == "RelayState").then(|| value.into_owned())
            })
            .expect("state in redirect")
    }

    #[tokio::test]
    async fn orphan_provider_duplicate_transfer_updates_matching_rows_in_bulk() {
        use crate::entities::prelude::{ConnectedAccounts, Identities};
        use crate::entities::{connected_accounts, identities};

        let state = setup_oauth_state().await;
        let target_user = UserStore::find_or_create_with_options(
            DB::Conn(&state.db),
            "target@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create target user")
        .0;
        let duplicate_user = UserStore::find_or_create_with_options(
            DB::Conn(&state.db),
            "duplicate@example.com",
            UserCreationOptions::default(),
        )
        .await
        .expect("create duplicate user")
        .0;

        IdentityStore::create(
            DB::Conn(&state.db),
            &duplicate_user.id,
            "github",
            "provider-user-1",
            Some("access-token"),
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
        .expect("create duplicate identity");
        connected_accounts::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            user_id: Set(duplicate_user.id.clone()),
            provider: Set("github".to_string()),
            provider_user_id: Set("provider-user-1".to_string()),
            email: Set(Some("duplicate@example.com".to_string())),
            display_name: Set(Some("Duplicate".to_string())),
            access_token: Set(Some("access-token".to_string())),
            refresh_token: Set(None),
            access_token_encrypted: Set(None),
            refresh_token_encrypted: Set(None),
            encryption_key_id: Set(None),
            expires_at: Set(None),
            scopes: Set(Some(r#"["read:user"]"#.to_string())),
            last_refreshed_at: Set(None),
            status: Set("active".to_string()),
            linked_at: Set(Utc::now().naive_utc()),
            updated_at: Set(Utc::now().naive_utc()),
            revoked_at: Set(None),
        }
        .insert(&state.db)
        .await
        .expect("create duplicate connected account");

        let transferred = transfer_orphan_provider_duplicate(
            &state,
            &duplicate_user.id,
            &target_user.id,
            None,
            None,
            "github",
            "provider-user-1",
        )
        .await
        .expect("transfer duplicate");

        assert!(transferred);
        assert_eq!(
            Identities::find()
                .filter(identities::Column::UserId.eq(&target_user.id))
                .count(&state.db)
                .await
                .expect("count target identities"),
            1
        );
        assert_eq!(
            ConnectedAccounts::find()
                .filter(connected_accounts::Column::UserId.eq(&target_user.id))
                .count(&state.db)
                .await
                .expect("count target accounts"),
            1
        );
        assert_eq!(
            Identities::find()
                .filter(identities::Column::UserId.eq(&duplicate_user.id))
                .count(&state.db)
                .await
                .expect("count duplicate identities"),
            0
        );
        assert_eq!(
            ConnectedAccounts::find()
                .filter(connected_accounts::Column::UserId.eq(&duplicate_user.id))
                .count(&state.db)
                .await
                .expect("count duplicate accounts"),
            0
        );
    }

    #[tokio::test]
    async fn orphan_provider_duplicate_transfer_rejects_extra_identity_rows() {
        use crate::entities::identities;
        use crate::entities::prelude::Identities;

        let state = setup_oauth_state().await;
        let target_user = UserStore::find_or_create_with_options(
            DB::Conn(&state.db),
            "target-extra@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create target user")
        .0;
        let duplicate_user = UserStore::find_or_create_with_options(
            DB::Conn(&state.db),
            "duplicate-extra@example.com",
            UserCreationOptions::default(),
        )
        .await
        .expect("create duplicate user")
        .0;

        IdentityStore::create(
            DB::Conn(&state.db),
            &duplicate_user.id,
            "github",
            "provider-user-1",
            Some("access-token"),
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
        .expect("create matching identity");
        IdentityStore::create(
            DB::Conn(&state.db),
            &duplicate_user.id,
            "google",
            "other-provider-user",
            Some("access-token"),
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
        .expect("create non-matching identity");

        let transferred = transfer_orphan_provider_duplicate(
            &state,
            &duplicate_user.id,
            &target_user.id,
            None,
            None,
            "github",
            "provider-user-1",
        )
        .await
        .expect("attempt transfer duplicate");

        assert!(!transferred);
        assert_eq!(
            Identities::find()
                .filter(identities::Column::UserId.eq(&duplicate_user.id))
                .count(&state.db)
                .await
                .expect("count duplicate identities"),
            2
        );
        assert_eq!(
            Identities::find()
                .filter(identities::Column::UserId.eq(&target_user.id))
                .count(&state.db)
                .await
                .expect("count target identities"),
            0
        );
    }

    #[tokio::test]
    async fn service_authorize_persists_resource_indicator_in_oauth_state() {
        let state = setup_oauth_state().await;
        create_org_service(
            &state,
            "acme",
            "Acme",
            "portal",
            Some(r#"["https://portal.example.com/callback"]"#),
            Some(r#"["https://api.example.com/mcp"]"#),
        )
        .await;

        let response = auth_provider(
            State(state.clone()),
            Path("github".to_string()),
            Query(AuthRequest {
                org: "acme".to_string(),
                service: "portal".to_string(),
                redirect_uri: Some("https://portal.example.com/callback".to_string()),
                state: Some("caller-state".to_string()),
                resource: Some("https://api.example.com/mcp".to_string()),
                user_code: None,
                saml_state: None,
                connection_id: None,
            }),
        )
        .await
        .expect("authorize service oauth");

        let location = response
            .headers()
            .get(LOCATION)
            .expect("redirect location")
            .to_str()
            .expect("location is string");
        let oauth_state = oauth_state_from_redirect(location);
        let persisted = OAuthStateStore::find_by_state(DB::Conn(&state.db), &oauth_state)
            .await
            .expect("load oauth state")
            .expect("oauth state persisted");

        assert_eq!(persisted.org_slug.as_deref(), Some("acme"));
        assert_eq!(persisted.service_slug.as_deref(), Some("portal"));
        assert_eq!(
            persisted.redirect_uri.as_deref(),
            Some("https://portal.example.com/callback")
        );
        assert_eq!(persisted.client_state.as_deref(), Some("caller-state"));
        assert_eq!(
            persisted.resource.as_deref(),
            Some("https://api.example.com/mcp")
        );
        assert!(persisted.pkce_verifier.is_some());
    }

    #[tokio::test]
    async fn service_authorize_persists_shared_upstream_connection_for_callback_resolution() {
        let state = setup_oauth_state().await;
        let (provider_org, _) =
            create_org_service(&state, "idp-owner", "IdP Owner", "admin", None, None).await;
        let (tenant_org, _) = create_org_service(
            &state,
            "acme",
            "Acme",
            "portal",
            Some(r#"["https://portal.example.com/callback"]"#),
            None,
        )
        .await;
        let provider = UpstreamProviderStore::create(
            DB::Conn(&state.db),
            &Uuid::new_v4().to_string(),
            &provider_org.id,
            "okta-main",
            "Okta Main",
            "saml",
            "sp-entity-id",
            Vec::new(),
            "test-key",
            Some("https://idp.example.com/sso"),
            None,
            None,
            None,
            None,
            Some("https://idp.example.com"),
            Some(r#"{"allow_domain_bindings":true}"#),
        )
        .await
        .expect("create shared saml provider");
        let domain = VerifiedDomainStore::create(
            DB::Conn(&state.db),
            &Uuid::new_v4().to_string(),
            &tenant_org.id,
            "acme.com",
            "verify-token",
            Some(&provider.id),
            None,
        )
        .await
        .expect("create domain route");
        VerifiedDomainStore::mark_verified(DB::Conn(&state.db), &domain.id)
            .await
            .expect("verify domain");

        let response = auth_provider(
            State(state.clone()),
            Path("oidc".to_string()),
            Query(AuthRequest {
                org: "acme".to_string(),
                service: "portal".to_string(),
                redirect_uri: Some("https://portal.example.com/callback".to_string()),
                state: Some("caller-state".to_string()),
                resource: None,
                user_code: None,
                saml_state: None,
                connection_id: Some("okta-main".to_string()),
            }),
        )
        .await
        .expect("authorize shared upstream provider");

        let location = response
            .headers()
            .get(LOCATION)
            .expect("redirect location")
            .to_str()
            .expect("location is string");
        let oauth_state = oauth_state_from_redirect(location);
        let persisted = OAuthStateStore::find_by_state(DB::Conn(&state.db), &oauth_state)
            .await
            .expect("load oauth state")
            .expect("oauth state persisted");

        assert_eq!(persisted.org_slug.as_deref(), Some("acme"));
        assert_eq!(persisted.service_slug.as_deref(), Some("portal"));
        assert_eq!(
            persisted.upstream_connection_id.as_deref(),
            Some("okta-main")
        );
        assert_eq!(persisted.client_state.as_deref(), Some("caller-state"));
    }

    #[test]
    fn microsoft_offline_access_is_persisted_when_refresh_token_returned() {
        let requested = vec![
            "openid".to_string(),
            "profile".to_string(),
            "offline_access".to_string(),
            "User.Read".to_string(),
            "Tasks.ReadWrite".to_string(),
        ];
        let returned = vec![
            "openid".to_string(),
            "profile".to_string(),
            "User.Read".to_string(),
            "Tasks.ReadWrite".to_string(),
        ];

        let scopes = normalized_granted_scopes(
            Provider::Microsoft,
            &requested,
            &returned,
            Some("refresh-token"),
        );

        assert!(scopes.iter().any(|scope| scope == "offline_access"));
    }

    #[test]
    fn microsoft_offline_access_is_not_added_without_refresh_token() {
        let requested = vec!["offline_access".to_string(), "User.Read".to_string()];
        let returned = vec!["User.Read".to_string()];

        let scopes = normalized_granted_scopes(Provider::Microsoft, &requested, &returned, None);

        assert!(!scopes.iter().any(|scope| scope == "offline_access"));
    }

    #[test]
    fn github_identity_requires_a_verified_email() {
        let emails = vec![
            ("public-unverified@example.com".to_string(), false, false),
            ("secondary@example.com".to_string(), false, true),
            ("primary@example.com".to_string(), true, true),
        ];
        assert_eq!(
            select_github_verified_email(Some("public-unverified@example.com"), &emails).as_deref(),
            Some("primary@example.com")
        );

        let no_primary = vec![
            ("public-verified@example.com".to_string(), false, true),
            ("other@example.com".to_string(), false, true),
        ];
        assert_eq!(
            select_github_verified_email(Some("public-verified@example.com"), &no_primary)
                .as_deref(),
            Some("public-verified@example.com")
        );

        let unverified = vec![("public@example.com".to_string(), false, false)];
        assert!(select_github_verified_email(Some("public@example.com"), &unverified).is_none());
    }

    #[test]
    fn google_email_must_be_verified() {
        assert!(require_google_verified_email(Some(true)).is_ok());
        assert!(require_google_verified_email(Some(false)).is_err());
        assert!(require_google_verified_email(None).is_err());
    }

    #[test]
    fn provider_token_redirect_preserves_client_state() {
        let now = Utc::now().naive_utc();
        let request = provider_token_requests::Model {
            state: "request-state".to_string(),
            user_id: "user-1".to_string(),
            service_id: "service-1".to_string(),
            provider: "microsoft".to_string(),
            connected_account_id: Some("account-1".to_string()),
            requested_scopes: r#"["User.Read"]"#.to_string(),
            redirect_uri: "act://auth/callback?existing=1".to_string(),
            client_state: Some("client-state".to_string()),
            status: "pending".to_string(),
            created_at: now,
            expires_at: now + Duration::minutes(10),
            completed_at: None,
        };

        let redirect = provider_token_redirect_url(&request).unwrap();
        let parsed = url::Url::parse(&redirect).unwrap();
        let params: std::collections::HashMap<_, _> = parsed.query_pairs().collect();

        assert_eq!(
            params.get("existing").map(std::convert::AsRef::as_ref),
            Some("1")
        );
        assert_eq!(
            params
                .get("provider_grant")
                .map(std::convert::AsRef::as_ref),
            Some("success")
        );
        assert_eq!(
            params.get("provider").map(std::convert::AsRef::as_ref),
            Some("microsoft")
        );
        assert_eq!(
            params.get("state").map(std::convert::AsRef::as_ref),
            Some("client-state")
        );
    }

    #[test]
    fn lite_return_to_accepts_internal_paths_only() {
        assert_eq!(
            normalize_lite_return_to(Some("/app/account-security?org=queuezero"))
                .unwrap()
                .as_deref(),
            Some("/app/account-security?org=queuezero")
        );
        assert!(normalize_lite_return_to(Some("//evil.example")).is_err());
        assert!(normalize_lite_return_to(Some("https://evil.example")).is_err());
        assert!(normalize_lite_return_to(Some("/app/account-security\nbad")).is_err());
    }

    #[test]
    fn lite_callback_redirect_keeps_return_path_in_query_and_tokens_in_fragment() {
        let redirect = lite_callback_redirect_uri(
            "https://athapi.authos.dev/",
            Some("/app/account-security?org=queuezero&service=flux"),
            &[("access_token", "access"), ("refresh_token", "refresh")],
        )
        .unwrap();
        let parsed = url::Url::parse(&redirect).unwrap();
        let query: std::collections::HashMap<_, _> = parsed.query_pairs().collect();
        let fragment: std::collections::HashMap<_, _> =
            url::form_urlencoded::parse(parsed.fragment().unwrap().as_bytes()).collect();

        assert_eq!(
            parsed.as_str().split('?').next(),
            Some("https://athapi.authos.dev/callback")
        );
        assert_eq!(
            query.get("redirect").map(std::convert::AsRef::as_ref),
            Some("/app/account-security?org=queuezero&service=flux")
        );
        assert_eq!(
            fragment
                .get("access_token")
                .map(std::convert::AsRef::as_ref),
            Some("access")
        );
        assert_eq!(
            fragment
                .get("refresh_token")
                .map(std::convert::AsRef::as_ref),
            Some("refresh")
        );
    }

    #[test]
    fn platform_device_mfa_redirect_uses_the_frontend_callback_contract() {
        let redirect = platform_device_mfa_redirect_url(
            "https://app.authos.dev",
            "preauth",
            "device-id",
            "ABCD-1234",
        );
        let fragment = url::Url::parse(&redirect)
            .expect("valid callback URL")
            .fragment()
            .expect("callback fragment")
            .to_string();
        let params: std::collections::HashMap<_, _> =
            url::form_urlencoded::parse(fragment.as_bytes()).collect();

        assert_eq!(
            params.get("mfa_required").map(std::convert::AsRef::as_ref),
            Some("true")
        );
        assert!(!params.contains_key("mfa_challenge"));
        assert_eq!(
            params
                .get("device_code_id")
                .map(std::convert::AsRef::as_ref),
            Some("device-id")
        );
    }

    #[test]
    fn hosted_service_mfa_redirect_keeps_the_challenge_inside_authos() {
        let redirect = hosted_service_mfa_redirect_uri(
            "https://athapi.authos.dev/",
            "https://admin.servos.dev/auth/callback",
            "preauth",
            Some("queuezero"),
            Some("servos"),
            Some("caller-state"),
        )
        .unwrap();
        let parsed = url::Url::parse(&redirect).unwrap();
        let query: std::collections::HashMap<_, _> = parsed.query_pairs().collect();
        let fragment: std::collections::HashMap<_, _> =
            url::form_urlencoded::parse(parsed.fragment().unwrap().as_bytes()).collect();

        assert_eq!(parsed.path(), "/callback");
        assert_eq!(
            query.get("redirect_uri").map(std::convert::AsRef::as_ref),
            Some("https://admin.servos.dev/auth/callback")
        );
        assert_eq!(
            query.get("state").map(std::convert::AsRef::as_ref),
            Some("caller-state")
        );
        assert_eq!(
            fragment
                .get("mfa_required")
                .map(std::convert::AsRef::as_ref),
            Some("true")
        );
        assert_eq!(
            fragment
                .get("preauth_token")
                .map(std::convert::AsRef::as_ref),
            Some("preauth")
        );
    }
}
