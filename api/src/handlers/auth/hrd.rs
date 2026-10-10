use crate::db::DB;
use crate::error::{AppError, Result};
use crate::state::AppState;
use crate::store::{
    organizations::OrganizationStore, services::ServiceStore, verified_domains::VerifiedDomainStore,
};
use axum::{
    extract::{Query, State},
    Json,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct LookupEmailRequest {
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct LookupEmailResponse {
    /// The connection ID to use for authentication, if any
    pub connection_id: Option<String>,
    /// The name of the upstream provider, for display purposes
    pub provider_name: Option<String>,
    /// Whether the domain is verified
    pub domain_verified: bool,
    /// The authentication method to use: "upstream", "password", or "oauth"
    pub auth_method: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthContextQuery {
    pub org: Option<String>,
    pub service: Option<String>,
    pub redirect_uri: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthOrganizationContext {
    pub slug: String,
    pub name: String,
    pub logo_url: Option<String>,
    pub primary_color: Option<String>,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct AuthServiceContext {
    pub slug: String,
    pub name: String,
    pub service_type: String,
    pub redirect_uri_valid: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct AuthContextResponse {
    pub organization: Option<AuthOrganizationContext>,
    pub service: Option<AuthServiceContext>,
    pub available_providers: Vec<String>,
    pub auth_methods: Vec<String>,
    pub support_available: bool,
}

/// Home Realm Discovery: map an email domain to its upstream connection.
///
/// Only *verified* domains resolve, otherwise anyone could claim a tenant's
/// domain and redirect its users. Unmapped domains fall back to local auth.
pub async fn lookup_email(
    State(state): State<AppState>,
    Json(payload): Json<LookupEmailRequest>,
) -> Result<Json<LookupEmailResponse>> {
    // Extract domain from email
    let email = payload.email.to_lowercase();
    let domain = email
        .split('@')
        .nth(1)
        .ok_or_else(|| AppError::BadRequest("Invalid email address".to_string()))?;

    // Look up the domain in verified_domains table
    match VerifiedDomainStore::find_by_domain(DB::Conn(&state.db), domain).await? {
        Some(verified_domain) if verified_domain.verified => {
            // Domain is verified and mapped to an upstream provider
            if let Some(provider_id) = verified_domain.upstream_provider_id {
                // Fetch the upstream provider to get connection_id and name
                use crate::store::upstream_providers::UpstreamProviderStore;
                match UpstreamProviderStore::find_by_id(DB::Conn(&state.db), &provider_id).await? {
                    Some(provider) if provider.enabled => Ok(Json(LookupEmailResponse {
                        connection_id: Some(provider.connection_id),
                        provider_name: Some(provider.name),
                        domain_verified: true,
                        auth_method: "upstream".to_string(),
                    })),
                    _ => {
                        // Provider not found or disabled, fall back to password
                        Ok(Json(LookupEmailResponse {
                            connection_id: None,
                            provider_name: None,
                            domain_verified: true,
                            auth_method: "password".to_string(),
                        }))
                    }
                }
            } else {
                // Domain verified but no upstream provider mapped
                Ok(Json(LookupEmailResponse {
                    connection_id: None,
                    provider_name: None,
                    domain_verified: true,
                    auth_method: "password".to_string(),
                }))
            }
        }
        _ => {
            // Domain not verified or not found, fall back to default OAuth or password
            Ok(Json(LookupEmailResponse {
                connection_id: None,
                provider_name: None,
                domain_verified: false,
                auth_method: "oauth".to_string(),
            }))
        }
    }
}

/// Public hosted-auth metadata for end-user login surfaces.
///
/// This gives the UI enough organization/service context to show the right
/// name, branding, provider choices, and redirect validation status before a
/// user commits to a sign-in path.
pub async fn get_auth_context(
    State(state): State<AppState>,
    Query(query): Query<AuthContextQuery>,
) -> Result<Json<AuthContextResponse>> {
    // Only configured providers and methods are advertised: showing
    // GitHub/Google/Microsoft buttons or magic-link when nothing is
    // configured behind them is a dead end (A9).
    let email_configured = state.email_service.is_some();
    let mut auth_methods = vec!["password".to_string(), "passkey".to_string()];
    if email_configured {
        auth_methods.insert(1, "magic_link".to_string());
    }

    let platform_providers = [
        ("github", state.config.platform_github_client_id.as_ref()),
        ("google", state.config.platform_google_client_id.as_ref()),
        (
            "microsoft",
            state.config.platform_microsoft_client_id.as_ref(),
        ),
    ]
    .into_iter()
    .filter(|(_, id)| id.as_ref().is_some_and(|id| !id.trim().is_empty()))
    .map(|(name, _)| name.to_string())
    .collect::<Vec<_>>();

    let Some(org_slug) = query
        .org
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Ok(Json(AuthContextResponse {
            organization: None,
            service: None,
            available_providers: platform_providers,
            auth_methods,
            support_available: true,
        }));
    };

    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // An org with no providers configured gets no buttons — not the
    // platform fallback (A9).
    let mut available_providers =
        OrganizationStore::list_oauth_providers(DB::Conn(&state.db), &org.id)
            .await
            .unwrap_or_default();

    let service = if let Some(service_slug) = query
        .service
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let service =
            ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, service_slug)
                .await?
                .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;

        let redirect_uri_valid = query.redirect_uri.as_deref().map(|redirect_uri| {
            service
                .redirect_uris
                .as_deref()
                .and_then(|uris| serde_json::from_str::<Vec<String>>(uris).ok())
                .is_some_and(|uris| !uris.is_empty() && uris.iter().any(|uri| uri == redirect_uri))
        });

        Some(AuthServiceContext {
            slug: service.slug,
            name: service.name,
            service_type: service.service_type,
            redirect_uri_valid,
        })
    } else {
        None
    };

    if org.status != "active" {
        auth_methods.clear();
        available_providers.clear();
    }

    Ok(Json(AuthContextResponse {
        organization: Some(AuthOrganizationContext {
            slug: org.slug,
            name: org.name,
            logo_url: org.brand_logo_url,
            primary_color: org.brand_primary_color,
            status: org.status,
        }),
        service,
        available_providers,
        auth_methods,
        support_available: true,
    }))
}
