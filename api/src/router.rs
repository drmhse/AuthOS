//! Application Router Module
//!
//! Organizes routes by domain for maintainability:
//! - Public routes (health, OIDC, SAML)
//! - Authentication routes (SSO, password, magic links)
//! - Protected routes (user, organizations, services)
//! - Platform admin routes
//! - Service API routes (API key auth)
//! - SCIM routes (provisioning)

use crate::client_ip::TrustedClientIpKeyExtractor;
use crate::config::Config;
use crate::handlers::analytics::*;
use crate::handlers::api_keys::*;
use crate::handlers::auth::*;
use crate::handlers::branding::*;
use crate::handlers::health::*;
use crate::handlers::identities::*;
use crate::handlers::invitations::*;
use crate::handlers::linked_accounts::*;
use crate::handlers::organization_audit::*;
use crate::handlers::organizations::roles::*;
use crate::handlers::organizations::*;
use crate::handlers::platform::*;
use crate::handlers::privacy::*;
use crate::handlers::provider_token::*;
use crate::handlers::saml::*;
use crate::handlers::scim::{
    create_group, create_user as create_scim_user, delete_group, delete_user as delete_scim_user,
    get_group, get_user as get_scim_user, list_groups, list_users as list_scim_users, patch_group,
    patch_user as patch_scim_user, update_group, update_user as update_scim_user,
};
use crate::handlers::service_api::{
    create_subscription, create_user as create_service_user,
    delete_subscription as delete_service_subscription, delete_user as delete_service_user,
    get_service_analytics, get_service_info, get_service_user, get_user_subscription,
    list_service_subscriptions, list_service_users, update_service_info, update_subscription,
    update_user as update_service_user,
};
use crate::handlers::service_provider_tokens::*;
use crate::handlers::services::*;
use crate::handlers::siem_configs::*;
use crate::handlers::subscription::{create_checkout, get_subscription};
use crate::handlers::user::{
    change_password, disable_mfa, get_device, get_mfa_status, get_user, list_devices,
    regenerate_backup_codes, revoke_all_devices, revoke_device, set_password, setup_mfa,
    trust_device, update_device_name, update_user, verify_and_enable_mfa,
};
use crate::handlers::webhooks::*;
use crate::middleware;
use crate::state::AppState;
use axum::{
    middleware as axum_middleware,
    routing::{delete, get, patch, post},
    Router,
};
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};

/// Build active organization routes (require org to be active, not suspended)
pub fn active_org_routes(state: &AppState) -> Router<AppState> {
    Router::new()
        // OAuth credentials management (BYOO)
        .route(
            "/api/organizations/:org_slug/oauth-credentials/:provider",
            post(set_org_oauth_credentials),
        )
        .route(
            "/api/organizations/:org_slug/oauth-credentials/:provider",
            get(get_org_oauth_credentials),
        )
        // End-user management routes
        .route("/api/organizations/:org_slug/users", get(list_end_users))
        .route(
            "/api/organizations/:org_slug/users/:user_id",
            get(get_end_user),
        )
        .route(
            "/api/organizations/:org_slug/users/:user_id/sessions",
            delete(revoke_end_user_sessions),
        )
        // Service management routes
        .route(
            "/api/organizations/:org_slug/services/:service_slug/plans",
            get(list_service_plans).post(create_plan),
        )
        .route(
            "/api/organizations/:org_slug/services/:service_slug/plans/:plan_id",
            patch(update_plan).delete(delete_plan),
        )
        .route(
            "/api/organizations/:org_slug/services/:service_slug/api-keys/:api_key_id",
            get(get_api_key).delete(delete_api_key),
        )
        .route(
            "/api/organizations/:org_slug/services/:service_slug/api-keys",
            get(list_api_keys).post(create_api_key),
        )
        .route(
            "/api/organizations/:org_slug/services/:service_slug",
            get(get_service)
                .patch(update_service)
                .delete(delete_service),
        )
        .route(
            "/api/organizations/:org_slug/services/:service_slug/secret/rotate",
            post(rotate_service_secret),
        )
        .route(
            "/api/organizations/:org_slug/services",
            get(list_organization_services).post(create_service),
        )
        // SAML configuration routes
        .route(
            "/api/organizations/:org_slug/services/:service_slug/saml",
            post(configure_saml)
                .get(get_saml_config)
                .delete(delete_saml_config),
        )
        .route(
            "/api/organizations/:org_slug/services/:service_slug/saml/certificate",
            post(generate_saml_certificate).get(get_saml_certificate),
        )
        .route(
            "/api/organizations/:org_slug/services/:service_slug/saml/certificate/overlap",
            delete(retire_saml_certificate_overlap),
        )
        .route(
            "/api/organizations/:org_slug/services/:service_slug/saml/login",
            get(saml_idp_login),
        )
        // Stripe checkout route
        .route(
            "/api/organizations/:org_slug/services/:service_slug/checkout",
            post(create_checkout),
        )
        // Apply active organization check middleware
        .route_layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::require_active_organization,
        ))
}

/// Build protected routes (require JWT authentication)
pub fn protected_routes(state: &AppState) -> Router<AppState> {
    Router::new()
        // User routes
        .route("/api/user", get(get_user))
        .route("/api/user", patch(update_user))
        .route("/api/user/change-password", post(change_password))
        .route("/api/user/set-password", post(set_password))
        .route("/api/subscription", get(get_subscription))
        .route("/api/provider-token/:provider", get(get_provider_token))
        // Identity linking routes
        .route("/api/user/identities", get(list_identities))
        .route("/api/user/identities/:provider/link", post(start_link))
        .route("/api/user/identities/:provider", delete(unlink_identity))
        // User-owned connected account and grant routes
        .route("/api/user/linked-accounts", get(list_linked_accounts))
        .route(
            "/api/user/linked-accounts/:provider/link",
            post(start_linked_account),
        )
        .route(
            "/api/user/linked-accounts/:account_id/grants",
            post(grant_linked_account),
        )
        .route(
            "/api/user/linked-accounts/:account_id",
            delete(revoke_linked_account),
        )
        .route(
            "/api/user/linked-accounts/:account_id/grants/:service_id",
            delete(revoke_linked_account_grant),
        )
        .route(
            "/api/user/provider-token-requests/:state",
            get(get_provider_token_request),
        )
        .route(
            "/api/user/provider-token-requests/:state/complete",
            post(complete_provider_token_request),
        )
        .route(
            "/api/user/provider-token-requests/:state/link",
            post(start_provider_token_request_link),
        )
        // Device management routes
        .route("/api/user/devices", get(list_devices))
        .route("/api/user/devices/:device_id", get(get_device))
        .route("/api/user/devices/:device_id/revoke", post(revoke_device))
        .route("/api/user/devices/:device_id", patch(update_device_name))
        .route("/api/user/devices/:device_id/trust", post(trust_device))
        .route("/api/user/devices/revoke-all", post(revoke_all_devices))
        // Privacy routes (GDPR compliance)
        .route("/api/privacy/export/:user_id", get(export_user_data))
        .route("/api/privacy/forget/:user_id", delete(forget_user))
        // Passkey registration routes (require JWT)
        .route("/api/auth/passkeys", get(list_passkeys))
        .route("/api/auth/passkeys/register/start", post(register_start))
        .route("/api/auth/passkeys/register/finish", post(register_finish))
        .route(
            "/api/auth/passkeys/:passkey_id",
            patch(update_passkey_name).delete(delete_passkey),
        )
        // Organization routes
        .route(
            "/api/organizations",
            get(list_user_organizations).post(create_organization),
        )
        .route(
            "/api/organizations/:org_slug",
            get(get_organization)
                .patch(update_organization)
                .delete(delete_organization),
        )
        .route(
            "/api/organizations/:org_slug/select",
            post(select_organization),
        )
        .route("/api/organizations/:org_slug/members", get(list_members))
        .route(
            "/api/organizations/:org_slug/members/:user_id",
            patch(update_member_role),
        )
        .route(
            "/api/organizations/:org_slug/members/:user_id/service-access",
            get(list_member_service_access).put(update_member_service_access),
        )
        .route(
            "/api/organizations/:org_slug/members/:user_id",
            post(remove_member),
        )
        .route(
            "/api/organizations/:org_slug/transfer-ownership",
            post(transfer_ownership),
        )
        // Billing routes
        .route(
            "/api/organizations/:org_slug/billing/portal",
            post(create_portal_session),
        )
        .route(
            "/api/organizations/:org_slug/billing/info",
            get(get_billing_info),
        )
        // BYOP billing credentials routes
        .route(
            "/api/organizations/:org_slug/billing-credentials/:provider",
            get(get_billing_credentials)
                .post(set_billing_credentials)
                .delete(delete_billing_credentials),
        )
        // Organization SMTP management routes
        .route(
            "/api/organizations/:org_slug/smtp",
            post(set_org_smtp).get(get_org_smtp).delete(delete_org_smtp),
        )
        // Organization risk settings routes
        .route(
            "/api/organizations/:org_slug/risk-settings",
            get(get_risk_settings).put(update_risk_settings),
        )
        .route(
            "/api/organizations/:org_slug/risk-settings/reset",
            post(reset_risk_settings),
        )
        .route(
            "/api/organizations/:org_slug/risk-events",
            get(crate::handlers::organizations::risk::get_risk_events),
        )
        // SCIM token management routes
        .route(
            "/api/organizations/:org_slug/scim-tokens",
            post(create_scim_token).get(list_scim_tokens),
        )
        .route(
            "/api/organizations/:org_slug/scim-tokens/:token_id/revoke",
            post(revoke_scim_token),
        )
        .route(
            "/api/organizations/:org_slug/scim-tokens/:token_id",
            delete(delete_scim_token),
        )
        // Invitation routes
        .route(
            "/api/organizations/:org_slug/invitations",
            post(create_invitation),
        )
        .route(
            "/api/organizations/:org_slug/invitations",
            get(list_invitations),
        )
        .route(
            "/api/organizations/:org_slug/invitations/:invitation_id",
            post(cancel_invitation),
        )
        .route(
            "/api/organizations/:org_slug/invitations/:invitation_id/accept",
            post(accept_invitation_as_admin),
        )
        .route("/api/invitations", get(list_user_invitations))
        .route("/api/invitations/accept", post(accept_invitation))
        .route(
            "/api/invitations/:invitation_id/accept",
            post(accept_invitation_by_id),
        )
        .route(
            "/api/invitations/:invitation_id/decline",
            post(decline_invitation_by_id),
        )
        // Organization audit log routes
        .route(
            "/api/organizations/:org_slug/audit-log",
            get(get_organization_audit_logs),
        )
        .route(
            "/api/organizations/:org_slug/audit-log/event-types",
            get(get_audit_event_types),
        )
        // Role management routes
        .route(
            "/api/organizations/:org_slug/roles",
            get(list_roles).post(create_role),
        )
        .route(
            "/api/organizations/:org_slug/roles/:role_id",
            get(get_role).put(update_role).delete(delete_role),
        )
        // Webhook management routes
        .route(
            "/api/organizations/:org_slug/webhooks",
            post(create_webhook).get(list_webhooks),
        )
        .route(
            "/api/organizations/:org_slug/webhooks/:webhook_id",
            get(get_webhook)
                .patch(update_webhook)
                .delete(delete_webhook),
        )
        .route(
            "/api/organizations/:org_slug/webhooks/:webhook_id/deliveries",
            get(get_webhook_deliveries),
        )
        .route(
            "/api/organizations/:org_slug/webhooks/:webhook_id/test",
            post(test_webhook),
        )
        .route(
            "/api/organizations/:org_slug/webhooks/event-types",
            get(get_webhook_event_types),
        )
        // SIEM configuration routes
        .route(
            "/api/organizations/:org_slug/siem-configs",
            post(create_siem_config).get(list_siem_configs),
        )
        .route(
            "/api/organizations/:org_slug/siem-configs/:config_id",
            get(get_siem_config)
                .put(update_siem_config)
                .delete(delete_siem_config),
        )
        .route(
            "/api/organizations/:org_slug/siem-configs/:config_id/test",
            post(test_siem_connection),
        )
        // Upstream Provider (Enterprise SSO) routes
        .route(
            "/api/organizations/:org_slug/upstream-providers",
            get(list_upstream_providers).post(create_upstream_provider),
        )
        .route(
            "/api/organizations/:org_slug/upstream-providers/:provider_id",
            get(get_upstream_provider)
                .patch(update_upstream_provider)
                .delete(delete_upstream_provider),
        )
        .route(
            "/api/organizations/:org_slug/domain-routes",
            get(list_domain_routes).post(create_domain_route),
        )
        .route(
            "/api/organizations/:org_slug/domain-routes/:domain_id",
            patch(update_domain_route).delete(delete_domain_route),
        )
        .route(
            "/api/organizations/:org_slug/domain-routes/:domain_id/verify",
            post(verify_domain_route),
        )
        // Custom domain and branding routes
        .route(
            "/api/organizations/:org_slug/domain",
            post(set_custom_domain)
                .get(get_domain_configuration)
                .delete(delete_custom_domain),
        )
        .route(
            "/api/organizations/:org_slug/domain/verify",
            post(verify_custom_domain),
        )
        .route(
            "/api/organizations/:org_slug/branding",
            patch(update_branding).get(get_branding),
        )
        .merge(active_org_routes(state))
        .layer(axum_middleware::from_fn(
            middleware::extract_request_info_middleware,
        ))
        // JWT extraction is outermost so the service-token boundary can read
        // the authenticated claims. Service tokens are limited to profile and
        // subscription reads; they cannot reach organization or account
        // management routes.
        .route_layer(axum_middleware::from_fn(
            middleware::reject_impersonation_for_sensitive_actions,
        ))
        .route_layer(axum_middleware::from_fn(
            middleware::enforce_service_token_scope,
        ))
        .route_layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::extract_user_from_jwt,
        ))
}

/// Build analytics routes (require JWT + org membership)
pub fn analytics_routes(state: &AppState) -> Router<AppState> {
    Router::new()
        .route(
            "/api/organizations/:org_slug/analytics/login-trends",
            get(get_login_trends),
        )
        .route(
            "/api/organizations/:org_slug/analytics/logins-by-service",
            get(get_logins_by_service),
        )
        .route(
            "/api/organizations/:org_slug/analytics/logins-by-provider",
            get(get_logins_by_provider),
        )
        .route(
            "/api/organizations/:org_slug/analytics/recent-logins",
            get(get_recent_logins),
        )
        .layer(axum_middleware::from_fn(
            middleware::extract_request_info_middleware,
        ))
        .route_layer(axum_middleware::from_fn(
            middleware::enforce_service_token_scope,
        ))
        .route_layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::extract_user_from_jwt,
        ))
}

/// Build MFA routes with specialized rate limiting
pub fn mfa_routes(state: &AppState, config: &Config) -> Router<AppState> {
    let routes = Router::new()
        .route("/api/user/mfa/status", get(get_mfa_status))
        .route("/api/user/mfa/setup", post(setup_mfa))
        .route("/api/user/mfa/verify", post(verify_and_enable_mfa))
        .route("/api/user/mfa", delete(disable_mfa))
        .route(
            "/api/user/mfa/backup-codes/regenerate",
            post(regenerate_backup_codes),
        );

    let routes = if config.disable_rate_limiting {
        routes
    } else {
        routes.layer(GovernorLayer {
            config: Box::leak(Box::new(
                GovernorConfigBuilder::default()
                    .per_millisecond(300)
                    .burst_size(5)
                    .key_extractor(TrustedClientIpKeyExtractor::from_env())
                    .finish()
                    .expect("Failed to build MFA setup rate limiter"),
            )),
        })
    };

    routes
        .layer(axum_middleware::from_fn(
            middleware::extract_request_info_middleware,
        ))
        .route_layer(axum_middleware::from_fn(
            middleware::reject_impersonation_for_sensitive_actions,
        ))
        .route_layer(axum_middleware::from_fn(
            middleware::enforce_service_token_scope,
        ))
        .route_layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::extract_user_from_jwt,
        ))
}

/// Build MFA verification routes (stricter rate limiting)
pub fn mfa_verification_routes(config: &Config) -> Router<AppState> {
    let routes = Router::new()
        .route("/api/auth/mfa/verify", post(verify_mfa_login))
        .route("/saml/mfa/verify", post(verify_saml_mfa));

    let routes = if config.disable_rate_limiting {
        routes
    } else {
        routes.layer(GovernorLayer {
            config: Box::leak(Box::new(
                GovernorConfigBuilder::default()
                    .per_millisecond(1000)
                    .burst_size(3)
                    .key_extractor(TrustedClientIpKeyExtractor::from_env())
                    .finish()
                    .expect("Failed to build MFA rate limiter"),
            )),
        })
    };

    routes.layer(axum_middleware::from_fn(
        middleware::extract_request_info_middleware,
    ))
}

/// Build platform admin routes (require JWT + platform owner)
pub fn platform_routes(state: &AppState) -> Router<AppState> {
    Router::new()
        .route("/api/platform/tiers", get(list_tiers))
        .route("/api/platform/organizations", get(list_organizations))
        .route(
            "/api/platform/organizations/:id/approve",
            post(approve_organization),
        )
        .route(
            "/api/platform/organizations/:id/reject",
            post(reject_organization),
        )
        .route(
            "/api/platform/organizations/:id/suspend",
            post(suspend_organization),
        )
        .route(
            "/api/platform/organizations/:id/activate",
            post(activate_organization),
        )
        .route(
            "/api/platform/organizations/:id/tier",
            patch(update_organization_tier),
        )
        .route(
            "/api/platform/organizations/:id/features",
            patch(update_organization_features),
        )
        .route(
            "/api/platform/organizations/:id",
            delete(delete_organization_platform),
        )
        .route("/api/platform/owners", post(promote_platform_owner))
        .route(
            "/api/platform/owners/:user_id",
            delete(demote_platform_owner),
        )
        .route("/api/platform/bootstrap/config", get(get_managed_config))
        .route(
            "/api/platform/bootstrap/config",
            patch(update_managed_config),
        )
        .route("/api/platform/bootstrap/apply", post(apply_managed_config))
        .route("/api/platform/audit-log", get(get_audit_log))
        // Platform analytics routes
        .route(
            "/api/platform/analytics/overview",
            get(get_platform_overview),
        )
        .route(
            "/api/platform/analytics/organization-status",
            get(get_organization_status_breakdown),
        )
        .route(
            "/api/platform/analytics/growth-trends",
            get(get_growth_trends),
        )
        .route(
            "/api/platform/analytics/login-activity",
            get(get_login_activity),
        )
        .route(
            "/api/platform/analytics/top-organizations",
            get(get_top_organizations),
        )
        .route(
            "/api/platform/analytics/recent-organizations",
            get(get_recent_organizations),
        )
        // Platform MFA management routes
        .route(
            "/api/platform/users/:user_id/mfa/status",
            get(get_user_mfa_status),
        )
        .route(
            "/api/platform/users/:user_id/mfa",
            delete(force_disable_user_mfa),
        )
        .route("/api/platform/users/search", get(search_users))
        .route("/api/platform/users", get(list_users))
        .route("/api/platform/users/:user_id", get(get_platform_user))
        .route("/api/platform/impersonate", post(impersonate_user))
        .route(
            "/api/platform/operations/status",
            get(get_operations_status),
        )
        .route("/api/platform/mfa/metrics", get(get_mfa_metrics))
        .route(
            "/api/platform/mfa/suspicious-activity",
            get(get_suspicious_activity),
        )
        .route(
            // POST is the correct verb for a rollup rebuild; GET stays for the
            // existing contract.
            "/api/platform/mfa/metrics/generate",
            post(generate_daily_metrics).get(generate_daily_metrics),
        )
        .layer(axum_middleware::from_fn(
            middleware::extract_request_info_middleware,
        ))
        .route_layer(axum_middleware::from_fn(
            middleware::enforce_service_token_scope,
        ))
        .route_layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::require_platform_owner,
        ))
        .route_layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::extract_user_from_jwt,
        ))
}

/// Build authentication routes with rate limiting
pub fn auth_routes(config: &Config) -> Router<AppState> {
    let routes = Router::new()
        // SSO routes
        .route("/auth/:provider", get(auth_provider))
        .route("/auth/:provider/callback", get(auth_callback))
        .route("/auth/saml/callback", post(auth_saml_callback))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/refresh", post(refresh_token))
        .route("/auth/revoke", post(revoke_token))
        .route("/oauth/token", post(enterprise_token))
        .route("/oauth2/token", post(enterprise_token))
        // Admin authentication routes
        .route("/auth/admin/:provider", get(auth_admin_provider))
        .route("/auth/admin/:provider/callback", get(auth_admin_callback))
        // Password authentication routes
        .route("/api/auth/register", post(register))
        .route("/api/auth/availability", get(availability))
        .route("/auth/verify-email", get(verify_email))
        .route("/api/auth/login", post(login))
        .route("/api/auth/forgot-password", post(forgot_password))
        .route("/api/auth/reset-password", post(reset_password))
        .route("/api/auth/resend-verification", post(resend_verification))
        // Home Realm Discovery
        .route("/api/auth/lookup-email", post(lookup_email))
        .route("/api/auth/context", get(get_auth_context))
        // Passkey authentication routes (public)
        .route(
            "/api/auth/passkeys/authenticate/start",
            post(authenticate_start),
        )
        .route(
            "/api/auth/passkeys/authenticate/finish",
            post(authenticate_finish),
        )
        // Magic link authentication routes
        .route("/api/auth/magic-link/request", post(request_magic_link))
        .route("/api/auth/magic-link/verify", get(verify_magic_link))
        .layer(axum_middleware::from_fn(
            middleware::extract_request_info_middleware,
        ));

    if config.disable_rate_limiting {
        routes
    } else {
        routes.layer(GovernorLayer {
            config: Box::leak(Box::new(
                GovernorConfigBuilder::default()
                    .per_millisecond(1000)
                    .burst_size(20)
                    .key_extractor(TrustedClientIpKeyExtractor::from_env())
                    .finish()
                    .expect("Failed to build auth rate limiter"),
            )),
        })
    }
}

/// Build device flow routes with stricter rate limiting
pub fn device_routes(config: &Config) -> Router<AppState> {
    let routes = Router::new()
        .route("/auth/device/code", post(device_code))
        .route("/auth/device/verify", post(device_verify))
        .route("/auth/token", post(token_exchange));

    if config.disable_rate_limiting {
        routes
    } else {
        routes.layer(GovernorLayer {
            config: Box::leak(Box::new(
                GovernorConfigBuilder::default()
                    .per_millisecond(5000)
                    .burst_size(10)
                    .key_extractor(TrustedClientIpKeyExtractor::from_env())
                    .finish()
                    .expect("Failed to build device rate limiter"),
            )),
        })
    }
}

/// Build service API routes (authenticated via API key)
pub fn service_api_routes(state: &AppState) -> Router<AppState> {
    Router::new()
        // User management
        .route(
            "/api/service/users",
            get(list_service_users).post(create_service_user),
        )
        .route(
            "/api/service/users/:user_id",
            get(get_service_user)
                .patch(update_service_user)
                .delete(delete_service_user),
        )
        // Subscription management
        .route(
            "/api/service/subscriptions",
            get(list_service_subscriptions).post(create_subscription),
        )
        .route(
            "/api/service/subscriptions/:user_id",
            get(get_user_subscription)
                .patch(update_subscription)
                .delete(delete_service_subscription),
        )
        // Analytics (read only)
        .route("/api/service/analytics", get(get_service_analytics))
        // Backend-only provider token exchange
        .route(
            "/api/service/provider-tokens",
            post(request_service_provider_token),
        )
        // Service info
        .route(
            "/api/service/info",
            get(get_service_info).patch(update_service_info),
        )
        .layer(axum_middleware::from_fn(
            middleware::extract_request_info_middleware,
        ))
        .route_layer(axum_middleware::from_fn_with_state(
            state.db.clone(),
            middleware::extract_api_key,
        ))
}

/// Build SCIM routes (authenticated via SCIM Bearer tokens)
pub fn scim_routes(state: &AppState) -> Router<AppState> {
    Router::new()
        // SCIM Users endpoints
        .route(
            "/scim/v2/Users",
            get(list_scim_users).post(create_scim_user),
        )
        .route(
            "/scim/v2/Users/:id",
            get(get_scim_user)
                .put(update_scim_user)
                .patch(patch_scim_user)
                .delete(delete_scim_user),
        )
        // SCIM Groups endpoints
        .route("/scim/v2/Groups", get(list_groups).post(create_group))
        .route(
            "/scim/v2/Groups/:id",
            get(get_group)
                .put(update_group)
                .patch(patch_group)
                .delete(delete_group),
        )
        .layer(axum_middleware::from_fn(
            middleware::extract_request_info_middleware,
        ))
        .route_layer(axum_middleware::from_fn_with_state(
            state.db.clone(),
            middleware::scim_auth_middleware,
        ))
}

/// Build SAML IdP routes (public, no authentication required)
pub fn saml_routes() -> Router<AppState> {
    Router::new()
        // SAML IdP metadata endpoint
        .route("/saml/:org_slug/:service_slug/metadata", get(saml_metadata))
        // SAML SSO initiation endpoint
        .route(
            "/saml/:org_slug/:service_slug/sso",
            post(saml_sso).get(saml_sso),
        )
        // SAML Single Logout endpoint
        .route(
            "/saml/:org_slug/:service_slug/slo",
            post(saml_slo_post).get(saml_slo),
        )
        // SAML authentication page
        .route(
            "/saml/:org_slug/:service_slug/authenticate",
            get(saml_authenticate),
        )
}

/// Build public routes (no authentication required)
/// Note: AuthOS capability metadata, explicit unsupported-discovery responses,
/// and the JWKS endpoint are added in main.rs.
pub fn public_routes(config: &Config) -> Router<AppState> {
    Router::new()
        // Health check endpoints
        .route("/health", get(health))
        .route("/health/live", get(liveness))
        // Hosted provider-token reauth/link flow for service integrations.
        .route(
            "/connect/provider-token/:state",
            get(start_provider_token_request_reauth),
        )
        // Public branding endpoint
        .route(
            "/api/organizations/:org_slug/branding/public",
            get(get_public_branding),
        )
        // Public invitation endpoints
        .route("/api/invitations/decline", post(decline_invitation))
        .route(
            "/invitations/accept/:token",
            get(accept_invitation_redirect),
        )
        .merge(auth_routes(config))
        .merge(device_routes(config))
        .merge(saml_routes())
}

#[cfg(test)]
mod platform_route_boundary_tests {
    /// Platform authorization is intentionally centralized as a route layer.
    /// Keep an explicit inventory here so a newly added platform handler
    /// cannot silently land outside that boundary.
    #[test]
    fn every_platform_route_is_inside_the_platform_owner_boundary() {
        const ROUTES: &[&str] = &[
            "/api/platform/tiers",
            "/api/platform/organizations",
            "/api/platform/organizations/:id/approve",
            "/api/platform/organizations/:id/reject",
            "/api/platform/organizations/:id/suspend",
            "/api/platform/organizations/:id/activate",
            "/api/platform/organizations/:id/tier",
            "/api/platform/organizations/:id/features",
            "/api/platform/organizations/:id",
            "/api/platform/owners",
            "/api/platform/owners/:user_id",
            "/api/platform/bootstrap/config",
            "/api/platform/bootstrap/config",
            "/api/platform/bootstrap/apply",
            "/api/platform/audit-log",
            "/api/platform/analytics/overview",
            "/api/platform/analytics/organization-status",
            "/api/platform/analytics/growth-trends",
            "/api/platform/analytics/login-activity",
            "/api/platform/analytics/top-organizations",
            "/api/platform/analytics/recent-organizations",
            "/api/platform/users/:user_id/mfa/status",
            "/api/platform/users/:user_id/mfa",
            "/api/platform/users/search",
            "/api/platform/users",
            "/api/platform/users/:user_id",
            "/api/platform/impersonate",
            "/api/platform/operations/status",
            "/api/platform/mfa/metrics",
            "/api/platform/mfa/suspicious-activity",
            "/api/platform/mfa/metrics/generate",
        ];

        let source = include_str!("router.rs");
        let start = source
            .find("pub fn platform_routes")
            .expect("platform router");
        let end = source[start..]
            .find("/// Build authentication routes")
            .map(|offset| start + offset)
            .expect("end of platform router");
        let platform_router = &source[start..end];
        let owner_boundary = platform_router
            .find("middleware::require_platform_owner")
            .expect("platform-owner boundary");
        let authentication_boundary = platform_router
            .find("middleware::extract_user_from_jwt")
            .expect("JWT authentication boundary");

        for route in ROUTES {
            let position = platform_router
                .find(&format!("\"{route}\""))
                .unwrap_or_else(|| panic!("missing platform route inventory entry: {route}"));
            assert!(
                position < owner_boundary,
                "{route} is outside the owner boundary"
            );
            assert!(
                position < authentication_boundary,
                "{route} is outside JWT auth"
            );
        }

        assert_eq!(
            platform_router.matches("\"/api/platform/").count(),
            ROUTES.len(),
            "update the explicit platform route authorization inventory"
        );
        assert!(!platform_router[owner_boundary..].contains("\"/api/platform/"));
    }
}

#[cfg(test)]
mod router_smoke_tests {
    use super::*;
    use crate::audit::actor::AuditHandle;
    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::crypto::jwt::JwtService;
    use crate::crypto::sso::OAuthClient;
    use crate::db::DB;
    use crate::entities::users;
    use crate::rsa_keys::GeneratedKey;
    use crate::services::{
        events::EventDispatcher, metrics::MfaMetricsService, risk_engine::RiskEngine,
    };
    use crate::state::AppState;
    use crate::store::users::UserStore;
    use axum::body::{to_bytes, Body};
    use axum::http::{header, Request, StatusCode};
    use base64::{engine::general_purpose::STANDARD, Engine};
    use migration::{Migrator, MigratorTrait};
    use moka::future::Cache;
    use sea_orm::{ActiveModelTrait, Database, Set};
    use std::sync::Arc;
    use tower::ServiceExt;

    use crate::test_support::test_config;

    /// Assembles the same route groups main() uses, with the request-info and
    /// JWT middleware layers in production order.
    fn build_app(state: AppState, config: &Config) -> axum::Router {
        Router::new()
            .merge(public_routes(config))
            .merge(protected_routes(&state))
            .with_state(state.clone())
            // protected_routes carries its own JWT route layer; adding a
            // global one here would also gate the public routes.
            .layer(axum::middleware::from_fn(
                middleware::extract_request_info_middleware,
            ))
    }

    #[tokio::test]
    async fn public_health_is_reachable_without_authentication() {
        let config = test_config();
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
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
        let state = AppState {
            db: db.clone(),
            #[cfg(feature = "db_sqlite")]
            db_writer: db.clone(),
            oauth_client: Arc::new(OAuthClient::new(&config).expect("oauth")),
            jwt_service,
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
            config: config.clone(),
        };
        let app = build_app(state.clone(), &config);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn protected_routes_demand_a_bearer_token_and_honour_it() {
        let config = test_config();
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
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
        let user = UserStore::create(DB::Conn(&db), "smoke@example.test", None, false)
            .await
            .expect("create user");

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
            config: config.clone(),
        };

        let app = build_app(state.clone(), &config);

        // No Authorization header at all.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/user")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            response.status() == StatusCode::UNAUTHORIZED,
            "missing token must be refused, got {}",
            response.status()
        );

        // A garbage token is refused too.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/user")
                    .header(header::AUTHORIZATION, "Bearer not-a-real-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(response.status(), StatusCode::OK);

        // A real token WITH a bound session passes the whole stack: the
        // middleware checks the token hash against the sessions table, so a
        // bare JWT is not enough by design.
        let token = jwt_service
            .create_token(&user.id, &user.email, false, None, None)
            .expect("token");
        crate::store::sessions::SessionStore::create(
            DB::Conn(&db),
            &user.id,
            &JwtService::hash_token(&token),
            (chrono::Utc::now() + chrono::Duration::hours(1)).naive_utc(),
            None,
            None,
            None,
            None,
            None,
            Some("router-smoke-test"),
            Some("127.0.0.1"),
        )
        .await
        .expect("seed session for token");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/user")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(
            String::from_utf8(body.to_vec()).unwrap().contains(&user.id),
            "the authenticated identity must be echoed back"
        );

        // A service-login token may read the profile but must not reach
        // organization or platform management routes.
        let service_token = jwt_service
            .create_token(&user.id, &user.email, false, Some("acme"), Some("portal"))
            .expect("service token");
        crate::store::sessions::SessionStore::create(
            DB::Conn(&db),
            &user.id,
            &JwtService::hash_token(&service_token),
            (chrono::Utc::now() + chrono::Duration::hours(1)).naive_utc(),
            None,
            None,
            Some("acme"),
            Some("service-id"),
            None,
            Some("router-smoke-test"),
            Some("127.0.0.1"),
        )
        .await
        .expect("seed service session");

        let profile = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/user")
                    .header(header::AUTHORIZATION, format!("Bearer {service_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(profile.status(), StatusCode::OK);

        let organization_management = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/organizations")
                    .header(header::AUTHORIZATION, format!("Bearer {service_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(organization_management.status(), StatusCode::FORBIDDEN);

        // A soft-deleted user must not keep using a still-valid session.
        let mut deleted: users::ActiveModel = UserStore::find_by_id(DB::Conn(&db), &user.id)
            .await
            .expect("load user")
            .expect("user exists")
            .into();
        deleted.deleted_at = Set(Some(chrono::Utc::now().naive_utc()));
        deleted.update(&db).await.expect("soft-delete user");
        state.user_cache.invalidate(&user.id).await;

        let deleted_response = app
            .oneshot(
                Request::builder()
                    .uri("/api/user")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(deleted_response.status(), StatusCode::UNAUTHORIZED);
    }
}
