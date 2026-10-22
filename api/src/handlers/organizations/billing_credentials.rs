//! BYOP (Bring Your Own Payment) billing credentials handlers
//!
//! Allows organizations to configure their own billing provider credentials
//! to charge their end-users directly.

use crate::db::transaction::with_retrying_transaction;
use crate::db::DB;
use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use crate::services::audit_builder::OrgAuditBuilder;
use crate::services::permission_service::{PermissionService, CAP_BILLING_MANAGE};
use crate::state::AppState;
use crate::store::{
    organization_billing_credentials::OrganizationBillingCredentialsStore,
    organizations::OrganizationStore,
};
use axum::{
    extract::{Path, State},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

async fn require_billing_credentials_manager(
    db: &sea_orm::DatabaseConnection,
    user_id: &str,
    org_slug: &str,
) -> Result<crate::entities::organizations::Model> {
    let org = OrganizationStore::find_by_slug(DB::Conn(db), org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
    let org = crate::handlers::organizations::ensure_organization_active(db, &org.id).await?;
    if !PermissionService::check(DB::Conn(db), &org.id, user_id, CAP_BILLING_MANAGE).await? {
        return Err(AppError::Forbidden(
            "Insufficient permissions to manage billing credentials".to_string(),
        ));
    }
    Ok(org)
}

/// Request for setting billing credentials
#[derive(Debug, Deserialize)]
pub struct SetBillingCredentialsRequest {
    pub api_key: String,
    pub webhook_secret: String,
    pub mode: String, // "test" or "live"
}

/// Response for billing credentials status
#[derive(Debug, Serialize)]
pub struct BillingCredentialsStatusResponse {
    pub configured: bool,
    pub provider: String,
    pub mode: Option<String>,
    pub enabled: bool,
}

fn validate_billing_credentials_input(request: &SetBillingCredentialsRequest) -> Result<()> {
    if request.api_key.trim().is_empty() {
        return Err(AppError::BadRequest(
            "Billing API key cannot be empty".to_string(),
        ));
    }
    if request.webhook_secret.trim().is_empty() {
        return Err(AppError::BadRequest(
            "Billing webhook secret cannot be empty".to_string(),
        ));
    }
    Ok(())
}

/// GET /api/organizations/:org_slug/billing-credentials/:provider
/// Get billing credentials status for a provider
pub async fn get_billing_credentials(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path((org_slug, provider)): Path<(String, String)>,
) -> Result<Json<BillingCredentialsStatusResponse>> {
    let org = require_billing_credentials_manager(&state.db, &auth_user.user.id, &org_slug).await?;

    // Validate provider
    if provider != "stripe" && provider != "polar" {
        return Err(AppError::BadRequest(
            "Invalid provider. Must be stripe or polar".to_string(),
        ));
    }

    // Get credentials status
    let status =
        OrganizationBillingCredentialsStore::get_status(DB::Conn(&state.db), &org.id, &provider)
            .await?;

    match status {
        Some(s) => Ok(Json(BillingCredentialsStatusResponse {
            configured: s.configured,
            provider: s.provider,
            mode: Some(s.mode),
            enabled: s.enabled,
        })),
        None => Ok(Json(BillingCredentialsStatusResponse {
            configured: false,
            provider,
            mode: None,
            enabled: false,
        })),
    }
}

/// POST /api/organizations/:org_slug/billing-credentials/:provider
/// Set billing credentials for a provider
pub async fn set_billing_credentials(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path((org_slug, provider)): Path<(String, String)>,
    Json(req): Json<SetBillingCredentialsRequest>,
) -> Result<Json<serde_json::Value>> {
    let org = require_billing_credentials_manager(&state.db, &auth_user.user.id, &org_slug).await?;

    // Validate provider
    if provider != "stripe" && provider != "polar" {
        return Err(AppError::BadRequest(
            "Invalid provider. Must be stripe or polar".to_string(),
        ));
    }

    // Validate mode
    if req.mode != "test" && req.mode != "live" {
        return Err(AppError::BadRequest(
            "Invalid mode. Must be test or live".to_string(),
        ));
    }
    validate_billing_credentials_input(&req)?;

    let encryption = crate::encryption::EncryptionService::new().map_err(|e| {
        AppError::InternalServerError(format!("Encryption service unavailable: {}", e))
    })?;

    let existing = OrganizationBillingCredentialsStore::find_by_org_provider_mode(
        DB::Conn(&state.db),
        &org.id,
        &provider,
        &req.mode,
    )
    .await?;
    let credential_id = existing.as_ref().map_or_else(
        || uuid::Uuid::new_v4().to_string(),
        |credential| credential.id.clone(),
    );

    // Encrypt API key
    let api_key_encrypted = encryption
        .encrypt_with_context(
            &req.api_key,
            crate::encryption::EncryptionContext::new(
                "organization_billing_credentials",
                &credential_id,
                "api_key_encrypted",
            ),
        )
        .map_err(|e| AppError::InternalServerError(format!("Failed to encrypt API key: {}", e)))?;

    // Encrypt webhook secret
    let webhook_secret_encrypted = encryption
        .encrypt_with_context(
            &req.webhook_secret,
            crate::encryption::EncryptionContext::new(
                "organization_billing_credentials",
                &credential_id,
                "webhook_secret_encrypted",
            ),
        )
        .map_err(|e| {
            AppError::InternalServerError(format!("Failed to encrypt webhook secret: {}", e))
        })?;

    let encryption_key_id = encryption.key_id().to_string();

    let org_id = org.id.clone();
    let actor_id = auth_user.user.id.clone();
    let mode = req.mode.clone();
    let audit_action = if existing.is_some() {
        "billing_credentials.updated"
    } else {
        "billing_credentials.created"
    };
    let audit_actor = state.audit_actor.clone();
    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "set_billing_credentials",
        |db| {
            let credential_id = credential_id.clone();
            let org_id = org_id.clone();
            let actor_id = actor_id.clone();
            let provider = provider.clone();
            let mode = mode.clone();
            let api_key_encrypted = api_key_encrypted.clone();
            let webhook_secret_encrypted = webhook_secret_encrypted.clone();
            let encryption_key_id = encryption_key_id.clone();
            let audit_actor = audit_actor.clone();
            Box::pin(async move {
                OrganizationBillingCredentialsStore::upsert(
                    db.clone(),
                    Some(&credential_id),
                    &org_id,
                    &provider,
                    &mode,
                    api_key_encrypted,
                    webhook_secret_encrypted,
                    &encryption_key_id,
                )
                .await?;
                let event = OrgAuditBuilder::new(&org_id, Some(&actor_id), audit_action)
                    .target("billing_credentials", &credential_id)
                    .success(true)
                    .details_json(Some(json!({ "provider": provider, "mode": mode })))
                    .build();
                audit_actor.log_org_with_db(db, event).await?;
                Ok(())
            })
        },
    )
    .await?;

    Ok(Json(serde_json::json!({
        "message": format!("Billing credentials for {} ({} mode) configured successfully", provider, req.mode)
    })))
}

/// DELETE /api/organizations/:org_slug/billing-credentials/:provider
/// Delete billing credentials for a provider
pub async fn delete_billing_credentials(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path((org_slug, provider)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>> {
    let org = require_billing_credentials_manager(&state.db, &auth_user.user.id, &org_slug).await?;

    // Validate provider
    if provider != "stripe" && provider != "polar" {
        return Err(AppError::BadRequest(
            "Invalid provider. Must be stripe or polar".to_string(),
        ));
    }

    let org_id = org.id.clone();
    let actor_id = auth_user.user.id.clone();
    let audit_actor = state.audit_actor.clone();
    let deleted = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "delete_billing_credentials",
        |db| {
            let org_id = org_id.clone();
            let actor_id = actor_id.clone();
            let provider = provider.clone();
            let audit_actor = audit_actor.clone();
            Box::pin(async move {
                let deleted =
                    OrganizationBillingCredentialsStore::delete(db.clone(), &org_id, &provider)
                        .await?;
                if deleted == 0 {
                    return Err(AppError::NotFound(
                        "No billing credentials found for this provider".to_string(),
                    ));
                }
                let event =
                    OrgAuditBuilder::new(&org_id, Some(&actor_id), "billing_credentials.deleted")
                        .target("billing_credentials", &provider)
                        .success(true)
                        .details_json(Some(json!({ "provider": provider })))
                        .build();
                audit_actor.log_org_with_db(db, event).await?;
                Ok(deleted)
            })
        },
    )
    .await?;

    Ok(Json(serde_json::json!({
        "message": format!("Billing credentials for {} deleted successfully", provider),
        "deleted_count": deleted
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{
        memberships::MembershipStore, organization_roles::OrganizationRoleStore, users::UserStore,
    };
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;

    #[test]
    fn billing_credentials_require_both_nonempty_secrets() {
        for request in [
            SetBillingCredentialsRequest {
                api_key: String::new(),
                webhook_secret: "webhook-secret".to_string(),
                mode: "test".to_string(),
            },
            SetBillingCredentialsRequest {
                api_key: "api-key".to_string(),
                webhook_secret: "  ".to_string(),
                mode: "live".to_string(),
            },
        ] {
            assert!(matches!(
                validate_billing_credentials_input(&request),
                Err(AppError::BadRequest(_))
            ));
        }
        validate_billing_credentials_input(&SetBillingCredentialsRequest {
            api_key: "api-key".to_string(),
            webhook_secret: "webhook-secret".to_string(),
            mode: "test".to_string(),
        })
        .expect("complete billing credentials");
    }

    #[tokio::test]
    async fn billing_credentials_authority_honors_scoped_capability_and_revocation() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let user = UserStore::create(DB::Conn(&db), "billing-role@example.com", None, false)
            .await
            .expect("create user");
        let outsider =
            UserStore::create(DB::Conn(&db), "billing-outsider@example.com", None, false)
                .await
                .expect("create outsider");
        let org = OrganizationStore::create(
            DB::Conn(&db),
            "billing-role-org",
            "Billing Role Org",
            &user.id,
            None,
        )
        .await
        .expect("create org");
        OrganizationStore::update_status(DB::Conn(&db), &org.id, "active")
            .await
            .expect("activate org");
        let membership =
            MembershipStore::create(DB::Conn(&db), &org.id, &user.id, "billing-manager")
                .await
                .expect("create custom membership");
        OrganizationRoleStore::create(
            DB::Conn(&db),
            "billing-manager-role",
            &org.id,
            "billing-manager",
            "Billing manager",
            None,
            serde_json::json!([CAP_BILLING_MANAGE]),
        )
        .await
        .expect("create billing role");

        require_billing_credentials_manager(&db, &user.id, &org.slug)
            .await
            .expect("custom billing capability is sufficient");
        OrganizationStore::update_status(DB::Conn(&db), &org.id, "suspended")
            .await
            .expect("suspend org");
        assert!(matches!(
            require_billing_credentials_manager(&db, &user.id, &org.slug).await,
            Err(AppError::Forbidden(_))
        ));
        OrganizationStore::update_status(DB::Conn(&db), &org.id, "active")
            .await
            .expect("reactivate org");
        assert!(matches!(
            require_billing_credentials_manager(&db, &outsider.id, &org.slug).await,
            Err(AppError::Forbidden(_))
        ));
        MembershipStore::update_role(DB::Conn(&db), &membership.id, "member")
            .await
            .expect("revoke billing role");
        assert!(matches!(
            require_billing_credentials_manager(&db, &user.id, &org.slug).await,
            Err(AppError::Forbidden(_))
        ));
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
    use serde_json::json;
    use std::sync::Arc;

    struct Fixture {
        state: AppState,
        owner: AuthUser,
        admin: AuthUser,
        custom_manager: AuthUser,
        member: AuthUser,
        outsider: AuthUser,
        other_owner: AuthUser,
        alpha_id: String,
        alpha_slug: String,
        beta_id: String,
        beta_slug: String,
    }

    async fn seed_credentials(
        db: &sea_orm::DatabaseConnection,
        org_id: &str,
        provider: &str,
        mode: &str,
    ) {
        OrganizationBillingCredentialsStore::upsert(
            DB::Conn(db),
            None,
            org_id,
            provider,
            mode,
            vec![1, 2, 3],
            vec![4, 5, 6],
            "test-key",
        )
        .await
        .expect("seed billing credentials");
    }

    async fn fixture() -> Fixture {
        let db = setup_db().await;
        let config = test_config();
        let jwt_service = Arc::new(test_jwt_service(&config));

        let owner = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "billing-route-owner@example.test",
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
            "billing-route-admin@example.test",
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
            "billing-route-custom@example.test",
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
            "billing-route-member@example.test",
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
            "billing-route-outsider@example.test",
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
            "billing-route-other-owner@example.test",
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
            "billing-route-alpha",
            "Billing Route Alpha",
            &owner.id,
            Some("tier_enterprise"),
        )
        .await
        .expect("create alpha");
        let (beta, _) = OrganizationStore::create_with_owner(
            DB::Conn(&db),
            "billing-route-beta",
            "Billing Route Beta",
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
            "billing-route-manager-role",
            &alpha.id,
            "billing-route-manager",
            "Billing Route Manager",
            None,
            json!([CAP_BILLING_MANAGE]),
        )
        .await
        .expect("create billing manager role");
        MembershipStore::create(
            DB::Conn(&db),
            &alpha.id,
            &custom_manager.id,
            "billing-route-manager",
        )
        .await
        .expect("add custom manager");
        seed_credentials(&db, &beta.id, "stripe", "test").await;

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
                user_agent: "billing-route-test".to_string(),
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
            alpha_id: alpha.id,
            alpha_slug: alpha.slug,
            beta_id: beta.id,
            beta_slug: beta.slug,
        }
    }

    #[tokio::test]
    async fn billing_credentials_routes_require_billing_authority_and_are_org_scoped() {
        let f = fixture().await;

        for auth in [f.owner.clone(), f.admin.clone(), f.custom_manager.clone()] {
            let Json(status) = get_billing_credentials(
                State(f.state.clone()),
                Extension(auth),
                Path((f.alpha_slug.clone(), "stripe".to_string())),
            )
            .await
            .expect("billing manager may read credentials status");
            assert!(!status.configured);
        }
        for auth in [f.member.clone(), f.outsider.clone(), f.other_owner.clone()] {
            assert!(matches!(
                get_billing_credentials(
                    State(f.state.clone()),
                    Extension(auth),
                    Path((f.alpha_slug.clone(), "stripe".to_string())),
                )
                .await,
                Err(AppError::Forbidden(_))
            ));
        }

        // Denied actors cannot mutate alpha, even with valid input.
        for auth in [f.member.clone(), f.outsider.clone(), f.other_owner.clone()] {
            assert!(matches!(
                set_billing_credentials(
                    State(f.state.clone()),
                    Extension(auth),
                    Path((f.alpha_slug.clone(), "stripe".to_string())),
                    Json(SetBillingCredentialsRequest {
                        api_key: "sk_test_canary".to_string(),
                        webhook_secret: "whsec_canary".to_string(),
                        mode: "test".to_string(),
                    }),
                )
                .await,
                Err(AppError::Forbidden(_))
            ));
        }
        assert!(
            OrganizationBillingCredentialsStore::get_status(
                DB::Conn(&f.state.db),
                &f.alpha_id,
                "stripe",
            )
            .await
            .expect("load alpha credentials")
            .is_none(),
            "denied credential writes must not create alpha credentials"
        );

        // The custom billing manager passes authorization before provider
        // validation.
        assert!(matches!(
            set_billing_credentials(
                State(f.state.clone()),
                Extension(f.custom_manager.clone()),
                Path((f.alpha_slug.clone(), "invalid-provider".to_string())),
                Json(SetBillingCredentialsRequest {
                    api_key: "sk_test_canary".to_string(),
                    webhook_secret: "whsec_canary".to_string(),
                    mode: "test".to_string(),
                }),
            )
            .await,
            Err(AppError::BadRequest(_))
        ));

        // Alpha credentials are not visible through the beta organization.
        assert!(matches!(
            get_billing_credentials(
                State(f.state.clone()),
                Extension(f.owner.clone()),
                Path((f.beta_slug.clone(), "stripe".to_string())),
            )
            .await,
            Err(AppError::Forbidden(_))
        ));
        let Json(beta_status) = get_billing_credentials(
            State(f.state.clone()),
            Extension(f.other_owner.clone()),
            Path((f.beta_slug.clone(), "stripe".to_string())),
        )
        .await
        .expect("beta owner may read beta credentials");
        assert!(beta_status.configured);

        // Deleting alpha has no credentials fails; deleting beta through alpha
        // is denied and leaves beta credentials configured.
        assert!(matches!(
            delete_billing_credentials(
                State(f.state.clone()),
                Extension(f.owner.clone()),
                Path((f.alpha_slug.clone(), "stripe".to_string())),
            )
            .await,
            Err(AppError::NotFound(_))
        ));
        assert!(matches!(
            delete_billing_credentials(
                State(f.state.clone()),
                Extension(f.owner.clone()),
                Path((f.beta_slug.clone(), "stripe".to_string())),
            )
            .await,
            Err(AppError::Forbidden(_))
        ));
        assert!(
            OrganizationBillingCredentialsStore::get_status(
                DB::Conn(&f.state.db),
                &f.beta_id,
                "stripe",
            )
            .await
            .expect("load beta credentials")
            .is_some(),
            "cross-tenant delete must preserve beta credentials"
        );

        // A permitted custom manager can delete alpha credentials.
        seed_credentials(&f.state.db, &f.alpha_id, "stripe", "test").await;
        let _ = delete_billing_credentials(
            State(f.state.clone()),
            Extension(f.custom_manager.clone()),
            Path((f.alpha_slug.clone(), "stripe".to_string())),
        )
        .await
        .expect("billing manager may delete alpha credentials");
        assert!(OrganizationBillingCredentialsStore::get_status(
            DB::Conn(&f.state.db),
            &f.alpha_id,
            "stripe",
        )
        .await
        .expect("load alpha credentials")
        .is_none());
        assert!(
            OrganizationBillingCredentialsStore::get_status(
                DB::Conn(&f.state.db),
                &f.beta_id,
                "stripe",
            )
            .await
            .expect("load beta credentials")
            .is_some(),
            "beta credentials must remain after alpha mutation"
        );
    }

    #[tokio::test]
    async fn billing_info_and_portal_require_billing_capability() {
        let f = fixture().await;

        for auth in [f.owner.clone(), f.admin.clone(), f.custom_manager.clone()] {
            let Json(info) = crate::handlers::organizations::billing::get_billing_info(
                State(f.state.clone()),
                Extension(auth),
                Path(f.alpha_slug.clone()),
            )
            .await
            .expect("billing manager may read billing info");
            assert!(!info.has_billing_account);
        }
        for auth in [f.member.clone(), f.outsider.clone(), f.other_owner.clone()] {
            assert!(matches!(
                crate::handlers::organizations::billing::get_billing_info(
                    State(f.state.clone()),
                    Extension(auth),
                    Path(f.alpha_slug.clone()),
                )
                .await,
                Err(AppError::Forbidden(_))
            ));
        }

        assert!(matches!(
            crate::handlers::organizations::billing::create_portal_session(
                State(f.state.clone()),
                Extension(f.member.clone()),
                Path(f.alpha_slug.clone()),
                Json(
                    crate::handlers::organizations::billing::BillingPortalRequest {
                        return_url: "https://example.test/billing".to_string(),
                    }
                ),
            )
            .await,
            Err(AppError::Forbidden(_))
        ));
        assert!(matches!(
            crate::handlers::organizations::billing::create_portal_session(
                State(f.state.clone()),
                Extension(f.owner.clone()),
                Path(f.alpha_slug.clone()),
                Json(
                    crate::handlers::organizations::billing::BillingPortalRequest {
                        return_url: "https://example.test/billing".to_string(),
                    }
                ),
            )
            .await,
            Err(AppError::ServiceUnavailable(_))
        ));
        assert!(matches!(
            crate::handlers::organizations::billing::create_portal_session(
                State(f.state.clone()),
                Extension(f.owner.clone()),
                Path(f.beta_slug.clone()),
                Json(
                    crate::handlers::organizations::billing::BillingPortalRequest {
                        return_url: "https://example.test/billing".to_string(),
                    }
                ),
            )
            .await,
            Err(AppError::Forbidden(_))
        ));
    }
}
