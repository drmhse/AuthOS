use crate::db::DB;
use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use crate::services::permission_service::{PermissionService, CAP_INTEGRATIONS_MANAGE};
use crate::services::tier_enforcement::TierService;
use crate::state::AppState;
use crate::store::{organizations::OrganizationStore, scim_tokens::ScimTokenStore};
use axum::{
    extract::{Path, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
pub struct CreateScimTokenRequest {
    pub name: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateScimTokenResponse {
    pub id: String,
    pub name: String,
    pub token: String,
    pub prefix: String,
    pub created_at: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ScimTokenResponse {
    pub id: String,
    pub name: String,
    pub prefix: String,
    pub active: bool,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
}

/// Create a new SCIM token for an organization
pub async fn create_scim_token(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
    Json(req): Json<CreateScimTokenRequest>,
) -> Result<Json<CreateScimTokenResponse>> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_integration_manager(&state, &org.id, &auth_user.user.id).await?;

    // Tier/Entitlement Check
    TierService::check_feature_access(
        DB::Conn(&state.db),
        &org.id,
        |f| f.allow_scim,
        "SCIM Provisioning",
    )
    .await?;

    let (plain_token, prefix, hash) = ScimTokenStore::generate();

    // Parse expires_at if provided
    let expires_at_naive = if let Some(expires_at_str) = &req.expires_at {
        Some(
            DateTime::parse_from_rfc3339(expires_at_str)
                .map_err(|e| AppError::BadRequest(format!("Invalid expires_at format: {}", e)))?
                .naive_utc(),
        )
    } else {
        None
    };

    let token_model = ScimTokenStore::create(
        DB::Conn(&state.db),
        &org.id,
        &req.name,
        &hash,
        &prefix,
        &auth_user.user.id,
        expires_at_naive,
    )
    .await?;

    Ok(Json(CreateScimTokenResponse {
        id: token_model.id,
        name: token_model.name,
        token: plain_token,
        prefix: token_model.prefix,
        created_at: DateTime::<Utc>::from_naive_utc_and_offset(token_model.created_at, Utc)
            .to_rfc3339(),
        expires_at: token_model
            .expires_at
            .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc).to_rfc3339()),
    }))
}

/// List SCIM tokens for an organization
pub async fn list_scim_tokens(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
) -> Result<Json<Vec<ScimTokenResponse>>> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_integration_manager(&state, &org.id, &auth_user.user.id).await?;

    let tokens = ScimTokenStore::list_by_org(DB::Conn(&state.db), &org.id).await?;

    let response = tokens
        .into_iter()
        .map(|token| ScimTokenResponse {
            id: token.id,
            name: token.name,
            prefix: token.prefix,
            active: token.active,
            created_at: DateTime::<Utc>::from_naive_utc_and_offset(token.created_at, Utc)
                .to_rfc3339(),
            expires_at: token
                .expires_at
                .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc).to_rfc3339()),
            last_used_at: token
                .last_used_at
                .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc).to_rfc3339()),
        })
        .collect();

    Ok(Json(response))
}

/// Revoke a SCIM token
pub async fn revoke_scim_token(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, token_id)): Path<(String, String)>,
) -> Result<Json<()>> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_integration_manager(&state, &org.id, &auth_user.user.id).await?;
    if !ScimTokenStore::revoke_in_org(DB::Conn(&state.db), &org.id, &token_id).await? {
        return Err(AppError::NotFound("SCIM token not found".to_string()));
    }

    Ok(Json(()))
}

/// Delete a SCIM token
pub async fn delete_scim_token(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, token_id)): Path<(String, String)>,
) -> Result<Json<()>> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_integration_manager(&state, &org.id, &auth_user.user.id).await?;
    if !ScimTokenStore::delete_in_org(DB::Conn(&state.db), &org.id, &token_id).await? {
        return Err(AppError::NotFound("SCIM token not found".to_string()));
    }

    Ok(Json(()))
}

#[cfg(test)]
mod route_tests {
    use super::*;

    use crate::audit::actor::AuditHandle;
    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::crypto::sso::OAuthClient;
    use crate::entities::{scim_tokens, users};
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
        member: AuthUser,
        custom_role: AuthUser,
        outsider: AuthUser,
        alpha_id: String,
        alpha_slug: String,
        beta_slug: String,
        alpha_token_id: String,
        beta_token_id: String,
    }

    async fn seed_token(
        db: &sea_orm::DatabaseConnection,
        org_id: &str,
        name: &str,
        created_by: &str,
    ) -> scim_tokens::Model {
        let (_plain, prefix, hash) = ScimTokenStore::generate();
        ScimTokenStore::create(DB::Conn(db), org_id, name, &hash, &prefix, created_by, None)
            .await
            .expect("seed SCIM token")
    }

    async fn fixture() -> Fixture {
        let db = setup_db().await;
        let config = test_config();
        let jwt_service = Arc::new(test_jwt_service(&config));

        let owner = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "scim-owner@example.test",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create owner")
        .0;
        let other_owner = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "scim-other-owner@example.test",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create other owner")
        .0;
        let admin = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "scim-admin@example.test",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create admin")
        .0;
        let member = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "scim-member@example.test",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create member")
        .0;
        let custom = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "scim-custom@example.test",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create custom-role user")
        .0;
        let outsider = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "scim-outsider@example.test",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create outsider")
        .0;

        let (alpha, _) = OrganizationStore::create_with_owner(
            DB::Conn(&db),
            "scim-alpha",
            "SCIM Alpha",
            &owner.id,
            Some("tier_enterprise"),
        )
        .await
        .expect("create alpha");
        let (beta, _) = OrganizationStore::create_with_owner(
            DB::Conn(&db),
            "scim-beta",
            "SCIM Beta",
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
            "scim-integration-manager-role",
            &alpha.id,
            "integration-manager",
            "Integration Manager",
            None,
            json!([CAP_INTEGRATIONS_MANAGE]),
        )
        .await
        .expect("create integration-manager role");
        MembershipStore::create(DB::Conn(&db), &alpha.id, &custom.id, "integration-manager")
            .await
            .expect("add custom-role user");

        let alpha_token = seed_token(&db, &alpha.id, "alpha-token", &owner.id).await;
        let beta_token = seed_token(&db, &beta.id, "beta-token", &other_owner.id).await;

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
                user_agent: "scim-route-test".to_string(),
                current_session_id: None,
            }
        };
        let owner_auth = auth_user_for(&owner);
        let admin_auth = auth_user_for(&admin);
        let member_auth = auth_user_for(&member);
        let custom_auth = auth_user_for(&custom);
        let outsider_auth = auth_user_for(&outsider);

        Fixture {
            state,
            owner: owner_auth,
            admin: admin_auth,
            member: member_auth,
            custom_role: custom_auth,
            outsider: outsider_auth,
            alpha_id: alpha.id,
            alpha_slug: alpha.slug,
            beta_slug: beta.slug,
            alpha_token_id: alpha_token.id,
            beta_token_id: beta_token.id,
        }
    }

    async fn single_token_list(
        state: &AppState,
        auth: AuthUser,
        org_slug: &str,
    ) -> Result<Json<Vec<ScimTokenResponse>>> {
        list_scim_tokens(State(state.clone()), auth, Path(org_slug.to_string())).await
    }

    #[tokio::test]
    async fn scim_token_routes_require_live_integration_authority() {
        let f = fixture().await;

        for auth in [f.owner.clone(), f.admin.clone(), f.custom_role.clone()] {
            let Json(tokens) = single_token_list(&f.state, auth, &f.alpha_slug)
                .await
                .expect("integration manager may list");
            let ids: Vec<&str> = tokens.iter().map(|token| token.id.as_str()).collect();
            assert!(ids.contains(&f.alpha_token_id.as_str()));
            assert!(!ids.contains(&f.beta_token_id.as_str()));
        }

        let tokens_before_denied_creates =
            ScimTokenStore::list_by_org(DB::Conn(&f.state.db), &f.alpha_id)
                .await
                .expect("list alpha tokens")
                .len();
        for auth in [f.member.clone(), f.outsider.clone()] {
            match single_token_list(&f.state, auth.clone(), &f.alpha_slug).await {
                Err(AppError::Forbidden(_)) => {}
                other => panic!("expected forbidden SCIM list, got {other:?}"),
            }
            match create_scim_token(
                State(f.state.clone()),
                auth,
                Path(f.alpha_slug.clone()),
                Json(CreateScimTokenRequest {
                    name: "denied-token".to_string(),
                    expires_at: None,
                }),
            )
            .await
            {
                Err(AppError::Forbidden(_)) => {}
                other => panic!("expected forbidden SCIM create, got {other:?}"),
            }
        }
        assert_eq!(
            ScimTokenStore::list_by_org(DB::Conn(&f.state.db), &f.alpha_id)
                .await
                .expect("list alpha tokens")
                .len(),
            tokens_before_denied_creates,
            "denied SCIM creates must not persist a token"
        );

        // A custom role holding only integrations.manage can create a token.
        let Json(created) = create_scim_token(
            State(f.state.clone()),
            f.custom_role.clone(),
            Path(f.alpha_slug.clone()),
            Json(CreateScimTokenRequest {
                name: "custom-created".to_string(),
                expires_at: Some((Utc::now() + chrono::Duration::days(1)).to_rfc3339()),
            }),
        )
        .await
        .expect("custom integration manager may create");
        assert!(!created.token.is_empty());
        assert!(!created.id.is_empty());
        assert!(created.expires_at.is_some());
        let Json(tokens_after_create) = single_token_list(&f.state, f.owner.clone(), &f.alpha_slug)
            .await
            .expect("list alpha tokens after create");
        assert!(
            tokens_after_create
                .iter()
                .any(|token| token.id == created.id),
            "created token must be visible in the selected organization"
        );

        // A tenant actor cannot revoke or delete another tenant's token, and
        // the denied operations leave that token active and present.
        match revoke_scim_token(
            State(f.state.clone()),
            f.owner.clone(),
            Path((f.alpha_slug.clone(), f.beta_token_id.clone())),
        )
        .await
        {
            Err(AppError::NotFound(_)) => {}
            other => panic!("expected cross-tenant revoke refusal, got {other:?}"),
        }
        let beta_after_revoke = ScimTokenStore::find_by_id(DB::Conn(&f.state.db), &f.beta_token_id)
            .await
            .expect("load beta token")
            .expect("beta token remains");
        assert!(beta_after_revoke.active);

        match delete_scim_token(
            State(f.state.clone()),
            f.owner.clone(),
            Path((f.alpha_slug.clone(), f.beta_token_id.clone())),
        )
        .await
        {
            Err(AppError::NotFound(_)) => {}
            other => panic!("expected cross-tenant delete refusal, got {other:?}"),
        }
        for operation in ["revoke", "delete"] {
            let result = if operation == "revoke" {
                revoke_scim_token(
                    State(f.state.clone()),
                    f.owner.clone(),
                    Path((f.alpha_slug.clone(), "missing-token".to_string())),
                )
                .await
                .err()
            } else {
                delete_scim_token(
                    State(f.state.clone()),
                    f.owner.clone(),
                    Path((f.alpha_slug.clone(), "missing-token".to_string())),
                )
                .await
                .err()
            };
            assert!(
                matches!(result, Some(AppError::NotFound(_))),
                "expected nonexistent token {operation} refusal, got {result:?}"
            );
        }
        assert!(
            ScimTokenStore::find_by_id(DB::Conn(&f.state.db), &f.beta_token_id)
                .await
                .expect("load beta token")
                .is_some(),
            "cross-tenant delete must preserve beta token"
        );

        // A member and outsider cannot mutate an alpha token.
        match revoke_scim_token(
            State(f.state.clone()),
            f.member.clone(),
            Path((f.alpha_slug.clone(), f.alpha_token_id.clone())),
        )
        .await
        {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected member revoke refusal, got {other:?}"),
        }
        assert!(
            ScimTokenStore::find_by_id(DB::Conn(&f.state.db), &f.alpha_token_id)
                .await
                .expect("load alpha token")
                .expect("alpha token remains")
                .active
        );
        match delete_scim_token(
            State(f.state.clone()),
            f.outsider.clone(),
            Path((f.alpha_slug.clone(), f.alpha_token_id.clone())),
        )
        .await
        {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected outsider delete refusal, got {other:?}"),
        }
        assert!(
            ScimTokenStore::find_by_id(DB::Conn(&f.state.db), &f.alpha_token_id)
                .await
                .expect("load alpha token")
                .is_some(),
            "outsider delete must preserve alpha token"
        );

        // The owner can revoke and delete a token in the selected organization.
        let _ = revoke_scim_token(
            State(f.state.clone()),
            f.owner.clone(),
            Path((f.alpha_slug.clone(), f.alpha_token_id.clone())),
        )
        .await
        .expect("owner may revoke");
        assert!(
            !ScimTokenStore::find_by_id(DB::Conn(&f.state.db), &f.alpha_token_id)
                .await
                .expect("load alpha token")
                .expect("alpha token remains")
                .active
        );
        let _ = delete_scim_token(
            State(f.state.clone()),
            f.owner.clone(),
            Path((f.alpha_slug.clone(), f.alpha_token_id.clone())),
        )
        .await
        .expect("owner may delete");
        assert!(
            ScimTokenStore::find_by_id(DB::Conn(&f.state.db), &f.alpha_token_id)
                .await
                .expect("load deleted token")
                .is_none()
        );

        // Cross-tenant listing is denied before any token row is exposed.
        match single_token_list(&f.state, f.owner.clone(), &f.beta_slug).await {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected cross-tenant list refusal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn scim_token_creation_rejects_invalid_expiry_without_persisting() {
        let f = fixture().await;
        let before = ScimTokenStore::list_by_org(DB::Conn(&f.state.db), &f.alpha_id)
            .await
            .expect("list alpha tokens")
            .len();
        match create_scim_token(
            State(f.state.clone()),
            f.owner.clone(),
            Path(f.alpha_slug.clone()),
            Json(CreateScimTokenRequest {
                name: "bad-expiry".to_string(),
                expires_at: Some("not-a-date".to_string()),
            }),
        )
        .await
        {
            Err(AppError::BadRequest(message)) => assert!(message.contains("expires_at")),
            other => panic!("expected invalid expiry refusal, got {other:?}"),
        }
        let after = ScimTokenStore::list_by_org(DB::Conn(&f.state.db), &f.alpha_id)
            .await
            .expect("list alpha tokens")
            .len();
        assert_eq!(after, before);
    }

    #[tokio::test]
    async fn suspended_parent_denies_every_scim_token_route_without_state_changes() {
        let f = fixture().await;
        let tokens_before = ScimTokenStore::list_by_org(DB::Conn(&f.state.db), &f.alpha_id)
            .await
            .expect("list alpha tokens")
            .len();
        OrganizationStore::update_status(DB::Conn(&f.state.db), &f.alpha_id, "suspended")
            .await
            .expect("suspend alpha");

        for result in [
            single_token_list(&f.state, f.owner.clone(), &f.alpha_slug)
                .await
                .err(),
            create_scim_token(
                State(f.state.clone()),
                f.owner.clone(),
                Path(f.alpha_slug.clone()),
                Json(CreateScimTokenRequest {
                    name: "suspended".to_string(),
                    expires_at: None,
                }),
            )
            .await
            .err(),
            revoke_scim_token(
                State(f.state.clone()),
                f.owner.clone(),
                Path((f.alpha_slug.clone(), f.alpha_token_id.clone())),
            )
            .await
            .err(),
            delete_scim_token(
                State(f.state.clone()),
                f.owner.clone(),
                Path((f.alpha_slug.clone(), f.alpha_token_id.clone())),
            )
            .await
            .err(),
        ] {
            assert!(
                matches!(result, Some(AppError::Forbidden(ref message)) if message.contains("active")),
                "expected inactive-parent refusal, got {result:?}"
            );
        }
        assert!(
            ScimTokenStore::find_by_id(DB::Conn(&f.state.db), &f.alpha_token_id)
                .await
                .expect("load alpha token")
                .expect("alpha token remains")
                .active
        );
        assert_eq!(
            ScimTokenStore::list_by_org(DB::Conn(&f.state.db), &f.alpha_id)
                .await
                .expect("list alpha tokens after suspension")
                .len(),
            tokens_before,
            "suspended-parent denials must not create or delete tokens"
        );
    }
}
