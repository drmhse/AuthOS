use crate::constants::{
    DEFAULT_MAX_ORGS_PER_USER, DEFAULT_TIER_NAME, MAX_NAME_LENGTH, MAX_SLUG_LENGTH,
    MIN_NAME_LENGTH, MIN_SLUG_LENGTH, RESERVED_SLUGS,
};
use crate::crypto::jwt::JwtService;
use crate::db::transaction::with_retrying_transaction;
use crate::db::DB;
use crate::entities::{memberships, organization_tiers, organizations, platform_audit_log, users};
use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use crate::services::permission_service::{
    PermissionService, CAP_ORG_SETTINGS_MANAGE, CAP_RISK_EVENTS_VIEW, CAP_RISK_POLICIES_MANAGE,
};
use crate::state::AppState;
use crate::store::{
    memberships::MembershipStore, organization_tiers::OrganizationTierStore,
    organizations::OrganizationStore, risk_rules::RiskRulesStore, services::ServiceStore,
    sessions::SessionStore,
};
use axum::{
    extract::{Extension, Path, Query, State},
    Json,
};
use chrono::Utc;
use sea_orm::{DatabaseConnection, Set};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct CreateOrganizationRequest {
    pub slug: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateOrganizationRequest {
    pub name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct OrganizationResponse {
    pub organization: organizations::Model,
    pub membership_count: i64,
    pub service_count: i64,
    pub tier: Option<organization_tiers::Model>,
}

async fn require_capability(
    state: &AppState,
    org_id: &str,
    auth_user: &AuthUser,
    capability: &str,
    message: &str,
) -> Result<()> {
    if crate::middleware::has_live_platform_authority(&state.db, auth_user).await?
        || PermissionService::check(DB::Conn(&state.db), org_id, &auth_user.user.id, capability)
            .await?
    {
        return Ok(());
    }

    Err(AppError::Forbidden(message.to_string()))
}

async fn require_any_capability(
    state: &AppState,
    org_id: &str,
    auth_user: &AuthUser,
    capabilities: &[&str],
    message: &str,
) -> Result<()> {
    if crate::middleware::has_live_platform_authority(&state.db, auth_user).await?
        || PermissionService::check_any(
            DB::Conn(&state.db),
            org_id,
            &auth_user.user.id,
            capabilities,
        )
        .await?
    {
        return Ok(());
    }

    Err(AppError::Forbidden(message.to_string()))
}

async fn current_session_created_at(
    state: &AppState,
    auth_user: &AuthUser,
) -> Result<chrono::NaiveDateTime> {
    let Some(session_id) = auth_user.current_session_id.as_deref() else {
        return Ok(Utc::now().naive_utc());
    };
    let session = crate::store::sessions::SessionStore::find_by_id(DB::Conn(&state.db), session_id)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Session is no longer active".to_string()))?;
    Ok(session.created_at)
}

#[derive(Debug, Serialize)]
pub struct CreateOrganizationResponse {
    pub organization: organizations::Model,
    pub owner: users::Model,
    pub membership: memberships::Model,
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct ListOrganizationsQuery {
    pub page: Option<i64>,
    pub limit: Option<i64>,
    pub status: Option<String>,
}

/// Create a new organization (requires authentication)
/// Uses with_retrying_transaction for automatic retry on SQLite busy errors
pub async fn create_organization(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Json(req): Json<CreateOrganizationRequest>,
) -> Result<Json<CreateOrganizationResponse>> {
    // Validate input
    validate_organization_slug(&req.slug)?;
    validate_organization_name(&req.name)?;

    // Use authenticated user as owner
    let owner = auth_user.user.clone();

    // Check organization creation rate limit (configurable via env var)
    let max_orgs_per_user = std::env::var("MAX_ORGS_PER_USER")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_MAX_ORGS_PER_USER);

    let current_org_count =
        OrganizationStore::count_by_owner(DB::Conn(&state.db), &owner.id).await?;
    if current_org_count >= max_orgs_per_user {
        return Err(AppError::BadRequest(format!(
            "You have reached the maximum number of organizations ({}) you can create. Please contact support if you need more.",
            max_orgs_per_user
        )));
    }

    // Clone values needed inside the closure
    let slug = req.slug.clone();
    let name = req.name.clone();
    let owner_id = owner.id.clone();

    // Execute transaction with automatic retry on database contention
    let (organization, membership) = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "create_organization",
        |db| {
            let slug = slug.clone();
            let name = name.clone();
            let owner_id = owner_id.clone();
            Box::pin(async move {
                // Check if slug already exists
                let existing = OrganizationStore::find_by_slug(db.clone(), &slug).await?;
                if existing.is_some() {
                    return Err(AppError::BadRequest(
                        "Unable to create organization with the provided information".to_string(),
                    ));
                }

                let free_tier = OrganizationTierStore::find_by_name(db.clone(), DEFAULT_TIER_NAME)
                    .await?
                    .ok_or_else(|| AppError::NotFound("Free tier not found".to_string()))?;

                let organization = OrganizationStore::create(
                    db.clone(),
                    &slug,
                    &name,
                    &owner_id,
                    Some(&free_tier.id),
                )
                .await
                .map_err(|e| {
                    // Convert unique constraint violations to user-friendly errors
                    let error_msg = e.to_string().to_lowercase();
                    if error_msg.contains("unique")
                        || error_msg.contains("duplicate")
                        || error_msg.contains("constraint")
                    {
                        AppError::BadRequest(
                            "Unable to create organization with the provided information"
                                .to_string(),
                        )
                    } else {
                        e
                    }
                })?;

                // Create owner membership
                let membership =
                    MembershipStore::create(db.clone(), &organization.id, &owner_id, "owner")
                        .await?;

                // Grant organization owner permission
                use crate::entities::permissions::RelationTuple;
                use crate::store::permissions::PermissionsStore;
                PermissionsStore::grant(
                    db.clone(),
                    RelationTuple::user(
                        "organization".to_string(),
                        organization.id.clone(),
                        "owner".to_string(),
                        owner_id.clone(),
                    ),
                )
                .await?;

                // Create default risk rules for the organization
                use crate::store::risk_rules::RiskRulesStore;
                RiskRulesStore::create_default(db.clone(), &organization.id).await?;

                Ok((organization, membership))
            })
        },
    )
    .await?;

    if state.billing_provider.provider_type() != crate::billing::BillingProviderType::Disabled {
        // We ignore errors here as we don't want to fail org creation if billing setup fails.
        if let Err(e) =
            super::billing::create_billing_customer(&state, &organization.id, &organization.name)
                .await
        {
            tracing::error!(
                "Failed to create billing customer for org {}: {}",
                organization.id,
                e
            );
        }
    }

    // Generate JWT with organization context
    let access_token = state
        .jwt_service
        .create_token(
            &owner.id,
            &owner.email,
            owner.is_platform_owner,
            Some(&organization.slug),
            None, // service_slug
        )
        .map_err(|e| AppError::InternalServerError(format!("Failed to create JWT: {}", e)))?;

    let refresh_token = crate::crypto::refresh_tokens::generate();
    let session_created_at = current_session_created_at(&state, &auth_user).await?;

    // Store session with refresh token. The new organization context is a
    // session switch, not a fresh authentication; preserve the original auth
    // time for recent-auth step-up checks.
    let token_hash = JwtService::hash_token(&access_token);
    let now = Utc::now();
    let expires_at = now + chrono::Duration::hours(state.config.jwt_expiration_hours);
    let refresh_expires_at = now + chrono::Duration::days(30);

    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "create_org_session",
        |db| {
            let user_id = owner.id.clone();
            let token_hash = token_hash.clone();
            let refresh_token = refresh_token.clone();
            let org_slug = organization.slug.clone();
            Box::pin(async move {
                SessionStore::create_with_created_at(
                    db.clone(),
                    &user_id,
                    &token_hash,
                    expires_at.naive_utc(),
                    Some(&refresh_token),
                    Some(refresh_expires_at.naive_utc()),
                    Some(&org_slug),
                    None, // service_id
                    None, // resource
                    None, // user_agent
                    None, // ip_address
                    session_created_at,
                )
                .await
            })
        },
    )
    .await?;

    Ok(Json(CreateOrganizationResponse {
        organization,
        owner,
        membership,
        access_token,
        refresh_token,
    }))
}

/// Get organization by slug
pub async fn get_organization(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
) -> Result<Json<OrganizationResponse>> {
    let user = &auth_user.user;

    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is member
    crate::middleware::check_org_membership(&state.db, &user.id, &organization.id, &[]).await?;

    let (membership_count, service_count, tier) =
        get_organization_stats(&state.db, &organization.id).await?;

    Ok(Json(OrganizationResponse {
        organization,
        membership_count,
        service_count,
        tier,
    }))
}

/// Update organization settings.
pub async fn update_organization(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
    Json(req): Json<UpdateOrganizationRequest>,
) -> Result<Json<OrganizationResponse>> {
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_capability(
        &state,
        &organization.id,
        &auth_user,
        CAP_ORG_SETTINGS_MANAGE,
        "Insufficient permissions to manage organization settings",
    )
    .await?;

    // Verify changes
    let updated_org = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "update_organization",
        |db| {
            let org_id = organization.id.clone();
            let name = req.name.clone();
            Box::pin(async move {
                if let Some(name) = &name {
                    // Validate name length
                    validate_organization_name(name)?;
                    OrganizationStore::update_name(db.clone(), &org_id, name).await
                } else {
                    // If no fields were updated, just update the timestamp
                    OrganizationStore::update_timestamp(db.clone(), &org_id).await
                }
            })
        },
    )
    .await?;

    let (membership_count, service_count, tier) =
        get_organization_stats(&state.db, &organization.id).await?;

    Ok(Json(OrganizationResponse {
        organization: updated_org,
        membership_count,
        service_count,
        tier,
    }))
}

/// Delete organization (owner only)
pub async fn delete_organization(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
) -> Result<Json<()>> {
    let user = &auth_user.user;

    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is owner (only owners can delete)
    crate::middleware::check_org_owner(&state.db, &user.id, &organization.id).await?;

    let deletion_audit = platform_audit_log::ActiveModel {
        id: Set(uuid::Uuid::new_v4().to_string()),
        platform_owner_id: Set(user.id.clone()),
        action: Set("org.deleted".to_string()),
        target_type: Set("organization".to_string()),
        target_id: Set(organization.id.clone()),
        metadata: Set(Some(
            serde_json::json!({
                "org_slug": org_slug,
                "org_name": organization.name,
                "deleted_by_org_owner": true,
            })
            .to_string(),
        )),
        ..Default::default()
    };

    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "delete_organization",
        |db| {
            let org_id = organization.id.clone();
            let deletion_audit = deletion_audit.clone();
            let audit_actor = state.audit_actor.clone();
            Box::pin(async move {
                OrganizationStore::delete(db.clone(), &org_id).await?;
                audit_actor.log_platform_with_db(db, deletion_audit).await?;
                Ok(())
            })
        },
    )
    .await?;

    Ok(Json(()))
}

/// List user's organizations
pub async fn list_user_organizations(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Query(query): Query<ListOrganizationsQuery>,
) -> Result<Json<Vec<OrganizationResponse>>> {
    let user = &auth_user.user;

    let (_page, limit, offset) =
        crate::utils::pagination::signed_page(query.page, query.limit, 20, 100);

    // Get user's organizations with optional status filter
    let (limit_u64, offset_u64) = crate::utils::pagination::store_u64(limit, offset, 100);
    let organizations = OrganizationStore::list_by_user_with_status(
        DB::Conn(&state.db),
        &user.id,
        query.status.as_deref(),
        limit_u64,
        offset_u64,
    )
    .await?;

    let org_ids = organizations
        .iter()
        .map(|org| org.id.clone())
        .collect::<Vec<_>>();
    let membership_counts = MembershipStore::count_by_orgs(DB::Conn(&state.db), &org_ids).await?;
    let service_counts = ServiceStore::count_by_orgs(DB::Conn(&state.db), &org_ids).await?;
    let tier_ids = organizations
        .iter()
        .filter_map(|org| org.tier_id.clone())
        .collect::<Vec<_>>();
    let tiers = OrganizationTierStore::find_by_ids(DB::Conn(&state.db), &tier_ids)
        .await?
        .into_iter()
        .map(|tier| (tier.id.clone(), tier))
        .collect::<std::collections::HashMap<_, _>>();

    let results = organizations
        .into_iter()
        .map(|org| {
            let membership_count = membership_counts.get(&org.id).copied().unwrap_or(0);
            let service_count = service_counts.get(&org.id).copied().unwrap_or(0);
            let tier = org
                .tier_id
                .as_ref()
                .and_then(|tier_id| tiers.get(tier_id).cloned());

            OrganizationResponse {
                organization: org,
                membership_count,
                service_count,
                tier,
            }
        })
        .collect();

    Ok(Json(results))
}

/// Response for selecting an organization
#[derive(Debug, Serialize)]
pub struct SelectOrganizationResponse {
    pub organization: organizations::Model,
    pub membership: memberships::Model,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
}

/// POST /api/organizations/:org_slug/select - Switch to a different organization context
///
/// This endpoint allows an authenticated user to switch their session to a different
/// organization they are a member of. It issues a new JWT with the organization context
/// and creates a new session, enabling seamless organization switching without re-authentication.
pub async fn select_organization(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
) -> Result<Json<SelectOrganizationResponse>> {
    let user = &auth_user.user;

    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Verify the organization is active
    if organization.status != "active" {
        return Err(AppError::Forbidden(format!(
            "Organization is not active. Current status: {}",
            organization.status
        )));
    }

    // Verify user is a member of this organization
    let membership =
        MembershipStore::find_by_org_slug_and_user(DB::Conn(&state.db), &org_slug, &user.id)
            .await?
            .ok_or_else(|| {
                AppError::Forbidden("You are not a member of this organization".to_string())
            })?;

    crate::services::tier_enforcement::TierService::check_mau_limit(
        DB::Conn(&state.db),
        &organization.id,
    )
    .await?;

    // Generate new JWT with organization context
    let access_token = state
        .jwt_service
        .create_token(
            &user.id,
            &user.email,
            user.is_platform_owner,
            Some(&org_slug),
            None, // service_slug
        )
        .map_err(|e| AppError::InternalServerError(format!("Failed to create JWT: {}", e)))?;

    let refresh_token = crate::crypto::refresh_tokens::generate();

    let session_created_at = current_session_created_at(&state, &auth_user).await?;

    // Store session with refresh token. Switching organization is not a fresh
    // authentication; preserve the original auth time.
    let token_hash = JwtService::hash_token(&access_token);
    let now = Utc::now();
    let expires_at = now + chrono::Duration::hours(state.config.jwt_expiration_hours);
    let refresh_expires_at = now + chrono::Duration::days(30);

    // Clone values for transaction
    let user_id = user.id.clone();
    let token_hash_clone = token_hash.clone();
    let refresh_token_clone = refresh_token.clone();
    let org_slug_clone = org_slug.clone();

    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "select_org_session",
        |db| {
            let user_id = user_id.clone();
            let token_hash = token_hash_clone.clone();
            let refresh_token = refresh_token_clone.clone();
            let org_slug = org_slug_clone.clone();
            Box::pin(async move {
                SessionStore::create_with_created_at(
                    db.clone(),
                    &user_id,
                    &token_hash,
                    expires_at.naive_utc(),
                    Some(&refresh_token),
                    Some(refresh_expires_at.naive_utc()),
                    Some(&org_slug),
                    None, // service_id
                    None, // resource
                    None, // user_agent
                    None, // ip_address
                    session_created_at,
                )
                .await
            })
        },
    )
    .await?;

    tracing::info!(
        user_id = %user.id,
        org_slug = %org_slug,
        "User switched organization context"
    );

    Ok(Json(SelectOrganizationResponse {
        organization,
        membership,
        access_token,
        refresh_token,
        expires_in: state.config.jwt_expiration_hours * 3600,
    }))
}

// Helper functions

pub async fn get_organization_stats(
    pool: &DatabaseConnection,
    org_id: &str,
) -> Result<(i64, i64, Option<organization_tiers::Model>)> {
    let membership_count =
        MembershipStore::count_by_org(DB::Conn(pool), org_id, None).await? as i64;

    let service_count = ServiceStore::count_by_org(DB::Conn(pool), org_id).await? as i64;

    let tier = OrganizationTierStore::find_by_org_id(DB::Conn(pool), org_id).await?;

    Ok((membership_count, service_count, tier))
}

// Validation helper functions

pub fn validate_organization_slug(slug: &str) -> Result<()> {
    if slug.len() < MIN_SLUG_LENGTH || slug.len() > MAX_SLUG_LENGTH {
        return Err(AppError::BadRequest(format!(
            "Slug must be between {} and {} characters",
            MIN_SLUG_LENGTH, MAX_SLUG_LENGTH
        )));
    }

    if !slug
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err(AppError::BadRequest(
            "Slug can only contain lowercase alphanumeric characters, hyphens, and underscores"
                .to_string(),
        ));
    }

    // Check for reserved slugs
    if RESERVED_SLUGS.contains(&slug) {
        return Err(AppError::BadRequest("Slug is reserved".to_string()));
    }

    Ok(())
}

pub fn validate_organization_name(name: &str) -> Result<()> {
    if name.len() < MIN_NAME_LENGTH || name.len() > MAX_NAME_LENGTH {
        return Err(AppError::BadRequest(format!(
            "Name must be between {} and {} characters",
            MIN_NAME_LENGTH, MAX_NAME_LENGTH
        )));
    }

    if name.trim().is_empty() {
        return Err(AppError::BadRequest("Name cannot be empty".to_string()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::crypto::sso::OAuthClient;

    use crate::audit::actor::AuditHandle;
    use crate::services::{
        events::EventDispatcher, metrics::MfaMetricsService, risk_engine::RiskEngine,
    };
    use crate::store::{
        organization_roles::OrganizationRoleStore,
        sessions::SessionStore,
        users::{UserCreationOptions, UserStore},
    };
    use serde_json::json;

    use migration::{Migrator, MigratorTrait};
    use moka::future::Cache;
    use sea_orm::Database;
    use std::sync::Arc;

    struct OrgSwitchFixture {
        state: AppState,
        auth_user: AuthUser,
        alpha_slug: String,
        beta_id: String,
        beta_slug: String,
        gamma_slug: String,
        member_auth: AuthUser,
        custom_role_auth: AuthUser,
        admin_auth: AuthUser,
        outsider_auth: AuthUser,
    }

    use crate::test_support::test_config;

    use crate::test_support::test_jwt_service;

    async fn setup_org_switch_fixture() -> OrgSwitchFixture {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let config = test_config();
        let jwt_service = Arc::new(test_jwt_service(&config));
        let oauth_client = Arc::new(OAuthClient::new(&config).expect("create oauth client"));

        let user = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "multi@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create switching user")
        .0;
        let other_owner = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "other@example.com",
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
            "alpha",
            "Alpha",
            &user.id,
            Some("tier_enterprise"),
        )
        .await
        .expect("create alpha org");
        let (beta, _) = OrganizationStore::create_with_owner(
            DB::Conn(&db),
            "beta",
            "Beta",
            &user.id,
            Some("tier_enterprise"),
        )
        .await
        .expect("create beta org");
        let (gamma, _) = OrganizationStore::create_with_owner(
            DB::Conn(&db),
            "gamma",
            "Gamma",
            &other_owner.id,
            Some("tier_enterprise"),
        )
        .await
        .expect("create gamma org");
        for org in [&alpha, &beta, &gamma] {
            OrganizationStore::update_status(DB::Conn(&db), &org.id, "active")
                .await
                .expect("activate org");
        }

        let member_model = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "alpha-member@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create alpha member")
        .0;
        let custom_role_model = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "alpha-custom@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create custom-role user")
        .0;
        let admin_model = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "alpha-admin@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create alpha admin")
        .0;
        let outsider_model = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "alpha-outsider@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create outsider")
        .0;

        MembershipStore::create(DB::Conn(&db), &alpha.id, &member_model.id, "member")
            .await
            .expect("add member to alpha");
        OrganizationRoleStore::create(
            DB::Conn(&db),
            "alpha-settings-manager-role",
            &alpha.id,
            "settings-manager",
            "Settings Manager",
            None,
            json!([CAP_ORG_SETTINGS_MANAGE]),
        )
        .await
        .expect("create custom settings-manager role");
        MembershipStore::create(
            DB::Conn(&db),
            &alpha.id,
            &custom_role_model.id,
            "settings-manager",
        )
        .await
        .expect("add custom-role user to alpha");
        MembershipStore::create(DB::Conn(&db), &alpha.id, &admin_model.id, "admin")
            .await
            .expect("add admin to alpha");

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

        let current_token = state
            .jwt_service
            .create_token(&user.id, &user.email, false, Some(&alpha.slug), None)
            .expect("create initial org token");
        let claims = state
            .jwt_service
            .validate_token(&current_token)
            .expect("validate initial org token");
        let mut auth_user = AuthUser {
            claims,
            user,
            permissions: vec![],
            ip_address: "127.0.0.1".to_string(),
            user_agent: "org-switch-test".to_string(),
            current_session_id: None,
        };
        let original_auth_time = Utc::now().naive_utc() - chrono::Duration::minutes(30);
        let original_session = SessionStore::create_with_created_at(
            DB::Conn(&db),
            &auth_user.user.id,
            &JwtService::hash_token(&current_token),
            (Utc::now() + chrono::Duration::hours(1)).naive_utc(),
            None,
            None,
            Some(&alpha.slug),
            None,
            None,
            Some("org-switch-test"),
            Some("127.0.0.1"),
            original_auth_time,
        )
        .await
        .expect("create original session");
        auth_user.current_session_id = Some(original_session.id.clone());

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
                user_agent: "org-core-isolation-test".to_string(),
                current_session_id: None,
            }
        };

        let member_auth = auth_user_for(&member_model);
        let custom_role_auth = auth_user_for(&custom_role_model);
        let admin_auth = auth_user_for(&admin_model);
        let outsider_auth = auth_user_for(&outsider_model);

        OrgSwitchFixture {
            state,
            auth_user,
            alpha_slug: alpha.slug,
            beta_id: beta.id,
            beta_slug: beta.slug,
            gamma_slug: gamma.slug,
            member_auth,
            custom_role_auth,
            admin_auth,
            outsider_auth,
        }
    }

    #[tokio::test]
    async fn select_organization_switches_multi_org_member_and_persists_session_scope() {
        let fixture = setup_org_switch_fixture().await;
        let Json(response) = select_organization(
            State(fixture.state.clone()),
            fixture.auth_user.clone(),
            Path(fixture.beta_slug.clone()),
        )
        .await
        .expect("switch organization");

        assert_eq!(response.organization.slug, fixture.beta_slug);
        assert_eq!(response.membership.org_id, fixture.beta_id);

        let claims = fixture
            .state
            .jwt_service
            .validate_token(&response.access_token)
            .expect("validate selected org token");
        assert_eq!(claims.org.as_deref(), Some(fixture.beta_slug.as_str()));
        assert_eq!(claims.service, None);
        assert_eq!(claims.aud.as_deref(), Some("org:beta"));

        let session = SessionStore::find_by_token_hash(
            DB::Conn(&fixture.state.db),
            &JwtService::hash_token(&response.access_token),
        )
        .await
        .expect("query selected org session")
        .expect("selected org session exists");
        assert_eq!(
            session.org_slug.as_deref(),
            Some(fixture.beta_slug.as_str())
        );
        assert_eq!(session.service_id, None);
        let original = SessionStore::find_by_id(
            DB::Conn(&fixture.state.db),
            fixture
                .auth_user
                .current_session_id
                .as_deref()
                .expect("original session id"),
        )
        .await
        .expect("load original session")
        .expect("original session exists");
        assert_eq!(
            session.created_at, original.created_at,
            "organization switching must preserve the original authentication time"
        );
    }

    #[tokio::test]
    async fn select_organization_rejects_inactive_target_org() {
        let fixture = setup_org_switch_fixture().await;
        OrganizationStore::update_status(
            DB::Conn(&fixture.state.db),
            &fixture.beta_id,
            "suspended",
        )
        .await
        .expect("suspend beta org");

        let error = select_organization(
            State(fixture.state.clone()),
            fixture.auth_user.clone(),
            Path(fixture.beta_slug.clone()),
        )
        .await
        .expect_err("inactive org switch should fail");

        assert!(matches!(
            error,
            AppError::Forbidden(ref message) if message.contains("Organization is not active")
        ));
    }

    #[tokio::test]
    async fn select_organization_rejects_non_member_target_org() {
        let fixture = setup_org_switch_fixture().await;
        let error = select_organization(
            State(fixture.state.clone()),
            fixture.auth_user.clone(),
            Path(fixture.gamma_slug.clone()),
        )
        .await
        .expect_err("non-member org switch should fail");

        assert!(matches!(
            error,
            AppError::Forbidden(ref message) if message.contains("not a member")
        ));
    }

    #[tokio::test]
    async fn tenant_capability_does_not_trust_stale_platform_owner_snapshot() {
        let fixture = setup_org_switch_fixture().await;
        let gamma =
            OrganizationStore::find_by_slug(DB::Conn(&fixture.state.db), &fixture.gamma_slug)
                .await
                .expect("lookup gamma")
                .expect("gamma exists");
        let mut stale_user = fixture.auth_user.user.clone();
        stale_user.is_platform_owner = true;

        let mut stale_auth_user = fixture.auth_user.clone();
        stale_auth_user.user = stale_user;

        assert!(matches!(
            require_capability(
                &fixture.state,
                &gamma.id,
                &stale_auth_user,
                CAP_RISK_POLICIES_MANAGE,
                "denied",
            )
            .await,
            Err(AppError::Forbidden(_))
        ));
    }

    #[tokio::test]
    async fn organization_reads_require_live_membership() {
        let f = setup_org_switch_fixture().await;
        let alpha = OrganizationStore::find_by_slug(DB::Conn(&f.state.db), &f.alpha_slug)
            .await
            .expect("load alpha")
            .expect("alpha exists");

        // Owner, member, custom role, and admin can read their organization.
        for auth in [
            f.auth_user.clone(),
            f.member_auth.clone(),
            f.custom_role_auth.clone(),
            f.admin_auth.clone(),
        ] {
            let Json(response) =
                get_organization(State(f.state.clone()), auth, Path(f.alpha_slug.clone()))
                    .await
                    .expect("member of alpha may read");
            assert_eq!(response.organization.id, alpha.id);
        }

        // A non-member and a member of another organization cannot read alpha
        // or gamma through a caller-selected slug.
        for (auth, target) in [
            (f.outsider_auth.clone(), f.alpha_slug.clone()),
            (f.auth_user.clone(), f.gamma_slug.clone()),
        ] {
            match get_organization(State(f.state.clone()), auth, Path(target)).await {
                Err(AppError::Forbidden(_)) => {}
                other => panic!("expected forbidden organization read, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn organization_updates_require_capability_and_preserve_denied_state() {
        let f = setup_org_switch_fixture().await;
        let alpha = OrganizationStore::find_by_slug(DB::Conn(&f.state.db), &f.alpha_slug)
            .await
            .expect("load alpha")
            .expect("alpha exists");
        let gamma = OrganizationStore::find_by_slug(DB::Conn(&f.state.db), &f.gamma_slug)
            .await
            .expect("load gamma")
            .expect("gamma exists");

        // A built-in member cannot change settings, and the denied update must
        // leave the stored organization unchanged.
        match update_organization(
            State(f.state.clone()),
            f.member_auth.clone(),
            Path(f.alpha_slug.clone()),
            Json(UpdateOrganizationRequest {
                name: Some("Member Rename".to_string()),
            }),
        )
        .await
        {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected member update refusal, got {other:?}"),
        }
        let unchanged = OrganizationStore::find_by_slug(DB::Conn(&f.state.db), &f.alpha_slug)
            .await
            .expect("reload alpha")
            .expect("alpha remains");
        assert_eq!(unchanged.name, alpha.name);

        // A custom role holding only org.settings.manage can update settings.
        let Json(updated) = update_organization(
            State(f.state.clone()),
            f.custom_role_auth.clone(),
            Path(f.alpha_slug.clone()),
            Json(UpdateOrganizationRequest {
                name: Some("Alpha Custom Rename".to_string()),
            }),
        )
        .await
        .expect("custom settings role may update");
        assert_eq!(updated.organization.name, "Alpha Custom Rename");

        // Admin is a built-in all-capability role.
        let Json(updated) = update_organization(
            State(f.state.clone()),
            f.admin_auth.clone(),
            Path(f.alpha_slug.clone()),
            Json(UpdateOrganizationRequest {
                name: Some("Alpha Admin Rename".to_string()),
            }),
        )
        .await
        .expect("admin may update");
        assert_eq!(updated.organization.name, "Alpha Admin Rename");

        // Cross-organization updates are denied without changing the target.
        match update_organization(
            State(f.state.clone()),
            f.auth_user.clone(),
            Path(f.gamma_slug.clone()),
            Json(UpdateOrganizationRequest {
                name: Some("Cross Tenant Rename".to_string()),
            }),
        )
        .await
        {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected cross-organization update refusal, got {other:?}"),
        }
        let gamma_unchanged = OrganizationStore::find_by_slug(DB::Conn(&f.state.db), &f.gamma_slug)
            .await
            .expect("reload gamma")
            .expect("gamma remains");
        assert_eq!(gamma_unchanged.name, gamma.name);
    }

    #[tokio::test]
    async fn organization_delete_requires_live_owner_and_preserves_denied_state() {
        let f = setup_org_switch_fixture().await;
        let gamma = OrganizationStore::find_by_slug(DB::Conn(&f.state.db), &f.gamma_slug)
            .await
            .expect("load gamma")
            .expect("gamma exists");

        // Only the owner may delete. Every denied actor leaves alpha intact.
        for auth in [
            f.member_auth.clone(),
            f.custom_role_auth.clone(),
            f.admin_auth.clone(),
            f.outsider_auth.clone(),
        ] {
            match delete_organization(State(f.state.clone()), auth, Path(f.alpha_slug.clone()))
                .await
            {
                Err(AppError::Forbidden(_)) => {}
                other => panic!("expected delete refusal, got {other:?}"),
            }
            assert!(
                OrganizationStore::find_by_slug(DB::Conn(&f.state.db), &f.alpha_slug)
                    .await
                    .expect("reload alpha after denied delete")
                    .is_some(),
                "denied delete must preserve alpha"
            );
        }

        // An owner of another organization cannot delete gamma.
        match delete_organization(
            State(f.state.clone()),
            f.auth_user.clone(),
            Path(f.gamma_slug.clone()),
        )
        .await
        {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected cross-organization delete refusal, got {other:?}"),
        }
        assert!(
            OrganizationStore::find_by_slug(DB::Conn(&f.state.db), &f.gamma_slug)
                .await
                .expect("reload gamma after denied delete")
                .is_some(),
            "cross-organization delete must preserve gamma"
        );
        assert_eq!(
            OrganizationStore::find_by_slug(DB::Conn(&f.state.db), &f.gamma_slug)
                .await
                .expect("reload gamma")
                .expect("gamma remains")
                .name,
            gamma.name
        );

        // The live owner can delete a disposable organization. This proves the
        // positive path without disturbing the fixture organizations used by
        // the other assertions.
        let (delta, _) = OrganizationStore::create_with_owner(
            DB::Conn(&f.state.db),
            "delta",
            "Delta",
            &f.auth_user.user.id,
            Some("tier_enterprise"),
        )
        .await
        .expect("create disposable organization");
        OrganizationStore::update_status(DB::Conn(&f.state.db), &delta.id, "active")
            .await
            .expect("activate disposable organization");
        let _ = delete_organization(
            State(f.state.clone()),
            f.auth_user.clone(),
            Path(delta.slug.clone()),
        )
        .await
        .expect("owner may delete");
        assert!(
            OrganizationStore::find_by_slug(DB::Conn(&f.state.db), &delta.slug)
                .await
                .expect("reload deleted organization")
                .is_none(),
            "owner delete must remove the organization"
        );
    }

    #[tokio::test]
    async fn organization_listing_is_derived_from_memberships() {
        let f = setup_org_switch_fixture().await;
        let alpha = OrganizationStore::find_by_slug(DB::Conn(&f.state.db), &f.alpha_slug)
            .await
            .expect("load alpha")
            .expect("alpha exists");
        let gamma = OrganizationStore::find_by_slug(DB::Conn(&f.state.db), &f.gamma_slug)
            .await
            .expect("load gamma")
            .expect("gamma exists");

        let Json(outsider_orgs) = list_user_organizations(
            State(f.state.clone()),
            f.outsider_auth.clone(),
            Query(ListOrganizationsQuery {
                page: None,
                limit: None,
                status: None,
            }),
        )
        .await
        .expect("list outsider organizations");
        assert!(outsider_orgs.is_empty());

        let Json(member_orgs) = list_user_organizations(
            State(f.state.clone()),
            f.member_auth.clone(),
            Query(ListOrganizationsQuery {
                page: None,
                limit: None,
                status: None,
            }),
        )
        .await
        .expect("list member organizations");
        assert_eq!(member_orgs.len(), 1);
        assert_eq!(member_orgs[0].organization.id, alpha.id);

        let Json(owner_orgs) = list_user_organizations(
            State(f.state.clone()),
            f.auth_user.clone(),
            Query(ListOrganizationsQuery {
                page: None,
                limit: None,
                status: None,
            }),
        )
        .await
        .expect("list owner organizations");
        let owner_org_ids: Vec<&str> = owner_orgs
            .iter()
            .map(|org| org.organization.id.as_str())
            .collect();
        assert!(owner_org_ids.contains(&alpha.id.as_str()));
        assert!(!owner_org_ids.contains(&gamma.id.as_str()));
    }
}

// Risk Settings Request/Response Types
#[derive(Debug, Serialize)]
pub struct GetRiskSettingsResponse {
    pub enforcement_mode: String,
    pub low_threshold: i32,
    pub medium_threshold: i32,
    pub new_device_score: i32,
    pub impossible_travel_score: i32,
    pub velocity_threshold: i32,
    pub velocity_score: i32,
}

#[derive(Debug, Deserialize)]
pub struct UpdateRiskSettingsRequest {
    pub enforcement_mode: Option<String>,
    pub low_threshold: Option<i32>,
    pub medium_threshold: Option<i32>,
    pub new_device_score: Option<i32>,
    pub impossible_travel_score: Option<i32>,
    pub velocity_threshold: Option<i32>,
    pub velocity_score: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct UpdateRiskSettingsResponse {
    pub message: String,
    pub settings: GetRiskSettingsResponse,
}

/// GET /api/organizations/:org_slug/risk-settings - Get organization risk settings
pub async fn get_risk_settings(
    State(state): State<AppState>,
    Extension(_auth_user): Extension<AuthUser>,
    Path(org_slug): Path<String>,
) -> Result<Json<GetRiskSettingsResponse>> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
    let org = crate::store::organizations::ensure_organization_active(&state.db, &org.id).await?;

    require_any_capability(
        &state,
        &org.id,
        &_auth_user,
        &[CAP_RISK_EVENTS_VIEW, CAP_RISK_POLICIES_MANAGE],
        "Insufficient permissions to view risk settings",
    )
    .await?;

    let risk_rules = RiskRulesStore::find_by_org(DB::Conn(&state.db), &org.id)
        .await?
        .ok_or_else(|| AppError::NotFound("Risk settings not found".to_string()))?;

    Ok(Json(GetRiskSettingsResponse {
        enforcement_mode: risk_rules.enforcement_mode,
        low_threshold: risk_rules.low_threshold,
        medium_threshold: risk_rules.medium_threshold,
        new_device_score: risk_rules.new_device_score,
        impossible_travel_score: risk_rules.impossible_travel_score,
        velocity_threshold: risk_rules.velocity_threshold,
        velocity_score: risk_rules.velocity_score,
    }))
}

/// PUT /api/organizations/:org_slug/risk-settings - Update organization risk settings
pub async fn update_risk_settings(
    State(state): State<AppState>,
    Extension(_auth_user): Extension<AuthUser>,
    Path(org_slug): Path<String>,
    Json(req): Json<UpdateRiskSettingsRequest>,
) -> Result<Json<UpdateRiskSettingsResponse>> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
    let org = crate::store::organizations::ensure_organization_active(&state.db, &org.id).await?;

    require_capability(
        &state,
        &org.id,
        &_auth_user,
        CAP_RISK_POLICIES_MANAGE,
        "Insufficient permissions to manage risk settings",
    )
    .await?;

    // Validate enforcement mode if provided
    if let Some(ref mode) = req.enforcement_mode {
        match mode.as_str() {
            "log_only" | "monitor" | "challenge" | "block" => (),
            _ => {
                return Err(AppError::BadRequest(
                    "Invalid enforcement mode. Must be one of: log_only, monitor, challenge, block"
                        .to_string(),
                ));
            }
        }
    }

    // Validate thresholds if provided
    if let Some(low) = req.low_threshold {
        if !(0..=100).contains(&low) {
            return Err(AppError::BadRequest(
                "Low threshold must be between 0 and 100".to_string(),
            ));
        }
    }

    if let Some(medium) = req.medium_threshold {
        if !(0..=100).contains(&medium) {
            return Err(AppError::BadRequest(
                "Medium threshold must be between 0 and 100".to_string(),
            ));
        }
    }

    if let (Some(low), Some(medium)) = (req.low_threshold, req.medium_threshold) {
        if low >= medium {
            return Err(AppError::BadRequest(
                "Low threshold must be less than medium threshold".to_string(),
            ));
        }
    }

    // Validate scores if provided
    if let Some(score) = req.new_device_score {
        if !(0..=100).contains(&score) {
            return Err(AppError::BadRequest(
                "New device score must be between 0 and 100".to_string(),
            ));
        }
    }

    if let Some(score) = req.impossible_travel_score {
        if !(0..=100).contains(&score) {
            return Err(AppError::BadRequest(
                "Impossible travel score must be between 0 and 100".to_string(),
            ));
        }
    }

    if let Some(score) = req.velocity_score {
        if !(0..=100).contains(&score) {
            return Err(AppError::BadRequest(
                "Velocity score must be between 0 and 100".to_string(),
            ));
        }
    }

    // Update risk rules
    let enforcement_mode = req.enforcement_mode.clone();
    let updated_rules = RiskRulesStore::update(
        DB::Conn(&state.db),
        &org.id,
        enforcement_mode.clone(),
        req.low_threshold,
        req.medium_threshold,
        req.new_device_score,
        req.impossible_travel_score,
        req.velocity_threshold,
        req.velocity_score,
    )
    .await?;

    // Log the change
    tracing::info!(
        org_id = %org.id,
        org_slug = %org_slug,
        user_id = %_auth_user.user.id,
        enforcement_mode = ?enforcement_mode,
        "Organization risk settings updated"
    );

    Ok(Json(UpdateRiskSettingsResponse {
        message: "Risk settings updated successfully".to_string(),
        settings: GetRiskSettingsResponse {
            enforcement_mode: updated_rules.enforcement_mode,
            low_threshold: updated_rules.low_threshold,
            medium_threshold: updated_rules.medium_threshold,
            new_device_score: updated_rules.new_device_score,
            impossible_travel_score: updated_rules.impossible_travel_score,
            velocity_threshold: updated_rules.velocity_threshold,
            velocity_score: updated_rules.velocity_score,
        },
    }))
}

/// POST /api/organizations/:org_slug/risk-settings/reset - Reset risk settings to defaults
pub async fn reset_risk_settings(
    State(state): State<AppState>,
    Extension(_auth_user): Extension<AuthUser>,
    Path(org_slug): Path<String>,
) -> Result<Json<UpdateRiskSettingsResponse>> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
    let org = crate::store::organizations::ensure_organization_active(&state.db, &org.id).await?;

    require_capability(
        &state,
        &org.id,
        &_auth_user,
        CAP_RISK_POLICIES_MANAGE,
        "Insufficient permissions to manage risk settings",
    )
    .await?;

    // Reset to defaults
    let reset_rules = RiskRulesStore::update(
        DB::Conn(&state.db),
        &org.id,
        Some("log_only".to_string()),
        Some(30),
        Some(70),
        Some(20),
        Some(50),
        Some(10),
        Some(30),
    )
    .await?;

    // Log the reset
    tracing::info!(
        org_id = %org.id,
        org_slug = %org_slug,
        user_id = %_auth_user.user.id,
        "Organization risk settings reset to defaults"
    );

    Ok(Json(UpdateRiskSettingsResponse {
        message: "Risk settings reset to default values".to_string(),
        settings: GetRiskSettingsResponse {
            enforcement_mode: reset_rules.enforcement_mode,
            low_threshold: reset_rules.low_threshold,
            medium_threshold: reset_rules.medium_threshold,
            new_device_score: reset_rules.new_device_score,
            impossible_travel_score: reset_rules.impossible_travel_score,
            velocity_threshold: reset_rules.velocity_threshold,
            velocity_score: reset_rules.velocity_score,
        },
    }))
}
