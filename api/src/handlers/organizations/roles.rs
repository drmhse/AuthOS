use crate::constants::VALID_ORG_ROLES;
use crate::db::transaction::with_retrying_transaction;
use crate::db::DB;
use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use crate::services::audit_builder::OrgAuditBuilder;
use crate::services::permission_service::{PermissionService, CAP_ORG_ROLES_MANAGE};
use crate::state::AppState;
use crate::store::{organization_roles::OrganizationRoleStore, organizations::OrganizationStore};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct RoleResponse {
    pub id: String,
    pub org_id: String,
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

impl From<crate::entities::organization_roles::Model> for RoleResponse {
    fn from(model: crate::entities::organization_roles::Model) -> Self {
        let permissions = model
            .permissions
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(std::string::ToString::to_string))
                    .collect()
            })
            .unwrap_or_default();

        Self {
            id: model.id,
            org_id: model.org_id,
            slug: model.slug,
            name: model.name,
            description: model.description,
            permissions,
            created_at: model.created_at,
            updated_at: model.updated_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateRoleRequest {
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateRoleRequest {
    pub name: Option<String>,
    /// Absent leaves the description alone, `null` clears it, a string sets it.
    #[serde(default, deserialize_with = "double_option")]
    pub description: Option<Option<String>>,
    pub permissions: Option<Vec<String>>,
}

/// Distinguishes an absent JSON field from an explicit `null`, which a plain
/// `Option<T>` collapses into the same value.
fn double_option<'de, D, T>(deserializer: D) -> std::result::Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Deserialize::deserialize(deserializer).map(Some)
}

/// GET /api/organizations/:org_slug/roles
/// List all custom roles for an organization
pub async fn list_roles(
    State(state): State<AppState>,
    Path(org_slug): Path<String>,
    auth_user: axum::Extension<AuthUser>,
) -> Result<Json<Vec<RoleResponse>>> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Deliberately strict: listing needs the manage capability, not just
    // membership, so the role layout is not readable by every member.
    if !PermissionService::check(
        DB::Conn(&state.db),
        &org.id,
        &auth_user.user.id,
        CAP_ORG_ROLES_MANAGE,
    )
    .await?
    {
        return Err(AppError::Forbidden(
            "Insufficient permissions to view roles".to_string(),
        ));
    }

    let custom_roles = OrganizationRoleStore::find_by_org(DB::Conn(&state.db), &org.id).await?;

    let mut all_roles = Vec::new();

    // Add default roles
    let now = chrono::Utc::now().naive_utc();

    all_roles.push(RoleResponse {
        id: "role_owner".to_string(),
        org_id: org.id.clone(),
        slug: "owner".to_string(),
        name: "Owner".to_string(),
        description: Some("Full access to all resources and settings".to_string()),
        permissions: vec!["*".to_string()], // improved permission representation
        created_at: now,
        updated_at: now,
    });

    all_roles.push(RoleResponse {
        id: "role_admin".to_string(),
        org_id: org.id.clone(),
        slug: "admin".to_string(),
        name: "Admin".to_string(),
        description: Some("Manage members, services, and billing".to_string()),
        permissions: vec!["org:manage".to_string()],
        created_at: now,
        updated_at: now,
    });

    all_roles.push(RoleResponse {
        id: "role_member".to_string(),
        org_id: org.id.clone(),
        slug: "member".to_string(),
        name: "Member".to_string(),
        description: Some("View access to assigned services".to_string()),
        permissions: vec!["org:view".to_string()],
        created_at: now,
        updated_at: now,
    });

    // Append custom roles
    for role in custom_roles {
        all_roles.push(RoleResponse::from(role));
    }

    Ok(Json(all_roles))
}

/// POST /api/organizations/:org_slug/roles
/// Create a new custom role
pub async fn create_role(
    State(state): State<AppState>,
    Path(org_slug): Path<String>,
    auth_user: axum::Extension<AuthUser>,
    Json(req): Json<CreateRoleRequest>,
) -> Result<Json<RoleResponse>> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    if !PermissionService::check(
        DB::Conn(&state.db),
        &org.id,
        &auth_user.user.id,
        CAP_ORG_ROLES_MANAGE,
    )
    .await?
    {
        return Err(AppError::Forbidden(
            "Insufficient permissions to create roles".to_string(),
        ));
    }

    if VALID_ORG_ROLES.contains(&req.slug.to_lowercase().as_str()) {
        return Err(AppError::BadRequest(
            "Custom role slug cannot use a built-in organization role".to_string(),
        ));
    }

    // Validate slug uniqueness
    if OrganizationRoleStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, &req.slug)
        .await?
        .is_some()
    {
        return Err(AppError::BadRequest(
            "Role with this slug already exists".to_string(),
        ));
    }

    // Determine permissions JSON
    let permissions_json = serde_json::to_value(req.permissions).unwrap();

    let role_id = Uuid::new_v4().to_string();
    let org_id = org.id.clone();
    let actor_id = auth_user.user.id.clone();
    let slug = req.slug.clone();
    let name = req.name.clone();
    let description = req.description.clone();
    let audit_actor = state.audit_actor.clone();
    let role = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "create_organization_role",
        |db| {
            let role_id = role_id.clone();
            let org_id = org_id.clone();
            let actor_id = actor_id.clone();
            let slug = slug.clone();
            let name = name.clone();
            let description = description.clone();
            let permissions_json = permissions_json.clone();
            let audit_actor = audit_actor.clone();
            Box::pin(async move {
                let role = OrganizationRoleStore::create(
                    db.clone(),
                    &role_id,
                    &org_id,
                    &slug,
                    &name,
                    description,
                    permissions_json,
                )
                .await?;
                let event =
                    OrgAuditBuilder::new(&org_id, Some(&actor_id), "organization_role.created")
                        .target("organization_role", &role_id)
                        .success(true)
                        .details_json(Some(json!({ "slug": slug, "name": name })))
                        .build();
                audit_actor.log_org_with_db(db, event).await?;
                Ok(role)
            })
        },
    )
    .await?;

    Ok(Json(RoleResponse::from(role)))
}

/// GET /api/organizations/:org_slug/roles/:role_id
/// Get details of a specific role
pub async fn get_role(
    State(state): State<AppState>,
    Path((org_slug, role_id)): Path<(String, String)>,
    auth_user: axum::Extension<AuthUser>,
) -> Result<Json<RoleResponse>> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Allow viewing if you can manage roles
    if !PermissionService::check(
        DB::Conn(&state.db),
        &org.id,
        &auth_user.user.id,
        CAP_ORG_ROLES_MANAGE,
    )
    .await?
    {
        return Err(AppError::Forbidden(
            "Insufficient permissions to view role details".to_string(),
        ));
    }

    let role = OrganizationRoleStore::find_by_id(DB::Conn(&state.db), &role_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Role not found".to_string()))?;

    if role.org_id != org.id {
        return Err(AppError::NotFound(
            "Role not found in this organization".to_string(),
        ));
    }

    Ok(Json(RoleResponse::from(role)))
}

/// PUT /api/organizations/:org_slug/roles/:role_id
/// Update a role
pub async fn update_role(
    State(state): State<AppState>,
    Path((org_slug, role_id)): Path<(String, String)>,
    auth_user: axum::Extension<AuthUser>,
    Json(req): Json<UpdateRoleRequest>,
) -> Result<Json<RoleResponse>> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    if !PermissionService::check(
        DB::Conn(&state.db),
        &org.id,
        &auth_user.user.id,
        CAP_ORG_ROLES_MANAGE,
    )
    .await?
    {
        return Err(AppError::Forbidden(
            "Insufficient permissions to update roles".to_string(),
        ));
    }

    let role = OrganizationRoleStore::find_by_id(DB::Conn(&state.db), &role_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Role not found".to_string()))?;

    if role.org_id != org.id {
        return Err(AppError::NotFound(
            "Role not found in this organization".to_string(),
        ));
    }

    let permissions_json = req.permissions.map(|p| serde_json::to_value(p).unwrap());

    let description_update = req.description.clone();

    let org_id = org.id.clone();
    let actor_id = auth_user.user.id.clone();
    let role_slug = role.slug.clone();
    let audit_actor = state.audit_actor.clone();
    let updated_role = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "update_organization_role",
        |db| {
            let role_id = role_id.clone();
            let org_id = org_id.clone();
            let actor_id = actor_id.clone();
            let role_slug = role_slug.clone();
            let name = req.name.clone();
            let description = description_update.clone();
            let permissions = permissions_json.clone();
            let audit_actor = audit_actor.clone();
            Box::pin(async move {
                let updated = OrganizationRoleStore::update(
                    db.clone(),
                    &role_id,
                    name,
                    description,
                    permissions,
                )
                .await?;
                let event =
                    OrgAuditBuilder::new(&org_id, Some(&actor_id), "organization_role.updated")
                        .target("organization_role", &role_id)
                        .success(true)
                        .details_json(Some(json!({ "slug": role_slug })))
                        .build();
                audit_actor.log_org_with_db(db, event).await?;
                Ok(updated)
            })
        },
    )
    .await?;

    Ok(Json(RoleResponse::from(updated_role)))
}

/// DELETE /api/organizations/:org_slug/roles/:role_id
/// Delete a role
pub async fn delete_role(
    State(state): State<AppState>,
    Path((org_slug, role_id)): Path<(String, String)>,
    auth_user: axum::Extension<AuthUser>,
) -> Result<StatusCode> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    if !PermissionService::check(
        DB::Conn(&state.db),
        &org.id,
        &auth_user.user.id,
        CAP_ORG_ROLES_MANAGE,
    )
    .await?
    {
        return Err(AppError::Forbidden(
            "Insufficient permissions to delete roles".to_string(),
        ));
    }

    let role = OrganizationRoleStore::find_by_id(DB::Conn(&state.db), &role_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Role not found".to_string()))?;

    if role.org_id != org.id {
        return Err(AppError::NotFound(
            "Role not found in this organization".to_string(),
        ));
    }

    let org_id = org.id.clone();
    let actor_id = auth_user.user.id.clone();
    let role_slug = role.slug.clone();
    let audit_actor = state.audit_actor.clone();
    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "delete_organization_role",
        |db| {
            let role_id = role_id.clone();
            let org_id = org_id.clone();
            let actor_id = actor_id.clone();
            let role_slug = role_slug.clone();
            let audit_actor = audit_actor.clone();
            Box::pin(async move {
                OrganizationRoleStore::delete(db.clone(), &role_id).await?;
                let event =
                    OrgAuditBuilder::new(&org_id, Some(&actor_id), "organization_role.deleted")
                        .target("organization_role", &role_id)
                        .success(true)
                        .details_json(Some(json!({ "slug": role_slug })))
                        .build();
                audit_actor.log_org_with_db(db, event).await?;
                Ok(())
            })
        },
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::crypto::jwt::Claims;
    use crate::crypto::sso::OAuthClient;

    use crate::audit::actor::AuditHandle;
    use crate::services::{
        events::EventDispatcher,
        metrics::MfaMetricsService,
        permission_service::{CAP_AUDIT_LOGS_VIEW, CAP_SERVICES_MANAGE},
        risk_engine::RiskEngine,
    };
    use crate::store::{
        memberships::MembershipStore,
        users::{UserCreationOptions, UserStore},
    };
    use axum::Extension;

    use migration::{Migrator, MigratorTrait};
    use moka::future::Cache;
    use sea_orm::Database;
    use std::sync::Arc;

    use crate::test_support::test_config;

    use crate::test_support::test_jwt_service;

    async fn setup_state_owner_org() -> (AppState, AuthUser, String, String) {
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
        let (org, _) =
            OrganizationStore::create_with_owner(DB::Conn(&db), "acme", "Acme", &owner.id, None)
                .await
                .expect("create org");
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
                jti: Uuid::new_v4().to_string(),
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
            user_agent: "roles-test".to_string(),
            current_session_id: None,
        };

        (state, auth_user, org.id, org.slug)
    }

    async fn create_custom_role(
        state: &AppState,
        auth_user: &AuthUser,
        org_slug: &str,
        slug: &str,
    ) -> Result<RoleResponse> {
        let Json(role) = create_role(
            State(state.clone()),
            Path(org_slug.to_string()),
            Extension(auth_user.clone()),
            Json(CreateRoleRequest {
                slug: slug.to_string(),
                name: "Service Manager".to_string(),
                description: Some("Can manage services".to_string()),
                permissions: vec![CAP_SERVICES_MANAGE.to_string()],
            }),
        )
        .await?;
        Ok(role)
    }

    #[tokio::test]
    async fn create_role_rejects_builtin_and_duplicate_slugs() {
        let (state, auth_user, _org_id, org_slug) = setup_state_owner_org().await;

        let builtin_error = create_custom_role(&state, &auth_user, &org_slug, "admin")
            .await
            .expect_err("built-in role slug should fail");
        assert!(matches!(
            builtin_error,
            AppError::BadRequest(ref message)
                if message.contains("built-in organization role")
        ));

        let created = create_custom_role(&state, &auth_user, &org_slug, "service-manager")
            .await
            .expect("create custom role");
        assert_eq!(created.slug, "service-manager");

        let duplicate_error = create_custom_role(&state, &auth_user, &org_slug, "service-manager")
            .await
            .expect_err("duplicate role slug should fail");
        assert!(matches!(
            duplicate_error,
            AppError::BadRequest(ref message) if message.contains("already exists")
        ));
    }

    #[tokio::test]
    async fn custom_role_grants_configured_capability() {
        let (state, auth_user, org_id, org_slug) = setup_state_owner_org().await;
        create_custom_role(&state, &auth_user, &org_slug, "service-manager")
            .await
            .expect("create custom role");
        let member = UserStore::find_or_create_with_options(
            DB::Conn(&state.db),
            "member@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create member")
        .0;
        MembershipStore::create(DB::Conn(&state.db), &org_id, &member.id, "service-manager")
            .await
            .expect("create custom-role membership");

        assert!(PermissionService::check(
            DB::Conn(&state.db),
            &org_id,
            &member.id,
            CAP_SERVICES_MANAGE,
        )
        .await
        .expect("check custom-role capability"));
        assert!(!PermissionService::check(
            DB::Conn(&state.db),
            &org_id,
            &member.id,
            CAP_ORG_ROLES_MANAGE,
        )
        .await
        .expect("check ungranted capability"));
        assert!(PermissionService::check_any(
            DB::Conn(&state.db),
            &org_id,
            &member.id,
            &[CAP_ORG_ROLES_MANAGE, CAP_SERVICES_MANAGE],
        )
        .await
        .expect("check any custom-role capability"));
        assert!(!PermissionService::check_any(
            DB::Conn(&state.db),
            &org_id,
            &member.id,
            &[CAP_ORG_ROLES_MANAGE, CAP_AUDIT_LOGS_VIEW],
        )
        .await
        .expect("check any ungranted capability"));
    }

    #[test]
    fn role_description_update_separates_absent_from_null() {
        let absent: UpdateRoleRequest =
            serde_json::from_str(r#"{"name":"Support"}"#).expect("absent description");
        assert_eq!(
            absent.description, None,
            "absent must not change the column"
        );

        let cleared: UpdateRoleRequest =
            serde_json::from_str(r#"{"description":null}"#).expect("null description");
        assert_eq!(
            cleared.description,
            Some(None),
            "explicit null must clear the column"
        );

        let set: UpdateRoleRequest =
            serde_json::from_str(r#"{"description":"Handles tickets"}"#).expect("set description");
        assert_eq!(set.description, Some(Some("Handles tickets".to_string())));
    }
}
