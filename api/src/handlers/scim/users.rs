use crate::db::transaction::with_retrying_transaction;
use crate::db::DB;
use crate::entities::permissions::{RelationTuple, SUBJECT_TYPE_USER};
use crate::entities::users;
use crate::error::{AppError, Result};
use crate::middleware::ScimAuth;
use crate::services::job_queue::JobQueueService;
use crate::services::scim_filter::{ScimFilterParser, ScimOperator};
use crate::state::AppState;
use crate::store::{
    memberships::MembershipStore,
    organizations::OrganizationStore,
    permissions::PermissionsStore,
    provider_token_requests::ProviderTokenRequestStore,
    services::ServiceStore,
    sessions::SessionStore,
    users::{UserEmailFilter, UserEmailFilterOp, UserStore},
};
use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::Deserialize;
use uuid::Uuid;

use super::schemas::*;

#[derive(Debug, Deserialize)]
pub struct ScimListParams {
    #[serde(rename = "startIndex")]
    start_index: Option<u64>,
    count: Option<u64>,
    filter: Option<String>,
}

/// Convert our User entity to SCIM User format
fn user_to_scim(user: users::Model, base_url: &str) -> ScimUser {
    let location = format!("{}/scim/v2/Users/{}", base_url, user.id);

    ScimUser {
        schemas: vec![SCIM_USER_SCHEMA.to_string()],
        id: user.id.clone(),
        external_id: None,
        meta: ScimMeta {
            resource_type: "User".to_string(),
            created: DateTime::<Utc>::from_naive_utc_and_offset(user.created_at, Utc).to_rfc3339(),
            last_modified: DateTime::<Utc>::from_naive_utc_and_offset(
                user.updated_at.unwrap_or(user.created_at),
                Utc,
            )
            .to_rfc3339(),
            location: Some(location),
        },
        user_name: user.email.clone(),
        name: Some(ScimName {
            formatted: Some(user.email.clone()),
            family_name: None,
            given_name: None,
            middle_name: None,
            honorific_prefix: None,
            honorific_suffix: None,
        }),
        display_name: Some(user.email.clone()),
        emails: Some(vec![ScimEmail {
            value: user.email.clone(),
            email_type: Some("work".to_string()),
            primary: Some(true),
        }]),
        active: user.deleted_at.is_none(), // Active if not soft-deleted
    }
}

fn ensure_scim_can_deprovision_membership(
    membership: &crate::entities::memberships::Model,
) -> Result<()> {
    if matches!(membership.role.as_str(), "owner" | "admin") {
        return Err(AppError::Forbidden(
            "SCIM cannot deprovision organization owners or admins".to_string(),
        ));
    }

    Ok(())
}

/// SCIM is a tenant provisioning interface, not a platform-identity or
/// privileged-tenant identity recovery interface. It may not rewrite a
/// platform owner or the email address of an organization owner/admin.
fn ensure_scim_can_modify_identity(
    user: &users::Model,
    membership: &crate::entities::memberships::Model,
    changing_email: bool,
) -> Result<()> {
    if user.is_platform_owner {
        return Err(AppError::Forbidden(
            "SCIM cannot modify a platform owner account".to_string(),
        ));
    }
    if changing_email && matches!(membership.role.as_str(), "owner" | "admin") {
        return Err(AppError::Forbidden(
            "SCIM cannot change the email address of an organization owner or admin".to_string(),
        ));
    }
    Ok(())
}

async fn deprovision_scim_user_in_transaction(
    db: DB<'_>,
    audit_actor: &crate::audit::actor::AuditHandle,
    org_id: &str,
    user_id: &str,
    deactivate_owned_user: Option<&str>,
    remove_membership: bool,
) -> Result<Option<crate::entities::users::Model>> {
    use crate::entities::prelude::{DeviceCodes, Identities, SamlStates, ServiceProviderGrants};
    use crate::entities::{
        device_codes, identities, oauth_states, saml_states, service_provider_grants,
    };
    use sea_orm::Condition;

    let organization = OrganizationStore::find_by_id(db.clone(), org_id)
        .await?
        .filter(|org| org.status == "active")
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
    let membership = MembershipStore::find_by_org_and_user(db.clone(), org_id, user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let target_user = users::Entity::find_by_id(user_id)
        .one(&db)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    if target_user.is_platform_owner {
        return Err(AppError::Forbidden(
            "SCIM cannot deprovision a platform owner account".to_string(),
        ));
    }
    ensure_scim_can_deprovision_membership(&membership)?;

    let updated_user = if let Some(email) = deactivate_owned_user {
        Some(
            UserStore::update_scim_owned_member(db.clone(), org_id, user_id, email, false)
                .await?
                .ok_or_else(|| {
                    AppError::Forbidden(
                        "SCIM user authorization changed before deprovisioning".to_string(),
                    )
                })?,
        )
    } else {
        None
    };

    let services = ServiceStore::list_by_org(db.clone(), org_id).await?;
    let service_ids = services
        .into_iter()
        .map(|service| service.id)
        .collect::<Vec<_>>();

    Identities::delete_many()
        .filter(identities::Column::UserId.eq(user_id))
        .filter(identities::Column::IssuingOrgId.eq(org_id))
        .exec(&db)
        .await?;
    if !service_ids.is_empty() {
        ServiceProviderGrants::delete_many()
            .filter(service_provider_grants::Column::UserId.eq(user_id))
            .filter(service_provider_grants::Column::ServiceId.is_in(service_ids.clone()))
            .exec(&db)
            .await?;
        for service_id in &service_ids {
            ProviderTokenRequestStore::cancel_pending_for_user_service(
                db.clone(),
                user_id,
                service_id,
            )
            .await?;
        }
        SamlStates::delete_many()
            .filter(saml_states::Column::UserId.eq(user_id))
            .filter(saml_states::Column::ServiceId.is_in(service_ids.clone()))
            .exec(&db)
            .await?;
    }
    oauth_states::Entity::delete_many()
        .filter(oauth_states::Column::UserIdForLinking.eq(user_id))
        .filter(
            Condition::any()
                .add(oauth_states::Column::OrgSlug.eq(&organization.slug))
                .add(oauth_states::Column::ServiceId.is_in(service_ids.clone())),
        )
        .exec(&db)
        .await?;
    DeviceCodes::delete_many()
        .filter(device_codes::Column::UserId.eq(user_id))
        .filter(device_codes::Column::OrgSlug.eq(&organization.slug))
        .exec(&db)
        .await?;
    SessionStore::delete_user_org_scoped_sessions(
        db.clone(),
        user_id,
        &organization.slug,
        &service_ids,
    )
    .await?;
    if deactivate_owned_user.is_some() {
        // A SCIM deactivation marks the user row inactive globally. Revoke
        // every session, including sessions for other tenant memberships.
        SessionStore::delete_all_for_user(db.clone(), user_id).await?;
    }

    if remove_membership {
        MembershipStore::delete(db.clone(), &membership.id).await?;
        PermissionsStore::revoke(
            db.clone(),
            "organization",
            org_id,
            &membership.role,
            SUBJECT_TYPE_USER,
            user_id,
            None,
        )
        .await?;
    }

    use crate::services::audit_builder::OrgAuditBuilder;
    let action = if remove_membership {
        "scim.user.deleted"
    } else {
        "scim.user.deactivated"
    };
    let event = OrgAuditBuilder::new(org_id, None, action)
        .target("user", user_id)
        .success(true)
        .details_json(Some(serde_json::json!({
            "scim": true,
            "sessions_revoked": true,
            "service_access_revoked": true,
        })))
        .build();
    audit_actor.log_org_with_db(db, event).await?;

    Ok(updated_user)
}

async fn scoped_email_conflict(
    state: &AppState,
    org_id: &str,
    email: &str,
    current_user_id: Option<&str>,
) -> Result<bool> {
    let existing =
        UserStore::find_by_email_with_context(DB::Conn(&state.db), email, Some(org_id)).await?;

    Ok(existing.is_some_and(|user| current_user_id.is_none_or(|id| user.id != id)))
}

fn parse_user_email_filters(filter: &str) -> std::result::Result<Vec<UserEmailFilter>, ScimError> {
    let expressions = ScimFilterParser::parse(filter)
        .map_err(|error| ScimError::invalid_filter(error.to_string()))?;
    if expressions.is_empty() {
        return Err(ScimError::invalid_filter(
            "Filter expression cannot be empty".to_string(),
        ));
    }

    expressions
        .into_iter()
        .map(|expression| {
            if !matches!(expression.attribute_path.as_str(), "userName" | "email") {
                return Err(ScimError::invalid_filter(format!(
                    "Unsupported user filter attribute: {}",
                    expression.attribute_path
                )));
            }

            let op = match expression.operator {
                ScimOperator::Equals => UserEmailFilterOp::Equals,
                ScimOperator::Contains => UserEmailFilterOp::Contains,
                ScimOperator::StartsWith => UserEmailFilterOp::StartsWith,
                ScimOperator::EndsWith => UserEmailFilterOp::EndsWith,
                ScimOperator::NotEquals => UserEmailFilterOp::NotEquals,
                operator => {
                    return Err(ScimError::invalid_filter(format!(
                        "Operator {} is not supported for {}",
                        operator.as_str(),
                        expression.attribute_path
                    )))
                }
            };
            let value = expression.comparison_value.ok_or_else(|| {
                ScimError::invalid_filter(format!(
                    "{} requires a comparison value",
                    expression.attribute_path
                ))
            })?;
            if value.is_empty() {
                return Err(ScimError::invalid_filter(format!(
                    "{} comparison value cannot be empty",
                    expression.attribute_path
                )));
            }

            Ok(UserEmailFilter { op, value })
        })
        .collect()
}

enum UserPatchAction {
    Email(String),
    Active(bool),
}

fn parse_user_patch_operations(
    operations: Vec<ScimPatchOp>,
) -> std::result::Result<Vec<UserPatchAction>, ScimError> {
    if operations.is_empty() {
        return Err(ScimError::invalid_value(
            "PATCH request must contain at least one operation".to_string(),
        ));
    }

    operations
        .into_iter()
        .map(|operation| {
            if !operation.op.eq_ignore_ascii_case("replace") {
                return Err(ScimError::invalid_value(format!(
                    "Unsupported user PATCH operation: {}",
                    operation.op
                )));
            }

            let path = operation.path.ok_or_else(|| {
                ScimError::invalid_value("User PATCH operation requires a path".to_string())
            })?;
            let value = operation.value.ok_or_else(|| {
                ScimError::invalid_value(format!("User PATCH path {path} requires a value"))
            })?;

            match path.as_str() {
                "userName" => value
                    .as_str()
                    .filter(|email| !email.is_empty())
                    .map(|email| UserPatchAction::Email(email.to_lowercase()))
                    .ok_or_else(|| {
                        ScimError::invalid_value(
                            "userName PATCH value must be a non-empty string".to_string(),
                        )
                    }),
                "emails" => {
                    let email = value
                        .as_array()
                        .and_then(|emails| emails.first())
                        .and_then(|email| email.get("value"))
                        .and_then(|email| email.as_str())
                        .filter(|email| !email.is_empty())
                        .ok_or_else(|| {
                            ScimError::invalid_value(
                                "emails PATCH value must contain a non-empty first value"
                                    .to_string(),
                            )
                        })?;
                    Ok(UserPatchAction::Email(email.to_lowercase()))
                }
                "active" => value.as_bool().map(UserPatchAction::Active).ok_or_else(|| {
                    ScimError::invalid_value("active PATCH value must be a boolean".to_string())
                }),
                _ => Err(ScimError::invalid_value(format!(
                    "Unsupported user PATCH path: {path}"
                ))),
            }
        })
        .collect()
}

/// List Users - GET /scim/v2/Users
pub async fn list_users(
    State(state): State<AppState>,
    Extension(scim_auth): Extension<ScimAuth>,
    Query(params): Query<ScimListParams>,
) -> Result<Response> {
    let start_index = params.start_index.unwrap_or(1).max(1);
    let count = params.count.unwrap_or(100).min(1000); // Max 1000 per page

    let offset = start_index - 1;
    let mut email_filters = Vec::new();

    // Handle filters (SCIM 2.0 filtering)
    if let Some(filter) = params.filter {
        match parse_user_email_filters(&filter) {
            Ok(filters) => email_filters = filters,
            Err(error) => {
                return Ok((StatusCode::BAD_REQUEST, Json(error)).into_response());
            }
        }
    }

    let users = UserStore::list_scim_org_members(
        DB::Conn(&state.db),
        &scim_auth.org_id,
        &email_filters,
        count,
        offset,
    )
    .await?;
    let total_results =
        UserStore::count_scim_org_members(DB::Conn(&state.db), &scim_auth.org_id, &email_filters)
            .await?;

    let base_url = &state.base_url;
    let scim_users: Vec<ScimUser> = users
        .into_iter()
        .map(|u| user_to_scim(u, base_url))
        .collect();

    Ok(Json(ScimListResponse::new(
        scim_users,
        total_results,
        start_index,
    ))
    .into_response())
}

/// Get User by ID - GET /scim/v2/Users/:id
pub async fn get_user(
    State(state): State<AppState>,
    Extension(scim_auth): Extension<ScimAuth>,
    Path(user_id): Path<String>,
) -> Result<Response> {
    let user = UserStore::find_by_id(DB::Conn(&state.db), &user_id).await?;

    // If user doesn't exist, return SCIM not found error
    let user = match user {
        Some(u) => u,
        None => {
            let error = ScimError::not_found("User not found".to_string());
            return Ok((StatusCode::NOT_FOUND, Json(error)).into_response());
        }
    };

    // Verify user is a member of the SCIM token's organization
    let membership =
        MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &scim_auth.org_id, &user.id)
            .await?;

    if membership.is_none() {
        // User exists but not in this organization - return 404 for security (don't leak user existence)
        let error = ScimError::not_found("User not found".to_string());
        return Ok((StatusCode::NOT_FOUND, Json(error)).into_response());
    }

    let base_url = &state.base_url;
    Ok(Json(user_to_scim(user, base_url)).into_response())
}

/// Create User - POST /scim/v2/Users
pub async fn create_user(
    State(state): State<AppState>,
    Extension(scim_auth): Extension<ScimAuth>,
    ScimJson(req): ScimJson<ScimUserRequest>,
) -> Result<Response> {
    // Extract email from request
    let email = if let Some(emails) = &req.emails {
        emails
            .first()
            .map(|e| e.value.clone())
            .unwrap_or(req.user_name.clone())
    } else {
        req.user_name.clone()
    };

    // Check if user already exists in this SCIM token's organization.
    if scoped_email_conflict(&state, &scim_auth.org_id, &email, None).await? {
        let error = ScimError::uniqueness(format!("User with email {} already exists", email));
        return Ok((StatusCode::CONFLICT, Json(error)).into_response());
    }

    // Clone values needed in the closure for retrying transaction
    let email_clone = email.clone();
    let org_id_clone = scim_auth.org_id.clone();

    // Use retrying transaction for atomicity with automatic retry on contention
    let created_user = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "scim_create_user",
        |db| {
            let email = email_clone.clone();
            let org_id = org_id_clone.clone();

            Box::pin(async move {
                // Create user
                let user = users::ActiveModel {
                    id: Set(Uuid::new_v4().to_string()),
                    email: Set(email.to_lowercase()),
                    org_id: Set(Some(org_id.clone())),
                    password_hash: Set(None),
                    is_platform_owner: Set(false),
                    email_verified_at: Set(None),
                    created_at: Set(Utc::now().naive_utc()),
                    updated_at: Set(None),
                    deleted_at: Set(None),
                };

                let created_user = user.insert(&db).await?;

                // Create membership in organization with 'member' role
                MembershipStore::create(db.clone(), &org_id, &created_user.id, "member").await?;

                // Grant member permission in the permissions table
                PermissionsStore::grant(
                    db.clone(),
                    RelationTuple {
                        namespace: "organization".to_string(),
                        object_id: org_id.clone(),
                        relation: "member".to_string(),
                        subject_type: SUBJECT_TYPE_USER.to_string(),
                        subject_id: created_user.id.clone(),
                        subject_relation: None,
                    },
                )
                .await?;

                // Enqueue welcome email job using the proper email job type
                JobQueueService::enqueue_email(
                    db.clone(),
                    &created_user.email,
                    "Welcome!",
                    &format!("Welcome to the platform, {}!", created_user.email),
                    None,
                )
                .await?;

                Ok(created_user)
            })
        },
    )
    .await?;

    tracing::debug!(
        user_id = %created_user.id,
        org_id = %scim_auth.org_id,
        "SCIM user provisioned with membership and welcome email queued"
    );

    let base_url = &state.base_url;
    let scim_user = user_to_scim(created_user, base_url);

    Ok((StatusCode::CREATED, Json(scim_user)).into_response())
}

/// Update User (PUT) - PUT /scim/v2/Users/:id
pub async fn update_user(
    State(state): State<AppState>,
    Extension(scim_auth): Extension<ScimAuth>,
    Path(user_id): Path<String>,
    ScimJson(req): ScimJson<ScimUserRequest>,
) -> Result<Response> {
    if let Some(error) = scim_id_mismatch_error(&user_id, req.id.as_deref(), "User") {
        return Ok((StatusCode::BAD_REQUEST, Json(error)).into_response());
    }

    let Some(user) = UserStore::find_by_id(DB::Conn(&state.db), &user_id).await? else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ScimError::not_found("User not found".to_string())),
        )
            .into_response());
    };

    // Verify user is a member of the SCIM token's organization
    let membership =
        MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &scim_auth.org_id, &user.id)
            .await?;

    let Some(membership) = membership else {
        // User exists but not in this organization - return 404 for security
        let error = ScimError::not_found("User not found".to_string());
        return Ok((StatusCode::NOT_FOUND, Json(error)).into_response());
    };

    // Extract email from request
    let email = if let Some(emails) = &req.emails {
        emails
            .first()
            .map(|e| e.value.clone())
            .unwrap_or(req.user_name.clone())
    } else {
        req.user_name.clone()
    };

    let email = email.to_lowercase();
    if let Err(error) = ensure_scim_can_modify_identity(&user, &membership, user.email != email) {
        return Ok((
            StatusCode::FORBIDDEN,
            Json(ScimError::new(403, error.to_string(), None)),
        )
            .into_response());
    }
    if scoped_email_conflict(&state, &scim_auth.org_id, &email, Some(&user.id)).await? {
        let error = ScimError::uniqueness(format!("User with email {} already exists", email));
        return Ok((StatusCode::CONFLICT, Json(error)).into_response());
    }

    let current_active = user.deleted_at.is_none();
    let requested_active = req.active.unwrap_or(current_active);
    if !requested_active {
        ensure_scim_can_deprovision_membership(&membership)?;
    }

    if user.email == email && current_active == requested_active {
        let base_url = &state.base_url;
        return Ok(Json(user_to_scim(user, base_url)).into_response());
    }

    // Membership-only users are shared identities. A tenant may see them via
    // SCIM, but cannot rewrite or globally deactivate their user record.
    if user.org_id.as_deref() != Some(scim_auth.org_id.as_str()) {
        return Ok((
            StatusCode::FORBIDDEN,
            Json(ScimError::new(
                403,
                "SCIM cannot modify a shared user identity".to_string(),
                None,
            )),
        )
            .into_response());
    }

    let updated_user = if requested_active {
        let org_id = scim_auth.org_id.clone();
        let user_id = user.id.clone();
        let email = email.clone();
        with_retrying_transaction(
            &state.db,
            #[cfg(feature = "db_sqlite")]
            &state.db_writer,
            "scim_update_user",
            |db| {
                let org_id = org_id.clone();
                let user_id = user_id.clone();
                let email = email.clone();
                Box::pin(async move {
                    UserStore::update_scim_owned_member(db, &org_id, &user_id, &email, true).await
                })
            },
        )
        .await?
    } else {
        let org_id = scim_auth.org_id.clone();
        let user_id = user.id.clone();
        let email = email.clone();
        with_retrying_transaction(
            &state.db,
            #[cfg(feature = "db_sqlite")]
            &state.db_writer,
            "scim_deactivate_user",
            |db| {
                let org_id = org_id.clone();
                let user_id = user_id.clone();
                let email = email.clone();
                let audit_actor = state.audit_actor.clone();
                Box::pin(async move {
                    deprovision_scim_user_in_transaction(
                        db,
                        &audit_actor,
                        &org_id,
                        &user_id,
                        Some(&email),
                        false,
                    )
                    .await
                })
            },
        )
        .await?
    };
    let Some(updated_user) = updated_user else {
        return Ok((
            StatusCode::FORBIDDEN,
            Json(ScimError::new(
                403,
                "SCIM user authorization changed before the update".to_string(),
                None,
            )),
        )
            .into_response());
    };

    state.user_cache.invalidate(&user.id).await;
    if !requested_active {
        state.permission_cache.invalidate(&user.id).await;
    }

    // Note: The users table doesn't store name fields (givenName, familyName)
    // These are provided in SCIM requests but not persisted to the database
    // The user_to_scim function will return None for these fields
    let base_url = &state.base_url;
    Ok(Json(user_to_scim(updated_user, base_url)).into_response())
}

/// Patch User (PATCH) - PATCH /scim/v2/Users/:id
pub async fn patch_user(
    State(state): State<AppState>,
    Extension(scim_auth): Extension<ScimAuth>,
    Path(user_id): Path<String>,
    Json(req): Json<ScimPatchRequest>,
) -> Result<Response> {
    if let Some(error) = scim_patch_schema_error(&req.schemas) {
        return Ok((StatusCode::BAD_REQUEST, Json(error)).into_response());
    }

    let Some(user) = UserStore::find_by_id(DB::Conn(&state.db), &user_id).await? else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(ScimError::not_found("User not found".to_string())),
        )
            .into_response());
    };

    // Verify user is a member of the SCIM token's organization
    let membership =
        MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &scim_auth.org_id, &user.id)
            .await?;

    let membership = if let Some(membership) = membership {
        membership
    } else {
        // User exists but not in this organization - return 404 for security
        let error = ScimError::not_found("User not found".to_string());
        return Ok((StatusCode::NOT_FOUND, Json(error)).into_response());
    };

    let actions = match parse_user_patch_operations(req.operations) {
        Ok(actions) => actions,
        Err(error) => return Ok((StatusCode::BAD_REQUEST, Json(error)).into_response()),
    };
    let mut requested_email = user.email.clone();
    let mut requested_active = user.deleted_at.is_none();
    for action in actions {
        match action {
            UserPatchAction::Email(email) => requested_email = email,
            UserPatchAction::Active(active) => requested_active = active,
        }
    }

    if let Err(error) =
        ensure_scim_can_modify_identity(&user, &membership, user.email != requested_email)
    {
        return Ok((
            StatusCode::FORBIDDEN,
            Json(ScimError::new(403, error.to_string(), None)),
        )
            .into_response());
    }
    if scoped_email_conflict(&state, &scim_auth.org_id, &requested_email, Some(&user.id)).await? {
        let error = ScimError::uniqueness(format!(
            "User with email {} already exists",
            requested_email
        ));
        return Ok((StatusCode::CONFLICT, Json(error)).into_response());
    }
    if !requested_active {
        ensure_scim_can_deprovision_membership(&membership)?;
    }

    let current_active = user.deleted_at.is_none();
    if user.email == requested_email && current_active == requested_active {
        let base_url = &state.base_url;
        return Ok(Json(user_to_scim(user, base_url)).into_response());
    }

    if user.org_id.as_deref() != Some(scim_auth.org_id.as_str()) {
        return Ok((
            StatusCode::FORBIDDEN,
            Json(ScimError::new(
                403,
                "SCIM cannot modify a shared user identity".to_string(),
                None,
            )),
        )
            .into_response());
    }

    let updated_user = if requested_active {
        let org_id = scim_auth.org_id.clone();
        let user_id = user.id.clone();
        let requested_email = requested_email.clone();
        with_retrying_transaction(
            &state.db,
            #[cfg(feature = "db_sqlite")]
            &state.db_writer,
            "scim_patch_update_user",
            |db| {
                let org_id = org_id.clone();
                let user_id = user_id.clone();
                let requested_email = requested_email.clone();
                Box::pin(async move {
                    UserStore::update_scim_owned_member(
                        db,
                        &org_id,
                        &user_id,
                        &requested_email,
                        true,
                    )
                    .await
                })
            },
        )
        .await?
    } else {
        let org_id = scim_auth.org_id.clone();
        let user_id = user.id.clone();
        let requested_email = requested_email.clone();
        with_retrying_transaction(
            &state.db,
            #[cfg(feature = "db_sqlite")]
            &state.db_writer,
            "scim_patch_deactivate_user",
            |db| {
                let org_id = org_id.clone();
                let user_id = user_id.clone();
                let requested_email = requested_email.clone();
                let audit_actor = state.audit_actor.clone();
                Box::pin(async move {
                    deprovision_scim_user_in_transaction(
                        db,
                        &audit_actor,
                        &org_id,
                        &user_id,
                        Some(&requested_email),
                        false,
                    )
                    .await
                })
            },
        )
        .await?
    };
    let Some(updated_user) = updated_user else {
        return Ok((
            StatusCode::FORBIDDEN,
            Json(ScimError::new(
                403,
                "SCIM user authorization changed before the update".to_string(),
                None,
            )),
        )
            .into_response());
    };

    state.user_cache.invalidate(&user.id).await;
    if !requested_active {
        state.permission_cache.invalidate(&user.id).await;
    }

    let base_url = &state.base_url;
    Ok(Json(user_to_scim(updated_user, base_url)).into_response())
}

/// Delete User - DELETE /scim/v2/Users/:id
pub async fn delete_user(
    State(state): State<AppState>,
    Extension(scim_auth): Extension<ScimAuth>,
    Path(user_id): Path<String>,
) -> Result<Response> {
    let user = UserStore::find_by_id(DB::Conn(&state.db), &user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Verify user is a member of the SCIM token's organization
    let membership =
        MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &scim_auth.org_id, &user.id)
            .await?;

    let membership = if let Some(membership) = membership {
        membership
    } else {
        // User exists but not in this organization - return 404 for security
        let error = ScimError::not_found("User not found".to_string());
        return Ok((StatusCode::NOT_FOUND, Json(error)).into_response());
    };

    if user.is_platform_owner {
        return Err(AppError::Forbidden(
            "SCIM cannot deprovision a platform owner account".to_string(),
        ));
    }
    ensure_scim_can_deprovision_membership(&membership)?;

    let org_id = scim_auth.org_id.clone();
    let user_id = user.id.clone();
    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "scim_delete_user_access",
        |db| {
            let org_id = org_id.clone();
            let user_id = user_id.clone();
            let audit_actor = state.audit_actor.clone();
            Box::pin(async move {
                deprovision_scim_user_in_transaction(
                    db,
                    &audit_actor,
                    &org_id,
                    &user_id,
                    None,
                    true,
                )
                .await?;
                Ok(())
            })
        },
    )
    .await?;
    state.user_cache.invalidate(&user.id).await;
    state.permission_cache.invalidate(&user.id).await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod deprovision_tests {
    use super::*;
    use crate::audit::actor::AuditHandle;
    use crate::entities::audit_outbox;
    use crate::store::{identities::IdentityStore, sessions::SessionStore};
    use migration::{Migrator, MigratorTrait};
    use sea_orm::{Database, PaginatorTrait, TransactionTrait};

    struct Fixture {
        db: sea_orm::DatabaseConnection,
        user: crate::entities::users::Model,
        org_a: crate::entities::organizations::Model,
        org_b: crate::entities::organizations::Model,
        service_a: crate::entities::services::Model,
        service_b: crate::entities::services::Model,
        identity_a: crate::entities::identities::Model,
        identity_b: crate::entities::identities::Model,
    }

    async fn fixture() -> Fixture {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        let owner = UserStore::create(DB::Conn(&db), "scim-fixture-owner@example.test", None, true)
            .await
            .unwrap();
        let user = UserStore::create(DB::Conn(&db), "shared-scim-user@example.test", None, false)
            .await
            .unwrap();
        let org_a = OrganizationStore::create(
            DB::Conn(&db),
            "scim-deprovision-a",
            "SCIM A",
            &owner.id,
            None,
        )
        .await
        .unwrap();
        let org_b = OrganizationStore::create(
            DB::Conn(&db),
            "scim-deprovision-b",
            "SCIM B",
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
        MembershipStore::create(DB::Conn(&db), &org_a.id, &user.id, "member")
            .await
            .unwrap();
        MembershipStore::create(DB::Conn(&db), &org_b.id, &user.id, "member")
            .await
            .unwrap();
        let service_a = ServiceStore::create(
            DB::Conn(&db),
            &org_a.id,
            "portal-a",
            "Portal A",
            "web",
            "scim-deprovision-client-a",
        )
        .await
        .unwrap();
        let service_b = ServiceStore::create(
            DB::Conn(&db),
            &org_b.id,
            "portal-b",
            "Portal B",
            "web",
            "scim-deprovision-client-b",
        )
        .await
        .unwrap();
        let identity_a = IdentityStore::create(
            DB::Conn(&db),
            &user.id,
            "google",
            "scim-provider-a",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&org_a.id),
            Some(&service_a.id),
        )
        .await
        .unwrap();
        let identity_b = IdentityStore::create(
            DB::Conn(&db),
            &user.id,
            "google",
            "scim-provider-b",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&org_b.id),
            Some(&service_b.id),
        )
        .await
        .unwrap();
        let expiry = (Utc::now() + chrono::Duration::hours(1)).naive_utc();
        for (hash, org_slug, service_id) in [
            (
                "scim-session-a",
                Some(org_a.slug.as_str()),
                Some(service_a.id.as_str()),
            ),
            (
                "scim-session-b",
                Some(org_b.slug.as_str()),
                Some(service_b.id.as_str()),
            ),
            ("scim-session-platform", None, None),
        ] {
            SessionStore::create(
                DB::Conn(&db),
                &user.id,
                hash,
                expiry,
                None,
                None,
                org_slug,
                service_id,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        }
        Fixture {
            db,
            user,
            org_a,
            org_b,
            service_a,
            service_b,
            identity_a,
            identity_b,
        }
    }

    #[tokio::test]
    async fn shared_user_deprovision_removes_only_selected_organization_authority() {
        let fixture = fixture().await;
        let audit = AuditHandle::without_worker(fixture.db.clone());
        let transaction = fixture.db.begin().await.unwrap();
        deprovision_scim_user_in_transaction(
            DB::Tx(&transaction),
            &audit,
            &fixture.org_a.id,
            &fixture.user.id,
            None,
            true,
        )
        .await
        .unwrap();
        transaction.commit().await.unwrap();

        assert!(MembershipStore::find_by_org_and_user(
            DB::Conn(&fixture.db),
            &fixture.org_a.id,
            &fixture.user.id
        )
        .await
        .unwrap()
        .is_none());
        assert!(MembershipStore::find_by_org_and_user(
            DB::Conn(&fixture.db),
            &fixture.org_b.id,
            &fixture.user.id
        )
        .await
        .unwrap()
        .is_some());
        assert!(
            IdentityStore::find_by_id(DB::Conn(&fixture.db), &fixture.identity_a.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            IdentityStore::find_by_id(DB::Conn(&fixture.db), &fixture.identity_b.id)
                .await
                .unwrap()
                .is_some()
        );
        let session_hashes = SessionStore::list_by_user(DB::Conn(&fixture.db), &fixture.user.id)
            .await
            .unwrap()
            .into_iter()
            .map(|session| session.token_hash)
            .collect::<std::collections::HashSet<_>>();
        assert!(!session_hashes.contains("scim-session-a"));
        assert!(session_hashes.contains("scim-session-b"));
        assert!(session_hashes.contains("scim-session-platform"));
        assert_eq!(
            audit_outbox::Entity::find()
                .count(&fixture.db)
                .await
                .unwrap(),
            1
        );
        assert_eq!(fixture.service_a.org_id, fixture.org_a.id);
        assert_eq!(fixture.service_b.org_id, fixture.org_b.id);
    }

    #[tokio::test]
    async fn deprovision_audit_failure_rolls_back_all_authority_changes() {
        use sea_orm::ConnectionTrait;

        let fixture = fixture().await;
        let audit = AuditHandle::without_worker(fixture.db.clone());
        fixture
            .db
            .execute_unprepared("DROP TABLE audit_outbox")
            .await
            .unwrap();
        let transaction = fixture.db.begin().await.unwrap();
        assert!(deprovision_scim_user_in_transaction(
            DB::Tx(&transaction),
            &audit,
            &fixture.org_a.id,
            &fixture.user.id,
            None,
            true,
        )
        .await
        .is_err());
        transaction.rollback().await.unwrap();

        assert!(MembershipStore::find_by_org_and_user(
            DB::Conn(&fixture.db),
            &fixture.org_a.id,
            &fixture.user.id
        )
        .await
        .unwrap()
        .is_some());
        assert!(
            IdentityStore::find_by_id(DB::Conn(&fixture.db), &fixture.identity_a.id)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            SessionStore::list_by_user(DB::Conn(&fixture.db), &fixture.user.id)
                .await
                .unwrap()
                .iter()
                .any(|session| session.token_hash == "scim-session-a")
        );
    }
}
