use crate::constants::{DEFAULT_MAX_USERS, DEFAULT_TIER_NAME, VALID_ORG_ROLES};
use crate::db::transaction::with_retrying_transaction;
use crate::db::DB;
use crate::entities::{memberships, users};
use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use crate::services::audit_builder::OrgAuditBuilder;
use crate::services::permission_service::{
    PermissionService, CAP_ORG_MEMBERS_MANAGE, CAP_ORG_ROLES_MANAGE,
};
use crate::state::AppState;
use crate::store::{
    memberships::MembershipStore, organization_roles::OrganizationRoleStore,
    organization_tiers::OrganizationTierStore, organizations::OrganizationStore,
    permissions::PermissionsStore, services::ServiceStore, users::UserStore,
};
use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Serialize)]
pub struct OrganizationMember {
    pub user: users::Model,
    pub membership: memberships::Model,
}

#[derive(Debug, Serialize)]
pub struct MemberListResponse {
    pub members: Vec<OrganizationMember>,
    pub total: i64,
    pub limit: LimitInfo,
}

#[derive(Debug, Serialize)]
pub struct LimitInfo {
    pub current: i64,
    pub max: i64,
    pub source: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateMemberRoleRequest {
    pub role: String,
}

#[derive(Debug, Deserialize)]
pub struct ListMembersQuery {
    pub page: Option<i64>,
    pub limit: Option<i64>,
    pub role: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TransferOwnershipRequest {
    pub new_owner_email: String,
}

#[derive(Debug, Serialize)]
pub struct MemberServiceAccess {
    pub service_id: String,
    pub service_slug: String,
    pub service_name: String,
    pub access: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateMemberServiceAccessRequest {
    pub grants: Vec<MemberServiceAccessGrant>,
}

#[derive(Debug, Deserialize)]
pub struct MemberServiceAccessGrant {
    pub service_slug: String,
    pub access: Option<String>,
}

async fn transfer_ownership_with_db(
    db: DB<'_>,
    audit_actor: &crate::audit::actor::AuditHandle,
    org_id: &str,
    previous_owner_id: &str,
    previous_owner_email: &str,
    new_owner_email: &str,
) -> Result<(users::Model, memberships::Model)> {
    let organization = OrganizationStore::find_by_id(db.clone(), org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
    let previous_owner_membership =
        MembershipStore::find_by_org_and_user(db.clone(), org_id, previous_owner_id)
            .await?
            .filter(|membership| membership.role == "owner")
            .ok_or_else(|| AppError::Forbidden("Organization owner access required".to_string()))?;
    if organization.owner_user_id != previous_owner_id {
        return Err(AppError::Forbidden(
            "Organization owner access required".to_string(),
        ));
    }

    let (target_membership, new_owner) =
        MembershipStore::find_unique_member_with_user_by_org_and_email(
            db.clone(),
            org_id,
            new_owner_email,
        )
        .await?
        .ok_or_else(|| {
            AppError::NotFound("User is not a member of this organization".to_string())
        })?;
    if new_owner.id == previous_owner_id {
        return Err(AppError::BadRequest(
            "New owner must be a different organization member".to_string(),
        ));
    }

    OrganizationStore::transfer_ownership_if_current(
        db.clone(),
        org_id,
        previous_owner_id,
        &new_owner.id,
    )
    .await?;
    let updated_membership =
        MembershipStore::update_role(db.clone(), &target_membership.id, "owner").await?;
    MembershipStore::update_role(db.clone(), &previous_owner_membership.id, "admin").await?;

    let event = OrgAuditBuilder::new(org_id, Some(previous_owner_id), "org.ownership_transferred")
        .target("organization", org_id)
        .success(true)
        .details_json(Some(json!({
            "previous_owner_email": previous_owner_email,
            "new_owner_email": new_owner.email,
            "ownership_transferred": true
        })))
        .build();
    audit_actor.log_org_with_db(db, event).await?;

    Ok((new_owner, updated_membership))
}

async fn validate_org_role(db: DB<'_>, org_id: &str, role: &str) -> Result<()> {
    if role == "owner" || VALID_ORG_ROLES.contains(&role) {
        return Ok(());
    }

    if OrganizationRoleStore::find_by_org_and_slug(db, org_id, role)
        .await?
        .is_some()
    {
        return Ok(());
    }

    Err(AppError::BadRequest(
        "Invalid role. Choose a system role or custom organization role.".to_string(),
    ))
}

async fn can_manage_members(state: &AppState, org_id: &str, user_id: &str) -> Result<bool> {
    PermissionService::check(DB::Conn(&state.db), org_id, user_id, CAP_ORG_MEMBERS_MANAGE).await
}

async fn can_manage_roles(state: &AppState, org_id: &str, user_id: &str) -> Result<bool> {
    PermissionService::check(DB::Conn(&state.db), org_id, user_id, CAP_ORG_ROLES_MANAGE).await
}

/// List organization members
pub async fn list_members(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
    Query(query): Query<ListMembersQuery>,
) -> Result<Json<MemberListResponse>> {
    let user = &auth_user.user;

    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is member
    crate::middleware::check_org_membership(&state.db, &user.id, &organization.id, &[]).await?;

    let (_page, limit, offset) =
        crate::utils::pagination::signed_page(query.page, query.limit, 50, 100);

    // Get members with user details using store layer
    let members = MembershipStore::list_with_users(
        DB::Conn(&state.db),
        &organization.id,
        query.role.as_deref(),
        limit,
        offset,
    )
    .await?;

    let member_responses: Vec<OrganizationMember> = members
        .into_iter()
        .map(|row| {
            let user = users::Model {
                id: row.user_id.clone(),
                email: row.user_email,
                org_id: None,
                is_platform_owner: row.user_is_platform_owner,
                password_hash: None,
                email_verified_at: None,
                created_at: row.user_created_at,
                updated_at: None,
                deleted_at: None,
            };
            let membership = memberships::Model {
                id: row.membership_id,
                org_id: organization.id.clone(),
                user_id: row.user_id,
                role: row.membership_role,
                created_at: row.membership_created_at,
            };
            OrganizationMember { user, membership }
        })
        .collect();

    // Get total member count
    let total_members =
        MembershipStore::count_by_org(DB::Conn(&state.db), &organization.id, None).await? as i64;

    // Get organization limits
    let (max_users, limit_source) = if let Some(custom_limit) = organization.max_users {
        (custom_limit as i64, "custom".to_string())
    } else {
        // Get tier default
        let tier =
            OrganizationTierStore::find_by_org_id(DB::Conn(&state.db), &organization.id).await?;

        if let Some(tier) = tier {
            (tier.default_max_users as i64, tier.name)
        } else {
            (DEFAULT_MAX_USERS, DEFAULT_TIER_NAME.to_string())
        }
    };

    Ok(Json(MemberListResponse {
        members: member_responses,
        total: total_members,
        limit: LimitInfo {
            current: total_members,
            max: max_users,
            source: limit_source,
        },
    }))
}

/// Update member role (owner only)
pub async fn update_member_role(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, user_id)): Path<(String, String)>,
    Json(req): Json<UpdateMemberRoleRequest>,
) -> Result<Json<OrganizationMember>> {
    let user = &auth_user.user;

    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    if !can_manage_roles(&state, &organization.id, &user.id).await? {
        return Err(AppError::Forbidden(
            "Insufficient permissions to change member roles".to_string(),
        ));
    }

    validate_org_role(DB::Conn(&state.db), &organization.id, &req.role).await?;

    // Cannot change own role (prevent self-demotion from owner)
    if user_id == user.id {
        return Err(AppError::BadRequest(
            "Cannot change your own role".to_string(),
        ));
    }

    // Get target membership
    let membership =
        MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &organization.id, &user_id)
            .await?
            .ok_or_else(|| {
                AppError::NotFound("User is not a member of this organization".to_string())
            })?;

    // Only a current owner may grant admin/owner authority or change an
    // existing owner/admin. A custom role with role-management capability may
    // manage member and custom roles, but cannot mint an all-capability admin.
    if matches!(membership.role.as_str(), "owner" | "admin")
        || matches!(req.role.as_str(), "owner" | "admin")
    {
        crate::middleware::check_org_owner(&state.db, &user.id, &organization.id).await?;
    }

    // Fetch immutable audit context before the transaction. No success event is
    // written until every role/permission/ownership mutation has succeeded.
    let target_user = UserStore::find_by_id(DB::Conn(&state.db), &user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let org_id = organization.id.clone();
    let membership_id = membership.id.clone();
    let old_role = membership.role.clone();
    let new_role = req.role.clone();
    let actor_id = user.id.clone();
    let actor_email = user.email.clone();
    let target_email = target_user.email.clone();
    let target_user_id = user_id.clone();
    let audit_actor = state.audit_actor.clone();

    let updated_membership = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "update_member_role",
        |db| {
            let org_id = org_id.clone();
            let membership_id = membership_id.clone();
            let old_role = old_role.clone();
            let new_role = new_role.clone();
            let actor_id = actor_id.clone();
            let actor_email = actor_email.clone();
            let target_email = target_email.clone();
            let target_user_id = target_user_id.clone();
            let audit_actor = audit_actor.clone();
            Box::pin(async move {
                use crate::entities::permissions::{RelationTuple, SUBJECT_TYPE_USER};

                let updated_membership =
                    MembershipStore::update_role(db.clone(), &membership_id, &new_role).await?;
                PermissionsStore::revoke(
                    db.clone(),
                    "organization",
                    &org_id,
                    &old_role,
                    SUBJECT_TYPE_USER,
                    &target_user_id,
                    None,
                )
                .await?;

                let service_ids = ServiceStore::list_by_org(db.clone(), &org_id)
                    .await?
                    .into_iter()
                    .map(|service| service.id)
                    .collect::<Vec<_>>();
                PermissionsStore::revoke_direct_service_access_for_user(
                    db.clone(),
                    &service_ids,
                    &target_user_id,
                )
                .await?;
                PermissionsStore::grant(
                    db.clone(),
                    RelationTuple::user(
                        "organization".to_string(),
                        org_id.clone(),
                        new_role.clone(),
                        target_user_id.clone(),
                    ),
                )
                .await?;

                if new_role == "owner" {
                    OrganizationStore::transfer_ownership_if_current(
                        db.clone(),
                        &org_id,
                        &actor_id,
                        &target_user_id,
                    )
                    .await?;
                    let previous_owner =
                        MembershipStore::find_by_org_and_user(db.clone(), &org_id, &actor_id)
                            .await?
                            .ok_or_else(|| {
                                AppError::NotFound(
                                    "Previous owner membership not found".to_string(),
                                )
                            })?;
                    MembershipStore::update_role(db.clone(), &previous_owner.id, "admin").await?;
                }

                let role_event =
                    OrgAuditBuilder::new(&org_id, Some(&actor_id), "member.role_changed")
                        .target("user", &target_user_id)
                        .success(true)
                        .details_json(Some(json!({
                            "old_role": old_role,
                            "new_role": new_role,
                            "target_user_email": target_email.clone()
                        })))
                        .build();
                audit_actor.log_org_with_db(db.clone(), role_event).await?;

                if new_role == "owner" {
                    let ownership_event =
                        OrgAuditBuilder::new(&org_id, Some(&actor_id), "org.ownership_transferred")
                            .target("organization", &org_id)
                            .success(true)
                            .details_json(Some(json!({
                                "previous_owner_email": actor_email,
                                "new_owner_email": target_email,
                                "ownership_transferred": true
                            })))
                            .build();
                    audit_actor.log_org_with_db(db, ownership_event).await?;
                }

                Ok(updated_membership)
            })
        },
    )
    .await?;

    // Invalidate only after the domain mutation and durable audit rows commit.
    state.permission_cache.invalidate(&user_id).await;
    if req.role == "owner" {
        state.permission_cache.invalidate(&user.id).await;
    }

    Ok(Json(OrganizationMember {
        user: target_user,
        membership: updated_membership,
    }))
}

/// Remove member from organization (owner/admin only)
pub async fn remove_member(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, user_id)): Path<(String, String)>,
) -> Result<Json<()>> {
    let user = &auth_user.user;

    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    if !can_manage_members(&state, &organization.id, &user.id).await? {
        return Err(AppError::Forbidden(
            "Insufficient permissions to remove members".to_string(),
        ));
    }

    let caller_membership =
        MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &organization.id, &user.id)
            .await?
            .ok_or_else(|| AppError::Forbidden("Not a member of this organization".to_string()))?;

    // Cannot remove yourself
    if user_id == user.id {
        return Err(AppError::BadRequest(
            "Cannot remove yourself from the organization".to_string(),
        ));
    }

    let target_membership =
        MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &organization.id, &user_id)
            .await?
            .ok_or_else(|| {
                AppError::NotFound("User is not a member of this organization".to_string())
            })?;

    // Get target user for audit logging
    let target_user = UserStore::find_by_id(DB::Conn(&state.db), &user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Check permissions: owner can remove anyone, admin can only remove members, not owners/admins
    if caller_membership.role != "owner"
        && (target_membership.role == "owner" || target_membership.role == "admin")
    {
        return Err(AppError::Forbidden(
            "Only owners can remove other owners and admins".to_string(),
        ));
    }

    let org_id = organization.id.clone();
    let membership_id = target_membership.id.clone();
    let removed_role = target_membership.role.clone();
    let removed_by_role = caller_membership.role.clone();
    let removed_user_email = target_user.email.clone();
    let actor_id = user.id.clone();
    let target_user_id = user_id.clone();
    let audit_actor = state.audit_actor.clone();

    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "remove_member",
        |db| {
            let org_id = org_id.clone();
            let membership_id = membership_id.clone();
            let removed_role = removed_role.clone();
            let removed_by_role = removed_by_role.clone();
            let removed_user_email = removed_user_email.clone();
            let actor_id = actor_id.clone();
            let target_user_id = target_user_id.clone();
            let audit_actor = audit_actor.clone();
            Box::pin(async move {
                use crate::entities::permissions::SUBJECT_TYPE_USER;

                MembershipStore::delete(db.clone(), &membership_id).await?;
                PermissionsStore::revoke(
                    db.clone(),
                    "organization",
                    &org_id,
                    &removed_role,
                    SUBJECT_TYPE_USER,
                    &target_user_id,
                    None,
                )
                .await?;

                let event = OrgAuditBuilder::new(&org_id, Some(&actor_id), "member.removed")
                    .target("user", &target_user_id)
                    .success(true)
                    .details_json(Some(json!({
                        "removed_user_email": removed_user_email,
                        "removed_role": removed_role,
                        "removed_by_role": removed_by_role
                    })))
                    .build();
                audit_actor.log_org_with_db(db, event).await?;
                Ok(())
            })
        },
    )
    .await?;

    state.permission_cache.invalidate(&user_id).await;

    Ok(Json(()))
}

/// List a member's direct per-service access grants.
pub async fn list_member_service_access(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, user_id)): Path<(String, String)>,
) -> Result<Json<Vec<MemberServiceAccess>>> {
    let actor = &auth_user.user;

    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    if !can_manage_members(&state, &organization.id, &actor.id).await? {
        return Err(AppError::Forbidden(
            "Insufficient permissions to view service access".to_string(),
        ));
    }

    MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &organization.id, &user_id)
        .await?
        .ok_or_else(|| {
            AppError::NotFound("User is not a member of this organization".to_string())
        })?;

    let services = ServiceStore::list_by_org(DB::Conn(&state.db), &organization.id).await?;
    let service_ids = services
        .iter()
        .map(|service| service.id.clone())
        .collect::<Vec<_>>();
    let access_by_service = PermissionsStore::list_direct_service_access_for_user(
        DB::Conn(&state.db),
        &service_ids,
        &user_id,
    )
    .await?;

    let response = services
        .into_iter()
        .map(|service| MemberServiceAccess {
            access: access_by_service.get(&service.id).cloned(),
            service_id: service.id,
            service_slug: service.slug,
            service_name: service.name,
        })
        .collect::<Vec<_>>();

    Ok(Json(response))
}

/// Replace a member's direct per-service access grants.
pub async fn update_member_service_access(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, user_id)): Path<(String, String)>,
    Json(req): Json<UpdateMemberServiceAccessRequest>,
) -> Result<Json<Vec<MemberServiceAccess>>> {
    let actor = &auth_user.user;

    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    if !can_manage_members(&state, &organization.id, &actor.id).await? {
        return Err(AppError::Forbidden(
            "Insufficient permissions to update service access".to_string(),
        ));
    }

    MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &organization.id, &user_id)
        .await?
        .ok_or_else(|| {
            AppError::NotFound("User is not a member of this organization".to_string())
        })?;

    let mut requested_grants = BTreeMap::new();
    for grant in req.grants {
        if let Some(access) = grant.access.as_deref() {
            if access != "viewer" && access != "manager" {
                return Err(AppError::BadRequest(
                    "Service access must be viewer, manager, or null".to_string(),
                ));
            }
        }

        requested_grants.insert(grant.service_slug, grant.access);
    }

    let requested_slugs = requested_grants.keys().cloned().collect::<Vec<_>>();
    let services_by_slug = ServiceStore::find_by_org_and_slugs(
        DB::Conn(&state.db),
        &organization.id,
        &requested_slugs,
    )
    .await?
    .into_iter()
    .map(|service| (service.slug.clone(), service))
    .collect::<HashMap<_, _>>();

    let mut validated_grants = Vec::with_capacity(requested_grants.len());
    for (service_slug, access) in requested_grants {
        let service = services_by_slug
            .get(&service_slug)
            .ok_or_else(|| AppError::NotFound(format!("Service '{}' not found", service_slug)))?;
        validated_grants.push((service.id.clone(), access));
    }

    let org_id = organization.id.clone();
    let actor_id = actor.id.clone();
    let target_user_id = user_id.clone();
    let audit_actor = state.audit_actor.clone();
    let response = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "update_member_service_access",
        |db| {
            let grants = validated_grants.clone();
            let org_id = org_id.clone();
            let actor_id = actor_id.clone();
            let target_user_id = target_user_id.clone();
            let audit_actor = audit_actor.clone();
            Box::pin(async move {
                let service_ids = grants
                    .iter()
                    .map(|(service_id, _)| service_id.clone())
                    .collect::<Vec<_>>();
                PermissionsStore::revoke_direct_service_access_for_user(
                    db.clone(),
                    &service_ids,
                    &target_user_id,
                )
                .await?;

                let grant_tuples = grants
                    .into_iter()
                    .filter_map(|(service_id, access)| {
                        access.map(|access| {
                            crate::entities::permissions::RelationTuple::user(
                                "service",
                                service_id,
                                access,
                                target_user_id.clone(),
                            )
                        })
                    })
                    .collect::<Vec<_>>();
                PermissionsStore::grant_many(db.clone(), grant_tuples).await?;

                let services = ServiceStore::list_by_org(db.clone(), &org_id).await?;
                let all_service_ids = services
                    .iter()
                    .map(|service| service.id.clone())
                    .collect::<Vec<_>>();
                let access_by_service = PermissionsStore::list_direct_service_access_for_user(
                    db.clone(),
                    &all_service_ids,
                    &target_user_id,
                )
                .await?;
                let response = services
                    .into_iter()
                    .map(|service| MemberServiceAccess {
                        access: access_by_service.get(&service.id).cloned(),
                        service_id: service.id,
                        service_slug: service.slug,
                        service_name: service.name,
                    })
                    .collect::<Vec<_>>();

                let event =
                    OrgAuditBuilder::new(&org_id, Some(&actor_id), "member.service_access_updated")
                        .target("user", &target_user_id)
                        .success(true)
                        .details_json(Some(json!({ "target_user_id": target_user_id })))
                        .build();
                audit_actor.log_org_with_db(db, event).await?;

                Ok(response)
            })
        },
    )
    .await?;

    state.permission_cache.invalidate(&user_id).await;
    Ok(Json(response))
}

/// Transfer ownership to another member (owner only)
pub async fn transfer_ownership(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
    Json(req): Json<TransferOwnershipRequest>,
) -> Result<Json<OrganizationMember>> {
    let user = &auth_user.user;

    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    crate::middleware::check_org_owner(&state.db, &user.id, &organization.id).await?;

    let org_id = organization.id.clone();
    let prev_owner_id = user.id.clone();
    let previous_owner_email = user.email.clone();
    let new_owner_email = req.new_owner_email.clone();
    let audit_actor = state.audit_actor.clone();

    let (new_owner, updated_membership) = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "transfer_ownership",
        |db| {
            let org_id = org_id.clone();
            let prev_owner_id = prev_owner_id.clone();
            let previous_owner_email = previous_owner_email.clone();
            let new_owner_email = new_owner_email.clone();
            let audit_actor = audit_actor.clone();
            Box::pin(async move {
                transfer_ownership_with_db(
                    db,
                    &audit_actor,
                    &org_id,
                    &prev_owner_id,
                    &previous_owner_email,
                    &new_owner_email,
                )
                .await
            })
        },
    )
    .await?;

    // CRITICAL: Invalidate permission cache for both users (new owner and old owner)
    state.permission_cache.invalidate(&new_owner.id).await;
    state.permission_cache.invalidate(&user.id).await;

    Ok(Json(OrganizationMember {
        user: new_owner,
        membership: updated_membership,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::actor::AuditHandle;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::{Database, TransactionTrait};

    #[cfg(feature = "db_sqlite")]
    async fn attempt_ownership_transfer(
        db: &sea_orm::DatabaseConnection,
        audit_actor: &AuditHandle,
        org_id: &str,
        owner_id: &str,
        owner_email: &str,
        target_email: &str,
    ) -> Result<(users::Model, memberships::Model)> {
        let org_id = org_id.to_string();
        let owner_id = owner_id.to_string();
        let owner_email = owner_email.to_string();
        let target_email = target_email.to_string();
        let audit_actor = audit_actor.clone();
        with_retrying_transaction(
            db,
            db,
            "concurrent_ownership_transfer",
            move |transaction| {
                let org_id = org_id.clone();
                let owner_id = owner_id.clone();
                let owner_email = owner_email.clone();
                let target_email = target_email.clone();
                let audit_actor = audit_actor.clone();
                Box::pin(async move {
                    transfer_ownership_with_db(
                        transaction,
                        &audit_actor,
                        &org_id,
                        &owner_id,
                        &owner_email,
                        &target_email,
                    )
                    .await
                })
            },
        )
        .await
    }

    #[tokio::test]
    async fn ownership_transfer_binds_same_email_to_selected_org_member() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");

        let owner = UserStore::find_or_create(DB::Conn(&db), "owner@example.test")
            .await
            .expect("create current owner")
            .0;
        let (organization, _) = OrganizationStore::create_with_owner(
            DB::Conn(&db),
            "selected-org",
            "Selected Org",
            &owner.id,
            None,
        )
        .await
        .expect("create selected organization");

        let other_owner = UserStore::find_or_create(DB::Conn(&db), "other-owner@example.test")
            .await
            .expect("create other owner")
            .0;
        let (other_org, _) = OrganizationStore::create_with_owner(
            DB::Conn(&db),
            "other-org",
            "Other Org",
            &other_owner.id,
            None,
        )
        .await
        .expect("create other organization");

        let shared_email = "same-owner@example.test";
        let platform_decoy = UserStore::find_or_create(DB::Conn(&db), shared_email)
            .await
            .expect("create platform decoy")
            .0;
        let selected_target =
            UserStore::create_with_org_id(DB::Conn(&db), shared_email, None, &organization.id)
                .await
                .expect("create selected-org target");
        MembershipStore::create(
            DB::Conn(&db),
            &organization.id,
            &selected_target.id,
            "member",
        )
        .await
        .expect("create selected-org membership");
        let other_tenant_decoy =
            UserStore::create_with_org_id(DB::Conn(&db), shared_email, None, &other_org.id)
                .await
                .expect("create other-tenant decoy");
        let other_membership = MembershipStore::create(
            DB::Conn(&db),
            &other_org.id,
            &other_tenant_decoy.id,
            "member",
        )
        .await
        .expect("create other-tenant membership");

        let platform_before = platform_decoy.clone();
        let other_tenant_before = other_tenant_decoy.clone();
        let other_org_before = other_org.clone();
        let transaction = db.begin().await.expect("begin transfer");
        let (new_owner, updated_membership) = transfer_ownership_with_db(
            DB::Tx(&transaction),
            &AuditHandle::new(db.clone()),
            &organization.id,
            &owner.id,
            &owner.email,
            shared_email,
        )
        .await
        .expect("transfer ownership");
        transaction.commit().await.expect("commit transfer");

        assert_eq!(new_owner.id, selected_target.id);
        assert_eq!(updated_membership.user_id, selected_target.id);
        assert_eq!(updated_membership.role, "owner");
        let selected_org_after = OrganizationStore::find_by_id(DB::Conn(&db), &organization.id)
            .await
            .expect("read selected org")
            .expect("selected org exists");
        assert_eq!(selected_org_after.owner_user_id, selected_target.id);
        let previous_owner_membership =
            MembershipStore::find_by_org_and_user(DB::Conn(&db), &organization.id, &owner.id)
                .await
                .expect("read previous owner membership")
                .expect("previous owner membership exists");
        assert_eq!(previous_owner_membership.role, "admin");

        assert_eq!(
            UserStore::find_by_id(DB::Conn(&db), &platform_decoy.id)
                .await
                .expect("read platform decoy")
                .expect("platform decoy exists"),
            platform_before
        );
        assert_eq!(
            UserStore::find_by_id(DB::Conn(&db), &other_tenant_decoy.id)
                .await
                .expect("read other-tenant decoy")
                .expect("other-tenant decoy exists"),
            other_tenant_before
        );
        assert_eq!(
            OrganizationStore::find_by_id(DB::Conn(&db), &other_org.id)
                .await
                .expect("read other org")
                .expect("other org exists"),
            other_org_before
        );
        assert_eq!(
            MembershipStore::find_by_org_and_user(
                DB::Conn(&db),
                &other_org.id,
                &other_tenant_decoy.id,
            )
            .await
            .expect("read other membership")
            .expect("other membership exists"),
            other_membership
        );
    }

    #[cfg(feature = "db_sqlite")]
    #[tokio::test]
    async fn concurrent_ownership_transfers_have_one_winner_and_one_owner_membership() {
        let path = std::env::temp_dir().join(format!(
            "authos-ownership-transfer-{}.db",
            uuid::Uuid::new_v4()
        ));
        let db = Database::connect(format!("sqlite://{}?mode=rwc", path.display()))
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let owner = UserStore::find_or_create(DB::Conn(&db), "race-owner@example.test")
            .await
            .expect("create owner")
            .0;
        let (organization, _) = OrganizationStore::create_with_owner(
            DB::Conn(&db),
            "race-org",
            "Race Org",
            &owner.id,
            None,
        )
        .await
        .expect("create organization");
        let first_target = UserStore::create_with_org_id(
            DB::Conn(&db),
            "first-target@example.test",
            None,
            &organization.id,
        )
        .await
        .expect("create first target");
        let second_target = UserStore::create_with_org_id(
            DB::Conn(&db),
            "second-target@example.test",
            None,
            &organization.id,
        )
        .await
        .expect("create second target");
        MembershipStore::create(DB::Conn(&db), &organization.id, &first_target.id, "member")
            .await
            .expect("create first membership");
        MembershipStore::create(DB::Conn(&db), &organization.id, &second_target.id, "member")
            .await
            .expect("create second membership");
        let audit_actor = AuditHandle::new(db.clone());

        let (first, second) = tokio::join!(
            attempt_ownership_transfer(
                &db,
                &audit_actor,
                &organization.id,
                &owner.id,
                &owner.email,
                &first_target.email,
            ),
            attempt_ownership_transfer(
                &db,
                &audit_actor,
                &organization.id,
                &owner.id,
                &owner.email,
                &second_target.email,
            )
        );
        assert_eq!(
            usize::from(first.is_ok()) + usize::from(second.is_ok()),
            1,
            "exactly one compare-and-swap transfer must commit"
        );

        let organization_after = OrganizationStore::find_by_id(DB::Conn(&db), &organization.id)
            .await
            .expect("read organization")
            .expect("organization exists");
        assert!(
            organization_after.owner_user_id == first_target.id
                || organization_after.owner_user_id == second_target.id
        );
        let memberships =
            MembershipStore::list_by_org(DB::Conn(&db), &organization.id, None, 10, 0)
                .await
                .expect("list memberships");
        assert_eq!(
            memberships
                .iter()
                .filter(|membership| membership.role == "owner")
                .count(),
            1
        );
        assert_eq!(
            memberships
                .iter()
                .find(|membership| membership.user_id == owner.id)
                .expect("previous owner membership")
                .role,
            "admin"
        );
        let losing_target_id = if organization_after.owner_user_id == first_target.id {
            &second_target.id
        } else {
            &first_target.id
        };
        assert_eq!(
            memberships
                .iter()
                .find(|membership| membership.user_id == *losing_target_id)
                .expect("losing target membership")
                .role,
            "member"
        );

        db.close().await.expect("close sqlite");
        let _ = std::fs::remove_file(path);
    }
}
