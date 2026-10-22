use crate::constants::{
    DEFAULT_MAX_USERS, INVITATION_EXPIRY_DAYS, VALID_INVITATION_ROLES, VALID_ORG_ROLES,
};
use crate::db::transaction::with_retrying_transaction;
use crate::db::DB;
use crate::entities::{organization_invitations, organizations, users};
use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use crate::services::permission_service::{
    PermissionService, CAP_ORG_MEMBERS_MANAGE, CAP_ORG_ROLES_MANAGE,
};
use crate::state::AppState;
use crate::store::{
    invitations::InvitationStore, memberships::MembershipStore,
    organization_roles::OrganizationRoleStore, organization_tiers::OrganizationTierStore,
    organizations::OrganizationStore, users::UserStore,
};
use axum::{
    extract::{Path, Query, State},
    response::Redirect,
    Json,
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Hash an invitation token using SHA256
fn hash_invitation_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

async fn validate_invitation_role(db: DB<'_>, org_id: &str, role: &str) -> Result<()> {
    if VALID_INVITATION_ROLES.contains(&role) {
        return Ok(());
    }

    if VALID_ORG_ROLES.contains(&role.to_lowercase().as_str()) {
        return Err(AppError::BadRequest(
            "Invalid role. Choose admin, member, or a custom organization role.".to_string(),
        ));
    }

    if OrganizationRoleStore::find_by_org_and_slug(db, org_id, role)
        .await?
        .is_some()
    {
        return Ok(());
    }

    Err(AppError::BadRequest(
        "Invalid role. Choose admin, member, or a custom organization role.".to_string(),
    ))
}

#[derive(Debug, Deserialize)]
pub struct CreateInvitationRequest {
    pub email: String,
    pub role: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateInvitationRequest {
    pub token: String,
}

enum InvitationLookup {
    Token(String),
    Id(String),
}

#[derive(Debug, Serialize)]
pub struct InvitationResponse {
    pub invitation: SafeInvitationResponse,
    pub inviter: InvitationInviterResponse,
    pub token: String, // Plaintext token for email links (only returned once)
}

#[derive(Debug, Serialize)]
pub struct SafeInvitationResponse {
    pub id: String,
    pub org_id: String,
    pub email: String,
    pub role: String,
    pub invited_by: String,
    pub status: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct InvitationInviterResponse {
    pub id: String,
    pub email: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct ListInvitationsQuery {
    pub page: Option<i64>,
    pub limit: Option<i64>,
    #[allow(dead_code)]
    pub status: Option<String>,
}

/// Create invitation.
pub async fn create_invitation(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
    Json(req): Json<CreateInvitationRequest>,
) -> Result<Json<InvitationResponse>> {
    let user = &auth_user.user;

    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
    let organization =
        crate::handlers::organizations::ensure_organization_active(&state.db, &organization.id)
            .await?;

    if !PermissionService::check(
        DB::Conn(&state.db),
        &organization.id,
        &user.id,
        CAP_ORG_MEMBERS_MANAGE,
    )
    .await?
    {
        return Err(AppError::Forbidden(
            "Insufficient permissions to create invitations".to_string(),
        ));
    }

    validate_invitation_role(DB::Conn(&state.db), &organization.id, &req.role).await?;

    if req.role != "member"
        && !PermissionService::check(
            DB::Conn(&state.db),
            &organization.id,
            &user.id,
            CAP_ORG_ROLES_MANAGE,
        )
        .await?
    {
        return Err(AppError::Forbidden(
            "Insufficient permissions to invite members with this role".to_string(),
        ));
    }
    // Admin invitations grant every tenant capability. Only an owner may
    // create them; a custom role with role-management permission may invite
    // members and custom roles but cannot mint an admin.
    if req.role == "admin" {
        crate::middleware::check_org_owner(&state.db, &user.id, &organization.id).await?;
    }

    // Check if email is already a member
    let is_member =
        MembershipStore::is_email_member(DB::Conn(&state.db), &organization.id, &req.email).await?;

    if is_member {
        return Err(AppError::BadRequest(
            "User is already a member of this organization".to_string(),
        ));
    }

    // Check for existing pending invitation
    let pending_count = InvitationStore::count_pending_by_org_and_email(
        DB::Conn(&state.db),
        &organization.id,
        &req.email,
    )
    .await?;

    if pending_count > 0 {
        return Err(AppError::BadRequest("Invitation already sent".to_string()));
    }

    // Create invitation
    let invitation_id = Uuid::new_v4().to_string();
    let token = Uuid::new_v4().to_string(); // Generate plaintext token
    let token_hash = hash_invitation_token(&token); // Hash for storage
    let expires_at = Utc::now() + ChronoDuration::days(INVITATION_EXPIRY_DAYS);

    let new_invitation = organization_invitations::ActiveModel {
        id: Set(invitation_id),
        org_id: Set(organization.id.clone()),
        email: Set(req.email.clone()),
        role: Set(req.role.clone()),
        invited_by: Set(user.id.clone()),
        status: Set("pending".to_string()),
        token: Set(token_hash),
        expires_at: Set(expires_at.naive_utc()),
        created_at: Set(Utc::now().naive_utc()),
    };

    let invitation = new_invitation.insert(&state.db).await?;

    // Get inviter details
    let inviter = UserStore::find_by_id(DB::Conn(&state.db), &user.id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Enqueue invitation email to job queue (non-blocking)
    let invitation_url = format!(
        "{}/invitations/accept?token={}",
        state.web_client_url, token
    );
    let email_subject = format!("You've been invited to join {}", organization.name);
    let email_body = format!(
        "{} ({}) has invited you to join {} as a {}.\n\n\
        Click the link below to accept or decline this invitation:\n\n\
        {}\n\n\
        This invitation will expire in 7 days.\n\n\
        If you don't recognize this invitation, you can safely ignore this email.",
        inviter.email, inviter.email, organization.name, req.role, invitation_url
    );

    use crate::services::job_queue::JobQueueService;
    if let Err(e) = JobQueueService::enqueue_email(
        DB::Conn(&state.db),
        &req.email,
        &email_subject,
        &email_body,
        None, // No HTML version
    )
    .await
    {
        tracing::warn!(
            org_slug = %org_slug,
            invitation_id = %invitation.id,
            error = %e,
            "Failed to enqueue invitation email, but invitation was created"
        );
    } else {
        tracing::info!(
            org_slug = %org_slug,
            invitation_id = %invitation.id,
            "Invitation email enqueued successfully"
        );
    }

    Ok(Json(InvitationResponse {
        invitation: SafeInvitationResponse {
            id: invitation.id,
            org_id: invitation.org_id,
            email: invitation.email,
            role: invitation.role,
            invited_by: invitation.invited_by,
            status: invitation.status,
            expires_at: DateTime::<Utc>::from_naive_utc_and_offset(invitation.expires_at, Utc),
            created_at: DateTime::<Utc>::from_naive_utc_and_offset(invitation.created_at, Utc),
        },
        inviter: InvitationInviterResponse {
            id: inviter.id,
            email: inviter.email,
            created_at: DateTime::<Utc>::from_naive_utc_and_offset(inviter.created_at, Utc),
        },
        token, // Return plaintext token for email links
    }))
}

/// List user's pending invitations
pub async fn list_user_invitations(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> Result<Json<Vec<serde_json::Value>>> {
    let user = &auth_user.user;

    let invitations =
        InvitationStore::list_user_pending_invitations(DB::Conn(&state.db), &user.email).await?;

    let responses: Vec<serde_json::Value> = invitations
        .into_iter()
        .map(|row| {
            serde_json::json!({
                "id": row.id,
                "email": row.email,
                "role": row.role,
                "expires_at": DateTime::<Utc>::from_naive_utc_and_offset(row.expires_at, Utc).to_rfc3339(),
                "created_at": DateTime::<Utc>::from_naive_utc_and_offset(row.created_at, Utc).to_rfc3339(),
                "organization_slug": row.org_slug,
                "organization_name": row.org_name
            })
        })
        .collect();

    Ok(Json(responses))
}

/// Accept invitation for the authenticated user.
pub async fn accept_invitation(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Json(req): Json<UpdateInvitationRequest>,
) -> Result<Json<()>> {
    accept_invitation_internal(
        State(state),
        InvitationLookup::Token(req.token),
        "accepted",
        Some(auth_user.user.email.clone()),
        None,
    )
    .await
}

/// Accept invitation by invitation ID for the authenticated invitee.
pub async fn accept_invitation_by_id(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(invitation_id): Path<String>,
) -> Result<Json<()>> {
    accept_invitation_internal(
        State(state),
        InvitationLookup::Id(invitation_id),
        "accepted",
        Some(auth_user.user.email.clone()),
        None,
    )
    .await
}

/// Accept invitation by invitation ID as an organization member manager.
pub async fn accept_invitation_as_admin(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, invitation_id)): Path<(String, String)>,
) -> Result<Json<()>> {
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
    let organization =
        crate::handlers::organizations::ensure_organization_active(&state.db, &organization.id)
            .await?;

    if !PermissionService::check(
        DB::Conn(&state.db),
        &organization.id,
        &auth_user.user.id,
        CAP_ORG_MEMBERS_MANAGE,
    )
    .await?
    {
        return Err(AppError::Forbidden(
            "Insufficient permissions to accept invitations".to_string(),
        ));
    }

    accept_invitation_internal(
        State(state),
        InvitationLookup::Id(invitation_id),
        "accepted",
        None,
        Some(organization.id),
    )
    .await
}

/// Decline invitation by token.
pub async fn decline_invitation(
    State(state): State<AppState>,
    Json(req): Json<UpdateInvitationRequest>,
) -> Result<Json<()>> {
    accept_invitation_internal(
        State(state),
        InvitationLookup::Token(req.token),
        "rejected",
        None,
        None,
    )
    .await
}

/// Decline invitation by invitation ID for the authenticated invitee.
pub async fn decline_invitation_by_id(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(invitation_id): Path<String>,
) -> Result<Json<()>> {
    accept_invitation_internal(
        State(state),
        InvitationLookup::Id(invitation_id),
        "rejected",
        Some(auth_user.user.email.clone()),
        None,
    )
    .await
}

/// Internal invitation acceptance/rejection logic
async fn accept_invitation_internal(
    state: State<AppState>,
    lookup: InvitationLookup,
    new_status: &str,
    expected_email: Option<String>,
    expected_org_id: Option<String>,
) -> Result<Json<()>> {
    let new_status = new_status.to_string();

    // Execute transaction with retry on database contention
    let affected_user_id = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "accept_invitation",
        |db| {
            let lookup = match &lookup {
                InvitationLookup::Token(token) => InvitationLookup::Token(token.clone()),
                InvitationLookup::Id(invitation_id) => InvitationLookup::Id(invitation_id.clone()),
            };
            let new_status = new_status.clone();
            let expected_email = expected_email.clone();
            let expected_org_id = expected_org_id.clone();
            Box::pin(async move {
                // Find invitation
                use crate::entities::prelude::OrganizationInvitations;
                let invitation = match &lookup {
                    InvitationLookup::Token(token) => {
                        let token_hash = hash_invitation_token(token);
                        OrganizationInvitations::find()
                            .filter(organization_invitations::Column::Token.eq(&token_hash))
                            .filter(organization_invitations::Column::Status.eq("pending"))
                            .one(&db)
                            .await?
                    }
                    InvitationLookup::Id(invitation_id) => {
                        OrganizationInvitations::find()
                            .filter(organization_invitations::Column::Id.eq(invitation_id))
                            .filter(organization_invitations::Column::Status.eq("pending"))
                            .one(&db)
                            .await?
                    }
                }
                .ok_or_else(|| {
                    AppError::NotFound("Invitation not found or already processed".to_string())
                })?;

                // Check if expired
                let expires_at =
                    DateTime::<Utc>::from_naive_utc_and_offset(invitation.expires_at, Utc);

                if expires_at < Utc::now() {
                    return Err(AppError::BadRequest("Invitation has expired".to_string()));
                }

                if let Some(expected_email) = expected_email.as_ref() {
                    if !invitation.email.eq_ignore_ascii_case(expected_email) {
                        return Err(AppError::Forbidden(
                            "This invitation belongs to another email address".to_string(),
                        ));
                    }
                }

                if let Some(expected_org_id) = expected_org_id.as_ref() {
                    if invitation.org_id != *expected_org_id {
                        // A manager scoped to one organization must not be able
                        // to distinguish a real invitation in another tenant
                        // from a nonexistent invitation ID.
                        return Err(AppError::NotFound(
                            "Invitation not found or already processed".to_string(),
                        ));
                    }
                }

                use crate::entities::prelude::Organizations;
                let org = Organizations::find()
                    .filter(organizations::Column::Id.eq(&invitation.org_id))
                    .one(&db)
                    .await?
                    .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
                if new_status == "accepted" && org.status != "active" {
                    return Err(AppError::Forbidden(
                        "Organization is not active; invitation acceptance is disabled".to_string(),
                    ));
                }

                // Claim the pending invitation before any membership/user
                // side effects. A concurrent consumer or parent-state change
                // therefore fails without changing tenant state.
                let active_org_ids = sea_orm::sea_query::Query::select()
                    .column(organizations::Column::Id)
                    .from(crate::entities::organizations::Entity)
                    .and_where(organizations::Column::Status.eq("active"))
                    .to_owned();
                let mut claim = OrganizationInvitations::update_many()
                    .filter(organization_invitations::Column::Id.eq(&invitation.id))
                    .filter(organization_invitations::Column::Status.eq("pending"))
                    .set(organization_invitations::ActiveModel {
                        status: Set(new_status.clone()),
                        ..Default::default()
                    });
                if new_status == "accepted" {
                    claim = claim.filter(
                        organization_invitations::Column::OrgId.in_subquery(active_org_ids),
                    );
                }
                let update_result = claim.exec(&db).await?;

                if update_result.rows_affected != 1 {
                    return Err(AppError::NotFound(
                        "Invitation not found or already processed".to_string(),
                    ));
                }

                // Track user_id for cache invalidation
                let mut affected_user_id: Option<String> = None;

                if new_status == "accepted" {
                    let user = find_or_create_user_internal(
                        db.clone(),
                        &invitation.org_id,
                        &invitation.email,
                    )
                    .await?;
                    affected_user_id = Some(user.id.clone());

                    // Check team limits
                    let member_count =
                        MembershipStore::count_by_org(db.clone(), &invitation.org_id, None).await?;

                    let tier_limit = if let (Some(max_users), Some(_tier_id)) =
                        (org.max_users, org.tier_id.as_ref())
                    {
                        // Use org-specific limit if set
                        max_users as i64
                    } else if let Some(tier_id) = org.tier_id.as_ref() {
                        // Use tier default
                        let tier = OrganizationTierStore::find_by_id(db.clone(), tier_id)
                            .await?
                            .ok_or_else(|| AppError::NotFound("Tier not found".to_string()))?;

                        tier.default_max_users as i64
                    } else {
                        DEFAULT_MAX_USERS // Free tier default
                    };

                    if member_count >= tier_limit as u64 {
                        return Err(AppError::BadRequest("Team limit reached".to_string()));
                    }

                    MembershipStore::create(
                        db.clone(),
                        &invitation.org_id,
                        &user.id,
                        &invitation.role,
                    )
                    .await?;

                    // Grant organization permission for the new member
                    use crate::entities::permissions::RelationTuple;
                    use crate::store::permissions::PermissionsStore;
                    PermissionsStore::grant(
                        db.clone(),
                        RelationTuple::user(
                            "organization".to_string(),
                            invitation.org_id.clone(),
                            invitation.role.clone(),
                            user.id.clone(),
                        ),
                    )
                    .await?;
                }

                Ok(affected_user_id)
            })
        },
    )
    .await?;

    // CRITICAL: Invalidate permission cache after accepting invitation
    if let Some(user_id) = affected_user_id {
        state.permission_cache.invalidate(&user_id).await;
    }

    Ok(Json(()))
}

/// Accept invitation via email link (redirect)
pub async fn accept_invitation_redirect(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<Redirect> {
    Ok(Redirect::temporary(&format!(
        "{}/invitations/accept?token={}",
        state.web_client_url, token
    )))
}

/// Cancel invitation.
pub async fn cancel_invitation(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, invitation_id)): Path<(String, String)>,
) -> Result<Json<()>> {
    let user = &auth_user.user;

    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
    let organization =
        crate::handlers::organizations::ensure_organization_active(&state.db, &organization.id)
            .await?;

    if !PermissionService::check(
        DB::Conn(&state.db),
        &organization.id,
        &user.id,
        CAP_ORG_MEMBERS_MANAGE,
    )
    .await?
    {
        return Err(AppError::Forbidden(
            "Insufficient permissions to cancel invitations".to_string(),
        ));
    }

    // Cancel invitation - find it first, then update
    use crate::entities::prelude::OrganizationInvitations;
    let invitation = OrganizationInvitations::find()
        .filter(organization_invitations::Column::Id.eq(&invitation_id))
        .filter(organization_invitations::Column::OrgId.eq(&organization.id))
        .filter(organization_invitations::Column::Status.eq("pending"))
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            AppError::NotFound("Invitation not found or already processed".to_string())
        })?;

    let mut invitation_active: organization_invitations::ActiveModel = invitation.into();
    invitation_active.status = Set("cancelled".to_string());
    invitation_active.update(&state.db).await?;

    Ok(Json(()))
}

/// List organization invitations.
pub async fn list_invitations(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
    query: Query<ListInvitationsQuery>,
) -> Result<Json<Vec<serde_json::Value>>> {
    let user = &auth_user.user;

    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
    let organization =
        crate::handlers::organizations::ensure_organization_active(&state.db, &organization.id)
            .await?;

    if !PermissionService::check(
        DB::Conn(&state.db),
        &organization.id,
        &user.id,
        CAP_ORG_MEMBERS_MANAGE,
    )
    .await?
    {
        return Err(AppError::Forbidden(
            "Insufficient permissions to view invitations".to_string(),
        ));
    }

    // Extract pagination parameters with defaults
    let (_page, limit, offset) =
        crate::utils::pagination::signed_page(query.page, query.limit, 50, 100);

    // Get invitations for this organization with pagination
    let invitations = InvitationStore::list_org_invitations_with_inviter(
        DB::Conn(&state.db),
        &organization.id,
        limit,
        offset,
    )
    .await?;

    let responses: Vec<serde_json::Value> = invitations
        .into_iter()
        .map(|row| {
            serde_json::json!({
                "invitation": {
                    "id": row.id,
                    "email": row.email,
                    "role": row.role,
                    "status": row.status,
                    "expires_at": DateTime::<Utc>::from_naive_utc_and_offset(row.expires_at, Utc).to_rfc3339(),
                    "created_at": DateTime::<Utc>::from_naive_utc_and_offset(row.created_at, Utc).to_rfc3339()
                },
                "inviter": {
                    "id": row.inviter_id,
                    "email": row.inviter_email,
                    "created_at": DateTime::<Utc>::from_naive_utc_and_offset(row.inviter_created_at, Utc).to_rfc3339()
                }
            })
        })
        .collect();

    Ok(Json(responses))
}

/// Helper function to find or create a user within a transaction (for invitation acceptance)
async fn find_or_create_user_internal(
    db: DB<'_>,
    org_id: &str,
    email: &str,
) -> Result<users::Model> {
    // Reuse a shared identity only when an existing membership proves that it
    // is already intentionally bound to this exact organization.
    if let Some((_, user)) =
        MembershipStore::find_unique_member_with_user_by_org_and_email(db.clone(), org_id, email)
            .await?
    {
        return Ok(user);
    }

    use crate::entities::prelude::Users;
    if let Some(user) = Users::find()
        .filter(users::Column::Email.eq(email))
        .filter(users::Column::OrgId.eq(org_id))
        .one(&db)
        .await?
    {
        return Ok(user);
    }

    // Create new user
    let new_user = users::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        email: Set(email.to_string()),
        org_id: Set(Some(org_id.to_string())),
        created_at: Set(Utc::now().naive_utc()),
        ..Default::default()
    };
    use sea_orm::sea_query::OnConflict;
    Users::insert(new_user)
        .on_conflict(OnConflict::new().do_nothing().to_owned())
        .exec_without_returning(&db)
        .await?;

    Users::find()
        .filter(users::Column::Email.eq(email))
        .filter(users::Column::OrgId.eq(org_id))
        .one(&db)
        .await?
        .ok_or_else(|| AppError::InternalServerError("Failed to create invited user".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::crypto::sso::OAuthClient;

    use crate::entities::prelude::OrganizationInvitations;

    use crate::audit::actor::AuditHandle;
    use crate::services::{
        events::EventDispatcher, metrics::MfaMetricsService, risk_engine::RiskEngine,
    };
    use crate::store::{
        memberships::MembershipStore,
        organizations::OrganizationStore,
        users::{UserCreationOptions, UserStore},
    };

    use moka::future::Cache;
    use sea_orm::{DatabaseConnection, EntityTrait, PaginatorTrait};
    use std::sync::Arc;

    #[test]
    fn invitation_response_serializes_only_safe_account_fields() {
        let now = Utc::now();
        let response = InvitationResponse {
            invitation: SafeInvitationResponse {
                id: "inv-1".to_string(),
                org_id: "org-1".to_string(),
                email: "invitee@example.com".to_string(),
                role: "member".to_string(),
                invited_by: "user-1".to_string(),
                status: "pending".to_string(),
                expires_at: now,
                created_at: now,
            },
            inviter: InvitationInviterResponse {
                id: "user-1".to_string(),
                email: "owner@example.com".to_string(),
                created_at: now,
            },
            token: "one-time-token".to_string(),
        };

        let value = serde_json::to_value(response).expect("response should serialize");
        assert_eq!(value["token"], "one-time-token");
        assert!(value["inviter"].get("password_hash").is_none());
        assert!(value["invitation"].get("token").is_none());
    }

    struct InvitationFixture {
        state: AppState,
        org_id: String,
        owner_id: String,
    }

    use crate::test_support::test_config;

    use crate::test_support::test_jwt_service;

    use crate::test_support::setup_db;

    async fn setup_fixture() -> InvitationFixture {
        let db = setup_db().await;
        let config = test_config();
        let owner = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "owner@example.com",
            UserCreationOptions {
                is_platform_owner: true,
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
        OrganizationStore::update_status(DB::Conn(&db), &org.id, "active")
            .await
            .expect("activate invitation fixture org");

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

        InvitationFixture {
            state,
            org_id: org.id,
            owner_id: owner.id,
        }
    }

    async fn create_invitation(
        db: &DatabaseConnection,
        org_id: &str,
        owner_id: &str,
        email: &str,
        role: &str,
        token: &str,
    ) -> organization_invitations::Model {
        organization_invitations::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            org_id: Set(org_id.to_string()),
            email: Set(email.to_string()),
            role: Set(role.to_string()),
            invited_by: Set(owner_id.to_string()),
            status: Set("pending".to_string()),
            token: Set(hash_invitation_token(token)),
            expires_at: Set((Utc::now() + ChronoDuration::days(1)).naive_utc()),
            created_at: Set(Utc::now().naive_utc()),
        }
        .insert(db)
        .await
        .expect("create invitation")
    }

    async fn accept_by_token(
        fixture: &InvitationFixture,
        token: &str,
        expected_email: Option<&str>,
    ) -> Result<Json<()>> {
        accept_invitation_internal(
            State(fixture.state.clone()),
            InvitationLookup::Token(token.to_string()),
            "accepted",
            expected_email.map(str::to_string),
            None,
        )
        .await
    }

    #[tokio::test]
    async fn token_invitation_acceptance_is_single_use() {
        let fixture = setup_fixture().await;
        let invite = create_invitation(
            &fixture.state.db,
            &fixture.org_id,
            &fixture.owner_id,
            "invitee@example.com",
            "member",
            "plain-token",
        )
        .await;

        let _ = accept_by_token(&fixture, "plain-token", Some("invitee@example.com"))
            .await
            .expect("first accept succeeds");
        let second = accept_by_token(&fixture, "plain-token", Some("invitee@example.com"))
            .await
            .expect_err("second accept fails");

        assert!(matches!(
            second,
            AppError::NotFound(ref message)
                if message.contains("Invitation not found or already processed")
        ));

        let stored = OrganizationInvitations::find_by_id(invite.id)
            .one(&fixture.state.db)
            .await
            .expect("query invitation")
            .expect("invitation exists");
        assert_eq!(stored.status, "accepted");
        let member_count =
            MembershipStore::count_by_org(DB::Conn(&fixture.state.db), &fixture.org_id, None)
                .await
                .expect("count members");
        assert_eq!(member_count, 2);
    }

    #[tokio::test]
    async fn suspended_parent_rejects_invitation_acceptance_without_state_changes() {
        let fixture = setup_fixture().await;
        let invite = create_invitation(
            &fixture.state.db,
            &fixture.org_id,
            &fixture.owner_id,
            "suspended-invitee@example.com",
            "member",
            "suspended-token",
        )
        .await;
        OrganizationStore::update_status(DB::Conn(&fixture.state.db), &fixture.org_id, "suspended")
            .await
            .expect("suspend organization");

        let error = accept_by_token(
            &fixture,
            "suspended-token",
            Some("suspended-invitee@example.com"),
        )
        .await
        .expect_err("suspended tenant must reject invitation acceptance");
        assert!(matches!(error, AppError::Forbidden(_)));

        let stored = OrganizationInvitations::find_by_id(invite.id)
            .one(&fixture.state.db)
            .await
            .expect("query invitation")
            .expect("invitation remains");
        assert_eq!(stored.status, "pending");
        assert_eq!(
            MembershipStore::count_by_org(DB::Conn(&fixture.state.db), &fixture.org_id, None)
                .await
                .expect("count unchanged memberships"),
            1
        );
        assert!(UserStore::find_by_email_with_context(
            DB::Conn(&fixture.state.db),
            "suspended-invitee@example.com",
            Some(&fixture.org_id),
        )
        .await
        .expect("query denied invitee")
        .is_none());
    }

    #[tokio::test]
    async fn concurrent_token_invitation_acceptance_consumes_once() {
        let fixture = setup_fixture().await;
        let invite = create_invitation(
            &fixture.state.db,
            &fixture.org_id,
            &fixture.owner_id,
            "race@example.com",
            "member",
            "race-token",
        )
        .await;

        let (first, second) = tokio::join!(
            accept_by_token(&fixture, "race-token", Some("race@example.com")),
            accept_by_token(&fixture, "race-token", Some("race@example.com"))
        );
        let successes = usize::from(first.is_ok()) + usize::from(second.is_ok());
        let failures = [first, second]
            .into_iter()
            .filter_map(Result::err)
            .collect::<Vec<_>>();

        assert_eq!(successes, 1);
        assert_eq!(failures.len(), 1);
        assert!(matches!(
            failures.first(),
            Some(AppError::NotFound(message))
                if message.contains("Invitation not found or already processed")
        ));

        let stored = OrganizationInvitations::find_by_id(invite.id)
            .one(&fixture.state.db)
            .await
            .expect("query invitation")
            .expect("invitation exists");
        assert_eq!(stored.status, "accepted");
        let member_count =
            MembershipStore::count_by_org(DB::Conn(&fixture.state.db), &fixture.org_id, None)
                .await
                .expect("count members");
        assert_eq!(member_count, 2);
    }

    #[tokio::test]
    async fn id_invitation_acceptance_is_single_use() {
        let fixture = setup_fixture().await;
        let invite = create_invitation(
            &fixture.state.db,
            &fixture.org_id,
            &fixture.owner_id,
            "id-invitee@example.com",
            "member",
            "id-token",
        )
        .await;

        let _ = accept_invitation_internal(
            State(fixture.state.clone()),
            InvitationLookup::Id(invite.id.clone()),
            "accepted",
            Some("id-invitee@example.com".to_string()),
            None,
        )
        .await
        .expect("first id accept succeeds");
        let second = accept_invitation_internal(
            State(fixture.state.clone()),
            InvitationLookup::Id(invite.id),
            "accepted",
            Some("id-invitee@example.com".to_string()),
            None,
        )
        .await
        .expect_err("second id accept fails");

        assert!(matches!(
            second,
            AppError::NotFound(ref message)
                if message.contains("Invitation not found or already processed")
        ));
    }

    #[tokio::test]
    async fn already_member_invitation_acceptance_consumes_without_duplicate_or_role_rewrite() {
        let fixture = setup_fixture().await;
        let member = UserStore::find_or_create_with_options(
            DB::Conn(&fixture.state.db),
            "member@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create existing member")
        .0;
        MembershipStore::create(
            DB::Conn(&fixture.state.db),
            &fixture.org_id,
            &member.id,
            "member",
        )
        .await
        .expect("create existing membership");
        let invite = create_invitation(
            &fixture.state.db,
            &fixture.org_id,
            &fixture.owner_id,
            &member.email,
            "admin",
            "already-member-token",
        )
        .await;

        let _ = accept_by_token(&fixture, "already-member-token", Some(&member.email))
            .await
            .expect("already-member accept succeeds");

        let membership = MembershipStore::find_by_org_and_user(
            DB::Conn(&fixture.state.db),
            &fixture.org_id,
            &member.id,
        )
        .await
        .expect("query membership")
        .expect("membership exists");
        assert_eq!(membership.role, "member");
        let member_count =
            MembershipStore::count_by_org(DB::Conn(&fixture.state.db), &fixture.org_id, None)
                .await
                .expect("count members");
        assert_eq!(member_count, 2);

        let stored = OrganizationInvitations::find_by_id(invite.id)
            .one(&fixture.state.db)
            .await
            .expect("query invitation")
            .expect("invitation exists");
        assert_eq!(stored.status, "accepted");
    }

    #[tokio::test]
    async fn invitation_acceptance_ignores_platform_and_sibling_same_email_users() {
        let fixture = setup_fixture().await;
        let email = "same-email-invitee@example.com";
        let platform_user = UserStore::find_or_create_with_options(
            DB::Conn(&fixture.state.db),
            email,
            UserCreationOptions::default(),
        )
        .await
        .expect("create same-email platform user")
        .0;
        let sibling_owner = UserStore::find_or_create_with_options(
            DB::Conn(&fixture.state.db),
            "sibling-invite-owner@example.com",
            UserCreationOptions::default(),
        )
        .await
        .expect("create sibling owner")
        .0;
        let (sibling_org, _) = OrganizationStore::create_with_owner(
            DB::Conn(&fixture.state.db),
            "sibling-invite-org",
            "Sibling Invite Org",
            &sibling_owner.id,
            None,
        )
        .await
        .expect("create sibling org");
        let sibling_user = UserStore::create_with_org_id(
            DB::Conn(&fixture.state.db),
            email,
            None,
            &sibling_org.id,
        )
        .await
        .expect("create same-email sibling user");
        create_invitation(
            &fixture.state.db,
            &fixture.org_id,
            &fixture.owner_id,
            email,
            "member",
            "same-email-target-token",
        )
        .await;

        let _ = accept_by_token(&fixture, "same-email-target-token", Some(email))
            .await
            .expect("accept target-tenant invitation");

        let target_user = UserStore::find_by_email_with_context(
            DB::Conn(&fixture.state.db),
            email,
            Some(&fixture.org_id),
        )
        .await
        .expect("load target user")
        .expect("target user created");
        assert_ne!(target_user.id, platform_user.id);
        assert_ne!(target_user.id, sibling_user.id);
        assert!(MembershipStore::find_by_org_and_user(
            DB::Conn(&fixture.state.db),
            &fixture.org_id,
            &target_user.id,
        )
        .await
        .expect("load target membership")
        .is_some());
        assert!(MembershipStore::find_by_org_and_user(
            DB::Conn(&fixture.state.db),
            &fixture.org_id,
            &platform_user.id,
        )
        .await
        .expect("check platform membership")
        .is_none());
        assert!(MembershipStore::find_by_org_and_user(
            DB::Conn(&fixture.state.db),
            &fixture.org_id,
            &sibling_user.id,
        )
        .await
        .expect("check sibling membership")
        .is_none());
    }

    #[tokio::test]
    async fn concurrent_invited_user_resolution_has_one_tenant_identity() {
        let fixture = setup_fixture().await;
        let email = "concurrent-invitee@example.com";
        let first =
            find_or_create_user_internal(DB::Conn(&fixture.state.db), &fixture.org_id, email);
        let second =
            find_or_create_user_internal(DB::Conn(&fixture.state.db), &fixture.org_id, email);
        let (first, second) = tokio::join!(first, second);
        let first = first.expect("first concurrent resolution");
        let second = second.expect("second concurrent resolution");
        assert_eq!(first.id, second.id);
        assert_eq!(first.org_id.as_deref(), Some(fixture.org_id.as_str()));
        assert_eq!(
            crate::entities::prelude::Users::find()
                .filter(users::Column::Email.eq(email))
                .filter(users::Column::OrgId.eq(&fixture.org_id))
                .count(&fixture.state.db)
                .await
                .expect("count tenant identities"),
            1
        );
    }
}

#[cfg(test)]
mod route_tests {
    use super::*;

    use crate::audit::actor::AuditHandle;
    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::crypto::sso::OAuthClient;
    use crate::entities::prelude::OrganizationInvitations;
    use crate::services::{
        events::EventDispatcher, metrics::MfaMetricsService, risk_engine::RiskEngine,
    };
    use crate::store::users::{UserCreationOptions, UserStore};
    use crate::test_support::{setup_db, test_config, test_jwt_service};
    use moka::future::Cache;
    use sea_orm::{DatabaseConnection, EntityTrait};
    use serde_json::json;
    use std::sync::Arc;

    struct Fixture {
        state: AppState,
        owner: AuthUser,
        admin: AuthUser,
        member: AuthUser,
        custom_manager: AuthUser,
        outsider: AuthUser,
        other_owner: AuthUser,
        alpha_invitee: AuthUser,
        beta_invitee: AuthUser,
        alpha_slug: String,
        alpha_invitation_id: String,
        beta_invitation_id: String,
        alpha_invitation_token: String,
        beta_invitation_id_for_admin: String,
    }

    async fn seed_invitation(
        db: &DatabaseConnection,
        org_id: &str,
        invited_by: &str,
        email: &str,
        role: &str,
        token: &str,
    ) -> organization_invitations::Model {
        organization_invitations::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            org_id: Set(org_id.to_string()),
            email: Set(email.to_string()),
            role: Set(role.to_string()),
            invited_by: Set(invited_by.to_string()),
            status: Set("pending".to_string()),
            token: Set(hash_invitation_token(token)),
            expires_at: Set((Utc::now() + ChronoDuration::days(1)).naive_utc()),
            created_at: Set(Utc::now().naive_utc()),
        }
        .insert(db)
        .await
        .expect("seed invitation")
    }

    async fn fixture() -> Fixture {
        let db = setup_db().await;
        let config = test_config();
        let jwt_service = Arc::new(test_jwt_service(&config));

        let owner = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "invite-owner@example.test",
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
            "invite-admin@example.test",
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
            "invite-member@example.test",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create member")
        .0;
        let custom_manager = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "invite-custom@example.test",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create custom manager")
        .0;
        let outsider = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "invite-outsider@example.test",
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
            "invite-other-owner@example.test",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create other owner")
        .0;
        let alpha_invitee = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "alpha-invitee@example.test",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create alpha invitee")
        .0;
        let beta_invitee = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "beta-invitee@example.test",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create beta invitee")
        .0;

        let (alpha, _) = OrganizationStore::create_with_owner(
            DB::Conn(&db),
            "invite-alpha",
            "Invite Alpha",
            &owner.id,
            Some("tier_enterprise"),
        )
        .await
        .expect("create alpha");
        let (beta, _) = OrganizationStore::create_with_owner(
            DB::Conn(&db),
            "invite-beta",
            "Invite Beta",
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
            "invite-manager-role",
            &alpha.id,
            "invite-manager",
            "Invite Manager",
            None,
            json!([CAP_ORG_MEMBERS_MANAGE, CAP_ORG_ROLES_MANAGE]),
        )
        .await
        .expect("create invite-manager role");
        MembershipStore::create(
            DB::Conn(&db),
            &alpha.id,
            &custom_manager.id,
            "invite-manager",
        )
        .await
        .expect("add custom manager");

        let alpha_invitation = seed_invitation(
            &db,
            &alpha.id,
            &owner.id,
            &alpha_invitee.email,
            "member",
            "alpha-invitation-token",
        )
        .await;
        let beta_invitation = seed_invitation(
            &db,
            &beta.id,
            &other_owner.id,
            &beta_invitee.email,
            "member",
            "beta-invitation-token",
        )
        .await;
        let admin_accept_invitation = seed_invitation(
            &db,
            &alpha.id,
            &owner.id,
            "admin-accept@example.test",
            "member",
            "admin-accept-token",
        )
        .await;

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
                user_agent: "invitation-route-test".to_string(),
                current_session_id: None,
            }
        };
        let owner_auth = auth_user_for(&owner);
        let admin_auth = auth_user_for(&admin);
        let member_auth = auth_user_for(&member);
        let custom_auth = auth_user_for(&custom_manager);
        let outsider_auth = auth_user_for(&outsider);
        let other_owner_auth = auth_user_for(&other_owner);
        let alpha_invitee_auth = auth_user_for(&alpha_invitee);
        let beta_invitee_auth = auth_user_for(&beta_invitee);

        Fixture {
            state,
            owner: owner_auth,
            admin: admin_auth,
            member: member_auth,
            custom_manager: custom_auth,
            outsider: outsider_auth,
            other_owner: other_owner_auth,
            alpha_invitee: alpha_invitee_auth,
            beta_invitee: beta_invitee_auth,
            alpha_slug: alpha.slug,
            alpha_invitation_id: alpha_invitation.id,
            beta_invitation_id: beta_invitation.id,
            alpha_invitation_token: "alpha-invitation-token".to_string(),
            beta_invitation_id_for_admin: admin_accept_invitation.id,
        }
    }

    async fn invitation_ids(
        state: &AppState,
        auth: AuthUser,
        org_slug: &str,
    ) -> Result<Vec<String>> {
        let Json(rows) = list_invitations(
            State(state.clone()),
            auth,
            Path(org_slug.to_string()),
            Query(ListInvitationsQuery {
                page: None,
                limit: None,
                status: None,
            }),
        )
        .await?;
        Ok(rows
            .into_iter()
            .filter_map(|row| {
                row.get("invitation")
                    .and_then(|invitation| invitation.get("id"))
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
            })
            .collect())
    }

    #[tokio::test]
    async fn invitation_management_requires_member_authority_and_is_org_scoped() {
        let f = fixture().await;

        for auth in [f.owner.clone(), f.admin.clone(), f.custom_manager.clone()] {
            let ids = invitation_ids(&f.state, auth, &f.alpha_slug)
                .await
                .expect("member manager may list invitations");
            assert!(ids.contains(&f.alpha_invitation_id));
            assert!(!ids.contains(&f.beta_invitation_id));
        }
        for auth in [f.member.clone(), f.outsider.clone(), f.other_owner.clone()] {
            assert!(matches!(
                invitation_ids(&f.state, auth, &f.alpha_slug).await,
                Err(AppError::Forbidden(_))
            ));
        }

        for auth in [f.member.clone(), f.outsider.clone(), f.other_owner.clone()] {
            assert!(matches!(
                create_invitation(
                    State(f.state.clone()),
                    auth,
                    Path(f.alpha_slug.clone()),
                    Json(CreateInvitationRequest {
                        email: "denied-invite@example.test".to_string(),
                        role: "member".to_string(),
                    }),
                )
                .await,
                Err(AppError::Forbidden(_))
            ));
        }

        // A custom member manager may invite members but cannot mint admins.
        let Json(member_invite) = create_invitation(
            State(f.state.clone()),
            f.custom_manager.clone(),
            Path(f.alpha_slug.clone()),
            Json(CreateInvitationRequest {
                email: "custom-invite@example.test".to_string(),
                role: "member".to_string(),
            }),
        )
        .await
        .expect("custom manager may invite a member");
        assert_eq!(member_invite.invitation.email, "custom-invite@example.test");
        assert_eq!(member_invite.invitation.role, "member");
        assert!(matches!(
            create_invitation(
                State(f.state.clone()),
                f.custom_manager.clone(),
                Path(f.alpha_slug.clone()),
                Json(CreateInvitationRequest {
                    email: "custom-admin-invite@example.test".to_string(),
                    role: "admin".to_string(),
                }),
            )
            .await,
            Err(AppError::Forbidden(_))
        ));

        // Only the owner can invite an admin.
        let Json(admin_invite) = create_invitation(
            State(f.state.clone()),
            f.owner.clone(),
            Path(f.alpha_slug.clone()),
            Json(CreateInvitationRequest {
                email: "owner-admin-invite@example.test".to_string(),
                role: "admin".to_string(),
            }),
        )
        .await
        .expect("owner may invite an admin");
        assert_eq!(admin_invite.invitation.role, "admin");

        // Denied cancellation leaves the pending invitation intact.
        for auth in [f.member.clone(), f.outsider.clone()] {
            assert!(matches!(
                cancel_invitation(
                    State(f.state.clone()),
                    auth,
                    Path((f.alpha_slug.clone(), f.alpha_invitation_id.clone())),
                )
                .await,
                Err(AppError::Forbidden(_))
            ));
        }
        // A cross-tenant invitation ID is hidden from the selected organization.
        assert!(matches!(
            cancel_invitation(
                State(f.state.clone()),
                f.owner.clone(),
                Path((f.alpha_slug.clone(), f.beta_invitation_id.clone())),
            )
            .await,
            Err(AppError::NotFound(_))
        ));
        let beta_stored = OrganizationInvitations::find_by_id(f.beta_invitation_id.clone())
            .one(&f.state.db)
            .await
            .expect("load beta invitation")
            .expect("beta invitation remains");
        assert_eq!(beta_stored.status, "pending");

        let _ = cancel_invitation(
            State(f.state.clone()),
            f.owner.clone(),
            Path((f.alpha_slug.clone(), f.alpha_invitation_id.clone())),
        )
        .await
        .expect("owner may cancel");
        let alpha_stored = OrganizationInvitations::find_by_id(f.alpha_invitation_id.clone())
            .one(&f.state.db)
            .await
            .expect("load alpha invitation")
            .expect("alpha invitation remains");
        assert_eq!(alpha_stored.status, "cancelled");
    }

    #[tokio::test]
    async fn invitation_acceptance_by_id_is_email_and_org_bound() {
        let f = fixture().await;
        let alpha = OrganizationStore::find_by_slug(DB::Conn(&f.state.db), &f.alpha_slug)
            .await
            .expect("load alpha")
            .expect("alpha exists");

        // A different authenticated email cannot accept or decline the invite.
        for auth in [f.outsider.clone(), f.other_owner.clone()] {
            assert!(matches!(
                accept_invitation_by_id(
                    State(f.state.clone()),
                    auth,
                    Path(f.alpha_invitation_id.clone()),
                )
                .await,
                Err(AppError::Forbidden(_))
            ));
        }
        assert!(matches!(
            decline_invitation_by_id(
                State(f.state.clone()),
                f.outsider.clone(),
                Path(f.alpha_invitation_id.clone()),
            )
            .await,
            Err(AppError::Forbidden(_))
        ));
        assert_eq!(
            OrganizationInvitations::find_by_id(f.alpha_invitation_id.clone())
                .one(&f.state.db)
                .await
                .expect("load alpha invitation")
                .expect("alpha invitation remains")
                .status,
            "pending"
        );

        // The matching invitee can accept by token.
        let _ = accept_invitation(
            State(f.state.clone()),
            f.alpha_invitee.clone(),
            Json(UpdateInvitationRequest {
                token: f.alpha_invitation_token.clone(),
            }),
        )
        .await
        .expect("matching invitee may accept by token");
        let alpha_user = UserStore::find_by_email_with_context(
            DB::Conn(&f.state.db),
            "alpha-invitee@example.test",
            Some(&alpha.id),
        )
        .await
        .expect("load accepted user")
        .expect("accepted user exists");
        assert!(MembershipStore::find_by_org_and_user(
            DB::Conn(&f.state.db),
            &alpha.id,
            &alpha_user.id,
        )
        .await
        .expect("load accepted membership")
        .is_some());

        // A member manager can accept a different pending invitation by ID.
        for auth in [f.member.clone(), f.outsider.clone()] {
            assert!(matches!(
                accept_invitation_as_admin(
                    State(f.state.clone()),
                    auth,
                    Path((f.alpha_slug.clone(), f.beta_invitation_id_for_admin.clone())),
                )
                .await,
                Err(AppError::Forbidden(_))
            ));
        }
        let _ = accept_invitation_as_admin(
            State(f.state.clone()),
            f.custom_manager.clone(),
            Path((f.alpha_slug.clone(), f.beta_invitation_id_for_admin.clone())),
        )
        .await
        .expect("member manager may accept an invitation");
        let admin_accept_user = UserStore::find_by_email_with_context(
            DB::Conn(&f.state.db),
            "admin-accept@example.test",
            Some(&alpha.id),
        )
        .await
        .expect("load admin-accepted user")
        .expect("admin-accepted user exists");
        assert!(MembershipStore::find_by_org_and_user(
            DB::Conn(&f.state.db),
            &alpha.id,
            &admin_accept_user.id,
        )
        .await
        .expect("load admin-accepted membership")
        .is_some());

        // A cross-tenant invitation ID cannot be accepted through alpha.
        assert!(matches!(
            accept_invitation_as_admin(
                State(f.state.clone()),
                f.owner.clone(),
                Path((f.alpha_slug.clone(), f.beta_invitation_id.clone())),
            )
            .await,
            Err(AppError::NotFound(_))
        ));
        assert_eq!(
            OrganizationInvitations::find_by_id(f.beta_invitation_id.clone())
                .one(&f.state.db)
                .await
                .expect("load beta invitation")
                .expect("beta invitation remains")
                .status,
            "pending"
        );

        // The beta invitee can accept their own invitation by ID.
        let _ = accept_invitation_by_id(
            State(f.state.clone()),
            f.beta_invitee.clone(),
            Path(f.beta_invitation_id.clone()),
        )
        .await
        .expect("beta invitee may accept");
    }

    #[tokio::test]
    async fn suspended_parent_denies_invitation_management_and_acceptance() {
        let f = fixture().await;
        let alpha = OrganizationStore::find_by_slug(DB::Conn(&f.state.db), &f.alpha_slug)
            .await
            .expect("load alpha")
            .expect("alpha exists");
        OrganizationStore::update_status(DB::Conn(&f.state.db), &alpha.id, "suspended")
            .await
            .expect("suspend alpha");

        assert!(matches!(
            invitation_ids(&f.state, f.owner.clone(), &f.alpha_slug).await,
            Err(AppError::Forbidden(_))
        ));
        assert!(matches!(
            create_invitation(
                State(f.state.clone()),
                f.owner.clone(),
                Path(f.alpha_slug.clone()),
                Json(CreateInvitationRequest {
                    email: "suspended-new@example.test".to_string(),
                    role: "member".to_string(),
                }),
            )
            .await,
            Err(AppError::Forbidden(_))
        ));
        assert!(matches!(
            cancel_invitation(
                State(f.state.clone()),
                f.owner.clone(),
                Path((f.alpha_slug.clone(), f.alpha_invitation_id.clone())),
            )
            .await,
            Err(AppError::Forbidden(_))
        ));
        assert!(matches!(
            accept_invitation_by_id(
                State(f.state.clone()),
                f.alpha_invitee.clone(),
                Path(f.alpha_invitation_id.clone()),
            )
            .await,
            Err(AppError::Forbidden(_))
        ));
        assert_eq!(
            OrganizationInvitations::find_by_id(f.alpha_invitation_id.clone())
                .one(&f.state.db)
                .await
                .expect("load alpha invitation")
                .expect("alpha invitation remains")
                .status,
            "pending"
        );
    }
}
