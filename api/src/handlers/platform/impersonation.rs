//! Impersonation Handlers
//!
//! Implements platform impersonation functionality following RFC 8693 (Token Exchange).
//! Only platform owners may impersonate users; tenant administrators cannot
//! mint tokens that cross tenant boundaries.

use crate::crypto::jwt::JwtService;
use crate::db::transaction::with_retrying_transaction;
use crate::db::DB;
use crate::entities::{platform_audit_log, users as users_entity};
use crate::error::AppError;
use crate::middleware::{AuthUser, ImpersonationContext};
use crate::state::AppState;
use crate::store::{
    memberships::MembershipStore, organizations::OrganizationStore, sessions::SessionStore,
};
use axum::{
    extract::{Extension, Json, State},
    response::Json as AxumJson,
};
use chrono::Utc;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

/// Request to impersonate a user
#[derive(Debug, Deserialize)]
pub struct ImpersonateRequest {
    /// User ID to impersonate
    pub user_id: String,
    /// Reason for impersonation (required for audit trail)
    pub reason: String,
}

/// Response containing impersonation token
#[derive(Debug, Serialize)]
pub struct ImpersonateResponse {
    /// JWT token for impersonated session
    pub token: String,
    /// Information about the impersonated user
    pub target_user: UserInfo,
    /// Information about the admin performing impersonation
    pub actor_user: UserInfo,
}

/// Basic user information
#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    pub is_platform_owner: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_name: Option<String>,
}

/// Mint a short-lived token acting as another user.
///
/// Platform owners may impersonate any user. TTL is 15 minutes and every
/// action is audited at HIGH severity with actor context, so the real principal
/// stays attributable.
pub async fn impersonate_user(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    impersonation_context: Option<Extension<ImpersonationContext>>,
    Json(request): Json<ImpersonateRequest>,
) -> crate::error::Result<AxumJson<ImpersonateResponse>> {
    let db = &state.db;
    let reason = validate_impersonation_request(&request.reason, impersonation_context.is_some())?;

    // Validate the target user exists and get their details
    let target_user = users_entity::Entity::find_by_id(request.user_id.clone())
        .filter(users_entity::Column::DeletedAt.is_null())
        .one(db)
        .await?
        .ok_or_else(|| AppError::NotFound("Target user not found".to_string()))?;

    // The route boundary already requires a platform-context token. Keep the
    // handler-level check as defense in depth so direct handler use cannot
    // create an impersonation token from an ordinary tenant session.
    if !crate::middleware::has_live_platform_authority(db, &auth_user).await? {
        return Err(AppError::Forbidden(
            "A current platform owner with MFA enrollment is required to impersonate users"
                .to_string(),
        ));
    }
    let impersonation_org: Option<crate::entities::organizations::Model> = None;

    // Get target user's organization and permission context
    let target_memberships = MembershipStore::list_by_user(DB::Conn(db), &target_user.id).await?;

    let (org_slug, service_slug) = if let Some(org) = impersonation_org.as_ref() {
        (Some(org.slug.clone()), None::<String>)
    } else if let Some(first_membership) = target_memberships.first() {
        let org = OrganizationStore::find_by_id(DB::Conn(db), &first_membership.org_id).await?;

        if let Some(org) = org {
            // Falls back to the target's first membership because the request
            // carries no org context; callers wanting a specific tenant must
            // pass one.
            (Some(org.slug), None::<String>)
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    // Create impersonation token with actual context
    let jwt_service = state.jwt_service.clone();
    let impersonation_token = jwt_service.create_impersonation_token(
        &target_user.id,
        &target_user.email,
        &auth_user.user.id,
        &auth_user.user.email,
        Some(reason),
        org_slug.as_deref(),     // Actual org context
        service_slug.as_deref(), // Service context (if available)
        target_user.is_platform_owner,
    )?;
    let token = impersonation_token.clone();
    let target_user_id = target_user.id.clone();
    let actor_user_id = auth_user.user.id.clone();
    let org_slug_for_session = org_slug.clone();
    let user_agent = auth_user.user_agent.clone();
    let ip_address = auth_user.ip_address.clone();
    let reason_for_audit = reason.to_string();
    let audit_actor = state.audit_actor.clone();
    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "create_impersonation_session",
        |transaction| {
            let token = token.clone();
            let target_user_id = target_user_id.clone();
            let actor_user_id = actor_user_id.clone();
            let org_slug = org_slug_for_session.clone();
            let user_agent = user_agent.clone();
            let ip_address = ip_address.clone();
            let reason = reason_for_audit.clone();
            let audit_actor = audit_actor.clone();
            let jwt_service = jwt_service.clone();
            Box::pin(async move {
                persist_impersonation_session(
                    transaction.clone(),
                    &jwt_service,
                    &token,
                    &target_user_id,
                    org_slug.as_deref(),
                    &user_agent,
                    &ip_address,
                )
                .await?;

                let metadata = json!({
                    "reason": reason,
                    "severity": "HIGH"
                });
                let audit_log = platform_audit_log::ActiveModel {
                    id: Set(Uuid::new_v4().to_string()),
                    platform_owner_id: Set(actor_user_id),
                    action: Set("user.impersonate".to_string()),
                    target_type: Set("user".to_string()),
                    target_id: Set(target_user_id),
                    metadata: Set(Some(metadata.to_string())),
                    created_at: Set(Utc::now().naive_utc()),
                };
                audit_actor
                    .log_platform_with_db(transaction, audit_log)
                    .await?;
                Ok(())
            })
        },
    )
    .await?;

    tracing::warn!(
        admin_user_id = %auth_user.user.id,
        target_user_id = %target_user.id,
        reason_recorded = !request.reason.is_empty(),
        "User impersonation initiated"
    );

    // Prepare response data with org context
    let (target_org_id, target_org_name) = if let Some(org) = impersonation_org {
        (Some(org.id), Some(org.name))
    } else if let Some(first_membership) = target_memberships.first() {
        if let Ok(Some(org)) =
            OrganizationStore::find_by_id(DB::Conn(db), &first_membership.org_id).await
        {
            (Some(org.id), Some(org.name))
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    let target_user_info = UserInfo {
        id: target_user.id.clone(),
        email: target_user.email.clone(),
        is_platform_owner: target_user.is_platform_owner,
        org_id: target_org_id,
        org_name: target_org_name,
    };

    let actor_user_info = UserInfo {
        id: auth_user.user.id.clone(),
        email: auth_user.user.email.clone(),
        is_platform_owner: auth_user.user.is_platform_owner,
        org_id: None, // Actor context not needed in response
        org_name: None,
    };

    Ok(AxumJson(ImpersonateResponse {
        token: impersonation_token,
        target_user: target_user_info,
        actor_user: actor_user_info,
    }))
}

fn validate_impersonation_request(reason: &str, nested: bool) -> crate::error::Result<&str> {
    // A support session must never mint a fresh impersonation token. Without
    // this boundary an impersonated platform owner could detach the original
    // actor context and extend the 15-minute lifetime.
    if nested {
        return Err(AppError::Forbidden(
            "Nested impersonation is not allowed".to_string(),
        ));
    }
    let reason = reason.trim();
    if reason.is_empty() || reason.chars().count() > 500 {
        return Err(AppError::BadRequest(
            "Impersonation reason must be between 1 and 500 characters".to_string(),
        ));
    }
    Ok(reason)
}

async fn persist_impersonation_session(
    db: DB<'_>,
    jwt_service: &JwtService,
    token: &str,
    target_user_id: &str,
    org_slug: Option<&str>,
    user_agent: &str,
    ip_address: &str,
) -> crate::error::Result<crate::entities::sessions::Model> {
    let claims = jwt_service.validate_impersonation_token(token)?;
    let expires_at = chrono::DateTime::from_timestamp(claims.exp, 0)
        .ok_or_else(|| AppError::InternalServerError("Invalid impersonation expiry".to_string()))?
        .naive_utc();

    // Impersonation is session-backed so logout, explicit session revocation,
    // target-user security actions, and expiry invalidate it immediately.
    SessionStore::create(
        db,
        target_user_id,
        &JwtService::hash_token(token),
        expires_at,
        None,
        None,
        org_slug,
        None,
        None,
        Some(user_agent),
        Some(ip_address),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;

    fn jwt_service() -> JwtService {
        let rsa = crate::rsa_keys::GeneratedKey::generate().expect("generate RSA key");
        JwtService::new(
            &STANDARD.encode(rsa.private_key_pem().expect("private PEM")),
            &STANDARD.encode(rsa.public_key_pem().expect("public PEM")),
            24,
            "impersonation-test-key",
            "https://auth.example.com",
        )
        .expect("create JWT service")
    }

    #[test]
    fn impersonation_request_rejects_nesting_and_requires_a_bounded_reason() {
        assert!(matches!(
            validate_impersonation_request("support", true),
            Err(AppError::Forbidden(message)) if message.contains("Nested")
        ));
        assert!(matches!(
            validate_impersonation_request("   ", false),
            Err(AppError::BadRequest(_))
        ));
        assert!(matches!(
            validate_impersonation_request(&"x".repeat(501), false),
            Err(AppError::BadRequest(_))
        ));
        assert_eq!(
            validate_impersonation_request("  support case  ", false).unwrap(),
            "support case"
        );
    }

    #[tokio::test]
    async fn impersonation_token_is_session_backed_and_revocable() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let target = crate::store::users::UserStore::create(
            DB::Conn(&db),
            "impersonated@example.com",
            None,
            false,
        )
        .await
        .expect("create target");
        let jwt = jwt_service();
        let token = jwt
            .create_impersonation_token(
                &target.id,
                &target.email,
                "actor-id",
                "actor@example.com",
                Some("support case"),
                Some("acme"),
                None,
                false,
            )
            .expect("create impersonation token");

        let session = persist_impersonation_session(
            DB::Conn(&db),
            &jwt,
            &token,
            &target.id,
            Some("acme"),
            "test-agent",
            "127.0.0.1",
        )
        .await
        .expect("persist impersonation session");
        assert_eq!(session.user_id, target.id);
        assert!(session.refresh_token_hash.is_none());
        let token_hash = JwtService::hash_token(&token);
        assert!(
            SessionStore::find_valid_by_token_hash(DB::Conn(&db), &token_hash)
                .await
                .expect("find session")
                .is_some()
        );

        SessionStore::delete_by_token_hash(DB::Conn(&db), &token_hash)
            .await
            .expect("revoke impersonation session");
        assert!(
            SessionStore::find_valid_by_token_hash(DB::Conn(&db), &token_hash)
                .await
                .expect("find revoked session")
                .is_none()
        );
    }
}
