use crate::db::transaction::with_retrying_transaction;
use crate::db::DB;
use crate::entities::{memberships, platform_audit_log};
use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use crate::state::AppState;
use crate::store::{
    memberships::MembershipStore, organizations::OrganizationStore,
    user_passkeys::UserPasskeysStore, users::UserStore,
};
use axum::{
    extract::{Path, State},
    Json,
};
use chrono::{DateTime, Utc};
use sea_orm::Set;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Deserialize)]
pub struct ForgetUserRequest {
    pub current_password: Option<String>,
    pub mfa_code: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ForgetUserResponse {
    pub success: bool,
    pub message: String,
    pub user_id: String,
}

async fn verify_self_delete_authorization(
    state: &AppState,
    user: &crate::entities::users::Model,
    req: &ForgetUserRequest,
) -> Result<()> {
    if let Some(code) = req
        .mfa_code
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let backup_event =
            crate::services::audit_builder::MfaAuditBuilder::new(&user.id, "backup_code_used")
                .success(true)
                .details(Some("context:self_anonymization"))
                .build();
        if crate::handlers::user::verify_mfa_code_with_backup_audit(
            &state.db,
            &user.id,
            code,
            (&state.audit_actor, backup_event),
        )
        .await?
        .is_some()
        {
            return Ok(());
        }
    }

    if let Some(password) = req
        .current_password
        .as_deref()
        .filter(|password| !password.is_empty())
    {
        let password_hash = user.password_hash.as_ref().ok_or_else(|| {
            AppError::BadRequest(
                "Password verification is not available for this account. Verify with MFA instead."
                    .to_string(),
            )
        })?;

        let is_valid = crate::crypto::concurrency::verify_password_bounded(
            password.to_string(),
            password_hash.clone(),
        )
        .await?;

        if is_valid {
            return Ok(());
        }
    }

    Err(AppError::Forbidden(
        "Confirm account deletion with your current password or MFA code".to_string(),
    ))
}

async fn require_platform_owner_or_owner_in_all_target_orgs(
    db: DB<'_>,
    requesting_user_id: &str,
    platform_token_context: bool,
    platform_mfa_verified: bool,
    target_user_id: &str,
    action: &str,
) -> Result<Vec<memberships::Model>> {
    let requesting_user = UserStore::find_by_id(db.clone(), requesting_user_id)
        .await?
        .filter(|user| user.deleted_at.is_none())
        .ok_or_else(|| AppError::Forbidden("Current user is no longer active".to_string()))?;
    let memberships = MembershipStore::list_by_user(db.clone(), target_user_id).await?;

    if crate::middleware::has_live_platform_authority_in(
        db.clone(),
        &requesting_user.id,
        platform_token_context,
        platform_mfa_verified,
    )
    .await?
    {
        return Ok(memberships);
    }

    if memberships.is_empty() {
        return Err(AppError::Forbidden(format!(
            "You do not have permission to {} this user's data",
            action
        )));
    }

    let owner_org_ids = MembershipStore::list_by_user(db.clone(), &requesting_user.id)
        .await?
        .into_iter()
        .filter(|membership| membership.role == "owner")
        .map(|membership| membership.org_id)
        .collect::<HashSet<_>>();

    for membership in &memberships {
        if !owner_org_ids.contains(&membership.org_id) {
            let org = OrganizationStore::find_by_id(db.clone(), &membership.org_id)
                .await?
                .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

            return Err(AppError::Forbidden(format!(
                "You must be an owner of organization '{}' to {} this user's data",
                org.slug, action
            )));
        }
    }

    Ok(memberships)
}

#[derive(Debug, Serialize)]
pub struct ExportUserDataResponse {
    pub user_id: String,
    pub email: String,
    pub created_at: String,
    pub memberships: Vec<MembershipExport>,
    pub login_events_count: i64,
    pub login_events: Vec<LoginEventExport>,
    pub oauth_identities: Vec<OAuthIdentityExport>,
    pub mfa_events: Vec<MfaEventExport>,
    pub passkeys: Vec<PasskeyExport>,
}

#[derive(Debug, Serialize)]
pub struct MembershipExport {
    pub organization_id: String,
    pub organization_slug: String,
    pub role: String,
    pub joined_at: String,
}

#[derive(Debug, Serialize)]
pub struct LoginEventExport {
    pub id: String,
    pub timestamp: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub provider: Option<String>,
    pub success: bool,
    pub risk_score: Option<i32>,
    pub risk_factors: Option<String>,
    pub geo_country: Option<String>,
    pub geo_city: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct OAuthIdentityExport {
    pub provider: String,
    pub provider_user_id: String,
    pub linked_at: String,
}

#[derive(Debug, Serialize)]
pub struct MfaEventExport {
    pub event_type: String,
    pub timestamp: String,
    pub success: bool,
    pub details: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PasskeyExport {
    pub id: String,
    pub name: Option<String>,
    pub aaguid: Option<String>,
    pub backup_eligible: bool,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

/// GDPR Right to be Forgotten - Anonymize user data
/// DELETE /api/privacy/forget/{user_id}
/// Requires: Organization owner permission for all organizations the user is a member of
pub async fn forget_user(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(user_id): Path<String>,
    payload: Option<Json<ForgetUserRequest>>,
) -> Result<Json<ForgetUserResponse>> {
    let requesting_user = &auth_user.user;

    let target_user = UserStore::find_by_id(DB::Conn(&state.db), &user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Prevent platform owners from being anonymized
    if target_user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owners cannot be anonymized".to_string(),
        ));
    }

    if requesting_user.id == user_id {
        let req = payload.map(|Json(req)| req).ok_or_else(|| {
            AppError::BadRequest(
                "Confirm account deletion with your current password or MFA code".to_string(),
            )
        })?;

        verify_self_delete_authorization(&state, &target_user, &req).await?;

        let memberships = MembershipStore::list_by_user(DB::Conn(&state.db), &user_id).await?;

        use crate::services::audit_builder::OrgAuditBuilder;
        let events = memberships
            .into_iter()
            .map(|membership| {
                OrgAuditBuilder::new(
                    &membership.org_id,
                    Some(&requesting_user.id),
                    "user.anonymized",
                )
                .target("user", &user_id)
                .success(true)
                .details_json(Some(serde_json::json!({
                    "reason": "Self-service GDPR Right to be Forgotten"
                })))
                .build()
            })
            .collect::<Vec<_>>();
        let platform_event = events.is_empty().then(|| platform_audit_log::ActiveModel {
            id: Set(uuid::Uuid::new_v4().to_string()),
            platform_owner_id: Set(requesting_user.id.clone()),
            action: Set("user.anonymized".to_string()),
            target_type: Set("user".to_string()),
            target_id: Set(user_id.clone()),
            metadata: Set(Some(
                serde_json::json!({
                    "reason": "Self-service GDPR Right to be Forgotten",
                    "actor_kind": "self",
                    "organization_count": 0,
                })
                .to_string(),
            )),
            ..Default::default()
        });
        with_retrying_transaction(
            &state.db,
            #[cfg(feature = "db_sqlite")]
            &state.db_writer,
            "self_anonymize_user_with_audit",
            |db| {
                let user_id = user_id.clone();
                let events = events.clone();
                let platform_event = platform_event.clone();
                let audit_actor = state.audit_actor.clone();
                Box::pin(async move {
                    UserStore::anonymize(db.clone(), &user_id).await?;
                    for event in events {
                        audit_actor.log_org_with_db(db.clone(), event).await?;
                    }
                    if let Some(event) = platform_event {
                        audit_actor.log_platform_with_db(db, event).await?;
                    }
                    Ok(())
                })
            },
        )
        .await?;

        state.user_cache.invalidate(&user_id).await;
        state.permission_cache.invalidate(&user_id).await;

        tracing::warn!(
            actor_id = %requesting_user.id,
            target_user_id = %user_id,
            "User anonymized their own account for GDPR compliance"
        );

        return Ok(Json(ForgetUserResponse {
            success: true,
            message:
                "Your account data has been anonymized. PII has been removed while preserving audit logs."
                    .to_string(),
            user_id,
        }));
    }

    require_platform_owner_or_owner_in_all_target_orgs(
        DB::Conn(&state.db),
        &requesting_user.id,
        auth_user.claims.is_platform_context(),
        auth_user.claims.mfa_verified == Some(true) || auth_user.claims.bootstrap == Some(true),
        &user_id,
        "anonymize",
    )
    .await?;

    let requesting_user_id = requesting_user.id.clone();
    let platform_token_context = auth_user.claims.is_platform_context();
    let platform_mfa_verified =
        auth_user.claims.mfa_verified == Some(true) || auth_user.claims.bootstrap == Some(true);
    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "admin_anonymize_user_with_audit",
        |db| {
            let user_id = user_id.clone();
            let requesting_user_id = requesting_user_id.clone();
            let audit_actor = state.audit_actor.clone();
            Box::pin(async move {
                // Recheck live authority inside the mutation transaction so a
                // cached platform-owner snapshot or concurrent demotion cannot
                // authorize cross-user anonymization.
                let memberships = require_platform_owner_or_owner_in_all_target_orgs(
                    db.clone(),
                    &requesting_user_id,
                    platform_token_context,
                    platform_mfa_verified,
                    &user_id,
                    "anonymize",
                )
                .await?;
                use crate::services::audit_builder::OrgAuditBuilder;
                let events = memberships
                    .into_iter()
                    .map(|membership| {
                        OrgAuditBuilder::new(
                            &membership.org_id,
                            Some(&requesting_user_id),
                            "user.anonymized",
                        )
                        .target("user", &user_id)
                        .success(true)
                        .details_json(Some(
                            serde_json::json!({"reason": "GDPR Right to be Forgotten"}),
                        ))
                        .build()
                    })
                    .collect::<Vec<_>>();
                let platform_event = events.is_empty().then(|| platform_audit_log::ActiveModel {
                    id: Set(uuid::Uuid::new_v4().to_string()),
                    platform_owner_id: Set(requesting_user_id.clone()),
                    action: Set("user.anonymized".to_string()),
                    target_type: Set("user".to_string()),
                    target_id: Set(user_id.clone()),
                    metadata: Set(Some(
                        serde_json::json!({
                            "reason": "GDPR Right to be Forgotten",
                            "actor_kind": "administrator",
                            "organization_count": 0,
                        })
                        .to_string(),
                    )),
                    ..Default::default()
                });
                UserStore::anonymize(db.clone(), &user_id).await?;
                for event in events {
                    audit_actor.log_org_with_db(db.clone(), event).await?;
                }
                if let Some(event) = platform_event {
                    audit_actor.log_platform_with_db(db, event).await?;
                }
                Ok(())
            })
        },
    )
    .await?;

    state.user_cache.invalidate(&user_id).await;
    state.permission_cache.invalidate(&user_id).await;

    tracing::warn!(
        actor_id = %requesting_user.id,
        target_user_id = %user_id,
        "User anonymized for GDPR compliance"
    );

    Ok(Json(ForgetUserResponse {
        success: true,
        message: "User data has been anonymized. PII has been removed while preserving audit logs."
            .to_string(),
        user_id,
    }))
}

/// GDPR Right to Access - Export user data
/// GET /api/privacy/export/{user_id}
/// Requires: User must be requesting their own data, be a platform owner, or
/// be an owner in every organization the target user belongs to.
pub async fn export_user_data(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(user_id): Path<String>,
) -> Result<Json<ExportUserDataResponse>> {
    let requesting_user = &auth_user.user;

    if requesting_user.id != user_id {
        require_platform_owner_or_owner_in_all_target_orgs(
            DB::Conn(&state.db),
            &requesting_user.id,
            auth_user.claims.is_platform_context(),
            auth_user.claims.mfa_verified == Some(true) || auth_user.claims.bootstrap == Some(true),
            &user_id,
            "export",
        )
        .await?;
    }

    let target_user = UserStore::find_by_id(DB::Conn(&state.db), &user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Platform-owner records contain global login and identity metadata. A
    // tenant owner must not be able to export them merely because the platform
    // owner is also a member of that tenant.
    if requesting_user.id != user_id
        && target_user.is_platform_owner
        && !crate::middleware::has_live_platform_authority(&state.db, &auth_user).await?
    {
        return Err(AppError::Forbidden(
            "Platform owner data can only be exported by a platform owner".to_string(),
        ));
    }

    // Get memberships with organization details
    let memberships = MembershipStore::list_by_user(DB::Conn(&state.db), &user_id).await?;
    let org_ids = memberships
        .iter()
        .map(|membership| membership.org_id.clone())
        .collect::<Vec<_>>();
    let organizations = OrganizationStore::find_by_ids(DB::Conn(&state.db), &org_ids)
        .await?
        .into_iter()
        .map(|org| (org.id.clone(), org))
        .collect::<HashMap<_, _>>();

    let mut membership_exports = Vec::new();
    for membership in memberships {
        if let Some(org) = organizations.get(&membership.org_id) {
            membership_exports.push(MembershipExport {
                organization_id: membership.org_id,
                organization_slug: org.slug.clone(),
                role: membership.role,
                joined_at: DateTime::<Utc>::from_naive_utc_and_offset(membership.created_at, Utc)
                    .to_rfc3339(),
            });
        }
    }

    // Get login events with details
    use crate::entities::prelude::{LoginEvents, MfaAuditLog};
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
    let login_events = LoginEvents::find()
        .filter(crate::entities::login_events::Column::UserId.eq(&user_id))
        .order_by_desc(crate::entities::login_events::Column::CreatedAt)
        .all(&state.db)
        .await?;

    let login_count = login_events.len() as i64;
    let mut login_event_exports = Vec::new();
    for event in login_events {
        login_event_exports.push(LoginEventExport {
            id: event.id,
            timestamp: DateTime::<Utc>::from_naive_utc_and_offset(event.created_at, Utc)
                .to_rfc3339(),
            ip_address: event.ip_address,
            user_agent: event.user_agent,
            provider: Some(event.provider),
            success: true, // login_events table only stores successful logins
            risk_score: event.risk_score,
            risk_factors: event.risk_factors,
            geo_country: event.geo_country,
            geo_city: event.geo_city,
        });
    }

    // Get OAuth identities
    use crate::entities::prelude::Identities;
    let identities = Identities::find()
        .filter(crate::entities::identities::Column::UserId.eq(&user_id))
        .all(&state.db)
        .await?;
    let mut identity_exports = Vec::new();
    for identity in identities {
        identity_exports.push(OAuthIdentityExport {
            provider: identity.provider,
            provider_user_id: identity.provider_user_id,
            linked_at: DateTime::<Utc>::from_naive_utc_and_offset(identity.created_at, Utc)
                .to_rfc3339(),
        });
    }

    let mfa_events = MfaAuditLog::find()
        .filter(crate::entities::mfa_audit_log::Column::UserId.eq(&user_id))
        .order_by_desc(crate::entities::mfa_audit_log::Column::CreatedAt)
        .all(&state.db)
        .await?;

    let mut mfa_event_exports = Vec::new();
    for event in mfa_events {
        mfa_event_exports.push(MfaEventExport {
            event_type: event.event_type,
            timestamp: DateTime::<Utc>::from_naive_utc_and_offset(event.created_at, Utc)
                .to_rfc3339(),
            success: event.success,
            details: event.details,
        });
    }

    // Get passkeys
    let passkeys = UserPasskeysStore::list_by_user(DB::Conn(&state.db), &user_id).await?;
    let mut passkey_exports = Vec::new();
    for passkey in passkeys {
        passkey_exports.push(PasskeyExport {
            id: passkey.id,
            name: Some(passkey.name),
            aaguid: passkey.aaguid,
            backup_eligible: passkey.backup_eligible,
            created_at: DateTime::<Utc>::from_naive_utc_and_offset(passkey.created_at, Utc)
                .to_rfc3339(),
            last_used_at: passkey
                .last_used_at
                .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc).to_rfc3339()),
        });
    }

    tracing::info!(
        actor_id = %requesting_user.id,
        target_user_id = %user_id,
        login_events = login_count,
        identities = identity_exports.len(),
        mfa_events = mfa_event_exports.len(),
        passkeys = passkey_exports.len(),
        "User data exported for GDPR compliance"
    );

    Ok(Json(ExportUserDataResponse {
        user_id: target_user.id,
        email: target_user.email,
        created_at: DateTime::<Utc>::from_naive_utc_and_offset(target_user.created_at, Utc)
            .to_rfc3339(),
        memberships: membership_exports,
        login_events_count: login_count,
        login_events: login_event_exports,
        oauth_identities: identity_exports,
        mfa_events: mfa_event_exports,
        passkeys: passkey_exports,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::{prelude::UserTotpSecrets, user_totp_secrets};
    use migration::{Migrator, MigratorTrait};
    use sea_orm::{Database, EntityTrait, Set};

    async fn enroll_test_mfa(db: &sea_orm::DatabaseConnection, user_id: &str) {
        UserTotpSecrets::insert(user_totp_secrets::ActiveModel {
            id: Set(format!("totp-{user_id}")),
            user_id: Set(user_id.to_string()),
            secret_encrypted: Set(vec![]),
            encryption_key_id: Set("test-key".to_string()),
            enabled: Set(true),
            created_at: Set(Utc::now().naive_utc()),
            enabled_at: Set(Some(Utc::now().naive_utc())),
        })
        .exec(db)
        .await
        .expect("enroll test MFA");
    }

    #[tokio::test]
    async fn demoted_cached_platform_owner_cannot_authorize_cross_user_privacy_action() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let actor = UserStore::create(DB::Conn(&db), "privacy-owner@example.com", None, true)
            .await
            .expect("create platform owner");
        let stale_actor = actor.clone();
        enroll_test_mfa(&db, &actor.id).await;
        let target = UserStore::create(DB::Conn(&db), "privacy-target@example.com", None, false)
            .await
            .expect("create target");

        require_platform_owner_or_owner_in_all_target_orgs(
            DB::Conn(&db),
            &actor.id,
            true,
            true,
            &target.id,
            "export",
        )
        .await
        .expect("current platform owner may export");

        UserStore::set_platform_owner(DB::Conn(&db), &actor.id, false)
            .await
            .expect("demote platform owner");
        assert!(
            stale_actor.is_platform_owner,
            "cached snapshot remains stale"
        );
        assert!(matches!(
            require_platform_owner_or_owner_in_all_target_orgs(
                DB::Conn(&db),
                &actor.id,
                true,
                true,
                &target.id,
                "export",
            )
            .await,
            Err(AppError::Forbidden(_))
        ));

        let unchanged = UserStore::find_by_id(DB::Conn(&db), &target.id)
            .await
            .expect("load target")
            .expect("target remains");
        assert_eq!(unchanged.email, target.email);
        assert!(unchanged.deleted_at.is_none());
    }
}

#[cfg(test)]
mod privacy_route_tests {
    use super::*;

    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::crypto::sso::OAuthClient;

    use crate::entities::{prelude::UserTotpSecrets, user_totp_secrets, users};
    use crate::middleware::AuthUser;

    use crate::audit::actor::AuditHandle;
    use crate::db::DB;
    use crate::services::{
        events::EventDispatcher, metrics::MfaMetricsService, risk_engine::RiskEngine,
    };
    use crate::state::AppState;
    use crate::store::{
        memberships::MembershipStore,
        organizations::OrganizationStore,
        users::{UserCreationOptions, UserStore},
    };
    use axum::extract::Path;

    use migration::{Migrator, MigratorTrait};
    use moka::future::Cache;
    use sea_orm::{Database, EntityTrait, Set};
    use std::sync::Arc;

    use crate::test_support::test_jwt_service;

    use crate::test_support::test_config;

    struct Fixture {
        state: AppState,
        platform: AuthUser,
        plain: AuthUser,
        plain_id: String,
        member_of_other_org: AuthUser,
        outsider: AuthUser,
    }

    async fn fixture() -> Fixture {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let config = test_config();
        let jwt_service = Arc::new(test_jwt_service(&config));

        let platform_model = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "privacy-platform@example.test",
            UserCreationOptions {
                is_platform_owner: true,
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create platform owner")
        .0;
        UserTotpSecrets::insert(user_totp_secrets::ActiveModel {
            id: Set("privacy-platform-totp".to_string()),
            user_id: Set(platform_model.id.clone()),
            secret_encrypted: Set(vec![]),
            encryption_key_id: Set("test-key".to_string()),
            enabled: Set(true),
            created_at: Set(Utc::now().naive_utc()),
            enabled_at: Set(Some(Utc::now().naive_utc())),
        })
        .exec(&db)
        .await
        .expect("enroll platform MFA");

        let plain_model =
            UserStore::create(DB::Conn(&db), "privacy-plain@example.test", None, false)
                .await
                .expect("create plain user");
        let member_model =
            UserStore::create(DB::Conn(&db), "privacy-member@example.test", None, false)
                .await
                .expect("create member");
        let outsider_model =
            UserStore::create(DB::Conn(&db), "privacy-outsider@example.test", None, false)
                .await
                .expect("create outsider");

        // The member owns an org; the plain user is a member of it.
        let (org, _) = OrganizationStore::create_with_owner(
            DB::Conn(&db),
            "acme",
            "Acme",
            &member_model.id,
            None,
        )
        .await
        .expect("create org owned by member");
        MembershipStore::create(DB::Conn(&db), &org.id, &plain_model.id, "member")
            .await
            .expect("add plain user to org");

        let state = AppState {
            db: db.clone(),
            #[cfg(feature = "db_sqlite")]
            db_writer: db.clone(),
            oauth_client: Arc::new(OAuthClient::new(&config).expect("oauth client")),
            jwt_service: jwt_service.clone(),
            base_url: config.base_url.clone(),
            web_client_url: config.platform_dashboard_base_url.clone(),
            full_web_client_url: config.full_web_client_base_url.clone(),
            encryption: None,
            email_service: None,
            metrics_service: Arc::new(MfaMetricsService::new(db.clone())),
            event_dispatcher: Arc::new(EventDispatcher::new(db.clone())),
            billing_provider: Arc::new(DisabledBillingProvider::new()),
            risk_engine: Arc::new(RiskEngine::new().expect("risk engine")),
            webauthn_service: None,
            permission_cache: Cache::new(10_000),
            user_cache: Cache::new(10_000),
            domain_cache: Cache::new(10_000),
            audit_actor: AuditHandle::new(db.clone()),
            config,
        };

        let auth_user_for = |user: &users::Model| -> AuthUser {
            let token = if user.is_platform_owner {
                jwt_service
                    .create_mfa_verified_token(&user.id, &user.email, true, None, None)
                    .expect("platform token")
            } else {
                jwt_service
                    .create_token(&user.id, &user.email, false, None, None)
                    .expect("token")
            };
            AuthUser {
                claims: jwt_service.validate_token(&token).expect("claims"),
                user: user.clone(),
                permissions: vec![],
                ip_address: "127.0.0.1".to_string(),
                user_agent: "privacy-route-test".to_string(),
                current_session_id: None,
            }
        };

        let outsider = auth_user_for(&outsider_model);
        Fixture {
            state,
            platform: auth_user_for(&platform_model),
            plain: auth_user_for(&plain_model),
            plain_id: plain_model.id.clone(),
            member_of_other_org: auth_user_for(&member_model),
            outsider,
        }
    }

    #[tokio::test]
    async fn export_returns_the_requesters_own_data() {
        let f = fixture().await;
        let Json(exported) = export_user_data(
            State(f.state.clone()),
            f.plain.clone(),
            Path(f.plain_id.clone()),
        )
        .await
        .expect("export own data");
        assert_eq!(exported.email, "privacy-plain@example.test");
    }

    #[tokio::test]
    async fn export_by_an_org_owner_covers_the_target_but_only_while_they_own_every_org() {
        let f = fixture().await;

        // The member owns `acme`, the target's only organization, so they are
        // authorised under "owner in all target orgs".
        let Json(owned_export) = export_user_data(
            State(f.state.clone()),
            f.member_of_other_org.clone(),
            Path(f.plain_id.clone()),
        )
        .await
        .expect("org owner may export");
        assert_eq!(owned_export.email, "privacy-plain@example.test");

        // A completely unrelated user is refused.
        match export_user_data(
            State(f.state.clone()),
            f.outsider.clone(),
            Path(f.plain_id.clone()),
        )
        .await
        {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected forbidden for outsider, got {other:?}"),
        }

        // The platform owner may always export.
        let Json(exported) = export_user_data(
            State(f.state.clone()),
            f.platform.clone(),
            Path(f.plain_id.clone()),
        )
        .await
        .expect("platform export");
        assert_eq!(exported.email, "privacy-plain@example.test");
    }

    #[tokio::test]
    async fn tenant_owner_cannot_export_a_platform_owner_member() {
        let fixture = fixture().await;
        let org = OrganizationStore::find_by_slug(DB::Conn(&fixture.state.db), "acme")
            .await
            .expect("load org")
            .expect("org exists");
        MembershipStore::create(
            DB::Conn(&fixture.state.db),
            &org.id,
            &fixture.platform.user.id,
            "member",
        )
        .await
        .expect("add platform owner to tenant");

        match export_user_data(
            State(fixture.state.clone()),
            fixture.member_of_other_org.clone(),
            Path(fixture.platform.user.id.clone()),
        )
        .await
        {
            Err(AppError::Forbidden(message)) => {
                assert!(message.contains("Platform owner"))
            }
            other => panic!("expected platform-owner export refusal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn forgetting_a_platform_owner_is_refused() {
        let f = fixture().await;
        match forget_user(
            State(f.state.clone()),
            f.platform.clone(),
            Path(f.platform.user.id.clone()),
            None,
        )
        .await
        {
            Err(AppError::Forbidden(message)) => {
                assert!(message.contains("Platform owners cannot"))
            }
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn forget_user_by_outsider_is_refused_and_preserves_target() {
        let f = fixture().await;
        match forget_user(
            State(f.state.clone()),
            f.outsider.clone(),
            Path(f.plain_id.clone()),
            None,
        )
        .await
        {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected outsider forget refusal, got {other:?}"),
        }
        let unchanged = UserStore::find_by_id(DB::Conn(&f.state.db), &f.plain_id)
            .await
            .expect("load target")
            .expect("target remains");
        assert_eq!(unchanged.email, "privacy-plain@example.test");
        assert!(unchanged.deleted_at.is_none());
    }

    #[tokio::test]
    async fn forget_user_by_owner_of_all_target_orgs_anonymizes() {
        let f = fixture().await;
        let Json(response) = forget_user(
            State(f.state.clone()),
            f.member_of_other_org.clone(),
            Path(f.plain_id.clone()),
            None,
        )
        .await
        .expect("owner of every target organization may anonymize");
        assert!(response.success);
        let anonymized = UserStore::find_by_id(DB::Conn(&f.state.db), &f.plain_id)
            .await
            .expect("load target")
            .expect("target remains");
        assert_ne!(anonymized.email, "privacy-plain@example.test");
        assert!(anonymized.deleted_at.is_some());
        assert!(anonymized.password_hash.is_none());
    }

    #[tokio::test]
    async fn forget_user_by_platform_owner_anonymizes() {
        let f = fixture().await;
        let Json(response) = forget_user(
            State(f.state.clone()),
            f.platform.clone(),
            Path(f.plain_id.clone()),
            None,
        )
        .await
        .expect("platform owner may anonymize");
        assert!(response.success);
        let anonymized = UserStore::find_by_id(DB::Conn(&f.state.db), &f.plain_id)
            .await
            .expect("load target")
            .expect("target remains");
        assert_ne!(anonymized.email, "privacy-plain@example.test");
        assert!(anonymized.deleted_at.is_some());
    }

    #[tokio::test]
    async fn forget_user_cross_tenant_owner_is_refused_and_preserves_target() {
        let f = fixture().await;
        let foreign = UserStore::create(
            DB::Conn(&f.state.db),
            "privacy-foreign@example.test",
            None,
            false,
        )
        .await
        .expect("create foreign target");
        let (beta, _) = OrganizationStore::create_with_owner(
            DB::Conn(&f.state.db),
            "privacy-beta",
            "Privacy Beta",
            &f.outsider.user.id,
            None,
        )
        .await
        .expect("create beta organization");
        OrganizationStore::update_status(DB::Conn(&f.state.db), &beta.id, "active")
            .await
            .expect("activate beta");
        MembershipStore::create(DB::Conn(&f.state.db), &beta.id, &foreign.id, "member")
            .await
            .expect("add foreign membership");

        match forget_user(
            State(f.state.clone()),
            f.member_of_other_org.clone(),
            Path(foreign.id.clone()),
            None,
        )
        .await
        {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected cross-tenant forget refusal, got {other:?}"),
        }
        let unchanged = UserStore::find_by_id(DB::Conn(&f.state.db), &foreign.id)
            .await
            .expect("load foreign target")
            .expect("foreign target remains");
        assert_eq!(unchanged.email, "privacy-foreign@example.test");
        assert!(unchanged.deleted_at.is_none());
    }

    #[tokio::test]
    async fn shared_user_multi_org_export_and_forget_require_owner_of_every_membership() {
        let f = fixture().await;
        let (beta, _) = OrganizationStore::create_with_owner(
            DB::Conn(&f.state.db),
            "privacy-beta",
            "Privacy Beta",
            &f.outsider.user.id,
            None,
        )
        .await
        .expect("create beta organization");
        OrganizationStore::update_status(DB::Conn(&f.state.db), &beta.id, "active")
            .await
            .expect("activate beta");
        MembershipStore::create(DB::Conn(&f.state.db), &beta.id, &f.plain_id, "member")
            .await
            .expect("add shared user to beta");

        // The owner of only one of the target's organizations cannot export or
        // anonymize the shared user.
        for auth in [f.member_of_other_org.clone(), f.outsider.clone()] {
            assert!(matches!(
                export_user_data(
                    State(f.state.clone()),
                    auth.clone(),
                    Path(f.plain_id.clone()),
                )
                .await,
                Err(AppError::Forbidden(_))
            ));
            assert!(matches!(
                forget_user(State(f.state.clone()), auth, Path(f.plain_id.clone()), None,).await,
                Err(AppError::Forbidden(_))
            ));
        }
        let unchanged = UserStore::find_by_id(DB::Conn(&f.state.db), &f.plain_id)
            .await
            .expect("load shared target")
            .expect("shared target remains");
        assert_eq!(unchanged.email, "privacy-plain@example.test");
        assert!(unchanged.deleted_at.is_none());

        // A live platform owner may export and then anonymize the shared user.
        let Json(exported) = export_user_data(
            State(f.state.clone()),
            f.platform.clone(),
            Path(f.plain_id.clone()),
        )
        .await
        .expect("platform owner may export shared user");
        assert_eq!(exported.memberships.len(), 2);
        let Json(response) = forget_user(
            State(f.state.clone()),
            f.platform.clone(),
            Path(f.plain_id.clone()),
            None,
        )
        .await
        .expect("platform owner may anonymize shared user");
        assert!(response.success);
        let anonymized = UserStore::find_by_id(DB::Conn(&f.state.db), &f.plain_id)
            .await
            .expect("load anonymized shared target")
            .expect("anonymized target remains");
        assert!(anonymized.deleted_at.is_some());
    }

    #[tokio::test]
    async fn self_service_forget_requires_confirmation_payload() {
        let f = fixture().await;
        match forget_user(
            State(f.state.clone()),
            f.plain.clone(),
            Path(f.plain_id.clone()),
            None,
        )
        .await
        {
            Err(AppError::BadRequest(message)) => {
                assert!(message.contains("Confirm account deletion"))
            }
            other => panic!("expected confirmation demand, got {other:?}"),
        }
    }
}
