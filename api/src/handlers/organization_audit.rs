//! Audit log endpoints for organizations

use crate::db::models::OrganizationAuditLogWithUser;
use crate::db::DB;
use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use crate::services::audit::OrganizationAuditService;
use crate::services::permission_service::{PermissionService, CAP_AUDIT_LOGS_VIEW};
use crate::state::AppState;
use crate::store::organizations::OrganizationStore;
use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};

async fn require_org_audit_admin(
    db: &sea_orm::DatabaseConnection,
    user_id: &str,
    org_slug: &str,
) -> Result<crate::entities::organizations::Model> {
    let organization = OrganizationStore::find_by_slug(DB::Conn(db), org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
    let organization =
        crate::handlers::organizations::ensure_organization_active(db, &organization.id).await?;
    if !PermissionService::check(DB::Conn(db), &organization.id, user_id, CAP_AUDIT_LOGS_VIEW)
        .await?
    {
        return Err(AppError::Forbidden(
            "Insufficient permissions to view organization audit logs".to_string(),
        ));
    }
    Ok(organization)
}

#[derive(Debug, Deserialize)]
pub struct AuditLogQuery {
    pub page: Option<i64>,
    pub limit: Option<i64>,
    pub action: Option<String>,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuditLogEntry {
    pub id: String,
    #[serde(rename = "organization_id")]
    pub org_id: String,
    #[serde(rename = "actor_id")]
    pub actor_user_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<ActorInfo>,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct ActorInfo {
    pub id: String,
    pub email: String,
}

fn audit_metadata_key_is_sensitive(key: &str) -> bool {
    // Split separators and camelCase so `client_secret_value`,
    // `clientSecretValue`, and `Client.Secret.Value` have the same policy.
    let mut canonical = String::with_capacity(key.len() + 4);
    let mut previous_was_lower_or_digit = false;
    for character in key.chars() {
        if character.is_ascii_alphanumeric() {
            if character.is_ascii_uppercase() && previous_was_lower_or_digit {
                canonical.push('_');
            }
            canonical.push(character.to_ascii_lowercase());
            previous_was_lower_or_digit =
                character.is_ascii_lowercase() || character.is_ascii_digit();
        } else {
            canonical.push('_');
            previous_was_lower_or_digit = false;
        }
    }
    let tokens = canonical
        .split('_')
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();

    let has_sensitive_token = tokens.iter().any(|token| {
        matches!(
            *token,
            "password"
                | "passwd"
                | "passphrase"
                | "secret"
                | "token"
                | "authorization"
                | "cookie"
                | "credential"
                | "credentials"
                | "otp"
                | "apikey"
                | "privatekey"
                | "authheader"
                | "setcookie"
                | "backupcode"
                | "backupcodes"
                | "recoverycode"
                | "recoverycodes"
        )
    }) || tokens.windows(2).any(|pair| {
        matches!(
            pair,
            ["api", "key"]
                | ["private", "key"]
                | ["auth", "header"]
                | ["backup", "code"]
                | ["backup", "codes"]
                | ["recovery", "code"]
                | ["recovery", "codes"]
        )
    });

    if !has_sensitive_token {
        return false;
    }

    // Identifiers and non-secret descriptors are useful audit evidence and do
    // not contain credential material. Keep the allowlist deliberately narrow.
    !matches!(
        tokens.last().copied(),
        Some("id" | "type" | "count" | "prefix" | "status")
    ) && !matches!(
        tokens.as_slice(),
        [.., "expires", "at"] | [.., "expired", "at"]
    )
}

pub(crate) fn redact_audit_metadata(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(values) => serde_json::Value::Object(
            values
                .into_iter()
                .map(|(key, value)| {
                    if audit_metadata_key_is_sensitive(&key) {
                        (key, serde_json::Value::String("[REDACTED]".to_string()))
                    } else {
                        (key, redact_audit_metadata(value))
                    }
                })
                .collect(),
        ),
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(redact_audit_metadata).collect())
        }
        value => value,
    }
}

impl From<OrganizationAuditLogWithUser> for AuditLogEntry {
    fn from(log: OrganizationAuditLogWithUser) -> Self {
        let actor = log.actor_user_email.as_ref().map(|email| ActorInfo {
            id: log.actor_user_id.clone(),
            email: email.clone(),
        });

        let metadata = log
            .details
            .as_ref()
            .and_then(|d| serde_json::from_str(d).ok())
            .map(redact_audit_metadata);

        Self {
            id: log.id,
            org_id: log.org_id,
            actor_user_id: log.actor_user_id,
            actor,
            action: log.action,
            target_type: log.target_type,
            target_id: log.target_id,
            ip_address: log.ip_address,
            user_agent: log.user_agent,
            success: log.success,
            metadata,
            created_at: log.created_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AuditLogResponse {
    pub logs: Vec<AuditLogEntry>,
    pub pagination: PaginationInfo,
}

#[derive(Debug, Serialize)]
pub struct PaginationInfo {
    pub page: i64,
    pub limit: i64,
    pub total: i64,
    pub total_pages: i64,
    pub has_next: bool,
    pub has_prev: bool,
}

/// Get audit logs for an organization (owner/admin only)
pub async fn get_organization_audit_logs(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
    Query(query): Query<AuditLogQuery>,
) -> Result<Json<AuditLogResponse>> {
    let organization = require_org_audit_admin(&state.db, &auth_user.user.id, &org_slug).await?;

    // Set default pagination values
    let (page, limit, offset) =
        crate::utils::pagination::signed_page(query.page, query.limit, 50, 100);

    let audit_service = OrganizationAuditService::new(state.db.clone());

    // Get audit logs with optional filtering
    let logs = if let Some(ref action) = query.action {
        audit_service
            .get_audit_logs_by_action(&organization.id, action, limit, offset)
            .await?
    } else if let (Some(target_type), Some(target_id)) =
        (query.target_type.as_ref(), query.target_id.as_ref())
    {
        audit_service
            .get_target_audit_logs(&organization.id, target_type, target_id, limit, offset)
            .await?
    } else {
        audit_service
            .get_organization_audit_logs(&organization.id, limit, offset)
            .await?
    };

    // Get total count for pagination
    let total = audit_service
        .get_audit_log_count_filtered(
            &organization.id,
            query.action.as_deref(),
            query.target_type.as_deref(),
            query.target_id.as_deref(),
        )
        .await?;
    let total_pages = (total + limit - 1) / limit; // Ceiling division

    let pagination = PaginationInfo {
        page,
        limit,
        total,
        total_pages,
        has_next: page < total_pages,
        has_prev: page > 1,
    };

    let log_entries: Vec<AuditLogEntry> = logs.into_iter().map(std::convert::Into::into).collect();
    Ok(Json(AuditLogResponse {
        logs: log_entries,
        pagination,
    }))
}

/// Get available audit event types for filtering
pub async fn get_audit_event_types(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
) -> Result<Json<Vec<EventTypeInfo>>> {
    // Although the values are static today, keep this audit route behind the
    // same tenant authorization boundary as the log data. This prevents a
    // future dynamic event catalog from silently becoming cross-tenant.
    require_org_audit_admin(&state.db, &auth_user.user.id, &org_slug).await?;

    let event_types = vec![
        EventTypeInfo {
            value: "user.invited".to_string(),
            label: "User Invited".to_string(),
            category: "User Management".to_string(),
        },
        EventTypeInfo {
            value: "user.joined".to_string(),
            label: "User Joined".to_string(),
            category: "User Management".to_string(),
        },
        EventTypeInfo {
            value: "user.removed".to_string(),
            label: "User Removed".to_string(),
            category: "User Management".to_string(),
        },
        EventTypeInfo {
            value: "user.role_updated".to_string(),
            label: "User Role Updated".to_string(),
            category: "User Management".to_string(),
        },
        EventTypeInfo {
            value: "service.created".to_string(),
            label: "Service Created".to_string(),
            category: "Service Management".to_string(),
        },
        EventTypeInfo {
            value: "service.updated".to_string(),
            label: "Service Updated".to_string(),
            category: "Service Management".to_string(),
        },
        EventTypeInfo {
            value: "service.deleted".to_string(),
            label: "Service Deleted".to_string(),
            category: "Service Management".to_string(),
        },
        EventTypeInfo {
            value: "service.oauth_credentials.updated".to_string(),
            label: "Service OAuth Credentials Updated".to_string(),
            category: "Service Management".to_string(),
        },
        EventTypeInfo {
            value: "organization.updated".to_string(),
            label: "Organization Updated".to_string(),
            category: "Organization Management".to_string(),
        },
        EventTypeInfo {
            value: "organization.smtp.configured".to_string(),
            label: "Organization SMTP Configured".to_string(),
            category: "Organization Management".to_string(),
        },
        EventTypeInfo {
            value: "organization.smtp.removed".to_string(),
            label: "Organization SMTP Removed".to_string(),
            category: "Organization Management".to_string(),
        },
        EventTypeInfo {
            value: "plan.created".to_string(),
            label: "Plan Created".to_string(),
            category: "Plan Management".to_string(),
        },
        EventTypeInfo {
            value: "plan.updated".to_string(),
            label: "Plan Updated".to_string(),
            category: "Plan Management".to_string(),
        },
        EventTypeInfo {
            value: "plan.deleted".to_string(),
            label: "Plan Deleted".to_string(),
            category: "Plan Management".to_string(),
        },
        EventTypeInfo {
            value: "subscription.created".to_string(),
            label: "Subscription Created".to_string(),
            category: "Subscription Management".to_string(),
        },
        EventTypeInfo {
            value: "subscription.updated".to_string(),
            label: "Subscription Updated".to_string(),
            category: "Subscription Management".to_string(),
        },
        EventTypeInfo {
            value: "subscription.canceled".to_string(),
            label: "Subscription Canceled".to_string(),
            category: "Subscription Management".to_string(),
        },
        EventTypeInfo {
            value: "invitation.accepted".to_string(),
            label: "Invitation Accepted".to_string(),
            category: "Invitation Management".to_string(),
        },
        EventTypeInfo {
            value: "invitation.declined".to_string(),
            label: "Invitation Declined".to_string(),
            category: "Invitation Management".to_string(),
        },
        EventTypeInfo {
            value: "invitation.expired".to_string(),
            label: "Invitation Expired".to_string(),
            category: "Invitation Management".to_string(),
        },
        EventTypeInfo {
            value: "invitation.revoked".to_string(),
            label: "Invitation Revoked".to_string(),
            category: "Invitation Management".to_string(),
        },
        EventTypeInfo {
            value: "security.mfa.enabled".to_string(),
            label: "MFA Enabled".to_string(),
            category: "Security".to_string(),
        },
        EventTypeInfo {
            value: "security.mfa.disabled".to_string(),
            label: "MFA Disabled".to_string(),
            category: "Security".to_string(),
        },
        EventTypeInfo {
            value: "security.password.changed".to_string(),
            label: "Password Changed".to_string(),
            category: "Security".to_string(),
        },
    ];

    Ok(Json(event_types))
}

#[derive(Debug, Serialize)]
pub struct EventTypeInfo {
    pub value: String,
    pub label: String,
    pub category: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{
        memberships::MembershipStore,
        organization_roles::OrganizationRoleStore,
        organizations::OrganizationStore,
        users::{UserCreationOptions, UserStore},
    };
    use migration::{Migrator, MigratorTrait};
    use sea_orm::{ColumnTrait, Database, EntityTrait, PaginatorTrait, QueryFilter};

    #[test]
    fn audit_metadata_recursively_redacts_credentials_but_preserves_identifiers() {
        let stored_details = serde_json::json!({
            "token_id": "safe-token-id",
            "key_id": "safe-key-id",
            "api_key_id": "safe-api-key-id",
            "token_type": "Bearer",
            "token_expires_at": "2030-01-01T00:00:00Z",
            "secretary": "not-a-secret-key-name",
            "tokenization_strategy": "wordpiece",
            "client_secret": "client-secret-canary",
            "client_secret_value": "secret-value-canary",
            "refreshTokenValue": "refresh-value-canary",
            "passphrase": "passphrase-canary",
            "credentials": "credentials-canary",
            "Client.Secret": "separator-canary",
            "nested": [{
                "api-key": "api-key-canary",
                "APIKey": "acronym-api-key-canary",
                "privateKey": "private-key-canary",
                "authorization": "authorization-canary",
                "backup_codes": "backup-code-canary",
                "password_hash": "password-hash-canary",
                "domain_verification_token": "domain-token-canary",
                "status": "active"
            }]
        })
        .to_string();
        let entry = AuditLogEntry::from(OrganizationAuditLogWithUser {
            id: "audit-redaction".to_string(),
            org_id: "org-a".to_string(),
            actor_user_id: "actor-a".to_string(),
            actor_user_email: Some("actor@example.com".to_string()),
            action: "integration.updated".to_string(),
            target_type: "integration".to_string(),
            target_id: "integration-a".to_string(),
            ip_address: None,
            user_agent: None,
            success: true,
            details: Some(stored_details.clone()),
            created_at: chrono::Utc::now(),
        });

        let metadata = entry.metadata.expect("parsed audit metadata");
        assert_eq!(metadata["token_id"], "safe-token-id");
        assert_eq!(metadata["key_id"], "safe-key-id");
        assert_eq!(metadata["api_key_id"], "safe-api-key-id");
        assert_eq!(metadata["token_type"], "Bearer");
        assert_eq!(metadata["token_expires_at"], "2030-01-01T00:00:00Z");
        assert_eq!(metadata["secretary"], "not-a-secret-key-name");
        assert_eq!(metadata["tokenization_strategy"], "wordpiece");
        assert_eq!(metadata["nested"][0]["status"], "active");
        for pointer in [
            "/client_secret",
            "/client_secret_value",
            "/refreshTokenValue",
            "/passphrase",
            "/credentials",
            "/Client.Secret",
            "/nested/0/api-key",
            "/nested/0/APIKey",
            "/nested/0/privateKey",
            "/nested/0/authorization",
            "/nested/0/backup_codes",
            "/nested/0/password_hash",
            "/nested/0/domain_verification_token",
        ] {
            assert_eq!(
                metadata.pointer(pointer),
                Some(&serde_json::json!("[REDACTED]"))
            );
        }
        let serialized = metadata.to_string();
        for canary in [
            "client-secret-canary",
            "secret-value-canary",
            "refresh-value-canary",
            "passphrase-canary",
            "credentials-canary",
            "separator-canary",
            "api-key-canary",
            "acronym-api-key-canary",
            "private-key-canary",
            "authorization-canary",
            "backup-code-canary",
            "password-hash-canary",
            "domain-token-canary",
        ] {
            assert!(!serialized.contains(canary));
            assert!(stored_details.contains(canary));
        }
    }

    #[tokio::test]
    async fn audit_route_authority_is_bound_to_selected_organization() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let audit_reconciler = crate::audit::actor::AuditHandle::new(db.clone());
        let owner_a = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "audit-owner-a@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create owner A")
        .0;
        let owner_b = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "audit-owner-b@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create owner B")
        .0;
        let org_a = OrganizationStore::create(
            DB::Conn(&db),
            "audit-org-a",
            "Audit Org A",
            &owner_a.id,
            None,
        )
        .await
        .expect("create org A");
        OrganizationStore::update_status(DB::Conn(&db), &org_a.id, "active")
            .await
            .expect("activate org A");
        let owner_membership =
            MembershipStore::create(DB::Conn(&db), &org_a.id, &owner_a.id, "owner")
                .await
                .expect("create owner membership");
        let org_b = OrganizationStore::create(
            DB::Conn(&db),
            "audit-org-b",
            "Audit Org B",
            &owner_b.id,
            None,
        )
        .await
        .expect("create org B");
        OrganizationStore::update_status(DB::Conn(&db), &org_b.id, "active")
            .await
            .expect("activate org B");

        assert_eq!(
            require_org_audit_admin(&db, &owner_a.id, &org_a.slug)
                .await
                .expect("owner can access own audit scope")
                .id,
            org_a.id
        );
        OrganizationStore::update_status(DB::Conn(&db), &org_a.id, "suspended")
            .await
            .expect("suspend org A");
        assert!(matches!(
            require_org_audit_admin(&db, &owner_a.id, &org_a.slug).await,
            Err(AppError::Forbidden(_))
        ));
        OrganizationStore::update_status(DB::Conn(&db), &org_a.id, "active")
            .await
            .expect("reactivate org A");
        assert!(matches!(
            require_org_audit_admin(&db, &owner_a.id, "audit-org-b").await,
            Err(AppError::Forbidden(_))
        ));
        assert!(matches!(
            require_org_audit_admin(&db, &owner_a.id, "missing-org").await,
            Err(AppError::NotFound(_))
        ));

        let audit_service = OrganizationAuditService::new(db.clone());
        audit_service
            .log_org_event(
                &org_a.id,
                Some(&owner_a.id),
                crate::services::audit::OrgAuditEvent::MemberAdded,
                Some("user"),
                Some("shared-target-id"),
                None,
                None,
                true,
                None,
            )
            .await
            .expect("write org A audit row");
        audit_service
            .log_org_event(
                &org_b.id,
                Some(&owner_b.id),
                crate::services::audit::OrgAuditEvent::MemberAdded,
                Some("user"),
                Some("shared-target-id"),
                None,
                None,
                true,
                None,
            )
            .await
            .expect("write org B audit row");
        audit_service
            .log_org_event(
                &org_a.id,
                Some(&owner_a.id),
                crate::services::audit::OrgAuditEvent::ServiceCreated,
                Some("user"),
                Some("shared-target-id"),
                None,
                None,
                true,
                None,
            )
            .await
            .expect("write second org A audit row");
        for _ in 0..50 {
            if crate::entities::organization_audit_log::Entity::find()
                .count(&db)
                .await
                .expect("count delivered audit rows")
                == 3
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(
            crate::entities::organization_audit_log::Entity::find()
                .count(&db)
                .await
                .expect("count delivered audit rows"),
            3
        );
        let tied_at = chrono::Utc::now().naive_utc();
        crate::entities::organization_audit_log::Entity::update_many()
            .filter(crate::entities::organization_audit_log::Column::OrgId.eq(&org_a.id))
            .col_expr(
                crate::entities::organization_audit_log::Column::CreatedAt,
                sea_orm::sea_query::Expr::value(tied_at),
            )
            .exec(&db)
            .await
            .expect("tie org A audit timestamps");
        let first_page = audit_service
            .get_organization_audit_logs(&org_a.id, 1, 0)
            .await
            .expect("load deterministic first page");
        let repeated_first_page = audit_service
            .get_organization_audit_logs(&org_a.id, 1, 0)
            .await
            .expect("repeat deterministic first page");
        let second_page_by_time_tie = audit_service
            .get_organization_audit_logs(&org_a.id, 1, 1)
            .await
            .expect("load deterministic second page");
        assert_eq!(first_page.len(), 1);
        assert_eq!(second_page_by_time_tie.len(), 1);
        assert_eq!(first_page[0].id, repeated_first_page[0].id);
        assert_ne!(first_page[0].id, second_page_by_time_tie[0].id);
        let scoped = audit_service
            .get_target_audit_logs(&org_a.id, "user", "shared-target-id", 1, 0)
            .await
            .expect("query org A target audit rows");
        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].org_id, org_a.id);
        let second_page = audit_service
            .get_target_audit_logs(&org_a.id, "user", "shared-target-id", 1, 1)
            .await
            .expect("query second org A target audit page");
        assert_eq!(second_page.len(), 1);
        assert_eq!(second_page[0].org_id, org_a.id);
        assert_eq!(
            audit_service
                .get_audit_log_count(&org_a.id)
                .await
                .expect("count org A audit rows"),
            2
        );
        assert_eq!(
            audit_service
                .get_audit_log_count_filtered(
                    &org_a.id,
                    None,
                    Some("user"),
                    Some("shared-target-id"),
                )
                .await
                .expect("count filtered org A audit rows"),
            2
        );
        assert_eq!(
            audit_service
                .get_audit_log_count_filtered(&org_a.id, Some("member.added"), None, None,)
                .await
                .expect("count action-filtered org A audit rows"),
            1
        );

        OrganizationRoleStore::create(
            DB::Conn(&db),
            "audit-viewer-role",
            &org_a.id,
            "audit-viewer",
            "Audit viewer",
            None,
            serde_json::json!([CAP_AUDIT_LOGS_VIEW]),
        )
        .await
        .expect("create custom audit role");
        MembershipStore::update_role(DB::Conn(&db), &owner_membership.id, "audit-viewer")
            .await
            .expect("assign audit capability role");
        require_org_audit_admin(&db, &owner_a.id, &org_a.slug)
            .await
            .expect("custom audit capability is sufficient");
        OrganizationRoleStore::update(
            DB::Conn(&db),
            "audit-viewer-role",
            None,
            None,
            Some(serde_json::json!([])),
        )
        .await
        .expect("revoke audit capability");
        assert!(matches!(
            require_org_audit_admin(&db, &owner_a.id, &org_a.slug).await,
            Err(AppError::Forbidden(_))
        ));
        audit_reconciler.shutdown().await;
    }
}

#[cfg(test)]
mod route_tests {
    use super::*;

    use crate::audit::actor::AuditHandle;
    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::crypto::sso::OAuthClient;
    use crate::entities::{organization_audit_log, users};
    use crate::services::{
        events::EventDispatcher, metrics::MfaMetricsService, risk_engine::RiskEngine,
    };
    use crate::store::{
        memberships::MembershipStore,
        organization_roles::OrganizationRoleStore,
        users::{UserCreationOptions, UserStore},
    };
    use crate::test_support::{setup_db, test_config, test_jwt_service};
    use chrono::Utc;
    use moka::future::Cache;
    use sea_orm::{ActiveModelTrait, Set};
    use std::sync::Arc;

    struct Fixture {
        state: AppState,
        owner: AuthUser,
        admin: AuthUser,
        viewer: AuthUser,
        member: AuthUser,
        outsider: AuthUser,
        other_owner: AuthUser,
        alpha_slug: String,
        beta_slug: String,
        alpha_id: String,
    }

    async fn seed_audit(
        db: &sea_orm::DatabaseConnection,
        org_id: &str,
        actor_id: &str,
        action: &str,
        target_type: &str,
        target_id: &str,
    ) {
        organization_audit_log::ActiveModel {
            id: Set(uuid::Uuid::new_v4().to_string()),
            org_id: Set(org_id.to_string()),
            actor_user_id: Set(actor_id.to_string()),
            action: Set(action.to_string()),
            target_type: Set(target_type.to_string()),
            target_id: Set(target_id.to_string()),
            ip_address: Set(Some("127.0.0.1".to_string())),
            user_agent: Set(Some("audit-route-test".to_string())),
            success: Set(true),
            details: Set(Some("{\"secret\":\"redacted\"}".to_string())),
            created_at: Set(Utc::now().naive_utc()),
        }
        .insert(db)
        .await
        .expect("seed audit row");
    }

    async fn fixture() -> Fixture {
        let db = setup_db().await;
        let config = test_config();
        let jwt_service = Arc::new(test_jwt_service(&config));

        let owner = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "audit-route-owner@example.test",
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
            "audit-route-admin@example.test",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create admin")
        .0;
        let viewer = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "audit-route-viewer@example.test",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create viewer")
        .0;
        let member = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "audit-route-member@example.test",
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
            "audit-route-outsider@example.test",
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
            "audit-route-other-owner@example.test",
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
            "audit-route-alpha",
            "Audit Route Alpha",
            &owner.id,
            Some("tier_enterprise"),
        )
        .await
        .expect("create alpha");
        let (beta, _) = OrganizationStore::create_with_owner(
            DB::Conn(&db),
            "audit-route-beta",
            "Audit Route Beta",
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
            "audit-route-viewer-role",
            &alpha.id,
            "audit-route-viewer",
            "Audit Route Viewer",
            None,
            serde_json::json!([CAP_AUDIT_LOGS_VIEW]),
        )
        .await
        .expect("create viewer role");
        MembershipStore::create(DB::Conn(&db), &alpha.id, &viewer.id, "audit-route-viewer")
            .await
            .expect("add viewer");

        seed_audit(
            &db,
            &alpha.id,
            &owner.id,
            "member.added",
            "user",
            "shared-target-id",
        )
        .await;
        seed_audit(
            &db,
            &alpha.id,
            &owner.id,
            "service.created",
            "service",
            "shared-target-id",
        )
        .await;
        seed_audit(
            &db,
            &beta.id,
            &other_owner.id,
            "member.added",
            "user",
            "shared-target-id",
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
                user_agent: "audit-route-test".to_string(),
                current_session_id: None,
            }
        };
        let owner_auth = auth_user_for(&owner);
        let admin_auth = auth_user_for(&admin);
        let viewer_auth = auth_user_for(&viewer);
        let member_auth = auth_user_for(&member);
        let outsider_auth = auth_user_for(&outsider);
        let other_owner_auth = auth_user_for(&other_owner);

        Fixture {
            state,
            owner: owner_auth,
            admin: admin_auth,
            viewer: viewer_auth,
            member: member_auth,
            outsider: outsider_auth,
            other_owner: other_owner_auth,
            alpha_slug: alpha.slug,
            beta_slug: beta.slug,
            alpha_id: alpha.id,
        }
    }

    fn query(
        action: Option<&str>,
        target_type: Option<&str>,
        target_id: Option<&str>,
    ) -> AuditLogQuery {
        AuditLogQuery {
            page: None,
            limit: None,
            action: action.map(str::to_string),
            target_type: target_type.map(str::to_string),
            target_id: target_id.map(str::to_string),
        }
    }

    #[tokio::test]
    async fn audit_routes_require_live_scoped_capability_and_scope_filters() {
        let f = fixture().await;

        for auth in [f.owner.clone(), f.admin.clone(), f.viewer.clone()] {
            let Json(response) = get_organization_audit_logs(
                State(f.state.clone()),
                auth.clone(),
                Path(f.alpha_slug.clone()),
                Query(query(None, None, None)),
            )
            .await
            .expect("audit viewer may read logs");
            assert_eq!(response.pagination.total, 2);
            assert!(response.logs.iter().all(|entry| entry.org_id == f.alpha_id));

            let Json(filtered) = get_organization_audit_logs(
                State(f.state.clone()),
                auth.clone(),
                Path(f.alpha_slug.clone()),
                Query(query(Some("member.added"), None, None)),
            )
            .await
            .expect("action filter applies within the tenant");
            assert_eq!(filtered.pagination.total, 1);
            assert_eq!(filtered.logs[0].action, "member.added");

            let Json(target_filtered) = get_organization_audit_logs(
                State(f.state.clone()),
                auth.clone(),
                Path(f.alpha_slug.clone()),
                Query(query(None, Some("user"), Some("shared-target-id"))),
            )
            .await
            .expect("target filter applies within the tenant");
            assert_eq!(target_filtered.pagination.total, 1);
            assert_eq!(target_filtered.logs[0].target_type, "user");

            let Json(event_types) =
                get_audit_event_types(State(f.state.clone()), auth, Path(f.alpha_slug.clone()))
                    .await
                    .expect("audit viewer may read event types");
            assert!(!event_types.is_empty());
        }

        for auth in [f.member.clone(), f.outsider.clone(), f.other_owner.clone()] {
            assert!(matches!(
                get_organization_audit_logs(
                    State(f.state.clone()),
                    auth.clone(),
                    Path(f.alpha_slug.clone()),
                    Query(query(None, None, None)),
                )
                .await,
                Err(AppError::Forbidden(_))
            ));
            assert!(matches!(
                get_audit_event_types(State(f.state.clone()), auth, Path(f.alpha_slug.clone()),)
                    .await,
                Err(AppError::Forbidden(_))
            ));
        }
        assert!(matches!(
            get_organization_audit_logs(
                State(f.state.clone()),
                f.owner.clone(),
                Path(f.beta_slug.clone()),
                Query(query(None, None, None)),
            )
            .await,
            Err(AppError::Forbidden(_))
        ));

        OrganizationStore::update_status(DB::Conn(&f.state.db), &f.alpha_id, "suspended")
            .await
            .expect("suspend alpha");
        assert!(matches!(
            get_organization_audit_logs(
                State(f.state.clone()),
                f.owner.clone(),
                Path(f.alpha_slug.clone()),
                Query(query(None, None, None)),
            )
            .await,
            Err(AppError::Forbidden(_))
        ));
    }
}
