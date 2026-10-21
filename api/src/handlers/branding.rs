use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::Deserialize;
use uuid::Uuid;

use crate::db::{transaction::with_retrying_transaction, DB};
use crate::services::domain_verification::{
    normalize_verifiable_domain, verify_dns_txt_record, verify_http_file,
};
use crate::services::permission_service::{PermissionService, CAP_ORG_SETTINGS_MANAGE};
use crate::services::tier_enforcement::TierService;
use crate::{
    db::models::{
        BrandingConfiguration, DomainConfiguration, DomainVerificationMethod,
        DomainVerificationResponse, DomainVerificationResult,
    },
    entities::organizations,
    error::AppError,
    middleware::AuthUser,
    state::AppState,
    store::{memberships::MembershipStore, organizations::OrganizationStore},
};

async fn mark_custom_domain_verified_with_audit(
    db: DB<'_>,
    org_id: &str,
    expected_domain: &str,
    expected_verification_token: &str,
    audit_actor: &crate::audit::actor::AuditHandle,
    event: crate::entities::organization_audit_log::ActiveModel,
) -> Result<(), AppError> {
    use crate::entities::prelude::Organizations;

    let updated = Organizations::update_many()
        .set(organizations::ActiveModel {
            domain_verified: Set(true),
            updated_at: Set(chrono::Utc::now().naive_utc()),
            ..Default::default()
        })
        .filter(organizations::Column::Id.eq(org_id))
        .filter(organizations::Column::CustomDomain.eq(expected_domain))
        .filter(organizations::Column::DomainVerificationToken.eq(expected_verification_token))
        .filter(organizations::Column::DomainVerified.eq(false))
        .exec(&db)
        .await?;
    if updated.rows_affected != 1 {
        return Err(AppError::BadRequest(
            "Domain verification state changed; retry verification".to_string(),
        ));
    }

    audit_actor.log_org_with_db(db, event).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn replace_custom_domain_with_audit(
    db: DB<'_>,
    org_id: &str,
    expected_domain: Option<&str>,
    expected_verification_token: Option<&str>,
    expected_verified: bool,
    new_domain: &str,
    new_verification_token: &str,
    audit_actor: &crate::audit::actor::AuditHandle,
    event: crate::entities::organization_audit_log::ActiveModel,
) -> Result<(), AppError> {
    use crate::entities::prelude::Organizations;

    let mut update = Organizations::update_many()
        .set(organizations::ActiveModel {
            custom_domain: Set(Some(new_domain.to_string())),
            domain_verified: Set(false),
            domain_verification_token: Set(Some(new_verification_token.to_string())),
            updated_at: Set(chrono::Utc::now().naive_utc()),
            ..Default::default()
        })
        .filter(organizations::Column::Id.eq(org_id))
        .filter(organizations::Column::DomainVerified.eq(expected_verified));
    update = match expected_domain {
        Some(domain) => update.filter(organizations::Column::CustomDomain.eq(domain)),
        None => update.filter(organizations::Column::CustomDomain.is_null()),
    };
    update = match expected_verification_token {
        Some(token) => update.filter(organizations::Column::DomainVerificationToken.eq(token)),
        None => update.filter(organizations::Column::DomainVerificationToken.is_null()),
    };

    let updated = update.exec(&db).await?;
    if updated.rows_affected != 1 {
        return Err(AppError::BadRequest(
            "Domain configuration changed; retry the update".to_string(),
        ));
    }
    audit_actor.log_org_with_db(db, event).await?;
    Ok(())
}

async fn clear_custom_domain_with_audit(
    db: DB<'_>,
    org_id: &str,
    expected_domain: Option<&str>,
    expected_verification_token: Option<&str>,
    expected_verified: bool,
    audit_actor: &crate::audit::actor::AuditHandle,
    event: Option<crate::entities::organization_audit_log::ActiveModel>,
) -> Result<(), AppError> {
    use crate::entities::prelude::Organizations;

    let mut update = Organizations::update_many()
        .set(organizations::ActiveModel {
            custom_domain: Set(None),
            domain_verified: Set(false),
            domain_verification_token: Set(None),
            updated_at: Set(chrono::Utc::now().naive_utc()),
            ..Default::default()
        })
        .filter(organizations::Column::Id.eq(org_id))
        .filter(organizations::Column::DomainVerified.eq(expected_verified));
    update = match expected_domain {
        Some(domain) => update.filter(organizations::Column::CustomDomain.eq(domain)),
        None => update.filter(organizations::Column::CustomDomain.is_null()),
    };
    update = match expected_verification_token {
        Some(token) => update.filter(organizations::Column::DomainVerificationToken.eq(token)),
        None => update.filter(organizations::Column::DomainVerificationToken.is_null()),
    };

    let updated = update.exec(&db).await?;
    if updated.rows_affected != 1 {
        return Err(AppError::BadRequest(
            "Domain configuration changed; retry deletion".to_string(),
        ));
    }
    if let Some(event) = event {
        audit_actor.log_org_with_db(db, event).await?;
    }
    Ok(())
}

async fn require_settings_manager(
    state: &AppState,
    org_id: &str,
    auth_user: &AuthUser,
) -> Result<(), AppError> {
    require_settings_manager_in(
        DB::Conn(&state.db),
        org_id,
        &auth_user.user.id,
        auth_user.claims.is_platform_context(),
        auth_user.claims.mfa_verified == Some(true) || auth_user.claims.bootstrap == Some(true),
    )
    .await
}

async fn require_settings_manager_in(
    db: DB<'_>,
    org_id: &str,
    user_id: &str,
    platform_token_context: bool,
    platform_mfa_verified: bool,
) -> Result<(), AppError> {
    OrganizationStore::find_by_id(db.clone(), org_id)
        .await?
        .filter(|org| org.status == "active")
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Platform authority is only valid from a platform-context token with a
    // live owner role and MFA enrollment. Transaction retries therefore cannot
    // inherit a stale tenant-scoped token or a demoted owner.
    if crate::middleware::has_live_platform_authority_in(
        db.clone(),
        user_id,
        platform_token_context,
        platform_mfa_verified,
    )
    .await?
    {
        return Ok(());
    }

    if PermissionService::check(db, org_id, user_id, CAP_ORG_SETTINGS_MANAGE).await? {
        return Ok(());
    }

    Err(AppError::Forbidden(
        "Insufficient permissions to manage organization settings".to_string(),
    ))
}

// Request/Response Types

#[derive(Debug, Deserialize)]
pub struct SetCustomDomainRequest {
    pub domain: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateBrandingRequest {
    pub logo_url: Option<String>,
    pub primary_color: Option<String>,
}

// Domain Management Handlers

pub async fn set_custom_domain(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
    Json(req): Json<SetCustomDomainRequest>,
) -> Result<Json<DomainVerificationResponse>, AppError> {
    // Verify user has permission
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .filter(|org| org.status == "active")
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_settings_manager(&state, &org.id, &auth_user).await?;

    // Tier/Entitlement Check
    TierService::check_feature_access(
        DB::Conn(&state.db),
        &org.id,
        |f| f.allow_custom_domain,
        "Custom Domain",
    )
    .await?;

    let domain = normalize_verifiable_domain(&req.domain)?;

    // Check if domain is already in use by another organization
    use crate::entities::prelude::Organizations;
    let existing = Organizations::find()
        .filter(organizations::Column::CustomDomain.eq(&domain))
        .filter(organizations::Column::Id.ne(&org.id))
        .one(&state.db)
        .await?;

    if existing.is_some() {
        return Err(AppError::BadRequest(
            "This domain is already in use by another organization".to_string(),
        ));
    }

    // Generate verification token
    let verification_token = Uuid::new_v4().to_string();

    // Update organization with new domain and verification token
    let org_id = org.id.clone();
    let expected_domain = org.custom_domain.clone();
    let expected_verification_token = org.domain_verification_token.clone();
    let expected_verified = org.domain_verified;
    let actor_id = auth_user.claims.sub.clone();
    let actor_has_platform_context = auth_user.claims.is_platform_context();
    let actor_has_platform_mfa =
        auth_user.claims.mfa_verified == Some(true) || auth_user.claims.bootstrap == Some(true);
    let domain_clone = domain.clone();
    let verification_token_clone = verification_token.clone();
    use crate::services::audit_builder::OrgAuditBuilder;
    let event = OrgAuditBuilder::new(&org.id, Some(&auth_user.claims.sub), "domain.set")
        .target("organization", &org.id)
        .success(true)
        .details_json(Some(serde_json::json!({ "domain": &domain })))
        .build();
    let audit_actor = state.audit_actor.clone();

    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "set_custom_domain",
        |db| {
            let org_id = org_id.clone();
            let expected_domain = expected_domain.clone();
            let expected_verification_token = expected_verification_token.clone();
            let actor_id = actor_id.clone();
            let domain = domain_clone.clone();
            let verification_token = verification_token_clone.clone();
            let event = event.clone();
            let audit_actor = audit_actor.clone();
            Box::pin(async move {
                require_settings_manager_in(
                    db.clone(),
                    &org_id,
                    &actor_id,
                    actor_has_platform_context,
                    actor_has_platform_mfa,
                )
                .await?;
                TierService::check_feature_access(
                    db.clone(),
                    &org_id,
                    |features| features.allow_custom_domain,
                    "Custom Domain",
                )
                .await?;
                replace_custom_domain_with_audit(
                    db,
                    &org_id,
                    expected_domain.as_deref(),
                    expected_verification_token.as_deref(),
                    expected_verified,
                    &domain,
                    &verification_token,
                    &audit_actor,
                    event,
                )
                .await
            })
        },
    )
    .await?;

    // Return verification instructions
    let verification_methods = vec![
        DomainVerificationMethod {
            method: "DNS TXT Record".to_string(),
            instructions: "Add a TXT record to your domain's DNS settings".to_string(),
            record_type: Some("TXT".to_string()),
            record_name: Some(format!("_sso-verification.{}", domain)),
            record_value: Some(verification_token.clone()),
        },
        DomainVerificationMethod {
            method: "HTTP File".to_string(),
            instructions: format!(
                "Upload a file to http://{}/.well-known/sso-verification.txt containing the verification token",
                domain
            ),
            record_type: None,
            record_name: None,
            record_value: Some(verification_token.clone()),
        },
    ];

    Ok(Json(DomainVerificationResponse {
        verification_token,
        verification_methods,
    }))
}

pub async fn verify_custom_domain(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
) -> Result<Json<DomainVerificationResult>, AppError> {
    // Verify user has permission
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .filter(|org| org.status == "active")
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_settings_manager(&state, &org.id, &auth_user).await?;

    // Check if domain is set
    let domain = org
        .custom_domain
        .as_ref()
        .ok_or_else(|| AppError::BadRequest("No custom domain configured".to_string()))?;

    let verification_token = org
        .domain_verification_token
        .as_ref()
        .ok_or_else(|| AppError::BadRequest("No verification token found".to_string()))?;

    // If already verified, return success
    if org.domain_verified {
        return Ok(Json(DomainVerificationResult {
            verified: true,
            message: "Domain is already verified".to_string(),
        }));
    }

    // Attempt DNS verification
    let dns_verified = verify_dns_txt_record(domain, verification_token).await;

    // Attempt HTTP verification
    let http_verified = verify_http_file(domain, verification_token).await;

    if dns_verified || http_verified {
        // Mark domain as verified
        let org_id = org.id.clone();
        let expected_domain = domain.clone();
        let expected_verification_token = verification_token.clone();
        let actor_id = auth_user.claims.sub.clone();
        let actor_has_platform_context = auth_user.claims.is_platform_context();
        let actor_has_platform_mfa =
            auth_user.claims.mfa_verified == Some(true) || auth_user.claims.bootstrap == Some(true);
        use crate::services::audit_builder::OrgAuditBuilder;
        let event = OrgAuditBuilder::new(&org.id, Some(&auth_user.claims.sub), "domain.verified")
            .target("organization", &org.id)
            .success(true)
            .details_json(Some(serde_json::json!({
                "domain": domain,
                "method": if dns_verified { "DNS" } else { "HTTP" }
            })))
            .build();
        let audit_actor = state.audit_actor.clone();
        with_retrying_transaction(
            &state.db,
            #[cfg(feature = "db_sqlite")]
            &state.db_writer,
            "verify_custom_domain",
            |db| {
                let org_id = org_id.clone();
                let expected_domain = expected_domain.clone();
                let expected_verification_token = expected_verification_token.clone();
                let actor_id = actor_id.clone();
                let event = event.clone();
                let audit_actor = audit_actor.clone();
                Box::pin(async move {
                    require_settings_manager_in(
                        db.clone(),
                        &org_id,
                        &actor_id,
                        actor_has_platform_context,
                        actor_has_platform_mfa,
                    )
                    .await?;
                    mark_custom_domain_verified_with_audit(
                        db,
                        &org_id,
                        &expected_domain,
                        &expected_verification_token,
                        &audit_actor,
                        event,
                    )
                    .await
                })
            },
        )
        .await?;

        Ok(Json(DomainVerificationResult {
            verified: true,
            message: format!(
                "Domain verified successfully via {}",
                if dns_verified {
                    "DNS TXT record"
                } else {
                    "HTTP file"
                }
            ),
        }))
    } else {
        Ok(Json(DomainVerificationResult {
            verified: false,
            message: "Domain verification failed. Please ensure the TXT record or HTTP file is correctly configured.".to_string(),
        }))
    }
}

pub async fn get_domain_configuration(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
) -> Result<Json<DomainConfiguration>, AppError> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .filter(|org| org.status == "active")
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    if !crate::middleware::has_live_platform_authority(&state.db, &auth_user).await? {
        let is_member =
            MembershipStore::is_member(DB::Conn(&state.db), &org.id, &auth_user.claims.sub).await?;

        if !is_member {
            return Err(AppError::Forbidden(
                "You must be a member of this organization".to_string(),
            ));
        }
    }

    Ok(Json(DomainConfiguration {
        custom_domain: org.custom_domain,
        domain_verified: org.domain_verified,
    }))
}

pub async fn delete_custom_domain(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
) -> Result<StatusCode, AppError> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .filter(|org| org.status == "active")
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_settings_manager(&state, &org.id, &auth_user).await?;

    let domain = org.custom_domain.clone();
    let verification_token = org.domain_verification_token.clone();
    let domain_verified = org.domain_verified;
    let actor_id = auth_user.claims.sub.clone();
    let actor_has_platform_context = auth_user.claims.is_platform_context();
    let actor_has_platform_mfa =
        auth_user.claims.mfa_verified == Some(true) || auth_user.claims.bootstrap == Some(true);
    let org_id = org.id.clone();
    let event = domain.as_ref().map(|domain| {
        use crate::services::audit_builder::OrgAuditBuilder;
        OrgAuditBuilder::new(&org.id, Some(&auth_user.claims.sub), "domain.deleted")
            .target("organization", &org.id)
            .success(true)
            .details_json(Some(serde_json::json!({ "domain": domain })))
            .build()
    });
    let audit_actor = state.audit_actor.clone();

    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "delete_custom_domain",
        |db| {
            let org_id = org_id.clone();
            let domain = domain.clone();
            let verification_token = verification_token.clone();
            let actor_id = actor_id.clone();
            let event = event.clone();
            let audit_actor = audit_actor.clone();
            Box::pin(async move {
                require_settings_manager_in(
                    db.clone(),
                    &org_id,
                    &actor_id,
                    actor_has_platform_context,
                    actor_has_platform_mfa,
                )
                .await?;
                clear_custom_domain_with_audit(
                    db,
                    &org_id,
                    domain.as_deref(),
                    verification_token.as_deref(),
                    domain_verified,
                    &audit_actor,
                    event,
                )
                .await
            })
        },
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

// Branding Management Handlers

pub async fn update_branding(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
    Json(req): Json<UpdateBrandingRequest>,
) -> Result<Json<BrandingConfiguration>, AppError> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .filter(|org| org.status == "active")
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_settings_manager(&state, &org.id, &auth_user).await?;

    // Tier/Entitlement Check
    TierService::check_feature_access(
        DB::Conn(&state.db),
        &org.id,
        |f| f.allow_branding,
        "Custom Branding",
    )
    .await?;

    // Validate color format if provided
    if let Some(ref color) = req.primary_color {
        // Must start with # and be 4 or 7 characters total
        if !color.starts_with('#') || (color.len() != 7 && color.len() != 4) {
            return Err(AppError::BadRequest(
                "Invalid color format. Must be a hex color (e.g., #FF5733 or #F57)".to_string(),
            ));
        }

        // Validate hex characters after #
        let hex_part = &color[1..];
        if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(AppError::BadRequest(
                "Invalid color format. Must be a hex color (e.g., #FF5733 or #F57)".to_string(),
            ));
        }
    }

    let org_id = org.id.clone();
    let logo_url = req.logo_url.clone();
    let primary_color = req.primary_color.clone();
    let actor_id = auth_user.claims.sub.clone();
    let actor_has_platform_context = auth_user.claims.is_platform_context();
    let actor_has_platform_mfa =
        auth_user.claims.mfa_verified == Some(true) || auth_user.claims.bootstrap == Some(true);
    use crate::services::audit_builder::OrgAuditBuilder;
    let event = OrgAuditBuilder::new(&org.id, Some(&auth_user.claims.sub), "branding.updated")
        .target("organization", &org.id)
        .success(true)
        .details_json(Some(serde_json::json!({
            "logo_url": req.logo_url,
            "primary_color": req.primary_color
        })))
        .build();
    let audit_actor = state.audit_actor.clone();

    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "update_branding",
        |db| {
            let org_id = org_id.clone();
            let logo_url = logo_url.clone();
            let primary_color = primary_color.clone();
            let actor_id = actor_id.clone();
            let event = event.clone();
            let audit_actor = audit_actor.clone();
            Box::pin(async move {
                require_settings_manager_in(
                    db.clone(),
                    &org_id,
                    &actor_id,
                    actor_has_platform_context,
                    actor_has_platform_mfa,
                )
                .await?;
                TierService::check_feature_access(
                    db.clone(),
                    &org_id,
                    |features| features.allow_branding,
                    "Custom Branding",
                )
                .await?;
                use crate::entities::prelude::Organizations;
                let org_model = Organizations::find()
                    .filter(organizations::Column::Id.eq(&org_id))
                    .one(&db)
                    .await?
                    .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

                let mut org_active: organizations::ActiveModel = org_model.into();
                org_active.brand_logo_url = Set(logo_url);
                org_active.brand_primary_color = Set(primary_color);
                org_active.updated_at = Set(chrono::Utc::now().naive_utc());
                org_active.update(&db).await?;
                audit_actor.log_org_with_db(db, event).await?;
                Ok(())
            })
        },
    )
    .await?;

    Ok(Json(BrandingConfiguration {
        logo_url: req.logo_url,
        primary_color: req.primary_color,
    }))
}

pub async fn get_branding(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
) -> Result<Json<BrandingConfiguration>, AppError> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .filter(|org| org.status == "active")
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    if !crate::middleware::has_live_platform_authority(&state.db, &auth_user).await? {
        let is_member =
            MembershipStore::is_member(DB::Conn(&state.db), &org.id, &auth_user.claims.sub).await?;

        if !is_member {
            return Err(AppError::Forbidden(
                "You must be a member of this organization".to_string(),
            ));
        }
    }

    Ok(Json(BrandingConfiguration {
        logo_url: org.brand_logo_url,
        primary_color: org.brand_primary_color,
    }))
}

pub async fn get_public_branding(
    State(state): State<AppState>,
    Path(org_slug): Path<String>,
) -> Result<Json<BrandingConfiguration>, AppError> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .filter(|org| org.status == "active")
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    Ok(Json(BrandingConfiguration {
        logo_url: org.brand_logo_url,
        primary_color: org.brand_primary_color,
    }))
}

#[cfg(test)]
mod domain_verification_race_tests {
    use super::*;
    use crate::entities::audit_outbox;
    use crate::entities::prelude::Organizations;
    use crate::services::audit_builder::OrgAuditBuilder;
    use crate::store::users::UserStore;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::{Database, PaginatorTrait, TransactionTrait};

    #[tokio::test]
    async fn concurrent_domain_replacement_cannot_be_verified_or_audited() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        let user = UserStore::create(DB::Conn(&db), "domain-owner@example.test", None, true)
            .await
            .unwrap();
        let org =
            OrganizationStore::create(DB::Conn(&db), "domain-race", "Domain race", &user.id, None)
                .await
                .unwrap();

        Organizations::update_many()
            .set(organizations::ActiveModel {
                custom_domain: Set(Some("replacement.example.test".to_string())),
                domain_verification_token: Set(Some("replacement-token".to_string())),
                domain_verified: Set(false),
                ..Default::default()
            })
            .filter(organizations::Column::Id.eq(&org.id))
            .exec(&db)
            .await
            .unwrap();

        let transaction = db.begin().await.unwrap();
        let audit = crate::audit::actor::AuditHandle::without_worker(db.clone());
        let event = OrgAuditBuilder::new(&org.id, Some(&user.id), "domain.verified")
            .target("organization", &org.id)
            .success(true)
            .build();
        let error = mark_custom_domain_verified_with_audit(
            DB::Tx(&transaction),
            &org.id,
            "original.example.test",
            "original-token",
            &audit,
            event,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, AppError::BadRequest(_)));
        transaction.rollback().await.unwrap();

        let unchanged = Organizations::find_by_id(&org.id)
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            unchanged.custom_domain.as_deref(),
            Some("replacement.example.test")
        );
        assert_eq!(
            unchanged.domain_verification_token.as_deref(),
            Some("replacement-token")
        );
        assert!(!unchanged.domain_verified);
        assert_eq!(audit_outbox::Entity::find().count(&db).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn concurrent_domain_addition_cannot_be_deleted_without_an_audit() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        let user = UserStore::create(DB::Conn(&db), "domain-delete@example.test", None, true)
            .await
            .unwrap();
        let org = OrganizationStore::create(
            DB::Conn(&db),
            "domain-delete-race",
            "Domain delete race",
            &user.id,
            None,
        )
        .await
        .unwrap();

        Organizations::update_many()
            .set(organizations::ActiveModel {
                custom_domain: Set(Some("new.example.test".to_string())),
                domain_verification_token: Set(Some("new-token".to_string())),
                domain_verified: Set(false),
                ..Default::default()
            })
            .filter(organizations::Column::Id.eq(&org.id))
            .exec(&db)
            .await
            .unwrap();

        let transaction = db.begin().await.unwrap();
        let audit = crate::audit::actor::AuditHandle::without_worker(db.clone());
        let error = clear_custom_domain_with_audit(
            DB::Tx(&transaction),
            &org.id,
            None,
            None,
            false,
            &audit,
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, AppError::BadRequest(_)));
        transaction.rollback().await.unwrap();

        let unchanged = Organizations::find_by_id(&org.id)
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(unchanged.custom_domain.as_deref(), Some("new.example.test"));
        assert_eq!(
            unchanged.domain_verification_token.as_deref(),
            Some("new-token")
        );
        assert!(!unchanged.domain_verified);
        assert_eq!(audit_outbox::Entity::find().count(&db).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn stale_platform_claim_cannot_read_or_mutate_another_tenant_after_demotion() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        let stale_owner = UserStore::create(
            DB::Conn(&db),
            "stale-branding-owner@example.test",
            None,
            true,
        )
        .await
        .unwrap();
        let tenant_owner = UserStore::create(
            DB::Conn(&db),
            "branding-tenant-owner@example.test",
            None,
            false,
        )
        .await
        .unwrap();
        let org = OrganizationStore::create(
            DB::Conn(&db),
            "branding-target",
            "Branding target",
            &tenant_owner.id,
            None,
        )
        .await
        .unwrap();
        OrganizationStore::update_status(DB::Conn(&db), &org.id, "active")
            .await
            .unwrap();
        Organizations::update_many()
            .set(organizations::ActiveModel {
                custom_domain: Set(Some("unchanged.example.test".to_string())),
                domain_verification_token: Set(Some("unchanged-token".to_string())),
                domain_verified: Set(false),
                brand_primary_color: Set(Some("#123456".to_string())),
                ..Default::default()
            })
            .filter(organizations::Column::Id.eq(&org.id))
            .exec(&db)
            .await
            .unwrap();

        // This models an already-issued token and cached request snapshot that
        // both still say platform owner after the database role is removed.
        UserStore::set_platform_owner(DB::Conn(&db), &stale_owner.id, false)
            .await
            .unwrap();
        assert!(!crate::middleware::has_live_platform_authority_in(
            DB::Conn(&db),
            &stale_owner.id,
            true,
            true
        )
        .await
        .unwrap());

        // Every write/verify/delete transaction enters through this live gate.
        for operation in ["write", "verify", "delete"] {
            let transaction = db.begin().await.unwrap();
            let error = require_settings_manager_in(
                DB::Tx(&transaction),
                &org.id,
                &stale_owner.id,
                true,
                true,
            )
            .await
            .unwrap_err();
            assert!(matches!(error, AppError::Forbidden(_)), "{operation}");
            transaction.rollback().await.unwrap();
        }

        let unchanged = Organizations::find_by_id(&org.id)
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            unchanged.custom_domain.as_deref(),
            Some("unchanged.example.test")
        );
        assert_eq!(
            unchanged.domain_verification_token.as_deref(),
            Some("unchanged-token")
        );
        assert!(!unchanged.domain_verified);
        assert_eq!(unchanged.brand_primary_color.as_deref(), Some("#123456"));
        assert_eq!(audit_outbox::Entity::find().count(&db).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn suspended_tenant_is_rejected_again_at_the_transaction_boundary() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        let owner = UserStore::create(
            DB::Conn(&db),
            "suspended-branding-owner@example.test",
            None,
            true,
        )
        .await
        .unwrap();
        let org = OrganizationStore::create(
            DB::Conn(&db),
            "suspended-branding",
            "Suspended branding",
            &owner.id,
            None,
        )
        .await
        .unwrap();
        OrganizationStore::update_status(DB::Conn(&db), &org.id, "suspended")
            .await
            .unwrap();

        assert!(matches!(
            require_settings_manager_in(DB::Conn(&db), &org.id, &owner.id, true, true).await,
            Err(AppError::NotFound(_))
        ));
    }
}
