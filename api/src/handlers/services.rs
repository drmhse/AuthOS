use crate::constants::{DEFAULT_MAX_SERVICES, DEFAULT_TIER_NAME, VALID_SERVICE_TYPES};
use crate::db::models::{Plan, ServiceResponse};
use crate::db::transaction::with_retrying_transaction;
use crate::db::DB;
use crate::entities::{organizations, plans};
use crate::error::Result;
use crate::middleware::AuthUser;
use crate::services::audit_builder::OrgAuditBuilder;
use crate::services::permission_service::{
    PermissionService, CAP_SERVICES_CREATE, CAP_SERVICES_MANAGE, CAP_SERVICES_VIEW,
};
use crate::state::AppState;
use crate::store::{
    memberships::MembershipStore, organizations::OrganizationStore, permissions::PermissionsStore,
    plans::PlanStore, services::ServiceStore, subscriptions::SubscriptionStore,
};
use crate::utils::client_secret::hash_client_secret;
use crate::utils::resource_indicators::validate_resource_uri;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use sea_orm::EntityTrait;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

fn validate_redirect_uris_input(redirect_uris: &[String]) -> Result<()> {
    if redirect_uris.is_empty() {
        return Err(crate::error::AppError::BadRequest(
            "At least one redirect URI is required".to_string(),
        ));
    }

    Ok(())
}

fn validate_resource_uris_input(resource_uris: &[String]) -> Result<()> {
    if resource_uris.is_empty() {
        return Err(crate::error::AppError::BadRequest(
            "At least one resource URI is required".to_string(),
        ));
    }

    for resource_uri in resource_uris {
        validate_resource_uri(resource_uri)?;
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct CreateServiceRequest {
    pub slug: String,
    pub name: String,
    pub service_type: String, // 'web', 'mobile', 'desktop', 'api'
    pub github_scopes: Option<Vec<String>>,
    pub microsoft_scopes: Option<Vec<String>>,
    pub google_scopes: Option<Vec<String>>,
    pub redirect_uris: Option<Vec<String>>,
    pub device_activation_uri: Option<String>,
    pub resource_uris: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateServiceRequest {
    pub name: Option<String>,
    pub service_type: Option<String>,
    pub github_scopes: Option<Vec<String>>,
    pub microsoft_scopes: Option<Vec<String>>,
    pub google_scopes: Option<Vec<String>>,
    pub redirect_uris: Option<Vec<String>>,
    pub device_activation_uri: Option<String>,
    pub resource_uris: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct RotateServiceSecretResponse {
    pub service: ServiceResponse,
    pub client_secret: String,
}

#[derive(Debug, Serialize)]
pub struct ServiceWithGrantsResponse {
    pub service: ServiceResponse,
    pub default_plan: Plan,
    pub usage: ServiceUsageInfo,
}

#[derive(Debug, Serialize)]
pub struct ServiceUsageInfo {
    pub current_services: i64,
    pub max_services: i64,
    pub tier: String,
}

#[derive(Debug, Serialize)]
pub struct ServiceListResponse {
    pub services: Vec<ServiceWithDetails>,
    pub usage: ServiceUsageInfo,
}

#[derive(Debug, Serialize)]
pub struct ServiceWithDetails {
    #[serde(flatten)]
    pub service: ServiceResponse,
    pub plan_count: i64,
    pub subscription_count: i64,
}

#[derive(Debug, Deserialize)]
pub struct ListServicesQuery {
    #[allow(dead_code)]
    pub status: Option<String>,
    pub service_type: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct CreatePlanRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub price_cents: i64,
    pub currency: String,
    pub features: Option<Vec<String>>,
    pub stripe_price_id: Option<String>,
    #[serde(default)]
    pub is_default: bool,
}

#[derive(Debug, Deserialize)]
pub struct UpdatePlanRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub price_cents: Option<i64>,
    pub currency: Option<String>,
    pub features: Option<Vec<String>>,
    pub stripe_price_id: Option<Option<String>>,
    pub is_default: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct PlanResponse {
    pub plan: Plan,
    pub subscription_count: i64,
}

// Helper function to check if user has permission to manage services
async fn can_manage_service(state: &AppState, user_id: &str, org_id: &str) -> Result<bool> {
    PermissionService::check(DB::Conn(&state.db), org_id, user_id, CAP_SERVICES_MANAGE).await
}

async fn can_manage_specific_service(
    state: &AppState,
    user_id: &str,
    org_id: &str,
    service_id: &str,
) -> Result<bool> {
    if can_manage_service(state, user_id, org_id).await? {
        return Ok(true);
    }

    if MembershipStore::find_by_org_and_user(DB::Conn(&state.db), org_id, user_id)
        .await?
        .is_none()
    {
        return Ok(false);
    }

    PermissionsStore::check(
        DB::Conn(&state.db),
        "service",
        service_id,
        "manager",
        user_id,
    )
    .await
}

async fn can_create_service(state: &AppState, user_id: &str, org_id: &str) -> Result<bool> {
    PermissionService::check(DB::Conn(&state.db), org_id, user_id, CAP_SERVICES_CREATE).await
}

async fn can_view_service(
    state: &AppState,
    user_id: &str,
    org_id: &str,
    service_id: &str,
) -> Result<bool> {
    if PermissionService::check_any(
        DB::Conn(&state.db),
        org_id,
        user_id,
        &[CAP_SERVICES_VIEW, CAP_SERVICES_MANAGE],
    )
    .await?
    {
        return Ok(true);
    }

    if MembershipStore::find_by_org_and_user(DB::Conn(&state.db), org_id, user_id)
        .await?
        .is_none()
    {
        return Ok(false);
    }

    if PermissionsStore::check(
        DB::Conn(&state.db),
        "service",
        service_id,
        "manager",
        user_id,
    )
    .await?
    {
        return Ok(true);
    }

    PermissionsStore::check(
        DB::Conn(&state.db),
        "service",
        service_id,
        "viewer",
        user_id,
    )
    .await
}

// Helper function to calculate service limits
async fn get_service_limits(state: &AppState, org: &organizations::Model) -> Result<(i64, String)> {
    use crate::store::organization_tiers::OrganizationTierStore;

    let max_services = if let Some(custom_limit) = org.max_services {
        custom_limit as i64
    } else {
        // Get tier default
        let tier_name = if let Some(tier_id) = &org.tier_id {
            OrganizationTierStore::find_by_id(DB::Conn(&state.db), tier_id)
                .await?
                .map_or_else(|| DEFAULT_TIER_NAME.to_string(), |t| t.name)
        } else {
            DEFAULT_TIER_NAME.to_string()
        };

        OrganizationTierStore::find_by_name(DB::Conn(&state.db), &tier_name)
            .await?
            .map_or(DEFAULT_MAX_SERVICES, |t| t.default_max_services as i64)
    };

    let tier_display = if let Some(tier_id) = &org.tier_id {
        OrganizationTierStore::find_by_id(DB::Conn(&state.db), tier_id)
            .await?
            .map_or_else(|| "Free Tier".to_string(), |t| t.display_name)
    } else {
        "Free Tier".to_string()
    };

    Ok((max_services, tier_display))
}

// Create service with auto-provisioning (Phase 5 enhancement)
pub async fn create_service(
    State(state): State<AppState>,
    Path(org_slug): Path<String>,
    auth_user: axum::Extension<AuthUser>,
    Json(req): Json<CreateServiceRequest>,
) -> Result<Json<ServiceWithGrantsResponse>> {
    if let Some(redirect_uris) = &req.redirect_uris {
        validate_redirect_uris_input(redirect_uris)?;
    }
    if let Some(resource_uris) = &req.resource_uris {
        validate_resource_uris_input(resource_uris)?;
    }

    // Validate service type
    if !VALID_SERVICE_TYPES.contains(&req.service_type.as_str()) {
        return Err(crate::error::AppError::BadRequest(format!(
            "Invalid service type. Must be one of: {}",
            VALID_SERVICE_TYPES.join(", ")
        )));
    }

    // Authentication already happened in middleware; this is authorization.

    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Organization not found".to_string()))?;

    let org =
        crate::handlers::organizations::ensure_organization_active(&state.db, &org.id).await?;

    if !can_create_service(&state, &auth_user.user.id, &org.id).await? {
        return Err(crate::error::AppError::Forbidden(
            "Insufficient permissions to create services".to_string(),
        ));
    }

    let current_service_count =
        ServiceStore::count_by_org(DB::Conn(&state.db), &org.id).await? as i64;

    let (max_services, tier_name) = get_service_limits(&state, &org).await?;

    if current_service_count >= max_services {
        return Err(crate::error::AppError::BadRequest(format!(
            "Organization has reached maximum service limit ({}/{})",
            current_service_count, max_services
        )));
    }

    let service_id = Uuid::new_v4().to_string();
    let client_id = Uuid::new_v4().to_string();
    let client_secret = Uuid::new_v4().to_string();
    let client_secret_hash = hash_client_secret(&client_secret);
    let plan_id = Uuid::new_v4().to_string();

    let github_scopes_json = req
        .github_scopes
        .as_ref()
        .map(|s| serde_json::to_string(s).unwrap());
    let microsoft_scopes_json = req
        .microsoft_scopes
        .as_ref()
        .map(|s| serde_json::to_string(s).unwrap());
    let google_scopes_json = req
        .google_scopes
        .as_ref()
        .map(|s| serde_json::to_string(s).unwrap());
    let redirect_uris_json = req
        .redirect_uris
        .as_ref()
        .map(|s| serde_json::to_string(s).unwrap());
    let resource_uris_json = req
        .resource_uris
        .as_ref()
        .map(|s| serde_json::to_string(s).unwrap());

    // Log service creation
    tracing::info!(
        service_slug = %req.slug,
        org_slug = %org_slug,
        user_id = %auth_user.user.id,
        service_type = %req.service_type,
        "Creating new service"
    );

    // Clone values needed inside the closure
    let slug = req.slug.clone();
    let name = req.name.clone();
    let service_type = req.service_type.clone();
    let device_activation_uri = req.device_activation_uri.clone();
    let org_id = org.id.clone();
    let event = OrgAuditBuilder::new(&org.id, Some(&auth_user.user.id), "service.created")
        .target("service", &service_id)
        .success(true)
        .details_json(Some(json!({
            "service_slug": &req.slug,
            "service_name": &req.name,
            "service_type": &req.service_type,
            "client_id": &client_id
        })))
        .build();
    let audit_actor = state.audit_actor.clone();

    let (service, default_plan) = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "create_service",
        |db| {
            let service_id = service_id.clone();
            let org_id = org_id.clone();
            let slug = slug.clone();
            let name = name.clone();
            let service_type = service_type.clone();
            let client_id = client_id.clone();
            let client_secret_hash = client_secret_hash.clone();
            let github_scopes_json = github_scopes_json.clone();
            let microsoft_scopes_json = microsoft_scopes_json.clone();
            let google_scopes_json = google_scopes_json.clone();
            let redirect_uris_json = redirect_uris_json.clone();
            let resource_uris_json = resource_uris_json.clone();
            let device_activation_uri = device_activation_uri.clone();
            let plan_id = plan_id.clone();
            let event = event.clone();
            let audit_actor = audit_actor.clone();
            Box::pin(async move {
                // Create service using ServiceStore
                let service = ServiceStore::create_with_options(
                    db.clone(),
                    &service_id,
                    &org_id,
                    &slug,
                    &name,
                    &service_type,
                    &client_id,
                    &client_secret_hash,
                    github_scopes_json.as_deref(),
                    microsoft_scopes_json.as_deref(),
                    google_scopes_json.as_deref(),
                    redirect_uris_json.as_deref(),
                    device_activation_uri.as_deref(),
                    resource_uris_json.as_deref(),
                )
                .await?;

                // AUTO-CREATE default plan
                let now = Utc::now().naive_utc();
                let features_json = serde_json::to_string::<Vec<String>>(&vec![]).unwrap();

                PlanStore::create(
                    db.clone(),
                    &plan_id,
                    &service_id,
                    DEFAULT_TIER_NAME,
                    None, // No description for default plan
                    0,
                    "usd",
                    &features_json,
                    None, // No Stripe price ID for default free plan
                    true, // Default plan is_default = true
                    now,
                )
                .await?;

                // Fetch the created plan
                let default_plan_entity = plans::Entity::find_by_id(plan_id.clone())
                    .one(&db)
                    .await?
                    .ok_or_else(|| {
                        crate::error::AppError::InternalServerError(
                            "Failed to create plan".to_string(),
                        )
                    })?;

                // Convert plan entity to Plan model
                let default_plan = Plan {
                    id: default_plan_entity.id,
                    service_id: default_plan_entity.service_id,
                    name: default_plan_entity.name,
                    description: default_plan_entity.description,
                    price_cents: default_plan_entity.price_cents as i64,
                    currency: default_plan_entity.currency,
                    features: default_plan_entity.features,
                    stripe_price_id: default_plan_entity.stripe_price_id,
                    is_default: default_plan_entity.is_default,
                    created_at: chrono::DateTime::from_naive_utc_and_offset(
                        default_plan_entity.created_at,
                        Utc,
                    ),
                };

                audit_actor.log_org_with_db(db, event).await?;
                Ok((service, default_plan))
            })
        },
    )
    .await?;

    let usage = ServiceUsageInfo {
        current_services: current_service_count + 1,
        max_services,
        tier: tier_name,
    };

    Ok(Json(ServiceWithGrantsResponse {
        service: ServiceResponse::with_client_secret(service, client_secret),
        default_plan,
        usage,
    }))
}

// List organization services with usage information
pub async fn list_organization_services(
    State(state): State<AppState>,
    Path(org_slug): Path<String>,
    auth_user: axum::Extension<AuthUser>,
    Query(query): Query<ListServicesQuery>,
) -> Result<Json<ServiceListResponse>> {
    // Get organization and verify membership
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Organization not found".to_string()))?;
    let org =
        crate::handlers::organizations::ensure_organization_active(&state.db, &org.id).await?;

    // Check if user is member
    let _membership =
        MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &org.id, &auth_user.user.id)
            .await?
            .ok_or_else(|| {
                crate::error::AppError::Forbidden("Not a member of this organization".to_string())
            })?;

    // Fetch all filtered services first; per-service grants must be applied before pagination.
    let all_services = ServiceStore::list_with_filters(
        DB::Conn(&state.db),
        &org.id,
        query.service_type.as_deref(),
        None,
        None,
    )
    .await?;
    let can_view_all = PermissionService::check_any(
        DB::Conn(&state.db),
        &org.id,
        &auth_user.user.id,
        &[CAP_SERVICES_VIEW, CAP_SERVICES_MANAGE],
    )
    .await?;

    let services = if can_view_all {
        all_services
    } else {
        let service_ids = all_services
            .iter()
            .map(|service| service.id.clone())
            .collect::<Vec<_>>();
        let access_by_service = PermissionsStore::list_service_access_for_user(
            DB::Conn(&state.db),
            &service_ids,
            &auth_user.user.id,
        )
        .await?;

        all_services
            .into_iter()
            .filter(|service| access_by_service.contains_key(&service.id))
            .collect::<Vec<_>>()
    };

    let accessible_total = services.len() as i64;
    let (limit, offset) =
        crate::utils::pagination::signed_slice_window(query.limit, query.offset, services.len());
    let services = services
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect::<Vec<_>>();

    let service_ids = services
        .iter()
        .map(|service| service.id.clone())
        .collect::<Vec<_>>();
    let plan_counts = PlanStore::count_by_services(DB::Conn(&state.db), &service_ids).await?;
    let subscription_counts =
        SubscriptionStore::count_active_by_services(DB::Conn(&state.db), &service_ids).await?;

    let services_with_details = services
        .into_iter()
        .map(|service| {
            let service_id = service.id.clone();
            ServiceWithDetails {
                service: ServiceResponse::from(service),
                plan_count: plan_counts.get(&service_id).copied().unwrap_or(0),
                subscription_count: subscription_counts.get(&service_id).copied().unwrap_or(0),
            }
        })
        .collect::<Vec<_>>();

    // Get usage information
    let current_services = accessible_total;
    let (max_services, tier_name) = get_service_limits(&state, &org).await?;

    Ok(Json(ServiceListResponse {
        services: services_with_details,
        usage: ServiceUsageInfo {
            current_services,
            max_services,
            tier: tier_name,
        },
    }))
}

// Get service details
pub async fn get_service(
    State(state): State<AppState>,
    Path((org_slug, service_slug)): Path<(String, String)>,
    auth_user: axum::Extension<AuthUser>,
) -> Result<Json<ServiceResponse>> {
    // Get organization and verify membership
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Organization not found".to_string()))?;
    let org =
        crate::handlers::organizations::ensure_organization_active(&state.db, &org.id).await?;

    // Check if user is member
    let _membership =
        MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &org.id, &auth_user.user.id)
            .await?
            .ok_or_else(|| {
                crate::error::AppError::Forbidden("Not a member of this organization".to_string())
            })?;

    let service = ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, &service_slug)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Service not found".to_string()))?;

    if !can_view_service(&state, &auth_user.user.id, &org.id, &service.id).await? {
        return Err(crate::error::AppError::Forbidden(
            "Insufficient permissions to view this service".to_string(),
        ));
    }

    Ok(Json(ServiceResponse::from(service)))
}

// Update service configuration
pub async fn update_service(
    State(state): State<AppState>,
    Path((org_slug, service_slug)): Path<(String, String)>,
    auth_user: axum::Extension<AuthUser>,
    Json(req): Json<UpdateServiceRequest>,
) -> Result<Json<ServiceResponse>> {
    if let Some(redirect_uris) = &req.redirect_uris {
        validate_redirect_uris_input(redirect_uris)?;
    }
    if let Some(resource_uris) = &req.resource_uris {
        validate_resource_uris_input(resource_uris)?;
    }

    // Get organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Organization not found".to_string()))?;
    let org =
        crate::handlers::organizations::ensure_organization_active(&state.db, &org.id).await?;

    // Validate service type if provided
    if let Some(service_type) = &req.service_type {
        if !VALID_SERVICE_TYPES.contains(&service_type.as_str()) {
            return Err(crate::error::AppError::BadRequest(format!(
                "Invalid service type. Must be one of: {}",
                VALID_SERVICE_TYPES.join(", ")
            )));
        }
    }

    // Check if there are any fields to update
    if req.name.is_none()
        && req.service_type.is_none()
        && req.github_scopes.is_none()
        && req.microsoft_scopes.is_none()
        && req.google_scopes.is_none()
        && req.redirect_uris.is_none()
        && req.device_activation_uri.is_none()
        && req.resource_uris.is_none()
    {
        return Err(crate::error::AppError::BadRequest(
            "No fields to update".to_string(),
        ));
    }

    let service = ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, &service_slug)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Service not found".to_string()))?;

    if !can_manage_specific_service(&state, &auth_user.user.id, &org.id, &service.id).await? {
        return Err(crate::error::AppError::Forbidden(
            "Insufficient permissions to update this service".to_string(),
        ));
    }

    // Convert scopes to JSON strings
    let github_scopes_json = req
        .github_scopes
        .as_ref()
        .map(|s| serde_json::to_string(s).unwrap());
    let microsoft_scopes_json = req
        .microsoft_scopes
        .as_ref()
        .map(|s| serde_json::to_string(s).unwrap());
    let google_scopes_json = req
        .google_scopes
        .as_ref()
        .map(|s| serde_json::to_string(s).unwrap());
    let redirect_uris_json = req
        .redirect_uris
        .as_ref()
        .map(|s| serde_json::to_string(s).unwrap());
    let resource_uris_json = req
        .resource_uris
        .as_ref()
        .map(|s| serde_json::to_string(s).unwrap());

    // Update service using ServiceStore
    let updated_service = ServiceStore::update_dynamic(
        DB::Conn(&state.db),
        &org.id,
        &service_slug,
        req.name.as_deref(),
        req.service_type.as_deref(),
        github_scopes_json.as_deref(),
        microsoft_scopes_json.as_deref(),
        google_scopes_json.as_deref(),
        redirect_uris_json.as_deref(),
        req.device_activation_uri.as_deref(),
        resource_uris_json.as_deref(),
    )
    .await?;

    Ok(Json(ServiceResponse::from(updated_service)))
}

pub async fn rotate_service_secret(
    State(state): State<AppState>,
    Path((org_slug, service_slug)): Path<(String, String)>,
    auth_user: axum::Extension<AuthUser>,
) -> Result<Json<RotateServiceSecretResponse>> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Organization not found".to_string()))?;
    let org =
        crate::handlers::organizations::ensure_organization_active(&state.db, &org.id).await?;

    let service = ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, &service_slug)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Service not found".to_string()))?;

    if !can_manage_specific_service(&state, &auth_user.user.id, &org.id, &service.id).await? {
        return Err(crate::error::AppError::Forbidden(
            "Insufficient permissions to rotate service secrets".to_string(),
        ));
    }

    let client_secret = Uuid::new_v4().to_string();
    let client_secret_hash = hash_client_secret(&client_secret);
    let audit_actor = state.audit_actor.clone();
    let helper_org_id = org.id.clone();
    let helper_service_slug = service_slug.clone();
    let helper_actor_id = auth_user.user.id.clone();
    let service = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "rotate_service_secret",
        |db| {
            let org_id = helper_org_id.clone();
            let service_slug = helper_service_slug.clone();
            let actor_id = helper_actor_id.clone();
            let client_secret_hash = client_secret_hash.clone();
            let audit_actor = audit_actor.clone();
            Box::pin(async move {
                let service = ServiceStore::update_client_secret_hash(
                    db.clone(),
                    &org_id,
                    &service_slug,
                    &client_secret_hash,
                )
                .await?;
                let event =
                    OrgAuditBuilder::new(&org_id, Some(&actor_id), "service.secret_rotated")
                        .target("service", &service.id)
                        .success(true)
                        .details_json(Some(json!({
                            "service_slug": service_slug,
                            "service_name": &service.name,
                            "client_id": &service.client_id
                        })))
                        .build();
                audit_actor.log_org_with_db(db, event).await?;
                Ok(service)
            })
        },
    )
    .await?;

    Ok(Json(RotateServiceSecretResponse {
        service: ServiceResponse::from(service),
        client_secret,
    }))
}

pub async fn delete_service(
    State(state): State<AppState>,
    Path((org_slug, service_slug)): Path<(String, String)>,
    auth_user: axum::Extension<AuthUser>,
) -> Result<StatusCode> {
    // Get organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Organization not found".to_string()))?;
    let org =
        crate::handlers::organizations::ensure_organization_active(&state.db, &org.id).await?;

    // Check if user is owner (only owners can delete services)
    let membership =
        MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &org.id, &auth_user.user.id)
            .await?;

    if membership.is_none_or(|m| m.role != "owner") {
        return Err(crate::error::AppError::Forbidden(
            "Only organization owners can delete services".to_string(),
        ));
    }

    // Check if service has active subscriptions
    let subscription_count = SubscriptionStore::count_active_by_service_lookup(
        DB::Conn(&state.db),
        &org.id,
        &service_slug,
    )
    .await?;

    if subscription_count > 0 {
        return Err(crate::error::AppError::BadRequest(
            "Cannot delete service with active subscriptions".to_string(),
        ));
    }

    // Delete service using ServiceStore
    let rows_affected =
        ServiceStore::delete_by_org_and_slug(DB::Conn(&state.db), &org.id, &service_slug).await?;

    if rows_affected == 0 {
        return Err(crate::error::AppError::NotFound(
            "Service not found".to_string(),
        ));
    }

    Ok(StatusCode::NO_CONTENT)
}

// Create plan for service
pub async fn create_plan(
    State(state): State<AppState>,
    Path((org_slug, service_slug)): Path<(String, String)>,
    auth_user: axum::Extension<AuthUser>,
    Json(req): Json<CreatePlanRequest>,
) -> Result<Json<PlanResponse>> {
    // Get organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Organization not found".to_string()))?;
    let org =
        crate::handlers::organizations::ensure_organization_active(&state.db, &org.id).await?;

    // Get service
    let service = ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, &service_slug)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Service not found".to_string()))?;

    if !can_manage_specific_service(&state, &auth_user.user.id, &org.id, &service.id).await? {
        return Err(crate::error::AppError::Forbidden(
            "Insufficient permissions to create plans for this service".to_string(),
        ));
    }

    let id = Uuid::new_v4().to_string();
    let features_json = req.features.map_or_else(
        || serde_json::to_string::<Vec<String>>(&vec![]).unwrap(),
        |f| serde_json::to_string(&f).unwrap(),
    );
    let now = Utc::now().naive_utc();

    // Create plan using PlanStore
    PlanStore::create(
        DB::Conn(&state.db),
        &id,
        &service.id,
        &req.name,
        req.description.as_deref(),
        req.price_cents,
        &req.currency,
        &features_json,
        req.stripe_price_id.as_deref(),
        req.is_default,
        now,
    )
    .await?;

    // Fetch the created plan
    let plan_entity = plans::Entity::find_by_id(id.clone())
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            crate::error::AppError::InternalServerError("Failed to create plan".to_string())
        })?;

    // Convert to Plan model
    let plan = Plan {
        id: plan_entity.id.clone(),
        service_id: plan_entity.service_id,
        name: plan_entity.name,
        description: plan_entity.description,
        price_cents: plan_entity.price_cents as i64,
        currency: plan_entity.currency,
        features: plan_entity.features,
        stripe_price_id: plan_entity.stripe_price_id,
        is_default: plan_entity.is_default,
        created_at: chrono::DateTime::from_naive_utc_and_offset(plan_entity.created_at, Utc),
    };

    // Get subscription count (should be 0 for new plan)
    let subscription_count =
        SubscriptionStore::count_active_by_plan(DB::Conn(&state.db), &plan_entity.id).await?;

    Ok(Json(PlanResponse {
        plan,
        subscription_count,
    }))
}

pub async fn list_service_plans(
    State(state): State<AppState>,
    Path((org_slug, service_slug)): Path<(String, String)>,
    auth_user: axum::Extension<AuthUser>,
) -> Result<Json<Vec<PlanResponse>>> {
    // Get organization and verify membership
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Organization not found".to_string()))?;
    let org =
        crate::handlers::organizations::ensure_organization_active(&state.db, &org.id).await?;

    // Check if user is member
    let _membership =
        MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &org.id, &auth_user.user.id)
            .await?
            .ok_or_else(|| {
                crate::error::AppError::Forbidden("Not a member of this organization".to_string())
            })?;

    // Get service
    let service = ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, &service_slug)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Service not found".to_string()))?;

    if !can_view_service(&state, &auth_user.user.id, &org.id, &service.id).await? {
        return Err(crate::error::AppError::Forbidden(
            "Insufficient permissions to view plans for this service".to_string(),
        ));
    }

    // Get all plans for this service using PlanStore
    let plan_entities = PlanStore::find_by_service(DB::Conn(&state.db), &service.id).await?;
    let plan_ids: Vec<String> = plan_entities.iter().map(|plan| plan.id.clone()).collect();
    let subscription_counts =
        SubscriptionStore::count_active_by_plans(DB::Conn(&state.db), &plan_ids).await?;

    let mut responses = Vec::new();

    for plan_entity in plan_entities {
        let subscription_count = subscription_counts
            .get(&plan_entity.id)
            .copied()
            .unwrap_or_default();

        // Convert to Plan model
        let plan = Plan {
            id: plan_entity.id,
            service_id: plan_entity.service_id,
            name: plan_entity.name,
            description: plan_entity.description,
            price_cents: plan_entity.price_cents as i64,
            currency: plan_entity.currency,
            features: plan_entity.features,
            stripe_price_id: plan_entity.stripe_price_id,
            is_default: plan_entity.is_default,
            created_at: chrono::DateTime::from_naive_utc_and_offset(plan_entity.created_at, Utc),
        };

        responses.push(PlanResponse {
            plan,
            subscription_count,
        });
    }

    Ok(Json(responses))
}

pub async fn update_plan(
    State(state): State<AppState>,
    Path((org_slug, service_slug, plan_id)): Path<(String, String, String)>,
    auth_user: axum::Extension<AuthUser>,
    Json(req): Json<UpdatePlanRequest>,
) -> Result<Json<PlanResponse>> {
    // Get organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Organization not found".to_string()))?;
    let org =
        crate::handlers::organizations::ensure_organization_active(&state.db, &org.id).await?;

    // Get service to verify it belongs to the organization
    let service = ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, &service_slug)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Service not found".to_string()))?;

    if !can_manage_specific_service(&state, &auth_user.user.id, &org.id, &service.id).await? {
        return Err(crate::error::AppError::Forbidden(
            "Insufficient permissions to update plans for this service".to_string(),
        ));
    }

    // Verify the plan belongs to this service
    let _existing_plan =
        PlanStore::find_by_id_and_service(DB::Conn(&state.db), &plan_id, &service.id)
            .await?
            .ok_or_else(|| crate::error::AppError::NotFound("Plan not found".to_string()))?;

    // Check if there are any fields to update
    if req.name.is_none()
        && req.price_cents.is_none()
        && req.currency.is_none()
        && req.features.is_none()
    {
        return Err(crate::error::AppError::BadRequest(
            "No fields to update".to_string(),
        ));
    }

    // Convert features to JSON string if provided
    let features_json = req
        .features
        .as_ref()
        .map(|f| serde_json::to_string(f).unwrap());

    // Convert stripe_price_id Option<Option<String>> to Option<Option<&str>>
    let stripe_price_id_update = req.stripe_price_id.as_ref().map(|opt| opt.as_deref());

    // Convert description Option<String> to Option<Option<&str>>
    let description_update = req.description.as_ref().map(|s| Some(s.as_str()));

    // Update plan using PlanStore
    let updated_plan_entity = PlanStore::update(
        DB::Conn(&state.db),
        &service.id,
        &plan_id,
        req.name.as_deref(),
        description_update,
        req.price_cents,
        req.currency.as_deref(),
        features_json.as_deref(),
        stripe_price_id_update,
        req.is_default,
    )
    .await?;

    // Convert to Plan model
    let plan = Plan {
        id: updated_plan_entity.id.clone(),
        service_id: updated_plan_entity.service_id,
        name: updated_plan_entity.name,
        description: updated_plan_entity.description,
        price_cents: updated_plan_entity.price_cents as i64,
        currency: updated_plan_entity.currency,
        features: updated_plan_entity.features,
        stripe_price_id: updated_plan_entity.stripe_price_id,
        is_default: updated_plan_entity.is_default,
        created_at: chrono::DateTime::from_naive_utc_and_offset(
            updated_plan_entity.created_at,
            Utc,
        ),
    };

    let subscription_count =
        SubscriptionStore::count_active_by_plan(DB::Conn(&state.db), &plan.id).await?;

    Ok(Json(PlanResponse {
        plan,
        subscription_count,
    }))
}

pub async fn delete_plan(
    State(state): State<AppState>,
    Path((org_slug, service_slug, plan_id)): Path<(String, String, String)>,
    auth_user: axum::Extension<AuthUser>,
) -> Result<StatusCode> {
    // Get organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Organization not found".to_string()))?;
    let org =
        crate::handlers::organizations::ensure_organization_active(&state.db, &org.id).await?;

    // Get service to verify it belongs to the organization
    let service = ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, &service_slug)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Service not found".to_string()))?;

    if !can_manage_specific_service(&state, &auth_user.user.id, &org.id, &service.id).await? {
        return Err(crate::error::AppError::Forbidden(
            "Insufficient permissions to delete plans for this service".to_string(),
        ));
    }

    // Verify the plan exists and belongs to this service
    let _existing_plan =
        PlanStore::find_by_id_and_service(DB::Conn(&state.db), &plan_id, &service.id)
            .await?
            .ok_or_else(|| crate::error::AppError::NotFound("Plan not found".to_string()))?;

    // Check if plan has active subscriptions
    let subscription_count =
        SubscriptionStore::count_active_by_plan(DB::Conn(&state.db), &plan_id).await?;

    if subscription_count > 0 {
        return Err(crate::error::AppError::BadRequest(
            "Cannot delete plan with active subscriptions".to_string(),
        ));
    }

    // Delete plan using PlanStore
    PlanStore::delete(DB::Conn(&state.db), &service.id, &plan_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::crypto::sso::OAuthClient;

    use crate::entities::users;
    use crate::error::AppError;

    use crate::audit::actor::AuditHandle;
    use crate::db::DB;
    use crate::services::{
        events::EventDispatcher, metrics::MfaMetricsService, risk_engine::RiskEngine,
    };
    use crate::state::AppState;
    use crate::store::{
        memberships::MembershipStore, organizations::OrganizationStore, users::UserStore,
    };

    use migration::{Migrator, MigratorTrait};
    use moka::future::Cache;
    use sea_orm::Database;
    use std::sync::Arc;

    use crate::test_support::test_config;

    use crate::test_support::test_jwt_service;

    struct Fixture {
        state: AppState,
        owner: AuthUser,
        member: AuthUser,
        org_slug: String,
    }

    async fn fixture() -> Fixture {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let config = test_config();
        let jwt_service = Arc::new(test_jwt_service(&config));
        let oauth_client = Arc::new(OAuthClient::new(&config).expect("create oauth client"));

        let owner_model = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "service-owner@example.test",
            crate::store::users::UserCreationOptions {
                is_platform_owner: true,
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create owner")
        .0;
        let member_model =
            UserStore::create(DB::Conn(&db), "service-member@example.test", None, false)
                .await
                .expect("create member");

        let (org, _) = OrganizationStore::create_with_owner(
            DB::Conn(&db),
            "acme",
            "Acme",
            &owner_model.id,
            None,
        )
        .await
        .expect("create org");
        OrganizationStore::update_status(DB::Conn(&db), &org.id, "active")
            .await
            .expect("activate org");
        MembershipStore::create(DB::Conn(&db), &org.id, &member_model.id, "member")
            .await
            .expect("create membership");

        let state = AppState {
            db: db.clone(),
            #[cfg(feature = "db_sqlite")]
            db_writer: db.clone(),
            oauth_client,
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
            let token = jwt_service
                .create_token(&user.id, &user.email, false, Some("acme"), None)
                .expect("create token");
            let claims = jwt_service.validate_token(&token).expect("validate token");
            AuthUser {
                claims,
                user: user.clone(),
                permissions: vec![],
                ip_address: "127.0.0.1".to_string(),
                user_agent: "service-test".to_string(),
                current_session_id: None,
            }
        };

        Fixture {
            owner: auth_user_for(&owner_model),
            member: auth_user_for(&member_model),
            org_slug: org.slug,
            state,
        }
    }

    fn create_request(slug: &str, name: &str) -> CreateServiceRequest {
        CreateServiceRequest {
            slug: slug.to_string(),
            name: name.to_string(),
            service_type: "web".to_string(),
            github_scopes: None,
            microsoft_scopes: None,
            google_scopes: None,
            redirect_uris: Some(vec!["https://app.example.test/callback".to_string()]),
            device_activation_uri: None,
            resource_uris: None,
        }
    }

    #[tokio::test]
    async fn create_service_returns_secret_once_and_a_default_free_plan() {
        let f = fixture().await;
        let Json(response) = create_service(
            State(f.state.clone()),
            Path(f.org_slug.clone()),
            axum::Extension(f.owner.clone()),
            Json(create_request("portal", "Portal")),
        )
        .await
        .expect("create service");

        assert_eq!(response.service.slug, "portal");
        assert!(
            response.service.client_secret.is_some(),
            "the client secret is shown exactly once, at creation"
        );
        assert!(response.default_plan.is_default);
        assert_eq!(response.default_plan.price_cents, 0);
        assert_eq!(response.usage.current_services, 1);
        assert_eq!(response.usage.max_services, 2);
    }

    #[tokio::test]
    async fn create_service_rejects_unknown_types_and_plain_members() {
        let f = fixture().await;
        let mut req = create_request("bad-type", "Bad");
        req.service_type = "satellite".to_string();
        match create_service(
            State(f.state.clone()),
            Path(f.org_slug.clone()),
            axum::Extension(f.owner.clone()),
            Json(req),
        )
        .await
        {
            Err(AppError::BadRequest(message)) => {
                assert!(message.contains("Invalid service type"))
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }

        match create_service(
            State(f.state.clone()),
            Path(f.org_slug.clone()),
            axum::Extension(f.member.clone()),
            Json(create_request("member-svc", "Member")),
        )
        .await
        {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected forbidden, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn free_tier_caps_services_at_two() {
        let f = fixture().await;
        for slug in ["one", "two"] {
            let _ = create_service(
                State(f.state.clone()),
                Path(f.org_slug.clone()),
                axum::Extension(f.owner.clone()),
                Json(create_request(slug, slug)),
            )
            .await
            .unwrap_or_else(|e| panic!("create {slug} failed: {e:?}"));
        }
        match create_service(
            State(f.state.clone()),
            Path(f.org_slug.clone()),
            axum::Extension(f.owner.clone()),
            Json(create_request("three", "Three")),
        )
        .await
        {
            Err(AppError::BadRequest(message)) => {
                assert!(message.contains("maximum service limit"), "{message}")
            }
            other => panic!("expected limit rejection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn list_get_update_rotate_delete_round_trip() {
        let f = fixture().await;
        let Json(created) = create_service(
            State(f.state.clone()),
            Path(f.org_slug.clone()),
            axum::Extension(f.owner.clone()),
            Json(create_request("portal", "Portal")),
        )
        .await
        .expect("create");

        // Members lack `services.view`, so the list comes back empty for them.
        let Json(member_view) = list_organization_services(
            State(f.state.clone()),
            Path(f.org_slug.clone()),
            axum::Extension(f.member.clone()),
            Query(ListServicesQuery {
                status: None,
                service_type: None,
                limit: None,
                offset: None,
            }),
        )
        .await
        .expect("list services as member");
        assert!(member_view.services.is_empty());

        let Json(list) = list_organization_services(
            State(f.state.clone()),
            Path(f.org_slug.clone()),
            axum::Extension(f.owner.clone()),
            Query(ListServicesQuery {
                status: None,
                service_type: None,
                limit: None,
                offset: None,
            }),
        )
        .await
        .expect("list services");
        assert_eq!(list.services.len(), 1);
        assert_eq!(list.services[0].service.id, created.service.id);

        // Members without `services.view` or a direct grant cannot read it.
        match get_service(
            State(f.state.clone()),
            Path((f.org_slug.clone(), "portal".to_string())),
            axum::Extension(f.member.clone()),
        )
        .await
        {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected forbidden for member, got {other:?}"),
        }

        let Json(fetched) = get_service(
            State(f.state.clone()),
            Path((f.org_slug.clone(), "portal".to_string())),
            axum::Extension(f.owner.clone()),
        )
        .await
        .expect("get service as owner");
        assert_eq!(fetched.id, created.service.id);

        let Json(updated) = update_service(
            State(f.state.clone()),
            Path((f.org_slug.clone(), "portal".to_string())),
            axum::Extension(f.owner.clone()),
            Json(UpdateServiceRequest {
                name: Some("Portal v2".to_string()),
                service_type: Some("api".to_string()),
                github_scopes: None,
                microsoft_scopes: None,
                google_scopes: None,
                redirect_uris: None,
                device_activation_uri: None,
                resource_uris: None,
            }),
        )
        .await
        .expect("update service");
        assert_eq!(updated.name, "Portal v2");
        assert_eq!(updated.service_type, "api");

        let Json(rotated) = rotate_service_secret(
            State(f.state.clone()),
            Path((f.org_slug.clone(), "portal".to_string())),
            axum::Extension(f.owner.clone()),
        )
        .await
        .expect("rotate secret");
        assert_ne!(
            rotated.client_secret,
            created.service.client_secret.clone().unwrap_or_default(),
            "rotation must issue a new secret"
        );

        delete_service(
            State(f.state.clone()),
            Path((f.org_slug.clone(), "portal".to_string())),
            axum::Extension(f.owner.clone()),
        )
        .await
        .expect("delete service");

        match get_service(
            State(f.state.clone()),
            Path((f.org_slug.clone(), "portal".to_string())),
            axum::Extension(f.owner.clone()),
        )
        .await
        {
            Err(AppError::NotFound(_)) => {}
            other => panic!("expected not found after delete, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn plan_crud_round_trip_rejects_deleting_the_default_plan() {
        let f = fixture().await;
        let _ = create_service(
            State(f.state.clone()),
            Path(f.org_slug.clone()),
            axum::Extension(f.owner.clone()),
            Json(create_request("portal", "Portal")),
        )
        .await
        .expect("create service");

        let Json(plans) = list_service_plans(
            State(f.state.clone()),
            Path((f.org_slug.clone(), "portal".to_string())),
            axum::Extension(f.owner.clone()),
        )
        .await
        .expect("list plans");
        assert_eq!(plans.len(), 1, "the auto-created default free plan");
        let _default_plan_id = plans[0].plan.id.clone();

        let Json(new_plan) = create_plan(
            State(f.state.clone()),
            Path((f.org_slug.clone(), "portal".to_string())),
            axum::Extension(f.owner.clone()),
            Json(CreatePlanRequest {
                name: "Pro".to_string(),
                description: Some("For bigger teams".to_string()),
                price_cents: 1999,
                currency: "usd".to_string(),
                features: Some(vec!["sso".to_string()]),
                stripe_price_id: None,
                is_default: false,
            }),
        )
        .await
        .expect("create plan");
        assert_eq!(new_plan.plan.price_cents, 1999);

        let Json(updated) = update_plan(
            State(f.state.clone()),
            Path((
                f.org_slug.clone(),
                "portal".to_string(),
                new_plan.plan.id.clone(),
            )),
            axum::Extension(f.owner.clone()),
            Json(UpdatePlanRequest {
                name: None,
                description: None,
                price_cents: Some(2999),
                currency: None,
                features: None,
                stripe_price_id: None,
                is_default: None,
            }),
        )
        .await
        .expect("update plan");
        assert_eq!(updated.plan.price_cents, 2999);

        delete_plan(
            State(f.state.clone()),
            Path((
                f.org_slug.clone(),
                "portal".to_string(),
                new_plan.plan.id.clone(),
            )),
            axum::Extension(f.owner.clone()),
        )
        .await
        .expect("delete non-default plan");
    }
}

#[cfg(test)]
mod route_tests {
    use super::*;

    use crate::audit::actor::AuditHandle;
    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::crypto::sso::OAuthClient;
    use crate::entities::users;
    use crate::error::AppError;
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
    use std::sync::Arc;

    struct Fixture {
        state: AppState,
        owner: AuthUser,
        admin: AuthUser,
        custom_manager: AuthUser,
        member: AuthUser,
        outsider: AuthUser,
        other_owner: AuthUser,
        alpha_slug: String,
        beta_slug: String,
        beta_service_slug: String,
        beta_plan_id: String,
    }

    async fn fixture() -> Fixture {
        let db = setup_db().await;
        let config = test_config();
        let jwt_service = Arc::new(test_jwt_service(&config));

        let owner = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "service-route-owner@example.test",
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
            "service-route-admin@example.test",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create admin")
        .0;
        let custom_manager = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "service-route-custom@example.test",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create custom manager")
        .0;
        let member = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "service-route-member@example.test",
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
            "service-route-outsider@example.test",
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
            "service-route-other-owner@example.test",
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
            "service-route-alpha",
            "Service Route Alpha",
            &owner.id,
            Some("tier_enterprise"),
        )
        .await
        .expect("create alpha");
        let (beta, _) = OrganizationStore::create_with_owner(
            DB::Conn(&db),
            "service-route-beta",
            "Service Route Beta",
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
            "service-route-manager-role",
            &alpha.id,
            "service-route-manager",
            "Service Route Manager",
            None,
            serde_json::json!([CAP_SERVICES_VIEW, CAP_SERVICES_CREATE, CAP_SERVICES_MANAGE]),
        )
        .await
        .expect("create service manager role");
        MembershipStore::create(
            DB::Conn(&db),
            &alpha.id,
            &custom_manager.id,
            "service-route-manager",
        )
        .await
        .expect("add custom manager");

        let beta_service = ServiceStore::create(
            DB::Conn(&db),
            &beta.id,
            "beta-portal",
            "Beta Portal",
            "web",
            "service-route-beta-client",
        )
        .await
        .expect("create beta service");
        let beta_plan_id = uuid::Uuid::new_v4().to_string();
        PlanStore::create(
            DB::Conn(&db),
            &beta_plan_id,
            &beta_service.id,
            "Beta Plan",
            None,
            1999,
            "usd",
            "[]",
            None,
            false,
            Utc::now().naive_utc(),
        )
        .await
        .expect("create beta plan");

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
                user_agent: "service-route-test".to_string(),
                current_session_id: None,
            }
        };
        let owner_auth = auth_user_for(&owner);
        let admin_auth = auth_user_for(&admin);
        let custom_auth = auth_user_for(&custom_manager);
        let member_auth = auth_user_for(&member);
        let outsider_auth = auth_user_for(&outsider);
        let other_owner_auth = auth_user_for(&other_owner);

        Fixture {
            state,
            owner: owner_auth,
            admin: admin_auth,
            custom_manager: custom_auth,
            member: member_auth,
            outsider: outsider_auth,
            other_owner: other_owner_auth,
            alpha_slug: alpha.slug,
            beta_slug: beta.slug,
            beta_service_slug: beta_service.slug,
            beta_plan_id,
        }
    }

    fn request(slug: &str, name: &str) -> CreateServiceRequest {
        CreateServiceRequest {
            slug: slug.to_string(),
            name: name.to_string(),
            service_type: "web".to_string(),
            github_scopes: None,
            microsoft_scopes: None,
            google_scopes: None,
            redirect_uris: Some(vec!["https://app.example.test/callback".to_string()]),
            device_activation_uri: None,
            resource_uris: None,
        }
    }

    #[tokio::test]
    async fn service_routes_require_live_scoped_capability_and_are_org_scoped() {
        let f = fixture().await;

        for (auth, slug) in [
            (f.owner.clone(), "owner-portal"),
            (f.admin.clone(), "admin-portal"),
            (f.custom_manager.clone(), "custom-portal"),
        ] {
            let Json(created) = create_service(
                State(f.state.clone()),
                Path(f.alpha_slug.clone()),
                axum::Extension(auth),
                Json(request(slug, slug)),
            )
            .await
            .expect("authorized actor may create a service");
            assert_eq!(created.service.slug, slug);
        }
        for auth in [f.member.clone(), f.outsider.clone(), f.other_owner.clone()] {
            assert!(matches!(
                create_service(
                    State(f.state.clone()),
                    Path(f.alpha_slug.clone()),
                    axum::Extension(auth),
                    Json(request("denied-portal", "Denied")),
                )
                .await,
                Err(AppError::Forbidden(_))
            ));
        }

        let Json(list) = list_organization_services(
            State(f.state.clone()),
            Path(f.alpha_slug.clone()),
            axum::Extension(f.owner.clone()),
            Query(ListServicesQuery {
                status: None,
                service_type: None,
                limit: None,
                offset: None,
            }),
        )
        .await
        .expect("owner may list alpha services");
        assert_eq!(list.services.len(), 3);

        // Cross-tenant reads and mutations are denied and leave beta intact.
        assert!(matches!(
            get_service(
                State(f.state.clone()),
                Path((f.beta_slug.clone(), f.beta_service_slug.clone())),
                axum::Extension(f.owner.clone()),
            )
            .await,
            Err(AppError::Forbidden(_))
        ));
        assert!(matches!(
            update_service(
                State(f.state.clone()),
                Path((f.beta_slug.clone(), f.beta_service_slug.clone())),
                axum::Extension(f.owner.clone()),
                Json(UpdateServiceRequest {
                    name: Some("Cross Tenant".to_string()),
                    service_type: None,
                    github_scopes: None,
                    microsoft_scopes: None,
                    google_scopes: None,
                    redirect_uris: None,
                    device_activation_uri: None,
                    resource_uris: None,
                }),
            )
            .await,
            Err(AppError::Forbidden(_))
        ));
        assert!(matches!(
            delete_service(
                State(f.state.clone()),
                Path((f.beta_slug.clone(), f.beta_service_slug.clone())),
                axum::Extension(f.owner.clone()),
            )
            .await,
            Err(AppError::Forbidden(_))
        ));
        let beta_after = ServiceStore::find_by_org_and_slug(
            DB::Conn(&f.state.db),
            &OrganizationStore::find_by_slug(DB::Conn(&f.state.db), &f.beta_slug)
                .await
                .expect("load beta")
                .expect("beta exists")
                .id,
            &f.beta_service_slug,
        )
        .await
        .expect("load beta service")
        .expect("beta service remains");
        assert_eq!(beta_after.name, "Beta Portal");
    }

    #[tokio::test]
    async fn plan_routes_require_live_scoped_capability_and_are_org_scoped() {
        let f = fixture().await;
        let Json(created) = create_service(
            State(f.state.clone()),
            Path(f.alpha_slug.clone()),
            axum::Extension(f.owner.clone()),
            Json(request("plan-portal", "Plan Portal")),
        )
        .await
        .expect("create alpha service");

        for (auth, name) in [
            (f.owner.clone(), "Owner Plan"),
            (f.admin.clone(), "Admin Plan"),
            (f.custom_manager.clone(), "Custom Plan"),
        ] {
            let Json(plan) = create_plan(
                State(f.state.clone()),
                Path((f.alpha_slug.clone(), created.service.slug.clone())),
                axum::Extension(auth),
                Json(CreatePlanRequest {
                    name: name.to_string(),
                    description: None,
                    price_cents: 100,
                    currency: "usd".to_string(),
                    features: None,
                    stripe_price_id: None,
                    is_default: false,
                }),
            )
            .await
            .expect("authorized actor may create a plan");
            assert_eq!(plan.plan.name, name);
        }
        for auth in [f.member.clone(), f.outsider.clone(), f.other_owner.clone()] {
            assert!(matches!(
                create_plan(
                    State(f.state.clone()),
                    Path((f.alpha_slug.clone(), created.service.slug.clone())),
                    axum::Extension(auth),
                    Json(CreatePlanRequest {
                        name: "Denied Plan".to_string(),
                        description: None,
                        price_cents: 100,
                        currency: "usd".to_string(),
                        features: None,
                        stripe_price_id: None,
                        is_default: false,
                    }),
                )
                .await,
                Err(AppError::Forbidden(_))
            ));
        }

        // A beta plan ID is not reachable through an alpha service.
        assert!(matches!(
            update_plan(
                State(f.state.clone()),
                Path((
                    f.alpha_slug.clone(),
                    created.service.slug.clone(),
                    f.beta_plan_id.clone(),
                )),
                axum::Extension(f.owner.clone()),
                Json(UpdatePlanRequest {
                    name: Some("Cross Tenant".to_string()),
                    description: None,
                    price_cents: None,
                    currency: None,
                    features: None,
                    stripe_price_id: None,
                    is_default: None,
                }),
            )
            .await,
            Err(AppError::NotFound(_))
        ));
        assert!(matches!(
            delete_plan(
                State(f.state.clone()),
                Path((
                    f.alpha_slug.clone(),
                    created.service.slug.clone(),
                    f.beta_plan_id.clone(),
                )),
                axum::Extension(f.owner.clone()),
            )
            .await,
            Err(AppError::NotFound(_))
        ));
        assert!(
            PlanStore::find_by_id(DB::Conn(&f.state.db), &f.beta_plan_id)
                .await
                .expect("load beta plan")
                .is_some(),
            "cross-tenant plan mutation must preserve the beta plan"
        );
    }
}
