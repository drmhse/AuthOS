use crate::db::DB;
use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use crate::services::permission_service::{
    PermissionService, CAP_RISK_EVENTS_VIEW, CAP_RISK_POLICIES_MANAGE,
};
use axum::{
    extract::{Path, Query},
    Json,
};
use sea_orm::{
    ColumnTrait, EntityTrait, JoinType, QueryFilter, QueryOrder, QuerySelect, RelationTrait,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct RiskEventsQuery {
    pub page: Option<u64>,
    pub limit: Option<u64>,
    pub min_score: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct RiskEventResponse {
    pub id: String,
    pub user_id: String,
    pub user_email: Option<String>, // Hydrated from user
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub risk_score: i32,
    pub risk_factors: Vec<String>,
    pub risk_action: String,
    pub geo_country: Option<String>,
    pub geo_city: Option<String>,
    pub geo_lat: Option<f64>,
    pub geo_long: Option<f64>,
    pub ip_address: Option<String>,
    pub provider: String,
}

fn infer_risk_action(score: i32) -> String {
    if score >= 80 {
        "block".to_string()
    } else if score >= 50 {
        "challenge_mfa".to_string()
    } else {
        "allow".to_string()
    }
}

/// GET /api/organizations/:org_slug/risk-events
/// Returns a list of risk events for the organization
pub async fn get_risk_events(
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
    Query(params): Query<RiskEventsQuery>,
    axum::extract::State(state): axum::extract::State<crate::AppState>,
) -> Result<Json<Vec<RiskEventResponse>>> {
    use crate::store::organizations::OrganizationStore;
    let user = &auth_user.user;

    // Resolve Org Slug to ID
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
    let org =
        crate::handlers::organizations::ensure_organization_active(&state.db, &org.id).await?;

    let org_id = org.id;

    // Authorization. A token/cache snapshot is insufficient for global
    // authority, and platform authority is only accepted from a
    // platform-context token with live MFA enrollment.
    if !crate::middleware::has_live_platform_authority(&state.db, &auth_user).await? {
        let can_view = PermissionService::check_any(
            DB::Conn(&state.db),
            &org_id,
            &user.id,
            &[CAP_RISK_EVENTS_VIEW, CAP_RISK_POLICIES_MANAGE],
        )
        .await?;

        if !can_view {
            return Err(AppError::Forbidden(
                "Insufficient permissions to view security insights".to_string(),
            ));
        }
    }

    use crate::entities::login_events::{Column, Entity as LoginEvents};
    use crate::entities::users::Entity as Users;

    let (_page, limit, offset) =
        crate::utils::pagination::zero_based_u64_page(params.page, params.limit, 50, 100);
    let min_score = params.min_score.unwrap_or(0); // Default to all events with risk data

    // Join with Users to get email
    let events = LoginEvents::find()
        .join(
            JoinType::LeftJoin,
            crate::entities::login_events::Relation::Services.def(),
        )
        .filter(crate::store::login_events::tenant_login_scope(&org_id))
        .filter(Column::RiskScore.is_not_null())
        .filter(Column::RiskScore.gte(min_score))
        .find_also_related(Users)
        .order_by_desc(Column::CreatedAt)
        .offset(offset)
        .limit(limit)
        .all(&state.db)
        .await
        .map_err(|e| {
            AppError::InternalServerError(format!("Failed to fetch risk events: {}", e))
        })?;

    let response: Vec<RiskEventResponse> = events
        .into_iter()
        .map(|(event, user)| {
            let risk_factors: Vec<String> = event
                .risk_factors
                .as_ref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();

            RiskEventResponse {
                id: event.id,
                user_id: event.user_id,
                user_email: user.map(|u| u.email),
                created_at: chrono::DateTime::from_naive_utc_and_offset(
                    event.created_at,
                    chrono::Utc,
                ),
                risk_score: event.risk_score.unwrap_or(0),
                risk_factors,
                risk_action: infer_risk_action(event.risk_score.unwrap_or(0)),
                geo_country: event.geo_country,
                geo_city: event.geo_city,
                geo_lat: event.geo_lat,
                geo_long: event.geo_long,
                ip_address: event.ip_address,
                provider: event.provider,
            }
        })
        .collect();

    Ok(Json(response))
}
