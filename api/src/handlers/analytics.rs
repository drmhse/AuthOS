use crate::db::DB;
use crate::error::AppError;
use crate::middleware::AuthUser;
use crate::services::permission_service::{PermissionService, CAP_AUDIT_LOGS_VIEW};
use crate::state::AppState;
use crate::store::{
    login_events::{
        LoginEventStore, LoginTrendPoint, LoginsByProvider, LoginsByService, RecentLogin,
    },
    organizations::OrganizationStore,
};
use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::Utc;
use sea_orm::DatabaseConnection;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct AnalyticsQuery {
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub limit: Option<i64>,
}

/// GET /api/organizations/:org_slug/analytics/login-trends
pub async fn get_login_trends(
    State(state): State<AppState>,
    Path(org_slug): Path<String>,
    Query(query): Query<AnalyticsQuery>,
    auth_user: AuthUser,
) -> std::result::Result<Json<Vec<LoginTrendPoint>>, AppError> {
    let organization =
        require_org_analytics_viewer(&state.db, &auth_user.user.id, &org_slug).await?;

    // Parse date range or use defaults (last 30 days)
    let end_date = query
        .end_date
        .and_then(|s| chrono::NaiveDate::parse_from_str(&s, "%Y-%m-%d").ok())
        .unwrap_or_else(|| Utc::now().date_naive())
        .and_hms_opt(23, 59, 59)
        .unwrap();
    let start_date = query
        .start_date
        .and_then(|s| chrono::NaiveDate::parse_from_str(&s, "%Y-%m-%d").ok())
        .unwrap_or_else(|| (Utc::now() - chrono::Duration::days(30)).date_naive())
        .and_hms_opt(0, 0, 0)
        .unwrap();

    let trends = LoginEventStore::get_login_trends(
        DB::Conn(&state.db),
        &organization.id,
        start_date,
        end_date,
    )
    .await?;

    Ok(Json(trends))
}

/// GET /api/organizations/:org_slug/analytics/logins-by-service
pub async fn get_logins_by_service(
    State(state): State<AppState>,
    Path(org_slug): Path<String>,
    Query(query): Query<AnalyticsQuery>,
    auth_user: AuthUser,
) -> std::result::Result<Json<Vec<LoginsByService>>, AppError> {
    let organization =
        require_org_analytics_viewer(&state.db, &auth_user.user.id, &org_slug).await?;

    // Parse date range or use defaults (last 30 days)
    let end_date = query
        .end_date
        .and_then(|s| chrono::NaiveDate::parse_from_str(&s, "%Y-%m-%d").ok())
        .unwrap_or_else(|| Utc::now().date_naive())
        .and_hms_opt(23, 59, 59)
        .unwrap();
    let start_date = query
        .start_date
        .and_then(|s| chrono::NaiveDate::parse_from_str(&s, "%Y-%m-%d").ok())
        .unwrap_or_else(|| (Utc::now() - chrono::Duration::days(30)).date_naive())
        .and_hms_opt(0, 0, 0)
        .unwrap();

    // Query logins using store
    let logins = LoginEventStore::get_logins_by_service(
        DB::Conn(&state.db),
        &organization.id,
        start_date,
        end_date,
    )
    .await?;

    Ok(Json(logins))
}

/// GET /api/organizations/:org_slug/analytics/logins-by-provider
pub async fn get_logins_by_provider(
    State(state): State<AppState>,
    Path(org_slug): Path<String>,
    Query(query): Query<AnalyticsQuery>,
    auth_user: AuthUser,
) -> std::result::Result<Json<Vec<LoginsByProvider>>, AppError> {
    let organization =
        require_org_analytics_viewer(&state.db, &auth_user.user.id, &org_slug).await?;

    // Parse date range or use defaults (last 30 days)
    let end_date = query
        .end_date
        .and_then(|s| chrono::NaiveDate::parse_from_str(&s, "%Y-%m-%d").ok())
        .unwrap_or_else(|| Utc::now().date_naive())
        .and_hms_opt(23, 59, 59)
        .unwrap();
    let start_date = query
        .start_date
        .and_then(|s| chrono::NaiveDate::parse_from_str(&s, "%Y-%m-%d").ok())
        .unwrap_or_else(|| (Utc::now() - chrono::Duration::days(30)).date_naive())
        .and_hms_opt(0, 0, 0)
        .unwrap();

    // Query logins using store
    let logins = LoginEventStore::get_logins_by_provider(
        DB::Conn(&state.db),
        &organization.id,
        start_date,
        end_date,
    )
    .await?;

    Ok(Json(logins))
}

/// GET /api/organizations/:org_slug/analytics/recent-logins
pub async fn get_recent_logins(
    State(state): State<AppState>,
    Path(org_slug): Path<String>,
    Query(query): Query<AnalyticsQuery>,
    auth_user: AuthUser,
) -> std::result::Result<Json<Vec<RecentLogin>>, AppError> {
    let organization =
        require_org_analytics_viewer(&state.db, &auth_user.user.id, &org_slug).await?;

    let limit = query.limit.unwrap_or(10).clamp(1, 100);

    // Query recent logins using store
    let logins =
        LoginEventStore::get_recent_logins(DB::Conn(&state.db), &organization.id, limit).await?;

    Ok(Json(logins))
}

/// Resolve the current organization and authorize access to its sensitive
/// login analytics. This deliberately follows the same capability boundary as
/// tenant audit-log reads: ordinary membership alone does not expose user IDs,
/// and a suspended parent or revoked custom role takes effect immediately.
async fn require_org_analytics_viewer(
    pool: &DatabaseConnection,
    user_id: &str,
    org_slug: &str,
) -> std::result::Result<crate::entities::organizations::Model, AppError> {
    let organization = OrganizationStore::find_by_slug(DB::Conn(pool), org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
    let organization =
        crate::handlers::organizations::ensure_organization_active(pool, &organization.id).await?;

    if !PermissionService::check(
        DB::Conn(pool),
        &organization.id,
        user_id,
        CAP_AUDIT_LOGS_VIEW,
    )
    .await?
    {
        return Err(AppError::Forbidden(
            "Insufficient permissions to view organization analytics".to_string(),
        ));
    }

    Ok(organization)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::login_events;
    use crate::store::{
        memberships::MembershipStore,
        organization_roles::OrganizationRoleStore,
        services::ServiceStore,
        users::{UserCreationOptions, UserStore},
    };
    use migration::{Migrator, MigratorTrait};
    use sea_orm::{ActiveModelTrait, Database, Set};

    async fn create_user(db: &DatabaseConnection, email: &str) -> crate::entities::users::Model {
        UserStore::find_or_create_with_options(
            DB::Conn(db),
            email,
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create user")
        .0
    }

    #[tokio::test]
    async fn tenant_analytics_requires_live_scoped_capability_and_excludes_other_scopes() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");

        let owner = create_user(&db, "analytics-owner@example.com").await;
        let admin = create_user(&db, "analytics-admin@example.com").await;
        let member = create_user(&db, "analytics-member@example.com").await;
        let viewer = create_user(&db, "analytics-viewer@example.com").await;
        let outsider = create_user(&db, "analytics-outsider@example.com").await;
        let other_owner = create_user(&db, "analytics-other-owner@example.com").await;

        let org = OrganizationStore::create(
            DB::Conn(&db),
            "analytics-org",
            "Analytics Org",
            &owner.id,
            None,
        )
        .await
        .expect("create organization");
        OrganizationStore::update_status(DB::Conn(&db), &org.id, "active")
            .await
            .expect("activate organization");
        let other_org = OrganizationStore::create(
            DB::Conn(&db),
            "analytics-other-org",
            "Other Analytics Org",
            &other_owner.id,
            None,
        )
        .await
        .expect("create other organization");
        OrganizationStore::update_status(DB::Conn(&db), &other_org.id, "active")
            .await
            .expect("activate other organization");

        MembershipStore::create(DB::Conn(&db), &org.id, &owner.id, "owner")
            .await
            .expect("create owner membership");
        MembershipStore::create(DB::Conn(&db), &org.id, &admin.id, "admin")
            .await
            .expect("create admin membership");
        MembershipStore::create(DB::Conn(&db), &org.id, &member.id, "member")
            .await
            .expect("create member membership");
        OrganizationRoleStore::create(
            DB::Conn(&db),
            "analytics-viewer-role",
            &org.id,
            "analytics-viewer",
            "Analytics viewer",
            None,
            serde_json::json!([CAP_AUDIT_LOGS_VIEW]),
        )
        .await
        .expect("create custom analytics role");
        MembershipStore::create(DB::Conn(&db), &org.id, &viewer.id, "analytics-viewer")
            .await
            .expect("create custom viewer membership");
        MembershipStore::create(DB::Conn(&db), &other_org.id, &other_owner.id, "owner")
            .await
            .expect("create other owner membership");

        for allowed in [&owner, &admin, &viewer] {
            assert_eq!(
                require_org_analytics_viewer(&db, &allowed.id, &org.slug)
                    .await
                    .expect("authorized analytics viewer")
                    .id,
                org.id
            );
        }
        for denied in [&member, &outsider, &other_owner] {
            assert!(matches!(
                require_org_analytics_viewer(&db, &denied.id, &org.slug).await,
                Err(AppError::Forbidden(_))
            ));
        }
        assert!(matches!(
            require_org_analytics_viewer(&db, &owner.id, "missing-analytics-org").await,
            Err(AppError::NotFound(_))
        ));

        OrganizationStore::update_status(DB::Conn(&db), &org.id, "suspended")
            .await
            .expect("suspend organization");
        assert!(matches!(
            require_org_analytics_viewer(&db, &owner.id, &org.slug).await,
            Err(AppError::Forbidden(_))
        ));
        OrganizationStore::update_status(DB::Conn(&db), &org.id, "active")
            .await
            .expect("reactivate organization");
        OrganizationRoleStore::update(
            DB::Conn(&db),
            "analytics-viewer-role",
            None,
            None,
            Some(serde_json::json!([])),
        )
        .await
        .expect("revoke custom analytics capability");
        assert!(matches!(
            require_org_analytics_viewer(&db, &viewer.id, &org.slug).await,
            Err(AppError::Forbidden(_))
        ));

        let service = ServiceStore::create(
            DB::Conn(&db),
            &org.id,
            "primary",
            "Primary",
            "web",
            "analytics-primary-client",
        )
        .await
        .expect("create tenant service");
        let other_service = ServiceStore::create(
            DB::Conn(&db),
            &other_org.id,
            "other",
            "Other",
            "web",
            "analytics-other-client",
        )
        .await
        .expect("create other tenant service");
        let now = Utc::now().naive_utc();
        for (id, user_id, service_id, org_id, provider) in [
            (
                "analytics-event-a1",
                owner.id.as_str(),
                Some(service.id.as_str()),
                None,
                "password",
            ),
            (
                "analytics-event-a2",
                admin.id.as_str(),
                Some(service.id.as_str()),
                None,
                "github",
            ),
            (
                "analytics-event-b",
                other_owner.id.as_str(),
                Some(other_service.id.as_str()),
                None,
                "microsoft",
            ),
            (
                "analytics-event-global",
                outsider.id.as_str(),
                None,
                Some(org.id.as_str()),
                "magic",
            ),
            (
                "analytics-event-mismatch",
                outsider.id.as_str(),
                Some(other_service.id.as_str()),
                Some(org.id.as_str()),
                "passkey",
            ),
        ] {
            login_events::ActiveModel {
                id: Set(id.to_string()),
                user_id: Set(user_id.to_string()),
                service_id: Set(service_id.map(str::to_string)),
                org_id: Set(org_id.map(str::to_string)),
                provider: Set(provider.to_string()),
                created_at: Set(now),
                ..Default::default()
            }
            .insert(&db)
            .await
            .expect("insert login event fixture");
        }

        let recent = LoginEventStore::get_recent_logins(DB::Conn(&db), &org.id, 100)
            .await
            .expect("load tenant recent logins");
        assert_eq!(recent.len(), 3);
        assert!(recent.iter().any(|event| event.service_id.is_none()));
        assert!(recent
            .iter()
            .filter_map(|event| event.service_id.as_deref())
            .all(|service_id| service_id == service.id));
        assert_eq!(
            recent
                .iter()
                .filter(|event| event.user_id == outsider.id)
                .count(),
            1
        );
        assert!(recent.iter().all(|event| event.user_id != other_owner.id));

        // The defensive store clamp prevents signed-to-unsigned expansion even
        // for non-HTTP callers.
        let clamped = LoginEventStore::get_recent_logins(DB::Conn(&db), &org.id, -1)
            .await
            .expect("load clamped recent logins");
        assert_eq!(clamped.len(), 1);

        let providers = LoginEventStore::get_logins_by_provider(
            DB::Conn(&db),
            &org.id,
            now - chrono::Duration::days(1),
            now + chrono::Duration::days(1),
        )
        .await
        .expect("load tenant provider aggregation");
        assert_eq!(providers.len(), 3);
        assert!(providers.iter().all(|row| row.provider != "microsoft"));
        assert!(providers.iter().all(|row| row.provider != "passkey"));
        assert_eq!(providers.iter().map(|row| row.count).sum::<i64>(), 3);
    }
}

#[cfg(test)]
mod route_tests {
    use super::*;

    use crate::audit::actor::AuditHandle;
    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::crypto::sso::OAuthClient;
    use crate::entities::{login_events, users};
    use crate::services::{
        events::EventDispatcher, metrics::MfaMetricsService, risk_engine::RiskEngine,
    };
    use crate::store::users::{UserCreationOptions, UserStore};
    use crate::store::{
        memberships::MembershipStore, organization_roles::OrganizationRoleStore,
        services::ServiceStore,
    };
    use crate::test_support::{setup_db, test_config, test_jwt_service};
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
    }

    async fn fixture() -> Fixture {
        let db = setup_db().await;
        let config = test_config();
        let jwt_service = Arc::new(test_jwt_service(&config));

        let owner = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "analytics-route-owner@example.test",
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
            "analytics-route-admin@example.test",
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
            "analytics-route-viewer@example.test",
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
            "analytics-route-member@example.test",
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
            "analytics-route-outsider@example.test",
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
            "analytics-route-other-owner@example.test",
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
            "analytics-route-alpha",
            "Analytics Route Alpha",
            &owner.id,
            Some("tier_enterprise"),
        )
        .await
        .expect("create alpha");
        let (beta, _) = OrganizationStore::create_with_owner(
            DB::Conn(&db),
            "analytics-route-beta",
            "Analytics Route Beta",
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
            "analytics-route-viewer-role",
            &alpha.id,
            "analytics-route-viewer",
            "Analytics Route Viewer",
            None,
            serde_json::json!([CAP_AUDIT_LOGS_VIEW]),
        )
        .await
        .expect("create viewer role");
        MembershipStore::create(
            DB::Conn(&db),
            &alpha.id,
            &viewer.id,
            "analytics-route-viewer",
        )
        .await
        .expect("add viewer");

        let alpha_service = ServiceStore::create(
            DB::Conn(&db),
            &alpha.id,
            "primary",
            "Primary",
            "web",
            "analytics-route-alpha-client",
        )
        .await
        .expect("create alpha service");
        let beta_service = ServiceStore::create(
            DB::Conn(&db),
            &beta.id,
            "beta-primary",
            "Beta Primary",
            "web",
            "analytics-route-beta-client",
        )
        .await
        .expect("create beta service");

        let now = Utc::now().naive_utc();
        for (id, service_id, org_id, provider, days_ago) in [
            (
                "analytics-route-old",
                alpha_service.id.as_str(),
                None,
                "password",
                40,
            ),
            (
                "analytics-route-middle",
                alpha_service.id.as_str(),
                None,
                "github",
                10,
            ),
            (
                "analytics-route-recent",
                alpha_service.id.as_str(),
                None,
                "microsoft",
                0,
            ),
            (
                "analytics-route-beta",
                beta_service.id.as_str(),
                None,
                "google",
                0,
            ),
            (
                "analytics-route-global",
                alpha_service.id.as_str(),
                Some(alpha.id.as_str()),
                "magic",
                0,
            ),
        ] {
            login_events::ActiveModel {
                id: Set(id.to_string()),
                user_id: Set(owner.id.clone()),
                service_id: Set(Some(service_id.to_string())),
                org_id: Set(org_id.map(str::to_string)),
                provider: Set(provider.to_string()),
                created_at: Set(now - chrono::Duration::days(days_ago)),
                ..Default::default()
            }
            .insert(&db)
            .await
            .expect("insert analytics event");
        }

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
                user_agent: "analytics-route-test".to_string(),
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
        }
    }

    fn query(start: Option<&str>, end: Option<&str>) -> AnalyticsQuery {
        AnalyticsQuery {
            start_date: start.map(str::to_string),
            end_date: end.map(str::to_string),
            limit: None,
        }
    }

    #[tokio::test]
    async fn analytics_routes_require_live_scoped_capability() {
        let f = fixture().await;

        for auth in [f.owner.clone(), f.admin.clone(), f.viewer.clone()] {
            let _ = get_login_trends(
                State(f.state.clone()),
                Path(f.alpha_slug.clone()),
                Query(query(None, None)),
                auth.clone(),
            )
            .await
            .expect("authorized analytics viewer may read trends");
            let _ = get_logins_by_service(
                State(f.state.clone()),
                Path(f.alpha_slug.clone()),
                Query(query(None, None)),
                auth.clone(),
            )
            .await
            .expect("authorized analytics viewer may read services");
            let _ = get_logins_by_provider(
                State(f.state.clone()),
                Path(f.alpha_slug.clone()),
                Query(query(None, None)),
                auth,
            )
            .await
            .expect("authorized analytics viewer may read providers");
        }

        for auth in [f.member.clone(), f.outsider.clone(), f.other_owner.clone()] {
            assert!(matches!(
                get_login_trends(
                    State(f.state.clone()),
                    Path(f.alpha_slug.clone()),
                    Query(query(None, None)),
                    auth,
                )
                .await,
                Err(AppError::Forbidden(_))
            ));
        }
        assert!(matches!(
            get_login_trends(
                State(f.state.clone()),
                Path(f.beta_slug.clone()),
                Query(query(None, None)),
                f.owner.clone(),
            )
            .await,
            Err(AppError::Forbidden(_))
        ));

        OrganizationStore::update_status(
            DB::Conn(&f.state.db),
            &OrganizationStore::find_by_slug(DB::Conn(&f.state.db), &f.alpha_slug)
                .await
                .expect("load alpha")
                .expect("alpha exists")
                .id,
            "suspended",
        )
        .await
        .expect("suspend alpha");
        assert!(matches!(
            get_login_trends(
                State(f.state.clone()),
                Path(f.alpha_slug.clone()),
                Query(query(None, None)),
                f.owner.clone(),
            )
            .await,
            Err(AppError::Forbidden(_))
        ));
    }

    #[tokio::test]
    async fn analytics_date_filters_scope_responses_and_ignore_invalid_dates() {
        let f = fixture().await;
        let today = Utc::now().date_naive();
        let middle = (Utc::now() - chrono::Duration::days(10))
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let old = (Utc::now() - chrono::Duration::days(40))
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let today_string = today.format("%Y-%m-%d").to_string();

        let Json(trends) = get_login_trends(
            State(f.state.clone()),
            Path(f.alpha_slug.clone()),
            Query(query(Some(&middle), Some(&middle))),
            f.owner.clone(),
        )
        .await
        .expect("filtered trends");
        assert_eq!(trends.iter().map(|point| point.count).sum::<i64>(), 1);

        let Json(all_trends) = get_login_trends(
            State(f.state.clone()),
            Path(f.alpha_slug.clone()),
            Query(query(Some(&old), Some(&today_string))),
            f.owner.clone(),
        )
        .await
        .expect("full-range trends");
        assert_eq!(all_trends.iter().map(|point| point.count).sum::<i64>(), 4);

        let Json(defaulted) = get_login_trends(
            State(f.state.clone()),
            Path(f.alpha_slug.clone()),
            Query(query(Some("not-a-date"), Some("also-not-a-date"))),
            f.owner.clone(),
        )
        .await
        .expect("invalid dates fall back to the default window");
        assert_eq!(defaulted.iter().map(|point| point.count).sum::<i64>(), 3);

        let Json(services) = get_logins_by_service(
            State(f.state.clone()),
            Path(f.alpha_slug.clone()),
            Query(query(Some(&middle), Some(&today_string))),
            f.owner.clone(),
        )
        .await
        .expect("filtered service aggregation");
        assert_eq!(services.iter().map(|row| row.count).sum::<i64>(), 3);
        assert!(services.iter().all(|row| row.service_id != "beta-service"));

        let Json(providers) = get_logins_by_provider(
            State(f.state.clone()),
            Path(f.alpha_slug.clone()),
            Query(query(Some(&middle), Some(&today_string))),
            f.owner.clone(),
        )
        .await
        .expect("filtered provider aggregation");
        assert_eq!(providers.iter().map(|row| row.count).sum::<i64>(), 3);
        assert!(providers.iter().all(|row| row.provider != "password"));
    }
}
