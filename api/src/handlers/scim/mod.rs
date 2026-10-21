pub mod groups;
pub mod schemas;
pub mod users;

pub use groups::*;
pub use users::*;

#[cfg(test)]
mod tests {

    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::crypto::sso::OAuthClient;

    use crate::crypto::jwt::JwtService;
    use crate::entities::{
        prelude::{Sessions, Users},
        users,
    };
    use crate::handlers::scim::schemas;
    use crate::router;

    use crate::audit::actor::AuditHandle;
    use crate::db::DB;
    use crate::services::{
        events::EventDispatcher, metrics::MfaMetricsService, risk_engine::RiskEngine,
    };
    use crate::state::AppState;
    use crate::store::{
        memberships::MembershipStore, organizations::OrganizationStore,
        permissions::PermissionsStore, scim_tokens::ScimTokenStore, sessions::SessionStore,
        users::UserStore,
    };
    use axum::body::{to_bytes, Body};
    use axum::http::{header, HeaderValue, Method, Request, StatusCode};

    use chrono::Utc;
    use moka::future::Cache;
    use sea_orm::{
        ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait,
        QueryFilter, Set,
    };
    use serde_json::Value;
    use std::sync::Arc;
    use tower::ServiceExt;
    use uuid::Uuid;

    struct ScimRouteFixture {
        state: AppState,
        bearer_token: String,
        org_id: String,
        owner_id: String,
        user_id: String,
    }

    use crate::test_support::test_config;

    use crate::test_support::test_jwt_service;

    use crate::test_support::setup_db;

    async fn setup_fixture() -> ScimRouteFixture {
        let db = setup_db().await;
        let config = test_config();
        let owner = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "owner@example.com",
            crate::store::users::UserCreationOptions {
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
            .expect("activate scim test org");
        let invitee =
            UserStore::create_with_org_id(DB::Conn(&db), "scim-user@example.com", None, &org.id)
                .await
                .expect("create tenant-owned scim user");
        MembershipStore::create(DB::Conn(&db), &org.id, &invitee.id, "member")
            .await
            .expect("create member");

        let (bearer_token, prefix, token_hash) = ScimTokenStore::generate();
        ScimTokenStore::create(
            DB::Conn(&db),
            &org.id,
            "route-test",
            &token_hash,
            &prefix,
            &owner.id,
            None,
        )
        .await
        .expect("create scim token");

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

        ScimRouteFixture {
            state,
            bearer_token,
            org_id: org.id,
            owner_id: owner.id,
            user_id: invitee.id,
        }
    }

    async fn scim_request(
        fixture: &ScimRouteFixture,
        method: Method,
        uri: String,
        body: Value,
    ) -> (StatusCode, Value) {
        let app = router::scim_routes(&fixture.state).with_state(fixture.state.clone());
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", fixture.bearer_token),
            )
            .header(header::CONTENT_TYPE, "application/scim+json")
            .body(Body::from(body.to_string()))
            .expect("build scim request");

        let response = app.oneshot(request).await.expect("send scim request");
        let status = response.status();
        let body_bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read scim response body");
        let body = serde_json::from_slice(&body_bytes).expect("parse scim response body");
        (status, body)
    }

    async fn scim_status_request(
        fixture: &ScimRouteFixture,
        method: Method,
        uri: String,
        body: Value,
    ) -> StatusCode {
        let app = router::scim_routes(&fixture.state).with_state(fixture.state.clone());
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", fixture.bearer_token),
            )
            .header(header::CONTENT_TYPE, "application/scim+json")
            .body(Body::from(body.to_string()))
            .expect("build scim request");

        app.oneshot(request)
            .await
            .expect("send scim request")
            .status()
    }

    async fn scim_empty_request(
        fixture: &ScimRouteFixture,
        method: Method,
        uri: String,
    ) -> (StatusCode, Value) {
        let app = router::scim_routes(&fixture.state).with_state(fixture.state.clone());
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", fixture.bearer_token),
            )
            .body(Body::empty())
            .expect("build scim request");

        let response = app.oneshot(request).await.expect("send scim request");
        let status = response.status();
        let body_bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read scim response body");
        let body = serde_json::from_slice(&body_bytes).expect("parse scim response body");
        (status, body)
    }

    async fn scim_empty_status_request(
        fixture: &ScimRouteFixture,
        method: Method,
        uri: String,
    ) -> StatusCode {
        let app = router::scim_routes(&fixture.state).with_state(fixture.state.clone());
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", fixture.bearer_token),
            )
            .body(Body::empty())
            .expect("build scim request");

        app.oneshot(request)
            .await
            .expect("send scim request")
            .status()
    }

    async fn user_email(db: &DatabaseConnection, user_id: &str) -> String {
        Users::find()
            .filter(users::Column::Id.eq(user_id))
            .one(db)
            .await
            .expect("query user")
            .expect("user exists")
            .email
    }

    async fn user_deleted_at_is_some(db: &DatabaseConnection, user_id: &str) -> bool {
        Users::find()
            .filter(users::Column::Id.eq(user_id))
            .one(db)
            .await
            .expect("query user")
            .expect("user exists")
            .deleted_at
            .is_some()
    }

    async fn user_updated_at(
        db: &DatabaseConnection,
        user_id: &str,
    ) -> Option<chrono::NaiveDateTime> {
        Users::find()
            .filter(users::Column::Id.eq(user_id))
            .one(db)
            .await
            .expect("query user")
            .expect("user exists")
            .updated_at
    }

    async fn membership_exists(db: &DatabaseConnection, org_id: &str, user_id: &str) -> bool {
        MembershipStore::find_by_org_and_user(DB::Conn(db), org_id, user_id)
            .await
            .expect("query membership")
            .is_some()
    }

    async fn create_org_scoped_user(
        db: &DatabaseConnection,
        org_id: &str,
        email: &str,
    ) -> users::Model {
        users::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            email: Set(email.to_string()),
            org_id: Set(Some(org_id.to_string())),
            password_hash: Set(None),
            is_platform_owner: Set(false),
            email_verified_at: Set(Some(Utc::now().naive_utc())),
            created_at: Set(Utc::now().naive_utc()),
            updated_at: Set(None),
            deleted_at: Set(None),
        }
        .insert(db)
        .await
        .expect("create org-scoped user")
    }

    #[tokio::test]
    async fn optional_organization_header_must_be_absent_or_exactly_match_token_scope() {
        let fixture = setup_fixture().await;
        let cases = [
            (vec![], StatusCode::OK),
            (
                vec![HeaderValue::from_str(&fixture.org_id).expect("exact org header")],
                StatusCode::OK,
            ),
            (
                vec![HeaderValue::from_static("another-organization")],
                StatusCode::FORBIDDEN,
            ),
            (
                vec![
                    HeaderValue::from_bytes(format!("{} ", fixture.org_id).as_bytes())
                        .expect("whitespace-different org header"),
                ],
                StatusCode::FORBIDDEN,
            ),
            (
                vec![HeaderValue::from_bytes(&[0xff]).expect("non-UTF-8 header value")],
                StatusCode::FORBIDDEN,
            ),
            (
                vec![
                    HeaderValue::from_str(&fixture.org_id).expect("first duplicate org header"),
                    HeaderValue::from_str(&fixture.org_id).expect("second duplicate org header"),
                ],
                StatusCode::FORBIDDEN,
            ),
            (
                vec![
                    HeaderValue::from_str(&fixture.org_id).expect("matching duplicate org header"),
                    HeaderValue::from_static("another-organization"),
                ],
                StatusCode::FORBIDDEN,
            ),
        ];

        for (organization_headers, expected) in cases {
            let app = router::scim_routes(&fixture.state).with_state(fixture.state.clone());
            let mut request = Request::builder()
                .method(Method::GET)
                .uri("/scim/v2/Users")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", fixture.bearer_token),
                )
                .body(Body::empty())
                .expect("build SCIM request");
            for organization_header in organization_headers {
                request
                    .headers_mut()
                    .append("X-Organization-ID", organization_header);
            }
            let response = app.oneshot(request).await.expect("send SCIM request");
            assert_eq!(response.status(), expected);
        }
    }

    #[tokio::test]
    async fn user_get_route_returns_org_member_as_scim_user() {
        let fixture = setup_fixture().await;
        let (status, body) = scim_empty_request(
            &fixture,
            Method::GET,
            format!("/scim/v2/Users/{}", fixture.user_id),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["schemas"][0], schemas::SCIM_USER_SCHEMA);
        assert_eq!(body["id"], fixture.user_id);
        assert_eq!(body["userName"], "scim-user@example.com");
        assert_eq!(body["active"], true);
    }

    #[tokio::test]
    async fn user_put_rejects_body_id_mismatch_and_preserves_user() {
        let fixture = setup_fixture().await;
        let (status, body) = scim_request(
            &fixture,
            Method::PUT,
            format!("/scim/v2/Users/{}", fixture.user_id),
            serde_json::json!({
                "schemas": [schemas::SCIM_USER_SCHEMA],
                "id": "different-user",
                "userName": "changed@example.com"
            }),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["scimType"], "invalidValue");
        assert_eq!(
            user_email(&fixture.state.db, &fixture.user_id).await,
            "scim-user@example.com"
        );
    }

    #[tokio::test]
    async fn user_put_updates_email_when_body_id_matches() {
        let fixture = setup_fixture().await;
        let (status, body) = scim_request(
            &fixture,
            Method::PUT,
            format!("/scim/v2/Users/{}", fixture.user_id),
            serde_json::json!({
                "schemas": [schemas::SCIM_USER_SCHEMA],
                "id": fixture.user_id,
                "userName": "updated@example.com",
                "emails": [{
                    "value": "updated@example.com",
                    "type": "work",
                    "primary": true
                }]
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["id"], fixture.user_id);
        assert_eq!(body["userName"], "updated@example.com");
        assert_eq!(
            user_email(&fixture.state.db, &fixture.user_id).await,
            "updated@example.com"
        );
    }

    #[tokio::test]
    async fn scim_cannot_modify_platform_owner_or_privileged_identity_email() {
        let fixture = setup_fixture().await;

        let promoted = UserStore::create_with_org_id(
            DB::Conn(&fixture.state.db),
            "promoted-platform@example.com",
            None,
            &fixture.org_id,
        )
        .await
        .expect("create tenant-scoped promoted user");
        MembershipStore::create(
            DB::Conn(&fixture.state.db),
            &fixture.org_id,
            &promoted.id,
            "member",
        )
        .await
        .expect("promoted membership");
        UserStore::set_platform_owner(DB::Conn(&fixture.state.db), &promoted.id, true)
            .await
            .expect("promote user");

        let (status, _) = scim_request(
            &fixture,
            Method::PATCH,
            format!("/scim/v2/Users/{}", promoted.id),
            serde_json::json!({
                "schemas": [schemas::SCIM_PATCH_SCHEMA],
                "Operations": [{
                    "op": "replace",
                    "path": "userName",
                    "value": "attacker@example.com"
                }]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            user_email(&fixture.state.db, &promoted.id).await,
            "promoted-platform@example.com"
        );

        let tenant_owner = UserStore::create_with_org_id(
            DB::Conn(&fixture.state.db),
            "tenant-owner-email@example.com",
            None,
            &fixture.org_id,
        )
        .await
        .expect("create tenant-scoped owner");
        MembershipStore::create(
            DB::Conn(&fixture.state.db),
            &fixture.org_id,
            &tenant_owner.id,
            "owner",
        )
        .await
        .expect("tenant owner membership");

        let (status, _) = scim_request(
            &fixture,
            Method::PATCH,
            format!("/scim/v2/Users/{}", tenant_owner.id),
            serde_json::json!({
                "schemas": [schemas::SCIM_PATCH_SCHEMA],
                "Operations": [{
                    "op": "replace",
                    "path": "emails",
                    "value": [{"value": "attacker@example.com", "primary": true}]
                }]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            user_email(&fixture.state.db, &tenant_owner.id).await,
            "tenant-owner-email@example.com"
        );
    }

    #[tokio::test]
    async fn scim_email_change_clears_verification_and_revokes_sessions() {
        let fixture = setup_fixture().await;
        let mut user: users::ActiveModel =
            UserStore::find_by_id(DB::Conn(&fixture.state.db), &fixture.user_id)
                .await
                .expect("load user")
                .expect("user exists")
                .into();
        user.email_verified_at = Set(Some(Utc::now().naive_utc()));
        user.update(&fixture.state.db).await.expect("verify email");

        let token = fixture
            .state
            .jwt_service
            .create_token(&fixture.user_id, "scim-user@example.com", false, None, None)
            .expect("token");
        SessionStore::create(
            DB::Conn(&fixture.state.db),
            &fixture.user_id,
            &JwtService::hash_token(&token),
            (Utc::now() + chrono::Duration::hours(1)).naive_utc(),
            None,
            None,
            None,
            None,
            None,
            Some("scim-test"),
            Some("127.0.0.1"),
        )
        .await
        .expect("session");

        let (status, _) = scim_request(
            &fixture,
            Method::PATCH,
            format!("/scim/v2/Users/{}", fixture.user_id),
            serde_json::json!({
                "schemas": [schemas::SCIM_PATCH_SCHEMA],
                "Operations": [{
                    "op": "replace",
                    "path": "userName",
                    "value": "scim-user-new@example.com"
                }]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let stored = UserStore::find_by_id(DB::Conn(&fixture.state.db), &fixture.user_id)
            .await
            .expect("load updated user")
            .expect("updated user exists");
        assert_eq!(stored.email, "scim-user-new@example.com");
        assert!(stored.email_verified_at.is_none());
        assert_eq!(
            Sessions::find()
                .filter(crate::entities::sessions::Column::UserId.eq(&fixture.user_id))
                .count(&fixture.state.db)
                .await
                .expect("count sessions"),
            0
        );
    }

    #[tokio::test]
    async fn group_put_rejects_body_id_mismatch() {
        let fixture = setup_fixture().await;
        let (status, body) = scim_request(
            &fixture,
            Method::PUT,
            format!("/scim/v2/Groups/{}", fixture.org_id),
            serde_json::json!({
                "schemas": [schemas::SCIM_GROUP_SCHEMA],
                "id": "different-group",
                "displayName": "Changed"
            }),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["scimType"], "invalidValue");
    }

    #[tokio::test]
    async fn group_get_route_returns_scim_group_with_members() {
        let fixture = setup_fixture().await;
        let (status, body) = scim_empty_request(
            &fixture,
            Method::GET,
            format!("/scim/v2/Groups/{}", fixture.org_id),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["schemas"][0], schemas::SCIM_GROUP_SCHEMA);
        assert_eq!(body["id"], fixture.org_id);
        assert_eq!(body["displayName"], "Acme");
        let members = body["members"].as_array().expect("group members");
        assert!(members
            .iter()
            .any(|member| member["value"] == fixture.user_id));
        assert!(members
            .iter()
            .any(|member| member["value"] == fixture.owner_id));
    }

    #[tokio::test]
    async fn group_put_replaces_members_without_removing_owner() {
        let fixture = setup_fixture().await;
        let (status, body) = scim_request(
            &fixture,
            Method::PUT,
            format!("/scim/v2/Groups/{}", fixture.org_id),
            serde_json::json!({
                "schemas": [schemas::SCIM_GROUP_SCHEMA],
                "id": fixture.org_id,
                "displayName": "Acme",
                "members": [{
                    "value": fixture.owner_id,
                    "$ref": format!("http://localhost:3001/scim/v2/Users/{}", fixture.owner_id),
                    "type": "User"
                }]
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["id"], fixture.org_id);
        assert!(membership_exists(&fixture.state.db, &fixture.org_id, &fixture.owner_id).await);
        assert!(!membership_exists(&fixture.state.db, &fixture.org_id, &fixture.user_id).await);
    }

    #[tokio::test]
    async fn user_patch_rejects_missing_patch_schema_and_preserves_user() {
        let fixture = setup_fixture().await;
        let (status, body) = scim_request(
            &fixture,
            Method::PATCH,
            format!("/scim/v2/Users/{}", fixture.user_id),
            serde_json::json!({
                "schemas": [schemas::SCIM_USER_SCHEMA],
                "Operations": [{
                    "op": "replace",
                    "path": "userName",
                    "value": "changed@example.com"
                }]
            }),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["scimType"], "invalidValue");
        assert_eq!(
            user_email(&fixture.state.db, &fixture.user_id).await,
            "scim-user@example.com"
        );
    }

    #[tokio::test]
    async fn user_patch_updates_email_with_valid_patch_schema() {
        let fixture = setup_fixture().await;
        let (status, body) = scim_request(
            &fixture,
            Method::PATCH,
            format!("/scim/v2/Users/{}", fixture.user_id),
            serde_json::json!({
                "schemas": [schemas::SCIM_PATCH_SCHEMA],
                "Operations": [{
                    "op": "replace",
                    "path": "userName",
                    "value": "patched@example.com"
                }]
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["id"], fixture.user_id);
        assert_eq!(body["userName"], "patched@example.com");
        assert_eq!(
            user_email(&fixture.state.db, &fixture.user_id).await,
            "patched@example.com"
        );
    }

    #[tokio::test]
    async fn user_patch_deactivates_member_with_valid_patch_schema() {
        let fixture = setup_fixture().await;
        let (status, body) = scim_request(
            &fixture,
            Method::PATCH,
            format!("/scim/v2/Users/{}", fixture.user_id),
            serde_json::json!({
                "schemas": [schemas::SCIM_PATCH_SCHEMA],
                "Operations": [{
                    "op": "replace",
                    "path": "active",
                    "value": false
                }]
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["id"], fixture.user_id);
        assert_eq!(body["active"], false);
        assert!(user_deleted_at_is_some(&fixture.state.db, &fixture.user_id).await);
    }

    #[tokio::test]
    async fn group_patch_rejects_missing_patch_schema() {
        let fixture = setup_fixture().await;
        let (status, body) = scim_request(
            &fixture,
            Method::PATCH,
            format!("/scim/v2/Groups/{}", fixture.org_id),
            serde_json::json!({
                "schemas": [schemas::SCIM_GROUP_SCHEMA],
                "Operations": [{
                    "op": "remove",
                    "path": format!("members[value eq \"{}\"]", fixture.user_id)
                }]
            }),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["scimType"], "invalidValue");
    }

    #[tokio::test]
    async fn group_patch_removes_regular_member_with_valid_patch_schema() {
        let fixture = setup_fixture().await;
        let (status, body) = scim_request(
            &fixture,
            Method::PATCH,
            format!("/scim/v2/Groups/{}", fixture.org_id),
            serde_json::json!({
                "schemas": [schemas::SCIM_PATCH_SCHEMA],
                "Operations": [{
                    "op": "remove",
                    "path": format!("members[value eq \"{}\"]", fixture.user_id)
                }]
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["id"], fixture.org_id);
        assert!(!membership_exists(&fixture.state.db, &fixture.org_id, &fixture.user_id).await);
        assert!(membership_exists(&fixture.state.db, &fixture.org_id, &fixture.owner_id).await);
    }

    #[tokio::test]
    async fn group_patch_add_maps_user_to_member_role_and_permission() {
        let fixture = setup_fixture().await;
        let user =
            create_org_scoped_user(&fixture.state.db, &fixture.org_id, "scim-add@example.com")
                .await;

        let (status, body) = scim_request(
            &fixture,
            Method::PATCH,
            format!("/scim/v2/Groups/{}", fixture.org_id),
            serde_json::json!({
                "schemas": [schemas::SCIM_PATCH_SCHEMA],
                "Operations": [{
                    "op": "add",
                    "value": {
                        "members": [{
                            "value": user.id,
                            "$ref": format!("http://localhost:3001/scim/v2/Users/{}", user.id),
                            "type": "User"
                        }]
                    }
                }]
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["id"], fixture.org_id);
        let membership = MembershipStore::find_by_org_and_user(
            DB::Conn(&fixture.state.db),
            &fixture.org_id,
            &user.id,
        )
        .await
        .expect("query added scim group member")
        .expect("scim group add creates membership");
        assert_eq!(membership.role, "member");
        assert!(PermissionsStore::check(
            DB::Conn(&fixture.state.db),
            "organization",
            &fixture.org_id,
            "member",
            &user.id,
        )
        .await
        .expect("check scim-added member permission"));
    }

    #[tokio::test]
    async fn group_patch_rejects_owner_removal() {
        let fixture = setup_fixture().await;
        let status = scim_status_request(
            &fixture,
            Method::PATCH,
            format!("/scim/v2/Groups/{}", fixture.org_id),
            serde_json::json!({
                "schemas": [schemas::SCIM_PATCH_SCHEMA],
                "Operations": [{
                    "op": "remove",
                    "path": format!("members[value eq \"{}\"]", fixture.owner_id)
                }]
            }),
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(membership_exists(&fixture.state.db, &fixture.org_id, &fixture.owner_id).await);
    }

    #[tokio::test]
    async fn user_create_and_list_routes_provision_org_member() {
        let fixture = setup_fixture().await;
        let (status, created) = scim_request(
            &fixture,
            Method::POST,
            "/scim/v2/Users".to_string(),
            serde_json::json!({
                "schemas": [schemas::SCIM_USER_SCHEMA],
                "userName": "provisioned@example.com",
                "emails": [{
                    "value": "provisioned@example.com",
                    "type": "work",
                    "primary": true
                }]
            }),
        )
        .await;

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(created["userName"], "provisioned@example.com");
        assert_eq!(created["active"], true);
        let created_user_id = created["id"]
            .as_str()
            .expect("created scim user id")
            .to_string();

        let membership = MembershipStore::find_by_org_and_user(
            DB::Conn(&fixture.state.db),
            &fixture.org_id,
            &created_user_id,
        )
        .await
        .expect("query created scim user membership")
        .expect("created user has org membership");
        assert_eq!(membership.role, "member");

        let (list_status, list_body) =
            scim_empty_request(&fixture, Method::GET, "/scim/v2/Users".to_string()).await;
        assert_eq!(list_status, StatusCode::OK);
        assert!(list_body["totalResults"].as_u64().unwrap_or_default() >= 3);
        let listed_users = list_body["Resources"]
            .as_array()
            .expect("list response resources");
        assert!(listed_users
            .iter()
            .any(|resource| resource["userName"] == "provisioned@example.com"));
    }

    #[tokio::test]
    async fn user_list_rejects_invalid_and_unsupported_filters_as_scim_errors() {
        let fixture = setup_fixture().await;

        for uri in [
            "/scim/v2/Users?filter=not%20a%20filter",
            "/scim/v2/Users?filter=active%20eq%20true",
            "/scim/v2/Users?filter=userName%20pr",
        ] {
            let (status, body) = scim_empty_request(&fixture, Method::GET, uri.to_string()).await;

            assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
            assert_eq!(body["schemas"][0], schemas::SCIM_ERROR_SCHEMA, "{uri}");
            assert_eq!(body["scimType"], "invalidFilter", "{uri}");
        }
    }

    #[tokio::test]
    async fn list_routes_report_returned_page_size_and_normalize_start_index() {
        let fixture = setup_fixture().await;

        let (user_status, users) = scim_empty_request(
            &fixture,
            Method::GET,
            "/scim/v2/Users?startIndex=2&count=1".to_string(),
        )
        .await;
        assert_eq!(user_status, StatusCode::OK);
        assert_eq!(users["totalResults"], 2);
        assert_eq!(users["startIndex"], 2);
        assert_eq!(users["itemsPerPage"], 1);
        assert_eq!(users["Resources"].as_array().unwrap().len(), 1);

        let (_, empty_users) = scim_empty_request(
            &fixture,
            Method::GET,
            "/scim/v2/Users?startIndex=0&count=0".to_string(),
        )
        .await;
        assert_eq!(empty_users["totalResults"], 2);
        assert_eq!(empty_users["startIndex"], 1);
        assert_eq!(empty_users["itemsPerPage"], 0);
        assert!(empty_users["Resources"].as_array().unwrap().is_empty());

        let (_, groups) =
            scim_empty_request(&fixture, Method::GET, "/scim/v2/Groups".to_string()).await;
        assert_eq!(groups["totalResults"], 1);
        assert_eq!(groups["itemsPerPage"], 1);

        let (_, empty_groups) = scim_empty_request(
            &fixture,
            Method::GET,
            "/scim/v2/Groups?startIndex=2&count=100".to_string(),
        )
        .await;
        assert_eq!(empty_groups["totalResults"], 1);
        assert_eq!(empty_groups["startIndex"], 2);
        assert_eq!(empty_groups["itemsPerPage"], 0);
    }

    #[tokio::test]
    async fn group_list_rejects_unsupported_filter_as_scim_error() {
        let fixture = setup_fixture().await;
        let (status, body) = scim_empty_request(
            &fixture,
            Method::GET,
            "/scim/v2/Groups?filter=id%20eq%20ignored".to_string(),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["schemas"][0], schemas::SCIM_ERROR_SCHEMA);
        assert_eq!(body["scimType"], "invalidFilter");
    }

    #[tokio::test]
    async fn user_routes_do_not_disclose_members_of_another_tenant() {
        let fixture = setup_fixture().await;
        let other_owner = UserStore::find_or_create_with_options(
            DB::Conn(&fixture.state.db),
            "other-owner@example.com",
            crate::store::users::UserCreationOptions::default(),
        )
        .await
        .expect("create other tenant owner")
        .0;
        let (other_org, _) = OrganizationStore::create_with_owner(
            DB::Conn(&fixture.state.db),
            "other-tenant",
            "Other Tenant",
            &other_owner.id,
            None,
        )
        .await
        .expect("create other tenant");
        let other_user =
            create_org_scoped_user(&fixture.state.db, &other_org.id, "other-member@example.com")
                .await;
        MembershipStore::create(
            DB::Conn(&fixture.state.db),
            &other_org.id,
            &other_user.id,
            "member",
        )
        .await
        .expect("create other tenant member");

        let (get_status, get_body) = scim_empty_request(
            &fixture,
            Method::GET,
            format!("/scim/v2/Users/{}", other_user.id),
        )
        .await;
        assert_eq!(get_status, StatusCode::NOT_FOUND);
        assert_eq!(get_body["schemas"][0], schemas::SCIM_ERROR_SCHEMA);

        let (list_status, list_body) = scim_empty_request(
            &fixture,
            Method::GET,
            "/scim/v2/Users?filter=userName%20eq%20%22other-member@example.com%22".to_string(),
        )
        .await;
        assert_eq!(list_status, StatusCode::OK);
        assert_eq!(list_body["totalResults"], 0);
        assert_eq!(list_body["itemsPerPage"], 0);
    }

    #[tokio::test]
    async fn user_patch_rejects_unsupported_operation_without_changing_state() {
        let fixture = setup_fixture().await;
        let before_updated_at = user_updated_at(&fixture.state.db, &fixture.user_id).await;
        let (status, body) = scim_request(
            &fixture,
            Method::PATCH,
            format!("/scim/v2/Users/{}", fixture.user_id),
            serde_json::json!({
                "schemas": [schemas::SCIM_PATCH_SCHEMA],
                "Operations": [{
                    "op": "add",
                    "path": "userName",
                    "value": "must-not-change@example.com"
                }]
            }),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["scimType"], "invalidValue");
        assert_eq!(
            user_email(&fixture.state.db, &fixture.user_id).await,
            "scim-user@example.com"
        );
        assert_eq!(
            user_updated_at(&fixture.state.db, &fixture.user_id).await,
            before_updated_at
        );
    }

    #[tokio::test]
    async fn unchanged_user_put_is_idempotent() {
        let fixture = setup_fixture().await;
        let before_updated_at = user_updated_at(&fixture.state.db, &fixture.user_id).await;
        let (status, body) = scim_request(
            &fixture,
            Method::PUT,
            format!("/scim/v2/Users/{}", fixture.user_id),
            serde_json::json!({
                "schemas": [schemas::SCIM_USER_SCHEMA],
                "id": fixture.user_id,
                "userName": "scim-user@example.com",
                "active": true
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["active"], true);
        assert_eq!(
            user_updated_at(&fixture.state.db, &fixture.user_id).await,
            before_updated_at
        );
    }

    #[tokio::test]
    async fn group_put_validation_failure_leaves_all_memberships_unchanged() {
        let fixture = setup_fixture().await;
        let candidate =
            create_org_scoped_user(&fixture.state.db, &fixture.org_id, "atomic-put@example.com")
                .await;

        let status = scim_status_request(
            &fixture,
            Method::PUT,
            format!("/scim/v2/Groups/{}", fixture.org_id),
            serde_json::json!({
                "schemas": [schemas::SCIM_GROUP_SCHEMA],
                "id": fixture.org_id,
                "displayName": "Acme",
                "members": [{"value": candidate.id}]
            }),
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(membership_exists(&fixture.state.db, &fixture.org_id, &fixture.owner_id).await);
        assert!(membership_exists(&fixture.state.db, &fixture.org_id, &fixture.user_id).await);
        assert!(!membership_exists(&fixture.state.db, &fixture.org_id, &candidate.id).await);
    }

    #[tokio::test]
    async fn group_patch_validation_failure_rolls_back_earlier_operations() {
        let fixture = setup_fixture().await;
        let candidate = create_org_scoped_user(
            &fixture.state.db,
            &fixture.org_id,
            "atomic-patch@example.com",
        )
        .await;

        let status = scim_status_request(
            &fixture,
            Method::PATCH,
            format!("/scim/v2/Groups/{}", fixture.org_id),
            serde_json::json!({
                "schemas": [schemas::SCIM_PATCH_SCHEMA],
                "Operations": [
                    {
                        "op": "add",
                        "value": {"members": [{"value": candidate.id}]}
                    },
                    {
                        "op": "remove",
                        "path": format!("members[value eq \"{}\"]", fixture.owner_id)
                    }
                ]
            }),
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(membership_exists(&fixture.state.db, &fixture.org_id, &fixture.owner_id).await);
        assert!(!membership_exists(&fixture.state.db, &fixture.org_id, &candidate.id).await);
    }

    #[tokio::test]
    async fn group_patch_rejects_cross_tenant_member_without_changing_state() {
        let fixture = setup_fixture().await;
        let other_owner = UserStore::find_or_create_with_options(
            DB::Conn(&fixture.state.db),
            "patch-other-owner@example.com",
            crate::store::users::UserCreationOptions::default(),
        )
        .await
        .expect("create other owner")
        .0;
        let (other_org, _) = OrganizationStore::create_with_owner(
            DB::Conn(&fixture.state.db),
            "patch-other-tenant",
            "Patch Other Tenant",
            &other_owner.id,
            None,
        )
        .await
        .expect("create other organization");
        let other_user = create_org_scoped_user(
            &fixture.state.db,
            &other_org.id,
            "patch-other-member@example.com",
        )
        .await;

        let status = scim_status_request(
            &fixture,
            Method::PATCH,
            format!("/scim/v2/Groups/{}", fixture.org_id),
            serde_json::json!({
                "schemas": [schemas::SCIM_PATCH_SCHEMA],
                "Operations": [{
                    "op": "add",
                    "value": {"members": [{"value": other_user.id}]}
                }]
            }),
        )
        .await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(!membership_exists(&fixture.state.db, &fixture.org_id, &other_user.id).await);
        assert!(membership_exists(&fixture.state.db, &fixture.org_id, &fixture.owner_id).await);
        assert!(membership_exists(&fixture.state.db, &fixture.org_id, &fixture.user_id).await);
    }

    #[tokio::test]
    async fn user_delete_removes_member_membership() {
        let fixture = setup_fixture().await;
        let status = scim_empty_status_request(
            &fixture,
            Method::DELETE,
            format!("/scim/v2/Users/{}", fixture.user_id),
        )
        .await;

        assert_eq!(status, StatusCode::NO_CONTENT);
        let membership = MembershipStore::find_by_org_and_user(
            DB::Conn(&fixture.state.db),
            &fixture.org_id,
            &fixture.user_id,
        )
        .await
        .expect("query deleted user membership");
        assert!(membership.is_none());
    }

    #[tokio::test]
    async fn user_delete_rejects_owner_deprovisioning() {
        let fixture = setup_fixture().await;
        let status = scim_empty_status_request(
            &fixture,
            Method::DELETE,
            format!("/scim/v2/Users/{}", fixture.owner_id),
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        let membership = MembershipStore::find_by_org_and_user(
            DB::Conn(&fixture.state.db),
            &fixture.org_id,
            &fixture.owner_id,
        )
        .await
        .expect("query owner membership");
        assert!(membership.is_some());
    }

    #[tokio::test]
    async fn group_delete_rejects_org_deletion() {
        let fixture = setup_fixture().await;
        let status = scim_empty_status_request(
            &fixture,
            Method::DELETE,
            format!("/scim/v2/Groups/{}", fixture.org_id),
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(membership_exists(&fixture.state.db, &fixture.org_id, &fixture.owner_id).await);
        assert!(membership_exists(&fixture.state.db, &fixture.org_id, &fixture.user_id).await);
    }

    #[tokio::test]
    async fn suspended_parent_rejects_every_scim_route_before_handler_state_changes() {
        let fixture = setup_fixture().await;
        let before = UserStore::find_by_id(DB::Conn(&fixture.state.db), &fixture.user_id)
            .await
            .expect("load user")
            .expect("user exists");
        OrganizationStore::update_status(DB::Conn(&fixture.state.db), &fixture.org_id, "suspended")
            .await
            .expect("suspend scim parent");

        for (method, uri, body) in [
            (
                Method::GET,
                "/scim/v2/Users".to_string(),
                serde_json::Value::Null,
            ),
            (
                Method::PATCH,
                format!("/scim/v2/Users/{}", fixture.user_id),
                serde_json::json!({
                    "schemas": [schemas::SCIM_PATCH_SCHEMA],
                    "Operations": [{"op": "replace", "path": "active", "value": false}]
                }),
            ),
            (
                Method::GET,
                "/scim/v2/Groups".to_string(),
                serde_json::Value::Null,
            ),
        ] {
            let status = if body.is_null() {
                scim_empty_status_request(&fixture, method, uri).await
            } else {
                scim_status_request(&fixture, method, uri, body).await
            };
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }

        let after = UserStore::find_by_id(DB::Conn(&fixture.state.db), &fixture.user_id)
            .await
            .expect("reload user")
            .expect("user remains");
        assert_eq!(after, before);
        assert!(membership_exists(&fixture.state.db, &fixture.org_id, &fixture.user_id).await);
    }

    #[tokio::test]
    async fn shared_user_put_and_patch_cannot_mutate_global_identity() {
        let fixture = setup_fixture().await;
        let shared = UserStore::find_or_create_with_options(
            DB::Conn(&fixture.state.db),
            "shared-scim@example.com",
            crate::store::users::UserCreationOptions::default(),
        )
        .await
        .expect("create shared user")
        .0;
        let (other_org, _) = OrganizationStore::create_with_owner(
            DB::Conn(&fixture.state.db),
            "shared-scim-owner-org",
            "Shared SCIM Owner Org",
            &shared.id,
            None,
        )
        .await
        .expect("create other org owned by shared user");
        MembershipStore::create(
            DB::Conn(&fixture.state.db),
            &fixture.org_id,
            &shared.id,
            "member",
        )
        .await
        .expect("add shared user to scim org");
        let before = shared.clone();

        let (put_status, _) = scim_request(
            &fixture,
            Method::PUT,
            format!("/scim/v2/Users/{}", shared.id),
            serde_json::json!({
                "schemas": [schemas::SCIM_USER_SCHEMA],
                "id": shared.id,
                "userName": "tenant-rewrite@example.com",
                "active": false
            }),
        )
        .await;
        assert_eq!(put_status, StatusCode::FORBIDDEN);

        let (patch_status, _) = scim_request(
            &fixture,
            Method::PATCH,
            format!("/scim/v2/Users/{}", shared.id),
            serde_json::json!({
                "schemas": [schemas::SCIM_PATCH_SCHEMA],
                "Operations": [{"op": "replace", "path": "active", "value": false}]
            }),
        )
        .await;
        assert_eq!(patch_status, StatusCode::FORBIDDEN);

        let after = UserStore::find_by_id(DB::Conn(&fixture.state.db), &shared.id)
            .await
            .expect("reload shared user")
            .expect("shared user remains");
        assert_eq!(after, before);
        assert!(membership_exists(&fixture.state.db, &fixture.org_id, &shared.id).await);
        assert!(membership_exists(&fixture.state.db, &other_org.id, &shared.id).await);
    }
}
