use crate::db::DB;
use crate::entities::prelude::{SessionRefreshTokenHistory, Sessions};
use crate::entities::{session_refresh_token_history, sessions};
use crate::error::{AppError, Result};
use chrono::NaiveDateTime;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set, TransactionTrait};
use uuid::Uuid;

pub struct SessionStore;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshRotationOutcome {
    Rotated,
    ReuseDetected,
}

impl SessionStore {
    /// Find a session by ID
    pub async fn find_by_id(db: DB<'_>, session_id: &str) -> Result<Option<sessions::Model>> {
        let result = Sessions::find()
            .filter(sessions::Column::Id.eq(session_id))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Find a session by token hash
    pub async fn find_by_token_hash(
        db: DB<'_>,
        token_hash: &str,
    ) -> Result<Option<sessions::Model>> {
        let result = Sessions::find()
            .filter(sessions::Column::TokenHash.eq(token_hash))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Find a valid (non-expired) session by token hash
    pub async fn find_valid_by_token_hash(
        db: DB<'_>,
        token_hash: &str,
    ) -> Result<Option<sessions::Model>> {
        let now = chrono::Utc::now().naive_utc();

        let result = Sessions::find()
            .filter(sessions::Column::TokenHash.eq(token_hash))
            .filter(sessions::Column::ExpiresAt.gt(now))
            .one(&db)
            .await?;

        Ok(result)
    }

    /// Find a session by refresh token
    pub async fn find_by_refresh_token(
        db: DB<'_>,
        refresh_token: &str,
    ) -> Result<Option<sessions::Model>> {
        let refresh_token_hash = crate::crypto::refresh_tokens::hash(refresh_token);
        let result = Sessions::find()
            .filter(sessions::Column::RefreshTokenHash.eq(refresh_token_hash))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Create a new session
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        db: DB<'_>,
        user_id: &str,
        token_hash: &str,
        expires_at: NaiveDateTime,
        refresh_token: Option<&str>,
        refresh_token_expires_at: Option<NaiveDateTime>,
        org_slug: Option<&str>,
        service_id: Option<&str>,
        resource: Option<&str>,
        user_agent: Option<&str>,
        ip_address: Option<&str>,
    ) -> Result<sessions::Model> {
        Self::create_with_created_at(
            db,
            user_id,
            token_hash,
            expires_at,
            refresh_token,
            refresh_token_expires_at,
            org_slug,
            service_id,
            resource,
            user_agent,
            ip_address,
            chrono::Utc::now().naive_utc(),
        )
        .await
    }

    /// Create a session with an explicit authentication time. Context-switch
    /// flows that mint a new session without re-entering credentials must carry
    /// the original session's authentication time forward so recent-auth
    /// step-up checks cannot be reset by an attacker holding a stolen token.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_with_created_at(
        db: DB<'_>,
        user_id: &str,
        token_hash: &str,
        expires_at: NaiveDateTime,
        refresh_token: Option<&str>,
        refresh_token_expires_at: Option<NaiveDateTime>,
        org_slug: Option<&str>,
        service_id: Option<&str>,
        resource: Option<&str>,
        user_agent: Option<&str>,
        ip_address: Option<&str>,
        created_at: NaiveDateTime,
    ) -> Result<sessions::Model> {
        let new_session = sessions::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            user_id: Set(user_id.to_string()),
            token_hash: Set(token_hash.to_string()),
            expires_at: Set(expires_at),
            // The legacy plaintext column is deliberately kept NULL until a
            // later compatibility migration removes it from the schema.
            refresh_token: Set(None),
            refresh_token_hash: Set(refresh_token.map(crate::crypto::refresh_tokens::hash)),
            refresh_token_expires_at: Set(refresh_token_expires_at),
            org_slug: Set(org_slug.map(std::string::ToString::to_string)),
            service_id: Set(service_id.map(std::string::ToString::to_string)),
            resource: Set(resource.map(std::string::ToString::to_string)),
            user_agent: Set(user_agent.map(std::string::ToString::to_string)),
            ip_address: Set(ip_address.map(std::string::ToString::to_string)),
            created_at: Set(created_at),
            ..Default::default()
        };

        let session = new_session;
        let db_clone = db.clone();

        let session = crate::db::transaction::with_deadlock_retry("create_session", 10, || {
            let session_am = session.clone();
            let db = &db_clone;
            async move { session_am.insert(db).await }
        })
        .await?;

        Ok(session)
    }

    /// Delete a session
    pub async fn delete(db: DB<'_>, session_id: &str) -> Result<()> {
        let result = Sessions::delete_many()
            .filter(sessions::Column::Id.eq(session_id))
            .exec(&db)
            .await?;

        if result.rows_affected == 0 {
            return Err(AppError::NotFound("Session not found".to_string()));
        }

        Ok(())
    }

    /// Delete session by token hash
    pub async fn delete_by_token_hash(db: DB<'_>, token_hash: &str) -> Result<()> {
        Sessions::delete_many()
            .filter(sessions::Column::TokenHash.eq(token_hash))
            .exec(&db)
            .await?;

        Ok(())
    }

    /// Delete all sessions for a user
    pub async fn delete_all_for_user(db: DB<'_>, user_id: &str) -> Result<u64> {
        let result = Sessions::delete_many()
            .filter(sessions::Column::UserId.eq(user_id))
            .exec(&db)
            .await?;

        Ok(result.rows_affected)
    }

    /// Delete all sessions for a user in a specific service
    pub async fn delete_user_service_sessions(
        db: DB<'_>,
        user_id: &str,
        service_id: &str,
    ) -> Result<u64> {
        let result = Sessions::delete_many()
            .filter(sessions::Column::UserId.eq(user_id))
            .filter(sessions::Column::ServiceId.eq(service_id))
            .exec(&db)
            .await?;

        Ok(result.rows_affected)
    }

    /// Delete sessions scoped to an organization slug or one of its services.
    pub async fn delete_user_org_scoped_sessions(
        db: DB<'_>,
        user_id: &str,
        org_slug: &str,
        service_ids: &[String],
    ) -> Result<u64> {
        use sea_orm::Condition;

        let mut scope = Condition::any().add(sessions::Column::OrgSlug.eq(org_slug));
        if !service_ids.is_empty() {
            scope = scope.add(sessions::Column::ServiceId.is_in(service_ids.iter().cloned()));
        }

        let result = Sessions::delete_many()
            .filter(sessions::Column::UserId.eq(user_id))
            .filter(scope)
            .exec(&db)
            .await?;

        Ok(result.rows_affected)
    }

    /// Delete expired sessions
    pub async fn delete_expired(db: DB<'_>) -> Result<u64> {
        use sea_orm::Condition;

        let now = chrono::Utc::now().naive_utc();

        let result = Sessions::delete_many()
            .filter(sessions::Column::ExpiresAt.lt(now))
            .filter(
                Condition::any()
                    .add(sessions::Column::RefreshTokenExpiresAt.is_null())
                    .add(sessions::Column::RefreshTokenExpiresAt.lt(now)),
            )
            .exec(&db)
            .await?;

        Ok(result.rows_affected)
    }

    /// List sessions for a user
    pub async fn list_by_user(db: DB<'_>, user_id: &str) -> Result<Vec<sessions::Model>> {
        let sessions = Sessions::find()
            .filter(sessions::Column::UserId.eq(user_id))
            .all(&db)
            .await?;

        Ok(sessions)
    }

    /// List sessions scoped to an organization slug or one of its services.
    pub async fn list_user_org_scoped_sessions(
        db: DB<'_>,
        user_id: &str,
        org_slug: &str,
        service_ids: &[String],
    ) -> Result<Vec<sessions::Model>> {
        use sea_orm::Condition;

        let mut scope = Condition::any().add(sessions::Column::OrgSlug.eq(org_slug));
        if !service_ids.is_empty() {
            scope = scope.add(sessions::Column::ServiceId.is_in(service_ids.iter().cloned()));
        }

        let sessions = Sessions::find()
            .filter(sessions::Column::UserId.eq(user_id))
            .filter(scope)
            .all(&db)
            .await?;

        Ok(sessions)
    }

    /// Count active (non-expired) sessions for a user
    pub async fn count_active_by_user(db: DB<'_>, user_id: &str) -> Result<u64> {
        use sea_orm::PaginatorTrait;

        let now = chrono::Utc::now().naive_utc();

        let count = Sessions::find()
            .filter(sessions::Column::UserId.eq(user_id))
            .filter(sessions::Column::ExpiresAt.gt(now))
            .count(&db)
            .await?;

        Ok(count)
    }

    /// Update session tokens for token rotation
    pub async fn update_tokens(
        db: DB<'_>,
        session_id: &str,
        current_refresh_token: &str,
        new_token_hash: &str,
        new_expires_at: NaiveDateTime,
        new_refresh_token: &str,
        new_refresh_expires_at: NaiveDateTime,
    ) -> Result<RefreshRotationOutcome> {
        match db {
            DB::Conn(connection) => {
                let transaction = connection.begin().await?;
                let outcome = Self::update_tokens_in_transaction(
                    DB::Tx(&transaction),
                    session_id,
                    current_refresh_token,
                    new_token_hash,
                    new_expires_at,
                    new_refresh_token,
                    new_refresh_expires_at,
                )
                .await;

                match outcome {
                    Ok(outcome) => {
                        transaction.commit().await?;
                        Ok(outcome)
                    }
                    Err(error) => {
                        transaction.rollback().await?;
                        Err(error)
                    }
                }
            }
            DB::Tx(transaction) => {
                Self::update_tokens_in_transaction(
                    DB::Tx(transaction),
                    session_id,
                    current_refresh_token,
                    new_token_hash,
                    new_expires_at,
                    new_refresh_token,
                    new_refresh_expires_at,
                )
                .await
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn update_tokens_in_transaction(
        db: DB<'_>,
        session_id: &str,
        current_refresh_token: &str,
        new_token_hash: &str,
        new_expires_at: NaiveDateTime,
        new_refresh_token: &str,
        new_refresh_expires_at: NaiveDateTime,
    ) -> Result<RefreshRotationOutcome> {
        let current_refresh_token_hash = crate::crypto::refresh_tokens::hash(current_refresh_token);
        let new_refresh_token_hash = crate::crypto::refresh_tokens::hash(new_refresh_token);
        let result = Sessions::update_many()
            .filter(sessions::Column::Id.eq(session_id))
            .filter(sessions::Column::RefreshTokenHash.eq(&current_refresh_token_hash))
            .col_expr(
                sessions::Column::TokenHash,
                sea_orm::sea_query::Expr::value(new_token_hash),
            )
            .col_expr(
                sessions::Column::ExpiresAt,
                sea_orm::sea_query::Expr::value(new_expires_at),
            )
            .col_expr(
                sessions::Column::RefreshTokenHash,
                sea_orm::sea_query::Expr::value(new_refresh_token_hash),
            )
            .col_expr(
                sessions::Column::RefreshTokenExpiresAt,
                sea_orm::sea_query::Expr::value(new_refresh_expires_at),
            )
            .exec(&db)
            .await?;

        if result.rows_affected == 1 {
            session_refresh_token_history::ActiveModel {
                token_hash: Set(current_refresh_token_hash),
                session_id: Set(session_id.to_string()),
                ..Default::default()
            }
            .insert(&db)
            .await?;
            return Ok(RefreshRotationOutcome::Rotated);
        }

        // The caller found this session by the presented hash before entering
        // rotation. Losing the conditional update means another request has
        // consumed the same token: revoke the entire session/family.
        Sessions::delete_many()
            .filter(sessions::Column::Id.eq(session_id))
            .exec(&db)
            .await?;
        Ok(RefreshRotationOutcome::ReuseDetected)
    }

    /// Revoke a session family when an already-consumed ancestor is replayed.
    pub async fn revoke_if_consumed_refresh_token(db: DB<'_>, refresh_token: &str) -> Result<bool> {
        let token_hash = crate::crypto::refresh_tokens::hash(refresh_token);
        let consumed = SessionRefreshTokenHistory::find_by_id(token_hash)
            .one(&db)
            .await?;
        let Some(consumed) = consumed else {
            return Ok(false);
        };

        Sessions::delete_many()
            .filter(sessions::Column::Id.eq(consumed.session_id))
            .exec(&db)
            .await?;
        Ok(true)
    }

    /// Delete all sessions for a user except the current session (for security after password change)
    pub async fn delete_all_except_current(
        db: DB<'_>,
        user_id: &str,
        current_session_id: &str,
    ) -> Result<u64> {
        let result = Sessions::delete_many()
            .filter(sessions::Column::UserId.eq(user_id))
            .filter(sessions::Column::Id.ne(current_session_id))
            .exec(&db)
            .await?;

        Ok(result.rows_affected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::users::{UserCreationOptions, UserStore};
    use chrono::{Duration, Utc};
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;

    async fn refresh_session_fixture() -> (sea_orm::DatabaseConnection, sessions::Model, String) {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let (user, _) = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "refresh-session@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create user");
        let refresh_token = crate::crypto::refresh_tokens::generate();
        let session = SessionStore::create(
            DB::Conn(&db),
            &user.id,
            "access-token-hash",
            (Utc::now() + Duration::hours(1)).naive_utc(),
            Some(&refresh_token),
            Some((Utc::now() + Duration::days(30)).naive_utc()),
            Some("acme"),
            None,
            None,
            None,
            None,
        )
        .await
        .expect("create refresh session");

        (db, session, refresh_token)
    }

    #[tokio::test]
    async fn refresh_tokens_are_high_entropy_hashed_at_rest_and_never_in_legacy_column() {
        let (db, session, refresh_token) = refresh_session_fixture().await;

        assert_eq!(session.refresh_token, None);
        assert_eq!(
            session.refresh_token_hash.as_deref(),
            Some(crate::crypto::refresh_tokens::hash(&refresh_token).as_str())
        );
        assert_ne!(
            session.refresh_token_hash.as_deref(),
            Some(refresh_token.as_str())
        );
        assert_eq!(
            SessionStore::find_by_refresh_token(DB::Conn(&db), &refresh_token)
                .await
                .unwrap()
                .unwrap()
                .id,
            session.id
        );
    }

    #[tokio::test]
    async fn sqlite_database_file_does_not_contain_refresh_bearer() {
        let path =
            std::env::temp_dir().join(format!("authos-refresh-token-canary-{}.db", Uuid::new_v4()));
        let database_url = format!("sqlite://{}?mode=rwc", path.display());
        let db = Database::connect(&database_url)
            .await
            .expect("connect file-backed sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let (user, _) = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "refresh-dump-canary@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create user");
        let refresh_token = crate::crypto::refresh_tokens::generate();
        let refresh_hash = crate::crypto::refresh_tokens::hash(&refresh_token);
        SessionStore::create(
            DB::Conn(&db),
            &user.id,
            "dump-canary-access-hash",
            (Utc::now() + Duration::hours(1)).naive_utc(),
            Some(&refresh_token),
            Some((Utc::now() + Duration::days(30)).naive_utc()),
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("create refresh session");
        db.close().await.expect("close sqlite database");

        let database_bytes = std::fs::read(&path).expect("read sqlite database");
        assert!(
            !database_bytes
                .windows(refresh_token.len())
                .any(|window| window == refresh_token.as_bytes()),
            "raw refresh bearer leaked into the SQLite database file"
        );
        assert!(
            database_bytes
                .windows(refresh_hash.len())
                .any(|window| window == refresh_hash.as_bytes()),
            "expected refresh-token digest was not persisted"
        );
        std::fs::remove_file(path).expect("remove sqlite canary database");
    }

    #[tokio::test]
    async fn consumed_ancestor_replay_revokes_the_current_session_family() {
        let (db, session, refresh_token) = refresh_session_fixture().await;
        let replacement = crate::crypto::refresh_tokens::generate();

        assert_eq!(
            SessionStore::update_tokens(
                DB::Conn(&db),
                &session.id,
                &refresh_token,
                "new-access-hash",
                (Utc::now() + Duration::hours(1)).naive_utc(),
                &replacement,
                (Utc::now() + Duration::days(30)).naive_utc(),
            )
            .await
            .unwrap(),
            RefreshRotationOutcome::Rotated
        );
        assert!(
            SessionStore::find_by_refresh_token(DB::Conn(&db), &replacement)
                .await
                .unwrap()
                .is_some()
        );

        assert!(
            SessionStore::revoke_if_consumed_refresh_token(DB::Conn(&db), &refresh_token)
                .await
                .unwrap()
        );
        assert!(SessionStore::find_by_id(DB::Conn(&db), &session.id)
            .await
            .unwrap()
            .is_none());
        assert!(
            SessionStore::find_by_refresh_token(DB::Conn(&db), &replacement)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn competing_refresh_rotations_have_one_winner_and_revoke_on_reuse() {
        let (db, session, refresh_token) = refresh_session_fixture().await;
        let first_replacement = crate::crypto::refresh_tokens::generate();
        let second_replacement = crate::crypto::refresh_tokens::generate();
        let new_expiry = (Utc::now() + Duration::hours(1)).naive_utc();
        let new_refresh_expiry = (Utc::now() + Duration::days(30)).naive_utc();

        let first = SessionStore::update_tokens(
            DB::Conn(&db),
            &session.id,
            &refresh_token,
            "first-access-hash",
            new_expiry,
            &first_replacement,
            new_refresh_expiry,
        );
        let second = SessionStore::update_tokens(
            DB::Conn(&db),
            &session.id,
            &refresh_token,
            "second-access-hash",
            new_expiry,
            &second_replacement,
            new_refresh_expiry,
        );
        let (first, second) = tokio::join!(first, second);
        let outcomes = [first.unwrap(), second.unwrap()];

        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == RefreshRotationOutcome::Rotated)
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == RefreshRotationOutcome::ReuseDetected)
                .count(),
            1
        );
        assert!(SessionStore::find_by_id(DB::Conn(&db), &session.id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn cleanup_retains_refreshable_sessions_until_refresh_expiry() {
        let (db, session, _) = refresh_session_fixture().await;
        let now = Utc::now().naive_utc();
        Sessions::update_many()
            .filter(sessions::Column::Id.eq(&session.id))
            .col_expr(
                sessions::Column::ExpiresAt,
                sea_orm::sea_query::Expr::value(now - Duration::minutes(1)),
            )
            .exec(&db)
            .await
            .unwrap();

        assert_eq!(
            SessionStore::delete_expired(DB::Conn(&db)).await.unwrap(),
            0
        );
        assert!(SessionStore::find_by_id(DB::Conn(&db), &session.id)
            .await
            .unwrap()
            .is_some());

        Sessions::update_many()
            .filter(sessions::Column::Id.eq(&session.id))
            .col_expr(
                sessions::Column::RefreshTokenExpiresAt,
                sea_orm::sea_query::Expr::value(now - Duration::seconds(1)),
            )
            .exec(&db)
            .await
            .unwrap();
        assert_eq!(
            SessionStore::delete_expired(DB::Conn(&db)).await.unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn list_user_org_scoped_sessions_filters_in_sql_shape() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");

        let (user, _) = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "session-user@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create user");

        let expires_at = (Utc::now() + Duration::hours(1)).naive_utc();
        SessionStore::create(
            DB::Conn(&db),
            &user.id,
            "token-org",
            expires_at,
            None,
            None,
            Some("org-a"),
            None,
            None,
            None,
            None,
        )
        .await
        .expect("create org session");
        SessionStore::create(
            DB::Conn(&db),
            &user.id,
            "token-service",
            expires_at,
            None,
            None,
            None,
            Some("svc-a"),
            None,
            None,
            None,
        )
        .await
        .expect("create service session");
        SessionStore::create(
            DB::Conn(&db),
            &user.id,
            "token-other",
            expires_at,
            None,
            None,
            Some("org-b"),
            Some("svc-b"),
            None,
            None,
            None,
        )
        .await
        .expect("create other session");

        let sessions = SessionStore::list_user_org_scoped_sessions(
            DB::Conn(&db),
            &user.id,
            "org-a",
            &["svc-a".to_string()],
        )
        .await
        .expect("list scoped sessions");
        let token_hashes = sessions
            .into_iter()
            .map(|session| session.token_hash)
            .collect::<std::collections::HashSet<_>>();

        assert_eq!(token_hashes.len(), 2);
        assert!(token_hashes.contains("token-org"));
        assert!(token_hashes.contains("token-service"));
        assert!(!token_hashes.contains("token-other"));
    }

    #[tokio::test]
    async fn direct_session_deletes_preserve_missing_row_semantics() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");

        let (user, _) = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "delete-session-user@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create user");
        let expires_at = (Utc::now() + Duration::hours(1)).naive_utc();
        let session = SessionStore::create(
            DB::Conn(&db),
            &user.id,
            "delete-token",
            expires_at,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("create session");

        SessionStore::delete(DB::Conn(&db), &session.id)
            .await
            .expect("delete session");
        assert!(SessionStore::find_by_id(DB::Conn(&db), &session.id)
            .await
            .expect("load deleted session")
            .is_none());
        assert!(matches!(
            SessionStore::delete(DB::Conn(&db), &session.id).await,
            Err(AppError::NotFound(_))
        ));
        SessionStore::delete_by_token_hash(DB::Conn(&db), "missing-token")
            .await
            .expect("missing token-hash delete is a noop");
    }

    #[tokio::test]
    async fn org_scoped_session_revocation_preserves_other_tenant_and_other_user() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let (target_user, _) = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "session-scope-target@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create target user");
        let (other_user, _) = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "session-scope-other@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create other user");
        let expires_at = (Utc::now() + Duration::hours(1)).naive_utc();
        let scoped = SessionStore::create(
            DB::Conn(&db),
            &target_user.id,
            "scope-org-a",
            expires_at,
            None,
            None,
            Some("org-a"),
            None,
            None,
            None,
            None,
        )
        .await
        .expect("create scoped target session");
        let other_tenant = SessionStore::create(
            DB::Conn(&db),
            &target_user.id,
            "scope-org-b",
            expires_at,
            None,
            None,
            Some("org-b"),
            None,
            None,
            None,
            None,
        )
        .await
        .expect("create other-tenant session");
        let other_users = SessionStore::create(
            DB::Conn(&db),
            &other_user.id,
            "scope-other-user",
            expires_at,
            None,
            None,
            Some("org-a"),
            None,
            None,
            None,
            None,
        )
        .await
        .expect("create other-user session");

        assert_eq!(
            SessionStore::delete_user_org_scoped_sessions(
                DB::Conn(&db),
                &target_user.id,
                "org-a",
                &[]
            )
            .await
            .expect("revoke target scope"),
            1
        );
        assert!(SessionStore::find_by_id(DB::Conn(&db), &scoped.id)
            .await
            .expect("load revoked session")
            .is_none());
        let unchanged_other_tenant = SessionStore::find_by_id(DB::Conn(&db), &other_tenant.id)
            .await
            .expect("load other-tenant session")
            .expect("other tenant session must remain");
        assert_eq!(unchanged_other_tenant.token_hash, "scope-org-b");
        let unchanged_other_user = SessionStore::find_by_id(DB::Conn(&db), &other_users.id)
            .await
            .expect("load other-user session")
            .expect("other user's session must remain");
        assert_eq!(unchanged_other_user.token_hash, "scope-other-user");
    }
}
