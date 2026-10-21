use crate::db::DB;
use crate::entities::password_reset_tokens;
use crate::entities::prelude::PasswordResetTokens;
use crate::error::Result;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use uuid::Uuid;

pub struct PasswordResetStore;

impl PasswordResetStore {
    /// Find a password reset token by token hash
    pub async fn find_by_token_hash(
        db: DB<'_>,
        token_hash: &str,
    ) -> Result<Option<password_reset_tokens::Model>> {
        let result = PasswordResetTokens::find()
            .filter(password_reset_tokens::Column::TokenHash.eq(token_hash))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Create a new password reset token
    pub async fn create(
        db: DB<'_>,
        user_id: &str,
        token_hash: &str,
        expires_at: &chrono::NaiveDateTime,
    ) -> Result<password_reset_tokens::Model> {
        let new_token = password_reset_tokens::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            user_id: Set(user_id.to_string()),
            token_hash: Set(token_hash.to_string()),
            expires_at: Set(*expires_at),
            used: Set(false),
            ..Default::default()
        };

        let token = new_token.insert(&db).await?;
        Ok(token)
    }

    /// Invalidate every outstanding password-reset token for a user.
    pub async fn delete_all_for_user(db: DB<'_>, user_id: &str) -> Result<u64> {
        let result = PasswordResetTokens::delete_many()
            .filter(password_reset_tokens::Column::UserId.eq(user_id))
            .exec(&db)
            .await?;
        Ok(result.rows_affected)
    }

    /// Mark a password reset token as used
    pub async fn mark_as_used(db: DB<'_>, token_hash: &str) -> Result<bool> {
        let now = chrono::Utc::now().naive_utc();
        let result = PasswordResetTokens::update_many()
            .filter(password_reset_tokens::Column::TokenHash.eq(token_hash))
            .filter(password_reset_tokens::Column::Used.eq(false))
            .filter(password_reset_tokens::Column::ExpiresAt.gt(now))
            .col_expr(
                password_reset_tokens::Column::Used,
                sea_orm::sea_query::Expr::value(true),
            )
            .exec(&db)
            .await?;

        Ok(result.rows_affected == 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::users::UserStore;
    use chrono::{Duration, Utc};
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;
    use std::sync::Arc;
    use tokio::sync::Barrier;

    #[tokio::test]
    async fn concurrent_use_has_exactly_one_winner() {
        let path = std::env::temp_dir().join(format!("authos-reset-{}.db", uuid::Uuid::new_v4()));
        let db = Database::connect(format!("sqlite://{}?mode=rwc", path.display()))
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let user = UserStore::create(DB::Conn(&db), "reset-user@example.test", None, false)
            .await
            .expect("create user");
        let expires_at = (Utc::now() + Duration::minutes(5)).naive_utc();
        PasswordResetStore::create(DB::Conn(&db), &user.id, "reset-hash", &expires_at)
            .await
            .expect("create reset token");

        let barrier = Arc::new(Barrier::new(3));
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let db = db.clone();
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                PasswordResetStore::mark_as_used(DB::Conn(&db), "reset-hash")
                    .await
                    .expect("consume reset token")
            }));
        }
        barrier.wait().await;

        let mut wins = 0;
        for task in tasks {
            wins += usize::from(task.await.expect("join consumer"));
        }
        assert_eq!(wins, 1);

        db.close().await.expect("close sqlite");
        let _ = std::fs::remove_file(path);
    }
}
