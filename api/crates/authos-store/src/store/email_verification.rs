use crate::db::DB;
use crate::entities::email_verification_tokens;
use crate::entities::prelude::EmailVerificationTokens;
use crate::error::Result;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use uuid::Uuid;

pub struct EmailVerificationStore;

impl EmailVerificationStore {
    /// Find an email verification token by token hash
    pub async fn find_by_token_hash(
        db: DB<'_>,
        token_hash: &str,
    ) -> Result<Option<email_verification_tokens::Model>> {
        let result = EmailVerificationTokens::find()
            .filter(email_verification_tokens::Column::TokenHash.eq(token_hash))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Create a new email verification token
    pub async fn create(
        db: DB<'_>,
        user_id: &str,
        token_hash: &str,
        expires_at: &chrono::NaiveDateTime,
    ) -> Result<email_verification_tokens::Model> {
        let new_token = email_verification_tokens::ActiveModel {
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

    /// Invalidate every outstanding verification token for a user. Used when
    /// the email address changes so a token issued for the previous address
    /// cannot verify the replacement address.
    pub async fn delete_all_for_user(db: DB<'_>, user_id: &str) -> Result<u64> {
        let result = EmailVerificationTokens::delete_many()
            .filter(email_verification_tokens::Column::UserId.eq(user_id))
            .exec(&db)
            .await?;
        Ok(result.rows_affected)
    }

    /// Mark an email verification token as used
    pub async fn mark_as_used(db: DB<'_>, token_hash: &str) -> Result<bool> {
        let now = chrono::Utc::now().naive_utc();
        let result = EmailVerificationTokens::update_many()
            .filter(email_verification_tokens::Column::TokenHash.eq(token_hash))
            .filter(email_verification_tokens::Column::Used.eq(false))
            .filter(email_verification_tokens::Column::ExpiresAt.gt(now))
            .col_expr(
                email_verification_tokens::Column::Used,
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

    #[tokio::test]
    async fn concurrent_email_verification_claim_has_exactly_one_winner() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let user = UserStore::create(DB::Conn(&db), "verify@example.com", None, false)
            .await
            .expect("create user");
        EmailVerificationStore::create(
            DB::Conn(&db),
            &user.id,
            "verification-hash",
            &(Utc::now() + Duration::minutes(5)).naive_utc(),
        )
        .await
        .expect("create verification token");

        let first = EmailVerificationStore::mark_as_used(DB::Conn(&db), "verification-hash");
        let second = EmailVerificationStore::mark_as_used(DB::Conn(&db), "verification-hash");
        let (first, second) = tokio::join!(first, second);
        assert_eq!(
            usize::from(first.expect("first claim")) + usize::from(second.expect("second claim")),
            1
        );
    }

    #[tokio::test]
    async fn expired_email_verification_token_cannot_be_claimed() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let user = UserStore::create(DB::Conn(&db), "expired-verify@example.com", None, false)
            .await
            .expect("create user");
        EmailVerificationStore::create(
            DB::Conn(&db),
            &user.id,
            "expired-verification-hash",
            &(Utc::now() - Duration::seconds(1)).naive_utc(),
        )
        .await
        .expect("create expired verification token");

        assert!(
            !EmailVerificationStore::mark_as_used(DB::Conn(&db), "expired-verification-hash")
                .await
                .expect("claim expired token")
        );
    }
}
