use crate::db::DB;
use crate::entities::{magic_link_tokens, prelude::MagicLinkTokens};
use crate::error::Result;
use chrono::{Duration, Utc};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use sha2::{Digest, Sha256};

pub struct MagicLinksStore;

impl MagicLinksStore {
    /// Create a new magic link token
    /// Returns the plaintext token that should be sent in the email
    pub async fn create(
        db: DB<'_>,
        email: &str,
        user_id: Option<&str>,
        context: &str,
    ) -> Result<String> {
        // Generate a secure random token (32 bytes = 64 hex chars)
        let token_bytes = rand::random::<[u8; 32]>();
        let token = hex::encode(token_bytes);

        // Hash the token for storage (SHA256)
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let token_hash = hex::encode(hasher.finalize());

        // Token expires in 15 minutes
        let expires_at = (Utc::now() + Duration::minutes(15)).naive_utc();

        let magic_link = magic_link_tokens::ActiveModel {
            token_hash: Set(token_hash),
            user_id: Set(user_id.map(std::string::ToString::to_string)),
            email: Set(email.to_string()),
            context: Set(context.to_string()),
            created_at: Set(Utc::now().naive_utc()),
            expires_at: Set(expires_at),
        };

        magic_link.insert(&db).await?;

        // Return the plaintext token to be sent in email
        Ok(token)
    }

    /// Find a magic link token by its hash
    pub async fn find_by_token(
        db: DB<'_>,
        token: &str,
    ) -> Result<Option<magic_link_tokens::Model>> {
        // Hash the provided token
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let token_hash = hex::encode(hasher.finalize());

        let magic_link = MagicLinkTokens::find()
            .filter(magic_link_tokens::Column::TokenHash.eq(&token_hash))
            .one(&db)
            .await?;

        Ok(magic_link)
    }

    /// Delete a magic link token (one-time use)
    pub async fn delete(db: DB<'_>, token: &str) -> Result<bool> {
        // Hash the provided token
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let token_hash = hex::encode(hasher.finalize());

        let result = MagicLinkTokens::delete_many()
            .filter(magic_link_tokens::Column::TokenHash.eq(&token_hash))
            .exec(&db)
            .await?;

        Ok(result.rows_affected == 1)
    }

    /// Delete a magic link token by hash directly
    pub async fn delete_by_hash(db: DB<'_>, token_hash: &str) -> Result<bool> {
        let result = MagicLinkTokens::delete_many()
            .filter(magic_link_tokens::Column::TokenHash.eq(token_hash))
            .exec(&db)
            .await?;

        Ok(result.rows_affected == 1)
    }

    /// Invalidate every outstanding magic link for a user. Email changes must
    /// not leave a link addressed to the previous mailbox usable against the
    /// account.
    pub async fn delete_all_for_user(db: DB<'_>, user_id: &str) -> Result<u64> {
        let result = MagicLinkTokens::delete_many()
            .filter(magic_link_tokens::Column::UserId.eq(user_id))
            .exec(&db)
            .await?;
        Ok(result.rows_affected)
    }

    /// Clean up expired magic link tokens (for background job)
    pub async fn cleanup_expired(db: DB<'_>) -> Result<u64> {
        let now = Utc::now().naive_utc();

        let result = MagicLinkTokens::delete_many()
            .filter(magic_link_tokens::Column::ExpiresAt.lt(now))
            .exec(&db)
            .await?;

        Ok(result.rows_affected)
    }

    /// Find all pending magic links for an email (for debugging/admin purposes)
    pub async fn find_by_email(db: DB<'_>, email: &str) -> Result<Vec<magic_link_tokens::Model>> {
        let tokens = MagicLinkTokens::find()
            .filter(magic_link_tokens::Column::Email.eq(email))
            .all(&db)
            .await?;

        Ok(tokens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;
    use std::sync::Arc;
    use tokio::sync::Barrier;

    #[tokio::test]
    async fn concurrent_consumption_has_exactly_one_winner() {
        let path = std::env::temp_dir().join(format!("authos-magic-{}.db", uuid::Uuid::new_v4()));
        let db = Database::connect(format!("sqlite://{}?mode=rwc", path.display()))
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let token = MagicLinksStore::create(DB::Conn(&db), "user@example.test", None, "{}")
            .await
            .expect("create magic link");

        let barrier = Arc::new(Barrier::new(3));
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let db = db.clone();
            let token = token.clone();
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                MagicLinksStore::delete(DB::Conn(&db), &token)
                    .await
                    .expect("consume token")
            }));
        }
        barrier.wait().await;

        let mut wins = 0;
        for task in tasks {
            wins += usize::from(task.await.expect("join consumer"));
        }
        assert_eq!(wins, 1);
        assert!(MagicLinksStore::find_by_token(DB::Conn(&db), &token)
            .await
            .expect("reload token")
            .is_none());

        db.close().await.expect("close sqlite");
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn email_change_can_invalidate_every_link_for_the_user() {
        let path = std::env::temp_dir().join(format!("authos-magic-{}.db", uuid::Uuid::new_v4()));
        let db = Database::connect(format!("sqlite://{}?mode=rwc", path.display()))
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let first_user =
            crate::store::users::UserStore::create(DB::Conn(&db), "old@example.test", None, false)
                .await
                .expect("create first user");
        let second_user = crate::store::users::UserStore::create(
            DB::Conn(&db),
            "other@example.test",
            None,
            false,
        )
        .await
        .expect("create second user");
        let first = MagicLinksStore::create(
            DB::Conn(&db),
            "old@example.test",
            Some(&first_user.id),
            "{}",
        )
        .await
        .expect("create first magic link");
        let second = MagicLinksStore::create(
            DB::Conn(&db),
            "old@example.test",
            Some(&first_user.id),
            "{}",
        )
        .await
        .expect("create second magic link");
        MagicLinksStore::create(
            DB::Conn(&db),
            "other@example.test",
            Some(&second_user.id),
            "{}",
        )
        .await
        .expect("create unrelated magic link");

        assert_eq!(
            MagicLinksStore::delete_all_for_user(DB::Conn(&db), &first_user.id)
                .await
                .expect("delete user links"),
            2
        );
        assert!(MagicLinksStore::find_by_token(DB::Conn(&db), &first)
            .await
            .expect("reload first")
            .is_none());
        assert!(MagicLinksStore::find_by_token(DB::Conn(&db), &second)
            .await
            .expect("reload second")
            .is_none());

        db.close().await.expect("close sqlite");
        let _ = std::fs::remove_file(path);
    }
}
