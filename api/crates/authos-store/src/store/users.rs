use crate::db::DB;
use crate::entities::prelude::{Memberships, Users};
use crate::entities::{memberships, users};
use crate::error::{AppError, Result};
use chrono::{NaiveDate, NaiveDateTime};
use sea_orm::{
    sea_query::{Expr, Query},
    ActiveModelTrait, ColumnTrait, Condition, EntityTrait, FromQueryResult, NotSet, PaginatorTrait,
    QueryFilter, QueryOrder, QuerySelect, Set,
};
use uuid::Uuid;

/// Options for user creation to unify different creation patterns
#[derive(Debug, Default)]
pub struct UserCreationOptions {
    /// Whether the user should be a platform owner
    pub is_platform_owner: bool,
    /// Optional password hash (for password-based users)
    pub password_hash: Option<String>,
    /// Platform owner email to check against for automatic platform owner detection
    pub platform_owner_email: Option<String>,
    /// Whether to mark email as verified immediately
    pub mark_email_verified: bool,
}

pub struct UserStore;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserEmailFilterOp {
    Equals,
    Contains,
    StartsWith,
    EndsWith,
    NotEquals,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserEmailFilter {
    pub op: UserEmailFilterOp,
    pub value: String,
}

impl UserStore {
    /// Find a user by their ID
    pub async fn find_by_id(db: DB<'_>, user_id: &str) -> Result<Option<users::Model>> {
        let result = Users::find()
            .filter(users::Column::Id.eq(user_id))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Find users by a list of IDs
    pub async fn find_by_ids(db: DB<'_>, user_ids: &[String]) -> Result<Vec<users::Model>> {
        let results = Users::find()
            .filter(users::Column::Id.is_in(user_ids))
            .all(&db)
            .await?;
        Ok(results)
    }

    /// List SCIM-visible users for an organization through memberships.
    pub async fn list_scim_org_members(
        db: DB<'_>,
        org_id: &str,
        email_filters: &[UserEmailFilter],
        limit: u64,
        offset: u64,
    ) -> Result<Vec<users::Model>> {
        use sea_orm::{JoinType, RelationTrait};

        let mut query = Users::find()
            .join(JoinType::InnerJoin, users::Relation::Memberships.def())
            .filter(memberships::Column::OrgId.eq(org_id))
            .order_by_asc(users::Column::CreatedAt)
            .limit(limit)
            .offset(offset);

        for filter in email_filters {
            query = match filter.op {
                UserEmailFilterOp::Equals => query.filter(users::Column::Email.eq(&filter.value)),
                UserEmailFilterOp::Contains => {
                    query.filter(users::Column::Email.contains(&filter.value))
                }
                UserEmailFilterOp::StartsWith => {
                    query.filter(users::Column::Email.starts_with(&filter.value))
                }
                UserEmailFilterOp::EndsWith => {
                    query.filter(users::Column::Email.ends_with(&filter.value))
                }
                UserEmailFilterOp::NotEquals => {
                    query.filter(users::Column::Email.ne(&filter.value))
                }
            };
        }

        let users = query.all(&db).await?;
        Ok(users)
    }

    /// Count SCIM-visible users for an organization through memberships.
    pub async fn count_scim_org_members(
        db: DB<'_>,
        org_id: &str,
        email_filters: &[UserEmailFilter],
    ) -> Result<u64> {
        use sea_orm::{JoinType, RelationTrait};

        let mut query = Users::find()
            .join(JoinType::InnerJoin, users::Relation::Memberships.def())
            .filter(memberships::Column::OrgId.eq(org_id));

        for filter in email_filters {
            query = match filter.op {
                UserEmailFilterOp::Equals => query.filter(users::Column::Email.eq(&filter.value)),
                UserEmailFilterOp::Contains => {
                    query.filter(users::Column::Email.contains(&filter.value))
                }
                UserEmailFilterOp::StartsWith => {
                    query.filter(users::Column::Email.starts_with(&filter.value))
                }
                UserEmailFilterOp::EndsWith => {
                    query.filter(users::Column::Email.ends_with(&filter.value))
                }
                UserEmailFilterOp::NotEquals => {
                    query.filter(users::Column::Email.ne(&filter.value))
                }
            };
        }

        let count = query.count(&db).await?;
        Ok(count)
    }

    /// Update a SCIM-managed user only when both the user record and a live
    /// membership belong to the token organization. The organization predicate
    /// prevents a SCIM tenant from mutating a shared/platform user through a
    /// membership, and the membership EXISTS predicate removes the handler's
    /// preload-to-primary-key update race.
    pub async fn update_scim_owned_member(
        db: DB<'_>,
        org_id: &str,
        user_id: &str,
        email: &str,
        active: bool,
    ) -> Result<Option<users::Model>> {
        let Some(current) = Users::find()
            .filter(users::Column::Id.eq(user_id))
            .filter(users::Column::OrgId.eq(org_id))
            .filter(users::Column::IsPlatformOwner.eq(false))
            .one(&db)
            .await?
        else {
            return Ok(None);
        };
        let email_changed = current.email != email;

        let mut membership_scope = Query::select();
        membership_scope
            .expr(Expr::val(1))
            .from(memberships::Entity)
            .and_where(memberships::Column::OrgId.eq(org_id))
            .and_where(memberships::Column::UserId.eq(user_id));
        if !active {
            membership_scope.and_where(
                memberships::Column::Role.is_not_in(["owner".to_string(), "admin".to_string()]),
            );
        }

        let now = chrono::Utc::now().naive_utc();
        let result = Users::update_many()
            .filter(users::Column::Id.eq(user_id))
            .filter(users::Column::OrgId.eq(org_id))
            .filter(users::Column::IsPlatformOwner.eq(false))
            .filter(Expr::exists(membership_scope.clone()))
            .set(users::ActiveModel {
                email: Set(email.to_string()),
                email_verified_at: if email_changed { Set(None) } else { NotSet },
                deleted_at: Set(if active { None } else { Some(now) }),
                updated_at: Set(Some(now)),
                ..Default::default()
            })
            .exec(&db)
            .await?;

        if result.rows_affected != 1 {
            return Ok(None);
        }

        if email_changed {
            crate::store::email_verification::EmailVerificationStore::delete_all_for_user(
                db.clone(),
                user_id,
            )
            .await?;
            crate::store::password_reset::PasswordResetStore::delete_all_for_user(
                db.clone(),
                user_id,
            )
            .await?;
            crate::store::magic_links::MagicLinksStore::delete_all_for_user(db.clone(), user_id)
                .await?;
            crate::store::sessions::SessionStore::delete_all_for_user(db.clone(), user_id).await?;
        }

        Ok(Users::find()
            .filter(users::Column::Id.eq(user_id))
            .filter(users::Column::OrgId.eq(org_id))
            .one(&db)
            .await?)
    }

    /// Unified find or create user method with options
    /// If the user exists, return it. Otherwise, create a new user with the specified options.
    /// Returns (user, was_created) where was_created is true if the user was just created
    pub async fn find_or_create_with_options(
        db: DB<'_>,
        email: &str,
        options: UserCreationOptions,
    ) -> Result<(users::Model, bool)> {
        // This convenience path creates platform-context users. Tenant users
        // must use `create_with_org_id`; an unscoped lookup could otherwise
        // select a same-email account belonging to an unrelated organization.
        if let Some(user) = Self::find_by_email_with_context(db.clone(), email, None).await? {
            return Ok((user, false));
        }

        // Determine platform owner status
        let is_platform_owner = if let Some(owner_email) = options.platform_owner_email {
            owner_email.eq_ignore_ascii_case(email)
        } else {
            options.is_platform_owner
        };

        // Determine email verification timestamp
        let email_verified_at = if options.mark_email_verified {
            Some(chrono::Utc::now().naive_utc())
        } else {
            None
        };

        // Create new user
        let new_user = users::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            email: Set(email.to_string()),
            is_platform_owner: Set(is_platform_owner),
            password_hash: Set(options.password_hash),
            email_verified_at: Set(email_verified_at),
            ..Default::default()
        };

        let user = new_user.insert(&db).await?;
        Ok((user, true))
    }

    /// Find a user by their email address
    pub async fn find_by_email(db: DB<'_>, email: &str) -> Result<Option<users::Model>> {
        let result = Users::find()
            .filter(users::Column::Email.eq(email))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Security Audit Item 1: Find a user by email with tenant context
    ///
    /// - org_id = None: Find platform-level user (org_id IS NULL)
    /// - org_id = Some(id): Find user in specific organization
    ///
    /// This enforces tenant isolation for user lookups.
    pub async fn find_by_email_with_context(
        db: DB<'_>,
        email: &str,
        org_id: Option<&str>,
    ) -> Result<Option<users::Model>> {
        let mut query = Users::find().filter(users::Column::Email.eq(email));

        match org_id {
            Some(id) => {
                query = query.filter(users::Column::OrgId.eq(Some(id.to_string())));
            }
            None => {
                query = query.filter(users::Column::OrgId.is_null());
            }
        }

        let result = query.one(&db).await?;
        Ok(result)
    }

    /// Security Audit Item 1: Create a user associated with an organization
    ///
    /// Used by Service API to create tenant-scoped users.
    pub async fn create_with_org_id(
        db: DB<'_>,
        email: &str,
        password_hash: Option<String>,
        org_id: &str,
    ) -> Result<users::Model> {
        let new_user = users::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            email: Set(email.to_string()),
            org_id: Set(Some(org_id.to_string())),
            is_platform_owner: Set(false),
            password_hash: Set(password_hash),
            ..Default::default()
        };

        let user = new_user.insert(&db).await?;
        Ok(user)
    }

    /// Security Audit Item 1: Find any user by email (ignoring tenant context)
    ///
    /// WARNING: Use carefully. Primarily for security checks (preventing enumeration)
    /// or for internal system logic. Do NOT use for authentication without checking org_id.
    pub async fn find_any_by_email(db: DB<'_>, email: &str) -> Result<Option<users::Model>> {
        let user = Users::find()
            .filter(users::Column::Email.eq(email))
            .one(&db)
            .await?;
        Ok(user)
    }

    /// Find or create a user by email address
    /// If the user exists, return it. Otherwise, create a new user.
    /// Returns (user, was_created) where was_created is true if the user was just created
    pub async fn find_or_create(db: DB<'_>, email: &str) -> Result<(users::Model, bool)> {
        let options = UserCreationOptions::default();
        Self::find_or_create_with_options(db, email, options).await
    }

    /// Find or create a user for admin OAuth flow with platform owner detection
    /// If the user exists, return it. Otherwise, create a new user with platform owner check.
    /// Returns (user, was_created) where was_created is true if the user was just created
    pub async fn find_or_create_admin_oauth(
        db: DB<'_>,
        email: &str,
        platform_owner_email: Option<&str>,
    ) -> Result<(users::Model, bool)> {
        let options = UserCreationOptions {
            platform_owner_email: platform_owner_email.map(std::string::ToString::to_string),
            ..Default::default()
        };
        Self::find_or_create_with_options(db, email, options).await
    }

    /// Create a new user with email and optional password hash
    pub async fn create(
        db: DB<'_>,
        email: &str,
        password_hash: Option<String>,
        is_platform_owner: bool,
    ) -> Result<users::Model> {
        let options = UserCreationOptions {
            is_platform_owner,
            password_hash,
            ..Default::default()
        };

        let (user, _was_created) = Self::find_or_create_with_options(db, email, options).await?;
        Ok(user)
    }

    /// Update a user's password hash
    pub async fn update_password(
        db: DB<'_>,
        user_id: &str,
        password_hash: String,
    ) -> Result<users::Model> {
        let user = Self::find_by_id(db.clone(), user_id)
            .await?
            .ok_or_else(|| crate::error::AppError::NotFound("User not found".to_string()))?;

        let mut user_active: users::ActiveModel = user.into();
        user_active.password_hash = Set(Some(password_hash));
        user_active.updated_at = Set(Some(chrono::Utc::now().naive_utc()));

        let updated_user = user_active.update(&db).await?;
        Ok(updated_user)
    }

    /// Set or unset platform owner status for a user
    pub async fn set_platform_owner(
        db: DB<'_>,
        user_id: &str,
        is_platform_owner: bool,
    ) -> Result<users::Model> {
        let user = Self::find_by_id(db.clone(), user_id)
            .await?
            .ok_or_else(|| crate::error::AppError::NotFound("User not found".to_string()))?;

        let mut user_active: users::ActiveModel = user.into();
        user_active.is_platform_owner = Set(is_platform_owner);
        user_active.updated_at = Set(Some(chrono::Utc::now().naive_utc()));

        let updated_user = user_active.update(&db).await?;
        Ok(updated_user)
    }

    /// Update user password hash
    pub async fn update_password_hash(
        db: DB<'_>,
        user_id: &str,
        password_hash: &str,
    ) -> Result<users::Model> {
        let user = Self::find_by_id(db.clone(), user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        let mut user_active: users::ActiveModel = user.into();
        user_active.password_hash = Set(Some(password_hash.to_string()));
        user_active.updated_at = Set(Some(chrono::Utc::now().naive_utc()));

        let updated_user = user_active.update(&db).await?;
        Ok(updated_user)
    }

    /// Mark email as verified
    pub async fn verify_email(db: DB<'_>, user_id: &str) -> Result<users::Model> {
        let user = Self::find_by_id(db.clone(), user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        let now = chrono::Utc::now().naive_utc();
        let mut user_active: users::ActiveModel = user.into();
        user_active.email_verified_at = Set(Some(now));
        user_active.updated_at = Set(Some(now));

        let updated_user = user_active.update(&db).await?;
        Ok(updated_user)
    }

    /// Check if an email is already taken by another user (excluding current user)
    pub async fn is_email_taken(db: DB<'_>, email: &str, exclude_user_id: &str) -> Result<bool> {
        let count = Users::find()
            .filter(users::Column::Email.eq(email))
            .filter(users::Column::Id.ne(exclude_user_id))
            .count(&db)
            .await?;

        Ok(count > 0)
    }

    /// Update user's email address
    pub async fn update_email(db: DB<'_>, user_id: &str, new_email: &str) -> Result<users::Model> {
        let user = Self::find_by_id(db.clone(), user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
        if user.email == new_email {
            return Ok(user);
        }

        let mut user_active: users::ActiveModel = user.into();
        user_active.email = Set(new_email.to_string());
        // A changed address is not the address that was previously verified.
        // Force the verification flow before password login can succeed again.
        user_active.email_verified_at = Set(None);
        user_active.updated_at = Set(Some(chrono::Utc::now().naive_utc()));

        let updated_user = user_active.update(&db).await?;
        crate::store::magic_links::MagicLinksStore::delete_all_for_user(db, user_id).await?;
        Ok(updated_user)
    }

    /// Count active platform owners. Soft-deleted owners cannot authorize a
    /// demotion that would otherwise leave the platform without a live owner.
    pub async fn count_platform_owners(db: DB<'_>) -> Result<u64> {
        let count = Users::find()
            .filter(users::Column::IsPlatformOwner.eq(true))
            .filter(users::Column::DeletedAt.is_null())
            .count(&db)
            .await?;
        Ok(count)
    }

    /// Search users with filters and ordering
    pub async fn search_users(
        db: DB<'_>,
        email_search: Option<&str>,
        role_filter: Option<&str>,
        order_by: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<users::Model>> {
        let mut query = Users::find();

        // Apply email search filter (case-insensitive LIKE)
        if let Some(email) = email_search {
            let search_pattern = format!("%{}%", email);
            query = query.filter(users::Column::Email.like(&search_pattern));
        }

        // Apply role filter
        if let Some(role) = role_filter {
            match role {
                "platform_owner" => {
                    query = query.filter(users::Column::IsPlatformOwner.eq(true));
                }
                "regular" => {
                    query = query.filter(users::Column::IsPlatformOwner.eq(false));
                }
                _ => {}
            }
        }

        // Apply ordering
        match order_by {
            "email_asc" => {
                query = query.order_by_asc(users::Column::Email);
            }
            "email_desc" => {
                query = query.order_by_desc(users::Column::Email);
            }
            "created_desc" => {
                query = query.order_by_desc(users::Column::CreatedAt);
            }
            "created_asc" => {
                query = query.order_by_asc(users::Column::CreatedAt);
            }
            _ => {
                // Default ordering
                query = query.order_by_desc(users::Column::CreatedAt);
            }
        }

        let (limit, offset) = crate::utils::pagination::store_u64(limit, offset, 1000);
        // Apply pagination
        let users = query.limit(limit).offset(offset).all(&db).await?;

        Ok(users)
    }

    /// Advanced search with relevance-based ordering for platform admin search
    pub async fn search_with_relevance(
        db: DB<'_>,
        search_query: &str,
        limit: u64,
    ) -> Result<Vec<UserSearchResult>> {
        let search_term = format!("%{}%", search_query.trim());
        let q_trimmed = search_query.trim();

        // Build the relevance ordering using raw SQL CASE expression
        // Build the relevance ordering using SeaORM CaseStatement
        let relevance_expr: sea_orm::sea_query::SimpleExpr =
            sea_orm::sea_query::CaseStatement::new()
                .case(users::Column::Email.eq(q_trimmed), 1)
                .case(users::Column::Email.like(&search_term), 2)
                .case(users::Column::Id.eq(q_trimmed), 3)
                .finally(4)
                .into();

        let results = Users::find()
            .select_only()
            .column(users::Column::Id)
            .column(users::Column::Email)
            .column(users::Column::IsPlatformOwner)
            .column(users::Column::CreatedAt)
            .filter(
                Condition::any()
                    .add(users::Column::Email.like(&search_term))
                    .add(users::Column::Id.eq(q_trimmed)),
            )
            .order_by_asc(relevance_expr)
            .order_by_desc(users::Column::CreatedAt)
            .limit(limit)
            .into_model::<UserSearchResult>()
            .all(&db)
            .await?;

        Ok(results)
    }

    /// Get user growth trends by date range
    pub async fn get_growth_trends(
        db: DB<'_>,
        start_date: NaiveDateTime,
        end_date: NaiveDateTime,
        include_platform_owners: bool,
    ) -> Result<Vec<UserGrowthTrendData>> {
        use sea_orm::sea_query::{Alias, Expr, SimpleExpr};
        // Use DATE() function - works in SQLite, MySQL, PostgreSQL
        let date_expr: SimpleExpr =
            Expr::cust_with_expr("DATE($1)", Expr::col(users::Column::CreatedAt));

        let mut query = Users::find()
            .filter(users::Column::CreatedAt.gte(start_date))
            .filter(users::Column::CreatedAt.lte(end_date));

        if !include_platform_owners {
            query = query.filter(users::Column::IsPlatformOwner.eq(false));
        }

        let results = query
            .select_only()
            .column_as(date_expr.clone(), "date")
            .column_as(Expr::col(users::Column::Id).count(), "count")
            .group_by(date_expr)
            .order_by_asc(Expr::col(Alias::new("date")))
            .into_model::<UserGrowthTrendData>()
            .all(&db)
            .await?;

        Ok(results)
    }

    /// List all users with pagination
    pub async fn list_all(db: DB<'_>, limit: u64, offset: u64) -> Result<Vec<users::Model>> {
        let users = Users::find()
            .order_by_desc(users::Column::CreatedAt)
            .limit(limit)
            .offset(offset)
            .all(&db)
            .await?;
        Ok(users)
    }

    /// Count total users with optional platform owner filter
    pub async fn count_all(db: DB<'_>, exclude_platform_owners: bool) -> Result<u64> {
        let mut query = Users::find();

        if exclude_platform_owners {
            query = query.filter(users::Column::IsPlatformOwner.eq(false));
        }

        let count = query.count(&db).await?;
        Ok(count)
    }

    /// Count admin users (platform owners + org owners/admins)
    pub async fn count_admin_users(db: DB<'_>) -> Result<i64> {
        use sea_orm::QuerySelect;

        // Count org owners/admins (distinct users)
        let org_admin_ids: Vec<String> = Memberships::find()
            .filter(memberships::Column::Role.is_in(vec!["owner", "admin"]))
            .select_only()
            .column(memberships::Column::UserId)
            .distinct()
            .into_tuple()
            .all(&db)
            .await?;

        // Get unique count by combining both sets
        let mut unique_ids: std::collections::HashSet<String> = org_admin_ids.into_iter().collect();

        // Platform owners might also be in org admin list, so we use a set
        let platform_owner_ids: Vec<String> = Users::find()
            .filter(users::Column::IsPlatformOwner.eq(true))
            .select_only()
            .column(users::Column::Id)
            .into_tuple()
            .all(&db)
            .await?;

        unique_ids.extend(platform_owner_ids);

        Ok(unique_ids.len() as i64)
    }

    /// Delete a user by ID
    /// This will cascade delete all related data (identities, sessions, subscriptions, etc.)
    pub async fn delete(db: DB<'_>, user_id: &str) -> Result<()> {
        let user = Self::find_by_id(db.clone(), user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        let user_active: users::ActiveModel = user.into();
        user_active.delete(&db).await?;
        Ok(())
    }

    /// Delete users by ID in one statement.
    /// This relies on database-level cascade rules for related data.
    pub async fn delete_by_ids(db: DB<'_>, user_ids: &[String]) -> Result<u64> {
        if user_ids.is_empty() {
            return Ok(0);
        }

        let result = Users::delete_many()
            .filter(users::Column::Id.is_in(user_ids.iter().cloned()))
            .exec(&db)
            .await?;

        Ok(result.rows_affected)
    }

    /// Anonymize a user for GDPR compliance
    /// - Soft deletes the user (sets deleted_at)
    /// - Anonymizes PII (email, password_hash)
    /// - Deletes sensitive authentication data (identities, passkeys, TOTP secrets)
    /// - Preserves audit logs and login events for security integrity
    pub async fn anonymize(db: DB<'_>, user_id: &str) -> Result<()> {
        use sea_orm::TransactionTrait;

        match db {
            DB::Conn(conn) => {
                let transaction = conn.begin().await?;
                Self::anonymize_on_db(DB::Tx(&transaction), user_id).await?;
                transaction.commit().await?;
            }
            DB::Tx(transaction) => {
                Self::anonymize_on_db(DB::Tx(transaction), user_id).await?;
            }
        }

        tracing::info!(user_id = %user_id, "User anonymized for GDPR compliance");
        Ok(())
    }

    async fn anonymize_on_db(db: DB<'_>, user_id: &str) -> Result<()> {
        use crate::entities::prelude::{Identities, Sessions, UserPasskeys, UserTotpSecrets};

        let user = Self::find_by_id(db.clone(), user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        // Generate anonymized email using a new UUID to prevent collisions
        let anonymized_email = format!("deleted_{}@redacted.invalid", Uuid::new_v4());
        let now = chrono::Utc::now().naive_utc();

        // Soft delete and anonymize the user
        let mut user_active: users::ActiveModel = user.into();
        user_active.email = Set(anonymized_email);
        user_active.password_hash = Set(None);
        user_active.deleted_at = Set(Some(now));
        user_active.updated_at = Set(Some(now));
        user_active.update(&db).await?;

        // Delete sensitive authentication data
        Identities::delete_many()
            .filter(crate::entities::identities::Column::UserId.eq(user_id))
            .exec(&db)
            .await?;

        UserPasskeys::delete_many()
            .filter(crate::entities::user_passkeys::Column::UserId.eq(user_id))
            .exec(&db)
            .await?;

        UserTotpSecrets::delete_many()
            .filter(crate::entities::user_totp_secrets::Column::UserId.eq(user_id))
            .exec(&db)
            .await?;

        crate::store::email_verification::EmailVerificationStore::delete_all_for_user(
            db.clone(),
            user_id,
        )
        .await?;
        crate::store::password_reset::PasswordResetStore::delete_all_for_user(db.clone(), user_id)
            .await?;
        crate::store::magic_links::MagicLinksStore::delete_all_for_user(db.clone(), user_id)
            .await?;

        // Anonymisation must log the user out everywhere.
        let sessions_deleted = Sessions::delete_many()
            .filter(crate::entities::sessions::Column::UserId.eq(user_id))
            .exec(&db)
            .await?;

        tracing::info!(
            user_id = %user_id,
            sessions_revoked = sessions_deleted.rows_affected,
            "Revoked all sessions during user anonymization"
        );

        Ok(())
    }

    /// Ensures a platform owner exists with the given email and password.
    /// If the user exists without a password, seeds the initial password.
    /// If the user already has a password hash, leaves it unchanged.
    /// If the user doesn't exist, creates them as a platform owner.
    pub async fn bootstrap_platform_owner(db: DB<'_>, email: &str, password: &str) -> Result<()> {
        let password_hash =
            crate::crypto::concurrency::hash_password_bounded(password.to_string()).await?;

        // Try to find the user by email first
        match Self::find_by_email_with_context(db.clone(), email, None).await? {
            Some(user) => {
                // User exists, ensure they are a platform owner.
                let now = chrono::Utc::now().naive_utc();
                let mut user_active: users::ActiveModel = user.into();
                user_active.is_platform_owner = Set(true);
                user_active.updated_at = Set(Some(now));
                if user_active.password_hash.as_ref().is_none() {
                    user_active.password_hash = Set(Some(password_hash));
                    user_active.email_verified_at = Set(Some(now));
                }
                let user = user_active.update(&db).await?;
                tracing::info!(user_id = %user.id, "Platform owner status ensured for existing user");
            }
            None => {
                // User doesn't exist, create them as platform owner using unified method
                let options = UserCreationOptions {
                    is_platform_owner: true,
                    password_hash: Some(password_hash),
                    mark_email_verified: true,
                    ..Default::default()
                };

                let (user, _was_created) =
                    Self::find_or_create_with_options(db, email, options).await?;
                tracing::info!(user_id = %user.id, "Platform owner account created");
            }
        }

        Ok(())
    }
}

/// User search result
#[derive(Debug, FromQueryResult)]
pub struct UserSearchResult {
    pub id: String,
    pub email: String,
    pub is_platform_owner: bool,
    pub created_at: chrono::NaiveDateTime,
}

/// User growth trend data point
#[derive(Debug, FromQueryResult)]
pub struct UserGrowthTrendData {
    pub date: NaiveDate,
    pub count: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::memberships::MembershipStore;
    use crate::store::organizations::OrganizationStore;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;
    use std::collections::HashSet;

    #[tokio::test]
    async fn scim_org_member_listing_filters_and_counts_through_memberships() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");

        let owner = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "owner@owner.test",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create owner")
        .0;
        let org = OrganizationStore::create(DB::Conn(&db), "scim-org", "SCIM Org", &owner.id, None)
            .await
            .expect("create org");

        let alpha = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "alpha@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create alpha")
        .0;
        let beta = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "beta@test.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create beta")
        .0;
        let non_member = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "nonmember@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create non-member")
        .0;

        MembershipStore::create(DB::Conn(&db), &org.id, &alpha.id, "member")
            .await
            .expect("add alpha");
        MembershipStore::create(DB::Conn(&db), &org.id, &beta.id, "member")
            .await
            .expect("add beta");

        let all_members = UserStore::list_scim_org_members(DB::Conn(&db), &org.id, &[], 10, 0)
            .await
            .expect("list members");
        let member_ids = all_members
            .iter()
            .map(|user| user.id.as_str())
            .collect::<HashSet<_>>();
        assert_eq!(all_members.len(), 2);
        assert!(!member_ids.contains(owner.id.as_str()));
        assert!(member_ids.contains(alpha.id.as_str()));
        assert!(member_ids.contains(beta.id.as_str()));
        assert!(!member_ids.contains(non_member.id.as_str()));

        let filters = vec![UserEmailFilter {
            op: UserEmailFilterOp::EndsWith,
            value: "example.com".to_string(),
        }];
        let filtered = UserStore::list_scim_org_members(DB::Conn(&db), &org.id, &filters, 10, 0)
            .await
            .expect("list filtered members");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, alpha.id);

        let count = UserStore::count_scim_org_members(DB::Conn(&db), &org.id, &filters)
            .await
            .expect("count filtered members");
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn same_email_lookups_and_default_creation_preserve_tenant_context() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let org_a_owner = UserStore::create(DB::Conn(&db), "owner-a@example.test", None, false)
            .await
            .expect("create owner A");
        let org_b_owner = UserStore::create(DB::Conn(&db), "owner-b@example.test", None, false)
            .await
            .expect("create owner B");
        let org_a = OrganizationStore::create(
            DB::Conn(&db),
            "same-email-a",
            "Same Email A",
            &org_a_owner.id,
            None,
        )
        .await
        .expect("create org A");
        let org_b = OrganizationStore::create(
            DB::Conn(&db),
            "same-email-b",
            "Same Email B",
            &org_b_owner.id,
            None,
        )
        .await
        .expect("create org B");
        let tenant_a =
            UserStore::create_with_org_id(DB::Conn(&db), "shared@example.test", None, &org_a.id)
                .await
                .expect("create tenant A user");
        let tenant_b =
            UserStore::create_with_org_id(DB::Conn(&db), "shared@example.test", None, &org_b.id)
                .await
                .expect("create tenant B user");

        assert_eq!(
            UserStore::find_by_email_with_context(
                DB::Conn(&db),
                "shared@example.test",
                Some(&org_a.id),
            )
            .await
            .expect("lookup tenant A")
            .expect("tenant A exists")
            .id,
            tenant_a.id
        );
        assert_eq!(
            UserStore::find_by_email_with_context(
                DB::Conn(&db),
                "shared@example.test",
                Some(&org_b.id),
            )
            .await
            .expect("lookup tenant B")
            .expect("tenant B exists")
            .id,
            tenant_b.id
        );
        assert!(
            UserStore::find_by_email_with_context(DB::Conn(&db), "shared@example.test", None,)
                .await
                .expect("lookup platform context")
                .is_none()
        );

        let (platform, created) = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "shared@example.test",
            UserCreationOptions {
                is_platform_owner: true,
                ..Default::default()
            },
        )
        .await
        .expect("create platform-context user");
        assert!(created);
        assert!(platform.org_id.is_none());
        assert!(platform.is_platform_owner);
        assert_ne!(platform.id, tenant_a.id);
        assert_ne!(platform.id, tenant_b.id);

        let (admin_oauth, created) = UserStore::find_or_create_admin_oauth(
            DB::Conn(&db),
            "shared@example.test",
            Some("shared@example.test"),
        )
        .await
        .expect("resolve admin OAuth user");
        assert!(!created);
        assert_eq!(admin_oauth.id, platform.id);
    }
}

#[cfg(test)]
mod store_user_tests {
    use super::*;
    use crate::entities::users;
    use crate::store::identities::IdentityStore;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;
    use sea_orm::DatabaseConnection;

    async fn db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        db
    }

    async fn user_at(db: &DatabaseConnection, email: &str) -> users::Model {
        UserStore::create(DB::Conn(db), email, None, false)
            .await
            .expect("create user")
    }

    #[tokio::test]
    async fn password_updates_clear_reset_tokens() {
        let db = db().await;
        let user = user_at(&db, "pw@example.test").await;
        let new_hash = "new-bcrypt-hash".to_string();

        UserStore::update_password(DB::Conn(&db), &user.id, new_hash)
            .await
            .expect("update password");
    }

    #[tokio::test]
    async fn search_orders_filters_and_paginates() {
        let db = db().await;
        for email in [
            "alpha@example.test",
            "beta@example.test",
            "gamma@other.test",
        ] {
            user_at(&db, email).await;
        }

        // Email filter.
        let alpha_only =
            UserStore::search_users(DB::Conn(&db), Some("alpha"), None, "email_asc", 10, 0)
                .await
                .expect("search alpha");
        assert_eq!(alpha_only.len(), 1);

        // Ordering variants all execute and return the full set.
        for order in ["email_asc", "email_desc", "created_asc", "created_desc"] {
            let rows = UserStore::search_users(DB::Conn(&db), None, Some(order), order, 10, 0)
                .await
                .unwrap_or_else(|e| panic!("search order {order} failed: {e:?}"));
            assert_eq!(rows.len(), 3);
        }
    }

    #[tokio::test]
    async fn delete_removes_the_record_and_dependents_survive_separately() {
        let db = db().await;
        let user = user_at(&db, "doomed@example.test").await;
        add_identity(&db, &user.id).await;

        UserStore::delete(DB::Conn(&db), &user.id)
            .await
            .expect("delete user");

        match UserStore::find_by_id(DB::Conn(&db), &user.id)
            .await
            .unwrap()
        {
            None => {}
            Some(_) => panic!("deleted user still present"),
        }
    }

    async fn add_identity(db: &DatabaseConnection, user_id: &str) {
        IdentityStore::create(
            DB::Conn(db),
            user_id,
            "github",
            "gh-uid",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("seed identity");
    }
}
