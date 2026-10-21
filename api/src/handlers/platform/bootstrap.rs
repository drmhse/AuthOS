use crate::crypto::jwt::JwtService;
use crate::db::DB;
use crate::error::{AppError, Result};
use crate::handlers::auth::session::RefreshTokenResponse;
use crate::middleware::{AuthUser, RequestInfo};
use crate::state::AppState;
use crate::store::{
    distributed_locks::DistributedLockStore, sessions::SessionStore, totp::TotpStore,
    users::UserStore,
};
use axum::{extract::State, Extension, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use subtle::ConstantTimeEq;
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct ManagedConfigResponse {
    pub config: Value,
    pub config_path: String,
    pub apply_command_configured: bool,
    pub status: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct BootstrapLoginRequest {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct ApplyManagedConfigResponse {
    pub scheduled: bool,
    pub message: String,
}

pub async fn get_managed_config(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
) -> Result<Json<ManagedConfigResponse>> {
    require_platform_owner(&auth_user)?;
    let paths = managed_paths(&state)?;
    Ok(Json(load_managed_config_response(
        &paths,
        state.config.managed_request_path.is_some(),
    )?))
}

pub async fn update_managed_config(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Json(config): Json<Value>,
) -> Result<Json<ManagedConfigResponse>> {
    require_platform_owner(&auth_user)?;
    let paths = managed_paths(&state)?;
    let current_config = read_json_file(&paths.config_path)?;
    validate_managed_config(&config, &current_config)?;
    write_json_file(&paths.config_path, &config)?;

    Ok(Json(load_managed_config_response(
        &paths,
        state.config.managed_request_path.is_some(),
    )?))
}

pub async fn apply_managed_config(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
) -> Result<Json<ApplyManagedConfigResponse>> {
    require_platform_owner(&auth_user)?;

    let paths = managed_paths(&state)?;
    let request_path = state
        .config
        .managed_request_path
        .ok_or_else(|| AppError::NotFound("Managed apply queue is not configured".to_string()))?;

    let queued_status = json!({
        "status": "queued",
        "message": "AuthOS reload has been queued.",
        "updated_at": Utc::now().to_rfc3339(),
    });
    if let Some(status_path) = paths.status_path.as_ref() {
        write_json_file(status_path, &queued_status)?;
    }

    write_json_file(
        &request_path,
        &json!({
            "requested_at": Utc::now().to_rfc3339(),
            "requested_by": auth_user.user.id,
        }),
    )?;

    Ok(Json(ApplyManagedConfigResponse {
        scheduled: true,
        message: "AuthOS reload queued. Refresh this page after the service comes back."
            .to_string(),
    }))
}

pub async fn bootstrap_login(
    State(state): State<AppState>,
    Extension(request_info): Extension<RequestInfo>,
    headers: axum::http::HeaderMap,
    Json(req): Json<BootstrapLoginRequest>,
) -> Result<Json<RefreshTokenResponse>> {
    crate::middleware::ensure_trusted_platform_origin(&headers, &state.config)?;
    if req.token.trim().is_empty() {
        return Err(AppError::BadRequest(
            "Bootstrap token is required".to_string(),
        ));
    }
    if req.token.len() > 512 {
        return Err(AppError::BadRequest(
            "Bootstrap token is invalid".to_string(),
        ));
    }

    let paths = managed_paths(&state)?;
    let mut managed_state =
        claim_bootstrap_login_token(DB::Conn(&state.db), &paths.state_path, req.token.trim())
            .await?;
    let token_state = managed_state
        .get_mut("bootstrap_login")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| AppError::Unauthorized("Bootstrap login is not available".to_string()))?;

    let owner_email = state.config.platform_owner_email.as_ref().ok_or_else(|| {
        AppError::Unauthorized("Platform owner email is not configured".to_string())
    })?;
    let user = UserStore::find_by_email_with_context(DB::Conn(&state.db), owner_email, None)
        .await?
        .filter(|user| user.deleted_at.is_none())
        .ok_or_else(|| AppError::Unauthorized("Platform owner user does not exist".to_string()))?;

    if !user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Configured owner does not have platform access".to_string(),
        ));
    }

    // A browser bootstrap link is a recovery credential, not an MFA bypass.
    // The standalone installer calls this endpoint without an Origin header
    // and needs a narrow local provisioning session even after MFA is enrolled.
    let browser_request = headers.contains_key(axum::http::header::ORIGIN);
    if browser_request && TotpStore::is_enabled(DB::Conn(&state.db), &user.id).await? {
        let preauth_token = state.jwt_service.create_mfa_preauth_token(
            &user.id,
            &user.email,
            true,
            None,
            None,
            None,
        )?;
        token_state.insert(
            "used_at".to_string(),
            Value::String(Utc::now().to_rfc3339()),
        );
        write_json_file(&paths.state_path, &managed_state)?;
        return Ok(Json(RefreshTokenResponse {
            access_token: preauth_token,
            refresh_token: String::new(),
            expires_in: 300,
        }));
    }

    let access_token = state.jwt_service.create_bootstrap_management_token(
        &user.id,
        &user.email,
        true,
        None,
        None,
    )?;
    let refresh_token = crate::crypto::refresh_tokens::generate();
    let expires_at =
        (Utc::now() + chrono::Duration::hours(state.config.jwt_expiration_hours)).naive_utc();
    let refresh_expires_at = (Utc::now() + chrono::Duration::days(30)).naive_utc();

    SessionStore::create(
        DB::Conn(&state.db),
        &user.id,
        &JwtService::hash_token(&access_token),
        expires_at,
        Some(&refresh_token),
        Some(refresh_expires_at),
        None,
        None,
        None,
        Some(&request_info.user_agent),
        Some(&request_info.ip_address),
    )
    .await?;

    token_state.insert(
        "used_at".to_string(),
        Value::String(Utc::now().to_rfc3339()),
    );
    write_json_file(&paths.state_path, &managed_state)?;

    Ok(Json(RefreshTokenResponse {
        access_token,
        refresh_token,
        expires_in: state.config.jwt_expiration_hours * 3600,
    }))
}

async fn claim_bootstrap_login_token(db: DB<'_>, state_path: &str, token: &str) -> Result<Value> {
    let managed_state = read_json_file(state_path)?;
    let token_state = managed_state
        .get("bootstrap_login")
        .and_then(Value::as_object)
        .ok_or_else(|| AppError::Unauthorized("Bootstrap login is not available".to_string()))?;
    let stored_token = token_state
        .get("token")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::Unauthorized("Bootstrap login is not available".to_string()))?;
    if stored_token.len() != token.len()
        || !bool::from(stored_token.as_bytes().ct_eq(token.as_bytes()))
    {
        return Err(AppError::Unauthorized(
            "Invalid bootstrap login token".to_string(),
        ));
    }
    if token_state.get("used_at").and_then(Value::as_str).is_some() {
        return Err(AppError::Unauthorized(
            "This bootstrap login link has already been used".to_string(),
        ));
    }

    let expires_at = token_state
        .get("expires_at")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::Unauthorized("Bootstrap login token is invalid".to_string()))?;
    let expires_at = chrono::DateTime::parse_from_rfc3339(expires_at)
        .map_err(|_| AppError::Unauthorized("Bootstrap login token is invalid".to_string()))?
        .with_timezone(&Utc);
    let now = Utc::now();
    if expires_at <= now {
        return Err(AppError::Unauthorized(
            "This bootstrap login link has expired".to_string(),
        ));
    }

    // The database lock is intentionally retained until the bootstrap token's
    // expiry. It is a durable consumption record, not a short critical-section
    // mutex, so concurrent processes and replicas have exactly one winner even
    // before the managed state file records `used_at`.
    let lock_key = format!("bootstrap-login:{}", JwtService::hash_token(token));
    let ttl_seconds = (expires_at - now).num_seconds().max(1);
    if !DistributedLockStore::try_acquire_lock(
        db,
        &lock_key,
        "bootstrap-login-consumer",
        ttl_seconds,
    )
    .await?
    {
        return Err(AppError::Unauthorized(
            "This bootstrap login link has already been used".to_string(),
        ));
    }

    Ok(managed_state)
}

struct ManagedPaths {
    config_path: String,
    state_path: String,
    status_path: Option<String>,
}

fn require_platform_owner(auth_user: &AuthUser) -> Result<()> {
    if auth_user.user.is_platform_owner {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ))
    }
}

fn managed_paths(state: &AppState) -> Result<ManagedPaths> {
    let config_path = state
        .config
        .managed_config_path
        .clone()
        .ok_or_else(|| AppError::NotFound("Managed config is not enabled".to_string()))?;
    let state_path = state
        .config
        .managed_state_path
        .clone()
        .ok_or_else(|| AppError::NotFound("Managed config state is not enabled".to_string()))?;

    Ok(ManagedPaths {
        config_path,
        state_path,
        status_path: state.config.managed_status_path.clone(),
    })
}

fn load_managed_config_response(
    paths: &ManagedPaths,
    apply_command_configured: bool,
) -> Result<ManagedConfigResponse> {
    let config = read_json_file(&paths.config_path)?;
    let status = paths
        .status_path
        .as_ref()
        .and_then(|path| read_json_file(path).ok());

    Ok(ManagedConfigResponse {
        config,
        config_path: paths.config_path.clone(),
        apply_command_configured,
        status,
    })
}

fn validate_managed_config(value: &Value, current: &Value) -> Result<()> {
    let object = value.as_object().ok_or_else(|| {
        AppError::BadRequest("Managed config payload must be a JSON object".to_string())
    })?;
    if let Some(deployment) = object.get("deployment") {
        if !deployment.is_object() {
            return Err(AppError::BadRequest(
                "deployment must be a JSON object".to_string(),
            ));
        }
    }
    if let Some(platform_owner) = object.get("platformOwner") {
        if !platform_owner.is_object() {
            return Err(AppError::BadRequest(
                "platformOwner must be a JSON object".to_string(),
            ));
        }
    }
    reject_protected_change(
        current
            .get("standalone")
            .and_then(|value| value.get("dataDir")),
        object
            .get("standalone")
            .and_then(|value| value.get("dataDir")),
        "standalone.dataDir",
    )?;
    reject_protected_change(
        current.get("caddy").and_then(|value| value.get("install")),
        object.get("caddy").and_then(|value| value.get("install")),
        "caddy.install",
    )?;
    Ok(())
}

fn reject_protected_change(
    current: Option<&Value>,
    proposed: Option<&Value>,
    field: &str,
) -> Result<()> {
    if current == proposed {
        return Ok(());
    }

    Err(AppError::BadRequest(format!(
        "{} is managed by the local installer and cannot be changed from the web workspace",
        field
    )))
}

fn read_json_file(path: &str) -> Result<Value> {
    let content = fs::read_to_string(path).map_err(|error| {
        AppError::InternalServerError(format!("Failed to read {}: {}", path, error))
    })?;
    serde_json::from_str(&content).map_err(|error| {
        AppError::InternalServerError(format!("Failed to parse {}: {}", path, error))
    })
}

fn write_json_file(path: &str, value: &Value) -> Result<()> {
    let serialized = format!(
        "{}\n",
        serde_json::to_string_pretty(value).map_err(|error| {
            AppError::InternalServerError(format!("Failed to serialize managed config: {}", error))
        })?
    );
    atomic_write_bytes(Path::new(path), serialized.as_bytes()).map_err(|error| {
        AppError::InternalServerError(format!("Failed to atomically write {}: {}", path, error))
    })
}

fn atomic_write_bytes(path: &Path, contents: &[u8]) -> io::Result<()> {
    atomic_write_bytes_with_replace(path, contents, |from, to| fs::rename(from, to))
}

fn atomic_write_bytes_with_replace<F>(path: &Path, contents: &[u8], replace: F) -> io::Result<()>
where
    F: FnOnce(&Path, &Path) -> io::Result<()>,
{
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        file_name.to_string_lossy(),
        Uuid::new_v4()
    ));

    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(contents)?;
        file.flush()?;
        file.set_permissions(Permissions::from_mode(0o600))?;
        file.sync_all()?;
        drop(file);

        replace(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;
    use std::os::unix::fs::PermissionsExt;

    fn state_file(expires_at: chrono::DateTime<Utc>) -> String {
        let path = std::env::temp_dir().join(format!("authos-bootstrap-{}.json", Uuid::new_v4()));
        write_json_file(
            path.to_str().expect("UTF-8 temporary path"),
            &json!({
                "bootstrap_login": {
                    "token": "one-time-bootstrap-token",
                    "expires_at": expires_at.to_rfc3339(),
                    "used_at": null
                }
            }),
        )
        .expect("write bootstrap state");
        path.to_string_lossy().into_owned()
    }

    #[tokio::test]
    async fn concurrent_bootstrap_token_claim_has_exactly_one_winner() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let path = state_file(Utc::now() + chrono::Duration::minutes(5));

        let first = claim_bootstrap_login_token(DB::Conn(&db), &path, "one-time-bootstrap-token");
        let second = claim_bootstrap_login_token(DB::Conn(&db), &path, "one-time-bootstrap-token");
        let (first, second) = tokio::join!(first, second);
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        let loser = if first.is_err() { first } else { second };
        assert!(matches!(
            loser,
            Err(AppError::Unauthorized(message)) if message.contains("already been used")
        ));

        std::fs::remove_file(path).expect("remove bootstrap state");
    }

    #[tokio::test]
    async fn bootstrap_claim_requires_unexpired_context_and_exact_token() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let path = state_file(Utc::now() - chrono::Duration::seconds(1));

        assert!(matches!(
            claim_bootstrap_login_token(DB::Conn(&db), &path, "one-time-bootstrap-token").await,
            Err(AppError::Unauthorized(message)) if message.contains("expired")
        ));
        assert!(matches!(
            claim_bootstrap_login_token(DB::Conn(&db), &path, "wrong-bootstrap-token").await,
            Err(AppError::Unauthorized(message)) if message.contains("Invalid")
        ));

        std::fs::remove_file(path).expect("remove bootstrap state");
    }

    #[test]
    fn atomic_json_write_is_mode_0600_and_preserves_parent_permissions() {
        let parent = std::env::temp_dir().join(format!("authos-atomic-{}", Uuid::new_v4()));
        fs::create_dir(&parent).expect("create atomic write directory");
        fs::set_permissions(&parent, Permissions::from_mode(0o750))
            .expect("set parent permissions");
        let path = parent.join("managed.json");

        write_json_file(
            path.to_str().expect("UTF-8 path"),
            &json!({"secret": "managed"}),
        )
        .expect("atomic JSON write");

        assert_eq!(
            fs::read_to_string(&path).expect("read managed JSON"),
            "{\n  \"secret\": \"managed\"\n}\n"
        );
        assert_eq!(
            fs::metadata(&path)
                .expect("stat managed JSON")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&parent)
                .expect("stat parent")
                .permissions()
                .mode()
                & 0o777,
            0o750
        );
        fs::remove_dir_all(parent).expect("remove atomic write directory");
    }

    #[test]
    fn atomic_write_failure_preserves_live_file_and_removes_staging_file() {
        let parent = std::env::temp_dir().join(format!("authos-atomic-{}", Uuid::new_v4()));
        fs::create_dir(&parent).expect("create atomic write directory");
        let path = parent.join("apply-request.json");
        fs::write(&path, b"old-request\n").expect("seed live request");
        fs::set_permissions(&path, Permissions::from_mode(0o640)).expect("set live permissions");

        let error = atomic_write_bytes_with_replace(&path, b"new-request\n", |staged, live| {
            assert_eq!(
                fs::read(live).expect("read prior live request"),
                b"old-request\n"
            );
            assert_eq!(
                fs::read(staged).expect("read staged request"),
                b"new-request\n"
            );
            assert_eq!(
                fs::metadata(staged)
                    .expect("stat staged request")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected replace failure",
            ))
        })
        .expect_err("replace failure must propagate");

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            fs::read(&path).expect("read preserved request"),
            b"old-request\n"
        );
        assert_eq!(
            fs::metadata(&path)
                .expect("stat preserved request")
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        assert_eq!(
            fs::read_dir(&parent)
                .expect("list parent")
                .filter_map(std::result::Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
                .count(),
            0
        );
        fs::remove_dir_all(parent).expect("remove atomic write directory");
    }
}
