//! SIEM Configuration Handlers
//!
//! Endpoints for managing SIEM (Security Information and Event Management) integrations.

use crate::db::transaction::with_retrying_transaction;
use crate::db::DB;
use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use crate::services::audit_builder::OrgAuditBuilder;
use crate::services::permission_service::{PermissionService, CAP_INTEGRATIONS_MANAGE};
use crate::services::tier_enforcement::TierService;
use crate::state::AppState;
use crate::store::{organizations::OrganizationStore, siem_configs::SiemConfigStore};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Deserialize)]
pub struct CreateSiemConfigRequest {
    pub name: String,
    pub provider_type: String, // 'Datadog', 'Splunk', 'Elastic', 'Custom'
    pub endpoint_url: String,
    pub api_key: Option<String>,
    pub auth_header: Option<String>,
    pub batch_size: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSiemConfigRequest {
    pub name: Option<String>,
    pub endpoint_url: Option<String>,
    pub api_key: Option<Option<String>>,
    pub auth_header: Option<Option<String>>,
    pub batch_size: Option<i32>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct SiemConfigResponse {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub provider_type: String,
    pub endpoint_url: String,
    pub batch_size: i32,
    pub enabled: bool,
    pub last_successful_batch_at: Option<String>,
    pub failure_count: i32,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct ListSiemConfigsResponse {
    pub siem_configs: Vec<SiemConfigResponse>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct TestConnectionResponse {
    pub success: bool,
    pub message: String,
}

/// Check if user can manage SIEM configurations.
async fn can_manage_siem(state: &AppState, user_id: &str, org_id: &str) -> Result<bool> {
    PermissionService::check(
        DB::Conn(&state.db),
        org_id,
        user_id,
        CAP_INTEGRATIONS_MANAGE,
    )
    .await
}

/// Convert database model to API response
fn to_response(model: crate::entities::siem_configs::Model) -> SiemConfigResponse {
    SiemConfigResponse {
        id: model.id,
        org_id: model.org_id,
        name: model.name,
        provider_type: model.provider,
        endpoint_url: model.endpoint_url,
        batch_size: model.batch_size.parse().unwrap_or(100),
        enabled: model.enabled,
        last_successful_batch_at: model
            .last_successful_batch_at
            .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc).to_rfc3339()),
        failure_count: model.failure_count,
        created_at: DateTime::<Utc>::from_naive_utc_and_offset(model.created_at, Utc).to_rfc3339(),
    }
}

fn decode_siem_secret(
    encryption: &crate::encryption::EncryptionService,
    value: &str,
    record_id: &str,
    field_name: &'static str,
) -> Result<String> {
    let encrypted = match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value)
    {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err(AppError::InternalServerError(
                "SIEM secret requires migration; run rewrap-secrets --apply".to_string(),
            ))
        }
    };

    encryption
        .decrypt_with_context(
            &encrypted,
            crate::encryption::EncryptionContext::new("siem_configs", record_id, field_name),
        )
        .map_err(|_| AppError::InternalServerError(
            "SIEM secret could not be authenticated; verify the encryption keyring and run rewrap-secrets".to_string(),
        ))
}

fn siem_auth_headers(
    provider: &str,
    encryption: Option<&crate::encryption::EncryptionService>,
    config_id: &str,
    api_key: Option<String>,
    auth_header: Option<String>,
) -> Result<Vec<(String, String)>> {
    let require_encryption = || {
        encryption.ok_or_else(|| {
            AppError::InternalServerError(
                "Encryption service is required to test SIEM credentials".to_string(),
            )
        })
    };
    let required_api_key = |header_name: &str, scheme: Option<&str>| -> Result<_> {
        let stored = api_key.as_deref().ok_or_else(|| {
            AppError::BadRequest(format!("{provider} SIEM configuration requires an API key"))
        })?;
        let key = decode_siem_secret(require_encryption()?, stored, config_id, "api_key")?;
        let value = scheme.map_or(key.clone(), |scheme| format!("{scheme} {key}"));
        Ok(vec![(header_name.to_string(), value)])
    };

    match provider {
        "Datadog" => required_api_key("DD-API-KEY", None),
        "Splunk" => required_api_key("Authorization", Some("Splunk")),
        "Elastic" => required_api_key("Authorization", Some("ApiKey")),
        "Custom" => {
            let Some(stored) = auth_header.as_deref() else {
                return Ok(Vec::new());
            };
            let header =
                decode_siem_secret(require_encryption()?, stored, config_id, "auth_header")?;
            let (name, value) = header
                .split_once(':')
                .map_or(("Authorization", header.trim()), |(name, value)| {
                    (name.trim(), value.trim())
                });
            if name.is_empty() || value.is_empty() {
                return Err(AppError::BadRequest(
                    "Custom SIEM authentication header is malformed".to_string(),
                ));
            }
            let parsed_name =
                reqwest::header::HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                    AppError::BadRequest(
                        "Custom SIEM authentication header name is invalid".to_string(),
                    )
                })?;
            reqwest::header::HeaderValue::from_str(value).map_err(|_| {
                AppError::BadRequest(
                    "Custom SIEM authentication header value is invalid".to_string(),
                )
            })?;
            if matches!(
                parsed_name.as_str(),
                "host" | "content-length" | "transfer-encoding" | "connection"
            ) {
                return Err(AppError::BadRequest(
                    "Custom SIEM authentication header name is not allowed".to_string(),
                ));
            }
            Ok(vec![(parsed_name.to_string(), value.to_string())])
        }
        _ => Err(AppError::BadRequest(
            "Unsupported SIEM provider type".to_string(),
        )),
    }
}

/// Create SIEM configuration
pub async fn create_siem_config(
    State(state): State<AppState>,
    Path(org_slug): Path<String>,
    auth_user: axum::Extension<AuthUser>,
    Json(req): Json<CreateSiemConfigRequest>,
) -> Result<(StatusCode, Json<SiemConfigResponse>)> {
    let org_model = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    let org = crate::handlers::organizations::ensure_organization_active(&state.db, &org_model.id)
        .await?;

    if !can_manage_siem(&state, &auth_user.user.id, &org.id).await? {
        return Err(AppError::Forbidden(
            "Insufficient permissions to manage SIEM configurations".to_string(),
        ));
    }

    // Tier/Entitlement Check
    TierService::check_feature_access(
        DB::Conn(&state.db),
        &org.id,
        |f| f.allow_siem,
        "Log Streaming (SIEM)",
    )
    .await?;

    // Validate provider type
    let valid_providers = ["Datadog", "Splunk", "Elastic", "Custom"];
    if !valid_providers.contains(&req.provider_type.as_str()) {
        return Err(AppError::BadRequest(format!(
            "Invalid provider type. Must be one of: {}",
            valid_providers.join(", ")
        )));
    }

    // Validate name
    if req.name.trim().is_empty() {
        return Err(AppError::BadRequest(
            "Configuration name cannot be empty".to_string(),
        ));
    }

    // Validate endpoint URL
    if req.endpoint_url.trim().is_empty() {
        return Err(AppError::BadRequest(
            "Endpoint URL cannot be empty".to_string(),
        ));
    }

    let org_id = org.id.clone();
    let user_id = auth_user.user.id.clone();
    let name = req.name.clone();
    let provider_type = req.provider_type.clone();

    let config_id = uuid::Uuid::new_v4().to_string();
    // Encrypt sensitive fields. The unencrypted-development escape hatch does
    // not permit writing operational credentials in plaintext.
    let mut api_key = req.api_key.clone();
    let mut auth_header = req.auth_header.clone();

    if api_key.is_some() || auth_header.is_some() {
        let encryption = state.encryption.as_ref().ok_or_else(|| {
            AppError::InternalServerError(
                "Encryption service is required to store SIEM credentials".to_string(),
            )
        })?;
        if let Some(key) = &api_key {
            let encrypted = encryption
                .encrypt_with_context(
                    key,
                    crate::encryption::EncryptionContext::new(
                        "siem_configs",
                        &config_id,
                        "api_key",
                    ),
                )
                .map_err(|e| {
                    AppError::InternalServerError(format!("Failed to encrypt SIEM API key: {}", e))
                })?;
            api_key = Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                encrypted,
            ));
        }

        if let Some(header) = &auth_header {
            let encrypted = encryption
                .encrypt_with_context(
                    header,
                    crate::encryption::EncryptionContext::new(
                        "siem_configs",
                        &config_id,
                        "auth_header",
                    ),
                )
                .map_err(|e| {
                    AppError::InternalServerError(format!(
                        "Failed to encrypt SIEM auth header: {}",
                        e
                    ))
                })?;
            auth_header = Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                encrypted,
            ));
        }
    }

    // Execute transaction with automatic retry on database contention
    let desired_config_id = config_id.clone();
    let event = OrgAuditBuilder::new(&org_id, Some(&user_id), "siem_config.created")
        .target("siem_config", &config_id)
        .success(true)
        .details_json(Some(json!({
            "siem_config_id": &config_id,
            "name": &name,
            "provider_type": &provider_type
        })))
        .build();
    let audit_actor = state.audit_actor.clone();
    let config = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "create_siem_config",
        |db| {
            let config_id = desired_config_id.clone();
            let org_id = org_id.clone();
            let name = name.clone();
            let provider_type = provider_type.clone();
            let endpoint_url = req.endpoint_url.clone();
            let api_key = api_key.clone();
            let auth_header = auth_header.clone();
            let batch_size = req.batch_size;
            let event = event.clone();
            let audit_actor = audit_actor.clone();
            Box::pin(async move {
                let config_id = SiemConfigStore::create(
                    db.clone(),
                    &config_id,
                    &org_id,
                    &name,
                    &provider_type,
                    &endpoint_url,
                    api_key,
                    auth_header,
                    batch_size,
                )
                .await?;

                let config = SiemConfigStore::get_by_id(db.clone(), &config_id)
                    .await?
                    .ok_or_else(|| {
                        AppError::InternalServerError(
                            "Failed to retrieve created config".to_string(),
                        )
                    })?;
                audit_actor.log_org_with_db(db, event).await?;
                Ok(config)
            })
        },
    )
    .await?;

    Ok((StatusCode::CREATED, Json(to_response(config))))
}

/// List SIEM configurations for an organization
pub async fn list_siem_configs(
    State(state): State<AppState>,
    Path(org_slug): Path<String>,
    auth_user: axum::Extension<AuthUser>,
) -> Result<Json<ListSiemConfigsResponse>> {
    let org_model = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    let org = crate::handlers::organizations::ensure_organization_active(&state.db, &org_model.id)
        .await?;

    if !can_manage_siem(&state, &auth_user.user.id, &org.id).await? {
        return Err(AppError::Forbidden(
            "Insufficient permissions to view SIEM configurations".to_string(),
        ));
    }

    let configs = SiemConfigStore::list_by_org(&state.db, &org.id).await?;
    let total = configs.len();

    let response_configs: Vec<SiemConfigResponse> = configs.into_iter().map(to_response).collect();

    Ok(Json(ListSiemConfigsResponse {
        siem_configs: response_configs,
        total,
    }))
}

/// Get a single SIEM configuration
pub async fn get_siem_config(
    State(state): State<AppState>,
    Path((org_slug, config_id)): Path<(String, String)>,
    auth_user: axum::Extension<AuthUser>,
) -> Result<Json<SiemConfigResponse>> {
    let org_model = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    let org = crate::handlers::organizations::ensure_organization_active(&state.db, &org_model.id)
        .await?;

    if !can_manage_siem(&state, &auth_user.user.id, &org.id).await? {
        return Err(AppError::Forbidden(
            "Insufficient permissions to view SIEM configuration".to_string(),
        ));
    }

    let config = SiemConfigStore::get_by_id(DB::Conn(&state.db), &config_id)
        .await?
        .ok_or_else(|| AppError::NotFound("SIEM configuration not found".to_string()))?;

    // Verify the config belongs to this organization
    if config.org_id != org.id {
        return Err(AppError::NotFound(
            "SIEM configuration not found".to_string(),
        ));
    }

    Ok(Json(to_response(config)))
}

/// Update SIEM configuration
pub async fn update_siem_config(
    State(state): State<AppState>,
    Path((org_slug, config_id)): Path<(String, String)>,
    auth_user: axum::Extension<AuthUser>,
    Json(req): Json<UpdateSiemConfigRequest>,
) -> Result<Json<SiemConfigResponse>> {
    let org_model = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    let org = crate::handlers::organizations::ensure_organization_active(&state.db, &org_model.id)
        .await?;

    if !can_manage_siem(&state, &auth_user.user.id, &org.id).await? {
        return Err(AppError::Forbidden(
            "Insufficient permissions to update SIEM configuration".to_string(),
        ));
    }

    // Verify the config exists and belongs to this organization
    let existing_config = SiemConfigStore::get_by_id(DB::Conn(&state.db), &config_id)
        .await?
        .ok_or_else(|| AppError::NotFound("SIEM configuration not found".to_string()))?;

    if existing_config.org_id != org.id {
        return Err(AppError::NotFound(
            "SIEM configuration not found".to_string(),
        ));
    }

    let org_id = org.id.clone();
    let user_id = auth_user.user.id.clone();

    // Encrypt sensitive fields; plaintext writes are never permitted.
    let mut api_key = req.api_key.clone();
    let mut auth_header = req.auth_header.clone();

    if api_key.as_ref().is_some_and(Option::is_some)
        || auth_header.as_ref().is_some_and(Option::is_some)
    {
        let encryption = state.encryption.as_ref().ok_or_else(|| {
            AppError::InternalServerError(
                "Encryption service is required to store SIEM credentials".to_string(),
            )
        })?;
        if let Some(Some(key)) = &api_key {
            let encrypted = encryption
                .encrypt_with_context(
                    key,
                    crate::encryption::EncryptionContext::new(
                        "siem_configs",
                        &config_id,
                        "api_key",
                    ),
                )
                .map_err(|e| {
                    AppError::InternalServerError(format!("Failed to encrypt SIEM API key: {}", e))
                })?;
            api_key = Some(Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                encrypted,
            )));
        }

        if let Some(Some(header)) = &auth_header {
            let encrypted = encryption
                .encrypt_with_context(
                    header,
                    crate::encryption::EncryptionContext::new(
                        "siem_configs",
                        &config_id,
                        "auth_header",
                    ),
                )
                .map_err(|e| {
                    AppError::InternalServerError(format!(
                        "Failed to encrypt SIEM auth header: {}",
                        e
                    ))
                })?;
            auth_header = Some(Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                encrypted,
            )));
        }
    }

    let event = OrgAuditBuilder::new(&org_id, Some(&user_id), "siem_config.updated")
        .target("siem_config", &config_id)
        .success(true)
        .details_json(Some(json!({"siem_config_id": &config_id})))
        .build();
    let audit_actor = state.audit_actor.clone();
    // Execute transaction with automatic retry on database contention
    let config = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "update_siem_config",
        |db| {
            let config_id = config_id.clone();
            let org_id = org_id.clone();
            let name = req.name.clone();
            let endpoint_url = req.endpoint_url.clone();
            let api_key = api_key.clone();
            let auth_header = auth_header.clone();
            let batch_size = req.batch_size;
            let enabled = req.enabled;
            let event = event.clone();
            let audit_actor = audit_actor.clone();
            Box::pin(async move {
                SiemConfigStore::update(
                    db.clone(),
                    &org_id,
                    &config_id,
                    name,
                    endpoint_url,
                    api_key,
                    auth_header,
                    batch_size,
                    enabled,
                )
                .await?;

                let config = SiemConfigStore::get_by_id(db.clone(), &config_id)
                    .await?
                    .ok_or_else(|| {
                        AppError::InternalServerError(
                            "Failed to retrieve updated config".to_string(),
                        )
                    })?;
                audit_actor.log_org_with_db(db, event).await?;
                Ok(config)
            })
        },
    )
    .await?;

    Ok(Json(to_response(config)))
}

/// Delete SIEM configuration
pub async fn delete_siem_config(
    State(state): State<AppState>,
    Path((org_slug, config_id)): Path<(String, String)>,
    auth_user: axum::Extension<AuthUser>,
) -> Result<StatusCode> {
    let org_model = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    let org = crate::handlers::organizations::ensure_organization_active(&state.db, &org_model.id)
        .await?;

    if !can_manage_siem(&state, &auth_user.user.id, &org.id).await? {
        return Err(AppError::Forbidden(
            "Insufficient permissions to delete SIEM configuration".to_string(),
        ));
    }

    // Verify the config exists and belongs to this organization
    let existing_config = SiemConfigStore::get_by_id(DB::Conn(&state.db), &config_id)
        .await?
        .ok_or_else(|| AppError::NotFound("SIEM configuration not found".to_string()))?;

    if existing_config.org_id != org.id {
        return Err(AppError::NotFound(
            "SIEM configuration not found".to_string(),
        ));
    }

    let org_id = org.id.clone();
    let user_id = auth_user.user.id.clone();
    let event = OrgAuditBuilder::new(&org_id, Some(&user_id), "siem_config.deleted")
        .target("siem_config", &config_id)
        .success(true)
        .details_json(Some(json!({"siem_config_id": &config_id})))
        .build();
    let audit_actor = state.audit_actor.clone();

    // Execute transaction with automatic retry on database contention
    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "delete_siem_config",
        |db| {
            let config_id = config_id.clone();
            let org_id = org_id.clone();
            let event = event.clone();
            let audit_actor = audit_actor.clone();
            Box::pin(async move {
                SiemConfigStore::delete(db.clone(), &org_id, &config_id).await?;
                audit_actor.log_org_with_db(db, event).await?;
                Ok(())
            })
        },
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Test SIEM connection
pub async fn test_siem_connection(
    State(state): State<AppState>,
    Path((org_slug, config_id)): Path<(String, String)>,
    auth_user: axum::Extension<AuthUser>,
) -> Result<Json<TestConnectionResponse>> {
    let org_model = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    let org = crate::handlers::organizations::ensure_organization_active(&state.db, &org_model.id)
        .await?;

    if !can_manage_siem(&state, &auth_user.user.id, &org.id).await? {
        return Err(AppError::Forbidden(
            "Insufficient permissions to test SIEM configuration".to_string(),
        ));
    }

    let config = SiemConfigStore::get_by_id(DB::Conn(&state.db), &config_id)
        .await?
        .ok_or_else(|| AppError::NotFound("SIEM configuration not found".to_string()))?;

    // Verify the config belongs to this organization
    if config.org_id != org.id {
        return Err(AppError::NotFound(
            "SIEM configuration not found".to_string(),
        ));
    }

    // Stored credentials are ciphertext. Fail closed when the runtime keyring
    // is absent rather than sending encoded ciphertext to an external system.
    let auth_headers = siem_auth_headers(
        &config.provider,
        state.encryption.as_deref(),
        &config.id,
        config.api_key.clone(),
        config.auth_header.clone(),
    )?;

    let test_payload = json!({
        "test": true,
        "message": "SIEM connection test from SSO platform",
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    let test_body = serde_json::to_string(&test_payload).map_err(|e| {
        AppError::InternalServerError(format!("Failed to serialize test payload: {}", e))
    })?;

    let safe_client = crate::crypto::safe_http::SafeHttpClient::new()?;
    let mut headers = vec![("Content-Type".to_string(), "application/json".to_string())];
    headers.extend(auth_headers);

    let response = safe_client
        .post_with_owned_headers(&config.endpoint_url, test_body, headers)
        .await;

    match response {
        Ok(response) => {
            match crate::crypto::safe_http::SafeHttpClient::read_body_limited(response, 8 * 1024)
                .await
            {
                Ok((status, _)) if status.is_success() => Ok(Json(TestConnectionResponse {
                    success: true,
                    message: format!("Successfully connected to SIEM endpoint (status: {status})"),
                })),
                Ok((status, _)) => Ok(Json(TestConnectionResponse {
                    success: false,
                    message: format!("SIEM endpoint returned error status {status}"),
                })),
                Err(_) => Ok(Json(TestConnectionResponse {
                    success: false,
                    message: "SIEM endpoint response could not be safely processed".to_string(),
                })),
            }
        }
        Err(_) => Ok(Json(TestConnectionResponse {
            success: false,
            message: "Failed to connect to SIEM endpoint".to_string(),
        })),
    }
}

#[cfg(test)]
mod secret_tests {
    use super::*;
    use base64::Engine as _;

    fn encryption() -> crate::encryption::EncryptionService {
        crate::encryption::EncryptionService::from_keyring_values("active", &"11".repeat(32), None)
            .unwrap()
    }

    #[test]
    fn siem_runtime_rejects_plaintext_and_wrong_context_without_fallback() {
        let encryption = encryption();
        assert!(decode_siem_secret(&encryption, "plaintext!", "config-a", "api_key").is_err());

        let ciphertext = encryption
            .encrypt_with_context(
                "siem-secret",
                crate::encryption::EncryptionContext::new("siem_configs", "config-a", "api_key"),
            )
            .unwrap();
        let stored = base64::engine::general_purpose::STANDARD.encode(ciphertext);
        assert_eq!(
            decode_siem_secret(&encryption, &stored, "config-a", "api_key").unwrap(),
            "siem-secret"
        );
        assert!(decode_siem_secret(&encryption, &stored, "config-b", "api_key").is_err());
        assert!(decode_siem_secret(&encryption, &stored, "config-a", "auth_header").is_err());
    }

    #[test]
    fn siem_test_credentials_are_provider_specific_and_fail_closed() {
        let encryption = encryption();
        let api_key = base64::engine::general_purpose::STANDARD.encode(
            encryption
                .encrypt_with_context(
                    "siem-secret",
                    crate::encryption::EncryptionContext::new(
                        "siem_configs",
                        "config-a",
                        "api_key",
                    ),
                )
                .unwrap(),
        );
        let auth_header = base64::engine::general_purpose::STANDARD.encode(
            encryption
                .encrypt_with_context(
                    "Bearer secret",
                    crate::encryption::EncryptionContext::new(
                        "siem_configs",
                        "config-a",
                        "auth_header",
                    ),
                )
                .unwrap(),
        );

        assert!(
            siem_auth_headers("Datadog", None, "config-a", Some(api_key.clone()), None).is_err()
        );
        assert!(siem_auth_headers("Datadog", Some(&encryption), "config-a", None, None).is_err());
        assert_eq!(
            siem_auth_headers(
                "Datadog",
                Some(&encryption),
                "config-a",
                Some(api_key),
                Some("corrupt-unused-auth-header".to_string()),
            )
            .unwrap(),
            vec![("DD-API-KEY".to_string(), "siem-secret".to_string())]
        );
        assert_eq!(
            siem_auth_headers(
                "Custom",
                Some(&encryption),
                "config-a",
                Some("corrupt-unused-api-key".to_string()),
                Some(auth_header),
            )
            .unwrap(),
            vec![("authorization".to_string(), "Bearer secret".to_string())]
        );
        assert!(siem_auth_headers(
            "Custom",
            Some(&encryption),
            "config-a",
            None,
            Some(
                base64::engine::general_purpose::STANDARD.encode(
                    encryption
                        .encrypt_with_context(
                            "Host: attacker.example",
                            crate::encryption::EncryptionContext::new(
                                "siem_configs",
                                "config-a",
                                "auth_header",
                            ),
                        )
                        .unwrap(),
                )
            ),
        )
        .is_err());
        assert_eq!(
            siem_auth_headers("Custom", None, "config-a", None, None).unwrap(),
            Vec::<(String, String)>::new()
        );
    }

    #[test]
    fn siem_api_response_never_serializes_credential_columns() {
        let now = chrono::Utc::now().naive_utc();
        let response = to_response(crate::entities::siem_configs::Model {
            id: "config-a".to_string(),
            org_id: "org-a".to_string(),
            name: "SIEM".to_string(),
            provider: "Custom".to_string(),
            endpoint_url: "https://siem.example.test/events".to_string(),
            api_key: Some("encrypted-api-key-canary".to_string()),
            auth_header: Some("encrypted-auth-header-canary".to_string()),
            batch_size: "100".to_string(),
            enabled: true,
            last_successful_batch_at: None,
            last_processed_log_id: None,
            failure_count: 0,
            created_at: now,
            updated_at: now,
        });
        let serialized = serde_json::to_value(response).expect("serialize SIEM response");
        let object = serialized.as_object().expect("response object");
        assert!(!object.contains_key("api_key"));
        assert!(!object.contains_key("auth_header"));
        let serialized = serialized.to_string();
        assert!(!serialized.contains("encrypted-api-key-canary"));
        assert!(!serialized.contains("encrypted-auth-header-canary"));
    }
}

#[cfg(test)]
mod route_tests {
    use super::*;

    use crate::audit::actor::AuditHandle;
    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::crypto::sso::OAuthClient;
    use crate::entities::users;
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
        alpha_config_id: String,
        beta_config_id: String,
    }

    async fn seed_config(db: &sea_orm::DatabaseConnection, org_id: &str, name: &str) -> String {
        SiemConfigStore::create(
            DB::Conn(db),
            &uuid::Uuid::new_v4().to_string(),
            org_id,
            name,
            "Custom",
            "https://siem.example.test/events",
            None,
            None,
            Some(50),
        )
        .await
        .expect("seed SIEM config")
    }

    async fn fixture() -> Fixture {
        let db = setup_db().await;
        let config = test_config();
        let jwt_service = Arc::new(test_jwt_service(&config));

        let owner = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "siem-route-owner@example.test",
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
            "siem-route-admin@example.test",
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
            "siem-route-custom@example.test",
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
            "siem-route-member@example.test",
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
            "siem-route-outsider@example.test",
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
            "siem-route-other-owner@example.test",
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
            "siem-route-alpha",
            "SIEM Route Alpha",
            &owner.id,
            Some("tier_enterprise"),
        )
        .await
        .expect("create alpha");
        let (beta, _) = OrganizationStore::create_with_owner(
            DB::Conn(&db),
            "siem-route-beta",
            "SIEM Route Beta",
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
            "siem-route-manager-role",
            &alpha.id,
            "siem-route-manager",
            "SIEM Route Manager",
            None,
            serde_json::json!([CAP_INTEGRATIONS_MANAGE]),
        )
        .await
        .expect("create SIEM manager role");
        MembershipStore::create(
            DB::Conn(&db),
            &alpha.id,
            &custom_manager.id,
            "siem-route-manager",
        )
        .await
        .expect("add custom manager");

        let alpha_config_id = seed_config(&db, &alpha.id, "Alpha SIEM").await;
        let beta_config_id = seed_config(&db, &beta.id, "Beta SIEM").await;

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
                user_agent: "siem-route-test".to_string(),
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
            alpha_config_id,
            beta_config_id,
        }
    }

    #[tokio::test]
    async fn siem_routes_require_live_integration_authority_and_are_org_scoped() {
        let f = fixture().await;

        for auth in [f.owner.clone(), f.admin.clone(), f.custom_manager.clone()] {
            let Json(list) = list_siem_configs(
                State(f.state.clone()),
                Path(f.alpha_slug.clone()),
                axum::Extension(auth.clone()),
            )
            .await
            .expect("integration manager may list SIEM configs");
            assert!(list
                .siem_configs
                .iter()
                .any(|config| config.id == f.alpha_config_id));
            assert!(!list
                .siem_configs
                .iter()
                .any(|config| config.id == f.beta_config_id));

            let Json(config) = get_siem_config(
                State(f.state.clone()),
                Path((f.alpha_slug.clone(), f.alpha_config_id.clone())),
                axum::Extension(auth.clone()),
            )
            .await
            .expect("integration manager may read SIEM config");
            assert_eq!(config.id, f.alpha_config_id);

            let Json(updated) = update_siem_config(
                State(f.state.clone()),
                Path((f.alpha_slug.clone(), f.alpha_config_id.clone())),
                axum::Extension(auth.clone()),
                Json(UpdateSiemConfigRequest {
                    name: Some("Renamed SIEM".to_string()),
                    endpoint_url: None,
                    api_key: None,
                    auth_header: None,
                    batch_size: None,
                    enabled: Some(true),
                }),
            )
            .await
            .expect("integration manager may update SIEM config");
            assert_eq!(updated.name, "Renamed SIEM");

            let Json(test_result) = test_siem_connection(
                State(f.state.clone()),
                Path((f.alpha_slug.clone(), f.alpha_config_id.clone())),
                axum::Extension(auth),
            )
            .await
            .expect("integration manager may test SIEM connection");
            assert!(!test_result.success);
        }

        for auth in [f.member.clone(), f.outsider.clone(), f.other_owner.clone()] {
            assert!(matches!(
                list_siem_configs(
                    State(f.state.clone()),
                    Path(f.alpha_slug.clone()),
                    axum::Extension(auth.clone()),
                )
                .await,
                Err(AppError::Forbidden(_))
            ));
            assert!(matches!(
                get_siem_config(
                    State(f.state.clone()),
                    Path((f.alpha_slug.clone(), f.alpha_config_id.clone())),
                    axum::Extension(auth.clone()),
                )
                .await,
                Err(AppError::Forbidden(_))
            ));
            assert!(matches!(
                update_siem_config(
                    State(f.state.clone()),
                    Path((f.alpha_slug.clone(), f.alpha_config_id.clone())),
                    axum::Extension(auth.clone()),
                    Json(UpdateSiemConfigRequest {
                        name: Some("Denied".to_string()),
                        endpoint_url: None,
                        api_key: None,
                        auth_header: None,
                        batch_size: None,
                        enabled: Some(true),
                    }),
                )
                .await,
                Err(AppError::Forbidden(_))
            ));
            assert!(matches!(
                delete_siem_config(
                    State(f.state.clone()),
                    Path((f.alpha_slug.clone(), f.alpha_config_id.clone())),
                    axum::Extension(auth.clone()),
                )
                .await,
                Err(AppError::Forbidden(_))
            ));
            assert!(matches!(
                test_siem_connection(
                    State(f.state.clone()),
                    Path((f.alpha_slug.clone(), f.alpha_config_id.clone())),
                    axum::Extension(auth),
                )
                .await,
                Err(AppError::Forbidden(_))
            ));
        }

        // Cross-tenant IDs are hidden and leave the beta config unchanged.
        for operation in ["get", "update", "delete", "test"] {
            let result = match operation {
                "get" => get_siem_config(
                    State(f.state.clone()),
                    Path((f.alpha_slug.clone(), f.beta_config_id.clone())),
                    axum::Extension(f.owner.clone()),
                )
                .await
                .map(|_| ())
                .err(),
                "update" => update_siem_config(
                    State(f.state.clone()),
                    Path((f.alpha_slug.clone(), f.beta_config_id.clone())),
                    axum::Extension(f.owner.clone()),
                    Json(UpdateSiemConfigRequest {
                        name: Some("Cross Tenant".to_string()),
                        endpoint_url: None,
                        api_key: None,
                        auth_header: None,
                        batch_size: None,
                        enabled: Some(true),
                    }),
                )
                .await
                .map(|_| ())
                .err(),
                "delete" => delete_siem_config(
                    State(f.state.clone()),
                    Path((f.alpha_slug.clone(), f.beta_config_id.clone())),
                    axum::Extension(f.owner.clone()),
                )
                .await
                .map(|_| ())
                .err(),
                _ => test_siem_connection(
                    State(f.state.clone()),
                    Path((f.alpha_slug.clone(), f.beta_config_id.clone())),
                    axum::Extension(f.owner.clone()),
                )
                .await
                .map(|_| ())
                .err(),
            };
            assert!(
                matches!(result, Some(AppError::NotFound(_))),
                "expected not found for cross-tenant SIEM {operation}, got {result:?}"
            );
        }
        assert!(
            SiemConfigStore::get_by_id(DB::Conn(&f.state.db), &f.beta_config_id)
                .await
                .expect("load beta config")
                .is_some(),
            "cross-tenant operations must preserve the beta config"
        );

        // The owner can delete the alpha config; beta remains.
        let _ = delete_siem_config(
            State(f.state.clone()),
            Path((f.alpha_slug.clone(), f.alpha_config_id.clone())),
            axum::Extension(f.owner.clone()),
        )
        .await
        .expect("owner may delete SIEM config");
        assert!(
            SiemConfigStore::get_by_id(DB::Conn(&f.state.db), &f.alpha_config_id)
                .await
                .expect("load deleted config")
                .is_none()
        );
        assert!(
            SiemConfigStore::get_by_id(DB::Conn(&f.state.db), &f.beta_config_id)
                .await
                .expect("load beta config")
                .is_some()
        );
    }
}
