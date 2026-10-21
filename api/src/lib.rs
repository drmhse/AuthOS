//! Top layer: HTTP surface (handlers, router, middleware, state).
//!
//! Lower layers live in `crates/authos-*`; they are re-exported here under
//! their original module names so `crate::<module>` paths keep resolving.

pub use authos_audit::audit;
pub use authos_core::{client_ip, config, constants, error, rsa_keys, runtime_metadata, utils};
pub use authos_crypto::{crypto, encryption};
pub use authos_db::db;
pub use authos_entities::entities;
pub use authos_services::{billing, email, jobs, services};
pub use authos_store::store;

mod handlers;
mod http_security;
mod lite_web;
mod middleware;
mod router;
mod state;
#[cfg(test)]
pub use authos_testkit as test_support;

use crate::billing::{
    BillingProvider, BillingProviderType, DisabledBillingProvider, PolarProvider, StripeProvider,
};
use crate::config::Config;
use crate::crypto::jwt::JwtService;
use crate::crypto::sso::OAuthClient;
use crate::encryption::EncryptionService;
use crate::handlers::health::readiness;
use crate::handlers::webhook::{billing_webhook, stripe_webhook, WebhookState};
use crate::jobs::device_code_cleanup::DeviceCodeCleanupJob;
use crate::jobs::job_processor::JobProcessor;
use crate::jobs::oauth_state_cleanup::OAuthStateCleanupJob;
use crate::jobs::saml_state_cleanup::SamlStateCleanupJob;
use crate::jobs::token_refresh::TokenRefreshJob;
use crate::state::AppState;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{extract::State, Json};
use axum::{
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sea_orm::DatabaseConnection;
use serde::Serialize;
use std::sync::Arc;
use std::{env, net::IpAddr};
use tower_http::set_header::SetResponseHeaderLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use webauthn_rs::prelude::*;

/// Ensures a platform owner exists with the given email.
/// If the user exists, updates is_platform_owner to true.
/// If the user doesn't exist, creates one.
async fn ensure_platform_owner(db: &DatabaseConnection, email: &str) -> anyhow::Result<()> {
    use crate::db::DB as DbEnum;
    use crate::store::users::UserStore;

    let db_conn = DbEnum::Conn(db);

    // Try to find the user by email (explicitly platform scope/no org)
    match UserStore::find_by_email_with_context(db_conn.clone(), email, None).await {
        Ok(Some(user)) => {
            // User exists, ensure they are a platform owner
            if !user.is_platform_owner {
                UserStore::set_platform_owner(db_conn, &user.id, true).await?;
                tracing::info!(user_id = %user.id, "Platform owner status granted to existing user");
            } else {
                tracing::info!(user_id = %user.id, "User is already a platform owner");
            }
        }
        Ok(None) => {
            // User doesn't exist, create them as a platform owner
            let user = UserStore::create(db_conn, email, None, true).await?;
            tracing::info!(user_id = %user.id, "Platform owner created");
        }
        Err(e) => {
            tracing::error!("Failed to ensure platform owner: {}", e);
            return Err(e.into());
        }
    }

    Ok(())
}

#[derive(Serialize)]
struct Jwk {
    kty: String,
    alg: String,
    #[serde(rename = "use")]
    key_use: String,
    kid: String,
    n: String,
    e: String,
}

#[derive(Serialize)]
struct JwksResponse {
    keys: Vec<Jwk>,
}

/// Prometheus metrics endpoint
async fn metrics_handler(
    headers: HeaderMap,
    prometheus_handle: axum::extract::Extension<Arc<metrics_exporter_prometheus::PrometheusHandle>>,
    metrics_access: axum::extract::Extension<crate::http_security::MetricsAccess>,
) -> Response {
    match metrics_access.authorize(headers.get(header::AUTHORIZATION)) {
        crate::http_security::MetricsAuthorization::Authorized => (
            [(
                header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            )],
            prometheus_handle.render(),
        )
            .into_response(),
        crate::http_security::MetricsAuthorization::Unauthorized => (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
        )
            .into_response(),
        crate::http_security::MetricsAuthorization::Disabled => {
            StatusCode::NOT_FOUND.into_response()
        }
    }
}

fn build_jwks(jwt_service: &JwtService) -> Result<JwksResponse, axum::http::StatusCode> {
    let keys = jwt_service
        .verification_public_keys()
        .into_iter()
        .map(|(kid, public_key_pem)| {
            let (modulus, exponent) = crate::rsa_keys::public_key_components(public_key_pem)
                .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
            Ok(Jwk {
                kty: "RSA".to_string(),
                alg: "RS256".to_string(),
                key_use: "sig".to_string(),
                kid: kid.to_string(),
                n: URL_SAFE_NO_PAD.encode(modulus),
                e: URL_SAFE_NO_PAD.encode(exponent),
            })
        })
        .collect::<Result<Vec<_>, axum::http::StatusCode>>()?;
    Ok(JwksResponse { keys })
}

async fn jwks_handler(
    State(state): State<AppState>,
) -> Result<Json<JwksResponse>, axum::http::StatusCode> {
    build_jwks(&state.jwt_service).map(Json)
}

fn webauthn_rp_id(base_url: &str) -> Option<String> {
    let parsed_url = Url::parse(base_url).ok()?;
    let host = parsed_url.host_str()?.to_string();
    if host == "localhost" {
        return Some(host);
    }
    if host.parse::<IpAddr>().is_ok() || parsed_url.scheme() != "https" {
        return None;
    }
    Some(host)
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
pub async fn run() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,sso=debug,sqlx::query=warn".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load environment variables
    dotenvy::dotenv().ok();

    // Handle "setup-geoip" command for container initialization
    // This replaces the need for curl/tar in the runtime image
    if std::env::args().nth(1).as_deref() == Some("setup-geoip") {
        crate::services::geoip_setup::run_setup().await?;
        return Ok(());
    }

    // Offline secret verification/rewrap command. It intentionally runs
    // before JWT material is loaded so this maintenance task cannot be blocked
    // by unrelated signing-key configuration.
    if std::env::args().nth(1).as_deref() == Some("rewrap-secrets") {
        let arguments = std::env::args().skip(2).collect::<Vec<_>>();
        let options = match crate::services::secret_rewrap::RewrapOptions::parse(&arguments) {
            Ok(options) => options,
            Err(crate::services::secret_rewrap::RewrapError::HelpRequested) => {
                println!(
                    "rewrap-secrets [--dry-run|--apply] [--batch-size 1-1000] [--max-batches N]"
                );
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        let config = Config::from_env().map_err(anyhow::Error::msg)?;
        let encryption = EncryptionService::new()?;
        let database = crate::db::connect_db(&config).await?;
        let report = crate::services::secret_rewrap::run(&database, &encryption, &options).await?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        if !report.complete {
            anyhow::bail!("secret rewrap stopped at the configured batch limit; rerun to continue");
        }
        return Ok(());
    }

    let config = Config::from_env().expect("Failed to load configuration");
    let http_security_config = crate::http_security::HttpSecurityConfig::from_env()
        .expect("Failed to load HTTP security configuration");

    // Validate secret encryption before touching the database. Normal server
    // operation fails closed when the key is missing or malformed.
    let encryption = EncryptionService::for_server_startup()?;
    if encryption.is_some() {
        tracing::info!("Encryption service initialized");
    } else {
        tracing::warn!(
            "UNENCRYPTED DEVELOPMENT MODE ENABLED via {} - selected secrets may be stored in plaintext; do not use this mode with persistent or production data",
            crate::encryption::ALLOW_UNENCRYPTED_DEVELOPMENT_ENV
        );
    }

    // Validate signing and device-trust key material before database
    // initialization. A bad secret must not run migrations or otherwise mutate
    // persistent state before startup fails.
    let private_key =
        env::var("JWT_PRIVATE_KEY_BASE64").expect("JWT_PRIVATE_KEY_BASE64 must be set");
    let public_key = env::var("JWT_PUBLIC_KEY_BASE64").expect("JWT_PUBLIC_KEY_BASE64 must be set");
    let key_id = env::var("JWT_KID").expect("JWT_KID must be set");
    let previous_public_keys = JwtService::parse_previous_public_keys_json(
        env::var(crate::crypto::jwt::PREVIOUS_PUBLIC_KEYS_ENV)
            .ok()
            .as_deref(),
    )
    .expect("Failed to parse previous JWT public-key ring");
    let jwt_service = Arc::new(
        JwtService::new_with_previous_keys(
            &private_key,
            &public_key,
            config.jwt_expiration_hours,
            &key_id,
            &config.base_url,
            &previous_public_keys,
        )
        .expect("Failed to initialize JWT service"),
    );
    let risk_engine = Arc::new(
        crate::services::risk_engine::RiskEngine::new().expect("Failed to initialize RiskEngine"),
    );

    // Initialize database using SeaORM
    let database_backend = config
        .database_url
        .split_once(':')
        .map_or("unknown", |(scheme, _)| scheme);
    tracing::info!(
        "Connecting to {} database (pool: {}-{} connections)",
        database_backend,
        config.db_min_connections,
        config.db_max_connections
    );
    let db = db::init_db(&config)
        .await
        .expect("Failed to initialize database");
    tracing::info!("Database initialized and migrated successfully");

    // A serving process may run schema migrations, but it must never perform
    // data-secret migration concurrently with API or worker traffic. Verify
    // the complete inventory read-only before bootstrap, writer-pool creation,
    // external connections, background tasks, or router startup.
    if let Some(encryption) = encryption.as_ref() {
        crate::services::secret_rewrap::verify_runtime_ready(&db, encryption).await?;
        tracing::info!("Secret inventory authenticated and runtime-ready");
    }

    // SQLite-only: Initialize writer connection pool (single connection)
    #[cfg(feature = "db_sqlite")]
    let db_writer = db::init_db_writer(&config)
        .await
        .expect("Failed to initialize SQLite writer connection");

    // Bootstrap platform owner if configured.
    // Password bootstrap is one-time only and will not overwrite an existing password.
    if let (Some(email), Some(password)) = (
        config.platform_owner_email.as_ref(),
        config.platform_owner_password.as_ref(),
    ) {
        use crate::db::DB as DbEnum;
        use crate::store::users::UserStore;
        UserStore::bootstrap_platform_owner(DbEnum::Conn(&db), email, password).await?;
    } else if let Some(email) = config.platform_owner_email.as_ref() {
        ensure_platform_owner(&db, email).await?;
    }

    // Initialize email service (optional)
    let email_service = crate::email::EmailService::from_env().ok();
    if let Some(ref svc) = email_service {
        // Test SMTP connection at startup to catch configuration issues early
        // Test SMTP connection at startup to catch configuration issues early
        // Wrap in timeout to prevent hanging startup if SMTP server is unresponsive
        match tokio::time::timeout(std::time::Duration::from_secs(5), svc.test_connection()).await {
            Ok(Ok(())) => tracing::info!("Email service ready - SMTP connection verified"),
            Ok(Err(e)) => tracing::warn!(
                "Email service SMTP connection test failed: {} - emails may fail",
                e
            ),
            Err(_) => {
                tracing::warn!("Email service SMTP connection test timed out - emails may fail")
            }
        }
    } else {
        tracing::warn!("Email service not configured - email features will be disabled");
    }

    // Start background token refresh job
    if let Some(enc) = encryption.clone() {
        let refresh_db = db.clone();
        tokio::spawn(async move {
            let job = TokenRefreshJob::new(refresh_db, Some(enc));
            job.start().await;
        });
        tracing::info!("Token refresh job started");
    }

    // Start background device code cleanup job
    {
        let cleanup_db = db.clone();
        tokio::spawn(async move {
            let job = DeviceCodeCleanupJob::new(cleanup_db);
            job.start().await;
        });
        tracing::info!("Device code cleanup job started");
    }

    // Start background OAuth state cleanup job
    {
        let cleanup_db = db.clone();
        tokio::spawn(async move {
            let job = OAuthStateCleanupJob::new(cleanup_db);
            job.start().await;
        });
        tracing::info!("OAuth state cleanup job started");
    }

    // The in-memory rate limiters prune each key's timestamps on access but
    // never drop the key itself, so without this the maps grow one entry per
    // address seen, forever.
    {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(600));
            loop {
                interval.tick().await;
                crate::middleware::EMAIL_RATE_LIMITER.cleanup().await;
                crate::middleware::LOGIN_ATTEMPT_LIMITER.cleanup().await;
                crate::middleware::MFA_RATE_LIMITER.cleanup().await;
            }
        });
        tracing::info!("Rate limiter cleanup job started");
    }

    // Start background SAML state cleanup job
    {
        let cleanup_db = db.clone();
        tokio::spawn(async move {
            let job = SamlStateCleanupJob::new(cleanup_db);
            job.start().await;
        });
        tracing::info!("SAML state cleanup job started");
    }

    // Start background user cleanup job for GDPR compliance
    {
        let cleanup_db = db.clone();
        tokio::spawn(async move {
            let job = crate::jobs::user_cleanup::UserCleanupJob::new(cleanup_db);
            job.start().await;
        });
        tracing::info!("User cleanup job started (GDPR compliance)");
    }

    // Start background job processor (new queue-based system)
    {
        let processor_db = db.clone();
        #[cfg(feature = "db_sqlite")]
        let processor_db_writer = db_writer.clone();

        let processor_email = email_service.clone().map(Arc::new);
        let processor_encryption = encryption.clone();
        let batch_size = config.job_processor_batch_size;
        tokio::spawn(async move {
            let processor = JobProcessor::new(
                processor_db,
                #[cfg(feature = "db_sqlite")]
                processor_db_writer,
                processor_email,
                processor_encryption,
                batch_size,
            );
            processor.start().await;
        });
        tracing::info!(
            batch_size = config.job_processor_batch_size,
            "Job processor started"
        );
    }

    // Initialize Prometheus metrics exporter
    let prometheus_handle =
        crate::services::prometheus_metrics::PrometheusMetricsService::initialize_exporter()
            .expect("Failed to initialize Prometheus metrics exporter");
    tracing::info!("Prometheus metrics exporter initialized");

    // Start Prometheus metrics updater task
    {
        let metrics_db = db.clone();
        tokio::spawn(async move {
            crate::services::prometheus_metrics::metrics_updater_task(metrics_db).await;
        });
        tracing::info!("Prometheus metrics updater task started");
    }

    // Initialize services
    let oauth_client =
        Arc::new(OAuthClient::new(&config).expect("Failed to initialize OAuth client"));

    // Initialize billing provider based on BILLING_PROVIDER env var
    let billing_provider_name =
        std::env::var("BILLING_PROVIDER").unwrap_or_else(|_| "none".to_string());
    let billing_provider_type = billing_provider_name
        .parse::<BillingProviderType>()
        .map_err(|err| {
            anyhow::anyhow!(
                "Invalid BILLING_PROVIDER '{}': {}",
                billing_provider_name,
                err
            )
        })?;

    let billing_provider: Arc<dyn BillingProvider> = match billing_provider_type {
        BillingProviderType::Disabled => {
            tracing::info!("Billing provider: disabled");
            Arc::new(DisabledBillingProvider::new())
        }
        BillingProviderType::Stripe => {
            let stripe_secret_key = config
                .stripe_secret_key
                .clone()
                .expect("STRIPE_SECRET_KEY must be set when BILLING_PROVIDER=stripe");
            let stripe_webhook_secret = config
                .stripe_webhook_secret
                .clone()
                .expect("STRIPE_WEBHOOK_SECRET must be set when BILLING_PROVIDER=stripe");
            let provider = if let Some(ref base_url) = config.stripe_api_base_url {
                StripeProvider::new_with_base_url(
                    stripe_secret_key,
                    stripe_webhook_secret,
                    base_url,
                )
            } else {
                StripeProvider::new(stripe_secret_key, stripe_webhook_secret)
            };
            tracing::info!("Billing provider: Stripe");
            Arc::new(provider)
        }
        BillingProviderType::Polar => {
            let polar_api_key = std::env::var("POLAR_API_KEY")
                .expect("POLAR_API_KEY must be set when BILLING_PROVIDER=polar");
            let polar_webhook_secret = std::env::var("POLAR_WEBHOOK_SECRET")
                .expect("POLAR_WEBHOOK_SECRET must be set when BILLING_PROVIDER=polar");
            let provider = PolarProvider::new(polar_api_key, polar_webhook_secret);
            tracing::info!("Billing provider: Polar");
            Arc::new(provider)
        }
    };

    // Initialize metrics service
    let metrics_service = Arc::new(crate::services::metrics::MfaMetricsService::new(db.clone()));

    // MFA daily metrics are read from mfa_daily_metrics rows, so something has
    // to write yesterday's rollup. Without this the metrics endpoints only ever
    // return whatever a manual /generate call happened to produce.
    {
        let metrics_service = metrics_service.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                // Yesterday, so the day being summarised is closed.
                let date = (chrono::Utc::now() - chrono::Duration::days(1)).date_naive();
                if let Err(error) = metrics_service.generate_all_daily_metrics(date).await {
                    tracing::warn!(%error, "MFA daily metrics rollup failed");
                }
            }
        });
        tracing::info!("MFA daily metrics job started");
    }

    // Initialize centralized event dispatcher
    let event_dispatcher = Arc::new(crate::services::events::EventDispatcher::new(db.clone()));

    // Check GeoIP database status and warn operator if unavailable
    if std::env::var("GEOIP_DISABLED").unwrap_or_default() != "true" {
        let geoip_db_path = std::env::var("GEOIP_DATABASE_PATH")
            .unwrap_or_else(|_| "data/GeoLite2-City.mmdb".to_string());

        if !std::path::Path::new(&geoip_db_path).exists() {
            tracing::warn!(
                "⚠️  GEOGRAPHIC SECURITY FEATURES DISABLED: GeoIP database not found at {}",
                geoip_db_path
            );
            tracing::warn!("   To enable impossible travel detection and geo-risk analysis:");
            tracing::warn!("   1. Run: ./sso setup-geoip");
            tracing::warn!("   2. Or set: GEOIP_DISABLED=true (not recommended for production)");
        } else {
            tracing::info!("✓ GeoIP database available: {}", geoip_db_path);
        }
    } else {
        tracing::info!("GeoIP features explicitly disabled via GEOIP_DISABLED=true");
    }

    // Initialize WebAuthn service only when the configured origin can be a valid RP.
    let webauthn_service = match webauthn_rp_id(&config.base_url) {
        Some(rp_id) => {
            match crate::services::webauthn::WebAuthnService::new(
                &rp_id,
                &config.base_url,
                Some("SSO Platform"),
            ) {
                Ok(service) => Some(Arc::new(service)),
                Err(e) => {
                    tracing::warn!("Failed to initialize WebAuthn service: {}", e);
                    None
                }
            }
        }
        None => {
            tracing::info!(
                "WebAuthn passkeys disabled because BASE_URL is not a domain-backed HTTPS or localhost origin"
            );
            None
        }
    };

    // Initialize permission cache
    // TTL: 60 seconds (balances security/revocation speed with performance)
    // Max capacity: 10,000 users (adjust based on available RAM)
    use moka::future::Cache;
    use std::time::Duration;
    let permission_cache = Cache::builder()
        .time_to_live(Duration::from_secs(60))
        .max_capacity(10_000)
        .build();

    // Short TTL so a revoked permission or changed password stops working
    // quickly; writers must still invalidate explicitly.
    let user_cache: Cache<String, crate::entities::users::Model> = Cache::builder()
        .time_to_live(Duration::from_secs(30))
        .max_capacity(10_000)
        .build();

    // Security Audit Item 3: Initialize domain cache for dynamic CORS
    // TTL: 5 minutes (300 seconds), Max capacity: 10,000 domains
    let domain_cache: Cache<String, bool> = Cache::builder()
        .time_to_live(Duration::from_secs(300))
        .max_capacity(10_000)
        .build();

    // Initialize the durable audit-outbox reconciler.
    // Uses db_writer for SQLite to avoid contention with main db pool
    #[cfg(feature = "db_sqlite")]
    let audit_actor = crate::audit::actor::AuditHandle::new(db_writer.clone());
    #[cfg(not(feature = "db_sqlite"))]
    let audit_actor = crate::audit::actor::AuditHandle::new(db.clone());

    // Create application state
    let app_state = AppState {
        db: db.clone(),
        #[cfg(feature = "db_sqlite")]
        db_writer: db_writer.clone(),
        oauth_client: oauth_client.clone(),
        jwt_service: jwt_service.clone(),
        base_url: config.base_url.clone(),
        web_client_url: config.platform_dashboard_base_url.clone(),
        full_web_client_url: config.full_web_client_base_url.clone(),
        encryption: encryption.clone().map(Arc::new),
        email_service: email_service.map(Arc::new),
        metrics_service: metrics_service.clone(),
        event_dispatcher: event_dispatcher.clone(),
        billing_provider: billing_provider.clone(),
        risk_engine: risk_engine.clone(),
        webauthn_service: webauthn_service.clone(),
        permission_cache,
        user_cache,
        domain_cache,
        audit_actor: audit_actor.clone(),
        config: config.clone(),
    };

    let webhook_state = WebhookState {
        db: db.clone(),
        #[cfg(feature = "db_sqlite")]
        db_writer: db_writer.clone(),
        billing_provider: billing_provider.clone(),
    };

    // Build routes using the router module
    let protected_routes = router::protected_routes(&app_state);
    let analytics_routes = router::analytics_routes(&app_state);
    let mfa_routes = router::mfa_routes(&app_state, &config);
    let mfa_verification_routes = router::mfa_verification_routes(&config);
    let platform_routes = router::platform_routes(&app_state);
    let service_api_routes = router::service_api_routes(&app_state);
    let scim_routes = router::scim_routes(&app_state);
    let public_routes = router::public_routes(&config);
    let lite_web_routes = lite_web::routes(&app_state);

    // Combine all routes
    let app = Router::new()
        // AuthOS runtime capability metadata and the JWT verification key.
        // Standards discovery returns 404 until AuthOS implements the
        // corresponding authorization-server/OIDC provider profiles.
        .merge(runtime_metadata::routes(&config.base_url))
        .route("/.well-known/jwks.json", get(jwks_handler))
        .merge(public_routes)
        .merge(protected_routes)
        .merge(mfa_routes)
        .merge(mfa_verification_routes)
        .merge(platform_routes)
        .merge(service_api_routes)
        .merge(scim_routes)
        .merge(analytics_routes)
        .merge(lite_web_routes)
        .with_state(app_state.clone())
        // Health readiness check (needs DB access)
        .route("/health/ready", get(readiness))
        .with_state(db.clone())
        // Webhook routes (separate state)
        .route("/webhooks/stripe", post(stripe_webhook))
        .route("/webhooks/billing", post(billing_webhook))
        .with_state(webhook_state)
        // Prometheus metrics endpoint
        .route("/metrics", get(metrics_handler))
        .layer(axum::Extension(Arc::new(prometheus_handle)))
        .layer(axum::Extension(http_security_config.metrics_access.clone()))
        // Request info extraction (IP and User-Agent) - must be before auth
        .layer(axum::middleware::from_fn(
            crate::middleware::extract_request_info_middleware,
        ))
        // Security Headers (Security Audit Item 4)
        .layer(SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        // Dynamic CORS (Security Audit Item 3)
        // Replaces permissive CorsLayer with domain-aware CORS validation
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            crate::middleware::dynamic_cors_middleware,
        ))
        // Request timeout: Fail fast at 30 seconds to prevent runaway requests
        // Note: 5s was too aggressive - SAML cert generation (RSA) needs ~10-20s under load
        // 30s provides protection while allowing legitimate slow crypto operations
        .layer(tower_http::timeout::TimeoutLayer::new(Duration::from_secs(
            30,
        )))
        // Bound streamed and buffered bodies before handlers allocate unbounded input.
        .layer(http_security_config.request_body_limit_layer())
        // HTTP request duration metrics - outermost layer to capture full request lifecycle
        // This measures time including CORS handling, auth, and all other middleware
        .layer(axum::middleware::from_fn(
            crate::middleware::http_metrics_middleware,
        ));

    // More Aggressive WAL Checkpointing (SQLite only)
    #[cfg(feature = "db_sqlite")]
    {
        let checkpoint_db = db.clone();
        tokio::spawn(async move {
            use sea_orm::ConnectionTrait;
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10)); // Checkpoint more frequently
            loop {
                interval.tick().await;
                // Use TRUNCATE to shrink the WAL file, which is more effective under heavy load
                if let Err(e) = checkpoint_db
                    .execute_unprepared("PRAGMA wal_checkpoint(TRUNCATE);")
                    .await
                {
                    tracing::warn!("WAL checkpoint failed: {}", e);
                } else {
                    tracing::debug!("WAL checkpoint (TRUNCATE) completed");
                }
            }
        });
    }

    // Start server
    let addr = format!("{}:{}", config.server_host, config.server_port);
    tracing::info!("Starting server on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;

    tracing::info!("Server listening on http://{}", addr);
    tracing::info!("SSO endpoints:");
    tracing::info!("  - GET /auth/github");
    tracing::info!("  - GET /auth/google");
    tracing::info!("  - GET /auth/microsoft");
    tracing::info!("Device flow endpoints:");
    tracing::info!("  - POST /auth/device/code");
    tracing::info!("  - GET /activate");
    tracing::info!("  - POST /auth/token");
    tracing::info!("Protected API endpoints:");
    tracing::info!("  - GET /api/user");
    tracing::info!("  - GET /api/subscription");
    tracing::info!("Service API endpoints (API key auth):");
    tracing::info!("  - GET /api/service/users");
    tracing::info!("  - GET /api/service/subscriptions");
    tracing::info!("  - GET /api/service/analytics");
    tracing::info!("SCIM 2.0 endpoints (Bearer token auth):");
    tracing::info!("  - GET /scim/v2/Users");
    tracing::info!("  - POST /scim/v2/Users");
    tracing::info!("  - GET /scim/v2/Groups");
    tracing::info!("  - PATCH /scim/v2/Groups/:id");
    tracing::info!("Webhook endpoints:");
    tracing::info!("  - POST /webhooks/stripe");

    // Create the server with graceful shutdown support
    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal(audit_actor));

    server.await?;

    Ok(())
}

/// Graceful shutdown signal handler
/// Waits for SIGTERM or SIGINT, then reconciles eligible durable audit rows.
async fn shutdown_signal(audit_actor: crate::audit::actor::AuditHandle) {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C, initiating graceful shutdown...");
        }
        _ = terminate => {
            tracing::info!("Received SIGTERM, initiating graceful shutdown...");
        }
    }

    // Durable rows remain replayable after shutdown; attempt eligible delivery
    // and report whether retry/backoff rows remain.
    audit_actor.shutdown().await;
}

#[cfg(test)]
mod jwks_tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use std::collections::BTreeMap;

    fn key_pair() -> (String, String) {
        let key = crate::rsa_keys::GeneratedKey::generate().expect("generate RSA key");
        (
            STANDARD.encode(key.private_key_pem().expect("private PEM")),
            STANDARD.encode(key.public_key_pem().expect("public PEM")),
        )
    }

    #[test]
    fn jwks_publishes_active_and_previous_verification_keys() {
        let (_, old_public) = key_pair();
        let (active_private, active_public) = key_pair();
        let previous = BTreeMap::from([("old-key".to_string(), old_public)]);
        let jwt = JwtService::new_with_previous_keys(
            &active_private,
            &active_public,
            24,
            "active-key",
            "https://auth.example.com",
            &previous,
        )
        .expect("JWT service with overlap");

        let jwks = build_jwks(&jwt).expect("build JWKS");
        assert_eq!(
            jwks.keys
                .iter()
                .map(|key| key.kid.as_str())
                .collect::<Vec<_>>(),
            vec!["active-key", "old-key"]
        );
        assert!(jwks
            .keys
            .iter()
            .all(|key| key.kty == "RSA" && key.alg == "RS256" && key.key_use == "sig"));
        assert_ne!(jwks.keys[0].n, jwks.keys[1].n);
        assert!(jwks
            .keys
            .iter()
            .all(|key| !key.n.is_empty() && !key.e.is_empty()));
    }
}
