use crate::{handlers::platform::bootstrap_login, state::AppState};
use axum::{
    extract::{Path, State},
    http::{
        header::{self, HeaderValue},
        StatusCode,
    },
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use include_dir::{include_dir, Dir};
use mime_guess::from_path;
use serde::Serialize;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};

use crate::client_ip::TrustedClientIpKeyExtractor;

static LITE_WEB_DIST: Dir<'_> = include_dir!("$LITE_WEB_DIST_DIR");

#[derive(Serialize)]
struct PublicWebConfigResponse {
    full_client_url: Option<String>,
    managed_config_enabled: bool,
}

pub fn routes(state: &AppState) -> Router<AppState> {
    let bootstrap = Router::new().route("/api/public/bootstrap-login", post(bootstrap_login));
    let bootstrap = if state.config.disable_rate_limiting {
        bootstrap
    } else {
        bootstrap.layer(GovernorLayer {
            config: Box::leak(Box::new(
                GovernorConfigBuilder::default()
                    .per_millisecond(1000)
                    .burst_size(10)
                    .key_extractor(TrustedClientIpKeyExtractor::from_env())
                    .finish()
                    .expect("Failed to build bootstrap login rate limiter"),
            )),
        })
    };

    Router::new()
        .route("/api/public/web-config", get(public_web_config))
        .merge(bootstrap)
        .route("/assets/*path", get(asset))
        .route("/authorize", get(index))
        .route("/", get(index))
        .route("/bootstrap-login", get(index))
        .route("/callback", get(index))
        .route("/register", get(index))
        .route("/forgot-password", get(index))
        .route("/mfa-challenge", get(index))
        .route("/reset-password", get(index))
        .route("/verify-email", get(index))
        .route("/auth/magic-link/verify", get(index))
        .route("/activate", get(index))
        .route("/activate/*path", get(index))
        .route("/support", get(index))
        .route("/app", get(index))
        .route("/app/*path", get(index))
        .route("/invitations/accept", get(index))
        .route("/home", get(home_redirect))
}

async fn public_web_config(State(state): State<AppState>) -> Json<PublicWebConfigResponse> {
    Json(PublicWebConfigResponse {
        full_client_url: state.full_web_client_url.clone(),
        managed_config_enabled: state.config.managed_config_path.is_some(),
    })
}

async fn asset(Path(path): Path<String>) -> Response {
    match LITE_WEB_DIST.get_file(format!("assets/{}", path)) {
        Some(file) => {
            let mime = from_path(file.path()).first_or_octet_stream().to_string();
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, HeaderValue::from_str(&mime).unwrap()),
                    (
                        header::CACHE_CONTROL,
                        HeaderValue::from_static("public, max-age=31536000, immutable"),
                    ),
                ],
                file.contents(),
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn index() -> Response {
    match LITE_WEB_DIST.get_file("index.html") {
        Some(file) => (
            StatusCode::OK,
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("text/html; charset=utf-8"),
                ),
                (
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("no-cache, no-store, must-revalidate"),
                ),
            ],
            Html(String::from_utf8_lossy(file.contents()).into_owned()),
        )
            .into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Lite web client assets are not available. Build lite-web-client/dist before starting the server.",
        )
            .into_response(),
    }
}

async fn home_redirect() -> impl IntoResponse {
    Redirect::temporary("/app")
}
