use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::{
    Json, Router,
    extract::{Path, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Serialize;
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::db::Db;
use crate::portmap;
use crate::socket::config::{apply_hermit_config, build_hermit_config};
use crate::unbound::UnboundManager;

/// Tracks failed auth attempts for exponential backoff.
struct ApiRateLimit {
    failures: u32,
    last_attempt: Instant,
}

/// Shared state passed to all REST API handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Mutex<Db>>,
    pub portmap: portmap::SharedRegistry,
    pub unbound: Arc<Mutex<UnboundManager>>,
    pub start_time: Instant,
    rate_limit: Arc<Mutex<ApiRateLimit>>,
}

impl AppState {
    pub fn new(
        db: Arc<Mutex<Db>>,
        portmap: portmap::SharedRegistry,
        unbound: Arc<Mutex<UnboundManager>>,
        start_time: Instant,
    ) -> Self {
        Self {
            db,
            portmap,
            unbound,
            start_time,
            rate_limit: Arc::new(Mutex::new(ApiRateLimit {
                failures: 0,
                last_attempt: Instant::now(),
            })),
        }
    }
}

/// Standard JSON error response.
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

/// Standard JSON success response for mutations.
#[derive(Serialize)]
struct OkResponse {
    ok: bool,
}

/// Status response.
#[derive(Serialize)]
struct StatusResponse {
    uptime_secs: u64,
    version: String,
    device_count: usize,
    ad_blocking_enabled: bool,
}

/// Config diff entry.
#[derive(Serialize)]
struct DiffResponse {
    changed: bool,
    sections: Vec<SectionDiff>,
}

#[derive(Serialize)]
struct SectionDiff {
    section: String,
    changed: bool,
}

/// Validation response.
#[derive(Serialize)]
struct ValidateResponse {
    valid: bool,
    errors: Vec<String>,
}

fn json_error(status: StatusCode, msg: &str) -> Response {
    (status, Json(ErrorResponse { error: msg.to_string() })).into_response()
}

fn json_ok() -> Response {
    (StatusCode::OK, Json(OkResponse { ok: true })).into_response()
}

/// Bearer token authentication middleware.
/// Extracts the API key from the Authorization header, looks up the hash in
/// the DB, and verifies with argon2.
async fn auth_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    let token = match headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
    {
        Some(val) if val.starts_with("Bearer ") => &val[7..],
        _ => {
            return json_error(StatusCode::UNAUTHORIZED, "missing or invalid Authorization header");
        }
    };

    if token.is_empty() {
        return json_error(StatusCode::UNAUTHORIZED, "empty bearer token");
    }

    // Exponential backoff: 2^min(failures, 6) seconds (max 64s)
    {
        let rl = state.rate_limit.lock().unwrap();
        if rl.failures > 0 {
            let backoff_secs = 1u64 << rl.failures.min(6);
            if rl.last_attempt.elapsed().as_secs() < backoff_secs {
                return json_error(StatusCode::TOO_MANY_REQUESTS, "too many failed attempts; try again later");
            }
        }
    }

    // Look up API key hash from DB
    let hash_str = {
        let db = state.db.lock().unwrap();
        match db.get_config("api_key_hash") {
            Ok(Some(h)) => Zeroizing::new(h),
            Ok(None) => {
                return json_error(
                    StatusCode::UNAUTHORIZED,
                    "no API key configured; set one via set_api_key socket command",
                );
            }
            Err(e) => {
                warn!(error = %e, "failed to read api_key_hash");
                return json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
            }
        }
    };

    // Verify the token against the stored hash
    let parsed_hash = match argon2::PasswordHash::new(&hash_str) {
        Ok(h) => h,
        Err(_) => {
            warn!("stored api_key_hash is not a valid argon2 hash");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };

    use argon2::PasswordVerifier;
    if argon2::Argon2::default()
        .verify_password(token.as_bytes(), &parsed_hash)
        .is_err()
    {
        warn!("REST API authentication failed: invalid API key");
        {
            let mut rl = state.rate_limit.lock().unwrap();
            rl.failures = rl.failures.saturating_add(1);
            rl.last_attempt = Instant::now();
        }
        let db = state.db.lock().unwrap();
        let _ = db.log_audit("api_auth_failure", "invalid API key");
        return json_error(StatusCode::UNAUTHORIZED, "invalid API key");
    }

    // Auth succeeded — reset rate limit counter
    {
        let mut rl = state.rate_limit.lock().unwrap();
        rl.failures = 0;
    }

    next.run(request).await
}

/// Build the axum router with all REST API routes.
pub fn router(state: AppState) -> Router {
    Router::new()
        // Config endpoints (read/write)
        .route("/api/v1/config", get(get_config).put(put_config))
        .route("/api/v1/config/diff", post(post_config_diff))
        .route("/api/v1/config/validate", post(post_config_validate))
        .route("/api/v1/config/{section}", get(get_config_section).put(put_config_section))
        // Runtime state (read-only)
        .route("/api/v1/status", get(get_status))
        .route("/api/v1/devices", get(get_devices))
        // Auth middleware applied to all routes
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state)
}

/// Start the REST API HTTP server on the given port.
pub async fn start(state: AppState, port: u16) -> anyhow::Result<()> {
    let app = router(state);
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(port = port, "REST API server listening on localhost");
    axum::serve(listener, app).await?;
    Ok(())
}

// ─── Config Handlers ───────────────────────────────────────────────────────

/// GET /api/v1/config — return full config as JSON.
async fn get_config(State(state): State<AppState>) -> Response {
    let db = state.db.lock().unwrap();
    let config = build_hermit_config(&db);
    (StatusCode::OK, Json(config)).into_response()
}

/// PUT /api/v1/config — apply full config from JSON body.
async fn put_config(
    State(state): State<AppState>,
    Json(config): Json<hermitshell_common::HermitConfig>,
) -> Response {
    match apply_hermit_config(&config, None, &state.db, &state.portmap, &state.unbound) {
        Ok(()) => json_ok(),
        Err(e) => json_error(StatusCode::BAD_REQUEST, &e),
    }
}

/// Valid section names for per-section GET/PUT.
const VALID_SECTIONS: &[&str] = &[
    "network", "dns", "firewall", "wireguard", "devices",
    "dhcp", "qos", "logging", "tls", "analysis", "wifi",
];

/// GET /api/v1/config/{section} — return a single section as JSON.
async fn get_config_section(
    State(state): State<AppState>,
    Path(section): Path<String>,
) -> Response {
    if !VALID_SECTIONS.contains(&section.as_str()) {
        return json_error(StatusCode::NOT_FOUND, &format!("unknown section: {}", section));
    }

    let db = state.db.lock().unwrap();
    let config = build_hermit_config(&db);
    drop(db);

    // Serialize the whole config to a JSON Value, extract the section
    let full = match serde_json::to_value(&config) {
        Ok(v) => v,
        Err(e) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    match full.get(&section) {
        Some(val) => (StatusCode::OK, Json(val.clone())).into_response(),
        None => json_error(StatusCode::NOT_FOUND, &format!("section not found: {}", section)),
    }
}

/// PUT /api/v1/config/{section} — merge a section into the full config and apply.
async fn put_config_section(
    State(state): State<AppState>,
    Path(section): Path<String>,
    body: String,
) -> Response {
    if !VALID_SECTIONS.contains(&section.as_str()) {
        return json_error(StatusCode::NOT_FOUND, &format!("unknown section: {}", section));
    }

    // Parse the body as a generic JSON value
    let section_value: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, &format!("invalid JSON: {}", e)),
    };

    // Read the current full config
    let current = {
        let db = state.db.lock().unwrap();
        build_hermit_config(&db)
    };

    // Serialize to a mutable JSON Value, replace the section, deserialize back
    let mut full = match serde_json::to_value(&current) {
        Ok(serde_json::Value::Object(m)) => m,
        _ => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "failed to serialize config"),
    };

    full.insert(section.clone(), section_value);

    let merged: hermitshell_common::HermitConfig =
        match serde_json::from_value(serde_json::Value::Object(full)) {
            Ok(c) => c,
            Err(e) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    &format!("merged config is invalid: {}", e),
                )
            }
        };

    match apply_hermit_config(&merged, None, &state.db, &state.portmap, &state.unbound) {
        Ok(()) => json_ok(),
        Err(e) => json_error(StatusCode::BAD_REQUEST, &e),
    }
}

/// POST /api/v1/config/diff — compare supplied config body to current.
async fn post_config_diff(
    State(state): State<AppState>,
    Json(desired): Json<hermitshell_common::HermitConfig>,
) -> Response {
    let current = {
        let db = state.db.lock().unwrap();
        build_hermit_config(&db)
    };

    // Serialize both to JSON Values and compare per section
    let current_val = serde_json::to_value(&current).unwrap_or_default();
    let desired_val = serde_json::to_value(&desired).unwrap_or_default();

    let mut sections = Vec::new();
    let mut any_changed = false;

    for &name in VALID_SECTIONS {
        let c = current_val.get(name);
        let d = desired_val.get(name);
        let changed = c != d;
        if changed {
            any_changed = true;
        }
        sections.push(SectionDiff {
            section: name.to_string(),
            changed,
        });
    }

    (
        StatusCode::OK,
        Json(DiffResponse {
            changed: any_changed,
            sections,
        }),
    )
        .into_response()
}

/// POST /api/v1/config/validate — validate supplied config, return errors.
async fn post_config_validate(
    Json(config): Json<hermitshell_common::HermitConfig>,
) -> Response {
    let errors = config.validate();
    let error_strings: Vec<String> = errors.iter().map(|e| e.to_string()).collect();

    (
        StatusCode::OK,
        Json(ValidateResponse {
            valid: error_strings.is_empty(),
            errors: error_strings,
        }),
    )
        .into_response()
}

// ─── Runtime State Handlers ─────────────────────────────────────────────────

/// GET /api/v1/status — uptime, version, device count.
async fn get_status(State(state): State<AppState>) -> Response {
    let db = state.db.lock().unwrap();
    let device_count = db.list_devices().map(|d| d.len()).unwrap_or(0);
    let ad_blocking = db.get_config_bool("ad_blocking_enabled", true);
    drop(db);

    (
        StatusCode::OK,
        Json(StatusResponse {
            uptime_secs: state.start_time.elapsed().as_secs(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            device_count,
            ad_blocking_enabled: ad_blocking,
        }),
    )
        .into_response()
}

/// GET /api/v1/devices — connected devices list.
async fn get_devices(State(state): State<AppState>) -> Response {
    let db = state.db.lock().unwrap();
    match db.list_devices() {
        Ok(devices) => (StatusCode::OK, Json(devices)).into_response(),
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}
