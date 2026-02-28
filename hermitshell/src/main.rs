use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::response::IntoResponse;
use axum::Router;
use tower_service::Service;
use leptos::config::get_configuration;
use leptos_axum::{generate_route_list, LeptosRoutes};

use hermitshell_ui::App;
use hermitshell_ui::client;

const STYLE_CSS: &str = include_str!("../../hermitshell-ui/style/style.css");

async fn serve_css() -> impl IntoResponse {
    ([("content-type", "text/css")], STYLE_CSS)
}

async fn handle_backup_config(
    axum::extract::Form(params): axum::extract::Form<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let include_secrets = params.get("secrets").map(|v| v == "1").unwrap_or(false);
    let passphrase = params.get("passphrase").cloned();
    match client::export_config_v2(include_secrets, passphrase.as_deref()) {
        Ok(data) => (
            [(axum::http::header::CONTENT_TYPE, "application/json"),
             (axum::http::header::CONTENT_DISPOSITION, "attachment; filename=hermitshell-config.json")],
            data
        ).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

async fn handle_restore_config(
    mut multipart: axum::extract::Multipart,
) -> impl IntoResponse {
    let mut file_data: Option<String> = None;
    let mut passphrase: Option<String> = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "file" => {
                if let Ok(bytes) = field.bytes().await {
                    file_data = String::from_utf8(bytes.to_vec()).ok();
                }
            }
            "passphrase" => {
                if let Ok(bytes) = field.bytes().await {
                    let s = String::from_utf8(bytes.to_vec()).unwrap_or_default();
                    if !s.is_empty() {
                        passphrase = Some(s);
                    }
                }
            }
            _ => {}
        }
    }

    let Some(data) = file_data else {
        return (axum::http::StatusCode::BAD_REQUEST, "file field required").into_response();
    };

    match client::import_config_v2(&data, passphrase.as_deref()) {
        Ok(()) => axum::response::Redirect::to("/settings").into_response(),
        Err(e) => (axum::http::StatusCode::BAD_REQUEST, e).into_response(),
    }
}

async fn security_headers_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(req).await;
    let h = response.headers_mut();
    h.insert(
        axum::http::header::STRICT_TRANSPORT_SECURITY,
        axum::http::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    h.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static("default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"),
    );
    h.insert(
        axum::http::header::X_FRAME_OPTIONS,
        axum::http::HeaderValue::from_static("DENY"),
    );
    h.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    h.insert(
        axum::http::header::REFERRER_POLICY,
        axum::http::HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    response
}

/// Allowed Host header values to prevent DNS rebinding attacks.
/// Requests with Host headers not matching these patterns are rejected.
fn is_allowed_host(host: &str) -> bool {
    // Strip port if present (e.g. "10.0.0.1:8443" → "10.0.0.1")
    let hostname = host.split(':').next().unwrap_or(host);

    // Always allow IP addresses (browser already connected to them directly)
    if hostname.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }

    // Allow known local hostnames
    matches!(hostname, "localhost" | "hermitshell.local")
}

async fn host_validation_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if let Some(host) = req.headers().get(axum::http::header::HOST).and_then(|v| v.to_str().ok()) {
        if !is_allowed_host(host) {
            return (axum::http::StatusCode::FORBIDDEN, "Invalid Host header").into_response();
        }
    }
    next.run(req).await
}

async fn csrf_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let method = req.method().clone();

    // Safe methods are always allowed
    if method == axum::http::Method::GET
        || method == axum::http::Method::HEAD
        || method == axum::http::Method::OPTIONS
    {
        return next.run(req).await;
    }

    // Check Sec-Fetch-Site first (most reliable)
    if let Some(sfs) = req.headers().get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        if sfs == "same-origin" {
            return next.run(req).await;
        }
        // Any other value (cross-site, same-site, none) → reject
        return (axum::http::StatusCode::FORBIDDEN, "Cross-origin request blocked").into_response();
    }

    // Fallback: compare Origin to Host
    let origin = req.headers().get(axum::http::header::ORIGIN).and_then(|v| v.to_str().ok());
    let host = req.headers().get(axum::http::header::HOST).and_then(|v| v.to_str().ok());

    match (origin, host) {
        (Some(origin_val), Some(host_val)) => {
            // Extract host from Origin URL (e.g., "https://hermitshell.local" → "hermitshell.local")
            let origin_host = origin_val
                .strip_prefix("https://").or_else(|| origin_val.strip_prefix("http://"))
                .unwrap_or(origin_val);
            if origin_host == host_val {
                next.run(req).await
            } else {
                (axum::http::StatusCode::FORBIDDEN, "Cross-origin request blocked").into_response()
            }
        }
        (Some(_), None) => {
            // Origin present but no Host to compare → reject
            (axum::http::StatusCode::FORBIDDEN, "Cross-origin request blocked").into_response()
        }
        (None, _) => {
            // No Sec-Fetch-Site, no Origin → non-browser client → allow
            next.run(req).await
        }
    }
}

async fn auth_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let path = req.uri().path().to_string();

    let is_setup_path = path.starts_with("/api/setup_interfaces")
        || path.starts_with("/api/get_interfaces");

    if path == "/login" || path == "/setup" || path == "/style.css"
        || path.starts_with("/api/login") || path.starts_with("/api/setup_password")
    {
        return next.run(req).await;
    }

    // Setup endpoints only bypass auth before a password is set
    if is_setup_path && !client::has_password().unwrap_or(true) {
        return next.run(req).await;
    }

    let has_password = client::has_password().unwrap_or(false);
    if !has_password {
        return axum::response::Redirect::to("/setup").into_response();
    }

    let cookie_header = req.headers().get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let session = cookie_header.split(';')
        .filter_map(|s| {
            let s = s.trim();
            s.strip_prefix("session=")
        })
        .next()
        .unwrap_or("")
        .to_string();

    if !client::verify_session(&session).unwrap_or(false) {
        return axum::response::Redirect::to("/login").into_response();
    }

    // Rolling refresh: update LAST_ACTIVE timestamp
    let mut response = next.run(req).await;
    if let Ok(refreshed) = client::refresh_session(&session) {
        if let Ok(hv) = axum::http::HeaderValue::from_str(
            &format!("session={}; HttpOnly; Secure; SameSite=Strict; Path=/", refreshed)
        ) {
            response.headers_mut().insert(axum::http::header::SET_COOKIE, hv);
        }
    }
    response
}

type RateLimitState = Arc<Mutex<lru::LruCache<IpAddr, (u32, Instant)>>>;

async fn rate_limit_middleware(
    axum::extract::State(rate_limit): axum::extract::State<RateLimitState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let path = req.uri().path().to_string();

    if !path.starts_with("/api/login") && !path.starts_with("/api/setup_password") {
        return next.run(req).await;
    }

    // Extract client IP from ConnectInfo extension (injected by TLS accept loop)
    let ip = req.extensions().get::<axum::extract::connect_info::ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());

    let ip = match ip {
        Some(ip) => ip,
        None => return next.run(req).await, // fail-open if no IP available
    };

    // Check cooldown for this IP
    {
        let mut state = rate_limit.lock().unwrap();
        if let Some((failures, last)) = state.get(&ip) {
            let failures = *failures;
            let last = *last;
            if failures > 0 {
                let shift = std::cmp::min(failures - 1, 63);
                let backoff_secs = std::cmp::min(1u64 << shift, 60);
                let elapsed = last.elapsed().as_secs();
                if elapsed < backoff_secs {
                    let remaining = backoff_secs - elapsed;
                    return (
                        axum::http::StatusCode::TOO_MANY_REQUESTS,
                        [(axum::http::header::RETRY_AFTER, remaining.to_string())],
                        format!("Too many attempts. Try again in {}s.", remaining),
                    ).into_response();
                }
            }
        }
    }

    let response = next.run(req).await;

    let status = response.status();
    {
        let mut state = rate_limit.lock().unwrap();
        if status.is_success() || status.is_redirection() {
            state.pop(&ip);
        } else {
            let entry = state.get_or_insert_mut(ip, || (0, Instant::now()));
            entry.0 = entry.0.saturating_add(1);
            entry.1 = Instant::now();
        }
    }

    response
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let conf = get_configuration(None).unwrap();
    let leptos_options = conf.leptos_options;
    let routes = generate_route_list(App);

    let rate_limit_state: RateLimitState = Arc::new(Mutex::new(
        lru::LruCache::new(std::num::NonZeroUsize::new(1000).unwrap()),
    ));

    let app = Router::new()
        .route("/style.css", axum::routing::get(serve_css))
        .route("/api/backup/config", axum::routing::post(handle_backup_config))
        .route("/api/restore/config", axum::routing::post(handle_restore_config))
        .leptos_routes(&leptos_options, routes, App)
        .layer(axum::middleware::from_fn(auth_middleware))
        .layer(axum::middleware::from_fn_with_state(
            rate_limit_state,
            rate_limit_middleware,
        ))
        .layer(axum::middleware::from_fn(csrf_middleware))
        .layer(axum::middleware::from_fn(host_validation_middleware))
        .layer(axum::middleware::from_fn(security_headers_middleware))
        .with_state(leptos_options);

    // Load TLS cert from agent
    let (cert_pem, key_pem) = client::get_tls_config()
        .expect("failed to get TLS config from agent");

    // Parse certs for rustls
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .filter_map(|c| c.ok())
        .collect();
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .expect("failed to parse TLS key")
        .expect("no private key found");

    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("invalid TLS config");
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(tls_config));

    // HTTPS on port 8443 (nftables redirects 443 -> 8443)
    let https_addr = std::net::SocketAddr::from(([0, 0, 0, 0], 8443));
    let https_app = app.clone();
    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(https_addr).await.unwrap();
        loop {
            let (stream, addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => continue,
            };
            let acceptor = tls_acceptor.clone();
            let app = https_app.clone();
            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(stream).await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let io = hyper_util::rt::TokioIo::new(tls_stream);
                let svc = hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
                    let mut router = app.clone().into_service();
                    async move {
                        req.extensions_mut().insert(
                            axum::extract::connect_info::ConnectInfo(addr),
                        );
                        Service::call(&mut router, req).await
                    }
                });
                let builder = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
                let conn = builder.serve_connection(io, svc);
                let _ = conn.await;
            });
        }
    });

    // HTTP on port 8080 -- redirect to HTTPS (nftables redirects 80 -> 8080)
    let redirect_app = Router::new().fallback(
        |req: axum::extract::Request| async move {
            let host = req.headers()
                .get(axum::http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("hermitshell.local");
            // Strip port if present (e.g., "192.168.1.1:8080" → "192.168.1.1")
            let host = host.split(':').next().unwrap_or(host);
            axum::response::Redirect::permanent(&format!("https://{host}/"))
        },
    );
    let http_addr = std::net::SocketAddr::from(([0, 0, 0, 0], 8080));
    let listener = tokio::net::TcpListener::bind(&http_addr).await.unwrap();
    println!("Listening on https://{} and http://{}", https_addr, http_addr);
    axum::serve(listener, redirect_app.into_make_service()).await.unwrap();
}
