use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::response::IntoResponse;
use axum::Router;
use leptos::config::get_configuration;
use leptos_axum::{generate_route_list, LeptosRoutes};

use hermitshell_ui::App;
use hermitshell_ui::client;

const STYLE_CSS: &str = include_str!("../../hermitshell-ui/style/style.css");

async fn serve_css() -> impl IntoResponse {
    ([("content-type", "text/css")], STYLE_CSS)
}

async fn handle_backup_config() -> impl IntoResponse {
    match client::export_config() {
        Ok(data) => (
            [(axum::http::header::CONTENT_TYPE, "application/json"),
             (axum::http::header::CONTENT_DISPOSITION, "attachment; filename=hermitshell-config.json")],
            data
        ).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

async fn auth_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let path = req.uri().path().to_string();

    if path == "/login" || path == "/setup" || path == "/style.css"
        || path.starts_with("/api/login") || path.starts_with("/api/setup_password")
    {
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

type RateLimitState = Arc<Mutex<(u32, Option<Instant>)>>;

async fn rate_limit_middleware(
    axum::extract::State(rate_limit): axum::extract::State<RateLimitState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let path = req.uri().path().to_string();

    if !path.starts_with("/api/login") {
        return next.run(req).await;
    }

    // Check cooldown
    {
        let state = rate_limit.lock().unwrap();
        let (failures, last) = &*state;
        if *failures > 0 {
            if let Some(last) = last {
                let shift = std::cmp::min(*failures - 1, 63);
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
            *state = (0, None);
        } else {
            state.0 = state.0.saturating_add(1);
            state.1 = Some(Instant::now());
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

    let rate_limit_state: RateLimitState = Arc::new(Mutex::new((0, None)));

    let app = Router::new()
        .route("/style.css", axum::routing::get(serve_css))
        .route("/api/backup/config", axum::routing::get(handle_backup_config))
        .leptos_routes(&leptos_options, routes, App)
        .layer(axum::middleware::from_fn(auth_middleware))
        .layer(axum::middleware::from_fn_with_state(
            rate_limit_state,
            rate_limit_middleware,
        ))
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

    // HTTPS on port 443
    let https_addr = std::net::SocketAddr::from(([0, 0, 0, 0], 443));
    let https_app = app.clone();
    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(https_addr).await.unwrap();
        loop {
            let (stream, _addr) = match listener.accept().await {
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
                let service = hyper_util::service::TowerToHyperService::new(app);
                let builder = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
                let conn = builder.serve_connection(io, service);
                let _ = conn.await;
            });
        }
    });

    // HTTP on port 80 -- redirect to HTTPS
    let redirect_app = Router::new().fallback(|| async {
        axum::response::Redirect::permanent("https://hermitshell.local/")
    });
    let http_addr = std::net::SocketAddr::from(([0, 0, 0, 0], 80));
    let listener = tokio::net::TcpListener::bind(&http_addr).await.unwrap();
    println!("Listening on https://{} and http://{}", https_addr, http_addr);
    axum::serve(listener, redirect_app.into_make_service()).await.unwrap();
}
