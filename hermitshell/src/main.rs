use axum::response::IntoResponse;
use axum::extract::Form;
use axum::Router;
use leptos::*;
use leptos_axum::{generate_route_list, LeptosRoutes};
use serde::Deserialize;

use hermitshell_ui::App;
use hermitshell_ui::client;

const STYLE_CSS: &str = include_str!("../../hermitshell-ui/style/style.css");

async fn serve_css() -> impl IntoResponse {
    ([("content-type", "text/css")], STYLE_CSS)
}

#[derive(Deserialize)]
struct ApproveForm {
    mac: String,
    group: String,
}

#[derive(Deserialize)]
struct DeviceForm {
    mac: String,
}

#[derive(Deserialize)]
struct SetGroupForm {
    mac: String,
    group: String,
    redirect: Option<String>,
}

#[derive(Deserialize)]
struct AdBlockingForm {
    enabled: String,
}

#[derive(Deserialize)]
struct LoginForm {
    password: String,
}

#[derive(Deserialize)]
struct SetupForm {
    password: String,
    confirm: String,
}

async fn handle_ad_blocking(Form(form): Form<AdBlockingForm>) -> impl IntoResponse {
    let enabled = form.enabled == "true";
    let _ = client::set_ad_blocking(enabled);
    axum::response::Redirect::to("/")
}

async fn handle_set_group(Form(form): Form<SetGroupForm>) -> impl IntoResponse {
    let _ = client::set_device_group(&form.mac, &form.group);
    let redirect = form.redirect
        .filter(|r| r.starts_with('/') && !r.starts_with("//"))
        .unwrap_or_else(|| "/devices".to_string());
    axum::response::Redirect::to(&redirect)
}

async fn handle_approve(Form(form): Form<ApproveForm>) -> impl IntoResponse {
    let _ = client::set_device_group(&form.mac, &form.group);
    axum::response::Redirect::to("/devices")
}

async fn handle_block(Form(form): Form<DeviceForm>) -> impl IntoResponse {
    let _ = client::block_device(&form.mac);
    axum::response::Redirect::to("/devices")
}

async fn handle_unblock(Form(form): Form<DeviceForm>) -> impl IntoResponse {
    let _ = client::unblock_device(&form.mac);
    axum::response::Redirect::to("/devices")
}

async fn handle_setup(Form(form): Form<SetupForm>) -> impl IntoResponse {
    if form.password != form.confirm || form.password.len() < 8 || form.password.len() > 128 {
        return axum::response::Redirect::to("/setup").into_response();
    }
    match client::setup_password(&form.password, None) {
        Ok(()) => axum::response::Redirect::to("/login").into_response(),
        Err(_) => axum::response::Redirect::to("/setup").into_response(),
    }
}

async fn handle_login(Form(form): Form<LoginForm>) -> impl IntoResponse {
    match client::verify_password(&form.password) {
        Ok(true) => {}
        _ => return axum::response::Redirect::to("/login").into_response(),
    }
    let cookie = match client::create_session() {
        Ok(c) => c,
        Err(_) => return axum::response::Redirect::to("/login").into_response(),
    };
    let mut response = axum::response::Redirect::to("/").into_response();
    response.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        format!("session={}; HttpOnly; SameSite=Strict; Path=/", cookie).parse().unwrap(),
    );
    response
}

async fn handle_logout() -> impl IntoResponse {
    let mut response = axum::response::Redirect::to("/login").into_response();
    response.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        "session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0".parse().unwrap(),
    );
    response
}

#[derive(Deserialize)]
struct PortForwardForm {
    protocol: String,
    external_port_start: u16,
    external_port_end: u16,
    internal_ip: String,
    internal_port: u16,
    description: String,
}

#[derive(Deserialize)]
struct PortForwardIdForm {
    id: i64,
}

#[derive(Deserialize)]
struct ReservationForm {
    mac: String,
}

async fn handle_add_port_forward(Form(form): Form<PortForwardForm>) -> impl IntoResponse {
    let _ = client::add_port_forward(&form.protocol, form.external_port_start, form.external_port_end, &form.internal_ip, form.internal_port, &form.description);
    axum::response::Redirect::to("/port-forwarding")
}

async fn handle_remove_port_forward(Form(form): Form<PortForwardIdForm>) -> impl IntoResponse {
    let _ = client::remove_port_forward(form.id);
    axum::response::Redirect::to("/port-forwarding")
}

async fn handle_set_reservation(Form(form): Form<ReservationForm>) -> impl IntoResponse {
    let _ = client::set_dhcp_reservation(&form.mac, None);
    axum::response::Redirect::to("/settings")
}

async fn handle_remove_reservation(Form(form): Form<ReservationForm>) -> impl IntoResponse {
    let _ = client::remove_dhcp_reservation(&form.mac);
    axum::response::Redirect::to("/settings")
}

#[derive(Deserialize)]
struct LogConfigForm {
    log_format: String,
    syslog_target: String,
    webhook_url: String,
    webhook_secret: String,
    log_retention_days: String,
}

#[derive(Deserialize)]
struct RunZeroConfigForm {
    runzero_url: String,
    runzero_token: String,
    runzero_sync_interval: String,
    runzero_enabled: String,
}

#[derive(Deserialize)]
struct AlertIdForm {
    id: i64,
}

async fn handle_set_runzero_config(Form(form): Form<RunZeroConfigForm>) -> impl IntoResponse {
    let mut config = serde_json::json!({
        "runzero_url": form.runzero_url,
        "runzero_sync_interval": form.runzero_sync_interval,
        "runzero_enabled": form.runzero_enabled,
    });
    if !form.runzero_token.is_empty() {
        config["runzero_token"] = serde_json::Value::String(form.runzero_token);
    }
    let _ = client::set_runzero_config(&config);
    axum::response::Redirect::to("/settings")
}

async fn handle_sync_runzero() -> impl IntoResponse {
    let _ = client::sync_runzero();
    axum::response::Redirect::to("/settings")
}

async fn handle_acknowledge_alert(Form(form): Form<AlertIdForm>) -> impl IntoResponse {
    let _ = client::acknowledge_alert(form.id);
    axum::response::Redirect::to("/alerts")
}

async fn handle_acknowledge_all_alerts() -> impl IntoResponse {
    let _ = client::acknowledge_all_alerts(None);
    axum::response::Redirect::to("/alerts")
}

async fn handle_set_log_config(Form(form): Form<LogConfigForm>) -> impl IntoResponse {
    let config = serde_json::json!({
        "log_format": form.log_format,
        "syslog_target": form.syslog_target,
        "webhook_url": form.webhook_url,
        "webhook_secret": form.webhook_secret,
        "log_retention_days": form.log_retention_days,
    });
    let _ = client::set_log_config(&config);
    axum::response::Redirect::to("/settings")
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

    if path == "/login" || path == "/api/login" || path == "/setup" || path == "/api/setup" || path == "/style.css" {
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
        .unwrap_or("");

    if client::verify_session(session).unwrap_or(false) {
        next.run(req).await
    } else {
        axum::response::Redirect::to("/login").into_response()
    }
}

#[tokio::main]
async fn main() {
    let conf = get_configuration(None).await.unwrap();
    let leptos_options = conf.leptos_options;
    let routes = generate_route_list(App);

    let app = Router::new()
        .route("/style.css", axum::routing::get(serve_css))
        .route("/api/setup", axum::routing::post(handle_setup))
        .route("/api/login", axum::routing::post(handle_login))
        .route("/api/logout", axum::routing::post(handle_logout))
        .route("/api/ad-blocking", axum::routing::post(handle_ad_blocking))
        .route("/api/set-group", axum::routing::post(handle_set_group))
        .route("/api/approve", axum::routing::post(handle_approve))
        .route("/api/block", axum::routing::post(handle_block))
        .route("/api/unblock", axum::routing::post(handle_unblock))
        .route("/api/add-port-forward", axum::routing::post(handle_add_port_forward))
        .route("/api/remove-port-forward", axum::routing::post(handle_remove_port_forward))
        .route("/api/set-reservation", axum::routing::post(handle_set_reservation))
        .route("/api/remove-reservation", axum::routing::post(handle_remove_reservation))
        .route("/api/backup/config", axum::routing::get(handle_backup_config))
        .route("/api/set-log-config", axum::routing::post(handle_set_log_config))
        .route("/api/set-runzero-config", axum::routing::post(handle_set_runzero_config))
        .route("/api/sync-runzero", axum::routing::post(handle_sync_runzero))
        .route("/api/acknowledge-alert", axum::routing::post(handle_acknowledge_alert))
        .route("/api/acknowledge-all-alerts", axum::routing::post(handle_acknowledge_all_alerts))
        .leptos_routes(&leptos_options, routes, App)
        .layer(axum::middleware::from_fn(auth_middleware))
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

    let tls_config = axum_server::tls_rustls::RustlsConfig::from_der(
        certs.into_iter().map(|c| c.to_vec()).collect(),
        key.secret_der().to_vec(),
    ).await.expect("invalid TLS config");

    // HTTPS on port 443
    let https_addr = std::net::SocketAddr::from(([0, 0, 0, 0], 443));
    let https_app = app.clone();
    tokio::spawn(async move {
        axum_server::bind_rustls(https_addr, tls_config)
            .serve(https_app.into_make_service())
            .await
            .unwrap();
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
