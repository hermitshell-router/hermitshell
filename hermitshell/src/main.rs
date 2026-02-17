use axum::response::IntoResponse;
use axum::extract::Form;
use axum::Router;
use leptos::*;
use leptos_axum::{generate_route_list, LeptosRoutes};
use serde::Deserialize;

use hermitshell_ui::App;
use hermitshell_ui::client;

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::SaltString;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use rand::Rng;

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

fn get_session_secret() -> String {
    match client::get_config("session_secret") {
        Ok(Some(s)) => s,
        _ => {
            let secret: String = hex::encode(rand::thread_rng().r#gen::<[u8; 32]>());
            let _ = client::set_config("session_secret", &secret);
            secret
        }
    }
}

fn make_session_cookie(secret: &str) -> String {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let payload = format!("admin:{}", timestamp);
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(payload.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());
    format!("{}.{}", payload, sig)
}

fn verify_session_cookie(cookie: &str, secret: &str) -> bool {
    let parts: Vec<&str> = cookie.rsplitn(2, '.').collect();
    if parts.len() != 2 { return false; }
    let (sig, payload) = (parts[0], parts[1]);
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(payload.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());
    sig == expected
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
    if form.password != form.confirm || form.password.len() < 8 {
        return axum::response::Redirect::to("/setup").into_response();
    }
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    let hash = Argon2::default()
        .hash_password(form.password.as_bytes(), &salt)
        .unwrap().to_string();
    let _ = client::set_config("admin_password_hash", &hash);
    axum::response::Redirect::to("/login").into_response()
}

async fn handle_login(Form(form): Form<LoginForm>) -> impl IntoResponse {
    let hash = match client::get_config("admin_password_hash") {
        Ok(Some(h)) => h,
        _ => return axum::response::Redirect::to("/setup").into_response(),
    };
    let parsed = match PasswordHash::new(&hash) {
        Ok(p) => p,
        Err(_) => return axum::response::Redirect::to("/login").into_response(),
    };
    if Argon2::default().verify_password(form.password.as_bytes(), &parsed).is_err() {
        return axum::response::Redirect::to("/login").into_response();
    }
    let secret = get_session_secret();
    let cookie = make_session_cookie(&secret);
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

    // Exempt paths
    if path == "/login" || path == "/api/login" || path == "/setup" || path == "/api/setup" || path == "/style.css" {
        return next.run(req).await;
    }

    // Check if setup is needed
    let has_password = client::get_config("admin_password_hash")
        .ok().flatten().is_some();
    if !has_password {
        return axum::response::Redirect::to("/setup").into_response();
    }

    // Verify session cookie
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

    let secret = get_session_secret();
    if verify_session_cookie(session, &secret) {
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
        .leptos_routes(&leptos_options, routes, App)
        .layer(axum::middleware::from_fn(auth_middleware))
        .with_state(leptos_options);

    // Load or generate TLS cert
    let (cert_pem, key_pem) = match (
        client::get_config("tls_cert_pem"),
        client::get_config("tls_key_pem"),
    ) {
        (Ok(Some(cert)), Ok(Some(key))) => (cert, key),
        _ => {
            let cert = rcgen::generate_simple_self_signed(vec![
                "hermitshell.local".to_string(),
                "10.0.0.1".to_string(),
            ]).expect("cert generation failed");
            let cert_pem = cert.cert.pem();
            let key_pem = cert.key_pair.serialize_pem();
            let _ = client::set_config("tls_cert_pem", &cert_pem);
            let _ = client::set_config("tls_key_pem", &key_pem);
            (cert_pem, key_pem)
        }
    };

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
