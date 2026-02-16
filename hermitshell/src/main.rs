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

async fn handle_ad_blocking(Form(form): Form<AdBlockingForm>) -> impl IntoResponse {
    let enabled = form.enabled == "true";
    let _ = client::set_ad_blocking(enabled);
    axum::response::Redirect::to("/")
}

async fn handle_set_group(Form(form): Form<SetGroupForm>) -> impl IntoResponse {
    let _ = client::set_device_group(&form.mac, &form.group);
    let redirect = form.redirect.unwrap_or_else(|| "/devices".to_string());
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

#[tokio::main]
async fn main() {
    let conf = get_configuration(None).await.unwrap();
    let leptos_options = conf.leptos_options;
    let addr = leptos_options.site_addr;
    let routes = generate_route_list(App);

    let app = Router::new()
        .route("/style.css", axum::routing::get(serve_css))
        .route("/api/ad-blocking", axum::routing::post(handle_ad_blocking))
        .route("/api/set-group", axum::routing::post(handle_set_group))
        .route("/api/approve", axum::routing::post(handle_approve))
        .route("/api/block", axum::routing::post(handle_block))
        .route("/api/unblock", axum::routing::post(handle_unblock))
        .leptos_routes(&leptos_options, routes, App)
        .with_state(leptos_options);

    println!("Listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app.into_make_service()).await.unwrap();
}
