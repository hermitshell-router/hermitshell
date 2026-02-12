mod client;

use axum::response::IntoResponse;
use axum::extract::Form;
use axum::Router;
use leptos::*;
use leptos_axum::{generate_route_list, LeptosRoutes};
use leptos_router::*;
use serde::Deserialize;

#[component]
fn App() -> impl IntoView {
    view! {
        <Router>
            <main>
                <Routes>
                    <Route path="/" view=Dashboard />
                    <Route path="/devices" view=DeviceList />
                </Routes>
            </main>
        </Router>
    }
}

#[component]
fn Dashboard() -> impl IntoView {
    let status = create_resource(
        || (),
        |_| async { client::get_status() }
    );

    view! {
        <h1>"HermitShell Dashboard"</h1>
        <nav><a href="/devices">"View Devices"</a></nav>
        <Suspense fallback=move || view! { <p>"Loading..."</p> }>
            {move || status.get().map(|result| match result {
                Ok(s) => {
                    let blocking_text = if s.ad_blocking_enabled { "Enabled" } else { "Disabled" };
                    view! {
                        <div>
                            <p>"Devices: " {s.device_count}</p>
                            <p>"Uptime: " {s.uptime_secs} " seconds"</p>
                            <p>"Ad Blocking: " {blocking_text}</p>
                            <form method="post" action="/api/ad-blocking">
                                <input type="hidden" name="enabled" value={if s.ad_blocking_enabled { "false" } else { "true" }} />
                                <button type="submit">{if s.ad_blocking_enabled { "Disable Ad Blocking" } else { "Enable Ad Blocking" }}</button>
                            </form>
                        </div>
                    }.into_view()
                },
                Err(e) => view! { <p class="error">"Error: " {e}</p> }.into_view(),
            })}
        </Suspense>
    }
}

#[component]
fn DeviceList() -> impl IntoView {
    let devices = create_resource(
        || (),
        |_| async { client::list_devices() }
    );

    view! {
        <h1>"Devices"</h1>
        <nav><a href="/">"Dashboard"</a></nav>
        <Suspense fallback=move || view! { <p>"Loading..."</p> }>
            {move || devices.get().map(|result| match result {
                Ok(devs) => view! {
                    <table>
                        <thead>
                            <tr>
                                <th>"MAC"</th>
                                <th>"IP"</th>
                                <th>"Hostname"</th>
                                <th>"Group"</th>
                                <th>"RX"</th>
                                <th>"TX"</th>
                                <th>"Actions"</th>
                            </tr>
                        </thead>
                        <tbody>
                            {devs.into_iter().map(|d| {
                                let mac = d.mac.clone();
                                let group = d.device_group.clone();
                                let actions = if group == "quarantine" {
                                    view! {
                                        <form method="post" action="/api/approve">
                                            <input type="hidden" name="mac" value={mac.clone()} />
                                            <select name="group">
                                                <option value="trusted">"Trusted"</option>
                                                <option value="iot">"IoT"</option>
                                                <option value="guest">"Guest"</option>
                                                <option value="servers">"Servers"</option>
                                            </select>
                                            <button type="submit">"Approve"</button>
                                        </form>
                                    }.into_view()
                                } else if group == "blocked" {
                                    view! {
                                        <form method="post" action="/api/unblock">
                                            <input type="hidden" name="mac" value={mac.clone()} />
                                            <button type="submit">"Unblock"</button>
                                        </form>
                                    }.into_view()
                                } else {
                                    view! {
                                        <form method="post" action="/api/block">
                                            <input type="hidden" name="mac" value={mac.clone()} />
                                            <button type="submit">"Block"</button>
                                        </form>
                                    }.into_view()
                                };
                                view! {
                                    <tr>
                                        <td>{d.mac}</td>
                                        <td>{d.ip.unwrap_or_default()}</td>
                                        <td>{d.hostname.unwrap_or_default()}</td>
                                        <td>{d.device_group}</td>
                                        <td>{format_bytes(d.rx_bytes)}</td>
                                        <td>{format_bytes(d.tx_bytes)}</td>
                                        <td>{actions}</td>
                                    </tr>
                                }
                            }).collect_view()}
                        </tbody>
                    </table>
                }.into_view(),
                Err(e) => view! { <p class="error">"Error: " {e}</p> }.into_view(),
            })}
        </Suspense>
    }
}

fn format_bytes(bytes: i64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
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
struct AdBlockingForm {
    enabled: String,
}

async fn handle_ad_blocking(Form(form): Form<AdBlockingForm>) -> impl IntoResponse {
    let enabled = form.enabled == "true";
    let _ = client::set_ad_blocking(enabled);
    axum::response::Redirect::to("/")
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
        .route("/api/ad-blocking", axum::routing::post(handle_ad_blocking))
        .route("/api/approve", axum::routing::post(handle_approve))
        .route("/api/block", axum::routing::post(handle_block))
        .route("/api/unblock", axum::routing::post(handle_unblock))
        .leptos_routes(&leptos_options, routes, App)
        .with_state(leptos_options);

    println!("Listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app.into_make_service()).await.unwrap();
}
