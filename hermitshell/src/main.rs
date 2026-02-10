mod client;

use axum::Router;
use leptos::*;
use leptos_axum::{generate_route_list, LeptosRoutes};
use leptos_router::*;

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
                Ok(s) => view! {
                    <div>
                        <p>"Devices: " {s.device_count}</p>
                        <p>"Uptime: " {s.uptime_secs} " seconds"</p>
                    </div>
                }.into_view(),
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
                                <th>"RX"</th>
                                <th>"TX"</th>
                            </tr>
                        </thead>
                        <tbody>
                            {devs.into_iter().map(|d| view! {
                                <tr>
                                    <td>{d.mac}</td>
                                    <td>{d.ip.unwrap_or_default()}</td>
                                    <td>{d.hostname.unwrap_or_default()}</td>
                                    <td>{format_bytes(d.rx_bytes)}</td>
                                    <td>{format_bytes(d.tx_bytes)}</td>
                                </tr>
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

#[tokio::main]
async fn main() {
    let conf = get_configuration(None).await.unwrap();
    let leptos_options = conf.leptos_options;
    let addr = leptos_options.site_addr;
    let routes = generate_route_list(App);

    let app = Router::new()
        .leptos_routes(&leptos_options, routes, App)
        .with_state(leptos_options);

    println!("Listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app.into_make_service()).await.unwrap();
}
