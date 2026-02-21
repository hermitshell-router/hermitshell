pub mod client;
pub mod components;
pub mod pages;
pub mod server_fns;
pub mod types;

use leptos::prelude::*;
use leptos_router::components::*;
use leptos_router::path;

use pages::alerts::Alerts;
use pages::dashboard::Dashboard;
use pages::device_detail::DeviceDetail;
use pages::devices::DeviceList;
use pages::dns::Dns;
use pages::groups::Groups;
use pages::login::Login;
use pages::settings::Settings;
use pages::setup::Setup;
use pages::traffic::Traffic;
use pages::port_forwarding::PortForwarding;
use pages::wireguard::Wireguard;

#[component]
pub fn App() -> impl IntoView {
    view! {
        <Router>
            <main>
                <Routes fallback=|| view! { <p>"Page not found."</p> }>
                    <Route path=path!("/") view=Dashboard />
                    <Route path=path!("/devices") view=DeviceList />
                    <Route path=path!("/devices/:mac") view=DeviceDetail />
                    <Route path=path!("/groups") view=Groups />
                    <Route path=path!("/traffic") view=Traffic />
                    <Route path=path!("/dns") view=Dns />
                    <Route path=path!("/alerts") view=Alerts />
                    <Route path=path!("/wireguard") view=Wireguard />
                    <Route path=path!("/port-forwarding") view=PortForwarding />
                    <Route path=path!("/settings") view=Settings />
                    <Route path=path!("/login") view=Login />
                    <Route path=path!("/setup") view=Setup />
                </Routes>
            </main>
        </Router>
    }
}

pub fn format_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    if days > 0 {
        format!("{}d {}h {}m", days, hours, minutes)
    } else if hours > 0 {
        format!("{}h {}m", hours, minutes)
    } else {
        format!("{}m", minutes)
    }
}

pub fn format_bytes(bytes: i64) -> String {
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
