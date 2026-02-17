pub mod client;
pub mod components;
pub mod pages;
pub mod types;

use leptos::*;
use leptos_router::*;

use pages::dashboard::Dashboard;
use pages::device_detail::DeviceDetail;
use pages::devices::DeviceList;
use pages::dns::Dns;
use pages::groups::Groups;
use pages::settings::Settings;
use pages::traffic::Traffic;
use pages::wireguard::Wireguard;

#[component]
pub fn App() -> impl IntoView {
    view! {
        <Router>
            <main>
                <Routes>
                    <Route path="/" view=Dashboard />
                    <Route path="/devices" view=DeviceList />
                    <Route path="/devices/:mac" view=DeviceDetail />
                    <Route path="/groups" view=Groups />
                    <Route path="/traffic" view=Traffic />
                    <Route path="/dns" view=Dns />
                    <Route path="/wireguard" view=Wireguard />
                    <Route path="/settings" view=Settings />
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
