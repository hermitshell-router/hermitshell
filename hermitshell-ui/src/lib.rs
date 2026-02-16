pub mod client;
pub mod components;
pub mod pages;
pub mod types;

use leptos::*;
use leptos_router::*;

use pages::dashboard::Dashboard;
use pages::devices::DeviceList;

#[component]
pub fn App() -> impl IntoView {
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
