use leptos::prelude::*;

/// Redirect `/settings` to `/settings/network`.
#[component]
pub fn Settings() -> impl IntoView {
    leptos_axum::redirect("/settings/network");
}
