use leptos::prelude::*;

#[component]
pub fn SettingsNav(#[prop(into)] active: String) -> impl IntoView {
    let tabs = [
        ("network", "Network", "/settings/network"),
        ("monitoring", "Monitoring", "/settings/monitoring"),
        ("system", "System", "/settings/system"),
    ];

    view! {
        <div class="settings-tabs">
            {tabs.iter().map(|(key, label, href)| {
                let class = if *key == active.as_str() { "active" } else { "" };
                view! { <a href={*href} class={class}>{*label}</a> }
            }).collect_view()}
        </div>
    }
}
