use leptos::*;
use crate::client;
use crate::components::layout::Layout;

#[component]
pub fn Dns() -> impl IntoView {
    let data = create_resource(
        || (),
        |_| async { client::get_status() },
    );

    view! {
        <Layout title="DNS & Ad Blocking" active_page="dns">
            <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                {move || data.get().map(|result| match result {
                    Ok(status) => {
                        let enabled = status.ad_blocking_enabled;
                        let status_text = if enabled { "Enabled" } else { "Disabled" };
                        let status_class = if enabled { "card-value success" } else { "card-value warning" };
                        let toggle_value = if enabled { "false" } else { "true" };
                        let toggle_label = if enabled { "Disable" } else { "Enable" };

                        view! {
                            <div class="settings-section">
                                <h3>"Ad Blocking"</h3>
                                <div class="settings-row">
                                    <span class="settings-label">"Status"</span>
                                    <span class={status_class}>{status_text}</span>
                                </div>
                                <div class="settings-row">
                                    <span class="settings-label">"DNS Provider"</span>
                                    <span class="settings-value">"Blocky"</span>
                                </div>
                                <div class="settings-row">
                                    <span class="settings-label">"Toggle"</span>
                                    <form method="post" action="/api/ad-blocking" style="display:inline">
                                        <input type="hidden" name="enabled" value={toggle_value} />
                                        <button type="submit" class="btn btn-sm">{toggle_label}</button>
                                    </form>
                                </div>
                            </div>

                            <div class="settings-section">
                                <h3>"Block Lists"</h3>
                                <div class="settings-row">
                                    <span class="settings-label">"StevenBlack Hosts"</span>
                                    <span class="settings-value">"Active"</span>
                                </div>
                                <div class="settings-row">
                                    <span class="settings-label">"Custom Blocklist"</span>
                                    <span class="settings-value">"Active"</span>
                                </div>
                            </div>
                        }.into_view()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_view(),
                })}
            </Suspense>
        </Layout>
    }
}
