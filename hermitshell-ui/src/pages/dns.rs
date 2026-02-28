use leptos::prelude::*;
use crate::client;
use crate::components::layout::Layout;
use crate::components::toast::ErrorToast;
use crate::server_fns::ToggleAdBlocking;

#[component]
pub fn Dns() -> impl IntoView {
    let data = Resource::new(
        || (),
        |_| async { client::get_status() },
    );
    let dns_config = Resource::new(
        || (),
        |_| async { client::get_dns_config() },
    );
    let blocklists = Resource::new(
        || (),
        |_| async { client::list_dns_blocklists() },
    );
    let forwards = Resource::new(
        || (),
        |_| async { client::list_dns_forwards() },
    );
    let rules = Resource::new(
        || (),
        |_| async { client::list_dns_rules() },
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

                        let ad_action = ServerAction::<ToggleAdBlocking>::new();

                        view! {
                            <div class="settings-section">
                                <h3>"Ad Blocking"</h3>
                                <div class="settings-row">
                                    <span class="settings-label">"Status"</span>
                                    <span class={status_class}>{status_text}</span>
                                </div>
                                <div class="settings-row">
                                    <span class="settings-label">"DNS Resolver"</span>
                                    <span class="settings-value">"Unbound (recursive, DNSSEC)"</span>
                                </div>
                                <div class="settings-row">
                                    <span class="settings-label">"Toggle"</span>
                                    <ActionForm action=ad_action attr:style="display:inline">
                                        <input type="hidden" name="enabled" value={toggle_value} />
                                        <button type="submit" class="btn btn-sm">{toggle_label}</button>
                                    </ActionForm>
                                </div>
                                <ErrorToast value=ad_action.value() />
                            </div>
                        }.into_any()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                })}
            </Suspense>

            // DNS Config (rate limits)
            <Suspense fallback=move || view! { <p>"Loading DNS config..."</p> }>
                {move || dns_config.get().map(|result| match result {
                    Ok(config) => {
                        let upstream = config.get("upstream_dns")
                            .and_then(|v| v.as_str())
                            .unwrap_or("auto")
                            .to_string();
                        let mode = if upstream == "auto" { "Recursive (DNSSEC enabled)".to_string() } else { format!("Forwarding to {}", upstream) };
                        let per_client = config.get("ratelimit_per_client")
                            .and_then(|v| v.as_str())
                            .unwrap_or("0")
                            .to_string();
                        let per_domain = config.get("ratelimit_per_domain")
                            .and_then(|v| v.as_str())
                            .unwrap_or("0")
                            .to_string();

                        view! {
                            <div class="settings-section">
                                <h3>"DNS Configuration"</h3>
                                <div class="settings-row">
                                    <span class="settings-label">"Mode"</span>
                                    <span class="settings-value">{mode}</span>
                                </div>
                                <div class="settings-row">
                                    <span class="settings-label">"Rate Limit (per client)"</span>
                                    <span class="settings-value">{per_client}" qps"</span>
                                </div>
                                <div class="settings-row">
                                    <span class="settings-label">"Rate Limit (per domain)"</span>
                                    <span class="settings-value">{per_domain}" qps"</span>
                                </div>
                            </div>
                        }.into_any()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                })}
            </Suspense>

            // Blocklists
            <Suspense fallback=move || view! { <p>"Loading blocklists..."</p> }>
                {move || blocklists.get().map(|result| match result {
                    Ok(lists) => {
                        view! {
                            <div class="settings-section">
                                <h3>"Block Lists"</h3>
                                {if lists.is_empty() {
                                    view! { <p class="settings-empty">"No blocklists configured"</p> }.into_any()
                                } else {
                                    lists.into_iter().map(|bl| {
                                        let status = if bl.enabled { "Active" } else { "Disabled" };
                                        let status_class = if bl.enabled { "settings-value success" } else { "settings-value warning" };
                                        view! {
                                            <div class="settings-row">
                                                <span class="settings-label">{bl.name}</span>
                                                <span class={status_class}>{status}</span>
                                            </div>
                                        }
                                    }).collect_view().into_any()
                                }}
                            </div>
                        }.into_any()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                })}
            </Suspense>

            // Forward Zones
            <Suspense fallback=move || view! { <p>"Loading forward zones..."</p> }>
                {move || forwards.get().map(|result| match result {
                    Ok(zones) => {
                        view! {
                            <div class="settings-section">
                                <h3>"Forward Zones"</h3>
                                {if zones.is_empty() {
                                    view! { <p class="settings-empty">"No forward zones configured"</p> }.into_any()
                                } else {
                                    zones.into_iter().map(|fz| {
                                        view! {
                                            <div class="settings-row">
                                                <span class="settings-label">{fz.domain}</span>
                                                <span class="settings-value">{fz.forward_addr}</span>
                                            </div>
                                        }
                                    }).collect_view().into_any()
                                }}
                            </div>
                        }.into_any()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                })}
            </Suspense>

            // Custom DNS Rules
            <Suspense fallback=move || view! { <p>"Loading custom rules..."</p> }>
                {move || rules.get().map(|result| match result {
                    Ok(rules) => {
                        view! {
                            <div class="settings-section">
                                <h3>"Custom DNS Rules"</h3>
                                {if rules.is_empty() {
                                    view! { <p class="settings-empty">"No custom rules configured"</p> }.into_any()
                                } else {
                                    rules.into_iter().map(|rule| {
                                        let label = format!("{} ({})", rule.domain, rule.record_type);
                                        view! {
                                            <div class="settings-row">
                                                <span class="settings-label">{label}</span>
                                                <span class="settings-value">{rule.value}</span>
                                            </div>
                                        }
                                    }).collect_view().into_any()
                                }}
                            </div>
                        }.into_any()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                })}
            </Suspense>
        </Layout>
    }
}
