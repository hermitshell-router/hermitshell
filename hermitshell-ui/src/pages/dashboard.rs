use leptos::prelude::*;
use crate::client;
use crate::charts;
use crate::components::layout::Layout;
use crate::components::stat_card::StatCard;
use crate::components::toast::ErrorToast;
use crate::server_fns::{ToggleAdBlocking, DismissTotpNudge};
use crate::types::{Device, Status};
use crate::{format_bytes, format_uptime};

#[component]
pub fn Dashboard() -> impl IntoView {
    let data = Resource::new(
        || (),
        |_| async move {
            let status = client::get_status();
            let devices = client::list_devices();
            let guest = client::guest_network_status();
            (status, devices, guest)
        },
    );
    let totp_status = Resource::new(
        || (),
        |_| async { client::totp_status() },
    );
    let nudge_dismissed = Resource::new(
        || (),
        |_| async { client::get_config("totp_nudge_dismissed") },
    );

    view! {
        <Layout title="Dashboard" active_page="dashboard">
            // 2FA nudge banner
            <Suspense fallback=move || ()>
                {move || {
                    let totp_on = totp_status.get().and_then(|r| r.ok()).unwrap_or(false);
                    let dismissed = nudge_dismissed.get()
                        .and_then(|r| r.ok())
                        .flatten()
                        .map_or(false, |v| v == "true");
                    if !totp_on && !dismissed {
                        let dismiss_action = ServerAction::<DismissTotpNudge>::new();
                        view! {
                            <div class="alert-banner">
                                <span>"Protect your router with two-factor authentication."</span>
                                <div class="alert-banner-actions">
                                    <a href="/settings#two-factor" class="btn btn-sm btn-primary">"Enable in Settings"</a>
                                    <ActionForm action=dismiss_action>
                                        <button type="submit" class="btn btn-sm">"Dismiss"</button>
                                    </ActionForm>
                                </div>
                            </div>
                        }.into_any()
                    } else {
                        ().into_any()
                    }
                }}
            </Suspense>
            <Suspense fallback=move || view! { <p>"Loading dashboard..."</p> }>
                {move || data.get().map(|(status_result, devices_result, guest_result)| {
                    let guest_status = guest_result.unwrap_or(serde_json::json!({"enabled": false}));
                    match (status_result, devices_result) {
                        (Ok(status), Ok(devices)) => {
                            render_dashboard(status, devices, guest_status)
                        }
                        (Err(e), _) | (_, Err(e)) => {
                            view! {
                                <div class="error">
                                    <p>{format!("Error loading dashboard: {}", e)}</p>
                                </div>
                            }.into_any()
                        }
                    }
                })}
            </Suspense>
        </Layout>
    }
}

fn render_dashboard(status: Status, mut devices: Vec<Device>, guest_status: serde_json::Value) -> AnyView {
    let total = devices.len();
    let quarantined = devices.iter().filter(|d| d.device_group == "quarantine").count();
    let blocked = devices.iter().filter(|d| d.device_group == "blocked").count();
    let active = total - quarantined - blocked;
    let uptime = format_uptime(status.uptime_secs);
    let ad_blocking = status.ad_blocking_enabled;
    let ad_blocking_text = if ad_blocking { "Enabled" } else { "Disabled" };
    let ad_blocking_class = if ad_blocking { "success" } else { "warning" };
    let toggle_value = if ad_blocking { "false" } else { "true" };

    let ad_action = ServerAction::<ToggleAdBlocking>::new();

    let guest_enabled = guest_status["enabled"].as_bool().unwrap_or(false);
    let guest_ssid = guest_status["ssid_name"].as_str().unwrap_or("").to_string();
    let guest_count = devices.iter().filter(|d| d.device_group == "guest").count();

    devices.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
    let recent: Vec<Device> = devices.into_iter().take(5).collect();

    view! {
        <div class="card-grid">
            <StatCard label="Total Devices" value={total.to_string()} class="accent" />
            <StatCard label="Active" value={active.to_string()} class="success" />
            <StatCard label="Quarantined" value={quarantined.to_string()} class="warning" />
            <StatCard label="Blocked" value={blocked.to_string()} class="danger" />
            <StatCard label="Uptime" value={uptime} />
            <StatCard label="Ad Blocking" value={ad_blocking_text.to_string()} class={ad_blocking_class.to_string()} />
        </div>

        <div class="section">
            <h2 class="section-header">"Network Bandwidth (24h)"</h2>
            {match client::get_bandwidth_history(None, "24h") {
                Ok(history) => {
                    view! { <div inner_html={charts::bandwidth_chart(&history, 800, 120)}></div> }.into_any()
                }
                Err(e) => {
                    view! { <p class="error">{format!("Error loading bandwidth: {e}")}</p> }.into_any()
                }
            }}
        </div>

        <div class="actions-bar">
            <ActionForm action=ad_action>
                <input type="hidden" name="enabled" value={toggle_value} />
                <button type="submit" class={if ad_blocking { "btn btn-danger btn-sm" } else { "btn btn-primary btn-sm" }}>
                    {if ad_blocking { "Disable Ad Blocking" } else { "Enable Ad Blocking" }}
                </button>
            </ActionForm>
            <ErrorToast value=ad_action.value() />
        </div>

        {match client::get_dashboard_stats() {
            Ok(stats) => {
                let alerts_class = if stats.unacked_alerts > 0 { "danger" } else { "success" };
                let top_talkers = stats.top_talkers;
                view! {
                    <div class="card-grid">
                        <StatCard label="Connections (24h)" value={stats.connections_24h.to_string()} />
                        <StatCard label="DNS Queries (24h)" value={stats.dns_queries_24h.to_string()} />
                        <StatCard label="Unacked Alerts" value={stats.unacked_alerts.to_string()} class={alerts_class.to_string()} />
                    </div>

                    {if !top_talkers.is_empty() {
                        view! {
                            <h2 class="section-header">"Top Talkers (24h)"</h2>
                            <table>
                                <thead>
                                    <tr>
                                        <th>"Device"</th>
                                        <th>"Total"</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {top_talkers.into_iter().map(|t| {
                                        let display = t.hostname.unwrap_or_else(|| t.mac.clone());
                                        let link = format!("/devices/{}", t.mac);
                                        view! {
                                            <tr>
                                                <td><a href={link}>{display}</a></td>
                                                <td>{format_bytes(t.total_bytes)}</td>
                                            </tr>
                                        }
                                    }).collect_view()}
                                </tbody>
                            </table>
                        }.into_any()
                    } else {
                        view! { }.into_any()
                    }}
                }.into_any()
            }
            Err(e) => {
                view! { <p class="error">{format!("Error loading stats: {e}")}</p> }.into_any()
            }
        }}

        <div class="card">
            <h2 class="section-header">"Guest Network"</h2>
            {if guest_enabled {
                view! {
                    <div class="detail-grid">
                        <div class="detail-item">
                            <span class="detail-label">"SSID"</span>
                            <span class="detail-value">{guest_ssid}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">"Guests"</span>
                            <span class="detail-value">{guest_count.to_string()}</span>
                        </div>
                    </div>
                    <a href="/guest" class="btn btn-sm">"Manage \u{2192}"</a>
                }.into_any()
            } else {
                view! {
                    <p class="text-muted">"Not configured"</p>
                    <a href="/guest" class="btn btn-sm btn-primary">"Set Up \u{2192}"</a>
                }.into_any()
            }}
        </div>

        <h2 class="section-header">"Recent Devices"</h2>
        <div class="table-scroll">
            <table>
                <thead>
                    <tr>
                        <th>"Hostname"</th>
                        <th>"IP"</th>
                        <th>"Group"</th>
                        <th>"MAC"</th>
                    </tr>
                </thead>
                <tbody>
                    {recent.into_iter().map(|device| {
                        let hostname = device.hostname.clone().unwrap_or_else(|| "Unknown".to_string());
                        let ip = device.ipv4.clone().unwrap_or_else(|| "-".to_string());
                        let badge_class = format!("badge badge-{}", device.device_group);
                        let device_link = format!("/devices/{}", device.mac);
                        view! {
                            <tr>
                                <td><a href={device_link}>{hostname}</a></td>
                                <td>{ip}</td>
                                <td><span class={badge_class}>{device.device_group.clone()}</span></td>
                                <td><code>{device.mac.clone()}</code></td>
                            </tr>
                        }
                    }).collect_view()}
                </tbody>
            </table>
        </div>
    }.into_any()
}
