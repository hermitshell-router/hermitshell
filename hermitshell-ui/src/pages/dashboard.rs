use leptos::prelude::*;
use crate::client;
use crate::components::layout::Layout;
use crate::components::stat_card::StatCard;
use crate::types::{Device, Status};
use crate::format_uptime;

#[component]
pub fn Dashboard() -> impl IntoView {
    let data = Resource::new(
        || (),
        |_| async move {
            let status = client::get_status();
            let devices = client::list_devices();
            (status, devices)
        },
    );

    view! {
        <Layout title="Dashboard" active_page="dashboard">
            <Suspense fallback=move || view! { <p>"Loading dashboard..."</p> }>
                {move || data.get().map(|(status_result, devices_result)| {
                    match (status_result, devices_result) {
                        (Ok(status), Ok(devices)) => {
                            render_dashboard(status, devices)
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

fn render_dashboard(status: Status, mut devices: Vec<Device>) -> AnyView {
    let total = devices.len();
    let quarantined = devices.iter().filter(|d| d.device_group == "quarantine").count();
    let blocked = devices.iter().filter(|d| d.device_group == "blocked").count();
    let active = total - quarantined - blocked;
    let uptime = format_uptime(status.uptime_secs);
    let ad_blocking = status.ad_blocking_enabled;
    let ad_blocking_text = if ad_blocking { "Enabled" } else { "Disabled" };
    let ad_blocking_class = if ad_blocking { "success" } else { "warning" };
    let toggle_value = if ad_blocking { "false" } else { "true" };

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

        <div class="actions-bar">
            <form method="post" action="/api/ad-blocking">
                <input type="hidden" name="enabled" value={toggle_value} />
                <button type="submit" class={if ad_blocking { "btn btn-danger btn-sm" } else { "btn btn-primary btn-sm" }}>
                    {if ad_blocking { "Disable Ad Blocking" } else { "Enable Ad Blocking" }}
                </button>
            </form>
        </div>

        <h2 class="section-header">"Recent Devices"</h2>
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
                        let ip = device.ip.clone().unwrap_or_else(|| "-".to_string());
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
    }.into_any()
}
