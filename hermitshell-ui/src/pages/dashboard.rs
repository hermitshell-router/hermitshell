use leptos::*;
use crate::client;
use crate::components::layout::Layout;
use crate::components::stat_card::StatCard;
use crate::types::{Device, Status};

fn format_uptime(secs: u64) -> String {
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

#[component]
pub fn Dashboard() -> impl IntoView {
    let data = create_resource(
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
                            }.into_view()
                        }
                    }
                })}
            </Suspense>
        </Layout>
    }
}

fn render_dashboard(status: Status, mut devices: Vec<Device>) -> View {
    let total = devices.len();
    let active = devices.iter().filter(|d| d.device_group == "default").count();
    let quarantined = devices.iter().filter(|d| d.device_group == "quarantine").count();
    let blocked = devices.iter().filter(|d| d.device_group == "blocked").count();
    let uptime = format_uptime(status.uptime_secs);
    let ad_blocking = status.ad_blocking_enabled;
    let ad_blocking_text = if ad_blocking { "Enabled" } else { "Disabled" };
    let ad_blocking_class = if ad_blocking { "text-success" } else { "text-warning" };
    let toggle_value = if ad_blocking { "false" } else { "true" };
    let toggle_label = if ad_blocking { "Disable" } else { "Enable" };

    devices.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
    let recent: Vec<Device> = devices.into_iter().take(5).collect();

    view! {
        <div class="stats-grid">
            <StatCard label="Total Devices" value={total.to_string()} class="text-accent" />
            <StatCard label="Active" value={active.to_string()} class="text-success" />
            <StatCard label="Quarantined" value={quarantined.to_string()} class="text-warning" />
            <StatCard label="Blocked" value={blocked.to_string()} class="text-danger" />
            <StatCard label="Uptime" value={uptime} />
            <StatCard label="Ad Blocking" value={ad_blocking_text.to_string()} class={ad_blocking_class.to_string()} />
        </div>

        <div class="section">
            <div class="section-header">
                <h2>"Ad Blocking"</h2>
                <form method="post" action="/api/ad-blocking">
                    <input type="hidden" name="enabled" value={toggle_value} />
                    <button type="submit" class="btn btn-sm">{toggle_label}</button>
                </form>
            </div>
        </div>

        <div class="section">
            <h2>"Recent Devices"</h2>
            <table class="table">
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
                                <td><span class={badge_class}>{&device.device_group}</span></td>
                                <td><code>{&device.mac}</code></td>
                            </tr>
                        }
                    }).collect_view()}
                </tbody>
            </table>
        </div>
    }.into_view()
}
