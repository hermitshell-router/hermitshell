use leptos::*;
use crate::client;
use crate::components::layout::Layout;
use crate::format_uptime;

#[component]
pub fn Settings() -> impl IntoView {
    let data = create_resource(
        || (),
        |_| async { client::get_status() },
    );
    let reservations = create_resource(
        || (),
        |_| async { client::list_dhcp_reservations() },
    );

    view! {
        <Layout title="Settings" active_page="settings">
            <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                {move || data.get().map(|result| match result {
                    Ok(status) => {
                        let uptime = format_uptime(status.uptime_secs);
                        let device_count = status.device_count;
                        let ad_blocking_text = if status.ad_blocking_enabled { "Enabled" } else { "Disabled" };

                        view! {
                            <div class="settings-section">
                                <h3>"System"</h3>
                                <div class="settings-row">
                                    <span class="settings-label">"Agent Uptime"</span>
                                    <span class="settings-value">{uptime}</span>
                                </div>
                                <div class="settings-row">
                                    <span class="settings-label">"Total Devices"</span>
                                    <span class="settings-value">{device_count}</span>
                                </div>
                                <div class="settings-row">
                                    <span class="settings-label">"Ad Blocking"</span>
                                    <span class="settings-value">{ad_blocking_text}</span>
                                </div>
                            </div>

                            <div class="settings-section">
                                <h3>"Backup & Restore"</h3>
                                <div class="actions-bar">
                                    <a href="/api/backup/config" class="btn btn-primary btn-sm">"Download Config (JSON)"</a>
                                </div>
                            </div>

                            <div class="settings-section">
                                <h3>"About"</h3>
                                <div class="settings-row">
                                    <span class="settings-label">"Software"</span>
                                    <span class="settings-value">"HermitShell"</span>
                                </div>
                                <div class="settings-row">
                                    <span class="settings-label">"Version"</span>
                                    <span class="settings-value">"0.1.0"</span>
                                </div>
                            </div>
                        }.into_view()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_view(),
                })}
            </Suspense>

            <Suspense fallback=move || view! { <p>"Loading reservations..."</p> }>
                {move || reservations.get().map(|result| match result {
                    Ok(res) => {
                        view! {
                            <div class="settings-section">
                                <h3>"DHCP Reservations"</h3>
                                <table class="data-table">
                                    <thead>
                                        <tr>
                                            <th>"MAC Address"</th>
                                            <th>"Subnet ID"</th>
                                            <th>"Actions"</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {res.iter().map(|r| {
                                            let mac = r.mac.clone();
                                            view! {
                                                <tr>
                                                    <td>{r.mac.clone()}</td>
                                                    <td>{r.subnet_id}</td>
                                                    <td>
                                                        <form method="post" action="/api/remove-reservation" style="display:inline">
                                                            <input type="hidden" name="mac" value={mac} />
                                                            <button type="submit" class="btn btn-danger btn-sm">"Remove"</button>
                                                        </form>
                                                    </td>
                                                </tr>
                                            }
                                        }).collect_view()}
                                    </tbody>
                                </table>
                            </div>
                        }.into_view()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_view(),
                })}
            </Suspense>
        </Layout>
    }
}
