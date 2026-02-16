use leptos::*;
use crate::client;
use crate::components::layout::Layout;
use crate::format_bytes;

#[component]
pub fn Traffic() -> impl IntoView {
    let data = create_resource(
        || (),
        |_| async { client::list_devices() },
    );

    view! {
        <Layout title="Traffic" active_page="traffic">
            <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                {move || data.get().map(|result| match result {
                    Ok(devices) => {
                        render_traffic(devices)
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_view(),
                })}
            </Suspense>
        </Layout>
    }
}

fn render_traffic(mut devices: Vec<crate::types::Device>) -> View {
    let total_rx: i64 = devices.iter().map(|d| d.rx_bytes).sum();
    let total_tx: i64 = devices.iter().map(|d| d.tx_bytes).sum();

    devices.sort_by(|a, b| {
        let total_b = b.rx_bytes + b.tx_bytes;
        let total_a = a.rx_bytes + a.tx_bytes;
        total_b.cmp(&total_a)
    });

    view! {
        <div class="card-grid">
            <div class="card">
                <div class="card-label">"Total Downloaded (RX)"</div>
                <div class="card-value">{format_bytes(total_rx)}</div>
            </div>
            <div class="card">
                <div class="card-label">"Total Uploaded (TX)"</div>
                <div class="card-value">{format_bytes(total_tx)}</div>
            </div>
        </div>

        <div class="section">
            <h2>"Device Traffic"</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>"Hostname"</th>
                        <th>"IP"</th>
                        <th>"Group"</th>
                        <th>"Downloaded"</th>
                        <th>"Uploaded"</th>
                        <th>"Total"</th>
                    </tr>
                </thead>
                <tbody>
                    {devices.iter().map(|d| {
                        let hostname = d.hostname.clone().unwrap_or_else(|| "(unknown)".to_string());
                        let ip = d.ip.clone().unwrap_or_default();
                        let badge_class = format!("badge badge-{}", d.device_group);
                        let device_link = format!("/devices/{}", d.mac);
                        let total = d.rx_bytes + d.tx_bytes;
                        view! {
                            <tr>
                                <td><a href={device_link}>{hostname}</a></td>
                                <td>{ip}</td>
                                <td><span class={badge_class}>{&d.device_group}</span></td>
                                <td>{format_bytes(d.rx_bytes)}</td>
                                <td>{format_bytes(d.tx_bytes)}</td>
                                <td>{format_bytes(total)}</td>
                            </tr>
                        }
                    }).collect_view()}
                </tbody>
            </table>
        </div>
    }.into_view()
}
