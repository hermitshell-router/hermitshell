use leptos::prelude::*;
use crate::client;
use crate::charts;
use crate::components::layout::Layout;
use crate::format_bytes;

fn format_bps(bps: i64) -> String {
    if bps < 1024 {
        format!("{bps} B/s")
    } else if bps < 1024 * 1024 {
        format!("{:.1} KB/s", bps as f64 / 1024.0)
    } else if bps < 1024 * 1024 * 1024 {
        format!("{:.1} MB/s", bps as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB/s", bps as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

#[component]
pub fn Traffic() -> impl IntoView {
    let data = Resource::new(
        || (),
        |_| async {
            let devices = client::list_devices()?;
            let realtime = client::get_bandwidth_realtime().unwrap_or_default();
            Ok::<_, String>((devices, realtime))
        },
    );

    view! {
        <Layout title="Traffic" active_page="traffic">
            <meta http-equiv="refresh" content="10" />
            <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                {move || data.get().map(|result| match result {
                    Ok((devices, realtime)) => {
                        render_traffic(devices, realtime)
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                })}
            </Suspense>
        </Layout>
    }
}

fn render_traffic(mut devices: Vec<crate::types::Device>, realtime: Vec<hermitshell_common::BandwidthRealtime>) -> AnyView {
    let total_rx: i64 = devices.iter().map(|d| d.rx_bytes).sum();
    let total_tx: i64 = devices.iter().map(|d| d.tx_bytes).sum();

    // Fetch bandwidth history for network-wide chart (default 24h)
    let history = client::get_bandwidth_history(None, "24h").unwrap_or_default();
    let chart_svg = charts::bandwidth_chart(&history, 800, 250);

    // Sort real-time by throughput (descending)
    let mut rt_sorted = realtime;
    rt_sorted.sort_by(|a, b| (b.rx_bps + b.tx_bps).cmp(&(a.rx_bps + a.tx_bps)));

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
            <h2>"Network Bandwidth (24h)"</h2>
            <div inner_html={chart_svg}></div>
        </div>

        {if !rt_sorted.is_empty() && rt_sorted.iter().any(|r| r.rx_bps > 0 || r.tx_bps > 0) {
            view! {
                <div class="section">
                    <h2>"Real-time Throughput"</h2>
                    <table class="table">
                        <thead>
                            <tr>
                                <th>"Device"</th>
                                <th>"Download"</th>
                                <th>"Upload"</th>
                            </tr>
                        </thead>
                        <tbody>
                            {rt_sorted.iter().filter(|r| r.rx_bps > 0 || r.tx_bps > 0).map(|r| {
                                let device_link = format!("/devices/{}", r.mac);
                                view! {
                                    <tr>
                                        <td><a href={device_link}>{r.ip.clone()}</a></td>
                                        <td>{format_bps(r.rx_bps)}</td>
                                        <td>{format_bps(r.tx_bps)}</td>
                                    </tr>
                                }
                            }).collect_view()}
                        </tbody>
                    </table>
                </div>
            }.into_any()
        } else {
            view! { <span></span> }.into_any()
        }}

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
                        let hostname = d.nickname.clone()
                            .or_else(|| d.hostname.clone())
                            .unwrap_or_else(|| "(unknown)".to_string());
                        let ip = d.ipv4.clone().unwrap_or_default();
                        let badge_class = format!("badge badge-{}", d.device_group);
                        let device_link = format!("/devices/{}", d.mac);
                        let total = d.rx_bytes + d.tx_bytes;
                        view! {
                            <tr>
                                <td><a href={device_link}>{hostname}</a></td>
                                <td>{ip}</td>
                                <td><span class={badge_class}>{d.device_group.clone()}</span></td>
                                <td>{format_bytes(d.rx_bytes)}</td>
                                <td>{format_bytes(d.tx_bytes)}</td>
                                <td>{format_bytes(total)}</td>
                            </tr>
                        }
                    }).collect_view()}
                </tbody>
            </table>
        </div>
    }.into_any()
}
