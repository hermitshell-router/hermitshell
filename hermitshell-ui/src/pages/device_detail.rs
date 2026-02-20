use leptos::*;
use leptos_router::*;
use crate::client;
use crate::components::layout::Layout;
use crate::format_bytes;

fn format_timestamp(ts: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let diff = now - ts;
    if diff < 60 {
        "just now".to_string()
    } else if diff < 3600 {
        format!("{}m ago", diff / 60)
    } else if diff < 86400 {
        format!("{}h ago", diff / 3600)
    } else {
        format!("{}d ago", diff / 86400)
    }
}

#[component]
pub fn DeviceDetail() -> impl IntoView {
    let params = use_params_map();

    let device = create_resource(
        move || params.with(|p| p.get("mac").cloned().unwrap_or_default()),
        |mac| async move { client::get_device(&mac) },
    );

    view! {
        <Layout title="Device Detail" active_page="devices">
            <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                {move || device.get().map(|result| match result {
                    Ok(d) => {
                        let mac = d.mac.clone();
                        let group = d.device_group.clone();
                        let badge_class = format!("badge badge-{}", group);

                        view! {
                            <div class="detail-grid">
                                <div class="detail-item">
                                    <div class="detail-label">"MAC Address"</div>
                                    <div class="detail-value">{mac.clone()}</div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">"IP Address"</div>
                                    <div class="detail-value">{d.ip.clone().unwrap_or_else(|| "\u{2014}".to_string())}</div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">"Hostname"</div>
                                    <div class="detail-value">{d.hostname.clone().unwrap_or_else(|| "\u{2014}".to_string())}</div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">"Group"</div>
                                    <div class="detail-value"><span class={badge_class}>{group.clone()}</span></div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">"First Seen"</div>
                                    <div class="detail-value">{format_timestamp(d.first_seen)}</div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">"Last Seen"</div>
                                    <div class="detail-value">{format_timestamp(d.last_seen)}</div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">"Downloaded (RX)"</div>
                                    <div class="detail-value">{format_bytes(d.rx_bytes)}</div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">"Uploaded (TX)"</div>
                                    <div class="detail-value">{format_bytes(d.tx_bytes)}</div>
                                </div>
                            </div>

                            {if d.runzero_last_sync.is_some() {
                                view! {
                                    <h2 class="section-header">"Device Identity (runZero)"</h2>
                                    <div class="detail-grid">
                                        <div class="detail-item">
                                            <div class="detail-label">"OS"</div>
                                            <div class="detail-value">{d.runzero_os.clone().unwrap_or_else(|| "\u{2014}".to_string())}</div>
                                        </div>
                                        <div class="detail-item">
                                            <div class="detail-label">"Hardware"</div>
                                            <div class="detail-value">{d.runzero_hw.clone().unwrap_or_else(|| "\u{2014}".to_string())}</div>
                                        </div>
                                        <div class="detail-item">
                                            <div class="detail-label">"Type"</div>
                                            <div class="detail-value">{d.runzero_device_type.clone().unwrap_or_else(|| "\u{2014}".to_string())}</div>
                                        </div>
                                        <div class="detail-item">
                                            <div class="detail-label">"Manufacturer"</div>
                                            <div class="detail-value">{d.runzero_manufacturer.clone().unwrap_or_else(|| "\u{2014}".to_string())}</div>
                                        </div>
                                    </div>
                                }.into_view()
                            } else {
                                view! { <span></span> }.into_view()
                            }}

                            <h2 class="section-header">"Actions"</h2>
                            <div class="actions-bar">
                                {if group != "blocked" {
                                    view! {
                                        <form method="post" action="/api/set-group" style="display:inline">
                                            <input type="hidden" name="mac" value={mac.clone()} />
                                            <input type="hidden" name="redirect" value={format!("/devices/{}", mac)} />
                                            <select name="group">
                                                <option value="trusted" selected={group == "trusted"}>"Trusted"</option>
                                                <option value="iot" selected={group == "iot"}>"IoT"</option>
                                                <option value="guest" selected={group == "guest"}>"Guest"</option>
                                                <option value="servers" selected={group == "servers"}>"Servers"</option>
                                                <option value="quarantine" selected={group == "quarantine"}>"Quarantine"</option>
                                            </select>
                                            " "
                                            <button type="submit" class="btn btn-primary btn-sm">"Change Group"</button>
                                        </form>
                                    }.into_view()
                                } else {
                                    view! { <span></span> }.into_view()
                                }}

                                {if group == "blocked" {
                                    view! {
                                        <form method="post" action="/api/unblock" style="display:inline">
                                            <input type="hidden" name="mac" value={mac.clone()} />
                                            <button type="submit" class="btn btn-primary btn-sm">"Unblock"</button>
                                        </form>
                                    }.into_view()
                                } else {
                                    view! {
                                        <form method="post" action="/api/block" style="display:inline">
                                            <input type="hidden" name="mac" value={mac.clone()} />
                                            <button type="submit" class="btn btn-danger btn-sm">"Block"</button>
                                        </form>
                                    }.into_view()
                                }}

                                <form method="post" action="/api/set-reservation" style="display:inline">
                                    <input type="hidden" name="mac" value={mac.clone()} />
                                    <button type="submit" class="btn btn-sm">"Reserve IP"</button>
                                </form>
                            </div>

                            {
                                let device_ip = d.ip.clone();

                                let conn_logs = device_ip.as_ref()
                                    .map(|ip| client::list_connection_logs(Some(ip), 50).unwrap_or_default())
                                    .unwrap_or_default();

                                let dns_logs = device_ip.as_ref()
                                    .map(|ip| client::list_dns_logs(Some(ip), 50).unwrap_or_default())
                                    .unwrap_or_default();

                                view! {
                                    <h2 class="section-header">"Recent Connections"</h2>
                                    {if conn_logs.is_empty() {
                                        view! { <p class="muted">"No connections recorded."</p> }.into_view()
                                    } else {
                                        view! {
                                            <table class="data-table">
                                                <thead><tr>
                                                    <th>"Destination"</th><th>"Port"</th><th>"Protocol"</th>
                                                    <th>"Sent"</th><th>"Received"</th><th>"Time"</th>
                                                </tr></thead>
                                                <tbody>
                                                    {conn_logs.iter().map(|log| {
                                                        view! {
                                                            <tr>
                                                                <td>{log.dest_ip.clone()}</td>
                                                                <td>{log.dest_port}</td>
                                                                <td>{log.protocol.clone()}</td>
                                                                <td>{format_bytes(log.bytes_sent)}</td>
                                                                <td>{format_bytes(log.bytes_recv)}</td>
                                                                <td>{format_timestamp(log.started_at)}</td>
                                                            </tr>
                                                        }
                                                    }).collect_view()}
                                                </tbody>
                                            </table>
                                        }.into_view()
                                    }}

                                    <h2 class="section-header">"Recent DNS Queries"</h2>
                                    {if dns_logs.is_empty() {
                                        view! { <p class="muted">"No DNS queries recorded."</p> }.into_view()
                                    } else {
                                        view! {
                                            <table class="data-table">
                                                <thead><tr>
                                                    <th>"Domain"</th><th>"Type"</th><th>"Time"</th>
                                                </tr></thead>
                                                <tbody>
                                                    {dns_logs.iter().map(|log| {
                                                        view! {
                                                            <tr>
                                                                <td>{log.domain.clone()}</td>
                                                                <td>{log.query_type.clone()}</td>
                                                                <td>{format_timestamp(log.ts)}</td>
                                                            </tr>
                                                        }
                                                    }).collect_view()}
                                                </tbody>
                                            </table>
                                        }.into_view()
                                    }}
                                }
                            }

                            {
                                let device_alerts = client::list_alerts(Some(&mac), 50).unwrap_or_default();
                                view! {
                                    <h2 class="section-header">"Recent Alerts"</h2>
                                    {if device_alerts.is_empty() {
                                        view! { <p class="muted">"No alerts for this device."</p> }.into_view()
                                    } else {
                                        view! {
                                            <table class="data-table">
                                                <thead><tr>
                                                    <th>"Time"</th><th>"Rule"</th><th>"Severity"</th><th>"Message"</th>
                                                </tr></thead>
                                                <tbody>
                                                    {device_alerts.iter().map(|a| {
                                                        let sev_class = match a.severity.as_str() {
                                                            "high" => "badge badge-high",
                                                            "medium" => "badge badge-medium",
                                                            _ => "badge badge-low",
                                                        };
                                                        view! {
                                                            <tr>
                                                                <td>{format_timestamp(a.created_at)}</td>
                                                                <td>{a.rule.clone()}</td>
                                                                <td><span class={sev_class}>{a.severity.clone()}</span></td>
                                                                <td>{a.message.clone()}</td>
                                                            </tr>
                                                        }
                                                    }).collect_view()}
                                                </tbody>
                                            </table>
                                        }.into_view()
                                    }}
                                }
                            }
                        }.into_view()
                    }
                    Err(e) => view! { <p>"Error: " {e}</p> }.into_view(),
                })}
            </Suspense>
        </Layout>
    }
}
