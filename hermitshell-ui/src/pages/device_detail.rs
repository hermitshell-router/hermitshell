use leptos::prelude::*;
use leptos_router::hooks::*;
use crate::client;
use crate::components::layout::Layout;
use crate::components::toast::ErrorToast;
use crate::format_bytes;
use crate::server_fns::{SetGroup, BlockDevice, UnblockDevice, SetReservation, SetNickname};

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

    let device = Resource::new(
        move || params.with(|p| p.get("mac").unwrap_or_default()),
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
                        let is_blocked = group == "blocked";
                        let group_trusted = group == "trusted";
                        let group_iot = group == "iot";
                        let group_guest = group == "guest";
                        let group_servers = group == "servers";
                        let group_quarantine = group == "quarantine";

                        let set_group_action = ServerAction::<SetGroup>::new();
                        let unblock_action = ServerAction::<UnblockDevice>::new();
                        let block_action = ServerAction::<BlockDevice>::new();
                        let reserve_action = ServerAction::<SetReservation>::new();
                        let set_nickname_action = ServerAction::<SetNickname>::new();

                        let mac_display = mac.clone();
                        let mac_for_nickname = mac.clone();
                        let mac_for_group = mac.clone();
                        let mac_redirect = mac.clone();
                        let mac_for_block_unblock = mac.clone();
                        let mac_for_reserve = mac.clone();
                        let mac_for_alerts = mac.clone();

                        view! {
                            <div class="detail-grid">
                                <div class="detail-item full-span">
                                    <div class="detail-label">"Nickname"</div>
                                    <div class="detail-value">
                                        <ActionForm action=set_nickname_action attr:class="flex-row">
                                            <input type="hidden" name="mac" value={mac_for_nickname} />
                                            <input type="text" name="nickname" value={d.nickname.clone().unwrap_or_default()}
                                                   placeholder="Enter nickname" maxlength="64"
                                                   />
                                            <button type="submit" class="btn btn-primary btn-sm">"Save"</button>
                                        </ActionForm>
                                    </div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">"MAC Address"</div>
                                    <div class="detail-value">{mac_display}</div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">"IP Address"</div>
                                    <div class="detail-value">{d.ipv4.clone().unwrap_or_else(|| "\u{2014}".to_string())}</div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">"Hostname"</div>
                                    <div class="detail-value">{d.hostname.clone().unwrap_or_else(|| "\u{2014}".to_string())}</div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">"Group"</div>
                                    <div class="detail-value"><span class={badge_class}>{group}</span></div>
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

                            // VLAN & Switch info (shown when VLAN mode is enabled)
                            {
                                let vlan_info = client::get_vlan_status().ok();
                                let vlan_enabled = vlan_info.as_ref().map(|(e, _)| *e).unwrap_or(false);
                                if vlan_enabled {
                                    let vlans = vlan_info.map(|(_, v)| v).unwrap_or_default();
                                    let device_vlan = vlans.iter().find(|v| v.group == d.device_group);
                                    view! {
                                        <h2 class="section-header">"VLAN & Switch"</h2>
                                        <div class="detail-grid">
                                            <div class="detail-item">
                                                <div class="detail-label">"VLAN ID"</div>
                                                <div class="detail-value">{device_vlan.map(|v| v.vlan_id.to_string()).unwrap_or_else(|| "\u{2014}".to_string())}</div>
                                            </div>
                                            <div class="detail-item">
                                                <div class="detail-label">"VLAN Subnet"</div>
                                                <div class="detail-value">{device_vlan.map(|v| v.subnet.clone()).unwrap_or_else(|| "\u{2014}".to_string())}</div>
                                            </div>
                                            <div class="detail-item">
                                                <div class="detail-label">"Switch Port"</div>
                                                <div class="detail-value">{d.switch_port.clone().unwrap_or_else(|| "\u{2014}".to_string())}</div>
                                            </div>
                                        </div>
                                    }.into_any()
                                } else {
                                    view! { <span></span> }.into_any()
                                }
                            }

                            // Bandwidth history chart and top destinations
                            {
                                let bw_mac = d.mac.clone();

                                match client::get_bandwidth_history(Some(&bw_mac), "24h") {
                                    Ok(bw_data) => {
                                        let chart_svg = crate::charts::bandwidth_chart(&bw_data, 800, 200);

                                        let top_dests_view = match client::get_top_destinations(&bw_mac, "24h", 10) {
                                            Ok(top_dests) if !top_dests.is_empty() => {
                                                view! {
                                                    <h2 class="section-header">"Top Destinations"</h2>
                                                    <div class="table-scroll">
                                                    <table class="data-table">
                                                        <thead><tr>
                                                            <th>"Destination"</th><th>"Port"</th><th>"Total"</th>
                                                        </tr></thead>
                                                        <tbody>
                                                            {top_dests.iter().map(|td| {
                                                                view! {
                                                                    <tr>
                                                                        <td>{td.dest_ip.clone()}</td>
                                                                        <td>{td.dest_port}</td>
                                                                        <td>{crate::format_bytes(td.total_bytes)}</td>
                                                                    </tr>
                                                                }
                                                            }).collect_view()}
                                                        </tbody>
                                                    </table>
                                                    </div>
                                                }.into_any()
                                            }
                                            Ok(_) => view! { <span></span> }.into_any(),
                                            Err(e) => view! { <p class="error">{format!("Error loading top destinations: {e}")}</p> }.into_any(),
                                        };

                                        view! {
                                            <h2 class="section-header">"Bandwidth (24h)"</h2>
                                            <div inner_html={chart_svg}></div>
                                            {top_dests_view}
                                        }.into_any()
                                    }
                                    Err(e) => view! {
                                        <h2 class="section-header">"Bandwidth (24h)"</h2>
                                        <p class="error">{format!("Error loading bandwidth: {e}")}</p>
                                    }.into_any(),
                                }
                            }

                            // mDNS Services
                            {
                                match client::list_mdns_services(&d.mac) {
                                    Ok(services) if !services.is_empty() => {
                                        view! {
                                            <h2 class="section-header">"Discovered Services"</h2>
                                            <div class="table-scroll">
                                            <table class="data-table">
                                                <thead><tr>
                                                    <th>"Service"</th><th>"Name"</th><th>"Port"</th>
                                                </tr></thead>
                                                <tbody>
                                                    {services.iter().map(|s| {
                                                        view! {
                                                            <tr>
                                                                <td>{s.service_type.clone()}</td>
                                                                <td>{s.service_name.clone()}</td>
                                                                <td>{s.port}</td>
                                                            </tr>
                                                        }
                                                    }).collect_view()}
                                                </tbody>
                                            </table>
                                            </div>
                                        }.into_any()
                                    }
                                    Ok(_) => view! { <span></span> }.into_any(),
                                    Err(e) => view! { <p class="error">{format!("Error loading services: {e}")}</p> }.into_any(),
                                }
                            }

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
                                }.into_any()
                            } else {
                                view! { <span></span> }.into_any()
                            }}

                            // Group suggestion based on runZero classification
                            {if d.device_group == "quarantine" {
                                if let Some(ref rz_type) = d.runzero_device_type {
                                    let suggested = match rz_type.as_str() {
                                        "phone" | "laptop" | "tablet" | "desktop" | "workstation" => Some("trusted"),
                                        "printer" | "media player" | "speaker" | "camera" | "iot"
                                        | "smart tv" | "streaming" | "display" | "nas" | "server" => Some("iot"),
                                        _ => None,
                                    };
                                    if let Some(group) = suggested {
                                        let mac_suggest = d.mac.clone();
                                        let suggest_action = ServerAction::<SetGroup>::new();
                                        view! {
                                            <div class="settings-section-highlight">
                                                <p>"This device looks like a " <strong>{rz_type.clone()}</strong> ". Move to " <strong>{group}</strong> "?"</p>
                                                <ActionForm action=suggest_action>
                                                    <input type="hidden" name="mac" value={mac_suggest} />
                                                    <input type="hidden" name="group" value={group} />
                                                    <input type="hidden" name="redirect" value={format!("/devices/{}", d.mac)} />
                                                    <button type="submit" class="btn btn-primary btn-sm">"Move to " {group}</button>
                                                </ActionForm>
                                            </div>
                                        }.into_any()
                                    } else {
                                        view! { <span></span> }.into_any()
                                    }
                                } else {
                                    view! { <span></span> }.into_any()
                                }
                            } else {
                                view! { <span></span> }.into_any()
                            }}

                            <h2 class="section-header">"Actions"</h2>
                            <div class="actions-bar">
                                {if !is_blocked {
                                    view! {
                                        <ActionForm action=set_group_action attr:class="inline-form">
                                            <input type="hidden" name="mac" value={mac_for_group} />
                                            <input type="hidden" name="redirect" value={format!("/devices/{}", mac_redirect)} />
                                            <select name="group">
                                                <option value="trusted" selected={group_trusted}>"Trusted"</option>
                                                <option value="iot" selected={group_iot}>"IoT"</option>
                                                <option value="guest" selected={group_guest}>"Guest"</option>
                                                <option value="servers" selected={group_servers}>"Servers"</option>
                                                <option value="quarantine" selected={group_quarantine}>"Quarantine"</option>
                                            </select>
                                            " "
                                            <button type="submit" class="btn btn-primary btn-sm">"Change Group"</button>
                                        </ActionForm>
                                    }.into_any()
                                } else {
                                    view! { <span></span> }.into_any()
                                }}

                                {if is_blocked {
                                    view! {
                                        <ActionForm action=unblock_action attr:class="inline-form">
                                            <input type="hidden" name="mac" value={mac_for_block_unblock} />
                                            <button type="submit" class="btn btn-primary btn-sm">"Unblock"</button>
                                        </ActionForm>
                                    }.into_any()
                                } else {
                                    view! {
                                        <button type="button"
                                            class="btn btn-danger btn-sm"
                                            onclick="this.nextElementSibling.showModal()">"Block"</button>
                                        <dialog class="confirm-dialog">
                                            <h3>"Block Device?"</h3>
                                            <p>"This device will lose all network access."</p>
                                            <div class="dialog-actions">
                                                <button type="button" class="btn btn-sm"
                                                    onclick="this.closest('dialog').close()">"Cancel"</button>
                                                <ActionForm action=block_action>
                                                    <input type="hidden" name="mac" value={mac_for_block_unblock} />
                                                    <button type="submit" class="btn btn-danger btn-sm">"Confirm Block"</button>
                                                </ActionForm>
                                            </div>
                                        </dialog>
                                    }.into_any()
                                }}

                                <ActionForm action=reserve_action attr:class="inline-form">
                                    <input type="hidden" name="mac" value={mac_for_reserve} />
                                    <button type="submit" class="btn btn-sm">"Reserve IP"</button>
                                </ActionForm>
                            </div>
                            <ErrorToast value=set_group_action.value() />
                            <ErrorToast value=unblock_action.value() />
                            <ErrorToast value=block_action.value() />
                            <ErrorToast value=reserve_action.value() />
                            <ErrorToast value=set_nickname_action.value() />

                            {
                                let device_ip = d.ipv4.clone();

                                let conn_result: Result<Vec<_>, String> = match device_ip.as_ref() {
                                    Some(ip) => client::list_connection_logs(Some(ip), 50),
                                    None => Ok(vec![]),
                                };

                                let dns_result: Result<Vec<_>, String> = match device_ip.as_ref() {
                                    Some(ip) => client::list_dns_logs(Some(ip), 50),
                                    None => Ok(vec![]),
                                };

                                let conn_view = match conn_result {
                                    Ok(conn_logs) if conn_logs.is_empty() => {
                                        view! { <p class="muted">"No connections recorded."</p> }.into_any()
                                    }
                                    Ok(conn_logs) => {
                                        view! {
                                            <div class="table-scroll">
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
                                            </div>
                                        }.into_any()
                                    }
                                    Err(e) => {
                                        view! { <p class="error">{format!("Error loading connections: {e}")}</p> }.into_any()
                                    }
                                };

                                let dns_view = match dns_result {
                                    Ok(dns_logs) if dns_logs.is_empty() => {
                                        view! { <p class="muted">"No DNS queries recorded."</p> }.into_any()
                                    }
                                    Ok(dns_logs) => {
                                        view! {
                                            <div class="table-scroll">
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
                                            </div>
                                        }.into_any()
                                    }
                                    Err(e) => {
                                        view! { <p class="error">{format!("Error loading DNS logs: {e}")}</p> }.into_any()
                                    }
                                };

                                view! {
                                    <h2 class="section-header">"Recent Connections"</h2>
                                    {conn_view}

                                    <h2 class="section-header">"Recent DNS Queries"</h2>
                                    {dns_view}
                                }
                            }

                            {
                                let alerts_view = match client::list_alerts(Some(&mac_for_alerts), 50) {
                                    Ok(device_alerts) if device_alerts.is_empty() => {
                                        view! { <p class="muted">"No alerts for this device."</p> }.into_any()
                                    }
                                    Ok(device_alerts) => {
                                        view! {
                                            <div class="table-scroll">
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
                                            </div>
                                        }.into_any()
                                    }
                                    Err(e) => {
                                        view! { <p class="error">{format!("Error loading alerts: {e}")}</p> }.into_any()
                                    }
                                };

                                view! {
                                    <h2 class="section-header">"Recent Alerts"</h2>
                                    {alerts_view}
                                }
                            }
                        }.into_any()
                    }
                    Err(e) => view! { <p>"Error: " {e}</p> }.into_any(),
                })}
            </Suspense>
        </Layout>
    }
}
