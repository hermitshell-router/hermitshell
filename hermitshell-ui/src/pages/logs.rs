use leptos::prelude::*;
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

fn parse_since(range: &str) -> Option<i64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let secs = match range {
        "1h" => 3600,
        "6h" => 6 * 3600,
        "24h" => 24 * 3600,
        "7d" => 7 * 24 * 3600,
        _ => return None,
    };
    Some(now - secs)
}

const PAGE_SIZE: i64 = 100;

/// Build a query string preserving all current filter params.
fn build_query(tab: &str, device: &str, port: &str, protocol: &str, range: &str, offset: i64) -> String {
    let mut parts: Vec<String> = Vec::new();
    if !tab.is_empty() && tab != "conn" {
        parts.push(format!("tab={}", tab));
    }
    if !device.is_empty() {
        parts.push(format!("device={}", device));
    }
    if !port.is_empty() {
        parts.push(format!("port={}", port));
    }
    if !protocol.is_empty() {
        parts.push(format!("protocol={}", protocol));
    }
    if !range.is_empty() {
        parts.push(format!("range={}", range));
    }
    if offset > 0 {
        parts.push(format!("offset={}", offset));
    }
    if parts.is_empty() {
        "/logs".to_string()
    } else {
        format!("/logs?{}", parts.join("&"))
    }
}

#[component]
pub fn Logs() -> impl IntoView {
    let params = leptos_router::hooks::use_query_map();

    let tab = move || {
        let t = params.get().get("tab").unwrap_or_default();
        if t.is_empty() { "conn".to_string() } else { t }
    };
    let device = move || params.get().get("device").unwrap_or_default();
    let port_str = move || params.get().get("port").unwrap_or_default();
    let protocol_str = move || params.get().get("protocol").unwrap_or_default();
    let range_str = move || {
        let r = params.get().get("range").unwrap_or_default();
        if r.is_empty() { "24h".to_string() } else { r }
    };
    let offset_val = move || {
        params.get().get("offset").unwrap_or_default()
            .parse::<i64>().unwrap_or(0).max(0)
    };

    let is_dns = move || tab() == "dns";
    let is_audit = move || tab() == "audit";

    // Connection logs resource
    let conn_data = Resource::new(
        move || (device(), port_str(), protocol_str(), range_str(), offset_val()),
        |args| async move {
            let (device, port, protocol, range, offset) = args;
            let device_ip = if device.is_empty() { None } else { Some(device) };
            let port_val = port.parse::<i64>().ok();
            let proto = if protocol.is_empty() { None } else { Some(protocol) };
            let since = parse_since(&range);
            client::list_connection_logs(
                device_ip.as_deref(), port_val, proto.as_deref(), since, PAGE_SIZE, offset,
            )
        },
    );

    // DNS logs resource
    let dns_data = Resource::new(
        move || (device(), range_str(), offset_val()),
        |args| async move {
            let (device, range, offset) = args;
            let device_ip = if device.is_empty() { None } else { Some(device) };
            let since = parse_since(&range);
            client::list_dns_logs(device_ip.as_deref(), since, PAGE_SIZE, offset)
        },
    );

    // Connection stats resource
    let conn_stats = Resource::new(
        move || (device(), port_str(), protocol_str(), range_str()),
        |args| async move {
            let (device, port, protocol, range) = args;
            let device_ip = if device.is_empty() { None } else { Some(device) };
            let port_val = port.parse::<i64>().ok();
            let proto = if protocol.is_empty() { None } else { Some(protocol) };
            let since = parse_since(&range);
            client::count_connection_logs(device_ip.as_deref(), port_val, proto.as_deref(), since)
        },
    );

    // DNS stats resource
    let dns_stats = Resource::new(
        move || (device(), range_str()),
        |args| async move {
            let (device, range) = args;
            let device_ip = if device.is_empty() { None } else { Some(device) };
            let since = parse_since(&range);
            client::count_dns_logs(device_ip.as_deref(), since)
        },
    );

    // Audit logs resource
    let audit_data = Resource::new(
        move || tab(),
        |t| async move {
            if t == "audit" {
                client::list_audit_logs(200)
            } else {
                Ok(vec![])
            }
        },
    );

    let device_value = move || device();
    let port_value = move || port_str();
    let protocol_value = move || protocol_str();
    let range_value = move || range_str();

    view! {
        <Layout title="Logs" active_page="logs">
            <div class="tab-nav">
                <a
                    href="/logs"
                    class=move || if !is_dns() && !is_audit() { "tab-link active" } else { "tab-link" }
                >"Connection Logs"</a>
                <a
                    href="/logs?tab=dns"
                    class=move || if is_dns() { "tab-link active" } else { "tab-link" }
                >"DNS Logs"</a>
                <a
                    href="/logs?tab=audit"
                    class=move || if is_audit() { "tab-link active" } else { "tab-link" }
                >"Audit"</a>
            </div>

            {move || {
                if !is_audit() {
                    view! {
                        <form method="get" action="/logs" class="form-inline mb-md">
                            {move || {
                                if is_dns() {
                                    view! { <input type="hidden" name="tab" value="dns" /> }.into_any()
                                } else {
                                    ().into_any()
                                }
                            }}
                            <label>"Device IP: "</label>
                            <input type="text" name="device" value=device_value placeholder="e.g. 10.0.0.2" class="input-md" />
                            {move || {
                                if !is_dns() {
                                    view! {
                                        <label>" Port: "</label>
                                        <input type="text" name="port" value=port_value placeholder="e.g. 443" class="input-narrow" />
                                        <label>" Protocol: "</label>
                                        <select name="protocol">
                                            <option value="" selected=move || protocol_value().is_empty()>"All"</option>
                                            <option value="tcp" selected=move || protocol_value() == "tcp">"TCP"</option>
                                            <option value="udp" selected=move || protocol_value() == "udp">"UDP"</option>
                                        </select>
                                    }.into_any()
                                } else {
                                    ().into_any()
                                }
                            }}
                            <label>" Time: "</label>
                            <select name="range">
                                <option value="1h" selected=move || range_value() == "1h">"1 hour"</option>
                                <option value="6h" selected=move || range_value() == "6h">"6 hours"</option>
                                <option value="24h" selected=move || range_value() == "24h">"24 hours"</option>
                                <option value="7d" selected=move || range_value() == "7d">"7 days"</option>
                            </select>
                            " "
                            <button type="submit" class="btn btn-sm">"Filter"</button>
                        </form>
                    }.into_any()
                } else {
                    ().into_any()
                }
            }}

            {move || {
                if is_audit() {
                    view! {
                        <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                            {move || audit_data.get().map(|result| match result {
                                Ok(entries) => {
                                    if entries.is_empty() {
                                        view! { <p class="text-muted">"No audit entries yet."</p> }.into_any()
                                    } else {
                                        view! {
                                            <div class="table-scroll">
                                                <table class="device-table">
                                                    <thead>
                                                        <tr>
                                                            <th>"Time"</th>
                                                            <th>"Action"</th>
                                                            <th>"Detail"</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        {entries.into_iter().map(|entry| {
                                                            let time = format_timestamp(entry.created_at);
                                                            view! {
                                                                <tr>
                                                                    <td>{time}</td>
                                                                    <td>{entry.action}</td>
                                                                    <td>{entry.detail}</td>
                                                                </tr>
                                                            }
                                                        }).collect_view()}
                                                    </tbody>
                                                </table>
                                            </div>
                                        }.into_any()
                                    }
                                }
                                Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                            })}
                        </Suspense>
                    }.into_any()
                } else if is_dns() {
                    view! {
                        // DNS stats summary
                        <Suspense fallback=move || ()>
                            {move || dns_stats.get().map(|result| match result {
                                Ok(stats) => view! {
                                    <p class="text-secondary text-sm mb-md">
                                        {stats.total}" queries | "
                                        {stats.unique_domains.unwrap_or(0)}" unique domains"
                                    </p>
                                }.into_any(),
                                Err(_) => ().into_any(),
                            })}
                        </Suspense>

                        <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                            {move || dns_data.get().map(|result| match result {
                                Ok(entries) => {
                                    let count = entries.len() as i64;
                                    let current_offset = offset_val();
                                    if entries.is_empty() && current_offset == 0 {
                                        view! { <p class="text-muted">"No DNS log entries."</p> }.into_any()
                                    } else {
                                        let show_start = current_offset + 1;
                                        let show_end = current_offset + count;
                                        let tab_s = tab();
                                        let dev_s = device();
                                        let range_s = range_str();
                                        let prev_offset = (current_offset - PAGE_SIZE).max(0);
                                        let next_offset = current_offset + PAGE_SIZE;
                                        let has_prev = current_offset > 0;
                                        let has_next = count == PAGE_SIZE;
                                        let prev_url = build_query(&tab_s, &dev_s, "", "", &range_s, prev_offset);
                                        let next_url = build_query(&tab_s, &dev_s, "", "", &range_s, next_offset);
                                        view! {
                                            <div class="table-scroll">
                                            <table class="device-table">
                                                <thead>
                                                    <tr>
                                                        <th>"Time"</th>
                                                        <th>"Client IP"</th>
                                                        <th>"Domain"</th>
                                                        <th>"Type"</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    {entries.into_iter().map(|entry| {
                                                        let time = format_timestamp(entry.ts);
                                                        view! {
                                                            <tr>
                                                                <td>{time}</td>
                                                                <td>{entry.device_ip}</td>
                                                                <td>{entry.domain}</td>
                                                                <td>{entry.query_type}</td>
                                                            </tr>
                                                        }
                                                    }).collect_view()}
                                                </tbody>
                                            </table>
                                            </div>
                                            <div class="flex-row my-sm">
                                                {if has_prev {
                                                    view! { <a href=prev_url class="btn btn-sm">"Prev"</a> }.into_any()
                                                } else {
                                                    ().into_any()
                                                }}
                                                <span class="text-sm text-muted">
                                                    "Showing "{show_start}"-"{show_end}
                                                </span>
                                                {if has_next {
                                                    view! { <a href=next_url class="btn btn-sm">"Next"</a> }.into_any()
                                                } else {
                                                    ().into_any()
                                                }}
                                            </div>
                                        }.into_any()
                                    }
                                }
                                Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                            })}
                        </Suspense>
                    }.into_any()
                } else {
                    view! {
                        // Connection stats summary
                        <Suspense fallback=move || ()>
                            {move || conn_stats.get().map(|result| match result {
                                Ok(stats) => view! {
                                    <p class="text-secondary text-sm mb-md">
                                        {stats.total}" connections | "
                                        {stats.unique_destinations.unwrap_or(0)}" unique destinations | "
                                        {stats.unique_protocols.unwrap_or(0)}" protocols"
                                    </p>
                                }.into_any(),
                                Err(_) => ().into_any(),
                            })}
                        </Suspense>

                        <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                            {move || conn_data.get().map(|result| match result {
                                Ok(entries) => {
                                    let count = entries.len() as i64;
                                    let current_offset = offset_val();
                                    if entries.is_empty() && current_offset == 0 {
                                        view! { <p class="text-muted">"No connection log entries."</p> }.into_any()
                                    } else {
                                        let show_start = current_offset + 1;
                                        let show_end = current_offset + count;
                                        let tab_s = tab();
                                        let dev_s = device();
                                        let port_s = port_str();
                                        let proto_s = protocol_str();
                                        let range_s = range_str();
                                        let prev_offset = (current_offset - PAGE_SIZE).max(0);
                                        let next_offset = current_offset + PAGE_SIZE;
                                        let has_prev = current_offset > 0;
                                        let has_next = count == PAGE_SIZE;
                                        let prev_url = build_query(&tab_s, &dev_s, &port_s, &proto_s, &range_s, prev_offset);
                                        let next_url = build_query(&tab_s, &dev_s, &port_s, &proto_s, &range_s, next_offset);
                                        view! {
                                            <div class="table-scroll">
                                            <table class="device-table">
                                                <thead>
                                                    <tr>
                                                        <th>"Time"</th>
                                                        <th>"Source IP"</th>
                                                        <th>"Dest IP"</th>
                                                        <th>"Port"</th>
                                                        <th>"Protocol"</th>
                                                        <th>"Bytes Sent"</th>
                                                        <th>"Bytes Recv"</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    {entries.into_iter().map(|entry| {
                                                        let time = format_timestamp(entry.started_at);
                                                        let sent = format_bytes(entry.bytes_sent);
                                                        let recv = format_bytes(entry.bytes_recv);
                                                        let highlight = entry.bytes_sent + entry.bytes_recv > 10_000_000;
                                                        let row_class = if highlight { "row-highlight" } else { "" };
                                                        view! {
                                                            <tr class=row_class>
                                                                <td>{time}</td>
                                                                <td>{entry.device_ip}</td>
                                                                <td>{entry.dest_ip}</td>
                                                                <td>{entry.dest_port}</td>
                                                                <td>{entry.protocol}</td>
                                                                <td>{sent}</td>
                                                                <td>{recv}</td>
                                                            </tr>
                                                        }
                                                    }).collect_view()}
                                                </tbody>
                                            </table>
                                            </div>
                                            <div class="flex-row my-sm">
                                                {if has_prev {
                                                    view! { <a href=prev_url class="btn btn-sm">"Prev"</a> }.into_any()
                                                } else {
                                                    ().into_any()
                                                }}
                                                <span class="text-sm text-muted">
                                                    "Showing "{show_start}"-"{show_end}
                                                </span>
                                                {if has_next {
                                                    view! { <a href=next_url class="btn btn-sm">"Next"</a> }.into_any()
                                                } else {
                                                    ().into_any()
                                                }}
                                            </div>
                                        }.into_any()
                                    }
                                }
                                Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                            })}
                        </Suspense>
                    }.into_any()
                }
            }}
        </Layout>
    }
}
