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

#[component]
pub fn Logs() -> impl IntoView {
    let params = leptos_router::hooks::use_query_map();
    let tab = move || params.get().get("tab").unwrap_or_default();
    let device = move || {
        let d = params.get().get("device").unwrap_or_default();
        if d.is_empty() { None } else { Some(d) }
    };

    let is_dns = move || tab() == "dns";

    let conn_data = Resource::new(
        device,
        |device_ip| async move {
            client::list_connection_logs(device_ip.as_deref(), 200)
        },
    );

    let dns_data = Resource::new(
        device,
        |device_ip| async move {
            client::list_dns_logs(device_ip.as_deref(), 200)
        },
    );

    let device_value = move || device().unwrap_or_default();

    view! {
        <Layout title="Logs" active_page="logs">
            <div class="tab-nav" style="margin-bottom: 1rem;">
                <a
                    href="/logs"
                    class=move || if !is_dns() { "tab-link active" } else { "tab-link" }
                >"Connection Logs"</a>
                " | "
                <a
                    href="/logs?tab=dns"
                    class=move || if is_dns() { "tab-link active" } else { "tab-link" }
                >"DNS Logs"</a>
            </div>

            <form method="get" action="/logs" style="margin-bottom: 1rem;">
                {move || {
                    if is_dns() {
                        view! { <input type="hidden" name="tab" value="dns" /> }.into_any()
                    } else {
                        ().into_any()
                    }
                }}
                <label>"Device IP: "</label>
                <input type="text" name="device" value=device_value placeholder="e.g. 10.0.0.2" />
                " "
                <button type="submit" class="btn btn-sm">"Filter"</button>
            </form>

            {move || {
                if is_dns() {
                    view! {
                        <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                            {move || dns_data.get().map(|result| match result {
                                Ok(entries) => {
                                    if entries.is_empty() {
                                        view! { <p class="text-muted">"No DNS log entries."</p> }.into_any()
                                    } else {
                                        view! {
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
                                        }.into_any()
                                    }
                                }
                                Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                            })}
                        </Suspense>
                    }.into_any()
                } else {
                    view! {
                        <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                            {move || conn_data.get().map(|result| match result {
                                Ok(entries) => {
                                    if entries.is_empty() {
                                        view! { <p class="text-muted">"No connection log entries."</p> }.into_any()
                                    } else {
                                        view! {
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
                                                        view! {
                                                            <tr>
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
