use leptos::prelude::*;
use crate::client;
use crate::components::layout::Layout;

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

fn severity_class(severity: &str) -> &'static str {
    match severity {
        "high" => "badge badge-high",
        "medium" => "badge badge-medium",
        "low" => "badge badge-low",
        _ => "badge",
    }
}

fn rule_display(rule: &str) -> &'static str {
    match rule {
        "dns_beaconing" => "DNS Beaconing",
        "dns_volume_spike" => "DNS Volume Spike",
        "new_dest_spike" => "New Destination Spike",
        "suspicious_ports" => "Suspicious Ports",
        "bandwidth_spike" => "Bandwidth Spike",
        _ => "Unknown",
    }
}

#[component]
pub fn Alerts() -> impl IntoView {
    let alerts = Resource::new(
        || (),
        |_| async { client::list_alerts(None, 200) },
    );

    view! {
        <Layout title="Alerts" active_page="alerts">
            <div class="actions-bar">
                <form method="post" action="/api/acknowledge-all-alerts" style="display:inline">
                    <button type="submit" class="btn btn-sm">"Acknowledge All"</button>
                </form>
            </div>
            <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                {move || alerts.get().map(|result| match result {
                    Ok(alert_list) => {
                        if alert_list.is_empty() {
                            view! { <p class="muted">"No alerts."</p> }.into_any()
                        } else {
                            view! {
                                <table class="data-table">
                                    <thead><tr>
                                        <th>"Time"</th>
                                        <th>"Device"</th>
                                        <th>"Rule"</th>
                                        <th>"Severity"</th>
                                        <th>"Message"</th>
                                        <th>"Actions"</th>
                                    </tr></thead>
                                    <tbody>
                                        {alert_list.iter().map(|a| {
                                            let sev_class = severity_class(&a.severity);
                                            let ack_class = if a.acknowledged { "muted" } else { "" };
                                            let rule_name = rule_display(&a.rule);
                                            view! {
                                                <tr class={ack_class}>
                                                    <td>{format_timestamp(a.created_at)}</td>
                                                    <td><a href={format!("/devices/{}", a.device_mac)}>{a.device_mac.clone()}</a></td>
                                                    <td>{rule_name}</td>
                                                    <td><span class={sev_class}>{a.severity.clone()}</span></td>
                                                    <td>{a.message.clone()}</td>
                                                    <td>
                                                        {if !a.acknowledged {
                                                            view! {
                                                                <form method="post" action="/api/acknowledge-alert" style="display:inline">
                                                                    <input type="hidden" name="id" value={a.id.to_string()} />
                                                                    <button type="submit" class="btn btn-sm">"Ack"</button>
                                                                </form>
                                                            }.into_any()
                                                        } else {
                                                            view! { <span class="muted">"acked"</span> }.into_any()
                                                        }}
                                                    </td>
                                                </tr>
                                            }
                                        }).collect_view()}
                                    </tbody>
                                </table>
                            }.into_any()
                        }
                    }
                    Err(e) => view! { <p>"Error: " {e}</p> }.into_any(),
                })}
            </Suspense>
        </Layout>
    }
}
