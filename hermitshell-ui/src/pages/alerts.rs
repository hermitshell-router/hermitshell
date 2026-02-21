use leptos::prelude::*;
use crate::client;
use crate::components::layout::Layout;
use crate::components::toast::ErrorToast;
use crate::server_fns::{AcknowledgeAlert, AcknowledgeAllAlerts};

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

    let ack_all_action = ServerAction::<AcknowledgeAllAlerts>::new();

    view! {
        <Layout title="Alerts" active_page="alerts">
            <div class="actions-bar">
                <ActionForm action=ack_all_action attr:style="display:inline">
                    <button type="submit" class="btn btn-sm">"Acknowledge All"</button>
                </ActionForm>
            </div>
            <ErrorToast value=ack_all_action.value() />
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
                                        {alert_list.into_iter().map(|a| {
                                            let sev_class = severity_class(&a.severity);
                                            let ack_class = if a.acknowledged { "muted" } else { "" };
                                            let rule_name = rule_display(&a.rule);
                                            let ack_action = ServerAction::<AcknowledgeAlert>::new();
                                            let id_str = a.id.to_string();
                                            let acknowledged = a.acknowledged;
                                            let device_link = format!("/devices/{}", a.device_mac);
                                            view! {
                                                <tr class={ack_class}>
                                                    <td>{format_timestamp(a.created_at)}</td>
                                                    <td><a href={device_link}>{a.device_mac}</a></td>
                                                    <td>{rule_name}</td>
                                                    <td><span class={sev_class}>{a.severity}</span></td>
                                                    <td>{a.message}</td>
                                                    <td>
                                                        {if !acknowledged {
                                                            view! {
                                                                <ActionForm action=ack_action attr:style="display:inline">
                                                                    <input type="hidden" name="id" value={id_str} />
                                                                    <button type="submit" class="btn btn-sm">"Ack"</button>
                                                                </ActionForm>
                                                            }.into_any()
                                                        } else {
                                                            view! { <span class="muted">"acked"</span> }.into_any()
                                                        }}
                                                        <ErrorToast value=ack_action.value() />
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
