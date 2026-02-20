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
    let log_config = create_resource(
        || (),
        |_| async { client::get_log_config() },
    );
    let runzero_config = create_resource(
        || (),
        |_| async { client::get_runzero_config() },
    );
    let analyzer_status = create_resource(
        || (),
        |_| async { client::get_analyzer_status() },
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

            <Suspense fallback=move || view! { <p>"Loading log config..."</p> }>
                {move || log_config.get().map(|result| match result {
                    Ok(config) => {
                        let log_format = config.get("log_format").and_then(|v| v.as_str()).unwrap_or("text").to_string();
                        let syslog_target = config.get("syslog_target").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let webhook_url = config.get("webhook_url").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let retention = config.get("log_retention_days").and_then(|v| v.as_str()).unwrap_or("7").to_string();

                        view! {
                            <div class="settings-section">
                                <h3>"Log Export"</h3>
                                <form method="post" action="/api/set-log-config">
                                    <div class="settings-row">
                                        <span class="settings-label">"Log Format"</span>
                                        <span class="settings-value">
                                            <select name="log_format">
                                                <option value="text" selected={log_format == "text"}>"Text"</option>
                                                <option value="json" selected={log_format == "json"}>"JSON"</option>
                                            </select>
                                        </span>
                                    </div>
                                    <div class="settings-row">
                                        <span class="settings-label">"Syslog Target"</span>
                                        <span class="settings-value">
                                            <input type="text" name="syslog_target" placeholder="udp://192.168.1.100:514" value={syslog_target} />
                                        </span>
                                    </div>
                                    <div class="settings-row">
                                        <span class="settings-label">"Webhook URL"</span>
                                        <span class="settings-value">
                                            <input type="text" name="webhook_url" placeholder="https://splunk:8088/services/collector" value={webhook_url} />
                                        </span>
                                    </div>
                                    <div class="settings-row">
                                        <span class="settings-label">"Webhook Secret"</span>
                                        <span class="settings-value">
                                            <input type="password" name="webhook_secret" placeholder="Bearer token" />
                                        </span>
                                    </div>
                                    <div class="settings-row">
                                        <span class="settings-label">"Log Retention (days)"</span>
                                        <span class="settings-value">
                                            <input type="number" name="log_retention_days" min="1" max="365" value={retention} />
                                        </span>
                                    </div>
                                    <div class="actions-bar">
                                        <button type="submit" class="btn btn-primary btn-sm">"Save Log Settings"</button>
                                    </div>
                                </form>
                            </div>
                        }.into_view()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_view(),
                })}
            </Suspense>

            <Suspense fallback=move || view! { <p>"Loading runZero config..."</p> }>
                {move || runzero_config.get().map(|result| match result {
                    Ok(config) => {
                        let url = config.get("runzero_url").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let interval = config.get("runzero_sync_interval").and_then(|v| v.as_str()).unwrap_or("3600").to_string();
                        let enabled = config.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
                        let has_token = config.get("has_token").and_then(|v| v.as_bool()).unwrap_or(false);
                        let token_placeholder = if has_token { "(configured)" } else { "XT-..." };

                        view! {
                            <div class="settings-section">
                                <h3>"runZero Integration"</h3>
                                <form method="post" action="/api/set-runzero-config">
                                    <div class="settings-row">
                                        <span class="settings-label">"Console URL"</span>
                                        <span class="settings-value">
                                            <input type="text" name="runzero_url" placeholder="https://runzero.lan:8443" value={url} />
                                        </span>
                                    </div>
                                    <div class="settings-row">
                                        <span class="settings-label">"Export Token"</span>
                                        <span class="settings-value">
                                            <input type="password" name="runzero_token" placeholder={token_placeholder} />
                                        </span>
                                    </div>
                                    <div class="settings-row">
                                        <span class="settings-label">"Sync Interval (seconds)"</span>
                                        <span class="settings-value">
                                            <input type="number" name="runzero_sync_interval" min="60" value={interval} />
                                        </span>
                                    </div>
                                    <div class="settings-row">
                                        <span class="settings-label">"Enabled"</span>
                                        <span class="settings-value">
                                            <select name="runzero_enabled">
                                                <option value="true" selected={enabled}>"Yes"</option>
                                                <option value="false" selected={!enabled}>"No"</option>
                                            </select>
                                        </span>
                                    </div>
                                    <div class="actions-bar">
                                        <button type="submit" class="btn btn-primary btn-sm">"Save runZero Settings"</button>
                                    </div>
                                </form>
                                <form method="post" action="/api/sync-runzero" style="margin-top: 0.5rem;">
                                    <button type="submit" class="btn btn-sm">"Sync Now"</button>
                                </form>
                            </div>
                        }.into_view()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_view(),
                })}
            </Suspense>

            <Suspense fallback=move || view! { <p>"Loading analyzer status..."</p> }>
                {move || analyzer_status.get().map(|result| match result {
                    Ok(status) => {
                        let enabled = status.get("enabled")
                            .and_then(|v| v.as_str())
                            .unwrap_or("true")
                            .to_string();
                        let alert_counts = status.get("unacknowledged_alerts")
                            .and_then(|v| v.as_object())
                            .map(|counts| {
                                let high = counts.get("high").and_then(|v| v.as_i64()).unwrap_or(0);
                                let medium = counts.get("medium").and_then(|v| v.as_i64()).unwrap_or(0);
                                let low = counts.get("low").and_then(|v| v.as_i64()).unwrap_or(0);
                                format!("{} high, {} medium, {} low", high, medium, low)
                            });
                        let rule_statuses: Vec<(&str, String)> = status.get("rules")
                            .and_then(|v| v.as_object())
                            .map(|rule_map| {
                                let rule_names = [
                                    ("dns_beaconing", "DNS Beaconing"),
                                    ("dns_volume_spike", "DNS Volume Spike"),
                                    ("new_dest_spike", "New Destination Spike"),
                                    ("suspicious_ports", "Suspicious Ports"),
                                    ("bandwidth_spike", "Bandwidth Spike"),
                                ];
                                rule_names.iter().map(|(key, label)| {
                                    let s = rule_map.get(*key)
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("enabled")
                                        .to_string();
                                    (*label, s)
                                }).collect()
                            })
                            .unwrap_or_default();

                        view! {
                            <div class="settings-section">
                                <h3>"Behavioral Analysis"</h3>
                                <div class="settings-row">
                                    <span class="settings-label">"Status"</span>
                                    <span class="settings-value">{if enabled == "true" { "Enabled" } else { "Disabled" }}</span>
                                </div>
                                {if let Some(counts_text) = alert_counts {
                                    view! {
                                        <div class="settings-row">
                                            <span class="settings-label">"Unacknowledged Alerts"</span>
                                            <span class="settings-value">
                                                {counts_text}
                                            </span>
                                        </div>
                                    }.into_view()
                                } else {
                                    view! { <span></span> }.into_view()
                                }}
                                {if !rule_statuses.is_empty() {
                                    view! {
                                        {rule_statuses.iter().map(|(label, s)| {
                                            view! {
                                                <div class="settings-row">
                                                    <span class="settings-label">{*label}</span>
                                                    <span class="settings-value">{s.clone()}</span>
                                                </div>
                                            }
                                        }).collect_view()}
                                    }.into_view()
                                } else {
                                    view! { <span></span> }.into_view()
                                }}
                            </div>
                        }.into_view()
                    }
                    Err(_) => view! { <span></span> }.into_view(),
                })}
            </Suspense>
        </Layout>
    }
}
