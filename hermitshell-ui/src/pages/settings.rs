use leptos::prelude::*;
use crate::client;
use crate::components::layout::Layout;
use crate::components::toast::ErrorToast;
use crate::format_uptime;
use crate::server_fns::{
    RemoveReservation, SetLogConfig, SetRunzeroConfig, SyncRunzero,
    SetQosConfig, SetQosTestUrl, RunSpeedTest,
    SetTlsCustomCert, SetTlsSelfSigned, SetTlsTailscale, SetTlsAcme,
    ApplyUpdate, SetAutoUpdate,
};

#[component]
pub fn Settings() -> impl IntoView {
    let data = Resource::new(
        || (),
        |_| async { client::get_status() },
    );
    let reservations = Resource::new(
        || (),
        |_| async { client::list_dhcp_reservations() },
    );
    let log_config = Resource::new(
        || (),
        |_| async { client::get_log_config() },
    );
    let runzero_config = Resource::new(
        || (),
        |_| async { client::get_runzero_config() },
    );
    let analyzer_status = Resource::new(
        || (),
        |_| async { client::get_analyzer_status() },
    );
    let qos_config = Resource::new(
        || (),
        |_| async { client::get_qos_config() },
    );
    let tls_status = Resource::new(
        || (),
        |_| async { client::get_tls_status() },
    );
    let update_info = Resource::new(
        || (),
        |_| async { client::check_update() },
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
                                <h3>"Device Classification"</h3>
                                <p class="hint">"When enabled, new devices with runZero type data skip quarantine and are placed in their suggested group automatically."</p>
                                <div class="settings-row">
                                    <span class="settings-label">"Auto-classify"</span>
                                    <span class="settings-value">
                                        {match client::get_config("auto_classify_devices") {
                                            Ok(Some(v)) if v == "true" => "Enabled",
                                            _ => "Disabled",
                                        }}
                                    </span>
                                </div>
                            </div>

                            <div class="settings-section">
                                <h3>"Backup & Restore"</h3>
                                <div class="actions-bar" style="flex-direction:column;gap:1rem;align-items:flex-start">
                                    <div>
                                        <h4 style="margin:0 0 0.5rem 0">"Download Backup"</h4>
                                        <form method="post" action="/api/backup/config" style="display:flex;flex-wrap:wrap;gap:0.5rem;align-items:center">
                                            <label style="display:flex;align-items:center;gap:0.25rem">
                                                <input type="checkbox" name="secrets" value="1" id="backup-secrets-cb" />
                                                " Include secrets"
                                            </label>
                                            <div id="backup-passphrase-row" style="display:none;align-items:center;gap:0.25rem">
                                                <label style="display:flex;align-items:center;gap:0.25rem">
                                                    <input type="checkbox" id="backup-encrypt-cb" />
                                                    " Encrypt"
                                                </label>
                                                <input type="password" name="passphrase" placeholder="Passphrase" style="width:12rem" disabled />
                                            </div>
                                            <button type="submit" class="btn btn-primary btn-sm">"Download"</button>
                                        </form>
                                        <script>"
                                            document.getElementById('backup-secrets-cb').addEventListener('change', function() {
                                                document.getElementById('backup-passphrase-row').style.display = this.checked ? 'flex' : 'none';
                                            });
                                            document.getElementById('backup-encrypt-cb').addEventListener('change', function() {
                                                this.closest('#backup-passphrase-row').querySelector('input[type=password]').disabled = !this.checked;
                                            });
                                        "</script>
                                    </div>
                                    <div>
                                        <h4 style="margin:0 0 0.5rem 0">"Restore from Backup"</h4>
                                        <form method="post" action="/api/restore/config" enctype="multipart/form-data" style="display:flex;flex-wrap:wrap;gap:0.5rem;align-items:center">
                                            <input type="file" name="file" accept=".json" required />
                                            <input type="password" name="passphrase" placeholder="Passphrase (if encrypted)" style="width:12rem" />
                                            <button type="submit" class="btn btn-primary btn-sm">"Restore"</button>
                                        </form>
                                    </div>
                                </div>
                            </div>

                        }.into_any()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                })}
            </Suspense>

            <Suspense fallback=move || view! { <p>"Checking for updates..."</p> }>
                {move || update_info.get().map(|result| match result {
                    Ok(info) => {
                        let current = info.get("current_version")
                            .and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
                        let latest = info.get("latest_version")
                            .and_then(|v| v.as_str()).map(String::from);
                        let check_enabled = info.get("enabled")
                            .and_then(|v| v.as_bool()).unwrap_or(false);
                        let auto_update = info.get("auto_update_enabled")
                            .and_then(|v| v.as_bool()).unwrap_or(false);

                        let has_update = latest.as_ref()
                            .map(|l| *l != format!("v{}", current) && !l.is_empty())
                            .unwrap_or(false);

                        let update_action = ServerAction::<ApplyUpdate>::new();
                        let update_action_error = Signal::derive(move || {
                            update_action.value().get().map(|r| r.map(|_| ()))
                        });
                        let auto_update_action = ServerAction::<SetAutoUpdate>::new();

                        view! {
                            <div class="settings-section">
                                <h3>"Software Update"</h3>
                                <div class="settings-row">
                                    <span class="settings-label">"Current Version"</span>
                                    <span class="settings-value">{format!("v{}", current)}</span>
                                </div>
                                {if let Some(ref latest_ver) = latest {
                                    view! {
                                        <div class="settings-row">
                                            <span class="settings-label">"Latest Version"</span>
                                            <span class="settings-value">{latest_ver.clone()}</span>
                                        </div>
                                    }.into_any()
                                } else {
                                    view! { <span></span> }.into_any()
                                }}
                                {if !check_enabled {
                                    view! {
                                        <p class="hint">"Update checking is disabled."</p>
                                    }.into_any()
                                } else if has_update {
                                    view! {
                                        <div class="update-available">
                                            <ActionForm action=update_action>
                                                <button type="submit" class="btn btn-primary">"Update Now"</button>
                                            </ActionForm>
                                            <ErrorToast value=update_action_error />
                                        </div>
                                    }.into_any()
                                } else {
                                    view! {
                                        <p class="hint">"You are running the latest version."</p>
                                    }.into_any()
                                }}
                                {if check_enabled {
                                    view! {
                                        <div class="settings-row" style="margin-top:0.5rem">
                                            <span class="settings-label">"Auto-update"</span>
                                            <span class="settings-value">
                                                <ActionForm action=auto_update_action attr:style="display:inline">
                                                    <input type="hidden" name="enabled" value={if auto_update { "false" } else { "true" }} />
                                                    <button type="submit" class="btn btn-sm">
                                                        {if auto_update { "Disable" } else { "Enable" }}
                                                    </button>
                                                </ActionForm>
                                                <ErrorToast value=auto_update_action.value() />
                                            </span>
                                        </div>
                                    }.into_any()
                                } else {
                                    view! { <span></span> }.into_any()
                                }}
                            </div>
                        }.into_any()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
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
                                            let remove_action = ServerAction::<RemoveReservation>::new();
                                            view! {
                                                <tr>
                                                    <td>{r.mac.clone()}</td>
                                                    <td>{r.subnet_id}</td>
                                                    <td>
                                                        <ActionForm action=remove_action attr:style="display:inline">
                                                            <input type="hidden" name="mac" value={mac} />
                                                            <button type="submit" class="btn btn-danger btn-sm">"Remove"</button>
                                                        </ActionForm>
                                                        <ErrorToast value=remove_action.value() />
                                                    </td>
                                                </tr>
                                            }
                                        }).collect_view()}
                                    </tbody>
                                </table>
                            </div>
                        }.into_any()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                })}
            </Suspense>

            <Suspense fallback=move || view! { <p>"Loading log config..."</p> }>
                {move || log_config.get().map(|result| match result {
                    Ok(config) => {
                        let log_format = config.get("log_format").and_then(|v| v.as_str()).unwrap_or("text").to_string();
                        let syslog_target = config.get("syslog_target").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let webhook_url = config.get("webhook_url").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let retention = config.get("log_retention_days").and_then(|v| v.as_str()).unwrap_or("7").to_string();

                        let log_action = ServerAction::<SetLogConfig>::new();

                        view! {
                            <div class="settings-section">
                                <h3>"Log Export"</h3>
                                <ActionForm action=log_action>
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
                                </ActionForm>
                                <ErrorToast value=log_action.value() />
                            </div>
                        }.into_any()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
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

                        let runzero_action = ServerAction::<SetRunzeroConfig>::new();
                        let sync_action = ServerAction::<SyncRunzero>::new();

                        view! {
                            <div class="settings-section">
                                <h3>"runZero Integration"</h3>
                                <ActionForm action=runzero_action>
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
                                </ActionForm>
                                <ActionForm action=sync_action attr:style="margin-top: 0.5rem;">
                                    <button type="submit" class="btn btn-sm">"Sync Now"</button>
                                </ActionForm>
                                <ErrorToast value=runzero_action.value() />
                                <ErrorToast value=sync_action.value() />
                            </div>
                        }.into_any()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
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
                                    }.into_any()
                                } else {
                                    view! { <span></span> }.into_any()
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
                                    }.into_any()
                                } else {
                                    view! { <span></span> }.into_any()
                                }}
                            </div>
                        }.into_any()
                    }
                    Err(_) => view! { <span></span> }.into_any(),
                })}
            </Suspense>
            <Suspense fallback=move || view! { <p>"Loading QoS config..."</p> }>
                {move || qos_config.get().map(|result| match result {
                    Ok(config) => {
                        let enabled = config.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
                        let upload_mbps = config.get("upload_mbps").and_then(|v| v.as_u64()).map(|v| v.to_string()).unwrap_or_default();
                        let download_mbps = config.get("download_mbps").and_then(|v| v.as_u64()).map(|v| v.to_string()).unwrap_or_default();
                        let test_url = config.get("test_url").and_then(|v| v.as_str()).unwrap_or("").to_string();

                        let qos_action = ServerAction::<SetQosConfig>::new();
                        let test_url_action = ServerAction::<SetQosTestUrl>::new();
                        let speed_test_action = ServerAction::<RunSpeedTest>::new();

                        view! {
                            <div class="settings-section">
                                <h3>"QoS / Bufferbloat Prevention"</h3>
                                <p class="hint">"CAKE qdisc with per-device fair queuing. Set bandwidth to ~85-90% of your ISP speed."</p>
                                <ActionForm action=qos_action>
                                    <div class="settings-row">
                                        <span class="settings-label">"Enabled"</span>
                                        <span class="settings-value">
                                            <select name="qos_enabled">
                                                <option value="true" selected={enabled}>"Yes"</option>
                                                <option value="false" selected={!enabled}>"No"</option>
                                            </select>
                                        </span>
                                    </div>
                                    <div class="settings-row">
                                        <span class="settings-label">"Upload Speed Mbps"</span>
                                        <span class="settings-value">
                                            <input type="number" name="upload_mbps" min="1" max="1000000" value={upload_mbps} />
                                        </span>
                                    </div>
                                    <div class="settings-row">
                                        <span class="settings-label">"Download Speed Mbps"</span>
                                        <span class="settings-value">
                                            <input type="number" name="download_mbps" min="1" max="1000000" value={download_mbps} />
                                        </span>
                                    </div>
                                    <div class="actions-bar">
                                        <button type="submit" class="btn btn-primary btn-sm">"Save"</button>
                                    </div>
                                </ActionForm>
                                <ActionForm action=test_url_action attr:style="margin-top: 0.5rem;">
                                    <div class="settings-row">
                                        <span class="settings-label">"Speed Test URL"</span>
                                        <span class="settings-value">
                                            <input type="text" name="url" placeholder="https://speed.cloudflare.com/__down?bytes=25000000" value={test_url} />
                                        </span>
                                    </div>
                                    <div class="actions-bar">
                                        <button type="submit" class="btn btn-primary btn-sm">"Save Test URL"</button>
                                    </div>
                                </ActionForm>
                                <ActionForm action=speed_test_action attr:style="margin-top: 0.5rem;">
                                    <button type="submit" class="btn btn-sm">"Run Speed Test"</button>
                                </ActionForm>
                                <ErrorToast value=qos_action.value() />
                                <ErrorToast value=test_url_action.value() />
                                <ErrorToast value=speed_test_action.value() />
                            </div>
                        }.into_any()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                })}
            </Suspense>
            <Suspense fallback=move || view! { <p>"Loading TLS status..."</p> }>
                {move || tls_status.get().map(|result| match result {
                    Ok(status) => {
                        let mode = status.get("tls_mode").and_then(|v| v.as_str()).unwrap_or("self_signed").to_string();
                        let issuer = status.get("issuer").and_then(|v| v.as_str()).unwrap_or("N/A").to_string();
                        let expires_at = status.get("expires_at").and_then(|v| v.as_i64()).unwrap_or(0);
                        let sans: Vec<String> = status.get("sans")
                            .and_then(|v| v.as_array())
                            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                            .unwrap_or_default();
                        let sans_text = sans.join(", ");

                        let mode_text = match mode.as_str() {
                            "self_signed" => "Self-Signed",
                            "custom" => "Custom Certificate",
                            "tailscale" => "Tailscale",
                            "acme_dns01" => "ACME DNS-01 (Cloudflare)",
                            _ => "Unknown",
                        };

                        let self_signed_action = ServerAction::<SetTlsSelfSigned>::new();
                        let custom_action = ServerAction::<SetTlsCustomCert>::new();
                        let tailscale_action = ServerAction::<SetTlsTailscale>::new();
                        let acme_action = ServerAction::<SetTlsAcme>::new();

                        view! {
                            <div class="settings-section">
                                <h3>"TLS Certificate"</h3>
                                <div class="settings-row">
                                    <span class="settings-label">"Mode"</span>
                                    <span class="settings-value">{mode_text}</span>
                                </div>
                                <div class="settings-row">
                                    <span class="settings-label">"Issuer"</span>
                                    <span class="settings-value">{issuer}</span>
                                </div>
                                <div class="settings-row">
                                    <span class="settings-label">"Expires"</span>
                                    <span class="settings-value">{if expires_at > 0 { format_expiry(expires_at) } else { "N/A".to_string() }}</span>
                                </div>
                                <div class="settings-row">
                                    <span class="settings-label">"SANs"</span>
                                    <span class="settings-value">{sans_text}</span>
                                </div>

                                <h4>"Switch to Self-Signed"</h4>
                                <ActionForm action=self_signed_action>
                                    <button type="submit" class="btn btn-sm">"Use Self-Signed"</button>
                                </ActionForm>

                                <h4>"Upload Custom Certificate"</h4>
                                <ActionForm action=custom_action>
                                    <div class="settings-row">
                                        <span class="settings-label">"Certificate PEM"</span>
                                        <span class="settings-value">
                                            <textarea name="cert_pem" rows="4" placeholder="-----BEGIN CERTIFICATE-----"></textarea>
                                        </span>
                                    </div>
                                    <div class="settings-row">
                                        <span class="settings-label">"Private Key PEM"</span>
                                        <span class="settings-value">
                                            <textarea name="key_pem" rows="4" placeholder="-----BEGIN PRIVATE KEY-----"></textarea>
                                        </span>
                                    </div>
                                    <div class="actions-bar">
                                        <button type="submit" class="btn btn-primary btn-sm">"Upload Certificate"</button>
                                    </div>
                                </ActionForm>

                                <h4>"Tailscale HTTPS"</h4>
                                <p class="hint">"Automatically provision a cert for your *.ts.net domain."</p>
                                <ActionForm action=tailscale_action>
                                    <div class="settings-row">
                                        <span class="settings-label">"ts.net Domain"</span>
                                        <span class="settings-value">
                                            <input type="text" name="domain" placeholder="router.tail1234.ts.net" />
                                        </span>
                                    </div>
                                    <div class="actions-bar">
                                        <button type="submit" class="btn btn-primary btn-sm">"Enable Tailscale HTTPS"</button>
                                    </div>
                                </ActionForm>

                                <h4>"ACME DNS-01 (Cloudflare)"</h4>
                                <p class="hint">"Let's Encrypt certificate via Cloudflare DNS. Works behind NAT."</p>
                                <ActionForm action=acme_action>
                                    <div class="settings-row">
                                        <span class="settings-label">"Domain"</span>
                                        <span class="settings-value">
                                            <input type="text" name="domain" placeholder="router.example.com" />
                                        </span>
                                    </div>
                                    <div class="settings-row">
                                        <span class="settings-label">"Email"</span>
                                        <span class="settings-value">
                                            <input type="email" name="email" placeholder="admin@example.com" />
                                        </span>
                                    </div>
                                    <div class="settings-row">
                                        <span class="settings-label">"Cloudflare API Token"</span>
                                        <span class="settings-value">
                                            <input type="password" name="cf_api_token" placeholder="Zone:DNS:Edit token" />
                                        </span>
                                    </div>
                                    <div class="settings-row">
                                        <span class="settings-label">"Cloudflare Zone ID"</span>
                                        <span class="settings-value">
                                            <input type="text" name="cf_zone_id" placeholder="32-char hex" />
                                        </span>
                                    </div>
                                    <div class="actions-bar">
                                        <button type="submit" class="btn btn-primary btn-sm">"Enable ACME DNS-01"</button>
                                    </div>
                                </ActionForm>

                                <ErrorToast value=self_signed_action.value() />
                                <ErrorToast value=custom_action.value() />
                                <ErrorToast value=tailscale_action.value() />
                                <ErrorToast value=acme_action.value() />
                                <p class="hint">"Note: Restart the web UI to apply new certificates."</p>
                            </div>
                        }.into_any()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                })}
            </Suspense>
        </Layout>
    }
}

fn format_expiry(epoch: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let days = (epoch - now) / 86400;
    if days < 0 {
        format!("Expired ({} days ago)", -days)
    } else {
        format!("{} days remaining", days)
    }
}
