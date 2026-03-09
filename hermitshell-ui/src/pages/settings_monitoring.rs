#![allow(clippy::unused_unit, clippy::unit_arg)]
use leptos::prelude::*;
use crate::client;
use crate::components::layout::Layout;
use crate::components::settings_nav::SettingsNav;
use crate::components::toast::ErrorToast;
use crate::format_uptime;
use crate::server_fns::{
    SetAnalyzerEnabled, SetAlertRule,
    SetLogConfig, SetRunzeroConfig, SyncRunzero,
};

#[component]
pub fn SettingsMonitoring() -> impl IntoView {
    let data = Resource::new(
        || (),
        |_| async { client::get_status() },
    );
    let analyzer_status = Resource::new(
        || (),
        |_| async { client::get_analyzer_status() },
    );
    let log_config = Resource::new(
        || (),
        |_| async { client::get_log_config() },
    );
    let runzero_config = Resource::new(
        || (),
        |_| async { client::get_runzero_config() },
    );

    view! {
        <Layout title="Settings" active_page="settings">
            <SettingsNav active="monitoring" />

            <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                {move || data.get().map(|result| match result {
                    Ok(status) => {
                        let uptime = format_uptime(status.uptime_secs);
                        let device_count = status.device_count;
                        let ad_blocking_text = if status.ad_blocking_enabled { "Enabled" } else { "Disabled" };

                        view! {
                            <details class="settings-section">
                                <summary class="settings-section-sub">"Backup & Restore"</summary>
                                <div class="flex-col">
                                    <div>
                                        <h4 class="mb-sm">"Download Backup"</h4>
                                        <form method="post" action="/api/backup/config" class="flex-row-wrap">
                                            <label class="backup-label">
                                                <input type="checkbox" name="secrets" value="1" id="backup-secrets-cb" data-toggle-visibility="#backup-passphrase-row" />
                                                " Include secrets"
                                            </label>
                                            <div id="backup-passphrase-row" style="display:none;align-items:center;gap:0.25rem">
                                                <label class="backup-label">
                                                    <input type="checkbox" id="backup-encrypt-cb" data-toggle-disabled="#backup-passphrase-row" />
                                                    " Encrypt"
                                                </label>
                                                <input type="password" name="passphrase" placeholder="Passphrase" class="input-md" disabled />
                                            </div>
                                            <button type="submit" class="btn btn-primary btn-sm">"Download"</button>
                                        </form>
                                    </div>
                                    <div>
                                        <h4 class="mb-sm">"Restore from Backup"</h4>
                                        <form method="post" action="/api/restore/config" enctype="multipart/form-data" class="flex-row-wrap">
                                            <input type="file" name="file" accept=".json" required />
                                            <input type="password" name="passphrase" placeholder="Passphrase (if encrypted)" class="input-md" />
                                            <button type="button" class="btn btn-primary btn-sm"
                                                data-dialog-open="">"Restore"</button>
                                            <dialog class="confirm-dialog" aria-labelledby="confirm-restore">
                                                <h3 id="confirm-restore">"Restore Configuration?"</h3>
                                                <p>"This will replace your current router configuration. This cannot be undone."</p>
                                                <div class="dialog-actions">
                                                    <button type="button" class="btn btn-sm"
                                                        data-dialog-close="">"Cancel"</button>
                                                    <button type="submit" class="btn btn-danger btn-sm">"Confirm Restore"</button>
                                                </div>
                                            </dialog>
                                        </form>
                                    </div>
                                </div>
                            </details>

                            <details class="settings-section" open>
                                <summary class="settings-section-sub">"System Info"</summary>
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
                            </details>

                            <details class="settings-section">
                                <summary class="settings-section-sub">"Device Classification"</summary>
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
                            </details>

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
                        let rule_statuses: Vec<(String, String, String)> = status.get("rules")
                            .and_then(|v| v.as_object())
                            .map(|rule_map| {
                                let rule_names = [
                                    ("DNS Beaconing", "dns_beaconing"),
                                    ("DNS Volume Spike", "dns_volume_spike"),
                                    ("New Destination Spike", "new_dest_spike"),
                                    ("Suspicious Ports", "suspicious_ports"),
                                    ("Bandwidth Spike", "bandwidth_spike"),
                                ];
                                rule_names.iter().map(|(label, key)| {
                                    let s = rule_map.get(*key)
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("enabled")
                                        .to_string();
                                    (label.to_string(), key.to_string(), s)
                                }).collect()
                            })
                            .unwrap_or_default();

                        let analyzer_action = ServerAction::<SetAnalyzerEnabled>::new();

                        view! {
                            <details class="settings-section" open>
                                <summary class="settings-section-sub">"Behavioral Analysis"</summary>
                                <div class="settings-row">
                                    <span class="settings-label">"Analyzer"</span>
                                    <span class="settings-value">
                                        <ActionForm action=analyzer_action attr:class="inline-form">
                                            <input type="hidden" name="enabled" value={if enabled == "true" { "false" } else { "true" }} />
                                            <button type="submit" class="btn btn-sm">
                                                {if enabled == "true" { "Disable" } else { "Enable" }}
                                            </button>
                                        </ActionForm>
                                        <ErrorToast value=analyzer_action.value() />
                                    </span>
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
                                {rule_statuses.into_iter().map(|(label, key, status)| {
                                    let rule_action = ServerAction::<SetAlertRule>::new();
                                    let is_enabled = status == "enabled";
                                    let toggle_val = if is_enabled { "false" } else { "true" };
                                    view! {
                                        <div class="settings-row">
                                            <span class="settings-label">{label}</span>
                                            <span class="settings-value">
                                                <ActionForm action=rule_action attr:class="inline-form">
                                                    <input type="hidden" name="rule" value={key} />
                                                    <input type="hidden" name="enabled" value={toggle_val} />
                                                    <button type="submit" class="btn btn-sm">
                                                        {if is_enabled { "Disable" } else { "Enable" }}
                                                    </button>
                                                </ActionForm>
                                                <ErrorToast value=rule_action.value() />
                                            </span>
                                        </div>
                                    }
                                }).collect_view()}
                            </details>
                        }.into_any()
                    }
                    Err(_) => view! { <span></span> }.into_any(),
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
                            <details class="settings-section">
                                <summary class="settings-section-sub">"Log Export"</summary>
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
                            </details>
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
                            <details class="settings-section">
                                <summary class="settings-section-sub">"runZero Integration"</summary>
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
                                <ActionForm action=sync_action attr:class="mt-sm">
                                    <button type="submit" class="btn btn-sm">"Sync Now"</button>
                                </ActionForm>
                                <ErrorToast value=runzero_action.value() />
                                <ErrorToast value=sync_action.value() />
                            </details>
                        }.into_any()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                })}
            </Suspense>
        </Layout>
    }
}
