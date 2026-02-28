use leptos::prelude::*;
use crate::client;
use crate::components::toast::ErrorToast;
use crate::server_fns::{SetupInterfaces, SetupWanConfig, SetupHostnameTz};

const TOTAL_STEPS: u32 = 8;

#[component]
fn SetupLayout(
    step: u32,
    title: &'static str,
    children: Children,
) -> impl IntoView {
    let pct = (step as f32 / TOTAL_STEPS as f32 * 100.0) as u32;
    view! {
        <html lang="en">
            <head>
                <meta charset="utf-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1" />
                <title>{format!("Setup ({}/{}) - HermitShell", step, TOTAL_STEPS)}</title>
                <link rel="stylesheet" href="/style.css" />
            </head>
            <body>
                <div class="setup-container">
                    <div class="setup-progress">
                        <span>{format!("Step {} of {}", step, TOTAL_STEPS)}</span>
                        <div class="setup-progress-bar">
                            <div class="setup-progress-fill" style={format!("width: {}%", pct)}></div>
                        </div>
                    </div>
                    <h1>{title}</h1>
                    {children()}
                </div>
            </body>
        </html>
    }
}

/// Step 1: Welcome
#[component]
pub fn SetupStep1() -> impl IntoView {
    view! {
        <html lang="en">
            <head>
                <meta charset="utf-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1" />
                <title>"Setup - HermitShell"</title>
                <link rel="stylesheet" href="/style.css" />
            </head>
            <body>
                <div class="setup-container">
                    <div class="setup-card setup-welcome">
                        <h1>"HermitShell"</h1>
                        <p>"Your network, your rules. No cloud, no controller."</p>
                        <a href="/setup/2" class="btn btn-primary" style="padding: 0.75rem 2rem; font-size: 1rem;">"Get Started"</a>
                    </div>
                </div>
            </body>
        </html>
    }
}

/// Step 2: Interface selection
#[component]
pub fn SetupStep2() -> impl IntoView {
    let interfaces = Resource::new(|| (), |_| async { client::list_interfaces() });
    let action = ServerAction::<SetupInterfaces>::new();

    view! {
        <SetupLayout step=2 title="Network Interfaces">
            <p class="setup-subtitle">"Select which ports connect to the internet and your local network."</p>
            <Suspense fallback=move || view! { <p>"Detecting interfaces..."</p> }>
                {move || {
                    interfaces.get().map(|result| {
                        match result {
                            Ok(ifaces) if !ifaces.is_empty() => {
                                view! {
                                    <div class="setup-card">
                                        <ActionForm action=action>
                                            <label for="wan">"WAN (Internet)"</label>
                                            <select name="wan" id="wan" required>
                                                <option value="">"-- Select interface --"</option>
                                                {ifaces.iter().map(|iface| {
                                                    let name = iface.name.clone();
                                                    let carrier = if iface.has_carrier { "\u{1F7E2}" } else { "\u{1F534}" };
                                                    let label = format!("{} {} ({})", carrier, iface.name, iface.mac);
                                                    view! {
                                                        <option value={name}>
                                                            {label}
                                                        </option>
                                                    }
                                                }).collect_view()}
                                            </select>
                                            <label for="lan">"LAN (Local network)"</label>
                                            <select name="lan" id="lan" required>
                                                <option value="">"-- Select interface --"</option>
                                                {ifaces.iter().map(|iface| {
                                                    let name = iface.name.clone();
                                                    let carrier = if iface.has_carrier { "\u{1F7E2}" } else { "\u{1F534}" };
                                                    let label = format!("{} {} ({})", carrier, iface.name, iface.mac);
                                                    view! {
                                                        <option value={name}>
                                                            {label}
                                                        </option>
                                                    }
                                                }).collect_view()}
                                            </select>
                                            <div class="setup-actions">
                                                <a href="/setup/1" class="setup-back">"Back"</a>
                                                <button type="submit" class="btn btn-primary">"Continue"</button>
                                            </div>
                                        </ActionForm>
                                        <ErrorToast value=action.value() />
                                    </div>
                                }.into_any()
                            }
                            _ => {
                                view! {
                                    <div class="setup-card">
                                        <p>"No physical interfaces detected. If running in Docker, interfaces are configured via environment variables."</p>
                                        <div class="setup-actions">
                                            <a href="/setup/1" class="setup-back">"Back"</a>
                                            <a href="/setup/3" class="btn btn-primary">"Skip"</a>
                                        </div>
                                    </div>
                                }.into_any()
                            }
                        }
                    })
                }}
            </Suspense>
        </SetupLayout>
    }
}

/// Step 3: WAN configuration
#[component]
pub fn SetupStep3() -> impl IntoView {
    let action = ServerAction::<SetupWanConfig>::new();

    view! {
        <SetupLayout step=3 title="WAN Configuration">
            <p class="setup-subtitle">"How does your router connect to the internet?"</p>
            <div class="setup-card">
                <ActionForm action=action>
                    <div class="radio-group">
                        <label>
                            <input type="radio" name="wan_mode" value="dhcp" checked />
                            " DHCP (automatic \u{2014} most common)"
                        </label>
                        <label>
                            <input type="radio" name="wan_mode" value="static" />
                            " Static IP"
                        </label>
                        <div class="wan-static-fields">
                            <label for="static_ip">"IP Address"</label>
                            <input type="text" name="static_ip" id="static_ip" placeholder="192.168.1.2" />
                            <label for="gateway">"Gateway"</label>
                            <input type="text" name="gateway" id="gateway" placeholder="192.168.1.1" />
                            <label for="dns">"DNS Server"</label>
                            <input type="text" name="dns" id="dns" placeholder="1.1.1.1" />
                        </div>
                    </div>
                    <div class="setup-actions">
                        <a href="/setup/2" class="setup-back">"Back"</a>
                        <button type="submit" class="btn btn-primary">"Continue"</button>
                    </div>
                </ActionForm>
                <ErrorToast value=action.value() />
            </div>
        </SetupLayout>
    }
}

/// Step 4: Hostname & Timezone
#[component]
pub fn SetupStep4() -> impl IntoView {
    let action = ServerAction::<SetupHostnameTz>::new();

    let common_timezones = vec![
        "UTC",
        "America/New_York",
        "America/Chicago",
        "America/Denver",
        "America/Los_Angeles",
        "America/Toronto",
        "America/Sao_Paulo",
        "Europe/London",
        "Europe/Berlin",
        "Europe/Paris",
        "Asia/Tokyo",
        "Asia/Shanghai",
        "Asia/Kolkata",
        "Australia/Sydney",
        "Pacific/Auckland",
    ];

    view! {
        <SetupLayout step=4 title="Hostname & Timezone">
            <p class="setup-subtitle">"Name your router and set the local timezone."</p>
            <div class="setup-card">
                <ActionForm action=action>
                    <label for="hostname">"Router Hostname"</label>
                    <input type="text" name="hostname" id="hostname" value="hermitshell" required />
                    <label for="timezone">"Timezone"</label>
                    <select name="timezone" id="timezone" required>
                        {common_timezones.iter().map(|tz| {
                            let selected = *tz == "UTC";
                            view! {
                                <option value={*tz} selected=selected>{*tz}</option>
                            }
                        }).collect_view()}
                    </select>
                    <div class="setup-actions">
                        <a href="/setup/3" class="setup-back">"Back"</a>
                        <button type="submit" class="btn btn-primary">"Continue"</button>
                    </div>
                </ActionForm>
                <ErrorToast value=action.value() />
            </div>
        </SetupLayout>
    }
}

/// Step 5: DNS & Ad blocking
#[component]
pub fn SetupStep5() -> impl IntoView {
    let action = ServerAction::<crate::server_fns::SetupDns>::new();

    view! {
        <SetupLayout step=5 title="DNS & Ad Blocking">
            <p class="setup-subtitle">"Choose your upstream DNS provider and enable built-in ad blocking."</p>
            <div class="setup-card">
                <ActionForm action=action>
                    <div class="radio-group">
                        <label>
                            <input type="radio" name="upstream_dns" value="auto" checked />
                            " Automatic (from your ISP)"
                        </label>
                        <label>
                            <input type="radio" name="upstream_dns" value="cloudflare" />
                            " Cloudflare (1.1.1.1)"
                        </label>
                        <label>
                            <input type="radio" name="upstream_dns" value="google" />
                            " Google (8.8.8.8)"
                        </label>
                        <label>
                            <input type="radio" name="upstream_dns" value="quad9" />
                            " Quad9 (9.9.9.9)"
                        </label>
                    </div>
                    <div class="checkbox-group" style="margin-top: 1rem;">
                        <label>
                            <input type="checkbox" name="ad_blocking" value="on" checked />
                            " Enable ad blocking"
                        </label>
                    </div>
                    <div class="setup-actions">
                        <a href="/setup/4" class="setup-back">"Back"</a>
                        <button type="submit" class="btn btn-primary">"Continue"</button>
                    </div>
                </ActionForm>
                <ErrorToast value=action.value() />
            </div>
        </SetupLayout>
    }
}

/// Step 6: Admin password
#[component]
pub fn SetupStep6() -> impl IntoView {
    let action = ServerAction::<crate::server_fns::SetupPasswordStep>::new();

    view! {
        <SetupLayout step=6 title="Admin Password">
            <p class="setup-subtitle">"Set a password to secure your router\u{2019}s web interface."</p>
            <div class="setup-card">
                <ActionForm action=action>
                    <label for="password">"Password"</label>
                    <input type="password" name="password" id="password" required autofocus minlength="8" />
                    <label for="confirm">"Confirm Password"</label>
                    <input type="password" name="confirm" id="confirm" required minlength="8" />
                    <div class="setup-actions">
                        <a href="/setup/5" class="setup-back">"Back"</a>
                        <button type="submit" class="btn btn-primary">"Continue"</button>
                    </div>
                </ActionForm>
                <ErrorToast value=action.value() />
            </div>
        </SetupLayout>
    }
}

/// Step 7: WiFi AP (optional)
#[component]
pub fn SetupStep7() -> impl IntoView {
    let action = ServerAction::<crate::server_fns::SetupWifiProvider>::new();

    view! {
        <SetupLayout step=7 title="WiFi Access Point">
            <p class="setup-subtitle">"Connect a WiFi access point for unified management. This step is optional."</p>
            <a href="/setup/8" class="setup-skip">"Skip this step"</a>
            <div class="setup-card">
                <ActionForm action=action>
                    <label for="provider_type">"AP Type"</label>
                    <select name="provider_type" id="provider_type" required>
                        <option value="unifi">"UniFi Controller"</option>
                        <option value="eap_standalone">"TP-Link EAP (standalone)"</option>
                    </select>
                    <label for="name">"Name"</label>
                    <input type="text" name="name" id="name" required placeholder="My WiFi AP" />
                    <label for="url">"URL"</label>
                    <input type="text" name="url" id="url" required placeholder="https://192.168.1.1" />
                    <label for="username">"Username"</label>
                    <input type="text" name="username" id="username" required placeholder="admin" />
                    <label for="password">"Password"</label>
                    <input type="password" name="password" id="password" required />
                    <label for="site">"Site (UniFi only)"</label>
                    <input type="text" name="site" id="site" placeholder="default" />
                    <label for="api_key">"API Key (UniFi only)"</label>
                    <input type="text" name="api_key" id="api_key" placeholder="Optional" />
                    <div class="setup-actions">
                        <a href="/setup/6" class="setup-back">"Back"</a>
                        <button type="submit" class="btn btn-primary">"Add & Continue"</button>
                    </div>
                </ActionForm>
                <ErrorToast value=action.value() />
            </div>
        </SetupLayout>
    }
}

/// Step 8: Summary
#[component]
pub fn SetupStep8() -> impl IntoView {
    let summary = Resource::new(|| (), |_| async { client::setup_get_summary() });
    let action = ServerAction::<crate::server_fns::SetupFinalize>::new();

    view! {
        <SetupLayout step=8 title="Review & Finish">
            <p class="setup-subtitle">"Review your settings. You can change these later from the Settings page."</p>
            <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                {move || {
                    summary.get().map(|result| {
                        match result {
                            Ok(s) => {
                                let wan_iface = s.get("wan_iface").and_then(|v| v.as_str()).unwrap_or("-").to_string();
                                let lan_iface = s.get("lan_iface").and_then(|v| v.as_str()).unwrap_or("-").to_string();
                                let wan_mode = s.get("wan_mode").and_then(|v| v.as_str()).unwrap_or("dhcp").to_string();
                                let wan_static_ip = s.get("wan_static_ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                let wan_static_gw = s.get("wan_static_gateway").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                let wan_static_dns = s.get("wan_static_dns").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                let is_static = wan_mode == "static";
                                let hostname = s.get("hostname").and_then(|v| v.as_str()).unwrap_or("hermitshell").to_string();
                                let timezone = s.get("timezone").and_then(|v| v.as_str()).unwrap_or("UTC").to_string();
                                let upstream_dns = s.get("upstream_dns").and_then(|v| v.as_str()).unwrap_or("auto").to_string();
                                let ad_blocking = s.get("ad_blocking").and_then(|v| v.as_bool()).unwrap_or(true);

                                let dns_label = match upstream_dns.as_str() {
                                    "auto" => "Automatic (ISP)".to_string(),
                                    "1.1.1.1,1.0.0.1" => "Cloudflare".to_string(),
                                    "8.8.8.8,8.8.4.4" => "Google".to_string(),
                                    "9.9.9.9,149.112.112.112" => "Quad9".to_string(),
                                    other => other.to_string(),
                                };

                                view! {
                                    <div class="setup-card">
                                        <div class="setup-summary-row">
                                            <span class="setup-summary-label">"WAN Interface"</span>
                                            <span class="setup-summary-value">{wan_iface}</span>
                                        </div>
                                        <div class="setup-summary-row">
                                            <span class="setup-summary-label">"LAN Interface"</span>
                                            <span class="setup-summary-value">{lan_iface}</span>
                                        </div>
                                        <div class="setup-summary-row">
                                            <span class="setup-summary-label">"WAN Mode"</span>
                                            <span class="setup-summary-value">{wan_mode.to_uppercase()}</span>
                                        </div>
                                        {if is_static {
                                            view! {
                                                <div class="setup-summary-row">
                                                    <span class="setup-summary-label">"Static IP"</span>
                                                    <span class="setup-summary-value">{wan_static_ip}</span>
                                                </div>
                                                <div class="setup-summary-row">
                                                    <span class="setup-summary-label">"Gateway"</span>
                                                    <span class="setup-summary-value">{wan_static_gw}</span>
                                                </div>
                                                <div class="setup-summary-row">
                                                    <span class="setup-summary-label">"WAN DNS"</span>
                                                    <span class="setup-summary-value">{wan_static_dns}</span>
                                                </div>
                                            }.into_any()
                                        } else {
                                            view! {}.into_any()
                                        }}
                                        <div class="setup-summary-row">
                                            <span class="setup-summary-label">"Hostname"</span>
                                            <span class="setup-summary-value">{hostname}</span>
                                        </div>
                                        <div class="setup-summary-row">
                                            <span class="setup-summary-label">"Timezone"</span>
                                            <span class="setup-summary-value">{timezone}</span>
                                        </div>
                                        <div class="setup-summary-row">
                                            <span class="setup-summary-label">"DNS"</span>
                                            <span class="setup-summary-value">{dns_label}</span>
                                        </div>
                                        <div class="setup-summary-row">
                                            <span class="setup-summary-label">"Ad Blocking"</span>
                                            <span class="setup-summary-value">{if ad_blocking { "Enabled" } else { "Disabled" }}</span>
                                        </div>
                                    </div>
                                    <ActionForm action=action>
                                        <div class="setup-actions">
                                            <a href="/setup/7" class="setup-back">"Back"</a>
                                            <button type="submit" class="btn btn-primary" style="padding: 0.75rem 2rem;">"Finish Setup"</button>
                                        </div>
                                    </ActionForm>
                                    <ErrorToast value=action.value() />
                                }.into_any()
                            }
                            Err(_) => {
                                view! {
                                    <p>"Failed to load summary."</p>
                                }.into_any()
                            }
                        }
                    })
                }}
            </Suspense>
        </SetupLayout>
    }
}

/// Legacy redirect: old /setup URL goes to step 1
#[component]
pub fn Setup() -> impl IntoView {
    view! {
        <html lang="en">
            <head>
                <meta http-equiv="refresh" content="0;url=/setup/1" />
            </head>
            <body></body>
        </html>
    }
}
