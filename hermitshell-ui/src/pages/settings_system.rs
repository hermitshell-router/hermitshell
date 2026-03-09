#![allow(clippy::unused_unit, clippy::unit_arg)]
use leptos::prelude::*;
use crate::client;
use crate::components::layout::Layout;
use crate::components::settings_nav::SettingsNav;
use crate::components::toast::ErrorToast;
use crate::server_fns::{
    ApplyUpdate, SetAutoUpdate,
    ChangePassword,
    TotpSetup, TotpEnable, TotpDisable,
    SetTlsCustomCert, SetTlsSelfSigned, SetTlsTailscale, SetTlsAcme,
};

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

#[component]
pub fn SettingsSystem() -> impl IntoView {
    let update_info = Resource::new(
        || (),
        |_| async { client::check_update() },
    );
    let totp_status = Resource::new(
        || (),
        |_| async { client::totp_status() },
    );
    let tls_status = Resource::new(
        || (),
        |_| async { client::get_tls_status() },
    );
    let password_action = ServerAction::<ChangePassword>::new();

    view! {
        <Layout title="Settings" active_page="settings">
            <SettingsNav active="system" />

            // ─── Software Update ───
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
                            <details class="settings-section" open>
                                <summary class="settings-section-sub">"Software Update"</summary>
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
                                        <div class="settings-row mt-sm">
                                            <span class="settings-label">"Auto-update"</span>
                                            <span class="settings-value">
                                                <ActionForm action=auto_update_action attr:class="inline-form">
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
                            </details>
                        }.into_any()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                })}
            </Suspense>

            // ─── Change Password ───
            <details class="settings-section" open>
                <summary class="settings-section-sub">"Change Password"</summary>
                <ActionForm action=password_action>
                    <div class="settings-row">
                        <span class="settings-label">"Current Password"</span>
                        <span class="settings-value"><input type="password" name="current_password" autocomplete="current-password" required /></span>
                    </div>
                    <div class="settings-row">
                        <span class="settings-label">"New Password"</span>
                        <span class="settings-value"><input type="password" name="new_password" autocomplete="new-password" required /></span>
                    </div>
                    <div class="settings-row">
                        <span class="settings-label">"Confirm New Password"</span>
                        <span class="settings-value"><input type="password" name="confirm_password" autocomplete="new-password" required /></span>
                    </div>
                    <div class="actions-bar">
                        <button type="submit" class="btn btn-primary btn-sm">"Change Password"</button>
                    </div>
                </ActionForm>
                <ErrorToast value=password_action.value() />
            </details>

            // ─── Two-Factor Authentication ───
            <details class="settings-section" open id="two-factor">
                <summary class="settings-section-sub">"Two-Factor Authentication"</summary>
                <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                    {move || totp_status.get().map(|result| match result {
                        Ok(true) => {
                            let disable_action = ServerAction::<TotpDisable>::new();
                            view! {
                                <p class="text-sm">
                                    <span class="badge badge-ok">"Enabled"</span>
                                    " Two-factor authentication is active."
                                </p>
                                <ActionForm action=disable_action>
                                    <div class="settings-row">
                                        <span class="settings-label">"Password"</span>
                                        <span class="settings-value"><input type="password" name="password" required placeholder="Enter password to disable" /></span>
                                    </div>
                                    <div class="actions-bar">
                                        <button type="submit" class="btn btn-sm btn-danger">"Disable 2FA"</button>
                                    </div>
                                </ActionForm>
                                <ErrorToast value=disable_action.value() />
                            }.into_any()
                        }
                        Ok(false) => {
                            let setup_action = ServerAction::<TotpSetup>::new();
                            let enable_action = ServerAction::<TotpEnable>::new();
                            view! {
                                <p class="text-sm text-muted">"Add a second layer of security using an authenticator app."</p>
                                {move || {
                                    match setup_action.value().get() {
                                        Some(Ok(json_str)) => {
                                            let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap_or_default();
                                            let secret = parsed["secret"].as_str().unwrap_or("").to_string();
                                            let uri = parsed["uri"].as_str().unwrap_or("").to_string();

                                            let qr_svg = qrcode::QrCode::new(uri.as_bytes())
                                                .map(|code| code.render::<qrcode::render::svg::Color>()
                                                    .min_dimensions(200, 200)
                                                    .build())
                                                .unwrap_or_default();

                                            view! {
                                                <div class="totp-setup">
                                                    <p class="text-sm">"Scan this QR code with your authenticator app:"</p>
                                                    <div class="qr-code" inner_html=qr_svg></div>
                                                    <p class="text-sm text-muted">"Or enter this secret manually: "<code>{secret}</code></p>
                                                    <ActionForm action=enable_action>
                                                        <div class="settings-row">
                                                            <span class="settings-label">"Verification Code"</span>
                                                            <span class="settings-value">
                                                                <input
                                                                    type="text"
                                                                    name="code"
                                                                    inputmode="numeric"
                                                                    pattern="[0-9]{6}"
                                                                    maxlength="6"
                                                                    autocomplete="one-time-code"
                                                                    required
                                                                    autofocus
                                                                    placeholder="000000"
                                                                />
                                                            </span>
                                                        </div>
                                                        <div class="actions-bar">
                                                            <button type="submit" class="btn btn-primary btn-sm">"Enable 2FA"</button>
                                                        </div>
                                                    </ActionForm>
                                                    <ErrorToast value=enable_action.value() />
                                                </div>
                                            }.into_any()
                                        }
                                        _ => {
                                            view! {
                                                <ActionForm action=setup_action>
                                                    <div class="actions-bar">
                                                        <button type="submit" class="btn btn-primary btn-sm">"Set Up 2FA"</button>
                                                    </div>
                                                </ActionForm>
                                            }.into_any()
                                        }
                                    }
                                }}
                            }.into_any()
                        }
                        Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                    })}
                </Suspense>
            </details>

            // ─── TLS Certificate ───
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
                            <details class="settings-section">
                                <summary class="settings-section-sub">"TLS Certificate"</summary>
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
                            </details>
                        }.into_any()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                })}
            </Suspense>
        </Layout>
    }
}
