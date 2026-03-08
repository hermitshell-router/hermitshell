use leptos::prelude::*;
use crate::client;
use crate::components::layout::Layout;
use crate::components::toast::ErrorToast;
use crate::server_fns::{EnableGuestNetwork, DisableGuestNetwork, RegenerateGuestPassword};

#[component]
pub fn Guest() -> impl IntoView {
    let data = Resource::new(
        || (),
        |_| async move {
            let status = client::guest_network_status();
            let providers = client::wifi_list_providers();
            (status, providers)
        },
    );

    view! {
        <Layout title="Guest Network" active_page="guest network">
            <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                {move || data.get().map(|(status_result, providers_result)| {
                    match (status_result, providers_result) {
                        (Ok(status), Ok(providers)) => {
                            let enabled = status["enabled"].as_bool().unwrap_or(false);
                            if providers.is_empty() {
                                render_no_providers()
                            } else if enabled {
                                render_enabled(status)
                            } else {
                                render_setup(providers)
                            }
                        }
                        (Err(e), _) | (_, Err(e)) => {
                            view! { <p class="text-muted">{format!("Error: {}", e)}</p> }.into_any()
                        }
                    }
                })}
            </Suspense>
        </Layout>
    }
}

fn render_no_providers() -> AnyView {
    view! {
        <div class="card">
            <p class="text-muted">
                "No WiFi providers are configured. A WiFi provider is required to create a guest network."
            </p>
            <a href="/wifi" class="btn btn-primary">"Configure WiFi Providers"</a>
        </div>
    }.into_any()
}

fn render_setup(providers: Vec<hermitshell_common::WifiProviderInfo>) -> AnyView {
    let enable_action = ServerAction::<EnableGuestNetwork>::new();

    view! {
        <div class="card">
            <h2 class="section-header">"Set Up Guest Network"</h2>
            <p class="text-muted">"Create an isolated WiFi network for guests with automatic password rotation."</p>

            <ActionForm action=enable_action>
                <div class="form-grid">
                    <div class="form-group">
                        <label for="guest-provider">"WiFi Provider"</label>
                        <select id="guest-provider" name="provider_id">
                            {providers.iter().map(|p| {
                                let id = p.id.clone();
                                let label = format!("{} ({})", p.name, p.provider_type);
                                view! {
                                    <option value={id}>{label}</option>
                                }
                            }).collect_view()}
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="guest-ssid">"SSID Name"</label>
                        <input type="text" id="guest-ssid" name="ssid_name" value="HermitShell-Guest" required maxlength="32" />
                    </div>
                    <div class="form-group">
                        <label for="guest-password">"Password"</label>
                        <input type="password" id="guest-password" name="password" required minlength="8" maxlength="63"
                            placeholder="Min 8 characters" />
                    </div>
                    <div class="form-group">
                        <label for="guest-band">"Band"</label>
                        <select id="guest-band" name="band">
                            <option value="2.4GHz" selected=true>"2.4 GHz"</option>
                            <option value="5GHz">"5 GHz"</option>
                        </select>
                    </div>
                </div>
                <button type="submit" class="btn btn-primary">"Enable Guest Network"</button>
            </ActionForm>
            <ErrorToast value=enable_action.value() />
        </div>
    }.into_any()
}

fn render_enabled(status: serde_json::Value) -> AnyView {
    let ssid = status["ssid_name"].as_str().unwrap_or("").to_string();
    let password = status["password"].as_str().unwrap_or("").to_string();
    let band = status["band"].as_str().unwrap_or("both").to_string();
    let provider_id = status["provider_id"].as_str().unwrap_or("").to_string();

    let disable_action = ServerAction::<DisableGuestNetwork>::new();
    let regen_action = ServerAction::<RegenerateGuestPassword>::new();

    let qr_data = Resource::new(
        || (),
        |_| async move { crate::server_fns::guest_qr_svg().await },
    );

    let guests = Resource::new(
        || (),
        |_| async move { client::list_devices() },
    );

    view! {
        <div class="card-grid card-grid-2col">
            // QR Code card
            <div class="card">
                <h2 class="section-header">"QR Code"</h2>
                <Suspense fallback=move || view! { <p>"Generating QR code..."</p> }>
                    {move || qr_data.get().map(|result| match result {
                        Ok(svg) => view! {
                            <div inner_html=svg role="img" aria-label="QR code for guest WiFi network"></div>
                        }.into_any(),
                        Err(e) => view! {
                            <p class="text-muted">{format!("QR code error: {}", e)}</p>
                        }.into_any(),
                    })}
                </Suspense>
                <p class="text-muted">"Scan to connect to the guest network"</p>
            </div>

            // Configuration card
            <div class="card">
                <h2 class="section-header">"Configuration"</h2>
                <div class="detail-grid">
                    <div class="detail-item">
                        <span class="detail-label">"SSID"</span>
                        <span class="detail-value">{ssid}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">"Password"</span>
                        <span class="detail-value"><code>{password}</code></span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">"Band"</span>
                        <span class="detail-value">{band}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">"Provider"</span>
                        <span class="detail-value">{provider_id}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">"Status"</span>
                        <span class="detail-value"><span class="badge badge-guest">"Active"</span></span>
                    </div>
                </div>

                <div class="flex-row mt-lg">
                    <ActionForm action=regen_action attr:class="inline-form">
                        <button type="submit" class="btn btn-warning btn-sm">"Regenerate Password"</button>
                    </ActionForm>
                    <button type="button" class="btn btn-danger btn-sm"
                        data-dialog-open="">"Disable Guest Network"</button>
                    <dialog class="confirm-dialog" aria-labelledby="confirm-disable-guest">
                        <h3 id="confirm-disable-guest">"Disable Guest Network?"</h3>
                        <p>"All guests will be disconnected and the guest SSID will be removed."</p>
                        <div class="dialog-actions">
                            <button type="button" class="btn btn-sm"
                                data-dialog-close="">"Cancel"</button>
                            <ActionForm action=disable_action attr:class="inline-form">
                                <button type="submit" class="btn btn-danger btn-sm">"Confirm Disable"</button>
                            </ActionForm>
                        </div>
                    </dialog>
                </div>
                <ErrorToast value=regen_action.value() />
                <ErrorToast value=disable_action.value() />
            </div>
        </div>

        // Connected guests table
        <h2 class="section-header mt-lg">"Connected Guests"</h2>
        <Suspense fallback=move || view! { <p>"Loading..."</p> }>
            {move || guests.get().map(|result| match result {
                Ok(devices) => {
                    let guest_devices: Vec<_> = devices.into_iter()
                        .filter(|d| d.device_group == "guest")
                        .collect();
                    if guest_devices.is_empty() {
                        view! { <p class="text-muted">"No guests currently connected."</p> }.into_any()
                    } else {
                        view! {
                            <table>
                                <thead>
                                    <tr>
                                        <th>"Hostname"</th>
                                        <th>"IP"</th>
                                        <th>"MAC"</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {guest_devices.into_iter().map(|device| {
                                        let hostname = device.hostname.clone().unwrap_or_else(|| "Unknown".to_string());
                                        let ip = device.ipv4.clone().unwrap_or_else(|| "-".to_string());
                                        let device_link = format!("/devices/{}", device.mac);
                                        view! {
                                            <tr>
                                                <td><a href={device_link}>{hostname}</a></td>
                                                <td>{ip}</td>
                                                <td><code>{device.mac.clone()}</code></td>
                                            </tr>
                                        }
                                    }).collect_view()}
                                </tbody>
                            </table>
                        }.into_any()
                    }
                }
                Err(e) => view! { <p class="text-muted">{format!("Error: {}", e)}</p> }.into_any(),
            })}
        </Suspense>
    }.into_any()
}
