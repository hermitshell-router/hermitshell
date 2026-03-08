use leptos::prelude::*;
use leptos_router::hooks::use_query_map;
use crate::client;
use crate::components::layout::Layout;
use crate::components::toast::ErrorToast;
use crate::server_fns::{AddWifiProvider, RemoveWifiProvider, SetWifiSsid, DeleteWifiSsid, SetWifiRadio, WifiKickClient};

#[component]
pub fn Wifi() -> impl IntoView {
    let query = use_query_map();
    let selected_ap = move || query.with(|q| q.get("ap"));
    let selected_provider = move || query.with(|q| q.get("provider"));

    let providers = Resource::new(
        || (),
        |_| async { client::wifi_list_providers() },
    );
    let aps = Resource::new(
        || (),
        |_| async { client::wifi_list_aps() },
    );
    let clients = Resource::new(
        || (),
        |_| async { client::wifi_get_clients() },
    );
    let add_provider_action = ServerAction::<AddWifiProvider>::new();
    let remove_provider_action = ServerAction::<RemoveWifiProvider>::new();
    let set_ssid_action = ServerAction::<SetWifiSsid>::new();
    let delete_ssid_action = ServerAction::<DeleteWifiSsid>::new();
    let set_radio_action = ServerAction::<SetWifiRadio>::new();

    view! {
        <Layout title="WiFi" active_page="wifi">
            // --- Providers ---
            <div class="settings-section">
                <h3>"WiFi Providers"</h3>
                <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                    {move || providers.get().map(|result| match result {
                        Ok(provs) => {
                            if provs.is_empty() {
                                view! { <p class="text-muted">"No WiFi providers configured."</p> }.into_any()
                            } else {
                                view! {
                                    <div class="table-scroll">
                                    <table class="device-table">
                                        <thead>
                                            <tr>
                                                <th>"Name"</th>
                                                <th>"Type"</th>
                                                <th>"URL"</th>
                                                <th>"Status"</th>
                                                <th>"APs"</th>
                                                <th></th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {provs.iter().map(|p| {
                                                let id = p.id.clone();
                                                let id2 = p.id.clone();
                                                let prov_dialog_id = format!("confirm-rm-prov-{}", id2);
                                                let type_label = match p.provider_type.as_str() {
                                                    "eap_standalone" => "TP-Link EAP",
                                                    "unifi" => "UniFi",
                                                    other => other,
                                                };
                                                view! {
                                                    <tr>
                                                        <td>{p.name.clone()}</td>
                                                        <td>{type_label.to_string()}</td>
                                                        <td>{p.url.clone()}</td>
                                                        <td>{p.status.clone()}</td>
                                                        <td>{p.ap_count.to_string()}</td>
                                                        <td>
                                                            <a href={format!("/wifi?provider={}", id)} class="btn btn-sm">"Manage SSIDs"</a>
                                                            " "
                                                            <button type="button" class="btn btn-sm btn-danger"
                                                                onclick="this.nextElementSibling.showModal()">"Remove"</button>
                                                            <dialog class="confirm-dialog" aria-labelledby={prov_dialog_id.clone()}>
                                                                <h3 id={prov_dialog_id.clone()}>"Remove WiFi Provider?"</h3>
                                                                <p>{format!("\"{}\" will be permanently removed.", p.name)}</p>
                                                                <div class="dialog-actions">
                                                                    <button type="button" class="btn btn-sm"
                                                                        onclick="this.closest('dialog').close()">"Cancel"</button>
                                                                    <ActionForm action=remove_provider_action attr:class="inline-form">
                                                                        <input type="hidden" name="id" value={id2} />
                                                                        <button type="submit" class="btn btn-sm btn-danger">"Confirm Remove"</button>
                                                                    </ActionForm>
                                                                </div>
                                                            </dialog>
                                                        </td>
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
                <ErrorToast value=remove_provider_action.value() />
            </div>

            // --- Provider Detail (SSIDs) ---
            {move || {
                let sel = selected_provider();
                sel.map(|pid| {
                    let pid2 = pid.clone();
                    view! {
                        <div class="settings-section">
                            <h3>{"SSIDs for Provider"}</h3>
                            <ProviderDetail provider_id=pid2
                                set_ssid_action=set_ssid_action
                                delete_ssid_action=delete_ssid_action />
                        </div>
                    }
                })
            }}

            // --- Add Provider ---
            <div class="settings-section">
                <h3>"Add WiFi Provider"</h3>
                <ActionForm action=add_provider_action>
                    <div class="form-grid">
                        <div class="form-group">
                            <label for="provider-type">"Provider Type"</label>
                            <select id="provider-type" name="provider_type">
                                <option value="eap_standalone">"TP-Link EAP (standalone)"</option>
                                <option value="unifi">"UniFi Controller"</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label for="provider-name">"Name"</label>
                            <input type="text" id="provider-name" name="name" placeholder="Office WiFi" required />
                        </div>
                        <div class="form-group">
                            <label for="provider-username">"Username"</label>
                            <input type="text" id="provider-username" name="username" value="admin" />
                        </div>
                        <div class="form-group">
                            <label for="provider-password">"Password"</label>
                            <input type="password" id="provider-password" name="password" required />
                        </div>
                    </div>
                    <p class="text-muted my-sm">"For TP-Link EAP (standalone):"</p>
                    <div class="form-grid">
                        <div class="form-group">
                            <label for="provider-mac">"AP MAC Address"</label>
                            <input type="text" id="provider-mac" name="mac" placeholder="aa:bb:cc:dd:ee:ff" />
                        </div>
                        <div class="form-group">
                            <label for="provider-url-eap">"AP IP Address"</label>
                            <input type="text" id="provider-url-eap" name="url" placeholder="192.168.1.100" />
                        </div>
                    </div>
                    <p class="text-muted my-sm">"For UniFi Controller:"</p>
                    <div class="form-grid">
                        <div class="form-group">
                            <label for="provider-site">"Site"</label>
                            <input type="text" id="provider-site" name="site" placeholder="default" />
                        </div>
                        <div class="form-group">
                            <label for="provider-api-key">"API Key (optional)"</label>
                            <input type="text" id="provider-api-key" name="api_key" placeholder="(optional)" />
                        </div>
                    </div>
                    <button type="submit" class="btn">"Add Provider"</button>
                </ActionForm>
                <ErrorToast value=add_provider_action.value() />
            </div>

            // --- Access Points ---
            <div class="settings-section">
                <h3>"Access Points"</h3>
                <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                    {move || {
                        let sel = selected_ap();
                        aps.get().map(|result| match result {
                        Ok(aps) => {
                            if aps.is_empty() {
                                view! { <p class="text-muted">"No access points discovered."</p> }.into_any()
                            } else {
                                view! {
                                    <div class="table-scroll">
                                    <table class="device-table">
                                        <thead>
                                            <tr>
                                                <th>"Name"</th>
                                                <th>"MAC"</th>
                                                <th>"IP"</th>
                                                <th>"Provider"</th>
                                                <th>"Status"</th>
                                                <th></th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {aps.iter().map(|ap| {
                                                let mac = ap.mac.clone();
                                                let is_expanded = sel.as_deref() == Some(ap.mac.as_str());
                                                view! {
                                                    <tr>
                                                        <td>{ap.name.clone()}</td>
                                                        <td>{ap.mac.clone()}</td>
                                                        <td>{ap.ip.clone()}</td>
                                                        <td>{ap.provider.clone()}</td>
                                                        <td>{ap.status.clone()}</td>
                                                        <td>
                                                            {if is_expanded {
                                                                view! { <a href="/wifi" class="btn btn-sm">"Close"</a> }.into_any()
                                                            } else {
                                                                view! { <a href={format!("/wifi?ap={}", mac)} class="btn btn-sm">"Manage"</a> }.into_any()
                                                            }}
                                                        </td>
                                                    </tr>
                                                    {if is_expanded {
                                                        let ap_mac = ap.mac.clone();
                                                        let ap_clients: Vec<_> = clients.get()
                                                            .and_then(|r| r.ok())
                                                            .unwrap_or_default()
                                                            .into_iter()
                                                            .filter(|c| c.ap_mac == ap.mac)
                                                            .collect();
                                                        Some(view! {
                                                            <tr>
                                                                <td colspan="6">
                                                                    <ApDetail mac=ap_mac
                                                                        ap_clients=ap_clients
                                                                        set_radio_action=set_radio_action />
                                                                </td>
                                                            </tr>
                                                        })
                                                    } else {
                                                        None
                                                    }}
                                                }
                                            }).collect_view()}
                                        </tbody>
                                    </table>
                                    </div>
                                    <ErrorToast value=set_radio_action.value() />
                                }.into_any()
                            }
                        }
                        Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                    })}}
                </Suspense>
            </div>

            // --- WiFi Clients ---
            <div class="settings-section">
                <h3>"WiFi Clients"</h3>
                <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                    {move || {
                        let first_provider_id = providers.get()
                            .and_then(|r| r.ok())
                            .and_then(|p| p.first().map(|prov| prov.id.clone()))
                            .unwrap_or_default();
                        clients.get().map(|result| match result {
                        Ok(clients) => {
                            if clients.is_empty() {
                                view! { <p class="text-muted">"No WiFi clients detected."</p> }.into_any()
                            } else {
                                view! {
                                    <div class="table-scroll">
                                    <table class="device-table">
                                        <thead>
                                            <tr>
                                                <th>"MAC"</th>
                                                <th>"AP"</th>
                                                <th>"SSID"</th>
                                                <th>"Band"</th>
                                                <th>"RSSI"</th>
                                                <th>"Actions"</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {clients.iter().map(|c| {
                                                let rssi_str = c.rssi.map(|r| format!("{} dBm", r)).unwrap_or_else(|| "\u{2014}".to_string());
                                                let kick_action = ServerAction::<WifiKickClient>::new();
                                                let pid = first_provider_id.clone();
                                                let client_mac = c.mac.clone();
                                                view! {
                                                    <tr>
                                                        <td>{c.mac.clone()}</td>
                                                        <td>{c.ap_mac.clone()}</td>
                                                        <td>{c.ssid.clone()}</td>
                                                        <td>{c.band.clone()}</td>
                                                        <td>{rssi_str}</td>
                                                        <td>
                                                            <ActionForm action=kick_action attr:class="inline-form">
                                                                <input type="hidden" name="provider_id" value={pid} />
                                                                <input type="hidden" name="mac" value={client_mac} />
                                                                <button type="submit" class="btn btn-warning btn-sm">"Kick"</button>
                                                            </ActionForm>
                                                        </td>
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
                    })}}
                </Suspense>
            </div>
        </Layout>
    }
}

/// Provider detail: shows SSIDs for a provider with add/edit/delete forms.
#[component]
fn ProviderDetail(
    provider_id: String,
    set_ssid_action: ServerAction<SetWifiSsid>,
    delete_ssid_action: ServerAction<DeleteWifiSsid>,
) -> impl IntoView {
    let pid_for_ssids = provider_id.clone();
    let pid_for_form = provider_id.clone();
    let pid_for_view = provider_id.clone();

    let ssids = Resource::new(
        || (),
        move |_| {
            let p = pid_for_ssids.clone();
            async move { client::wifi_get_ssids(&p) }
        },
    );

    view! {
        <div class="ap-detail">
            <h4>"SSIDs"</h4>
            <Suspense fallback=move || view! { <p>"Loading SSIDs..."</p> }>
                {move || {
                    let pid_c = pid_for_view.clone();
                    ssids.get().map(move |result| match result {
                    Ok(ssids) => {
                        let ssids = ssids.clone();
                        if ssids.is_empty() {
                            view! { <p class="text-muted">"No SSIDs configured."</p> }.into_any()
                        } else {
                            view! {
                                <div class="table-scroll">
                                <table class="device-table">
                                    <thead>
                                        <tr>
                                            <th>"Name"</th>
                                            <th>"Band"</th>
                                            <th>"Security"</th>
                                            <th>"Hidden"</th>
                                            <th>"Enabled"</th>
                                            <th></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {ssids.into_iter().map(|s| {
                                            let pid_del = pid_c.clone();
                                            let ssid_display = s.ssid_name.clone();
                                            let ssid_msg = format!("\"{}\" will be permanently deleted.", s.ssid_name);
                                            let ssid_dialog_id = format!("confirm-del-ssid-{}", s.ssid_name);
                                            let ssid_hidden = s.ssid_name;
                                            let band_display = s.band.clone();
                                            let band_hidden = s.band;
                                            view! {
                                                <tr>
                                                    <td>{ssid_display}</td>
                                                    <td>{band_display}</td>
                                                    <td>{s.security.clone()}</td>
                                                    <td>{if s.hidden { "Yes" } else { "No" }}</td>
                                                    <td>{if s.enabled { "Yes" } else { "No" }}</td>
                                                    <td>
                                                        <button type="button" class="btn btn-sm btn-danger"
                                                            onclick="this.nextElementSibling.showModal()">"Delete"</button>
                                                        <dialog class="confirm-dialog" aria-labelledby={ssid_dialog_id.clone()}>
                                                            <h3 id={ssid_dialog_id.clone()}>"Delete SSID?"</h3>
                                                            <p>{ssid_msg}</p>
                                                            <div class="dialog-actions">
                                                                <button type="button" class="btn btn-sm"
                                                                    onclick="this.closest('dialog').close()">"Cancel"</button>
                                                                <ActionForm action=delete_ssid_action attr:class="inline-form">
                                                                    <input type="hidden" name="provider_id" value={pid_del} />
                                                                    <input type="hidden" name="ssid_name" value={ssid_hidden} />
                                                                    <input type="hidden" name="band" value={band_hidden} />
                                                                    <button type="submit" class="btn btn-sm btn-danger">"Confirm Delete"</button>
                                                                </ActionForm>
                                                            </div>
                                                        </dialog>
                                                    </td>
                                                </tr>
                                            }
                                        }).collect_view()}
                                    </tbody>
                                </table>
                                </div>
                            }.into_any()
                        }
                    }
                    Err(e) => view! { <p class="error">{format!("Error loading SSIDs: {}", e)}</p> }.into_any(),
                })}}
            </Suspense>

            <h4>"Add / Edit SSID"</h4>
            <ActionForm action=set_ssid_action>
                <input type="hidden" name="provider_id" value={pid_for_form} />
                <div class="form-grid">
                    <div class="form-group">
                        <label>"SSID Name"</label>
                        <input type="text" name="ssid_name" required maxlength="32" />
                    </div>
                    <div class="form-group">
                        <label>"Password"</label>
                        <input type="password" name="password" placeholder="(leave blank for open)" />
                    </div>
                    <div class="form-group">
                        <label>"Band"</label>
                        <select name="band">
                            <option value="2.4GHz">"2.4 GHz"</option>
                            <option value="5GHz">"5 GHz"</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>"Security"</label>
                        <select name="security">
                            <option value="wpa2_wpa3">"WPA2/WPA3"</option>
                            <option value="wpa-psk">"WPA-PSK"</option>
                            <option value="none">"None (Open)"</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>
                            <input type="checkbox" name="hidden" />
                            " Hidden"
                        </label>
                    </div>
                </div>
                <button type="submit" class="btn">"Save SSID"</button>
            </ActionForm>
            <ErrorToast value=set_ssid_action.value() />
            <ErrorToast value=delete_ssid_action.value() />
        </div>
    }
}

/// AP detail: shows radio config and connected clients (no SSIDs -- those are on the provider).
#[component]
fn ApDetail(
    mac: String,
    ap_clients: Vec<hermitshell_common::WifiClient>,
    set_radio_action: ServerAction<SetWifiRadio>,
) -> impl IntoView {
    let mac_for_radios = mac.clone();

    let radios = Resource::new(
        || (),
        move |_| {
            let m = mac_for_radios.clone();
            async move { client::wifi_get_radios(&m) }
        },
    );

    view! {
        <div class="ap-detail">
            // --- Radios ---
            <h4>"Radios"</h4>
            <Suspense fallback=move || view! { <p>"Loading radios..."</p> }>
                {move || {
                    let mac_r = mac.clone();
                    radios.get().map(move |result| match result {
                    Ok(radios) => {
                        let radios = radios.clone();
                        if radios.is_empty() {
                            view! { <p class="text-muted">"No radio information available."</p> }.into_any()
                        } else {
                            view! {
                                {radios.into_iter().map(|r| {
                                    let mac_rf = mac_r.clone();
                                    let band_val = r.band.clone();
                                    let sel_20 = r.channel_width == "20MHz";
                                    let sel_40 = r.channel_width == "40MHz";
                                    let sel_80 = r.channel_width == "80MHz";
                                    let sel_160 = r.channel_width == "160MHz";
                                    let sel_auto = r.channel_width == "Auto";
                                    view! {
                                        <div class="radio-card">
                                            <strong>{r.band.clone()}</strong>
                                            <ActionForm action=set_radio_action>
                                                <input type="hidden" name="mac" value={mac_rf} />
                                                <input type="hidden" name="band" value={band_val} />
                                                <div class="form-grid">
                                                    <div class="form-group">
                                                        <label>"Channel"</label>
                                                        <input type="text" name="channel" value={r.channel} />
                                                    </div>
                                                    <div class="form-group">
                                                        <label>"Width"</label>
                                                        <select name="channel_width">
                                                            <option value="20MHz" selected={sel_20}>"20 MHz"</option>
                                                            <option value="40MHz" selected={sel_40}>"40 MHz"</option>
                                                            <option value="80MHz" selected={sel_80}>"80 MHz"</option>
                                                            <option value="160MHz" selected={sel_160}>"160 MHz"</option>
                                                            <option value="Auto" selected={sel_auto}>"Auto"</option>
                                                        </select>
                                                    </div>
                                                    <div class="form-group">
                                                        <label>"TX Power"</label>
                                                        <input type="text" name="tx_power" value={r.tx_power} />
                                                    </div>
                                                    <div class="form-group">
                                                        <label>
                                                            <input type="checkbox" name="enabled" checked={r.enabled} />
                                                            " Enabled"
                                                        </label>
                                                    </div>
                                                </div>
                                                <button type="submit" class="btn btn-sm">"Save Radio"</button>
                                            </ActionForm>
                                        </div>
                                    }
                                }).collect_view()}
                            }.into_any()
                        }
                    }
                    Err(e) => view! { <p class="error">{format!("Error loading radios: {}", e)}</p> }.into_any(),
                })}}
            </Suspense>

            // --- Connected Clients ---
            <h4 class="mt-lg">"Connected Clients"</h4>
            {if ap_clients.is_empty() {
                view! { <p class="text-muted">"No clients connected to this AP."</p> }.into_any()
            } else {
                view! {
                    <div class="table-scroll">
                    <table class="device-table">
                        <thead>
                            <tr>
                                <th>"Client MAC"</th>
                                <th>"SSID"</th>
                                <th>"Band"</th>
                                <th>"RSSI"</th>
                                <th>"RX Rate"</th>
                                <th>"TX Rate"</th>
                            </tr>
                        </thead>
                        <tbody>
                            {ap_clients.into_iter().map(|c| {
                                let rssi_str = c.rssi.map(|r| format!("{} dBm", r)).unwrap_or_else(|| "\u{2014}".to_string());
                                let rx_str = c.rx_rate.map(|r| format!("{} Mbps", r)).unwrap_or_else(|| "\u{2014}".to_string());
                                let tx_str = c.tx_rate.map(|r| format!("{} Mbps", r)).unwrap_or_else(|| "\u{2014}".to_string());
                                view! {
                                    <tr>
                                        <td>{c.mac}</td>
                                        <td>{c.ssid}</td>
                                        <td>{c.band}</td>
                                        <td>{rssi_str}</td>
                                        <td>{rx_str}</td>
                                        <td>{tx_str}</td>
                                    </tr>
                                }
                            }).collect_view()}
                        </tbody>
                    </table>
                    </div>
                }.into_any()
            }}
        </div>
    }
}
