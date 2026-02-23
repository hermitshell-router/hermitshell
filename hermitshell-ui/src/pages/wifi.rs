use leptos::prelude::*;
use crate::client;
use crate::components::layout::Layout;
use crate::components::toast::ErrorToast;
use crate::server_fns::{AdoptWifiAp, RemoveWifiAp};

#[component]
pub fn Wifi() -> impl IntoView {
    let aps = Resource::new(
        || (),
        |_| async { client::wifi_list_aps() },
    );
    let clients = Resource::new(
        || (),
        |_| async { client::wifi_get_clients() },
    );
    let adopt_action = ServerAction::<AdoptWifiAp>::new();
    let remove_action = ServerAction::<RemoveWifiAp>::new();

    view! {
        <Layout title="WiFi" active_page="wifi">
            <div class="settings-section">
                <h3>"Access Points"</h3>
                <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                    {move || aps.get().map(|result| match result {
                        Ok(aps) => {
                            if aps.is_empty() {
                                view! { <p class="text-muted">"No access points adopted."</p> }.into_any()
                            } else {
                                view! {
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
                                                view! {
                                                    <tr>
                                                        <td>{ap.name.clone()}</td>
                                                        <td style="font-family:monospace;font-size:0.85em">{ap.mac.clone()}</td>
                                                        <td>{ap.ip.clone()}</td>
                                                        <td>{ap.provider.clone()}</td>
                                                        <td>{ap.status.clone()}</td>
                                                        <td>
                                                            <ActionForm action=remove_action attr:style="display:inline">
                                                                <input type="hidden" name="mac" value={mac} />
                                                                <button type="submit" class="btn btn-sm btn-danger">"Remove"</button>
                                                            </ActionForm>
                                                        </td>
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
                <ErrorToast value=remove_action.value() />
            </div>

            <div class="settings-section">
                <h3>"Adopt Access Point"</h3>
                <ActionForm action=adopt_action>
                    <div class="form-grid">
                        <div class="form-group">
                            <label for="ap-mac">"MAC Address"</label>
                            <input type="text" id="ap-mac" name="mac" placeholder="aa:bb:cc:dd:ee:ff" required />
                        </div>
                        <div class="form-group">
                            <label for="ap-ip">"IP Address"</label>
                            <input type="text" id="ap-ip" name="ip" placeholder="192.168.1.100" required />
                        </div>
                        <div class="form-group">
                            <label for="ap-name">"Name"</label>
                            <input type="text" id="ap-name" name="name" placeholder="Office AP" required />
                        </div>
                        <div class="form-group">
                            <label for="ap-username">"Username"</label>
                            <input type="text" id="ap-username" name="username" value="admin" />
                        </div>
                        <div class="form-group">
                            <label for="ap-password">"Password"</label>
                            <input type="password" id="ap-password" name="password" required />
                        </div>
                    </div>
                    <button type="submit" class="btn">"Adopt AP"</button>
                </ActionForm>
                <ErrorToast value=adopt_action.value() />
            </div>

            <div class="settings-section">
                <h3>"WiFi Clients"</h3>
                <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                    {move || clients.get().map(|result| match result {
                        Ok(clients) => {
                            if clients.is_empty() {
                                view! { <p class="text-muted">"No WiFi clients detected."</p> }.into_any()
                            } else {
                                view! {
                                    <table class="device-table">
                                        <thead>
                                            <tr>
                                                <th>"MAC"</th>
                                                <th>"AP"</th>
                                                <th>"SSID"</th>
                                                <th>"Band"</th>
                                                <th>"RSSI"</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {clients.iter().map(|c| {
                                                let rssi_str = c.rssi.map(|r| format!("{} dBm", r)).unwrap_or_else(|| "\u{2014}".to_string());
                                                view! {
                                                    <tr>
                                                        <td style="font-family:monospace;font-size:0.85em">{c.mac.clone()}</td>
                                                        <td style="font-family:monospace;font-size:0.85em">{c.ap_mac.clone()}</td>
                                                        <td>{c.ssid.clone()}</td>
                                                        <td>{c.band.clone()}</td>
                                                        <td>{rssi_str}</td>
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
            </div>
        </Layout>
    }
}
