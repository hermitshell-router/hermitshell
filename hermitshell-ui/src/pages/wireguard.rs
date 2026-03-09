use leptos::prelude::*;
use crate::client;
use crate::components::layout::Layout;
use crate::components::toast::ErrorToast;
use crate::server_fns::{ToggleWireguard, AddWgPeer, RemoveWgPeer, SetWgPeerGroup};

#[component]
pub fn Wireguard() -> impl IntoView {
    let data = Resource::new(
        || (),
        |_| async { client::get_wireguard() },
    );

    view! {
        <Layout title="WireGuard VPN" active_page="wireguard">
            <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                {move || data.get().map(|result| match result {
                    Ok(wg) => {
                        let status_text = if wg.enabled { "Enabled" } else { "Disabled" };
                        let status_class = if wg.enabled { "card-value success" } else { "card-value warning" };
                        let toggle_value = if wg.enabled { "false" } else { "true" };
                        let toggle_label = if wg.enabled { "Disable" } else { "Enable" };
                        let pubkey_display = wg.public_key.clone().unwrap_or_else(|| "\u{2014}".to_string());
                        let wg_action = ServerAction::<ToggleWireguard>::new();

                        view! {
                            <div class="settings-section">
                                <h3>"Server"</h3>
                                <div class="settings-row">
                                    <span class="settings-label">"Status"</span>
                                    <span class={status_class}>{status_text}</span>
                                </div>
                                <div class="settings-row">
                                    <span class="settings-label">"Public Key"</span>
                                    <span class="settings-value">{pubkey_display}</span>
                                </div>
                                <div class="settings-row">
                                    <span class="settings-label">"Listen Port"</span>
                                    <span class="settings-value">{wg.listen_port}</span>
                                </div>
                                <div class="settings-row">
                                    <span class="settings-label">"Toggle"</span>
                                    <ActionForm action=wg_action attr:class="inline-form">
                                        <input type="hidden" name="enabled" value={toggle_value} />
                                        <button type="submit" class="btn btn-sm">{toggle_label}</button>
                                    </ActionForm>
                                </div>
                                <ErrorToast value=wg_action.value() />
                            </div>

                            <div class="settings-section">
                                <h3>"Peers"</h3>
                                {if wg.peers.is_empty() {
                                    view! { <p class="text-muted">"No peers configured. Add a peer to allow VPN access to your network."</p> }.into_any()
                                } else {
                                    view! {
                                        <div class="table-scroll">
                                            <table class="device-table">
                                                <thead>
                                                    <tr>
                                                        <th>"Name"</th>
                                                        <th>"IP"</th>
                                                        <th>"Group"</th>
                                                        <th>"Public Key"</th>
                                                        <th>"Actions"</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    {wg.peers.iter().map(|peer| {
                                                        let pk = peer.public_key.clone();
                                                        let pk2 = peer.public_key.clone();
                                                        let dialog_id = format!("confirm-rm-peer-{}", &pk2[..8.min(pk2.len())]);
                                                        let short_key = format!("{}...", &peer.public_key[..12.min(peer.public_key.len())]);
                                                        let group_action = ServerAction::<SetWgPeerGroup>::new();
                                                        let remove_action = ServerAction::<RemoveWgPeer>::new();
                                                        view! {
                                                            <tr>
                                                                <td>{peer.name.clone()}</td>
                                                                <td>{peer.ip.clone()}</td>
                                                                <td><span class="group-badge">{peer.device_group.clone()}</span></td>
                                                                <td>{short_key}</td>
                                                                <td>
                                                                    <ActionForm action=group_action attr:class="inline-form">
                                                                        <input type="hidden" name="public_key" value={pk.clone()} />
                                                                        <select name="group">
                                                                            <option value="trusted">"trusted"</option>
                                                                            <option value="iot">"iot"</option>
                                                                            <option value="guest">"guest"</option>
                                                                            <option value="servers">"servers"</option>
                                                                        </select>
                                                                        <button type="submit" class="btn btn-sm">"Move"</button>
                                                                    </ActionForm>
                                                                    <ErrorToast value=group_action.value() />
                                                                    <button type="button" class="btn btn-danger btn-sm"
                                                                        data-dialog-open="">"Remove"</button>
                                                                    <dialog class="confirm-dialog" aria-labelledby={dialog_id.clone()}>
                                                                        <h3 id={dialog_id.clone()}>"Remove Peer?"</h3>
                                                                        <p>{format!("\"{}\" will lose VPN access.", peer.name)}</p>
                                                                        <div class="dialog-actions">
                                                                            <button type="button" class="btn btn-sm"
                                                                                data-dialog-close="">"Cancel"</button>
                                                                            <ActionForm action=remove_action attr:class="inline-form">
                                                                                <input type="hidden" name="public_key" value={pk2} />
                                                                                <button type="submit" class="btn btn-danger btn-sm">"Confirm Remove"</button>
                                                                            </ActionForm>
                                                                        </div>
                                                                    </dialog>
                                                                    <ErrorToast value=remove_action.value() />
                                                                </td>
                                                            </tr>
                                                        }
                                                    }).collect_view()}
                                                </tbody>
                                            </table>
                                        </div>
                                    }.into_any()
                                }}

                                <h4 class="mt-lg">"Add Peer"</h4>
                                {
                                    let add_action = ServerAction::<AddWgPeer>::new();
                                    view! {
                                        <ActionForm action=add_action>
                                            <div class="settings-row">
                                                <label class="settings-label" for="peer-name">"Peer Name"</label>
                                                <input type="text" id="peer-name" name="name" required class="settings-input" />
                                            </div>
                                            <div class="settings-row">
                                                <label class="settings-label" for="peer-pubkey">"Public Key"</label>
                                                <input type="text" id="peer-pubkey" name="public_key" required class="settings-input mono" />
                                            </div>
                                            <div class="settings-row">
                                                <label class="settings-label" for="peer-group">"Device Group"</label>
                                                <select id="peer-group" name="group" class="settings-input">
                                                    <option value="trusted">"trusted"</option>
                                                    <option value="iot">"iot"</option>
                                                    <option value="guest">"guest"</option>
                                                    <option value="servers">"servers"</option>
                                                </select>
                                            </div>
                                            <button type="submit" class="btn">"Add Peer"</button>
                                        </ActionForm>
                                        <ErrorToast value=add_action.value() />
                                    }
                                }
                            </div>
                        }.into_any()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                })}
            </Suspense>
        </Layout>
    }
}
