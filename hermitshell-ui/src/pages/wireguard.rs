use leptos::*;
use crate::client;
use crate::components::layout::Layout;

#[component]
pub fn Wireguard() -> impl IntoView {
    let data = create_resource(
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

                        view! {
                            <div class="settings-section">
                                <h3>"Server"</h3>
                                <div class="settings-row">
                                    <span class="settings-label">"Status"</span>
                                    <span class={status_class}>{status_text}</span>
                                </div>
                                <div class="settings-row">
                                    <span class="settings-label">"Public Key"</span>
                                    <span class="settings-value" style="font-family:monospace;font-size:0.85em">{pubkey_display}</span>
                                </div>
                                <div class="settings-row">
                                    <span class="settings-label">"Listen Port"</span>
                                    <span class="settings-value">{wg.listen_port}</span>
                                </div>
                                <div class="settings-row">
                                    <span class="settings-label">"Toggle"</span>
                                    <form method="post" action="/api/wireguard" style="display:inline">
                                        <input type="hidden" name="enabled" value={toggle_value} />
                                        <button type="submit" class="btn btn-sm">{toggle_label}</button>
                                    </form>
                                </div>
                            </div>

                            <div class="settings-section">
                                <h3>"Peers"</h3>
                                {if wg.peers.is_empty() {
                                    view! { <p class="text-muted">"No peers configured."</p> }.into_view()
                                } else {
                                    view! {
                                        <table class="device-table">
                                            <thead>
                                                <tr>
                                                    <th>"Name"</th>
                                                    <th>"IP"</th>
                                                    <th>"Group"</th>
                                                    <th>"Public Key"</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {wg.peers.iter().map(|peer| {
                                                    let short_key = format!("{}...", &peer.public_key[..12]);
                                                    view! {
                                                        <tr>
                                                            <td>{&peer.name}</td>
                                                            <td>{&peer.ip}</td>
                                                            <td><span class="group-badge">{&peer.device_group}</span></td>
                                                            <td style="font-family:monospace;font-size:0.85em">{short_key}</td>
                                                        </tr>
                                                    }
                                                }).collect_view()}
                                            </tbody>
                                        </table>
                                    }.into_view()
                                }}
                            </div>
                        }.into_view()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_view(),
                })}
            </Suspense>
        </Layout>
    }
}
