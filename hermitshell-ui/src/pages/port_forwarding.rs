use leptos::prelude::*;
use crate::client;
use crate::components::layout::Layout;
use crate::components::toast::ErrorToast;
use crate::server_fns::{AddPortForward, RemovePortForward, ToggleUpnp};

#[component]
pub fn PortForwarding() -> impl IntoView {
    let data = Resource::new(
        || (),
        |_| async { client::list_port_forwards() },
    );
    let upnp_data = Resource::new(
        || (),
        |_| async { client::get_upnp_enabled() },
    );

    view! {
        <Layout title="Port Forwarding" active_page="port forwarding">
            <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                {move || data.get().map(|result| match result {
                    Ok(info) => {
                        let forwards = info.port_forwards;
                        let dmz_ip = info.dmz_ip.clone();

                        let add_action = ServerAction::<AddPortForward>::new();

                        view! {
                            <h2 class="section-header">"Rules"</h2>
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>"Protocol"</th>
                                        <th>"External Port(s)"</th>
                                        <th>"Internal IP"</th>
                                        <th>"Internal Port"</th>
                                        <th>"Description"</th>
                                        <th>"Source"</th>
                                        <th>"Actions"</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {forwards.iter().map(|fwd| {
                                        let id = fwd.id;
                                        let port_display = if fwd.external_port_start == fwd.external_port_end {
                                            fwd.external_port_start.to_string()
                                        } else {
                                            format!("{}-{}", fwd.external_port_start, fwd.external_port_end)
                                        };
                                        let remove_action = ServerAction::<RemovePortForward>::new();
                                        view! {
                                            <tr>
                                                <td>{fwd.protocol.clone()}</td>
                                                <td>{port_display}</td>
                                                <td>{fwd.internal_ip.clone()}</td>
                                                <td>{fwd.internal_port}</td>
                                                <td>{fwd.description.clone()}</td>
                                                <td>{match fwd.source.as_str() {
                                                    "upnp" => "UPnP",
                                                    "natpmp" => "NAT-PMP",
                                                    "pcp" => "PCP",
                                                    _ => "Manual",
                                                }}</td>
                                                <td>
                                                    <ActionForm action=remove_action attr:style="display:inline">
                                                        <input type="hidden" name="id" value={id.to_string()} />
                                                        <button type="submit" class="btn btn-danger btn-sm">"Remove"</button>
                                                    </ActionForm>
                                                    <ErrorToast value=remove_action.value() />
                                                </td>
                                            </tr>
                                        }
                                    }).collect_view()}
                                </tbody>
                            </table>

                            <h2 class="section-header">"Add Rule"</h2>
                            <ActionForm action=add_action attr:class="form-inline">
                                <label>"Protocol"
                                    <select name="protocol">
                                        <option value="both">"TCP+UDP"</option>
                                        <option value="tcp">"TCP"</option>
                                        <option value="udp">"UDP"</option>
                                    </select>
                                </label>
                                <label>"External Port Start"
                                    <input type="number" name="external_port_start" min="1" max="65535" required />
                                </label>
                                <label>"External Port End"
                                    <input type="number" name="external_port_end" min="1" max="65535" required />
                                </label>
                                <label>"Internal IP"
                                    <input type="text" name="internal_ip" placeholder="10.0.x.x" required />
                                </label>
                                <label>"Internal Port"
                                    <input type="number" name="internal_port" min="1" max="65535" required />
                                </label>
                                <label>"Description"
                                    <input type="text" name="description" placeholder="optional" />
                                </label>
                                <button type="submit" class="btn btn-primary">"Add"</button>
                            </ActionForm>
                            <ErrorToast value=add_action.value() />

                            <h2 class="section-header">"DMZ Host"</h2>
                            <p>"Current DMZ: " {if dmz_ip.is_empty() { "None".to_string() } else { dmz_ip }}</p>
                        }.into_any()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                })}
            </Suspense>

            <h2 class="section-header">"UPnP / NAT-PMP"</h2>
            <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                {move || upnp_data.get().map(|result| match result {
                    Ok(enabled) => {
                        let toggle_value = if enabled { "false" } else { "true" };
                        let toggle_label = if enabled { "Disable UPnP" } else { "Enable UPnP" };
                        let btn_class = if enabled { "btn btn-danger btn-sm" } else { "btn btn-primary btn-sm" };
                        let upnp_action = ServerAction::<ToggleUpnp>::new();
                        view! {
                            <p>"Status: " <strong>{if enabled { "Enabled" } else { "Disabled" }}</strong></p>
                            <p class="text-muted">"Allow trusted devices to create port forwards automatically via UPnP, NAT-PMP, and PCP. Requires agent restart after toggling."</p>
                            <ActionForm action=upnp_action attr:style="display:inline">
                                <input type="hidden" name="enabled" value={toggle_value} />
                                <button type="submit" class={btn_class}>{toggle_label}</button>
                            </ActionForm>
                            <ErrorToast value=upnp_action.value() />
                        }.into_any()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                })}
            </Suspense>
        </Layout>
    }
}
