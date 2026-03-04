use leptos::prelude::*;
use crate::client;
use crate::components::layout::Layout;
use crate::components::toast::ErrorToast;
use crate::server_fns::{AddPortForward, RemovePortForward, ToggleUpnp, TogglePortForward, AddIpv6Pinhole, RemoveIpv6Pinhole};

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
                            <div class="table-scroll">
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>"Protocol"</th>
                                        <th>"External Port(s)"</th>
                                        <th>"Internal IP"</th>
                                        <th>"Internal Port"</th>
                                        <th>"Description"</th>
                                        <th>"Source"</th>
                                        <th>"Enabled"</th>
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
                                                    {let toggle_action = ServerAction::<TogglePortForward>::new();
                                                    let toggle_val = if fwd.enabled { "false" } else { "true" };
                                                    let toggle_label = if fwd.enabled { "Disable" } else { "Enable" };
                                                    let btn_class = if fwd.enabled { "btn btn-sm" } else { "btn btn-primary btn-sm" };
                                                    view! {
                                                        <ActionForm action=toggle_action attr:class="inline-form">
                                                            <input type="hidden" name="id" value={id.to_string()} />
                                                            <input type="hidden" name="enabled" value={toggle_val} />
                                                            <button type="submit" class={btn_class}>{toggle_label}</button>
                                                        </ActionForm>
                                                        <ErrorToast value=toggle_action.value() />
                                                    }}
                                                </td>
                                                <td>
                                                    <ActionForm action=remove_action attr:class="inline-form">
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
                            </div>

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
                            <ActionForm action=upnp_action attr:class="inline-form">
                                <input type="hidden" name="enabled" value={toggle_value} />
                                <button type="submit" class={btn_class}>{toggle_label}</button>
                            </ActionForm>
                            <ErrorToast value=upnp_action.value() />
                        }.into_any()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                })}
            </Suspense>

            {
                let pinholes = Resource::new(|| (), |_| async { client::list_ipv6_pinholes() });
                let add_pinhole_action = ServerAction::<AddIpv6Pinhole>::new();
                view! {
                    <h2 class="section-header">"IPv6 Pinholes"</h2>
                    <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                        {move || pinholes.get().map(|result| match result {
                            Ok(list) => {
                                view! {
                                    <div class="table-scroll">
                                    <table class="data-table">
                                        <thead>
                                            <tr>
                                                <th>"Device MAC"</th>
                                                <th>"Protocol"</th>
                                                <th>"Port Start"</th>
                                                <th>"Port End"</th>
                                                <th>"Description"</th>
                                                <th>"Actions"</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {list.iter().map(|ph| {
                                                let mac = ph.get("mac").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                                let protocol = ph.get("protocol").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                                let port_start = ph.get("port_start").and_then(|v| v.as_i64()).unwrap_or(0);
                                                let port_end = ph.get("port_end").and_then(|v| v.as_i64()).unwrap_or(0);
                                                let description = ph.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                                let id = ph.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
                                                let remove_action = ServerAction::<RemoveIpv6Pinhole>::new();
                                                view! {
                                                    <tr>
                                                        <td>{mac}</td>
                                                        <td>{protocol}</td>
                                                        <td>{port_start}</td>
                                                        <td>{port_end}</td>
                                                        <td>{description}</td>
                                                        <td>
                                                            <ActionForm action=remove_action attr:class="inline-form">
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
                                    </div>
                                }.into_any()
                            }
                            Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                        })}
                    </Suspense>

                    <h2 class="section-header">"Add Pinhole"</h2>
                    <ActionForm action=add_pinhole_action attr:class="form-inline">
                        <label>"Device MAC"
                            <input type="text" name="device_mac" placeholder="AA:BB:CC:DD:EE:FF" required />
                        </label>
                        <label>"Protocol"
                            <select name="protocol">
                                <option value="tcp">"TCP"</option>
                                <option value="udp">"UDP"</option>
                            </select>
                        </label>
                        <label>"Port Start"
                            <input type="number" name="port_start" min="1" max="65535" required />
                        </label>
                        <label>"Port End"
                            <input type="number" name="port_end" min="1" max="65535" required />
                        </label>
                        <label>"Description"
                            <input type="text" name="description" placeholder="optional" />
                        </label>
                        <button type="submit" class="btn btn-primary">"Add"</button>
                    </ActionForm>
                    <ErrorToast value=add_pinhole_action.value() />
                }
            }
        </Layout>
    }
}
