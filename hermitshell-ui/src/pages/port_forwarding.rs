use leptos::*;
use crate::client;
use crate::components::layout::Layout;

#[component]
pub fn PortForwarding() -> impl IntoView {
    let data = create_resource(
        || (),
        |_| async { client::list_port_forwards() },
    );

    view! {
        <Layout title="Port Forwarding" active_page="port forwarding">
            <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                {move || data.get().map(|result| match result {
                    Ok(info) => {
                        let forwards = info.port_forwards;
                        let dmz_ip = info.dmz_ip.clone();

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
                                        view! {
                                            <tr>
                                                <td>{fwd.protocol.clone()}</td>
                                                <td>{port_display}</td>
                                                <td>{fwd.internal_ip.clone()}</td>
                                                <td>{fwd.internal_port}</td>
                                                <td>{fwd.description.clone()}</td>
                                                <td>
                                                    <form method="post" action="/api/remove-port-forward" style="display:inline">
                                                        <input type="hidden" name="id" value={id.to_string()} />
                                                        <button type="submit" class="btn btn-danger btn-sm">"Remove"</button>
                                                    </form>
                                                </td>
                                            </tr>
                                        }
                                    }).collect_view()}
                                </tbody>
                            </table>

                            <h2 class="section-header">"Add Rule"</h2>
                            <form method="post" action="/api/add-port-forward" class="form-inline">
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
                            </form>

                            <h2 class="section-header">"DMZ Host"</h2>
                            <p>"Current DMZ: " {if dmz_ip.is_empty() { "None".to_string() } else { dmz_ip }}</p>
                        }.into_view()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_view(),
                })}
            </Suspense>
        </Layout>
    }
}
