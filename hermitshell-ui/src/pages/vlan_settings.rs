use leptos::prelude::*;
use crate::client;
use crate::components::layout::Layout;
use crate::components::toast::ErrorToast;
use crate::server_fns::{EnableVlan, DisableVlan};

#[component]
pub fn VlanSettings() -> impl IntoView {
    let status = Resource::new(
        || (),
        |_| async { client::get_vlan_status() },
    );

    view! {
        <Layout title="VLAN Segmentation" active_page="vlans">
            <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                {move || status.get().map(|result| match result {
                    Ok((enabled, vlans)) => {
                        let status_text = if enabled { "Enabled" } else { "Disabled" };
                        let status_class = if enabled { "card-value success" } else { "card-value warning" };

                        let enable_action = ServerAction::<EnableVlan>::new();
                        let disable_action = ServerAction::<DisableVlan>::new();

                        view! {
                            <div class="settings-section">
                                <h3>"VLAN Mode"</h3>
                                <div class="settings-row">
                                    <span class="settings-label">"Status"</span>
                                    <span class={status_class}>{status_text}</span>
                                </div>
                                <div class="settings-row">
                                    <span class="settings-label">"Description"</span>
                                    <span class="settings-value">"Isolates device trust groups into separate VLANs on the LAN interface"</span>
                                </div>
                                <div class="settings-row">
                                    <span class="settings-label">"Toggle"</span>
                                    {if enabled {
                                        view! {
                                            <ActionForm action=disable_action attr:class="inline-form">
                                                <button type="submit" class="btn btn-sm btn-danger">"Disable"</button>
                                            </ActionForm>
                                        }.into_any()
                                    } else {
                                        view! {
                                            <ActionForm action=enable_action attr:class="inline-form">
                                                <button type="submit" class="btn btn-sm btn-primary">"Enable"</button>
                                            </ActionForm>
                                        }.into_any()
                                    }}
                                </div>
                                <ErrorToast value=enable_action.value() />
                                <ErrorToast value=disable_action.value() />
                            </div>

                            <div class="settings-section">
                                <h3>"VLAN Assignments"</h3>
                                {if vlans.is_empty() {
                                    view! { <p class="settings-empty">"No VLANs configured"</p> }.into_any()
                                } else {
                                    view! {
                                        <table class="data-table">
                                            <thead>
                                                <tr>
                                                    <th>"Trust Group"</th>
                                                    <th>"VLAN ID"</th>
                                                    <th>"Subnet"</th>
                                                    <th>"Gateway"</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {vlans.iter().map(|v| {
                                                    view! {
                                                        <tr>
                                                            <td>{v.group.clone()}</td>
                                                            <td>{v.vlan_id.to_string()}</td>
                                                            <td>{v.subnet.clone()}</td>
                                                            <td>{v.gateway.clone()}</td>
                                                        </tr>
                                                    }
                                                }).collect_view()}
                                            </tbody>
                                        </table>
                                    }.into_any()
                                }}
                            </div>
                        }.into_any()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                })}
            </Suspense>
        </Layout>
    }
}
