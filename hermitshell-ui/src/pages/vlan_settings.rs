use leptos::prelude::*;
use crate::client;
use crate::components::layout::Layout;
use crate::components::toast::ErrorToast;
use crate::server_fns::{EnableVlan, DisableVlan, UpdateVlanId};

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
                                        <div class="table-scroll">
                                        <table class="data-table">
                                            <thead>
                                                <tr>
                                                    <th>"Trust Group"</th>
                                                    <th>"VLAN ID"</th>
                                                    <th>"Subnet"</th>
                                                    <th>"Gateway"</th>
                                                    {if enabled {
                                                        view! { <th>"Interface"</th> }.into_any()
                                                    } else {
                                                        view! { }.into_any()
                                                    }}
                                                    <th></th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {vlans.into_iter().map(|v| {
                                                    let update_action = ServerAction::<UpdateVlanId>::new();
                                                    let group = v.group.clone();
                                                    let vlan_id_str = v.vlan_id.to_string();
                                                    let iface_name = format!("eth2.{}", v.vlan_id);
                                                    view! {
                                                        <tr>
                                                            <td>{v.group.clone()}</td>
                                                            <td colspan="4">
                                                                <ActionForm action=update_action attr:class="inline-form">
                                                                    <input type="hidden" name="group" value={group} />
                                                                    <input type="number" name="vlan_id" min="1" max="4094"
                                                                        value={vlan_id_str}
                                                                        class="input-sm" />
                                                                    <span class="settings-value">{v.subnet}</span>
                                                                    <span class="settings-value">{v.gateway}</span>
                                                                    {if enabled {
                                                                        view! { <span class="settings-value mono">{iface_name}</span> }.into_any()
                                                                    } else {
                                                                        view! { }.into_any()
                                                                    }}
                                                                    <button type="submit" class="btn btn-sm btn-primary">"Save"</button>
                                                                </ActionForm>
                                                                <ErrorToast value=update_action.value() />
                                                            </td>
                                                        </tr>
                                                    }
                                                }).collect_view()}
                                            </tbody>
                                        </table>
                                        </div>
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
