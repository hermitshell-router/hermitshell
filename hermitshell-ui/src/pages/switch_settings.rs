use leptos::prelude::*;
use crate::client;
use crate::components::layout::Layout;
use crate::components::toast::ErrorToast;
use crate::server_fns::{AddSwitch, RemoveSwitch, TestSwitch};

#[component]
pub fn SwitchSettings() -> impl IntoView {
    let switches = Resource::new(
        || (),
        |_| async { client::list_switches() },
    );

    view! {
        <Layout title="Switch Management" active_page="switches">
            <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                {move || switches.get().map(|result| match result {
                    Ok(list) => {
                        let add_action = ServerAction::<AddSwitch>::new();

                        view! {
                            <div class="settings-section">
                                <h3>"Managed Switches"</h3>
                                {if list.is_empty() {
                                    view! { <p class="settings-empty">"No switches configured"</p> }.into_any()
                                } else {
                                    view! {
                                        <table class="data-table">
                                            <thead>
                                                <tr>
                                                    <th>"Name"</th>
                                                    <th>"Host"</th>
                                                    <th>"Port"</th>
                                                    <th>"Vendor"</th>
                                                    <th>"Uplink"</th>
                                                    <th>"Status"</th>
                                                    <th>"Actions"</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {list.iter().map(|sw| {
                                                    let name_for_remove = sw.name.clone();
                                                    let name_for_test = sw.name.clone();
                                                    let remove_action = ServerAction::<RemoveSwitch>::new();
                                                    let test_action = ServerAction::<TestSwitch>::new();
                                                    let status_class = if sw.status == "connected" { "card-value success" } else { "card-value warning" };
                                                    view! {
                                                        <tr>
                                                            <td>{sw.name.clone()}</td>
                                                            <td>{sw.host.clone()}</td>
                                                            <td>{sw.port.to_string()}</td>
                                                            <td>{sw.vendor_profile.clone()}</td>
                                                            <td>{sw.uplink_port.clone().unwrap_or_else(|| "-".to_string())}</td>
                                                            <td><span class={status_class}>{sw.status.clone()}</span></td>
                                                            <td>
                                                                <ActionForm action=test_action attr:style="display:inline">
                                                                    <input type="hidden" name="name" value={name_for_test} />
                                                                    <button type="submit" class="btn btn-sm">"Test"</button>
                                                                </ActionForm>
                                                                <ActionForm action=remove_action attr:style="display:inline">
                                                                    <input type="hidden" name="name" value={name_for_remove} />
                                                                    <button type="submit" class="btn btn-danger btn-sm">"Remove"</button>
                                                                </ActionForm>
                                                                <ErrorToast value=test_action.value() />
                                                                <ErrorToast value=remove_action.value() />
                                                            </td>
                                                        </tr>
                                                    }
                                                }).collect_view()}
                                            </tbody>
                                        </table>
                                    }.into_any()
                                }}

                                <h4>"Add Switch"</h4>
                                <ActionForm action=add_action attr:class="form-inline">
                                    <label>"Name"
                                        <input type="text" name="name" required />
                                    </label>
                                    <label>"Host"
                                        <input type="text" name="host" placeholder="192.168.1.100" required />
                                    </label>
                                    <label>"SSH Port"
                                        <input type="number" name="port" value="22" min="1" max="65535" />
                                    </label>
                                    <label>"Username"
                                        <input type="text" name="username" required />
                                    </label>
                                    <label>"Password"
                                        <input type="password" name="password" required />
                                    </label>
                                    <label>"Vendor Profile"
                                        <select name="vendor_profile">
                                            <option value="cisco_ios">"Cisco IOS"</option>
                                            <option value="tplink_t">"TP-Link T-series"</option>
                                            <option value="netgear_prosafe">"Netgear ProSafe"</option>
                                        </select>
                                    </label>
                                    <button type="submit" class="btn btn-primary">"Add"</button>
                                </ActionForm>
                                <ErrorToast value=add_action.value() />
                            </div>
                        }.into_any()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                })}
            </Suspense>
        </Layout>
    }
}
