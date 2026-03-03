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
        <Layout title="SNMP Switches" active_page="switches">
            <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                {move || switches.get().map(|result| match result {
                    Ok(list) => {
                        let add_action = ServerAction::<AddSwitch>::new();

                        view! {
                            <div class="settings-section">
                                <h3>"SNMP Switches"</h3>
                                <p class="settings-description">"Add managed switches for MAC-to-port discovery. Uses SNMP v2c or v3 read-only polling."</p>
                                {if list.is_empty() {
                                    view! { <p class="settings-empty">"No switches configured"</p> }.into_any()
                                } else {
                                    view! {
                                        <table class="data-table">
                                            <thead>
                                                <tr>
                                                    <th>"Name"</th>
                                                    <th>"Host"</th>
                                                    <th>"Version"</th>
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
                                                            <td>{sw.version.clone()}</td>
                                                            <td><span class={status_class}>{sw.status.clone()}</span></td>
                                                            <td>
                                                                <ActionForm action=test_action attr:class="inline-form">
                                                                    <input type="hidden" name="name" value={name_for_test} />
                                                                    <button type="submit" class="btn btn-sm">"Test"</button>
                                                                </ActionForm>
                                                                <ActionForm action=remove_action attr:class="inline-form">
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
                                        <input type="text" name="name" />
                                    </label>
                                    <label>"Host"
                                        <input type="text" name="host" placeholder="192.168.1.100" />
                                    </label>
                                    <label>"SNMP Version"
                                        <select name="snmp_version">
                                            <option value="2c" selected>"v2c"</option>
                                            <option value="3">"v3"</option>
                                        </select>
                                    </label>
                                    <label>"Community String (v2c)"
                                        <input type="password" name="community" value="public" />
                                    </label>
                                    <label>"Username (v3)"
                                        <input type="text" name="v3_username" />
                                    </label>
                                    <label>"Auth Password (v3)"
                                        <input type="password" name="v3_auth_pass" />
                                    </label>
                                    <label>"Privacy Password (v3)"
                                        <input type="password" name="v3_priv_pass" />
                                    </label>
                                    <label>"Auth Protocol (v3)"
                                        <select name="v3_auth_protocol">
                                            <option value="md5">"MD5"</option>
                                            <option value="sha1">"SHA1"</option>
                                            <option value="sha224">"SHA224"</option>
                                            <option value="sha256" selected>"SHA256"</option>
                                            <option value="sha384">"SHA384"</option>
                                            <option value="sha512">"SHA512"</option>
                                        </select>
                                    </label>
                                    <label>"Cipher (v3)"
                                        <select name="v3_cipher">
                                            <option value="des">"DES"</option>
                                            <option value="aes128" selected>"AES128"</option>
                                            <option value="aes192">"AES192"</option>
                                            <option value="aes256">"AES256"</option>
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
