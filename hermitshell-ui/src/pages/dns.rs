use leptos::prelude::*;
use crate::client;
use crate::components::layout::Layout;
use crate::components::toast::ErrorToast;
use crate::server_fns::{
    ToggleAdBlocking, SetDnsSettings,
    AddDnsBlocklist, RemoveDnsBlocklist, SetDnsBlocklistEnabled,
    AddDnsForwardZone, RemoveDnsForwardZone, SetDnsForwardEnabled,
    AddDnsCustomRule, RemoveDnsCustomRule, SetDnsRuleEnabled,
};

#[component]
pub fn Dns() -> impl IntoView {
    let data = Resource::new(
        || (),
        |_| async { client::get_status() },
    );
    let dns_config = Resource::new(
        || (),
        |_| async { client::get_dns_config() },
    );
    let blocklists = Resource::new(
        || (),
        |_| async { client::list_dns_blocklists() },
    );
    let forwards = Resource::new(
        || (),
        |_| async { client::list_dns_forwards() },
    );
    let rules = Resource::new(
        || (),
        |_| async { client::list_dns_rules() },
    );

    view! {
        <Layout title="DNS & Ad Blocking" active_page="dns">
            // Ad Blocking section
            <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                {move || data.get().map(|result| match result {
                    Ok(status) => {
                        let enabled = status.ad_blocking_enabled;
                        let status_text = if enabled { "Enabled" } else { "Disabled" };
                        let status_class = if enabled { "card-value success" } else { "card-value warning" };
                        let toggle_value = if enabled { "false" } else { "true" };
                        let toggle_label = if enabled { "Disable" } else { "Enable" };

                        let ad_action = ServerAction::<ToggleAdBlocking>::new();

                        view! {
                            <div class="settings-section">
                                <h3>"Ad Blocking"</h3>
                                <div class="settings-row">
                                    <span class="settings-label">"Status"</span>
                                    <span class={status_class}>{status_text}</span>
                                </div>
                                <div class="settings-row">
                                    <span class="settings-label">"DNS Resolver"</span>
                                    <span class="settings-value">"Unbound (recursive, DNSSEC)"</span>
                                </div>
                                <div class="settings-row">
                                    <span class="settings-label">"Toggle"</span>
                                    <ActionForm action=ad_action attr:class="inline-form">
                                        <input type="hidden" name="enabled" value={toggle_value} />
                                        <button type="submit" class="btn btn-sm">{toggle_label}</button>
                                    </ActionForm>
                                </div>
                                <ErrorToast value=ad_action.value() />
                            </div>
                        }.into_any()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                })}
            </Suspense>

            // DNS Configuration (rate limits) - editable form
            <Suspense fallback=move || view! { <p>"Loading DNS config..."</p> }>
                {move || dns_config.get().map(|result| match result {
                    Ok(config) => {
                        let upstream = config.get("upstream_dns")
                            .and_then(|v| v.as_str())
                            .unwrap_or("auto")
                            .to_string();
                        let mode = if upstream == "auto" { "Recursive (DNSSEC enabled)".to_string() } else { format!("Forwarding to {}", upstream) };
                        let per_client = config.get("ratelimit_per_client")
                            .and_then(|v| v.as_str())
                            .unwrap_or("0")
                            .to_string();
                        let per_domain = config.get("ratelimit_per_domain")
                            .and_then(|v| v.as_str())
                            .unwrap_or("0")
                            .to_string();

                        let dns_action = ServerAction::<SetDnsSettings>::new();

                        view! {
                            <div class="settings-section">
                                <h3>"DNS Configuration"</h3>
                                <div class="settings-row">
                                    <span class="settings-label">"Mode"</span>
                                    <span class="settings-value">{mode}</span>
                                </div>
                                <ActionForm action=dns_action>
                                    <div class="settings-row">
                                        <span class="settings-label">"Rate Limit (per client)"</span>
                                        <span class="settings-value">
                                            <input type="number" name="ratelimit_per_client" min="0" value={per_client} />
                                            " qps"
                                        </span>
                                    </div>
                                    <div class="settings-row">
                                        <span class="settings-label">"Rate Limit (per domain)"</span>
                                        <span class="settings-value">
                                            <input type="number" name="ratelimit_per_domain" min="0" value={per_domain} />
                                            " qps"
                                        </span>
                                    </div>
                                    <div class="actions-bar">
                                        <button type="submit" class="btn btn-primary btn-sm">"Save"</button>
                                    </div>
                                </ActionForm>
                                <ErrorToast value=dns_action.value() />
                            </div>
                        }.into_any()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                })}
            </Suspense>

            // Block Lists - table with remove + add form
            <Suspense fallback=move || view! { <p>"Loading blocklists..."</p> }>
                {move || blocklists.get().map(|result| match result {
                    Ok(lists) => {
                        let add_bl_action = ServerAction::<AddDnsBlocklist>::new();

                        view! {
                            <div class="settings-section">
                                <h3>"Block Lists"</h3>
                                {if lists.is_empty() {
                                    view! { <p class="settings-empty">"No blocklists configured"</p> }.into_any()
                                } else {
                                    view! {
                                        <div class="table-scroll">
                                        <table class="data-table">
                                            <thead>
                                                <tr>
                                                    <th>"Name"</th>
                                                    <th>"URL"</th>
                                                    <th>"Tag"</th>
                                                    <th>"Enabled"</th>
                                                    <th>"Actions"</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {lists.iter().map(|bl| {
                                                    let id = bl.id;
                                                    let remove_action = ServerAction::<RemoveDnsBlocklist>::new();
                                                    let toggle_action = ServerAction::<SetDnsBlocklistEnabled>::new();
                                                    let new_enabled = if bl.enabled { "false" } else { "true" };
                                                    let btn_class = if bl.enabled { "btn btn-sm btn-success" } else { "btn btn-sm btn-secondary" };
                                                    let btn_label = if bl.enabled { "Enabled" } else { "Disabled" };
                                                    view! {
                                                        <tr>
                                                            <td>{bl.name.clone()}</td>
                                                            <td>{bl.url.clone()}</td>
                                                            <td>{bl.tag.clone()}</td>
                                                            <td>
                                                                <ActionForm action=toggle_action attr:class="inline-form">
                                                                    <input type="hidden" name="id" value={id.to_string()} />
                                                                    <input type="hidden" name="enabled" value={new_enabled} />
                                                                    <button type="submit" class={btn_class}>{btn_label}</button>
                                                                </ActionForm>
                                                            </td>
                                                            <td>
                                                                <button type="button" class="btn btn-danger btn-sm"
                                                                    data-dialog-open="">"Remove"</button>
                                                                <dialog class="confirm-dialog" aria-labelledby={format!("confirm-rm-bl-{}", id)}>
                                                                    <h3 id={format!("confirm-rm-bl-{}", id)}>"Remove Blocklist?"</h3>
                                                                    <p>{format!("\"{}\" will be permanently removed.", bl.name)}</p>
                                                                    <div class="dialog-actions">
                                                                        <button type="button" class="btn btn-sm"
                                                                            data-dialog-close="">"Cancel"</button>
                                                                        <ActionForm action=remove_action attr:class="inline-form">
                                                                            <input type="hidden" name="id" value={id.to_string()} />
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

                                <h4>"Add Blocklist"</h4>
                                <ActionForm action=add_bl_action attr:class="form-inline">
                                    <label for="add-bl-name">"Name"</label>
                                    <input type="text" name="name" id="add-bl-name" required />
                                    <label for="add-bl-url">"URL"</label>
                                    <input type="text" name="url" id="add-bl-url" placeholder="https://..." required />
                                    <label for="add-bl-tag">"Tag"</label>
                                    <select name="tag" id="add-bl-tag">
                                        <option value="ads">"ads"</option>
                                        <option value="custom">"custom"</option>
                                        <option value="strict">"strict"</option>
                                    </select>
                                    <button type="submit" class="btn btn-primary">"Add"</button>
                                </ActionForm>
                                <ErrorToast value=add_bl_action.value() />
                            </div>
                        }.into_any()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                })}
            </Suspense>

            // Forward Zones - table with remove + add form
            <Suspense fallback=move || view! { <p>"Loading forward zones..."</p> }>
                {move || forwards.get().map(|result| match result {
                    Ok(zones) => {
                        let add_fz_action = ServerAction::<AddDnsForwardZone>::new();

                        view! {
                            <div class="settings-section">
                                <h3>"Forward Zones"</h3>
                                {if zones.is_empty() {
                                    view! { <p class="settings-empty">"No forward zones configured"</p> }.into_any()
                                } else {
                                    view! {
                                        <div class="table-scroll">
                                        <table class="data-table">
                                            <thead>
                                                <tr>
                                                    <th>"Domain"</th>
                                                    <th>"Forward Address"</th>
                                                    <th>"Enabled"</th>
                                                    <th>"Actions"</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {zones.iter().map(|fz| {
                                                    let id = fz.id;
                                                    let remove_action = ServerAction::<RemoveDnsForwardZone>::new();
                                                    let toggle_action = ServerAction::<SetDnsForwardEnabled>::new();
                                                    let new_enabled = if fz.enabled { "false" } else { "true" };
                                                    let btn_class = if fz.enabled { "btn btn-sm btn-success" } else { "btn btn-sm btn-secondary" };
                                                    let btn_label = if fz.enabled { "Enabled" } else { "Disabled" };
                                                    view! {
                                                        <tr>
                                                            <td>{fz.domain.clone()}</td>
                                                            <td>{fz.forward_addr.clone()}</td>
                                                            <td>
                                                                <ActionForm action=toggle_action attr:class="inline-form">
                                                                    <input type="hidden" name="id" value={id.to_string()} />
                                                                    <input type="hidden" name="enabled" value={new_enabled} />
                                                                    <button type="submit" class={btn_class}>{btn_label}</button>
                                                                </ActionForm>
                                                            </td>
                                                            <td>
                                                                <button type="button" class="btn btn-danger btn-sm"
                                                                    data-dialog-open="">"Remove"</button>
                                                                <dialog class="confirm-dialog" aria-labelledby={format!("confirm-rm-fz-{}", id)}>
                                                                    <h3 id={format!("confirm-rm-fz-{}", id)}>"Remove Forward Zone?"</h3>
                                                                    <p>{format!("\"{}\" will be permanently removed.", fz.domain)}</p>
                                                                    <div class="dialog-actions">
                                                                        <button type="button" class="btn btn-sm"
                                                                            data-dialog-close="">"Cancel"</button>
                                                                        <ActionForm action=remove_action attr:class="inline-form">
                                                                            <input type="hidden" name="id" value={id.to_string()} />
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

                                <h4>"Add Forward Zone"</h4>
                                <ActionForm action=add_fz_action attr:class="form-inline">
                                    <label for="add-fz-domain">"Domain"</label>
                                    <input type="text" name="domain" id="add-fz-domain" placeholder="example.local" required />
                                    <label for="add-fz-addr">"Forward Address"</label>
                                    <input type="text" name="forward_addr" id="add-fz-addr" placeholder="10.0.0.1" required />
                                    <button type="submit" class="btn btn-primary">"Add"</button>
                                </ActionForm>
                                <ErrorToast value=add_fz_action.value() />
                            </div>
                        }.into_any()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                })}
            </Suspense>

            // Custom DNS Rules - table with remove + add form
            <Suspense fallback=move || view! { <p>"Loading custom rules..."</p> }>
                {move || rules.get().map(|result| match result {
                    Ok(rules) => {
                        let add_rule_action = ServerAction::<AddDnsCustomRule>::new();

                        view! {
                            <div class="settings-section">
                                <h3>"Custom DNS Rules"</h3>
                                {if rules.is_empty() {
                                    view! { <p class="settings-empty">"No custom rules configured"</p> }.into_any()
                                } else {
                                    view! {
                                        <div class="table-scroll">
                                        <table class="data-table">
                                            <thead>
                                                <tr>
                                                    <th>"Domain"</th>
                                                    <th>"Type"</th>
                                                    <th>"Value"</th>
                                                    <th>"Enabled"</th>
                                                    <th>"Actions"</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {rules.iter().map(|rule| {
                                                    let id = rule.id;
                                                    let remove_action = ServerAction::<RemoveDnsCustomRule>::new();
                                                    let toggle_action = ServerAction::<SetDnsRuleEnabled>::new();
                                                    let new_enabled = if rule.enabled { "false" } else { "true" };
                                                    let btn_class = if rule.enabled { "btn btn-sm btn-success" } else { "btn btn-sm btn-secondary" };
                                                    let btn_label = if rule.enabled { "Enabled" } else { "Disabled" };
                                                    view! {
                                                        <tr>
                                                            <td>{rule.domain.clone()}</td>
                                                            <td>{rule.record_type.clone()}</td>
                                                            <td>{rule.value.clone()}</td>
                                                            <td>
                                                                <ActionForm action=toggle_action attr:class="inline-form">
                                                                    <input type="hidden" name="id" value={id.to_string()} />
                                                                    <input type="hidden" name="enabled" value={new_enabled} />
                                                                    <button type="submit" class={btn_class}>{btn_label}</button>
                                                                </ActionForm>
                                                            </td>
                                                            <td>
                                                                <button type="button" class="btn btn-danger btn-sm"
                                                                    data-dialog-open="">"Remove"</button>
                                                                <dialog class="confirm-dialog" aria-labelledby={format!("confirm-rm-rule-{}", id)}>
                                                                    <h3 id={format!("confirm-rm-rule-{}", id)}>"Remove DNS Rule?"</h3>
                                                                    <p>{format!("\"{}\" will be permanently removed.", rule.domain)}</p>
                                                                    <div class="dialog-actions">
                                                                        <button type="button" class="btn btn-sm"
                                                                            data-dialog-close="">"Cancel"</button>
                                                                        <ActionForm action=remove_action attr:class="inline-form">
                                                                            <input type="hidden" name="id" value={id.to_string()} />
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

                                <h4>"Add Rule"</h4>
                                <ActionForm action=add_rule_action attr:class="form-inline">
                                    <label for="add-rule-domain">"Domain"</label>
                                    <input type="text" name="domain" id="add-rule-domain" placeholder="example.com" required />
                                    <label for="add-rule-type">"Type"</label>
                                    <select name="record_type" id="add-rule-type">
                                        <option value="A">"A"</option>
                                        <option value="AAAA">"AAAA"</option>
                                        <option value="CNAME">"CNAME"</option>
                                        <option value="MX">"MX"</option>
                                        <option value="TXT">"TXT"</option>
                                    </select>
                                    <label for="add-rule-value">"Value"</label>
                                    <input type="text" name="value" id="add-rule-value" placeholder="10.0.0.1" required />
                                    <button type="submit" class="btn btn-primary">"Add"</button>
                                </ActionForm>
                                <ErrorToast value=add_rule_action.value() />
                            </div>
                        }.into_any()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                })}
            </Suspense>
        </Layout>
    }
}
