#![allow(clippy::unused_unit, clippy::unit_arg)]
use leptos::prelude::*;
use crate::client;
use crate::components::layout::Layout;
use crate::components::settings_nav::SettingsNav;
use crate::components::toast::ErrorToast;
use crate::server_fns::{
    RemoveReservation,
    UpdateHostname, UpdateTimezone, UpdateUpstreamDns,
    UpdateWanConfig, UpdateInterfaces,
    AddPortForward, RemovePortForward, ToggleUpnp, TogglePortForward,
    AddIpv6Pinhole, RemoveIpv6Pinhole,
    EnableVlan, DisableVlan, UpdateVlanId,
    AddSwitch, RemoveSwitch, TestSwitch,
    SetQosConfig, SetQosTestUrl, RunSpeedTest,
};

struct GroupInfo {
    name: &'static str,
    key: &'static str,
    description: &'static str,
}

const GROUPS: &[GroupInfo] = &[
    GroupInfo { name: "Trusted", key: "trusted", description: "Full network access. Can reach all other groups and the internet." },
    GroupInfo { name: "IoT", key: "iot", description: "Internet-only. Cannot reach other devices on the network." },
    GroupInfo { name: "Guest", key: "guest", description: "Internet-only. Isolated from all other devices." },
    GroupInfo { name: "Servers", key: "servers", description: "Internet access. Reachable by trusted devices." },
    GroupInfo { name: "Quarantine", key: "quarantine", description: "Internet-only. New devices land here until approved." },
    GroupInfo { name: "Blocked", key: "blocked", description: "No network access. All traffic dropped." },
];

#[component]
pub fn SettingsNetwork() -> impl IntoView {
    let interfaces = Resource::new(|| (), |_| async { client::list_interfaces() });
    let net_config = Resource::new(|| (), |_| async {
        let wan_iface = client::get_config("wan_iface").unwrap_or(None).unwrap_or_default();
        let lan_iface = client::get_config("lan_iface").unwrap_or(None).unwrap_or_default();
        let wan_mode = client::get_config("wan_mode").unwrap_or(None).unwrap_or_else(|| "dhcp".to_string());
        let hostname = client::get_config("router_hostname").unwrap_or(None).unwrap_or_default();
        let timezone = client::get_config("timezone").unwrap_or(None).unwrap_or_else(|| "UTC".to_string());
        let upstream = client::get_config("upstream_dns").unwrap_or(None).unwrap_or_else(|| "auto".to_string());
        Ok::<_, String>((wan_iface, lan_iface, wan_mode, hostname, timezone, upstream))
    });
    let reservations = Resource::new(
        || (),
        |_| async { client::list_dhcp_reservations() },
    );
    let port_forwards = Resource::new(|| (), |_| async { client::list_port_forwards() });
    let upnp_data = Resource::new(|| (), |_| async { client::get_upnp_enabled() });
    let vlan_status = Resource::new(|| (), |_| async { client::get_vlan_status() });
    let switches = Resource::new(|| (), |_| async { client::list_switches() });
    let devices_for_groups = Resource::new(|| (), |_| async { client::list_devices() });
    let qos_config = Resource::new(|| (), |_| async { client::get_qos_config() });

    view! {
        <Layout title="Settings" active_page="settings">
            <SettingsNav active="network" />

            <Suspense fallback=move || view! { <p>"Loading network config..."</p> }>
                {move || {
                    let ifaces_data = interfaces.get();
                    let config_data = net_config.get();
                    match (ifaces_data, config_data) {
                        (Some(Ok(ifaces)), Some(Ok((wan_iface, lan_iface, wan_mode, hostname, timezone, upstream)))) => {
                            let iface_action = ServerAction::<UpdateInterfaces>::new();
                            let wan_action = ServerAction::<UpdateWanConfig>::new();
                            let hostname_action = ServerAction::<UpdateHostname>::new();
                            let tz_action = ServerAction::<UpdateTimezone>::new();
                            let dns_action = ServerAction::<UpdateUpstreamDns>::new();

                            let is_static = wan_mode == "static";

                            let upstream_select = match upstream.as_str() {
                                "1.1.1.1,1.0.0.1" => "cloudflare",
                                "8.8.8.8,8.8.4.4" => "google",
                                "9.9.9.9,149.112.112.112" => "quad9",
                                "auto" => "auto",
                                _ => "custom",
                            };
                            let custom_dns_val = if upstream_select == "custom" { upstream.clone() } else { String::new() };

                            Some(view! {
                                <details class="settings-section" open>
                                    <summary class="settings-section-sub">"Interfaces"</summary>
                                    <ActionForm action=iface_action>
                                        <div class="settings-row">
                                            <span class="settings-label">"WAN Interface"</span>
                                            <span class="settings-value">
                                                <select name="wan">
                                                    <option value="">"-- Select --"</option>
                                                    {ifaces.iter().map(|iface| {
                                                        let name = iface.name.clone();
                                                        let selected = name == wan_iface;
                                                        let label = format!("{} ({})", iface.name, iface.mac);
                                                        view! {
                                                            <option value={name} selected=selected>{label}</option>
                                                        }
                                                    }).collect_view()}
                                                </select>
                                            </span>
                                        </div>
                                        <div class="settings-row">
                                            <span class="settings-label">"LAN Interface"</span>
                                            <span class="settings-value">
                                                <select name="lan">
                                                    <option value="">"-- Select --"</option>
                                                    {ifaces.iter().map(|iface| {
                                                        let name = iface.name.clone();
                                                        let selected = name == lan_iface;
                                                        let label = format!("{} ({})", iface.name, iface.mac);
                                                        view! {
                                                            <option value={name} selected=selected>{label}</option>
                                                        }
                                                    }).collect_view()}
                                                </select>
                                            </span>
                                        </div>
                                        <p class="hint">"Requires agent restart after changing."</p>
                                        <div class="actions-bar">
                                            <button type="submit" class="btn btn-primary btn-sm">"Save Interfaces"</button>
                                        </div>
                                    </ActionForm>
                                    <ErrorToast value=iface_action.value() />
                                </details>

                                <details class="settings-section" open>
                                    <summary class="settings-section-sub">"WAN Mode"</summary>
                                    <ActionForm action=wan_action>
                                        <div class="settings-row">
                                            <span class="settings-label">"Mode"</span>
                                            <span class="settings-value">
                                                <label class="mr-md">
                                                    <input type="radio" name="wan_mode" value="dhcp" checked={!is_static} />
                                                    " DHCP"
                                                </label>
                                                <label>
                                                    <input type="radio" name="wan_mode" value="static" checked={is_static} />
                                                    " Static"
                                                </label>
                                            </span>
                                        </div>
                                        <div class="settings-row">
                                            <span class="settings-label">"Static IP"</span>
                                            <span class="settings-value">
                                                <input type="text" name="static_ip" placeholder="192.168.1.2" />
                                            </span>
                                        </div>
                                        <div class="settings-row">
                                            <span class="settings-label">"Gateway"</span>
                                            <span class="settings-value">
                                                <input type="text" name="gateway" placeholder="192.168.1.1" />
                                            </span>
                                        </div>
                                        <div class="settings-row">
                                            <span class="settings-label">"DNS Server"</span>
                                            <span class="settings-value">
                                                <input type="text" name="dns" placeholder="1.1.1.1" />
                                            </span>
                                        </div>
                                        <div class="actions-bar">
                                            <button type="submit" class="btn btn-primary btn-sm">"Save WAN Config"</button>
                                        </div>
                                    </ActionForm>
                                    <ErrorToast value=wan_action.value() />
                                </details>

                                <details class="settings-section">
                                    <summary class="settings-section-sub">"Hostname"</summary>
                                    <ActionForm action=hostname_action>
                                        <div class="settings-row">
                                            <span class="settings-label">"Router Hostname"</span>
                                            <span class="settings-value">
                                                <input type="text" name="hostname" value={hostname} />
                                            </span>
                                        </div>
                                        <div class="actions-bar">
                                            <button type="submit" class="btn btn-primary btn-sm">"Save"</button>
                                        </div>
                                    </ActionForm>
                                    <ErrorToast value=hostname_action.value() />
                                </details>

                                <details class="settings-section">
                                    <summary class="settings-section-sub">"Timezone"</summary>
                                    <ActionForm action=tz_action>
                                        <div class="settings-row">
                                            <span class="settings-label">"Timezone"</span>
                                            <span class="settings-value">
                                                <input type="text" name="timezone" value={timezone} />
                                            </span>
                                        </div>
                                        <div class="actions-bar">
                                            <button type="submit" class="btn btn-primary btn-sm">"Save"</button>
                                        </div>
                                    </ActionForm>
                                    <ErrorToast value=tz_action.value() />
                                </details>

                                <details class="settings-section">
                                    <summary class="settings-section-sub">"Upstream DNS"</summary>
                                    <ActionForm action=dns_action>
                                        <div class="settings-row">
                                            <span class="settings-label">"Provider"</span>
                                            <span class="settings-value">
                                                <select name="upstream_dns">
                                                    <option value="auto" selected={upstream_select == "auto"}>"Auto (from DHCP)"</option>
                                                    <option value="cloudflare" selected={upstream_select == "cloudflare"}>"Cloudflare (1.1.1.1)"</option>
                                                    <option value="google" selected={upstream_select == "google"}>"Google (8.8.8.8)"</option>
                                                    <option value="quad9" selected={upstream_select == "quad9"}>"Quad9 (9.9.9.9)"</option>
                                                    <option value="custom" selected={upstream_select == "custom"}>"Custom"</option>
                                                </select>
                                            </span>
                                        </div>
                                        <div class="settings-row">
                                            <span class="settings-label">"Custom DNS"</span>
                                            <span class="settings-value">
                                                <input type="text" name="custom_dns" placeholder="1.1.1.1,8.8.8.8" value={custom_dns_val} />
                                            </span>
                                        </div>
                                        <div class="actions-bar">
                                            <button type="submit" class="btn btn-primary btn-sm">"Save"</button>
                                        </div>
                                    </ActionForm>
                                    <ErrorToast value=dns_action.value() />
                                </details>
                            }.into_any())
                        }
                        (Some(Err(e)), _) | (_, Some(Err(e))) => {
                            Some(view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any())
                        }
                        _ => None,
                    }
                }}
            </Suspense>

            <Suspense fallback=move || view! { <p>"Loading reservations..."</p> }>
                {move || reservations.get().map(|result| match result {
                    Ok(res) => {
                        view! {
                            <details class="settings-section">
                                <summary class="settings-section-sub">"DHCP Reservations"</summary>
                                <div class="table-scroll">
                                    <table class="data-table">
                                        <thead>
                                            <tr>
                                                <th>"MAC Address"</th>
                                                <th>"Subnet ID"</th>
                                                <th>"Actions"</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {res.iter().map(|r| {
                                                let mac = r.mac.clone();
                                                let dialog_id = format!("confirm-rm-res-{}", mac);
                                                let remove_action = ServerAction::<RemoveReservation>::new();
                                                view! {
                                                    <tr>
                                                        <td>{r.mac.clone()}</td>
                                                        <td>{r.subnet_id}</td>
                                                        <td>
                                                            <button type="button" class="btn btn-danger btn-sm"
                                                                data-dialog-open="">"Remove"</button>
                                                            <dialog class="confirm-dialog" aria-labelledby={dialog_id.clone()}>
                                                                <h3 id={dialog_id.clone()}>"Remove Reservation?"</h3>
                                                                <p>{format!("Reservation for {} will be removed.", r.mac)}</p>
                                                                <div class="dialog-actions">
                                                                    <button type="button" class="btn btn-sm"
                                                                        data-dialog-close="">"Cancel"</button>
                                                                    <ActionForm action=remove_action attr:class="inline-form">
                                                                        <input type="hidden" name="mac" value={mac} />
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
                            </details>
                        }.into_any()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                })}
            </Suspense>

            // ─── Port Forwarding ───
            <details id="port-forwarding" class="settings-section" open>
                <summary class="settings-section-sub">"Port Forwarding"</summary>
                <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                    {move || port_forwards.get().map(|result| match result {
                        Ok(info) => {
                            let forwards = info.port_forwards;
                            let dmz_ip = info.dmz_ip.clone();

                            let add_action = ServerAction::<AddPortForward>::new();

                            view! {
                                <h4>"Rules"</h4>
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
                                            let dialog_id = format!("confirm-rm-pf-{}", id);
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
                                                        <button type="button" class="btn btn-danger btn-sm"
                                                            data-dialog-open="">"Remove"</button>
                                                        <dialog class="confirm-dialog" aria-labelledby={dialog_id.clone()}>
                                                            <h3 id={dialog_id.clone()}>"Remove Port Forward?"</h3>
                                                            <p>"This port forward rule will be permanently removed."</p>
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

                                <h4>"Add Rule"</h4>
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

                                <h4>"DMZ Host"</h4>
                                <p>"Current DMZ: " {if dmz_ip.is_empty() { "None".to_string() } else { dmz_ip }}</p>
                            }.into_any()
                        }
                        Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                    })}
                </Suspense>

                <details class="settings-section">
                    <summary class="settings-section-sub">"UPnP / NAT-PMP"</summary>
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
                </details>

                {
                    let pinholes = Resource::new(|| (), |_| async { client::list_ipv6_pinholes() });
                    let add_pinhole_action = ServerAction::<AddIpv6Pinhole>::new();
                    view! {
                        <details class="settings-section">
                            <summary class="settings-section-sub">"IPv6 Pinholes"</summary>
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
                                                        let dialog_id = format!("confirm-rm-ph-{}", id);
                                                        let remove_action = ServerAction::<RemoveIpv6Pinhole>::new();
                                                        view! {
                                                            <tr>
                                                                <td>{mac}</td>
                                                                <td>{protocol}</td>
                                                                <td>{port_start}</td>
                                                                <td>{port_end}</td>
                                                                <td>{description}</td>
                                                                <td>
                                                                    <button type="button" class="btn btn-danger btn-sm"
                                                                        data-dialog-open="">"Remove"</button>
                                                                    <dialog class="confirm-dialog" aria-labelledby={dialog_id.clone()}>
                                                                        <h3 id={dialog_id.clone()}>"Remove Pinhole?"</h3>
                                                                        <p>"This IPv6 pinhole will be permanently removed."</p>
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
                                    }
                                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                                })}
                            </Suspense>

                            <h4>"Add Pinhole"</h4>
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
                        </details>
                    }
                }
            </details>

            // ─── VLANs ───
            <details id="vlans" class="settings-section">
                <summary class="settings-section-sub">"VLANs"</summary>
                <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                    {move || vlan_status.get().map(|result| match result {
                        Ok((enabled, vlans)) => {
                            let status_text = if enabled { "Enabled" } else { "Disabled" };
                            let status_class = if enabled { "card-value success" } else { "card-value warning" };

                            let enable_action = ServerAction::<EnableVlan>::new();
                            let disable_action = ServerAction::<DisableVlan>::new();

                            view! {
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

                                <h4>"VLAN Assignments"</h4>
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
                            }.into_any()
                        }
                        Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                    })}
                </Suspense>
            </details>

            // ─── Switches ───
            <details id="switches" class="settings-section">
                <summary class="settings-section-sub">"Switches"</summary>
                <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                    {move || switches.get().map(|result| match result {
                        Ok(list) => {
                            let add_action = ServerAction::<AddSwitch>::new();

                            view! {
                                <p class="settings-description">"Add managed switches for MAC-to-port discovery. Uses SNMP v2c or v3 read-only polling."</p>
                                {if list.is_empty() {
                                    view! { <p class="settings-empty">"No switches configured. Add managed switches for automatic MAC-to-port discovery."</p> }.into_any()
                                } else {
                                    view! {
                                        <div class="table-scroll">
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
                                                        let dialog_id = format!("confirm-rm-sw-{}", name_for_remove);
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
                                                                    <button type="button" class="btn btn-danger btn-sm"
                                                                        data-dialog-open="">"Remove"</button>
                                                                    <dialog class="confirm-dialog" aria-labelledby={dialog_id.clone()}>
                                                                        <h3 id={dialog_id.clone()}>"Remove Switch?"</h3>
                                                                        <p>{format!("\"{}\" will be permanently removed.", sw.name)}</p>
                                                                        <div class="dialog-actions">
                                                                            <button type="button" class="btn btn-sm"
                                                                                data-dialog-close="">"Cancel"</button>
                                                                            <ActionForm action=remove_action attr:class="inline-form">
                                                                                <input type="hidden" name="name" value={name_for_remove} />
                                                                                <button type="submit" class="btn btn-danger btn-sm">"Confirm Remove"</button>
                                                                            </ActionForm>
                                                                        </div>
                                                                    </dialog>
                                                                    <ErrorToast value=test_action.value() />
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
                            }.into_any()
                        }
                        Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                    })}
                </Suspense>
            </details>

            // ─── Groups ───
            <details id="groups" class="settings-section">
                <summary class="settings-section-sub">"Groups"</summary>
                <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                    {move || devices_for_groups.get().map(|result| match result {
                        Ok(devices) => {
                            render_groups(devices)
                        }
                        Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                    })}
                </Suspense>
            </details>

            // ─── QoS ───
            <Suspense fallback=move || view! { <p>"Loading QoS config..."</p> }>
                {move || qos_config.get().map(|result| match result {
                    Ok(config) => {
                        let enabled = config.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
                        let upload_mbps = config.get("upload_mbps").and_then(|v| v.as_u64()).map(|v| v.to_string()).unwrap_or_default();
                        let download_mbps = config.get("download_mbps").and_then(|v| v.as_u64()).map(|v| v.to_string()).unwrap_or_default();
                        let test_url = config.get("test_url").and_then(|v| v.as_str()).unwrap_or("").to_string();

                        let qos_action = ServerAction::<SetQosConfig>::new();
                        let test_url_action = ServerAction::<SetQosTestUrl>::new();
                        let speed_test_action = ServerAction::<RunSpeedTest>::new();

                        view! {
                            <details class="settings-section">
                                <summary class="settings-section-sub">"QoS / Bufferbloat Prevention"</summary>
                                <p class="hint">"CAKE qdisc with per-device fair queuing. Set bandwidth to ~85-90% of your ISP speed."</p>
                                <ActionForm action=qos_action>
                                    <div class="settings-row">
                                        <span class="settings-label">"Enabled"</span>
                                        <span class="settings-value">
                                            <select name="qos_enabled">
                                                <option value="true" selected={enabled}>"Yes"</option>
                                                <option value="false" selected={!enabled}>"No"</option>
                                            </select>
                                        </span>
                                    </div>
                                    <div class="settings-row">
                                        <span class="settings-label">"Upload Speed Mbps"</span>
                                        <span class="settings-value">
                                            <input type="number" name="upload_mbps" min="1" max="1000000" value={upload_mbps} />
                                        </span>
                                    </div>
                                    <div class="settings-row">
                                        <span class="settings-label">"Download Speed Mbps"</span>
                                        <span class="settings-value">
                                            <input type="number" name="download_mbps" min="1" max="1000000" value={download_mbps} />
                                        </span>
                                    </div>
                                    <div class="actions-bar">
                                        <button type="submit" class="btn btn-primary btn-sm">"Save"</button>
                                    </div>
                                </ActionForm>
                                <ActionForm action=test_url_action attr:class="mt-sm">
                                    <div class="settings-row">
                                        <span class="settings-label">"Speed Test URL"</span>
                                        <span class="settings-value">
                                            <input type="text" name="url" placeholder="https://speed.cloudflare.com/__down?bytes=25000000" value={test_url} />
                                        </span>
                                    </div>
                                    <div class="actions-bar">
                                        <button type="submit" class="btn btn-primary btn-sm">"Save Test URL"</button>
                                    </div>
                                </ActionForm>
                                <ActionForm action=speed_test_action attr:class="mt-sm">
                                    <button type="submit" class="btn btn-sm">"Run Speed Test"</button>
                                </ActionForm>
                                <ErrorToast value=qos_action.value() />
                                <ErrorToast value=test_url_action.value() />
                                <ErrorToast value=speed_test_action.value() />
                            </details>
                        }.into_any()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                })}
            </Suspense>
        </Layout>
    }
}

fn render_groups(devices: Vec<crate::types::Device>) -> AnyView {
    view! {
        <div class="group-grid">
            {GROUPS.iter().map(|g| {
                let count = devices.iter().filter(|d| d.device_group == g.key).count();
                let badge_class = format!("badge badge-{}", g.key);
                view! {
                    <div class="group-card">
                        <span class={badge_class}>{g.name}</span>
                        <p>{g.description}</p>
                        <p><strong>{count}</strong>" device"{if count != 1 { "s" } else { "" }}</p>
                    </div>
                }
            }).collect_view()}
        </div>

        <div class="section">
            <h4>"Access Policy Matrix"</h4>
            <div class="table-scroll">
                <table class="policy-matrix">
                    <thead>
                        <tr>
                            <th></th>
                            <th>"Trusted"</th>
                            <th>"IoT"</th>
                            <th>"Guest"</th>
                            <th>"Servers"</th>
                            <th>"Quarantine"</th>
                            <th>"Blocked"</th>
                            <th>"Internet"</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><strong>"Trusted"</strong></td>
                            <td class="policy-allow">"\u{2713}"</td>
                            <td class="policy-allow">"\u{2713}"</td>
                            <td class="policy-allow">"\u{2713}"</td>
                            <td class="policy-allow">"\u{2713}"</td>
                            <td class="policy-allow">"\u{2713}"</td>
                            <td class="policy-deny">"\u{2717}"</td>
                            <td class="policy-allow">"\u{2713}"</td>
                        </tr>
                        <tr>
                            <td><strong>"IoT"</strong></td>
                            <td class="policy-deny">"\u{2717}"</td>
                            <td class="policy-deny">"\u{2717}"</td>
                            <td class="policy-deny">"\u{2717}"</td>
                            <td class="policy-deny">"\u{2717}"</td>
                            <td class="policy-deny">"\u{2717}"</td>
                            <td class="policy-deny">"\u{2717}"</td>
                            <td class="policy-allow">"\u{2713}"</td>
                        </tr>
                        <tr>
                            <td><strong>"Guest"</strong></td>
                            <td class="policy-deny">"\u{2717}"</td>
                            <td class="policy-deny">"\u{2717}"</td>
                            <td class="policy-deny">"\u{2717}"</td>
                            <td class="policy-deny">"\u{2717}"</td>
                            <td class="policy-deny">"\u{2717}"</td>
                            <td class="policy-deny">"\u{2717}"</td>
                            <td class="policy-allow">"\u{2713}"</td>
                        </tr>
                        <tr>
                            <td><strong>"Servers"</strong></td>
                            <td class="policy-deny">"\u{2717}"</td>
                            <td class="policy-deny">"\u{2717}"</td>
                            <td class="policy-deny">"\u{2717}"</td>
                            <td class="policy-deny">"\u{2717}"</td>
                            <td class="policy-deny">"\u{2717}"</td>
                            <td class="policy-deny">"\u{2717}"</td>
                            <td class="policy-allow">"\u{2713}"</td>
                        </tr>
                        <tr>
                            <td><strong>"Quarantine"</strong></td>
                            <td class="policy-deny">"\u{2717}"</td>
                            <td class="policy-deny">"\u{2717}"</td>
                            <td class="policy-deny">"\u{2717}"</td>
                            <td class="policy-deny">"\u{2717}"</td>
                            <td class="policy-deny">"\u{2717}"</td>
                            <td class="policy-deny">"\u{2717}"</td>
                            <td class="policy-allow">"\u{2713}"</td>
                        </tr>
                        <tr>
                            <td><strong>"Blocked"</strong></td>
                            <td class="policy-deny">"\u{2717}"</td>
                            <td class="policy-deny">"\u{2717}"</td>
                            <td class="policy-deny">"\u{2717}"</td>
                            <td class="policy-deny">"\u{2717}"</td>
                            <td class="policy-deny">"\u{2717}"</td>
                            <td class="policy-deny">"\u{2717}"</td>
                            <td class="policy-deny">"\u{2717}"</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    }.into_any()
}
