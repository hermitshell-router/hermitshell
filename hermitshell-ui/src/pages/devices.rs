use leptos::prelude::*;
use leptos_router::hooks::*;
use crate::client;
use crate::components::layout::Layout;
use crate::format_bytes;
use crate::server_fns::{ApproveDevice, BlockDevice, UnblockDevice};

const GROUPS: &[&str] = &["all", "quarantine", "trusted", "iot", "guest", "servers", "blocked"];

#[component]
pub fn DeviceList() -> impl IntoView {
    let query = use_query_map();

    let data = Resource::new(
        || (),
        |_| async { client::list_devices() },
    );

    view! {
        <Layout title="Devices" active_page="devices">
            <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                {move || {
                    let filter = query.with(|q| q.get("group").unwrap_or_else(|| "all".to_string()));

                    data.get().map(|result| match result {
                        Ok(devices) => {
                            let filtered: Vec<_> = if filter == "all" {
                                devices.clone()
                            } else {
                                devices.into_iter().filter(|d| d.device_group == filter).collect()
                            };

                            view! {
                                <div class="filter-bar">
                                    {GROUPS.iter().map(|g| {
                                        let href = if *g == "all" {
                                            "/devices".to_string()
                                        } else {
                                            format!("/devices?group={}", g)
                                        };
                                        let class = if *g == filter { "active" } else { "" };
                                        let label = match *g {
                                            "all" => "All",
                                            "quarantine" => "Quarantine",
                                            "trusted" => "Trusted",
                                            "iot" => "IoT",
                                            "guest" => "Guest",
                                            "servers" => "Servers",
                                            "blocked" => "Blocked",
                                            _ => g,
                                        };
                                        view! {
                                            <a href={href} class={class}>{label}</a>
                                        }
                                    }).collect_view()}
                                </div>

                                <table>
                                    <thead>
                                        <tr>
                                            <th>"Hostname"</th>
                                            <th>"IP"</th>
                                            <th>"MAC"</th>
                                            <th>"Group"</th>
                                            <th>"RX"</th>
                                            <th>"TX"</th>
                                            <th>"Actions"</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {filtered.iter().map(|d| {
                                            let mac = d.mac.clone();
                                            let group = d.device_group.clone();
                                            let badge_class = format!("badge badge-{}", group);

                                            let approve_action = ServerAction::<ApproveDevice>::new();
                                            let unblock_action = ServerAction::<UnblockDevice>::new();
                                            let block_action = ServerAction::<BlockDevice>::new();

                                            view! {
                                                <tr>
                                                    <td>
                                                        <a href={format!("/devices/{}", mac)}>
                                                            {d.hostname.clone().unwrap_or_else(|| "(unknown)".to_string())}
                                                        </a>
                                                    </td>
                                                    <td>{d.ip.clone().unwrap_or_default()}</td>
                                                    <td style="color: var(--text-muted); font-size: 0.8125rem;">{mac.clone()}</td>
                                                    <td><span class={badge_class}>{group.clone()}</span></td>
                                                    <td>{format_bytes(d.rx_bytes)}</td>
                                                    <td>{format_bytes(d.tx_bytes)}</td>
                                                    <td>
                                                        {if group == "quarantine" {
                                                            view! {
                                                                <ActionForm action=approve_action attr:style="display:inline">
                                                                    <input type="hidden" name="mac" value={mac.clone()} />
                                                                    <select name="group">
                                                                        <option value="trusted">"Trusted"</option>
                                                                        <option value="iot">"IoT"</option>
                                                                        <option value="guest">"Guest"</option>
                                                                        <option value="servers">"Servers"</option>
                                                                    </select>
                                                                    " "
                                                                    <button type="submit" class="btn btn-primary btn-sm">"Approve"</button>
                                                                </ActionForm>
                                                            }.into_any()
                                                        } else if group == "blocked" {
                                                            view! {
                                                                <ActionForm action=unblock_action attr:style="display:inline">
                                                                    <input type="hidden" name="mac" value={mac.clone()} />
                                                                    <button type="submit" class="btn btn-primary btn-sm">"Unblock"</button>
                                                                </ActionForm>
                                                            }.into_any()
                                                        } else {
                                                            view! {
                                                                <ActionForm action=block_action attr:style="display:inline">
                                                                    <input type="hidden" name="mac" value={mac.clone()} />
                                                                    <button type="submit" class="btn btn-danger btn-sm">"Block"</button>
                                                                </ActionForm>
                                                            }.into_any()
                                                        }}
                                                    </td>
                                                </tr>
                                            }
                                        }).collect_view()}
                                    </tbody>
                                </table>
                            }.into_any()
                        }
                        Err(e) => view! { <p>"Error: " {e}</p> }.into_any(),
                    })
                }}
            </Suspense>
        </Layout>
    }
}
