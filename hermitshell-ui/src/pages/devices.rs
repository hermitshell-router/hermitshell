use leptos::prelude::*;
use leptos_router::hooks::*;
use crate::client;
use crate::components::layout::Layout;
use crate::components::toast::ErrorToast;
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
                    let search = query.with(|q| q.get("search").unwrap_or_default());
                    let search_lower = search.to_lowercase();

                    data.get().map(|result| match result {
                        Ok(devices) => {
                            let mut filtered: Vec<_> = if filter == "all" {
                                devices.clone()
                            } else {
                                devices.into_iter().filter(|d| d.device_group == filter).collect()
                            };

                            if !search_lower.is_empty() {
                                filtered.retain(|d| {
                                    d.nickname.as_deref().unwrap_or("").to_lowercase().contains(&search_lower)
                                    || d.hostname.as_deref().unwrap_or("").to_lowercase().contains(&search_lower)
                                    || d.ipv4.as_deref().unwrap_or("").to_lowercase().contains(&search_lower)
                                    || d.mac.to_lowercase().contains(&search_lower)
                                });
                            }

                            let search_val = search.clone();
                            let filter_for_hidden = filter.clone();

                            view! {
                                <form method="get" action="/devices" class="device-search">
                                    <input type="text" name="search" placeholder="Search by name, IP, or MAC\u{2026}"
                                           value={search_val} />
                                    {if filter_for_hidden != "all" {
                                        Some(view! { <input type="hidden" name="group" value={filter_for_hidden} /> })
                                    } else {
                                        None
                                    }}
                                    <button type="submit" class="btn btn-sm">"Search"</button>
                                </form>

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

                                <div class="table-scroll">
                                    <table>
                                        <thead>
                                            <tr>
                                                <th>"Name"</th>
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
                                                                {d.nickname.clone()
                                                                    .or_else(|| d.hostname.clone())
                                                                    .unwrap_or_else(|| "(unknown)".to_string())}
                                                            </a>
                                                            {d.nickname.as_ref().and(d.hostname.as_ref()).map(|h| {
                                                                view! { <br /><span class="text-muted text-sm">{h.clone()}</span> }
                                                            })}
                                                        </td>
                                                        <td>{d.ipv4.clone().unwrap_or_default()}</td>
                                                        <td class="text-muted">{mac.clone()}</td>
                                                        <td><span class={badge_class}>{group.clone()}</span></td>
                                                        <td>{format_bytes(d.rx_bytes)}</td>
                                                        <td>{format_bytes(d.tx_bytes)}</td>
                                                        <td>
                                                            {if group == "quarantine" {
                                                                view! {
                                                                    <ActionForm action=approve_action attr:class="inline-form">
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
                                                                    <ActionForm action=unblock_action attr:class="inline-form">
                                                                        <input type="hidden" name="mac" value={mac.clone()} />
                                                                        <button type="submit" class="btn btn-primary btn-sm">"Unblock"</button>
                                                                    </ActionForm>
                                                                }.into_any()
                                                            } else {
                                                                view! {
                                                                    <button type="button"
                                                                        class="btn btn-danger btn-sm"
                                                                        data-dialog-open="">"Block"</button>
                                                                    <dialog class="confirm-dialog" aria-labelledby="confirm-block-device">
                                                                        <h3 id="confirm-block-device">"Block Device?"</h3>
                                                                        <p>"This device will lose all network access."</p>
                                                                        <div class="dialog-actions">
                                                                            <button type="button" class="btn btn-sm"
                                                                                data-dialog-close="">"Cancel"</button>
                                                                            <ActionForm action=block_action>
                                                                                <input type="hidden" name="mac" value={mac.clone()} />
                                                                                <button type="submit" class="btn btn-danger btn-sm">"Confirm Block"</button>
                                                                            </ActionForm>
                                                                        </div>
                                                                    </dialog>
                                                                }.into_any()
                                                            }}
                                                            <ErrorToast value=approve_action.value() />
                                                            <ErrorToast value=unblock_action.value() />
                                                            <ErrorToast value=block_action.value() />
                                                        </td>
                                                    </tr>
                                                }
                                            }).collect_view()}
                                        </tbody>
                                    </table>
                                </div>
                            }.into_any()
                        }
                        Err(e) => view! { <p>"Error: " {e}</p> }.into_any(),
                    })
                }}
            </Suspense>
        </Layout>
    }
}
