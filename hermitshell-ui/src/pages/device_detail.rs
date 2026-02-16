use leptos::*;
use leptos_router::*;
use crate::client;
use crate::components::layout::Layout;
use crate::format_bytes;

fn format_timestamp(ts: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let diff = now - ts;
    if diff < 60 {
        "just now".to_string()
    } else if diff < 3600 {
        format!("{}m ago", diff / 60)
    } else if diff < 86400 {
        format!("{}h ago", diff / 3600)
    } else {
        format!("{}d ago", diff / 86400)
    }
}

#[component]
pub fn DeviceDetail() -> impl IntoView {
    let params = use_params_map();

    let device = create_resource(
        move || params.with(|p| p.get("mac").cloned().unwrap_or_default()),
        |mac| async move { client::get_device(&mac) },
    );

    view! {
        <Layout title="Device Detail" active_page="devices">
            <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                {move || device.get().map(|result| match result {
                    Ok(d) => {
                        let mac = d.mac.clone();
                        let group = d.device_group.clone();
                        let badge_class = format!("badge badge-{}", group);

                        view! {
                            <div class="detail-grid">
                                <div class="detail-item">
                                    <div class="detail-label">"MAC Address"</div>
                                    <div class="detail-value">{mac.clone()}</div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">"IP Address"</div>
                                    <div class="detail-value">{d.ip.clone().unwrap_or_else(|| "\u{2014}".to_string())}</div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">"Hostname"</div>
                                    <div class="detail-value">{d.hostname.clone().unwrap_or_else(|| "\u{2014}".to_string())}</div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">"Group"</div>
                                    <div class="detail-value"><span class={badge_class}>{group.clone()}</span></div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">"First Seen"</div>
                                    <div class="detail-value">{format_timestamp(d.first_seen)}</div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">"Last Seen"</div>
                                    <div class="detail-value">{format_timestamp(d.last_seen)}</div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">"Downloaded (RX)"</div>
                                    <div class="detail-value">{format_bytes(d.rx_bytes)}</div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">"Uploaded (TX)"</div>
                                    <div class="detail-value">{format_bytes(d.tx_bytes)}</div>
                                </div>
                            </div>

                            <h2 class="section-header">"Actions"</h2>
                            <div class="actions-bar">
                                {if group != "blocked" {
                                    view! {
                                        <form method="post" action="/api/set-group" style="display:inline">
                                            <input type="hidden" name="mac" value={mac.clone()} />
                                            <input type="hidden" name="redirect" value={format!("/devices/{}", mac)} />
                                            <select name="group">
                                                <option value="trusted" selected={group == "trusted"}>"Trusted"</option>
                                                <option value="iot" selected={group == "iot"}>"IoT"</option>
                                                <option value="guest" selected={group == "guest"}>"Guest"</option>
                                                <option value="servers" selected={group == "servers"}>"Servers"</option>
                                                <option value="quarantine" selected={group == "quarantine"}>"Quarantine"</option>
                                            </select>
                                            " "
                                            <button type="submit" class="btn btn-primary btn-sm">"Change Group"</button>
                                        </form>
                                    }.into_view()
                                } else {
                                    view! { <span></span> }.into_view()
                                }}

                                {if group == "blocked" {
                                    view! {
                                        <form method="post" action="/api/unblock" style="display:inline">
                                            <input type="hidden" name="mac" value={mac.clone()} />
                                            <button type="submit" class="btn btn-primary btn-sm">"Unblock"</button>
                                        </form>
                                    }.into_view()
                                } else {
                                    view! {
                                        <form method="post" action="/api/block" style="display:inline">
                                            <input type="hidden" name="mac" value={mac.clone()} />
                                            <button type="submit" class="btn btn-danger btn-sm">"Block"</button>
                                        </form>
                                    }.into_view()
                                }}
                            </div>
                        }.into_view()
                    }
                    Err(e) => view! { <p>"Error: " {e}</p> }.into_view(),
                })}
            </Suspense>
        </Layout>
    }
}
