use leptos::*;
use crate::client;
use crate::components::layout::Layout;

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
pub fn Groups() -> impl IntoView {
    let data = create_resource(
        || (),
        |_| async { client::list_devices() },
    );

    view! {
        <Layout title="Groups" active_page="groups">
            <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                {move || data.get().map(|result| match result {
                    Ok(devices) => {
                        render_groups(devices)
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_view(),
                })}
            </Suspense>
        </Layout>
    }
}

fn render_groups(devices: Vec<crate::types::Device>) -> View {
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
            <h2>"Access Policy Matrix"</h2>
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
    }.into_view()
}
