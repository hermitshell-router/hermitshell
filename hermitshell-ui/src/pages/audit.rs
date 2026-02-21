use leptos::prelude::*;
use crate::client;
use crate::components::layout::Layout;

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
pub fn Audit() -> impl IntoView {
    let data = Resource::new(|| (), |_| async { client::list_audit_logs(200) });

    view! {
        <Layout title="Audit Trail" active_page="audit">
            <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                {move || data.get().map(|result| match result {
                    Ok(entries) => {
                        if entries.is_empty() {
                            view! { <p class="text-muted">"No audit entries yet."</p> }.into_any()
                        } else {
                            view! {
                                <table class="device-table">
                                    <thead>
                                        <tr>
                                            <th>"Time"</th>
                                            <th>"Action"</th>
                                            <th>"Detail"</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {entries.into_iter().map(|entry| {
                                            let time = format_timestamp(entry.created_at);
                                            view! {
                                                <tr>
                                                    <td>{time}</td>
                                                    <td>{entry.action}</td>
                                                    <td>{entry.detail}</td>
                                                </tr>
                                            }
                                        }).collect_view()}
                                    </tbody>
                                </table>
                            }.into_any()
                        }
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                })}
            </Suspense>
        </Layout>
    }
}
