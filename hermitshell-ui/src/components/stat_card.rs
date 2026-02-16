use leptos::*;

#[component]
pub fn StatCard(
    #[prop(into)] label: String,
    #[prop(into)] value: String,
    #[prop(default = String::new(), into)] class: String,
) -> impl IntoView {
    let value_class = format!("card-value {}", class);
    view! {
        <div class="card">
            <div class="card-label">{label}</div>
            <div class={value_class}>{value}</div>
        </div>
    }
}
