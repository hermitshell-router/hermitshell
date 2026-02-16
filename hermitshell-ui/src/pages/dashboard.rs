use leptos::*;
use crate::components::layout::Layout;

#[component]
pub fn Dashboard() -> impl IntoView {
    view! {
        <Layout title="Dashboard" active_page="dashboard">
            <p>"Dashboard content coming soon."</p>
        </Layout>
    }
}
