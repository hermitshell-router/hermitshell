use leptos::*;
use crate::components::layout::Layout;

#[component]
pub fn DeviceList() -> impl IntoView {
    view! {
        <Layout title="Devices" active_page="devices">
            <p>"Device list coming soon."</p>
        </Layout>
    }
}
