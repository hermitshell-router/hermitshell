use leptos::prelude::*;
use leptos_router::hooks::use_query_map;
use server_fn::error::ServerFnError;

#[component]
pub fn SuccessToast() -> impl IntoView {
    let query = use_query_map();
    let msg = move || query.with(|q| q.get("msg"));

    move || msg().map(|m| {
        view! {
            <div class="toast toast-success">{m}</div>
        }
    })
}

#[component]
pub fn ErrorToast(#[prop(into)] value: Signal<Option<Result<(), ServerFnError>>>) -> impl IntoView {
    let error_msg = move || match value.get() {
        Some(Err(e)) => Some(e.to_string()),
        _ => None,
    };

    move || error_msg().map(|e| {
        view! {
            <div class="toast toast-error">{e}</div>
        }
    })
}
