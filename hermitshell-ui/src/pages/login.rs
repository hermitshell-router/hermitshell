use leptos::prelude::*;
use leptos::nonce::use_nonce;
use leptos_router::hooks::use_query_map;
use crate::components::layout::CspMeta;
use crate::components::toast::ErrorToast;
use crate::server_fns::{Login, LoginTotp};

#[component]
pub fn Login() -> impl IntoView {
    let login_action = ServerAction::<Login>::new();
    let totp_action = ServerAction::<LoginTotp>::new();
    let params = use_query_map();
    let is_totp_step = move || params.get().get("step").unwrap_or_default() == "totp";

    view! {
        <html lang="en">
            <head>
                <meta charset="utf-8" />
                <CspMeta />
                <meta name="viewport" content="width=device-width, initial-scale=1" />
                <title>"Login - HermitShell"</title>
                <link rel="stylesheet" href="/style.css" />
            </head>
            <body>
                <div class="login-container">
                    <h1>"HermitShell"</h1>
                    {move || {
                        if is_totp_step() {
                            view! {
                                <p class="text-sm text-muted mb-md">"Enter the 6-digit code from your authenticator app."</p>
                                <ActionForm action=totp_action>
                                    <label for="totp_code">"Authentication Code"</label>
                                    <input
                                        type="text"
                                        name="totp_code"
                                        id="totp_code"
                                        inputmode="numeric"
                                        pattern="[0-9]{6}"
                                        maxlength="6"
                                        autocomplete="one-time-code"
                                        required
                                        autofocus
                                        placeholder="000000"
                                    />
                                    <button type="submit" class="btn btn-primary">"Verify"</button>
                                </ActionForm>
                                <ErrorToast value=totp_action.value() />
                            }.into_any()
                        } else {
                            view! {
                                <ActionForm action=login_action>
                                    <label for="password">"Admin Password"</label>
                                    <input type="password" name="password" id="password" required autofocus autocomplete="current-password" />
                                    <button type="submit" class="btn btn-primary">"Login"</button>
                                </ActionForm>
                                <ErrorToast value=login_action.value() />
                            }.into_any()
                        }
                    }}
                </div>
                {use_nonce().map(|nonce| view! {
                    <script nonce={nonce.to_string()}>"
                        document.addEventListener('submit', function(e) {
                            var form = e.target;
                            if (form.tagName !== 'FORM') return;
                            var btns = form.querySelectorAll('button[type=submit]');
                            btns.forEach(function(btn) {
                                btn.disabled = true;
                                btn.style.opacity = '0.6';
                                btn.style.cursor = 'wait';
                            });
                        });
                    "</script>
                })}
            </body>
        </html>
    }
}
