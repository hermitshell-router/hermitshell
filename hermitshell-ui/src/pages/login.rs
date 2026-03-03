use leptos::prelude::*;
use crate::components::layout::CspMeta;
use crate::components::toast::ErrorToast;
use crate::server_fns::Login;

#[component]
pub fn Login() -> impl IntoView {
    let login_action = ServerAction::<Login>::new();

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
                    <ActionForm action=login_action>
                        <label for="password">"Admin Password"</label>
                        <input type="password" name="password" id="password" required autofocus />
                        <button type="submit" class="btn btn-primary">"Login"</button>
                    </ActionForm>
                    <ErrorToast value=login_action.value() />
                </div>
            </body>
        </html>
    }
}
