use leptos::prelude::*;
use crate::client;
use crate::components::toast::ErrorToast;
use crate::server_fns::{SetupPassword, SetupInterfaces};

#[component]
pub fn Setup() -> impl IntoView {
    let interfaces = Resource::new(
        || (),
        |_| async { client::list_interfaces() },
    );
    let setup_iface_action = ServerAction::<SetupInterfaces>::new();
    let setup_pw_action = ServerAction::<SetupPassword>::new();

    view! {
        <html lang="en">
            <head>
                <meta charset="utf-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1" />
                <title>"Setup - HermitShell"</title>
                <link rel="stylesheet" href="/style.css" />
            </head>
            <body>
                <div class="login-container">
                    <h1>"HermitShell Setup"</h1>
                    <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                        {move || {
                            interfaces.get().map(|result| {
                                match result {
                                    Ok(ifaces) if !ifaces.is_empty() => {
                                        view! {
                                            <div>
                                                <p>"Step 1: Select network interfaces"</p>
                                                <ActionForm action=setup_iface_action>
                                                    <label for="wan">"WAN (Internet)"</label>
                                                    <select name="wan" id="wan" required>
                                                        <option value="">"-- Select --"</option>
                                                        {ifaces.iter().map(|iface| {
                                                            let name = iface.name.clone();
                                                            let label = format!("{} ({})", iface.name, iface.mac);
                                                            view! { <option value={name}>{label}</option> }
                                                        }).collect_view()}
                                                    </select>
                                                    <label for="lan">"LAN (Local)"</label>
                                                    <select name="lan" id="lan" required>
                                                        <option value="">"-- Select --"</option>
                                                        {ifaces.iter().map(|iface| {
                                                            let name = iface.name.clone();
                                                            let label = format!("{} ({})", iface.name, iface.mac);
                                                            view! { <option value={name}>{label}</option> }
                                                        }).collect_view()}
                                                    </select>
                                                    <button type="submit" class="btn btn-primary">"Save Interfaces"</button>
                                                </ActionForm>
                                                <ErrorToast value=setup_iface_action.value() />
                                                <hr />
                                                <p>"Step 2: Set admin password"</p>
                                                <ActionForm action=setup_pw_action>
                                                    <label for="password">"Password"</label>
                                                    <input type="password" name="password" id="password" required minlength="8" />
                                                    <label for="confirm">"Confirm Password"</label>
                                                    <input type="password" name="confirm" id="confirm" required minlength="8" />
                                                    <button type="submit" class="btn btn-primary">"Set Password"</button>
                                                </ActionForm>
                                                <ErrorToast value=setup_pw_action.value() />
                                            </div>
                                        }.into_any()
                                    }
                                    _ => {
                                        view! {
                                            <div>
                                                <p>"Set an admin password to secure your router."</p>
                                                <ActionForm action=setup_pw_action>
                                                    <label for="password">"Password"</label>
                                                    <input type="password" name="password" id="password" required autofocus minlength="8" />
                                                    <label for="confirm">"Confirm Password"</label>
                                                    <input type="password" name="confirm" id="confirm" required minlength="8" />
                                                    <button type="submit" class="btn btn-primary">"Set Password"</button>
                                                </ActionForm>
                                                <ErrorToast value=setup_pw_action.value() />
                                            </div>
                                        }.into_any()
                                    }
                                }
                            })
                        }}
                    </Suspense>
                </div>
            </body>
        </html>
    }
}
