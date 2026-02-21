use leptos::prelude::*;

#[component]
pub fn Setup() -> impl IntoView {
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
                    <p>"Set an admin password to secure your router."</p>
                    <form method="post" action="/api/setup">
                        <label for="password">"Password"</label>
                        <input type="password" name="password" id="password" required autofocus minlength="8" />
                        <label for="confirm">"Confirm Password"</label>
                        <input type="password" name="confirm" id="confirm" required minlength="8" />
                        <button type="submit" class="btn btn-primary">"Set Password"</button>
                    </form>
                </div>
            </body>
        </html>
    }
}
