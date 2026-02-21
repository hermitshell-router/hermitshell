use leptos::prelude::*;

#[component]
pub fn Login() -> impl IntoView {
    view! {
        <html lang="en">
            <head>
                <meta charset="utf-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1" />
                <title>"Login - HermitShell"</title>
                <link rel="stylesheet" href="/style.css" />
            </head>
            <body>
                <div class="login-container">
                    <h1>"HermitShell"</h1>
                    <form method="post" action="/api/login">
                        <label for="password">"Admin Password"</label>
                        <input type="password" name="password" id="password" required autofocus />
                        <button type="submit" class="btn btn-primary">"Login"</button>
                    </form>
                </div>
            </body>
        </html>
    }
}
