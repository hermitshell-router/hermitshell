use leptos::prelude::*;

#[component]
pub fn Layout(
    #[prop(into)] title: String,
    #[prop(into)] active_page: String,
    children: Children,
) -> impl IntoView {
    let pages = vec![
        ("Dashboard", "/"),
        ("Devices", "/devices"),
        ("Groups", "/groups"),
        ("Traffic", "/traffic"),
        ("DNS", "/dns"),
        ("Alerts", "/alerts"),
        ("WireGuard", "/wireguard"),
        ("Port Forwarding", "/port-forwarding"),
        ("Settings", "/settings"),
    ];

    view! {
        <html lang="en">
            <head>
                <meta charset="utf-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1" />
                <title>{format!("{} - HermitShell", &title)}</title>
                <link rel="stylesheet" href="/style.css" />
            </head>
            <body>
                <div class="app-shell">
                    <nav class="sidebar">
                        <div class="sidebar-brand">
                            <h1>"HermitShell"</h1>
                            <p>"Router Dashboard"</p>
                        </div>
                        <ul class="sidebar-nav">
                            {pages.into_iter().map(|(name, href)| {
                                let class = if name.to_lowercase() == active_page { "active" } else { "" };
                                view! {
                                    <li><a href={href} class={class}>{name}</a></li>
                                }
                            }).collect_view()}
                        </ul>
                    </nav>
                    <main class="main-content">
                        <h1 class="page-title">{title}</h1>
                        {children()}
                    </main>
                </div>
            </body>
        </html>
    }
}
