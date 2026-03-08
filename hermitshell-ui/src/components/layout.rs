use leptos::prelude::*;
use leptos::nonce::use_nonce;
use crate::components::toast::SuccessToast;
use crate::server_fns::Logout;

/// Renders a CSP `<meta>` tag with the per-request nonce for inline scripts.
#[component]
pub fn CspMeta() -> impl IntoView {
    let csp = use_nonce().map(|nonce| {
        format!(
            "default-src 'self'; script-src 'nonce-{nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'"
        )
    });
    view! {
        {csp.map(|c| view! { <meta http-equiv="Content-Security-Policy" content=c /> })}
    }
}

#[component]
pub fn Layout(
    #[prop(into)] title: String,
    #[prop(into)] active_page: String,
    children: Children,
) -> impl IntoView {
    let logout_action = ServerAction::<Logout>::new();

    let nav_items: Vec<(Option<&str>, &str, &str)> = vec![
        (None, "Dashboard", "/"),
        (None, "Devices", "/devices"),
        (Some("Network"), "WiFi", "/wifi"),
        (None, "Guest Network", "/guest"),
        (None, "WireGuard", "/wireguard"),
        (None, "DNS", "/dns"),
        (Some("Monitoring"), "Traffic", "/traffic"),
        (None, "Alerts", "/alerts"),
        (None, "Logs", "/logs"),
        (Some(""), "Settings", "/settings"),
    ];

    view! {
        <html lang="en">
            <head>
                <meta charset="utf-8" />
                <CspMeta />
                <meta name="viewport" content="width=device-width, initial-scale=1" />
                <title>{format!("{} - HermitShell", &title)}</title>
                <link rel="stylesheet" href="/style.css" />
            </head>
            <body>
                <div class="app-shell">
                    <input type="checkbox" id="nav-toggle" class="nav-toggle" />
                    <label for="nav-toggle" class="nav-hamburger" aria-label="Toggle navigation menu">{"\u{2630}"}</label>
                    <label for="nav-toggle" class="nav-overlay"></label>
                    <nav class="sidebar">
                        <div class="sidebar-brand">
                            <h1>"HermitShell"</h1>
                            <p>"Router Dashboard"</p>
                        </div>
                        <ul class="sidebar-nav">
                            {nav_items.into_iter().map(|(group, name, href)| {
                                let is_active = name.to_lowercase().replace(' ', "-") == active_page
                                    || (name == "Dashboard" && active_page == "dashboard");
                                let class = if is_active { "active" } else { "" };
                                let aria_current = if is_active { Some("page") } else { None };
                                if let Some(label) = group {
                                    if label.is_empty() {
                                        view! {
                                            <li class="nav-spacer"></li>
                                            <li><a href={href} class={class} aria-current={aria_current}>{name}</a></li>
                                        }.into_any()
                                    } else {
                                        view! {
                                            <li class="nav-group-label">{label}</li>
                                            <li><a href={href} class={class} aria-current={aria_current}>{name}</a></li>
                                        }.into_any()
                                    }
                                } else {
                                    view! {
                                        <li><a href={href} class={class} aria-current={aria_current}>{name}</a></li>
                                    }.into_any()
                                }
                            }).collect_view()}
                        </ul>
                        <div class="sidebar-footer">
                            <ActionForm action=logout_action>
                                <button type="submit" class="btn btn-sm btn-logout">"Logout"</button>
                            </ActionForm>
                        </div>
                    </nav>
                    <main class="main-content">
                        <h1 class="page-title">{title}</h1>
                        {children()}
                    </main>
                </div>
                <SuccessToast />
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
