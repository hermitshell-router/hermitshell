use leptos::prelude::*;
use leptos::server;
use server_fn::ServerFnError;

/// Maps raw client errors to user-friendly messages.
fn friendly_error(e: impl std::fmt::Display) -> ServerFnError {
    let msg = e.to_string();
    if msg.contains("Connection refused") || msg.contains("No such file") {
        ServerFnError::new("Could not reach the router agent. Check that the service is running.")
    } else if msg.contains("timed out") || msg.contains("Timeout") {
        ServerFnError::new("The operation timed out. Please try again.")
    } else if msg.contains("Permission denied") {
        ServerFnError::new("Permission denied. You may need to log in again.")
    } else {
        ServerFnError::new(msg)
    }
}

#[server]
pub async fn setup_password(password: String, confirm: String) -> Result<(), ServerFnError> {
    if crate::client::has_password().unwrap_or(false) {
        leptos_axum::redirect("/login");
        return Ok(());
    }
    if password != confirm || password.len() < 8 || password.len() > 128 {
        return Err(ServerFnError::new("Invalid password"));
    }
    crate::client::setup_password(&password, None)
        .map_err(friendly_error)?;
    leptos_axum::redirect("/login");
    Ok(())
}

#[server]
pub async fn login(password: String) -> Result<(), ServerFnError> {
    match crate::client::verify_password(&password) {
        Ok(true) => {}
        _ => return Err(ServerFnError::new("Invalid password")),
    }
    // Check if 2FA is enabled
    if crate::client::totp_status().unwrap_or(false) {
        // Create a session but store it as totp_pending (5-min TTL)
        let cookie = crate::client::create_session()
            .map_err(friendly_error)?;
        let response = expect_context::<leptos_axum::ResponseOptions>();
        response.insert_header(
            axum::http::header::SET_COOKIE,
            axum::http::HeaderValue::from_str(
                &format!("totp_pending={}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=300", cookie)
            ).unwrap(),
        );
        leptos_axum::redirect("/login?step=totp");
        return Ok(());
    }
    let cookie = crate::client::create_session()
        .map_err(friendly_error)?;
    let response = expect_context::<leptos_axum::ResponseOptions>();
    response.insert_header(
        axum::http::header::SET_COOKIE,
        axum::http::HeaderValue::from_str(
            &format!("session={}; HttpOnly; Secure; SameSite=Strict; Path=/", cookie)
        ).unwrap(),
    );
    leptos_axum::redirect("/");
    Ok(())
}

#[server]
pub async fn login_totp(totp_code: String) -> Result<(), ServerFnError> {
    // Extract the totp_pending cookie from the request
    let headers = expect_context::<axum::http::HeaderMap>();
    let cookie_header = headers.get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let pending = cookie_header.split(';')
        .filter_map(|c| {
            let c = c.trim();
            c.strip_prefix("totp_pending=")
        })
        .next()
        .unwrap_or("");
    if pending.is_empty() {
        return Err(ServerFnError::new("Session expired, please log in again"));
    }
    // Verify the pending session is still valid
    match crate::client::verify_session(pending) {
        Ok(true) => {}
        _ => return Err(ServerFnError::new("Session expired, please log in again")),
    }
    // Verify the TOTP code
    match crate::client::totp_verify(&totp_code) {
        Ok(true) => {}
        _ => return Err(ServerFnError::new("Invalid code")),
    }
    // Promote: set the pending session as the real session cookie
    let response = expect_context::<leptos_axum::ResponseOptions>();
    response.insert_header(
        axum::http::header::SET_COOKIE,
        axum::http::HeaderValue::from_str(
            &format!("session={}; HttpOnly; Secure; SameSite=Strict; Path=/", pending)
        ).unwrap(),
    );
    // Clear the pending cookie
    response.append_header(
        axum::http::header::SET_COOKIE,
        axum::http::HeaderValue::from_str(
            "totp_pending=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
        ).unwrap(),
    );
    leptos_axum::redirect("/");
    Ok(())
}

#[server]
pub async fn logout() -> Result<(), ServerFnError> {
    let response = expect_context::<leptos_axum::ResponseOptions>();
    response.insert_header(
        axum::http::header::SET_COOKIE,
        axum::http::HeaderValue::from_str(
            "session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
        ).unwrap(),
    );
    leptos_axum::redirect("/login");
    Ok(())
}

#[server]
pub async fn toggle_wireguard(enabled: String) -> Result<(), ServerFnError> {
    let enabled = enabled == "true";
    crate::client::set_wireguard_enabled(enabled)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("set_wireguard_enabled", &enabled.to_string());
    leptos_axum::redirect("/wireguard?msg=WireGuard%20updated");
    Ok(())
}

#[server]
pub async fn toggle_ad_blocking(enabled: String) -> Result<(), ServerFnError> {
    let enabled = enabled == "true";
    crate::client::set_ad_blocking(enabled)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("set_ad_blocking", &enabled.to_string());
    leptos_axum::redirect("/?msg=Ad%20blocking%20updated");
    Ok(())
}

#[server]
pub async fn toggle_upnp(enabled: String) -> Result<(), ServerFnError> {
    let enabled = enabled == "true";
    crate::client::set_upnp_enabled(enabled)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("set_upnp_config", &enabled.to_string());
    leptos_axum::redirect("/settings?msg=UPnP%20updated#port-forwarding");
    Ok(())
}

#[server]
pub async fn set_group(mac: String, group: String, redirect: Option<String>) -> Result<(), ServerFnError> {
    crate::client::set_device_group(&mac, &group)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("set_device_group", &format!("{}: {}", mac, group));
    let target = redirect
        .filter(|r| r.starts_with('/') && !r.starts_with("//"))
        .unwrap_or_else(|| "/devices".to_string());
    leptos_axum::redirect(&format!("{}?msg=Device%20moved", target));
    Ok(())
}

#[server]
pub async fn approve_device(mac: String, group: String) -> Result<(), ServerFnError> {
    crate::client::set_device_group(&mac, &group)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("approve_device", &format!("{}: {}", mac, group));
    leptos_axum::redirect("/devices?msg=Device%20approved");
    Ok(())
}

#[server]
pub async fn block_device(mac: String) -> Result<(), ServerFnError> {
    crate::client::block_device(&mac)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("block_device", &mac);
    leptos_axum::redirect("/devices?msg=Device%20blocked");
    Ok(())
}

#[server]
pub async fn unblock_device(mac: String) -> Result<(), ServerFnError> {
    crate::client::unblock_device(&mac)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("unblock_device", &mac);
    leptos_axum::redirect("/devices?msg=Device%20unblocked");
    Ok(())
}

#[server]
pub async fn set_nickname(mac: String, nickname: String) -> Result<(), ServerFnError> {
    crate::client::set_device_nickname(&mac, &nickname)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("set_device_nickname", &format!("{}: {}", mac, nickname));
    leptos_axum::redirect(&format!("/devices/{}?msg=Nickname%20saved", mac));
    Ok(())
}

#[server]
pub async fn add_port_forward(
    protocol: String,
    external_port_start: u16,
    external_port_end: u16,
    internal_ip: String,
    internal_port: u16,
    description: String,
) -> Result<(), ServerFnError> {
    crate::client::add_port_forward(
        &protocol,
        external_port_start,
        external_port_end,
        &internal_ip,
        internal_port,
        &description,
    )
    .map_err(friendly_error)?;
    let _ = crate::client::log_audit("add_port_forward", &format!("{}:{}-{}", internal_ip, external_port_start, external_port_end));
    leptos_axum::redirect("/settings?msg=Port%20forward%20added#port-forwarding");
    Ok(())
}

#[server]
pub async fn remove_port_forward(id: i64) -> Result<(), ServerFnError> {
    crate::client::remove_port_forward(id)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("remove_port_forward", &id.to_string());
    leptos_axum::redirect("/settings?msg=Port%20forward%20removed#port-forwarding");
    Ok(())
}

#[server]
pub async fn set_reservation(mac: String) -> Result<(), ServerFnError> {
    crate::client::set_dhcp_reservation(&mac, None)
        .map_err(friendly_error)?;
    leptos_axum::redirect("/settings?msg=Reservation%20added");
    Ok(())
}

#[server]
pub async fn remove_reservation(mac: String) -> Result<(), ServerFnError> {
    crate::client::remove_dhcp_reservation(&mac)
        .map_err(friendly_error)?;
    leptos_axum::redirect("/settings?msg=Reservation%20removed");
    Ok(())
}

#[server]
pub async fn set_log_config(
    log_format: String,
    syslog_target: String,
    webhook_url: String,
    webhook_secret: String,
    log_retention_days: String,
) -> Result<(), ServerFnError> {
    let config = serde_json::json!({
        "log_format": log_format,
        "syslog_target": syslog_target,
        "webhook_url": webhook_url,
        "webhook_secret": webhook_secret,
        "log_retention_days": log_retention_days,
    });
    crate::client::set_log_config(&config)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("set_log_config", "");
    leptos_axum::redirect("/settings?msg=Settings%20saved");
    Ok(())
}

#[server]
pub async fn set_runzero_config(
    runzero_url: String,
    runzero_token: String,
    runzero_sync_interval: String,
    runzero_enabled: String,
) -> Result<(), ServerFnError> {
    let mut config = serde_json::json!({
        "runzero_url": runzero_url,
        "runzero_sync_interval": runzero_sync_interval,
        "runzero_enabled": runzero_enabled,
    });
    if !runzero_token.is_empty() {
        config["runzero_token"] = serde_json::Value::String(runzero_token);
    }
    crate::client::set_runzero_config(&config)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("set_runzero_config", "");
    leptos_axum::redirect("/settings?msg=Settings%20saved");
    Ok(())
}

#[server]
pub async fn sync_runzero() -> Result<(), ServerFnError> {
    crate::client::sync_runzero()
        .map_err(friendly_error)?;
    leptos_axum::redirect("/settings?msg=Sync%20started");
    Ok(())
}

#[server]
pub async fn acknowledge_alert(id: i64) -> Result<(), ServerFnError> {
    crate::client::acknowledge_alert(id)
        .map_err(friendly_error)?;
    leptos_axum::redirect("/alerts?msg=Alert%20acknowledged");
    Ok(())
}

#[server]
pub async fn acknowledge_all_alerts() -> Result<(), ServerFnError> {
    crate::client::acknowledge_all_alerts(None)
        .map_err(friendly_error)?;
    leptos_axum::redirect("/alerts?msg=All%20alerts%20acknowledged");
    Ok(())
}

#[server]
pub async fn set_qos_config(
    qos_enabled: String,
    upload_mbps: Option<String>,
    download_mbps: Option<String>,
) -> Result<(), ServerFnError> {
    let enabled = qos_enabled == "true";
    let upload: Option<u32> = upload_mbps.as_deref().and_then(|s| s.parse().ok());
    let download: Option<u32> = download_mbps.as_deref().and_then(|s| s.parse().ok());
    crate::client::set_qos_config(enabled, upload, download)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("set_qos_config", &format!("enabled={}", enabled));
    leptos_axum::redirect("/settings?msg=Settings%20saved");
    Ok(())
}

#[server]
pub async fn set_qos_test_url(url: String) -> Result<(), ServerFnError> {
    crate::client::set_qos_test_url(&url)
        .map_err(friendly_error)?;
    leptos_axum::redirect("/settings?msg=Settings%20saved");
    Ok(())
}

#[server]
pub async fn run_speed_test() -> Result<(), ServerFnError> {
    crate::client::run_speed_test()
        .map_err(friendly_error)?;
    leptos_axum::redirect("/settings?msg=Speed%20test%20started");
    Ok(())
}

#[server]
pub async fn set_tls_custom_cert(cert_pem: String, key_pem: String) -> Result<(), ServerFnError> {
    crate::client::set_tls_cert(&cert_pem, &key_pem)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("set_tls_cert", "custom cert uploaded");
    leptos_axum::redirect("/settings?msg=TLS%20settings%20saved");
    Ok(())
}

#[server]
pub async fn set_tls_self_signed() -> Result<(), ServerFnError> {
    crate::client::set_tls_mode("self_signed", None)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("set_tls_mode", "self_signed");
    leptos_axum::redirect("/settings?msg=TLS%20settings%20saved");
    Ok(())
}

#[server]
pub async fn set_tls_tailscale(domain: String) -> Result<(), ServerFnError> {
    crate::client::set_tls_mode("tailscale", Some(&domain))
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("set_tls_mode", &format!("tailscale: {}", domain));
    leptos_axum::redirect("/settings?msg=TLS%20settings%20saved");
    Ok(())
}

#[server]
pub async fn set_tls_acme(
    domain: String,
    email: String,
    cf_api_token: String,
    cf_zone_id: String,
) -> Result<(), ServerFnError> {
    crate::client::set_acme_config(&domain, &email, &cf_api_token, &cf_zone_id)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("set_acme_config", &domain);
    leptos_axum::redirect("/settings?msg=TLS%20settings%20saved");
    Ok(())
}

#[server]
pub async fn add_wifi_provider(
    provider_type: String,
    name: String,
    url: String,
    username: String,
    password: String,
    mac: Option<String>,
    site: Option<String>,
    api_key: Option<String>,
) -> Result<(), ServerFnError> {
    crate::client::wifi_add_provider(
        &provider_type,
        &name,
        &url,
        &username,
        &password,
        mac.as_deref(),
        site.as_deref(),
        api_key.as_deref(),
    )
    .map_err(friendly_error)?;
    let _ = crate::client::log_audit("wifi_add_provider", &format!("{}: {}", name, provider_type));
    leptos_axum::redirect("/wifi?msg=Provider%20added");
    Ok(())
}

#[server]
pub async fn remove_wifi_provider(id: String) -> Result<(), ServerFnError> {
    crate::client::wifi_remove_provider(&id)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("wifi_remove_provider", &id);
    leptos_axum::redirect("/wifi?msg=Provider%20removed");
    Ok(())
}

#[server]
pub async fn set_wifi_ssid(
    provider_id: String,
    ssid_name: String,
    password: Option<String>,
    band: String,
    security: String,
    hidden: Option<String>,
) -> Result<(), ServerFnError> {
    let hidden = hidden.as_deref() == Some("on");
    crate::client::wifi_set_ssid(&provider_id, &ssid_name, password.as_deref(), &band, &security, hidden)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("wifi_set_ssid", &format!("{}: {} on {}", provider_id, ssid_name, band));
    leptos_axum::redirect(&format!("/wifi?provider={}&msg=SSID%20saved", provider_id));
    Ok(())
}

#[server]
pub async fn delete_wifi_ssid(provider_id: String, ssid_name: String, band: String) -> Result<(), ServerFnError> {
    crate::client::wifi_delete_ssid(&provider_id, &ssid_name, &band)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("wifi_delete_ssid", &format!("{}: {} on {}", provider_id, ssid_name, band));
    leptos_axum::redirect(&format!("/wifi?provider={}&msg=SSID%20deleted", provider_id));
    Ok(())
}

#[server]
pub async fn set_wifi_radio(
    mac: String,
    band: String,
    channel: String,
    channel_width: String,
    tx_power: String,
    enabled: Option<String>,
) -> Result<(), ServerFnError> {
    let enabled = enabled.as_deref() == Some("on");
    crate::client::wifi_set_radio(&mac, &band, &channel, &channel_width, &tx_power, enabled)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("wifi_set_radio", &format!("{}: {}", mac, band));
    leptos_axum::redirect(&format!("/wifi?ap={}&msg=Radio%20settings%20saved", mac));
    Ok(())
}

#[server]
pub async fn wifi_kick_client(provider_id: String, mac: String) -> Result<(), ServerFnError> {
    crate::client::wifi_kick_client(&provider_id, &mac).map_err(friendly_error)?;
    let _ = crate::client::log_audit("wifi_kick_client", &mac);
    leptos_axum::redirect("/wifi?msg=Client%20disconnected");
    Ok(())
}

#[server]
pub async fn wifi_block_client(provider_id: String, mac: String) -> Result<(), ServerFnError> {
    crate::client::wifi_block_client(&provider_id, &mac).map_err(friendly_error)?;
    let _ = crate::client::log_audit("wifi_block_client", &mac);
    leptos_axum::redirect("/wifi?msg=Client%20blocked");
    Ok(())
}

#[server]
pub async fn wifi_unblock_client(provider_id: String, mac: String) -> Result<(), ServerFnError> {
    crate::client::wifi_unblock_client(&provider_id, &mac).map_err(friendly_error)?;
    let _ = crate::client::log_audit("wifi_unblock_client", &mac);
    leptos_axum::redirect("/wifi?msg=Client%20unblocked");
    Ok(())
}

#[server]
pub async fn setup_interfaces(wan: String, lan: String) -> Result<(), ServerFnError> {
    crate::client::set_interfaces(&wan, &lan)
        .map_err(friendly_error)?;
    leptos_axum::redirect("/setup/3");
    Ok(())
}

#[server]
pub async fn get_interfaces() -> Result<Vec<hermitshell_common::NetworkInterface>, ServerFnError> {
    crate::client::list_interfaces()
        .map_err(friendly_error)
}

#[server]
pub async fn apply_update() -> Result<String, ServerFnError> {
    let version = crate::client::apply_update()
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("apply_update", &version);
    Ok(version)
}

#[server]
pub async fn set_auto_update(enabled: String) -> Result<(), ServerFnError> {
    let enabled = enabled == "true";
    crate::client::set_auto_update(enabled)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("set_auto_update", &enabled.to_string());
    leptos_axum::redirect("/settings?msg=Settings%20saved");
    Ok(())
}

#[server]
pub async fn setup_wan_config(
    wan_mode: String,
    static_ip: Option<String>,
    gateway: Option<String>,
    dns: Option<String>,
) -> Result<(), ServerFnError> {
    let mode = if wan_mode == "static" { "static" } else { "dhcp" };
    crate::client::setup_wan_config(
        mode,
        static_ip.as_deref().filter(|s| !s.is_empty()),
        gateway.as_deref().filter(|s| !s.is_empty()),
        dns.as_deref().filter(|s| !s.is_empty()),
    )
    .map_err(friendly_error)?;
    leptos_axum::redirect("/setup/4");
    Ok(())
}

#[server]
pub async fn setup_hostname_tz(hostname: String, timezone: String) -> Result<(), ServerFnError> {
    if !hostname.is_empty() {
        crate::client::set_router_hostname(&hostname)
            .map_err(friendly_error)?;
    }
    if !timezone.is_empty() {
        crate::client::set_timezone(&timezone)
            .map_err(friendly_error)?;
    }
    leptos_axum::redirect("/setup/5");
    Ok(())
}

#[server]
pub async fn setup_dns(upstream_dns: String, ad_blocking: Option<String>) -> Result<(), ServerFnError> {
    let ad_blocking_on = ad_blocking.as_deref() == Some("on");
    let dns = match upstream_dns.as_str() {
        "cloudflare" => "1.1.1.1,1.0.0.1",
        "google" => "8.8.8.8,8.8.4.4",
        "quad9" => "9.9.9.9,149.112.112.112",
        _ => "auto",
    };
    crate::client::setup_set_dns(dns, ad_blocking_on)
        .map_err(friendly_error)?;
    leptos_axum::redirect("/setup/6");
    Ok(())
}

#[server]
pub async fn setup_password_step(password: String, confirm: String) -> Result<(), ServerFnError> {
    if crate::client::has_password().unwrap_or(false) {
        leptos_axum::redirect("/setup/7");
        return Ok(());
    }
    if password != confirm || password.len() < 8 || password.len() > 128 {
        return Err(ServerFnError::new("Passwords must match and be 8-128 characters"));
    }
    crate::client::setup_password(&password, None)
        .map_err(friendly_error)?;
    // Create session so steps 7-8 work (user is now authenticated)
    let cookie = crate::client::create_session()
        .map_err(friendly_error)?;
    let response = expect_context::<leptos_axum::ResponseOptions>();
    response.insert_header(
        axum::http::header::SET_COOKIE,
        axum::http::HeaderValue::from_str(
            &format!("session={}; HttpOnly; Secure; SameSite=Strict; Path=/", cookie)
        ).unwrap(),
    );
    leptos_axum::redirect("/setup/7");
    Ok(())
}

#[server]
pub async fn setup_wifi_provider(
    provider_type: String,
    name: String,
    url: String,
    username: String,
    password: String,
    site: Option<String>,
    api_key: Option<String>,
) -> Result<(), ServerFnError> {
    crate::client::wifi_add_provider(
        &provider_type,
        &name,
        &url,
        &username,
        &password,
        None,
        site.as_deref().filter(|s| !s.is_empty()),
        api_key.as_deref().filter(|s| !s.is_empty()),
    )
    .map_err(friendly_error)?;
    let _ = crate::client::log_audit("wifi_add_provider", &format!("{}: {}", name, provider_type));
    leptos_axum::redirect("/setup/8");
    Ok(())
}

#[server]
pub async fn setup_finalize() -> Result<(), ServerFnError> {
    crate::client::finalize_setup()
        .map_err(friendly_error)?;
    leptos_axum::redirect("/");
    Ok(())
}

// --- Post-wizard settings ---

#[server]
pub async fn change_password(
    current_password: String,
    new_password: String,
    confirm_password: String,
) -> Result<(), ServerFnError> {
    if new_password != confirm_password {
        return Err(ServerFnError::new("Passwords do not match"));
    }
    if new_password.len() < 8 || new_password.len() > 128 {
        return Err(ServerFnError::new("Password must be 8-128 characters"));
    }
    crate::client::setup_password(&new_password, Some(&current_password))
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("change_password", "");
    leptos_axum::redirect("/settings?msg=Password%20changed#security");
    Ok(())
}

#[server]
pub async fn update_hostname(hostname: String) -> Result<(), ServerFnError> {
    crate::client::update_hostname(&hostname)
        .map_err(friendly_error)?;
    leptos_axum::redirect("/settings?msg=Settings%20saved");
    Ok(())
}

#[server]
pub async fn update_timezone(timezone: String) -> Result<(), ServerFnError> {
    crate::client::update_timezone(&timezone)
        .map_err(friendly_error)?;
    leptos_axum::redirect("/settings?msg=Settings%20saved");
    Ok(())
}

#[server]
pub async fn update_upstream_dns(upstream_dns: String, custom_dns: Option<String>) -> Result<(), ServerFnError> {
    let dns = match upstream_dns.as_str() {
        "cloudflare" => "1.1.1.1,1.0.0.1".to_string(),
        "google" => "8.8.8.8,8.8.4.4".to_string(),
        "quad9" => "9.9.9.9,149.112.112.112".to_string(),
        "custom" => custom_dns.filter(|s| !s.is_empty()).unwrap_or_else(|| "auto".to_string()),
        _ => "auto".to_string(),
    };
    crate::client::update_upstream_dns(&dns)
        .map_err(friendly_error)?;
    leptos_axum::redirect("/settings?msg=Settings%20saved");
    Ok(())
}

#[server]
pub async fn update_wan_config(
    wan_mode: String,
    static_ip: Option<String>,
    gateway: Option<String>,
    dns: Option<String>,
) -> Result<(), ServerFnError> {
    let mode = if wan_mode == "static" { "static" } else { "dhcp" };
    crate::client::update_wan_config(
        mode,
        static_ip.as_deref().filter(|s| !s.is_empty()),
        gateway.as_deref().filter(|s| !s.is_empty()),
        dns.as_deref().filter(|s| !s.is_empty()),
    )
    .map_err(friendly_error)?;
    let _ = crate::client::log_audit("update_wan_config", mode);
    leptos_axum::redirect("/settings?msg=Settings%20saved");
    Ok(())
}

#[server]
pub async fn update_interfaces(wan: String, lan: String) -> Result<(), ServerFnError> {
    crate::client::update_interfaces(&wan, &lan)
        .map_err(friendly_error)?;
    leptos_axum::redirect("/settings?msg=Settings%20saved");
    Ok(())
}

// --- DNS CRUD ---

#[server]
pub async fn add_dns_blocklist(name: String, url: String, tag: String) -> Result<(), ServerFnError> {
    crate::client::add_dns_blocklist(&name, &url, &tag)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("add_dns_blocklist", &name);
    leptos_axum::redirect("/dns?msg=Blocklist%20added");
    Ok(())
}

#[server]
pub async fn remove_dns_blocklist(id: i64) -> Result<(), ServerFnError> {
    crate::client::remove_dns_blocklist(id)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("remove_dns_blocklist", &id.to_string());
    leptos_axum::redirect("/dns?msg=Blocklist%20removed");
    Ok(())
}

#[server]
pub async fn add_dns_forward_zone(domain: String, forward_addr: String) -> Result<(), ServerFnError> {
    crate::client::add_dns_forward(&domain, &forward_addr)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("add_dns_forward", &domain);
    leptos_axum::redirect("/dns?msg=Forward%20zone%20added");
    Ok(())
}

#[server]
pub async fn remove_dns_forward_zone(id: i64) -> Result<(), ServerFnError> {
    crate::client::remove_dns_forward(id)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("remove_dns_forward", &id.to_string());
    leptos_axum::redirect("/dns?msg=Forward%20zone%20removed");
    Ok(())
}

#[server]
pub async fn add_dns_custom_rule(domain: String, record_type: String, value: String) -> Result<(), ServerFnError> {
    crate::client::add_dns_rule(&domain, &record_type, &value)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("add_dns_rule", &domain);
    leptos_axum::redirect("/dns?msg=Rule%20added");
    Ok(())
}

#[server]
pub async fn remove_dns_custom_rule(id: i64) -> Result<(), ServerFnError> {
    crate::client::remove_dns_rule(id)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("remove_dns_rule", &id.to_string());
    leptos_axum::redirect("/dns?msg=Rule%20removed");
    Ok(())
}

#[server]
pub async fn set_dns_settings(
    ratelimit_per_client: String,
    ratelimit_per_domain: String,
) -> Result<(), ServerFnError> {
    let config = serde_json::json!({
        "ratelimit_per_client": ratelimit_per_client,
        "ratelimit_per_domain": ratelimit_per_domain,
    });
    crate::client::set_dns_config(&config)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("set_dns_config", "");
    leptos_axum::redirect("/dns?msg=DNS%20settings%20saved");
    Ok(())
}

#[server]
pub async fn set_dns_forward_enabled(id: i64, enabled: String) -> Result<(), ServerFnError> {
    let enabled = enabled == "true";
    crate::client::set_dns_forward_enabled(id, enabled).map_err(friendly_error)?;
    let _ = crate::client::log_audit("set_dns_forward_enabled", &format!("id={} enabled={}", id, enabled));
    leptos_axum::redirect("/dns?msg=Forward%20zone%20updated");
    Ok(())
}

#[server]
pub async fn set_dns_rule_enabled(id: i64, enabled: String) -> Result<(), ServerFnError> {
    let enabled = enabled == "true";
    crate::client::set_dns_rule_enabled(id, enabled).map_err(friendly_error)?;
    let _ = crate::client::log_audit("set_dns_rule_enabled", &format!("id={} enabled={}", id, enabled));
    leptos_axum::redirect("/dns?msg=Rule%20updated");
    Ok(())
}

#[server]
pub async fn set_dns_blocklist_enabled(id: i64, enabled: String) -> Result<(), ServerFnError> {
    let enabled = enabled == "true";
    crate::client::set_dns_blocklist_enabled(id, enabled).map_err(friendly_error)?;
    let _ = crate::client::log_audit("set_dns_blocklist_enabled", &format!("id={} enabled={}", id, enabled));
    leptos_axum::redirect("/dns?msg=Blocklist%20updated");
    Ok(())
}

// --- Port forwarding ---

#[server]
pub async fn toggle_port_forward(id: i64, enabled: String) -> Result<(), ServerFnError> {
    let enabled = enabled == "true";
    crate::client::set_port_forward_enabled(id, enabled)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("set_port_forward_enabled", &format!("{}={}", id, enabled));
    leptos_axum::redirect("/settings?msg=Port%20forward%20updated#port-forwarding");
    Ok(())
}

#[server]
pub async fn add_ipv6_pinhole(
    device_mac: String,
    protocol: String,
    port_start: u16,
    port_end: u16,
    description: String,
) -> Result<(), ServerFnError> {
    crate::client::add_ipv6_pinhole(&device_mac, &protocol, port_start, port_end, &description)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("add_ipv6_pinhole", &format!("{}: {}/{}-{}", device_mac, protocol, port_start, port_end));
    leptos_axum::redirect("/settings?msg=Pinhole%20added#port-forwarding");
    Ok(())
}

#[server]
pub async fn remove_ipv6_pinhole(id: i64) -> Result<(), ServerFnError> {
    crate::client::remove_ipv6_pinhole(id)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("remove_ipv6_pinhole", &id.to_string());
    leptos_axum::redirect("/settings?msg=Pinhole%20removed#port-forwarding");
    Ok(())
}

// --- WireGuard peer management ---

#[server]
pub async fn add_wg_peer(name: String, public_key: String, group: String) -> Result<(), ServerFnError> {
    crate::client::add_wg_peer(&name, &public_key, &group)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("add_wg_peer", &name);
    leptos_axum::redirect("/wireguard?msg=Peer%20added");
    Ok(())
}

#[server]
pub async fn remove_wg_peer(public_key: String) -> Result<(), ServerFnError> {
    crate::client::remove_wg_peer(&public_key)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("remove_wg_peer", &public_key);
    leptos_axum::redirect("/wireguard?msg=Peer%20removed");
    Ok(())
}

#[server]
pub async fn set_wg_peer_group(public_key: String, group: String) -> Result<(), ServerFnError> {
    crate::client::set_wg_peer_group(&public_key, &group)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("set_wg_peer_group", &format!("{}: {}", public_key, group));
    leptos_axum::redirect("/wireguard?msg=Peer%20moved");
    Ok(())
}

// --- VLAN ---

#[server]
pub async fn enable_vlan() -> Result<(), ServerFnError> {
    crate::client::vlan_enable().map_err(friendly_error)?;
    let _ = crate::client::log_audit("vlan_enable", "");
    leptos_axum::redirect("/settings?msg=VLANs%20enabled#vlans");
    Ok(())
}

#[server]
pub async fn disable_vlan() -> Result<(), ServerFnError> {
    crate::client::vlan_disable().map_err(friendly_error)?;
    let _ = crate::client::log_audit("vlan_disable", "");
    leptos_axum::redirect("/settings?msg=VLANs%20disabled#vlans");
    Ok(())
}

#[server]
pub async fn update_vlan_id(group: String, vlan_id: u16) -> Result<(), ServerFnError> {
    crate::client::vlan_update_config(&group, vlan_id)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("vlan_update_config", &format!("{}: {}", group, vlan_id));
    leptos_axum::redirect("/settings?msg=VLAN%20ID%20updated#vlans");
    Ok(())
}

// --- Behavioral analysis toggles ---

#[server]
pub async fn set_analyzer_enabled(enabled: String) -> Result<(), ServerFnError> {
    let val = if enabled == "true" { "true" } else { "false" };
    crate::client::set_config("analyzer_enabled", val)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("set_analyzer_enabled", val);
    leptos_axum::redirect("/settings?msg=Settings%20saved");
    Ok(())
}

#[server]
pub async fn set_alert_rule(rule: String, enabled: String) -> Result<(), ServerFnError> {
    let valid_rules = ["dns_beaconing", "dns_volume_spike", "new_dest_spike", "suspicious_ports", "bandwidth_spike"];
    if !valid_rules.contains(&rule.as_str()) {
        return Err(ServerFnError::new("Invalid rule name"));
    }
    let val = if enabled == "true" { "enabled" } else { "disabled" };
    let key = format!("alert_rule_{}", rule);
    crate::client::set_config(&key, val)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("set_alert_rule", &format!("{}={}", rule, val));
    leptos_axum::redirect("/settings");
    Ok(())
}

#[server]
pub async fn add_switch(
    name: String,
    host: String,
    community: Option<String>,
    snmp_version: Option<String>,
    v3_username: Option<String>,
    v3_auth_protocol: Option<String>,
    v3_cipher: Option<String>,
    v3_auth_pass: Option<String>,
    v3_priv_pass: Option<String>,
) -> Result<(), ServerFnError> {
    if snmp_version.as_deref() == Some("3") {
        let username = v3_username.ok_or_else(|| ServerFnError::new("username required for v3"))?;
        let auth_pass = v3_auth_pass.ok_or_else(|| ServerFnError::new("auth password required for v3"))?;
        let priv_pass = v3_priv_pass.ok_or_else(|| ServerFnError::new("privacy password required for v3"))?;
        let auth_proto = v3_auth_protocol.unwrap_or_else(|| "sha256".to_string());
        let cipher = v3_cipher.unwrap_or_else(|| "aes128".to_string());
        crate::client::add_switch_v3(&name, &host, &username, &auth_proto, &cipher, &auth_pass, &priv_pass)
            .map_err(friendly_error)?;
    } else {
        let community = community.ok_or_else(|| ServerFnError::new("community string required for v2c"))?;
        crate::client::add_switch(&name, &host, &community)
            .map_err(friendly_error)?;
    }
    let _ = crate::client::log_audit("switch_add", &name);
    leptos_axum::redirect("/settings#switches");
    Ok(())
}

#[server]
pub async fn remove_switch(name: String) -> Result<(), ServerFnError> {
    crate::client::remove_switch(&name).map_err(friendly_error)?;
    let _ = crate::client::log_audit("switch_remove", &name);
    leptos_axum::redirect("/settings#switches");
    Ok(())
}

#[server]
pub async fn test_switch(name: String) -> Result<(), ServerFnError> {
    crate::client::test_switch(&name).map_err(friendly_error)?;
    leptos_axum::redirect("/settings#switches");
    Ok(())
}

// --- Guest Network ---

#[server]
pub async fn enable_guest_network(
    provider_id: String,
    ssid_name: String,
    password: String,
    band: String,
) -> Result<(), ServerFnError> {
    crate::client::guest_network_enable(&provider_id, &ssid_name, &password, &band)
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("guest_network_enable", &ssid_name);
    leptos_axum::redirect("/guest");
    Ok(())
}

#[server]
pub async fn disable_guest_network() -> Result<(), ServerFnError> {
    crate::client::guest_network_disable()
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("guest_network_disable", "");
    leptos_axum::redirect("/guest");
    Ok(())
}

#[server]
pub async fn regenerate_guest_password() -> Result<(), ServerFnError> {
    crate::client::guest_network_regenerate_password()
        .map_err(friendly_error)?;
    let _ = crate::client::log_audit("guest_network_regenerate_password", "");
    leptos_axum::redirect("/guest");
    Ok(())
}

#[server]
pub async fn guest_qr_svg() -> Result<String, ServerFnError> {
    let status = crate::client::guest_network_status()
        .map_err(friendly_error)?;
    let ssid = status["ssid_name"].as_str().unwrap_or("");
    let password = status["password"].as_str().unwrap_or("");
    if ssid.is_empty() {
        return Err(ServerFnError::new("guest network not configured"));
    }
    // Escape special chars per WiFi QR code spec (ZXing)
    fn escape_wifi(s: &str) -> String {
        s.replace('\\', "\\\\")
         .replace(';', "\\;")
         .replace(',', "\\,")
         .replace('"', "\\\"")
         .replace(':', "\\:")
    }
    let wifi_string = format!("WIFI:T:WPA;S:{};P:{};;", escape_wifi(ssid), escape_wifi(password));
    use qrcode::QrCode;
    let code = QrCode::new(wifi_string.as_bytes())
        .map_err(|e| ServerFnError::new(format!("QR generation failed: {}", e)))?;
    let svg = code.render::<qrcode::render::svg::Color>()
        .min_dimensions(200, 200)
        .build();
    Ok(svg)
}

#[server]
pub async fn totp_setup() -> Result<String, ServerFnError> {
    let (secret, uri) = crate::client::totp_setup()
        .map_err(friendly_error)?;
    Ok(serde_json::json!({"secret": secret, "uri": uri}).to_string())
}

#[server]
pub async fn totp_enable(code: String) -> Result<(), ServerFnError> {
    crate::client::totp_enable(&code)
        .map_err(friendly_error)?;
    leptos_axum::redirect("/settings#security");
    Ok(())
}

#[server]
pub async fn totp_disable(password: String) -> Result<(), ServerFnError> {
    crate::client::totp_disable(&password)
        .map_err(friendly_error)?;
    leptos_axum::redirect("/settings#security");
    Ok(())
}

#[server]
pub async fn dismiss_totp_nudge() -> Result<(), ServerFnError> {
    crate::client::set_config("totp_nudge_dismissed", "true")
        .map_err(friendly_error)?;
    leptos_axum::redirect("/");
    Ok(())
}
