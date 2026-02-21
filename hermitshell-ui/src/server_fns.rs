use leptos::prelude::*;
use leptos::server;
use server_fn::ServerFnError;

#[server]
pub async fn setup_password(password: String, confirm: String) -> Result<(), ServerFnError> {
    if password != confirm || password.len() < 8 || password.len() > 128 {
        return Err(ServerFnError::new("Invalid password"));
    }
    crate::client::setup_password(&password, None)
        .map_err(|e| ServerFnError::new(e))?;
    leptos_axum::redirect("/login");
    Ok(())
}

#[server]
pub async fn login(password: String) -> Result<(), ServerFnError> {
    match crate::client::verify_password(&password) {
        Ok(true) => {}
        _ => return Err(ServerFnError::new("Invalid password")),
    }
    let cookie = crate::client::create_session()
        .map_err(|e| ServerFnError::new(e))?;
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
        .map_err(|e| ServerFnError::new(e))?;
    let _ = crate::client::log_audit("set_wireguard_enabled", &enabled.to_string());
    leptos_axum::redirect("/wireguard");
    Ok(())
}

#[server]
pub async fn toggle_ad_blocking(enabled: String) -> Result<(), ServerFnError> {
    let enabled = enabled == "true";
    crate::client::set_ad_blocking(enabled)
        .map_err(|e| ServerFnError::new(e))?;
    let _ = crate::client::log_audit("set_ad_blocking", &enabled.to_string());
    leptos_axum::redirect("/");
    Ok(())
}

#[server]
pub async fn set_group(mac: String, group: String, redirect: Option<String>) -> Result<(), ServerFnError> {
    crate::client::set_device_group(&mac, &group)
        .map_err(|e| ServerFnError::new(e))?;
    let _ = crate::client::log_audit("set_device_group", &format!("{}: {}", mac, group));
    let target = redirect
        .filter(|r| r.starts_with('/') && !r.starts_with("//"))
        .unwrap_or_else(|| "/devices".to_string());
    leptos_axum::redirect(&target);
    Ok(())
}

#[server]
pub async fn approve_device(mac: String, group: String) -> Result<(), ServerFnError> {
    crate::client::set_device_group(&mac, &group)
        .map_err(|e| ServerFnError::new(e))?;
    let _ = crate::client::log_audit("approve_device", &format!("{}: {}", mac, group));
    leptos_axum::redirect("/devices");
    Ok(())
}

#[server]
pub async fn block_device(mac: String) -> Result<(), ServerFnError> {
    crate::client::block_device(&mac)
        .map_err(|e| ServerFnError::new(e))?;
    let _ = crate::client::log_audit("block_device", &mac);
    leptos_axum::redirect("/devices");
    Ok(())
}

#[server]
pub async fn unblock_device(mac: String) -> Result<(), ServerFnError> {
    crate::client::unblock_device(&mac)
        .map_err(|e| ServerFnError::new(e))?;
    let _ = crate::client::log_audit("unblock_device", &mac);
    leptos_axum::redirect("/devices");
    Ok(())
}

#[server]
pub async fn set_nickname(mac: String, nickname: String) -> Result<(), ServerFnError> {
    crate::client::set_device_nickname(&mac, &nickname)
        .map_err(|e| ServerFnError::new(e))?;
    let _ = crate::client::log_audit("set_device_nickname", &format!("{}: {}", mac, nickname));
    leptos_axum::redirect(&format!("/devices/{}", mac));
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
    .map_err(|e| ServerFnError::new(e))?;
    let _ = crate::client::log_audit("add_port_forward", &format!("{}:{}-{}", internal_ip, external_port_start, external_port_end));
    leptos_axum::redirect("/port-forwarding");
    Ok(())
}

#[server]
pub async fn remove_port_forward(id: i64) -> Result<(), ServerFnError> {
    crate::client::remove_port_forward(id)
        .map_err(|e| ServerFnError::new(e))?;
    let _ = crate::client::log_audit("remove_port_forward", &id.to_string());
    leptos_axum::redirect("/port-forwarding");
    Ok(())
}

#[server]
pub async fn set_reservation(mac: String) -> Result<(), ServerFnError> {
    crate::client::set_dhcp_reservation(&mac, None)
        .map_err(|e| ServerFnError::new(e))?;
    leptos_axum::redirect("/settings");
    Ok(())
}

#[server]
pub async fn remove_reservation(mac: String) -> Result<(), ServerFnError> {
    crate::client::remove_dhcp_reservation(&mac)
        .map_err(|e| ServerFnError::new(e))?;
    leptos_axum::redirect("/settings");
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
        .map_err(|e| ServerFnError::new(e))?;
    let _ = crate::client::log_audit("set_log_config", "");
    leptos_axum::redirect("/settings");
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
        .map_err(|e| ServerFnError::new(e))?;
    let _ = crate::client::log_audit("set_runzero_config", "");
    leptos_axum::redirect("/settings");
    Ok(())
}

#[server]
pub async fn sync_runzero() -> Result<(), ServerFnError> {
    crate::client::sync_runzero()
        .map_err(|e| ServerFnError::new(e))?;
    leptos_axum::redirect("/settings");
    Ok(())
}

#[server]
pub async fn acknowledge_alert(id: i64) -> Result<(), ServerFnError> {
    crate::client::acknowledge_alert(id)
        .map_err(|e| ServerFnError::new(e))?;
    leptos_axum::redirect("/alerts");
    Ok(())
}

#[server]
pub async fn acknowledge_all_alerts() -> Result<(), ServerFnError> {
    crate::client::acknowledge_all_alerts(None)
        .map_err(|e| ServerFnError::new(e))?;
    leptos_axum::redirect("/alerts");
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
        .map_err(|e| ServerFnError::new(e))?;
    let _ = crate::client::log_audit("set_qos_config", &format!("enabled={}", enabled));
    leptos_axum::redirect("/settings");
    Ok(())
}

#[server]
pub async fn set_qos_test_url(url: String) -> Result<(), ServerFnError> {
    crate::client::set_qos_test_url(&url)
        .map_err(|e| ServerFnError::new(e))?;
    leptos_axum::redirect("/settings");
    Ok(())
}

#[server]
pub async fn run_speed_test() -> Result<(), ServerFnError> {
    crate::client::run_speed_test()
        .map_err(|e| ServerFnError::new(e))?;
    leptos_axum::redirect("/settings");
    Ok(())
}
