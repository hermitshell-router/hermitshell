use anyhow::Result;
use serde::Deserialize;
use std::sync::{Arc, Mutex};
use tokio::time::{Duration, interval};
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::db::Db;

#[derive(Debug, Deserialize)]
struct RunZeroAsset {
    macs: Option<Vec<String>>,
    os: Option<String>,
    os_product: Option<String>,
    os_version: Option<String>,
    hw: Option<String>,
    hw_vendor: Option<String>,
    #[serde(rename = "type")]
    device_type: Option<String>,
}

fn build_os_string(asset: &RunZeroAsset) -> Option<String> {
    match (&asset.os_product, &asset.os_version) {
        (Some(product), Some(version)) if !product.is_empty() && !version.is_empty() => {
            Some(format!("{} {}", product, version))
        }
        (Some(product), _) if !product.is_empty() => Some(product.clone()),
        _ => asset.os.clone().filter(|s| !s.is_empty()),
    }
}

pub async fn sync_once(db: &Arc<Mutex<Db>>, url: &str, token: &str, ca_cert_pem: Option<&str>) -> Result<usize> {
    let client = crate::tls_client::builder_with_ca(ca_cert_pem)?
        .timeout(Duration::from_secs(30))
        .build()?;

    let resp = client
        .get(format!("{}/api/v1.0/export/org/assets.json", url.trim_end_matches('/')))
        .bearer_auth(token)
        .send()
        .await?;

    if !resp.status().is_success() {
        anyhow::bail!("runZero API returned {}", resp.status());
    }

    let assets: Vec<RunZeroAsset> = resp.json().await?;
    let db = db.lock().unwrap();

    let mut matched = 0;
    for asset in &assets {
        let Some(ref macs) = asset.macs else { continue };
        let os = build_os_string(asset);
        let hw = asset.hw.as_deref();
        let device_type = asset.device_type.as_deref();
        let manufacturer = asset.hw_vendor.as_deref();

        for mac in macs {
            let mac_lower = mac.to_lowercase();
            if db.get_device(&mac_lower)?.is_some() {
                db.update_runzero_data(&mac_lower, os.as_deref(), hw, device_type, manufacturer)?;
                matched += 1;
            }
        }
    }

    Ok(matched)
}

pub async fn run(db: Arc<Mutex<Db>>) {
    let mut check_interval = interval(Duration::from_secs(60));

    loop {
        check_interval.tick().await;

        let (enabled, url, token, sync_secs, ca_cert) = {
            let db = db.lock().unwrap();
            let enabled = db.get_config_bool("runzero_enabled", false);
            let url = db.get_config("runzero_url").ok().flatten().unwrap_or_default();
            let token = Zeroizing::new(db.get_config("runzero_token").ok().flatten().unwrap_or_default());
            let sync_secs: u64 = db.get_config("runzero_sync_interval")
                .ok().flatten()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600);
            let ca_cert = db.get_config("runzero_ca_cert").ok().flatten()
                .filter(|c| !c.is_empty());
            (enabled, url, token, sync_secs, ca_cert)
        };

        if !enabled || url.is_empty() || token.is_empty() {
            continue;
        }

        info!("runZero sync starting");
        match sync_once(&db, &url, &token, ca_cert.as_deref()).await {
            Ok(matched) => info!(matched, "runZero sync complete"),
            Err(e) => warn!(error = %e, "runZero sync failed"),
        }

        // Sleep for the remaining sync interval
        let sleep_secs = sync_secs.saturating_sub(60);
        if sleep_secs > 0 {
            tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
        }
    }
}
