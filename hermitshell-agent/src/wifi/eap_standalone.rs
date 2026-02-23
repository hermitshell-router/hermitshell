use anyhow::Result;
use async_trait::async_trait;
use hermitshell_common::{WifiClient, WifiRadioConfig, WifiSsidConfig};

use super::{ApStatus, WifiSession};

/// Session to a TP-Link EAP in standalone mode via its HTTPS web UI.
pub struct EapSession {
    _client: reqwest::Client,
    _base_url: String,
    // Cookie jar is handled by reqwest client with cookie_store enabled
}

impl EapSession {
    pub async fn login(ip: &str, _username: &str, _password: &str) -> Result<Self> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .cookie_store(true)
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        let base_url = format!("https://{}", ip);

        // TODO: Implement actual EAP login by reverse-engineering the web UI.
        // For now, just verify connectivity.
        let resp = client.get(&base_url).send().await?;
        if !resp.status().is_success() && resp.status().as_u16() != 302 {
            anyhow::bail!("EAP at {} returned {}", ip, resp.status());
        }

        Ok(Self {
            _client: client,
            _base_url: base_url,
        })
    }
}

#[async_trait]
impl WifiSession for EapSession {
    async fn get_status(&self) -> Result<ApStatus> {
        // TODO: reverse-engineer EAP status endpoint
        Ok(ApStatus {
            model: Some("EAP720".to_string()),
            firmware: None,
            uptime: None,
        })
    }

    async fn get_clients(&self) -> Result<Vec<WifiClient>> {
        // TODO: reverse-engineer EAP client list endpoint
        Ok(vec![])
    }

    async fn get_ssids(&self) -> Result<Vec<WifiSsidConfig>> {
        // TODO: reverse-engineer EAP SSID list endpoint
        Ok(vec![])
    }

    async fn set_ssid(&self, _config: &WifiSsidConfig) -> Result<()> {
        // TODO: reverse-engineer EAP SSID set endpoint
        anyhow::bail!("EAP standalone provider: set_ssid not yet implemented")
    }

    async fn delete_ssid(&self, _ssid_name: &str, _band: &str) -> Result<()> {
        anyhow::bail!("EAP standalone provider: delete_ssid not yet implemented")
    }

    async fn get_radios(&self) -> Result<Vec<WifiRadioConfig>> {
        // TODO: reverse-engineer EAP radio list endpoint
        Ok(vec![])
    }

    async fn set_radio(&self, _config: &WifiRadioConfig) -> Result<()> {
        anyhow::bail!("EAP standalone provider: set_radio not yet implemented")
    }

    async fn kick_client(&self, _mac: &str) -> Result<()> {
        anyhow::bail!("EAP standalone provider: kick_client not yet implemented")
    }

    async fn block_client(&self, _mac: &str) -> Result<()> {
        anyhow::bail!("EAP standalone provider: block_client not yet implemented")
    }

    async fn unblock_client(&self, _mac: &str) -> Result<()> {
        anyhow::bail!("EAP standalone provider: unblock_client not yet implemented")
    }
}
