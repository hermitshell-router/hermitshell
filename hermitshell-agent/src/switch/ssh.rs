use std::sync::Arc;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use regex::Regex;
use russh::ChannelMsg;
use russh::client;
use russh::keys::ssh_key;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use super::{MacTableEntry, PortStatus, SwitchPort, SwitchProvider};
use super::vendor::VendorProfile;

const CMD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// SSH-based managed switch provider.
///
/// Connects to a managed switch via SSH, sends CLI commands based on a
/// vendor profile, and parses the output.
pub struct SshSwitchProvider {
    host: String,
    port: u16,
    username: String,
    password: String,
    profile: VendorProfile,
    /// TOFU pinned host key in OpenSSH format.
    host_key: Option<String>,
}

impl SshSwitchProvider {
    pub fn new(
        host: String,
        port: u16,
        username: String,
        password: String,
        profile: VendorProfile,
        host_key: Option<String>,
    ) -> Self {
        Self {
            host,
            port,
            username,
            password,
            profile,
            host_key,
        }
    }

    pub fn host_key(&self) -> Option<&str> {
        self.host_key.as_deref()
    }

    /// Connect via SSH, authenticate, and open a shell channel.
    /// Returns the channel and the (possibly updated) host key.
    async fn connect(
        &self,
    ) -> Result<(
        russh::Channel<client::Msg>,
        client::Handle<TofuHandler>,
        String,
    )> {
        let config = Arc::new(client::Config {
            inactivity_timeout: Some(CMD_TIMEOUT),
            ..Default::default()
        });

        let handler = TofuHandler {
            pinned_key: self.host_key.clone(),
            discovered_key: Arc::new(Mutex::new(None)),
        };
        let discovered_key_ref = handler.discovered_key.clone();

        let addr = format!("{}:{}", self.host, self.port);
        let mut handle = tokio::time::timeout(
            CMD_TIMEOUT,
            client::connect(config, &addr, handler),
        )
        .await
        .context("SSH connect timed out")?
        .context("SSH connect failed")?;

        let auth_result = tokio::time::timeout(
            CMD_TIMEOUT,
            handle.authenticate_password(&self.username, &self.password),
        )
        .await
        .context("SSH auth timed out")?
        .context("SSH auth failed")?;

        if !matches!(auth_result, russh::client::AuthResult::Success) {
            bail!("SSH authentication failed for {}@{}", self.username, self.host);
        }

        let channel = handle
            .channel_open_session()
            .await
            .context("failed to open SSH session channel")?;

        // Request a PTY so switch CLI sends prompts
        channel
            .request_pty(false, "xterm", 200, 24, 0, 0, &[])
            .await
            .context("failed to request PTY")?;

        channel
            .request_shell(false)
            .await
            .context("failed to request shell")?;

        // Retrieve discovered host key
        let key = discovered_key_ref
            .lock()
            .await
            .clone()
            .unwrap_or_default();

        Ok((channel, handle, key))
    }

    /// Send a single command line to the channel and read output until the
    /// prompt pattern matches. Returns the accumulated output.
    async fn send_command(
        channel: &mut russh::Channel<client::Msg>,
        cmd: &str,
        prompt_re: &Regex,
    ) -> Result<String> {
        let data = format!("{}\n", cmd);
        channel
            .data(data.as_bytes())
            .await
            .context("failed to send command")?;

        Self::read_until_prompt(channel, prompt_re).await
    }

    /// Read channel output until the prompt regex matches the end of the
    /// accumulated buffer.
    async fn read_until_prompt(
        channel: &mut russh::Channel<client::Msg>,
        prompt_re: &Regex,
    ) -> Result<String> {
        let mut output = String::new();
        loop {
            let msg = tokio::time::timeout(CMD_TIMEOUT, channel.wait())
                .await
                .context("timed out waiting for switch response")?;

            match msg {
                Some(ChannelMsg::Data { data }) => {
                    let chunk = String::from_utf8_lossy(&data);
                    output.push_str(&chunk);
                    // Check if the prompt appeared
                    if prompt_re.is_match(&output) {
                        return Ok(output);
                    }
                }
                Some(ChannelMsg::ExtendedData { data, .. }) => {
                    let chunk = String::from_utf8_lossy(&data);
                    output.push_str(&chunk);
                    if prompt_re.is_match(&output) {
                        return Ok(output);
                    }
                }
                Some(ChannelMsg::Eof | ChannelMsg::Close) => {
                    // Channel closed before prompt matched
                    if output.is_empty() {
                        bail!("SSH channel closed without output");
                    }
                    return Ok(output);
                }
                None => {
                    bail!("SSH channel closed unexpectedly");
                }
                _ => {
                    // Ignore other messages (WindowAdjusted, ExitStatus, etc.)
                }
            }
        }
    }

    /// Execute a multi-line command sequence (lines separated by literal `\n`
    /// in the vendor template) and return the combined output.
    async fn exec_lines(
        channel: &mut russh::Channel<client::Msg>,
        template: &str,
        prompt_re: &Regex,
    ) -> Result<String> {
        let mut combined = String::new();
        for line in template.split("\\n") {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let out = Self::send_command(channel, line, prompt_re).await?;
            combined.push_str(&out);
        }
        Ok(combined)
    }

    /// Build the combined prompt regex that matches both normal and config mode prompts.
    fn prompt_regex(&self) -> Result<Regex> {
        let pattern = format!(
            "(?:{})|(?:{})",
            self.profile.prompt_pattern, self.profile.config_prompt_pattern
        );
        Regex::new(&pattern).context("invalid prompt pattern")
    }

    /// Connect, consume initial prompt, run a sequence of commands, and disconnect.
    async fn run_commands(&self, commands: &[String]) -> Result<String> {
        let (mut channel, handle, _key) = self.connect().await?;
        let prompt_re = self.prompt_regex()?;

        // Consume initial banner/prompt
        Self::read_until_prompt(&mut channel, &prompt_re)
            .await
            .context("failed to read initial prompt")?;

        let mut combined = String::new();
        for cmd_template in commands {
            let out = Self::exec_lines(&mut channel, cmd_template, &prompt_re).await?;
            combined.push_str(&out);
        }

        // Best-effort close
        let _ = channel.close().await;
        let _ = handle
            .disconnect(russh::Disconnect::ByApplication, "done", "en")
            .await;

        Ok(combined)
    }

    /// Connect, consume initial prompt, run a config session (enter config,
    /// run commands, exit config), and disconnect.
    async fn run_config_session(&self, commands: &[String]) -> Result<String> {
        let session = build_config_session(&self.profile, commands);
        let (mut channel, handle, _key) = self.connect().await?;
        let prompt_re = self.prompt_regex()?;

        // Consume initial banner/prompt
        Self::read_until_prompt(&mut channel, &prompt_re)
            .await
            .context("failed to read initial prompt")?;

        let out = Self::exec_lines(&mut channel, &session, &prompt_re).await?;

        let _ = channel.close().await;
        let _ = handle
            .disconnect(russh::Disconnect::ByApplication, "done", "en")
            .await;

        Ok(out)
    }
}

/// Build a config-mode session string from a vendor profile and a list of
/// commands. Returns the enter_config command, followed by each command,
/// followed by the exit_config command, all joined by `\n` (literal
/// backslash-n to match vendor template convention).
pub fn build_config_session(profile: &VendorProfile, commands: &[String]) -> String {
    let mut parts = Vec::with_capacity(commands.len() + 2);
    parts.push(profile.commands.enter_config.clone());
    for cmd in commands {
        parts.push(cmd.clone());
    }
    parts.push(profile.commands.exit_config.clone());
    parts.join("\\n")
}

// ── TOFU host key handler ──────────────────────────────────────────

/// A minimal SSH client handler that implements Trust-On-First-Use (TOFU)
/// host key verification.
struct TofuHandler {
    /// Previously pinned host key (OpenSSH format), or None on first connect.
    pinned_key: Option<String>,
    /// Slot where the server's offered key is stored after verification so
    /// the caller can persist it.
    discovered_key: Arc<Mutex<Option<String>>>,
}

impl client::Handler for TofuHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        let offered = server_public_key
            .to_openssh()
            .unwrap_or_default();

        // Store the key for the caller to retrieve
        *self.discovered_key.lock().await = Some(offered.clone());

        match &self.pinned_key {
            None => {
                debug!("TOFU: accepting new host key");
                Ok(true)
            }
            Some(pinned) => {
                if *pinned == offered {
                    debug!("TOFU: host key matches pinned key");
                    Ok(true)
                } else {
                    warn!("TOFU: host key mismatch! Expected: {pinned}");
                    Ok(false)
                }
            }
        }
    }
}

// ── SwitchProvider implementation ──────────────────────────────────

#[async_trait]
impl SwitchProvider for SshSwitchProvider {
    async fn ping(&self) -> Result<()> {
        let (mut channel, handle, _key) = self.connect().await?;
        let prompt_re = self.prompt_regex()?;

        // Send a blank line and verify we get a prompt back
        Self::send_command(&mut channel, "", &prompt_re)
            .await
            .context("switch did not respond to ping")?;

        let _ = channel.close().await;
        let _ = handle
            .disconnect(russh::Disconnect::ByApplication, "done", "en")
            .await;

        Ok(())
    }

    async fn list_ports(&self) -> Result<Vec<SwitchPort>> {
        let output = self
            .run_commands(&[self.profile.commands.get_ports.clone()])
            .await?;

        // Basic parsing: look for lines that contain common interface name
        // patterns and up/down status.
        let mut ports = Vec::new();
        let iface_re = Regex::new(
            r"(?i)((?:Gi|Fa|Te|Eth|ge|fe|GigabitEthernet|FastEthernet)\S*)\s+.*?(up|down|disabled)"
        )?;

        for line in output.lines() {
            if let Some(caps) = iface_re.captures(line) {
                let name = caps[1].to_string();
                let status_str = caps[2].to_lowercase();
                let status = match status_str.as_str() {
                    "up" => PortStatus::Up,
                    "down" => PortStatus::Down,
                    "disabled" => PortStatus::Disabled,
                    _ => PortStatus::Down,
                };
                ports.push(SwitchPort {
                    name,
                    status,
                    vlan_id: None,
                    is_trunk: false,
                    macs: Vec::new(),
                });
            }
        }

        Ok(ports)
    }

    async fn set_port_vlan(&self, port: &str, vlan_id: u16) -> Result<()> {
        let cmd = self.profile.render_set_access_port(port, vlan_id);
        self.run_config_session(&[cmd]).await?;
        self.save_config().await?;
        Ok(())
    }

    async fn get_mac_table(&self) -> Result<Vec<MacTableEntry>> {
        let output = self
            .run_commands(&[self.profile.commands.get_mac_table.clone()])
            .await?;

        Ok(self.profile.parse_mac_table(&output))
    }

    async fn set_trunk_port(&self, port: &str, allowed_vlans: &[u16]) -> Result<()> {
        let cmd = self.profile.render_set_trunk_port(port, allowed_vlans);
        self.run_config_session(&[cmd]).await?;
        self.save_config().await?;
        Ok(())
    }

    async fn create_vlan(&self, vlan_id: u16, name: &str) -> Result<()> {
        let cmd = self.profile.render_create_vlan(vlan_id, name);
        self.run_config_session(&[cmd]).await?;
        self.save_config().await?;
        Ok(())
    }

    async fn save_config(&self) -> Result<()> {
        self.run_commands(&[self.profile.commands.save_config.clone()])
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::switch::vendor;

    #[test]
    fn test_build_config_session() {
        let profile = vendor::built_in_profile("cisco_ios").unwrap();
        let cmds = vec![
            profile.render_create_vlan(10, "trusted"),
            profile.render_set_access_port("Gi0/1", 10),
        ];
        let session = build_config_session(&profile, &cmds);
        assert!(session.contains("configure terminal"));
        assert!(session.contains("vlan 10"));
        assert!(session.contains("name trusted"));
        assert!(session.contains("interface Gi0/1"));
        assert!(session.contains("switchport access vlan 10"));
        assert!(session.contains("end"));
    }

    #[test]
    fn test_ssh_provider_new() {
        let profile = vendor::built_in_profile("cisco_ios").unwrap();
        let provider = SshSwitchProvider::new(
            "192.168.1.100".into(),
            22,
            "admin".into(),
            "pass".into(),
            profile,
            None,
        );
        assert!(provider.host_key().is_none());
    }

    #[test]
    fn test_ssh_provider_with_host_key() {
        let profile = vendor::built_in_profile("cisco_ios").unwrap();
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest".to_string();
        let provider = SshSwitchProvider::new(
            "192.168.1.100".into(),
            22,
            "admin".into(),
            "pass".into(),
            profile,
            Some(key.clone()),
        );
        assert_eq!(provider.host_key(), Some(key.as_str()));
    }

    #[test]
    fn test_build_config_session_tplink() {
        let profile = vendor::built_in_profile("tplink_t").unwrap();
        let cmds = vec![profile.render_create_vlan(20, "guest")];
        let session = build_config_session(&profile, &cmds);
        assert!(session.contains("configure"));
        assert!(session.contains("vlan 20"));
        assert!(session.contains("name guest"));
        assert!(session.contains("end"));
    }

    #[test]
    fn test_build_config_session_empty() {
        let profile = vendor::built_in_profile("cisco_ios").unwrap();
        let session = build_config_session(&profile, &[]);
        assert!(session.contains("configure terminal"));
        assert!(session.contains("end"));
    }
}
