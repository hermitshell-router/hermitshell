use anyhow::Result;
use std::process::Command;
use tracing::{debug, info};

/// Validate WireGuard public key: base64-encoded, exactly 44 characters, decodes to 32 bytes.
fn validate_pubkey(key: &str) -> Result<()> {
    if key.len() != 44 || !key.ends_with('=') {
        anyhow::bail!("invalid WireGuard public key: {}", key);
    }
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(key)
        .map_err(|_| anyhow::anyhow!("invalid base64 in WireGuard public key"))?;
    if decoded.len() != 32 {
        anyhow::bail!("WireGuard public key must decode to 32 bytes, got {}", decoded.len());
    }
    Ok(())
}

/// Generate a WireGuard private key. Returns (private_key, public_key).
pub fn generate_keypair() -> Result<(String, String)> {
    let privkey_output = Command::new("/usr/bin/wg")
        .arg("genkey")
        .output()?;
    if !privkey_output.status.success() {
        anyhow::bail!("wg genkey failed");
    }
    let private_key = String::from_utf8(privkey_output.stdout)?.trim().to_string();

    let public_key = pubkey_from_private(&private_key)?;
    Ok((private_key, public_key))
}

/// Derive public key from a private key string.
pub fn pubkey_from_private(private_key: &str) -> Result<String> {
    use std::io::Write;
    let mut cmd = Command::new("/usr/bin/wg")
        .arg("pubkey")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    cmd.stdin.take()
        .ok_or_else(|| anyhow::anyhow!("wg stdin not piped"))?
        .write_all(private_key.as_bytes())?;
    let output = cmd.wait_with_output()?;
    if !output.status.success() {
        anyhow::bail!("wg pubkey failed");
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

/// Create and bring up the wg0 interface with the given private key and port.
pub fn create_interface(private_key: &str, listen_port: u16) -> Result<()> {
    // Create interface (ignore error if already exists)
    let _ = Command::new("/usr/sbin/ip")
        .args(["link", "add", "wg0", "type", "wireguard"])
        .status();

    // Set private key via temp file (wg requires file path)
    let key_path = "/tmp/hermitshell-wg-key";
    std::fs::write(key_path, private_key)?;
    let status = Command::new("/usr/bin/wg")
        .args(["set", "wg0", "private-key", key_path, "listen-port", &listen_port.to_string()])
        .status()?;
    std::fs::remove_file(key_path).ok();
    if !status.success() {
        anyhow::bail!("wg set failed");
    }

    // Assign router IPv4 address (ignore: may already exist)
    let _ = Command::new("/usr/sbin/ip")
        .args(["addr", "add", "10.0.0.1/32", "dev", "wg0"])
        .status();

    // Assign router IPv6 ULA address (ignore: may already exist)
    let _ = Command::new("/usr/sbin/ip")
        .args(["-6", "addr", "add", "fd00::1/128", "dev", "wg0"])
        .status();

    // Bring up
    let status = Command::new("/usr/sbin/ip")
        .args(["link", "set", "wg0", "up"])
        .status()?;
    if !status.success() {
        anyhow::bail!("failed to bring up wg0");
    }

    info!(port = listen_port, "wireguard interface wg0 created");
    Ok(())
}

/// Destroy the wg0 interface.
pub fn destroy_interface() -> Result<()> {
    // best-effort: interface may not exist
    let _ = Command::new("/usr/sbin/ip")
        .args(["link", "del", "wg0"])
        .status();
    info!("wireguard interface wg0 removed");
    Ok(())
}

/// Add a peer to the wg0 interface with dual-stack allowed-ips.
pub fn add_peer(public_key: &str, device_ipv4: &str, device_ipv6_ula: &str) -> Result<()> {
    validate_pubkey(public_key)?;
    crate::nftables::validate_ip(device_ipv4)?;
    crate::nftables::validate_ipv6_ula(device_ipv6_ula)?;

    let allowed_ips = format!("{}/32,{}/128", device_ipv4, device_ipv6_ula);
    let status = Command::new("/usr/bin/wg")
        .args(["set", "wg0", "peer", public_key, "allowed-ips", &allowed_ips])
        .status()?;
    if !status.success() {
        anyhow::bail!("failed to add WireGuard peer {}", public_key);
    }

    // Add IPv4 route (ignore: may already exist from previous add)
    let route_v4 = format!("{}/32", device_ipv4);
    let _ = Command::new("/usr/sbin/ip")
        .args(["route", "add", &route_v4, "dev", "wg0"])
        .status();

    // Add IPv6 route (ignore: may already exist)
    let route_v6 = format!("{}/128", device_ipv6_ula);
    let _ = Command::new("/usr/sbin/ip")
        .args(["-6", "route", "add", &route_v6, "dev", "wg0"])
        .status();

    debug!(public_key = %public_key, ipv4 = %device_ipv4, ipv6 = %device_ipv6_ula, "added wireguard peer");
    Ok(())
}

/// Remove a peer from the wg0 interface and clean up routes.
pub fn remove_peer(public_key: &str, device_ipv4: &str, device_ipv6_ula: &str) -> Result<()> {
    validate_pubkey(public_key)?;

    // best-effort cleanup: peer may already be removed
    let _ = Command::new("/usr/bin/wg")
        .args(["set", "wg0", "peer", public_key, "remove"])
        .status();

    // best-effort: route may not exist
    let route_v4 = format!("{}/32", device_ipv4);
    let _ = Command::new("/usr/sbin/ip")
        .args(["route", "del", &route_v4, "dev", "wg0"])
        .status();

    // best-effort: IPv6 route may not exist
    let route_v6 = format!("{}/128", device_ipv6_ula);
    let _ = Command::new("/usr/sbin/ip")
        .args(["-6", "route", "del", &route_v6, "dev", "wg0"])
        .status();

    debug!(public_key = %public_key, "removed wireguard peer");
    Ok(())
}

/// Open the WireGuard listen port in nftables input chain.
pub fn open_listen_port(port: u16) -> Result<()> {
    let port_str = port.to_string();
    let status = Command::new("/usr/sbin/nft")
        .args(["add", "rule", "inet", "filter", "input",
               "udp", "dport", &port_str, "accept",
               "comment", "\"wireguard\""])
        .status()?;
    if !status.success() {
        anyhow::bail!("failed to open WireGuard port {}", port);
    }
    Ok(())
}

/// Close the WireGuard listen port by removing only the wireguard-commented rule.
pub fn close_listen_port() -> Result<()> {
    let output = Command::new("/usr/sbin/nft")
        .args(["-a", "list", "chain", "inet", "filter", "input"])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.contains("wireguard") {
            if let Some(handle) = line.split("# handle ").last() {
                let handle = handle.trim();
                // best-effort: rule may already have been removed
                let _ = Command::new("/usr/sbin/nft")
                    .args(["delete", "rule", "inet", "filter", "input", "handle", handle])
                    .status();
            }
        }
    }
    Ok(())
}
