use anyhow::Result;
use std::net::IpAddr;
use std::process::Command;
use tracing::{debug, info};

/// Validate that bandwidth is within the supported range (1-1,000,000 Mbps).
pub fn validate_bandwidth(mbps: u32) -> Result<()> {
    if mbps < 1 || mbps > 1_000_000 {
        anyhow::bail!("bandwidth {} Mbps out of range (1-1000000)", mbps);
    }
    Ok(())
}

/// Enable CAKE qdiscs for traffic shaping on the WAN interface.
///
/// Creates CAKE on WAN egress for upload shaping and an IFB device with CAKE
/// for download shaping. Calls `disable()` first to clean up any previous state.
pub fn enable(wan_iface: &str, upload_mbps: u32, download_mbps: u32) -> Result<()> {
    crate::nftables::validate_iface(wan_iface)?;
    validate_bandwidth(upload_mbps)?;
    validate_bandwidth(download_mbps)?;

    // Clean up any previous QoS state
    disable(wan_iface)?;

    // Upload shaping: CAKE on WAN egress
    let up_bw = format!("{}mbit", upload_mbps);
    let status = Command::new("/usr/sbin/tc")
        .args([
            "qdisc", "replace", "dev", wan_iface, "root", "cake",
            "bandwidth", &up_bw, "dual-srchost", "nat", "wash", "diffserv4",
        ])
        .status()?;
    if !status.success() {
        anyhow::bail!("failed to set CAKE upload qdisc on {}", wan_iface);
    }
    info!(iface = %wan_iface, bandwidth = %up_bw, "CAKE upload qdisc applied");

    // Download shaping: IFB device + CAKE
    // Create ifb0 module and device
    let status = Command::new("/usr/sbin/ip")
        .args(["link", "add", "ifb0", "type", "ifb"])
        .status()?;
    if !status.success() {
        anyhow::bail!("failed to create ifb0 device");
    }

    let status = Command::new("/usr/sbin/ip")
        .args(["link", "set", "ifb0", "up"])
        .status()?;
    if !status.success() {
        anyhow::bail!("failed to bring up ifb0");
    }

    // Add ingress qdisc on WAN to capture incoming traffic
    let status = Command::new("/usr/sbin/tc")
        .args(["qdisc", "add", "dev", wan_iface, "handle", "ffff:", "ingress"])
        .status()?;
    if !status.success() {
        anyhow::bail!("failed to add ingress qdisc on {}", wan_iface);
    }

    // Redirect all ingress traffic to ifb0
    let status = Command::new("/usr/sbin/tc")
        .args([
            "filter", "add", "dev", wan_iface, "parent", "ffff:",
            "protocol", "all", "u32", "match", "u32", "0", "0",
            "action", "mirred", "egress", "redirect", "dev", "ifb0",
        ])
        .status()?;
    if !status.success() {
        anyhow::bail!("failed to add redirect filter on {}", wan_iface);
    }

    // CAKE on ifb0 for download shaping
    let down_bw = format!("{}mbit", download_mbps);
    let status = Command::new("/usr/sbin/tc")
        .args([
            "qdisc", "replace", "dev", "ifb0", "root", "cake",
            "bandwidth", &down_bw, "dual-dsthost", "nat", "wash", "diffserv4",
        ])
        .status()?;
    if !status.success() {
        anyhow::bail!("failed to set CAKE download qdisc on ifb0");
    }
    info!(bandwidth = %down_bw, "CAKE download qdisc applied on ifb0");

    Ok(())
}

/// Disable QoS by removing qdiscs and the IFB device. Ignores errors since
/// the resources may not exist (e.g., QoS was never enabled).
pub fn disable(wan_iface: &str) -> Result<()> {
    crate::nftables::validate_iface(wan_iface)?;

    // Remove root qdisc from WAN (removes CAKE upload shaping)
    let _ = Command::new("/usr/sbin/tc")
        .args(["qdisc", "del", "dev", wan_iface, "root"])
        .status();
    debug!(iface = %wan_iface, "removed root qdisc (if any)");

    // Remove ingress qdisc from WAN
    let _ = Command::new("/usr/sbin/tc")
        .args(["qdisc", "del", "dev", wan_iface, "ingress"])
        .status();
    debug!(iface = %wan_iface, "removed ingress qdisc (if any)");

    // Remove root qdisc from ifb0
    let _ = Command::new("/usr/sbin/tc")
        .args(["qdisc", "del", "dev", "ifb0", "root"])
        .status();

    // Remove ifb0 device
    let _ = Command::new("/usr/sbin/ip")
        .args(["link", "del", "ifb0"])
        .status();
    debug!("removed ifb0 device (if any)");

    Ok(())
}

/// Returns true if the address is a public (globally routable) IP.
/// Returns false for private, loopback, link-local, and ULA ranges.
pub fn is_public_ip(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            // Private: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            // Loopback: 127.0.0.0/8
            // Link-local: 169.254.0.0/16
            // CGNAT: 100.64.0.0/10
            // Documentation: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
            // Broadcast: 255.255.255.255
            // Unspecified: 0.0.0.0
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64) // 100.64.0.0/10
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            // Loopback: ::1
            // Unspecified: ::
            // Link-local: fe80::/10
            // ULA: fc00::/7 (includes fd00::/8)
            // Multicast: ff00::/8
            !(v6.is_loopback()
                || v6.is_unspecified()
                || (octets[0] == 0xfe && (octets[1] & 0xC0) == 0x80) // link-local
                || (octets[0] & 0xFE) == 0xFC // ULA (fc00::/7)
                || octets[0] == 0xFF) // multicast
        }
    }
}

/// Apply DSCP marking rules via nftables. Takes (ipv4, group) pairs and
/// marks traffic from/to IoT and guest devices as CS1 (Bulk/deprioritized).
///
/// Groups that get CS1: `iot`, `guest`
/// Groups that keep CS0: `trusted`, `servers`
/// Groups that never reach CAKE: `quarantine`, `blocked` (dropped before)
pub fn apply_dscp_rules(devices: &[(String, String)]) -> Result<()> {
    // Validate all IPs before building the script
    for (ip, _group) in devices {
        let _: std::net::Ipv4Addr = ip
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid IPv4 in DSCP rules: {}", ip))?;
    }

    // Collect IPs from bulk groups (iot, guest)
    let bulk_ips: Vec<&str> = devices
        .iter()
        .filter(|(_ip, group)| group == "iot" || group == "guest")
        .map(|(ip, _group)| ip.as_str())
        .collect();

    // Build set elements
    let elements = if bulk_ips.is_empty() {
        String::new()
    } else {
        format!("        elements = {{ {} }}", bulk_ips.join(", "))
    };

    let script = format!(
        r#"#!/usr/sbin/nft -f
table inet qos
delete table inet qos
table inet qos {{
    set bulk_v4 {{
        type ipv4_addr
{elements}
    }}

    chain mark_forward {{
        type filter hook forward priority mangle; policy accept;
        ip saddr @bulk_v4 ip dscp set cs1
        ip daddr @bulk_v4 ip dscp set cs1
    }}
}}
"#
    );

    let temp_path = "/tmp/hermitshell-dscp.nft";
    std::fs::write(temp_path, &script)?;

    let status = Command::new("/usr/sbin/nft")
        .args(["-f", temp_path])
        .status()?;
    if !status.success() {
        anyhow::bail!("failed to apply DSCP marking rules");
    }

    info!(bulk_count = bulk_ips.len(), "DSCP marking rules applied");
    Ok(())
}

/// Run a download speed test by fetching the given URL and measuring throughput.
/// Returns estimated download speed in Mbps.
pub async fn run_speed_test(url: &str) -> Result<u32> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|_| anyhow::anyhow!("invalid url"))?;

    // SSRF check
    if let Some(host) = parsed.host_str() {
        if let Ok(addr) = host.parse::<std::net::IpAddr>() {
            if !is_public_ip(&addr) {
                anyhow::bail!("url must not point to private/loopback address");
            }
        }
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let start = std::time::Instant::now();
    let resp = client.get(url).send().await?;
    let bytes = resp.bytes().await?;
    let elapsed = start.elapsed().as_secs_f64();

    if elapsed < 0.001 {
        anyhow::bail!("test completed too quickly for accurate measurement");
    }

    let mbps = (bytes.len() as f64 * 8.0) / (elapsed * 1_000_000.0);
    info!(url = url, bytes = bytes.len(), elapsed_ms = (elapsed * 1000.0) as u64, mbps = mbps as u32, "speed test complete");
    Ok(mbps as u32)
}

/// Remove DSCP marking rules by deleting the `table inet qos`.
/// Ignores errors if the table does not exist.
pub fn remove_dscp_rules() -> Result<()> {
    let _ = Command::new("/usr/sbin/nft")
        .args(["delete", "table", "inet", "qos"])
        .status();
    info!("DSCP marking rules removed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_validate_bandwidth_valid() {
        assert!(validate_bandwidth(1).is_ok());
        assert!(validate_bandwidth(100).is_ok());
        assert!(validate_bandwidth(1_000_000).is_ok());
    }

    #[test]
    fn test_validate_bandwidth_invalid() {
        assert!(validate_bandwidth(0).is_err());
        assert!(validate_bandwidth(1_000_001).is_err());
    }

    #[test]
    fn test_is_public_ip_v4() {
        // Private ranges
        assert!(!is_public_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!is_public_ip(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(!is_public_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        // Loopback
        assert!(!is_public_ip(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        // Link-local
        assert!(!is_public_ip(&IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
        // CGNAT
        assert!(!is_public_ip(&IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        // Public
        assert!(is_public_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(is_public_ip(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }

    #[test]
    fn test_is_public_ip_v6() {
        // Loopback
        assert!(!is_public_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        // Link-local
        assert!(!is_public_ip(&IpAddr::V6(
            "fe80::1".parse::<Ipv6Addr>().unwrap()
        )));
        // ULA
        assert!(!is_public_ip(&IpAddr::V6(
            "fd00::1".parse::<Ipv6Addr>().unwrap()
        )));
        assert!(!is_public_ip(&IpAddr::V6(
            "fc00::1".parse::<Ipv6Addr>().unwrap()
        )));
        // Global unicast
        assert!(is_public_ip(&IpAddr::V6(
            "2001:db8::1".parse::<Ipv6Addr>().unwrap()
        )));
        assert!(is_public_ip(&IpAddr::V6(
            "2607:f8b0:4004:800::200e".parse::<Ipv6Addr>().unwrap()
        )));
    }
}
