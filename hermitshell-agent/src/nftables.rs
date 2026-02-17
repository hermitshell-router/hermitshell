use anyhow::Result;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::Command;
use tracing::{debug, info};

const VALID_GROUPS: &[&str] = &["quarantine", "trusted", "iot", "guest", "servers", "blocked"];

/// Validate that an IP string is a valid IPv4 address within 10.0.0.0/8.
fn validate_ip(ip: &str) -> Result<()> {
    let addr: Ipv4Addr = ip.parse().map_err(|_| anyhow::anyhow!("invalid IP: {}", ip))?;
    let octets = addr.octets();
    if octets[0] != 10 {
        anyhow::bail!("IP {} not in 10.0.0.0/8 range", ip);
    }
    Ok(())
}

/// Validate that a group name is one of the known forwarding chains.
fn validate_group(group: &str) -> Result<()> {
    if !VALID_GROUPS.contains(&group) {
        anyhow::bail!("invalid group: {}", group);
    }
    Ok(())
}

/// Validate a MAC address: exactly "XX:XX:XX:XX:XX:XX" with lowercase hex.
pub fn validate_mac(mac: &str) -> Result<()> {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 || !parts.iter().all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit())) {
        anyhow::bail!("invalid MAC address: {}", mac);
    }
    Ok(())
}

/// Validate a network interface name: alphanumeric, hyphens, underscores, dots; max 15 chars.
pub fn validate_iface(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 15
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        anyhow::bail!("invalid interface name: {}", name);
    }
    Ok(())
}

/// Public wrapper for IP validation, used by wireguard.rs.
pub fn validate_ip_pub(ip: &str) -> Result<()> {
    validate_ip(ip)
}

pub fn apply_base_rules(wan_iface: &str, lan_iface: &str) -> Result<()> {
    validate_iface(wan_iface)?;
    validate_iface(lan_iface)?;
    let rules = format!(r#"#!/usr/sbin/nft -f
flush ruleset

table inet filter {{
    map device_groups {{
        type ipv4_addr : verdict;
    }}

    chain input {{
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        iifname "lo" accept
        iifname "{lan_iface}" tcp dport {{ 80, 443 }} accept
        iifname "{lan_iface}" udp dport 67 accept
        iifname "{lan_iface}" tcp dport 53 accept
        iifname "{lan_iface}" udp dport 53 accept
        iifname "{wan_iface}" icmp type echo-request accept
    }}
    chain forward {{
        type filter hook forward priority 0; policy drop;
        ct state established,related accept
        ip saddr vmap @device_groups
    }}
    chain output {{
        type filter hook output priority 0; policy accept;
    }}

    chain quarantine_fwd {{
        oifname "{wan_iface}" accept
        drop
    }}
    chain trusted_fwd {{
        accept
    }}
    chain iot_fwd {{
        oifname "{wan_iface}" accept
        drop
    }}
    chain guest_fwd {{
        oifname "{wan_iface}" accept
        drop
    }}
    chain servers_fwd {{
        oifname "{wan_iface}" accept
        drop
    }}
    chain blocked_fwd {{
        drop
    }}
}}

table ip nat {{
    chain prerouting {{
        type nat hook prerouting priority -100;
        iifname "{lan_iface}" udp dport 53 dnat to 10.0.0.1:53
        iifname "{lan_iface}" tcp dport 53 dnat to 10.0.0.1:53
    }}
    chain postrouting {{
        type nat hook postrouting priority 100;
        oifname "{wan_iface}" masquerade
    }}
}}

table inet traffic {{
    set tx_devices {{
        type ipv4_addr
        flags dynamic
        counter
    }}
    set rx_devices {{
        type ipv4_addr
        flags dynamic
        counter
    }}

    chain count_lan {{
        type filter hook forward priority -10; policy accept;
        ip saddr @tx_devices
        ip daddr @rx_devices
    }}
}}
"#);

    let temp_path = "/tmp/hermitshell-rules.nft";
    std::fs::write(temp_path, &rules)?;

    let status = Command::new("/usr/sbin/nft")
        .args(["-f", temp_path])
        .status()?;

    if status.success() {
        info!("applied nftables rules");
        Ok(())
    } else {
        anyhow::bail!("Failed to apply nftables rules")
    }
}

pub fn add_device_counter(ip: &str) -> Result<()> {
    validate_ip(ip)?;
    let element = format!("{{ {} }}", ip);

    // Add to TX counter set (traffic from device)
    let _ = Command::new("/usr/sbin/nft")
        .args(["add", "element", "inet", "traffic", "tx_devices", &element])
        .status()?;

    // Add to RX counter set (traffic to device)
    let _ = Command::new("/usr/sbin/nft")
        .args(["add", "element", "inet", "traffic", "rx_devices", &element])
        .status()?;

    Ok(())
}

/// Parse counter set output into map of ip -> bytes.
/// Element lines look like: "10.0.1.2 counter packets 123 bytes 45678"
fn parse_counter_set(output: &str) -> HashMap<String, i64> {
    let mut counters = HashMap::new();
    for line in output.lines() {
        let line = line.trim();
        if !line.contains("counter packets") {
            continue;
        }
        for entry in line.split(',') {
            let entry = entry.trim().trim_start_matches("elements = {").trim().trim_end_matches('}').trim();
            if entry.is_empty() {
                continue;
            }
            let parts: Vec<&str> = entry.split_whitespace().collect();
            // Expected: ["10.0.1.2", "counter", "packets", "123", "bytes", "45678"]
            if parts.len() >= 6 && parts[1] == "counter" && parts[4] == "bytes" {
                if let Ok(bytes) = parts[5].parse::<i64>() {
                    counters.insert(parts[0].to_string(), bytes);
                }
            }
        }
    }
    counters
}

/// Get rx/tx bytes for a specific IP
pub fn get_device_counters(ip: &str) -> Result<(i64, i64)> {
    let tx_output = Command::new("/usr/sbin/nft")
        .args(["list", "set", "inet", "traffic", "tx_devices"])
        .output()?;
    let rx_output = Command::new("/usr/sbin/nft")
        .args(["list", "set", "inet", "traffic", "rx_devices"])
        .output()?;

    let tx_map = parse_counter_set(&String::from_utf8_lossy(&tx_output.stdout));
    let rx_map = parse_counter_set(&String::from_utf8_lossy(&rx_output.stdout));

    let tx = tx_map.get(ip).copied().unwrap_or(0);
    let rx = rx_map.get(ip).copied().unwrap_or(0);
    Ok((rx, tx))
}

/// Add device to verdict map: ip -> jump {group}_fwd
pub fn add_device_forward_rule(ip: &str, group: &str) -> Result<()> {
    validate_ip(ip)?;
    validate_group(group)?;
    let chain = format!("{}_fwd", group);
    let element = format!("{{ {} : jump {} }}", ip, chain);
    let status = Command::new("/usr/sbin/nft")
        .args(["add", "element", "inet", "filter", "device_groups", &element])
        .status()?;
    if status.success() {
        debug!(ip = %ip, chain = %chain, "added device_groups element");
        Ok(())
    } else {
        anyhow::bail!("Failed to add device_groups element for {}", ip)
    }
}

/// Remove device from verdict map and flush conntrack entries.
pub fn remove_device_forward_rule(ip: &str) -> Result<()> {
    validate_ip(ip)?;
    let element = format!("{{ {} }}", ip);
    // Ignore errors — element may not exist (e.g. already blocked)
    let _ = Command::new("/usr/sbin/nft")
        .args(["delete", "element", "inet", "filter", "device_groups", &element])
        .status();

    // Flush conntrack entries so established connections don't bypass the block
    let _ = Command::new("/usr/sbin/conntrack")
        .args(["-D", "-s", ip])
        .status();

    Ok(())
}

/// Add /30 gateway address to LAN interface
pub fn add_gateway_address(gateway: &str, lan_iface: &str) -> Result<()> {
    validate_ip(gateway)?;
    let addr = format!("{}/30", gateway);
    let status = Command::new("/usr/sbin/ip")
        .args(["addr", "add", &addr, "dev", lan_iface])
        .status()?;
    // Ignore "already exists" errors
    if status.success() {
        debug!(addr = %addr, iface = lan_iface, "added gateway address");
    }
    Ok(())
}

/// Apply port forwarding DNAT rules and corresponding forward rules.
/// Flushes and rebuilds the nat prerouting chain and a dedicated forward chain.
pub fn apply_port_forwards(
    wan_iface: &str,
    lan_iface: &str,
    forwards: &[crate::db::PortForward],
    dmz_ip: Option<&str>,
) -> Result<()> {
    validate_iface(wan_iface)?;
    validate_iface(lan_iface)?;

    // Build prerouting chain rules
    let mut prerouting_rules = String::new();

    // Port forward DNAT rules
    for fwd in forwards {
        validate_ip(&fwd.internal_ip)?;
        let protos: Vec<&str> = match fwd.protocol.as_str() {
            "tcp" => vec!["tcp"],
            "udp" => vec!["udp"],
            _ => vec!["tcp", "udp"],
        };
        for proto in protos {
            if fwd.external_port_start == fwd.external_port_end {
                prerouting_rules.push_str(&format!(
                    "        iifname \"{}\" {} dport {} dnat to {}:{}\n",
                    wan_iface, proto, fwd.external_port_start, fwd.internal_ip, fwd.internal_port
                ));
            } else {
                prerouting_rules.push_str(&format!(
                    "        iifname \"{}\" {} dport {}-{} dnat to {}:{}-{}\n",
                    wan_iface, proto, fwd.external_port_start, fwd.external_port_end,
                    fwd.internal_ip, fwd.internal_port,
                    fwd.internal_port + (fwd.external_port_end - fwd.external_port_start)
                ));
            }
        }
    }

    // DMZ catch-all (must be last before DNS redirect)
    if let Some(ip) = dmz_ip {
        if !ip.is_empty() {
            validate_ip(ip)?;
            prerouting_rules.push_str(&format!(
                "        iifname \"{}\" dnat to {}\n",
                wan_iface, ip
            ));
        }
    }

    // DNS redirect rules (always present)
    prerouting_rules.push_str(&format!(
        "        iifname \"{}\" udp dport 53 dnat to 10.0.0.1:53\n",
        lan_iface
    ));
    prerouting_rules.push_str(&format!(
        "        iifname \"{}\" tcp dport 53 dnat to 10.0.0.1:53\n",
        lan_iface
    ));

    // Build forward allow rules for port forwards
    let mut forward_rules = String::new();
    for fwd in forwards {
        let protos: Vec<&str> = match fwd.protocol.as_str() {
            "tcp" => vec!["tcp"],
            "udp" => vec!["udp"],
            _ => vec!["tcp", "udp"],
        };
        for proto in protos {
            if fwd.external_port_start == fwd.external_port_end {
                forward_rules.push_str(&format!(
                    "        ct state new iifname \"{}\" ip daddr {} {} dport {} accept\n",
                    wan_iface, fwd.internal_ip, proto, fwd.internal_port
                ));
            } else {
                forward_rules.push_str(&format!(
                    "        ct state new iifname \"{}\" ip daddr {} {} dport {}-{} accept\n",
                    wan_iface, fwd.internal_ip, proto, fwd.internal_port,
                    fwd.internal_port + (fwd.external_port_end - fwd.external_port_start)
                ));
            }
        }
    }
    // DMZ forward rule
    if let Some(ip) = dmz_ip {
        if !ip.is_empty() {
            forward_rules.push_str(&format!(
                "        ct state new iifname \"{}\" ip daddr {} accept\n",
                wan_iface, ip
            ));
        }
    }

    // Rebuild the nat prerouting chain
    let nft_script = format!(r#"#!/usr/sbin/nft -f
flush chain ip nat prerouting
table ip nat {{
    chain prerouting {{
        type nat hook prerouting priority -100;
{prerouting_rules}    }}
}}

delete chain inet filter port_fwd 2>/dev/null
table inet filter {{
    chain port_fwd {{
{forward_rules}    }}
}}
"#);

    let temp_path = "/tmp/hermitshell-portfwd.nft";
    std::fs::write(temp_path, &nft_script)?;
    let status = Command::new("/usr/sbin/nft")
        .args(["-f", temp_path])
        .status()?;
    if !status.success() {
        anyhow::bail!("failed to apply port forwarding rules");
    }

    // Add jump to port_fwd from forward chain (idempotent)
    let _ = Command::new("/usr/sbin/nft")
        .args(["add", "rule", "inet", "filter", "forward",
               "ct", "state", "new", "jump", "port_fwd"])
        .status();

    Ok(())
}
