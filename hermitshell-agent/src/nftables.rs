use anyhow::Result;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::Command;

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

pub fn apply_base_rules(wan_iface: &str, lan_iface: &str) -> Result<()> {
    let rules = format!(r#"#!/usr/sbin/nft -f
flush ruleset

table inet filter {{
    map device_groups {{
        type ipv4_addr : verdict;
    }}

    chain input {{
        type filter hook input priority 0; policy accept;
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

    let status = Command::new("nft")
        .args(["-f", temp_path])
        .status()?;

    if status.success() {
        println!("Applied nftables rules");
        Ok(())
    } else {
        anyhow::bail!("Failed to apply nftables rules")
    }
}

pub fn add_device_counter(ip: &str) -> Result<()> {
    validate_ip(ip)?;
    let element = format!("{{ {} }}", ip);

    // Add to TX counter set (traffic from device)
    let _ = Command::new("nft")
        .args(["add", "element", "inet", "traffic", "tx_devices", &element])
        .status()?;

    // Add to RX counter set (traffic to device)
    let _ = Command::new("nft")
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
    let tx_output = Command::new("nft")
        .args(["list", "set", "inet", "traffic", "tx_devices"])
        .output()?;
    let rx_output = Command::new("nft")
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
    let status = Command::new("nft")
        .args(["add", "element", "inet", "filter", "device_groups", &element])
        .status()?;
    if status.success() {
        println!("Added device_groups element: {} -> {}", ip, chain);
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
    let _ = Command::new("nft")
        .args(["delete", "element", "inet", "filter", "device_groups", &element])
        .status();

    // Flush conntrack entries so established connections don't bypass the block
    let _ = Command::new("conntrack")
        .args(["-D", "-s", ip])
        .status();

    Ok(())
}

/// Add /30 gateway address to LAN interface
pub fn add_gateway_address(gateway: &str, lan_iface: &str) -> Result<()> {
    validate_ip(gateway)?;
    let addr = format!("{}/30", gateway);
    let status = Command::new("ip")
        .args(["addr", "add", &addr, "dev", lan_iface])
        .status()?;
    // Ignore "already exists" errors
    if status.success() {
        println!("Added gateway address {} on {}", addr, lan_iface);
    }
    Ok(())
}


