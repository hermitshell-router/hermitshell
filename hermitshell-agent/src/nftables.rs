use anyhow::Result;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::Command;

const VALID_GROUPS: &[&str] = &["quarantine", "trusted", "iot", "guest", "servers"];

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
    chain input {{
        type filter hook input priority 0; policy accept;
    }}
    chain forward {{
        type filter hook forward priority 0; policy drop;
        ct state established,related accept
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
    chain count_lan {{
        type filter hook forward priority -10; policy accept;
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
    // Add TX counter (traffic from device)
    let _ = Command::new("nft")
        .args(["add", "counter", "inet", "traffic", &format!("dev_{}_tx", ip.replace('.', "_"))])
        .status()?;

    // Add RX counter (traffic to device)
    let _ = Command::new("nft")
        .args(["add", "counter", "inet", "traffic", &format!("dev_{}_rx", ip.replace('.', "_"))])
        .status()?;

    // Add counting rules
    let _ = Command::new("nft")
        .args([
            "add", "rule", "inet", "traffic", "count_lan",
            "ip", "saddr", ip, "counter", "name", &format!("dev_{}_tx", ip.replace('.', "_"))
        ])
        .status()?;

    let _ = Command::new("nft")
        .args([
            "add", "rule", "inet", "traffic", "count_lan",
            "ip", "daddr", ip, "counter", "name", &format!("dev_{}_rx", ip.replace('.', "_"))
        ])
        .status()?;

    Ok(())
}

#[derive(Debug, Default)]
pub struct Counter {
    pub bytes: i64,
}

/// Get all counters, returns map of counter_name -> Counter
pub fn get_counters() -> Result<HashMap<String, Counter>> {
    let output = Command::new("nft")
        .args(["list", "counters"])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut counters = HashMap::new();
    let mut current_name = String::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("counter inet traffic") {
            // Extract counter name: "counter inet traffic dev_10_0_0_100_tx {"
            if let Some(name) = line.split_whitespace().nth(3) {
                current_name = name.trim_end_matches(" {").to_string();
            }
        } else if line.starts_with("packets") && !current_name.is_empty() {
            // Parse: "packets 123 bytes 45678"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let bytes = parts[3].parse().unwrap_or(0);
                counters.insert(current_name.clone(), Counter { bytes });
            }
            current_name.clear();
        }
    }

    Ok(counters)
}

/// Get rx/tx bytes for a specific IP
pub fn get_device_counters(ip: &str) -> Result<(i64, i64)> {
    let counters = get_counters()?;
    let ip_key = ip.replace('.', "_");
    let rx = counters.get(&format!("dev_{}_rx", ip_key)).map(|c| c.bytes).unwrap_or(0);
    let tx = counters.get(&format!("dev_{}_tx", ip_key)).map(|c| c.bytes).unwrap_or(0);
    Ok((rx, tx))
}

/// Add nftables forward rule: ip saddr {ip} jump {group}_fwd
pub fn add_device_forward_rule(ip: &str, group: &str) -> Result<()> {
    validate_ip(ip)?;
    validate_group(group)?;
    let chain = format!("{}_fwd", group);
    let status = Command::new("nft")
        .args(["add", "rule", "inet", "filter", "forward",
               "ip", "saddr", ip, "jump", &chain])
        .status()?;
    if status.success() {
        println!("Added forward rule: {} -> {}", ip, chain);
        Ok(())
    } else {
        anyhow::bail!("Failed to add forward rule for {}", ip)
    }
}

/// Remove nftables forward rule for device IP and flush its conntrack entries.
/// Lists rules with handles, finds the one matching the IP, deletes it.
pub fn remove_device_forward_rule(ip: &str) -> Result<()> {
    validate_ip(ip)?;
    let output = Command::new("nft")
        .args(["-a", "list", "chain", "inet", "filter", "forward"])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        if line.contains(&format!("ip saddr {}", ip)) {
            // Extract handle number from "# handle N"
            if let Some(handle) = line.rsplit("# handle ").next() {
                let handle = handle.trim();
                Command::new("nft")
                    .args(["delete", "rule", "inet", "filter", "forward", "handle", handle])
                    .status()?;
                println!("Removed forward rule for {} (handle {})", ip, handle);
            }
        }
    }

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


