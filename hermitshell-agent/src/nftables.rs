use anyhow::Result;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
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

/// Validate that an IPv6 string is a valid ULA address (fd00::/8).
pub fn validate_ipv6_ula(ip: &str) -> Result<()> {
    let addr: Ipv6Addr = ip.parse().map_err(|_| anyhow::anyhow!("invalid IPv6: {}", ip))?;
    let octets = addr.octets();
    if octets[0] != 0xfd {
        anyhow::bail!("IPv6 {} not in fd00::/8 ULA range", ip);
    }
    Ok(())
}

/// Validate that an IPv6 string is a valid global unicast address (2000::/3).
pub fn validate_ipv6_global(ip: &str) -> Result<()> {
    let addr: Ipv6Addr = ip.parse().map_err(|_| anyhow::anyhow!("invalid IPv6: {}", ip))?;
    let octets = addr.octets();
    // Global unicast: first 3 bits are 001 (2000::/3), i.e. first byte 0x20..0x3f
    if octets[0] < 0x20 || octets[0] > 0x3f {
        anyhow::bail!("IPv6 {} not a global unicast address (2000::/3)", ip);
    }
    Ok(())
}

/// Validate that a protocol string is "tcp" or "udp".
fn validate_protocol(protocol: &str) -> Result<()> {
    match protocol {
        "tcp" | "udp" => Ok(()),
        _ => anyhow::bail!("invalid protocol: {} (must be tcp or udp)", protocol),
    }
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
    map device_groups_v4 {{
        type ipv4_addr : verdict;
    }}

    map device_groups_v6 {{
        type ipv6_addr : verdict;
    }}

    chain input {{
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        iifname "lo" accept
        tcp dport 22 accept
        iifname "{lan_iface}" tcp dport {{ 8080, 8443 }} accept
        iifname "{lan_iface}" udp dport 67 accept
        iifname "{lan_iface}" tcp dport 53 accept
        iifname "{lan_iface}" udp dport 53 accept
        iifname "{lan_iface}" udp dport {{ 546, 547 }} accept
        icmp type echo-request accept
        icmpv6 type {{ echo-request, nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert }} accept
    }}
    chain forward {{
        type filter hook forward priority 0; policy drop;
        ct state established,related accept
        ip saddr vmap @device_groups_v4
        ip6 saddr vmap @device_groups_v6
        icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert }} accept
        ip6 saddr fe80::/10 icmpv6 type nd-router-advert drop
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
    chain port_fwd {{
    }}
}}

table ip nat {{
    chain prerouting {{
        type nat hook prerouting priority -100;
        iifname "{lan_iface}" tcp dport 443 redirect to :8443
        iifname "{lan_iface}" tcp dport 80 redirect to :8080
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
    set tx_devices_v6 {{
        type ipv6_addr
        flags dynamic
        counter
    }}
    set rx_devices_v6 {{
        type ipv6_addr
        flags dynamic
        counter
    }}

    chain count_lan {{
        type filter hook forward priority -10; policy accept;
        ip saddr @tx_devices
        ip daddr @rx_devices
        ip6 saddr @tx_devices_v6
        ip6 daddr @rx_devices_v6
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

pub fn add_device_counter_v6(ip: &str) -> Result<()> {
    validate_ipv6_ula(ip)?;
    let element = format!("{{ {} }}", ip);

    let _ = Command::new("/usr/sbin/nft")
        .args(["add", "element", "inet", "traffic", "tx_devices_v6", &element])
        .status()?;

    let _ = Command::new("/usr/sbin/nft")
        .args(["add", "element", "inet", "traffic", "rx_devices_v6", &element])
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

/// Add device to IPv4 verdict map: ip -> jump {group}_fwd
pub fn add_device_forward_rule(ip: &str, group: &str) -> Result<()> {
    validate_ip(ip)?;
    validate_group(group)?;
    let chain = format!("{}_fwd", group);
    let element = format!("{{ {} : jump {} }}", ip, chain);
    let status = Command::new("/usr/sbin/nft")
        .args(["add", "element", "inet", "filter", "device_groups_v4", &element])
        .status()?;
    if status.success() {
        debug!(ip = %ip, chain = %chain, "added device_groups_v4 element");
        Ok(())
    } else {
        anyhow::bail!("Failed to add device_groups_v4 element for {}", ip)
    }
}

/// Add device to IPv6 verdict map: ip -> jump {group}_fwd
pub fn add_device_forward_rule_v6(ip: &str, group: &str) -> Result<()> {
    validate_ipv6_ula(ip)?;
    validate_group(group)?;
    let chain = format!("{}_fwd", group);
    let element = format!("{{ {} : jump {} }}", ip, chain);
    let status = Command::new("/usr/sbin/nft")
        .args(["add", "element", "inet", "filter", "device_groups_v6", &element])
        .status()?;
    if status.success() {
        debug!(ip = %ip, chain = %chain, "added device_groups_v6 element");
        Ok(())
    } else {
        anyhow::bail!("Failed to add device_groups_v6 element for {}", ip)
    }
}

/// Remove device from IPv4 verdict map and flush conntrack entries.
pub fn remove_device_forward_rule(ip: &str) -> Result<()> {
    validate_ip(ip)?;
    let element = format!("{{ {} }}", ip);
    // Ignore errors -- element may not exist (e.g. already blocked)
    let _ = Command::new("/usr/sbin/nft")
        .args(["delete", "element", "inet", "filter", "device_groups_v4", &element])
        .status();

    // Flush conntrack entries so established connections don't bypass the block
    let _ = Command::new("/usr/sbin/conntrack")
        .args(["-D", "-s", ip])
        .status();

    Ok(())
}

/// Remove device from IPv6 verdict map.
pub fn remove_device_forward_rule_v6(ip: &str) -> Result<()> {
    validate_ipv6_ula(ip)?;
    let element = format!("{{ {} }}", ip);
    let _ = Command::new("/usr/sbin/nft")
        .args(["delete", "element", "inet", "filter", "device_groups_v6", &element])
        .status();

    Ok(())
}

/// Add /32 host route to LAN interface for a device
pub fn add_device_route(device_ip: &str, lan_iface: &str) -> Result<()> {
    validate_ip(device_ip)?;
    validate_iface(lan_iface)?;
    let route = format!("{}/32", device_ip);
    let _ = Command::new("/usr/sbin/ip")
        .args(["route", "add", &route, "dev", lan_iface])
        .status();
    debug!(route = %route, iface = lan_iface, "added device route");
    Ok(())
}

/// Add /128 host route and NDP proxy for a device on LAN interface
pub fn add_device_route_v6(device_ipv6: &str, lan_iface: &str) -> Result<()> {
    validate_ipv6_ula(device_ipv6)?;
    validate_iface(lan_iface)?;
    let route = format!("{}/128", device_ipv6);
    let _ = Command::new("/usr/sbin/ip")
        .args(["-6", "route", "add", &route, "dev", lan_iface])
        .status();
    let _ = Command::new("/usr/sbin/ip")
        .args(["-6", "neigh", "add", "proxy", device_ipv6, "dev", lan_iface])
        .status();
    debug!(route = %route, iface = lan_iface, "added device v6 route");
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

    // Web UI redirect (high ports, so container needs no privileged port binding)
    prerouting_rules.push_str(&format!(
        "        iifname \"{}\" tcp dport 443 redirect to :8443\n",
        lan_iface
    ));
    prerouting_rules.push_str(&format!(
        "        iifname \"{}\" tcp dport 80 redirect to :8080\n",
        lan_iface
    ));

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

    // Rebuild the nat prerouting chain (flush and re-add rules)
    let mut nft_commands = Vec::new();
    nft_commands.push("flush chain ip nat prerouting".to_string());
    for line in prerouting_rules.lines() {
        let rule = line.trim();
        if !rule.is_empty() {
            nft_commands.push(format!("add rule ip nat prerouting {}", rule));
        }
    }

    // Delete and recreate port_fwd chain
    nft_commands.push("flush chain inet filter port_fwd".to_string());
    for line in forward_rules.lines() {
        let rule = line.trim();
        if !rule.is_empty() {
            nft_commands.push(format!("add rule inet filter port_fwd {}", rule));
        }
    }

    let nft_script = nft_commands.join("\n") + "\n";

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

/// Add an IPv6 pinhole: allow inbound traffic to a specific global IPv6 address and port range.
pub fn add_ipv6_pinhole(ipv6_global: &str, protocol: &str, port_start: u16, port_end: u16) -> Result<()> {
    validate_ipv6_global(ipv6_global)?;
    validate_protocol(protocol)?;

    let port_spec = if port_start == port_end {
        format!("{}", port_start)
    } else {
        format!("{}-{}", port_start, port_end)
    };

    let rule = format!(
        "ip6 daddr {} {} dport {} accept comment \"ipv6-pinhole\"",
        ipv6_global, protocol, port_spec
    );

    let status = Command::new("/usr/sbin/nft")
        .args(["add", "rule", "inet", "filter", "forward"])
        .args(rule.split_whitespace().collect::<Vec<_>>())
        .status()?;

    if status.success() {
        info!(ipv6 = %ipv6_global, proto = %protocol, ports = %port_spec, "added IPv6 pinhole");
        Ok(())
    } else {
        anyhow::bail!("failed to add IPv6 pinhole rule")
    }
}

/// Remove IPv6 pinhole rules for a specific global IPv6 address and port range.
pub fn remove_ipv6_pinhole(ipv6_global: &str, protocol: &str, port_start: u16, port_end: u16) -> Result<()> {
    validate_ipv6_global(ipv6_global)?;
    validate_protocol(protocol)?;

    let port_spec = if port_start == port_end {
        format!("{}", port_start)
    } else {
        format!("{}-{}", port_start, port_end)
    };

    let search = format!("ip6 daddr {} {} dport {} accept", ipv6_global, protocol, port_spec);

    // List rules with handles
    let output = Command::new("/usr/sbin/nft")
        .args(["-a", "list", "chain", "inet", "filter", "forward"])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.contains(&search) {
            // Extract handle number from "# handle N"
            if let Some(handle) = trimmed.rsplit("# handle ").next().and_then(|s| s.trim().parse::<u64>().ok()) {
                let status = Command::new("/usr/sbin/nft")
                    .args(["delete", "rule", "inet", "filter", "forward", "handle", &handle.to_string()])
                    .status()?;
                if status.success() {
                    info!(ipv6 = %ipv6_global, proto = %protocol, ports = %port_spec, handle = handle, "removed IPv6 pinhole");
                }
            }
        }
    }

    Ok(())
}
