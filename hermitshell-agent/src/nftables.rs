use anyhow::Result;
use std::collections::HashMap;
use std::process::Command;

pub fn apply_base_rules(wan_iface: &str, _lan_iface: &str) -> Result<()> {
    let rules = format!(r#"#!/usr/sbin/nft -f
flush ruleset

table inet filter {{
    chain input {{
        type filter hook input priority 0; policy accept;
    }}
    chain forward {{
        type filter hook forward priority 0; policy accept;
    }}
    chain output {{
        type filter hook output priority 0; policy accept;
    }}
}}

table ip nat {{
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
    pub packets: i64,
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
                let packets = parts[1].parse().unwrap_or(0);
                let bytes = parts[3].parse().unwrap_or(0);
                counters.insert(current_name.clone(), Counter { bytes, packets });
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
