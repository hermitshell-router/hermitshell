use anyhow::Result;
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
