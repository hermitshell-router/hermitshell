use anyhow::Result;
use std::process::Command;
use tracing::info;

use crate::nftables;

/// Start dhclient for prefix delegation on WAN interface.
/// Returns the delegated prefix if obtained, or None.
pub fn request_prefix(wan_iface: &str) -> Result<Option<String>> {
    nftables::validate_iface(wan_iface)?;

    // Start dhclient for prefix delegation (-P flag)
    // -1 = try once and exit
    let _ = Command::new("/sbin/dhclient")
        .args(["-6", "-P", "-1", wan_iface])
        .status();

    // Parse lease file for delegated prefix
    let lease_path = format!("/var/lib/dhcp/dhclient6.{}.leases", wan_iface);
    parse_delegated_prefix(&lease_path)
}

fn parse_delegated_prefix(lease_path: &str) -> Result<Option<String>> {
    let content = match std::fs::read_to_string(lease_path) {
        Ok(c) => c,
        Err(_) => return Ok(None),
    };

    // Look for "iaprefix" line in the most recent lease
    for line in content.lines().rev() {
        let trimmed = line.trim();
        if trimmed.starts_with("iaprefix") {
            // Format: "iaprefix 2001:db8::/48 {"
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                let prefix = parts[1].to_string();
                info!(prefix = %prefix, "obtained delegated prefix");
                return Ok(Some(prefix));
            }
        }
    }

    Ok(None)
}
