use anyhow::Result;
use std::process::Command;
use tracing::{error, info, warn};

use crate::nftables;

/// Start dhclient for prefix delegation on WAN interface.
/// Returns the delegated prefix if obtained, or None.
///
/// The `-1` flag makes dhclient try once and exit. Callers should periodically
/// re-invoke this function to renew the delegated prefix before it expires (H17).
pub fn request_prefix(wan_iface: &str) -> Result<Option<String>> {
    nftables::validate_iface(wan_iface)?;

    let lease_path = format!("/var/lib/dhcp/dhclient6.{}.leases", wan_iface);

    // M13: Delete stale lease file before invoking dhclient
    let _ = std::fs::remove_file(&lease_path);

    // H16: Specify lease file path explicitly so dhclient writes where we read
    let status = Command::new("/sbin/dhclient")
        .args(["-6", "-P", "-1", "-lf", &lease_path, wan_iface])
        .status();

    // M13: Check exit status
    match status {
        Ok(s) if s.success() => parse_delegated_prefix(&lease_path),
        Ok(s) => {
            warn!(exit_code = ?s.code(), "dhclient failed");
            Ok(None)
        }
        Err(e) => {
            error!(error = %e, "failed to run dhclient");
            Ok(None)
        }
    }
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
