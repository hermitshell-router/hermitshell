use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use snmp2::{AsyncSession, Oid, Value};
use tokio::time::{Duration, interval};
use tracing::{info, warn};

use crate::db::Db;

/// Standard OIDs for MAC table discovery (BRIDGE-MIB + IF-MIB).
const DOT1D_TP_FDB_PORT: &[u64] = &[1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 2];
const DOT1D_BASE_PORT_IFINDEX: &[u64] = &[1, 3, 6, 1, 2, 1, 17, 1, 4, 1, 2];
const IF_NAME: &[u64] = &[1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1];
const SYS_DESCR: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];

/// A discovered MAC-to-port mapping.
#[derive(Debug)]
struct MacEntry {
    mac: String,
    port_name: String,
}

/// Test connectivity by reading sysDescr.0.
pub async fn test_connectivity(host: &str, community: &[u8]) -> Result<String> {
    let addr = format!("{}:161", host);
    let oid = Oid::from(SYS_DESCR).context("invalid OID")?;
    let mut sess = AsyncSession::new_v2c(&addr, community, 0)
        .await
        .context("SNMP session failed")?;
    let response = sess.get(&oid).await.context("SNMP GET sysDescr failed")?;
    for (_, val) in response.varbinds {
        if let Value::OctetString(bytes) = val {
            return Ok(String::from_utf8_lossy(bytes).to_string());
        }
    }
    Ok("(no sysDescr)".to_string())
}

/// Collect OID components into a Vec<u64>, or return None if iter() fails.
fn oid_components(oid: &Oid<'_>) -> Option<Vec<u64>> {
    Some(oid.iter()?.collect())
}

/// Check whether `oid` is under the given `prefix` subtree and return the
/// suffix components (the part after the prefix).
fn oid_suffix(oid: &Oid<'_>, prefix: &Oid<'_>) -> Option<Vec<u64>> {
    if !oid.starts_with(prefix) {
        return None;
    }
    let full = oid_components(oid)?;
    let prefix_len = oid_components(prefix)?.len();
    if full.len() <= prefix_len {
        return None;
    }
    Some(full[prefix_len..].to_vec())
}

/// Result of processing a single GETNEXT response within a walk.
enum WalkStep {
    /// Got a valid entry: (suffix components, next cursor OID).
    Entry(Vec<u64>, WalkValue, Oid<'static>),
    /// Reached end of subtree or MIB view.
    Done,
    /// No varbinds in response.
    Empty,
}

/// Owned copy of the Value variants we care about during walks.
enum WalkValue {
    Integer(i64),
    OctetString(Vec<u8>),
    Other,
}

/// Walk an SNMP subtree using GETNEXT, calling `callback` for each varbind
/// that falls under `root`. Stops when the response leaves the subtree or
/// returns EndOfMibView.
async fn walk<F>(
    sess: &mut AsyncSession,
    root: &Oid<'static>,
    mut callback: F,
) -> Result<()>
where
    F: FnMut(Vec<u64>, &WalkValue),
{
    let mut cursor = root.clone();

    loop {
        // Process the response in a limited scope so the borrow on sess is
        // released before the next getnext call.
        let step = {
            let response = match sess.getnext(&cursor).await {
                Ok(r) => r,
                Err(_) => break,
            };

            let mut result = WalkStep::Empty;
            for (oid, val) in response.varbinds {
                if matches!(val, Value::EndOfMibView) {
                    result = WalkStep::Done;
                    break;
                }
                let suffix = match oid_suffix(&oid, root) {
                    Some(s) => s,
                    None => {
                        result = WalkStep::Done;
                        break;
                    }
                };
                // Copy the value into an owned form so we can drop `response`.
                let owned_val = match val {
                    Value::Integer(n) => WalkValue::Integer(n),
                    Value::OctetString(bytes) => WalkValue::OctetString(bytes.to_vec()),
                    _ => WalkValue::Other,
                };
                result = WalkStep::Entry(suffix, owned_val, oid.to_owned());
                break; // GETNEXT returns one varbind per call
            }
            result
        };

        match step {
            WalkStep::Entry(suffix, val, next_oid) => {
                callback(suffix, &val);
                cursor = next_oid;
            }
            WalkStep::Done | WalkStep::Empty => break,
        }
    }
    Ok(())
}

/// Walk the BRIDGE-MIB forwarding table and IF-MIB to map MACs to port names.
async fn poll_mac_table(host: &str, community: &[u8]) -> Result<Vec<MacEntry>> {
    let addr = format!("{}:161", host);

    let mut sess = AsyncSession::new_v2c(&addr, community, 0)
        .await
        .context("SNMP session failed")?;

    // Step 1: Walk dot1dTpFdbPort to get MAC -> bridge port number.
    // The trailing 6 suffix components of each OID are the MAC address bytes.
    let fdb_oid = Oid::from(DOT1D_TP_FDB_PORT).context("invalid OID")?;
    let mut mac_to_bridge_port: Vec<(String, u64)> = Vec::new();

    walk(&mut sess, &fdb_oid, |suffix, val| {
        if suffix.len() >= 6 {
            let mac = format!(
                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                suffix[0], suffix[1], suffix[2],
                suffix[3], suffix[4], suffix[5]
            );
            if let WalkValue::Integer(port_num) = val {
                mac_to_bridge_port.push((mac, *port_num as u64));
            }
        }
    })
    .await?;

    if mac_to_bridge_port.is_empty() {
        return Ok(Vec::new());
    }

    // Step 2: Walk dot1dBasePortIfIndex to get bridge port -> ifIndex.
    let bp_oid = Oid::from(DOT1D_BASE_PORT_IFINDEX).context("invalid OID")?;
    let mut bridge_port_to_ifindex: HashMap<u64, u64> = HashMap::new();

    walk(&mut sess, &bp_oid, |suffix, val| {
        if let (Some(&bridge_port), WalkValue::Integer(ifindex)) = (suffix.first(), val) {
            bridge_port_to_ifindex.insert(bridge_port, *ifindex as u64);
        }
    })
    .await?;

    // Step 3: Walk ifName to get ifIndex -> port name.
    let ifname_oid = Oid::from(IF_NAME).context("invalid OID")?;
    let mut ifindex_to_name: HashMap<u64, String> = HashMap::new();

    walk(&mut sess, &ifname_oid, |suffix, val| {
        if let (Some(&ifindex), WalkValue::OctetString(bytes)) = (suffix.first(), val) {
            let name = String::from_utf8_lossy(bytes).to_string();
            ifindex_to_name.insert(ifindex, name);
        }
    })
    .await?;

    // Combine: MAC -> bridge port -> ifIndex -> port name.
    let entries = mac_to_bridge_port
        .into_iter()
        .filter_map(|(mac, bp)| {
            let ifindex = bridge_port_to_ifindex.get(&bp)?;
            let port_name = ifindex_to_name.get(ifindex)?;
            Some(MacEntry {
                mac,
                port_name: port_name.clone(),
            })
        })
        .collect();

    Ok(entries)
}

/// Background polling loop — queries switches via SNMP for MAC table data
/// and correlates entries with known devices.
pub async fn run(db: Arc<Mutex<Db>>) {
    let mut poll_interval = interval(Duration::from_secs(60));

    loop {
        poll_interval.tick().await;

        // Skip if VLAN mode is not enabled
        let vlan_enabled = {
            let db = db.lock().unwrap();
            db.get_config("vlan_mode").ok().flatten().as_deref() == Some("enabled")
        };
        if !vlan_enabled {
            continue;
        }

        let switches = {
            let db = db.lock().unwrap();
            db.list_snmp_switches().unwrap_or_default()
        };

        for sw in &switches {
            if !sw.enabled {
                continue;
            }

            // Decrypt community string
            let community = {
                let db = db.lock().unwrap();
                match db.get_snmp_switch_community(&sw.id) {
                    Ok(enc) => {
                        let secret = db
                            .get_config("session_secret")
                            .ok()
                            .flatten()
                            .unwrap_or_default();
                        if secret.is_empty() || !crate::crypto::is_encrypted(&enc) {
                            enc
                        } else {
                            match crate::crypto::decrypt_password(&enc, &secret) {
                                Ok(p) => p,
                                Err(e) => {
                                    warn!(switch = %sw.name, error = %e, "failed to decrypt community");
                                    continue;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!(switch = %sw.name, error = %e, "failed to get community");
                        continue;
                    }
                }
            };

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            match poll_mac_table(&sw.host, community.as_bytes()).await {
                Ok(entries) => {
                    let db = db.lock().unwrap();
                    db.update_snmp_switch_status(&sw.id, "connected", now).ok();

                    for entry in &entries {
                        if let Ok(Some(_)) = db.get_device(&entry.mac) {
                            let port_display =
                                format!("{} on {}", entry.port_name, sw.name);
                            let _ =
                                db.update_device_switch_port(&entry.mac, &port_display);
                        }
                    }

                    info!(switch = %sw.name, mac_count = entries.len(), "SNMP poll complete");
                }
                Err(e) => {
                    warn!(switch = %sw.name, error = %e, "SNMP poll failed");
                    let db = db.lock().unwrap();
                    db.update_snmp_switch_status(&sw.id, "error", now).ok();
                }
            }
        }
    }
}
