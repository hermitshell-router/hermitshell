use anyhow::Result;
use std::process::Command;
use tracing::{info, warn};

use crate::paths;
use hermitshell_common::VlanGroupConfig;

/// Build the `ip` commands needed to create VLAN subinterfaces.
pub fn build_vlan_create_commands(lan_iface: &str, configs: &[VlanGroupConfig]) -> Vec<String> {
    let mut cmds = Vec::new();
    for cfg in configs {
        let sub = format!("{}.{}", lan_iface, cfg.vlan_id);
        cmds.push(format!(
            "link add link {} name {} type vlan id {}",
            lan_iface, sub, cfg.vlan_id
        ));
        cmds.push(format!("addr add {}/24 dev {}", cfg.gateway, sub));
        cmds.push(format!("link set {} up", sub));
    }
    cmds
}

/// Build the `ip` commands needed to remove VLAN subinterfaces.
pub fn build_vlan_teardown_commands(lan_iface: &str, vlan_ids: &[u16]) -> Vec<String> {
    vlan_ids
        .iter()
        .map(|id| format!("link del {}.{}", lan_iface, id))
        .collect()
}

/// Create all VLAN subinterfaces on the LAN interface.
pub fn create_vlan_interfaces(lan_iface: &str, configs: &[VlanGroupConfig]) -> Result<()> {
    for cmd_args in build_vlan_create_commands(lan_iface, configs) {
        let args: Vec<&str> = cmd_args.split_whitespace().collect();
        let status = Command::new(paths::ip()).args(&args).status()?;
        if !status.success() {
            warn!(cmd = %cmd_args, "ip command failed (may already exist)");
        }
    }
    info!(count = configs.len(), "created VLAN subinterfaces");
    Ok(())
}

/// Remove all VLAN subinterfaces.
pub fn teardown_vlan_interfaces(lan_iface: &str, vlan_ids: &[u16]) -> Result<()> {
    for cmd_args in build_vlan_teardown_commands(lan_iface, vlan_ids) {
        let args: Vec<&str> = cmd_args.split_whitespace().collect();
        let _ = Command::new(paths::ip()).args(&args).status();
    }
    info!(count = vlan_ids.len(), "removed VLAN subinterfaces");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_create_commands() {
        let configs = vec![VlanGroupConfig {
            group_name: "trusted".into(),
            vlan_id: 10,
            subnet: "10.0.10.0/24".into(),
            gateway: "10.0.10.1".into(),
        }];
        let cmds = build_vlan_create_commands("eth2", &configs);
        assert_eq!(cmds.len(), 3); // link add, addr add, link set up
        assert!(cmds[0].contains("type vlan id 10"));
        assert!(cmds[1].contains("10.0.10.1/24"));
        assert!(cmds[2].contains("eth2.10 up"));
    }

    #[test]
    fn test_build_teardown_commands() {
        let cmds = build_vlan_teardown_commands("eth2", &[10, 20, 50]);
        assert_eq!(cmds.len(), 3);
        assert!(cmds[0].contains("del eth2.10"));
    }
}
