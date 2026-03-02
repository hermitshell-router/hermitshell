use regex::Regex;

use super::MacTableEntry;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VendorProfile {
    pub name: String,
    pub commands: VendorCommands,
    pub prompt_pattern: String,
    pub config_prompt_pattern: String,
    pub mac_table_regex: String,
    pub mac_table_vlan_group: usize,
    pub mac_table_mac_group: usize,
    pub mac_table_port_group: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VendorCommands {
    pub create_vlan: String,
    pub set_access_port: String,
    pub set_trunk_port: String,
    pub get_mac_table: String,
    pub get_ports: String,
    pub save_config: String,
    pub enter_config: String,
    pub exit_config: String,
}

impl VendorProfile {
    pub fn render_create_vlan(&self, vlan_id: u16, name: &str) -> String {
        self.commands
            .create_vlan
            .replace("{vlan_id}", &vlan_id.to_string())
            .replace("{name}", name)
    }

    pub fn render_set_access_port(&self, port: &str, vlan_id: u16) -> String {
        self.commands
            .set_access_port
            .replace("{port}", port)
            .replace("{vlan_id}", &vlan_id.to_string())
    }

    pub fn render_set_trunk_port(&self, port: &str, allowed_vlans: &[u16]) -> String {
        let vlans = allowed_vlans
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(",");
        self.commands
            .set_trunk_port
            .replace("{port}", port)
            .replace("{vlans}", &vlans)
    }

    pub fn parse_mac_table(&self, output: &str) -> Vec<MacTableEntry> {
        let re = match Regex::new(&self.mac_table_regex) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        let mut entries = Vec::new();
        for caps in re.captures_iter(output) {
            let vlan_str = match caps.get(self.mac_table_vlan_group) {
                Some(m) => m.as_str(),
                None => continue,
            };
            let vlan_id: u16 = match vlan_str.parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let mac = match caps.get(self.mac_table_mac_group) {
                Some(m) => m.as_str().to_string(),
                None => continue,
            };
            let port = match caps.get(self.mac_table_port_group) {
                Some(m) => m.as_str().to_string(),
                None => continue,
            };
            entries.push(MacTableEntry { mac, vlan_id, port });
        }
        entries
    }
}

fn cisco_ios_profile() -> VendorProfile {
    VendorProfile {
        name: "cisco_ios".to_string(),
        commands: VendorCommands {
            create_vlan: "vlan {vlan_id}\n name {name}".to_string(),
            set_access_port:
                "interface {port}\n switchport mode access\n switchport access vlan {vlan_id}"
                    .to_string(),
            set_trunk_port:
                "interface {port}\n switchport mode trunk\n switchport trunk allowed vlan {vlans}"
                    .to_string(),
            get_mac_table: "show mac address-table".to_string(),
            get_ports: "show interfaces status".to_string(),
            save_config: "write memory".to_string(),
            enter_config: "configure terminal".to_string(),
            exit_config: "end".to_string(),
        },
        prompt_pattern: r"[#>]\s*$".to_string(),
        config_prompt_pattern: r"\(config[^)]*\)#\s*$".to_string(),
        mac_table_regex: r"\s+(\d+)\s+([0-9a-fA-F.:-]+)\s+\S+\s+(\S+)".to_string(),
        mac_table_vlan_group: 1,
        mac_table_mac_group: 2,
        mac_table_port_group: 3,
    }
}

fn tplink_t_profile() -> VendorProfile {
    VendorProfile {
        name: "tplink_t".to_string(),
        commands: VendorCommands {
            create_vlan: "vlan {vlan_id}\n name {name}\n exit".to_string(),
            set_access_port:
                "interface {port}\n switchport mode access\n switchport access vlan {vlan_id}\n exit"
                    .to_string(),
            set_trunk_port:
                "interface {port}\n switchport mode trunk\n switchport trunk allowed vlan {vlans}\n exit"
                    .to_string(),
            get_mac_table: "show mac address-table".to_string(),
            get_ports: "show interface status".to_string(),
            save_config: "copy running-config startup-config".to_string(),
            enter_config: "configure".to_string(),
            exit_config: "end".to_string(),
        },
        prompt_pattern: r"[#>]\s*$".to_string(),
        config_prompt_pattern: r"\(config[^)]*\)#\s*$".to_string(),
        mac_table_regex: r"\s+([0-9a-fA-F:-]+)\s+(\d+)\s+\S+\s+(\S+)".to_string(),
        mac_table_vlan_group: 2,
        mac_table_mac_group: 1,
        mac_table_port_group: 3,
    }
}

fn netgear_prosafe_profile() -> VendorProfile {
    VendorProfile {
        name: "netgear_prosafe".to_string(),
        commands: VendorCommands {
            create_vlan:
                "vlan database\n vlan {vlan_id}\n vlan name {vlan_id} {name}\n exit".to_string(),
            set_access_port:
                "interface {port}\n vlan pvid {vlan_id}\n vlan participation include {vlan_id}\n exit"
                    .to_string(),
            set_trunk_port:
                "interface {port}\n vlan participation include {vlans}\n vlan tagging {vlans}\n exit"
                    .to_string(),
            get_mac_table: "show mac-addr-table".to_string(),
            get_ports: "show interfaces status all".to_string(),
            save_config: "write memory".to_string(),
            enter_config: "configure".to_string(),
            exit_config: "exit".to_string(),
        },
        prompt_pattern: r"[#>]\s*$".to_string(),
        config_prompt_pattern: r"\(Config[^)]*\)#\s*$".to_string(),
        mac_table_regex: r"(\d+)\s+([0-9A-F:]+)\s+\S+\s+(\S+)".to_string(),
        mac_table_vlan_group: 1,
        mac_table_mac_group: 2,
        mac_table_port_group: 3,
    }
}

pub fn built_in_profile(name: &str) -> Option<VendorProfile> {
    match name {
        "cisco_ios" => Some(cisco_ios_profile()),
        "tplink_t" => Some(tplink_t_profile()),
        "netgear_prosafe" => Some(netgear_prosafe_profile()),
        _ => None,
    }
}

pub fn list_built_in_profiles() -> Vec<&'static str> {
    vec!["cisco_ios", "tplink_t", "netgear_prosafe"]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cisco_ios_profile_exists() {
        let profile = built_in_profile("cisco_ios").unwrap();
        assert!(profile.commands.create_vlan.contains("{vlan_id}"));
        assert!(profile.commands.set_access_port.contains("{port}"));
    }

    #[test]
    fn test_render_create_vlan() {
        let profile = built_in_profile("cisco_ios").unwrap();
        let rendered = profile.render_create_vlan(10, "trusted");
        assert!(rendered.contains("vlan 10"));
        assert!(rendered.contains("name trusted"));
    }

    #[test]
    fn test_render_set_access_port() {
        let profile = built_in_profile("cisco_ios").unwrap();
        let rendered = profile.render_set_access_port("Gi0/1", 10);
        assert!(rendered.contains("interface Gi0/1"));
        assert!(rendered.contains("switchport access vlan 10"));
    }

    #[test]
    fn test_render_set_trunk_port() {
        let profile = built_in_profile("cisco_ios").unwrap();
        let rendered = profile.render_set_trunk_port("Gi0/1", &[10, 20, 30]);
        assert!(rendered.contains("interface Gi0/1"));
        assert!(rendered.contains("switchport trunk allowed vlan 10,20,30"));
    }

    #[test]
    fn test_parse_cisco_mac_table() {
        let output =
            "  10    001a.2b3c.4d5e    DYNAMIC     Gi0/1\n  20    aabb.ccdd.eeff    DYNAMIC     Gi0/2\n";
        let profile = built_in_profile("cisco_ios").unwrap();
        let entries = profile.parse_mac_table(output);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].vlan_id, 10);
        assert_eq!(entries[0].mac, "001a.2b3c.4d5e");
        assert_eq!(entries[0].port, "Gi0/1");
        assert_eq!(entries[1].vlan_id, 20);
        assert_eq!(entries[1].port, "Gi0/2");
    }

    #[test]
    fn test_parse_tplink_mac_table() {
        let output = "  aa:bb:cc:dd:ee:ff    10    Learned   gi1/0/1\n";
        let profile = built_in_profile("tplink_t").unwrap();
        let entries = profile.parse_mac_table(output);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(entries[0].vlan_id, 10);
        assert_eq!(entries[0].port, "gi1/0/1");
    }

    #[test]
    fn test_unknown_profile() {
        assert!(built_in_profile("nonexistent").is_none());
    }

    #[test]
    fn test_list_built_in_profiles() {
        let profiles = list_built_in_profiles();
        assert!(profiles.contains(&"cisco_ios"));
        assert!(profiles.contains(&"tplink_t"));
        assert!(profiles.contains(&"netgear_prosafe"));
    }
}
