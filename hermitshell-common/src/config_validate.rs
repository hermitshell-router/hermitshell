use crate::*;

#[derive(Debug)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

impl HermitConfig {
    /// Validate the config for structural correctness.
    /// Returns a list of validation errors (empty = valid).
    pub fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        self.validate_network(&mut errors);
        self.validate_dns(&mut errors);
        self.validate_firewall(&mut errors);
        self.validate_wireguard(&mut errors);
        self.validate_devices(&mut errors);
        self.validate_qos(&mut errors);
        self.validate_tls(&mut errors);
        self.validate_wifi(&mut errors);
        errors
    }

    fn validate_network(&self, errors: &mut Vec<ValidationError>) {
        if let Some(ref iface) = self.network.wan_interface {
            if !is_valid_iface(iface) {
                errors.push(ValidationError {
                    field: "network.wan_interface".into(),
                    message: format!("invalid interface name: {}", iface),
                });
            }
        }
        if let Some(ref iface) = self.network.lan_interface {
            if !is_valid_iface(iface) {
                errors.push(ValidationError {
                    field: "network.lan_interface".into(),
                    message: format!("invalid interface name: {}", iface),
                });
            }
        }
        match self.network.wan.mode.as_str() {
            "dhcp" | "static" | "pppoe" => {}
            other => errors.push(ValidationError {
                field: "network.wan.mode".into(),
                message: format!("invalid WAN mode: {} (expected dhcp, static, or pppoe)", other),
            }),
        }
    }

    fn validate_dns(&self, errors: &mut Vec<ValidationError>) {
        for (i, bl) in self.dns.blocklists.iter().enumerate() {
            if bl.name.is_empty() || bl.name.len() > 128 {
                errors.push(ValidationError {
                    field: format!("dns.blocklists[{}].name", i),
                    message: "name must be 1-128 characters".into(),
                });
            }
            match bl.tag.as_str() {
                "ads" | "custom" | "strict" => {}
                other => errors.push(ValidationError {
                    field: format!("dns.blocklists[{}].tag", i),
                    message: format!("invalid tag: {} (expected ads, custom, or strict)", other),
                }),
            }
        }
        for (i, fz) in self.dns.forward_zones.iter().enumerate() {
            if fz.domain.is_empty() {
                errors.push(ValidationError {
                    field: format!("dns.forward_zones[{}].domain", i),
                    message: "domain is required".into(),
                });
            }
            if fz.forward_to.parse::<std::net::IpAddr>().is_err() {
                errors.push(ValidationError {
                    field: format!("dns.forward_zones[{}].forward_to", i),
                    message: format!("invalid IP address: {}", fz.forward_to),
                });
            }
        }
        for (i, cr) in self.dns.custom_records.iter().enumerate() {
            match cr.record_type.as_str() {
                "A" | "AAAA" | "CNAME" | "MX" | "TXT" => {}
                other => errors.push(ValidationError {
                    field: format!("dns.custom_records[{}].type", i),
                    message: format!("invalid record type: {}", other),
                }),
            }
        }
    }

    fn validate_firewall(&self, errors: &mut Vec<ValidationError>) {
        if let Some(ref dmz) = self.firewall.dmz_host {
            if dmz.parse::<std::net::Ipv4Addr>().is_err() {
                errors.push(ValidationError {
                    field: "firewall.dmz_host".into(),
                    message: format!("invalid IPv4 address: {}", dmz),
                });
            }
        }
        for (i, pf) in self.firewall.port_forwards.iter().enumerate() {
            match pf.protocol.as_str() {
                "tcp" | "udp" | "both" => {}
                other => errors.push(ValidationError {
                    field: format!("firewall.port_forwards[{}].protocol", i),
                    message: format!("invalid protocol: {}", other),
                }),
            }
            if pf.internal_ip.parse::<std::net::Ipv4Addr>().is_err() {
                errors.push(ValidationError {
                    field: format!("firewall.port_forwards[{}].internal_ip", i),
                    message: format!("invalid IPv4 address: {}", pf.internal_ip),
                });
            }
            if pf.external_port == 0 {
                errors.push(ValidationError {
                    field: format!("firewall.port_forwards[{}].external_port", i),
                    message: "external_port must be > 0".into(),
                });
            }
        }
        for (i, ph) in self.firewall.ipv6_pinholes.iter().enumerate() {
            if !is_valid_mac(&ph.device) {
                errors.push(ValidationError {
                    field: format!("firewall.ipv6_pinholes[{}].device", i),
                    message: format!("invalid MAC address: {}", ph.device),
                });
            }
            match ph.protocol.as_str() {
                "tcp" | "udp" => {}
                other => errors.push(ValidationError {
                    field: format!("firewall.ipv6_pinholes[{}].protocol", i),
                    message: format!("invalid protocol: {} (expected tcp or udp)", other),
                }),
            }
        }
    }

    fn validate_wireguard(&self, errors: &mut Vec<ValidationError>) {
        for (i, peer) in self.wireguard.peers.iter().enumerate() {
            if peer.name.is_empty() || peer.name.len() > 64 {
                errors.push(ValidationError {
                    field: format!("wireguard.peers[{}].name", i),
                    message: "name must be 1-64 characters".into(),
                });
            }
            if peer.public_key.is_empty() {
                errors.push(ValidationError {
                    field: format!("wireguard.peers[{}].public_key", i),
                    message: "public_key is required".into(),
                });
            }
            match peer.device_group.as_str() {
                "trusted" | "iot" | "guest" | "servers" | "quarantine" => {}
                other => errors.push(ValidationError {
                    field: format!("wireguard.peers[{}].device_group", i),
                    message: format!("invalid group: {}", other),
                }),
            }
        }
    }

    fn validate_devices(&self, errors: &mut Vec<ValidationError>) {
        for (i, dev) in self.devices.iter().enumerate() {
            if !is_valid_mac(&dev.mac) {
                errors.push(ValidationError {
                    field: format!("devices[{}].mac", i),
                    message: format!("invalid MAC address: {}", dev.mac),
                });
            }
            match dev.group.as_str() {
                "trusted" | "iot" | "guest" | "servers" | "quarantine" => {}
                other => errors.push(ValidationError {
                    field: format!("devices[{}].group", i),
                    message: format!("invalid group: {}", other),
                }),
            }
        }
    }

    fn validate_qos(&self, errors: &mut Vec<ValidationError>) {
        if self.qos.enabled && (self.qos.upload_mbps == 0 || self.qos.download_mbps == 0) {
            errors.push(ValidationError {
                field: "qos".into(),
                message: "upload_mbps and download_mbps must be > 0 when QoS is enabled".into(),
            });
        }
    }

    fn validate_tls(&self, errors: &mut Vec<ValidationError>) {
        match self.tls.mode.as_str() {
            "self_signed" | "custom" | "tailscale" | "acme_dns01" => {}
            other => errors.push(ValidationError {
                field: "tls.mode".into(),
                message: format!("invalid TLS mode: {} (expected self_signed, custom, tailscale, or acme_dns01)", other),
            }),
        }
    }

    fn validate_wifi(&self, errors: &mut Vec<ValidationError>) {
        for (i, p) in self.wifi.providers.iter().enumerate() {
            if p.name.is_empty() || p.name.len() > 64 {
                errors.push(ValidationError {
                    field: format!("wifi.providers[{}].name", i),
                    message: "name must be 1-64 characters".into(),
                });
            }
            match p.provider_type.as_str() {
                "eap_standalone" | "unifi" => {}
                other => errors.push(ValidationError {
                    field: format!("wifi.providers[{}].type", i),
                    message: format!("invalid provider type: {}", other),
                }),
            }
        }
    }
}

/// Basic interface name validation: alphanumeric, dash, dot, underscore, 1-15 chars.
pub fn is_valid_iface(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
}

/// Basic MAC address validation: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX.
pub fn is_valid_mac(mac: &str) -> bool {
    let parts: Vec<&str> = if mac.contains(':') {
        mac.split(':').collect()
    } else if mac.contains('-') {
        mac.split('-').collect()
    } else {
        return false;
    };
    parts.len() == 6 && parts.iter().all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_minimal_config() {
        let config = HermitConfig::default();
        let errors = config.validate();
        assert!(errors.is_empty(), "default config should be valid: {:?}", errors);
    }

    #[test]
    fn test_toml_round_trip() {
        let toml_str = r#"
[network]
wan_interface = "eth0"
lan_interface = "eth1"
hostname = "hermit"

[network.wan]
mode = "dhcp"

[dns]
ad_blocking = true

[qos]
enabled = false
"#;
        let config = HermitConfig::from_toml(toml_str).unwrap();
        assert_eq!(config.network.wan_interface.as_deref(), Some("eth0"));
        assert_eq!(config.network.lan_interface.as_deref(), Some("eth1"));
        assert!(config.dns.ad_blocking);

        let errors = config.validate();
        assert!(errors.is_empty(), "parsed config should be valid: {:?}", errors);
    }

    #[test]
    fn test_invalid_mac() {
        assert!(!is_valid_mac("not-a-mac"));
        assert!(is_valid_mac("aa:bb:cc:dd:ee:ff"));
        assert!(is_valid_mac("AA-BB-CC-DD-EE-FF"));
    }

    #[test]
    fn test_invalid_port_forward() {
        let config = HermitConfig {
            firewall: FirewallConfig {
                port_forwards: vec![PortForwardConfig {
                    protocol: "invalid".into(),
                    external_port: 0,
                    external_port_end: None,
                    internal_ip: "not-an-ip".into(),
                    internal_port: 80,
                    enabled: true,
                    description: String::new(),
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        let errors = config.validate();
        assert!(errors.len() >= 3, "should have protocol, ip, and port errors: {:?}", errors);
    }

    #[test]
    fn test_invalid_tls_mode() {
        let config = HermitConfig {
            tls: TlsConfig { mode: "invalid".into() },
            ..Default::default()
        };
        let errors = config.validate();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].field == "tls.mode");
    }

    #[test]
    fn test_qos_enabled_without_bandwidth() {
        let config = HermitConfig {
            qos: QosConfig { enabled: true, upload_mbps: 0, download_mbps: 0 },
            ..Default::default()
        };
        let errors = config.validate();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].field == "qos");
    }
}
