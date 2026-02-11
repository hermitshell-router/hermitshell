/// Information about a /30 subnet assignment
pub struct SubnetInfo {
    pub subnet_id: i64,
    pub network: String,
    pub gateway: String,
    pub device_ip: String,
    pub broadcast: String,
    pub netmask: String,
    pub gateway_octets: [u8; 4],
    pub device_ip_octets: [u8; 4],
    pub netmask_octets: [u8; 4],
}

/// Compute /30 subnet info from a sequential subnet_id.
/// Returns None if subnet_id is out of range (> 16255).
pub fn compute_subnet(subnet_id: i64) -> Option<SubnetInfo> {
    let third_octet = 1 + (subnet_id / 64);
    let fourth_octet_base = (subnet_id % 64) * 4;

    if third_octet > 254 {
        return None;
    }

    let third = third_octet as u8;
    let base = fourth_octet_base as u8;

    Some(SubnetInfo {
        subnet_id,
        network: format!("10.0.{}.{}", third, base),
        gateway: format!("10.0.{}.{}", third, base + 1),
        device_ip: format!("10.0.{}.{}", third, base + 2),
        broadcast: format!("10.0.{}.{}", third, base + 3),
        netmask: "255.255.255.252".to_string(),
        gateway_octets: [10, 0, third, base + 1],
        device_ip_octets: [10, 0, third, base + 2],
        netmask_octets: [255, 255, 255, 252],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subnet_0() {
        let s = compute_subnet(0).unwrap();
        assert_eq!(s.network, "10.0.1.0");
        assert_eq!(s.gateway, "10.0.1.1");
        assert_eq!(s.device_ip, "10.0.1.2");
        assert_eq!(s.broadcast, "10.0.1.3");
        assert_eq!(s.gateway_octets, [10, 0, 1, 1]);
        assert_eq!(s.device_ip_octets, [10, 0, 1, 2]);
    }

    #[test]
    fn test_subnet_63() {
        let s = compute_subnet(63).unwrap();
        assert_eq!(s.network, "10.0.1.252");
        assert_eq!(s.gateway, "10.0.1.253");
        assert_eq!(s.device_ip, "10.0.1.254");
        assert_eq!(s.broadcast, "10.0.1.255");
    }

    #[test]
    fn test_subnet_64_wraps_to_next_octet() {
        let s = compute_subnet(64).unwrap();
        assert_eq!(s.network, "10.0.2.0");
        assert_eq!(s.gateway, "10.0.2.1");
        assert_eq!(s.device_ip, "10.0.2.2");
    }

    #[test]
    fn test_last_valid_subnet() {
        let s = compute_subnet(16255).unwrap();
        assert_eq!(s.network, "10.0.254.252");
        assert_eq!(s.gateway, "10.0.254.253");
        assert_eq!(s.device_ip, "10.0.254.254");
    }

    #[test]
    fn test_exhausted() {
        assert!(compute_subnet(16256).is_none());
    }
}
