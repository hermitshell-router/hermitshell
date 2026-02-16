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

/// Total /30 subnets per octet (256 addresses / 4 per subnet)
const SUBNETS_PER_OCTET: i64 = 64;

/// Subnets available in one second+third octet pair (256 * 64)
const SUBNETS_PER_SECOND_OCTET: i64 = 256 * SUBNETS_PER_OCTET;

/// Maximum subnet_id. We use 10.0.1.0/30 through 10.255.255.252/30,
/// skipping 10.0.0.x (base address). That gives 256*256*64 - 64 - 1 as max id.
const MAX_SUBNET_ID: i64 = 256 * SUBNETS_PER_SECOND_OCTET - SUBNETS_PER_OCTET - 1;

/// Compute /30 subnet info from a sequential subnet_id.
///
/// Allocates from 10.0.1.0/30 through 10.255.255.252/30,
/// skipping 10.0.0.x (reserved for the router base address).
/// Supports up to 4,194,240 devices across the full 10.0.0.0/8 range.
///
/// Returns None if subnet_id is out of range.
pub fn compute_subnet(subnet_id: i64) -> Option<SubnetInfo> {
    if subnet_id < 0 || subnet_id > MAX_SUBNET_ID {
        return None;
    }

    // Skip 10.0.0.x by offsetting: subnet 0 starts at 10.0.1.0
    let offset = subnet_id + SUBNETS_PER_OCTET; // skip first 64 slots (10.0.0.x)
    let second = (offset / SUBNETS_PER_SECOND_OCTET) as u8;
    let remaining = offset % SUBNETS_PER_SECOND_OCTET;
    let third = (remaining / SUBNETS_PER_OCTET) as u8;
    let base = ((remaining % SUBNETS_PER_OCTET) * 4) as u8;

    Some(SubnetInfo {
        subnet_id,
        network: format!("10.{}.{}.{}", second, third, base),
        gateway: format!("10.{}.{}.{}", second, third, base + 1),
        device_ip: format!("10.{}.{}.{}", second, third, base + 2),
        broadcast: format!("10.{}.{}.{}", second, third, base + 3),
        netmask: "255.255.255.252".to_string(),
        gateway_octets: [10, second, third, base + 1],
        device_ip_octets: [10, second, third, base + 2],
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
    fn test_subnet_64_wraps_to_next_third_octet() {
        let s = compute_subnet(64).unwrap();
        assert_eq!(s.network, "10.0.2.0");
        assert_eq!(s.gateway, "10.0.2.1");
        assert_eq!(s.device_ip, "10.0.2.2");
    }

    #[test]
    fn test_last_in_first_second_octet() {
        // Last subnet in 10.0.x.x: third=255, base=252
        // subnet_id = 255*64 - 64 - 1 ... let's compute:
        // offset = subnet_id + 64, second = offset / 16384, remaining = offset % 16384
        // We want second=0, third=255, base=252 => offset = 255*64 + 63 = 16383
        // subnet_id = 16383 - 64 = 16319
        let s = compute_subnet(16319).unwrap();
        assert_eq!(s.network, "10.0.255.252");
        assert_eq!(s.gateway, "10.0.255.253");
        assert_eq!(s.device_ip, "10.0.255.254");
    }

    #[test]
    fn test_first_in_second_octet_1() {
        // subnet_id = 16320 => offset = 16384 => second=1, third=0, base=0
        let s = compute_subnet(16320).unwrap();
        assert_eq!(s.network, "10.1.0.0");
        assert_eq!(s.gateway, "10.1.0.1");
        assert_eq!(s.device_ip, "10.1.0.2");
    }

    #[test]
    fn test_last_valid_subnet() {
        let s = compute_subnet(MAX_SUBNET_ID).unwrap();
        assert_eq!(s.network, "10.255.255.252");
        assert_eq!(s.gateway, "10.255.255.253");
        assert_eq!(s.device_ip, "10.255.255.254");
    }

    #[test]
    fn test_exhausted() {
        assert!(compute_subnet(MAX_SUBNET_ID + 1).is_none());
    }

    #[test]
    fn test_negative() {
        assert!(compute_subnet(-1).is_none());
    }

    #[test]
    fn test_total_capacity() {
        // 256 second octets * 256 third octets * 64 subnets - 64 skipped
        assert_eq!(MAX_SUBNET_ID + 1, 4_194_240);
    }
}
