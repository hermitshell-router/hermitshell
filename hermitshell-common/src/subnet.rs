use std::net::{Ipv4Addr, Ipv6Addr};

/// Information about a per-device address assignment.
/// Each device gets a /32 IPv4 and a /128 ULA IPv6 address.
pub struct SubnetInfo {
    pub subnet_id: i64,
    pub device_ipv4: Ipv4Addr,
    pub device_ipv6_ula: Ipv6Addr,
}

/// Parse a device range CIDR string into (base_u32, prefix_len, max_subnet_id).
///
/// Only the three RFC 1918 ranges are accepted:
/// - `10.0.0.0/8`      → 16,777,214 addresses (subnet_id 0..16,777,213)
/// - `172.16.0.0/12`    → 1,048,574 addresses  (subnet_id 0..1,048,573)
/// - `192.168.0.0/16`   → 65,534 addresses      (subnet_id 0..65,533)
///
/// Returns None for anything else.
pub fn parse_device_range(cidr: &str) -> Option<(u32, u8, i64)> {
    let (addr_str, prefix_str) = cidr.split_once('/')?;
    let addr: Ipv4Addr = addr_str.parse().ok()?;
    let prefix_len: u8 = prefix_str.parse().ok()?;
    let base = u32::from(addr);

    // Validate this is a supported RFC 1918 range with exact network address
    let valid = match (base, prefix_len) {
        (0x0A000000, 8) => true,   // 10.0.0.0/8
        (0xAC100000, 12) => true,  // 172.16.0.0/12
        (0xC0A80000, 16) => true,  // 192.168.0.0/16
        _ => false,
    };
    if !valid {
        return None;
    }

    // Capacity: 2^host_bits - 2 (skip base+0 and base+1)
    let host_bits = 32 - prefix_len;
    let capacity = (1i64 << host_bits) - 2;
    let max_subnet_id = capacity - 1;

    Some((base, prefix_len, max_subnet_id))
}

/// Compute per-device addressing from a sequential subnet_id.
///
/// IPv4: Sequential allocation starting at base+2.
/// With /32 point-to-point addressing, every address is a valid host.
/// We skip base+0 (network-like) and base+1 (conventional router address).
///
/// IPv6: fd00::2 for subnet_id 0, fd00::3 for subnet_id 1, etc. (always fixed).
///
/// Returns None if subnet_id is out of range.
pub fn compute_subnet(subnet_id: i64, ipv4_base: u32, max_subnet_id: i64) -> Option<SubnetInfo> {
    if subnet_id < 0 || subnet_id > max_subnet_id {
        return None;
    }

    let device_ipv4 = Ipv4Addr::from(ipv4_base + (subnet_id + 2) as u32);

    // IPv6 ULA: fd00::2 for subnet_id 0, fd00::3 for subnet_id 1, etc.
    let v6_host = (subnet_id + 2) as u128;
    let v6_base: u128 = 0xfd00_0000_0000_0000_0000_0000_0000_0000;
    let device_ipv6_ula = Ipv6Addr::from(v6_base | v6_host);

    Some(SubnetInfo {
        subnet_id,
        device_ipv4,
        device_ipv6_ula,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Default 10.0.0.0/8 range constants for tests
    const BASE_10: u32 = 0x0A000000;
    const MAX_10: i64 = 16_777_213;

    #[test]
    fn test_subnet_0() {
        let s = compute_subnet(0, BASE_10, MAX_10).unwrap();
        assert_eq!(s.device_ipv4, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(s.device_ipv6_ula, "fd00::2".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn test_subnet_1() {
        let s = compute_subnet(1, BASE_10, MAX_10).unwrap();
        assert_eq!(s.device_ipv4, Ipv4Addr::new(10, 0, 0, 3));
    }

    #[test]
    fn test_sequential_through_255() {
        let s = compute_subnet(253, BASE_10, MAX_10).unwrap();
        assert_eq!(s.device_ipv4, Ipv4Addr::new(10, 0, 0, 255));
    }

    #[test]
    fn test_sequential_through_0() {
        let s = compute_subnet(254, BASE_10, MAX_10).unwrap();
        assert_eq!(s.device_ipv4, Ipv4Addr::new(10, 0, 1, 0));
    }

    #[test]
    fn test_last_valid_10() {
        let s = compute_subnet(MAX_10, BASE_10, MAX_10).unwrap();
        assert_eq!(s.device_ipv4, Ipv4Addr::new(10, 255, 255, 255));
    }

    #[test]
    fn test_exhausted_10() {
        assert!(compute_subnet(MAX_10 + 1, BASE_10, MAX_10).is_none());
    }

    #[test]
    fn test_negative() {
        assert!(compute_subnet(-1, BASE_10, MAX_10).is_none());
    }

    #[test]
    fn test_ipv6_sequential() {
        let s0 = compute_subnet(0, BASE_10, MAX_10).unwrap();
        let s1 = compute_subnet(1, BASE_10, MAX_10).unwrap();
        assert_eq!(s0.device_ipv6_ula, "fd00::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(s1.device_ipv6_ula, "fd00::3".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn test_capacity_10() {
        assert_eq!(MAX_10 + 1, 16_777_214);
    }

    #[test]
    fn test_never_allocates_base_or_base_plus_1() {
        for sid in 0..1000 {
            let s = compute_subnet(sid, BASE_10, MAX_10).unwrap();
            assert_ne!(s.device_ipv4, Ipv4Addr::new(10, 0, 0, 0));
            assert_ne!(s.device_ipv4, Ipv4Addr::new(10, 0, 0, 1));
        }
    }

    // --- 172.16.0.0/12 tests ---

    #[test]
    fn test_172_16_first() {
        let (base, _, max_sid) = parse_device_range("172.16.0.0/12").unwrap();
        let s = compute_subnet(0, base, max_sid).unwrap();
        assert_eq!(s.device_ipv4, Ipv4Addr::new(172, 16, 0, 2));
    }

    #[test]
    fn test_172_16_last() {
        let (base, _, max_sid) = parse_device_range("172.16.0.0/12").unwrap();
        let s = compute_subnet(max_sid, base, max_sid).unwrap();
        assert_eq!(s.device_ipv4, Ipv4Addr::new(172, 31, 255, 255));
    }

    #[test]
    fn test_172_16_capacity() {
        let (_, _, max_sid) = parse_device_range("172.16.0.0/12").unwrap();
        assert_eq!(max_sid + 1, 1_048_574);
    }

    #[test]
    fn test_172_16_exhausted() {
        let (base, _, max_sid) = parse_device_range("172.16.0.0/12").unwrap();
        assert!(compute_subnet(max_sid + 1, base, max_sid).is_none());
    }

    // --- 192.168.0.0/16 tests ---

    #[test]
    fn test_192_168_first() {
        let (base, _, max_sid) = parse_device_range("192.168.0.0/16").unwrap();
        let s = compute_subnet(0, base, max_sid).unwrap();
        assert_eq!(s.device_ipv4, Ipv4Addr::new(192, 168, 0, 2));
    }

    #[test]
    fn test_192_168_last() {
        let (base, _, max_sid) = parse_device_range("192.168.0.0/16").unwrap();
        let s = compute_subnet(max_sid, base, max_sid).unwrap();
        assert_eq!(s.device_ipv4, Ipv4Addr::new(192, 168, 255, 255));
    }

    #[test]
    fn test_192_168_capacity() {
        let (_, _, max_sid) = parse_device_range("192.168.0.0/16").unwrap();
        assert_eq!(max_sid + 1, 65_534);
    }

    // --- parse_device_range tests ---

    #[test]
    fn test_parse_10() {
        let (base, prefix, max_sid) = parse_device_range("10.0.0.0/8").unwrap();
        assert_eq!(base, 0x0A000000);
        assert_eq!(prefix, 8);
        assert_eq!(max_sid, 16_777_213);
    }

    #[test]
    fn test_parse_172() {
        let (base, prefix, max_sid) = parse_device_range("172.16.0.0/12").unwrap();
        assert_eq!(base, 0xAC100000);
        assert_eq!(prefix, 12);
        assert_eq!(max_sid, 1_048_573);
    }

    #[test]
    fn test_parse_192() {
        let (base, prefix, max_sid) = parse_device_range("192.168.0.0/16").unwrap();
        assert_eq!(base, 0xC0A80000);
        assert_eq!(prefix, 16);
        assert_eq!(max_sid, 65_533);
    }

    #[test]
    fn test_parse_invalid_range() {
        assert!(parse_device_range("8.8.8.0/24").is_none());
    }

    #[test]
    fn test_parse_wrong_prefix() {
        assert!(parse_device_range("10.0.0.0/16").is_none());
    }

    #[test]
    fn test_parse_wrong_network() {
        assert!(parse_device_range("172.17.0.0/12").is_none());
    }

    #[test]
    fn test_parse_garbage() {
        assert!(parse_device_range("not-a-cidr").is_none());
        assert!(parse_device_range("").is_none());
    }
}
