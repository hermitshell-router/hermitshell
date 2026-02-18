use std::net::{Ipv4Addr, Ipv6Addr};

/// Information about a per-device subnet assignment.
/// Each device gets a /32 IPv4 address within 10.0.0.0/8
/// and a /128 ULA IPv6 address within fd00::/8.
pub struct SubnetInfo {
    pub subnet_id: i64,
    pub device_ipv4: Ipv4Addr,
    pub device_ipv6_ula: Ipv6Addr,
}

/// Usable addresses per /24 block: .2 through .254 (skip .0 network, .1 router, .255 broadcast)
const USABLE_PER_BLOCK: i64 = 253;

/// Maximum subnet_id.
/// 65536 total /24 blocks in 10.0.0.0/8.
/// We skip 10.0.0.x (block 0) for the router base address, leaving 65535 usable blocks.
/// 65535 * 253 = 16,580,355 usable addresses, indices 0..16,580,354.
const MAX_SUBNET_ID: i64 = 16_580_354;

/// Return the maximum valid subnet_id.
pub fn max_subnet_id() -> i64 {
    MAX_SUBNET_ID
}

/// Compute per-device addressing from a sequential subnet_id.
///
/// IPv4: Allocates from 10.0.1.2 through 10.255.255.254,
/// skipping 10.0.0.x (reserved for the router base address).
/// Within each /24 block, .0, .1, and .255 are skipped.
///
/// IPv6: fd00::2 for subnet_id 0, fd00::3 for subnet_id 1, etc.
/// fd00::1 is the router.
///
/// Returns None if subnet_id is out of range.
pub fn compute_subnet(subnet_id: i64) -> Option<SubnetInfo> {
    if subnet_id < 0 || subnet_id > MAX_SUBNET_ID {
        return None;
    }

    // Skip block 0 (10.0.0.x) by offsetting by USABLE_PER_BLOCK.
    // subnet_id 0 -> offset 253, which is block_index 1, addr_index 0.
    let offset = subnet_id + USABLE_PER_BLOCK;
    let block_index = offset / USABLE_PER_BLOCK;
    let addr_index = offset % USABLE_PER_BLOCK;

    let second = (block_index / 256) as u8;
    let third = (block_index % 256) as u8;
    let fourth = (addr_index + 2) as u8; // +2 to skip .0 and .1

    let device_ipv4 = Ipv4Addr::new(10, second, third, fourth);

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

    #[test]
    fn test_subnet_0() {
        let s = compute_subnet(0).unwrap();
        assert_eq!(s.device_ipv4, Ipv4Addr::new(10, 0, 1, 2));
        assert_eq!(s.device_ipv6_ula, "fd00::2".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn test_subnet_252_last_in_first_block() {
        let s = compute_subnet(252).unwrap();
        assert_eq!(s.device_ipv4, Ipv4Addr::new(10, 0, 1, 254));
    }

    #[test]
    fn test_subnet_253_wraps_to_next_block() {
        let s = compute_subnet(253).unwrap();
        assert_eq!(s.device_ipv4, Ipv4Addr::new(10, 0, 2, 2));
    }

    #[test]
    fn test_last_valid_subnet() {
        let s = compute_subnet(MAX_SUBNET_ID).unwrap();
        assert_eq!(s.device_ipv4, Ipv4Addr::new(10, 255, 255, 254));
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
    fn test_ipv6_sequential() {
        let s0 = compute_subnet(0).unwrap();
        let s1 = compute_subnet(1).unwrap();
        assert_eq!(s0.device_ipv6_ula, "fd00::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(s1.device_ipv6_ula, "fd00::3".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn test_total_capacity() {
        // 65535 usable blocks * 253 per block = 16,580,355
        assert_eq!(MAX_SUBNET_ID + 1, 16_580_355);
    }

    #[test]
    fn test_skips_0_1_255() {
        // Ensure no device gets .0, .1, or .255
        for sid in 0..1000 {
            let s = compute_subnet(sid).unwrap();
            let fourth = s.device_ipv4.octets()[3];
            assert!(fourth >= 2 && fourth <= 254, "subnet_id {} got fourth octet {}", sid, fourth);
        }
    }
}
