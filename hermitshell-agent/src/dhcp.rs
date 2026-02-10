use anyhow::Result;
use std::fs;

#[derive(Debug, Clone)]
pub struct Lease {
    pub mac: String,
    pub ip: String,
    pub hostname: Option<String>,
}

/// Parse dnsmasq lease file
/// Format: <expiry> <mac> <ip> <hostname> <client-id>
pub fn parse_leases(path: &str) -> Result<Vec<Lease>> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.into()),
    };

    let mut leases = Vec::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            let hostname = if parts[3] == "*" {
                None
            } else {
                Some(parts[3].to_string())
            };
            leases.push(Lease {
                mac: parts[1].to_lowercase(),
                ip: parts[2].to_string(),
                hostname,
            });
        }
    }
    Ok(leases)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_leases() {
        let content = "1707500000 aa:bb:cc:dd:ee:ff 10.0.0.100 myhost 01:aa:bb:cc:dd:ee:ff\n\
                       1707500001 11:22:33:44:55:66 10.0.0.101 * 01:11:22:33:44:55:66";
        std::fs::write("/tmp/test-leases", content).unwrap();

        let leases = parse_leases("/tmp/test-leases").unwrap();
        assert_eq!(leases.len(), 2);
        assert_eq!(leases[0].mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(leases[0].ip, "10.0.0.100");
        assert_eq!(leases[0].hostname, Some("myhost".to_string()));
        assert_eq!(leases[1].hostname, None);

        std::fs::remove_file("/tmp/test-leases").unwrap();
    }
}
