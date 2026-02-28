use anyhow::{bail, Context, Result};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use tracing::{debug, error, info};

use crate::db::Db;

const UNBOUND_CONFIG_DIR: &str = "/var/lib/hermitshell/unbound";
const UNBOUND_BLOCKLIST_DIR: &str = "/var/lib/hermitshell/unbound/blocklists";
const UNBOUND_CONFIG_PATH: &str = "/var/lib/hermitshell/unbound/unbound.conf";

/// Well-known DoH resolver IPs to block in nftables (for bypass prevention).
pub const DOH_RESOLVER_IPS_V4: &[&str] = &[
    "1.1.1.1",
    "1.0.0.1", // Cloudflare
    "8.8.8.8",
    "8.8.4.4", // Google
    "9.9.9.9",
    "149.112.112.112", // Quad9
    "208.67.222.222",
    "208.67.220.220", // OpenDNS
    "94.140.14.14",
    "94.140.15.15", // AdGuard
    "185.228.168.168",
    "185.228.169.168", // CleanBrowsing
    "45.90.28.0",
    "45.90.30.0", // NextDNS
];

/// Well-known DoH resolver domains to block in Unbound.
pub const DOH_RESOLVER_DOMAINS: &[&str] = &[
    "dns.google",
    "dns.cloudflare.com",
    "cloudflare-dns.com",
    "one.one.one.one",
    "dns.quad9.net",
    "doh.opendns.com",
    "dns.adguard-dns.com",
    "doh.cleanbrowsing.org",
    "dns.nextdns.io",
];

pub struct UnboundManager {
    listen_port: u16,
    listen_addr: String,
    listen_addr_v6: Option<String>,
    tls_cert_path: Option<String>,
    tls_key_path: Option<String>,
    child: Option<Child>,
}

impl UnboundManager {
    pub fn new(
        listen_port: u16,
        listen_addr: String,
        listen_addr_v6: Option<String>,
        tls_cert_path: Option<String>,
        tls_key_path: Option<String>,
    ) -> Self {
        Self {
            listen_port,
            listen_addr,
            listen_addr_v6,
            tls_cert_path,
            tls_key_path,
            child: None,
        }
    }

    pub fn write_config(&self, db: &Arc<Mutex<Db>>) -> Result<()> {
        std::fs::create_dir_all(UNBOUND_CONFIG_DIR)?;
        std::fs::create_dir_all(UNBOUND_BLOCKLIST_DIR)?;

        let cfg = self.generate_config_string(db)?;
        std::fs::write(UNBOUND_CONFIG_PATH, &cfg)?;
        debug!(path = UNBOUND_CONFIG_PATH, "wrote unbound config");
        Ok(())
    }

    /// Generate the full unbound.conf content as a string, without writing to disk.
    pub fn generate_config_string(&self, db: &Arc<Mutex<Db>>) -> Result<String> {
        // Read all DB state under a single lock, then drop it.
        let (
            devices,
            blocklists,
            custom_rules,
            forward_zones,
            upstream_dns,
            per_client_rate,
            per_domain_rate,
            ad_blocking_enabled,
        ) = {
            let db = db.lock().unwrap();
            let devices = db.list_assigned_devices().unwrap_or_default();
            let blocklists = db.list_dns_blocklists().unwrap_or_default();
            let custom_rules = db.list_dns_custom_rules().unwrap_or_default();
            let forward_zones = db.list_dns_forward_zones().unwrap_or_default();
            let upstream_dns = db
                .get_config("upstream_dns")
                .ok()
                .flatten()
                .unwrap_or_default();
            let per_client_rate: u32 = db
                .get_config("dns_ratelimit_per_client")
                .ok()
                .flatten()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let per_domain_rate: u32 = db
                .get_config("dns_ratelimit_per_domain")
                .ok()
                .flatten()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let ad_blocking_enabled = db.get_config_bool("ad_blocking_enabled", true);
            (
                devices,
                blocklists,
                custom_rules,
                forward_zones,
                upstream_dns,
                per_client_rate,
                per_domain_rate,
                ad_blocking_enabled,
            )
        };

        let mut cfg = String::with_capacity(4096);

        // --- server: block ---
        cfg.push_str("server:\n");
        cfg.push_str(&format!("    interface: 0.0.0.0@{}\n", self.listen_port));
        cfg.push_str(&format!("    interface: ::0@{}\n", self.listen_port));
        cfg.push_str("    access-control: 0.0.0.0/0 allow\n");
        cfg.push_str("    access-control: ::/0 allow\n");
        cfg.push_str("    do-ip4: yes\n");
        cfg.push_str("    do-ip6: yes\n");
        cfg.push_str("    do-udp: yes\n");
        cfg.push_str("    do-tcp: yes\n");
        cfg.push_str("\n");

        // Logging
        cfg.push_str("    # Logging\n");
        cfg.push_str("    verbosity: 1\n");
        cfg.push_str("    log-queries: yes\n");
        cfg.push_str("    logfile: \"/var/lib/hermitshell/unbound/query.log\"\n");
        cfg.push_str("    use-syslog: no\n");
        cfg.push_str("    log-time-ascii: no\n");
        cfg.push_str("\n");

        // Security
        cfg.push_str("    # Security\n");
        cfg.push_str("    hide-identity: yes\n");
        cfg.push_str("    hide-version: yes\n");
        cfg.push_str("    harden-glue: yes\n");
        cfg.push_str("    harden-dnssec-stripped: yes\n");
        cfg.push_str("    auto-trust-anchor-file: \"/var/lib/hermitshell/unbound/root.key\"\n");
        cfg.push_str("\n");

        // Performance
        cfg.push_str("    # Performance\n");
        cfg.push_str("    num-threads: 2\n");
        cfg.push_str("    msg-cache-size: 4m\n");
        cfg.push_str("    rrset-cache-size: 8m\n");
        cfg.push_str("    prefetch: yes\n");
        cfg.push_str("\n");

        // TLS (if cert/key paths are set)
        if let (Some(cert), Some(key)) = (&self.tls_cert_path, &self.tls_key_path) {
            cfg.push_str("    tls-port: 853\n");
            cfg.push_str(&format!("    tls-service-key: \"{}\"\n", key));
            cfg.push_str(&format!("    tls-service-pem: \"{}\"\n", cert));
            cfg.push_str("\n");
        }

        // Rate limiting
        cfg.push_str(&format!("    ip-ratelimit: {}\n", per_client_rate));
        cfg.push_str(&format!("    ratelimit: {}\n", per_domain_rate));
        cfg.push_str("\n");

        // Per-device tags
        cfg.push_str("    define-tag: \"ads custom strict\"\n");
        cfg.push_str("\n");

        for dev in &devices {
            let ip = match &dev.ipv4 {
                Some(ip) => ip,
                None => continue,
            };
            let tags = match dev.device_group.as_str() {
                "blocked" => continue,
                "iot" => "ads custom strict",
                // quarantine, trusted, guest, servers all get the same tags
                _ => "ads custom",
            };
            cfg.push_str(&format!("    access-control-tag: {}/32 \"{}\"\n", ip, tags));
        }
        cfg.push_str("\n");

        // Blocklist includes (only when blocking is enabled)
        if ad_blocking_enabled {
            for bl in &blocklists {
                if bl.enabled {
                    cfg.push_str(&format!(
                        "    include: \"{}/{}.conf\"\n",
                        UNBOUND_BLOCKLIST_DIR, bl.id
                    ));
                }
            }
            cfg.push_str("\n");

            // DoH domain blocking
            for domain in DOH_RESOLVER_DOMAINS {
                cfg.push_str(&format!("    local-zone: \"{}\" always_refuse\n", domain));
                cfg.push_str(&format!(
                    "    local-zone-tag: \"{}\" \"ads custom strict\"\n",
                    domain
                ));
            }
            cfg.push_str("\n");
        }

        // Custom DNS rules
        for rule in &custom_rules {
            if rule.enabled {
                cfg.push_str(&format!(
                    "    local-data: \"{} IN {} {}\"\n",
                    rule.domain, rule.record_type, rule.value
                ));
            }
        }
        cfg.push_str("\n");

        // --- remote-control: block ---
        cfg.push_str("remote-control:\n");
        cfg.push_str("    control-enable: yes\n");
        cfg.push_str("    control-interface: 127.0.0.1\n");
        cfg.push_str("\n");

        // --- Forward zones ---
        for fz in &forward_zones {
            if fz.enabled {
                cfg.push_str("forward-zone:\n");
                cfg.push_str(&format!("    name: \"{}\"\n", fz.domain));
                cfg.push_str(&format!("    forward-addr: {}\n", fz.forward_addr));
                cfg.push_str("\n");
            }
        }

        // Catch-all forward zone from upstream_dns config
        let upstream = upstream_dns.trim();
        if !upstream.is_empty() && upstream != "auto" {
            cfg.push_str("forward-zone:\n");
            cfg.push_str("    name: \".\"\n");
            for ip in upstream.split(',') {
                let ip = ip.trim();
                if !ip.is_empty() {
                    cfg.push_str(&format!("    forward-addr: {}\n", ip));
                }
            }
            cfg.push_str("\n");
        }

        Ok(cfg)
    }

    pub fn start(&mut self) -> Result<()> {
        // Kill any existing process
        self.stop();

        let child = Command::new("unbound")
            .args(["-d", "-c", UNBOUND_CONFIG_PATH])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .context("failed to spawn unbound")?;

        info!(pid = child.id(), "started unbound");
        self.child = Some(child);
        Ok(())
    }

    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
            info!("stopped unbound");
        }
    }

    pub fn reload(&self) -> Result<()> {
        let status = Command::new("unbound-control")
            .args(["-c", UNBOUND_CONFIG_PATH, "reload"])
            .output()
            .context("failed to run unbound-control reload")?;
        if !status.status.success() {
            let stderr = String::from_utf8_lossy(&status.stderr);
            bail!("unbound-control reload failed: {}", stderr);
        }
        debug!("unbound-control reload succeeded");
        Ok(())
    }

    pub fn wait_for_ready(&self, timeout_secs: u64) -> bool {
        let start = std::time::Instant::now();
        let interval = std::time::Duration::from_millis(200);
        let timeout = std::time::Duration::from_secs(timeout_secs);
        while start.elapsed() < timeout {
            let result = Command::new("dig")
                .args([
                    "+short",
                    "+time=1",
                    "+tries=1",
                    "@127.0.0.1",
                    &format!("-p{}", self.listen_port),
                    "example.com",
                ])
                .output();
            if let Ok(output) = result {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    if !stdout.trim().is_empty() {
                        return true;
                    }
                }
            }
            std::thread::sleep(interval);
        }
        false
    }

    pub fn set_blocking_enabled(&self, db: &Arc<Mutex<Db>>, enabled: bool) -> Result<()> {
        {
            let db = db.lock().unwrap();
            db.set_config(
                "ad_blocking_enabled",
                if enabled { "true" } else { "false" },
            )?;
        }
        self.write_config(db)?;
        self.reload()?;
        Ok(())
    }

    pub fn download_blocklists(&self, db: &Arc<Mutex<Db>>) -> Result<()> {
        let blocklists = {
            let db = db.lock().unwrap();
            db.list_dns_blocklists().unwrap_or_default()
        };

        std::fs::create_dir_all(UNBOUND_BLOCKLIST_DIR)?;

        for bl in &blocklists {
            if !bl.enabled {
                continue;
            }
            info!(id = bl.id, name = %bl.name, url = %bl.url, "downloading blocklist");
            match download_and_convert_blocklist(&bl.url, &bl.tag) {
                Ok(content) => {
                    let path = format!("{}/{}.conf", UNBOUND_BLOCKLIST_DIR, bl.id);
                    std::fs::write(&path, &content)?;
                    info!(
                        id = bl.id,
                        path = %path,
                        "wrote blocklist"
                    );
                }
                Err(e) => {
                    error!(
                        id = bl.id,
                        url = %bl.url,
                        err = %e,
                        "failed to download blocklist"
                    );
                }
            }
        }
        Ok(())
    }
}

impl Drop for UnboundManager {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Validate that a domain is well-formed: alphanumeric, hyphens, dots only.
/// Max 253 chars total, each label max 63 chars.
pub fn validate_domain(domain: &str) -> Result<()> {
    if domain.is_empty() {
        bail!("domain is empty");
    }
    if domain.len() > 253 {
        bail!("domain exceeds 253 characters");
    }
    for label in domain.split('.') {
        if label.is_empty() {
            bail!("domain has empty label");
        }
        if label.len() > 63 {
            bail!("domain label exceeds 63 characters: {}", label);
        }
        for ch in label.chars() {
            if !ch.is_ascii_alphanumeric() && ch != '-' {
                bail!(
                    "domain contains invalid character '{}' in label '{}'",
                    ch,
                    label
                );
            }
        }
        if label.starts_with('-') || label.ends_with('-') {
            bail!("domain label '{}' starts or ends with hyphen", label);
        }
    }
    Ok(())
}

/// Download a hosts-format blocklist and convert to Unbound local-zone config.
fn download_and_convert_blocklist(url: &str, tag: &str) -> Result<String> {
    let body = http_download(url).context("blocklist download failed")?;
    Ok(convert_blocklist_body(&body, tag))
}

/// Parse a hosts-file body into Unbound local-zone config lines.
fn convert_blocklist_body(body: &str, tag: &str) -> String {
    let mut out = String::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Hosts-file format: "0.0.0.0 domain" or "127.0.0.1 domain"
        let domain = if let Some(rest) = line
            .strip_prefix("0.0.0.0")
            .or_else(|| line.strip_prefix("127.0.0.1"))
        {
            rest.trim()
        } else {
            // Some lists have bare domains
            line
        };
        // Skip entries with spaces (e.g. comments after domain)
        let domain = domain.split_whitespace().next().unwrap_or("");
        if domain.is_empty() || domain == "localhost" {
            continue;
        }
        // Basic sanity: skip lines that don't look like domains
        if !domain.contains('.') {
            continue;
        }
        out.push_str(&format!("local-zone: \"{}\" always_refuse\n", domain));
        out.push_str(&format!("local-zone-tag: \"{}\" \"{}\"\n", domain, tag));
    }
    out
}

/// Simple HTTP(S)-unaware download using TCP. Follows one redirect.
/// For HTTPS URLs, shells out to curl as a pragmatic fallback since the
/// agent binary runs on a system that always has curl installed.
fn http_download(url: &str) -> Result<String> {
    if url.starts_with("https://") {
        return http_download_curl(url);
    }

    // Plain HTTP via raw TcpStream
    let url_no_scheme = url.strip_prefix("http://").unwrap_or(url);
    let (host, path) = match url_no_scheme.find('/') {
        Some(i) => (&url_no_scheme[..i], &url_no_scheme[i..]),
        None => (url_no_scheme, "/"),
    };
    let addr = if host.contains(':') {
        host.to_string()
    } else {
        format!("{}:80", host)
    };

    let mut stream = TcpStream::connect(&addr).context("connect for blocklist download")?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: hermitshell-agent\r\n\r\n",
        path, host
    );
    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    let mut reader = BufReader::new(&stream);

    // Read status line
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;

    // Read headers, check for redirect
    let mut location: Option<String> = None;
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                if line.trim().is_empty() {
                    break;
                }
                let lower = line.to_ascii_lowercase();
                if lower.starts_with("location: ") {
                    let offset = "location: ".len();
                    location = Some(line[offset..].trim().to_string());
                }
            }
            Err(_) => break,
        }
    }

    // Follow one redirect (common for blocklist URLs)
    if status_line.contains("301")
        || status_line.contains("302")
        || status_line.contains("307")
        || status_line.contains("308")
    {
        if let Some(loc) = location {
            return http_download(&loc);
        }
    }

    let mut body = String::new();
    let _ = reader.read_to_string(&mut body);
    Ok(body)
}

/// Download via curl for HTTPS URLs (the router always has curl).
fn http_download_curl(url: &str) -> Result<String> {
    let output = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--location",
            "--max-time",
            "30",
            url,
        ])
        .output()
        .context("failed to run curl")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("curl failed for {}: {}", url, stderr);
    }
    String::from_utf8(output.stdout).context("blocklist response is not valid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- validate_domain tests ---

    #[test]
    fn test_validate_domain_valid() {
        assert!(validate_domain("example.com").is_ok());
        assert!(validate_domain("sub.example.com").is_ok());
        assert!(validate_domain("a-b.example.com").is_ok());
        assert!(validate_domain("x").is_ok());
    }

    #[test]
    fn test_validate_domain_empty() {
        assert!(validate_domain("").is_err());
    }

    #[test]
    fn test_validate_domain_too_long() {
        let long = "a".repeat(254);
        assert!(validate_domain(&long).is_err());
    }

    #[test]
    fn test_validate_domain_invalid_chars() {
        assert!(validate_domain("example .com").is_err());
        assert!(validate_domain("exam!ple.com").is_err());
        assert!(validate_domain("exam_ple.com").is_err());
    }

    #[test]
    fn test_validate_domain_hyphen_rules() {
        assert!(validate_domain("-example.com").is_err());
        assert!(validate_domain("example-.com").is_err());
    }

    #[test]
    fn test_validate_domain_empty_label() {
        assert!(validate_domain("example..com").is_err());
        assert!(validate_domain(".example.com").is_err());
    }

    #[test]
    fn test_validate_domain_long_label() {
        let label = "a".repeat(64);
        let domain = format!("{}.com", label);
        assert!(validate_domain(&domain).is_err());
    }

    // --- blocklist parsing tests ---

    #[test]
    fn test_convert_blocklist_hosts_format() {
        let body = "\
# comment line
0.0.0.0 ads.example.com
127.0.0.1 tracker.example.com
0.0.0.0 localhost
";
        let out = convert_blocklist_body(body, "ads");
        assert!(out.contains("local-zone: \"ads.example.com\" always_refuse"));
        assert!(out.contains("local-zone-tag: \"ads.example.com\" \"ads\""));
        assert!(out.contains("local-zone: \"tracker.example.com\" always_refuse"));
        assert!(!out.contains("localhost"));
    }

    #[test]
    fn test_convert_blocklist_bare_domains() {
        let body = "malware.example.com\nphishing.example.net\n";
        let out = convert_blocklist_body(body, "custom");
        assert!(out.contains("local-zone: \"malware.example.com\" always_refuse"));
        assert!(out.contains("local-zone: \"phishing.example.net\" always_refuse"));
        assert!(out.contains("local-zone-tag: \"malware.example.com\" \"custom\""));
    }

    #[test]
    fn test_convert_blocklist_skips_blanks_and_comments() {
        let body = "\n# header\n\n# another comment\n0.0.0.0 bad.com\n";
        let out = convert_blocklist_body(body, "ads");
        // Only one domain should appear
        assert_eq!(out.matches("local-zone:").count(), 1);
        assert!(out.contains("bad.com"));
    }

    #[test]
    fn test_convert_blocklist_skips_no_dot() {
        let body = "0.0.0.0 localhostonly\nbare\n0.0.0.0 real.domain.com\n";
        let out = convert_blocklist_body(body, "ads");
        assert!(!out.contains("localhostonly"));
        assert!(!out.contains("\"bare\""));
        assert!(out.contains("real.domain.com"));
    }

    // --- generate_config_string tests ---

    #[test]
    fn test_generate_config_basic() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = Arc::new(Mutex::new(Db::open(db_path.to_str().unwrap()).unwrap()));

        let mgr = UnboundManager::new(
            5354,
            "10.0.0.1".to_string(),
            Some("fd00::1".to_string()),
            None,
            None,
        );
        let config = mgr.generate_config_string(&db).unwrap();

        assert!(config.contains("server:"));
        assert!(config.contains("interface: 0.0.0.0@5354"));
        assert!(config.contains("remote-control:"));
        assert!(config.contains("define-tag:"));
        assert!(config.contains("log-queries: yes"));
        assert!(config.contains("hide-identity: yes"));
    }

    #[test]
    fn test_generate_config_with_tls() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = Arc::new(Mutex::new(Db::open(db_path.to_str().unwrap()).unwrap()));

        let mgr = UnboundManager::new(
            5354,
            "10.0.0.1".to_string(),
            None,
            Some("/tmp/cert.pem".to_string()),
            Some("/tmp/key.pem".to_string()),
        );
        let config = mgr.generate_config_string(&db).unwrap();

        assert!(config.contains("tls-port: 853"));
        assert!(config.contains("tls-service-key: \"/tmp/key.pem\""));
        assert!(config.contains("tls-service-pem: \"/tmp/cert.pem\""));
    }

    #[test]
    fn test_generate_config_forward_zone() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = Arc::new(Mutex::new(Db::open(db_path.to_str().unwrap()).unwrap()));

        {
            let db_guard = db.lock().unwrap();
            db_guard
                .add_dns_forward_zone("corp.local", "10.1.1.1")
                .unwrap();
        }

        let mgr = UnboundManager::new(5354, "10.0.0.1".to_string(), None, None, None);
        let config = mgr.generate_config_string(&db).unwrap();

        assert!(config.contains("forward-zone:"));
        assert!(config.contains("name: \"corp.local\""));
        assert!(config.contains("forward-addr: 10.1.1.1"));
    }

    #[test]
    fn test_generate_config_custom_rules() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = Arc::new(Mutex::new(Db::open(db_path.to_str().unwrap()).unwrap()));

        {
            let db_guard = db.lock().unwrap();
            db_guard
                .add_dns_custom_rule("myhost.home", "A", "10.0.1.50")
                .unwrap();
        }

        let mgr = UnboundManager::new(5354, "10.0.0.1".to_string(), None, None, None);
        let config = mgr.generate_config_string(&db).unwrap();

        assert!(config.contains("local-data: \"myhost.home IN A 10.0.1.50\""));
    }

    #[test]
    fn test_generate_config_upstream_dns_forwarding() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = Arc::new(Mutex::new(Db::open(db_path.to_str().unwrap()).unwrap()));

        {
            let db_guard = db.lock().unwrap();
            db_guard.set_config("upstream_dns", "1.1.1.1,8.8.8.8").unwrap();
        }

        let mgr = UnboundManager::new(5354, "10.0.0.1".to_string(), None, None, None);
        let config = mgr.generate_config_string(&db).unwrap();

        assert!(config.contains("name: \".\""));
        assert!(config.contains("forward-addr: 1.1.1.1"));
        assert!(config.contains("forward-addr: 8.8.8.8"));
    }

    #[test]
    fn test_generate_config_doh_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = Arc::new(Mutex::new(Db::open(db_path.to_str().unwrap()).unwrap()));

        let mgr = UnboundManager::new(5354, "10.0.0.1".to_string(), None, None, None);
        let config = mgr.generate_config_string(&db).unwrap();

        // DoH domains should be blocked by default (ad_blocking_enabled defaults to true)
        assert!(config.contains("local-zone: \"dns.google\" always_refuse"));
        assert!(config.contains("local-zone: \"dns.cloudflare.com\" always_refuse"));
    }

    #[test]
    fn test_generate_config_blocking_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = Arc::new(Mutex::new(Db::open(db_path.to_str().unwrap()).unwrap()));

        {
            let db_guard = db.lock().unwrap();
            db_guard.set_config("ad_blocking_enabled", "false").unwrap();
        }

        let mgr = UnboundManager::new(5354, "10.0.0.1".to_string(), None, None, None);
        let config = mgr.generate_config_string(&db).unwrap();

        // With blocking disabled, no DoH blocking or blocklist includes
        assert!(!config.contains("local-zone: \"dns.google\" always_refuse"));
    }

    #[test]
    fn test_generate_config_rate_limits() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = Arc::new(Mutex::new(Db::open(db_path.to_str().unwrap()).unwrap()));

        {
            let db_guard = db.lock().unwrap();
            db_guard
                .set_config("dns_ratelimit_per_client", "100")
                .unwrap();
            db_guard
                .set_config("dns_ratelimit_per_domain", "50")
                .unwrap();
        }

        let mgr = UnboundManager::new(5354, "10.0.0.1".to_string(), None, None, None);
        let config = mgr.generate_config_string(&db).unwrap();

        assert!(config.contains("ip-ratelimit: 100"));
        assert!(config.contains("ratelimit: 50"));
    }
}
