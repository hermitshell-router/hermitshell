use crate::db::Db;
use crate::log_export::LogEvent;

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, error, warn};

const LOG_FILE: &str = "/var/lib/hermitshell/unbound/query.log";
const SCAN_INTERVAL_SECS: u64 = 30;

/// Parsed DNS log entry from an Unbound log line.
struct DnsLogEntry<'a> {
    client_ip: &'a str,
    domain: &'a str,
    query_type: &'a str,
}

/// Parse a single line from an Unbound query log.
///
/// Format: `[timestamp] unbound[pid:thread] info: client_ip domain. query_type class`
/// Example: `[1709312345] unbound[1234:0] info: 10.0.1.2 example.com. A IN`
fn parse_unbound_log_line(line: &str) -> Option<DnsLogEntry<'_>> {
    let info_idx = line.find("info: ")?;
    let rest = &line[info_idx + 6..];
    let mut parts = rest.split_whitespace();
    let client_ip = parts.next()?;
    let domain_raw = parts.next()?;
    let domain = domain_raw.trim_end_matches('.');
    let query_type = parts.next()?;
    // Skip class (IN)
    if domain.is_empty() {
        return None;
    }
    Some(DnsLogEntry {
        client_ip,
        domain,
        query_type,
    })
}

/// Run one ingest cycle: read Unbound query log, parse and store DNS queries.
pub fn ingest_once(db: &Arc<Mutex<Db>>, tx: &UnboundedSender<LogEvent>) {
    let ingest_path = format!("{}.ingest", LOG_FILE);

    // Atomic rename: move the active log file so Unbound reopens a fresh one on next write
    if let Err(e) = std::fs::rename(LOG_FILE, &ingest_path) {
        // File may not exist yet — that's fine
        if e.kind() != std::io::ErrorKind::NotFound {
            debug!(error = %e, file = LOG_FILE, "cannot rename log file");
        }
        return;
    }

    let contents = match std::fs::read_to_string(&ingest_path) {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, file = %ingest_path, "failed to read ingest file");
            return;
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    for line in contents.lines() {
        if let Some(entry) = parse_unbound_log_line(line) {
            let device_ip = if entry.client_ip.parse::<IpAddr>().is_ok()
                && entry.client_ip != "0.0.0.0"
            {
                entry.client_ip.to_string()
            } else {
                continue;
            };

            // Insert into database
            {
                let db_guard = db.lock().unwrap();
                if let Err(e) =
                    db_guard.insert_dns_log(&device_ip, entry.domain, entry.query_type, now)
                {
                    error!(error = %e, device = %device_ip, domain = entry.domain, "failed to insert DNS log");
                }
            }

            // Send to log export channel
            let _ = tx.send(LogEvent::DnsQuery {
                device_ip: device_ip.clone(),
                domain: entry.domain.to_string(),
                query_type: entry.query_type.to_string(),
            });
        }
    }

    // Clean up ingest file
    if let Err(e) = std::fs::remove_file(&ingest_path) {
        warn!(error = %e, file = %ingest_path, "failed to remove ingest file");
    }
}

/// Ingest loop: scan Unbound query log every 30 seconds, parse and store DNS queries.
pub async fn start(db: Arc<Mutex<Db>>, tx: UnboundedSender<LogEvent>) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(SCAN_INTERVAL_SECS));

    loop {
        interval.tick().await;
        ingest_once(&db, &tx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_unbound_log_line() {
        let line = "[1709312345] unbound[1234:0] info: 10.0.1.2 example.com. A IN";
        let entry = parse_unbound_log_line(line).unwrap();
        assert_eq!(entry.client_ip, "10.0.1.2");
        assert_eq!(entry.domain, "example.com");
        assert_eq!(entry.query_type, "A");
    }

    #[test]
    fn test_parse_unbound_log_aaaa() {
        let line = "[1709312345] unbound[1234:0] info: 10.0.1.2 example.com. AAAA IN";
        let entry = parse_unbound_log_line(line).unwrap();
        assert_eq!(entry.query_type, "AAAA");
    }

    #[test]
    fn test_parse_unbound_log_strips_trailing_dot() {
        let line = "[1709312345] unbound[1234:0] info: 10.0.1.2 example.com. A IN";
        let entry = parse_unbound_log_line(line).unwrap();
        assert_eq!(entry.domain, "example.com");
    }

    #[test]
    fn test_parse_unbound_log_subdomain() {
        let line = "[1709312345] unbound[1234:0] info: 10.0.1.5 sub.domain.example.com. MX IN";
        let entry = parse_unbound_log_line(line).unwrap();
        assert_eq!(entry.client_ip, "10.0.1.5");
        assert_eq!(entry.domain, "sub.domain.example.com");
        assert_eq!(entry.query_type, "MX");
    }

    #[test]
    fn test_parse_unbound_log_invalid() {
        assert!(parse_unbound_log_line("").is_none());
        assert!(parse_unbound_log_line("some random text").is_none());
    }

    #[test]
    fn test_parse_unbound_log_ipv6_client() {
        let line =
            "[1709312345] unbound[1234:0] info: fd00::2 example.com. A IN";
        let entry = parse_unbound_log_line(line).unwrap();
        assert_eq!(entry.client_ip, "fd00::2");
        assert_eq!(entry.domain, "example.com");
    }
}
