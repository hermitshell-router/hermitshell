use crate::db::Db;
use crate::log_export::LogEvent;
use crate::paths;

use std::io::{Read, Seek};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, error};

fn log_file() -> String {
    format!("{}/query.log", paths::unbound_dir())
}
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
///
/// Older Unbound versions (e.g. 1.13 on Ubuntu 22.04) don't reopen the
/// logfile after a rename — they keep writing to the old fd.  We read the
/// file and track how far we've consumed using a persistent offset.
pub fn ingest_once(db: &Arc<Mutex<Db>>, tx: &UnboundedSender<LogEvent>) {
    let log_path = log_file();
    let offset_path = format!("{}.offset", log_path);

    // Read saved offset (byte position of last-consumed data)
    let offset: u64 = std::fs::read_to_string(&offset_path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);

    let mut file = match std::fs::File::open(&log_path) {
        Ok(f) => f,
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                debug!(error = %e, file = %log_path, "cannot open log file");
            }
            return;
        }
    };

    // If file is smaller than our offset, it was recreated (agent restart)
    let meta = match file.metadata() {
        Ok(m) => m,
        Err(_) => return,
    };
    let file_len = meta.len();
    let seek_to = if file_len < offset { 0 } else { offset };

    if file_len == seek_to {
        // No new data
        return;
    }

    if let Err(e) = file.seek(std::io::SeekFrom::Start(seek_to)) {
        error!(error = %e, "failed to seek log file");
        return;
    }

    let mut contents = String::new();
    if let Err(e) = file.read_to_string(&mut contents) {
        error!(error = %e, file = %log_path, "failed to read log file");
        return;
    }

    if contents.is_empty() {
        return;
    }

    // Save new offset
    let new_offset = seek_to + contents.len() as u64;
    let _ = std::fs::write(&offset_path, new_offset.to_string());

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
