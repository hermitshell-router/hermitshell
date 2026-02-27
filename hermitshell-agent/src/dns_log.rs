use crate::db::Db;
use crate::log_export::LogEvent;

use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, error, warn};

const LOG_DIR: &str = "/var/lib/hermitshell/blocky/logs";
const SCAN_INTERVAL_SECS: u64 = 30;

/// Extract the device IP from a Blocky csv-client log filename.
///
/// Blocky csv-client format: `YYYY-MM-DD_<client-ip>.log`
/// e.g. `2026-02-18_10.0.1.2.log` -> Some("10.0.1.2")
/// Blocky v0.24 may write `_none.log` when client identification fails.
fn extract_ip_from_filename(filename: &str) -> Option<&str> {
    let stem = filename.strip_suffix(".log")?;
    let (_date, ip) = stem.split_once('_')?;
    // Basic validation: must contain at least one dot and only digits/dots
    if ip.is_empty() || !ip.contains('.') {
        return None;
    }
    if !ip.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return None;
    }
    Some(ip)
}

/// Parsed DNS log entry from a blocky log line.
struct DnsLogEntry<'a> {
    client_ip: &'a str,
    domain: &'a str,
    query_type: &'a str,
}

/// Parse a single line from a Blocky query log (TSV format).
///
/// Blocky v0.24 writes TSV with all fields regardless of `fields` config:
/// `timestamp\tclient_ip\tclient_name\tduration_ms\tresponse_reason\tdomain\t\tresponse_code\tresponse_type\tquery_type\tclient_group`
///
/// Falls back to CSV format (3 comma-separated fields) for compatibility.
fn parse_log_line(line: &str) -> Option<DnsLogEntry<'_>> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    // Try TSV format first (blocky v0.24 actual output)
    let parts: Vec<&str> = line.split('\t').collect();
    if parts.len() >= 10 {
        let client_ip = parts[1];
        let domain = parts[5].trim_end_matches('.');
        let query_type = parts[9];
        if !domain.is_empty() {
            return Some(DnsLogEntry { client_ip, domain, query_type });
        }
    }

    // Fallback: CSV format (question,responseReason,duration)
    let mut csv_parts = line.splitn(3, ',');
    let domain = csv_parts.next()?;
    let response_reason = csv_parts.next()?;
    let _duration = csv_parts.next()?;
    if domain.is_empty() || response_reason.is_empty() {
        return None;
    }
    Some(DnsLogEntry { client_ip: "", domain, query_type: response_reason })
}

/// Run one ingest cycle: scan Blocky log files, parse and store DNS queries.
pub fn ingest_once(db: &Arc<Mutex<Db>>, tx: &UnboundedSender<LogEvent>) {
    let entries = match std::fs::read_dir(LOG_DIR) {
        Ok(e) => e,
        Err(e) => {
            debug!(error = %e, dir = LOG_DIR, "cannot read log dir");
            return;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let filename = entry.file_name();
        let filename_str = match filename.to_str() {
            Some(s) => s,
            None => continue,
        };

        // Only process .log files (skip .ingest files and others)
        if !filename_str.ends_with(".log") {
            continue;
        }

        // Extract device IP from filename (may be None for _none.log files)
        let filename_ip = extract_ip_from_filename(filename_str).map(|s| s.to_string());

        let log_path = entry.path();
        let ingest_path = log_path.with_extension("log.ingest");

        // Atomic rename: Blocky opens/closes per write, so this is safe
        if let Err(e) = std::fs::rename(&log_path, &ingest_path) {
            warn!(error = %e, file = ?log_path, "failed to rename log file");
            continue;
        }

        let contents = match std::fs::read_to_string(&ingest_path) {
            Ok(c) => c,
            Err(e) => {
                error!(error = %e, file = ?ingest_path, "failed to read ingest file");
                continue;
            }
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        for line in contents.lines() {
            if let Some(entry) = parse_log_line(line) {
                // Use client IP from log line, fall back to filename IP
                let device_ip = if !entry.client_ip.is_empty()
                    && entry.client_ip != "0.0.0.0"
                    && entry.client_ip.contains('.')
                {
                    entry.client_ip.to_string()
                } else if let Some(ref ip) = filename_ip {
                    ip.clone()
                } else {
                    // No device IP available; store with empty string
                    String::new()
                };

                // Insert into database
                {
                    let db_guard = db.lock().unwrap();
                    if let Err(e) = db_guard.insert_dns_log(&device_ip, entry.domain, entry.query_type, now) {
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
            warn!(error = %e, file = ?ingest_path, "failed to remove ingest file");
        }
    }
}

/// Ingest loop: scan Blocky CSV log files every 30 seconds, parse and store DNS queries.
pub async fn start(
    db: Arc<Mutex<Db>>,
    tx: UnboundedSender<LogEvent>,
) {
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
    fn test_extract_ip_from_filename_valid() {
        assert_eq!(
            extract_ip_from_filename("2026-02-18_10.0.1.2.log"),
            Some("10.0.1.2")
        );
    }

    #[test]
    fn test_extract_ip_from_filename_no_match() {
        assert_eq!(extract_ip_from_filename("config.yml"), None);
    }

    #[test]
    fn test_extract_ip_from_filename_no_underscore() {
        assert_eq!(extract_ip_from_filename("nounderscore.log"), None);
    }

    #[test]
    fn test_extract_ip_from_filename_empty_ip() {
        assert_eq!(extract_ip_from_filename("2026-02-18_.log"), None);
    }

    #[test]
    fn test_extract_ip_from_filename_none() {
        // Blocky v0.24 writes _none.log when client identification fails
        assert_eq!(extract_ip_from_filename("2026-02-20_none.log"), None);
    }

    #[test]
    fn test_parse_log_line_tsv() {
        let line = "2026-02-20 16:45:33\t10.0.1.2\tnone\t10\tRESOLVED (tcp+udp:192.168.100.2)\texample.com.\t\tNOERROR\tRESOLVED\tA\trouter";
        let entry = parse_log_line(line).unwrap();
        assert_eq!(entry.client_ip, "10.0.1.2");
        assert_eq!(entry.domain, "example.com");
        assert_eq!(entry.query_type, "A");
    }

    #[test]
    fn test_parse_log_line_tsv_zero_ip() {
        let line = "2026-02-20 16:45:33\t0.0.0.0\tnone\t10\tRESOLVED\texample.com.\t\tNOERROR\tRESOLVED\tA\trouter";
        let entry = parse_log_line(line).unwrap();
        assert_eq!(entry.client_ip, "0.0.0.0");
        assert_eq!(entry.domain, "example.com");
        assert_eq!(entry.query_type, "A");
    }

    #[test]
    fn test_parse_log_line_csv_fallback() {
        let entry = parse_log_line("example.com,NOERROR,1.234ms").unwrap();
        assert_eq!(entry.domain, "example.com");
        assert_eq!(entry.query_type, "NOERROR");
    }

    #[test]
    fn test_parse_log_line_empty() {
        assert!(parse_log_line("").is_none());
    }

    #[test]
    fn test_parse_log_line_csv_missing_fields() {
        assert!(parse_log_line("example.com,NOERROR").is_none());
    }

    #[test]
    fn test_parse_log_line_strips_trailing_dot() {
        let line = "2026-02-20 16:45:33\t10.0.1.2\tnone\t10\tRESOLVED\texample.com.\t\tNOERROR\tRESOLVED\tAAAA\trouter";
        let entry = parse_log_line(line).unwrap();
        assert_eq!(entry.domain, "example.com");
        assert_eq!(entry.query_type, "AAAA");
    }
}
