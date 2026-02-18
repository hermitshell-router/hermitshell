use crate::db::Db;
use crate::log_export::LogEvent;

use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, error, warn};

const LOG_DIR: &str = "/data/hermitshell/blocky/logs";
const SCAN_INTERVAL_SECS: u64 = 30;

/// Extract the device IP from a Blocky csv-client log filename.
///
/// Blocky csv-client format: `YYYY-MM-DD_<client-ip>.log`
/// e.g. `2026-02-18_10.0.1.2.log` -> Some("10.0.1.2")
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

/// Parse a single CSV line from a Blocky query log.
///
/// Expected format: `questionName,questionType,responseCode`
/// e.g. `example.com,A,NOERROR` -> Some(("example.com", "A"))
fn parse_csv_line(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let mut parts = line.splitn(3, ',');
    let domain = parts.next()?;
    let query_type = parts.next()?;
    // We require at least the response code field to exist
    let _response_code = parts.next()?;
    if domain.is_empty() || query_type.is_empty() {
        return None;
    }
    Some((domain, query_type))
}

/// Ingest loop: scan Blocky CSV log files every 30 seconds, parse and store DNS queries.
pub async fn start(
    db: Arc<Mutex<Db>>,
    tx: UnboundedSender<LogEvent>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(SCAN_INTERVAL_SECS));

    loop {
        interval.tick().await;

        let entries = match std::fs::read_dir(LOG_DIR) {
            Ok(e) => e,
            Err(e) => {
                debug!(error = %e, dir = LOG_DIR, "cannot read log dir");
                continue;
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

            let device_ip = match extract_ip_from_filename(filename_str) {
                Some(ip) => ip.to_string(),
                None => {
                    debug!(file = filename_str, "skipping file: cannot extract IP");
                    continue;
                }
            };

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
                if let Some((domain, query_type)) = parse_csv_line(line) {
                    // Insert into database
                    {
                        let db_guard = db.lock().unwrap();
                        if let Err(e) = db_guard.insert_dns_log(&device_ip, domain, query_type, now) {
                            error!(error = %e, device = %device_ip, domain = domain, "failed to insert DNS log");
                        }
                    }

                    // Send to log export channel
                    let _ = tx.send(LogEvent::DnsQuery {
                        device_ip: device_ip.clone(),
                        domain: domain.to_string(),
                        query_type: query_type.to_string(),
                    });
                }
            }

            // Clean up ingest file
            if let Err(e) = std::fs::remove_file(&ingest_path) {
                warn!(error = %e, file = ?ingest_path, "failed to remove ingest file");
            }
        }
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
    fn test_parse_csv_line_valid() {
        assert_eq!(
            parse_csv_line("example.com,A,NOERROR"),
            Some(("example.com", "A"))
        );
    }

    #[test]
    fn test_parse_csv_line_empty() {
        assert_eq!(parse_csv_line(""), None);
    }

    #[test]
    fn test_parse_csv_line_missing_fields() {
        assert_eq!(parse_csv_line("example.com,A"), None);
    }

    #[test]
    fn test_parse_csv_line_aaaa_record() {
        assert_eq!(
            parse_csv_line("example.com,AAAA,NOERROR"),
            Some(("example.com", "AAAA"))
        );
    }
}
