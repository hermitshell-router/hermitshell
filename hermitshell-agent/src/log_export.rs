use crate::db::Db;

use std::net::UdpSocket;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::{error, info};
use zeroize::Zeroizing;

#[derive(Debug, Clone)]
pub enum LogEvent {
    Connection {
        device_ip: String,
        dest_ip: String,
        dest_port: u16,
        protocol: String,
        event: String,
        bytes_sent: i64,
        bytes_recv: i64,
    },
    DnsQuery {
        device_ip: String,
        domain: String,
        query_type: String,
    },
    Alert {
        device_mac: String,
        rule: String,
        severity: String,
        message: String,
        details: Option<String>,
    },
}

/// Escape characters required by RFC 5424 §6.3.3 for SD-PARAM values.
fn escape_sd_param(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            ']' => escaped.push_str("\\]"),
            _ => escaped.push(c),
        }
    }
    escaped
}

/// Convert epoch seconds + microseconds to ISO 8601 date-time string (UTC).
fn epoch_to_iso8601(epoch_secs: u64, micros: u32) -> String {
    let secs_per_day: u64 = 86400;
    let days = epoch_secs / secs_per_day;
    let time_of_day = epoch_secs % secs_per_day;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Convert days since epoch (1970-01-01) to Y-M-D
    let (year, month, day) = days_to_ymd(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
        year, month, day, hours, minutes, seconds, micros
    )
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm based on civil_from_days (Howard Hinnant)
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn now_timestamp() -> (u64, u32) {
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    (dur.as_secs(), dur.subsec_micros())
}

impl LogEvent {
    /// Serialize event to JSON for webhook batching.
    pub fn to_json(&self) -> serde_json::Value {
        let (secs, micros) = now_timestamp();
        let ts = epoch_to_iso8601(secs, micros);
        match self {
            LogEvent::Connection {
                device_ip,
                dest_ip,
                dest_port,
                protocol,
                event,
                bytes_sent,
                bytes_recv,
            } => serde_json::json!({
                "type": "connection",
                "timestamp": ts,
                "device_ip": device_ip,
                "dest_ip": dest_ip,
                "dest_port": dest_port,
                "protocol": protocol,
                "event": event,
                "bytes_sent": bytes_sent,
                "bytes_recv": bytes_recv,
            }),
            LogEvent::DnsQuery {
                device_ip,
                domain,
                query_type,
            } => serde_json::json!({
                "type": "dns_query",
                "timestamp": ts,
                "device_ip": device_ip,
                "domain": domain,
                "query_type": query_type,
            }),
            LogEvent::Alert {
                device_mac,
                rule,
                severity,
                message,
                details,
            } => {
                let mut json = serde_json::json!({
                    "type": "alert",
                    "timestamp": ts,
                    "device_mac": device_mac,
                    "rule": rule,
                    "severity": severity,
                    "message": message,
                });
                if let Some(d) = details
                    && let Ok(parsed) = serde_json::from_str::<serde_json::Value>(d) {
                        json["details"] = parsed;
                    }
                json
            },
        }
    }

    /// Format as RFC 5424 syslog structured data message.
    pub fn to_syslog(&self, hostname: &str) -> String {
        let (secs, micros) = now_timestamp();
        let ts = epoch_to_iso8601(secs, micros);
        match self {
            LogEvent::Connection {
                device_ip,
                dest_ip,
                dest_port,
                protocol,
                event,
                bytes_sent,
                bytes_recv,
            } => {
                format!(
                    "<14>1 {} {} hermitshell-agent - connection [conn@hermitshell device_ip=\"{}\" dest_ip=\"{}\" dest_port=\"{}\" protocol=\"{}\" event=\"{}\" bytes_sent=\"{}\" bytes_recv=\"{}\"]",
                    ts, hostname,
                    escape_sd_param(device_ip),
                    escape_sd_param(dest_ip),
                    dest_port,
                    escape_sd_param(protocol),
                    escape_sd_param(event),
                    bytes_sent,
                    bytes_recv
                )
            }
            LogEvent::DnsQuery {
                device_ip,
                domain,
                query_type,
            } => {
                format!(
                    "<14>1 {} {} hermitshell-agent - dns [query@hermitshell device_ip=\"{}\" domain=\"{}\" query_type=\"{}\"]",
                    ts, hostname,
                    escape_sd_param(device_ip),
                    escape_sd_param(domain),
                    escape_sd_param(query_type)
                )
            }
            LogEvent::Alert {
                device_mac,
                rule,
                severity,
                message,
                ..
            } => {
                let pri = match severity.as_str() {
                    "high" => 11,
                    "medium" => 12,
                    "low" => 13,
                    _ => 14,
                };
                format!(
                    "<{}>1 {} {} hermitshell-agent - alert [alert@hermitshell device_mac=\"{}\" rule=\"{}\" severity=\"{}\" message=\"{}\"]",
                    pri, ts, hostname,
                    escape_sd_param(device_mac),
                    escape_sd_param(rule),
                    escape_sd_param(severity),
                    escape_sd_param(message)
                )
            },
        }
    }
}

/// Parse a syslog target string like "udp://192.168.1.100:514" into addr:port.
fn parse_syslog_target(target: &str) -> Option<String> {
    target.strip_prefix("udp://").map(|s| s.to_string())
}

/// Send a JSON array payload via HTTP(S) POST to the given URL (fire-and-forget).
/// Supports HTTPS with certificate validation. Includes Bearer auth if secret is set.
async fn webhook_post(url: &str, payload: String, secret: &str) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "webhook client build failed");
            return;
        }
    };

    let mut req = client
        .post(url)
        .header("Content-Type", "application/json")
        .body(payload);

    if !secret.is_empty() {
        req = req.header("Authorization", format!("Bearer {}", secret));
    }

    match req.send().await {
        Ok(resp) => {
            if !resp.status().is_success() {
                error!(status = %resp.status(), url, "webhook POST failed");
            }
        }
        Err(e) => {
            error!(error = %e, url, "webhook POST failed");
        }
    }
}

/// Get system hostname for syslog messages.
/// Per RFC 5424 §6.2.4, FQDN is preferred over bare hostname.
fn get_hostname() -> String {
    // Try FQDN first
    if let Ok(output) = std::process::Command::new("hostname").arg("--fqdn").output()
        && output.status.success() {
            let fqdn = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !fqdn.is_empty() && fqdn.contains('.') {
                return fqdn;
            }
        }
    // Fall back to bare hostname
    std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "hermitshell".to_string())
        .trim()
        .to_string()
}

/// Main dispatcher loop: reads events from the channel and dispatches to
/// configured sinks (tracing/stdout, syslog UDP, webhook HTTP POST).
pub async fn start(
    db: Arc<Mutex<Db>>,
    mut rx: UnboundedReceiver<LogEvent>,
) {
    let hostname = get_hostname();
    let mut syslog_addr: Option<String> = None;
    let mut webhook_url: Option<String> = None;
    let mut webhook_secret: Zeroizing<String> = Zeroizing::new(String::new());
    let mut webhook_batch: Vec<serde_json::Value> = Vec::new();
    let mut last_config_refresh = std::time::Instant::now();
    let mut last_webhook_flush = std::time::Instant::now();

    // Initial config load
    refresh_config(&db, &mut syslog_addr, &mut webhook_url, &mut webhook_secret);

    loop {
        // Use a short timeout to enable periodic webhook flushing
        let event = tokio::time::timeout(Duration::from_secs(1), rx.recv()).await;

        match event {
            Ok(Some(event)) => {
                // Emit structured tracing (appears on stdout, JSON if log_format=json)
                emit_tracing(&event);

                // Syslog sink
                if let Some(ref addr) = syslog_addr {
                    send_syslog(addr, &event, &hostname);
                }

                // Webhook batching
                if webhook_url.is_some() {
                    webhook_batch.push(event.to_json());
                    if webhook_batch.len() >= 100 {
                        flush_webhook(&webhook_url, &webhook_secret, &mut webhook_batch);
                        last_webhook_flush = std::time::Instant::now();
                    }
                }
            }
            Ok(None) => {
                // Channel closed, exit
                break;
            }
            Err(_) => {
                // Timeout — check if we need to flush webhook batch
            }
        }

        // Flush webhook batch if 10 seconds have passed
        if !webhook_batch.is_empty() && last_webhook_flush.elapsed() >= Duration::from_secs(10) {
            flush_webhook(&webhook_url, &webhook_secret, &mut webhook_batch);
            last_webhook_flush = std::time::Instant::now();
        }

        // Refresh config every 30 seconds
        if last_config_refresh.elapsed() >= Duration::from_secs(30) {
            refresh_config(&db, &mut syslog_addr, &mut webhook_url, &mut webhook_secret);
            last_config_refresh = std::time::Instant::now();
        }
    }
}

fn refresh_config(
    db: &Arc<Mutex<Db>>,
    syslog_addr: &mut Option<String>,
    webhook_url: &mut Option<String>,
    webhook_secret: &mut Zeroizing<String>,
) {
    let db_guard = db.lock().unwrap();
    *syslog_addr = db_guard
        .get_config("syslog_target")
        .ok()
        .flatten()
        .and_then(|v| parse_syslog_target(&v));
    *webhook_url = db_guard
        .get_config("webhook_url")
        .ok()
        .flatten()
        .filter(|v| !v.is_empty());
    *webhook_secret = Zeroizing::new(db_guard
        .get_config("webhook_secret")
        .ok()
        .flatten()
        .unwrap_or_default());
}

fn emit_tracing(event: &LogEvent) {
    match event {
        LogEvent::Connection {
            device_ip,
            dest_ip,
            dest_port,
            protocol,
            event,
            bytes_sent,
            bytes_recv,
        } => {
            info!(
                log_type = "connection",
                device_ip = %device_ip,
                dest_ip = %dest_ip,
                dest_port = dest_port,
                protocol = %protocol,
                event = %event,
                bytes_sent = bytes_sent,
                bytes_recv = bytes_recv,
                "log_export"
            );
        }
        LogEvent::DnsQuery {
            device_ip,
            domain,
            query_type,
        } => {
            info!(
                log_type = "dns_query",
                device_ip = %device_ip,
                domain = %domain,
                query_type = %query_type,
                "log_export"
            );
        }
        LogEvent::Alert {
            device_mac,
            rule,
            severity,
            message,
            ..
        } => {
            info!(device_mac, rule, severity, message, "alert");
        }
    }
}

/// RFC 5426 §3.2: senders SHOULD restrict UDP syslog messages to 480 octets.
const SYSLOG_UDP_MAX_BYTES: usize = 480;

fn send_syslog(addr: &str, event: &LogEvent, hostname: &str) {
    let msg = event.to_syslog(hostname);
    let bytes = msg.as_bytes();
    let payload = if bytes.len() > SYSLOG_UDP_MAX_BYTES {
        let mut truncate_at = SYSLOG_UDP_MAX_BYTES;
        while truncate_at > 0 && !msg.is_char_boundary(truncate_at) {
            truncate_at -= 1;
        }
        &bytes[..truncate_at]
    } else {
        bytes
    };
    match UdpSocket::bind("0.0.0.0:0") {
        Ok(sock) => {
            let _ = sock.send_to(payload, addr);
        }
        Err(e) => {
            error!(error = %e, "failed to bind UDP socket for syslog");
        }
    }
}

fn flush_webhook(webhook_url: &Option<String>, webhook_secret: &str, batch: &mut Vec<serde_json::Value>) {
    if batch.is_empty() {
        return;
    }
    let Some(url) = webhook_url else {
        batch.clear();
        return;
    };
    let payload = serde_json::to_string(&batch).unwrap_or_else(|_| "[]".to_string());
    batch.clear();

    let url = url.clone();
    let secret = webhook_secret.to_string();
    tokio::spawn(async move {
        webhook_post(&url, payload, &secret).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_to_iso8601() {
        // 2024-01-01T00:00:00.000000Z = 1704067200
        assert_eq!(epoch_to_iso8601(1704067200, 0), "2024-01-01T00:00:00.000000Z");
    }

    #[test]
    fn test_epoch_to_iso8601_with_time() {
        // 2024-06-15T12:45:30.123456Z = 1718455530
        assert_eq!(epoch_to_iso8601(1718455530, 123456), "2024-06-15T12:45:30.123456Z");
    }

    #[test]
    fn test_epoch_zero() {
        assert_eq!(epoch_to_iso8601(0, 0), "1970-01-01T00:00:00.000000Z");
    }

    #[test]
    fn test_parse_syslog_target_valid() {
        assert_eq!(
            parse_syslog_target("udp://192.168.1.100:514"),
            Some("192.168.1.100:514".to_string())
        );
    }

    #[test]
    fn test_parse_syslog_target_invalid() {
        assert_eq!(parse_syslog_target("tcp://192.168.1.100:514"), None);
    }

    #[test]
    fn test_connection_event_to_json() {
        let event = LogEvent::Connection {
            device_ip: "10.0.1.2".to_string(),
            dest_ip: "1.2.3.4".to_string(),
            dest_port: 443,
            protocol: "tcp".to_string(),
            event: "new".to_string(),
            bytes_sent: 1024,
            bytes_recv: 2048,
        };
        let json = event.to_json();
        assert_eq!(json["type"], "connection");
        assert_eq!(json["device_ip"], "10.0.1.2");
        assert_eq!(json["dest_port"], 443);
        assert_eq!(json["bytes_sent"], 1024);
    }

    #[test]
    fn test_dns_event_to_json() {
        let event = LogEvent::DnsQuery {
            device_ip: "10.0.1.2".to_string(),
            domain: "example.com".to_string(),
            query_type: "A".to_string(),
        };
        let json = event.to_json();
        assert_eq!(json["type"], "dns_query");
        assert_eq!(json["domain"], "example.com");
    }

    #[test]
    fn test_connection_event_to_syslog() {
        let event = LogEvent::Connection {
            device_ip: "10.0.1.2".to_string(),
            dest_ip: "1.2.3.4".to_string(),
            dest_port: 443,
            protocol: "tcp".to_string(),
            event: "new".to_string(),
            bytes_sent: 1024,
            bytes_recv: 2048,
        };
        let msg = event.to_syslog("router1");
        assert!(msg.starts_with("<14>1 "));
        assert!(msg.contains("router1"));
        assert!(msg.contains("hermitshell-agent"));
        assert!(msg.contains("[conn@hermitshell "));
        assert!(msg.contains("device_ip=\"10.0.1.2\""));
    }

    #[test]
    fn test_dns_event_to_syslog() {
        let event = LogEvent::DnsQuery {
            device_ip: "10.0.1.2".to_string(),
            domain: "example.com".to_string(),
            query_type: "A".to_string(),
        };
        let msg = event.to_syslog("router1");
        assert!(msg.starts_with("<14>1 "));
        assert!(msg.contains("[query@hermitshell "));
        assert!(msg.contains("domain=\"example.com\""));
    }

    #[test]
    fn test_alert_event_to_syslog() {
        let event = LogEvent::Alert {
            device_mac: "aa:bb:cc:dd:ee:ff".to_string(),
            rule: "port_scan".to_string(),
            severity: "high".to_string(),
            message: "Port scan detected".to_string(),
            details: None,
        };
        let msg = event.to_syslog("router1");
        assert!(msg.starts_with("<11>1 "));
        assert!(msg.contains("hermitshell-agent"));
        assert!(msg.contains("[alert@hermitshell "));
        assert!(msg.contains("device_mac=\"aa:bb:cc:dd:ee:ff\""));
    }

    #[test]
    fn test_alert_low_severity_maps_to_notice() {
        let event = LogEvent::Alert {
            device_mac: "aa:bb:cc:dd:ee:ff".to_string(),
            rule: "test".to_string(),
            severity: "low".to_string(),
            message: "test".to_string(),
            details: None,
        };
        let msg = event.to_syslog("router1");
        assert!(msg.starts_with("<13>1 "), "low severity should map to pri 13 (user.notice)");
    }

    #[test]
    fn test_escape_sd_param() {
        assert_eq!(escape_sd_param("simple"), "simple");
        assert_eq!(escape_sd_param(r#"has "quotes""#), r#"has \"quotes\""#);
        assert_eq!(escape_sd_param(r"back\slash"), r"back\\slash");
        assert_eq!(escape_sd_param("close]bracket"), r"close\]bracket");
        assert_eq!(escape_sd_param(r#"all"\]three"#), r#"all\"\\\]three"#);
    }

    #[test]
    fn test_syslog_escapes_domain() {
        let event = LogEvent::DnsQuery {
            device_ip: "10.0.1.2".to_string(),
            domain: r#"evil".example.com"#.to_string(),
            query_type: "A".to_string(),
        };
        let msg = event.to_syslog("router1");
        assert!(msg.contains(r#"domain="evil\".example.com""#));
    }

    #[test]
    fn test_timestamp_has_fractional_seconds() {
        assert_eq!(
            epoch_to_iso8601(1704067200, 500000),
            "2024-01-01T00:00:00.500000Z"
        );
    }

    #[test]
    fn test_days_to_ymd_epoch() {
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
    }

    #[test]
    fn test_days_to_ymd_leap_year() {
        // 2024-02-29 is day 19782 from epoch
        assert_eq!(days_to_ymd(19782), (2024, 2, 29));
    }

    #[test]
    fn test_days_to_ymd_end_of_year() {
        // 2023-12-31 is day 19722
        assert_eq!(days_to_ymd(19722), (2023, 12, 31));
    }

    #[test]
    fn test_syslog_truncation_respects_utf8() {
        // Build a syslog message that exceeds 480 bytes by using multi-byte chars
        // in the domain field. Each '€' is 3 bytes in UTF-8.
        let long_domain = "€".repeat(200); // 600 bytes of UTF-8
        let event = LogEvent::DnsQuery {
            device_ip: "10.0.1.2".to_string(),
            domain: long_domain,
            query_type: "A".to_string(),
        };
        let msg = event.to_syslog("router1");
        assert!(msg.as_bytes().len() > SYSLOG_UDP_MAX_BYTES);

        // Truncate like send_syslog does
        let bytes = msg.as_bytes();
        let mut truncate_at = SYSLOG_UDP_MAX_BYTES;
        while truncate_at > 0 && !msg.is_char_boundary(truncate_at) {
            truncate_at -= 1;
        }
        let truncated = &bytes[..truncate_at];

        // Must be valid UTF-8
        assert!(std::str::from_utf8(truncated).is_ok());
        // Must not exceed limit
        assert!(truncated.len() <= SYSLOG_UDP_MAX_BYTES);
    }
}
