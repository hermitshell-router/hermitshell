use crate::db::Db;

use std::io::{BufRead, BufReader, Write as IoWrite};
use std::net::{TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::{error, info};

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
}

/// Convert epoch seconds to ISO 8601 date-time string (UTC).
fn epoch_to_iso8601(epoch_secs: u64) -> String {
    let secs_per_day: u64 = 86400;
    let days = epoch_secs / secs_per_day;
    let time_of_day = epoch_secs % secs_per_day;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Convert days since epoch (1970-01-01) to Y-M-D
    let (year, month, day) = days_to_ymd(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
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

fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl LogEvent {
    /// Serialize event to JSON for webhook batching.
    pub fn to_json(&self) -> serde_json::Value {
        let ts = epoch_to_iso8601(now_epoch_secs());
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
        }
    }

    /// Format as RFC 5424 syslog structured data message.
    pub fn to_syslog(&self, hostname: &str) -> String {
        let ts = epoch_to_iso8601(now_epoch_secs());
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
                    "<14>1 {} {} hermitshell-agent - connection [conn device_ip=\"{}\" dest_ip=\"{}\" dest_port=\"{}\" protocol=\"{}\" event=\"{}\" bytes_sent=\"{}\" bytes_recv=\"{}\"]",
                    ts, hostname, device_ip, dest_ip, dest_port, protocol, event, bytes_sent, bytes_recv
                )
            }
            LogEvent::DnsQuery {
                device_ip,
                domain,
                query_type,
            } => {
                format!(
                    "<14>1 {} {} hermitshell-agent - dns [query device_ip=\"{}\" domain=\"{}\" query_type=\"{}\"]",
                    ts, hostname, device_ip, domain, query_type
                )
            }
        }
    }
}

/// Parse a syslog target string like "udp://192.168.1.100:514" into addr:port.
fn parse_syslog_target(target: &str) -> Option<String> {
    target.strip_prefix("udp://").map(|s| s.to_string())
}

/// Send a JSON array payload via HTTP POST to the given URL (fire-and-forget).
/// URL format: "http://host:port/path" or "http://host/path"
fn webhook_post(url: &str, payload: &str) {
    let url = url.strip_prefix("http://").unwrap_or(url);
    let url = url.strip_prefix("https://").unwrap_or(url);

    let (host_port, path) = match url.find('/') {
        Some(i) => (&url[..i], &url[i..]),
        None => (url, "/"),
    };

    let Ok(mut stream) = TcpStream::connect(host_port) else {
        error!(target = host_port, "webhook connect failed");
        return;
    };
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));

    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path, host_port, payload.len(), payload
    );
    if stream.write_all(request.as_bytes()).is_err() {
        error!(target = host_port, "webhook write failed");
        return;
    }
    let _ = stream.flush();

    // Read response status line (fire-and-forget, but drain to avoid RST)
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    let _ = reader.read_line(&mut line);
}

/// Get system hostname for syslog messages.
fn get_hostname() -> String {
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
    let mut webhook_batch: Vec<serde_json::Value> = Vec::new();
    let mut last_config_refresh = std::time::Instant::now();
    let mut last_webhook_flush = std::time::Instant::now();

    // Initial config load
    refresh_config(&db, &mut syslog_addr, &mut webhook_url);

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
                        flush_webhook(&webhook_url, &mut webhook_batch);
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
            flush_webhook(&webhook_url, &mut webhook_batch);
            last_webhook_flush = std::time::Instant::now();
        }

        // Refresh config every 30 seconds
        if last_config_refresh.elapsed() >= Duration::from_secs(30) {
            refresh_config(&db, &mut syslog_addr, &mut webhook_url);
            last_config_refresh = std::time::Instant::now();
        }
    }
}

fn refresh_config(
    db: &Arc<Mutex<Db>>,
    syslog_addr: &mut Option<String>,
    webhook_url: &mut Option<String>,
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
    }
}

fn send_syslog(addr: &str, event: &LogEvent, hostname: &str) {
    let msg = event.to_syslog(hostname);
    match UdpSocket::bind("0.0.0.0:0") {
        Ok(sock) => {
            let _ = sock.send_to(msg.as_bytes(), addr);
        }
        Err(e) => {
            error!(error = %e, "failed to bind UDP socket for syslog");
        }
    }
}

fn flush_webhook(webhook_url: &Option<String>, batch: &mut Vec<serde_json::Value>) {
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
    std::thread::spawn(move || {
        webhook_post(&url, &payload);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_to_iso8601() {
        // 2024-01-01T00:00:00Z = 1704067200
        assert_eq!(epoch_to_iso8601(1704067200), "2024-01-01T00:00:00Z");
    }

    #[test]
    fn test_epoch_to_iso8601_with_time() {
        // 2024-06-15T12:45:30Z = 1718455530
        assert_eq!(epoch_to_iso8601(1718455530), "2024-06-15T12:45:30Z");
    }

    #[test]
    fn test_epoch_zero() {
        assert_eq!(epoch_to_iso8601(0), "1970-01-01T00:00:00Z");
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
        assert!(msg.contains("domain=\"example.com\""));
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
}
