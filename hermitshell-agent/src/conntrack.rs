use crate::db::Db;
use crate::log_export::LogEvent;

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{error, info, warn};

#[derive(Debug, Clone, PartialEq)]
pub enum EventType {
    New,
    Destroy,
}

#[derive(Debug, Clone)]
pub struct ConntrackEvent {
    pub event_type: EventType,
    pub protocol: String,
    pub src_ip: String,
    pub dst_ip: String,
    #[allow(dead_code)]
    pub src_port: u16,
    pub dst_port: u16,
    pub bytes_src: i64,
    pub bytes_dst: i64,
    pub timestamp: i64,
}

/// Parse a single conntrack event line into a ConntrackEvent.
///
/// Filters out:
/// - Events where src_ip does not start with "10." (non-LAN traffic)
/// - Events where dst_ip is the router itself
pub fn parse_event(line: &str, lan_ip: &str) -> Option<ConntrackEvent> {
    // Detect event type: [NEW] or [DESTROY]
    let event_type = if line.contains("[NEW]") {
        EventType::New
    } else if line.contains("[DESTROY]") {
        EventType::Destroy
    } else {
        return None;
    };

    // Extract protocol (tcp/udp/icmp) - appears as a standalone word
    let protocol = extract_protocol(line)?;

    // Parse key=value pairs from the line.
    // conntrack lines have two halves (src->dst and reply dst->src).
    // We want the FIRST occurrence of src, dst, sport, dport.
    let src_ip = extract_first_value(line, "src")?;
    let dst_ip = extract_first_value(line, "dst")?;

    let src_port = extract_first_value(line, "sport")
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let dst_port = extract_first_value(line, "dport")
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    // For DESTROY events, extract bytes counts.
    // First bytes= is src->dst, second bytes= is dst->src.
    let (bytes_src, bytes_dst) = if event_type == EventType::Destroy {
        extract_bytes_pair(line)
    } else {
        (0, 0)
    };

    // Filter: only LAN devices (within configured device range)
    if crate::nftables::validate_ip(&src_ip).is_err() {
        return None;
    }

    // Filter: ignore traffic to router itself
    if dst_ip == lan_ip {
        return None;
    }

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    Some(ConntrackEvent {
        event_type,
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        bytes_src,
        bytes_dst,
        timestamp,
    })
}

/// Extract protocol name from conntrack line.
/// Looks for known protocol names that appear as tokens in the line.
fn extract_protocol(line: &str) -> Option<String> {
    for token in line.split_whitespace() {
        match token {
            "tcp" | "udp" | "icmp" => return Some(token.to_string()),
            _ => {}
        }
    }
    None
}

/// Extract the first occurrence of `key=value` from the line.
fn extract_first_value(line: &str, key: &str) -> Option<String> {
    let prefix = format!("{}=", key);
    for token in line.split_whitespace() {
        if let Some(val) = token.strip_prefix(&prefix) {
            return Some(val.to_string());
        }
    }
    None
}

/// Extract the first two bytes= values from a DESTROY line.
/// Returns (src_to_dst_bytes, dst_to_src_bytes).
fn extract_bytes_pair(line: &str) -> (i64, i64) {
    let mut bytes_values = Vec::new();
    for token in line.split_whitespace() {
        if let Some(val) = token.strip_prefix("bytes=")
            && let Ok(n) = val.parse::<i64>() {
                bytes_values.push(n);
            }
    }
    let src = bytes_values.first().copied().unwrap_or(0);
    let dst = bytes_values.get(1).copied().unwrap_or(0);
    (src, dst)
}

/// Conntrack accounting is expected via sysctl.d drop-in (deploy/hermitshell.sysctl.conf).
pub fn enable_accounting() {
    info!("conntrack accounting expected via sysctl.d drop-in");
}

/// Spawn the conntrack event listener as a child process.
///
/// Runs `conntrack -E -e NEW,DESTROY -o timestamp` and reads its stdout
/// in a dedicated std::thread (blocking I/O). Each parsed event is inserted
/// into the database and sent to the log export channel.
///
/// Returns the Child handle (if spawn succeeded) so the caller can keep it alive.
pub fn start(
    db: Arc<Mutex<Db>>,
    tx: UnboundedSender<LogEvent>,
    lan_ip: String,
) -> Option<Child> {
    let mut child = match Command::new("conntrack")
        .args(["-E", "-e", "NEW,DESTROY", "-o", "timestamp"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "failed to spawn conntrack listener");
            return None;
        }
    };

    let stdout = child.stdout.take().expect("conntrack stdout piped");
    info!(pid = child.id(), "conntrack listener started");

    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    error!(error = %e, "conntrack stdout read error");
                    break;
                }
            };

            if let Some(ev) = parse_event(&line, &lan_ip) {
                let db_guard = db.lock().unwrap();
                match ev.event_type {
                    EventType::New => {
                        if let Err(e) = db_guard.insert_connection(
                            &ev.src_ip,
                            &ev.dst_ip,
                            ev.dst_port as i64,
                            &ev.protocol,
                            ev.timestamp,
                        ) {
                            error!(error = %e, "failed to insert connection");
                        }
                    }
                    EventType::Destroy => {
                        if let Err(e) = db_guard.update_connection_end(
                            &ev.src_ip,
                            &ev.dst_ip,
                            ev.dst_port as i64,
                            &ev.protocol,
                            ev.bytes_src,
                            ev.bytes_dst,
                            ev.timestamp,
                        ) {
                            error!(error = %e, "failed to update connection end");
                        }
                    }
                }
                drop(db_guard);

                let event_str = match ev.event_type {
                    EventType::New => "new",
                    EventType::Destroy => "destroy",
                };
                let _ = tx.send(LogEvent::Connection {
                    device_ip: ev.src_ip,
                    dest_ip: ev.dst_ip,
                    dest_port: ev.dst_port,
                    protocol: ev.protocol,
                    event: event_str.to_string(),
                    bytes_sent: ev.bytes_src,
                    bytes_recv: ev.bytes_dst,
                });
            }
        }
        warn!("conntrack reader thread exiting");
    });

    Some(child)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_new_tcp_event() {
        let line = "[1706000000.000000] [NEW] tcp      6 120 SYN_SENT src=10.0.1.2 dst=93.184.216.34 sport=54321 dport=443 [UNREPLIED] src=93.184.216.34 dst=10.0.1.2 sport=443 dport=54321";
        let ev = parse_event(line, "10.0.0.1").expect("should parse NEW tcp event");
        assert_eq!(ev.event_type, EventType::New);
        assert_eq!(ev.protocol, "tcp");
        assert_eq!(ev.src_ip, "10.0.1.2");
        assert_eq!(ev.dst_ip, "93.184.216.34");
        assert_eq!(ev.src_port, 54321);
        assert_eq!(ev.dst_port, 443);
        assert_eq!(ev.bytes_src, 0);
        assert_eq!(ev.bytes_dst, 0);
    }

    #[test]
    fn parse_destroy_with_bytes() {
        let line = "[1706000010.000000] [DESTROY] tcp      6 src=10.0.1.2 dst=93.184.216.34 sport=54321 dport=443 packets=10 bytes=1500 src=93.184.216.34 dst=10.0.1.2 sport=443 dport=54321 packets=8 bytes=12000";
        let ev = parse_event(line, "10.0.0.1").expect("should parse DESTROY event");
        assert_eq!(ev.event_type, EventType::Destroy);
        assert_eq!(ev.protocol, "tcp");
        assert_eq!(ev.src_ip, "10.0.1.2");
        assert_eq!(ev.dst_ip, "93.184.216.34");
        assert_eq!(ev.src_port, 54321);
        assert_eq!(ev.dst_port, 443);
        assert_eq!(ev.bytes_src, 1500);
        assert_eq!(ev.bytes_dst, 12000);
    }

    #[test]
    fn non_lan_source_filtered() {
        let line = "[1706000000.000000] [NEW] tcp      6 120 SYN_SENT src=192.168.1.5 dst=93.184.216.34 sport=12345 dport=80 [UNREPLIED] src=93.184.216.34 dst=192.168.1.5 sport=80 dport=12345";
        assert!(parse_event(line, "10.0.0.1").is_none(), "non-LAN source should be filtered");
    }

    #[test]
    fn router_destination_filtered() {
        let line = "[1706000000.000000] [NEW] tcp      6 120 SYN_SENT src=10.0.1.2 dst=10.0.0.1 sport=12345 dport=53 [UNREPLIED] src=10.0.0.1 dst=10.0.1.2 sport=53 dport=12345";
        assert!(parse_event(line, "10.0.0.1").is_none(), "traffic to router should be filtered");
    }

    #[test]
    fn parse_udp_event() {
        let line = "[1706000000.000000] [NEW] udp      17 30 src=10.0.2.1 dst=1.1.1.1 sport=5000 dport=53 [UNREPLIED] src=1.1.1.1 dst=10.0.2.1 sport=53 dport=5000";
        let ev = parse_event(line, "10.0.0.1").expect("should parse UDP event");
        assert_eq!(ev.protocol, "udp");
        assert_eq!(ev.src_ip, "10.0.2.1");
        assert_eq!(ev.dst_ip, "1.1.1.1");
        assert_eq!(ev.src_port, 5000);
        assert_eq!(ev.dst_port, 53);
    }

    #[test]
    fn unknown_event_type_returns_none() {
        let line = "[1706000000.000000] [UPDATE] tcp      6 120 src=10.0.1.2 dst=8.8.8.8 sport=1234 dport=443";
        assert!(parse_event(line, "10.0.0.1").is_none(), "UPDATE events should be ignored");
    }
}
