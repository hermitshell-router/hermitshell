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
