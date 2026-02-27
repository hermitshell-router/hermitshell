mod analyzer;
mod blocky;
mod conntrack;
mod crypto;
mod db;
mod dns_log;
mod log_export;
mod mdns;
mod natpmp;
mod nftables;
mod pd;
mod portmap;
mod qos;
mod ra;
mod socket;
mod tls;
mod tls_client;
mod update;
mod upnp;
mod runzero;
mod wifi;
mod wireguard;

use hermitshell_common::subnet;

use anyhow::Result;
use std::io::{BufRead, BufReader, Write};
use std::net::Ipv4Addr;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use tracing::{debug, error, info, warn};

/// Read nameservers from WAN DHCP lease, then /etc/resolv.conf, falling back to public DNS.
fn read_upstream_dns(wan_iface: &str) -> Vec<Ipv4Addr> {
    // Prefer DNS from WAN DHCP lease (most accurate for a router)
    let lease_path = format!("/var/lib/dhcp/dhclient.{}.leases", wan_iface);
    if let Ok(content) = std::fs::read_to_string(&lease_path) {
        // Parse last "option domain-name-servers" line (most recent lease)
        if let Some(line) = content.lines().rev().find(|l| l.contains("option domain-name-servers")) {
            let servers: Vec<Ipv4Addr> = line
                .split("domain-name-servers")
                .nth(1)
                .unwrap_or("")
                .trim()
                .trim_end_matches(';')
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            if !servers.is_empty() {
                return servers;
            }
        }
    }

    // Fall back to /etc/resolv.conf
    let content = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let servers: Vec<Ipv4Addr> = content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with("nameserver") {
                let ip: Ipv4Addr = line.split_whitespace().nth(1)?.parse().ok()?;
                // Skip systemd-resolved stub
                if ip == Ipv4Addr::new(127, 0, 0, 53) {
                    None
                } else {
                    Some(ip)
                }
            } else {
                None
            }
        })
        .collect();
    if servers.is_empty() {
        vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)]
    } else {
        servers
    }
}

const DB_PATH: &str = "/var/lib/hermitshell/hermitshell.db";
const SOCKET_PATH: &str = "/run/hermitshell/agent.sock";
const POLL_INTERVAL_SECS: u64 = 10;

/// Send a JSON request to the agent socket and return the parsed response.
fn socket_request(req: &serde_json::Value) -> Result<serde_json::Value, String> {
    let mut stream = UnixStream::connect(SOCKET_PATH)
        .map_err(|e| format!("failed to connect to {}: {}", SOCKET_PATH, e))?;
    let mut payload = serde_json::to_string(req).map_err(|e| format!("JSON encode: {}", e))?;
    payload.push('\n');
    stream
        .write_all(payload.as_bytes())
        .map_err(|e| format!("write: {}", e))?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|e| format!("shutdown write: {}", e))?;
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("read: {}", e))?;
    serde_json::from_str(&line).map_err(|e| format!("JSON decode: {}", e))
}

/// Read a line from stdin with echo disabled (for passphrase entry on a TTY).
fn rpassword_fallback() -> String {
    let _ = std::process::Command::new("stty")
        .arg("-echo")
        .stdin(std::process::Stdio::inherit())
        .status();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    let _ = std::process::Command::new("stty")
        .arg("echo")
        .stdin(std::process::Stdio::inherit())
        .status();
    eprint!("\n");
    line.trim_end_matches('\n').trim_end_matches('\r').to_string()
}

/// Export subcommand: dump config JSON from the running agent.
fn cli_export(args: &[String]) -> i32 {
    let mut include_secrets = false;
    let mut encrypt = false;
    let mut passphrase_from_stdin = false;
    let mut output_file: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--include-secrets" => include_secrets = true,
            "--encrypt" => {
                encrypt = true;
                include_secrets = true;
            }
            "--passphrase-from-stdin" => passphrase_from_stdin = true,
            "-o" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: -o requires a filename");
                    return 1;
                }
                output_file = Some(args[i].clone());
            }
            other => {
                eprintln!("error: unknown flag: {}", other);
                return 1;
            }
        }
        i += 1;
    }

    let passphrase = if encrypt {
        if passphrase_from_stdin {
            let mut line = String::new();
            if std::io::stdin().read_line(&mut line).is_err() {
                eprintln!("error: failed to read passphrase from stdin");
                return 1;
            }
            let p = line.trim_end_matches('\n').trim_end_matches('\r').to_string();
            if p.is_empty() {
                eprintln!("error: passphrase cannot be empty");
                return 1;
            }
            Some(p)
        } else {
            eprint!("Enter passphrase: ");
            let _ = std::io::stderr().flush();
            let p1 = rpassword_fallback();
            if p1.is_empty() {
                eprintln!("error: passphrase cannot be empty");
                return 1;
            }
            eprint!("Confirm passphrase: ");
            let _ = std::io::stderr().flush();
            let p2 = rpassword_fallback();
            if p1 != p2 {
                eprintln!("error: passphrases do not match");
                return 1;
            }
            Some(p1)
        }
    } else {
        None
    };

    let mut req = serde_json::json!({
        "method": "export_config",
        "include_secrets": include_secrets,
    });
    if let Some(ref p) = passphrase {
        req["passphrase"] = serde_json::Value::String(p.clone());
    }

    let resp = match socket_request(&req) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {}", e);
            return 1;
        }
    };

    if resp.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        let msg = resp
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        eprintln!("error: {}", msg);
        return 1;
    }

    let data = resp
        .get("config_value")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if let Some(ref path) = output_file {
        match std::fs::write(path, data) {
            Ok(_) => {
                eprintln!("Exported to {}", path);
                0
            }
            Err(e) => {
                eprintln!("error: failed to write {}: {}", path, e);
                1
            }
        }
    } else {
        print!("{}", data);
        0
    }
}

/// Import subcommand: restore config JSON into the running agent.
fn cli_import(args: &[String]) -> i32 {
    let mut input_file: Option<String> = None;
    let mut passphrase_from_stdin = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-f" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: -f requires a filename");
                    return 1;
                }
                input_file = Some(args[i].clone());
            }
            "--passphrase-from-stdin" => passphrase_from_stdin = true,
            other => {
                eprintln!("error: unknown flag: {}", other);
                return 1;
            }
        }
        i += 1;
    }

    // Read the JSON data
    let data = if let Some(ref path) = input_file {
        match std::fs::read_to_string(path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("error: failed to read {}: {}", path, e);
                return 1;
            }
        }
    } else {
        if passphrase_from_stdin {
            eprintln!("error: --passphrase-from-stdin cannot be used when reading data from stdin; use -f");
            return 1;
        }
        let mut buf = String::new();
        if std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf).is_err() {
            eprintln!("error: failed to read from stdin");
            return 1;
        }
        buf
    };

    // Parse to check if secrets are encrypted
    let parsed: serde_json::Value = match serde_json::from_str(&data) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: invalid JSON: {}", e);
            return 1;
        }
    };

    let needs_passphrase = parsed
        .get("secrets_encrypted")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let passphrase = if needs_passphrase {
        if passphrase_from_stdin {
            let mut line = String::new();
            if std::io::stdin().read_line(&mut line).is_err() {
                eprintln!("error: failed to read passphrase from stdin");
                return 1;
            }
            line.trim_end_matches('\n')
                .trim_end_matches('\r')
                .to_string()
        } else {
            eprint!("Enter passphrase: ");
            let _ = std::io::stderr().flush();
            rpassword_fallback()
        }
    } else {
        String::new()
    };

    let mut req = serde_json::json!({
        "method": "import_config",
        "value": data,
    });
    if !passphrase.is_empty() {
        req["passphrase"] = serde_json::Value::String(passphrase);
    }

    let resp = match socket_request(&req) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {}", e);
            return 1;
        }
    };

    if resp.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        let msg = resp
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        eprintln!("error: {}", msg);
        return 1;
    }

    eprintln!("Import successful");
    0
}

/// Check if a CLI subcommand was requested; return Some(exit_code) to short-circuit daemon startup.
fn cli_main() -> Option<i32> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        return None;
    }
    match args[1].as_str() {
        "export" => Some(cli_export(&args[2..])),
        "import" => Some(cli_import(&args[2..])),
        _ => None,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    if let Some(exit_code) = cli_main() {
        std::process::exit(exit_code);
    }

    let use_json = db::Db::open(DB_PATH)
        .ok()
        .and_then(|d| d.get_config("log_format").ok().flatten())
        .map(|v| v == "json")
        .unwrap_or(false);

    if use_json {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .init();
    }

    info!("hermitshell-agent starting");
    let start_time = std::time::Instant::now();

    let wan_iface = {
        db::Db::open(DB_PATH)
            .ok()
            .and_then(|d| d.get_config("wan_iface").ok().flatten())
    }
    .unwrap_or_else(|| std::env::var("WAN_IFACE").unwrap_or_else(|_| "eth1".into()));

    let lan_iface = {
        db::Db::open(DB_PATH)
            .ok()
            .and_then(|d| d.get_config("lan_iface").ok().flatten())
    }
    .unwrap_or_else(|| std::env::var("LAN_IFACE").unwrap_or_else(|_| "eth2".into()));

    // Validate interface names
    nftables::validate_iface(&wan_iface)?;
    nftables::validate_iface(&lan_iface)?;

    // Verify interfaces exist on the system
    let wan_exists = std::path::Path::new(&format!("/sys/class/net/{}", wan_iface)).exists();
    let lan_exists = std::path::Path::new(&format!("/sys/class/net/{}", lan_iface)).exists();
    if !wan_exists {
        anyhow::bail!("WAN interface '{}' not found (set WAN_IFACE env var)", wan_iface);
    }
    if !lan_exists {
        anyhow::bail!("LAN interface '{}' not found (set LAN_IFACE env var)", lan_iface);
    }
    info!(wan = %wan_iface, lan = %lan_iface, "network interfaces");

    // Read LAN IP from config (default: 10.0.0.1 / fd00::1)
    let lan_ip = {
        db::Db::open(DB_PATH)
            .ok()
            .and_then(|d| d.get_config("lan_ip").ok().flatten())
    }
    .unwrap_or_else(|| "10.0.0.1".into());
    let lan_ip_v6 = {
        db::Db::open(DB_PATH)
            .ok()
            .and_then(|d| d.get_config("lan_ip_v6").ok().flatten())
    }
    .unwrap_or_else(|| "fd00::1".into());
    let lan_addr = format!("{}/32", lan_ip);
    let lan_addr_v6 = format!("{}/128", lan_ip_v6);
    info!(lan_ip = %lan_ip, lan_ip_v6 = %lan_ip_v6, "LAN gateway addresses");

    // Read device IP range from config (default: 10.0.0.0/8)
    let device_range_cidr = {
        db::Db::open(DB_PATH)
            .ok()
            .and_then(|d| d.get_config("device_ipv4_base").ok().flatten())
    }
    .unwrap_or_else(|| "10.0.0.0/8".into());
    let (device_ipv4_base, device_prefix_len, device_max_subnet_id) =
        subnet::parse_device_range(&device_range_cidr)
            .unwrap_or_else(|| {
                warn!(cidr = %device_range_cidr, "invalid device_ipv4_base, falling back to 10.0.0.0/8");
                (0x0A000000, 8, 16_777_213)
            });
    nftables::init_device_range(device_ipv4_base, device_prefix_len, device_max_subnet_id);
    nftables::init_gateway_ip(&lan_ip);
    info!(device_range = %device_range_cidr, max_devices = device_max_subnet_id + 1, "device IP range");

    // Ensure LAN interface has the base IPv4 address
    let status = std::process::Command::new("/usr/sbin/ip")
        .args(["addr", "add", &lan_addr, "dev", &lan_iface])
        .status();
    match status {
        Ok(s) if s.success() || s.code() == Some(2) => {} // 2 = already exists
        Ok(s) => warn!(addr = %lan_addr, iface = lan_iface, code = ?s.code(), "ip addr add exited unexpectedly"),
        Err(e) => warn!(error = %e, "failed to add LAN address"),
    }

    // Ensure LAN interface has the base IPv6 ULA address
    let _ = std::process::Command::new("/usr/sbin/ip")
        .args(["-6", "addr", "add", &lan_addr_v6, "dev", &lan_iface])
        .status();
    // Verify the address is actually present (ip addr add exit code 2 is ambiguous)
    let has_ipv6_ula = std::process::Command::new("/usr/sbin/ip")
        .args(["-6", "addr", "show", "dev", &lan_iface])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains(&lan_ip_v6))
        .unwrap_or(false);
    if !has_ipv6_ula {
        warn!("IPv6 ULA address not available on {}", lan_iface);
    }

    // Apply base nftables rules
    nftables::apply_base_rules(&wan_iface, &lan_iface, &lan_ip)?;

    // Open database
    let db = Arc::new(Mutex::new(db::Db::open(DB_PATH)?));
    info!(path = DB_PATH, "database opened");

    // Generate self-signed TLS cert if missing
    {
        let db_guard = db.lock().unwrap();
        let has_cert = db_guard.get_config("tls_cert_pem").ok().flatten().is_some();
        let has_key = db_guard.get_config("tls_key_pem").ok().flatten().is_some();
        if !has_cert || !has_key {
            let mut subject_alt_names = vec![
                "hermitshell.local".to_string(),
                lan_ip.clone(),
            ];
            // Add system hostname
            if let Ok(hostname) = nix::unistd::gethostname() {
                let h = hostname.to_string_lossy().to_string();
                if !h.is_empty() && !subject_alt_names.contains(&h) {
                    subject_alt_names.push(h);
                }
            }
            // Add extra SANs from env var
            if let Ok(extra) = std::env::var("TLS_SANS") {
                for san in extra.split(',') {
                    let san = san.trim().to_string();
                    if !san.is_empty() && !subject_alt_names.contains(&san) {
                        subject_alt_names.push(san);
                    }
                }
            }
            info!(sans = ?subject_alt_names, "generating self-signed TLS certificate");
            match rcgen::generate_simple_self_signed(subject_alt_names) {
                Ok(cert) => {
                    let cert_pem = cert.cert.pem();
                    let key_pem = cert.key_pair.serialize_pem();
                    let _ = db_guard.set_config("tls_cert_pem", &cert_pem);
                    let _ = db_guard.set_config("tls_key_pem", &key_pem);
                    info!("self-signed TLS certificate generated");
                }
                Err(e) => {
                    error!(error = %e, "failed to generate TLS certificate");
                }
            }
        }
        // Generate session secret if missing
        if db_guard.get_config("session_secret").ok().flatten().is_none() {
            let secret = hex::encode(rand::Rng::r#gen::<[u8; 32]>(&mut rand::thread_rng()));
            let _ = db_guard.set_config("session_secret", &secret);
            info!("session secret generated");
        }
    }

    // Encrypt any legacy plaintext WiFi provider passwords
    {
        let db_lock = db.lock().unwrap();
        if let Ok(Some(secret)) = db_lock.get_config("session_secret") {
            if let Err(e) = db_lock.encrypt_wifi_provider_passwords(&secret) {
                warn!(error = %e, "failed to encrypt legacy WiFi passwords");
            }
        }
    }

    // Try to obtain IPv6 prefix delegation from ISP
    match crate::pd::request_prefix(&wan_iface) {
        Ok(Some(prefix)) => {
            info!(prefix = %prefix, "IPv6 prefix delegated");
            let db_guard = db.lock().unwrap();
            let _ = db_guard.set_config("ipv6_delegated_prefix", &prefix);
        }
        Ok(None) => {
            info!("no IPv6 prefix delegation, using ULA only");
        }
        Err(e) => {
            warn!(error = %e, "DHCPv6-PD failed, using ULA only");
        }
    };

    // Restore state for previously assigned devices
    {
        let db_guard = db.lock().unwrap();
        let assigned = db_guard.list_assigned_devices()?;
        for dev in &assigned {
            if let Some(ip) = &dev.ipv4 {
                // Re-add /32 device route
                let _ = nftables::add_device_route(ip, &lan_iface, &dev.mac);
                // Re-add nftables counter
                let _ = nftables::add_device_counter(ip);
                // Re-add nftables forward rule
                let _ = nftables::add_device_forward_rule(ip, &dev.device_group);
                // Re-add IPv6 route, counter, forward rule
                let ipv6 = dev.ipv6_ula.as_deref().unwrap_or_default();
                if !ipv6.is_empty() {
                    let _ = nftables::add_device_route_v6(ipv6, &lan_iface, &dev.mac);
                    let _ = nftables::add_device_counter_v6(ipv6);
                    let _ = nftables::add_device_forward_rule_v6(ipv6, &dev.device_group);
                    let _ = nftables::add_mac_ip_rule_v6(ipv6, &dev.mac);
                }
                let _ = nftables::add_mac_ip_rule(ip, &dev.mac);
                info!(mac = %dev.mac, ip = %ip, group = %dev.device_group, "device restored");
            }
        }
    }

    // Restore QoS if enabled
    {
        let db_guard = db.lock().unwrap();
        let qos_enabled = db_guard.get_config_bool("qos_enabled", false);
        if qos_enabled {
            let upload: u32 = db_guard.get_config("qos_upload_mbps")
                .ok().flatten()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let download: u32 = db_guard.get_config("qos_download_mbps")
                .ok().flatten()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            if upload > 0 && download > 0 {
                if let Err(e) = qos::enable(&wan_iface, upload, download) {
                    error!(error = %e, "failed to restore QoS");
                } else {
                    info!(upload = upload, download = download, "QoS restored");
                    let assigned = db_guard.list_assigned_devices().unwrap_or_default();
                    let devices: Vec<(String, String)> = assigned.iter()
                        .filter_map(|d| d.ipv4.as_ref().map(|ip| (ip.clone(), d.device_group.clone())))
                        .collect();
                    if let Err(e) = qos::apply_dscp_rules(&devices) {
                        error!(error = %e, "failed to restore DSCP rules");
                    }
                }
            }
        }
    }

    // Restore port forwarding rules
    {
        let db_guard = db.lock().unwrap();
        let forwards = db_guard.list_enabled_port_forwards().unwrap_or_default();
        let dmz = db_guard.get_config("dmz_host_ip").ok().flatten().unwrap_or_default();
        let dmz_ref = if dmz.is_empty() { None } else { Some(dmz.as_str()) };
        if !forwards.is_empty() || dmz_ref.is_some() {
            if let Err(e) = nftables::apply_port_forwards(&wan_iface, &lan_iface, &forwards, dmz_ref, &lan_ip) {
                error!(error = %e, "failed to restore port forwards");
            } else {
                info!(count = forwards.len(), "port forwards restored");
            }
        }
    }

    // Restore IPv6 pinholes
    {
        let db_guard = db.lock().unwrap();
        let pinholes = db_guard.list_ipv6_pinholes().unwrap_or_default();
        let mut restored = 0;
        for p in &pinholes {
            let ipv6 = p.get("device_ipv6_global").and_then(|v| v.as_str()).unwrap_or("");
            let protocol = p.get("protocol").and_then(|v| v.as_str()).unwrap_or("");
            let port_start = p.get("port_start").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            let port_end = p.get("port_end").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            if !ipv6.is_empty() && !protocol.is_empty() && port_start > 0 {
                if let Err(e) = nftables::add_ipv6_pinhole(ipv6, protocol, port_start, port_end) {
                    error!(error = %e, ipv6 = %ipv6, "failed to restore IPv6 pinhole");
                } else {
                    restored += 1;
                }
            }
        }
        if restored > 0 {
            info!(count = restored, "IPv6 pinholes restored");
        }
    }

    // Restore WireGuard state if enabled
    {
        let db_guard = db.lock().unwrap();
        let wg_enabled = db_guard.get_config_bool("wg_enabled", false);
        if wg_enabled {
            if let Some(private_key) = db_guard.get_config("wg_private_key").ok().flatten() {
                let private_key = zeroize::Zeroizing::new(private_key);
                let listen_port: u16 = db_guard.get_config("wg_listen_port")
                    .ok().flatten()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(51820);
                if let Err(e) = wireguard::create_interface(&private_key, listen_port, &lan_ip, &lan_ip_v6) {
                    error!(error = %e, "failed to restore wg0");
                } else {
                    let _ = wireguard::open_listen_port(listen_port);
                    let peers = db_guard.list_wg_peers().unwrap_or_default();
                    for peer in &peers {
                        if !peer.enabled { continue; }
                        if let Some(info) = subnet::compute_subnet(peer.subnet_id, device_ipv4_base, device_max_subnet_id) {
                            let ipv4 = info.device_ipv4.to_string();
                            let ipv6 = info.device_ipv6_ula.to_string();
                            let _ = wireguard::add_peer(&peer.public_key, &ipv4, &ipv6);
                            let _ = nftables::add_device_counter(&ipv4);
                            let _ = nftables::add_device_counter_v6(&ipv6);
                            let _ = nftables::add_device_forward_rule(&ipv4, &peer.device_group);
                            let _ = nftables::add_device_forward_rule_v6(&ipv6, &peer.device_group);
                            info!(peer = %peer.name, ipv4 = %ipv4, ipv6 = %ipv6, "wireguard peer restored");
                        }
                    }
                }
            }
        }
    }

    // Start blocky DNS server
    let upstream_dns = read_upstream_dns(&wan_iface);
    info!(servers = ?upstream_dns, "upstream DNS");

    let blocky_mgr = {
        let dns_strings: Vec<String> = upstream_dns.iter().map(|ip| ip.to_string()).collect();
        let blocky_listen = if has_ipv6_ula {
            format!("{}:5354,[{}]:5354", lan_ip, lan_ip_v6)
        } else {
            format!("{}:5354", lan_ip)
        };
        let blocky_bin = std::env::var("BLOCKY_BIN")
            .unwrap_or_else(|_| "/opt/hermitshell/blocky".into());
        let mut mgr = blocky::BlockyManager::new(
            dns_strings,
            blocky_listen,
            "/var/lib/hermitshell/blocky".to_string(),
            blocky_bin,
        );
        if let Err(e) = mgr.start() {
            error!(error = %e, "failed to start blocky");
        } else {
            if !mgr.wait_for_ready(10) {
                error!("blocky did not become ready within 10s");
            }
            // Check ad_blocking_enabled setting
            let db_guard = db.lock().unwrap();
            let enabled = db_guard.get_config_bool("ad_blocking_enabled", true);
            drop(db_guard);
            if !enabled {
                if let Err(e) = mgr.set_blocking_enabled(false) {
                    error!(error = %e, "failed to disable blocking");
                }
            }
        }
        Arc::new(Mutex::new(mgr))
    };

    // Start RA sender for IPv6 (tells LAN clients to use DHCPv6)
    let lan_for_ra = lan_iface.to_string();
    std::thread::spawn(move || {
        if let Err(e) = crate::ra::run_ra_sender(&lan_for_ra) {
            error!(error = %e, "RA sender error");
        }
    });

    // Start conntrack event listener
    conntrack::enable_accounting();
    let (log_tx, log_rx) = tokio::sync::mpsc::unbounded_channel::<log_export::LogEvent>();
    let _conntrack_child = conntrack::start(db.clone(), log_tx.clone(), lan_ip.clone());

    let db_dns = db.clone();
    let log_tx_dns = log_tx.clone();
    let log_tx_analyzer = log_tx.clone();
    tokio::spawn(async move {
        dns_log::start(db_dns, log_tx_dns).await;
    });

    let db_export = db.clone();
    tokio::spawn(async move {
        log_export::start(db_export, log_rx).await;
    });

    // Create mDNS registry (shared between proxy task and socket handler)
    let mdns_registry: mdns::SharedRegistry = Arc::new(Mutex::new(mdns::ServiceRegistry::new()));

    // Create shared port-mapping registry (used by socket handlers and UPnP/NAT-PMP)
    let portmap_registry: crate::portmap::SharedRegistry = std::sync::Arc::new(
        crate::portmap::PortMapRegistry::new(db.clone(), wan_iface.to_string(), lan_iface.to_string(), lan_ip.clone())
    );

    // Spawn UPnP/NAT-PMP if enabled
    {
        let db_check = db.lock().unwrap();
        let upnp_enabled = db_check.get_config_bool("upnp_enabled", false);
        drop(db_check);

        if upnp_enabled {
            if let Err(e) = nftables::add_upnp_input_rules(&lan_iface) {
                error!(error = %e, "failed to add UPnP nftables rules");
            }

            let db_upnp = db.clone();
            let pm_upnp = portmap_registry.clone();
            let wan_upnp = wan_iface.to_string();
            let lan_upnp = lan_iface.to_string();
            let lan_ip_upnp = lan_ip.clone();
            tokio::spawn(async move {
                upnp::run(db_upnp, pm_upnp, wan_upnp, lan_upnp, lan_ip_upnp).await;
            });

            let db_natpmp = db.clone();
            let pm_natpmp = portmap_registry.clone();
            let wan_natpmp = wan_iface.to_string();
            let lan_natpmp = lan_iface.to_string();
            tokio::spawn(async move {
                natpmp::run(db_natpmp, pm_natpmp, lan_natpmp, wan_natpmp).await;
            });
        }
    }

    // Lease expiry sweep (runs regardless of upnp_enabled — cleans up stale entries)
    let pm_expiry = portmap_registry.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            pm_expiry.expire_leases();
        }
    });

    // Spawn socket server
    let db_clone = db.clone();
    let blocky_clone = blocky_mgr.clone();
    let wan_for_socket = wan_iface.to_string();
    let lan_for_socket = lan_iface.to_string();
    let log_tx_socket = log_tx.clone();
    let bandwidth_realtime: crate::socket::BandwidthRealtimeMap =
        Arc::new(Mutex::new(std::collections::HashMap::new()));
    let bandwidth_rt_for_socket = bandwidth_realtime.clone();
    let speed_test_state: crate::socket::SpeedTestState = Arc::new(Mutex::new((false, None, None)));
    let mdns_reg_for_socket = mdns_registry.clone();
    let portmap_for_socket = portmap_registry.clone();
    tokio::spawn(async move {
        if let Err(e) = socket::run_server(SOCKET_PATH, db_clone, start_time, blocky_clone, wan_for_socket, lan_for_socket, log_tx_socket, bandwidth_rt_for_socket, speed_test_state, mdns_reg_for_socket, portmap_for_socket).await {
            error!(error = %e, "socket server error");
        }
    });

    // Spawn DHCP IPC socket
    const DHCP_SOCKET_PATH: &str = "/run/hermitshell/dhcp.sock";
    let db_dhcp = db.clone();
    let lan_iface_dhcp = lan_iface.to_string();
    tokio::spawn(async move {
        if let Err(e) = socket::run_dhcp_socket(DHCP_SOCKET_PATH, db_dhcp, lan_iface_dhcp).await {
            error!(error = %e, "DHCP socket error");
        }
    });

    // Spawn runZero sync task
    let db_runzero = db.clone();
    tokio::spawn(async move {
        runzero::run(db_runzero).await;
    });

    // Spawn TLS cert renewal task
    let db_tls = db.clone();
    tokio::spawn(async move {
        tls::run_renewal(db_tls).await;
    });

    // Spawn WiFi AP polling task
    let db_wifi = db.clone();
    tokio::spawn(async move {
        wifi::run(db_wifi).await;
    });

    // Spawn mDNS proxy
    let db_mdns = db.clone();
    let lan_mdns = lan_iface.to_string();
    let mdns_reg_for_task = mdns_registry.clone();
    let lan_ip_mdns = lan_ip.clone();
    tokio::spawn(async move {
        mdns::run(db_mdns, lan_mdns, mdns_reg_for_task, lan_ip_mdns).await;
    });

    // Spawn update check loop (opt-in)
    let update_enabled = db.lock().unwrap()
        .get_config("update_check_enabled").ok().flatten()
        .map(|v| v == "true").unwrap_or(false);
    if update_enabled {
        update::spawn_update_loop(db.clone());
    }

    // Spawn DHCP server as child process
    let db_for_counters = db.clone();
    let dhcp_bin = std::env::var("HERMITSHELL_DHCP_BIN")
        .unwrap_or_else(|_| "/opt/hermitshell/hermitshell-dhcp".into());
    std::process::Command::new(&dhcp_bin)
        .args([&lan_iface, &lan_ip, &lan_ip_v6])
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()?;

    // Main polling loop: update traffic counters for assigned devices
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(POLL_INTERVAL_SECS));

    info!("agent initialized, entering main loop");

    // Run log rotation once on startup
    {
        let db_guard = db_for_counters.lock().unwrap();
        let retention_days: i64 = db_guard
            .get_config("log_retention_days")
            .ok()
            .flatten()
            .and_then(|v| v.parse().ok())
            .unwrap_or(7);
        let _ = db_guard.rotate_logs(retention_days * 86400);
    }

    let mut rotation_counter: u64 = 0;
    let mut analysis_counter: u64 = 0;

    loop {
        interval.tick().await;

        let db_guard = db_for_counters.lock().unwrap();
        let devices = match db_guard.list_assigned_devices() {
            Ok(d) => d,
            Err(e) => {
                error!(error = %e, "failed to list devices");
                continue;
            }
        };

        for dev in &devices {
            if let Some(ref ip) = dev.ipv4 {
                match nftables::get_device_counters(ip) {
                    Ok((rx, tx)) => {
                        if let Err(e) = db_guard.update_counters(ip, rx, tx) {
                            error!(ip = %ip, error = %e, "failed to update counters");
                        }
                        // Update real-time throughput map
                        let mut rt = bandwidth_realtime.lock().unwrap();
                        let now_inst = std::time::Instant::now();
                        if let Some(entry) = rt.get(ip.as_str()).cloned() {
                            // Shift current to prev, set new current
                            rt.insert(ip.clone(), (entry.2, entry.3, rx, tx, now_inst));
                        } else {
                            rt.insert(ip.clone(), (rx, tx, rx, tx, now_inst));
                        }
                        drop(rt);
                    }
                    Err(e) => debug!(ip = %ip, error = %e, "failed to get counters"),
                }
            }
        }
        drop(db_guard);

        // Run behavioral analysis every 6 ticks (60 seconds)
        analysis_counter += 1;
        if analysis_counter % 6 == 0 {
            analyzer::run_analysis_cycle(&db_for_counters, &log_tx_analyzer);
        }

        // Hourly log rotation (360 ticks * 10s = 1 hour)
        rotation_counter += 1;
        if rotation_counter % 360 == 0 {
            let db_guard = db_for_counters.lock().unwrap();
            let retention_days: i64 = db_guard
                .get_config("log_retention_days")
                .ok()
                .flatten()
                .and_then(|v| v.parse().ok())
                .unwrap_or(7);
            match db_guard.rotate_logs(retention_days * 86400) {
                Ok((conn, dns)) => {
                    if conn > 0 || dns > 0 {
                        info!(connection_logs = conn, dns_logs = dns, "rotated old logs");
                    }
                }
                Err(e) => error!(error = %e, "log rotation failed"),
            }
            if let Err(e) = db_guard.rotate_alerts(retention_days * 86400) {
                error!(error = %e, "alert rotation failed");
            }
            // Bandwidth rollups
            match db_guard.rollup_all_pending() {
                Ok((h, d)) => {
                    if h > 0 || d > 0 {
                        info!(hourly = h, daily = d, "bandwidth rollup complete");
                    }
                }
                Err(e) => error!(error = %e, "bandwidth rollup failed"),
            }
            match db_guard.rotate_bandwidth_rollups() {
                Ok((h, d)) => {
                    if h > 0 || d > 0 {
                        info!(hourly_deleted = h, daily_deleted = d, "bandwidth rollup rotation");
                    }
                }
                Err(e) => error!(error = %e, "bandwidth rollup rotation failed"),
            }
        }
    }
}
