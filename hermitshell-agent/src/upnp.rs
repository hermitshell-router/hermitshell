use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use rand::RngExt as _;
use tracing::{debug, error, info, warn};

use crate::db::Db;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SSDP_ADDR: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const SSDP_PORT: u16 = 1900;
const HTTP_PORT: u16 = 5000;
const NOTIFY_INTERVAL_SECS: u64 = 900;

// UPnP search target URNs we respond to.
const ST_ROOT: &str = "upnp:rootdevice";
const ST_ALL: &str = "ssdp:all";
const ST_IGD: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";
const ST_WANIP: &str = "urn:schemas-upnp-org:service:WANIPConnection:1";

// ---------------------------------------------------------------------------
// SSDP helpers
// ---------------------------------------------------------------------------

/// Escape a string for safe inclusion in XML text content.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Check whether `ip` belongs to a device in the "trusted" group.
fn is_trusted(db: &Db, ip: &Ipv4Addr) -> bool {
    let ip_str = ip.to_string();
    let devices = match db.list_assigned_devices() {
        Ok(d) => d,
        Err(_) => return false,
    };
    devices
        .iter()
        .any(|d| d.ipv4.as_deref() == Some(&ip_str) && d.device_group == "trusted")
}

/// Create a UDP socket bound to 0.0.0.0:1900 with multicast membership on the LAN interface.
fn create_ssdp_socket(lan_iface: &str, lan_ip: Ipv4Addr) -> anyhow::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;

    let addr: SocketAddr = format!("0.0.0.0:{}", SSDP_PORT).parse()?;
    socket.bind(&addr.into())?;

    socket.join_multicast_v4(&SSDP_ADDR, &lan_ip)?;
    socket.bind_device(Some(lan_iface.as_bytes()))?;

    Ok(socket.into())
}

/// Build an SSDP M-SEARCH response for a given search target.
fn ssdp_response(st: &str, uuid: &str, lan_ip: &str) -> String {
    let usn = format!("uuid:{}::{}", uuid, st);
    format!(
        "HTTP/1.1 200 OK\r\n\
         CACHE-CONTROL: max-age=1800\r\n\
         EXT:\r\n\
         LOCATION: http://{lan_ip}:{HTTP_PORT}/rootDesc.xml\r\n\
         ST: {st}\r\n\
         USN: {usn}\r\n\
         SERVER: HermitShell/1.0 UPnP/1.1\r\n\
         \r\n"
    )
}

/// Build an SSDP NOTIFY alive message for a given notification type.
fn ssdp_notify(nt: &str, uuid: &str, lan_ip: &str) -> String {
    let usn = format!("uuid:{}::{}", uuid, nt);
    format!(
        "NOTIFY * HTTP/1.1\r\n\
         HOST: 239.255.255.250:1900\r\n\
         CACHE-CONTROL: max-age=1800\r\n\
         LOCATION: http://{lan_ip}:{HTTP_PORT}/rootDesc.xml\r\n\
         NT: {nt}\r\n\
         NTS: ssdp:alive\r\n\
         USN: {usn}\r\n\
         SERVER: HermitShell/1.0 UPnP/1.1\r\n\
         \r\n"
    )
}

/// Build an SSDP NOTIFY byebye message for a given notification type.
fn ssdp_byebye(nt: &str, uuid: &str) -> String {
    let usn = format!("uuid:{}::{}", uuid, nt);
    format!(
        "NOTIFY * HTTP/1.1\r\n\
         HOST: 239.255.255.250:1900\r\n\
         NT: {nt}\r\n\
         NTS: ssdp:byebye\r\n\
         USN: {usn}\r\n\
         \r\n"
    )
}

/// Parse the ST header from an M-SEARCH request.
fn parse_st(data: &str) -> Option<&str> {
    for line in data.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("st:") {
            return Some(line[3..].trim());
        }
    }
    None
}

/// Parse the MX header from an M-SEARCH request.
/// Returns a value clamped to [1, 120]; defaults to 3 seconds per spec.
fn parse_mx(data: &str) -> u32 {
    for line in data.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("mx:")
            && let Ok(val) = line[3..].trim().parse::<u32>() {
                return val.clamp(1, 120);
            }
    }
    3 // default 3 seconds per spec
}

// ---------------------------------------------------------------------------
// SSDP listener + NOTIFY sender
// ---------------------------------------------------------------------------

/// All notification types for the IGD device hierarchy.
fn all_notify_types(uuid: &str) -> Vec<String> {
    vec![
        format!("uuid:{}", uuid),
        ST_ROOT.to_string(),
        ST_IGD.to_string(),
        "urn:schemas-upnp-org:device:WANDevice:1".to_string(),
        "urn:schemas-upnp-org:device:WANConnectionDevice:1".to_string(),
        ST_WANIP.to_string(),
        "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1".to_string(),
    ]
}

/// Main SSDP loop: listen for M-SEARCH, respond to trusted devices, and
/// periodically send NOTIFY alive multicast.  Sends ssdp:byebye on shutdown.
async fn run_ssdp(db: Arc<Mutex<Db>>, device_uuid: String, lan_iface: String, lan_ip: Ipv4Addr) {
    let lan_ip_str = lan_ip.to_string();
    let socket = match create_ssdp_socket(&lan_iface, lan_ip) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "failed to create SSDP socket");
            return;
        }
    };
    info!(iface = %lan_iface, "UPnP SSDP listener started");

    let socket = Arc::new(tokio::net::UdpSocket::from_std(socket).expect("tokio UdpSocket"));

    // Spawn periodic NOTIFY sender
    let notify_socket = socket.clone();
    let notify_uuid = device_uuid.clone();
    let notify_lan_ip = lan_ip_str.clone();
    tokio::spawn(async move {
        let mcast_dest: SocketAddr = SocketAddr::new(SSDP_ADDR.into(), SSDP_PORT);
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(NOTIFY_INTERVAL_SECS));
        let all_nts = all_notify_types(&notify_uuid);
        loop {
            interval.tick().await;
            for nt in &all_nts {
                let msg = ssdp_notify(nt, &notify_uuid, &notify_lan_ip);
                if let Err(e) = notify_socket.send_to(msg.as_bytes(), mcast_dest).await {
                    debug!(error = %e, "SSDP NOTIFY send failed");
                }
            }
            debug!("SSDP NOTIFY alive sent");
        }
    });

    let mut buf = [0u8; 4096];

    // L13: Send ssdp:byebye on shutdown (SIGTERM/SIGINT)
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();

    loop {
        // Wait for incoming data or shutdown signal
        let recv_result = tokio::select! {
            r = socket.recv_from(&mut buf) => Some(r),
            _ = async {
                match sigterm.as_mut() {
                    Some(s) => s.recv().await,
                    None => std::future::pending().await,
                }
            } => None,
        };

        let (len, src) = match recv_result {
            Some(Ok(r)) => r,
            Some(Err(e)) => {
                warn!(error = %e, "SSDP recv error");
                continue;
            }
            None => {
                // Shutdown signal received — send byebye for all NTs
                let mcast_dest: SocketAddr = SocketAddr::new(SSDP_ADDR.into(), SSDP_PORT);
                let all_nts = all_notify_types(&device_uuid);
                for nt in &all_nts {
                    let msg = ssdp_byebye(nt, &device_uuid);
                    let _ = socket.send_to(msg.as_bytes(), mcast_dest).await;
                }
                info!("SSDP byebye sent, shutting down");
                return;
            }
        };

        // Ignore packets from the router itself
        if let SocketAddr::V4(addr) = src
            && *addr.ip() == lan_ip {
                continue;
            }

        let data = match std::str::from_utf8(&buf[..len]) {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Only handle M-SEARCH requests
        if !data.starts_with("M-SEARCH") {
            continue;
        }

        // L12: Validate MAN header
        let has_valid_man = data.lines().any(|line| {
            let lower = line.to_ascii_lowercase();
            lower.starts_with("man:") && lower.contains("\"ssdp:discover\"")
        });
        if !has_valid_man {
            debug!("M-SEARCH missing valid MAN header, ignoring");
            continue;
        }

        let src_ip = match src {
            SocketAddr::V4(addr) => *addr.ip(),
            _ => continue,
        };

        // Check that the requesting device is trusted
        let trusted = {
            let db_guard = db.lock().unwrap();
            is_trusted(&db_guard, &src_ip)
        };
        if !trusted {
            debug!(ip = %src_ip, "SSDP M-SEARCH from non-trusted device, ignoring");
            continue;
        }

        let st = match parse_st(data) {
            Some(s) => s.to_string(),
            None => continue,
        };

        // Determine which STs to respond with
        let response_sts: Vec<&str> = if st == ST_ALL {
            vec![ST_ROOT, ST_IGD, ST_WANIP]
        } else if st == ST_ROOT || st == ST_IGD || st == ST_WANIP {
            vec![st.as_str()]
        } else {
            continue;
        };

        // H9: Random delay 0..MX seconds before responding
        let mx = parse_mx(data);
        let delay = rand::rng().random_range(0..=mx);
        tokio::time::sleep(std::time::Duration::from_secs(delay as u64)).await;

        for rst in response_sts {
            let resp = ssdp_response(rst, &device_uuid, &lan_ip_str);
            if let Err(e) = socket.send_to(resp.as_bytes(), src).await {
                debug!(error = %e, dest = %src, "SSDP response send failed");
            }
        }
        debug!(from = %src, st = %st, "SSDP M-SEARCH handled");
    }
}

// ---------------------------------------------------------------------------
// XML helper: extract element value from SOAP body
// ---------------------------------------------------------------------------

/// Extract the text content of an XML element by tag name.
/// Handles both `<Tag>value</Tag>` and `<Tag xmlns:u="...">value</Tag>`.
fn extract_xml_value(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}", tag);
    let close = format!("</{}", tag);
    let start = xml.find(&open)?;
    let after_open = &xml[start..];
    let content_start = after_open.find('>')? + 1;
    let content = &after_open[content_start..];
    let end = content.find(&close)?;
    Some(content[..end].trim().to_string())
}

// ---------------------------------------------------------------------------
// SOAP response builders
// ---------------------------------------------------------------------------

fn soap_ok(action: &str, body: &str) -> Response {
    let xml = format!(
        r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:{action}Response xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
{body}
    </u:{action}Response>
  </s:Body>
</s:Envelope>"#
    );
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/xml; charset=\"utf-8\"")
        .body(axum::body::Body::from(xml))
        .unwrap()
}

fn soap_error(code: u16, desc: &str) -> Response {
    let xml = format!(
        r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <s:Fault>
      <faultcode>s:Client</faultcode>
      <faultstring>UPnPError</faultstring>
      <detail>
        <UPnPError xmlns="urn:schemas-upnp-org:control-1-0">
          <errorCode>{code}</errorCode>
          <errorDescription>{desc}</errorDescription>
        </UPnPError>
      </detail>
    </s:Fault>
  </s:Body>
</s:Envelope>"#
    );
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header("Content-Type", "text/xml; charset=\"utf-8\"")
        .body(axum::body::Body::from(xml))
        .unwrap()
}

// ---------------------------------------------------------------------------
// Shared state for the HTTP server
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct AppState {
    db: Arc<Mutex<Db>>,
    portmap: crate::portmap::SharedRegistry,
    wan_iface: String,
    device_uuid: String,
}

// ---------------------------------------------------------------------------
// HTTP handlers: device description XML
// ---------------------------------------------------------------------------

async fn root_desc(State(state): State<AppState>) -> impl IntoResponse {
    let uuid = &state.device_uuid;
    let xml = format!(
        r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>HermitShell Router</friendlyName>
    <manufacturer>HermitShell</manufacturer>
    <modelName>HermitShell</modelName>
    <modelNumber>1.0</modelNumber>
    <UDN>uuid:{uuid}</UDN>
    <deviceList>
      <device>
        <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
        <friendlyName>WANDevice</friendlyName>
        <UDN>uuid:{uuid}-wan</UDN>
        <serviceList>
          <service>
            <serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>
            <serviceId>urn:upnp-org:serviceId:WANCommonIFC1</serviceId>
            <SCPDURL>/WANCommonIFC.xml</SCPDURL>
            <controlURL>/ctl/WANCommonIFC</controlURL>
            <eventSubURL></eventSubURL>
          </service>
        </serviceList>
        <deviceList>
          <device>
            <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
            <friendlyName>WANConnectionDevice</friendlyName>
            <UDN>uuid:{uuid}-wanconn</UDN>
            <serviceList>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
                <SCPDURL>/WANIPConn.xml</SCPDURL>
                <controlURL>/ctl/WANIPConn</controlURL>
                <eventSubURL></eventSubURL>
              </service>
            </serviceList>
          </device>
        </deviceList>
      </device>
    </deviceList>
  </device>
</root>"#
    );
    (
        StatusCode::OK,
        [("Content-Type", "text/xml; charset=\"utf-8\"")],
        xml,
    )
}

// ---------------------------------------------------------------------------
// SCPD: WANIPConnection
// ---------------------------------------------------------------------------

const WAN_IP_CONN_SCPD: &str = r#"<?xml version="1.0"?>
<scpd xmlns="urn:schemas-upnp-org:service-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <actionList>
    <action>
      <name>AddPortMapping</name>
      <argumentList>
        <argument><name>NewRemoteHost</name><direction>in</direction><relatedStateVariable>RemoteHost</relatedStateVariable></argument>
        <argument><name>NewExternalPort</name><direction>in</direction><relatedStateVariable>ExternalPort</relatedStateVariable></argument>
        <argument><name>NewProtocol</name><direction>in</direction><relatedStateVariable>PortMappingProtocol</relatedStateVariable></argument>
        <argument><name>NewInternalPort</name><direction>in</direction><relatedStateVariable>InternalPort</relatedStateVariable></argument>
        <argument><name>NewInternalClient</name><direction>in</direction><relatedStateVariable>InternalClient</relatedStateVariable></argument>
        <argument><name>NewEnabled</name><direction>in</direction><relatedStateVariable>PortMappingEnabled</relatedStateVariable></argument>
        <argument><name>NewPortMappingDescription</name><direction>in</direction><relatedStateVariable>PortMappingDescription</relatedStateVariable></argument>
        <argument><name>NewLeaseDuration</name><direction>in</direction><relatedStateVariable>PortMappingLeaseDuration</relatedStateVariable></argument>
      </argumentList>
    </action>
    <action>
      <name>DeletePortMapping</name>
      <argumentList>
        <argument><name>NewRemoteHost</name><direction>in</direction><relatedStateVariable>RemoteHost</relatedStateVariable></argument>
        <argument><name>NewExternalPort</name><direction>in</direction><relatedStateVariable>ExternalPort</relatedStateVariable></argument>
        <argument><name>NewProtocol</name><direction>in</direction><relatedStateVariable>PortMappingProtocol</relatedStateVariable></argument>
      </argumentList>
    </action>
    <action>
      <name>GetExternalIPAddress</name>
      <argumentList>
        <argument><name>NewExternalIPAddress</name><direction>out</direction><relatedStateVariable>ExternalIPAddress</relatedStateVariable></argument>
      </argumentList>
    </action>
    <action>
      <name>GetGenericPortMappingEntry</name>
      <argumentList>
        <argument><name>NewPortMappingIndex</name><direction>in</direction><relatedStateVariable>PortMappingNumberOfEntries</relatedStateVariable></argument>
        <argument><name>NewRemoteHost</name><direction>out</direction><relatedStateVariable>RemoteHost</relatedStateVariable></argument>
        <argument><name>NewExternalPort</name><direction>out</direction><relatedStateVariable>ExternalPort</relatedStateVariable></argument>
        <argument><name>NewProtocol</name><direction>out</direction><relatedStateVariable>PortMappingProtocol</relatedStateVariable></argument>
        <argument><name>NewInternalPort</name><direction>out</direction><relatedStateVariable>InternalPort</relatedStateVariable></argument>
        <argument><name>NewInternalClient</name><direction>out</direction><relatedStateVariable>InternalClient</relatedStateVariable></argument>
        <argument><name>NewEnabled</name><direction>out</direction><relatedStateVariable>PortMappingEnabled</relatedStateVariable></argument>
        <argument><name>NewPortMappingDescription</name><direction>out</direction><relatedStateVariable>PortMappingDescription</relatedStateVariable></argument>
        <argument><name>NewLeaseDuration</name><direction>out</direction><relatedStateVariable>PortMappingLeaseDuration</relatedStateVariable></argument>
      </argumentList>
    </action>
    <action>
      <name>GetSpecificPortMappingEntry</name>
      <argumentList>
        <argument><name>NewRemoteHost</name><direction>in</direction><relatedStateVariable>RemoteHost</relatedStateVariable></argument>
        <argument><name>NewExternalPort</name><direction>in</direction><relatedStateVariable>ExternalPort</relatedStateVariable></argument>
        <argument><name>NewProtocol</name><direction>in</direction><relatedStateVariable>PortMappingProtocol</relatedStateVariable></argument>
        <argument><name>NewInternalPort</name><direction>out</direction><relatedStateVariable>InternalPort</relatedStateVariable></argument>
        <argument><name>NewInternalClient</name><direction>out</direction><relatedStateVariable>InternalClient</relatedStateVariable></argument>
        <argument><name>NewEnabled</name><direction>out</direction><relatedStateVariable>PortMappingEnabled</relatedStateVariable></argument>
        <argument><name>NewPortMappingDescription</name><direction>out</direction><relatedStateVariable>PortMappingDescription</relatedStateVariable></argument>
        <argument><name>NewLeaseDuration</name><direction>out</direction><relatedStateVariable>PortMappingLeaseDuration</relatedStateVariable></argument>
      </argumentList>
    </action>
    <action>
      <name>GetStatusInfo</name>
      <argumentList>
        <argument><name>NewConnectionStatus</name><direction>out</direction><relatedStateVariable>ConnectionStatus</relatedStateVariable></argument>
        <argument><name>NewLastConnectionError</name><direction>out</direction><relatedStateVariable>LastConnectionError</relatedStateVariable></argument>
        <argument><name>NewUptime</name><direction>out</direction><relatedStateVariable>Uptime</relatedStateVariable></argument>
      </argumentList>
    </action>
  </actionList>
  <serviceStateTable>
    <stateVariable sendEvents="no"><name>RemoteHost</name><dataType>string</dataType></stateVariable>
    <stateVariable sendEvents="no"><name>ExternalPort</name><dataType>ui2</dataType></stateVariable>
    <stateVariable sendEvents="no"><name>PortMappingProtocol</name><dataType>string</dataType><allowedValueList><allowedValue>TCP</allowedValue><allowedValue>UDP</allowedValue></allowedValueList></stateVariable>
    <stateVariable sendEvents="no"><name>InternalPort</name><dataType>ui2</dataType></stateVariable>
    <stateVariable sendEvents="no"><name>InternalClient</name><dataType>string</dataType></stateVariable>
    <stateVariable sendEvents="no"><name>PortMappingEnabled</name><dataType>boolean</dataType></stateVariable>
    <stateVariable sendEvents="no"><name>PortMappingDescription</name><dataType>string</dataType></stateVariable>
    <stateVariable sendEvents="no"><name>PortMappingLeaseDuration</name><dataType>ui4</dataType></stateVariable>
    <stateVariable sendEvents="yes"><name>ExternalIPAddress</name><dataType>string</dataType></stateVariable>
    <stateVariable sendEvents="yes"><name>PortMappingNumberOfEntries</name><dataType>ui2</dataType></stateVariable>
    <stateVariable sendEvents="no"><name>ConnectionStatus</name><dataType>string</dataType></stateVariable>
    <stateVariable sendEvents="no"><name>LastConnectionError</name><dataType>string</dataType></stateVariable>
    <stateVariable sendEvents="no"><name>Uptime</name><dataType>ui4</dataType></stateVariable>
  </serviceStateTable>
</scpd>"#;

async fn wan_ip_conn_scpd() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("Content-Type", "text/xml; charset=\"utf-8\"")],
        WAN_IP_CONN_SCPD,
    )
}

// ---------------------------------------------------------------------------
// SCPD: WANCommonInterfaceConfig (minimal)
// ---------------------------------------------------------------------------

const WAN_COMMON_IFC_SCPD: &str = r#"<?xml version="1.0"?>
<scpd xmlns="urn:schemas-upnp-org:service-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <actionList>
    <action>
      <name>GetTotalBytesReceived</name>
      <argumentList>
        <argument><name>NewTotalBytesReceived</name><direction>out</direction><relatedStateVariable>TotalBytesReceived</relatedStateVariable></argument>
      </argumentList>
    </action>
    <action>
      <name>GetTotalBytesSent</name>
      <argumentList>
        <argument><name>NewTotalBytesSent</name><direction>out</direction><relatedStateVariable>TotalBytesSent</relatedStateVariable></argument>
      </argumentList>
    </action>
  </actionList>
  <serviceStateTable>
    <stateVariable sendEvents="no"><name>TotalBytesReceived</name><dataType>ui4</dataType></stateVariable>
    <stateVariable sendEvents="no"><name>TotalBytesSent</name><dataType>ui4</dataType></stateVariable>
  </serviceStateTable>
</scpd>"#;

async fn wan_common_ifc_scpd() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("Content-Type", "text/xml; charset=\"utf-8\"")],
        WAN_COMMON_IFC_SCPD,
    )
}

// ---------------------------------------------------------------------------
// SOAP action dispatch: POST /ctl/WANIPConn
// ---------------------------------------------------------------------------

/// Get the WAN IP address by parsing `ip -4 -o addr show <iface>`.
/// Cached for 30 seconds to avoid subprocess fork on every UPnP request.
fn get_wan_ip(wan_iface: &str) -> Option<String> {
    use std::sync::Mutex;
    static CACHE: Mutex<Option<(Instant, Option<String>)>> = Mutex::new(None);
    let mut guard = CACHE.lock().unwrap();
    if let Some((ref ts, ref ip)) = *guard
        && ts.elapsed().as_secs() < 30 {
            return ip.clone();
        }
    let ip = query_wan_ip(wan_iface);
    *guard = Some((Instant::now(), ip.clone()));
    ip
}

fn query_wan_ip(wan_iface: &str) -> Option<String> {
    let output = std::process::Command::new("ip")
        .args(["-4", "-o", "addr", "show", wan_iface])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    // Format: "2: eth1    inet 192.168.1.100/24 brd ..."
    for part in text.split_whitespace() {
        if part.contains('/') {
            let ip_str = part.split('/').next()?;
            if ip_str.parse::<Ipv4Addr>().is_ok() {
                return Some(ip_str.to_string());
            }
        }
    }
    None
}

/// Extract the SOAP action name from the SOAPAction header.
/// Format: "urn:schemas-upnp-org:service:WANIPConnection:1#ActionName"
fn parse_soap_action(headers: &HeaderMap) -> Option<String> {
    let val = headers.get("SOAPAction")?.to_str().ok()?;
    let val = val.trim_matches('"');
    val.rsplit_once('#').map(|(_, action)| action.to_string())
}

/// System boot time for uptime calculation.
static BOOT_TIME: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

fn uptime_secs() -> u64 {
    let boot = BOOT_TIME.get_or_init(std::time::Instant::now);
    boot.elapsed().as_secs()
}

async fn soap_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let src_ip = match addr {
        SocketAddr::V4(v4) => *v4.ip(),
        SocketAddr::V6(v6) => {
            // Attempt to extract mapped IPv4
            if let Some(v4) = v6.ip().to_ipv4_mapped() {
                v4
            } else {
                return soap_error(606, "Action not authorized");
            }
        }
    };

    // Group check: only trusted devices may use UPnP SOAP
    {
        let db_guard = state.db.lock().unwrap();
        if !is_trusted(&db_guard, &src_ip) {
            info!(ip = %src_ip, "UPnP SOAP request from non-trusted device");
            return soap_error(606, "Action not authorized");
        }
    }

    let action = match parse_soap_action(&headers) {
        Some(a) => a,
        None => return soap_error(401, "Invalid Action"),
    };

    debug!(action = %action, from = %src_ip, "UPnP SOAP request");

    match action.as_str() {
        "AddPortMapping" => handle_add_port_mapping(&state, &src_ip, &body),
        "DeletePortMapping" => handle_delete_port_mapping(&state, &src_ip, &body),
        "GetExternalIPAddress" => handle_get_external_ip(&state),
        "GetGenericPortMappingEntry" => handle_get_generic_entry(&state, &body),
        "GetSpecificPortMappingEntry" => handle_get_specific_entry(&state, &body),
        "GetStatusInfo" => handle_get_status_info(),
        _ => soap_error(401, "Invalid Action"),
    }
}

// ---------------------------------------------------------------------------
// SOAP action: AddPortMapping
// ---------------------------------------------------------------------------

fn handle_add_port_mapping(state: &AppState, src_ip: &Ipv4Addr, body: &str) -> Response {
    let ext_port: u16 = match extract_xml_value(body, "NewExternalPort").and_then(|v| v.parse().ok())
    {
        Some(p) => p,
        None => return soap_error(402, "Invalid Args"),
    };
    let protocol = match extract_xml_value(body, "NewProtocol") {
        Some(p) => p.to_ascii_lowercase(),
        None => return soap_error(402, "Invalid Args"),
    };
    let int_port: u16 =
        match extract_xml_value(body, "NewInternalPort").and_then(|v| v.parse().ok()) {
            Some(p) => p,
            None => return soap_error(402, "Invalid Args"),
        };
    let int_client = match extract_xml_value(body, "NewInternalClient") {
        Some(c) if !c.is_empty() => c,
        _ => src_ip.to_string(),
    };
    let description = extract_xml_value(body, "NewPortMappingDescription").unwrap_or_default();
    let lease_duration: u32 = extract_xml_value(body, "NewLeaseDuration")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let req = crate::portmap::MappingRequest {
        protocol,
        external_port: ext_port,
        internal_ip: int_client,
        internal_port: int_port,
        description,
        source: "upnp".to_string(),
        requesting_ip: src_ip.to_string(),
        lease_secs: lease_duration,
    };

    match state.portmap.add_mapping(&req) {
        Ok(_resp) => soap_ok("AddPortMapping", ""),
        Err(e) => {
            let (code, desc) = match e {
                crate::portmap::MappingError::SecureMode => (718, "ConflictInMappingEntry"),
                crate::portmap::MappingError::Conflict(_) => (718, "ConflictInMappingEntry"),
                crate::portmap::MappingError::PrivilegedPort => (716, "WildCardNotPermittedInExtPort"),
                crate::portmap::MappingError::PerIpLimit => (728, "NoPortMapsAvailable"),
                crate::portmap::MappingError::GlobalLimit => (728, "NoPortMapsAvailable"),
                crate::portmap::MappingError::NotTrusted => (606, "Action not authorized"),
                crate::portmap::MappingError::Internal(ref msg) => {
                    warn!(error = %msg, "UPnP AddPortMapping internal error");
                    (501, "Action Failed")
                }
            };
            soap_error(code, desc)
        }
    }
}

// ---------------------------------------------------------------------------
// SOAP action: DeletePortMapping
// ---------------------------------------------------------------------------

fn handle_delete_port_mapping(state: &AppState, src_ip: &Ipv4Addr, body: &str) -> Response {
    let ext_port: u16 = match extract_xml_value(body, "NewExternalPort").and_then(|v| v.parse().ok())
    {
        Some(p) => p,
        None => return soap_error(402, "Invalid Args"),
    };
    let protocol = match extract_xml_value(body, "NewProtocol") {
        Some(p) => p.to_ascii_lowercase(),
        None => return soap_error(402, "Invalid Args"),
    };

    match state
        .portmap
        .remove_mapping(&protocol, ext_port, &src_ip.to_string())
    {
        Ok(()) => soap_ok("DeletePortMapping", ""),
        Err(crate::portmap::MappingError::Conflict(_)) => {
            soap_error(714, "NoSuchEntryInArray")
        }
        Err(e) => {
            warn!(error = %e, "UPnP DeletePortMapping error");
            soap_error(501, "Action Failed")
        }
    }
}

// ---------------------------------------------------------------------------
// SOAP action: GetExternalIPAddress
// ---------------------------------------------------------------------------

fn handle_get_external_ip(state: &AppState) -> Response {
    let wan_ip = get_wan_ip(&state.wan_iface).unwrap_or_default();
    soap_ok(
        "GetExternalIPAddress",
        &format!("      <NewExternalIPAddress>{wan_ip}</NewExternalIPAddress>"),
    )
}

// ---------------------------------------------------------------------------
// SOAP action: GetGenericPortMappingEntry
// ---------------------------------------------------------------------------

fn handle_get_generic_entry(state: &AppState, body: &str) -> Response {
    let index: usize =
        match extract_xml_value(body, "NewPortMappingIndex").and_then(|v| v.parse().ok()) {
            Some(i) => i,
            None => return soap_error(402, "Invalid Args"),
        };

    let mappings = state.portmap.list_mappings();
    let fwd = match mappings.get(index) {
        Some(f) => f,
        None => return soap_error(713, "SpecifiedArrayIndexInvalid"),
    };

    let remaining = remaining_lease(fwd);
    let body_xml = format!(
        "      <NewRemoteHost></NewRemoteHost>\n\
         <NewExternalPort>{}</NewExternalPort>\n\
         <NewProtocol>{}</NewProtocol>\n\
         <NewInternalPort>{}</NewInternalPort>\n\
         <NewInternalClient>{}</NewInternalClient>\n\
         <NewEnabled>1</NewEnabled>\n\
         <NewPortMappingDescription>{}</NewPortMappingDescription>\n\
         <NewLeaseDuration>{}</NewLeaseDuration>",
        fwd.external_port_start,
        fwd.protocol.to_ascii_uppercase(),
        fwd.internal_port,
        fwd.internal_ip,
        xml_escape(&fwd.description),
        remaining,
    );
    soap_ok("GetGenericPortMappingEntry", &body_xml)
}

// ---------------------------------------------------------------------------
// SOAP action: GetSpecificPortMappingEntry
// ---------------------------------------------------------------------------

fn handle_get_specific_entry(state: &AppState, body: &str) -> Response {
    let ext_port: u16 = match extract_xml_value(body, "NewExternalPort").and_then(|v| v.parse().ok())
    {
        Some(p) => p,
        None => return soap_error(402, "Invalid Args"),
    };
    let protocol = match extract_xml_value(body, "NewProtocol") {
        Some(p) => p.to_ascii_lowercase(),
        None => return soap_error(402, "Invalid Args"),
    };

    let fwd = match state.portmap.get_mapping(&protocol, ext_port) {
        Some(f) => f,
        None => return soap_error(714, "NoSuchEntryInArray"),
    };

    let remaining = remaining_lease(&fwd);
    let body_xml = format!(
        "      <NewInternalPort>{}</NewInternalPort>\n\
         <NewInternalClient>{}</NewInternalClient>\n\
         <NewEnabled>1</NewEnabled>\n\
         <NewPortMappingDescription>{}</NewPortMappingDescription>\n\
         <NewLeaseDuration>{}</NewLeaseDuration>",
        fwd.internal_port, fwd.internal_ip, xml_escape(&fwd.description), remaining,
    );
    soap_ok("GetSpecificPortMappingEntry", &body_xml)
}

/// Compute remaining lease seconds for a port forward (0 = permanent/manual).
fn remaining_lease(fwd: &crate::db::PortForward) -> u64 {
    match fwd.expires_at {
        Some(exp) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            if exp > now {
                (exp - now) as u64
            } else {
                0
            }
        }
        None => 0,
    }
}

// ---------------------------------------------------------------------------
// SOAP action: GetStatusInfo
// ---------------------------------------------------------------------------

fn handle_get_status_info() -> Response {
    let uptime = uptime_secs();
    let body_xml = format!(
        "      <NewConnectionStatus>Connected</NewConnectionStatus>\n\
         <NewLastConnectionError>ERROR_NONE</NewLastConnectionError>\n\
         <NewUptime>{uptime}</NewUptime>"
    );
    soap_ok("GetStatusInfo", &body_xml)
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------

async fn run_http_server(
    db: Arc<Mutex<Db>>,
    portmap: crate::portmap::SharedRegistry,
    wan_iface: String,
    device_uuid: String,
    lan_ip: Ipv4Addr,
) {
    let state = AppState {
        db,
        portmap,
        wan_iface,
        device_uuid,
    };

    let app = Router::new()
        .route("/rootDesc.xml", get(root_desc))
        .route("/WANIPConn.xml", get(wan_ip_conn_scpd))
        .route("/WANCommonIFC.xml", get(wan_common_ifc_scpd))
        .route("/ctl/WANIPConn", post(soap_handler))
        .with_state(state);

    let bind_addr: SocketAddr = SocketAddr::new(lan_ip.into(), HTTP_PORT);
    let listener = match tokio::net::TcpListener::bind(bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(addr = %bind_addr, error = %e, "failed to bind UPnP HTTP server");
            return;
        }
    };

    info!(addr = %bind_addr, "UPnP HTTP server started");

    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    {
        error!(error = %e, "UPnP HTTP server error");
    }
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

pub async fn run(
    db: Arc<Mutex<Db>>,
    portmap: crate::portmap::SharedRegistry,
    wan_iface: String,
    lan_iface: String,
    lan_ip_str: String,
) {
    let lan_ip: Ipv4Addr = lan_ip_str.parse().unwrap_or(Ipv4Addr::new(10, 0, 0, 1));

    // Initialise boot time for uptime reporting
    BOOT_TIME.get_or_init(std::time::Instant::now);

    // Get or generate device UUID
    let device_uuid = {
        let db_guard = db.lock().unwrap();
        match db_guard.get_config("upnp_device_uuid") {
            Ok(Some(uuid)) => uuid,
            _ => {
                let uuid = uuid::Uuid::new_v4().to_string();
                let _ = db_guard.set_config("upnp_device_uuid", &uuid);
                uuid
            }
        }
    };

    // Spawn SSDP listener task
    let db_ssdp = db.clone();
    let uuid_ssdp = device_uuid.clone();
    tokio::spawn(async move {
        run_ssdp(db_ssdp, uuid_ssdp, lan_iface, lan_ip).await;
    });

    // Run HTTP/SOAP server (blocks)
    run_http_server(db, portmap, wan_iface, device_uuid, lan_ip).await;
}
