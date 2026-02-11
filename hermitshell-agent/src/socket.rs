use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::db::Db;
use crate::nftables;
use crate::subnet;

#[derive(Debug, Deserialize)]
struct Request {
    method: String,
    mac: Option<String>,
    group: Option<String>,
}

#[derive(Debug, Serialize)]
struct Response {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    devices: Option<Vec<crate::db::Device>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device: Option<crate::db::Device>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<Status>,
}

#[derive(Debug, Serialize)]
struct Status {
    uptime_secs: u64,
    device_count: usize,
}

impl Response {
    fn ok() -> Self {
        Self { ok: true, error: None, devices: None, device: None, status: None }
    }
    fn err(msg: &str) -> Self {
        Self { ok: false, error: Some(msg.to_string()), devices: None, device: None, status: None }
    }
}

pub async fn run_server(socket_path: &str, db: Arc<Mutex<Db>>, start_time: std::time::Instant) -> Result<()> {
    // Remove old socket if exists
    let _ = std::fs::remove_file(socket_path);

    // Create socket directory
    if let Some(parent) = std::path::Path::new(socket_path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(socket_path)?;

    // Set permissions so container can access
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o666))?;
    }

    println!("Socket server listening on {}", socket_path);

    loop {
        let (stream, _) = listener.accept().await?;
        let db = db.clone();
        let start = start_time;

        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, db, start).await {
                eprintln!("Client error: {}", e);
            }
        });
    }
}

async fn handle_client(stream: UnixStream, db: Arc<Mutex<Db>>, start_time: std::time::Instant) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    while reader.read_line(&mut line).await? > 0 {
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(req) => handle_request(req, &db, start_time),
            Err(e) => Response::err(&format!("Invalid JSON: {}", e)),
        };

        let mut json = serde_json::to_string(&response)?;
        json.push('\n');
        writer.write_all(json.as_bytes()).await?;
        line.clear();
    }

    Ok(())
}

fn handle_request(req: Request, db: &Arc<Mutex<Db>>, start_time: std::time::Instant) -> Response {
    match req.method.as_str() {
        "list_devices" => {
            let db = db.lock().unwrap();
            match db.list_devices() {
                Ok(devices) => {
                    let mut resp = Response::ok();
                    resp.devices = Some(devices);
                    resp
                }
                Err(e) => Response::err(&e.to_string()),
            }
        }
        "get_device" => {
            let Some(mac) = req.mac else {
                return Response::err("mac required");
            };
            let db = db.lock().unwrap();
            match db.get_device(&mac) {
                Ok(Some(device)) => {
                    let mut resp = Response::ok();
                    resp.device = Some(device);
                    resp
                }
                Ok(None) => Response::err("device not found"),
                Err(e) => Response::err(&e.to_string()),
            }
        }
        "get_status" => {
            let db = db.lock().unwrap();
            let device_count = db.list_devices().map(|d| d.len()).unwrap_or(0);
            let mut resp = Response::ok();
            resp.status = Some(Status {
                uptime_secs: start_time.elapsed().as_secs(),
                device_count,
            });
            resp
        }
        "set_device_group" => {
            let Some(mac) = req.mac else {
                return Response::err("mac required");
            };
            let Some(group) = req.group else {
                return Response::err("group required");
            };
            match group.as_str() {
                "trusted" | "iot" | "guest" | "servers" => {}
                _ => return Response::err("invalid group: must be trusted, iot, guest, or servers"),
            }
            let db = db.lock().unwrap();
            let device = match db.get_device(&mac) {
                Ok(Some(d)) => d,
                Ok(None) => return Response::err("device not found"),
                Err(e) => return Response::err(&e.to_string()),
            };
            let Some(subnet_id) = device.subnet_id else {
                return Response::err("device has no subnet assignment");
            };
            let Some(info) = subnet::compute_subnet(subnet_id) else {
                return Response::err("invalid subnet_id");
            };
            let ip = &info.device_ip;
            if let Err(e) = nftables::remove_device_forward_rule(ip) {
                return Response::err(&format!("failed to remove old rule: {}", e));
            }
            if let Err(e) = db.set_device_group(&mac, &group) {
                return Response::err(&format!("failed to update group: {}", e));
            }
            if let Err(e) = nftables::add_device_forward_rule(ip, &group) {
                return Response::err(&format!("failed to add new rule: {}", e));
            }
            match db.get_device(&mac) {
                Ok(Some(device)) => {
                    let mut resp = Response::ok();
                    resp.device = Some(device);
                    resp
                }
                Ok(None) => Response::err("device not found after update"),
                Err(e) => Response::err(&e.to_string()),
            }
        }
        "block_device" => {
            let Some(mac) = req.mac else {
                return Response::err("mac required");
            };
            let db = db.lock().unwrap();
            let device = match db.get_device(&mac) {
                Ok(Some(d)) => d,
                Ok(None) => return Response::err("device not found"),
                Err(e) => return Response::err(&e.to_string()),
            };
            if let Some(ref ip) = device.ip {
                if let Err(e) = nftables::remove_device_forward_rule(ip) {
                    return Response::err(&format!("failed to remove forward rule: {}", e));
                }
            }
            if let Err(e) = db.block_device(&mac) {
                return Response::err(&format!("failed to block device: {}", e));
            }
            Response::ok()
        }
        "unblock_device" => {
            let Some(mac) = req.mac else {
                return Response::err("mac required");
            };
            let db = db.lock().unwrap();
            let device = match db.get_device(&mac) {
                Ok(Some(d)) => d,
                Ok(None) => return Response::err("device not found"),
                Err(e) => return Response::err(&e.to_string()),
            };
            if let Err(e) = db.unblock_device(&mac) {
                return Response::err(&format!("failed to unblock device: {}", e));
            }
            if let Some(ref ip) = device.ip {
                if let Err(e) = nftables::add_device_forward_rule(ip, "quarantine") {
                    return Response::err(&format!("failed to add forward rule: {}", e));
                }
            }
            Response::ok()
        }
        _ => Response::err("unknown method"),
    }
}
