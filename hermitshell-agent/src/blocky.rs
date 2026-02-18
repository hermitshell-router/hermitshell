use anyhow::{Context, Result};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command};
use tracing::{debug, info};

pub struct BlockyManager {
    upstream_dns: Vec<String>,
    listen_addr: String,
    config_dir: String,
    binary_path: String,
    child: Option<Child>,
}

impl BlockyManager {
    pub fn new(
        upstream_dns: Vec<String>,
        listen_addr: String,
        config_dir: String,
        binary_path: String,
    ) -> Self {
        Self {
            upstream_dns,
            listen_addr,
            config_dir,
            binary_path,
            child: None,
        }
    }

    pub fn write_config(&self) -> Result<()> {
        std::fs::create_dir_all(&self.config_dir)?;
        std::fs::create_dir_all(&format!("{}/logs", self.config_dir))?;

        let servers: String = self
            .upstream_dns
            .iter()
            .map(|s| format!("      - {}", s))
            .collect::<Vec<_>>()
            .join("\n");

        let custom_blocklist = format!("{}/custom-blocklist.txt", self.config_dir);
        let log_dir = format!("{}/logs", self.config_dir);

        let config = format!(
            r#"upstreams:
  groups:
    default:
{servers}
blocking:
  denylists:
    ads:
      - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
      - file://{custom_blocklist}
  clientGroupsBlock:
    default:
      - ads
ports:
  dns: {listen}
  http: 127.0.0.1:4000
log:
  level: warn
queryLog:
  type: csv-client
  target: {log_dir}
  logRetentionDays: 1
  creationAttempts: 1
  creationCooldown: 5s
  fields:
    - questionName
    - questionType
    - responseCode
"#,
            servers = servers,
            custom_blocklist = custom_blocklist,
            listen = self.listen_addr,
            log_dir = log_dir,
        );

        let path = format!("{}/config.yml", self.config_dir);
        std::fs::write(&path, config)?;
        debug!(path = %path, "wrote blocky config");

        // Ensure the custom blocklist file exists (empty = no extra blocking)
        if !std::path::Path::new(&custom_blocklist).exists() {
            std::fs::write(&custom_blocklist, "")?;
        }

        Ok(())
    }

    pub fn start(&mut self) -> Result<()> {
        // Kill any existing blocky process
        self.stop();

        self.write_config()?;

        let config_path = format!("{}/config.yml", self.config_dir);
        let child = Command::new(&self.binary_path)
            .args(["--config", &config_path])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .context("failed to spawn blocky")?;

        info!(pid = child.id(), "started blocky");
        self.child = Some(child);
        Ok(())
    }

    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
            info!("stopped blocky");
        }
    }

    pub fn wait_for_ready(&self, timeout_secs: u64) -> bool {
        let start = std::time::Instant::now();
        let interval = std::time::Duration::from_millis(200);
        let timeout = std::time::Duration::from_secs(timeout_secs);
        while start.elapsed() < timeout {
            if http_request("127.0.0.1:4000", "/api/blocking/status").is_ok() {
                return true;
            }
            std::thread::sleep(interval);
        }
        false
    }

    pub fn set_blocking_enabled(&self, enabled: bool) -> Result<()> {
        let path = if enabled {
            "/api/blocking/enable"
        } else {
            "/api/blocking/disable"
        };
        http_request("127.0.0.1:4000", path)?;
        Ok(())
    }

}

impl Drop for BlockyManager {
    fn drop(&mut self) {
        self.stop();
    }
}

fn http_request(addr: &str, path: &str) -> Result<String> {
    let mut stream = TcpStream::connect(addr).context("connect to blocky API")?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, addr
    );
    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    let mut reader = BufReader::new(&stream);
    let mut headers_done = false;
    let mut body = String::new();

    // Read headers
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                if line.trim().is_empty() {
                    headers_done = true;
                    break;
                }
            }
            Err(_) => break,
        }
    }

    if headers_done {
        let _ = reader.read_to_string(&mut body);
    }

    Ok(body)
}
