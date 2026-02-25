use std::sync::{Arc, Mutex};
use tracing::{debug, warn};

const GITHUB_RELEASES_URL: &str =
    "https://api.github.com/repos/jnordwick/hermitshell/releases/latest";
const CHECK_INTERVAL_SECS: u64 = 86400; // 24 hours

/// Poll GitHub releases API for the latest release tag.
async fn check_for_update() -> anyhow::Result<Option<String>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("hermitshell-agent")
        .build()?;
    let resp = client.get(GITHUB_RELEASES_URL).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("GitHub API returned {}", resp.status());
    }
    let body: serde_json::Value = resp.json().await?;
    let tag = body["tag_name"].as_str().unwrap_or("").to_string();
    if tag.is_empty() {
        return Ok(None);
    }
    Ok(Some(tag))
}

/// Spawn a background task that periodically checks for new releases.
/// Stores `update_latest_version` and `update_last_check` in the config DB.
/// Non-blocking: failures are logged and silently ignored.
pub fn spawn_update_loop(db: Arc<Mutex<crate::db::Db>>) {
    tokio::spawn(async move {
        loop {
            // Exit if disabled at runtime
            {
                let db = db.lock().unwrap();
                let enabled = db.get_config("update_check_enabled").ok().flatten()
                    .map(|v| v == "true").unwrap_or(false);
                if !enabled {
                    debug!("update check disabled, stopping loop");
                    return;
                }
            }

            let should_check = {
                let db = db.lock().unwrap();
                let last_check: i64 = db
                    .get_config("update_last_check")
                    .ok()
                    .flatten()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                now - last_check >= CHECK_INTERVAL_SECS as i64
            };

            if should_check {
                let result = check_for_update().await;

                // Always update last_check to prevent rapid retries on failure
                let db = db.lock().unwrap();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    .to_string();
                let _ = db.set_config("update_last_check", &now);

                match result {
                    Ok(Some(version)) => {
                        let _ = db.set_config("update_latest_version", &version);
                        debug!(version = %version, "update check complete");
                    }
                    Ok(None) => {
                        debug!("no release found");
                    }
                    Err(e) => {
                        warn!(error = %e, "update check failed");
                    }
                }
            }

            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    });
}
