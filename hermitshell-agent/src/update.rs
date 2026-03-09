use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};

use crate::paths;

/// Ed25519 public key for release signature verification.
/// Generated offline; private key stored as CI secret RELEASE_SIGNING_KEY.
const RELEASE_PUBLIC_KEY: &[u8; 32] = include_bytes!("../../keys/release.pub.bin");

const GITHUB_RELEASES_URL: &str =
    "https://api.github.com/repos/hermitshell-router/hermitshell/releases/latest";
const GITHUB_DOWNLOAD_URL: &str = "https://github.com/hermitshell-router/hermitshell/releases/download";
const CHECK_INTERVAL_SECS: u64 = 86400; // 24 hours
const BINARIES: &[&str] = &["hermitshell-agent", "hermitshell-dhcp", "hermitshell"];

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
    validate_version(&tag)?;
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
                {
                    let db = db.lock().unwrap();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        .to_string();
                    let _ = db.set_config("update_last_check", &now);
                }

                match result {
                    Ok(Some(version)) => {
                        {
                            let db = db.lock().unwrap();
                            let _ = db.set_config("update_latest_version", &version);
                        }
                        debug!(version = %version, "update check complete");

                        // Auto-update if enabled and version differs
                        let auto_enabled = {
                            let db = db.lock().unwrap();
                            db.get_config("auto_update_enabled").ok().flatten()
                                .map(|v| v == "true").unwrap_or(false)
                        };
                        let current = format!("v{}", current_version());
                        if auto_enabled && version != current {
                            info!(version = %version, "auto-update: applying");
                            match apply_update(&db).await {
                                Ok(v) => {
                                    info!(version = %v, "auto-update: download complete, restarting");
                                    trigger_staged_restart();
                                    return; // exit loop — agent is restarting
                                }
                                Err(e) => {
                                    warn!(error = %e, "auto-update: apply failed");
                                }
                            }
                        }
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

/// Current agent version from Cargo.toml.
pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Validate that a version string looks like a release tag (e.g. v0.1.0, v1.2.3-rc1).
fn validate_version(v: &str) -> anyhow::Result<()> {
    if !v.starts_with('v') || v.len() > 32
        || !v[1..].chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        anyhow::bail!("invalid version format: {}", v);
    }
    Ok(())
}

/// Verify an Ed25519 detached signature over data using the provided public key.
fn verify_release_signature(
    data: &[u8],
    sig_bytes: &[u8; 64],
    pub_key_bytes: &[u8; 32],
) -> anyhow::Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let verifying_key = VerifyingKey::from_bytes(pub_key_bytes)
        .map_err(|e| anyhow::anyhow!("invalid public key: {}", e))?;
    let signature = Signature::from_bytes(sig_bytes);
    verifying_key
        .verify(data, &signature)
        .map_err(|e| anyhow::anyhow!("signature verification failed: {}", e))
}

/// Download, verify, and stage a new release. Returns the version string on success.
/// Does NOT restart — the caller must trigger the restart after responding to the client.
pub async fn apply_update(db: &std::sync::Arc<std::sync::Mutex<crate::db::Db>>) -> anyhow::Result<String> {
    let latest = {
        let db = db.lock().unwrap();
        db.get_config("update_latest_version").ok().flatten()
    };
    let Some(version) = latest else {
        anyhow::bail!("no update available");
    };
    validate_version(&version)?;
    let current = format!("v{}", current_version());
    if version == current {
        anyhow::bail!("already running {}", version);
    }

    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        _ => anyhow::bail!("unsupported architecture: {}", std::env::consts::ARCH),
    };

    let tarball_name = format!("hermitshell-{}-{}-linux.tar.gz", version, arch);
    let tarball_url = format!("{}/{}/{}", GITHUB_DOWNLOAD_URL, version, tarball_name);
    let checksum_url = format!("{}.sha256", tarball_url);

    info!(version = %version, "downloading update");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .user_agent("hermitshell-agent")
        .build()?;

    // Download tarball
    let tarball_bytes = client.get(&tarball_url).send().await?
        .error_for_status()?
        .bytes().await?;

    // Download and verify checksum
    let checksum_text = client.get(&checksum_url).send().await?
        .error_for_status()?
        .text().await?;
    let expected_hash = checksum_text.split_whitespace().next()
        .ok_or_else(|| anyhow::anyhow!("invalid checksum file"))?;

    use sha2::{Sha256, Digest};
    let actual_hash = hex::encode(Sha256::digest(&tarball_bytes));
    if actual_hash != expected_hash {
        anyhow::bail!("checksum mismatch: expected {} got {}", expected_hash, actual_hash);
    }
    info!("checksum verified");

    // Download and verify Ed25519 signature
    let sig_url = format!("{}.sig", tarball_url);
    let sig_bytes = client.get(&sig_url).send().await?
        .error_for_status()
        .map_err(|e| anyhow::anyhow!("signature file not available for {}: {}", version, e))?
        .bytes().await?;
    if sig_bytes.len() != 64 {
        anyhow::bail!(
            "invalid signature file: expected 64 bytes, got {}",
            sig_bytes.len()
        );
    }
    let sig_array: [u8; 64] = sig_bytes[..64].try_into().unwrap();
    verify_release_signature(&tarball_bytes, &sig_array, RELEASE_PUBLIC_KEY)?;
    info!("signature verified");

    // Create rollback dir and copy current binaries
    let rollback_dir = paths::rollback_dir();
    let install_dir = paths::install_dir();
    std::fs::create_dir_all(&rollback_dir)?;
    for bin in BINARIES {
        let src = format!("{}/{}", install_dir, bin);
        let dst = format!("{}/{}", rollback_dir, bin);
        if std::path::Path::new(&src).exists() {
            std::fs::copy(&src, &dst)?;
        }
    }
    info!("current binaries backed up to rollback/");

    // Extract to staging dir
    let staging_dir = paths::staging_dir();
    let staging = std::path::Path::new(&staging_dir);
    if staging.exists() {
        std::fs::remove_dir_all(staging)?;
    }
    std::fs::create_dir_all(staging)?;

    let tar_gz = flate2::read::GzDecoder::new(std::io::Cursor::new(&tarball_bytes));
    let mut archive = tar::Archive::new(tar_gz);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        if path.is_absolute() || path.components().any(|c| c == std::path::Component::ParentDir) {
            anyhow::bail!("tarball contains unsafe path: {}", path.display());
        }
        let entry_type = entry.header().entry_type();
        if entry_type == tar::EntryType::Symlink || entry_type == tar::EntryType::Link {
            warn!(path = %path.display(), "skipping symlink/hardlink in tarball");
            continue;
        }
        entry.unpack_in(staging)?;
    }

    // Atomic rename each binary from staging to install dir
    for bin in BINARIES {
        // tarball may have a top-level directory — find the binary
        let staged = find_binary(staging, bin)?;
        let dest = format!("{}/{}", install_dir, bin);
        std::fs::rename(&staged, &dest)?;
    }
    info!("binaries swapped");

    // Clean up staging
    let _ = std::fs::remove_dir_all(staging);

    // Write update marker
    let update_marker = paths::update_marker();
    std::fs::write(&update_marker, &version)?;
    info!(version = %version, "update marker written");

    // Store version in DB
    {
        let db = db.lock().unwrap();
        let _ = db.set_config("update_installed_version", &version);
    }

    Ok(version)
}

/// Find a binary inside the staging directory (may be nested in a subdirectory).
fn find_binary(staging: &std::path::Path, name: &str) -> anyhow::Result<std::path::PathBuf> {
    // Check top-level first
    let direct = staging.join(name);
    if direct.exists() {
        return Ok(direct);
    }
    // Check one level of subdirectory (tarball with strip-components=1 equivalent)
    for entry in std::fs::read_dir(staging)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let nested = entry.path().join(name);
            if nested.exists() {
                return Ok(nested);
            }
        }
    }
    anyhow::bail!("binary '{}' not found in staging", name)
}

/// Trigger staged restart: UI first, then agent.
/// This function spawns a detached task and returns immediately.
pub fn trigger_staged_restart() {
    tokio::spawn(async {
        info!("restarting hermitshell-ui");
        if let Err(e) = tokio::process::Command::new("systemctl")
            .args(["restart", "hermitshell-ui"])
            .status().await
        {
            warn!(error = %e, "failed to restart hermitshell-ui");
        }

        // Poll until UI is active (max 10 seconds)
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if tokio::time::Instant::now() >= deadline {
                warn!("hermitshell-ui did not become active within 10s");
                break;
            }
            match tokio::process::Command::new("systemctl")
                .args(["is-active", "--quiet", "hermitshell-ui"])
                .status().await
            {
                Ok(status) if status.success() => break,
                _ => tokio::time::sleep(std::time::Duration::from_millis(250)).await,
            }
        }

        info!("restarting hermitshell-agent");
        if let Err(e) = tokio::process::Command::new("systemctl")
            .args(["restart", "hermitshell-agent"])
            .status().await
        {
            warn!(error = %e, "failed to restart hermitshell-agent");
        }
    });
}

/// Check for update marker on startup. Returns Ok(Some(version)) if update succeeded.
pub fn check_update_marker() -> anyhow::Result<Option<String>> {
    let marker_path = paths::update_marker();
    let marker = std::path::Path::new(&marker_path);
    if !marker.exists() {
        return Ok(None);
    }
    let expected_version = std::fs::read_to_string(marker)?;
    let expected_version = expected_version.trim();
    let current = format!("v{}", current_version());

    if current == expected_version {
        // Update succeeded — clean up
        std::fs::remove_file(marker)?;
        let _ = std::fs::remove_dir_all(paths::rollback_dir());
        info!(version = %current, "update successful, marker cleared");
        Ok(Some(current))
    } else {
        // Version mismatch — rollback was triggered by rollback.sh,
        // or rollback.sh didn't run. Clean up the marker.
        tracing::warn!(
            expected = %expected_version, current = %current,
            "update marker present but version mismatch — rollback may have occurred"
        );
        std::fs::remove_file(marker)?;
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_version_valid() {
        assert!(validate_version("v0.1.0").is_ok());
        assert!(validate_version("v1.2.3-rc1").is_ok());
    }

    #[test]
    fn test_validate_version_invalid() {
        assert!(validate_version("0.1.0").is_err());
        assert!(validate_version(&format!("v{}", "a".repeat(32))).is_err());
    }

    #[test]
    fn test_verify_signature_valid() {
        use ed25519_dalek::{Signer, SigningKey};
        // Deterministic key from fixed seed
        let seed: [u8; 32] = [1u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let message = b"test tarball content";
        let signature = signing_key.sign(message);
        let pub_key_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
        assert!(verify_release_signature(message, &signature.to_bytes(), &pub_key_bytes).is_ok());
    }

    #[test]
    fn test_verify_signature_wrong_key() {
        use ed25519_dalek::{Signer, SigningKey};
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let message = b"test tarball content";
        let signature = signing_key.sign(message);
        let wrong_key = SigningKey::from_bytes(&[2u8; 32]);
        let wrong_pub: [u8; 32] = wrong_key.verifying_key().to_bytes();
        assert!(verify_release_signature(message, &signature.to_bytes(), &wrong_pub).is_err());
    }

    #[test]
    fn test_verify_signature_tampered() {
        use ed25519_dalek::{Signer, SigningKey};
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let signature = signing_key.sign(b"original");
        let pub_key_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
        assert!(verify_release_signature(b"tampered", &signature.to_bytes(), &pub_key_bytes).is_err());
    }

    #[test]
    fn test_embedded_public_key_valid() {
        // Verify the embedded public key can be parsed as a valid Ed25519 key
        use ed25519_dalek::VerifyingKey;
        assert!(
            VerifyingKey::from_bytes(RELEASE_PUBLIC_KEY).is_ok(),
            "embedded release public key is not a valid Ed25519 key"
        );
    }
}
