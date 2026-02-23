use std::sync::{Arc, Mutex};
use tracing::{error, info, warn};

use crate::db::Db;

/// Run the TLS certificate renewal loop. Checks once per day.
pub async fn run_renewal(db: Arc<Mutex<Db>>) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(86400));
    // First tick is immediate — skip it to avoid racing with startup cert gen
    interval.tick().await;

    loop {
        interval.tick().await;
        if let Err(e) = check_and_renew(&db).await {
            error!(error = %e, "TLS renewal check failed");
        }
    }
}

async fn check_and_renew(db: &Arc<Mutex<Db>>) -> anyhow::Result<()> {
    let (mode, domain) = {
        let db = db.lock().unwrap();
        let mode = db.get_config("tls_mode").ok().flatten().unwrap_or_else(|| "self_signed".to_string());
        let domain = db.get_config("acme_domain").ok().flatten().unwrap_or_default();
        (mode, domain)
    };

    match mode.as_str() {
        "tailscale" => {
            if domain.is_empty() {
                return Ok(());
            }
            if needs_renewal(db)? {
                info!(domain = %domain, "renewing Tailscale cert");
                match provision_tailscale(&domain).await {
                    Ok((cert, key)) => {
                        let db = db.lock().unwrap();
                        let _ = db.set_config("tls_cert_pem", &cert);
                        let _ = db.set_config("tls_key_pem", &key);
                        info!("Tailscale cert renewed");
                    }
                    Err(e) => error!(error = %e, "Tailscale cert renewal failed"),
                }
            }
        }
        "acme_dns01" => {
            if domain.is_empty() {
                return Ok(());
            }
            if needs_renewal(db)? {
                info!(domain = %domain, "renewing ACME DNS-01 cert");
                if let Err(e) = provision_acme_dns01(db).await {
                    error!(error = %e, "ACME DNS-01 renewal failed");
                }
            }
        }
        _ => {} // self_signed and custom: no auto-renewal
    }
    Ok(())
}

fn needs_renewal(db: &Arc<Mutex<Db>>) -> anyhow::Result<bool> {
    let cert_pem = {
        let db = db.lock().unwrap();
        db.get_config("tls_cert_pem").ok().flatten()
    };
    let Some(pem) = cert_pem else {
        return Ok(true);
    };

    let cert_der = rustls_pemfile::certs(&mut pem.as_bytes())
        .filter_map(|c| c.ok())
        .next();
    let Some(der) = cert_der else {
        return Ok(true);
    };
    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| anyhow::anyhow!("failed to parse cert: {}", e))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    let expires_at = cert.validity().not_after.timestamp();
    let days_remaining = (expires_at - now) / 86400;

    Ok(days_remaining < 30)
}

/// Provision a cert from Tailscale by running `tailscale cert`.
pub async fn provision_tailscale(domain: &str) -> anyhow::Result<(String, String)> {
    let output = tokio::process::Command::new("tailscale")
        .args(["cert", "--cert-file=-", "--key-file=-", domain])
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("failed to run tailscale cert: {} (is tailscale installed?)", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("tailscale cert failed: {}", stderr.trim());
    }

    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| anyhow::anyhow!("tailscale cert output is not valid UTF-8"))?;

    // tailscale cert --cert-file=- --key-file=- outputs cert then key concatenated
    let mut cert_pem = String::new();
    let mut key_pem = String::new();
    let mut in_key = false;
    let mut found_cert_end = false;

    for line in stdout.lines() {
        if found_cert_end && line.starts_with("-----BEGIN") {
            in_key = true;
        }
        if line.contains("END CERTIFICATE") {
            found_cert_end = true;
        }
        if in_key {
            key_pem.push_str(line);
            key_pem.push('\n');
        } else {
            cert_pem.push_str(line);
            cert_pem.push('\n');
        }
    }

    if cert_pem.is_empty() || key_pem.is_empty() {
        anyhow::bail!("tailscale cert output missing cert or key");
    }

    Ok((cert_pem, key_pem))
}

/// Provision a cert via ACME DNS-01 with Cloudflare. Placeholder — implemented in Task 6.
pub async fn provision_acme_dns01(db: &Arc<Mutex<Db>>) -> anyhow::Result<()> {
    warn!("ACME DNS-01 provisioning not yet implemented");
    let _ = db;
    Ok(())
}
