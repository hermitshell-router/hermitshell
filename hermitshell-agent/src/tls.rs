use std::sync::{Arc, Mutex};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier,
    LetsEncrypt, NewAccount, NewOrder, OrderStatus,
};
use tracing::{error, info, warn};
use zeroize::Zeroizing;

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

    // tailscale cert --cert-file=- --key-file=- outputs cert chain then key concatenated
    let mut cert_pem = String::new();
    let mut key_pem = String::new();
    let mut in_key = false;

    for line in stdout.lines() {
        if line.starts_with("-----BEGIN") && line.contains("PRIVATE KEY") {
            in_key = true;
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

/// Provision a cert via ACME DNS-01 with Cloudflare.
pub async fn provision_acme_dns01(db: &Arc<Mutex<Db>>) -> anyhow::Result<()> {
    let (domain, email, cf_token, cf_zone_id, account_key) = {
        let db = db.lock().unwrap();
        (
            db.get_config("acme_domain").ok().flatten().unwrap_or_default(),
            db.get_config("acme_contact_email").ok().flatten().unwrap_or_default(),
            Zeroizing::new(db.get_config("acme_cf_api_token").ok().flatten().unwrap_or_default()),
            db.get_config("acme_cf_zone_id").ok().flatten().unwrap_or_default(),
            db.get_config("acme_account_key").ok().flatten().map(Zeroizing::new),
        )
    };

    if domain.is_empty() || cf_token.is_empty() || cf_zone_id.is_empty() {
        anyhow::bail!("ACME DNS-01 config incomplete");
    }

    let directory_url = if std::env::var("ACME_DIRECTORY").as_deref() == Ok("staging") {
        LetsEncrypt::Staging.url()
    } else {
        LetsEncrypt::Production.url()
    };

    let account = if let Some(ref credentials_json) = account_key {
        let credentials: instant_acme::AccountCredentials = serde_json::from_str(credentials_json)?;
        Account::builder()?
            .from_credentials(credentials)
            .await
            .map_err(|e| anyhow::anyhow!("failed to restore ACME account: {}", e))?
    } else {
        let contacts: Vec<String> = if email.is_empty() {
            vec![]
        } else {
            vec![format!("mailto:{}", email)]
        };
        let contact_refs: Vec<&str> = contacts.iter().map(|s| s.as_str()).collect();
        let (account, credentials) = Account::builder()?
            .create(
                &NewAccount {
                    contact: &contact_refs,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                directory_url.to_string(),
                None,
            )
            .await
            .map_err(|e| anyhow::anyhow!("failed to create ACME account: {}", e))?;

        let credentials_json = serde_json::to_string(&credentials)?;
        let db = db.lock().unwrap();
        let _ = db.set_config("acme_account_key", &credentials_json);
        account
    };

    let identifier = Identifier::Dns(domain.clone());
    let mut order = account
        .new_order(&NewOrder::new(&[identifier]))
        .await
        .map_err(|e| anyhow::anyhow!("failed to create ACME order: {}", e))?;

    let mut authorizations = order.authorizations();
    let mut authorization = authorizations
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("no authorizations"))?
        .map_err(|e| anyhow::anyhow!("failed to get authorization: {}", e))?;

    if matches!(authorization.status, AuthorizationStatus::Pending) {
        let mut challenge = authorization
            .challenge(ChallengeType::Dns01)
            .ok_or_else(|| anyhow::anyhow!("no DNS-01 challenge offered"))?;

        let dns_value = challenge.key_authorization().dns_value();

        let record_name = format!("_acme-challenge.{}", domain);
        let cf_record_id = cf_create_txt_record(&cf_token, &cf_zone_id, &record_name, &dns_value).await?;
        info!(record = %record_name, "DNS-01 TXT record created");

        // Poll DNS until the TXT record propagates (or timeout after 120s)
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(120);
        loop {
            let output = tokio::process::Command::new("dig")
                .args(["+short", "TXT", &record_name, "@1.1.1.1"])
                .output()
                .await;
            if let Ok(ref o) = output {
                let txt = String::from_utf8_lossy(&o.stdout);
                if txt.contains(&dns_value) {
                    break;
                }
            }
            if tokio::time::Instant::now() >= deadline {
                warn!("DNS propagation timeout, proceeding anyway");
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }

        challenge
            .set_ready()
            .await
            .map_err(|e| anyhow::anyhow!("failed to set challenge ready: {}", e))?;

        // Drop borrows so we can use order again
        #[allow(clippy::drop_non_drop)]
        drop(authorizations);

        let status = order
            .poll_ready(&instant_acme::RetryPolicy::new()
                .initial_delay(std::time::Duration::from_secs(5))
                .timeout(std::time::Duration::from_secs(150)))
            .await
            .map_err(|e| anyhow::anyhow!("order validation failed: {}", e))?;

        if matches!(status, OrderStatus::Invalid) {
            let _ = cf_delete_txt_record(&cf_token, &cf_zone_id, &cf_record_id).await;
            anyhow::bail!("ACME order invalid");
        }

        // Generate CSR with rcgen
        let mut params = rcgen::CertificateParams::new(vec![domain.clone()])?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        let private_key = rcgen::KeyPair::generate()?;
        let csr = params.serialize_request(&private_key)?;
        order
            .finalize_csr(csr.der())
            .await
            .map_err(|e| anyhow::anyhow!("failed to finalize order: {}", e))?;

        let cert_chain_pem = order
            .poll_certificate(&instant_acme::RetryPolicy::new()
                .initial_delay(std::time::Duration::from_secs(3))
                .timeout(std::time::Duration::from_secs(60)))
            .await
            .map_err(|e| anyhow::anyhow!("failed to get certificate: {}", e))?;

        let key_pem = private_key.serialize_pem();

        {
            let db = db.lock().unwrap();
            let _ = db.set_config("tls_cert_pem", &cert_chain_pem);
            let _ = db.set_config("tls_key_pem", &key_pem);
        }
        info!("ACME DNS-01 certificate issued");

        let _ = cf_delete_txt_record(&cf_token, &cf_zone_id, &cf_record_id).await;
        info!("DNS-01 TXT record cleaned up");
    }

    Ok(())
}

async fn cf_create_txt_record(token: &str, zone_id: &str, name: &str, content: &str) -> anyhow::Result<String> {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("https://api.cloudflare.com/client/v4/zones/{}/dns_records", zone_id))
        .header("Authorization", format!("Bearer {}", token))
        .json(&serde_json::json!({
            "type": "TXT",
            "name": name,
            "content": content,
            "ttl": 60,
        }))
        .send()
        .await?;

    let body: serde_json::Value = resp.json().await?;
    if !body.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
        let errors = body.get("errors").map(|e| e.to_string()).unwrap_or_default();
        anyhow::bail!("Cloudflare API error: {}", errors);
    }
    let record_id = body.get("result")
        .and_then(|r| r.get("id"))
        .and_then(|id| id.as_str())
        .ok_or_else(|| anyhow::anyhow!("no record id in Cloudflare response"))?;
    Ok(record_id.to_string())
}

async fn cf_delete_txt_record(token: &str, zone_id: &str, record_id: &str) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let resp = client
        .delete(format!("https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}", zone_id, record_id))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await?;

    if !resp.status().is_success() {
        warn!(status = %resp.status(), "failed to delete Cloudflare DNS record");
    }
    Ok(())
}
