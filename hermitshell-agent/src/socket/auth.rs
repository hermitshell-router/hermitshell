use super::*;
use zeroize::Zeroizing;

pub(super) fn handle_has_password(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    let has = db
        .get_config("admin_password_hash")
        .ok()
        .flatten()
        .is_some();
    let mut resp = Response::ok();
    resp.config_value = Some(if has { "true" } else { "false" }.to_string());
    resp
}

pub(super) fn handle_verify_password(req: &Request, db: &Arc<Mutex<Db>>, login_rate_limit: &LoginRateLimit, password_lock: &PasswordLock) -> Response {
    let Some(ref value) = req.value else {
        return Response::err("value required");
    };
    if value.len() > 128 {
        return Response::err("password too long");
    }
    if let Some(msg) = check_login_rate_limit(login_rate_limit) {
        warn!("verify_password rate-limited");
        return Response::err(&msg);
    }
    let _pw_guard = password_lock.lock().unwrap();
    let hash_str = {
        let db = db.lock().unwrap();
        db.get_config("admin_password_hash").ok().flatten().map(Zeroizing::new)
    };
    let hash_str = match hash_str {
        Some(h) => h,
        None => {
            warn!("password verification failed");
            record_login_failure(login_rate_limit);
            let mut resp = Response::ok();
            resp.config_value = Some("false".to_string());
            return resp;
        }
    };
    let parsed_hash = match PasswordHash::new(&hash_str) {
        Ok(h) => h,
        Err(_) => {
            warn!("password verification failed");
            record_login_failure(login_rate_limit);
            let mut resp = Response::ok();
            resp.config_value = Some("false".to_string());
            return resp;
        }
    };
    let valid = Argon2::default()
        .verify_password(value.as_bytes(), &parsed_hash)
        .is_ok();
    if !valid {
        warn!("password verification failed");
        record_login_failure(login_rate_limit);
    } else {
        reset_login_rate_limit(login_rate_limit);
    }
    let mut resp = Response::ok();
    resp.config_value = Some(if valid { "true" } else { "false" }.to_string());
    resp
}

pub(super) fn handle_setup_password(req: &Request, db: &Arc<Mutex<Db>>, login_rate_limit: &LoginRateLimit, password_lock: &PasswordLock) -> Response {
    let Some(ref value) = req.value else {
        return Response::err("value required");
    };
    if value.len() < 8 {
        return Response::err("password too short (minimum 8 characters)");
    }
    if value.len() > 128 {
        return Response::err("password too long (maximum 128 characters)");
    }
    let _pw_guard = password_lock.lock().unwrap();
    let existing_hash = {
        let db = db.lock().unwrap();
        db.get_config("admin_password_hash").ok().flatten()
    };
    if let Some(ref hash_str) = existing_hash {
        let Some(ref current) = req.key else {
            return Response::err("key required (current password)");
        };
        if let Some(msg) = check_login_rate_limit(login_rate_limit) {
            warn!("setup_password rate-limited");
            return Response::err(&msg);
        }
        let parsed_hash = match PasswordHash::new(hash_str) {
            Ok(h) => h,
            Err(_) => return Response::err("stored hash corrupt"),
        };
        if Argon2::default()
            .verify_password(current.as_bytes(), &parsed_hash)
            .is_err()
        {
            warn!("setup_password rejected: wrong current password");
            record_login_failure(login_rate_limit);
            return Response::err("wrong current password");
        }
        reset_login_rate_limit(login_rate_limit);
    }
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    let new_hash = match Argon2::default().hash_password(value.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(e) => return Response::err(&format!("hashing failed: {}", e)),
    };
    let db = db.lock().unwrap();
    match db.set_config("admin_password_hash", &new_hash) {
        Ok(()) => Response::ok(),
        Err(e) => Response::err(&e.to_string()),
    }
}

pub(super) fn handle_create_session(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    let secret = match db.get_config("session_secret").ok().flatten() {
        Some(s) => Zeroizing::new(s),
        None => {
            let s = hex::encode(rand::Rng::r#gen::<[u8; 32]>(&mut rand::thread_rng()));
            if let Err(e) = db.set_config("session_secret", &s) {
                return Response::err(&format!("failed to store secret: {}", e));
            }
            Zeroizing::new(s)
        }
    };
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs();
    let payload = format!("admin:{}:{}", timestamp, timestamp);
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
    mac.update(payload.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());
    let cookie = format!("{}.{}", payload, sig);
    let mut resp = Response::ok();
    resp.config_value = Some(cookie);
    resp
}

pub(super) fn handle_verify_session(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref value) = req.value else {
        return Response::err("value required");
    };
    let db = db.lock().unwrap();
    let secret = match db.get_config("session_secret").ok().flatten() {
        Some(s) => Zeroizing::new(s),
        None => {
            let mut resp = Response::ok();
            resp.config_value = Some("false".to_string());
            return resp;
        }
    };
    let valid = if let Some(dot_pos) = value.rfind('.') {
        let payload = &value[..dot_pos];
        let sig = &value[dot_pos + 1..];
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
        mac.update(payload.as_bytes());
        let sig_bytes = match hex::decode(sig) {
            Ok(b) => b,
            Err(_) => return {
                let mut resp = Response::ok();
                resp.config_value = Some("false".to_string());
                resp
            },
        };
        if mac.verify_slice(&sig_bytes).is_err() {
            false
        } else {
            let parts: Vec<&str> = payload.splitn(3, ':').collect();
            if parts.len() != 3 {
                false
            } else {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                match (parts[1].parse::<u64>(), parts[2].parse::<u64>()) {
                    (Ok(created), Ok(last_active)) => {
                        let absolute_ok = now.saturating_sub(created) <= SESSION_ABSOLUTE_TIMEOUT_SECS;
                        let idle_ok = now.saturating_sub(last_active) <= SESSION_IDLE_TIMEOUT_SECS;
                        absolute_ok && idle_ok
                    }
                    _ => false,
                }
            }
        }
    } else {
        false
    };
    let mut resp = Response::ok();
    resp.config_value = Some(if valid { "true" } else { "false" }.to_string());
    resp
}

pub(super) fn handle_refresh_session(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref value) = req.value else {
        return Response::err("value required");
    };
    let db = db.lock().unwrap();
    let secret = match db.get_config("session_secret").ok().flatten() {
        Some(s) => Zeroizing::new(s),
        None => return Response::err("no session secret"),
    };
    let dot_pos = match value.rfind('.') {
        Some(p) => p,
        None => return Response::err("invalid token"),
    };
    let payload = &value[..dot_pos];
    let sig = &value[dot_pos + 1..];
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
    mac.update(payload.as_bytes());
    let sig_bytes = match hex::decode(sig) {
        Ok(b) => b,
        Err(_) => return Response::err("invalid signature"),
    };
    if mac.verify_slice(&sig_bytes).is_err() {
        return Response::err("invalid signature");
    }
    let parts: Vec<&str> = payload.splitn(3, ':').collect();
    if parts.len() != 3 {
        return Response::err("invalid token format");
    }
    let created = match parts[1].parse::<u64>() {
        Ok(t) => t,
        Err(_) => return Response::err("invalid timestamp"),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs();
    if now.saturating_sub(created) > SESSION_ABSOLUTE_TIMEOUT_SECS {
        return Response::err("session expired");
    }
    let last_active = match parts[2].parse::<u64>() {
        Ok(t) => t,
        Err(_) => return Response::err("invalid timestamp"),
    };
    if now.saturating_sub(last_active) > SESSION_IDLE_TIMEOUT_SECS {
        return Response::err("session idle expired");
    }
    let new_payload = format!("admin:{}:{}", created, now);
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
    mac.update(new_payload.as_bytes());
    let new_sig = hex::encode(mac.finalize().into_bytes());
    let new_cookie = format!("{}.{}", new_payload, new_sig);
    let mut resp = Response::ok();
    resp.config_value = Some(new_cookie);
    resp
}

pub(super) fn handle_set_tls_cert(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref cert_pem) = req.tls_cert_pem else {
        return Response::err("tls_cert_pem required");
    };
    let Some(ref key_pem) = req.tls_key_pem else {
        return Response::err("tls_key_pem required");
    };

    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .filter_map(|c| c.ok())
        .collect();
    if certs.is_empty() {
        return Response::err("invalid certificate PEM");
    }

    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes());
    match key {
        Ok(Some(_)) => {}
        _ => return Response::err("invalid private key PEM"),
    }

    let db = db.lock().unwrap();
    let _ = db.set_config("tls_cert_pem", cert_pem);
    let _ = db.set_config("tls_key_pem", key_pem);
    let _ = db.set_config("tls_mode", "custom");
    info!("custom TLS certificate uploaded");
    Response::ok()
}

pub(super) fn handle_set_tls_mode(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref mode) = req.value else {
        return Response::err("value required (tls mode)");
    };
    match mode.as_str() {
        "self_signed" => {
            let db = db.lock().unwrap();
            // Regenerate a fresh self-signed cert when switching back
            let sans = vec!["hermitshell.local".to_string(), "10.0.0.1".to_string()];
            match rcgen::generate_simple_self_signed(sans) {
                Ok(cert) => {
                    let _ = db.set_config("tls_cert_pem", &cert.cert.pem());
                    let _ = db.set_config("tls_key_pem", &cert.key_pair.serialize_pem());
                    let _ = db.set_config("tls_mode", "self_signed");
                    info!(mode = "self_signed", "TLS mode changed, cert regenerated");
                    Response::ok()
                }
                Err(e) => Response::err(&format!("failed to generate self-signed cert: {}", e)),
            }
        }
        "custom" => {
            Response::err("use set_tls_cert to upload a custom certificate")
        }
        "tailscale" => {
            let Some(ref domain) = req.key else {
                return Response::err("key required (ts.net domain)");
            };
            if !domain.ends_with(".ts.net") {
                return Response::err("domain must end with .ts.net");
            }
            if domain.is_empty() || domain.len() > 253
                || !domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            {
                return Response::err("invalid domain");
            }
            let db = db.lock().unwrap();
            let _ = db.set_config("acme_domain", domain);
            let _ = db.set_config("tls_mode", "tailscale");
            info!(mode = "tailscale", domain = %domain, "TLS mode changed");
            Response::ok()
        }
        "acme_dns01" => {
            let Some(ref domain) = req.key else {
                return Response::err("key required (domain)");
            };
            if domain.is_empty() || domain.len() > 253
                || !domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            {
                return Response::err("invalid domain");
            }
            let db = db.lock().unwrap();
            let _ = db.set_config("acme_domain", domain);
            let _ = db.set_config("tls_mode", "acme_dns01");
            info!(mode = "acme_dns01", domain = %domain, "TLS mode changed");
            Response::ok()
        }
        _ => Response::err("invalid tls mode (self_signed, custom, tailscale, acme_dns01)"),
    }
}

pub(super) fn handle_set_acme_config(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref value) = req.value else {
        return Response::err("value required (JSON config)");
    };
    let parsed: serde_json::Value = match serde_json::from_str(value) {
        Ok(v) => v,
        Err(e) => return Response::err(&format!("invalid JSON: {}", e)),
    };

    let domain = parsed.get("domain").and_then(|v| v.as_str()).unwrap_or("");
    if domain.is_empty() || domain.len() > 253
        || !domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Response::err("domain required and must be a valid hostname");
    }

    let email = parsed.get("email").and_then(|v| v.as_str()).unwrap_or("");
    if email.is_empty() || !email.contains('@') {
        return Response::err("email required");
    }

    let cf_api_token = parsed.get("cf_api_token").and_then(|v| v.as_str()).unwrap_or("");
    if cf_api_token.is_empty() {
        return Response::err("cf_api_token required");
    }

    let cf_zone_id = parsed.get("cf_zone_id").and_then(|v| v.as_str()).unwrap_or("");
    if cf_zone_id.len() != 32 || !cf_zone_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Response::err("cf_zone_id must be a 32-character hex string");
    }

    let db = db.lock().unwrap();
    let _ = db.set_config("acme_domain", domain);
    let _ = db.set_config("acme_contact_email", email);
    let _ = db.set_config("acme_cf_api_token", cf_api_token);
    let _ = db.set_config("acme_cf_zone_id", cf_zone_id);
    let _ = db.set_config("tls_mode", "acme_dns01");
    info!(domain = %domain, "ACME DNS-01 config saved");
    Response::ok()
}

pub(super) fn handle_get_tls_status(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    let mode = db.get_config("tls_mode").ok().flatten().unwrap_or_else(|| "self_signed".to_string());
    let cert_pem = db.get_config("tls_cert_pem").ok().flatten();

    let mut status = serde_json::json!({
        "tls_mode": mode,
    });

    if let Some(ref pem) = cert_pem {
        if let Some(info) = parse_cert_info(pem) {
            status["issuer"] = serde_json::Value::String(info.issuer);
            status["expires_at"] = serde_json::Value::Number(info.expires_at.into());
            status["sans"] = serde_json::Value::Array(
                info.sans.into_iter().map(serde_json::Value::String).collect()
            );
        }
    }

    let mut resp = Response::ok();
    resp.tls_status = Some(status);
    resp
}

struct CertInfo {
    issuer: String,
    expires_at: i64,
    sans: Vec<String>,
}

fn parse_cert_info(pem: &str) -> Option<CertInfo> {
    let cert_der = rustls_pemfile::certs(&mut pem.as_bytes())
        .filter_map(|c| c.ok())
        .next()?;
    let (_, cert) = x509_parser::parse_x509_certificate(&cert_der).ok()?;
    let issuer = cert.issuer().to_string();
    let expires_at = cert.validity().not_after.timestamp();
    let sans = cert.subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| {
            ext.value.general_names.iter().filter_map(|name| {
                match name {
                    x509_parser::extensions::GeneralName::DNSName(s) => Some(s.to_string()),
                    x509_parser::extensions::GeneralName::IPAddress(bytes) => {
                        if bytes.len() == 4 {
                            Some(format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]))
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            }).collect()
        })
        .unwrap_or_default();
    Some(CertInfo { issuer, expires_at, sans })
}

pub(super) fn handle_get_tls_config(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    let cert = db.get_config("tls_cert_pem").ok().flatten();
    let key = db.get_config("tls_key_pem").ok().flatten().map(Zeroizing::new);
    match (cert, key) {
        (Some(c), Some(k)) => {
            let mut resp = Response::ok();
            resp.tls_cert_pem = Some(c);
            resp.tls_key_pem = Some(String::from(&*k));
            resp
        }
        _ => Response::err("TLS not yet configured"),
    }
}
