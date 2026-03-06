use super::*;
use data_encoding::BASE32;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use zeroize::Zeroizing;

type HmacSha1 = Hmac<Sha1>;

const TOTP_PERIOD: u64 = 30;
const TOTP_DIGITS: u32 = 6;
const TOTP_SECRET_BYTES: usize = 20;

/// Generate a 6-digit TOTP code for the given secret and time step.
fn generate_code(secret: &[u8], time_step: u64) -> u32 {
    let msg = time_step.to_be_bytes();
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key size");
    mac.update(&msg);
    let result = mac.finalize().into_bytes();

    // Dynamic truncation (RFC 4226 section 5.4)
    let offset = (result[19] & 0x0f) as usize;
    let code = ((result[offset] as u32 & 0x7f) << 24)
        | ((result[offset + 1] as u32) << 16)
        | ((result[offset + 2] as u32) << 8)
        | (result[offset + 3] as u32);

    code % 10u32.pow(TOTP_DIGITS)
}

/// Verify a TOTP code with ±1 window tolerance.
fn verify_code(secret: &[u8], code: &str) -> bool {
    let code_val: u32 = match code.parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    if code.len() != 6 {
        return false;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs();
    let current_step = now / TOTP_PERIOD;

    for offset in [0i64, -1, 1] {
        let step = (current_step as i64 + offset) as u64;
        if generate_code(secret, step) == code_val {
            return true;
        }
    }
    false
}

pub(super) fn handle_totp_setup(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let mut secret_bytes = [0u8; TOTP_SECRET_BYTES];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret_bytes);
    let secret_b32 = BASE32.encode(&secret_bytes);

    let db = db.lock().unwrap();
    if let Err(e) = db.set_config("totp_secret", &secret_b32) {
        return Response::err(&format!("failed to store secret: {}", e));
    }

    let uri = format!(
        "otpauth://totp/HermitShell:admin?secret={}&issuer=HermitShell&algorithm=SHA1&digits=6&period=30",
        secret_b32
    );

    let mut resp = Response::ok();
    resp.config_value = Some(serde_json::json!({
        "secret": secret_b32,
        "uri": uri,
    }).to_string());
    resp
}

pub(super) fn handle_totp_verify(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref code) = req.value else {
        return Response::err("value required (6-digit code)");
    };
    let db = db.lock().unwrap();
    let secret_b32 = match db.get_config("totp_secret").ok().flatten() {
        Some(s) => Zeroizing::new(s),
        None => return Response::err("TOTP not configured"),
    };
    let secret_bytes = match BASE32.decode(secret_b32.as_bytes()) {
        Ok(b) => b,
        Err(_) => return Response::err("stored secret corrupt"),
    };
    let valid = verify_code(&secret_bytes, code);
    let mut resp = Response::ok();
    resp.config_value = Some(if valid { "true" } else { "false" }.to_string());
    resp
}

pub(super) fn handle_totp_enable(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref code) = req.value else {
        return Response::err("value required (6-digit code)");
    };
    let db = db.lock().unwrap();
    let secret_b32 = match db.get_config("totp_secret").ok().flatten() {
        Some(s) => Zeroizing::new(s),
        None => return Response::err("run totp_setup first"),
    };
    let secret_bytes = match BASE32.decode(secret_b32.as_bytes()) {
        Ok(b) => b,
        Err(_) => return Response::err("stored secret corrupt"),
    };
    if !verify_code(&secret_bytes, code) {
        return Response::err("invalid code");
    }
    if let Err(e) = db.set_config("totp_enabled", "true") {
        return Response::err(&format!("failed to enable: {}", e));
    }
    let _ = db.log_audit("totp_enabled", "");
    Response::ok()
}

pub(super) fn handle_totp_disable(req: &Request, db: &Arc<Mutex<Db>>, password_lock: &PasswordLock, login_rate_limit: &LoginRateLimit) -> Response {
    let from_cli = req.value.as_ref().map_or(true, |v| v.is_empty());

    if !from_cli {
        let password = req.value.as_ref().unwrap();
        if let Some(msg) = check_login_rate_limit(login_rate_limit) {
            return Response::err(&msg);
        }
        let _pw_guard = password_lock.lock().unwrap();
        let hash_str = {
            let db = db.lock().unwrap();
            db.get_config("admin_password_hash").ok().flatten().map(Zeroizing::new)
        };
        let hash_str = match hash_str {
            Some(h) => h,
            None => return Response::err("no password set"),
        };
        let parsed_hash = match PasswordHash::new(&hash_str) {
            Ok(h) => h,
            Err(_) => return Response::err("stored hash corrupt"),
        };
        if Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_err() {
            record_login_failure(login_rate_limit);
            return Response::err("wrong password");
        }
        reset_login_rate_limit(login_rate_limit);
    }

    let db = db.lock().unwrap();
    let _ = db.set_config("totp_enabled", "false");
    let _ = db.set_config("totp_secret", "");
    let _ = db.log_audit("totp_disabled", "");
    Response::ok()
}

pub(super) fn handle_totp_status(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    let enabled = db.get_config("totp_enabled").ok().flatten()
        .map_or(false, |v| v == "true");
    let mut resp = Response::ok();
    resp.config_value = Some(if enabled { "true" } else { "false" }.to_string());
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_generate_and_verify() {
        let secret = b"12345678901234567890";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let step = now / TOTP_PERIOD;
        let current_code = generate_code(secret, step);
        let code_str = format!("{:06}", current_code);
        assert!(verify_code(secret, &code_str));
    }

    #[test]
    fn test_totp_wrong_code() {
        let secret = b"12345678901234567890";
        // Generate a definitely-wrong code
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let step = now / TOTP_PERIOD;
        let current_code = generate_code(secret, step);
        let wrong_code = format!("{:06}", (current_code + 1) % 1000000);
        // Only assert false if we're sure it doesn't match any window
        let wrong_val: u32 = wrong_code.parse().unwrap();
        let matches_any_window = [-1i64, 0, 1].iter().any(|&off| {
            generate_code(secret, (step as i64 + off) as u64) == wrong_val
        });
        if !matches_any_window {
            assert!(!verify_code(secret, &wrong_code));
        }
    }

    #[test]
    fn test_totp_bad_input() {
        let secret = b"12345678901234567890";
        assert!(!verify_code(secret, "abc"));
        assert!(!verify_code(secret, "12345"));
        assert!(!verify_code(secret, "1234567"));
    }
}
