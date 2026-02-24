use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use anyhow::{Context, Result};
use base64::Engine;
use hkdf::Hkdf;
use sha2::Sha256;

const HKDF_INFO: &[u8] = b"hermitshell-wifi-password-encryption";
const ENCRYPTED_PREFIX: &str = "enc:v1:";

/// Derive a 32-byte AES-256 key from the session_secret using HKDF-SHA256.
fn derive_key(session_secret: &str) -> Result<[u8; 32]> {
    if session_secret.len() < 32 {
        anyhow::bail!("session_secret too short for key derivation");
    }
    let hk = Hkdf::<Sha256>::new(None, session_secret.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut key)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
    Ok(key)
}

/// Encrypt a plaintext password. Returns base64(nonce || ciphertext).
pub fn encrypt_password(plaintext: &str, session_secret: &str) -> Result<String> {
    let key = derive_key(session_secret)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("AES key init: {}", e))?;

    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("AES encrypt: {}", e))?;

    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    Ok(format!("{}{}", ENCRYPTED_PREFIX, base64::engine::general_purpose::STANDARD.encode(&combined)))
}

/// Decrypt a password. Input is base64(nonce || ciphertext).
/// Returns Ok(plaintext) or Err if decryption fails.
pub fn decrypt_password(encrypted: &str, session_secret: &str) -> Result<String> {
    let key = derive_key(session_secret)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("AES key init: {}", e))?;

    let data = encrypted.strip_prefix(ENCRYPTED_PREFIX)
        .ok_or_else(|| anyhow::anyhow!("missing encryption prefix"))?;
    let combined = base64::engine::general_purpose::STANDARD.decode(data)
        .context("base64 decode failed")?;

    if combined.len() < 13 {
        anyhow::bail!("encrypted data too short");
    }

    let nonce = Nonce::from_slice(&combined[..12]);
    let ciphertext = &combined[12..];

    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("AES decrypt: {}", e))?;

    String::from_utf8(plaintext).context("decrypted data not UTF-8")
}

/// Check if a stored value is encrypted (has the magic prefix).
pub fn is_encrypted(value: &str) -> bool {
    value.starts_with(ENCRYPTED_PREFIX)
}
