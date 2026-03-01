//! Build reqwest clients with custom CA certificates.
//!
//! Two builders are provided:
//!
//! - `builder_with_ca` — Uses rustls with custom CA cert verification
//!   (validates cert chain, skips hostname check). Best for services with
//!   modern TLS (2048-bit+ RSA/ECC, forward-secrecy ciphers).
//!
//! - `builder_wifi_native_verified` — Uses native-tls (OpenSSL) with CA cert
//!   verification. Required for IoT devices with legacy TLS (1024-bit RSA,
//!   TLS_RSA_WITH_* ciphers).
//!
//! Additionally, `grab_leaf_cert` performs a bare TLS handshake to extract the
//! server's leaf certificate for TOFU (trust-on-first-use) pinning.

use std::sync::Arc;

use anyhow::Result;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, RootCertStore, SignatureScheme};

/// A certificate verifier that validates the cert chain against a
/// `RootCertStore` but does NOT check hostname/IP match.
#[derive(Debug)]
struct CaOnlyVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
}

impl ServerCertVerifier for CaOnlyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let dummy = ServerName::try_from("ca-verified.internal").unwrap();
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            &dummy,
            ocsp_response,
            now,
        ) {
            Ok(v) => Ok(v),
            Err(Error::InvalidCertificate(rustls::CertificateError::NotValidForName)) => {
                Ok(ServerCertVerified::assertion())
            }
            Err(e) => Err(e),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Build a reqwest client using rustls with custom CA cert.
///
/// Validates cert chain against the CA but skips hostname verification.
/// Requires the server to support modern TLS ciphers (ECDHE + 2048-bit+).
pub fn builder_with_ca(ca_cert_pem: Option<&str>) -> Result<reqwest::ClientBuilder> {
    let base = reqwest::Client::builder();
    if let Some(pem) = ca_cert_pem {
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut pem.as_bytes())
            .filter_map(|r| r.ok())
            .collect();
        if certs.is_empty() {
            anyhow::bail!("no valid certificates in PEM data");
        }

        let mut roots = RootCertStore::empty();
        for cert in certs {
            roots.add(cert)?;
        }

        let provider = CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));

        let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            provider.clone(),
        )
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build verifier: {}", e))?;

        let verifier = Arc::new(CaOnlyVerifier { inner });

        let tls_config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

        Ok(base.use_preconfigured_tls(tls_config))
    } else {
        Ok(base)
    }
}

/// Build a reqwest client using native-tls (OpenSSL) with CA cert verification.
///
/// Validates cert chain against the provided CA. Skips hostname verification
/// (APs are accessed by IP, not hostname). Works with legacy TLS (1024-bit RSA,
/// non-ECDHE ciphers) common on IoT devices.
pub fn builder_wifi_native_verified(ca_cert_pem: &str) -> Result<reqwest::ClientBuilder> {
    let cert = reqwest::Certificate::from_pem(ca_cert_pem.as_bytes())?;
    Ok(reqwest::Client::builder()
        .tls_backend_native()
        .tls_certs_only([cert])
        .tls_danger_accept_invalid_certs(false)
        .tls_danger_accept_invalid_hostnames(true))
}

/// Perform a bare TLS handshake to `ip:port` and extract the server's leaf
/// certificate as PEM.  No HTTP data is sent.  Uses native-tls with
/// verification disabled so it works with any cert (self-signed, expired, etc).
pub async fn grab_leaf_cert(ip: &str, port: u16) -> Result<String> {
    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| anyhow::anyhow!("TLS connector: {}", e))?;
    let connector = tokio_native_tls::TlsConnector::from(connector);

    let tcp = tokio::net::TcpStream::connect((ip, port)).await?;
    let tls = connector.connect(ip, tcp).await
        .map_err(|e| anyhow::anyhow!("TLS handshake failed: {}", e))?;

    let cert = tls.get_ref()
        .peer_certificate()
        .map_err(|e| anyhow::anyhow!("peer_certificate: {}", e))?
        .ok_or_else(|| anyhow::anyhow!("server sent no certificate"))?;

    let der = cert.to_der()
        .map_err(|e| anyhow::anyhow!("cert to DER: {}", e))?;

    // Encode as PEM
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");

    Ok(pem)
}
