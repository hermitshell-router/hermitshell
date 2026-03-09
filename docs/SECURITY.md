# Security Compromises and Known Issues

This document tracks security compromises made during implementation, why they were made, and what the proper fix would be.

Most entries from the original audit have been resolved — either fixed in code, accepted as appropriate for the home router threat model, or addressed by the 2026-03-08/09 security hardening sweeps. The remaining items below require future architectural work or are accepted tradeoffs.

---

## Socket Access Control

## 90. SO_PEERCRED method allowlist grants broad access to non-root callers

**What:** The agent socket uses `SO_PEERCRED` (`peer_cred()`) to identify the UID of each connecting process. Root (UID 0) callers have unrestricted access. Non-root callers are restricted to a compile-time allowlist (`WEB_ALLOWED_METHODS`, ~80 methods). Methods not in the allowlist — `dhcp_discover`, `dhcp_provision`, `dhcp6_discover`, `dhcp6_provision`, `ingest_dns_logs` — return "access denied" for non-root callers.

**Why:** The web UI container runs as non-root and connects to the agent socket. It needs access to most methods (device management, config, status, WiFi, WireGuard, etc.) but should not be able to invoke DHCP provisioning or DNS log ingestion, which are internal IPC between the agent and its child processes.

**Risk:** The allowlist is permissive — non-root callers can still modify firewall rules, change DNS settings, and manage WireGuard peers. A compromised web UI container retains significant control over the router. The allowlist is deny-by-default for new methods (they must be explicitly added), which prevents accidental exposure of future admin-only methods.

**Mitigating factor:** The socket is `0660 root:root`, so only root and the web UI container (which has the socket bind-mounted) can connect. The `peer_cred()` check is kernel-enforced and unforgeable. Connections that fail `peer_cred()` are dropped immediately. `export_config` with `include_secrets=true` is now restricted to UID 0.

**Proper fix:** Further partition the allowlist into read-only and read-write tiers. Read-only methods (status, list) could be available to any socket caller, while write methods (set_config, add_port_forward) could require a session token or elevated credential. This would limit damage from a compromised read-only consumer.

---

## Security Logging and Monitoring (OWASP C9)

## 141. Syslog export limited to unencrypted UDP

**What:** The syslog export only supports `udp://` targets. There is no TCP or TLS transport option. Messages are sent as plaintext UDP datagrams, limited to 480 bytes per RFC 5426 section 3.2, with no authentication or encryption.

**Why:** UDP syslog is the simplest to implement (stateless, fire-and-forget) and compatible with virtually all syslog receivers. TCP+TLS (RFC 5425) requires persistent connection management, TLS handshake, reconnection logic, and message framing.

**Risk:** On a shared network, syslog messages are visible to any observer. For a home router where the syslog receiver is typically on the same trusted LAN, the risk is low. However, for users forwarding logs to a cloud SIEM over the WAN, plaintext UDP is unacceptable. The webhook export (which supports HTTPS) is the recommended alternative for encrypted log forwarding.

**Proper fix:** Add `tcp+tls://` prefix support to `parse_syslog_target()`. Implement a persistent TCP+TLS connection using `rustls` (already a dependency) with automatic reconnection. Use RFC 5425 octet counting framing. This removes the 480-byte message limit and provides confidentiality and integrity for syslog transport.

---

## Cryptographic Design

## 142. HKDF-SHA256 without salt for WiFi password encryption (enc:v1)

**What:** `crypto.rs` derives AES-256 encryption keys from the session secret using HKDF-SHA256 with no salt (`Hkdf::new(None, ...)`). The encrypted values are stored in the database with an `enc:v1:` prefix.

**Why:** The session secret is 32 bytes of OS-sourced random data, making the unsalted HKDF output indistinguishable from random. Adding a salt now would break decryption of all existing `enc:v1:` values with no recovery path.

**Risk:** Low. The cryptographic argument is sound — HKDF with high-entropy input does not benefit from a salt. The concern is defense-in-depth: a salt provides domain separation in case the same secret is reused across contexts (it is not, but a future refactor could introduce this).

**Proper fix:** Introduce `enc:v2:` with a static domain-separation salt and transparent migration from v1 values on first read.

## 143. CSP allows `unsafe-inline` for stylesheets

**What:** The Content-Security-Policy meta tag in `layout.rs` includes `style-src 'self' 'unsafe-inline'`. Scripts are properly nonce-gated.

**Why:** Leptos SSR renders component styles inline. Extracting them into external stylesheets or computing per-element hashes at SSR time is not supported by the framework.

**Risk:** Low. CSS injection can exfiltrate data via `background-image: url(...)` or overlay UI elements, but requires an HTML injection point first. All user-controlled values in the UI are escaped by Leptos's templating system.

**Proper fix:** When Leptos supports nonce-gated inline styles or style extraction, switch to `style-src 'self' 'nonce-{nonce}'`.

## 144. MD5 used for TP-Link EAP720 authentication

**What:** `wifi/eap_standalone.rs` hashes the AP management password with MD5 (uppercase hex) before sending it to the EAP720 web UI.

**Why:** The EAP720 firmware (1.0.0) requires this specific authentication format. This is a reverse-engineered protocol constraint, not a design choice.

**Risk:** Low. The MD5 hash is sent over HTTPS to a device on the local LAN. MD5's collision weakness is irrelevant for this use case (password obfuscation, not integrity verification). The actual password is stored encrypted (AES-256-GCM) in the HermitShell database.

**Proper fix:** None available — the AP firmware dictates the protocol. If TP-Link releases firmware with a stronger auth scheme, update the provider implementation.

---

## Concurrency Design

## 145. Mutex poisoning causes cascading panics

**What:** All `Mutex::lock()` calls use `.unwrap()`, which panics if the mutex is poisoned (i.e., another thread panicked while holding the lock). The database mutex is shared across the socket handler, REST API, conntrack thread, update loop, and background tasks.

**Why:** This is a deliberate fail-fast design. If a thread panics while holding the DB mutex, the database state may be inconsistent. Continuing to serve requests against a potentially corrupted state is worse than crashing. The systemd unit restarts the agent on crash, and SQLite's WAL journal ensures database integrity across restarts.

**Risk:** Low. A single panic in any DB-holding code path takes down the entire agent. This is acceptable for a router daemon where a clean restart is the correct recovery strategy. The agent starts in ~2 seconds, so downtime is minimal.

**Accepted as intentional.** The fail-fast behavior is the correct choice for this threat model.
