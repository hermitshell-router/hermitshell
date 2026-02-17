# Security Compromises and Known Issues

This document tracks security compromises made during implementation, why they were made, and what the proper fix would be.

## 1. get_config exposes all keys over the Unix socket

**What:** The `get_config` IPC method returns any key from the config table, including `admin_password_hash`, `session_secret`, `wg_private_key`, and `tls_key_pem`.

**Why:** The web UI container needs `admin_password_hash` (to verify login) and `session_secret` (to sign/verify session cookies) at runtime. An access block list was attempted but broke auth because the web UI reads these through the same IPC path.

**Risk:** Any process that can connect to the agent Unix socket can read password hashes, session secrets, and private keys.

**Mitigating factor:** The socket is `0660 root:root` in production (tests `chmod 666` it for the vagrant user). Only root and the Docker container (via volume mount) should have access.

**Proper fix:** Separate the IPC into privileged and unprivileged channels, or have the agent handle auth verification directly (e.g., a `verify_password` method that accepts a plaintext password and returns true/false, keeping the hash internal).

## 2. Session cookies have no expiration

**What:** Session cookies are HMAC-signed `admin:TIMESTAMP` values. The timestamp is recorded but never checked — a cookie is valid forever as long as the HMAC verifies against the current `session_secret`.

**Why:** Simplicity. Expiration checking was not implemented.

**Risk:** Stolen session cookies remain valid until the `session_secret` is rotated (which only happens if the config DB is wiped).

**Proper fix:** Check the timestamp in `verify_session_cookie` and reject cookies older than a configurable TTL (e.g., 24 hours). Add a logout-all mechanism that rotates `session_secret`.

## 3. Session cookie comparison is not constant-time

**What:** `verify_session_cookie` compares the HMAC signature using `==` (string equality), which is vulnerable to timing attacks.

**Why:** Simplicity. The `hmac` crate provides `verify_slice` for constant-time comparison, but the implementation hex-encodes and uses string comparison instead.

**Risk:** An attacker on the local network could theoretically forge a session cookie by measuring response times. In practice, network jitter makes this extremely difficult over HTTP.

**Proper fix:** Use `mac.verify_slice(&hex::decode(sig))` instead of comparing hex strings.

## 4. Self-signed TLS certificate

**What:** The web UI generates a self-signed certificate on first run and stores it in the config DB. Browsers will show security warnings.

**Why:** A local router appliance has no domain name to get a real certificate from a CA. Self-signed is the standard approach for appliance web UIs.

**Risk:** Vulnerable to MITM on first connection (no TOFU mechanism). Users must manually trust the certificate.

**Proper fix:** Offer Let's Encrypt via DNS challenge for users with a domain. For LAN-only access, consider mDNS + a local CA root that users can install, or just document the self-signed approach as acceptable for the threat model.

## 5. SSH open on all interfaces in nftables input chain

**What:** The rule `tcp dport 22 accept` in the input chain accepts SSH from any interface, including WAN.

**Why:** The agent manages the router via SSH in the test environment. Restricting to LAN-only broke test infrastructure because the Vagrant management interface isn't the LAN interface.

**Risk:** SSH exposed to the WAN. If the router has weak SSH credentials or an unpatched SSH daemon, it's directly attackable from the internet.

**Proper fix:** Restrict to LAN and management interfaces: `iifname { "eth2", "eth0" } tcp dport 22 accept`. In production, SSH should never be open on the WAN interface without explicit user opt-in.

## 6. ICMP open on all interfaces

**What:** The rule `icmp type echo-request accept` allows ping from any interface, including WAN.

**Why:** Originally WAN-only (`iifname "eth1"`), it was broadened to allow LAN clients to ping the router. The simpler all-interfaces rule was chosen over listing both interfaces.

**Risk:** The router responds to pings from the WAN, revealing its presence to scanners. Low severity — most ISPs allow ICMP anyway — but unnecessary exposure.

**Proper fix:** `iifname { "eth1", "eth2" } icmp type echo-request accept` to explicitly list WAN and LAN.

## 7. No CSRF protection on form endpoints

**What:** Form POST endpoints (`/api/login`, `/api/setup`, `/api/approve`, `/api/block`, etc.) rely only on `SameSite=Strict` cookies for CSRF protection. There are no CSRF tokens.

**Why:** Simplicity. `SameSite=Strict` prevents cross-origin form submissions in modern browsers.

**Risk:** Older browsers that don't enforce `SameSite` are vulnerable. A malicious page could trick the user into submitting forms (blocking devices, changing groups, adding port forwards).

**Proper fix:** Add a per-session CSRF token to all forms and validate it server-side.

## 8. No rate limiting on login

**What:** The `/api/login` endpoint has no rate limiting or account lockout. An attacker can brute-force passwords.

**Why:** Not implemented. Argon2 hashing adds some natural slowdown.

**Risk:** Sustained brute-force attacks against the login form, especially if exposed on LAN where multiple devices could coordinate.

**Proper fix:** Track failed login attempts by IP and add exponential backoff or temporary lockout after N failures.

## 9. Docker container mounts full /run/hermitshell directory

**What:** The web UI container mounts `-v /run/hermitshell:/run/hermitshell` (the entire directory) instead of just the socket file.

**Why:** File bind mounts go stale when the agent restarts and recreates the socket (new inode). Directory mounts survive this.

**Risk:** The container can see all files in `/run/hermitshell/`, not just the agent socket. If other sensitive files are placed there, the container has access.

**Mitigating factor:** The directory currently only contains Unix sockets. The container runs with `--network host` anyway, so isolation is already limited.

**Proper fix:** Acceptable as-is given the directory's contents. If sensitive files are added later, consider a dedicated socket subdirectory or use a named socket with inotify-based reconnection in the client.

## 10. Session cookie lacks Secure flag

**What:** The session cookie is set with `HttpOnly; SameSite=Strict; Path=/` but without the `Secure` flag.

**Why:** The HTTP listener only serves redirects to HTTPS, so the cookie should never be sent over plain HTTP in practice. However, without the `Secure` flag, a MITM could potentially intercept it if the user is tricked into visiting an HTTP URL.

**Proper fix:** Add `Secure` to the cookie: `session=...; HttpOnly; Secure; SameSite=Strict; Path=/`.

## 11. Single admin account with no username

**What:** There is only one admin account. The session cookie payload is `admin:TIMESTAMP` with no configurable username.

**Why:** A home router typically has one administrator. Multi-user support was not in scope.

**Risk:** No audit trail for who performed actions. No way to revoke access for one user without rotating the shared secret.

**Proper fix:** Add per-user accounts if multi-admin is ever needed. For single-admin, this is acceptable for the threat model.
