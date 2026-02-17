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

---

## Input Validation

## 12. import_config bypasses all validation

**What:** The `import_config` handler (`socket.rs:740-800`) imports devices, port forwards, and DHCP reservations from a JSON blob. Unlike the individual `add_port_forward`, `set_device_group`, and `dhcp_discover` handlers, import skips all validation: no IP validation on port forward targets, no group name whitelist, no hostname sanitization, no port range checks.

**Why:** The import was written as a bulk insert to restore backups. Validation was assumed to have been applied when the data was originally created.

**Risk:** A crafted config file can inject invalid IPs into port forwarding rules (potential nftables injection), invalid group names (breaking firewall rules), or unsanitized hostnames (XSS if the web UI doesn't escape them). Since `export_config` output is trusted, the main risk is a user importing a hand-edited or malicious JSON file.

**Proper fix:** Apply the same validation used by individual handlers: `validate_ip` for port forward IPs, group name whitelist check, `sanitize_hostname()` for hostnames, and port range validation (`ext_end >= ext_start`, ports > 0).

## 13. SQL injection pattern in VACUUM INTO

**What:** `db.rs:vacuum_into()` uses `format!("VACUUM INTO '{}'", path)` to build the SQL query. The path is string-interpolated directly into SQL.

**Why:** SQLite doesn't support parameterized queries for `VACUUM INTO`. The path is currently hardcoded to `/data/hermitshell/hermitshell-backup.db` in the calling code.

**Risk:** If the function is ever exposed to user-controlled input, a path containing `'` could break out of the SQL string. Currently safe because the caller uses a hardcoded path.

**Proper fix:** Add path validation in `vacuum_into()`: reject paths containing `'`, or whitelist only alphanumeric, `/`, `-`, `_`, `.` characters.

## 14. Port forwarding description field is unbounded

**What:** The `description` field in `add_port_forward` has no length limit. Stored in SQLite and rendered in the web UI.

**Why:** Not validated — it's a free-text label.

**Risk:** A very large description could cause performance issues in the DB and UI. If Leptos doesn't escape output properly, it could be an XSS vector (though Leptos escapes by default).

**Proper fix:** Truncate to a reasonable limit (e.g., 256 characters) in the `add_port_forward` handler.

---

## Container and Service Hardening

## 15. Docker container runs as root

**What:** The Dockerfile has no `USER` directive. The web UI process runs as root (UID 0) inside the container.

**Why:** Simplicity. The container needs to bind ports 80 and 443 (privileged ports) and access the agent socket.

**Risk:** If the web UI is compromised, the attacker has root inside the container. With `--network host`, this means full network access on the host.

**Proper fix:** Add a non-root user, use `setcap cap_net_bind_service` on the binary to allow privileged port binding, and ensure the socket is readable by the container user.

## 16. Systemd service missing hardening directives

**What:** `hermitshell-agent.service` has `ProtectHome=yes`, `ProtectSystem=strict`, and `PrivateTmp=yes`, but is missing several hardening options.

**Why:** Basic hardening was applied; exhaustive hardening was not prioritized.

**Risk:** The agent runs as root with more privileges than necessary. A compromised agent could access devices, change kernel parameters, or pivot to other services.

**Proper fix:** Add: `NoNewPrivileges=yes`, `PrivateDevices=yes`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK`, `RestrictNamespaces=yes`, `LockPersonality=yes`, `MemoryDenyWriteExecute=yes`. Note: `AF_NETLINK` is needed for nftables and `ip` commands.

---

## Temporary Files and Permissions

## 17. WireGuard private key left in /tmp on error

**What:** `wireguard.rs` writes the WG private key to `/tmp/hermitshell-wg-key`, runs `wg set`, then deletes it. If `wg set` fails (the `?` operator returns early), the key file is never deleted.

**Why:** No cleanup-on-error pattern was implemented.

**Risk:** The WireGuard private key sits in `/tmp` unencrypted until the next successful call or reboot. With `PrivateTmp=yes` in systemd, it's in a private namespace, but still readable by the agent process.

**Proper fix:** Restructure to always clean up: capture the result, delete the file, then propagate the error. Or use a `Drop` guard pattern.

## 18. Backup file created with default permissions

**What:** `VACUUM INTO` creates the backup file with the process umask (likely 0644). The backup contains the full database including device MACs, IPs, and network topology.

**Why:** SQLite's `VACUUM INTO` doesn't support setting file permissions.

**Risk:** Other processes on the system can read the backup. Low risk given the agent runs as root and `/data/hermitshell/` should be root-owned.

**Proper fix:** `chmod 0600` the backup file after creation.

---

## Rate Limiting and Resource Exhaustion

## 19. No connection limiting on the agent Unix socket

**What:** The agent socket server spawns a new tokio task per connection with no limit. There is no rate limiting or connection cap.

**Why:** Not implemented. The socket is access-controlled by filesystem permissions.

**Risk:** A process with socket access can open thousands of connections, exhausting memory. In the test environment where the socket is `chmod 666`, any user can do this.

**Proper fix:** Add a connection semaphore or counter. Reject new connections above a threshold (e.g., 100 concurrent).

## 20. No password maximum length

**What:** The setup form checks `password.len() < 8` but has no upper bound. Argon2 will happily hash a multi-megabyte password.

**Why:** Oversight.

**Risk:** An attacker can POST a very large password to the setup or login endpoint, causing high CPU usage from Argon2 hashing. This is a denial-of-service vector.

**Proper fix:** Add `|| form.password.len() > 128` to the validation check.
