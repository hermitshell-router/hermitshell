# Security Compromises and Known Issues

This document tracks security compromises made during implementation, why they were made, and what the proper fix would be.

## 1. get_config exposes all keys over the Unix socket

**What:** The `get_config` IPC method returns any key from the config table, including `admin_password_hash`, `session_secret`, `wg_private_key`, and `tls_key_pem`.

**Why:** The web UI container needs `admin_password_hash` (to verify login) and `session_secret` (to sign/verify session cookies) at runtime. An access block list was attempted but broke auth because the web UI reads these through the same IPC path.

**Risk:** Any process that can connect to the agent Unix socket can read password hashes, session secrets, and private keys.

**Mitigating factor:** The socket is `0660` (root + group only) — see issue #49. Only root and group members can connect. Mitigated by the sensitive keys being blocked (see Status below).

**Proper fix:** Separate the IPC into privileged and unprivileged channels, or have the agent handle auth verification directly (e.g., a `verify_password` method that accepts a plaintext password and returns true/false, keeping the hash internal).

**Status: Fixed.** `get_config` now blocks reads of `admin_password_hash`, `session_secret`, `wg_private_key`, `tls_key_pem`, `tls_cert_pem`. Dedicated IPC methods (`verify_password`, `create_session`, `verify_session`, `get_tls_config`) provide minimum-necessary access. The web UI no longer handles raw secrets.

## 2. Session cookies have no expiration

**What:** Session cookies are HMAC-signed `admin:TIMESTAMP` values. The timestamp is recorded but never checked — a cookie is valid forever as long as the HMAC verifies against the current `session_secret`.

**Why:** Simplicity. Expiration checking was not implemented.

**Risk:** Stolen session cookies remain valid until the `session_secret` is rotated (which only happens if the config DB is wiped).

**Proper fix:** Check the timestamp in `verify_session` and reject cookies older than a configurable TTL (e.g., 24 hours). Add a logout-all mechanism that rotates `session_secret`.

**Note:** Session creation and verification moved from the web UI to the agent (`socket.rs` `create_session`/`verify_session`). The expiration gap persists — the agent's `verify_session` verifies the HMAC but does not check the embedded timestamp.

**Status: Fixed.** Token format changed to `admin:CREATED:LAST_ACTIVE.HMAC`. The agent enforces a 30-minute idle timeout and 8-hour absolute timeout per OWASP Session Management Cheat Sheet guidance. The auth middleware issues a refreshed token on every authenticated request, resetting the idle clock. Non-persistent session cookies (no `Max-Age`) per OWASP recommendation.

## 3. Session cookie comparison is not constant-time

**What:** The agent's `verify_session` handler compares the HMAC signature using `==` (string equality), which is vulnerable to timing attacks.

**Why:** Simplicity. The `hmac` crate provides `verify_slice` for constant-time comparison, but the implementation hex-encodes and uses string comparison instead.

**Risk:** An attacker on the local network could theoretically forge a session cookie by measuring response times. In practice, network jitter makes this extremely difficult over a Unix socket.

**Proper fix:** Use `mac.verify_slice(&hex::decode(sig))` instead of comparing hex strings.

**Note:** This logic moved from the web UI to the agent (`socket.rs` `verify_session`). The non-constant-time comparison was carried forward and also exists in the new `refresh_session` handler. The attack surface is now a Unix socket rather than an HTTPS endpoint. However, the socket is `0660` (see issue #49), so any process in the socket's group could attempt timing attacks.

## 4. Self-signed TLS certificate

**What:** The agent generates a self-signed certificate on first startup and stores it in the config DB. The web UI retrieves it via `get_tls_config`. Browsers will show security warnings.

**Why:** A local router appliance has no domain name to get a real certificate from a CA. Self-signed is the standard approach for appliance web UIs.

**Risk:** Vulnerable to MITM on first connection (no TOFU mechanism). Users must manually trust the certificate.

**Proper fix:** Offer Let's Encrypt via DNS challenge for users with a domain. For LAN-only access, consider mDNS + a local CA root that users can install, or just document the self-signed approach as acceptable for the threat model.

**Note:** TLS cert generation moved from the web UI to the agent startup (`main.rs`). The self-signed nature is unchanged. The cert and private key are now stored in the config DB and served to the web UI via the `get_tls_config` IPC method — see issue #32.

## 5. SSH open on all interfaces in nftables input chain

**What:** The rule `tcp dport 22 accept` in the input chain accepts SSH from any interface, including WAN.

**Why:** The agent manages the router via SSH in the test environment. Restricting to LAN-only broke test infrastructure because the Vagrant management interface isn't the LAN interface.

**Risk:** SSH exposed to the WAN. If the router has weak SSH credentials or an unpatched SSH daemon, it's directly attackable from the internet.

**Proper fix:** Restrict to LAN and management interfaces: `iifname { "eth2", "eth0" } tcp dport 22 accept`. In production, SSH should never be open on the WAN interface without explicit user opt-in.

**Status: Fixed.** SSH now uses `iifname != "{wan_iface}"` — blocked on WAN, allowed on all other interfaces (LAN, tailscale0, management). This is more permissive than a strict whitelist (`iifname { lan, tailscale0 }`) but avoids breaking management access from non-LAN interfaces (IPMI, serial console, Vagrant management network). The trade-off: any future non-WAN interface automatically gets SSH access.

## 6. ICMP open on all interfaces

**What:** The rule `icmp type echo-request accept` allows ping from any interface, including WAN.

**Why:** Originally WAN-only (`iifname "eth1"`), it was broadened to allow LAN clients to ping the router. The simpler all-interfaces rule was chosen over listing both interfaces.

**Risk:** The router responds to pings from the WAN, revealing its presence to scanners. Low severity — most ISPs allow ICMP anyway — but unnecessary exposure.

**Proper fix:** `iifname { "eth1", "eth2" } icmp type echo-request accept` to explicitly list WAN and LAN.

**Status: Fixed.** ICMP echo-request (IPv4 and IPv6) scoped to `iifname { "{lan_iface}", "tailscale0", "wg0" }`. ICMPv6 neighbor discovery (nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert) remains global as required for IPv6 link-layer operation. Web UI ports (8080/8443) accept traffic from LAN, tailscale0, and wg0 for remote management via Tailscale and WireGuard VPN. DNS (port 53) remains LAN-only — WireGuard peers cannot use the router's DNS resolver or ad-blocking (see issue #64).

## 7. No CSRF protection on form endpoints

**What:** Form POST endpoints (`/api/login`, `/api/setup`, `/api/approve`, `/api/block`, etc.) rely only on `SameSite=Strict` cookies for CSRF protection. There are no CSRF tokens.

**Why:** Simplicity. `SameSite=Strict` prevents cross-origin form submissions in modern browsers.

**Risk:** Older browsers that don't enforce `SameSite` are vulnerable. A malicious page could trick the user into submitting forms (blocking devices, changing groups, adding port forwards).

**Proper fix:** Add a per-session CSRF token to all forms and validate it server-side.

**Status: Fixed.** Origin-based CSRF protection middleware validates `Sec-Fetch-Site` header (preferred) and `Origin` vs `Host` header (fallback) on all non-safe HTTP methods. Same-origin requests are allowed; cross-origin requests return 403. Requests with neither header (non-browser clients like curl) are allowed through. This provides equivalent protection to CSRF tokens for all browsers that send `Sec-Fetch-Site` (Chrome 76+, Firefox 90+, Safari 16.4+) or `Origin` headers.

## 8. No rate limiting on login

**What:** The `/api/login` endpoint has no rate limiting or account lockout. An attacker can brute-force passwords.

**Why:** Not implemented. Argon2 hashing adds some natural slowdown.

**Risk:** Sustained brute-force attacks against the login form, especially if exposed on LAN where multiple devices could coordinate.

**Proper fix:** Track failed login attempts by IP and add exponential backoff or temporary lockout after N failures.

**Status: FIXED.** Exponential backoff (1s, 2s, 4s... 60s cap) on both agent (global counter in `verify_password` and `setup_password`) and web UI (middleware returning 429). State is in-memory, resets on restart.

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

**Status: Fixed.** `Secure` flag added to login, logout, and rolling-refresh `Set-Cookie` headers.

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

**Status: Fixed.** `import_config` now validates all imported data before modifying the database (validate-then-apply). Validation uses the same checks as individual handlers: `validate_mac()` for all MACs (devices, reservations, pinholes), group name whitelist (`quarantine|trusted|iot|guest|servers`), `sanitize_hostname()` for device hostnames, `validate_ip()` for port forward IPs, protocol whitelist (`tcp|udp|both` for port forwards, `tcp|udp` for pinholes), and port range validation. If any field fails validation, the entire import is rejected with a descriptive error and no data is changed.

## 13. SQL injection pattern in VACUUM INTO

**What:** `db.rs:vacuum_into()` uses `format!("VACUUM INTO '{}'", path)` to build the SQL query. The path is string-interpolated directly into SQL.

**Why:** SQLite doesn't support parameterized queries for `VACUUM INTO`. The path is currently hardcoded to `/data/hermitshell/hermitshell-backup.db` in the calling code.

**Risk:** If the function is ever exposed to user-controlled input, a path containing `'` could break out of the SQL string. Currently safe because the caller uses a hardcoded path.

**Proper fix:** Add path validation in `vacuum_into()`: reject paths containing `'`, or whitelist only alphanumeric, `/`, `-`, `_`, `.` characters.

**Status: Fixed.** Eliminated the attack surface entirely: `vacuum_into()` replaced with `vacuum_into_backup()` which takes no path parameter. The backup path is a compile-time constant (`Db::BACKUP_PATH`) embedded in the SQL string literal. No user input reaches the query.

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

**Status: Fixed.** The standalone web UI Dockerfile creates a `hermitshell` user (UID/GID 1000) and sets `USER hermitshell`. The web UI binds high ports (8080/8443) with nftables DNAT redirecting 80→8080 and 443→8443. The agent socket is `0660` (see issue #49) so the container user must be in the socket's group to access it. Docker run adds `--read-only --cap-drop ALL --security-opt no-new-privileges`.

## 16. Systemd service missing hardening directives

**What:** `hermitshell-agent.service` has `ProtectHome=yes`, `ProtectSystem=strict`, and `PrivateTmp=yes`, but is missing several hardening options.

**Why:** Basic hardening was applied; exhaustive hardening was not prioritized.

**Risk:** The agent runs as root with more privileges than necessary. A compromised agent could access devices, change kernel parameters, or pivot to other services.

**Proper fix:** Add: `NoNewPrivileges=yes`, `PrivateDevices=yes`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`, `RestrictNamespaces=yes`, `LockPersonality=yes`, `MemoryDenyWriteExecute=yes`. Note: `AF_NETLINK` is needed for nftables and `ip` commands; `AF_INET6` is needed for DHCPv6 and IPv6 routing.

**Status: Fixed.** Added 13 hardening directives: `NoNewPrivileges`, `PrivateDevices`, `RestrictAddressFamilies` (AF_UNIX/INET/INET6/NETLINK), `RestrictNamespaces`, `LockPersonality`, `MemoryDenyWriteExecute`, `RestrictSUIDSGID`, `ProtectClock`, `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectKernelLogs`, `ProtectControlGroups`, `RestrictRealtime`.

---

## Temporary Files and Permissions

## 17. WireGuard private key written to predictable /tmp path

**What:** `wireguard.rs` writes the WG private key to `/tmp/hermitshell-wg-key`, runs `wg set`, then deletes it. The path is hardcoded and predictable, creating a theoretical symlink race window between the `fs::write()` and the `wg set` read.

**Why:** The `wg` command requires a file path for the private key. A fixed path was chosen for simplicity.

**Risk:** A local attacker could replace the file with a symlink between write and read, causing `wg set` to read from an attacker-controlled location or causing the write to overwrite a symlink target. Mitigated by `PrivateTmp=yes` in systemd (the agent's `/tmp` is a private namespace) and the agent running as root. The race window is microseconds. The error-path key leak from the original implementation is fixed — cleanup runs unconditionally before the status check.

**Proper fix:** Use `tempfile::NamedTempFile` to create a file with a unique, unpredictable name and restricted permissions (0600).

## 18. Backup file created with default permissions

**What:** `VACUUM INTO` creates the backup file with the process umask (likely 0644). The backup contains the full database including device MACs, IPs, and network topology.

**Why:** SQLite's `VACUUM INTO` doesn't support setting file permissions.

**Risk:** Other processes on the system can read the backup. Low risk given the agent runs as root and `/data/hermitshell/` should be root-owned.

**Proper fix:** `chmod 0600` the backup file after creation.

**Status: Fixed.** Backup file is now `chmod 0600` after creation.

---

## Rate Limiting and Resource Exhaustion

## 19. No connection limiting on the agent Unix socket

**What:** The agent socket server spawns a new tokio task per connection with no limit. There is no rate limiting or connection cap.

**Why:** Not implemented. The socket is access-controlled by filesystem permissions.

**Risk:** A process with socket access can open thousands of connections, exhausting memory. The socket is `0660` (see issue #49), so only root and group members can do this.

**Proper fix:** Add a connection semaphore or counter. Reject new connections above a threshold (e.g., 100 concurrent).

## 20. No password maximum length

**What:** The setup form checks `password.len() < 8` but has no upper bound. Argon2 will happily hash a multi-megabyte password.

**Why:** Oversight.

**Risk:** An attacker can POST a very large password to the setup or login endpoint, causing high CPU usage from Argon2 hashing. This is a denial-of-service vector.

**Proper fix:** Add `|| form.password.len() > 128` to the validation check.

**Status: Fixed.** Both `verify_password` and `setup_password` IPC methods reject passwords over 128 bytes. The web UI `handle_setup` also checks `form.password.len() > 128`.

---

## Untrusted Network Input

## 21. DHCP hostname from LAN clients is not length-bounded at the network layer

**What:** The DHCP server (`hermitshell-dhcp/src/main.rs:209`) accepts the raw hostname from DHCP Option 12 without any length or character check, then sends it verbatim over IPC to the agent. The agent's `sanitize_hostname()` (`socket.rs:13`) strips invalid characters and truncates to 63 chars, but the full unsanitized string crosses the DHCP→agent IPC boundary first. DHCPv6 does not carry hostnames the same way (there is no Option 12 equivalent), but the DHCPv6 path extracts the client MAC from the DUID, which is used for device identification instead.

**Why:** Validation was deferred to the agent side. The dhcproto library parses the option into a String without length enforcement.

**Risk:** A malicious DHCP client can send an arbitrarily large hostname (up to the 1500-byte UDP packet limit). This wastes IPC bandwidth and causes unnecessary allocations. The actual DB storage is safe because `sanitize_hostname()` truncates, but log messages may include the raw value before sanitization. The DHCPv6 path is not affected by this specific issue since it does not process hostnames, but the DUID parsing has its own validation concerns (see issue #29).

**Proper fix:** Truncate and validate in the DHCP handler before sending to the agent: reject hostnames > 255 bytes or containing non-printable characters.

**Status: Fixed.** `sanitize_hostname()` added to the DHCP server — filters to `[a-zA-Z0-9._-]` and truncates to 63 chars before IPC. The agent retains its own `sanitize_hostname()` as defense-in-depth.

## 22. DHCP discover_times and DHCPv6 solicit_times HashMaps grow without bound

**What:** The DHCP server (`hermitshell-dhcp/src/main.rs:53`) uses `HashMap<String, Instant>` to rate-limit DHCPDISCOVER messages (10-second cooldown per MAC). The DHCPv6 server uses a similar `solicit_times` HashMap to rate-limit DHCPv6 SOLICIT messages. Entries are never evicted in either map — every unique MAC that sends a DISCOVER or SOLICIT is stored forever.

**Why:** Simplicity. Rate limiting was added but eviction was not.

**Risk:** An attacker on the LAN can send DHCPDISCOVER or DHCPv6 SOLICIT packets with spoofed MAC addresses (different source MAC each time). Each unique MAC adds a HashMap entry. Over hours/days, this exhausts the DHCP/DHCPv6 server's memory. The MAC validation (`is_valid_mac`) filters broadcast and multicast MACs, but there are ~140 trillion valid unicast MACs.

**Proper fix:** Periodically evict entries older than 60 seconds, or cap the HashMap size and evict the oldest entry when full. A simple approach: every 1000 packets, remove entries where `elapsed() > 60s`. Apply the same eviction strategy to both `discover_times` and `solicit_times`.

**Status: Fixed.** Both `discover_times` and `solicit_times` replaced with `LruCache` (cap 10,000 entries). When full, the least-recently-seen MAC is evicted automatically.

## 23. DHCP/DHCPv6 servers accept packets from any source on the LAN interface

**What:** The DHCP server binds to `0.0.0.0:67` and the DHCPv6 server binds to `[::]:547` on the LAN interface. Both process all valid packets without source validation — any device that can send a UDP packet to port 67 (DHCP) or 547 (DHCPv6) on the LAN interface gets an address allocation.

**Why:** This is how DHCP/DHCPv6 works — clients don't have IPs yet when they send DISCOVER/SOLICIT, so you can't filter by source IP. The LAN interface binding provides the boundary.

**Risk:** This is expected DHCP/DHCPv6 behavior, but it means any device physically connected to the LAN (or bridged to it) can claim addresses. A rogue device can exhaust the address pool by requesting allocations with many spoofed MACs. The agent allocates /32 point-to-point IPv4 addresses from 10.0.0.0/16 plus /128 ULA IPv6 addresses per device, giving 16,580,355 possible device allocations (up from ~16,000 with the old /30 subnet scheme). DHCPv6 has the same MAC spoofing risk — a client can use a different DUID per request to appear as a new device each time.

**Proper fix:** Add a maximum device limit in the agent's `dhcp_discover` handler. When the device count exceeds a threshold (e.g., 1000), reject new allocations. Apply the same limit to the DHCPv6 `dhcpv6_solicit` handler. Consider alerting the admin.

**Status: Mitigated.** The LRU cap on DHCP rate-limit maps (#22) bounds the rate of new device registrations from MAC-spoofing attacks. The architectural 16.5M device limit in `db.rs` remains as the hard cap.

## 24. set_config allows overwriting critical keys without restriction

**What:** The `set_config` IPC method (`socket.rs:590`) accepts any key/value pair and writes it to the config table. This includes `admin_password_hash` (overwrite the admin password), `session_secret` (invalidate all sessions or set a known secret), `wg_private_key` (replace the WireGuard key), and `tls_cert_pem`/`tls_key_pem` (replace the TLS certificate).

**Why:** The web UI needs to write some config values (password hash during setup, session secret, TLS cert on first run). No write restriction was implemented.

**Risk:** Any process with socket access can reset the admin password, set a known session secret (forging auth cookies), or replace the TLS certificate with an attacker-controlled one. This is the same access level as issue #1, but for writes — the combination means full takeover via the socket.

**Mitigating factor:** Socket access is required — the socket is `0660` (see issue #49), so only root and group members can connect.

**Proper fix:** Write-protect critical keys: `admin_password_hash` should only be writable via a dedicated `setup` or `change_password` IPC method. `wg_private_key` should be agent-internal. `session_secret` should be auto-generated and never externally writable.

**Status: Fixed.** `set_config` now blocks writes to the same five keys. Password changes go through `setup_password` (requires current password). Session secret and TLS cert are agent-generated. Attempts to read or write blocked keys are logged as warnings.

## 25. Port forwarding can shadow management services

**What:** A user can create port forwards for ports 22 (SSH), 80/443 (web UI), 53 (DNS), or 67 (DHCP). The DNAT rules are applied to the WAN interface, but there's no check against forwarding ports that the router itself uses.

**Why:** Not validated. The nftables rules operate on WAN-inbound traffic, so LAN management access is unaffected, but WAN-side management is impacted.

**Risk:** Forwarding WAN port 22 to an internal host means the admin can no longer SSH to the router from the WAN (if SSH were WAN-accessible). Forwarding port 53 could redirect external DNS queries. Low severity because WAN management access is already limited by the input chain.

**Proper fix:** Reject port forwards for ports in a reserved set: `{22, 53, 67, 68, 80, 443, 51820}`. Or warn the user in the web UI.

**Status: Mitigated.** WAN hardening (#5, #6) blocks SSH and ICMP on WAN, reducing the set of shadowable services. Additionally, overlapping port forward ranges are now rejected — the agent checks all existing forwards before inserting a new one and rejects if the external port range and protocol overlap with any existing forward. The system-port shadowing risk is further reduced because no management services are WAN-accessible (only WireGuard, which is dynamically opened). A static reserved-port check was not added because WAN hardening made it redundant.

## 26. Web UI form handlers silently discard errors

**What:** All web UI form handlers (`main.rs:180-198`) use `let _ = client::...()` to discard IPC errors. The user is always redirected regardless of whether the action succeeded.

**Why:** The web UI was built as a thin wrapper. Error display would require flash messages or query parameters.

**Risk:** A user adds a port forward, gets redirected to the port forwarding page, and sees the forward in the list (because the DB write succeeded) but the nftables rules failed to apply. The forward appears active but doesn't work. Worse, the `handle_setup` handler at `main.rs:117` doesn't discard — if `set_config` fails for the password hash, the user thinks setup worked but no password was saved.

**Proper fix:** Check return values from IPC calls. On error, redirect to an error page or append `?error=...` to the redirect URL.

## 27. No validation on WireGuard peer name or public key format

**What:** The `add_wg_peer` handler (`socket.rs`) accepts a `name` and `public_key` for WireGuard peers. The public key is passed directly to the `wg set` command. The name is stored in the DB without sanitization.

**Why:** The `wg` command validates the public key format (base64, 44 chars). The name is only used for display.

**Risk:** An invalid public key causes `wg set` to fail, which is handled. But the name could be very long or contain special characters. If used in log messages, it could cause log injection. Leptos escapes display output, so XSS via the web UI is unlikely.

**Proper fix:** Validate the public key format (44-char base64 string) and sanitize the name (alphanumeric + hyphens, max 64 chars) before storage.

---

## IPv6 Dual-Stack

## 28. RA Guard bypass potential

**What:** The nftables RA Guard rule drops ICMPv6 type 134 (Router Advertisement) from LAN devices in the forward chain. However, a malicious device could send RAs directly to link-local multicast (`ff02::1`) before nftables processes the packet if the RA reaches the LAN bridge/switch before the router.

**Why:** RA Guard is implemented at L3 (nftables) rather than L2. The router only sees packets that traverse its interfaces — RAs sent between devices on the same L2 segment may never reach the router's nftables chains.

**Risk:** A rogue device on the LAN can send fake Router Advertisements to other LAN devices, causing them to configure incorrect default gateways or DNS servers. This enables MITM attacks on IPv6 traffic. The nftables rule only protects against RAs that transit the router, not same-segment RAs.

**Proper fix:** RA Guard at L2 (managed switch with RA Guard support) would provide better protection. Alternatively, use `ebtables` or bridge netfilter rules to filter RAs at the bridge level before they reach other LAN ports.

## 29. DHCPv6 DUID-based MAC extraction assumes Ethernet

**What:** The `extract_mac_from_duid()` function only handles DUID-LLT (type 1) and DUID-LL (type 3) with Ethernet hardware type. Clients using DUID-EN (type 2) or DUID-UUID (type 4) will be rejected.

**Why:** This is intentional for security — the agent needs a MAC address for device tracking and per-device isolation. Without a MAC, there is no way to associate the DHCPv6 client with an existing device record or apply the correct firewall rules.

**Risk:** Some clients (notably Windows with certain configurations, VMs, or IoT devices) may use DUID-EN or DUID-UUID formats. These clients will fail to obtain IPv6 addresses via DHCPv6, falling back to SLAAC only (if available) or having no IPv6 connectivity. This is a compatibility limitation rather than a security vulnerability.

**Proper fix:** For DUID-EN and DUID-UUID clients, consider extracting the MAC from the DHCPv6 packet's source link-layer address option (Option 79) or the Ethernet frame's source MAC as a fallback. Log a warning when a DUID type cannot be parsed so administrators can identify affected devices.

## 30. IPv6 pinholes expose devices to inbound internet traffic

**What:** When an IPv6 pinhole is created, it adds a forwarding rule that accepts inbound traffic to the device's global IPv6 address on the specified port. Unlike IPv4 port forwarding (DNAT), which translates the destination address, IPv6 pinholes directly expose the device's real address to the internet.

**Why:** IPv6 does not use NAT. Each device has a globally routable address, and pinholes work by selectively allowing inbound traffic through the firewall to that address.

**Risk:** If the device has a vulnerability on the pinholed port, it is directly exploitable from the internet without any address translation layer. An attacker can connect directly to the device's global IPv6 address. Unlike IPv4 DNAT where the router terminates the connection and re-originates it, IPv6 pinhole traffic passes straight through to the device.

**Proper fix:** Warn the user in the web UI when creating a pinhole that the device will be directly reachable from the internet on the specified port. Consider adding rate limiting or geo-IP filtering options for pinholed ports. Log all inbound connections through pinholes for audit purposes.

## 31. DHCPv6-PD lease file parsing trusts dhclient output

**What:** The `parse_delegated_prefix()` function reads the dhclient6 lease file and extracts the `iaprefix` value. The lease file is written by dhclient running as root, so it is treated as trusted input.

**Why:** dhclient6 is a system daemon running as root that writes lease files to a root-owned directory. The content originates from the ISP's DHCPv6 server, but dhclient validates the protocol-level fields before writing them.

**Risk:** If the lease file is tampered with (by an attacker with root access, or if the file permissions are misconfigured), the parsed prefix could be invalid or malicious. An attacker-controlled prefix could cause the agent to assign addresses from an unexpected range, potentially conflicting with other networks or routing traffic to attacker-controlled infrastructure. However, an attacker with root access already has full control of the system.

**Proper fix:** Validate the parsed prefix format (must be a valid IPv6 prefix with a reasonable prefix length, e.g., /48 to /64). Reject prefixes that fall outside expected ULA or GUA ranges. Set the lease file permissions to `0600 root:root` and verify them before parsing.

---

## Config Key Protection

## 32. get_tls_config exposes the TLS private key over IPC

**What:** The `get_tls_config` IPC method returns both `tls_cert_pem` and `tls_key_pem` to the caller. The TLS private key crosses the Unix socket boundary.

**Why:** The web UI container terminates TLS (it binds ports 8080/8443 and handles HTTPS). It needs the private key to configure `rustls`. The agent generates and stores the cert, so the web UI must retrieve it at startup.

**Risk:** Any process with socket access can obtain the TLS private key. With the key, an attacker can impersonate the router's web UI or decrypt captured traffic. The socket is `0660` (see issue #49), so only root and group members can read the key.

**Mitigating factor:** Same socket access control as all other IPC methods. The cert is self-signed, so impersonation is only meaningful if the user has already trusted it.

**Proper fix:** Have the agent terminate TLS directly instead of delegating to the web UI container. Alternatively, write the cert/key to a file readable only by the container, avoiding IPC transfer. Neither approach is clearly better given the current Docker architecture.

## 33. verify_password accepts plaintext passwords over the Unix socket

**What:** The `verify_password` IPC method accepts a plaintext password in the `value` field. The password is transmitted in the clear over the Unix socket.

**Why:** This is the purpose-built replacement for the web UI reading the password hash directly. The agent now performs Argon2 verification internally, keeping the hash secret. The tradeoff is that the plaintext password crosses the IPC boundary instead.

**Risk:** A process that can read Unix socket traffic (e.g., root using `strace` or `socat` on the socket path) could capture plaintext passwords. In practice, a root attacker can already read the hash from the DB directly.

**Mitigating factor:** Unix socket traffic is local-only and not network-observable. However, the socket is `0660` (see issue #49), so only root and group members can connect and send `verify_password` requests. The previous approach (web UI reading the hash) was worse — the hash could be extracted and cracked offline, while a plaintext password captured from a single request has limited replay value if sessions are used.

**Proper fix:** Acceptable for the threat model. A challenge-response protocol (e.g., SRP) would avoid sending the plaintext, but adds significant complexity for no practical security gain on a local socket.

## 34. Argon2 hashing holds the database mutex

**What:** The `verify_password` and `setup_password` handlers acquire the database mutex lock and hold it through the Argon2 hash/verify operation. Argon2 is intentionally slow (~100ms-1s depending on parameters), blocking all other IPC methods that need DB access during that time.

**Why:** The agent uses a single `Mutex<Db>` for all database access. The password handlers need to read from the DB (get the stored hash) and the Argon2 operation is performed while the lock is held.

**Risk:** During password verification or setup, all other IPC requests (device listing, DHCP, config reads) are blocked. Under normal usage this is a brief delay on infrequent operations. Under brute-force attack, the attacker effectively DoS-es the entire agent IPC.

**Mitigating factor:** Logins are infrequent. Issue #8 (no rate limiting) is the more direct concern — rate limiting would prevent sustained blocking.

**Proper fix:** Read the hash from the DB, drop the lock, perform Argon2, then re-acquire for writes. This requires splitting the operation but keeps the mutex held for only microseconds.

**Status: Fixed.** Both handlers now scope the DB lock to just `get_config`/`set_config` calls. Argon2 verify and hash run with the DB mutex released. A separate `PasswordLock` (`Mutex<()>`) serializes `setup_password` to prevent TOCTOU races on concurrent password changes without holding the DB lock.

## 35. No memory zeroization of secret material

**What:** The `session_secret`, `admin_password_hash`, TLS private key, and plaintext passwords during verification are held in standard Rust `String` values. When dropped, the memory is freed but not zeroed — the secret data may linger in the process heap until overwritten by a future allocation.

**Why:** Simplicity. The `zeroize` crate exists for this purpose but was not added.

**Risk:** A memory dump of the agent process (via `/proc/pid/mem`, core dump, or cold boot attack) could recover secret material. An attacker who can dump the agent's memory already has root access, so the practical risk is limited to forensic scenarios.

**Proper fix:** Use `zeroize::Zeroizing<String>` for secret values to ensure they are zeroed on drop. Apply to variables holding `session_secret`, password hash strings, plaintext passwords, and TLS key PEM data.

## 36. runZero API token stored in plaintext

**What:** The `runzero_token` config value (a runZero Export API token, XT-prefixed) is stored unencrypted in the SQLite config table, same as `wg_private_key`.

**Why:** The agent needs the token to authenticate with the runZero Export API on each sync cycle. There is no keyring or HSM available on a router appliance.

**Risk:** An attacker with filesystem access to the SQLite database can read the token and use it to query the runZero console's asset inventory. The token is read-only (Export API), so no data can be modified. The token is blocked from `get_config`/`set_config` IPC reads/writes and only accessible via the dedicated `set_runzero_config` method.

**Proper fix:** Encrypt secrets at rest using a key derived from a hardware identifier or TPM, if available. Alternatively, use short-lived OAuth tokens instead of long-lived Export API tokens.

## 37. TLS certificate verification disabled for runZero API

**What:** The reqwest client in `runzero.rs` uses `danger_accept_invalid_certs(true)` when connecting to the runZero console.

**Why:** Self-hosted runZero consoles commonly use self-signed TLS certificates. Requiring valid certs would prevent most self-hosted deployments from working without a custom CA configuration path.

**Risk:** An attacker in a man-in-the-middle position on the network path between the router and the runZero console could intercept the API token and asset data. The token is read-only, limiting the impact.

**Proper fix:** Add a `runzero_ca_cert` config option that allows the user to upload a custom CA certificate for the runZero console. Use this CA cert for TLS verification instead of disabling it entirely.

**Status: Fixed.** The `runzero_ca_cert` config option allows uploading a custom CA certificate for the runZero console. When set, TLS verification uses system trust roots plus the custom CA. When not set, only system trust roots are used. `danger_accept_invalid_certs` has been removed.

## 38. Speed test makes outbound HTTP requests to admin-configured URL

**What:** The QoS speed test feature uses `reqwest` to make HTTP GET/POST requests from the router to a URL configured by the admin.

**Why:** Needed to measure WAN link speed for CAKE qdisc bandwidth configuration.

**Risk:** SSRF — if the admin configures a URL pointing to an internal service (e.g., `http://10.0.0.5:8080/admin`), the router will make a request to it on the admin's behalf. Mitigated by rejecting private/loopback IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, ::1, fd00::) when the host is an IP literal. However, DNS hostnames bypass the check entirely — a hostname resolving to a private IP (e.g., `http://attacker.example.com` → `127.0.0.1`) is accepted.

**Proper fix:** Resolve the hostname to an IP before the `is_public_ip` check. The admin already has full router access, so SSRF provides no privilege escalation — the validation prevents accidental misconfiguration rather than a real attack vector.

## 39. refresh_session only checks absolute timeout, not idle timeout

**What:** The `refresh_session` IPC method verifies the HMAC and checks the absolute timeout (8 hours), but does not check the idle timeout (30 minutes). It will reissue a token for any session that hasn't exceeded its absolute lifetime, regardless of how long it has been idle.

**Why:** The auth middleware always calls `verify_session` (which checks both idle and absolute timeouts) before calling `refresh_session`. An idle-expired token is rejected at the `verify_session` step and never reaches `refresh_session`.

**Risk:** A direct IPC caller (not going through the web UI middleware) could refresh an idle-expired token by calling `refresh_session` directly, bypassing the idle timeout. The socket is `0660` (see issue #49), so only root and group members can do this.

**Proper fix:** Add idle timeout checking to `refresh_session` so it is self-contained. This would make the IPC API consistent — both methods enforce both timeouts.

**Status: Fixed.** `refresh_session` now checks both idle timeout (`now - last_active > SESSION_IDLE_TIMEOUT_SECS`) and absolute timeout (`now - created > SESSION_ABSOLUTE_TIMEOUT_SECS`) before issuing a refreshed token.

## 40. Stateless sessions cannot be individually revoked

**What:** Sessions are stateless HMAC tokens with no server-side session store. There is no way to revoke a specific session — the only mechanism is rotating `session_secret`, which invalidates all sessions.

**Why:** Stateless tokens were chosen to avoid per-request database writes for session tracking. The router admin panel has a single admin user, so per-session revocation is less critical than for multi-user systems.

**Risk:** If a session token is stolen, it remains valid until it expires (up to 8 hours absolute). Logout clears the client's cookie but the token itself is still valid if replayed. On a LAN-only appliance with a single admin, the practical risk is low.

**Proper fix:** Add a server-side session revocation list (a small in-memory set of revoked token prefixes checked during `verify_session`). Or switch to server-side session storage if multi-user support is added.

## 41. Login rate limit state is in-memory only

**What:** The exponential backoff counters for `verify_password` and `setup_password` are stored in process memory. Restarting the agent or web UI container resets all rate limiting state.

**Why:** Avoids DB schema changes, prevents permanent lockout on a single-admin appliance, and keeps the implementation simple.

**Risk:** An attacker with the ability to restart the agent process (requires root or systemd access) can clear the rate limit and resume brute-forcing. Also, a legitimate DoS of the agent (e.g., crashing it) would reset protection.

**Proper fix:** Acceptable for the threat model — root access is already game over. If persistence is needed later, store failure counts in SQLite with a TTL column.

## 42. Web UI rate limiting uses global counter, not per-IP

**What:** The web UI rate limit middleware uses a single global `(failures, last_failure)` counter rather than tracking per source IP.

**Why:** Simplicity. Per-IP tracking was not implemented. The container uses `--network host`, so real client IPs are visible on the socket — they are available but not extracted.

**Risk:** A brute-force attack from one client locks out all clients, including the legitimate admin. On a single-admin LAN appliance this is low risk, but it means a malicious LAN device could DoS the admin UI by sending repeated wrong passwords.

**Proper fix:** Use Axum's `ConnectInfo<SocketAddr>` extractor to get the client IP, then switch the middleware to a per-IP `HashMap<IpAddr, (u32, Option<Instant>)>` with LRU eviction.

**Status: Fixed.** Rate limiting now uses `LruCache<IpAddr, (u32, Instant)>` capped at 1,000 entries. Client IP extracted via `ConnectInfo<SocketAddr>` injected from the HTTPS accept loop. One client's brute-force attempts no longer affect other clients.

## 43. setup_password not rate-limited at web UI layer

**What:** The web UI rate limit middleware only applies to `/api/login*` paths, not `/api/setup_password*`. The agent-side rate limiter still protects `setup_password`.

**Why:** `setup_password` returns HTTP 500 for multiple non-brute-force reasons (password already set without current password, too short, too long). Counting these as failed login attempts caused false-positive lockouts during normal operation and broke integration tests.

**Risk:** An attacker can brute-force the current password via `setup_password` without web UI rate limiting. The agent-side rate limiter still applies (shared counter with `verify_password`), so this is defense-in-depth reduction, not a bypass.

**Proper fix:** Distinguish brute-force failures (wrong current password → HTTP 422) from validation errors (HTTP 500) in the middleware, and only count 422 responses as failures.

**Status: Fixed.** The per-IP rate limit middleware now applies to both `/api/login*` and `/api/setup_password*` paths. All non-success responses count as failures.

## 44. DHCP server IPC has no read timeout

**What:** The `agent_request()` function (`hermitshell-dhcp/src/main.rs:168`) opens a blocking `UnixStream` to the agent and calls `read_line()` with no timeout. If the agent hangs or crashes mid-response, the DHCP server blocks indefinitely.

**Why:** Simplicity. The agent is expected to always respond promptly.

**Risk:** The DHCP server is single-threaded (synchronous event loop). A hung agent blocks the entire DHCP server — no new clients can get addresses until the process is restarted. The DHCPv6 server runs in a separate thread and is independently affected (it also uses `agent_request()`).

**Proper fix:** Call `stream.set_read_timeout(Some(Duration::from_secs(5)))` before `read_line()` in `agent_request()`. On timeout, log the error and return `Err` so the DHCP handler can continue processing other packets.

**Status: Fixed.** `agent_request()` now calls `stream.set_read_timeout(Some(Duration::from_secs(5)))` after connecting. On timeout, `read_line()` returns an I/O error which propagates to callers. DHCP handlers already handle errors by logging and skipping the reply, so the client retries via standard DHCP backoff.

## 45. Agent IPC read_line has no size limit

**What:** The agent's IPC handler (`hermitshell-agent/src/socket.rs:246`) reads lines with `reader.read_line(&mut line)` which grows the buffer until it finds a newline. There is no cap on line length.

**Why:** Simplicity. IPC callers are expected to send well-formed, reasonably-sized JSON.

**Risk:** Any process with socket access can send a multi-gigabyte line (no newline) to exhaust agent memory. The socket is `0660` (see issue #49), so only root and group members can trigger this.

**Mitigating factor:** The DHCP server's requests are bounded by the 1500-byte UDP packet that triggered them, so this is only exploitable by a direct socket client.

**Proper fix:** Use `read_line()` with a size-limited wrapper, or switch to `tokio::io::AsyncBufReadExt::read_line()` with a manual length check. Reject lines longer than 64 KB.

**Status: Fixed.** Both `handle_client` and `handle_dhcp_client` now check `line.len() > 65_536` after `read_line()` and close the connection with a warning if exceeded. The check is post-allocation (tokio reads in 8KB chunks, so the String grows incrementally) but prevents processing and stops further reads. The 64KB limit is well above the largest legitimate request (`import_config`).

## 46. DHCP server opens a new IPC connection per request

**What:** The `agent_request()` function (`hermitshell-dhcp/src/main.rs:168`) opens a new `UnixStream` for every IPC call. Each DHCP DISCOVER triggers one connection, and each DHCP REQUEST triggers two (one for discover, one for provision).

**Why:** Simplicity. A persistent connection would require reconnection logic if the agent restarts.

**Risk:** Under heavy DHCP traffic (many devices joining simultaneously), the DHCP server opens many short-lived connections. Each connection spawns a tokio task in the agent (`socket.rs:233`). This compounds with issue #19 (no connection limiting) — a DHCP flood creates both rate-limit map entries (now bounded by LRU) and agent connections (unbounded).

**Mitigating factor:** The 10-second rate limit per MAC means legitimate traffic creates at most one connection per device per 10 seconds. The risk is primarily from spoofed-MAC floods, which are already mitigated by the LRU cap discarding old entries.

## 47. Container lacks no-new-privileges protection

**What:** The Docker container runs without `--security-opt no-new-privileges`. This means a process inside the container could theoretically escalate privileges via setuid/setgid binaries if any were present.

**Why:** `no-new-privileges` sets the kernel's `PR_SET_NO_NEW_PRIVS` flag, which prevents privilege escalation during `execve` — but it also prevents the kernel from honoring file capabilities set via `setcap`. The container binary uses `setcap cap_net_bind_service=+ep` to bind ports 80/443 as a non-root user. With `no-new-privileges` enabled, this capability is silently ignored and the binary cannot bind privileged ports.

**Risk:** If an attacker compromises the web UI process and can write a setuid binary to the container filesystem, they could escalate to root inside the container. In practice, this is mitigated by `--read-only` (filesystem is immutable) and `--cap-drop ALL --cap-add NET_BIND_SERVICE` (only one capability available). There are no setuid binaries in the Alpine base image after `adduser`/`addgroup`.

**Proper fix:** Switch to high ports (8080/8443) with nftables DNAT rules on the host redirecting 80/443. This would eliminate the need for `cap_net_bind_service` entirely, allowing `no-new-privileges` to be re-enabled. Alternatively, use Docker's ambient capabilities (`--cap-add` with `--security-opt no-new-privileges`) which requires a Docker runtime that supports ambient capability injection (not yet standard).

**Status: Fixed.** Web UI switched to high ports (8080/8443). nftables DNAT redirects 80→8080 and 443→8443 on the LAN interface. `setcap` and `libcap` removed from Dockerfile. `--security-opt no-new-privileges` re-enabled, `--cap-add NET_BIND_SERVICE` removed (no longer needed).

## 48. Per-IP rate limit cache can be evicted by distributed attack

**What:** The web UI per-IP rate limiter uses an `LruCache` capped at 1,000 entries. An attacker with access to many source IPs (e.g., multiple compromised LAN devices) could flood the cache with new entries, evicting a previously tracked IP and resetting its backoff counter.

**Why:** Bounded caches are necessary to prevent unbounded memory growth. LRU eviction is a standard trade-off — it favors tracking recently active IPs, but allows old entries to be displaced.

**Risk:** Low. The agent-side rate limiter uses a global counter that is unaffected by web UI cache eviction. An attacker who evicts their IP from the web UI cache still hits the agent's exponential backoff on the next attempt. The web UI per-IP layer is a UX improvement (prevents one attacker from locking out other clients); the agent-side global limiter is the ultimate brute-force defense.

**Proper fix:** No fix needed — the two-layer design (per-IP web UI + global agent) provides defense in depth. If a stronger guarantee were desired, the web UI could use a larger cache or persist rate limit state to the agent's SQLite database.

---

## Multi-Mode Deployment

## 49. Agent socket is world-readable/writable (0666)

**What:** The agent sets both Unix sockets (`agent.sock` and `dhcp.sock`) to mode `0666`. Previously they were `0660 root:root` with a `chown` to GID 1000.

**Why:** Three deployment modes need socket access from different users: (1) direct mode — the standalone web UI container runs as `hermitshell` (UID/GID 1000), which the old `chown` handled; (2) install mode — `install.sh` creates a `hermitshell` system user with a dynamic UID/GID (not necessarily 1000), so the `chown(GID 1000)` would target the wrong group; (3) docker mode — the all-in-one container runs all processes as root, so no `chown` is needed. Making the socket `0666` is the simplest way to support all three modes without per-mode socket ownership logic.

**Risk:** Any local process can connect to the agent socket and issue IPC commands — listing devices, changing firewall rules, toggling QoS, reading the TLS private key via `get_tls_config`, and brute-forcing the admin password via `verify_password`. Previously, only root and GID 1000 could connect. This broadens the attack surface for issues #1, #3, #19, #32, #33, #39, and #45.

**Mitigating factor:** The router is a single-purpose appliance. In the install mode, only `root` and `hermitshell` user processes should be running. On a dedicated router, there are no untrusted local users. The agent's sensitive key protections (#1 Status: Fixed) and rate limiting (#8 Status: Fixed) still apply regardless of socket permissions.

**Proper fix:** Detect the web UI user at startup and `chown` the socket to match. In install mode, read the `hermitshell` user's GID via `getgrnam("hermitshell")`. In direct mode, use GID 1000 (matching the container user). In docker mode, skip the `chown` entirely (all processes are root). Alternatively, create a `hermitshell` group during install and ensure all web UI processes run with that group, then `chown root:hermitshell 0660`.

**Status: Mitigated.** Socket permissions tightened from `0666` to `0660` (root + group only). The web UI container must run in the same group as the agent to access the socket. Integration tests `chmod 666` the socket after agent restarts so the unprivileged test user can connect.

## 50. Docker all-in-one container runs with --privileged

**What:** The `hermitshell-aio` container runs with `--privileged`, giving it full access to the host kernel's capabilities, devices, and syscalls. All processes inside (agent, DHCP, blocky, web UI) run as root.

**Why:** The agent needs to manage nftables rules, create/configure network interfaces (WireGuard wg0, IFB ifb0), load kernel modules (ifb, wireguard), run `ip`, `tc`, and `conntrack`, and bind to raw sockets for DHCP. These operations require `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_SYS_MODULE`, and access to `/dev/net/tun`. The `--privileged` flag was the expedient choice to grant all of these at once.

**Risk:** A compromised process inside the container (e.g., via a web UI vulnerability) has unrestricted root access to the host. With `--network host`, this means full control over the host's network stack, filesystem (via `/proc`, `/sys`), and all devices. The `--privileged` flag also disables all seccomp, AppArmor, and SELinux confinement.

**Mitigating factor:** The standalone web UI container (`hermitshell/Dockerfile`) still runs non-privileged with `--read-only --cap-drop ALL --security-opt no-new-privileges`. Only the all-in-one container requires `--privileged`. The all-in-one mode is primarily for testing and simple deployments; production-grade deployments should use install mode (systemd units with hardening directives).

**Proper fix:** Replace `--privileged` with the minimum required capabilities: `--cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_MODULE --device /dev/net/tun`. Add `--security-opt no-new-privileges` and `--read-only` (with tmpfs mounts for writable paths). Run the web UI process as a non-root user inside the container using s6's `s6-setuidgid`. Keep only the agent and DHCP server as root.

## 51. ACME account key stored in SQLite config

**What:** The ACME account private key (used to sign requests to Let's Encrypt) is stored in the SQLite config table alongside other secrets.

**Why:** Consistent with existing secret storage pattern (TLS key, WireGuard key). No separate key store.

**Risk:** Low. The account key can only be used to request/revoke certs for domains you control. It cannot decrypt traffic. Blocked from `get_config` access.

**Proper fix:** External secrets manager or encrypted-at-rest column.

## 52. Cloudflare API token stored in plaintext

**What:** The Cloudflare API token (with Zone:DNS:Edit permission) is stored in the config DB in plaintext.

**Why:** The agent needs the token to create/delete DNS records during ACME challenges. Same storage pattern as runZero token.

**Risk:** Medium. Token grants DNS write access to the configured zone. Scoped to a single zone. Blocked from `get_config` access.

**Proper fix:** Encrypted-at-rest column, or use Cloudflare scoped API tokens (zone-locked + permission-limited).

## 53. Syslog export uses unencrypted, unauthenticated UDP

**What:** `send_syslog()` in `log_export.rs` sends RFC 5424 syslog messages over UDP with no encryption or authentication.

**Why:** UDP syslog is the standard protocol. Most syslog collectors (rsyslog, syslog-ng, Splunk) expect this format. Adding TLS syslog (RFC 5425) would add complexity.

**Risk:** Low. An attacker on the network can eavesdrop on syslog traffic (device IPs, DNS queries, alerts) or inject forged syslog messages. Syslog targets are typically on a trusted LAN segment.

**Proper fix:** Add TLS syslog (RFC 5425) as an option. Validate that the syslog target is on a local network segment, or warn when targeting WAN addresses.

## 54. WiFi AP credentials stored recoverable by root

**What:** AP login passwords are stored in the SQLite config table. They are readable by the agent process to authenticate to APs.

**Why:** The agent must authenticate to APs to push config and pull client data. Passwords cannot be one-way hashed.

**Risk:** Root on the router box can read AP credentials. Same trust model as WireGuard private key and TLS key.

**Proper fix:** Hardware security module or separate credential store with process-level isolation. Out of scope for a commodity router.

**Status: Mitigated.** Passwords are now encrypted at rest with AES-256-GCM, keyed from session_secret via HKDF-SHA256. Existing plaintext passwords are migrated on startup. Root can still derive the key from the session_secret in the config DB, so this is defense-in-depth, not a complete fix.

## 55. TLS verification disabled for WiFi AP HTTPS connections

**What:** The EAP standalone provider uses `danger_accept_invalid_certs(true)` when connecting to access points via HTTPS.

**Why:** Consumer and prosumer APs use self-signed TLS certificates in standalone mode. There is no CA trust chain to verify against.

**Risk:** An attacker in a man-in-the-middle position between the router and an AP could intercept AP credentials and client data during polling. The AP is typically on the same LAN segment as the router, so the MITM window is small.

**Proper fix:** Add a `wifi_ap_ca_cert` config option allowing the user to upload a custom CA certificate per AP. Same approach as the runZero TLS fix (#37).

**Status: Partially fixed.** Each WiFi AP record supports an optional `ca_cert_pem` field for a custom CA certificate. The WiFi AP client uses native-tls (OpenSSL) to support legacy TLS found on IoT devices (1024-bit RSA, non-ECDHE ciphers). `danger_accept_invalid_certs` remains enabled unconditionally — even when a CA cert is uploaded, TLS verification is not enforced. The CA cert is currently stored for audit/fingerprinting purposes only and provides **no verification benefit**. A MITM attacker presenting any certificate will be accepted regardless of the CA cert setting. The runZero client (#37) uses rustls with proper CA cert validation since self-hosted servers typically have modern TLS.

## 56. AP password sent as MD5 hash, not plaintext TLS-protected

**What:** The EAP720 login flow sends `MD5(password).toUpperCase()` over HTTPS. The MD5 hash is the effective credential — anyone who captures it can replay it to authenticate.

**Why:** This is the TP-Link firmware's authentication protocol. The agent must conform to it.

**Risk:** MD5 is fast to brute-force. If TLS is compromised (see #55), the MD5 hash can be captured and either replayed directly or cracked to recover the plaintext. The plaintext is also needed for the agent to authenticate, so it's stored recoverable (see #54).

**Proper fix:** Nothing the agent can do — this is the AP firmware's design. Ensure #55 is mitigated (TLS verification) to protect the hash in transit. Use strong random passwords for APs to resist offline cracking.

## 57. EAP session timeout causes re-authentication on every poll cycle

**What:** The EAP720 has a very aggressive session timeout (~30-60 seconds). The agent's 60-second polling loop creates a fresh `EapSession` per cycle, sending the MD5 password hash each time.

**Why:** The agent uses a connect-per-poll pattern. The AP's session cannot be kept alive across poll intervals because the timeout is shorter than the polling interval.

**Risk:** Each poll cycle transmits the AP credential hash. Increased exposure window compared to a persistent session. If the polling interval were reduced, reuse of sessions would be feasible.

**Proper fix:** Consider caching the `EapSession` and re-authenticating only when a request returns `timeout:true`. This reduces credential exposure to once per session rather than once per poll.

## 58. Update checker phones home to GitHub

**What:** The agent spawns a background loop that polls `https://api.github.com/repos/jnordwick/hermitshell/releases/latest` every 24 hours using reqwest with a 10-second timeout. The request includes a `User-Agent: hermitshell-agent` header.

**Why:** Users need to know when a new release is available. There is no push notification channel for a self-hosted router appliance, so the agent must poll.

**Risk:** Each check reveals the router's WAN IP and the fact that it runs HermitShell to GitHub (and any network observer). The `User-Agent` header confirms the software identity. GitHub's API may log the IP for rate-limiting purposes.

**Proper fix:** Make the update check opt-in (disabled by default). Add a config key `update_check_enabled` that the setup wizard or settings page can toggle. Use a generic `User-Agent` or omit it entirely. Consider proxying through a project-specific update endpoint that aggregates check counts without logging individual IPs.

**Status: Fixed.** Update checker is now opt-in. Gated on `update_check_enabled` config key, which defaults to `false` (no outbound network calls unless explicitly enabled). The loop checks this flag at startup and each iteration, exiting when disabled. The `check_update` IPC response includes an `enabled` field so the UI can display the current state.

## 59. Update checker trusts GitHub API response without signature verification

**What:** The update checker parses the `tag_name` field from the GitHub releases API response and stores it in the config DB. No signature or checksum verification is performed on the version string.

**Why:** The check is informational only — it tells the admin a new version exists. It does not download or install anything.

**Risk:** A MITM attacker (between router and GitHub) could inject a fake version string, potentially tricking the admin into visiting a malicious download URL. The response is HTTPS-protected, so this requires TLS compromise. The stored `tag_name` is rendered in the web UI — if it contains HTML/JS, Leptos's default escaping prevents XSS.

**Proper fix:** Sign releases with a project GPG key and verify the signature in the agent. For the notification-only use case, the current HTTPS protection is adequate.

## 60. Setup wizard endpoints are unauthenticated

**What:** The `list_interfaces` and `set_interfaces` IPC methods (and their web UI server functions) require no authentication. They are guarded only by checking whether `admin_password_hash` is already set in the DB.

**Why:** The setup wizard runs before any password exists. There is no credential to authenticate with.

**Risk:** During the window between first boot and password setup, any process with socket access (or any LAN client reaching the web UI) can set the WAN and LAN interface assignments. After the password is set, `set_interfaces` rejects all calls. The window is typically seconds to minutes on first boot.

**Proper fix:** Acceptable for the threat model — the router is physically controlled during initial setup. For defense-in-depth, consider a one-time setup token displayed on the console during first boot.

## 61. MAC filtering used as client blocking mechanism

**What:** `block_client` and `kick_client` use the AP's MAC filtering feature (deny list). `kick_client` blocks then unblocks after 2 seconds.

**Why:** The EAP720 standalone API does not expose a direct client deauthentication endpoint.

**Risk:** MAC filtering affects all SSIDs globally. Blocking one client's MAC blocks it from all radios and SSIDs. The 2-second window in `kick_client` is a race condition — if the agent crashes between block and unblock, the client stays permanently blocked. MAC addresses can be spoofed, so a determined attacker can change their MAC to bypass the block.

**Proper fix:** Track blocked MACs in the agent DB so they can be cleaned up on restart. Consider using the AP's scheduler or portal features for more granular access control. Document that MAC-based blocking is advisory, not a security boundary.

## 62. Backup with plaintext secrets

**What:** When exporting a backup with `--include-secrets` but without `--encrypt`, secret values (admin password hash, WireGuard private key, TLS private key, API tokens, WiFi AP passwords) are included as plaintext JSON.

**Why:** Users need the ability to fully restore a router from backup without re-entering every credential. Requiring encryption adds friction that may prevent users from making backups at all.

**Risk:** If the backup file is compromised, an attacker gains all router credentials. The admin password hash (Argon2id) still requires cracking, but WireGuard keys, TLS keys, and API tokens are immediately usable. Additionally, the `export_config` IPC method returns all secrets as cleartext JSON over the Unix socket when `include_secrets` is true and no passphrase is given — any process with socket access can obtain every credential in a single request.

**Proper fix:** Always use `--encrypt` with a strong passphrase. The encrypted backup uses Argon2id key derivation (m=64MB, t=3) + AES-256-GCM, making brute-force impractical with a decent passphrase. Store backup files with restricted permissions (0600) and on encrypted storage. Consider requiring a passphrase for any export that includes secrets.

## 63. Backup passphrase in URL query parameter

**What:** The web UI backup download endpoint (`/api/backup/config`) accepts the encryption passphrase as a URL query parameter (`?secrets=1&passphrase=...`).

**Why:** Browser download flows require GET requests. Sending the passphrase in a POST body would prevent the browser from initiating a file download directly (it would require JavaScript to fetch the response and trigger a download, or a two-step flow).

**Risk:** The passphrase appears in the URL. HTTPS encrypts the URL in transit, so it is not visible on the wire. However, the URL may be logged in browser history, proxy logs (if TLS-terminating), or the `Referer` header on subsequent navigation. The agent does not log query parameters.

**Proper fix:** Use a POST-based download flow with JavaScript: submit the form via `fetch()`, receive the response as a blob, and trigger a download via `URL.createObjectURL()`. This keeps the passphrase in the POST body, out of URL logs. The tradeoff is requiring JavaScript for the download (currently works without JS).

---

## WiFi AP Management

## 64. WireGuard peers cannot use router DNS

**What:** The nftables input chain accepts DNS (TCP/UDP port 53) only from the LAN interface. WireGuard peers can reach the web UI and ping the router via wg0, but cannot use the router's DNS resolver or ad-blocking service.

**Why:** When wg0 was added to the ICMP and web UI rules (issue #6 fix), DNS was not included. The omission was not caught because no integration test exercises DNS resolution through a WireGuard tunnel.

**Risk:** WireGuard VPN peers must use external DNS servers, bypassing the router's ad-blocking and DNS query logging. This defeats a key security feature for remote users who expect the same protection as LAN clients.

**Proper fix:** Add wg0 to the DNS rules: `iifname { "{lan_iface}", "wg0" } tcp dport 53 accept` and `iifname { "{lan_iface}", "wg0" } udp dport 53 accept`.

## 65. WiFi SSID password not validated for length

**What:** The `handle_wifi_set_ssid` handler (`socket/wifi.rs`) validates the SSID name (1-32 chars) and band, but does not validate the WiFi password length before sending it to the AP. WPA-PSK requires 8-63 ASCII characters per IEEE 802.11.

**Why:** Validation was applied to the SSID name but overlooked for the password field, assuming the AP would reject invalid values.

**Risk:** A password shorter than 8 characters or longer than 63 could be sent to the AP. The AP may accept it and enter an inconsistent state, or reject it with an error the agent doesn't distinguish from other failures. An empty password with `wpa-psk` security mode would leave the network open.

**Proper fix:** Validate in `handle_wifi_set_ssid`: reject if security is `wpa-psk` and password length is outside 8-63 characters or contains non-ASCII characters.

## 66. import_config does not validate WiFi AP records

**What:** The `handle_import_config` handler (`socket/config.rs`) imports WiFi APs from a backup without validating the `ip`, `name`, or `provider` fields. The handler inserts records directly via `db.insert_wifi_ap()`. In contrast, the individual `handle_wifi_adopt_ap` handler validates IP format (`ip.parse::<IpAddr>()`), name charset and length (1-64 chars, alphanumeric/hyphen/underscore/dot/space), and provider against a whitelist.

**Why:** WiFi AP import was added after `import_config` validation was implemented for devices, port forwards, and DHCP reservations. The AP import section uses best-effort per-entry insertion without the same validation pass.

**Risk:** A crafted or corrupted backup file could insert invalid AP IPs (e.g., `not-an-ip`), causing the WiFi polling loop to fail on connection attempts. Invalid names could contain characters that break audit log parsing. An unknown provider string would cause the polling loop to skip the AP silently.

**Proper fix:** Apply the same validation as `handle_wifi_adopt_ap`: validate IP with `ip.parse::<IpAddr>()`, validate name charset and length, and check provider against the known providers list. Skip invalid entries with a warning rather than inserting them.

## 67. rollup_all_pending holds DB mutex for unbounded time

**What:** The `rollup_all_pending()` method iterates over every unrolled hour since the earliest connection log entry, executing an INSERT+SELECT per hour while holding the DB mutex. On first run after a long uptime (e.g., 1 year = 8,760 hours), this can take seconds to minutes.

**Why:** The rollup needs consistent reads across the iteration and the current architecture uses a single `Mutex<Db>` for all access.

**Risk:** While the mutex is held, all other IPC operations are blocked — DHCP provisioning, device management, DNS log ingestion, and all web UI requests. A client calling `run_bandwidth_rollup` could effectively DoS the router's management plane.

**Proper fix:** Cap iterations per call (e.g., max 168 hours per invocation) so the rollup catches up incrementally across multiple hourly triggers, or release and re-acquire the mutex between iterations.

## 68. set_log_config bypasses BLOCKED_CONFIG_KEYS for webhook_secret

**What:** The `handle_set_log_config` handler (`socket/config.rs`) defines a local `allowed_keys` array that includes `"webhook_secret"`. This handler writes matching keys directly via `db.set_config()` without calling `is_blocked_config_key()`. The generic `handle_set_config` handler correctly blocks writes to `webhook_secret`, but `set_log_config` is a separate code path that sidesteps this check.

**Why:** The log config handler was written with its own allowlist for convenience, not realizing `webhook_secret` was later added to the global blocked keys list.

**Risk:** Any IPC client can overwrite `webhook_secret` via `set_log_config`, enabling them to set a known HMAC secret and forge authenticated webhook payloads. This bypasses the protection documented in #24.

**Proper fix:** Remove `"webhook_secret"` from the `allowed_keys` array in `handle_set_log_config`, or add an `is_blocked_config_key()` check within the write loop.

## 69. Arbitrary audit log injection via log_audit

**What:** The `handle_log_audit` handler (`socket/logs.rs`) accepts arbitrary `action` and `detail` strings and writes them to the audit log table. There is no validation on action name (no allowlist, no length limit, no character filtering) and no length limit on the detail string.

**Why:** The handler was designed to allow external callers (e.g., the web UI) to record audit events. Input validation was not applied.

**Risk:** A process with socket access could flood the audit log with fake entries, inject entries that mimic legitimate admin actions (undermining forensic analysis), or insert very large strings to grow the database. The audit log is informational and not used for access control.

**Proper fix:** Add length limits on the `action` field (max 64 chars) and `detail` field (max 512 chars). Consider restricting `action` to a whitelist of known action names.

## 70. Speed test blocks tokio runtime thread for up to 30 seconds

**What:** The `handle_run_speed_test` handler calls `tokio::task::block_in_place()` to run the HTTP download synchronously. The speed test has a 30-second timeout (`qos.rs`). During this time, one tokio worker thread is blocked.

**Why:** The speed test needs synchronous integration with the IPC response pattern. `block_in_place` was the simplest approach.

**Risk:** While the speed test runs, the blocked worker thread cannot serve other async tasks. Multiple concurrent speed test requests would block multiple threads. The speed test is admin-triggered, so concurrent requests are unlikely.

**Proper fix:** Use `tokio::spawn` to run the speed test asynchronously, return a "test started" response immediately, and provide a separate IPC method to poll for results. Alternatively, reject concurrent speed test requests.

## 71. set_config has no value length limit

**What:** The `handle_set_config` handler (`socket/config.rs`) writes any key/value pair to the config table (after the blocked-key check) with no length validation on the value.

**Why:** No explicit length validation was added. The 64KB IPC message limit provides an implicit per-request cap.

**Risk:** Repeated writes of near-64KB values to many different keys could grow the SQLite database. Requires socket access (0660 permissions).

**Proper fix:** Add a value length limit (e.g., 4KB) in `handle_set_config`. Config values that legitimately need more space (PEM certificates, JSON blobs) already have dedicated handlers that bypass `set_config`.

## 72. HKDF key derivation for WiFi passwords uses no salt

**What:** The `derive_key` function (`crypto.rs`) calls `Hkdf::<Sha256>::new(None, session_secret.as_bytes())` with `None` for the salt parameter. The HKDF output is deterministic for a given session_secret.

**Why:** The session_secret is a 256-bit random value with sufficient entropy. Each encryption uses a unique random 12-byte nonce, so ciphertexts are not repeated.

**Risk:** Theoretically suboptimal per RFC 5869 recommendations, but practically safe given the high-entropy IKM and per-encryption random nonces.

**Proper fix:** Use a fixed application-specific salt (e.g., `b"hermitshell-wifi-encryption-salt-v1"`) for defense-in-depth per RFC 5869 Section 3.1.

## 73. Device nickname lacks character sanitization

**What:** The `handle_set_device_nickname` handler (`socket/devices.rs`) passes the nickname to `db.set_device_nickname()` with only a length check (max 64 chars). No character validation is performed. The nickname is rendered in the web UI and included in audit log messages.

**Why:** Character validation was not applied. Leptos escapes HTML output by default, limiting XSS risk.

**Risk:** Control characters (newlines, tabs, null bytes) or Unicode RTL override characters in nicknames could cause log injection or display rendering issues. Leptos HTML escaping prevents XSS in the web UI.

**Proper fix:** Strip control characters (ASCII 0x00-0x1F, 0x7F) and restrict to printable Unicode, similar to `sanitize_hostname()` but allowing spaces.

## 74. ingest_dns_logs and run_analysis have no rate limiting

**What:** The `ingest_dns_logs` and `run_analysis` IPC methods are available to any socket client with no rate limiting. These trigger expensive operations: DNS log file parsing with DB inserts, and behavioral analysis across all connection/DNS data.

**Why:** These operations are normally triggered by the agent's own background loops (every 10 seconds for DNS ingestion, every 5 minutes for analysis). The IPC methods exist for manual triggering.

**Risk:** An IPC client could call these in a tight loop to cause sustained CPU and I/O load, degrading agent responsiveness. Socket access requires group membership (0660 permissions).

**Proper fix:** Add a debounce (reject if last invocation was < 10 seconds ago), or make them internal-only by removing from the public method routing table.
