# Security Compromises and Known Issues

This document tracks security compromises made during implementation, why they were made, and what the proper fix would be.

## 4. Self-signed TLS certificate

**What:** The agent generates a self-signed certificate on first startup and stores it in the config DB. The web UI retrieves it via `get_tls_config`. Browsers will show security warnings.

**Why:** A local router appliance has no domain name to get a real certificate from a CA. Self-signed is the standard approach for appliance web UIs.

**Risk:** Vulnerable to MITM on first connection (no TOFU mechanism). Users must manually trust the certificate.

**Proper fix:** Offer Let's Encrypt via DNS challenge for users with a domain. For LAN-only access, consider mDNS + a local CA root that users can install, or just document the self-signed approach as acceptable for the threat model.

**Note:** TLS cert generation moved from the web UI to the agent startup (`main.rs`). The self-signed nature is unchanged. The cert and private key are now stored in the config DB and served to the web UI via the `get_tls_config` IPC method — see issue #32.

## 9. Docker container mounts full /run/hermitshell directory

**What:** The web UI container mounts `-v /run/hermitshell:/run/hermitshell` (the entire directory) instead of just the socket file.

**Why:** File bind mounts go stale when the agent restarts and recreates the socket (new inode). Directory mounts survive this.

**Risk:** The container can see all files in `/run/hermitshell/`, not just the agent socket. If other sensitive files are placed there, the container has access.

**Mitigating factor:** The directory currently only contains Unix sockets. The container runs with `--network host` anyway, so isolation is already limited.

**Proper fix:** Acceptable as-is given the directory's contents. If sensitive files are added later, consider a dedicated socket subdirectory or use a named socket with inotify-based reconnection in the client.

## 11. Single admin account with no username

**What:** There is only one admin account. The session cookie payload is `admin:TIMESTAMP` with no configurable username.

**Why:** A home router typically has one administrator. Multi-user support was not in scope.

**Risk:** No audit trail for who performed actions. No way to revoke access for one user without rotating the shared secret.

**Proper fix:** Add per-user accounts if multi-admin is ever needed. For single-admin, this is acceptable for the threat model.

---

## Rate Limiting and Resource Exhaustion

---

## Untrusted Network Input

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

## 36. runZero API token stored in plaintext

**What:** The `runzero_token` config value (a runZero Export API token, XT-prefixed) is stored unencrypted in the SQLite config table, same as `wg_private_key`.

**Why:** The agent needs the token to authenticate with the runZero Export API on each sync cycle. There is no keyring or HSM available on a router appliance.

**Risk:** An attacker with filesystem access to the SQLite database can read the token and use it to query the runZero console's asset inventory. The token is read-only (Export API), so no data can be modified. The token is blocked from `get_config`/`set_config` IPC reads/writes and only accessible via the dedicated `set_runzero_config` method.

**Proper fix:** Encrypt secrets at rest using a key derived from a hardware identifier or TPM, if available. Alternatively, use short-lived OAuth tokens instead of long-lived Export API tokens.

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

## 48. Per-IP rate limit cache can be evicted by distributed attack

**What:** The web UI per-IP rate limiter uses an `LruCache` capped at 1,000 entries. An attacker with access to many source IPs (e.g., multiple compromised LAN devices) could flood the cache with new entries, evicting a previously tracked IP and resetting its backoff counter.

**Why:** Bounded caches are necessary to prevent unbounded memory growth. LRU eviction is a standard trade-off — it favors tracking recently active IPs, but allows old entries to be displaced.

**Risk:** Low. The agent-side rate limiter uses a global counter that is unaffected by web UI cache eviction. An attacker who evicts their IP from the web UI cache still hits the agent's exponential backoff on the next attempt. The web UI per-IP layer is a UX improvement (prevents one attacker from locking out other clients); the agent-side global limiter is the ultimate brute-force defense.

**Proper fix:** No fix needed — the two-layer design (per-IP web UI + global agent) provides defense in depth. If a stronger guarantee were desired, the web UI could use a larger cache or persist rate limit state to the agent's SQLite database.

---

## Multi-Mode Deployment

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

## Performance and Resource Management

## 72. HKDF with no salt for WiFi password encryption

**What:** The `derive_key` function in `crypto.rs` uses `Hkdf::<Sha256>::new(None, session_secret)` — HKDF-SHA256 with no salt to derive the AES-256 key for WiFi AP password encryption.

**Why:** The session_secret is already 32 bytes of cryptographically random data (generated via `rand::thread_rng()`). HKDF salt provides domain separation and defense against weak input keying material, but the input here is already high-entropy. Adding a salt would require a migration path for existing encrypted passwords, which are auto-generated random values the admin never sees — breaking decryption would make APs unmanageable with no recovery path.

**Risk:** Theoretical. With high-entropy input, unsalted HKDF produces output indistinguishable from random. The risk would only materialize if the session_secret generation were weakened to use a low-entropy source.

**Proper fix:** Acceptable as-is given the high-entropy input. If the session_secret generation ever changes to accept user-provided input, add a salt at that time with a versioned encryption prefix (e.g., `enc:v2:`) and migration.
