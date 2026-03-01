# Security Compromises and Known Issues

This document tracks security compromises made during implementation, why they were made, and what the proper fix would be.

## 4. Self-signed TLS certificate

**What:** The agent generates a self-signed certificate on first startup and stores it in the config DB. The web UI retrieves it via `get_tls_config`. Browsers will show security warnings.

**Why:** A local router appliance has no domain name to get a real certificate from a CA. Self-signed is the standard approach for appliance web UIs.

**Risk:** Vulnerable to MITM on first connection (no TOFU mechanism). Users must manually trust the certificate.

**Proper fix:** Let's Encrypt via ACME DNS-01 challenge is now available (Cloudflare provider). For LAN-only access without a domain, the self-signed cert remains the fallback.

**Note:** TLS cert generation moved from the web UI to the agent startup (`main.rs`). The self-signed nature is unchanged for the default mode. The cert and private key are now stored in the config DB and served to the web UI via the `get_tls_config` IPC method — see issue #32. Users with a domain can switch to ACME mode for a real CA-signed certificate.

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

## 29. DHCPv6 MAC resolution uses kernel neighbor cache

**What:** The DHCPv6 server resolves client MAC addresses by querying the kernel's IPv6 neighbor cache for the packet's source link-local address, rather than parsing DUID contents. This works for all DUID types (LLT, LL, EN, UUID).

**Why:** All DHCPv6 clients are L2-adjacent and have a link-local address learned via NDP before any DHCPv6 exchange. The kernel neighbor cache reliably maps link-local → MAC.

**Risk:** If the neighbor cache entry expires or is flushed between NDP and the DHCPv6 packet (extremely unlikely on the same L2 segment), the client will be rejected. It will retry and succeed on the next SOLICIT since NDP runs again.

## 30. IPv6 pinholes expose devices to inbound internet traffic

**What:** When an IPv6 pinhole is created, it adds a forwarding rule that accepts inbound traffic to the device's global IPv6 address on the specified port. Unlike IPv4 port forwarding (DNAT), which translates the destination address, IPv6 pinholes directly expose the device's real address to the internet.

**Why:** IPv6 does not use NAT. Each device has a globally routable address, and pinholes work by selectively allowing inbound traffic through the firewall to that address.

**Risk:** If the device has a vulnerability on the pinholed port, it is directly exploitable from the internet without any address translation layer. An attacker can connect directly to the device's global IPv6 address. Unlike IPv4 DNAT where the router terminates the connection and re-originates it, IPv6 pinhole traffic passes straight through to the device.

**Proper fix:** Warn the user in the web UI when creating a pinhole that the device will be directly reachable from the internet on the specified port. Consider adding rate limiting or geo-IP filtering options for pinholed ports. Log all inbound connections through pinholes for audit purposes.

## 31. WAN DHCP client trusts server responses

**What:** The in-agent DHCP client (`wan.rs`) processes DHCPv4 OFFER/ACK and DHCPv6 ADVERTISE/REPLY messages from the upstream DHCP server. It applies the offered IP address, subnet mask, gateway, and DNS servers directly to the WAN interface.

**Why:** DHCP inherently trusts the server on the network segment. The agent validates transaction IDs (`xid`) to match requests with responses, preventing replay of stale messages. The `dhcproto` crate handles protocol-level validation (option lengths, message format).

**Risk:** A rogue DHCP server on the WAN segment could provide a malicious gateway or DNS servers. This is the same risk as any DHCP client (including the replaced `dhclient`).

**Proper fix:** DHCP authentication (RFC 3118) is rarely deployed. In practice, the WAN segment is between the router and the ISP — if that's compromised, DHCP auth wouldn't help.

## 92. No DHCPRELEASE sent on agent shutdown

**What:** When the agent stops or the WAN lease expires, the IP is flushed from the interface but no DHCP RELEASE message is sent to the server.

**Why:** Implementing graceful shutdown signaling adds complexity. The DHCP protocol handles this — the server's own lease timer will reclaim the address.

**Risk:** The server holds the IP allocation until its timer expires, wasting addresses in the pool. No security impact.

**Proper fix:** Send DHCPRELEASE on `SIGTERM`/`SIGINT` before exiting. Low priority since ISP DHCP pools are large and leases expire naturally.

## 93. DHCPv6-PD prefix not independently renewed

**What:** The DHCPv6 delegated prefix is acquired once after DHCPv4 lease acquisition. It is re-acquired on full DORA restart but not independently renewed if its lifetime expires before the DHCPv4 lease.

**Why:** DHCPv6 prefix lifetimes are typically long (hours to days) and aligned with DHCPv4 lease times. Independent renewal adds significant complexity for a rare edge case.

**Risk:** If the prefix lifetime is shorter than the DHCPv4 lease, the stale prefix remains configured in the DB and advertised to LAN clients. IPv6 connectivity would break until the next DHCPv4 re-acquire.

**Proper fix:** Track prefix valid lifetime and run an independent DHCPv6 RENEW timer. Alternatively, re-run DHCPv6-PD after each DHCPv4 renewal.

---

## Config Key Protection

## 32. get_tls_config exposes the TLS private key over IPC

**What:** The `get_tls_config` IPC method returns both `tls_cert_pem` and `tls_key_pem` to the caller. The TLS private key crosses the Unix socket boundary.

**Why:** The web UI container terminates TLS (it binds ports 8080/8443 and handles HTTPS). It needs the private key to configure `rustls`. The agent generates and stores the cert, so the web UI must retrieve it at startup.

**Risk:** Any process with socket access can obtain the TLS private key. With the key, an attacker can impersonate the router's web UI or decrypt captured traffic. The socket is `0660` (see issue #49), so only root and group members can read the key.

**Mitigating factor:** The socket now enforces SO_PEERCRED method allowlists (see issue #90). `get_tls_config` is in the web-allowed set because the web UI container needs it at startup. The cert is self-signed, so impersonation is only meaningful if the user has already trusted it.

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

**Risk:** Low. The agent-side rate limiter uses a global counter that is unaffected by web UI cache eviction. An attacker who evicts their IP from the web UI cache still hits the agent's exponential backoff on the next attempt. The web UI per-IP layer is a UX improvement (prevents one attacker from locking out other clients); the agent-side global limiter is the ultimate brute-force defense. The web UI rate limiter now fails closed — if the client IP cannot be determined (missing `ConnectInfo`), the request is rejected with 403 instead of being allowed through.

**Proper fix:** No fix needed — the two-layer design (per-IP web UI + global agent) provides defense in depth. If a stronger guarantee were desired, the web UI could use a larger cache or persist rate limit state to the agent's SQLite database.

---

## Socket Access Control

## 90. SO_PEERCRED method allowlist grants broad access to non-root callers

**What:** The agent socket uses `SO_PEERCRED` (`peer_cred()`) to identify the UID of each connecting process. Root (UID 0) callers have unrestricted access. Non-root callers are restricted to a compile-time allowlist (`WEB_ALLOWED_METHODS`, ~80 methods). Methods not in the allowlist — `dhcp_discover`, `dhcp_provision`, `dhcp6_discover`, `dhcp6_provision`, `ingest_dns_logs` — return "access denied" for non-root callers.

**Why:** The web UI container runs as non-root and connects to the agent socket. It needs access to most methods (device management, config, status, WiFi, WireGuard, etc.) but should not be able to invoke DHCP provisioning or DNS log ingestion, which are internal IPC between the agent and its child processes.

**Risk:** The allowlist is permissive — non-root callers can still read secrets via `get_tls_config` and `export_config`, modify firewall rules, change DNS settings, and manage WireGuard peers. A compromised web UI container retains significant control over the router. The allowlist is deny-by-default for new methods (they must be explicitly added), which prevents accidental exposure of future admin-only methods.

**Mitigating factor:** The socket is `0660 root:root`, so only root and the web UI container (which has the socket bind-mounted) can connect. The `peer_cred()` check is kernel-enforced and unforgeable. Connections that fail `peer_cred()` are dropped immediately.

**Proper fix:** Further partition the allowlist into read-only and read-write tiers. Read-only methods (status, list) could be available to any socket caller, while write methods (set_config, add_port_forward) could require a session token or elevated credential. This would limit damage from a compromised read-only consumer.

## 91. DHCP IPC socket does not enforce SO_PEERCRED

**What:** The DHCP IPC socket (`/run/hermitshell/dhcp.sock`) does not perform peer credential checks. It relies solely on filesystem permissions (`0660 root:root`) for access control.

**Why:** The DHCP socket has a restricted dispatch table that only handles `dhcp_discover`, `dhcp_provision`, `dhcp6_discover`, and `dhcp6_provision`. Only the DHCP server process (running as root) connects to it.

**Risk:** Low. The filesystem permissions prevent non-root access, and the dispatch table limits what can be done even if access is gained. However, this lacks the defense-in-depth that `peer_cred()` provides on the main socket.

**Proper fix:** Add a `peer_cred()` check that only allows UID 0. Low priority given the restricted dispatch table and filesystem permissions.

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

**Mitigating factor:** The syslog format is now RFC 5424 compliant — SD-PARAMs are escaped to prevent log injection, message IDs and timestamps follow the spec. This prevents a crafted hostname or alert from breaking structured data fields in the collector.

**Proper fix:** Add TLS syslog (RFC 5425) as an option. Validate that the syslog target is on a local network segment, or warn when targeting WAN addresses.

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

**Risk:** If the backup file is compromised, an attacker gains all router credentials. The admin password hash (Argon2id) still requires cracking, but WireGuard keys, TLS keys, and API tokens are immediately usable. The `export_config` IPC method returns all secrets as cleartext JSON over the Unix socket when `include_secrets` is true and no passphrase is given. The method is in the web-allowed set (see issue #90), so non-root callers with socket access can reach it.

**Proper fix:** Always use `--encrypt` with a strong passphrase. The encrypted backup uses Argon2id key derivation (m=64MB, t=3) + AES-256-GCM, making brute-force impractical with a decent passphrase. Store backup files with restricted permissions (0600) and on encrypted storage. Consider requiring a passphrase for any export that includes secrets.

---

## Performance and Resource Management

## 72. HKDF with no salt for WiFi password encryption

**What:** The `derive_key` function in `crypto.rs` uses `Hkdf::<Sha256>::new(None, session_secret)` — HKDF-SHA256 with no salt to derive the AES-256 key for WiFi AP password encryption.

**Why:** The session_secret is already 32 bytes of cryptographically random data (generated via `rand::thread_rng()`). HKDF salt provides domain separation and defense against weak input keying material, but the input here is already high-entropy. Adding a salt would require a migration path for existing encrypted passwords, which are auto-generated random values the admin never sees — breaking decryption would make APs unmanageable with no recovery path.

**Risk:** Theoretical. With high-entropy input, unsalted HKDF produces output indistinguishable from random. The risk would only materialize if the session_secret generation were weakened to use a low-entropy source.

**Proper fix:** Acceptable as-is given the high-entropy input. If the session_secret generation ever changes to accept user-provided input, add a salt at that time with a versioned encryption prefix (e.g., `enc:v2:`) and migration.

---

## mDNS Proxy

## 73. mDNS proxy responds via unicast only (RFC 6762 §6.3 deviation)

**What:** The mDNS proxy always sends query responses via unicast to the querier, even when RFC 6762 Section 6.3 says responses to standard (non-QU) queries should be sent to the multicast group (224.0.0.251:5353).

**Why:** HermitShell isolates devices into groups (trusted, iot, servers, guest, quarantine, blocked). The mDNS proxy applies group-based filtering to response *content* — a guest device's query will never include trusted-only services. However, multicast responses are delivered by the kernel to *all* devices on the LAN interface regardless of group. Even though the payload is filtered, a passive listener could observe the multicast packet and learn that a query was answered, what service types exist, and for whom. This leaks metadata across isolation boundaries.

**Risk:** Queriers do not benefit from seeing other devices' cached responses (the standard rationale for multicast responses), since the proxy filters per-group anyway. The only loss is that RFC-conformant mDNS clients cannot passively populate their caches from overheard multicast responses — they must send their own queries.

**Proper fix:** None needed — this is an intentional privacy/isolation decision, not a compromise.

## 74. mDNS announcement attribution trusts IP-to-MAC mapping

**What:** `handle_announcement` resolves the UDP source IP to a device MAC via the DB, then stores service records under that MAC. The attribution relies on the source IP being correct.

**Why:** Per-device /32 isolation with nftables ensures each device can only send traffic from its assigned IP. IP spoofing at L3 is blocked by the firewall rules. There is no mDNS-layer authentication (mDNS is inherently unauthenticated).

**Risk:** Low. If a device could bypass nftables (e.g., via a kernel bug or misconfigured rule), it could spoof another device's IP and register fake services under that device's MAC. The mDNS proxy would then serve those fake services to queriers, potentially directing traffic to the attacker.

**Proper fix:** Acceptable given the nftables enforcement. For defense-in-depth, the proxy could cross-check the A record IP in announcements against the source IP — if a device announces services for an IP that isn't its own, drop the announcement.

## 75. Auto-classify bypasses quarantine based on device fingerprint

**What:** When `auto_classify_devices` is enabled, new devices are promoted from quarantine to "trusted" or "iot" based solely on runZero's `device_type` heuristic (OS fingerprinting, HTTP headers, etc.).

**Why:** Convenience. Manual classification of every device is tedious for home users. The toggle is off by default, requiring explicit opt-in.

**Risk:** An attacker can craft a device that fingerprints as a "laptop" or "phone" (matching the OS stack, open ports, and HTTP headers that runZero expects) and get automatically placed in the trusted group. This bypasses the quarantine review that would otherwise catch unauthorized devices.

**Proper fix:** Acceptable as opt-in. For stronger security, auto-classify could suggest a group in the UI without applying it (current behavior when the toggle is off). If auto-apply is desired, consider a confirmation period (e.g., device stays quarantined for 5 minutes, then auto-promotes if the classification is stable).

---

## UPnP/NAT-PMP/PCP

## 80. Trusted devices can create port forwards without admin approval

**What:** Devices in the "trusted" group can create NAT port forwarding rules via UPnP IGD, NAT-PMP, or PCP without admin intervention. Mappings are limited to 20 per device, 128 total, and expire after a maximum of 24 hours.

**Why:** UPnP/NAT-PMP protocols require automatic port mapping for gaming consoles, P2P clients, and VoIP applications to function behind NAT.

**Risk:** A compromised trusted device can expose internal services to the WAN by creating port forwards to its own IP. Secure mode prevents mapping to other devices' IPs, but a compromised device can forward to itself.

**Proper fix:** UPnP-UP (User Profile) authorization prompts per mapping request, allowing the admin to approve or deny each mapping individually.

## 81. UPnP SSDP and SOAP have no authentication

**What:** UPnP SSDP discovery and SOAP control endpoints have no authentication mechanism. Any device that can reach UDP 1900 or TCP 5000 can discover and control the gateway.

**Why:** The UPnP protocol design predates modern security concerns. Authentication was never part of the spec.

**Risk:** Mitigated by group filtering (only trusted devices receive SSDP responses and can use SOAP), secure mode (devices can only map to their own IP), and LAN-only binding (UPnP HTTP server listens on 10.0.0.1:5000 only).

**Proper fix:** UPnP-UP (User Profile) adds authorization to UPnP. Not widely supported by clients.

## 82. NAT-PMP/PCP use unauthenticated UDP

**What:** NAT-PMP and PCP use unauthenticated UDP on port 5351. The source IP in UDP packets is trivially spoofable on a shared LAN segment.

**Why:** Both protocols were designed for simplicity on trusted home networks. PCP added a MAP nonce for replay protection but no authentication.

**Risk:** An attacker on the LAN could craft UDP packets with a trusted device's source IP and create port mappings attributed to that device. The per-device /32 isolation and nftables source validation mitigate this — spoofed packets from incorrect source IPs are dropped by the firewall before reaching the NAT-PMP listener.

**Mitigating factor:** PCP now validates the client IP field in MAP requests against the UDP source address, returning `ADDRESS_MISMATCH` (result code 12) on mismatch. This prevents a PCP client from requesting mappings on behalf of a different IP. NAT-PMP has no equivalent field — it relies solely on the UDP source IP.

**Proper fix:** Cross-reference the UDP source IP against the device's ARP/NDP entry to verify the source MAC matches the expected device. This would catch IP spoofing even on the same L2 segment.

### UPnP permanent leases capped to 24 hours

- **What:** UPnP `AddPortMapping` with `NewLeaseDuration=0` (permanent) is capped to 86400 seconds (24 hours).
- **Why:** Permanent UPnP port mappings create indefinite attack surface. Clients that need persistent mappings renew periodically.
- **Risk:** Clients expecting truly permanent mappings lose them after 24 hours. Most UPnP clients renew every 20 minutes.
- **Proper fix:** None needed — this is an intentional security limit, not a compromise.

---

## MAC Spoofing Defense

## 83. Static ARP/NDP binding does not prevent same-MAC spoofing

**What:** Permanent ARP/NDP neighbor entries are added when devices are provisioned. This binds an IP address to a specific MAC address in the kernel's neighbor table.

**Why:** Prevents ARP cache poisoning attacks where a malicious device sends gratuitous ARP to claim another device's IP. Also prevents IP spoofing without MAC spoofing.

**Risk:** If an attacker spoofs the real device's MAC address, the static neighbor entry matches the spoofed MAC — no protection. This defense prevents IP-only attacks, not full MAC+IP spoofing.

**Proper fix:** 802.1X or per-device PSK for cryptographic device identity. The static binding is defense-in-depth alongside MAC-IP validation (issue #84) and DHCP fingerprinting (issue #85).

## 84. nftables MAC-IP validation trusts the Ethernet source address

**What:** The `mac_ip_validate` chain drops forwarded packets where `ip saddr` matches a known device but `ether saddr` does not match the expected MAC. This validates that traffic from a device's assigned IP comes from the correct MAC.

**Why:** Prevents an attacker from using their own MAC while spoofing a trusted device's IP address. Also catches accidental IP conflicts.

**Risk:** An attacker who spoofs both the MAC and IP of a trusted device bypasses this check (both match). The `ether saddr` field is set by the sending device and can be forged. On WiFi, the AP bridges frames to the router — the Ethernet source MAC seen by nftables is the WiFi client's MAC, which the client controls.

**Proper fix:** Per-device PSK (PPSK) or 802.1X binds identity to a cryptographic secret rather than a spoofable MAC. DHCP fingerprinting (issue #85) provides an additional heuristic layer.

## 85. DHCP fingerprint change detection is heuristic

**What:** The analyzer compares each device's DHCP fingerprint (Option 55 Parameter Request List) against a stored baseline. A change fires a "dhcp_fingerprint_change" alert.

**Why:** Different operating systems and device types produce distinctly different Option 55 values. When a "known" MAC reconnects with a different OS fingerprint, it strongly suggests device impersonation.

**Risk:** Same-OS spoofing (e.g., one Linux laptop spoofing another) produces identical fingerprints and evades detection. DHCP fingerprints can be forged — an attacker who knows the target's fingerprint can replay it. Detection is after the fact (alert, not prevention).

**Proper fix:** Acceptable as defense-in-depth. Combine with MAC-IP validation (preventive) and consider TCP/IP stack fingerprinting (p0f) for deeper behavioral analysis.

---

## WiFi AP TLS

## 76. TOFU first connection is unauthenticated

**What:** When no CA cert is pinned for a WiFi AP, the first connection performs a bare TLS handshake with `danger_accept_invalid_certs(true)` to grab the AP's leaf certificate. This initial handshake accepts any certificate without verification.

**Why:** The AP uses a self-signed certificate with no pre-shared CA. There is no out-of-band channel to obtain the cert before connecting. TOFU is the standard solution for this bootstrap problem (same model as SSH `known_hosts`).

**Risk:** An attacker on the local network at adoption time could MITM the first connection and present their own certificate, which would be pinned as trusted. All subsequent connections would then verify against the attacker's cert, not the real AP's cert. The attacker would need sustained MITM to exploit this (they must proxy every future connection).

**Proper fix:** Acceptable for the threat model — AP adoption happens on a physically controlled local network. For higher assurance, the admin can upload a CA cert manually before the first connection, bypassing TOFU entirely. An out-of-band verification step (e.g., displaying the cert fingerprint in the AP's web UI for manual confirmation) would close this gap but adds friction.

## 77. Hostname verification bypassed for WiFi AP connections

**What:** Both the rustls `CaOnlyVerifier` and the native-tls builder use `danger_accept_invalid_hostnames(true)`, skipping hostname/SAN verification when connecting to APs.

**Why:** APs are accessed by IP address, not hostname. Self-signed AP certificates never include the correct IP in the Subject Alternative Name field. Hostname verification would reject every AP connection.

**Risk:** If an attacker can redirect traffic for the AP's IP address (e.g., ARP spoofing) and possesses a certificate signed by the same CA (or the same self-signed cert), they can MITM the connection without triggering a hostname mismatch error. In practice, TOFU leaf-cert pinning mitigates this — the attacker would need the exact pinned certificate's private key, not just any cert from the same CA.

**Proper fix:** Acceptable given TOFU pinning. Leaf-cert pinning is strictly more restrictive than hostname verification (only the exact cert is accepted, not any cert with the right hostname). If APs ever support configurable SANs, hostname verification could be re-enabled.

## 78. AP cert rotation breaks TOFU pin

**What:** If a WiFi AP regenerates its TLS certificate (firmware update, factory reset, manual cert change), subsequent connections fail because the new cert does not match the pinned `ca_cert_pem`.

**Why:** This is the intended security behavior — rejecting unexpected cert changes is the whole point of pinning. Silent acceptance of new certs would defeat TOFU.

**Risk:** Operational disruption, not a security risk. The admin must clear the pinned cert (`wifi_set_ap_ca_cert` with empty value) to re-trigger TOFU. If the admin does not realize the cert changed, AP management will fail silently until the pin is cleared. The agent logs the verification failure, but there is no push notification to the admin.

**Proper fix:** Add an alert when AP connection fails due to cert verification (distinct from network unreachable). The web UI could surface this as "AP certificate changed — re-pin?" with a one-click action. This preserves security (admin must explicitly accept the new cert) while improving discoverability.

## 79. Two TLS handshakes for legacy AP cipher negotiation

**What:** `build_verified_client()` first attempts a rustls connection (modern ciphers only), and on failure falls back to native-tls (OpenSSL, supports legacy ciphers). APs with legacy TLS (1024-bit RSA, TLS_RSA_WITH_* suites) trigger two full TLS handshakes per connection.

**Why:** Rustls intentionally excludes weak cipher suites for security. IoT devices like the EAP720 may only support legacy ciphers. The probe-and-fallback approach uses the strongest available TLS without requiring the admin to know their AP's cipher support.

**Risk:** The failed rustls handshake exposes a partial TLS connection to the network (ClientHello + server response). An observer learns that a connection attempt was made. The credential (MD5 password hash) is only sent after the successful handshake, so it is not exposed by the failed attempt. The doubled connection time (~200ms extra) is negligible for a 60-second polling cycle.

**Proper fix:** Cache the TLS backend choice per AP after the first successful connection (e.g., a `tls_backend` column: "rustls" or "native"). Skip the probe on subsequent connections. This eliminates the extra handshake after the first poll cycle.

---

## Software Updates

## 86. Update binaries downloaded without signature verification

**What:** `apply_update` downloads release tarballs from GitHub and verifies them via SHA256 checksum. There is no GPG signature verification. The checksum is fetched alongside the tarball from the same origin.

**Why:** The checksum verifies download integrity but not authenticity — an attacker who compromises the GitHub release could publish a malicious tarball with a matching checksum. This is the same trust model as the `install.sh` script and most projects that distribute via GitHub releases (OpenWrt, OPNsense).

**Risk:** Medium. Requires compromising the GitHub repo or performing a MITM on the HTTPS connection to github.com (TLS protects against the latter). If successful, an attacker gets code execution as root on the router.

**Proper fix:** GPG-sign releases with a project key. Embed the public key in the agent binary and verify the detached signature before extracting.

## 87. Auto-update installs new code without admin interaction

**What:** When `auto_update_enabled` is true, the agent downloads and installs new releases automatically when discovered by the update checker.

**Why:** Convenience for users who prefer hands-off maintenance. Opt-in, disabled by default.

**Risk:** Combined with #86 (no signature verification), a compromised release would be auto-installed without the admin seeing a notification first. The rollback mechanism catches crashes but not deliberately malicious code that runs successfully.

**Proper fix:** Acceptable as opt-in. Signature verification (#86) is the proper mitigation.

## 88. Rollback restores binaries but does not verify them

**What:** When the agent crashes after an update, `rollback.sh` copies binaries from `/opt/hermitshell/rollback/` back to the install directory. It does not verify the integrity of the rollback binaries.

**Why:** The rollback directory is populated by the agent itself immediately before the update swap. The binaries are the same ones that were running moments earlier. Verifying them would require a checksum stored somewhere — but the update process runs as root, so an attacker who can tamper with the rollback directory already has root access.

**Risk:** Low. An attacker with root access could replace the rollback binaries with malicious ones, then trigger a failed update to get them installed. But root access already means full compromise.

**Proper fix:** Store a SHA256 manifest of the rollback binaries and verify before restoring. Marginal benefit given the root-only threat model.

## 89. Staged restart has a fixed 2-second sleep between UI and agent restart

**What:** `trigger_staged_restart` restarts `hermitshell-ui` first, waits 2 seconds, then restarts `hermitshell-agent`. During the 2-second window, the old agent is still running with new UI binaries.

**Why:** The UI container needs a moment to come up before the agent restarts. Polling `systemctl is-active` would be more robust but adds complexity. The nftables ruleset and routing are kernel-resident and unaffected by the restart, so network connectivity is maintained throughout.

**Risk:** Low. During the 2-second window, a request to the new UI could reach the old agent. Since the API is backwards-compatible between adjacent versions, this is unlikely to cause issues. If the UI restart fails, the agent still restarts, which the rollback script handles.

**Proper fix:** Poll `systemctl is-active hermitshell-ui` instead of sleeping, with a timeout.

---

## DNS / Unbound

## 92. Blocklist downloads allow HTTP (no integrity verification)

**What:** `http_download()` in `unbound.rs` accepts both HTTP and HTTPS blocklist URLs. HTTP downloads use raw TCP with no TLS. Downloaded content is written directly to Unbound config files with no checksum or signature verification.

**Why:** Some blocklist providers only serve HTTP. Supporting both maximizes compatibility with third-party lists.

**Risk:** Medium. A MITM attacker can intercept HTTP blocklist downloads and inject entries — either blocking legitimate domains (DoS) or removing blocked domains (filter bypass). The poisoned entries are written to `/var/lib/hermitshell/unbound/blocklists/*.conf` and loaded by Unbound on reload.

**Proper fix:** Enforce HTTPS-only for blocklist URLs. Add optional SHA256 checksum verification (store expected hash in DB alongside URL).

## 95. Hardcoded DoH resolver IPs may go stale

**What:** `DOH_RESOLVER_IPS_V4` contains 14 static IPs for well-known DoH providers. New providers or IP changes are not reflected without an agent update.

**Why:** Hardcoding avoids external dependencies and provides a fail-closed default.

**Risk:** Low-medium. If a provider changes IPs, the old IPs remain in the block set (harmless) but the new IPs are not blocked (bypass). New DoH services that emerge after the release are not blocked at all.

**Proper fix:** Make the IP list admin-configurable via DB. Provide a built-in default that can be updated via the update checker.

## 96. Unbound runs as root (no privilege drop)

**What:** Unbound is configured with `username: ""` so it does not drop privileges after startup. It inherits the agent's root UID and runs inside the same systemd sandbox (`ProtectSystem=strict`, `PrivateTmp`, restricted `CapabilityBoundingSet`).

**Why:** The systemd unit restricts capabilities to `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_NET_BIND_SERVICE`. Unbound needs `CAP_SETUID`/`CAP_SETGID`/`CAP_CHOWN` to drop privileges, which are not available. Running as root inside the sandbox avoids permission issues between the agent (writes config) and Unbound (writes logs, query log, trust anchor).

**Risk:** Low-medium. An Unbound RCE vulnerability would grant the attacker root within the systemd sandbox (restricted file access, no new privileges, limited capabilities). The blast radius is smaller than full root due to `ProtectSystem=strict` and `ReadWritePaths` restrictions.

**Proper fix:** Run Unbound as a dedicated non-root user. Add `CAP_SETUID CAP_SETGID CAP_CHOWN` to the capability bounding set so Unbound can drop privileges. Use a shared group for the config directory.

## 98. DNSSEC trust anchor copied to agent-owned directory

**What:** The agent copies `/var/lib/unbound/root.key` to `/var/lib/hermitshell/unbound/root.key` at config write time. Unbound's `auto-trust-anchor-file` points to the copy, not the system original.

**Why:** Unbound updates the trust anchor by creating temp files (`root.key.<pid>-<seq>-<hash>`) in the same directory. The system copy lives in `/var/lib/unbound/`, owned by the `unbound` user. AppArmor's `owner` qualifier on that path blocks root-owned Unbound from writing there. Copying to the agent's data directory (`/var/lib/hermitshell/unbound/`) sidesteps the AppArmor restriction because the agent's AppArmor local override grants `rw` without the `owner` qualifier.

**Risk:** Low. The trust anchor is public data (IANA root zone KSK). The copy drifts from the system copy over time as Unbound updates it independently, but both copies track the same IANA root key via RFC 5011 automated updates. If the system copy is updated by `unbound-anchor` (e.g., via a package upgrade), the agent's copy is not refreshed until the agent restarts and `write_config()` runs again — but only if the agent's copy is deleted first (the copy is skipped if the file already exists).

**Proper fix:** Run Unbound as the `unbound` user so it can write to `/var/lib/unbound/` natively. This eliminates the copy entirely. Requires `CAP_SETUID`/`CAP_SETGID` in the capability bounding set.

## 99. Unbound control socket disabled; reload via SIGHUP

**What:** The agent sets `control-enable: no` in the Unbound config and reloads Unbound by sending `SIGHUP` to the child process instead of using `unbound-control reload`.

**Why:** `unbound-control` requires a control socket (`/run/unbound.ctl`), which Unbound creates with `chown` to match its configured user. Inside the systemd sandbox, `CAP_CHOWN` is not available, so socket creation fails. SIGHUP achieves the same config reload without any control socket or extra capabilities.

**Risk:** Low. SIGHUP reload is documented Unbound behavior. The tradeoff is that the agent cannot use `unbound-control` for runtime queries (cache stats, cache dump, flush). These features are not currently used. If the child PID is stale (Unbound crashed and was not reaped), the SIGHUP would be sent to a nonexistent or wrong process — but `process_group(0)` isolation and the agent's `Child` handle prevent this.

**Proper fix:** Acceptable as-is. If `unbound-control` features are needed later, add `CAP_CHOWN` to the capability bounding set and re-enable the control socket.

## 100. DNS rebinding protection blocks private answers from upstream resolvers

**What:** Unbound is configured with `private-address` directives for all RFC1918, link-local, loopback, and ULA ranges. This causes Unbound to refuse upstream DNS responses that resolve external domain names to private IP addresses (NXDOMAIN instead of the real answer).

**Why:** DNS rebinding attacks work by pointing an attacker-controlled domain at a private IP (e.g., `evil.com → 10.0.0.1`). A browser that resolved `evil.com` would then make same-origin requests to the router's LAN address. The `private-address` directives block this class of attack.

**Risk:** The catch-all upstream forwarder (the `upstream_dns` config) cannot return private IPs. If an ISP or public resolver returns RFC1918 addresses (rare but not impossible), those answers are blocked. Forward zones configured by the admin are automatically exempted via `private-domain` directives, so split-horizon DNS (e.g., `corp.internal → 10.1.1.1`) works as expected. Custom rules (`local-data`) are unaffected because they are local, not forwarded.

**Proper fix:** Acceptable as-is. The only unprotected case is a user who configures `upstream_dns` to point at a private DNS server that returns RFC1918 answers for the root zone (`.`). This is uncommon and can be worked around by adding a forward zone for the specific domain instead of using the catch-all upstream.

## 97. Blocklist file permissions not restricted

**What:** Files under `/var/lib/hermitshell/unbound/blocklists/` are written with default permissions (typically 0644). No explicit `chmod` is applied.

**Why:** The files are non-secret config data in a root-owned directory.

**Risk:** Low-medium. World-readable blocklists reveal which domains are filtered. If directory permissions are misconfigured, a non-root user could write malicious blocklist files.

**Proper fix:** Set file permissions to 0640 at write time. Verify parent directory is 0750 or more restrictive.

## 101. Session secret and HMAC key generated with thread_rng

**What:** The one-time session secret (`main.rs`) and per-password HMAC signing key (`socket/auth.rs`) are generated with `rand::thread_rng()` instead of `rand::rngs::OsRng`. Password hashing (Argon2 salt) correctly uses `OsRng`.

**Why:** `thread_rng()` is the default convenience RNG in the `rand` crate. It is seeded from OS entropy and is cryptographically secure in practice, but the seeding happens once per thread and the CSPRNG state lives in userspace afterward.

**Risk:** Low. If the userspace CSPRNG state were somehow leaked or the initial seeding were weak, all session tokens signed with that key could be forged. In practice this is unlikely on modern Linux with a healthy entropy pool.

**Proper fix:** Replace `rand::thread_rng()` with `rand::rngs::OsRng` for the two call sites that generate cryptographic key material. The operations run once (secret generation) or rarely (password change), so performance is irrelevant.

## 102. Tarball extraction does not reject symlinks

**What:** The update installer (`update.rs`) validates that tarball entry paths have no absolute components or `..` segments, then calls `entry.unpack_in(staging)`. It does not check whether an entry is a symlink.

**Why:** The `tar` crate's `unpack_in` resolves symlinks relative to the target directory, which mitigates simple escapes. The path traversal check catches the most common attack vector.

**Risk:** Low. A crafted tarball could include a symlink entry pointing to an arbitrary path (e.g., `link → /etc/shadow`), then a subsequent regular entry with the same name that overwrites the symlink target. However, the tarball must already be compromised to contain such entries, and unsigned tarballs are already documented as issue #86.

**Proper fix:** Skip or reject entries where `entry.header().entry_type()` is `Symlink` or `Link`. Alternatively, use `tar::Archive::set_preserve_permissions(false)` and manually filter entry types before unpacking.

## 103. Update version tag stored in DB before validation

**What:** The `check_for_update` function stores the raw `tag_name` string from the GitHub Releases API into the config DB (`update_latest_version`) at line 82 of `update.rs`. The `validate_version()` check only runs later, during `apply_update`, at line 146.

**Why:** The check loop and apply logic are separate code paths. The check loop stores the version for the web UI to display; the apply path validates it before downloading.

**Risk:** Low. A compromised or spoofed GitHub API response could inject an arbitrary string into `update_latest_version`, which is displayed in the web UI. Leptos auto-escapes HTML output, preventing XSS. The string cannot cause code execution because `validate_version()` gates the download path.

**Proper fix:** Call `validate_version()` in `check_for_update` before storing the tag. Reject tags that don't match the expected `v\d+\.\d+\.\d+` pattern.

## 104. DHCP transaction IDs use thread_rng

**What:** The WAN DHCP client (`wan.rs`) generates DHCPv4 and DHCPv6 transaction IDs (xid) with `rand::thread_rng()` instead of `OsRng`.

**Why:** Same convenience pattern as issue #101. Transaction IDs are 32-bit values used to match requests to responses, not long-lived secrets.

**Risk:** Very low. An attacker on the WAN segment who can observe DHCP requests and predict XIDs could inject forged DHCP responses. This requires Layer 2 adjacency to the WAN interface. The `rand` crate's `thread_rng` is cryptographically secure in practice.

**Proper fix:** Use `OsRng` for XID generation to comply with RFC 2131 guidance on strong randomness. The cost is negligible (one syscall per DHCP transaction).

---

## Post-Wizard Settings

## 105. Interface and WAN config changes are DB-only with no live apply

**What:** `update_interfaces` and `update_wan_config` write the new values to the config DB but do not reconfigure the running system. The `wan_iface` and `lan_iface` are read once at agent startup (`main.rs:347-357`) and passed as owned strings to nftables, DHCP, QoS, WAN client, port forwarding, RA sender, mDNS, and UPnP. After a change, the DB says one thing while every subsystem uses the old values.

**Why:** Live interface swaps require tearing down and rebuilding nftables rules, restarting the DHCP server, rebinding the WAN client, reconfiguring QoS, and updating every subsystem that holds a copy of the interface name. This is complex and error-prone to do atomically. The wizard versions had the same limitation but it was masked by the fact that the agent had not yet started its main loop when those values were set.

**Risk:** The admin changes interfaces or WAN mode in the UI, gets a success message, but the router continues operating on the old config. No indication that a restart is needed. If the admin does not restart the agent, the firewall rules, NAT, DHCP, and QoS are all mismatched with the DB — a split-brain state that could cause traffic to be routed incorrectly or firewall rules to apply to the wrong interface.

**Proper fix:** Either (a) trigger an agent restart after interface/WAN config changes and display a "restarting..." banner in the UI, or (b) refactor subsystems to accept interface names via `Arc<RwLock<String>>` so they can be updated at runtime. Option (a) is simpler and sufficient.

## 106. update_wan_config has partial write on validation failure

**What:** `handle_update_wan_config` stores `wan_mode` in the DB (line 395) before validating the static IP fields (lines 400-425). If the mode is set to "static" and the gateway or DNS validation fails, the DB is left with `wan_mode=static` but potentially stale or missing `wan_static_gateway` / `wan_static_dns` values from a prior configuration.

**Why:** The wizard version (`handle_setup_wan_config`) has the same bug. The post-wizard version was copied from it.

**Risk:** Low. On the next agent restart, the WAN client reads `wan_mode=static` and attempts to configure the interface with whatever static fields are in the DB. If the gateway is missing or stale, WAN connectivity fails. The admin would need to re-submit a valid static config or switch back to DHCP.

**Proper fix:** Validate all fields before writing any of them to the DB. Collect the validated values into local variables first, then write them all in a batch. This applies to both the wizard and post-wizard versions.

## 108. REST API serves plaintext HTTP on localhost

**What:** The REST API (`/api/v1/*`) listens on `127.0.0.1:9080` using plaintext HTTP. It is only reachable from the router itself (e.g., web UI container, hermitctl CLI). API keys are transmitted in the `Authorization: Bearer` header.

**Why:** The REST API binds to localhost only, so it is not exposed to the LAN or WAN. The web UI container (on the same host) can proxy to it over HTTPS. Adding direct TLS would duplicate the web UI's cert management.

**Risk:** A process on the router host with network access to localhost can reach the API. Since the router runs only trusted agent and container processes, this is acceptable. If the router is compromised at the process level, the attacker already has access to the Unix socket and DB file.

**Proper fix:** Add TLS to the REST API for defense-in-depth, or front it with the web UI's HTTPS reverse proxy for external access.

## 107. Post-wizard interface change can lock out the admin

**What:** The wizard's `handle_set_interfaces` can only run before a password is set — meaning before the admin has a management session and before real traffic flows. The post-wizard `handle_update_interfaces` has no such guard. An admin can swap WAN and LAN assignments on a live router.

**Why:** The whole point of the post-wizard settings is to allow reconfiguration after setup. Blocking interface changes would defeat the purpose.

**Risk:** If the admin swaps WAN and LAN (or assigns the management interface as WAN), the next agent restart applies the new assignment. The firewall rules flip, the DHCP server binds to the wrong interface, and the admin's management connection drops. Recovery requires console access or physical presence to fix the config DB.

**Proper fix:** Display a confirmation warning in the UI when the new interface assignment differs from the current running config: "Changing interfaces requires an agent restart. You may lose management access if your current connection is on the interface being reassigned. Continue?" Consider a watchdog timer that reverts the change if the admin does not confirm via a second request within 60 seconds (similar to display resolution change dialogs).

---

## NixOS Flake

## 108. NixOS web UI service runs natively without Docker isolation

**What:** The NixOS module runs `hermitshell-ui` as a native systemd service under the `hermitshell` user, not inside a Docker container. The upstream Debian/Ubuntu deployment uses Docker with `--cap-drop ALL --read-only --security-opt no-new-privileges`.

**Why:** NixOS deployments avoid Docker when possible. The NixOS module uses systemd hardening directives that provide equivalent restrictions: `CapabilityBoundingSet = [""]` (no capabilities), `ProtectSystem = "strict"`, `NoNewPrivileges`, `MemoryDenyWriteExecute`, namespace/device/syscall restrictions.

**Risk:** Low. The systemd hardening profile is stricter than Docker's default seccomp in some areas (explicit syscall filter, kernel protection directives) and equivalent in others (capability drop, read-only filesystem). The web UI runs as a non-root user with no capabilities, so a vulnerability would grant limited access within the sandbox.

**Proper fix:** Acceptable as-is. The systemd hardening matches or exceeds the Docker container's security posture.

## 109. NixOS test mode bypasses systemd hardening

**What:** The `nix` deploy mode in `tests/lib/deploy.sh` spawns the agent with bare `setsid` instead of through the NixOS module's systemd unit. The agent runs as root without capability bounding, syscall filters, or filesystem restrictions.

**Why:** Tests need to restart the agent after redeployment without configuring the full NixOS module in the VM. The test provisioner installs packages but does not enable `services.hermitshell`.

**Risk:** Low (test-only). Production NixOS deployments use the module's systemd units with full hardening. The test gap means systemd-level hardening is not exercised in the NixOS test path, but it is tested indirectly via the `direct` and `install` modes on Debian.

**Proper fix:** Acceptable for test infrastructure. If NixOS-specific systemd hardening needs testing, add a test case that enables the module and verifies the service starts with the expected restrictions.

