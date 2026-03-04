# HermitShell Threat Model

This document describes the assets HermitShell protects, the adversaries it defends against, the trust boundaries in its architecture, the attack surfaces exposed, the security controls at each boundary, and the risks explicitly accepted.

## 1. Assets

### 1.1 Network Traffic

All traffic transiting the router — LAN-to-WAN, LAN-to-LAN (inter-device), and VPN tunnels. Compromise allows eavesdropping, injection, or redirection of any connected device's communications.

### 1.2 Admin Credentials and Session Material

- Admin password hash (Argon2id) in SQLite
- HMAC session secret (32 bytes, generated at first boot)
- REST API key hash
- Stateless HMAC session tokens (8-hour absolute expiry)

Compromise allows full administrative control of the router.

### 1.3 Cryptographic Keys

- TLS private key (self-signed, ACME, Tailscale, or custom)
- WireGuard interface private key
- WireGuard peer pre-shared keys
- ACME account private key
- WiFi AP password encryption key (derived from session secret via HKDF-SHA256)

Compromise allows traffic decryption, VPN impersonation, or AP takeover.

### 1.4 Third-Party API Tokens

- Cloudflare API token (DNS zone write access for ACME DNS-01)
- runZero Export API token (read-only asset inventory)
- Webhook secret

Stored in plaintext in the SQLite config table. Blocked from `get_config`/`set_config` IPC reads and writes.

### 1.5 Device Configuration and State

- Per-device group assignments (trusted, iot, guest, servers, quarantine, blocked)
- DHCP reservations, DNS custom records, forward zones, blocklists
- Port forwarding rules, IPv6 pinholes, UPnP/NAT-PMP mappings
- QoS profiles and bandwidth history
- Behavioral analysis alerts and audit logs
- WiFi AP provider credentials and SSID configurations

### 1.6 DNS Query Logs

Query logs from Unbound reveal browsing activity for every device on the network. Exported via syslog (UDP, unencrypted — [security overview](security.md), SECURITY.md #53).

---

## 2. Adversaries

### 2.1 Malicious LAN Device (Compromised IoT / Guest)

**Capability:** Layer 2 adjacency on the LAN bridge. Can send arbitrary Ethernet frames, ARP, mDNS, SSDP, DHCPv4/v6, and IPv6 Router Advertisements. Cannot (should not) reach the Unix socket or SQLite database.

**Goal:** Escape device isolation group, pivot to other LAN devices, exfiltrate data via DNS tunneling, spoof trusted devices, or create unauthorized port forwards.

**Mitigated by:** Per-device /32 nftables isolation, group-based forwarding chains, MAC-IP validation (#84), static ARP/NDP binding (#83), DHCP fingerprint change detection (#85), UPnP group filtering (#81), mDNS group filtering (#73).

### 2.2 WAN Attacker (Remote / Internet)

**Capability:** Can reach any port exposed on the WAN interface. Cannot reach LAN-only services (Unix socket, UPnP HTTP, mDNS) unless a port forward or pinhole exists.

**Goal:** Compromise the router for botnet recruitment, pivot into the LAN, intercept traffic, or degrade service (DDoS).

**Mitigated by:** nftables WAN input chain (drop all unsolicited inbound by default), WireGuard listen port (authenticated), HTTPS web UI with rate-limited login, stateful connection tracking, DNS rebinding protection (#100).

### 2.3 Compromised Web UI Container

**Capability:** Non-root process with Unix socket access. Has ~100 IPC methods in `WEB_ALLOWED_METHODS`. Can read TLS private key (`get_tls_config`), export full config (`export_config`), modify firewall rules, manage WireGuard peers, and apply declarative config including secrets.

**Goal:** Escalate to full router control (already has significant control via the allowlist), exfiltrate secrets, or persist access.

**Mitigated by:** Docker `--cap-drop ALL --read-only --security-opt no-new-privileges` (standalone mode), SO_PEERCRED method allowlist (#90), DHCP/DNS-log methods excluded from web-allowed set. The allowlist is acknowledged as permissive (#90).

### 2.4 Physical Attacker

**Capability:** Console access, USB boot, hard drive removal. Can read the SQLite database file directly, modify binaries, or replace the boot environment.

**Goal:** Extract secrets, install persistent backdoor, or take over the network.

**Mitigated by:** Limited — secrets at rest are not encrypted (#36, #51, #52). Physical access is considered full compromise. The setup wizard's unauthenticated window (#60) is only exploitable at first boot, which assumes physical control.

### 2.5 Supply Chain Attacker

**Capability:** Compromise of the GitHub repository, CI/CD pipeline, or release artifacts. Can inject malicious code into release tarballs.

**Goal:** Code execution as root on all routers that update.

**Mitigated by:** HTTPS for GitHub API and downloads. SHA256 checksum verification on tarballs (integrity, not authenticity). **No GPG signature verification** (#86). Auto-update amplifies this risk (#87). Tarball extraction does not reject symlinks (#102).

### 2.6 Rogue DHCP Server (WAN Segment)

**Capability:** Layer 2 adjacency on the WAN segment (between router and ISP).

**Goal:** Provide malicious gateway/DNS to redirect all traffic.

**Mitigated by:** Transaction ID matching (`xid`), `dhcproto` protocol validation. DHCP inherently trusts the server — this is accepted risk (#31).

---

## 3. Trust Boundaries

### 3.1 Unix Socket Boundary

**Boundary:** `/run/hermitshell/agent.sock` (permissions `0660 root:root`)

**Crosses:** IPC requests from web UI container, hermitctl CLI, DHCP process.

**Controls:**
- Filesystem permissions: only root and group members can connect
- `SO_PEERCRED` (kernel-enforced UID check): root gets unrestricted access; non-root gets `WEB_ALLOWED_METHODS` allowlist (~100 methods)
- `BLOCKED_CONFIG_KEYS`: 14 secret keys excluded from `get_config`/`set_config`
- Input validation: MAC, IP, interface name, group, hostname validation on all mutating methods
- Concurrency: `Semaphore` limits concurrent connections

**Residual risk:** The web-allowed set is broad (#90). `apply_config` bypasses `BLOCKED_CONFIG_KEYS` (#110).

### 3.2 nftables Firewall Boundary

**Boundary:** Kernel netfilter ruleset managed by the agent.

**Crosses:** All network traffic between WAN, LAN, VPN, and the router itself.

**Controls:**
- Per-device /32 isolation (each device can only reach its gateway, not other devices, unless group policy allows)
- Group-based forwarding chains (trusted, iot, guest, servers, quarantine, blocked)
- MAC-IP source validation chain (`mac_ip_validate`)
- Static ARP/NDP neighbor entries
- RA Guard (ICMPv6 type 134 drop in forward chain)
- WAN input: drop all unsolicited, allow established/related
- DoH IP blocking (14 hardcoded resolver IPs)
- DNS redirect: force all DNS through Unbound on the router
- Conntrack-based stateful inspection

**Residual risk:** RA Guard at L3 only (#28), MAC-IP validation trusts Ethernet source (#84), static ARP does not prevent same-MAC spoofing (#83).

### 3.3 Docker Container Boundary

**Boundary:** Web UI runs in a Docker container with restricted capabilities.

**Standalone mode controls:**
- `--cap-drop ALL` (no Linux capabilities)
- `--read-only` filesystem
- `--security-opt no-new-privileges`
- Non-root user (UID 1000)
- `--network host` (no network namespace isolation — required for LAN-facing HTTPS)

**All-in-one mode:** `--privileged` — effectively no container isolation (#50). Intended for testing only.

**Residual risk:** `--network host` means the container shares the host's network stack. The `/run/hermitshell` directory mount exposes all files in that directory (#9).

### 3.4 Web UI Authentication Boundary

**Boundary:** HTTPS endpoints on ports 80 (redirect) and 443.

**Controls:**
- Argon2id password hashing (m=19MiB, t=2, p=1)
- Stateless HMAC session tokens with 8-hour absolute expiry
- Exponential backoff rate limiting: per-IP in web UI (LRU cache, 1000 entries) + global in agent
- Rate limiter fails closed (missing `ConnectInfo` returns 403)
- HTTPS with TLS (self-signed, ACME, Tailscale, or custom cert)
- Leptos SSR-only (no WASM) — eliminates client-side XSS vectors from hydration
- Default HTML escaping in Leptos templates

**Residual risk:** Sessions cannot be individually revoked (#40). Rate limit state is in-memory only (#41). Per-IP cache can be evicted (#48). Self-signed cert vulnerable to MITM on first connection (#4).

### 3.5 REST API Boundary

**Boundary:** `127.0.0.1:9080` (localhost only, plaintext HTTP).

**Controls:**
- Bearer token authentication (API key verified via Argon2)
- Localhost binding (not reachable from LAN/WAN)
- Secrets excluded from config export via REST

**Residual risk:** No rate limiting on authentication (#115). Plaintext HTTP on localhost (#108).

---

## 4. Attack Surfaces

### 4.1 Web UI (HTTPS, Ports 80/443)

**Exposure:** LAN and optionally WAN (if port forwarded).

**Protocol:** HTTPS (TLS 1.2+).

**Threats:** Brute-force login, session hijacking, CSRF (mitigated by SameSite cookies and ActionForm), XSS (mitigated by SSR-only + Leptos escaping), MITM (self-signed cert first-connection risk).

### 4.2 DNS (Unbound, Port 53)

**Exposure:** LAN only (nftables redirects all DNS to router).

**Protocol:** DNS over UDP/TCP port 53.

**Threats:** DNS cache poisoning (mitigated by DNSSEC + upstream DoT/DoH), DNS tunneling for data exfiltration, DNS rebinding attacks (mitigated by `private-address` directives, #100). Blocklist downloads now require HTTPS and reject internal IPs (#142, fixes #92).

### 4.3 DHCP (Ports 67-68, 546-547)

**Exposure:** LAN only.

**Protocol:** DHCPv4 (UDP 67/68), DHCPv6 (UDP 546/547).

**Threats:** Rogue DHCP server on LAN, DHCP starvation (mitigated by per-device /32 point-to-point addressing), DHCP fingerprint spoofing (#85). The DHCP IPC socket now enforces SO_PEERCRED (#131).

### 4.4 WireGuard (Configurable UDP Port)

**Exposure:** WAN (if enabled).

**Protocol:** WireGuard (Noise protocol framework, Curve25519, ChaCha20-Poly1305).

**Threats:** Key compromise (private key in SQLite), DDoS on listen port (WireGuard silently drops unauthenticated packets). Peer reconciliation deferred to restart creates sync gap (#111).

### 4.5 mDNS Proxy (Port 5353)

**Exposure:** LAN only.

**Protocol:** mDNS (multicast UDP 224.0.0.251:5353).

**Threats:** Service record spoofing (mitigated by nftables source IP enforcement, #74), cross-group metadata leakage (mitigated by unicast-only responses, #73). Bounded at 50 records/device and 10,000 total.

### 4.6 UPnP/NAT-PMP/PCP (Ports 1900, 5000, 5351)

**Exposure:** LAN only.

**Protocol:** SSDP (UDP 1900), UPnP SOAP (TCP 5000), NAT-PMP/PCP (UDP 5351).

**Threats:** Unauthorized port forward creation (mitigated by group filtering — trusted only), spoofed NAT-PMP requests (mitigated by nftables source IP validation, PCP address mismatch check, #82). Per-device limit of 20 mappings, 128 total, 24-hour max lease.

### 4.7 WiFi AP Management

**Exposure:** LAN only (agent to AP).

**Protocol:** HTTPS to AP web interface.

**Threats:** TOFU first-connection MITM (#76), hostname verification bypassed (#77), MD5 credential hash (#56), re-authentication per poll cycle (#57). Cert rotation breaks TOFU pin (#78).

### 4.8 Update Mechanism

**Exposure:** Outbound HTTPS to GitHub.

**Protocol:** HTTPS (GitHub Releases API + tarball download).

**Threats:** Compromised release artifacts (#86), auto-update without admin review (#87), symlink injection in tarballs (#102), version tag stored before validation (#103). Rollback binaries not verified (#88).

### 4.9 Syslog Export

**Exposure:** Configurable target (typically LAN).

**Protocol:** UDP syslog (RFC 5424, unencrypted).

**Threats:** Eavesdropping on exported logs, forged syslog injection (#53). SD-PARAMs are escaped to prevent log injection.

### 4.10 Declarative Config / Backup-Restore

**Exposure:** Unix socket (hermitctl CLI or web UI).

**Protocol:** JSON over Unix socket.

**Threats:** Unencrypted backup with plaintext secrets (#62), `apply_config` bypasses blocked keys (#110), no transaction atomicity (#113), DELETE-then-INSERT peer loss (#114), secrets not zeroized (#119).

---

## 5. Security Controls Summary

| Layer | Control | Mechanism |
|-------|---------|-----------|
| Language | Memory safety | Rust, `unsafe_code = "forbid"` workspace-wide |
| Process | Privilege restriction | systemd `CapabilityBoundingSet`, `NoNewPrivileges`, `ProtectSystem=strict` |
| Process | Syscall filtering | systemd `SystemCallFilter=~@mount @reboot @swap @debug @module @cpu-emulation` |
| Process | Filesystem isolation | `ProtectHome`, `PrivateTmp`, `ReadWritePaths` restricted to `/var/lib/hermitshell` and `/run/hermitshell` |
| Network | Firewall | nftables: per-device /32 isolation, group chains, MAC-IP validation, stateful tracking |
| Network | DNS security | DNSSEC validation, DNS rebinding protection, DoH IP blocking, forced DNS redirect |
| Network | Traffic encryption | WireGuard (Noise), HTTPS (TLS 1.2+), upstream DNS over TLS/HTTPS |
| IPC | Socket access control | Filesystem permissions `0660`, `SO_PEERCRED` UID check, method allowlist |
| IPC | Secret protection | `BLOCKED_CONFIG_KEYS` (14 keys), dedicated methods for secret access |
| Auth | Password storage | Argon2id (m=19MiB, t=2, p=1, OsRng salt) |
| Auth | Session tokens | HMAC-SHA256, 8-hour absolute expiry, timestamp binding |
| Auth | Brute-force defense | Two-layer rate limiting: per-IP (web UI) + global exponential backoff (agent) |
| Container | Web UI isolation | `--cap-drop ALL`, `--read-only`, `--security-opt no-new-privileges`, non-root user |
| Input | Validation | MAC, IP, interface, group, hostname sanitization on all mutating socket methods |
| Input | Config key blocklist | 14 sensitive keys blocked from generic get/set |
| Crypto | Key generation | `OsRng` for all cryptographic material (Argon2 salt, session secret, nonces) |
| Update | Integrity | SHA256 checksum on downloaded tarballs, path traversal checks |
| WiFi | Cert pinning | TOFU leaf-cert pinning for AP TLS connections |
| Spoofing | Defense-in-depth | Static ARP/NDP + MAC-IP nftables validation + DHCP fingerprint detection |

---

## 6. Accepted Risks

The following risks are documented in the [security overview](security.md) and explicitly accepted as part of the threat model:

| # | Risk | Rationale |
|---|------|-----------|
| 4 | Self-signed TLS, MITM on first connection | Standard for appliance UIs; ACME DNS-01 available for domain owners |
| 9 | Docker mounts full `/run/hermitshell` directory | Directory contains only sockets; container already uses `--network host` |
| 11 | Single admin account, no per-user audit trail | Home router has one admin; acceptable for single-user threat model |
| 28 | RA Guard at L3 only (same-segment bypass) | L2 RA Guard requires managed switch hardware |
| 31 | WAN DHCP trusts server responses | Inherent to DHCP protocol; WAN segment assumed ISP-controlled |
| 32 | TLS private key exposed over IPC | Socket is `0660`; web UI needs key to terminate TLS; cert is self-signed |
| 33 | Plaintext password over Unix socket | Local-only; root can read DB directly; better than exposing hash |
| 40 | Sessions cannot be individually revoked | Single admin; full revocation via secret rotation; 8-hour max lifetime |
| 41 | Rate limit state in-memory only | Root access to restart agent is already game over |
| 50 | All-in-one Docker container runs `--privileged` | Testing/simple deployments only; production uses systemd with hardening |
| 60 | Setup wizard endpoints unauthenticated | First-boot only; router physically controlled during initial setup |
| 72 | HKDF with no salt for WiFi password encryption | Input is 32 bytes of OS entropy; theoretical risk only |
| 73 | mDNS unicast-only response (RFC deviation) | Intentional privacy decision to prevent cross-group metadata leakage |
| 75 | Auto-classify bypasses quarantine | Opt-in, disabled by default |
| 76 | TOFU first connection unauthenticated | Standard bootstrap model (like SSH); local network physically controlled |
| 77 | Hostname verification bypassed for APs | Leaf-cert pinning is strictly more restrictive |
| 82 | NAT-PMP/PCP unauthenticated UDP | Protocol design; mitigated by nftables source validation and PCP address check |
| 83 | Static ARP does not prevent same-MAC spoofing | Defense-in-depth alongside MAC-IP validation and fingerprint detection |
| 86 | Update binaries lack signature verification | HTTPS provides transport security; same trust model as most GitHub-distributed projects |
| ~~91~~ | ~~DHCP IPC socket lacks SO_PEERCRED~~ | Fixed: now enforces `SO_PEERCRED` UID 0 check (#131) |
| ~~101~~ | ~~`thread_rng` for session secret~~ | Fixed: replaced with `OsRng` (#134) |
| 108 | REST API plaintext HTTP on localhost | Localhost-only; all processes on host are trusted |
| 110 | `apply_config` bypasses `BLOCKED_CONFIG_KEYS` | Required for declarative config; caller authenticated via session/API key |
| 112 | Secrets as plaintext JSON over Unix socket | Root access is already game over; consistent with `verify_password` |
| 113 | `apply_config` has no transaction atomicity | Best-effort pattern; SQLite WAL provides individual write durability |

---

## 7. Threat Matrix

| Adversary | Asset Targeted | Attack Vector | Control | Residual Risk |
|-----------|---------------|---------------|---------|---------------|
| Malicious LAN device | Other LAN devices | ARP spoofing | Static ARP + MAC-IP validation | Same-MAC spoofing (#83, #84) |
| Malicious LAN device | Network traffic | Rogue RA (IPv6 MITM) | nftables RA Guard | Same-segment bypass (#28) |
| Malicious LAN device | WAN access | Unauthorized port forward | UPnP group filtering | N/A (non-trusted devices blocked) |
| Malicious LAN device | DNS | DNS tunnel exfiltration | Forced DNS redirect + logging | Encoding in legitimate queries |
| WAN attacker | Router | Port scan / exploit | nftables drop-all WAN input | Zero-day in WireGuard or kernel |
| WAN attacker | Admin credentials | Web UI brute force | Two-layer rate limiting + Argon2 | In-memory state reset on restart (#41) |
| WAN attacker | Network traffic | MITM on HTTPS | TLS + cert pinning (APs) | Self-signed first-connection (#4) |
| Compromised web UI | All secrets | `export_config` / `apply_config` | Socket allowlist + session auth | Allowlist is broad (#90, #110) |
| Physical attacker | SQLite database | Disk read | None (plaintext at rest) | Full compromise assumed |
| Supply chain | All routers | Malicious release tarball | SHA256 checksum + HTTPS | No signature verification (#86) |
| Rogue DHCP (WAN) | WAN connectivity | Malicious DHCP response | XID matching | Inherent protocol trust (#31) |

---

## 8. Data Flow Diagram (Text)

```
                    ┌─────────────┐
                    │   Internet  │
                    └──────┬──────┘
                           │ WAN (eth1)
                    ┌──────┴──────┐
                    │  nftables   │◄── Stateful firewall, NAT, per-device isolation
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
     ┌────────┴───┐ ┌─────┴─────┐ ┌───┴────────┐
     │ WireGuard  │ │  Router   │ │    LAN     │
     │  (wg0)     │ │ Services  │ │  (eth2)    │
     └────────────┘ └─────┬─────┘ └───┬────────┘
                          │           │
           ┌──────────────┼───────────┼──────────────┐
           │              │           │              │
    ┌──────┴──────┐ ┌─────┴────┐ ┌───┴───┐ ┌───────┴──────┐
    │   Unbound   │ │  Agent   │ │ DHCP  │ │   Web UI     │
    │  (DNS :53)  │ │ (socket) │ │ (IPC) │ │ (HTTPS :443) │
    └─────────────┘ └─────┬────┘ └───┬───┘ └───────┬──────┘
                          │          │              │
                    ┌─────┴──────────┴──────────────┘
                    │         Unix Socket IPC
                    │    /run/hermitshell/agent.sock
                    │    (0660, SO_PEERCRED, allowlist)
                    └──────────┬───────────────────┐
                               │                   │
                        ┌──────┴──────┐     ┌──────┴──────┐
                        │   SQLite    │     │   REST API  │
                        │   (DB)      │     │ (localhost   │
                        │             │     │  :9080)      │
                        └─────────────┘     └─────────────┘
```

---

## 9. Out of Scope

The following are explicitly **not** part of the HermitShell threat model:

- **Kernel exploits:** A kernel vulnerability (nftables bypass, privilege escalation) is outside application-level mitigation. Kernel updates are the responsibility of the host OS.
- **Hardware attacks:** Side-channel attacks, JTAG, bus sniffing, or chip-level tampering.
- **Denial of service via physical layer:** Cutting cables, RF jamming, or physically powering off the device.
- **Compromise of upstream infrastructure:** ISP DNS poisoning, BGP hijacking, or CA compromise (beyond what DNSSEC and certificate pinning can detect).
- **Multi-admin access control:** The system is designed for a single administrator. Per-user RBAC is not in scope.
