# YAGNI Feature Evaluation — Parallel Audit Prompt

Use this prompt to dispatch 5 sub-agents (one per feature category) to rigorously evaluate every HermitShell feature against the YAGNI principle. Each agent works independently and produces a scored verdict for each feature in its scope.

---

## Evaluation Framework

Every feature must be evaluated against these five criteria. A feature must pass **all five** to earn a Keep verdict:

| # | Criterion | Key Question |
|---|-----------|-------------|
| 1 | **Core value** | Does this feature directly serve "autonomous routing on commodity hardware, no cloud, no controller"? |
| 2 | **Launch necessity** | Would a real home-network user notice or care if this were missing on day one? |
| 3 | **Maintenance cost** | What's the ongoing cost in code size, dependency surface, test surface, and security audit surface? |
| 4 | **Deferral safety** | Can this be added post-1.0 without breaking the config schema, DB schema, or API contract? |
| 5 | **Simpler alternative** | Could documentation, a shell script, or manual config achieve 80% of the value at 10% of the code? |

### Verdict Definitions

- **Keep** — Essential for 1.0. Removing it would make the product incomplete for its target user.
- **Defer** — Valuable but not essential. Remove from the codebase now; design the extension point so it can return post-1.0 without breaking changes. The findings report must explain what to preserve (config key names, DB columns, API method signatures) to avoid future migration pain.
- **Cut** — Over-engineered, niche, or solvable outside the codebase. Remove permanently. The findings report must explain the simpler alternative.

### Scoring

For each feature, assign a 1–5 score on each criterion (5 = strong Keep signal, 1 = strong Cut signal). A feature with **any criterion scoring 1–2** requires explicit justification to Keep. Features averaging below 3.0 default to Defer or Cut.

---

## Instructions for the orchestrator

Dispatch **5 agents in parallel** using the Agent tool with `subagent_type: "general-purpose"`. Each agent gets its own category below. After all agents complete, consolidate their verdicts into a single summary table.

**Convention reminders to include in every agent prompt:**
- Working directory: the hermitshell repo root
- This is a **read-only audit** — do NOT make code changes or commits
- Read the actual source files to assess code size and complexity; do not guess
- The target user is a technically-inclined homeowner who wants Ubiquiti-level features without the Ubiquiti headaches (see SPEC.md §1.1)
- Be ruthless. The bias should be toward Defer/Cut. The burden of proof is on Keep.
- Write findings to `/tmp/yagni-catN-findings.md` (where N is the agent number)

**Output format per feature:**

```
### Feature Name
| Criterion | Score | Notes |
|-----------|-------|-------|
| Core value | X/5 | ... |
| Launch necessity | X/5 | ... |
| Maintenance cost | X/5 | ... |
| Deferral safety | X/5 | ... |
| Simpler alternative | X/5 | ... |
| **Average** | **X.X** | |

**Verdict: Keep / Defer / Cut**
Rationale: ...
```

---

## Agent 1: Core Networking

```
You are evaluating HermitShell features against the YAGNI principle.
Your scope: core networking features.

CONTEXT:
HermitShell is a router platform for commodity Linux hardware. The core promise
is: routing, firewalling, DHCP, and device isolation — all self-contained, no
cloud. Read SPEC.md §1.1–1.2 for the value proposition.

FEATURES TO EVALUATE (read the source for each):

1. WAN interface management (DHCP client, static IP, failover)
   - hermitshell-agent/src/wan.rs (41 KB)

2. DHCP server (DHCPv4 + DHCPv6, /32 isolation, reservations, fingerprinting)
   - hermitshell-dhcp/src/main.rs
   - hermitshell-agent/src/dhcp.rs

3. Device isolation (proxy ARP, per-device /32 subnets)
   - hermitshell-agent/src/nftables.rs

4. Firewall (nftables, per-group policies, default-deny)
   - hermitshell-agent/src/nftables.rs (36.8 KB)

5. Port forwarding (TCP/UDP, ranges, enable/disable)
   - hermitshell-agent/src/portmap.rs (14.1 KB)

6. DMZ host
   - hermitshell-agent/src/nftables.rs (search for "dmz")

7. IPv6 dual-stack (RA, DHCPv6-PD, ULA, pinholes)
   - hermitshell-agent/src/ra.rs (4.9 KB)
   - hermitshell-agent/src/nftables.rs (ipv6 pinhole logic)

8. QoS / bufferbloat prevention (CAKE, DSCP, speed test)
   - hermitshell-agent/src/qos.rs (11.4 KB)

9. Device groups (Trusted, IoT, Servers, Guest, Quarantine, Blocked)
   - hermitshell-common/src/lib.rs (DeviceGroup enum)

TASKS:
1. Read each source file to assess actual complexity and code size.
2. For each feature, score against the 5 YAGNI criteria using the framework above.
3. Pay special attention to:
   - DMZ host: is this a niche power-user feature or genuinely needed?
   - QoS: does a home router need built-in CAKE/DSCP or can users run tc manually?
   - IPv6 pinholes: how many home users actively manage IPv6 pinholes?
   - Speed test integration: is this core routing or bloat?
   - 6 device groups: are this many groups necessary or would 3 (Trusted/Untrusted/Blocked) suffice?
4. Write findings to /tmp/yagni-cat1-findings.md
```

## Agent 2: DNS & Privacy

```
You are evaluating HermitShell features against the YAGNI principle.
Your scope: DNS services and privacy features.

CONTEXT:
HermitShell runs Unbound for DNS resolution with ad-blocking. The question is
how much DNS functionality belongs in a router vs. being left to dedicated tools
like Pi-hole or AdGuard Home.

FEATURES TO EVALUATE (read the source for each):

1. DNS server (Unbound integration, upstream forwarding)
   - hermitshell-agent/src/unbound.rs (40.8 KB — this is massive for DNS config)

2. Ad-blocking (blocklist management, enable/disable per-list, tags)
   - hermitshell-agent/src/socket/dns.rs (368 lines)
   - hermitshell-agent/src/unbound.rs (blocklist download/apply logic)

3. DNS forward zones (domain → specific DNS server)
   - hermitshell-agent/src/unbound.rs

4. Custom DNS records (A, AAAA, CNAME, etc.)
   - hermitshell-agent/src/unbound.rs

5. Per-device DNS rate limiting
   - hermitshell-agent/src/unbound.rs

6. DNS query logging and analytics
   - hermitshell-agent/src/dns_log.rs (6.3 KB)
   - hermitshell-ui/src/pages/dns.rs

7. mDNS proxy (group-based filtering across isolated subnets)
   - hermitshell-agent/src/mdns.rs or similar
   - Phase 17 in ROADMAP.md

8. DNS bypass for specific device groups
   - hermitshell-agent/src/nftables.rs (DNS bypass rules)

TASKS:
1. Read each source file to assess actual complexity.
2. Score each feature against the 5 YAGNI criteria.
3. Pay special attention to:
   - unbound.rs at 40.8 KB: what's driving this size? Is the blocklist management
     reimplementing what Pi-hole does, but worse?
   - Forward zones: how many home users configure split-horizon DNS?
   - Custom DNS records: is this a router feature or a DNS-server feature?
   - Per-device rate limiting: what problem does this solve for a home network?
   - mDNS proxy: essential for device isolation to work (Chromecast, AirPlay) or niche?
   - DNS query logging: privacy feature or surveillance feature? What's the storage cost?
4. Write findings to /tmp/yagni-cat2-findings.md
```

## Agent 3: VPN & Remote Access

```
You are evaluating HermitShell features against the YAGNI principle.
Your scope: VPN, guest networking, and automatic port mapping.

CONTEXT:
HermitShell offers WireGuard VPN, a guest network mode, and full UPnP/NAT-PMP/PCP
support. The question is whether the scope of each is appropriate.

FEATURES TO EVALUATE (read the source for each):

1. WireGuard VPN (dual-stack, peer management, QR codes, group assignment)
   - hermitshell-agent/src/wireguard.rs
   - hermitshell-agent/src/socket/wireguard.rs (246 lines)

2. Guest network (isolated mode, auto-generated passwords, regeneration)
   - hermitshell-agent/src/socket/guest.rs (358 lines)
   - hermitshell-ui/src/pages/guest.rs

3. UPnP IGD (SSDP discovery, port mapping, lease management)
   - hermitshell-agent/src/upnp.rs (38.1 KB — this is enormous)

4. NAT-PMP (port mapping protocol)
   - hermitshell-agent/src/natpmp.rs (24.1 KB)

5. PCP (Port Control Protocol, NAT-PMP successor)
   - hermitshell-agent/src/natpmp.rs (combined with NAT-PMP)

TASKS:
1. Read each source file to assess actual complexity.
2. Score each feature against the 5 YAGNI criteria.
3. Pay special attention to:
   - UPnP at 38.1 KB + NAT-PMP at 24.1 KB = 62 KB of port mapping code. That's
     more code than many entire applications. Is this justified for a home router?
     Could miniupnpd be used instead of a from-scratch implementation?
   - WireGuard QR codes: nice-to-have or essential? Could the UI just show the
     config text and let users copy it?
   - Guest network: is this a distinct feature or just "a device group with a
     password display"? How much code is guest-specific vs. reusing group logic?
   - UPnP security surface: UPnP is historically one of the most exploited router
     features. Is implementing it from scratch wise?
4. Write findings to /tmp/yagni-cat3-findings.md
```

## Agent 4: Integrations & Hardware

```
You are evaluating HermitShell features against the YAGNI principle.
Your scope: WiFi AP management, RunZero integration, SNMP switches, and VLANs.

CONTEXT:
HermitShell manages external hardware (WiFi APs, network switches) and integrates
with third-party services (RunZero). The question is whether a router should be an
AP controller, a switch manager, and an asset inventory client.

FEATURES TO EVALUATE (read the source for each):

1. WiFi AP management — UniFi controller integration
   - hermitshell-agent/src/wifi/unifi.rs
   - hermitshell-agent/src/socket/wifi.rs (646 lines)

2. WiFi AP management — TP-Link EAP standalone
   - hermitshell-agent/src/wifi/eap_standalone.rs

3. WiFi feature scope (SSID config, radio tuning, client kick/block, VLAN per SSID)
   - hermitshell-agent/src/wifi/mod.rs
   - hermitshell-ui/src/pages/wifi.rs

4. RunZero asset sync (device discovery, OS/hardware identification)
   - hermitshell-agent/src/runzero.rs (3.6 KB)

5. SNMP switch management (MAC table polling)
   - hermitshell-agent/src/switch/mod.rs
   - hermitshell-agent/src/socket/switch.rs (231 lines)

6. VLAN support (subinterface creation, per-group VLANs)
   - hermitshell-agent/src/vlan.rs
   - hermitshell-agent/src/socket/vlan.rs (180 lines)

TASKS:
1. Read each source file to assess actual complexity.
2. Score each feature against the 5 YAGNI criteria.
3. Pay special attention to:
   - WiFi AP management: HermitShell's pitch is "no controller needed" — but it IS
     a controller for WiFi APs. Is this contradictory? Could WiFi management be a
     separate optional component or plugin?
   - Two AP vendors already, with ROADMAP.md listing "additional AP vendor support".
     Is multi-vendor AP management a rabbit hole that will consume maintenance forever?
   - RunZero: how many home users have a RunZero account? Is this enterprise creep?
   - SNMP switches: the SPEC says "dumb/unmanaged is fine — no VLAN support needed".
     Why does the codebase then have SNMP switch polling and VLAN management?
   - VLANs: the entire value proposition of device isolation is that you DON'T need
     VLANs. Why are VLANs in the codebase?
4. Write findings to /tmp/yagni-cat4-findings.md
```

## Agent 5: Operations & Observability

```
You are evaluating HermitShell features against the YAGNI principle.
Your scope: monitoring, logging, security operations, system management, and CLI tools.

CONTEXT:
HermitShell has accumulated significant operational tooling: behavioral analysis,
structured log export, connection logging, backup/restore with encryption, GUI
self-updates with rollback, TOTP 2FA, ACME certificate management, and a
declarative CLI tool. The question is how much ops tooling a 1.0 router needs.

FEATURES TO EVALUATE (read the source for each):

1. Behavioral analysis (anomaly detection, DNS beaconing, volume spikes, alert rules)
   - hermitshell-agent/src/analyzer.rs (10.3 KB)
   - hermitshell-ui/src/pages/alerts.rs

2. Connection logging (source/dest/port/bytes/timestamps, retention policies)
   - hermitshell-agent/src/conntrack.rs (10.1 KB)
   - hermitshell-agent/src/db.rs (connection_log table)

3. Syslog export (RFC 5424, UDP)
   - hermitshell-agent/src/log_export.rs (22.1 KB)

4. Webhook export (JSON + HMAC signing)
   - hermitshell-agent/src/log_export.rs

5. Backup/restore (JSON export, AES-256-GCM encryption, import with secrets)
   - hermitshell-agent/src/socket/config.rs (export/import logic)
   - hermitshell-agent/src/crypto.rs

6. GUI self-update (download, verify, staged restart, automatic rollback)
   - hermitshell-agent/src/update.rs (16.4 KB)

7. TOTP 2FA
   - hermitshell-agent/src/socket/totp.rs (208 lines)
   - hermitshell-agent/src/socket/auth.rs

8. ACME DNS-01 TLS certificates (Cloudflare integration)
   - hermitshell-agent/src/tls.rs (12.1 KB)

9. hermitctl CLI (apply, diff, export, validate, status)
   - hermitctl/src/main.rs

10. Audit logging
    - hermitshell-agent/src/db.rs (audit_log table)

TASKS:
1. Read each source file to assess actual complexity.
2. Score each feature against the 5 YAGNI criteria.
3. Pay special attention to:
   - Behavioral analysis: is a home router an IDS? This is a complex domain with
     high false-positive rates. Is the analysis sophisticated enough to be useful,
     or just sophisticated enough to generate noise?
   - Syslog + webhook export at 22 KB combined: how many home users run a SIEM?
   - Encrypted backup: is AES-256-GCM encryption of config backups solving a real
     problem, or is `cp hermitshell.db somewhere-safe/` (from SPEC.md) sufficient?
   - GUI self-update with rollback: impressive engineering, but apt/dpkg already
     does this. Is this reinventing the package manager?
   - TOTP 2FA: for a single-admin device on a home LAN behind the firewall, is
     2FA solving a real threat or is it security theater?
   - ACME DNS-01: a home router typically uses a self-signed cert or is accessed
     via IP. How many users will configure Cloudflare DNS-01?
   - hermitctl: is a declarative CLI tool needed at 1.0, or is the web UI + API
     sufficient? How many home users write TOML config files?
   - Audit logging: valuable for enterprise compliance, but for a home router?
4. Write findings to /tmp/yagni-cat5-findings.md
```

---

## Post-Audit Steps

After all 5 agents complete:

1. **Consolidate verdicts:**
   ```bash
   cat /tmp/yagni-cat*-findings.md > docs/yagni-audit-findings.md
   ```

2. **Build the summary table:**

   Create a single table with all features, their average scores, and verdicts.
   Sort by verdict (Cut first, then Defer, then Keep) so the action items are at
   the top.

3. **Estimate removal impact:**

   For each Defer/Cut feature, estimate:
   - Lines of Rust removed
   - Dependencies that become unused (check Cargo.toml)
   - UI pages that can be deleted
   - API methods that can be removed
   - Test cases affected

4. **Identify removal order:**

   Some features depend on others. Propose a safe removal sequence that avoids
   breaking intermediate states. Each removal should leave the project in a
   compiling, functional state.

5. **File issues** for each Defer verdict with the tag `yagni-deferred`, documenting
   what to preserve for future re-addition.
