# YAGNI Audit Findings — HermitShell

**Date:** 2026-03-09
**Methodology:** 5 parallel agents, each evaluating a feature category against 5 YAGNI criteria (core value, launch necessity, maintenance cost, deferral safety, simpler alternative). Scores 1–5 per criterion; features averaging below 3.0 default to Defer/Cut.

---

## Executive Summary

**31 features evaluated. 13 Keep, 9 Defer, 9 Cut.**

Estimated removal: **~6,400 lines of Rust** plus significant dependency reductions (snmp2, flate2, tar, ed25519-dalek, instant-acme, data-encoding). The cuts concentrate in three areas:

1. **WiFi/VLAN/SNMP cluster** (~3,600 lines) — contradicts the SPEC's "no controller, no VLANs" positioning
2. **Custom protocol implementations** (~1,700 lines) — UPnP/NAT-PMP/PCP should use miniupnpd instead of from-scratch code
3. **Enterprise ops features** (~1,100 lines) — behavioral analysis, webhook export, ACME DNS-01, GUI self-update

---

## Consolidated Verdict Table

Sorted by verdict (Cut → Defer → Keep), then by average score ascending.

| # | Feature | Category | Avg | Verdict | Lines | Key Concern |
|---|---------|----------|-----|---------|-------|-------------|
| 1 | VLAN support | Integrations | 2.0 | **Cut** | 261 | Contradicts SPEC's core differentiator |
| 2 | Speed test | Core Net | 2.0 | **Cut** | ~40 | Bloat; browser tests are better |
| 3 | TP-Link EAP standalone | Integrations | 2.2 | **Cut** | 765 | Reverse-engineered, fragile, AP has own UI |
| 4 | SNMP switch management | Integrations | 2.2 | **Cut** | 608 | Contradicts "dumb switch is fine" |
| 5 | UPnP IGD (custom impl) | VPN/Remote | 2.4 | **Cut** | 965 | Replace with miniupnpd; security risk |
| 6 | GUI self-update | Ops | 2.4 | **Cut** | 429 | Reinvents apt/dpkg |
| 7 | ACME DNS-01 (Cloudflare) | Ops | 2.4 | **Cut** | 327 | Niche; Tailscale + self-signed cover it |
| 8 | PCP protocol | VPN/Remote | 2.6 | **Cut** | ~430 | No consumer device requires it |
| 9 | DNS bypass per group | DNS | 2.6 | **Cut** | ~30 | Dead code; undermines privacy promise |
| 10 | Webhook export | Ops | 2.6 | **Cut** | ~100 | Enterprise; syslog covers it |
| 11 | UniFi controller integration | Integrations | 2.4 | **Defer** | 895 | "No controller" product IS a controller |
| 12 | WiFi feature scope (active) | Integrations | 2.6 | **Defer** | 940 | AP's own UI does this |
| 13 | Behavioral analysis | Ops | 2.6 | **Defer** | 297 | Mini-IDS; too noisy for home users |
| 14 | DNS forward zones | DNS | 2.8 | **Defer** | ~120 | Niche split-horizon DNS |
| 15 | DNS rate limiting | DNS | 2.8 | **Defer** | ~60 | Two Unbound config lines |
| 16 | QoS DSCP marking | Core Net | 2.8 | **Defer** | ~60 | Second-order feature |
| 17 | Guest network | VPN/Remote | 3.0 | **Defer** | 586 | "Device group + managed SSID" |
| 18 | NAT-PMP (custom impl) | VPN/Remote | 3.0 | **Defer** | ~300 | Free with miniupnpd |
| 19 | RunZero asset sync | Integrations | 3.0 | **Cut** | 107 | Enterprise creep; OUI lookup is free |
| 20 | JSON backup/restore + encryption | Ops | 3.2 | **Defer** | ~350 | cp hermitshell.db is sufficient |
| 21 | TOTP 2FA | Ops | 3.2 | **Defer** | 208 | Password + rate limiting is enough |
| 22 | QoS CAKE | Core Net | 3.2 | **Defer** | ~95 | tc one-liner + docs covers it |
| 23 | Custom DNS records | DNS | 3.0 | **Keep** | ~40 | Borderline; most-requested DNS feature |
| 24 | DNS query logging | DNS | 3.0 | **Keep** | 146 | Feeds traffic visibility UI |
| 25 | IPv6 dual-stack | Core Net | 3.0 | **Keep** | ~800 | High cost but deferring creates schema pain |
| 26 | DMZ host | Core Net | 3.2 | **Keep** | ~40 | Near-zero cost (~40 lines total) |
| 27 | Syslog export | Ops | 3.2 | **Keep** | ~120 | Explicitly promised in SPEC |
| 28 | Device groups (all 6) | Core Net | 3.4 | **Keep** | ~12/group | Reducing post-1.0 is breaking |
| 29 | hermitctl CLI | Ops | 3.4 | **Keep** | 204 | 204 lines, enables API-first promise |
| 30 | Audit logging | Ops | 3.4 | **Keep** | ~50 | Remove chain-hashing, keep basics |
| 31 | Port forwarding | Core Net | 4.0 | **Keep** | 392 | Standard home router feature |
| 32 | Ad-blocking | DNS | 3.8 | **Keep** | ~130 | Key differentiator, lean impl |
| 33 | WAN management | Core Net | 4.2 | **Keep** | ~1175 | Foundational |
| 34 | DHCP server | Core Net | 4.4 | **Keep** | ~993 | /32 isolation requires custom DHCP |
| 35 | WireGuard VPN | VPN/Remote | 4.6 | **Keep** | 440 | Thin wrapper, core remote access |
| 36 | mDNS proxy | DNS | 4.6 | **Keep** | 875 | Essential for isolation to work |
| 37 | Firewall | Core Net | 4.8 | **Keep** | ~150 | Non-negotiable |
| 38 | Device isolation | Core Net | 4.8 | **Keep** | ~100 | The product's identity |
| 39 | Connection logging | Ops | 4.8 | **Keep** | 289 | Feeds traffic visibility |
| 40 | DNS server (Unbound) | DNS | 5.0 | **Keep** | ~305 | Non-negotiable |

---

## Impact Analysis

### Code Removal (Cut + Defer)

| Component | Lines | Action |
|-----------|-------|--------|
| `upnp.rs` | 965 | Cut (replace with miniupnpd) |
| `natpmp.rs` | 734 | Cut (free with miniupnpd) |
| `wifi/unifi.rs` | 895 | Defer |
| `wifi/eap_standalone.rs` | 765 | Cut |
| `socket/wifi.rs` | 647 | Defer (keep passive WiFi only) |
| `wifi/mod.rs` | 293 | Defer (keep passive WiFi only) |
| `update.rs` | 429 | Cut |
| `switch/mod.rs` | 376 | Cut |
| `tls.rs` (ACME portion) | ~250 | Cut |
| `socket/switch.rs` | 232 | Cut |
| `socket/guest.rs` | 358 | Defer |
| `analyzer.rs` | 297 | Defer |
| `socket/totp.rs` | 208 | Defer |
| `socket/config.rs` (JSON export/import) | ~350 | Defer |
| `vlan.rs` | 80 | Cut |
| `socket/vlan.rs` | 181 | Cut |
| `runzero.rs` | 107 | Cut |
| `qos.rs` | ~200 | Defer (all of QoS) |
| `log_export.rs` (webhook) | ~100 | Cut |
| DNS forward zones (agent + UI) | ~120 | Defer |
| DNS rate limiting (UI + handler) | ~60 | Defer |
| DNS bypass config | ~30 | Cut |
| Speed test code | ~40 | Cut |
| **Total** | **~7,742** | |

### Dependency Removals

| Crate | Removed with |
|-------|-------------|
| `snmp2` | SNMP switch cut |
| `flate2` | GUI self-update cut |
| `tar` | GUI self-update cut |
| `ed25519-dalek` | GUI self-update cut |
| `instant-acme` | ACME DNS-01 cut |
| `data-encoding` | TOTP 2FA defer |

### UI Pages Affected

| Page | Action |
|------|--------|
| `/wifi` | Defer (remove active management, keep passive device enrichment) |
| `/guest` | Defer |
| `/alerts` | Defer |
| `/settings/monitoring` (RunZero, webhook sections) | Cut those sections |

---

## Recommended Removal Order

Each step leaves the project in a compiling, functional state:

1. **Cut VLAN + SNMP + WiFi VLAN tagging** — coupled cluster, remove together
2. **Cut RunZero** — independent 107-line module
3. **Cut DNS bypass config** — dead code removal
4. **Cut speed test** — isolated function in qos.rs
5. **Cut UPnP + NAT-PMP + PCP** — replace with miniupnpd or remove entirely
6. **Cut TP-Link EAP** — independent WiFi provider
7. **Cut GUI self-update** — independent module
8. **Cut ACME DNS-01** — portion of tls.rs
9. **Cut webhook export** — portion of log_export.rs
10. **Defer UniFi + active WiFi management** — behind trait; remove providers
11. **Defer guest network** — depends on WiFi providers
12. **Defer behavioral analysis** — independent module
13. **Defer QoS (CAKE + DSCP)** — independent module
14. **Defer TOTP 2FA** — independent module
15. **Defer JSON backup/restore** — keep raw DB backup
16. **Defer DNS forward zones + rate limiting** — small scope

---

## Architectural Observations

### The Controller Paradox
HermitShell positions itself as "no controller needed" but ships a multi-vendor WiFi AP controller (1,660 lines across two vendors). This is a branding and messaging contradiction. If WiFi management returns post-1.0, it should be an explicitly optional, separately installable component.

### The VLAN-SNMP Cascade
VLANs, SNMP switches, and WiFi SSID VLAN tagging form a coupled dependency chain. Cutting VLANs cleanly cascades to cutting SNMP and WiFi VLAN tagging — three features removed by one decision.

### The UPnP Security Surface
965 lines of hand-rolled UPnP IGD (including custom XML parsing, SSDP, SOAP) is the highest-risk code in the codebase. UPnP is historically the most exploited router protocol. miniupnpd has 15+ years of security hardening and should replace this entirely.

### The "Standard Linux" Promise
The SPEC says "Standard Linux underneath." Features like GUI self-update (reinventing apt), custom ACME (reinventing certbot), and structured backup (reinventing pg_dump) contradict this by reimplementing standard Linux tools. Lean into the OS; don't reimplement it.
