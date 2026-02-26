# HermitShell Roadmap

## Completed Phases

| Phase | Feature | Date |
|-------|---------|------|
| 1 | WAN/LAN connectivity | — |
| 2 | DHCP (DHCPv4 /32 + DHCPv6 /128) | — |
| 3 | Device isolation (per-device subnets) | — |
| 4 | DNS ad blocking (Blocky) | — |
| 5 | WireGuard VPN (dual-stack) | — |
| 6 | Production hardening (auth, HTTPS, systemd) | 2026-02-17 |
| 7 | Connection/DNS logging, syslog/webhook export | 2026-02-18 |
| 8 | IPv6 dual-stack (RA, DHCPv6-PD, ULA) | 2026-02-19 |
| 9 | Behavioral analysis (anomaly detection, alerts) | 2026-02-20 |
| 10 | QoS bufferbloat prevention (CAKE, DSCP) | 2026-02-20 |
| 11 | runZero asset sync | 2026-02-20 |
| 12 | TLS certificate management (self-signed, custom, Tailscale, ACME DNS-01) | 2026-02-23 |
| 13 | WiFi AP management (TP-Link EAP standalone) | 2026-02-23 |
| 14 | Production readiness (setup wizard, update checker, encrypted WiFi creds) | 2026-02-24 |
| 15 | Backup/restore (v2 export, optional encrypted secrets) | 2026-02-24 |
| 16 | Multi-AP management UI (inline SSID/radio config, per-AP clients) | 2026-02-25 |
| 17 | mDNS proxy (group-based service discovery across isolated subnets) | 2026-02-26 |

## Future Work

### Security Hardening

- [ ] WiFi AP TLS verification when CA cert provided (#55)
- [ ] EAP session caching to reduce credential exposure (#57)
- [ ] L2 RA Guard via ebtables (#28)
- [ ] DUID-EN/UUID MAC fallback (#29)

### Operational Features

- [ ] Scheduled automatic backups
- [ ] Multi-admin accounts (#11)
- [ ] Metrics / Prometheus endpoint

### Networking

- [ ] Per-device firewall rules (beyond group-based)
- [ ] IPv6 pinhole rate limiting / geo-IP filtering (#30)
- [ ] UPnP/NAT-PMP for automatic port forwarding
