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

## Future Work

### Security Hardening

Items tracked in `docs/SECURITY.md` with issue numbers.

- [ ] Rate limiting on login (#8)
- [ ] Session cookie expiration / TTL (#2)
- [ ] Secure flag on session cookie (#10)
- [ ] `import_config` validation (#12)
- [ ] VACUUM path validation (#13)
- [ ] Port forwarding description length limit (#14)
- [ ] Container non-root user + setcap (#15)
- [ ] Systemd hardening directives (#16)
- [ ] WireGuard key file cleanup on error (#17)
- [ ] Agent socket connection limiting (#19)
- [ ] DHCP hostname length validation at network layer (#21)
- [ ] DHCP discover_times / solicit_times eviction (#22)
- [ ] Max device limit (#23)
- [ ] Port forwarding reserved port check (#25)
- [ ] WireGuard peer name/key validation (#27)
- [ ] L2 RA Guard (#28)
- [ ] DUID-EN/UUID MAC fallback (#29)
- [ ] DHCPv6-PD lease file validation (#31)
- [ ] Argon2 mutex split (#34)
- [ ] Memory zeroization of secrets (#35)

### Web UI Improvements

- [ ] Error flash messages on form submissions (#26)
- [ ] Audit trail for admin actions
- [ ] Device nicknames / tagging
- [ ] Confirmation dialogs for destructive actions (block, delete)

### Operational Features

- [ ] Scheduled automatic backups
- [ ] Let's Encrypt / custom CA certificate management (#4)
- [ ] CSRF tokens on forms (#7)
- [ ] Multi-admin accounts (#11)
- [ ] Metrics / Prometheus endpoint

### Networking

- [ ] Per-device firewall rules (beyond group-based)
- [ ] IPv6 pinhole rate limiting / geo-IP filtering (#30)
- [ ] runZero custom CA cert for self-hosted consoles (#37)
- [ ] UPnP/NAT-PMP for automatic port forwarding
