# Security Compromises and Known Issues

This document tracks security compromises made during implementation, why they were made, and what the proper fix would be.

Most entries from the original audit have been resolved — either fixed in code, accepted as appropriate for the home router threat model, or addressed by the 2026-03-08 security hardening sweep. The remaining items below require future architectural work.

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

---

## Socket Access Control

## 90. SO_PEERCRED method allowlist grants broad access to non-root callers

**What:** The agent socket uses `SO_PEERCRED` (`peer_cred()`) to identify the UID of each connecting process. Root (UID 0) callers have unrestricted access. Non-root callers are restricted to a compile-time allowlist (`WEB_ALLOWED_METHODS`, ~80 methods). Methods not in the allowlist — `dhcp_discover`, `dhcp_provision`, `dhcp6_discover`, `dhcp6_provision`, `ingest_dns_logs` — return "access denied" for non-root callers.

**Why:** The web UI container runs as non-root and connects to the agent socket. It needs access to most methods (device management, config, status, WiFi, WireGuard, etc.) but should not be able to invoke DHCP provisioning or DNS log ingestion, which are internal IPC between the agent and its child processes.

**Risk:** The allowlist is permissive — non-root callers can still modify firewall rules, change DNS settings, and manage WireGuard peers. A compromised web UI container retains significant control over the router. The allowlist is deny-by-default for new methods (they must be explicitly added), which prevents accidental exposure of future admin-only methods.

**Mitigating factor:** The socket is `0660 root:root`, so only root and the web UI container (which has the socket bind-mounted) can connect. The `peer_cred()` check is kernel-enforced and unforgeable. Connections that fail `peer_cred()` are dropped immediately. `export_config` with `include_secrets=true` is now restricted to UID 0.

**Proper fix:** Further partition the allowlist into read-only and read-write tiers. Read-only methods (status, list) could be available to any socket caller, while write methods (set_config, add_port_forward) could require a session token or elevated credential. This would limit damage from a compromised read-only consumer.

---

## Post-Wizard Settings

## 107. Post-wizard interface change can lock out the admin

**What:** The wizard's `handle_set_interfaces` can only run before a password is set — meaning before the admin has a management session and before real traffic flows. The post-wizard `handle_update_interfaces` has no such guard. An admin can swap WAN and LAN assignments on a live router.

**Why:** The whole point of the post-wizard settings is to allow reconfiguration after setup. Blocking interface changes would defeat the purpose.

**Risk:** If the admin swaps WAN and LAN (or assigns the management interface as WAN), the next agent restart applies the new assignment. The firewall rules flip, the DHCP server binds to the wrong interface, and the admin's management connection drops. Recovery requires console access or physical presence to fix the config DB.

**Proper fix:** Display a confirmation warning in the UI when the new interface assignment differs from the current running config. Consider a watchdog timer that reverts the change if the admin does not confirm via a second request within 60 seconds (similar to display resolution change dialogs).

---

## Declarative Config System

## 111. WireGuard peer reconciliation deferred to agent restart

**What:** When `apply_config` processes WireGuard peers, it deletes all rows from `wg_peers` and re-inserts the declared peers with fresh subnet allocations and nftables rules. However, runtime changes to the `wg0` interface (adding/removing peers via the `wg` command) are not performed — they are deferred to the next agent restart.

**Why:** Reconciling the live wg0 interface requires kernel syscalls for each peer add/remove and must coordinate with the interface's private key and listen port. The same deferral pattern is used by `import_config`.

**Risk:** Between apply and restart, the database and running WireGuard interface are out of sync. Peers deleted from the config can still connect via wg0, and newly declared peers cannot connect until the agent restarts. If the agent crashes before restarting, the DB has the new state while wg0 retains the old state.

**Proper fix:** Reconcile WireGuard peers live by computing a diff (peers to add, remove, keep) and applying changes via `wg set` commands. Use a transaction to ensure DB and wg0 changes are atomic.

---

## Security Logging and Monitoring (OWASP C9)

## 141. Syslog export limited to unencrypted UDP

**What:** The syslog export only supports `udp://` targets. There is no TCP or TLS transport option. Messages are sent as plaintext UDP datagrams, limited to 480 bytes per RFC 5426 section 3.2, with no authentication or encryption.

**Why:** UDP syslog is the simplest to implement (stateless, fire-and-forget) and compatible with virtually all syslog receivers. TCP+TLS (RFC 5425) requires persistent connection management, TLS handshake, reconnection logic, and message framing.

**Risk:** On a shared network, syslog messages are visible to any observer. For a home router where the syslog receiver is typically on the same trusted LAN, the risk is low. However, for users forwarding logs to a cloud SIEM over the WAN, plaintext UDP is unacceptable. The webhook export (which supports HTTPS) is the recommended alternative for encrypted log forwarding.

**Proper fix:** Add `tcp+tls://` prefix support to `parse_syslog_target()`. Implement a persistent TCP+TLS connection using `rustls` (already a dependency) with automatic reconnection. Use RFC 5425 octet counting framing. This removes the 480-byte message limit and provides confidentiality and integrity for syslog transport.
