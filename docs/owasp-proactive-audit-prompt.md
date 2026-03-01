# OWASP Top 10 Proactive Controls — Parallel Audit Prompt

Use this prompt to dispatch 10 sub-agents (one per OWASP Proactive Control) to audit and fix the HermitShell codebase. Each agent works independently and produces both code changes and a findings report.

---

## Instructions for the orchestrator

Dispatch **10 agents in parallel** using the Task tool with `subagent_type: "general-purpose"`. Each agent gets its own control below. After all agents complete, review their outputs and commit the changes.

**Convention reminders to include in every agent prompt:**
- Working directory: `/home/ubuntu/hermitshell`
- Do NOT touch files under `.worktrees/`
- Commit convention: ten words or fewer, don't mention Claude
- Security trade-offs must be documented in `docs/SECURITY.md` (append, don't rewrite) using the existing format: `## NNN. Title` with **What**, **Why**, **Risk**, **Proper fix** sections. The last existing entry is `## 119`. New entries start at `## 120`.
- `unsafe_code = "forbid"` is workspace-wide — do not add unsafe blocks
- Follow CONTRIBUTING.md conventions: validate input before interpolation, secrets use zeroize, wire types in hermitshell-common
- If a change is too risky or large to implement safely, write a findings report only (no code changes) and explain what should be done

---

## Agent 1: C1 — Implement Access Control

```
You are auditing HermitShell against OWASP Proactive Control C1: Implement Access Control.

CONTEXT:
- Agent socket uses SO_PEERCRED for caller identity (socket/mod.rs)
- WEB_ALLOWED_METHODS controls what the web UI can call
- BLOCKED_CONFIG_KEYS prevents reading secrets via generic get_config
- Default-deny nftables firewall with per-device verdict maps
- Known issues: SECURITY.md #90 (WEB_ALLOWED_METHODS too broad), #91 (DHCP socket no SO_PEERCRED)

KEY FILES TO READ:
- hermitshell-agent/src/socket/mod.rs (WEB_ALLOWED_METHODS, BLOCKED_CONFIG_KEYS, peer_cred)
- hermitshell-agent/src/socket/config.rs (export_config, apply_config)
- hermitshell-agent/src/nftables.rs (firewall rules, validate_* functions)
- hermitshell-dhcp/src/main.rs (DHCP socket handling)

TASKS:
1. Read WEB_ALLOWED_METHODS and identify methods that should be restricted (especially export_config with secrets). Propose splitting into read/write method sets or adding per-method guards.
2. Check if the DHCP socket enforces SO_PEERCRED. If not, assess feasibility of adding it.
3. Verify BLOCKED_CONFIG_KEYS covers all secrets (cross-reference with db.rs config keys).
4. Check that all nftables rule generation uses validate_* functions — no unsanitized input reaches nft commands.
5. Write findings to /tmp/owasp-c1-findings.md
6. Make code changes for any quick wins (e.g., tightening method lists, adding missing BLOCKED_CONFIG_KEYS entries).
7. If you add security trade-off entries, append them to docs/SECURITY.md starting at ## 120+.
```

## Agent 2: C2 — Use Cryptography to Protect Data

```
You are auditing HermitShell against OWASP Proactive Control C2: Use Cryptography to Protect Data.

CONTEXT:
- Argon2id for passwords (socket/auth.rs)
- AES-256-GCM for WiFi AP passwords (crypto.rs)
- HMAC-SHA256 for session tokens (socket/auth.rs)
- HKDF-SHA256 key derivation (crypto.rs)
- rustls for TLS (tls.rs)
- Known issues: #101 (thread_rng for session secret), #104 (thread_rng for DHCP txids), #119 (incomplete zeroization), #72 (HKDF no salt)

KEY FILES TO READ:
- hermitshell-agent/src/socket/auth.rs (password hashing, session creation/validation)
- hermitshell-agent/src/crypto.rs (encrypt/decrypt WiFi passwords)
- hermitshell-agent/src/db.rs (secret storage, session_secret generation)
- hermitshell-agent/src/tls.rs (TLS cert generation, renewal)
- hermitshell-dhcp/src/main.rs (transaction ID generation)
- hermitshell-agent/src/rest_api.rs (API key handling)
- hermitshell-agent/src/socket/config.rs (HermitSecrets, apply_config with secrets)

TASKS:
1. Find all uses of thread_rng() for cryptographic material and replace with OsRng (#101, #104).
2. Audit zeroization coverage: find all paths where secrets are read from DB or deserialized from JSON but not wrapped in Zeroizing<String>. Fix the most critical paths (#119).
3. Check HKDF usage in crypto.rs — add a static context salt if missing (#72).
4. Verify TLS configuration: minimum version, cipher suites, cert validation.
5. Check that no secrets are logged (search for tracing/log macros near secret variables).
6. Write findings to /tmp/owasp-c2-findings.md
7. Make code changes for #101 and #104 (OsRng). Assess #119 zeroization fixes.
8. If you add security trade-off entries, append them to docs/SECURITY.md starting at ## 120+.
```

## Agent 3: C3 — Validate All Input & Handle Exceptions

```
You are auditing HermitShell against OWASP Proactive Control C3: Validate all Input & Handle Exceptions.

CONTEXT:
- Two-tier validation: structural (hermitshell-common/src/config_validate.rs) + agent-level (nftables.rs, socket/config.rs)
- Allowlist-based validators for IPs, MACs, interfaces, groups, protocols
- Prepared SQL statements via rusqlite (db.rs)
- Leptos auto-escaping for HTML (SSR-only, no client WASM)
- Syslog RFC 5424 escaping in log_export.rs

KEY FILES TO READ:
- hermitshell-common/src/config_validate.rs (structural validation)
- hermitshell-agent/src/nftables.rs (validate_ip, validate_mac, validate_iface, validate_group, validate_protocol, validate_ipv6_*)
- hermitshell-agent/src/socket/config.rs (apply_config validation flow)
- hermitshell-agent/src/db.rs (SQL query patterns — verify all use prepared statements)
- hermitshell-agent/src/unbound.rs (DNS config generation — check for injection)
- hermitshell-agent/src/log_export.rs (syslog escaping)
- hermitshell-agent/src/socket/dns.rs (DNS-related input handling)
- hermitshell-common/src/lib.rs (wire types — check for #[serde(deny_unknown_fields)])

TASKS:
1. Verify ALL SQL in db.rs uses parameterized queries. Flag any string interpolation into SQL.
2. Check unbound.rs config generation for command/config injection (domains, IPs written to unbound.conf).
3. Audit wire types in hermitshell-common/src/lib.rs: add #[serde(deny_unknown_fields)] to IPC command structs to prevent mass assignment.
4. Check nftables.rs: verify every user-supplied value passed to nft commands goes through validate_* first.
5. Look for ReDoS-vulnerable regex patterns (though Rust's regex crate is largely immune, confirm no PCRE usage).
6. Check error handling: ensure no panics in request-handling code paths (no unwrap() on user input).
7. Write findings to /tmp/owasp-c3-findings.md
8. Make code changes: add deny_unknown_fields, fix any missing validation.
```

## Agent 4: C4 — Address Security from the Start

```
You are auditing HermitShell against OWASP Proactive Control C4: Address Security from the Start (Secure Architecture).

CONTEXT:
- Defense-in-depth: nftables → socket perms → method allowlists → key blocklists → input validation
- Minimal attack surface: SSR-only web UI (no WASM), Unix socket (no TCP API for agent)
- unsafe_code = "forbid" workspace-wide
- 119 documented security trade-offs in SECURITY.md
- No formal threat model document exists

TASKS (research/documentation only — no code changes):
1. Read docs/SECURITY.md (full file) to understand documented trade-offs.
2. Read the project structure: hermitshell-agent/, hermitshell/, hermitshell-common/, hermitshell-dhcp/, hermitctl/
3. Draft a threat model document at docs/THREAT-MODEL.md covering:
   a. Assets: what are we protecting? (network traffic, admin credentials, device configs, DNS queries)
   b. Adversaries: who are the attackers? (malicious LAN device, WAN attacker, compromised IoT device, physical attacker, supply chain)
   c. Trust boundaries: Unix socket, nftables, Docker container, web UI auth
   d. Attack surfaces: web UI (HTTPS), DNS (port 53), DHCP, WireGuard, mDNS, UPnP, WiFi AP management, update mechanism
   e. Security controls per boundary (reference existing controls)
   f. Accepted risks (reference SECURITY.md issue numbers)
4. Create docs/.well-known/security.txt (RFC 9116) with:
   - Contact: security@hermitshell.org
   - Preferred-Languages: en
   - Canonical: https://hermitshell.org/.well-known/security.txt
   - Policy: https://github.com/hermitshell-router/hermitshell/blob/main/docs/SECURITY.md
5. Write findings to /tmp/owasp-c4-findings.md
```

## Agent 5: C5 — Secure By Default Configurations

```
You are auditing HermitShell against OWASP Proactive Control C5: Secure By Default Configurations.

CONTEXT:
- Default-deny firewall
- New devices default to "quarantine" group
- HTTPS by default (self-signed cert on first start)
- Docker: non-root, --cap-drop ALL, --read-only, --security-opt no-new-privileges
- Systemd: ProtectSystem=strict, NoNewPrivileges, MemoryDenyWriteExecute, CapabilityBoundingSet
- Auto-update enabled by default (#87)

KEY FILES TO READ:
- hermitshell-agent/src/db.rs (default config values, schema initialization)
- hermitshell-agent/src/nftables.rs (default firewall rules)
- hermitshell-agent/src/main.rs (startup defaults)
- systemd/hermitshell-agent.service (systemd hardening)
- systemd/hermitshell-ui.service (container launch flags)
- hermitshell/Dockerfile (web UI container)
- Dockerfile (all-in-one container)
- hermitshell-agent/src/socket/config.rs (default config on apply)

TASKS:
1. Audit all default config values in db.rs schema initialization. List each default and assess if it's the most secure option.
2. Verify systemd service hardening is complete — compare against systemd-analyze security recommendations.
3. Check Docker container flags for missing hardening (e.g., --no-new-privileges is there, but is --tmpfs /tmp used? Is the filesystem truly read-only?).
4. Audit the default nftables ruleset: are there any overly permissive default rules?
5. Check if debug/development features can leak into production (debug logging, test endpoints, etc.).
6. Write findings to /tmp/owasp-c5-findings.md
7. Make code changes for any missing hardening that's low-risk to add.
```

## Agent 6: C6 — Keep Your Components Secure

```
You are auditing HermitShell against OWASP Proactive Control C6: Keep your Components Secure (Dependency/Supply Chain Security).

CONTEXT:
- cargo-deny in CI: advisory checks, license auditing, registry/git source restrictions
- deny.toml: unknown-registry=deny, unknown-git=deny
- Dependabot: weekly Cargo + GitHub Actions updates
- 3 ignored RUSTSEC advisories in deny.toml
- Release workflow: SHA256 checksums, GPG-signed apt repo
- No SBOM generation, no binary signing (beyond checksums), no SLSA provenance

KEY FILES TO READ:
- deny.toml (cargo-deny configuration)
- .github/dependabot.yml
- .github/workflows/ci.yml (build + deny job)
- .github/workflows/release.yml (artifact generation)
- .github/workflows/apt-repo.yml (GPG signing)
- Cargo.toml (workspace), hermitshell-agent/Cargo.toml, hermitshell-ui/Cargo.toml (dependencies)

TASKS:
1. Review the 3 ignored RUSTSEC advisories in deny.toml. Check if upstream fixes are now available.
2. Add SBOM generation to the release workflow using cargo-cyclonedx or syft (CycloneDX format). The SBOM should be uploaded as a release artifact alongside the tarballs.
3. Add a scheduled weekly cargo-audit job to .github/workflows/ci.yml (or a new workflow) that runs independently of PRs.
4. Evaluate adding SLSA provenance via slsa-framework/slsa-github-generator — write a recommendation in findings (don't implement, it's complex).
5. Evaluate adding Sigstore/cosign for binary signing — write a recommendation in findings.
6. Check if GitHub Actions versions are pinned by SHA (not just tag) for supply chain safety.
7. Write findings to /tmp/owasp-c6-findings.md
8. Make code changes: SBOM generation in release workflow, scheduled audit job.
```

## Agent 7: C7 — Secure Digital Identities

```
You are auditing HermitShell against OWASP Proactive Control C7: Secure Digital Identities.

CONTEXT:
- Single admin account, no username
- Argon2id password hashing with per-password random salt
- HMAC-SHA256 session tokens: "admin:created:last_active.signature"
- 30-min idle timeout, 8-hour absolute timeout
- Cookie: HttpOnly, Secure, SameSite=Strict
- Rate limiting: exponential backoff (2^failures seconds, max 60s), dual-layer
- Known issues: #40 (stateless sessions can't be revoked), #41 (rate limit resets on restart), #48 (per-IP cache eviction)

KEY FILES TO READ:
- hermitshell-agent/src/socket/auth.rs (password hashing, session create/validate/refresh)
- hermitshell/src/main.rs (auth middleware, rate limiting, cookie handling)
- hermitshell-ui/src/pages/login.rs (login form)
- hermitshell-ui/src/pages/settings.rs (password change)
- hermitshell-agent/src/rest_api.rs (API key auth)

TASKS:
1. Verify password hashing: Argon2id params, salt generation, timing-safe comparison.
2. Verify session management: token format, HMAC verification, timeout enforcement, cookie flags.
3. Assess adding a breached/common password check: embed a small list (top 1,000 common passwords) checked during password set/change. Implement if feasible (a simple HashSet check in auth.rs).
4. Verify rate limiting: check that failed login attempts are tracked correctly, backoff works, and the rate limiter can't be trivially bypassed.
5. Check password change flow: does it invalidate existing sessions? Does it require the old password?
6. Verify API key auth in rest_api.rs: constant-time comparison, proper storage.
7. Write findings to /tmp/owasp-c7-findings.md
8. Make code changes: add common password check if feasible.
```

## Agent 8: C8 — Leverage Browser Security Features

```
You are auditing HermitShell against OWASP Proactive Control C8: Leverage Browser Security Features.

CONTEXT:
- HSTS: max-age=31536000; includeSubDomains
- CSP: default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Referrer-Policy: strict-origin-when-cross-origin
- Cookie: HttpOnly, Secure, SameSite=Strict
- CSRF: Sec-Fetch-Site + Origin header verification
- DNS rebinding: Host header validation

KEY FILES TO READ:
- hermitshell/src/main.rs (security headers middleware, CSRF middleware, auth middleware, host validation)
- hermitshell-ui/src/components/layout.rs (HTML head, meta tags)
- hermitshell-ui/src/pages/*.rs (any inline scripts or styles)

TASKS:
1. Verify all security headers are set correctly. Check for missing headers:
   - Permissions-Policy (should declare unused features: camera=(), microphone=(), geolocation=(), etc.)
   - Cross-Origin-Opener-Policy (COOP)
   - Cross-Origin-Resource-Policy (CORP)
2. Audit the CSP policy: can 'unsafe-inline' for styles be removed? Check if Leptos SSR generates inline styles that require it.
3. Verify CSRF protection: check Sec-Fetch-Site and Origin validation logic for bypasses.
4. Check Host header validation for DNS rebinding: what hosts are allowed? Can it be bypassed with non-standard headers?
5. Verify all forms use POST (not GET for state-changing operations).
6. Add Permissions-Policy header if missing.
7. Write findings to /tmp/owasp-c8-findings.md
8. Make code changes: add Permissions-Policy, fix any header issues.
```

## Agent 9: C9 — Security Logging and Monitoring

```
You are auditing HermitShell against OWASP Proactive Control C9: Implement Security Logging and Monitoring.

CONTEXT:
- Audit log table for admin actions (db.rs)
- Connection logging (device IP, dest, port, bytes, timestamps)
- DNS query logging
- Syslog export (RFC 5424, UDP) — #53: unencrypted
- Webhook export (JSON + HMAC signature)
- SQLite local retention (configurable)
- tracing crate for structured logging

KEY FILES TO READ:
- hermitshell-agent/src/db.rs (audit_log table, log retention, log queries)
- hermitshell-agent/src/log_export.rs (syslog + webhook export)
- hermitshell-agent/src/socket/auth.rs (auth event logging)
- hermitshell-agent/src/socket/mod.rs (request logging)
- hermitshell-agent/src/analyzer.rs (behavioral analysis alerts)
- hermitshell-agent/src/dns_log.rs (DNS query logging)
- hermitshell-agent/src/conntrack.rs (connection tracking)

TASKS:
1. Audit what security events are logged:
   - Login success/failure (with source IP)
   - Password changes
   - Config changes
   - Session creation/expiry
   - Rate limiting triggers
   - Firewall rule changes
   - API key usage
2. Verify no sensitive data in logs: search for password, secret, key, token near tracing::info/warn/error/debug macros.
3. Check log injection prevention: verify syslog output escapes user-controlled data.
4. Assess log integrity: is there any tamper detection? Could HMAC chaining be added?
5. Check alert surfacing: do behavioral analysis alerts reach the admin in real-time?
6. Evaluate adding TLS syslog (TCP+TLS) as an option alongside UDP (#53).
7. Write findings to /tmp/owasp-c9-findings.md
8. Make code changes for any quick wins (e.g., missing security event logging).
```

## Agent 10: C10 — Stop Server Side Request Forgery

```
You are auditing HermitShell against OWASP Proactive Control C10: Stop Server Side Request Forgery (SSRF).

CONTEXT:
- The agent makes outbound HTTP requests for:
  1. DNS blocklist downloads (user-configured URLs) — socket/dns.rs or unbound.rs
  2. ACME (Let's Encrypt) challenges — tls.rs
  3. runZero API calls — runzero.rs
  4. GitHub update checks — update.rs
  5. WiFi AP management (user-configured AP IPs) — wifi/eap_standalone.rs, wifi/unifi.rs
  6. Webhook delivery (user-configured URL) — log_export.rs
- Known issue: #92 (blocklist HTTP not HTTPS-only)

KEY FILES TO READ:
- hermitshell-agent/src/unbound.rs (blocklist download)
- hermitshell-agent/src/socket/dns.rs (blocklist URL configuration)
- hermitshell-agent/src/log_export.rs (webhook delivery)
- hermitshell-agent/src/update.rs (GitHub update checks)
- hermitshell-agent/src/runzero.rs (runZero API)
- hermitshell-agent/src/tls.rs (ACME)
- hermitshell-agent/src/wifi/eap_standalone.rs (EAP AP requests)
- hermitshell-agent/src/wifi/unifi.rs (UniFi controller requests)
- hermitshell-common/src/config_validate.rs (URL validation)

TASKS:
1. For each outbound request source, assess SSRF risk:
   - Can the user control the destination URL/IP?
   - Is there validation against internal network ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, fd00::/8, ::1)?
   - Is the scheme restricted (HTTPS-only where appropriate)?
2. Implement URL validation for blocklist URLs: reject internal IPs and require HTTPS (#92).
3. Implement URL validation for webhook URLs: reject internal IPs (or document the intentional allowance if webhooks to internal services are a valid use case).
4. WiFi AP IPs are intentionally internal — document this as an accepted risk (it's by design, not an SSRF vuln).
5. Check for DNS rebinding in outbound requests: does the agent resolve the hostname and validate the IP before connecting?
6. Write findings to /tmp/owasp-c10-findings.md
7. Make code changes: add SSRF protection for blocklist and webhook URLs.
8. If you add security trade-off entries, append them to docs/SECURITY.md starting at ## 120+.
```

---

## Post-Audit Steps

After all 10 agents complete:

1. **Collect findings:**
   ```bash
   cat /tmp/owasp-c*-findings.md > docs/owasp-audit-findings.md
   ```

2. **Review SECURITY.md changes:** Ensure new entries (## 120+) don't conflict and numbering is sequential.

3. **Build and test:**
   ```bash
   cargo build --workspace
   cd tests && sudo -E ./run.sh
   ```

4. **Commit per-control or as a single audit commit.**

5. **Review the threat model** (docs/THREAT-MODEL.md) for completeness.

6. **File issues** for items agents flagged as "too large to implement safely."
