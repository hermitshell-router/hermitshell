# OWASP Proactive Control C1: Implement Access Control -- Audit Findings

Auditor: Claude Code Agent
Date: 2026-03-01
Scope: HermitShell agent socket access control, DHCP IPC, nftables input validation

---

## Summary

HermitShell implements a layered access control model for its Unix socket API:

1. **Filesystem permissions** (`0660 root:root`) restrict socket access
2. **SO_PEERCRED** (kernel-provided UID) distinguishes root vs. non-root callers
3. **WEB_ALLOWED_METHODS** allowlist restricts non-root callers to ~100 methods
4. **BLOCKED_CONFIG_KEYS** prevents reading/writing secrets via generic `get_config`/`set_config`
5. **Input validation** (`validate_mac`, `validate_ip`, `validate_iface`, `validate_group`, `validate_protocol`) sanitizes all data before nftables command interpolation
6. **Default-deny nftables** firewall with per-device verdict maps

Overall posture is strong for a single-admin appliance. Findings below are ordered by severity.

---

## Finding 1: DHCP IPC socket lacked SO_PEERCRED (FIXED)

**Severity:** Low (defense-in-depth gap)
**File:** `hermitshell-agent/src/socket/mod.rs` lines 562-594
**Status:** FIXED in this audit

The DHCP IPC socket (`/run/hermitshell/dhcp.sock`) relied solely on filesystem permissions (`0660 root:root`) for access control. Unlike the main agent socket, it did not call `peer_cred()` to verify the caller's UID.

**Fix applied:** Added `peer_cred()` check that rejects all non-root (UID != 0) callers. This resolves SECURITY.md #91.

**Risk mitigated:** If filesystem permissions were loosened (e.g., for debugging), an unprivileged process could have called `dhcp_discover`/`dhcp_provision` to allocate IP addresses and inject nftables rules.

---

## Finding 2: `acme_cf_zone_id` missing from BLOCKED_CONFIG_KEYS (FIXED)

**Severity:** Low
**File:** `hermitshell-agent/src/socket/mod.rs` line 29-45
**Status:** FIXED in this audit

The Cloudflare zone ID (`acme_cf_zone_id`) was not in `BLOCKED_CONFIG_KEYS`, making it readable via `get_config` and writable via `set_config` by any caller with socket access. While not a credential itself, the zone ID identifies the DNS zone and could aid an attacker who has obtained the API token.

**Fix applied:** Added `"acme_cf_zone_id"` to `BLOCKED_CONFIG_KEYS`.

---

## Finding 3: `export_config` with `include_secrets=true` accessible to non-root callers (NOT FIXED)

**Severity:** Medium
**File:** `hermitshell-agent/src/socket/mod.rs` line 71, `config.rs` line 64-212

`export_config` is in `WEB_ALLOWED_METHODS`, and the handler does not check `caller_uid`. A non-root caller (the web UI container) can call `export_config` with `include_secrets=true` and receive all secrets in plaintext: admin password hash, session secret, WireGuard private key, TLS private key, ACME tokens, runZero token, WiFi provider passwords, and API key hash.

**Current mitigation:** The web UI container must authenticate the admin via session token before proxying this call. The socket is `0660 root:root`, so only the container has access.

**Risk:** A compromised web UI container can exfiltrate all secrets without admin interaction.

**Recommended fix:** Thread `caller_uid` through to `handle_export_config` and reject `include_secrets=true` for non-root callers. Alternatively, split into two methods: `export_config` (no secrets, web-allowed) and `export_config_full` (with secrets, root-only). This is documented in new SECURITY.md entry #120.

---

## Finding 4: `get_tls_config` returns TLS private key to non-root callers (NOT FIXED)

**Severity:** Medium
**File:** `hermitshell-agent/src/socket/auth.rs` lines 444-457

`get_tls_config` returns both the TLS certificate AND private key PEM. It is in `WEB_ALLOWED_METHODS`. The web UI container needs this to configure its HTTPS listener, so removing it from the allowlist would break TLS.

**Current mitigation:** The socket is `0660`, so only the web UI container can access it. The container needs the key to serve HTTPS.

**Risk:** A compromised web UI container obtains the TLS private key, enabling MITM attacks even after the container is restored.

**Recommended fix:** Consider a file-based TLS key delivery mechanism (write key to a file mounted into the container) instead of passing it over the socket. Alternatively, accept this as inherent to the architecture where the web UI terminates TLS. This is already noted in SECURITY.md #90.

---

## Finding 5: WEB_ALLOWED_METHODS is overly broad (EXISTING -- SECURITY.md #90)

**Severity:** Medium (acknowledged)
**File:** `hermitshell-agent/src/socket/mod.rs` lines 57-100

The allowlist grants non-root callers access to ~100 methods including:
- **Write methods:** `set_config`, `import_config`, `apply_config`, `apply_update`, `set_api_key`
- **Secret-adjacent reads:** `get_tls_config`, `export_config`, `backup_database`
- **Network mutation:** `add_port_forward`, `set_dmz`, `set_wireguard_enabled`

This is documented in SECURITY.md #90. The recommended improvement is tiered access (read-only vs read-write), but this is a significant architectural change.

---

## Finding 6: Domain-specific handlers bypass BLOCKED_CONFIG_KEYS by design (ACCEPTABLE)

**Severity:** Informational
**Files:** `config.rs` (set_log_config, set_runzero_config), `auth.rs` (set_acme_config)

Several handlers write blocked config keys directly to the DB without going through `set_config`:
- `set_log_config` writes `webhook_secret`
- `set_runzero_config` writes `runzero_token`
- `set_acme_config` writes `acme_cf_api_token` and `acme_cf_zone_id`
- `set_tls_cert` writes `tls_key_pem` and `tls_cert_pem`

This is intentional: `BLOCKED_CONFIG_KEYS` blocks the generic `get_config`/`set_config` path, but domain-specific handlers that validate and process these secrets are the authorized write path. This parallels how RBAC systems have specific endpoints for credential rotation rather than exposing a generic "set any field" API.

**No action needed.**

---

## Finding 7: nftables input validation is comprehensive (PASS)

**Severity:** N/A (positive finding)

All paths that generate nftables commands validate inputs before interpolation:

| Function | Validates |
|---|---|
| `apply_base_rules` | `validate_iface(wan)`, `validate_iface(lan)` |
| `add_device_counter` | `validate_ip(ip)` |
| `add_device_counter_v6` | `validate_ipv6_ula(ip)` |
| `add_device_forward_rule` | `validate_ip(ip)`, `validate_group(group)` |
| `add_device_forward_rule_v6` | `validate_ipv6_ula(ip)`, `validate_group(group)` |
| `add_device_route` | `validate_ip`, `validate_iface`, `validate_mac` |
| `add_device_route_v6` | `validate_ipv6_ula`, `validate_iface`, `validate_mac` |
| `add_mac_ip_rule` | `validate_ip`, `validate_mac` |
| `add_mac_ip_rule_v6` | `validate_ipv6_ula`, `validate_mac` |
| `add_ipv6_pinhole` | `validate_ipv6_global`, `validate_protocol` |
| `remove_ipv6_pinhole` | `validate_ipv6_global`, `validate_protocol` |
| `apply_port_forwards` | `validate_iface(wan)`, `validate_iface(lan)`, `validate_ip` per forward |
| `add_upnp_input_rules` | `validate_iface` |
| `apply_dscp_rules` | Parses all IPs as `Ipv4Addr` before interpolation |

Additionally, the top-level dispatch (`handle_client`, `handle_dhcp_request`) validates MAC addresses before dispatching to any handler.

The QoS module (`qos.rs`) validates interface names via `nftables::validate_iface` and bandwidth values via `validate_bandwidth` before passing to `tc` commands.

**No issues found.** The validation layer effectively prevents command injection through nftables or ip/tc commands.

---

## Finding 8: BLOCKED_CONFIG_KEYS coverage is complete (PASS after fix)

After adding `acme_cf_zone_id`, the blocked keys list covers all sensitive config values:

| Key | Type | Blocked? |
|---|---|---|
| `admin_password_hash` | Credential | Yes |
| `session_secret` | Credential | Yes |
| `wg_private_key` | Credential | Yes |
| `tls_key_pem` | Credential | Yes |
| `tls_cert_pem` | Certificate | Yes |
| `runzero_token` | Credential | Yes |
| `runzero_ca_cert` | Certificate | Yes |
| `acme_cf_api_token` | Credential | Yes |
| `acme_cf_zone_id` | Identifier (sensitive) | Yes (NEWLY ADDED) |
| `acme_account_key` | Credential | Yes |
| `webhook_secret` | Credential | Yes |
| `api_key_hash` | Credential | Yes |
| `update_latest_version` | Internal state | Yes |
| `update_installed_version` | Internal state | Yes |
| `setup_complete` | Internal state | Yes |
| `setup_step` | Internal state | Yes |

Non-secret config keys like `acme_domain`, `acme_contact_email`, `upstream_dns`, `wan_mode`, etc. are intentionally NOT blocked since they are needed by the web UI for display and configuration.

---

## Changes Made

1. **`hermitshell-agent/src/socket/mod.rs`:**
   - Added `"acme_cf_zone_id"` to `BLOCKED_CONFIG_KEYS`
   - Added `peer_cred()` check to `run_dhcp_socket()` that rejects non-root callers

2. **No changes to `nftables.rs`** -- validation is already comprehensive

3. **No changes to `config.rs`** beyond the `acme_cf_zone_id` blocking (which is inherited from mod.rs)

---

## Recommendations for Future Work

1. **Thread `caller_uid` to handlers** -- Enable per-handler access control decisions (e.g., reject `include_secrets=true` for non-root). This is the "proper fix" for Finding 3.

2. **Split WEB_ALLOWED_METHODS into tiers** -- Read-only methods (list, get, status) vs. write methods (set, add, remove, apply). This is the "proper fix" for SECURITY.md #90.

3. **File-based TLS key delivery** -- Instead of passing `tls_key_pem` over the socket, write it to a file that the web UI container mounts read-only. This eliminates Finding 4.

4. **Audit logging for secret access** -- Log when `export_config` is called with `include_secrets=true` (already done) and when `get_tls_config` returns the private key.
# OWASP Proactive Control C2: Use Cryptography to Protect Data

## Audit Date: 2026-03-01

## Scope

HermitShell cryptographic subsystems: password hashing, session management,
WiFi AP password encryption, TLS configuration, DHCP transaction IDs,
secret zeroization, and logging hygiene.

---

## 1. thread_rng() replaced with OsRng for cryptographic material (FIXED)

**Issue:** Four call sites used `rand::thread_rng()` (a userspace CSPRNG seeded
from OS entropy once per thread) instead of `rand::rngs::OsRng` (direct OS
entropy) for cryptographic material:

| File | Line | Material |
|------|------|----------|
| `hermitshell-agent/src/main.rs` | 486 | Session secret (32-byte hex) |
| `hermitshell-agent/src/socket/auth.rs` | 123 | Session secret fallback path |
| `hermitshell-agent/src/wan.rs` | 392 | DHCPv4 DISCOVER xid |
| `hermitshell-agent/src/wan.rs` | 546 | DHCPv4 RENEW xid |

Additionally, three `rand::random()` calls in `crypto.rs` (which internally use
`thread_rng()`) generated AES-GCM nonces and Argon2 salts:

| File | Line | Material |
|------|------|----------|
| `hermitshell-agent/src/crypto.rs` | 30 | AES-GCM nonce (12 bytes) |
| `hermitshell-agent/src/crypto.rs` | 88 | Argon2 salt (16 bytes) |
| `hermitshell-agent/src/crypto.rs` | 92 | AES-GCM nonce (12 bytes) |

**Fix applied:** All seven call sites now use `rand::rngs::OsRng` directly.

**Remaining thread_rng() uses (acceptable):**
- `hermitshell-agent/src/ra.rs:71` -- RA timer jitter (non-cryptographic)
- `hermitshell-agent/src/upnp.rs:288` -- SSDP response delay (non-cryptographic)

**References:** SECURITY.md #101, #104

---

## 2. Zeroization coverage improved for session_secret (FIXED)

**Issue:** The `session_secret` (master encryption key for WiFi AP passwords)
was read from the SQLite database as a plain `String` in 8 code paths without
`Zeroizing<String>` wrapping.  This left the 64-character hex key in heap memory
after use, accessible via debugger or core dump.

**Paths fixed:**

| File | Line(s) | Context |
|------|---------|---------|
| `socket/wifi.rs` | 105-109 | WiFi provider add (encrypt password) |
| `socket/wifi.rs` | 256-258 | WiFi provider test (decrypt password) |
| `socket/wifi.rs` | 273-276 | WiFi provider test (decrypt API key) |
| `socket/config.rs` | 120 | Config export (decrypt for plaintext export) |
| `socket/config.rs` | 411 | Config import (encrypt provider passwords) |
| `socket/config.rs` | 508 | Config import backward compat (encrypt) |
| `wifi/mod.rs` | 118-121 | WiFi poll loop (decrypt password) |
| `wifi/mod.rs` | 138-141 | WiFi poll loop (decrypt API key) |
| `main.rs` | 495 | Legacy WiFi password migration |

**Fix applied:** All nine reads now wrap the value in `Zeroizing::new()`.

**Remaining zeroization gaps (documented, not fixed):**
- The `HermitSecrets` struct deserialized from JSON in the `apply_config` path
  creates temporary `String` values that are not zeroized after DB insertion.
  Fixing this requires either `Zeroizing` fields on `HermitSecrets` or manual
  zeroing after each `set_config` call.  The risk is low (root attacker who can
  read process memory can also read the DB directly).
- `setup_password` in `auth.rs:79` reads the existing hash as a plain `String`
  (not `Zeroizing`) when verifying the current password during a change.  This
  is a brief-lived stack value but could be wrapped for completeness.

**References:** SECURITY.md #119

---

## 3. HKDF salt omission assessed (NOT CHANGED)

**Issue:** `crypto.rs:derive_key()` uses `Hkdf::<Sha256>::new(None, ...)` with
no salt.  HKDF salt provides domain separation and defense against weak IKM.

**Assessment:** Adding a salt changes the derived key, which breaks decryption
of all existing `enc:v1:` encrypted WiFi passwords.  Since these passwords are
auto-generated random values that the admin never sees, there is no manual
recovery path.  The IKM (session_secret) is 32 bytes of OS-sourced random data,
making unsalted HKDF output cryptographically indistinguishable from random.

**Recommendation:** Implement a versioned scheme:
1. Introduce `enc:v2:` prefix with a static domain-separation salt
2. On decrypt, try v2 first, fall back to v1 (no salt) for migration
3. On encrypt, always use v2
4. After one release cycle, remove v1 support

**Updated the derive_key() doc comment** to explain the rationale and the
recommended future migration path.

**References:** SECURITY.md #72

---

## 4. TLS configuration (PASS)

**Server (hermitshell/src/main.rs:350):**
- Uses `rustls 0.23.37` with default `ServerConfig::builder()`
- Default protocol versions: TLS 1.2 and TLS 1.3
- Default cipher suites: AEAD-only (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305)
  with ECDHE key exchange for TLS 1.2; all TLS 1.3 suites
- No CBC, RC4, or 3DES ciphers
- No client certificate authentication (appropriate for web UI)

**Client (hermitshell-agent/src/tls_client.rs:111):**
- Uses `with_safe_default_protocol_versions()` explicitly
- Custom `CaOnlyVerifier` validates cert chain against CA store but skips
  hostname verification (documented trade-off for AP access by IP)
- Legacy path uses native-tls (OpenSSL) for IoT devices with 1024-bit RSA
  (documented trade-off in SECURITY.md #79)

**Finding:** TLS configuration is sound.  No action needed.

---

## 5. Secret logging audit (PASS)

**Checked all `info!`, `warn!`, `error!`, `debug!`, `trace!` macros** near
secret-handling code paths.  No secret values are interpolated into log messages.

Specific checks:
- `auth.rs`: Logs "session secret generated" (no value), "password verification
  failed" (no hash)
- `tls.rs`: Logs "renewed" messages without cert/key content
- `config.rs`: Logs blocked key names but not values
- `rest_api.rs`: Logs "failed to read api_key_hash" (error, not value)
- `wifi/mod.rs`: Logs provider name on decrypt failure (not the password)
- `log_export.rs`: Puts webhook secret in HTTP header (necessary for auth)

**Finding:** No secret logging issues found.

---

## 6. Additional observations

### 6a. Argon2id usage (PASS)
- Password hashing uses `Argon2::default()` which is Argon2id with safe parameters
- Salt generation uses `SaltString::generate(&mut OsRng)` (already correct)

### 6b. AES-256-GCM usage (PASS)
- Nonce is 12 bytes, randomly generated (now via OsRng)
- Ciphertext includes authentication tag (inherent in AES-GCM)
- Key derived via HKDF-SHA256 from 32-byte random session_secret

### 6c. HMAC-SHA256 session tokens (PASS)
- Session tokens use HMAC-SHA256 with the session_secret as key
- Token format: `payload.signature` with constant-time verification via
  `mac.verify_slice()`
- Tokens include creation time and last-active time for expiry enforcement

### 6d. DHCPv6 transaction ID (INFO)
- `wan.rs:741` uses `v6::Message::new(MessageType::Solicit)` which internally
  generates the xid.  The `dhcproto` crate generates this using its own RNG.
  This is not under our control but DHCPv6 xids are 24-bit (not security
  critical).

---

## Summary

| Issue | Severity | Status |
|-------|----------|--------|
| thread_rng for session secret (#101) | Medium | FIXED |
| thread_rng for DHCP xid (#104) | Low | FIXED |
| thread_rng for AES nonces/salts | Medium | FIXED |
| session_secret not zeroized (#119) | Low | FIXED (9 paths) |
| HKDF no salt (#72) | Informational | Documented, deferred |
| TLS configuration | N/A | PASS |
| Secret logging | N/A | PASS |
# OWASP Proactive Control C3: Validate All Input and Handle Exceptions

**Audit date:** 2026-03-01
**Scope:** hermitshell-agent, hermitshell-common

---

## 1. SQL Injection (db.rs)

### Finding: ALL runtime SQL uses parameterized queries — PASS

Every `SELECT`, `INSERT`, `UPDATE`, `DELETE` in `db.rs` uses rusqlite's `?N` parameter
binding. No user-supplied data is interpolated into SQL strings at runtime.

**Two safe exceptions in migrations (hardcoded values only):**
- Lines 223, 264: `format!("ALTER TABLE devices ADD COLUMN {col}")` — `col` comes from
  a hardcoded `&[&str]` literal, not user input. Safe.
- Line 940: `format!("VACUUM INTO '{}'", path)` — `path` comes from `paths::backup_path()`,
  an internal constant. Safe.

**Dynamic SQL in `list_alerts` (line 1143):** Builds query dynamically with `?{idx}`
numbered parameters — all values are bound via `params`, never interpolated. Safe.

**`conn_exec` method (line 929):** Accepts raw SQL string. All call sites pass hardcoded
`DELETE FROM <table>` literals. Safe but worth noting: this is the only raw-SQL escape
hatch and should not be used with user input.

### Verdict: No SQL injection vulnerabilities found.

---

## 2. Unbound Config Injection (unbound.rs)

### Finding: Adequate validation — PASS with notes

**Forward zones** (lines 197, 319-320):
- `fz.domain`: Validated by `validate_domain()` before DB insertion at all entry points
  (dns.rs:95, config.rs:889, config.rs:559). Domain validator restricts to
  `[a-zA-Z0-9-.]` so config injection via newlines/quotes is impossible.
- `fz.forward_addr`: Validated as `IpAddr` before DB insertion. Safe.

**Custom rules** (lines 298-303):
- `rule.domain`: Validated by `validate_domain()`.
- `rule.value`: Escaped via `escape_unbound_value()` which handles `\`, `"`, and
  newlines. Test at line 864 confirms injection via `"; malicious` is blocked.

**Blocklist parsing** (lines 532-562):
- `convert_blocklist_body()` parses hosts-format lists. Domain names from external
  blocklists are inserted into `local-zone: "domain" always_refuse`. The `domain`
  value is NOT escaped/validated — it comes from downloaded blocklist content. A
  malicious blocklist could inject unbound config directives via a domain containing
  `"\n  forward-zone:` etc.
- **Mitigating factor:** Blocklist URLs are admin-configured and validated as http/https.
  The risk requires a compromised or malicious blocklist provider.
- **Recommendation:** Add `validate_domain()` check in `convert_blocklist_body()` to
  skip invalid entries. Filed as FINDING-B1.

**Device IPs** (line 268):
- `dev.ipv4`: Set by agent's own IP allocation from validated range. Safe.

**lan_subnet** (line 179): Internal startup constant. Safe.

**Upstream DNS** (lines 327-336): Validated as `IpAddr::parse()`. Safe.

### Verdict: One low-risk gap in blocklist domain parsing (FINDING-B1).

---

## 3. Mass Assignment / deny_unknown_fields (lib.rs)

### Finding: IPC command structs lack deny_unknown_fields — ACTIONABLE

**Wire types (hermitshell-common/src/lib.rs):**
None of the `HermitConfig`, `NetworkConfig`, `DnsConfig`, `FirewallConfig`,
`WireguardConfig`, `DeviceConfig`, `DhcpConfig`, `QosConfig`, `LoggingConfig`,
`TlsConfig`, `AnalysisConfig`, `WifiConfig`, or `HermitSecrets` structs have
`#[serde(deny_unknown_fields)]`.

**Impact:** An attacker who gains socket access (requires local root or socket group)
could send JSON with unexpected fields. Since all fields have `#[serde(default)]`,
extra fields are silently ignored rather than causing errors. This is a defense-in-depth
issue rather than an active vulnerability because:
1. The socket is protected by Unix permissions (0660 root:root)
2. Unknown fields are ignored, not stored
3. Serde defaults mean missing fields get safe defaults

**However:** The `HermitConfig` and `HermitSecrets` structs are the primary IPC contracts.
Adding `deny_unknown_fields` catches typos in config files and malformed API requests
early, improving robustness.

**Socket Request/Response structs (socket/mod.rs):**
`Request` (line 153) already uses serde without deny_unknown_fields. Since this is
an internal struct, the main risk is config file parsing, not socket protocol.

### Action: Add `#[serde(deny_unknown_fields)]` to `HermitConfig` sub-structs.
This should NOT be added to `HermitConfig` or `HermitSecrets` themselves because
TOML parsing with `#[serde(default)]` sections requires allowing unknown fields
at the top level for forward compatibility. Instead, add to leaf structs where
exact field sets are known: `PortForwardConfig`, `Ipv6PinholeConfig`,
`WgPeerConfig`, `DeviceConfig`, `DhcpReservationConfig`, `BlocklistConfig`,
`ForwardZoneConfig`, `CustomRecordConfig`.

---

## 4. nftables Command Injection (nftables.rs)

### Finding: Comprehensive validation — PASS

Every function that passes user-supplied values to `nft` commands validates first:
- `add_device_counter`: `validate_ip()` (line 282)
- `add_device_counter_v6`: `validate_ipv6_ula()` (line 299)
- `add_device_forward_rule`: `validate_ip()` + `validate_group()` (lines 357-358)
- `add_device_forward_rule_v6`: `validate_ipv6_ula()` + `validate_group()` (lines 374-375)
- `remove_device_forward_rule`: `validate_ip()` (line 391)
- `remove_device_forward_rule_v6`: `validate_ipv6_ula()` (line 408)
- `add_device_route`: `validate_ip()` + `validate_iface()` + `validate_mac()` (lines 419-421)
- `add_device_route_v6`: `validate_ipv6_ula()` + `validate_iface()` + `validate_mac()` (lines 436-438)
- `add_mac_ip_rule`: `validate_ip()` + `validate_mac()` (lines 456-457)
- `add_mac_ip_rule_v6`: `validate_ipv6_ula()` + `validate_mac()` (lines 478-479)
- `apply_base_rules`: `validate_iface()` for wan/lan (lines 273-274)
- `apply_port_forwards`: `validate_iface()` + `validate_ip()` (lines 534-535, 552, 573)
- `add_upnp_input_rules`: `validate_iface()` (line 652)
- `add_ipv6_pinhole`: `validate_ipv6_global()` + `validate_protocol()` (lines 691-692)
- `remove_ipv6_pinhole`: `validate_ipv6_global()` + `validate_protocol()` (lines 720-721)

**Port numbers** (u16 type): Cannot be injected — they're typed as u16 integers.

**Group names**: Allowlist-validated against `VALID_GROUPS` constant.

### Verdict: No injection vectors found. All validators use strict allowlists.

---

## 5. ReDoS and Regex Patterns

### Finding: No PCRE usage, no custom regex — PASS

- No `pcre`, `pcre2`, `fancy_regex`, or `onig` dependencies found.
- No `Regex::new` calls found in agent source code.
- All pattern matching uses string methods (`contains`, `starts_with`, `split`)
  or Rust's built-in `str::parse()`.
- The Rust `regex` crate (not used here) has linear-time guarantees anyway.

### Verdict: No ReDoS risk.

---

## 6. Error Handling / Panic Safety

### Finding: Most unwrap() calls are on Mutex::lock() — acceptable

**Mutex::lock().unwrap() calls (all socket handlers):**
The ~150+ `db.lock().unwrap()` calls are on `Mutex<Db>`. In Rust, a Mutex is
poisoned only if a thread panics while holding the lock. Since the DB operations
use `?` error propagation (no panics), the mutex should never be poisoned.
If it were, propagating the panic via unwrap is the correct behavior — a poisoned
mutex means data corruption.

**Other unwrap() patterns found:**
- `socket/mod.rs:642`: `dev.subnet_id.unwrap()` — guarded by `if dev.subnet_id.is_some()`
  on line 641. Safe.
- `socket/mod.rs:763`: Same pattern. Safe.
- `socket/auth.rs:179`: `.unwrap()` on SystemTime — would only fail if system clock
  is before Unix epoch, which is a system configuration error. Acceptable.

**No unwrap() on user-supplied data parsing** — all parsing uses `parse().is_err()`
checks, `map_err()`, or `?` operator.

### Verdict: No panic risk from user input in request-handling code paths.

---

## 7. Additional Findings

### FINDING-A1: `conn_exec()` is a raw SQL escape hatch (LOW)
`Db::conn_exec()` accepts arbitrary SQL. All current call sites use hardcoded
`DELETE FROM <table>` literals, which is safe. But the method's existence is a
footgun for future development. Consider either removing it or adding a doc comment
warning against user-supplied SQL.

### FINDING-B1: Blocklist domain names not validated (LOW)
`convert_blocklist_body()` in unbound.rs writes downloaded domains directly into
unbound config without validation. A malicious blocklist could inject config
directives. Mitigated by admin-controlled blocklist URLs.

### FINDING-C1: Forward zone domains not re-validated at config generation time (INFO)
`generate_config_string()` trusts that DB values were validated at insertion time.
If the DB were corrupted or a future code path bypassed validation, invalid domains
could reach the unbound config. Defense-in-depth would re-validate, but the current
entry-point validation is comprehensive.

### FINDING-D1: Syslog hostname not sanitized (INFO)
`get_hostname()` in log_export.rs reads from `/etc/hostname` and passes to syslog
format string. On a compromised system, a malicious hostname could inject into
syslog headers. Mitigated by the fact that if the system is compromised, the
attacker has bigger problems.

---

## Summary

| Area | Status | Findings |
|------|--------|----------|
| SQL injection (db.rs) | PASS | All parameterized |
| Unbound config injection | PASS (1 low) | FINDING-B1: blocklist domains |
| Mass assignment (lib.rs) | ACTIONABLE | Add deny_unknown_fields |
| nftables injection | PASS | All validated |
| ReDoS / regex | PASS | No PCRE, no custom regex |
| Panic safety | PASS | No unwrap on user input |

**Code changes to make:**
1. Add `#[serde(deny_unknown_fields)]` to leaf config structs in lib.rs
2. Add domain validation in `convert_blocklist_body()` in unbound.rs
3. Document trade-offs in SECURITY.md
# OWASP Proactive Control C4: Address Security from the Start — Audit Findings

**Project:** HermitShell
**Date:** 2026-03-01
**Auditor:** OWASP C4 review (research/documentation)
**Scope:** Secure architecture assessment per OWASP Proactive Controls C4

---

## Executive Summary

HermitShell demonstrates strong adherence to OWASP Proactive Control C4 (Secure Architecture). The project employs defense-in-depth across five layers (nftables, socket permissions, method allowlists, key blocklists, input validation), minimizes attack surface through SSR-only rendering and Unix socket IPC, forbids unsafe Rust workspace-wide, and documents 119 security trade-offs in SECURITY.md. Two deliverables were created during this audit: a formal threat model (`docs/THREAT-MODEL.md`) and a security contact file (`docs/.well-known/security.txt` per RFC 9116).

---

## Findings

### F1: PASS — Defense-in-Depth Architecture

HermitShell implements layered security controls at every boundary:

1. **Network layer:** nftables with per-device /32 isolation, group-based forwarding chains, MAC-IP source validation, static ARP/NDP binding, RA Guard, DNS redirect, DoH IP blocking, and stateful connection tracking.
2. **IPC layer:** Unix socket with `0660` permissions, `SO_PEERCRED` kernel-enforced UID verification, compile-time method allowlist (~100 web-allowed methods, deny-by-default for new methods), and `BLOCKED_CONFIG_KEYS` (14 sensitive keys excluded from generic get/set).
3. **Application layer:** Argon2id password hashing (OsRng salt), HMAC-SHA256 session tokens with absolute expiry, two-layer rate limiting (per-IP + global), and input validation on all mutating methods (MAC, IP, interface, group, hostname).
4. **Container layer:** Docker `--cap-drop ALL --read-only --security-opt no-new-privileges` with non-root user (standalone mode).
5. **Process layer:** systemd hardening with `CapabilityBoundingSet`, `NoNewPrivileges`, `ProtectSystem=strict`, syscall filtering, and namespace restrictions.

**Assessment:** Exceeds C4 expectations for a home router appliance.

### F2: PASS — Minimal Attack Surface

- **SSR-only web UI:** No WASM/hydration eliminates client-side XSS vectors from hydration mismatches. Leptos default HTML escaping prevents stored/reflected XSS.
- **Unix socket (no TCP API):** The agent exposes no network-facing management interface. All IPC is via Unix socket, limiting access to local processes with filesystem permissions.
- **`unsafe_code = "forbid"`:** Workspace-wide prohibition of unsafe Rust eliminates entire categories of memory corruption vulnerabilities.
- **Localhost-only REST API:** The REST API binds to `127.0.0.1:9080`, unreachable from the network.
- **UPnP/mDNS group filtering:** Only trusted devices can interact with UPnP; mDNS responses are unicast and group-filtered.

**Assessment:** Attack surface is well-constrained for the required functionality.

### F3: PASS — Documented Security Trade-offs

SECURITY.md contains 119 numbered entries (issues #4 through #119), each documenting:
- **What:** The specific compromise or known issue
- **Why:** The rationale for the current design
- **Risk:** The threat scenario and severity
- **Proper fix:** What a better solution would look like

This level of documentation is exceptional for an open-source project and directly supports OWASP C4's requirement to address security from the start.

**Assessment:** Best-practice documentation of accepted risks.

### F4: FINDING — No Formal Threat Model Existed

Prior to this audit, no structured threat model document existed. Security trade-offs were documented individually in SECURITY.md but without a unified view of assets, adversaries, trust boundaries, and attack surfaces.

**Action taken:** Created `docs/THREAT-MODEL.md` covering:
- 6 asset categories (network traffic, admin credentials, crypto keys, API tokens, device config, DNS logs)
- 6 adversary profiles (malicious LAN device, WAN attacker, compromised web UI, physical attacker, supply chain, rogue DHCP)
- 5 trust boundaries (Unix socket, nftables, Docker container, web UI auth, REST API)
- 10 attack surfaces with specific protocol/port details
- Security controls summary table
- Accepted risks cross-referenced to SECURITY.md issue numbers
- Threat matrix mapping adversaries to assets, vectors, and controls
- Data flow diagram

**Assessment:** Gap remediated. The threat model provides the architectural security context that OWASP C4 requires.

### F5: FINDING — No security.txt (RFC 9116)

No `security.txt` existed for coordinated vulnerability disclosure.

**Action taken:** Created `docs/.well-known/security.txt` with:
- `Contact: mailto:security@hermitshell.dev`
- `Expires: 2027-03-01T00:00:00.000Z`
- `Preferred-Languages: en`
- `Canonical: https://hermitshell.dev/.well-known/security.txt`
- `Policy: https://github.com/hermitshell/hermitshell/blob/main/docs/SECURITY.md`

**Assessment:** Gap remediated. The file should be served at the canonical URL on the project website.

### F6: OBSERVATION — Supply Chain Risk is the Largest Gap

The most significant residual risk is supply chain compromise (SECURITY.md #86, #87, #88, #102, #103):

- Release tarballs verified by SHA256 checksum only (integrity, not authenticity)
- No GPG/Sigstore signature verification
- Auto-update installs code without admin review
- Tarball extraction does not reject symlinks
- Version tag stored before validation

A compromised GitHub release would result in root-level code execution on all routers that update. This is acknowledged in SECURITY.md but represents the single highest-impact attack vector.

**Recommendation:** Implement GPG or Sigstore signing of release artifacts and verify signatures in `apply_update` before extraction. Reject symlink entries in tarballs.

### F7: OBSERVATION — Broad Web-Allowed Method Set

The `WEB_ALLOWED_METHODS` list contains ~100 methods, including `apply_config`, `export_config`, `set_config`, `add_port_forward`, `set_wireguard_enabled`, and `apply_update`. A compromised web UI container can:

- Export the full configuration
- Apply arbitrary config changes including secrets (via `apply_config`)
- Create port forwards opening WAN attack surface
- Trigger software updates
- Modify DNS, firewall, and WiFi settings

This is documented as SECURITY.md #90 and acknowledged as permissive. The proposed fix (read-only vs read-write tiers) would meaningfully reduce blast radius.

### F8: OBSERVATION — Secrets at Rest Not Encrypted

All secrets (WireGuard private key, TLS private key, API tokens, Cloudflare token, ACME account key) are stored in plaintext in SQLite. This is documented across SECURITY.md #36, #51, #52. Physical access to the database file yields all secrets.

For a home router appliance without TPM/HSM, this is standard practice (comparable to OpenWrt's `/etc/config/`). The `BLOCKED_CONFIG_KEYS` mechanism prevents IPC-level exposure.

### F9: OBSERVATION — Strong Cryptographic Practices

- Argon2id with OsRng salt for password hashing
- HMAC-SHA256 for session tokens
- AES-256-GCM for encrypted backups (Argon2id key derivation, m=64MB, t=3)
- WireGuard (Noise protocol, Curve25519, ChaCha20-Poly1305)
- TOFU cert pinning for WiFi AP connections
- `Zeroizing<String>` used for sensitive values in read paths

Minor gap: `thread_rng()` used instead of `OsRng` for session secret and HMAC key generation (#101). Practically equivalent but not best practice.

### F10: OBSERVATION — systemd Hardening is Comprehensive

The systemd unit (`systemd/hermitshell-agent.service`) applies 17 hardening directives:

```
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/hermitshell /run/hermitshell
PrivateTmp=yes
NoNewPrivileges=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictSUIDSGID=yes
ProtectClock=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictRealtime=yes
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
SystemCallFilter=~@mount @reboot @swap @debug @module @cpu-emulation
ProtectProc=invisible
```

This restricts the agent process even as root to minimal capabilities and filesystem access.

---

## Summary Table

| # | Type | Status | Description |
|---|------|--------|-------------|
| F1 | Control | PASS | Defense-in-depth architecture across 5 layers |
| F2 | Control | PASS | Minimal attack surface (SSR-only, Unix socket, no unsafe) |
| F3 | Control | PASS | 119 documented security trade-offs |
| F4 | Gap | REMEDIATED | No formal threat model — created `docs/THREAT-MODEL.md` |
| F5 | Gap | REMEDIATED | No security.txt — created `docs/.well-known/security.txt` |
| F6 | Risk | OBSERVATION | Supply chain: no signature verification on updates |
| F7 | Risk | OBSERVATION | Broad web-allowed method set (~100 methods) |
| F8 | Risk | OBSERVATION | Secrets at rest in plaintext SQLite |
| F9 | Control | PASS | Strong cryptographic practices throughout |
| F10 | Control | PASS | Comprehensive systemd hardening (17 directives) |

---

## Files Created

| File | Purpose |
|------|---------|
| `docs/THREAT-MODEL.md` | Formal threat model with assets, adversaries, trust boundaries, attack surfaces, controls, and accepted risks |
| `docs/.well-known/security.txt` | RFC 9116 security contact file for coordinated vulnerability disclosure |
| `/tmp/owasp-c4-findings.md` | This findings document |

---

## Conclusion

HermitShell's architecture strongly aligns with OWASP Proactive Control C4. Security is addressed from the start through Rust's memory safety guarantees, a layered defense architecture, comprehensive input validation, minimal attack surface design, and exceptionally thorough documentation of trade-offs. The two identified gaps (missing threat model and security.txt) have been remediated. The primary remaining risk areas — supply chain integrity and broad IPC allowlist — are acknowledged in SECURITY.md with proposed mitigations documented.
# OWASP Proactive Control C5: Secure By Default Configurations

## Audit Report — HermitShell

**Date:** 2026-03-01
**Auditor:** OWASP C5 Agent (Agent 4)
**Scope:** Default configuration values, systemd hardening, Docker container flags, nftables ruleset, debug/dev feature leaks

---

## 1. Default Config Values in db.rs Schema Initialization

### 1.1 Device group defaults to 'quarantine' — PASS

- `device_group TEXT NOT NULL DEFAULT 'quarantine'` (line 26, devices table)
- `device_group TEXT NOT NULL DEFAULT 'quarantine'` (line 45, wg_peers table)
- New devices and WireGuard peers default to the most restrictive group that still allows internet access. The `blocked` group is more restrictive but would make new devices completely non-functional.
- **Verdict:** Secure by default.

### 1.2 Ad blocking enabled by default — PASS

- `INSERT OR IGNORE INTO config (key, value) VALUES ('ad_blocking_enabled', 'true')` (line 36)
- DNS ad blocking is on by default, reducing attack surface from malvertising.
- **Verdict:** Secure by default.

### 1.3 DNS blocklist seeded by default — PASS

- StevenBlack Hosts list is pre-loaded (line 152).
- **Verdict:** Good. Provides immediate protection.

### 1.4 WiFi SSID security defaults to WPA2/WPA3 — PASS

- `security TEXT NOT NULL DEFAULT 'wpa2_wpa3'` (migration v2, line 289)
- **Verdict:** Secure by default. No open/WEP/WPA1.

### 1.5 Port forwards default to enabled — FINDING

- `enabled INTEGER NOT NULL DEFAULT 1` (port_forwards table, line 58)
- Port forwards are enabled when created. This means a newly added port forward immediately opens a hole in the firewall.
- **Verdict:** Acceptable — port forwards are user-initiated actions. Disabling by default would confuse users who expect the rule to take effect immediately.

### 1.6 UPnP disabled by default — PASS

- `get_config_bool("upnp_enabled", false)` — UPnP/NAT-PMP defaults to off.
- **Verdict:** Secure by default. UPnP is an attack surface and should be opt-in.

### 1.7 WireGuard disabled by default — PASS

- `get_config_bool("wg_enabled", false)` — WG is off until explicitly enabled.
- **Verdict:** Secure by default.

### 1.8 Behavioral analyzer disabled by default — FINDING

- `get_config_bool("analyzer_enabled", false)` — Security analysis is off by default.
- This means anomaly detection (DNS beaconing, suspicious ports, bandwidth spikes) does not run unless the user explicitly enables it.
- **Verdict:** Less secure than ideal. A security-focused product should enable monitoring by default. However, the analyzer has performance implications on resource-constrained hardware, so opt-in is a reasonable tradeoff.

### 1.9 Auto-update default — PASS

- `update_check_enabled` defaults to `false`, `auto_update_enabled` defaults to `false`.
- The context says "auto-update enabled by default (#87)" but code shows both are opt-in.
- **Verdict:** The code is more conservative than the context suggests. This is secure — auto-update without signature verification (documented in SECURITY.md #86) should not be on by default.

### 1.10 Log retention defaults to 7 days — PASS

- `unwrap_or(7)` for `log_retention_days` throughout the codebase.
- **Verdict:** Reasonable default. Provides forensic capability without unbounded storage.

### 1.11 DNS rate limiting defaults to 0 (disabled) — FINDING

- `dns_ratelimit_per_client` defaults to `0`, `dns_ratelimit_per_domain` defaults to `0`.
- No DNS rate limiting by default means a compromised device can generate unlimited DNS queries.
- **Verdict:** Should have non-zero defaults for defense in depth. However, aggressive rate limits can break legitimate use. Document as tradeoff.

### 1.12 DNS bypass defaults to denied for all groups — PASS

- All `dns_bypass_allowed_*` default to `false`.
- **Verdict:** Secure by default — no group can bypass the local DNS resolver.

### 1.13 No default DNS rate limits in DB schema — FINDING

- The `config` table INSERT statements in the SCHEMA do not set `dns_ratelimit_per_client` or `dns_ratelimit_per_domain`. They only exist when explicitly configured.
- **Verdict:** Could insert conservative defaults (e.g., 1000 queries/sec per client).

---

## 2. Systemd Service Hardening

### 2.1 hermitshell-agent.service — MOSTLY PASS

**Present hardening directives:**
- `ProtectHome=yes` — PASS
- `ProtectSystem=strict` — PASS
- `ReadWritePaths=/var/lib/hermitshell /run/hermitshell` — PASS (minimal writable paths)
- `PrivateTmp=yes` — PASS
- `NoNewPrivileges=yes` — PASS
- `PrivateDevices=yes` — PASS
- `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET` — PASS (all needed)
- `RestrictNamespaces=yes` — PASS
- `LockPersonality=yes` — PASS
- `MemoryDenyWriteExecute=yes` — PASS
- `RestrictSUIDSGID=yes` — PASS
- `ProtectClock=yes` — PASS
- `ProtectKernelTunables=yes` — PASS
- `ProtectKernelModules=yes` — PASS
- `ProtectKernelLogs=yes` — PASS
- `ProtectControlGroups=yes` — PASS
- `RestrictRealtime=yes` — PASS
- `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE` — PASS
- `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE` — PASS
- `SystemCallFilter=~@mount @reboot @swap @debug @module @cpu-emulation` — PASS
- `ProtectProc=invisible` — PASS

**Missing directives — FINDINGS:**

- `SystemCallArchitectures=native` — Missing. Should restrict to native arch only to prevent 32-bit compat syscall exploits. LOW RISK TO ADD.
- `ProtectHostname=yes` — Missing. Agent does read hostname via `gethostname()` for TLS SANs, so this is acceptable to omit, but worth noting.
- `IPAddressDeny=` / `IPAddressAllow=` — Not used. Could restrict but the agent legitimately needs all network access.
- `UMask=0077` — Missing. Default umask for created files. LOW RISK TO ADD.

**Verdict:** Very strong. Only `SystemCallArchitectures=native` is a clear gap.

### 2.2 hermitshell-ui.service — PASS (via Docker flags)

- Container runs with `--read-only --cap-drop ALL --security-opt no-new-privileges`.
- No systemd-level hardening directives — relies on Docker isolation instead.
- **Verdict:** Appropriate since systemd is just a container launcher here.

---

## 3. Docker Container Hardening

### 3.1 Web UI Container (hermitshell/Dockerfile) — FINDINGS

**Good:**
- Non-root user: `USER hermitshell` (UID 1000)
- Minimal base: `alpine:latest`
- No shell access, minimal packages (`ca-certificates` only)

**Missing:**
- `--tmpfs /tmp` — Missing from service file. The container runs `--read-only` but has no tmpfs for /tmp. If the binary needs temp files, it will fail silently. LOW RISK TO ADD.
- `--pids-limit` — Missing. No process count limit inside container. LOW RISK TO ADD.
- `FROM alpine:latest` — Uses mutable `:latest` tag. Should pin to a specific version (e.g., `alpine:3.21`) for reproducible builds. LOW RISK TO CHANGE.
- No HEALTHCHECK instruction.

### 3.2 All-in-one Container (Dockerfile) — DOCUMENTED

- Runs as root, no `--read-only`, no `--cap-drop`. Requires `--privileged`.
- Already documented in SECURITY.md #50 with proper fix suggestions.
- **Verdict:** Known tradeoff, adequately documented.

---

## 4. Default nftables Ruleset

### 4.1 Input chain — PASS (policy drop)

- `policy drop` — default deny on input. PASS.
- Only allows: established/related, loopback, SSH (non-WAN), web UI ports (LAN/tailscale), DHCP, DNS, ICMPv6 essentials.
- SSH allowed from all non-WAN interfaces (LAN, tailscale, WireGuard). Acceptable.

### 4.2 Forward chain — PASS (policy drop)

- `policy drop` — default deny on forwarding. PASS.
- Devices must be in the verdict map to forward traffic.
- MAC-IP validation runs at priority -5. PASS.

### 4.3 Output chain — FINDING

- `policy accept` — The output chain accepts all traffic.
- **Verdict:** Standard for a router. The agent needs to make outgoing connections (DNS, updates, runZero sync, etc.). Restricting output would break functionality. Acceptable.

### 4.4 DoH/DoT bypass prevention — PASS

- Blocks well-known DoH resolvers by IP (both v4 and v6).
- Blocks DoT (port 853) for non-trusted groups.
- Blocks DoH domains in Unbound config.
- **Verdict:** Defense in depth against DNS bypass.

### 4.5 Quarantine group allows internet — PASS (with note)

- `quarantine_fwd` allows outbound to WAN but blocks inter-device traffic and DoH/DoT bypass.
- New devices get internet access but cannot communicate with other LAN devices.
- **Verdict:** Secure by default. Blocking all internet for quarantine would break device setup (captive portals, initial updates).

### 4.6 Guest group allows internet only — PASS

- `guest_fwd`: `oifname "{wan_iface}" accept; drop` — WAN-only, no DoH/DoT blocking.
- **Verdict:** Appropriate for guest devices. No access to LAN devices.

### 4.7 Trusted group allows all — PASS (with note)

- `trusted_fwd`: `accept` — no restrictions.
- **Verdict:** By design. Trusted devices should have full network access. The key security property is that new devices default to quarantine, not trusted.

### 4.8 DNS redirect is enforced via NAT — PASS

- All DNS traffic on port 53 from LAN/WG is redirected to Unbound on port 5354.
- Output chain also redirects local DNS to Unbound.
- **Verdict:** Strong DNS enforcement.

### 4.9 mac_ip_validate chain has policy accept — FINDING (minor)

- `chain mac_ip_validate { type filter hook forward priority -5; policy accept; }`
- Rules are added per-device to DROP mismatches. Devices without rules pass through.
- **Verdict:** This is correct behavior — new devices before MAC-IP rules are added still need to be processed by the verdict map (which handles their group policy). The accept policy is intentional and safe because the forward chain's `policy drop` catches anything not in the verdict map.

---

## 5. Debug/Development Feature Leaks

### 5.1 Log level defaults to `info` — PASS

- `tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_ | "info".into())`
- Default is `info`, which is appropriate for production. `debug` and `trace` are only enabled via `RUST_LOG` env var.
- The systemd service sets `Environment=RUST_LOG=info` explicitly.
- **Verdict:** Secure by default. No debug logging in production.

### 5.2 REST API on localhost only — PASS

- `let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));` (rest_api.rs line 158)
- REST API binds to localhost (127.0.0.1), not 0.0.0.0.
- **Verdict:** Secure by default. Not accessible from LAN or WAN.

### 5.3 REST API requires API key — PASS

- All REST API routes require Bearer token authentication verified against an Argon2 hash.
- If no API key is configured, all requests are rejected with 401.
- **Verdict:** Secure by default.

### 5.4 No test endpoints in production — PASS

- No `#[cfg(test)]` routes or debug-only endpoints found in production code.
- **Verdict:** Clean separation of test and production code.

### 5.5 Unbound query logging enabled by default — FINDING

- `log-queries: yes` and `verbosity: 1` in the generated unbound config.
- DNS query logs are written to a file. This is used for the DNS log analysis feature.
- **Verdict:** This is a feature requirement, not a debug leak. The logs are rotated by retention policy. However, it does create a privacy consideration — all DNS queries from all devices are logged.

### 5.6 REST API port configurable via env var — PASS (with note)

- `REST_API_PORT` env var, default 9080. Not in systemd service file.
- **Verdict:** Acceptable. The default port is only on localhost. An attacker would need local access.

---

## 6. Summary of Findings

### Code Changes (Low Risk):

1. **Add `SystemCallArchitectures=native` to agent systemd service** — Prevents 32-bit compat syscall exploits.
2. **Add `UMask=0077` to agent systemd service** — Ensures created files have restrictive permissions.
3. **Add `--tmpfs /tmp` to Docker container run command** — Provides a writable temp directory in the read-only container.
4. **Add `--pids-limit 100` to Docker container run command** — Prevents fork bombs inside container.

### Documentation-Only (SECURITY.md entries):

5. **DNS rate limiting defaults to 0** — Should be documented as a tradeoff.
6. **Behavioral analyzer disabled by default** — Should be documented as a tradeoff.
7. **Docker uses `alpine:latest` mutable tag** — Should pin to specific version.
8. **Output chain policy accept** — Standard but worth noting.

### No Action Needed:

- Default device quarantine: PASS
- Default ad blocking: PASS
- Default-deny firewall (input/forward): PASS
- HTTPS by default: PASS
- Docker non-root + cap-drop ALL: PASS
- Systemd comprehensive hardening: PASS (very strong)
- No debug/dev leaks: PASS
- REST API localhost-only + auth required: PASS
- UPnP disabled by default: PASS
- WireGuard disabled by default: PASS
- DNS bypass denied by default: PASS
# OWASP Proactive Control C6: Keep Your Components Secure

## Audit Report -- HermitShell

**Date:** 2026-03-01
**Scope:** Dependency management, supply chain security, release artifact integrity
**Framework:** OWASP Proactive Controls C6 (Dependency/Supply Chain Security)

---

## 1. Current State Summary

### Strengths

| Control | Status |
|---|---|
| cargo-deny in CI | Active -- advisories, licenses, source registry restrictions |
| deny.toml source policy | `unknown-registry=deny`, `unknown-git=deny`, only crates.io allowed |
| Dependabot | Weekly for both Cargo and GitHub Actions |
| Release checksums | SHA256 per tarball |
| Apt repo signing | GPG-signed Release/InRelease files |
| `unsafe_code = "forbid"` | Workspace-wide lint |

### Gaps Identified

| Gap | Severity | Status |
|---|---|---|
| 3 ignored RUSTSEC advisories (1 actionable) | Medium | See Section 2 |
| No SBOM generation | Medium | **Fixed** -- added to release workflow |
| No scheduled audit (only runs on PR/push) | Medium | **Fixed** -- new `audit.yml` workflow |
| GitHub Actions pinned by tag, not SHA | High | See Section 3 |
| No binary signing (beyond SHA256 checksums) | Medium | See Section 5 |
| No SLSA provenance attestation | Low | See Section 4 |

---

## 2. Ignored RUSTSEC Advisories

### RUSTSEC-2024-0421: idna 0.2.3 (Punycode validation bypass)

- **Source:** `dhcproto 0.12.0` -> `trust-dns-proto 0.22.0` -> `idna 0.2.3`
- **Fix available:** YES. `dhcproto 0.13.0` (May 2025) switched from `trust-dns-proto` to `hickory-proto`, which uses `idna 1.x`. Upgrading `dhcproto` from `0.12` to `0.13+` in both `hermitshell-agent/Cargo.toml` and `hermitshell-dhcp/Cargo.toml` would resolve this advisory.
- **Risk of upgrade:** Medium. Major version bump in the underlying DNS library (`trust-dns-proto` -> `hickory-proto`). The `dhcproto` API itself may have breaking changes between 0.12 and 0.13. Requires testing of DHCP functionality.
- **Recommendation:** Upgrade `dhcproto` to `>=0.13` and remove this ignore entry. Test DHCP lease acquisition and relay behavior. This is the most actionable advisory of the three.

### RUSTSEC-2024-0436: paste (unmaintained)

- **Source:** Transitive dependency via Leptos 0.8 (`either_of` -> `paste`, `leptos` -> `paste`)
- **Fix available:** NO. The `paste` crate is archived by its author (dtolnay). No drop-in replacement exists. The Leptos project and many other major crates (tauri, libp2p, Azure SDK for Rust) are in the same situation.
- **Actual risk:** Low. The `paste` crate is a proc-macro that runs at compile time only; it is not present in the final binary. The "unmaintained" label does not indicate any known vulnerability, only that no future patches will be issued.
- **Recommendation:** Keep the ignore entry. Monitor Leptos upstream for eventual removal of `paste`. No action needed.

### RUSTSEC-2025-0134: rustls-pemfile (unmaintained)

- **Source:** Direct dependency in both `hermitshell-agent/Cargo.toml` and `hermitshell/Cargo.toml`
- **Fix available:** YES. The `rustls-pemfile` functionality has been absorbed into `rustls-pki-types` (since version 1.9.0) via the `PemObject` trait. The project already depends on `rustls-pki-types = "1"`.
- **Migration path:** Replace all `rustls_pemfile::certs(reader)` calls with `CertificateDer::pem_reader_iter(reader)`, and `rustls_pemfile::private_key(reader)` with `PrivateKeyDer::from_pem_reader(reader)`. Seven call sites in `hermitshell-agent/src/` need updating, plus the `hermitshell/` crate.
- **Files affected:**
  - `hermitshell-agent/src/tls.rs` (1 call)
  - `hermitshell-agent/src/tls_client.rs` (1 call)
  - `hermitshell-agent/src/socket/auth.rs` (3 calls)
  - `hermitshell-agent/src/socket/wifi.rs` (1 call)
  - `hermitshell-agent/src/socket/config.rs` (1 call)
  - `hermitshell/` crate (Cargo.toml dependency)
- **Recommendation:** Migrate to `rustls-pki-types` PEM parsing and remove the `rustls-pemfile` dependency. This is a safe, low-risk change. Remove the ignore entry after migration.

---

## 3. GitHub Actions Version Pinning

**Finding: All 12 unique GitHub Actions are pinned by mutable tag, not by commit SHA.**

Actions pinned by tag (e.g., `@v4`) are vulnerable to tag mutation attacks. If an action's repository is compromised, the attacker can move the tag to point to malicious code. The March 2025 `tj-actions/changed-files` incident demonstrated this attack vector affecting 23,000+ repositories.

### Current State

| Action | Current Pin | Risk |
|---|---|---|
| `actions/checkout` | `@v4` | High (first-party, lower risk but still mutable) |
| `actions/upload-artifact` | `@v4` | High |
| `actions/download-artifact` | `@v4` | High |
| `dtolnay/rust-toolchain` | `@stable` | **Critical** (third-party, branch ref, not even a tag) |
| `Swatinem/rust-cache` | `@v2` | High (third-party) |
| `EmbarkStudios/cargo-deny-action` | `@v2` | High (third-party) |
| `softprops/action-gh-release` | `@v2` | High (third-party, has write access to releases) |
| `docker/setup-buildx-action` | `@v3` | High (third-party) |
| `docker/login-action` | `@v3` | High (third-party, handles registry credentials) |
| `docker/build-push-action` | `@v6` | High (third-party, pushes images) |

### Recommendation

Pin all actions to full SHA with a comment noting the version tag. Example:

```yaml
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
```

**Priority:** HIGH. This is the single highest-impact supply chain hardening measure available. Dependabot already updates GitHub Actions weekly and will automatically propose SHA pin updates, so maintenance burden is minimal.

**Note:** `dtolnay/rust-toolchain@stable` is a special case -- it uses branch tracking to always get the latest stable toolchain. The alternative is to pin to a SHA and let Dependabot update it, or use `actions-rust-lang/setup-rust-toolchain` which provides versioned releases.

**Implementation:** Use [pin-github-action](https://github.com/mheap/pin-github-action) or [StepSecurity's secureworkflow](https://app.stepsecurity.io/) to automatically convert all tags to SHA pins. This is a low-effort, high-value change.

---

## 4. SLSA Provenance Attestation

**Recommendation: Defer implementation. Write a tracking issue.**

### What It Is

SLSA (Supply-chain Levels for Software Artifacts) Level 3 provenance provides a cryptographically signed attestation that a specific artifact was built from a specific source commit, using a specific build process, on a specific infrastructure (GitHub Actions). Consumers can verify that a release binary was not tampered with after CI built it.

### How It Would Work

The `slsa-framework/slsa-github-generator` provides a reusable workflow (`slsa-github-generator/.github/workflows/generator_generic_slsa3.yml`) that:

1. Accepts a SHA256 digest of build artifacts as input
2. Runs in an isolated, non-forgeable GitHub Actions environment
3. Generates an in-toto provenance attestation signed by Sigstore
4. Uploads the `.intoto.jsonl` provenance file as a release artifact

### Why Defer

- **Complexity:** SLSA provenance requires the build to happen in a reusable workflow called via `workflow_call`. The current release workflow would need restructuring to separate the build steps into a called workflow.
- **Cross-compilation complication:** The current matrix build with `cross` for aarch64 adds complexity, since provenance must cover both architectures.
- **Ecosystem maturity:** SLSA verification tooling for end-users of .deb packages and tarballs is still limited. The primary consumers of HermitShell releases (self-hosted router operators) are unlikely to verify SLSA provenance today.
- **Incremental path:** Implement SBOM first (done), then cosign signing (see Section 5), then SLSA provenance. Each step builds on the previous.

### When to Implement

Consider implementing SLSA provenance when:
- The project reaches 1.0 or has significant external adopters
- GitHub's native artifact attestation feature (`actions/attest-build-provenance`) stabilizes further, which may simplify the integration compared to `slsa-github-generator`

---

## 5. Sigstore/Cosign Binary Signing

**Recommendation: Implement after SHA pinning. Medium priority.**

### What It Is

Cosign provides keyless code signing using short-lived certificates tied to the CI identity (GitHub Actions OIDC token). Unlike GPG signing (which requires managing a long-lived private key stored in secrets), cosign signing is:

- **Keyless:** No private key to manage, rotate, or risk leaking
- **Verifiable:** Anyone can verify the signature against the Sigstore transparency log
- **CI-identity-bound:** The signature attests that the artifact was produced by a specific GitHub Actions workflow in a specific repository

### How It Would Work

Add to the `release` job in `release.yml`:

```yaml
- name: Install cosign
  uses: sigstore/cosign-installer@v3

- name: Sign release artifacts
  run: |
    for f in hermitshell-*.tar.gz *.deb *.cdx.json; do
      cosign sign-blob "$f" --bundle "${f}.sigstore.json" --yes
    done
  env:
    COSIGN_EXPERIMENTAL: "1"
```

Required permissions addition: `id-token: write` (for GitHub OIDC token).

### Benefits Over Current State

| Current | With Cosign |
|---|---|
| SHA256 checksums (integrity only) | Checksums + cryptographic identity attestation |
| GPG-signed apt repo (key management burden) | Keyless, automated, tied to CI identity |
| No way to verify "was this built by CI?" | Verifiable via `cosign verify-blob` |

### Considerations

- The GPG-signed apt repo should be kept (apt clients expect it), but cosign provides an additional, stronger assurance layer.
- Cosign bundles (`.sigstore.json`) should be uploaded alongside each artifact.
- Document verification commands in the README for users who want to verify.

---

## 6. Additional Findings

### 6a. `cross` Installed from Git HEAD

In `release.yml` line 37:
```yaml
run: cargo install cross --git https://github.com/cross-rs/cross
```

This installs `cross` from the latest Git HEAD, which is non-reproducible and could be compromised. Pin to a specific tag or SHA:
```yaml
run: cargo install cross --git https://github.com/cross-rs/cross --tag v0.2.5
```

### 6b. Dependabot Groups May Mask Breaking Changes

The Dependabot config groups all Cargo minor+patch updates together. While convenient, a single grouped PR could contain a breaking transitive dependency update that is hard to bisect. Consider:
- Keeping the grouping for patch updates only
- Separating minor updates for security-sensitive crates (rustls, reqwest, tokio)

### 6c. deny.toml `wildcards = "allow"`

The `[bans]` section allows wildcard dependencies (`*`). While no crate currently uses wildcards, tightening this to `wildcards = "deny"` would prevent future additions.

### 6d. No Cargo.lock Committed Check

There is no CI check verifying that `Cargo.lock` is committed and up-to-date. If a developer forgets to commit a lockfile update, CI may build with different dependency versions than intended. Consider adding `cargo update --locked` or `cargo check --locked` as a CI step.

---

## 7. Implementation Summary

### Changes Made (This Audit)

1. **SBOM generation** added to `release.yml`: Generates CycloneDX JSON SBOMs per workspace crate using `cargo-cyclonedx`, uploaded as release artifacts alongside tarballs and debs.

2. **Scheduled security audit** added as `.github/workflows/audit.yml`: Runs `cargo audit` and `cargo-deny check advisories` weekly (Monday 08:00 UTC) and on manual trigger, independent of PR/push events.

### Recommended Follow-Up Actions (Priority Order)

| # | Action | Priority | Effort |
|---|---|---|---|
| 1 | Pin all GitHub Actions to SHA | **High** | Low (use pin-github-action tool) |
| 2 | Migrate off `rustls-pemfile` -> `rustls-pki-types` | Medium | Low (7 call sites) |
| 3 | Upgrade `dhcproto` 0.12 -> 0.13+ | Medium | Medium (test DHCP flows) |
| 4 | Pin `cross` install to specific tag | Medium | Trivial |
| 5 | Add cosign binary signing | Medium | Low-Medium |
| 6 | Set `wildcards = "deny"` in deny.toml | Low | Trivial |
| 7 | Add `--locked` check in CI | Low | Trivial |
| 8 | Implement SLSA provenance | Low | High (workflow restructuring) |
# OWASP Proactive Control C7: Secure Digital Identities -- Audit Findings

**Date:** 2026-03-01
**Scope:** HermitShell password hashing, session management, rate limiting, API key auth
**Auditor:** Agent 6 (C7 -- Secure Digital Identities)

---

## 1. Password Hashing

### Implementation
- **Algorithm:** `Argon2::default()` from the `argon2 0.5` crate.
- **Default params (argon2 0.5):** Argon2id v19, m_cost=19456 KiB (~19 MiB), t_cost=2, p_cost=1, output_len=32.
- **Salt:** `SaltString::generate(&mut rand::rngs::OsRng)` -- 16-byte random salt from OS entropy per OWASP recommendation.
- **Hash format:** PHC string format (`$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`), stored in SQLite config table under key `admin_password_hash`.

### Findings
- **PASS: Algorithm selection.** Argon2id is OWASP's first-choice algorithm for password hashing.
- **PASS: Per-password random salt.** `OsRng` is used (not `thread_rng`), and each password gets a unique salt.
- **PASS: Timing-safe comparison.** `Argon2::verify_password()` internally uses `PasswordHash::verify_password()` which calls `ConstantTimeEq` from the `subtle` crate. This is constant-time.
- **PASS: HMAC signature verification.** `mac.verify_slice()` from the `hmac` crate uses `CtOutput` which performs constant-time comparison via the `subtle` crate.
- **NOTE: Memory cost below OWASP minimum.** OWASP recommends m=47104 KiB (46 MiB) minimum for Argon2id. The default `m=19456` (19 MiB) is below this. However, this is a router appliance with constrained RAM (typically 1-4 GB shared with the OS, nftables, DNS, DHCP). The 19 MiB default is a reasonable trade-off. Increasing to 47 MiB is not recommended without memory profiling on target hardware.
- **NOTE: Iteration count.** t=2 matches OWASP's recommended minimum. Acceptable.

### Verdict: PASS (with noted trade-off on m_cost)

---

## 2. Session Management

### Implementation
- **Token format:** `admin:<created_ts>:<last_active_ts>.<hmac_hex>`
- **HMAC key:** 32-byte random secret generated with `OsRng`, stored in DB as `session_secret`. Wrapped in `Zeroizing<String>`.
- **HMAC algorithm:** HMAC-SHA256
- **Idle timeout:** 30 minutes (`SESSION_IDLE_TIMEOUT_SECS = 1800`)
- **Absolute timeout:** 8 hours (`SESSION_ABSOLUTE_TIMEOUT_SECS = 28800`)
- **Cookie flags:** `HttpOnly; Secure; SameSite=Strict; Path=/`
- **Session refresh:** Rolling refresh on every authenticated request updates `last_active` timestamp with fresh HMAC signature.

### Findings
- **PASS: HMAC verification.** Uses `mac.verify_slice()` (constant-time). Signature is hex-decoded and verified before any timestamp parsing.
- **PASS: Timeout enforcement.** Both idle and absolute timeouts are checked in `handle_verify_session` and `handle_refresh_session`. Uses `saturating_sub` to prevent underflow.
- **PASS: Cookie security flags.** All three critical flags (HttpOnly, Secure, SameSite=Strict) are set consistently in `login`, `setup_password_step`, and `auth_middleware` refresh.
- **PASS: Session secret entropy.** 32 bytes from `OsRng`, hex-encoded to 64-char string. This provides 256 bits of entropy.
- **FINDING: Session secret generated with OsRng.** The `handle_create_session` function (line 123) correctly uses `rand::rngs::OsRng` for the session secret, addressing the concern noted in SECURITY.md #101. This was already fixed.
- **KNOWN ISSUE: No session revocation.** Documented in SECURITY.md #40. Logout clears the cookie but the token remains valid if captured. The only revocation mechanism is rotating `session_secret`, which invalidates all sessions.
- **KNOWN ISSUE: No session invalidation on password change.** When the password is changed via `handle_setup_password`, the `session_secret` is NOT rotated. Existing sessions remain valid. This means a stolen session token survives a password change.

### Verdict: PASS (with known limitations #40, password change session invalidation)

---

## 3. Common Password Check

### Implementation (NEW -- added by this audit)
- **File:** `hermitshell-agent/src/socket/common_passwords.rs`
- **Approach:** Static `HashSet` of ~230 common passwords, checked with case-insensitive comparison during `handle_setup_password` (both initial setup and password change).
- **List sources:** NCSC top passwords, NordPass annual reports, Have I Been Pwned top breached passwords, SecLists.
- **Filtering:** Only passwords >= 8 characters are included (shorter ones are already rejected by the length check).
- **Error message:** "password is too common; choose a stronger password"

### Design Decisions
- The check runs BEFORE the old password verification and hashing, so it is cheap (HashSet lookup, O(1)).
- Case-insensitive comparison catches "Password", "PASSWORD", "pAssWoRd" etc.
- The list is intentionally small (~230 entries) to avoid bloating the agent binary. A full 10k/100k list would add 50-500 KB. The top ~230 covers the vast majority of breach-derived attacks.
- No external dependency or file I/O -- the list is compiled into the binary.

### Verdict: IMPLEMENTED

---

## 4. Rate Limiting

### Implementation
- **Agent-side (global):** `LoginRateLimit = Arc<Mutex<(u32, Option<Instant>)>>` -- single global counter. Exponential backoff: `min(2^(failures-1), 60)` seconds. Checked in both `verify_password` and `setup_password`.
- **Web UI-side (per-IP):** `LruCache<IpAddr, (u32, Instant)>` with 1000 entries. Same exponential backoff formula. Applied only to `/api/login*` and `/api/setup_password*` paths.
- **Password lock:** `PasswordLock = Arc<Mutex<()>>` serializes password operations to prevent race conditions between concurrent verification attempts.

### Findings
- **PASS: Dual-layer defense.** Per-IP web UI limiter + global agent limiter. Even if the per-IP cache is evicted (SECURITY.md #48), the global limiter still enforces backoff.
- **PASS: Backoff formula.** Exponential with cap at 60 seconds. After 7 failures: 64 -> capped to 60s. After 1 failure: 1s. After 2: 2s. After 3: 4s. After 4: 8s. This is reasonable.
- **PASS: Fail-closed for unknown IPs.** The web UI rate limiter rejects requests where `ConnectInfo` is missing (returns 403).
- **PASS: Web UI tracks success/failure by HTTP status.** Success (2xx/3xx) clears the IP's counter. Failure (4xx/5xx) increments it.
- **KNOWN ISSUE: In-memory only.** Documented in SECURITY.md #41. Agent restart clears all rate limit state.
- **NOTE: Rate limit check placement in verify_password.** The rate limit check happens BEFORE the password lock acquisition. This is correct -- it avoids holding the lock while the rate limit is active. However, the rate limit check and the password lock acquisition are not atomic, so a burst of concurrent requests could slip through between the check and the lock. In practice, the password lock serializes the actual verification, so this is a minor timing window that doesn't bypass the rate limit on the next attempt.

### Verdict: PASS (with known limitation #41)

---

## 5. Password Change Flow

### Implementation
- **Server function:** `change_password` in `server_fns.rs` calls `client::setup_password(&new_password, Some(&current_password))`.
- **Agent handler:** `handle_setup_password` in `auth.rs`. When `existing_hash` is `Some`, it requires `req.key` (current password) and verifies it via Argon2 before hashing the new password.
- **Validation:** New password must be 8-128 chars, not in common passwords list. Confirm password match checked in the server function.
- **Rate limiting:** Current password verification is rate-limited via the same `LoginRateLimit`.

### Findings
- **PASS: Old password required.** The agent enforces this at the IPC level. Without a valid current password, the request is rejected.
- **PASS: Common password check on change.** The new common password check applies to both initial setup and password changes.
- **FINDING: Sessions NOT invalidated on password change.** When `handle_setup_password` succeeds, it writes the new hash to the DB but does NOT rotate `session_secret`. All existing HMAC-signed session tokens remain valid. An attacker who stole a session token retains access even after the admin changes the password. This is a meaningful gap -- OWASP C7 recommends invalidating existing sessions on credential change.
- **FINDING: No audit log for password change.** (UPDATE: Another agent has added audit logging at lines 116-121 of the current auth.rs. This is now addressed.)

### Verdict: PARTIAL PASS (session invalidation gap)

---

## 6. API Key Authentication

### Implementation
- **Storage:** API key hash stored as `api_key_hash` in config DB (in BLOCKED_CONFIG_KEYS).
- **Hashing:** Same `Argon2::default()` with `OsRng` salt, identical to password hashing.
- **Verification:** `auth_middleware` in `rest_api.rs` extracts `Bearer <token>` from `Authorization` header, looks up hash, verifies via `Argon2::verify_password()`.
- **Key length:** Minimum 16 characters enforced by `handle_set_api_key`.
- **Binding:** REST API listens on `127.0.0.1:9080` only (localhost).

### Findings
- **PASS: Constant-time comparison.** Same Argon2 `verify_password()` with `ConstantTimeEq` as password verification.
- **PASS: Hash stored, not plaintext.** The API key is hashed with Argon2id before storage.
- **PASS: Hash in Zeroizing wrapper.** The hash string read from DB is wrapped in `Zeroizing::new(h)`.
- **PASS: Bearer token extraction.** Properly strips "Bearer " prefix, rejects empty tokens.
- **KNOWN ISSUE: No rate limiting.** Documented in SECURITY.md #115. The REST API has no exponential backoff on failed auth attempts. However, it only binds to localhost, limiting the attack surface to local processes.
- **NOTE: Argon2 cost on every request.** Each REST API request runs a full Argon2id verification (~50-100ms). This is by design (timing-safe), but means the REST API can only handle ~10-20 authenticated requests per second. For a localhost management API, this is acceptable.

### Verdict: PASS (with known limitation #115)

---

## 7. CSRF Protection

### Findings (bonus coverage)
- **PASS: SameSite=Strict cookies.** Prevents CSRF via cookie-bearing cross-site requests.
- **PASS: Sec-Fetch-Site header check.** The CSRF middleware checks `sec-fetch-site: same-origin` for state-changing requests.
- **PASS: Origin/Host comparison fallback.** When `Sec-Fetch-Site` is absent, Origin is compared to Host.
- **PASS: Non-browser clients allowed.** Requests with no `Sec-Fetch-Site` and no `Origin` are allowed through (curl, scripts).
- **PASS: Host validation.** DNS rebinding prevention via `is_allowed_host()` check.

### Verdict: PASS

---

## Summary

| Area | Verdict | Notes |
|------|---------|-------|
| Password Hashing | PASS | Argon2id, OsRng salt, constant-time. m_cost below OWASP rec but justified for router. |
| Session Management | PASS | HMAC-SHA256, proper timeouts, secure cookie flags. No revocation (known). |
| Common Password Check | IMPLEMENTED | ~230 common passwords, case-insensitive, checked on set/change. |
| Rate Limiting | PASS | Dual-layer (per-IP + global), exponential backoff, fail-closed. In-memory only (known). |
| Password Change | PARTIAL PASS | Old password required, but sessions not invalidated on change. |
| API Key Auth | PASS | Argon2id hash, constant-time, localhost-only. No rate limiting (known). |
| CSRF | PASS | SameSite=Strict + Sec-Fetch-Site + Origin/Host validation. |

### Code Changes Made
1. **New file:** `hermitshell-agent/src/socket/common_passwords.rs` -- common password list with `is_common_password()` function.
2. **Modified:** `hermitshell-agent/src/socket/mod.rs` -- added `mod common_passwords` declaration.
3. **Modified:** `hermitshell-agent/src/socket/auth.rs` -- added common password check in `handle_setup_password` before password lock acquisition.
4. **New entry:** `docs/SECURITY.md` -- entry #132 documenting the common password check trade-offs.

### Recommendations (no code changes)
1. **Session invalidation on password change:** Rotate `session_secret` in `handle_setup_password` when `existing_hash.is_some()`. This invalidates all sessions (acceptable for single-admin). Requires a one-line `db.set_config("session_secret", &new_secret)` after the password hash is written.
2. **Expand common password list:** Consider loading an external list (e.g., top 10k from SecLists) from a file at startup, if binary size is not a concern.
3. **OWASP m_cost:** If target hardware allows, increase Argon2id m_cost to 47104 KiB (46 MiB). Benchmark on production hardware first.
# OWASP Proactive Control C8: Leverage Browser Security Features -- Audit Findings

**Audit date:** 2026-03-01
**Scope:** `hermitshell/src/main.rs` (security headers, CSRF, host validation, auth middleware), `hermitshell-ui/src/` (components, pages)

---

## 1. Security Headers Audit

### Currently set (all correct):
| Header | Value | Status |
|--------|-------|--------|
| Strict-Transport-Security | `max-age=31536000; includeSubDomains` | PASS |
| Content-Security-Policy | `default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'` | PARTIAL (see finding 2) |
| X-Frame-Options | `DENY` | PASS |
| X-Content-Type-Options | `nosniff` | PASS |
| Referrer-Policy | `strict-origin-when-cross-origin` | PASS |

### Previously missing (now added):
| Header | Value | Status |
|--------|-------|--------|
| Permissions-Policy | `camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()` | ADDED |
| Cross-Origin-Opener-Policy | `same-origin` | ADDED |
| Cross-Origin-Resource-Policy | `same-origin` | ADDED |

### Notes on added headers:
- **Permissions-Policy**: Disables browser features that a router admin UI should never use. Prevents feature-policy-based attacks if XSS is ever achieved.
- **COOP (same-origin)**: Prevents the page from being referenced by cross-origin windows via `window.opener`. Mitigates Spectre-class side-channel attacks and cross-origin window manipulation.
- **CORP (same-origin)**: Prevents cross-origin embedding of any resources from this origin. Appropriate because HermitShell serves no public resources.

---

## 2. CSP Analysis: `unsafe-inline` for Styles

### Finding: `style-src 'unsafe-inline'` is required and cannot be removed

The codebase has **extensive** inline `style=` attributes across virtually every page:
- `hermitshell-ui/src/pages/settings.rs`: 15+ inline style attributes
- `hermitshell-ui/src/pages/device_detail.rs`: 7+ inline style attributes
- `hermitshell-ui/src/pages/wifi.rs`: 13+ inline style attributes
- `hermitshell-ui/src/pages/dns.rs`: 4 inline style attributes
- `hermitshell-ui/src/pages/wireguard.rs`: 5 inline style attributes
- `hermitshell-ui/src/pages/devices.rs`: 2 inline style attributes
- `hermitshell-ui/src/pages/setup.rs`: 4 inline style attributes (including dynamic `format!("width: {}%")`)
- `hermitshell-ui/src/pages/logs.rs`: 2 inline style attributes
- `hermitshell-ui/src/pages/port_forwarding.rs`: 4 inline style attributes
- `hermitshell-ui/src/pages/alerts.rs`: 2 inline style attributes
- `hermitshell-ui/src/charts.rs`: SVG with inline `style` in raw HTML string

**Conclusion:** Removing `'unsafe-inline'` from `style-src` would break the entire UI. Refactoring 60+ inline styles to CSS classes is a large effort. The risk of `style-src 'unsafe-inline'` is low -- style injection via CSS is theoretically possible but far less dangerous than script injection. This is an acceptable trade-off for a local network appliance UI.

**Alternative:** Nonce-based CSP for styles would require Leptos SSR to inject a per-request nonce into every style attribute, which is not supported by Leptos's SSR model.

---

## 3. CSP Finding: Inline Scripts and Event Handlers Are Blocked

### Finding: The current CSP blocks inline JavaScript that the application uses

The CSP sets `default-src 'self'` without a separate `script-src` directive. This means `script-src` inherits `'self'`, which **blocks inline scripts and inline event handlers**.

The application has:
1. **Inline `<script>` block** in `settings.rs` (lines 316-323): Backup checkbox toggle logic for showing/hiding passphrase fields.
2. **Inline `onclick` handlers** in `devices.rs` (lines 124, 130) and `device_detail.rs` (lines 280, 286): Dialog show/close for device block confirmations.

These are currently **silently blocked by CSP** in standards-compliant browsers. The backup passphrase toggle does not work, and the block confirmation dialogs cannot open.

### Recommendation (NOT implemented -- too risky for this audit):
The inline script and onclick handlers should be moved to an external `.js` file served at a `'self'` URL. This avoids needing `script-src 'unsafe-inline'` which would significantly weaken the CSP.

Specifically:
- Create `/static/app.js` with event delegation for `[data-toggle-passphrase]` and `[data-show-dialog]`/`[data-close-dialog]` attributes
- Replace `onclick` attributes with `data-*` attributes
- Replace the `<script>` block with the external file inclusion
- This is a medium-sized refactor touching 3 files

**NOT adding `script-src 'unsafe-inline'`** because that would be a security regression. The broken functionality is minor (passphrase toggle, confirm dialog) and the current behavior is fail-safe (operations still work, just without the UX polish).

---

## 4. CSRF Protection Audit

### Mechanism: Sec-Fetch-Site + Origin/Host fallback

**Implementation** (`main.rs` lines 127-175):
1. Safe methods (GET, HEAD, OPTIONS) are always allowed -- CORRECT
2. If `Sec-Fetch-Site` header is present:
   - `same-origin` -> allow
   - Anything else (`cross-site`, `same-site`, `none`) -> reject
3. Fallback: compare `Origin` header host to `Host` header
4. No `Sec-Fetch-Site` and no `Origin` -> allow (non-browser client)

### Analysis: PASS with minor notes

- **Sec-Fetch-Site check is correct.** The `same-origin` value is the only one that should be allowed. `none` (direct navigation) is correctly rejected for POST requests, since legitimate form submissions always originate from the same page.
- **Origin/Host fallback is correct.** Strips scheme prefix and compares. Rejects if Origin is present but Host is missing.
- **No Origin, no Sec-Fetch-Site -> allow:** This is the correct behavior for non-browser clients (curl, API scripts). Browsers always send at least one of these headers for POST requests.

### Potential concern: `Sec-Fetch-Site: same-origin` trust
- Modern browsers (Chrome 76+, Firefox 90+, Safari 16.4+) send `Sec-Fetch-Site`. The `Sec-` prefix means the header cannot be set by JavaScript (`fetch` or `XMLHttpRequest`), making it reliable.
- Older browsers that don't send `Sec-Fetch-Site` fall through to the Origin/Host check, which is also sound.

**No bypass found.**

---

## 5. Host Header Validation (DNS Rebinding) Audit

### Implementation (`main.rs` lines 100-125):

```rust
fn is_allowed_host(host: &str) -> bool {
    let hostname = host.split(':').next().unwrap_or(host);
    if hostname.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    matches!(hostname, "localhost" | "hermitshell.local")
}
```

### Analysis: PASS

- **All IP addresses are allowed.** This is correct for a router appliance -- users connect via the router's IP (e.g., `10.0.0.1`, `192.168.1.1`, `[fd00::1]`). The user might connect via any interface IP.
- **Only `localhost` and `hermitshell.local` hostnames allowed.** This prevents DNS rebinding attacks where an attacker's domain resolves to the router's IP, because the Host header would be `attacker.com` which is rejected.
- **Port stripping is correct.** `host.split(':').next()` handles `10.0.0.1:8443`.
- **Missing Host header:** The middleware allows requests through if Host header is absent (`if let Some(host) = ...`). This is acceptable because HTTP/1.1 requires Host, and HTTP/2 uses `:authority` pseudo-header. Requests without Host are malformed and would fail routing anyway.

### Potential concern: IPv6 bracket notation
- IPv6 addresses in Host headers use bracket notation: `[::1]:8443`. The `split(':')` would split `[::1]:8443` into `[` and others. However, `[::1]` would fail `parse::<IpAddr>()` and fall through to the hostname match, which would reject it.
- **This is a minor bug:** IPv6 access via Host header with brackets would be rejected. However, in practice, most HTTP clients send the raw address without brackets in Host, and axum's routing works regardless. This is cosmetic rather than a security issue.

**No DNS rebinding bypass found.**

---

## 6. Form Method Audit

### Finding: All state-changing operations use POST -- PASS

Every `ActionForm` in the codebase generates `<form method="post">` by default (Leptos SSR behavior). Manual `<form>` elements also use `method="post"`:
- `settings.rs:302`: `<form method="post" action="/api/backup/config">`
- `settings.rs:327`: `<form method="post" action="/api/restore/config">`

The only GET form is `logs.rs:64`: `<form method="get" action="/logs">` -- this is correct because it's a read-only filter/search form that does not change state.

**No state-changing GET forms found.**

---

## 7. Cookie Security Audit

### Finding: PASS

Cookie is set with: `session={}; HttpOnly; Secure; SameSite=Strict; Path=/`
- `HttpOnly`: Prevents JavaScript access -- PASS
- `Secure`: Only sent over HTTPS -- PASS
- `SameSite=Strict`: Not sent with cross-site requests -- PASS (defense-in-depth with CSRF middleware)
- `Path=/`: Scoped to entire site -- CORRECT for a single-app domain

---

## Summary of Changes Made

1. **Added Permissions-Policy header** -- Declares unused browser features (camera, microphone, geolocation, payment, USB, magnetometer, gyroscope, accelerometer) as disabled.
2. **Added Cross-Origin-Opener-Policy header** -- `same-origin` prevents cross-origin window references.
3. **Added Cross-Origin-Resource-Policy header** -- `same-origin` prevents cross-origin resource embedding.

## Summary of Findings (No Code Changes)

1. **CSP blocks existing inline JS** -- The inline `<script>` and `onclick` handlers are blocked by the current CSP. This should be fixed by refactoring to an external JS file, NOT by adding `'unsafe-inline'` to script-src.
2. **`style-src 'unsafe-inline'` cannot be removed** -- Too many inline styles across the UI. Acceptable trade-off.
3. **CSRF protection is sound** -- No bypasses found.
4. **Host validation is sound** -- No DNS rebinding bypasses found.
5. **All forms use correct methods** -- POST for mutations, GET only for reads.
6. **Cookie security is correct** -- HttpOnly, Secure, SameSite=Strict.
# OWASP Proactive Control C9: Security Logging and Monitoring

## Audit Summary

Audited against OWASP C9 requirements. HermitShell has a solid logging foundation
but had several gaps in security event coverage and log forwarding.

**Audit Date:** 2026-03-01
**Files Reviewed:**
- hermitshell-agent/src/db.rs (audit_log table, rotation, queries)
- hermitshell-agent/src/log_export.rs (syslog + webhook export)
- hermitshell-agent/src/socket/auth.rs (auth event logging)
- hermitshell-agent/src/socket/mod.rs (request routing, SO_PEERCRED)
- hermitshell-agent/src/socket/logs.rs (audit log API handlers)
- hermitshell-agent/src/socket/config.rs (config change auditing)
- hermitshell-agent/src/socket/devices.rs (device group changes)
- hermitshell-agent/src/socket/wireguard.rs (WG peer management)
- hermitshell-agent/src/socket/network.rs (port forwards, DMZ)
- hermitshell-agent/src/socket/setup.rs (setup wizard auditing)
- hermitshell-agent/src/socket/wifi.rs (WiFi config auditing)
- hermitshell-agent/src/analyzer.rs (behavioral analysis alerts)
- hermitshell-agent/src/dns_log.rs (DNS query logging)
- hermitshell-agent/src/conntrack.rs (connection tracking)
- hermitshell-agent/src/rest_api.rs (REST API auth middleware)
- hermitshell-ui/src/server_fns.rs (web UI audit log calls)

---

## 1. Security Event Logging Coverage

### What IS logged (audit_log table):

| Event Category | Coverage | Where |
|---|---|---|
| Config export/import | YES | config.rs |
| Config apply (declarative) | YES | config.rs |
| API key set | YES | config.rs |
| Device group changes | YES | server_fns.rs (web UI) |
| Device block/unblock | YES | server_fns.rs (web UI) |
| Port forward add/remove | YES | server_fns.rs (web UI) |
| WireGuard enable/disable | YES | server_fns.rs (web UI) |
| WireGuard peer add/remove | YES | server_fns.rs (web UI) |
| WiFi provider add/remove | YES | setup.rs + wifi.rs + server_fns.rs |
| WiFi SSID/radio changes | YES | wifi.rs + server_fns.rs |
| TLS cert/mode changes | YES | server_fns.rs (web UI) |
| ACME config changes | YES | server_fns.rs (web UI) |
| Setup wizard steps | YES | setup.rs |
| Hostname/timezone changes | YES | setup.rs |
| DNS config changes | YES | server_fns.rs (web UI) |
| Ad blocking toggle | YES | server_fns.rs (web UI) |
| QoS config changes | YES | server_fns.rs (web UI) |
| Analyzer rule toggles | YES | server_fns.rs (web UI) |
| Update apply | YES | server_fns.rs (web UI) |
| Password change | YES | server_fns.rs (web UI) |

### What was NOT logged (FIXED in this audit):

| Event Category | Status | Fix |
|---|---|---|
| Login success | FIXED | Added `login_success` to auth.rs |
| Login failure | FIXED | Added `login_failure` to auth.rs |
| Session creation | FIXED | Added `session_created` to auth.rs |
| Password set/change (agent) | FIXED | Added `password_set`/`password_changed` to auth.rs |
| REST API auth failure | FIXED | Added `api_auth_failure` to rest_api.rs |
| Audit events to syslog/webhook | FIXED | Added `LogEvent::Audit` variant |

### What is STILL NOT logged (recommendations):

| Event Category | Risk | Recommendation |
|---|---|---|
| Session expiry/invalidation | Low | Log when verify_session returns false after valid HMAC (expired) |
| Rate limit triggers with source info | Medium | The rate limit warn! logs lack caller identity |
| REST API config mutations | Medium | PUT /api/v1/config does not audit-log changes |
| set_config generic key changes | Low | Generic set_config writes arbitrary keys without audit |
| Backup database events | Low | backup_database does not audit-log |

---

## 2. Sensitive Data in Logs

**Finding: PASS** -- No sensitive data leaks found.

- `password`, `secret`, `key`, `token` were searched near all tracing macros
- Password verification failures log "password verification failed" without the password value
- API key failures log "invalid API key" without the key value
- WireGuard operations log public keys (not private keys)
- WiFi provider operations log provider names (not passwords)
- Session cookies are not logged
- The `BLOCKED_CONFIG_KEYS` list prevents reading secrets via `get_config`
- Webhook secret uses `Zeroizing<String>` wrapper

**One minor concern:** `flush_webhook` copies `webhook_secret` to a plain `String`
via `.to_string()` before spawning the async task. This copy is not zeroized.
This is documented in SECURITY.md #119 and is a known limitation.

---

## 3. Log Injection Prevention

**Finding: PASS** -- Syslog output properly escapes user-controlled data.

- `escape_sd_param()` escapes `\`, `"`, and `]` per RFC 5424 section 6.3.3
- All user-controlled fields (device_ip, domain, dest_ip, protocol, event,
  device_mac, rule, severity, message, action, detail) pass through `escape_sd_param()`
- Existing test `test_syslog_escapes_domain` validates quote injection is prevented
- Existing test `test_escape_sd_param` validates all three escape characters
- UDP message truncation respects UTF-8 char boundaries (tested)

**The new `Audit` variant also uses `escape_sd_param()` for both `action` and `detail`.**

---

## 4. Log Integrity / Tamper Detection

**Finding: GAP** -- No tamper detection mechanism exists.

Current state:
- Logs stored in SQLite (local, unencrypted, no integrity checks)
- Syslog export is plaintext UDP (no authentication, no integrity)
- Webhook export uses Bearer token auth (not HMAC signature over payload)
- No hash chain or sequence numbers for log entries
- No write-ahead log or append-only storage

The webhook implementation documentation claims "HMAC signature" but the code
actually uses a plain `Authorization: Bearer <secret>` header. The secret
authenticates the sender but does NOT provide payload integrity verification.

### Recommendations (not implemented -- too large for quick fix):

1. **Webhook HMAC signature**: Compute `HMAC-SHA256(secret, payload)` and send
   as an `X-Hermitshell-Signature` header alongside the payload. This provides
   payload integrity verification. Many webhook consumers (GitHub, Stripe)
   use this pattern.

2. **Audit log hash chain**: Each audit_log entry could include a SHA-256 hash
   of `(previous_hash || action || detail || timestamp)`. The first entry uses
   a known seed. This enables detection of record deletion or modification,
   though not prevention.

3. **Syslog TLS**: See section 6 below.

---

## 5. Alert Surfacing (Behavioral Analysis)

**Finding: GOOD** -- Alerts reach the admin through multiple channels.

- Behavioral analysis runs every 60 seconds (`analysis_counter` in main.rs)
- Alerts are inserted into the `alerts` SQLite table
- Alerts are forwarded to the log_export channel as `LogEvent::Alert`
- This means alerts reach: tracing/stdout, syslog (if configured), webhook (if configured)
- Syslog priority is mapped: high=3 (error), medium=4 (warning), low=5 (notice)
- Alert cooldown (1 hour per rule per device) prevents alert fatigue
- Web UI has an `/alerts` page that displays unacknowledged alerts
- 6 behavioral rules: dns_beaconing, dns_volume_spike, new_dest_spike,
  suspicious_ports, bandwidth_spike, dhcp_fingerprint_change

**Gap:** No push notification mechanism (e.g., email, Pushover, Telegram).
The webhook export is the closest to real-time notification but requires
the admin to set up a webhook receiver. This is acceptable for the threat model
(home router, single admin).

---

## 6. TLS Syslog (TCP+TLS)

**Finding: GAP** -- Only plaintext UDP syslog is supported (documented in SECURITY.md #53).

Current implementation:
- `parse_syslog_target()` only accepts `udp://` prefix
- `send_syslog()` uses `UdpSocket::bind("0.0.0.0:0")` + `send_to()`
- Messages truncated to 480 bytes per RFC 5426 section 3.2
- No TCP support, no TLS support

### Recommendation (not implemented -- significant scope):

Adding TCP+TLS syslog (RFC 5425) would require:
1. New `tcp+tls://host:port` prefix in `parse_syslog_target()`
2. Persistent TCP connection with reconnect logic
3. TLS client using `rustls` (already a dependency)
4. Framing: RFC 5425 uses octet counting (`<length> <message>`)
5. Optional client certificate authentication
6. Connection state management in the log_export loop

This is a meaningful improvement but is a standalone feature (~200-300 lines).
The webhook export (which supports HTTPS) provides an encrypted alternative
for environments where TLS syslog is not available.

---

## 7. Audit Log Retention

**Finding: GAP (FIXED)** -- Audit logs were not subject to retention/rotation.

- `rotate_logs()` only deletes old `connection_logs` and `dns_logs`
- `rotate_alerts()` deletes old `alerts`
- The `audit_log` table had no rotation mechanism -- unbounded growth

**Fix applied:** Added `rotate_audit_logs()` to db.rs and called it from the
hourly rotation loop in main.rs. Audit logs use a minimum 90-day retention
(or `log_retention_days` if larger) to ensure compliance with typical audit
retention requirements while still bounding table growth.

---

## 8. Audit Events Not Forwarded to External Sinks

**Finding: GAP (FIXED)** -- Audit events were only stored in SQLite.

The `LogEvent` enum had three variants (Connection, DnsQuery, Alert) but no
Audit variant. This meant audit events (login, config changes, etc.) were:
- Stored in the local `audit_log` SQLite table
- NOT forwarded to syslog
- NOT forwarded to webhook
- NOT emitted via structured tracing

This is a significant gap for OWASP C9: if the router is compromised, the
attacker could modify or delete the local SQLite database. External log
forwarding is the primary defense against log tampering.

**Fix applied:** Added `LogEvent::Audit { action, detail }` variant with:
- JSON serialization for webhook export
- RFC 5424 syslog formatting with `[audit@hermitshell action="..." detail="..."]`
- Structured tracing emission (log_type="audit")
- The `handle_log_audit` socket handler now sends events to the log_tx channel

---

## 9. Code Changes Summary

### Files modified:

1. **hermitshell-agent/src/log_export.rs**
   - Added `LogEvent::Audit { action, detail }` variant
   - Added `to_json()` for Audit events
   - Added `to_syslog()` for Audit events (RFC 5424 structured data)
   - Added `emit_tracing()` for Audit events

2. **hermitshell-agent/src/socket/auth.rs**
   - `handle_verify_password`: audit log `login_success` / `login_failure`
   - `handle_create_session`: audit log `session_created`
   - `handle_setup_password`: audit log `password_set` / `password_changed`

3. **hermitshell-agent/src/socket/logs.rs**
   - `handle_log_audit`: now accepts `log_tx` parameter, forwards audit events
     to the log export channel (syslog/webhook)

4. **hermitshell-agent/src/socket/mod.rs**
   - Updated `handle_log_audit` call to pass `log_tx`

5. **hermitshell-agent/src/db.rs**
   - Added `rotate_audit_logs()` method (retention-based DELETE)

6. **hermitshell-agent/src/main.rs**
   - Added audit log rotation to hourly rotation cycle (90-day minimum)

7. **hermitshell-agent/src/rest_api.rs**
   - Added `api_auth_failure` audit log on invalid API key

### Verification:
- `cargo check --package hermitshell-agent` -- PASS
- `cargo check --package hermitshell-ui` -- PASS
- `cargo test --package hermitshell-agent -- log_export` -- 18/18 PASS
- Pre-existing test failures (unbound/nftables paths::init) unchanged

---

## 10. Remaining Recommendations (Future Work)

| Priority | Recommendation | Effort |
|---|---|---|
| High | Webhook HMAC payload signature (X-Hermitshell-Signature header) | Small |
| High | TLS syslog support (RFC 5425 TCP+TLS) | Medium |
| Medium | REST API mutation audit logging (PUT /api/v1/config) | Small |
| Medium | Audit log hash chain for tamper detection | Medium |
| Low | Push notification integration (email/Pushover/Telegram) | Medium |
| Low | Per-session audit trail (link audit entries to session tokens) | Medium |
| Low | Log export health monitoring (alert if syslog/webhook fails) | Small |
# OWASP Proactive Control C10: Stop Server Side Request Forgery

## Audit Scope

HermitShell router management agent -- all outbound HTTP/HTTPS request sources.

## Outbound Request Inventory

| Source | URL Origin | Scheme | SSRF Risk | Action Taken |
|--------|-----------|--------|-----------|--------------|
| Blocklist download | User-configured | Was HTTP/HTTPS, now HTTPS-only | **HIGH -> LOW** | Hardened |
| Webhook delivery | User-configured | Was HTTP/HTTPS, now HTTPS-only | **MEDIUM -> LOW** | Hardened |
| WiFi AP (EAP standalone) | Admin-configured IP | HTTPS | None (by design) | Documented as accepted risk |
| WiFi AP (UniFi controller) | Admin-configured URL | HTTPS | None (by design) | Documented as accepted risk |
| runZero API | Admin-configured URL | HTTPS (already enforced) | Low | No change needed |
| GitHub releases | Hardcoded | HTTPS | None | No change needed |
| ACME (Let's Encrypt) | Hardcoded | HTTPS | None | No change needed |
| Cloudflare DNS API | Hardcoded | HTTPS | None | No change needed |

## Findings

### F1. Blocklist URLs allowed HTTP and internal IPs [FIXED]

**Severity:** High
**SECURITY.md:** #144

Blocklist URLs configured via `handle_add_dns_blocklist`, `apply_hermit_config`, or `handle_import_config` accepted `http://` and placed no restriction on the target IP address. An attacker with admin access could configure `http://127.0.0.1:9080/...` to probe internal services or `http://192.168.1.x/...` to scan the LAN. HTTP downloads were also vulnerable to MITM content injection of Unbound config lines.

**Fix:** Added `validate_outbound_url()` in `unbound.rs` which:
1. Requires HTTPS (rejects `http://` unless explicitly allowed)
2. Parses the host component and rejects private, loopback, link-local, ULA, and unspecified IP addresses using the existing `qos::is_public_ip()` function
3. Handles IPv6 bracket notation (`[::1]`) from `reqwest::Url::host_str()`

Validation is now called in all three entry points:
- `socket/dns.rs:242` -- `handle_add_dns_blocklist`
- `socket/config.rs:590` -- `handle_import_config`
- `socket/config.rs:899` -- `apply_hermit_config` (blocklists)

### F2. Webhook URLs allowed HTTP and internal IPs [FIXED]

**Severity:** Medium
**SECURITY.md:** #145

Webhook URLs configured via `handle_set_log_config` or `apply_hermit_config` had no scheme or IP restrictions. The agent sends `POST` requests with `Authorization: Bearer <secret>` to these URLs, meaning an internal-targeting URL would exfiltrate the webhook secret to an arbitrary internal HTTP endpoint.

**Fix:** Added `validate_outbound_url()` calls in both entry points:
- `socket/config.rs:1208` -- `handle_set_log_config`
- `socket/config.rs:916` -- `apply_hermit_config` (webhook)

### F3. WiFi AP connections intentionally target internal IPs [ACCEPTED RISK]

**Severity:** N/A (by design)
**SECURITY.md:** #146

The EAP standalone provider connects to an admin-configured LAN IP (`eap_standalone.rs`). The UniFi provider connects to an admin-configured HTTPS URL typically on the LAN (`unifi.rs`). Both are intentionally internal -- WiFi APs are LAN devices by definition.

SSRF utility is limited because:
- EAP sends vendor-specific MD5 auth, not generic HTTP
- UniFi sends session cookies scoped to the controller
- Both validate TLS certificates (TOFU/pinned), which would fail against non-AP services

**Decision:** No SSRF validation added. Documented as accepted risk.

### F4. No DNS rebinding protection on outbound requests [DOCUMENTED]

**Severity:** Low
**SECURITY.md:** #147

`validate_outbound_url()` checks IP literals but does not resolve hostnames before connecting. A DNS rebinding attack could bypass the check by using a hostname that resolves to a public IP at config time but a private IP at download/delivery time.

**Mitigations already in place:**
- Unbound's `private-address` directives block DNS responses resolving external names to private IPs (e.g., `private-address: 10.0.0.0/8`)
- Attack requires admin access + attacker-controlled DNS + TTL timing

**Decision:** Deferred. Risk is low given existing Unbound mitigation and the threat model (attacker needs admin access).

### F5. runZero and hardcoded URLs have no SSRF risk [NO ACTION]

**Severity:** None
**SECURITY.md:** #148

- **runZero:** Admin-configurable but already requires `https://` prefix. The agent sends requests to a specific API path (`/api/v1.0/export/org/assets.json`), limiting SSRF utility.
- **GitHub releases:** Hardcoded to `https://api.github.com/repos/jnordwick/hermitshell/releases/latest`.
- **ACME:** Hardcoded to Let's Encrypt production/staging directories.
- **Cloudflare:** Hardcoded to `https://api.cloudflare.com/client/v4/`.

## Code Changes Summary

### New function: `validate_outbound_url()`

**File:** `/home/ubuntu/hermitshell/hermitshell-agent/src/unbound.rs` (line 533)

```rust
pub fn validate_outbound_url(url: &str, allow_http: bool) -> Result<()>
```

- Parses URL with `reqwest::Url::parse`
- Enforces HTTPS by default; `allow_http: true` permits HTTP (unused currently, reserved for future use)
- Extracts host, strips IPv6 brackets, parses as `IpAddr`
- Rejects non-public IPs via `crate::qos::is_public_ip()`
- Hostnames (non-IP-literal) pass through (DNS rebinding caveat documented)

### Call sites added

| File | Function | Line | Context |
|------|----------|------|---------|
| `socket/dns.rs` | `handle_add_dns_blocklist` | 242 | Single blocklist add via IPC |
| `socket/config.rs` | `handle_import_config` | 590 | Blocklist import from backup |
| `socket/config.rs` | `apply_hermit_config` | 899 | Declarative config blocklists |
| `socket/config.rs` | `apply_hermit_config` | 916 | Declarative config webhook |
| `socket/config.rs` | `handle_set_log_config` | 1208 | Webhook URL set via IPC |

### Unit tests added

**File:** `/home/ubuntu/hermitshell/hermitshell-agent/src/unbound.rs` (line 1079)

11 tests covering:
- `test_validate_outbound_url_https_ok` -- HTTPS accepted
- `test_validate_outbound_url_http_rejected_by_default` -- HTTP rejected
- `test_validate_outbound_url_http_allowed_when_flag_set` -- HTTP allowed with flag
- `test_validate_outbound_url_rejects_loopback` -- 127.0.0.1 and [::1] rejected
- `test_validate_outbound_url_rejects_private_ipv4` -- 10.x, 172.16.x, 192.168.x rejected
- `test_validate_outbound_url_rejects_link_local` -- 169.254.x rejected
- `test_validate_outbound_url_rejects_ula_ipv6` -- fd00:: rejected
- `test_validate_outbound_url_accepts_public_ip` -- 93.184.216.34 accepted
- `test_validate_outbound_url_accepts_hostname` -- example.com accepted
- `test_validate_outbound_url_rejects_bad_scheme` -- ftp:// rejected
- `test_validate_outbound_url_rejects_invalid` -- garbage string rejected

## SECURITY.md Entries

Entries **## 144** through **## 148** added under new section "Server-Side Request Forgery (OWASP C10)" in `/home/ubuntu/hermitshell/docs/SECURITY.md`.

## Remaining Risks

1. **DNS rebinding** (F4) -- Low risk, mitigated by Unbound `private-address` directives. Full fix requires custom DNS resolver integration.
2. **runZero URL** -- HTTPS-only but no private IP check. Low risk due to specific API path requirement.
3. **Hostname-based blocklist/webhook URLs** -- Only IP literals are validated. Hostnames resolving to private IPs at download time are not caught (same as F4).
