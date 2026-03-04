# Security

HermitShell's security model: what's protected, what's configurable, and what to be aware of.

## Security by Default

- Every device gets an isolated /32 subnet — no device-to-device communication unless allowed by group policy
- HTTPS on by default (self-signed certificate, upgradeable to ACME/custom/Tailscale)
- Admin password hashed with Argon2id
- Rate-limited login with exponential backoff
- CSRF protection on all forms
- HttpOnly, Secure, SameSite=Strict session cookies
- 30-minute idle timeout, 8-hour absolute session expiry
- Sensitive config keys excluded from exports (passwords, private keys, API tokens)
- DNS blocklist URLs restricted to HTTPS (SSRF protection)
- Webhook URLs restricted to HTTPS with private IP blocking

## TLS Options

| Mode | Description |
|------|-------------|
| Self-signed | Generated at startup, browser warning expected |
| Custom | Upload your own cert and key |
| Tailscale | Uses Tailscale's HTTPS cert provisioning |
| ACME DNS-01 | Automatic Let's Encrypt via Cloudflare DNS |

## Firewall

nftables with per-device isolation. Group policies control inter-device and internet access. WireGuard peers get their own /30 subnets with the same isolation model.

## Audit Trail

All admin actions are logged with timestamps. View at /audit in the web UI, or export via syslog/webhook.

## Backup Encryption

Config exports can be encrypted with AES-256-GCM. Sensitive keys (passwords, private keys, API tokens) are only included in encrypted exports.

## Known Limitations

- Single admin account (no multi-user or RBAC)
- No signed updates (SHA256 checksum verification only)
- Self-signed TLS by default (upgrade recommended for production — see Settings > TLS)

For a detailed internal security audit, see [SECURITY.md on GitHub](https://github.com/hermitshell-router/hermitshell/blob/main/docs/SECURITY.md).
