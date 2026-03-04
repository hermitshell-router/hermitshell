# Settings

The Settings page is where you configure everything about how HermitShell
operates -- network interfaces, DNS, TLS certificates, QoS, logging, and more.
Changes take effect immediately unless noted otherwise.

---

## Network & Interfaces

Core network configuration. Most of these are set during the
[Setup Wizard](../getting-started/setup-wizard.md) but can be changed here at
any time.

- **WAN Interface** -- the physical port connected to your modem or ISP uplink.
- **LAN Interface** -- the physical port connected to your switch or access
  point.

> **Important:** Changing either interface requires an agent restart. The UI
> will prompt you to confirm before applying.

- **WAN Mode** -- how the WAN port gets its IP address:
  - **DHCP** -- automatic, suitable for most ISPs.
  - **Static** -- enter a fixed IP, gateway, and DNS server.
- **Hostname** -- the router's hostname, shown in the dashboard title, logs, and
  mDNS advertisements. Alphanumeric and hyphens only.
- **Timezone** -- used for log timestamps and scheduled tasks. Pick the timezone
  closest to your location.
- **Upstream DNS** -- where HermitShell forwards DNS queries it cannot resolve
  locally:

| Option | Servers |
|---|---|
| Automatic | Whatever your ISP provides via DHCP |
| Cloudflare | 1.1.1.1, 1.0.0.1 |
| Google | 8.8.8.8, 8.8.4.4 |
| Quad9 | 9.9.9.9, 149.112.112.112 |
| Custom | Enter your own resolver addresses |

---

## Change Password

Update the admin password. Three fields:

- **Current Password** -- your existing password, required for verification.
- **New Password** -- minimum 8 characters.
- **Confirm Password** -- must match the new password.

There is only one admin account and no password recovery mechanism. If you lose
your password, see [Troubleshooting](../reference/troubleshooting.md) for reset
instructions.

---

## TLS / HTTPS

HermitShell always serves the web UI over HTTPS. Four certificate modes are
available:

### Self-Signed

The default. HermitShell generates a self-signed certificate at first startup.
Your browser will show a certificate warning -- this is expected and safe to
accept for a device on your own LAN. No configuration needed.

### Custom Certificate

Upload your own certificate and private key (PEM format). Use this if you
already have a certificate from your organization's CA or a wildcard cert.

Two file upload fields:

- **Certificate** -- the full chain (leaf + intermediates) in PEM format.
- **Private Key** -- the corresponding private key in PEM format.

### Tailscale

Uses Tailscale's built-in HTTPS certificate provisioning. HermitShell
automatically fetches a valid certificate from Tailscale's coordination server.
Requires Tailscale to be installed and authenticated on the router.

Once enabled, you can access the web UI at
`https://<hostname>.<tailnet>.ts.net` with a browser-trusted certificate.

### ACME DNS-01

Automatic certificate from Let's Encrypt using DNS-01 validation via Cloudflare.
This gives you a publicly trusted certificate without opening any ports to the
internet.

Two fields:

- **Cloudflare API Token** -- a token with `Zone:DNS:Edit` permission for your
  domain.
- **Domain** -- the FQDN to issue the certificate for (e.g.,
  `router.example.com`).

HermitShell handles issuance and automatic renewal. The certificate renews
before expiry with no manual intervention.

---

## QoS

Quality of Service using CAKE + fq_codel -- a modern queuing discipline that
reduces bufferbloat and keeps latency low even under heavy load.

- **Enable QoS** -- toggle on or off.
- **Upload Speed** -- your connection's upload capacity in Mbps.
- **Download Speed** -- your connection's download capacity in Mbps.

Set these to roughly 90-95% of your actual speeds for best results. If you are
not sure what your speeds are, click **Run Speed Test** to measure your
connection. The test takes about 15 seconds and fills in the results
automatically.

> **Tip:** QoS matters most on slower connections (under ~100 Mbps) or
> connections with low upload speeds. On gigabit fiber it may not make a
> noticeable difference.

---

## Logging

Controls how long logs are kept and where they are forwarded.

- **Retention Period** -- how many days of connection logs, DNS logs, and audit
  entries to keep. Older entries are automatically purged. Default is 30 days.
- **Syslog Target** -- optional. Enter a `host:port` to forward logs to an
  external syslog server (e.g., `192.168.1.50:514`). Leave blank to disable.
- **Webhook URL** -- optional. An HTTPS URL that receives JSON payloads for log
  events. Only HTTPS URLs are accepted -- plain HTTP is rejected.

---

## Behavioral Analysis

HermitShell's behavioral analyzer watches network traffic patterns and flags
anomalies. This section controls whether the analyzer is active and which alert
rules are enabled.

- **Enable Analyzer** -- master toggle. When off, no behavioral analysis runs
  and no alerts are generated from traffic patterns.

When enabled, you can individually toggle each alert rule:

| Rule | What it detects |
|---|---|
| **DNS Beaconing** | A device making DNS queries at suspiciously regular intervals, which can indicate malware phoning home. |
| **DNS Volume Spike** | A sudden increase in DNS query volume from a single device. |
| **New Destination Spike** | A device suddenly connecting to many new IP addresses it has never contacted before. |
| **Suspicious Ports** | Connections to ports commonly associated with malicious activity. |
| **Bandwidth Spike** | An unusual surge in data transfer from a device compared to its baseline. |

Alerts generated by these rules appear on the [Alerts](alerts.md) page.

---

## runZero

Integrate with [runZero](https://www.runzero.com/) to enrich device information
with data from network scans.

- **API Token** -- your runZero API token.
- **Enable Sync** -- toggle to activate periodic synchronization.

When enabled, HermitShell pulls scan results from runZero and adds OS, hardware
model, and manufacturer information to individual device detail pages. This data
supplements what HermitShell discovers on its own through DHCP fingerprinting
and traffic analysis.

---

## Backup & Restore

### Export

Click **Export Config** to download your entire HermitShell configuration as a
JSON file. This includes network settings, device groups, firewall rules, DNS
blocklists, DHCP reservations, WireGuard peers, WiFi provider configs, and all
other settings.

Optionally enable **Encrypt backup** before exporting. When enabled, secrets in
the backup (passwords, API tokens, private keys) are encrypted with
AES-256-GCM. You will be prompted for an encryption passphrase. Without
encryption, secrets are included in plaintext.

### Import

Click **Import Config** and select a previously exported JSON file. If the
backup was encrypted, you will be prompted for the passphrase.

Importing replaces your current configuration with the contents of the backup
file. The agent restarts automatically after a successful import.

---

## Updates

Manage HermitShell software updates.

- **Check for Updates** -- queries the release server for available versions. If
  a newer version is available, it shows the version number and release notes.
- **Apply Update** -- downloads the update, verifies its SHA256 checksum, and
  stages a restart. If the new version fails to start, the agent automatically
  rolls back to the previous version.
- **Auto-Update** -- opt-in toggle. When enabled, HermitShell checks for updates
  daily and applies them automatically. Disabled by default.

> **Note:** NixOS users should update via `nix flake update` and
> `nixos-rebuild switch` instead. The built-in updater is automatically disabled
> on NixOS installations.

---

## DHCP Reservations

A table of static DHCP assignments -- devices that always receive the same IP
address.

| Column | Description |
|---|---|
| **Hostname** | The device's name. |
| **MAC Address** | The device's hardware address. |
| **IP Address** | The reserved IP. |
| **Remove** | Deletes the reservation. The device will receive a dynamic address on its next lease renewal. |

Reservations are not created from this table. To reserve an IP for a device,
go to its detail page (from the [Devices](devices.md) list) and click
**Reserve IP**. The reservation then appears here for reference and removal.
