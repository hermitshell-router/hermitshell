# Setup Wizard

After installation, open **<https://10.0.0.1>** in a browser on a device
connected to the LAN port. The setup wizard walks you through initial
configuration in eight steps. A progress bar at the top tracks where you are.

You can go back to any previous step at any time. Nothing is applied until the
final step.

---

## Step 1 -- Welcome

A splash screen with the HermitShell tagline: *Your network, your rules. No
cloud, no controller.*

Click **Get Started** to begin.

---

## Step 2 -- Network Interfaces

Pick which physical port is your WAN (internet uplink) and which is your LAN
(local network). Each interface is listed with its name, MAC address, and a
status indicator:

- Green dot -- cable detected
- Red dot -- no cable detected

Select one interface for **WAN** and a different one for **LAN**, then click
**Continue**.

> **Tip:** Not sure which port is which? Unplug and replug cables -- the status
> indicator updates live.

If no interfaces appear (common when running in Docker), the wizard shows a
message and a **Skip** button. Docker deployments set interfaces via environment
variables instead.

---

## Step 3 -- WAN Configuration

Choose how the WAN port gets its IP address:

- **DHCP (automatic)** -- the default, and correct for most ISPs. Your upstream
  modem or gateway assigns an address automatically.
- **Static IP** -- for environments where you have a fixed address. Three
  additional fields appear:
  - **IP Address** -- the WAN IP (e.g., `192.168.1.2`)
  - **Gateway** -- your upstream gateway (e.g., `192.168.1.1`)
  - **DNS Server** -- a resolver for the WAN side (e.g., `1.1.1.1`)

If you are unsure, leave it on DHCP. You can change this later in
[Settings](../web-ui/settings.md).

---

## Step 4 -- Hostname & Timezone

Two fields:

- **Router Hostname** -- defaults to `hermitshell`. This name shows up in logs,
  the dashboard title, and mDNS. Alphanumeric and hyphens only.
- **Timezone** -- a dropdown of common timezones. Defaults to `UTC`. Pick the
  one closest to your location so that logs and scheduled tasks use local time.

---

## Step 5 -- DNS & Ad Blocking

**Upstream DNS provider** -- controls where HermitShell forwards DNS queries
that it cannot resolve locally:

| Option | Servers | Notes |
|---|---|---|
| Automatic | Whatever your ISP provides | Default. No third-party dependency. |
| Cloudflare | 1.1.1.1, 1.0.0.1 | Fast, privacy-focused. |
| Google | 8.8.8.8, 8.8.4.4 | Widely used, reliable. |
| Quad9 | 9.9.9.9, 149.112.112.112 | Blocks known-malicious domains at the resolver level. |

**Ad blocking** -- enabled by default. Uses built-in blocklists via Unbound. You
can fine-tune blocklists and add exceptions later on the
[DNS & Ad Blocking](../web-ui/dns.md) page.

> **Tip:** If you already run a Pi-hole or AdGuard Home instance, you can
> disable ad blocking here and point that instance at HermitShell as its upstream
> instead.

---

## Step 6 -- Admin Password

Set the password for the `admin` account. Minimum 8 characters. You will use
this to log in to the web UI after setup completes.

There is only one admin account and **no password recovery mechanism**. Write it
down or store it in a password manager. If you lose it, see
[Troubleshooting](../reference/troubleshooting.md) for reset instructions.

---

## Step 7 -- WiFi Access Point (Optional)

Connect a WiFi access point so HermitShell can manage SSIDs, radio settings, and
client visibility from one place. Two AP types are supported:

- **UniFi Controller** -- for Ubiquiti UniFi APs managed by a UniFi OS console
  (UDM, UDR, Cloud Key Gen2+) or a legacy software controller. Requires the
  controller URL, username, and password. Optionally provide a site name
  (defaults to `default`) and an API key.
- **TP-Link EAP (standalone)** -- for TP-Link EAP series access points in
  standalone mode (not managed by Omada). Requires the AP URL, username, and
  password.

Fill in the fields and click **Add & Continue**.

If you do not have a supported AP, or you manage your APs separately, click
**Skip this step**. You can add APs later from the [WiFi](../web-ui/wifi.md)
page.

---

## Step 8 -- Review & Finish

A summary table shows every setting you chose:

- WAN / LAN interfaces
- WAN mode (DHCP or static, with address details if static)
- Hostname and timezone
- DNS provider and ad blocking status

Review each line. If anything looks wrong, click **Back** to return to the
relevant step.

When everything is correct, click **Finish Setup**. HermitShell applies the
configuration -- setting up interfaces, firewall rules, DNS, and DHCP -- then
redirects you to the login page. Log in with the admin password you set in Step
6.

> **Note:** All of these settings can be changed later from the
> [Settings](../web-ui/settings.md) page. The wizard is a one-time shortcut, not
> a permanent commitment.

---

## What happens next

After login you land on the [Dashboard](../web-ui/dashboard.md). Devices
connected to the LAN port will start appearing within a few seconds as they
request DHCP leases. Each device is automatically assigned its own isolated
subnet -- no further configuration needed.
