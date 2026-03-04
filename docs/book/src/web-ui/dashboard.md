# Dashboard

The dashboard is the landing page after login -- your at-a-glance view of the
network.

## Stat cards

Six cards across the top summarize the current state:

| Card | What it shows |
|---|---|
| **Total Devices** | Number of devices HermitShell has seen (all groups). |
| **Active** | Total minus quarantined and blocked. |
| **Quarantined** | Devices waiting for approval. |
| **Blocked** | Devices with all access revoked. |
| **Uptime** | How long the agent has been running. |
| **Ad Blocking** | Whether DNS ad blocking is currently enabled or disabled. |

## Toggle ad blocking

Below the stat cards is a button to toggle ad blocking on or off. If ad
blocking is currently enabled the button reads **Disable Ad Blocking**; if
disabled it reads **Enable Ad Blocking**. The change takes effect immediately --
no restart required. Fine-grained blocklist configuration lives on the
[DNS & Ad Blocking](dns.md) page.

## Recent devices

A table of the five most recently seen devices, sorted by last-seen time:

| Column | Description |
|---|---|
| **Hostname** | The device's hostname (or "Unknown" if none). Links to the device detail page. |
| **IP** | Current IPv4 address. |
| **Group** | Device group shown as a colored badge. |
| **MAC** | Hardware address. |

Click any hostname to jump to that device's [detail page](devices.md#device-detail).

> **Tip:** The dashboard is intentionally minimal. For the full device list,
> filtering, and bulk actions, head to [Devices](devices.md).
