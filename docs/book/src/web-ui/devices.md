# Devices

The devices page is where you manage every device on your network -- approve new
ones, move them between groups, block them, and drill into per-device details.

---

## Device list

**URL:** `/devices`

### Filtering by group

A row of tabs across the top filters the table: **All**, **Quarantine**,
**Trusted**, **IoT**, **Guest**, **Servers**, **Blocked**. The active tab is
highlighted. Clicking a tab reloads the page with only devices in that group.

### Table columns

| Column | Description |
|---|---|
| **Name** | Nickname if set, otherwise hostname. If both exist, the nickname is shown with the hostname in smaller text below it. Links to the device detail page. |
| **IP** | Current IPv4 address. |
| **MAC** | Hardware address. |
| **Group** | Colored badge (quarantine, trusted, iot, guest, servers, blocked). |
| **RX** | Total bytes received (downloaded) by the device, human-readable. |
| **TX** | Total bytes sent (uploaded) by the device, human-readable. |
| **Actions** | Context-sensitive controls (see below). |

### Approving quarantined devices

New devices that connect to the network land in **Quarantine** automatically.
Quarantined devices get internet access but cannot reach any other device on
the LAN.

To approve a quarantined device, use the dropdown in the **Actions** column to
pick a target group (Trusted, IoT, Guest, or Servers) and click **Approve**.
The device's firewall rules update immediately.

### Blocking a device

For devices in any group other than blocked, the Actions column shows a
**Block** button. Clicking it opens a confirmation dialog:

> **Block Device?**
> This device will lose all network access.

Click **Confirm Block** to proceed or **Cancel** to dismiss. Blocked devices
have all traffic dropped -- no internet, no LAN.

### Unblocking a device

Blocked devices show an **Unblock** button in the Actions column. Clicking it
moves the device back to quarantine so you can re-approve it into the
appropriate group.

---

## Device detail

**URL:** `/devices/:mac`

Click any device name in the device list to open its detail page. This is the
single-device deep dive.

### Device info

A grid at the top shows:

| Field | Description |
|---|---|
| **Nickname** | Editable text field. Type a name and click **Save** to set a friendly label for the device. |
| **MAC Address** | Hardware address. |
| **IP Address** | Current IPv4 address. |
| **Hostname** | DHCP hostname reported by the device. |
| **Group** | Current group as a colored badge. |
| **First Seen** | When HermitShell first saw this device. |
| **Last Seen** | Most recent activity. |
| **Downloaded (RX)** | Total bytes received by the device. |
| **Uploaded (TX)** | Total bytes sent by the device. |

### Actions

Below the info grid:

- **Change Group** -- a dropdown and **Change Group** button let you move the
  device to any group (Trusted, IoT, Guest, Servers, Quarantine). Not shown for
  blocked devices.
- **Block** -- opens the same confirmation dialog as the device list. Not shown
  if already blocked.
- **Unblock** -- shown for blocked devices. Moves the device back to
  quarantine.
- **Reserve IP** -- assigns a static DHCP reservation so the device always gets
  the same IP address.

### Bandwidth chart

A 24-hour SVG chart shows the device's bandwidth usage over time.

### Top destinations

A table of the destinations this device has communicated with most, ranked by
total bytes:

| Column | Description |
|---|---|
| **Destination** | Remote IP address. |
| **Port** | Destination port. |
| **Total** | Total bytes transferred. |

### Discovered services

If the device advertises any mDNS services (e.g., AirPlay, Google Cast,
printers), they appear in a table:

| Column | Description |
|---|---|
| **Service** | Service type (e.g., `_airplay._tcp`). |
| **Name** | Service instance name. |
| **Port** | Port the service listens on. |

### Device identity (runZero)

If [runZero integration](settings.md) is configured, a section shows the
device's fingerprinted identity:

| Field | Description |
|---|---|
| **OS** | Operating system detected by runZero. |
| **Hardware** | Hardware model. |
| **Type** | Device classification (phone, laptop, printer, camera, etc.). |
| **Manufacturer** | Hardware manufacturer. |

#### Auto-suggest

When a quarantined device has a runZero device type, HermitShell suggests an
appropriate group. Personal devices (phone, laptop, tablet, desktop,
workstation) are suggested for **Trusted**. IoT-class devices (printer, camera,
smart TV, NAS, media player, speaker, etc.) are suggested for **IoT**. A
one-click button lets you accept the suggestion.

### Recent connections

A table of the 50 most recent network connections made by this device:

| Column | Description |
|---|---|
| **Destination** | Remote IP address. |
| **Port** | Destination port. |
| **Protocol** | TCP or UDP. |
| **Sent** | Bytes sent. |
| **Received** | Bytes received. |
| **Time** | When the connection was established. |

### Recent DNS queries

A table of the 50 most recent DNS lookups from this device:

| Column | Description |
|---|---|
| **Domain** | The domain name queried. |
| **Type** | Query type (A, AAAA, CNAME, etc.). |
| **Time** | When the query was made. |

### Recent alerts

A table of the 50 most recent [alerts](alerts.md) triggered by this device:

| Column | Description |
|---|---|
| **Time** | When the alert fired. |
| **Rule** | Which behavioral analysis rule triggered it. |
| **Severity** | Low, medium, or high (color-coded badge). |
| **Message** | Human-readable description of what happened. |

---

## Device groups

HermitShell uses six device groups to control what each device can access.
Every device belongs to exactly one group. The firewall rules are enforced
automatically -- you just pick a group and HermitShell handles the rest.

| Group | Internet | Can reach | Reached by |
|---|---|---|---|
| **Trusted** | Yes | All groups except blocked | All groups except blocked |
| **IoT** | Yes | Internet only | Trusted |
| **Guest** | Yes | Internet only | None |
| **Servers** | Yes | Internet only | Trusted |
| **Quarantine** | Yes | Internet only | None |
| **Blocked** | No | Nothing | Nothing |

**Trusted** is the most permissive group -- devices here can talk to each
other and to devices in every other group (except blocked). Use it for
computers, phones, and tablets you own.

**IoT** devices get internet access but cannot initiate connections to other
devices on the LAN. Trusted devices can reach IoT devices (e.g., to control a
smart speaker). Good for smart home devices, cameras, and appliances.

**Guest** is fully isolated. Internet access, but no visibility into any other
device. Ideal for visitors.

**Servers** is similar to IoT -- internet access, no outbound LAN access -- but
trusted devices can reach them. Use it for a NAS, home server, or self-hosted
services.

**Quarantine** is the default group for new devices. Same policy as guest
(internet only, isolated from everything). Devices stay here until you approve
them into another group.

**Blocked** drops all traffic. The device cannot reach the internet or any other
device.

There is also a dedicated **Groups** page at `/groups` that shows each group
with its description, device count, and a full access policy matrix. It is a
handy reference when deciding where to place a device.
