# Port Forwarding

The Port Forwarding page manages inbound access to devices on your network.
You can create manual rules, enable automatic mappings via UPnP/NAT-PMP/PCP,
set a DMZ host, and open IPv6 pinholes.

---

## Rules

The rules table lists every active port forward:

| Column | Description |
|---|---|
| **Protocol** | TCP, UDP, or TCP+UDP. |
| **External Port(s)** | The port or port range exposed on the WAN side. A single port shows as one number; a range shows as `start-end`. |
| **Internal IP** | The LAN device that receives the forwarded traffic. |
| **Internal Port** | The port on the internal device. |
| **Description** | Optional label describing what the rule is for. |
| **Source** | How the rule was created -- **Manual**, **UPnP**, **NAT-PMP**, or **PCP**. |
| **Enabled** | Toggle a rule on or off without deleting it. Click **Enable** or **Disable** in this column. |
| **Actions** | **Remove** deletes the rule permanently. |

Rules created automatically by UPnP/NAT-PMP/PCP show their source label so you
can tell them apart from manual rules. You can disable or remove auto-created
rules the same way you would a manual one.

---

## Add Rule

Use the form below the rules table to create a manual port forward.

| Field | Description |
|---|---|
| **Protocol** | TCP+UDP (default), TCP, or UDP. |
| **External Port Start** | First port in the range (1--65535). For a single port, enter the same value in both start and end. |
| **External Port End** | Last port in the range. |
| **Internal IP** | The LAN IP of the destination device (e.g., `10.0.x.x`). |
| **Internal Port** | The port on the internal device that should receive the traffic. |
| **Description** | Optional free-text label. |

Click **Add** to create the rule. It takes effect immediately.

---

## DMZ Host

The DMZ section shows the current DMZ host IP, or "None" if no DMZ is
configured. A DMZ host receives all inbound traffic that does not match any
specific port forward rule -- effectively exposing the device to the internet.

> **Tip:** Only use DMZ for devices that are designed to be internet-facing
> (e.g., a firewall appliance or a dedicated server). Placing a regular
> workstation in the DMZ bypasses most of HermitShell's inbound protection.

---

## UPnP / NAT-PMP / PCP

This section lets trusted devices on your network request port forwards
automatically using the UPnP, NAT-PMP, or PCP protocols. Many games, chat
applications, and media servers use these protocols to open ports without manual
configuration.

- **Status** shows whether automatic mapping is currently enabled or disabled.
- Click **Enable UPnP** or **Disable UPnP** to toggle it.
- Only devices in the **trusted** group can request automatic mappings.
- Auto-created rules appear in the Rules table above with their source label
  (UPnP, NAT-PMP, or PCP) and can be removed manually at any time.

> **Note:** Toggling UPnP/NAT-PMP/PCP requires an agent restart to take effect.

---

## IPv6 Pinholes

IPv6 pinholes allow inbound IPv6 connections to reach specific devices. Unlike
IPv4 port forwarding (which uses NAT), IPv6 pinholes open firewall rules for
devices that already have globally routable addresses.

The pinholes table shows:

| Column | Description |
|---|---|
| **Device MAC** | MAC address of the device the pinhole applies to. |
| **Protocol** | TCP or UDP. |
| **Port Start** | First port in the allowed range. |
| **Port End** | Last port in the range. |
| **Description** | Optional label. |
| **Actions** | **Remove** deletes the pinhole. |

### Add Pinhole

Use the form below the table to create a new pinhole:

| Field | Description |
|---|---|
| **Device MAC** | The MAC address of the target device (e.g., `AA:BB:CC:DD:EE:FF`). |
| **Protocol** | TCP or UDP. |
| **Port Start** | First port to open (1--65535). |
| **Port End** | Last port to open. Use the same value as Port Start for a single port. |
| **Description** | Optional free-text label. |

Click **Add** to create the pinhole. It takes effect immediately.
