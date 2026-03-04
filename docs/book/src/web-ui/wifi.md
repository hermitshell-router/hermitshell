# WiFi

HermitShell is a wired router, but it can manage external WiFi access points
over the network. The WiFi page lets you add AP providers, configure SSIDs, tune
radios, see connected clients, and kick misbehaving devices -- all from one
place.

> **Tip:** Your access points must be reachable from the router's LAN. Connect
> them to the same switch as HermitShell's LAN port.

---

## WiFi Providers

A **provider** is the controller or standalone AP that HermitShell talks to.
The top of the page shows a table of configured providers:

| Column | Description |
|---|---|
| **Name** | Friendly label you chose when adding the provider |
| **Type** | UniFi or TP-Link EAP |
| **URL** | Controller URL or AP IP address |
| **Status** | Connection state (connected, unreachable, auth error) |
| **APs** | Number of access points discovered through this provider |

Each row has two buttons:

- **Manage SSIDs** -- opens the SSID list for that provider (see
  [SSIDs](#ssids) below)
- **Remove** -- deletes the provider and all its associated configuration

### Supported provider types

**UniFi Controller** -- for Ubiquiti UniFi access points managed by a UniFi OS
console (UDM, UDR, Cloud Key Gen2+) or a legacy software controller. HermitShell
connects to the controller API over HTTPS. Auth options:

- Username + password (local admin account on the controller)
- API key (UniFi OS 8+ supports API keys as an alternative to password auth)

On first connection, HermitShell pins the controller's TLS certificate using
TOFU (trust on first use). Subsequent connections reject any certificate that
does not match the pinned fingerprint, protecting against MITM attacks even when
the controller uses a self-signed cert.

**TP-Link EAP (standalone)** -- for TP-Link EAP series access points (EAP720
and similar) running in standalone mode, not managed by an Omada controller.
HermitShell connects directly to the AP's IP address over HTTPS.

---

## Add Provider

Below the provider table is an **Add WiFi Provider** form with these fields:

| Field | Notes |
|---|---|
| **Provider Type** | Dropdown: *TP-Link EAP (standalone)* or *UniFi Controller* |
| **Name** | A friendly label (e.g., "Office WiFi") |
| **Username** | Admin username on the AP or controller (defaults to `admin`) |
| **Password** | Admin password |

Additional fields appear depending on the type:

**For TP-Link EAP (standalone):**

| Field | Notes |
|---|---|
| **AP MAC Address** | The access point's MAC (e.g., `aa:bb:cc:dd:ee:ff`) |
| **AP IP Address** | The AP's LAN IP (e.g., `192.168.1.100`) |

**For UniFi Controller:**

| Field | Notes |
|---|---|
| **Site** | UniFi site name (defaults to `default`; most setups only have one) |
| **API Key** | Optional. If provided, used instead of username/password |

Click **Add Provider**. HermitShell will attempt to connect immediately and
report success or an error.

---

## Access Points

The **Access Points** table lists every AP discovered through your providers:

| Column | Description |
|---|---|
| **Name** | AP model or label reported by the provider |
| **MAC** | AP hardware address |
| **IP** | AP IP address on the LAN |
| **Provider** | Which provider manages this AP |
| **Status** | Online, offline, or upgrading |

Click **Manage** on any row to expand it and reveal two detail panels: Radios
and Connected Clients. Click **Close** to collapse.

### Radios

Each AP has one or more radios (typically 2.4 GHz and 5 GHz). The expanded view
shows a card per radio with these settings:

| Field | Options |
|---|---|
| **Channel** | Numeric channel (e.g., `1`, `6`, `36`, `149`) or auto |
| **Width** | 20 MHz, 40 MHz, 80 MHz, 160 MHz, or Auto |
| **TX Power** | Transmit power level (provider-specific units) |
| **Enabled** | Checkbox to enable or disable the radio |

Change any value and click **Save Radio** to apply.

### Connected Clients

Below the radios is a table of wireless clients currently associated with that
AP:

| Column | Description |
|---|---|
| **Client MAC** | Client device hardware address |
| **SSID** | Network name the client is connected to |
| **Band** | 2.4 GHz or 5 GHz |
| **RSSI** | Signal strength in dBm (e.g., -45 dBm is strong, -80 dBm is weak) |
| **RX Rate** | Receive data rate in Mbps |
| **TX Rate** | Transmit data rate in Mbps |

---

## SSIDs

Click **Manage SSIDs** on a provider row to view and edit its SSIDs. The SSID
table shows:

| Column | Description |
|---|---|
| **Name** | Network name broadcast by the AP |
| **Band** | 2.4 GHz or 5 GHz |
| **Security** | WPA2/WPA3, WPA-PSK, or None (Open) |
| **Hidden** | Yes or No -- hidden SSIDs are not broadcast |
| **Enabled** | Yes or No |

Each row has a **Delete** button to remove the SSID.

### Add / Edit SSID

Below the SSID table is a form to create or update an SSID:

| Field | Notes |
|---|---|
| **SSID Name** | Up to 32 characters. If the name matches an existing SSID on the same band, it updates the existing one. |
| **Password** | Leave blank for an open network |
| **Band** | 2.4 GHz or 5 GHz |
| **Security** | WPA2/WPA3 (recommended), WPA-PSK, or None (Open) |
| **Hidden** | Checkbox -- when checked, the AP will not broadcast this SSID |

Click **Save SSID** to apply. Changes take effect on the AP within a few
seconds.

---

## WiFi Clients

The bottom of the page shows a combined **WiFi Clients** table across all
providers and APs:

| Column | Description |
|---|---|
| **MAC** | Client hardware address |
| **AP** | MAC of the access point the client is associated with |
| **SSID** | Network name |
| **Band** | 2.4 GHz or 5 GHz |
| **RSSI** | Signal strength in dBm |
| **Actions** | **Kick** button |

### Kick Client

Click **Kick** to immediately disconnect a wireless client. The client's device
will typically reconnect automatically within a few seconds unless you also
change the SSID password or disable the network. Kicking is useful for forcing a
client to re-associate (for example, to move it to a closer AP) or for
temporarily booting an unwanted device.
