# WireGuard VPN

The WireGuard page lets you run a VPN server on your router so you can access
your home network -- and route traffic through it -- from anywhere. Each peer
gets its own isolated subnet, just like a LAN device.

---

## Server

The top section shows the current state of the WireGuard interface:

| Field | Description |
|---|---|
| **Status** | Enabled or Disabled. Green when the tunnel is up. |
| **Public Key** | The server's WireGuard public key. Clients need this to connect. Shows a dash when WireGuard has never been enabled. |
| **Listen Port** | UDP port the server listens on. Defaults to **51820**. |

Click **Enable** or **Disable** to toggle the WireGuard interface on or off.
When you enable it for the first time, HermitShell generates a keypair
automatically.

---

## Peers

Below the server section is a table of configured peers:

| Column | Description |
|---|---|
| **Name** | Friendly label you chose when adding the peer. |
| **IP** | The peer's assigned address inside the tunnel. |
| **Group** | Device group that determines firewall policy (trusted, iot, guest, or servers). |
| **Public Key** | First 12 characters of the peer's public key, abbreviated for readability. |
| **Actions** | Change group or remove the peer. |

### Changing a peer's group

Each row has a **group dropdown** and a **Move** button. Select a new group and
click Move. The peer's firewall rules update immediately -- the same isolation
rules that apply to LAN devices in that group apply to the VPN peer.

### Removing a peer

Click **Remove** to delete a peer. This revokes its tunnel access and frees
its IP address.

---

## Add Peer

Use the form at the bottom of the Peers section to add a new VPN peer.

| Field | Description |
|---|---|
| **Peer Name** | A human-readable label (e.g., "laptop" or "phone"). |
| **Public Key** | The peer's WireGuard public key, base64-encoded. Generate this on the client with `wg genkey \| wg pubkey`. |
| **Device Group** | One of **trusted**, **iot**, **guest**, or **servers**. Controls what the peer can reach on your network. |

Click **Add Peer** to create the peer. HermitShell assigns it a dual-stack
address pair (IPv4 + IPv6) in its own /30 subnet, exactly like LAN devices.
The assigned IP appears in the peers table once the peer is created.

---

## Connecting a client

After adding a peer, configure the WireGuard client on that device:

1. Set **Endpoint** to your router's WAN IP address and port -- for example,
   `203.0.113.5:51820`.
2. Set the **server public key** to the value shown in the Server section above.
3. Set **AllowedIPs** to `0.0.0.0/0, ::/0` to route all traffic through the
   tunnel, or limit it to `10.0.0.0/8` for split-tunnel (home network only).
4. Use the peer's own private key (the one that generated the public key you
   entered in the Add Peer form).

> **Tip:** If your router is behind double NAT (e.g., an ISP-provided modem),
> you may need to forward UDP port 51820 on the upstream device to your
> router's WAN IP.
