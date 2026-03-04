# Traffic

Real-time bandwidth monitoring for every device on your network. This page is
read-only -- there are no actions to take, just data to watch.

---

## Summary Cards

Two cards at the top show aggregate totals across all devices:

- **Total Downloaded (RX)** -- cumulative bytes received by all devices since
  counters were last reset.
- **Total Uploaded (TX)** -- cumulative bytes sent by all devices.

Values are formatted automatically (B, KB, MB, GB) based on magnitude.

---

## Network Bandwidth Chart

A 24-hour SVG chart showing network-wide bandwidth over time. This gives you a
quick visual of when your network is busiest and whether any traffic spikes
stand out.

---

## Real-time Throughput

A table of devices that are actively transferring data right now. Devices with
zero throughput in both directions are hidden -- only devices with at least one
non-zero rate appear.

| Column | Description |
|---|---|
| **Device** | The device IP address, linked to its detail page. |
| **Download** | Current receive rate. |
| **Upload** | Current transmit rate. |

Rates are formatted in the most readable unit: B/s, KB/s, MB/s, or GB/s.

The table sorts by total throughput (download + upload) descending, so the
heaviest consumers appear first.

The page auto-refreshes every 10 seconds. If no device is actively
transferring, this section is hidden entirely.

---

## Device Traffic

A table of all devices sorted by total bytes transferred (highest first).

| Column | Description |
|---|---|
| **Hostname** | Device nickname or hostname, linked to the device detail page. Shows "(unknown)" if neither is set. |
| **IP** | The device's IPv4 address. |
| **Group** | The device group (trusted, IoT, guest, etc.) shown as a colored badge. |
| **Downloaded** | Total bytes received. |
| **Uploaded** | Total bytes sent. |
| **Total** | Downloaded + Uploaded combined. |

This table always shows every device regardless of current activity, giving you
a cumulative view of which devices have used the most bandwidth over time.
