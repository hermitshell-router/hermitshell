# Logs

HermitShell records every connection and DNS query that crosses your network.
The Logs page gives you a searchable, read-only view of this data so you can
investigate incidents, verify that ad blocking is working, or just see what your
devices are up to.

---

## Tabs

The page has two tabs along the top:

- **Connection Logs** (`/logs`) -- the default view. Shows raw network
  connections flowing through the router.
- **DNS Logs** (`/logs?tab=dns`) -- shows DNS queries handled by the built-in
  resolver.

Clicking a tab switches the view without a full page reload. The selected tab is
reflected in the URL so you can bookmark or share a direct link to either view.

---

## Filter by Device

Both tabs include an optional filter form at the top. Enter a device IP address
and click **Filter** to narrow results to that device. Clear the field and
submit again to return to the full list.

The filter preserves your current tab -- filtering on the DNS tab stays on the
DNS tab, and vice versa.

---

## Connection Logs

The 200 most recent connections, newest first.

| Column | Description |
|---|---|
| **Time** | When the connection was recorded, shown in relative format ("2m ago", "1h ago", etc.). |
| **Source IP** | The originating device's IP address. |
| **Dest IP** | The destination IP the device connected to. |
| **Port** | The destination port number. |
| **Protocol** | TCP, UDP, or ICMP. |
| **Bytes Sent** | Data transmitted from source to destination. |
| **Bytes Recv** | Data received back by the source. |

Byte values are formatted automatically (B, KB, MB, GB) based on magnitude.

---

## DNS Logs

The 200 most recent DNS queries, newest first.

| Column | Description |
|---|---|
| **Time** | When the query was received, in relative format. |
| **Client IP** | The device that made the query. |
| **Domain** | The domain name that was looked up (e.g., `example.com`). |
| **Query Type** | The DNS record type -- A, AAAA, CNAME, MX, TXT, etc. |

Blocked queries (from ad blocking) appear alongside regular queries. Check the
[DNS & Ad Blocking](dns.md) page to manage blocklists and see block statistics.

---

## Audit Trail

The Audit Trail is a separate page at `/audit`, accessible from the main
navigation sidebar. It is a read-only, append-only log of every admin action
taken through the web UI or API.

| Column | Description |
|---|---|
| **Time** | When the action occurred, in relative format. |
| **Action** | What was done (e.g., "login", "update_device", "change_password", "backup_export"). |
| **Detail** | Additional context -- the device IP that was modified, the setting that changed, etc. |

The audit trail cannot be cleared or edited. It exists so you always have a
record of what changed and when, which is useful for troubleshooting unexpected
behavior or verifying that no unauthorized changes were made.
