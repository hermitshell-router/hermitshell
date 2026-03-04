# DNS & Ad Blocking

Configure DNS resolution, ad blocking, forward zones, and custom DNS records.
Changes take effect immediately -- no restart required.

---

## Status

The top of the page shows two pieces of information:

- **Ad Blocking** -- whether ad blocking is currently **Enabled** or
  **Disabled**.
- **DNS Resolver** -- always Unbound, running in recursive mode with DNSSEC
  validation.

Click the **Enable** or **Disable** button to toggle ad blocking on or off.
When enabled, queries matching any active blocklist are answered with
`0.0.0.0` (sinkholed). When disabled, all queries resolve normally.

---

## DNS Configuration

Displays the current DNS mode and rate limit settings.

**Mode** is either *Recursive (DNSSEC enabled)* when using the default
configuration, or *Forwarding to \<address\>* when an upstream DNS server has
been configured.

Two rate limits can be adjusted:

| Setting | Description |
|---|---|
| **Rate Limit (per client)** | Maximum queries per second from a single device. Set to 0 for unlimited. |
| **Rate Limit (per domain)** | Maximum queries per second for a single domain across all clients. Set to 0 for unlimited. |

Enter new values and click **Save** to apply.

---

## Block Lists

A table of blocklist sources used for ad blocking. Each entry has:

| Column | Description |
|---|---|
| **Name** | A label you choose (e.g., "StevenBlack Unified"). |
| **URL** | The HTTPS URL of the blocklist file. |
| **Tag** | Category: `ads`, `custom`, or `strict`. |
| **Enabled** | Toggle button -- click to enable or disable this list. |
| **Actions** | **Remove** button to delete the entry. |

### Adding a blocklist

Fill in the form below the table:

1. **Name** -- a descriptive label.
2. **URL** -- the full URL to the blocklist. Must use HTTPS.
3. **Tag** -- pick from the dropdown: `ads` (general advertising), `custom`
   (your own list), or `strict` (aggressive blocking that may cause
   false positives).

Click **Add**. The list is fetched and applied immediately.

> **Tip:** Blocklist URLs must use HTTPS. HTTP URLs will be rejected.

---

## Forward Zones

Route DNS queries for specific domains to a particular DNS server instead of
resolving them recursively. This is useful when you have internal domains
served by a local DNS server (e.g., `corp.local` resolved by `10.0.0.50`).

| Column | Description |
|---|---|
| **Domain** | The domain suffix to match (e.g., `example.local`). |
| **Forward Address** | The DNS server IP to forward matching queries to. |
| **Enabled** | Toggle button -- click to enable or disable this zone. |
| **Actions** | **Remove** button to delete the entry. |

### Adding a forward zone

1. **Domain** -- the domain to forward (e.g., `home.lab`).
2. **Forward Address** -- the IP of the DNS server that handles this domain.

Click **Add** to create the zone.

---

## Custom DNS Rules

Create local DNS records that override public resolution. Use this for
split-horizon DNS, internal service names, or overriding external domains.

| Column | Description |
|---|---|
| **Domain** | The fully qualified domain name. |
| **Type** | Record type: `A`, `AAAA`, `CNAME`, `MX`, or `TXT`. |
| **Value** | The record value (an IP address, hostname, or text string depending on type). |
| **Enabled** | Toggle button -- click to enable or disable this rule. |
| **Actions** | **Remove** button to delete the entry. |

### Adding a rule

1. **Domain** -- the domain name (e.g., `nas.home`).
2. **Type** -- select from the dropdown: A, AAAA, CNAME, MX, or TXT.
3. **Value** -- the record value (e.g., `10.0.0.100` for an A record).

Click **Add** to create the rule. It takes effect immediately.
