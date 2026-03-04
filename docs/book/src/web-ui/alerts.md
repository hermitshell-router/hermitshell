# Alerts

The Alerts page shows anomalies detected by HermitShell's behavioral analysis
engine. Each alert identifies a device doing something unusual -- a DNS pattern
that looks like beaconing, a traffic spike to new destinations, connections on
suspicious ports, and similar signals.

> **Note:** Alerts require behavioral analysis to be enabled. Turn it on at
> **Settings > Analyzer**. Alert rules are also configured there.

---

## Alerts Table

Alerts are listed newest-first in a table with these columns:

| Column | Description |
|---|---|
| **Time** | Relative timestamp (e.g., "5m ago", "2h ago", "3d ago") |
| **Device** | MAC address of the device that triggered the alert, linked to the [device detail](devices.md) page |
| **Rule** | Which detection rule fired (see [Alert Rules](#alert-rules) below) |
| **Severity** | Badge colored by level: **high** (red), **medium** (yellow), **low** (green) |
| **Message** | Human-readable description of what was detected |
| **Actions** | **Ack** button for unacknowledged alerts |

---

## Alert Rules

HermitShell ships with five built-in detection rules. Each can be enabled or
disabled individually in **Settings > Analyzer**.

| Rule | What it detects |
|---|---|
| **DNS Beaconing** | A device making DNS queries at regular intervals to the same domain -- a common pattern for malware command-and-control callbacks |
| **DNS Volume Spike** | An unusual surge in DNS query volume from a single device compared to its baseline |
| **New Destination Spike** | A device suddenly connecting to many IP addresses it has never contacted before |
| **Suspicious Ports** | Outbound connections to ports commonly associated with malware, botnets, or unauthorized services |
| **Bandwidth Spike** | A device consuming significantly more bandwidth than its historical average |

---

## Severity Levels

Each alert is assigned one of three severity levels:

| Severity | Badge Color | Meaning |
|---|---|---|
| **High** | Red | Likely malicious or requires immediate attention |
| **Medium** | Yellow | Suspicious -- worth investigating |
| **Low** | Green | Informational -- minor anomaly or low-confidence detection |

---

## Acknowledging Alerts

Unacknowledged alerts appear in full contrast. To acknowledge an alert, click
the **Ack** button in its row. Acknowledged alerts are grayed out and remain
visible in the table so you can review past events.

To acknowledge everything at once, click the **Acknowledge All** button at the
top of the page. This marks every currently unacknowledged alert as read.

Acknowledging an alert does not delete it or change any firewall rules. It is
purely a bookkeeping action -- a way to mark that you have seen and considered
the alert.

---

## Workflow

A typical response to an alert:

1. Review the alert message and severity.
2. Click the device MAC to open its detail page. Check recent connections, DNS
   queries, and traffic patterns.
3. If the device looks compromised, move it to the **quarantine** or **blocked**
   group on the [Devices](devices.md) page.
4. Acknowledge the alert once you have taken action (or decided it is a false
   positive).
5. If a rule generates too many false positives, adjust or disable it in
   **Settings > Analyzer**.
