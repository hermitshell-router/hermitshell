use hermitshell_common::{BandwidthPoint, DevicePresenceRecord};

/// Render a stacked area SVG chart for bandwidth data.
/// Returns an SVG string suitable for embedding in HTML.
pub fn bandwidth_chart(data: &[BandwidthPoint], width: u32, height: u32) -> String {
    if data.is_empty() {
        return format!(
            r##"<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">
                <title>Network bandwidth chart — no data available</title>
                <text x="{}" y="{}" fill="#A67C52" font-size="14" text-anchor="middle">No data</text>
            </svg>"##,
            width / 2, height / 2
        );
    }

    let margin_left = 70u32;
    let margin_right = 20u32;
    let margin_top = 20u32;
    let margin_bottom = 40u32;
    let chart_w = width - margin_left - margin_right;
    let chart_h = height - margin_top - margin_bottom;

    // Find max value for Y axis (rx + tx stacked)
    let max_val = data.iter()
        .map(|p| p.rx_bytes + p.tx_bytes)
        .max()
        .unwrap_or(1)
        .max(1) as f64;

    let n = data.len();
    let x_step = if n > 1 { chart_w as f64 / (n - 1) as f64 } else { chart_w as f64 };

    // Build path data for RX (bottom) and TX (top, stacked on RX)
    let mut rx_points = String::new();
    let mut total_points = String::new();

    for (i, p) in data.iter().enumerate() {
        let x = margin_left as f64 + i as f64 * x_step;
        let rx_h = (p.rx_bytes as f64 / max_val) * chart_h as f64;
        let total_h = ((p.rx_bytes + p.tx_bytes) as f64 / max_val) * chart_h as f64;
        let rx_y = (margin_top + chart_h) as f64 - rx_h;
        let total_y = (margin_top + chart_h) as f64 - total_h;

        if i == 0 {
            rx_points.push_str(&format!("M{x:.1},{rx_y:.1}"));
            total_points.push_str(&format!("M{x:.1},{total_y:.1}"));
        } else {
            rx_points.push_str(&format!("L{x:.1},{rx_y:.1}"));
            total_points.push_str(&format!("L{x:.1},{total_y:.1}"));
        }
    }

    // Close paths for fill (go to baseline and back)
    let baseline_y = (margin_top + chart_h) as f64;
    let last_x = margin_left as f64 + (n - 1).max(0) as f64 * x_step;
    let first_x = margin_left as f64;

    let rx_fill = format!("{rx_points}L{last_x:.1},{baseline_y:.1}L{first_x:.1},{baseline_y:.1}Z");
    // TX fill: goes along total line, then back along rx line (reversed)
    let mut rx_reversed = String::new();
    for (i, p) in data.iter().enumerate().rev() {
        let x = margin_left as f64 + i as f64 * x_step;
        let rx_h = (p.rx_bytes as f64 / max_val) * chart_h as f64;
        let rx_y = (margin_top + chart_h) as f64 - rx_h;
        rx_reversed.push_str(&format!("L{x:.1},{rx_y:.1}"));
    }
    let tx_fill = format!("{total_points}{rx_reversed}Z");

    // Y-axis labels (5 ticks)
    let mut y_labels = String::new();
    for i in 0..=4 {
        let val = max_val * i as f64 / 4.0;
        let y = (margin_top + chart_h) as f64 - (i as f64 / 4.0) * chart_h as f64;
        let label = format_bytes_short(val as i64);
        y_labels.push_str(&format!(
            r##"<text x="{}" y="{:.1}" fill="#A67C52" font-size="11" text-anchor="end" dominant-baseline="middle">{label}</text>"##,
            margin_left - 8, y
        ));
        // Grid line
        y_labels.push_str(&format!(
            r##"<line x1="{}" y1="{y:.1}" x2="{}" y2="{y:.1}" stroke="#D4CFC7" stroke-width="0.5" />"##,
            margin_left, margin_left + chart_w
        ));
    }

    // X-axis labels (up to 6 labels)
    let mut x_labels = String::new();
    let label_count = 6.min(n);
    if label_count > 0 {
        let step = if label_count > 1 { (n - 1) / (label_count - 1) } else { 0 };
        for i in 0..label_count {
            let idx = (i * step).min(n - 1);
            let x = margin_left as f64 + idx as f64 * x_step;
            let bucket = data[idx].bucket;
            let label = format_time_label(bucket);
            x_labels.push_str(&format!(
                r##"<text x="{x:.1}" y="{}" fill="#A67C52" font-size="11" text-anchor="middle">{label}</text>"##,
                margin_top + chart_h + 20
            ));
        }
    }

    format!(
        r##"<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" style="background:var(--cream,#FDFCFA)">
            <title>Network bandwidth chart showing download and upload over time</title>
            {y_labels}
            {x_labels}
            <path d="{rx_fill}" fill="rgba(82,183,136,0.25)" />
            <path d="{tx_fill}" fill="rgba(233,163,25,0.25)" />
            <path d="{rx_points}" fill="none" stroke="#52B788" stroke-width="1.5" />
            <path d="{total_points}" fill="none" stroke="#E9A319" stroke-width="1.5" />
            <rect x="{}" y="5" width="12" height="12" fill="rgba(82,183,136,0.25)" />
            <text x="{}" y="15" fill="#A67C52" font-size="11">RX</text>
            <rect x="{}" y="5" width="12" height="12" fill="rgba(233,163,25,0.25)" />
            <text x="{}" y="15" fill="#A67C52" font-size="11">TX</text>
        </svg>"##,
        width - 90, width - 75,
        width - 50, width - 35,
    )
}

fn format_bytes_short(bytes: i64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.0} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Render a horizontal presence timeline SVG.
/// Green segments = online, dark = offline.
pub fn presence_timeline(
    records: &[DevicePresenceRecord],
    period_start: i64,
    period_end: i64,
    width: u32,
    height: u32,
) -> String {
    let total_secs = (period_end - period_start).max(1) as f64;
    let bar_height = height.saturating_sub(20);

    let mut segments = String::new();

    for (i, rec) in records.iter().enumerate() {
        let end_ts = if i + 1 < records.len() { records[i + 1].ts } else { period_end };
        let x = ((rec.ts - period_start) as f64 / total_secs * width as f64).max(0.0);
        let w = ((end_ts - rec.ts) as f64 / total_secs * width as f64).max(0.5);
        let fill = if rec.state == "online" { "rgba(82,183,136,0.4)" } else { "rgba(212,207,199,0.5)" };
        segments.push_str(&format!(
            r##"<rect x="{x:.1}" y="0" width="{w:.1}" height="{bar_height}" fill="{fill}" />"##,
        ));
    }

    if records.is_empty() {
        segments = format!(
            r##"<rect x="0" y="0" width="{width}" height="{bar_height}" fill="rgba(212,207,199,0.5)" />"##,
        );
    }

    let start_label = format_date_short(period_start);
    let end_label = format_date_short(period_end);

    format!(
        r##"<svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg" style="background:var(--cream,#FDFCFA)">
            <title>Device presence timeline showing online and offline periods</title>
            {segments}
            <text x="4" y="{}" fill="#A67C52" font-size="10">{start_label}</text>
            <text x="{}" y="{}" fill="#A67C52" font-size="10" text-anchor="end">{end_label}</text>
        </svg>"##,
        height - 4,
        width - 4, height - 4,
    )
}

fn format_date_short(epoch: i64) -> String {
    let days_since_epoch = epoch / 86400;
    let day_of_year = (days_since_epoch % 365) as u32;
    let month = day_of_year / 30 + 1;
    let day = day_of_year % 30 + 1;
    format!("{month}/{day}")
}

fn format_time_label(epoch: i64) -> String {
    // Simple UTC time formatting without external crate
    let secs_in_day = epoch % 86400;
    let hour = secs_in_day / 3600;
    // For daily buckets (epoch is midnight), show month/day
    // For hourly buckets, show HH:00
    // Heuristic: if epoch is exactly divisible by 86400, it's a daily bucket
    if epoch % 86400 == 0 {
        // Daily bucket — show approximate month/day
        let days_since_epoch = epoch / 86400;
        let day_of_year = (days_since_epoch % 365) as u32;
        let month = day_of_year / 30 + 1;
        let day = day_of_year % 30 + 1;
        format!("{month}/{day}")
    } else {
        format!("{hour:02}:00")
    }
}
