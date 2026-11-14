//! Server-drawn SVG charts (no inline script or style, so the CSP stays strict).

use std::fmt::Write;

use crate::db::stats::Bucket;

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Short local label for a bucket start.
pub fn label(ms: i64, offset_ms: i64, hourly: bool) -> String {
    let local = ms + offset_ms;
    let days = local.div_euclid(86_400_000);
    let (_, m, d) = crate::timefmt::civil(days);
    const MON: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let mon = MON[usize::try_from(m - 1).unwrap_or(0).min(11)];
    if hourly {
        let h = local.rem_euclid(86_400_000) / 3_600_000;
        format!("{mon} {d} {h:02}:00")
    } else {
        format!("{mon} {d}")
    }
}

/// Stacked bars: clean, detections, failures. Each bar links to the matching jobs.
pub fn activity(
    buckets: &[Bucket],
    since: i64,
    bucket_ms: i64,
    count: usize,
    offset_ms: i64,
    hourly: bool,
) -> String {
    const W: f64 = 760.0;
    const H: f64 = 200.0;
    const PAD_L: f64 = 36.0;
    const PAD_B: f64 = 22.0;
    let first = (since + offset_ms) - (since + offset_ms).rem_euclid(bucket_ms) - offset_ms;
    let slots: Vec<Bucket> = (0..count)
        .map(|i| {
            let start = first + i64::try_from(i).unwrap_or(0) * bucket_ms;
            buckets
                .iter()
                .find(|b| b.start == start)
                .cloned()
                .unwrap_or(Bucket {
                    start,
                    ..Default::default()
                })
        })
        .collect();
    let max = slots.iter().map(|b| b.total).max().unwrap_or(0).max(1);
    // A rounded axis top.
    let step = [
        1, 2, 5, 10, 20, 25, 50, 100, 200, 250, 500, 1000, 2000, 5000, 10_000, 25_000, 50_000,
        100_000,
    ]
    .into_iter()
    .find(|s| max <= s * 4)
    .unwrap_or(max / 4 + 1);
    let top = step * ((max + step - 1) / step).max(1);
    let plot_h = H - PAD_B - 8.0;
    #[allow(clippy::cast_precision_loss)]
    let y = |v: i64| 8.0 + plot_h - (v as f64 / top as f64) * plot_h;
    #[allow(clippy::cast_precision_loss)]
    let bw = (W - PAD_L - 24.0) / count.max(1) as f64;
    let mut s = String::new();
    let _ = write!(
        s,
        r#"<svg class="chart" viewBox="0 0 {W} {H}" role="img" aria-label="Scans over time: clean, detections and failures">"#
    );
    let mut v = 0;
    while v <= top {
        let yy = y(v);
        let _ = write!(
            s,
            r#"<line class="chart-grid" x1="{PAD_L}" x2="{W}" y1="{yy:.1}" y2="{yy:.1}"/><text class="chart-axis" x="{:.1}" y="{:.1}" text-anchor="end">{v}</text>"#,
            PAD_L - 6.0,
            yy + 4.0
        );
        v += step;
    }
    let every = (count / 8).max(1);
    for (i, b) in slots.iter().enumerate() {
        #[allow(clippy::cast_precision_loss)]
        let x = PAD_L + i as f64 * bw + bw * 0.12;
        let w = (bw * 0.76).max(1.0);
        let clean = b.total - b.detections - b.errors;
        let tip = format!(
            "{}: {} scan(s), {} with detections, {} failed",
            label(b.start, offset_ms, hourly),
            b.total,
            b.detections,
            b.errors
        );
        let _ = write!(
            s,
            r#"<a href="/jobs?since={}&amp;until={}" aria-label="{}"><title>{}</title><rect class="chart-hit" x="{x:.1}" y="8" width="{w:.1}" height="{plot_h:.1}"/>"#,
            b.start,
            b.start + bucket_ms,
            esc(&tip),
            esc(&tip)
        );
        let mut base = 0;
        for (n, class) in [
            (clean, "bar-ok"),
            (b.errors, "bar-err"),
            (b.detections, "bar-hit"),
        ] {
            if n > 0 {
                let y1 = y(base + n);
                let h = y(base) - y1;
                let _ = write!(
                    s,
                    r#"<rect class="{class}" x="{x:.1}" y="{y1:.1}" width="{w:.1}" height="{h:.1}" rx="2"/>"#
                );
                base += n;
            }
        }
        s.push_str("</a>");
        if i % every == 0 {
            let _ = write!(
                s,
                r#"<text class="chart-axis" x="{:.1}" y="{:.1}" text-anchor="middle">{}</text>"#,
                x + w / 2.0,
                H - 6.0,
                esc(&label(b.start, offset_ms, hourly))
            );
        }
    }
    s.push_str("</svg>");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draws_every_slot_and_escapes() {
        let b = vec![Bucket {
            start: 0,
            total: 5,
            detections: 1,
            errors: 1,
        }];
        let svg = activity(&b, 0, 3_600_000, 24, 0, true);
        assert_eq!(svg.matches("<a href=\"/jobs?since=").count(), 24);
        assert!(svg.contains("bar-hit") && svg.contains("bar-err") && svg.contains("bar-ok"));
        assert!(svg.contains("Jan 1 00:00: 5 scan(s), 1 with detections, 1 failed"));
        assert!(!svg.contains("style="), "CSP: no inline styles");
    }
}
