//! Server-drawn SVG charts (no inline script or style, so the CSP stays strict).
//!
//! Every bar is a link with a `<title>` (tooltip) and an `aria-label`, so it can be reached and
//! read with the keyboard. The chart itself has a `<title>` and `<desc>`. Styling, hover and the
//! one-time grow animation live in `ops.css` (`.chart`, `.bar-stack`, `.chart-grow`).

use std::fmt::Write;

use crate::db::stats::Bucket;

const DAY: i64 = 86_400_000;

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

const MON: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn day_label(local: i64) -> String {
    let (_, m, d) = crate::timefmt::civil(local.div_euclid(DAY));
    let mon = MON[usize::try_from(m - 1).unwrap_or(0).min(11)];
    format!("{mon} {d}")
}

/// Short local label for a bucket start.
pub fn label(ms: i64, offset_ms: i64, hourly: bool) -> String {
    let local = ms + offset_ms;
    if hourly {
        let h = local.rem_euclid(DAY) / 3_600_000;
        format!("{} {h:02}:00", day_label(local))
    } else {
        day_label(local)
    }
}

/// X-axis labels for bucket starts: about eight, never overlapping. A day or less of hourly
/// buckets reads "14:00" (with the date at midnight); several days of sub-day buckets get one
/// date per labelled day, on local midnight; daily buckets get dates.
pub fn ticks(starts: &[i64], offset_ms: i64, bucket_ms: i64) -> Vec<Option<String>> {
    let count = starts.len();
    let per_day = (DAY / bucket_ms.max(1)).max(1);
    let span_days = i64::try_from(count).unwrap_or(0) / per_day;
    let every = (count / 8).max(1);
    starts
        .iter()
        .enumerate()
        .map(|(i, &ms)| {
            let local = ms + offset_ms;
            let midnight = local.rem_euclid(DAY) == 0;
            if per_day > 1 && span_days >= 2 {
                // Several days of 6-hour (or finer) buckets: dates on midnight only.
                let step = (span_days + 7) / 8;
                (midnight && local.div_euclid(DAY) % step.max(1) == 0).then(|| day_label(local))
            } else if per_day > 1 {
                (i % every == 0).then(|| {
                    if midnight {
                        day_label(local)
                    } else {
                        format!("{:02}:00", local.rem_euclid(DAY) / 3_600_000)
                    }
                })
            } else {
                (i % every == 0).then(|| day_label(local))
            }
        })
        .collect()
}

/// One bar of a stacked chart.
pub struct Bar {
    pub href: String,
    /// Tooltip and accessible name.
    pub tip: String,
    /// Axis label under the bar, if any.
    pub tick: Option<String>,
    /// Segments from the baseline up: (value, CSS class).
    pub segs: Vec<(i64, &'static str)>,
}

/// Stacked bar chart. `id` must be unique on the page (it names the title and desc).
/// `grow` adds `.chart-grow`, which animates the bars once; pass false for background refreshes.
pub fn stacked(
    bars: &[Bar],
    size: (f64, f64),
    id: &str,
    title: &str,
    desc: &str,
    grow: bool,
) -> String {
    let (w, h) = size;
    const PAD_L: f64 = 36.0;
    const PAD_R: f64 = 8.0;
    const PAD_T: f64 = 14.0;
    const PAD_B: f64 = 22.0;
    let total = |b: &Bar| b.segs.iter().map(|s| s.0).sum::<i64>();
    let max = bars.iter().map(total).max().unwrap_or(0).max(1);
    // A rounded axis top.
    let step = [
        1, 2, 5, 10, 20, 25, 50, 100, 200, 250, 500, 1000, 2000, 5000, 10_000, 25_000, 50_000,
        100_000,
    ]
    .into_iter()
    .find(|s| max <= s * 4)
    .unwrap_or(max / 4 + 1);
    let top = step * ((max + step - 1) / step).max(1);
    let plot_h = h - PAD_B - PAD_T;
    #[allow(clippy::cast_precision_loss)]
    let y = |v: i64| PAD_T + plot_h - (v as f64 / top as f64) * plot_h;
    #[allow(clippy::cast_precision_loss)]
    let bw = (w - PAD_L - PAD_R) / bars.len().max(1) as f64;
    let mut s = String::new();
    let _ = write!(
        s,
        r#"<svg class="chart{}" viewBox="0 0 {w} {h}" role="group" aria-labelledby="{id}-title {id}-desc"><title id="{id}-title">{}</title><desc id="{id}-desc">{}</desc>"#,
        if grow { " chart-grow" } else { "" },
        esc(title),
        esc(desc)
    );
    s.push_str(r#"<g aria-hidden="true">"#);
    let mut v = step;
    while v <= top {
        let yy = y(v);
        let _ = write!(
            s,
            r#"<line class="chart-grid" x1="{PAD_L}" x2="{:.1}" y1="{yy:.1}" y2="{yy:.1}"/><text class="chart-axis" x="{:.1}" y="{:.1}" text-anchor="end">{v}</text>"#,
            w - PAD_R,
            PAD_L - 6.0,
            yy + 4.0
        );
        v += step;
    }
    let base = y(0);
    let _ = write!(
        s,
        r#"<line class="chart-base" x1="{PAD_L}" x2="{:.1}" y1="{base:.1}" y2="{base:.1}"/><text class="chart-axis" x="{:.1}" y="{:.1}" text-anchor="end">0</text>"#,
        w - PAD_R,
        PAD_L - 6.0,
        base + 4.0
    );
    for (i, b) in bars.iter().enumerate() {
        if let Some(t) = &b.tick {
            #[allow(clippy::cast_precision_loss)]
            let cx = PAD_L + i as f64 * bw + bw / 2.0;
            let _ = write!(
                s,
                r#"<text class="chart-axis" x="{cx:.1}" y="{:.1}" text-anchor="middle">{}</text>"#,
                h - 6.0,
                esc(t)
            );
        }
    }
    s.push_str("</g>");
    for (i, b) in bars.iter().enumerate() {
        #[allow(clippy::cast_precision_loss)]
        let x = PAD_L + i as f64 * bw + bw * 0.14;
        let bar_w = (bw * 0.72).max(1.0);
        let _ = write!(
            s,
            r#"<a href="{}" aria-label="{t}"><title>{t}</title><rect class="chart-hit" x="{:.1}" y="{PAD_T}" width="{:.1}" height="{plot_h:.1}" rx="3"/><g class="bar-stack">"#,
            esc(&b.href),
            x - bw * 0.1,
            bar_w + bw * 0.2,
            t = esc(&b.tip)
        );
        let mut acc = 0;
        for (n, class) in &b.segs {
            if *n > 0 {
                let y1 = y(acc + n);
                let _ = write!(
                    s,
                    r#"<rect class="{class}" x="{x:.1}" y="{y1:.1}" width="{bar_w:.1}" height="{:.1}" rx="2"/>"#,
                    y(acc) - y1
                );
                acc += n;
            }
        }
        s.push_str("</g>");
        if acc > 0 {
            let _ = write!(
                s,
                r#"<text class="chart-val" x="{:.1}" y="{:.1}" text-anchor="middle">{acc}</text>"#,
                x + bar_w / 2.0,
                y(acc) - 4.0
            );
        }
        s.push_str("</a>");
    }
    s.push_str("</svg>");
    s
}

/// Stacked bars: clean, detections, failures. Each bar links to the matching jobs.
pub fn activity(
    buckets: &[Bucket],
    since: i64,
    bucket_ms: i64,
    count: usize,
    offset_ms: i64,
    hourly: bool,
    grow: bool,
) -> String {
    let first = (since + offset_ms) - (since + offset_ms).rem_euclid(bucket_ms) - offset_ms;
    let starts: Vec<i64> = (0..count)
        .map(|i| first + i64::try_from(i).unwrap_or(0) * bucket_ms)
        .collect();
    let ticks = ticks(&starts, offset_ms, bucket_ms);
    let bars: Vec<Bar> = starts
        .iter()
        .zip(ticks)
        .map(|(&start, tick)| {
            let b = buckets
                .iter()
                .find(|b| b.start == start)
                .cloned()
                .unwrap_or(Bucket {
                    start,
                    ..Default::default()
                });
            let clean = b.total - b.detections - b.errors;
            Bar {
                href: format!("/jobs?since={}&until={}", b.start, b.start + bucket_ms),
                tip: format!(
                    "{}: {} scan(s), {} with detections, {} failed",
                    label(b.start, offset_ms, hourly),
                    b.total,
                    b.detections,
                    b.errors
                ),
                tick,
                segs: vec![
                    (clean, "bar-ok"),
                    (b.errors, "bar-err"),
                    (b.detections, "bar-hit"),
                ],
            }
        })
        .collect();
    stacked(
        &bars,
        (760.0, 210.0),
        "activity",
        "Scans over time",
        "Stacked bars: clean scans, failed scans and scans with detections. Each bar links to its jobs.",
        grow,
    )
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
        let svg = activity(&b, 0, 3_600_000, 24, 0, true, true);
        assert_eq!(svg.matches("<a href=\"/jobs?since=").count(), 24);
        assert!(svg.contains("bar-hit") && svg.contains("bar-err") && svg.contains("bar-ok"));
        assert!(svg.contains("Jan 1 00:00: 5 scan(s), 1 with detections, 1 failed"));
        assert!(svg.contains("&amp;until="), "hrefs are escaped");
        assert!(!svg.contains("style="), "CSP: no inline styles");
    }

    #[test]
    fn accessible_and_grows_only_when_asked() {
        let svg = activity(&[], 0, 3_600_000, 24, 0, true, true);
        assert!(svg.contains(r#"aria-labelledby="activity-title activity-desc""#));
        assert!(svg.contains(r#"<title id="activity-title">"#) && svg.contains("<desc id="));
        assert!(svg.contains("chart chart-grow"));
        let quiet = activity(&[], 0, 3_600_000, 24, 0, true, false);
        assert!(!quiet.contains("chart-grow"));
        // Empty buckets draw no bar segments and no value labels.
        assert!(!quiet.contains("chart-val") && !quiet.contains("bar-ok"));
    }

    #[test]
    fn ticks_stay_sparse() {
        let hour = 3_600_000;
        let day: Vec<i64> = (0..25).map(|i| i * hour).collect();
        let t = ticks(&day, 0, hour);
        assert_eq!(t[0].as_deref(), Some("Jan 1"));
        assert_eq!(t[3].as_deref(), Some("03:00"));
        assert!(t.iter().flatten().count() <= 9);
        let week: Vec<i64> = (0..29).map(|i| i * 6 * hour).collect();
        let t = ticks(&week, 0, 6 * hour);
        assert_eq!(t.iter().flatten().count(), 8);
        assert!(t.iter().flatten().all(|l| l.starts_with("Jan ")));
        let month: Vec<i64> = (0..31).map(|i| i * DAY).collect();
        assert!(ticks(&month, 0, DAY).iter().flatten().count() <= 11);
    }
}
