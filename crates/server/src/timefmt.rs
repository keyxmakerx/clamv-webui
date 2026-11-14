//! Small UTC date helpers (no time-zone database needed).

/// Civil date from days since 1970-01-01 (H. Hinnant's algorithm).
pub(crate) fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// Days since 1970-01-01 for a civil date.
pub(crate) fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn split(ms: i64) -> (i64, i64, i64, i64, i64, i64, i64) {
    let secs = ms.div_euclid(1000);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (y, m, d) = civil(days);
    (
        y,
        m,
        d,
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        ms.rem_euclid(1000),
    )
}

/// `2026-11-13 03:43:06 UTC`, for pages.
pub fn display(ms: i64) -> String {
    let (y, m, d, h, mi, s, _) = split(ms);
    format!("{y:04}-{m:02}-{d:02} {h:02}:{mi:02}:{s:02} UTC")
}

/// `2026-11-13T03:43:06.123Z`, for JSON.
pub fn rfc3339(ms: i64) -> String {
    let (y, m, d, h, mi, s, frac) = split(ms);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{frac:03}Z")
}

/// Parse `2026-11-14T10:00:00.123456789Z` or with a `+hh:mm` offset, to unix ms.
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.len() < 20 {
        return None;
    }
    let num = |a: usize, b: usize| -> Option<i64> { s.get(a..b)?.parse().ok() };
    let (y, m, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (h, mi, sec) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if s.get(4..5) != Some("-") || !matches!(s.get(10..11), Some("T" | "t" | " ")) {
        return None;
    }
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let mut rest = &s[19..];
    let mut ms = 0;
    if let Some(r) = rest.strip_prefix('.') {
        let digits: String = r.chars().take_while(char::is_ascii_digit).collect();
        let first3: String = digits.chars().chain("000".chars()).take(3).collect();
        ms = first3.parse().ok()?;
        rest = &r[digits.len()..];
    }
    let offset = match rest {
        "Z" | "z" => 0,
        o if o.len() == 6 && (o.starts_with('+') || o.starts_with('-')) => {
            let oh: i64 = o.get(1..3)?.parse().ok()?;
            let om: i64 = o.get(4..6)?.parse().ok()?;
            let v = (oh * 60 + om) * 60_000;
            if o.starts_with('-') { -v } else { v }
        }
        _ => return None,
    };
    let days = days_from_civil(y, m, d);
    Some((days * 86_400 + h * 3600 + mi * 60 + sec) * 1000 + ms - offset)
}

/// Parse clamd's signature date, e.g. `Thu Nov 12 09:00:00 2026`, as UTC.
pub fn parse_clamd_date(s: &str) -> Option<i64> {
    let mut it = s.split_whitespace();
    let _weekday = it.next()?;
    let mon = it.next()?;
    let day: i64 = it.next()?.parse().ok()?;
    let mut hms = it.next()?.split(':');
    let h: i64 = hms.next()?.parse().ok()?;
    let mi: i64 = hms.next()?.parse().ok()?;
    let sec: i64 = hms.next()?.parse().ok()?;
    let year: i64 = it.next()?.parse().ok()?;
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let m = months.iter().position(|x| *x == mon)? as i64 + 1;
    if !(1..=31).contains(&day) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let days = days_from_civil(year, m, day);
    Some((days * 86_400 + h * 3600 + mi * 60 + sec) * 1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_round_trip() {
        let t = parse_rfc3339("2026-11-14T10:00:00.123456789Z").expect("parse");
        assert_eq!(rfc3339(t), "2026-11-14T10:00:00.123Z");
        assert_eq!(
            parse_rfc3339("2026-11-14T12:00:00+02:00"),
            parse_rfc3339("2026-11-14T10:00:00Z")
        );
        assert!(parse_rfc3339("yesterday").is_none());
    }

    #[test]
    fn formats_and_parses() {
        assert_eq!(display(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(rfc3339(1_700_000_000_123), "2023-11-14T22:13:20.123Z");
        let t = parse_clamd_date("Thu Nov 12 09:00:00 2026").expect("date");
        assert_eq!(rfc3339(t), "2026-11-12T09:00:00.000Z");
        assert_eq!(parse_clamd_date("garbage"), None);
        for days in [-1000, 0, 365, 20_000, 60_000] {
            let (y, m, d) = civil(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
    }
}
