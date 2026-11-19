//! Five-field cron expressions (minute hour day-of-month month day-of-week),
//! evaluated in UTC or in an IANA time zone (`next_after_in`).
//!
//! Supports `*`, lists, ranges, steps, `@hourly`, `@daily`, `@weekly` and
//! `@monthly`. When both day fields are restricted, either may match (as in cron).

use jiff::Timestamp;
use jiff::tz::TimeZone;

use crate::timefmt::civil;

/// An IANA zone name ("Europe/Berlin"); empty or "UTC" is UTC.
pub fn zone(name: &str) -> Result<TimeZone, String> {
    let name = name.trim();
    if name.is_empty() || name.eq_ignore_ascii_case("UTC") {
        return Ok(TimeZone::UTC);
    }
    if name.len() > 64 {
        return Err("time zone names are at most 64 characters".into());
    }
    TimeZone::get(name)
        .map_err(|_| format!("unknown time zone {name}; use a name like Europe/Berlin"))
}

/// Milliseconds east of UTC in `tz` at `ms`.
fn offset_ms(tz: &TimeZone, ms: i64) -> Option<i64> {
    let ts = Timestamp::from_millisecond(ms).ok()?;
    Some(i64::from(tz.to_offset(ts).seconds()) * 1000)
}

/// Minute of the day (0..1440) at `ms` in `tz`.
pub fn local_minute(tz: &TimeZone, ms: i64) -> i64 {
    (ms + offset_ms(tz, ms).unwrap_or(0))
        .div_euclid(60_000)
        .rem_euclid(1440)
}

/// A wall-clock time written as if it were UTC → the real instant in `tz`.
/// A time skipped by a DST change moves forward; a repeated one takes the first.
fn wall_to_real(tz: &TimeZone, wall_ms: i64) -> Option<i64> {
    let dt = TimeZone::UTC.to_datetime(Timestamp::from_millisecond(wall_ms).ok()?);
    let ts = tz.to_ambiguous_timestamp(dt).compatible().ok()?;
    Some(ts.as_millisecond())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cron {
    minute: u64,
    hour: u32,
    dom: u32,
    month: u16,
    dow: u8,
    dom_any: bool,
    dow_any: bool,
}

fn field(spec: &str, min: u32, max: u32) -> Result<(u64, bool), String> {
    let mut bits = 0u64;
    let any = spec == "*";
    for part in spec.split(',') {
        let (range, step) = match part.split_once('/') {
            Some((r, s)) => (
                r,
                s.parse::<u32>()
                    .map_err(|_| format!("bad step in {part}"))?,
            ),
            None => (part, 1),
        };
        if step == 0 {
            return Err(format!("zero step in {part}"));
        }
        let (lo, hi) = if range == "*" {
            (min, max)
        } else if let Some((a, b)) = range.split_once('-') {
            (
                a.parse().map_err(|_| format!("bad number in {part}"))?,
                b.parse().map_err(|_| format!("bad number in {part}"))?,
            )
        } else {
            let v: u32 = range.parse().map_err(|_| format!("bad number in {part}"))?;
            // `5/15` means from 5 to the end.
            (v, if part.contains('/') { max } else { v })
        };
        if lo < min || hi > max || lo > hi {
            return Err(format!("{part} is outside {min}-{max}"));
        }
        let mut v = lo;
        while v <= hi {
            bits |= 1 << v;
            v += step;
        }
    }
    Ok((bits, any))
}

impl std::str::FromStr for Cron {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let s = match s.trim() {
            "@hourly" => "0 * * * *",
            "@daily" | "@midnight" => "0 0 * * *",
            "@weekly" => "0 0 * * 0",
            "@monthly" => "0 0 1 * *",
            other => other,
        };
        let f: Vec<&str> = s.split_whitespace().collect();
        let [mi, h, dom, mon, dow] = f.as_slice() else {
            return Err("use five fields: minute hour day month weekday".into());
        };
        let (minute, _) = field(mi, 0, 59)?;
        let (hour, _) = field(h, 0, 23)?;
        let (dom_bits, dom_any) = field(dom, 1, 31)?;
        let (month, _) = field(mon, 1, 12)?;
        let (mut dow_bits, dow_any) = field(dow, 0, 7)?;
        if dow_bits & (1 << 7) != 0 {
            dow_bits |= 1; // 7 is Sunday too
        }
        Ok(Cron {
            minute,
            hour: hour as u32,
            dom: dom_bits as u32,
            month: month as u16,
            dow: (dow_bits & 0x7f) as u8,
            dom_any,
            dow_any,
        })
    }
}

impl Cron {
    fn day_matches(&self, days: i64) -> bool {
        let (_, m, d) = civil(days);
        if self.month & (1 << m) == 0 {
            return false;
        }
        let wd = (days + 4).rem_euclid(7); // 1970-01-01 was a Thursday
        let dom_ok = self.dom & (1 << d) != 0;
        let dow_ok = self.dow & (1 << wd) != 0;
        match (self.dom_any, self.dow_any) {
            (true, true) => true,
            (false, true) => dom_ok,
            (true, false) => dow_ok,
            (false, false) => dom_ok || dow_ok,
        }
    }

    /// The first matching minute strictly after `after_ms`, within five years.
    pub fn next_after(&self, after_ms: i64) -> Option<i64> {
        let mut t = after_ms.div_euclid(60_000) + 1; // whole minutes since epoch
        let limit = t + 5 * 366 * 1440;
        while t < limit {
            let days = t.div_euclid(1440);
            let mod_day = t.rem_euclid(1440);
            if !self.day_matches(days) {
                t = (days + 1) * 1440;
                continue;
            }
            let h = mod_day / 60;
            if self.hour & (1 << h) == 0 {
                t = days * 1440 + (h + 1) * 60;
                continue;
            }
            if self.minute & (1 << (mod_day % 60)) == 0 {
                t += 1;
                continue;
            }
            return Some(t * 60_000);
        }
        None
    }

    /// Like `next_after`, with the fields read as wall-clock time in `tz`.
    pub fn next_after_in(&self, after_ms: i64, tz: &TimeZone) -> Option<i64> {
        let mut wall = after_ms + offset_ms(tz, after_ms)?;
        // Around a DST fall-back a wall time can map to an instant already past.
        for _ in 0..8 {
            let cand = self.next_after(wall)?;
            let real = wall_to_real(tz, cand)?;
            if real > after_ms {
                return Some(real);
            }
            wall = cand;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timefmt::{days_from_civil, rfc3339};

    fn at(s: &str) -> i64 {
        // 2026-11-13T03:00:00Z style without fractions
        let (d, t) = s.split_once('T').expect("T");
        let p: Vec<i64> = d.split('-').map(|x| x.parse().expect("n")).collect();
        let q: Vec<i64> = t
            .trim_end_matches('Z')
            .split(':')
            .map(|x| x.parse().expect("n"))
            .collect();
        (days_from_civil(p[0], p[1], p[2]) * 86_400 + q[0] * 3600 + q[1] * 60) * 1000
    }

    fn next(expr: &str, from: &str) -> String {
        let c: Cron = expr.parse().expect("parse");
        rfc3339(c.next_after(at(from)).expect("next"))
    }

    #[test]
    fn computes_next_runs() {
        assert_eq!(
            next("30 2 * * *", "2026-11-13T03:00Z"),
            "2026-11-14T02:30:00.000Z"
        );
        assert_eq!(
            next("30 2 * * *", "2026-11-13T02:00Z"),
            "2026-11-13T02:30:00.000Z"
        );
        assert_eq!(
            next("*/15 * * * *", "2026-11-13T03:07Z"),
            "2026-11-13T03:15:00.000Z"
        );
        // 2026-11-13 is a Friday; next Sunday 04:00.
        assert_eq!(
            next("0 4 * * 0", "2026-11-13T03:00Z"),
            "2026-11-15T04:00:00.000Z"
        );
        assert_eq!(
            next("0 4 * * 7", "2026-11-13T03:00Z"),
            "2026-11-15T04:00:00.000Z"
        );
        assert_eq!(
            next("@monthly", "2026-11-13T03:00Z"),
            "2026-12-01T00:00:00.000Z"
        );
        assert_eq!(
            next("0 0 29 2 *", "2026-11-13T03:00Z"),
            "2028-02-29T00:00:00.000Z"
        );
        assert_eq!(
            next("0 3 1-7 * 1", "2026-11-13T03:00Z"),
            "2026-11-16T03:00:00.000Z",
            "dom or dow"
        );
        assert_eq!(
            next("0 9-17/4 * * 1-5", "2026-11-13T10:00Z"),
            "2026-11-13T13:00:00.000Z"
        );
    }

    #[test]
    fn runs_in_a_time_zone() {
        let berlin = zone("Europe/Berlin").expect("zone");
        let c: Cron = "0 2 * * *".parse().expect("parse");
        // Winter: 02:00 in Berlin is 01:00Z.
        assert_eq!(
            rfc3339(
                c.next_after_in(at("2026-11-13T03:00Z"), &berlin)
                    .expect("n")
            ),
            "2026-11-14T01:00:00.000Z"
        );
        // Summer: 00:00Z.
        assert_eq!(
            rfc3339(
                c.next_after_in(at("2026-07-01T03:00Z"), &berlin)
                    .expect("n")
            ),
            "2026-07-02T00:00:00.000Z"
        );
        // 2026-03-29 02:30 does not exist in Berlin: runs at 03:30 local (01:30Z), once.
        let c: Cron = "30 2 * * *".parse().expect("parse");
        let first = c
            .next_after_in(at("2026-03-28T12:00Z"), &berlin)
            .expect("n");
        assert_eq!(rfc3339(first), "2026-03-29T01:30:00.000Z");
        assert_eq!(
            rfc3339(c.next_after_in(first, &berlin).expect("n")),
            "2026-03-30T00:30:00.000Z"
        );
        // 2026-10-25 02:30 happens twice in Berlin: runs once.
        let first = c
            .next_after_in(at("2026-10-24T12:00Z"), &berlin)
            .expect("n");
        assert_eq!(rfc3339(first), "2026-10-25T00:30:00.000Z");
        assert_eq!(
            rfc3339(c.next_after_in(first, &berlin).expect("n")),
            "2026-10-26T01:30:00.000Z"
        );
        assert_eq!(local_minute(&berlin, at("2026-11-13T23:30Z")), 30);
        assert!(zone("Mars/Olympus").is_err());
        assert_eq!(zone("").expect("utc"), TimeZone::UTC);
    }

    #[test]
    fn rejects_bad_expressions() {
        for bad in [
            "",
            "* * * *",
            "60 * * * *",
            "* 24 * * *",
            "* * 0 * *",
            "*/0 * * * *",
            "a * * * *",
            "5-1 * * * *",
        ] {
            assert!(bad.parse::<Cron>().is_err(), "{bad}");
        }
        assert!("0 31 2 *".parse::<Cron>().is_err());
        assert!(
            "0 0 31 2 *"
                .parse::<Cron>()
                .expect("parses")
                .next_after(0)
                .is_none(),
            "never"
        );
    }
}
