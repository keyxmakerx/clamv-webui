//! Five-field cron expressions (minute hour day-of-month month day-of-week), in UTC.
//!
//! Supports `*`, lists, ranges, steps, `@hourly`, `@daily`, `@weekly` and
//! `@monthly`. When both day fields are restricted, either may match (as in cron).

use crate::timefmt::civil;

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
