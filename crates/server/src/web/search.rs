//! Search box syntax shared by Jobs and Detections.
//!
//! `word` or `"two words"` matches text; `field:value` contains, `field=value`
//! is exact; `-` in front negates; `after:2026-11-01`, `before:2026-11-14`
//! and `since:24h` / `since:7d` limit dates.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Term {
    pub field: Option<String>,
    pub exact: bool,
    pub negate: bool,
    pub value: String,
}

/// Split into terms. At most 20 terms of 256 characters each.
pub fn parse(q: &str) -> Vec<Term> {
    let mut out = Vec::new();
    let mut chars = q.chars().peekable();
    while out.len() < 20 {
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }
        let Some(&first) = chars.peek() else { break };
        let negate = first == '-';
        if negate {
            chars.next();
        }
        let mut word = String::new();
        let mut quoted = false;
        while let Some(&c) = chars.peek() {
            if c == '"' {
                quoted = !quoted;
                chars.next();
                continue;
            }
            if c.is_whitespace() && !quoted {
                break;
            }
            if !c.is_control() {
                word.push(c);
            }
            chars.next();
        }
        let word: String = word.chars().take(256).collect();
        if word.is_empty() {
            continue;
        }
        // field:value or field=value, where field is a plain word.
        let split = word
            .char_indices()
            .find(|(_, c)| *c == ':' || *c == '=')
            .filter(|(i, _)| *i > 0 && word[..*i].chars().all(|c| c.is_ascii_alphabetic()));
        let term = match split {
            Some((i, sep)) if !word[i + 1..].is_empty() => Term {
                field: Some(word[..i].to_ascii_lowercase()),
                exact: sep == '=',
                negate,
                value: word[i + 1..].to_owned(),
            },
            _ => Term {
                field: None,
                exact: false,
                negate,
                value: word,
            },
        };
        out.push(term);
    }
    out
}

/// `2026-11-01` (local midnight via `offset_ms`) or `24h`/`7d`/`30m` before `now`.
pub fn date(value: &str, now: i64, offset_ms: i64) -> Option<i64> {
    let v = value.trim();
    if let Some(n) = v.strip_suffix('d').and_then(|n| n.parse::<i64>().ok()) {
        return Some(now - n.clamp(0, 3650) * 86_400_000);
    }
    if let Some(n) = v.strip_suffix('h').and_then(|n| n.parse::<i64>().ok()) {
        return Some(now - n.clamp(0, 87_600) * 3_600_000);
    }
    if let Some(n) = v.strip_suffix('m').and_then(|n| n.parse::<i64>().ok()) {
        return Some(now - n.clamp(0, 5_256_000) * 60_000);
    }
    let mut it = v.splitn(3, '-').map(|p| p.parse::<i64>().ok());
    let (Some(Some(y)), Some(Some(m)), Some(Some(d))) = (it.next(), it.next(), it.next()) else {
        return None;
    };
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some(crate::timefmt::days_from_civil(y, m, d) * 86_400_000 - offset_ms)
}

/// Free-text terms joined, positive and negated.
pub fn free_text(terms: &[Term]) -> (Option<String>, Option<String>) {
    let pick = |neg: bool| {
        let v: Vec<&str> = terms
            .iter()
            .filter(|t| t.field.is_none() && t.negate == neg)
            .map(|t| t.value.as_str())
            .collect();
        (!v.is_empty()).then(|| v.join(" "))
    };
    (pick(false), pick(true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fields_quotes_and_negation() {
        let t = parse(r#"eicar kind=WATCH -path:/tmp "two words" sig:Win.Trojan url:http://x"#);
        assert_eq!(t.len(), 6);
        assert_eq!(
            t[0],
            Term {
                field: None,
                exact: false,
                negate: false,
                value: "eicar".into()
            }
        );
        assert_eq!(t[1].field.as_deref(), Some("kind"));
        assert!(t[1].exact);
        assert!(t[2].negate && t[2].field.as_deref() == Some("path") && t[2].value == "/tmp");
        assert_eq!(t[3].value, "two words");
        assert_eq!(t[4].value, "Win.Trojan");
        assert_eq!(t[5].value, "http://x");
        assert_eq!(free_text(&t), (Some("eicar two words".into()), None));
        assert!(parse("").is_empty());
        assert_eq!(
            parse("/data/a:b")[0].field,
            None,
            "paths with colons stay text"
        );
    }

    #[test]
    fn dates() {
        let now = 1_700_000_000_000;
        assert_eq!(date("24h", now, 0), Some(now - 86_400_000));
        assert_eq!(date("7d", now, 0), Some(now - 7 * 86_400_000));
        assert_eq!(date("2026-11-01", now, 0), Some(1_793_491_200_000));
        assert_eq!(
            date("2026-11-01", now, -6 * 3_600_000),
            Some(1_793_491_200_000 + 6 * 3_600_000)
        );
        assert_eq!(date("2026-13-01", now, 0), None);
        assert_eq!(date("soon", now, 0), None);
    }
}
