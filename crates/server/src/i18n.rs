//! UI translations. Templates wrap text in `nav.t("...")`; the English text is
//! the key, so a string without a translation shows in English.
//!
//! To add a language: copy `i18n/en.json` to `i18n/<code>.json`, translate the
//! values, and add one line to `LANGS`.

use std::collections::HashMap;
use std::sync::LazyLock;

/// Cookie holding the chosen language code.
pub const COOKIE: &str = "clamv_lang";

/// (code, name in that language, catalog).
pub const LANGS: &[(&str, &str, &str)] = &[("en", "English", include_str!("../i18n/en.json"))];

static CATALOGS: LazyLock<HashMap<&'static str, HashMap<String, String>>> = LazyLock::new(|| {
    LANGS
        .iter()
        .map(|(code, _, raw)| {
            let m: HashMap<String, String> = serde_json::from_str(raw).unwrap_or_else(|e| {
                tracing::error!(event = "i18n.catalog_invalid", lang = code, error = %e, "translation file is not valid JSON");
                HashMap::new()
            });
            (*code, m)
        })
        .collect()
});

/// The known code for `code`, if any.
pub fn known(code: &str) -> Option<&'static str> {
    LANGS
        .iter()
        .map(|(c, _, _)| *c)
        .find(|c| c.eq_ignore_ascii_case(code))
}

/// The language for a request: the cookie if it names a known language, else
/// the first known language in Accept-Language, else English.
pub fn pick(cookie: Option<&str>, accept: Option<&str>) -> &'static str {
    if let Some(c) = cookie.and_then(known) {
        return c;
    }
    let mut prefs: Vec<(f32, &str)> = accept
        .unwrap_or("")
        .split(',')
        .filter_map(|part| {
            let mut it = part.trim().split(';');
            let tag = it.next()?.trim();
            let q = it
                .find_map(|p| p.trim().strip_prefix("q="))
                .and_then(|q| q.parse::<f32>().ok())
                .unwrap_or(1.0);
            (!tag.is_empty() && q > 0.0).then_some((q, tag))
        })
        .collect();
    prefs.sort_by(|a, b| b.0.total_cmp(&a.0));
    prefs
        .iter()
        .find_map(|(_, tag)| known(tag).or_else(|| known(tag.split('-').next().unwrap_or(""))))
        .unwrap_or("en")
}

/// `s` in `lang`, or `s` itself when there is no translation.
pub fn t<'a>(lang: &str, s: &'a str) -> &'a str {
    CATALOGS
        .get(lang)
        .and_then(|m| m.get(s))
        .map(String::as_str)
        .filter(|v| !v.is_empty())
        .unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_then_browser_then_english() {
        assert_eq!(pick(Some("en"), Some("de")), "en");
        assert_eq!(pick(Some("xx"), Some("fr;q=0.5, en-GB;q=0.9")), "en");
        assert_eq!(pick(None, Some("zz")), "en");
        assert_eq!(pick(None, None), "en");
    }

    #[test]
    fn untranslated_text_falls_back_to_english() {
        assert_eq!(t("en", "Dashboard"), "Dashboard");
        assert_eq!(t("xx", "No such string"), "No such string");
    }

    /// Every catalog is valid JSON and every `nav.t("...")` string in the
    /// templates is listed in `en.json`, so translators see the full set.
    #[test]
    fn catalogs_cover_the_templates() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/templates");
        let mut used = std::collections::BTreeSet::new();
        for e in std::fs::read_dir(dir).expect("templates") {
            let text = std::fs::read_to_string(e.expect("entry").path()).expect("read");
            for part in text.split("nav.t(\"").skip(1) {
                used.insert(part.split("\")").next().expect("close").to_owned());
            }
        }
        for (code, _, raw) in LANGS {
            let m: HashMap<String, String> = serde_json::from_str(raw).expect("valid catalog");
            if *code == "en" {
                let listed: std::collections::BTreeSet<String> = m.keys().cloned().collect();
                assert_eq!(
                    listed, used,
                    "i18n/en.json must list exactly the template strings"
                );
            }
            assert!(m.keys().all(|k| used.contains(k)), "{code}: unused keys");
        }
    }
}
