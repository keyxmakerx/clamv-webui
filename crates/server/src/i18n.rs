//! UI translations. Templates wrap text in `nav.t("...")` (signed-in pages) or
//! `crate::i18n::tr("...")` (sign-in and error pages); the English text is the
//! key, so a string without a translation shows in English.
//!
//! To add a language: copy `i18n/en.json` to `i18n/<code>.json`, translate the
//! values, and add one line to `LANGS`.

use std::collections::HashMap;
use std::sync::LazyLock;

/// Cookie holding the chosen language code.
pub const COOKIE: &str = "palisade_lang";

/// (code, name in that language, catalog).
pub const LANGS: &[(&str, &str, &str)] = &[
    ("en", "English", include_str!("../i18n/en.json")),
    ("uk", "Українська", include_str!("../i18n/uk.json")),
    ("ro", "Română", include_str!("../i18n/ro.json")),
    ("fr", "Français", include_str!("../i18n/fr.json")),
    ("es", "Español", include_str!("../i18n/es.json")),
    ("de", "Deutsch", include_str!("../i18n/de.json")),
];

tokio::task_local! {
    /// The language of the request being handled, set by [`layer`].
    static LANG: &'static str;
}

/// The current request's language, or English outside a request.
pub fn current() -> &'static str {
    LANG.try_with(|l| *l).unwrap_or("en")
}

/// `s` in the current request's language.
pub fn tr(s: &str) -> &str {
    t(current(), s)
}

/// Middleware: picks the language from the cookie or the browser for pages
/// that have no signed-in session, such as sign-in and error pages.
pub async fn layer(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let h = req.headers();
    let lang = pick(
        crate::web::session::cookie(h, COOKIE).as_deref(),
        h.get(axum::http::header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok()),
    );
    LANG.scope(lang, next.run(req)).await
}

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
        assert_eq!(pick(Some("UK"), None), "uk");
        assert_eq!(pick(Some("xx"), Some("fr;q=0.5, en-GB;q=0.9")), "en");
        assert_eq!(pick(None, Some("de-AT, fr;q=0.8")), "de");
        assert_eq!(pick(None, Some("zz")), "en");
        assert_eq!(pick(None, None), "en");
    }

    #[test]
    fn untranslated_text_falls_back_to_english() {
        assert_eq!(t("en", "Dashboard"), "Dashboard");
        assert_eq!(t("xx", "No such string"), "No such string");
    }

    /// Every catalog is valid JSON, `en.json` lists every string the templates
    /// translate, and every other catalog has exactly the English keys.
    #[test]
    fn catalogs_cover_the_templates() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/templates");
        let mut used = std::collections::BTreeSet::new();
        for e in std::fs::read_dir(dir).expect("templates") {
            let text = std::fs::read_to_string(e.expect("entry").path()).expect("read");
            for open in ["nav.t(\"", "i18n::tr(\""] {
                for part in text.split(open).skip(1) {
                    used.insert(part.split("\")").next().expect("close").to_owned());
                }
            }
        }
        let keys = |raw: &str| -> std::collections::BTreeSet<String> {
            let m: HashMap<String, String> = serde_json::from_str(raw).expect("valid catalog");
            m.into_keys().collect()
        };
        let en = keys(LANGS[0].2);
        assert_eq!(
            en, used,
            "i18n/en.json must list exactly the template strings"
        );
        for (code, _, raw) in &LANGS[1..] {
            let k = keys(raw);
            let missing: Vec<_> = en.difference(&k).collect();
            let extra: Vec<_> = k.difference(&en).collect();
            assert!(
                missing.is_empty() && extra.is_empty(),
                "{code}: missing {missing:?}, extra {extra:?}"
            );
        }
    }
}
