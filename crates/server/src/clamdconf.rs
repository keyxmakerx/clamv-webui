//! Read-only view of a mounted clamd.conf / freshclam.conf, and clamd's ExcludePath rules.
//!
//! clamd applies ExcludePath itself when it walks a folder. Files the app
//! picks on its own (watched folders, single-file path scans) are checked
//! here too, so excluded files are skipped the same way.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

/// Larger files are not read.
const MAX_BYTES: u64 = 256 * 1024;
const MAX_RULES: usize = 500;

#[derive(Debug)]
pub struct ConfFile {
    pub path: PathBuf,
    pub modified: Option<SystemTime>,
    pub text: String,
    /// `(directive, value)` in file order, comments dropped.
    pub directives: Vec<(String, String)>,
    pub excludes: Vec<regex::Regex>,
    /// ExcludePath values that are not valid regular expressions.
    pub bad_excludes: Vec<String>,
}

impl ConfFile {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.directives
            .iter()
            .rev()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }

    pub fn excluded(&self, path: &str) -> bool {
        self.excludes.iter().any(|r| r.is_match(path))
    }
}

/// Parse clamd.conf syntax: `Directive value`, `#` comments.
pub fn parse(path: &Path, text: String, modified: Option<SystemTime>) -> ConfFile {
    let mut directives = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let (k, v) = l.split_once(char::is_whitespace).unwrap_or((l, ""));
        let v = v.trim().trim_matches('"');
        directives.push((k.to_owned(), v.to_owned()));
    }
    let mut excludes = Vec::new();
    let mut bad_excludes = Vec::new();
    for (_, v) in directives
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("ExcludePath"))
        .take(MAX_RULES)
    {
        match regex::RegexBuilder::new(v).size_limit(1 << 20).build() {
            Ok(r) => excludes.push(r),
            Err(_) => bad_excludes.push(v.clone()),
        }
    }
    ConfFile {
        path: path.to_path_buf(),
        modified,
        text,
        directives,
        excludes,
        bad_excludes,
    }
}

/// A clamd size value (`25M`, `100k`, `4000000`) in bytes.
pub fn size_bytes(v: &str) -> Option<u64> {
    let v = v.trim();
    let (num, mul) = match v.chars().last()? {
        'k' | 'K' => (&v[..v.len() - 1], 1024),
        'm' | 'M' => (&v[..v.len() - 1], 1024 * 1024),
        'g' | 'G' => (&v[..v.len() - 1], 1024 * 1024 * 1024),
        _ => (v, 1),
    };
    num.trim().parse::<u64>().ok()?.checked_mul(mul)
}

/// Re-reads a file only when its modification time changes.
#[derive(Default)]
pub struct Cache {
    slot: Mutex<Option<Arc<ConfFile>>>,
}

impl Cache {
    pub fn load(&self, path: Option<&Path>) -> Result<Option<Arc<ConfFile>>, String> {
        let Some(path) = path else {
            return Ok(None);
        };
        let meta =
            std::fs::metadata(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        if !meta.is_file() || meta.len() > MAX_BYTES {
            return Err(format!(
                "{} is not a regular file under 256 KiB",
                path.display()
            ));
        }
        let modified = meta.modified().ok();
        if let Ok(g) = self.slot.lock()
            && let Some(c) = g.as_ref()
            && c.path == path
            && c.modified == modified
            && modified.is_some()
        {
            return Ok(Some(c.clone()));
        }
        let bytes =
            std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let conf = Arc::new(parse(
            path,
            String::from_utf8_lossy(&bytes).into_owned(),
            modified,
        ));
        if !conf.bad_excludes.is_empty() {
            tracing::warn!(event = "clamd_conf.bad_exclude", file = %path.display(), rules = ?conf.bad_excludes, "ExcludePath rules that are not valid regular expressions are ignored");
        }
        if let Ok(mut g) = self.slot.lock() {
            *g = Some(conf.clone());
        }
        Ok(Some(conf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_directives_and_excludes() {
        let c = parse(
            Path::new("/etc/clamav/clamd.conf"),
            "# comment\nTCPSocket 3310\nStreamMaxLength 100M\nExcludePath ^/data/cache/\nExcludePath \\.tmp$\nExcludePath ([\nMaxFileSize 25M\nstreammaxlength 200M\n".into(),
            None,
        );
        assert_eq!(
            c.get("StreamMaxLength"),
            Some("200M"),
            "last wins, any case"
        );
        assert_eq!(c.get("TCPSocket"), Some("3310"));
        assert!(c.excluded("/data/cache/x.bin"));
        assert!(c.excluded("/data/a.tmp"));
        assert!(!c.excluded("/data/a.txt"));
        assert_eq!(c.bad_excludes, vec!["([".to_owned()]);
        assert_eq!(size_bytes("100M"), Some(100 * 1024 * 1024));
        assert_eq!(size_bytes("4k"), Some(4096));
        assert_eq!(size_bytes("123"), Some(123));
        assert_eq!(size_bytes("x"), None);
    }
}
