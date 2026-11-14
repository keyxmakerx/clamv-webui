//! Fixed-window rate limit per key, with a bounded store.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MAX_KEYS: usize = 10_000;

pub struct RateLimit {
    per_window: u32,
    window: Duration,
    hits: Mutex<HashMap<String, (Instant, u32)>>,
}

impl RateLimit {
    pub fn new(per_window: u32, window: Duration) -> Self {
        Self {
            per_window,
            window,
            hits: Mutex::new(HashMap::new()),
        }
    }

    /// Count one hit for `key`; false when over the limit.
    pub fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut map = self.hits.lock().unwrap_or_else(|p| p.into_inner());
        if map.len() >= MAX_KEYS {
            map.retain(|_, (start, _)| now.duration_since(*start) < self.window);
            if map.len() >= MAX_KEYS {
                // Still full of live keys: refuse new ones rather than grow.
                return map.contains_key(key) && self.bump(&mut map, key, now);
            }
        }
        self.bump(&mut map, key, now)
    }

    fn bump(&self, map: &mut HashMap<String, (Instant, u32)>, key: &str, now: Instant) -> bool {
        let e = map.entry(key.to_owned()).or_insert((now, 0));
        if now.duration_since(e.0) >= self.window {
            *e = (now, 0);
        }
        e.1 += 1;
        e.1 <= self.per_window
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_per_key() {
        let r = RateLimit::new(2, Duration::from_secs(60));
        assert!(r.allow("a") && r.allow("a"));
        assert!(!r.allow("a"));
        assert!(r.allow("b"));
    }
}
