//! Login throttling shared by every password check (form, API, LDAP, setup).
//!
//! Three counters, each a fixed window: (account, ip), account alone and ip
//! alone. Any one over its limit blocks the attempt. Maps are bounded, so a
//! flood of distinct usernames cannot grow memory (audit N9).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct LockoutPolicy {
    pub window: Duration,
    pub lock_for: Duration,
    pub per_pair: u32,
    pub per_account: u32,
    pub per_ip: u32,
    pub max_entries: usize,
}

impl Default for LockoutPolicy {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(15 * 60),
            lock_for: Duration::from_secs(15 * 60),
            per_pair: 5,
            per_account: 20,
            per_ip: 30,
            max_entries: 10_000,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    window_start: Instant,
    failures: u32,
    locked_until: Option<Instant>,
}

#[derive(Debug, Default)]
struct Maps {
    pair: HashMap<(String, IpAddr), Entry>,
    account: HashMap<String, Entry>,
    ip: HashMap<IpAddr, Entry>,
}

#[derive(Debug)]
pub struct Lockout {
    policy: LockoutPolicy,
    maps: Mutex<Maps>,
}

/// Which counter tripped, for the log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockScope {
    AccountFromIp,
    Account,
    Ip,
}

impl Lockout {
    pub fn new(policy: LockoutPolicy) -> Self {
        Self {
            policy,
            maps: Mutex::new(Maps::default()),
        }
    }

    /// `Err(retry_after)` while any counter is locked.
    pub fn check(&self, account: &str, ip: IpAddr) -> Result<(), Duration> {
        let now = Instant::now();
        let account = normalise(account);
        let maps = self.lock();
        let until = [
            maps.pair.get(&(account.clone(), ip)),
            maps.account.get(&account),
            maps.ip.get(&ip),
        ]
        .into_iter()
        .flatten()
        .filter_map(|e| e.locked_until)
        .filter(|t| *t > now)
        .max();
        match until {
            Some(t) => Err(t - now),
            None => Ok(()),
        }
    }

    /// Record a failure. Returns the scope that just became locked, if any.
    pub fn fail(&self, account: &str, ip: IpAddr) -> Option<LockScope> {
        let now = Instant::now();
        let account = normalise(account);
        let p = self.policy.clone();
        let mut maps = self.lock();
        let mut tripped = None;
        if bump(&mut maps.pair, (account.clone(), ip), now, p.per_pair, &p) {
            tripped = Some(LockScope::AccountFromIp);
        }
        if bump(&mut maps.account, account, now, p.per_account, &p) {
            tripped = Some(LockScope::Account);
        }
        if bump(&mut maps.ip, ip, now, p.per_ip, &p) {
            tripped = Some(LockScope::Ip);
        }
        tripped
    }

    /// A correct password clears the (account, ip) counter only, so a valid
    /// login from one place cannot reset throttling of an attacker elsewhere.
    pub fn success(&self, account: &str, ip: IpAddr) {
        self.lock().pair.remove(&(normalise(account), ip));
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Maps> {
        self.maps.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn normalise(account: &str) -> String {
    account.trim().to_lowercase().chars().take(128).collect()
}

/// Returns true when this failure locks the key.
fn bump<K: std::hash::Hash + Eq + Clone>(
    map: &mut HashMap<K, Entry>,
    key: K,
    now: Instant,
    limit: u32,
    p: &LockoutPolicy,
) -> bool {
    if !map.contains_key(&key) && map.len() >= p.max_entries {
        evict(map, now, p);
    }
    let e = map.entry(key).or_insert(Entry {
        window_start: now,
        failures: 0,
        locked_until: None,
    });
    if now.duration_since(e.window_start) > p.window && e.locked_until.is_none_or(|t| t <= now) {
        *e = Entry {
            window_start: now,
            failures: 0,
            locked_until: None,
        };
    }
    e.failures = e.failures.saturating_add(1);
    if e.failures >= limit && e.locked_until.is_none_or(|t| t <= now) {
        e.locked_until = Some(now + p.lock_for);
        return true;
    }
    false
}

fn evict<K: std::hash::Hash + Eq + Clone>(
    map: &mut HashMap<K, Entry>,
    now: Instant,
    p: &LockoutPolicy,
) {
    map.retain(|_, e| {
        e.locked_until.is_some_and(|t| t > now) || now.duration_since(e.window_start) <= p.window
    });
    if map.len() >= p.max_entries {
        // Still full of live entries: drop the oldest unlocked one.
        let oldest = map
            .iter()
            .filter(|(_, e)| e.locked_until.is_none_or(|t| t <= now))
            .min_by_key(|(_, e)| e.window_start)
            .map(|(k, _)| k.clone());
        if let Some(k) = oldest {
            map.remove(&k);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, n])
    }

    #[test]
    fn locks_pair_after_limit_and_success_clears_pair() {
        let l = Lockout::new(LockoutPolicy::default());
        for _ in 0..4 {
            assert!(l.fail("Admin", ip(1)).is_none());
        }
        assert_eq!(l.fail("admin ", ip(1)), Some(LockScope::AccountFromIp));
        assert!(l.check("admin", ip(1)).is_err());
        // Other IPs are not blocked by the pair lock.
        assert!(l.check("admin", ip(2)).is_ok());
    }

    #[test]
    fn locks_account_across_ips() {
        let l = Lockout::new(LockoutPolicy {
            per_pair: 100,
            ..Default::default()
        });
        for i in 0..20u8 {
            l.fail("admin", ip(i));
        }
        assert!(l.check("admin", ip(200)).is_err());
        assert!(l.check("other", ip(200)).is_ok());
    }

    #[test]
    fn locks_ip_across_accounts() {
        let l = Lockout::new(LockoutPolicy::default());
        for i in 0..30 {
            l.fail(&format!("user{i}"), ip(9));
        }
        assert!(l.check("fresh", ip(9)).is_err());
    }

    #[test]
    fn memory_is_bounded() {
        let l = Lockout::new(LockoutPolicy {
            max_entries: 100,
            ..Default::default()
        });
        for i in 0..1000 {
            l.fail(&format!("u{i}"), ip(1));
        }
        let m = l.lock();
        assert!(m.account.len() <= 100 && m.pair.len() <= 100);
    }

    #[test]
    fn window_expiry_resets() {
        let l = Lockout::new(LockoutPolicy {
            window: Duration::from_millis(1),
            lock_for: Duration::from_millis(1),
            ..Default::default()
        });
        for _ in 0..5 {
            l.fail("a", ip(1));
        }
        std::thread::sleep(Duration::from_millis(5));
        assert!(l.check("a", ip(1)).is_ok());
    }
}
