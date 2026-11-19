//! Login throttling shared by every password check (form, API, LDAP, setup).
//!
//! Three counters, each a fixed window: (account, ip), account alone and ip
//! alone. Any one over its limit blocks the attempt. Maps are bounded, so a
//! flood of distinct usernames cannot grow memory (audit N9). IPv6 clients
//! are counted per /64, since one host usually holds the whole prefix.
//!
//! Counters live in memory only: restarting the server clears every lock.

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

/// One counted failure taken before a check; which counters it locked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct Reservation {
    pair: bool,
    account: bool,
    ip: bool,
}

impl Reservation {
    /// The widest counter this failure locked, for the log line.
    pub fn scope(self) -> Option<LockScope> {
        if self.ip {
            Some(LockScope::Ip)
        } else if self.account {
            Some(LockScope::Account)
        } else if self.pair {
            Some(LockScope::AccountFromIp)
        } else {
            None
        }
    }
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
        let maps = self.lock();
        Self::check_in(&maps, &normalise(account), ip_key(ip))
    }

    fn check_in(maps: &Maps, account: &str, ip: IpAddr) -> Result<(), Duration> {
        let now = Instant::now();
        let account = account.to_owned();
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
        let mut maps = self.lock();
        self.fail_in(&mut maps, normalise(account), ip_key(ip))
    }

    /// Check and count a failure in one step, before the expensive check runs,
    /// so a burst of parallel attempts cannot all get past the limit. A correct
    /// answer hands the failure back with `release`.
    pub fn reserve(&self, account: &str, ip: IpAddr) -> Result<Reservation, Duration> {
        let account = normalise(account);
        let ip = ip_key(ip);
        let mut maps = self.lock();
        Self::check_in(&maps, &account, ip)?;
        Ok(self.bump_all(&mut maps, account, ip))
    }

    /// Undo one `reserve` after a correct answer: clears the (account, ip)
    /// counter and takes the reserved failure off the other two. A lock this
    /// reservation set is lifted; locks from earlier failures stay.
    pub fn release(&self, account: &str, ip: IpAddr, r: Reservation) {
        self.refund(account, ip, r);
        self.lock().pair.remove(&(normalise(account), ip_key(ip)));
    }

    /// Undo one `reserve` when no check ran (server busy or unavailable).
    pub fn refund(&self, account: &str, ip: IpAddr, r: Reservation) {
        let account = normalise(account);
        let ip = ip_key(ip);
        let mut maps = self.lock();
        if let Some(e) = maps.pair.get_mut(&(account.clone(), ip)) {
            unbump(e, r.pair);
        }
        if let Some(e) = maps.account.get_mut(&account) {
            unbump(e, r.account);
        }
        if let Some(e) = maps.ip.get_mut(&ip) {
            unbump(e, r.ip);
        }
    }

    /// Address-only throttle, for sign-ins that name no account (passkeys).
    pub fn check_ip(&self, ip: IpAddr) -> Result<(), Duration> {
        let now = Instant::now();
        let maps = self.lock();
        match maps.ip.get(&ip_key(ip)).and_then(|e| e.locked_until) {
            Some(t) if t > now => Err(t - now),
            _ => Ok(()),
        }
    }

    /// Count a failure against the address only.
    pub fn fail_ip(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let p = self.policy.clone();
        let mut maps = self.lock();
        bump(&mut maps.ip, ip_key(ip), now, p.per_ip, &p)
    }

    fn fail_in(&self, maps: &mut Maps, account: String, ip: IpAddr) -> Option<LockScope> {
        self.bump_all(maps, account, ip).scope()
    }

    fn bump_all(&self, maps: &mut Maps, account: String, ip: IpAddr) -> Reservation {
        let now = Instant::now();
        let p = self.policy.clone();
        Reservation {
            pair: bump(&mut maps.pair, (account.clone(), ip), now, p.per_pair, &p),
            account: bump(&mut maps.account, account, now, p.per_account, &p),
            ip: bump(&mut maps.ip, ip, now, p.per_ip, &p),
        }
    }

    /// A correct password clears the (account, ip) counter only, so a valid
    /// login from one place cannot reset throttling of an attacker elsewhere.
    pub fn success(&self, account: &str, ip: IpAddr) {
        self.lock().pair.remove(&(normalise(account), ip_key(ip)));
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Maps> {
        self.maps.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The address a counter is kept under: IPv4 as is (also when mapped into
/// IPv6), IPv6 cut to its /64.
pub fn ip_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::from([s[0], s[1], s[2], s[3], 0, 0, 0, 0])
            }
        },
    }
}

/// Take back one reserved failure, and the lock if that reservation set it.
fn unbump(e: &mut Entry, set_lock: bool) {
    e.failures = e.failures.saturating_sub(1);
    if set_lock {
        e.locked_until = None;
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
    fn reserve_counts_before_the_check_and_release_hands_it_back() {
        let l = Lockout::new(LockoutPolicy::default());
        // A burst: only the first five get a reservation, the rest are refused at once.
        let ok = (0..200)
            .filter(|_| l.reserve("admin", ip(1)).is_ok())
            .count();
        assert_eq!(ok, 5);
        assert!(l.check("admin", ip(1)).is_err());
        // A correct password from elsewhere takes its own reservation back.
        let r = l.reserve("bob", ip(2)).expect("not locked");
        l.release("bob", ip(2), r);
        let m = l.lock();
        assert_eq!(m.account.get("bob").map(|e| e.failures), Some(0));
    }

    #[test]
    fn release_lifts_only_the_lock_it_set() {
        let l = Lockout::new(LockoutPolicy {
            per_pair: 100,
            ..Default::default()
        });
        for i in 0..19u8 {
            l.fail("admin", ip(i));
        }
        // The 20th attempt locks the account; it was the owner, and correct.
        let r = l.reserve("admin", ip(100)).expect("not locked");
        assert!(l.check("admin", ip(101)).is_err());
        l.release("admin", ip(100), r);
        assert!(l.check("admin", ip(101)).is_ok());
        // The next failure locks it again.
        l.fail("admin", ip(5));
        assert!(l.check("admin", ip(101)).is_err());
    }

    #[test]
    fn ipv6_counts_per_64() {
        let l = Lockout::new(LockoutPolicy::default());
        for i in 0..30u16 {
            let a: IpAddr = std::net::Ipv6Addr::new(0x2001, 0xdb8, 1, 2, i, i, i, i).into();
            l.fail(&format!("user{i}"), a);
        }
        let other: IpAddr = std::net::Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 9, 9, 9, 99).into();
        assert!(l.check("fresh", other).is_err());
        let next: IpAddr = std::net::Ipv6Addr::new(0x2001, 0xdb8, 1, 3, 0, 0, 0, 1).into();
        assert!(l.check("fresh", next).is_ok());
        let mapped: IpAddr = "::ffff:10.0.0.7".parse().expect("ip");
        assert_eq!(ip_key(mapped), ip(7));
    }

    #[test]
    fn passkey_failures_lock_one_address_only() {
        let l = Lockout::new(LockoutPolicy::default());
        for _ in 0..30 {
            l.fail_ip(ip(1));
        }
        assert!(l.check_ip(ip(1)).is_err());
        assert!(l.check_ip(ip(2)).is_ok());
        assert!(l.check("admin", ip(2)).is_ok());
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
