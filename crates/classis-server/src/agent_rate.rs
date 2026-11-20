//! How often an admitted peer may be heard on the Agent plane (ADR-0013).
//!
//! Every message on `/v1/opamp` takes one token from a bucket. A bucket holds `burst` tokens and
//! gains `messages_per_sec` of them a second, and a new one starts full. The bucket is the host a
//! message is counted for, or the peer address where no host is named. The table is bounded, and a
//! full one forgets the bucket used least recently, which can only grant tokens.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use crate::fleet::Clock;

/// How many buckets a Server keeps.
const MAX_SUBJECTS: usize = 100_000;

/// The `[agent_rate_limit]` values (ADR-0013 clause 19).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub messages_per_sec: u32,
    pub burst: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            messages_per_sec: 10,
            burst: 300,
        }
    }
}

/// Who a message is counted for (ADR-0013 clause 22).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Subject {
    /// The host a message arrived over.
    Host(String),
    /// A connection that names no host, by its peer address — an IPv6 one by its /64.
    Peer(IpAddr),
}

impl Subject {
    /// The subject of a connection that names no host: its peer address, an unknown one counted
    /// as one address. Every listener supplies the address the socket reports, so `None` — and
    /// with it one bucket shared by every such connection — occurs where a test drives the router
    /// without a listener, or where the socket cannot report its peer.
    #[must_use]
    pub fn peer(peer: Option<IpAddr>) -> Self {
        Subject::Peer(crate::throttle::peer_key(
            peer.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
        ))
    }
}

/// A bucket's tokens, in thousandths so that a refill of a few milliseconds is not lost.
#[derive(Clone, Copy)]
struct Level {
    milli: u64,
    at_ms: u64,
    used: u64,
}

const TOKEN: u64 = 1000;

/// One bounded table of buckets, forgetting the one used least recently when full.
struct Table {
    capacity: usize,
    buckets: HashMap<Subject, Level>,
    /// The order of use: the tick each bucket was last used at.
    order: BTreeMap<u64, Subject>,
    tick: u64,
}

impl Table {
    fn new(capacity: usize) -> Self {
        Table {
            capacity: capacity.max(1),
            buckets: HashMap::new(),
            order: BTreeMap::new(),
            tick: 0,
        }
    }

    /// The tokens in `key`'s bucket now, in thousandths; a new bucket starts full.
    fn level(&mut self, key: &Subject, rate: u32, burst: u32, now: u64) -> u64 {
        self.tick += 1;
        let full = u64::from(burst) * TOKEN;
        if !self.buckets.contains_key(key) && self.buckets.len() >= self.capacity {
            if let Some((_, oldest)) = self.order.pop_first() {
                self.buckets.remove(&oldest);
            }
        }
        let level = self.buckets.entry(key.clone()).or_insert(Level {
            milli: full,
            at_ms: now,
            used: self.tick,
        });
        // Thousandths a millisecond is tokens a second.
        let gained = now
            .saturating_sub(level.at_ms)
            .saturating_mul(u64::from(rate));
        level.milli = level.milli.saturating_add(gained).min(full);
        level.at_ms = level.at_ms.max(now);
        self.order.remove(&level.used);
        level.used = self.tick;
        self.order.insert(self.tick, key.clone());
        level.milli
    }

    fn spend(&mut self, key: &Subject) {
        if let Some(level) = self.buckets.get_mut(key) {
            level.milli = level.milli.saturating_sub(TOKEN);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.buckets.len()
    }
}

/// The limit itself: the table of buckets and what it is sized by.
pub struct AgentRate {
    limits: Limits,
    clock: Arc<dyn Clock>,
    table: Mutex<Table>,
}

impl AgentRate {
    /// The limit as a Server keeps it (ADR-0013 clause 26).
    #[must_use]
    pub fn new(limits: Limits, clock: Arc<dyn Clock>) -> Self {
        AgentRate::with_capacity(limits, MAX_SUBJECTS, clock)
    }

    #[must_use]
    pub fn with_capacity(limits: Limits, subjects: usize, clock: Arc<dyn Clock>) -> Self {
        AgentRate {
            limits,
            clock,
            table: Mutex::new(Table::new(subjects)),
        }
    }

    /// Takes one token for a message of `subject`; `false` when its bucket had none, and nothing
    /// is taken then.
    pub fn admit(&self, subject: &Subject) -> bool {
        let now = self.clock.now_ms();
        let limits = self.limits;
        let mut table = self.table.lock().expect("agent rate lock");
        if table.level(subject, limits.messages_per_sec, limits.burst, now) < TOKEN {
            return false;
        }
        table.spend(subject);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Manual(AtomicU64);

    impl Clock for Manual {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    const LIMITS: Limits = Limits {
        messages_per_sec: 2,
        burst: 3,
    };

    fn rate(subjects: usize) -> (AgentRate, Arc<Manual>) {
        let clock = Arc::new(Manual(AtomicU64::new(1_000_000)));
        (
            AgentRate::with_capacity(LIMITS, subjects, clock.clone()),
            clock,
        )
    }

    fn host(name: &str) -> Subject {
        Subject::Host(name.to_string())
    }

    /// How many messages pass in a row.
    fn passing(rate: &AgentRate, subject: &Subject) -> usize {
        (0..100).take_while(|_| rate.admit(subject)).count()
    }

    /// Verifies: ADR-0013
    #[test]
    fn a_bucket_starts_full_and_refills_at_the_configured_rate() {
        let (rate, clock) = rate(16);
        let edge = host("edge");
        assert_eq!(passing(&rate, &edge), 3, "a new bucket holds the burst");
        assert!(!rate.admit(&edge));
        clock.0.fetch_add(499, Ordering::SeqCst);
        assert!(!rate.admit(&edge), "not yet a whole token");
        clock.0.fetch_add(1, Ordering::SeqCst);
        assert!(rate.admit(&edge), "two a second is one per 500 ms");
        clock.0.fetch_add(60_000, Ordering::SeqCst);
        assert_eq!(passing(&rate, &edge), 3, "never more than the burst");
    }

    /// Verifies: ADR-0013
    #[test]
    fn a_host_is_one_bucket_and_another_host_another() {
        let (rate, _) = rate(16);
        let edge = host("edge");
        assert_eq!(passing(&rate, &edge), 3);
        assert!(!rate.admit(&edge));
        assert!(rate.admit(&host("other")), "another host");
    }

    /// Verifies: ADR-0013
    #[test]
    fn a_connection_naming_no_host_is_counted_by_its_peer_address() {
        let (rate, _) = rate(16);
        let a = Subject::peer(Some("2001:db8::1".parse().expect("ip")));
        let same_block = Subject::peer(Some("2001:db8::ffff:2".parse().expect("ip")));
        let b = Subject::peer(Some("192.0.2.7".parse().expect("ip")));
        assert_eq!(passing(&rate, &a), 3);
        assert!(!rate.admit(&same_block), "one /64");
        assert_eq!(passing(&rate, &b), 3, "another address");
    }

    /// Verifies: ADR-0013
    #[test]
    fn a_full_table_evicts_the_bucket_used_least_recently() {
        let (rate, _) = rate(2);
        let (a, b, c) = (host("a"), host("b"), host("c"));
        assert_eq!(passing(&rate, &a), 3);
        assert!(rate.admit(&b));
        // `a` is used again, so `b` is the one used least recently when `c` arrives.
        assert!(!rate.admit(&a));
        assert!(rate.admit(&c));
        assert!(!rate.admit(&a), "the bucket used most recently was kept");
        assert_eq!(passing(&rate, &b), 3, "b was forgotten: a new bucket");
    }

    /// Verifies: ADR-0013
    #[test]
    fn the_table_is_bounded() {
        let (rate, clock) = rate(4);
        for n in 0..50u8 {
            clock.0.fetch_add(1000, Ordering::SeqCst);
            assert!(rate.admit(&host(&format!("h{n}"))));
        }
        assert_eq!(rate.table.lock().expect("lock").len(), 4);
    }
}
