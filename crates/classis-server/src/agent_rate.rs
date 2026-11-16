//! How often an admitted peer may be heard on the Agent plane (ADR-0013).
//!
//! Every message on `/v1/opamp` and every package download a member sends takes one token from a
//! bucket. A bucket holds `burst` tokens and gains `messages_per_sec` of them a second, and a new
//! one starts full. The bucket is the host the certificate names, the certificate itself where it
//! names none, or the peer address of an enrolling host. A host marked as a Gateway carries other
//! hosts' Agents, so a message through it takes a token from the bucket of the Agent it names and
//! one from the Gateway's aggregate. An enrolment request through it takes from neither but from
//! the Gateway's enrolment aggregate and, once its bootstrap certificate is one of a bootstrap CA,
//! from that certificate's bucket (ADR-0039 clause 13). Both tables are bounded, and a full one
//! forgets the bucket used least recently, which can only grant tokens.

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use crate::fleet::Clock;
use crate::revocation::CertId;

/// The `[agent_rate_limit]` values (ADR-0013 clause 19).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub messages_per_sec: u32,
    pub burst: u32,
    pub gateway_messages_per_sec: u32,
    pub gateway_burst: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            messages_per_sec: 10,
            burst: 300,
            gateway_messages_per_sec: 500,
            gateway_burst: 10_000,
        }
    }
}

/// Who a message or a download is counted for (ADR-0013 clause 22).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Subject {
    /// The host a member's certificate names.
    Host(String),
    /// A member's certificate that names no host, by its issuer and serial.
    Certificate(CertId),
    /// An enrolling host, or a connection without a certificate, by its peer address — an IPv6
    /// one by its /64.
    Peer(IpAddr),
}

impl Subject {
    /// The subject of an enrolling host or a connection without a certificate: its peer address,
    /// an unknown one counted as one address. Every listener supplies the address the socket
    /// reports, so `None` — and with it one bucket shared by every such connection — occurs where
    /// a test drives the router without a listener, or where the socket cannot report its peer.
    #[must_use]
    pub fn peer(peer: Option<IpAddr>) -> Self {
        Subject::Peer(crate::throttle::peer_key(
            peer.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
        ))
    }
}

/// The bucket that was empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bucket {
    /// The bucket of one Agent behind a Gateway.
    Agent,
    /// The bucket of a host, a certificate or an enrolling peer.
    Host,
    /// A Gateway's aggregate.
    Gateway,
    /// A Gateway's enrolment aggregate, which checked enrolment requests share.
    Enrolment,
    /// The bucket of one bootstrap certificate an enrolment request through a Gateway proves.
    Bootstrap,
    /// A Gateway's bucket for enrolment requests whose bootstrap certificate failed the check.
    UncheckedEnrolment,
}

impl Bucket {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Bucket::Agent => "agent",
            Bucket::Host => "host",
            Bucket::Gateway => "gateway",
            Bucket::Enrolment => "enrolment",
            Bucket::Bootstrap => "bootstrap",
            Bucket::UncheckedEnrolment => "unchecked_enrolment",
        }
    }
}

/// The keys of the first table: a subject's own bucket, a Gateway's aggregate, and its enrolment
/// aggregate.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Key {
    Own(Subject),
    Gateway(String),
    Enrolments(String),
    UncheckedEnrolments(String),
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
struct Table<K> {
    capacity: usize,
    buckets: HashMap<K, Level>,
    /// The order of use: the tick each bucket was last used at.
    order: BTreeMap<u64, K>,
}

impl<K: Clone + Eq + Hash> Table<K> {
    fn new(capacity: usize) -> Self {
        Table {
            capacity: capacity.max(1),
            buckets: HashMap::new(),
            order: BTreeMap::new(),
        }
    }

    /// The tokens in `key`'s bucket now, in thousandths; a new bucket starts full.
    fn level(&mut self, key: &K, rate: u32, burst: u32, now: u64, tick: u64) -> u64 {
        let full = u64::from(burst) * TOKEN;
        if !self.buckets.contains_key(key) && self.buckets.len() >= self.capacity {
            if let Some((_, oldest)) = self.order.pop_first() {
                self.buckets.remove(&oldest);
            }
        }
        let level = self.buckets.entry(key.clone()).or_insert(Level {
            milli: full,
            at_ms: now,
            used: tick,
        });
        // Thousandths a millisecond is tokens a second.
        let gained = now
            .saturating_sub(level.at_ms)
            .saturating_mul(u64::from(rate));
        level.milli = level.milli.saturating_add(gained).min(full);
        level.at_ms = level.at_ms.max(now);
        self.order.remove(&level.used);
        level.used = tick;
        self.order.insert(tick, key.clone());
        level.milli
    }

    fn spend(&mut self, key: &K) {
        if let Some(level) = self.buckets.get_mut(key) {
            level.milli = level.milli.saturating_sub(TOKEN);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.buckets.len()
    }
}

/// What a message through a Gateway is counted for besides an aggregate: the Agent it names, or —
/// for an enrolment request — the bootstrap certificate the request proves (ADR-0039 clause 13).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Named {
    Agent([u8; 16]),
    Enrolment(CertId),
}

struct Tables {
    tick: u64,
    own: Table<Key>,
    agents: Table<(String, Named)>,
}

/// The limit itself: the two tables and what they are sized by.
pub struct AgentRate {
    limits: Limits,
    clock: Arc<dyn Clock>,
    tables: Mutex<Tables>,
}

impl AgentRate {
    /// The limit as a Server keeps it: the subjects and aggregates as many as the certificate
    /// register holds, the Agents behind Gateways as many as the fleet holds (ADR-0013 clause 26).
    #[must_use]
    pub fn new(limits: Limits, max_agents: usize, clock: Arc<dyn Clock>) -> Self {
        AgentRate::with_capacities(limits, crate::revocation::MAX_ISSUED, max_agents, clock)
    }

    #[must_use]
    pub fn with_capacities(
        limits: Limits,
        subjects: usize,
        agents: usize,
        clock: Arc<dyn Clock>,
    ) -> Self {
        AgentRate {
            limits,
            clock,
            tables: Mutex::new(Tables {
                tick: 0,
                own: Table::new(subjects),
                agents: Table::new(agents),
            }),
        }
    }

    /// Takes one token for a message or a download of `subject`, or names the bucket that had
    /// none. `gateway` says that the subject is a host marked as a Gateway, and `agent` the
    /// `instance_uid` the message names; one that is not 16 bytes names no Agent.
    ///
    /// # Errors
    /// Answers the empty [`Bucket`]; nothing is taken then.
    pub fn admit(
        &self,
        subject: &Subject,
        gateway: bool,
        agent: Option<&[u8]>,
    ) -> Result<(), Bucket> {
        let named = agent
            .and_then(|uid| <[u8; 16]>::try_from(uid).ok())
            .map(Named::Agent);
        self.take(subject, gateway, named)
    }

    /// [`admit`](Self::admit) for a message carrying an enrolment request. Through a Gateway it
    /// takes no token of the Gateway's members (ADR-0039 clause 13). With `bootstrap` — the
    /// certificate its proof embeds, once checked to be one of a bootstrap CA — it takes one from
    /// that certificate's bucket, sized by `messages_per_sec` and `burst`, and one from the
    /// Gateway's enrolment aggregate, sized by `gateway_messages_per_sec` and `gateway_burst`, so
    /// one certificate empties its own bucket long before the aggregate. Without, it takes one from
    /// the Gateway's bucket for unchecked enrolments alone, sized by `messages_per_sec` and `burst`,
    /// so forged proofs spend neither the members' tokens nor the checked enrolments'. On a host
    /// that is no Gateway it is the host's message.
    ///
    /// # Errors
    /// Answers the empty [`Bucket`]; nothing is taken then.
    pub fn admit_enrolment(
        &self,
        subject: &Subject,
        gateway: bool,
        bootstrap: Option<&CertId>,
    ) -> Result<(), Bucket> {
        let (Subject::Host(host), true) = (subject, gateway) else {
            return self.take(subject, false, None);
        };
        let now = self.clock.now_ms();
        let limits = self.limits;
        let mut tables = self.tables.lock().expect("agent rate lock");
        let Tables { tick, own, agents } = &mut *tables;
        *tick += 1;
        let Some(bootstrap) = bootstrap else {
            let unchecked = Key::UncheckedEnrolments(host.clone());
            if own.level(
                &unchecked,
                limits.messages_per_sec,
                limits.burst,
                now,
                *tick,
            ) < TOKEN
            {
                return Err(Bucket::UncheckedEnrolment);
            }
            own.spend(&unchecked);
            return Ok(());
        };
        let aggregate = Key::Enrolments(host.clone());
        // The aggregate is checked first, so a full one fills no table with certificates.
        if own.level(
            &aggregate,
            limits.gateway_messages_per_sec,
            limits.gateway_burst,
            now,
            *tick,
        ) < TOKEN
        {
            return Err(Bucket::Enrolment);
        }
        let key = (host.clone(), Named::Enrolment(bootstrap.clone()));
        *tick += 1;
        if agents.level(&key, limits.messages_per_sec, limits.burst, now, *tick) < TOKEN {
            return Err(Bucket::Bootstrap);
        }
        agents.spend(&key);
        own.spend(&aggregate);
        Ok(())
    }

    fn take(&self, subject: &Subject, gateway: bool, named: Option<Named>) -> Result<(), Bucket> {
        let now = self.clock.now_ms();
        let limits = self.limits;
        let mut tables = self.tables.lock().expect("agent rate lock");
        let Tables { tick, own, agents } = &mut *tables;
        *tick += 1;
        let host = match (subject, gateway) {
            (Subject::Host(host), true) => host,
            _ => {
                let key = Key::Own(subject.clone());
                if own.level(&key, limits.messages_per_sec, limits.burst, now, *tick) < TOKEN {
                    return Err(Bucket::Host);
                }
                own.spend(&key);
                return Ok(());
            }
        };
        let aggregate = Key::Gateway(host.clone());
        let level = own.level(
            &aggregate,
            limits.gateway_messages_per_sec,
            limits.gateway_burst,
            now,
            *tick,
        );
        // Checked first, so a peer cycling uids against an empty aggregate fills no table.
        if level < TOKEN {
            return Err(Bucket::Gateway);
        }
        if let Some(named) = named {
            let key = (host.clone(), named);
            *tick += 1;
            if agents.level(&key, limits.messages_per_sec, limits.burst, now, *tick) < TOKEN {
                return Err(Bucket::Agent);
            }
            agents.spend(&key);
        }
        own.spend(&aggregate);
        Ok(())
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
        gateway_messages_per_sec: 4,
        gateway_burst: 5,
    };

    fn rate(subjects: usize, agents: usize) -> (AgentRate, Arc<Manual>) {
        let clock = Arc::new(Manual(AtomicU64::new(1_000_000)));
        (
            AgentRate::with_capacities(LIMITS, subjects, agents, clock.clone()),
            clock,
        )
    }

    fn host(name: &str) -> Subject {
        Subject::Host(name.to_string())
    }

    fn uid(n: u8) -> [u8; 16] {
        [n; 16]
    }

    /// How many messages pass in a row.
    fn passing(rate: &AgentRate, subject: &Subject, gateway: bool, agent: Option<&[u8]>) -> usize {
        (0..100)
            .take_while(|_| rate.admit(subject, gateway, agent).is_ok())
            .count()
    }

    /// Verifies: ADR-0013
    #[test]
    fn a_bucket_starts_full_and_refills_at_the_configured_rate() {
        let (rate, clock) = rate(16, 16);
        let edge = host("edge");
        assert_eq!(
            passing(&rate, &edge, false, None),
            3,
            "a new bucket holds the burst"
        );
        assert_eq!(rate.admit(&edge, false, None), Err(Bucket::Host));
        clock.0.fetch_add(499, Ordering::SeqCst);
        assert!(
            rate.admit(&edge, false, None).is_err(),
            "not yet a whole token"
        );
        clock.0.fetch_add(1, Ordering::SeqCst);
        assert!(
            rate.admit(&edge, false, None).is_ok(),
            "two a second is one per 500 ms"
        );
        clock.0.fetch_add(60_000, Ordering::SeqCst);
        assert_eq!(
            passing(&rate, &edge, false, None),
            3,
            "never more than the burst"
        );
    }

    /// Verifies: ADR-0013
    #[test]
    fn a_host_is_one_bucket_whatever_its_agents_report() {
        let (rate, _) = rate(16, 16);
        let edge = host("edge");
        for n in 0..3 {
            assert!(rate.admit(&edge, false, Some(&uid(n))).is_ok());
        }
        assert_eq!(rate.admit(&edge, false, Some(&uid(9))), Err(Bucket::Host));
        assert!(
            rate.admit(&host("other"), false, None).is_ok(),
            "another host"
        );
    }

    /// Verifies: ADR-0013
    #[test]
    fn a_member_certificate_without_a_host_is_counted_by_issuer_and_serial() {
        let (rate, _) = rate(16, 16);
        let one = Subject::Certificate(CertId {
            issuer: "ca".into(),
            serial: "01".into(),
        });
        let two = Subject::Certificate(CertId {
            issuer: "ca".into(),
            serial: "02".into(),
        });
        assert_eq!(passing(&rate, &one, false, None), 3);
        assert_eq!(passing(&rate, &two, false, None), 3, "another serial");
    }

    /// Verifies: ADR-0013
    #[test]
    fn an_enrolment_connection_is_counted_by_its_peer_address() {
        let (rate, _) = rate(16, 16);
        let a = Subject::peer(Some("2001:db8::1".parse().expect("ip")));
        let same_block = Subject::peer(Some("2001:db8::ffff:2".parse().expect("ip")));
        let b = Subject::peer(Some("192.0.2.7".parse().expect("ip")));
        assert_eq!(passing(&rate, &a, false, None), 3);
        assert!(rate.admit(&same_block, false, None).is_err(), "one /64");
        assert_eq!(passing(&rate, &b, false, None), 3, "another address");
    }

    /// Verifies: ADR-0013
    #[test]
    fn marking_a_gateway_takes_effect_at_the_next_message() {
        let (rate, _) = rate(16, 16);
        let edge = host("edge");
        assert_eq!(passing(&rate, &edge, false, Some(&uid(1))), 3);
        // Marked: the next message is counted per Agent within the aggregate.
        assert!(rate.admit(&edge, true, Some(&uid(1))).is_ok());
        assert!(rate.admit(&edge, true, Some(&uid(2))).is_ok());
        // Unmarked again: the host's own bucket, still empty.
        assert_eq!(rate.admit(&edge, false, Some(&uid(3))), Err(Bucket::Host));
    }

    /// Verifies: ADR-0013
    #[test]
    fn behind_a_gateway_a_message_passes_its_agents_bucket_and_the_aggregate() {
        let (rate, _) = rate(16, 64);
        let gateway = host("gateway");
        // One looping uid is stopped by its own bucket while another passes.
        assert_eq!(passing(&rate, &gateway, true, Some(&uid(1))), 3);
        assert_eq!(
            rate.admit(&gateway, true, Some(&uid(1))),
            Err(Bucket::Agent)
        );
        assert!(rate.admit(&gateway, true, Some(&uid(2))).is_ok());
        // A peer cycling fresh uids is stopped by the aggregate: 5 in all.
        assert!(rate.admit(&gateway, true, Some(&uid(3))).is_ok());
        assert_eq!(
            rate.admit(&gateway, true, Some(&uid(4))),
            Err(Bucket::Gateway)
        );
        assert_eq!(
            rate.admit(&gateway, true, Some(&uid(5))),
            Err(Bucket::Gateway)
        );
    }

    /// Verifies: ADR-0013
    #[test]
    fn a_message_naming_no_agent_behind_a_gateway_counts_in_the_aggregate_alone() {
        let (rate, _) = rate(16, 16);
        let gateway = host("gateway");
        assert_eq!(
            passing(&rate, &gateway, true, None),
            5,
            "no Agent bucket of 3"
        );
        assert_eq!(
            rate.admit(&gateway, true, Some(&[1, 2, 3])),
            Err(Bucket::Gateway),
            "a uid that is not 16 bytes names no Agent"
        );
        assert_eq!(rate.tables.lock().expect("lock").agents.len(), 0);
    }

    /// Enrolments through a Gateway are counted in the bucket of the bootstrap certificate they
    /// prove and in the Gateway's enrolment aggregate, and never in the aggregate its members are
    /// counted in; one whose certificate failed the check is counted in a bucket of its own and
    /// makes no bucket of its certificate. Each names the bucket that was empty. On a host that is
    /// no Gateway an enrolment request is counted as the host's message.
    /// Verifies: ADR-0039
    #[test]
    fn enrolments_through_a_gateway_are_counted_in_an_aggregate_of_their_own() {
        let (rate, _) = rate(16, 64);
        let gateway = host("gateway");
        let cert = |serial: &str| CertId {
            issuer: "bootstrap".into(),
            serial: serial.into(),
        };
        let (one, two) = (cert("01"), cert("02"));
        let enrolling = |bootstrap: Option<&CertId>| {
            (0..100)
                .take_while(|_| rate.admit_enrolment(&gateway, true, bootstrap).is_ok())
                .count()
        };
        // Forged proofs: their own small bucket, no table entry, nothing of anyone else's.
        assert_eq!(enrolling(None), 3, "the unchecked enrolments' burst");
        assert_eq!(
            rate.admit_enrolment(&gateway, true, None),
            Err(Bucket::UncheckedEnrolment)
        );
        assert_eq!(
            rate.tables.lock().expect("lock").agents.len(),
            0,
            "an unchecked certificate made a bucket"
        );
        // One checked certificate empties its own bucket, never another's.
        assert_eq!(enrolling(Some(&one)), 3, "one certificate's burst");
        assert_eq!(
            rate.admit_enrolment(&gateway, true, Some(&one)),
            Err(Bucket::Bootstrap)
        );
        assert!(
            rate.admit_enrolment(&gateway, true, Some(&two)).is_ok(),
            "one certificate spent another's tokens"
        );
        // The aggregate, `gateway_burst` 5, bounds them all together.
        assert!(rate.admit_enrolment(&gateway, true, Some(&two)).is_ok());
        assert_eq!(
            rate.admit_enrolment(&gateway, true, Some(&cert("03"))),
            Err(Bucket::Enrolment)
        );
        // And the Gateway's members are heard as before.
        assert_eq!(
            passing(&rate, &gateway, true, Some(&uid(1))),
            3,
            "a member behind the Gateway is heard as before"
        );
        assert!(rate.admit(&gateway, true, Some(&uid(2))).is_ok());

        let (rate, _) = self::rate(16, 16);
        assert_eq!(
            (0..100)
                .take_while(|_| rate
                    .admit_enrolment(&host("edge"), false, Some(&one))
                    .is_ok())
                .count(),
            3
        );
        assert_eq!(rate.admit(&host("edge"), false, None), Err(Bucket::Host));
    }

    /// Verifies: ADR-0013
    #[test]
    fn a_full_table_evicts_the_bucket_used_least_recently() {
        let (rate, _) = rate(2, 16);
        let (a, b, c) = (host("a"), host("b"), host("c"));
        assert_eq!(passing(&rate, &a, false, None), 3);
        assert!(rate.admit(&b, false, None).is_ok());
        // `a` is used again, so `b` is the one used least recently when `c` arrives.
        assert!(rate.admit(&a, false, None).is_err());
        assert!(rate.admit(&c, false, None).is_ok());
        assert!(
            rate.admit(&a, false, None).is_err(),
            "the bucket used most recently was kept"
        );
        assert_eq!(
            passing(&rate, &b, false, None),
            3,
            "b was forgotten: a new bucket"
        );
    }

    /// Verifies: ADR-0013
    #[test]
    fn both_tables_are_bounded() {
        let (rate, clock) = rate(4, 8);
        for n in 0..50u8 {
            // A second apart, so the aggregate always has a token for the next uid.
            clock.0.fetch_add(1000, Ordering::SeqCst);
            assert!(rate.admit(&host(&format!("h{n}")), false, None).is_ok());
            assert!(rate.admit(&host("gateway"), true, Some(&uid(n))).is_ok());
        }
        let tables = rate.tables.lock().expect("lock");
        assert_eq!(tables.own.len(), 4);
        assert_eq!(tables.agents.len(), 8);
    }
}
