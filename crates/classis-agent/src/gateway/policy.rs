//! Which host a Gateway takes to speak for an `instance_uid` (ADR-0058 clause 2, after ADR-0036
//! clause 2): the host of the first report for it, kept across the Gateway's restarts in its store
//! ([`store`](crate::gateway::store)). What the Gateway forwards, relays and passes on for an Agent
//! is decided against this binding; the state is the core's, and the package cache holds it and
//! asks it.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use opamp::uid::InstanceUid;

/// How many bindings there may be: per host, and in all.
#[derive(Clone, Copy)]
pub struct Limits {
    /// The most `instance_uid`s one host may bind: `max_carried_agents`.
    pub per_host: usize,
    /// The most bindings the Gateway holds at once.
    pub total: usize,
}

/// What a report did to its `instance_uid`'s binding.
#[derive(Debug, PartialEq, Eq)]
pub enum Bound {
    /// Bound already, to whichever host reported it first; now the most recently reported.
    Kept,
    /// Bound now, to the reporting host.
    New,
    /// Not bound, for this reason.
    Refused(&'static str),
    /// Not decided: the report relies on its host's certificate end, which another report is
    /// moving and the store does not hold yet. Ask again once it is written.
    Waiting,
}

/// Where a host's certificate ends, as the Gateway keeps it (ADR-0058 clause 3): the latest
/// `notAfter` among the valid certificates the host reported under, and that certificate as the
/// revocation list names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct End {
    /// The `notAfter`, in seconds since the Unix epoch.
    pub not_after: i64,
    /// The SHA-256 of the issuer's DER-encoded name, in lowercase hex.
    pub issuer: String,
    /// The serial in lowercase hex without leading zeros.
    pub serial: String,
}

/// One change to the bindings, as the store keeps it (ADR-0058 clause 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// An `instance_uid` is bound to a host.
    Bound(InstanceUid, String),
    /// A binding is given up or ended.
    Unbound(InstanceUid),
    /// A binding was reported: it is now the most recently reported.
    Reported(InstanceUid),
    /// A host's certificate ends here.
    Ends(String, End),
}

/// An `instance_uid`'s host, and when it last reported.
struct Binding {
    host: Arc<str>,
    reported: u64,
    /// Made, and not yet in the store.
    pending: bool,
}

/// Each `instance_uid` to the host of its first report.
#[derive(Default)]
pub struct Bindings {
    bound: HashMap<InstanceUid, Binding>,
    /// The `instance_uid`s each host has bound, so a host's bindings are found without a scan.
    hosts: HashMap<Arc<str>, HashSet<InstanceUid>>,
    /// Where the certificate of each host with a binding ends.
    ends: HashMap<Arc<str>, Arc<End>>,
    /// The same ends by `notAfter`, so those that have passed are found without a scan.
    expiring: BTreeSet<(i64, Arc<str>)>,
    /// The hosts whose end a report moved and the store does not hold yet, each with the end it
    /// holds, if any: restored should the write fail.
    moving: HashMap<Arc<str>, Option<Arc<End>>>,
    /// Orders the reports, so the least recently reported binding is known.
    tick: u64,
    /// The bindings reported since their order was last written.
    reported: HashSet<InstanceUid>,
}

/// What a report did: to its binding, to the bindings that made room for it, and what the store
/// must hold before the report is relied on.
#[derive(Debug, PartialEq, Eq)]
pub struct Outcome {
    pub bound: Bound,
    /// The `instance_uid` whose binding made room, if one did, so what else the Gateway holds for
    /// it can go too.
    pub evicted: Vec<InstanceUid>,
    /// What the store must hold before the report is forwarded (ADR-0058 clause 3): the new
    /// binding, the removals that made room for it, and the host's certificate end where the
    /// report moved it. Empty when the report changed nothing the store keeps.
    pub changes: Vec<Change>,
}

fn refused_waiting() -> Outcome {
    Outcome {
        bound: Bound::Waiting,
        evicted: Vec::new(),
        changes: Vec::new(),
    }
}

/// The bindings as a rewrite of the store needs them, copied cheaply under the lock that guards
/// them and turned into changes after it is released.
pub struct Raw {
    ends: Vec<(Arc<str>, Arc<End>)>,
    bound: Vec<(u64, InstanceUid, Arc<str>)>,
}

impl Raw {
    /// What the store holds when it is rewritten whole: each host's certificate end, then every
    /// binding, the least recently reported first, so that [`Bindings::replay`] restores the order.
    #[must_use]
    pub fn changes(mut self) -> Vec<Change> {
        self.bound
            .sort_unstable_by_key(|(reported, _, _)| *reported);
        self.ends
            .into_iter()
            .map(|(host, end)| Change::Ends(host.to_string(), (*end).clone()))
            .chain(
                self.bound
                    .into_iter()
                    .map(|(_, uid, host)| Change::Bound(uid, host.to_string())),
            )
            .collect()
    }
}

/// The bindings reported since their order was last written, copied under the lock and ordered
/// after it is released.
pub struct Reports(Vec<(u64, InstanceUid)>);

impl Reports {
    /// Whether there are none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The reports as the store keeps them, the least recently reported first.
    #[must_use]
    pub fn changes(mut self) -> Vec<Change> {
        self.0.sort_unstable_by_key(|(reported, _)| *reported);
        self.0
            .into_iter()
            .map(|(_, uid)| Change::Reported(uid))
            .collect()
    }
}

impl Bindings {
    /// Binds `uid` to `host` on its first report, and on every report of that host marks it the
    /// most recently reported; another host's report for it changes nothing. A host binds at most
    /// `limits.per_host`, and the Gateway at most `limits.total`: past either the host's own least
    /// recently reported binding whose `instance_uid` is `idle` makes room, so a host whose Agents
    /// come and go is not shut out by its own past, and never another host's (ADR-0058 clause 2).
    /// Without one nothing is bound.
    ///
    /// A report under a certificate whose `notAfter` has passed by `now` binds nothing and moves
    /// no end (ADR-0058 clause 4); one under a certificate that ends later than the one the host's
    /// end was kept from moves it to `end` (clause 2). A new binding is pending until
    /// [`Bindings::commit`], and a moved end until the write settles it: a pending binding makes
    /// no room, a report for it binds nothing, and a report of its host that relies on a moved end
    /// is [`Bound::Waiting`], so nothing is relied on before the store holds it.
    pub fn bind(
        &mut self,
        uid: InstanceUid,
        host: &str,
        end: &End,
        now: i64,
        limits: Limits,
        idle: impl Fn(&InstanceUid) -> bool,
    ) -> Outcome {
        let refused = |why, evicted| Outcome {
            bound: Bound::Refused(why),
            evicted,
            changes: Vec::new(),
        };
        if end.not_after < now {
            return refused(
                "the certificate it was reported under has expired",
                Vec::new(),
            );
        }
        if let Some(binding) = self.bound.get(&uid) {
            if binding.pending {
                return refused("its binding is still being written", Vec::new());
            }
            if &*binding.host != host {
                return Outcome {
                    bound: Bound::Kept,
                    evicted: Vec::new(),
                    changes: Vec::new(),
                };
            }
        }
        if self.waits_for_end(host, end) {
            return refused_waiting();
        }
        self.tick += 1;
        let tick = self.tick;
        if let Some(binding) = self.bound.get_mut(&uid) {
            binding.reported = tick;
            self.reported.insert(uid);
            return Outcome {
                bound: Bound::Kept,
                evicted: Vec::new(),
                changes: self.move_end(host, end).into_iter().collect(),
            };
        }
        let mut evicted = Vec::new();
        let own = self.hosts.get(host);
        let full = if own.map_or(0, HashSet::len) >= limits.per_host {
            Some("the host holds as many bindings as max_carried_agents allows, none of them idle")
        } else if self.bound.len() >= limits.total {
            Some(
                "the Gateway holds as many bindings as it may, and none of this host's own is idle",
            )
        } else {
            None
        };
        if let Some(why) = full {
            let victim = own.into_iter().flatten().copied().filter(|uid| {
                self.bound
                    .get(uid)
                    .is_some_and(|binding| !binding.pending && idle(uid))
            });
            let Some(victim) = victim.min_by_key(|uid| self.bound.get(uid).map(|b| b.reported))
            else {
                return refused(why, evicted);
            };
            // The host keeps its end through giving up its last binding for this one, so an
            // earlier certificate does not move it back.
            self.unbind(&victim, true);
            evicted.push(victim);
        }
        let key = self.key(host);
        self.bound.insert(
            uid,
            Binding {
                host: key.clone(),
                reported: tick,
                pending: true,
            },
        );
        self.hosts.entry(key).or_default().insert(uid);
        let mut changes: Vec<Change> = evicted.iter().map(|uid| Change::Unbound(*uid)).collect();
        changes.extend(self.move_end(host, end));
        changes.push(Change::Bound(uid, host.to_string()));
        Outcome {
            bound: Bound::New,
            evicted,
            changes,
        }
    }

    /// The one shared name of `host`.
    fn key(&self, host: &str) -> Arc<str> {
        self.hosts
            .get_key_value(host)
            .map(|(key, _)| key.clone())
            .or_else(|| self.ends.get_key_value(host).map(|(key, _)| key.clone()))
            .unwrap_or_else(|| Arc::from(host))
    }

    fn set_end(&mut self, host: Arc<str>, end: Arc<End>) {
        self.drop_end(&host);
        self.expiring.insert((end.not_after, host.clone()));
        self.ends.insert(host, end);
    }

    fn drop_end(&mut self, host: &str) {
        if let Some((host, end)) = self.ends.remove_entry(host) {
            self.expiring.remove(&(end.not_after, host));
        }
    }

    /// Whether a report of `host` under a certificate ending at `end` relies on a move of the
    /// host's end the store does not hold yet: it would move the end past what the store holds.
    fn waits_for_end(&self, host: &str, end: &End) -> bool {
        self.moving.get(host).is_some_and(|held| {
            held.as_ref()
                .is_none_or(|held| held.not_after < end.not_after)
        })
    }

    /// Moves `host`'s certificate end to `end` when it ends later, or when the host has none yet;
    /// the move is pending until [`Bindings::ends_written`] or [`Bindings::compacted`] settles it.
    fn move_end(&mut self, host: &str, end: &End) -> Option<Change> {
        let kept = self.ends.get(host).cloned();
        if kept
            .as_ref()
            .is_some_and(|kept| kept.not_after >= end.not_after)
        {
            return None;
        }
        let key = self.key(host);
        self.moving.insert(key.clone(), kept);
        self.set_end(key, Arc::new(end.clone()));
        Some(Change::Ends(host.to_string(), end.clone()))
    }

    /// The store took `changes`, or failed to: the moves of the ends among them are settled, kept
    /// or undone.
    pub fn ends_written(&mut self, changes: &[Change], written: bool) {
        for change in changes {
            if let Change::Ends(host, _) = change {
                self.settle_end(host, written);
            }
        }
    }

    /// The hosts whose end moves a store rewritten whole from [`Bindings::raw`] settles.
    #[must_use]
    pub fn moving(&self) -> Vec<Arc<str>> {
        self.moving.keys().cloned().collect()
    }

    /// A rewrite of the store that held the ends of `hosts` succeeded, or failed.
    pub fn compacted(&mut self, hosts: &[Arc<str>], written: bool) {
        for host in hosts {
            self.settle_end(host, written);
        }
    }

    fn settle_end(&mut self, host: &str, written: bool) {
        let Some((key, held)) = self.moving.remove_entry(host) else {
            return;
        };
        if written {
            return;
        }
        match held {
            Some(held) => self.set_end(key, held),
            None => self.drop_end(host),
        }
    }

    /// The store holds `uid`'s new binding: it is relied on from now.
    pub fn commit(&mut self, uid: &InstanceUid) {
        if let Some(binding) = self.bound.get_mut(uid) {
            binding.pending = false;
        }
    }

    /// The store could not take `uid`'s new binding: it is not made. Returns its removal, should
    /// the store hold it after all.
    pub fn abort(&mut self, uid: &InstanceUid) -> Vec<Change> {
        if !self.bound.get(uid).is_some_and(|binding| binding.pending) {
            return Vec::new();
        }
        self.unbind(uid, false);
        vec![Change::Unbound(*uid)]
    }

    /// Whether `uid` is bound to `host` and relied on: its binding is not pending.
    #[must_use]
    pub fn holds(&self, uid: &InstanceUid, host: &str) -> bool {
        self.bound
            .get(uid)
            .is_some_and(|binding| &*binding.host == host && !binding.pending)
    }

    /// The bindings reported since the last call: what keeps their order across a restart
    /// (ADR-0058 clause 3).
    pub fn reports(&mut self) -> Reports {
        Reports(
            std::mem::take(&mut self.reported)
                .into_iter()
                .filter_map(|uid| self.bound.get(&uid).map(|binding| (binding.reported, uid)))
                .collect(),
        )
    }

    /// Ends every binding of each host whose kept certificate end has passed by `now`, or, when
    /// `revoked` is given, whose certificate it says the revocation list names (ADR-0058 clause
    /// 3). Returns each such host, and the `instance_uid`s it held. The ends that have passed are
    /// found by their order; the revocation list is asked about every host's end.
    pub fn end(
        &mut self,
        now: i64,
        revoked: Option<&dyn Fn(&End) -> bool>,
    ) -> Vec<(String, Vec<InstanceUid>)> {
        let mut ended: HashSet<Arc<str>> = self
            .expiring
            .range(..(now, Arc::from("")))
            .map(|(_, host)| host.clone())
            .collect();
        if let Some(revoked) = revoked {
            ended.extend(
                self.ends
                    .iter()
                    .filter(|(_, end)| revoked(end))
                    .map(|(host, _)| host.clone()),
            );
        }
        ended
            .into_iter()
            .map(|host| {
                let uids: Vec<InstanceUid> = self
                    .hosts
                    .remove(&host)
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                for uid in &uids {
                    self.bound.remove(uid);
                }
                self.drop_end(&host);
                self.moving.remove(&host);
                (host.to_string(), uids)
            })
            .collect()
    }

    /// Removes `uid`'s binding. A host left with none keeps no certificate end, unless
    /// `keep_end`: it gives the binding up for another.
    fn unbind(&mut self, uid: &InstanceUid, keep_end: bool) {
        let Some(binding) = self.bound.remove(uid) else {
            return;
        };
        let Some(own) = self.hosts.get_mut(&binding.host) else {
            return;
        };
        own.remove(uid);
        if own.is_empty() {
            self.hosts.remove(&binding.host);
            if !keep_end {
                self.drop_end(&binding.host);
                self.moving.remove(&binding.host);
            }
        }
    }

    /// The bindings `changes` leave, applied in order: the store read back (ADR-0058 clause 3). A
    /// later report orders a binding after the earlier ones, and a removal of what is not bound
    /// changes nothing.
    ///
    /// # Errors
    /// Returns an error when a host is left with a binding and no certificate end, which only a
    /// damaged store holds: such a binding could never end.
    pub fn replay(changes: impl IntoIterator<Item = Change>) -> Result<Bindings, String> {
        let mut bindings = Bindings::default();
        let mut ends = HashMap::new();
        for change in changes {
            bindings.tick += 1;
            let tick = bindings.tick;
            match change {
                Change::Bound(uid, host) => {
                    bindings.unbind(&uid, false);
                    let key = bindings.key(&host);
                    bindings.hosts.entry(key.clone()).or_default().insert(uid);
                    bindings.bound.insert(
                        uid,
                        Binding {
                            host: key,
                            reported: tick,
                            pending: false,
                        },
                    );
                }
                Change::Unbound(uid) => bindings.unbind(&uid, false),
                Change::Reported(uid) => {
                    if let Some(binding) = bindings.bound.get_mut(&uid) {
                        binding.reported = tick;
                    }
                }
                Change::Ends(host, end) => {
                    ends.insert(host, end);
                }
            }
        }
        let hosts: Vec<Arc<str>> = bindings.hosts.keys().cloned().collect();
        for host in hosts {
            let end = ends
                .remove(&*host)
                .ok_or_else(|| format!("the host {host} has a binding and no certificate end"))?;
            bindings.set_end(host, Arc::new(end));
        }
        Ok(bindings)
    }

    /// A copy of the bindings, cheap enough to take under the lock that guards them, that
    /// [`Raw::changes`] turns into what the store holds when it is rewritten whole.
    #[must_use]
    pub fn raw(&self) -> Raw {
        Raw {
            ends: self
                .ends
                .iter()
                .map(|(host, end)| (host.clone(), end.clone()))
                .collect(),
            bound: self
                .bound
                .iter()
                .map(|(uid, binding)| (binding.reported, *uid, binding.host.clone()))
                .collect(),
        }
    }

    /// What the store holds when it is rewritten whole: [`Raw::changes`] of [`Bindings::raw`].
    #[must_use]
    pub fn snapshot(&self) -> Vec<Change> {
        self.raw().changes()
    }

    /// How many lines a store rewritten whole holds: one per binding, one per host's end.
    #[must_use]
    pub fn live(&self) -> usize {
        self.bound.len() + self.ends.len()
    }

    /// The host `uid` is bound to.
    pub fn host_of(&self, uid: &InstanceUid) -> Option<&str> {
        self.bound.get(uid).map(|binding| &*binding.host)
    }

    /// How many `instance_uid`s `host` has bound.
    #[cfg(test)]
    pub fn count_of(&self, host: &str) -> usize {
        self.hosts.get(host).map_or(0, HashSet::len)
    }

    /// How many bindings there are.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bound.len()
    }

    /// Whether there are none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bound.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: Limits = Limits {
        per_host: 2,
        total: 3,
    };

    fn end(not_after: i64) -> End {
        End {
            not_after,
            issuer: "ab".repeat(32),
            serial: "1".to_string(),
        }
    }

    /// The store took everything: `uid`'s binding and every moved end.
    fn commit(bindings: &mut Bindings, uid: &InstanceUid) {
        bindings.commit(uid);
        bindings.moving.clear();
    }

    /// A report of `uid` from `host`, its binding written at once.
    fn bind(
        bindings: &mut Bindings,
        uid: InstanceUid,
        host: &str,
        idle: impl Fn(&InstanceUid) -> bool,
    ) -> (Bound, Vec<InstanceUid>) {
        let outcome = bindings.bind(uid, host, &end(i64::MAX), 0, LIMITS, idle);
        commit(bindings, &uid);
        (outcome.bound, outcome.evicted)
    }

    /// The first report binds, and a later one from another host leaves the binding where it was.
    /// Verifies: ADR-0026
    #[test]
    fn the_first_reporting_host_keeps_the_binding() {
        let mut bindings = Bindings::default();
        let uid = InstanceUid::default();
        assert_eq!(bind(&mut bindings, uid, "a", |_| true).0, Bound::New);
        assert_eq!(bind(&mut bindings, uid, "b", |_| true).0, Bound::Kept);
        assert_eq!(bindings.host_of(&uid), Some("a"));
        assert_eq!(bindings.count_of("b"), 0);
    }

    /// Past its share a host gives up its own least recently reported idle binding, never another
    /// host's, and with none of its own idle nothing is bound.
    /// Verifies: ADR-0039
    #[test]
    fn past_its_share_a_host_gives_up_its_own_idle_binding() {
        let mut bindings = Bindings::default();
        let [first, second, other] = [(); 3].map(|()| InstanceUid::default());
        bind(&mut bindings, first, "a", |_| true);
        bind(&mut bindings, other, "b", |_| true);
        bind(&mut bindings, second, "a", |_| true);
        let third = InstanceUid::default();
        assert_eq!(
            bind(&mut bindings, third, "a", |uid| *uid != second),
            (Bound::New, vec![first]),
            "its own idle one made room, and is named"
        );
        assert!(
            bindings.host_of(&first).is_none(),
            "its own idle one made room"
        );
        assert_eq!(bindings.host_of(&other), Some("b"), "another host's stayed");
        assert_eq!(bindings.count_of("a"), 2);
        assert!(matches!(
            bind(&mut bindings, InstanceUid::default(), "a", |_| false),
            (Bound::Refused(_), evicted) if evicted.is_empty()
        ));
    }

    /// At the total, a host's report for a new `instance_uid` takes the place of the host's own
    /// least recently reported idle binding — a report refreshing how recent a binding is — and
    /// never another host's: a host without one of its own binds nothing.
    /// Verifies: ADR-0058
    #[test]
    fn at_the_total_only_the_reporting_hosts_own_idle_binding_makes_room() {
        let mut bindings = Bindings::default();
        let [first, second, other] = [(); 3].map(|()| InstanceUid::default());
        bind(&mut bindings, first, "a", |_| true);
        bind(&mut bindings, other, "b", |_| true);
        bind(&mut bindings, second, "a", |_| true);
        assert_eq!(bind(&mut bindings, first, "a", |_| true).0, Bound::Kept);
        let limits = Limits {
            per_host: 3,
            total: 3,
        };
        let new = InstanceUid::default();
        let outcome = bindings.bind(new, "a", &end(i64::MAX), 0, limits, |_| true);
        assert_eq!(
            (outcome.bound, outcome.evicted),
            (Bound::New, vec![second]),
            "its own least recently reported"
        );
        commit(&mut bindings, &new);
        assert_eq!(
            bindings.host_of(&first),
            Some("a"),
            "reported again, so kept"
        );
        assert_eq!(bindings.host_of(&other), Some("b"), "another host's stayed");
        assert_eq!(bindings.len(), 3);

        let outcome = bindings.bind(
            InstanceUid::default(),
            "c",
            &end(i64::MAX),
            0,
            limits,
            |_| true,
        );
        assert!(
            matches!(outcome.bound, Bound::Refused(_)) && outcome.evicted.is_empty(),
            "a host with no binding of its own binds nothing"
        );
        let outcome = bindings.bind(
            InstanceUid::default(),
            "b",
            &end(i64::MAX),
            0,
            limits,
            |_| false,
        );
        assert!(
            matches!(outcome.bound, Bound::Refused(_)) && outcome.evicted.is_empty(),
            "nor one whose own are not idle"
        );
        assert_eq!(
            [first, other, new].map(|uid| bindings.host_of(&uid).is_some()),
            [true; 3]
        );
    }

    /// Replaying a store keeps each host's last certificate end and only for a host left with a
    /// binding; a binding whose host has no end is a damaged store.
    /// Verifies: ADR-0058
    #[test]
    fn a_replayed_binding_keeps_its_hosts_last_end() {
        let (kept, gone) = (InstanceUid::default(), InstanceUid::default());
        let bindings = Bindings::replay([
            Change::Ends("a".into(), end(1)),
            Change::Bound(kept, "a".into()),
            Change::Ends("a".into(), end(2)),
            Change::Ends("b".into(), end(3)),
            Change::Bound(gone, "b".into()),
            Change::Unbound(gone),
            Change::Unbound(InstanceUid::default()),
        ])
        .expect("replay");
        assert_eq!(bindings.host_of(&kept), Some("a"));
        assert_eq!(
            bindings.snapshot(),
            vec![
                Change::Ends("a".into(), end(2)),
                Change::Bound(kept, "a".into())
            ]
        );
        assert_eq!(bindings.live(), 2);
        assert!(Bindings::replay([Change::Bound(kept, "a".into())]).is_err());
    }

    /// A new binding is pending until the store holds it: what the store must hold comes with it,
    /// the host's certificate end among it; a report for it meanwhile binds nothing, and it makes
    /// no room. A later certificate moves the end, an earlier one does not, and a binding the store
    /// could not take is not made.
    /// Verifies: ADR-0058
    #[test]
    fn a_new_binding_waits_for_the_store() {
        let mut bindings = Bindings::default();
        let uid = InstanceUid::default();
        let outcome = bindings.bind(uid, "a", &end(10), 0, LIMITS, |_| true);
        assert_eq!(
            outcome,
            Outcome {
                bound: Bound::New,
                evicted: Vec::new(),
                changes: vec![
                    Change::Ends("a".into(), end(10)),
                    Change::Bound(uid, "a".into())
                ],
            }
        );
        assert!(!bindings.holds(&uid, "a"), "pending");
        assert!(matches!(
            bindings.bind(uid, "a", &end(10), 0, LIMITS, |_| true).bound,
            Bound::Refused(_)
        ));
        commit(&mut bindings, &uid);
        assert!(bindings.holds(&uid, "a"));
        assert_eq!(
            bindings
                .bind(uid, "a", &end(20), 0, LIMITS, |_| true)
                .changes,
            vec![Change::Ends("a".into(), end(20))],
            "a renewed certificate moves the end"
        );
        assert!(bindings
            .bind(uid, "a", &end(15), 0, LIMITS, |_| true)
            .changes
            .is_empty());

        let other = InstanceUid::default();
        bindings.bind(other, "b", &end(10), 0, LIMITS, |_| true);
        assert_eq!(bindings.abort(&other), vec![Change::Unbound(other)]);
        assert_eq!(bindings.host_of(&other), None);
        assert_eq!(bindings.live(), 2, "b keeps no end without a binding");
        assert!(bindings.abort(&uid).is_empty(), "a written binding stays");
    }

    /// A report under a certificate whose `notAfter` has passed binds nothing and moves no end. A
    /// host's bindings end once its kept end has passed, or once the revocation list names the
    /// certificate it was kept from; another host's are left, and the `instance_uid` is free to
    /// bind anew.
    /// Verifies: ADR-0058
    #[test]
    fn a_hosts_bindings_end_with_its_certificate() {
        let mut bindings = Bindings::default();
        let [first, second, other] = [(); 3].map(|()| InstanceUid::default());
        for (uid, host) in [(first, "a"), (second, "a"), (other, "b")] {
            bindings.bind(uid, host, &end(100), 50, LIMITS, |_| true);
            commit(&mut bindings, &uid);
        }
        // Later than the end kept for "a", and expired by the time of the report.
        let outcome = bindings.bind(first, "a", &end(120), 150, LIMITS, |_| true);
        assert!(matches!(outcome.bound, Bound::Refused(_)), "expired at 150");
        assert!(outcome.changes.is_empty(), "and moves no end");
        assert!(bindings
            .bind(InstanceUid::default(), "c", &end(100), 150, LIMITS, |_| {
                true
            })
            .changes
            .is_empty());

        assert!(bindings.end(100, None).is_empty(), "not yet passed");
        let mut ended = bindings.end(101, Some(&|end: &End| end.serial == "none"));
        for (_, uids) in &mut ended {
            uids.sort_by_key(InstanceUid::to_string);
        }
        ended.sort_by(|x, y| x.0.cmp(&y.0));
        let mut a = vec![first, second];
        a.sort_by_key(InstanceUid::to_string);
        assert_eq!(
            ended,
            vec![("a".to_string(), a), ("b".to_string(), vec![other])]
        );
        assert!(bindings.is_empty() && bindings.live() == 0);

        bindings.bind(first, "c", &end(500), 200, LIMITS, |_| true);
        commit(&mut bindings, &first);
        assert_eq!(bindings.host_of(&first), Some("c"), "bound anew");
        let revoked = bindings.end(200, Some(&|end: &End| end.serial == "1"));
        assert_eq!(revoked, vec![("c".to_string(), vec![first])]);
    }

    /// A host of one binding that gives it up for another keeps its certificate end: a report
    /// under an earlier certificate does not move it back.
    /// Verifies: ADR-0058
    #[test]
    fn giving_up_its_last_binding_keeps_the_hosts_end() {
        let limits = Limits {
            per_host: 1,
            total: 10,
        };
        let mut bindings = Bindings::default();
        let [first, second] = [(); 2].map(|()| InstanceUid::default());
        bindings.bind(first, "a", &end(100), 0, limits, |_| true);
        commit(&mut bindings, &first);
        let outcome = bindings.bind(second, "a", &end(50), 0, limits, |_| true);
        assert_eq!(outcome.evicted, vec![first]);
        assert_eq!(
            outcome.changes,
            vec![Change::Unbound(first), Change::Bound(second, "a".into())]
        );
        commit(&mut bindings, &second);
        assert_eq!(
            bindings.snapshot(),
            vec![
                Change::Ends("a".into(), end(100)),
                Change::Bound(second, "a".into())
            ]
        );
    }

    /// A moved end is pending until the store settles it: a report of the host that relies on it
    /// waits, one under a certificate the store's end covers does not, and a failed write puts the
    /// end the store holds back. A host's first end is pending the same way.
    /// Verifies: ADR-0058
    #[test]
    fn a_moved_end_is_pending_until_written() {
        let mut bindings = Bindings::default();
        let [first, second, third] = [(); 3].map(|()| InstanceUid::default());
        let outcome = bindings.bind(first, "a", &end(100), 0, LIMITS, |_| true);
        assert!(
            matches!(
                bindings
                    .bind(second, "a", &end(100), 0, LIMITS, |_| true)
                    .bound,
                Bound::Waiting
            ),
            "the host's first end is not written yet"
        );
        bindings.ends_written(&outcome.changes, true);
        commit(&mut bindings, &first);

        let moved = bindings.bind(first, "a", &end(200), 0, LIMITS, |_| true);
        assert_eq!(moved.changes, vec![Change::Ends("a".into(), end(200))]);
        assert_eq!(
            bindings
                .bind(second, "a", &end(200), 0, LIMITS, |_| true)
                .bound,
            Bound::Waiting
        );
        assert_eq!(
            bindings
                .bind(third, "a", &end(100), 0, LIMITS, |_| true)
                .bound,
            Bound::New,
            "covered by the end the store holds"
        );
        bindings.ends_written(&moved.changes, false);
        commit(&mut bindings, &third);
        assert_eq!(
            bindings.snapshot()[0],
            Change::Ends("a".into(), end(100)),
            "put back"
        );
    }
}
