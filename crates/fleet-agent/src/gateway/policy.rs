//! Which host a Gateway takes to speak for an `instance_uid` (ADR-0039 clause 6, after ADR-0036
//! clause 2): the host of the first report for it since the Gateway started. What the Gateway
//! forwards, relays and passes on for an Agent is decided against this binding; the state is the
//! core's, and the package cache holds it and asks it.

use std::collections::HashMap;

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
}

/// An `instance_uid`'s host, and when it last reported.
struct Binding {
    host: String,
    reported: u64,
}

/// Each `instance_uid` to the host of its first report.
#[derive(Default)]
pub struct Bindings {
    bound: HashMap<InstanceUid, Binding>,
    /// How many `instance_uid`s each host has bound.
    per_host: HashMap<String, usize>,
    /// Orders the reports, so the least recently reported binding is known.
    tick: u64,
}

impl Bindings {
    /// Binds `uid` to `host` on its first report, and on every report marks it the most recently
    /// reported. A host binds at most `limits.per_host`: past that its own least recently reported
    /// binding whose `instance_uid` is `idle` makes room, so a host whose Agents come and go is not
    /// shut out by its own past (ADR-0039 clause 6). At `limits.total` the least recently reported
    /// idle binding of any host makes room. Without one nothing is bound.
    pub fn bind(
        &mut self,
        uid: InstanceUid,
        host: &str,
        limits: Limits,
        idle: impl Fn(&InstanceUid) -> bool,
    ) -> Bound {
        self.tick += 1;
        let tick = self.tick;
        if let Some(binding) = self.bound.get_mut(&uid) {
            binding.reported = tick;
            return Bound::Kept;
        }
        if self.per_host.get(host).copied().unwrap_or(0) >= limits.per_host {
            let evicted = self
                .bound
                .iter()
                .filter(|(uid, binding)| binding.host == host && idle(uid))
                .min_by_key(|(_, binding)| binding.reported)
                .map(|(uid, _)| *uid);
            let Some(evicted) = evicted else {
                return Bound::Refused(
                    "the host holds as many bindings as max_carried_agents allows, none of them idle",
                );
            };
            self.unbind(&evicted);
        }
        if self.bound.len() >= limits.total {
            let evicted = self
                .bound
                .iter()
                .filter(|(uid, _)| idle(uid))
                .min_by_key(|(_, binding)| binding.reported)
                .map(|(uid, _)| *uid);
            let Some(evicted) = evicted else {
                return Bound::Refused(
                    "the Gateway holds as many bindings as it may, none of them idle",
                );
            };
            self.unbind(&evicted);
        }
        self.bound.insert(
            uid,
            Binding {
                host: host.to_string(),
                reported: tick,
            },
        );
        *self.per_host.entry(host.to_string()).or_default() += 1;
        Bound::New
    }

    fn unbind(&mut self, uid: &InstanceUid) {
        let Some(binding) = self.bound.remove(uid) else {
            return;
        };
        if let Some(count) = self.per_host.get_mut(&binding.host) {
            *count -= 1;
            if *count == 0 {
                self.per_host.remove(&binding.host);
            }
        }
    }

    /// The host `uid` is bound to.
    pub fn host_of(&self, uid: &InstanceUid) -> Option<&str> {
        self.bound.get(uid).map(|binding| binding.host.as_str())
    }

    /// How many `instance_uid`s `host` has bound.
    #[cfg(test)]
    pub fn count_of(&self, host: &str) -> usize {
        self.per_host.get(host).copied().unwrap_or(0)
    }

    /// How many bindings there are.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.bound.len()
    }

    /// Whether there are none.
    #[cfg(test)]
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

    /// The first report binds, and a later one from another host leaves the binding where it was.
    /// Verifies: ADR-0026
    #[test]
    fn the_first_reporting_host_keeps_the_binding() {
        let mut bindings = Bindings::default();
        let uid = InstanceUid::default();
        assert_eq!(bindings.bind(uid, "a", LIMITS, |_| true), Bound::New);
        assert_eq!(bindings.bind(uid, "b", LIMITS, |_| true), Bound::Kept);
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
        bindings.bind(first, "a", LIMITS, |_| true);
        bindings.bind(other, "b", LIMITS, |_| true);
        bindings.bind(second, "a", LIMITS, |_| true);
        let third = InstanceUid::default();
        assert_eq!(
            bindings.bind(third, "a", LIMITS, |uid| *uid != second),
            Bound::New
        );
        assert!(
            bindings.host_of(&first).is_none(),
            "its own idle one made room"
        );
        assert_eq!(bindings.host_of(&other), Some("b"), "another host's stayed");
        assert_eq!(bindings.count_of("a"), 2);
        assert!(matches!(
            bindings.bind(InstanceUid::default(), "a", LIMITS, |_| false),
            Bound::Refused(_)
        ));
    }

    /// At the total, the least recently reported idle binding makes room — a report refreshing
    /// how recent a binding is — and with none idle nothing is bound.
    /// Verifies: ADR-0026
    #[test]
    fn at_the_total_the_least_recently_reported_idle_binding_makes_room() {
        let mut bindings = Bindings::default();
        let [first, second, third] = [(); 3].map(|()| InstanceUid::default());
        bindings.bind(first, "a", LIMITS, |_| true);
        bindings.bind(second, "b", LIMITS, |_| true);
        bindings.bind(third, "c", LIMITS, |_| true);
        assert_eq!(bindings.bind(first, "a", LIMITS, |_| true), Bound::Kept);
        assert_eq!(
            bindings.bind(InstanceUid::default(), "d", LIMITS, |_| true),
            Bound::New
        );
        assert!(
            bindings.host_of(&first).is_some(),
            "reported again, so kept"
        );
        assert!(
            bindings.host_of(&second).is_none(),
            "now the least recently reported, so evicted"
        );
        assert_eq!(bindings.len(), 3);
        assert!(matches!(
            bindings.bind(InstanceUid::default(), "e", LIMITS, |_| false),
            Bound::Refused(_)
        ));
    }
}
