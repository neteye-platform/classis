//! Where a `ServerToAgent` goes on its way down (ADR-0039 clause 5).
//!
//! The Gateway routes by `instance_uid`, for the host it is bound to (ADR-0039 clause 5). Upward
//! that needs no lookup — a report leaves on its own Agent's connection, once its `instance_uid`
//! is bound to the host that sent it. Downward it does: the pool's reader tasks see replies for
//! every Agent the Gateway carries, and each has to reach the downstream connection that Agent is
//! actually on, which is always one of its bound host's.
//!
//! Two shapes of downstream connection, because there are two transports. A WebSocket peer holds a
//! channel open for as long as it is connected; a plain-HTTP peer is a single exchange waiting for
//! exactly one reply. Both are registered here, and a reply for an `instance_uid` nobody claims is
//! dropped with a log line rather than broadcast.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use opamp::proto::ServerToAgent;
use opamp::uid::InstanceUid;
use tokio::sync::{mpsc, oneshot};
use tracing::debug;

use crate::gateway::cache::PackageCache;

/// Who is waiting for an Agent's replies, and the host its certificate names.
struct Route {
    downstream: Downstream,
    /// The host the downstream connection's certificate names (`urn:opamp-fleet:host:<id>`), the
    /// one an offer relayed over it is recorded for (ADR-0026 clause 45).
    host: Option<String>,
}

/// Who is waiting for an Agent's replies.
enum Downstream {
    /// A WebSocket peer: everything for this Agent goes down this channel until it disconnects.
    Socket(mpsc::Sender<ServerToAgent>),
    /// A plain-HTTP peer mid-exchange: one reply, then gone. The number tells this exchange from
    /// a later one for the same Agent.
    Exchange(oneshot::Sender<ServerToAgent>, u64),
}

pub struct Registry {
    routes: Mutex<HashMap<InstanceUid, Route>>,
    /// The number the next plain-HTTP exchange is registered under.
    exchanges: AtomicU64,
    /// What sees every offer on its way down (ADR-0026 clause 42).
    cache: Arc<PackageCache>,
}

impl Registry {
    pub fn new(cache: Arc<PackageCache>) -> Self {
        Registry {
            routes: Mutex::new(HashMap::new()),
            exchanges: AtomicU64::new(0),
            cache,
        }
    }

    /// The package cache, which holds the bindings and logs the Gateway's refusals.
    pub fn cache(&self) -> &PackageCache {
        &self.cache
    }

    /// A WebSocket peer whose certificate speaks as `speaker` claims an Agent, and gets it only
    /// when the Agent's `instance_uid` is bound to `speaker`: then the route is its, and `false`
    /// leaves the route where it was (ADR-0039 clause 5). Claiming again from the same host
    /// replaces the route: an Agent that reconnects through a second socket is reachable on the
    /// new one.
    pub fn attach(
        &self,
        uid: InstanceUid,
        sink: mpsc::Sender<ServerToAgent>,
        host: Option<String>,
        speaker: &str,
    ) -> bool {
        // A report binds its `instance_uid` to its host, the first one only (ADR-0039 clause 6);
        // an `instance_uid` with a route here is never the binding that makes room.
        let mut routes = self.routes.lock().expect("registry lock");
        if !self
            .cache
            .bind(uid, speaker, |uid| routes.contains_key(uid))
        {
            return false;
        }
        routes.insert(
            uid,
            Route {
                downstream: Downstream::Socket(sink),
                host,
            },
        );
        true
    }

    /// A plain-HTTP peer whose certificate speaks as `speaker` waits for exactly one reply for
    /// this Agent, when the Agent's `instance_uid` is bound to `speaker` (ADR-0039 clause 5).
    /// Returns the number that [`Registry::abandon`] takes once the exchange ends without one, and
    /// `None` for an `instance_uid` that is not the host's.
    pub fn expect_once(
        &self,
        uid: InstanceUid,
        reply: oneshot::Sender<ServerToAgent>,
        host: Option<String>,
        speaker: &str,
    ) -> Option<u64> {
        let mut routes = self.routes.lock().expect("registry lock");
        if !self
            .cache
            .bind(uid, speaker, |uid| routes.contains_key(uid))
        {
            return None;
        }
        let exchange = self.exchanges.fetch_add(1, Ordering::Relaxed);
        routes.insert(
            uid,
            Route {
                downstream: Downstream::Exchange(reply, exchange),
                host,
            },
        );
        Some(exchange)
    }

    /// An enrolling peer's plain-HTTP exchange waits for exactly one reply for `uid`, binding
    /// nothing (ADR-0039 clause 5): its exchange is its route for that reply alone. `None` — the
    /// report is not forwarded — for an `instance_uid` bound to a host or routed already, so an
    /// enrolling peer never takes another Agent's replies.
    pub fn expect_enrolment(
        &self,
        uid: InstanceUid,
        reply: oneshot::Sender<ServerToAgent>,
    ) -> Option<u64> {
        let mut routes = self.routes.lock().expect("registry lock");
        if routes.contains_key(&uid) || self.cache.is_bound(&uid) {
            return None;
        }
        let exchange = self.exchanges.fetch_add(1, Ordering::Relaxed);
        routes.insert(
            uid,
            Route {
                downstream: Downstream::Exchange(reply, exchange),
                host: None,
            },
        );
        Some(exchange)
    }

    /// Releases the route of a plain-HTTP exchange that ended without its reply, unless a later
    /// exchange or a socket has claimed the Agent since.
    pub fn abandon(&self, uid: InstanceUid, exchange: u64) {
        let mut routes = self.routes.lock().expect("registry lock");
        if matches!(
            routes.get(&uid).map(|route| &route.downstream),
            Some(Downstream::Exchange(_, current)) if *current == exchange
        ) {
            routes.remove(&uid);
        }
    }

    /// Whether anyone downstream is waiting for this Agent's replies.
    pub fn routes(&self, uid: &InstanceUid) -> bool {
        self.routes.lock().expect("registry lock").contains_key(uid)
    }

    /// Releases every Agent a departing WebSocket peer carried, save those another downstream
    /// connection has claimed since.
    ///
    /// Nothing is sent upstream about it: a downstream Client that vanished said no goodbye, and
    /// this Gateway does not say one for it (ADR-0015 clause 10).
    pub fn detach_all(
        &self,
        uids: impl IntoIterator<Item = InstanceUid>,
        sink: &mpsc::Sender<ServerToAgent>,
    ) {
        let mut routes = self.routes.lock().expect("registry lock");
        for uid in uids {
            if matches!(
                routes.get(&uid).map(|route| &route.downstream),
                Some(Downstream::Socket(own)) if own.same_channel(sink)
            ) {
                routes.remove(&uid);
            }
        }
    }

    /// Hands one reply to whoever is waiting for that Agent, once the package cache has seen what
    /// it offers — so an artifact the Agent asks for next is already recorded as offered to its host
    /// (ADR-0026 clauses 42, 45).
    pub async fn deliver(&self, uid: InstanceUid, reply: ServerToAgent) {
        // Taken out under the lock, awaited outside it: a slow downstream peer must not hold the
        // routing table while every other Agent's replies queue behind it.
        let route = {
            let mut routes = self.routes.lock().expect("registry lock");
            let host = routes.get(&uid).and_then(|route| route.host.clone());
            let downstream = match routes.get(&uid).map(|route| &route.downstream) {
                Some(Downstream::Exchange(..)) => routes.remove(&uid).map(|route| route.downstream),
                Some(Downstream::Socket(sink)) => Some(Downstream::Socket(sink.clone())),
                None => None,
            };
            downstream.map(|downstream| (downstream, host))
        };
        let route = route.map(|(downstream, host)| {
            self.cache.observe(uid, host, &reply);
            downstream
        });
        match route {
            Some(Downstream::Socket(sink)) => {
                let _ = sink.send(reply).await;
            }
            Some(Downstream::Exchange(reply_to, _)) => {
                let _ = reply_to.send(reply);
            }
            None => debug!(agent = %uid, "dropping a Server message for an unknown Agent"),
        }
    }
}
