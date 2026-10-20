//! The upstream Connection Pool (ADR-0015): *m* WebSocket connections carrying *n* Agents.
//!
//! Two rules do the work. The pool **grows lazily** to its configured cap — a Gateway in front of
//! three Agents holds three connections, not ten — and an Agent is **stuck to its connection** by
//! `instance_uid` for as long as that connection lives. Nothing in the protocol requires the
//! stickiness; it keeps one Agent's `sequence_num` stream and its `ReportFullState` exchanges on a
//! single socket, which is what makes a fleet debuggable.
//!
//! The pool is WebSocket-only, and the configuration refuses anything else at startup: a polling
//! upstream could not carry the Server's pushes to the Agents behind the Gateway.
//!
//! Any live connection carries any downstream Agent: every one is opened with this Gateway's own
//! identity and nothing else, so nothing on it depends on the peer an Agent came through
//! (ADR-0015 clause 7).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use futures_util::{SinkExt, StreamExt};
use opamp::proto::{AgentToServer, ServerToAgent};
use opamp::uid::InstanceUid;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

use crate::config::ClientConfig;
use crate::gateway::registry::Registry;

/// One upstream connection: a sender into its writer task, and who rides it.
struct Upstream {
    outbound: mpsc::Sender<Vec<u8>>,
    /// The Agents assigned to this connection — the count least-connections balances on, and the
    /// set to re-home when it drops.
    carries: Vec<InstanceUid>,
    /// Cleared by the reader task when the socket is gone, so the next send re-homes instead of
    /// writing into a channel nobody drains.
    alive: Arc<AtomicBool>,
}

/// The pool, shared between the downstream connections that feed it.
pub struct Pool {
    inner: Mutex<Inner>,
    config: Arc<ClientConfig>,
    registry: Arc<Registry>,
    limit: usize,
}

struct Inner {
    connections: Vec<Upstream>,
    /// Which connection an Agent is stuck to, by index into `connections`.
    assigned: HashMap<InstanceUid, usize>,
}

impl Pool {
    pub fn new(config: Arc<ClientConfig>, registry: Arc<Registry>) -> Self {
        let limit = config.max_message_size_bytes;
        Pool {
            inner: Mutex::new(Inner {
                connections: Vec::new(),
                assigned: HashMap::new(),
            }),
            config,
            registry,
            limit,
        }
    }

    /// Forwards one report upstream on its Agent's connection, opening or re-homing as needed.
    ///
    /// The message is forwarded **unchanged** (ADR-0015): this encodes exactly what arrived.
    pub async fn forward(&self, uid: InstanceUid, report: &AgentToServer) -> Result<(), String> {
        let frame = opamp::frame::encode_within(report, self.limit)
            .map_err(|e| format!("cannot forward a report of {uid}: {e}"))?;

        // Two attempts: the assigned connection may have died between the last send and this one,
        // and re-homing is exactly what clause 9 of ADR-0015 asks for.
        let outbound = self.connection_for(uid).await?;
        if outbound.send(frame.clone()).await.is_ok() {
            return Ok(());
        }
        debug!(agent = %uid, "the upstream connection is gone; re-homing");
        self.forget_connection_of(uid);
        let outbound = self.connection_for(uid).await?;
        outbound
            .send(frame)
            .await
            .map_err(|e| format!("cannot forward a report of {uid}: {e}"))
    }

    /// The Agent's connection: the one it is stuck to while that lives, else the least-loaded one,
    /// else a new one while the cap allows.
    async fn connection_for(&self, uid: InstanceUid) -> Result<mpsc::Sender<Vec<u8>>, String> {
        {
            let mut inner = self.inner.lock().expect("pool lock");
            if let Some(&index) = inner.assigned.get(&uid) {
                if let Some(upstream) = inner.connections.get(index) {
                    if upstream.alive.load(Ordering::Relaxed) {
                        return Ok(upstream.outbound.clone());
                    }
                }
                // Gone: re-home.
                inner.assigned.remove(&uid);
                if let Some(upstream) = inner.connections.get_mut(index) {
                    upstream.carries.retain(|carried| *carried != uid);
                }
            }
            // Grow only when every existing connection already carries something, and only to the
            // cap: the pool costs what it uses (ADR-0015 clause 8).
            let live = inner
                .connections
                .iter()
                .filter(|c| c.alive.load(Ordering::Relaxed))
                .count();
            let at_cap = live >= self.limit_connections();
            let idle = inner
                .connections
                .iter()
                .enumerate()
                .filter(|(_, c)| c.alive.load(Ordering::Relaxed))
                .min_by_key(|(_, c)| c.carries.len());
            let reuse = match idle {
                Some((index, connection)) if connection.carries.is_empty() || at_cap => Some(index),
                _ => None,
            };
            if let Some(index) = reuse {
                inner.assigned.insert(uid, index);
                inner.connections[index].carries.push(uid);
                return Ok(inner.connections[index].outbound.clone());
            }
        }
        self.open(uid).await
    }

    fn limit_connections(&self) -> usize {
        self.config
            .gateway
            .as_ref()
            .map(|g| g.upstream_connections)
            .unwrap_or(1)
    }

    /// Opens one upstream connection and starts its reader and writer tasks.
    async fn open(&self, uid: InstanceUid) -> Result<mpsc::Sender<Vec<u8>>, String> {
        // This Gateway's own identity, and no `Authorization`: a downstream peer's is never
        // forwarded, and nothing is sent in its place (ADR-0015 clause 11, ADR-0021).
        let mut upstream = crate::transport::connection(&self.config)?;
        upstream.max_message_size = self.limit;
        let socket = upstream.connect_websocket().await?;

        let (mut sink, mut stream) = socket.split();
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
        let alive = Arc::new(AtomicBool::new(true));

        tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                if sink.send(Message::Binary(frame.into())).await.is_err() {
                    break;
                }
            }
            let _ = sink.close().await;
        });

        let registry = self.registry.clone();
        let limit = self.limit;
        let reader_alive = alive.clone();
        tokio::spawn(async move {
            while let Some(message) = stream.next().await {
                let payload = match message {
                    Ok(Message::Binary(payload)) => payload,
                    Ok(Message::Close(_)) | Err(_) => break,
                    Ok(_) => continue,
                };
                match opamp::frame::decode::<ServerToAgent>(&payload, limit) {
                    // Routing is by `instance_uid` alone (ADR-0015 clause 13): a message for an Agent
                    // this Gateway has never carried is dropped, never broadcast.
                    Ok(reply) => match InstanceUid::from_wire(&reply.instance_uid) {
                        Some(uid) => registry.deliver(uid, reply).await,
                        None => warn!("dropping a Server message with a malformed instance_uid"),
                    },
                    Err(e) => warn!(error = %e, "dropping an unreadable Server message"),
                }
            }
            reader_alive.store(false, Ordering::Relaxed);
            debug!("an upstream connection closed");
        });

        let mut inner = self.inner.lock().expect("pool lock");
        let upstream = Upstream {
            outbound: tx.clone(),
            carries: vec![uid],
            alive,
        };
        // A closed connection's place is taken rather than the list growing; what it still
        // carried re-homes on its next report.
        let index = match inner
            .connections
            .iter()
            .position(|c| !c.alive.load(Ordering::Relaxed))
        {
            Some(index) => {
                let stale = std::mem::replace(&mut inner.connections[index], upstream);
                for carried in stale.carries {
                    if inner.assigned.get(&carried) == Some(&index) {
                        inner.assigned.remove(&carried);
                    }
                }
                index
            }
            None => {
                inner.connections.push(upstream);
                inner.connections.len() - 1
            }
        };
        inner.assigned.insert(uid, index);
        info!(
            connections = inner.connections.len(),
            endpoint = %self.config.endpoint,
            "opened an upstream connection"
        );
        Ok(tx)
    }

    /// Drops an Agent's assignment so the next report re-homes it (ADR-0015 clause 9). Nothing is
    /// said upstream on its behalf: it never disconnected.
    fn forget_connection_of(&self, uid: InstanceUid) {
        let mut inner = self.inner.lock().expect("pool lock");
        if let Some(index) = inner.assigned.remove(&uid) {
            if let Some(connection) = inner.connections.get_mut(index) {
                connection.carries.retain(|carried| *carried != uid);
            }
        }
    }

    /// Releases the places of Agents no downstream connection carries any more, so a peer that
    /// keeps coming back under new `instance_uid`s grows nothing here. Nothing is said upstream on
    /// their behalf (ADR-0015 clause 10). The registry is asked under the pool's lock, so an Agent
    /// claimed again in between keeps the place its next report is forwarded on.
    pub fn release(&self, uids: impl IntoIterator<Item = InstanceUid>) {
        let mut inner = self.inner.lock().expect("pool lock");
        for uid in uids {
            if self.registry.routes(&uid) {
                continue;
            }
            if let Some(index) = inner.assigned.remove(&uid) {
                if let Some(connection) = inner.connections.get_mut(index) {
                    connection.carries.retain(|carried| *carried != uid);
                }
            }
        }
    }

    /// The Agents assigned to a connection, and how many entries the connections' `carries` hold.
    #[cfg(test)]
    pub(crate) fn assignments(&self) -> (std::collections::HashSet<InstanceUid>, usize) {
        let inner = self.inner.lock().expect("pool lock");
        (
            inner.assigned.keys().copied().collect(),
            inner.connections.iter().map(|c| c.carries.len()).sum(),
        )
    }
}
