//! Enrolment and admission on the Agent plane (ADR-0064 clauses 2 to 6): the glue between the two
//! OAuth crates, the Spaces and the clients' records.
//!
//! [`Enrolment`] is the one object behind `/v1/enrol`, `/v1/token` and the bearer admission of
//! `/v1/opamp` and the download route:
//!
//! - as a [`RegistrationStore`] it judges an enrolment key (a Space's *current* key, and the same
//!   key again, under the rotation lock, at the moment the client is stored, so a rotation between
//!   the two steps refuses) and stores the client with its Space and the hash of its secret;
//! - as a [`TokenStore`] it checks a client secret's hash and replaces the client's one token,
//!   which ends every WebSocket session admitted with the token before it ([`Sessions`]);
//! - [`admit`](Enrolment::admit) reads the Bearer credential of a request, hashes it, and asks the
//!   clients who holds it.
//!
//! The host an admitted request arrived over is the `client_id` of the client holding the token:
//! the Server derives it, a host never states one (clause 3).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::http::header::HeaderMap;
use axum::http::Uri;
use oauth_registration::server::{NewClient, RegistrationStore, StoreError as RegistrationError};
use oauth_token::bearer::{presented, Presented, Refusal};
use oauth_token::secret;
use oauth_token::server::{Lifetime, StoreError as TokenError, TokenStore};
use serde_json::{Map, Value};
use tokio::sync::watch;
use tracing::{error, info};
use zeroize::Zeroizing;

use crate::client_store::{ActiveToken, ClientRecord, ClientStore, Hash, TokenReplaced};
use crate::fleet::Clock;
use crate::spaces::Spaces;
use crate::throttle::Throttle;
use crate::Records;

/// Where a host registers (ADR-0064 clause 2).
pub const ENROL_PATH: &str = "/v1/enrol";

/// Where a host asks for its token (ADR-0064 clause 4).
pub const TOKEN_PATH: &str = "/v1/token";

/// The Bearer realm of every challenge the Agent plane sends (ADR-0064 clauses 2 and 6).
pub const REALM: &str = "fleet";

/// The Spaces, the clients and the token lifetime behind the Agent plane's three routes.
pub struct Enrolment {
    spaces: Spaces,
    clients: Box<dyn ClientStore>,
    clock: Arc<dyn Clock>,
    lifetime: Lifetime,
    sessions: Arc<Sessions>,
    throttle: Arc<Throttle>,
}

impl Enrolment {
    /// Enrolment over `spaces` and `clients`. A token lives `lifetime` (ADR-0064 clause 5), and
    /// one is expired when `clock` has reached its `expires_at`. Every refused authentication of
    /// the Agent plane is counted in `throttle`, and a peer in back-off is answered before
    /// anything else is checked (clause 6); the table is the Agent plane's own, the Operator
    /// plane counts its failures in another.
    #[must_use]
    pub fn new(
        spaces: Spaces,
        clients: Box<dyn ClientStore>,
        lifetime: Lifetime,
        clock: Arc<dyn Clock>,
        throttle: Arc<Throttle>,
    ) -> Self {
        Enrolment {
            spaces,
            clients,
            clock,
            lifetime,
            sessions: Arc::new(Sessions::default()),
            throttle,
        }
    }

    /// Enrolment over the Spaces and clients of `records`.
    ///
    /// # Errors
    /// Returns an error when either store cannot be opened.
    pub fn on(
        records: &Records,
        lifetime: Lifetime,
        clock: Arc<dyn Clock>,
        throttle: Arc<Throttle>,
    ) -> Result<Self, String> {
        Ok(Self::new(
            Spaces::new(records.spaces()?),
            records.clients()?,
            lifetime,
            clock,
            throttle,
        ))
    }

    /// The Agent plane's back-off table.
    #[must_use]
    pub fn throttle(&self) -> &Arc<Throttle> {
        &self.throttle
    }

    /// The lifetime a token is issued with.
    #[must_use]
    pub fn lifetime(&self) -> Lifetime {
        self.lifetime
    }

    /// The Spaces, for the tooling that creates them and reads their keys.
    #[must_use]
    pub fn spaces(&self) -> &Spaces {
        &self.spaces
    }

    fn now_secs(&self) -> u64 {
        self.clock.now_ms() / 1000
    }

    /// Admits a request by its Bearer credential (ADR-0064 clause 6): the token's hash must be a
    /// client's active token and must not have expired. `websocket` asks for a [`SessionWatch`],
    /// which ends when the token is replaced; it is made *before* the lookup, so a replacement
    /// that lands between the two is not missed.
    ///
    /// # Errors
    /// The refusal to answer with.
    pub async fn admit(
        self: &Arc<Self>,
        headers: &HeaderMap,
        uri: &Uri,
        websocket: bool,
    ) -> Result<Admitted, Refused> {
        let credential = presented(headers, uri);
        let check = match &credential {
            Presented::Absent => "absent",
            Presented::Unsupported => "scheme",
            Presented::InvalidToken => "malformed",
            Presented::InvalidRequest => "invalid_request",
            Presented::Token(_) => "token",
        };
        let token = credential
            .token()
            .map_err(|refusal| Refused::Challenge { refusal, check })?;
        let hash = secret::hash(token);
        let watch = websocket.then(|| self.sessions.watch(hash));
        let this = self.clone();
        let found = tokio::task::spawn_blocking(move || this.clients.find_by_token(&hash)).await;
        match found {
            Ok(Ok(Some(client))) => {
                if client
                    .expires_at
                    .is_some_and(|expires_at| self.now_secs() >= expires_at)
                {
                    return Err(Refused::Challenge {
                        refusal: Refusal::InvalidToken,
                        check: "expired",
                    });
                }
                Ok(Admitted {
                    client_id: client.client_id,
                    watch,
                })
            }
            Ok(Ok(None)) => Err(Refused::Challenge {
                refusal: Refusal::InvalidToken,
                check: "unknown",
            }),
            Ok(Err(e)) => {
                error!(event = "admission.failed", error = %e, "cannot look up a token");
                Err(Refused::Unavailable)
            }
            Err(e) => {
                error!(event = "admission.failed", error = %e, "the token lookup did not finish");
                Err(Refused::Unavailable)
            }
        }
    }
}

/// A request admitted: the client that holds its token.
pub struct Admitted {
    /// The host's identity (ADR-0064 clause 3).
    pub client_id: String,
    /// Present for a WebSocket upgrade: it ends when the token is replaced.
    pub watch: Option<SessionWatch>,
}

/// Why a request was not admitted.
#[derive(Debug)]
pub enum Refused {
    /// A Bearer challenge (RFC 6750 §3): which, and which check refused, for the log.
    Challenge {
        refusal: Refusal,
        check: &'static str,
    },
    /// The clients could not be read: not the peer's doing, and no challenge.
    Unavailable,
}

impl Refused {
    /// The check that refused, for the log; never the presented value.
    #[must_use]
    pub fn check(&self) -> &'static str {
        match self {
            Refused::Challenge { check, .. } => check,
            Refused::Unavailable => "store",
        }
    }

    /// The answer: `401` or `400` with its `WWW-Authenticate` challenge.
    #[must_use]
    pub fn into_response(self) -> axum::response::Response {
        use axum::http::{header, StatusCode};
        use axum::response::IntoResponse;
        match self {
            Refused::Challenge { refusal, .. } => {
                let mut response = refusal.status().into_response();
                if let Ok(challenge) = refusal.challenge(REALM) {
                    response
                        .headers_mut()
                        .insert(header::WWW_AUTHENTICATE, challenge);
                }
                response
            }
            Refused::Unavailable => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}

/// What an authorised enrolment key stands for between the two steps of a registration: the Space
/// it named, and the key itself, to be judged again when the client is stored.
pub struct Grant {
    space: String,
    key: Zeroizing<String>,
}

impl RegistrationStore for Enrolment {
    type Grant = Grant;

    fn authorise(&self, initial_access_token: &str) -> Result<Option<Grant>, RegistrationError> {
        match self.spaces.resolve(initial_access_token) {
            Ok(space) => Ok(space.map(|space| Grant {
                space,
                key: Zeroizing::new(initial_access_token.to_owned()),
            })),
            Err(e) => {
                error!(event = "enrolment.failed", error = %e, "cannot read the Spaces");
                Err(RegistrationError)
            }
        }
    }

    fn register(
        &self,
        grant: &Grant,
        client: NewClient,
    ) -> Result<Option<Map<String, Value>>, RegistrationError> {
        let record = ClientRecord {
            client_id: client.client_id,
            space: grant.space.clone(),
            secret_hash: client.client_secret_hash,
            issued_at: client.client_id_issued_at,
            token: None,
        };
        // The key may have been rotated since `authorise`: a client is stored only under a key
        // that is still its Space's current one, and a rotation cannot land between that check and
        // the store, so once a rotation has returned the old key has enrolled nothing more.
        let stored = self
            .spaces
            .while_current(&grant.key, &grant.space, || self.clients.insert(&record));
        match stored {
            Ok(Some(Ok(true))) => {}
            Ok(None) => return Ok(None),
            Ok(Some(Ok(false))) => {
                error!(
                    event = "enrolment.failed",
                    "a client identifier was made twice"
                );
                return Err(RegistrationError);
            }
            Ok(Some(Err(e))) => {
                error!(event = "enrolment.failed", error = %e, "cannot store a client");
                return Err(RegistrationError);
            }
            Err(e) => {
                error!(event = "enrolment.failed", error = %e, "cannot read the Spaces");
                return Err(RegistrationError);
            }
        }
        info!(
            event = "enrolment.registered",
            client = %record.client_id,
            space = %record.space,
            "a host enrolled"
        );
        let mut extension = Map::new();
        extension.insert("space".into(), Value::String(grant.space.clone()));
        Ok(Some(extension))
    }
}

impl TokenStore for Enrolment {
    fn client_secret_hash(&self, client_id: &str) -> Result<Option<Hash>, TokenError> {
        self.clients.secret_hash(client_id).map_err(|e| {
            error!(event = "token.failed", error = %e, "cannot read a client's secret");
            TokenError
        })
    }

    fn replace_token(
        &self,
        client_id: &str,
        token_hash: Hash,
        expires_at: Option<u64>,
    ) -> Result<(), TokenError> {
        let token = ActiveToken {
            hash: token_hash,
            expires_at,
        };
        match self.clients.replace_token(client_id, &token) {
            Ok(TokenReplaced::Replaced { previous }) => {
                // The overwrite is the revocation; sessions admitted with the old token end now.
                if let Some(previous) = previous {
                    self.sessions.replaced(&previous);
                }
                info!(
                    event = "token.issued",
                    client = client_id,
                    expires_at,
                    "issued a token"
                );
                Ok(())
            }
            Ok(TokenReplaced::NoSuchClient) => {
                error!(event = "token.failed", "the client of a token vanished");
                Err(TokenError)
            }
            Err(e) => {
                error!(event = "token.failed", error = %e, "cannot store a token");
                Err(TokenError)
            }
        }
    }
}

/// The WebSocket sessions admitted with each token, as far as it matters: when a token is
/// replaced, every session admitted with it hears so.
#[derive(Default)]
pub struct Sessions {
    watched: Mutex<HashMap<Hash, watch::Sender<bool>>>,
}

impl Sessions {
    /// A watch on `hash`: it fires when [`replaced`](Self::replaced) is told of that hash.
    fn watch(self: &Arc<Self>, hash: Hash) -> SessionWatch {
        let ended = self
            .watched
            .lock()
            .expect("sessions lock")
            .entry(hash)
            .or_insert_with(|| watch::channel(false).0)
            .subscribe();
        SessionWatch(Arc::new(Watching {
            sessions: self.clone(),
            hash,
            ended,
        }))
    }

    /// Tells every watch on `hash` that its token is gone.
    fn replaced(&self, hash: &Hash) {
        if let Some(sender) = self.watched.lock().expect("sessions lock").remove(hash) {
            sender.send_replace(true);
        }
    }
}

/// Ends when the token a WebSocket session was admitted with is replaced. Cheap to clone; the entry
/// in [`Sessions`] goes when the last clone does.
#[derive(Clone)]
pub struct SessionWatch(Arc<Watching>);

struct Watching {
    sessions: Arc<Sessions>,
    hash: Hash,
    ended: watch::Receiver<bool>,
}

impl Drop for Watching {
    fn drop(&mut self) {
        let mut watched = self.sessions.watched.lock().expect("sessions lock");
        // This watch's own receiver is still alive here, so one is the last.
        if watched
            .get(&self.hash)
            .is_some_and(|sender| sender.receiver_count() <= 1)
        {
            watched.remove(&self.hash);
        }
    }
}

impl SessionWatch {
    /// Resolves when the token is replaced; never otherwise.
    pub async fn replaced(&self) {
        let mut ended = self.0.ended.clone();
        if ended.wait_for(|replaced| *replaced).await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies: ADR-0064
    #[tokio::test]
    async fn a_watch_ends_when_its_token_is_replaced_and_only_then() {
        let sessions = Arc::new(Sessions::default());
        let watch = sessions.watch([1; 32]);
        let other = sessions.watch([2; 32]);
        sessions.replaced(&[1; 32]);
        tokio::time::timeout(std::time::Duration::from_secs(5), watch.replaced())
            .await
            .expect("the watch on the replaced token ends");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), other.replaced())
                .await
                .is_err(),
            "a watch on another token did not"
        );
    }

    /// Verifies: ADR-0064
    #[test]
    fn a_watch_leaves_no_entry_behind_once_dropped() {
        let sessions = Arc::new(Sessions::default());
        let first = sessions.watch([1; 32]);
        let second = first.clone();
        drop(first);
        assert_eq!(sessions.watched.lock().expect("lock").len(), 1);
        drop(second);
        assert!(sessions.watched.lock().expect("lock").is_empty());
        drop(sessions.watch([3; 32]));
        assert!(sessions.watched.lock().expect("lock").is_empty());
    }

    /// A client store whose `insert` stops in the middle until it is let go: the moment between
    /// the final check of the key and the store of the client, held open.
    struct Gate {
        inner: Box<dyn ClientStore>,
        entered: std::sync::mpsc::SyncSender<()>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
        /// Read as the insert finishes: has a rotation returned by then?
        rotated: Arc<std::sync::atomic::AtomicBool>,
        rotated_when_stored: Arc<std::sync::atomic::AtomicBool>,
    }

    impl ClientStore for Gate {
        fn load(&self) -> Result<Vec<ClientRecord>, String> {
            self.inner.load()
        }
        fn insert(&self, client: &ClientRecord) -> Result<bool, String> {
            self.entered.send(()).expect("the test listens");
            self.release
                .lock()
                .expect("release")
                .recv()
                .expect("the test lets go");
            self.rotated_when_stored.store(
                self.rotated.load(std::sync::atomic::Ordering::SeqCst),
                std::sync::atomic::Ordering::SeqCst,
            );
            self.inner.insert(client)
        }
        fn secret_hash(&self, client_id: &str) -> Result<Option<Hash>, String> {
            self.inner.secret_hash(client_id)
        }
        fn replace_token(
            &self,
            client_id: &str,
            token: &ActiveToken,
        ) -> Result<TokenReplaced, String> {
            self.inner.replace_token(client_id, token)
        }
        fn find_by_token(
            &self,
            token_hash: &Hash,
        ) -> Result<Option<crate::client_store::Admitted>, String> {
            self.inner.find_by_token(token_hash)
        }
    }

    fn new_client() -> NewClient {
        NewClient {
            client_id: "0192f0c4-7b1e-7d2a-9c3b-4a5d6e7f8091".to_string(),
            client_secret_hash: [7; 32],
            client_id_issued_at: 1_790_000_000,
            metadata: oauth_registration::server::Metadata::REGISTERED,
        }
    }

    fn enrolment_over(dir: &std::path::Path, clients: Box<dyn ClientStore>) -> Arc<Enrolment> {
        let clock: Arc<dyn Clock> = Arc::new(crate::clock::SystemClock);
        Arc::new(Enrolment::new(
            Spaces::new(Box::new(
                crate::fs::FsSpaceStore::open(dir).expect("the spaces"),
            )),
            clients,
            Lifetime::Never,
            clock.clone(),
            Arc::new(Throttle::new(crate::throttle::Limits::default(), clock)),
        ))
    }

    /// Once `rotate` has returned, the old key has enrolled nothing: a rotation that arrives while
    /// a registration under the old key is between its final check and the store of its client
    /// waits for it, so a client is never stored after the rotation that made its key stale
    /// returned.
    /// Verifies: ADR-0064
    #[test]
    fn a_rotation_waits_for_the_registration_that_is_storing_its_client() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let dir = tempfile::tempdir().expect("tempdir");
        crate::fs::open_data_dir(dir.path(), true).expect("the data directory");
        let (entered_tx, entered) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release) = std::sync::mpsc::channel();
        let rotated = Arc::new(AtomicBool::new(false));
        let rotated_when_stored = Arc::new(AtomicBool::new(true));
        let gate = Gate {
            inner: Box::new(crate::fs::FsClientStore::open(dir.path()).expect("the clients")),
            entered: entered_tx,
            release: Mutex::new(release),
            rotated: rotated.clone(),
            rotated_when_stored: rotated_when_stored.clone(),
        };
        let enrolment = enrolment_over(dir.path(), Box::new(gate));
        let old_key = enrolment.spaces().create("lab").expect("a space");
        let grant = enrolment
            .authorise(&old_key)
            .expect("authorise")
            .expect("the key is current");

        let registering = {
            let enrolment = enrolment.clone();
            std::thread::spawn(move || enrolment.register(&grant, new_client()))
        };
        entered.recv().expect("the registration reaches the store");
        let (rotation_tx, rotation_done) = std::sync::mpsc::channel();
        let rotating = {
            let enrolment = enrolment.clone();
            let rotated = rotated.clone();
            std::thread::spawn(move || {
                let key = enrolment.spaces().rotate("lab").expect("rotate");
                rotated.store(true, Ordering::SeqCst);
                rotation_tx.send(()).expect("the test listens");
                key
            })
        };
        // Given every chance to return, the rotation does not while the client is being stored.
        let returned_early = rotation_done
            .recv_timeout(std::time::Duration::from_millis(300))
            .is_ok();
        release_tx.send(()).expect("let the store go");
        let registered = registering.join().expect("registering");
        rotating.join().expect("rotating");

        assert!(
            !returned_early && !rotated_when_stored.load(Ordering::SeqCst),
            "a rotation returned while a client was being stored under the old key"
        );
        assert!(registered.expect("registered").is_some());
        // The rotation came after the registration, and the old key enrols nothing from here on.
        assert_eq!(enrolment.spaces().resolve(&old_key).expect("resolve"), None);
    }

    /// A registration that judged its key current and finds it rotated when it comes to store its
    /// client is refused, and stores nothing.
    /// Verifies: ADR-0064
    #[test]
    fn a_registration_whose_key_was_rotated_meanwhile_stores_no_client() {
        let dir = tempfile::tempdir().expect("tempdir");
        crate::fs::open_data_dir(dir.path(), true).expect("the data directory");
        let clients = crate::fs::FsClientStore::open(dir.path()).expect("the clients");
        let enrolment = enrolment_over(dir.path(), Box::new(clients));
        let old_key = enrolment.spaces().create("lab").expect("a space");
        let grant = enrolment
            .authorise(&old_key)
            .expect("authorise")
            .expect("the key is current");
        enrolment.spaces().rotate("lab").expect("rotate");

        assert!(enrolment
            .register(&grant, new_client())
            .expect("register")
            .is_none());
        assert_eq!(
            crate::fs::FsClientStore::open(dir.path())
                .expect("the clients")
                .load()
                .expect("load"),
            []
        );
    }
}
