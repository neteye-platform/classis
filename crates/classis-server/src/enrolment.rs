//! Enrolment and admission on the Agent plane (ADR-0064 clauses 2 to 6): the glue between the two
//! OAuth crates, the Spaces and the clients' records.
//!
//! [`Enrolment`] is the one object behind `/v1/enrol`, `/v1/token` and the bearer admission of
//! `/v1/opamp` and the download route:
//!
//! - as a [`RegistrationStore`] it judges an enrolment key (a Space's *current* key, and the same
//!   key again at the moment the client is stored, so a rotation between the two steps refuses) and
//!   stores the client with its Space and the hash of its secret;
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
    throttle: Option<Arc<Throttle>>,
}

impl Enrolment {
    /// Enrolment over `spaces` and `clients`. A token lives `lifetime` (ADR-0064 clause 5), and
    /// one is expired when `clock` has reached its `expires_at`.
    #[must_use]
    pub fn new(
        spaces: Spaces,
        clients: Box<dyn ClientStore>,
        lifetime: Lifetime,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Enrolment {
            spaces,
            clients,
            clock,
            lifetime,
            sessions: Arc::new(Sessions::default()),
            throttle: None,
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
    ) -> Result<Self, String> {
        Ok(Self::new(
            Spaces::new(records.spaces()?),
            records.clients()?,
            lifetime,
            clock,
        ))
    }

    /// Counts every refused authentication of the Agent plane in `throttle` and answers a peer in
    /// back-off before anything else is checked (ADR-0064 clause 6). The table is the Agent
    /// plane's own: the Operator plane counts its failures in another.
    #[must_use]
    pub fn with_throttle(mut self, throttle: Arc<Throttle>) -> Self {
        self.throttle = Some(throttle);
        self
    }

    /// The Agent plane's back-off table, when one is armed.
    #[must_use]
    pub fn throttle(&self) -> Option<&Arc<Throttle>> {
        self.throttle.as_ref()
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
        // The key may have been rotated since `authorise`: a client is stored only under a key
        // that is still its Space's current one.
        match self.spaces.resolve(&grant.key) {
            Ok(Some(space)) if space == grant.space => {}
            Ok(_) => return Ok(None),
            Err(e) => {
                error!(event = "enrolment.failed", error = %e, "cannot read the Spaces");
                return Err(RegistrationError);
            }
        }
        let record = ClientRecord {
            client_id: client.client_id,
            space: grant.space.clone(),
            secret_hash: client.client_secret_hash,
            issued_at: client.client_id_issued_at,
            token: None,
        };
        match self.clients.insert(&record) {
            Ok(true) => {}
            Ok(false) => {
                error!(
                    event = "enrolment.failed",
                    "a client identifier was made twice"
                );
                return Err(RegistrationError);
            }
            Err(e) => {
                error!(event = "enrolment.failed", error = %e, "cannot store a client");
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
}
