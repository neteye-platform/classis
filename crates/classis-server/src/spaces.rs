//! The Spaces (ADR-0064 clause 1): what an operator's tooling and the enrolment route ask of the
//! Server about them, over the [`SpaceStore`] port.
//!
//! A Space has exactly one active enrolment key, `cle1_<space>_<secret>`, whose secret is made here
//! by the one generator of the OAuth crates ([`oauth_token::secret::generate`]). The key is stored
//! whole so it can be read again; reading it, enrolling a host or restarting the Server never
//! replaces it, and only [`Spaces::rotate`] does. Rotation makes the old key resolve to nothing and
//! touches no client: a client keeps the Space it enrolled in, and its token, after the key that
//! enrolled it is gone.
//!
//! The service holds no state beyond the port, so what one caller does through one [`Spaces`] is
//! what another sees through its own at once.

use std::fmt::Write as _;
use std::sync::{PoisonError, RwLock};

use classis_core::enrolment_key::{validate_space_name, EnrolmentKey};
use oauth_token::secret;
use zeroize::Zeroizing;

use crate::space_store::{SpaceRecord, SpaceStore};

/// Why an operation on a Space was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum SpaceError {
    /// The name is outside the pattern of ADR-0064 clause 1.
    InvalidName(String),
    /// A Space of that name — ignoring ASCII case — exists already.
    Exists,
    /// No Space has that name, spelt exactly so.
    NotFound,
    /// The store failed; the Space is as it was.
    Store(String),
}

impl std::fmt::Display for SpaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpaceError::InvalidName(why) => f.write_str(why),
            SpaceError::Exists => f.write_str("a space of that name exists, ignoring case"),
            SpaceError::NotFound => f.write_str("no such space"),
            SpaceError::Store(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for SpaceError {}

impl From<String> for SpaceError {
    fn from(why: String) -> Self {
        SpaceError::Store(why)
    }
}

/// The Spaces of one store.
pub struct Spaces {
    store: Box<dyn SpaceStore>,
    /// Held for writing by [`Spaces::rotate`] and for reading by [`Spaces::while_current`], so
    /// that once a rotation has returned, no registration that judged the old key current can
    /// still be stored, while registrations stay concurrent with one another. It guards no data:
    /// what it orders lives in the stores, so a panic that poisons it leaves nothing to repair and
    /// the guard is taken from a poisoned lock all the same.
    ///
    /// In-process is enough, and is the whole guarantee: the Server is a single process, which on
    /// PostgreSQL its advisory lock (ADR-0050 clause 6) makes so, and every rotation goes through
    /// the running Server's own [`Spaces`]. A process that rotated a key from outside it would not
    /// be ordered by this lock.
    rotation: RwLock<()>,
}

/// A fresh key of the Space `name`, in a buffer sized once and wiped when it is dropped.
fn new_key(name: &str) -> Zeroizing<String> {
    let secret = secret::generate();
    let key = EnrolmentKey::new(name, &secret).expect("a valid name and a generated secret");
    let mut text = Zeroizing::new(String::with_capacity(key.encoded_len()));
    write!(text, "{key}").expect("a string takes what is written to it");
    text
}

impl Spaces {
    /// The Spaces kept in `store`.
    #[must_use]
    pub fn new(store: Box<dyn SpaceStore>) -> Self {
        Spaces {
            store,
            rotation: RwLock::new(()),
        }
    }

    /// Creates the Space `name` with a new key, and returns the key. The name keeps the case it is
    /// given.
    ///
    /// # Errors
    /// [`SpaceError::InvalidName`] outside the pattern, [`SpaceError::Exists`] when a Space of that
    /// name ignoring ASCII case exists, [`SpaceError::Store`] when it cannot be written.
    pub fn create(&self, name: &str) -> Result<Zeroizing<String>, SpaceError> {
        validate_space_name(name).map_err(|e| SpaceError::InvalidName(e.to_string()))?;
        let space = SpaceRecord {
            name: name.to_string(),
            key: new_key(name),
        };
        if self.store.create(&space)? {
            Ok(space.key)
        } else {
            Err(SpaceError::Exists)
        }
    }

    /// The names of the Spaces, sorted. Never a key. The operator's commands of ADR-0065 call it;
    /// nothing in the Server does yet.
    ///
    /// # Errors
    /// [`SpaceError::Store`] when the Spaces cannot be read.
    pub fn list(&self) -> Result<Vec<String>, SpaceError> {
        Ok(self
            .store
            .load()?
            .into_iter()
            .map(|space| space.name)
            .collect())
    }

    /// The Space's key, as it was created or last rotated. Reading it changes nothing.
    ///
    /// # Errors
    /// [`SpaceError::NotFound`] for a name no Space has, spelt exactly so.
    pub fn key(&self, name: &str) -> Result<Zeroizing<String>, SpaceError> {
        self.store
            .get(name)?
            .map(|space| space.key)
            .ok_or(SpaceError::NotFound)
    }

    /// Replaces the Space's key with a new one, persisted before it is returned. The old key
    /// resolves to nothing from then on; the Space's clients and their tokens are untouched.
    ///
    /// # Errors
    /// [`SpaceError::NotFound`] for a name no Space has, spelt exactly so, and
    /// [`SpaceError::Store`] when the new key cannot be written, the old one then standing.
    pub fn rotate(&self, name: &str) -> Result<Zeroizing<String>, SpaceError> {
        validate_space_name(name).map_err(|_| SpaceError::NotFound)?;
        let key = new_key(name);
        let _rotating = self
            .rotation
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        if self.store.replace_key(name, &key)? {
            Ok(key)
        } else {
            Err(SpaceError::NotFound)
        }
    }

    /// Runs `act` only if `presented` is still the active key of the Space `space`, and returns
    /// its result; `None` when it is not. [`rotate`](Self::rotate) cannot land while `act` runs,
    /// so once a rotation has returned `act` has not been started under the old key: "the old key
    /// enrols nothing" (ADR-0064 clause 1) holds for what `act` stores, not only for what was
    /// checked before it. Calls of `while_current` do not wait for one another, only for a
    /// rotation that is running.
    ///
    /// # Errors
    /// Returns an error when the Spaces cannot be read.
    pub fn while_current<T>(
        &self,
        presented: &str,
        space: &str,
        act: impl FnOnce() -> T,
    ) -> Result<Option<T>, String> {
        let _held = self.rotation.read().unwrap_or_else(PoisonError::into_inner);
        match self.resolve(presented)? {
            Some(current) if current == space => Ok(Some(act())),
            _ => Ok(None),
        }
    }

    /// The name of the Space `presented` is the active key of; `None` for text that is no key,
    /// for a Space that is unknown or spelt differently in the key, and for a key that has been
    /// replaced. The secret is compared in time that does not depend on where it differs.
    ///
    /// # Errors
    /// Returns an error when the Spaces cannot be read.
    pub fn resolve(&self, presented: &str) -> Result<Option<String>, String> {
        let Ok(parsed) = EnrolmentKey::parse(presented) else {
            return Ok(None);
        };
        let Some(space) = self.store.get(parsed.space())? else {
            return Ok(None);
        };
        let stored = secret::hash(&space.key);
        Ok(secret::hashes_equal(&stored, &secret::hash(presented)).then_some(space.name))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;

    use oauth_registration::server::{NewClient, RegistrationStore as _};
    use oauth_token::server::{Lifetime, TokenStore as _};

    use super::*;
    use crate::client_store::{ActiveToken, ClientRecord, ClientStore, TokenReplaced};
    use crate::enrolment::Enrolment;
    use crate::fs::{FsClientStore, FsSpaceStore};
    use crate::throttle::{Limits, Throttle};

    /// A Space service and the client store beside it, both reopened by calling `open` again, which
    /// is what a Server restart does.
    pub(crate) type Open<'a> = &'a dyn Fn() -> (Spaces, Box<dyn ClientStore>);

    /// ADR-0064's server store tests, through the service: on either backend, a Space's complete
    /// key is recoverable after reopening; reading it, resolving it and enrolling a client leaves
    /// it unchanged; an explicit rotation persists a different key that survives reopening,
    /// resolves instead of the old one, and changes no client and no token.
    pub(crate) fn contract(open: Open<'_>) {
        let (spaces, clients) = open();
        assert_eq!(spaces.list().expect("list"), Vec::<String>::new());
        let prod = spaces.create("Prod_EU").expect("create");
        let lab = spaces.create("lab").expect("create");
        assert!(
            prod.starts_with("cle1_Prod_EU_"),
            "the case is kept in the key"
        );
        assert_eq!(prod.len(), "cle1_Prod_EU_".len() + 43);
        assert_ne!(*prod, *lab);

        // Names are unique ignoring case, and refusing one writes nothing.
        for clash in ["prod_eu", "PROD_EU", "Prod_eu"] {
            assert_eq!(spaces.create(clash).expect_err(clash), SpaceError::Exists);
        }
        assert_eq!(
            spaces.create("_bad").expect_err("invalid"),
            SpaceError::InvalidName(
                classis_core::enrolment_key::KeyError::InvalidSpace.to_string()
            )
        );
        assert_eq!(spaces.list().expect("list"), ["Prod_EU", "lab"]);

        // Reading the key does not change it, and neither does enrolling a host, which here goes
        // the way a host does: through the registration of the Agent plane, then a token request.
        assert_eq!(*spaces.key("Prod_EU").expect("key"), *prod);
        assert_eq!(
            spaces.resolve(&prod).expect("resolve").as_deref(),
            Some("Prod_EU")
        );
        let clock: Arc<dyn crate::fleet::Clock> = Arc::new(crate::clock::SystemClock);
        let enrolment = Enrolment::new(
            spaces,
            clients,
            Lifetime::Never,
            clock.clone(),
            Arc::new(Throttle::new(Limits::default(), clock)),
        );
        let grant = enrolment
            .authorise(&prod)
            .expect("authorise")
            .expect("the key is current");
        let enrolled = ClientRecord {
            client_id: "0192f0c4-7b1e-7d2a-9c3b-4a5d6e7f8091".to_string(),
            space: "Prod_EU".to_string(),
            secret_hash: [1; 32],
            issued_at: 1_790_000_001,
            token: None,
        };
        enrolment
            .register(
                &grant,
                NewClient {
                    client_id: enrolled.client_id.clone(),
                    client_secret_hash: enrolled.secret_hash,
                    client_id_issued_at: enrolled.issued_at,
                    metadata: oauth_registration::server::Metadata::REGISTERED,
                },
            )
            .expect("register")
            .expect("the key enrols");
        let token = ActiveToken {
            hash: oauth_token::secret::hash("a token"),
            expires_at: Some(2_000_000_000),
        };
        enrolment
            .replace_token(&enrolled.client_id, token.hash, token.expires_at)
            .expect("a token");
        assert_eq!(*enrolment.spaces().key("Prod_EU").expect("key"), *prod);

        // The key is recoverable after the stores are reopened.
        drop(enrolment);
        let (spaces, clients) = open();
        assert_eq!(*spaces.key("Prod_EU").expect("key"), *prod);
        assert_eq!(*spaces.key("lab").expect("key"), *lab);
        assert_eq!(
            spaces.resolve(&prod).expect("resolve").as_deref(),
            Some("Prod_EU")
        );

        // A key whose space part differs only in case resolves to nothing; so does one that is no
        // key, one of an unknown Space, and one whose secret is another's.
        let recased = prod.replacen("Prod_EU", "prod_eu", 1);
        assert_eq!(spaces.resolve(&recased).expect("resolve"), None);
        assert_eq!(
            spaces.key("prod_eu").expect_err("exact"),
            SpaceError::NotFound
        );
        assert_eq!(spaces.resolve("").expect("resolve"), None);
        assert_eq!(spaces.resolve("cle1_nobody_x").expect("resolve"), None);
        let unknown = prod.replacen("Prod_EU", "Other", 1);
        assert_eq!(spaces.resolve(&unknown).expect("resolve"), None);
        let crossed = format!("cle1_lab_{}", &prod[prod.len() - 43..]);
        assert_eq!(spaces.resolve(&crossed).expect("resolve"), None);
        let one_off = format!(
            "{}{}",
            &prod[..prod.len() - 1],
            if prod.ends_with('a') { 'b' } else { 'a' }
        );
        assert_eq!(spaces.resolve(&one_off).expect("resolve"), None);

        // Rotation persists a different key. The old key resolves to nothing, the new one to the
        // Space, and the other Space and the client are as they were.
        let rotated = spaces.rotate("Prod_EU").expect("rotate");
        assert_ne!(*rotated, *prod);
        assert!(rotated.starts_with("cle1_Prod_EU_"));
        assert_eq!(spaces.resolve(&prod).expect("resolve"), None);
        assert_eq!(
            spaces.resolve(&rotated).expect("resolve").as_deref(),
            Some("Prod_EU")
        );
        assert_eq!(*spaces.key("lab").expect("key"), *lab);
        assert_eq!(
            spaces.rotate("nowhere").expect_err("unknown"),
            SpaceError::NotFound
        );
        assert_eq!(
            spaces.rotate("prod_eu").expect_err("exact"),
            SpaceError::NotFound
        );
        assert_eq!(
            spaces.rotate("_").expect_err("invalid"),
            SpaceError::NotFound
        );

        drop((spaces, clients));
        let (spaces, clients) = open();
        assert_eq!(*spaces.key("Prod_EU").expect("key"), *rotated);
        assert_eq!(spaces.resolve(&prod).expect("resolve"), None);
        assert_eq!(
            spaces.resolve(&rotated).expect("resolve").as_deref(),
            Some("Prod_EU")
        );
        assert_eq!(
            clients.load().expect("load"),
            [{
                let mut held = enrolled.clone();
                held.token = Some(token);
                held
            }]
        );
        assert!(
            clients
                .find_by_token(&token.hash)
                .expect("find")
                .is_some_and(|admitted| admitted.client_id == enrolled.client_id),
            "the token of a client enrolled with the old key still admits"
        );
        assert_eq!(
            clients
                .replace_token(&enrolled.client_id, &token)
                .expect("replace"),
            TokenReplaced::Replaced {
                previous: Some(token.hash)
            }
        );
    }

    /// Verifies: ADR-0064
    #[test]
    fn the_space_service_keeps_its_key_and_rotates_it_on_request_on_the_filesystem() {
        let dir = tempfile::tempdir().expect("tempdir");
        contract(&|| {
            (
                Spaces::new(Box::new(FsSpaceStore::open(dir.path()).expect("open"))),
                Box::new(FsClientStore::open(dir.path()).expect("open")),
            )
        });
    }

    /// A rotation whose write fails leaves the old key in force, on either backend.
    pub(crate) fn rotation_fails_part_way(spaces: &Spaces, refuse: &dyn Fn(), mend: &dyn Fn()) {
        let key = spaces.create("prod").expect("create");
        refuse();
        assert!(matches!(
            spaces.rotate("prod").expect_err("the write fails"),
            SpaceError::Store(_)
        ));
        assert_eq!(*spaces.key("prod").expect("key"), *key);
        assert_eq!(
            spaces.resolve(&key).expect("resolve").as_deref(),
            Some("prod")
        );
        mend();
        let rotated = spaces.rotate("prod").expect("rotate");
        assert_ne!(*rotated, *key);
    }

    /// Verifies: ADR-0064
    #[test]
    fn a_failed_rotation_leaves_the_old_key_in_force_on_the_filesystem() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("spaces/prod.json");
        rotation_fails_part_way(
            &Spaces::new(Box::new(FsSpaceStore::open(dir.path()).expect("open"))),
            &|| crate::fs::testing::refuse(&file),
            &|| crate::fs::testing::mend(&file),
        );
    }

    /// Registrations do not wait for one another: two that judge the key current are both inside
    /// `while_current` at once. Each waits, with a bound, for the other to arrive; were they
    /// serialised the wait would end unmet.
    /// Verifies: ADR-0064
    #[test]
    fn two_registrations_proceed_concurrently_while_no_rotation_runs() {
        use std::sync::mpsc::channel;
        use std::time::Duration;
        let dir = tempfile::tempdir().expect("tempdir");
        let spaces = Arc::new(Spaces::new(Box::new(
            FsSpaceStore::open(dir.path()).expect("open"),
        )));
        let key = spaces.create("prod").expect("create");
        let (first_in, first_seen) = channel();
        let (second_in, second_seen) = channel();
        let register = |arrived: std::sync::mpsc::Sender<()>,
                        other: std::sync::mpsc::Receiver<()>| {
            let (spaces, key) = (spaces.clone(), key.clone());
            std::thread::spawn(move || {
                spaces
                    .while_current(&key, "prod", || {
                        arrived.send(()).expect("the test listens");
                        other.recv_timeout(Duration::from_secs(10)).is_ok()
                    })
                    .expect("read")
                    .expect("the key is current")
            })
        };
        let first = register(first_in, second_seen);
        let second = register(second_in, first_seen);
        assert!(first.join().expect("first"), "the second never arrived");
        assert!(second.join().expect("second"), "the first never arrived");
    }

    /// A store whose key replacement panics while it is armed.
    struct Panicking {
        inner: FsSpaceStore,
        armed: Arc<std::sync::atomic::AtomicBool>,
    }

    impl SpaceStore for Panicking {
        fn load(&self) -> Result<Vec<SpaceRecord>, String> {
            self.inner.load()
        }
        fn create(&self, space: &SpaceRecord) -> Result<bool, String> {
            self.inner.create(space)
        }
        fn get(&self, name: &str) -> Result<Option<SpaceRecord>, String> {
            self.inner.get(name)
        }
        fn replace_key(&self, name: &str, key: &str) -> Result<bool, String> {
            assert!(
                !self.armed.load(std::sync::atomic::Ordering::SeqCst),
                "the store panics"
            );
            self.inner.replace_key(name, key)
        }
    }

    /// One panic while a key is being replaced does not poison the rotation lock for good: the
    /// state it orders is in the stores, so later registrations and rotations run as before.
    /// Verifies: ADR-0064
    #[test]
    fn a_panic_under_the_rotation_lock_does_not_disable_enrolment_or_rotation() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let dir = tempfile::tempdir().expect("tempdir");
        let armed = Arc::new(AtomicBool::new(false));
        let spaces = Arc::new(Spaces::new(Box::new(Panicking {
            inner: FsSpaceStore::open(dir.path()).expect("open"),
            armed: armed.clone(),
        })));
        let key = spaces.create("prod").expect("create");

        armed.store(true, Ordering::SeqCst);
        let rotating = {
            let spaces = spaces.clone();
            std::thread::spawn(move || spaces.rotate("prod"))
        };
        assert!(rotating.join().is_err(), "the rotation panicked");
        armed.store(false, Ordering::SeqCst);
        assert!(spaces.rotation.is_poisoned(), "the lock is poisoned");

        assert_eq!(
            spaces.while_current(&key, "prod", || 7).expect("read"),
            Some(7),
            "the old key still stands, and still enrols"
        );
        let rotated = spaces.rotate("prod").expect("rotate");
        assert_eq!(
            spaces.while_current(&key, "prod", || 7).expect("read"),
            None
        );
        assert_eq!(
            spaces.while_current(&rotated, "prod", || 7).expect("read"),
            Some(7)
        );
    }

    /// An enrolment key is a secret held in a buffer wiped when it is dropped, whatever hands it
    /// on: were any of these to return or hold a plain `String` again, this would not compile.
    /// Verifies: ADR-0057
    #[test]
    fn an_enrolment_key_is_held_in_a_zeroizing_buffer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FsSpaceStore::open(dir.path()).expect("open");
        let spaces = Spaces::new(Box::new(store));
        let created: Zeroizing<String> = spaces.create("prod").expect("create");
        let read: Zeroizing<String> = spaces.key("prod").expect("key");
        let rotated: Zeroizing<String> = spaces.rotate("prod").expect("rotate");
        assert_ne!(created, rotated);
        assert_ne!(read, rotated);
        let held = FsSpaceStore::open(dir.path())
            .expect("open")
            .get("prod")
            .expect("get")
            .expect("a space");
        let _: &Zeroizing<String> = &held.key;
    }

    /// Verifies: ADR-0064
    #[test]
    fn a_key_is_never_shown_by_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let spaces = Spaces::new(Box::new(FsSpaceStore::open(dir.path()).expect("open")));
        let key = spaces.create("prod").expect("create");
        let secret = &key[key.len() - 43..];
        for error in [
            spaces.create("prod").expect_err("exists"),
            spaces.create("-").expect_err("invalid"),
            spaces.rotate("none").expect_err("unknown"),
        ] {
            assert!(!format!("{error} {error:?}").contains(secret));
        }
    }
}
