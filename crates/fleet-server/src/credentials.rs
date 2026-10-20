//! The Operator plane's credential check (ADR-0021 clause 2).
//!
//! Nothing configured authenticates on its own (ADR-0021 clause 26): a Basic password is kept as an
//! Argon2id hash and verified against it, and a success is remembered for a while by the hash of
//! the whole header, so a browser that re-sends the header with every request pays the password
//! hash once and not per request.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::{Algorithm, Argon2, Params, Version};
use axum::http::{header, HeaderMap};
use base64::Engine as _;
use sha2::{Digest, Sha256};

/// The least an Argon2id hash may cost: OWASP's minimum (`m=19456`, `t=2`, `p=1`).
pub const MIN_MEMORY_KIB: u32 = 19_456;
pub const MIN_ITERATIONS: u32 = 2;
pub const MIN_PARALLELISM: u32 = 1;

/// How long a successful Basic verification is remembered.
pub const REMEMBER_FOR: Duration = Duration::from_secs(600);

/// How many successful Basic verifications are remembered at once.
pub const REMEMBERED_MAX: usize = 1024;

/// How many password hashes one plane computes at once; past it a request is answered `503`, so a
/// flood of wrong passwords cannot take every worker thread.
pub const CONCURRENT_HASHES: usize = 4;

/// The shortest hash output and salt a Basic entry may carry, in bytes.
pub const MIN_OUTPUT_LEN: usize = 32;
pub const MIN_SALT_LEN: usize = 16;

/// What a check of a request comes to.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Permitted,
    Refused,
    /// Too many password hashes are being computed; try again shortly.
    Busy,
}

/// The configured credentials of the Operator plane, and the challenge a refusal carries.
pub struct Credentials {
    /// Every accepted Basic user and the Argon2id hash of its password.
    basic: BTreeMap<String, String>,
    /// SHA-256 of a Basic header that verified, and until when that holds.
    remembered: Mutex<HashMap<[u8; 32], Instant>>,
    /// Verified against for an unknown user, at the highest cost any user's hash has, so the
    /// answer's timing does not tell which users exist.
    dummy: String,
    hashing: Arc<tokio::sync::Semaphore>,
    /// The one password hash each peer address may have under way, an IPv6 one by its /64.
    in_flight: Mutex<HashMap<IpAddr, Arc<tokio::sync::Mutex<()>>>>,
    /// The `WWW-Authenticate` value a `401` answers with (RFC 9110).
    challenge: String,
}

impl Credentials {
    /// Credentials from entries [`check_basic`] accepted.
    ///
    /// # Errors
    /// Returns an error naming the first entry that is not a hash this Server keeps.
    pub fn new(basic: &BTreeMap<String, String>, challenge: String) -> Result<Self, String> {
        let mut costliest = Params::new(MIN_MEMORY_KIB, MIN_ITERATIONS, MIN_PARALLELISM, None)
            .map_err(|e| format!("cannot set Argon2 parameters: {e}"))?;
        for (user, phc) in basic {
            let params = check_basic(phc).map_err(|e| format!("user {user:?}: {e}"))?;
            if (params.m_cost(), params.t_cost(), params.p_cost())
                > (costliest.m_cost(), costliest.t_cost(), costliest.p_cost())
            {
                costliest = params;
            }
        }
        let dummy = if basic.is_empty() {
            String::new()
        } else {
            let mut secret = [0u8; 24];
            use ring::rand::SecureRandom as _;
            ring::rand::SystemRandom::new()
                .fill(&mut secret)
                .map_err(|_| "no secure random source".to_string())?;
            Argon2::new(Algorithm::Argon2id, Version::V0x13, costliest)
                .hash_password_with_salt(&secret, &salt()?)
                .map_err(|e| format!("cannot make the comparison hash: {e}"))?
                .to_string()
        };
        Ok(Credentials {
            basic: basic.clone(),
            remembered: Mutex::new(HashMap::new()),
            dummy,
            hashing: Arc::new(tokio::sync::Semaphore::new(CONCURRENT_HASHES)),
            in_flight: Mutex::new(HashMap::new()),
            challenge,
        })
    }

    pub fn challenge(&self) -> &str {
        &self.challenge
    }

    /// Checks a request's `Authorization` header. A password hash, when one is needed, runs on a
    /// blocking thread and at most [`CONCURRENT_HASHES`] at once; past that the answer is
    /// [`Verdict::Busy`]. One peer address — an IPv6 one by its /64 — has at most one hash under
    /// way: its next request waits for it rather than taking another slot, so wrong passwords from
    /// one address cannot hold every slot.
    pub async fn check(self: &Arc<Self>, peer: Option<IpAddr>, headers: &HeaderMap) -> Verdict {
        let presented = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string();
        let needs_hash = presented.starts_with("Basic ") && !self.is_remembered(&presented);
        if !needs_hash {
            return if self.verify(&presented) {
                Verdict::Permitted
            } else {
                Verdict::Refused
            };
        }
        let verdict = self.hash_in_turn(peer, presented).await;
        if let Some(peer) = peer {
            self.end_turn(peer);
        }
        verdict
    }

    async fn hash_in_turn(self: &Arc<Self>, peer: Option<IpAddr>, presented: String) -> Verdict {
        let turn = match peer {
            Some(peer) => Some(self.turn_of(peer).lock_owned().await),
            None => None,
        };
        // The hash this one waited for may have verified the same header.
        if self.is_remembered(&presented) {
            return Verdict::Permitted;
        }
        let Ok(permit) = self.hashing.clone().try_acquire_owned() else {
            return Verdict::Busy;
        };
        let this = self.clone();
        let verified = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _turn = turn;
            this.verify(&presented)
        })
        .await
        .unwrap_or(false);
        if verified {
            Verdict::Permitted
        } else {
            Verdict::Refused
        }
    }

    /// The turn a peer address waits for before it hashes. Turns nobody holds any more are
    /// dropped whenever a new address takes one, so a request cancelled mid-hash leaves nothing
    /// behind for long.
    fn turn_of(&self, peer: IpAddr) -> Arc<tokio::sync::Mutex<()>> {
        let key = crate::throttle::peer_key(peer);
        let mut in_flight = self.in_flight.lock().expect("credentials lock");
        if let Some(turn) = in_flight.get(&key) {
            return turn.clone();
        }
        in_flight.retain(|_, turn| Arc::strong_count(turn) > 1);
        in_flight.entry(key).or_default().clone()
    }

    /// Drops a peer address's turn once nobody holds or waits for it.
    fn end_turn(&self, peer: IpAddr) {
        let key = crate::throttle::peer_key(peer);
        let mut in_flight = self.in_flight.lock().expect("credentials lock");
        if in_flight
            .get(&key)
            .is_some_and(|turn| Arc::strong_count(turn) == 1)
        {
            in_flight.remove(&key);
        }
    }

    fn is_remembered(&self, header: &str) -> bool {
        self.remembers(&Sha256::digest(header.as_bytes()).into(), Instant::now())
    }

    /// Whether a success with this header hash is remembered and still holds. Compared in constant
    /// time, so a lookup never leaks how far a remembered hash matched.
    fn remembers(&self, key: &[u8; 32], now: Instant) -> bool {
        self.remembered
            .lock()
            .expect("credentials lock")
            .iter()
            .any(|(remembered, until)| {
                *until > now && constant_time_eq::constant_time_eq(remembered, key)
            })
    }

    /// Whether an `Authorization` value matches a configured Basic credential.
    #[must_use]
    pub fn verify(&self, authorization: &str) -> bool {
        authorization
            .strip_prefix("Basic ")
            .is_some_and(|encoded| self.verify_basic(authorization, encoded))
    }

    fn verify_basic(&self, header: &str, encoded: &str) -> bool {
        let key: [u8; 32] = Sha256::digest(header.as_bytes()).into();
        let now = Instant::now();
        if self.remembers(&key, now) {
            return true;
        }
        let Some((user, password)) = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .and_then(|text| {
                text.split_once(':')
                    .map(|(user, password)| (user.to_string(), password.to_string()))
            })
        else {
            return false;
        };
        let known = self.basic.get(&user);
        // An unknown user costs the same verification, so the answer's timing does not tell which
        // users exist.
        let phc = known.unwrap_or(&self.dummy);
        let verified = PasswordHash::new(phc).ok().is_some_and(|hash| {
            Argon2::default()
                .verify_password(password.as_bytes(), &hash)
                .is_ok()
        });
        if !(verified && known.is_some()) {
            return false;
        }
        let mut remembered = self.remembered.lock().expect("credentials lock");
        if remembered.len() >= REMEMBERED_MAX {
            remembered.retain(|_, until| *until > now);
            if remembered.len() >= REMEMBERED_MAX {
                if let Some(oldest) = remembered
                    .iter()
                    .min_by_key(|(_, until)| **until)
                    .map(|(key, _)| *key)
                {
                    remembered.remove(&oldest);
                }
            }
        }
        remembered.insert(key, now + REMEMBER_FOR);
        true
    }
}

/// A Basic entry as `server.toml` keeps it: an Argon2id PHC string at least as costly as OWASP's
/// minimum.
///
/// # Errors
/// Returns an error saying what the entry must be, never echoing it.
pub fn check_basic(phc: &str) -> Result<Params, String> {
    let refused = || {
        "is not an Argon2id hash — a password is never kept in clear; make the entry with \
         `server hash-credential --basic`"
            .to_string()
    };
    let hash = PasswordHash::new(phc).map_err(|_| refused())?;
    if hash.algorithm.as_str() != "argon2id" {
        return Err(refused());
    }
    let params = Params::try_from(&hash).map_err(|_| refused())?;
    if params.m_cost() < MIN_MEMORY_KIB
        || params.t_cost() < MIN_ITERATIONS
        || params.p_cost() < MIN_PARALLELISM
    {
        return Err(format!(
            "is an Argon2id hash cheaper than m={MIN_MEMORY_KIB}, t={MIN_ITERATIONS}, \
             p={MIN_PARALLELISM} — make it again with `server hash-credential --basic`"
        ));
    }
    let output = hash.hash.map_or(0, |output| output.len());
    let salt = hash.salt.map_or(0, |salt| salt.len());
    if output < MIN_OUTPUT_LEN || salt < MIN_SALT_LEN {
        return Err(format!(
            "is an Argon2id hash shorter than {MIN_OUTPUT_LEN} bytes or with a salt shorter than \
             {MIN_SALT_LEN} bytes — make it again with `server hash-credential --basic`"
        ));
    }
    Ok(params)
}

/// The entry `server.toml` keeps for a Basic password: Argon2id at OWASP's minimum cost.
///
/// # Errors
/// Returns an error when no salt can be drawn or the hash cannot be made.
pub fn hash_basic(password: &str) -> Result<String, String> {
    if password.is_empty() {
        return Err("a password must not be empty".to_string());
    }
    Ok(argon2id()
        .hash_password_with_salt(password.as_bytes(), &salt()?)
        .map_err(|e| format!("cannot hash the password: {e}"))?
        .to_string())
}

fn argon2id() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(MIN_MEMORY_KIB, MIN_ITERATIONS, MIN_PARALLELISM, None)
            .expect("OWASP's minimum is valid Argon2 parameters"),
    )
}

fn salt() -> Result<[u8; MIN_SALT_LEN], String> {
    use ring::rand::SecureRandom as _;
    let mut bytes = [0u8; MIN_SALT_LEN];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "no secure random source for a salt".to_string())?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, value.parse().expect("header"));
        headers
    }

    fn basic(user: &str, password: &str) -> String {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
        )
    }

    /// Verifies: ADR-0021
    #[test]
    fn a_basic_password_is_verified_against_its_argon2id_hash() {
        let phc = hash_basic("s3cret").expect("hash");
        assert!(phc.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{phc}");
        let users = BTreeMap::from([("ops".to_string(), phc)]);
        let credentials = Credentials::new(&users, "Basic".into()).expect("credentials");
        assert!(credentials.verify(&basic("ops", "s3cret")));
        assert!(!credentials.verify(&basic("ops", "wrong")));
    }

    /// Verifies: ADR-0021
    #[test]
    fn an_unknown_user_costs_the_same_verification() {
        let users = BTreeMap::from([("ops".to_string(), hash_basic("s3cret").expect("hash"))]);
        let credentials = Credentials::new(&users, "Basic".into()).expect("credentials");
        let started = Instant::now();
        assert!(!credentials.verify(&basic("ops", "wrong")));
        let known = started.elapsed();
        let started = Instant::now();
        assert!(!credentials.verify(&basic("nobody", "wrong")));
        let unknown = started.elapsed();
        assert!(
            unknown * 4 > known,
            "an unknown user answered far faster: {unknown:?} against {known:?}"
        );
        assert!(
            credentials.remembered.lock().expect("lock").is_empty(),
            "a failure is never remembered"
        );
    }

    /// Verifies: ADR-0021
    #[test]
    fn a_basic_verification_is_remembered_and_bounded() {
        let users = BTreeMap::from([("ops".to_string(), hash_basic("s3cret").expect("hash"))]);
        let credentials = Credentials::new(&users, "Basic".into()).expect("credentials");
        assert!(credentials.verify(&basic("ops", "s3cret")));
        let started = Instant::now();
        assert!(credentials.verify(&basic("ops", "s3cret")));
        assert!(
            started.elapsed() < Duration::from_millis(5),
            "a remembered success is answered without the hash"
        );
        {
            // A full table of other headers: the next success must make room, not grow it.
            let mut remembered = credentials.remembered.lock().expect("lock");
            remembered.clear();
            let far = Instant::now() + REMEMBER_FOR;
            for n in 0..REMEMBERED_MAX {
                let key: [u8; 32] = Sha256::digest(n.to_le_bytes()).into();
                remembered.insert(key, far);
            }
        }
        assert!(credentials.verify(&basic("ops", "s3cret")));
        assert!(credentials.remembered.lock().expect("lock").len() <= REMEMBERED_MAX);
    }

    #[test]
    fn a_cheap_or_foreign_hash_is_refused() {
        assert!(check_basic("s3cret").is_err());
        let cheap = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(1024, 1, 1, None).expect("params"),
        )
        .hash_password_with_salt(b"x", &salt().expect("salt"))
        .expect("hash")
        .to_string();
        assert!(check_basic(&cheap).expect_err("cheap").contains("cheaper"));
    }

    /// Password hashes run off the async workers and at most a few at once; past that a request
    /// is answered busy rather than queued behind them.
    /// Verifies: ADR-0021
    #[tokio::test]
    async fn password_hashes_are_bounded_and_off_the_async_workers() {
        let users = BTreeMap::from([("ops".to_string(), hash_basic("s3cret").expect("hash"))]);
        let credentials = Arc::new(Credentials::new(&users, "Basic".into()).expect("credentials"));
        assert_eq!(
            credentials
                .check(None, &header(&basic("ops", "s3cret")))
                .await,
            Verdict::Permitted
        );
        let held: Vec<_> = (0..CONCURRENT_HASHES)
            .map(|_| {
                credentials
                    .hashing
                    .clone()
                    .try_acquire_owned()
                    .expect("permit")
            })
            .collect();
        assert_eq!(
            credentials
                .check(None, &header(&basic("ops", "wrong")))
                .await,
            Verdict::Busy
        );
        assert_eq!(
            credentials
                .check(None, &header(&basic("ops", "s3cret")))
                .await,
            Verdict::Permitted,
            "a remembered success needs no hash"
        );
        drop(held);
        assert_eq!(
            credentials
                .check(None, &header(&basic("ops", "wrong")))
                .await,
            Verdict::Refused
        );
    }

    /// One address holds at most one password hash at a time: wrong passwords sent at once from
    /// it wait for each other, and an operator at another address still finds a slot.
    /// Verifies: ADR-0021
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn one_address_holds_one_password_hash_at_a_time() {
        let users = BTreeMap::from([("ops".to_string(), hash_basic("s3cret").expect("hash"))]);
        let credentials = Arc::new(Credentials::new(&users, "Basic".into()).expect("credentials"));
        // Two addresses of one IPv6 /64 are one address here, as the throttle counts them.
        let guesser = |n: u16| -> Option<IpAddr> {
            Some(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, n).into())
        };
        let guesses: Vec<_> = (0..u16::try_from(CONCURRENT_HASHES * 2).expect("fits"))
            .map(|n| {
                let credentials = credentials.clone();
                tokio::spawn(async move {
                    credentials
                        .check(guesser(n), &header(&basic("ops", "wrong")))
                        .await
                })
            })
            .collect();
        // Only to know the guesses are under way before the operator signs in; what is asserted
        // is the operator's answer.
        let deadline = Instant::now() + Duration::from_secs(10);
        while credentials.hashing.available_permits() == CONCURRENT_HASHES {
            assert!(Instant::now() < deadline, "no guess started");
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert_eq!(
            credentials
                .check(
                    Some("192.0.2.7".parse().expect("ip")),
                    &header(&basic("ops", "s3cret"))
                )
                .await,
            Verdict::Permitted,
            "the operator found every slot taken"
        );
        for guess in guesses {
            assert_eq!(guess.await.expect("task"), Verdict::Refused);
        }
        // That no turn outlives its hash is a matter of memory, which no interface shows.
        assert!(credentials.in_flight.lock().expect("lock").is_empty());
    }

    /// The comparison hash for an unknown user costs what the costliest user's hash costs.
    /// Verifies: ADR-0021
    #[test]
    fn the_comparison_hash_matches_the_costliest_user() {
        let costly = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(MIN_MEMORY_KIB * 2, 3, 1, None).expect("params"),
        )
        .hash_password_with_salt(b"s3cret", &salt().expect("salt"))
        .expect("hash")
        .to_string();
        let users = BTreeMap::from([("ops".to_string(), costly)]);
        let credentials = Credentials::new(&users, "Basic".into()).expect("credentials");
        let dummy = PasswordHash::new(&credentials.dummy).expect("phc");
        let params = Params::try_from(&dummy).expect("params");
        assert_eq!((params.m_cost(), params.t_cost()), (MIN_MEMORY_KIB * 2, 3));
    }

    #[test]
    fn a_short_output_is_refused() {
        let short = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(MIN_MEMORY_KIB, MIN_ITERATIONS, MIN_PARALLELISM, Some(16)).expect("params"),
        )
        .hash_password_with_salt(b"x", &salt().expect("salt"))
        .expect("hash")
        .to_string();
        assert!(check_basic(&short).expect_err("short").contains("shorter"));
    }

    #[test]
    fn a_short_salt_is_refused() {
        let short = argon2id()
            .hash_password_with_salt(b"x", &[7u8; MIN_SALT_LEN - 4])
            .expect("hash")
            .to_string();
        assert!(check_basic(&short).expect_err("short").contains("shorter"));
        let enough = argon2id()
            .hash_password_with_salt(b"x", &salt().expect("salt"))
            .expect("hash")
            .to_string();
        check_basic(&enough).expect("a salt of MIN_SALT_LEN bytes");
    }
}
