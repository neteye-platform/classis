//! Artifact bytes in one bucket of an S3-compatible object store (ADR-0049): the second adapter
//! behind [`BlobStore`](crate::blobs::BlobStore), beside the filesystem's.
//!
//! The port is synchronous and `object_store` is not, so the adapter bridges inside itself
//! (ADR-0049 clause 1) through a [`Bridge`]: a small Tokio runtime of its own, onto which every
//! operation is spawned while the calling thread waits on a plain channel. The callers stay as they
//! are — the upload and the download stream run on blocking threads, the rest on whatever thread
//! calls.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use futures_util::{StreamExt as _, TryStreamExt as _};
use object_store::aws::{AmazonS3, AmazonS3Builder, AmazonS3ConfigKey};
use object_store::client::{HttpClient, HttpConnector};
use object_store::path::Path as Key;
use object_store::{
    BackoffConfig, ClientConfigKey, ClientOptions, ObjectStore, ObjectStoreExt as _, PutPayload,
    RetryConfig,
};
use sha2::{Digest, Sha256};

use crate::blobs::{is_hash, BlobStore};
use crate::bridge::Bridge;
use crate::config::S3BlobsConfig;

/// The bytes of one part of a multipart upload. S3 takes no part below 5 MiB but the last, so an
/// upload holds this much in memory while it is streamed.
const PART_SIZE: usize = 8 * 1024 * 1024;

/// The only `AWS_*` variables the Server reads (ADR-0049 clause 6): those of its platform's
/// workload identity, each with the setting it feeds. None of them names an endpoint, a bucket, a
/// region or whether plaintext is allowed.
const WORKLOAD_IDENTITY: [(&str, AmazonS3ConfigKey); 5] = [
    (
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        AmazonS3ConfigKey::WebIdentityTokenFile,
    ),
    ("AWS_ROLE_ARN", AmazonS3ConfigKey::RoleArn),
    (
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        AmazonS3ConfigKey::ContainerCredentialsRelativeUri,
    ),
    (
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        AmazonS3ConfigKey::ContainerCredentialsFullUri,
    ),
    // EKS Pod Identity: the token that goes with the full URI above.
    (
        "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
        AmazonS3ConfigKey::ContainerAuthorizationTokenFile,
    ),
];

/// How long an S3 request may wait (ADR-0049 clause 5), so a store that stops answering fails the
/// one call that needs it instead of holding it — and whatever lock its caller holds — forever.
#[derive(Clone, Copy, Debug)]
struct Limits {
    /// A connection, TLS included.
    connect: Duration,
    /// Silence: from the request until its answer begins — the upload of one part included —
    /// and then between two pieces of the answer, so a download of any size runs as long as
    /// bytes keep coming.
    silence: Duration,
    /// Retries of a request that failed or fell silent, and how long after the first attempt
    /// one may still start.
    retries: usize,
    retry_for: Duration,
}

/// The limits the Server runs with: a stalled store fails a call within about two minutes at
/// most — the last retry's silence after `retry_for` — and a single silent request within 30
/// seconds.
const LIMITS: Limits = Limits {
    connect: Duration::from_secs(10),
    silence: Duration::from_secs(30),
    retries: 2,
    retry_for: Duration::from_secs(60),
};

/// One object per blob at `<prefix>blobs/<sha256>`, an upload in progress at
/// `<prefix>staging/<random>`, and no key outside `<prefix>` (ADR-0049 clause 4).
pub struct S3BlobStore {
    store: Arc<AmazonS3>,
    bucket: String,
    /// Empty, or ending in `/` ([`S3BlobsConfig`] checks it).
    prefix: String,
    bridge: Arc<Bridge>,
}

impl S3BlobStore {
    /// Connects to the bucket `config` names and checks that it can be listed. Nothing is created:
    /// a bucket that does not exist fails here, naming it (ADR-0049 clause 4).
    ///
    /// # Errors
    /// Returns an error naming the key when the secret or the CA file cannot be read, and naming
    /// the bucket when it does not exist or cannot be listed.
    pub fn open(config: &S3BlobsConfig) -> Result<Self, String> {
        Self::open_within(config, LIMITS)
    }

    /// [`open`](Self::open) with `limits` rather than [`LIMITS`]: what the tests of a store that
    /// stops answering wait for.
    fn open_within(config: &S3BlobsConfig, limits: Limits) -> Result<Self, String> {
        let builder = builder(config, &|name| std::env::var(name).ok(), limits)?;
        let store = builder
            .build()
            .map_err(|e| format!("[blobs.s3]: cannot build the S3 client: {e}"))?;
        let s3 = S3BlobStore {
            store: Arc::new(store),
            bucket: config.bucket.clone(),
            prefix: config.prefix.clone(),
            bridge: Arc::new(Bridge::new("blobs-s3")?),
        };
        let root = s3.root();
        let store = s3.store.clone();
        s3.bridge
            .run(async move { store.list_with_delimiter(root.as_ref()).await })
            .map_err(|e| {
                format!(
                    "[blobs.s3] bucket {}: it does not exist or cannot be listed: {e}",
                    s3.bucket
                )
            })?;
        tracing::info!(
            endpoint = %config.endpoint,
            bucket = %s3.bucket,
            prefix = %s3.prefix,
            "keeping the package artifacts in an S3 bucket"
        );
        Ok(s3)
    }

    /// `<prefix>` as a key, `None` for the whole bucket.
    fn root(&self) -> Option<Key> {
        let prefix = self.prefix.trim_end_matches('/');
        (!prefix.is_empty()).then(|| Key::from(prefix))
    }

    fn blob_key(&self, sha256: &str) -> Result<Key, String> {
        if !is_hash(sha256) {
            return Err(format!("{sha256:?} is not the SHA-256 of a blob"));
        }
        Key::parse(format!("{}blobs/{sha256}", self.prefix)).map_err(|e| e.to_string())
    }

    fn staging_key(&self) -> Result<Key, String> {
        let mut random = [0u8; 16];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut random)
            .map_err(|_| "no randomness for a staging key".to_string())?;
        Key::parse(format!("{}staging/{}", self.prefix, hex::encode(random)))
            .map_err(|e| e.to_string())
    }

    /// What a key under `<prefix>` is: a blob, a staging object, or neither.
    fn classify(&self, key: &str) -> Kind {
        let Some(rest) = key.strip_prefix(&self.prefix) else {
            return Kind::Unknown;
        };
        if let Some(name) = rest.strip_prefix("blobs/") {
            if is_hash(name) {
                return Kind::Blob(name.to_string());
            }
        } else if rest.starts_with("staging/") {
            return Kind::Staging;
        }
        Kind::Unknown
    }

    fn delete_key(&self, key: Key) -> Result<(), String> {
        let store = self.store.clone();
        let named = key.to_string();
        match self.bridge.run(async move { store.delete(&key).await }) {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(e) => Err(format!(
                "cannot delete {named} in bucket {}: {e}",
                self.bucket
            )),
        }
    }

    /// Streams `bytes` into a multipart upload at `staging`, hashing them on the way, and answers
    /// their hash and size. A stream that fails aborts the upload, so nothing is left of it.
    fn stage(&self, staging: &Key, bytes: &mut dyn Read) -> Result<(String, u64), String> {
        let store = self.store.clone();
        let key = staging.clone();
        let mut upload = self
            .bridge
            .run(async move { store.put_multipart(&key).await })
            .map_err(|e| format!("cannot start an upload to bucket {}: {e}", self.bucket))?;
        let mut hasher = Sha256::new();
        let mut size = 0u64;
        let streamed = loop {
            let part = match read_part(bytes) {
                Ok(part) => part,
                Err(e) => break Err(format!("the upload failed: {e}")),
            };
            if part.is_empty() {
                break Ok(());
            }
            hasher.update(&part);
            size += part.len() as u64;
            let last = part.len() < PART_SIZE;
            let sent = upload.put_part(PutPayload::from(part));
            if let Err(e) = self.bridge.run(sent) {
                break Err(format!("cannot upload to bucket {}: {e}", self.bucket));
            }
            if last {
                break Ok(());
            }
        };
        let (upload, result) = match streamed {
            Ok(()) => {
                let (upload, completed) = self.bridge.run(async move {
                    let completed = upload.complete().await;
                    (upload, completed)
                });
                (
                    upload,
                    completed.map(|_| ()).map_err(|e| {
                        format!("cannot complete an upload to bucket {}: {e}", self.bucket)
                    }),
                )
            }
            Err(e) => (upload, Err(e)),
        };
        if result.is_err() {
            // Neither the parts nor the staging object outlive a failed stream.
            let mut upload = upload;
            let _ = self.bridge.run(async move { upload.abort().await });
        }
        result.map(|()| (hex::encode(hasher.finalize()), size))
    }
}

/// A key under `<prefix>`, as [`S3BlobStore::classify`] reads it.
enum Kind {
    Blob(String),
    Staging,
    Unknown,
}

impl BlobStore for S3BlobStore {
    /// The upload goes to a staging key; once its hash is known it is copied to its blob's key
    /// unless that is stored already, and the staging object is deleted (ADR-0049 clause 4). A
    /// stream that fails leaves no object under `blobs/`.
    fn put(&self, bytes: &mut dyn Read) -> Result<(String, u64), String> {
        let staging = self.staging_key()?;
        let (sha256, size) = self.stage(&staging, bytes)?;
        let copied = self.blob_key(&sha256).and_then(|blob| {
            if self.exists(&sha256)? {
                // The same bytes are stored already: once is enough.
                return Ok(());
            }
            let store = self.store.clone();
            let from = staging.clone();
            self.bridge
                .run(async move { store.copy(&from, &blob).await })
                .map_err(|e| format!("cannot store blob {sha256} in bucket {}: {e}", self.bucket))
        });
        let removed = self.delete_key(staging);
        copied?;
        if let Err(e) = removed {
            // The blob is stored; the next startup deletes what is left under staging/.
            tracing::warn!(error = %e, "cannot delete an upload's staging object");
        }
        Ok((sha256, size))
    }

    fn get(&self, sha256: &str) -> Result<Box<dyn Read + Send>, String> {
        let key = self.blob_key(sha256)?;
        let store = self.store.clone();
        let result = self
            .bridge
            .run(async move { store.get(&key).await })
            .map_err(|e| format!("cannot read blob {sha256} from bucket {}: {e}", self.bucket))?;
        Ok(Box::new(ObjectReader {
            stream: Some(result.into_stream()),
            current: Bytes::new(),
            bridge: self.bridge.clone(),
        }))
    }

    fn exists(&self, sha256: &str) -> Result<bool, String> {
        let Ok(key) = self.blob_key(sha256) else {
            return Ok(false);
        };
        let store = self.store.clone();
        match self.bridge.run(async move { store.head(&key).await }) {
            Ok(_) => Ok(true),
            Err(object_store::Error::NotFound { .. }) => Ok(false),
            Err(e) => Err(format!(
                "cannot ask bucket {} for blob {sha256}: {e}",
                self.bucket
            )),
        }
    }

    fn delete(&self, sha256: &str) -> Result<(), String> {
        self.delete_key(self.blob_key(sha256)?)
    }

    /// Every blob with its size, from the listing alone: nothing is downloaded (ADR-0049 clause 4).
    /// A staging object an interrupted upload left is deleted; any other key under `<prefix>`
    /// fails, naming it.
    fn list(&self) -> Result<Vec<(String, u64)>, String> {
        let store = self.store.clone();
        let root = self.root();
        let objects = self
            .bridge
            .run(async move { store.list(root.as_ref()).try_collect::<Vec<_>>().await })
            .map_err(|e| format!("cannot list bucket {}: {e}", self.bucket))?;
        let mut blobs = BTreeMap::new();
        for object in objects {
            let key = object.location.to_string();
            match self.classify(&key) {
                Kind::Blob(sha256) => {
                    blobs.insert(sha256, object.size);
                }
                Kind::Staging => self.delete_key(object.location)?,
                Kind::Unknown => {
                    return Err(format!(
                        "{key} in bucket {} is not part of the store's layout — the Server keeps \
                         only <prefix>blobs/<sha256> and <prefix>staging/ under [blobs.s3] prefix \
                         {:?}; move it out of the prefix",
                        self.bucket, self.prefix
                    ))
                }
            }
        }
        Ok(blobs.into_iter().collect())
    }
}

/// Fills one part: up to [`PART_SIZE`] bytes, fewer only at the end of the stream.
fn read_part(bytes: &mut dyn Read) -> std::io::Result<Vec<u8>> {
    let mut part = vec![0u8; PART_SIZE];
    let mut filled = 0;
    while filled < PART_SIZE {
        match bytes.read(&mut part[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    part.truncate(filled);
    Ok(part)
}

/// An object's bytes as the port hands them out: each chunk of the response fetched on the
/// adapter's runtime when the reader asks for it.
struct ObjectReader {
    stream: Option<futures_util::stream::BoxStream<'static, object_store::Result<Bytes>>>,
    current: Bytes,
    bridge: Arc<Bridge>,
}

impl Read for ObjectReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while self.current.is_empty() {
            let Some(mut stream) = self.stream.take() else {
                return Ok(0);
            };
            let (stream, next) = self.bridge.run(async move {
                let next = stream.next().await;
                (stream, next)
            });
            match next {
                None => return Ok(0),
                Some(Ok(chunk)) => {
                    self.current = chunk;
                    self.stream = Some(stream);
                }
                Some(Err(e)) => return Err(std::io::Error::other(e)),
            }
        }
        let n = buf.len().min(self.current.len());
        buf[..n].copy_from_slice(&self.current.split_to(n));
        Ok(n)
    }
}

/// The S3 client for `config`, with the credentials of clause 6 and the HTTP client of clause 5.
/// `variable` reads the environment, and is asked for the names of [`WORKLOAD_IDENTITY`] alone.
fn builder(
    config: &S3BlobsConfig,
    variable: &dyn Fn(&str) -> Option<String>,
    limits: Limits,
) -> Result<AmazonS3Builder, String> {
    let mut builder = AmazonS3Builder::new()
        .with_endpoint(config.endpoint.clone())
        .with_bucket_name(config.bucket.clone())
        .with_region(config.region.clone())
        .with_allow_http(config.allows_http())
        .with_retry(RetryConfig {
            backoff: BackoffConfig::default(),
            max_retries: limits.retries,
            retry_timeout: limits.retry_for,
        })
        .with_http_connector(TlsConnector::new(config.ca_file.as_deref(), limits)?);
    match (&config.access_key_id, &config.secret_access_key_file) {
        (Some(key_id), Some(file)) => {
            let secret =
                crate::config::read_secret_file("[blobs.s3] secret_access_key_file", file)?;
            // `object_store` takes the key as its own `String`: the copy is made at this call, and
            // the one read is wiped when it is dropped (ADR-0057 clauses 3 and 4).
            builder = builder
                .with_access_key_id(key_id.clone())
                .with_secret_access_key(secret.as_str());
        }
        _ => {
            for (name, key) in WORKLOAD_IDENTITY {
                if let Some(value) = variable(name) {
                    builder = builder.with_config(key, value);
                }
            }
        }
    }
    Ok(builder)
}

/// The HTTP client `object_store` is handed: the project's TLS 1.3, *ring*-only configuration with
/// the public roots and the optional `ca_file` root (ADR-0049 clause 5). Plaintext only where the
/// client's own options allow it: the loopback endpoint `[blobs.s3]` checked, and the platform's
/// credential endpoints on their link-local addresses. No proxy and no other setting is taken from
/// the environment.
///
/// The client is built here, so `object_store`'s own timeouts in its `ClientOptions` never reach
/// it: the timeouts of [`Limits`] are set on it instead.
#[derive(Debug)]
struct TlsConnector {
    tls: rustls::ClientConfig,
    limits: Limits,
}

impl TlsConnector {
    fn new(ca_file: Option<&Path>, limits: Limits) -> Result<Self, String> {
        let mut roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        if let Some(path) = ca_file {
            let pem = std::fs::read(path)
                .map_err(|e| format!("[blobs.s3] ca_file {}: {e}", path.display()))?;
            for certificate in opamp::tls::certificates(&pem)
                .map_err(|e| format!("[blobs.s3] ca_file {}: {e}", path.display()))?
            {
                roots
                    .add(certificate)
                    .map_err(|e| format!("[blobs.s3] ca_file {}: {e}", path.display()))?;
            }
        }
        let tls = opamp::tls::client_builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(TlsConnector { tls, limits })
    }
}

impl HttpConnector for TlsConnector {
    fn connect(&self, options: &ClientOptions) -> object_store::Result<HttpClient> {
        let allow_http = options
            .get_config_value(&ClientConfigKey::AllowHttp)
            .is_some_and(|value| value == "true");
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(self.tls.clone())
            .https_only(!allow_http)
            .no_proxy()
            // A compressed response would not be the bytes its `Content-Length` counts.
            .no_gzip()
            .connect_timeout(self.limits.connect)
            // reqwest's read timeout runs from the request until its answer begins and then
            // again between two chunks of the answer.
            .read_timeout(self.limits.silence)
            .build()
            .map_err(|e| object_store::Error::Generic {
                store: "S3",
                source: Box::new(e),
            })?;
        Ok(HttpClient::new(client))
    }
}

/// Copies what the bucket lacks from `data_dir/blobs/` (ADR-0049 clause 7): every blob of
/// `referenced` that `store` does not hold and `dir` does, hashed again on the way — a file whose
/// content does not match its name fails, naming it — and uploaded as `put` does. Each is logged.
/// `dir` is only read: removing it is the operator's.
///
/// # Errors
/// Returns an error naming the file when it cannot be read or does not match its name, or when
/// the upload fails.
pub fn copy_from_filesystem<'a>(
    dir: &Path,
    referenced: impl IntoIterator<Item = &'a str>,
    store: &dyn BlobStore,
) -> Result<(), String> {
    for sha256 in referenced {
        let path = dir.join(sha256);
        if !is_hash(sha256) || !path.is_file() || store.exists(sha256)? {
            // Not there to copy: the package store names the entry whose blob is missing.
            continue;
        }
        let mut file = std::fs::File::open(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => hasher.update(&buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
            }
        }
        if hex::encode(hasher.finalize()) != sha256 {
            return Err(format!(
                "{} does not match its name — the blob is corrupt; restore it from a backup or \
                 upload the artifact again",
                path.display()
            ));
        }
        let mut file = std::fs::File::open(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let (stored, size) = store
            .put(&mut file)
            .map_err(|e| format!("cannot copy {} into the bucket: {e}", path.display()))?;
        if stored != sha256 {
            return Err(format!(
                "{} changed while it was copied into the bucket — stop whatever writes to it and \
                 start the Server again",
                path.display()
            ));
        }
        tracing::info!(
            blob = %sha256,
            bytes = size,
            "copied an artifact from {} into the bucket; the file is left in place",
            dir.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BlobsConfig;
    use crate::fs::FsBlobStore;
    use crate::packages::{PackageId, PackageStore, Platform};

    /// The store the S3 tests run against (ADR-0049 clause 9), under a prefix of its own so that
    /// tests running at once never see each other's keys; `None`, said aloud, where none is named.
    fn named_store() -> Option<S3BlobsConfig> {
        let variable = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
        let (Some(endpoint), Some(bucket)) = (
            variable("FLEET_TEST_S3_ENDPOINT"),
            variable("FLEET_TEST_S3_BUCKET"),
        ) else {
            eprintln!(
                "skipped: no S3 store is named — set FLEET_TEST_S3_ENDPOINT, \
                 FLEET_TEST_S3_BUCKET, FLEET_TEST_S3_ACCESS_KEY_ID and \
                 FLEET_TEST_S3_SECRET_ACCESS_KEY_FILE to run the S3 store's tests"
            );
            return None;
        };
        let mut random = [0u8; 8];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut random)
            .expect("random");
        Some(S3BlobsConfig {
            endpoint,
            bucket,
            region: variable("FLEET_TEST_S3_REGION").unwrap_or_else(|| "us-east-1".to_string()),
            prefix: format!("test-{}/", hex::encode(random)),
            ca_file: variable("FLEET_TEST_S3_CA_FILE").map(Into::into),
            access_key_id: variable("FLEET_TEST_S3_ACCESS_KEY_ID"),
            secret_access_key_file: variable("FLEET_TEST_S3_SECRET_ACCESS_KEY_FILE")
                .map(Into::into),
        })
    }

    /// The same settings again — a second Server start on the same prefix.
    fn again(config: &S3BlobsConfig) -> S3BlobsConfig {
        S3BlobsConfig {
            endpoint: config.endpoint.clone(),
            bucket: config.bucket.clone(),
            region: config.region.clone(),
            prefix: config.prefix.clone(),
            ca_file: config.ca_file.clone(),
            access_key_id: config.access_key_id.clone(),
            secret_access_key_file: config.secret_access_key_file.clone(),
        }
    }

    /// Writes an object at `key` under the store's prefix, past the port — what another writer, or
    /// an interrupted upload, would leave.
    fn plant(store: &S3BlobStore, key: &str) {
        let key = Key::parse(format!("{}{key}", store.prefix)).expect("key");
        let raw = store.store.clone();
        store
            .bridge
            .run(async move { raw.put(&key, PutPayload::from_static(b"x")).await })
            .expect("plant");
    }

    /// Every key under the store's prefix, past the port.
    fn keys(store: &S3BlobStore) -> Vec<String> {
        let raw = store.store.clone();
        let root = store.root();
        let mut keys: Vec<String> = store
            .bridge
            .run(async move { raw.list(root.as_ref()).try_collect::<Vec<_>>().await })
            .expect("list")
            .into_iter()
            .map(|object| object.location.to_string())
            .collect();
        keys.sort();
        keys
    }

    /// Leaves the bucket as the test found it.
    fn clear(store: &S3BlobStore) {
        for key in keys(store) {
            store.delete_key(Key::from(key)).expect("clear");
        }
    }

    fn sha256(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn read_all(mut bytes: Box<dyn Read + Send>) -> Vec<u8> {
        let mut read = Vec::new();
        bytes.read_to_end(&mut read).expect("read");
        read
    }

    /// A stream that yields some bytes and then fails, as a cut-off upload does.
    struct CutOff(usize);

    impl Read for CutOff {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.0 == 0 {
                return Err(std::io::Error::other("cut off"));
            }
            let n = buf.len().min(self.0);
            buf[..n].fill(1);
            self.0 -= n;
            Ok(n)
        }
    }

    /// The blob port's contract, which every store keeps (ADR-0049 clause 1): identical bytes are
    /// one blob named by their hash; what was stored reads back, an upload of several parts and an
    /// empty one included; `list` names every blob with its size; deleting an absent blob is no
    /// error; and a stream that fails stores nothing.
    fn contract(store: &dyn BlobStore) {
        assert_eq!(store.list().expect("list"), Vec::new(), "starts empty");
        let (artifact, size) = store.put(&mut &b"artifact"[..]).expect("put");
        let (again, _) = store.put(&mut &b"artifact"[..]).expect("put again");
        assert_eq!((artifact.as_str(), size), (sha256(b"artifact").as_str(), 8));
        assert_eq!(again, artifact, "identical bytes are one blob");
        let large: Vec<u8> = (0..PART_SIZE + 4321).map(|i| (i % 251) as u8).collect();
        let (parts, large_size) = store.put(&mut large.as_slice()).expect("put large");
        assert_eq!(
            (parts.clone(), large_size),
            (sha256(&large), large.len() as u64)
        );
        let (empty, empty_size) = store.put(&mut &b""[..]).expect("put empty");
        assert_eq!((empty.clone(), empty_size), (sha256(b""), 0));

        let mut expected = vec![
            (artifact.clone(), 8),
            (parts.clone(), large.len() as u64),
            (empty.clone(), 0),
        ];
        expected.sort();
        assert_eq!(store.list().expect("list"), expected);
        assert_eq!(read_all(store.get(&artifact).expect("get")), b"artifact");
        assert!(read_all(store.get(&parts).expect("get large")) == large);
        assert!(read_all(store.get(&empty).expect("get empty")).is_empty());

        assert!(store.exists(&artifact).expect("exists"));
        store.delete(&artifact).expect("delete");
        assert!(!store.exists(&artifact).expect("exists"));
        assert!(store.get(&artifact).is_err());
        store
            .delete(&artifact)
            .expect("deleting the absent is no error");
        assert!(store.get("../x").is_err(), "only a hash names a blob");
        assert!(!store.exists("../x").expect("no hash, no blob"));

        assert!(store.put(&mut CutOff(PART_SIZE + 10)).is_err());
        assert!(store.put(&mut CutOff(10)).is_err());
        expected.retain(|(sha256, _)| *sha256 != artifact);
        assert_eq!(
            store.list().expect("list"),
            expected,
            "a failed stream stores nothing"
        );
    }

    /// Verifies: ADR-0049
    #[test]
    fn the_blob_port_contract_holds_on_the_filesystem() {
        let dir = tempfile::tempdir().expect("tempdir");
        contract(&FsBlobStore::open(dir.path()).expect("open"));
        assert_eq!(
            std::fs::read_dir(dir.path().join("blobs"))
                .expect("dir")
                .count(),
            2,
            "no staging file is left"
        );
    }

    /// Run from inside a runtime's own thread, as the Server's handlers call the port: the bridge
    /// neither panics there nor waits on the runtime it blocks, and the store is dropped there too.
    /// Verifies: ADR-0049
    #[tokio::test(flavor = "current_thread")]
    async fn the_blob_port_contract_holds_on_s3() {
        let Some(config) = named_store() else { return };
        let store = S3BlobStore::open(&config).expect("open");
        contract(&store);
        assert!(
            keys(&store)
                .iter()
                .all(|key| key.starts_with(&format!("{}blobs/", config.prefix))),
            "no staging object is left: {:?}",
            keys(&store)
        );
        clear(&store);
    }

    /// A failed upload leaves nothing under `blobs/`, and a staging object an interrupted upload
    /// left is deleted at the next startup; any other key under the prefix fails it, naming the
    /// key (ADR-0049 clause 4).
    /// Verifies: ADR-0049
    #[test]
    fn leftover_staging_objects_go_and_unknown_keys_fail_startup_on_s3() {
        let Some(config) = named_store() else { return };
        let store = S3BlobStore::open(&config).expect("open");
        assert!(store.put(&mut CutOff(10)).is_err());
        assert_eq!(
            keys(&store),
            Vec::<String>::new(),
            "a failed stream leaves nothing"
        );

        let (sha256, _) = store.put(&mut &b"artifact"[..]).expect("put");
        plant(&store, "staging/0123456789abcdef");
        let reopened = S3BlobStore::open(&again(&config)).expect("reopen");
        assert_eq!(reopened.list().expect("list"), vec![(sha256.clone(), 8)]);
        assert_eq!(
            keys(&store),
            vec![format!("{}blobs/{sha256}", config.prefix)],
            "the staging object is gone"
        );

        for stray in ["otelcol.bin", "blobs/not-a-hash", "blobs/nested/key"] {
            plant(&store, stray);
            let err = store.list().expect_err(stray);
            assert!(err.contains(&format!("{}{stray}", config.prefix)), "{err}");
            store
                .delete_key(Key::parse(format!("{}{stray}", config.prefix)).expect("key"))
                .expect("remove");
        }
        clear(&store);
    }

    /// The Server does not create its bucket: one that does not exist fails startup naming it
    /// (ADR-0049 clause 4).
    /// Verifies: ADR-0049
    #[test]
    fn a_bucket_that_does_not_exist_fails_startup_naming_it() {
        let Some(mut config) = named_store() else {
            return;
        };
        config.bucket = format!("fleet-missing-{}", &config.prefix[5..13]);
        let err = S3BlobStore::open(&config).err().expect("no such bucket");
        assert!(err.contains(&config.bucket), "{err}");
    }

    /// Switching to S3 copies every referenced artifact the bucket lacks, verified against its
    /// name, and leaves the file where it is; the reverse — an entry whose blob neither the bucket
    /// nor the copy can supply — fails startup naming the entry (ADR-0049 clause 7).
    /// Verifies: ADR-0049
    #[test]
    fn switching_to_s3_copies_what_the_bucket_lacks_and_leaves_the_file() {
        let Some(config) = named_store() else { return };
        let dir = tempfile::tempdir().expect("tempdir");
        let id = PackageId::new("otelcol", "1.0.0").expect("id");
        let linux = Platform::new("linux", "amd64").expect("platform");
        {
            let store = PackageStore::open(dir.path().to_path_buf()).expect("fs store");
            store.create(&id).expect("create");
            store
                .put_entry(&id, &linux, b"artifact".to_vec())
                .expect("entry");
        }
        let sha256 = sha256(b"artifact");
        let file = dir.path().join("blobs").join(&sha256);
        let blobs = |config: &S3BlobsConfig| BlobsConfig {
            store: "s3".to_string(),
            s3: Some(again(config)),
        };

        let store = PackageStore::open_with(dir.path().to_path_buf(), &blobs(&config))
            .expect("switch to s3");
        assert_eq!(
            read_all(
                store
                    .open_artifact(&hex::decode(&sha256).expect("hex"))
                    .expect("artifact")
            ),
            b"artifact"
        );
        assert_eq!(std::fs::read(&file).expect("left in place"), b"artifact");
        drop(store);
        PackageStore::open_with(dir.path().to_path_buf(), &blobs(&config))
            .expect("a second start copies nothing and opens");

        let bucket = S3BlobStore::open(&config).expect("open");
        std::fs::remove_file(&file).expect("the operator removes data_dir/blobs");
        let mut elsewhere = again(&config);
        elsewhere.prefix = format!("{}elsewhere/", config.prefix);
        let err = PackageStore::open_with(dir.path().to_path_buf(), &blobs(&elsewhere))
            .err()
            .expect("a blob neither store holds");
        assert!(
            err.contains("otelcol@1.0.0") || err.contains("otelcol"),
            "{err}"
        );
        assert!(err.contains(&sha256), "{err}");
        clear(&bucket);
    }

    /// The copy of clause 7 reads `data_dir/blobs/` and nothing else: a referenced file the target
    /// lacks is hashed and uploaded, the file stays, a second run copies nothing, and a file whose
    /// content does not match its name fails, naming it. Run against a filesystem target, so it
    /// needs no store.
    /// Verifies: ADR-0049
    #[test]
    fn the_copy_from_the_filesystem_verifies_each_file_and_leaves_it() {
        let source = tempfile::tempdir().expect("tempdir");
        let blobs = source.path().join("blobs");
        std::fs::create_dir(&blobs).expect("blobs");
        let (one, two) = (sha256(b"one"), sha256(b"two"));
        std::fs::write(blobs.join(&one), b"one").expect("one");
        std::fs::write(blobs.join(&two), b"two").expect("two");
        let unreferenced = sha256(b"three");
        std::fs::write(blobs.join(&unreferenced), b"three").expect("three");

        let target = tempfile::tempdir().expect("tempdir");
        let store = FsBlobStore::open(target.path()).expect("target");
        let missing = sha256(b"missing");
        copy_from_filesystem(
            &blobs,
            [one.as_str(), two.as_str(), missing.as_str()],
            &store,
        )
        .expect("copy");
        let mut expected = vec![(one.clone(), 3), (two.clone(), 3)];
        expected.sort();
        assert_eq!(
            store.list().expect("list"),
            expected,
            "the referenced, and only them"
        );
        assert_eq!(
            std::fs::read_dir(&blobs).expect("dir").count(),
            3,
            "left in place"
        );
        copy_from_filesystem(&blobs, [one.as_str()], &store).expect("nothing to copy");

        std::fs::write(blobs.join(&two), b"tampered").expect("tamper");
        let target = tempfile::tempdir().expect("tempdir");
        let store = FsBlobStore::open(target.path()).expect("target");
        let err = copy_from_filesystem(&blobs, [two.as_str()], &store).expect_err("refused");
        assert!(err.contains(&two), "{err}");
        assert_eq!(store.list().expect("list"), Vec::new(), "nothing copied");
    }

    fn config(endpoint: &str) -> S3BlobsConfig {
        S3BlobsConfig {
            endpoint: endpoint.to_string(),
            bucket: "fleet".to_string(),
            region: "eu-central-1".to_string(),
            prefix: String::new(),
            ca_file: None,
            access_key_id: None,
            secret_access_key_file: None,
        }
    }

    /// The marker that makes [`aws_variables_child`] check the environment it was started with.
    const CHILD: &str = "FLEET_TEST_AWS_VARIABLES_CHILD";

    /// `AWS_ENDPOINT`, `AWS_ALLOW_HTTP` and their kin, set in the Server's environment, change
    /// neither the endpoint nor whether plaintext is allowed; the only `AWS_*` variables read are
    /// those of the workload identity (ADR-0049 clauses 5 and 6). The environment is the real one
    /// of a child process, so whatever reads it — this module or the S3 client — is held to it.
    /// Verifies: ADR-0049
    #[test]
    fn aws_variables_change_neither_the_endpoint_nor_plaintext() {
        let asked = std::cell::RefCell::new(Vec::new());
        builder(
            &config("https://s3.example"),
            &|name| {
                asked.borrow_mut().push(name.to_string());
                Some("x".to_string())
            },
            LIMITS,
        )
        .expect("builder");
        let identity: Vec<&str> = WORKLOAD_IDENTITY.iter().map(|(name, _)| *name).collect();
        assert_eq!(asked.into_inner(), identity);

        let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args(["s3::tests::aws_variables_child", "--exact", "--nocapture"])
            .env(CHILD, "1")
            .env("AWS_ENDPOINT", "http://203.0.113.9:9000")
            .env("AWS_ENDPOINT_URL", "http://203.0.113.9:9000")
            .env("AWS_ENDPOINT_URL_S3", "http://203.0.113.9:9000")
            .env("AWS_ALLOW_HTTP", "true")
            .env("AWS_BUCKET", "elsewhere")
            .env("AWS_DEFAULT_REGION", "us-west-2")
            .env("AWS_REGION", "us-west-2")
            .env("AWS_ACCESS_KEY_ID", "AKIDELSEWHERE")
            .env("AWS_SECRET_ACCESS_KEY", "elsewhere")
            .output()
            .expect("run the child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// The child of [`aws_variables_change_neither_the_endpoint_nor_plaintext`]; it passes
    /// trivially when run by itself.
    #[test]
    fn aws_variables_child() {
        if std::env::var_os(CHILD).is_none() {
            return;
        }
        let builder = builder(
            &config("https://s3.example"),
            &|name| std::env::var(name).ok(),
            LIMITS,
        )
        .expect("builder");
        assert_eq!(
            builder
                .get_config_value(&AmazonS3ConfigKey::Endpoint)
                .as_deref(),
            Some("https://s3.example")
        );
        assert_eq!(
            builder
                .get_config_value(&AmazonS3ConfigKey::Bucket)
                .as_deref(),
            Some("fleet")
        );
        assert_eq!(
            builder
                .get_config_value(&AmazonS3ConfigKey::Region)
                .as_deref(),
            Some("eu-central-1")
        );
        assert_eq!(
            builder
                .get_config_value(&AmazonS3ConfigKey::Client(ClientConfigKey::AllowHttp))
                .as_deref(),
            Some("false")
        );
        for key in [
            AmazonS3ConfigKey::S3Endpoint,
            AmazonS3ConfigKey::AccessKeyId,
            AmazonS3ConfigKey::SecretAccessKey,
        ] {
            assert_eq!(builder.get_config_value(&key), None, "{key:?}");
        }
        let built = format!("{:?}", builder.build().expect("build"));
        assert!(built.contains("https://s3.example/fleet"), "{built}");
        assert!(!built.contains("203.0.113.9"), "{built}");
    }

    /// A store that takes the connection and never answers fails the call within the limits —
    /// the silence of each attempt, retried — rather than holding it, and whatever lock its caller
    /// holds, forever (ADR-0049 clause 5). The call is the listing at startup; every request goes
    /// through the same client. Needs no store.
    /// Verifies: ADR-0049
    #[test]
    fn a_store_that_never_answers_fails_the_call_within_the_limits() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in listener.incoming() {
                // Kept open, read from never, answered never.
                held.push(stream);
            }
        });
        let limits = Limits {
            connect: Duration::from_secs(1),
            silence: Duration::from_millis(300),
            retries: 1,
            retry_for: Duration::from_millis(500),
        };
        // A key pair, so that the request goes to the store rather than to a credential source.
        let dir = tempfile::tempdir().expect("tempdir");
        let secret = dir.path().join("secret");
        std::fs::write(&secret, "the-secret").expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600))
                .expect("chmod");
        }
        let mut silent = config(&format!("http://127.0.0.1:{port}"));
        silent.access_key_id = Some("fleet-test".to_string());
        silent.secret_access_key_file = Some(secret);
        let started = std::time::Instant::now();
        let err = S3BlobStore::open_within(&silent, limits)
            .err()
            .expect("no answer");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}: {err}",
            started.elapsed()
        );
        assert!(err.contains("bucket fleet"), "{err}");
        assert!(
            err.contains(&format!("GET http://127.0.0.1:{port}/")) && err.contains("1 retries"),
            "the store itself fell silent, and was asked again: {err}"
        );
    }

    /// A static key pair's secret comes from its file, which its owner and group alone may read
    /// (ADR-0049 clause 6).
    /// Verifies: ADR-0049
    #[test]
    fn the_secret_file_is_read_and_must_be_the_servers_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret");
        std::fs::write(&path, "the-secret\n").expect("write");
        let mut keyed = config("http://127.0.0.1:9100");
        keyed.access_key_id = Some("fleet-dev".to_string());
        keyed.secret_access_key_file = Some(path.clone());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
            let err = builder(&keyed, &|_| None, LIMITS).expect_err("readable by others");
            assert!(err.contains("[blobs.s3] secret_access_key_file"), "{err}");
            // Its group may read it, as an orchestrator's secret mount lets it.
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).expect("chmod");
        }
        let builder = builder(
            &keyed,
            &|_| panic!("no AWS_* variable beside a key pair"),
            LIMITS,
        )
        .expect("builder");
        assert_eq!(
            builder
                .get_config_value(&AmazonS3ConfigKey::SecretAccessKey)
                .as_deref(),
            Some("the-secret")
        );
        assert_eq!(
            builder
                .get_config_value(&AmazonS3ConfigKey::Client(ClientConfigKey::AllowHttp))
                .as_deref(),
            Some("true"),
            "plaintext on the loopback endpoint"
        );
    }
}
