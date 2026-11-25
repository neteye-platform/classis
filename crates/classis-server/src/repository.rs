//! A Package Repository: the tree of static files a Server reads its Packages from, and writes
//! none to. One manifest per Package at `packages/<agent_type>@<version>.json`, in the format of
//! the filesystem package backend ([`read_manifest`]), and one Blob per SHA-256 at
//! `blobs/<sha256>`. Another party writes it — the Blobs first, the manifest last — so a Package
//! is in the repository once its manifest is.
//!
//! The adapter reads through `object_store`, whose local filesystem has the interface of its S3
//! client: one listing and one reader serve every source, a directory or a prefix of a bucket. The interface is asynchronous and the
//! ports are not, so every operation runs on a [`Bridge`] of the adapter's own, as the S3 blob
//! store's do.
//!
//! What another party wrote is not trusted to be well formed: a manifest that cannot be read, or
//! that names a Blob the repository does not hold as recorded, is set aside — its Package is not
//! loaded and a warning says why — and every other Package is. Whether an Entry is offered is the
//! package store's signature check, as for an uploaded one.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use object_store::local::LocalFileSystem;
use object_store::path::Path as Key;
use object_store::{ObjectMeta, ObjectStore, ObjectStoreExt as _};

use crate::blobs::{is_hash, BlobStore};
use crate::bridge::Bridge;
use crate::config::{RepositoryConfig, RepositorySource, S3BlobsConfig, REPOSITORY_S3};
use crate::fs::{read_manifest, too_large, MAX_MANIFEST_BYTES};
use crate::packages::{Package, FROM_REPOSITORY};
use crate::s3::{Limits, ObjectReader};

/// Where the manifests are, under the root of the repository.
const MANIFESTS: &str = "packages";
/// Where the Blobs are, under the root of the repository.
const BLOBS: &str = "blobs";

/// One Package Repository, read by its listings, and what the last listing set aside.
///
/// It is `Send` and `Sync`. A listing takes it mutably, so the record of what was set aside
/// has one owner and needs no lock; the downloads read through a [`RepositoryBlobs`] of their
/// own.
#[derive(Debug)]
pub struct Repository {
    source: Source,
    /// Each manifest the last listing set aside, with why, so a warning is logged when that
    /// changes and not at every listing.
    set_aside: BTreeMap<String, String>,
}

/// The Blobs of a [`Repository`], for the downloads: read, never written and never deleted.
#[derive(Debug)]
pub struct RepositoryBlobs(Source);

/// What both halves read through: the store, its name and the runtime its calls run on. A clone
/// is another handle on the same store.
#[derive(Clone)]
struct Source {
    store: Arc<dyn ObjectStore>,
    /// Where the repository is in the store: empty for a directory, the prefix of a bucket
    /// otherwise, which ends in `/` (the configuration check makes sure of it).
    prefix: String,
    /// What a message names the repository by: its directory, or its bucket and prefix.
    name: String,
    bridge: Arc<Bridge>,
    /// The directory of a repository on the filesystem, which must still be there at each
    /// listing: the local store lists a directory that is gone as an empty one.
    directory: Option<PathBuf>,
}

impl std::fmt::Debug for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Source")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl Repository {
    /// Opens the repository `config` names. Nothing is created and nothing is checked of its
    /// owner or its mode: a directory that does not exist fails here, naming it.
    ///
    /// # Errors
    /// Returns an error naming the key when the repository cannot be opened.
    pub fn open(config: &RepositoryConfig) -> Result<Self, String> {
        match config.source()? {
            RepositorySource::Directory(path) => Self::open_directory(path),
            RepositorySource::Bucket(bucket) => Self::open_bucket(bucket),
        }
    }

    /// Opens the repository in the directory `path`.
    ///
    /// ```no_run
    /// use classis_server::repository::Repository;
    ///
    /// let mut repository = Repository::open_directory("/srv/classis/repository".as_ref())?;
    /// for package in repository.read()? {
    ///     println!("{} holds {} entries", package.id, package.entries.len());
    /// }
    /// # Ok::<(), String>(())
    /// ```
    ///
    /// # Errors
    /// Returns an error naming `path` when it is not a directory that can be opened.
    pub fn open_directory(path: &Path) -> Result<Self, String> {
        let named = |why: &dyn std::fmt::Display| {
            format!("[packages.repository] path {}: {why}", path.display())
        };
        let store = LocalFileSystem::new_with_prefix(path).map_err(|e| named(&e))?;
        if !path.is_dir() {
            return Err(named(&"not a directory"));
        }
        Ok(Self::on(Source {
            store: Arc::new(store),
            prefix: String::new(),
            name: path.display().to_string(),
            bridge: Arc::new(Bridge::new("repository")?),
            directory: Some(path.to_path_buf()),
        }))
    }

    /// Opens the repository under the prefix of the bucket `config` names, with the connection
    /// of the S3 blob store: nothing is created, a bucket that does not exist or credentials it
    /// refuses fail at once, and a store that does not answer yet is asked again for up to three
    /// minutes.
    ///
    /// # Errors
    /// Returns an error naming the key or the bucket when the bucket cannot be reached or listed.
    pub fn open_bucket(config: &S3BlobsConfig) -> Result<Self, String> {
        Self::open_bucket_within(
            config,
            crate::s3::LIMITS,
            crate::s3::START_WAIT,
            crate::s3::START_RETRY,
        )
    }

    /// [`open_bucket`](Self::open_bucket) within `limits`, asking again every `interval` for
    /// `wait`.
    fn open_bucket_within(
        config: &S3BlobsConfig,
        limits: Limits,
        wait: Duration,
        interval: Duration,
    ) -> Result<Self, String> {
        let bridge = Bridge::new("repository")?;
        let store = crate::s3::connect(config, REPOSITORY_S3, &bridge, limits, wait, interval)?;
        Ok(Self::on(Source {
            store,
            prefix: config.prefix.clone(),
            name: format!(
                "in bucket {} under prefix {:?}",
                config.bucket, config.prefix
            ),
            bridge: Arc::new(bridge),
            directory: None,
        }))
    }

    fn on(source: Source) -> Self {
        Repository {
            source,
            set_aside: BTreeMap::new(),
        }
    }

    /// Lists the repository once and reads every manifest it holds. Answers each Package whose
    /// manifest is well formed and names only Blobs the listing found, of the sizes it records;
    /// every other manifest is set aside, and a warning names it and why when that is new since
    /// the last listing. A file that is neither a manifest nor a Blob is ignored.
    ///
    /// # Errors
    /// Returns an error naming the repository when it cannot be listed, or when its directory
    /// went away while it was listed.
    pub fn read(&mut self) -> Result<Vec<Package>, String> {
        // The Manifests first and the Blobs after: a writer writes the Blobs of a Manifest before
        // it, so every Blob a Manifest read here names is in the listing that follows.
        let mut read = Vec::new();
        for object in self.source.listing(MANIFESTS)? {
            if let Some(file_name) = manifest_name(&object) {
                let manifest = self.source.manifest(&object, &file_name);
                read.push((file_name, manifest));
            }
        }
        let blobs: BTreeMap<String, u64> = self.source.blobs()?.into_iter().collect();
        // Asked once both listings are done: a directory that went away before or during them
        // listed as an empty one.
        if let Some(directory) = &self.source.directory {
            if !directory.is_dir() {
                return Err(format!(
                    "the Package Repository {} is no longer a directory",
                    self.source.name
                ));
            }
        }
        let mut packages = Vec::new();
        let mut set_aside = BTreeMap::new();
        for (file_name, manifest) in read {
            match manifest.and_then(|package| held(package, &file_name, &blobs)) {
                Ok(package) => packages.push(package),
                Err(why) => {
                    set_aside.insert(file_name, why);
                }
            }
        }
        self.report(set_aside);
        Ok(packages)
    }

    /// Reads the repository again every `every`, for as long as the Server runs, and hands each
    /// listing to `apply`, which replaces the Packages in use. A listing that fails changes
    /// nothing: the Packages of the last one stay in use, a warning names the failure when it
    /// starts or changes, and a message says so when the listings succeed again. Each listing
    /// runs on a blocking thread, so the runtime is never held by the store.
    pub async fn reread_every(
        mut self,
        every: Duration,
        apply: impl Fn(Vec<Package>) -> Result<(), String> + Send + Sync + 'static,
    ) {
        let apply = Arc::new(apply);
        let mut failing: Option<String> = None;
        let mut ticks = tokio::time::interval(every);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick is at once, and the startup has read the repository already.
        ticks.tick().await;
        loop {
            ticks.tick().await;
            let apply = Arc::clone(&apply);
            let listing = tokio::task::spawn_blocking(move || {
                let listed = self.read().and_then(|packages| apply(packages));
                (self, listed)
            })
            .await;
            let listed = match listing {
                Ok((repository, listed)) => {
                    self = repository;
                    listed
                }
                // The runtime is shutting down, and the Server with it.
                Err(e) if e.is_cancelled() => return,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "the listing of the Package Repository stopped; the Packages of the last \
                         listing stay in use until the Server restarts"
                    );
                    return;
                }
            };
            match listed {
                Ok(()) => {
                    if failing.take().is_some() {
                        tracing::info!(
                            repository = %self.source.name,
                            "the Package Repository is listed again"
                        );
                    }
                }
                Err(why) => {
                    if failing.as_deref() != Some(why.as_str()) {
                        tracing::warn!(
                            repository = %self.source.name,
                            "{why} — the Packages of the last listing stay in use"
                        );
                    }
                    failing = Some(why);
                }
            }
        }
    }

    /// A handle on the Blobs of the repository, for the package store to serve the downloads
    /// from.
    #[must_use]
    pub fn blob_store(&self) -> RepositoryBlobs {
        RepositoryBlobs(self.source.clone())
    }

    /// Logs each manifest set aside that the last listing did not set aside for the same reason,
    /// and keeps `set_aside` for the next listing to compare with.
    fn report(&mut self, set_aside: BTreeMap<String, String>) {
        for (manifest, why) in &set_aside {
            if self.set_aside.get(manifest) != Some(why) {
                tracing::warn!(
                    repository = %self.source.name,
                    manifest = %manifest,
                    "the manifest is set aside and its Package is not loaded — {why}"
                );
            }
        }
        for manifest in self.set_aside.keys() {
            if !set_aside.contains_key(manifest) {
                tracing::info!(
                    repository = %self.source.name,
                    manifest = %manifest,
                    "the manifest is no longer set aside"
                );
            }
        }
        self.set_aside = set_aside;
    }
}

impl Source {
    /// Every Blob the repository holds, with its size, from the listing alone.
    fn blobs(&self) -> Result<Vec<(String, u64)>, String> {
        Ok(self
            .listing(BLOBS)?
            .into_iter()
            .filter_map(|object| {
                let name = object.location.filename()?;
                is_hash(name).then(|| (name.to_string(), object.size))
            })
            .collect())
    }

    /// The objects directly under `dir`. A directory the repository does not hold lists empty.
    fn listing(&self, dir: &str) -> Result<Vec<ObjectMeta>, String> {
        // The future runs on the adapter's runtime, so it owns its handle on the store.
        let store = Arc::clone(&self.store);
        let prefix = self.key(dir)?;
        self.bridge
            .run(async move { store.list_with_delimiter(Some(&prefix)).await })
            .map(|listing| listing.objects)
            .map_err(|e| {
                format!(
                    "cannot list {dir}/ of the Package Repository {}: {e}",
                    self.name
                )
            })
    }

    /// Reads the manifest `object`, refused unread when the listing says it is larger than a
    /// manifest may be, or when it is not a regular file.
    fn manifest(&self, object: &ObjectMeta, file_name: &str) -> Result<Package, String> {
        if object.size > MAX_MANIFEST_BYTES as u64 {
            return Err(too_large(file_name));
        }
        self.regular(&object.location, file_name)?;
        read_manifest(file_name, &mut self.reader(&object.location)?)
    }

    /// Refuses `key` in a directory when it is not a regular file. A named pipe would hold the
    /// open, and the listing with it, until something writes to it.
    fn regular(&self, key: &Key, named: &str) -> Result<(), String> {
        let Some(directory) = &self.directory else {
            return Ok(());
        };
        let path = directory.join(key.as_ref());
        match std::fs::metadata(&path) {
            Ok(metadata) if metadata.is_file() => Ok(()),
            Ok(_) => Err(format!("{named} is not a regular file")),
            Err(e) => Err(format!("cannot read {named}: {e}")),
        }
    }

    /// The key of `path` under the root of the repository.
    fn key(&self, path: &str) -> Result<Key, String> {
        Key::parse(format!("{}{path}", self.prefix))
            .map_err(|e| format!("{path} of the Package Repository {}: {e}", self.name))
    }

    /// The key of the Blob `sha256`; only a hash names one, so nothing else can name a path.
    fn blob_key(&self, sha256: &str) -> Result<Key, String> {
        if !is_hash(sha256) {
            return Err(format!("{sha256:?} is not the SHA-256 of a blob"));
        }
        self.key(&format!("{BLOBS}/{sha256}"))
    }

    /// The bytes of the object at `key`, as a stream.
    fn reader(&self, key: &Key) -> Result<ObjectReader, String> {
        let store = Arc::clone(&self.store);
        let location = key.clone();
        let result = self
            .bridge
            .run(async move { store.get(&location).await })
            .map_err(|e| {
                format!(
                    "cannot read {key} of the Package Repository {}: {e}",
                    self.name
                )
            })?;
        Ok(ObjectReader::new(result, Arc::clone(&self.bridge)))
    }
}

/// The file name of a manifest the listing found: a name ending in `.json`, not hidden. Anything
/// else under `packages/` — a writer's temporary file among them — is not a manifest.
fn manifest_name(object: &ObjectMeta) -> Option<String> {
    let name = object.location.filename()?;
    (name.ends_with(".json") && !name.starts_with('.')).then(|| name.to_string())
}

/// `package`, when every Blob its entries name is in `blobs` at the size the entry records.
fn held(
    package: Package,
    file_name: &str,
    blobs: &BTreeMap<String, u64>,
) -> Result<Package, String> {
    for entry in package.entries.values() {
        let sha256 = hex::encode(&entry.content_hash);
        match blobs.get(&sha256) {
            Some(size) if *size == entry.size => {}
            Some(size) => {
                return Err(format!(
                    "{file_name} records {} bytes for the entry of {}, and blob {sha256} holds \
                     {size}",
                    entry.size,
                    entry.platform.tag()
                ))
            }
            None => {
                return Err(format!(
                    "{file_name} names blob {sha256} for the entry of {}, and the repository \
                     does not hold it",
                    entry.platform.tag()
                ))
            }
        }
    }
    Ok(package)
}

impl BlobStore for RepositoryBlobs {
    fn put(&self, _bytes: &mut dyn Read) -> Result<(String, u64), String> {
        Err(FROM_REPOSITORY.to_string())
    }

    fn get(&self, sha256: &str) -> Result<Box<dyn Read + Send>, String> {
        let key = self.0.blob_key(sha256)?;
        self.0.regular(&key, &format!("blob {sha256}"))?;
        Ok(Box::new(self.0.reader(&key)?))
    }

    fn exists(&self, sha256: &str) -> Result<bool, String> {
        let Ok(key) = self.0.blob_key(sha256) else {
            return Ok(false);
        };
        let store = Arc::clone(&self.0.store);
        match self.0.bridge.run(async move { store.head(&key).await }) {
            Ok(_) => Ok(true),
            Err(object_store::Error::NotFound { .. }) => Ok(false),
            Err(e) => Err(format!(
                "cannot ask the Package Repository {} for blob {sha256}: {e}",
                self.0.name
            )),
        }
    }

    fn delete(&self, _sha256: &str) -> Result<(), String> {
        Err(FROM_REPOSITORY.to_string())
    }

    fn list(&self) -> Result<Vec<(String, u64)>, String> {
        self.0.blobs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RevokedSigners, RootsVerifier};
    use crate::packages::test_signing::{signed, test_root};
    use crate::packages::{PackageId, PackageStore, Platform, SignatureState};
    use sha2::{Digest, Sha256};
    use std::sync::Mutex;

    /// The party that writes a repository, past the Server: what a test stands in for.
    trait Writer {
        /// Writes `bytes` at `key` under the root, whole or not at all.
        fn put(&self, key: &str, bytes: &[u8]);
        /// Deletes what is at `key` under the root.
        fn remove(&self, key: &str);
        /// The repository as a Server opens it.
        fn open(&self) -> Repository;
    }

    /// A repository in a directory of its own.
    struct Directory(tempfile::TempDir);

    impl Directory {
        fn new() -> Self {
            Directory(tempfile::tempdir().expect("tempdir"))
        }
    }

    impl Writer for Directory {
        /// A temporary file renamed into place, as D1 asks of a writer.
        fn put(&self, key: &str, bytes: &[u8]) {
            let path = self.0.path().join(key);
            let dir = path.parent().expect("a key has a directory");
            std::fs::create_dir_all(dir).expect("create the directory");
            let staged = dir.join(".staged");
            std::fs::write(&staged, bytes).expect("write");
            std::fs::rename(&staged, &path).expect("rename");
        }

        fn remove(&self, key: &str) {
            std::fs::remove_file(self.0.path().join(key)).expect("remove");
        }

        fn open(&self) -> Repository {
            Repository::open_directory(self.0.path()).expect("open the repository")
        }
    }

    fn linux() -> Platform {
        Platform::new("linux", "amd64").expect("platform")
    }

    fn windows() -> Platform {
        Platform::new("windows", "amd64").expect("platform")
    }

    fn id(agent_type: &str, version: &str) -> PackageId {
        PackageId::new(agent_type, version).expect("id")
    }

    /// One entry of a manifest, as a writer states it.
    struct Written<'a> {
        platform: Platform,
        artifact: &'a [u8],
        signature: Option<Vec<u8>>,
    }

    /// The entry for `artifact` on `platform`, signed by the test Package Signer.
    fn signed_entry<'a>(id: &PackageId, platform: Platform, artifact: &'a [u8]) -> Written<'a> {
        Written {
            platform,
            artifact,
            signature: Some(signed(id, artifact)),
        }
    }

    /// The manifest of `id` holding `entries`, in the format of D1.
    fn manifest(id: &PackageId, entries: &[Written<'_>]) -> Vec<u8> {
        let entries: Vec<serde_json::Value> = entries
            .iter()
            .map(|entry| {
                let mut value = serde_json::json!({
                    "os": entry.platform.os,
                    "arch": entry.platform.arch,
                    "sha256": hex::encode(Sha256::digest(entry.artifact)),
                    "size": entry.artifact.len(),
                });
                if let Some(signature) = &entry.signature {
                    value["signature_hex"] = hex::encode(signature).into();
                }
                value
            })
            .collect();
        serde_json::to_vec_pretty(&serde_json::json!({
            "agent_type": id.agent_type,
            "version": id.version,
            "entries": entries,
        }))
        .expect("manifest")
    }

    /// Publishes a Package: its Blobs first, its manifest last.
    fn publish(writer: &dyn Writer, id: &PackageId, entries: &[Written<'_>]) {
        for entry in entries {
            let sha256 = hex::encode(Sha256::digest(entry.artifact));
            writer.put(&format!("blobs/{sha256}"), entry.artifact);
        }
        writer.put(&format!("packages/{id}.json"), &manifest(id, entries));
    }

    /// The package store on `repository`, its signatures checked by `verifier`, as the binary
    /// opens it.
    fn store_on(repository: &mut Repository, verifier: RootsVerifier) -> PackageStore {
        let packages = repository.read().expect("read the repository");
        PackageStore::from_repository(packages, Box::new(repository.blob_store()))
            .with_verifier(Box::new(verifier))
    }

    fn armed() -> RootsVerifier {
        RootsVerifier::new(test_root().0.roots())
    }

    /// A `tracing` writer into a shared buffer, so a test can read what was logged.
    struct LogBuffer(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for LogBuffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("logs").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Runs `work` and answers what it answered and what it logged.
    fn logged<T>(work: impl FnOnce() -> T) -> (T, String) {
        logged_with(|_| work())
    }

    /// Runs `work`, which can read what has been logged so far, and answers what it answered and
    /// what it logged.
    fn logged_with<T>(work: impl FnOnce(&dyn Fn() -> String) -> T) -> (T, String) {
        let logs = Arc::new(Mutex::new(Vec::<u8>::new()));
        let writer = {
            let logs = logs.clone();
            move || LogBuffer(logs.clone())
        };
        let subscriber = tracing_subscriber::fmt()
            .with_writer(writer)
            .with_ansi(false)
            .finish();
        let so_far = || String::from_utf8_lossy(&logs.lock().expect("logs")).into_owned();
        let answer = tracing::subscriber::with_default(subscriber, || work(&so_far));
        (answer, so_far())
    }

    fn read_all(mut bytes: Box<dyn Read + Send>) -> Vec<u8> {
        let mut read = Vec::new();
        bytes.read_to_end(&mut read).expect("read");
        read
    }

    /// A signed Package for two platforms loads with both entries offered, and its Blobs read back
    /// through the store.
    fn a_signed_package_loads(writer: &dyn Writer) {
        let package = id("otelcol", "1.2.0");
        publish(
            writer,
            &package,
            &[
                signed_entry(&package, linux(), b"linux build"),
                signed_entry(&package, windows(), b"windows build"),
            ],
        );
        let store = store_on(&mut writer.open(), armed());

        let listed = store.list();
        assert_eq!(listed.len(), 1);
        let states: Vec<(String, SignatureState)> = listed[0]
            .entries
            .iter()
            .map(|entry| {
                (
                    format!("{}/{}", entry.os, entry.arch),
                    entry.signature_state,
                )
            })
            .collect();
        assert_eq!(
            states,
            vec![
                ("linux/amd64".to_string(), SignatureState::Valid),
                ("windows/amd64".to_string(), SignatureState::Valid),
            ]
        );
        assert!(!store.is_empty(), "the Server declares OffersPackages");
        let (sha256, size) = store.artifact(&package, &linux()).expect("an entry");
        assert_eq!(size, 11);
        assert_eq!(
            read_all(store.open_artifact(&sha256).expect("open")),
            b"linux build"
        );
    }

    /// Every manifest that is not well formed, or names a Blob the repository does not hold as
    /// recorded, is set aside with one warning naming it and why; the rest loads. Read again
    /// unchanged, nothing new is logged.
    fn what_is_not_well_formed_is_set_aside_once(writer: &dyn Writer) {
        let good = id("otelcol", "1.0.0");
        publish(writer, &good, &[signed_entry(&good, linux(), b"good")]);

        writer.put("packages/garbled@1.0.0.json", b"{ not json");
        let other = id("otelcol", "9.9.9");
        writer.put(
            "packages/misnamed@1.0.0.json",
            &manifest(&other, &[signed_entry(&other, linux(), b"good")]),
        );
        let mut unknown: serde_json::Value = serde_json::from_slice(&manifest(
            &id("unknown", "1.0.0"),
            &[signed_entry(&id("unknown", "1.0.0"), linux(), b"good")],
        ))
        .expect("json");
        unknown["origin"] = "elsewhere".into();
        writer.put(
            "packages/unknown@1.0.0.json",
            &serde_json::to_vec(&unknown).expect("json"),
        );
        let mut large = manifest(
            &id("large", "1.0.0"),
            &[signed_entry(&id("large", "1.0.0"), linux(), b"good")],
        );
        large.resize(MAX_MANIFEST_BYTES + 1, b' ');
        writer.put("packages/large@1.0.0.json", &large);
        let short = id("short", "1.0.0");
        let mut entry = manifest(&short, &[signed_entry(&short, linux(), b"good")]);
        entry = String::from_utf8(entry)
            .expect("utf-8")
            .replace("\"size\": 4", "\"size\": 5")
            .into_bytes();
        writer.put("packages/short@1.0.0.json", &entry);
        let absent = id("absent", "1.0.0");
        writer.put(
            "packages/absent@1.0.0.json",
            &manifest(&absent, &[signed_entry(&absent, linux(), b"never written")]),
        );

        let mut repository = writer.open();
        let (packages, logs) = logged(|| repository.read().expect("read"));
        let loaded: Vec<String> = packages.iter().map(|p| p.id.to_string()).collect();
        assert_eq!(loaded, vec!["otelcol@1.0.0"], "only the good one loads");
        for (manifest, why) in [
            ("garbled@1.0.0.json", "cannot parse"),
            ("misnamed@1.0.0.json", "does not match the identity"),
            ("unknown@1.0.0.json", "unknown field `origin`"),
            ("large@1.0.0.json", "is larger than"),
            ("short@1.0.0.json", "records 5 bytes"),
            ("absent@1.0.0.json", "does not hold it"),
        ] {
            let warnings: Vec<&str> = logs
                .lines()
                .filter(|line| line.contains("WARN") && line.contains(manifest))
                .collect();
            assert_eq!(warnings.len(), 1, "one warning names {manifest}: {logs}");
            assert!(warnings[0].contains(why), "{manifest}: {}", warnings[0]);
        }

        let (_, logs) = logged(|| {
            for _ in 0..10 {
                repository.read().expect("read");
            }
        });
        assert!(
            !logs.contains("WARN"),
            "an unchanged manifest is not named again: {logs}"
        );
    }

    /// A signature of a revoked or an unknown Package Signer withholds its entry, as an uploaded
    /// one's does: the entry is `missing` and offered to nobody.
    fn a_signature_that_does_not_verify_withholds_its_entry(writer: &dyn Writer) {
        let package = id("otelcol", "1.0.0");
        let stranger = classis_core::package::testing::TestRoot::new().signer();
        let hash = Sha256::digest(b"windows build");
        publish(
            writer,
            &package,
            &[
                signed_entry(&package, linux(), b"linux build"),
                Written {
                    platform: windows(),
                    artifact: b"windows build",
                    signature: Some(stranger.sign_artifact("otelcol", "1.0.0", &hash)),
                },
            ],
        );
        let states = |store: &PackageStore| -> Vec<SignatureState> {
            store.list()[0]
                .entries
                .iter()
                .map(|entry| entry.signature_state)
                .collect()
        };
        let store = store_on(&mut writer.open(), armed());
        assert_eq!(
            states(&store),
            vec![SignatureState::Valid, SignatureState::Missing],
            "an unknown Package Signer"
        );
        let revoked = RevokedSigners::parse(&[hex::encode(Sha256::digest(&test_root().1.der))])
            .expect("revoked");
        let store = store_on(&mut writer.open(), armed().with_revoked(revoked));
        assert_eq!(
            states(&store),
            vec![SignatureState::Missing, SignatureState::Missing],
            "a revoked Package Signer"
        );
    }

    /// Files outside `packages/` and `blobs/`, and anything there that is neither a manifest nor
    /// a Blob, are no part of the repository.
    fn other_files_are_ignored(writer: &dyn Writer) {
        let package = id("otelcol", "1.0.0");
        publish(
            writer,
            &package,
            &[signed_entry(&package, linux(), b"build")],
        );
        writer.put("README", b"written by hand");
        writer.put("agents/whatever.json", b"{}");
        writer.put("packages/.otelcol@2.0.0.json.tmp", b"half written");
        writer.put("packages/notes.txt", b"not a manifest");
        writer.put("packages/nested/otelcol@3.0.0.json", b"{}");
        writer.put("blobs/not-a-hash", b"x");

        let (packages, logs) = logged(|| writer.open().read().expect("read"));
        let loaded: Vec<String> = packages.iter().map(|p| p.id.to_string()).collect();
        assert_eq!(loaded, vec!["otelcol@1.0.0"]);
        assert!(!logs.contains("WARN"), "{logs}");
    }

    /// The Server writes nothing and deletes nothing: the store refuses every write, the Blobs
    /// refuse a put and a delete, and the repository is as the writer left it.
    fn nothing_is_written(writer: &dyn Writer) {
        let package = id("otelcol", "1.0.0");
        publish(
            writer,
            &package,
            &[signed_entry(&package, linux(), b"build")],
        );
        let mut repository = writer.open();
        let store = store_on(&mut repository, armed());
        let blobs = repository.blob_store();
        let refused = |result: Result<(), String>| {
            assert_eq!(result.expect_err("refused"), FROM_REPOSITORY);
        };
        refused(store.create(&id("otelcol", "2.0.0")));
        refused(store.writable(&package));
        refused(store.put_entry(&package, &windows(), b"new".to_vec()));
        refused(
            store
                .put_signature(&package, &linux(), signed(&package, b"build"))
                .map(|_| ()),
        );
        refused(store.remove_signature(&package, &linux()).map(|_| ()));
        refused(store.delete_entry(&package, &linux()).map(|_| ()));
        refused(store.delete_set(&package).map(|_| ()));
        refused(blobs.put(&mut &b"bytes"[..]).map(|_| ()));
        let sha256 = hex::encode(Sha256::digest(b"build"));
        refused(blobs.delete(&sha256));
        assert!(blobs.exists(&sha256).expect("exists"));
        assert!(!blobs.exists(&"0".repeat(64)).expect("exists"));
        assert!(blobs.get("../x").is_err(), "only a hash names a blob");
        assert_eq!(
            store.list()[0].entries[0].signature_state,
            SignatureState::Valid
        );
        assert_eq!(store.list().len(), 1);
    }

    /// The contract every source of a repository keeps.
    fn contract(new: &dyn Fn() -> Box<dyn Writer>) {
        a_signed_package_loads(new().as_ref());
        what_is_not_well_formed_is_set_aside_once(new().as_ref());
        a_signature_that_does_not_verify_withholds_its_entry(new().as_ref());
        other_files_are_ignored(new().as_ref());
        nothing_is_written(new().as_ref());
        the_store_follows_each_listing(new().as_ref());
        a_package_that_leaves_is_missing_until_it_is_back(new().as_ref());
        a_pinned_package_keeps_its_entries(new().as_ref());
    }

    /// The entries of a Package an Agent's assignment pins do not change: a Manifest that gives
    /// it other entries is refused with one warning, the store keeps the entries it had while
    /// their Blobs are there and holds the Package missing once they are gone, and the new entries
    /// are taken once no assignment pins it.
    fn a_pinned_package_keeps_its_entries(writer: &dyn Writer) {
        let package = id("otelcol", "1.0.0");
        publish(
            writer,
            &package,
            &[signed_entry(&package, linux(), b"first build")],
        );
        let mut repository = writer.open();
        let store = store_on(&mut repository, armed());
        let pinned = |_: &PackageId| true;
        let hash = |store: &PackageStore| store.artifact(&package, &linux()).map(|(hash, _)| hash);

        publish(
            writer,
            &package,
            &[signed_entry(&package, linux(), b"second build")],
        );
        let (changed, logs) = logged(|| {
            (0..3)
                .map(|_| {
                    store
                        .replace(repository.read().expect("read"), &pinned)
                        .expect("replace")
                })
                .collect::<Vec<bool>>()
        });
        assert_eq!(changed, vec![false; 3], "nothing changes");
        assert_eq!(
            hash(&store),
            Some(Sha256::digest(b"first build").to_vec()),
            "the store keeps the entries it had"
        );
        assert_eq!(
            store.list()[0].entries[0].signature_state,
            SignatureState::Valid
        );
        assert_eq!(
            logs.matches("changes the entries").count(),
            1,
            "one warning over three listings: {logs}"
        );

        writer.remove(&format!(
            "blobs/{}",
            hex::encode(Sha256::digest(b"first build"))
        ));
        assert!(store
            .replace(repository.read().expect("read"), &pinned)
            .expect("replace"));
        assert!(!store.holds(&package), "its Blobs are gone: it is missing");

        assert!(store
            .replace(repository.read().expect("read"), &|_| false)
            .expect("replace"));
        assert_eq!(
            hash(&store),
            Some(Sha256::digest(b"second build").to_vec()),
            "with no assignment pinning it, the new entries are taken"
        );
    }

    /// A Package written after the startup is in the store after the next listing, and its
    /// signature is checked then; one that does not verify is named once, not at every listing.
    fn the_store_follows_each_listing(writer: &dyn Writer) {
        let mut repository = writer.open();
        let store = store_on(&mut repository, armed());
        assert!(store.is_empty(), "an empty repository offers nothing");

        let package = id("otelcol", "1.0.0");
        let stranger = classis_core::package::testing::TestRoot::new().signer();
        let hash = Sha256::digest(b"windows build");
        publish(
            writer,
            &package,
            &[
                signed_entry(&package, linux(), b"linux build"),
                Written {
                    platform: windows(),
                    artifact: b"windows build",
                    signature: Some(stranger.sign_artifact("otelcol", "1.0.0", &hash)),
                },
            ],
        );
        let (_, logs) = logged(|| {
            store
                .replace(repository.read().expect("read"), &|_| false)
                .expect("replace")
        });
        assert!(
            !store.is_empty(),
            "the first Package declares OffersPackages"
        );
        let states: Vec<SignatureState> = store.list()[0]
            .entries
            .iter()
            .map(|entry| entry.signature_state)
            .collect();
        assert_eq!(states, vec![SignatureState::Valid, SignatureState::Missing]);
        assert_eq!(
            logs.matches("does not verify").count(),
            1,
            "the new Package's signatures are checked: {logs}"
        );

        let (_, logs) = logged(|| {
            for _ in 0..10 {
                store
                    .replace(repository.read().expect("read"), &|_| false)
                    .expect("replace");
            }
        });
        assert!(
            !logs.contains("WARN"),
            "an unchanged Package is not checked again: {logs}"
        );
        assert_eq!(
            store.list()[0].entries[0].signature_state,
            SignatureState::Valid
        );
    }

    /// A Package whose manifest is removed leaves the store at the next listing: a Deployment that
    /// holds it names it missing, nothing of it is offered or served, and it all works again once
    /// the manifest is back.
    fn a_package_that_leaves_is_missing_until_it_is_back(writer: &dyn Writer) {
        let package = id("otelcol", "1.0.0");
        publish(
            writer,
            &package,
            &[signed_entry(&package, linux(), b"build")],
        );
        let mut repository = writer.open();
        let store = store_on(&mut repository, armed());
        let deployment = crate::deployments::Deployment {
            name: "stable".to_string(),
            selector: BTreeMap::from([("channel".to_string(), "stable".to_string())]),
            packages: BTreeMap::from([(package.agent_type.clone(), package.clone())]),
            configurations: Default::default(),
        };
        let attr = opamp::attributes::string_attr;
        let host = opamp::proto::AgentDescription {
            identifying_attributes: vec![attr(opamp::attributes::SERVICE_NAME, "otelcol")],
            non_identifying_attributes: vec![
                attr(opamp::attributes::OS_TYPE, "linux"),
                attr(opamp::attributes::HOST_ARCH, "amd64"),
            ],
        };
        assert!(store.missing_in(&deployment).is_empty());
        assert!(store
            .offer_for_assigned(Some(&package), Some(&host))
            .is_some());

        writer.remove(&format!("packages/{package}.json"));
        store
            .replace(repository.read().expect("read"), &|_| false)
            .expect("replace");
        assert!(
            store.list().is_empty(),
            "the Package is absent from the list"
        );
        assert!(!store.holds(&package));
        assert_eq!(store.missing_in(&deployment), vec![package.display_name()]);
        assert!(
            store
                .offer_for_assigned(Some(&package), Some(&host))
                .is_none(),
            "an Agent it is assigned to is offered nothing"
        );
        assert!(
            store.artifact(&package, &linux()).is_none(),
            "nothing is served"
        );

        publish(
            writer,
            &package,
            &[signed_entry(&package, linux(), b"build")],
        );
        store
            .replace(repository.read().expect("read"), &|_| false)
            .expect("replace");
        assert!(store.missing_in(&deployment).is_empty(), "it is back");
        assert!(store
            .offer_for_assigned(Some(&package), Some(&host))
            .is_some());
        assert_eq!(
            store.list()[0].entries[0].signature_state,
            SignatureState::Valid
        );
    }

    #[test]
    fn the_repository_contract_holds_on_a_directory() {
        contract(&|| Box::new(Directory::new()));
    }

    /// The contract on a bucket, and what only a bucket shows. The contract runs against the
    /// store `CLASSIS_TEST_S3_*` names, each part under a prefix of its own, and says aloud that it
    /// is skipped when none is named; the rest answers from a stub on the loopback.
    mod s3 {
        use super::*;
        use crate::s3::tests::{again, config_for, named_store, reply, store_answering};
        use futures_util::TryStreamExt as _;
        use object_store::PutPayload;

        /// A repository under a prefix of its own in the named bucket. What it wrote goes when it
        /// is dropped.
        struct Bucket {
            config: S3BlobsConfig,
            client: Arc<object_store::aws::AmazonS3>,
            bridge: Bridge,
        }

        impl Bucket {
            fn new(config: S3BlobsConfig) -> Self {
                let bridge = Bridge::new("repository-test").expect("bridge");
                let client = crate::s3::connect(
                    &config,
                    REPOSITORY_S3,
                    &bridge,
                    crate::s3::LIMITS,
                    Duration::ZERO,
                    Duration::ZERO,
                )
                .expect("connect to the named store");
                Bucket {
                    config,
                    client,
                    bridge,
                }
            }

            fn key(&self, key: &str) -> Key {
                Key::parse(format!("{}{key}", self.config.prefix)).expect("key")
            }
        }

        impl Writer for Bucket {
            fn put(&self, key: &str, bytes: &[u8]) {
                let client = Arc::clone(&self.client);
                let key = self.key(key);
                let payload = PutPayload::from(bytes.to_vec());
                self.bridge
                    .run(async move { client.put(&key, payload).await })
                    .expect("put");
            }

            fn remove(&self, key: &str) {
                let client = Arc::clone(&self.client);
                let key = self.key(key);
                self.bridge
                    .run(async move { client.delete(&key).await })
                    .expect("delete");
            }

            fn open(&self) -> Repository {
                Repository::open_bucket(&again(&self.config)).expect("open the repository")
            }
        }

        impl Drop for Bucket {
            /// Leaves the bucket as the test found it.
            fn drop(&mut self) {
                let client = Arc::clone(&self.client);
                let root = Key::parse(self.config.prefix.trim_end_matches('/')).expect("prefix");
                self.bridge.run(async move {
                    let objects: Vec<ObjectMeta> = client
                        .list(Some(&root))
                        .try_collect()
                        .await
                        .unwrap_or_default();
                    for object in objects {
                        // What is left behind is under a random prefix no other test reads.
                        let _ = client.delete(&object.location).await;
                    }
                });
            }
        }

        #[test]
        fn the_repository_contract_holds_on_s3() {
            if named_store().is_none() {
                return;
            }
            contract(&|| Box::new(Bucket::new(named_store().expect("named above"))));
        }

        /// Limits that fail a call to the stub within seconds.
        const QUICK: Limits = Limits {
            connect: Duration::from_secs(1),
            silence: Duration::from_secs(2),
            retries: 0,
            retry_for: Duration::from_millis(1),
        };

        /// A listing of `prefix` that holds `objects`, each a key and its size, as S3 answers it.
        fn listing(prefix: &str, objects: &[(String, usize)]) -> String {
            let contents: String = objects
                .iter()
                .map(|(key, size)| {
                    format!(
                        "<Contents><Key>{key}</Key><LastModified>2026-01-01T00:00:00.000Z\
                         </LastModified><ETag>&quot;x&quot;</ETag><Size>{size}</Size>\
                         <StorageClass>STANDARD</StorageClass></Contents>"
                    )
                })
                .collect();
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult \
                 xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>fleet</Name>\
                 <Prefix>{prefix}</Prefix><KeyCount>{}</KeyCount><MaxKeys>1000</MaxKeys>\
                 <Delimiter>/</Delimiter><IsTruncated>false</IsTruncated>{contents}\
                 </ListBucketResult>",
                objects.len()
            )
        }

        /// The Server only lists and reads its bucket: every request it sends to open it, read
        /// it and serve a download from it is a `GET` or a `HEAD`. Needs no store.
        #[test]
        fn no_request_to_the_bucket_writes_or_deletes() {
            let package = id("otelcol", "1.0.0");
            let artifact: &[u8] = b"build";
            let sha256 = hex::encode(Sha256::digest(artifact));
            let manifest = String::from_utf8(manifest(
                &package,
                &[signed_entry(&package, linux(), artifact)],
            ))
            .expect("utf-8");
            // In the order the Server asks: the prefix when it opens, then the Manifests, each
            // Manifest, the Blobs, and the download.
            let (port, requests) = store_answering(vec![
                reply(200, &listing("p/", &[])),
                reply(
                    200,
                    &listing(
                        "p/packages/",
                        &[("p/packages/otelcol@1.0.0.json".to_string(), manifest.len())],
                    ),
                ),
                reply(200, &manifest),
                reply(
                    200,
                    &listing("p/blobs/", &[(format!("p/blobs/{sha256}"), 5)]),
                ),
                reply(200, "build"),
                reply(200, ""),
            ]);
            let dir = tempfile::tempdir().expect("tempdir");
            let mut config = config_for(port, dir.path());
            config.prefix = "p/".to_string();

            let mut repository =
                Repository::open_bucket_within(&config, QUICK, Duration::ZERO, Duration::ZERO)
                    .expect("open");
            let packages = repository.read().expect("read");
            assert_eq!(packages.len(), 1);
            let blobs = repository.blob_store();
            assert_eq!(read_all(blobs.get(&sha256).expect("get")), artifact);
            assert!(blobs.exists(&sha256).expect("exists"));

            let requests = requests.lock().expect("requests").clone();
            assert_eq!(requests.len(), 6, "{requests:?}");
            for line in &requests {
                assert!(
                    line.starts_with("GET ") || line.starts_with("HEAD "),
                    "{line} — of {requests:?}"
                );
            }
        }

        /// A listing that the bucket refuses after the startup is an error, so the Packages in
        /// use stay as they are. Needs no store.
        #[test]
        fn a_listing_the_bucket_refuses_fails() {
            let (port, _) = store_answering(vec![
                reply(200, &listing("", &[])),
                reply(500, "<Error><Code>InternalError</Code></Error>"),
            ]);
            let dir = tempfile::tempdir().expect("tempdir");
            let mut repository = Repository::open_bucket_within(
                &config_for(port, dir.path()),
                QUICK,
                Duration::ZERO,
                Duration::ZERO,
            )
            .expect("open");
            let failed = repository.read().err().expect("the listing fails");
            assert!(failed.contains("cannot list packages/"), "{failed}");
        }

        /// A bucket that does not exist, or credentials it refuses, stop the open at once, naming
        /// the section and the bucket; a store that does not answer yet is asked again. Needs no
        /// store.
        #[test]
        fn a_bucket_it_cannot_list_fails_the_open_and_a_silent_one_is_asked_again() {
            let dir = tempfile::tempdir().expect("tempdir");
            let ask = |replies: Vec<String>| {
                let (port, requests) = store_answering(replies);
                let opened = Repository::open_bucket_within(
                    &config_for(port, dir.path()),
                    QUICK,
                    Duration::from_secs(20),
                    Duration::from_millis(50),
                )
                .map(|_| ());
                let asked = requests.lock().expect("requests").len();
                (opened, asked)
            };

            let (opened, asked) = ask(vec![reply(
                404,
                "<Error><Code>NoSuchBucket</Code><Message>no such bucket</Message></Error>",
            )]);
            let refused = opened.expect_err("no such bucket");
            assert!(
                refused.contains("[packages.repository.s3] bucket fleet"),
                "{refused}"
            );
            assert_eq!(asked, 1, "a missing bucket is asked once");

            let (opened, asked) = ask(vec![reply(
                403,
                "<Error><Code>AccessDenied</Code><Message>denied</Message></Error>",
            )]);
            assert!(opened.is_err());
            assert_eq!(asked, 1, "refused credentials are asked once");

            let (opened, asked) = ask(vec![
                reply(503, "<Error><Code>SlowDown</Code></Error>"),
                reply(503, "<Error><Code>SlowDown</Code></Error>"),
                reply(200, &listing("", &[])),
            ]);
            assert_eq!(opened, Ok(()), "it opened once the store answered");
            assert_eq!(asked, 3, "it asked again after each server error");
        }
    }

    #[test]
    fn a_directory_that_does_not_exist_fails_the_open_naming_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("missing");
        let refused = Repository::open_directory(&missing).expect_err("refused");
        assert!(
            refused.contains("[packages.repository] path") && refused.contains("missing"),
            "{refused}"
        );
        let file = dir.path().join("file");
        std::fs::write(&file, b"x").expect("write");
        let refused = Repository::open_directory(&file).expect_err("refused");
        assert!(refused.contains("not a directory"), "{refused}");
    }

    /// A directory that goes away after the startup fails the listing, rather than reading as an
    /// empty repository and taking every Package away; it reads again once it is back.
    #[test]
    fn a_directory_that_goes_away_fails_the_listing() {
        let writer = Directory::new();
        let package = id("otelcol", "1.0.0");
        publish(
            &writer,
            &package,
            &[signed_entry(&package, linux(), b"build")],
        );
        let mut repository = writer.open();
        assert_eq!(repository.read().expect("read").len(), 1);

        let moved = writer.0.path().with_extension("moved");
        std::fs::rename(writer.0.path(), &moved).expect("move the repository away");
        let failed = repository.read().err().expect("the listing fails");
        assert!(failed.contains("no longer a directory"), "{failed}");
        std::fs::rename(&moved, writer.0.path()).expect("move it back");
        assert_eq!(repository.read().expect("read").len(), 1);
    }

    /// Polls `done` until it holds, for a few seconds at most.
    async fn wait_until(what: &str, done: impl Fn() -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !done() {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {what}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// The listing at an interval: a Package written while the Server runs is in the store within
    /// one interval and one listing, and a listing that fails keeps the Packages of the last one,
    /// with one warning that names the failure and a message once the listings succeed again.
    #[test]
    fn the_repository_is_read_again_at_each_interval() {
        let writer = Directory::new();
        let mut repository = writer.open();
        let store = Arc::new(store_on(&mut repository, armed()));
        let package = id("otelcol", "1.0.0");
        // One thread for the loop and the test, so the loop's own log is the one read below.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let (_, logs) = logged_with(|so_far| {
            runtime.block_on(async {
                let listed = Arc::clone(&store);
                let task = tokio::spawn(
                    repository.reread_every(Duration::from_millis(50), move |packages| {
                        listed.replace(packages, &|_| false).map(|_| ())
                    }),
                );
                publish(
                    &writer,
                    &package,
                    &[signed_entry(&package, linux(), b"build")],
                );
                wait_until("the new Package", || store.holds(&package)).await;

                let moved = writer.0.path().with_extension("moved");
                std::fs::rename(writer.0.path(), &moved).expect("move the repository away");
                wait_until("a warning that names the failure", || {
                    so_far().contains("no longer a directory")
                })
                .await;
                // More listings that fail alike: however many run, none warns again.
                tokio::time::sleep(Duration::from_millis(200)).await;
                assert!(store.holds(&package), "the last listing stays in use");
                std::fs::rename(&moved, writer.0.path()).expect("move it back");
                wait_until("the listings to succeed again", || {
                    so_far().contains("listed again")
                })
                .await;
                task.abort();
            });
        });
        assert_eq!(
            logs.matches("no longer a directory").count(),
            1,
            "one warning for listings that fail alike: {logs}"
        );
        assert!(logs.contains("listed again"), "{logs}");
    }

    /// A Manifest that is not a regular file, such as a named pipe that would hold its open, is
    /// set aside, and the listing goes on.
    #[cfg(unix)]
    #[test]
    fn a_manifest_that_is_not_a_regular_file_is_set_aside() {
        let writer = Directory::new();
        let package = id("otelcol", "1.0.0");
        publish(
            &writer,
            &package,
            &[signed_entry(&package, linux(), b"build")],
        );
        let pipe = writer.0.path().join("packages/pipe@1.0.0.json");
        let made = std::process::Command::new("mkfifo")
            .arg(&pipe)
            .status()
            .expect("mkfifo");
        assert!(made.success(), "mkfifo {}", pipe.display());
        let mut repository = writer.open();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            // A test that gave up waiting no longer receives.
            let _ = sender.send(logged(|| repository.read()));
        });
        let (read, logs) = receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("the listing does not wait on the pipe");
        let loaded: Vec<String> = read
            .expect("read")
            .iter()
            .map(|p| p.id.to_string())
            .collect();
        assert_eq!(loaded, vec!["otelcol@1.0.0"]);
        assert!(
            logs.contains("pipe@1.0.0.json is not a regular file"),
            "{logs}"
        );
    }

    /// A read-only mount reads as any other directory: the Server needs read access alone.
    #[cfg(unix)]
    #[test]
    fn a_read_only_directory_is_read_without_error() {
        use std::os::unix::fs::PermissionsExt;
        let writer = Directory::new();
        let package = id("otelcol", "1.0.0");
        publish(
            &writer,
            &package,
            &[signed_entry(&package, linux(), b"build")],
        );
        let read_only = |path: &Path, mode: u32| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
        };
        let sha256 = hex::encode(Sha256::digest(b"build"));
        read_only(&writer.0.path().join("blobs").join(&sha256), 0o444);
        read_only(&writer.0.path().join("packages/otelcol@1.0.0.json"), 0o444);
        for dir in ["blobs", "packages", ""] {
            read_only(&writer.0.path().join(dir), 0o555);
        }
        let store = store_on(&mut writer.open(), armed());
        let (sha256, _) = store.artifact(&package, &linux()).expect("an entry");
        assert_eq!(
            read_all(store.open_artifact(&sha256).expect("open")),
            b"build"
        );
        for dir in ["", "packages", "blobs"] {
            read_only(&writer.0.path().join(dir), 0o755);
        }
    }

    /// The data directory of a Server that keeps its Packages on the filesystem is a repository
    /// already: a second Server reads the same Packages, with the same signature states.
    #[test]
    fn the_data_directory_of_a_server_is_a_repository() {
        let dir = tempfile::tempdir().expect("tempdir");
        let uploaded = crate::packages::test_signing::open_store(dir.path()).expect("store");
        let package = id("otelcol", "1.0.0");
        uploaded.create(&package).expect("create");
        uploaded
            .put_entry(&package, &linux(), b"linux build".to_vec())
            .expect("upload");
        uploaded
            .put_entry(&package, &windows(), b"windows build".to_vec())
            .expect("upload");
        uploaded
            .put_signature(&package, &linux(), signed(&package, b"linux build"))
            .expect("sign");
        uploaded.create(&id("empty", "1.0.0")).expect("create");

        let read = store_on(
            &mut Repository::open_directory(dir.path()).expect("open"),
            armed(),
        );
        // Each Package, and each of its entries as its platform, its hash and its state.
        type View = Vec<(String, Vec<(String, String, SignatureState)>)>;
        let view = |store: &PackageStore| -> View {
            store
                .list()
                .into_iter()
                .map(|summary| {
                    (
                        summary.id.to_string(),
                        summary
                            .entries
                            .into_iter()
                            .map(|e| (e.os, e.content_hash, e.signature_state))
                            .collect(),
                    )
                })
                .collect()
        };
        assert_eq!(view(&read), view(&uploaded));
    }
}
