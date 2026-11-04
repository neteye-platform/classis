//! Enrolment: the client certificate this Client asks the Server to issue (ADR-0021).
//!
//! The Baseline's CSR flow keeps the private key on the host. This module generates that key and
//! the request over its public half, and takes in the certificate that comes back through the
//! ordinary connection-settings offer. What leaves the host is a signing request; what is written
//! beside it is a key nothing ever sends.
//!
//! Enrolment is driven by capability, not by a switch in `supervisor.toml`: a Client asks when the
//! Server says it signs (`AcceptsConnectionSettingsRequest`) and it has no certificate, or the one
//! it holds is two thirds through its life. A Server that declares nothing is never asked, which is
//! the protocol's own negotiation rule — and a certificate obtained before mutual TLS is switched
//! on is exactly what makes switching it on uneventful.

use std::path::Path;

use rcgen::{CertificateParams, KeyPair};
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::config::ClientConfig;
use crate::nofollow::HeldDir;
use crate::tls::{
    ISSUED_CERT_FILE, ISSUED_KEY_FILE, PENDING_CERT_FILE, PENDING_CSR_FILE, PENDING_KEY_FILE,
};

/// A certificate is renewed once it is this far through its validity — early enough that a Server
/// that cannot sign for a while costs nothing, and that the attempt can fail twice before the
/// certificate it replaces actually expires.
const RENEW_AFTER: f64 = 2.0 / 3.0;

/// The PEM certificate signing request to send, or `None` when this Client needs no certificate
/// right now.
///
/// A request in flight is re-sent unchanged until it is answered: an enrolment waits for an
/// operator, and the Server's queue knows a request by its public key (ADR-0021 clause 21).
/// Generating one **writes the private key** to the state directory before the request goes out,
/// as a pending key beside the one in force, so an answer arriving after a restart is still usable
/// and the certificate in force keeps its own key until the new one is proved.
pub fn request(config: &ClientConfig) -> Option<Vec<u8>> {
    if !needs_certificate(config) {
        return None;
    }
    if let Some(pending) = pending(config) {
        return Some(pending);
    }
    match generate(config) {
        Ok(csr) => {
            info!("requesting a client certificate from the Server");
            Some(csr)
        }
        Err(e) => {
            warn!(error = %e, "cannot build a certificate signing request");
            None
        }
    }
}

/// Stores an issued certificate beside the key it was requested for, putting it in force on the
/// next connection (ADR-0021).
///
/// The certificate and its key are two files, so the swap runs in an order every step of which
/// [`recover`] completes: the certificate is staged whole beside the pending key, then the key goes
/// into force, then the certificate. A crash after the staging leaves the old pair in force and
/// the new one staged; a crash after the key leaves the staged certificate as the one thing to
/// finish.
///
/// # Errors
/// Returns an error when the certificate cannot be written, or when no pending key is there to go
/// with it — a certificate this Client did not ask for is refused rather than stored.
pub fn accept(state_dir: &Path, cert_pem: &[u8]) -> Result<(), String> {
    let pending = state_dir.join(PENDING_KEY_FILE);
    if !pending.exists() {
        return Err(format!(
            "an offered certificate has no key to go with it — {} is missing",
            pending.display()
        ));
    }
    // Whole or not at all, through a temporary name and a rename in the held directory, so a link
    // the service's account put at either name is replaced rather than written through (ADR-0054).
    // Owner-only, as every file of the Client's in a state directory the process account's group
    // may pass through (ADR-0059 clause 6).
    held(state_dir)?
        .write(PENDING_CERT_FILE, cert_pem, 0o600)
        .map_err(|e| format!("cannot store the issued certificate: {e}"))?;
    recover(state_dir)
}

/// The state directory, held without following a link at its name: an install enrols as root in a
/// directory that belongs to the service's account (ADR-0054).
fn held(state_dir: &Path) -> Result<HeldDir, String> {
    HeldDir::open(state_dir).map_err(|e| format!("cannot open {}: {e}", state_dir.display()))
}

/// Completes a swap [`accept`] began, when one was cut short: a staged certificate goes into force
/// beside the key it certifies — the pending key, which goes into force first, or the key already
/// in force when the crash came between the two renames. A staged certificate that certifies
/// neither is stale and dropped, so it is never paired with a key it does not belong to. Nothing
/// staged is nothing to do — a pending key alone is a request in flight. Run before the identity
/// in force is read.
///
/// # Errors
/// Returns an error when a file of the swap cannot be renamed or removed.
pub fn recover(state_dir: &Path) -> Result<(), String> {
    // A state directory not made yet holds nothing to recover; one that is a link is refused.
    let dir = match HeldDir::open(state_dir) {
        Ok(dir) => dir,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("cannot open {}: {e}", state_dir.display())),
    };
    let cert_pem = match dir.read(PENDING_CERT_FILE) {
        Ok(cert_pem) => cert_pem,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(format!(
                "cannot read {}: {e}",
                state_dir.join(PENDING_CERT_FILE).display()
            ))
        }
    };
    if certifies(&dir, &cert_pem, PENDING_KEY_FILE) {
        dir.rename(PENDING_KEY_FILE, ISSUED_KEY_FILE)
            .map_err(|e| format!("cannot put the issued key in force: {e}"))?;
    } else if !certifies(&dir, &cert_pem, ISSUED_KEY_FILE) {
        let staged = state_dir.join(PENDING_CERT_FILE);
        warn!(file = %staged.display(), "a staged certificate certifies no key on this host; dropping it");
        return dir
            .remove(PENDING_CERT_FILE)
            .map_err(|e| format!("cannot remove {}: {e}", staged.display()));
    }
    dir.rename(PENDING_CERT_FILE, ISSUED_CERT_FILE)
        .map_err(|e| format!("cannot put the issued certificate in force: {e}"))?;
    // The request is answered — unless a later one is in flight beside it.
    if !state_dir.join(PENDING_KEY_FILE).exists() {
        let _ = dir.remove(PENDING_CSR_FILE);
    }
    Ok(())
}

/// Whether the PEM certificate `cert_pem` is issued for the private key in the file `key_name`.
fn certifies(dir: &HeldDir, cert_pem: &[u8], key_name: &str) -> bool {
    use rcgen::PublicKeyData as _;
    let Ok(key_bytes) = dir.read(key_name).map(Zeroizing::new) else {
        return false;
    };
    let Ok(key_pem) = std::str::from_utf8(&key_bytes) else {
        return false;
    };
    let Ok(key) = KeyPair::from_pem(key_pem) else {
        return false;
    };
    let Ok((_, block)) = x509_parser::pem::parse_x509_pem(cert_pem) else {
        return false;
    };
    block
        .parse_x509()
        .is_ok_and(|cert| cert.public_key().raw == key.subject_public_key_info().as_slice())
}

/// The SHA-256 fingerprint of the key a request in flight asks to be certified — the one logged
/// when the request was generated, and the `id` the Server's queue lists it under (ADR-0021
/// clause 22). `None` when no request is in flight or its key cannot be read.
#[must_use]
pub fn pending_fingerprint(state_dir: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    let pem = Zeroizing::new(crate::nofollow::read(&state_dir.join(PENDING_KEY_FILE)).ok()?);
    let key = KeyPair::from_pem(std::str::from_utf8(&pem).ok()?).ok()?;
    Some(hex::encode(Sha256::digest(key.public_key_raw())))
}

/// The request in flight, if one is: its key and its CSR are both on disk.
fn pending(config: &ClientConfig) -> Option<Vec<u8>> {
    if !config.state_dir.join(PENDING_KEY_FILE).exists() {
        return None;
    }
    crate::nofollow::read(&config.state_dir.join(PENDING_CSR_FILE)).ok()
}

/// Whether this Client should ask for a certificate: it has none, or the one it has is into its
/// renewal window.
fn needs_certificate(config: &ClientConfig) -> bool {
    let cert = config.state_dir.join(ISSUED_CERT_FILE);
    let key = config.state_dir.join(ISSUED_KEY_FILE);
    if !cert.exists() || !key.exists() {
        return true;
    }
    match renewal_due(&cert) {
        Ok(due) => due,
        Err(e) => {
            // A certificate that cannot be read is one that cannot be presented either; asking for
            // a new one is the recovery, and refusing to ask would strand the host.
            warn!(error = %e, "cannot read the stored client certificate; requesting a new one");
            true
        }
    }
}

/// Whether the stored certificate is at least [`RENEW_AFTER`] through its validity.
///
/// Read with `x509-parser` — the parser rcgen itself uses, whose own X.509 entry point is private.
fn renewal_due(cert_file: &Path) -> Result<bool, String> {
    let pem = crate::nofollow::read(cert_file)
        .map_err(|e| format!("cannot read {}: {e}", cert_file.display()))?;
    let (_, block) = x509_parser::pem::parse_x509_pem(&pem)
        .map_err(|e| format!("cannot read {}: {e}", cert_file.display()))?;
    let certificate = block
        .parse_x509()
        .map_err(|e| format!("cannot read {}: {e}", cert_file.display()))?;
    let validity = certificate.validity();
    let (not_before, not_after) = (
        validity.not_before.to_datetime(),
        validity.not_after.to_datetime(),
    );
    let life = not_after - not_before;
    if life <= time::Duration::ZERO {
        return Ok(true);
    }
    let elapsed = time::OffsetDateTime::now_utc() - not_before;
    Ok(elapsed.as_seconds_f64() >= life.as_seconds_f64() * RENEW_AFTER)
}

/// Generates the keypair and the request over it. The key lands in the state directory; only the
/// request travels.
fn generate(config: &ClientConfig) -> Result<Vec<u8>, String> {
    let key = KeyPair::generate().map_err(|e| format!("cannot generate a key: {e}"))?;
    // The subject says which Client this is, for a human reading a certificate — never for the
    // Server to match on (ADR-0021): identity is `instance_uid`, and the Server may re-key it.
    let mut params = CertificateParams::new(vec![config.name.clone()])
        .map_err(|e| format!("cannot build a certificate request: {e}"))?;
    // The subject an operator reads in the enrolment queue (ADR-0021 clause 22); rcgen's default
    // names every host alike.
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, config.name.clone());
    // A renewal says which certificate it renews, signed with that certificate's key (ADR-0021
    // clause 27): the Server carries the host on from it even when a Gateway is in between.
    if let Some(proof) = renewal_proof(config, &key) {
        let uri = rcgen::string::Ia5String::try_from(proof)
            .map_err(|e| format!("cannot build a renewal proof: {e}"))?;
        params.subject_alt_names.push(rcgen::SanType::URI(uri));
    } else if let Some(proof) = bootstrap_proof(config, &key) {
        // An enrolment says which bootstrap certificate it enrols with, signed with its key
        // (ADR-0039): the Server files the request under it, directly or through a Gateway.
        let uri = rcgen::string::Ia5String::try_from(proof)
            .map_err(|e| format!("cannot build a bootstrap proof: {e}"))?;
        params.subject_alt_names.push(rcgen::SanType::URI(uri));
    }
    let csr = params
        .serialize_request(&key)
        .map_err(|e| format!("cannot build a certificate request: {e}"))?
        .pem()
        .map_err(|e| format!("cannot encode the certificate request: {e}"))?;

    // Held without following a link at its name, and each file written whole over a link at its
    // own: an install enrols as root in a directory that belongs to the service's account
    // (ADR-0054). Passed through by the process group where one is registered (ADR-0059 clause 6).
    crate::storage::create_shared_dir(
        &config.state_dir,
        &config.state_dir,
        config.process_account_group,
        crate::storage::Shared::Traversed,
    )
    .map_err(|e| format!("cannot create {}: {e}", config.state_dir.display()))?;
    let dir = HeldDir::open(&config.state_dir)
        .map_err(|e| format!("cannot open {}: {e}", config.state_dir.display()))?;
    // The key is written no wider than its owner, the mode set in the open call so it is never on
    // disk at the umask default even briefly; it replaces a key file a prior enrolment left at a
    // wider mode. On Windows the state directory's ACL under `%ProgramData%` protects it
    // (ADR-0019).
    dir.write(
        PENDING_KEY_FILE,
        Zeroizing::new(key.serialize_pem()).as_bytes(),
        0o600,
    )
    .map_err(|e| format!("cannot store the private key: {e}"))?;
    // Owner-only, as every file of the Client's in a state directory the process account's group
    // may pass through (ADR-0059 clause 6).
    dir.write(PENDING_CSR_FILE, csr.as_bytes(), 0o600)
        .map_err(|e| format!("cannot store the certificate request: {e}"))?;
    // What the operator matches in the enrolment queue (ADR-0021 clause 22): the same SHA-256 the
    // Server lists as the request's key fingerprint.
    {
        use sha2::{Digest, Sha256};
        info!(
            key_fingerprint = %hex::encode(Sha256::digest(key.public_key_raw())),
            "certificate request generated; an enrolling host waits for an operator's approval"
        );
    }
    Ok(csr.into_bytes())
}

/// The renewal proof for `new_key`, while a certificate and its key are in force; `None` for a
/// first enrolment, or when they cannot be read — the Server then renews what the connection
/// presents.
fn renewal_proof(config: &ClientConfig, new_key: &KeyPair) -> Option<String> {
    use base64::Engine as _;
    use rcgen::{PublicKeyData as _, SigningKey as _};
    use sha2::{Digest as _, Sha256};
    let dir = HeldDir::open(&config.state_dir).ok()?;
    let cert_pem = dir.read(ISSUED_CERT_FILE).ok()?;
    let key_pem = Zeroizing::new(dir.read(ISSUED_KEY_FILE).ok()?);
    let (_, block) = x509_parser::pem::parse_x509_pem(&cert_pem).ok()?;
    let old_key = KeyPair::from_pem(std::str::from_utf8(&key_pem).ok()?).ok()?;
    let new_key_sha256 = Sha256::digest(new_key.subject_public_key_info());
    let signature = old_key
        .sign(&fleet_core::renewal::statement(&new_key_sha256))
        .ok()?;
    Some(format!(
        "{}{}",
        fleet_core::renewal::URI_PREFIX,
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(fleet_core::renewal::encode(&block.contents, &signature))
    ))
}

/// The bootstrap proof for `new_key` (ADR-0039), while this Client holds no certificate the Server
/// issued: the certificate it presents — the bootstrap certificate it enrols with — and a signature
/// with that certificate's key. `None` with nothing to present, or when the pair cannot be read or
/// its key cannot sign; the Server then reads the certificate from the handshake of a direct
/// connection. A certificate an operator provisioned cannot be told apart from a bootstrap one
/// here, so it is proved the same way, and the Server renews it as one without a proof.
fn bootstrap_proof(config: &ClientConfig, new_key: &KeyPair) -> Option<String> {
    use base64::Engine as _;
    use rcgen::{PublicKeyData as _, SigningKey as _};
    use sha2::{Digest as _, Sha256};
    if config.is_enrolled() {
        return None;
    }
    let identity = crate::tls::client_tls(config).ok()?.identity?;
    // Read here only to sign: the key moves into a buffer wiped on drop (ADR-0057).
    let key_pem = Zeroizing::new(identity.key_pem);
    let certificate = opamp::tls::certificates(&identity.cert_pem).ok()?;
    let leaf = certificate.first()?;
    let key = KeyPair::from_pem(std::str::from_utf8(&key_pem).ok()?).ok()?;
    let new_key_sha256 = Sha256::digest(new_key.subject_public_key_info());
    let signature = key
        .sign(&fleet_core::bootstrap_proof::statement(&new_key_sha256))
        .ok()?;
    Some(format!(
        "{}{}",
        fleet_core::bootstrap_proof::URI_PREFIX,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            fleet_core::bootstrap_proof::encode(leaf.as_ref(), &signature)
        )
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(state_dir: &Path) -> ClientConfig {
        ClientConfig {
            state_dir: state_dir.to_path_buf(),
            ..ClientConfig::default()
        }
    }

    /// A fresh host asks, and the key is on disk before the request leaves — but the Client still
    /// presents nothing, because half an identity is not one.
    /// Verifies: ADR-0021
    #[test]
    fn a_client_without_a_certificate_asks_and_keeps_its_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());
        let csr = request(&config).expect("a request");
        assert!(String::from_utf8_lossy(&csr).contains("BEGIN CERTIFICATE REQUEST"));
        assert!(dir.path().join(PENDING_KEY_FILE).exists());
        assert!(config.client_identity().is_none(), "a key alone is inert");
        assert_eq!(
            request(&config).expect("asked again"),
            csr,
            "a request in flight is re-sent unchanged until it is answered"
        );
    }

    /// The private key is never on disk wider than its owner — set in the open call, so there is no
    /// window between a world-readable create and a later chmod for a local attacker to read it.
    #[cfg(unix)]
    /// Verifies: ADR-0021
    #[test]
    fn the_private_key_is_written_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());
        request(&config).expect("a request");

        let mode = dir
            .path()
            .join(PENDING_KEY_FILE)
            .metadata()
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the private key must be owner-only");
    }

    /// A state directory the request creates is owner-only, like every other one the Client
    /// creates for its secrets — the key in it is `0600`, and the directory listing is no wider.
    #[cfg(unix)]
    /// Verifies: ADR-0021
    #[test]
    fn the_state_directory_a_request_creates_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let state_dir = dir.path().join("state");
        request(&config(&state_dir)).expect("a request");
        let mode = state_dir.metadata().expect("metadata").permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o700,
            "the state directory must be owner-only"
        );
    }

    /// Where a process account is registered, its group passes through the state directory, and
    /// the request and the certificate are the Client's alone: `0600`, beside the key.
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn with_a_process_account_the_request_and_the_certificate_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let state_dir = dir.path().join("state");
        let mut config = config(&state_dir);
        // SAFETY: getegid(2) cannot fail and touches no memory.
        let group = unsafe { libc::getegid() };
        config.process_account_group = Some(crate::supervisor::ports::ProcessAccountGroup(group));
        let signed = sign(request(&config).expect("a request"));
        let mode = |name: &str| {
            state_dir
                .join(name)
                .metadata()
                .expect("metadata")
                .permissions()
                .mode()
                & 0o7777
        };
        assert_eq!(
            mode(""),
            0o710,
            "passed through by the process account's group"
        );
        assert_eq!(mode(PENDING_CSR_FILE), 0o600);
        accept(&state_dir, signed.as_bytes()).expect("accept");
        assert_eq!(mode(ISSUED_CERT_FILE), 0o600);
        assert_eq!(mode(ISSUED_KEY_FILE), 0o600);
    }

    /// Signs `csr` the way a Server does.
    fn sign(csr: Vec<u8>) -> String {
        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca_params = CertificateParams::new(vec!["test-ca".to_string()]).expect("ca params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca");
        let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_cert.pem(), ca_key).expect("issuer");
        rcgen::CertificateSigningRequestParams::from_pem(&String::from_utf8(csr).unwrap())
            .expect("csr")
            .signed_by(&issuer)
            .expect("signed")
            .pem()
    }

    /// Whether the certificate and the key in force belong together.
    fn pair_in_force_matches(state_dir: &Path) -> bool {
        use rcgen::PublicKeyData as _;
        let cert_pem = std::fs::read(state_dir.join(ISSUED_CERT_FILE)).expect("certificate");
        let key_pem = std::fs::read_to_string(state_dir.join(ISSUED_KEY_FILE)).expect("key");
        let (_, block) = x509_parser::pem::parse_x509_pem(&cert_pem).expect("pem");
        let cert = block.parse_x509().expect("x509");
        let key = KeyPair::from_pem(&key_pem).expect("key pem");
        cert.public_key().raw == key.subject_public_key_info().as_slice()
    }

    /// A host enrolled once, with a renewal requested and answered: the pair in force is the old
    /// one, the pending key the new one, and `signed` its certificate.
    fn renewal_answered(state_dir: &Path) -> String {
        let config = config(state_dir);
        accept(state_dir, sign(request(&config).expect("first")).as_bytes()).expect("accept");
        sign(generate(&config).expect("a renewal request"))
    }

    /// Storing an issued certificate is two files, and a crash between them must not leave a
    /// certificate in force beside a key it does not belong to: from the certificate staged
    /// beside the pending key, and from the key put in force before the certificate, the next start
    /// completes the swap into the new pair.
    /// Verifies: ADR-0021
    #[test]
    fn a_swap_cut_short_recovers_to_a_matching_pair() {
        // Staged, nothing renamed yet.
        let dir = tempfile::tempdir().expect("tempdir");
        let signed = renewal_answered(dir.path());
        std::fs::write(dir.path().join(PENDING_CERT_FILE), &signed).expect("stage");
        recover(dir.path()).expect("recover");
        assert!(pair_in_force_matches(dir.path()));
        assert_eq!(
            std::fs::read_to_string(dir.path().join(ISSUED_CERT_FILE)).expect("cert"),
            signed,
            "the swap is completed, not undone"
        );
        assert!(!dir.path().join(PENDING_KEY_FILE).exists());
        assert!(!dir.path().join(PENDING_CERT_FILE).exists());
        assert!(!dir.path().join(PENDING_CSR_FILE).exists());

        // The key in force already, the certificate still staged.
        let dir = tempfile::tempdir().expect("tempdir");
        let signed = renewal_answered(dir.path());
        std::fs::write(dir.path().join(PENDING_CERT_FILE), &signed).expect("stage");
        std::fs::rename(
            dir.path().join(PENDING_KEY_FILE),
            dir.path().join(ISSUED_KEY_FILE),
        )
        .expect("key in force");
        assert!(!pair_in_force_matches(dir.path()), "the torn state");
        recover(dir.path()).expect("recover");
        assert!(pair_in_force_matches(dir.path()));
        assert_eq!(
            std::fs::read_to_string(dir.path().join(ISSUED_CERT_FILE)).expect("cert"),
            signed
        );
    }

    /// A request in flight with nothing staged is no torn swap: recovery leaves it alone.
    #[test]
    fn recovery_leaves_a_request_in_flight_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let _ = renewal_answered(dir.path());
        recover(dir.path()).expect("recover");
        assert!(dir.path().join(PENDING_KEY_FILE).exists());
        assert!(dir.path().join(PENDING_CSR_FILE).exists());
        assert!(pair_in_force_matches(dir.path()));
    }

    /// A staged certificate is put in force only beside the key it certifies. Left staged after
    /// its key went into force, it outlives the next renewal's pending key — and is paired with the
    /// key in force, not with that one; a staged certificate that certifies neither is dropped.
    /// Verifies: ADR-0021
    #[test]
    fn a_stale_staged_certificate_is_never_paired_with_another_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let signed = renewal_answered(dir.path());
        std::fs::write(dir.path().join(PENDING_CERT_FILE), &signed).expect("stage");
        std::fs::rename(
            dir.path().join(PENDING_KEY_FILE),
            dir.path().join(ISSUED_KEY_FILE),
        )
        .expect("key in force");
        // The next renewal, before any start completed the swap.
        generate(&config(dir.path())).expect("another request");
        let next_key = std::fs::read(dir.path().join(PENDING_KEY_FILE)).expect("pending");

        recover(dir.path()).expect("recover");
        assert!(pair_in_force_matches(dir.path()));
        assert_eq!(
            std::fs::read_to_string(dir.path().join(ISSUED_CERT_FILE)).expect("cert"),
            signed
        );
        assert_eq!(
            std::fs::read(dir.path().join(PENDING_KEY_FILE)).expect("still pending"),
            next_key,
            "the request in flight is left alone"
        );

        // A certificate for a key this host does not hold.
        let stranger =
            sign(generate(&config(tempfile::tempdir().expect("t").path())).expect("csr"));
        std::fs::write(dir.path().join(PENDING_CERT_FILE), stranger).expect("stage");
        recover(dir.path()).expect("recover");
        assert!(!dir.path().join(PENDING_CERT_FILE).exists(), "dropped");
        assert!(pair_in_force_matches(dir.path()));
        assert!(dir.path().join(PENDING_KEY_FILE).exists());
    }

    /// `accept` stopped at each of its steps — a directory standing where the step writes makes
    /// exactly that write fail — leaves a state `recover` turns into a matching pair.
    /// Verifies: ADR-0021
    #[test]
    fn accept_cut_short_at_any_step_recovers_to_a_matching_pair() {
        for (blocked, completes) in [
            (PENDING_CERT_FILE, false),
            (ISSUED_KEY_FILE, true),
            (ISSUED_CERT_FILE, true),
        ] {
            let dir = tempfile::tempdir().expect("tempdir");
            let signed = renewal_answered(dir.path());
            let target = dir.path().join(blocked);
            let _ = std::fs::remove_file(&target);
            std::fs::create_dir_all(target.join("in-the-way")).expect("block");

            accept(dir.path(), signed.as_bytes()).expect_err(blocked);
            std::fs::remove_dir_all(&target).expect("unblock");
            recover(dir.path()).expect("recover");
            assert!(pair_in_force_matches(dir.path()), "{blocked}");
            assert_eq!(
                dir.path().join(PENDING_KEY_FILE).exists(),
                !completes,
                "{blocked}: the swap is completed exactly when the certificate was staged"
            );
        }
    }

    /// What comes back is stored beside the key and is what the Client presents from then on.
    /// Verifies: ADR-0021
    #[test]
    fn an_issued_certificate_becomes_the_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());
        let csr = request(&config).expect("a request");

        // Stand in for the Server: sign what was actually sent.
        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca_params = CertificateParams::new(vec!["test-ca".to_string()]).expect("ca params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca");
        let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_cert.pem(), ca_key).expect("issuer");
        let signed =
            rcgen::CertificateSigningRequestParams::from_pem(&String::from_utf8(csr).unwrap())
                .expect("csr")
                .signed_by(&issuer)
                .expect("signed");

        accept(dir.path(), signed.pem().as_bytes()).expect("accept");
        let (cert, key) = config.client_identity().expect("an identity");
        assert_eq!(cert, dir.path().join(ISSUED_CERT_FILE));
        assert_eq!(key, dir.path().join(ISSUED_KEY_FILE));
        // And with one in force and fresh, nothing more is asked for.
        assert!(request(&config).is_none());
    }

    /// A certificate the Client never asked for has no key to go with it, and is refused rather
    /// than written where the connection code would then try to present it.
    /// Verifies: ADR-0021
    #[test]
    fn a_certificate_without_a_pending_key_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let error = accept(dir.path(), b"-----BEGIN CERTIFICATE-----").expect_err("refused");
        assert!(error.contains("no key to go with it"), "{error}");
    }

    /// The bootstrap proof `csr` carries: its certificate, and whether its signature verifies with
    /// that certificate's key over the request's own key.
    fn bootstrap_proof_of(csr: &[u8]) -> Option<(Vec<u8>, bool)> {
        use base64::Engine as _;
        use sha2::{Digest as _, Sha256};
        let der = fleet_core::csr::der(csr).expect("one PEM block");
        let encoded = fleet_core::csr::requested_uri(&der, fleet_core::bootstrap_proof::URI_PREFIX)
            .expect("a request")?;
        let content = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .expect("base64url");
        let (cert, signature) = fleet_core::bootstrap_proof::decode(&content).expect("a proof");
        let (_, request) = <x509_parser::certification_request::X509CertificationRequest as
            x509_parser::prelude::FromDer<'_, _>>::from_der(&der)
        .expect("csr");
        let new_key = Sha256::digest(request.certification_request_info.subject_pki.raw);
        let (_, parsed) =
            <x509_parser::certificate::X509Certificate as x509_parser::prelude::FromDer<'_, _>>::from_der(cert)
                .expect("certificate");
        let verifies = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            parsed.public_key().subject_public_key.data.as_ref(),
        )
        .verify(&fleet_core::bootstrap_proof::statement(&new_key), signature)
        .is_ok();
        Some((cert.to_vec(), verifies))
    }

    /// An enrolling Client proves in its request the bootstrap certificate it presents — from the
    /// configured pair, and from the identity a `bootstrap.p12` opened to — signed with its key;
    /// once it holds a certificate the Server issued, its renewal carries a renewal proof alone.
    /// Verifies: ADR-0039
    #[test]
    fn an_enrolment_request_proves_its_bootstrap_certificate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = KeyPair::generate().expect("key");
        let cert = CertificateParams::new(vec!["bootstrap".to_string()])
            .expect("params")
            .self_signed(&key)
            .expect("cert");
        std::fs::write(dir.path().join("bootstrap.pem"), cert.pem()).expect("write");
        std::fs::write(dir.path().join("bootstrap-key.pem"), key.serialize_pem()).expect("write");
        let state_dir = dir.path().join("state");
        let enrolling = ClientConfig {
            tls: Some(crate::config::TlsConfig {
                ca_file: None,
                cert_file: Some(dir.path().join("bootstrap.pem")),
                key_file: Some(dir.path().join("bootstrap-key.pem")),
            }),
            ..config(&state_dir)
        };
        let csr = request(&enrolling).expect("a request");
        assert_eq!(
            bootstrap_proof_of(&csr),
            Some((cert.der().to_vec(), true)),
            "the proof names the bootstrap certificate and its key signed the request's"
        );

        let p12_state = dir.path().join("p12-state");
        let from_p12 = ClientConfig {
            bootstrap_identity: Some(crate::config::BootstrapIdentity {
                cert_pem: cert.pem().into_bytes(),
                key_pem: zeroize::Zeroizing::new(key.serialize_pem().into_bytes()),
            }),
            ..config(&p12_state)
        };
        let csr = request(&from_p12).expect("a request");
        assert_eq!(bootstrap_proof_of(&csr), Some((cert.der().to_vec(), true)));

        accept(
            &state_dir,
            sign(request(&enrolling).expect("pending")).as_bytes(),
        )
        .expect("accept");
        let renewal = generate(&enrolling).expect("a renewal request");
        assert_eq!(
            bootstrap_proof_of(&renewal),
            None,
            "a renewal is no enrolment"
        );
        assert!(
            fleet_core::csr::requested_uri(
                &fleet_core::csr::der(&renewal).expect("one PEM block"),
                fleet_core::renewal::URI_PREFIX
            )
            .expect("a request")
            .is_some(),
            "it carries the renewal proof"
        );
    }

    /// The renewal window: a certificate two thirds through its life is asked for again, and the
    /// old one stays in force until the new one is verified.
    /// Verifies: ADR-0021
    #[test]
    fn a_certificate_in_its_renewal_window_is_requested_again() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());
        let _ = request(&config).expect("a request");

        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::new(vec!["edge-01".to_string()]).expect("params");
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(80);
        params.not_after = now + time::Duration::days(10);
        let cert = params.self_signed(&key).expect("cert");
        std::fs::write(dir.path().join(ISSUED_CERT_FILE), cert.pem()).expect("write");

        assert!(
            request(&config).is_some(),
            "eight ninths through its life is past the renewal point"
        );
    }
}
