//! When the Server's certificates end (ADR-0028).
//!
//! `server pki status` says when each certificate the Server host depends on ends, and the running
//! Server reads the same ends and warns before one of them does. The Server makes no certificate
//! authority, no server certificate and no bootstrap certificate: those are made by the operator
//! tool's `pki` commands, on the operator's machine (ADR-0028). When a certificate counts as ending
//! is [`fleet_core::ending`], so both programs judge alike.

use std::path::{Path, PathBuf};

use fleet_core::ending::Standing;
use time::OffsetDateTime;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::config::ServerConfig;

/// When one certificate ends, as `server pki status` lists it and the running Server watches it.
#[derive(Debug, Clone)]
pub struct Ending {
    pub file: PathBuf,
    pub subject: String,
    pub serial: String,
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
}

impl Ending {
    /// Where this end stands at `now`.
    #[must_use]
    pub fn standing(&self, now: OffsetDateTime) -> Standing {
        fleet_core::ending::standing(
            self.not_before.unix_timestamp(),
            self.not_after.unix_timestamp(),
            now.unix_timestamp(),
        )
    }

    /// Whole days left at `now`, negative once ended.
    #[must_use]
    pub fn days_left(&self, now: OffsetDateTime) -> i64 {
        (self.not_after - now).whole_days()
    }
}

/// Reads the first certificate of a PEM file.
///
/// # Errors
/// Returns the message to print when the file cannot be read or holds no certificate.
pub fn read_ending(file: &Path) -> Result<Ending, String> {
    let pem = std::fs::read(file).map_err(|e| format!("cannot read {}: {e}", file.display()))?;
    let der = opamp::tls::certificates(&pem)
        .map_err(|e| format!("cannot read {}: {e}", file.display()))?
        .into_iter()
        .next()
        .ok_or_else(|| format!("{} holds no certificate", file.display()))?;
    let (_, cert) = X509Certificate::from_der(der.as_ref())
        .map_err(|e| format!("cannot read {}: {e}", file.display()))?;
    Ok(Ending {
        file: file.to_path_buf(),
        subject: cert.subject().to_string(),
        serial: hex::encode(cert.raw_serial()),
        not_before: cert.validity().not_before.to_datetime(),
        not_after: cert.validity().not_after.to_datetime(),
    })
}

/// The certificates a running Server depends on (ADR-0028 clause 11): its own on each plane
/// (ADR-0032), the client CA as both `[tls]` and `[client_ca]` name it, and the bootstrap CA. Each
/// file once.
#[must_use]
pub fn depended_on(config: &ServerConfig) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Some(tls) = &config.tls {
        files.push(tls.cert_file.clone());
        files.extend(tls.client_ca_file.clone());
    }
    if let Some(operator) = &config.rest.tls {
        files.push(operator.cert_file.clone());
    }
    if let Some(ca) = &config.client_ca {
        files.push(ca.cert_file.clone());
    }
    if let Some(enrolment) = &config.enrolment {
        files.push(enrolment.bootstrap_ca_file.clone());
    }
    let mut seen = std::collections::HashSet::new();
    files.retain(|file| seen.insert(file.clone()));
    files
}

/// `server pki status` (ADR-0028 clause 12): every certificate the configuration depends on, with
/// its end.
///
/// # Errors
/// Returns the message to print when a named file cannot be read.
pub fn status(config: &ServerConfig) -> Result<Vec<Ending>, String> {
    depended_on(config)
        .iter()
        .map(|file| read_ending(file))
        .collect()
}

/// The exit code of `server pki status`: `0` when nothing is ending, `1` when something is, `2`
/// when something has ended.
#[must_use]
pub fn exit_code(endings: &[Ending], now: OffsetDateTime) -> i32 {
    fleet_core::ending::exit_code(endings.iter().map(|ending| ending.standing(now)))
}

/// The certificates a running Server depends on as it read them at startup, which is what it
/// serves and trusts until it restarts. A file that cannot be read is said once, here.
#[must_use]
pub fn loaded(files: &[PathBuf]) -> Vec<Ending> {
    files
        .iter()
        .filter_map(|file| match read_ending(file) {
            Ok(ending) => Some(ending),
            Err(e) => {
                tracing::warn!("cannot read when a certificate ends: {e}");
                None
            }
        })
        .collect()
}

/// The running Server's look at what it depends on (ADR-0028 clause 11): a certificate that is
/// ending is a warning and `pki.expiring`, one that has ended an error and `pki.expired`.
/// Nothing stops: the hosts decide for themselves.
///
/// It judges the certificates as [`loaded`] read them, since those are what the Server serves
/// until it restarts. A file that now holds another certificate is said too, as one a restart
/// would take, and answered, so a replaced file neither silences the warning for the certificate
/// still served nor goes unnoticed.
pub fn warn_endings(
    loaded: &[Ending],
    audit: Option<&dyn crate::audit::Audit>,
    now: OffsetDateTime,
) -> Vec<PathBuf> {
    let mut replaced = Vec::new();
    for ending in loaded {
        match read_ending(&ending.file) {
            Ok(on_disk)
                if on_disk.serial != ending.serial || on_disk.not_after != ending.not_after =>
            {
                tracing::warn!(
                    file = %ending.file.display(),
                    serving_until = %ending.not_after.date(),
                    file_until = %on_disk.not_after.date(),
                    "the file holds another certificate than the Server serves; restart the Server to serve it"
                );
                replaced.push(ending.file.clone());
            }
            Ok(_) => {}
            // Said every day, as before: the next start reads this file and would fail on it.
            Err(e) => tracing::warn!("cannot read when a certificate ends: {e}"),
        }
        let (event, outcome) = match ending.standing(now) {
            Standing::Fine => continue,
            Standing::Ending => {
                tracing::warn!(
                    file = %ending.file.display(),
                    subject = %ending.subject,
                    not_after = %ending.not_after.date(),
                    days_left = ending.days_left(now),
                    "a certificate the Server depends on ends soon; renew it"
                );
                ("pki.expiring", "expiring")
            }
            Standing::Ended => {
                tracing::error!(
                    file = %ending.file.display(),
                    subject = %ending.subject,
                    not_after = %ending.not_after.date(),
                    "a certificate the Server depends on has ended; renew it"
                );
                ("pki.expired", "expired")
            }
        };
        if let Some(audit) = audit {
            let not_after_ms = u64::try_from(ending.not_after.unix_timestamp())
                .unwrap_or(0)
                .saturating_mul(1000);
            let _ = audit.record(
                crate::audit::Entry::new(event, outcome)
                    .with("file", ending.file.display().to_string())
                    .with("subject", ending.subject.clone())
                    .with("serial", ending.serial.clone())
                    .with("not_after_ms", not_after_ms),
            );
        }
    }
    replaced
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
    use time::Duration;

    /// A self-signed CA that lived `lived` days and has `left` days left, written to `file`.
    fn aged_ca(file: &Path, lived: i64, left: i64) {
        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "aged CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::days(lived);
        params.not_after = now + Duration::days(left);
        std::fs::write(file, params.self_signed(&key).expect("ca").pem()).expect("write");
    }

    #[derive(Default)]
    struct Recorded(std::sync::Mutex<Vec<crate::audit::Entry>>);

    impl crate::audit::Audit for Recorded {
        fn record(&self, entry: crate::audit::Entry) -> Result<(), crate::audit::Unavailable> {
            self.0.lock().expect("lock").push(entry);
            Ok(())
        }
    }

    // Verifies: ADR-0028
    #[test]
    fn the_server_records_what_is_ending_and_what_has_ended() {
        let root = tempfile::tempdir().expect("tempdir");
        let fine = root.path().join("fine.pem");
        let ending = root.path().join("ending.pem");
        let ended = root.path().join("ended.pem");
        aged_ca(&fine, 10, 3000);
        aged_ca(&ending, 3600, 10);
        aged_ca(&ended, 3650, -1);
        let audit = Recorded::default();
        let replaced = warn_endings(
            &loaded(&[fine, ending.clone(), ended.clone()]),
            Some(&audit),
            OffsetDateTime::now_utc(),
        );
        assert!(replaced.is_empty(), "an unchanged file is no replacement");
        let recorded = audit.0.lock().expect("lock");
        let seen: Vec<(String, String)> = recorded
            .iter()
            .map(|entry| (entry.event.clone(), entry.outcome.clone()))
            .collect();
        assert_eq!(
            seen,
            [
                ("pki.expiring".to_string(), "expiring".to_string()),
                ("pki.expired".to_string(), "expired".to_string())
            ]
        );
        assert_eq!(
            recorded[0].fields.get("file"),
            Some(&crate::audit::Field::Text(ending.display().to_string()))
        );
    }

    /// The running Server judges the certificate it serves, read at startup, not whatever the
    /// file holds a day later: a file replaced without a restart neither silences the warning
    /// for the certificate still served nor goes unsaid (ADR-0028 clause 11).
    /// Verifies: ADR-0028
    #[test]
    fn a_file_replaced_without_a_restart_neither_silences_the_warning_nor_goes_unsaid() {
        let root = tempfile::tempdir().expect("tempdir");
        let served = root.path().join("server.pem");
        aged_ca(&served, 3600, 10);
        let loaded = loaded(std::slice::from_ref(&served));
        aged_ca(&served, 1, 3000);
        let audit = Recorded::default();
        let replaced = warn_endings(&loaded, Some(&audit), OffsetDateTime::now_utc());
        let recorded = audit.0.lock().expect("lock");
        assert_eq!(
            recorded
                .iter()
                .map(|entry| entry.event.as_str())
                .collect::<Vec<_>>(),
            ["pki.expiring"],
            "the certificate still served is ending, whatever the file holds now"
        );
        assert_eq!(
            replaced,
            [served],
            "the replaced file is named for a restart"
        );
    }

    /// The Operator plane's own certificate is one the Server depends on, and a file both
    /// sections name is watched once (ADR-0032 clause 5).
    /// Verifies: ADR-0032
    #[test]
    fn the_operator_planes_certificate_is_watched_once() {
        let config: ServerConfig = toml::from_str(
            "[tls]\ncert_file = \"server.pem\"\nkey_file = \"server-key.pem\"\n\
             [rest.tls]\ncert_file = \"ui.pem\"\nkey_file = \"ui-key.pem\"\n",
        )
        .expect("parse");
        assert_eq!(
            depended_on(&config),
            [PathBuf::from("server.pem"), PathBuf::from("ui.pem")]
        );
        let config: ServerConfig = toml::from_str(
            "[tls]\ncert_file = \"server.pem\"\nkey_file = \"server-key.pem\"\n\
             [rest.tls]\ncert_file = \"server.pem\"\nkey_file = \"server-key.pem\"\n",
        )
        .expect("parse");
        assert_eq!(depended_on(&config), [PathBuf::from("server.pem")]);
    }

    // Verifies: ADR-0028
    #[test]
    fn status_exits_by_the_worst_end() {
        let now = OffsetDateTime::now_utc();
        let ending = |lived: i64, left: i64| Ending {
            file: PathBuf::from("x.pem"),
            subject: String::new(),
            serial: String::new(),
            not_before: now - Duration::days(lived),
            not_after: now + Duration::days(left),
        };
        assert_eq!(exit_code(&[ending(0, 400)], now), 0);
        assert_eq!(exit_code(&[ending(0, 400), ending(380, 20)], now), 1);
        assert_eq!(exit_code(&[ending(380, 20), ending(30, -1)], now), 2);
        assert_eq!(exit_code(&[], now), 0);
    }
}
