//! `classisctl pki` — the fleet's certificates, made on the operator's machine.
//!
//! `init` makes the server CA, the Server's certificate and the package signing key;
//! `server-cert` makes another server certificate; `status` says when the server CA in the offline
//! directory ends. The Server binary makes no CA and no server certificate; it reads its own
//! certificate's end with its own `pki status`, by the same rule, [`classis_core::ending`].

use std::path::{Path, PathBuf};

use clap::Subcommand;
use classis_core::ending::Standing;
use classis_core::naming;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use time::{Duration, OffsetDateTime};
use x509_parser::prelude::{FromDer, X509Certificate};
use zeroize::Zeroizing;

/// How long the server CA lives unless told otherwise.
pub const CA_DAYS: u32 = 3650;
/// How long a server certificate lives unless told otherwise: within every browser's limit.
pub const SERVER_DAYS: u32 = 397;
/// The product the certificates are named for unless told otherwise.
pub const DEFAULT_PRODUCT: &str = naming::DEFAULT_PRODUCT;

/// How far a certificate's life starts before the moment it is signed.
const CLOCK_SKEW: Duration = Duration::minutes(5);

/// The commands of `classisctl pki`.
#[derive(Subcommand)]
pub enum Command {
    /// Make a fleet's certificates from nothing: the certificate the reverse proxy in front of the
    /// Server presents into --server-dir, what stays with the operator into --offline-dir.
    Init {
        /// Receives the reverse proxy's certificate and key, server.pem and server-key.pem.
        #[arg(long)]
        server_dir: PathBuf,
        /// Receives the server CA with its key and supervisor.toml.fragment. Keep it off the
        /// Server host.
        #[arg(long)]
        offline_dir: PathBuf,
        /// A DNS name or IP address the Server is dialled by. Repeatable; at least one.
        #[arg(long = "name", value_name = "DNS|IP", required = true)]
        names: Vec<String>,
        /// Where a host's files will live; supervisor.toml.fragment names them there. Default: the
        /// absolute path of --offline-dir.
        #[arg(long)]
        host_path: Option<PathBuf>,
        /// The product the certificates are named for: letters, digits, space, '.' and '-', at
        /// most 40 characters.
        #[arg(long, default_value = DEFAULT_PRODUCT)]
        product: String,
        #[command(flatten)]
        organization: Organization,
        /// How long the server CA lives.
        #[arg(long, default_value_t = CA_DAYS)]
        ca_days: u32,
        /// How long the server certificate lives.
        #[arg(long, default_value_t = SERVER_DAYS)]
        server_days: u32,
    },
    /// Make a server certificate from the offline server CA.
    ServerCert {
        /// The directory `init` wrote --offline-dir to.
        #[arg(long)]
        offline_dir: PathBuf,
        /// A DNS name or IP address the certificate is dialled by. Repeatable; at least one.
        #[arg(long = "name", value_name = "DNS|IP", required = true)]
        names: Vec<String>,
        /// Receives server.pem and server-key.pem.
        #[arg(long)]
        out: PathBuf,
        /// Each replaces the server CA's own, which the certificate carries otherwise.
        #[command(flatten)]
        organization: Organization,
        /// How long the certificate lives; never past the server CA.
        #[arg(long, default_value_t = SERVER_DAYS)]
        days: u32,
    },
    /// Say when the server CA in the offline directory ends. Exits 0 when it is not ending, 1
    /// when it is, 2 when it has ended.
    Status {
        /// The directory `init` wrote --offline-dir to.
        #[arg(long)]
        offline_dir: PathBuf,
    },
}

/// The organization a certificate names for audit.
#[derive(clap::Args, Clone, Debug, Default)]
pub struct Organization {
    /// The organization (O) the certificates name: 1 to 64 characters.
    #[arg(long)]
    pub organization: Option<String>,
    /// The organizational unit (OU) the certificates name: 1 to 64 characters.
    #[arg(long)]
    pub organizational_unit: Option<String>,
}

impl Organization {
    /// Refuses a value outside its grammar.
    fn check(&self) -> Result<(), String> {
        for (flag, value) in [
            ("--organization", &self.organization),
            ("--organizational-unit", &self.organizational_unit),
        ] {
            if let Some(value) = value {
                naming::check_organization(value).map_err(|e| format!("{flag} {e}"))?;
            }
        }
        Ok(())
    }

    /// Each value of `self`, or else `other`'s.
    fn or(&self, other: &Organization) -> Organization {
        Organization {
            organization: self
                .organization
                .clone()
                .or_else(|| other.organization.clone()),
            organizational_unit: self
                .organizational_unit
                .clone()
                .or_else(|| other.organizational_unit.clone()),
        }
    }
}

/// Runs one `pki` command and answers the exit code.
///
/// # Errors
/// Returns the message to print when an option is invalid, a file exists or cannot be read, or
/// writing fails.
pub fn run(command: Command) -> Result<u8, String> {
    let lines = match command {
        Command::Init {
            server_dir,
            offline_dir,
            names,
            host_path,
            product,
            organization,
            ca_days,
            server_days,
        } => init(&InitOptions {
            server_dir,
            offline_dir,
            host_path,
            product,
            organization,
            names,
            ca_days,
            server_days,
        })?,
        Command::ServerCert {
            offline_dir,
            names,
            out,
            organization,
            days,
        } => server_cert(&offline_dir, &names, &organization, days, &out)?,
        Command::Status { offline_dir } => {
            let endings = status(&offline_dir)?;
            let now = OffsetDateTime::now_utc();
            for ending in &endings {
                println!("{}", ending.line(now));
            }
            return Ok(exit_code(&endings, now));
        }
    };
    for line in lines {
        println!("{line}");
    }
    Ok(0)
}

/// What `pki init` is asked for.
pub struct InitOptions {
    pub server_dir: PathBuf,
    pub offline_dir: PathBuf,
    /// Where a host's files will live; the fragment names them there.
    pub host_path: Option<PathBuf>,
    /// What the certificates are named for.
    pub product: String,
    /// What the server CA and the server certificate name for audit.
    pub organization: Organization,
    pub names: Vec<String>,
    /// The server CA's life.
    pub ca_days: u32,
    pub server_days: u32,
}

/// One file a command writes: its name in the target directory, its contents, and whether it is a
/// private key. The contents are wiped when they are dropped, a key's as every file's.
struct File {
    name: &'static str,
    contents: Zeroizing<Vec<u8>>,
    key: bool,
}

/// A directory and the files a command writes into it.
struct Target {
    dir: PathBuf,
    files: Vec<File>,
}

/// A CA ready to sign: what signs, when it ends, and what its subject names.
struct Authority {
    issuer: Issuer<'static, KeyPair>,
    end: OffsetDateTime,
    common_name: String,
    organization: Organization,
}

/// A certificate a command signed.
struct Made {
    cert_pem: String,
    key_pem: Zeroizing<String>,
    serial: String,
    /// The life asked for reached past the CA's end and was cut to it.
    cut: bool,
}

/// `pki init`: the server CA, the server certificate and the package signing
/// key, split into what the Server host needs and what stays offline, the server CA's key and the
/// package signing key. Returns the lines to print.
///
/// # Errors
/// Returns the message to print when an option is invalid, a file exists, or writing fails.
pub fn init(options: &InitOptions) -> Result<Vec<String>, String> {
    check_product(&options.product)?;
    options.organization.check()?;
    let names = names(&options.names)?;
    for days in [options.ca_days, options.server_days] {
        check_days(days)?;
    }
    let (product, organization) = (&options.product, &options.organization);
    let (server_ca_pem, server_ca_key, server_ca) = authority(
        &format!("{product} Server CA"),
        organization,
        options.ca_days,
    )?;
    let server = server_certificate(
        &server_ca,
        &names,
        &Organization::default(),
        options.server_days,
    )?;
    // The package signing key stays with the server CA's.
    let (signing_key, public_key) = crate::package::signing_key()?;

    let host_path = destination(&options.offline_dir, options.host_path.as_deref())?;
    // The fragment names the CA a host trusts the Server by.
    let supervisor_toml = format!("[tls]\nca_file = {}\n", quoted(&host_path, "server-ca.pem"));

    let targets = [
        Target {
            dir: options.server_dir.clone(),
            files: vec![
                cert("server.pem", &server.cert_pem),
                key("server-key.pem", &server.key_pem),
            ],
        },
        Target {
            dir: options.offline_dir.clone(),
            files: vec![
                cert("server-ca.pem", &server_ca_pem),
                key("server-ca-key.pem", &server_ca_key),
                File {
                    name: "package-signing-key.pk8",
                    contents: signing_key,
                    key: true,
                },
                cert("package-signing-key.pub", &format!("{public_key}\n")),
                cert("supervisor.toml.fragment", &supervisor_toml),
            ],
        },
    ];
    write_all(&targets)?;

    let mut lines = vec![
        format!(
            "{}: for the reverse proxy in front of the Server — the certificate and key it presents",
            options.server_dir.display()
        ),
        format!(
            "{}: keep offline — the server CA's key and the package signing key; give every new \
             host server-ca.pem, as supervisor.toml.fragment names it",
            options.offline_dir.display()
        ),
    ];
    if same_file_system(&options.server_dir, &options.offline_dir) {
        lines.push(format!(
            "notice: both directories are on one file system; move {} off the Server host",
            options.offline_dir.display()
        ));
    }
    Ok(lines)
}

/// `pki server-cert`: a server certificate from the offline server CA,
/// for the Server. It carries the CA's O and OU unless `organization` replaces either.
///
/// # Errors
/// Returns the message to print when an option is invalid, the CA cannot be read, a file exists,
/// or writing fails.
pub fn server_cert(
    offline_dir: &Path,
    names: &[String],
    organization: &Organization,
    days: u32,
    out: &Path,
) -> Result<Vec<String>, String> {
    let names = self::names(names)?;
    organization.check()?;
    check_days(days)?;
    let ca = load_authority(offline_dir, "server-ca")?;
    let made = server_certificate(&ca, &names, organization, days)?;
    write_all(&[Target {
        dir: out.to_path_buf(),
        files: vec![
            cert("server.pem", &made.cert_pem),
            key("server-key.pem", &made.key_pem),
        ],
    }])?;
    let mut lines = vec![format!(
        "{}: server.pem and server-key.pem, serial {}",
        out.display(),
        made.serial
    )];
    lines.extend(cut_notice(&made, &ca));
    Ok(lines)
}

// ---------------------------------------------------------------------------------------------
// When they end
// ---------------------------------------------------------------------------------------------

/// When one certificate ends, as `pki status` lists it.
#[derive(Debug, Clone)]
pub struct Ending {
    pub file: PathBuf,
    pub subject: String,
    pub serial: String,
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
}

impl Ending {
    /// Where this end stands at `now`, by the rule the Server judges by.
    #[must_use]
    pub fn standing(&self, now: OffsetDateTime) -> Standing {
        classis_core::ending::standing(
            self.not_before.unix_timestamp(),
            self.not_after.unix_timestamp(),
            now.unix_timestamp(),
        )
    }

    /// The line `pki status` prints for it: standing, days left, end, serial, subject and file —
    /// the columns of the Server's `pki status`.
    #[must_use]
    pub fn line(&self, now: OffsetDateTime) -> String {
        let standing = match self.standing(now) {
            Standing::Fine => "ok",
            Standing::Ending => "ENDS SOON",
            Standing::Ended => "ENDED",
        };
        format!(
            "{standing:9} {} days  {}  serial {}  {}  ({})",
            (self.not_after - now).whole_days(),
            self.not_after.date(),
            self.serial,
            self.subject,
            self.file.display()
        )
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

/// `pki status`: the server CA in the offline directory, with its end.
///
/// # Errors
/// Returns the message to print when the directory holds no server CA or it cannot be read.
pub fn status(offline_dir: &Path) -> Result<Vec<Ending>, String> {
    let file = offline_dir.join("server-ca.pem");
    if !file.exists() {
        return Err(format!(
            "{} holds no server-ca.pem, the certificate `pki init` writes to an offline directory",
            offline_dir.display()
        ));
    }
    Ok(vec![read_ending(&file)?])
}

/// The exit code of `pki status`: `0` when nothing is ending, `1` when something is, `2` when
/// something has ended.
#[must_use]
pub fn exit_code(endings: &[Ending], now: OffsetDateTime) -> u8 {
    match classis_core::ending::exit_code(endings.iter().map(|ending| ending.standing(now))) {
        0 => 0,
        1 => 1,
        _ => 2,
    }
}

/// A serial of 16 random bytes, positive.
fn random_serial() -> Result<SerialNumber, String> {
    use ring::rand::SecureRandom as _;
    let mut bytes = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "no secure random source for a serial number".to_string())?;
    bytes[0] &= 0x7f;
    Ok(SerialNumber::from_slice(&bytes))
}

// ---------------------------------------------------------------------------------------------
// Making certificates
// ---------------------------------------------------------------------------------------------

/// A self-signed CA: `CA:TRUE` with a path length of 0,
/// `keyCertSign` and `cRLSign`, named O, OU and CN. Returns its certificate and key as PEM, the
/// key wiped when it is dropped, and the authority that signs with it.
fn authority(
    common_name: &str,
    organization: &Organization,
    days: u32,
) -> Result<(String, Zeroizing<String>, Authority), String> {
    let key = KeyPair::generate().map_err(|e| format!("cannot make a key: {e}"))?;
    let (not_before, not_after, _) = life(days, None)?;
    let mut params = CertificateParams::default();
    params.distinguished_name = subject(organization, common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.serial_number = Some(random_serial()?);
    params.not_before = not_before;
    params.not_after = not_after;
    let cert = params
        .self_signed(&key)
        .map_err(|e| format!("cannot make the {common_name}: {e}"))?;
    let key_pem = Zeroizing::new(key.serialize_pem());
    Ok((
        cert.pem(),
        key_pem,
        Authority {
            issuer: Issuer::new(params, key),
            end: not_after,
            common_name: common_name.to_string(),
            organization: organization.clone(),
        },
    ))
}

/// A subject of O, OU and CN in that order, as `UTF8String`s.
fn subject(organization: &Organization, common_name: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    if let Some(value) = &organization.organization {
        name.push(DnType::OrganizationName, value.as_str());
    }
    if let Some(value) = &organization.organizational_unit {
        name.push(DnType::OrganizationalUnitName, value.as_str());
    }
    name.push(DnType::CommonName, common_name);
    name
}

/// A server certificate: every name and both loopback addresses in its SAN,
/// its role in its subject, and the CA's O and OU unless `organization` replaces either.
fn server_certificate(
    ca: &Authority,
    names: &[SanType],
    organization: &Organization,
    days: u32,
) -> Result<Made, String> {
    let mut params = CertificateParams::default();
    params.distinguished_name = subject(
        &organization.or(&ca.organization),
        &naming::leaf_common_name(&ca.common_name),
    );
    params.subject_alt_names = names.to_vec();
    for loopback in [
        std::net::IpAddr::from([127, 0, 0, 1]),
        std::net::IpAddr::from(std::net::Ipv6Addr::LOCALHOST),
    ] {
        let san = SanType::IpAddress(loopback);
        if !params.subject_alt_names.contains(&san) {
            params.subject_alt_names.push(san);
        }
    }
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf(params, ca, days)
}

/// Signs a leaf: `CA:FALSE`, `digitalSignature`, a random serial, and a life that never reaches
/// past the CA's end.
fn leaf(mut params: CertificateParams, ca: &Authority, days: u32) -> Result<Made, String> {
    let key = KeyPair::generate().map_err(|e| format!("cannot make a key: {e}"))?;
    let (not_before, not_after, cut) = life(days, Some(ca.end))?;
    let serial = random_serial()?;
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.serial_number = Some(serial.clone());
    params.not_before = not_before;
    params.not_after = not_after;
    let cert = params
        .signed_by(&key, &ca.issuer)
        .map_err(|e| format!("cannot sign with the {}: {e}", ca.common_name))?;
    Ok(Made {
        cert_pem: cert.pem(),
        key_pem: Zeroizing::new(key.serialize_pem()),
        serial: hex::encode(serial.to_bytes()),
        cut,
    })
}

/// From a moment ago to `days` from now, cut to `ceiling` when it would reach past it.
fn life(
    days: u32,
    ceiling: Option<OffsetDateTime>,
) -> Result<(OffsetDateTime, OffsetDateTime, bool), String> {
    let now = OffsetDateTime::now_utc();
    let asked = now
        .checked_add(Duration::days(i64::from(days)))
        .ok_or_else(|| format!("{days} days is out of range"))?;
    match ceiling {
        Some(end) if end <= now => Err(format!("the CA ended on {}", end.date())),
        Some(end) if asked > end => Ok((now - CLOCK_SKEW, end, true)),
        _ => Ok((now - CLOCK_SKEW, asked, false)),
    }
}

/// The notice a cut life leaves.
fn cut_notice(made: &Made, ca: &Authority) -> Option<String> {
    made.cut.then(|| {
        format!(
            "notice: the certificate ends with the {} on {}, before the days asked for",
            ca.common_name,
            ca.end.date()
        )
    })
}

/// Loads `<stem>.pem` and `<stem>-key.pem` from the offline directory as an authority.
fn load_authority(dir: &Path, stem: &str) -> Result<Authority, String> {
    let cert_file = dir.join(format!("{stem}.pem"));
    let key_file = dir.join(format!("{stem}-key.pem"));
    let cert_pem = std::fs::read_to_string(&cert_file)
        .map_err(|e| format!("cannot read {}: {e}", cert_file.display()))?;
    let key_pem = std::fs::read_to_string(&key_file)
        .map(Zeroizing::new)
        .map_err(|e| format!("cannot read {}: {e}", key_file.display()))?;
    let key = KeyPair::from_pem(&key_pem)
        .map_err(|e| format!("cannot read {}: {e}", key_file.display()))?;
    let ending = read_ending(&cert_file)?;
    let (common_name, organization) = {
        let der = opamp::tls::certificates(cert_pem.as_bytes())
            .map_err(|e| format!("cannot read {}: {e}", cert_file.display()))?
            .into_iter()
            .next()
            .ok_or_else(|| format!("{} holds no certificate", cert_file.display()))?;
        let (_, cert) = X509Certificate::from_der(der.as_ref())
            .map_err(|e| format!("cannot read {}: {e}", cert_file.display()))?;
        let first = |values: Vec<&x509_parser::x509::AttributeTypeAndValue<'_>>| {
            values
                .first()
                .and_then(|value| value.as_str().ok())
                .map(str::to_string)
        };
        let common_name = first(cert.subject().iter_common_name().collect())
            .ok_or_else(|| format!("{} names no common name", cert_file.display()))?;
        let organization = Organization {
            organization: first(cert.subject().iter_organization().collect()),
            organizational_unit: first(cert.subject().iter_organizational_unit().collect()),
        };
        (common_name, organization)
    };
    let issuer = Issuer::from_ca_cert_pem(&cert_pem, key)
        .map_err(|e| format!("cannot use {} as a CA: {e}", cert_file.display()))?;
    Ok(Authority {
        issuer,
        end: ending.not_after,
        common_name,
        organization,
    })
}

// ---------------------------------------------------------------------------------------------
// Checking what is asked for
// ---------------------------------------------------------------------------------------------

/// A product name.
fn check_product(product: &str) -> Result<(), String> {
    naming::check_product(product).map_err(|e| format!("--product {e}"))
}

/// A life of at least a day.
fn check_days(days: u32) -> Result<(), String> {
    if days == 0 {
        return Err("a certificate needs at least one day".to_string());
    }
    Ok(())
}

/// The `--name`s of a server certificate: at least one, each a DNS name or an
/// IP address, no wildcard.
fn names(names: &[String]) -> Result<Vec<SanType>, String> {
    if names.is_empty() {
        return Err(
            "--name is required: the DNS name or address the certificate is dialled by".into(),
        );
    }
    names
        .iter()
        .map(|name| {
            if let Ok(ip) = name.parse::<std::net::IpAddr>() {
                return Ok(SanType::IpAddress(ip));
            }
            if !is_dns_name(name) {
                return Err(format!(
                    "--name {name:?} is neither a DNS name nor an IP address (no wildcards)"
                ));
            }
            name.as_str()
                .try_into()
                .map(SanType::DnsName)
                .map_err(|e| format!("--name {name:?}: {e}"))
        })
        .collect()
}

/// A DNS name: labels of letters, digits and `-`, none empty, none starting or ending with `-`,
/// at most 63 characters each and 253 in all.
fn is_dns_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

// ---------------------------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------------------------

fn cert(name: &'static str, contents: &str) -> File {
    File {
        name,
        contents: Zeroizing::new(contents.as_bytes().to_vec()),
        key: false,
    }
}

/// A key file, copied from a buffer that is itself wiped.
fn key(name: &'static str, contents: &str) -> File {
    File {
        name,
        contents: Zeroizing::new(contents.as_bytes().to_vec()),
        key: true,
    }
}

/// The path a fragment names a file by: where the directory is meant to live, absolute.
fn destination(dir: &Path, meant: Option<&Path>) -> Result<PathBuf, String> {
    let path = match meant {
        Some(path) => path.to_path_buf(),
        None if dir.is_absolute() => dir.to_path_buf(),
        None => std::env::current_dir()
            .map_err(|e| format!("cannot resolve {}: {e}", dir.display()))?
            .join(dir),
    };
    if !path.is_absolute() {
        return Err(format!("{} is not an absolute path", path.display()));
    }
    Ok(path)
}

/// A TOML basic string naming `file` in `dir`.
fn quoted(dir: &Path, file: &str) -> String {
    toml::Value::String(dir.join(file).display().to_string()).to_string()
}

/// Writes every target or none: refuses when any file exists, writes each
/// directory's files into a temporary directory inside it, and renames them into place only once
/// all are written. Directories it creates are `0700`, keys `0600`.
fn write_all(targets: &[Target]) -> Result<(), String> {
    for target in targets {
        for file in &target.files {
            let path = target.dir.join(file.name);
            if path.exists() {
                return Err(format!("{} exists; nothing was written", path.display()));
            }
        }
    }
    let mut staged = Vec::new();
    for target in targets {
        create_private_dir(&target.dir)?;
        let temp = target.dir.join(format!(".pki-{}", hex::encode(nonce()?)));
        create_private_dir(&temp)?;
        for file in &target.files {
            write_file(&temp.join(file.name), &file.contents, file.key)?;
        }
        staged.push((temp, target));
    }
    for (temp, target) in &staged {
        for file in &target.files {
            std::fs::rename(temp.join(file.name), target.dir.join(file.name)).map_err(|e| {
                format!("cannot place {}: {e}", target.dir.join(file.name).display())
            })?;
        }
        std::fs::remove_dir(temp).map_err(|e| format!("cannot remove {}: {e}", temp.display()))?;
    }
    Ok(())
}

fn nonce() -> Result<[u8; 8], String> {
    use ring::rand::SecureRandom as _;
    let mut bytes = [0u8; 8];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "no secure random source".to_string())?;
    Ok(bytes)
}

/// Creates `dir` and its missing parents; the ones it creates are `0700`.
fn create_private_dir(dir: &Path) -> Result<(), String> {
    if dir.is_dir() {
        return Ok(());
    }
    if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
        create_private_dir(parent)?;
    }
    // `mut` is used only by the Unix block below; on Windows there is nothing to set.
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .map_err(|e| format!("cannot create {}: {e}", dir.display()))
}

/// Writes a new file; a key is `0600` from the moment it exists.
fn write_file(path: &Path, contents: &[u8], key: bool) -> Result<(), String> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(if key { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = key;
    let mut file = options
        .open(path)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// Whether two directories sit on one file system.
fn same_file_system(a: &Path, b: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        matches!(
            (std::fs::metadata(a), std::fs::metadata(b)),
            (Ok(a), Ok(b)) if a.dev() == b.dev()
        )
    }
    #[cfg(not(unix))]
    {
        let _ = (a, b);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(root: &Path) -> InitOptions {
        InitOptions {
            server_dir: root.join("server"),
            offline_dir: root.join("offline"),
            host_path: None,
            product: DEFAULT_PRODUCT.to_string(),
            organization: Organization::default(),
            names: vec!["fleet.example.com".to_string(), "10.0.0.5".to_string()],
            ca_days: CA_DAYS,
            server_days: SERVER_DAYS,
        }
    }

    fn files(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("read dir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    fn parsed(file: &Path) -> Vec<u8> {
        let pem = std::fs::read(file).expect("read");
        opamp::tls::certificates(&pem).expect("pem")[0]
            .as_ref()
            .to_vec()
    }

    #[test]
    fn init_splits_what_the_server_needs_from_what_stays_offline() {
        let root = tempfile::tempdir().expect("tempdir");
        let lines = init(&options(root.path())).expect("init");
        assert_eq!(
            files(&root.path().join("server")),
            ["server-key.pem", "server.pem"]
        );
        assert_eq!(
            files(&root.path().join("offline")),
            [
                "package-signing-key.pk8",
                "package-signing-key.pub",
                "server-ca-key.pem",
                "server-ca.pem",
                "supervisor.toml.fragment"
            ]
        );
        let supervisor_toml =
            std::fs::read_to_string(root.path().join("offline/supervisor.toml.fragment"))
                .expect("read");
        assert!(
            supervisor_toml.contains("server-ca.pem")
                && !supervisor_toml.contains("cert_file")
                && !supervisor_toml.contains("key_file"),
            "the fragment names the CA a host trusts and no host certificate: {supervisor_toml}"
        );
        assert!(lines
            .iter()
            .any(|l| l.starts_with("notice: both directories")));
    }

    /// The package signing key lands offline with its public half, and the fragment names no key:
    /// the Client verifies packages up to its compiled-in Package Roots.
    #[test]
    fn init_makes_the_package_signing_key_offline_and_the_fragment_names_no_key() {
        use ring::signature::{Ed25519KeyPair, KeyPair as _};
        let root = tempfile::tempdir().expect("tempdir");
        init(&options(root.path())).expect("init");
        let offline = root.path().join("offline");
        let pkcs8 = std::fs::read(offline.join("package-signing-key.pk8")).expect("read");
        let keypair = Ed25519KeyPair::from_pkcs8(&pkcs8).expect("a PKCS#8 Ed25519 key");
        let public = hex::encode(keypair.public_key().as_ref());
        assert_eq!(
            std::fs::read_to_string(offline.join("package-signing-key.pub")).expect("read"),
            format!("{public}\n")
        );
        let fragment: toml::Table =
            std::fs::read_to_string(offline.join("supervisor.toml.fragment"))
                .expect("read")
                .parse()
                .expect("toml");
        assert!(
            !fragment.contains_key("packages"),
            "the fragment names no package key: {fragment:?}"
        );
        assert!(
            files(&root.path().join("server"))
                .iter()
                .all(|name| !name.starts_with("package-signing-key")),
            "no package signing key on the Server host"
        );
    }

    #[cfg(unix)]
    #[test]
    fn keys_are_owner_only_and_new_directories_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::tempdir().expect("tempdir");
        init(&options(root.path())).expect("init");
        for dir in ["server", "offline"] {
            let dir = root.path().join(dir);
            let mode = std::fs::metadata(&dir).expect("meta").permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{}", dir.display());
            for name in files(&dir) {
                let mode = std::fs::metadata(dir.join(&name))
                    .expect("meta")
                    .permissions()
                    .mode()
                    & 0o777;
                let expected = if name.ends_with("-key.pem") || name.ends_with(".pk8") {
                    0o600
                } else {
                    0o644
                };
                assert_eq!(mode, expected, "{name}");
            }
        }
    }

    #[test]
    fn a_second_init_refuses_and_writes_nothing() {
        let root = tempfile::tempdir().expect("tempdir");
        init(&options(root.path())).expect("init");
        let before = std::fs::read(root.path().join("server/server.pem")).expect("read");
        let error = init(&options(root.path())).expect_err("refused");
        assert!(error.contains("exists"), "{error}");
        assert_eq!(
            std::fs::read(root.path().join("server/server.pem")).expect("read"),
            before
        );
        assert!(
            files(&root.path().join("server"))
                .iter()
                .all(|n| !n.starts_with(".pki-")),
            "no temporary directory is left"
        );
    }

    #[test]
    fn the_server_ca_has_its_own_subject_and_signs_no_ca() {
        let root = tempfile::tempdir().expect("tempdir");
        init(&options(root.path())).expect("init");
        let der = parsed(&root.path().join("offline/server-ca.pem"));
        let (_, cert) = X509Certificate::from_der(&der).expect("parse");
        let constraints = cert
            .basic_constraints()
            .expect("ext")
            .expect("present")
            .value;
        assert!(constraints.ca);
        assert_eq!(constraints.path_len_constraint, Some(0));
        assert_eq!(cert.subject().to_string(), "CN=Classis Server CA");
    }

    fn acme() -> Organization {
        Organization {
            organization: Some("Acme AG".to_string()),
            organizational_unit: Some("IT".to_string()),
        }
    }

    /// The server CA and the server certificate are named by product and role, with the operator's
    /// organization, in the order O, OU, CN.
    #[test]
    fn init_names_every_certificate_by_product_role_and_organization() {
        let root = tempfile::tempdir().expect("tempdir");
        let mut o = options(root.path());
        o.product = "Acme Fleet".to_string();
        o.organization = acme();
        init(&o).expect("init");
        for (file, subject) in [
            (
                "offline/server-ca.pem",
                "O=Acme AG, OU=IT, CN=Acme Fleet Server CA",
            ),
            (
                "server/server.pem",
                "O=Acme AG, OU=IT, CN=Acme Fleet Server Certificate",
            ),
        ] {
            let ending = read_ending(&root.path().join(file)).expect("read");
            assert_eq!(ending.subject, subject, "{file}");
        }
    }

    /// `server-cert` carries the server CA's O and OU, and a flag replaces one alone.
    #[test]
    fn server_cert_takes_the_cas_organization_and_a_flag_replaces_it() {
        let root = tempfile::tempdir().expect("tempdir");
        let mut o = options(root.path());
        o.organization = acme();
        init(&o).expect("init");
        let other_unit = Organization {
            organization: None,
            organizational_unit: Some("Operations".to_string()),
        };
        for (out, organization, subject) in [
            (
                "same",
                Organization::default(),
                "O=Acme AG, OU=IT, CN=Classis Server Certificate",
            ),
            (
                "unit",
                other_unit,
                "O=Acme AG, OU=Operations, CN=Classis Server Certificate",
            ),
        ] {
            server_cert(
                &root.path().join("offline"),
                &["fleet.example.net".to_string()],
                &organization,
                90,
                &root.path().join(out),
            )
            .expect("server-cert");
            let ending = read_ending(&root.path().join(out).join("server.pem")).expect("read");
            assert_eq!(ending.subject, subject, "{out}");
        }
    }

    /// A product or an organization outside its grammar is refused, and nothing is written.
    #[test]
    fn a_bad_product_or_organization_is_refused() {
        let root = tempfile::tempdir().expect("tempdir");
        let mut o = options(root.path());
        o.product = " Acme".to_string();
        assert!(init(&o).is_err(), "a leading space was accepted");
        let mut o = options(root.path());
        o.organization.organization = Some("a\nb".to_string());
        assert!(init(&o).is_err(), "a control character was accepted");
        let mut o = options(root.path());
        o.organization.organizational_unit = Some("x".repeat(65));
        assert!(init(&o).is_err(), "65 characters were accepted");
        assert!(!root.path().join("server").exists(), "nothing was written");
    }

    #[test]
    fn a_server_certificate_names_what_is_dialled_and_the_loopback() {
        use x509_parser::extensions::GeneralName;
        let root = tempfile::tempdir().expect("tempdir");
        init(&options(root.path())).expect("init");
        let der = parsed(&root.path().join("server/server.pem"));
        let (_, cert) = X509Certificate::from_der(&der).expect("parse");
        let san = cert
            .subject_alternative_name()
            .expect("ext")
            .expect("present")
            .value;
        let names: Vec<String> = san
            .general_names
            .iter()
            .map(|name| match name {
                GeneralName::DNSName(dns) => (*dns).to_string(),
                GeneralName::IPAddress(ip) => match ip.len() {
                    4 => std::net::IpAddr::from(<[u8; 4]>::try_from(*ip).expect("v4")).to_string(),
                    _ => std::net::IpAddr::from(<[u8; 16]>::try_from(*ip).expect("v6")).to_string(),
                },
                other => format!("{other:?}"),
            })
            .collect();
        assert_eq!(names, ["fleet.example.com", "10.0.0.5", "127.0.0.1", "::1"]);
        assert_eq!(cert.subject().to_string(), "CN=Classis Server Certificate");
    }

    #[test]
    fn a_wildcard_an_empty_name_and_a_bad_product_are_refused() {
        let root = tempfile::tempdir().expect("tempdir");
        for name in ["*.example.com", "", "under_score.example"] {
            let mut o = options(root.path());
            o.names = vec![name.to_string()];
            assert!(init(&o).is_err(), "{name:?} was accepted");
        }
        let mut o = options(root.path());
        o.names.clear();
        assert!(init(&o).is_err(), "no --name was accepted");
        let mut o = options(root.path());
        o.product = "a/b".to_string();
        assert!(init(&o).is_err(), "a product with '/' was accepted");
        assert!(!root.path().join("server").exists(), "nothing was written");
    }

    #[test]
    fn a_certificate_never_outlives_its_ca() {
        let root = tempfile::tempdir().expect("tempdir");
        let mut o = options(root.path());
        o.ca_days = 10;
        init(&o).expect("init");
        let ca = read_ending(&root.path().join("offline/server-ca.pem")).expect("ca");
        let server = read_ending(&root.path().join("server/server.pem")).expect("server");
        assert_eq!(server.not_after, ca.not_after);
        let lines = server_cert(
            &root.path().join("offline"),
            &["fleet.example.com".to_string()],
            &Organization::default(),
            SERVER_DAYS,
            &root.path().join("next"),
        )
        .expect("server-cert");
        assert!(lines
            .iter()
            .any(|l| l.starts_with("notice: the certificate ends with")));
    }

    #[test]
    fn server_cert_signs_with_the_offline_server_ca() {
        let root = tempfile::tempdir().expect("tempdir");
        init(&options(root.path())).expect("init");
        server_cert(
            &root.path().join("offline"),
            &["fleet.example.net".to_string()],
            &Organization::default(),
            90,
            &root.path().join("next-cert"),
        )
        .expect("server-cert");
        let leaf_der = parsed(&root.path().join("next-cert/server.pem"));
        let ca_der = parsed(&root.path().join("offline/server-ca.pem"));
        let (_, leaf_cert) = X509Certificate::from_der(&leaf_der).expect("leaf");
        let (_, ca_cert) = X509Certificate::from_der(&ca_der).expect("ca");
        leaf_cert
            .verify_signature(Some(ca_cert.public_key()))
            .expect("signed by the server CA");
    }

    #[test]
    fn status_lists_the_offline_certificates_and_a_fresh_set_is_not_ending() {
        let root = tempfile::tempdir().expect("tempdir");
        init(&options(root.path())).expect("init");
        let endings = status(&root.path().join("offline")).expect("status");
        let names: Vec<String> = endings
            .iter()
            .map(|ending| {
                ending
                    .file
                    .file_name()
                    .expect("name")
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(names, ["server-ca.pem"]);
        let now = OffsetDateTime::now_utc();
        assert_eq!(exit_code(&endings, now), 0);
        let serial = &endings[0].serial;
        assert!(endings[0].line(now).contains(&format!("serial {serial}")));
        // A directory `init` did not write is refused, not listed as empty.
        assert!(status(root.path()).is_err());
    }

    /// The server CA lives ten years unless told otherwise.
    #[test]
    fn the_server_ca_lives_ten_years() {
        let root = tempfile::tempdir().expect("tempdir");
        init(&options(root.path())).expect("init");
        let ca = read_ending(&root.path().join("offline/server-ca.pem")).expect("read");
        let life = ca.not_after - ca.not_before;
        assert!(
            life >= Duration::days(3650) && life <= Duration::days(3650) + Duration::minutes(6),
            "the server CA lives {life}"
        );
    }

    /// The keys these tools read and write are held in buffers wiped when they are dropped: were
    /// any of them a plain buffer again, this would not compile.
    #[test]
    fn the_tools_hold_keys_in_zeroizing_buffers() {
        fn contents(file: File) -> Zeroizing<Vec<u8>> {
            file.contents
        }
        fn made_key(made: Made) -> Zeroizing<String> {
            made.key_pem
        }
        fn makes() -> Zeroizing<Vec<u8>> {
            crate::package::signing_key().expect("a key").0
        }
        fn creates() -> Zeroizing<String> {
            authority("Test CA", &Organization::default(), 1)
                .expect("a CA")
                .1
        }

        assert!(!makes().is_empty());
        assert_eq!(*contents(key("key.pem", "pem")), b"pem");
        assert!(creates().starts_with("-----BEGIN PRIVATE KEY-----"));
        let made = Made {
            cert_pem: String::new(),
            key_pem: Zeroizing::new("key".to_string()),
            serial: String::new(),
            cut: false,
        };
        assert_eq!(made_key(made).as_str(), "key");
    }
}
