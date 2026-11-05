// The product's name and title, fixed at build time (ADR-0019 clause 2).
//
// `PRODUCT_NAME` names the installation: the directory under the platform's base, the service, the
// `.deb`/`.rpm` package, the `/usr/libexec` payload directory and the `PATH` symlink. A second
// instance is a second build, so the name has to exist before anything the build produces —
// which is why it is here and not a runtime value read from a configuration file the name itself
// decides the location of.
//
// The display name is prose and cannot be derived from the slug by any rule that would still read
// correctly for the next variant, so it is a second variable rather than a transformation.
//
// The grammar is the one ADR-0019 set for instance names, for the same reason: the value must be
// simultaneously a systemd unit name, a launchd label, an SCM service name and a directory name on
// every platform. Breaking it fails *this build* — the class of failure ADR-0019 clause 2 moves
// from a runtime parse of operator input to a compile-time check, so an illegal name cannot reach
// a service manager at all.

const DEFAULT_PRODUCT_NAME: &str = "opamp-fleet";
const DEFAULT_PRODUCT_TITLE: &str = "OpAMP Fleet Agent";

/// Legal under the grammar below, but invalid directory names on Windows — and the product is a
/// directory everywhere.
const WINDOWS_RESERVED: [&str; 22] = [
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

fn main() {
    println!("cargo:rerun-if-env-changed=OPAMP_PRODUCT_NAME");
    println!("cargo:rerun-if-env-changed=OPAMP_PRODUCT_TITLE");

    let name =
        std::env::var("OPAMP_PRODUCT_NAME").unwrap_or_else(|_| DEFAULT_PRODUCT_NAME.to_string());
    if let Err(e) = check_product_name(&name) {
        eprintln!("OPAMP_PRODUCT_NAME={name:?} is not a usable product name: {e}");
        std::process::exit(1);
    }

    // Deliberately unvalidated beyond being non-empty: it is prose, and the three places it
    // appears — Add/Remove Programs, the SCM's display column, the installer dialog's title —
    // accept prose. A name that is only whitespace is a typo, not prose.
    let display =
        std::env::var("OPAMP_PRODUCT_TITLE").unwrap_or_else(|_| DEFAULT_PRODUCT_TITLE.to_string());
    if display.trim().is_empty() {
        eprintln!("OPAMP_PRODUCT_TITLE is empty");
        std::process::exit(1);
    }

    println!("cargo:rustc-env=OPAMP_PRODUCT_NAME={name}");
    println!("cargo:rustc-env=OPAMP_PRODUCT_TITLE={display}");
}

fn check_product_name(raw: &str) -> Result<(), String> {
    if raw.is_empty() || raw.len() > 32 {
        return Err("must be 1–32 characters".to_string());
    }
    if !raw
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err("only lowercase letters, digits, and '-' are allowed".to_string());
    }
    if raw.starts_with('-') || raw.ends_with('-') {
        return Err("must not start or end with '-'".to_string());
    }
    if WINDOWS_RESERVED.contains(&raw) {
        return Err(format!("{raw:?} is a reserved device name on Windows"));
    }
    Ok(())
}
