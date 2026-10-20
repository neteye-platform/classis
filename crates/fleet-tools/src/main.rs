//! `opamp-fleetctl` — the operator tool (ADR-0028): what an operator makes before a fleet does
//! anything useful, on the operator's own machine. `package` fetches, packs, hashes and signs
//! package artifacts and makes the signing key; `pki` makes the fleet's certificates and says when
//! they end. Neither the Server nor a Client depends on it, and a managed host never runs it.
//!
//! Status goes to stderr and results to stdout, so a hash, a key or a signature composes into a
//! shell variable while the commentary stays on the terminal.

#![forbid(unsafe_code)]

mod fetch;
mod package;
mod pki;
mod signing;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "opamp-fleetctl",
    about = "The OpAMP Fleet operator tool: package artifacts and the fleet's certificates",
    // The git-derived version baked in at build time (ADR-0012) — never clap's default, which
    // would report the static crate version.
    version = fleet_core::version::current()
)]
struct Cli {
    #[command(subcommand)]
    tree: Tree,
}

/// The two command trees, and nothing else (ADR-0028 clause 15).
#[derive(Subcommand)]
enum Tree {
    /// Fetch, pack, hash and sign package artifacts, and make the package signing key.
    #[command(subcommand)]
    Package(package::Command),
    /// Make the fleet's certificate authorities, server and bootstrap certificates, and say when
    /// they end.
    #[command(subcommand)]
    Pki(pki::Command),
}

fn main() -> ExitCode {
    // reqwest is built with `rustls-no-provider`, which refuses to construct a TLS client until a
    // process-wide provider exists (ADR-0013).
    opamp::tls::install_ring_provider();
    let result = match Cli::parse().tree {
        Tree::Package(command) => package::run(command).map(|()| 0),
        Tree::Pki(command) => pki::run(command),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    fn subcommands(command: &clap::Command) -> Vec<String> {
        command
            .get_subcommands()
            .map(|sub| sub.get_name().to_string())
            .collect()
    }

    // Verifies: ADR-0028, ADR-0031
    #[test]
    fn the_program_has_two_trees_holding_the_operator_commands() {
        let cli = Cli::command();
        assert_eq!(cli.get_name(), "opamp-fleetctl");
        assert_eq!(subcommands(&cli), ["package", "pki"]);
        let tree = |name| cli.find_subcommand(name).expect(name);
        assert_eq!(
            subcommands(tree("package")),
            ["fetch", "keygen", "sign", "public-key", "pack", "sha256"]
        );
        assert_eq!(
            subcommands(tree("pki")),
            [
                "init",
                "server-cert",
                "bootstrap-ca",
                "status",
                "p12-extract"
            ]
        );
        assert!(
            Cli::try_parse_from(["opamp-fleetctl", "pki", "bootstrap-cert", "--out", "b"]).is_err(),
            "the Server issues bootstrap certificates (ADR-0028)"
        );
    }

    // Verifies: ADR-0028
    #[test]
    fn the_version_flag_reports_the_baked_version() {
        let err = Cli::try_parse_from(["opamp-fleetctl", "--version"])
            .err()
            .expect("--version ends parsing");
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
        assert!(err.to_string().contains(fleet_core::version::current()));
    }

    /// `sign` has two forms and no mixture of them: the artifact form names the type, the version
    /// and the file; the signing-file form names the file alone, since the type and version are in
    /// it. A mixture would leave a reader guessing which statement got signed.
    /// Verifies: ADR-0027
    #[test]
    fn sign_takes_an_artifact_or_a_signing_file_and_never_both() {
        let parse = |args: &[&str]| {
            let mut all = vec!["opamp-fleetctl", "package", "sign", "--key", "k.pk8"];
            all.extend_from_slice(args);
            Cli::try_parse_from(all)
        };
        assert!(parse(&["--agent-type", "a", "--version", "1", "art"]).is_ok());
        assert!(parse(&["--signing-info", "s.json"]).is_ok());
        assert!(parse(&["--signing-info", "s.json", "--out", "o.json"]).is_ok());
        assert!(parse(&["--signing-info", "s.json", "--version", "1"]).is_err());
        assert!(parse(&["--signing-info", "s.json", "art"]).is_err());
        assert!(parse(&["--agent-type", "a", "--version", "1", "art", "--out", "o"]).is_err());
        assert!(parse(&[]).is_err());
    }
}
