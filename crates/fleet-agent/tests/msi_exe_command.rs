//! The MSI's custom-action command lines, parsed the way Windows will parse them
//! (`packaging/windows/supervisor.wxs`, ADR-0019).
//!
//! A guard on the hazard ADR-0019 clause 8 rules out.
//!
//! `[INSTALLFOLDER]` always resolves with a trailing backslash, and the C runtime that builds a
//! process's argv treats a backslash before a quote as an escaped, literal quote — so
//! `--root &quot;[INSTALLFOLDER]&quot;` would not end the argument at the closing quote. The root
//! would swallow the rest of the command line, `service install` would stage into an impossible
//! path, and every MSI install would die with error 1722 ("A program run as part of the setup did
//! not finish as expected").
//!
//! The MSI passes no root at all: `Program Files` holds the payload and the layout goes under
//! `%ProgramData%`, so no directory property reaches a command line. That is the stronger fix — a
//! doubled backslash is one edit away from being undoubled, while an argument that is not there
//! cannot be mis-split. Both facts are asserted below, because the day someone adds `--root` here,
//! they bring error 1722 with it.
//!
//! This test formats each ExeCommand the way msiexec does, splits it under the CRT's documented
//! rules, and feeds the result to the real CLI parser — pure string handling, so the Windows
//! failure is caught on every platform.

use std::collections::BTreeMap;
use std::path::Path;

use fleet_agent::cli::{self, Command, ServiceAction};

/// A realistic resolution of `ProgramFiles64Folder\opamp-fleet`: a space in the path, and — the
/// whole point — the trailing backslash every Windows Installer directory property carries. Still
/// substituted below even though no command line names it any more, so that a reintroduced
/// `--root` would be parsed under the conditions that broke it.
const INSTALLFOLDER: &str = r"C:\Program Files\opamp-fleet\";
const ENDPOINT: &str = "wss://fleet.example.com/v1/opamp";
const PROGRAM: &str = r"C:\Program Files\opamp-fleet\supervisor.exe";

/// Split a command line into arguments by the C runtime's rules ("Parsing C++ command-line
/// arguments"): whitespace separates arguments outside quotes; 2n backslashes before a quote
/// become n backslashes and the quote opens/closes; 2n+1 backslashes before a quote become n
/// backslashes and a literal quote; backslashes not before a quote are literal.
fn split_as_crt(line: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut arg = String::new();
    let mut in_arg = false;
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                in_arg = true;
                let mut n = 1;
                while chars.peek() == Some(&'\\') {
                    chars.next();
                    n += 1;
                }
                if chars.peek() == Some(&'"') {
                    arg.push_str(&"\\".repeat(n / 2));
                    if n % 2 == 1 {
                        chars.next();
                        arg.push('"');
                    }
                    // n even: the quote stays for the next iteration and opens/closes there.
                } else {
                    arg.push_str(&"\\".repeat(n));
                }
            }
            '"' => {
                in_arg = true;
                if in_quotes && chars.peek() == Some(&'"') {
                    chars.next();
                    arg.push('"');
                } else {
                    in_quotes = !in_quotes;
                }
            }
            ' ' | '\t' if !in_quotes => {
                if in_arg {
                    args.push(std::mem::take(&mut arg));
                    in_arg = false;
                }
            }
            _ => {
                in_arg = true;
                arg.push(c);
            }
        }
    }
    if in_arg {
        args.push(arg);
    }
    args
}

/// The splitter against the reference table in Microsoft's "Parsing C++ command-line arguments" —
/// what makes the assertions below evidence about the `.wxs` rather than about this file.
#[test]
fn splitter_follows_the_crt_reference_table() {
    assert_eq!(split_as_crt(r#""abc" d e"#), ["abc", "d", "e"]);
    assert_eq!(split_as_crt(r#"a\\\b d"e f"g h"#), [r"a\\\b", "de fg", "h"]);
    assert_eq!(split_as_crt(r#"a\\\"b c d"#), [r#"a\"b"#, "c", "d"]);
    assert_eq!(split_as_crt(r#"a\\\\"b c" d e"#), [r"a\\b c", "d", "e"]);
}

fn package_source() -> String {
    let wxs = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/windows/supervisor.wxs");
    std::fs::read_to_string(&wxs).unwrap_or_else(|e| panic!("cannot read {}: {e}", wxs.display()))
}

/// Every `ExeCommand` in the package source, keyed by its custom action's `Id`, with the XML
/// entities decoded.
fn exe_commands() -> BTreeMap<String, String> {
    package_source()
        .split("<CustomAction")
        .skip(1)
        .filter_map(|block| {
            let element = &block[..block.find('>').expect("unterminated CustomAction element")];
            Some((attribute(element, "Id")?, attribute(element, "ExeCommand")?))
        })
        .collect()
}

fn attribute(element: &str, name: &str) -> Option<String> {
    let opener = format!("{name}=\"");
    let start = element.find(&opener)? + opener.len();
    let value = &element[start..start + element[start..].find('"')?];
    Some(
        value
            .replace("&quot;", "\"")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&"),
    )
}

/// A type 18 custom action's command line is the quoted file followed by the ExeCommand, with the
/// bracketed properties formatted in. `self_update_flag` is what `[SELFUPDATEFLAG]` resolves to:
/// the empty string when the consent stands (an unset property formats to nothing), and the flag
/// itself when the checkbox was cleared or `SELFUPDATE=0` was given.
fn parse_with(exe_command: &str, self_update_flag: &str) -> cli::Parsed {
    let line = format!("\"{PROGRAM}\" {exe_command}")
        .replace("[INSTALLFOLDER]", INSTALLFOLDER)
        .replace("[ENDPOINT]", ENDPOINT)
        .replace("[SELFUPDATEFLAG]", self_update_flag);
    cli::parse_from(split_as_crt(&line)).unwrap_or_else(|e| panic!("the CLI refuses `{line}`: {e}"))
}

/// The ordinary resolution: every answer left at its default, so the self-update flag is absent.
fn parse(exe_command: &str) -> cli::Parsed {
    parse_with(exe_command, "")
}

/// What the `.wxs` sets `SELFUPDATEFLAG` to, read from the source rather than restated here — a
/// flag this test spelled itself would pass while the package shipped a typo.
fn self_update_flag() -> String {
    let element = set_property("SELFUPDATEFLAG");
    attribute(&element, "Value").expect("SELFUPDATEFLAG has no Value")
}

/// One `SetProperty` element from the package source, by the property it sets. By Id rather than by
/// position: the package has several, and a test that took "the first one" would silently start
/// asserting about a different property the day another is added.
fn set_property(id: &str) -> String {
    package_source()
        .split("<SetProperty")
        .skip(1)
        .map(|block| {
            block[..block.find('>').expect("unterminated SetProperty element")].to_string()
        })
        .find(|element| attribute(element, "Id").as_deref() == Some(id))
        .unwrap_or_else(|| panic!("no SetProperty for {id} in the package source"))
}

fn install_args(parsed: cli::Parsed) -> cli::InstallArgs {
    match parsed.cli.command {
        Some(Command::Service {
            action: ServiceAction::Install(args),
        }) => args,
        other => panic!("expected `service install`, parsed {other:?}"),
    }
}

/// Verifies: ADR-0019
#[test]
fn register_service_with_endpoint_survives_the_crt() {
    let args = install_args(parse(&exe_commands()["RegisterServiceWithEndpoint"]));
    assert_eq!(args.endpoint.as_deref(), Some(ENDPOINT));
    assert!(!args.interactive);
}

/// Verifies: ADR-0019
#[test]
fn register_service_survives_the_crt() {
    let args = install_args(parse(&exe_commands()["RegisterService"]));
    assert_eq!(args.endpoint, None);
}

/// ADR-0019 clause 8: the MSI names neither root, so the install takes the platform defaults —
/// `%ProgramData%\opamp-fleet` for both halves — and `Program Files` holds only the payload.
///
/// This is also what keeps error 1722 out. A directory property resolves with a trailing backslash,
/// and there is no command line for one to reach.
/// Verifies: ADR-0019
#[test]
fn the_msi_names_no_root_so_no_directory_property_reaches_a_command_line() {
    for (id, command) in exe_commands() {
        assert!(
            !command.contains("[INSTALLFOLDER]"),
            "{id} passes a directory property again — the trailing backslash that resolves into \
             it is what produced error 1722 (ADR-0019 clause 8)"
        );
        assert!(
            !command.contains("--root") && !command.contains("--data-root"),
            "{id} names a root; the MSI takes the platform defaults so an archive install and a \
             packaged one put the same things in the same places"
        );
    }
    let args = install_args(parse(&exe_commands()["RegisterService"]));
    assert_eq!(args.root, None);
    assert_eq!(args.data_root, None);
}

/// The endpoint prefill (ADR-0019): the development Server over TLS on the loopback literal, held
/// to the loader's own endpoint rule so the dialog can never offer a value that `service install
/// --endpoint` would then reject. And it must stay confined to the UI sequence: leaking it into a
/// silent install would write the development default on every unattended host, the state
/// ADR-0019 refuses to manufacture.
/// Verifies: ADR-0019
#[test]
fn endpoint_prefill_is_the_development_server_and_interactive_only() {
    let element = set_property("ENDPOINT");
    let element = element.as_str();
    let value = attribute(element, "Value").expect("the prefill has no Value");
    assert_eq!(value, "wss://127.0.0.1:4320/v1/opamp");
    fleet_agent::config::ClientConfig {
        endpoint: value,
        ..Default::default()
    }
    .transport()
    .expect("the loader rejects the prefilled endpoint");
    assert_eq!(attribute(element, "Sequence").as_deref(), Some("ui"));
}

/// ADR-0018: the consent stands unless the install was told otherwise, and the MSI's answer travels
/// as a flag appended to the same command line. Two things have to hold, and the second is the one
/// that would break silently: the withdrawing line must parse to `--no-self-update`, and the
/// *consenting* line must be character for character what this package sent before the flag
/// existed — an unset formatted property resolves to nothing, so no `--` argument may appear.
/// Verifies: ADR-0018
#[test]
fn the_self_update_answer_rides_both_register_actions() {
    let commands = exe_commands();
    let flag = self_update_flag();
    assert_eq!(flag, " --no-self-update", "the package's own spelling");

    for id in ["RegisterServiceWithEndpoint", "RegisterService"] {
        let command = &commands[id];
        assert!(
            command.contains("[SELFUPDATEFLAG]"),
            "{id} does not carry the self-update answer"
        );

        // Consent: the flag resolves to nothing and the arguments are the ones from before.
        let standing = install_args(parse(command));
        assert_eq!(standing.root, None);
        assert!(
            !standing.no_self_update,
            "{id} withdrew a consent nobody withdrew"
        );

        // Withdrawal: the same line with the property set.
        let withdrawn = install_args(parse_with(command, &flag));
        assert_eq!(withdrawn.root, None);
        assert!(withdrawn.no_self_update, "{id} did not pass the withdrawal");
    }

    // The endpoint answer is untouched by either, which is what appending rather than branching buys.
    assert_eq!(
        install_args(parse_with(&commands["RegisterServiceWithEndpoint"], &flag))
            .endpoint
            .as_deref(),
        Some(ENDPOINT)
    );
}

/// The MSI trap the package comments name: a condition on a bare property name is true for any
/// non-empty value, so the withdrawal has to test for the literal `"0"` an administrator types as
/// well as for the empty property a cleared checkbox leaves. A condition of just `NOT SELFUPDATE`
/// would honour the checkbox and silently ignore `SELFUPDATE=0`.
/// Verifies: ADR-0018
#[test]
fn the_withdrawal_condition_reads_both_spellings_of_off() {
    let condition = attribute(&set_property("SELFUPDATEFLAG"), "Condition")
        .expect("SELFUPDATEFLAG has no Condition");
    assert!(
        condition.contains("NOT SELFUPDATE"),
        "a cleared checkbox leaves the property empty: {condition}"
    );
    assert!(
        condition.contains("SELFUPDATE=\"0\""),
        "an administrator types SELFUPDATE=0, which is non-empty and therefore truthy: {condition}"
    );

    // Default-on for every install path — unlike the endpoint prefill, whose UI-only scope is the
    // point of `endpoint_prefill_is_the_development_server_and_interactive_only`. A silent install
    // that names nothing must still get a fleet-updatable Client (ADR-0018). The default lives on
    // the `Property` element, which both sequences see; the flag it feeds is computed in the
    // execute sequence alone, because `InstallInitialize` — the place a SetProperty feeding a
    // deferred action belongs before — exists only there.
    let source = package_source();
    let property = source
        .split("<Property")
        .skip(1)
        .map(|block| block[..block.find('>').expect("unterminated Property")].to_string())
        .find(|element| attribute(element, "Id").as_deref() == Some("SELFUPDATE"))
        .expect("no SELFUPDATE property");
    assert_eq!(attribute(&property, "Value").as_deref(), Some("1"));
    assert_eq!(
        attribute(&set_property("SELFUPDATEFLAG"), "Sequence").as_deref(),
        Some("execute"),
        "the UI sequence has no InstallInitialize to schedule against"
    );
}

/// Verifies: ADR-0019
#[test]
fn stop_and_unregister_survive_the_crt() {
    let commands = exe_commands();
    assert!(matches!(
        parse(&commands["StopService"]).cli.command,
        Some(Command::Service {
            action: ServiceAction::Stop(_)
        })
    ));
    assert!(matches!(
        parse(&commands["UnregisterService"]).cli.command,
        Some(Command::Service {
            action: ServiceAction::Uninstall(_)
        })
    ));
}

/// The endpoint dialog asks for no client identity and names where it goes instead: the client
/// certificate and its key, as `cert_file` and `key_file`, in the configuration under
/// `%ProgramData%` — not in the installation folder, which holds only the payload. It mentions no
/// credential, since the Client reads none.
/// Verifies: ADR-0019
#[test]
fn the_endpoint_dialog_names_the_identity_and_no_credential() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/windows/EndpointDlg.wxs");
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let texts: Vec<String> = source
        .split("<Control")
        .skip(1)
        .filter_map(|block| attribute(&block[..block.find('>')?], "Text"))
        .collect();
    let shown = texts.join("\n");
    for named in [
        "client certificate",
        "cert_file",
        "key_file",
        "%ProgramData%",
    ] {
        assert!(
            shown.contains(named),
            "the dialog does not name {named}: {shown}"
        );
    }
    assert!(
        !shown.contains("installation folder"),
        "the configuration is not in the installation folder: {shown}"
    );
    let lower = source.to_lowercase();
    for absent in ["credential", "[auth]", "bearer", "password"] {
        assert!(!lower.contains(absent), "EndpointDlg.wxs mentions {absent}");
    }
}
