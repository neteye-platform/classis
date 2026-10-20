//! What the Linux post-install prints (`packaging/linux/postinst`), read as text the way
//! `msi_exe_command.rs` reads the WiX source: the package is not built here, so the guidance it
//! shows an operator is checked by `cargo test` on every platform.

use std::path::Path;

fn post_install() -> String {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/linux/postinst");
    std::fs::read_to_string(&script)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", script.display()))
}

/// The lines between each `<<'EOF'` and its `EOF`: what the script prints, not its comments.
fn printed(script: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut inside = false;
    for line in script.lines() {
        if inside {
            if line == "EOF" {
                inside = false;
            } else {
                lines.push(line);
            }
        } else if line.contains("<<'EOF'") {
            inside = true;
        }
    }
    lines
}

/// Every endpoint the post-install shows an operator is one the Client accepts at startup: the
/// startup rule (`ClientConfig::transport`, which `ClientConfig::load` applies) refuses plaintext
/// off the loopback literals, so a `ws://` or `http://localhost` example would teach a value the
/// service then refuses. A placeholder host stands in for the operator's Server.
/// Verifies: ADR-0019
#[test]
fn the_post_install_prints_no_endpoint_the_client_refuses_at_startup() {
    let script = post_install();
    let printed = printed(&script);
    assert!(!printed.is_empty(), "the post-install prints its guidance");
    for endpoint in printed
        .iter()
        .flat_map(|line| line.split_whitespace())
        .filter(|word| word.contains("://"))
    {
        let endpoint = endpoint
            .trim_matches(|c: char| c == '`' || c == '\'' || c == '"')
            .replace("<server>", "fleet.example.com");
        fleet_agent::config::ClientConfig {
            endpoint: endpoint.clone(),
            ..Default::default()
        }
        .transport()
        .unwrap_or_else(|e| panic!("the post-install prints {endpoint}, refused at startup: {e}"));
    }
}

/// The first step the post-install prints is the questionnaire, which asks for the client identity;
/// an endpoint alone is never offered as a complete step, since a Client with nothing more refuses
/// to start. The `--endpoint` it does print is the scripted form, with `--fleet-files`, where the
/// install finds the bootstrap identity it enrols with. The manual alternative names the identity,
/// `[tls] cert_file` and `key_file`, and nothing the Client does not read; a password it names is
/// a `bootstrap.p12`'s, never a credential (ADR-0029 clause 13, which restates ADR-0019 clause 37).
/// Verifies: ADR-0029
#[test]
fn the_post_install_steps_ask_for_the_client_identity() {
    let script = post_install();
    let printed = printed(&script);
    let first_step = printed
        .iter()
        .find(|line| line.trim_start().starts_with("opamp-fleet service install"))
        .expect("a step that writes the configuration");
    assert!(first_step.contains("--interactive"), "{first_step}");
    let text = printed.join("\n");
    let scripted = text
        .replace("\\\n", " ")
        .lines()
        .filter(|line| line.contains("--endpoint"))
        .map(str::to_string)
        .collect::<Vec<_>>();
    assert!(!scripted.is_empty(), "the scripted form is printed");
    for line in &scripted {
        assert!(
            line.contains("--fleet-files"),
            "an endpoint-only install is not offered as a step: {line}"
        );
    }
    assert!(
        text.contains("[tls]") && text.contains("cert_file") && text.contains("key_file"),
        "{text}"
    );
    let lower = text.to_lowercase();
    for absent in ["[auth]", "credential", "bearer_token"] {
        assert!(
            !lower.contains(absent),
            "the post-install names {absent}: {text}"
        );
    }
    for line in printed
        .iter()
        .filter(|l| l.to_lowercase().contains("password"))
    {
        assert!(
            line.contains("bootstrap"),
            "a password the post-install names is a bootstrap.p12's: {line}"
        );
    }
}

fn maintainer_script(name: &str) -> String {
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../packaging/linux")
        .join(name);
    std::fs::read_to_string(&script)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", script.display()))
}

/// What the script runs: the lines outside its heredocs and comments, trimmed, each `\`
/// continuation joined onto its line.
fn commands(script: &str) -> Vec<String> {
    let mut commands = Vec::new();
    let mut inside = false;
    let mut pending = String::new();
    for line in script.lines() {
        if inside {
            inside = line != "EOF";
            continue;
        }
        if line.contains("<<'EOF'") {
            inside = true;
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(head) = line.strip_suffix('\\') {
            pending.push_str(head.trim_end());
            pending.push(' ');
            continue;
        }
        pending.push_str(line);
        commands.push(std::mem::take(&mut pending));
    }
    commands
}

/// The account exists before the first `service install` runs, created as a system account with
/// no password and no login shell, its home the data root.
/// Verifies: ADR-0042
#[test]
fn the_post_install_creates_the_account_before_it_registers() {
    let commands = commands(&post_install());
    let position = |needle: &str| {
        commands
            .iter()
            .position(|c| c.contains(needle))
            .unwrap_or_else(|| panic!("no {needle} in {commands:#?}"))
    };
    let getent = position("getent passwd opamp-fleet");
    let group = position("getent group opamp-fleet");
    let useradd = position("useradd ");
    assert!(getent < group && group < useradd, "{commands:#?}");
    let adds: Vec<&String> = commands
        .iter()
        .filter(|c| c.starts_with("useradd "))
        .collect();
    assert_eq!(
        adds,
        [
            "useradd --system --gid opamp-fleet --no-create-home --home-dir /var/lib/opamp-fleet \
             --shell /usr/sbin/nologin opamp-fleet",
            "useradd --system --user-group --no-create-home --home-dir /var/lib/opamp-fleet \
             --shell /usr/sbin/nologin opamp-fleet",
        ],
        "a lone group is joined, otherwise one is created with the account"
    );
    for (index, command) in commands.iter().enumerate() {
        if command.contains("supervisor service install") {
            assert!(index > useradd, "{command} runs before the account exists");
        }
    }
}

/// `--run-as opamp-fleet` is passed only where no unit is registered; a re-registration runs
/// `service install` without it, which keeps the account the unit names.
/// Verifies: ADR-0042
#[test]
fn the_post_install_names_the_account_only_where_no_unit_is_registered() {
    let commands = commands(&post_install());
    let start = commands
        .iter()
        .position(|c| c == "if [ -e /etc/systemd/system/opamp-fleet.service ]; then")
        .unwrap_or_else(|| panic!("no test for the unit in {commands:#?}"));
    assert_eq!(
        commands[start + 1..start + 5],
        [
            "/usr/libexec/opamp-fleet/supervisor service install",
            "else",
            "/usr/libexec/opamp-fleet/supervisor service install --run-as opamp-fleet",
            "fi",
        ]
    );
    let installs = commands
        .iter()
        .filter(|c| c.contains("supervisor service install"))
        .count();
    assert_eq!(installs, 2, "{commands:#?}");
}

/// The account outlives the package: no hook removes it or its group, on removal or on purge.
/// Verifies: ADR-0042
#[test]
fn no_maintainer_script_removes_the_account() {
    for name in ["postinst", "prerm", "postrm", "posttrans"] {
        for command in commands(&maintainer_script(name)) {
            for removes in ["userdel", "groupdel", "deluser", "delgroup"] {
                assert!(!command.contains(removes), "{name}: {command}");
            }
        }
    }
}
