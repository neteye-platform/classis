//! The install command the operator pastes on a host. The scripts take the
//! endpoint and the key and never a Space, since the key names it.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Linux,
    Windows,
}

/// The one-liner that fetches the install script from `endpoint` and passes it `key`.
///
/// Both come from the Server: `endpoint` from its validated public URL, HTTPS or a loopback HTTP
/// origin and possibly behind a reverse-proxy path prefix, `key` from the characters its keys are
/// generated from. Neither can hold a single quote, so every URL and argument is single-quoted.
pub fn install_command(endpoint: &str, key: &str, os: Os) -> String {
    let endpoint = endpoint.trim_end_matches('/');
    match os {
        Os::Linux => {
            let proto = if endpoint.starts_with("https://") {
                "--proto '=https' --tlsv1.3"
            } else {
                "--proto '=http'"
            };
            format!(
                "curl {proto} -fsS '{endpoint}/v1/install.sh' | sudo sh -s -- --url '{endpoint}' --key '{key}'"
            )
        }
        Os::Windows => {
            let tls = if endpoint.starts_with("https://") {
                "[Net.ServicePointManager]::SecurityProtocol = 12288; "
            } else {
                ""
            };
            format!(
                "{tls}& ([scriptblock]::Create((Invoke-RestMethod -Uri '{endpoint}/v1/install.ps1' -MaximumRedirection 0))) -Url '{endpoint}' -Key '{key}'"
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "https://neteye.example/neteye/classis";
    const LOOPBACK: &str = "http://127.0.0.1:8443/neteye/classis";
    const KEY: &str = "cle1_acme_secret";

    #[test]
    fn linux_command_fetches_the_script_and_passes_the_key() {
        assert_eq!(
            install_command(BASE, KEY, Os::Linux),
            "curl --proto '=https' --tlsv1.3 -fsS 'https://neteye.example/neteye/classis/v1/install.sh' | sudo sh -s -- --url 'https://neteye.example/neteye/classis' --key 'cle1_acme_secret'"
        );
    }

    #[test]
    fn windows_command_fetches_the_script_and_passes_the_key() {
        assert_eq!(
            install_command(BASE, KEY, Os::Windows),
            "[Net.ServicePointManager]::SecurityProtocol = 12288; & ([scriptblock]::Create((Invoke-RestMethod -Uri 'https://neteye.example/neteye/classis/v1/install.ps1' -MaximumRedirection 0))) -Url 'https://neteye.example/neteye/classis' -Key 'cle1_acme_secret'"
        );
    }

    #[test]
    fn trailing_slashes_of_the_endpoint_are_stripped() {
        for os in [Os::Linux, Os::Windows] {
            assert_eq!(
                install_command("https://neteye.example/neteye/classis//", KEY, os),
                install_command(BASE, KEY, os)
            );
        }
    }

    #[test]
    fn a_server_at_the_origin_of_a_domain_keeps_one_path_segment() {
        assert_eq!(
            install_command("https://neteye.example/", KEY, Os::Linux),
            "curl --proto '=https' --tlsv1.3 -fsS 'https://neteye.example/v1/install.sh' | sudo sh -s -- --url 'https://neteye.example' --key 'cle1_acme_secret'"
        );
    }

    #[test]
    fn a_reverse_proxy_path_prefix_stays_in_the_script_url_and_the_endpoint() {
        for os in [Os::Linux, Os::Windows] {
            let command = install_command("https://neteye.example/neteye/classis//", KEY, os);
            assert!(
                command.contains("'https://neteye.example/neteye/classis/v1/install."),
                "{command}"
            );
            assert!(
                command.contains("'https://neteye.example/neteye/classis'"),
                "{command}"
            );
        }
    }

    #[test]
    fn a_loopback_http_endpoint_fetches_over_http_without_a_tls_floor() {
        assert_eq!(
            install_command(LOOPBACK, KEY, Os::Linux),
            "curl --proto '=http' -fsS 'http://127.0.0.1:8443/neteye/classis/v1/install.sh' | sudo sh -s -- --url 'http://127.0.0.1:8443/neteye/classis' --key 'cle1_acme_secret'"
        );
        assert_eq!(
            install_command(LOOPBACK, KEY, Os::Windows),
            "& ([scriptblock]::Create((Invoke-RestMethod -Uri 'http://127.0.0.1:8443/neteye/classis/v1/install.ps1' -MaximumRedirection 0))) -Url 'http://127.0.0.1:8443/neteye/classis' -Key 'cle1_acme_secret'"
        );
    }

    #[test]
    fn the_key_is_an_argument_never_part_of_a_url() {
        for endpoint in [BASE, LOOPBACK] {
            for os in [Os::Linux, Os::Windows] {
                let command = install_command(endpoint, KEY, os);
                let script_url = command
                    .split_whitespace()
                    .find(|word| word.contains("/v1/install."))
                    .expect("the script URL");
                assert!(!script_url.contains(KEY), "{script_url}");
                assert_eq!(command.matches(KEY).count(), 1, "{command}");
            }
        }
    }
}
