//! The install command the operator pastes on a host. The scripts take the
//! endpoint and the key and never a Space, since the key names it.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Linux,
    Windows,
}

/// The one-liner that fetches the install script from `endpoint` and passes it `key`.
pub fn install_command(endpoint: &str, key: &str, os: Os) -> String {
    let endpoint = endpoint.trim_end_matches('/');
    match os {
        Os::Linux => format!(
            "curl --proto '=https' --tlsv1.2 -fsSL {endpoint}/install.sh | sudo sh -s -- --token '{key}'"
        ),
        Os::Windows => format!(
            "[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; & ([scriptblock]::Create((irm {endpoint}/install.ps1))) -Token '{key}'"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "cle1_acme_secret";

    #[test]
    fn linux_command_fetches_the_script_and_passes_the_key() {
        assert_eq!(
            install_command("https://neteye.example/neteye/classis", KEY, Os::Linux),
            "curl --proto '=https' --tlsv1.2 -fsSL https://neteye.example/neteye/classis/install.sh | sudo sh -s -- --token 'cle1_acme_secret'"
        );
    }

    #[test]
    fn windows_command_fetches_the_script_and_passes_the_key() {
        assert_eq!(
            install_command("https://neteye.example/neteye/classis", KEY, Os::Windows),
            "[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; & ([scriptblock]::Create((irm https://neteye.example/neteye/classis/install.ps1))) -Token 'cle1_acme_secret'"
        );
    }

    #[test]
    fn trailing_slashes_of_the_endpoint_are_stripped() {
        for os in [Os::Linux, Os::Windows] {
            assert_eq!(
                install_command("https://neteye.example/neteye/classis//", KEY, os),
                install_command("https://neteye.example/neteye/classis", KEY, os)
            );
        }
    }
}
