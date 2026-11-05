//! The host's own description, read from the platform (ADR-0016): the adapter behind
//! [`HostFacts`]. Every fact that cannot change under a running process is read once; the network
//! addresses are read live.

use std::net::IpAddr;

use crate::supervisor::ports::{HostFacts, OsInfo};

/// The platform this process runs on.
pub struct SystemHost;

impl HostFacts for SystemHost {
    fn os(&self) -> &OsInfo {
        os_info()
    }

    fn host_name(&self) -> Option<&str> {
        host_name()
    }

    fn host_id(&self) -> Option<&str> {
        host_id()
    }

    fn cpu_model(&self) -> Option<&str> {
        cpu_model()
    }

    fn addresses(&self) -> (Vec<String>, Vec<String>) {
        host_addresses()
    }

    fn now_ns(&self) -> u64 {
        crate::supervisor::process::now_ns()
    }

    fn process_id(&self) -> u32 {
        std::process::id()
    }
}

/// The host's network addresses, enumerated live from the platform (ADR-0016).
fn host_addresses() -> (Vec<String>, Vec<String>) {
    let networks = sysinfo::Networks::new_with_refreshed_list();
    collect_host_addresses(networks.values().map(|data| {
        (
            data.mac_address().0,
            data.ip_networks().iter().map(|net| net.addr).collect(),
        )
    }))
}

/// The rules of [`host_addresses`], separated from the platform so they are testable: an
/// interface whose every address is loopback is skipped whole — its MAC too, which is how the
/// conventions' "excluding loopback interfaces" reads for both keys — and an unspecified MAC is
/// no answer. Both lists come out deduplicated and sorted, so the description does not change
/// with enumeration order and re-report an unchanged host.
///
/// The formats are the conventions': IPv4 dotted-quad and IPv6 RFC 5952 (both what [`IpAddr`]'s
/// `Display` writes), the MAC in IEEE RA hyphen-separated uppercase hexadecimal.
fn collect_host_addresses(
    interfaces: impl Iterator<Item = ([u8; 6], Vec<IpAddr>)>,
) -> (Vec<String>, Vec<String>) {
    let mut ips = std::collections::BTreeSet::new();
    let mut macs = std::collections::BTreeSet::new();
    for (mac, addrs) in interfaces {
        if !addrs.is_empty() && addrs.iter().all(IpAddr::is_loopback) {
            continue;
        }
        if mac != [0; 6] {
            macs.insert(format!(
                "{:02X}-{:02X}-{:02X}-{:02X}-{:02X}-{:02X}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            ));
        }
        ips.extend(
            addrs
                .iter()
                .filter(|ip| !ip.is_loopback())
                .map(ToString::to_string),
        );
    }
    (ips.into_iter().collect(), macs.into_iter().collect())
}

fn os_info() -> &'static OsInfo {
    static INFO: std::sync::OnceLock<OsInfo> = std::sync::OnceLock::new();
    INFO.get_or_init(read_os_info)
}

#[cfg(target_os = "linux")]
fn read_os_info() -> OsInfo {
    std::fs::read_to_string("/etc/os-release")
        .map(|text| parse_os_release(&text))
        .unwrap_or_default()
}

/// os-release(5): NAME="Ubuntu", VERSION_ID="24.04", PRETTY_NAME="Ubuntu 24.04.2 LTS", and —
/// where the distribution stamps its image builds — BUILD_ID.
#[cfg(target_os = "linux")]
fn parse_os_release(text: &str) -> OsInfo {
    let field = |key: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
            .map(|value| value.trim().trim_matches(['"', '\'']).to_string())
            .filter(|value| !value.is_empty())
    };
    OsInfo {
        description: field("PRETTY_NAME"),
        name: field("NAME"),
        version: field("VERSION_ID"),
        build_id: field("BUILD_ID"),
    }
}

#[cfg(target_os = "macos")]
fn read_os_info() -> OsInfo {
    // `sw_vers` prints ProductName/ProductVersion/BuildVersion lines, e.g. "macOS" / "15.5".
    let Ok(output) = std::process::Command::new("sw_vers").output() else {
        return OsInfo::default();
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let field = |name: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(name))
            .map(|value| value.trim_start_matches(':').trim().to_string())
            .filter(|value| !value.is_empty())
    };
    let name = field("ProductName");
    let version = field("ProductVersion");
    let description = match (&name, &version) {
        (Some(name), Some(version)) => Some(format!("{name} {version}")),
        (Some(name), None) => Some(name.clone()),
        _ => None,
    };
    OsInfo {
        description,
        name,
        version,
        build_id: field("BuildVersion"),
    }
}

#[cfg(windows)]
fn read_os_info() -> OsInfo {
    // `cmd /c ver` prints e.g. "Microsoft Windows [Version 10.0.26100.2033]".
    let Ok(output) = std::process::Command::new("cmd")
        .args(["/c", "ver"])
        .output()
    else {
        return OsInfo::default();
    };
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() {
        return OsInfo::default();
    }
    // The version is what stands between "[Version " and "]". When that shape is not what this
    // Windows printed, the line is still the description — which is the whole of what this
    // platform offers instead of a structured answer.
    let version = text
        .split_once('[')
        .and_then(|(_, rest)| rest.split_once(']'))
        .map(|(inside, _)| inside.trim_start_matches("Version").trim().to_string())
        .filter(|value| !value.is_empty());
    // `os.build_id` is the build that version line ends in: "10.0.26100.2033" is
    // major.minor.build.revision, and the conventions' Windows example names the build ("22621").
    // Everything from the third component on, so the UBR revision stays attached when `ver`
    // prints one.
    let build_id = version.as_ref().and_then(|version| {
        let parts: Vec<&str> = version.split('.').collect();
        (parts.len() >= 3).then(|| parts[2..].join("."))
    });
    OsInfo {
        description: Some(text),
        name: Some("Windows".to_string()),
        version,
        build_id,
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn read_os_info() -> OsInfo {
    OsInfo::default()
}

/// The processor's model designation (`host.cpu.model.name`) — read once, hardware does not
/// change under a running process. From the same `sysinfo` the addresses come from (ADR-0016);
/// one CPU answers for all of them, which is what the convention's singular key asks for.
fn cpu_model() -> Option<&'static str> {
    static MODEL: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    MODEL
        .get_or_init(|| {
            let mut system = sysinfo::System::new();
            system.refresh_cpu_list(sysinfo::CpuRefreshKind::nothing());
            system
                .cpus()
                .first()
                .map(|cpu| cpu.brand().trim().to_string())
                .filter(|brand| !brand.is_empty())
        })
        .as_deref()
}

/// The host's name (`host.name`) — read once. ADR-0026 twice offers a Selector on this attribute
/// as the way to pin one host to one artifact, so a fleet that does not report it cannot be aimed
/// at a machine at all.
pub(crate) fn host_name() -> Option<&'static str> {
    static NAME: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    NAME.get_or_init(read_host_name).as_deref()
}

#[cfg(unix)]
fn read_host_name() -> Option<String> {
    // HOST_NAME_MAX is 64 on Linux and 255 on macOS; 256 holds either. A name that had to be
    // truncated is not required to be terminated, which is why the end is scanned for rather
    // than assumed.
    let mut buffer = vec![0u8; 256];
    // SAFETY: `buffer` is writable for `buffer.len()` bytes and outlives the call.
    if unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) } != 0 {
        return None;
    }
    let end = buffer.iter().position(|&b| b == 0).unwrap_or(buffer.len());
    let name = String::from_utf8_lossy(&buffer[..end]).trim().to_string();
    (!name.is_empty()).then_some(name)
}

#[cfg(windows)]
fn read_host_name() -> Option<String> {
    // The SCM starts the service with the machine's environment, where COMPUTERNAME is always
    // set — so this one answer costs no process, unlike every other one this platform gives.
    std::env::var("COMPUTERNAME")
        .ok()
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
}

#[cfg(not(any(unix, windows)))]
fn read_host_name() -> Option<String> {
    None
}

/// The host's installation identity (`host.id`) — read once. What still names the machine after it
/// has been renamed, which `host.name` by itself does not.
fn host_id() -> Option<&'static str> {
    static ID: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    ID.get_or_init(read_host_id).as_deref()
}

#[cfg(target_os = "linux")]
fn read_host_id() -> Option<String> {
    // machine-id(5): 32 hex characters, generated once per installation. The D-Bus copy is where
    // it lives on systems that do not populate /etc/machine-id.
    ["/etc/machine-id", "/var/lib/dbus/machine-id"]
        .into_iter()
        .find_map(|path| {
            let value = std::fs::read_to_string(path).ok()?.trim().to_string();
            (!value.is_empty()).then_some(value)
        })
}

#[cfg(target_os = "macos")]
fn read_host_id() -> Option<String> {
    // ioreg prints `"IOPlatformUUID" = "…"` among the platform device's properties.
    let output = std::process::Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let value = text
        .lines()
        .find(|line| line.contains("IOPlatformUUID"))?
        .split_once('=')?
        .1
        .trim()
        .trim_matches('"')
        .to_string();
    (!value.is_empty()).then_some(value)
}

#[cfg(windows)]
fn read_host_id() -> Option<String> {
    // The MachineGuid the installer writes. `reg query` prints
    // "    MachineGuid    REG_SZ    <guid>" and needs no registry binding to read.
    let output = std::process::Command::new("reg")
        .args([
            "query",
            r"HKLM\SOFTWARE\Microsoft\Cryptography",
            "/v",
            "MachineGuid",
        ])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let value = text
        .lines()
        .find(|line| line.contains("MachineGuid"))?
        .split_whitespace()
        .last()?
        .to_string();
    (!value.is_empty()).then_some(value)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn read_host_id() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `host.ip` and `host.mac` as the conventions define them (ADR-0016): loopback interfaces
    /// excluded whole — the MAC of one too — an unspecified MAC not an answer, everything
    /// deduplicated and sorted so the description is stable across enumeration order, IPv6 in
    /// RFC 5952 form and the MAC in IEEE RA hyphenated uppercase.
    // Verifies: ADR-0016
    #[test]
    fn host_addresses_follow_the_conventions() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        let loopback = (
            [0; 6],
            vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ],
        );
        let mac = [0xac, 0xde, 0x48, 0x23, 0x45, 0x67];
        let ethernet = (
            mac,
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 140)),
                IpAddr::V6(Ipv6Addr::new(
                    0xfe80, 0, 0, 0, 0xabc2, 0x4a28, 0x737a, 0x609e,
                )),
            ],
        );
        // A bond partner: the same MAC again, one of its addresses again.
        let bonded = (mac, vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 140))]);
        // A tunnel: an address worth reporting, no hardware address behind it.
        let tunnel = ([0; 6], vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))]);
        let (ips, macs) = collect_host_addresses([loopback, ethernet, bonded, tunnel].into_iter());
        assert_eq!(
            ips,
            ["10.0.0.7", "192.168.1.140", "fe80::abc2:4a28:737a:609e"]
        );
        assert_eq!(macs, ["AC-DE-48-23-45-67"]);
    }

    /// The os-release parser behind `os.*`, now including `os.build_id` (ADR-0016): quotes
    /// stripped, an absent or empty field absent rather than blank.
    #[cfg(target_os = "linux")]
    #[test]
    fn os_release_parses_the_fields_the_description_reports() {
        let info = parse_os_release(
            "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.2 LTS\"\nBUILD_ID=20240801.1\nVARIANT=\n",
        );
        assert_eq!(info.name.as_deref(), Some("Ubuntu"));
        assert_eq!(info.version.as_deref(), Some("24.04"));
        assert_eq!(info.description.as_deref(), Some("Ubuntu 24.04.2 LTS"));
        assert_eq!(info.build_id.as_deref(), Some("20240801.1"));
        assert_eq!(parse_os_release("BUILD_ID=\n").build_id, None);
    }
}
