//! The dependency direction of ADR-0006: a module of the core depends on no adapter and on no
//! technology. Every source file of the workspace's library crates has a role in `ROLES`; the core
//! files are read and every path they name is held to the rule. A new module fails until it is
//! given a role, so where it belongs is decided when it is written.
//!
//! The test reads source text, not the compiled crate, so every `cfg` branch is checked whatever
//! the host — the Windows and macOS paths included. Code under `#[cfg(test)]` is not checked.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Role {
    /// Domain or port: holds the rule.
    Core,
    /// Binds a port to a technology.
    Adapter,
    /// Composition root: wires adapters to the core and may depend on everything.
    Root,
}
use Role::*;

/// Every module of the checked crates, by crate directory and module path. A module path is the
/// file's path under `src` without `.rs`, `mod.rs`, or `lib.rs`; `""` is the crate root.
const ROLES: &[(&str, &[(&str, Role)])] = &[
    (
        "opamp",
        &[
            ("", Root),
            // Inline in lib.rs: the generated protobuf types.
            ("proto", Core),
            ("attributes", Core),
            ("endpoint", Core),
            ("frame", Core),
            ("uid", Core),
            ("client", Core),
            ("client::protocol", Core),
            ("client::backoff", Adapter),
            ("client::connection", Adapter),
            ("client::http", Adapter),
            ("client::ws", Adapter),
            ("server", Adapter),
            ("server::listen", Adapter),
            ("server::pace", Adapter),
            ("tls", Adapter),
        ],
    ),
    (
        "fleet-core",
        &[
            ("", Root),
            ("bootstrap_proof", Core),
            // Reading what a CSR asks for, with `x509-parser`.
            ("csr", Adapter),
            ("ending", Core),
            ("host", Core),
            ("naming", Core),
            ("package", Core),
            // The bootstrap PKCS#12 file (ADR-0029): its rule, and its binding to `p12-keystore`.
            ("pkcs12", Core),
            ("pkcs12::file", Adapter),
            ("platform", Core),
            ("renewal", Core),
            ("version", Core),
        ],
    ),
    (
        "fleet-server",
        &[
            ("", Root),
            ("main", Root),
            ("agent_rate", Core),
            ("agent_store", Core),
            ("audit", Core),
            ("blobs", Core),
            ("bootstrap", Core),
            ("configs", Core),
            ("deployments", Core),
            ("enrolment", Core),
            ("fleet", Core),
            ("labels", Core),
            ("packages", Core),
            ("revocation", Core),
            ("throttle", Core),
            ("api", Adapter),
            ("audit_log", Adapter),
            ("ca", Adapter),
            ("clock", Adapter),
            ("config", Adapter),
            ("credentials", Adapter),
            ("fs", Adapter),
            ("fs::agents", Adapter),
            ("fs::audit", Adapter),
            ("fs::blobs", Adapter),
            ("fs::bootstrap", Adapter),
            ("fs::configs", Adapter),
            ("fs::deployments", Adapter),
            ("fs::enrolment", Adapter),
            ("fs::labels", Adapter),
            ("fs::packages", Adapter),
            ("fs::revocation", Adapter),
            ("listen", Adapter),
            ("migrate", Adapter),
            ("pki", Adapter),
            ("tls", Adapter),
            ("transport", Adapter),
        ],
    ),
    (
        "fleet-agent",
        &[
            ("", Root),
            ("main", Root),
            ("bin::stub_agent", Root),
            ("bin::stub_crasher", Root),
            ("supervisor", Root),
            ("service::enrol", Root),
            ("service::runtime", Root),
            ("config", Core),
            ("engine", Core),
            ("product", Core),
            ("shutdown", Core),
            ("span", Core),
            ("supervisor::agent", Core),
            ("supervisor::agent::connection_settings", Core),
            ("supervisor::agent::description", Core),
            ("supervisor::agent::packages", Core),
            ("supervisor::agent::remote_config", Core),
            ("supervisor::block", Core),
            ("supervisor::delivered", Core),
            ("supervisor::ports", Core),
            ("supervisor::restart", Core),
            ("update", Core),
            ("archive", Adapter),
            ("cli", Adapter),
            ("config_file", Adapter),
            ("config_init", Adapter),
            ("connection", Adapter),
            ("csr", Adapter),
            ("gateway", Adapter),
            ("gateway::cache", Adapter),
            ("gateway::policy", Core),
            ("gateway::pool", Adapter),
            ("gateway::registry", Adapter),
            ("gateway::revocations", Adapter),
            ("host", Adapter),
            ("install", Adapter),
            ("logging", Adapter),
            ("packages", Adapter),
            ("reconfigure", Adapter),
            ("service", Adapter),
            ("service::layout", Adapter),
            ("service::manager", Adapter),
            ("service::run_as", Adapter),
            ("service::windows", Adapter),
            ("service::windows_config", Adapter),
            ("service::windows_rights", Adapter),
            ("storage", Adapter),
            ("supervisor::collector", Adapter),
            ("supervisor::command", Adapter),
            ("supervisor::endpoint", Adapter),
            ("supervisor::process", Adapter),
            ("telemetry", Adapter),
            ("tls", Adapter),
            ("transport", Adapter),
            ("update::installer", Adapter),
        ],
    ),
    (
        "fleet-tools",
        &[
            // One command-line program and no library (ADR-0028): nothing here is core, and a
            // module added to the crate has to be given a role like anywhere else.
            ("main", Root),
            ("fetch", Adapter),
            ("package", Adapter),
            ("pki", Adapter),
            ("signing", Adapter),
        ],
    ),
];

/// The external crates the core may name: data formats, codecs, and the logging facade — none of
/// them reaches a file, a socket, a process, or a clock.
const CORE_CRATES: &[&str] = &[
    "prost", "serde", "sha2", "hex", "base64", "uuid", "flate2", "tracing",
];

/// What the core may name of a technology, by path prefix. `tokio::sync` is channels, which need
/// no runtime and do no I/O — and ADR-0017 makes a Port a message pair over them; `tokio::select`
/// and `tokio::pin` are how the core waits on several of them, control flow over futures that
/// starts no task and touches nothing outside the process. `toml::Table` and
/// `toml::Value` are the configuration's values (ADR-0010 clause 23), which ADR-0017 hands a
/// Plugin as its block; reading and parsing the file stays at the edge. An address is a value, and
/// `env::consts` is fixed at compile time.
const CORE_PREFIXES: &[&[&str]] = &[
    &["tokio", "sync"],
    &["tokio", "select"],
    &["tokio", "pin"],
    &["toml", "Table"],
    &["toml", "Value"],
    &["std", "net", "IpAddr"],
    &["std", "net", "Ipv4Addr"],
    &["std", "net", "Ipv6Addr"],
    &["std", "net", "SocketAddr"],
    &["std", "env", "consts"],
];

/// The parts of the standard library that are technology rather than language.
const STD_TECHNOLOGY: &[&str] = &["fs", "net", "process", "env", "thread", "os"];

/// The clocks: reading the time is a technology, holding a time is not.
const CLOCKS: &[&str] = &["SystemTime", "Instant"];

/// The workspace crates a core module may reach into, by the name code uses for them.
const WORKSPACE_CRATES: &[(&str, &str)] = &[("opamp", "opamp"), ("fleet_core", "fleet-core")];

fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn roles_of(krate: &str) -> &'static [(&'static str, Role)] {
    ROLES
        .iter()
        .find(|(k, _)| *k == krate)
        .map(|(_, r)| *r)
        .unwrap_or_else(|| panic!("no roles for crate {krate}"))
}

/// Whether a path into `krate` leaves the core: the longest module prefix decides, and a module
/// that is not core — an adapter, or a composition root — is outside it. A path
/// that matches no module names an item of the crate root, which is the crate's own vocabulary.
fn leaves_the_core(krate: &str, segments: &[String]) -> bool {
    let depth = |module: &str| module.split("::").filter(|s| !s.is_empty()).count();
    let mut best = ("", Root);
    for &(module, role) in roles_of(krate) {
        let parts: Vec<&str> = module.split("::").filter(|s| !s.is_empty()).collect();
        if parts.len() > depth(best.0)
            && segments.len() >= parts.len()
            && parts.iter().zip(segments).all(|(a, b)| a == b)
        {
            best = (module, role);
        }
    }
    !best.0.is_empty() && best.1 != Core
}

fn module_path(src: &Path, file: &Path) -> String {
    let rel = file.strip_prefix(src).unwrap().with_extension("");
    let mut parts: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    if matches!(parts.last().map(String::as_str), Some("mod" | "lib")) {
        parts.pop();
    }
    parts.join("::")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The names of the external crates in the lockfile, as code spells them. The workspace's own
/// members are not technology: a path into opamp or fleet-core is judged by their roles.
fn locked_crates() -> BTreeSet<String> {
    let lock = fs::read_to_string(crates_dir().join("../Cargo.lock")).unwrap();
    let members: Vec<String> = ROLES.iter().map(|(k, _)| k.replace('-', "_")).collect();
    lock.lines()
        .filter_map(|l| l.strip_prefix("name = \""))
        .map(|n| n.trim_end_matches('"').replace('-', "_"))
        .filter(|n| !members.contains(n))
        .collect()
}

#[derive(Clone, PartialEq, Debug)]
enum Token {
    Ident(String),
    PathSep,
    Punct(char),
}

/// Rust source as identifiers, `::`, and punctuation, with comments, strings, and characters
/// dropped, each token with its line.
fn tokenize(src: &str) -> Vec<(Token, usize)> {
    let chars: Vec<char> = src.chars().collect();
    let (mut i, mut line, mut out) = (0, 1, Vec::new());
    let at = |i: usize| chars.get(i).copied().unwrap_or('\0');
    while i < chars.len() {
        let c = chars[i];
        if c == '\n' {
            line += 1;
            i += 1;
        } else if c.is_whitespace() {
            i += 1;
        } else if c == '/' && at(i + 1) == '/' {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && at(i + 1) == '*' {
            let mut depth = 0;
            loop {
                if at(i) == '/' && at(i + 1) == '*' {
                    depth += 1;
                    i += 2;
                } else if at(i) == '*' && at(i + 1) == '/' {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    if at(i) == '\n' {
                        line += 1;
                    }
                    i += 1;
                }
            }
        } else if (c == 'r' || c == 'b')
            && (at(i + 1) == '"' || at(i + 1) == '#' || (c == 'b' && at(i + 1) == 'r'))
            && {
                // A raw or byte string: r"..", r#".."#, b"..", br#".."#.
                let mut j = i + 1;
                if c == 'b' && at(j) == 'r' {
                    j += 1;
                }
                while at(j) == '#' {
                    j += 1;
                }
                at(j) == '"'
            }
        {
            let raw = c == 'r' || at(i + 1) == 'r';
            while at(i) != '"' {
                i += 1;
            }
            let hashes = chars[..i].iter().rev().take_while(|&&h| h == '#').count();
            i += 1;
            loop {
                if at(i) == '\n' {
                    line += 1;
                }
                if !raw && at(i) == '\\' {
                    i += 2;
                    continue;
                }
                if at(i) == '"' && (0..hashes).all(|k| at(i + 1 + k) == '#') {
                    i += 1 + hashes;
                    break;
                }
                i += 1;
            }
        } else if c == '"' {
            i += 1;
            while at(i) != '"' {
                if at(i) == '\n' {
                    line += 1;
                }
                i += if at(i) == '\\' { 2 } else { 1 };
            }
            i += 1;
        } else if c == '\'' {
            // A character literal, or a lifetime.
            if at(i + 1) == '\\' {
                i += 2;
                while at(i) != '\'' {
                    i += 1;
                }
                i += 1;
            } else if at(i + 2) == '\'' {
                i += 3;
            } else {
                i += 1;
            }
        } else if c.is_alphabetic() || c == '_' {
            let start = i;
            while at(i).is_alphanumeric() || at(i) == '_' {
                i += 1;
            }
            let ident: String = chars[start..i].iter().collect();
            out.push((Token::Ident(ident), line));
        } else if c == ':' && at(i + 1) == ':' {
            out.push((Token::PathSep, line));
            i += 2;
        } else {
            out.push((Token::Punct(c), line));
            i += 1;
        }
    }
    out
}

/// The tokens without the items under `#[cfg(test)]`.
fn without_test_code(tokens: Vec<(Token, usize)>) -> Vec<(Token, usize)> {
    let cfg_test = [
        Token::Punct('#'),
        Token::Punct('['),
        Token::Ident("cfg".into()),
        Token::Punct('('),
        Token::Ident("test".into()),
        Token::Punct(')'),
        Token::Punct(']'),
    ];
    let mut out = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let is_cfg_test = tokens.len() - i >= cfg_test.len()
            && tokens[i..i + cfg_test.len()]
                .iter()
                .map(|(t, _)| t)
                .eq(cfg_test.iter());
        if !is_cfg_test {
            out.push(tokens[i].clone());
            i += 1;
            continue;
        }
        // Skip the item: up to its `;`, or through its outermost braces.
        i += cfg_test.len();
        let mut depth = 0;
        while i < tokens.len() {
            match tokens[i].0 {
                Token::Punct('{') => depth += 1,
                Token::Punct('}') => {
                    depth -= 1;
                    if depth == 0 {
                        i += 1;
                        break;
                    }
                }
                Token::Punct(';') if depth == 0 => {
                    i += 1;
                    break;
                }
                _ => {}
            }
            i += 1;
        }
    }
    out
}

/// A path the source names, where, and — for `use … as` — the name it is known by.
struct Named {
    segments: Vec<String>,
    line: usize,
    alias: Option<String>,
}

impl Named {
    /// The name a `use` makes the path known by in the declaring module.
    fn name(&self) -> Option<&str> {
        self.alias
            .as_deref()
            .or(self.segments.last().map(String::as_str))
    }
}

/// A token and the line it is on.
type Located = (Token, usize);

/// The tokens split into the `pub use` declarations — re-exports, a module's API rather than a
/// dependency of its own code — and everything else.
fn split_reexports(tokens: Vec<Located>) -> (Vec<Located>, Vec<Located>) {
    let (mut rest, mut reexports) = (Vec::new(), Vec::new());
    let mut i = 0;
    while i < tokens.len() {
        let mut j = i;
        if tokens[j].0 == Token::Ident("pub".into()) {
            j += 1;
            if tokens.get(j).is_some_and(|t| t.0 == Token::Punct('(')) {
                while tokens.get(j).is_some_and(|t| t.0 != Token::Punct(')')) {
                    j += 1;
                }
                j += 1;
            }
            if tokens
                .get(j)
                .is_some_and(|t| t.0 == Token::Ident("use".into()))
            {
                while j < tokens.len() && tokens[j].0 != Token::Punct(';') {
                    reexports.push(tokens[j].clone());
                    j += 1;
                }
                reexports.push((Token::Punct(';'), tokens.get(j).map_or(0, |t| t.1)));
                i = j + 1;
                continue;
            }
        }
        rest.push(tokens[i].clone());
        i += 1;
    }
    (rest, reexports)
}

/// Every path the tokens name, with `use` groups expanded: `use std::{fs, io::Read}` is
/// `std::fs` and `std::io::Read`.
fn paths(tokens: &[(Token, usize)]) -> Vec<Named> {
    fn path_at(
        tokens: &[(Token, usize)],
        mut i: usize,
        prefix: Vec<String>,
        out: &mut Vec<Named>,
    ) -> usize {
        let mut segments = prefix;
        let line = tokens[i].1;
        loop {
            match &tokens[i].0 {
                Token::Ident(name) => {
                    segments.push(name.clone());
                    i += 1;
                    // `use a::b as c`: the alias names nothing new, but a re-export is known by it.
                    if tokens
                        .get(i)
                        .is_some_and(|t| t.0 == Token::Ident("as".into()))
                    {
                        if segments.last().is_some_and(|s| s == "self") {
                            segments.pop();
                        }
                        let alias = match tokens.get(i + 1) {
                            Some((Token::Ident(alias), _)) => Some(alias.clone()),
                            _ => None,
                        };
                        out.push(Named {
                            segments,
                            line,
                            alias,
                        });
                        return i + 2;
                    }
                }
                Token::Punct('{') => {
                    i += 1;
                    while i < tokens.len() && tokens[i].0 != Token::Punct('}') {
                        if tokens[i].0 == Token::Punct(',') {
                            i += 1;
                        } else {
                            i = path_at(tokens, i, segments.clone(), out);
                        }
                    }
                    return i + 1;
                }
                _ => {
                    out.push(Named {
                        segments,
                        line,
                        alias: None,
                    });
                    return i;
                }
            }
            if i < tokens.len() && tokens[i].0 == Token::PathSep {
                i += 1;
            } else {
                if segments.last().is_some_and(|s| s == "self") {
                    segments.pop();
                }
                out.push(Named {
                    segments,
                    line,
                    alias: None,
                });
                return i;
            }
        }
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let starts_path = matches!(tokens[i].0, Token::Ident(_))
            && tokens.get(i + 1).is_some_and(|t| t.0 == Token::PathSep)
            && (i == 0 || !matches!(tokens[i - 1].0, Token::PathSep | Token::Punct('.')));
        if starts_path {
            i = path_at(tokens, i, Vec::new(), &mut out);
        } else {
            i += 1;
        }
    }
    out
}

/// Where a path leads: an item of one of the checked crates, by its module path there, or
/// anything else.
#[derive(Clone, Debug)]
enum Target {
    Internal(&'static str, Vec<String>),
    External(Vec<String>),
}

/// What the `pub use` declarations of every checked crate re-export: by crate, module and the name
/// the item is known by there, where it really is.
type Reexports = BTreeMap<(&'static str, String, String), Target>;

/// Where `path`, named in module `module` of `krate`, leads. `crate`, `self` and `super` are this
/// crate; a bare first segment that is a child module of `module` is too, as Rust 2018 resolves
/// it; a workspace crate is that crate.
fn resolve(krate: &'static str, module: &str, path: &[String]) -> Target {
    let segments = |m: &str| -> Vec<String> {
        m.split("::")
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect()
    };
    let Some(root) = path.first().map(String::as_str) else {
        return Target::External(Vec::new());
    };
    match root {
        "crate" => Target::Internal(krate, path[1..].to_vec()),
        "self" | "super" => {
            let mut base = segments(module);
            let mut rest = path;
            if rest.first().is_some_and(|s| s == "self") {
                rest = &rest[1..];
            }
            while rest.first().is_some_and(|s| s == "super") {
                base.pop();
                rest = &rest[1..];
            }
            base.extend(rest.iter().cloned());
            Target::Internal(krate, base)
        }
        _ => {
            if let Some(&(_, dir)) = WORKSPACE_CRATES.iter().find(|(name, _)| *name == root) {
                return Target::Internal(dir, path[1..].to_vec());
            }
            let child = if module.is_empty() {
                root.to_owned()
            } else {
                format!("{module}::{root}")
            };
            if roles_of(krate).iter().any(|(m, _)| *m == child) {
                let mut base = segments(module);
                base.extend(path.iter().cloned());
                return Target::Internal(krate, base);
            }
            Target::External(path.to_vec())
        }
    }
}

/// Why `path`, named in module `module` of `krate`, breaks the rule for a core module — if it does.
fn violation(
    krate: &'static str,
    module: &str,
    path: &[String],
    locked: &BTreeSet<String>,
    reexports: &Reexports,
) -> Option<String> {
    let shown = path.join("::");
    if path
        .windows(2)
        .any(|w| CLOCKS.contains(&w[0].as_str()) && w[1] == "now")
    {
        return Some(format!("{shown}: reads a clock"));
    }
    judge(&resolve(krate, module, path), locked, reexports, 0).map(|why| format!("{shown}: {why}"))
}

/// Why a path that leads to `target` breaks the rule — following a re-export to where the item
/// really is, so a core module re-exporting an adapter's item does not launder it.
fn judge(
    target: &Target,
    locked: &BTreeSet<String>,
    reexports: &Reexports,
    depth: usize,
) -> Option<String> {
    match target {
        Target::External(path) => {
            if CORE_PREFIXES
                .iter()
                .any(|p| path.len() >= p.len() && p.iter().zip(path).all(|(a, b)| a == b))
            {
                return None;
            }
            let root = path.first()?.as_str();
            match root {
                "std" | "core" | "alloc" => path
                    .get(1)
                    .filter(|m| STD_TECHNOLOGY.contains(&m.as_str()))
                    .map(|_| "a technology of the standard library".to_owned()),
                _ => (locked.contains(root) && !CORE_CRATES.contains(&root))
                    .then(|| format!("the technology crate {root}")),
            }
        }
        Target::Internal(krate, segments) => {
            if leaves_the_core(krate, segments) {
                return Some(format!("outside the core of {krate}"));
            }
            if depth > 8 {
                return None;
            }
            // The item the path names, in the deepest module it passes through.
            let module_len = (0..=segments.len())
                .rev()
                .find(|&n| {
                    let module = segments[..n].join("::");
                    roles_of(krate).iter().any(|(m, _)| *m == module)
                })
                .unwrap_or(0);
            let name = segments.get(module_len)?;
            let key = (*krate, segments[..module_len].join("::"), name.clone());
            let reexported = reexports.get(&key)?;
            let mut through = reexported.clone();
            let rest = &segments[module_len + 1..];
            match &mut through {
                Target::Internal(_, s) | Target::External(s) => s.extend(rest.iter().cloned()),
            }
            judge(&through, locked, reexports, depth + 1).map(|why| format!("{why}, re-exported"))
        }
    }
}

/// The `pub use` declarations of every checked crate, test code aside.
fn reexports() -> Reexports {
    let mut found = Reexports::new();
    for &(krate, _) in ROLES {
        let src = crates_dir().join(krate).join("src");
        let mut files = Vec::new();
        rust_files(&src, &mut files);
        for file in files {
            let module = module_path(&src, &file);
            let tokens = without_test_code(tokenize(&fs::read_to_string(&file).unwrap()));
            let (_, declared) = split_reexports(tokens);
            for named in paths(&declared) {
                if let Some(name) = named.name() {
                    let target = resolve(krate, &module, &named.segments);
                    found.insert((krate, module.clone(), name.to_owned()), target);
                }
            }
        }
    }
    found
}

/// Verifies: ADR-0006, G-8
#[test]
fn the_core_depends_on_no_adapter_and_no_technology() {
    let locked = locked_crates();
    let reexports = reexports();
    let (mut broken, mut unclassified) = (Vec::new(), Vec::new());
    for &(krate, roles) in ROLES {
        let src = crates_dir().join(krate).join("src");
        let mut files = Vec::new();
        rust_files(&src, &mut files);
        files.sort();
        for file in files {
            let module = module_path(&src, &file);
            let Some(&(_, role)) = roles.iter().find(|(m, _)| *m == module) else {
                unclassified.push(format!("{krate}: {module}"));
                continue;
            };
            if role != Core {
                continue;
            }
            let tokens = without_test_code(tokenize(&fs::read_to_string(&file).unwrap()));
            let (own, _) = split_reexports(tokens);
            let found: Vec<String> = paths(&own)
                .into_iter()
                .filter_map(|Named { segments, line, .. }| {
                    violation(krate, &module, &segments, &locked, &reexports).map(|why| {
                        format!(
                            "{}:{line}: {why}",
                            file.strip_prefix(crates_dir()).unwrap().display()
                        )
                    })
                })
                .collect();
            broken.extend(found);
        }
    }
    assert!(
        unclassified.is_empty(),
        "modules without a role in ROLES: {unclassified:#?}"
    );
    assert!(
        broken.is_empty(),
        "a core module depends on an adapter or a technology: {broken:#?}"
    );
}

/// The reader the test stands on: a path in a string, a comment, or test code is not a
/// dependency, and a `use` group names each of its members.
#[test]
fn the_reader_finds_the_paths_code_names() {
    let src = r##"
        use std::{fs, io::Read};
        use crate::client::{self, ws::Driver as D};
        // tokio::spawn in a comment
        /* reqwest::get /* nested */ in a block */
        const S: &str = "axum::Router";
        const R: &str = r#"rustls::"#;
        fn f<'a>(c: char) -> &'a str { let _ = '"'; tracing::info!("x"); x.y::<u8>(); "" }
        #[cfg(test)]
        mod tests { use tokio::net::TcpStream; }
        #[cfg(test)]
        fn g() { libc::getpid(); }
        fn h() { std::time::Instant::now(); }
    "##;
    let found: Vec<String> = paths(&without_test_code(tokenize(src)))
        .into_iter()
        .map(|named| named.segments.join("::"))
        .collect();
    assert_eq!(
        found,
        [
            "std::fs",
            "std::io::Read",
            "crate::client",
            "crate::client::ws::Driver",
            "tracing::info",
            "std::time::Instant::now",
        ]
    );
}

/// The rule's boundary between a value and a technology: a channel, a configuration value, and an
/// address are values; a socket, a file, a clock reading, and an adapter of the crate are not.
#[test]
fn the_rule_tells_a_value_from_a_technology() {
    let locked: BTreeSet<String> = ["tokio", "toml", "reqwest"].map(String::from).into();
    let judged = |path: &str| {
        let segments: Vec<String> = path.split("::").map(String::from).collect();
        violation(
            "fleet-agent",
            "supervisor::ports",
            &segments,
            &locked,
            &Reexports::new(),
        )
        .is_some()
    };
    for value in [
        "tokio::sync::mpsc",
        "toml::Table",
        "std::net::IpAddr",
        "std::env::consts::OS",
        "std::time::Duration",
        "crate::shutdown::Shutdown",
        "super::agent::PackageDownload",
        "opamp::client::protocol::AgentProtocol",
    ] {
        assert!(!judged(value), "{value} is a value the core may name");
    }
    for technology in [
        "tokio::net::TcpStream",
        "toml::from_str",
        "reqwest::Client",
        "std::net::TcpStream",
        "std::fs::read",
        "std::env::var",
        "std::time::SystemTime::now",
        "crate::service::runtime::run",
        "super::process::Runner",
        "opamp::client::ws::run",
    ] {
        assert!(
            judged(technology),
            "{technology} is a technology the core may not name"
        );
    }
}

/// A re-export does not launder an adapter: a path through a core module's `pub use` is judged by
/// where the item really is — and a bare child module is the module it names, as Rust 2018 has it.
#[test]
fn a_reexport_is_judged_by_where_the_item_is() {
    let locked = locked_crates();
    let reexports = reexports();
    let judged = |krate: &'static str, module: &str, path: &str| {
        let segments: Vec<String> = path.split("::").map(String::from).collect();
        violation(krate, module, &segments, &locked, &reexports)
    };
    // `opamp::client` is core and re-exports the backoff, whose jitter reads the system's randomness.
    assert!(judged(
        "fleet-agent",
        "supervisor::restart",
        "opamp::client::Backoff"
    )
    .is_some());
    assert!(judged("opamp", "client", "backoff::Backoff").is_some());
    // What `opamp::client` defines itself is core.
    assert!(judged(
        "fleet-agent",
        "supervisor::restart",
        "opamp::client::Session"
    )
    .is_none());
}
