//! `opamp-fleetctl package fetch` — turns an agent release into package artifacts this fleet can
//! install, and optionally uploads them (ADR-0026, ADR-0028).
//!
//! Getting a real agent into the fleet is a research task before it is a command: which repository
//! publishes the binaries, what the assets are called this month, which checksum file goes with
//! them, and whether the container is one a Client can open at all. This tool holds that knowledge
//! for the agent types the manual documents — `otelcol`, `otelcol-contrib`,
//! and `supervisor`, this fleet's own Client (ADR-0019) — and asks the
//! operator only what it cannot know: which one, which version, which platforms, and where to send
//! the result.
//!
//! Two rules shape what it produces:
//!
//! - **As published wherever possible.** An artifact that reaches the fleet unaltered is one whose
//!   SHA-256 an operator can compare against the release page, and ADR-0026's line from author to
//!   host stays unbroken. Every artifact is verified against the checksum *upstream* published
//!   before anything else happens to it.
//! - **Repacked only where it must be.** An agent whose upstream publishes no archive a Client can
//!   install is repacked deterministically (ADR-0026). That is the one place the bytes change, and
//!   the tool says so.
//!
//! Interactive by default; every prompt has a flag, so the same tool serves a pipeline:
//!   opamp-fleetctl package fetch                          # asks for everything
//!   opamp-fleetctl package fetch --agent otelcol-contrib --version 0.158.0 --platform linux/amd64 --no-upload

use crate::package::sha256_file;
use clap::ValueEnum;
use dialoguer::{Confirm, Input, MultiSelect, Select};
use std::path::{Path, PathBuf};

/// How many release series the operator is offered. Enough to reach the release before last when
/// one turns out badly, few enough to read without scrolling.
const SERIES_SHOWN: usize = 3;

/// The member cap a tree package is held to (ADR-0026). Checked while packing rather than
/// discovered on three hundred hosts at rollout time.
#[cfg_attr(
    any(not(test), not(unix)),
    expect(
        dead_code,
        reason = "only an agent whose upstream publishes no installable archive is repacked"
    )
)]
const MAX_TREE_MEMBERS: usize = 10_000;

/// What `package fetch` is asked for; every prompt has its flag.
#[derive(clap::Args)]
pub struct Args {
    /// Which agent to fetch. Omitted, it is asked for.
    #[arg(long, value_enum)]
    agent: Option<AgentKind>,
    /// Which version, as upstream numbers it (`0.158.0`, `1.19`). Omitted, the latest few are
    /// offered.
    #[arg(long)]
    version: Option<String>,
    /// A platform to fetch, as `os/arch` (`linux/amd64`). Repeatable. Omitted, the platforms this
    /// release publishes are offered.
    #[arg(long = "platform", value_name = "OS/ARCH")]
    platforms: Vec<String>,
    /// Where to write the artifacts.
    #[arg(long, default_value = ".")]
    out_dir: PathBuf,
    /// Upload to this Server when the artifacts are ready, e.g. `https://127.0.0.1:4321`. The
    /// Operator plane serves TLS 1.3 only (ADR-0013).
    #[arg(long, value_name = "URL")]
    server: Option<String>,
    /// The CA certificate (PEM) the Server's certificate chains to, such as the `server-ca.pem`
    /// `pki init` writes. It replaces the system's roots for the calls to the Server alone; the
    /// downloads from upstream keep them. Omitted, the Server is checked against the system's roots.
    #[arg(long, value_name = "FILE", conflicts_with = "no_upload")]
    cacert: Option<PathBuf>,
    /// Write the artifacts and stop — no upload, and no question about one.
    #[arg(long, conflicts_with = "server")]
    no_upload: bool,
}

/// The agents this tool knows how to fetch. Adding one is this enum, its [`Source`], and nothing
/// else — the rest of the tool works from what the source says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum AgentKind {
    /// The OpenTelemetry Collector, core distribution.
    #[value(name = "otelcol")]
    Otelcol,
    /// The OpenTelemetry Collector, Contrib distribution — the one carrying `opampextension`.
    #[value(name = "otelcol-contrib")]
    OtelcolContrib,
    /// This fleet's own Client — the package a Client updates *itself* from (ADR-0018, ADR-0019).
    #[value(name = "supervisor")]
    Supervisor,
}

/// Everything that differs between one upstream project and the next, in one place.
struct Source {
    /// The Agent type a Supervisor reports and a package Set is built for (ADR-0026) — also this
    /// tool's default package name.
    service_name: &'static str,
    /// The GitHub repository whose tags name the versions.
    repo: &'static str,
}

impl AgentKind {
    fn source(self) -> Source {
        match self {
            AgentKind::Otelcol => Source {
                service_name: "otelcol",
                repo: "open-telemetry/opentelemetry-collector-releases",
            },
            AgentKind::OtelcolContrib => Source {
                service_name: "otelcol-contrib",
                repo: "open-telemetry/opentelemetry-collector-releases",
            },
            // This repository's own releases. The Client is an Agent like any other (ADR-0018), so
            // the artifact that updates it is fetched the way every other agent's is — and since
            // ADR-0019 it is named and packed like one too, which is what makes that possible.
            AgentKind::Supervisor => Source {
                service_name: "supervisor",
                repo: "neteye-platform/classis",
            },
        }
    }

    /// The version a tag names, or `None` when the tag is not a release of *this* agent.
    ///
    /// Each project spells its tags its own way, and one of them carries tags that are not releases
    /// at all: the Collector repository tags its builder and supervisor alongside
    /// (`cmd/builder/v0.158.0`). A pattern
    /// per source is what keeps those out of the list an operator picks from.
    fn version_of_tag(self, tag: &str) -> Option<String> {
        let numeric = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
        let rest = tag.strip_prefix(self.tag_prefix())?;
        let parts = rest.split('.').count();
        // `v0.158.0`, `version/1.2.3` — three numeric parts behind the prefix, and nothing else.
        let shaped = parts == 3;
        (shaped && rest.split('.').all(numeric)).then(|| rest.to_string())
    }

    /// What each project puts in front of the version in its tags: `v`, the `version/` this
    /// project's release workflow creates them under (ADR-0012).
    fn tag_prefix(self) -> &'static str {
        match self {
            AgentKind::Otelcol | AgentKind::OtelcolContrib => "v",
            AgentKind::Supervisor => "version/",
        }
    }

    /// The tag a version came from — the reverse of [`version_of_tag`](Self::version_of_tag), for
    /// the `--version` flag, which takes the version an operator reads on the release page.
    fn tag_of_version(self, version: &str) -> String {
        format!("{}{version}", self.tag_prefix())
    }

    /// What one upstream version is called on each side: the tag it is fetched under, in
    /// upstream's own spelling, and the Package version it is uploaded as, written as SemVer
    /// (ADR-0043 clause 6) — `1.19` is fetched as `v1.19` and becomes Package `1.19.0`.
    ///
    /// # Errors
    /// Returns the message to print when upstream's number cannot be written as SemVer.
    fn release_names(self, upstream: &str) -> Result<(String, String), String> {
        Ok((self.tag_of_version(upstream), package_version(upstream)?))
    }

    /// The systems this agent can be fetched for, as the agent menu states them.
    ///
    /// A hint, not the plan: what is actually offered comes from the release itself a step later.
    /// It is here because the menu asks for an agent before any of that is known, and picking one
    /// only to be told that it publishes nothing for the systems an operator runs is a round trip
    /// the operator should not have to make.
    ///
    /// The Collectors publish per platform and add new ones between releases, so naming their
    /// architectures here would be a table going stale — the operating systems are the honest
    /// answer, and the platform question that follows shows the release's own list.
    fn platforms(self) -> String {
        match self {
            AgentKind::Otelcol | AgentKind::OtelcolContrib => {
                "linux, darwin, windows — as the release publishes".to_string()
            }
            // Named rather than left to the release, unlike the Collectors': this is *this*
            // project's own build matrix (`.github/workflows/release.yml`), so it moves only when
            // this repository decides it should — and the column's question, "does it run on the
            // hosts I have", deserves the concrete answer where one can be given.
            AgentKind::Supervisor => group_platforms(SUPERVISOR_PLATFORMS.iter().copied()),
        }
    }

    /// The line that introduces the per-platform hints printed when the fetch is done.
    ///
    /// Every other agent is installed by a Supervisor, which needs a block; this fleet's own Client
    /// is installed *by itself* over itself, and what admits that is a consent rather than a block
    /// (ADR-0018). One sentence, so the hints below it read as the answer to it.
    fn install_hint(self) -> &'static str {
        match self {
            AgentKind::Supervisor => "What a Client needs to take these:",
            _ => "What a Supervisor needs to install these:",
        }
    }

    /// The Configurations this agent needs before it can do anything, typed the way
    /// `scripts/seed_test_configs.sh` types them — which is where these bodies come from, and why
    /// they agree with the `[[supervisor]]` blocks in `config/supervisor.toml` down to the file names.
    fn default_configurations(self) -> &'static [DefaultConfiguration] {
        // Each is stated for the `service.name` its Collector reports, so a Deployment holding it
        // fits it to that Agent type alone (ADR-0034); the Deployment's Selector does the aiming.
        match self {
            AgentKind::Otelcol => &[DefaultConfiguration {
                name: "otelcol-conf",
                service_name: "otelcol",
                body: include_str!("../../../config/examples/otelcol-conf.yaml"),
            }],
            AgentKind::OtelcolContrib => &[DefaultConfiguration {
                name: "otelcol-contrib-conf",
                service_name: "otelcol-contrib",
                body: include_str!("../../../config/examples/otelcol-contrib-conf.yaml"),
            }],
            // None. A Client is configured by `supervisor.toml` on its host — the one file the fleet
            // deliberately does not own (ADR-0017 admits only `[[supervisor]]` blocks), and none
            // of it has a default this tool could put on a Server.
            AgentKind::Supervisor => &[],
        }
    }
}

/// An upstream version written as a Package version (ADR-0043 clause 6): a number with fewer than
/// three numeric components is completed with `.0` (`1.19` becomes `1.19.0`), and a leading zero
/// is dropped from a numeric component (`24.04.1` becomes `24.4.1`). Both keep upstream's order.
///
/// # Errors
/// Names the number when it cannot be written as SemVer this way.
fn package_version(upstream: &str) -> Result<String, String> {
    let split = upstream.find(['-', '+']).unwrap_or(upstream.len());
    let (core, rest) = upstream.split_at(split);
    let components: Vec<&str> = core.split('.').collect();
    let numeric = |c: &&str| !c.is_empty() && c.bytes().all(|b| b.is_ascii_digit());
    let written = (components.len() <= 3 && components.iter().all(numeric)).then(|| {
        let mut parts: Vec<&str> = components
            .iter()
            .map(|c| match c.trim_start_matches('0') {
                "" => "0",
                trimmed => trimmed,
            })
            .collect();
        parts.resize(3, "0");
        format!("{}{rest}", parts.join("."))
    });
    written
        .filter(|version| fleet_core::version::is_semver(version))
        .ok_or_else(|| {
            format!(
                "upstream's version {upstream:?} cannot be written as SemVer, which a Package \
                 version is — fetch it by hand and upload it under a SemVer version you choose \
                 in the same order"
            )
        })
}

/// A Configuration this tool puts on the Server beside the package, when the Server has none of
/// that name yet.
///
/// The body is compiled in rather than read from the repository: this tool is released as a
/// binary an operator runs anywhere (ADR-0010), so a file path beside it would be a default that
/// only works in a checkout.
struct DefaultConfiguration {
    /// The Configuration's name — also the file name its entry gets in the Supervisor's config
    /// directory, which is what the `[[supervisor]]` block has to name.
    name: &'static str,
    /// The Agent type this is for (ADR-0034 clause 3); empty is every type.
    service_name: &'static str,
    body: &'static str,
}

/// One file to fetch, and where the SHA-256 it must match comes from.
struct Download {
    url: String,
    checksum: ChecksumSource,
}

/// One platform's artifact, planned before anything is downloaded.
struct Plan {
    /// The platform as *this fleet* names it (ADR-0026), which is what the upload path carries.
    os: String,
    arch: String,
    /// What has to be fetched. Every one of them is verified before any of them is used.
    sources: Vec<Download>,
    /// What has to happen to the downloaded bytes before they are a package artifact.
    action: Action,
    /// The artifact's file name in `--out-dir`.
    out_name: String,
    /// What a `[[supervisor]]` block has to say to install it — or, for this fleet's own Client,
    /// what `[packages] self_update` has to say, since nothing supervises that one. Printed at the end,
    /// because it is the next thing an operator needs.
    ///
    /// For a **wrapped** agent it is the `type` alone (ADR-0017): the Client's kind knows the
    /// program's name, where it sits in the tree, and how it is invoked, so this tool dictates no
    /// line for a host to transcribe. Those facts live in that agent's artifact document under
    /// `docs/artifacts/`, which the kind's own tests pin — the two ends of one artifact, kept in
    /// step by a red test rather than by a hint printed on a terminal.
    block_hint: String,
}

/// Where an artifact's published SHA-256 is found. Every source publishes one; no two publish it
/// the same way, and the Collector changed its mind at 0.158.0.
enum ChecksumSource {
    /// Files holding `<hash>  <name>` lines, `sha256sum` style — the artifact's line is looked up
    /// by name. The Collector's pre-0.158 files.
    ///
    /// Several, because a release may split them: 0.157.0 keeps its Windows assets in a file of
    /// their own. Which file holds a given artifact is answered by looking, not by a rule about
    /// platforms that would need revisiting the next time upstream reorganises.
    Sums { urls: Vec<String> },
    /// A file holding one bare hex digest and nothing else — the Collector's per-asset sidecar
    /// from 0.158.0 on.
    BareDigest { url: String },
}

/// What happens between the download and the artifact.
enum Action {
    /// Nothing. The artifact is uploaded exactly as upstream published it, so the hash the fleet
    /// verifies is the hash on the release page (ADR-0026).
    AsPublished,
}

/// `package fetch`: which agent, which version, which platforms, and whether to upload — each
/// asked for when its flag is missing.
///
/// # Errors
/// Returns the message to print when a download, a check or an upload fails.
pub async fn run(args: Args) -> Result<(), String> {
    // Built before anything is downloaded: a CA path with a typo is cheaper to hear about now than
    // after hundreds of megabytes.
    let server_client = server_http(args.cacert.as_deref())?;
    let agent = match args.agent {
        Some(agent) => agent,
        None => choose_agent()?,
    };
    let source = agent.source();

    let version = match args.version.clone() {
        Some(version) => version,
        None => choose_version(agent, &source).await?,
    };
    // The release is fetched under upstream's spelling, and named as a Package in SemVer — before
    // anything is downloaded, so a number that cannot be written so costs nothing.
    let (tag, package_version) = agent.release_names(&version)?;

    let assets = release_assets(&source, &tag).await?;
    let available = plans(agent, &version, &assets).await?;
    if available.is_empty() {
        // For this project's own releases the likeliest reason is a known one, and saying it saves
        // the operator a trip to the release page: older releases carry another name and container,
        // and a Set built from those fits no Client reporting the type `supervisor` anyway
        // (ADR-0019).
        let why = match agent {
            AgentKind::Supervisor => {
                " — a release from before the rename publishes \
                 `opamp-fleet-client_<version>_<os>_<arch>.7z`, which is a package no Client of \
                 this type installs"
            }
            _ => "",
        };
        return Err(format!(
            "{} {version} publishes nothing this tool can install{why}",
            source.service_name
        ));
    }
    let chosen = select_platforms(&available, &args.platforms)?;

    std::fs::create_dir_all(&args.out_dir)
        .map_err(|e| format!("cannot create {}: {e}", args.out_dir.display()))?;
    let mut produced: Vec<(&Plan, PathBuf)> = Vec::new();
    for plan in &chosen {
        let artifact = produce(plan, &args.out_dir).await?;
        produced.push((plan, artifact));
    }

    let server = upload_target(&args)?;
    if let Some(server) = &server {
        for (plan, artifact) in &produced {
            upload(
                &server_client,
                server,
                source.service_name,
                &package_version,
                plan,
                artifact,
            )
            .await?;
        }
        upload_default_configurations(&server_client, server, agent).await?;
    }

    eprintln!("\nDone. {}", agent.install_hint());
    for (plan, artifact) in &produced {
        eprintln!(
            "  {}/{}  {}\n      {}",
            plan.os,
            plan.arch,
            artifact.display(),
            plan.block_hint
        );
    }
    if server.is_none() {
        eprintln!(
            "\nNothing was uploaded. To do it later, create the package, PUT each artifact, sign \
             each entry, and put it in the deployment that should carry it:\n  \
             curl -X PUT -H 'Content-Type: application/json' -d '{{}}' \\\n       \
             <server>/api/v1/packages/{name}/{version}\n  \
             curl -X PUT --data-binary @<artifact> \\\n       \
             \"<server>/api/v1/packages/{name}/{version}/entries/<os>/<arch>\"\n  \
             curl -X PUT -H 'Content-Type: application/json' -d '{{\"signature\": \"<hex>\"}}' \\\n       \
             \"<server>/api/v1/packages/{name}/{version}/entries/<os>/<arch>/signature\"\n  \
             curl -X PUT <server>/api/v1/deployments/<ring>/packages/{name}/{version}\n  \
             curl -X POST <server>/api/v1/deployments/<ring>/rollout",
            name = source.service_name,
            version = package_version
        );
        // Silent for an agent that has none — the Client's own configuration is its host's
        // (ADR-0017), so there is nothing here to offer and nothing to apologise for.
        if !agent.default_configurations().is_empty() {
            eprintln!(
                "  The default configuration ({}) is not uploaded either; an upload puts it there \
                 when the Server has none of that name. Or seed it from config/examples/ with \
                 scripts/seed_test_configs.sh.",
                agent
                    .default_configurations()
                    .iter()
                    .map(|c| c.name)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    Ok(())
}

// ── The questions ───────────────────────────────────────────────────────────

/// Platform pairs as one menu line: `linux/amd64+arm64 windows/amd64`.
///
/// Grouped by operating system, and tightly, because the menu is one line per agent and a line
/// that wraps at eighty columns is one `dialoguer` redraws wrongly when the selection moves.
fn group_platforms<'p>(pairs: impl Iterator<Item = (&'p str, &'p str)>) -> String {
    let mut groups: Vec<(&str, Vec<&str>)> = Vec::new();
    for (os, arch) in pairs {
        match groups.iter_mut().find(|(name, _)| *name == os) {
            Some((_, arches)) => arches.push(arch),
            None => groups.push((os, vec![arch])),
        }
    }
    groups
        .iter()
        .map(|(os, arches)| format!("{os}/{}", arches.join("+")))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The agent menu's lines, name and systems in two columns.
///
/// Its own function so the width rule below is testable against the very lines the menu shows,
/// rather than against a copy of them that drifts.
fn agent_menu_labels() -> Vec<String> {
    // Asked of clap rather than written out again. A second list of the same agents is exactly how
    // `icinga2` came to be missing from this prompt while `--agent icinga2` worked: adding a
    // variant is one place, and the menu now follows it whether or not anyone remembers this
    // function.
    let agents = AgentKind::value_variants();
    // The systems beside each name, in a column: the choice that follows this one is a platform,
    // and an agent that publishes nothing for the systems an operator runs is better seen here
    // than after two more questions.
    let width = agents
        .iter()
        .map(|a| a.source().service_name.len())
        .max()
        .unwrap_or(0);
    agents
        .iter()
        .map(|a| {
            format!(
                "{name:<width$}  {platforms}",
                name = a.source().service_name,
                platforms = a.platforms()
            )
        })
        .collect()
}

fn choose_agent() -> Result<AgentKind, String> {
    let agents = AgentKind::value_variants();
    let labels = agent_menu_labels();
    let picked = Select::new()
        .with_prompt("Which agent")
        .items(&labels)
        .default(0)
        .interact()
        .map_err(|e| format!("cannot read the choice: {e}"))?;
    Ok(agents[picked])
}

async fn choose_version(agent: AgentKind, source: &Source) -> Result<String, String> {
    eprintln!("Reading the last releases of {} …", source.repo);
    let versions = recent_versions(agent, source).await?;
    if versions.is_empty() {
        return Err(format!("{} publishes no release tags", source.repo));
    }
    let picked = Select::new()
        .with_prompt("Which version")
        .items(&versions)
        .default(0)
        .interact()
        .map_err(|e| format!("cannot read the choice: {e}"))?;
    Ok(versions[picked].clone())
}

/// Picks the platforms to fetch: from `--platform` when given, by multi-select otherwise.
fn select_platforms<'p>(available: &'p [Plan], wanted: &[String]) -> Result<Vec<&'p Plan>, String> {
    if !wanted.is_empty() {
        return wanted
            .iter()
            .map(|w| {
                let (os, arch) = w
                    .split_once('/')
                    .ok_or_else(|| format!("{w:?} is not an os/arch pair"))?;
                available
                    .iter()
                    .find(|p| p.os == os && p.arch == arch)
                    .ok_or_else(|| {
                        format!(
                            "this release publishes nothing for {w} (it has: {})",
                            available
                                .iter()
                                .map(|p| format!("{}/{}", p.os, p.arch))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    })
            })
            .collect();
    }
    let labels: Vec<String> = available
        .iter()
        .map(|p| match p.action {
            Action::AsPublished => format!("{}/{}", p.os, p.arch),
        })
        .collect();
    let picked = MultiSelect::new()
        .with_prompt("Which platforms (space to select, enter to confirm)")
        .items(&labels)
        .interact()
        .map_err(|e| format!("cannot read the choice: {e}"))?;
    if picked.is_empty() {
        return Err("no platform selected".to_string());
    }
    Ok(picked.into_iter().map(|i| &available[i]).collect())
}

/// Where to upload, if anywhere. `--no-upload` answers it, `--server` answers it, and otherwise it
/// is a question — with the artifacts already written, so a "no" here has still produced them.
fn upload_target(args: &Args) -> Result<Option<String>, String> {
    if args.no_upload {
        return Ok(None);
    }
    if let Some(server) = &args.server {
        return Ok(Some(server.trim_end_matches('/').to_string()));
    }
    let wants = Confirm::new()
        .with_prompt("Upload these to a fleet Server")
        .default(false)
        .interact()
        .map_err(|e| format!("cannot read the answer: {e}"))?;
    if !wants {
        return Ok(None);
    }
    let url: String = Input::new()
        .with_prompt("Server base URL")
        .default("https://127.0.0.1:4321".to_string())
        .interact_text()
        .map_err(|e| format!("cannot read the answer: {e}"))?;
    Ok(Some(url.trim_end_matches('/').to_string()))
}

// ── Upstream ────────────────────────────────────────────────────────────────

/// The newest version of each of the last [`SERIES_SHOWN`] release series, newest first.
///
/// A *series* is a `major.minor` line, and only its newest patch is offered: nobody installing
/// 2.16 wants 2.16.3 when 2.16.5 exists, and an agent that patches often — Icinga 2 published five
/// 2.16 patches — would otherwise fill the whole list with one line and hide every version an
/// operator might actually be looking for. Where an agent's versions carry no patch number at all,
/// every version is its own series and this is simply the last three.
///
/// Tags rather than releases: a Collector release object carries hundreds of assets, so listing
/// twenty of them to read their names would move megabytes to answer a question tags answer in
/// kilobytes. The order is this tool's own — sorted by the numbers, not by whatever order the API
/// returned — so the newest is the newest whatever the repository's tagging history looks like.
async fn recent_versions(agent: AgentKind, source: &Source) -> Result<Vec<String>, String> {
    let body = get_json(&format!(
        "https://api.github.com/repos/{}/tags?per_page=100",
        source.repo
    ))
    .await?;
    let mut versions: Vec<String> = body
        .as_array()
        .ok_or("the tag listing is not a list")?
        .iter()
        .filter_map(|tag| tag.get("name")?.as_str())
        .filter_map(|name| agent.version_of_tag(name))
        .collect();
    versions.sort_by_key(|v| std::cmp::Reverse(version_key(v)));
    versions.dedup();
    Ok(newest_per_series(&versions))
}

/// The newest version of each of the last [`SERIES_SHOWN`] `major.minor` series, given a list
/// already sorted newest first — so the first version of a series encountered *is* its newest.
fn newest_per_series(versions: &[String]) -> Vec<String> {
    let mut newest = Vec::new();
    let mut series_seen: Vec<Vec<u64>> = Vec::new();
    for version in versions {
        // A version with no minor part is its own series, which is what makes an agent that
        // versions in two parts behave as "the last three versions" without a special case.
        let series: Vec<u64> = version_key(version).into_iter().take(2).collect();
        if series_seen.contains(&series) {
            continue;
        }
        series_seen.push(series);
        newest.push(version.clone());
        if newest.len() == SERIES_SHOWN {
            break;
        }
    }
    newest
}

/// A version's parts as numbers, so `0.9.0` sorts below `0.10.0` — which it does not as text.
fn version_key(version: &str) -> Vec<u64> {
    version
        .split('.')
        .map(|p| p.parse::<u64>().unwrap_or(0))
        .collect()
}

/// The assets of one release: `(name, download URL)`.
async fn release_assets(source: &Source, tag: &str) -> Result<Vec<(String, String)>, String> {
    let body = get_json(&format!(
        "https://api.github.com/repos/{}/releases/tags/{tag}",
        source.repo
    ))
    .await?;
    let assets = body
        .get("assets")
        .and_then(|a| a.as_array())
        .ok_or_else(|| format!("{} has no release {tag}", source.repo))?;
    Ok(assets
        .iter()
        .filter_map(|asset| {
            Some((
                asset.get("name")?.as_str()?.to_string(),
                asset.get("browser_download_url")?.as_str()?.to_string(),
            ))
        })
        .collect())
}

/// What this release offers, one entry per platform this fleet can name.
async fn plans(
    agent: AgentKind,
    version: &str,
    assets: &[(String, String)],
) -> Result<Vec<Plan>, String> {
    match agent {
        AgentKind::Otelcol | AgentKind::OtelcolContrib => {
            Ok(collector_plans(agent, version, assets))
        }
        AgentKind::Supervisor => Ok(supervisor_plans(version, assets)),
    }
}

/// The Collector publishes `<dist>_<version>_<os>_<arch>.tar.gz` for every platform it supports,
/// so the platform list *is* the asset list — no table here goes stale when upstream adds one.
fn collector_plans(agent: AgentKind, version: &str, assets: &[(String, String)]) -> Vec<Plan> {
    let dist = agent.source().service_name;
    let prefix = format!("{dist}_{version}_");
    let mut plans = Vec::new();
    for (name, url) in assets {
        // `otelcol-contrib_…` also starts with `otelcol_`-like text under a naive check, so the
        // remainder is split off the full prefix and must be exactly `<os>_<arch>.tar.gz`.
        let Some((os, arch)) = platform_of(name, &prefix) else {
            continue;
        };
        let program = if os == "windows" {
            format!("{dist}.exe")
        } else {
            dist.to_string()
        };
        plans.push(Plan {
            os: os.clone(),
            arch,
            sources: vec![Download {
                url: url.clone(),
                checksum: collector_checksum(name, dist, assets),
            }],
            action: Action::AsPublished,
            out_name: name.clone(),
            block_hint: format!("binary = {program:?}  (type = \"collector\")"),
        });
    }
    plans.sort_by(|a, b| (&a.os, &a.arch).cmp(&(&b.os, &b.arch)));
    plans
}

/// The platform an asset named `<prefix><os>_<arch>.tar.gz` is for, in the words an Agent reports
/// — or `None` when the name has another shape or a platform this fleet does not know.
fn platform_of(name: &str, prefix: &str) -> Option<(String, String)> {
    let (os, arch) = name
        .strip_prefix(prefix)?
        .strip_suffix(".tar.gz")?
        .split_once('_')?;
    Some((normalize_os(os)?, normalize_arch(arch)?))
}

/// The platforms this project's own release publishes, in the order its build matrix states them
/// (`.github/workflows/release.yml`). The agent menu names them
/// ([`AgentKind::platforms`]); what is actually fetched comes from the release's assets, so this
/// list understating a new target costs a menu line and never a download.
const SUPERVISOR_PLATFORMS: [(&str, &str); 5] = [
    ("linux", "amd64"),
    ("linux", "arm64"),
    ("darwin", "arm64"),
    ("darwin", "amd64"),
    ("windows", "amd64"),
];

/// This fleet's own Client, as its release publishes it: one `.tar.gz` per platform named
/// `supervisor_<version>_<os>_<arch>` (ADR-0019), holding the binary under the name it is installed
/// as. Nothing is repacked — the artifact *is* the package, which is the point of packing the
/// release with this project's own packer.
///
/// The `.deb`, `.rpm` and `.msi` of the same release are installers for a machine to run, not
/// artifacts a fleet distributes, so they are passed over exactly as the Collector's MSI is.
fn supervisor_plans(version: &str, assets: &[(String, String)]) -> Vec<Plan> {
    let package = AgentKind::Supervisor.source().service_name;
    let prefix = format!("{package}_{version}_");
    // One file for the whole release, written by the publish job from every artifact's own
    // checksum — `<hash>  <name>` lines, which is the shape `ChecksumSource::Sums` looks up by.
    let sums: Vec<String> = assets
        .iter()
        .filter(|(name, _)| name == "SHA256SUMS")
        .map(|(_, url)| url.clone())
        .collect();
    let mut plans = Vec::new();
    for (name, url) in assets {
        let Some((os, arch)) = platform_of(name, &prefix) else {
            continue;
        };
        plans.push(Plan {
            os,
            arch,
            sources: vec![Download {
                url: url.clone(),
                checksum: ChecksumSource::Sums { urls: sums.clone() },
            }],
            action: Action::AsPublished,
            out_name: name.clone(),
            // Not a `[[supervisor]]` block: a Client installs this one over itself, and what
            // admits that is the consent in its own `supervisor.toml` (ADR-0018), which takes
            // only the package named after its Agent type and stands by default, so most hosts
            // need no line at all.
            block_hint: "[packages] self_update = true  (the default)".to_string(),
        });
    }
    plans.sort_by(|a, b| (&a.os, &a.arch).cmp(&(&b.os, &b.arch)));
    plans
}

/// The Collector's checksum, whichever way this release publishes it.
///
/// Up to 0.157.0 it was one file per distribution holding every asset's line; from 0.158.0 each
/// asset has a sidecar holding a bare digest. Both are release assets, so which one exists is
/// visible in the list rather than something to infer from the version number — a rule by version
/// would be wrong for exactly one release and no one would find out until it broke.
fn collector_checksum(asset: &str, dist: &str, assets: &[(String, String)]) -> ChecksumSource {
    let sidecar = format!("{asset}.sha256");
    if let Some((_, url)) = assets.iter().find(|(name, _)| *name == sidecar) {
        return ChecksumSource::BareDigest { url: url.clone() };
    }
    // Every combined file this distribution has, most specific first: 0.157.0 and earlier put the
    // Windows assets in `…_<dist>_windows_checksums.txt` and the rest in `…_<dist>_checksums.txt`.
    let prefix = format!("opentelemetry-collector-releases_{dist}_");
    let mut urls: Vec<String> = assets
        .iter()
        .filter(|(name, _)| name.starts_with(&prefix) && name.ends_with("checksums.txt"))
        .map(|(_, url)| url.clone())
        .collect();
    urls.sort_by_key(|url| std::cmp::Reverse(url.len()));
    ChecksumSource::Sums { urls }
}

/// Upstream's platform words in this fleet's vocabulary (ADR-0026), or `None` for one this fleet
/// has no name for — an Agent reports `os.type` and `host.arch`, and a package entry no Agent can
/// match is one nobody would ever be offered.
fn normalize_os(os: &str) -> Option<String> {
    match os {
        "linux" | "windows" | "darwin" => Some(os.to_string()),
        "macos" => Some("darwin".to_string()),
        _ => None,
    }
}

fn normalize_arch(arch: &str) -> Option<String> {
    match arch {
        "amd64" | "arm64" | "386" => Some(arch.to_string()),
        "x86_64" => Some("amd64".to_string()),
        "aarch64" => Some("arm64".to_string()),
        "i386" => Some("386".to_string()),
        _ => None,
    }
}

// ── Producing an artifact ───────────────────────────────────────────────────

/// Downloads one platform's artifact, verifies it against what upstream published, and applies
/// whatever [`Action`] the plan carries. Returns the file that is now ready to upload.
async fn produce(plan: &Plan, out_dir: &Path) -> Result<PathBuf, String> {
    eprintln!("\n{}/{}", plan.os, plan.arch);
    let mut fetched = Vec::new();
    for source in &plan.sources {
        let downloaded = out_dir.join(
            Path::new(&source.url)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| plan.out_name.clone()),
        );
        eprintln!("  downloading {} …", source.url);
        download(&source.url, &downloaded).await?;

        let published = published_sha256(&source.checksum, &downloaded).await?;
        let actual = hex::encode(sha256_file(&downloaded)?);
        if actual != published {
            // The file stays for inspection: a mismatch is either a truncated download or
            // something that deserves a look, and deleting the evidence serves neither.
            return Err(format!(
                "{} does not match the SHA-256 upstream published\n  upstream: {published}\n  \
                 downloaded: {actual}",
                downloaded.display()
            ));
        }
        eprintln!("  verified against upstream's SHA-256");
        fetched.push(downloaded);
    }
    // Every plan has exactly one; the ones that act on "the download" mean this.
    let downloaded = fetched
        .first()
        .cloned()
        .ok_or_else(|| "a plan with nothing to fetch".to_string())?;

    match &plan.action {
        Action::AsPublished => {
            eprintln!("  as published — the fleet verifies upstream's own hash");
            Ok(downloaded)
        }
    }
}

/// The SHA-256 upstream published for this artifact, from whichever form the source uses.
async fn published_sha256(source: &ChecksumSource, artifact: &Path) -> Result<String, String> {
    let urls = match source {
        ChecksumSource::BareDigest { url } => {
            let text = String::from_utf8(get_bytes(url).await?)
                .map_err(|_| format!("{url} is not a checksum file"))?;
            return Ok(text
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_string());
        }
        ChecksumSource::Sums { urls } => urls,
    };
    if urls.is_empty() {
        return Err("upstream published no checksum for this artifact".to_string());
    }
    for url in urls {
        let text = String::from_utf8(get_bytes(url).await?)
            .map_err(|_| format!("{url} is not a checksum file"))?;
        if let Some(hash) = parse_sums(&text, artifact) {
            return Ok(hash);
        }
    }
    Err(format!(
        "none of the checksum files upstream published has a line for {} ({})",
        artifact.file_name().unwrap_or_default().to_string_lossy(),
        urls.join(", ")
    ))
}

/// The artifact's digest out of a `sha256sum`-style file: `<hash>  <name>` lines, where the name
/// may carry a `*` for binary mode or a path in front of it. Matched on the file name alone, which
/// is the one thing every one of these files spells the same way.
fn parse_sums(text: &str, artifact: &Path) -> Option<String> {
    let wanted = artifact.file_name()?.to_string_lossy().into_owned();
    text.lines()
        .filter_map(|line| line.split_once(char::is_whitespace))
        .find(|(_, name)| {
            Path::new(name.trim().trim_start_matches('*'))
                .file_name()
                .is_some_and(|n| n.to_string_lossy() == wanted)
        })
        .map(|(hash, _)| hash.trim().to_string())
}

/// Packs a directory as a `.tar.gz` a Client can install as a tree — deterministically, and with
/// every link resolved.
///
/// Determinism is not tidiness: the fleet decides whether to distribute by content hash, so an
/// artifact that differed by when it was packed would be a rollout nobody asked for. Times, owners
/// and order are therefore fixed, exactly as `package pack` fixes them for one file.
///
/// Links are resolved rather than carried because a tree package refuses them (ADR-0026): what a
/// link names is not where it sits, which is the one thing a path check cannot judge. A link
/// pointing at nothing is dropped.
#[cfg_attr(
    any(not(test), not(unix)),
    expect(
        dead_code,
        reason = "only an agent whose upstream publishes no installable archive is repacked"
    )
)]
fn pack_tree(root: &Path, wrapper: &str, out: &Path) -> Result<(), String> {
    let mut members = Vec::new();
    collect_members(root, Path::new(""), &mut members, &mut Vec::new())?;
    members.sort();
    if members.len() > MAX_TREE_MEMBERS {
        return Err(format!(
            "the tree holds {} members — past the {MAX_TREE_MEMBERS} a package may carry",
            members.len()
        ));
    }

    let file =
        std::fs::File::create(out).map_err(|e| format!("cannot write {}: {e}", out.display()))?;
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        file,
        flate2::Compression::default(),
    ));
    for relative in &members {
        let full = root.join(relative);
        // Following the link is the point: `metadata` resolves, and an error means it resolves to
        // nothing, which is a member to drop rather than a failure to pack.
        let Ok(meta) = std::fs::metadata(&full) else {
            continue;
        };
        let inside = Path::new(wrapper).join(relative);
        let mut header = tar::Header::new_gnu();
        header.set_mtime(0);
        header.set_uid(0);
        header.set_gid(0);
        if meta.is_dir() {
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, &inside, std::io::empty())
                .map_err(|e| format!("cannot pack {}: {e}", inside.display()))?;
            continue;
        }
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(meta.len());
        header.set_mode(mode_of(&meta));
        header.set_cksum();
        let source = std::fs::File::open(&full)
            .map_err(|e| format!("cannot read {}: {e}", full.display()))?;
        builder
            .append_data(&mut header, &inside, source)
            .map_err(|e| format!("cannot pack {}: {e}", inside.display()))?;
    }
    builder
        .into_inner()
        .map_err(|e| format!("cannot finish {}: {e}", out.display()))?
        .finish()
        .map_err(|e| format!("cannot finish {}: {e}", out.display()))?;
    Ok(())
}

/// Every path under `root`, relative to it — directories included, because a tree keeps its shape.
///
/// Links are followed, and that is the whole difficulty. A link to a *directory* has to be
/// descended into and packed **at the name the link carries**, because that name is one the agent
/// uses: the GLPI AppImage reaches its Perl library through `usr/share/perl/5.26`, a link to
/// `5.26.1`, and a tree where that path is an empty directory is one whose agent cannot find a
/// single module. So the contents are packed under both names, exactly as `tar -h` writes them.
///
/// Following links makes a cycle possible, and the guard has to be the *ancestors* of the walk
/// rather than everywhere it has already been: a link pointing back up is a cycle and is dropped,
/// while a second path to the same directory is legitimate duplication and must be packed again.
/// Deduplicating by real path instead would leave one of the two names empty — and which one, on
/// directory-read order, which is nobody's guarantee.
#[cfg_attr(
    any(not(test), not(unix)),
    expect(
        dead_code,
        reason = "only an agent whose upstream publishes no installable archive is repacked"
    )
)]
fn collect_members(
    root: &Path,
    prefix: &Path,
    into: &mut Vec<PathBuf>,
    ancestors: &mut Vec<PathBuf>,
) -> Result<(), String> {
    let dir = root.join(prefix);
    for entry in
        std::fs::read_dir(&dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?
    {
        let entry = entry.map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        let relative = prefix.join(entry.file_name());
        let full = root.join(&relative);
        // Resolving rather than reading the entry itself: what matters is what the member *is*
        // once the link is followed, because that is what gets packed. An error means it resolves
        // to nothing — a dangling link, which is where the AppImage's Debian leftovers go.
        let Ok(meta) = std::fs::metadata(&full) else {
            continue;
        };
        into.push(relative.clone());
        if !meta.is_dir() {
            continue;
        }
        let real = full.canonicalize().unwrap_or_else(|_| full.clone());
        if ancestors.contains(&real) {
            continue;
        }
        ancestors.push(real);
        collect_members(root, &relative, into, ancestors)?;
        ancestors.pop();
    }
    Ok(())
}

/// The mode to store, which off Unix is a decision rather than a reading: a tar written on Windows
/// has no mode to carry, and a tree whose programs arrive unexecutable is a tree that will not run.
#[cfg_attr(
    any(not(test), not(unix)),
    expect(
        dead_code,
        reason = "only an agent whose upstream publishes no installable archive is repacked"
    )
)]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o777
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        0o755
    }
}

// ── The Server ──────────────────────────────────────────────────────────────

/// Creates the Set if it is not there and stores this platform's artifact as its entry
/// (ADR-0026). Nothing is distributed by either call: a Set reaches an Agent only through a
/// rollout act (ADR-0025), which stays the operator's.
async fn upload(
    client: &reqwest::Client,
    server: &str,
    service_name: &str,
    version: &str,
    plan: &Plan,
    artifact: &Path,
) -> Result<(), String> {
    let set = format!("{server}/api/v1/packages/{service_name}/{version}");
    eprintln!("  creating the Set at {set} …");
    put_json(client, &set, "{}".to_string()).await?;

    let entry = format!("{set}/entries/{}/{}", plan.os, plan.arch);
    eprintln!("  uploading {} …", artifact.display());
    let bytes =
        std::fs::read(artifact).map_err(|e| format!("cannot read {}: {e}", artifact.display()))?;
    let response = match client.put(&entry).body(bytes).send().await {
        Ok(response) => response,
        Err(e) => return Err(refusal_behind(client, &entry, &e).await),
    };
    expect_ok(response, &entry).await?;
    eprintln!(
        "  stored as the {}/{} entry — and it reaches nobody yet: it is unsigned, and a package \
         aims at nothing by itself. Sign the entry on the Packages tab (or PUT its …/signature), \
         then put it in a deployment when it should reach hosts:\n    \
         curl -X PUT <server>/api/v1/deployments/<ring>/packages/{}/{}",
        plan.os, plan.arch, service_name, version
    );
    Ok(())
}

/// Puts this agent's default Configurations beside the package — **only the ones the Server does
/// not already have**.
///
/// A package alone leaves an Agent with nothing to run: the Supervisor holds at "awaiting
/// configuration" until a Configuration of the name its block reads arrives. Uploading the default
/// with the package closes that gap in the same act.
///
/// Two rules keep it from being a surprise. **An existing Configuration is never touched** — the
/// name is asked for first, and one that answers is left exactly as the operator left it, edits and
/// all. And **nothing is distributed**: saving only saves (ADR-0025), and a Configuration reaches an
/// Agent only through a Deployment that holds it (ADR-0034), so the default reaches no Agent until
/// an operator reads it, puts it into a Deployment and presses that Deployment's rollout. That
/// matters here, because these bodies are starting points with example values in them — a parent
/// host to correct, a plugin path to confirm.
async fn upload_default_configurations(
    client: &reqwest::Client,
    server: &str,
    agent: AgentKind,
) -> Result<(), String> {
    for config in agent.default_configurations() {
        let url = format!("{server}/api/v1/configurations/{}", config.name);
        if configuration_exists(client, &url).await? {
            eprintln!("  {} is already on the Server — left as it is", config.name);
            continue;
        }
        let spec = serde_json::json!({
            "body": config.body,
            "service_name": config.service_name,
        });
        eprintln!("  storing the default configuration {} …", config.name);
        put_json(client, &url, spec.to_string()).await?;
        eprintln!(
            "  saved — read it over, put it into the deployment that should carry it and press \
             that deployment's rollout when it should reach hosts, since it carries example values"
        );
    }
    Ok(())
}

/// Whether the Server already holds a Configuration of this name. `404` is the answer that means
/// "no"; anything else that is not a success is an answer this tool must not read past — a Server
/// that refuses the question would otherwise have a default written over the top of what it holds.
async fn configuration_exists(client: &reqwest::Client, url: &str) -> Result<bool, String> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("cannot reach {url}: {}", because(&e)))?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(false);
    }
    expect_ok(response, url).await.map(|()| true)
}

async fn put_json(client: &reqwest::Client, url: &str, body: String) -> Result<(), String> {
    let response = client
        .put(url)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|e| format!("cannot reach {url}: {}", because(&e)))?;
    expect_ok(response, url).await
}

/// Why an upload never came back with a status.
///
/// The Server refuses some uploads *before* it reads a byte of the body — an identity nobody
/// created, a Set already assigned and therefore immutable (ADR-0025), a store at its ceiling
/// (ADR-0026). With hundreds of megabytes already in flight and no `Expect: 100-continue` to hold
/// them back — HTTP's own remedy for exactly this, which this client does not speak — that
/// response races the upload, the connection resets, and what arrives here is a transport error
/// carrying no status at all. Reporting it as "cannot reach" would name the one thing that is not
/// the problem: the Server answered, and said why.
///
/// So ask a second time with an empty artifact. The pre-body checks are the same ones and they run
/// again, but the request is small enough to survive the trip. An empty artifact is itself refused
/// (`400`), so the probe can never store anything — and a `400` is the answer that carries no news:
/// it means the checks passed and the Server got as far as the body, leaving the transport error as
/// the real story.
async fn refusal_behind(client: &reqwest::Client, entry: &str, error: &reqwest::Error) -> String {
    if let Ok(response) = client.put(entry).body(Vec::new()).send().await {
        let status = response.status();
        if status != reqwest::StatusCode::BAD_REQUEST {
            let body = response.text().await.unwrap_or_default();
            return format!("{entry} answered {status}: {}", body.trim());
        }
    }
    format!("cannot reach {entry}: {}", because(error))
}

/// A transport error with the cause that explains it. `reqwest::Error` displays only its own layer
/// — "error sending request for url (…)" — while the sentence that says *what went wrong* sits one
/// or two sources below it.
fn because(error: &reqwest::Error) -> String {
    let mut message = error.to_string();
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        message.push_str(&format!(": {cause}"));
        source = cause.source();
    }
    message
}

async fn expect_ok(response: reqwest::Response, url: &str) -> Result<(), String> {
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    let body = response.text().await.unwrap_or_default();
    Err(format!("{url} answered {status}: {}", body.trim()))
}

// ── HTTP ────────────────────────────────────────────────────────────────────

fn http() -> Result<reqwest::Client, String> {
    client_builder()
        .build()
        .map_err(|e| format!("cannot build an HTTP client: {e}"))
}

/// The client for the Server's Operator plane: the one every download uses, trusting `--cacert`
/// in place of the system's roots when it is given — the Client's own trust, so the two read a CA
/// file alike.
fn server_http(cacert: Option<&Path>) -> Result<reqwest::Client, String> {
    let ca_pem = cacert
        .map(|path| std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display())))
        .transpose()?;
    opamp::client::connection::ClientTls {
        ca_pem,
        identity: None,
    }
    .trust(client_builder())
    .map_err(|e| format!("--cacert: {e}"))?
    .build()
    .map_err(|e| format!("cannot build an HTTP client: {e}"))
}

fn client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        // TLS 1.3 alone, as every connection of this project (ADR-0013).
        .tls_version_min(reqwest::tls::Version::TLS_1_3)
        // Release hosts redirect to their CDN, so redirects are followed — but never to http.
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.url().scheme() != "https" {
                attempt.error("a redirect to anything but https is refused")
            } else if attempt.previous().len() >= 10 {
                attempt.error("too many redirects")
            } else {
                attempt.follow()
            }
        }))
        // An artifact is hundreds of megabytes over someone else's CDN; a whole-request timeout
        // would kill a working download on principle, so only the connect phase is bounded.
        .connect_timeout(std::time::Duration::from_secs(30))
        .user_agent("opamp-fleetctl")
}

async fn get(url: &str) -> Result<reqwest::Response, String> {
    let response = http()?
        .get(url)
        .send()
        .await
        .map_err(|e| format!("cannot reach {url}: {}", because(&e)))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("{url} answered {status}"));
    }
    Ok(response)
}

/// Streams an artifact to disk. An agent release is hundreds of megabytes, and a tool that read
/// one into memory to write it straight back out would be choosing the one shape that cannot work
/// on a small host.
async fn download(url: &str, dest: &Path) -> Result<(), String> {
    use std::io::Write;

    let mut response = get(url).await?;
    let mut file =
        std::fs::File::create(dest).map_err(|e| format!("cannot write {}: {e}", dest.display()))?;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("cannot download {url}: {}", because(&e)))?
    {
        file.write_all(&chunk)
            .map_err(|e| format!("cannot write {}: {e}", dest.display()))?;
    }
    file.flush()
        .map_err(|e| format!("cannot write {}: {e}", dest.display()))?;
    Ok(())
}

/// For the small answers — a checksum file, a JSON listing — where holding the whole body is the
/// simplest thing that works.
async fn get_bytes(url: &str) -> Result<Vec<u8>, String> {
    Ok(get(url)
        .await?
        .bytes()
        .await
        .map_err(|e| format!("cannot read {url}: {e}"))?
        .to_vec())
}

async fn get_json(url: &str) -> Result<serde_json::Value, String> {
    let bytes = get_bytes(url).await.map_err(|e| {
        // The one failure an operator hits without doing anything wrong, and it says nothing about
        // itself: GitHub answers 403 for sixty-one unauthenticated requests in an hour.
        if e.contains("403") {
            format!("{e} — GitHub rate-limits unauthenticated requests to 60 per hour")
        } else {
            e
        }
    })?;
    serde_json::from_slice(&bytes).map_err(|e| format!("{url} did not answer JSON: {e}"))
}

#[cfg(test)]
mod tests {
    /// The agent menu names the systems each agent can be fetched for, which is not something to
    /// discover three questions later. Every variant answers —
    /// adding one without a line here is the omission this catches.
    #[test]
    fn the_agent_menu_states_the_systems_each_agent_is_published_for() {
        for agent in super::AgentKind::value_variants() {
            let platforms = agent.platforms();
            assert!(
                platforms.contains('/') || platforms.contains("linux"),
                "{agent:?} names no system: {platforms:?}"
            );
        }
    }

    /// `group_platforms` states that a menu line wrapping at eighty columns is one `dialoguer`
    /// redraws wrongly as the selection moves — but nothing held anyone to it, and a line written
    /// by hand rather than by that function promptly ran to ninety-five. The rule is measured here
    /// on the lines the menu really shows, with the two columns `dialoguer` prefixes them with.
    ///
    /// Columns, not bytes: the Collectors' line carries an em dash.
    #[test]
    fn no_agent_menu_line_wraps() {
        const SELECTION_PREFIX: usize = 2;
        for label in super::agent_menu_labels() {
            let columns = SELECTION_PREFIX + label.chars().count();
            assert!(
                columns <= 80,
                "this line renders {columns} columns wide and will wrap: {label:?}"
            );
        }
    }

    /// Every agent the `--agent` flag accepts is also offered when the flag is omitted.
    ///
    /// The two came apart once — `icinga2` was reachable by flag and absent from the prompt for as
    /// long as the prompt kept its own list — so what is asserted here is that the menu is built
    /// from the same variants clap validates against.
    #[test]
    fn the_prompt_offers_every_agent_the_flag_accepts() {
        use clap::ValueEnum as _;
        let offered: Vec<&str> = super::AgentKind::value_variants()
            .iter()
            .map(|agent| agent.source().service_name)
            .collect();
        for expected in ["otelcol", "otelcol-contrib"] {
            assert!(offered.contains(&expected), "{expected} is not offered");
        }
    }

    use super::*;
    use std::io::Read as _;

    /// The tag patterns are what keep a version list from offering things that are not releases of
    /// the agent being fetched — the Collector repository tags its builder alongside.
    #[test]
    fn a_tag_is_a_version_only_when_it_is_this_agents_release() {
        assert_eq!(
            AgentKind::Otelcol.version_of_tag("v0.158.0"),
            Some("0.158.0".to_string())
        );
        for other in [
            "cmd/builder/v0.158.0",
            "cmd/opampsupervisor/v0.158.0",
            "0.158.0",
        ] {
            assert_eq!(AgentKind::Otelcol.version_of_tag(other), None, "{other}");
        }

        // This project's own tags carry the prefix its release workflow creates them under, and
        // the round trip is what `--version` relies on: an operator types what the release page
        // shows, and the tag is derived from it.
        assert_eq!(
            AgentKind::Supervisor.version_of_tag("version/1.2.3"),
            Some("1.2.3".to_string())
        );
        for other in ["v1.2.3", "1.2.3", "version/1.2", "version/1.2.3-dev"] {
            assert_eq!(AgentKind::Supervisor.version_of_tag(other), None, "{other}");
        }
        assert_eq!(
            AgentKind::Supervisor.tag_of_version("1.2.3"),
            "version/1.2.3"
        );
    }

    /// Upstream `1.19` is fetched under its own tag and named Package `1.19.0`; a leading zero is
    /// dropped, and a number that cannot be written as SemVer is refused, naming it (ADR-0043
    /// clause 6).
    /// Verifies: ADR-0043
    #[test]
    fn fetch_names_the_package_in_semver_and_fetches_upstreams_tag() {
        assert_eq!(
            AgentKind::Otelcol.release_names("1.19"),
            Ok(("v1.19".to_string(), "1.19.0".to_string()))
        );
        assert_eq!(
            AgentKind::Otelcol.release_names("0.158.0"),
            Ok(("v0.158.0".to_string(), "0.158.0".to_string()))
        );
        assert_eq!(package_version("24.04.1").as_deref(), Ok("24.4.1"));
        assert_eq!(package_version("2").as_deref(), Ok("2.0.0"));
        assert_eq!(package_version("1.19-rc.1").as_deref(), Ok("1.19.0-rc.1"));
        for unwritable in ["nightly", "1.2.3.4", "1.x", "", "1.0.0-01"] {
            let refusal = AgentKind::Otelcol
                .release_names(unwritable)
                .expect_err(unwritable);
            assert!(
                refusal.contains(&format!("{unwritable:?}")) && refusal.contains("SemVer"),
                "{refusal}"
            );
        }
    }

    /// Versions sort by their numbers: `0.9.0` is older than `0.10.0`, which as text it is not.
    #[test]
    fn versions_sort_by_number_rather_than_by_text() {
        let mut versions = vec![
            "0.9.0".to_string(),
            "0.10.0".to_string(),
            "0.158.0".to_string(),
        ];
        versions.sort_by_key(|v| std::cmp::Reverse(version_key(v)));
        assert_eq!(versions, vec!["0.158.0", "0.10.0", "0.9.0"]);
    }

    /// The list offers release *series*, not tags. Icinga 2 is the agent that makes the difference
    /// visible: five 2.16 patches would have been the entire list, so the one question an operator
    /// asks it — which versions can I still go back to — would have no answer in it. Only the
    /// newest patch of a series is offered, because an older one of the same line is not a choice
    /// anybody makes.
    #[test]
    fn the_version_list_offers_the_newest_patch_of_each_recent_series() {
        let icinga: Vec<String> = [
            "2.16.5", "2.16.4", "2.16.3", "2.16.2", "2.16.1", "2.16.0", "2.15.2", "2.15.1",
            "2.14.6", "2.13.10",
        ]
        .map(str::to_string)
        .to_vec();
        assert_eq!(
            super::newest_per_series(&icinga),
            ["2.16.5", "2.15.2", "2.14.6"]
        );

        // An agent that versions in two parts has no patch to collapse, so every version is its own
        // series and the list is simply the last three (GLPI tags `1.15`, `1.14`, …).
        let glpi: Vec<String> = ["1.15", "1.14", "1.13", "1.12"]
            .map(str::to_string)
            .to_vec();
        assert_eq!(super::newest_per_series(&glpi), ["1.15", "1.14", "1.13"]);

        // Fewer series than asked for is the whole list, not an error — a young repository has
        // nothing else to offer.
        let young: Vec<String> = ["0.2.1", "0.2.0"].map(str::to_string).to_vec();
        assert_eq!(super::newest_per_series(&young), ["0.2.1"]);
        assert!(super::newest_per_series(&[]).is_empty());
    }

    fn asset(name: &str) -> (String, String) {
        (name.to_string(), format!("https://example.invalid/{name}"))
    }

    /// The Collector's platform list is read from the assets, and the two distributions must not
    /// be confused: `otelcol-contrib_…` starts with text a careless `otelcol_` check would accept.
    #[test]
    fn collector_plans_come_from_the_assets_and_keep_the_distributions_apart() {
        let assets = vec![
            asset("otelcol_0.158.0_linux_amd64.tar.gz"),
            asset("otelcol_0.158.0_windows_amd64.tar.gz"),
            asset("otelcol_0.158.0_linux_s390x.tar.gz"),
            asset("otelcol_0.158.0_windows_x64.msi"),
            asset("otelcol-contrib_0.158.0_linux_amd64.tar.gz"),
        ];

        let core = collector_plans(AgentKind::Otelcol, "0.158.0", &assets);
        let platforms: Vec<String> = core
            .iter()
            .map(|p| format!("{}/{}", p.os, p.arch))
            .collect();
        assert_eq!(
            platforms,
            vec!["linux/amd64", "windows/amd64"],
            "an MSI is not an artifact a Supervisor installs, and s390x is a platform this fleet \
             cannot name"
        );
        assert!(
            core[1].block_hint.contains("otelcol.exe"),
            "{:?}",
            core[1].block_hint
        );

        let contrib = collector_plans(AgentKind::OtelcolContrib, "0.158.0", &assets);
        assert_eq!(contrib.len(), 1);
        assert_eq!(
            contrib[0].out_name,
            "otelcol-contrib_0.158.0_linux_amd64.tar.gz"
        );
    }

    /// The release also carries the operator tool's archives, named like the Client's
    /// (ADR-0028 clause 18); they are selected by stem, never by version and platform alone, so none
    /// of them becomes the `supervisor` Package's entry for its platform (clause 5).
    // Verifies: ADR-0028
    #[test]
    fn the_supervisor_passes_over_the_operator_tools_archives() {
        let assets = vec![
            asset("opamp-fleetctl_1.2.3_linux_amd64.tar.gz"),
            asset("opamp-fleetctl_1.2.3_darwin_arm64.tar.gz"),
            asset("supervisor_1.2.3_linux_amd64.tar.gz"),
            asset("SHA256SUMS"),
        ];
        let plans = supervisor_plans("1.2.3", &assets);
        let names: Vec<&str> = plans.iter().map(|p| p.out_name.as_str()).collect();
        assert_eq!(names, ["supervisor_1.2.3_linux_amd64.tar.gz"]);
    }

    /// This project's own release is fetched like any other agent's (ADR-0019): the `.tar.gz` per
    /// platform is the package, the installers beside it are not, and the one `SHA256SUMS` the
    /// publish job writes is what every artifact is verified against.
    #[test]
    fn the_supervisor_takes_the_archives_of_its_own_release_and_not_the_installers() {
        let assets = vec![
            asset("supervisor_1.2.3_linux_amd64.tar.gz"),
            asset("supervisor_1.2.3_linux_amd64.deb"),
            asset("supervisor_1.2.3_linux_amd64.rpm"),
            asset("supervisor_1.2.3_linux_arm64.tar.gz"),
            asset("supervisor_1.2.3_darwin_arm64.tar.gz"),
            asset("supervisor_1.2.3_darwin_amd64.tar.gz"),
            asset("supervisor_1.2.3_windows_amd64.tar.gz"),
            asset("supervisor_1.2.3_windows_amd64.msi"),
            asset("supervisor_1.1.0_linux_amd64.tar.gz"),
            asset("SHA256SUMS"),
        ];

        let plans = supervisor_plans("1.2.3", &assets);
        let platforms: Vec<String> = plans
            .iter()
            .map(|p| format!("{}/{}", p.os, p.arch))
            .collect();
        assert_eq!(
            platforms,
            vec![
                "darwin/amd64",
                "darwin/arm64",
                "linux/amd64",
                "linux/arm64",
                "windows/amd64",
            ],
            "an installer is not an artifact a fleet distributes, and another release's archive              is not this version"
        );
        // The menu promises exactly these, so a target added to the workflow and not to the list
        // is caught here rather than by an operator who cannot find their platform.
        let promised: Vec<String> = SUPERVISOR_PLATFORMS
            .iter()
            .map(|(os, arch)| format!("{os}/{arch}"))
            .collect();
        let mut promised_sorted = promised.clone();
        promised_sorted.sort();
        assert_eq!(platforms, promised_sorted);

        for plan in &plans {
            assert!(
                matches!(plan.action, Action::AsPublished),
                "the release is packed by this project's own packer; repacking it would only                  break the published hash"
            );
            match &plan.sources[0].checksum {
                ChecksumSource::Sums { urls } => {
                    assert_eq!(urls.len(), 1, "one file holds every artifact's line");
                    assert!(urls[0].ends_with("SHA256SUMS"), "{urls:?}");
                }
                other => panic!(
                    "the release publishes sums, not {:?}",
                    std::mem::discriminant(other)
                ),
            }
            assert!(
                plan.block_hint.contains("[packages] self_update"),
                "a Client takes this one over itself, so the hint is its consent and not a                  [[supervisor]] block: {:?}",
                plan.block_hint
            );
        }

        // Nothing to seed beside it: the Client's configuration is its host's (ADR-0017).
        assert!(AgentKind::Supervisor.default_configurations().is_empty());
    }

    /// The checksum layout changed at 0.158.0, so which one a release uses is read from its assets
    /// rather than derived from its version.
    #[test]
    fn the_collector_checksum_follows_whichever_form_the_release_publishes() {
        let modern = vec![
            asset("otelcol_0.158.0_linux_amd64.tar.gz"),
            asset("otelcol_0.158.0_linux_amd64.tar.gz.sha256"),
        ];
        assert!(matches!(
            collector_checksum("otelcol_0.158.0_linux_amd64.tar.gz", "otelcol", &modern),
            ChecksumSource::BareDigest { .. }
        ));

        let older = vec![
            asset("otelcol_0.157.0_linux_amd64.tar.gz"),
            asset("opentelemetry-collector-releases_otelcol_checksums.txt"),
        ];
        assert!(matches!(
            collector_checksum("otelcol_0.157.0_linux_amd64.tar.gz", "otelcol", &older),
            ChecksumSource::Sums { .. }
        ));
    }

    /// A directory reached through a link is packed **under the linked name too**, with its
    /// contents — the regression this exists for. The GLPI AppImage reaches its Perl library
    /// through `usr/share/perl/5.26`, a link to `5.26.1`; packing that name as an empty directory
    /// produced a tree whose agent could not find a single module, and packing only one of the two
    /// names left which one to directory-read order. A cycle is still refused, and a link pointing
    /// at nothing is dropped.
    #[cfg(unix)]
    #[test]
    fn a_linked_directory_is_packed_under_both_names_and_a_cycle_does_not_hang() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tree = dir.path().join("tree");
        std::fs::create_dir_all(tree.join("lib/5.26.1")).expect("create");
        std::fs::write(tree.join("AppRun"), b"the-entry-point").expect("write");
        std::fs::write(tree.join("lib/5.26.1/Universal.pm"), b"a-module").expect("write");
        std::os::unix::fs::symlink("5.26.1", tree.join("lib/5.26")).expect("link the version");
        std::os::unix::fs::symlink("../lib", tree.join("lib/loop")).expect("link a cycle");
        std::os::unix::fs::symlink("nowhere", tree.join("lib/dangling")).expect("link to nothing");

        let artifact = dir.path().join("packed.tar.gz");
        pack_tree(&tree, "wrapper", &artifact).expect("pack");

        let dest = dir.path().join("unpacked");
        std::fs::create_dir_all(&dest).expect("create");
        let summary =
            fleet_agent::archive::extract_tree_tar_gz(&artifact, Path::new("AppRun"), &dest)
                .expect("the packed tree is one a Client installs");

        assert_eq!(
            std::fs::read(dest.join("lib/5.26.1/Universal.pm")).expect("the real path"),
            b"a-module"
        );
        assert_eq!(
            std::fs::read(dest.join("lib/5.26/Universal.pm")).expect("the linked path"),
            b"a-module",
            "the name the agent actually uses carries the contents"
        );
        assert!(
            !dest.join("lib/dangling").exists(),
            "a link pointing at nothing is not a member"
        );
        // The cycle is a directory that stops rather than a walk that never ends; it is only its
        // presence that matters here, since arriving at all means the pack returned.
        assert!(summary.files >= 3, "{summary:?}");
    }

    /// Both checksum shapes, read the way each source publishes them — including the `*` a
    /// `sha256sum` binary-mode line carries.
    #[test]
    fn a_published_checksum_is_read_from_either_shape() {
        let dir = tempfile::tempdir().expect("tempdir");
        let artifact = dir.path().join("telegraf-1.39.3_linux_amd64.tar.gz");
        std::fs::write(&artifact, b"x").expect("write");

        let sums = dir.path().join("sums");
        std::fs::write(
            &sums,
            "aaaa  other.tar.gz\nbbbb *telegraf-1.39.3_linux_amd64.tar.gz\n",
        )
        .expect("write");
        // Read through the same code the network path uses, with a `file:` URL standing in for the
        // download — the parsing is the part worth testing.
        assert_eq!(
            parse_sums(&std::fs::read_to_string(&sums).expect("read"), &artifact),
            Some("bbbb".to_string())
        );
        assert_eq!(
            parse_sums("aaaa  something-else\n", &artifact),
            None,
            "a file with no line for this artifact is not a checksum for it"
        );
    }

    /// An upload the Server refuses before it reads the body — an assigned Set (ADR-0025), an
    /// unknown identity, a full store — leaves the operator with a transport error and no status:
    /// the refusal races a body already in flight and loses. What the operator must still be told
    /// is *why the Server said no*, never "cannot reach" about a Server that answered.
    ///
    /// The stand-in Server here drops the upload connection without answering at all, which is the
    /// same thing seen from the client and the deterministic form of it: a race that sometimes
    /// delivers the response would be a test that sometimes passes.
    #[tokio::test]
    async fn a_refusal_lost_with_the_upload_is_asked_for_again() {
        use std::io::Write;

        // What `main` does before anything builds a client (ADR-0013).
        opamp::tls::install_ring_provider();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let server = format!("http://{}", listener.local_addr().expect("addr"));
        std::thread::spawn(move || {
            let mut uploads = 0;
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                // Byte at a time, stopping at the blank line: reading the head must never spill
                // into a body this Server has decided not to read.
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut byte) {
                        Ok(1) => head.push(byte[0]),
                        _ => break,
                    }
                }
                let head = String::from_utf8_lossy(&head).into_owned();
                if !head.contains("/entries/") {
                    // The Set call is answered as the real Server answers it — body read first,
                    // so the response is not what a reset takes away.
                    let length: usize = head
                        .to_ascii_lowercase()
                        .split("content-length:")
                        .nth(1)
                        .and_then(|rest| rest.split("\r\n").next())
                        .and_then(|value| value.trim().parse().ok())
                        .unwrap_or(0);
                    let mut body = vec![0u8; length];
                    let _ = stream.read_exact(&mut body);
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}",
                    );
                    continue;
                }
                uploads += 1;
                if uploads == 1 {
                    // The artifact is still being written; this connection ends with nothing on it.
                    continue;
                }
                let refusal = b"{\"error\":\"set otelcol@0.0.1@otelcol is assigned to an Agent\"}";
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 409 Conflict\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        refusal.len()
                    )
                    .as_bytes(),
                );
                let _ = stream.write_all(refusal);
            }
        });

        let dir = tempfile::tempdir().expect("tempdir");
        let artifact = dir.path().join("otelcol_0.0.1_linux_amd64.tar.gz");
        // Comfortably past any socket buffer, so the write is still in progress when the
        // connection goes — the shape a real artifact has and a two-byte body would not.
        std::fs::write(&artifact, vec![0u8; 8 * 1024 * 1024]).expect("write");
        let plan = Plan {
            os: "linux".into(),
            arch: "amd64".into(),
            sources: vec![Download {
                url: String::new(),
                checksum: ChecksumSource::BareDigest { url: String::new() },
            }],
            action: Action::AsPublished,
            out_name: "otelcol_0.0.1_linux_amd64.tar.gz".into(),
            block_hint: String::new(),
        };

        let client = http().expect("client");
        let error = upload(&client, &server, "otelcol", "0.0.1", &plan, &artifact)
            .await
            .expect_err("an upload nothing accepted is not a success");
        assert!(
            error.contains("409 Conflict") && error.contains("assigned to an Agent"),
            "the operator is told what the Server refused, not that it could not be reached: {error}"
        );
    }

    /// Every *supervised* agent this tool can fetch carries a default Configuration, and each one
    /// is storable: the name follows the ADR-0019 grammar the Server enforces (which admits no dot,
    /// so no file extension), the body is not empty (the Server refuses an empty one), and it is
    /// stated for its Agent type, so a Deployment holding it fits it to that type alone (ADR-0034).
    ///
    /// This is the test that fails when a variant is added and its default is forgotten, which is
    /// the only way an agent could reach a Server with a package and nothing to run. The Client's
    /// own package is the one exemption, and it is stated below rather than skipped.
    #[test]
    fn every_agent_carries_a_storable_default_configuration() {
        for agent in AgentKind::value_variants() {
            let defaults = agent.default_configurations();
            let service_name = agent.source().service_name;
            if matches!(agent, AgentKind::Supervisor) {
                // The one package nothing supervises. A Client reads `supervisor.toml` on its own
                // host, and the fleet owns only the `[[supervisor]]` half of it (ADR-0017), so
                // there is no body this tool could put on a Server — and an offer needs none: the
                // consent that admits this package is already in that file (ADR-0018).
                assert!(
                    defaults.is_empty(),
                    "{service_name} is the Client itself; a Configuration for it would be a \
                     decision this test has not been told about"
                );
                continue;
            }
            assert!(
                !defaults.is_empty(),
                "{service_name} has no default configuration"
            );
            for config in defaults {
                assert!(
                    !config.name.is_empty()
                        && config
                            .name
                            .chars()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                    "{service_name}: {:?} is not a name the Server would accept",
                    config.name
                );
                assert!(
                    !config.body.trim().is_empty(),
                    "{service_name}: {} has an empty body",
                    config.name
                );
                assert_eq!(
                    config.service_name, service_name,
                    "{service_name}: {} would fit every Agent type of its Deployment",
                    config.name
                );
            }
        }
    }

    /// The upload asks before it writes: a Configuration the Server already holds is left exactly
    /// as it is — operator edits included — and only the missing one is stored.
    ///
    /// The stand-in Server answers `200` for `otelcol-conf` and `404` for `otelcol-contrib-conf`,
    /// and records every request, so what the test asserts is the *absence* of a PUT over the top
    /// of the existing one.
    #[tokio::test]
    async fn a_default_configuration_the_server_already_holds_is_not_written_over() {
        use std::io::Write;
        use std::sync::{Arc, Mutex};

        opamp::tls::install_ring_provider();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let server = format!("http://{}", listener.local_addr().expect("addr"));
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut byte) {
                        Ok(1) => head.push(byte[0]),
                        _ => break,
                    }
                }
                let head = String::from_utf8_lossy(&head).into_owned();
                let Some(line) = head.lines().next() else {
                    continue;
                };
                recorded.lock().expect("lock").push(line.to_string());
                // A body must be read before the answer, or the response races a reset.
                let length: usize = head
                    .to_ascii_lowercase()
                    .split("content-length:")
                    .nth(1)
                    .and_then(|rest| rest.split("\r\n").next())
                    .and_then(|value| value.trim().parse().ok())
                    .unwrap_or(0);
                let mut body = vec![0u8; length];
                let _ = stream.read_exact(&mut body);
                let answer = if line.starts_with("GET") && line.contains("/otelcol-conf ") {
                    "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}"
                } else if line.starts_with("GET") {
                    "HTTP/1.1 404 Not Found\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}"
                } else {
                    "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}"
                };
                let _ = stream.write_all(answer.as_bytes());
            }
        });

        for agent in [AgentKind::Otelcol, AgentKind::OtelcolContrib] {
            upload_default_configurations(&http().expect("client"), &server, agent)
                .await
                .expect("the Server accepted the one it was missing");
        }

        let seen = seen.lock().expect("lock").clone();
        assert!(
            seen.iter().any(|r| r.starts_with("PUT")
                && r.contains("/api/v1/configurations/otelcol-contrib-conf")),
            "the missing configuration is stored: {seen:?}"
        );
        assert!(
            !seen
                .iter()
                .any(|r| r.starts_with("PUT") && r.contains("/api/v1/configurations/otelcol-conf")),
            "the one the Server already holds is left alone: {seen:?}"
        );
    }

    /// `--cacert` is what lets the tool upload to a fleet whose Server certificate a self-made CA
    /// signed: with it the Server is trusted, and without it the same Server is refused for the
    /// reason the operator would otherwise meet — a certificate no system root vouches for.
    ///
    /// Verifies: ADR-0013
    #[tokio::test]
    async fn a_server_signed_by_the_named_ca_is_trusted_and_only_then() {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use std::io::Write;
        use std::sync::Arc;

        opamp::tls::install_ring_provider();

        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).expect("ca");
        let issuer = Issuer::new(ca_params, ca_key);
        let key = KeyPair::generate().expect("key");
        let leaf = CertificateParams::new(vec!["127.0.0.1".to_string()])
            .expect("params")
            .signed_by(&key, &issuer)
            .expect("leaf");

        let config = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(leaf.der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .expect("server config"),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let server = format!("https://{}", listener.local_addr().expect("addr"));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let Ok(connection) = rustls::ServerConnection::new(Arc::clone(&config)) else {
                    continue;
                };
                let mut tls = rustls::StreamOwned::new(connection, stream);
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match tls.read(&mut byte) {
                        Ok(1) => head.push(byte[0]),
                        _ => break,
                    }
                }
                let length: usize = String::from_utf8_lossy(&head)
                    .to_ascii_lowercase()
                    .split("content-length:")
                    .nth(1)
                    .and_then(|rest| rest.split("\r\n").next())
                    .and_then(|value| value.trim().parse().ok())
                    .unwrap_or(0);
                let mut body = vec![0u8; length];
                let _ = tls.read_exact(&mut body);
                let _ = tls.write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}",
                );
                let _ = tls.flush();
            }
        });

        let dir = tempfile::tempdir().expect("tempdir");
        let cacert = dir.path().join("ca.pem");
        std::fs::write(&cacert, ca.pem()).expect("write");
        let url = format!("{server}/api/v1/packages/otelcol/0.0.1");

        let trusting = server_http(Some(&cacert)).expect("the CA reads");
        put_json(&trusting, &url, "{}".to_string())
            .await
            .expect("a Server the named CA signed is reached");

        let error = put_json(&server_http(None).expect("client"), &url, "{}".to_string())
            .await
            .expect_err("without --cacert the same Server is not trusted");
        assert!(error.contains("UnknownIssuer"), "{error}");
    }

    /// A `--cacert` that names no certificate is refused when it is read, before any download,
    /// rather than surfacing as an untrusted Server at the very end.
    #[test]
    fn a_cacert_without_a_certificate_is_refused_up_front() {
        let dir = tempfile::tempdir().expect("tempdir");
        let empty = dir.path().join("empty.pem");
        std::fs::write(&empty, "").expect("write");
        let error = server_http(Some(&empty)).expect_err("an empty file is no CA");
        assert!(error.contains("no certificates"), "{error}");

        let missing = dir.path().join("missing.pem");
        let error = server_http(Some(&missing)).expect_err("a missing file is no CA");
        assert!(error.contains("cannot read"), "{error}");
    }
}
