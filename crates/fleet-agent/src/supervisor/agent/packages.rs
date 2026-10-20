//! The package channel (ADR-0026, ADR-0018): an offer checked and taken or refused, the
//! download and install in flight, and the `PackageStatuses` this Agent reports about them.

use opamp::proto::{
    AgentCapabilities, PackageAvailable, PackageDownloadDetails, PackageStatus, PackageStatusEnum,
    PackageStatuses, PackageType,
};
use tracing::{error, info, warn};

use super::{AgentState, Handled, Local};
use crate::supervisor::ports::{HighWaterMarks, InstalledPackage};

impl AgentState {
    /// Opts this Agent into package delivery (ADR-0026): declares `AcceptsPackages` and
    /// `ReportsPackageStatuses`, and restores what it last installed so a restarted Client reports
    /// the version it runs and is not re-offered it.
    ///
    /// It consents; it does not choose. Which artifact arrives is decided on the Server, so a
    /// rollout is aimed centrally rather than from this host's file.
    ///
    /// For a Supervisor the restored record also seeds the high-water mark of its Agent type
    /// (ADR-0043 clause 9), and a record whose version is not SemVer is dropped with a warning
    /// (clause 10): nothing enters the mark from it, and the Agent reports no version for it.
    pub fn accept_packages(&mut self) {
        self.local.accepts_packages = true;
        self.local.installed_package = self.storage.load_package();
        if self.local.managed {
            self.restore_supervisor_record();
        }
        self.declare_capability(AgentCapabilities::AcceptsPackages);
        self.declare_capability(AgentCapabilities::ReportsPackageStatuses);
    }

    /// Hands this Supervisor the high-water marks it shares with every other Supervisor of the
    /// Client (ADR-0043 clause 8). Set before [`accept_packages`](Self::accept_packages), which
    /// seeds the mark from the installed record.
    #[must_use]
    pub fn with_high_water(mut self, marks: std::sync::Arc<dyn HighWaterMarks>) -> Self {
        self.local.high_water = Some(marks);
        self
    }

    /// A Supervisor's restored record, held to the SemVer rule and entered into the mark.
    fn restore_supervisor_record(&mut self) {
        let Some(installed) = &self.local.installed_package else {
            return;
        };
        if !fleet_core::version::is_semver(&installed.version) {
            warn!(
                supervisor = %self.local.instance_name, version = %installed.version,
                "the installed-package record names a version that is not SemVer; dropping it — \
                 the program keeps running, and a rollout of a SemVer version reaches it as a \
                 first rollout"
            );
            self.local.installed_package = None;
            if let Err(e) = self.storage.forget_package() {
                warn!(error = %e, "cannot drop the installed package record");
            }
            return;
        }
        if let Some(marks) = &self.local.high_water {
            marks.raise(&self.local.service_name, &installed.version);
        }
    }

    /// Opts this Agent into package delivery for **one named package only** (ADR-0018) — what the
    /// Client's own Agent does. A Supervisor takes whichever top-level package the Server offers
    /// it, because the worst case there is a Managed Process that will not start and is rolled
    /// back. The Client has no such safety net: a package written over this binary takes the host
    /// out of reach for good. So this side matches the name and refuses everything else.
    ///
    /// The restored record is held against the version this binary *is*, and dropped when the two
    /// are not the same release. `service uninstall` deliberately keeps the install layout and the
    /// state (ADR-0019), so an operator who reinstalls an older Client comes up on top of the
    /// record its successor wrote — and reporting that record would tell the Server this host runs
    /// a version it does not have. Worse than the wrong line in the fleet view: the offer is gated
    /// on the hash inside it, so the Server would never offer this host the package again. A
    /// record that does not name the running binary is a record about a binary that is gone.
    pub fn accept_packages_named(&mut self, name: String) {
        self.accept_packages();
        let running = fleet_core::version::current();
        if let Some(installed) = &self.local.installed_package {
            // Not string equality: the record holds the version the operator uploaded (`1.2.3`)
            // and this binary calls itself `1.2.3+a1b2c3d`. The same comparison the self-update
            // probe makes before a version is ever pointed at (ADR-0012).
            if !fleet_core::version::same_release(&installed.version, running) {
                warn!(
                    recorded = %installed.version, running = %running,
                    "the installed package record does not name the version this Client runs; \
                     discarding it, so the Server can offer the package again"
                );
                self.local.installed_package = None;
                if let Err(e) = self.storage.forget_package() {
                    warn!(error = %e, "cannot drop the stale installed package record");
                }
            }
        }
        self.local.expected_package = Some(name);
    }

    /// Whether this Agent takes Server-offered packages (ADR-0026) — the self-Agent unless
    /// `[packages] self_update = false` withdraws the consent (ADR-0018), and every Supervisor, since every Managed
    /// Process is one this Client installs (ADR-0017). Read without side effects, so a startup
    /// check can ask it before anything is polled.
    pub fn accepts_packages(&self) -> bool {
        self.protocol.declares(AgentCapabilities::AcceptsPackages)
    }

    /// Records how far the artifact download has got (ADR-0026), so the next report carries
    /// `Downloading` with the details. The Baseline only *permits* these interim reports; without
    /// them a multi-hundred-megabyte download is indistinguishable from a stuck install.
    pub fn package_downloading(&mut self, details: PackageDownloadDetails) {
        self.local.downloading = Some(details);
        self.protocol.package_status_changed();
    }

    /// The artifact is downloaded and verified; what follows is the Supervisor applying it, which
    /// the Baseline reports as `Installing` rather than `Downloading`.
    pub fn package_downloaded(&mut self) {
        self.local.downloading = None;
        self.protocol.package_status_changed();
    }

    /// Closes a package's lifecycle the Supervisor applied (ADR-0026): `Ok(version)` records it
    /// Installed and persists it; `Err` reports InstallFailed (the binary was rolled back). Either
    /// way the offered aggregate is echoed, so the Server stops re-offering the same bytes — a
    /// refusal is a report, not a loop.
    pub fn package_applied(&mut self, hash: Vec<u8>, result: Result<String, String>) {
        let local = &mut self.local;
        // Keep the name the outcome is about: `installing` is cleared here, and a failure leaves
        // no installed record to fall back on, but the status still has to name its package.
        if let Some(name) = local.installing.as_ref().map(|d| d.name.clone()) {
            local.offered_name = Some(name);
        }
        local.installing = None;
        local.downloading = None;
        match result {
            Ok(version) => {
                let installed = InstalledPackage {
                    name: local.package_name().unwrap_or_default(),
                    version: version.clone(),
                    hash_hex: hex::encode(&hash),
                };
                if let Err(e) = self.storage.store_package(&installed) {
                    warn!(error = %e, "cannot persist the installed package record");
                }
                // The program survived the apply grace: its Agent type's mark rises to it
                // (ADR-0043 clause 8). A rollback is an `Err` and moves nothing.
                if local.expected_package.is_none() {
                    if let Some(marks) = &local.high_water {
                        marks.raise(&local.service_name, &version);
                    }
                }
                info!(version = %version, "package installed");
                local.installed_package = Some(installed);
                local.package_error.clear();
            }
            Err(error) => {
                error!(error = %error, "package installation failed");
                local.package_error = error;
            }
        }
        local.echoed_all_packages_hash = local.offered_all_packages_hash.clone();
        self.protocol.package_status_changed();
    }
}

impl Local {
    /// The package this Agent is processing or has: the one being installed, else the installed
    /// one, else the one last offered — and for the Client's own Agent, else the one it consents
    /// to, which it knows from its own configuration before any offer arrives (ADR-0018).
    ///
    /// That last fallback is what lets this Client state a version for its own package from the
    /// first report on. A Supervisor has no such name: which package it gets is the Server's
    /// choice, so before an offer there is nothing to key a status by, and `None` is then the
    /// whole of "all packages the Agent has".
    fn package_name(&self) -> Option<String> {
        self.installing
            .as_ref()
            .map(|d| d.name.clone())
            .or_else(|| self.installed_package.as_ref().map(|p| p.name.clone()))
            .or_else(|| self.offered_name.clone())
            .or_else(|| self.expected_package.clone())
    }

    /// This Agent's package status as one `PackageStatuses`: its single package's state, plus the
    /// `server_provided_all_packages_hash` the Server compares to gate re-offering.
    pub(super) fn package_statuses(&self) -> PackageStatuses {
        // Every package the Agent has or is processing — which is at most one, and none until
        // the Server has offered something. The aggregate still rides an empty map: it is what
        // tells the Server this Agent is in sync with an offer of nothing.
        let Some(name) = self.package_name() else {
            return PackageStatuses {
                packages: Default::default(),
                server_provided_all_packages_hash: self.echoed_all_packages_hash.clone(),
                error_message: self.offer_error.clone(),
            };
        };
        // `agent_has_*` is what the Agent actually runs — the last successful install, if any.
        //
        // For the Client's own Agent there is one without an install record too: *this process*. A
        // Client that arrived by `.deb`, `.rpm`, MSI or by hand has installed no package, and
        // reporting nothing there says "nothing installed under this name" — which is precisely the
        // answer (ADR-0025) that lets a Set of the version it already runs reach it, and a Set
        // *older* than it downgrade it. The binary knows what it is; the record only says how it
        // got here.
        let (has_version, has_hash) = self
            .installed_package
            .as_ref()
            .map(|p| {
                (
                    p.version.clone(),
                    hex::decode(&p.hash_hex).unwrap_or_default(),
                )
            })
            .or_else(|| {
                // The *identity* of what this binary reports, not the whole string: a version
                // recorded by an install carries the operator's spelling, without the build
                // metadata this binary appends (ADR-0012), and the two have to read alike in the
                // fleet view. Nothing is lost — metadata takes no part in a comparison.
                self.expected_package.as_ref().and_then(|_| {
                    fleet_core::version::identity(fleet_core::version::current())
                        .map(|version| (version.to_string(), Vec::new()))
                })
            })
            .unwrap_or_default();
        let status = if self.downloading.is_some() {
            // Still fetching the artifact. Reported apart from `Installing` because a download of
            // a few hundred megabytes is the part that takes minutes — the Server would otherwise
            // watch a silent `Installing` and have no way to tell progress from a hang.
            PackageStatusEnum::Downloading
        } else if self.installing.is_some() {
            // Downloaded and verified; the Supervisor is applying it.
            PackageStatusEnum::Installing
        } else if !self.package_error.is_empty() {
            // The last attempt failed — a refusal is a report, not a silence.
            PackageStatusEnum::InstallFailed
        } else if !has_version.is_empty() {
            // Installed, whether a package put it there or an installer did: the status describes
            // what is on the host under this name, not how it arrived.
            PackageStatusEnum::Installed
        } else {
            PackageStatusEnum::InstallPending
        };
        let (offered_version, offered_hash) = self
            .server_offered
            .clone()
            .unwrap_or_else(|| (String::new(), Vec::new()));
        let package = PackageStatus {
            name: name.clone(),
            // While installing this is still the old one (we have not switched yet).
            agent_has_version: has_version,
            agent_has_hash: has_hash,
            server_offered_version: offered_version,
            server_offered_hash: offered_hash,
            status: status as i32,
            error_message: self.package_error.clone(),
            // "Should only be set if status is Downloading" — so it rides exactly that status.
            download_details: self.downloading,
        };
        PackageStatuses {
            packages: [(name, package)].into(),
            server_provided_all_packages_hash: self.echoed_all_packages_hash.clone(),
            error_message: self.offer_error.clone(),
        }
    }

    /// Reacts to a `PackagesAvailable` offer: the Server selected what this Agent may have
    /// (ADR-0026), so this side takes the one **top-level** package out of the offer — the binary
    /// of its Managed Process — and ignores addons, which a Supervisor has no way to apply.
    pub(super) fn handle_package_offer(
        &mut self,
        offer: &opamp::proto::PackagesAvailable,
        handled: &mut Handled,
    ) {
        if !self.accepts_packages {
            return;
        }
        self.offered_all_packages_hash = offer.all_packages_hash.clone();
        // The Baseline: "There is normally only one top-level package, which implements the
        // primary functionality of the Agent." The Server refuses to create an overlap, so more
        // than one here means a peer that does not — refused rather than picked from at random.
        let mut top_level = offer
            .packages
            .iter()
            .filter(|(_, available)| available.r#type != PackageType::Addon as i32);
        let Some((name, available)) = top_level.next() else {
            // Nothing top-level for us. An empty offer is simply "nothing for this Agent"; an
            // offer of addons only is an operator error — a Supervisor replaces one binary and
            // knows nothing about addons — so that one is reported rather than passed over.
            if offer.packages.is_empty() {
                self.echoed_all_packages_hash = offer.all_packages_hash.clone();
                self.package_status_owed = true;
            } else {
                error!(
                    packages = offer.packages.len(),
                    "refusing an offer of addons only: this Client installs top-level packages only"
                );
                self.refuse_offer(
                    offer,
                    "this Client installs top-level packages only; the offer carries addons only"
                        .to_string(),
                    handled,
                );
            }
            return;
        };
        if let Some((second, _)) = top_level.next() {
            error!(
                first = %name, second = %second,
                "refusing an offer with two top-level packages: an Agent has one binary to replace"
            );
            self.refuse_offer(
                offer,
                format!(
                    "the Server offered two top-level packages ({name:?} and {second:?}); \
                     an Agent has one binary to replace"
                ),
                handled,
            );
            return;
        }
        let name = name.clone();
        // The Client's own Agent takes one named package and nothing else (ADR-0018). A
        // fleet-wide package with an empty Selector reaches every consenting Agent, so without
        // this an artifact meant for a Collector would be written over this binary and the host
        // would be gone. Refused and reported, never silently ignored.
        if let Some(expected) = self.expected_package.as_ref().filter(|e| **e != name) {
            error!(
                offered = %name, expected = %expected,
                "refusing a package this Agent was not configured to take"
            );
            let error = format!(
                "this Agent installs only the package {expected:?}; the Server offered {name:?}"
            );
            self.refuse_offer(offer, error, handled);
            return;
        }
        // A Supervisor takes a package for its own Agent type and nothing else, only under a
        // SemVer version, and never one below what it runs or below the highest version this
        // Client has installed for the type (ADR-0043 clause 7). The signature binds the artifact
        // to its type and version, but says nothing about how that version orders against
        // another, so the order is this side's to hold — against a Server that offers an old,
        // validly signed build.
        if self.expected_package.is_none() {
            let mark = match self
                .high_water
                .as_ref()
                .map(|marks| marks.mark(&self.service_name))
            {
                Some(Err(reason)) => {
                    error!(reason = %reason, "refusing a package: the high-water file cannot be read");
                    self.refuse_offer(offer, reason, handled);
                    return;
                }
                Some(Ok(mark)) => mark,
                None => None,
            };
            if name != self.service_name {
                error!(
                    offered = %name, agent_type = %self.service_name,
                    "refusing a package for another Agent type"
                );
                let error = format!(
                    "this Agent is a {:?}; the Server offered a package for {name:?}",
                    self.service_name
                );
                self.refuse_offer(offer, error, handled);
                return;
            }
            if !fleet_core::version::is_semver(&available.version) {
                error!(offered = %available.version, "refusing a package whose version is not SemVer");
                let error = format!(
                    "the Server offered {name} {:?}, which is not SemVer — a package version is a \
                     SemVer 2.0.0 version, and no other is taken",
                    available.version
                );
                self.refuse_offer(offer, error, handled);
                return;
            }
            if let Some(installed) = &self.installed_package {
                if fleet_core::version::precedence(&available.version, &installed.version)
                    == Some(std::cmp::Ordering::Less)
                {
                    error!(
                        offered = %available.version, installed = %installed.version,
                        "refusing a package older than the one installed"
                    );
                    let error = format!(
                        "the Server offered {} {}, older than the {} installed — a downgrade is \
                         not taken",
                        name, available.version, installed.version
                    );
                    self.refuse_offer(offer, error, handled);
                    return;
                }
            }
            if let Some(mark) = mark.filter(|mark| {
                fleet_core::version::precedence(&available.version, mark)
                    == Some(std::cmp::Ordering::Less)
            }) {
                error!(
                    offered = %available.version, mark = %mark,
                    "refusing a package below the high-water mark of its Agent type"
                );
                let error = format!(
                    "the Server offered {name} {}, below {mark}, the highest version this Client \
                     has installed for {name:?} — a downgrade is not taken",
                    available.version
                );
                self.refuse_offer(offer, error, handled);
                return;
            }
        }
        // A usable offer clears whatever the last unusable one complained about.
        self.offer_error.clear();
        self.offered_name = Some(name.clone());
        self.server_offered = Some((available.version.clone(), available.hash.clone()));
        if self.already_has(available) {
            // Already running this package: in sync — echo the aggregate to end the offer.
            self.echoed_all_packages_hash = offer.all_packages_hash.clone();
            self.package_status_owed = true;
            return;
        }
        let in_flight = self
            .installing
            .as_ref()
            .is_some_and(|d| d.hash == available.hash);
        if in_flight {
            return; // Already downloading/installing this exact package.
        }
        let Some(file) = &available.file else {
            warn!(package = %name, "package offer carries no downloadable file; ignoring");
            return;
        };
        let download = PackageDownload {
            name: name.clone(),
            version: available.version.clone(),
            hash: available.hash.clone(),
            download_url: file.download_url.clone(),
            content_hash: file.content_hash.clone(),
            signature: file.signature.clone(),
            // The Baseline asks the Agent to send these on the GET. This Server sends none; any a
            // Server does send go to its own origin alone (ADR-0033).
            headers: file
                .headers
                .as_ref()
                .map(|headers| {
                    headers
                        .headers
                        .iter()
                        .map(|header| (header.key.clone(), header.value.clone()))
                        .collect()
                })
                .unwrap_or_default(),
        };
        info!(package = %name, version = %available.version, "package offered; installing");
        self.installing = Some(download.clone());
        self.package_error.clear();
        self.package_status_owed = true;
        handled.send_report = true;
        handled.package_download = Some(download);
    }

    /// Refuses an offer this Agent cannot act on, and says why: nothing is left installing, the
    /// reason is reported as the offer's own error, and the aggregate is echoed at once so the
    /// Server stops re-offering it — a refusal is a report, not a loop.
    fn refuse_offer(
        &mut self,
        offer: &opamp::proto::PackagesAvailable,
        error: String,
        handled: &mut Handled,
    ) {
        self.installing = None;
        self.offer_error = error;
        self.echoed_all_packages_hash = offer.all_packages_hash.clone();
        self.package_status_owed = true;
        handled.send_report = true;
    }

    /// Whether this offer is what the Agent already has, so the offer ends with an echo rather
    /// than a download.
    ///
    /// For the package that carries the Client itself (ADR-0018, ADR-0019) that question is
    /// answered by the version *this process runs*: what a program reports about itself outranks
    /// what a record says was once installed here (ADR-0025). The record's hash would otherwise end
    /// an offer of the very bytes this host is not running: a state directory that outlived its
    /// binary claims a version, the Server offers it again, and the claim is what swallows the
    /// offer.
    ///
    /// A Supervisor has no such answer — the Managed Process's version is the process's own, and a
    /// package numbers it in whatever space the operator chose — so there the installed hash stays
    /// the test: the same bytes are the same package.
    fn already_has(&self, available: &PackageAvailable) -> bool {
        if self.expected_package.is_some() {
            return fleet_core::version::same_release(
                fleet_core::version::current(),
                &available.version,
            );
        }
        self.installed_package
            .as_ref()
            .map(|p| hex::decode(&p.hash_hex).unwrap_or_default())
            .as_deref()
            == Some(available.hash.as_slice())
    }
}

/// One offered package the transport must download, verify, and hand to the Supervisor. Built by
/// the Agent state machine from a `PackageAvailable`; the raw fields it needs travel here.
#[derive(Clone, PartialEq, Eq)]
pub struct PackageDownload {
    pub name: String,
    pub version: String,
    /// The package hash the reported status refers to.
    pub hash: Vec<u8>,
    /// The `download_url` from the offer — absolute, or a path resolved against the endpoint.
    pub download_url: String,
    /// The expected SHA-256 of the artifact.
    pub content_hash: Vec<u8>,
    /// The Ed25519 signature over the artifact; empty means unsigned.
    pub signature: Vec<u8>,
    /// The headers the offer says this download needs, sent only to this Client's own Server
    /// origin (ADR-0033). The Baseline: *"The Agent SHOULD include the HTTP headers provided in the
    /// headers field for the GET request."*
    ///
    /// Raw pairs rather than the wire type, like every other field here: what the download needs is
    /// a name and a value, not a protobuf message.
    pub headers: Vec<(String, String)>,
}

/// Written by hand rather than derived, because a header value is a credential.
///
/// This struct travels inside `Handled`, which derives `Debug`; a single `debug!(?handled)` added
/// later would otherwise put a download credential in the log file that ADR-0019 writes to disk in
/// service mode. Keys are printed — they are what a diagnosis needs — and values never are.
impl std::fmt::Debug for PackageDownload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PackageDownload")
            .field("name", &self.name)
            .field("version", &self.version)
            .field("hash", &self.hash)
            .field("download_url", &self.download_url)
            .field("content_hash", &self.content_hash)
            .field("signature", &self.signature)
            .field(
                "headers",
                &self
                    .headers
                    .iter()
                    .map(|(key, _)| format!("{key}: <redacted>"))
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}
