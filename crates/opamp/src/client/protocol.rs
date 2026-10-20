//! One Agent's OpAMP state machine, as the specification defines it (ADR-0010).
//!
//! It decides **which** fields a report carries — a full snapshot or only what changed, and only
//! what the Server's Capability Set licenses — and settles what a reply means for the protocol:
//! capabilities, flags, error responses, a reassigned identity, commands. **What** a report holds,
//! and what to do with a configuration, a connection-settings offer or a package offer, is the
//! application's: it supplies the content through [`ReportContent`] and is handed the rest as a
//! [`Received`].
//!
//! It performs no I/O and needs only `opamp` and the standard library, so a program that brings its
//! own I/O can drive it directly; [`ws`](crate::client::ws) and [`http`](crate::client::http) are the drivers this
//! crate offers on top of it.

use std::time::Duration;

use crate::proto::{
    AgentCapabilities, AgentDescription, AgentDisconnect, AgentRemoteConfig, AgentToServer,
    AvailableComponents, ComponentHealth, ConnectionSettingsOffers, ConnectionSettingsStatus,
    EffectiveConfig, PackageStatuses, PackagesAvailable, RemoteConfigStatus, ServerCapabilities,
    ServerErrorResponseType, ServerToAgent, ServerToAgentFlags,
};
use crate::uid::InstanceUid;
use tracing::{error, info, warn};

/// What a report holds, supplied by the application. The protocol asks only for what the report
/// it is building carries.
pub trait ReportContent {
    /// The Agent's description, for a full report. `uid` is the identity it is reported under.
    fn description(&self, uid: &InstanceUid) -> AgentDescription;
    fn health(&self) -> ComponentHealth;
    fn effective_config(&self) -> EffectiveConfig;
    /// `None` for an Agent that takes no packages.
    fn package_statuses(&self) -> Option<PackageStatuses>;
    /// `None` until the Agent has components to report.
    fn available_components(&self) -> Option<&AvailableComponents>;
}

/// What a reply leaves for the application, once the protocol has settled its own part.
#[derive(Debug, Default)]
pub struct Received<'a> {
    /// Something the Server must hear about now — the next report should not wait for the poll.
    pub report_now: bool,
    /// The Server is throttling (`UNAVAILABLE`): stay away this long first.
    pub retry_after: Option<Duration>,
    /// A command, which the specification says to act on alone: every other field of the message
    /// is to be ignored, and is.
    pub command: Option<i32>,
    /// The Server assigned a new identity, already adopted; the application persists it.
    pub new_uid: Option<InstanceUid>,
    /// The Server asked for the full components map; the application has it or not.
    pub components_requested: bool,
    pub remote_config: Option<&'a AgentRemoteConfig>,
    pub connection_settings: Option<&'a ConnectionSettingsOffers>,
    pub packages_available: Option<&'a PackagesAvailable>,
}

/// One Agent as the protocol sees it.
#[derive(Debug)]
pub struct AgentProtocol {
    uid: InstanceUid,
    sequence_num: u64,
    /// This Agent's declared Capability Set, carried in every report.
    capabilities: u64,
    /// The Server's declared Capability Set, once a reply carried it. Binding in both directions:
    /// what the Server cannot accept is not reported.
    server_capabilities: Option<u64>,
    /// The Server has sent a connection-settings offer at least once, and therefore takes the
    /// status for one whatever its bitmask says (ADR-0014 clause 13).
    settings_offered: bool,
    remote_config_status: Option<RemoteConfigStatus>,
    connection_settings_status: Option<ConnectionSettingsStatus>,
    /// A certificate signing request to send once (ADR-0021).
    pending_csr: Option<Vec<u8>>,
    // What the next report owes: a full snapshot, or each part that changed.
    send_full: bool,
    send_config_status: bool,
    send_health: bool,
    send_components_full: bool,
    send_settings_status: bool,
    send_package_status: bool,
}

impl AgentProtocol {
    /// An Agent under `uid`, declaring `capabilities`. Its first report is a full one: a Server
    /// that has never heard of it needs the whole snapshot.
    #[must_use]
    pub fn new(uid: InstanceUid, capabilities: u64) -> Self {
        AgentProtocol {
            uid,
            sequence_num: 0,
            capabilities,
            server_capabilities: None,
            settings_offered: false,
            remote_config_status: None,
            connection_settings_status: None,
            pending_csr: None,
            send_full: true,
            send_config_status: false,
            send_health: false,
            send_components_full: false,
            send_settings_status: false,
            send_package_status: false,
        }
    }

    #[must_use]
    pub fn uid(&self) -> InstanceUid {
        self.uid
    }

    /// Adds one capability to the declared set.
    pub fn declare(&mut self, capability: AgentCapabilities) {
        self.capabilities |= capability as u64;
    }

    /// Whether this Agent declares `capability`.
    #[must_use]
    pub fn declares(&self, capability: AgentCapabilities) -> bool {
        self.capabilities & capability as u64 != 0
    }

    /// The next report starts from a full snapshot — after (re)connecting, after a failed
    /// exchange, or when something only a full report carries changed.
    pub fn force_full(&mut self) {
        self.send_full = true;
    }

    /// The remote configuration's status, or what the effective configuration says, changed.
    pub fn set_remote_config_status(&mut self, status: RemoteConfigStatus) {
        self.remote_config_status = Some(status);
        self.send_config_status = true;
    }

    /// A status restored from an earlier run: reported with the next full report, not owed now.
    pub fn restore_remote_config_status(&mut self, status: RemoteConfigStatus) {
        self.remote_config_status = Some(status);
    }

    /// The effective configuration changed without the status changing.
    pub fn effective_config_changed(&mut self) {
        self.send_config_status = true;
    }

    pub fn health_changed(&mut self) {
        self.send_health = true;
    }

    pub fn package_status_changed(&mut self) {
        self.send_package_status = true;
    }

    /// The outcome of a connection-settings offer. With `owed`, the next report carries it; a
    /// status restored from an earlier run is not owed until the next full report.
    pub fn set_connection_settings_status(&mut self, status: ConnectionSettingsStatus, owed: bool) {
        self.connection_settings_status = Some(status);
        if owed {
            self.send_settings_status = true;
        }
    }

    #[must_use]
    pub fn connection_settings_status(&self) -> Option<&ConnectionSettingsStatus> {
        self.connection_settings_status.as_ref()
    }

    /// The full components map goes out with the next report.
    pub fn send_components_full(&mut self) {
        self.send_components_full = true;
    }

    /// Queues a certificate signing request for the next report (ADR-0021).
    pub fn request_certificate(&mut self, csr: Vec<u8>) {
        self.pending_csr = Some(csr);
    }

    /// Whether the Server has *declared* `capability`. Pessimistic, unlike the gates on what a
    /// report carries: exercising what a peer never declared is what the specification's
    /// negotiation rule forbids, so a request the Server may not take waits for its word.
    #[must_use]
    pub fn server_declared(&self, capability: ServerCapabilities) -> bool {
        self.server_capabilities
            .is_some_and(|caps| caps & capability as u64 != 0)
    }

    /// The next `AgentToServer`. Unchanged fields are omitted, as the specification recommends: a
    /// routine report carries only identity and sequence number; a full snapshot goes out when one
    /// was forced, and each status whenever it changed.
    pub fn next_report(&mut self, content: &impl ReportContent) -> AgentToServer {
        self.sequence_num += 1;
        let mut msg = AgentToServer {
            instance_uid: self.uid.as_bytes().to_vec(),
            sequence_num: self.sequence_num,
            capabilities: self.capabilities,
            ..Default::default()
        };
        if self.send_full {
            msg.agent_description = Some(content.description(&self.uid));
        }
        if self.send_full || self.send_health {
            msg.health = Some(content.health());
        }
        if self.send_full || self.send_config_status {
            // Deliberately **not** gated on `OffersRemoteConfig` (ADR-0014 clause 16), and this is a
            // decision rather than an oversight — do not "fix" it. That bit says the Server *can
            // offer* configuration; what licenses an inbound status report is `AcceptsStatus`, which
            // every Server MUST set, and no `AcceptsRemoteConfigStatus` exists. Gating here would
            // also be dangerous where it bit: `last_remote_config_hash` is the sole input to the
            // Server's re-offer decision, so a Server that stopped declaring the bit would silence
            // the hash and put the fleet in a permanent re-offer loop. And where it would not bite
            // it does nothing — the status is unset until a configuration has actually been offered.
            msg.remote_config_status = self.remote_config_status.clone();
            if self.server_accepts(ServerCapabilities::AcceptsEffectiveConfig) {
                msg.effective_config = Some(content.effective_config());
            }
        }
        if self.server_accepts_connection_settings_status()
            && (self.send_full || self.send_settings_status)
        {
            msg.connection_settings_status = self.connection_settings_status.clone();
        }
        if let Some(csr) = self.pending_csr.take() {
            msg.connection_settings_request = Some(crate::proto::ConnectionSettingsRequest {
                opamp: Some(crate::proto::OpAmpConnectionSettingsRequest {
                    certificate_request: Some(crate::proto::CertificateRequest { csr }),
                }),
            });
        }
        // A status suppressed here is *not* held for later: the dirty flag clears as usual, and the
        // report returns with the full snapshot that follows any reconnect or `ReportFullState`.
        // Holding the flag would deliver a stale status the moment the bit appeared.
        if self.server_accepts(ServerCapabilities::AcceptsPackagesStatus)
            && (self.send_full || self.send_package_status)
        {
            msg.package_statuses = content.package_statuses();
        }
        // Available components ride the specification's two-step shape: the hash in every full
        // snapshot, the full map only when the Server demanded it via ReportAvailableComponents.
        if let Some(components) = content.available_components() {
            if self.send_components_full {
                msg.available_components = Some(components.clone());
            } else if self.send_full {
                msg.available_components = Some(AvailableComponents {
                    components: Default::default(),
                    hash: components.hash.clone(),
                });
            }
        }
        self.send_full = false;
        self.send_config_status = false;
        self.send_health = false;
        self.send_components_full = false;
        self.send_settings_status = false;
        self.send_package_status = false;
        msg
    }

    /// A report carrying `csr` and nothing else but the Agent's identity, sequence number and
    /// capabilities — what an application sends where only a certificate signing request may pass,
    /// as through a gateway that relays an enrolment. What the next full report owes is left as it
    /// was, so the report after this one carries it.
    pub fn csr_report(&mut self, csr: Vec<u8>) -> AgentToServer {
        self.sequence_num += 1;
        AgentToServer {
            instance_uid: self.uid.as_bytes().to_vec(),
            sequence_num: self.sequence_num,
            capabilities: self.capabilities,
            connection_settings_request: Some(crate::proto::ConnectionSettingsRequest {
                opamp: Some(crate::proto::OpAmpConnectionSettingsRequest {
                    certificate_request: Some(crate::proto::CertificateRequest { csr }),
                }),
            }),
            ..Default::default()
        }
    }

    /// The final message of a connection: the specification requires `agent_disconnect` in it.
    pub fn disconnect_message(&mut self) -> AgentToServer {
        self.sequence_num += 1;
        AgentToServer {
            instance_uid: self.uid.as_bytes().to_vec(),
            sequence_num: self.sequence_num,
            capabilities: self.capabilities,
            agent_disconnect: Some(AgentDisconnect {}),
            ..Default::default()
        }
    }

    /// Settles one `ServerToAgent` for the protocol and returns what is left for the application.
    pub fn receive<'a>(&mut self, reply: &'a ServerToAgent) -> Received<'a> {
        let mut received = Received::default();

        if reply.capabilities != 0 {
            self.server_capabilities = Some(reply.capabilities);
        }

        // A command message carries only identity, capabilities, and the command — every other
        // field is to be ignored, so this returns before touching them.
        if let Some(command) = &reply.command {
            received.command = Some(command.r#type);
            return received;
        }

        if let Some(response) = &reply.error_response {
            error!(message = %response.error_message, "the server reported an error");
            if response.r#type == ServerErrorResponseType::Unavailable as i32 {
                let nanos = match &response.details {
                    Some(crate::proto::server_error_response::Details::RetryInfo(info)) => {
                        info.retry_after_nanoseconds
                    }
                    _ => 30_000_000_000, // no hint: be gentle and stay away half a minute
                };
                received.retry_after = Some(Duration::from_nanos(nanos));
            }
            return received;
        }

        // The Server may reassign the identity (AgentIdentification); it is used for all further
        // communication from here on.
        if let Some(identification) = &reply.agent_identification {
            match InstanceUid::from_wire(&identification.new_instance_uid) {
                Some(new_uid) => {
                    info!(old = %self.uid, new = %new_uid, "adopting a server-assigned identity");
                    self.uid = new_uid;
                    received.new_uid = Some(new_uid);
                }
                None => warn!("ignoring a malformed server-assigned instance_uid"),
            }
        }

        if reply.flags & ServerToAgentFlags::ReportFullState as u64 != 0 {
            self.send_full = true;
            received.report_now = true;
        }
        received.components_requested =
            reply.flags & ServerToAgentFlags::ReportAvailableComponents as u64 != 0;

        received.remote_config = reply.remote_config.as_ref();
        if let Some(offers) = &reply.connection_settings {
            // A Server that has sent an offer accepts the status for it, whatever its capability
            // bitmask says (ADR-0014 clause 13) — latched even for an offer the application cannot
            // act on, because a Server that offers and then learns nothing can never stop offering.
            self.settings_offered = true;
            received.connection_settings = Some(offers);
        }
        received.packages_available = reply.packages_available.as_ref();
        received
    }

    /// The specification's negotiation rule, in the direction an Agent owes it: optimistic until
    /// the Server has declared anything, binding once it has. A `capabilities` of zero is *"MAY be
    /// omitted in subsequent ServerToAgent messages"* — silence, not a retraction — so the last
    /// non-zero declaration is what `server_capabilities` holds.
    fn server_accepts(&self, capability: ServerCapabilities) -> bool {
        self.server_capabilities
            .map(|caps| caps & capability as u64 != 0)
            .unwrap_or(true)
    }

    /// A **received offer outranks the bitmask** (ADR-0014 clause 13). Gating on the capability alone
    /// would deadlock against Servers that offer without declaring it — including this project's
    /// own, which sets the bit from `[connection_offer]` and so omits it for a telemetry-only or
    /// `[client_ca]`-only configuration.
    fn server_accepts_connection_settings_status(&self) -> bool {
        self.settings_offered || self.server_accepts(ServerCapabilities::OffersConnectionSettings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{RemoteConfigStatuses, RetryInfo, ServerErrorResponse};

    /// The least content a report can hold, recording what the protocol asked for.
    #[derive(Default)]
    struct Content {
        components: Option<AvailableComponents>,
        packages: bool,
    }

    impl ReportContent for Content {
        fn description(&self, _: &InstanceUid) -> AgentDescription {
            AgentDescription::default()
        }
        fn health(&self) -> ComponentHealth {
            ComponentHealth {
                healthy: true,
                ..Default::default()
            }
        }
        fn effective_config(&self) -> EffectiveConfig {
            EffectiveConfig::default()
        }
        fn package_statuses(&self) -> Option<PackageStatuses> {
            self.packages.then(PackageStatuses::default)
        }
        fn available_components(&self) -> Option<&AvailableComponents> {
            self.components.as_ref()
        }
    }

    fn protocol() -> AgentProtocol {
        AgentProtocol::new(
            InstanceUid::default(),
            AgentCapabilities::ReportsStatus as u64,
        )
    }

    fn declaring(capabilities: u64) -> ServerToAgent {
        ServerToAgent {
            capabilities,
            ..Default::default()
        }
    }

    #[test]
    fn the_first_report_is_full_and_the_next_carries_only_identity() {
        let mut agent = protocol();
        let content = Content::default();
        let first = agent.next_report(&content);
        assert_eq!(first.sequence_num, 1);
        assert!(first.agent_description.is_some() && first.health.is_some());
        let second = agent.next_report(&content);
        assert_eq!(second.sequence_num, 2);
        assert_eq!(second.instance_uid, agent.uid().as_bytes());
        assert!(second.agent_description.is_none() && second.health.is_none());
    }

    #[test]
    fn a_csr_report_carries_the_request_alone_and_leaves_the_full_report_owed() {
        let mut agent = protocol();
        let content = Content::default();
        let report = agent.csr_report(b"csr".to_vec());
        assert_eq!(report.sequence_num, 1);
        assert_eq!(
            report,
            AgentToServer {
                instance_uid: agent.uid().as_bytes().to_vec(),
                sequence_num: 1,
                capabilities: AgentCapabilities::ReportsStatus as u64,
                connection_settings_request: Some(crate::proto::ConnectionSettingsRequest {
                    opamp: Some(crate::proto::OpAmpConnectionSettingsRequest {
                        certificate_request: Some(crate::proto::CertificateRequest {
                            csr: b"csr".to_vec()
                        }),
                    }),
                }),
                ..Default::default()
            }
        );
        let next = agent.next_report(&content);
        assert_eq!(next.sequence_num, 2);
        assert!(
            next.agent_description.is_some(),
            "the full report is still owed"
        );
    }

    #[test]
    fn report_full_state_forces_a_full_report_and_owes_it_now() {
        let mut agent = protocol();
        let content = Content::default();
        agent.next_report(&content);
        let reply = ServerToAgent {
            flags: ServerToAgentFlags::ReportFullState as u64,
            ..Default::default()
        };
        assert!(agent.receive(&reply).report_now);
        assert!(agent.next_report(&content).agent_description.is_some());
    }

    #[test]
    fn a_command_is_acted_on_alone() {
        let mut agent = protocol();
        let reply = ServerToAgent {
            command: Some(crate::proto::ServerToAgentCommand {
                r#type: crate::proto::CommandType::Restart as i32,
            }),
            flags: ServerToAgentFlags::ReportFullState as u64,
            remote_config: Some(AgentRemoteConfig::default()),
            ..Default::default()
        };
        let received = agent.receive(&reply);
        assert_eq!(
            received.command,
            Some(crate::proto::CommandType::Restart as i32)
        );
        assert!(!received.report_now && received.remote_config.is_none());
    }

    #[test]
    fn unavailable_yields_the_retry_hint_or_half_a_minute() {
        let mut agent = protocol();
        let unavailable = |details| ServerToAgent {
            error_response: Some(ServerErrorResponse {
                r#type: ServerErrorResponseType::Unavailable as i32,
                details,
                ..Default::default()
            }),
            ..Default::default()
        };
        let hinted = unavailable(Some(
            crate::proto::server_error_response::Details::RetryInfo(RetryInfo {
                retry_after_nanoseconds: 5_000_000_000,
            }),
        ));
        assert_eq!(
            agent.receive(&hinted).retry_after,
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            agent.receive(&unavailable(None)).retry_after,
            Some(Duration::from_secs(30))
        );
    }

    #[test]
    fn a_reassigned_identity_is_adopted_and_handed_over() {
        let mut agent = protocol();
        let new_uid = InstanceUid::default();
        let reply = ServerToAgent {
            agent_identification: Some(crate::proto::AgentIdentification {
                new_instance_uid: new_uid.as_bytes().to_vec(),
            }),
            ..Default::default()
        };
        assert_eq!(agent.receive(&reply).new_uid, Some(new_uid));
        assert_eq!(agent.uid(), new_uid);
        assert_eq!(
            agent.next_report(&Content::default()).instance_uid,
            new_uid.as_bytes()
        );
    }

    /// Optimistic until the Server speaks, binding once it has, and a later zero is silence.
    #[test]
    fn the_servers_capabilities_bind_what_a_report_carries() {
        let mut agent = protocol();
        let content = Content {
            packages: true,
            ..Default::default()
        };
        let before = agent.next_report(&content);
        assert!(before.effective_config.is_some() && before.package_statuses.is_some());

        agent.receive(&declaring(ServerCapabilities::AcceptsStatus as u64));
        agent.force_full();
        let after = agent.next_report(&content);
        assert!(after.effective_config.is_none() && after.package_statuses.is_none());
        assert!(
            after.remote_config_status.is_none(),
            "nothing to report yet"
        );

        agent.receive(&declaring(0));
        agent.force_full();
        assert!(
            agent.next_report(&content).effective_config.is_none(),
            "a zero is silence, not a retraction"
        );
    }

    #[test]
    fn a_remote_config_status_rides_whether_or_not_remote_config_is_offered() {
        let mut agent = protocol();
        agent.receive(&declaring(ServerCapabilities::AcceptsStatus as u64));
        agent.next_report(&Content::default());
        agent.set_remote_config_status(RemoteConfigStatus {
            status: RemoteConfigStatuses::Applied as i32,
            ..Default::default()
        });
        assert!(agent
            .next_report(&Content::default())
            .remote_config_status
            .is_some());
    }

    #[test]
    fn an_offer_arms_the_connection_settings_status_whatever_the_bitmask_says() {
        let mut agent = protocol();
        agent.receive(&declaring(ServerCapabilities::AcceptsStatus as u64));
        agent.set_connection_settings_status(ConnectionSettingsStatus::default(), true);
        assert!(agent
            .next_report(&Content::default())
            .connection_settings_status
            .is_none());

        let offer = ServerToAgent {
            connection_settings: Some(ConnectionSettingsOffers::default()),
            ..Default::default()
        };
        assert!(agent.receive(&offer).connection_settings.is_some());
        agent.set_connection_settings_status(ConnectionSettingsStatus::default(), true);
        assert!(agent
            .next_report(&Content::default())
            .connection_settings_status
            .is_some());
    }

    #[test]
    fn components_go_out_as_a_hash_until_the_server_asks_for_the_map() {
        let mut agent = protocol();
        let content = Content {
            components: Some(AvailableComponents {
                components: [("receiver".to_string(), Default::default())].into(),
                hash: b"h".to_vec(),
            }),
            ..Default::default()
        };
        let full = agent.next_report(&content);
        let carried = full.available_components.expect("the hash");
        assert!(carried.components.is_empty() && carried.hash == b"h");

        let ask = ServerToAgent {
            flags: ServerToAgentFlags::ReportAvailableComponents as u64,
            ..Default::default()
        };
        assert!(agent.receive(&ask).components_requested);
        agent.send_components_full();
        let map = agent
            .next_report(&content)
            .available_components
            .expect("map");
        assert_eq!(map.components.len(), 1);
    }

    #[test]
    fn a_certificate_request_goes_out_once_and_only_to_a_server_that_declared_signing() {
        let mut agent = protocol();
        assert!(!agent.server_declared(ServerCapabilities::AcceptsConnectionSettingsRequest));
        agent.receive(&declaring(
            ServerCapabilities::AcceptsConnectionSettingsRequest as u64,
        ));
        assert!(agent.server_declared(ServerCapabilities::AcceptsConnectionSettingsRequest));
        agent.request_certificate(b"csr".to_vec());
        assert!(agent
            .next_report(&Content::default())
            .connection_settings_request
            .is_some());
        assert!(agent
            .next_report(&Content::default())
            .connection_settings_request
            .is_none());
    }

    #[test]
    fn the_goodbye_carries_agent_disconnect_and_the_declared_set() {
        let mut agent = protocol();
        agent.declare(AgentCapabilities::ReportsHeartbeat);
        let goodbye = agent.disconnect_message();
        assert!(goodbye.agent_disconnect.is_some());
        assert!(agent.declares(AgentCapabilities::ReportsHeartbeat));
        assert_eq!(
            goodbye.capabilities,
            AgentCapabilities::ReportsStatus as u64 | AgentCapabilities::ReportsHeartbeat as u64
        );
    }
}
