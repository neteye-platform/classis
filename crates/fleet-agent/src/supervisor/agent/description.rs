//! What an Agent reports about itself (ADR-0016): its configured attributes, the host's facts,
//! and the `service.*` attributes of a Managed Process's own description folded in (ADR-0055).

use opamp::attributes::{self, string_array_attr, string_attr};
use opamp::proto::{AgentDescription, KeyValue};
use opamp::uid::InstanceUid;
use tracing::warn;

use super::{AgentState, Local};

/// How much of a type a Managed Process reports reaches the warning about it (ADR-0055 clause 3):
/// enough for any reverse FQDN, and no more of what a process can make as long as it likes.
const LOGGED_TYPE_CHARS: usize = 128;

impl AgentState {
    /// The Managed Process reported its own description (through the Supervisor Endpoint or the
    /// version probe); fold its `service.*` attributes into ours — identity, type and where the
    /// Agent runs stay the Supervisor's (goal 16, ADR-0055).
    pub fn set_process_description(&mut self, description: AgentDescription) {
        let before = reported_types(self.local.process_description.as_ref());
        // Merged per attribute, not replaced wholesale: two sources describe the same process —
        // the version probe, which reports `service.version` and nothing else, and the
        // opampextension, which reports everything else — and whichever speaks second must not
        // erase what the first said. On the same key the later report wins, so a swapped binary's
        // probed version replaces the one it succeeded.
        let merged = self
            .local
            .process_description
            .get_or_insert_with(AgentDescription::default);
        for attr in &description.identifying_attributes {
            upsert_attr(&mut merged.identifying_attributes, attr);
        }
        for attr in &description.non_identifying_attributes {
            upsert_attr(&mut merged.non_identifying_attributes, attr);
        }
        // The type is the Supervisor's, and the fold drops the process's `service.name` (ADR-0055
        // clause 3). A value that differs is said once, when the process starts to report it, so
        // an operator whose Collector states a `dist.name` learns where to set it, and a report
        // repeated every few seconds does not flood the log. Only the merged report's values are
        // compared, so nothing grows however many values a process cycles through. The value is
        // the process's word, so the log carries it cut short and escaped, never as raw text
        // that could forge a line of its own.
        let after = reported_types(self.local.process_description.as_ref());
        for reported in after.iter().filter(|value| !before.contains(value)) {
            if *reported != self.local.service_name {
                let shown: String = reported.chars().take(LOGGED_TYPE_CHARS).collect();
                warn!(
                    supervisor = %self.local.instance_name,
                    reported = ?shown,
                    r#type = %self.local.service_name,
                    "the Managed Process reports another Agent type, which is ignored: the type \
                     is the Supervisor's; set the block key `service_name` to present the \
                     process's"
                );
            }
        }
        self.protocol.force_full();
    }

    /// Attaches the operator-defined attributes this Agent reports (ADR-0041 clause 2).
    #[must_use]
    pub fn with_attributes(
        mut self,
        attributes: std::collections::BTreeMap<String, String>,
    ) -> Self {
        self.local.configured_attributes = attributes.into_iter().collect();
        self
    }

    /// Attaches the deployment's `service.namespace`, reported by every Agent this Client presents.
    /// `None` — the default — reports nothing, which is what the Baseline's "if it is used in the
    /// environment" amounts to for a deployment that does not use one.
    #[must_use]
    pub fn with_namespace(mut self, namespace: Option<String>) -> Self {
        self.local.namespace = namespace;
        self
    }
}

impl Local {
    pub(super) fn describe(&self, uid: &InstanceUid) -> AgentDescription {
        // `service.name` is the Agent *type* — the Baseline's "reverse FQDN that uniquely
        // identifies the Agent type" (ADR-0055), and the Supervisor's alone: the fold below never
        // lets a Managed Process restate it. The instance name has its own key below.
        let mut identifying_attributes =
            vec![string_attr(attributes::SERVICE_NAME, &self.service_name)];
        // The Baseline lists `service.namespace` second, among what identifies the Agent — it says
        // *which* deployment this service belongs to, so it belongs beside the name rather than
        // among the tags an operator hangs on it.
        if let Some(namespace) = &self.namespace {
            identifying_attributes.push(string_attr(attributes::SERVICE_NAMESPACE, namespace));
        }
        // `service.version` is the *Agent's* version. The self-Agent is the Client, so its baked
        // version is the truth; a Supervisor-backed Agent stands for its Managed Process, whose
        // version only the process itself can report (folded in below, goal 16) — never invented
        // from the Client's.
        if !self.managed {
            identifying_attributes.push(string_attr(
                attributes::SERVICE_VERSION,
                fleet_core::version::current(),
            ));
        }
        identifying_attributes.push(string_attr(
            attributes::SERVICE_INSTANCE_ID,
            &uid.to_string(),
        ));
        // The rest of what the Baseline asks for "to describe where the Agent runs": `os.*` and
        // `host.*`. Every one of them is best effort, and what the platform cannot answer is left
        // out rather than filled in — an absent attribute says "unknown", where one carrying a
        // placeholder would say something false that a Selector could then match.
        let os = self.host.os();
        let mut non_identifying_attributes = vec![
            // The operator's name for this Agent (ADR-0016). Non-identifying because the Baseline
            // has no key for a human instance name and admits "any user-defined attributes the end
            // user would like to associate with this Agent" here; identity itself stays
            // `service.instance.id`. A Selector can match it, which is how ADR-0026's "pin one
            // host" is expressed for a machine running several Supervisors.
            string_attr(attributes::SERVICE_INSTANCE_NAME, &self.instance_name),
            string_attr(attributes::OS_TYPE, os_type()),
            string_attr(attributes::HOST_ARCH, host_arch()),
        ];
        for (key, value) in [
            ("os.name", os.name.as_deref()),
            ("os.version", os.version.as_deref()),
            ("os.build_id", os.build_id.as_deref()),
            (attributes::OS_DESCRIPTION, os.description.as_deref()),
            ("host.name", self.host.host_name()),
            ("host.id", self.host.host_id()),
            ("host.cpu.model.name", self.host.cpu_model()),
        ] {
            if let Some(value) = value {
                non_identifying_attributes.push(string_attr(key, value));
            }
        }
        // The host's network addresses — the conventions' `host.ip` and `host.mac` (ADR-0016),
        // both arrays and both "excluding loopback interfaces". Read live rather than once, so a
        // DHCP move is reported instead of the address the process happened to start with; a host
        // with nothing to say reports no attribute rather than an empty array.
        let (ips, macs) = self.host.addresses();
        for (key, values) in [("host.ip", ips), ("host.mac", macs)] {
            if !values.is_empty() {
                non_identifying_attributes.push(string_array_attr(key, &values));
            }
        }
        let mut description = AgentDescription {
            identifying_attributes,
            non_identifying_attributes,
        };
        // Operator-defined attributes (ADR-0041 clause 2) — added only where nothing is reported
        // under the same key, so what the code reports always wins. A key added here stands
        // against the Managed Process: the fold below leaves it alone.
        let mut operators_keys = Vec::new();
        for (key, value) in &self.configured_attributes {
            let taken = |list: &[KeyValue]| list.iter().any(|kv| kv.key == *key);
            if !taken(&description.identifying_attributes)
                && !taken(&description.non_identifying_attributes)
            {
                description
                    .non_identifying_attributes
                    .push(string_attr(key, value));
                operators_keys.push(key.as_str());
            }
        }
        // Fold in what the Managed Process reported about itself (ADR-0055 clause 2) — its
        // `service.*` attributes alone. A process is code the Supervisor does not vouch for, and
        // where the Agent runs (`host.*`, `os.*`) and what kind of Agent it is (`supervisor.*`)
        // decide which Selectors match and which artifact is offered; those stay the
        // Supervisor's statement, and every key outside `service.*` is dropped. Within it, the
        // Supervisor keeps the type (`service.name`, which decides which Configurations are
        // pinned to the Agent and which Deployment claims it), its identity
        // (`service.instance.id`, goal 16) and the operator's name (`service.instance.name`), and
        // the operator keeps every value they set: `service.namespace` where `service_namespace`
        // is set, and each `[attributes]` key added above. The process's `service.version` is the
        // Agent's version.
        //
        // The rule is by *key*, in both lists: the Server resolves a Selector against the
        // identifying attributes first and the non-identifying ones only after (`configs.rs`), so
        // an admitted key replaces the Supervisor's value in whichever list already holds it, and
        // is added to the list the process used only where the Supervisor states no such key. A
        // key is therefore reported once, and a Selector and the fleet row read the same value.
        if let Some(reported) = &self.process_description {
            let admitted = |key: &str| {
                key.starts_with(attributes::SERVICE_PREFIX)
                    && key != attributes::SERVICE_NAME
                    && key != attributes::SERVICE_INSTANCE_ID
                    && key != attributes::SERVICE_INSTANCE_NAME
                    && !(key == attributes::SERVICE_NAMESPACE && self.namespace.is_some())
                    && !operators_keys.contains(&key)
            };
            // Where a process states one key in both lists, its identifying statement is the one
            // folded and the other is dropped: the key is reported once, among the identifying
            // attributes the Server reads it from, with the identifying value.
            for attr in reported
                .identifying_attributes
                .iter()
                .filter(|attr| admitted(&attr.key))
            {
                fold_attr(&mut description, attr, true);
            }
            let stated_identifying = |key: &str| {
                reported
                    .identifying_attributes
                    .iter()
                    .any(|kv| kv.key == key)
            };
            for attr in reported
                .non_identifying_attributes
                .iter()
                .filter(|attr| admitted(&attr.key) && !stated_identifying(&attr.key))
            {
                fold_attr(&mut description, attr, false);
            }
        }
        description
    }
}

/// Lays one admitted attribute over the description: it replaces the value in whichever list
/// already holds its key, and only where neither does is it added to the list it was reported in.
fn fold_attr(description: &mut AgentDescription, attr: &KeyValue, identifying: bool) {
    let held = |list: &[KeyValue]| list.iter().any(|kv| kv.key == attr.key);
    let list = if held(&description.identifying_attributes) {
        &mut description.identifying_attributes
    } else if held(&description.non_identifying_attributes) || !identifying {
        &mut description.non_identifying_attributes
    } else {
        &mut description.identifying_attributes
    };
    upsert_attr(list, attr);
}

/// The `service.name` values a Managed Process's merged report carries, in either list — what
/// ADR-0055 clause 3 compares against the Supervisor's type. An empty string is no value.
fn reported_types(reported: Option<&AgentDescription>) -> Vec<String> {
    let mut types: Vec<String> = Vec::new();
    for list in reported.into_iter().flat_map(|reported| {
        [
            &reported.identifying_attributes,
            &reported.non_identifying_attributes,
        ]
    }) {
        if let Some(value) = attributes::string_value(list, attributes::SERVICE_NAME) {
            if !types.iter().any(|known| known == value) {
                types.push(value.to_string());
            }
        }
    }
    types
}

fn upsert_attr(attrs: &mut Vec<KeyValue>, attr: &KeyValue) {
    match attrs.iter_mut().find(|existing| existing.key == attr.key) {
        Some(existing) => existing.value = attr.value.clone(),
        None => attrs.push(attr.clone()),
    }
}

/// OpenTelemetry semantic-convention value for `os.type` (Rust says "macos", the convention
/// "darwin").
pub(super) fn os_type() -> &'static str {
    fleet_core::platform::canonical_os(std::env::consts::OS)
}

/// OpenTelemetry semantic-convention value for `host.arch` — the convention says `amd64`/`arm64`
/// where Rust's constant says `x86_64`/`aarch64` (ADR-0026).
///
/// The Baseline points at the conventions for these keys, and the Collector's `opampextension`
/// reports `runtime.GOARCH`, which is already this vocabulary. Reporting Rust's spelling instead
/// meant the *same host* changed architecture depending on whether a Collector was running on it:
/// a Managed Process's attributes are folded over the Supervisor's, so `amd64` overwrote `x86_64`
/// and any Selector written against one of them stopped matching.
fn host_arch() -> &'static str {
    fleet_core::platform::canonical_arch(std::env::consts::ARCH)
}
