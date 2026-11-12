//! Server-set labels on an Agent, and the effective description Selectors match (ADR-0024,
//! ADR-0035).
//!
//! The attribute a staged rollout wants — `rollout = "canary"` — is one an operator invents, and a
//! label lets the operator invent it on the Server. Invented in `supervisor.toml` on the machine,
//! moving a host between channels would be a file edit plus a restart *on that host*: the per-host
//! wiring ADR-0026 removes, surviving in the one place it matters most.
//!
//! A label joins the attribute set a Deployment's Selector matches against (ADR-0034), which
//! releases Configurations and packages alike. It never travels to the Agent: it is an input to
//! matching here, and the Agent experiences it only as the Configurations and the packages it is
//! offered. Labels are part of the Agent's record (ADR-0035 clause 6), and the labels of a
//! Client's own Agent hold for that Client's other Agents (clause 4).
//!
//! **A label can never restate a reported attribute.** `os.type` and `host.arch` decide which
//! artifact an Agent is offered (ADR-0026) and `service.name` decides which packages fit it at all
//! (ADR-0026), so a label that outranked them would let a typo hand a Windows binary to a Linux
//! host. Labels annotate; they do not correct. **And nothing an Agent reports or an operator
//! labels can speak in the Server's name**: `fleet.*` is the Server's own, filled from the Host's
//! certificate (ADR-0035 clauses 3 and 5).

use std::collections::{BTreeMap, BTreeSet};

use opamp::proto::AgentDescription;

/// The key prefix only the Server fills (ADR-0035 clause 5).
pub const RESERVED_PREFIX: &str = "fleet.";

/// The attribute prefix only a Client's own Agent reports (ADR-0017 clause 18), which recognises
/// it as the Client Agent (ADR-0035 clause 4).
pub const CLIENT_KIND_PREFIX: &str = "supervisor.kind.";

/// Why a label set was refused (`PUT /api/v1/agents/{uid}/labels`).
pub enum LabelError {
    /// No Agent of that identity is known. Labels are attached to something the Server has seen.
    UnknownAgent,
    /// A pair no Selector could use, or a key in the Server's reserved `fleet.` space.
    Invalid(String),
    /// A label key the Agent already reports. Refused rather than applied: a label that could
    /// override `os.type`, `host.arch`, or `service.name` would let a slip in the UI offer an
    /// Agent an artifact built for another machine (ADR-0026).
    RestatesReported(String),
    /// The Agent's record could not be written.
    Storage(String),
}

/// Whether a label set can be applied: an empty key or value can match no Selector and is far
/// more likely a mistake than an intent, and a `fleet.` key is the Server's own (ADR-0035
/// clause 5).
pub fn check_pairs(set: &BTreeMap<String, String>) -> Result<(), String> {
    for (key, value) in set {
        if key.trim().is_empty() {
            return Err("a label key cannot be empty".to_string());
        }
        if key.starts_with(RESERVED_PREFIX) {
            return Err(format!(
                "label {key:?} is in the Server's reserved {RESERVED_PREFIX:?} space — the Server \
                 fills those keys from the certificate of the Host an Agent arrives over; choose \
                 another key"
            ));
        }
        if value.trim().is_empty() {
            return Err(format!(
                "label {key:?} has an empty value — remove the key instead, or give it the value a \
                 Selector should match"
            ));
        }
    }
    Ok(())
}

/// The keys this Agent reports, which a label may not restate.
pub fn reported_keys(description: Option<&AgentDescription>) -> Vec<&str> {
    let Some(description) = description else {
        return Vec::new();
    };
    description
        .identifying_attributes
        .iter()
        .chain(&description.non_identifying_attributes)
        .map(|kv| kv.key.as_str())
        .collect()
}

/// What an Agent's effective description is built from (ADR-0035 clause 3), in order of
/// precedence: for each key the first source that has it.
#[derive(Clone, Copy)]
pub struct Sources<'a> {
    /// The `fleet.host.*` values of the Host the Agent arrived over directly; empty behind a
    /// Gateway and without `[client_ca]`.
    pub host: &'a BTreeMap<String, String>,
    /// What the Agent reported: identifying attributes, then non-identifying ones.
    pub reported: Option<&'a AgentDescription>,
    /// The Agent's own labels.
    pub own: &'a BTreeMap<String, String>,
    /// The labels of its Client Agent (ADR-0035 clause 4).
    pub inherited: &'a BTreeMap<String, String>,
}

impl Sources<'_> {
    /// Whether the effective description is exactly what the Agent reported — no Host value, no
    /// label, and no reported attribute left out. The overwhelming majority of Agents, so the
    /// fleet view borrows rather than builds for them.
    pub fn adds_nothing(&self) -> bool {
        self.host.is_empty()
            && self.own.is_empty()
            && self.inherited.is_empty()
            && !self.reported.is_some_and(|description| {
                description
                    .identifying_attributes
                    .iter()
                    .chain(&description.non_identifying_attributes)
                    .any(|kv| kv.key.starts_with(RESERVED_PREFIX))
            })
    }
}

/// The description a Selector is matched against (ADR-0035 clause 3): the Host's values, what the
/// Agent reported without its `fleet.*` attributes, its own labels and then its Client Agent's —
/// each key from the first source that has it.
///
/// Reported wins over every label. The API refuses a colliding key up front, so this is the second
/// line rather than the first — but it is the one that holds when an Agent *starts* reporting a
/// key that was labelled earlier, which no up-front check can prevent. A Host value wins over
/// everything: an Agent cannot claim another Host's subject values.
pub fn effective_description(sources: &Sources<'_>) -> Option<AgentDescription> {
    if sources.adds_nothing() {
        return sources.reported.cloned();
    }
    let reported = sources.reported.cloned().unwrap_or_default();
    let ours = |key: &str| key.starts_with(RESERVED_PREFIX);
    let mut effective = AgentDescription {
        identifying_attributes: reported
            .identifying_attributes
            .into_iter()
            .filter(|kv| !ours(&kv.key))
            .collect(),
        non_identifying_attributes: sources
            .host
            .iter()
            .map(|(key, value)| opamp::attributes::string_attr(key, value))
            .chain(
                reported
                    .non_identifying_attributes
                    .into_iter()
                    .filter(|kv| !ours(&kv.key)),
            )
            .collect(),
    };
    let mut taken: BTreeSet<String> = reported_keys(Some(&effective))
        .into_iter()
        .map(str::to_string)
        .collect();
    for (key, value) in sources.own.iter().chain(sources.inherited) {
        if ours(key) || !taken.insert(key.clone()) {
            continue;
        }
        effective
            .non_identifying_attributes
            .push(opamp::attributes::string_attr(key, value));
    }
    Some(effective)
}

/// The labels this Agent has that its own reports shadow — set, and matching nothing.
///
/// Surfaced on the fleet row rather than dropped in silence: doing what can be done and saying what
/// was not is what ADR-0014 does for connection settings.
pub fn shadowed(
    description: Option<&AgentDescription>,
    labels: &BTreeMap<String, String>,
) -> Vec<String> {
    let reported = reported_keys(description);
    labels
        .keys()
        .filter(|key| reported.iter().any(|r| r == key))
        .cloned()
        .collect()
}

/// The reported attributes left out of the effective description because their key is the
/// Server's own (ADR-0035 clause 5), in the order reported.
pub fn ignored(description: Option<&AgentDescription>) -> Vec<String> {
    reported_keys(description)
        .into_iter()
        .filter(|key| key.starts_with(RESERVED_PREFIX))
        .map(str::to_string)
        .collect()
}

/// Whether this is a Client's own Agent: it alone reports `supervisor.kind.*` (ADR-0017
/// clause 18, ADR-0035 clause 4).
pub fn is_client_agent(description: Option<&AgentDescription>) -> bool {
    description.is_some_and(|description| {
        description
            .non_identifying_attributes
            .iter()
            .any(|kv| kv.key.starts_with(CLIENT_KIND_PREFIX))
    })
}

/// The machine an Agent behind a Gateway says it runs on (ADR-0035 clause 4): its `host.id`, or
/// its `host.name` where it reports no `host.id`. Kept apart, so a `host.id` never equals a
/// `host.name` that happens to be spelled alike. `None` when it reports neither.
pub fn machine(description: Option<&AgentDescription>) -> Option<String> {
    let description = description?;
    let reported = |key: &str| {
        opamp::attributes::string_value(&description.identifying_attributes, key)
            .or_else(|| {
                opamp::attributes::string_value(&description.non_identifying_attributes, key)
            })
            .filter(|value| !value.is_empty())
    };
    reported("host.id")
        .map(|id| format!("host.id={id}"))
        .or_else(|| reported("host.name").map(|name| format!("host.name={name}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn described(pairs: &[(&str, &str)]) -> AgentDescription {
        AgentDescription {
            identifying_attributes: vec![opamp::attributes::string_attr("service.name", "otelcol")],
            non_identifying_attributes: pairs
                .iter()
                .map(|(k, v)| opamp::attributes::string_attr(k, v))
                .collect(),
        }
    }

    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    static NONE: BTreeMap<String, String> = BTreeMap::new();

    /// The description of an Agent that arrived over no Host and has no Client Agent: what it
    /// reported plus its own labels.
    fn with_labels(
        description: Option<&AgentDescription>,
        own: &BTreeMap<String, String>,
    ) -> Option<AgentDescription> {
        effective_description(&Sources {
            host: &NONE,
            reported: description,
            own,
            inherited: &NONE,
        })
    }

    /// The point of the decision: a label is matchable exactly like a reported attribute, so a
    /// Selector written for `rollout = canary` finds a host an operator moved into that channel.
    #[test]
    fn a_label_is_matched_like_a_reported_attribute() {
        let described = described(&[("os.type", "linux")]);
        let effective =
            with_labels(Some(&described), &labels(&[("rollout", "canary")])).expect("some");
        assert!(crate::deployments::matches(
            &labels(&[("rollout", "canary")]),
            Some(&effective)
        ));
        // And the reported ones still match, so a label adds reach rather than replacing it.
        assert!(crate::deployments::matches(
            &labels(&[("os.type", "linux")]),
            Some(&effective)
        ));
    }

    /// The crux (ADR-0024 point 18): reported wins. A label that could rewrite `os.type` would let a
    /// slip in the UI offer this Agent an artifact built for another machine.
    /// Verifies: ADR-0024
    #[test]
    fn a_label_never_overrides_what_the_agent_reports() {
        let described = described(&[("os.type", "linux")]);
        let effective =
            with_labels(Some(&described), &labels(&[("os.type", "windows")])).expect("some");
        assert!(
            crate::deployments::matches(&labels(&[("os.type", "linux")]), Some(&effective)),
            "the reported platform is what matches"
        );
        assert!(
            !crate::deployments::matches(&labels(&[("os.type", "windows")]), Some(&effective)),
            "and the label does not"
        );
        assert_eq!(
            shadowed(Some(&described), &labels(&[("os.type", "windows")])),
            ["os.type"],
            "the shadowed label is surfaced, not silently dropped"
        );
    }

    /// An Agent that has described itself with nothing can still be labelled — it is the operator's
    /// annotation, not a report.
    #[test]
    fn an_agent_that_reported_nothing_can_still_be_labelled() {
        let effective = with_labels(None, &labels(&[("rollout", "canary")])).expect("some");
        assert!(crate::deployments::matches(
            &labels(&[("rollout", "canary")]),
            Some(&effective)
        ));
    }

    /// An empty key or value is refused, and so is a key in the Server's `fleet.` space.
    /// Verifies: ADR-0035
    #[test]
    fn empty_keys_and_values_and_fleet_keys_are_refused() {
        assert!(check_pairs(&labels(&[("rollout", "canary")])).is_ok());
        assert!(check_pairs(&labels(&[("", "canary")])).is_err());
        assert!(check_pairs(&labels(&[("rollout", "  ")])).is_err());
        let refused = check_pairs(&labels(&[("fleet.x", "1")])).expect_err("reserved");
        assert!(refused.contains("fleet.x"), "{refused}");
        assert!(check_pairs(&labels(&[("fleetwide", "1")])).is_ok());
    }

    /// The Host's values come first, a reported `fleet.*` attribute is left out and listed, the
    /// Agent's own label wins over its Client Agent's, and a reported attribute wins over both.
    /// Verifies: ADR-0035
    #[test]
    fn the_effective_description_takes_each_key_from_the_first_source_that_has_it() {
        let reported = described(&[
            ("fleet.host.organization", "Mitbewerber AG"),
            ("os.type", "linux"),
        ]);
        let host = labels(&[("fleet.host.organization", "Kunde GmbH")]);
        let own = labels(&[("ring", "early")]);
        let inherited = labels(&[("ring", "late"), ("site", "wien"), ("os.type", "windows")]);
        let sources = Sources {
            host: &host,
            reported: Some(&reported),
            own: &own,
            inherited: &inherited,
        };
        let effective = effective_description(&sources).expect("some");
        let matches =
            |pairs: &[(&str, &str)]| crate::deployments::matches(&labels(pairs), Some(&effective));
        assert!(matches(&[("fleet.host.organization", "Kunde GmbH")]));
        assert!(!matches(&[("fleet.host.organization", "Mitbewerber AG")]));
        assert!(matches(&[("ring", "early")]), "its own label wins");
        assert!(
            matches(&[("site", "wien")]),
            "the Client Agent's label holds"
        );
        assert!(matches(&[("os.type", "linux")]), "reported wins over both");
        assert_eq!(ignored(Some(&reported)), ["fleet.host.organization"]);

        // Without a Host, a reported `fleet.*` attribute is still left out.
        let alone = effective_description(&Sources {
            host: &NONE,
            ..sources
        })
        .expect("some");
        assert!(!crate::deployments::matches(
            &labels(&[("fleet.host.organization", "Mitbewerber AG")]),
            Some(&alone)
        ));
    }

    /// The Client Agent is the one reporting `supervisor.kind.*`, and the machine behind a Gateway
    /// is its `host.id`, else its `host.name`.
    #[test]
    fn a_client_agent_and_its_machine_are_read_from_the_report() {
        let client = described(&[("supervisor.kind.collector", "true"), ("host.id", "m-1")]);
        let supervisor = described(&[("host.name", "edge-01")]);
        assert!(is_client_agent(Some(&client)));
        assert!(!is_client_agent(Some(&supervisor)));
        assert_eq!(machine(Some(&client)).as_deref(), Some("host.id=m-1"));
        assert_eq!(
            machine(Some(&supervisor)).as_deref(),
            Some("host.name=edge-01")
        );
        assert_eq!(machine(Some(&described(&[]))), None);
    }
}
