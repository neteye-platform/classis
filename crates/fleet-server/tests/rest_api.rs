//! The REST API v1 as the integration contract (ADR-0023, ADR-0034): Configuration CRUD, the
//! Deployments that hold and release Configurations, loud rejection of invalid input, and the
//! OpenAPI document any portal generates a client from.

mod support;

use support::{deploy, save_configuration, spawn, AGENT_TYPE, FLEET_DEPLOYMENT};

fn url(addr: std::net::SocketAddr, path: &str) -> String {
    format!("http://{addr}{path}")
}

/// Verifies: G-5
#[tokio::test]
async fn configurations_crud_round_trips() {
    let server = spawn().await;
    let client = reqwest::Client::new();

    // Nothing yet.
    let list: serde_json::Value = client
        .get(url(server.rest_addr, "/api/v1/configurations"))
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("json");
    assert_eq!(list.as_array().expect("array").len(), 0);

    // Create; the stored resource comes back, body normalized to a trailing newline — content
    // only, held by no Deployment yet (ADR-0034).
    let put = client
        .put(url(server.rest_addr, "/api/v1/configurations/base"))
        .json(&serde_json::json!({ "body": "receivers: {}", "service_name": AGENT_TYPE }))
        .send()
        .await
        .expect("put");
    assert_eq!(put.status(), 200);
    let stored: serde_json::Value = put.json().await.expect("json");
    assert_eq!(stored["name"], "base");
    assert_eq!(stored["service_name"], AGENT_TYPE);
    assert!(stored.get("selector").is_none(), "no Selector: {stored}");
    assert_eq!(stored["deployments"], serde_json::json!([]));
    assert_eq!(stored["body"], "receivers: {}\n");
    assert!(
        stored.get("published").is_none() && stored.get("pending_changes").is_none(),
        "ADR-0025: content has one state — saved; rollout is a fact about Agents: {stored}"
    );

    // Read back, singly and as the list.
    let got: serde_json::Value = client
        .get(url(server.rest_addr, "/api/v1/configurations/base"))
        .send()
        .await
        .expect("get")
        .json()
        .await
        .expect("json");
    assert_eq!(got, stored);
    let list: serde_json::Value = client
        .get(url(server.rest_addr, "/api/v1/configurations"))
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("json");
    assert_eq!(list.as_array().expect("array").len(), 1);

    // Delete; a second delete and a read find nothing.
    let deleted = client
        .delete(url(server.rest_addr, "/api/v1/configurations/base"))
        .send()
        .await
        .expect("delete");
    assert_eq!(deleted.status(), 204);
    let again = client
        .delete(url(server.rest_addr, "/api/v1/configurations/base"))
        .send()
        .await
        .expect("delete again");
    assert_eq!(again.status(), 404);
    let gone = client
        .get(url(server.rest_addr, "/api/v1/configurations/base"))
        .send()
        .await
        .expect("get");
    assert_eq!(gone.status(), 404);
}

/// ADR-0023: `role` is optional on the way in and absent on the way out when unset, so every
/// stored Configuration and every generated client keeps working unchanged.
#[tokio::test]
async fn a_configuration_carries_an_optional_role() {
    let server = spawn().await;
    let client = reqwest::Client::new();

    // Omitted: accepted, and absent from the response.
    let stored: serde_json::Value = client
        .put(url(server.rest_addr, "/api/v1/configurations/base"))
        .json(&serde_json::json!({ "body": "receivers: {}", "service_name": AGENT_TYPE }))
        .send()
        .await
        .expect("put")
        .json()
        .await
        .expect("json");
    assert!(
        stored.get("role").is_none(),
        "an unset role stays out of the JSON: {stored}"
    );

    // Set: stored verbatim and returned.
    let stored: serde_json::Value = client
        .put(url(server.rest_addr, "/api/v1/configurations/ruleset"))
        .json(&serde_json::json!({
            "body": "rules: []",
            "role": "supplementary",
            "service_name": AGENT_TYPE
        }))
        .send()
        .await
        .expect("put")
        .json()
        .await
        .expect("json");
    assert_eq!(stored["role"], "supplementary");

    let got: serde_json::Value = client
        .get(url(server.rest_addr, "/api/v1/configurations/ruleset"))
        .send()
        .await
        .expect("get")
        .json()
        .await
        .expect("json");
    assert_eq!(got["role"], "supplementary");

    // A value this project has no word for is carried, not rejected — the vocabulary is
    // Agent-type-specific and the Server never guesses at one.
    let stored: serde_json::Value = client
        .put(url(server.rest_addr, "/api/v1/configurations/other"))
        .json(&serde_json::json!({
            "body": "x",
            "role": "some-agents-own-word",
            "service_name": AGENT_TYPE
        }))
        .send()
        .await
        .expect("put")
        .json()
        .await
        .expect("json");
    assert_eq!(stored["role"], "some-agents-own-word");
}

/// A Configuration has no Selector (ADR-0034 clauses 1 and 9): a `PUT` naming one is `400` and says the
/// Deployment is where to aim, and the Configuration's own rollout route is gone (`404`).
/// Verifies: ADR-0034
#[tokio::test]
async fn a_configuration_takes_no_selector_and_has_no_rollout_of_its_own() {
    let server = spawn().await;
    let client = reqwest::Client::new();
    let refused = client
        .put(url(server.rest_addr, "/api/v1/configurations/base"))
        .json(&serde_json::json!({
            "selector": { "os.type": "linux" },
            "body": "receivers: {}",
            "service_name": AGENT_TYPE
        }))
        .send()
        .await
        .expect("put");
    assert_eq!(refused.status(), 400);
    let error: serde_json::Value = refused.json().await.expect("an error body");
    assert!(
        error["error"]
            .as_str()
            .is_some_and(|why| why.contains("selector") && why.contains("Deployment")),
        "the refusal names where to aim: {error}"
    );
    let gone = client
        .get(url(server.rest_addr, "/api/v1/configurations/base"))
        .send()
        .await
        .expect("get");
    assert_eq!(gone.status(), 404, "nothing was stored");

    save_configuration(server.rest_addr, "base", "receivers: {}", "").await;
    let rollout = client
        .post(url(server.rest_addr, "/api/v1/configurations/base/rollout"))
        .send()
        .await
        .expect("rollout");
    assert_eq!(
        rollout.status(),
        404,
        "a Configuration is rolled out only through a Deployment"
    );
}

/// ADR-0025 and ADR-0034 over the wire: saving proposes, the Deployment's rollout act
/// distributes — for the channel or per Agent — and a later edit waits as `update` until the next
/// act pins it.
/// Verifies: ADR-0034
#[tokio::test]
async fn a_configuration_waits_until_it_is_rolled_out() {
    let server = spawn().await;
    let client = reqwest::Client::new();
    let uid = opamp::uid::InstanceUid::default();
    report(&client, server.addr, &support::full_report(&uid, "host", 1)).await;

    // Saved and put into the Deployment that claims the Agent: a visible candidate, assigned to
    // nobody.
    save_configuration(server.rest_addr, "fleet", "receivers: {}", "").await;
    let put = client
        .put(url(server.rest_addr, "/api/v1/deployments/fleet"))
        .json(&serde_json::json!({ "selector": { "service.name": AGENT_TYPE } }))
        .send()
        .await
        .expect("put the deployment");
    assert_eq!(put.status(), 200);
    let held: serde_json::Value = client
        .put(url(
            server.rest_addr,
            "/api/v1/deployments/fleet/configurations/fleet",
        ))
        .send()
        .await
        .expect("hold")
        .json()
        .await
        .expect("json");
    assert_eq!(held["configurations"], serde_json::json!(["fleet"]));
    assert_eq!(held["targeted_agents"], 1);
    let view = agent_view(&client, server.rest_addr, &uid).await;
    assert_eq!(view["matched_configurations"][0], "fleet", "a candidate");
    assert!(
        view["assigned_configurations"]
            .as_array()
            .expect("array")
            .is_empty(),
        "saving distributes nothing: {view}"
    );
    assert_eq!(view["pending_configurations"][0]["name"], "fleet");
    assert_eq!(view["pending_configurations"][0]["change"], "new");
    let config: serde_json::Value = client
        .get(url(server.rest_addr, "/api/v1/configurations/fleet"))
        .send()
        .await
        .expect("get")
        .json()
        .await
        .expect("json");
    assert_eq!(config["deployments"], serde_json::json!(["fleet"]));

    // The Deployment's act: released to every Agent it claims.
    let rollout: serde_json::Value = client
        .post(url(server.rest_addr, "/api/v1/deployments/fleet/rollout"))
        .send()
        .await
        .expect("rollout")
        .json()
        .await
        .expect("json");
    assert_eq!(rollout["assigned_agents"], 1);
    let view = agent_view(&client, server.rest_addr, &uid).await;
    assert_eq!(view["assigned_configurations"][0], "fleet");
    assert_eq!(view["assigned_deployment"], "fleet");
    assert!(view["pending_configurations"]
        .as_array()
        .expect("array")
        .is_empty());

    // Edited: the Agent keeps its pinned revision; the edit waits as an update.
    let put = client
        .put(url(server.rest_addr, "/api/v1/configurations/fleet"))
        .json(&serde_json::json!({
            "body": "receivers: {}\nexporters: {}",
            "service_name": AGENT_TYPE
        }))
        .send()
        .await
        .expect("edit");
    assert_eq!(put.status(), 200);
    let view = agent_view(&client, server.rest_addr, &uid).await;
    assert_eq!(
        view["pending_configurations"][0]["change"], "update",
        "the edit is saved, waiting, not in force: {view}"
    );

    // The per-Agent act releases the edit to this one Agent, naming its Deployment.
    let per_agent = client
        .post(url(
            server.rest_addr,
            &format!("/api/v1/agents/{uid}/rollout"),
        ))
        .json(&serde_json::json!({ "deployment": "fleet" }))
        .send()
        .await
        .expect("rollout to agent");
    assert_eq!(per_agent.status(), 200);
    let view: serde_json::Value = per_agent.json().await.expect("json");
    assert!(view["pending_configurations"]
        .as_array()
        .expect("array")
        .is_empty());

    // Naming another Deployment is a conflict, and a bare Configuration cannot be named at all.
    let other = client
        .post(url(
            server.rest_addr,
            &format!("/api/v1/agents/{uid}/rollout"),
        ))
        .json(&serde_json::json!({ "deployment": "missing" }))
        .send()
        .await
        .expect("rollout another to agent");
    assert_eq!(other.status(), 409);
    let named = client
        .post(url(
            server.rest_addr,
            &format!("/api/v1/agents/{uid}/rollout"),
        ))
        .json(&serde_json::json!({ "configuration": "fleet" }))
        .send()
        .await
        .expect("rollout a configuration to agent");
    assert!(
        named.status().is_client_error() && named.status() != 404,
        "a configuration is not a field of the act: {}",
        named.status()
    );
    // A Deployment the Server does not hold is 404, never a silent create.
    let missing = client
        .post(url(server.rest_addr, "/api/v1/deployments/missing/rollout"))
        .send()
        .await
        .expect("rollout missing");
    assert_eq!(missing.status(), 404);
}

/// ADR-0025 point 6: an Agent that appears after the rollout act waits — it surfaces as pending
/// and receives nothing until an act of its own. The Deployment's act must be repeated (or the
/// per-Agent one pressed) for latecomers.
#[tokio::test]
async fn an_agent_that_appears_later_waits() {
    let server = spawn().await;
    let client = reqwest::Client::new();
    let early = opamp::uid::InstanceUid::default();
    report(
        &client,
        server.addr,
        &support::full_report(&early, "early", 1),
    )
    .await;
    save_configuration(server.rest_addr, "fleet", "receivers: {}", "").await;
    deploy(
        server.rest_addr,
        FLEET_DEPLOYMENT,
        &[("service.name", AGENT_TYPE)],
        &["fleet"],
    )
    .await;
    assert_eq!(
        agent_view(&client, server.rest_addr, &early).await["assigned_configurations"][0],
        "fleet"
    );

    // The latecomer enrols: a candidate, pending, assigned nothing.
    let late = opamp::uid::InstanceUid::default();
    report(
        &client,
        server.addr,
        &support::full_report(&late, "late", 1),
    )
    .await;
    let view = agent_view(&client, server.rest_addr, &late).await;
    assert!(
        view["assigned_configurations"]
            .as_array()
            .expect("array")
            .is_empty(),
        "enrolment distributes nothing: {view}"
    );
    assert_eq!(view["pending_configurations"][0]["change"], "new");

    // Its own act — the empty body releases the Deployment that claims it.
    let rolled = client
        .post(url(
            server.rest_addr,
            &format!("/api/v1/agents/{late}/rollout"),
        ))
        .send()
        .await
        .expect("rollout to agent");
    assert_eq!(rolled.status(), 200);
    let view: serde_json::Value = rolled.json().await.expect("json");
    assert_eq!(view["assigned_configurations"][0], "fleet");
}

/// ADR-0034 clause 3 over the wire: of the Configurations a Deployment holds, one stating an
/// Agent type reaches only Agents reporting that `service.name`.
/// Verifies: ADR-0034
#[tokio::test]
async fn a_typed_configuration_reaches_only_agents_of_its_type() {
    let server = spawn().await;
    let client = reqwest::Client::new();
    let uid = opamp::uid::InstanceUid::default();
    report(&client, server.addr, &support::full_report(&uid, "host", 1)).await;

    for (name, service_name) in [
        ("for-collectors", support::AGENT_TYPE),
        ("for-clients", "supervisor"),
    ] {
        let put = client
            .put(url(
                server.rest_addr,
                &format!("/api/v1/configurations/{name}"),
            ))
            .json(&serde_json::json!({ "body": "x", "service_name": service_name }))
            .send()
            .await
            .expect("put");
        assert_eq!(put.status(), 200);
    }
    deploy(
        server.rest_addr,
        FLEET_DEPLOYMENT,
        &[("service.name", AGENT_TYPE)],
        &["for-collectors", "for-clients"],
    )
    .await;

    assert_eq!(
        matched_configurations(&client, server.rest_addr, &uid).await,
        ["for-collectors"],
        "the type is a fit, not an aim: the other type's Configuration is no candidate"
    );
    assert_eq!(
        agent_view(&client, server.rest_addr, &uid).await["assigned_configurations"],
        serde_json::json!(["for-collectors"]),
        "the press released only what fits"
    );
}

/// Nothing an assignment pins can be deleted (ADR-0034 clause 8): a pinned Configuration and a
/// pinned Deployment answer `409` saying how many Agents pin them. After a press without the
/// Configuration it is deleted, and it leaves every Deployment that held it.
/// Verifies: ADR-0034
#[tokio::test]
async fn a_pinned_configuration_or_deployment_is_not_deleted() {
    let server = spawn().await;
    let client = reqwest::Client::new();
    let uid = opamp::uid::InstanceUid::default();
    report(&client, server.addr, &support::full_report(&uid, "host", 1)).await;
    save_configuration(server.rest_addr, "base", "receivers: {}", "").await;
    save_configuration(server.rest_addr, "extra", "exporters: {}", "").await;
    deploy(
        server.rest_addr,
        FLEET_DEPLOYMENT,
        &[("service.name", AGENT_TYPE)],
        &["base", "extra"],
    )
    .await;
    // A second Deployment holds `extra` too, and claims nobody.
    deploy(
        server.rest_addr,
        "canary",
        &[("channel", "canary")],
        &["extra"],
    )
    .await;

    for path in ["/api/v1/configurations/extra", "/api/v1/deployments/fleet"] {
        let refused = client
            .delete(url(server.rest_addr, path))
            .send()
            .await
            .expect("delete");
        assert_eq!(refused.status(), 409, "{path}");
        let error: serde_json::Value = refused.json().await.expect("an error body");
        assert!(
            error["error"]
                .as_str()
                .is_some_and(|why| why.contains("1 Agent")),
            "{path}: {error}"
        );
    }

    let dropped = client
        .delete(url(
            server.rest_addr,
            "/api/v1/deployments/fleet/configurations/extra",
        ))
        .send()
        .await
        .expect("drop");
    assert_eq!(
        dropped.status(),
        200,
        "nothing a Deployment holds is frozen"
    );
    deploy(
        server.rest_addr,
        FLEET_DEPLOYMENT,
        &[("service.name", AGENT_TYPE)],
        &[],
    )
    .await;
    let deleted = client
        .delete(url(server.rest_addr, "/api/v1/configurations/extra"))
        .send()
        .await
        .expect("delete");
    assert_eq!(deleted.status(), 204);
    let canary: serde_json::Value = client
        .get(url(server.rest_addr, "/api/v1/deployments/canary"))
        .send()
        .await
        .expect("get")
        .json()
        .await
        .expect("json");
    assert_eq!(canary["configurations"], serde_json::json!([]));
}

/// The per-Agent act on an Agent no Deployment claims, or two claim, is `409` (ADR-0034 clause 6).
/// Verifies: ADR-0034
#[tokio::test]
async fn the_per_agent_act_without_one_claiming_deployment_is_a_conflict() {
    let server = spawn().await;
    let client = reqwest::Client::new();
    let uid = opamp::uid::InstanceUid::default();
    report(&client, server.addr, &support::full_report(&uid, "host", 1)).await;
    let press = || {
        client
            .post(url(
                server.rest_addr,
                &format!("/api/v1/agents/{uid}/rollout"),
            ))
            .send()
    };
    let refused = press().await.expect("rollout");
    assert_eq!(refused.status(), 409, "in no deployment");

    save_configuration(server.rest_addr, "base", "receivers: {}", "").await;
    deploy(
        server.rest_addr,
        FLEET_DEPLOYMENT,
        &[("service.name", AGENT_TYPE)],
        &["base"],
    )
    .await;
    deploy(
        server.rest_addr,
        "hosts",
        &[("service.instance.name", "host")],
        &["base"],
    )
    .await;
    let refused = press().await.expect("rollout");
    assert_eq!(refused.status(), 409, "in conflict");
    let view = agent_view(&client, server.rest_addr, &uid).await;
    assert!(
        view["package_conflict"]
            .as_str()
            .is_some_and(|why| why.contains("hosts") && why.contains(FLEET_DEPLOYMENT)),
        "the view says why: {view}"
    );
}

#[tokio::test]
async fn invalid_configurations_are_rejected_loudly() {
    let server = spawn().await;
    let client = reqwest::Client::new();

    for (name, body) in [
        ("Bad Name", "x: 1"), // grammar violation
        ("con", "x: 1"),      // Windows reserved device name
        ("ok-name", "   \n"), // empty body
    ] {
        let response = client
            .put(url(
                server.rest_addr,
                &format!("/api/v1/configurations/{}", urlencoding(name)),
            ))
            .json(&serde_json::json!({ "body": body, "service_name": AGENT_TYPE }))
            .send()
            .await
            .expect("put");
        assert_eq!(response.status(), 400, "{name:?} must be rejected");
        let error: serde_json::Value = response.json().await.expect("an error body");
        assert!(error["error"].is_string());
    }
}

/// A Configuration is written for one Agent type (ADR-0034 clause 1): a `PUT` without
/// `service_name`, or with an empty one, is `400` naming the field, and nothing is stored.
/// Verifies: ADR-0034
#[tokio::test]
async fn a_configuration_without_an_agent_type_is_refused() {
    let server = spawn().await;
    let client = reqwest::Client::new();
    for spec in [
        serde_json::json!({ "body": "receivers: {}" }),
        serde_json::json!({ "body": "receivers: {}", "service_name": "" }),
    ] {
        let response = client
            .put(url(server.rest_addr, "/api/v1/configurations/base"))
            .json(&spec)
            .send()
            .await
            .expect("put");
        assert_eq!(response.status(), 400, "{spec}");
        let error: serde_json::Value = response.json().await.expect("an error body");
        assert!(
            error["error"]
                .as_str()
                .is_some_and(|why| why.contains("service_name")),
            "the refusal names the field: {error}"
        );
    }
    let gone = client
        .get(url(server.rest_addr, "/api/v1/configurations/base"))
        .send()
        .await
        .expect("get");
    assert_eq!(gone.status(), 404, "nothing was stored");

    let document: serde_json::Value = client
        .get(url(server.rest_addr, "/api/v1/openapi.json"))
        .send()
        .await
        .expect("get the document")
        .json()
        .await
        .expect("json");
    for schema in ["ConfigurationSpec", "ConfigurationView"] {
        assert!(
            document["components"]["schemas"][schema]["required"]
                .as_array()
                .is_some_and(|required| required.iter().any(|f| f == "service_name")),
            "the document marks service_name required in {schema}"
        );
    }
}

fn urlencoding(s: &str) -> String {
    s.replace(' ', "%20")
}

/// Verifies: ADR-0023, ADR-0026, ADR-0033, ADR-0034, G-5
#[tokio::test]
async fn the_openapi_document_describes_the_contract() {
    let server = spawn().await;
    let response = reqwest::Client::new()
        .get(url(server.rest_addr, "/api/v1/openapi.json"))
        .send()
        .await
        .expect("get");
    assert_eq!(response.status(), 200);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
    let document: serde_json::Value = response.json().await.expect("json");
    let paths = document["paths"].as_object().expect("paths");
    assert!(paths.contains_key("/api/v1/agents"));
    // OpenAPI 3.1 requires a description on every response, and a generator may refuse a
    // document without one; utoipa writes none for a response that does not state it (ADR-0023).
    let silent: Vec<String> = paths
        .iter()
        .flat_map(|(path, operations)| {
            operations
                .as_object()
                .into_iter()
                .flatten()
                .flat_map(move |(method, operation)| {
                    operation["responses"]
                        .as_object()
                        .into_iter()
                        .flatten()
                        .filter(|(_, response)| {
                            response["description"].as_str().unwrap_or("").is_empty()
                        })
                        .map(move |(status, _)| format!("{method} {path} {status}"))
                })
        })
        .collect();
    assert!(
        silent.is_empty(),
        "responses without a description: {silent:?}"
    );
    // Deployments and entry signatures are part of the contract (ADR-0026, ADR-0033) — a portal
    // generates against this document, and a route it cannot see is a route it cannot call.
    for route in [
        "/api/v1/deployments",
        "/api/v1/deployments/{name}",
        "/api/v1/deployments/{name}/selector",
        "/api/v1/deployments/{name}/packages/{agent_type}/{version}",
        "/api/v1/packages/{agent_type}/{version}/entries/{os}/{arch}/signature",
    ] {
        assert!(paths.contains_key(route), "{route} is described");
    }
    // A signature lives on the entry, and every artifact is uploaded (ADR-0033 clause 9): the
    // Deployment signature routes and the entry's source route are not in the contract.
    for gone in [
        "/api/v1/deployments/{name}/signatures/{agent_type}/{version}/{os}/{arch}",
        "/api/v1/packages/{agent_type}/{version}/entries/{os}/{arch}/source",
    ] {
        assert!(!paths.contains_key(gone), "{gone} is still described");
    }
    // And the retired package paths are gone rather than lingering as a promise (ADR-0026).
    assert!(
        !paths
            .keys()
            .any(|path| path.starts_with("/api/v1/packages/{name}/")),
        "no package route still carries a name segment: {:?}",
        paths.keys().collect::<Vec<_>>()
    );
    // Forgetting an Agent is part of the contract a portal generates against (ADR-0024), and the
    // description is where the "reaches no host" caveat has to be readable.
    let forget = &paths["/api/v1/agents/{instance_uid}"]["delete"];
    assert!(forget.is_object(), "DELETE on an Agent is described");
    assert!(
        forget["description"]
            .as_str()
            .expect("description")
            .contains("Nothing happens on the host"),
        "the description says what it does not do"
    );
    assert!(paths.contains_key("/api/v1/configurations"));
    assert!(paths.contains_key("/api/v1/configurations/{name}"));
    assert!(
        paths.contains_key("/api/v1/deployments/{name}/configurations/{configuration}"),
        "a Deployment holds Configurations (ADR-0034)"
    );
    assert!(
        !paths.contains_key("/api/v1/configurations/{name}/rollout"),
        "a Configuration is rolled out only through a Deployment (ADR-0034)"
    );
    assert!(paths.contains_key("/api/v1/deployments/{name}/rollout"));
    assert!(paths.contains_key("/api/v1/agents/{instance_uid}/rollout"));
    assert!(
        !paths.contains_key("/api/v1/configurations/{name}/publication"),
        "publication left the contract with ADR-0025"
    );
    // The resource schemas ride along, so a client can be generated without the source.
    assert!(document["components"]["schemas"]["ConfigurationView"].is_object());
    assert!(document["components"]["schemas"]["ConfigurationSpec"].is_object());
    assert!(
        document["components"]["schemas"]["ConfigurationSpec"]["properties"]
            .get("selector")
            .is_none(),
        "a Configuration takes no Selector (ADR-0034)"
    );
    assert!(document["components"]["schemas"]["AgentView"].is_object());
}

#[tokio::test]
async fn the_docs_page_and_its_vendored_renderer_are_served_same_origin() {
    let server = spawn().await;
    let client = reqwest::Client::new();

    // The docs page renders the OpenAPI document and pulls its renderer from this same origin.
    let page = client
        .get(url(server.rest_addr, "/api/v1/docs"))
        .send()
        .await
        .expect("get docs");
    assert_eq!(page.status(), 200);
    assert!(page
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("text/html")));
    let html = page.text().await.expect("html");
    assert!(
        html.contains("spec-url=\"/api/v1/openapi.json\""),
        "points at the document"
    );
    assert!(
        html.contains("/api/v1/docs/redoc.js"),
        "loads the vendored renderer"
    );

    // The vendored bundle is served as JavaScript — no CDN, so the docs work offline.
    let js = client
        .get(url(server.rest_addr, "/api/v1/docs/redoc.js"))
        .send()
        .await
        .expect("get renderer");
    assert_eq!(js.status(), 200);
    assert!(js
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.contains("javascript")));
    assert!(
        js.text().await.expect("js").len() > 100_000,
        "the real bundle, not a stub"
    );
}

#[tokio::test]
async fn configurations_survive_a_server_restart() {
    // The store is the persistence: a new AppState over the same directory restores everything.
    let dir = tempfile::tempdir().expect("tempdir");
    let store_dir = dir.path().join("fleet-configs");
    {
        let state = fleet_server::fleet::AppState::new(store_dir.clone()).expect("open");
        state
            .save_configuration(
                "keeper",
                fleet_server::configs::Revision {
                    body: "receivers: {}\n".to_string(),
                    role: String::new(),
                    service_name: AGENT_TYPE.to_string(),
                },
            )
            .expect("put");
    }
    let reopened = fleet_server::fleet::AppState::new(store_dir).expect("reopen");
    let restored = reopened.configurations().list();
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].name, "keeper");
    assert_eq!(restored[0].saved.body, "receivers: {}\n");
}

/// ADR-0024. The gate, over the wire: an Agent that just reported is doing its job, and forgetting
/// it would have its configuration offered again — which restarts a Managed Process.
#[tokio::test]
async fn forgetting_an_agent_that_is_still_reporting_is_refused() {
    let server = spawn().await;
    let client = reqwest::Client::new();
    let uid = opamp::uid::InstanceUid::default();
    report(&client, server.addr, &support::full_report(&uid, "live", 1)).await;

    let refused = client
        .delete(url(server.rest_addr, &format!("/api/v1/agents/{uid}")))
        .send()
        .await
        .expect("delete");
    assert_eq!(refused.status(), 409);
    let body: serde_json::Value = refused.json().await.expect("json");
    assert!(
        body["error"]
            .as_str()
            .expect("message")
            .contains("still reporting"),
        "the refusal says why: {body}"
    );
    assert_eq!(
        agents(&client, server.rest_addr).await.len(),
        1,
        "the row stays"
    );
}

/// ADR-0024, points 11 and 11: forgetting drops the record and reaches no host, so a Client that is
/// still running simply comes back — and the Server, which now knows nothing about it, asks for
/// full state exactly as it does for any Agent it has never seen.
// Verifies: ADR-0024
#[tokio::test]
async fn a_silent_agent_is_forgotten_and_returns_as_a_stranger() {
    // A zero budget makes the Agent silent the moment the clock ticks past its last report; the
    // rule under test is the comparison, not the duration.
    let server = support::spawn_with_stale_after(std::time::Duration::ZERO).await;
    let client = reqwest::Client::new();
    let uid = opamp::uid::InstanceUid::default();
    report(&client, server.addr, &support::full_report(&uid, "gone", 1)).await;
    assert_eq!(agents(&client, server.rest_addr).await.len(), 1);
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let forgotten = client
        .delete(url(server.rest_addr, &format!("/api/v1/agents/{uid}")))
        .send()
        .await
        .expect("delete");
    assert_eq!(forgotten.status(), 204);
    assert!(
        agents(&client, server.rest_addr).await.is_empty(),
        "the row is gone"
    );

    // Nothing happened on the host, so the Client reports again — and is a stranger.
    let reply = report(&client, server.addr, &support::compressed_report(&uid, 2)).await;
    assert_ne!(
        reply.flags & opamp::proto::ServerToAgentFlags::ReportFullState as u64,
        0,
        "an Agent the Server does not know is asked for full state"
    );
    assert_eq!(
        agents(&client, server.rest_addr).await.len(),
        1,
        "and it is back"
    );
}

/// The two ways to ask for something that is not there. `404` rather than a silent `204`: the
/// restart endpoint answers the same condition the same way, and an operator who mistypes a UID
/// should be told, not thanked.
#[tokio::test]
async fn forgetting_what_is_not_there_is_reported() {
    let server = spawn().await;
    let client = reqwest::Client::new();

    let unknown = client
        .delete(url(
            server.rest_addr,
            &format!("/api/v1/agents/{}", opamp::uid::InstanceUid::default()),
        ))
        .send()
        .await
        .expect("delete");
    assert_eq!(unknown.status(), 404);

    let malformed = client
        .delete(url(server.rest_addr, "/api/v1/agents/not-a-uid"))
        .send()
        .await
        .expect("delete");
    assert_eq!(malformed.status(), 400);
}

/// The body-less `POST` routes (`restart`, `rollback`) are CORS "simple requests": a cross-origin
/// page can fire them without a preflight. Fetch Metadata refuses the cross-site ones — a browser
/// stamps `Sec-Fetch-Site` and cannot let a page forge it — while same-origin and non-browser
/// callers pass. The guard runs before the handler, so it decides regardless of the target.
/// Verifies: ADR-0021
#[tokio::test]
async fn a_cross_site_state_changing_post_is_refused() {
    let server = spawn().await;
    let client = reqwest::Client::new();
    let uid = opamp::uid::InstanceUid::default();

    // A browser marks a cross-site request: refused with 403, whether or not the Agent exists.
    let cross = client
        .post(url(
            server.rest_addr,
            &format!("/api/v1/agents/{uid}/restart"),
        ))
        .header("sec-fetch-site", "cross-site")
        .send()
        .await
        .expect("restart");
    assert_eq!(cross.status(), 403, "a cross-site restart is refused");

    // The same-site case from the bundled UI passes the guard — the request reaches the handler,
    // which then answers 404 for an Agent that is not there. The point is it is *not* 403.
    let same_origin = client
        .post(url(
            server.rest_addr,
            &format!("/api/v1/agents/{uid}/restart"),
        ))
        .header("sec-fetch-site", "same-origin")
        .send()
        .await
        .expect("restart");
    assert_ne!(
        same_origin.status(),
        403,
        "a same-origin restart is not a CSRF"
    );
    assert_eq!(
        same_origin.status(),
        404,
        "it reaches the handler: no such agent"
    );

    // A non-browser client (curl, a portal) sends no Sec-Fetch header and is unaffected.
    let no_header = client
        .post(url(
            server.rest_addr,
            &format!("/api/v1/agents/{uid}/restart"),
        ))
        .send()
        .await
        .expect("restart");
    assert_ne!(
        no_header.status(),
        403,
        "a client with no fetch metadata is not a CSRF"
    );
}

/// A browser that sends no Fetch Metadata still sends `Origin` on a `POST`. An `Origin` that is
/// not the plane's own marks a cross-site caller and is refused, while the plane's own origin and
/// a caller with neither header pass the guard.
/// Verifies: ADR-0021
#[tokio::test]
async fn a_post_from_a_foreign_origin_without_fetch_metadata_is_refused() {
    let server = spawn().await;
    let client = reqwest::Client::new();
    let uid = opamp::uid::InstanceUid::default();
    let restart = || {
        client.post(url(
            server.rest_addr,
            &format!("/api/v1/agents/{uid}/restart"),
        ))
    };

    for origin in ["https://attacker.example", "null"] {
        let foreign = restart()
            .header("origin", origin)
            .send()
            .await
            .expect("restart");
        assert_eq!(foreign.status(), 403, "Origin {origin} is refused");
    }

    let own = restart()
        .header("origin", format!("http://{}", server.rest_addr))
        .send()
        .await
        .expect("restart");
    assert_eq!(
        own.status(),
        404,
        "the plane's own origin reaches the handler"
    );

    // A page on port 80 is another origin than a plane addressed on 443, though both name the host.
    let port_80 = restart()
        .header("host", "127.0.0.1:443")
        .header("origin", "http://127.0.0.1")
        .send()
        .await
        .expect("restart");
    assert_eq!(port_80.status(), 403, "an Origin on port 80 is refused");
}

/// Every response of the Operator plane — the UI, the API, the API docs and a miss alike —
/// forbids framing and content sniffing, sends no referrer and tells a browser to come back over
/// TLS only, and an `/api/v1` answer is never cached.
/// Verifies: Q-1
#[tokio::test]
async fn every_operator_response_carries_the_security_headers() {
    let server = spawn().await;
    let client = reqwest::Client::new();
    for path in [
        "/",
        "/ui.css",
        "/ui-carbon.css",
        "/ui-quiet.css",
        "/shiki.js",
        "/api/v1/agents",
        "/api/v1/docs",
        "/api/v1/openapi.json",
        "/no-such-page",
    ] {
        let response = client
            .get(url(server.rest_addr, path))
            .send()
            .await
            .expect("get");
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string()
        };
        let policy = header("content-security-policy");
        assert!(
            policy.contains("frame-ancestors 'none'") && policy.contains("default-src 'self'"),
            "{path}: {policy:?}"
        );
        assert_eq!(header("x-frame-options"), "DENY", "{path}");
        assert_eq!(header("x-content-type-options"), "nosniff", "{path}");
        assert_eq!(header("referrer-policy"), "no-referrer", "{path}");
        assert_eq!(
            header("strict-transport-security"),
            "max-age=31536000",
            "{path}"
        );
        if path.starts_with("/api/v1/") {
            assert_eq!(header("cache-control"), "no-store", "{path}");
        }
    }
}

/// The bundled UI runs under the plane's policy: every inline script of the page, whatever its
/// attributes, is one the policy names by its hash, and no element carries an inline event
/// handler the policy would block.
#[tokio::test]
async fn the_policy_names_every_inline_script_of_the_ui() {
    use base64::Engine as _;
    use sha2::Digest as _;
    let server = spawn().await;
    let response = reqwest::get(url(server.rest_addr, "/")).await.expect("get");
    let policy = response
        .headers()
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .expect("a policy")
        .to_string();
    let script_src = policy
        .split(';')
        .map(str::trim)
        .find(|d| d.starts_with("script-src "))
        .expect("a script-src directive")
        .to_string();
    assert!(!script_src.contains("'unsafe-inline'"), "{script_src}");
    let page = response.text().await.expect("page");
    let lower = page.to_ascii_lowercase();

    // Every `<script …>` without a `src`, whatever its attributes, is named by its hash.
    let mut inline = 0;
    let mut rest = 0;
    while let Some(start) = lower[rest..].find("<script").map(|i| rest + i) {
        let open_end = start + lower[start..].find('>').expect("a closed tag");
        let close = open_end + lower[open_end..].find("</script").expect("a closed script");
        rest = close;
        if lower[start..open_end].contains("src=") {
            continue;
        }
        let body = &page[open_end + 1..close];
        let hash = base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(body));
        assert!(
            script_src.contains(&format!("'sha256-{hash}'")),
            "an inline script the policy does not name: {}",
            &page[start..open_end + 1]
        );
        inline += 1;
    }

    // No element of the page, nor one its scripts write, carries an inline event handler.
    for (at, _) in lower.match_indices('<') {
        let tag = &lower[at + 1..];
        if !tag.starts_with(|c: char| c.is_ascii_alphabetic()) {
            continue;
        }
        let tag = &tag[..tag.find('>').unwrap_or(tag.len())];
        assert!(
            !tag.split_whitespace()
                .any(|attr| attr.starts_with("on") && attr.contains('=')),
            "an inline event handler: <{tag}>"
        );
    }
    assert!(inline > 0, "the page has inline scripts to name");
}

/// The bundled UI's look lives in its own stylesheets: the page links the default, carries no
/// `<style>` of its own, names every look its style combo offers, and each is served as CSS from
/// the plane's origin, which the policy admits. Light, dark or the system's is a choice of its
/// own, the same for every look.
#[tokio::test]
async fn the_ui_takes_its_look_from_its_own_stylesheet() {
    let server = spawn().await;
    let client = reqwest::Client::new();
    let page = client
        .get(url(server.rest_addr, "/"))
        .send()
        .await
        .expect("get the UI");
    let policy = page
        .headers()
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .expect("a policy")
        .to_string();
    assert!(
        policy
            .split(';')
            .map(str::trim)
            .any(|d| d.starts_with("style-src ") && d.contains("'self'")),
        "{policy}"
    );
    let html = page.text().await.expect("html").to_ascii_lowercase();
    assert!(
        html.contains(r#"<link id="ui-style" rel="stylesheet" href="/ui.css" />"#),
        "the page no longer links /ui.css"
    );
    assert!(!html.contains("<style"), "the page carries a <style> again");

    // The theme is one choice for every look — light, dark, or the system's — remembered under
    // one key, not one per look.
    assert!(
        html.contains(r#"const ui_themes = ["system", "light", "dark"];"#),
        "the theme's buttons do not offer system, light and dark"
    );
    assert!(
        html.contains(
            r#"<div id="theme-switch" class="theme-switch" role="group" aria-label="theme">"#
        ),
        "the theme is not chosen by a group of buttons"
    );
    assert!(
        html.contains(r#"matchmedia("(prefers-color-scheme: dark)")"#),
        "the system theme does not follow the system's preference"
    );
    assert!(
        !html.contains("themekey"),
        "a look remembers its own theme again"
    );
    assert!(
        html.contains(r#"const attr_hue = { host: "blue", os: "teal", service: "pink", supervisor: "slate" };"#),
        "the attribute namespaces lost their hues"
    );

    // Each look defines the theme it does not open in, since the page always sets one outright.
    for (path, other_theme) in [
        ("/ui.css", r#":root[data-theme="light"]"#),
        ("/ui-carbon.css", r#":root[data-theme="light"]"#),
        ("/ui-quiet.css", r#":root[data-theme="dark"]"#),
    ] {
        assert!(
            html.contains(&format!(r#"href: "{path}""#)),
            "the style combo does not offer {path}"
        );
        let css = client
            .get(url(server.rest_addr, path))
            .send()
            .await
            .expect("get the stylesheet");
        assert_eq!(css.status(), 200, "{path}");
        assert_eq!(
            css.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("text/css; charset=utf-8"),
            "{path}"
        );
        let css = css.text().await.expect("css");
        assert!(css.contains(":root"), "{path}");
        assert!(css.contains(other_theme), "{path} lacks {other_theme}");
        // Every hue the page gives an attribute namespace is one the look defines, and a list
        // value's count of further entries has its rule.
        for hue in ["blue", "teal", "pink", "slate"] {
            assert!(
                html.contains(&format!(r#": "{hue}""#)),
                "the page gives no namespace {hue}"
            );
            assert!(
                css.contains(&format!(".chip.hue-{hue} ")),
                "{path} lacks {hue}"
            );
        }
        assert!(
            css.contains(".chip-count "),
            "{path} lacks the list value's count"
        );
    }
}

/// The vendored Shiki bundle is served from the plane's own origin as JavaScript, under the same
/// policy as every page, and it is the file the pin names: the bundle cannot change without
/// `scripts/vendor-shiki.lock` changing in the same commit.
/// Verifies: ADR-0038
#[tokio::test]
async fn the_ui_serves_the_pinned_shiki_bundle() {
    use sha2::Digest as _;
    let server = spawn().await;
    let response = reqwest::get(url(server.rest_addr, "/shiki.js"))
        .await
        .expect("get the bundle");
    assert_eq!(response.status(), 200);
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    };
    assert!(
        header("content-type").starts_with("text/javascript"),
        "{}",
        header("content-type")
    );
    let policy = header("content-security-policy");
    assert!(
        policy.contains("script-src 'self'")
            && !policy.contains("'unsafe-eval'")
            && !policy.contains("'wasm-unsafe-eval'"),
        "{policy}"
    );
    let body = response.bytes().await.expect("the bundle");
    let digest: String = sha2::Sha256::digest(&body)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let lock = include_str!("../../../scripts/vendor-shiki.lock");
    let pinned = lock
        .lines()
        .find_map(|line| line.strip_prefix("sha256 "))
        .expect("the lock pins a sha256");
    assert_eq!(
        digest, pinned,
        "static/shiki.js differs from the bundle scripts/vendor-shiki.lock pins"
    );
    assert!(
        lock.lines().any(|line| line == "shiki 4.5.0"),
        "the lock pins another Shiki than ADR-0038 names"
    );
    let text = std::str::from_utf8(&body).expect("utf-8");
    assert!(
        text.starts_with("/*\n * Shiki 4.5.0") && text.contains("window.fleetHighlight"),
        "the bundle lost its header or its one function"
    );
    let header_end = text.find("*/").expect("the header ends");
    assert!(
        text[..header_end]
            .contains("the CSS-variables theme with this project's TOML and\n * INI token rules"),
        "the header does not name the project's TOML and INI token rules"
    );
}

/// The UI loads the vendored Shiki bundle without waiting for it, chooses the grammar of an
/// Agent's effective configuration by the type the Agent reports — `otelcol*` YAML, the fleet's
/// own Client and Telegraf TOML, Fluent Bit INI, anything else none — and each look defines the
/// CSS-variables theme's colours in its light and its dark theme. The project's TOML and INI token
/// rules in the bundle name only those colours, so no look needs a variable of its own for them.
/// Verifies: ADR-0038
#[tokio::test]
async fn the_ui_colours_an_effective_configuration_by_the_agents_type() {
    let server = spawn().await;
    let client = reqwest::Client::new();
    let html = client
        .get(url(server.rest_addr, "/"))
        .send()
        .await
        .expect("get the UI")
        .text()
        .await
        .expect("html");
    assert!(
        html.contains(r#"<script id="shiki" src="/shiki.js" defer></script>"#),
        "the page does not load /shiki.js deferred"
    );
    assert!(
        html.contains(
            r#"const CONFIG_GRAMMARS = new Map([["supervisor", "toml"], ["telegraf", "toml"], ["fluent-bit", "ini"]]);"#
        ),
        "supervisor and telegraf are not TOML, or fluent-bit is not INI"
    );
    assert!(
        html.contains(
            r#"const configGrammar = (type) => ((type || "").startsWith("otelcol") ? "yaml" : CONFIG_GRAMMARS.get(type) || null);"#
        ),
        "otelcol* is not YAML, or another type is not left plain"
    );
    // Both places the configuration shows are coloured: the cell and the dialog.
    assert!(
        html.contains("colourConfigs(rows);"),
        "the cell is not coloured"
    );
    assert!(
        html.contains("agent.effective_config, configGrammar(agent.service_name));"),
        "the dialog is not coloured"
    );

    const NAMES: [&str; 11] = [
        "foreground",
        "background",
        "token-keyword",
        "token-string",
        "token-string-expression",
        "token-constant",
        "token-comment",
        "token-parameter",
        "token-function",
        "token-punctuation",
        "token-link",
    ];
    let bundle = include_str!("../static/shiki.js");
    let mut named = 0;
    for (at, _) in bundle.match_indices("var(--shiki-") {
        let rest = &bundle[at + "var(--shiki-".len()..];
        let name = &rest[..rest.find(')').expect("the var() closes")];
        assert!(
            NAMES.contains(&name),
            "the bundle's token rules name --shiki-{name}, which no look defines"
        );
        named += 1;
    }
    assert!(
        named > 0,
        "the bundle carries no token rules of the project's"
    );

    for path in ["/ui.css", "/ui-carbon.css", "/ui-quiet.css"] {
        let css = client
            .get(url(server.rest_addr, path))
            .send()
            .await
            .expect("get the stylesheet")
            .text()
            .await
            .expect("css");
        for name in NAMES {
            // Once in the theme the look opens in, once in the other.
            assert_eq!(
                css.matches(&format!("--shiki-{name}:")).count(),
                2,
                "{path} does not define --shiki-{name} for light and dark"
            );
        }
    }
}

/// The fleet as the REST API shows it.
async fn agents(client: &reqwest::Client, addr: std::net::SocketAddr) -> Vec<serde_json::Value> {
    client
        .get(url(addr, "/api/v1/agents"))
        .send()
        .await
        .expect("agents")
        .json()
        .await
        .expect("json")
}

/// One OpAMP report over plain HTTP, the way a Client sends it.
async fn report(
    client: &reqwest::Client,
    addr: std::net::SocketAddr,
    msg: &opamp::proto::AgentToServer,
) -> opamp::proto::ServerToAgent {
    use prost::Message;
    let response = client
        .post(url(addr, "/v1/opamp"))
        .header("content-type", "application/x-protobuf")
        .body(msg.encode_to_vec())
        .send()
        .await
        .expect("post");
    assert_eq!(response.status(), 200);
    opamp::proto::ServerToAgent::decode(response.bytes().await.expect("body").as_ref())
        .expect("decode")
}

/// ADR-0024, and the whole point of it: a rollout ring becomes a Server-side decision. The Agent
/// reports nothing about `rollout`, so before the label the canary Deployment cannot claim it —
/// and moving it into the ring is one API call rather than an edit and a restart on that host.
#[tokio::test]
async fn a_label_moves_an_agent_into_a_rollout_ring() {
    let server = spawn().await;
    let client = reqwest::Client::new();
    let uid = opamp::uid::InstanceUid::default();
    report(&client, server.addr, &support::full_report(&uid, "host", 1)).await;

    // A Deployment aimed at the canary ring, holding a Configuration. Nothing reports `rollout`,
    // so it proposes itself to nobody — and even a match only proposes (ADR-0025).
    save_configuration(server.rest_addr, "canary", "receivers: {}", "").await;
    deploy(
        server.rest_addr,
        "canary",
        &[("rollout", "canary")],
        &["canary"],
    )
    .await;
    assert!(
        matched_configurations(&client, server.rest_addr, &uid)
            .await
            .is_empty(),
        "an attribute nobody reports reaches nobody"
    );

    // One call, no host access: the Agent is in the ring.
    let labelled = set_labels(
        &client,
        server.rest_addr,
        &uid,
        serde_json::json!({"rollout": "canary"}),
    )
    .await;
    assert_eq!(labelled.status(), 200);
    let view: serde_json::Value = labelled.json().await.expect("json");
    assert_eq!(view["labels"]["rollout"], "canary");
    assert_eq!(view["deployment"], "canary");
    assert_eq!(
        matched_configurations(&client, server.rest_addr, &uid).await,
        ["canary"],
        "the label is matched exactly like a reported attribute"
    );

    // And out again: an empty map clears them.
    assert_eq!(
        set_labels(&client, server.rest_addr, &uid, serde_json::json!({}))
            .await
            .status(),
        200
    );
    assert!(matched_configurations(&client, server.rest_addr, &uid)
        .await
        .is_empty());
}

/// The crux (ADR-0024 point 18): reported attributes decide which artifact fits a machine, so a
/// label may not restate one. Refused where it is written, naming the key — not quietly ignored.
// Verifies: ADR-0024
#[tokio::test]
async fn a_label_may_not_restate_what_the_agent_reports() {
    let server = spawn().await;
    let client = reqwest::Client::new();
    let uid = opamp::uid::InstanceUid::default();
    report(&client, server.addr, &support::full_report(&uid, "host", 1)).await;

    // `os.type` is reported by this Agent and chooses which artifact it is offered (ADR-0026).
    let refused = set_labels(
        &client,
        server.rest_addr,
        &uid,
        serde_json::json!({"os.type": "windows"}),
    )
    .await;
    assert_eq!(refused.status(), 409);
    let body: serde_json::Value = refused.json().await.expect("json");
    let message = body["error"].as_str().expect("message");
    assert!(message.contains("os.type"), "it names the key: {message}");

    // An empty value is a mistake rather than an intent, and is refused where it is written.
    assert_eq!(
        set_labels(
            &client,
            server.rest_addr,
            &uid,
            serde_json::json!({"rollout": ""})
        )
        .await
        .status(),
        400
    );

    // Nothing was stored by either attempt.
    let agents = agents(&client, server.rest_addr).await;
    assert!(
        agents[0]["labels"].as_object().expect("labels").is_empty(),
        "a refused set leaves nothing behind"
    );
}

/// A Supervisor whose Managed Process will not start still reads Connected — truthfully, the
/// Supervisor lives — so the reported health is the only place an operator can see that nothing
/// is actually running. The view must carry it whole: the flag, the Agent's own status string,
/// and the reason (`ComponentHealth.last_error`, which the Baseline says SHOULD be set when
/// unhealthy).
/// Verifies: G-2
#[tokio::test]
async fn the_view_carries_the_reported_health_and_its_reason() {
    let server = spawn().await;
    let client = reqwest::Client::new();
    let uid = opamp::uid::InstanceUid::default();

    // Before any health report, the view claims nothing either way.
    report(&client, server.addr, &support::full_report(&uid, "host", 1)).await;
    let view = &agents(&client, server.rest_addr).await[0];
    assert_eq!(view["healthy"], false);
    assert_eq!(view["health_status"], "");
    assert_eq!(view["health_error"], "");

    // The Supervisor's process would not start: unhealthy, with the situation and the reason.
    let mut unhealthy = support::full_report(&uid, "host", 2);
    unhealthy.capabilities |= opamp::proto::AgentCapabilities::ReportsHealth as u64;
    unhealthy.health = Some(opamp::proto::ComponentHealth {
        healthy: false,
        status: "no process installed".to_string(),
        last_error: "cannot spawn otelcol: No such file or directory".to_string(),
        ..Default::default()
    });
    report(&client, server.addr, &unhealthy).await;
    let view = &agents(&client, server.rest_addr).await[0];
    assert_eq!(view["healthy"], false);
    assert_eq!(view["health_status"], "no process installed");
    assert_eq!(
        view["health_error"],
        "cannot spawn otelcol: No such file or directory"
    );

    // The process came up: the finding clears with the next report.
    let mut healthy = support::full_report(&uid, "host", 3);
    healthy.capabilities |= opamp::proto::AgentCapabilities::ReportsHealth as u64;
    healthy.health = Some(opamp::proto::ComponentHealth {
        healthy: true,
        status: "running".to_string(),
        ..Default::default()
    });
    report(&client, server.addr, &healthy).await;
    let view = &agents(&client, server.rest_addr).await[0];
    assert_eq!(view["healthy"], true);
    assert_eq!(view["health_status"], "running");
    assert_eq!(view["health_error"], "");
}

/// What the Server knows of an Agent reaches the API whole: its identity, the configuration it
/// holds, and — when it refuses one — that it did, and the Agent's own reason.
/// Verifies: G-2, G-4
#[tokio::test]
async fn the_view_carries_the_held_configuration_and_a_refusal_with_its_reason() {
    use opamp::proto::{
        AgentConfigMap, AgentConfigObject, EffectiveConfig, RemoteConfigStatus,
        RemoteConfigStatuses,
    };
    let server = spawn().await;
    let client = reqwest::Client::new();
    let uid = opamp::uid::InstanceUid::default();

    let mut held = support::full_report(&uid, "host", 1);
    held.effective_config = Some(EffectiveConfig {
        config_map: Some(AgentConfigMap {
            config_map: [(
                "fleet".to_string(),
                AgentConfigObject {
                    body: b"receivers: {otlp: {}}\n".to_vec(),
                    content_type: "text/yaml".to_string(),
                    ..Default::default()
                },
            )]
            .into(),
        }),
    });
    held.remote_config_status = Some(RemoteConfigStatus {
        last_remote_config_hash: vec![7; 32],
        status: RemoteConfigStatuses::Failed as i32,
        error_message: "line 3: unknown receiver \"otlpp\"".to_string(),
    });
    report(&client, server.addr, &held).await;

    let view = &agents(&client, server.rest_addr).await[0];
    assert_eq!(view["instance_uid"], uid.to_string());
    assert!(
        view["effective_config"]
            .as_str()
            .is_some_and(|config| config.contains("receivers: {otlp: {}}")),
        "{view}"
    );
    assert_eq!(view["remote_config_status"], "FAILED");
    assert_eq!(
        view["remote_config_error"],
        "line 3: unknown receiver \"otlpp\""
    );
}

/// Labels are part of the Agent's record (ADR-0035 clause 6): forgetting an Agent removes them
/// with it, and an Agent that comes back starts unlabelled.
/// Verifies: ADR-0035
#[tokio::test]
async fn forgetting_an_agent_removes_its_labels() {
    let server = support::spawn_with_stale_after(std::time::Duration::ZERO).await;
    let client = reqwest::Client::new();
    let uid = opamp::uid::InstanceUid::default();
    report(&client, server.addr, &support::full_report(&uid, "host", 1)).await;
    assert_eq!(
        set_labels(
            &client,
            server.rest_addr,
            &uid,
            serde_json::json!({"rollout": "canary"})
        )
        .await
        .status(),
        200
    );

    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let forgotten = client
        .delete(url(server.rest_addr, &format!("/api/v1/agents/{uid}")))
        .send()
        .await
        .expect("delete");
    assert_eq!(forgotten.status(), 204);
    assert!(agents(&client, server.rest_addr).await.is_empty());

    // It comes back — without the labels it had.
    report(&client, server.addr, &support::full_report(&uid, "host", 2)).await;
    let agents = agents(&client, server.rest_addr).await;
    assert!(
        agents[0]["labels"].as_object().expect("labels").is_empty(),
        "{}",
        agents[0]
    );
}

/// `fleet.*` is the Server's own: a label in it is refused `400`, naming the key, and nothing is
/// stored.
/// Verifies: ADR-0035
#[tokio::test]
async fn a_label_in_the_fleet_space_is_refused() {
    let server = spawn().await;
    let client = reqwest::Client::new();
    let uid = opamp::uid::InstanceUid::default();
    report(&client, server.addr, &support::full_report(&uid, "host", 1)).await;
    let refused = set_labels(
        &client,
        server.rest_addr,
        &uid,
        serde_json::json!({"fleet.x": "1", "rollout": "canary"}),
    )
    .await;
    assert_eq!(refused.status(), 400);
    let body: serde_json::Value = refused.json().await.expect("json");
    let message = body["error"].as_str().expect("message");
    assert!(message.contains("fleet.x"), "it names the key: {message}");
    let agents = agents(&client, server.rest_addr).await;
    assert!(agents[0]["labels"].as_object().expect("labels").is_empty());
}

/// One Agent's row of the fleet view.
async fn agent_view(
    client: &reqwest::Client,
    addr: std::net::SocketAddr,
    uid: &opamp::uid::InstanceUid,
) -> serde_json::Value {
    agents(client, addr)
        .await
        .into_iter()
        .find(|a| a["instance_uid"] == uid.to_string())
        .expect("the agent is in the fleet")
}

/// The Configurations the Deployment claiming one Agent would release to it — the candidates — as
/// the fleet view reports them.
async fn matched_configurations(
    client: &reqwest::Client,
    addr: std::net::SocketAddr,
    uid: &opamp::uid::InstanceUid,
) -> Vec<String> {
    agents(client, addr)
        .await
        .into_iter()
        .find(|a| a["instance_uid"] == uid.to_string())
        .expect("the agent is in the fleet")["matched_configurations"]
        .as_array()
        .expect("array")
        .iter()
        .map(|v| v.as_str().expect("name").to_string())
        .collect()
}

async fn set_labels(
    client: &reqwest::Client,
    addr: std::net::SocketAddr,
    uid: &opamp::uid::InstanceUid,
    labels: serde_json::Value,
) -> reqwest::Response {
    client
        .put(url(addr, &format!("/api/v1/agents/{uid}/labels")))
        .json(&serde_json::json!({ "labels": labels }))
        .send()
        .await
        .expect("put labels")
}

/// The bundled UI splits along ADR-0034's seam: the Configurations tab edits content with no
/// Selector and no rollout press, the Deployments form holds Configurations in place through the
/// Deployment's own route, and the fields the page reads are the ones the API serves. A rename on
/// either side breaks here rather than in an empty column.
/// Verifies: ADR-0034
#[tokio::test]
async fn the_ui_edits_configurations_as_content_and_deployments_hold_them() {
    let server = spawn().await;
    let client = reqwest::Client::new();
    let html = client
        .get(url(server.rest_addr, "/"))
        .send()
        .await
        .expect("get the UI")
        .text()
        .await
        .expect("html");
    for needle in [
        "c.deployments",
        "d.configurations",
        "${depPath(name)}/configurations/${encodeURIComponent(configuration)}",
        "${depPath(d.name)}/configurations/${encodeURIComponent(pick)}",
        "${depPath(d.name)}/configurations/${encodeURIComponent(del.dataset.name)}",
        "${depPath(act.dataset.name)}/rollout",
        "a.assigned_deployment",
        "p.change",
    ] {
        assert!(
            html.contains(needle),
            "the UI no longer contains {needle:?}"
        );
    }
    for gone in ["config-selector", "config-rollout"] {
        assert!(!html.contains(gone), "the UI still contains {gone:?}");
    }
    assert!(
        !html.contains("configurations/${encodeURIComponent(config.name)}/rollout"),
        "a Configuration has no rollout press of its own"
    );

    let document: serde_json::Value = client
        .get(url(server.rest_addr, "/api/v1/openapi.json"))
        .send()
        .await
        .expect("get the document")
        .json()
        .await
        .expect("json");
    let schemas = &document["components"]["schemas"];
    for (schema, field) in [
        ("ConfigurationView", "deployments"),
        ("ConfigurationView", "service_name"),
        ("DeploymentView", "configurations"),
        ("AgentView", "assigned_deployment"),
        ("AgentView", "pending_configurations"),
        ("PendingConfigurationView", "change"),
    ] {
        assert!(
            schemas[schema]["properties"][field].is_object(),
            "{schema} no longer serves {field}"
        );
    }
}

/// Every field of the UI's forms says, in words beside it, whether the action needs it, and a
/// field the action refuses to run without carries `required` for assistive technology too — the
/// placeholder alone vanishes the moment the field is typed into.
#[tokio::test]
async fn the_forms_mark_every_field_required_or_optional() {
    let server = spawn().await;
    let html = reqwest::Client::new()
        .get(url(server.rest_addr, "/"))
        .send()
        .await
        .expect("get the UI")
        .text()
        .await
        .expect("html");
    // The caption that labels the control with this id: the `<label class="field…">` it sits in.
    let caption = |id: &str| -> String {
        let at = html
            .find(&format!("id=\"{id}\""))
            .unwrap_or_else(|| panic!("the UI has no field {id}"));
        let label = html[..at]
            .rfind("<label class=\"field")
            .unwrap_or_else(|| panic!("{id} has no caption"));
        html[label..at].to_string()
    };
    for id in [
        "config-name",
        "config-type",
        "set-type",
        "set-version",
        "entry-os",
        "entry-arch",
        "entry-file",
        "dep-name",
        "dep-selector",
        "boot-org",
        "boot-unit",
        "boot-pass",
        "boot-pass2",
    ] {
        let caption = caption(id);
        assert!(caption.contains(">required<"), "{id}: {caption}");
        assert!(
            caption.ends_with("required aria-required=\"true\" "),
            "{id} does not carry `required`: {caption}"
        );
    }
    for id in [
        "config-role",
        "set-sig-file",
        "dep-package-pick",
        "dep-config-pick",
        "boot-country",
        "boot-state",
        "boot-locality",
        "boot-org-id",
        "boot-days",
    ] {
        assert!(caption(id).contains(">optional<"), "{id}: {}", caption(id));
    }
    assert!(html.contains(
        "<label class=\"field-cap\" for=\"config\">Body <b class=\"need req\">required</b></label>"
    ));
}

/// The bundled UI asks for a bootstrap password of 8 to 128 characters, as the Server takes.
/// Verifies: ADR-0048
#[tokio::test]
async fn the_ui_asks_for_a_bootstrap_password_of_8_to_128_characters() {
    let server = spawn().await;
    let html = reqwest::Client::new()
        .get(url(server.rest_addr, "/"))
        .send()
        .await
        .expect("get the UI")
        .text()
        .await
        .expect("html");
    let at = html.find("id=\"boot-pass\"").expect("the password field");
    let field = &html[at..at + html[at..].find("/>").expect("its end")];
    assert!(
        field.contains(&format!(
            "minlength=\"{}\" maxlength=\"{}\"",
            fleet_core::pkcs12::MIN_PASSWORD_CHARS,
            fleet_core::pkcs12::MAX_PASSWORD_CHARS
        )),
        "{field}"
    );
    assert!(field.contains("8 to 128 characters"), "{field}");
}

/// The bundled UI's Hosts tab reads what `GET /api/v1/hosts` serves and acts on a row through the
/// Gateway and revocation routes, and the Agents tab marks inherited labels — the fields the page
/// reads are the ones the API documents.
/// Verifies: ADR-0035
#[tokio::test]
async fn the_ui_lists_hosts_and_marks_inherited_labels() {
    let server = spawn().await;
    let client = reqwest::Client::new();
    let html = client
        .get(url(server.rest_addr, "/"))
        .send()
        .await
        .expect("get the UI")
        .text()
        .await
        .expect("html");
    for needle in [
        "data-tab=\"hosts\"",
        "fetch(\"/api/v1/hosts\")",
        "/api/v1/hosts/${encodeURIComponent(mark.dataset.host)}/gateway",
        "certificate: { authority: \"client\", serial }",
        "h.subject[field]",
        "a.client_agent",
        "a.inherited_labels",
        "a.ignored_attributes",
        "a.host_attributes",
    ] {
        assert!(
            html.contains(needle),
            "the UI no longer contains {needle:?}"
        );
    }
    let document: serde_json::Value = client
        .get(url(server.rest_addr, "/api/v1/openapi.json"))
        .send()
        .await
        .expect("get the document")
        .json()
        .await
        .expect("json");
    let schemas = &document["components"]["schemas"];
    for (schema, field) in [
        ("HostView", "name"),
        ("HostView", "subject"),
        ("HostView", "agents"),
        ("HostSubject", "organizational_unit"),
        ("HostAgent", "client_agent"),
        ("HostAgent", "machine"),
        ("HostAgent", "ambiguous"),
        ("AgentView", "inherited_labels"),
        ("AgentView", "host_attributes"),
        ("AgentView", "ignored_attributes"),
    ] {
        assert!(
            schemas[schema]["properties"][field].is_object(),
            "{schema} no longer serves {field}"
        );
    }
}

/// The Packages tab shows each entry's SHA-256 and signature state, offers what a signature covers
/// as a signing file, and imports a signed one through the entry's signature route (ADR-0033) — so
/// the page writes the one format `opamp-fleetctl package sign --signing-info` reads, and the
/// fields it reads must be the ones the API serves. A rename on either side breaks here rather than
/// in an empty column or a signing file with a hole in it.
/// Verifies: ADR-0023, ADR-0027, ADR-0033
#[tokio::test]
async fn the_ui_shows_the_sha256_and_carries_the_signing_file_the_api_serves() {
    let server = spawn().await;
    let client = reqwest::Client::new();
    let html = client
        .get(url(server.rest_addr, "/"))
        .send()
        .await
        .expect("get the UI")
        .text()
        .await
        .expect("html");
    for needle in [
        "e.content_hash",
        "p.agent_type",
        "p.version",
        "e.os",
        "e.arch",
        "\"opamp-fleet-signing-v1\"",
        "format: SIGNING_FORMAT",
        "/entries/${encodeURIComponent(os)}/${encodeURIComponent(arch)}/signature",
        "entrySigPath(info.agent_type, info.version, e.os, e.arch)",
        "e.sha256 !== entry.content_hash",
        "JSON.stringify({ signature: e.signature })",
        "e.signature_state",
        "stored.signature_state",
    ] {
        assert!(
            html.contains(needle),
            "the UI no longer contains {needle:?}"
        );
    }

    let document: serde_json::Value = client
        .get(url(server.rest_addr, "/api/v1/openapi.json"))
        .send()
        .await
        .expect("get the document")
        .json()
        .await
        .expect("json");
    let schemas = &document["components"]["schemas"];
    for (schema, field) in [
        ("PackageSetView", "agent_type"),
        ("PackageSetView", "version"),
        ("PackageEntryView", "os"),
        ("PackageEntryView", "arch"),
        ("PackageEntryView", "content_hash"),
        ("PackageEntryView", "signature_state"),
        ("SignatureSpec", "signature"),
    ] {
        assert!(
            schemas[schema]["properties"][field].is_object(),
            "{schema} no longer carries {field}"
        );
    }
}

/// The bundled UI is a client of the REST API and nothing more (ADR-0023 clause 13), so its
/// Enrolments tab depends on the names the enrolment routes share with it: the routes it calls and
/// the fields it shows and sends, the requested key's fingerprint above all — what ADR-0021 clause 22 lists
/// so an operator can match a request to the Client's log. The page asks for them, and the OpenAPI
/// document describes them; a rename on one side breaks here rather than in an empty column. What
/// the page does with them is not tested in the repository: it is one embedded page with no
/// frontend toolchain to run it in. The queue lists the bootstrap certificate's subject values and
/// not the request's own subject, the issue form sends all six attributes and the password, and
/// the page never handles a private key: every certificate offers its PKCS#12 file (ADR-0036).
/// Verifies: ADR-0023, ADR-0028, ADR-0036
#[tokio::test]
async fn the_ui_and_the_enrolment_api_share_their_names() {
    let server = spawn().await;
    let client = reqwest::Client::new();
    let html = client
        .get(url(server.rest_addr, "/"))
        .send()
        .await
        .expect("get the UI")
        .text()
        .await
        .expect("html");
    for needle in [
        "\"/api/v1/enrolment/window\"",
        "\"/api/v1/enrolments\"",
        "/api/v1/enrolments/${",
        ".key_fingerprint",
        ".bootstrap_subject",
        ".bootstrap_fingerprint",
        ".bootstrap_serial",
        "\"/api/v1/bootstrap-certificates\"",
        "\"/api/v1/revocations\"",
        "authority: \"bootstrap\"",
        "[\"country\", \"boot-country\"]",
        "[\"state\", \"boot-state\"]",
        "[\"locality\", \"boot-locality\"]",
        "[\"organization\", \"boot-org\"]",
        "[\"organizational_unit\", \"boot-unit\"]",
        "[\"organization_identifier\", \"boot-org-id\"]",
        "e.bootstrap_subject[field]",
        "e.subject_refusal",
        "validity_days:",
        "password };",
        "/p12`",
        "download = \"bootstrap.p12\"",
        ".issued_ms",
        ".not_after_ms",
        ".revoked",
        ".arrived_ms",
        ".until_ms",
        "open_for_secs:",
    ] {
        assert!(
            html.contains(needle),
            "the UI no longer contains {needle:?}"
        );
    }
    for gone in ["private_key_pem", "bootstrap-key.pem", "beforeunload"] {
        assert!(
            !html.contains(gone),
            "the page handles no private key, yet contains {gone:?}"
        );
    }

    let document: serde_json::Value = client
        .get(url(server.rest_addr, "/api/v1/openapi.json"))
        .send()
        .await
        .expect("get the document")
        .json()
        .await
        .expect("json");
    let schemas = &document["components"]["schemas"];
    for (schema, fields) in [
        (
            "PendingEnrolment",
            &[
                "id",
                "arrived_ms",
                "peer",
                "key_fingerprint",
                "bootstrap_subject",
                "subject_refusal",
                "bootstrap_fingerprint",
                "bootstrap_serial",
            ][..],
        ),
        ("EnrolmentWindow", &["open", "until_ms"][..]),
        (
            "BootstrapSubject",
            &[
                "country",
                "state",
                "locality",
                "organization",
                "organizational_unit",
                "organization_identifier",
            ][..],
        ),
        (
            "BootstrapView",
            &["serial", "subject", "issued_ms", "not_after_ms", "revoked"][..],
        ),
        (
            "IssuedBootstrap",
            &["serial", "subject", "not_after_ms", "certificate_pem"][..],
        ),
    ] {
        for field in fields {
            assert!(
                schemas[schema]["properties"].get(field).is_some(),
                "{schema} no longer has {field}"
            );
        }
    }
    assert!(
        schemas["IssuedBootstrap"]["properties"]
            .get("private_key_pem")
            .is_none(),
        "an issue never answers a private key"
    );
    for (schema, field) in [
        ("IssueBootstrapRequest", "subject"),
        ("IssueBootstrapRequest", "password"),
        ("BootstrapSubject", "organization"),
        ("BootstrapSubject", "organizational_unit"),
    ] {
        assert!(
            schemas[schema]["required"]
                .as_array()
                .is_some_and(|required| required.iter().any(|f| f == field)),
            "{schema} marks {field} required"
        );
    }
    assert!(
        schemas["PendingEnrolment"]["properties"]
            .get("subject")
            .is_none(),
        "a pending request lists no subject of its own"
    );
    assert!(
        // Optional, so the reference sits beside `null` in a `oneOf`.
        schemas["PendingEnrolment"]["properties"]["bootstrap_subject"]
            .to_string()
            .contains("\"#/components/schemas/HostSubject\""),
        "the bootstrap certificate's subject is listed by its values"
    );
    for path in [
        "/api/v1/enrolment/window",
        "/api/v1/enrolments",
        "/api/v1/enrolments/{id}/approve",
        "/api/v1/enrolments/{id}/reject",
    ] {
        assert!(document["paths"].get(path).is_some(), "no route {path}");
    }
}

/// Approving an enrolment admits a host to the fleet, and the bundled UI now offers it as a press
/// in the browser — so a cross-site page must not be able to fire it. Both enrolment decisions are
/// body-less `POST`s behind the same Fetch Metadata guard as `restart`, which answers before the
/// handler, whether or not enrolment is configured.
/// Verifies: ADR-0021
#[tokio::test]
async fn a_cross_site_enrolment_decision_is_refused() {
    let server = spawn().await;
    let client = reqwest::Client::new();
    for act in ["approve", "reject"] {
        let path = format!("/api/v1/enrolments/{}/{act}", "ab".repeat(32));
        let cross = client
            .post(url(server.rest_addr, &path))
            .header("sec-fetch-site", "cross-site")
            .send()
            .await
            .expect("decide");
        assert_eq!(cross.status(), 403, "a cross-site {act} is refused");
        let same_origin = client
            .post(url(server.rest_addr, &path))
            .header("sec-fetch-site", "same-origin")
            .send()
            .await
            .expect("decide");
        assert_ne!(
            same_origin.status(),
            403,
            "a same-origin {act} is not a CSRF"
        );
    }
}
