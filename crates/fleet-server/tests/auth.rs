//! Which plane answers what: the OpAMP endpoint is the Agent plane's, and the REST API is the
//! Operator plane's alone (ADR-0013).

mod support;

use support::spawn;

/// The REST API answers on the Operator plane's own listener (ADR-0013), where authenticating it is
/// a separate decision from the Agent plane's admission, and it is *not* served on the Agent plane
/// at all, which is what the split is. The name is kept because accepted ADRs cite it.
/// Verifies: ADR-0013
#[tokio::test]
async fn the_rest_api_stays_open_on_its_own_listener_when_the_opamp_endpoint_is_guarded() {
    let server = spawn().await;
    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/api/v1/agents", server.rest_addr))
        .send()
        .await
        .expect("get");
    assert_eq!(
        response.status(),
        200,
        "operator auth is a separate decision"
    );

    let on_the_agent_plane = client
        .get(format!("http://{}/api/v1/agents", server.addr))
        .send()
        .await
        .expect("get");
    assert_eq!(
        on_the_agent_plane.status(),
        404,
        "the fleet view is not served where the Agents connect"
    );
}
