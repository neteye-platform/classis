//! One upstream connection, described once and built here (ADR-0010).
//!
//! The application says *what* to connect with: the endpoint, the credential, the trust anchors and
//! the identity, the limit and the intervals. Everything else is built in this module: the rustls
//! configuration for `wss://`, the HTTP client for `https://`, the headers, the transport. The same
//! description drives a long-running connection ([`run`]), a one-shot proof that offered settings
//! work ([`probe`]), and a single socket for a caller that drives its own ([`connect_websocket`]).

use std::sync::Arc;
use std::time::Duration;

use prost::Message as _;
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;
use tokio_tungstenite::tungstenite::http::{HeaderMap, HeaderValue};

use super::{http, ws, Ended, Session, StopSignal};
use crate::endpoint::check_url;
use crate::endpoint::PROTOBUF_CONTENT_TYPE;
use crate::proto::AgentToServer;
use crate::tls::{certificates, client_builder, private_key, root_store, Identity};

/// How long one plain-HTTP exchange, and the probe, may take.
pub const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Whom a client trusts and what it presents, as PEM.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientTls {
    /// The CA certificates to trust. They *replace* the built-in roots, so a private deployment
    /// trusts its own CA and nobody else. `None` trusts the built-in web roots.
    pub ca_pem: Option<Vec<u8>>,
    /// The client certificate a server demanding mutual TLS asks for.
    pub identity: Option<Identity>,
}

impl ClientTls {
    /// The rustls configuration for `wss://`, always built here — never the transport's default,
    /// which would take whatever provider the process happens to have, TLS 1.2 included
    /// (ADR-0010). Nothing configured means the web roots and no client certificate. Always
    /// `Some`; the `Option` keeps the callers' shape.
    ///
    /// # Errors
    /// Returns an error naming the part — CA, certificate or key — that cannot be used.
    pub fn rustls_config(&self) -> Result<Option<Arc<rustls::ClientConfig>>, String> {
        let roots = match &self.ca_pem {
            Some(pem) => root_store(pem).map_err(|e| format!("the CA: {e}"))?,
            // An identity does not imply a private CA: presenting a client certificate to a
            // server with a publicly trusted one is an ordinary deployment.
            None => rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            },
        };
        let builder = client_builder().with_root_certificates(roots);
        let config = match &self.identity {
            None => builder.with_no_client_auth(),
            Some(identity) => builder
                .with_client_auth_cert(
                    certificates(&identity.cert_pem)
                        .map_err(|e| format!("the client certificate: {e}"))?,
                    private_key(&identity.key_pem).map_err(|e| format!("the client key: {e}"))?,
                )
                .map_err(|e| format!("cannot present the client certificate: {e}"))?,
        };
        Ok(Some(Arc::new(config)))
    }

    /// Applies the trust anchors alone to an HTTP client: what a download from a host that is not
    /// the server needs, since an identity is for the server and not for whoever hosts a file.
    ///
    /// # Errors
    /// Returns an error when the CA cannot be parsed.
    pub fn trust(&self, builder: reqwest::ClientBuilder) -> Result<reqwest::ClientBuilder, String> {
        // The floor holds even should a process provider other than `tls::provider` be installed.
        let builder = builder.tls_version_min(reqwest::tls::Version::TLS_1_3);
        let Some(pem) = &self.ca_pem else {
            return Ok(builder);
        };
        let certs = reqwest::Certificate::from_pem_bundle(pem)
            .map_err(|e| format!("the CA: cannot parse a certificate: {e}"))?;
        if certs.is_empty() {
            return Err("the CA: no certificates".to_string());
        }
        // `tls_certs_only`: the configured CA replaces the built-in roots, as for `wss://`.
        Ok(builder.tls_certs_only(certs))
    }

    /// Applies the trust anchors and the identity to an HTTP client: what talking to the server
    /// over `https://` needs.
    ///
    /// # Errors
    /// Returns an error when the CA or the identity cannot be used.
    pub fn apply(&self, builder: reqwest::ClientBuilder) -> Result<reqwest::ClientBuilder, String> {
        let builder = self.trust(builder)?;
        let Some(identity) = &self.identity else {
            return Ok(builder);
        };
        // reqwest's rustls backend takes key and certificate as one PEM buffer, key first.
        let mut pem = identity.key_pem.clone();
        if !pem.ends_with(b"\n") {
            pem.push(b'\n');
        }
        pem.extend_from_slice(&identity.cert_pem);
        let identity = reqwest::Identity::from_pem(&pem)
            .map_err(|e| format!("cannot present the client certificate: {e}"))?;
        Ok(builder.identity(identity))
    }
}

/// The transport an endpoint's scheme names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// `ws://` or `wss://`.
    WebSocket,
    /// `http://` or `https://`.
    Http,
}

impl Scheme {
    /// The transport `endpoint` names.
    ///
    /// # Errors
    /// Returns an error for any other scheme.
    pub fn of(endpoint: &str) -> Result<Scheme, String> {
        match endpoint.split("://").next() {
            Some("ws" | "wss") => Ok(Scheme::WebSocket),
            Some("http" | "https") => Ok(Scheme::Http),
            _ => Err(format!(
                "endpoint {endpoint} must start with ws://, wss://, http:// or https://"
            )),
        }
    }
}

/// Everything one upstream connection is built from.
#[derive(Clone)]
pub struct Connection {
    /// `ws://`, `wss://`, `http://` or `https://`; the scheme picks the transport.
    pub endpoint: String,
    /// The `Authorization` header value, sent with the upgrade request or with every exchange.
    pub authorization: Option<String>,
    pub tls: ClientTls,
    /// The largest message received or sent.
    pub max_message_size: usize,
    /// On a WebSocket, a routine report per Agent this often; `None` sends none.
    pub heartbeat: Option<Duration>,
    /// On plain HTTP, how long to wait between cycles once nothing is owed.
    pub poll: Duration,
}

impl std::fmt::Debug for Connection {
    /// The credential is a secret, so a `Debug` of a connection never prints it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("endpoint", &self.endpoint)
            .field(
                "authorization",
                &self.authorization.as_ref().map(|_| "<redacted>"),
            )
            .field("tls", &self.tls)
            .field("max_message_size", &self.max_message_size)
            .field("heartbeat", &self.heartbeat)
            .field("poll", &self.poll)
            .finish()
    }
}

impl Connection {
    /// The transport this connection may use. `ws://` and `http://` are refused unless the host is
    /// the loopback literal `127.0.0.1` or `::1` (specification Q-1): off the loopback everything
    /// is TLS 1.3, and a host name never counts as loopback.
    ///
    /// # Errors
    /// Returns an error for an unknown scheme, or for plaintext off the loopback.
    pub fn scheme(&self) -> Result<Scheme, String> {
        let scheme = Scheme::of(&self.endpoint)?;
        check_url(&self.endpoint).map_err(|e| format!("refusing {e}"))?;
        Ok(scheme)
    }

    /// The headers of a WebSocket upgrade: the credential, marked sensitive so that no `Debug` of
    /// the request prints it.
    ///
    /// # Errors
    /// Returns an error when the credential is not a valid header value.
    pub fn headers(&self) -> Result<HeaderMap, String> {
        let mut headers = HeaderMap::new();
        if let Some(value) = &self.authorization {
            let mut value: HeaderValue = value
                .parse()
                .map_err(|e| format!("the credentials are not a valid header: {e}"))?;
            value.set_sensitive(true);
            headers.insert(AUTHORIZATION, value);
        }
        Ok(headers)
    }

    /// The HTTP client of the plain-HTTP transport and of the probe.
    ///
    /// It follows no redirect: an OpAMP endpoint is a fixed address and never legitimately
    /// redirects, so following one would only let a compromised or misconfigured server bounce an
    /// authenticated session elsewhere. The credential rides every request, marked sensitive.
    ///
    /// # Errors
    /// Returns an error when the TLS material or the credential cannot be used.
    pub fn http_client(&self) -> Result<reqwest::Client, String> {
        let mut builder = reqwest::Client::builder()
            .use_rustls_tls()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(HTTP_TIMEOUT);
        if let Some(value) = &self.authorization {
            let mut value = reqwest::header::HeaderValue::from_str(value)
                .map_err(|e| format!("the credentials are not a valid header: {e}"))?;
            value.set_sensitive(true);
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(reqwest::header::AUTHORIZATION, value);
            builder = builder.default_headers(headers);
        }
        self.tls
            .apply(builder)?
            .build()
            .map_err(|e| format!("cannot build the HTTP client: {e}"))
    }

    fn connector(&self) -> Result<Option<ws::Connector>, String> {
        Ok(self.tls.rustls_config()?.map(ws::Connector::Rustls))
    }

    /// Opens one WebSocket to the endpoint with this connection's credential and TLS, for a caller
    /// that drives the socket itself.
    ///
    /// # Errors
    /// Returns an error when the material cannot be used or the server cannot be reached.
    pub async fn connect_websocket(&self) -> Result<ws::Socket, String> {
        self.scheme()?;
        ws::connect(
            &self.endpoint,
            &self.headers()?,
            self.connector()?,
            self.max_message_size,
        )
        .await
        .map_err(|e| format!("cannot reach {}: {e}", self.endpoint))
    }
}

/// Runs the session over the transport the endpoint's scheme names, until it is stopped or asks
/// to end.
///
/// # Errors
/// Returns an error when the endpoint or the material cannot be used.
pub async fn run<S: Session, X: StopSignal>(
    connection: &Connection,
    session: &mut S,
    stop: &mut X,
) -> Result<Ended, String> {
    match connection.scheme()? {
        Scheme::WebSocket => {
            let settings = ws::Settings {
                endpoint: connection.endpoint.clone(),
                headers: connection.headers()?,
                connector: connection.connector()?,
                max_message_size: connection.max_message_size,
                heartbeat: connection.heartbeat,
            };
            ws::run(&settings, session, stop).await
        }
        Scheme::Http => {
            let settings = http::Settings {
                endpoint: connection.endpoint.clone(),
                client: connection.http_client()?,
                poll: connection.poll,
                max_message_size: connection.max_message_size,
            };
            http::run(&settings, session, stop).await
        }
    }
}

/// Proves that a server answers on this connection, by connecting once — what a client must do
/// before it adopts offered connection settings. A WebSocket is opened and closed again; on plain
/// HTTP, `report` is sent and any success status counts.
///
/// # Errors
/// Returns why the server could not be reached or refused.
pub async fn probe(
    connection: &Connection,
    report: impl FnOnce() -> Option<AgentToServer>,
) -> Result<(), String> {
    match connection.scheme()? {
        Scheme::WebSocket => {
            let mut socket = connection.connect_websocket().await?;
            let _ = futures_util::SinkExt::close(&mut socket).await;
            Ok(())
        }
        Scheme::Http => {
            let report = report().ok_or("no agent to build a probe report from")?;
            let endpoint = &connection.endpoint;
            let response = connection
                .http_client()?
                .post(endpoint)
                .header(reqwest::header::CONTENT_TYPE, PROTOBUF_CONTENT_TYPE)
                .body(report.encode_to_vec())
                .send()
                .await
                .map_err(|e| format!("cannot reach {endpoint}: {e}"))?;
            let status = response.status();
            if !status.is_success() {
                return Err(format!("{endpoint} answered {status}"));
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connection(endpoint: &str, authorization: Option<&str>) -> Connection {
        Connection {
            endpoint: endpoint.to_string(),
            authorization: authorization.map(str::to_string),
            tls: ClientTls::default(),
            max_message_size: 1024,
            heartbeat: None,
            poll: Duration::from_secs(1),
        }
    }

    /// Verifies: ADR-0010
    #[test]
    fn the_scheme_picks_the_transport_and_anything_else_is_refused() {
        assert_eq!(Scheme::of("wss://h/v1/opamp"), Ok(Scheme::WebSocket));
        assert_eq!(Scheme::of("ws://h/v1/opamp"), Ok(Scheme::WebSocket));
        assert_eq!(Scheme::of("https://h/v1/opamp"), Ok(Scheme::Http));
        assert_eq!(Scheme::of("http://h/v1/opamp"), Ok(Scheme::Http));
        assert!(Scheme::of("ftp://h/v1/opamp").is_err());
        assert!(Scheme::of("h/v1/opamp").is_err());
    }

    /// Verifies: ADR-0010, ADR-0013
    #[test]
    fn plaintext_is_refused_off_the_loopback_literals() {
        let allowed = |endpoint| connection(endpoint, Some("Bearer t")).scheme();
        assert_eq!(
            allowed("ws://127.0.0.1:4320/v1/opamp"),
            Ok(Scheme::WebSocket)
        );
        assert_eq!(allowed("http://[::1]:4320/v1/opamp"), Ok(Scheme::Http));
        assert_eq!(
            allowed("wss://fleet.example/v1/opamp"),
            Ok(Scheme::WebSocket)
        );
        assert_eq!(allowed("https://10.0.0.1/v1/opamp"), Ok(Scheme::Http));
        for endpoint in [
            "ws://fleet.example:4320/v1/opamp",
            "http://10.0.0.1/v1/opamp",
            "ws://localhost:4320/v1/opamp",
            "http://127.0.0.1.evil.example/v1/opamp",
            "http://user@10.0.0.1/v1/opamp",
        ] {
            assert!(allowed(endpoint).is_err(), "{endpoint} was allowed");
        }
        // Without a credential plaintext is no less readable, and no more allowed.
        assert!(connection("ws://fleet.example/v1/opamp", None)
            .scheme()
            .is_err());
    }

    /// Verifies: ADR-0010, ADR-0013
    #[tokio::test]
    async fn plaintext_off_the_loopback_is_refused_before_connecting() {
        let refused = connection("ws://192.0.2.1:9/v1/opamp", None);
        let error = probe(&refused, || None).await.expect_err("refused");
        assert!(error.starts_with("refusing"), "{error}");
    }

    #[test]
    fn the_credential_header_is_sensitive() {
        let headers = connection("ws://h/v1/opamp", Some("Bearer t"))
            .headers()
            .expect("headers");
        assert!(headers[AUTHORIZATION].is_sensitive());
        assert!(connection("ws://h/v1/opamp", Some("a\nb"))
            .headers()
            .is_err());
    }

    #[test]
    fn the_debug_form_of_a_connection_hides_its_credential() {
        let shown = format!(
            "{:?}",
            connection("wss://h/v1/opamp", Some("Bearer secret"))
        );
        assert!(!shown.contains("secret"), "{shown}");
    }

    /// Verifies: ADR-0010
    #[test]
    fn no_tls_material_still_offers_tls_1_3_alone() {
        let config = ClientTls::default()
            .rustls_config()
            .expect("config")
            .expect("always built here");
        assert!(config
            .crypto_provider()
            .cipher_suites
            .iter()
            .all(|suite| suite.version() == &rustls::version::TLS13));
    }

    #[test]
    fn unusable_tls_material_names_the_part() {
        let tls = ClientTls {
            ca_pem: Some(b"not pem".to_vec()),
            identity: None,
        };
        let error = tls.rustls_config().expect_err("no CA in it");
        assert!(error.starts_with("the CA:"), "{error}");
    }
}
