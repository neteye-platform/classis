//! The Agent's own telemetry (ADR-0016): OTLP/HTTP to the destinations the Server names.
//!
//! Three capabilities, one mechanism. `ReportsOwnMetrics`, `ReportsOwnTraces`, and `ReportsOwnLogs`
//! each mean "the Agent can report own <signal> to the destination specified by the Server via
//! `ConnectionSettingsOffers.own_*`" — so nothing here is configured in `supervisor.toml`, and with no
//! destination offered this module builds nothing and costs nothing.
//!
//! What "own" means here is what this Client can honestly observe: its own process, and the
//! Managed Processes it spawned and holds the pids of. It does **not** reach into a Collector's
//! internal telemetry the way upstream's supervisor does — ADR-0017 forbids this Client from
//! touching a Managed Process's configuration, and the specification's non-goal forbids inventing
//! an abstraction over it.
//!
//! The wire format is the standard's own implementation rather than a copy of its schema: the
//! exporters come from `opentelemetry-otlp` over HTTP with protobuf bodies, which is what the
//! Baseline's `destination_endpoint` requires, and the names come from
//! `opentelemetry-semantic-conventions` rather than string literals of this project's own.

use std::collections::HashMap;

use std::time::Duration;

use opamp::attributes::{
    string_value, HOST_ARCH, OS_DESCRIPTION, OS_TYPE, SERVICE_INSTANCE_NAME, SERVICE_NAME,
};
use opamp::proto::{AgentDescription, ConnectionSettingsOffers, TelemetryConnectionSettings};
use opentelemetry::metrics::MeterProvider as _;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_otlp::{
    LogExporter, MetricExporter, SpanExporter, WithExportConfig, WithHttpConfig,
};
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use tracing::{info, warn};

use crate::config::ClientConfig;

/// How often process metrics are sampled, and how often the exporter ships them.
///
/// The Baseline's recommendation for own metrics, taken as written: *"The Agent SHOULD periodically
/// report its metrics to the destination offered in the own_metrics field. The recommended
/// reporting interval is 10 seconds."*
///
/// One constant for both halves on purpose. What reaches the backend is only as fresh as the
/// sampling behind it: exporting every 10 s off a 30 s sample would ship each value three times and
/// turn a gauge series into a step function — a reporting interval in name only. The SDK's periodic
/// reader defaults to 60 s and must therefore be told this explicitly; leaving it at the default is
/// how the interval silently became six times the recommendation.
const SAMPLE_INTERVAL: Duration = Duration::from_secs(10);

/// How long one export may take before it is abandoned.
///
/// Nothing else on the export path bounds it. The SDK's `PeriodicReader` says so in its own
/// documentation — *"does **not** enforce a timeout for exports … If an export operation never
/// returns, `PeriodicReader` will **stop exporting new metrics**"* — and the batch processors
/// behind traces and logs block on their export the same way, then drop records once their queue
/// fills. `opentelemetry-otlp` resolves a timeout but applies it only to the HTTP client it builds
/// itself; the one handed to it through `with_http_client` keeps whatever bound it was built with,
/// and `reqwest`'s default is none. A destination that stops answering rather than refusing — a
/// host asleep, a NAT that dropped the mapping, a network gone dark — therefore left the exporter
/// thread blocked on a socket that never closes, and own telemetry stayed dead until this Client
/// was restarted. That is the failure this bound exists for: refusal already recovers by itself,
/// since OTLP/HTTP is a fresh request per interval and the next one simply succeeds.
///
/// Half the reporting interval, so a stalled export gives up in time for the next one to be tried
/// on schedule. A bound at the interval would have every cycle finish late, and the reader answers
/// a late export by running the next one immediately — the stall would turn into a queue.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(SAMPLE_INTERVAL.as_secs() / 2);

/// The instrumentation scope every signal this Client emits is attributed to.
const SCOPE: &str = "opamp-fleet-client";

/// The non-identifying attributes the Resource carries beside what identifies the Agent — named
/// one by one rather than taken as a bag.
///
/// **Why a list and not "everything non-identifying".** That bag also holds `host.ip`, `host.mac`
/// and whatever the operator wrote under `[attributes]` in `supervisor.toml`. ADR-0016 says out loud
/// that the Resource is what leaves the host for a destination the *Server* named, so widening this
/// to the whole bag is a decision about what gets sent somewhere else — naming what describes the
/// platform is not.
///
/// - `service.instance.name` is non-identifying only because the Baseline has no key for a human
///   instance name and identity stays `service.instance.id` (ADR-0016) — that is a statement about
///   *identity*, not about what the telemetry is worth carrying. Without it every series at the
///   receiving end is a uuid the operator cannot place against the fleet view they searched by.
/// - `os.type` and `host.arch` are the two halves this project calls a platform (ADR-0026), and
///   `os.description` is the readable form of the first. They sit on the Resource rather than on
///   each sample because they are a property of the *host*: this Client samples its own process and
///   the Managed Processes it holds the pids of, so every Agent in one export runs on the machine
///   this Resource describes. Per-sample they would be a constant repeated on every data point.
///
/// Each is reported only where the description carries it — an absent attribute says "unknown",
/// where one carrying a placeholder would say something false.
const DESCRIPTIVE_ATTRIBUTES: [&str; 4] =
    [SERVICE_INSTANCE_NAME, OS_TYPE, HOST_ARCH, OS_DESCRIPTION];

/// The layer the `tracing` subscriber reserves for the OTLP bridge, so a destination that arrives
/// at runtime has somewhere to go (ADR-0016).
///
/// A global, because the subscriber it belongs to is one: `tracing` has exactly one, installed
/// before anything is configured, and the bridge cannot be added to it afterwards without a slot
/// held open from the start. Nothing else here is global — the providers are owned.
type BridgeLayer = Option<
    opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge<
        SdkLoggerProvider,
        opentelemetry_sdk::logs::SdkLogger,
    >,
>;
static BRIDGE: std::sync::OnceLock<tracing_subscriber::reload::Handle<BridgeLayer, WithSpans>> =
    std::sync::OnceLock::new();

/// The second slot, for the span exporter (ADR-0016). The appender above converts `tracing`
/// *events* and says so in its own documentation; this is what converts `tracing` *spans*, and
/// without it the `own_traces` exporter has nothing to export.
///
/// Two slots rather than one, because the two destinations are independent: an offer may name
/// traces and not logs, or withdraw one and keep the other (ADR-0016).
///
/// Public because `main` builds the slot and has to name what it holds — the subscriber is
/// installed there, long before this module has anything to put in it.
pub type SpanLayer = Option<
    tracing_opentelemetry::OpenTelemetryLayer<
        tracing_subscriber::Registry,
        opentelemetry_sdk::trace::SdkTracer,
    >,
>;

/// The subscriber the *log* slot sits on: the registry with the span slot already added.
///
/// The span slot goes on first so the layer inside it is typed for the bare `Registry` rather than
/// for a stack of layers. The order is otherwise immaterial — the filter that governs both is a
/// layer of the same subscriber, so neither slot filters the other.
pub type WithSpans = tracing_subscriber::layer::Layered<
    tracing_subscriber::reload::Layer<SpanLayer, tracing_subscriber::Registry>,
    tracing_subscriber::Registry,
>;

static SPANS: std::sync::OnceLock<
    tracing_subscriber::reload::Handle<SpanLayer, tracing_subscriber::Registry>,
> = std::sync::OnceLock::new();

/// Hands this module the slot the subscriber reserved. Called once, from the binary's startup.
pub fn hold_log_bridge(handle: tracing_subscriber::reload::Handle<BridgeLayer, WithSpans>) {
    let _ = BRIDGE.set(handle);
}

/// The same, for the span slot (ADR-0016).
pub fn hold_span_layer(
    handle: tracing_subscriber::reload::Handle<SpanLayer, tracing_subscriber::Registry>,
) {
    let _ = SPANS.set(handle);
}

fn set_spans(provider: Option<&SdkTracerProvider>) {
    let Some(handle) = SPANS.get() else {
        return;
    };
    let layer =
        provider.map(|provider| tracing_opentelemetry::layer().with_tracer(provider.tracer(SCOPE)));
    if let Err(e) = handle.modify(|slot| *slot = layer) {
        warn!(error = %e, "cannot install the OTLP span layer");
    }
}

pub use crate::span::{failed, succeeded, STATUS_CODE, STATUS_DESCRIPTION};

/// The trace the operation in force belongs to, as the two hex ids that identify it — or `None`
/// when nothing is being traced, which is every run with no destination offered.
///
/// Exists so a caller can persist a trace across something a span cannot survive: the self-update's
/// restart (ADR-0016 clause 20), where the process that stages a version is not the process that
/// commits or rolls back one. The OpenTelemetry types stay here; what leaves this module is two
/// strings.
#[must_use]
pub fn current_trace() -> Option<(String, String)> {
    use opentelemetry::trace::TraceContextExt as _;
    use tracing_opentelemetry::OpenTelemetrySpanExt as _;
    let context = tracing::Span::current().context();
    let span = context.span();
    let context = span.span_context();
    context.is_valid().then(|| {
        (
            context.trace_id().to_string(),
            context.span_id().to_string(),
        )
    })
}

/// Makes `span` a continuation of the trace [`current_trace`] returned in an earlier process.
///
/// The parent is marked **remote**, which is what it is: the span it names ended with a process
/// that is gone. Ids that do not parse are ignored rather than reported — they come from a file an
/// older version wrote, and a trace is not worth failing an update over.
pub fn continue_trace(span: &tracing::Span, trace_id: &str, span_id: &str) {
    use opentelemetry::trace::{SpanContext, SpanId, TraceContextExt as _, TraceFlags, TraceId};
    use tracing_opentelemetry::OpenTelemetrySpanExt as _;
    let (Ok(trace_id), Ok(span_id)) = (TraceId::from_hex(trace_id), SpanId::from_hex(span_id))
    else {
        return;
    };
    let parent = SpanContext::new(
        trace_id,
        span_id,
        TraceFlags::SAMPLED,
        true,
        opentelemetry::trace::TraceState::default(),
    );
    // The error case is "there is no such span to give a parent to" — a closed span, or a run with
    // no subscriber interested in it. Nothing to report: this whole function is best-effort
    // decoration on an update that proceeds either way.
    let _ = span.set_parent(opentelemetry::Context::new().with_remote_span_context(parent));
}

fn set_bridge(provider: Option<&SdkLoggerProvider>) {
    let Some(handle) = BRIDGE.get() else {
        return;
    };
    let layer = provider.map(|provider| {
        opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(provider)
    });
    if let Err(e) = handle.modify(|slot| *slot = layer) {
        warn!(error = %e, "cannot install the OTLP log bridge");
    }
}

pub use crate::engine::SamplingTarget;

/// The providers currently in force, if any.
///
/// Held rather than left to the SDK's globals because the destination is not a startup decision: it
/// arrives from the Server and can change. Applying a new offer means building fresh providers and
/// shutting these down, which needs a handle on exactly what is running.
///
/// **Interior mutability, deliberately.** The exporters outlive a connection (ADR-0016), so this is
/// owned by the runtime loop — but a destination is put in force from *inside* a transport, where
/// the offer's acknowledgement is composed (ADR-0014). Both the sampler arm of the runtime's
/// `select!` and the transport future it drives therefore hold this at once, which `&mut self`
/// cannot express. One `Mutex` gives both a shared borrow and costs nothing else: every method
/// under the lock is synchronous, so the guard is never held across an `.await` and no deadlock
/// class is introduced. An `Arc` would buy a clone nobody needs.
///
/// **Replacing a destination never waits on the old one.** Shutting a provider down flushes what it
/// holds, and an export to a destination that has gone silent takes its full timeout. `apply` runs
/// inside the transport, so the providers it replaces are detached at once and shut down on a
/// thread of their own; only [`Telemetry::shutdown`], on the way out, waits for every flush.
#[derive(Default)]
pub struct Telemetry {
    inner: std::sync::Mutex<Providers>,
}

#[derive(Default)]
struct Providers {
    meters: Option<SdkMeterProvider>,
    tracers: Option<SdkTracerProvider>,
    loggers: Option<SdkLoggerProvider>,
    /// The endpoints in force, so an offer that repeats them rebuilds nothing.
    in_force: Endpoints,
    /// Providers an offer replaced, still flushing on a thread of their own.
    retiring: Vec<std::thread::JoinHandle<()>>,
}

/// Providers taken out of service, detached from `tracing`, waiting to be shut down.
#[derive(Default)]
struct Retired {
    meters: Option<SdkMeterProvider>,
    tracers: Option<SdkTracerProvider>,
    loggers: Option<SdkLoggerProvider>,
}

#[derive(Default, PartialEq, Eq, Clone)]
struct Endpoints {
    metrics: Option<String>,
    traces: Option<String>,
    logs: Option<String>,
}

impl Telemetry {
    pub fn new() -> Self {
        Telemetry::default()
    }

    /// The providers, recovering from a poisoned lock rather than propagating the panic: a thread
    /// that died mid-export must not take the Client down with it.
    fn providers(&self) -> std::sync::MutexGuard<'_, Providers> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Puts the offered destinations in force, replacing whatever was running.
    ///
    /// Returns the destinations it refused, if any, so the caller can report them rather than drop
    /// them silently — the same honesty the OpAMP settings get (ADR-0021).
    pub fn apply(
        &self,
        settings: &ConnectionSettingsOffers,
        description: &AgentDescription,
        config: &ClientConfig,
    ) -> Vec<String> {
        let wanted = Endpoints {
            metrics: endpoint_of(settings.own_metrics.as_ref()),
            traces: endpoint_of(settings.own_traces.as_ref()),
            logs: endpoint_of(settings.own_logs.as_ref()),
        };
        let mut this = self.providers();
        if wanted == this.in_force {
            return Vec::new();
        }

        let mut refused = Vec::new();
        let resource = resource(description);
        let retired = this.take();
        this.retire(retired);

        if let Some(settings) = offered(settings.own_metrics.as_ref()) {
            match check(settings, "own_metrics")
                .and_then(|()| metric_provider(settings, resource.clone(), config))
            {
                Ok(provider) => this.meters = Some(provider),
                Err(e) => refused.push(e),
            }
        }
        if let Some(settings) = offered(settings.own_traces.as_ref()) {
            match check(settings, "own_traces")
                .and_then(|()| trace_provider(settings, resource.clone(), config))
            {
                Ok(provider) => {
                    opentelemetry::global::set_tracer_provider(provider.clone());
                    // The spans themselves come from this Client's `tracing` spans (ADR-0016); the
                    // global provider above is for anything reaching the OpenTelemetry API
                    // directly, which nothing here does.
                    set_spans(Some(&provider));
                    this.tracers = Some(provider);
                }
                Err(e) => refused.push(e),
            }
        }
        if let Some(settings) = offered(settings.own_logs.as_ref()) {
            match check(settings, "own_logs")
                .and_then(|()| log_provider(settings, resource, config))
            {
                Ok(provider) => {
                    set_bridge(Some(&provider));
                    this.loggers = Some(provider);
                }
                Err(e) => refused.push(e),
            }
        }

        this.in_force = wanted;
        if this.any() {
            info!("reporting own telemetry to the destinations the Server offered");
        } else if refused.is_empty() {
            // Only a withdrawal reaches here (ADR-0016): an offer that changes nothing returned
            // above, and one whose destinations were refused has something in `refused` to report.
            // An operator switching telemetry off from the fleet should see it land on the host.
            info!("the Server withdrew every own-telemetry destination; no longer reporting");
        }
        refused
    }

    /// Samples the process behind `target`'s pid and records it against that Agent's meter. A pid
    /// that has gone away records nothing — a Managed Process between restarts is not an error.
    pub fn sample(&self, system: &mut sysinfo::System, target: &SamplingTarget) {
        let this = self.providers();
        let Some(meters) = &this.meters else {
            return;
        };
        let pid = sysinfo::Pid::from_u32(target.pid);
        system.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
        let Some(process) = system.process(pid) else {
            return;
        };

        let meter = meters.meter(SCOPE);
        // Per Agent rather than left to the Resource: the Resource is the *Client's* identity
        // (`apply` is handed the self-Agent's description), so a Managed Process's series would
        // otherwise carry the Supervisor's uid, name and type. All three keys are restated here for
        // the same reason — one identifies the series, one makes it readable, and one says what the
        // Agent is. `service.name` in particular means two different things on the two levels: on
        // the Resource it is the Client's type (`supervisor`), here it is the sampled Agent's.
        let attributes = [
            KeyValue::new(
                opentelemetry_semantic_conventions::attribute::SERVICE_INSTANCE_ID,
                target.uid.clone(),
            ),
            KeyValue::new(SERVICE_INSTANCE_NAME, target.instance_name.clone()),
            KeyValue::new(SERVICE_NAME, target.service_name.clone()),
        ];
        // Gauges rather than counters: what is sampled is a level, and the exporter's periodic
        // reader is what turns a series of levels into a time series.
        meter
            .u64_gauge(opentelemetry_semantic_conventions::metric::PROCESS_MEMORY_USAGE)
            .with_unit("By")
            .build()
            .record(process.memory(), &attributes);
        meter
            .f64_gauge(opentelemetry_semantic_conventions::metric::PROCESS_CPU_UTILIZATION)
            .with_unit("1")
            .build()
            .record(f64::from(process.cpu_usage()) / 100.0, &attributes);
        meter
            .u64_gauge(opentelemetry_semantic_conventions::metric::PROCESS_UPTIME)
            .with_unit("s")
            .build()
            .record(process.run_time(), &attributes);
    }

    /// The interval between samples — the caller owns the timer, this owns the number.
    pub fn sample_interval(&self) -> Duration {
        SAMPLE_INTERVAL
    }

    /// Whether any destination is in force, so a caller can skip the sampling work entirely.
    pub fn reporting(&self) -> bool {
        self.providers().any()
    }

    /// Stops every provider in force and waits for each to flush what it holds — the ones in force
    /// and the ones an earlier offer replaced. Called on the way out; an exporter that cannot flush
    /// is logged, never fatal.
    pub fn shutdown(&self) {
        let (retired, retiring) = {
            let mut this = self.providers();
            (this.take(), std::mem::take(&mut this.retiring))
        };
        retired.shut_down();
        for handle in retiring {
            let _ = handle.join();
        }
    }
}

impl Providers {
    /// Whether any destination is in force.
    fn any(&self) -> bool {
        self.meters.is_some() || self.tracers.is_some() || self.loggers.is_some()
    }

    /// Takes every provider out of service at once. The span layer and the log bridge are detached
    /// here, before anything is shut down: a span opened or an event logged afterwards must not
    /// reach an exporter that is closing, which is how a flush deadlocks.
    fn take(&mut self) -> Retired {
        let retired = Retired {
            meters: self.meters.take(),
            tracers: self.tracers.take(),
            loggers: self.loggers.take(),
        };
        if retired.tracers.is_some() {
            set_spans(None);
        }
        if retired.loggers.is_some() {
            set_bridge(None);
        }
        retired
    }

    /// Shuts `retired` down on a thread of its own, so the caller does not wait for its flush.
    /// Should no thread be had, it is shut down here instead: late, but not lost.
    fn retire(&mut self, retired: Retired) {
        self.retiring.retain(|handle| !handle.is_finished());
        if !retired.any() {
            return;
        }
        let shared = std::sync::Arc::new(std::sync::Mutex::new(Some(retired)));
        let on_thread = shared.clone();
        let spawned = std::thread::Builder::new()
            .name("telemetry-retire".to_string())
            .spawn(move || {
                let retired = on_thread
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                if let Some(retired) = retired {
                    retired.shut_down();
                }
            });
        match spawned {
            Ok(handle) => self.retiring.push(handle),
            Err(e) => {
                warn!(error = %e, "no thread to retire the replaced exporters on; shutting them down here");
                let retired = shared
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                if let Some(retired) = retired {
                    retired.shut_down();
                }
            }
        }
    }
}

impl Retired {
    fn any(&self) -> bool {
        self.meters.is_some() || self.tracers.is_some() || self.loggers.is_some()
    }

    /// Shuts every provider down, flushing what each holds.
    fn shut_down(self) {
        if let Some(provider) = self.meters {
            if let Err(e) = provider.shutdown() {
                warn!(error = %e, "the metrics exporter did not shut down cleanly");
            }
        }
        if let Some(provider) = self.tracers {
            if let Err(e) = provider.shutdown() {
                warn!(error = %e, "the traces exporter did not shut down cleanly");
            }
        }
        if let Some(provider) = self.loggers {
            if let Err(e) = provider.shutdown() {
                warn!(error = %e, "the logs exporter did not shut down cleanly");
            }
        }
    }
}

/// The destination a field offers, if it offers one.
///
/// An endpoint offered **empty** is a withdrawal (ADR-0016), not a malformed URL: the exporter for
/// that signal is shut down, nothing is built in its place, and nothing is reported about it. The
/// Server is saying stop, and stopping is not a failure to be handed back as one.
fn offered(settings: Option<&TelemetryConnectionSettings>) -> Option<&TelemetryConnectionSettings> {
    settings.filter(|s| !s.destination_endpoint.is_empty())
}

fn endpoint_of(settings: Option<&TelemetryConnectionSettings>) -> Option<String> {
    offered(settings).map(|s| s.destination_endpoint.clone())
}

/// The Baseline's "MAY refuse to send the telemetry if the URL begins with `http://`", taken.
///
/// The Resource carries the Agent's identifying attributes and the log records carry whatever this
/// Client logs, so plaintext is refused anywhere but on the host itself: the loopback literals
/// `127.0.0.1` and `::1` (ADR-0016). A private address is not a private network, and a name is
/// not an address. `tls` and `proxy` are refused for the same reasons they are on the OpAMP
/// settings (ADR-0014 clause 8).
fn check(settings: &TelemetryConnectionSettings, field: &str) -> Result<(), String> {
    let endpoint = &settings.destination_endpoint;
    if endpoint.starts_with("http://") && opamp::endpoint::check_url(endpoint).is_err() {
        return Err(format!(
            "{field}: refusing to send own telemetry to {endpoint} in cleartext — a cleartext \
             destination must be 127.0.0.1 or ::1, otherwise use https://"
        ));
    }
    if !endpoint.starts_with("https://") && !endpoint.starts_with("http://") {
        return Err(format!(
            "{field}: {endpoint} is not an OTLP/HTTP endpoint — the protocol requires a full \
             http(s) URL with path"
        ));
    }
    let mut unhonoured = Vec::new();
    if settings.tls.is_some() {
        unhonoured.push("tls");
    }
    if settings.proxy.is_some() {
        unhonoured.push("proxy");
    }
    // An offered certificate *is* honoured (ADR-0016 point 32) — but only its `cert`, paired with
    // the key this Client already holds. A `private_key` in the offer is a key the Server generated
    // for us, and ADR-0021's rule is that this Client's private key never leaves its host and is
    // never handed to it: that is the whole point of asking for a certificate through a CSR. Refused
    // by name rather than quietly ignored, so a Server issuing pairs learns why nothing happened.
    if settings
        .certificate
        .as_ref()
        .is_some_and(|certificate| !certificate.private_key.is_empty())
    {
        unhonoured.push("certificate.private_key");
    }
    if !unhonoured.is_empty() {
        return Err(format!(
            "{field}: this Client does not implement the offered {} settings",
            unhonoured.join(" and ")
        ));
    }
    Ok(())
}

/// An OTLP HTTP client bound to the Tokio runtime this process runs on.
///
/// **Why this wrapper exists.** The SDK's exporters do not run on the async runtime. A
/// `BatchLogProcessor` — and the metrics `PeriodicReader`, and the span batch processor — each
/// spawn a **dedicated OS thread** and drive the export with `futures_executor::block_on`. That
/// thread has no Tokio reactor. An asynchronous `reqwest::Client` handed to it panics the moment it
/// resolves a name:
///
/// ```text
/// thread 'OpenTelemetry.Logs.BatchProcessor' panicked at hyper-util .../connect/dns.rs:
/// there is no reactor running, must be called from the context of a Tokio 1.x runtime
/// ```
///
/// This is not a consequence of supplying our own client: with the `reqwest-client` feature
/// `opentelemetry-otlp` builds exactly the same asynchronous client when given none, so the fault
/// comes with the feature ADR-0016 chose and shows only once a destination is actually offered.
/// ADR-0016's reasoning — *"this Client is a tokio process"* — is true of the process and false of
/// the thread the export happens on.
///
/// The fix keeps the asynchronous client the ADR chose and puts the work where it belongs: every
/// request is `spawn`ed onto the runtime handle captured when the exporter was built, and the
/// exporter thread merely awaits the join. Awaiting a `JoinHandle` needs no reactor of its own —
/// it is a waker-driven channel — so the blocking executor on that thread is satisfied while the
/// socket work happens on the runtime that owns the reactor.
struct RuntimeBoundClient {
    client: reqwest::Client,
    handle: tokio::runtime::Handle,
}

#[async_trait::async_trait]
impl opentelemetry_http::HttpClient for RuntimeBoundClient {
    async fn send_bytes(
        &self,
        request: opentelemetry_http::Request<opentelemetry_http::Bytes>,
    ) -> Result<
        opentelemetry_http::Response<opentelemetry_http::Bytes>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let client = self.client.clone();
        // The request/response translation stays the library's: this delegates to its own
        // `HttpClient for reqwest::Client`, only from inside the runtime.
        self.handle
            .spawn(
                async move { opentelemetry_http::HttpClient::send_bytes(&client, request).await },
            )
            .await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("the OTLP export task did not complete: {e}").into()
            })?
    }
}

impl std::fmt::Debug for RuntimeBoundClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RuntimeBoundClient")
    }
}

/// The HTTP client the OTLP exporters send through: this Client's TLS trust, plus the client
/// certificate the offer named, if it named one. Without an offered certificate it presents none —
/// the fleet identity is for the Server, not for a telemetry destination (ADR-0016) — and it
/// follows no redirect, so a destination cannot steer the export to another host or to plaintext.
///
/// The certificate machinery is ADR-0021's, reused as-is (ADR-0016 point 32): the offered `cert` is
/// paired with the key already on disk — the one the CSR was made for — because that key is what
/// proves the certificate belongs to this host, and it never travels.
///
/// `ca_cert` is deliberately *not* added to the trust store. The Baseline is explicit about it:
/// *"It is not recommended that the Agent accepts this CA as an authority for any purposes."* It
/// exists so a TLS-terminating intermediary can verify the client later, not so the Agent can widen
/// whom it trusts on a Server's say-so — the same reasoning that refuses `tls`.
fn exporter_client(
    settings: &TelemetryConnectionSettings,
    field: &str,
    config: &ClientConfig,
) -> Result<RuntimeBoundClient, String> {
    let offered = settings
        .certificate
        .as_ref()
        .map(|certificate| certificate.cert.as_slice())
        .filter(|cert| !cert.is_empty());
    let tls = match offered {
        Some(cert) => crate::tls::client_tls_for(config, Some(cert)),
        None => crate::tls::trust(config),
    };
    let builder = tls
        .and_then(|tls| {
            tls.apply(
                // The timeout belongs here rather than on the exporter: `opentelemetry-otlp` keeps
                // its own for the client it would have built, and never applies it to this one.
                reqwest::Client::builder()
                    .use_rustls_tls()
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(EXPORT_TIMEOUT),
            )
        })
        .map_err(|e| format!("{field}: {e}"))?;
    let client = builder
        .build()
        .map_err(|e| format!("{field}: cannot build the OTLP client: {e}"))?;
    // Captured here, on the runtime thread that applies the offer — the exporter thread this is
    // handed to has no runtime of its own to ask.
    let handle = tokio::runtime::Handle::try_current().map_err(|_| {
        format!("{field}: own telemetry can only be started from within the Tokio runtime")
    })?;
    Ok(RuntimeBoundClient { client, handle })
}

/// The OTLP Resource: the Agent's identifying attributes, as the Baseline asks — "the combination
/// of identifying attributes SHOULD be sufficient to uniquely identify the Agent's own telemetry"
/// — plus the one name that makes the result readable.
fn resource(description: &AgentDescription) -> Resource {
    let attributes = description.identifying_attributes.iter().filter_map(|kv| {
        let value = match kv.value.as_ref()?.value.as_ref()? {
            opamp::proto::any_value::Value::StringValue(s) => s.clone(),
            _ => return None,
        };
        Some(KeyValue::new(kv.key.clone(), value))
    });
    let descriptive = DESCRIPTIVE_ATTRIBUTES.iter().filter_map(|key| {
        string_value(&description.non_identifying_attributes, key)
            .map(|value| KeyValue::new(*key, value.to_string()))
    });
    Resource::builder_empty()
        .with_attributes(attributes.chain(descriptive))
        .build()
}

fn headers(settings: &TelemetryConnectionSettings) -> HashMap<String, String> {
    settings
        .headers
        .as_ref()
        .map(|headers| {
            headers
                .headers
                .iter()
                .map(|header| (header.key.clone(), header.value.clone()))
                .collect()
        })
        .unwrap_or_default()
}

fn metric_provider(
    settings: &TelemetryConnectionSettings,
    resource: Resource,
    config: &ClientConfig,
) -> Result<SdkMeterProvider, String> {
    let exporter = MetricExporter::builder()
        .with_http()
        .with_endpoint(&settings.destination_endpoint)
        .with_headers(headers(settings))
        .with_http_client(exporter_client(settings, "own_metrics", config)?)
        .build()
        .map_err(|e| format!("own_metrics: cannot build the exporter: {e}"))?;
    // The reader is built explicitly rather than through `with_periodic_exporter`, which would take
    // the SDK's 60 s default and quietly miss the Baseline's recommended reporting interval.
    let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(exporter)
        .with_interval(SAMPLE_INTERVAL)
        .build();
    Ok(SdkMeterProvider::builder()
        .with_resource(resource)
        .with_reader(reader)
        .build())
}

fn trace_provider(
    settings: &TelemetryConnectionSettings,
    resource: Resource,
    config: &ClientConfig,
) -> Result<SdkTracerProvider, String> {
    let exporter = SpanExporter::builder()
        .with_http()
        .with_endpoint(&settings.destination_endpoint)
        .with_headers(headers(settings))
        .with_http_client(exporter_client(settings, "own_traces", config)?)
        .build()
        .map_err(|e| format!("own_traces: cannot build the exporter: {e}"))?;
    Ok(SdkTracerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build())
}

fn log_provider(
    settings: &TelemetryConnectionSettings,
    resource: Resource,
    config: &ClientConfig,
) -> Result<SdkLoggerProvider, String> {
    let exporter = LogExporter::builder()
        .with_http()
        .with_endpoint(&settings.destination_endpoint)
        .with_headers(headers(settings))
        .with_http_client(exporter_client(settings, "own_logs", config)?)
        .build()
        .map_err(|e| format!("own_logs: cannot build the exporter: {e}"))?;
    Ok(SdkLoggerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use opamp::proto::{
        any_value, AnyValue, KeyValue as ProtoKeyValue, TlsCertificate, TlsConnectionSettings,
    };

    fn description() -> AgentDescription {
        AgentDescription {
            identifying_attributes: vec![ProtoKeyValue {
                key: "service.name".to_string(),
                value: Some(AnyValue {
                    value: Some(any_value::Value::StringValue(
                        "opamp-fleet-client".to_string(),
                    )),
                }),
            }],
            non_identifying_attributes: vec![ProtoKeyValue {
                key: "service.instance.name".to_string(),
                value: Some(AnyValue {
                    value: Some(any_value::Value::StringValue("edge-01".to_string())),
                }),
            }],
        }
    }

    fn destination(endpoint: &str) -> TelemetryConnectionSettings {
        TelemetryConnectionSettings {
            destination_endpoint: endpoint.to_string(),
            ..Default::default()
        }
    }

    /// With nothing offered nothing is built — the capability says the Client *can* report, and the
    /// Server's offer is what arms it.
    /// Verifies: ADR-0016
    #[test]
    fn no_destination_builds_nothing() {
        let telemetry = Telemetry::new();
        let refused = telemetry.apply(
            &ConnectionSettingsOffers::default(),
            &description(),
            &ClientConfig::default(),
        );
        assert!(refused.is_empty());
        assert!(!telemetry.reporting());
    }

    /// The Baseline's "MAY refuse" for cleartext, taken — and refused *loudly*, so the Server is
    /// told rather than left believing the telemetry flows.
    /// Verifies: ADR-0016
    #[test]
    fn a_cleartext_destination_beyond_the_private_network_is_refused() {
        let telemetry = Telemetry::new();
        let offer = ConnectionSettingsOffers {
            own_metrics: Some(destination("http://collector.example:4318/v1/metrics")),
            ..Default::default()
        };
        let refused = telemetry.apply(&offer, &description(), &ClientConfig::default());
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(refused[0].contains("cleartext"), "{}", refused[0]);
        assert!(!telemetry.reporting());
    }

    /// The loopback literals are where cleartext is admitted and where it stops (ADR-0016). The
    /// private ranges, the name `localhost`, and the rest of 127.0.0.0/8 are all refused, and so is
    /// a host *name* whose first labels read like an address.
    /// Verifies: ADR-0016
    #[test]
    fn cleartext_is_admitted_by_address_and_nowhere_else() {
        for allowed in [
            "http://127.0.0.1:4318/v1/metrics",
            "http://[::1]:4318/v1/metrics",
        ] {
            assert!(
                check(&destination(allowed), "own_metrics").is_ok(),
                "{allowed} is a loopback literal"
            );
        }
        for refused in [
            "http://localhost:4318/v1/metrics",
            "http://127.0.0.2:4318/v1/metrics",
            "http://192.168.10.5:4318/v1/metrics",
            "http://10.0.0.5:4318/v1/metrics",
            "http://172.16.0.5:4318/v1/metrics",
            "http://[fd00::5]:4318/v1/metrics",
            "http://collector.example:4318/v1/metrics",
            "http://203.0.113.5:4318/v1/metrics",
            "http://172.32.0.5:4318/v1/metrics",
            "http://[2001:db8::5]:4318/v1/metrics",
            "http://192.168.0.1.example.com:4318/v1/metrics",
        ] {
            let Err(error) = check(&destination(refused), "own_metrics") else {
                panic!("{refused} is not a private address");
            };
            assert!(error.contains("cleartext"), "{error}");
        }
    }

    /// A Collector on the LAN rather than on the host is one hop out, and that hop is a network:
    /// in cleartext it is refused and reported, and nothing is exported (ADR-0016).
    /// Verifies: ADR-0016
    #[tokio::test]
    async fn a_private_network_destination_is_refused_in_cleartext() {
        opamp::tls::install_ring_provider();
        let telemetry = Telemetry::new();
        let offer = ConnectionSettingsOffers {
            own_metrics: Some(destination("http://192.168.10.5:4318/v1/metrics")),
            ..Default::default()
        };
        let refused = telemetry.apply(&offer, &description(), &ClientConfig::default());
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(refused[0].starts_with("own_metrics:"), "{}", refused[0]);
        assert!(refused[0].contains("127.0.0.1 or ::1"), "{}", refused[0]);
        assert!(!telemetry.reporting());
    }

    /// Loopback is the innermost case: a Collector on the same host over plain HTTP is the ordinary
    /// development and sidecar shape, and nothing leaves the machine at all.
    /// Verifies: ADR-0016
    #[tokio::test]
    async fn a_loopback_destination_is_allowed_in_cleartext() {
        opamp::tls::install_ring_provider();
        let telemetry = Telemetry::new();
        let offer = ConnectionSettingsOffers {
            own_metrics: Some(destination("http://127.0.0.1:4318/v1/metrics")),
            ..Default::default()
        };
        let refused = telemetry.apply(&offer, &description(), &ClientConfig::default());
        assert!(refused.is_empty(), "{refused:?}");
        assert!(telemetry.reporting());
        telemetry.shutdown();
    }

    /// A destination offered with an empty endpoint is a withdrawal (ADR-0016 rule 18): the
    /// exporter is shut down and **nothing is refused**. Reporting it back as a malformed URL
    /// would answer "stop" with `FAILED`, which is the one answer the Server cannot act on.
    /// Verifies: ADR-0016
    #[tokio::test]
    async fn an_empty_endpoint_stops_reporting_and_refuses_nothing() {
        opamp::tls::install_ring_provider();
        let telemetry = Telemetry::new();
        let running = ConnectionSettingsOffers {
            own_metrics: Some(destination("http://127.0.0.1:4318/v1/metrics")),
            ..Default::default()
        };
        let refused = telemetry.apply(&running, &description(), &ClientConfig::default());
        assert!(refused.is_empty(), "{refused:?}");
        assert!(telemetry.reporting());

        let withdrawal = ConnectionSettingsOffers {
            own_metrics: Some(destination("")),
            ..Default::default()
        };
        let refused = telemetry.apply(&withdrawal, &description(), &ClientConfig::default());

        assert!(
            refused.is_empty(),
            "a withdrawal is not a refusal: {refused:?}"
        );
        assert!(!telemetry.reporting(), "the exporter is shut down");
    }

    /// The same two fields refused on the OpAMP settings are refused here, and for the same
    /// reasons — named, not dropped in silence (ADR-0021, ADR-0016).
    /// Verifies: ADR-0016
    #[test]
    fn offered_tls_settings_are_refused_by_name() {
        let telemetry = Telemetry::new();
        let offer = ConnectionSettingsOffers {
            own_logs: Some(TelemetryConnectionSettings {
                destination_endpoint: "https://collector.example:4318/v1/logs".to_string(),
                tls: Some(TlsConnectionSettings {
                    insecure_skip_verify: true,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let refused = telemetry.apply(&offer, &description(), &ClientConfig::default());
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(refused[0].contains("tls"), "{}", refused[0]);
        assert!(!telemetry.reporting());
    }

    /// ADR-0016 point 32: the offered `certificate` is *honoured*, not refused — the ADR-0021
    /// machinery is reused as-is, which means the offered `cert` is paired with the key this Client
    /// already generated for its CSR. With that key present, an offer naming a certificate builds
    /// an exporter that presents it.
    /// Verifies: ADR-0016
    #[tokio::test]
    async fn an_offered_certificate_is_presented_by_the_exporter() {
        opamp::tls::install_ring_provider();
        let dir = tempfile::tempdir().expect("tempdir");
        // What the CSR flow leaves behind: the key the request was made for, and the certificate
        // the Server signed for it. Self-signed here — nothing verifies the chain in this test, the
        // point is that key and certificate pair into a usable identity.
        let key = rcgen::KeyPair::generate().expect("key");
        let params =
            rcgen::CertificateParams::new(vec!["agent.example".to_string()]).expect("params");
        let cert = params.self_signed(&key).expect("cert");
        std::fs::write(
            dir.path().join(crate::tls::ISSUED_KEY_FILE),
            key.serialize_pem(),
        )
        .expect("write key");

        let config = ClientConfig {
            state_dir: dir.path().to_path_buf(),
            ..ClientConfig::default()
        };
        let offer = ConnectionSettingsOffers {
            own_metrics: Some(TelemetryConnectionSettings {
                destination_endpoint: "http://127.0.0.1:4318/v1/metrics".to_string(),
                certificate: Some(TlsCertificate {
                    cert: cert.pem().into_bytes(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let telemetry = Telemetry::new();
        let refused = telemetry.apply(&offer, &description(), &config);
        assert!(refused.is_empty(), "{refused:?}");
        assert!(telemetry.reporting());
        telemetry.shutdown();
    }

    /// And an offered certificate with no key to go with it is refused *by name* rather than
    /// dropped: without the CSR key there is nothing to prove possession with, so an exporter that
    /// silently connected without the certificate would be reporting success it did not have.
    /// Verifies: ADR-0016
    #[test]
    fn an_offered_certificate_without_its_key_is_refused_and_named() {
        opamp::tls::install_ring_provider();
        let dir = tempfile::tempdir().expect("tempdir");
        let config = ClientConfig {
            state_dir: dir.path().to_path_buf(),
            ..ClientConfig::default()
        };
        let offer = ConnectionSettingsOffers {
            own_metrics: Some(TelemetryConnectionSettings {
                destination_endpoint: "http://127.0.0.1:4318/v1/metrics".to_string(),
                certificate: Some(TlsCertificate {
                    cert: b"-----BEGIN CERTIFICATE-----".to_vec(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let telemetry = Telemetry::new();
        let refused = telemetry.apply(&offer, &description(), &config);
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(refused[0].contains("own_metrics"), "{}", refused[0]);
        assert!(refused[0].contains("no key"), "{}", refused[0]);
        assert!(!telemetry.reporting());
    }

    /// But a private key *in the offer* is refused by name. ADR-0021's rule is that this Client's
    /// private key never leaves its host and is never handed to it — which is the whole reason the
    /// certificate is obtained through a CSR.
    /// Verifies: ADR-0016
    #[test]
    fn an_offered_private_key_is_refused_by_name() {
        let telemetry = Telemetry::new();
        let offer = ConnectionSettingsOffers {
            own_traces: Some(TelemetryConnectionSettings {
                destination_endpoint: "https://collector.example:4318/v1/traces".to_string(),
                certificate: Some(TlsCertificate {
                    cert: b"-----BEGIN CERTIFICATE-----".to_vec(),
                    private_key: b"-----BEGIN PRIVATE KEY-----".to_vec(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let refused = telemetry.apply(&offer, &description(), &ClientConfig::default());
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(
            refused[0].contains("certificate.private_key"),
            "{}",
            refused[0]
        );
        assert!(!telemetry.reporting());
    }

    /// The Baseline names a number for own metrics — *"The recommended reporting interval is 10
    /// seconds"* — and this pins it, because the way it drifts is silent: the SDK's periodic reader
    /// defaults to 60 s, so an exporter built without an explicit interval reports six times more
    /// slowly than recommended and nothing says so. Sampling and export share the constant, so this
    /// guards both.
    /// Verifies: ADR-0016
    #[test]
    fn metrics_are_reported_at_the_interval_the_baseline_recommends() {
        assert_eq!(Telemetry::new().sample_interval(), Duration::from_secs(10));
    }

    /// The Resource carries what identifies the Agent, which is what makes one host's several
    /// Agents distinguishable at the receiving end — and the operator's name for it beside them,
    /// which is what makes the result placeable against the fleet view.
    /// Verifies: ADR-0016
    #[test]
    fn the_resource_carries_the_agents_identifying_attributes() {
        let resource = resource(&description());
        let attribute = |key: &str| {
            resource
                .iter()
                .find(|(k, _)| k.as_str() == key)
                .map(|(_, value)| value.to_string())
        };
        assert_eq!(
            attribute("service.name").as_deref(),
            Some("opamp-fleet-client")
        );
        assert_eq!(
            attribute("service.instance.name").as_deref(),
            Some("edge-01")
        );
    }

    /// The platform travels with the telemetry, because a series that cannot be placed on an
    /// operating system and an architecture (ADR-0026) cannot be read against a fleet whose Agents
    /// do not all run the same one. It sits on the Resource: every Agent in one export runs on the
    /// host this Resource describes, so per-sample it would be a constant repeated on every point.
    /// Verifies: ADR-0016
    #[test]
    fn the_resource_carries_the_platform() {
        let mut description = description();
        for (key, value) in [("os.type", "linux"), ("host.arch", "amd64")] {
            description
                .non_identifying_attributes
                .push(opamp::attributes::string_attr(key, value));
        }
        let resource = resource(&description);
        let attribute = |key: &str| {
            resource
                .iter()
                .find(|(k, _)| k.as_str() == key)
                .map(|(_, value)| value.to_string())
        };
        assert_eq!(attribute("os.type").as_deref(), Some("linux"));
        assert_eq!(attribute("host.arch").as_deref(), Some("amd64"));
    }

    /// And nothing else does. The non-identifying attributes are a bag that also holds the host's
    /// addresses and whatever the operator tagged this Agent with (ADR-0023) — the Resource is what
    /// leaves the host for a destination the *Server* named, so what goes in it is a named list,
    /// not the bag. This is the test that fails if that list is ever replaced by a filter.
    /// Verifies: ADR-0016
    #[test]
    fn the_resource_carries_no_other_non_identifying_attribute() {
        let mut description = description();
        for (key, value) in [("host.name", "edge-01.example"), ("team", "platform")] {
            description
                .non_identifying_attributes
                .push(opamp::attributes::string_attr(key, value));
        }
        let resource = resource(&description);
        for key in ["host.name", "team"] {
            assert!(
                resource.iter().all(|(k, _)| k.as_str() != key),
                "{key} reached the Resource"
            );
        }
    }

    /// The instance name is non-identifying, so it is reported where an Agent has one and left out
    /// where it does not — an absent attribute says "unknown" where an empty one says nothing true.
    /// Verifies: ADR-0016
    #[test]
    fn an_agent_without_an_instance_name_reports_none() {
        let mut description = description();
        description.non_identifying_attributes.clear();
        assert!(resource(&description)
            .iter()
            .all(|(key, _)| key.as_str() != "service.instance.name"));
    }

    /// The bound nothing else on the path supplies. A destination that *refuses* recovers by
    /// itself — the next interval is a fresh request — so what is worth a test is the one that
    /// does not: a socket accepted and then left silent, which without this holds the exporter
    /// thread for good and takes own telemetry down until the process restarts.
    /// Verifies: ADR-0016
    #[tokio::test]
    async fn an_export_to_a_destination_that_never_answers_gives_up() {
        opamp::tls::install_ring_provider();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/v1/metrics", listener.local_addr().unwrap());
        let _silent = tokio::spawn(async move {
            // Accepted and held: closing the socket would be an answer, and an answer is the case
            // that was never broken.
            let mut connections = Vec::new();
            while let Ok((connection, _)) = listener.accept().await {
                connections.push(connection);
            }
        });

        let client = exporter_client(
            &destination(&endpoint),
            "own_metrics",
            &ClientConfig::default(),
        )
        .expect("the client builds");
        // Bounded from the outside as well: without the client's own timeout this send never
        // returns, and a regression should fail the test rather than hang it.
        let outcome = tokio::time::timeout(SAMPLE_INTERVAL, client.client.post(&endpoint).send())
            .await
            .expect("the export gives up within the interval that drives it");

        assert!(
            outcome
                .as_ref()
                .err()
                .is_some_and(reqwest::Error::is_timeout),
            "a silent destination must time out, got {outcome:?}"
        );
    }

    /// A destination that accepts a connection and never answers, for as long as the test runs.
    async fn silent_destination() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/v1/metrics", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let mut connections = Vec::new();
            while let Ok((connection, _)) = listener.accept().await {
                connections.push(connection);
            }
        });
        endpoint
    }

    /// This process as an Agent to sample, so the exporter has something to flush.
    fn this_process() -> SamplingTarget {
        SamplingTarget {
            uid: "0123456789abcdef0123456789abcdef".to_string(),
            instance_name: "edge-01".to_string(),
            service_name: "supervisor".to_string(),
            pid: std::process::id(),
        }
    }

    /// Replacing a destination returns at once even when the old one has gone silent: the flush of
    /// the replaced exporter, which waits out its export timeout, happens off the caller — the
    /// transport that applies the offer — and only `shutdown` on the way out waits for it.
    /// Verifies: ADR-0016
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn replacing_a_silent_destination_does_not_wait_for_its_flush() {
        opamp::tls::install_ring_provider();
        let telemetry = Telemetry::new();
        let silent = ConnectionSettingsOffers {
            own_metrics: Some(destination(&silent_destination().await)),
            ..Default::default()
        };
        assert!(telemetry
            .apply(&silent, &description(), &ClientConfig::default())
            .is_empty());
        telemetry.sample(&mut sysinfo::System::new(), &this_process());

        let withdrawal = ConnectionSettingsOffers {
            own_metrics: Some(destination("")),
            ..Default::default()
        };
        let started = std::time::Instant::now();
        let refused = telemetry.apply(&withdrawal, &description(), &ClientConfig::default());
        let took = started.elapsed();
        assert!(refused.is_empty(), "{refused:?}");
        assert!(!telemetry.reporting());
        assert!(
            took < Duration::from_secs(1),
            "the offer waited {took:?} for the replaced exporter's flush"
        );

        // On the way out the flush is waited for, and it ends: the export gives up on its timeout.
        let flushed = tokio::task::spawn_blocking(move || telemetry.shutdown());
        tokio::time::timeout(Duration::from_secs(30), flushed)
            .await
            .expect("shutdown waits for the flush, and the flush ends")
            .expect("shutdown");
    }

    /// A destination that refuses the connection costs nothing but the failed exports: sampling
    /// goes on, a new offer is applied, and shutting down ends.
    /// Verifies: ADR-0016
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_destination_that_refuses_the_connection_stops_nothing() {
        opamp::tls::install_ring_provider();
        // A port that was free a moment ago: nothing listens, so every connection is refused.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let telemetry = Telemetry::new();
        let refusing = ConnectionSettingsOffers {
            own_metrics: Some(destination(&format!("http://127.0.0.1:{port}/v1/metrics"))),
            ..Default::default()
        };
        assert!(telemetry
            .apply(&refusing, &description(), &ClientConfig::default())
            .is_empty());
        let mut system = sysinfo::System::new();
        for _ in 0..3 {
            telemetry.sample(&mut system, &this_process());
        }
        assert!(telemetry.reporting());

        let elsewhere = ConnectionSettingsOffers {
            own_metrics: Some(destination("http://127.0.0.1:4318/v1/metrics")),
            ..Default::default()
        };
        assert!(telemetry
            .apply(&elsewhere, &description(), &ClientConfig::default())
            .is_empty());
        assert!(telemetry.reporting());

        let stopped = tokio::task::spawn_blocking(move || telemetry.shutdown());
        tokio::time::timeout(Duration::from_secs(30), stopped)
            .await
            .expect("shutdown ends with the destination refusing")
            .expect("shutdown");
    }

    /// The exporter's client offers TLS 1.3 and nothing older, so a destination that speaks only
    /// TLS 1.2 cannot complete a handshake with it. Read off the wire: the ClientHello it sends
    /// names TLS 1.3 alone in `supported_versions` and only the TLS 1.3 suites.
    /// Verifies: ADR-0016
    #[tokio::test]
    async fn the_exporter_client_speaks_tls_1_3_alone() {
        use tokio::io::AsyncReadExt as _;

        opamp::tls::install_ring_provider();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("https://{}/v1/metrics", listener.local_addr().unwrap());
        let hello = tokio::spawn(async move {
            let (mut connection, _) = listener.accept().await.expect("the exporter connects");
            let mut header = [0u8; 5];
            connection.read_exact(&mut header).await.expect("a record");
            let mut record = vec![0u8; usize::from(u16::from_be_bytes([header[3], header[4]]))];
            connection.read_exact(&mut record).await.expect("the hello");
            record
        });

        let client = exporter_client(
            &destination(&endpoint),
            "own_metrics",
            &ClientConfig::default(),
        )
        .expect("the client builds");
        // Nobody answers the hello; the send fails, and what it offered is what is asserted.
        let _ = tokio::time::timeout(Duration::from_secs(1), client.client.post(&endpoint).send())
            .await;
        let record = tokio::time::timeout(Duration::from_secs(5), hello)
            .await
            .expect("the hello arrives")
            .expect("the reader");

        assert_eq!(record[0], 1, "a ClientHello");
        let length = |at: usize, width: usize| {
            record[at..at + width]
                .iter()
                .fold(0usize, |n, b| n << 8 | usize::from(*b))
        };
        // handshake header (4), legacy version (2), random (32), then the session id.
        let mut at = 4 + 2 + 32;
        at += 1 + length(at, 1);
        let suites: Vec<u16> = record[at + 2..at + 2 + length(at, 2)]
            .chunks(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect();
        at += 2 + length(at, 2);
        at += 1 + length(at, 1);
        let extensions_end = at + 2 + length(at, 2);
        at += 2;
        let mut versions = None;
        while at < extensions_end {
            let (kind, size) = (length(at, 2), length(at + 2, 2));
            if kind == 0x002b {
                versions = Some(
                    record[at + 5..at + 4 + size]
                        .chunks(2)
                        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                        .collect::<Vec<_>>(),
                );
            }
            at += 4 + size;
        }

        assert_eq!(
            versions,
            Some(vec![0x0304]),
            "supported_versions is TLS 1.3 alone"
        );
        assert!(
            suites.iter().all(|suite| (0x1301..=0x1303).contains(suite)),
            "only TLS 1.3 suites are offered: {suites:04x?}"
        );
    }

    /// The whole chain the traces half rests on (ADR-0016): a `tracing` span this Client writes,
    /// through the layer, the provider and the exporter, to the destination the Server offered.
    ///
    /// Worth an end-to-end test rather than a unit one because every link was already in place
    /// *except* the first, and the failure it guards against is silent: the exporter builds, the
    /// offer is acknowledged, the dashboard stays empty. It asserts the span's name and its
    /// recorded status, which is what makes a trace worth reading.
    /// Verifies: ADR-0016
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_span_this_client_writes_reaches_the_offered_destination() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tracing_subscriber::layer::SubscriberExt as _;

        opamp::tls::install_ring_provider();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/v1/traces", listener.local_addr().unwrap());
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut connection, _) = listener.accept().await.expect("the exporter connects");
            // Read until the exporter has nothing more to say, then answer: the body is protobuf
            // and this stub has no reason to parse it — the span's name and status travel as plain
            // strings inside it, which is exactly what is being asserted.
            let mut request = Vec::new();
            let mut chunk = [0u8; 4096];
            while let Ok(Ok(read)) =
                tokio::time::timeout(Duration::from_millis(200), connection.read(&mut chunk)).await
            {
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
            }
            let _ = connection
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await;
            let _ = tx.send(request);
        });

        let provider = trace_provider(
            &destination(&endpoint),
            Resource::builder_empty().build(),
            &ClientConfig::default(),
        )
        .expect("the provider builds");
        // The layer the slot holds in a real run, installed for this thread only: the process-wide
        // subscriber belongs to `main`, and a test must not take it from the other tests.
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer(SCOPE)));
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!(
                "package.install",
                otel.status_code = tracing::field::Empty,
                otel.status_description = tracing::field::Empty,
            );
            let _entered = span.enter();
            failed(&span, "the artifact would not start");
        });

        // Blocking, on a thread of its own: the batch processor drives its export with a blocking
        // wait, and the export itself needs this runtime to send the request.
        let flushed = provider.clone();
        tokio::task::spawn_blocking(move || flushed.shutdown())
            .await
            .expect("the flush thread")
            .expect("the exporter flushes");

        let request = tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .expect("the exporter posts within the export timeout")
            .expect("the stub answers");
        let body = String::from_utf8_lossy(&request);
        assert!(
            body.contains("package.install"),
            "the span's name is exported"
        );
        assert!(
            body.contains("the artifact would not start"),
            "the recorded status description travels with it"
        );
    }

    /// ADR-0016 clause 20: an operation that outlives the process it started in stays **one** trace.
    ///
    /// Asserted through the two functions the self-update uses — the ids it writes into its marker,
    /// and the parent it builds from them afterwards — because what the restart breaks is exactly
    /// the link between those two, and nothing else about it can be tested in one process.
    /// Verifies: ADR-0016
    #[test]
    fn a_trace_survives_being_written_down_and_picked_up_again() {
        use tracing_subscriber::layer::SubscriberExt as _;
        // No exporter: what is under test is the identity of the trace, not its delivery.
        let provider = SdkTracerProvider::builder().build();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer(SCOPE)));
        tracing::subscriber::with_default(subscriber, || {
            // The process that stages the version: it records what it is part of.
            let staged = {
                let install = tracing::info_span!("package.install");
                let _entered = install.enter();
                current_trace().expect("an install is being traced")
            };

            // The process that comes up after the restart: a fresh span, told what it continues.
            let commit = tracing::info_span!("commit");
            continue_trace(&commit, &staged.0, &staged.1);
            let _entered = commit.enter();
            let continued = current_trace().expect("the commit is being traced");

            assert_eq!(continued.0, staged.0, "the same trace");
            assert_ne!(continued.1, staged.1, "a span of its own within it");
        });
    }

    /// And an unusable pair changes nothing: the ids come from a file an older version wrote, and
    /// an update is not worth failing over a trace.
    /// Verifies: ADR-0016
    #[test]
    fn an_unreadable_trace_reference_is_ignored() {
        use tracing_subscriber::layer::SubscriberExt as _;
        let provider = SdkTracerProvider::builder().build();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer(SCOPE)));
        tracing::subscriber::with_default(subscriber, || {
            let commit = tracing::info_span!("commit");
            continue_trace(&commit, "not-a-trace-id", "nor-a-span-id");
            let _entered = commit.enter();
            assert!(
                current_trace().is_some(),
                "the span still belongs to a trace of its own"
            );
        });
    }
}
