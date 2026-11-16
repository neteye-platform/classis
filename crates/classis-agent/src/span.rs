//! An operation's outcome on the span that measures it (ADR-0016): recorded through `tracing`, which
//! the telemetry adapter turns into the OpenTelemetry span status.

/// The two fields every operation span declares empty and fills in when it ends.
///
/// They are `tracing-opentelemetry`'s reserved names, not this project's: recording them turns into
/// the OpenTelemetry span status, which is what ADR-0016 meant by *"the existing outcome becomes the
/// span status"*. Declared empty at creation because a field can only be recorded on a span that
/// declared it — and the outcome is, by definition, not known then.
///
/// Written through [`failed`] and [`succeeded`] rather than by hand at a dozen call sites, so the
/// spelling of the status codes lives in one place.
pub const STATUS_CODE: &str = "otel.status_code";
/// The description beside [`STATUS_CODE`]; recorded only with an error, as the crate ignores it
/// otherwise.
pub const STATUS_DESCRIPTION: &str = "otel.status_description";

/// Marks the operation `span` measures as failed, with the message the Server is told.
///
/// The message is this Client's own error text — the same string that reaches the Server as the
/// operation's status and the log as a `warn!`. Nothing is composed for the trace alone: a trace
/// that says something different from the report beside it is worse than no trace.
pub fn failed(span: &tracing::Span, error: &str) {
    span.record(STATUS_CODE, "ERROR");
    span.record(STATUS_DESCRIPTION, error);
}

/// Marks the operation `span` measures as succeeded.
///
/// Explicit rather than implied by the absence of an error: an unset status is *"unset"* in the
/// standard's own vocabulary, which is what a span that ended abruptly also looks like.
pub fn succeeded(span: &tracing::Span) {
    span.record(STATUS_CODE, "OK");
}
