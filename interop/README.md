# Interop against opamp-go

This directory holds the Go side of the conformance check of
[ADR-0011](../docs/adr/0011-the-protocol-is-pinned-and-checked-against-opamp-go-on-the-endpoint-as-it-ships.md): a small program that puts
[`opamp-go`](https://github.com/open-telemetry/opamp-go), the OpAMP reference implementation, at the
far end of a connection with this project's Server or Client. It decides nothing. It reports what
`opamp-go` sees as one JSON object per line on stdout and takes commands on stdin. The scenarios and
every assertion live in
[`crates/fleet-agent/tests/interop_opamp_go.rs`](../crates/fleet-agent/tests/interop_opamp_go.rs),
where both ends' state can be read.

`go.mod` pins the oracle. Moving the pin is a deliberate change, like a Baseline move: read what the
new release brought and update the oracle row in [`CONFORMANCE.md`](../docs/CONFORMANCE.md).

## Running it

The job runs weekly and on demand ([`interop.yml`](../.github/workflows/interop.yml)). Locally, with
a Go toolchain on `PATH` (nothing else in the repository needs one, and the Dev Container ships
none):

```console
cargo test -p fleet-agent --test interop_opamp_go -- --ignored --nocapture --test-threads=1
```

The test builds this program itself with `go build`.

## Scenarios

Each runs in both directions (`opamp-go`'s Client against our Server, our Client against
`opamp-go`'s Server) and on both transports. All run in plaintext on the loopback with an open
admission, except the runs on the endpoint as it ships:

- connect and report: the description and the declared capabilities arrive;
- `sequence_num` continuity, and the `ReportFullState` recovery: our Server asks for the full state
  from an Agent a relay hands it without its history, and from one that comes back to it after a
  gap with a changed description; `opamp-go`'s Server asks our Client for it;
- the remote-config offer, its `APPLIED` acknowledgement with the offered hash, and the hash gate
  that stops our Server repeating an applied offer;
- capability negotiation: each side records what the other declared, and our Client drops its
  effective configuration from its reports once `opamp-go`'s Server stops accepting it.
  `opamp-go`'s Client hands its callbacks no Server capabilities, so on that side they are read off
  the wire, on plain HTTP only;
- identity: a Server-assigned `AgentIdentification` is adopted, our Client persists it, and our
  Server keeps no record under the requested identity;
- the endpoint as it ships: both directions over `wss://` and `https://` with TLS 1.3 alone and a
  required client certificate from a PKI the test generates, carrying connect and report and a
  configuration round trip; a certificate another CA issued is refused by both ends, and our
  Server refuses a peer that offers none;
- `agent_disconnect` on a graceful stop of our Client. The other direction is not decided:
  `opamp-go`'s plain-HTTP Client sends no `agent_disconnect` (an oracle gap), and over WebSocket
  the goodbye and the closing socket mark the Agent disconnected alike.

## When it is red

Triage a failure before calling it a defect. It is one of three things:

1. **Our bug.** The point of the exercise. Fix it, with a regression test in the ordinary suite
   where one can be written.
2. **The oracle lagging the Baseline.** `opamp-go` may implement an older `opamp-spec` than the
   Baseline. Record it as a known upstream gap in `CONFORMANCE.md`, and pin the scenario to the
   older behaviour or skip it by name, with the row it concerns.
3. **A genuine ambiguity in the specification.** Open an issue upstream in `opamp-spec`, and link
   it from the `CONFORMANCE.md` row it concerns.
