# Conventions — Classis

> How this project writes code and tests **where no check decides it**: the
> judgement calls. What a module may know, what a test asserts and never does,
> the shape of an error, how a thing is named when the glossary has no word for
> it. Whoever settles a convention updates this file inline, an agent included,
> in the same change as the review or code that settled it. The reviewer always
> has it.

An entry says in a sentence or two what is done and why; the why tells a
convention from a habit. A convention a check can decide is the check, not an
entry. One that constrains future choices is a decision ([`AGENTS.md`
§3](../AGENTS.md#3-decisions)). What the golden path already shows needs none.
Few entries that hold beat many that are skimmed. The design revision at the
close of a feature spec drops what prevented nothing ([`AGENTS.md`
§5](../AGENTS.md#5-quality-bar--definition-of-done)).

## Safety and failure

- **`unsafe` stays behind a safe function** — A crate that needs no `unsafe`
  forbids it with `#![forbid(unsafe_code)]`. Where the Client calls the
  operating system, an `unsafe` block holds that call alone, carries a
  `// SAFETY:` comment that names the invariants it relies on, and sits inside
  a safe function. Why: the reviewer checks each invariant at the one place
  that claims it.
- **A panic means a bug** — Outside tests, a failure that can happen is
  returned with `?`. `expect` is for what only a bug can break, such as a
  poisoned lock or a value that a check above guarantees, and its message
  names that invariant. `unwrap` is for tests only. Why: a panic in the Server
  drops every connection it carries, so no input may cause one.
- **A discarded result says why** — `let _ = …` carries a comment that says
  why the failure does not matter there, such as in a drop or for a peer that
  has left. Why: a silent discard reads as a forgotten error.
- **A number from outside is converted, not cast** — A length, a count or a
  size read from the network, a file or a Package Repository is converted with
  `try_from` and combined with `checked_*` or `saturating_*`. `as` only widens
  a value that the code controls. Why: [Q-2](SPECIFICATION.md#quality-goals)
  bounds what is read, and this keeps the arithmetic on it from wrapping.
- **An error is a message that names what failed** — Stores, ports and
  configuration checks return `Result<_, String>`. The message starts in lower
  case, has no punctuation at its end, and names the key, the path or the
  identity that failed and, when there is one, what to do. A refusal that the
  REST API answers with a status of its own is a constant that the API
  compares with, so a reworded message cannot change the status. Why: one
  shape across every port lets an adapter's failure pass through the core to
  the operator unchanged; `thiserror` and `anyhow` were weighed and not taken,
  because they add two dependencies and change every port.

## Types and ownership

- **The type rules out the wrong state** — When a value has a few shapes, an
  enum names them, not a `bool` or an `Option` beside another field. A
  configuration kept as strings, so that its check can name the key, becomes
  such a type once the check passes. Why: a state that the type cannot hold
  needs no test and no check where it is used.
- **A port is a trait object, the rest is generic** — The composition root
  chooses the adapter of a port from the configuration, so a port is held as
  `Box<dyn …>`. Elsewhere `impl Trait` or a generic comes first, and an
  argument that the callee does not keep is borrowed. Why: dynamic dispatch
  where the choice is made at runtime, and none where it is not.
- **One owner before a lock** — State that changes has one owner where it can:
  a `&mut self` method comes before a `Mutex`, and a `Mutex` before an
  `Arc<Mutex<_>>`. A `clone` that stays is cheap or needed, such as a handle,
  a key or a value that a `'static` future owns, and never a way around the
  borrow checker. Why: every lock is a place where the next change can
  deadlock or poison.
- **The public surface is what another crate uses** — An item is `pub` only
  when another crate of the workspace, an integration test or a fuzz target
  uses it; otherwise it is `pub(crate)` or private. Why: everything public is
  something the next change must keep.
- **Every type implements `Debug`** — It is derived, or written by hand to
  show what identifies the value when a field cannot be shown or holds a
  secret, as `S3BlobsConfig` hides its key. Why: a value without it cannot
  appear in a failed assertion or in `expect_err`.

## Runtime and documentation

- **The runtime is never blocked by I/O of its own** — Async code runs a
  blocking read or write, a stream of unbounded length and a sleep in
  `spawn_blocking`. A port is called where it is needed: each call of its
  adapter is bounded, and a `Bridge` waits on a channel, which cannot deadlock
  the runtime that waits. The startup opens its stores before the Server
  serves. Why: one blocked worker stalls every connection it carries.
- **The log goes through `tracing`** — The Server and the Client log with
  `tracing`. `println!` and `eprintln!` are for what a command prints as its
  result, such as a `migrate` report, and for a test that says it was skipped.
  Why: the log carries the security decisions, in one format.
- **A public item says how it fails** — Every `pub` item has a `///` comment,
  with `# Errors` when it returns a `Result` and `# Panics` when it can panic.
  The entry point of a module, where a reader starts, has a short example,
  `no_run` when it needs a filesystem or a network. Why: the contract of a port
  is read without reading its adapters.
