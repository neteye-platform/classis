# ADR-0057: The secrets the application crates hold in memory are wiped when they are dropped, with `zeroize`

- **Status:** 🟢 accepted
- **Date:** 2026-10-24
- **Deciders:** Markus Brigl, Davide Zeni
- **Applies to:** the `zeroize` crate in `Cargo.toml` and in the manifests of
  `crates/classis-core/`, `crates/classis-agent/`, `crates/classis-server/` and
  `crates/classis-tools/`, every value of those crates that holds a private key,
  a password, the S3 secret access key, a `bootstrap.p12` being read or the
  Supervisor Endpoint token (among them `BootstrapIdentity` in
  `crates/classis-agent/src/config.rs`, `crates/classis-agent/src/tls.rs`,
  `crates/classis-agent/src/csr.rs`, `read_password_file` and the questionnaire
  in `crates/classis-agent/src/config_init.rs`, the token in
  `crates/classis-agent/src/supervisor/`,
  `crates/classis-core/src/pkcs12/file.rs`, `crates/classis-server/src/ca.rs`,
  `Password` in `crates/classis-server/src/bootstrap.rs`, the Basic password in
  `crates/classis-server/src/credentials.rs`, the Server's own TLS key,
  `read_secret_file` in `crates/classis-server/src/config.rs`, the contents of
  `[database.postgres] password_file` in
  `crates/classis-server/src/postgres/mod.rs` and of
  `[blobs.s3] secret_access_key_file` in `crates/classis-server/src/s3.rs`,
  `[packages] archive_key` in `crates/classis-agent/src/config.rs` and
  `crates/classis-agent/src/config_file.rs`, the text of `supervisor.toml` where
  `crates/classis-agent/src/reconfigure.rs` and
  `crates/classis-agent/src/config_init.rs` rewrite it, the Gateway's listener
  key, and the password and key handling of `crates/classis-tools/src/pki.rs`
  and `crates/classis-tools/src/package.rs` with `package pack --archive-key`)

## Context

The specification puts security before convenience and holds that no
vulnerability can be ruled out. Both ends hold secrets in memory, as plain
`String` and `Vec<u8>`, and drop them without overwriting them:

- the Client's private key as PEM, read from `client_key_file` or the pending
  and issued key files under `state_dir`, and the key `csr.rs` reads to sign a
  renewal or a bootstrap proof;
- the bootstrap identity a `bootstrap.p12` opened to, held in `ClientConfig`
  until the Client is enrolled
  ([ADR-0029](0029-a-bootstrap-certificate-as-a-password-protected-pkcs12-file-the-server-keeps.md)
  clause 7), the file's bytes while it is read, and its password
  ([ADR-0048](0048-a-bootstrap-pkcs12-password-of-8-to-128-characters.md)) from
  the questionnaire or a password file;
- the Server's client-CA and bootstrap-CA keys as PEM while they are loaded, the
  DER of every key it seals into a PKCS#12 file, the bootstrap password of an
  issuing request, the password of an Operator plane Basic login before it is
  verified, and the PostgreSQL password and the S3 secret access key
  `read_secret_file` reads from `[database.postgres] password_file` and
  `[blobs.s3] secret_access_key_file`
  ([ADR-0050](0050-the-servers-records-may-live-in-postgresql.md),
  [ADR-0049](0049-artifact-bytes-may-live-in-an-s3-compatible-object-store.md));
- the Supervisor Endpoint token
  ([ADR-0015](0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md));
- the passwords and keys `classisctl` reads and writes.

Memory that is freed keeps its bytes until it is reused. A core dump, a swapped
page, a heap read past a buffer, or a later allocation that is handed out
uninitialised can reveal them. Overwriting a buffer by hand does not hold: the
compiler may remove a write to memory that is freed right after. `zeroize` is
the established crate for this; it writes through volatile operations behind a
compiler fence. It is already in the tree at 1.9.1, through `dialoguer`'s
`password` feature, `der`, `pkcs8`, `pkcs12`, `rustls` and `rustls-pki-types`,
so naming it costs no new crate and no new licence, but none of this project's
code uses it.

What the crates around the secrets do, read in the locked sources:

- `rustls` 0.23.46 wipes its own traffic keys (`AeadKey`, `Tag`, the HPKE key)
  on drop, and its `ring` provider wraps the `PrivateKeyDer` it is handed in
  `Zeroizing` while it loads it. What it keeps after loading is a `ring` key.
- `rustls-pki-types` 1.15.1 implements `Zeroize` for `PrivateKeyDer` and its
  three forms, but not `Drop`: a key is wiped only when its owner calls
  `zeroize` or wraps it.
- `ring` 0.17.14 wipes no key it holds; its sources say so.
- `rcgen` 0.14.10 implements `Zeroize` for `KeyPair` only behind its `zeroize`
  feature, which is off here, and never on drop; the `ring` key inside it stays
  unwiped either way.
- `p12-keystore` 0.4.1 wipes nothing. `pkcs12` 0.2.0-pre.0 wipes its derived
  keys and its copy of the password.
- `dialoguer` 0.12.0 holds the typed password in `Zeroizing` and returns a plain
  `String` clone.
- `tokio-postgres` 0.7.18 copies the password `Config::password` is handed into
  a `Vec<u8>` of its own, and `object_store` 0.14.2 keeps the key
  `AmazonS3Builder::with_secret_access_key` is handed as a `String`. Neither
  names `zeroize`.

`opamp::tls::Identity` carries the key as PEM into every connection
([ADR-0010](0010-five-crates-the-whole-opamp-communication-layer-in-the-opamp-crate-and-toml-configuration.md)
clause 4). ADR-0010 clause 3 lists the dependencies each feature of `opamp`
adds, and `zeroize` is not among them.

## Decision

We will make `zeroize` a direct dependency of the application crates and hold
every secret their own code keeps — a private key in any encoding, a password,
the S3 secret access key, the bytes of a `bootstrap.p12` while the Client reads
it, and the Supervisor Endpoint token — in a `Zeroizing` buffer from the moment
it is read or made until it is dropped.

1. **One dependency, default features.** `zeroize` is pinned once in
   `[workspace.dependencies]`
   ([ADR-0010](0010-five-crates-the-whole-opamp-communication-layer-in-the-opamp-crate-and-toml-configuration.md)
   clause 11) with its default `alloc` feature and no derive, and named by
   `classis-core`, `classis-agent`, `classis-server` and `classis-tools` where
   they hold a secret. It pulls no TLS or crypto backend, so
   [ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)
   clause 5 holds.
2. **`Zeroizing` is the whole mechanism.** A secret is a `Zeroizing<Vec<u8>>` or
   a `Zeroizing<String>`, or a struct field of that type; no type of this
   project's own wraps it. A function that hands a secret on returns it so, and
   a borrow (`&[u8]`, `&str`) passes it to a function that only reads it.
3. **A copy is made only where a library takes ownership.** Where a crate
   demands an owned `String` or `Vec<u8>` of a secret, the copy is made at that
   call and nowhere earlier. A crate's own types that implement `Zeroize`, such
   as `PrivateKeyDer`, are wrapped in `Zeroizing` while this project's code owns
   them.
4. **What a library keeps is not wiped.** The keys `ring` holds inside
   `rcgen::KeyPair` and inside a rustls configuration, the copies `reqwest` and
   `p12-keystore` make, the PostgreSQL password
   `tokio_postgres::Config::password` copies and the S3 secret access key
   `AmazonS3Builder::with_secret_access_key` keeps, and the token the Managed
   Process receives are outside the reach of this project's code. This decision
   makes no claim about them.

**Out of scope:** `opamp`. Wiping the key `opamp::tls::Identity` carries adds
`zeroize` to both features of the publishable crate and changes a public field's
type, which supersedes ADR-0010 clause 3 and is its own decision. Also out of
scope: locking secret pages against swap (`mlock`), excluding them from core
dumps, and the ciphertext the Server keeps of a bootstrap certificate, which
lies on disk under `config_dir` anyway.

## Alternatives considered

- **Leave memory as it is.** No dependency, but a secret outlives its use for as
  long as the allocator leaves the page alone. Rejected under _Security before
  convenience_.
- **Overwrite buffers by hand.** No dependency, but a plain write to memory
  about to be freed may be optimised away, and the volatile writes and fence
  that prevent it are what `zeroize` already is. Rejected.
- **A `Secret` type of this project's own, or the `secrecy` crate.** It would
  also redact `Debug` and gate access behind `expose_secret`. A second crate and
  a wrapper every call site unwraps, where `Zeroizing` dereferences to the
  buffer and the `Debug` redactions already exist (`Identity`,
  `BootstrapIdentity`, `Password`). Not chosen now.
- **Include `opamp` now.** Covers the copy that lives longest, but supersedes a
  clause of an accepted ADR in the publishable crate's interface. Left to its
  own decision.
- **Turn on `rcgen`'s `zeroize` feature.** Its `Zeroize` wipes only the
  serialised DER and runs only when called; the `ring` key stays. Not chosen.

## Sources / Prior art

- The locked sources under the Cargo registry, read 2026-10-20: `zeroize` 1.9.1;
  `rustls` 0.23.46 `crypto/cipher.rs`, `crypto/hmac.rs`, `crypto/hpke.rs`,
  `crypto/ring/mod.rs`; `rustls-pki-types` 1.15.1 `lib.rs`; `ring` 0.17.14
  `agreement.rs` and `ec/suite_b/ecdh.rs`; `rcgen` 0.14.10 `lib.rs`;
  `p12-keystore` 0.4.1; `pkcs12` 0.2.0-pre.0 `kdf.rs`; `pkcs8` 0.11.0
  `traits.rs`; `dialoguer` 0.12.0 `prompts/password.rs`. Read 2026-10-23:
  `tokio-postgres` 0.7.18 `src/config.rs`; `object_store` 0.14.2
  `src/aws/builder.rs` and `src/aws/credential.rs`.
- [`zeroize` 1.9.1](https://docs.rs/zeroize/1.9.1/zeroize/), its crate
  documentation read in the locked source: volatile writes and a compiler fence,
  and that a buffer reallocated or a value moved on the stack leaves copies it
  cannot reach.
- RustCrypto, `rustls` and `pkcs8` use `zeroize` for their own secrets, as the
  sources above show.

## Consequences

- Positive: a key, password or token this project's code dropped no longer stays
  readable in freed memory. The dependency is one the tree already builds.
- Negative / trade-offs: the protection is partial. `ring`, `reqwest` and
  `p12-keystore` keep copies that live as long as a connection or a parse,
  `tokio-postgres` and `object_store` keep theirs as long as the Server's record
  and blob stores, and `opamp`'s `Identity` keeps the Client's key in plain
  memory until the follow-up below. A `Vec` that grows reallocates and leaves
  the old buffer behind, so a secret buffer is read at its final size.
- Negative / trade-offs: the signatures that carry a secret change inside the
  application crates.
- Follow-ups: wiping `opamp::tls::Identity`'s key, which supersedes ADR-0010
  clause 3; keeping secret pages out of swap and core dumps.

## Enforcement

Tests that will carry `Verifies: ADR-0057`: the types of the secrets the
Applies-to line names are pinned at compile time, by a test in each crate that
binds `BootstrapIdentity::key_pem`, what `key_file`, `read_password_file`, the
Server's `read_secret_file` and `classis_core::pkcs12::file::open` return,
`Password`'s field and the Endpoint token to a `Zeroizing` type, so a change
back to a plain buffer stops compiling. That the bytes are overwritten on drop
is `zeroize`'s own tested behaviour; reading freed memory from a test is
undefined behaviour and is not done.

**Not mechanically decidable:** whether a new secret is held in `Zeroizing`, and
whether a copy is made earlier than clause 3 allows. No check can tell a secret
from other bytes; review decides it.
