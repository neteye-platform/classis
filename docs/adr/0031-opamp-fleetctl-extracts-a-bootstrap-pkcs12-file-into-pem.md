# ADR-0031: `opamp-fleetctl pki p12-extract` writes a bootstrap PKCS#12 file's certificate and key as PEM

- **Status:** 🟢 accepted
- **Date:** 2026-10-15
- **Deciders:** Markus Brigl
- **Applies to:** the `pki` command tree of `opamp-fleetctl` in
  `crates/fleet-tools/src/main.rs` and `crates/fleet-tools/src/pki.rs`, the
  dependencies of `crates/fleet-tools/Cargo.toml`, the reading of a PKCS#12 file
  in `crates/fleet-core/src/pkcs12/` and in `pkcs12_identity` of
  `crates/fleet-agent/src/tls.rs`, the reading of a password file in
  `read_password_file` of `crates/fleet-agent/src/config_init.rs`, and every
  document that names an operator command or tells an operator how to hand out a
  bootstrap certificate
- **Supersedes:**
  [ADR-0028](0028-one-operator-program-that-makes-the-fleets-certificates.md)
  clauses 2 and 15

## Context

Since
[ADR-0029](0029-a-bootstrap-certificate-as-a-password-protected-pkcs12-file-the-server-keeps.md),
the Server hands out a bootstrap certificate either as a PEM pair (certificate
and key in the clear) or as a `bootstrap.p12` under a password. The Client's
install takes either form
([ADR-0020](0020-the-client-install-takes-the-fleet-files-it-finds-beside-its-program.md),
ADR-0029 clause 6). Some places want the PEM form while only the `.p12` is at
hand:

- a host whose install is fed the pair;
- a tool that reads PEM only;
- an operator who wants to see what the file holds.

Today that takes OpenSSL. OpenSSL 1.1 cannot read the PBES2/AES file at all, and
OpenSSL 3 needs the right options to open it.

[ADR-0028](0028-one-operator-program-that-makes-the-fleets-certificates.md)
fixes the operator program's command tree (clause 15). Its clause 2 restricts
the `pki` commands to `rcgen` and `time`. The Client's install already reads the
file with `fleet_agent::tls::pkcs12_identity`, which bounds and checks the file
and opens it with the internal crate's `fleet_core::pkcs12::file::open`, on
`p12-keystore` (ADR-0029 clause 14). `opamp-fleetctl` already depends on the
Client's crate and the internal crate (ADR-0028 clause 16). No new crate enters
the build.

## Decision

We will give `opamp-fleetctl pki` a command `p12-extract` that opens a bootstrap
PKCS#12 file with the Client's reader and writes its certificate and its key as
PEM, the key unencrypted and readable by its owner alone.

1. **Restates ADR-0028 clause 2. No dependency beyond ADR-0021 clause 12, and
   the Client's PKCS#12 reader.** The commands use `rcgen` with the features
   that clause states, and `time`. `p12-extract` also reads through the Client's
   `pkcs12_identity`, and so through `fleet_core::pkcs12::file` and
   `p12-keystore` (ADR-0029 clause 14). Every key is ECDSA P-256 and written as
   PKCS#8 PEM, the form `[client_ca]` loads. Every certificate is PEM. Every
   serial is 16 random bytes, as the client CA's are.

2. **Restates ADR-0028 clause 15. One program, two command trees.**
   `opamp-fleetctl package` holds `fetch`, `pack`, `sha256`, `sign`, `keygen`
   and `public-key`, each with the options and output it has today.
   `opamp-fleetctl pki` holds `init`, `server-cert`, `bootstrap-ca` and `status`
   as ADR-0028 states them, and `p12-extract` as this ADR states it.
   `opamp-fleetctl --version` prints the version every binary of this project
   prints ([ADR-0012](0012-versions-resolved-in-the-internal-crate.md)). No
   other program name exists for any of these commands: no alias, no wrapper, no
   symlink.

3. **What it reads.** `opamp-fleetctl pki p12-extract <file> --out <dir>` opens
   `<file>` with `fleet_agent::tls::pkcs12_identity`, the reader the Client's
   install uses. It therefore takes exactly the files ADR-0029 clauses 1 and 7
   describe and refuses the rest, naming why. That covers a file over the
   reader's size bound, a wrong password, a scheme other than PBES2/AES with an
   HMAC-SHA-2 MAC, and anything other than one key with its one certificate.

4. **Where the password comes from.** The password is taken from a hidden
   question on a terminal, or from `--password-file <path>`, which holds the
   password on its first line. It is never taken from a command-line value or an
   environment variable, which other users or the shell history could see
   (ADR-0029, _Alternatives_). Without a terminal and without `--password-file`,
   the command fails before it reads the file.

5. **What it writes.** It writes `<dir>/bootstrap.pem` (the certificate) and
   `<dir>/bootstrap-key.pem` (the key as unencrypted PKCS#8). These are the
   names of the pair the Client's install finds (ADR-0020). On Unix the key is
   written `0600`. It creates `<dir>` when it is missing and overwrites nothing
   (ADR-0028 clause 10): if either file exists, it writes neither and names the
   one in the way. It prints the certificate's subject, serial and `notAfter`,
   and never the key or the password.

**Out of scope:** writing the key encrypted, extracting files other than the
bootstrap form of ADR-0029 clause 1, and making a PKCS#12 file with the tool.

## Alternatives considered

- **Leave it to OpenSSL.** No code is needed, but OpenSSL 1.1 cannot open the
  file, and with OpenSSL 3 the operator has to know the options. The project's
  own program is the one the documents can rely on.
- **Write the key encrypted (PKCS#8 `ENCRYPTED PRIVATE KEY`).** The key stays
  protected at rest. But the Client's install reads the pair in the clear
  (ADR-0020), and neither `rustls` nor `rcgen` reads an encrypted key.
  Owner-only permissions are what ADR-0021 clause 8 gives every other key.
- **Write the certificate only.** The key never leaves the file. It was not
  chosen: the operator asked for the key, and the PEM pair is a form the Client
  takes.
- **Read any PKCS#12 file (other schemes, several certificates).** This is more
  general, but needs a second reader with weaker schemes. The bootstrap file is
  the only PKCS#12 file this project makes.
- **A command of its own outside `pki` (for example
  `opamp-fleetctl p12 extract`).** A third tree for one command. The
  certificates already live under `pki`.
- **The password as `--password <value>`.** It would be visible in `ps` and in
  the shell history.

## Sources / Prior art

- `openssl pkcs12 -in bootstrap.p12 -nodes` (OpenSSL 3 man page
  `openssl-pkcs12`). This is the established way to do the same. It reads
  PBES2/AES files only from OpenSSL 3 on. Consulted from memory.
- [ADR-0029](0029-a-bootstrap-certificate-as-a-password-protected-pkcs12-file-the-server-keeps.md)
  clauses 1, 7 and 14, which fix the file and its reader.

## Consequences

- Positive: an operator turns a `bootstrap.p12` into the PEM pair with the
  project's own tool, on Linux and macOS, without OpenSSL.
- Negative / trade-offs: the key lies in the clear on whatever disk `--out`
  names, as the PEM pair of ADR-0020 does. Protecting that directory is the
  operator's job.
- Follow-ups: whether the Enrolments tab should offer the PEM pair again, now
  that the tool can make it; this ADR does not change what the Server hands out.

## Enforcement

Tests that will carry `Verifies: ADR-0031`:

- A `bootstrap.p12` made by `fleet_core::pkcs12::file::seal` extracts to a
  `bootstrap.pem` and a `bootstrap-key.pem` whose key matches the certificate.
  The key is `0600` on Unix (clauses 3 and 5).
- A wrong password, a file that is no bootstrap PKCS#12 file, and a file over
  the size bound are refused, and nothing is written (clause 3).
- An existing `bootstrap.pem` or `bootstrap-key.pem` in `--out` leaves both
  untouched, and the command fails naming it (clause 5).
- Without a terminal and without `--password-file` the command fails before it
  reads the file, and no command-line flag takes a password value (clause 4).
- `opamp-fleetctl pki --help` lists `p12-extract` among exactly the commands
  clause 2 names.
