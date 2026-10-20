# ADR-0020: The Client's install takes the fleet's files it finds beside its program

- **Status:** 🟢 accepted · clauses 1, 2, 3 and 4 superseded by [ADR-0029](0029-a-bootstrap-certificate-as-a-password-protected-pkcs12-file-the-server-keeps.md)
- **Date:** 2026-10-13
- **Deciders:** Markus Brigl
- **Applies to:** `service install` and `service config` of the Client in `crates/fleet-agent/src/main.rs`, the questionnaire and the installer's answers in `crates/fleet-agent/src/config_init.rs`, the enrolment in `crates/fleet-agent/src/service/enrol.rs`, and every document that tells an operator how to install a Client
- **Supersedes:** [ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md) clauses 17, 19 and 42

## Context

A host joins the fleet with four things from the operator's offline directory: the server CA
(`server-ca.pem`), the bootstrap pair the Server issued (`bootstrap.pem`, `bootstrap-key.pem`,
[ADR-0028](0028-one-operator-program-that-makes-the-fleets-certificates.md)), and
the package verification key (`package-signing-key.pub`, ADR-0028 clause 3). An operator copies
them to the host together with the Client's program, typically into one directory, and runs the
install from there.

[ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md) clause 17 has
the questionnaire ask for each of them as a path, with no default on a fresh host, and clause 42
gives a non-interactive install no way to name them at all: a file written from `--endpoint` has no
CA and no client identity, and stays incomplete until someone runs the questionnaire.

The forces:

- **The files are named the same on every host.** `pki init` and the Server's issuing route give
  them fixed names, and the operator manual tells the operator to keep them. Asking for four paths
  whose answer is "here, next to the program" is typing that tells the Client nothing.
- **A host set up by a script has no terminal.** An install that needs the questionnaire for its
  identity cannot be automated; one that finds the files can.
- **The bootstrap pair is used once and is not written into the file** (ADR-0019 clause 17): the
  enrolment presents it and stores what the Server issues. That holds wherever the pair comes from.
- **Enrolment waits for an operator** (ADR-0021 clause 21). An install that enrols blocks until the
  request is approved or the wait is interrupted; an install that does not enrol leaves a service
  that refuses to start.

This serves **G-11** (the Client runs as an OS service on every platform) and **G-17** (the
connection is secured and the Agent is identified).

## Decision

We will have `service install` look beside its own program for `server-ca.pem`, `bootstrap.pem`,
`bootstrap-key.pem` and `package-signing-key.pub`, offer what it finds as the questionnaire's
defaults, and take it without a question when the install is not interactive, enrolling with a
bootstrap pair it finds.

1. **Beside the program is the directory of the running executable.** The install reads it from
   the operating system (`std::env::current_exe`), before the program is staged, so it is where the
   operator ran the program from. A file counts only when it is a readable regular file under its
   exact name. The bootstrap pair counts only as a pair; one of the two alone is named in a warning
   and not used. `package-signing-key.pub` counts when its content, trimmed, is 64 hexadecimal
   digits; any other content is named in a warning and not used.

2. **Restates ADR-0019 clause 17. The questionnaire asks only what has no useful default on a
   fresh host, and offers no answer the Client would refuse.** It asks for the Server `endpoint`,
   suggesting `wss://127.0.0.1:4320/v1/opamp`; a `ws://` or `http://` endpoint is refused unless its
   host is a loopback IP literal — `127.0.0.1` or `::1`; a host name is never loopback, `localhost`
   included — and the question is asked again with a message saying that beyond the loopback the
   endpoint must be `wss://` or `https://`. It asks for the Agent `name`, reported as
   `service.instance.name`. It asks for the CA certificate of the Server, written as
   `[tls] ca_file`, for every `wss://` or `https://` endpoint, without a question before it. It
   asks for the bootstrap certificate and its private key only while the Client is not enrolled —
   while its state directory holds no certificate the Server issued. It asks for the package
   verification key, written as `[packages] verification_key`; an empty answer is accepted, and the
   install then says that the Client installs no package, its own update included, until a key is
   configured.

   **Each question's default is what the file holds, else what lies beside the program**
   (clause 1), else none. The bootstrap pair is neither copied nor written into the file: the
   questionnaire enrols with it directly against the Server, after the file is written. It connects
   with the pair where it lies, sends the CSR
   ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
   clause 21), prints the request's key fingerprint and waits until an operator approves it, then
   stores the issued certificate in the state directory, where the Client looks for it first. An
   interrupted wait leaves the written file and registers nothing; running the install again
   resumes the request in flight, printing its fingerprint. A rejected request stays rejected for
   its key, and the wait goes on until it is interrupted: removing the pending key and request from
   the state directory starts a fresh one. On an enrolled Client neither file of the pair is asked:
   the Client renews what it was issued. A certificate already issued by the Server's client CA goes
   in `[tls] cert_file` and `key_file`, by editing the file. The pair is required while it is
   asked, and a path that names no readable file, here or for the CA, is asked for again.

   **The answered CA is copied beside the written file**, as `server-ca.pem`, owner-only on Unix,
   and the file names the copy. A copy left by an earlier answer is replaced. The copy is handed
   over to the service account with the file (ADR-0019 clause 13). The questionnaire asks nothing
   about the self-update: the file carries `[packages] self_update = true`, and the verification
   key decides whether that takes effect
   ([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md)). Everything else is
   written as commented defaults. No question asks for a credential, and no written file has an
   `[auth]` section; a leftover `[auth]` section is kept and ignored, as ADR-0019 clause 17 stated.

3. **Restates ADR-0019 clause 42. `service install --endpoint <URL>` writes the first
   configuration without a terminal, with what lies beside the program.** It writes the file
   `--interactive` writes, through the same renderer, with the endpoint given rather than asked:
   the same shape, mode `0600`, never overwriting an existing file, validated by the rule the
   Client applies to its endpoint at startup before anything is written — a `ws://` or `http://`
   endpoint whose host is not `127.0.0.1` or `::1` is refused, naming the setting, and `localhost`
   is no exception. It conflicts with `--interactive` and carries the self-update answer
   ([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md) clause 3). For a
   `wss://` or `https://` endpoint, a `server-ca.pem` beside the program is copied and written as
   `[tls] ca_file` as the questionnaire's answer would be, and a `package-signing-key.pub` beside it
   is written as `[packages] verification_key`. Each file it takes is printed. It has no flag for
   the CA file or the client identity, and it takes no credential, since there is none. The
   installers do not write TOML themselves. **The same rule binds every default an installer
   supplies:** no installer writes, prefills or prints a value the Client would refuse at startup,
   and none writes a setting that stands in for a client certificate.

4. **A non-interactive install enrols with a bootstrap pair it finds.** When the configuration —
   written by `--endpoint` or already on disk — has a `wss://` or `https://` endpoint, the Client is
   not enrolled, and a bootstrap pair lies beside the program, the install enrols with it as the
   questionnaire does (clause 2): it prints the request's key fingerprint, waits until an operator
   approves it or the wait is interrupted, and stores the issued certificate. It needs no terminal.
   An installer that runs the program from a directory holding a bootstrap pair therefore waits for
   an approval; one that runs it from where no pair lies does not.

5. **Restates ADR-0019 clause 19. The configuration is validated before the service is
   registered, by the rules the Client applies at startup.** The order is write → load through
   `ClientConfig::load` → enrol, when the questionnaire took a bootstrap pair (clause 2) or one lies
   beside the program (clause 4) → stage the layout → register, so a broken configuration fails at
   install and not at the service's first start. A `ws://` or `http://` endpoint off the loopback
   fails the install, naming the setting. A missing client identity is what the Client refuses at
   startup; the install names it in a warning and registers the service all the same, and the
   service refuses to run until the file is complete, so nothing ever runs unauthenticated. A file
   that already exists is validated the same way. A written file that fails to load is left on
   disk and named in the error. An interrupted enrolment leaves the written file and registers
   nothing.

**Out of scope:**

- Looking anywhere but beside the program, such as the working directory or a directory named on
  the command line.
- Taking the endpoint from a file beside the program.
- `service config` looking beside the program: it runs the installed copy, whose directory holds no
  fleet files.
- Removing the files beside the program after the install.

## Alternatives considered

- **Flags for each file (`--ca-file`, `--bootstrap-cert`, `--bootstrap-key`).** They name any
  location, but every scripted install then repeats four paths that are the same on every host.
  The names are fixed; the directory is the only thing that varies, and the program knows it.
- **Look in the working directory.** It is where the operator stands, not where the files were
  put. A service manager and an installer run from `/` or `System32`, where nothing lies.
- **Copy the bootstrap pair beside the configuration and let the service enrol on first start.**
  The install would not wait, but the pair would stay on the host after it has served, and the
  file would name a certificate that stops working within days. The enrolment is the install's,
  as the questionnaire already does it.
- **Use what lies beside the program only in the questionnaire.** It keeps a scripted install
  unchanged, but leaves every scripted install with an incomplete file and a service that refuses
  to start.
- **No decision.** The operator types four paths per host, and a scripted install stays incomplete.

## Sources / Prior art

- [ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md) clauses 13,
  16, 17, 19 and 42;
  [ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
  clauses 21 and 22; [ADR-0028](0028-one-operator-program-that-makes-the-fleets-certificates.md)
  clause 8.
- `std::env::current_exe`: the path of the running executable as the operating system reports
  it; on Linux it resolves symbolic links. <https://doc.rust-lang.org/std/env/fn.current_exe.html>
- Kubernetes `kubeadm join`: a joining node takes the CA and a bootstrap token, and waits for its
  first certificate before it serves.
  <https://kubernetes.io/docs/reference/setup-tools/kubeadm/kubeadm-join/>

## Consequences

- Positive: a host is installed by copying the program and the offline directory's four files into
  one directory and running `service install --endpoint <URL>` there; the install enrols and the
  service starts complete (G-11, G-17).
- Positive: the questionnaire's answers on a fresh host are Enter, Enter, Enter.
- Negative / trade-offs: an install run from a directory that holds a bootstrap pair waits for an
  operator's approval. An installer package whose program lies beside such a pair would wait too;
  the packages install their program where no pair lies.
- Negative / trade-offs: the files beside the program stay where they are. The bootstrap pair is
  worthless once the host is enrolled and ends within days; the operator removes it.
- Follow-ups: removing the bootstrap pair after a successful enrolment.

## Enforcement

Tests that will carry `Verifies: ADR-0020`:

- The files beside a given directory are found under their exact names; one file of the pair alone
  and a `package-signing-key.pub` that is not 64 hexadecimal digits are not taken (clause 1).
- The questionnaire's defaults are what the file holds, else what lies beside the program
  (clause 2).
- `--endpoint` with `server-ca.pem` and `package-signing-key.pub` beside the program writes a file
  whose `ca_file` names the copy and whose `verification_key` is the key; for a loopback `ws://`
  endpoint no CA is written; an existing file is kept (clause 3).
- A non-interactive install with a bootstrap pair beside the program enrols and stores the issued
  certificate; an enrolled Client does not enrol again (clauses 4 and 5).

**Not mechanically decidable:** that the installer packages put their program where no bootstrap
pair lies is held by review.
