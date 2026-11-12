# Changelog

Operator-facing changes to the Server and the Client — what a running deployment
has to be told about, in particular anything that must be edited or moved before
an upgrade. The reasoning behind each change lives in the ADR it names
([`docs/adr/`](docs/adr/)); this file says only what to do.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). A
version is the one `[workspace.package] version` in `Cargo.toml` names, which
the release pipeline creates the `version/*` tag from
([ADR-0012](docs/adr/0012-versions-resolved-in-the-internal-crate.md)). A
section carries a date once its tag exists.

## [Unreleased]

### Changed

- **The product is renamed from OpAMP Fleet to Classis**
  ([ADR-0061](docs/adr/0061-the-product-is-named-classis-and-the-strings-signatures-cover-keep-their-old-spelling.md)).
  Nothing reads an old name any more, so an installation is moved by hand
  before the upgrade:
  - **Client.** The product `opamp-fleet` is now `classis`: the package, the
    services `opamp-fleet` and `opamp-fleet-agents` (now `classis` and
    `classis-agents`), the Managed Processes' account `opamp-fleet-agents` /
    `_opamp-fleet-agents` (now `classis-agents` / `_classis-agents`), and every
    directory named after the product — `/opt/opamp-fleet`,
    `/var/lib/opamp-fleet`, `/usr/libexec/opamp-fleet`,
    `/run/opamp-fleet-agents`, and their macOS and Windows counterparts. Run
    `opamp-fleet service uninstall` with the old release, install the new package,
    and move `supervisor.toml` and the state directory to the new paths before
    starting it.
  - **Server.** The variables `FLEET_SERVER__…` and `FLEET_SERVER_CONFIG` are
    now `CLASSIS_SERVER__…` and `CLASSIS_SERVER_CONFIG`; the image is
    `ghcr.io/neteye-platform/classis-server`; the example paths in the
    manual are `/etc/classis`, `/etc/classis-server` and
    `/var/lib/classis-server`.
  - **Operator tool.** `opamp-fleetctl` is now `classisctl`, its release assets
    `classisctl_<version>_<os>_<arch>…`. A CA it creates from now on is named
    _Classis … CA_; existing CAs keep their names and stay valid.
  - **Unchanged:** the certificate URIs `urn:opamp-fleet:…`, the proof and
    signing formats `opamp-fleet-…-v1` and the Gateway's binding store. Issued
    certificates, signed packages, signing files and Gateway bindings remain
    valid across the upgrade.
