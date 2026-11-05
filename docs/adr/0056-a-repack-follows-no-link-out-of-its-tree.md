# ADR-0056: A repack follows no link out of its tree, and a link that leads out fails the repack naming it

- **Status:** 🟢 accepted
- **Date:** 2026-10-24
- **Deciders:** Markus Brigl
- **Applies to:** the deterministic repack of `opamp-fleetctl package fetch`
  (`pack_tree` and `collect_members` in `crates/fleet-tools/src/fetch.rs`) and
  every kind whose upstream tree it packs, and every document that tells an
  operator what a repacked package carries
- **Supersedes:**
  [ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)
  clause 67

## Context

Where an upstream publishes no artifact a Client can run as published,
`opamp-fleetctl package fetch` unpacks it on the operator's host and repacks the
tree as a `.tar.gz` before it is signed
([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)
clause 67). A tree package carries no link (clause 59), so the repack
dereferences every link: a linked directory is packed under the linked name with
its contents, because that name is one the agent uses (the GLPI AppImage reaches
its Perl library through `usr/share/perl/5.26`, a link to `5.26.1`).

Clause 67 says _every_ link is dereferenced, and the code does exactly that: it
resolves a link with `std::fs::metadata` and reads it with `File::open`, both of
which follow an absolute target and a `../..` target out of the tree into the
operator host's own file system. A link `x -> /etc/ssl/certs` or
`y -> ../../../home/op/.config` in an upstream tree therefore packs the
operator's files into an artifact the operator then signs and the fleet installs
on every host it is offered to. Three things follow:

- **Disclosure.** Whatever the operator's account can read under the named path
  travels to the fleet, inside a signature that vouches for it. An upstream
  whose release is compromised, and whose download therefore matches the
  checksum published beside it, chooses which of the operator's files ship.
- **Determinism.** The bytes depend on the operator's host: the same release
  repacked on two hosts, or on one host before and after a change under `/etc`,
  gives two hashes, and clause 67's promise — the same release yields the same
  bytes and no accidental rollout — does not hold. Even a link that names
  nothing on one host is dropped there and packed on another.
- **Meaning.** An absolute link in an upstream tree names the file system of the
  host it was built for, not the tree. Packing the operator's copy of that path
  is never what upstream meant.

The specification puts security before convenience (**Q-1** _Secure by default_)
and holds that no vulnerability can be ruled out; hardening is the project's
first priority. Clause 67's wording covers the leak, so closing it changes an
accepted clause and needs this record
([`AGENTS.md` §3](../../AGENTS.md#3-adr-rules), rule 5;
[ADR-0009](0009-an-adr-may-supersede-named-clauses-of-another.md)).

The repack is not yet reached from any command: `pack_tree` is only called by
tests until a kind whose upstream needs a repack lands. The decision is
therefore made before it reaches an operator.

## Decision

We will resolve every link of a repacked tree inside that tree alone, and fail
the repack, naming the link, when a link leads out of it.

1. **Restates ADR-0026 clause 67. Every repack `opamp-fleetctl package fetch`
   makes is deterministic, and it carries nothing from outside its tree.** Where
   an upstream publishes no artifact a Client can run as published, the tool
   repacks it on the operator's host, before it is signed, into a `.tar.gz` that
   keeps file modes. The repack has a fixed member order and zeroed times and
   ownership, and it carries no link.
   - **A link is resolved inside the tree.** Its target is taken relative to the
     directory holding the link, and every link met on the way is resolved by
     the same rule. A link that resolves to a file or a directory inside the
     tree is dereferenced: a linked directory is packed under the linked name
     too, with its contents.
   - **A link that leads out of the tree fails the repack.** A link leads out
     when its target is absolute, or when resolving it climbs above the root of
     the tree, whether or not anything exists at the path it would name on the
     operator's host. The repack stops before it writes the artifact and names
     every such link by its path in the tree and its target. Nothing of the
     operator's host is read through it.
   - **A link that names nothing inside the tree is dropped.**
   - **A link leading back up the tree is not followed,** the root of the tree
     included: a link to a directory the walk is already inside is packed as
     that name and not descended into.
   - The member cap of clause 59 is checked while packing.

   Repacking the same release therefore yields the same bytes and the same hash
   on any operator's host, and no accidental rollout.

**Out of scope:** the file modes the repack keeps, including group- and
world-writable bits a tree may carry, which clause 60 and the first sentence
above leave as upstream set them; a kind's own removal, before packing, of links
it knows upstream leaves behind (as the GLPI repack removes `.DirIcon`), which
each kind states where it is decided; hard links, which are files of the tree;
and the trust in the extracted tree's origin, which the hash of what was
downloaded settles.

## Alternatives considered

- **Keep clause 67: follow every link.** The current behaviour. Rejected: it
  ships the operator's files to the fleet under a signature, and it makes the
  bytes depend on the operator's host, which breaks the clause's own promise.
- **Drop a link that leads out of the tree, and report it.** Nothing leaks
  either, the outcome is host-independent if the test is the same one, and a
  tree with stray links still repacks. Rejected as the default: the artifact
  then silently differs from the tree upstream built — a line on the operator's
  terminal, before a signature, is easily missed and never reaches the fleet —
  and an agent that needed the path fails on every host it is rolled out to
  rather than on the one host where it was packed. Failing puts the decision
  before the signature, where the operator is. A kind whose upstream reliably
  leaves such links removes them by name before packing, which is a reviewed,
  per-kind choice rather than a general silence. Dropping is cheaper to the
  operator; hardening outranks that.
- **Pack the out-of-tree link as a link.** Faithful to upstream, but a tree
  package refuses every link (clause 59), so the Client would refuse the
  artifact on every host. Rejected.
- **Decide by the canonical path on the operator's host** (`canonicalize` the
  target and compare it with the canonical root). Simple to write, but a target
  that does not exist cannot be canonicalized, so a dangling absolute link would
  be dropped on one host and refused on another, and the result would again
  depend on the host. Rejected for the rule; it may still serve inside the
  implementation for targets inside the tree.
- **Confine the walk with the operating system** (`openat2` with
  `RESOLVE_BENEATH`, or a chroot). Strong where it exists, but Linux-only, and
  the repack also runs on macOS. Left to the implementation as a further guard,
  not the rule.

## Sources / Prior art

- rsync's `--safe-links` (ignore a link that points outside the copied tree) and
  `--copy-unsafe-links` (copy what it points to, the behaviour clause 67 has):
  two established answers to the same question, the first close to the dropping
  alternative. Recalled from the rsync manual, not re-read for this record.
- GNU tar's `--dereference` (`-h`), which clause 67 already follows for links
  inside the tree and which follows a link wherever it leads. Recalled, not
  re-read.
- CWE-59, _Improper Link Resolution Before File Access ('Link Following')_: the
  class this leak belongs to. Recalled, not re-read.
- Reproducible Builds (reproducible-builds.org): an artifact's bytes must not
  depend on the build host's file system beyond its declared inputs. Recalled,
  not re-read.
- The extraction of the GLPI AppImage on the `feat/glpi` branch, whose comment
  says the Debian packaging leaves links "pointing at files no tree carries".
  Whether any of them is absolute was not verified for this record.

## Consequences

- Positive: no file of the operator's host reaches a signed artifact through a
  link, and the bytes of a repack depend on the release alone, so clause 67's
  determinism holds across operators.
- Positive: the operator learns of an out-of-tree link before signing, by name,
  on the host where it can be judged.
- Negative / trade-offs: an upstream tree with an absolute or escaping link no
  longer repacks until the kind removes that link by name. If the GLPI
  AppImage's Debian leftovers are absolute, the GLPI repack has to name them,
  which the kind's change does with its tests.
- Negative / trade-offs: resolving a link component by component inside the tree
  is more code than calling `metadata`; it is bounded by the member cap and by
  the ancestor guard against cycles.
- Follow-ups: whether a repack keeps a group- or world-writable mode as upstream
  set it or normalizes modes (for example to `0755`/`0644`), together with
  clause 60 on the Client, which applies a tar's mode as it finds it; whether
  the Client's tree extraction should clear those bits regardless of how the
  artifact was built.

## Enforcement

Tests that will carry `Verifies: ADR-0056`, in the tests of
`crates/fleet-tools/src/fetch.rs`:

- A tree holding a link with an absolute target to an existing file outside it,
  and one holding `../../` past the root to an existing file, each fail
  `pack_tree`, the error names the link, and no artifact is left at the output
  path.
- The same two links with targets that exist nowhere fail the same way, so the
  outcome does not depend on the host.
- A link inside the tree to a file and to a directory is still packed under its
  name with the contents, a link to a missing member inside the tree is dropped,
  and a link to the root or above inside the tree is not descended into. The
  existing
  `a_linked_directory_is_packed_under_both_names_and_a_cycle_does_not_hang` and
  `a_link_to_the_root_is_not_followed` move to this ADR for those halves of
  clause 1.
- Packing the same tree twice yields byte-identical artifacts.
