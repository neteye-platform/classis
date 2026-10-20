# ADR-0038: The bundled UI colours an Agent's effective configuration with Shiki's TextMate grammars and its JavaScript engine, vendored as one file with a pinned hash

- **Status:** 🟢 accepted
- **Date:** 2026-10-17
- **Deciders:** Markus Brigl
- **Applies to:** the effective-configuration cell and dialog of the Agents tab in `crates/fleet-server/static/index.html`, the vendored `crates/fleet-server/static/shiki.js` and the route that serves it in `crates/fleet-server/src/api.rs`, the token colours in `crates/fleet-server/static/ui.css`, `ui-carbon.css` and `ui-quiet.css`, the script that builds the vendored file under `scripts/`, and `NOTICE`

## Context

The Agents tab shows each Agent's effective configuration as plain text, in a table cell and in a
dialog. These texts are long YAML or TOML files, and without colour they are hard to read. The
human wants them coloured with TextMate grammars, the ones VS Code uses, and the colouring done
locally in the browser. The human chose to colour only the effective configuration for now, not
the Configuration editor.

Forces:

- [ADR-0010](0010-five-crates-the-whole-opamp-communication-layer-in-the-opamp-crate-and-toml-configuration.md) clause 14: the bundled UI is static assets
  embedded in the Server binary, plain HTML, CSS and JS, with **no frontend toolchain**. Its
  alternatives reject a node toolchain in the Dev Container and in CI. Redoc is vendored as one
  pre-built file and named in `NOTICE`; that is the precedent.
- The Operator plane's CSP is `script-src 'self'` plus the hashes of the inline scripts, and no
  `'wasm-unsafe-eval'`. TextMate grammars are written for the Oniguruma regex engine, which
  usually runs as WebAssembly. Allowing WebAssembly would weaken the policy (Q-1).
- Shiki is the library that brings VS Code's TextMate grammars to the browser. Since its 1.x line
  it has a JavaScript regex engine (`@shikijs/engine-javascript`) that translates the grammars'
  Oniguruma patterns into JavaScript regular expressions, with no WebAssembly. Shiki 4.5.0 was
  published on 2026-10-01 under the MIT licence.
- Shiki ships as ES modules with dependencies. It has no single pre-built browser file like
  Redoc's, so one has to be built once.
- The supply-chain check (Q-3, `cargo-deny`) covers Rust crates only. A vendored JavaScript file
  is outside it, as Redoc is today.
- The Server knows no configuration format (Non-Goal "Replacing an agent's configuration
  language"). Choosing a grammar for display is presentation and changes nothing the Server
  stores, sends or decides.

## Decision

We will colour an Agent's effective configuration in the bundled UI with Shiki 4.5.0 and its
JavaScript regex engine, vendored as one pre-built file whose version and SHA-256 are pinned and
checked by a test, and whose colours come from each look's stylesheet.

1. **One vendored file, built once, never in CI.**
   - `crates/fleet-server/static/shiki.js` is a single browser script built from `shiki@4.5.0`
     with `@shikijs/engine-javascript`, the grammars of clause 3 and Shiki's CSS-variables theme.
     It exposes one function on `window`. The file starts with a header naming the packages,
     their versions and the script that built it.
   - `scripts/vendor-shiki.sh` rebuilds it. It runs only when the version is to change, on a
     developer's machine. CI and the Dev Container do not need node; ADR-0010 clause 14 stands.
   - The Server embeds the file and serves it from its own origin as `/shiki.js`, like the
     stylesheets. The CSP does not change: `script-src 'self'` covers it, and nothing needs
     WebAssembly or `eval`.

2. **The version and the hash are pinned and checked.** The file's SHA-256 and the version are
   written beside the build script. A test fails when the embedded file's hash differs from the
   pinned one, so the file cannot change without the pin changing in the same commit. `NOTICE`
   names Shiki and every package and grammar bundled, with their licences. Shiki and its packages
   are MIT; the YAML and TOML grammars come from TextMate's bundles under TextMate's own permissive
   notice, the INI grammar from VS Code under MIT. The bundle's header carries both texts.

3. **The grammar follows the Agent type, and anything else stays plain.** The UI chooses the
   grammar from the Agent's reported `service.name`:
   - `otelcol`, `otelcol-contrib` and any name starting `otelcol` → YAML;
   - this fleet's own Client (`supervisor`) and `telegraf` → TOML;
   - `fluent-bit` → INI;
   - any other type → no colouring, the text shown as today.

   Only YAML, TOML and INI are bundled. A grammar is added when a supported kind needs it.

4. **The colours are the look's.** The theme emits `var(--shiki-…)` colours. Each of `ui.css`,
   `ui-carbon.css` and `ui-quiet.css` defines them for its light and dark theme, so a coloured
   configuration follows the look and the theme the operator chose.
   - The theme is Shiki's CSS-variables theme with token rules of this project's on top: the
     CSS-variables theme alone leaves TOML table headers and keys and everything in INI but its
     comments in the foreground colour. The added rules map the TOML and INI scopes for table
     and section headers, keys, values and operators onto the same `--shiki-token-*` variables,
     so no stylesheet needs a variable of its own for them.
   - An unquoted INI value, and a `key: value` or Fluent Bit `Name cpu` line, stay in the
     foreground colour: the bundled INI grammar gives them no scope of their own, and a rule on the
     whole `source.ini` would colour every line alike.

5. **Colouring is display only, and it never blocks.** The text is coloured after the table is
   drawn, on the cell and in the dialog. If the script fails to load or a grammar throws, the
   plain text stays. Text is escaped as today; Shiki builds its HTML from tokens of the text, not
   from markup in it.

**Out of scope:** colouring or editing the Configuration body (a later step, if wanted); a code
editor; a grammar per Configuration chosen by the operator; formatting (re-indenting) any
configuration; WebAssembly in the browser.

## Alternatives considered

- **highlight.js or Prism.** They are small (20–50 KB) and ship as single files. Their regular
  expressions are their own, not TextMate grammars, and colour YAML and TOML less exactly. The
  human asked for TextMate.
- **Shiki with the Oniguruma engine.** It is the reference engine, but it needs WebAssembly, so the
  CSP would need `'wasm-unsafe-eval'`. The JavaScript engine reaches the same grammars without it.
- **Loading Shiki from a CDN.** It needs no vendoring. It breaks the UI on a host without internet,
  hands the page to a third party, and would need the CSP opened to that origin.
- **A node toolchain in CI that builds the file on every build.** It keeps the file reproducible
  at all times. ADR-0010 rejected this cost for a rudimentary UI, and the pinned hash (clause 2)
  catches an unreviewed change.
- **Colouring on the Server.** Shiki could run there through a JavaScript runtime or a Rust port
  of TextMate (`syntect`). It adds a dependency to the Server binary for a display concern, and
  colours that would not follow the look.

## Sources / Prior art

- npm registry: `shiki` 4.5.0, published 2026-10-01, licence MIT; its dependencies include
  `@shikijs/engine-javascript` and `@shikijs/langs`; the CSS-variables theme comes from Shiki's
  core, so `@shikijs/themes` is not bundled.
- Shiki documentation: the JavaScript regex engine and the CSS-variables theme.
- ADR-0010 clause 14 and its alternative "A frontend framework and bundler for the UI";
  `NOTICE` (Redoc vendored as a pre-built file); the Operator plane's CSP in
  `crates/fleet-server/src/api.rs`.

## Consequences

- Positive: effective configurations are readable, coloured with the grammars operators know from
  VS Code, in the look's own colours, with no change to the CSP and no network access.
- Negative / trade-offs: the Server binary grows by the size of the bundle, about 190 KB.
- Negative / trade-offs: the JavaScript file is outside `cargo-deny`. The pinned hash makes a
  change visible but does not scan for vulnerabilities; updating Shiki is a manual step with the
  script.
- Negative / trade-offs: the JavaScript engine may fail on a rare grammar pattern. The text then
  stays plain (clause 5).
- Follow-ups:
  - Colouring the Configuration body while it is edited.
  - A supply-chain check that covers vendored JavaScript as well as Rust crates.

## Enforcement

Tests that will carry `Verifies: ADR-0038`:

- The embedded `shiki.js` has the pinned SHA-256.
- `GET /shiki.js` answers the file with a JavaScript content type, under the unchanged CSP.
- The UI loads `/shiki.js` and maps `otelcol*` to YAML, `supervisor` and `telegraf` to TOML,
  and `fluent-bit` to INI.
- Each of the three stylesheets defines the CSS-variables theme's colours for light and dark.
