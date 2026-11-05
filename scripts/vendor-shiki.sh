#!/usr/bin/env bash
#
# Rebuilds crates/fleet-server/static/shiki.js, the vendored Shiki bundle the bundled UI colours an
# Agent's effective configuration with (ADR-0038), and pins its SHA-256 in scripts/vendor-shiki.lock.
#
# Dev-only: run it when the version is to change, on a developer's machine. CI and the Dev
# Container never run it and need no node (ADR-0010 clause 14). The bundle is built from the
# inputs under scripts/vendor-shiki/: package.json names the exact versions, package-lock.json
# pins every package with its integrity hash, entry.mjs is the code bundled. To change a version,
# edit package.json, refresh the lock with `npm install --package-lock-only --ignore-scripts` in
# that directory, and run this script; commit the lock, shiki.js and vendor-shiki.lock together,
# since a test fails while the bundle's hash differs from the pinned one.
#
# Needs node >= 22.22.2 or >= 24.15.0 (npm's own requirement) as `node` on PATH or named by
# $NODE, curl, tar and sha256sum. npm is not needed: the script fetches the pinned npm release from
# the registry, checks its integrity, and runs it with that node. Everything is downloaded into a
# temporary directory outside the repository and removed afterwards; npm checks every package
# against the lock's integrity hash and runs no install scripts.
#
# Usage:
#     scripts/vendor-shiki.sh        (or: NODE=/path/to/node bash scripts/vendor-shiki.sh)
# Prints the bundle's SHA-256. Exit code 0 when the bundle was written, 1 otherwise.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INPUTS="$ROOT/scripts/vendor-shiki"
OUT="$ROOT/crates/fleet-server/static/shiki.js"
PIN="$ROOT/scripts/vendor-shiki.lock"

# The npm release that installs from the lock, and its integrity as the registry states it.
NPM_VERSION="12.2.0"
NPM_INTEGRITY="sha512-ZsJjKpTnlmSXOLLXiU1xDCzC4Wlok4IwZmh/aw2KUuXytU7q6qMv/cUT7MoeSf95Slwuw/lRXYefGzGCspHPNQ=="

NODE="${NODE:-node}"
if ! command -v "$NODE" >/dev/null 2>&1; then
  echo "node not found: put node >= 22.22.2 on PATH or name it with NODE=/path/to/node" >&2
  exit 1
fi
for tool in curl tar sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || { echo "$tool not found" >&2; exit 1; }
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/vendor-shiki.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# npm, fetched into its own directory and checked before it is unpacked.
mkdir "$WORK/npm"
curl -fsSL -o "$WORK/npm.tgz" "https://registry.npmjs.org/npm/-/npm-$NPM_VERSION.tgz"
actual="$("$NODE" -e 'const c=require("node:crypto"),f=require("node:fs");
  console.log("sha512-"+c.createHash("sha512").update(f.readFileSync(process.argv[1])).digest("base64"))' \
  "$WORK/npm.tgz")"
if [[ "$actual" != "$NPM_INTEGRITY" ]]; then
  echo "npm $NPM_VERSION does not have the pinned integrity: $actual" >&2
  exit 1
fi
tar -xzf "$WORK/npm.tgz" -C "$WORK/npm"

# The build inputs, installed exactly as the lock pins them.
mkdir "$WORK/build"
cp "$INPUTS/package.json" "$INPUTS/package-lock.json" "$INPUTS/entry.mjs" "$WORK/build/"
(
  cd "$WORK/build"
  "$NODE" "$WORK/npm/package/bin/npm-cli.js" ci --ignore-scripts --no-audit --no-fund --loglevel=error
)

version() {
  "$NODE" -e 'console.log(require(process.argv[1]).version)' "$WORK/build/node_modules/$1/package.json"
}
shiki="$(version shiki)"
engine="$(version @shikijs/engine-javascript)"
langs="$(version @shikijs/langs)"
esbuild="$(version esbuild)"

# The header names what the file is, what built it, and the licences of what it bundles; every
# bundled package is MIT-licensed, and the grammars are under the licences NOTICE names.
header="$(cat <<EOF
/*
 * Shiki $shiki (https://shiki.style) for the bundled UI of OpAMP Fleet (ADR-0038):
 * shiki@$shiki, @shikijs/core@$shiki, @shikijs/engine-javascript@$engine,
 * @shikijs/langs@$langs (yaml, toml, ini), the CSS-variables theme with this project's TOML and
 * INI token rules, and their dependencies.
 * Built by scripts/vendor-shiki.sh with esbuild@$esbuild from scripts/vendor-shiki/; do not edit,
 * rebuild. Exposes window.fleetHighlight(text, lang) -> Promise<string | null>.
 *
 * Copyright (c) 2021 Pine Wu, (c) 2023 Anthony Fu (shiki, @shikijs/*);
 * (c) Microsoft Corporation (@shikijs/vscode-textmate, the ini grammar);
 * (c) 2024-2026 Steven Levithan (oniguruma-to-es, oniguruma-parser, regex, regex-utilities,
 * regex-recursion); (c) Titus Wormer (hast-util-to-html and its dependencies). MIT License:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 * and associated documentation files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions: The above copyright notice
 * and this permission notice shall be included in all copies or substantial portions of the
 * Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE
 * AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * The yaml and toml grammars come from TextMate's yaml.tmbundle and toml.tmbundle: Permission to
 * copy, use, modify, sell and distribute this software is granted. This software is provided
 * "as is" without express or implied warranty, and with no claim as to its suitability for any
 * purpose.
 */
EOF
)"

(
  cd "$WORK/build"
  "$NODE" node_modules/esbuild/bin/esbuild entry.mjs --bundle --format=iife --minify \
    --target=es2022 --legal-comments=none --log-level=warning \
    --banner:js="$header" --outfile="$WORK/shiki.js"
)

# The page's policy admits no eval and no WebAssembly (ADR-0038 clause 1): a bundle that needs
# either is refused here rather than shipped.
if grep -qE '\beval\(|new Function\b|WebAssembly' "$WORK/shiki.js"; then
  echo "the bundle uses eval, new Function or WebAssembly, which the UI's policy forbids" >&2
  exit 1
fi

cp "$WORK/shiki.js" "$OUT"
sha="$(sha256sum "$OUT" | cut -d' ' -f1)"
cat >"$PIN" <<EOF
# The vendored crates/fleet-server/static/shiki.js (ADR-0038 clause 2), written by
# scripts/vendor-shiki.sh. A test fails while the file's SHA-256 differs from the one here.
shiki $shiki
sha256 $sha
EOF
echo "wrote ${OUT#"$ROOT/"} ($(wc -c <"$OUT") bytes), shiki $shiki"
echo "sha256 $sha"
