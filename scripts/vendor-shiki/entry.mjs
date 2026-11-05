// The entry of crates/fleet-server/static/shiki.js, bundled by scripts/vendor-shiki.sh (ADR-0038).
// Shiki's fine-grained core: the JavaScript regex engine (no WebAssembly), the CSS-variables theme
// with this project's TOML and INI token rules (each look's stylesheet defines the colours) and
// only the grammars ADR-0038 clause 3 names.
import { createCssVariablesTheme, createHighlighterCore, hastToHtml } from "shiki/core";
import { createJavaScriptRegexEngine } from "shiki/engine/javascript";
import ini from "shiki/langs/ini.mjs";
import toml from "shiki/langs/toml.mjs";
import yaml from "shiki/langs/yaml.mjs";

// The CSS-variables theme leaves TOML table headers, keys, dates and brackets and INI section
// headers in the foreground colour. These rules give them the variables YAML's keys and values
// already use, so the three languages look alike and no stylesheet needs a variable of its own
// (ADR-0038 clause 4). INI's unquoted values carry no scope of their own and stay as they are.
const base = createCssVariablesTheme({ name: "css-variables" });
const theme = {
  ...base,
  tokenColors: [
    ...base.tokenColors,
    {
      scope: ["meta.group.toml", "meta.group.double.toml", "entity.name.section"],
      settings: { foreground: "var(--shiki-token-function)" },
    },
    { scope: "variable.other.key.toml", settings: { foreground: "var(--shiki-token-keyword)" } },
    { scope: "constant.other.date.toml", settings: { foreground: "var(--shiki-token-constant)" } },
    {
      scope: ["punctuation.definition.array", "punctuation.definition.inline-table"],
      settings: { foreground: "var(--shiki-token-punctuation)" },
    },
  ],
};
let highlighter;

// The coloured tokens of `text` as HTML, lines joined by newlines, without Shiki's own <pre> and
// <code>, so the caller keeps its element and the look keeps its background; null when `lang` is
// not bundled or anything fails, and the caller then shows the plain text.
window.fleetHighlight = async (text, lang) => {
  try {
    highlighter ??= createHighlighterCore({
      themes: [theme],
      langs: [yaml, toml, ini],
      engine: createJavaScriptRegexEngine(),
    });
    const root = (await highlighter).codeToHast(text, { lang, theme: "css-variables" });
    const code = root.children[0].children[0];
    return hastToHtml({ type: "root", children: code.children });
  } catch {
    return null;
  }
};
