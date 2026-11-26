import { createHighlighter, type ThemeRegistration } from "shiki";

const v = (name: string) => `var(--syntax-${name})`;

const oxide: ThemeRegistration = {
  name: "oxide",
  type: "light",
  fg: v("plain"),
  bg: "transparent",
  colors: { "editor.foreground": v("plain"), "editor.background": "transparent" },
  tokenColors: [
    { scope: ["comment", "punctuation.definition.comment"], settings: { foreground: v("comment") } },
    { scope: ["punctuation", "keyword.operator", "meta.brace", "punctuation.separator", "punctuation.terminator"], settings: { foreground: v("punct") } },
    {
      scope: [
        "keyword",
        "storage.type",
        "storage.modifier",
        "keyword.control",
        "keyword.other",
        "keyword.declaration",
        "variable.language.self",
        "variable.language.this",
        "entity.other.attribute-name.table",
        "support.type.property-name.table",
        "punctuation.definition.table",
      ],
      settings: { foreground: v("keyword") },
    },
    {
      scope: ["entity.name.type", "entity.name.class", "entity.name.struct", "entity.name.enum", "entity.name.trait", "support.type", "support.class", "entity.name.type.primitive", "storage.type.core"],
      settings: { foreground: v("type") },
    },
    {
      scope: ["entity.name.function", "support.function", "meta.function-call.generic", "entity.name.command", "support.function.builtin"],
      settings: { foreground: v("fn") },
    },
    { scope: ["string", "punctuation.definition.string", "constant.character.escape", "string.quoted"], settings: { foreground: v("string") } },
    {
      scope: [
        "entity.name.function.macro",
        "support.macro",
        "meta.attribute",
        "punctuation.definition.attribute",
        "constant.numeric",
        "constant.language",
        "entity.name.function.preprocessor",
      ],
      settings: { foreground: v("macro") },
    },
    { scope: ["constant.other.option", "keyword.operator.redirect", "keyword.operator.pipe"], settings: { foreground: v("punct") } },
    {
      scope: [
        "variable",
        "variable.other",
        "variable.parameter",
        "entity.name.namespace",
        "support.type.property-name",
        "meta.object-literal.key",
        "entity.name.module",
        "support.variable.property",
        "variable.other.property",
      ],
      settings: { foreground: v("plain") },
    },
    { scope: ["entity.other.attribute-name.table", "support.type.property-name.table.toml"], settings: { foreground: v("keyword") } },
    { scope: ["entity.name.tag", "entity.name.section", "meta.group.toml", "punctuation.definition.section"], settings: { foreground: v("keyword") } },
    {
      scope: ["meta.attribute entity.name.type", "meta.attribute punctuation", "meta.attribute variable", "meta.attribute keyword.operator", "meta.attribute string"],
      settings: { foreground: v("macro") },
    },
  ],
};

const LANGS = ["rust", "toml", "shellscript", "typescript", "tsx", "javascript", "json", "sql", "yaml", "diff", "html", "http"];
const ALIASES: Record<string, string> = { rs: "rust", bash: "shellscript", sh: "shellscript", shell: "shellscript", zsh: "shellscript", console: "shellscript", ts: "typescript", js: "javascript", yml: "yaml" };

const LABELS: Record<string, string> = {
  rust: "Rust",
  toml: "TOML",
  shellscript: "Terminal",
  typescript: "TypeScript",
  tsx: "TypeScript",
  javascript: "JavaScript",
  json: "JSON",
  sql: "SQL",
  yaml: "YAML",
  diff: "Diff",
  html: "HTML",
  http: "HTTP",
};

let highlighter: ReturnType<typeof createHighlighter> | undefined;
const getHighlighter = () => (highlighter ??= createHighlighter({ themes: [oxide], langs: LANGS }));

export const escapeHtml = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

const lineSpan = (inner: string) => `<span class="line">${inner}</span>`;

export const resolveLang = (lang?: string | null) => {
  const l = (lang ?? "").toLowerCase();
  const id = ALIASES[l] ?? l;
  return LANGS.includes(id) ? id : "text";
};

export async function highlightLines(code: string, lang?: string | null): Promise<string> {
  const id = resolveLang(lang);
  const lines = code.replace(/\n$/, "").split("\n");
  if (id === "text") {
    return lines.map((l) => lineSpan(escapeHtml(l))).join("");
  }
  const hl = await getHighlighter();
  const { tokens } = hl.codeToTokens(code.replace(/\n$/, ""), { lang: id as never, theme: "oxide" });
  return tokens
    .map((line) =>
      lineSpan(
        line
          .map((t) => (!t.color || t.color === v("plain") ? escapeHtml(t.content) : `<span style="color:${t.color}">${escapeHtml(t.content)}</span>`))
          .join(""),
      ),
    )
    .join("");
}

export async function highlightInline(code: string, lang: string): Promise<string> {
  const hl = await getHighlighter();
  const { tokens } = hl.codeToTokens(code, { lang: resolveLang(lang) as never, theme: "oxide" });
  return tokens[0]
    .map((t) => (!t.color || t.color === v("plain") ? escapeHtml(t.content) : `<span style="color:${t.color}">${escapeHtml(t.content)}</span>`))
    .join("");
}

export const isRustcOutput = (code: string) => /^(error|warning)(\[[A-Z]\d{4}\])?: /.test(code.trimStart());

export function rustcLines(code: string): string {
  return code
    .replace(/\n$/, "")
    .split("\n")
    .map((line) => {
      let m: RegExpMatchArray | null;
      if ((m = line.match(/^(error|warning)(\[[A-Z]\d{4}\])?(:.*)$/))) {
        const level = m[1] + (m[2] ?? "");
        return lineSpan(`<span class="r-err">${level}</span><span class="r-b r-msg">${escapeHtml(m[3])}</span>`);
      }
      if ((m = line.match(/^(\s*)(-->|:::)(.*)$/))) {
        return lineSpan(`${m[1]}<span class="r-gut">${escapeHtml(m[2])}</span><span class="r-dim">${escapeHtml(m[3])}</span>`);
      }
      if ((m = line.match(/^(\s*)= (help|note|warning):(.*)$/))) {
        return lineSpan(`${m[1]}<span class="r-gut">= </span><span class="r-b r-dim">${m[2]}:</span><span class="r-dim">${escapeHtml(m[3])}</span>`);
      }
      if ((m = line.match(/^(help|note)(:.*)$/))) {
        return lineSpan(`<span class="r-b r-dim">${m[1]}</span><span class="r-dim">${escapeHtml(m[2])}</span>`);
      }
      if ((m = line.match(/^(\s*\d*\s*\|)(.*)$/))) {
        const gutter = m[1];
        const rest = m[2];
        if (/\d/.test(gutter)) {
          return lineSpan(`<span class="r-gut">${gutter}</span>${escapeHtml(rest)}`);
        }
        const caret = rest.indexOf("^");
        const head = caret === -1 ? rest : rest.slice(0, caret);
        const markers = head.replace(/[-|]+/g, (s) => `<span class="r-gut">${s}</span>`);
        if (caret !== -1) {
          const tail = rest.slice(caret);
          return lineSpan(`<span class="r-gut">${gutter}</span>${markers}<span class="r-err">${escapeHtml(tail)}</span>`);
        }
        const text = head.match(/^([\s\-|]*)(.*)$/)!;
        const lead = text[1].replace(/[-|]+/g, (s) => `<span class="r-gut">${s}</span>`);
        return lineSpan(`<span class="r-gut">${gutter}</span>${lead}<span class="r-sec">${escapeHtml(text[2])}</span>`);
      }
      if (line.trim() === "...") return lineSpan(`<span class="r-gut">${line}</span>`);
      return lineSpan(escapeHtml(line));
    })
    .join("");
}

const FILE_COMMENT = /^(?:\/\/|#|--)\s+((?:[\w.-]+\/)*[\w.-]+\.(?:rs|toml|ts|tsx|js|mjs|sql|json|ya?ml|sh|env))\s*$/;

export function splitTitle(code: string): { title?: string; code: string } {
  const [first, ...rest] = code.split("\n");
  const m = first.match(FILE_COMMENT);
  return m ? { title: m[1], code: rest.join("\n") } : { code };
}

export const copyButton = `<button type="button" class="copy-action" data-copy>Copy</button>`;

export function codeFrame(label: string, body: string, className = "code") {
  return `<figure class="${className}" data-pagefind-ignore><figcaption class="code-head"><span>${escapeHtml(label)}</span>${copyButton}</figcaption><pre class="code-body"><code>${body}</code></pre></figure>`;
}

export async function codeBlock(source: string, lang?: string | null, title?: string) {
  if (isRustcOutput(source) && resolveLang(lang) === "text") {
    return codeFrame(title ?? "cargo build", rustcLines(source), "code rustc");
  }
  const split = title ? { title, code: source } : splitTitle(source);
  const id = resolveLang(lang);
  const label = split.title ?? (id === "toml" && /^\[(dependencies|package|workspace)/m.test(split.code) ? "Cargo.toml" : (LABELS[id] ?? ""));
  return codeFrame(label, await highlightLines(split.code, lang), `code lang-${id}`);
}
