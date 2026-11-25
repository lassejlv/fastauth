import path from "node:path";
import { renderMermaidSVG } from "beautiful-mermaid";
import { visit } from "unist-util-visit";
import type { Root, Code, Blockquote, Paragraph, Text } from "mdast";
import { codeBlock, escapeHtml } from "./code";
import { GITHUB, REPO_ROOT, docHref, slugOf } from "./site";

function rewriteUrl(url: string, dir: string) {
  if (!url || /^[a-z][a-z\d+.-]*:/i.test(url) || url.startsWith("#") || url.startsWith("//") || url.startsWith("/")) return url;
  const [target, hash] = url.split("#");
  const anchor = hash ? `#${hash}` : "";
  const rel = path.relative(REPO_ROOT, path.resolve(dir, target)).split(path.sep).join("/");
  if (rel.startsWith("..")) return url;
  if (/^docs\/[^/]+\.md$/.test(rel)) return docHref(slugOf(rel)) + anchor;
  if (rel === "CHANGELOG.md") return "/changelog/" + anchor;
  if (rel === "" || rel === "README.md") return GITHUB + "#readme";
  return `${GITHUB}/blob/main/${rel}${anchor}`;
}

const ALERT = /^\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*/i;

function toCallout(node: Blockquote) {
  const first = node.children[0] as Paragraph | undefined;
  const text = first?.type === "paragraph" ? (first.children[0] as Text | undefined) : undefined;
  let kind = "note";
  if (text?.type === "text") {
    const m = text.value.match(ALERT);
    if (m) {
      kind = m[1].toLowerCase();
      text.value = text.value.slice(m[0].length);
      if (!text.value && first) first.children.shift();
      if (first && first.children[0]?.type === "break") first.children.shift();
    }
  }
  const tone = kind === "warning" || kind === "caution" ? "warning" : "note";
  node.data = { hName: "aside", hProperties: { className: ["callout", `callout-${tone}`], role: "note" } };
}

function mermaid(code: string) {
  try {
    const svg = renderMermaidSVG(code, {
      bg: "var(--diagram-bg)",
      fg: "var(--diagram-fg)",
      line: "var(--diagram-line)",
      muted: "var(--diagram-muted)",
      surface: "var(--diagram-surface)",
      border: "var(--diagram-border)",
      transparent: true,
      font: "Schibsted Grotesk Variable",
    });
    return `<figure class="diagram" data-pagefind-ignore>${svg.replace(/@import url\([^)]*\);?/g, "")}</figure>`;
  } catch {
    return `<pre class="diagram-source">${escapeHtml(code)}</pre>`;
  }
}

export function remarkDocs() {
  return async (tree: Root, file: { path?: string; history?: string[] }) => {
    const source = file.path ?? file.history?.[0];
    const dir = source ? path.dirname(source) : path.join(REPO_ROOT, "docs");

    const h1 = tree.children.findIndex((n) => n.type === "heading" && n.depth === 1);
    if (h1 !== -1) tree.children.splice(h1, 1);

    visit(tree, ["link", "definition"], (node) => {
      const n = node as { url: string };
      n.url = rewriteUrl(n.url, dir);
    });

    visit(tree, "blockquote", (node) => toCallout(node as Blockquote));

    const codes: { node: Code; index: number; parent: { children: unknown[] } }[] = [];
    visit(tree, "code", (node, index, parent) => {
      if (parent && index !== undefined) codes.push({ node: node as Code, index, parent: parent as never });
    });
    for (const { node, index, parent } of codes) {
      const lang = node.lang?.toLowerCase();
      const title = node.meta?.match(/title="([^"]+)"/)?.[1];
      const value = lang === "mermaid" ? mermaid(node.value) : await codeBlock(node.value, lang, title);
      parent.children[index] = { type: "html", value };
    }
  };
}

export function rehypeTables() {
  return (tree: { children: unknown[] }) => {
    const walk = (node: { type?: string; tagName?: string; children?: unknown[] }) => {
      if (!node.children) return;
      node.children = node.children.map((child) => {
        const c = child as { type?: string; tagName?: string; children?: unknown[] };
        if (c.type === "element" && c.tagName === "table") {
          return { type: "element", tagName: "div", properties: { className: ["table-wrap"] }, children: [c] };
        }
        walk(c);
        return c;
      });
    };
    walk(tree);
  };
}
