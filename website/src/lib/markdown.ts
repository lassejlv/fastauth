import fs from "node:fs";
import path from "node:path";
import { checks, client, crates, hero, heroCode, install, later } from "./landing";
import { CRATES_IO, DOCS_RS, GITHUB, REPO_ROOT, slugOf, version, type DocPage, type NavGroup } from "./site";

export const SITE = "https://fastauth.lassejlv.dev";

export const markdownHref = (href: string) => (href === "/" ? "/index.md" : href.replace(/\/$/, "") + ".md");

function rewriteUrl(url: string, dir: string) {
  if (!url || /^[a-z][a-z\d+.-]*:/i.test(url) || url.startsWith("#") || url.startsWith("//")) return url;
  const [target, hash] = url.split("#");
  const anchor = hash ? `#${hash}` : "";
  if (target.startsWith("/")) return SITE + markdownHref(target) + anchor;
  const rel = path.relative(REPO_ROOT, path.resolve(dir, target)).split(path.sep).join("/");
  if (rel.startsWith("..")) return url;
  if (/^docs\/.+\.md$/.test(rel)) return `${SITE}/docs/${slugOf(rel)}.md${anchor}`;
  if (rel === "CHANGELOG.md") return `${SITE}/changelog.md${anchor}`;
  if (rel === "" || rel === "README.md") return GITHUB + "#readme";
  return `${GITHUB}/blob/main/${rel}${anchor}`;
}

function rewriteLinks(line: string, dir: string) {
  const spans: string[] = [];
  const masked = line.replace(/(`+)[^`]*?\1/g, (span) => `\u0000${spans.push(span) - 1}\u0000`);
  return masked
    .replace(/\]\(\s*<?([^)\s>]+)>?((?:\s+"[^"]*")?)\s*\)/g, (_, url, title) => `](${rewriteUrl(url, dir)}${title})`)
    .replace(/^(\s{0,3}\[[^\]]+\]:\s*)(\S+)/, (_, head, url) => head + rewriteUrl(url, dir))
    .replace(/\u0000(\d+)\u0000/g, (_, i) => spans[Number(i)]);
}

const FENCE = /^(\s*)(`{3,}|~{3,})\s*([\w+-]*)/;
const RUST = new Set(["rust", "rs"]);

export function agentMarkdown(title: string, body: string, sourceFile?: string) {
  const dir = sourceFile ? path.dirname(path.resolve(sourceFile)) : REPO_ROOT;
  const lines = body
    .replace(/^\uFEFF/, "")
    .replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n/, "")
    .replace(/\r\n/g, "\n")
    .split("\n");
  const out: string[] = [];
  let fence: { marker: string; rust: boolean } | undefined;
  let droppedTitle = false;
  let inComment = false;
  for (const line of lines) {
    const open = line.match(FENCE);
    if (fence) {
      if (open && open[2].startsWith(fence.marker) && !open[3]) fence = undefined;
      else if (fence.rust && /^\s*#(?:\s|$)/.test(line)) continue;
      else if (fence.rust) {
        out.push(line.replace(/^(\s*)##/, "$1#"));
        continue;
      }
      out.push(line);
      continue;
    }
    if (open) {
      fence = { marker: open[2], rust: RUST.has(open[3].toLowerCase()) };
      out.push(line);
      continue;
    }
    if (inComment) {
      if (line.includes("-->")) inComment = false;
      continue;
    }
    if (/^\s*<!--/.test(line) && !line.includes("-->")) {
      inComment = true;
      continue;
    }
    const text = line.replace(/<!--[\s\S]*?-->/g, "");
    if (!droppedTitle && /^#\s+/.test(text)) {
      droppedTitle = true;
      continue;
    }
    if (/^\s*(import|export)\s.+from\s+["']/.test(text)) continue;
    out.push(rewriteLinks(text, dir));
  }
  const content = out.join("\n").replace(/\n{3,}/g, "\n\n").trim();
  return `# ${title}\n\n${content}\n`;
}

export const markdownResponse = (text: string, type = "text/markdown") =>
  new Response(text, { headers: { "Content-Type": `${type}; charset=utf-8` } });

type Nav = { groups: NavGroup[]; ordered: DocPage[] };

export const SUMMARY = `fastauth is ${hero.title.charAt(0).toLowerCase()}${hero.title.slice(1, -1)}: ${hero.lede.charAt(0).toLowerCase()}${hero.lede.slice(1)}`;

const CHANGELOG_DESCRIPTION = "Every change to fastauth, newest first";

function readmeIntro() {
  const text = fs.readFileSync(path.join(REPO_ROOT, "README.md"), "utf8").replace(/^#\s+.+\n+/, "");
  return text.split(/\n\s*\n/)[0].replace(/\s*\n\s*/g, " ").trim();
}

function navList(nav: Nav, hrefs?: string[]) {
  const links = nav.groups.flatMap((g) => g.pages).filter((l) => !hrefs || hrefs.includes(l.href));
  return links.map((l) => {
    const description = l.href === "/changelog/" ? CHANGELOG_DESCRIPTION : nav.ordered.find((p) => p.href === l.href)?.description;
    return `- [${l.title}](${SITE}${markdownHref(l.href)})${description ? `: ${description}` : ""}`;
  });
}

export function llmsTxt(nav: Nav) {
  const sections = nav.groups.map((g) => `## ${g.label}\n\n${navList(nav, g.pages.map((p) => p.href)).join("\n")}`);
  const optional = [
    `- [All docs in one file](${SITE}/llms-full.txt): every page above, in this order`,
    `- [Landing page](${SITE}/index.md): install command, an example and the crate list`,
    `- [Source on GitHub](${GITHUB}): the repository, with examples and the CLI`,
    `- [API reference on docs.rs](${DOCS_RS}): rustdoc for every crate`,
  ];
  const tip = "Every page on this site has a Markdown version: add .md to its path, for example /docs/quickstart.md.";
  return [`# fastauth`, `> ${SUMMARY}`, readmeIntro(), tip, ...sections, `## Optional\n\n${optional.join("\n")}`].join("\n\n") + "\n";
}

export function landingMarkdown(nav: Nav) {
  const release = version().split(".").slice(0, 2).join(".");
  const start = ["/docs/overview/", "/docs/quickstart/", "/docs/configuration/", "/docs/plugins/", "/docs/better-auth-client/", "/changelog/"];
  return [
    "# fastauth",
    `> ${hero.title} ${hero.lede}`,
    readmeIntro(),
    `## Install\n\n\`\`\`bash\n${install}\n\`\`\``,
    `## Example\n\n\`\`\`rust\n${heroCode}\n\`\`\``,
    `## A missing plugin is a compile error\n\nChecked by rustc:\n\n${checks.map((c) => `- ${c}`).join("\n")}`,
    `## Better Auth's TypeScript client works unchanged\n\n${client.map(([k, v]) => `- ${k}: ${v}`).join("\n")}`,
    `## What's in ${release}\n\n${[...crates.map(([k, v]) => `- \`${k}\`: ${v}`), ...later.map(([k, v]) => `- ${k}: ${v}`)].join("\n")}`,
    `## Docs\n\n${navList(nav, start).join("\n")}\n- [Every page](${SITE}/llms.txt): the full docs index for agents`,
    `## Project\n\n- [GitHub](${GITHUB})\n- [crates.io](${CRATES_IO})\n- [docs.rs](${DOCS_RS})\n- License: MIT`,
  ].join("\n\n") + "\n";
}
