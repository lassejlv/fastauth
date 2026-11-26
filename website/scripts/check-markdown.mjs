import fs from "node:fs";
import path from "node:path";

const SITE = "https://fastauth.lassejlv.dev";
const dist = path.resolve(process.argv[2] ?? "dist");
const errors = [];
const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)]));
const files = walk(dist).map((f) => path.relative(dist, f).split(path.sep).join("/"));
const read = (f) => fs.readFileSync(path.join(dist, f), "utf8");
const twinOf = (route) => (route === "/" ? "index.md" : route.slice(1).replace(/\/$/, "") + ".md");

const pages = files.filter((f) => f.endsWith(".html") && f !== "404.html" && !/http-equiv="refresh"/.test(read(f)));
for (const f of pages) {
  const route = "/" + f.replace(/(^|\/)index\.html$/, "$1");
  const twin = twinOf(route);
  if (!files.includes(twin)) errors.push(`${route}: missing twin ${twin}`);
  const html = read(f);
  if (!html.includes(`<link rel="alternate" type="text/markdown" href="${SITE}/${twin}">`)) errors.push(`${route}: missing alternate link`);
}

const anchorsOf = (mdFile) => {
  const html = mdFile === "index.md" ? "index.html" : mdFile.replace(/\.md$/, "/index.html");
  return files.includes(html) ? new Set([...read(html).matchAll(/\sid="([^"]+)"/g)].map((m) => m[1])) : new Set();
};
let siteLinks = 0;
const checkLinks = (file, text) => {
  for (const [, url] of text.matchAll(/\]\((https:\/\/fastauth\.lassejlv\.dev[^)\s]*)\)/g)) {
    siteLinks++;
    const [p, hash] = url.slice(SITE.length + 1).split("#");
    if (!files.includes(p)) errors.push(`${file}: link to missing ${url}`);
    else if (hash && !anchorsOf(p).has(hash)) errors.push(`${file}: link to missing anchor ${url}`);
  }
};

const llms = read("llms.txt");
const llmsLinks = [...llms.matchAll(/\]\((https:\/\/fastauth\.lassejlv\.dev[^)]*)\)/g)].length;
checkLinks("llms.txt", llms);

const fences = {};
const markdown = files.filter((f) => f.endsWith(".md"));
for (const f of markdown) {
  const text = read(f);
  checkLinks(f, text);
  if (!text.startsWith("# ")) errors.push(`${f}: does not open with an H1`);
  if (/^---\s*$/m.test(text.split("\n").slice(0, 3).join("\n"))) errors.push(`${f}: frontmatter`);
  let fence;
  text.split("\n").forEach((line, i) => {
    const open = line.match(/^\s*(`{3,}|~{3,})\s*([\w+-]*)/);
    if (fence) {
      if (open && open[1].startsWith(fence.marker) && !open[2]) fence = undefined;
      else if (fence.lang === "rust" && /^\s*#(\s|$)/.test(line)) errors.push(`${f}:${i + 1}: rustdoc hidden line ${line}`);
      return;
    }
    if (open) {
      fence = { marker: open[1], lang: open[2] || "(none)" };
      fences[fence.lang] = (fences[fence.lang] ?? 0) + 1;
      return;
    }
    const prose = line.replace(/(`+)[^`]*?\1/g, "");
    const tag = prose.match(/<!--|<\/?[a-zA-Z][\w-]*(\s[^>]*)?\/?>|\b(class|data-pagefind[\w-]*)="/);
    if (tag) errors.push(`${f}:${i + 1}: HTML ${tag[0]}`);
    if (/^\s*(import|export)\s.+from\s/.test(prose)) errors.push(`${f}:${i + 1}: MDX import/export`);
  });
  if (fence) errors.push(`${f}: unclosed code fence`);
}

const full = read("llms-full.txt");
const fullPages = (full.match(/^Source: /gm) ?? []).length;
const navPages = [...llms.matchAll(/^- \[.+\]\(https:\/\/fastauth\.lassejlv\.dev\/(docs\/[\w-]+|changelog)\.md\)/gm)].length;
if (fullPages !== navPages) errors.push(`llms-full.txt: ${fullPages} pages, nav has ${navPages}`);

console.log(`HTML pages: ${pages.length}, markdown twins: ${markdown.length}, llms.txt site links: ${llmsLinks}, llms-full.txt pages: ${fullPages}`);
console.log(`Site links checked in .md and llms.txt: ${siteLinks}, code fences by language: ${JSON.stringify(fences)}`);
for (const e of errors) console.error(e);
console.log(errors.length ? `${errors.length} problems` : "0 problems");
process.exit(errors.length ? 1 : 0);
