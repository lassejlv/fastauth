import fs from "node:fs";
import path from "node:path";

export const REPO_ROOT = path.resolve(process.cwd(), "..");
export const GITHUB = "https://github.com/lassejlv/fastauth";
export const CRATES_IO = "https://crates.io/crates/fastauth";
export const DOCS_RS = "https://docs.rs/fastauth";

const DOCS_DIR = path.join(REPO_ROOT, "docs");

const GROUPS: { dir: string; label: string; sections?: Record<string, string> }[] = [
  { dir: "get-started", label: "Get started" },
  { dir: "concepts", label: "Core concepts" },
  { dir: "integrations", label: "Integrations" },
  { dir: "plugins", label: "Plugins", sections: { "sign-in": "Sign-in methods", tokens: "Tokens", access: "Organizations and access" } },
  { dir: "reference", label: "Reference" },
];

export type DocPage = {
  id: string;
  file: string;
  slug: string;
  href: string;
  title: string;
  description: string;
  group: string;
  section?: string;
};

export type NavLink = { href: string; title: string; section?: string };
export type NavGroup = { label: string; pages: NavLink[] };

export const slugOf = (file: string) => {
  const name = path.basename(file, ".md");
  return (name === "README" ? path.basename(path.dirname(file)) : name).replace(/^\d+-/, "");
};
export const docHref = (slug: string) => `/docs/${slug}/`;

function readIndexTable(): Map<string, { title: string; description: string; order: number }> {
  const index = new Map<string, { title: string; description: string; order: number }>();
  const text = fs.readFileSync(path.join(DOCS_DIR, "README.md"), "utf8");
  const row = /^\|\s*\[([^\]]+)\]\((?:\.\/)?([\w/-]+\.md)\)\s*\|\s*(.*?)\s*\|\s*$/gm;
  for (const m of text.matchAll(row)) {
    if (!index.has(m[2])) index.set(m[2], { title: m[1], description: stripMarkdown(m[3]), order: index.size });
  }
  return index;
}

export const stripMarkdown = (s: string) =>
  s
    .replace(/\[([^\]]+)\]\([^)]*\)/g, "$1")
    .replace(/[`*]/g, "")
    .trim();

function firstHeading(body: string) {
  return body.match(/^#\s+(.+)$/m)?.[1].trim();
}

function firstParagraph(body: string) {
  const blocks = body.replace(/^#\s+.+$/m, "").split(/\n\s*\n/);
  const para = blocks.map((b) => b.trim()).find((b) => b && !/^[#`|>\-*<!]/.test(b));
  return para ? stripMarkdown(para.replace(/\s+/g, " ")).split(/(?<=\.)\s/)[0] : "";
}

export function buildNav(entries: { id: string; body?: string; filePath?: string }[]) {
  const index = readIndexTable();
  const pages = entries.map((entry) => {
    const file = path.relative(DOCS_DIR, path.resolve(entry.filePath ?? `${entry.id}.md`)).split(path.sep).join("/");
    const [dir, sub] = file.split("/");
    const groupIndex = Math.max(GROUPS.findIndex((g) => g.dir === dir), 0);
    const group = GROUPS[groupIndex];
    const slug = slugOf(file);
    const known = index.get(file);
    const body = entry.body ?? "";
    return {
      id: entry.id,
      file,
      slug,
      href: docHref(slug),
      title: known?.title ?? firstHeading(body) ?? slug,
      description: known?.description || firstParagraph(body),
      group: group.label,
      section: file.split("/").length > 2 ? group.sections?.[sub] : undefined,
      order: groupIndex * 1000 + (known ? known.order : 500 + (Number.parseInt(path.basename(file), 10) || 0)),
    } satisfies DocPage & { order: number };
  });
  pages.sort((a, b) => a.order - b.order || a.file.localeCompare(b.file));
  const groups: NavGroup[] = GROUPS.map(({ label }) => ({
    label,
    pages: pages.filter((p) => p.group === label).map(({ href, title, section }) => ({ href, title, section })),
  }));
  groups[groups.length - 1].pages.push({ href: "/changelog/", title: "Changelog" });
  return { groups: groups.filter((g) => g.pages.length), ordered: pages };
}

export function version() {
  const manifest = fs.readFileSync(path.join(REPO_ROOT, "crates/fastauth/Cargo.toml"), "utf8");
  const own = manifest.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
  if (own) return own;
  const workspace = fs.readFileSync(path.join(REPO_ROOT, "Cargo.toml"), "utf8");
  return workspace.match(/\[workspace\.package\][^[]*?version\s*=\s*"([^"]+)"/)?.[1] ?? "";
}
