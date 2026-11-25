import fs from "node:fs";
import path from "node:path";

export const REPO_ROOT = path.resolve(process.cwd(), "..");
export const GITHUB = "https://github.com/lassejlv/fastauth";
export const CRATES_IO = "https://crates.io/crates/fastauth";
export const DOCS_RS = "https://docs.rs/fastauth";

const GROUP_ORDER = ["Get started", "Guides", "Under the hood"] as const;
const GROUP_OF: Record<string, (typeof GROUP_ORDER)[number]> = {
  overview: "Get started",
  quickstart: "Get started",
  configuration: "Get started",
  internals: "Under the hood",
  security: "Under the hood",
  "open-questions": "Under the hood",
};

export type DocPage = {
  id: string;
  file: string;
  slug: string;
  href: string;
  title: string;
  description: string;
  group: string;
};

export type NavGroup = { label: string; pages: DocPage[] };

export const slugOf = (file: string) => path.basename(file, ".md").replace(/^\d+-/, "");
export const docHref = (slug: string) => `/docs/${slug}/`;

function readIndexTable(): Map<string, { title: string; description: string; order: number }> {
  const index = new Map<string, { title: string; description: string; order: number }>();
  for (const source of ["README.md", "docs/01-overview.md"]) {
    const text = fs.readFileSync(path.join(REPO_ROOT, source), "utf8");
    const row = /^\|\s*\[([^\]]+)\]\((?:\.\/)?(?:docs\/)?(\d+-[\w-]+\.md)\)\s*\|\s*(.*?)\s*\|\s*$/gm;
    for (const m of text.matchAll(row)) {
      if (!index.has(m[2])) index.set(m[2], { title: m[1], description: stripMarkdown(m[3]), order: index.size });
    }
    if (index.size) break;
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
  const pages: (DocPage & { order: number })[] = entries.map((entry) => {
    const file = path.basename(entry.filePath ?? `${entry.id}.md`);
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
      group: GROUP_OF[slug] ?? "Guides",
      order: known ? known.order : 1000 + Number.parseInt(file, 10),
    };
  });
  pages.sort((a, b) => a.order - b.order || a.file.localeCompare(b.file));
  const groups: NavGroup[] = GROUP_ORDER.map((label) => ({ label, pages: pages.filter((p) => p.group === label) })).filter((g) => g.pages.length);
  const ordered = groups.flatMap((g) => g.pages);
  return { groups, ordered };
}

export function version() {
  const manifest = fs.readFileSync(path.join(REPO_ROOT, "crates/fastauth/Cargo.toml"), "utf8");
  const own = manifest.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
  if (own) return own;
  const workspace = fs.readFileSync(path.join(REPO_ROOT, "Cargo.toml"), "utf8");
  return workspace.match(/\[workspace\.package\][^[]*?version\s*=\s*"([^"]+)"/)?.[1] ?? "";
}
