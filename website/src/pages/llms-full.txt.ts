import type { APIRoute } from "astro";
import { getCollection } from "astro:content";
import { agentMarkdown, markdownResponse, SITE, markdownHref, SUMMARY } from "../lib/markdown";
import { getNav } from "../lib/nav";

export const GET: APIRoute = async () => {
  const entries = await getCollection("docs");
  const [changelog] = await getCollection("changelog");
  const { groups, ordered } = await getNav();
  const pages = groups.flatMap((g) => g.pages).map((link) => {
    const page = ordered.find((p) => p.href === link.href);
    const entry = page ? entries.find((e) => e.id === page.id) : changelog;
    const doc = agentMarkdown(link.title, entry?.body ?? "", entry?.filePath);
    return doc.replace(/^(# .+\n)/, `$1\nSource: ${SITE}${markdownHref(link.href)}\n`);
  });
  return markdownResponse([`# fastauth\n\n> ${SUMMARY}\n`, ...pages].join("\n\n"), "text/plain");
};
