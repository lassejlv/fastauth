import type { APIRoute } from "astro";
import { getCollection } from "astro:content";
import { agentMarkdown, markdownResponse } from "../../lib/markdown";
import { getNav } from "../../lib/nav";

export async function getStaticPaths() {
  const entries = await getCollection("docs");
  const { ordered } = await getNav();
  return ordered.map((page) => ({ params: { slug: page.slug }, props: { page, entry: entries.find((e) => e.id === page.id)! } }));
}

export const GET: APIRoute = ({ props }) => markdownResponse(agentMarkdown(props.page.title, props.entry.body ?? "", props.entry.filePath));
