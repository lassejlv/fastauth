import type { APIRoute } from "astro";
import { getCollection } from "astro:content";
import { agentMarkdown, markdownResponse } from "../lib/markdown";

export const GET: APIRoute = async () => {
  const [entry] = await getCollection("changelog");
  return markdownResponse(agentMarkdown("Changelog", entry.body ?? "", entry.filePath));
};
