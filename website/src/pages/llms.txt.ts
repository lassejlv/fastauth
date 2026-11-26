import type { APIRoute } from "astro";
import { llmsTxt, markdownResponse } from "../lib/markdown";
import { getNav } from "../lib/nav";

export const GET: APIRoute = async () => markdownResponse(llmsTxt(await getNav()), "text/plain");
