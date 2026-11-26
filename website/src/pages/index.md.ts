import type { APIRoute } from "astro";
import { landingMarkdown, markdownResponse } from "../lib/markdown";
import { getNav } from "../lib/nav";

export const GET: APIRoute = async () => markdownResponse(landingMarkdown(await getNav()));
