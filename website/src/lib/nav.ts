import { getCollection } from "astro:content";
import { buildNav } from "./site";

export async function getNav() {
  const entries = await getCollection("docs");
  return buildNav(entries.map((e) => ({ id: e.id, body: e.body, filePath: e.filePath })));
}
