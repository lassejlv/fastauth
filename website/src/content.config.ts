import { defineCollection } from "astro:content";
import { glob } from "astro/loaders";

const docs = defineCollection({ loader: glob({ pattern: "[0-9]*.md", base: "../docs" }) });
const changelog = defineCollection({ loader: glob({ pattern: "CHANGELOG.md", base: ".." }) });

export const collections = { docs, changelog };
