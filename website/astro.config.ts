import { unified } from "@astrojs/markdown-remark";
import { defineConfig } from "astro/config";
import { rehypeTables, remarkDocs } from "./src/lib/remark-docs";

export default defineConfig({
  site: "https://fastauth-docs.pages.dev",
  trailingSlash: "always",
  build: { format: "directory" },
  redirects: { "/docs": "/docs/overview/" },
  markdown: {
    syntaxHighlight: false,
    processor: unified({ remarkPlugins: [remarkDocs], rehypePlugins: [rehypeTables] }),
  },
  vite: { server: { fs: { allow: [".."] } } },
});
