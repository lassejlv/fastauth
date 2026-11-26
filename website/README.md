# fastauth docs website

The documentation site for fastauth, built with [Astro](https://astro.build) as a static site.
It is live at https://fastauth.lassejlv.dev.

The pages come straight from the repository's Markdown at build time, so there is nothing to
copy or keep in sync:

- Each folder in `docs/` is a sidebar group: `get-started`, `concepts`, `integrations`,
  `plugins` and `reference`. The folders under `docs/plugins/` (`sign-in`, `tokens`, `access`)
  are the sections inside the Plugins group. Labels and order are set in `GROUPS` in
  `src/lib/site.ts`.
- `docs/<group>/NN-name.md` becomes `/docs/<name>/`, with the folder and number prefix dropped
  (`docs/get-started/02-quickstart.md` is `/docs/quickstart/`). A folder's `README.md` takes
  the folder's name (`docs/plugins/README.md` is `/docs/plugins/`).
- The page order, titles and descriptions come from the docs tables in the root `README.md`. A
  new file that isn't in a table still gets a page: it goes at the end of its group, with the
  title taken from its `# heading`.
- `CHANGELOG.md` becomes `/changelog/`, listed last under Reference.
- Links between docs (`../reference/01-plugin-authoring.md#hooks`) become site links, and links
  to other repository files go to GitHub.
- A page that moves gets a redirect from its old URL in `astro.config.ts`.

## Writing docs for the site

The site needs nothing special, but a few Markdown conventions render better:

- A code block whose first line is a file path comment (`// src/auth.rs` or `# Cargo.toml`) shows
  the path in its header instead of the language.
- A code block without a language that starts with `error[E…]:` is rendered as rustc output.
- `> [!WARNING]` (or `[!CAUTION]`) makes a warning callout. Any other blockquote, including
  `> [!NOTE]`, is a note.
- ```mermaid` blocks are drawn as SVG at build time.

## Develop

Requires Node 22 or newer.

```bash
cd website
npm install
npm run dev        # http://localhost:4321
```

`npm run dev` has no search index. To try search, build and preview:

```bash
npm run build      # astro build, then pagefind indexes dist/
npm run preview
```

## How it's built

- **Content**: an Astro content collection reads `../docs` and `../CHANGELOG.md`
  (`src/content.config.ts`). `src/lib/remark-docs.ts` rewrites links, turns blockquotes into
  callouts, renders Mermaid and replaces every code block with highlighted HTML.
- **Code**: Shiki with the `oxide` theme in `src/lib/code.ts`. Token colours are CSS variables
  (`--syntax-*` in `src/styles/global.css`), so light and Ink share one highlight pass. Long lines
  scroll sideways inside the block.
- **Search**: [Pagefind](https://pagefind.app) indexes the built HTML after `astro build`. The
  ⌘K palette in `src/components/SearchDialog.astro` loads `/pagefind/pagefind.js` when it opens.
- **Theme**: follows the system setting until someone uses the toggle, which is remembered in
  `localStorage`. Dark mode is the Ink palette from the design (true black, dither texture in the
  hero and in a band of the top bar that stays clear of the controls).
- **Design source**: the Paper file "fastauth docs" (Light and Ink pages). The dither PNGs in
  `public/dither/` were generated with `dith`; the commands are in the design report.

## Deploy

The site is a Cloudflare Pages project called `fastauth-docs`, deployed by direct upload of
`dist/`. There is no CI deploy.

```bash
cd website
npm run build
npx wrangler pages deploy dist --project-name fastauth-docs --branch main
```

Wrangler needs a Cloudflare login (`npx wrangler login`) or `CLOUDFLARE_API_TOKEN` and
`CLOUDFLARE_ACCOUNT_ID` for an account with Pages access. `--branch main` makes it the production
deployment on https://fastauth-docs.pages.dev; any other branch name gives a preview URL.
