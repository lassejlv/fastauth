# docs-check

Compiles every ```rust` block in `docs/` against the workspace crates, so the docs can't drift from the code.

## What it checks

`tests/check-docs.sh` fails when any of these hold:

- **No template.** A Rust block has no entry in `templates.py`, or its first line changed so the entry no longer matches. It prints `docs/<page>.md:<line> has no template; add one in tests/docs-check/templates.py ...`, plus a "matches no block" line for the stale entry when a block was edited or removed.
- **Compile error.** The generated scratch crate (`target/docs-check/`, one module per block) fails `cargo check --tests`. Each compiler span in the crate is followed by `= docs: docs/<page>.md:<line>`, or by "in template scaffolding" when the error is in code the template added. Warnings are allowed.
- **Dropped line.** A non-empty line of a block doesn't appear verbatim (ignoring indentation) in the generated module that includes the block, so a template can't quietly skip code.
- **Stale excerpt.** Blocks marked `excerpt(...)` are deliberately truncated copies of `fastauth-core` (all of `reference/02-internals.md` and the `pub trait Queries` block in `concepts/02-database.md`). They aren't compiled; every line must appear in `crates/core/src` (whitespace-normalized).

## Running it

```sh
tests/check-docs.sh                        # check docs/
DOCS_DIR=/tmp/docs-copy tests/check-docs.sh  # check another copy of the docs tree
```

It needs Python 3 (stdlib only) and cargo. Builds go to `CARGO_TARGET_DIR`, by default the repository's `target/`, and `CARGO_INCREMENTAL`, `CARGO_PROFILE_DEV_DEBUG` and `CARGO_PROFILE_TEST_DEBUG` default to 0. The first run compiles the dependencies with every `fastauth` feature (a few minutes); later runs take seconds.

The steps can also run on their own: `docs_check.py generate`, `cargo check --manifest-path target/docs-check/Cargo.toml --tests`, `docs_check.py verify`.

## Adding or changing a template

Templates live in `templates.py`, one `page(...)` per docs page, listing its blocks in page order by their first line. Blocks are matched per page, so adding a block to one page never affects another.

```python
page("plugins/tokens/01-bearer.md", "use fastauth::plugins::bearer::Bearer;\n" + app_auth("Bearer"), [
    block("use fastauth::plugins::bearer::Bearer;", ctx=""),           # compiled as is, no page ctx
    block("async fn me(session: Session<AppAuth>) -> String {"),       # compiled as is
    block(".plugin(Bearer::new().require_signature(true))", chain()),  # wrapped in FastAuth::builder()...;
])
```

1. Run the check. The new block is reported as `docs/<page>.md:<line> has no template` with its first line.
2. Add `block("<first line>", <template>)` at its position in the page's list. Use `excerpt("<first line>")` instead for a truncated excerpt of core code.
3. If the block compiles on its own, the default template `"@"` is enough. Otherwise wrap it: `stmts(args)` for statements (inside an `async fn` returning `anyhow::Result<()>`), `autherr(args)` for the same returning `Result<(), AuthError>`, `chain(prefix)` for builder method calls, `expr(binding, args)` for one expression, or a literal template string.
4. Re-run until it passes.

In a template string, a line that is only an include inserts docs lines verbatim; every other line is scaffolding:

| Line | Inserts |
| --- | --- |
| `@` | this block |
| `@:a-b` | lines a to b of this block (1-based) |
| `@N` | block N of the same page (1-based position in the page's list) |
| `@N:a-b` | lines a to b of block N |

Each block becomes its own module: the page's `base` (axum imports by default, `ACTIX` for the actix page) and `ctx` (the page's `AppAuth` and imports earlier blocks on the page provide) at the top, then the template inside `pub mod it { use super::*; ... }`, so imports in the block itself take precedence. Pass `ctx=` to override the page ctx for one block. A page passed `module=` compiles as a single module from that template (`reference/01-plugin-authoring.md` builds one plugin across all its blocks).

When a docs edit changes a block's first line, update the `block(...)` entry to the new line. If you insert or remove a block, check the `@N` references on that page, since N is a position.
