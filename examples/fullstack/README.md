# Fullstack example: axum, Postgres and React

A small but complete app on fastauth: an axum server on Postgres and a React client that uses
Better Auth's own client (`better-auth` 1.7.28). It's the reference for wiring fastauth into a
real backend, and it doubles as fastauth's end-to-end test: Playwright drives the React app in
Chrome against the real server and a real Postgres.

What it has: email and password sign-up with email verification, GitHub sign-in, two-factor
(authenticator app and backup codes), passkeys, organizations with invitations and roles, an
admin users page with bans, API keys, and two app routes that sit on a table of the app's own.

```text
examples/fullstack/
  server/                  the Rust server (workspace member, never published)
    src/auth.rs            the whole auth configuration: AppAuth and build()
    src/routes.rs          the app's own routes and their extractors
    src/mailer.rs          the dev mailer: one JSON line per email in outbox.jsonl
    src/config.rs          every environment variable
    src/main.rs            migrations, the first admin, the router, serving
    src/bin/fastauth.rs    the fastauth CLI for this config: schema, status, generate, migrate
    migrations/            fastauth's generated SQL and the app's own project table
  web/                     the React app (Vite, TypeScript, react-router)
    src/auth-client.ts     Better Auth's client with the plugins that match the server
    e2e/                   the Playwright suite
  e2e.sh                   runs the suite against a throwaway Postgres container
```

## Running it

You need Rust 1.94 or newer, Node 20 or newer, and Postgres (Docker is easiest).

```bash
docker run -d --name acme-db -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=acme -p 5432:5432 postgres:17

cd examples/fullstack/server
cp .env.example .env
sed -i "s/^FASTAUTH_SECRET=.*/FASTAUTH_SECRET=$(openssl rand -hex 32)/" .env
cargo run --bin server            # applies migrations/, creates the first admin, listens on :3000

cd ../web                         # in a second terminal
npm install
npm run dev                       # http://localhost:5173
```

Open http://localhost:5173 and create an account. The verification link is in
`server/outbox.jsonl` (and in the server log); open it and you're signed in. Sign in as
`ADMIN_EMAIL` to see the admin page.

In development the app runs on Vite and `/api` is proxied to the server, so the browser sees
one origin: cookies are first-party, no CORS is needed, and passkeys work on `localhost`.
In production, build the app (`npm run build`) and set `WEB_DIST=../web/dist`: the server
then serves it next to the API, from one origin again. If the app and the API live on different
origins, read [Better Auth's client](../../docs/integrations/02-better-auth-client.md#in-a-browser)
for the CORS layer and `trusted_origins`.

### GitHub sign-in

Create an OAuth app on GitHub with the callback URL
`http://localhost:5173/api/auth/callback/github` (`{APP_URL}/api/auth/callback/github`), and
set `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`. Without them the server registers no
provider and the sign-in page hides the button.

### Migrations

The tables come from SQL files in `server/migrations/`, which the server applies with
`sqlx::migrate!` on start:

- `…_fastauth.sql` was written by the fastauth CLI: `cargo run --bin fastauth -- generate`
  diffs the auth config against a database and writes the SQL for what's missing.
- `…_projects.sql` is the app's own table. It references `organization` and `"user"` like any
  other foreign key.

After you change the auth config (add a plugin, a user field), run
`cargo run --bin fastauth -- generate` against a database that has every earlier migration,
review the new file, and commit it. The server refuses to start while the config needs schema
changes that `migrations/` doesn't have, and `cargo run --bin fastauth -- status` exits
non-zero in the same case, so it works as a CI check.

## The end-to-end suite

```bash
examples/fullstack/e2e.sh                        # 16 tests, about a minute
examples/fullstack/e2e.sh -- --grep passkey      # arguments after -- go to playwright test
examples/fullstack/e2e.sh --screenshots shots/   # also saves each main screen, light and dark
```

It starts Postgres in Docker, builds the server and the app, starts the server serving the
built app, checks `fastauth status`, and runs Playwright in Chrome (`CHROME_PATH`, or
Playwright's `chrome` channel). Each test is its own client IP: the server runs with
`TRUSTED_PROXIES=1` and every browser context sends its own `x-forwarded-for`, which is also
how the rate-limit test proves limits are per client.

| Spec | Covers |
|---|---|
| `auth.spec.ts` | sign-up, sign-in refused until the email is verified, resend, verify, sign-out and sign-in; `?next=` after sign-in; a taken email gets the same answer as a new one; wrong password; the sign-in limit per client IP |
| `two-factor.spec.ts` | enrolment with the QR code and backup codes; sign-in challenge with a wrong code, then the right one; a backup code works once; turning it off needs the password |
| `passkey.spec.ts` | registering a passkey with Chrome's virtual authenticator, signing in with it, deleting it |
| `organization.spec.ts` | create, invite, accept from the email link; a member can read projects but gets 403 creating one; a non-member gets 403 on the org's route; an invitation only works for the invited email |
| `api-keys.spec.ts` | create a key, call `/api/me` with only `x-api-key`, a wrong key is 401, a deleted key is 401 |
| `admin.spec.ts` | list and search users, ban (which signs the user out and blocks sign-in), unban; non-admins get 403 |
| `github.spec.ts` | the GitHub button sends the browser to GitHub with this app's callback URL (placeholder credentials; a full round trip needs a real OAuth app) |

## Where each piece is documented

| In this app | Where | fastauth docs |
|---|---|---|
| The secret from `FASTAUTH_SECRET` | `server/src/auth.rs` | [Configuration: secrets](../../docs/get-started/03-configuration.md#secrets) |
| Email and password, verification required, auto sign-in after verifying | `server/src/auth.rs` | [Configuration: email and password](../../docs/get-started/03-configuration.md#email-and-password) |
| The dev mailer (`impl Mailer`) | `server/src/mailer.rs` | [Configuration: email and password](../../docs/get-started/03-configuration.md#email-and-password) |
| GitHub sign-in (`Social`, `Github`) | `server/src/auth.rs`, `web/src/pages/SignIn.tsx` | [Configuration: social providers](../../docs/get-started/03-configuration.md#social-providers) |
| Two-factor | `web/src/pages/Security.tsx`, `TwoFactor.tsx` | [Quickstart: add a plugin](../../docs/get-started/02-quickstart.md#7-add-a-plugin), [Security: two-factor sign-in](../../docs/concepts/03-security.md#two-factor-sign-in) |
| Passkeys | `web/src/pages/Security.tsx`, `SignIn.tsx` | [Passkeys](../../docs/plugins/sign-in/03-passkey.md) |
| Organizations, custom `project` permissions, invitations | `server/src/auth.rs`, `web/src/pages/Organization.tsx` | [Organizations](../../docs/plugins/access/01-organization.md) |
| `OrgMember` and `RequirePermission` on app routes | `server/src/routes.rs` | [Organizations](../../docs/plugins/access/01-organization.md), [Sessions: guards from plugins](../../docs/concepts/01-sessions.md#guards-from-plugins) |
| Admin, `RequireRole`, bans, the first admin | `server/src/main.rs`, `server/src/routes.rs`, `web/src/pages/Admin.tsx` | [Admin](../../docs/plugins/access/02-admin.md) |
| API keys, sessions from `x-api-key` | `server/src/auth.rs`, `web/src/pages/ApiKeys.tsx` | [API keys](../../docs/plugins/tokens/03-api-keys.md) |
| `Session` on app routes, `FromRef` state | `server/src/routes.rs` | [Sessions](../../docs/concepts/01-sessions.md), [HTTP integrations](../../docs/integrations/01-http.md) |
| Client IP behind proxies, rate limits | `server/src/auth.rs` | [Configuration: rate limits](../../docs/get-started/03-configuration.md#rate-limits) |
| Migrations through the CLI | `server/src/bin/fastauth.rs`, `server/migrations/` | [Quickstart: tables](../../docs/get-started/02-quickstart.md#4-tables), [Database: migrations](../../docs/concepts/02-database.md#migrations) |
| An app table joined to `user` | `server/migrations/…_projects.sql`, `server/src/routes.rs` | [Database: the schema](../../docs/concepts/02-database.md#the-schema) |
| Better Auth's client and its plugins | `web/src/auth-client.ts` | [Better Auth's client](../../docs/integrations/02-better-auth-client.md) |
| Origin checks (CSRF) | the browser sends `Origin`; nothing to configure on one origin | [Security: CSRF](../../docs/concepts/03-security.md#csrf) |

## Notes for a real deployment

- Replace `OutboxMailer` with a mailer for your provider; it's the only dev-only piece.
- Set `TRUSTED_PROXIES` to the number of proxies in front of the server that append to
  `x-forwarded-for` (one nginx: 1), or 0 when clients connect directly. A wrong number lets
  clients pick their own IP for rate limiting.
- `APP_URL` must be the https origin people use: it's the cookie scope, the passkey relying
  party and the start of every emailed link.
- The app's own POST route relies on fastauth's `SameSite=Lax` cookie and on JSON bodies
  (which a cross-site form can't send) for CSRF protection. Add an origin check if a route
  accepts form posts.
