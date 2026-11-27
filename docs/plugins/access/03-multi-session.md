# Multiple sessions

The `MultiSession` plugin keeps several accounts signed in in one browser and lets the user
switch between them, like account switchers in mail apps. It matches Better Auth's
`multiSession` plugin, cookie for cookie: every session a browser signs in gets a signed
device-session cookie, the usual session cookie says which account is active, and
`/multi-session/list-device-sessions`, `/multi-session/set-active` and
`/multi-session/revoke` work on them. Better Auth's `multiSessionClient` works unchanged.

## Setup

Turn on the facade's `multi-session` feature:

```toml
[dependencies]
fastauth = { version = "0.8", features = ["multi-session"] }
```

The plugin lives at `fastauth::plugins::multi_session` (crate
`fastauth-plugin-multi-session`):

```rust
use fastauth::plugins::multi_session::MultiSession;
use fastauth::prelude::*;

pub type AppAuth = Auth<Sqlx<Postgres>, (), plugins![MultiSession]>;

pub fn build(pool: PgPool) -> Result<AppAuth, BuildError> {
    FastAuth::builder()
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("https://acme.dk")
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default())
        .plugin(MultiSession::new().maximum_sessions(5))
        .build()
}
```

It adds no tables or columns.

## How it works

**Remembering accounts.** Every new session in a browser (any sign-in or sign-up method) also
sets a device-session cookie:

```
set-cookie: fastauth.session_token=Vb3...Xw.k9...Qs; Path=/; Max-Age=604800; HttpOnly; SameSite=Lax
set-cookie: fastauth.session_token_multi-vb3...xw=Vb3...Xw.k9...Qs; Path=/; Max-Age=604800; HttpOnly; SameSite=Lax
```

Its name is the session cookie's name, `_multi-` and the session token in lowercase; its value
is the token signed like the session cookie, and it lasts the session's lifetime. Better Auth
names and signs it the same way (with its own prefix and secret). After a `rememberMe: false`
sign-in the device cookie has no `Max-Age`, like the session cookie, so closing the browser
forgets the account.

When the new session's user already has a remembered session in this browser, that older
session is deleted and its cookie expired, so each account appears once. When the browser
already remembers `maximum_sessions` accounts, the new session still signs in and becomes
active but isn't remembered next to the others.

**Listing.** `GET /multi-session/list-device-sessions` answers one `{ session, user }` per
remembered account whose session is still valid, the same shape as `/get-session`. Each
`session` carries its `token`, which the other two routes take. Cookies with a bad
signature are ignored. A browser without device-session cookies gets `[]`.

**Switching.** `POST /multi-session/set-active` with `{ "sessionToken": "..." }` makes that
remembered session the active one: it sets the session cookie to it (for the browser session
only when the browser signed in with `rememberMe: false`) and answers `{ session, user }`.

**Signing one account out.** `POST /multi-session/revoke` with `{ "sessionToken": "..." }`
needs a signed-in browser. It deletes that session and expires its device cookie. Revoking
the active account makes the next remembered, still-valid session active, or signs the
browser out when none is left. It answers `{ "status": true }`.

**Signing everyone out.** `/sign-out` also expires every device-session cookie and deletes
their sessions.

**Tokens the browser doesn't hold.** `set-active` and `revoke` only act on a token whose
signed device cookie the request carries, so knowing another browser's token isn't enough.
They answer 401 `INVALID_SESSION_TOKEN` ("Invalid session token") otherwise; `set-active`
also answers it, and expires the cookie, when the remembered session has expired or was
revoked elsewhere.

## Configuration

| Option | Default | What it does |
|---|---|---|
| `maximum_sessions(n)` | 5 | How many accounts one browser remembers |

## Server API

`MultiSessionExt` adds `auth.multi_session()`. `headers` are the browser's request headers,
which carry the device cookies; the responses' `set_cookies` carry the cookie changes:

```rust
use fastauth::plugins::multi_session::MultiSessionExt;

let sessions = auth.multi_session().list_device_sessions(&headers).await?.data;
let switched = auth.multi_session().set_active(&headers, token).await?;
auth.multi_session().revoke(&headers, token).await?;
```

## Better Auth's client

```ts
import { createAuthClient } from "better-auth/client";
import { multiSessionClient } from "better-auth/client/plugins";

const authClient = createAuthClient({ baseURL: "https://acme.dk", plugins: [multiSessionClient()] });

const { data: sessions } = await authClient.multiSession.listDeviceSessions();
await authClient.multiSession.setActive({ sessionToken: sessions[0].session.token });
await authClient.multiSession.revoke({ sessionToken: sessions[1].session.token });
```

`compat/better-auth/run-multi-session.sh` runs Better Auth's 1.7.28 `multiSessionClient`
against the plugin's `multi_session_server` example and checks 40 things: three accounts in
one browser and their device cookies (name, `HttpOnly`, `Max-Age`), `listDeviceSessions`,
`setActive` (and 401 for an unknown token or another browser's token), revoking a background
account and the active one, signing in again as a remembered account, the five-account
maximum, `signOut`, and that every error's code and message match the client's
`MULTI_SESSION_ERROR_CODES`. It takes `PORT` (default 3000):

```bash
PORT=3001 compat/better-auth/run-multi-session.sh
```

## How it differs from Better Auth

- **Order.** `list-device-sessions` lists accounts, and `revoke` picks the next active one,
  in the order the browser sends its cookies. Better Auth uses the order its database query
  returns.
- **When a session is remembered.** fastauth remembers sessions in a core hook that runs when
  a session is created. Better Auth's hook runs on every response that sets the session
  cookie with a new session; the extra cases (a refresh, `set-active`) find the device cookie
  already there and do nothing, so the cookies come out the same.
- **The maximum counts every device cookie name**, including ones with a bad signature, as
  Better Auth does.

### Not built

Nothing from Better Auth's plugin is missing. Server API calls return cookie changes in
`set_cookies`; apply them to your response yourself.
