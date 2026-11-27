# Bearer tokens

The `Bearer` plugin lets clients that can't keep cookies (mobile apps, CLIs, desktop apps,
other servers) use a session through `Authorization: Bearer <token>`. It matches Better
Auth's `bearer` plugin: every route that reads the session accepts the header, and every
response that sets the session cookie also returns the token in a `set-auth-token` header.

## Setup

Turn on the facade's `bearer` feature:

```toml
[dependencies]
fastauth = { version = "0.8", features = ["bearer"] }
```

or `cargo add fastauth --features bearer`. The plugin lives at `fastauth::plugins::bearer`
(crate `fastauth-plugin-bearer`).

Register it on the builder and list it in your `Auth` alias:

```rust
use fastauth::plugins::bearer::Bearer;
use fastauth::prelude::*;

pub type AppAuth = Auth<Sqlx<Postgres>, (), plugins![Bearer]>;

pub fn build(pool: PgPool) -> Result<AppAuth, BuildError> {
    FastAuth::builder()
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("https://acme.dk")
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default())
        .plugin(Bearer::new())
        .build()
}
```

The plugin adds no tables, endpoints or error codes, and depends on no other plugin.

## How it works

**Getting a token.** Sign-up, sign-in, and any other response that sets the session cookie
(a two-factor verification, a social sign-in callback, a refreshed session) carries the
cookie's value in `set-auth-token`:

```
HTTP/1.1 200 OK
set-cookie: fastauth.session_token=Vb3...Xw.k9...Qs; Path=/; Max-Age=604800; HttpOnly; SameSite=Lax
set-auth-token: Vb3...Xw.k9...Qs
access-control-expose-headers: set-auth-token
```

The value is the signed form of the session token, `token.signature`. `set-auth-token` is
added to `Access-Control-Expose-Headers` (keeping any names already there), so browser
scripts on another origin can read it once your CORS layer allows that origin. A response
that clears the cookie, such as `/sign-out`, has no `set-auth-token`.

**Using a token.** Send it back as `Authorization: Bearer <token>`. The scheme is
case-insensitive. A request with a valid token gets the same session a cookie would give:

- every auth route that reads the session (`/get-session`, `/list-sessions`,
  `/update-user`, `/sign-out`, plugin routes);
- the axum `Session<AppAuth>`, `Option<Session<AppAuth>>` and `FreshSession<AppAuth>`
  extractors, the session layer, and plugin extractors built on them
  ([Sessions](../../concepts/01-sessions.md));
- `auth.get_session(&headers)` and server API calls made with `.headers(&headers)`.

```rust
async fn me(session: Session<AppAuth>) -> String {
    session.user.email.clone()
}
// curl -H "Authorization: Bearer $TOKEN" https://acme.dk/me
```

The plugin accepts two forms:

| Form | Example | Accepted |
|---|---|---|
| Signed, what `set-auth-token` carries | `Vb3...Xw.k9...Qs` | When the signature matches one of the app's secrets. A percent-encoded value is decoded first |
| Raw, the `token` field of the sign-in and sign-up JSON | `Vb3...Xw` | Unless `require_signature(true)` is set |

A token with a bad signature, an unknown or expired token, or another scheme
(`Basic ...`) is ignored: the request is treated as signed out, so routes that need a
session answer `401 UNAUTHORIZED`.

**Sessions refresh.** A bearer session is extended like a cookie session, at most once per
`update_age` ([Sessions](../../concepts/01-sessions.md)). The refresh sets the session cookie again, so that
response carries `set-auth-token` too. The token itself doesn't change; clients can store
the new value or keep the old one.

**Signing out** with `POST /sign-out` and the bearer header deletes the session, so the token
stops working everywhere.

## Configuration

| Option | Default | What it does |
|---|---|---|
| `require_signature(b)` | off | Accept only the signed form, not the raw token. Better Auth's `requireSignature` |

```rust
.plugin(Bearer::new().require_signature(true))
```

With signatures required, a leaked raw token from a log of sign-in responses isn't enough;
the caller needs the value from `set-auth-token`.

## Better Auth's client

Better Auth has no bearer client plugin. Its documented pattern works unchanged: read
`set-auth-token` in `onSuccess`, store it, and send it with `fetchOptions.auth`:

```ts
import { createAuthClient } from "better-auth/client";

export const authClient = createAuthClient({
  baseURL: "https://acme.dk",
  fetchOptions: {
    onSuccess(ctx) {
      const token = ctx.response.headers.get("set-auth-token");
      if (token) localStorage.setItem("bearer_token", token);
    },
    auth: {
      type: "Bearer",
      token: () => localStorage.getItem("bearer_token") ?? "",
    },
  },
});
```

`compat/better-auth/run-bearer.sh` runs Better Auth's 1.7.28 client against the plugin's
`compat_server` example and checks: `set-auth-token` and `Access-Control-Expose-Headers` on
sign-up and sign-in, `getSession` with the signed and the raw token, a bad signature and no
token (signed out), `listSessions`, `updateUser`, and `signOut` with a bearer token (the
token stops working, the other session doesn't). It takes `PORT` (default 3000):

```bash
PORT=3001 compat/better-auth/run-bearer.sh
```

## Security

- **Store tokens like passwords.** A bearer token is a session: anyone holding it is signed
  in until it expires or the session is revoked. In browsers, an `HttpOnly` cookie can't be
  read by scripts and a token in `localStorage` can, so prefer cookies for same-site web
  apps and use bearer tokens where cookies don't work.
- **Origin checks.** fastauth checks `Origin` (or `Referer`) on every `POST` that sends one,
  with or without cookies. Native clients and servers usually send neither and pass. A
  browser on another origin sends `Origin`, so add that origin to `trusted_origins`.
- **Secrets rotate.** Signed tokens verify against every configured secret, so
  `.secrets([new, old])` keeps old tokens working while you rotate.

`set-auth-token` and its `Access-Control-Expose-Headers` entry let page scripts read the
signed session token on every response that sets the session cookie, browser sign-ins
included. The session cookie stays `HttpOnly`, but an XSS on your origin, or on an origin
your CORS config allows with credentials, can read the token from that header and use it as
a bearer token. Better Auth's plugin behaves the same; its client reads `set-auth-token` from
the sign-in response, so the header can't be limited to requests that already carry a bearer
token without breaking that flow. Register `Bearer` only in apps whose clients need it, and
serve browser-only apps from an `Auth` without it.

## With other plugins

- **JWT.** Bearer and [JWT](02-jwt.md) are often used together: a native client signs in,
  keeps the bearer token, and calls `GET /token` with it to get a JWT for other services.
  `/get-session` with a bearer token answers with `set-auth-jwt` as well.
- **API keys.** If `ApiKeys` also reads `Authorization: Bearer` (through a `key_getter`),
  register `ApiKeys` first and have its getter return only values with your key prefix.
  Resolvers run in registration order and the bearer plugin claims every bearer value, so a
  key that reaches it is treated as an unknown session token.

## Known gaps

- When a request has both a session cookie and a bearer token, fastauth uses the cookie.
  Better Auth uses the bearer token.
- `set-auth-token` is only added to HTTP responses. Server API calls
  (`auth.api().sign_in_email(..)`) return the raw token in `data.token` and the cookie in
  `set_cookies`, so sign that token yourself if a client needs the signed form, or return
  the raw token (accepted unless `require_signature` is on).
- The signature is fastauth's (HMAC-SHA256 under a key derived from the app secret), not
  Better Auth's, so tokens from a Better Auth server don't verify in fastauth.
