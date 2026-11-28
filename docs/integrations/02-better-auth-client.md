# Better Auth client

fastauth's core endpoints and its first-party plugins (two-factor, organization, admin, API
keys, magic links, email OTP, bearer, JWT, passkeys, usernames, anonymous users and multiple
sessions) use Better Auth's paths, JSON shapes and error codes, so Better Auth's own TypeScript client works against a fastauth server with no
TypeScript of your own. This page shows how to point the client at fastauth, which version
is tested, and what doesn't match yet.

## Tested version

| Package | Version |
|---|---|
| `better-auth` (`better-auth/client`, `better-auth/client/plugins`) | 1.7.28 |
| `@better-auth/api-key` (`apiKeyClient`) | 1.7.28 |
| `@better-auth/passkey` (`passkeyClient`) | 1.7.28 |
| `@better-auth/core` | 1.7.28 |
| `@better-fetch/fetch` | 1.3.3 |

The versions are pinned in `tests/compat/better-auth/package.json` and `bun.lock`.

## Pointing the client at fastauth

```ts
import { createAuthClient } from "better-auth/client"; // or better-auth/react, /vue, /svelte
import { adminClient, organizationClient, twoFactorClient } from "better-auth/client/plugins";
import { apiKeyClient } from "@better-auth/api-key/client";

export const authClient = createAuthClient({
  baseURL: "http://localhost:3000", // fastauth's base_url; the client adds /api/auth
  plugins: [
    twoFactorClient({ onTwoFactorRedirect: () => (location.href = "/2fa") }),
    organizationClient(),
    adminClient(),
    apiKeyClient(),
  ],
});
```

Add only the client plugins whose fastauth plugins you registered. If you moved the routes with `.base_path("/auth")`, pass `basePath: "/auth"` too. Extra user
fields marked `input` (such as `plan` in the example) are accepted by `signUp.email` and
`updateUser` and come back on `user`. Better Auth's client doesn't know their types, so add
them with `inferAdditionalFields` or a cast.

### In a browser

The browser stores the cookies and sends them back, so the client needs nothing else.
The server does:

- **Same origin** (the app and `/api/auth` behind one host, or a dev proxy) works as is.
- **A different origin** (`app.acme.dk` calling `api.acme.dk`) needs a CORS layer on your router
  that allows that origin with credentials (for example `tower_http::cors::CorsLayer` with
  `allow_credentials(true)`), and the origin in `.trusted_origins([...])`. Cross-site, not
  just cross-origin, also needs `SameSite=None` and https.
- **Cookie names don't matter to the client.** The session cookie is `HttpOnly`, so the
  client never reads it. fastauth names it `fastauth.session_token`; Better Auth uses
  `better-auth.session_token`. Only server-side helpers that look for a cookie by name care,
  such as `getSessionCookie` from `better-auth/cookies` in Next.js middleware. For those, set
  `CookieConfig::default().prefix("better-auth")`. Both sign the value, but with different
  schemes and keys, so only presence checks work, not Better Auth's own cookie verification.

### In Node, Bun or Deno

Server-side fetch has no cookie store and sends no `Origin`. fastauth rejects a
cookie-carrying `POST` without one (403 `MISSING_OR_NULL_ORIGIN`, as Better Auth does), so pass
a `customFetchImpl` that does both:

```ts
const jar = new Map<string, string>();
const authClient = createAuthClient({
  baseURL: "http://localhost:3000",
  plugins: [twoFactorClient()],
  fetchOptions: {
    customFetchImpl: async (input, init) => {
      const request = new Request(input, init);
      request.headers.set("origin", "http://localhost:3000");
      if (jar.size) request.headers.set("cookie", [...jar].map(([k, v]) => k + "=" + v).join("; "));
      const response = await fetch(request);
      for (const cookie of response.headers.getSetCookie()) {
        const [pair, ...attrs] = cookie.split(";").map((s) => s.trim());
        const [name, value] = [pair.slice(0, pair.indexOf("=")), pair.slice(pair.indexOf("=") + 1)];
        if (!value || attrs.some((a) => a.toLowerCase() === "max-age=0")) jar.delete(name);
        else jar.set(name, value);
      }
      return response;
    },
  },
});
```

`tests/compat/better-auth/compat.ts` uses this jar, one per simulated device.

## The compatibility tests

Eleven scripts in `tests/compat/better-auth/` each build a server, start it with a fresh database,
run a TypeScript file with Better Auth's client, and stop the server. They need cargo and
bun (`run-passkey.sh` also needs Chrome or Chromium), listen on `PORT` (3000 unless set), and
exit non-zero when any check fails:

| Script | Server | Client file | Checks |
|---|---|---|---|
| `run.sh` | `crates/fastauth/examples/axum_sqlite.rs` (features `sqlite,two-factor,organization,admin,api-key`) | `compat.ts`: core, two-factor, API keys | 92 |
| `run-organization.sh` | the organization plugin's `compat_server` example, in memory | `organization.ts` | 30 |
| `run-admin.sh` | `crates/plugins/admin/examples/admin_server.rs`, in memory | `admin.ts` | 40 |
| `run-magic-link.sh` | the magic link plugin's `magic_link_server` example, in memory | `magic-link.ts` | 28 |
| `run-email-otp.sh` | the email OTP plugin's `email_otp_server` example, in memory | `email-otp.ts` | 45 |
| `run-bearer.sh` | the bearer plugin's `compat_server` example, in memory | `bearer.ts` | 25 |
| `run-jwt.sh` | the JWT plugin's `compat_server` example, in memory | `jwt.ts` | 26 |
| `run-passkey.sh` | the passkey plugin's `compat_server` example, in memory, driven in headless Chrome | `passkey.ts` | 67 |
| `run-username.sh` | the username plugin's `username_server` example, in memory | `username.ts` | 47 |
| `run-anonymous.sh` | the anonymous plugin's `anonymous_server` example, in memory | `anonymous.ts` | 31 |
| `run-multi-session.sh` | the multi-session plugin's `multi_session_server` example, in memory | `multi-session.ts` | 40 |

```bash
tests/compat/better-auth/run.sh
PORT=3107 tests/compat/better-auth/run-organization.sh
```

All eleven passed on 2026-11-26.

`compat.ts` checks, through the client: `signUp.email` (with an app field), `getSession`, `signOut`,
`signIn.email`, `listSessions`, `revokeSession` by token and by id, `updateUser`,
`changePassword`, `requestPasswordReset` then `resetPassword`, `twoFactor.enable` then
`verifyTotp`, a sign-in that answers `twoFactorRedirect` (and fires `onTwoFactorRedirect`), and
`verifyTotp` finishing it, and the API key flow: `apiKey.create` (and 400
`SERVER_ONLY_PROPERTY` for a server-only field), `list`, `get`, `update`, `getSession` with
`x-api-key`, `delete`, then `KEY_NOT_FOUND`. It also checks `error.code` and `error.status` for a wrong password
(401 `INVALID_EMAIL_OR_PASSWORD`), a duplicate sign-up (422
`USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL`), a wrong current password (400 `INVALID_PASSWORD`), a
used reset token (400 `INVALID_TOKEN`) and a wrong TOTP code (401 `INVALID_CODE`).

The example sends email through `LogMailer`, which logs it. `run.sh` writes the server log to a
file and passes it as `FASTAUTH_LOG`; the script reads the reset token from it. Without
`FASTAUTH_LOG` (when you start the server yourself), the script still calls
`requestPasswordReset` and skips `resetPassword`. The TOTP code is computed in the script from
the `totpURI`.

`organization.ts` covers organizations, members, invitations and the active organization
through `organizationClient`; `admin.ts` covers user management, roles, bans and
impersonation through `adminClient`. The plugin pages describe what the other scripts check
and list their gaps:
[Organization](../plugins/access/01-organization.md#better-auths-client),
[Admin](../plugins/access/02-admin.md#better-auths-client), [API keys](../plugins/tokens/03-api-keys.md#better-auths-client),
[Magic links](../plugins/sign-in/01-magic-link.md#better-auths-client),
[Email OTP](../plugins/sign-in/02-email-otp.md#better-auths-client),
[Bearer tokens](../plugins/tokens/01-bearer.md#better-auths-client), [JWT](../plugins/tokens/02-jwt.md#better-auths-client),
[Passkeys](../plugins/sign-in/03-passkey.md#better-auths-client), [Usernames](../plugins/sign-in/04-username.md#better-auths-client),
[Anonymous users](../plugins/sign-in/05-anonymous.md#better-auths-client) and
[Multiple sessions](../plugins/access/03-multi-session.md#better-auths-client).

There's no CI job; run the scripts before changing an endpoint's path, input or output.

## Known gaps

- **`listSessions` returns no `token`.** fastauth stores only a hash of each session token
  ([Security](../concepts/03-security.md)), so it can't list them. Better Auth's usual pattern,
  `revokeSession({ token: session.token })` on a listed session, doesn't work. Revoke by id
  instead, which fastauth accepts on the same endpoint
  (`revokeSession({ id: session.id } as any)`; Better Auth's types only know `token`), or by
  the token a client already holds from sign-in.
- **Rate limits are on in development.** Better Auth only enables its limiter in production;
  fastauth always does, with 3 requests per 10 s on `/sign-in/*`, `/sign-up/*` and the
  password-reset and verification-email routes. The client gets 429 `TOO_MANY_REQUESTS`
  (without a `Retry-After` header). The test script waits and retries.
- **`changePassword({ revokeOtherSessions: true })` keeps the current session.** Better Auth
  replaces it with a new one and returns the new token; fastauth returns the current token.
  The client keeps working either way.
- **The session cookie isn't Better Auth's.** Its name and signature differ (see *In a
  browser*), so Better Auth server code can't read a fastauth session.
- **`getSession({ query: { disableCookieCache: true } })`** is accepted but ignored; fastauth
  always reads the session from the database unless `cookie_cache` is on.
- **Not tested here:** social sign-in (needs a provider), email verification links,
  `twoFactor.sendOtp`/`verifyOtp` and backup codes, and Better Auth plugins fastauth doesn't
  have ([planned](../get-started/01-overview.md#planned)).
