# Better Auth's client

fastauth uses Better Auth's paths, JSON shapes (camelCase, `{ user, session }`) and error
format (`{ code, message }`), so a frontend can use `better-auth/client` (and its React, Vue
or Svelte bindings) against a fastauth server. That covers core sign-up, sign-in, sessions,
password reset and email verification, social sign-in (`/sign-in/social`), and the plugin
clients `twoFactorClient`, `organizationClient`, `adminClient`, `magicLinkClient`,
`emailOTPClient`, `jwtClient`, `usernameClient`, `anonymousClient` and `multiSessionClient`
(from `better-auth/client/plugins`), `apiKeyClient` (from
`@better-auth/api-key/client`) and `passkeyClient` (from `@better-auth/passkey/client`). The
bearer plugin needs no client plugin, only `fetchOptions.auth`. Add only
the client plugins whose fastauth plugins the server registers. Better Auth plugins fastauth
doesn't have yet have no server side.

Point the client at the Rust server. Better Auth's default base path is `/api/auth`, the
same as fastauth's; if you change `.base_path(..)` on the builder, set the client's to match.

```ts
import { createAuthClient } from "better-auth/client";

export const authClient = createAuthClient({ baseURL: "http://localhost:3000" });
```

When the frontend runs on another origin than `base_url`:

- add its origin to `.trusted_origins([..])`, or every cookie-carrying POST answers
  `403 INVALID_ORIGIN`;
- add a CORS layer that allows that origin with credentials (fastauth sends no CORS headers);
- keep `SameSite`/`Secure` cookie settings compatible with a cross-site request
  (`.cookies(CookieConfig::default().same_site(..))`).

The two-factor challenge arrives as `{ "twoFactorRedirect": true }` from `/sign-in/email`,
which is what `twoFactorClient`'s `onTwoFactorRedirect` handles.

Better Auth's real client (1.7.28) is tested against fastauth with `compat/better-auth/run.sh`
and one `run-<plugin>.sh` script per plugin.
Read the repo's [docs/integrations/02-better-auth-client.md](../../../docs/integrations/02-better-auth-client.md) for setup in a browser and in Node,
the pinned version, and the known gaps (`listSessions` has no `token`, so revoke by `id`).
