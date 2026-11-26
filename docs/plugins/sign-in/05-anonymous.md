# Anonymous users

The `Anonymous` plugin lets people use your app before they sign up. It matches Better
Auth's `anonymous` plugin: `POST /sign-in/anonymous` creates a user with a placeholder email
and `isAnonymous: true`; when that browser later signs in or up with a real method, your
`on_link_account` hook gets both users so you can move their data across, and the anonymous
user is deleted. Better Auth's `anonymousClient` works unchanged.

## Setup

Turn on the facade's `anonymous` feature:

```toml
[dependencies]
fastauth = { version = "0.5", features = ["anonymous"] }
```

The plugin lives at `fastauth::plugins::anonymous` (crate `fastauth-plugin-anonymous`):

```rust
use fastauth::plugins::anonymous::{Anonymous, LinkAccount};
use fastauth::prelude::*;

pub type AppAuth = Auth<Sqlx<Postgres>, (), plugins![Anonymous]>;

pub fn build(pool: PgPool, carts: Carts) -> Result<AppAuth, BuildError> {
    FastAuth::builder()
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("https://acme.dk")
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default())
        .plugin(Anonymous::new().on_link_account(move |link: LinkAccount| {
            let carts = carts.clone();
            async move {
                carts
                    .move_to(&link.anonymous_user.user.id, &link.new_user.user.id)
                    .await
                    .map_err(AuthError::internal)
            }
        }))
        .build()
}
```

It adds one column to `user`, so run your migrations after registering it:

| Column | JSON | What it holds |
|---|---|---|
| `is_anonymous` | `isAnonymous` | `true` for users made by `/sign-in/anonymous`, `false` otherwise. Clients can't set it |

Read it in Rust with `session.user.plugin::<Anonymous, _>().is_anonymous`, or
`fastauth::plugins::anonymous::is_anonymous(&user_view)`.

## How it works

**Signing in anonymously.** `POST /sign-in/anonymous` (empty body) creates a user named
`Anonymous` with the email `{id}@anonymous.placeholder.invalid`, no account and no password,
and signs them in:

```json
200 { "token": "...", "user": { "id": "...", "email": "01jf...@anonymous.placeholder.invalid", "name": "Anonymous", "isAnonymous": true, ... } }
```

The session works like any other: extractors, `/get-session` and plugin routes see a normal
user with `isAnonymous: true`. Sign-in gates run with method `"anonymous"`. A browser that
already has an anonymous session gets 400
`ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY`; a browser signed in as a real user may
start an anonymous session.

**Linking.** Whenever a request that carries an anonymous session cookie creates a new
session for another user (`/sign-up/email`, `/sign-in/email`, a social callback, a magic
link, an email code, a passkey, a username sign-in, finishing a two-factor challenge), the
plugin:

1. calls `on_link_account` with `LinkAccount { anonymous_user, new_user }`, both full
   `SessionView`s (user, session and every plugin column);
2. deletes the anonymous user with its sessions and accounts, and emits `UserDeleted`.

Deletion is skipped when `disable_delete_anonymous_user(true)` is set, or when the new
session belongs to the same user or to another anonymous user. An error from
`on_link_account` fails that sign-in's response and keeps the anonymous user; the new
session already exists, so the client can retry the link by signing in again. A failure to
delete is logged and doesn't fail the sign-in.

**Deleting.** `POST /delete-anonymous-user` deletes the signed-in anonymous user with their
sessions and accounts, clears the session cookies and answers `{ "success": true }`.

### Errors

| Code | Status | When |
|---|---|---|
| `ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY` | 400 | `/sign-in/anonymous` from an anonymous session |
| `INVALID_EMAIL_FORMAT` | 400 | `generate_random_email` returned something that isn't an email |
| `USER_IS_NOT_ANONYMOUS` | 403 | `/delete-anonymous-user` by a real user |
| `DELETE_ANONYMOUS_USER_DISABLED` | 400 | `/delete-anonymous-user` with `disable_delete_anonymous_user(true)` |
| `UNAUTHORIZED` | 401 | `/delete-anonymous-user` without a session |

The statuses and messages are Better Auth's.

## Configuration

| Option | Default | What it does |
|---|---|---|
| `email_domain_name(d)` | none | Emails become `temp-{id}@{d}` instead of `{id}@anonymous.placeholder.invalid` |
| `generate_name(f)` | `"Anonymous"` | `Fn() -> String`; an empty name falls back to the default |
| `generate_random_email(f)` | none | `Fn() -> String` for the whole email. It must be valid and unused |
| `on_link_account(f)` | none | `Fn(LinkAccount) -> impl Future<Output = Result<(), AuthError>>`, see above |
| `disable_delete_anonymous_user(b)` | off | Keep anonymous users after linking, and turn `/delete-anonymous-user` off |

The `{id}` in placeholder emails comes from the configured id strategy (a ULID by default),
so placeholder emails are unique. `.invalid` is a reserved top-level domain, so nothing is
ever delivered there; skip those addresses in your mailer.

## Server API

`AnonymousExt` adds `auth.anonymous()`. `headers` are the request's; their cookies carry
the current session:

```rust
use fastauth::plugins::anonymous::{AnonymousExt, SignInAnonymousOutput};

let res = auth.anonymous().sign_in(&headers).await?; // res.set_cookies carries the session
if let SignInAnonymousOutput::SignedIn { token, user } = res.data {
    // ...
}
auth.anonymous().delete_user(&headers).await?;
```

## Better Auth's client

```ts
import { createAuthClient } from "better-auth/client";
import { anonymousClient } from "better-auth/client/plugins";

const authClient = createAuthClient({ baseURL: "https://acme.dk", plugins: [anonymousClient()] });

await authClient.signIn.anonymous();
// later, in the same browser:
await authClient.signUp.email({ email, password, name }); // links and deletes the anonymous user
await authClient.deleteAnonymousUser();
```

`compat/better-auth/run-anonymous.sh` runs Better Auth's 1.7.28 `anonymousClient` against
the plugin's `anonymous_server` example and checks 31 things: `signIn.anonymous` and its
user, signing in anonymously twice, `signUp.email` and `signIn.email` from an anonymous
session (the old anonymous session stops working), that sign-up can't set `isAnonymous`,
`deleteAnonymousUser` for anonymous, signed-out and real users, and that every error's code
and message match the client's `ANONYMOUS_ERROR_CODES`. It takes `PORT` (default 3000):

```bash
PORT=3001 compat/better-auth/run-anonymous.sh
```

## How it differs from Better Auth

- **When linking happens.** fastauth links in a core hook that runs whenever a session is
  created, so it covers every sign-in method, including ones Better Auth's path list
  misses. One visible difference: a user with two-factor who signs in from an anonymous
  session is linked when the two-factor challenge is answered. Better Auth skips the link
  when two-factor is required and doesn't link at `/two-factor/verify-*`, so its anonymous
  user stays.
- **Where the anonymous session comes from.** Only the session cookie. Better Auth also reads
  a bearer token, and falls back to an anonymous user id saved in the OAuth state when a
  social callback arrives without the cookie (Expo's in-app browser). fastauth has neither.
- **`on_link_account` gets the two sessions, not a request context.** Capture what you need
  (a pool, a client) in the closure. `generate_name` and `generate_random_email` are
  synchronous and get no request either; Better Auth passes the request context to
  `generateName` and accepts async functions.
- **Placeholder ids** come from the app's id strategy; Better Auth uses a 32-character random
  id.

### Not built

- The `schema` option for a custom column name.
- The OAuth-state fallback for cookie-less social callbacks (see above).
