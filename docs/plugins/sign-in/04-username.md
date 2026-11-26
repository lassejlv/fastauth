# Usernames

The `Username` plugin gives users a username next to their email, and lets them sign in
with it. It matches Better Auth's `username` plugin: the `username` and `displayUsername`
user fields, username on `/sign-up/email` and `/update-user`, `POST /sign-in/username` and
`POST /is-username-available`, with Better Auth's error codes, so its `usernameClient` works
unchanged.

## Setup

Turn on the facade's `username` feature:

```toml
[dependencies]
fastauth = { version = "0.3", features = ["username"] }
```

The plugin lives at `fastauth::plugins::username` (crate `fastauth-plugin-username`).
Register it next to email and password, which owns sign-up and the password check:

```rust
use fastauth::plugins::username::Username;
use fastauth::prelude::*;

pub type AppAuth = Auth<Sqlx<Postgres>, (), plugins![Username]>;

pub fn build(pool: PgPool) -> Result<AppAuth, BuildError> {
    FastAuth::builder()
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("https://acme.dk")
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default())
        .plugin(Username::new())
        .build()
}
```

It adds two nullable columns to `user`, so run your migrations after registering it:

| Column | JSON | What it holds |
|---|---|---|
| `username` | `username` | The normalized username (lowercase by default). Unique |
| `display_username` | `displayUsername` | The username as the user wrote it, for display |

Both are client-settable on sign-up and update-user, and returned in every user JSON. Read
them in Rust with `session.user.plugin::<Username, _>()`, which gives a `UsernameUser`.

## How it works

**Signing up.** `/sign-up/email` takes `username` and `displayUsername` next to the usual
fields. The username is checked (length, then the validator), refused when another user has
it, and stored normalized. `displayUsername` defaults to the username as sent:

```json
POST /api/auth/sign-up/email
{ "email": "ada@acme.dk", "password": "...", "name": "Ada", "username": "Ada_Lovelace" }

200 { "token": "...", "user": { "username": "ada_lovelace", "displayUsername": "Ada_Lovelace", ... } }
```

A sign-up with only `displayUsername` uses it as the username when it passes the checks.
Users without a username are fine: both columns stay `null`.

**Signing in.** `POST /sign-in/username` takes `username`, `password`, and optionally
`rememberMe` and `callbackURL`. The username is normalized before the lookup, so `ADA` finds
`ada`. It answers like `/sign-in/email`: `{ redirect, token, url, user }` and the session
cookie, or with `callbackURL` a redirect. Sign-in gates run with method `"username"`, so a
two-factor user gets `{ "twoFactorRedirect": true, ... }` and a banned user is refused.
When email and password requires a verified email, an unverified user gets 403
`EMAIL_NOT_VERIFIED` and a new verification email.

**Checking a name.** `POST /is-username-available` with `{ "username": "ada" }` answers
`{ "available": false }` when a user has it (after normalizing), and 422 when the name itself
isn't valid.

**Changing it.** `/update-user` with `username` checks and normalizes it the same way, and
refuses a name another user has. Sending your own username back (in any case) is fine.
`displayUsername` can change on its own.

**Server-side users.** `auth.api().create_user(..)` with `username` in `fields` is checked
and normalized like a sign-up.

### Errors

| Code | Status | When |
|---|---|---|
| `INVALID_USERNAME_OR_PASSWORD` | 401 | Sign-in with an unknown username, a wrong password, or a user without a password |
| `USERNAME_IS_ALREADY_TAKEN` | 400 | Sign-up, update-user or `create_user` with a username another user has |
| `USERNAME_TOO_SHORT`, `USERNAME_TOO_LONG` | 400, or 422 on sign-in and the availability check | Outside the length limits |
| `INVALID_USERNAME` | 400, or 422 on sign-in and the availability check | The validator refused it, or it was empty |
| `INVALID_DISPLAY_USERNAME` | 400 | The display username validator refused it |
| `USERNAME_IS_IMMUTABLE` | 400 | `immutable_username` is on and the user already has a different username |
| `EMAIL_NOT_VERIFIED` | 403 | Sign-in when a verified email is required |
| `PASSWORD_TOO_LONG` | 400 | Sign-in with a password over the email and password maximum |

The statuses and messages are Better Auth's.

## Configuration

| Option | Default | What it does |
|---|---|---|
| `min_username_length(n)` | 3 | Shortest username, in characters |
| `max_username_length(n)` | 30 | Longest username, in characters |
| `username_validator(f)` | ASCII letters, digits, `_` and `.` | `Fn(&str) -> bool`; `false` answers `INVALID_USERNAME` |
| `display_username_validator(f)` | none | `Fn(&str) -> bool`; `false` answers `INVALID_DISPLAY_USERNAME` |
| `username_normalization(f)` | lowercase | `Fn(&str) -> String` applied before storing and looking up |
| `disable_username_normalization()` | | Store and look up usernames exactly as sent (Better Auth's `usernameNormalization: false`) |
| `display_username_normalization(f)` | none | `Fn(&str) -> String` applied to `displayUsername` before storing |
| `username_validation_order(o)` | `PreNormalization` | Whether length and validator see the username before or after normalization |
| `display_username_validation_order(o)` | `PreNormalization` | The same for the display username validator |
| `immutable_username(b)` | off | Once a user has a username, `/update-user` can't change it |

```rust
use fastauth::plugins::username::{Username, ValidationOrder};

let plugin = Username::new()
    .min_username_length(4)
    .username_validator(|name| name.chars().all(|c| c.is_ascii_alphanumeric()))
    .display_username_normalization(|name| name.trim().to_owned())
    .username_validation_order(ValidationOrder::PostNormalization);
```

## Server API

`UsernameExt` adds `auth.username()`:

```rust
use fastauth::plugins::username::{SignInUsernameInput, UsernameExt};

let available = auth.username().is_available("ada").await?.data.available;
let user = auth.username().find_user("Ada").await?; // normalized lookup
let signed_in = auth
    .username()
    .sign_in(&headers, SignInUsernameInput {
        username: "ada".into(),
        password: "correct horse".into(),
        ..Default::default()
    })
    .await?; // signed_in.set_cookies carries the session
```

## Better Auth's client

```ts
import { createAuthClient } from "better-auth/client";
import { usernameClient } from "better-auth/client/plugins";

const authClient = createAuthClient({ baseURL: "https://acme.dk", plugins: [usernameClient()] });

await authClient.signUp.email({ email, password, name, username: "Ada" });
await authClient.signIn.username({ username: "ada", password });
const { data } = await authClient.isUsernameAvailable({ username: "grace" });
await authClient.updateUser({ username: "countess" });
```

`compat/better-auth/run-username.sh` runs Better Auth's 1.7.28 `usernameClient` against the
plugin's `username_server` example and checks 47 things: sign-up with a username and with
only `displayUsername`, taken, short and invalid usernames, `signIn.username` in another
case, its 401 and 422 errors, `isUsernameAvailable`, `updateUser` with a new, taken or bad
username and a new display username, and that every error's code and message match the
client's `USERNAME_ERROR_CODES`. It takes `PORT` (default 3000):

```bash
PORT=3001 compat/better-auth/run-username.sh
```

## How it differs from Better Auth

- **Where usernames are checked.** fastauth checks and normalizes usernames on
  `/sign-up/email`, `/update-user` and `auth.api().create_user(..)`. Better Auth does it in
  a database hook, so it also covers every other write of the user row. A username written
  another way (the admin plugin's `/admin/create-user` and `/admin/update-user`, or your own
  queries) isn't validated or normalized, and a non-normalized one can't be found by
  sign-in. Normalize it yourself with `Username::normalize`.
- **A race on the same username.** Two sign-ups with the same new username at the same moment
  both pass the check; the unique index refuses the second, which answers 422
  `USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL` instead of `USERNAME_IS_ALREADY_TAKEN`.
- **Validators and normalizers are synchronous** (`Fn(&str) -> bool` and
  `Fn(&str) -> String`); Better Auth also accepts async ones.
- **Length** counts Unicode characters; Better Auth counts UTF-16 code units, which differ
  only for characters outside the Basic Multilingual Plane, such as emoji.
- **`callbackURL` on sign-in** answers a 302 to it, as fastauth's `/sign-in/email` does.
  Better Auth answers 200 with the JSON and a `Location` header.
- **The verification email on an unverified sign-in** goes out whenever a mailer is
  configured, as on `/sign-in/email`; Better Auth sends it only with `sendOnSignIn`.

### Not built

- `displayUsername: false` (the plugin always adds both columns).
- The `schema` option for custom column names.
