# Passkeys

The `Passkey` plugin lets users sign in with passkeys: WebAuthn credentials held by the
device (Touch ID, Windows Hello, Android) or a security key, unlocked with a PIN or biometric.
A signed-in user adds a passkey; later anyone signs in with it, with no email or password.
It matches Better Auth's passkey plugin (`@better-auth/passkey`): the same seven routes, the
same JSON and error codes, and the same `passkey` table. Better Auth's `passkeyClient` works
unchanged. The WebAuthn checks (challenge, origin, RP ID, signature, user verification,
signature counter) are [webauthn-rs](https://docs.rs/webauthn-rs) 0.6.

## Setup

Turn on the facade's `passkey` feature:

```toml
[dependencies]
fastauth = { version = "0.5", features = ["passkey"] }
```

or `cargo add fastauth --features passkey`. The plugin lives at `fastauth::plugins::passkey`
(crate `fastauth-plugin-passkey`).

Register it on the builder and list it in your `Auth` alias:

```rust
use fastauth::plugins::passkey::Passkey;
use fastauth::prelude::*;

pub type AppAuth = Auth<Sqlx<Postgres>, (), plugins![Passkey]>;

pub fn build(pool: PgPool) -> Result<AppAuth, BuildError> {
    FastAuth::builder()
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("https://acme.dk")
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default())
        .plugin(Passkey::new().rp_name("Acme"))
        .build()
}
```

`Passkey` depends on no other plugin. By default users need some other way in first (email
and password, a magic link, social sign-in) to add their first passkey, because registering
needs a session. [Passkey-first sign-up](#passkey-first-sign-up) lets a signed-out visitor
register a passkey and become a user with it.

WebAuthn only runs in a secure context: `https://`, or `http://localhost` in development.

### The `passkey` table

The plugin adds one table, `passkey`. Run migrations after adding it
([Migrations](../../concepts/02-database.md#migrations)). `cargo run --bin fastauth -- schema` prints it:

```
passkey
  id                        id         passkey primary key
  name                      text       passkey nullable
  public_key                text       passkey
  user_id                   id         passkey -> user.id on delete cascade, index
  credential_id             text       passkey unique
  counter                   int        passkey
  device_type               text       passkey
  backed_up                 bool       passkey
  transports                text       passkey nullable
  created_at                timestamp  passkey default now
  aaguid                    text       passkey nullable
```

| Column | Meaning |
|---|---|
| `name` | The name the user gave the passkey, if any |
| `public_key` | The credential's COSE public key, base64, exactly as the authenticator sent it |
| `credential_id` | The credential id, base64url: the `id` browsers send |
| `counter` | The authenticator's signature counter at the last sign-in; 0 for authenticators that don't count |
| `device_type` | `singleDevice`, or `multiDevice` when the credential can sync (backup eligible) |
| `backed_up` | Whether the credential is synced right now |
| `transports` | The browser's transport hints, comma-separated (`internal,hybrid`) |
| `aaguid` | The authenticator model, as a UUID; all zeros when the authenticator hides it |

These are Better Auth's columns, in snake case, with Better Auth's encodings, so passkeys from
a Better Auth app's `passkey` table keep working. `credential_id` is unique here (Better Auth
only indexes it), so one credential can't belong to two users.

## Configuration

| Option | Default | What it does |
|---|---|---|
| `rp_id(s)` | `base_url`'s host | The relying party ID passkeys are bound to. A parent domain (`acme.dk`) shares passkeys with its subdomains |
| `rp_name(s)` | the app name | The name authenticators show for the site |
| `origin(s)` | see below | An origin ceremonies may come from. Call once per origin |
| `sign_up(resolver)` | off | [Passkey-first sign-up](#passkey-first-sign-up): signed-out registration creates the user `resolver` names |

These are Better Auth's `rpID`, `rpName` and `origin`. Without `origin`, ceremonies may
come from `base_url`'s origin or any trusted origin listed exactly (entries with `*` or
`?` don't count), as in Better Auth. Set `origin` when the frontend runs on another
origin than the API:

```rust
Passkey::new()
    .rp_id("acme.dk")
    .rp_name("Acme")
    .origin("https://app.acme.dk")
    .origin("https://acme.dk")
```

When the RP ID isn't the host of the first origin or one of its parent domains, every
ceremony answers `500 ORIGIN_NOT_CONFIGURED`.

User verification is always required: the authenticator must check a PIN or biometric. That's
webauthn-rs's rule for passkeys. Better Auth asks for it as `"preferred"` unless configured.
Registration asks for a discoverable credential (`residentKey: "preferred"`), so a signed-out
user can sign in without typing anything.

## Endpoints

Under your `base_path` (`/api/auth` by default):

| Method | Path | Better Auth client | Access | Answers |
|---|---|---|---|---|
| `GET` | `/passkey/generate-register-options` | `passkey.addPasskey()` | fresh session, or none with `sign_up` | `PublicKeyCredentialCreationOptionsJSON` |
| `POST` | `/passkey/verify-registration` | `passkey.addPasskey()` | fresh session, or none with `sign_up` | the new passkey |
| `GET` | `/passkey/generate-authenticate-options` | `signIn.passkey()` | public | `PublicKeyCredentialRequestOptionsJSON` |
| `POST` | `/passkey/verify-authentication` | `signIn.passkey()` | public | `{ session, user }` |
| `GET` | `/passkey/list-user-passkeys` | `passkey.listUserPasskeys()` | session | the user's passkeys |
| `POST` | `/passkey/update-passkey` | `passkey.updatePasskey({ id, name })` | session | `{ passkey }` |
| `POST` | `/passkey/delete-passkey` | `passkey.deletePasskey({ id })` | session | `{ status: true }` |

"Fresh session" means a session younger than `fresh_age` (one day by default,
[Sessions](../../concepts/01-sessions.md)), as Better Auth's `freshSessionMiddleware` requires: `401`
without a session, `403 SESSION_NOT_FRESH` with an old one or an API key's. Registration also
reads the session again from the database, skipping the cookie cache, as Better Auth's
`sensitiveSessionMiddleware` does: a revoked session gets `401`, and an impersonation session
`403 NOT_ALLOWED_WHILE_IMPERSONATING` ([Admin](../access/02-admin.md#impersonation)).

### Adding a passkey

`generate-register-options` takes three optional query parameters: `authenticatorAttachment`
(`platform` or `cross-platform`), `name` (the account name the authenticator shows;
default the user's email) and `context` (for [passkey-first sign-up](#passkey-first-sign-up);
ignored for signed-in users).
It excludes the user's existing passkeys, so an authenticator can't register twice.

`verify-registration` takes `{ response, name?, createSession? }`, where `response` is the
`navigator.credentials.create()` result as JSON (what `@simplewebauthn/browser`'s
`startRegistration` returns). It answers the stored passkey:

```json
{
  "id": "01KBQ3A7XW0M5Y6Z7A8B9C0D1E",
  "name": "Laptop",
  "publicKey": "pQECAyYgASFYIJ...",
  "userId": "01KBQ2Z8Q4N0Y3C4V5W6X7Y8Z9",
  "credentialID": "Xq3G5v0c2kU8iA1oQd7m4w",
  "counter": 0,
  "deviceType": "multiDevice",
  "backedUp": true,
  "transports": "internal,hybrid",
  "createdAt": "2026-11-26T10:00:00Z",
  "aaguid": "fbfc3007-154e-4ecc-8c0b-6e020557d7bd"
}
```

With `createSession: true` it also starts a new session for the user (no sign-in gates run:
the user is already signed in) and adds `session` and `user`.

### Passkey-first sign-up

`sign_up` lets a signed-out visitor register a passkey, and registering it creates their user.
It's off by default. Your resolver decides who the new user is, usually from the `context`
the client passes to `addPasskey`:

```rust
use fastauth::plugins::passkey::{Passkey, PasskeyUser};
use fastauth::prelude::*;

let passkey = Passkey::new().sign_up(|request| async move {
    let email = request
        .context
        .ok_or_else(|| AuthError::bad_request("EMAIL_REQUIRED", "pass the email as context"))?;
    Ok(PasskeyUser { name: request.name.unwrap_or_default(), email, email_verified: false })
});
```

```ts
await authClient.passkey.addPasskey({ context: "ada@acme.dk", name: "Laptop", createSession: true });
```

The resolver gets a `PasskeySignUp` with the `context` and `name` query parameters, as the
client sent them, and returns a `PasskeyUser`: `email`, `name` and `email_verified`. An error
it returns is the route's answer, so it can turn visitors away. `context` is untrusted input:
anyone can call the route with any value, so pass something you can check (a signed token
from your sign-up form, say) when it matters who may sign up.

The flow:

1. `generate-register-options` with no session calls the resolver, checks the email
   (`400 INVALID_EMAIL`) and stores the user with the challenge. Nothing is created yet.
2. `verify-registration` checks the attestation, then creates the user and the passkey. When
   the email belongs to a user by then, it answers `422 USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL`
   and creates nothing: sign-up never adds a passkey to an existing user.
3. With `createSession: true` the new user signs in through every sign-in gate, with method
   `"passkey"`. A gate that denies answers its error; the user and passkey stay, without a
   session. A gate that challenges adds its JSON (`twoFactorRedirect`) instead of `session`
   and `user`. Without `createSession`, the user signs in with the passkey afterwards.

Signed-in requests keep the usual rules, with sign-up on or not: the passkey goes to the
session's user and `context` is ignored. An old, API-key or impersonation session still
gets `403`: it never falls back to sign-up. A challenge stays with the kind of registration
that started it, so a sign-up challenge finished signed in answers
`401 YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY`, and a signed-in challenge finished signed
out answers `401 UNAUTHORIZED`.

**Unverified emails.** Leave `email_verified` false unless your app has proven the visitor
owns the address. An unverified user is claimed by whoever later proves the email with a
magic link, an email code, a password reset, a verification link or a verified social
account: core deletes the accounts and sessions from before the proof, and the passkey plugin
deletes that user's passkeys in the same transaction. So someone who signs up with another person's email keeps no way in.

This is Better Auth's `registration: { requireSession: false, resolveUser }`. Better Auth
leaves creating the user to an `afterVerification` callback; fastauth creates it from what the
resolver returned.

### Signing in

`generate-authenticate-options` needs no session. Signed out, its `allowCredentials` is
empty, so the browser offers every discoverable passkey it has for the site. Signed in, it
lists the user's passkeys.

`verify-authentication` takes `{ response }`, the `navigator.credentials.get()` result as
JSON. It finds the passkey by credential id, verifies the assertion, checks the signature
counter, and signs the passkey's user in. The answer is `{ session, user }` with the session
cookie set, like `/get-session` plus the session token.

### Challenges

Each `generate-*` call stores its challenge server-side, in the `verification` table, for five
minutes, and sets a signed `{prefix}.passkey` cookie naming it (only the name's hash is
stored). The matching `verify-*` call consumes it, whatever the outcome, and clears the
cookie. So each challenge works once, a challenge from one ceremony can't finish the other,
and a registration challenge issued to one user can't add a passkey for another
(`401 YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY`).

### The signature counter

Authenticators that count sign each assertion with a higher counter than the last. A counter
that didn't go up means the credential may have been cloned: the sign-in fails with
`400 AUTHENTICATION_FAILED` and the stored counter stays. Otherwise the stored counter moves
to the new value, with a compare-and-swap, so two concurrent sign-ins with the same counter
can't both succeed. Authenticators that report 0 every time (most synced passkeys) are
allowed, as the WebAuthn spec says. `backed_up` is updated on each sign-in too.

### Sign-in gates

A passkey sign-in runs every plugin's sign-in gate with method `"passkey"`, like any other
sign-in. A gate that denies (an admin ban) answers its error and no session is created. A gate
that challenges answers its JSON instead of `{ session, user }`: with
[two-factor](../README.md#sign-in-methods) on, that's `{ "twoFactorRedirect": true, ... }`, and
`/two-factor/verify-totp` finishes the sign-in, still as method `"passkey"`. Better Auth's
own `verify-authentication` skips this and creates the session directly.

### Claimed users

When proof of an email claims a user whose email wasn't verified (a magic link, an email
code, a password reset, a verification link, a verified social account; see
[Claiming an email](../../concepts/03-security.md#claiming-an-email)), the plugin deletes every
passkey that user had, inside the claim's transaction. They were registered before anyone proved
the address, so they don't count as the owner's.

### Errors

| Status | Code | When |
|---|---|---|
| 400 | `CHALLENGE_NOT_FOUND` | No challenge cookie, or the challenge expired, was used, or belongs to the other ceremony |
| 401 | `YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY` | The registration challenge was issued to another user, or is a sign-up challenge finished signed in; renaming someone else's passkey |
| 422 | `USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL` | Passkey-first sign-up for an email that has a user |
| 400 | `FAILED_TO_VERIFY_REGISTRATION` | The attestation doesn't verify (wrong origin or RP ID, no user verification, an excluded or already registered credential) |
| 401 | `PASSKEY_NOT_FOUND` | No passkey has the credential that signed in |
| 404 | `PASSKEY_NOT_FOUND` | Updating or deleting an id that doesn't exist |
| 401 | `UNAUTHORIZED` | Deleting someone else's passkey |
| 401 | `AUTHENTICATION_FAILED` | The assertion's signature is wrong |
| 400 | `AUTHENTICATION_FAILED` | The assertion is malformed, answers another origin or RP ID, lacks user verification, or its counter didn't go up |
| 400 | `INVALID_REQUEST_BODY` | `update-passkey` with an empty name |
| 500 | `ORIGIN_NOT_CONFIGURED` | The RP ID and origins don't make a valid relying party |

Statuses and codes are Better Auth's.

## Server API

`auth.passkey()` manages a user's passkeys without HTTP. It only compiles when `Passkey` is
registered. `headers` are the request's, whose cookies carry the session:

```rust
use fastauth::plugins::passkey::{PasskeyExt, UpdatePasskeyInput};

let passkeys = auth.passkey().list(&headers).await?;
auth.passkey()
    .update(&headers, UpdatePasskeyInput { id: passkeys[0].id.to_string(), name: "Work".into() })
    .await?;
```

`delete(&headers, DeletePasskeyInput { id })` deletes one. Registering and signing in need a
browser, so they only go over HTTP.

The plugin emits `PasskeyAdded { user_id, passkey_id }` and `PasskeyDeleted { user_id,
passkey_id }` ([Events](../../reference/01-plugin-authoring.md#events)).

## Better Auth's client

```ts
import { createAuthClient } from "better-auth/client";
import { passkeyClient } from "@better-auth/passkey/client";

const authClient = createAuthClient({
  baseURL: "https://acme.dk",
  plugins: [passkeyClient()],
});

await authClient.passkey.addPasskey({ name: "Laptop" });
await authClient.signIn.passkey();
const { data: passkeys } = await authClient.passkey.listUserPasskeys();
await authClient.passkey.updatePasskey({ id: passkeys[0].id, name: "Work laptop" });
await authClient.passkey.deletePasskey({ id: passkeys[0].id });
```

`compat/better-auth/run-passkey.sh` checks this against Better Auth 1.7.28's `passkeyClient`
in headless Chrome, with Chrome's virtual authenticator answering WebAuthn: adding passkeys
(with and without `createSession`), the excluded second registration, discoverable sign-in
signed out, sign-in signed in, the counter, renaming, deleting, signing in with a deleted
passkey, and passkey-first sign-up (`addPasskey({ context, createSession: true })` signed out,
a taken email, no context). Its server turns sign-up on with the email taken from `context`. It needs cargo, bun and Chrome or Chromium (`CHROME_PATH`), and takes `PORT`.

## Not built

- Better Auth's `registration.afterVerification` callback: passkey-first sign-up creates the
  user from what the `sign_up` resolver returned, and the passkey always goes to that user.
- `authenticatorSelection` and `advanced.webAuthnChallengeCookie`: user verification is always
  required, the resident key is always preferred, and the cookie is always `{prefix}.passkey`.
- Registration and authentication `extensions`, and `authentication.afterVerification`.
- Attestation: registration asks for `none` and doesn't check authenticator certificates.
- Better Auth's `getAuthenticatorName` AAGUID table; the AAGUID is stored for apps to resolve.
- Signature algorithms: ES256, ES384 and RS256 (webauthn-rs's set). EdDSA-only authenticators
  can't register.
