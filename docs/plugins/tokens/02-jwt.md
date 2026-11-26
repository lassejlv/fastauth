# JWT

The `Jwt` plugin issues JSON Web Tokens for signed-in users and publishes the public keys as
a JWKS, so other services can check who a request comes from without calling the auth
server or sharing its database. It matches Better Auth's `jwt` plugin: `GET /token`,
`GET /jwks`, the `set-auth-jwt` header on `/get-session`, a `jwks` table with private keys
encrypted at rest, and the same claims. Better Auth's `jwtClient` works unchanged.

## Setup

Turn on the facade's `jwt` feature:

```toml
[dependencies]
fastauth = { version = "0.5", features = ["jwt"] }
```

or `cargo add fastauth --features jwt`. The plugin lives at `fastauth::plugins::jwt` (crate
`fastauth-plugin-jwt`).

Register it on the builder and list it in your `Auth` alias:

```rust
use fastauth::plugins::jwt::Jwt;
use fastauth::prelude::*;

pub type AppAuth = Auth<Sqlx<Postgres>, (), plugins![Jwt]>;

pub fn build(pool: PgPool) -> Result<AppAuth, BuildError> {
    FastAuth::builder()
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("https://acme.dk")
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default())
        .plugin(Jwt::new())
        .build()
}
```

`Jwt` depends on no other plugin. Native clients often pair it with
[Bearer](01-bearer.md): `plugins![Bearer, Jwt]`.

### The `jwks` table

The plugin adds one table, `jwks`. Run migrations after adding it
([Migrations](../../concepts/02-database.md#migrations)). `cargo run --bin fastauth -- schema` prints it:

```
jwks
  id                        id         jwt  primary key
  public_key                text       jwt
  private_key               text       jwt
  created_at                timestamp  jwt  default now
  expires_at                timestamp  jwt  nullable
  alg                       text       jwt  nullable
  crv                       text       jwt  nullable
```

| Column | Meaning |
|---|---|
| `id` | The key id, the `kid` of the JWKS entry and of every token the key signs |
| `public_key` | The public JWK as JSON, e.g. `{"kty":"OKP","crv":"Ed25519","x":"..."}` |
| `private_key` | The private key, encrypted (see [Keys](#keys)) |
| `expires_at` | When the key stops signing; empty means never |
| `alg`, `crv` | `EdDSA`/`Ed25519`, `ES256`/`P-256` or `RS256` (no curve) |

The table and column meanings are Better Auth's. The private keys are encrypted differently,
so a `jwks` table from a Better Auth app can't be reused.

## Configuration

| Option | Default | What it does |
|---|---|---|
| `algorithm(a)` | `JwtAlgorithm::EdDSA` | The algorithm of new keys: `EdDSA` (Ed25519), `ES256` (P-256) or `RS256` (RSA 2048) |
| `issuer(s)` | the base URL | `iss` of every token |
| `audience(s)` | the base URL | `aud` of every token |
| `expiration_time(d)` | 15 minutes | How long tokens are valid |
| `define_payload(f)` | the user | The claims a session's token carries |
| `rotation_interval(d)` | never | Keys expire this long after they're created; the next signing creates a new one |
| `grace_period(d)` | 30 days | How long an expired key stays in the JWKS and keeps verifying |
| `disable_jwt_header()` | header on | Stop signing a token into `set-auth-jwt` on every `/get-session` |

These are Better Auth's `jwks.keyPairConfig.alg`, `jwt.issuer`, `jwt.audience`,
`jwt.expirationTime`, `jwt.definePayload`, `jwks.rotationInterval`, `jwks.gracePeriod` and
`disableSettingJwtHeader`, with the same defaults. "The base URL" is the builder's
`base_url` without a trailing slash, e.g. `https://acme.dk`.

```rust
use fastauth::plugin_prelude::SessionView;
use fastauth::plugins::jwt::{Jwt, JwtAlgorithm};

Jwt::new()
    .algorithm(JwtAlgorithm::ES256)
    .issuer("https://auth.acme.dk")
    .audience("https://api.acme.dk")
    .expiration_time(Duration::minutes(5))
    .rotation_interval(Duration::days(30))
    .grace_period(Duration::days(7))
    .define_payload(|session: SessionView| async move {
        let mut claims = serde_json::Map::new();
        claims.insert("email".into(), session.user.email.clone().into());
        let plan: String = session.user.row.get("plan").map_err(AuthError::internal)?;
        claims.insert("plan".into(), plan.into());
        Ok(claims)
    })
```

`define_payload` gets the session (`session.session`, `session.user`, and the raw rows for
your own and plugins' columns) and returns the claims. It's async, so it can read the
database. `sub` is always the user id, and `iat`, `exp`, `iss` and `aud` are added unless
it sets them.

## Endpoints

Under your `base_path` (`/api/auth` by default):

| Method | Path | Better Auth client | Access | Answers |
|---|---|---|---|---|
| `GET` | `/token` | `authClient.token()` | session | `{ "token": "<jwt>" }`; `401 UNAUTHORIZED` without a session |
| `GET` | `/jwks` | `authClient.jwks()` (`jwtClient`) | public | `{ "keys": [..] }` |

`/get-session` with a session also answers with the session's token in a `set-auth-jwt`
header, added to `Access-Control-Expose-Headers`. Without a session there's no header.

A JWKS entry is the stored public JWK plus `alg`, `crv` (none for RSA) and `kid`:

```json
{
  "keys": [
    {
      "alg": "EdDSA",
      "crv": "Ed25519",
      "kty": "OKP",
      "x": "2XoTZ9c3bU6Qh0h2bXq1d6g1kQm8Jq3b8m7wq9i4Y1A",
      "kid": "01KBQ2Z8Q4N0Y3C4V5W6X7Y8Z9"
    }
  ]
}
```

The first key is created on the first call to `/token`, `/jwks` or `/get-session` that needs
one. Private key material never leaves the server.

### What a token contains

A session's token is signed with the newest live key and carries:

| Claim | Value |
|---|---|
| header `alg`, `kid` | The key's algorithm and id; no `typ`, as in Better Auth |
| `sub` | The user id |
| `iat` | Now |
| `exp` | `iat` plus `expiration_time` |
| `iss`, `aud` | The issuer and audience |
| the rest | The user as `/get-session` returns it (`id`, `email`, `name`, `emailVerified`, `image`, `createdAt`, `updatedAt` and your returned columns), or what `define_payload` returns |

## Server API

`auth.jwt()` (trait `JwtExt`) works without HTTP:

| Method | Does | Better Auth |
|---|---|---|
| `headers(&h).token()` | The token for the session in `h`, as `/token` answers | `auth.api.getToken({ headers })` |
| `sign(claims)` | Signs any claims with the current key, adding `exp`, `iss` and `aud` unless set | `auth.api.signJWT({ body: { payload } })` |
| `verify(token)` | `Some(claims)` when a key `/jwks` publishes signed it and `exp`, `nbf`, `iss` and `aud` check out, else `None` | `auth.api.verifyJWT({ body: { token } })` |
| `jwks()` | The JWKS, as `/jwks` answers | `auth.api.getJwks()` |
| `rotate()` | Retires every live key, deletes keys past their grace period, and creates a new key, returning its `kid` | `createJwk` |

```rust
pub async fn service_token(auth: &AppAuth) -> Result<String, AuthError> {
    let mut claims = serde_json::Map::new();
    claims.insert("sub".into(), "billing-worker".into());
    claims.insert("scope".into(), "invoices:read".into());
    auth.jwt().sign(claims).await
}
```

`sign`, `verify` and `rotate` are server-only endpoints with no HTTP route
(`SignJwt`, `VerifyJwt`, `RotateKeys`), so hooks can target them like routed ones.
`auth.jwt()` only compiles when `Jwt` is in the alias.

## Verifying tokens in another service

A resource server doesn't need fastauth or a database: it fetches the JWKS and checks tokens
against it with `JwksVerifier` (in `fastauth-plugin-jwt`, which you can depend on alone):

```toml
[dependencies]
fastauth-plugin-jwt = "0.5"
```

```rust
use fastauth_plugin_jwt::{JwksVerifier, VerifyError};
use serde::Deserialize;

#[derive(Deserialize)]
struct Claims {
    sub: String,
    email: String,
}

async fn load(http: &reqwest::Client) -> anyhow::Result<JwksVerifier> {
    let jwks = http
        .get("https://acme.dk/api/auth/jwks")
        .send()
        .await?
        .text()
        .await?;
    Ok(JwksVerifier::from_json(&jwks, "https://acme.dk", "https://acme.dk")?)
}

async fn user_of(
    http: &reqwest::Client,
    verifier: &mut JwksVerifier,
    token: &str,
) -> anyhow::Result<Claims> {
    match verifier.verify::<Claims>(token) {
        Err(VerifyError::UnknownKey(_)) => {
            *verifier = load(http).await?;
            Ok(verifier.verify(token)?)
        }
        result => Ok(result?),
    }
}
```

`verify` checks the signature with the key named by the token's `kid`, then `exp` and `nbf`
(no clock leeway unless you set `.leeway(seconds)`), `iss`, and `aud`, and requires `exp`,
`sub`, `iss` and `aud`. The algorithm comes from the key, never from the token header.
`VerifyError::UnknownKey` means the token names a key the verifier hasn't seen: after a
rotation, fetch the JWKS again, as above. Every other failure, a token without a `kid`
included, is `VerifyError::Invalid`.

The `kid` comes from the token's header, which nobody has checked yet, so anyone can make
`UnknownKey` happen with a made-up `kid`. Refetch at most once per cool-down (30 seconds or
more; jose's `createRemoteJWKSet` waits 30 seconds by default), or every such request makes
your server fetch the JWKS again. The example above refetches on every miss; keep the time of
the last fetch next to the verifier and skip the refetch inside the cool-down.

Any JOSE library works the same way; with `jose` in JavaScript:

```ts
import { createRemoteJWKSet, jwtVerify } from "jose";

const jwks = createRemoteJWKSet(new URL("https://acme.dk/api/auth/jwks"));
const { payload } = await jwtVerify(token, jwks, {
  issuer: "https://acme.dk",
  audience: "https://acme.dk",
});
```

## Keys

- **Generation.** Keys are generated with aws-lc-rs (the crypto library rustls already uses),
  Ed25519 by default, and signed and verified with
  [`jsonwebtoken`](https://docs.rs/jsonwebtoken) on the same backend. `jsonwebtoken` is
  re-exported as `fastauth_plugin_jwt::jsonwebtoken`.
- **Encrypted at rest.** `private_key` holds the PKCS#8 key encrypted with
  XChaCha20-Poly1305 under a key derived from the app secret, the same encryption core uses
  for other secrets ([Security](../../concepts/03-security.md)). A database dump alone can't sign tokens.
  The secret must stay the same, or be kept in `.secrets([new, old])` when you rotate it:
  a key that no configured secret decrypts fails every signing with `500 INTERNAL_SERVER_ERROR`. To start
  over, delete the `jwks` rows; a new key is created on the next request.
- **Rotation on a schedule.** With `rotation_interval(d)`, each key gets an `expires_at`. The
  first signing after that creates a new key, and the old one stays in the JWKS for
  `grace_period` so tokens it signed keep verifying. Keep the grace period longer than
  `expiration_time`.
- **Rotation on demand.** `auth.jwt().rotate()` sets `expires_at` to now on every live key and
  creates a new one, for example after a suspected leak. With a leak, also shorten the grace
  period or delete the old rows, so the old key stops verifying.
- **Retired keys.** A key stops verifying, in `auth.jwt().verify()` as in the JWKS, when its
  grace period ends, and the next `rotate()` deletes its row. Better Auth's `verifyJWT`
  keeps trusting every stored key.
- **Changing the algorithm.** After `algorithm(..)` changes, the next signing creates a key of
  the new algorithm. Old keys stay in the JWKS until they expire, so tokens they signed keep
  verifying.
- **Concurrency.** When two servers create the first key at the same moment, both keys are
  stored and listed; each token names its own `kid`, so both verify.

## Better Auth's client

Add `jwtClient`. The tested version is 1.7.28:

```ts
import { createAuthClient } from "better-auth/client";
import { jwtClient } from "better-auth/client/plugins";

export const authClient = createAuthClient({
  baseURL: "https://acme.dk",
  plugins: [jwtClient()],
});

const { data } = await authClient.token();
const { data: jwks } = await authClient.jwks();
```

`compat/better-auth/run-jwt.sh` runs it, with bearer auth, against the plugin's
`compat_server` example and checks: `jwks()` (one EdDSA/Ed25519/OKP key with a `kid` and no
private part), `token()` (header `alg` and `kid`, verified with `jose` against the local and
the remote JWKS: `sub`, the user, a 15-minute lifetime), `set-auth-jwt` and
`Access-Control-Expose-Headers` on `getSession`, and `token()` without a session
(`401`). It takes `PORT` (default 3000):

```bash
PORT=3001 compat/better-auth/run-jwt.sh
```

## Not built

These Better Auth `jwt` options don't exist in fastauth:

- `jwks.jwksPath` (the JWKS is always at `/jwks`) and `jwks.remoteUrl` with `jwt.sign`
  (signing outside fastauth).
- `keyPairConfig` beyond the algorithm: RSA keys are 2048-bit and ES256 uses P-256;
  `keyPairConfigs` for several algorithms at once.
- `jwt.getSubject` (`sub` is always the user id), `signJWT`'s `overrideOptions`, and an
  array `audience`.
- `disablePrivateKeyEncryption` and custom key storage (`adapter.getJwks`, `createJwk`).
- `sessionCookieCache` (JWTs as the cookie cache) and the OIDC provider integration.

One difference in key choice: when the configured algorithm changes, Better Auth can keep
signing with the newest key of the old algorithm; fastauth always signs with a key of the
configured algorithm, creating one if needed.
