# JWT (feature `jwt`)

```rust
use fastauth::plugins::bearer::Bearer;
use fastauth::plugins::jwt::{Jwt, JwtAlgorithm, JwtExt};
use fastauth::prelude::*;

pub type AppAuth = Auth<Sqlx<Postgres>, (), plugins![Bearer, Jwt]>;

pub fn build(pool: PgPool) -> Result<AppAuth, BuildError> {
    FastAuth::builder()
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("https://acme.dk")
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default())
        .plugin(Bearer::new())
        .plugin(
            Jwt::new()
                .algorithm(JwtAlgorithm::ES256)
                .expiration_time(Duration::minutes(5))
                .rotation_interval(Duration::days(30)),
        )
        .build()
}

pub async fn service_token(auth: &AppAuth) -> Result<String, AuthError> {
    let mut claims = serde_json::Map::new();
    claims.insert("sub".into(), "billing-worker".into());
    auth.jwt().sign(claims).await
}
```

Full page: `docs/plugins/tokens/02-jwt.md`.

## Setup

- `fastauth = { version = "0.5", features = ["jwt"] }`; path `fastauth::plugins::jwt`.
- Adds the `jwks` table (`id`, `public_key`, `private_key`, `created_at`, `expires_at`, `alg`,
  `crv`). Run migrations. Private keys are encrypted with the app secret: keep the secret,
  or list the old one in `.secrets([new, old])`, or every signing fails with 500.
- Options: `algorithm` (EdDSA default, ES256, RS256), `issuer` and `audience` (the base URL),
  `expiration_time` (15 minutes), `rotation_interval` (never), `grace_period` (30 days),
  `define_payload(|session: SessionView| async move { .. })`, `disable_jwt_header()`.

## Routes and server API

- `GET /token` (session) answers `{ token }`; `GET /jwks` (public) answers `{ keys }`.
  `/get-session` adds a `set-auth-jwt` header unless `disable_jwt_header()`.
- Claims: `sub` (always the user id), `iat`, `exp`, `iss`, `aud`, plus the user or what
  `define_payload` returns.
- `auth.jwt()`: `headers(&h).token()`, `sign(claims)`, `verify(token)` (`Option` of claims),
  `jwks()`, `rotate()`. `sign`, `verify` and `rotate` have no HTTP route.
- Other services verify with `fastauth_plugin_jwt::JwksVerifier::from_json(jwks, issuer, audience)`
  and `verify::<Claims>(token)`; on `VerifyError::UnknownKey` fetch the JWKS again.
- Not built: `jwksPath`, `remoteUrl`, `getSubject`, `keyPairConfigs`,
  `disablePrivateKeyEncryption`, JWTs as the cookie cache.
- Client: `jwtClient()` from `better-auth/client/plugins`, then `authClient.token()`.
