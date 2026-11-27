# Bearer tokens (feature `bearer`)

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
        .plugin(Bearer::new().require_signature(true))
        .build()
}

// Authorization: Bearer <token> works with every session extractor.
pub async fn me(session: Session<AppAuth>) -> String {
    session.user.email.clone()
}
```

Full page: `docs/plugins/tokens/01-bearer.md`.

- `fastauth = { version = "0.7", features = ["bearer"] }`; path `fastauth::plugins::bearer`.
  No tables.
- Every response that sets the session cookie also carries the signed token in
  `set-auth-token` (listed in `Access-Control-Expose-Headers`). Clients store it and send
  `Authorization: Bearer <token>`.
- Accepted: the signed `set-auth-token` value, and the raw `token` from the sign-in JSON
  unless `require_signature(true)`. A bad or unknown token means signed out (401 on routes
  that need a session).
- It works on every auth route, the axum extractors, the session layer, `auth.get_session`
  and server API calls with `.headers(&headers)`. `POST /sign-out` with it deletes the session.
- A session cookie wins over a bearer token (Better Auth prefers the bearer token).
- Server API calls get no `set-auth-token`; they return the raw token in `data.token`.
- With `ApiKeys` reading `Authorization: Bearer` too, register `ApiKeys` first and make its
  `key_getter` return only your prefixed keys.
- Client: no client plugin; use `fetchOptions.onSuccess` to store `set-auth-token` and
  `fetchOptions.auth: { type: "Bearer", token }`.
