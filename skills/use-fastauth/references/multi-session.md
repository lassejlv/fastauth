# Multiple sessions (feature `multi-session`)

```rust
use axum::http::HeaderMap;
use fastauth::plugins::multi_session::{MultiSession, MultiSessionExt};
use fastauth::prelude::*;

pub type AppAuth = Auth<Sqlx<Postgres>, (), plugins![MultiSession]>;

pub fn build(pool: PgPool) -> Result<AppAuth, BuildError> {
    FastAuth::builder()
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("https://acme.dk")
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default())
        .plugin(MultiSession::new().maximum_sessions(3))
        .build()
}

pub async fn accounts(auth: &AppAuth, headers: &HeaderMap) -> Result<usize, AuthError> {
    let sessions = auth.multi_session().list_device_sessions(headers).await?.data;
    Ok(sessions.len())
}
```

Full page: `docs/22-multi-session.md`.

- `fastauth = { version = "0.4", features = ["multi-session"] }`; path
  `fastauth::plugins::multi_session`. No tables.
- Every new session also sets a signed `{prefix}.session_token_multi-{token lowercased}`
  cookie; the normal session cookie stays the active account. Signing in again as a
  remembered user replaces their older session. Past `maximum_sessions` (default 5) the new
  session is active but not remembered.
- `GET /multi-session/list-device-sessions` → `[{ session, user }]` (each `session.token`
  is what the other routes take). `POST /multi-session/set-active` `{ sessionToken }` switches
  the active account. `POST /multi-session/revoke` `{ sessionToken }` signs one account out;
  revoking the active one switches to the next. 401 `INVALID_SESSION_TOKEN` for a token the
  browser doesn't hold.
- `/sign-out` signs every remembered account out.
- Server API calls return cookie changes in `set_cookies`; copy them onto your response.
- Client: `multiSessionClient()` from `better-auth/client/plugins`:
  `authClient.multiSession.listDeviceSessions()`, `.setActive(..)`, `.revoke(..)`.
