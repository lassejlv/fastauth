# Passkeys (feature `passkey`)

```rust
use axum::http::HeaderMap;
use fastauth::plugins::passkey::{Passkey, PasskeyExt, UpdatePasskeyInput};
use fastauth::prelude::*;

pub type AppAuth = Auth<Sqlx<Postgres>, (), plugins![Passkey]>;

pub fn build(pool: PgPool) -> Result<AppAuth, BuildError> {
    FastAuth::builder()
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("https://acme.dk")
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default())
        .plugin(Passkey::new().rp_id("acme.dk").rp_name("Acme").origin("https://app.acme.dk"))
        .build()
}

pub async fn rename_first(auth: &AppAuth, headers: &HeaderMap) -> Result<(), AuthError> {
    let passkeys = auth.passkey().list(headers).await?;
    if let Some(first) = passkeys.first() {
        auth.passkey()
            .update(headers, UpdatePasskeyInput { id: first.id.to_string(), name: "Work".into() })
            .await?;
    }
    Ok(())
}
```

Full page: `docs/19-passkey.md`.

- `fastauth = { version = "0.3", features = ["passkey"] }`; path `fastauth::plugins::passkey`.
  Built on webauthn-rs 0.6.
- Adds the `passkey` table with Better Auth's columns and encodings. Run migrations.
- Options: `rp_id` (the base URL's host), `rp_name` (the app name), `origin` (repeatable;
  default the base URL's origin plus exact trusted origins).
- WebAuthn needs a secure context: https, or http://localhost.
- Adding a passkey needs a fresh session (`fresh_age`, 1 day): users need another way in first.
- Routes under `/api/auth/passkey/`: `generate-register-options`, `verify-registration`,
  `generate-authenticate-options`, `verify-authentication` (public; runs the sign-in gates with
  method `"passkey"`), `list-user-passkeys`, `update-passkey`, `delete-passkey`.
- `auth.passkey()`: `list`, `update`, `delete`. Registering and signing in only go over HTTP
  (they need a browser).
- Events: `PasskeyAdded`, `PasskeyDeleted`.
- Always: user verification required, resident key preferred, attestation `none`. Not built:
  passkey-first sign-up, extensions, EdDSA-only authenticators.
- Client: `passkeyClient()` from `@better-auth/passkey/client`.
