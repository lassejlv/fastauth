# Usernames (feature `username`)

```rust
use axum::http::HeaderMap;
use fastauth::plugins::username::{SignInUsernameInput, Username, UsernameExt, UsernameUser};
use fastauth::prelude::*;

pub type AppAuth = Auth<Sqlx<Postgres>, (), plugins![Username]>;

pub fn build(pool: PgPool) -> Result<AppAuth, BuildError> {
    FastAuth::builder()
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("https://acme.dk")
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default())
        .plugin(Username::new().min_username_length(4).immutable_username(true))
        .build()
}

pub async fn handle(session: Session<AppAuth>) -> String {
    let fields: &UsernameUser = session.user.plugin::<Username, _>();
    fields.display_username.clone().unwrap_or_default()
}

pub async fn server_side(auth: &AppAuth, headers: &HeaderMap) -> Result<(), AuthError> {
    let free = auth.username().is_available("ada").await?.data.available;
    let _user = auth.username().find_user("Ada").await?;
    if !free {
        let _signed_in = auth
            .username()
            .sign_in(
                headers,
                SignInUsernameInput {
                    username: "ada".into(),
                    password: "correct horse".into(),
                    ..Default::default()
                },
            )
            .await?;
    }
    Ok(())
}
```

Full page: `docs/plugins/sign-in/04-username.md`.

- `fastauth = { version = "0.3", features = ["username"] }`; path `fastauth::plugins::username`.
  Adds nullable `username` (unique) and `display_username` columns to `user`: run migrations.
- Clients send `username` (and optionally `displayUsername`) on `/sign-up/email` and
  `/update-user`. It's validated (3 to 30 characters, ASCII letters, digits, `_`, `.`),
  refused when taken (400 `USERNAME_IS_ALREADY_TAKEN`) and stored lowercased;
  `displayUsername` defaults to the username as sent.
- `POST /sign-in/username` `{ username, password }` answers like `/sign-in/email` and runs the
  sign-in gates; 401 `INVALID_USERNAME_OR_PASSWORD`, 422 for an invalid username.
  `POST /is-username-available` answers `{ available }`.
- Options: `min_username_length`, `max_username_length`, `username_validator`,
  `display_username_validator`, `username_normalization`, `disable_username_normalization`,
  `display_username_normalization`, `username_validation_order`,
  `display_username_validation_order`, `immutable_username`.
- Only sign-up, update-user and `auth.api().create_user` check and normalize usernames. If you
  write one another way (admin routes, your own queries), store `Username::normalize(name)`
  or sign-in won't find it.
- Client: `usernameClient()` from `better-auth/client/plugins`.
