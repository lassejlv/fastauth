# Anonymous users (feature `anonymous`)

```rust
use axum::http::HeaderMap;
use fastauth::plugins::anonymous::{Anonymous, AnonymousExt, LinkAccount};
use fastauth::prelude::*;

pub type AppAuth = Auth<Sqlx<Postgres>, (), plugins![Anonymous]>;

pub fn build(pool: PgPool, app_db: PgPool) -> Result<AppAuth, BuildError> {
    FastAuth::builder()
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("https://acme.dk")
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default())
        .plugin(Anonymous::new().on_link_account(move |link: LinkAccount| {
            let app_db = app_db.clone();
            async move {
                // Move the guest's data to the real user, e.g. with sqlx on app_db.
                let _ = (&app_db, &link.anonymous_user.user.id, &link.new_user.user.id);
                Ok(())
            }
        }))
        .build()
}

pub async fn is_guest(session: Session<AppAuth>) -> bool {
    session.user.plugin::<Anonymous, _>().is_anonymous
}

pub async fn server_side(auth: &AppAuth, headers: &HeaderMap) -> Result<(), AuthError> {
    let _signed_in = auth.anonymous().sign_in(headers).await?; // .set_cookies has the session
    Ok(())
}
```

Full page: `docs/plugins/sign-in/05-anonymous.md`.

- `fastauth = { version = "0.5", features = ["anonymous"] }`; path `fastauth::plugins::anonymous`.
  Adds `is_anonymous` (bool, default false, not client-settable) to `user`: run migrations.
- `POST /sign-in/anonymous` creates a user named "Anonymous" with
  `{id}@anonymous.placeholder.invalid` and signs them in: `{ token, user }`. From an
  anonymous session it answers 400 `ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY`.
- When a browser with an anonymous session gets a new session for another user (any sign-in
  or sign-up method), `on_link_account` runs with both sessions, then the anonymous user is
  deleted (unless `disable_delete_anonymous_user(true)`). An error from the hook fails that
  response and keeps the anonymous user.
- `POST /delete-anonymous-user` deletes the signed-in anonymous user (403
  `USER_IS_NOT_ANONYMOUS` for real users).
- Options: `email_domain_name`, `generate_name`, `generate_random_email`, `on_link_account`,
  `disable_delete_anonymous_user`. The callbacks get no request context; capture what you need.
- Client: `anonymousClient()` from `better-auth/client/plugins`:
  `authClient.signIn.anonymous()`, `authClient.deleteAnonymousUser()`.
