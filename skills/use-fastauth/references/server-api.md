# The server API

Every endpoint can be called from Rust with typed input and output, no HTTP and no JSON.
Calls run the same access checks, hooks and events as HTTP requests.

```rust
use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use fastauth::mail::MailError;
use fastauth::prelude::*;
use fastauth::routes::{SignInEmailInput, SignUpEmailInput};
use serde::Deserialize;

pub type AppAuth = Auth<MemoryAdapter>;

pub async fn create_user(
    auth: &AppAuth,
    email: &str,
    password: &str,
) -> Result<Option<String>, AuthError> {
    let created = auth
        .api()
        .sign_up_email(SignUpEmailInput {
            name: "Lasse".into(),
            email: email.into(),
            password: password.into(),
            image: None,
            callback_url: None,
            remember_me: None,
            extra: Default::default(),
        })
        .await?;
    Ok(created.data.token)
}

#[derive(Deserialize)]
pub struct InviteSignIn {
    code: String,
    email: String,
    password: String,
}

pub async fn sign_in_with_invite(
    State(auth): State<AppAuth>,
    headers: HeaderMap,
    Json(body): Json<InviteSignIn>,
) -> Result<Response, AuthError> {
    if body.code != "let-me-in" {
        return Err(AuthError::bad_request("INVALID_INVITE", "unknown invite code"));
    }
    let signed_in = auth
        .api()
        .headers(&headers)
        .sign_in_email(SignInEmailInput {
            email: body.email,
            password: body.password,
            callback_url: None,
            remember_me: Some(true),
        })
        .await?;
    Ok(signed_in.into_http().map(Body::from))
}

pub async fn session_count(auth: &AppAuth, token: &str) -> Result<usize, AuthError> {
    let sessions = auth.api().session_token(token).list_sessions().await?;
    Ok(sessions.data.len())
}

pub async fn whoami(auth: &AppAuth, headers: &HeaderMap) -> Result<Option<String>, AuthError> {
    let session = auth.get_session(headers).await?;
    Ok(session.map(|s| s.user.email.clone()))
}

pub struct ConsoleMailer;

impl Mailer for ConsoleMailer {
    async fn send(&self, email: AuthEmail) -> Result<(), MailError> {
        let (subject, body) = email.default_text("Acme");
        println!("to {}: {subject}\n{body}", email.to());
        Ok(())
    }
}
```

- `auth.api()` has `sign_up_email`, `sign_in_email`, `sign_out`, `list_sessions`,
  `revoke_other_sessions`, `change_password`, `request_password_reset` and
  `reset_password`. Their input types are in `fastauth::routes` (`SignUpEmailInput`,
  `SignInEmailInput`, `ChangePasswordInput`, ...); every field is public.
- `.call(&endpoint, input)` runs any other endpoint, core or plugin:
  `auth.api().headers(&headers).call(&fastauth::routes::RevokeSessions, Empty {})`. The
  endpoint types are in `fastauth::routes` and in each plugin crate.
- Endpoints that need a session read it from `.headers(&request_headers)` (the cookie) or
  `.session_token(&token)`. Without either they fail with `401`.
- Each call returns `ApiResponse { data, set_cookies }`. To pass a sign-in's cookies to the
  browser, return `.into_http().map(Body::from)` from the handler, as above.
- App columns go in `SignUpEmailInput.extra`, a JSON map keyed by camelCase name, and the
  `input` rule applies there too.
- `auth.get_session(&headers)` and `auth.get_session_by_token(&token)` read the current
  session. Plugin server APIs are extension traits: `auth.two_factor()`.
- `.in_tx(..)` and `.meta(..)` from `docs/04-sessions.md` don't exist yet.

## App-level hooks and events

The app registers hooks and event handlers on the builder, the same way plugins do in
`init`:

```rust
use fastauth::endpoint::Before;
use fastauth::routes::{SignUpEmail, SignUpEmailInput};

FastAuth::builder()
    // ...
        .configure(|app| {
            app.hook::<SignUpEmail>()
                .before(|_ctx, mut input: SignUpEmailInput| async move {
                    if input.email.ends_with("@mailinator.com") {
                        return Err(AuthError::bad_request("DISPOSABLE_EMAIL", "use a real email address"));
                    }
                    input.name = input.name.trim().to_owned();
                    Ok(Before::Continue(input))
                });
        })
        .on(|e: UserCreated, _ctx| async move {
            println!("welcome, {}", e.email);
            Ok(())
        })
    .build()
```

- `app.hook::<E>().before(..)` gets `E`'s typed input and returns `Before::Continue(input)`
  or `Before::Respond(response)`; `.after(..)` gets the output and returns
  `After::Continue(output)`. Hooks run for HTTP and server API callers alike. Hooking an
  endpoint nothing registered (`SignUpEmail` without `.email_password(..)`) is a
  `BuildError`.
- `.on(|e: Event, ctx| ..)` runs after the endpoint that emitted the event succeeds. Its
  error is logged and doesn't fail the request. Core events, all in the prelude:
  `UserCreated { user_id, email }`, `UserUpdated`, `SessionCreated`, `SessionRevoked`,
  `PasswordChanged`, `EmailVerified`, `AccountLinked`. Two-factor adds `TwoFactorEnabled`
  and `TwoFactorDisabled`.
- To stop a sign-in for every method (bans, forced resets), write a sign-in gate in a
  plugin ([custom-plugins.md](custom-plugins.md#gates)); a hook on `SignInEmail` misses social
  sign-in.

## Email

Verification, password reset and two-factor codes go through `.mailer(..)`. `LogMailer`
logs them (development), `MemoryMailer` keeps them (tests), and anything else implements
`Mailer` (the `ConsoleMailer` at the end of the sample above). `AuthEmail::default_text`
gives a plain subject and body; match on `AuthEmail::VerifyEmail`, `ResetPassword` and
`Plugin` for templates. `require_email_verification(true)` without a mailer is a
`BuildError`.
