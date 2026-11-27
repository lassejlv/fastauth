//! The fastauth app's config, the counterpart of `better-auth/app.config.ts`. Keep the two in
//! step: the same cookie prefix, session lifetime and refresh age, and the same app fields.
//!
//! The suite runs it in two shapes. [`App`] is the app as it starts the cutover. [`WithAdmin`]
//! adds the admin plugin, the way a later fastauth upgrade adds columns: its migrations go
//! through `fastauth generate` and review like the first four.
//!
//! OAuth tokens are stored as plain text, as Better Auth stores them
//! (`store_oauth_tokens_in_plaintext`), so its `/get-access-token` works after a sign-in here.
//! `FASTAUTH_PLAINTEXT_TOKENS=0` keeps fastauth's default, encrypted tokens, for the instance
//! that shows the gap that leaves.

use fastauth::plugins::admin::Admin;
use fastauth::plugins::email_otp::EmailOtp;
use fastauth::plugins::magic_link::MagicLink;
use fastauth::prelude::*;
use fastauth::social::Social;
use serde::Serialize;
use time::Duration;

use crate::mock_provider::MockProvider;
use crate::outbox::Outbox;

/// The Better Auth app's `user.additionalFields.customerId`: written by the app's own code,
/// never by a client.
#[derive(Fields, Serialize, Clone, Debug)]
pub struct Customer {
    pub customer_id: Option<String>,
}

pub type App = Auth<Sqlx<Postgres>, Customer, plugins![Social, MagicLink, EmailOtp]>;
pub type WithAdmin = Auth<Sqlx<Postgres>, Customer, plugins![Social, MagicLink, EmailOtp, Admin]>;

/// Everything both shapes share. A macro because each `.plugin(..)` changes the builder's
/// type.
macro_rules! builder {
    ($pool:expr) => {{
        let env = |var: &str| {
            std::env::var(var).map_err(|_| BuildError::new(format!("`{var}` is not set")))
        };
        let social = Social::new().provider(MockProvider::new(env("MOCK_OAUTH_URL")?));
        FastAuth::builder()
            .app_name("vt")
            .secret(Secret::from_env("FASTAUTH_SECRET")?)
            .base_url(env("FASTAUTH_URL")?)
            .client_ip(ClientIp::TrustedProxies {
                header: "x-forwarded-for".into(),
                proxies: 1,
            })
            .database(Sqlx::new($pool).rename("verification", "fastauth_verification"))
            .user_fields::<Customer>()
            .mailer(Outbox::new(env("OUTBOX")?))
            .email_password(EmailPassword::default())
            .better_auth_compat(
                BetterAuthCompat::from_env("BETTER_AUTH_SECRET")?
                    .cookie_prefix("vt")
                    .expires_in(Duration::days(14))
                    .update_age(Duration::days(1)),
            )
            .store_oauth_tokens_in_plaintext(
                std::env::var("FASTAUTH_PLAINTEXT_TOKENS").map_or(true, |v| v != "0"),
            )
            .plugin(social)
            .plugin(MagicLink::new())
            .plugin(EmailOtp::new())
    }};
}

pub fn app(pool: PgPool) -> Result<App, BuildError> {
    builder!(pool).build()
}

pub fn with_admin(pool: PgPool) -> Result<WithAdmin, BuildError> {
    builder!(pool).plugin(Admin::new()).build()
}
