use fastauth::plugins::admin::Admin;
use fastauth::plugins::api_key::ApiKeys;
use fastauth::plugins::organization::{Organization, Permission, Roles};
use fastauth::plugins::passkey::Passkey;
use fastauth::plugins::two_factor::TwoFactor;
use fastauth::prelude::*;
use fastauth::social::{Github, Social};

use crate::config::Config;
use crate::mailer::OutboxMailer;

/// The whole auth configuration as one type. The plugin list is in registration order.
pub type AppAuth =
    Auth<Sqlx<Postgres>, (), plugins![Social, TwoFactor, Passkey, Organization, Admin, ApiKeys]>;

pub fn build(config: &Config, pool: PgPool) -> Result<AppAuth, BuildError> {
    let mut social = Social::new();
    if let Some(github) = &config.github {
        social = social.provider(Github::new(&github.client_id, &github.client_secret));
    }

    FastAuth::builder()
        .app_name("Acme")
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url(&config.app_url)
        .client_ip(client_ip(config.trusted_proxies))
        .database(Sqlx::new(pool))
        .mailer(OutboxMailer::new(&config.outbox))
        .email_password(EmailPassword::default().require_email_verification(true))
        .email_verification(EmailVerification::default().auto_sign_in_after_verification(true))
        .plugin(social)
        .plugin(TwoFactor::new().issuer("Acme"))
        .plugin(Passkey::new().rp_name("Acme"))
        .plugin(
            Organization::default()
                .roles(roles())
                .invitation_url(format!("{}/accept-invitation/{{id}}", config.app_url)),
        )
        .plugin(Admin::new())
        .plugin(ApiKeys::new().default_prefix("acme_").sessions(true))
        .build()
}

/// Rate limits key on the client IP. Directly on the internet the socket address is the
/// client; behind proxies that append to `x-forwarded-for` (nginx, a load balancer, Vite's
/// dev proxy) the client is the address those proxies added, counted from the right.
fn client_ip(trusted_proxies: usize) -> ClientIp {
    match trusted_proxies {
        0 => ClientIp::Socket,
        proxies => ClientIp::TrustedProxies {
            header: "x-forwarded-for".into(),
            proxies,
        },
    }
}

/// The built-in owner, admin and member roles, plus the app's own `project` resource.
fn roles() -> Roles {
    Roles::new()
        .grant("owner", [("project", &["read", "create", "delete"])])
        .grant("admin", [("project", &["read", "create", "delete"])])
        .grant("member", [("project", &["read"])])
}

/// `project:create`, checked by `RequirePermission<AppAuth, ProjectCreate, _>`.
pub struct ProjectCreate;

impl Permission for ProjectCreate {
    const RESOURCE: &'static str = "project";
    const ACTIONS: &'static [&'static str] = &["create"];
}
