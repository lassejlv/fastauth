use std::env;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};

/// Everything the server reads from the environment. `.env.example` lists each variable.
#[derive(Clone, Debug)]
pub struct Config {
    /// The origin the browser uses: fastauth's `base_url`, the passkey relying party and the
    /// start of every link in an email.
    pub app_url: String,
    pub port: u16,
    pub database_url: String,
    /// Redis or Valkey that every instance of the server shares, so rate limits hold across
    /// instances. Without it each instance counts on its own, which is right for one.
    pub redis_url: Option<String>,
    /// Where the dev mailer appends one JSON line per email.
    pub outbox: PathBuf,
    /// How many proxies that append to `x-forwarded-for` sit in front of the server. 0 means
    /// clients connect directly and the socket address is the client IP.
    pub trusted_proxies: usize,
    pub github: Option<GithubApp>,
    pub admin: Option<AdminSeed>,
    /// The built React app (`web/dist`). Without it the server serves only the API, and
    /// Vite's dev server serves the app.
    pub web_dist: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct GithubApp {
    pub client_id: String,
    pub client_secret: String,
}

/// The first admin, created on start when no user has this email.
#[derive(Clone, Debug)]
pub struct AdminSeed {
    pub email: String,
    pub password: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let github = match (
            optional("GITHUB_CLIENT_ID"),
            optional("GITHUB_CLIENT_SECRET"),
        ) {
            (Some(client_id), Some(client_secret)) => Some(GithubApp {
                client_id,
                client_secret,
            }),
            (None, None) => None,
            _ => bail!("set both GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET, or neither"),
        };
        let admin = match (optional("ADMIN_EMAIL"), optional("ADMIN_PASSWORD")) {
            (Some(email), Some(password)) => Some(AdminSeed { email, password }),
            (None, None) => None,
            _ => bail!("set both ADMIN_EMAIL and ADMIN_PASSWORD, or neither"),
        };
        Ok(Self {
            app_url: optional("APP_URL").unwrap_or_else(|| "http://localhost:5173".to_owned()),
            port: optional("PORT")
                .map(|port| port.parse().context("PORT must be a port number"))
                .transpose()?
                .unwrap_or(3000),
            database_url: env::var("DATABASE_URL").context("DATABASE_URL is not set")?,
            redis_url: optional("REDIS_URL"),
            outbox: optional("MAIL_OUTBOX")
                .unwrap_or_else(|| "outbox.jsonl".to_owned())
                .into(),
            trusted_proxies: optional("TRUSTED_PROXIES")
                .map(|hops| hops.parse().context("TRUSTED_PROXIES must be a number"))
                .transpose()?
                .unwrap_or(0),
            github,
            admin,
            web_dist: optional("WEB_DIST").map(PathBuf::from),
        })
    }
}

fn optional(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.is_empty())
}
