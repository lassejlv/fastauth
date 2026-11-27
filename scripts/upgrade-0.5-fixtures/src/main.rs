//! Seeds a fastauth 0.5.0 database through 0.5's own HTTP API and migrator, for the 0.5 to
//! 0.6 upgrade test. generate.sh runs it once per backend, dumps the database to
//! crates/fastauth/tests/fixtures/upgrade_0_5/<backend>.sql and keeps the manifest it prints
//! (passwords, cookies, tokens and ids the test needs) as manifest.json.
//!
//! Usage: upgrade-0-5-fixtures <sqlite|postgres|mysql> <database url>

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use axum::body::Bytes;
use axum::http::{Request, header};
use fastauth::adapter::Adapter;
use fastauth::crypto::Argon2id;
use fastauth::mail::{AuthEmail, MemoryMailer};
use fastauth::models::{Account, Session, Verification};
use fastauth::plugins::admin::Admin;
use fastauth::plugins::anonymous::Anonymous;
use fastauth::plugins::api_key::{ApiKey, ApiKeys};
use fastauth::plugins::bearer::Bearer;
use fastauth::plugins::email_otp::EmailOtp;
use fastauth::plugins::jwt::Jwt;
use fastauth::plugins::magic_link::MagicLink;
use fastauth::plugins::multi_session::MultiSession;
use fastauth::plugins::organization::{Invitation, Organization};
use fastauth::plugins::passkey::Passkey;
use fastauth::plugins::two_factor::TwoFactor;
use fastauth::plugins::username::Username;
use fastauth::prelude::*;
use fastauth::query::Where;
use fastauth::value::Value;
use serde_json::{Value as Json, json};
use time::macros::datetime;

/// Shared with the 0.6 test, which must decrypt and verify what 0.5 wrote.
const SECRET: &str = "upgrade-fixture-secret-0.5-to-0.6-do-not-use-anywhere-else-7f3c9a";
const ORIGIN: &str = "http://localhost:3000";
const PASSWORD: &str = "correct horse battery staple";

type Everything = plugins![
    TwoFactor,
    Organization,
    Admin,
    ApiKeys,
    MagicLink,
    EmailOtp,
    Bearer,
    Jwt,
    Passkey,
    Username,
    Anonymous,
    MultiSession,
];

fn build<D: Adapter>(db: D, mail: MemoryMailer) -> Result<Auth<D, (), Everything>> {
    Ok(FastAuth::builder()
        .secret(Secret::from_bytes(SECRET.as_bytes().to_vec()))
        .base_url(ORIGIN)
        .database(db)
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .mailer(mail)
        .plugin(TwoFactor::new().skip_verification_on_enable(true))
        .plugin(Organization::default())
        .plugin(Admin::new())
        .plugin(ApiKeys::new().sessions(true))
        .plugin(MagicLink::new())
        .plugin(EmailOtp::new())
        .plugin(Bearer::new())
        .plugin(Jwt::new())
        .plugin(Passkey::new())
        .plugin(Username::new())
        .plugin(Anonymous::new())
        .plugin(MultiSession::new())
        .build()?)
}

/// A browser: a cookie jar in front of `Auth::handle`.
struct Browser<'a, D: Adapter> {
    auth: &'a Auth<D, (), Everything>,
    jar: Vec<(String, String)>,
}

impl<'a, D: Adapter> Browser<'a, D> {
    fn new(auth: &'a Auth<D, (), Everything>) -> Self {
        Self {
            auth,
            jar: Vec::new(),
        }
    }

    fn cookie_header(&self) -> String {
        self.jar
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }

    async fn send(&mut self, method: &str, path: &str, body: Option<Json>) -> Result<Json> {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("/api/auth{path}"))
            .header(header::ORIGIN, ORIGIN)
            .header(header::CONTENT_TYPE, "application/json");
        if !self.jar.is_empty() {
            builder = builder.header(header::COOKIE, self.cookie_header());
        }
        let body = body.map(|b| Bytes::from(b.to_string())).unwrap_or_default();
        let response = self.auth.handle(builder.body(body)?).await;
        for cookie in response.headers().get_all(header::SET_COOKIE) {
            let cookie = cookie.to_str()?;
            let (pair, attrs) = cookie.split_once(';').unwrap_or((cookie, ""));
            let (name, value) = pair.split_once('=').context("cookie")?;
            self.jar.retain(|(k, _)| k != name);
            if !attrs.contains("Max-Age=0") {
                self.jar.push((name.to_owned(), value.to_owned()));
            }
        }
        let status = response.status().as_u16();
        let json: Json = serde_json::from_slice(response.body()).unwrap_or(Json::Null);
        if status >= 400 {
            bail!("{method} {path} answered {status}: {json}");
        }
        Ok(json)
    }

    async fn post(&mut self, path: &str, body: Json) -> Result<Json> {
        self.send("POST", path, Some(body)).await
    }

    /// The jar's session token cookie, as a browser would send it.
    fn session_cookie(&self) -> Result<String> {
        self.jar
            .iter()
            .find(|(k, _)| k.ends_with("session_token"))
            .map(|(k, v)| format!("{k}={v}"))
            .context("no session cookie")
    }
}

fn last_mail(mail: &MemoryMailer, to: &str) -> Result<AuthEmail> {
    mail.sent()
        .into_iter()
        .rev()
        .find(|m| match m {
            AuthEmail::VerifyEmail(m) => m.to == to,
            AuthEmail::ResetPassword(m) => m.to == to,
            AuthEmail::Plugin(m) => m.to == to,
            _ => false,
        })
        .with_context(|| format!("no mail to {to}"))
}

fn verify_token(mail: &MemoryMailer, to: &str) -> Result<String> {
    match last_mail(mail, to)? {
        AuthEmail::VerifyEmail(m) => Ok(m.token),
        other => bail!("expected a verification mail, got {other:?}"),
    }
}

async fn seed<D: Adapter>(db: D) -> Result<Json> {
    let mail = MemoryMailer::new();
    let auth = build(db, mail.clone())?;
    auth.migrator().run().await?;
    let mut manifest = BTreeMap::<String, Json>::new();
    let sign_up =
        |email: &str, name: &str| json!({"email": email, "name": name, "password": PASSWORD});

    // alice: verified, signed in on two devices, owns the organization, has an API key and a
    // GitHub link.
    let mut alice = Browser::new(&auth);
    let out = alice
        .post("/sign-up/email", sign_up("alice@example.com", "Alice"))
        .await?;
    let alice_id = out["user"]["id"].as_str().context("alice id")?.to_owned();
    let token = verify_token(&mail, "alice@example.com")?;
    alice
        .send("GET", &format!("/verify-email?token={token}"), None)
        .await?;
    let mut alice_phone = Browser::new(&auth);
    alice_phone
        .post(
            "/sign-in/email",
            json!({"email": "alice@example.com", "password": PASSWORD}),
        )
        .await?;
    let org = alice
        .post(
            "/organization/create",
            json!({"name": "Acme", "slug": "acme"}),
        )
        .await?;
    let org_id = org["id"].as_str().context("org id")?.to_owned();
    let key = alice.post("/api-key/create", json!({"name": "ci"})).await?;
    manifest.insert("alice_api_key".into(), key["key"].clone());

    // bob: unverified, with a verification link and a reset link from 0.5 still unused, and a
    // pending invitation.
    let mut bob = Browser::new(&auth);
    let out = bob
        .post("/sign-up/email", sign_up("bob@example.com", "Bob"))
        .await?;
    let bob_id = out["user"]["id"].as_str().context("bob id")?.to_owned();
    manifest.insert(
        "bob_verify_token".into(),
        json!(verify_token(&mail, "bob@example.com")?),
    );
    Browser::new(&auth)
        .post(
            "/request-password-reset",
            json!({"email": "bob@example.com"}),
        )
        .await?;
    let reset = match last_mail(&mail, "bob@example.com")? {
        AuthEmail::ResetPassword(m) => m.token,
        other => bail!("expected a reset mail, got {other:?}"),
    };
    manifest.insert("bob_reset_token".into(), json!(reset));

    // carol and frank: verified, two-factor on, members of the organization.
    let mut two_factor_users = Vec::new();
    for (email, name) in [
        ("carol@example.com", "Carol"),
        ("frank@example.com", "Frank"),
    ] {
        let mut browser = Browser::new(&auth);
        let out = browser.post("/sign-up/email", sign_up(email, name)).await?;
        let id = out["user"]["id"].as_str().context("id")?.to_owned();
        let token = verify_token(&mail, email)?;
        browser
            .send("GET", &format!("/verify-email?token={token}"), None)
            .await?;
        let enabled = browser
            .post("/two-factor/enable", json!({"password": PASSWORD}))
            .await?;
        let invitation = alice
            .post(
                "/organization/invite-member",
                json!({"email": email, "role": "member", "organizationId": org_id}),
            )
            .await?;
        browser
            .post(
                "/organization/accept-invitation",
                json!({"invitationId": invitation["id"]}),
            )
            .await?;
        manifest.insert(
            format!("{name}_backup_codes").to_lowercase(),
            enabled["backupCodes"].clone(),
        );
        two_factor_users.push(id);
    }
    alice
        .post(
            "/organization/invite-member",
            json!({"email": "bob@example.com", "role": "admin", "organizationId": org_id}),
        )
        .await?;

    // dave: signed up with a username. A guest from the anonymous plugin. erin: made by the
    // server API, no password.
    let mut dave = Browser::new(&auth);
    dave.post(
        "/sign-up/email",
        json!({"email": "dave@example.com", "name": "Dave", "password": PASSWORD, "username": "dave_dev"}),
    )
    .await?;
    let mut guest = Browser::new(&auth);
    guest.post("/sign-in/anonymous", json!({})).await?;
    let erin = auth
        .api()
        .create_user(fastauth::routes::CreateUserInput {
            email: "erin@example.com".into(),
            name: "Erin".into(),
            ..Default::default()
        })
        .await?;

    // Social links, as 0.5's OAuth callback stores them.
    let api = auth.api();
    let db = api.db();
    for (user, provider, account) in [
        (alice_id.as_str(), "github", "1001"),
        (two_factor_users[0].as_str(), "google", "g-2002"),
        (erin.id.as_str(), "github", "1005"),
    ] {
        db.insert_row::<Account>(vec![
            ("id", Value::Text(format!("acct-{provider}-{account}"))),
            ("user_id", Value::Text(user.to_owned())),
            ("provider_id", Value::Text(provider.into())),
            ("account_id", Value::Text(account.into())),
            ("scope", Value::Text("read:user".into())),
        ])
        .await?;
    }

    // Nothing expires, so the fixture stays usable: the test decides what is too old.
    let far = Value::Timestamp(datetime!(2099-01-01 0:00 UTC));
    db.update::<Session>(Where::all())
        .set_raw("expires_at", far.clone())
        .exec()
        .await?;
    db.update::<Verification>(Where::all())
        .set_raw("expires_at", far.clone())
        .exec()
        .await?;
    db.update::<Invitation>(Where::all())
        .set_raw("expires_at", far.clone())
        .exec()
        .await?;
    db.update::<ApiKey>(Where::all())
        .set_raw("expires_at", far)
        .exec()
        .await?;

    manifest.insert("secret".into(), json!(SECRET));
    manifest.insert("password".into(), json!(PASSWORD));
    manifest.insert("organization_id".into(), json!(org_id));
    manifest.insert("alice_id".into(), json!(alice_id));
    manifest.insert("bob_id".into(), json!(bob_id));
    manifest.insert("carol_id".into(), json!(two_factor_users[0]));
    manifest.insert("frank_id".into(), json!(two_factor_users[1]));
    manifest.insert(
        "alice_session_cookie".into(),
        json!(alice.session_cookie()?),
    );
    manifest.insert(
        "alice_phone_session_cookie".into(),
        json!(alice_phone.session_cookie()?),
    );
    manifest.insert("bob_session_cookie".into(), json!(bob.session_cookie()?));
    manifest.insert("dave_session_cookie".into(), json!(dave.session_cookie()?));
    manifest.insert(
        "guest_session_cookie".into(),
        json!(guest.session_cookie()?),
    );
    Ok(serde_json::to_value(manifest)?)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let [_, backend, url] = args.as_slice() else {
        bail!("usage: upgrade-0-5-fixtures <sqlite|postgres|mysql> <database url>");
    };
    let manifest = match backend.as_str() {
        "sqlite" => seed(Sqlx::new(SqlitePool::connect(url).await?)).await?,
        "postgres" => seed(Sqlx::new(PgPool::connect(url).await?)).await?,
        "mysql" => seed(Sqlx::new(MySqlPool::connect(url).await?)).await?,
        other => bail!("unknown backend {other}"),
    };
    println!("{}", serde_json::to_string_pretty(&manifest)?);
    Ok(())
}
