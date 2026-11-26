//! The `axum_sqlite` app on actix-web: SQLite through sqlx, app fields on the user,
//! two-factor, organizations, admin and API keys.
//!
//! ```bash
//! cargo run -p fastauth --example actix_sqlite --no-default-features \
//!   --features actix,sqlite,macros,two-factor,organization,admin,api-key
//!
//! curl -i -c jar -X POST localhost:3000/api/auth/sign-up/email \
//!   -H 'content-type: application/json' -H 'origin: http://localhost:3000' \
//!   -d '{"email":"lasse@acme.dk","password":"correct horse battery","name":"Lasse","plan":"pro"}'
//! curl -b jar localhost:3000/me
//! ```
//!
//! It listens on `PORT` (default 3000). The database is `fastauth-example.db` in the working
//! directory; tables are created on start.

use actix_web::{App, HttpResponse, HttpServer, web};
use fastauth::actix::{AuthScope, Session};
use fastauth::plugins::admin::Admin;
use fastauth::plugins::api_key::ApiKeys;
use fastauth::plugins::organization::Organization;
use fastauth::plugins::two_factor::{TwoFactor, TwoFactorUser};
use fastauth::prelude::*;
use serde::Serialize;

#[derive(Fields, Clone, Debug, Serialize)]
pub struct Profile {
    #[field(default = "free", input)]
    pub plan: String,
}

pub type AppAuth = Auth<Sqlx<Sqlite>, Profile, plugins![TwoFactor, Organization, Admin, ApiKeys]>;

fn build(pool: SqlitePool, port: &str) -> Result<AppAuth, BuildError> {
    let secret = Secret::from_env("FASTAUTH_SECRET")
        .unwrap_or_else(|_| Secret::from_base64(&Secret::generate()));
    FastAuth::builder()
        .app_name("Acme")
        .secret(secret)
        .base_url(format!("http://localhost:{port}"))
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default())
        .mailer(LogMailer)
        .user_fields::<Profile>()
        .plugin(TwoFactor::new().issuer("Acme"))
        .plugin(Organization::default())
        .plugin(Admin::new())
        .plugin(ApiKeys::new().sessions(true))
        .build()
}

#[derive(Serialize)]
struct Me {
    email: String,
    plan: String,
    two_factor: bool,
}

async fn me(session: Session<AppAuth>) -> HttpResponse {
    let two_factor: &TwoFactorUser = session.user.plugin::<TwoFactor, _>();
    HttpResponse::Ok().json(Me {
        email: session.user.email.clone(),
        plan: session.user.fields.plan.clone(),
        two_factor: two_factor.two_factor_enabled,
    })
}

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_owned());
    let pool = SqlitePool::connect("sqlite://fastauth-example.db?mode=rwc").await?;
    let auth = build(pool, &port)?;
    let plan = auth.migrator().run().await?;
    println!("migrations: {} steps", plan.steps.len());

    let server = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(auth.clone()))
            .wrap(auth.session_middleware())
            .service(auth.scope())
            .route("/me", web::get().to(me))
    })
    .bind(("127.0.0.1", port.parse::<u16>()?))?;
    println!("listening on http://localhost:{port}");
    server.run().await?;
    Ok(())
}
