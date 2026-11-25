//! A complete app: SQLite through sqlx, axum, app fields on the user, two-factor,
//! organizations, admin and API keys.
//!
//! ```bash
//! cargo run -p fastauth --example axum_sqlite --features sqlite,two-factor,organization,admin,api-key
//!
//! curl -i -c jar -X POST localhost:3000/api/auth/sign-up/email \
//!   -H 'content-type: application/json' -H 'origin: http://localhost:3000' \
//!   -d '{"email":"lasse@acme.dk","password":"correct horse battery","name":"Lasse","plan":"pro"}'
//! curl -b jar localhost:3000/me
//! ```
//!
//! The database is `fastauth-example.db` in the working directory; tables are created on start.

use std::net::SocketAddr;

use axum::routing::get;
use axum::{Json, Router};
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

fn build(pool: SqlitePool) -> Result<AppAuth, BuildError> {
    let secret = Secret::from_env("FASTAUTH_SECRET")
        .unwrap_or_else(|_| Secret::from_base64(&Secret::generate()));
    FastAuth::builder()
        .app_name("Acme")
        .secret(secret)
        .base_url("http://localhost:3000")
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

async fn me(session: Session<AppAuth>) -> Json<Me> {
    let two_factor: &TwoFactorUser = session.user.plugin::<TwoFactor, _>();
    Json(Me {
        email: session.user.email.clone(),
        plan: session.user.fields.plan.clone(),
        two_factor: two_factor.two_factor_enabled,
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let pool = SqlitePool::connect("sqlite://fastauth-example.db?mode=rwc").await?;
    let auth = build(pool)?;
    let plan = auth.migrator().run().await?;
    println!("migrations: {} steps", plan.steps.len());

    let app = Router::new()
        .route("/me", get(me))
        .merge(auth.router())
        .layer(auth.session_layer())
        .with_state(auth);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("listening on http://localhost:3000");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
