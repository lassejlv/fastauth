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
//! It listens on `PORT` (default 3000). The database is `fastauth-example.db` in the working
//! directory; tables are created on start. Built with the `mysql` feature too, it runs on the
//! MySQL database at `DATABASE_URL` when that is set.

use std::error::Error;
use std::net::SocketAddr;

use axum::routing::get;
use axum::{Json, Router};
use fastauth::adapter::Adapter;
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

pub type AppAuth<D = Sqlx<Sqlite>> =
    Auth<D, Profile, plugins![TwoFactor, Organization, Admin, ApiKeys]>;

fn build<D: Adapter>(db: D, port: &str) -> Result<AppAuth<D>, BuildError> {
    let secret = Secret::from_env("FASTAUTH_SECRET")
        .unwrap_or_else(|_| Secret::from_base64(&Secret::generate()));
    FastAuth::builder()
        .app_name("Acme")
        .secret(secret)
        .base_url(format!("http://localhost:{port}"))
        .database(db)
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

async fn me<D: Adapter>(session: Session<AppAuth<D>>) -> Json<Me> {
    let two_factor: &TwoFactorUser = session.user.plugin::<TwoFactor, _>();
    Json(Me {
        email: session.user.email.clone(),
        plan: session.user.fields.plan.clone(),
        two_factor: two_factor.two_factor_enabled,
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_owned());
    #[cfg(feature = "mysql")]
    if let Ok(url) = std::env::var("DATABASE_URL") {
        let pool = MySqlPool::connect(&url).await?;
        return serve(build(Sqlx::new(pool), &port)?, &port).await;
    }
    let pool = SqlitePool::connect("sqlite://fastauth-example.db?mode=rwc").await?;
    serve(build(Sqlx::new(pool), &port)?, &port).await
}

async fn serve<D: Adapter>(auth: AppAuth<D>, port: &str) -> Result<(), Box<dyn Error>> {
    let plan = auth.migrator().run().await?;
    println!("migrations: {} steps", plan.steps.len());

    let app = Router::new()
        .route("/me", get(me::<D>))
        .merge(auth.router())
        .layer(auth.session_layer())
        .with_state(auth);

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}")).await?;
    println!("listening on http://localhost:{port}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
