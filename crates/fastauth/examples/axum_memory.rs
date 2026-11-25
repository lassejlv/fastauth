//! The quickstart (docs/02-quickstart.md) on the in-memory adapter: sign up, `/me`, sign out.
//!
//! ```bash
//! cargo run -p fastauth --example axum_memory
//!
//! curl -i -c jar -X POST localhost:3000/api/auth/sign-up/email \
//!   -H 'content-type: application/json' -H 'origin: http://localhost:3000' \
//!   -d '{"email":"lasse@acme.dk","password":"correct horse battery","name":"Lasse"}'
//! curl -b jar localhost:3000/me
//! curl -b jar -c jar -X POST localhost:3000/api/auth/sign-out -H 'origin: http://localhost:3000'
//! ```
//!
//! Set `FASTAUTH_SECRET` to keep sessions across restarts; without it every start
//! generates a new secret (the data is in memory anyway).

use std::net::SocketAddr;

use axum::routing::get;
use axum::{Json, Router};
use fastauth::axum::Session;
use fastauth::prelude::*;
use serde::Serialize;

type AppAuth = Auth<MemoryAdapter>;

fn build() -> Result<AppAuth, BuildError> {
    let secret = Secret::from_env("FASTAUTH_SECRET")
        .unwrap_or_else(|_| Secret::from_base64(&Secret::generate()));
    FastAuth::builder()
        .secret(secret)
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default())
        .mailer(LogMailer)
        .build()
}

#[derive(Serialize)]
struct Me {
    id: String,
    email: String,
}

async fn me(session: Session<AppAuth>) -> Json<Me> {
    Json(Me {
        id: session.user.id.to_string(),
        email: session.user.email.clone(),
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let auth = build()?;

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
