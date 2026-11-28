//! The fastauth app of the Better Auth cross-app suite (`tests/compat/better-auth-dual/run-dual.sh`).
//!
//! `serve` runs it on axum at `127.0.0.1:$PORT`; every other command is the app's `fastauth`
//! binary (`status`, `generate`, ...). `FASTAUTH_ADMIN=1` adds the admin plugin to both.

mod auth;
mod mock_provider;
mod outbox;

use std::net::SocketAddr;

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use fastauth::PluginSet;
use fastauth::prelude::*;
use fastauth::query::Db;
use fastauth::value::Value;
use serde::Deserialize;
use serde_json::json;

use crate::auth::Customer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();
    let admin = std::env::var("FASTAUTH_ADMIN").is_ok_and(|v| v == "1");
    if std::env::args().nth(1).as_deref() != Some("serve") {
        return if admin {
            fastauth::cli::run(auth::with_admin).await
        } else {
            fastauth::cli::run(auth::app).await
        };
    }
    let pool = PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
    if admin {
        serve(auth::with_admin(pool)?).await
    } else {
        serve(auth::app(pool)?).await
    }
}

async fn serve<P: PluginSet>(auth: Auth<Sqlx<Postgres>, Customer, P>) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/app/me", get(me::<P>))
        .route("/app/customer-id", post(set_customer_id::<P>))
        .route("/app/provider-token", get(provider_token::<P>))
        .merge(auth.router())
        .layer(auth.session_layer())
        .with_state(auth);
    let port = std::env::var("PORT")?;
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}")).await?;
    println!("listening on 127.0.0.1:{port}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// The app's own read of the signed-in user's tokens from the mock provider, as code that
/// calls the provider's API would: plain text or encrypted, whichever app stored them.
async fn provider_token<P: PluginSet>(
    State(auth): State<Auth<Sqlx<Postgres>, Customer, P>>,
    session: Session<Auth<Sqlx<Postgres>, Customer, P>>,
) -> Result<Json<serde_json::Value>, String> {
    let account = Db::new(auth.adapter(), auth.schema())
        .find::<Account>(
            Account::USER_ID
                .eq(session.user.id.clone())
                .and(Account::PROVIDER_ID.eq(mock_provider::ID)),
        )
        .one()
        .await
        .map_err(|e| e.to_string())?
        .ok_or("no mock account")?;
    Ok(Json(json!({
        "accessToken": account.read_access_token(auth.keys()),
        "refreshToken": account.read_refresh_token(auth.keys()),
    })))
}

/// The app's own read of its field, through the typed `Customer`.
async fn me<P: PluginSet>(
    session: Session<Auth<Sqlx<Postgres>, Customer, P>>,
) -> Json<serde_json::Value> {
    Json(
        json!({ "id": session.user.id.as_str(), "email": session.user.email, "customerId": session.user.fields.customer_id }),
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetCustomerId {
    customer_id: String,
}

/// The app's own write of its field, as billing code would after creating a customer.
async fn set_customer_id<P: PluginSet>(
    State(auth): State<Auth<Sqlx<Postgres>, Customer, P>>,
    session: Session<Auth<Sqlx<Postgres>, Customer, P>>,
    Json(input): Json<SetCustomerId>,
) -> Result<Json<serde_json::Value>, String> {
    Db::new(auth.adapter(), auth.schema())
        .update::<User>(User::ID.eq(session.user.id.clone()))
        .set_raw("customer_id", Value::Text(input.customer_id))
        .exec()
        .await
        .map_err(|e| e.to_string())?;
    Ok(Json(json!({ "ok": true })))
}
