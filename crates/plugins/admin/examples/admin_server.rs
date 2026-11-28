//! A server for Better Auth's `adminClient`: email and password, the admin plugin, and an
//! admin account, in memory.
//!
//! ```bash
//! cargo run -p fastauth-plugin-admin --example admin_server --features axum
//! ```
//!
//! It listens on `PORT` (default 3000). Sign in as `admin@acme.dk` / `correct horse battery` for an admin session; `/admin-only` answers
//! only admins. `tests/compat/better-auth/run-admin.sh` drives it with the TypeScript client.

use std::net::SocketAddr;

use axum::Router;
use axum::routing::get;
use fastauth_axum::AuthRouter;
use fastauth_core::prelude::*;
use fastauth_plugin_admin::{Admin, AdminExt, CreateUserInput, RequireRole, role};

type AppAuth = Auth<MemoryAdapter, (), plugins![Admin]>;

async fn admin_only(admin: RequireRole<AppAuth, role::Admin>) -> String {
    format!("hello admin {}", admin.user.email)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_owned());
    let auth: AppAuth = FastAuth::builder()
        .secret(Secret::from_bytes(vec![7u8; 32]))
        .base_url(format!("http://localhost:{port}"))
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default())
        .rate_limit(RateLimit::disabled())
        .plugin(Admin::new())
        .build()?;
    auth.admin()
        .create_user(CreateUserInput {
            email: "admin@acme.dk".into(),
            password: Some("correct horse battery".into()),
            name: "Admin".into(),
            role: Some("admin".into()),
            ..CreateUserInput::default()
        })
        .await?;

    let app = Router::new()
        .route("/admin-only", get(admin_only))
        .merge(auth.router())
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
