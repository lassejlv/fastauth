//! The server `compat/better-auth/run-organization.sh` points Better Auth's
//! `organizationClient` at: email and password plus the organization plugin, in memory, on
//! localhost:$PORT (3000 by default).
//!
//! ```bash
//! cargo run -p fastauth-plugin-organization --example compat_server --features axum
//! ```

use std::net::SocketAddr;

use axum::Router;
use fastauth_axum::AuthRouter;
use fastauth_core::prelude::*;
use fastauth_plugin_organization::Organization;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_owned());
    let auth: Auth<MemoryAdapter, (), plugins![Organization]> = FastAuth::builder()
        .app_name("Acme")
        .secret(Secret::from_base64(&Secret::generate()))
        .base_url(format!("http://localhost:{port}"))
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default())
        .rate_limit(RateLimit::disabled())
        .plugin(Organization::default())
        .build()?;
    let app = Router::new()
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
