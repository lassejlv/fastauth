//! The server `compat/better-auth/run-organization.sh` points Better Auth's
//! `organizationClient` at: email and password plus the organization plugin, in memory, on
//! localhost:3000.
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
    let auth: Auth<MemoryAdapter, (), plugins![Organization]> = FastAuth::builder()
        .app_name("Acme")
        .secret(Secret::from_base64(&Secret::generate()))
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default())
        .rate_limit(RateLimit::disabled())
        .plugin(Organization::default())
        .build()?;
    let app = Router::new()
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
