//! The fullstack example's server: everything but `main`, so the `fastauth` binary in
//! `src/bin/fastauth.rs` builds the same auth instance as the server.

pub mod auth;
pub mod config;
pub mod mailer;
pub mod routes;
