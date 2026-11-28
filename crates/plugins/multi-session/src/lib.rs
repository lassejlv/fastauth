//! Several signed-in accounts per browser for [fastauth](https://github.com/lassejlv/fastauth).
//! The routes, cookies and JSON match Better Auth's `multiSession` plugin, so its
//! `multiSessionClient` works unchanged.
//!
//! Every session created in a browser is also remembered in a signed device-session cookie,
//! `{prefix}.session_token_multi-{token in lowercase}`, up to
//! [`maximum_sessions`](MultiSession::maximum_sessions) accounts. The session cookie stays
//! the active account; the plugin serves:
//!
//! - `GET /multi-session/list-device-sessions`: one `{ session, user }` per account.
//! - `POST /multi-session/set-active`: makes another remembered session the active one.
//! - `POST /multi-session/revoke`: signs one account out; revoking the active one switches to
//!   the next remembered session.
//!
//! Signing in again as an account the browser already holds replaces its older session, and
//! `/sign-out` signs every remembered account out.
//!
//! ```
//! use fastauth_core::prelude::*;
//! use fastauth_plugin_multi_session::{MultiSession, MultiSessionExt};
//!
//! let auth: Auth<MemoryAdapter, (), plugins![MultiSession]> = FastAuth::builder()
//!     .secret(Secret::from_bytes(vec![1u8; 32]))
//!     .base_url("http://localhost:3000")
//!     .database(MemoryAdapter::new())
//!     .email_password(EmailPassword::default())
//!     .plugin(MultiSession::new().maximum_sessions(3))
//!     .build()?;
//! let _multi_session = auth.multi_session();
//! # Ok::<(), BuildError>(())
//! ```
//!
//! Without the plugin registered, `auth.multi_session()` doesn't compile:
//!
//! ```compile_fail
//! use fastauth_core::prelude::*;
//! use fastauth_plugin_multi_session::MultiSessionExt;
//!
//! let auth: Auth<MemoryAdapter> = FastAuth::builder()
//!     .secret(Secret::from_bytes(vec![1u8; 32]))
//!     .base_url("http://localhost:3000")
//!     .database(MemoryAdapter::new())
//!     .build()
//!     .unwrap();
//! let _multi_session = auth.multi_session();
//! ```

mod endpoints;
mod error;

use fastauth_core::ApiResponse;
use fastauth_core::plugin_prelude::*;
use fastauth_core::routes::{SignOut, Status};
use serde_json::Value as Json;

pub use endpoints::{ListDeviceSessions, RevokeDeviceSession, SessionTokenInput, SetActiveSession};
pub use error::MultiSessionError;

/// The multi-session plugin: `.plugin(MultiSession::new())`.
#[derive(Clone, Debug)]
pub struct MultiSession {
    maximum_sessions: usize,
}

impl Default for MultiSession {
    fn default() -> Self {
        Self {
            maximum_sessions: 5,
        }
    }
}

impl MultiSession {
    pub fn new() -> Self {
        Self::default()
    }

    /// How many accounts one browser remembers (default 5). A sign-in beyond it still
    /// signs in, but the new session isn't remembered next to the others.
    pub fn maximum_sessions(mut self, maximum: usize) -> Self {
        self.maximum_sessions = maximum;
        self
    }
}

impl Plugin for MultiSession {
    const ID: &'static str = "multi-session";
    type Requires = ();
    type UserFields = ();
    type SessionFields = ();

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        app.endpoint(ListDeviceSessions)
            .endpoint(SetActiveSession)
            .endpoint(RevokeDeviceSession)
            .errors::<MultiSessionError>();
        let plugin = self.clone();
        app.on_session_created(move |ctx, session| {
            let plugin = plugin.clone();
            async move { endpoints::remember(&plugin, ctx, session).await }
        });
        app.hook::<SignOut>().after(|ctx, output| async move {
            endpoints::sign_out_all(&ctx).await?;
            Ok(After::Continue(output))
        });
    }
}

/// `auth.multi_session()`: the server API. Only compiles on an `Auth` with `MultiSession`
/// registered.
pub trait MultiSessionExt: AuthInstance + Sized {
    fn multi_session<I>(&self) -> MultiSessionApi<'_, Self>
    where
        Self: HasPlugin<MultiSession, I>,
    {
        MultiSessionApi { auth: self }
    }
}

impl<A: AuthInstance> MultiSessionExt for A {}

/// Calls the multi-session endpoints without HTTP. `headers` are the browser's request
/// headers: the device-session cookies live there.
pub struct MultiSessionApi<'a, A> {
    auth: &'a A,
}

impl<A: AuthInstance> MultiSessionApi<'_, A> {
    /// `GET /multi-session/list-device-sessions`: `[{ session, user }]`.
    pub async fn list_device_sessions(
        &self,
        headers: &HeaderMap,
    ) -> Result<ApiResponse<Vec<Json>>, AuthError> {
        self.auth
            .api()
            .headers(headers)
            .call(&ListDeviceSessions, Default::default())
            .await
    }

    /// `POST /multi-session/set-active`. The response's cookies switch the active session.
    pub async fn set_active(
        &self,
        headers: &HeaderMap,
        session_token: impl Into<String>,
    ) -> Result<ApiResponse<Json>, AuthError> {
        self.auth
            .api()
            .headers(headers)
            .call(
                &SetActiveSession,
                SessionTokenInput {
                    session_token: session_token.into(),
                },
            )
            .await
    }

    /// `POST /multi-session/revoke`.
    pub async fn revoke(
        &self,
        headers: &HeaderMap,
        session_token: impl Into<String>,
    ) -> Result<ApiResponse<Status>, AuthError> {
        self.auth
            .api()
            .headers(headers)
            .call(
                &RevokeDeviceSession,
                SessionTokenInput {
                    session_token: session_token.into(),
                },
            )
            .await
    }
}
