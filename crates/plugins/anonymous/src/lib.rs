//! Anonymous sign-in for [fastauth](https://github.com/lassejlv/fastauth). The routes, field and
//! JSON match Better Auth's `anonymous` plugin, so its `anonymousClient` works unchanged.
//!
//! `POST /sign-in/anonymous` creates a user with a placeholder email and `is_anonymous: true`
//! and signs them in. When that browser later signs in or up with a real method, the plugin
//! calls [`on_link_account`](Anonymous::on_link_account) with both users, so the app can move
//! data across, and then deletes the anonymous user (unless
//! [`disable_delete_anonymous_user`](Anonymous::disable_delete_anonymous_user) is set).
//! `POST /delete-anonymous-user` lets an anonymous user delete themselves. A guest whose email
//! gets verified (for example by moving to a real address with an email code) stops being
//! anonymous: `is_anonymous` turns false and linking never deletes the account.
//!
//! ```
//! use fastauth_core::prelude::*;
//! use fastauth_plugin_anonymous::{Anonymous, AnonymousExt};
//!
//! let auth: Auth<MemoryAdapter, (), plugins![Anonymous]> = FastAuth::builder()
//!     .secret(Secret::from_bytes(vec![1u8; 32]))
//!     .base_url("http://localhost:3000")
//!     .database(MemoryAdapter::new())
//!     .email_password(EmailPassword::default())
//!     .plugin(Anonymous::new().on_link_account(|link| async move {
//!         println!("{} is now {}", link.anonymous_user.user.id, link.new_user.user.id);
//!         Ok(())
//!     }))
//!     .build()?;
//! let _anonymous = auth.anonymous();
//! # Ok::<(), BuildError>(())
//! ```
//!
//! Without the plugin registered, `auth.anonymous()` doesn't compile:
//!
//! ```compile_fail
//! use fastauth_core::prelude::*;
//! use fastauth_plugin_anonymous::AnonymousExt;
//!
//! let auth: Auth<MemoryAdapter> = FastAuth::builder()
//!     .secret(Secret::from_bytes(vec![1u8; 32]))
//!     .base_url("http://localhost:3000")
//!     .database(MemoryAdapter::new())
//!     .build()
//!     .unwrap();
//! let _anonymous = auth.anonymous();
//! ```

mod endpoints;
mod error;
mod model;

use std::future::Future;
use std::pin::Pin;

use fastauth_core::ApiResponse;
use fastauth_core::events::EmailVerified;
use fastauth_core::plugin_prelude::*;

pub use endpoints::{DeleteAnonymousUser, SignInAnonymous, SignInAnonymousOutput, Success};
pub use error::AnonymousError;
pub use model::{AnonymousUser, is_anonymous};

type LinkHook = Arc<
    dyn Fn(LinkAccount) -> Pin<Box<dyn Future<Output = Result<(), AuthError>> + Send>>
        + Send
        + Sync,
>;
type Generator = Arc<dyn Fn() -> String + Send + Sync>;

/// What [`Anonymous::on_link_account`] gets: the anonymous user's session (from the request's
/// cookie) and the session the real sign-in just created.
#[derive(Clone, Debug)]
pub struct LinkAccount {
    pub anonymous_user: SessionView,
    pub new_user: SessionView,
}

/// The anonymous plugin: `.plugin(Anonymous::new())`.
#[derive(Clone, Default)]
pub struct Anonymous {
    email_domain_name: Option<String>,
    generate_name: Option<Generator>,
    generate_random_email: Option<Generator>,
    on_link_account: Option<LinkHook>,
    disable_delete_anonymous_user: bool,
}

impl std::fmt::Debug for Anonymous {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Anonymous")
            .field("email_domain_name", &self.email_domain_name)
            .field(
                "disable_delete_anonymous_user",
                &self.disable_delete_anonymous_user,
            )
            .finish_non_exhaustive()
    }
}

impl Anonymous {
    pub fn new() -> Self {
        Self::default()
    }

    /// Anonymous users get `temp-{id}@{domain}` instead of the default
    /// `{id}@anonymous.placeholder.invalid`.
    pub fn email_domain_name(mut self, domain: impl Into<String>) -> Self {
        self.email_domain_name = Some(domain.into());
        self
    }

    /// Names anonymous users (default `"Anonymous"`). An empty name falls back to the default.
    pub fn generate_name(mut self, generate: impl Fn() -> String + Send + Sync + 'static) -> Self {
        self.generate_name = Some(Arc::new(generate));
        self
    }

    /// Generates anonymous users' emails. It must return a valid, unused address; an invalid
    /// one answers `INVALID_EMAIL_FORMAT`.
    pub fn generate_random_email(
        mut self,
        generate: impl Fn() -> String + Send + Sync + 'static,
    ) -> Self {
        self.generate_random_email = Some(Arc::new(generate));
        self
    }

    /// Runs when a browser signed in anonymously signs in or up with a real method, before
    /// the anonymous user is deleted. Move the anonymous user's data to the new user here.
    /// An error fails that sign-in's response (the new session already exists) and keeps
    /// the anonymous user.
    pub fn on_link_account<F, Fut>(mut self, hook: F) -> Self
    where
        F: Fn(LinkAccount) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), AuthError>> + Send + 'static,
    {
        self.on_link_account = Some(Arc::new(move |link| Box::pin(hook(link))));
        self
    }

    /// Keeps anonymous users after they link a real account, and turns
    /// `/delete-anonymous-user` off.
    pub fn disable_delete_anonymous_user(mut self, disable: bool) -> Self {
        self.disable_delete_anonymous_user = disable;
        self
    }
}

impl Plugin for Anonymous {
    const ID: &'static str = "anonymous";
    type Requires = ();
    type UserFields = AnonymousUser;
    type SessionFields = ();

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        app.endpoint(SignInAnonymous(self.clone()))
            .endpoint(DeleteAnonymousUser(self.clone()))
            .errors::<AnonymousError>();
        let plugin = self.clone();
        app.on_session_created(move |ctx, session| {
            let plugin = plugin.clone();
            async move { endpoints::link(&plugin, ctx, session).await }
        });
        app.on(|verified: EmailVerified, ctx: Ctx<D>| async move {
            ctx.db()
                .update::<User>(
                    User::ID
                        .eq(&verified.user_id)
                        .and(AnonymousUser::IS_ANONYMOUS.eq(true)),
                )
                .set(AnonymousUser::IS_ANONYMOUS, false)
                .exec()
                .await?;
            Ok(())
        });
    }
}

/// `auth.anonymous()`: the server API. Only compiles on an `Auth` with `Anonymous` registered.
pub trait AnonymousExt: AuthInstance + Sized {
    fn anonymous<I>(&self) -> AnonymousApi<'_, Self>
    where
        Self: HasPlugin<Anonymous, I>,
    {
        AnonymousApi {
            auth: self,
            plugin: self.plugin_arc().clone(),
        }
    }
}

impl<A: AuthInstance> AnonymousExt for A {}

/// Calls the anonymous endpoints without HTTP. `headers` are the request's: their cookies
/// carry the current session.
pub struct AnonymousApi<'a, A> {
    auth: &'a A,
    plugin: Arc<Anonymous>,
}

impl<A: AuthInstance> AnonymousApi<'_, A> {
    /// `POST /sign-in/anonymous`. The response's cookies carry the new session.
    pub async fn sign_in(
        &self,
        headers: &HeaderMap,
    ) -> Result<ApiResponse<SignInAnonymousOutput>, AuthError> {
        self.auth
            .api()
            .headers(headers)
            .call(&SignInAnonymous(self.plugin.clone()), Empty {})
            .await
    }

    /// `POST /delete-anonymous-user`.
    pub async fn delete_user(
        &self,
        headers: &HeaderMap,
    ) -> Result<ApiResponse<Success>, AuthError> {
        self.auth
            .api()
            .headers(headers)
            .call(&DeleteAnonymousUser(self.plugin.clone()), Empty {})
            .await
    }
}
