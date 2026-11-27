//! The core of [fastauth](https://github.com/lassejlv/fastauth): the builder, the type-level
//! plugin list, sessions, crypto, routing and the core endpoints. Apps use the `fastauth`
//! facade crate; adapters, integrations and plugins depend on this one.

pub mod adapter;
mod auth;
pub mod config;
pub mod cookies;
pub mod crypto;
#[doc(hidden)]
pub mod doctests;
pub mod endpoint;
pub mod error;
pub mod events;
mod hlist;
pub mod internal;
pub mod mail;
pub mod memory;
pub mod migrate;
pub mod model;
pub mod models;
pub mod plugin;
pub mod query;
pub mod rate_limit;
pub mod routes;
pub mod schema;
pub mod session;
pub mod storage;
#[cfg(feature = "testing")]
pub mod testing;
pub mod value;

pub use auth::{
    Api, ApiResponse, Auth, AuthInstance, Builder, ClientAddr, FastAuth, HasPlugin, Missing,
    NoDatabase, Present,
};
pub use error::{AuthError, BuildError};
#[cfg(feature = "macros")]
pub use fastauth_macros::{AuthError, Fields, Model};
pub use hlist::{Append, Cons, Has, Here, Nil, PluginSet, Satisfied, There};
pub use time::Duration;

/// Everything an app needs to configure auth.
pub mod prelude {
    pub use crate::config::{
        ClientIp, CookieConfig, EmailPassword, EmailVerification, IdStrategy, SameSite, Secure,
        SessionConfig,
    };
    pub use crate::crypto::Secret;
    pub use crate::events::*;
    pub use crate::mail::{AuthEmail, LogMailer, Mailer, MemoryMailer};
    pub use crate::memory::MemoryAdapter;
    pub use crate::model::Fields;
    pub use crate::models::{Account, Session, User};
    pub use crate::rate_limit::{Limit, RateLimit};
    pub use crate::session::{AuthUser, SessionData};
    pub use crate::value::Id;
    pub use crate::{Auth, AuthError, AuthInstance, BuildError, Duration, FastAuth, plugins};
    #[cfg(feature = "macros")]
    pub use fastauth_macros::Fields;
}

/// Everything a plugin author needs.
pub mod plugin_prelude {
    pub use std::sync::Arc;

    pub use http::{HeaderMap, Method, StatusCode};
    pub use serde::{Deserialize, Serialize};
    pub use time::OffsetDateTime;

    pub use crate::adapter::{Adapter, Order, Transaction};
    pub use crate::crypto::{Hash, random_string, random_token};
    pub use crate::endpoint::BoxFuture;
    pub use crate::endpoint::{
        After, Authenticated, Before, Ctx, Empty, Endpoint, Fresh, Gate, HookCtx,
        MaybeAuthenticated, Public, Resolved, SessionResolver, SessionUse, SignInAttempt,
    };
    pub use crate::error::{AuthError, ErrorCodes, codes};
    pub use crate::events::Event;
    pub use crate::internal::{Claim, NewAccount, NewSession, NewUser, SignInResult, UserInput};
    pub use crate::model::{Col, Fields, Model, OnTable};
    pub use crate::models::{Account, Session, User, Verification};
    pub use crate::plugin::{Plugin, PluginBuilder};
    pub use crate::query::Where;
    pub use crate::rate_limit::Limit;
    pub use crate::schema::{ColumnDef, ColumnType, DefaultValue, OnDelete, SchemaBuilder};
    pub use crate::session::{SessionView, UserView};
    pub use crate::value::{ColumnValue, DecodeError, Id, Json, Row, Value};
    pub use crate::{AuthInstance, Duration, HasPlugin};
    #[cfg(feature = "macros")]
    pub use fastauth_macros::{AuthError, Fields, Model};
}
