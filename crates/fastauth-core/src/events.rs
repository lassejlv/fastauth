//! Events fire after an endpoint succeeds, for every caller (HTTP, server API, plugins).

use crate::value::Id;

pub trait Event: Clone + Send + Sync + 'static {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserCreated {
    pub user_id: Id,
    pub email: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserUpdated {
    pub user_id: Id,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionCreated {
    pub session_id: Id,
    pub user_id: Id,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRevoked {
    pub user_id: Id,
    /// `None` when several sessions were revoked at once.
    pub session_id: Option<Id>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswordChanged {
    pub user_id: Id,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmailVerified {
    pub user_id: Id,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountLinked {
    pub user_id: Id,
    pub provider_id: String,
}

impl Event for UserCreated {}
impl Event for UserUpdated {}
impl Event for SessionCreated {}
impl Event for SessionRevoked {}
impl Event for PasswordChanged {}
impl Event for EmailVerified {}
impl Event for AccountLinked {}
