//! Events fire after an endpoint succeeds, for every caller (HTTP, server API, plugins).
//! Server API calls made with `Api::within` defer them to a [`DeferredEvents`] queue.

use std::sync::{Arc, Mutex};

use crate::endpoint::BoxFuture;
use crate::value::Id;

pub(crate) type Dispatch = Box<dyn FnOnce() -> BoxFuture<'static, ()> + Send>;

/// Events from server API calls, held back until the caller fires them after its own
/// commit. Clones share one queue; dropping the last one discards the events.
#[derive(Clone, Default)]
pub struct DeferredEvents(Arc<Mutex<Vec<Dispatch>>>);

impl std::fmt::Debug for DeferredEvents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("DeferredEvents")
            .field(&self.0.lock().unwrap().len())
            .finish()
    }
}

impl DeferredEvents {
    pub(crate) fn push(&self, dispatch: Dispatch) {
        self.0.lock().unwrap().push(dispatch);
    }

    /// Runs the handlers of every queued event, in the order the calls emitted them, and
    /// empties the queue.
    pub async fn fire(&self) {
        let queued = std::mem::take(&mut *self.0.lock().unwrap());
        for dispatch in queued {
            dispatch().await;
        }
    }
}

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

/// Emitted after a user and their sessions and accounts are deleted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserDeleted {
    pub user_id: Id,
    pub email: String,
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

/// Emitted when proof of an email (a magic link, an email code, a verified social profile)
/// claimed a user whose email wasn't verified: the accounts and sessions it collected before
/// the proof are gone. Plugins that keep sign-in credentials of their own, such as passkeys,
/// delete them on this event, so whoever registered the address first keeps no way in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserClaimed {
    pub user_id: Id,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountLinked {
    pub user_id: Id,
    pub provider_id: String,
}

impl Event for UserCreated {}
impl Event for UserUpdated {}
impl Event for UserDeleted {}
impl Event for SessionCreated {}
impl Event for SessionRevoked {}
impl Event for PasswordChanged {}
impl Event for EmailVerified {}
impl Event for UserClaimed {}
impl Event for AccountLinked {}
