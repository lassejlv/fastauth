//! Compile-time guarantees of the plugin list, as `compile_fail` doctests.
//!
//! A plugin that isn't registered can't be read:
//!
//! ```compile_fail
//! use fastauth_core::{doctests::*, prelude::*};
//! let auth = app().plugin(A).build().unwrap();
//! let _ = auth.plugin::<B, _>();
//! ```
//!
//! A plugin whose dependency is missing can't be registered:
//!
//! ```compile_fail
//! use fastauth_core::{doctests::*, prelude::*};
//! let _ = app().plugin(B).build();
//! ```
//!
//! Nor can one registered before its dependency:
//!
//! ```compile_fail
//! use fastauth_core::{doctests::*, prelude::*};
//! let _ = app().plugin(B).plugin(A).build();
//! ```
//!
//! The alias must list plugins in registration order:
//!
//! ```compile_fail
//! use fastauth_core::{doctests::*, prelude::*};
//! let _: Auth<MemoryAdapter, (), plugins![B, A]> = app().plugin(A).plugin(B).build().unwrap();
//! ```
//!
//! The correct versions compile:
//!
//! ```
//! use fastauth_core::{doctests::*, prelude::*};
//! let auth: Auth<MemoryAdapter, (), plugins![A, B]> = app().plugin(A).plugin(B).build().unwrap();
//! let _: &B = auth.plugin::<B, _>();
//! ```

use std::sync::Arc;

use crate::adapter::Adapter;
use crate::auth::{Builder, FastAuth, Present};
use crate::memory::MemoryAdapter;
use crate::plugin::{Plugin, PluginBuilder};
use crate::{Nil, crypto::Secret};

pub struct A;
pub struct B;

impl Plugin for A {
    const ID: &'static str = "a";
    type Requires = ();
    type UserFields = ();
    type SessionFields = ();
}

impl Plugin for B {
    const ID: &'static str = "b";
    type Requires = (A,);
    type UserFields = ();
    type SessionFields = ();

    fn init<D: Adapter>(self: &Arc<Self>, _: &mut PluginBuilder<'_, D>) {}
}

pub fn app() -> Builder<MemoryAdapter, (), Nil, Present, Present> {
    FastAuth::builder()
        .secret(Secret::from_bytes(vec![1u8; 32]))
        .base_url("http://localhost")
        .database(MemoryAdapter::new())
}
