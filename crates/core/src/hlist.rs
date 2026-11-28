//! The type-level plugin list. See `docs/reference/02-internals.md`.

use std::marker::PhantomData;
use std::sync::Arc;

use crate::adapter::Adapter;
use crate::model::Fields;
use crate::plugin::{Plugin, Registry};
use crate::value::{DecodeError, Row};

/// The empty plugin list.
#[derive(Clone, Copy, Debug, Default)]
pub struct Nil;

/// A plugin followed by the rest of the list.
#[derive(Debug)]
pub struct Cons<H, T>(pub(crate) Arc<H>, pub(crate) T);

impl<H, T: Clone> Clone for Cons<H, T> {
    fn clone(&self) -> Self {
        Cons(self.0.clone(), self.1.clone())
    }
}

/// Index: the plugin is the head.
#[derive(Debug)]
pub struct Here;

/// Index: the plugin is in the tail.
#[derive(Debug)]
pub struct There<I>(PhantomData<I>);

/// `plugins![A, B]` is `Cons<A, Cons<B, Nil>>`: the plugin list in registration order.
#[macro_export]
macro_rules! plugins {
    () => { $crate::Nil };
    ($head:ty $(, $tail:ty)* $(,)?) => { $crate::Cons<$head, $crate::plugins![$($tail),*]> };
}

/// Walks the list: registration at build time, decoding on every session load.
pub trait PluginSet: Send + Sync + 'static {
    /// Nested tuple of each plugin's `UserFields`, parallel to the list.
    type UserExt: Clone + Send + Sync + 'static;
    /// Nested tuple of each plugin's `SessionFields`.
    type SessionExt: Clone + Send + Sync + 'static;

    #[doc(hidden)]
    fn register<D: Adapter>(&self, registry: &mut Registry<D>);
    #[doc(hidden)]
    fn decode_user(row: &Row) -> Result<Self::UserExt, DecodeError>;
    #[doc(hidden)]
    fn decode_session(row: &Row) -> Result<Self::SessionExt, DecodeError>;
}

impl PluginSet for Nil {
    type UserExt = ();
    type SessionExt = ();

    fn register<D: Adapter>(&self, _: &mut Registry<D>) {}
    fn decode_user(_: &Row) -> Result<(), DecodeError> {
        Ok(())
    }
    fn decode_session(_: &Row) -> Result<(), DecodeError> {
        Ok(())
    }
}

impl<H: Plugin, T: PluginSet> PluginSet for Cons<H, T> {
    type UserExt = (H::UserFields, T::UserExt);
    type SessionExt = (H::SessionFields, T::SessionExt);

    fn register<D: Adapter>(&self, registry: &mut Registry<D>) {
        registry.register_plugin(&self.0);
        self.1.register(registry);
    }
    fn decode_user(row: &Row) -> Result<Self::UserExt, DecodeError> {
        Ok((H::UserFields::decode(row)?, T::decode_user(row)?))
    }
    fn decode_session(row: &Row) -> Result<Self::SessionExt, DecodeError> {
        Ok((H::SessionFields::decode(row)?, T::decode_session(row)?))
    }
}

#[diagnostic::on_unimplemented(
    message = "plugin `{P}` is not registered on this auth instance",
    label = "`{P}` is not in this plugin list",
    note = "register it with `.plugin(...)` on the builder, before any plugin that requires it, and list it in your `plugins![..]` alias"
)]
pub trait Has<P: Plugin, I>: PluginSet {
    fn get(&self) -> &Arc<P>;
    fn user_ext(ext: &Self::UserExt) -> &P::UserFields;
    fn session_ext(ext: &Self::SessionExt) -> &P::SessionFields;
}

impl<P: Plugin, T: PluginSet> Has<P, Here> for Cons<P, T> {
    fn get(&self) -> &Arc<P> {
        &self.0
    }
    fn user_ext(ext: &Self::UserExt) -> &P::UserFields {
        &ext.0
    }
    fn session_ext(ext: &Self::SessionExt) -> &P::SessionFields {
        &ext.0
    }
}

impl<P: Plugin, H: Plugin, T: Has<P, I>, I> Has<P, There<I>> for Cons<H, T> {
    fn get(&self) -> &Arc<P> {
        self.1.get()
    }
    fn user_ext(ext: &Self::UserExt) -> &P::UserFields {
        T::user_ext(&ext.1)
    }
    fn session_ext(ext: &Self::SessionExt) -> &P::SessionFields {
        T::session_ext(&ext.1)
    }
}

/// A tuple of plugins that must all be in list `L`. Checked by `.plugin(..)`.
pub trait Satisfied<L, I> {}

impl<L> Satisfied<L, ()> for () {}

macro_rules! satisfied {
    ($(($p:ident, $i:ident)),+) => {
        impl<L, $($p: Plugin, $i),+> Satisfied<L, ($($i,)+)> for ($($p,)+) where $(L: Has<$p, $i>),+ {}
    };
}

satisfied!((A, IA));
satisfied!((A, IA), (B, IB));
satisfied!((A, IA), (B, IB), (C, IC));
satisfied!((A, IA), (B, IB), (C, IC), (E, IE));
satisfied!((A, IA), (B, IB), (C, IC), (E, IE), (F, IF));
satisfied!((A, IA), (B, IB), (C, IC), (E, IE), (F, IF), (G, IG));

/// Appends at the end, so the list reads in registration order like `plugins![..]`.
pub trait Append<T> {
    type Out;
    fn append(self, item: Arc<T>) -> Self::Out;
}

impl<T> Append<T> for Nil {
    type Out = Cons<T, Nil>;
    fn append(self, item: Arc<T>) -> Self::Out {
        Cons(item, Nil)
    }
}

impl<H, Tail: Append<T>, T> Append<T> for Cons<H, Tail> {
    type Out = Cons<H, Tail::Out>;
    fn append(self, item: Arc<T>) -> Self::Out {
        Cons(self.0, self.1.append(item))
    }
}
