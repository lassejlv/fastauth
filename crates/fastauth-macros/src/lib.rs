//! Derive macros for [fastauth](https://github.com/lassejlv/fastauth). Use them through
//! `fastauth` or `fastauth_core` (feature `macros`), which re-export each derive next to the
//! trait it implements.
//!
//! The generated code names `fastauth_core` when the crate depends on it directly, and
//! `fastauth::__private::core` when it only depends on the `fastauth` facade.

use proc_macro::TokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{DeriveInput, parse_macro_input};

mod auth_error;
mod column;

/// Implements `Fields` and `OnTable` for a struct of columns added to an existing table,
/// plus a typed `Col` constant per field (`two_factor_enabled` becomes
/// `TWO_FACTOR_ENABLED`).
///
/// ```
/// use fastauth_core::plugin_prelude::*;
///
/// #[derive(Fields, Clone)]
/// #[fields(table = User)]
/// pub struct TwoFactorUser {
///     #[field(default = false)]
///     pub two_factor_enabled: bool,
/// }
///
/// let _: Where<User> = TwoFactorUser::TWO_FACTOR_ENABLED.eq(true);
/// ```
///
/// `#[fields(table = ..)]` names the model the columns live on, `User` when omitted.
/// Field attributes, all inside `#[field(..)]`:
///
/// - `default = ..`: a bool, integer or string literal, or `now` for timestamps.
/// - `input`: sign-up and update-user bodies may set it. Without it, clients never can.
///   `input = false` spells out the default.
/// - `returned = false`: never serialized to clients.
/// - `unique`, `index`.
/// - `rename = ".."`: the column name, when it differs from the field name.
///
/// `Option<T>` fields are nullable; the column type is `<T as ColumnValue>::TYPE`.
#[proc_macro_derive(Fields, attributes(fields, field))]
pub fn derive_fields(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    column::derive_fields(&input, &core_path())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Implements `Model` and `OnTable<Table = Self>` for a table, plus a typed `Col` constant
/// per field.
///
/// ```
/// use fastauth_core::plugin_prelude::*;
///
/// #[derive(Model, Clone)]
/// #[model(table = "api_key")]
/// pub struct ApiKey {
///     #[model(id)]
///     pub id: Id,
///     #[model(references = User, on_delete = Cascade, index)]
///     pub user_id: Id,
///     #[model(unique, hidden)]
///     pub key_hash: Hash,
///     #[model(default = now)]
///     pub created_at: OffsetDateTime,
/// }
///
/// let _: Where<ApiKey> = ApiKey::KEY_HASH.eq(Hash::sha256("ak_123"));
/// ```
///
/// `#[model(table = "..")]` is required. Field attributes, all inside `#[model(..)]`:
///
/// - `id`: the primary key.
/// - `references = Model`: a foreign key to that model's `id` column, with
///   `on_delete = Cascade | SetNull | Restrict` (default `Restrict`).
/// - `unique`, `index`, `hidden` (never serialized to clients).
/// - `default = ..`: as for `Fields`.
///
/// Every field is a column; `created_at` and `updated_at` are not added for you. Encoding
/// clones each field, so field types must be `Clone`.
#[proc_macro_derive(Model, attributes(model))]
pub fn derive_model(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    column::derive_model(&input, &core_path())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Implements `From<E> for AuthError` and `ErrorCodes` for an enum of plugin errors.
///
/// ```
/// use fastauth_core::plugin_prelude::*;
///
/// #[derive(AuthError, Debug)]
/// #[auth_error(prefix = "API_KEY")]
/// pub enum ApiKeyError {
///     #[auth_error(status = 404, message = "API key not found")]
///     NotFound,
///     #[auth_error(status = 403, message = "scope {scope} is not allowed")]
///     ScopeDenied { scope: String },
/// }
///
/// let err = AuthError::from(ApiKeyError::ScopeDenied { scope: "admin".into() });
/// assert_eq!(err.code(), "API_KEY_SCOPE_DENIED");
/// assert_eq!(err.message(), "scope admin is not allowed");
/// ```
///
/// Each variant's code is the prefix and the variant name in `SCREAMING_SNAKE_CASE`
/// (`API_KEY_NOT_FOUND`); without a prefix it is the variant name alone. Messages can name
/// fields of struct-like variants in `{field}` placeholders, formatted with `Display`.
#[proc_macro_derive(AuthError, attributes(auth_error))]
pub fn derive_auth_error(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    auth_error::derive(&input, &core_path())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

fn core_path() -> TokenStream2 {
    let found = |name: &str| match crate_name(name).ok()? {
        FoundCrate::Itself => Some(format_ident!("{}", name.replace('-', "_"))),
        FoundCrate::Name(name) => Some(format_ident!("{name}")),
    };
    if let Some(core) = found("fastauth-core") {
        return quote!(::#core);
    }
    if let Some(facade) = found("fastauth") {
        return quote!(::#facade::__private::core);
    }
    quote!(::fastauth_core)
}
