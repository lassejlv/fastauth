use std::sync::Arc;

use fastauth_core::crypto::Secret;
use fastauth_core::plugin_prelude::*;
use fastauth_core::prelude::{FastAuth, MemoryAdapter};

#[derive(AuthError, Debug)]
#[auth_error(prefix = "API_KEY")]
enum ApiKeyError {
    #[auth_error(status = 404, message = "API key not found")]
    NotFound,
    #[auth_error(status = 401, message = "API key expired")]
    Expired,
    #[auth_error(
        status = 403,
        message = "scope {scope} is not allowed for {{key}} {key_id} ({scope:?})"
    )]
    ScopeDenied { scope: String, key_id: Id },
}

#[derive(AuthError, Debug)]
enum Plain {
    #[auth_error(status = 418, message = "short and stout")]
    TeaPot,
}

#[test]
fn variants_become_auth_errors() {
    let err = AuthError::from(ApiKeyError::NotFound);
    assert_eq!(err.status(), StatusCode::NOT_FOUND);
    assert_eq!(err.code(), "API_KEY_NOT_FOUND");
    assert_eq!(err.message(), "API key not found");

    let err = AuthError::from(ApiKeyError::Expired);
    assert_eq!(err.status(), StatusCode::UNAUTHORIZED);

    let err: AuthError = ApiKeyError::ScopeDenied {
        scope: "admin".to_owned(),
        key_id: Id::from("k1"),
    }
    .into();
    assert_eq!(err.status(), StatusCode::FORBIDDEN);
    assert_eq!(err.code(), "API_KEY_SCOPE_DENIED");
    assert_eq!(
        err.message(),
        "scope admin is not allowed for {key} k1 (\"admin\")"
    );

    let err = AuthError::from(Plain::TeaPot);
    assert_eq!((err.status().as_u16(), err.code()), (418, "TEA_POT"));
}

#[test]
fn codes_are_listed() {
    assert_eq!(
        ApiKeyError::CODES,
        [
            "API_KEY_NOT_FOUND",
            "API_KEY_EXPIRED",
            "API_KEY_SCOPE_DENIED"
        ]
    );
    assert_eq!(Plain::CODES, ["TEA_POT"]);
}

struct ApiKeys;

impl Plugin for ApiKeys {
    const ID: &'static str = "api-key";
    type Requires = ();
    type UserFields = ();
    type SessionFields = ();

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        app.errors::<ApiKeyError>();
    }
}

struct Impostor;

impl Plugin for Impostor {
    const ID: &'static str = "impostor";
    type Requires = ();
    type UserFields = ();
    type SessionFields = ();

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        app.errors::<ApiKeyError>();
    }
}

#[test]
fn plugins_register_derived_codes() {
    let err = FastAuth::builder()
        .secret(Secret::from_bytes(vec![42u8; 32]))
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .plugin(ApiKeys)
        .plugin(Impostor)
        .build()
        .unwrap_err();
    let clash = "`API_KEY_NOT_FOUND` is registered by both `api-key` and `impostor`";
    assert!(err.problems.iter().any(|p| p.contains(clash)), "{err}");
}
