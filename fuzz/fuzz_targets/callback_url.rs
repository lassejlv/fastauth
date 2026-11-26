//! CoreConfig::is_safe_redirect, the check behind callbackURL, newUserCallbackURL,
//! errorCallbackURL and redirectTo. Whatever it accepts must land on the app's origin or a
//! trusted origin when a browser resolves it against the app's URL (WHATWG URL parsing, as
//! the url crate does it).

#![no_main]

use fastauth_fuzz::{BASE_URL, FIXTURE, TRUSTED};
use libfuzzer_sys::fuzz_target;
use url::Url;

fuzz_target!(|target: &str| {
    let config = FIXTURE.auth.config();
    if !config.is_safe_redirect(target) {
        return;
    }
    let base = Url::parse(BASE_URL).unwrap();
    let Ok(resolved) = base.join(target) else {
        return;
    };
    let origin = resolved.origin().ascii_serialization();
    assert!(
        origin == base.origin().ascii_serialization() || origin == TRUSTED,
        "is_safe_redirect accepted {target:?}, which resolves to {resolved}"
    );
});
