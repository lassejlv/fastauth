//! normalize_email, which every email route runs first. Must not panic, and what it accepts
//! must already be normalized, short enough, and have a local part and a dotted domain.

#![no_main]

use fastauth_core::routes::normalize_email;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &str| {
    let Ok(email) = normalize_email(input) else {
        return;
    };
    assert!(email.len() <= 254, "{email:?} is longer than 254 bytes");
    let (local, domain) = email.split_once('@').expect("an accepted email has an @");
    assert!(!local.is_empty() && domain.contains('.'), "{email:?}");
    assert_eq!(
        normalize_email(&email).ok().as_deref(),
        Some(email.as_str()),
        "normalizing {input:?} twice changes it"
    );
});
