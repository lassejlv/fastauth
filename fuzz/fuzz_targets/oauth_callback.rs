//! The OAuth callback (`/callback/{provider}`): a fuzzed query (`code`, `state`, `error`
//! and junk), a fuzzed or missing state cookie, and fuzzed provider answers (token and
//! userinfo JSON). It always answers a redirect to the app's origin or a trusted one, never a
//! 500, and only signs in when the state and its cookie are the ones this browser started.

#![no_main]

use arbitrary::Arbitrary;
use fastauth_core::crypto::{Argon2id, Secret};
use fastauth_core::prelude::*;
use fastauth_fuzz::client::Client;
use fastauth_fuzz::mock_http::{GOOGLE_TOKEN, GOOGLE_USERINFO, MockHttp};
use fastauth_fuzz::{BASE_URL, SECRET, TRUSTED};
use fastauth_oauth::{Google, Social};
use http::StatusCode;
use libfuzzer_sys::fuzz_target;
use serde_json::json;
use url::Url;

type SocialAuth = Auth<MemoryAdapter, (), plugins![Social]>;

#[derive(Arbitrary, Debug)]
enum Part {
    Absent,
    Real,
    Fuzz(String),
    RealPlus(String),
}

#[derive(Arbitrary, Debug)]
enum StateCookie {
    Real,
    Absent,
    Fuzz(String),
    RealPlus(String),
}

#[derive(Arbitrary, Debug)]
struct Input {
    code: Part,
    state: Part,
    error: Option<String>,
    extra: String,
    cookie: StateCookie,
    provider: u8,
    token_answer: Option<(u16, Vec<u8>)>,
    userinfo_answer: Option<(u16, Vec<u8>)>,
    callback_url: Option<String>,
}

fn part(part: &Part, real: &str) -> Option<String> {
    match part {
        Part::Absent => None,
        Part::Real => Some(real.to_owned()),
        Part::Fuzz(s) => Some(s.clone()),
        Part::RealPlus(s) => Some(format!("{real}{s}")),
    }
}

fn is_safe(location: &str) -> bool {
    let base = Url::parse(BASE_URL).unwrap();
    base.join(location).is_ok_and(|url| {
        let origin = url.origin().ascii_serialization();
        origin == base.origin().ascii_serialization() || origin == TRUSTED
    })
}

fuzz_target!(|input: Input| {
    let mock = MockHttp::default();
    mock.google_user("social@acme.dk");
    if let Some((status, body)) = &input.token_answer {
        mock.respond(GOOGLE_TOKEN, *status, body.clone());
    }
    if let Some((status, body)) = &input.userinfo_answer {
        mock.respond(GOOGLE_USERINFO, *status, body.clone());
    }
    let auth: SocialAuth = FastAuth::builder()
        .secret(Secret::from_bytes(SECRET.to_vec()))
        .base_url(BASE_URL)
        .trusted_origins([TRUSTED])
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(256, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .plugin(Social::with_http_client(mock).provider(Google::new("google-id", "google-secret")))
        .build()
        .expect("valid config");

    let mut browser = Client::new(&auth);
    let mut body =
        json!({ "provider": "google", "callbackURL": "/dashboard", "errorCallbackURL": "/error" });
    if let Some(url) = &input.callback_url {
        body["callbackURL"] = json!(url);
    }
    let started = browser.post("/sign-in/social", &body);
    assert_ne!(
        started.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        started.json
    );
    if started.status != StatusCode::OK {
        return;
    }
    let provider_url = Url::parse(started.json["url"].as_str().expect("a provider URL")).unwrap();
    let real_state = provider_url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.into_owned())
        .expect("a state");
    let real_cookie = browser
        .jar
        .get("fastauth.oauth_state")
        .cloned()
        .expect("a state cookie");

    let mut query = url::form_urlencoded::Serializer::new(String::new());
    if let Some(code) = part(&input.code, "good-code") {
        query.append_pair("code", &code);
    }
    let state = part(&input.state, &real_state);
    if let Some(state) = &state {
        query.append_pair("state", state);
    }
    if let Some(error) = &input.error {
        query.append_pair("error", error);
    }
    let mut query = query.finish();
    if !input.extra.is_empty() {
        query.push('&');
        query.push_str(
            &url::form_urlencoded::byte_serialize(input.extra.as_bytes()).collect::<String>(),
        );
    }
    let cookie = match &input.cookie {
        StateCookie::Real => Some(real_cookie.clone()),
        StateCookie::Absent => None,
        StateCookie::Fuzz(s) => Some(s.clone()),
        StateCookie::RealPlus(s) => Some(format!("{real_cookie}{s}")),
    };
    let provider = ["google", "github", "Google", ""][usize::from(input.provider) % 4];
    let mut request = http::Request::get(format!("/api/auth/callback/{provider}?{query}"));
    if let Some(cookie) = &cookie {
        request = request.header(
            http::header::COOKIE,
            format!("fastauth.oauth_state={cookie}"),
        );
    }
    let Ok(request) = request.body(bytes::Bytes::new()) else {
        return;
    };
    let mut callback = Client::new(&auth);
    let reply = callback.send_raw(request);
    assert_ne!(
        reply.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{input:?}: {}",
        reply.json
    );
    if reply.status == StatusCode::NOT_FOUND {
        return;
    }
    // OAUTH-1 (info, FAST-46): a query the decoder rejects, such as a repeated `error`,
    // `state` or `code`, answers 400 JSON instead of redirecting to the error callback.
    if reply.status == StatusCode::BAD_REQUEST && reply.json["code"] == "INVALID_REQUEST_BODY" {
        assert!(!reply.signs_in());
        return;
    }
    assert!(
        reply.status.is_redirection(),
        "{input:?}: {} {}",
        reply.status,
        reply.json
    );
    let location = reply.location().unwrap_or_default();
    assert!(is_safe(location), "redirect to {location:?} for {input:?}");
    // The cookie parser drops whitespace around a value and the quotes of a quoted one
    // (RFC 6265), so those variants are the same cookie.
    if reply.signs_in() {
        assert_eq!(
            state.as_deref(),
            Some(real_state.as_str()),
            "signed in with state {state:?}"
        );
        assert_eq!(
            cookie.as_deref().map(|c| c
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .trim_matches('"')),
            Some(real_cookie.as_str()),
            "signed in with state cookie {cookie:?}"
        );
        assert_eq!(provider, "google");
    }
});
