//! Property tests for invariants example-based tests miss: signing, encryption, hashing and
//! password round-trips; the redirect resolver never leaving the app's origins; the rate
//! limiter never letting more than its limit through under concurrent requests; and email
//! normalization being idempotent.

use std::sync::{Arc, LazyLock};

use bytes::Bytes;
use fastauth_core::config::{ClientIp, CoreConfig};
use fastauth_core::crypto::{
    Argon2id, Hash, Passwords, SignPurpose, base64url, base64url_decode, ct_eq,
};
use fastauth_core::plugin_prelude::*;
use fastauth_core::prelude::{EmailPassword, FastAuth, MemoryAdapter, RateLimit};
use fastauth_core::rate_limit::Limit;
use fastauth_core::routes::normalize_email;
use fastauth_core::{Auth, crypto::Secret, plugins};
use http::{Request, StatusCode};
use proptest::prelude::*;
use url::Url;

const BASE_URL: &str = "http://localhost:3000";
const TRUSTED: &str = "https://app.acme.dk";

// ---------------------------------------------------------------- signing and encryption

/// Exposes the instance's keys to the tests through an endpoint, as a plugin sees them.
struct Probe;

#[derive(Debug, Default, Deserialize)]
struct ProbeInput {
    value: String,
    purpose_cache: bool,
    check: Vec<String>,
    plaintext: Vec<u8>,
    sealed: Vec<Vec<u8>>,
}

#[derive(Debug, Serialize)]
struct ProbeOutput {
    signed: String,
    /// What `verify` returns for each of `check`, under the same purpose and the other one.
    verified: Vec<(Option<String>, Option<String>)>,
    sealed: Vec<u8>,
    opened: Vec<Option<Vec<u8>>>,
}

struct ProbeEndpoint;

impl<D: Adapter> Endpoint<D> for ProbeEndpoint {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/probe";
    type Access = Public;
    type Input = ProbeInput;
    type Output = ProbeOutput;

    async fn call(&self, ctx: Ctx<D, Public>, input: ProbeInput) -> Result<ProbeOutput, AuthError> {
        let keys = ctx.keys();
        let (purpose, other) = if input.purpose_cache {
            (SignPurpose::CookieCache, SignPurpose::Cookie)
        } else {
            (SignPurpose::Cookie, SignPurpose::CookieCache)
        };
        Ok(ProbeOutput {
            signed: keys.sign(purpose, &input.value),
            verified: input
                .check
                .iter()
                .map(|s| {
                    (
                        keys.verify(purpose, s).map(str::to_owned),
                        keys.verify(other, s).map(str::to_owned),
                    )
                })
                .collect(),
            sealed: keys.encrypt(&input.plaintext),
            opened: input.sealed.iter().map(|s| keys.decrypt(s)).collect(),
        })
    }
}

impl Plugin for Probe {
    const ID: &'static str = "probe";
    type Requires = ();
    type UserFields = ();
    type SessionFields = ();

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        app.endpoint(ProbeEndpoint);
    }
}

type ProbeAuth = Auth<MemoryAdapter, (), plugins![Probe]>;

static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
});

static PROBE: LazyLock<ProbeAuth> = LazyLock::new(|| {
    FastAuth::builder()
        .secret(Secret::from_bytes(vec![9u8; 32]))
        .base_url(BASE_URL)
        .database(MemoryAdapter::new())
        .plugin(Probe)
        .build()
        .expect("valid config")
});

fn probe(input: ProbeInput) -> ProbeOutput {
    RUNTIME
        .block_on(PROBE.api().call(&ProbeEndpoint, input))
        .expect("probe")
        .data
}

/// `text` with the byte at `at` replaced, when that is still UTF-8 and differs.
fn tamper(text: &str, at: usize, byte: u8) -> Option<String> {
    let mut bytes = text.as_bytes().to_vec();
    let i = at % bytes.len().max(1);
    *bytes.get_mut(i)? = byte;
    String::from_utf8(bytes).ok().filter(|t| t != text)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn signed_values_round_trip_and_tampering_never_verifies(
        value in "\\PC{0,64}",
        purpose_cache: bool,
        at: usize,
        byte: u8,
        suffix in "\\PC{1,8}",
    ) {
        let signed = probe(ProbeInput { value: value.clone(), purpose_cache, ..Default::default() }).signed;
        let mut check = vec![signed.clone(), format!("{signed}{suffix}"), format!("{suffix}{signed}")];
        check.extend(tamper(&signed, at, byte));
        let verified = probe(ProbeInput { value: String::new(), purpose_cache, check, ..Default::default() }).verified;
        prop_assert_eq!(&verified[0], &(Some(value.clone()), None), "own purpose only");
        for (i, (same, other)) in verified.iter().enumerate().skip(1) {
            prop_assert_eq!(other, &None, "check {} verified under the other purpose", i);
            prop_assert!(same.as_deref() != Some(value.as_str()) || i == 0, "check {} verified as the original", i);
            prop_assert_eq!(same, &None, "check {} verified", i);
        }
    }

    #[test]
    fn sealed_bytes_round_trip_and_tampering_never_opens(
        plaintext in prop::collection::vec(any::<u8>(), 0..256),
        at: usize,
        xor in 1u8..,
    ) {
        let sealed = probe(ProbeInput { plaintext: plaintext.clone(), ..Default::default() }).sealed;
        let mut tampered = sealed.clone();
        let i = at % tampered.len();
        tampered[i] ^= xor;
        let truncated = sealed[..sealed.len() - 1].to_vec();
        let opened = probe(ProbeInput { sealed: vec![sealed, tampered, truncated], ..Default::default() }).opened;
        prop_assert_eq!(&opened[0], &Some(plaintext.clone()));
        // Byte 0 is the key id, which isn't authenticated: a change there may still open,
        // but never to other bytes. Everything after it is authenticated.
        if i == 0 {
            prop_assert!(opened[1].is_none() || opened[1] == Some(plaintext));
        } else {
            prop_assert_eq!(&opened[1], &None);
        }
        prop_assert_eq!(&opened[2], &None);
    }

    #[test]
    fn hashes_and_base64url_round_trip(data in prop::collection::vec(any::<u8>(), 0..512), other in prop::collection::vec(any::<u8>(), 0..64)) {
        let hash = Hash::sha256(&data);
        prop_assert_eq!(Hash::from_slice(hash.as_bytes()), Some(hash));
        prop_assert_eq!(Hash::sha256(&data), hash);
        prop_assert_eq!(Hash::sha256(&other) == hash, other == data);
        prop_assert_eq!(base64url_decode(&base64url(&data)), Some(data.clone()));
        prop_assert_eq!(ct_eq(&data, &other), data == other);
        prop_assert!(ct_eq(&data, &data));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn passwords_verify_only_themselves(password in "\\PC{1,40}", other in "\\PC{1,40}") {
        let passwords = Passwords::new(Arc::new(Argon2id::with_params(256, 1, 1)));
        let (hash, ok, wrong) = RUNTIME.block_on(async {
            let hash = passwords.hash(&password).await.unwrap();
            let ok = passwords.verify(&password, &hash).await.unwrap();
            let wrong = passwords.verify(&other, &hash).await.unwrap();
            (hash, ok, wrong)
        });
        prop_assert!(!hash.contains(&password) || password.len() < 4, "the hash holds the password");
        prop_assert!(ok);
        prop_assert_eq!(wrong, other == password);
    }
}

// ---------------------------------------------------------------- redirects

static CONFIG: LazyLock<CoreConfig> = LazyLock::new(|| {
    let auth: Auth<MemoryAdapter> = FastAuth::builder()
        .secret(Secret::from_bytes(vec![9u8; 32]))
        .base_url(BASE_URL)
        .trusted_origins([TRUSTED])
        .database(MemoryAdapter::new())
        .build()
        .unwrap();
    auth.config().clone()
});

/// Redirect targets built from the pieces that trip URL parsers up.
fn redirect_target() -> impl Strategy<Value = String> {
    let piece = prop::sample::select(vec![
        "/",
        "//",
        "///",
        "\\",
        "\t",
        "\n",
        "\r",
        " ",
        "\u{3000}",
        "\u{feff}",
        "%2f",
        "%2F",
        "%5c",
        "%5C",
        "%09",
        "%00",
        "%252f",
        ".",
        "..",
        "./",
        "../",
        "@",
        ":",
        "?",
        "#",
        "&",
        "=",
        "evil.example",
        "localhost",
        "localhost:3000",
        ":3000",
        "app.acme.dk",
        "acme.dk",
        "http:",
        "https:",
        "javascript:",
        "data:",
        "HTTP://",
        "https://app.acme.dk",
        "http://localhost:3000",
        "dashboard",
        "a",
        "0",
        "[::1]",
        "127.0.0.1",
        "xn--",
    ]);
    prop_oneof![
        prop::collection::vec(piece, 0..8).prop_map(|parts| parts.concat()),
        "\\PC{0,40}",
        ("/", "\\PC{0,40}").prop_map(|(a, b)| format!("{a}{b}")),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn redirects_never_leave_the_apps_origins(target in redirect_target()) {
        let config = &*CONFIG;
        let resolved = config.resolve_redirect(&target);
        prop_assert_eq!(config.is_safe_redirect(&target), resolved.is_some());
        let Some(resolved) = resolved else { return Ok(()) };
        let base = Url::parse(BASE_URL).unwrap();
        let allowed = [base.origin().ascii_serialization(), TRUSTED.to_owned()];
        prop_assert!(allowed.contains(&resolved.origin().ascii_serialization()), "{:?} resolved to {}", target, resolved);
        let browser = base.join(&target);
        prop_assert!(browser.is_ok(), "accepted {:?}, which a browser can't resolve", target);
        let browser = browser.unwrap();
        prop_assert!(allowed.contains(&browser.origin().ascii_serialization()), "{:?} opens {} in a browser", target, browser);
    }
}

// ---------------------------------------------------------------- rate limiting

fn limited_auth(max: u32) -> Auth<MemoryAdapter> {
    FastAuth::builder()
        .secret(Secret::from_bytes(vec![9u8; 32]))
        .base_url(BASE_URL)
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default())
        .client_ip(ClientIp::Header("x-client-ip".into()))
        .rate_limit(RateLimit::default().rule("/get-session", Limit::per(Duration::hours(1), max)))
        .build()
        .unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn the_rate_limiter_never_exceeds_its_limit_under_concurrency(
        max in 1u32..12,
        per_client in prop::collection::vec(0usize..40, 1..4),
    ) {
        let auth = limited_auth(max);
        let allowed = RUNTIME.block_on(async {
            let mut tasks = Vec::new();
            for (client, &count) in per_client.iter().enumerate() {
                for _ in 0..count {
                    let auth = auth.clone();
                    tasks.push(tokio::spawn(async move {
                        let request = Request::get("/api/auth/get-session")
                            .header("x-client-ip", format!("10.0.0.{client}"))
                            .body(Bytes::new())
                            .unwrap();
                        (client, auth.handle(request).await.status())
                    }));
                }
            }
            let mut allowed = vec![0usize; per_client.len()];
            for task in tasks {
                let (client, status) = task.await.unwrap();
                if status != StatusCode::TOO_MANY_REQUESTS {
                    allowed[client] += 1;
                }
            }
            allowed
        });
        for (client, (&allowed, &sent)) in allowed.iter().zip(&per_client).enumerate() {
            prop_assert_eq!(allowed, sent.min(max as usize), "client {} sent {} with a limit of {}", client, sent, max);
        }
    }
}

// ---------------------------------------------------------------- email normalization

fn email_like() -> impl Strategy<Value = String> {
    let piece = prop::sample::select(vec![
        "a", "Z", "ø", "Å", "İ", "ß", "ﬃ", "K", "+", ".", "..", "-", "_", "@", "@@", " ", "\t",
        "\u{3000}", "\u{200b}", "acme", "dk", "xn--", "\"", "(", ")", "[", "]", "%", "1", "Σ", "ς",
        "ǅ",
    ]);
    prop_oneof![
        prop::collection::vec(piece, 1..12).prop_map(|parts| parts.concat()),
        ("\\PC{1,20}", "\\PC{1,20}", "\\PC{1,10}").prop_map(|(l, d, t)| format!("{l}@{d}.{t}")),
        "\\PC{0,64}",
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn email_normalization_is_idempotent(input in email_like()) {
        if let Ok(email) = normalize_email(&input) {
            prop_assert_eq!(normalize_email(&email).ok(), Some(email.clone()), "from {:?}", input);
        }
    }
}
