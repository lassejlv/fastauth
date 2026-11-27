//! Secrets, derived keys, signing, encryption, hashing and password hashing.
//! See `docs/concepts/03-security.md`.

use std::fmt;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use crate::error::BuildError;

type HmacSha256 = Hmac<Sha256>;

/// A master secret. Zeroized on drop; never printed.
#[derive(Clone)]
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    pub const MIN_LEN: usize = 32;

    /// The least estimated entropy `.build()` accepts for a production `base_url`, as in
    /// Better Auth. See [`Secret::entropy_bits`].
    pub const MIN_ENTROPY_BITS: f64 = 120.0;

    /// A rough entropy estimate: length times log2 of the number of distinct bytes. A
    /// generated secret scores about 370 bits; one repeated byte scores 0.
    pub fn entropy_bits(&self) -> f64 {
        let mut seen = [false; 256];
        for byte in self.0.iter() {
            seen[usize::from(*byte)] = true;
        }
        let distinct = seen.iter().filter(|s| **s).count();
        if distinct < 2 {
            return 0.0;
        }
        self.0.len() as f64 * (distinct as f64).log2()
    }

    /// Raw bytes. Prefer `from_env` or `from_base64` so the secret never sits in source.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Secret(Zeroizing::new(bytes.into()))
    }

    /// Accepts base64url (what `fastauth secret` prints) or, failing that, the raw string.
    pub fn from_base64(value: &str) -> Self {
        match B64.decode(value.trim()) {
            Ok(bytes) if bytes.len() >= Self::MIN_LEN => Secret::from_bytes(bytes),
            _ => Secret::from_bytes(value.as_bytes().to_vec()),
        }
    }

    pub fn from_env(var: &str) -> Result<Self, BuildError> {
        let value = std::env::var(var)
            .map_err(|_| BuildError::new(format!("environment variable `{var}` is not set")))?;
        Ok(Secret::from_base64(&value))
    }

    /// 64 random bytes as base64url: a fresh secret.
    pub fn generate() -> String {
        B64.encode(random_bytes::<64>())
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    fn derive(&self, info: &str) -> Zeroizing<[u8; 32]> {
        let hk = hkdf::Hkdf::<Sha256>::new(Some(b"fastauth"), &self.0);
        let mut out = Zeroizing::new([0u8; 32]);
        hk.expand(info.as_bytes(), out.as_mut())
            .expect("32 bytes is a valid HKDF output length");
        out
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(..)")
    }
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("the OS random number generator is available");
    buf
}

/// 32 random bytes as base64url (43 chars): session tokens, verification values, state.
pub fn random_token() -> String {
    B64.encode(random_bytes::<32>())
}

/// A random string from `alphabet`, without modulo bias.
pub fn random_string(len: usize, alphabet: &[u8]) -> String {
    assert!(!alphabet.is_empty() && alphabet.len() <= 256);
    let limit = 256 - (256 % alphabet.len());
    let mut out = String::with_capacity(len);
    while out.len() < len {
        for byte in random_bytes::<64>() {
            if (byte as usize) < limit && out.len() < len {
                out.push(alphabet[byte as usize % alphabet.len()] as char);
            }
        }
    }
    out
}

pub fn base64url(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

pub fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    B64.decode(s).ok()
}

/// SHA-256 digest. Stored instead of tokens.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash([u8; 32]);

impl Hash {
    pub fn sha256(data: impl AsRef<[u8]>) -> Self {
        Hash(Sha256::digest(data.as_ref()).into())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(Hash)
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({}..)", &base64url(&self.0)[..8])
    }
}

/// Constant-time string equality.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Keys derived from the configured secrets. The first secret signs, verifies and encrypts.
/// Every secret decrypts, so encrypted columns stay readable after a rotation, and every
/// secret verifies a signed session token ([`Keys::verify_token`]), which is only a
/// pointer to a session row, so rotating signs nobody out. A retired secret can't sign
/// anything self-contained (the cookie cache, plugin cookies) that is accepted.
pub struct Keys {
    cookie: Vec<Zeroizing<[u8; 32]>>,
    cache: Vec<Zeroizing<[u8; 32]>>,
    encrypt: Vec<Zeroizing<[u8; 32]>>,
    secrets: Vec<Secret>,
}

impl fmt::Debug for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Keys({} secrets)", self.secrets.len())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignPurpose {
    Cookie,
    CookieCache,
}

impl Keys {
    pub(crate) fn new(secrets: Vec<Secret>) -> Self {
        Self {
            cookie: secrets
                .iter()
                .map(|s| s.derive("fastauth/v1/cookie"))
                .collect(),
            cache: secrets
                .iter()
                .map(|s| s.derive("fastauth/v1/cookie-cache"))
                .collect(),
            encrypt: secrets
                .iter()
                .map(|s| s.derive("fastauth/v1/encrypt"))
                .collect(),
            secrets,
        }
    }

    fn sign_keys(&self, purpose: SignPurpose) -> &[Zeroizing<[u8; 32]>] {
        match purpose {
            SignPurpose::Cookie => &self.cookie,
            SignPurpose::CookieCache => &self.cache,
        }
    }

    fn mac(key: &[u8; 32], value: &str) -> HmacSha256 {
        let mut mac =
            <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
        mac.update(value.as_bytes());
        mac
    }

    /// `value.signature`, signature base64url.
    pub fn sign(&self, purpose: SignPurpose, value: &str) -> String {
        let tag = Self::mac(&self.sign_keys(purpose)[0], value)
            .finalize()
            .into_bytes();
        format!("{value}.{}", B64.encode(tag))
    }

    /// The value, when the current (first) secret signed it. For values that carry their
    /// own meaning, like the cookie cache or a plugin's signed cookie.
    pub fn verify<'a>(&self, purpose: SignPurpose, signed: &'a str) -> Option<&'a str> {
        Self::verify_with(&self.sign_keys(purpose)[..1], signed)
    }

    /// A session token signed with [`SignPurpose::Cookie`] by any configured secret. Only
    /// for raw session tokens, and for markers that only restrict the session they come
    /// with (the `rememberMe: false` flag): a token means nothing until its session row is
    /// found, and a forged marker only shortens a session, so a retired secret can't gain
    /// anything, and values signed before a rotation keep working.
    pub fn verify_token<'a>(&self, signed: &'a str) -> Option<&'a str> {
        Self::verify_with(&self.cookie, signed)
    }

    fn verify_with<'a>(keys: &[Zeroizing<[u8; 32]>], signed: &'a str) -> Option<&'a str> {
        let (value, sig) = signed.rsplit_once('.')?;
        let sig = B64.decode(sig).ok()?;
        keys.iter()
            .any(|key| Self::mac(key, value).verify_slice(&sig).is_ok())
            .then_some(value)
    }

    /// `[key id][24-byte nonce][ciphertext]`.
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let cipher =
            XChaCha20Poly1305::new_from_slice(self.encrypt[0].as_ref()).expect("32-byte key");
        let nonce_bytes = random_bytes::<24>();
        let nonce = chacha20poly1305::XNonce::from(nonce_bytes);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .expect("XChaCha20-Poly1305 encryption cannot fail");
        let mut out = Vec::with_capacity(1 + 24 + ciphertext.len());
        out.push(0);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        out
    }

    pub fn decrypt(&self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 25 {
            return None;
        }
        let (nonce, ciphertext) = data[1..].split_at(24);
        let nonce = chacha20poly1305::XNonce::try_from(nonce).ok()?;
        self.encrypt.iter().find_map(|key| {
            let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).ok()?;
            cipher.decrypt(&nonce, ciphertext).ok()
        })
    }

    /// A per-plugin key, so plugins can't reach core's keys.
    pub fn derive_key(&self, plugin_id: &str) -> Zeroizing<[u8; 32]> {
        self.secrets[0].derive(&format!("fastauth/v1/plugin/{plugin_id}"))
    }
}

/// Password hashing. Runs on a blocking thread; see `Passwords`.
pub trait PasswordHasher: Send + Sync + 'static {
    fn hash(&self, password: &str) -> Result<String, String>;
    fn verify(&self, password: &str, hash: &str) -> Result<bool, String>;
    /// Whether a stored hash should be replaced on the next successful sign-in.
    fn needs_rehash(&self, hash: &str) -> bool {
        let _ = hash;
        false
    }
}

/// argon2id with OWASP parameters: 19 MiB, t=2, p=1.
#[derive(Debug, Clone)]
pub struct Argon2id {
    params: argon2::Params,
}

impl Argon2id {
    pub fn owasp() -> Self {
        Self::with_params(19 * 1024, 2, 1)
    }

    pub fn with_params(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Self {
        let params =
            argon2::Params::new(m_cost_kib, t_cost, p_cost, None).expect("valid argon2 parameters");
        Self { params }
    }

    fn engine(&self) -> argon2::Argon2<'static> {
        argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            self.params.clone(),
        )
    }
}

impl Default for Argon2id {
    fn default() -> Self {
        Self::owasp()
    }
}

impl PasswordHasher for Argon2id {
    fn hash(&self, password: &str) -> Result<String, String> {
        use argon2::password_hash::PasswordHasher as _;
        self.engine()
            .hash_password(password.as_bytes())
            .map(|h| h.to_string())
            .map_err(|e| e.to_string())
    }

    fn verify(&self, password: &str, hash: &str) -> Result<bool, String> {
        use argon2::password_hash::PasswordVerifier as _;
        let parsed =
            argon2::password_hash::phc::PasswordHash::new(hash).map_err(|e| e.to_string())?;
        Ok(self
            .engine()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    }

    fn needs_rehash(&self, hash: &str) -> bool {
        let Ok(parsed) = argon2::password_hash::phc::PasswordHash::new(hash) else {
            return true;
        };
        let Ok(params) = argon2::Params::try_from(&parsed) else {
            return true;
        };
        parsed.algorithm.as_str() != "argon2id"
            || params.m_cost() < self.params.m_cost()
            || params.t_cost() < self.params.t_cost()
    }
}

/// Runs a `PasswordHasher` on the blocking pool behind a semaphore, so a burst of sign-ins
/// can't allocate unbounded argon2 memory.
#[derive(Clone)]
pub struct Passwords {
    hasher: Arc<dyn PasswordHasher>,
    permits: Arc<Semaphore>,
    dummy_hash: Arc<std::sync::OnceLock<String>>,
}

impl fmt::Debug for Passwords {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Passwords(..)")
    }
}

impl Passwords {
    pub fn new(hasher: Arc<dyn PasswordHasher>) -> Self {
        let cpus = std::thread::available_parallelism().map_or(2, |n| n.get());
        Self {
            hasher,
            permits: Arc::new(Semaphore::new(cpus)),
            dummy_hash: Arc::default(),
        }
    }

    async fn run<T: Send + 'static>(
        &self,
        f: impl FnOnce(&dyn PasswordHasher) -> T + Send + 'static,
    ) -> T {
        let _permit = self
            .permits
            .acquire()
            .await
            .expect("semaphore is never closed");
        let hasher = self.hasher.clone();
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle
                .spawn_blocking(move || f(hasher.as_ref()))
                .await
                .expect("password hashing task panicked"),
            Err(_) => f(hasher.as_ref()),
        }
    }

    pub async fn hash(&self, password: &str) -> Result<String, String> {
        let password = Zeroizing::new(password.to_owned());
        self.run(move |h| h.hash(&password)).await
    }

    pub async fn verify(&self, password: &str, hash: &str) -> Result<bool, String> {
        let password = Zeroizing::new(password.to_owned());
        let hash = hash.to_owned();
        self.run(move |h| h.verify(&password, &hash)).await
    }

    pub fn needs_rehash(&self, hash: &str) -> bool {
        self.hasher.needs_rehash(hash)
    }

    /// Spends the same time as a real verification, for unknown emails.
    pub async fn verify_dummy(&self, password: &str) {
        let dummy = match self.dummy_hash.get() {
            Some(h) => h.clone(),
            None => {
                let h = self
                    .hash("fastauth-dummy-password")
                    .await
                    .unwrap_or_default();
                self.dummy_hash.get_or_init(|| h).clone()
            }
        };
        let _ = self.verify(password, &dummy).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> Keys {
        Keys::new(vec![Secret::from_bytes(vec![7u8; 32])])
    }

    #[test]
    fn sign_round_trips_and_rejects_tampering() {
        let keys = keys();
        let signed = keys.sign(SignPurpose::Cookie, "token");
        assert_eq!(keys.verify(SignPurpose::Cookie, &signed), Some("token"));
        assert_eq!(keys.verify(SignPurpose::CookieCache, &signed), None);
        assert_eq!(
            keys.verify(SignPurpose::Cookie, &signed.replace("token", "tokem")),
            None
        );
    }

    #[test]
    fn rotation_keeps_old_tokens_and_ciphertexts_but_not_old_signatures() {
        let old = keys();
        let signed = old.sign(SignPurpose::Cookie, "v");
        let cached = old.sign(SignPurpose::CookieCache, "v");
        let rotated = Keys::new(vec![
            Secret::from_bytes(vec![9u8; 32]),
            Secret::from_bytes(vec![7u8; 32]),
        ]);
        assert_eq!(rotated.verify_token(&signed), Some("v"));
        assert_eq!(rotated.verify(SignPurpose::Cookie, &signed), None);
        assert_eq!(rotated.verify(SignPurpose::CookieCache, &cached), None);
        let fresh = rotated.sign(SignPurpose::CookieCache, "v");
        assert_eq!(rotated.verify(SignPurpose::CookieCache, &fresh), Some("v"));
        assert_eq!(
            rotated.decrypt(&old.encrypt(b"hi")).as_deref(),
            Some(&b"hi"[..])
        );
    }

    #[test]
    fn encryption_round_trips() {
        let keys = keys();
        let sealed = keys.encrypt(b"secret");
        assert_ne!(&sealed[25..], b"secret");
        assert_eq!(keys.decrypt(&sealed).unwrap(), b"secret");
    }

    #[test]
    fn argon2_hashes_and_verifies() {
        let hasher = Argon2id::with_params(1024, 1, 1);
        let hash = hasher.hash("correct horse").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(hasher.verify("correct horse", &hash).unwrap());
        assert!(!hasher.verify("wrong", &hash).unwrap());
        assert!(Argon2id::owasp().needs_rehash(&hash));
    }

    #[test]
    fn entropy_estimate_separates_generated_from_guessable_secrets() {
        assert!(Secret::from_base64(&Secret::generate()).entropy_bits() > 300.0);
        assert_eq!(Secret::from_bytes(vec![0u8; 32]).entropy_bits(), 0.0);
        assert!(
            Secret::from_base64("password password password pass!").entropy_bits()
                < Secret::MIN_ENTROPY_BITS
        );
    }

    #[test]
    fn random_string_uses_alphabet() {
        let s = random_string(40, b"ab");
        assert_eq!(s.len(), 40);
        assert!(s.bytes().all(|b| b == b'a' || b == b'b'));
    }
}
