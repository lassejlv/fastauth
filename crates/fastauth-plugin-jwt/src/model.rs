//! The `jwks` table.

use fastauth_core::plugin_prelude::*;

/// A row of `jwks`: one signing key pair. The public half is a JWK as JSON; the private half
/// is a PKCS#8 key encrypted with the app secret (XChaCha20-Poly1305 under a key derived
/// from it), so a database dump alone can't mint tokens.
#[derive(Model, Clone)]
#[model(table = "jwks")]
pub struct JsonWebKey {
    /// Also the `kid` of the key and of every token it signs.
    #[model(id)]
    pub id: Id,
    /// The public JWK, as JSON: `{"kty":"OKP","crv":"Ed25519","x":"..."}`.
    pub public_key: String,
    /// The encrypted private key, base64url.
    #[model(hidden)]
    pub private_key: String,
    #[model(default = now)]
    pub created_at: OffsetDateTime,
    /// After this the key no longer signs; the JWKS keeps listing it for the grace period.
    pub expires_at: Option<OffsetDateTime>,
    /// `EdDSA`, `ES256` or `RS256`.
    pub alg: Option<String>,
    /// `Ed25519` or `P-256`; none for RSA.
    pub crv: Option<String>,
}

impl std::fmt::Debug for JsonWebKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonWebKey")
            .field("id", &self.id)
            .field("alg", &self.alg)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}
