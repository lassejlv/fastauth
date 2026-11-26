export const hero = {
  title: "Auth for Rust, checked by the compiler.",
  lede: "Sign-in, sessions and two-factor for axum and sqlx, in the shape of Better Auth.",
};

export const install = "cargo add fastauth --features oauth,two-factor";

export const heroCode = `pub type AppAuth = Auth<Sqlx<Postgres>, Profile, plugins![Social, TwoFactor]>;

#[derive(Fields, Clone, Debug, Serialize)]
pub struct Profile {
    #[field(default = "free")]
    pub plan: String,
}

pub fn auth(pool: PgPool) -> Result<AppAuth, BuildError> {
    FastAuth::builder()
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("http://localhost:3000")
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default())
        .user_fields::<Profile>()
        .plugin(Social::new().provider(Github::from_env()?))
        .plugin(TwoFactor::new().issuer("Acme"))
        .build()
}`;

export const checks = ["Reading a plugin's state", "Calling its server API", "Columns it adds to user", "Plugins it depends on"];

export const client = [
  ["Tested against", "better-auth 1.7.28"],
  ["Clients", "React, Vue, Svelte"],
  ["Same as Better Auth", "Paths, JSON shapes, error codes"],
  ["Endpoints", "Core and every first-party plugin"],
];

export const crates = [
  ["fastauth", "The crate apps depend on: re-exports everything below behind features"],
  ["fastauth-core", "Builder, compile-checked plugin list, sessions, crypto, routing, email and password, verification, reset"],
  ["fastauth-axum", "auth.router(), Session / FreshSession extractors, the session layer"],
  ["fastauth-sqlx", "Postgres, SQLite and MySQL adapter, migrations, shared transactions (.in_tx)"],
  ["fastauth-macros", "#[derive(Fields, Model, AuthError)]"],
  ["fastauth-oauth", "The Social plugin: GitHub and Google"],
  ["fastauth-plugin-two-factor", "TOTP, email codes, backup codes, trusted devices"],
  ["fastauth-plugin-organization", "Organizations, members, invitations, roles and permissions, axum extractors"],
  ["fastauth-plugin-admin", "User management, roles and permissions, bans, impersonation, RequireRole"],
  ["fastauth-plugin-api-key", "Hashed API keys with expiry, usage and rate limits, permissions, optional sessions from keys"],
  ["fastauth-plugin-magic-link", "Sign-in links by email, with sign-up on first use"],
  ["fastauth-plugin-email-otp", "One-time codes by email for sign-in, email verification and password reset"],
  ["fastauth-plugin-bearer", "Sessions from Authorization: Bearer, and the set-auth-token header"],
  ["fastauth-plugin-jwt", "JWTs for signed-in users, a JWKS with rotating keys, JwksVerifier for other services"],
  ["fastauth-plugin-passkey", "Passkeys (WebAuthn) on webauthn-rs: registration, sign-in, management"],
  ["fastauth-plugin-username", "Usernames next to emails, sign-in by username, availability checks"],
  ["fastauth-plugin-anonymous", "Anonymous users, linked to the real account they sign up or in with"],
  ["fastauth-plugin-multi-session", "Several signed-in accounts per browser, switching between them"],
  ["fastauth-cli", "fastauth secret; schema and migration commands run from your app via fastauth::cli::run"],
];

export const later = [["Not built yet", "Organization teams, an OIDC provider, actix-web, Redis and MySQL"]];
