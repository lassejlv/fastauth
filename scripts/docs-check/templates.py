"""Templates that turn each Rust block in docs/ into a compilable module. See README.md.

Every page in docs/ with Rust blocks has a page(...) entry listing its blocks in page order,
each by its first line. A template is the block plus scaffolding: imports, stubs and an
enclosing fn. Template lines that are only an include insert docs lines verbatim:

    @         this block           @:a-b    lines a..b of this block (1-based)
    @N        block N of the page  @N:a-b   lines a..b of block N of the page

Each block becomes its own module: page.base + ctx at the top, then the template inside
"pub mod it { use super::*; ... }", so the block's own imports shadow the scaffolding's.
"""


class Entry:
    def __init__(self, first, tpl="@", ctx=None, excerpt=False):
        self.first, self.tpl, self.ctx, self.excerpt = first.strip(), tpl, ctx, excerpt


class Page:
    def __init__(self, path, ctx, blocks, base, module):
        self.path, self.ctx, self.blocks, self.base, self.module = path, ctx, blocks, base, module


PAGES = {}


def block(first, tpl="@", ctx=None):
    """A compiled block. ctx=None uses the page's ctx."""
    return Entry(first, tpl, ctx)


def excerpt(first):
    """A deliberately truncated excerpt of fastauth-core: not compiled, checked line by line against
    crates/fastauth-core/src instead."""
    return Entry(first, excerpt=True)


def page(path, ctx, blocks, base=None, module=None):
    """module: compile the whole page as one module from this template (blocks are then just listed)."""
    PAGES[path] = Page(path, ctx, blocks, AXUM if base is None else base, module)


def stmts(args):
    """Statements inside an async fn returning anyhow::Result<()>."""
    return f"async fn block({args}) -> anyhow::Result<()> {{\n@\nOk(())\n}}"


def autherr(args):
    """Statements inside an async fn returning Result<(), AuthError>."""
    return f"async fn block({args}) -> Result<(), fastauth::AuthError> {{\n@\nOk(())\n}}"


def chain(prefix="FastAuth::builder()", args=""):
    """Builder method calls chained onto prefix."""
    return f"fn block({args}) {{\nlet _b = {prefix}\n@\n;\n}}"


def expr(binding="_v", args=""):
    """A single expression."""
    return f"fn block({args}) {{\nlet {binding} =\n@\n;\n}}"


FEATURES = [
    "axum", "actix", "macros", "postgres", "sqlite", "mysql", "oauth", "cli",
    "two-factor", "organization", "admin", "api-key", "magic-link", "email-otp",
    "bearer", "jwt", "passkey", "username", "anonymous", "multi-session", "redis",
]


def cargo_toml(repo):
    """repo: the repository root, relative to the generated crate."""
    feats = ", ".join(f'"{f}"' for f in FEATURES)
    return f"""[package]
name = "acme"
version = "0.0.0"
edition = "2024"
publish = false

[workspace]

[dependencies]
fastauth = {{ path = "{repo}/crates/fastauth", features = [{feats}] }}
fastauth-core = {{ path = "{repo}/crates/fastauth-core", features = ["testing"] }}
fastauth-plugin-jwt = {{ path = "{repo}/crates/fastauth-plugin-jwt" }}
actix-web = {{ version = "4", default-features = false, features = ["macros"] }}
anyhow = "1"
axum = {{ version = "0.8", features = ["macros"] }}
bytes = "1"
http = "1"
reqwest = {{ version = "0.13", default-features = false, features = ["rustls"] }}
serde = {{ version = "1", features = ["derive"] }}
serde_json = "1"
sqlx = {{ version = "0.9", default-features = false, features = ["postgres", "sqlite", "mysql", "runtime-tokio"] }}
tokio = {{ version = "1", features = ["full"] }}
"""


# get-started/02-quickstart.md block 1 is src/auth.rs of the quickstart app; other blocks use it as acme::auth.
LIB = """#![allow(unused, dead_code, unreachable_code, private_interfaces, clippy::all)]
extern crate self as acme;
pub mod auth { pub use crate::get_started_02_quickstart_b01::it::*; }
"""

AXUM = """use fastauth::prelude::*;
use axum::{Json, Router, extract::{FromRef, Path, State}, http::{HeaderMap, StatusCode, header::{self, SET_COOKIE}}, response::{IntoResponse, Response}, routing::{delete, get, post}};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::net::SocketAddr;
"""

ACTIX = """use fastauth::prelude::*;
use fastauth::actix::{AuthScope, Session};
use actix_web::{App, HttpRequest, HttpResponse, HttpServer, web};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
"""

# The builder boilerplate that plugin pages elide with "// ...".
SECRETS = '    .secret(Secret::from_env("FASTAUTH_SECRET")?).base_url("http://localhost:3000").database(Sqlx::new(pool)).email_password(EmailPassword::default())'


def app_auth(*plugins):
    """pub type AppAuth with these plugins, as each plugin page's setup block declares it."""
    return f"pub type AppAuth = Auth<Sqlx<Postgres>, (), plugins![{', '.join(plugins)}]>;\n"


# ---------------------------------------------------------------- concepts

page("concepts/01-sessions.md", """use fastauth::plugins::{admin::{Admin, AdminUser}, two_factor::{TwoFactor, TwoFactorUser}};
""" + app_auth("TwoFactor", "Admin"), [
    block("use fastauth::axum::{FreshSession, Session};"),
    block("async fn whoami(session: Session<AppAuth>) -> String {"),
    block("#[derive(Clone, FromRef)]"),
    block("let app = Router::new()", """@3
async fn me(session: Session<AppAuth>) -> String { String::new() }
async fn block(auth: AppAuth, state: AppState) {
@
let _: Router = app;
}"""),
    block("async fn settings(session: Session<AppAuth>) -> Json<Settings> {", """#[derive(Serialize)]
struct Settings { two_factor: bool, role: Option<String>, banned: bool }
@"""),
    block("use fastauth::plugins::admin::{Admin, AdminExt, AdminUser, BanUserInput, RequireRole, role};"),
    block("use fastauth::routes::{SignInEmailInput, SignInOutput};", stmts("auth: AppAuth, headers: HeaderMap, email: String, password: String")),
    block("async fn sign_in_with_invite(", """use fastauth::routes::{SignInEmailInput, SignInOutput};
use fastauth::ApiResponse;
#[derive(Deserialize)]
struct InviteSignIn { code: String, password: String }
struct Invite { email: String }
mod invites { pub async fn redeem(code: &str) -> Result<super::Invite, fastauth::AuthError> { todo!() } }
@"""),
    block("let session = auth.get_session(&headers).await?;              // Option<SessionData<..>>", stmts("auth: AppAuth, headers: HeaderMap, token: String")),
    block("use fastauth::routes::CreateUserInput;", stmts("auth: AppAuth, pool: PgPool, email: String, name: String, team_id: String")),
])

DB = """pub type AppAuth = Auth<Sqlx<Postgres>>;
use fastauth::plugins::two_factor::TwoFactorUser;
use fastauth::plugin_prelude::{Adapter, Ctx, Hash};
use crate::reference_01_plugin_authoring::it::AccessToken;
"""

page("concepts/02-database.md", DB, [
    block("use fastauth::prelude::*;   // re-exports Sqlx and the pool types of the enabled drivers", stmts("url: String")),
    block("Sqlx::new(pool)", expr("_s", "pool: PgPool")),
    block(".ids(IdStrategy::Ulid)                                     // default: 01M8AH3K9Q2W7X5R1N0PJCV4TB",
          chain(), ctx=DB + "use fastauth::plugin_prelude::random_token;\n"),
    block("// 1. At startup. Fine for development and small deployments.", stmts("auth: AppAuth")),
    block("let token = ctx.db().find::<AccessToken>(AccessToken::TOKEN_HASH.eq(hash)).one().await?;  // Option<AccessToken>", """async fn block<D: Adapter>(ctx: Ctx<D>, hash: Hash, user_id: Id, id: Id) -> Result<(), fastauth::AuthError> {
@
Ok(())
}""", ctx=DB + "use fastauth::models::Session;\n"),
    block("let tx = ctx.adapter().begin().await?;", """async fn block<D: Adapter>(ctx: Ctx<D>, user_id: Id) -> Result<(), fastauth::AuthError> {
@
Ok(())
}""", ctx=DB + "use fastauth::adapter::Transaction;\n"),
    excerpt("pub trait Queries: Send + Sync {"),
    block('// [dev-dependencies] fastauth-core = { version = "0.6", features = ["testing"] }'),
])

page("concepts/04-multiple-instances.md", "", [
    block("use fastauth::prelude::*;", ctx=""),
    excerpt("pub trait SecondaryStorage: Send + Sync + 'static {"),
    block('// [dev-dependencies] fastauth-core = { version = "0.6", features = ["testing"] }', ctx=""),
])

# ---------------------------------------------------------------- get-started

page("get-started/02-quickstart.md", "", [
    block("// src/auth.rs"),
    block("auth.migrator().run().await?;", stmts("auth: acme::auth::AppAuth")),
    block("// src/bin/fastauth.rs"),
    block("// src/main.rs"),
    block('.client_ip(ClientIp::Header("fly-client-ip".into()))         // one address, set by the proxy', chain()),
    block("use actix_web::{App, HttpServer, web};", """async fn me(session: fastauth::actix::Session<AppAuth>) -> actix_web::HttpResponse { todo!() }
async fn block(auth: AppAuth) -> anyhow::Result<()> {
@
Ok(())
}""", ctx="use acme::auth::AppAuth;\n"),
    block("use fastauth::plugins::two_factor::TwoFactor;", """@:1-3
fn block(pool: PgPool) -> Result<AppAuth, BuildError> {
@:5-5
""" + SECRETS + """
@:6-9
}"""),
])

CFG = """use fastauth::plugins::two_factor::TwoFactor;
use fastauth::crypto::Argon2id;
use fastauth::social::{Github, Google, Social};
use fastauth::plugin_prelude::random_token;
"""

page("get-started/03-configuration.md", CFG, [
    block("FastAuth::builder()", """#[derive(Fields, Serialize, Deserialize, Clone, Debug)]
pub struct Profile { #[field(default = "free", input)] pub plan: String }
fn block(pool: PgPool) -> Result<Auth<Sqlx<Postgres>, Profile, plugins![Social, TwoFactor]>, BuildError> {
@
}"""),
    block('.secret(Secret::from_env("FASTAUTH_SECRET")?)', """fn block() -> Result<(), BuildError> {
let _b = FastAuth::builder()
@
;
Ok(())
}"""),
    block('.base_url("http://staging.internal:3000")', chain()),
    block(".email_password(", """fn block() {
let _b = FastAuth::builder()
@
}"""),
    block("use fastauth::mail::MailError;", """fn verify_template(url: &str) -> String { todo!() }
fn reset_template(url: &str) -> String { todo!() }
async fn deliver(to: &str, subject: &str, html: String) -> Result<(), fastauth::mail::MailError> { todo!() }
@"""),
    block("use fastauth::social::{AccountLinking, Github, Google, OAuthProfile, OAuthProviderExt, Social};", """pub struct Profile;
@:1-3
fn block(client_id: String, client_secret: String) -> anyhow::Result<()> {
let _b = FastAuth::builder()
@:5-10
Ok(())
}"""),
    block("Social::new()", """#[derive(Fields, Serialize, Deserialize, Clone, Debug)]
pub struct Profile { #[field(default = "free", input)] pub plan: String }
use fastauth::social::{OAuthProfile, OAuthProviderExt, Social};
fn block() -> anyhow::Result<()> {
let _s =
@
;
Ok(())
}"""),
    block(".session(", chain()),
    block(".cookies(", chain()),
    block(".rate_limit(", chain()),
    block(".ids(IdStrategy::UuidV7)", chain()),
    block("#[derive(Fields, Serialize, Deserialize, Clone, Debug)]", """@:1-8
fn block() {
let _b = FastAuth::builder()
@:10-10
;
}"""),
    block(".on(|e: UserCreated, ctx| async move {", """#[derive(Fields, Serialize, Deserialize, Clone, Debug)]
pub struct Profile { pub stripe_customer_id: Option<String> }
fn block() {
let _b = FastAuth::builder().database(MemoryAdapter::new())
@
;
}"""),
])

# ---------------------------------------------------------------- integrations

HTTP = "pub type AppAuth = Auth<Sqlx<Postgres>>;\n"

page("integrations/01-http.md", HTTP, [
    block("use fastauth::axum::{AuthRouter, Session};", """async fn me() -> String { String::new() }
async fn block(auth: AppAuth) -> anyhow::Result<()> {
let state = auth.clone();
@
Ok(())
}"""),
    block('.nest_service("/auth", auth.service())     // set .base_path("/auth") on the builder to match', chain("Router::<()>::new()", "auth: AppAuth")),
    block("let session = auth.get_session(request.headers()).await?;  // Option<SessionData<..>>",
          autherr("auth: AppAuth, request: http::Request<bytes::Bytes>"), ctx=HTTP + "use bytes::Bytes;\n"),
    block("/// Serves the auth routes for any `AuthInstance`. `peer` is the client's socket address.", """use bytes::Bytes;
use fastauth::{AuthError, ClientAddr};
use std::net::IpAddr;
@"""),
    block("impl HttpClient for MyClient {", """use bytes::Bytes;
use fastauth::social::{HttpClient, HttpClientError, ReqwestClient, Social};
struct MyClient;
@:1-5
fn block(my_reqwest_client: reqwest::Client) {
@:7-9
}"""),
])

page("integrations/03-actix.md", "use fastauth::plugins::{admin::Admin, organization::Organization};\n" + app_auth("Organization", "Admin") + """mod auth { pub fn build(pool: fastauth::prelude::PgPool) -> Result<super::AppAuth, fastauth::prelude::BuildError> { todo!() } }
""", base=ACTIX, blocks=[
    block("use actix_web::{App, HttpResponse, HttpServer, web};", """@:1-6
async fn block(pool: PgPool) -> anyhow::Result<()> {
@:8-19
Ok(())
}"""),
    block("use fastauth::actix::OptionalSession;"),
    block("async fn admin_only(session: Session<AppAuth>) -> Result<String, AuthError> {"),
    block("use fastauth::plugins::organization::access::MemberDelete;", """@:1-13
fn block() {
let _app =
@:15-17
;
}"""),
    block("use fastauth::plugins::admin::actix::RequireRole;"),
    block("use fastauth::ApiResponse;"),
])

# ---------------------------------------------------------------- plugins

page("plugins/README.md", "", [
    block("use fastauth::plugins::{admin::Admin, api_key::ApiKeys, organization::Organization, two_factor::TwoFactor};", """@:1-3
fn block(pool: PgPool) -> Result<AppAuth, BuildError> {
@:5-5
""" + SECRETS + """
@:6-12
}"""),
])

ORG = "use fastauth::plugins::organization::Organization;\n" + app_auth("Organization")
ORG_BUILDER = "FastAuth::builder().plugin(Organization::default()).database(MemoryAdapter::new())"

page("plugins/access/01-organization.md", ORG, [
    block("use fastauth::plugins::organization::Organization;", ctx=""),
    block("use fastauth::plugins::organization::{Organization, Roles};", ctx=""),
    block("async fn active_organization(session: Session<AppAuth>) -> String {"),
    block("use fastauth::mail::{AuthEmail, MailError, Mailer};", """async fn send(to: &str, subject: &str, text: &str) -> Result<(), fastauth::mail::MailError> { todo!() }
@"""),
    block("use axum::http::HeaderMap;"),
    block("pub async fn invite(auth: &AppAuth, headers: &HeaderMap, email: &str) -> Result<Id, AuthError> {", "@5\n@"),
    block(".configure(|app| {", chain(ORG_BUILDER),
          ctx=ORG + "use fastauth::plugins::organization::{CreateOrganization, CreateOrganizationInput};\nuse fastauth::plugin_prelude::Before;\n"),
    block("use axum::Router;", "@12\n@", ctx=ORG + "use fastauth::plugins::organization::Permission;\n"),
    block(".on(|e: MemberAdded, ctx: Ctx<_>| async move {", chain(ORG_BUILDER),
          ctx=ORG + "use fastauth::plugins::organization::{Member, MemberAdded};\nuse fastauth::plugin_prelude::Ctx;\n"),
    block("pub fn roles() -> Roles {", "use fastauth::plugins::organization::Roles;\n@"),
    block("let roles = roles();", "use fastauth::plugins::organization::Roles;\n@10\nfn block() {\n@\n}"),
    block("pub struct InvoicePay;", "use fastauth::plugins::organization::Permission;\n@"),
])

ADM = "use fastauth::plugins::admin::Admin;\n" + app_auth("Admin")

page("plugins/access/02-admin.md", ADM, [
    block("use fastauth::plugins::admin::{Admin, Permissions};", ctx=""),
    block("auth.migrator().run().await?;", stmts("auth: AppAuth")),
    block("use fastauth::plugins::admin::{Admin, AdminExt, AdminUser};", """#[derive(Serialize)]
struct Me { email: String, role: Option<String> }
@"""),
    block("Admin::new()", "use fastauth::plugins::admin::Permissions;\n" + expr("_a")),
    block("use fastauth::plugins::admin::{"),
    block("async fn view_as(", ctx=ADM + "use fastauth::plugins::admin::AdminExt;\n"),
    block("use fastauth::plugin_prelude::Before;", """@:1-3
fn block(pool: PgPool) -> Result<AppAuth, BuildError> {
FastAuth::builder()
""" + SECRETS + """
@:5-100
}"""),
    block("use fastauth::plugins::admin::{AdminExt, RequireRole, role};", "@6\n@"),
    block("use fastauth::plugins::admin::{Admin, AdminExt, Permissions};"),
])

page("plugins/access/03-multi-session.md", "use fastauth::plugins::multi_session::MultiSession;\n" + app_auth("MultiSession"), [
    block("use fastauth::plugins::multi_session::MultiSession;", ctx=""),
    block("use fastauth::plugins::multi_session::MultiSessionExt;", autherr("auth: AppAuth, headers: HeaderMap, token: &str")),
])

page("plugins/sign-in/01-magic-link.md", "use fastauth::plugins::magic_link::MagicLink;\n" + app_auth("MagicLink") + "use fastauth::mail::MailError;\n", [
    block("use fastauth::plugins::magic_link::MagicLink;", ctx=""),
    block("use fastauth::mail::{AuthEmail, MailError, Mailer};", """struct MyMailer;
impl MyMailer {
    async fn send_template(&self, id: &str, to: &str, url: &str) -> Result<(), MailError> { todo!() }
    async fn send_plain(&self, to: &str, subject: &str, body: &str) -> Result<(), MailError> { todo!() }
}
@"""),
    block("use fastauth::plugins::magic_link::{MagicLinkExt, SignInMagicLinkInput, VerifyMagicLinkInput};", autherr("auth: AppAuth, headers: HeaderMap, token: String")),
])

page("plugins/sign-in/02-email-otp.md", "use fastauth::plugins::email_otp::EmailOtp;\n" + app_auth("EmailOtp") + "use fastauth::mail::MailError;\n", [
    block("use fastauth::plugins::email_otp::EmailOtp;", ctx=""),
    block("match email {", """struct M;
impl M {
    async fn send_plain(&self, email: AuthEmail) -> Result<(), MailError> { todo!() }
    async fn send_template(&self, kind: impl AsRef<str>, to: &str, code: &str) -> Result<(), MailError> { todo!() }
}
impl Mailer for M {
    async fn send(&self, email: AuthEmail) -> Result<(), MailError> {
@
    }
}"""),
    block("use fastauth::plugins::email_otp::{EmailOtpExt, OtpType, SendOtpInput};", autherr("auth: AppAuth")),
])

page("plugins/sign-in/03-passkey.md", "use fastauth::plugins::passkey::Passkey;\n" + app_auth("Passkey"), [
    block("use fastauth::plugins::passkey::Passkey;", ctx=""),
    block("Passkey::new()", expr("_p")),
    block("use fastauth::plugins::passkey::{Passkey, PasskeyUser};", "@:1-3\nfn block() {\n@:4-100\n}"),
    block("use fastauth::plugins::passkey::{PasskeyExt, UpdatePasskeyInput};", autherr("auth: AppAuth, headers: HeaderMap")),
])

page("plugins/sign-in/04-username.md", "use fastauth::plugins::username::Username;\n" + app_auth("Username"), [
    block("use fastauth::plugins::username::Username;", ctx=""),
    block("use fastauth::plugins::username::{Username, ValidationOrder};", "fn block() {\n@\n}"),
    block("use fastauth::plugins::username::{SignInUsernameInput, UsernameExt};", autherr("auth: AppAuth, headers: HeaderMap")),
])

page("plugins/sign-in/05-anonymous.md", "use fastauth::plugins::anonymous::Anonymous;\n" + app_auth("Anonymous"), [
    block("use fastauth::plugins::anonymous::{Anonymous, LinkAccount};", """#[derive(Clone)]
pub struct Carts;
impl Carts { pub async fn move_to(&self, from: &Id, to: &Id) -> Result<(), std::io::Error> { todo!() } }
@""", ctx=""),
    block("use fastauth::plugins::anonymous::{AnonymousExt, SignInAnonymousOutput};", autherr("auth: AppAuth, headers: HeaderMap")),
])

page("plugins/tokens/01-bearer.md", "use fastauth::plugins::bearer::Bearer;\n" + app_auth("Bearer"), [
    block("use fastauth::plugins::bearer::Bearer;", ctx=""),
    block("async fn me(session: Session<AppAuth>) -> String {"),
    block(".plugin(Bearer::new().require_signature(true))", chain()),
])

page("plugins/tokens/02-jwt.md", "use fastauth::plugins::jwt::Jwt;\n" + app_auth("Jwt"), [
    block("use fastauth::plugins::jwt::Jwt;", ctx=""),
    block("use fastauth::plugin_prelude::SessionView;", "@:1-2\nfn block() {\nlet _j =\n@:4-100\n;\n}"),
    block("pub async fn service_token(auth: &AppAuth) -> Result<String, AuthError> {", "use fastauth::plugins::jwt::JwtExt;\n@"),
    block("use fastauth_plugin_jwt::{JwksVerifier, VerifyError};", ctx=""),
])

AK = """use fastauth::plugins::api_key::{ApiKeys, ApiKey, ApiKeyList, CreateApiKeyInput, CreatedApiKey, ListApiKeysInput, UpdateApiKeyInput, ApiKeyCreated, ApiKeyDeleted, ApiKeysExt, Permissions};
use axum::http::HeaderName;
use fastauth::plugin_prelude::Ctx;
""" + app_auth("ApiKeys")

page("plugins/tokens/03-api-keys.md", AK, [
    block("use fastauth::plugins::api_key::ApiKeys;", ctx=""),
    block("let auth = build(pool)?;", "@1\n" + stmts("pool: PgPool"), ctx=""),
    block("ApiKeys::new()", expr("_a")),
    block("pub async fn issue_ci_key(auth: &AppAuth, user_id: Id) -> Result<CreatedApiKey, AuthError> {"),
    block("pub async fn keys_of(auth: &AppAuth, headers: &HeaderMap) -> Result<ApiKeyList, AuthError> {"),
    block("let mut update = UpdateApiKeyInput::new(key_id);", """async fn block(auth: AppAuth, key_id: Id, user_id: Id) {
let _r = {
@
};
}"""),
    block("pub async fn nightly_cleanup(auth: &AppAuth) -> Result<u64, AuthError> {"),
    block("async fn upload(State(auth): State<AppAuth>, headers: HeaderMap) -> Result<String, Response> {"),
    block(".plugin(ApiKeys::new().sessions(true))", chain()),
    block("async fn whoami(session: Session<AppAuth>) -> Json<Value> {"),
    block("ApiKeys::new()", expr("_a")),
    block(".plugin(ApiKeys::new())", chain("FastAuth::builder().database(MemoryAdapter::new())")),
])

# ---------------------------------------------------------------- reference

# The plugin-authoring page builds one plugin (AccessTokens) across its blocks, so it compiles as one module.
page("reference/01-plugin-authoring.md", """use fastauth::plugin_prelude::*;
use fastauth::plugins::organization::{Organization, OrganizationWithMembers, CreateOrganization};
use fastauth::plugins::admin::AdminSession;
use fastauth::plugins::two_factor::TwoFactor;
use fastauth::routes::{SignUpEmail, SignUpEmailInput, GetSession};
use std::borrow::Cow;
mod disposable { pub fn is_disposable(_: &str) -> bool { false } }
mod stripe { pub async fn create_customer(_: &str) -> Result<(), fastauth::AuthError> { Ok(()) } }
""", [
    block("use fastauth::plugin_prelude::*;"),
    block("impl Plugin for AccessTokens {"),
    block("#[derive(Model, Clone)]"),
    block("#[derive(Fields, Clone, Debug)]"),
    block("pub struct CreateToken(Arc<AccessTokens>);"),
    block("async fn call(&self, ctx: Ctx<D, Authenticated>, input: CreateTokenInput) -> Result<CreatedToken, AuthError> {"),
    block("pub struct ListTokens;"),
    block("struct TokenResolver;"),
    block("#[derive(AuthError, Debug)]"),
    block("#[derive(Clone, Debug)]"),
    block("pub trait AccessTokensExt: AuthInstance + Sized {"),
    block("fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {"),
    block("fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {"),
    block("app.prepare_user_input(|ctx, mut input, kind| async move {"),
    block("fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {"),
    block('let remember_me = if attempt.remember_me { "1" } else { "0" };'),
    block("match ctx"),
    block("app.session_gate(|_ctx, session: SessionView, usage: SessionUse| async move {"),
    block("app.fixed_session_expiry(|session| {"),
    block("app.on_session_created(|ctx, session: SessionView| async move {"),
    block("impl Plugin for OrgBilling {"),
    block("#[cfg(test)]"),
], module="""@1
@2
@3
#[derive(AuthError, Debug)]
#[auth_error(prefix = "BAN")]
pub enum BanError {
    #[auth_error(status = 403, message = "banned")]
    Banned,
    #[auth_error(status = 403, message = "not with this session")]
    NotWithThisSession,
}
fn is_borrowed(_: &SessionView) -> bool { false }
@4
@15
}
@5
pub struct CreateTokenFresh(Arc<AccessTokens>);
async fn mint<D: Adapter, A>(ctx: &Ctx<D, A>, user_id: &Id, name: String) -> Result<(AccessToken, String), AuthError> { todo!() }
impl<D: Adapter> Endpoint<D> for CreateTokenFresh {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/access-token/create";
    type Access = Authenticated;
    type Input = CreateTokenInput;
    type Output = CreatedToken;

@6
}
@7
@8
@9
@10
@11
pub struct Disposable;
impl Plugin for Disposable {
    const ID: &'static str = "disposable";
    type Requires = ();
    type UserFields = ();
    type SessionFields = ();

@12
}
pub struct ClaimTokens;
impl Plugin for ClaimTokens {
    const ID: &'static str = "claim-tokens";
    type Requires = ();
    type UserFields = ();
    type SessionFields = ();

@13
}
fn prepare_user_input<D: Adapter>(app: &mut PluginBuilder<'_, D>) {
@14
}
struct Tfa { two_factor_cookie_max_age: Duration }
const PENDING_PREFIX: &str = "two-factor-pending:";
const PENDING_COOKIE: &str = "two_factor";
async fn two_factor_gate<D: Adapter>(plugin: &Tfa, ctx: HookCtx<D>, attempt: SignInAttempt) -> Result<Gate, AuthError> {
@16
}
enum VerifyOutput { Challenge(serde_json::Value) }
async fn verify_two_factor<D: Adapter>(ctx: &Ctx<D, MaybeAuthenticated>, user: UserView, method: Cow<'static, str>, remember_me: bool) -> Result<VerifyOutput, AuthError> {
let _session =
@17
;
Ok(VerifyOutput::Challenge(json!(null)))
}
fn session_gate<D: Adapter>(app: &mut PluginBuilder<'_, D>) {
@18
}
fn fixed_session_expiry<D: Adapter>(app: &mut PluginBuilder<'_, D>) {
@19
}
fn on_session_created<D: Adapter>(app: &mut PluginBuilder<'_, D>) {
@20
}
pub struct OrgBilling;
@21
@22""")

page("reference/02-internals.md", "", [
    excerpt("pub struct Nil;"),
    excerpt("impl<T> Append<T> for Nil {"),
    excerpt("pub struct Here;"),
    excerpt("#[diagnostic::on_unimplemented("),
    excerpt("impl<L> Satisfied<L, ()> for () {}"),
    excerpt("impl<H: Plugin, T: PluginSet> PluginSet for Cons<H, T> {"),
])
