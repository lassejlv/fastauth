use fastauth_core::crypto::{Argon2id, Secret};
use fastauth_core::plugin_prelude::*;
use fastauth_core::prelude::{EmailPassword, FastAuth, MemoryAdapter, RateLimit};
use fastauth_core::query::Db;
use fastauth_core::routes::SignUpEmailInput;
use fastauth_core::{Auth, plugins};
use serde_json::json;

/// The hand-written impl from `fastauth-core/tests/plugins.rs`.
#[derive(Clone, Debug, PartialEq)]
struct HandBetaUser {
    beta: bool,
}

impl Fields for HandBetaUser {
    fn columns() -> &'static [ColumnDef] {
        const COLUMNS: &[ColumnDef] =
            &[ColumnDef::new("beta", ColumnType::Bool).default(DefaultValue::Bool(false))];
        COLUMNS
    }
    fn decode(row: &Row) -> Result<Self, DecodeError> {
        Ok(Self {
            beta: row.get("beta")?,
        })
    }
}

impl OnTable for HandBetaUser {
    type Table = User;
}

impl HandBetaUser {
    const BETA: Col<HandBetaUser, bool> = Col::new("beta");
}

/// The same struct, derived.
#[derive(Fields, Clone, Debug, PartialEq)]
#[fields(table = User)]
struct BetaUser {
    #[field(default = false, input = false)]
    beta: bool,
}

#[derive(Fields, Clone, Debug, PartialEq)]
struct Profile {
    #[field(default = "free")]
    plan: String,
    #[field(input = false, unique)]
    stripe_customer_id: Option<String>,
    #[field(returned = false)]
    internal_notes: Option<String>,
    #[field(rename = "login_count", default = -1, index, input)]
    logins: i64,
    #[field(default = now, input = false)]
    seen_at: OffsetDateTime,
}

struct Beta;

impl Plugin for Beta {
    const ID: &'static str = "beta";
    type Requires = ();
    type UserFields = BetaUser;
    type SessionFields = ();
}

type AppAuth = Auth<MemoryAdapter, Profile, plugins![Beta]>;

fn app() -> AppAuth {
    FastAuth::builder()
        .secret(Secret::from_bytes(vec![42u8; 32]))
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .user_fields::<Profile>()
        .plugin(Beta)
        .build()
        .expect("valid config")
}

fn sign_up(email: &str, extra: serde_json::Value) -> SignUpEmailInput {
    let serde_json::Value::Object(extra) = extra else {
        panic!("extra must be an object")
    };
    SignUpEmailInput {
        name: "Test User".to_owned(),
        email: email.to_owned(),
        password: "correct horse".to_owned(),
        image: None,
        callback_url: None,
        remember_me: None,
        extra,
    }
}

#[test]
fn derive_matches_the_hand_written_impl() {
    fn on_user<O: OnTable<Table = User>>() {}

    assert_eq!(BetaUser::columns(), HandBetaUser::columns());
    assert_eq!(BetaUser::BETA.name(), HandBetaUser::BETA.name());
    on_user::<BetaUser>();
    on_user::<HandBetaUser>();
}

#[test]
fn attributes_map_to_column_builders() {
    let expected: &[ColumnDef] = &[
        ColumnDef::new("plan", ColumnType::Text)
            .default(DefaultValue::Text("free"))
            .input(),
        ColumnDef::new("stripe_customer_id", ColumnType::Text)
            .nullable()
            .unique(),
        ColumnDef::new("internal_notes", ColumnType::Text)
            .nullable()
            .input()
            .hidden(),
        ColumnDef::new("login_count", ColumnType::Int)
            .default(DefaultValue::Int(-1))
            .index()
            .input(),
        ColumnDef::new("seen_at", ColumnType::Timestamp).default(DefaultValue::Now),
    ];
    assert_eq!(Profile::columns(), expected);
    assert_eq!(Profile::LOGINS.name(), "login_count");
    assert_eq!(Profile::STRIPE_CUSTOMER_ID.name(), "stripe_customer_id");
}

#[tokio::test]
async fn derived_fields_decode_on_the_session() {
    let auth = app();
    let signed_up = auth
        .api()
        .sign_up_email(sign_up(
            "p@acme.dk",
            json!({ "plan": "pro", "internalNotes": "vip" }),
        ))
        .await
        .unwrap()
        .data;
    assert_eq!(signed_up.user["plan"], "pro");
    assert_eq!(signed_up.user["beta"], false);
    assert!(!signed_up.user.contains_key("internalNotes"));

    let token = signed_up.token.unwrap();
    let session = auth.get_session_by_token(&token).await.unwrap().unwrap();
    let fields = &session.user.fields;
    assert_eq!(fields.plan, "pro");
    assert_eq!(fields.internal_notes.as_deref(), Some("vip"));
    assert_eq!(fields.stripe_customer_id, None);
    assert_eq!(fields.logins, -1);
    assert_eq!(session.user.plugin::<Beta, _>(), &BetaUser { beta: false });

    let db = Db::new(auth.adapter(), auth.schema());
    let updated = db
        .update::<User>(Profile::PLAN.eq("pro"))
        .set(BetaUser::BETA, true)
        .exec()
        .await
        .unwrap();
    assert_eq!(updated, 1);
    let session = auth.get_session_by_token(&token).await.unwrap().unwrap();
    assert!(session.user.plugin::<Beta, _>().beta);
}

#[tokio::test]
async fn input_false_fields_reject_client_values() {
    let err = app()
        .api()
        .sign_up_email(sign_up("i@acme.dk", json!({ "beta": true })))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "INVALID_FIELD");
}
