use fastauth_core::crypto::Secret;
use fastauth_core::models::Verification;
use fastauth_core::plugin_prelude::*;
use fastauth_core::prelude::{FastAuth, MemoryAdapter};
use fastauth_core::query::Db;
use time::macros::datetime;

#[derive(Model, Clone, Debug, PartialEq)]
#[model(table = "api_key")]
struct ApiKey {
    #[model(id)]
    id: Id,
    #[model(references = User, on_delete = Cascade, index)]
    user_id: Id,
    name: String,
    #[model(unique, hidden)]
    key_hash: Hash,
    scopes: Json<Vec<String>>,
    expires_at: Option<OffsetDateTime>,
    #[model(default = 0)]
    uses: i64,
    #[model(default = now)]
    created_at: OffsetDateTime,
}

struct ApiKeys;

impl Plugin for ApiKeys {
    const ID: &'static str = "api-key";
    type Requires = ();
    type UserFields = ();
    type SessionFields = ();

    fn schema(&self, schema: &mut SchemaBuilder) {
        schema.model::<ApiKey>();
    }
}

/// Core's `session` and `verification` tables, derived instead of written by hand.
#[derive(Model, Clone)]
#[model(table = "session")]
struct DerivedSession {
    #[model(id)]
    id: Id,
    #[model(unique, hidden)]
    token_hash: Hash,
    #[model(references = User, on_delete = Cascade, index)]
    user_id: Id,
    expires_at: OffsetDateTime,
    ip_address: Option<String>,
    user_agent: Option<String>,
    #[model(default = now)]
    created_at: OffsetDateTime,
    #[model(default = now)]
    updated_at: OffsetDateTime,
}

#[derive(Model, Clone)]
#[model(table = "verification")]
struct DerivedVerification {
    #[model(id)]
    id: Id,
    #[model(index)]
    identifier: String,
    #[model(unique, hidden)]
    value_hash: Hash,
    #[model(hidden)]
    data: Option<String>,
    expires_at: OffsetDateTime,
    #[model(default = now)]
    created_at: OffsetDateTime,
    #[model(default = now)]
    updated_at: OffsetDateTime,
}

fn key(user_id: &Id, name: &str, created_at: OffsetDateTime) -> ApiKey {
    ApiKey {
        id: Id::new_v7(),
        user_id: user_id.clone(),
        name: name.to_owned(),
        key_hash: Hash::sha256(name),
        scopes: Json(vec!["read".to_owned()]),
        expires_at: None,
        uses: 0,
        created_at,
    }
}

#[test]
fn derive_matches_core_models() {
    assert_eq!(DerivedSession::TABLE, Session::TABLE);
    assert_eq!(DerivedSession::columns(), Session::columns());
    assert_eq!(DerivedVerification::TABLE, Verification::TABLE);
    assert_eq!(DerivedVerification::columns(), Verification::columns());

    let now = datetime!(2026-11-25 12:00 UTC);
    let session = Session {
        id: Id::from("s1"),
        token_hash: Hash::sha256("token"),
        user_id: Id::from("u1"),
        expires_at: now,
        ip_address: Some("127.0.0.1".to_owned()),
        user_agent: None,
        created_at: now,
        updated_at: now,
    };
    let derived = DerivedSession {
        id: session.id.clone(),
        token_hash: session.token_hash,
        user_id: session.user_id.clone(),
        expires_at: now,
        ip_address: session.ip_address.clone(),
        user_agent: None,
        created_at: now,
        updated_at: now,
    };
    assert_eq!(derived.encode(), session.encode());
}

#[test]
fn columns_carry_the_attributes() {
    let columns = ApiKey::columns();
    let column = |name: &str| columns.iter().find(|c| c.name == name).unwrap();
    assert!(column("id").primary_key);
    let user_id = column("user_id");
    assert!(user_id.index);
    let reference = user_id.references.unwrap();
    assert_eq!(
        (reference.table, reference.column, reference.on_delete),
        ("user", "id", OnDelete::Cascade)
    );
    assert!(column("key_hash").unique && !column("key_hash").returned);
    assert_eq!(column("scopes").ty, ColumnType::Json);
    assert!(column("expires_at").nullable);
    assert!(!column("name").nullable && !column("name").input);
    assert_eq!(column("uses").default, Some(DefaultValue::Int(0)));
    assert_eq!(column("created_at").default, Some(DefaultValue::Now));
    assert_eq!(ApiKey::KEY_HASH.name(), "key_hash");
}

#[tokio::test]
async fn round_trip_through_a_plugin_schema() {
    let auth = FastAuth::builder()
        .secret(Secret::from_bytes(vec![42u8; 32]))
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .plugin(ApiKeys)
        .build()
        .expect("valid config");
    assert_eq!(auth.schema().table("api_key").unwrap().owner, "api-key");

    let db = Db::new(auth.adapter(), auth.schema());
    let (alice, bob) = (Id::new_v7(), Id::new_v7());
    let older = key(&alice, "ci", datetime!(2026-11-24 12:00 UTC));
    let newer = key(&alice, "deploy", datetime!(2026-11-25 12:00 UTC));
    for row in [&older, &newer, &key(&bob, "laptop", older.created_at)] {
        assert_eq!(&db.insert(row).await.unwrap(), row);
    }

    let found = db
        .find::<ApiKey>(ApiKey::KEY_HASH.eq(Hash::sha256("deploy")))
        .one()
        .await
        .unwrap();
    assert_eq!(found, Some(newer.clone()));

    let alices = db
        .find::<ApiKey>(ApiKey::USER_ID.eq(&alice).and(ApiKey::EXPIRES_AT.is_null()))
        .order_by(ApiKey::CREATED_AT.desc())
        .all()
        .await
        .unwrap();
    assert_eq!(alices, vec![newer.clone(), older]);

    db.update::<ApiKey>(ApiKey::ID.eq(&newer.id))
        .set(ApiKey::USES, 3)
        .exec()
        .await
        .unwrap();
    assert_eq!(
        db.count::<ApiKey>(ApiKey::USES.gt(0)).await.unwrap(),
        1,
        "filters on a generated column"
    );
}
