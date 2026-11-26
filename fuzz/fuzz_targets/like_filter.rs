//! The LIKE/GLOB patterns fastauth-sqlx builds for `contains`, `starts_with` and
//! `ends_with`, as a property on SQLite in-process: for any stored names and any needle, the
//! SQL returns exactly the rows a plain Rust filter returns. Wildcards in the needle must
//! match only themselves.

#![no_main]

use std::sync::LazyLock;

use arbitrary::Arbitrary;
use fastauth_core::crypto::Secret;
use fastauth_core::models::User;
use fastauth_core::prelude::*;
use fastauth_core::query::Where;
use fastauth_fuzz::{BASE_URL, RUNTIME, SECRET};
use fastauth_sqlx::{Sqlite, SqlitePool, Sqlx};
use libfuzzer_sys::fuzz_target;

type SqlAuth = Auth<Sqlx<Sqlite>>;

static AUTH: LazyLock<SqlAuth> = LazyLock::new(|| {
    RUNTIME.block_on(async {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("SQLite");
        let auth: SqlAuth = FastAuth::builder()
            .secret(Secret::from_bytes(SECRET.to_vec()))
            .base_url(BASE_URL)
            .database(Sqlx::new(pool))
            .rate_limit(RateLimit::disabled())
            .build()
            .expect("valid config");
        auth.migrator().run().await.expect("migrations");
        auth
    })
});

#[derive(Arbitrary, Debug)]
enum Kind {
    Contains,
    StartsWith,
    EndsWith,
}

#[derive(Arbitrary, Debug)]
struct Input {
    names: Vec<String>,
    needle: String,
    kind: Kind,
}

fuzz_target!(|input: Input| {
    let names = &input.names[..input.names.len().min(12)];
    let needle = &input.needle;
    let auth = &*AUTH;
    let api = auth.api();
    let db = api.db();
    RUNTIME.block_on(async {
        db.delete::<User>(Where::all()).await.expect("delete");
        let now = time::OffsetDateTime::now_utc();
        for (i, name) in names.iter().enumerate() {
            db.insert(&User {
                id: Id::from(format!("u{i}")),
                email: format!("u{i}@acme.dk"),
                email_verified: false,
                name: name.clone(),
                image: None,
                created_at: now,
                updated_at: now,
            })
            .await
            .expect("insert");
        }
        let filter = match input.kind {
            Kind::Contains => User::NAME.contains(needle.clone()),
            Kind::StartsWith => User::NAME.starts_with(needle.clone()),
            Kind::EndsWith => User::NAME.ends_with(needle.clone()),
        };
        let mut found: Vec<String> = db
            .find::<User>(filter)
            .all()
            .await
            .expect("query")
            .into_iter()
            .map(|u| u.id.as_str().to_owned())
            .collect();
        found.sort();
        let mut expected: Vec<String> = names
            .iter()
            .enumerate()
            .filter(|(_, name)| match input.kind {
                Kind::Contains => name.contains(needle.as_str()),
                Kind::StartsWith => name.starts_with(needle.as_str()),
                Kind::EndsWith => name.ends_with(needle.as_str()),
            })
            .map(|(i, _)| format!("u{i}"))
            .collect();
        expected.sort();
        assert_eq!(
            found, expected,
            "{:?} {needle:?} over {names:?}",
            input.kind
        );
    });
});
