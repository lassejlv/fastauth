use fastauth_spike_typed_plugins::plugins::*;
use fastauth_spike_typed_plugins::*;

#[derive(Debug, PartialEq)]
struct Profile {
    plan: String,
}

impl Fields for Profile {
    fn columns() -> &'static [Column] {
        &[Column {
            name: "plan",
            ty: ColumnType::Text,
            default: Some(DefaultValue::Text("free")),
        }]
    }
    fn decode(record: &Record) -> Result<Self, AuthError> {
        Ok(Self {
            plan: text(record, "plan")?,
        })
    }
}

type AppAuth = Auth<MemoryAdapter, Profile, plugins![TwoFactor, Organization, OrgBilling]>;

fn app() -> AppAuth {
    builder(MemoryAdapter::default())
        .user_fields::<Profile>()
        .plugin(TwoFactor {
            issuer: "Acme".to_owned(),
        })
        .plugin(Organization {
            allow_user_to_create: true,
        })
        .plugin(OrgBilling)
        .build()
        .expect("valid config")
}

fn post(path: &str, bearer: Option<&str>, body: &str) -> Request {
    Request {
        method: Method::Post,
        path: path.to_owned(),
        bearer: bearer.map(str::to_owned),
        body: body.as_bytes().to_vec(),
    }
}

#[tokio::test]
async fn http_flow_updates_typed_plugin_fields() {
    let auth = app();
    let res = auth
        .handle(post(
            "/sign-up/email",
            None,
            r#"{"email":"a@b.dk","name":"Lasse"}"#,
        ))
        .await;
    assert_eq!(res.status, 200);
    let token = serde_json::from_slice::<serde_json::Value>(&res.body).unwrap()["token"]
        .as_str()
        .unwrap()
        .to_owned();

    let before = auth.get_session(&token).await.unwrap().unwrap();
    assert!(!before.user.plugin::<TwoFactor, _>().two_factor_enabled);
    assert_eq!(
        before.user.fields,
        Profile {
            plan: "free".to_owned()
        }
    );

    let res = auth
        .handle(post("/two-factor/enable", Some(&token), "{}"))
        .await;
    assert_eq!(res.status, 200, "{}", String::from_utf8_lossy(&res.body));

    let after = auth.get_session(&token).await.unwrap().unwrap();
    assert!(after.user.plugin::<TwoFactor, _>().two_factor_enabled);
}

#[tokio::test]
async fn server_side_api_skips_json() {
    let auth = app();
    let out = auth
        .sign_up_email(SignUpEmailInput {
            email: "x@y.dk".into(),
            name: "X".into(),
        })
        .await
        .unwrap();
    let enabled = auth.two_factor().enable(&out.token).await.unwrap();
    assert!(enabled.totp_uri.starts_with("otpauth://totp/Acme:"));
}

#[tokio::test]
async fn plugin_reads_its_dependency_without_fallible_lookup() {
    let res = app()
        .handle(Request {
            method: Method::Get,
            path: "/org-billing/status".into(),
            bearer: None,
            body: b"null".to_vec(),
        })
        .await;
    assert_eq!(
        String::from_utf8(res.body).unwrap(),
        r#"{"orgs_self_serve":true}"#
    );
}

#[tokio::test]
async fn errors_are_json_with_codes() {
    let res = app().handle(post("/two-factor/enable", None, "{}")).await;
    assert_eq!(res.status, 401);
    assert_eq!(
        String::from_utf8(res.body).unwrap(),
        r#"{"code":"UNAUTHORIZED","message":"a valid session is required"}"#
    );
}

#[test]
fn schema_merges_app_and_plugin_columns() {
    let auth = app();
    let user: Vec<_> = auth.schema().tables["user"]
        .iter()
        .map(|c| (c.column.name, c.owner))
        .collect();
    assert_eq!(
        user,
        [
            ("id", "core"),
            ("email", "core"),
            ("name", "core"),
            ("plan", "app"),
            ("two_factor_enabled", "two-factor"),
        ]
    );
    assert!(auth.schema().tables.contains_key("two_factor"));
    assert!(auth.schema().tables.contains_key("organization"));
}

#[test]
fn column_clash_is_a_build_error() {
    struct Clash;
    impl Fields for Clash {
        fn columns() -> &'static [Column] {
            &[Column {
                name: "two_factor_enabled",
                ty: ColumnType::Bool,
                default: None,
            }]
        }
        fn decode(_: &Record) -> Result<Self, AuthError> {
            Ok(Clash)
        }
    }
    let Err(err) = builder(MemoryAdapter::default())
        .user_fields::<Clash>()
        .plugin(TwoFactor::default())
        .build()
    else {
        panic!("clash should fail the build");
    };
    assert_eq!(
        err.0,
        ["column `user.two_factor_enabled` is defined by both `app` and `two-factor`"]
    );
}
