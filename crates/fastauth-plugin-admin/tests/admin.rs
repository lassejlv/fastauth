mod common;

use common::{Client, Res, secret};
use fastauth_core::crypto::Argon2id;
use fastauth_core::model::Fields;
use fastauth_core::prelude::*;
use fastauth_core::query::Db;
use fastauth_plugin_admin::{
    Admin, AdminExt, AdminSession, AdminUser, BanUserInput, CreateUserInput, ListUsersQuery,
    Permissions, SearchOperator, SortDirection, WhereOperator,
};
use http::StatusCode;
use serde_json::{Value, json};
use time::OffsetDateTime;

type Plugins = plugins![Admin];
type AppAuth = Auth<MemoryAdapter, (), Plugins>;

const PASSWORD: &str = "correct horse";

fn build(admin: Admin) -> AppAuth {
    build_on(MemoryAdapter::new(), admin)
}

fn build_on(db: MemoryAdapter, admin: Admin) -> AppAuth {
    FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(db)
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .plugin(admin)
        .build()
        .expect("valid config")
}

fn db(auth: &AppAuth) -> Db<'_, MemoryAdapter> {
    Db::new(auth.adapter(), auth.schema())
}

/// A browser signed up as `email`, and the user's id.
async fn signed_up(auth: &AppAuth, email: &str) -> (Client<MemoryAdapter, (), Plugins>, Id) {
    let mut browser = Client::new(auth.clone());
    let res = browser.sign_up(email, PASSWORD).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let id = Id::from(res.json["user"]["id"].as_str().unwrap());
    (browser, id)
}

/// An admin's browser, a plain user's browser, and the plain user's id.
async fn admin_and_user(
    auth: &AppAuth,
) -> (
    Client<MemoryAdapter, (), Plugins>,
    Client<MemoryAdapter, (), Plugins>,
    Id,
) {
    let (admin, admin_id) = signed_up(auth, "root@acme.dk").await;
    auth.admin().set_role(&admin_id, "admin").await.unwrap();
    let (user, user_id) = signed_up(auth, "bob@acme.dk").await;
    (admin, user, user_id)
}

async fn sign_in(
    browser: &mut Client<MemoryAdapter, (), Plugins>,
    email: &str,
    password: &str,
) -> Res {
    browser
        .post(
            "/sign-in/email",
            json!({ "email": email, "password": password }),
        )
        .await
}

fn assert_error(res: &Res, status: u16, code: &str) {
    assert_eq!(res.status.as_u16(), status, "{}", res.json);
    assert_eq!(res.json["code"], code, "{}", res.json);
}

async fn fields(auth: &AppAuth, id: &Id) -> AdminUser {
    db(auth)
        .find::<User>(User::ID.eq(id))
        .one_row()
        .await
        .unwrap()
        .map(|row| AdminUser::decode(&row).unwrap())
        .expect("user exists")
}

#[tokio::test]
async fn new_users_get_the_default_role() {
    let auth = build(Admin::new());
    let (mut browser, id) = signed_up(&auth, "ada@acme.dk").await;
    let session = browser.get("/get-session").await;
    assert_eq!(session.json["user"]["role"], "user");
    assert_eq!(session.json["user"]["banned"], false);
    assert_eq!(session.json["session"]["impersonatedBy"], Value::Null);
    assert_eq!(fields(&auth, &id).await.role.as_deref(), Some("user"));

    let custom = build(
        Admin::new()
            .role("member", Permissions::new())
            .default_role("member"),
    );
    let (_, id) = signed_up(&custom, "ada@acme.dk").await;
    assert_eq!(
        custom.admin().get_user(&id).await.unwrap().to_json()["role"],
        "member"
    );
}

#[tokio::test]
async fn admin_fields_are_not_client_settable() {
    let auth = build(Admin::new());
    let mut browser = Client::new(auth.clone());
    let res = browser
        .post(
            "/sign-up/email",
            json!({ "email": "eve@acme.dk", "password": PASSWORD, "name": "Eve", "role": "admin" }),
        )
        .await;
    assert_error(&res, 400, "INVALID_FIELD");

    let (mut eve, _) = signed_up(&auth, "eve@acme.dk").await;
    let res = eve.post("/update-user", json!({ "banned": false })).await;
    assert_error(&res, 400, "INVALID_FIELD");
}

#[tokio::test]
async fn non_admins_are_denied_with_better_auths_codes() {
    let auth = build(Admin::new());
    let (_, mut user, user_id) = admin_and_user(&auth).await;
    let id = user_id.to_string();
    let cases = [
        (
            "/admin/create-user",
            json!({ "email": "x@acme.dk", "name": "X" }),
            "YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS",
        ),
        (
            "/admin/set-role",
            json!({ "userId": id, "role": "admin" }),
            "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE",
        ),
        (
            "/admin/ban-user",
            json!({ "userId": id }),
            "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS",
        ),
        (
            "/admin/unban-user",
            json!({ "userId": id }),
            "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS",
        ),
        (
            "/admin/update-user",
            json!({ "userId": id, "data": { "name": "X" } }),
            "YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS",
        ),
        (
            "/admin/set-user-password",
            json!({ "userId": id, "newPassword": "new password" }),
            "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD",
        ),
        (
            "/admin/remove-user",
            json!({ "userId": id }),
            "YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS",
        ),
        (
            "/admin/list-user-sessions",
            json!({ "userId": id }),
            "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS",
        ),
        (
            "/admin/revoke-user-session",
            json!({ "sessionToken": "t" }),
            "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS",
        ),
        (
            "/admin/revoke-user-sessions",
            json!({ "userId": id }),
            "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS",
        ),
        (
            "/admin/impersonate-user",
            json!({ "userId": id }),
            "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS",
        ),
    ];
    let mut anonymous = Client::new(auth.clone());
    for (path, body, code) in cases {
        let res = user.post(path, body.clone()).await;
        assert_error(&res, 403, code);
        let res = anonymous.post(path, body).await;
        assert_error(&res, 401, "UNAUTHORIZED");
    }
    let res = user.get("/admin/list-users").await;
    assert_error(&res, 403, "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS");
    let res = user.get(&format!("/admin/get-user?id={id}")).await;
    assert_error(&res, 403, "YOU_ARE_NOT_ALLOWED_TO_GET_USER");
    let res = anonymous.get("/admin/list-users").await;
    assert_error(&res, 401, "UNAUTHORIZED");
}

#[tokio::test]
async fn admins_create_users() {
    let auth = build(Admin::new());
    let (mut admin, _, _) = admin_and_user(&auth).await;

    let res = admin
        .post(
            "/admin/create-user",
            json!({
                "email": "  Carol@Acme.dk ",
                "password": "carols password",
                "name": "Carol",
                "role": ["admin", "user"],
                "data": { "emailVerified": true, "banReason": null }
            }),
        )
        .await;
    assert_eq!(res.status, 200, "{}", res.json);
    assert_eq!(res.json["user"]["email"], "carol@acme.dk");
    assert_eq!(res.json["user"]["role"], "admin,user");
    assert_eq!(res.json["user"]["emailVerified"], true);
    let mut carol = Client::new(auth.clone());
    let res = sign_in(&mut carol, "carol@acme.dk", "carols password").await;
    assert_eq!(res.status, 200, "{}", res.json);

    let res = admin
        .post(
            "/admin/create-user",
            json!({ "email": "dan@acme.dk", "name": "Dan" }),
        )
        .await;
    assert_eq!(res.json["user"]["role"], "user");

    let res = admin
        .post(
            "/admin/create-user",
            json!({ "email": "dan@acme.dk", "name": "Dan" }),
        )
        .await;
    assert_error(&res, 400, "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL");
    let res = admin
        .post(
            "/admin/create-user",
            json!({ "email": "eve@acme.dk", "name": "Eve", "role": "owner" }),
        )
        .await;
    assert_error(&res, 400, "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE");
    let res = admin
        .post(
            "/admin/create-user",
            json!({ "email": "eve@acme.dk", "name": "Eve", "data": { "role": 7 } }),
        )
        .await;
    assert_error(&res, 400, "INVALID_ROLE_TYPE");
    let res = admin
        .post(
            "/admin/create-user",
            json!({ "email": "not-an-email", "name": "Eve" }),
        )
        .await;
    assert_error(&res, 400, "INVALID_EMAIL");
    let res = admin
        .post(
            "/admin/create-user",
            json!({ "email": "eve@acme.dk", "name": "Eve", "password": "short" }),
        )
        .await;
    assert_error(&res, 400, "PASSWORD_TOO_SHORT");
}

#[tokio::test]
async fn a_role_without_set_role_cant_pick_roles_on_create() {
    let auth = build(Admin::new().role("support", Permissions::new().allow("user", ["create"])));
    let (mut support, support_id) = signed_up(&auth, "help@acme.dk").await;
    auth.admin().set_role(&support_id, "support").await.unwrap();

    let res = support
        .post(
            "/admin/create-user",
            json!({ "email": "x@acme.dk", "name": "X" }),
        )
        .await;
    assert_eq!(res.status, 200, "{}", res.json);
    let res = support
        .post(
            "/admin/create-user",
            json!({ "email": "y@acme.dk", "name": "Y", "role": "admin" }),
        )
        .await;
    assert_error(&res, 403, "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE");
    let res = support
        .post(
            "/admin/create-user",
            json!({ "email": "y@acme.dk", "name": "Y", "data": { "banned": true } }),
        )
        .await;
    assert_error(&res, 403, "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS");
}

#[tokio::test]
async fn list_users_searches_filters_sorts_and_pages() {
    let auth = build(Admin::new());
    let (mut admin, _, bob) = admin_and_user(&auth).await;
    for (email, name) in [
        ("ann@acme.dk", "Ann"),
        ("cat@other.io", "Cat"),
        ("dot@acme.dk", "Dot"),
    ] {
        auth.admin()
            .create_user(CreateUserInput {
                email: email.into(),
                name: name.into(),
                ..CreateUserInput::default()
            })
            .await
            .unwrap();
    }
    auth.admin()
        .ban(BanUserInput::new(bob.clone()))
        .await
        .unwrap();

    let emails = |res: &Res| -> Vec<String> {
        res.json["users"]
            .as_array()
            .unwrap()
            .iter()
            .map(|u| u["email"].as_str().unwrap().to_owned())
            .collect()
    };

    let res = admin.get("/admin/list-users").await;
    assert_eq!(res.status, 200, "{}", res.json);
    assert_eq!(res.json["total"], 5);
    assert!(res.json.get("limit").is_none());

    let res = admin
        .get("/admin/list-users?searchValue=ACME&sortBy=email&sortDirection=desc&limit=2&offset=1")
        .await;
    assert_eq!(res.json["total"], 4);
    assert_eq!(emails(&res), ["dot@acme.dk", "bob@acme.dk"]);
    assert_eq!(res.json["limit"], 2);
    assert_eq!(res.json["offset"], 1);

    let res = admin
        .get("/admin/list-users?searchValue=c&searchField=name&searchOperator=starts_with")
        .await;
    assert_eq!(emails(&res), ["cat@other.io"]);
    let res = admin
        .get("/admin/list-users?searchValue=.io&searchOperator=ends_with")
        .await;
    assert_eq!(emails(&res), ["cat@other.io"]);

    let res = admin
        .get("/admin/list-users?filterField=banned&filterValue=true")
        .await;
    assert_eq!(emails(&res), ["bob@acme.dk"]);
    assert_eq!(res.json["total"], 1);
    let res = admin
        .get("/admin/list-users?filterField=role&filterValue=admin&filterOperator=ne&sortBy=email")
        .await;
    assert_eq!(
        emails(&res),
        ["ann@acme.dk", "bob@acme.dk", "cat@other.io", "dot@acme.dk"]
    );
    let res = admin
        .get("/admin/list-users?filterValue=ann@acme.dk,dot@acme.dk&filterOperator=in&sortBy=email")
        .await;
    assert_eq!(emails(&res), ["ann@acme.dk", "dot@acme.dk"]);
    let res = admin
        .get("/admin/list-users?filterField=name&filterValue=T&filterOperator=contains&searchValue=acme")
        .await;
    assert_eq!(emails(&res), ["root@acme.dk", "bob@acme.dk", "dot@acme.dk"]);

    let res = admin.get("/admin/list-users?sortBy=password").await;
    assert_error(&res, 400, "INVALID_FIELD");

    let list = auth
        .admin()
        .list_users(ListUsersQuery {
            search_value: Some("acme".into()),
            search_operator: Some(SearchOperator::Contains),
            filter_field: Some("banned".into()),
            filter_value: Some("false".into()),
            filter_operator: Some(WhereOperator::Eq),
            sort_by: Some("name".into()),
            sort_direction: Some(SortDirection::Asc),
            ..ListUsersQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(list.total, 3);
}

#[tokio::test]
async fn get_user_and_set_role() {
    let auth = build(Admin::new().role("support", Permissions::new()));
    let (mut admin, _, bob) = admin_and_user(&auth).await;

    let res = admin.get(&format!("/admin/get-user?id={bob}")).await;
    assert_eq!(res.status, 200, "{}", res.json);
    assert_eq!(res.json["email"], "bob@acme.dk");
    let res = admin.get("/admin/get-user?id=nobody").await;
    assert_error(&res, 404, "USER_NOT_FOUND");

    let res = admin
        .post(
            "/admin/set-role",
            json!({ "userId": bob, "role": ["support", "user"] }),
        )
        .await;
    assert_eq!(res.status, 200, "{}", res.json);
    assert_eq!(res.json["user"]["role"], "support,user");
    let res = admin
        .post("/admin/set-role", json!({ "userId": bob, "role": "owner" }))
        .await;
    assert_error(&res, 400, "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE");
    let res = admin
        .post(
            "/admin/set-role",
            json!({ "userId": "nobody", "role": "user" }),
        )
        .await;
    assert_error(&res, 404, "USER_NOT_FOUND");
}

#[tokio::test]
async fn update_user_sets_columns_with_the_matching_permissions() {
    let auth = build(Admin::new());
    let (mut admin, mut bob_browser, bob) = admin_and_user(&auth).await;
    let root = Id::from(
        admin.get("/get-session").await.json["user"]["id"]
            .as_str()
            .unwrap(),
    );

    let res = admin
        .post(
            "/admin/update-user",
            json!({ "userId": bob, "data": { "name": "Robert", "email": "Robert@Acme.dk", "role": "admin" } }),
        )
        .await;
    assert_eq!(res.status, 200, "{}", res.json);
    assert_eq!(res.json["name"], "Robert");
    assert_eq!(res.json["email"], "robert@acme.dk");
    assert_eq!(res.json["role"], "admin");

    for (data, code) in [
        (json!({}), "NO_DATA_TO_UPDATE"),
        (
            json!({ "password": "x" }),
            "PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER",
        ),
        (json!({ "id": "x" }), "USER_ID_CANNOT_BE_UPDATED"),
        (
            json!({ "email": "root@acme.dk" }),
            "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL",
        ),
        (
            json!({ "role": "owner" }),
            "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE",
        ),
        (json!({ "nope": 1 }), "INVALID_FIELD"),
        (json!({ "banned": "yes" }), "INVALID_FIELD"),
    ] {
        let res = admin
            .post("/admin/update-user", json!({ "userId": bob, "data": data }))
            .await;
        assert_error(&res, 400, code);
    }
    let res = admin
        .post(
            "/admin/update-user",
            json!({ "userId": root, "data": { "banned": true } }),
        )
        .await;
    assert_error(&res, 400, "YOU_CANNOT_BAN_YOURSELF");

    let res = admin
        .post(
            "/admin/update-user",
            json!({ "userId": bob, "data": { "banned": true, "banReason": "spam", "banExpires": "2099-01-01T00:00:00.000Z" } }),
        )
        .await;
    assert_eq!(res.status, 200, "{}", res.json);
    assert_eq!(res.json["banReason"], "spam");
    assert_eq!(
        bob_browser.get("/get-session").await.json,
        Value::Null,
        "banning through update-user revokes sessions"
    );
}

#[tokio::test]
async fn set_user_password_and_remove_user() {
    let auth = build(Admin::new());
    let (mut admin, _, bob) = admin_and_user(&auth).await;
    let root = Id::from(
        admin.get("/get-session").await.json["user"]["id"]
            .as_str()
            .unwrap(),
    );

    let res = admin
        .post(
            "/admin/set-user-password",
            json!({ "userId": bob, "newPassword": "brand new password" }),
        )
        .await;
    assert_eq!(res.status, 200, "{}", res.json);
    assert_eq!(res.json["status"], true);
    let mut browser = Client::new(auth.clone());
    assert_eq!(
        sign_in(&mut browser, "bob@acme.dk", PASSWORD).await.status,
        401
    );
    assert_eq!(
        sign_in(&mut browser, "bob@acme.dk", "brand new password")
            .await
            .status,
        200
    );
    let res = admin
        .post(
            "/admin/set-user-password",
            json!({ "userId": bob, "newPassword": "short" }),
        )
        .await;
    assert_error(&res, 400, "PASSWORD_TOO_SHORT");

    let passwordless = auth
        .admin()
        .create_user(CreateUserInput {
            email: "sso@acme.dk".into(),
            name: "SSO".into(),
            ..CreateUserInput::default()
        })
        .await
        .unwrap();
    auth.admin()
        .set_user_password(&passwordless.id, "now with a password")
        .await
        .unwrap();
    assert_eq!(
        sign_in(
            &mut Client::new(auth.clone()),
            "sso@acme.dk",
            "now with a password"
        )
        .await
        .status,
        200
    );

    let res = admin
        .post("/admin/remove-user", json!({ "userId": root }))
        .await;
    assert_error(&res, 400, "YOU_CANNOT_REMOVE_YOURSELF");
    let res = admin
        .post("/admin/remove-user", json!({ "userId": bob }))
        .await;
    assert_eq!(res.json, json!({ "success": true }));
    assert_eq!(browser.get("/get-session").await.json, Value::Null);
    assert!(
        db(&auth)
            .find::<Account>(Account::USER_ID.eq(&bob))
            .one()
            .await
            .unwrap()
            .is_none()
    );
    let res = admin
        .post("/admin/remove-user", json!({ "userId": bob }))
        .await;
    assert_error(&res, 404, "USER_NOT_FOUND");
}

#[tokio::test]
async fn admins_list_and_revoke_user_sessions() {
    let auth = build(Admin::new());
    let (mut admin, mut bob_browser, bob) = admin_and_user(&auth).await;
    let mut second = Client::new(auth.clone());
    let token = sign_in(&mut second, "bob@acme.dk", PASSWORD).await.json["token"]
        .as_str()
        .unwrap()
        .to_owned();

    let res = admin
        .post("/admin/list-user-sessions", json!({ "userId": bob }))
        .await;
    assert_eq!(res.status, 200, "{}", res.json);
    let sessions = res.json["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 2);
    assert_eq!(sessions[0]["userId"], bob.as_str());
    assert!(sessions[0].get("tokenHash").is_none());

    let res = admin
        .post(
            "/admin/revoke-user-session",
            json!({ "sessionToken": token }),
        )
        .await;
    assert_eq!(res.json, json!({ "success": true }));
    assert_eq!(second.get("/get-session").await.json, Value::Null);
    assert_ne!(bob_browser.get("/get-session").await.json, Value::Null);

    let res = admin
        .post("/admin/revoke-user-sessions", json!({ "userId": bob }))
        .await;
    assert_eq!(res.json, json!({ "success": true }));
    assert_eq!(bob_browser.get("/get-session").await.json, Value::Null);
    let res = admin
        .post("/admin/list-user-sessions", json!({ "userId": bob }))
        .await;
    assert_eq!(res.json["sessions"], json!([]));
}

#[tokio::test]
async fn a_ban_without_expiry_blocks_sign_in_until_unbanned() {
    let auth = build(Admin::new().banned_user_message("You are banned."));
    let (mut admin, mut bob_browser, bob) = admin_and_user(&auth).await;
    let root = Id::from(
        admin.get("/get-session").await.json["user"]["id"]
            .as_str()
            .unwrap(),
    );

    let res = admin
        .post(
            "/admin/ban-user",
            json!({ "userId": bob, "banReason": "spamming" }),
        )
        .await;
    assert_eq!(res.status, 200, "{}", res.json);
    assert_eq!(res.json["user"]["banned"], true);
    assert_eq!(res.json["user"]["banReason"], "spamming");
    assert_eq!(res.json["user"]["banExpires"], Value::Null);
    assert_eq!(
        bob_browser.get("/get-session").await.json,
        Value::Null,
        "sessions revoked"
    );

    let res = sign_in(&mut bob_browser, "bob@acme.dk", PASSWORD).await;
    assert_error(&res, 403, "BANNED_USER");
    assert_eq!(res.json["message"], "You are banned. Reason: spamming");
    assert!(!bob_browser.jar.keys().any(|k| k.ends_with("session_token")));

    let res = admin
        .post("/admin/ban-user", json!({ "userId": root }))
        .await;
    assert_error(&res, 400, "YOU_CANNOT_BAN_YOURSELF");
    let res = admin
        .post("/admin/ban-user", json!({ "userId": "nobody" }))
        .await;
    assert_error(&res, 404, "USER_NOT_FOUND");

    let res = admin
        .post("/admin/unban-user", json!({ "userId": bob }))
        .await;
    assert_eq!(res.json["user"]["banned"], false);
    assert_eq!(res.json["user"]["banReason"], Value::Null);
    assert_eq!(
        sign_in(&mut bob_browser, "bob@acme.dk", PASSWORD)
            .await
            .status,
        200
    );
}

#[tokio::test]
async fn a_ban_with_expiry_lifts_at_the_next_sign_in() {
    let auth = build(
        Admin::new()
            .default_ban_reason("rules")
            .default_ban_expires_in(Duration::days(7)),
    );
    let (mut admin, mut bob_browser, bob) = admin_and_user(&auth).await;

    let res = admin
        .post("/admin/ban-user", json!({ "userId": bob }))
        .await;
    assert_eq!(res.json["user"]["banReason"], "rules");
    let expires = fields(&auth, &bob)
        .await
        .ban_expires
        .expect("default expiry");
    assert!(expires > OffsetDateTime::now_utc() + Duration::days(6));
    let res = admin
        .post(
            "/admin/ban-user",
            json!({ "userId": bob, "banExpiresIn": 60 }),
        )
        .await;
    assert_eq!(res.status, 200);
    let expires = fields(&auth, &bob).await.ban_expires.unwrap();
    assert!(expires < OffsetDateTime::now_utc() + Duration::seconds(61));
    assert_error(
        &sign_in(&mut bob_browser, "bob@acme.dk", PASSWORD).await,
        403,
        "BANNED_USER",
    );

    db(&auth)
        .update::<User>(User::ID.eq(&bob))
        .set(
            AdminUser::BAN_EXPIRES,
            Some(OffsetDateTime::now_utc() - Duration::seconds(1)),
        )
        .exec()
        .await
        .unwrap();
    assert_eq!(
        sign_in(&mut bob_browser, "bob@acme.dk", PASSWORD)
            .await
            .status,
        200
    );
    let lifted = fields(&auth, &bob).await;
    assert!(!lifted.banned);
    assert_eq!(lifted.ban_reason, None);
    assert_eq!(lifted.ban_expires, None);
}

#[tokio::test]
async fn admins_impersonate_and_stop() {
    let auth = build(Admin::new().impersonation_session_duration(Duration::minutes(10)));
    let (mut admin, _, bob) = admin_and_user(&auth).await;
    let root = admin.get("/get-session").await.json;
    let root_id = root["user"]["id"].as_str().unwrap().to_owned();

    let res = admin
        .post("/admin/impersonate-user", json!({ "userId": bob }))
        .await;
    assert_eq!(res.status, 200, "{}", res.json);
    assert_eq!(res.json["user"]["email"], "bob@acme.dk");
    assert_eq!(res.json["session"]["impersonatedBy"], root_id.as_str());
    assert!(res.json["session"]["token"].is_string());
    assert!(admin.jar.contains_key("fastauth.admin_session"));

    let session = admin.get("/get-session").await.json;
    assert_eq!(session["user"]["email"], "bob@acme.dk");
    assert_eq!(session["session"]["impersonatedBy"], root_id.as_str());
    let expires = OffsetDateTime::parse(
        session["session"]["expiresAt"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    assert!(expires <= OffsetDateTime::now_utc() + Duration::minutes(10));

    let listed = admin.get("/list-sessions").await.json;
    let listed = listed.as_array().unwrap();
    assert_eq!(listed.len(), 1, "only bob's own session: {listed:?}");
    assert_eq!(listed[0]["impersonatedBy"], Value::Null);

    let res = admin
        .post("/admin/impersonate-user", json!({ "userId": root_id }))
        .await;
    assert_error(&res, 403, "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS");

    let res = admin.post("/admin/stop-impersonating", json!({})).await;
    assert_eq!(res.status, 200, "{}", res.json);
    assert_eq!(res.json["user"]["email"], "root@acme.dk");
    assert_eq!(res.json["session"]["id"], root["session"]["id"]);
    assert!(!admin.jar.contains_key("fastauth.admin_session"));
    let back = admin.get("/get-session").await.json;
    assert_eq!(back["session"]["id"], root["session"]["id"]);
    let sessions = db(&auth)
        .find::<Session>(Session::USER_ID.eq(&bob))
        .all_rows()
        .await
        .unwrap();
    assert!(
        sessions
            .iter()
            .all(|row| AdminSession::decode(row).unwrap().impersonated_by.is_none()),
        "the impersonation session is gone"
    );

    let res = admin.post("/admin/stop-impersonating", json!({})).await;
    assert_error(&res, 400, "NOT_IMPERSONATING");
}

#[tokio::test]
async fn impersonating_admins_and_banned_users_is_refused() {
    let auth = build(Admin::new().role(
        "owner",
        Permissions::admin().allow("user", ["impersonate-admins"]),
    ));
    let (mut admin, _, bob) = admin_and_user(&auth).await;
    let (_, other) = signed_up(&auth, "ops@acme.dk").await;
    auth.admin().set_role(&other, "admin").await.unwrap();

    let res = admin
        .post("/admin/impersonate-user", json!({ "userId": other }))
        .await;
    assert_error(&res, 403, "YOU_CANNOT_IMPERSONATE_ADMINS");

    let (mut owner, owner_id) = signed_up(&auth, "owner@acme.dk").await;
    auth.admin().set_role(&owner_id, "owner").await.unwrap();
    let res = owner
        .post("/admin/impersonate-user", json!({ "userId": other }))
        .await;
    assert_eq!(res.status, 200, "{}", res.json);

    auth.admin()
        .ban(BanUserInput::new(bob.clone()))
        .await
        .unwrap();
    let res = admin
        .post("/admin/impersonate-user", json!({ "userId": bob }))
        .await;
    assert_error(&res, 403, "BANNED_USER");
}

#[tokio::test]
async fn admin_user_ids_are_always_admins() {
    let db = MemoryAdapter::new();
    let first = build_on(db.clone(), Admin::new());
    let (mut ada, ada_id) = signed_up(&first, "ada@acme.dk").await;
    assert_error(
        &ada.get("/admin/list-users").await,
        403,
        "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS",
    );

    let auth = build_on(db, Admin::new().admin_user_ids([ada_id.clone()]));
    let mut ada = Client::new(auth.clone());
    assert_eq!(sign_in(&mut ada, "ada@acme.dk", PASSWORD).await.status, 200);
    let res = ada.get("/admin/list-users").await;
    assert_eq!(res.status, 200, "{}", res.json);
    assert_eq!(fields(&auth, &ada_id).await.role.as_deref(), Some("user"));
    let (_, bob) = signed_up(&auth, "bob@acme.dk").await;
    let res = ada.post("/admin/ban-user", json!({ "userId": bob })).await;
    assert_eq!(res.status, 200, "{}", res.json);
    let res = ada
        .post(
            "/admin/has-permission",
            json!({ "permissions": { "user": ["impersonate-admins"] } }),
        )
        .await;
    assert_eq!(res.json["success"], true);

    let (mut carol, _) = signed_up(&auth, "carol@acme.dk").await;
    auth.admin().unban(&bob).await.unwrap();
    let res = carol
        .post("/admin/impersonate-user", json!({ "userId": ada_id }))
        .await;
    assert_error(&res, 403, "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS");
}

#[tokio::test]
async fn has_permission_checks_the_callers_roles() {
    let auth =
        build(Admin::new().role("support", Permissions::new().allow("user", ["list", "get"])));
    let (mut admin, mut bob_browser, bob) = admin_and_user(&auth).await;

    let check = json!({ "permissions": { "user": ["list"] } });
    let res = admin.post("/admin/has-permission", check.clone()).await;
    assert_eq!(res.json, json!({ "error": null, "success": true }));
    let res = bob_browser
        .post("/admin/has-permission", check.clone())
        .await;
    assert_eq!(res.json, json!({ "error": null, "success": false }));
    let res = admin
        .post(
            "/admin/has-permission",
            json!({ "permission": { "user": ["impersonate-admins"] } }),
        )
        .await;
    assert_eq!(res.json["success"], false);
    let res = admin.post("/admin/has-permission", json!({})).await;
    assert_eq!(res.status, 400);
    let res = Client::new(auth.clone())
        .post("/admin/has-permission", check)
        .await;
    assert_error(&res, 401, "UNAUTHORIZED");

    auth.admin().set_role(&bob, ["support"]).await.unwrap();
    assert!(
        auth.admin()
            .has_permission(&bob, Permissions::new().allow("user", ["get", "list"]))
            .await
            .unwrap()
    );
    assert!(
        !auth
            .admin()
            .has_permission(&bob, Permissions::new().allow("user", ["ban"]))
            .await
            .unwrap()
    );
    assert!(
        !auth
            .admin()
            .has_permission(
                &Id::from("nobody"),
                Permissions::new().allow("user", ["get"])
            )
            .await
            .unwrap()
    );
    let res = bob_browser.get("/admin/list-users").await;
    assert_eq!(
        res.status, 200,
        "custom roles reach the endpoints they're granted"
    );
    let res = bob_browser
        .post("/admin/ban-user", json!({ "userId": bob }))
        .await;
    assert_error(&res, 403, "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS");
}

#[tokio::test]
async fn the_server_api_needs_no_session() {
    let auth = build(Admin::new());
    let (_, mut bob_browser, bob) = admin_and_user(&auth).await;
    let api = auth.admin();

    let carol = api
        .create_user(CreateUserInput {
            email: "carol@acme.dk".into(),
            name: "Carol".into(),
            password: Some("carols password".into()),
            role: Some("admin".into()),
            ..CreateUserInput::default()
        })
        .await
        .unwrap();
    assert_eq!(
        carol.fields::<AdminUser>().unwrap().role.as_deref(),
        Some("admin")
    );

    let banned = api
        .ban(
            BanUserInput::new(bob.clone())
                .reason("fraud")
                .expires_in(Duration::hours(1)),
        )
        .await
        .unwrap();
    assert!(banned.fields::<AdminUser>().unwrap().banned);
    assert_eq!(bob_browser.get("/get-session").await.json, Value::Null);
    assert!(
        !api.unban(&bob)
            .await
            .unwrap()
            .fields::<AdminUser>()
            .unwrap()
            .banned
    );

    let mut data = serde_json::Map::new();
    data.insert("name".into(), json!("Bobby"));
    assert_eq!(api.update_user(&bob, data).await.unwrap().name, "Bobby");
    assert_eq!(
        api.list_users(ListUsersQuery::default())
            .await
            .unwrap()
            .total,
        3
    );
    assert_eq!(api.get_user(&bob).await.unwrap().email, "bob@acme.dk");

    sign_in(&mut bob_browser, "bob@acme.dk", PASSWORD).await;
    assert_eq!(api.list_user_sessions(&bob).await.unwrap().len(), 1);
    api.revoke_user_sessions(&bob).await.unwrap();
    assert!(api.list_user_sessions(&bob).await.unwrap().is_empty());
    api.remove_user(&carol.id).await.unwrap();
    assert_eq!(
        api.get_user(&carol.id).await.unwrap_err().code(),
        "USER_NOT_FOUND"
    );
}

#[test]
#[should_panic(expected = "invalid admin roles: superadmin")]
fn admin_roles_must_be_defined() {
    build(Admin::new().admin_roles(["admin", "superadmin"]));
}
