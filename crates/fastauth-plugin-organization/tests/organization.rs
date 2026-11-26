mod common;

use std::sync::{Arc, Mutex};

use common::{Client, Res, secret};
use fastauth_core::crypto::Argon2id;
use fastauth_core::endpoint::Before;
use fastauth_core::mail::AuthEmail;
use fastauth_core::prelude::*;
use fastauth_core::query::Db;
use fastauth_plugin_organization::{
    AddMember, CreateOrganization, CreateOrganizationInput, Invitation, InvitationAccepted,
    MemberAdded, MemberRemoved, NewMember, Organization, OrganizationCreated, OrganizationExt,
    OrganizationRow, RoleInput, Roles,
};
use http::StatusCode;
use serde_json::{Value, json};
use time::OffsetDateTime;

type AppAuth = Auth<MemoryAdapter, (), plugins![Organization]>;
type App = Client<MemoryAdapter, (), plugins![Organization]>;

const PASSWORD: &str = "correct horse";

struct Setup {
    auth: AppAuth,
    mailer: MemoryMailer,
    events: Arc<Mutex<Vec<String>>>,
}

fn setup(plugin: Organization) -> Setup {
    let mailer = MemoryMailer::new();
    let events = Arc::new(Mutex::new(Vec::new()));
    let log = |events: &Arc<Mutex<Vec<String>>>, line: String| {
        events.lock().unwrap().push(line);
    };
    let (e1, e2, e3, e4) = (
        events.clone(),
        events.clone(),
        events.clone(),
        events.clone(),
    );
    let auth = FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .mailer(mailer.clone())
        .rate_limit(RateLimit::disabled())
        .plugin(plugin)
        .on(move |e: OrganizationCreated, _| {
            log(&e1, format!("created {}", e.organization_id));
            async { Ok(()) }
        })
        .on(move |e: MemberAdded, _| {
            log(&e2, format!("added {} {}", e.user_id, e.role));
            async { Ok(()) }
        })
        .on(move |e: MemberRemoved, _| {
            log(&e3, format!("removed {}", e.user_id));
            async { Ok(()) }
        })
        .on(move |e: InvitationAccepted, _| {
            log(&e4, format!("accepted {}", e.invitation_id));
            async { Ok(()) }
        })
        .build()
        .expect("valid config");
    Setup {
        auth,
        mailer,
        events,
    }
}

fn app() -> Setup {
    setup(Organization::default())
}

/// A signed-in browser for a new user.
async fn user(auth: &AppAuth, email: &str) -> App {
    let mut client = Client::new(auth.clone());
    let res = client.sign_up(email, PASSWORD).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    client
}

async fn me(client: &mut App) -> Value {
    client.get("/get-session").await.json
}

async fn id_of(client: &mut App) -> Id {
    Id::from(me(client).await["user"]["id"].as_str().unwrap())
}

async fn active_org(client: &mut App) -> Value {
    me(client).await["session"]["activeOrganizationId"].clone()
}

async fn create(client: &mut App, slug: &str) -> Value {
    let res = client
        .post(
            "/organization/create",
            json!({ "name": format!("Org {slug}"), "slug": slug, "metadata": { "plan": "pro" } }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    res.json
}

fn code(res: &Res) -> &str {
    res.json["code"].as_str().unwrap_or_default()
}

fn assert_err(res: &Res, status: StatusCode, expected: &str) {
    assert_eq!(res.status, status, "{}", res.json);
    assert_eq!(code(res), expected, "{}", res.json);
}

/// An organization owned by `owner` with `admin` and `member` added by invitation.
struct Team {
    org: String,
    owner: App,
    admin: App,
    member: App,
}

async fn invite_and_accept(
    auth: &AppAuth,
    inviter: &mut App,
    org: &str,
    email: &str,
    role: &str,
) -> App {
    let res = inviter
        .post(
            "/organization/invite-member",
            json!({ "email": email, "role": role, "organizationId": org }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let id = res.json["id"].as_str().unwrap().to_owned();
    let mut invitee = user(auth, email).await;
    let res = invitee
        .post(
            "/organization/accept-invitation",
            json!({ "invitationId": id }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    invitee
}

async fn team(auth: &AppAuth) -> Team {
    let mut owner = user(auth, "owner@acme.dk").await;
    let org = create(&mut owner, "acme").await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let admin = invite_and_accept(auth, &mut owner, &org, "admin@acme.dk", "admin").await;
    let member = invite_and_accept(auth, &mut owner, &org, "member@acme.dk", "member").await;
    Team {
        org,
        owner,
        admin,
        member,
    }
}

fn db(auth: &AppAuth) -> Db<'_, MemoryAdapter> {
    Db::new(auth.adapter(), auth.schema())
}

#[tokio::test]
async fn create_makes_the_creator_owner_and_the_org_active() {
    let Setup { auth, events, .. } = app();
    let mut owner = user(&auth, "owner@acme.dk").await;
    let org = create(&mut owner, "acme").await;
    assert_eq!(org["name"], "Org acme");
    assert_eq!(org["slug"], "acme");
    assert_eq!(org["logo"], Value::Null);
    assert_eq!(org["metadata"], json!({ "plan": "pro" }));
    assert!(org["createdAt"].as_str().unwrap().contains('T'));
    let members = org["members"].as_array().unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0]["role"], "owner");
    assert_eq!(members[0]["organizationId"], org["id"]);
    let owner_id = id_of(&mut owner).await;
    assert_eq!(members[0]["userId"], owner_id.as_str());
    assert_eq!(active_org(&mut owner).await, org["id"]);
    let events = events.lock().unwrap().clone();
    assert_eq!(
        events,
        [
            format!("created {}", org["id"].as_str().unwrap()),
            format!("added {owner_id} owner")
        ]
    );

    let res = owner
        .post(
            "/organization/create",
            json!({ "name": "Second", "slug": "second", "keepCurrentActiveOrganization": true }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(active_org(&mut owner).await, org["id"]);
}

#[tokio::test]
async fn create_refuses_taken_slugs_disabled_creation_and_the_limit() {
    let Setup { auth, .. } = app();
    let mut owner = user(&auth, "owner@acme.dk").await;
    create(&mut owner, "acme").await;
    let res = owner
        .post(
            "/organization/create",
            json!({ "name": "Again", "slug": "acme" }),
        )
        .await;
    assert_err(&res, StatusCode::BAD_REQUEST, "ORGANIZATION_ALREADY_EXISTS");
    let res = owner
        .post(
            "/organization/create",
            json!({ "name": "", "slug": "empty" }),
        )
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);

    let res = owner
        .post("/organization/check-slug", json!({ "slug": "acme" }))
        .await;
    assert_err(
        &res,
        StatusCode::BAD_REQUEST,
        "ORGANIZATION_SLUG_ALREADY_TAKEN",
    );
    let res = owner
        .post("/organization/check-slug", json!({ "slug": "free" }))
        .await;
    assert_eq!(res.json, json!({ "status": true }));

    let Setup { auth, .. } =
        setup(Organization::default().allow_user_to_create_organization(false));
    let mut owner = user(&auth, "owner@acme.dk").await;
    let res = owner
        .post(
            "/organization/create",
            json!({ "name": "Acme", "slug": "acme" }),
        )
        .await;
    assert_err(
        &res,
        StatusCode::FORBIDDEN,
        "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION",
    );
    let owner_id = id_of(&mut owner).await;
    let created = auth
        .organization()
        .create(
            &owner_id,
            CreateOrganizationInput {
                name: "Acme".into(),
                slug: "acme".into(),
                ..Default::default()
            },
        )
        .await
        .expect("the server may create organizations for anyone");
    assert_eq!(created.members[0].role, "owner");

    let Setup { auth, .. } = setup(Organization::default().organization_limit(1));
    let mut owner = user(&auth, "owner@acme.dk").await;
    create(&mut owner, "one").await;
    let res = owner
        .post(
            "/organization/create",
            json!({ "name": "Two", "slug": "two" }),
        )
        .await;
    assert_err(
        &res,
        StatusCode::FORBIDDEN,
        "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS",
    );
}

#[tokio::test]
async fn update_needs_organization_update() {
    let Setup { auth, .. } = app();
    let Team {
        org,
        mut owner,
        mut admin,
        mut member,
    } = team(&auth).await;
    let res = owner
        .post(
            "/organization/update",
            json!({ "data": { "name": "Acme ApS", "logo": "https://acme.dk/logo.png" } }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["name"], "Acme ApS");
    assert_eq!(res.json["logo"], "https://acme.dk/logo.png");
    assert_eq!(res.json["metadata"], json!({ "plan": "pro" }));

    let res = admin
        .post(
            "/organization/update",
            json!({ "organizationId": org, "data": { "slug": "acme-aps", "logo": null } }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["slug"], "acme-aps");
    assert_eq!(res.json["logo"], Value::Null);
    assert_eq!(res.json["name"], "Acme ApS");

    let res = member
        .post(
            "/organization/update",
            json!({ "data": { "name": "Mine" } }),
        )
        .await;
    assert_err(
        &res,
        StatusCode::FORBIDDEN,
        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION",
    );

    create(&mut owner, "other").await;
    let res = owner
        .post(
            "/organization/update",
            json!({ "organizationId": org, "data": { "slug": "other" } }),
        )
        .await;
    assert_err(
        &res,
        StatusCode::BAD_REQUEST,
        "ORGANIZATION_SLUG_ALREADY_TAKEN",
    );

    let mut stranger = user(&auth, "stranger@acme.dk").await;
    let res = stranger
        .post(
            "/organization/update",
            json!({ "organizationId": org, "data": { "name": "Mine" } }),
        )
        .await;
    assert_err(
        &res,
        StatusCode::BAD_REQUEST,
        "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
    );
}

#[tokio::test]
async fn delete_needs_organization_delete_and_cascades() {
    let Setup { auth, .. } = app();
    let Team {
        org,
        mut owner,
        mut admin,
        mut member,
    } = team(&auth).await;
    owner
        .post(
            "/organization/invite-member",
            json!({ "email": "later@acme.dk", "role": "member" }),
        )
        .await;
    let res = admin
        .post("/organization/delete", json!({ "organizationId": org }))
        .await;
    assert_err(
        &res,
        StatusCode::FORBIDDEN,
        "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION",
    );
    let res = member
        .post("/organization/delete", json!({ "organizationId": org }))
        .await;
    assert_err(
        &res,
        StatusCode::FORBIDDEN,
        "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION",
    );

    assert_eq!(active_org(&mut member).await, json!(org));
    let res = owner
        .post("/organization/delete", json!({ "organizationId": org }))
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["id"], json!(org));
    let id = Id::from(org.as_str());
    let db = db(&auth);
    assert_eq!(
        db.count::<OrganizationRow>(OrganizationRow::ID.eq(&id))
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        db.count::<fastauth_plugin_organization::Member>(
            fastauth_plugin_organization::Member::ORGANIZATION_ID.eq(&id)
        )
        .await
        .unwrap(),
        0
    );
    assert_eq!(
        db.count::<Invitation>(Invitation::ORGANIZATION_ID.eq(&id))
            .await
            .unwrap(),
        0
    );
    assert_eq!(owner.get("/organization/list").await.json, json!([]));
    assert_eq!(active_org(&mut owner).await, Value::Null);
    assert_eq!(active_org(&mut member).await, Value::Null);
}

#[tokio::test]
async fn list_get_full_and_set_active() {
    let Setup { auth, .. } = app();
    let Team {
        org,
        mut owner,
        mut admin,
        mut member,
    } = team(&auth).await;
    let second = create(&mut owner, "second").await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let list = owner.get("/organization/list").await.json;
    let slugs: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["slug"].as_str().unwrap())
        .collect();
    assert_eq!(slugs, ["acme", "second"]);
    assert_eq!(
        member
            .get("/organization/list")
            .await
            .json
            .as_array()
            .unwrap()
            .len(),
        1
    );

    assert_eq!(active_org(&mut owner).await, json!(second));
    let res = owner
        .post(
            "/organization/set-active",
            json!({ "organizationSlug": "acme" }),
        )
        .await;
    assert_eq!(res.json["id"], json!(org));
    assert_eq!(active_org(&mut owner).await, json!(org));

    let full = owner.get("/organization/get-full-organization").await.json;
    assert_eq!(full["slug"], "acme");
    let members = full["members"].as_array().unwrap();
    assert_eq!(members.len(), 3);
    assert_eq!(members[0]["user"]["email"], "owner@acme.dk");
    assert_eq!(members[1]["role"], "admin");
    assert_eq!(members[2]["user"]["name"], "Test User");
    assert_eq!(full["invitations"].as_array().unwrap().len(), 2);
    let limited = owner
        .get("/organization/get-full-organization?organizationSlug=acme&membersLimit=1")
        .await
        .json;
    assert_eq!(limited["members"].as_array().unwrap().len(), 1);
    let as_member = member
        .get(&format!(
            "/organization/get-full-organization?organizationId={org}"
        ))
        .await
        .json;
    assert_eq!(as_member["invitations"], json!([]));
    let as_admin = admin.get("/organization/get-full-organization").await.json;
    assert_eq!(as_admin["invitations"].as_array().unwrap().len(), 2);

    let res = member
        .post(
            "/organization/set-active",
            json!({ "organizationId": second }),
        )
        .await;
    assert_err(
        &res,
        StatusCode::FORBIDDEN,
        "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
    );
    assert_eq!(active_org(&mut member).await, Value::Null);
    assert_eq!(
        member.get("/organization/get-full-organization").await.json,
        Value::Null
    );
    let res = member
        .get(&format!(
            "/organization/get-full-organization?organizationId={second}"
        ))
        .await;
    assert_err(
        &res,
        StatusCode::FORBIDDEN,
        "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
    );

    let res = owner
        .post(
            "/organization/set-active",
            json!({ "organizationId": null }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.json, Value::Null);
    assert_eq!(active_org(&mut owner).await, Value::Null);
}

#[tokio::test]
async fn invitations_email_a_link_and_accepting_joins() {
    let Setup {
        auth,
        mailer,
        events,
    } = setup(Organization::default().invitation_url("https://app.acme.dk/invite/{id}"));
    let mut owner = user(&auth, "owner@acme.dk").await;
    let org = create(&mut owner, "acme").await["id"].clone();
    let res = owner
        .post(
            "/organization/invite-member",
            json!({ "email": " Ada@Acme.dk ", "role": ["admin", "member"] }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let invitation = res.json;
    assert_eq!(invitation["email"], "ada@acme.dk");
    assert_eq!(invitation["role"], "admin,member");
    assert_eq!(invitation["status"], "pending");
    assert_eq!(invitation["organizationId"], org);
    let id = invitation["id"].as_str().unwrap();
    let Some(AuthEmail::Plugin(email)) = mailer.last() else {
        panic!("no invitation email");
    };
    assert_eq!(email.kind, "organization-invitation");
    assert_eq!(email.to, "ada@acme.dk");
    assert_eq!(
        email.url.as_deref(),
        Some(format!("https://app.acme.dk/invite/{id}").as_str())
    );
    assert_eq!(email.code.as_deref(), Some(id));
    assert!(email.subject.contains("Org acme"), "{}", email.subject);

    let res = owner
        .post(
            "/organization/invite-member",
            json!({ "email": "ada@acme.dk", "role": "member" }),
        )
        .await;
    assert_err(
        &res,
        StatusCode::BAD_REQUEST,
        "USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION",
    );
    let sent = mailer.sent().len();
    let res = owner
        .post(
            "/organization/invite-member",
            json!({ "email": "ada@acme.dk", "role": "member", "resend": true }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.json["id"], id);
    assert_eq!(
        mailer.sent().len(),
        sent + 1,
        "resending sends the email again"
    );

    let mut ada = user(&auth, "ada@acme.dk").await;
    let details = ada
        .get(&format!("/organization/get-invitation?id={id}"))
        .await
        .json;
    assert_eq!(details["organizationName"], "Org acme");
    assert_eq!(details["organizationSlug"], "acme");
    assert_eq!(details["inviterEmail"], "owner@acme.dk");

    let res = ada
        .post(
            "/organization/accept-invitation",
            json!({ "invitationId": id }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["invitation"]["status"], "accepted");
    assert_eq!(res.json["member"]["role"], "admin,member");
    assert_eq!(active_org(&mut ada).await, org);
    let ada_id = id_of(&mut ada).await;
    let events = events.lock().unwrap().clone();
    assert!(
        events.contains(&format!("added {ada_id} admin,member")),
        "{events:?}"
    );
    assert!(events.contains(&format!("accepted {id}")), "{events:?}");

    let res = ada
        .post(
            "/organization/accept-invitation",
            json!({ "invitationId": id }),
        )
        .await;
    assert_err(&res, StatusCode::BAD_REQUEST, "INVITATION_NOT_FOUND");
    let res = owner
        .post(
            "/organization/invite-member",
            json!({ "email": "ada@acme.dk", "role": "member" }),
        )
        .await;
    assert_err(
        &res,
        StatusCode::BAD_REQUEST,
        "USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION",
    );
}

#[tokio::test]
async fn invite_checks_permission_roles_and_email() {
    let Setup { auth, .. } = app();
    let Team {
        mut owner,
        mut admin,
        mut member,
        ..
    } = team(&auth).await;
    let res = member
        .post(
            "/organization/invite-member",
            json!({ "email": "x@acme.dk", "role": "member" }),
        )
        .await;
    assert_err(
        &res,
        StatusCode::FORBIDDEN,
        "YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION",
    );
    let res = admin
        .post(
            "/organization/invite-member",
            json!({ "email": "x@acme.dk", "role": "owner" }),
        )
        .await;
    assert_err(
        &res,
        StatusCode::FORBIDDEN,
        "YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE",
    );
    let res = owner
        .post(
            "/organization/invite-member",
            json!({ "email": "x@acme.dk", "role": "janitor" }),
        )
        .await;
    assert_err(&res, StatusCode::BAD_REQUEST, "ROLE_NOT_FOUND");
    assert!(res.json["message"].as_str().unwrap().contains("janitor"));
    let res = owner
        .post(
            "/organization/invite-member",
            json!({ "email": "not-an-email", "role": "member" }),
        )
        .await;
    assert_err(&res, StatusCode::BAD_REQUEST, "INVALID_EMAIL");
    let res = admin
        .post(
            "/organization/invite-member",
            json!({ "email": "x@acme.dk", "role": "admin" }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
}

#[tokio::test]
async fn accepting_needs_the_invited_email_and_a_live_invitation() {
    let Setup { auth, .. } = app();
    let mut owner = user(&auth, "owner@acme.dk").await;
    create(&mut owner, "acme").await;
    let id = owner
        .post(
            "/organization/invite-member",
            json!({ "email": "ada@acme.dk", "role": "member" }),
        )
        .await
        .json["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let mut mallory = user(&auth, "mallory@acme.dk").await;
    for path in [
        "/organization/accept-invitation",
        "/organization/reject-invitation",
    ] {
        let res = mallory.post(path, json!({ "invitationId": id })).await;
        assert_err(
            &res,
            StatusCode::FORBIDDEN,
            "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION",
        );
    }
    let res = mallory
        .get(&format!("/organization/get-invitation?id={id}"))
        .await;
    assert_err(
        &res,
        StatusCode::FORBIDDEN,
        "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION",
    );

    db(&auth)
        .update::<Invitation>(Invitation::ID.eq(Id::from(id.as_str())))
        .set(
            Invitation::EXPIRES_AT,
            OffsetDateTime::now_utc() - Duration::minutes(1),
        )
        .exec()
        .await
        .unwrap();
    let mut ada = user(&auth, "ada@acme.dk").await;
    let res = ada
        .post(
            "/organization/accept-invitation",
            json!({ "invitationId": id }),
        )
        .await;
    assert_err(&res, StatusCode::BAD_REQUEST, "INVITATION_NOT_FOUND");
    let res = ada
        .get(&format!("/organization/get-invitation?id={id}"))
        .await;
    assert_err(&res, StatusCode::BAD_REQUEST, "INVITATION_NOT_FOUND");
    assert_eq!(ada.get("/organization/list").await.json, json!([]));

    let res = owner
        .post(
            "/organization/invite-member",
            json!({ "email": "ada@acme.dk", "role": "member" }),
        )
        .await;
    assert_eq!(
        res.status,
        StatusCode::OK,
        "an expired invitation doesn't block a new one"
    );
}

#[tokio::test]
async fn reject_cancel_and_list_invitations() {
    let Setup { auth, .. } = app();
    let Team {
        org,
        mut owner,
        mut admin,
        mut member,
    } = team(&auth).await;
    let invite = |role: &str, email: &str| json!({ "email": email, "role": role });
    let to_owner = owner
        .post(
            "/organization/invite-member",
            invite("owner", "co-owner@acme.dk"),
        )
        .await
        .json["id"]
        .clone();
    let to_bob = admin
        .post(
            "/organization/invite-member",
            invite("member", "bob@acme.dk"),
        )
        .await
        .json["id"]
        .clone();
    let to_eve = admin
        .post(
            "/organization/invite-member",
            invite("member", "eve@acme.dk"),
        )
        .await
        .json["id"]
        .clone();

    let ids = |res: Res| -> Vec<Value> {
        res.json
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["id"].clone())
            .collect()
    };
    let owner_view = ids(owner.get("/organization/list-invitations").await);
    assert!(owner_view.contains(&to_owner) && owner_view.contains(&to_bob));
    let admin_view = ids(admin
        .get(&format!(
            "/organization/list-invitations?organizationId={org}"
        ))
        .await);
    assert!(
        !admin_view.contains(&to_owner),
        "owner invitations show to owners only"
    );
    assert!(admin_view.contains(&to_bob));
    let res = member.get("/organization/list-invitations").await;
    assert_err(
        &res,
        StatusCode::FORBIDDEN,
        "YOU_ARE_NOT_ALLOWED_TO_LIST_INVITATIONS",
    );
    let mut stranger = user(&auth, "stranger@acme.dk").await;
    let res = stranger
        .get(&format!(
            "/organization/list-invitations?organizationId={org}"
        ))
        .await;
    assert_err(
        &res,
        StatusCode::FORBIDDEN,
        "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
    );

    let res = member
        .post(
            "/organization/cancel-invitation",
            json!({ "invitationId": to_eve }),
        )
        .await;
    assert_err(
        &res,
        StatusCode::FORBIDDEN,
        "YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION",
    );
    let res = admin
        .post(
            "/organization/cancel-invitation",
            json!({ "invitationId": to_eve }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["status"], "canceled");

    let mut bob = user(&auth, "bob@acme.dk").await;
    let res = bob.get("/organization/list-user-invitations").await;
    assert_err(
        &res,
        StatusCode::FORBIDDEN,
        "EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION",
    );
    verify_email(&auth, "bob@acme.dk").await;
    let mine = bob.get("/organization/list-user-invitations").await.json;
    assert_eq!(mine.as_array().unwrap().len(), 1);
    assert_eq!(mine[0]["id"], to_bob);
    assert_eq!(mine[0]["organizationName"], "Org acme");
    let res = bob
        .post(
            "/organization/reject-invitation",
            json!({ "invitationId": to_bob }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["invitation"]["status"], "rejected");
    assert_eq!(res.json["member"], Value::Null);
    assert_eq!(
        bob.get("/organization/list-user-invitations").await.json,
        json!([])
    );
    let res = bob
        .post(
            "/organization/accept-invitation",
            json!({ "invitationId": to_bob }),
        )
        .await;
    assert_err(&res, StatusCode::BAD_REQUEST, "INVITATION_NOT_FOUND");

    let pending = auth
        .organization()
        .invitations_for_email("CO-OWNER@acme.dk")
        .await
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(json!(pending[0].invitation.id), to_owner);
}

async fn verify_email(auth: &AppAuth, email: &str) {
    db(auth)
        .update::<User>(User::EMAIL.eq(email))
        .set(User::EMAIL_VERIFIED, true)
        .exec()
        .await
        .unwrap();
}

#[tokio::test]
async fn email_verification_can_be_required_for_invitations() {
    let Setup { auth, .. } =
        setup(Organization::default().require_email_verification_on_invitation(true));
    let mut owner = user(&auth, "owner@acme.dk").await;
    create(&mut owner, "acme").await;
    let id = owner
        .post(
            "/organization/invite-member",
            json!({ "email": "ada@acme.dk", "role": "member" }),
        )
        .await
        .json["id"]
        .clone();
    let mut ada = user(&auth, "ada@acme.dk").await;
    let res = ada
        .post(
            "/organization/accept-invitation",
            json!({ "invitationId": id }),
        )
        .await;
    assert_err(
        &res,
        StatusCode::FORBIDDEN,
        "EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION",
    );
    verify_email(&auth, "ada@acme.dk").await;
    let res = ada
        .post(
            "/organization/accept-invitation",
            json!({ "invitationId": id }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
}

#[tokio::test]
async fn remove_member_needs_member_delete_and_spares_owners() {
    let Setup { auth, events, .. } = app();
    let Team {
        org,
        mut owner,
        mut admin,
        mut member,
    } = team(&auth).await;
    let owner_member = owner.get("/organization/get-active-member").await.json["id"].clone();
    let member_id = member.get("/organization/get-active-member").await.json["id"].clone();

    let res = member
        .post(
            "/organization/remove-member",
            json!({ "memberIdOrEmail": "admin@acme.dk" }),
        )
        .await;
    assert_err(
        &res,
        StatusCode::UNAUTHORIZED,
        "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER",
    );
    let res = admin
        .post(
            "/organization/remove-member",
            json!({ "memberIdOrEmail": owner_member }),
        )
        .await;
    assert_err(
        &res,
        StatusCode::BAD_REQUEST,
        "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER",
    );
    let res = owner
        .post(
            "/organization/remove-member",
            json!({ "memberIdOrEmail": "owner@acme.dk" }),
        )
        .await;
    assert_err(
        &res,
        StatusCode::BAD_REQUEST,
        "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER",
    );
    let res = admin
        .post(
            "/organization/remove-member",
            json!({ "memberIdOrEmail": "nobody@acme.dk" }),
        )
        .await;
    assert_err(&res, StatusCode::BAD_REQUEST, "MEMBER_NOT_FOUND");

    let res = admin
        .post(
            "/organization/remove-member",
            json!({ "memberIdOrEmail": member_id, "organizationId": org }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["member"]["id"], member_id);
    assert_eq!(member.get("/organization/list").await.json, json!([]));
    let member_user = id_of(&mut member).await;
    assert!(
        events
            .lock()
            .unwrap()
            .contains(&format!("removed {member_user}"))
    );
}

#[tokio::test]
async fn update_member_role_protects_the_owner_role() {
    let Setup { auth, .. } = app();
    let Team {
        mut owner,
        mut admin,
        mut member,
        ..
    } = team(&auth).await;
    let owner_member = owner.get("/organization/get-active-member").await.json["id"].clone();
    let admin_member = admin.get("/organization/get-active-member").await.json["id"].clone();
    let member_id = member.get("/organization/get-active-member").await.json["id"].clone();
    let set = |member: &Value, role: Value| json!({ "memberId": member, "role": role });

    let res = member
        .post(
            "/organization/update-member-role",
            set(&member_id, json!("admin")),
        )
        .await;
    assert_err(
        &res,
        StatusCode::FORBIDDEN,
        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER",
    );
    let res = admin
        .post(
            "/organization/update-member-role",
            set(&member_id, json!("owner")),
        )
        .await;
    assert_err(
        &res,
        StatusCode::FORBIDDEN,
        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER",
    );
    let res = admin
        .post(
            "/organization/update-member-role",
            set(&owner_member, json!("member")),
        )
        .await;
    assert_err(
        &res,
        StatusCode::FORBIDDEN,
        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER",
    );
    let res = admin
        .post(
            "/organization/update-member-role",
            set(&member_id, json!("ghost")),
        )
        .await;
    assert_err(&res, StatusCode::BAD_REQUEST, "ROLE_NOT_FOUND");
    let res = owner
        .post(
            "/organization/update-member-role",
            set(&owner_member, json!("admin")),
        )
        .await;
    assert_err(
        &res,
        StatusCode::BAD_REQUEST,
        "YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER",
    );

    let res = admin
        .post(
            "/organization/update-member-role",
            set(&member_id, json!(["admin"])),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["role"], "admin");
    let res = owner
        .post(
            "/organization/update-member-role",
            set(&admin_member, json!("owner")),
        )
        .await;
    assert_eq!(res.json["role"], "owner");
    let res = owner
        .post(
            "/organization/update-member-role",
            set(&owner_member, json!("member")),
        )
        .await;
    assert_eq!(
        res.status,
        StatusCode::OK,
        "a second owner lets the first step down"
    );
    assert_eq!(res.json["role"], "member");
}

#[tokio::test]
async fn leave_spares_the_last_owner() {
    let Setup { auth, .. } = app();
    let Team {
        org,
        mut owner,
        mut member,
        ..
    } = team(&auth).await;
    let res = owner
        .post("/organization/leave", json!({ "organizationId": org }))
        .await;
    assert_err(
        &res,
        StatusCode::BAD_REQUEST,
        "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER",
    );
    let res = member
        .post("/organization/leave", json!({ "organizationId": org }))
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["role"], "member");
    assert_eq!(active_org(&mut member).await, Value::Null);
    let res = member
        .post("/organization/leave", json!({ "organizationId": org }))
        .await;
    assert_err(&res, StatusCode::BAD_REQUEST, "MEMBER_NOT_FOUND");
}

#[tokio::test]
async fn active_member_and_list_members() {
    let Setup { auth, .. } = app();
    let Team {
        org,
        mut owner,
        mut member,
        ..
    } = team(&auth).await;
    let active = member.get("/organization/get-active-member").await.json;
    assert_eq!(active["role"], "member");
    assert_eq!(active["organizationId"], json!(org));
    assert_eq!(active["user"]["email"], "member@acme.dk");

    let page = owner
        .get("/organization/list-members?limit=2&offset=1&sortBy=createdAt&sortDirection=asc")
        .await
        .json;
    assert_eq!(page["total"], 3);
    let emails: Vec<&str> = page["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["user"]["email"].as_str().unwrap())
        .collect();
    assert_eq!(emails, ["admin@acme.dk", "member@acme.dk"]);
    let desc = owner
        .get("/organization/list-members?organizationSlug=acme&sortDirection=desc")
        .await
        .json;
    assert_eq!(desc["members"][0]["user"]["email"], "member@acme.dk");
    let res = owner
        .get("/organization/list-members?sortBy=password")
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);

    let mut stranger = user(&auth, "stranger@acme.dk").await;
    let res = stranger.get("/organization/get-active-member").await;
    assert_err(&res, StatusCode::BAD_REQUEST, "NO_ACTIVE_ORGANIZATION");
    let res = stranger
        .get(&format!("/organization/list-members?organizationId={org}"))
        .await;
    assert_err(
        &res,
        StatusCode::FORBIDDEN,
        "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
    );
}

#[tokio::test]
async fn has_permission_per_role() {
    let Setup { auth, .. } = app();
    let Team {
        org,
        mut owner,
        mut admin,
        mut member,
    } = team(&auth).await;
    let cases = [
        (json!({ "organization": ["delete"] }), [true, false, false]),
        (json!({ "organization": ["update"] }), [true, true, false]),
        (
            json!({ "member": ["create", "update", "delete"] }),
            [true, true, false],
        ),
        (
            json!({ "invitation": ["create"], "member": ["delete"] }),
            [true, true, false],
        ),
        (json!({ "ac": ["read"] }), [true, true, true]),
        (json!({ "invoice": ["read"] }), [false, false, false]),
        (json!({}), [false, false, false]),
    ];
    for (permissions, expected) in cases {
        for (client, allowed) in [&mut owner, &mut admin, &mut member]
            .into_iter()
            .zip(expected)
        {
            let res = client
                .post(
                    "/organization/has-permission",
                    json!({ "permissions": permissions }),
                )
                .await;
            assert_eq!(res.status, StatusCode::OK, "{}", res.json);
            assert_eq!(
                res.json,
                json!({ "error": null, "success": allowed }),
                "{permissions} for {}",
                me(client).await["user"]["email"]
            );
        }
    }
    let res = member
        .post(
            "/organization/has-permission",
            json!({ "permission": { "ac": ["read"] } }),
        )
        .await;
    assert_eq!(
        res.json["success"], true,
        "the deprecated `permission` key still works"
    );

    let mut stranger = user(&auth, "stranger@acme.dk").await;
    let res = stranger
        .post(
            "/organization/has-permission",
            json!({ "organizationId": org, "permissions": { "ac": ["read"] } }),
        )
        .await;
    assert_err(
        &res,
        StatusCode::UNAUTHORIZED,
        "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
    );

    let org = Id::from(org.as_str());
    let admin_id = id_of(&mut admin).await;
    let stranger_id = id_of(&mut stranger).await;
    let api = auth.organization();
    assert!(
        api.has_permission(&org, &admin_id, &[("member", &["delete"])])
            .await
            .unwrap()
    );
    assert!(
        !api.has_permission(&org, &admin_id, &[("organization", &["delete"])])
            .await
            .unwrap()
    );
    assert!(
        !api.has_permission(&org, &stranger_id, &[("ac", &["read"])])
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn custom_roles_and_statements() {
    let roles = Roles::new()
        .role("billing", [("invoice", &["read", "pay"])])
        .grant("owner", [("invoice", &["read", "pay", "refund"])]);
    let Setup { auth, events, .. } = setup(Organization::default().roles(roles));
    let mut owner = user(&auth, "owner@acme.dk").await;
    let org = Id::from(create(&mut owner, "acme").await["id"].as_str().unwrap());
    let mut billing = user(&auth, "billing@acme.dk").await;
    let billing_id = id_of(&mut billing).await;
    let member = auth
        .organization()
        .add_member(&org, &billing_id, "billing,member")
        .await
        .unwrap();
    assert_eq!(member.role, "billing,member");
    assert!(
        events
            .lock()
            .unwrap()
            .contains(&format!("added {billing_id} billing,member"))
    );
    let res = billing
        .post(
            "/organization/set-active",
            json!({ "organizationId": org.as_str() }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK);
    let check = |permissions: Value| json!({ "permissions": permissions });
    let res = billing
        .post(
            "/organization/has-permission",
            check(json!({ "invoice": ["pay"] })),
        )
        .await;
    assert_eq!(res.json["success"], true);
    let res = billing
        .post(
            "/organization/has-permission",
            check(json!({ "invoice": ["refund"] })),
        )
        .await;
    assert_eq!(res.json["success"], false);
    let res = owner
        .post(
            "/organization/has-permission",
            check(json!({ "invoice": ["refund"] })),
        )
        .await;
    assert_eq!(res.json["success"], true);
    let res = owner
        .post(
            "/organization/invite-member",
            json!({ "email": "accounts@acme.dk", "role": "billing" }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "custom roles can be invited");

    let err = auth
        .organization()
        .add_member(&org, &billing_id, "member")
        .await
        .unwrap_err();
    assert_eq!(err.code(), "USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION");
    let err = auth
        .organization()
        .add_member(&org, &billing_id, "ghost")
        .await
        .unwrap_err();
    assert_eq!(err.code(), "ROLE_NOT_FOUND");
}

#[tokio::test]
async fn server_api_calls_endpoints_as_the_session() {
    let Setup { auth, .. } = app();
    let mut owner = user(&auth, "owner@acme.dk").await;
    let headers = {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            owner.cookie_header().unwrap().parse().unwrap(),
        );
        headers
    };
    let api = auth.organization();
    let created = api
        .create_as(
            &headers,
            CreateOrganizationInput {
                name: "Acme".into(),
                slug: "acme".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(
        created
            .set_cookies
            .iter()
            .any(|c| c.to_str().unwrap().contains("session_data=")),
        "switching the active organization drops the session cache cookie"
    );
    let list = api
        .list(&headers, fastauth_core::endpoint::Empty {})
        .await
        .unwrap();
    assert_eq!(list.data, vec![created.data.organization.clone()]);
    let active = api
        .get_active_member(&headers, fastauth_core::endpoint::Empty {})
        .await
        .unwrap();
    assert_eq!(active.data.member.role, "owner");
    assert_eq!(
        active_org(&mut owner).await,
        json!(created.data.organization.id)
    );
}

fn hooked() -> (AppAuth, Arc<Mutex<Vec<String>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (create_seen, add_seen) = (seen.clone(), seen.clone());
    let auth = FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .plugin(Organization::default())
        .configure(move |app| {
            app.hook::<CreateOrganization>()
                .before(move |_ctx, input: CreateOrganizationInput| {
                    let seen = create_seen.clone();
                    async move {
                        let creator = input.user_id.as_ref().map_or("session", Id::as_str);
                        seen.lock()
                            .unwrap()
                            .push(format!("create {} by {creator}", input.slug));
                        if input.slug.starts_with("blocked") {
                            return Err(AuthError::bad_request("SLUG_BLOCKED", "blocked"));
                        }
                        Ok(Before::Continue(input))
                    }
                });
            app.hook::<AddMember>()
                .before(move |_ctx, input: NewMember| {
                    let seen = add_seen.clone();
                    async move {
                        seen.lock().unwrap().push(format!("add {}", input.user_id));
                        if input.role == RoleInput::from("guest") {
                            return Err(AuthError::bad_request("NO_GUESTS", "no guests"));
                        }
                        Ok(Before::Continue(input))
                    }
                });
        })
        .build()
        .expect("CreateOrganization and AddMember can be hooked");
    (auth, seen)
}

#[tokio::test]
async fn create_hooks_run_for_http_and_server_calls() {
    let (auth, seen) = hooked();
    let mut owner = user(&auth, "owner@acme.dk").await;
    let owner_id = id_of(&mut owner).await;

    create(&mut owner, "acme").await;
    let res = owner
        .post(
            "/organization/create",
            json!({ "name": "Blocked", "slug": "blocked-http" }),
        )
        .await;
    assert_err(&res, StatusCode::BAD_REQUEST, "SLUG_BLOCKED");

    let api = auth.organization();
    let input = |slug: &str| CreateOrganizationInput {
        name: "Server".into(),
        slug: slug.into(),
        ..Default::default()
    };
    let created = api.create(&owner_id, input("server")).await.unwrap();
    assert_eq!(created.members[0].user_id, owner_id);
    let err = api
        .create(&owner_id, input("blocked-server"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "SLUG_BLOCKED");

    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            "create acme by session".to_owned(),
            "create blocked-http by session".to_owned(),
            format!("create server by {owner_id}"),
            format!("create blocked-server by {owner_id}"),
        ]
    );
    for slug in ["blocked-http", "blocked-server"] {
        let count = db(&auth)
            .count::<OrganizationRow>(OrganizationRow::SLUG.eq(slug))
            .await
            .unwrap();
        assert_eq!(count, 0, "{slug} was refused before it was created");
    }
}

#[tokio::test]
async fn add_member_hooks_run_and_can_reject() {
    let (auth, seen) = hooked();
    let mut owner = user(&auth, "owner@acme.dk").await;
    let org = Id::from(create(&mut owner, "acme").await["id"].as_str().unwrap());
    let mut guest = user(&auth, "guest@acme.dk").await;
    let guest_id = id_of(&mut guest).await;

    let api = auth.organization();
    let err = api.add_member(&org, &guest_id, "guest").await.unwrap_err();
    assert_eq!(err.code(), "NO_GUESTS");
    let member = api.add_member(&org, &guest_id, "member").await.unwrap();
    assert_eq!(member.role, "member");
    let adds = seen
        .lock()
        .unwrap()
        .iter()
        .filter(|line| **line == format!("add {guest_id}"))
        .count();
    assert_eq!(adds, 2);
}

#[tokio::test]
async fn only_the_server_names_the_creator() {
    let Setup { auth, .. } = app();
    let mut owner = user(&auth, "owner@acme.dk").await;
    let owner_id = id_of(&mut owner).await;
    let mut other = user(&auth, "other@acme.dk").await;
    let other_id = id_of(&mut other).await;
    let res = other
        .post(
            "/organization/create",
            json!({ "name": "Acme", "slug": "acme", "userId": owner_id.as_str() }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(
        res.json["members"][0]["userId"],
        other_id.as_str(),
        "a body's userId is ignored; the session creates it"
    );
    let res = Client::new(auth.clone())
        .post(
            "/organization/create",
            json!({ "name": "Acme 2", "slug": "acme-2", "userId": owner_id.as_str() }),
        )
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    let err = auth
        .organization()
        .create(
            &Id::from("nobody"),
            CreateOrganizationInput {
                name: "Acme".into(),
                slug: "acme".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), "USER_NOT_FOUND");
}
