//! FAST-31 security review (area: authz). Coverage tests for the organization plugin's
//! cross-organization and role checks (they pass on 0.3.0), and one race that fails.

mod common;

use common::{Client, Res, secret};
use fastauth_core::adapter::Adapter;
use fastauth_core::crypto::Argon2id;
use fastauth_core::prelude::*;
use fastauth_core::query::Db;
use fastauth_plugin_organization::{Member, Organization};
use fastauth_sqlx::sqlx::sqlite::SqlitePoolOptions;
use fastauth_sqlx::{Sqlite, Sqlx};
use http::StatusCode;
use serde_json::{Value, json};

type AppAuth = Auth<MemoryAdapter, (), plugins![Organization]>;
type App = Client<MemoryAdapter, (), plugins![Organization]>;

const PASSWORD: &str = "correct horse";

fn build() -> AppAuth {
    FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .plugin(Organization::default())
        .build()
        .expect("valid config")
}

async fn user(auth: &AppAuth, email: &str) -> App {
    let mut client = Client::new(auth.clone());
    let res = client.sign_up(email, PASSWORD).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    client
}

async fn create(client: &mut App, slug: &str) -> String {
    let res = client
        .post(
            "/organization/create",
            json!({ "name": slug, "slug": slug }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    res.json["id"].as_str().unwrap().to_owned()
}

async fn invite_and_accept(
    auth: &AppAuth,
    inviter: &mut App,
    org: &str,
    email: &str,
    role: &str,
) -> (App, String) {
    let res = inviter
        .post(
            "/organization/invite-member",
            json!({ "email": email, "role": role, "organizationId": org }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let mut invitee = user(auth, email).await;
    verify_email(auth, email).await;
    let res = invitee
        .post(
            "/organization/accept-invitation",
            json!({ "invitationId": res.json["id"] }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let member_id = res.json["member"]["id"].as_str().unwrap().to_owned();
    (invitee, member_id)
}

fn refused(res: &Res, what: &str) {
    assert!(
        res.status.is_client_error(),
        "{what} was allowed: {} {}",
        res.status,
        res.json
    );
}

/// Invitations need a verified email by default (AUTHZ-9).
async fn verify_email<D: Adapter>(auth: &Auth<D, (), plugins![Organization]>, email: &str) {
    Db::new(auth.adapter(), auth.schema())
        .update::<User>(User::EMAIL.eq(email))
        .set(User::EMAIL_VERIFIED, true)
        .exec()
        .await
        .unwrap();
}

async fn members(auth: &AppAuth, org: &str) -> Vec<Member> {
    Db::new(auth.adapter(), auth.schema())
        .find::<Member>(Member::ORGANIZATION_ID.eq(Id::from(org)))
        .all()
        .await
        .unwrap()
}

/// Two organizations: Eve owns `evil` (and is admin there), Ada owns `acme` with Bob as a
/// member. Eve may act only on `evil`.
struct World {
    auth: AppAuth,
    eve: App,
    evil: String,
    ada: App,
    acme: String,
    bob_member: String,
    invitation: String,
}

async fn world() -> World {
    let auth = build();
    let mut eve = user(&auth, "eve@evil.dk").await;
    let evil = create(&mut eve, "evil").await;
    let mut ada = user(&auth, "ada@acme.dk").await;
    let acme = create(&mut ada, "acme").await;
    let (_, bob_member) = invite_and_accept(&auth, &mut ada, &acme, "bob@acme.dk", "member").await;
    let res = ada
        .post(
            "/organization/invite-member",
            json!({ "email": "carol@acme.dk", "role": "admin", "organizationId": acme }),
        )
        .await;
    let invitation = res.json["id"].as_str().unwrap().to_owned();
    World {
        auth,
        eve,
        evil,
        ada,
        acme,
        bob_member,
        invitation,
    }
}

/// Coverage: ids from another organization are refused whether the request names the
/// caller's own organization or the foreign one.
#[tokio::test]
async fn sec_org_cross_organization_ids_are_refused() {
    let World {
        auth,
        mut eve,
        evil,
        acme,
        bob_member,
        invitation,
        ..
    } = world().await;

    for org in [&evil, &acme] {
        let res = eve
            .post(
                "/organization/update-member-role",
                json!({ "memberId": bob_member, "role": "admin", "organizationId": org }),
            )
            .await;
        refused(&res, "update-member-role on another org's member");
        let res = eve
            .post(
                "/organization/remove-member",
                json!({ "memberIdOrEmail": bob_member, "organizationId": org }),
            )
            .await;
        refused(&res, "remove-member on another org's member");
        let res = eve
            .post(
                "/organization/remove-member",
                json!({ "memberIdOrEmail": "bob@acme.dk", "organizationId": org }),
            )
            .await;
        refused(&res, "remove-member by email on another org's member");
    }
    for (path, body) in [
        (
            "/organization/update",
            json!({ "organizationId": acme, "data": { "name": "pwned" } }),
        ),
        ("/organization/delete", json!({ "organizationId": acme })),
        (
            "/organization/invite-member",
            json!({ "organizationId": acme, "email": "x@evil.dk", "role": "owner" }),
        ),
        (
            "/organization/cancel-invitation",
            json!({ "invitationId": invitation }),
        ),
        (
            "/organization/accept-invitation",
            json!({ "invitationId": invitation }),
        ),
        (
            "/organization/reject-invitation",
            json!({ "invitationId": invitation }),
        ),
        (
            "/organization/set-active",
            json!({ "organizationId": acme }),
        ),
        (
            "/organization/set-active",
            json!({ "organizationSlug": "acme" }),
        ),
        ("/organization/leave", json!({ "organizationId": acme })),
    ] {
        let res = eve.post(path, body).await;
        refused(&res, path);
    }
    for path in [
        format!("/organization/list-members?organizationId={acme}"),
        "/organization/list-members?organizationSlug=acme".to_owned(),
        format!("/organization/get-full-organization?organizationId={acme}"),
        format!("/organization/list-invitations?organizationId={acme}"),
        format!("/organization/get-invitation?id={invitation}"),
    ] {
        let res = eve.get(&path).await;
        refused(&res, &path);
    }
    let res = eve
        .post(
            "/organization/has-permission",
            json!({ "organizationId": acme, "permissions": { "member": ["delete"] } }),
        )
        .await;
    assert!(
        res.status.is_client_error() || res.json["success"] == json!(false),
        "{}",
        res.json
    );
    let acme_members = members(&auth, &acme).await;
    assert_eq!(acme_members.len(), 2);
    assert!(acme_members.iter().all(|m| m.role != "admin"));
}

/// Coverage: admins can't reach the owner role, members can't change roles, and the last
/// owner can neither leave nor demote themselves.
#[tokio::test]
async fn sec_org_role_escalation_is_refused() {
    let World {
        auth,
        mut ada,
        acme,
        ..
    } = world().await;
    let (mut admin, admin_member) =
        invite_and_accept(&auth, &mut ada, &acme, "dan@acme.dk", "admin").await;
    let (mut member, member_id) =
        invite_and_accept(&auth, &mut ada, &acme, "erin@acme.dk", "member").await;
    let owner_member = members(&auth, &acme)
        .await
        .into_iter()
        .find(|m| m.role == "owner")
        .unwrap()
        .id
        .to_string();

    for (who, body) in [
        (
            "admin promotes self to owner",
            json!({ "memberId": admin_member, "role": "owner" }),
        ),
        (
            "admin adds owner to own roles",
            json!({ "memberId": admin_member, "role": ["admin", "owner"] }),
        ),
        (
            "admin demotes the owner",
            json!({ "memberId": owner_member, "role": "member" }),
        ),
    ] {
        let res = admin.post("/organization/update-member-role", body).await;
        refused(&res, who);
    }
    let res = member
        .post(
            "/organization/update-member-role",
            json!({ "memberId": member_id, "role": "admin" }),
        )
        .await;
    refused(&res, "member promotes self");
    let res = admin
        .post(
            "/organization/invite-member",
            json!({ "email": "boss@evil.dk", "role": "owner" }),
        )
        .await;
    refused(&res, "admin invites an owner");
    let res = admin
        .post(
            "/organization/remove-member",
            json!({ "memberIdOrEmail": owner_member }),
        )
        .await;
    refused(&res, "admin removes the owner");
    let res = admin
        .post("/organization/delete", json!({ "organizationId": acme }))
        .await;
    refused(&res, "admin deletes the organization");
    let res = ada
        .post("/organization/leave", json!({ "organizationId": acme }))
        .await;
    refused(&res, "last owner leaves");
    let res = ada
        .post(
            "/organization/update-member-role",
            json!({ "memberId": owner_member, "role": "admin" }),
        )
        .await;
    refused(&res, "last owner demotes self");
    let roles: Vec<String> = members(&auth, &acme)
        .await
        .into_iter()
        .map(|m| m.role)
        .collect();
    assert_eq!(
        roles.iter().filter(|r| *r == "owner").count(),
        1,
        "{roles:?}"
    );
}

/// Coverage: an invitation can only be accepted by the address it was sent to, once.
#[tokio::test]
async fn sec_org_invitation_is_bound_to_its_email_and_single_use() {
    let World {
        auth,
        mut ada,
        acme,
        ..
    } = world().await;
    let res = ada
        .post(
            "/organization/invite-member",
            json!({ "email": "frank@acme.dk", "role": "admin", "organizationId": acme }),
        )
        .await;
    let invitation = res.json["id"].clone();
    let mut mallory = user(&auth, "mallory@evil.dk").await;
    verify_email(&auth, "mallory@evil.dk").await;
    let res = mallory
        .post(
            "/organization/accept-invitation",
            json!({ "invitationId": invitation }),
        )
        .await;
    refused(&res, "accepting someone else's invitation");

    let mut frank = user(&auth, "FRANK@acme.dk").await;
    verify_email(&auth, "frank@acme.dk").await;
    let res = frank
        .post(
            "/organization/accept-invitation",
            json!({ "invitationId": invitation }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let res = frank
        .post(
            "/organization/accept-invitation",
            json!({ "invitationId": invitation }),
        )
        .await;
    refused(&res, "accepting twice");
    let res = ada
        .post(
            "/organization/cancel-invitation",
            json!({ "invitationId": invitation }),
        )
        .await;
    let _: Value = res.json;
    let res = frank
        .post(
            "/organization/reject-invitation",
            json!({ "invitationId": invitation }),
        )
        .await;
    refused(&res, "rejecting an accepted invitation");
}

/// AUTHZ-8: `/organization/leave` checks "not the last owner" and deletes the membership
/// in separate statements, so two owners leaving at once both pass the check and leave the
/// organization with no owner (nobody can delete it or manage owners any more).
#[tokio::test]
async fn sec_org_concurrent_owner_leave_keeps_an_owner() {
    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .connect("sqlite:file:fast31_leave?mode=memory&cache=shared")
        .await
        .expect("in-memory SQLite");
    let auth: Auth<Sqlx<Sqlite>, (), plugins![Organization]> = FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .plugin(Organization::default())
        .build()
        .expect("valid config");
    auth.migrator().run().await.expect("migrates");

    let mut zero_owner_runs = 0;
    const RUNS: usize = 20;
    for run in 0..RUNS {
        let mut a = Client::new(auth.clone());
        assert_eq!(
            a.sign_up(&format!("a{run}@acme.dk"), PASSWORD).await.status,
            StatusCode::OK
        );
        let org = a
            .post(
                "/organization/create",
                json!({ "name": "race", "slug": format!("race-{run}") }),
            )
            .await
            .json["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let res = a
            .post(
                "/organization/invite-member",
                json!({ "email": format!("b{run}@acme.dk"), "role": "owner", "organizationId": org }),
            )
            .await;
        let mut b = Client::new(auth.clone());
        assert_eq!(
            b.sign_up(&format!("b{run}@acme.dk"), PASSWORD).await.status,
            StatusCode::OK
        );
        verify_email(&auth, &format!("b{run}@acme.dk")).await;
        let res = b
            .post(
                "/organization/accept-invitation",
                json!({ "invitationId": res.json["id"] }),
            )
            .await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.json);

        let body = json!({ "organizationId": org });
        let (ra, rb) = tokio::join!(
            a.post("/organization/leave", body.clone()),
            b.post("/organization/leave", body.clone())
        );
        let owners = Db::new(auth.adapter(), auth.schema())
            .count::<Member>(Member::ORGANIZATION_ID.eq(Id::from(org.as_str())))
            .await
            .unwrap();
        if owners == 0 {
            zero_owner_runs += 1;
            println!(
                "[run {run}] both owners left: {} / {}",
                ra.status, rb.status
            );
        }
    }
    println!("[concurrent leave] organizations left without an owner: {zero_owner_runs}/{RUNS}");
    assert_eq!(zero_owner_runs, 0, "organizations were left with no owner");
}
