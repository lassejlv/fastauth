// The cross-app suite: a Better Auth 1.7.8 app and a fastauth app on one Postgres 17, each
// accepting the other's sign-ins. run-dual.sh builds both and runs this; it needs
// DATABASE_URL (an empty database), FASTAUTH_BIN, SUITE_DIR, WORK and OUTBOX.
import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, readdirSync } from "node:fs";
import { next, startMock } from "./mock-oauth.ts";
import {
  app, appEnv, browser, call, check, db, email, env, freePort, outboxSize, q, run, section, setCookie, sleep, start,
  stop, summary, type App, type Browser, type Res,
} from "./lib.ts";

const DAY = 24 * 60 * 60 * 1000;
const EXPIRES_IN = 14 * DAY;
const TOKEN = "vt.session_token";
const SECURE_TOKEN = `__Secure-${TOKEN}`;
const PASSWORD = "correct horse battery";
const BA_HASH = /^[0-9a-f]{32}:[0-9a-f]{128}$/;

env.BETTER_AUTH_SECRET ??= randomBytes(32).toString("hex");
env.FASTAUTH_SECRET ??= randomBytes(32).toString("base64");
const mockPort = await freePort();
env.MOCK_OAUTH_URL = `http://127.0.0.1:${mockPort}`;

const ba = app("better-auth", "better-auth", "http", await freePort());
const baCache = app("better-auth-cookie-cache", "better-auth", "http", await freePort());
const baHttps = app("better-auth-https", "better-auth", "https", await freePort());
const fa = app("fastauth", "fastauth", "http", await freePort());
const faHttps = app("fastauth-https", "fastauth", "https", await freePort());
const faEncrypted = app("fastauth-encrypted-tokens", "fastauth", "http", await freePort());
const apps = [ba, baCache, baHttps, fa, faHttps, faEncrypted];
const other = (a: App) => (a.kind === "better-auth" ? fa : ba);

let counter = 0;
const newEmail = (tag: string) => `${tag}-${++counter}-${randomBytes(3).toString("hex")}@vt.test`;

// ------------------------------------------------------------------------------ helpers

const signUp = (a: App, b: Browser, mail: string, password = PASSWORD, extra: object = {}) =>
  call(a, b, "POST", "/api/auth/sign-up/email", { email: mail, password, name: mail.split("@")[0], ...extra });
const signIn = (a: App, b: Browser, mail: string, password = PASSWORD, extra: object = {}) =>
  call(a, b, "POST", "/api/auth/sign-in/email", { email: mail, password, ...extra });
const getSession = (a: App, b: Browser, query = "") => call(a, b, "GET", `/api/auth/get-session${query}`);
const signOut = (a: App, b: Browser) => call(a, b, "POST", "/api/auth/sign-out", {});

/** A new browser signed in on `a` as a new user who signed up on `a`. */
async function signedUp(a: App, tag: string) {
  const b = browser();
  const mail = newEmail(tag);
  const res = await signUp(a, b, mail);
  if (res.status !== 200) throw new Error(`sign-up on ${a.name}: ${res.status} ${res.text}`);
  return { b, mail, id: res.json.user.id as string, token: res.json.token as string };
}

/** A browser holding only the cookies of `b` that `a` would see, copied. */
function copy(b: Browser): Browser {
  return { jar: new Map(b.jar), ip: b.ip };
}

async function sessionRow(token: string) {
  return (await q<any>('SELECT * FROM "session" WHERE "token" = $1', [token]))[0];
}

async function setExpiresAt(token: string, at: number) {
  await q('UPDATE "session" SET "expiresAt" = $1 WHERE "token" = $2', [new Date(at), token]);
}

function maxAge(header: string | undefined): number | undefined {
  const m = header?.match(/max-age=(\d+)/i);
  return m ? Number(m[1]) : undefined;
}

async function accountRow(userId: string, providerId: string) {
  return (await q<any>('SELECT * FROM "account" WHERE "userId" = $1 AND "providerId" = $2', [userId, providerId]))[0];
}

async function seedOidc(userId: string, sub: string) {
  await q(
    `INSERT INTO "account" ("id", "accountId", "providerId", "userId", "accessToken", "refreshToken", "idToken",
       "accessTokenExpiresAt", "scope", "createdAt", "updatedAt")
     VALUES ($1, $2, 'oidc', $3, 'oidc-plain-access-token', 'oidc-plain-refresh-token', 'oidc.id.token',
       now() + interval '1 hour', 'openid email profile', now(), now())`,
    [`oidc_${sub}`, sub, userId],
  );
}

/** Social sign-in through the mock provider, following every redirect by hand. */
async function social(a: App, b: Browser, profile: { sub: string; email: string; name?: string; email_verified?: boolean }) {
  next({ name: profile.email.split("@")[0], email_verified: true, ...profile });
  // Better Auth 1.7.8's genericOAuth registers its providers as social providers, so both apps
  // use /sign-in/social and /callback/mock.
  const begin = await call(a, b, "POST", "/api/auth/sign-in/social", { provider: "mock", callbackURL: "/done" });
  if (!begin.json?.url) return { begin, callback: undefined as Res | undefined };
  const authorize = await fetch(begin.json.url, { redirect: "manual" });
  const back = new URL(authorize.headers.get("location") ?? "");
  const callback = await call(a, b, "GET", back.pathname + back.search);
  return { begin, callback };
}

function oidcSnapshot(row: any) {
  return row && JSON.stringify({ ...row });
}

// ------------------------------------------------------------------------------ the run

const mock = await startMock(mockPort);
const seeded: Record<string, { mail: string; id: string; b: Browser; token?: string }> = {};

try {
  await section("1. Better Auth creates the schema", async () => {
    const migrate = await run("npx", ["auth", "migrate", "--config", "better-auth/auth.ts", "--yes"], appEnv(ba));
    check("npx auth migrate --yes succeeds", migrate.code === 0 && /completed successfully/.test(migrate.out), migrate.out);
    const tables = (await q<any>("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY 1")).map((r) => r.table_name);
    check("it creates user, session, account and verification", JSON.stringify(tables) === '["account","session","user","verification"]', tables);
    await start(ba);
  });

  await section("2. Users, sessions and SSO rows from before fastauth", async () => {
    for (const tag of ["early", "early-refresh", "sso-verified", "sso-claim-link", "sso-claim-otp", "sso-claim-social", "sso-delete"]) {
      const b = browser();
      const mail = newEmail(tag);
      const res = await signUp(ba, b, mail);
      check(`Better Auth signs up ${tag}`, res.status === 200, res.text);
      seeded[tag] = { mail, id: res.json?.user?.id, b, token: res.json?.token };
    }
    for (const tag of ["sso-verified", "sso-claim-link", "sso-claim-otp", "sso-claim-social", "sso-delete"]) {
      await seedOidc(seeded[tag].id, `sub-${tag}`);
    }
    await q(`UPDATE "user" SET "emailVerified" = true WHERE "id" = ANY($1)`, [[seeded["sso-verified"].id, seeded["sso-delete"].id]]);
    // The OTP and social claims start from SSO-only users: no password.
    await q(`DELETE FROM "account" WHERE "providerId" = 'credential' AND "userId" = ANY($1)`, [[seeded["sso-claim-otp"].id, seeded["sso-claim-social"].id]]);
    const oidc = await q<any>(`SELECT count(*)::int AS n FROM "account" WHERE "providerId" = 'oidc'`);
    check("five oidc account rows seeded", oidc[0].n === 5, oidc);
    const reset = await call(ba, browser(), "POST", "/api/auth/request-password-reset", { email: seeded.early.mail, redirectTo: "/reset" });
    check("Better Auth writes a reset-password row to its verification table", reset.status === 200, reset.text);
    const stamp = await q("SELECT 1 FROM information_schema.columns WHERE table_name = 'user' AND column_name = 'securityStamp'");
    check("the seeded users have no securityStamp column yet", stamp.length === 0);
  });

  await section("3. fastauth's review-only migrations on top", async () => {
    const status = await run(env.FASTAUTH_BIN, ["status"], appEnv(fa));
    check("fastauth status lists pending steps and exits 1", status.code === 1 && /pending steps/.test(status.out), status.out);
    const migrate = await run(env.FASTAUTH_BIN, ["migrate"], appEnv(fa));
    check("fastauth migrate refuses (Migrations::ReviewOnly)", migrate.code !== 0, migrate.out);
    const dir = `${env.WORK}/migrations`;
    mkdirSync(dir, { recursive: true });
    const generate = await run(env.FASTAUTH_BIN, ["generate", "--out", dir], appEnv(fa));
    check("fastauth generate succeeds", generate.code === 0, generate.out);
    const files = readdirSync(dir).sort();
    const names = files.map((f) => f.replace(/^\d+_fastauth_/, "").replace(/\.sql$/, ""));
    check(
      "it writes exactly the four documented migrations, in order",
      JSON.stringify(names) === JSON.stringify(["add_user_securityStamp", "index_account_accountId", "unique_account_providerId_accountId", "create_verification"]),
      names,
    );
    check("no warnings", !/warning/i.test(generate.out), generate.out);
    const sql = files.map((f) => readFileSync(`${dir}/${f}`, "utf8"));
    check("1: securityStamp bigint NOT NULL DEFAULT 0", /ADD COLUMN "securityStamp" bigint NOT NULL DEFAULT 0/.test(sql[0] ?? ""), sql[0]);
    const duplicates = (sql[2] ?? "").match(/^--\s+(SELECT .*)$/m)?.[1];
    check("3: starts with a duplicate-check query", duplicates !== undefined, sql[2]);
    if (duplicates) {
      const rows = await q(duplicates);
      check("3: the duplicate check returns no rows on this database", rows.length === 0, rows);
    }
    check("4: creates fastauth_verification, not verification", /CREATE TABLE "fastauth_verification"/.test(sql[3] ?? ""), sql[3]);
    for (const [i, text] of sql.entries()) {
      try {
        await db.query(`BEGIN; ${text}; COMMIT;`);
        check(`applies ${files[i]}`, true);
      } catch (error) {
        await db.query("ROLLBACK");
        check(`applies ${files[i]}`, false, String(error));
      }
    }
    const after = await run(env.FASTAUTH_BIN, ["status"], appEnv(fa));
    check("fastauth status: up to date, no warnings", after.code === 0 && /up to date/.test(after.out) && !/warning/i.test(after.out), after.out);
  });

  await section("4. Better Auth after fastauth's migrations", async () => {
    const migrate = await run("npx", ["auth", "migrate", "--config", "better-auth/auth.ts"], appEnv(ba));
    check("npx auth migrate: No migrations needed", migrate.code === 0 && /No migrations needed/.test(migrate.out), migrate.out);
    const stamps = await q<any>('SELECT DISTINCT "securityStamp" AS s FROM "user"');
    check("the seeded users got securityStamp 0 from the default", stamps.length === 1 && Number(stamps[0].s) === 0, stamps);
    const early = seeded.early;
    const resolved = await getSession(ba, copy(early.b));
    check("a session Better Auth made before still resolves in Better Auth", resolved.json?.user?.id === early.id, resolved.text);
    const signedIn = await signIn(ba, browser(), early.mail);
    check("a user from before still signs in to Better Auth", signedIn.status === 200, signedIn.text);
    const fresh = await signedUp(ba, "ba-after-migrations");
    const row = (await q<any>('SELECT "securityStamp", "emailVerified" FROM "user" WHERE "id" = $1', [fresh.id]))[0];
    check("a Better Auth sign-up after the migrations gets securityStamp 0", Number(row?.securityStamp) === 0, row);
    check("and emailVerified false (Better Auth sets it; the column has no default)", row?.emailVerified === false, row);
    await start(fa);
    await start(baCache, { COOKIE_CACHE: "on" });
    await start(baHttps);
    await start(faHttps);
    await start(faEncrypted, { FASTAUTH_PLAINTEXT_TOKENS: "0" });
  });

  await section("5. Sign up in one app, sign in with the other", async () => {
    for (const from of [ba, fa]) {
      const to = other(from);
      const user = await signedUp(from, `up-${from.kind}`);
      const hash = (await accountRow(user.id, "credential"))?.password;
      check(`${from.name} writes a Better Auth scrypt hash (salt:key, hex)`, BA_HASH.test(hash ?? ""), hash);
      const res = await signIn(to, browser(), user.mail);
      check(`${to.name} signs in a user who signed up on ${from.name}`, res.status === 200 && res.json?.user?.id === user.id, res.text);
      const wrong = await signIn(to, browser(), user.mail, "wrong password here");
      check(`${to.name} refuses a wrong password`, wrong.status === 401, wrong.text);
      const mixed = await signIn(to, browser(), user.mail.toUpperCase());
      check(`${to.name} signs in with the email in another case`, mixed.status === 200, mixed.text);
    }
    const early = await signIn(fa, browser(), seeded.early.mail);
    check("fastauth signs in a user Better Auth created before fastauth existed", early.status === 200 && early.json?.user?.id === seeded.early.id, early.text);
    const dup = await signUp(fa, browser(), seeded.early.mail);
    check("fastauth refuses to sign up an email Better Auth already has", dup.status >= 400 && dup.status < 500, dup.text);
  });

  await section("6. Each app resolves the other's session cookie", async () => {
    const early = await getSession(fa, copy(seeded.early.b));
    check("fastauth resolves a session Better Auth made before fastauth existed", early.json?.user?.id === seeded.early.id, early.text);
    for (const from of [ba, fa]) {
      const to = other(from);
      const user = await signedUp(from, `cookie-${from.kind}`);
      const cookie = user.b.jar.get(TOKEN);
      check(`${from.name} sets ${TOKEN}`, cookie !== undefined, [...user.b.jar.keys()]);
      const seen = await getSession(to, copy(user.b));
      check(`${to.name} resolves ${from.name}'s cookie to the same user and session`, seen.json?.user?.id === user.id && seen.json?.session?.token === user.token, seen.text);
      const row = await sessionRow(user.token);
      check(`${from.name}'s session row holds the raw token`, row?.userId === user.id, row);
      if (from === fa) check("fastauth's token is 43 characters of base64url", /^[A-Za-z0-9_-]{43}$/.test(user.token), user.token);
      else check("Better Auth's token is 32 alphanumeric characters", /^[A-Za-z0-9]{32}$/.test(user.token), user.token);
      const tampered = copy(user.b);
      tampered.jar.set(TOKEN, cookie!.replace(/^./, (c) => (c === "a" ? "b" : "a")));
      const refused = await getSession(to, tampered);
      check(`${to.name} refuses ${from.name}'s cookie with a changed token`, refused.status === 200 && refused.json === null, refused.text);
      const unsigned = browser();
      unsigned.jar.set(TOKEN, user.token);
      const bare = await getSession(to, unsigned);
      check(`${to.name} refuses the bare token without a signature`, bare.json === null, bare.text);
      const me = await call(to, copy(user.b), "GET", "/app/me");
      check(`${to.name}'s own routes see ${from.name}'s session`, me.json?.id === user.id, me.text);
      await signIn(to, browser(), user.mail);
      const list = await call(to, copy(user.b), "GET", "/api/auth/list-sessions");
      check(`${to.name}'s /list-sessions lists the sessions of both apps`, Array.isArray(list.json) && list.json.length === 2, list.text);
    }
    for (const from of [baHttps, faHttps]) {
      const to = from === baHttps ? faHttps : baHttps;
      const user = await signedUp(from, `https-${from.kind}`);
      const header = user.b.jar.has(SECURE_TOKEN) ? "set" : undefined;
      check(`${from.name} on https sets ${SECURE_TOKEN}`, header !== undefined && !user.b.jar.has(TOKEN), [...user.b.jar.keys()]);
      const seen = await getSession(to, copy(user.b));
      check(`${to.name} resolves ${from.name}'s __Secure- cookie`, seen.json?.user?.id === user.id, seen.text);
      const plain = browser();
      plain.jar.set(TOKEN, user.b.jar.get(SECURE_TOKEN)!);
      const [baPlain, faPlain] = [await getSession(baHttps, copy(plain)), await getSession(faHttps, copy(plain))];
      check(`on https, neither app reads the cookie without __Secure- (${from.name}'s session)`, baPlain.json === null && faPlain.json === null, [baPlain.text, faPlain.text]);
    }
    const signIn1 = await signedUp(faHttps, "https-attrs");
    const res = await signIn(faHttps, signIn1.b, signIn1.mail);
    const attrs = setCookie(res, SECURE_TOKEN) ?? "";
    check("fastauth's __Secure- cookie is Secure, HttpOnly, SameSite=Lax, Path=/", /;\s*Secure/i.test(attrs) && /HttpOnly/i.test(attrs) && /SameSite=Lax/i.test(attrs) && /Path=\//i.test(attrs), attrs);
  });

  await section("7. Sign-out in one app counts in the other", async () => {
    for (const from of [ba, fa]) {
      const to = other(from);
      const user = await signedUp(to, `signout-${from.kind}`);
      const out = await signOut(from, copy(user.b));
      check(`${from.name} signs out ${to.name}'s session`, out.status === 200 && out.json?.success === true, out.text);
      check(`${from.name}'s sign-out clears the session cookie`, /max-age=0/i.test(setCookie(out, TOKEN) ?? ""), out.setCookies);
      const after = await getSession(to, copy(user.b));
      check(`${to.name} no longer resolves it`, after.json === null, after.text);
      check("the session row is gone", (await sessionRow(user.token)) === undefined);
    }
    for (const from of [ba, fa]) {
      const to = other(from);
      const user = await signedUp(to, `revoke-${from.kind}`);
      const second = browser();
      await signIn(from, second, user.mail);
      const revoke = await call(from, second, "POST", "/api/auth/revoke-session", { token: user.token });
      check(`${from.name}'s /revoke-session revokes a session ${to.name} made`, revoke.status === 200, revoke.text);
      const after = await getSession(to, copy(user.b));
      check(`${to.name} no longer resolves it`, after.json === null, after.text);
    }
  });

  await section("8. Password changes", async () => {
    for (const changer of [fa, ba]) {
      const otherApp = other(changer);
      const user = await signedUp(changer, `pw-revoke-${changer.kind}`);
      const there = browser();
      await signIn(otherApp, there, user.mail);
      const change = await call(changer, user.b, "POST", "/api/auth/change-password", { currentPassword: PASSWORD, newPassword: "new password 1234", revokeOtherSessions: true });
      check(`${changer.name} changes the password with revokeOtherSessions`, change.status === 200, change.text);
      check(`${otherApp.name}'s session is signed out`, (await getSession(otherApp, copy(there))).json === null);
      const own = await getSession(otherApp, copy(user.b));
      check(`${changer.name}'s current session still works in ${otherApp.name}`, own.json?.user?.id === user.id, own.text);
      const old = await signIn(otherApp, browser(), user.mail);
      check(`the old password fails in ${otherApp.name}`, old.status === 401, old.text);
      const fresh = await signIn(otherApp, browser(), user.mail, "new password 1234");
      check(`the new password works in ${otherApp.name}`, fresh.status === 200, fresh.text);
    }
    for (const changer of [fa, ba]) {
      const otherApp = other(changer);
      const user = await signedUp(changer, `pw-keep-${changer.kind}`);
      const there = browser();
      await signIn(otherApp, there, user.mail);
      const change = await call(changer, user.b, "POST", "/api/auth/change-password", { currentPassword: PASSWORD, newPassword: "new password 1234", revokeOtherSessions: false });
      check(`${changer.name} changes the password without revokeOtherSessions`, change.status === 200, change.text);
      const kept = await getSession(otherApp, copy(there));
      check(`${otherApp.name}'s session keeps working, as both apps document`, kept.json?.user?.id === user.id, kept.text);
      const old = await signIn(otherApp, browser(), user.mail);
      check(`the old password fails in ${otherApp.name}`, old.status === 401, old.text);
    }
    {
      // fastauth's reset revokes every session (revoke_sessions_on_password_reset, on by default).
      const user = await signedUp(ba, "reset-fastauth");
      const mark = outboxSize();
      await call(fa, browser(), "POST", "/api/auth/request-password-reset", { email: user.mail, redirectTo: "/reset" });
      const mail = await email(user.mail, "reset-password", mark);
      const token = new URL(mail.url).pathname.split("/").at(-1);
      const reset = await call(fa, browser(), "POST", "/api/auth/reset-password", { token, newPassword: "reset password 1234" });
      check("fastauth resets the password of a Better Auth user", reset.status === 200, reset.text);
      check("the Better Auth session is signed out", (await getSession(ba, copy(user.b))).json === null);
      check("the old password fails in Better Auth", (await signIn(ba, browser(), user.mail)).status === 401);
      check("the new password works in Better Auth", (await signIn(ba, browser(), user.mail, "reset password 1234")).status === 200);
    }
    {
      // Better Auth's reset keeps sessions (revokeSessionsOnPasswordReset is off in app.config.ts).
      const user = await signedUp(fa, "reset-better-auth");
      const mark = outboxSize();
      await call(ba, browser(), "POST", "/api/auth/request-password-reset", { email: user.mail, redirectTo: "/reset" });
      const mail = await email(user.mail, "reset-password", mark);
      const token = new URL(mail.url).pathname.split("/").at(-1);
      const reset = await call(ba, browser(), "POST", "/api/auth/reset-password", { token, newPassword: "reset password 1234" });
      check("Better Auth resets the password of a fastauth user", reset.status === 200, reset.text);
      const kept = await getSession(fa, copy(user.b));
      check("the fastauth session keeps working (Better Auth's revokeSessionsOnPasswordReset is off)", kept.json?.user?.id === user.id, kept.text);
      check("the old password fails in fastauth", (await signIn(fa, browser(), user.mail)).status === 401);
      check("the new password works in fastauth", (await signIn(fa, browser(), user.mail, "reset password 1234")).status === 200);
    }
  });

  await section("9. Session refresh (expiresAt rule, 14 days, updateAge 1 day)", async () => {
    for (const from of [ba, fa]) {
      const to = other(from);
      const user = await signedUp(from, `refresh-${from.kind}`);
      const created = new Date((await sessionRow(user.token)).expiresAt).getTime();
      check(`${from.name} creates a session lasting 14 days`, Math.abs(created - Date.now() - EXPIRES_IN) < 60_000, created - Date.now());
      await setExpiresAt(user.token, Date.now() + EXPIRES_IN - DAY + 60 * 60 * 1000);
      const notDue = await getSession(to, copy(user.b));
      const notDueAt = new Date((await sessionRow(user.token)).expiresAt).getTime();
      check(`${to.name} doesn't extend a session extended 23 hours ago`, notDue.json?.user?.id === user.id && notDueAt < Date.now() + EXPIRES_IN - DAY + 2 * 60 * 60 * 1000, notDueAt - Date.now());
      check(`${to.name} sets no session cookie then`, setCookie(notDue, TOKEN) === undefined, notDue.setCookies);
      await setExpiresAt(user.token, Date.now() + EXPIRES_IN - DAY - 60_000);
      const due = await getSession(to, user.b);
      const dueAt = new Date((await sessionRow(user.token)).expiresAt).getTime();
      check(`${to.name} extends ${from.name}'s session once a day has passed`, Math.abs(dueAt - Date.now() - EXPIRES_IN) < 60_000, dueAt - Date.now());
      const cookie = setCookie(due, TOKEN);
      check(`${to.name} sets the cookie again with Max-Age 14 days`, Math.abs((maxAge(cookie) ?? 0) - EXPIRES_IN / 1000) < 60, cookie);
      const back = await getSession(from, copy(user.b));
      check(`${from.name} resolves the refreshed cookie`, back.json?.user?.id === user.id, back.text);
      await setExpiresAt(user.token, Date.now() - 1000);
      const [expiredHere, expiredThere] = [await getSession(from, copy(user.b)), await getSession(to, copy(user.b))];
      check("neither app resolves an expired session", expiredHere.json === null && expiredThere.json === null, [expiredHere.text, expiredThere.text]);
    }
    for (const from of [ba, fa]) {
      const to = other(from);
      const b = browser();
      const mail = newEmail(`dont-remember-${from.kind}`);
      await signUp(from, browser(), mail);
      const res = await signIn(from, b, mail, PASSWORD, { rememberMe: false });
      check(`${from.name} sets vt.dont_remember for rememberMe: false`, b.jar.has("vt.dont_remember"), [...b.jar.keys()]);
      const token = res.json?.token;
      const row = await sessionRow(token);
      await setExpiresAt(token, Date.now() + 60_000);
      await q('UPDATE "session" SET "createdAt" = $1 WHERE "token" = $2', [new Date(Date.now() - 2 * DAY), token]);
      await getSession(to, copy(b));
      const after = new Date((await sessionRow(token)).expiresAt).getTime();
      check(`${to.name} doesn't extend ${from.name}'s rememberMe: false session`, after < Date.now() + 2 * 60_000, { before: row?.expiresAt, after: after - Date.now() });
    }
  });

  await section("10. customerId, written by one app's code and read by the other", async () => {
    for (const writer of [ba, fa]) {
      const reader = other(writer);
      const user = await signedUp(writer, `customer-${writer.kind}`);
      const id = `cus_${writer.kind}_${randomBytes(4).toString("hex")}`;
      const set = await call(writer, user.b, "POST", "/app/customer-id", { customerId: id });
      check(`${writer.name}'s code writes customerId`, set.status === 200, set.text);
      const column = (await q<any>('SELECT "customerId" FROM "user" WHERE "id" = $1', [user.id]))[0]?.customerId;
      check('it lands in "user"."customerId"', column === id, column);
      const me = await call(reader, copy(user.b), "GET", "/app/me");
      check(`${reader.name}'s code reads it`, me.json?.customerId === id, me.text);
      const session = await getSession(reader, copy(user.b));
      check(`${reader.name}'s get-session returns it as customerId`, session.json?.user?.customerId === id, session.json?.user);
    }
    for (const a of [ba, fa]) {
      const b = browser();
      const mail = newEmail(`customer-input-${a.kind}`);
      await signUp(a, b, mail, PASSWORD, { customerId: "cus_forged" });
      const column = (await q<any>('SELECT "customerId" FROM "user" WHERE "email" = $1', [mail]))[0]?.customerId;
      check(`a client can't set customerId at sign-up in ${a.name}`, column == null, column);
    }
  });

  await section("11. Better Auth's scrypt hashes, both ways", async () => {
    const early = (await accountRow(seeded.early.id, "credential"))?.password;
    check("a hash Better Auth wrote before fastauth is salt:key hex", BA_HASH.test(early ?? ""), early);
    check("fastauth verifies it", (await signIn(fa, browser(), seeded.early.mail)).status === 200);
    const user = await signedUp(fa, "rollback");
    await stop(fa);
    const rollback = await signIn(ba, browser(), user.mail);
    check("with fastauth stopped (a rollback), Better Auth verifies a hash fastauth wrote", rollback.status === 200, rollback.text);
    await start(fa);
    const mail = newEmail("nfkc");
    const nfkcUp = await signUp(fa, browser(), mail, "\ufb01sh and chips 123");
    const nfkc = await signIn(ba, browser(), mail, "fish and chips 123");
    check("an NFKC-equivalent password (ﬁ = fi) set in fastauth verifies in Better Auth", nfkcUp.status === 200 && nfkc.status === 200, [nfkcUp.text, nfkc.text]);
  });

  await section("12. The oidc rows fastauth doesn't own", async () => {
    const snapshot = async (tag: string) => oidcSnapshot(await accountRow(seeded[tag].id, "oidc"));
    const before: Record<string, string> = {};
    for (const tag of ["sso-verified", "sso-claim-link", "sso-claim-otp", "sso-claim-social", "sso-delete"]) before[tag] = await snapshot(tag);
    // Better Auth deletes expired verification rows itself whenever it looks one up, so the
    // expired row goes in now, and only fastauth runs until the check at the end.
    await q(`INSERT INTO "verification" ("id", "identifier", "value", "expiresAt", "createdAt", "updatedAt")
             VALUES ('ba-expired', 'ba-expired-identifier', 'x', now() - interval '1 day', now(), now())`);
    const baVerification = await q<any>('SELECT "id", "identifier", "value", "expiresAt" FROM "verification" ORDER BY "id"');

    {
      const s = seeded["sso-verified"];
      const mark = outboxSize();
      const b = browser();
      await call(fa, b, "POST", "/api/auth/sign-in/magic-link", { email: s.mail, callbackURL: "/done" });
      const link = new URL((await email(s.mail, "magic-link", mark)).url);
      const verify = await call(fa, b, "GET", link.pathname + link.search);
      check("a verified SSO user signs in with a magic link", verify.status === 302 && b.jar.has(TOKEN), [verify.status, verify.text]);
      check("the oidc row is untouched", (await snapshot("sso-verified")) === before["sso-verified"]);
      const list = await call(fa, b, "GET", "/api/auth/list-accounts");
      check("fastauth's /list-accounts leaves the oidc row out", Array.isArray(list.json) && !list.json.some((a: any) => a.providerId === "oidc"), list.text);
      const baList = await call(ba, copy(b), "GET", "/api/auth/list-accounts");
      check("Better Auth's /list-accounts still shows it", Array.isArray(baList.json) && baList.json.some((a: any) => a.providerId === "oidc"), baList.text);
      const unlink = await call(fa, b, "POST", "/api/auth/unlink-account", { providerId: "oidc", accountId: "sub-sso-verified" });
      check("fastauth's /unlink-account answers ACCOUNT_NOT_FOUND for it", unlink.status === 400 && unlink.json?.code === "ACCOUNT_NOT_FOUND", unlink.text);
      const update = await call(fa, b, "POST", "/api/auth/update-user", { name: "Renamed SSO user" });
      check("fastauth's /update-user works for the user", update.status === 200, update.text);
      const revoke = await call(fa, b, "POST", "/api/auth/revoke-sessions", {});
      check("fastauth's /revoke-sessions works for the user", revoke.status === 200, revoke.text);
      check("the oidc row is still untouched", (await snapshot("sso-verified")) === before["sso-verified"]);
    }
    {
      const s = seeded["sso-claim-link"];
      const stamp = Number((await q<any>('SELECT "securityStamp" FROM "user" WHERE "id" = $1', [s.id]))[0].securityStamp);
      const mark = outboxSize();
      const b = browser();
      await call(fa, b, "POST", "/api/auth/sign-in/magic-link", { email: s.mail, callbackURL: "/done" });
      const link = new URL((await email(s.mail, "magic-link", mark)).url);
      const verify = await call(fa, b, "GET", link.pathname + link.search);
      check("a magic link claims an unverified SSO user with a password", verify.status === 302 && b.jar.has(TOKEN), [verify.status, verify.text]);
      const row = (await q<any>('SELECT "emailVerified", "securityStamp" FROM "user" WHERE "id" = $1', [s.id]))[0];
      check("the user is verified and its securityStamp changed", row.emailVerified === true && Number(row.securityStamp) !== stamp, row);
      check("the claim deletes the credential account (owned)", (await accountRow(s.id, "credential")) === undefined);
      check("the claim signs out the session Better Auth made before", (await getSession(ba, copy(s.b))).json === null);
      check("the oidc row survives the claim, untouched", (await snapshot("sso-claim-link")) === before["sso-claim-link"]);
    }
    {
      const s = seeded["sso-claim-otp"];
      const mark = outboxSize();
      const b = browser();
      const send = await call(fa, b, "POST", "/api/auth/email-otp/send-verification-otp", { email: s.mail, type: "sign-in" });
      check("fastauth sends a sign-in code", send.status === 200, send.text);
      const code = (await email(s.mail, "email-otp-sign-in", mark)).code;
      const signInOtp = await call(fa, b, "POST", "/api/auth/sign-in/email-otp", { email: s.mail, otp: code });
      check("an email code claims an unverified SSO-only user", signInOtp.status === 200 && signInOtp.json?.user?.id === s.id, signInOtp.text);
      check("the oidc row survives the claim, untouched", (await snapshot("sso-claim-otp")) === before["sso-claim-otp"]);
      const baSees = await getSession(ba, copy(b));
      check("Better Auth resolves the session the code created", baSees.json?.user?.id === s.id, baSees.text);
    }
    {
      const s = seeded["sso-claim-social"];
      const b = browser();
      const { callback } = await social(fa, b, { sub: "mock-sso-claim-social", email: s.mail, email_verified: true });
      check("a verified social profile claims an unverified SSO-only user", callback?.status === 302 && b.jar.has(TOKEN), callback?.text);
      const seen = await getSession(fa, copy(b));
      check("as that user", seen.json?.user?.id === s.id, seen.text);
      check("the oidc row survives the claim, untouched", (await snapshot("sso-claim-social")) === before["sso-claim-social"]);
    }
    const kept = await q<any>('SELECT "id", "identifier", "value", "expiresAt" FROM "verification" ORDER BY "id"');
    check("fastauth never read, changed or pruned Better Auth's verification rows (the expired one included)", JSON.stringify(kept) === JSON.stringify(baVerification), { before: baVerification, after: kept });
  });

  await section("13. Social sign-in, a provider both apps configure (mock OAuth)", async () => {
    // The sub the provider answers for an access token, or undefined when it refuses it.
    const providerSub = async (token: unknown) => {
      const res = await fetch(`${env.MOCK_OAUTH_URL}/userinfo`, { headers: { authorization: `Bearer ${token}` } });
      return res.status === 200 ? ((await res.json()) as any).sub : undefined;
    };
    const getAccessToken = (b: Browser, accountId: string) => call(ba, copy(b), "POST", "/api/auth/get-access-token", { accountId });
    const readTokens = (a: App, b: Browser) => call(a, copy(b), "GET", "/app/provider-token");

    const mail = newEmail("social-ba-first");
    const b = browser();
    const first = await social(ba, b, { sub: "mock-ba-first", email: mail });
    check("Better Auth signs up a user through the provider", first.callback?.status === 302 && b.jar.has(TOKEN), [first.begin.text, first.callback?.text]);
    const userId = (await getSession(ba, copy(b))).json?.user?.id;
    const plain = (await accountRow(userId, "mock"))?.accessToken;
    check("Better Auth stores the access token as plain text", typeof plain === "string" && plain.startsWith("mock-access-"), plain);
    const fb = browser();
    const then = await social(fa, fb, { sub: "mock-ba-first", email: mail });
    check("fastauth signs the same user in on that account row (no 500 on plain tokens)", then.callback?.status === 302 && fb.jar.has(TOKEN), [then.begin.text, then.callback?.status, then.callback?.text]);
    const fid = (await getSession(fa, copy(fb))).json?.user?.id;
    check("as the same user", fid === userId, fid);
    const stored = await accountRow(userId, "mock");
    check(
      "with store_oauth_tokens_in_plaintext, fastauth stores the provider's new tokens as plain text",
      stored?.accessToken?.startsWith("mock-access-") && stored.accessToken !== plain && stored?.refreshToken?.startsWith("mock-refresh-"),
      stored,
    );
    check("one mock account row for the user", (await q('SELECT 1 FROM "account" WHERE "userId" = $1 AND "providerId" = $2', [userId, "mock"])).length === 1);
    const fresh = await getAccessToken(b, stored?.id);
    check("Better Auth's /get-access-token returns the token fastauth stored", fresh.status === 200 && fresh.json?.accessToken === stored?.accessToken, fresh.text);
    check("and the provider accepts it", (await providerSub(fresh.json?.accessToken)) === "mock-ba-first");
    const own = await readTokens(fa, fb);
    check("fastauth's code reads the tokens back (Account::read_access_token)", own.json?.accessToken === stored?.accessToken && own.json?.refreshToken === stored?.refreshToken, own.text);

    const eb = browser();
    const sealedIn = await social(faEncrypted, eb, { sub: "mock-ba-first", email: mail });
    check("fastauth with encrypted tokens (the default) signs the user in on the same row", sealedIn.callback?.status === 302 && eb.jar.has(TOKEN), sealedIn.callback?.text);
    const sealed = await accountRow(userId, "mock");
    check("it stores its ciphertext, as hex", /^[0-9a-f]+$/.test(sealed?.accessToken ?? "") && /^[0-9a-f]+$/.test(sealed?.refreshToken ?? ""), sealed);
    const stale = await getAccessToken(b, sealed?.id);
    check(
      "the documented gap without the knob: Better Auth's /get-access-token returns fastauth's ciphertext",
      stale.status === 200 && stale.json?.accessToken === sealed?.accessToken,
      stale.text,
    );
    check("which the provider refuses", (await providerSub(stale.json?.accessToken)) === undefined);
    const mixed = await readTokens(fa, fb);
    check(
      "fastauth with plain-text tokens still reads the encrypted row",
      (await providerSub(mixed.json?.accessToken)) === "mock-ba-first" && mixed.json?.refreshToken?.startsWith("mock-refresh-"),
      mixed.text,
    );
    const again = await social(ba, browser(), { sub: "mock-ba-first", email: mail });
    check("Better Auth signs in again on the row fastauth wrote", again.callback?.status === 302 && !/error/.test(again.callback?.location ?? ""), again.callback?.location);
    const restored = (await accountRow(userId, "mock"))?.accessToken;
    check("and writes the provider's plain token back", typeof restored === "string" && restored.startsWith("mock-access-"), restored);
    const back = await readTokens(faEncrypted, eb);
    check("fastauth with encrypted tokens reads Better Auth's plain token as it is", back.json?.accessToken === restored, back.text);

    const mail2 = newEmail("social-fa-first");
    const b2 = browser();
    const fFirst = await social(fa, b2, { sub: "mock-fa-first", email: mail2 });
    check("fastauth signs up a user through the provider", fFirst.callback?.status === 302 && b2.jar.has(TOKEN), fFirst.callback?.text);
    const fUser = (await getSession(fa, copy(b2))).json?.user?.id;
    const fRow = await accountRow(fUser, "mock");
    const fToken = await getAccessToken(b2, fRow?.id);
    check("Better Auth's /get-access-token returns a token the provider accepts for it", (await providerSub(fToken.json?.accessToken)) === "mock-fa-first", fToken.text);
    const bb = browser();
    const bThen = await social(ba, bb, { sub: "mock-fa-first", email: mail2 });
    const bUser = (await getSession(ba, copy(bb))).json?.user?.id;
    check("Better Auth signs the same user in on fastauth's row", bThen.callback?.status === 302 && bUser === fUser, [bThen.callback?.location, bUser, fUser]);
    const list = await call(fa, copy(b2), "GET", "/api/auth/list-accounts");
    check("fastauth lists the mock account", Array.isArray(list.json) && list.json.some((a: any) => a.providerId === "mock"), list.text);
  });

  await section("14. Better Auth's cookie cache (session_data)", async () => {
    {
      const user = await signedUp(ba, "cache-off");
      const revoke = await call(fa, copy(user.b), "POST", "/api/auth/revoke-sessions", {});
      check("fastauth revokes every session of a Better Auth user", revoke.status === 200, revoke.text);
      const after = await getSession(ba, copy(user.b));
      check("with cookieCache off, Better Auth signs the user out at once", after.json === null, after.text);
    }
    {
      const b = browser();
      const mail = newEmail("cache-on");
      await signUp(baCache, browser(), mail);
      await signIn(baCache, b, mail);
      check("Better Auth with cookieCache on sets vt.session_data", b.jar.has("vt.session_data"), [...b.jar.keys()]);
      const cached = await getSession(baCache, copy(b));
      check("and resolves the session", cached.json?.user?.email === mail, cached.text);
      const revoke = await call(fa, copy(b), "POST", "/api/auth/revoke-sessions", {});
      check("fastauth revokes the session", revoke.status === 200, revoke.text);
      const gap = await getSession(baCache, copy(b));
      check("the documented gap: Better Auth's cache still answers with the revoked session", gap.json?.user?.email === mail, gap.text);
      const bypass = await getSession(baCache, copy(b), "?disableCookieCache=true");
      check("Better Auth without its cache (disableCookieCache) sees the revocation", bypass.json === null, bypass.text);
      const off = await getSession(ba, copy(b));
      check("the instance with cookieCache off sees it too", off.json === null, off.text);
    }
    {
      const b = browser();
      const mail = newEmail("cache-signout");
      await signUp(baCache, browser(), mail);
      await signIn(baCache, b, mail);
      const out = await signOut(fa, b);
      check("fastauth's sign-out deletes vt.session_data", /max-age=0/i.test(setCookie(out, "vt.session_data") ?? ""), out.setCookies);
      check("so the cache is gone from the browser", !b.jar.has("vt.session_data"), [...b.jar.keys()]);
      const after = await getSession(baCache, copy(b));
      check("and the cookie-cache instance is signed out", after.json === null, after.text);
    }
  });

  if (env.DUAL_ADMIN !== "0") {
    await section("15. A later fastauth upgrade: the admin plugin's migrations", async () => {
      await stop(fa);
      const admin = { FASTAUTH_ADMIN: "1" };
      const dir = `${env.WORK}/migrations-admin`;
      mkdirSync(dir, { recursive: true });
      const generate = await run(env.FASTAUTH_BIN, ["generate", "--out", dir], appEnv(fa, admin));
      check("fastauth generate writes the admin plugin's migrations", generate.code === 0, generate.out);
      const files = readdirSync(dir).sort();
      const sql = files.map((f) => readFileSync(`${dir}/${f}`, "utf8"));
      console.log(`       ${files.map((f) => f.replace(/^\d+_fastauth_/, "")).join(", ")}`);
      check("only added columns, each nullable or with a default", sql.every((s) => /ADD COLUMN/.test(s) && !/NOT NULL(?! DEFAULT)/.test(s.replace(/^--.*$/gm, ""))), sql);
      for (const [i, text] of sql.entries()) {
        try {
          await db.query(`BEGIN; ${text}; COMMIT;`);
          check(`applies ${files[i]}`, true);
        } catch (error) {
          await db.query("ROLLBACK");
          check(`applies ${files[i]}`, false, String(error));
        }
      }
      const status = await run(env.FASTAUTH_BIN, ["status"], appEnv(fa, admin));
      check("fastauth status: up to date", status.code === 0, status.out);
      const migrate = await run("npx", ["auth", "migrate", "--config", "better-auth/auth.ts"], appEnv(ba));
      check("npx auth migrate: still No migrations needed", /No migrations needed/.test(migrate.out), migrate.out);
      const baUser = await signedUp(ba, "after-admin");
      check("Better Auth still signs users up", baUser.id !== undefined);
      await start(fa, admin);
      const adminUser = await signedUp(fa, "admin");
      await q(`UPDATE "user" SET "role" = 'admin' WHERE "id" = $1`, [adminUser.id]);
      const ab = browser();
      await signIn(fa, ab, adminUser.mail);
      const target = seeded["sso-delete"];
      const before = oidcSnapshot(await accountRow(target.id, "oidc"));
      const remove = await call(fa, ab, "POST", "/api/auth/admin/remove-user", { userId: target.id });
      check("removing a user with an oidc row answers 409 USER_HAS_FOREIGN_ACCOUNTS", remove.status === 409 && remove.json?.code === "USER_HAS_FOREIGN_ACCOUNTS", remove.text);
      check("the user is still there", (await q('SELECT 1 FROM "user" WHERE "id" = $1', [target.id])).length === 1);
      check("and the oidc row is untouched", oidcSnapshot(await accountRow(target.id, "oidc")) === before);
      check("the user still signs in to Better Auth", (await signIn(ba, browser(), target.mail)).status === 200);
      const removable = await call(fa, ab, "POST", "/api/auth/admin/remove-user", { userId: baUser.id });
      check("removing a user without one works", removable.status === 200, removable.text);
      check("and Better Auth no longer signs them in", (await signIn(ba, browser(), baUser.mail)).status === 401);
      const seen = await getSession(ba, copy(adminUser.b));
      check("Better Auth resolves sessions of users with the admin columns set", seen.json?.user?.id === adminUser.id, seen.text);
    });
  }
} finally {
  mock.close();
  for (const a of apps) await stop(a);
  await db.end();
}

const failures = summary();
if (failures > 0) console.log(`\nlogs: ${apps.map((a) => a.log).join(" ")}`);
process.exit(failures === 0 ? 0 : 1);
