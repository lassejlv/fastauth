import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { createAuthClient } from "better-auth/client";
import { twoFactorClient } from "better-auth/client/plugins";
import { apiKeyClient } from "@better-auth/api-key/client";

const BASE_URL = process.env.FASTAUTH_URL ?? "http://localhost:3000";
const SERVER_LOG = process.env.FASTAUTH_LOG;
const ORIGIN = new URL(BASE_URL).origin;

/**
 * A fetch that behaves like a browser tab: it keeps the cookies the server sets and sends
 * them back, and it sends Origin on every request, which the CSRF check needs on
 * cookie-carrying POSTs. Node's fetch does neither on its own.
 */
function cookieJarFetch() {
  const jar = new Map<string, string>();
  const fetchImpl = async (input: string | URL | Request, init?: RequestInit) => {
    const request = new Request(input, init);
    request.headers.set("origin", ORIGIN);
    if (jar.size > 0) {
      request.headers.set(
        "cookie",
        [...jar].map(([name, value]) => `${name}=${value}`).join("; "),
      );
    }
    let response = await fetch(request.clone());
    while (response.status === 429) {
      const wait = Number(response.headers.get("retry-after") ?? 10);
      console.log(`  ...  rate limited on ${new URL(request.url).pathname}, retrying in ${wait}s`);
      await new Promise((resolve) => setTimeout(resolve, wait * 1000));
      response = await fetch(request.clone());
    }
    for (const header of response.headers.getSetCookie()) {
      const [pair, ...attributes] = header.split(";").map((part) => part.trim());
      const eq = pair.indexOf("=");
      const name = pair.slice(0, eq);
      const value = pair.slice(eq + 1);
      const expired = attributes.some((a) => a.toLowerCase() === "max-age=0");
      if (expired || value === "") jar.delete(name);
      else jar.set(name, value);
    }
    return response;
  };
  return { jar, fetchImpl };
}

function newClient() {
  const { jar, fetchImpl } = cookieJarFetch();
  const client = createAuthClient({
    baseURL: BASE_URL,
    plugins: [twoFactorClient(), apiKeyClient()],
    fetchOptions: { customFetchImpl: fetchImpl },
  });
  return { client, jar };
}

let failures = 0;
let passes = 0;

function check(name: string, condition: unknown, detail?: unknown) {
  if (condition) {
    passes++;
    console.log(`  ok   ${name}`);
    return;
  }
  failures++;
  console.log(`  FAIL ${name}`);
  if (detail !== undefined) console.log(`       ${JSON.stringify(detail)}`);
}

async function step(name: string, body: () => Promise<void>) {
  console.log(name);
  try {
    await body();
  } catch (error) {
    failures++;
    console.log(`  FAIL threw: ${error instanceof Error ? error.stack : String(error)}`);
  }
}

function base32Decode(input: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const char of input.replace(/=+$/, "").toUpperCase()) {
    value = (value << 5) | alphabet.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** RFC 6238 TOTP for the time step containing unixSeconds. */
function totp(totpURI: string, unixSeconds: number): string {
  const params = new URL(totpURI).searchParams;
  const secret = base32Decode(params.get("secret") ?? "");
  const period = Number(params.get("period") ?? 30);
  const digits = Number(params.get("digits") ?? 6);
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(unixSeconds / period)));
  const hmac = createHmac(params.get("algorithm")?.toLowerCase() ?? "sha1", secret)
    .update(counter)
    .digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = (hmac.readUInt32BE(offset) & 0x7fffffff) % 10 ** digits;
  return code.toString().padStart(digits, "0");
}

/**
 * Reads the newest reset token from the server's log. The example server uses LogMailer,
 * which logs each email instead of sending it.
 */
function resetTokenFromLog(): string | undefined {
  if (!SERVER_LOG) return undefined;
  const log = readFileSync(SERVER_LOG, "utf8");
  return [...log.matchAll(/\/reset-password\/([A-Za-z0-9_-]+)/g)].at(-1)?.[1];
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const field = (value: unknown, key: string) => (value as Record<string, unknown> | null | undefined)?.[key];

const email = `compat-${Date.now().toString(36)}@example.com`;
let password = "correct horse battery";
const alice = newClient();
const other = newClient();

console.log(`better-auth client against ${BASE_URL} (${email})\n`);

await step("signUp.email", async () => {
  const { data, error } = await alice.client.signUp.email({
    email,
    password,
    name: "Alice",
    plan: "pro",
  } as Parameters<typeof alice.client.signUp.email>[0]);
  check("no error", !error, error);
  check("returns a token", typeof data?.token === "string" && data.token.length > 0, data);
  check("returns the user", data?.user.email === email && data.user.name === "Alice", data);
  check("user.emailVerified is false", data?.user.emailVerified === false, data?.user);
  check("app field plan is stored", field(data?.user, "plan") === "pro", data?.user);
  check("session cookie set", alice.jar.size > 0, [...alice.jar.keys()]);
});

await step("getSession", async () => {
  const { data, error } = await alice.client.getSession();
  check("no error", !error, error);
  check("user matches", data?.user.email === email, data);
  check("session.userId matches user.id", data?.session.userId === data?.user.id, data?.session);
  check(
    "session.expiresAt is a date",
    !Number.isNaN(new Date(data?.session.expiresAt ?? "").getTime()),
    data?.session,
  );
});

await step("signUp.email with a taken email", async () => {
  const { data, error } = await other.client.signUp.email({ email, password, name: "Mallory" });
  check("no data", data === null, data);
  check("status 422", error?.status === 422, error);
  check(
    "error.code USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL",
    error?.code === "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL",
    error,
  );
});

await step("signOut", async () => {
  const { data, error } = await alice.client.signOut();
  check("no error", !error, error);
  check("success", data?.success === true, data);
  const session = await alice.client.getSession();
  check("getSession is null afterwards", session.data === null && !session.error, session);
});

await step("signIn.email with a wrong password", async () => {
  const { data, error } = await alice.client.signIn.email({ email, password: "wrong password!" });
  check("no data", data === null, data);
  check("status 401", error?.status === 401, error);
  check("error.code INVALID_EMAIL_OR_PASSWORD", error?.code === "INVALID_EMAIL_OR_PASSWORD", error);
});

let otherToken = "";
await step("signIn.email", async () => {
  const { data, error } = await alice.client.signIn.email({ email, password });
  check("no error", !error, error);
  check("returns a token", typeof data?.token === "string" && data.token.length > 0, data);
  check("redirect is false", data?.redirect === false, data);
  check("returns the user", data?.user.email === email, data);
  const session = await alice.client.getSession();
  check("getSession works", session.data?.user.email === email, session);

  const second = await other.client.signIn.email({ email, password });
  check("a second sign-in works", !second.error && typeof second.data?.token === "string", second);
  otherToken = second.data?.token ?? "";
});

await step("listSessions", async () => {
  const { data, error } = await alice.client.listSessions();
  check("no error", !error, error);
  check("two sessions", Array.isArray(data) && data.length === 2, data);
  check("all sessions belong to the user", new Set((data ?? []).map((s) => s.userId)).size === 1, data);
});

await step("revokeSession with the other client's token", async () => {
  const { data, error } = await alice.client.revokeSession({ token: otherToken });
  check("no error", !error, error);
  check("status true", data?.status === true, data);
  const revoked = await other.client.getSession();
  check("other client is signed out", revoked.data === null, revoked);
  const still = await alice.client.getSession();
  check("this client is still signed in", still.data?.user.email === email, still);
  const list = await alice.client.listSessions();
  check("one session left", list.data?.length === 1, list);
});

await step("revokeSession by id, from listSessions", async () => {
  const signIn = await other.client.signIn.email({ email, password });
  check("the other client signs in again", !signIn.error, signIn.error);
  const current = await alice.client.getSession();
  const list = await alice.client.listSessions();
  check("listSessions has no tokens (they are stored hashed)", list.data?.every((s) => !("token" in s)), list.data);
  const target = list.data?.find((s) => s.id !== current.data?.session.id);
  check("the other session is listed", target, list.data);
  const { data, error } = await alice.client.revokeSession({ id: target?.id } as unknown as { token: string });
  check("no error", !error, error);
  check("status true", data?.status === true, data);
  const revoked = await other.client.getSession();
  check("other client is signed out", revoked.data === null, revoked);
});

await step("updateUser", async () => {
  const { data, error } = await alice.client.updateUser({
    name: "Alice Updated",
    plan: "team",
  } as Parameters<typeof alice.client.updateUser>[0]);
  check("no error", !error, error);
  check("status true", data?.status === true, data);
  const session = await alice.client.getSession({ query: { disableCookieCache: true } });
  check("getSession shows the new name", session.data?.user.name === "Alice Updated", session.data?.user);
  check("getSession shows the new plan", field(session.data?.user, "plan") === "team", session.data?.user);
});

await step("changePassword", async () => {
  const newPassword = "even more correct horse";
  const wrong = await alice.client.changePassword({ currentPassword: "nope nope nope", newPassword });
  check("wrong current password: status 400", wrong.error?.status === 400, wrong.error);
  check("wrong current password: error.code INVALID_PASSWORD", wrong.error?.code === "INVALID_PASSWORD", wrong.error);

  const { data, error } = await alice.client.changePassword({
    currentPassword: password,
    newPassword,
    revokeOtherSessions: true,
  });
  check("no error", !error, error);
  check("returns the user", data?.user.email === email, data);
  password = newPassword;
  const session = await alice.client.getSession();
  check("still signed in", session.data?.user.email === email, session);
  const signIn = await other.client.signIn.email({ email, password });
  check("the new password signs in", !signIn.error, signIn.error);
  await other.client.signOut();
});

await step("requestPasswordReset + resetPassword", async () => {
  const { data, error } = await alice.client.requestPasswordReset({
    email,
    redirectTo: `${ORIGIN}/reset-password`,
  });
  check("no error", !error, error);
  check("status true", data?.status === true, data);
  if (!SERVER_LOG) {
    console.log("  skip resetPassword: set FASTAUTH_LOG to the server's log file to read the token");
    return;
  }
  await sleep(200);
  const token = resetTokenFromLog();
  check("token found in the server log", token, SERVER_LOG);
  if (!token) return;
  const newPassword = "reset correct horse battery";
  const reset = await other.client.resetPassword({ newPassword, token });
  check("resetPassword: no error", !reset.error, reset.error);
  check("resetPassword: status true", reset.data?.status === true, reset.data);
  password = newPassword;
  const reused = await other.client.resetPassword({ newPassword, token });
  check("a used token: error.code INVALID_TOKEN", reused.error?.code === "INVALID_TOKEN", reused.error);
  const signIn = await alice.client.signIn.email({ email, password });
  check("the reset password signs in", !signIn.error, signIn.error);
});

await step("apiKey (skipped when the server has no api-key plugin)", async () => {
  const probe = await fetch(`${BASE_URL}/api/auth/api-key/list`);
  if (probe.status === 404) {
    console.log("  skip: /api-key/list is 404, the server doesn't register the api-key plugin");
    return;
  }
  const created = await alice.client.apiKey.create({ name: "compat", prefix: "ck_" });
  check("create: no error", !created.error, created.error);
  const key = created.data?.key ?? "";
  check("create: returns the key once", key.startsWith("ck_") && key.length > 64, created.data);
  check("create: start is the key's first characters", key.startsWith(created.data?.start ?? "-"), created.data);
  check("create: referenceId is the user", typeof created.data?.referenceId === "string", created.data);
  check("create: rateLimitMax defaults to 10", created.data?.rateLimitMax === 10, created.data);
  const id = created.data?.id ?? "";

  const serverOnly = await alice.client.apiKey.create({ remaining: 5 } as never);
  check("create with remaining: status 400", serverOnly.error?.status === 400, serverOnly.error);
  check("create with remaining: SERVER_ONLY_PROPERTY", serverOnly.error?.code === "SERVER_ONLY_PROPERTY", serverOnly.error);

  const list = await alice.client.apiKey.list();
  check("list: no error", !list.error, list.error);
  check("list: one key, total 1", list.data?.apiKeys.length === 1 && list.data.total === 1, list.data);
  check("list: no key or hash", list.data?.apiKeys.every((k) => !("key" in k) && !("keyHash" in k)), list.data);

  const got = await alice.client.apiKey.get({ query: { id } });
  check("get: no error", !got.error, got.error);
  check("get: same key", got.data?.id === id && got.data.name === "compat", got.data);

  const updated = await alice.client.apiKey.update({ keyId: id, name: "renamed" });
  check("update: no error", !updated.error, updated.error);
  check("update: new name", updated.data?.name === "renamed", updated.data);

  const keyed = createAuthClient({
    baseURL: BASE_URL,
    fetchOptions: { headers: { "x-api-key": key } },
  });
  const session = await keyed.getSession();
  check("getSession with x-api-key: the key's user", session.data?.user.email === email, session);

  const deleted = await alice.client.apiKey.delete({ keyId: id });
  check("delete: success", deleted.data?.success === true, deleted);
  const gone = await alice.client.apiKey.get({ query: { id } });
  check("get after delete: KEY_NOT_FOUND", gone.error?.code === "KEY_NOT_FOUND", gone.error);
});

let totpURI = "";
await step("twoFactor.enable + verifyTotp", async () => {
  const { data, error } = await alice.client.twoFactor.enable({ password });
  check("no error", !error, error);
  check("method is totp", field(data, "method") === "totp", data);
  check("totpURI is an otpauth URI", data?.totpURI?.startsWith("otpauth://totp/"), data);
  check("backupCodes", Array.isArray(data?.backupCodes) && data.backupCodes.length > 0, data);
  totpURI = data?.totpURI ?? "";
  const before = await alice.client.getSession({ query: { disableCookieCache: true } });
  check("twoFactorEnabled is false before verifying", field(before.data?.user, "twoFactorEnabled") === false, before.data?.user);
  const verify = await alice.client.twoFactor.verifyTotp({ code: totp(totpURI, Date.now() / 1000) });
  check("verifyTotp: no error", !verify.error, verify.error);
  const after = await alice.client.getSession({ query: { disableCookieCache: true } });
  check("twoFactorEnabled is true", field(after.data?.user, "twoFactorEnabled") === true, after.data?.user);
});

await step("signIn.email with two-factor on", async () => {
  await alice.client.signOut();
  let redirect: unknown;
  const hooked = createAuthClient({
    baseURL: BASE_URL,
    plugins: [twoFactorClient({ onTwoFactorRedirect: (ctx) => void (redirect = ctx) })],
    fetchOptions: { customFetchImpl: cookieJarFetch().fetchImpl },
  });
  const first = await hooked.signIn.email({ email, password });
  check("no error", !first.error, first.error);
  check("twoFactorRedirect is true", field(first.data, "twoFactorRedirect") === true, first.data);
  const methods = '["totp","otp"]';
  check("twoFactorMethods is totp and otp", JSON.stringify(field(first.data, "twoFactorMethods")) === methods, first.data);
  check("onTwoFactorRedirect fired with the methods", JSON.stringify(field(redirect, "twoFactorMethods")) === methods, redirect);

  const challenged = await alice.client.signIn.email({ email, password });
  check("twoFactorRedirect on the main client", field(challenged.data, "twoFactorRedirect") === true, challenged);
  const pending = await alice.client.getSession();
  check("no session before the code", pending.data === null, pending);

  const current = totp(totpURI, Date.now() / 1000);
  const wrong = await alice.client.twoFactor.verifyTotp({ code: current === "000000" ? "111111" : "000000" });
  check("a wrong code: status 401", wrong.error?.status === 401, wrong.error);
  check("a wrong code: error.code INVALID_CODE", wrong.error?.code === "INVALID_CODE", wrong.error);

  // The code that enabled two-factor can't be replayed, so wait for the next time step.
  const period = Number(new URL(totpURI).searchParams.get("period") ?? 30) * 1000;
  await sleep(period - (Date.now() % period) + 500);
  const verify = await alice.client.twoFactor.verifyTotp({ code: totp(totpURI, Date.now() / 1000) });
  check("verifyTotp: no error", !verify.error, verify.error);
  check("verifyTotp: returns a token", typeof verify.data?.token === "string", verify.data);
  check("verifyTotp: returns the user", verify.data?.user.email === email, verify.data);
  const session = await alice.client.getSession();
  check("signed in after the code", session.data?.user.email === email, session);
});

console.log(`\n${passes} passed, ${failures} failed`);
process.exit(failures === 0 ? 0 : 1);
