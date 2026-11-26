import { readFileSync } from "node:fs";
import { chromium, type CDPSession, type Page } from "playwright-core";

// Better Auth's passkeyClient in headless Chrome, against the passkey plugin's compat_server
// example. The page is served on the server's own origin (Playwright fulfils `/` and the
// client bundle), so WebAuthn runs for rpID localhost, and Chrome's virtual authenticator
// (CDP WebAuthn.addVirtualAuthenticator) answers navigator.credentials. run-passkey.sh builds
// the bundle and starts the server.

const BASE_URL = process.env.FASTAUTH_URL ?? "http://localhost:3000";
const BUNDLE = process.env.PASSKEY_BUNDLE ?? "passkey-client.js";
const CHROME = process.env.CHROME_PATH;

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

type Result = { data: any; error: any };

const browser = await chromium.launch({ executablePath: CHROME, headless: true });
const context = await browser.newContext();
const page: Page = await context.newPage();
await page.route(`${BASE_URL}/`, (route) =>
  route.fulfill({
    contentType: "text/html",
    body: '<!doctype html><title>passkey compat</title><script src="/passkey-client.js"></script>',
  }),
);
await page.route(`${BASE_URL}/passkey-client.js`, (route) =>
  route.fulfill({ contentType: "text/javascript", body: readFileSync(BUNDLE) }),
);
await page.goto(`${BASE_URL}/`);
await page.waitForFunction(() => "client" in window);

const cdp: CDPSession = await context.newCDPSession(page);
await cdp.send("WebAuthn.enable");
const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
  options: {
    protocol: "ctap2",
    transport: "internal",
    hasResidentKey: true,
    hasUserVerification: true,
    isUserVerified: true,
    automaticPresenceSimulation: true,
  },
});
const credentials = async () =>
  (await cdp.send("WebAuthn.getCredentials", { authenticatorId })).credentials;

const run = Date.now().toString(36);
const email = `passkey-${run}@example.com`;
let userId = "";
let passkeyId = "";
let credentialID = "";
let firstCredential: Awaited<ReturnType<typeof credentials>>[number] | undefined;
let restoredAuthenticatorId = "";

console.log(`better-auth passkeyClient in ${await browser.version()} against ${BASE_URL} (${email})\n`);

await step("signUp.email", async () => {
  const { data, error } = await page.evaluate(
    (email) => window.client.signUp.email({ email, password: "correct horse battery", name: "Passkey" }),
    email,
  );
  check("no error", !error, error);
  userId = data?.user.id ?? "";
  check("returns the user", userId.length > 0, data);
});

await step("passkey.addPasskey", async () => {
  const { data, error }: Result = await page.evaluate(() =>
    window.client.passkey.addPasskey({ name: "Laptop" }),
  );
  check("no error", !error, error);
  passkeyId = data?.id ?? "";
  credentialID = data?.credentialID ?? "";
  check("returns the passkey id", passkeyId.length > 0, data);
  check("name is Laptop", data?.name === "Laptop", data);
  check("userId is the user", data?.userId === userId, data);
  check("deviceType is singleDevice", data?.deviceType === "singleDevice", data);
  check("backedUp is false", data?.backedUp === false, data);
  check("transports is internal", data?.transports === "internal", data);
  check("publicKey is set", typeof data?.publicKey === "string" && data.publicKey.length > 40, data);
  check("aaguid is a UUID", /^[0-9a-f-]{36}$/.test(data?.aaguid ?? ""), data);
  check("no session without createSession", data?.session === undefined, data);
  const stored = await credentials();
  check("the authenticator holds one credential", stored.length === 1, stored);
  check("for rpId localhost", stored[0]?.rpId === "localhost", stored[0]);
  check("discoverable (resident key preferred)", stored[0]?.isResidentCredential === true, stored[0]);
  check(
    "credentialID is the authenticator's",
    Buffer.from(stored[0]?.credentialId ?? "", "base64").toString("base64url") === credentialID,
    { stored: stored[0]?.credentialId, credentialID },
  );
});

await step("passkey.addPasskey with the same authenticator", async () => {
  const { data, error }: Result = await page.evaluate(() =>
    window.client.passkey.addPasskey({ name: "Again" }),
  );
  check("no data", !data, data);
  check(
    "error.code ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED (excludeCredentials)",
    error?.code === "ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED",
    error,
  );
  check("still one credential", (await credentials()).length === 1);
});

await step("passkey.listUserPasskeys", async () => {
  const { data, error }: Result = await page.evaluate(() => window.client.passkey.listUserPasskeys());
  check("no error", !error, error);
  check("one passkey", Array.isArray(data) && data.length === 1, data);
  check("it is the new one", data?.[0]?.id === passkeyId, data);
  check("credentialID matches", data?.[0]?.credentialID === credentialID, data);
});

await step("signOut", async () => {
  const { error } = await page.evaluate(() => window.client.signOut());
  check("no error", !error, error);
  const session = await page.evaluate(() => window.client.getSession());
  check("getSession is null", session.data === null, session);
});

await step("signIn.passkey signed out (discoverable)", async () => {
  const { data, error }: Result = await page.evaluate(() => window.client.signIn.passkey());
  check("no error", !error, error);
  check("returns the user", data?.user?.id === userId, data);
  check("returns the session", data?.session?.userId === userId, data);
  check("session has a token", typeof data?.session?.token === "string", data);
  const session = await page.evaluate(() => window.client.getSession());
  check("getSession is the user", session.data?.user?.email === email, session);
});

await step("signIn.passkey signed in (allowCredentials)", async () => {
  const { data, error }: Result = await page.evaluate(() => window.client.signIn.passkey());
  check("no error", !error, error);
  check("returns the user", data?.user?.id === userId, data);
});

await step("signature counter", async () => {
  const [stored] = await credentials();
  const { data }: Result = await page.evaluate(() => window.client.passkey.listUserPasskeys());
  check("the authenticator counted two sign-ins", stored?.signCount >= 2, stored);
  check("the stored counter is the authenticator's", data?.[0]?.counter === stored?.signCount, {
    stored: data?.[0]?.counter,
    authenticator: stored?.signCount,
  });
});

await step("passkey.updatePasskey", async () => {
  const { data, error }: Result = await page.evaluate(
    (id) => window.client.passkey.updatePasskey({ id, name: "Work laptop" }),
    passkeyId,
  );
  check("no error", !error, error);
  check("returns the renamed passkey", data?.passkey?.name === "Work laptop", data);
  const empty: Result = await page.evaluate(
    (id) => window.client.passkey.updatePasskey({ id, name: "" }),
    passkeyId,
  );
  check("an empty name: status 400", empty.error?.status === 400, empty.error);
  const missing: Result = await page.evaluate(() =>
    window.client.passkey.updatePasskey({ id: "missing", name: "x" }),
  );
  check("an unknown id: status 404", missing.error?.status === 404, missing.error);
  check("an unknown id: error.code PASSKEY_NOT_FOUND", missing.error?.code === "PASSKEY_NOT_FOUND", missing.error);
});

await step("passkey.addPasskey with createSession on a second authenticator", async () => {
  const second = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "usb",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  [firstCredential] = await credentials();
  await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId });
  const { data, error }: Result = await page.evaluate(() =>
    window.client.passkey.addPasskey({ name: "Key", createSession: true }),
  );
  check("no error", !error, error);
  check("returns the session", typeof data?.session?.token === "string", data);
  check("returns the user", data?.user?.id === userId, data);
  check("transports is usb", data?.transports === "usb", data);
  const { data: list }: Result = await page.evaluate(() => window.client.passkey.listUserPasskeys());
  check("two passkeys", list?.length === 2, list);
  const deleted: Result = await page.evaluate(
    (id) => window.client.passkey.deletePasskey({ id }),
    data?.id ?? "",
  );
  check("deletePasskey: status true", deleted.data?.status === true, deleted);
  await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId: second.authenticatorId });
});

await step("passkey.deletePasskey", async () => {
  const { data, error }: Result = await page.evaluate(
    (id) => window.client.passkey.deletePasskey({ id }),
    passkeyId,
  );
  check("no error", !error, error);
  check("status true", data?.status === true, data);
  const list: Result = await page.evaluate(() => window.client.passkey.listUserPasskeys());
  check("no passkeys left", Array.isArray(list.data) && list.data.length === 0, list);
});

await step("signIn.passkey with a deleted passkey", async () => {
  const restored = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  restoredAuthenticatorId = restored.authenticatorId;
  if (!firstCredential) throw new Error("no saved credential");
  await cdp.send("WebAuthn.addCredential", {
    authenticatorId: restored.authenticatorId,
    credential: firstCredential,
  });
  await page.evaluate(() => window.client.signOut());
  const { data, error }: Result = await page.evaluate(() => window.client.signIn.passkey());
  check("no data", !data, data);
  check("status 401", error?.status === 401, error);
  check("error.code PASSKEY_NOT_FOUND", error?.code === "PASSKEY_NOT_FOUND", error);
  const session = await page.evaluate(() => window.client.getSession());
  check("still signed out", session.data === null, session);
});

// Passkey-first sign-up: compat_server's Passkey::sign_up takes the new user's email from
// addPasskey's context.
const firstEmail = `passkey-first-${run}@example.com`;

await step("passkey.addPasskey signed out with a context (passkey-first sign-up)", async () => {
  if (restoredAuthenticatorId) {
    await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId: restoredAuthenticatorId });
  }
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  const before = await page.evaluate(() => window.client.getSession());
  check("signed out first", before.data === null, before);
  const { data, error }: Result = await page.evaluate(
    (context) => window.client.passkey.addPasskey({ name: "First", context, createSession: true }),
    firstEmail,
  );
  check("no error", !error, error);
  check("returns the passkey", data?.name === "First" && typeof data?.credentialID === "string", data);
  check("creates the user", data?.user?.email === firstEmail, data);
  check("the user's email is unverified", data?.user?.emailVerified === false, data);
  check("the passkey is the new user's", data?.userId === data?.user?.id, data);
  check("returns the session", typeof data?.session?.token === "string", data);
  const session = await page.evaluate(() => window.client.getSession());
  check("getSession is the new user", session.data?.user?.email === firstEmail, session);
  await page.evaluate(() => window.client.signOut());
  const signedIn: Result = await page.evaluate(() => window.client.signIn.passkey());
  check("signIn.passkey signs the new user in", signedIn.data?.user?.email === firstEmail, signedIn);
  await page.evaluate(() => window.client.signOut());
});

await step("passkey.addPasskey signed out for a taken email", async () => {
  const { data, error }: Result = await page.evaluate(
    (context) => window.client.passkey.addPasskey({ name: "Taken", context }),
    email,
  );
  check("no data", !data, data);
  check("status 422", error?.status === 422, error);
  check(
    "error.code USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL",
    error?.code === "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL",
    error,
  );
});

await step("passkey.addPasskey signed out without a context", async () => {
  const { data, error }: Result = await page.evaluate(() => window.client.passkey.addPasskey({ name: "None" }));
  check("no data", !data, data);
  check("status 400 from the resolver", error?.status === 400, error);
  check("error.code EMAIL_REQUIRED", error?.code === "EMAIL_REQUIRED", error);
});

await browser.close();
console.log(`${passes} passed, ${failures} failed`);
process.exit(failures === 0 ? 0 : 1);
