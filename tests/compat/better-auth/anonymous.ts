import { createAuthClient } from "better-auth/client";
import { anonymousClient } from "better-auth/client/plugins";

// Better Auth's anonymousClient against the username plugin's username_server example.
// run-username.sh builds and starts the server, then runs this.

const BASE_URL = process.env.FASTAUTH_URL ?? "http://localhost:3000";
const ORIGIN = new URL(BASE_URL).origin;

/** A browser tab: keeps cookies and sends Origin. */
function newBrowser() {
  const jar = new Map<string, string>();
  const setCookies: string[] = [];
  const browserFetch = async (input: string | URL | Request, init?: RequestInit) => {
    const request = new Request(input, init);
    request.headers.set("origin", ORIGIN);
    if (jar.size > 0) {
      request.headers.set("cookie", [...jar].map(([name, value]) => `${name}=${value}`).join("; "));
    }
    const response = await fetch(request);
    for (const header of response.headers.getSetCookie()) {
      setCookies.push(header);
      const [pair, ...attributes] = header.split(";").map((part) => part.trim());
      const eq = pair.indexOf("=");
      const name = pair.slice(0, eq);
      const value = pair.slice(eq + 1);
      if (attributes.some((a) => a.toLowerCase() === "max-age=0") || value === "") jar.delete(name);
      else jar.set(name, value);
    }
    return response;
  };
  const client = createAuthClient({
    baseURL: BASE_URL,
    plugins: [anonymousClient()],
    fetchOptions: { customFetchImpl: browserFetch },
  });
  return { client, jar, setCookies };
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

type ApiError = { status: number; code?: string; message?: string } | null;

const observed = new Map<string, string | undefined>();

function checkError(error: ApiError, status: number, code: string, message?: string) {
  if (error?.code) observed.set(error.code, error.message);
  check(`${status} ${code}`, error?.status === status && error?.code === code, error);
  if (message !== undefined) check(`message "${message}"`, error?.message === message, error);
}

const run = Date.now().toString(36);
const password = "correct horse battery";


console.log(`better-auth anonymousClient against ${BASE_URL}\n`);

/** A copy of a browser's cookie header, to replay an old session later. */
function cookieHeader(jar: Map<string, string>) {
  return [...jar].map(([name, value]) => `${name}=${value}`).join("; ");
}

async function sessionFor(cookie: string) {
  const response = await fetch(`${BASE_URL}/api/auth/get-session`, { headers: { cookie, origin: ORIGIN } });
  return response.json();
}

const guest = newBrowser();
let anonymousId = "";
let anonymousCookie = "";

await step("signIn.anonymous", async () => {
  const { data, error } = await guest.client.signIn.anonymous();
  check("no error", !error, error);
  check("token", typeof data?.token === "string" && data.token.length > 0, data);
  check("isAnonymous", data?.user.isAnonymous === true, data?.user);
  check("placeholder email", data?.user.email.endsWith("@anonymous.placeholder.invalid"), data?.user.email);
  check("name Anonymous", data?.user.name === "Anonymous", data?.user);
  anonymousId = data?.user.id ?? "";
  const session = await guest.client.getSession();
  check("getSession is the anonymous user", session.data?.user.id === anonymousId, session.data);
  check("getSession isAnonymous", (session.data?.user as { isAnonymous?: boolean }).isAnonymous === true);
  anonymousCookie = cookieHeader(guest.jar);
  check("a replayed cookie finds the session", (await sessionFor(anonymousCookie))?.user?.id === anonymousId);
});

await step("signIn.anonymous twice", async () => {
  const { error } = await guest.client.signIn.anonymous();
  checkError(
    error,
    400,
    "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY",
    "Anonymous users cannot sign in again anonymously",
  );
});

await step("signUp.email links the anonymous user and deletes it", async () => {
  const email = `anon-ada-${run}@example.com`;
  const { data, error } = await guest.client.signUp.email({ email, password, name: "Ada" });
  check("no error", !error, error);
  check("a new, real user", data?.user.id !== anonymousId && data?.user.isAnonymous === false, data?.user);
  const session = await guest.client.getSession();
  check("signed in as the new user", session.data?.user.email === email, session.data);
  check("old anonymous session is gone", (await sessionFor(anonymousCookie)) === null);
});

await step("signIn.email from an anonymous session links too", async () => {
  const tab = newBrowser();
  const anon = await tab.client.signIn.anonymous();
  check("anonymous first", anon.data?.user.isAnonymous === true, anon);
  const before = cookieHeader(tab.jar);
  check("a replayed cookie finds the session", (await sessionFor(before))?.user?.isAnonymous === true);
  const { error } = await tab.client.signIn.email({ email: `anon-ada-${run}@example.com`, password });
  check("no error", !error, error);
  const session = await tab.client.getSession();
  check("signed in as Ada", session.data?.user.email === `anon-ada-${run}@example.com`, session.data);
  check("the anonymous session is gone", (await sessionFor(before)) === null);
});

await step("signUp.email can't set isAnonymous", async () => {
  const { error } = await newBrowser().client.signUp.email({
    email: `sneaky-${run}@example.com`,
    password,
    name: "Sneaky",
    isAnonymous: true,
  } as never);
  check("refused with 400", error?.status === 400, error);
});

await step("deleteAnonymousUser", async () => {
  const tab = newBrowser();
  await tab.client.signIn.anonymous();
  const { data, error } = await tab.client.deleteAnonymousUser();
  check("no error", !error, error);
  check("success", data?.success === true, data);
  check("session cookie cleared", !tab.jar.has("fastauth.session_token"), [...tab.jar.keys()]);
  check("signed out", (await tab.client.getSession()).data === null);
  const again = await tab.client.deleteAnonymousUser();
  check("401 without a session", again.error?.status === 401, again.error);
  const real = await guest.client.deleteAnonymousUser();
  checkError(real.error, 403, "USER_IS_NOT_ANONYMOUS", "User is not anonymous");
  check("the real user is still signed in", (await guest.client.getSession()).data?.user.name === "Ada");
});

await step("codes and messages match the client's ANONYMOUS_ERROR_CODES", async () => {
  const codes = (anonymousClient() as unknown as { $ERROR_CODES: Record<string, { message: string }> })
    .$ERROR_CODES;
  check("observed codes", observed.size > 0, [...observed.keys()]);
  for (const [code, message] of observed) {
    check(`${code}: "${message}"`, codes[code]?.message === message, codes[code]);
  }
});

console.log(`${passes} passed, ${failures} failed`);
process.exit(failures > 0 ? 1 : 0);
