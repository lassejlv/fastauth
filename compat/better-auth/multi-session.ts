import { createAuthClient } from "better-auth/client";
import { multiSessionClient } from "better-auth/client/plugins";

// Better Auth's multiSessionClient against the multi-session plugin's multi_session_server example.
// run-multi-session.sh builds and starts the server, then runs this.

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
    plugins: [multiSessionClient()],
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


console.log(`better-auth multiSessionClient against ${BASE_URL}\n`);

const browser = newBrowser();
const email = (who: string) => `ms-${who}-${run}@example.com`;
const tokens: Record<string, string> = {};

async function active() {
  return (await browser.client.getSession()).data?.user.email;
}

async function listed() {
  const { data, error } = await browser.client.multiSession.listDeviceSessions();
  if (error) throw new Error(JSON.stringify(error));
  return data.map((entry) => entry.user.email).sort();
}

function deviceCookies(jar: Map<string, string>) {
  return [...jar.keys()].filter((name) => name.includes("_multi-"));
}

await step("three accounts sign up in one browser", async () => {
  for (const who of ["ada", "bob", "cy"]) {
    const { data, error } = await browser.client.signUp.email({ email: email(who), password, name: who });
    check(`${who} signed up`, !error && data?.token, error);
    tokens[who] = data?.token ?? "";
  }
  check("the last one is active", (await active()) === email("cy"));
  check("three device cookies", deviceCookies(browser.jar).length === 3, deviceCookies(browser.jar));
  const name = `fastauth.session_token_multi-${tokens.ada.toLowerCase()}`;
  const header = browser.setCookies.find((c) => c.startsWith(`${name}=`)) ?? "";
  check("device cookie name has the lowercased token", header !== "", browser.setCookies);
  check("device cookie is HttpOnly with the session Max-Age", /HttpOnly/.test(header) && /Max-Age=604800/.test(header), header);
});

await step("listDeviceSessions", async () => {
  const { data, error } = await browser.client.multiSession.listDeviceSessions();
  check("no error", !error, error);
  check("three entries", data?.length === 3, data);
  check(
    "each has session.token and its user",
    data?.every((entry) => tokens[entry.user.name] === entry.session.token && entry.session.userId === entry.user.id),
    data,
  );
  const stranger = await newBrowser().client.multiSession.listDeviceSessions();
  check("a fresh browser has none", Array.isArray(stranger.data) && stranger.data.length === 0, stranger);
});

await step("setActive", async () => {
  const { data, error } = await browser.client.multiSession.setActive({ sessionToken: tokens.ada });
  check("no error", !error, error);
  check("answers the session and user", data?.user.email === email("ada") && data?.session.token === tokens.ada, data);
  check("ada is active", (await active()) === email("ada"));
  const bad = await browser.client.multiSession.setActive({ sessionToken: "not-a-token" });
  checkError(bad.error, 401, "INVALID_SESSION_TOKEN", "Invalid session token");
  const other = await newBrowser().client.multiSession.setActive({ sessionToken: tokens.bob });
  checkError(other.error, 401, "INVALID_SESSION_TOKEN");
  check("still ada", (await active()) === email("ada"));
});

await step("revoke a background account", async () => {
  const { data, error } = await browser.client.multiSession.revoke({ sessionToken: tokens.bob });
  check("no error", !error, error);
  check("status true", data?.status === true, data);
  check("bob is gone", JSON.stringify(await listed()) === JSON.stringify([email("ada"), email("cy")]));
  check("ada still active", (await active()) === email("ada"));
  const again = await browser.client.multiSession.setActive({ sessionToken: tokens.bob });
  checkError(again.error, 401, "INVALID_SESSION_TOKEN");
});

await step("revoke the active account switches to the next", async () => {
  const { error } = await browser.client.multiSession.revoke({ sessionToken: tokens.ada });
  check("no error", !error, error);
  check("cy is active", (await active()) === email("cy"));
  check("only cy left", JSON.stringify(await listed()) === JSON.stringify([email("cy")]));
});

await step("signing in again replaces that account's older session", async () => {
  const { data } = await browser.client.signIn.email({ email: email("cy"), password });
  check("signed in", data?.token && data.token !== tokens.cy, data);
  check("one device cookie", deviceCookies(browser.jar).length === 1, deviceCookies(browser.jar));
  const list = await browser.client.multiSession.listDeviceSessions();
  check("listed with the new token", list.data?.[0]?.session.token === data?.token, list.data);
  const old = await browser.client.multiSession.setActive({ sessionToken: tokens.cy });
  checkError(old.error, 401, "INVALID_SESSION_TOKEN");
  tokens.cy = data?.token ?? "";
});

await step("maximumSessions (5) caps the remembered accounts", async () => {
  const tab = newBrowser();
  for (const n of [1, 2, 3, 4, 5, 6]) {
    await tab.client.signUp.email({ email: email(`max${n}`), password, name: `max${n}` });
  }
  check("the sixth is active", (await tab.client.getSession()).data?.user.email === email("max6"));
  const list = await tab.client.multiSession.listDeviceSessions();
  check("five are remembered", list.data?.length === 5, list.data?.map((e) => e.user.email));
  check("five device cookies", deviceCookies(tab.jar).length === 5, deviceCookies(tab.jar));
});

await step("signOut signs every account out", async () => {
  await browser.client.signUp.email({ email: email("dee"), password, name: "dee" });
  check("two accounts", (await listed()).length === 2);
  const { data, error } = await browser.client.signOut();
  check("no error", !error && data?.success === true, error ?? data);
  check("no device cookies", deviceCookies(browser.jar).length === 0, [...browser.jar.keys()]);
  check("signed out", (await active()) === undefined);
  const list = await browser.client.multiSession.listDeviceSessions();
  check("nothing listed", list.data?.length === 0, list.data);
});

await step("codes and messages match the client's MULTI_SESSION_ERROR_CODES", async () => {
  const codes = (multiSessionClient() as unknown as { $ERROR_CODES: Record<string, { message: string }> })
    .$ERROR_CODES;
  check("observed codes", observed.size > 0, [...observed.keys()]);
  for (const [code, message] of observed) {
    check(`${code}: "${message}"`, codes[code]?.message === message, codes[code]);
  }
});

console.log(`${passes} passed, ${failures} failed`);
process.exit(failures > 0 ? 1 : 0);
