import { createAuthClient } from "better-auth/client";
import { usernameClient } from "better-auth/client/plugins";

// Better Auth's usernameClient against the username plugin's username_server example.
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
    plugins: [usernameClient()],
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

const ada = newBrowser();
const name = `Ada_${run}`;
const lower = name.toLowerCase();
console.log(`better-auth usernameClient against ${BASE_URL} (${name})\n`);

await step("signUp.email with a username", async () => {
  const { data, error } = await ada.client.signUp.email({
    email: `ada-${run}@example.com`,
    password,
    name: "Ada",
    username: name,
  });
  check("no error", !error, error);
  check("username is normalized", data?.user.username === lower, data?.user);
  check("displayUsername keeps the case", data?.user.displayUsername === name, data?.user);
  const session = await ada.client.getSession();
  check("getSession has the username", session.data?.user.username === lower, session.data);
});

await step("signUp.email refuses taken and bad usernames", async () => {
  const other = newBrowser();
  const taken = await other.client.signUp.email({
    email: `taken-${run}@example.com`,
    password,
    name: "Taken",
    username: name.toUpperCase(),
  });
  checkError(taken.error, 400, "USERNAME_IS_ALREADY_TAKEN", "Username is already taken. Please try another.");
  const short = await other.client.signUp.email({
    email: `short-${run}@example.com`,
    password,
    name: "Short",
    username: "ab",
  });
  checkError(short.error, 400, "USERNAME_TOO_SHORT", "Username is too short");
  const bad = await other.client.signUp.email({
    email: `bad-${run}@example.com`,
    password,
    name: "Bad",
    username: "no spaces",
  });
  checkError(bad.error, 400, "INVALID_USERNAME", "Username is invalid");
  check("no session after a refused sign-up", (await other.client.getSession()).data === null);
});

await step("signUp.email with only displayUsername", async () => {
  const grace = newBrowser();
  const { data, error } = await grace.client.signUp.email({
    email: `grace-${run}@example.com`,
    password,
    name: "Grace",
    displayUsername: `Grace_${run}`,
  });
  check("no error", !error, error);
  check("username comes from displayUsername", data?.user.username === `grace_${run}`.toLowerCase(), data?.user);
  check("displayUsername kept", data?.user.displayUsername === `Grace_${run}`, data?.user);
});

await step("signIn.username", async () => {
  const tab = newBrowser();
  const { data, error } = await tab.client.signIn.username({ username: name.toUpperCase(), password });
  check("no error", !error, error);
  check("token", typeof data?.token === "string" && data.token.length > 0, data);
  check("user", data?.user.username === lower && data?.user.email === `ada-${run}@example.com`, data?.user);
  check("redirect false", data?.redirect === false, data);
  check("session cookie set", tab.jar.has("fastauth.session_token"), [...tab.jar.keys()]);
  const session = await tab.client.getSession();
  check("getSession is Ada", session.data?.user.username === lower, session.data);
});

await step("signIn.username failures", async () => {
  const tab = newBrowser();
  const wrong = await tab.client.signIn.username({ username: name, password: "wrong password" });
  checkError(wrong.error, 401, "INVALID_USERNAME_OR_PASSWORD", "Invalid username or password");
  const unknown = await tab.client.signIn.username({ username: `nobody_${run}`, password });
  checkError(unknown.error, 401, "INVALID_USERNAME_OR_PASSWORD");
  const invalid = await tab.client.signIn.username({ username: "no spaces", password });
  checkError(invalid.error, 422, "INVALID_USERNAME", "Username is invalid");
  const short = await tab.client.signIn.username({ username: "ab", password });
  checkError(short.error, 422, "USERNAME_TOO_SHORT");
  check("still signed out", (await tab.client.getSession()).data === null);
});

await step("isUsernameAvailable", async () => {
  const tab = newBrowser();
  const taken = await tab.client.isUsernameAvailable({ username: name.toUpperCase() });
  check("taken", taken.data?.available === false, taken);
  const free = await tab.client.isUsernameAvailable({ username: `free_${run}` });
  check("free", free.data?.available === true, free);
  const short = await tab.client.isUsernameAvailable({ username: "ab" });
  checkError(short.error, 422, "USERNAME_TOO_SHORT");
  const long = await tab.client.isUsernameAvailable({ username: "a".repeat(31) });
  checkError(long.error, 422, "USERNAME_TOO_LONG", "Username is too long");
});

await step("updateUser changes the username", async () => {
  const next = `Countess_${run}`;
  const { data, error } = await ada.client.updateUser({ username: next });
  check("no error", !error, error);
  check("status true", data?.status === true, data);
  const session = await ada.client.getSession();
  check("username normalized", session.data?.user.username === next.toLowerCase(), session.data?.user);
  check("displayUsername unchanged", session.data?.user.displayUsername === name, session.data?.user);
  const taken = await ada.client.updateUser({ username: `Grace_${run}` });
  checkError(taken.error, 400, "USERNAME_IS_ALREADY_TAKEN");
  const bad = await ada.client.updateUser({ username: "no spaces" });
  checkError(bad.error, 400, "INVALID_USERNAME");
  const display = await ada.client.updateUser({ displayUsername: "The Countess" });
  check("displayUsername updated", !display.error && (await ada.client.getSession()).data?.user.displayUsername === "The Countess");
  const old = await newBrowser().client.signIn.username({ username: name, password });
  checkError(old.error, 401, "INVALID_USERNAME_OR_PASSWORD");
  const fresh = await newBrowser().client.signIn.username({ username: next, password });
  check("signs in with the new username", !fresh.error && fresh.data?.user.username === next.toLowerCase(), fresh);
});

await step("codes and messages match the client's USERNAME_ERROR_CODES", async () => {
  const codes = (usernameClient() as unknown as { $ERROR_CODES: Record<string, { message: string }> })
    .$ERROR_CODES;
  check("observed several codes", observed.size >= 5, [...observed.keys()]);
  for (const [code, message] of observed) {
    check(`${code}: "${message}"`, codes[code]?.message === message, codes[code]);
  }
});

console.log(`${passes} passed, ${failures} failed`);
process.exit(failures > 0 ? 1 : 0);
