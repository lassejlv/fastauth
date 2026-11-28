import { createAuthClient } from "better-auth/client";
import { magicLinkClient } from "better-auth/client/plugins";
import { readFileSync } from "node:fs";

// Better Auth's magicLinkClient against the magic link plugin's example server.
// run-magic-link.sh builds and starts the server, then runs this.

const BASE_URL = process.env.FASTAUTH_URL ?? "http://localhost:3000";
const ORIGIN = new URL(BASE_URL).origin;
const OUTBOX = process.env.FASTAUTH_OUTBOX ?? "outbox.jsonl";

type Email = { to: string; kind: string; url: string | null; code: string | null };

/** The newest email the server's outbox mailer wrote for `to`. */
function lastEmail(to: string): Email | undefined {
  let text = "";
  try {
    text = readFileSync(OUTBOX, "utf8");
  } catch {
    return undefined;
  }
  const emails = text.split("\n").filter(Boolean).map((line) => JSON.parse(line) as Email);
  return emails.filter((email) => email.to === to).at(-1);
}

/** A browser tab: keeps cookies and sends Origin (see compat.ts). */
function newBrowser() {
  const jar = new Map<string, string>();
  const browserFetch = async (input: string | URL | Request, init?: RequestInit) => {
    const request = new Request(input, init);
    request.headers.set("origin", ORIGIN);
    if (jar.size > 0) {
      request.headers.set("cookie", [...jar].map(([name, value]) => `${name}=${value}`).join("; "));
    }
    const response = await fetch(request);
    for (const header of response.headers.getSetCookie()) {
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
    plugins: [magicLinkClient()],
    fetchOptions: { customFetchImpl: browserFetch },
  });
  return { client, fetch: browserFetch, jar };
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

const run = Date.now().toString(36);
const adaEmail = `ml-ada-${run}@example.com`;
const ada = newBrowser();
let firstLink = "";

console.log(`better-auth magicLinkClient against ${BASE_URL}\n`);

/** Sends a link to `email` through `browser` and returns the emailed URL. */
async function sendLink(browser: ReturnType<typeof newBrowser>, body: Parameters<typeof ada.client.signIn.magicLink>[0]) {
  const { data, error } = await browser.client.signIn.magicLink(body);
  check("signIn.magicLink: { status: true }", !error && data?.status === true, error ?? data);
  check("the response carries no token", data && Object.keys(data).join() === "status", data);
  const email = lastEmail(body.email);
  check("a magic-link email was sent", email?.kind === "magic-link" && !!email.url, email);
  return email?.url ?? "";
}

await step("signIn.magicLink emails a link", async () => {
  firstLink = await sendLink(ada, {
    email: adaEmail,
    name: "Ada",
    callbackURL: "/dashboard",
    newUserCallbackURL: "/welcome",
    errorCallbackURL: "/error",
  });
  const url = new URL(firstLink);
  check("the link is /api/auth/magic-link/verify", url.origin === ORIGIN && url.pathname === "/api/auth/magic-link/verify", firstLink);
  check("the link has a token", (url.searchParams.get("token") ?? "").length >= 32, firstLink);
  check(
    "the link keeps the callbacks",
    url.searchParams.get("callbackURL") === "/dashboard" &&
      url.searchParams.get("newUserCallbackURL") === "/welcome" &&
      url.searchParams.get("errorCallbackURL") === "/error",
    firstLink,
  );
});

await step("the link signs a new user up", async () => {
  const response = await ada.fetch(firstLink, { redirect: "manual" });
  check("302 to newUserCallbackURL", response.status === 302 && response.headers.get("location") === `${ORIGIN}/welcome`, [
    response.status,
    response.headers.get("location"),
  ]);
  const { data } = await ada.client.getSession();
  check("getSession: the new user", data?.user.email === adaEmail && data.user.name === "Ada", data);
  check("the email is verified", data?.user.emailVerified === true, data?.user);
});

await step("a used link fails", async () => {
  const stranger = newBrowser();
  const response = await stranger.fetch(firstLink, { redirect: "manual" });
  check(
    "302 to errorCallbackURL?error=INVALID_TOKEN",
    response.status === 302 && response.headers.get("location") === `${ORIGIN}/error?error=INVALID_TOKEN`,
    response.headers.get("location"),
  );
  check("no session cookie", stranger.jar.size === 0, [...stranger.jar.keys()]);
});

await step("an existing user lands on callbackURL", async () => {
  const again = newBrowser();
  const link = await sendLink(again, { email: adaEmail, callbackURL: "/dashboard", newUserCallbackURL: "/welcome" });
  const response = await again.fetch(link, { redirect: "manual" });
  check("302 to callbackURL", response.headers.get("location") === `${ORIGIN}/dashboard`, response.headers.get("location"));
  const { data } = await again.client.getSession();
  check("signed in as the same user", data?.user.email === adaEmail, data);
});

await step("magicLink.verify without callbackURL answers JSON", async () => {
  const api = newBrowser();
  const link = await sendLink(api, { email: adaEmail });
  const token = new URL(link).searchParams.get("token") ?? "";
  const { data, error } = await api.client.magicLink.verify({ query: { token } });
  check("no error", !error, error);
  check("token, user and session", typeof data?.token === "string" && data.user?.email === adaEmail, data);
  const session = (data as { session?: { userId?: string } } | null)?.session;
  check("session.userId is the user", session?.userId === data?.user?.id, session);
  const current = await api.client.getSession();
  check("the cookie signs the tab in", current.data?.user.email === adaEmail, current.data);
});

await step("an unknown token redirects with INVALID_TOKEN", async () => {
  const response = await fetch(`${BASE_URL}/api/auth/magic-link/verify?token=nope&errorCallbackURL=%2Foops`, { redirect: "manual" });
  check(
    "302 to /oops?error=INVALID_TOKEN",
    response.headers.get("location") === `${ORIGIN}/oops?error=INVALID_TOKEN`,
    response.headers.get("location"),
  );
});

await step("untrusted callbacks are refused", async () => {
  const evil = newBrowser();
  const callback = await evil.client.signIn.magicLink({ email: adaEmail, callbackURL: "https://evil.example/" });
  check("callbackURL: 403 INVALID_CALLBACK_URL", callback.error?.status === 403 && callback.error.code === "INVALID_CALLBACK_URL", callback.error);
  const error = await evil.client.signIn.magicLink({ email: adaEmail, errorCallbackURL: "https://evil.example/" });
  check(
    "errorCallbackURL: 403 INVALID_ERROR_CALLBACK_URL",
    error.error?.status === 403 && error.error.code === "INVALID_ERROR_CALLBACK_URL",
    error.error,
  );
  const newUser = await evil.client.signIn.magicLink({ email: adaEmail, newUserCallbackURL: "https://evil.example/" });
  check(
    "newUserCallbackURL: 403 INVALID_NEW_USER_CALLBACK_URL",
    newUser.error?.status === 403 && newUser.error.code === "INVALID_NEW_USER_CALLBACK_URL",
    newUser.error,
  );
});

await step("an invalid email is refused", async () => {
  const { error } = await newBrowser().client.signIn.magicLink({ email: "not-an-email" });
  check("400", error?.status === 400, error);
});

console.log(`\n${passes} passed, ${failures} failed`);
process.exit(failures === 0 ? 0 : 1);
