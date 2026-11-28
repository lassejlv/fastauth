import { createAuthClient } from "better-auth/client";

// Better Auth's client with bearer auth against the bearer plugin's compat_server example.
// Better Auth ships no bearer client plugin: its docs read `set-auth-token` in onSuccess and
// send it back through `fetchOptions.auth`. run-bearer.sh builds and starts the server.

const BASE_URL = process.env.FASTAUTH_URL ?? "http://localhost:3000";

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

/** A client that sends `Authorization: Bearer <token()>` and no cookies. */
function bearerClient(token: () => string) {
  return createAuthClient({
    baseURL: BASE_URL,
    fetchOptions: { auth: { type: "Bearer", token } },
  });
}

const run = Date.now().toString(36);
const email = `bearer-${run}@example.com`;
const password = "correct horse battery";
const plain = createAuthClient({ baseURL: BASE_URL });
let signed = "";
let raw = "";
let userId = "";
let second = "";

console.log(`better-auth client with bearer auth against ${BASE_URL} (${email})\n`);

await step("signUp.email sets set-auth-token", async () => {
  let exposed = "";
  const { data, error } = await plain.signUp.email(
    { email, password, name: "Bearer" },
    {
      onSuccess(ctx) {
        signed = ctx.response.headers.get("set-auth-token") ?? "";
        exposed = ctx.response.headers.get("access-control-expose-headers") ?? "";
      },
    },
  );
  check("no error", !error, error);
  raw = data?.token ?? "";
  userId = data?.user.id ?? "";
  check("returns a token", raw.length > 0);
  check("set-auth-token header", signed.length > 0);
  check("the header is the signed token", signed.startsWith(`${raw}.`), { signed, raw });
  check("Access-Control-Expose-Headers lists it", exposed.split(",").map((h) => h.trim()).includes("set-auth-token"), exposed);
});

await step("getSession with the signed token", async () => {
  const { data, error } = await bearerClient(() => signed).getSession();
  check("no error", !error, error);
  check("user matches", data?.user.email === email, data);
  check("session.userId matches", data?.session.userId === userId);
});

await step("getSession with the raw token", async () => {
  const { data } = await bearerClient(() => raw).getSession();
  check("user matches", data?.user.email === email, data);
});

await step("getSession with a bad signature", async () => {
  const { data, error } = await bearerClient(() => `${raw}.AAAA`).getSession();
  check("no error", !error, error);
  check("no session", data === null, data);
});

await step("getSession without a token", async () => {
  const { data } = await plain.getSession();
  check("no session", data === null, data);
});

await step("signIn.email sets set-auth-token", async () => {
  const { data, error } = await plain.signIn.email(
    { email, password },
    {
      onSuccess(ctx) {
        second = ctx.response.headers.get("set-auth-token") ?? "";
      },
    },
  );
  check("no error", !error, error);
  check("set-auth-token header", second.startsWith(`${data?.token}.`), { second, token: data?.token });
  check("a different session", second !== signed);
});

await step("listSessions with a bearer token", async () => {
  const { data, error } = await bearerClient(() => second).listSessions();
  check("no error", !error, error);
  check("two sessions", data?.length === 2, data);
});

await step("updateUser with a bearer token", async () => {
  const client = bearerClient(() => second);
  const { data, error } = await client.updateUser({ name: "Renamed" });
  check("no error", !error, error);
  check("status true", data?.status === true, data);
  const session = await client.getSession();
  check("getSession shows the new name", session.data?.user.name === "Renamed", session.data);
});

await step("signOut with a bearer token", async () => {
  let header: string | null = "unset";
  const { data, error } = await bearerClient(() => signed).signOut({
    fetchOptions: {
      onSuccess(ctx) {
        header = ctx.response.headers.get("set-auth-token");
      },
    },
  });
  check("no error", !error, error);
  check("success", data?.success === true, data);
  check("no set-auth-token on sign-out", header === null, header);
  const gone = await bearerClient(() => signed).getSession();
  check("the token no longer works", gone.data === null, gone.data);
  const other = await bearerClient(() => second).getSession();
  check("the other session still works", other.data?.user.email === email);
});

console.log(`${passes} passed, ${failures} failed`);
process.exit(failures > 0 ? 1 : 0);
