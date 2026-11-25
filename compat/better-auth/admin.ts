// Better Auth's adminClient against the admin plugin's example server
// (crates/fastauth-plugin-admin/examples/admin_server.rs). Run it with run-admin.sh.
import { createAuthClient } from "better-auth/client";
import { adminClient } from "better-auth/client/plugins";

const BASE_URL = process.env.FASTAUTH_URL ?? "http://localhost:3000";
const ORIGIN = new URL(BASE_URL).origin;

function newClient() {
  const jar = new Map<string, string>();
  const customFetchImpl = async (input: string | URL | Request, init?: RequestInit) => {
    const request = new Request(input, init);
    request.headers.set("origin", ORIGIN);
    if (jar.size > 0) {
      request.headers.set("cookie", [...jar].map(([k, v]) => `${k}=${v}`).join("; "));
    }
    const response = await fetch(request);
    for (const header of response.headers.getSetCookie()) {
      const [pair, ...attributes] = header.split(";").map((part) => part.trim());
      const eq = pair.indexOf("=");
      const name = pair.slice(0, eq);
      const value = pair.slice(eq + 1);
      if (value === "" || attributes.some((a) => a.toLowerCase() === "max-age=0")) jar.delete(name);
      else jar.set(name, value);
    }
    return response;
  };
  const client = createAuthClient({
    baseURL: BASE_URL,
    plugins: [adminClient()],
    fetchOptions: { customFetchImpl },
  });
  return { client, jar, fetch: customFetchImpl };
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

const field = (value: unknown, key: string) => (value as Record<string, unknown> | null | undefined)?.[key];
const suffix = Date.now().toString(36);
const userEmail = `member-${suffix}@example.com`;
const password = "correct horse battery";
const admin = newClient();
const member = newClient();
let userId = "";
let adminSessionId = "";

console.log(`better-auth adminClient against ${BASE_URL}\n`);

await step("an admin signs in", async () => {
  const { data, error } = await admin.client.signIn.email({ email: "admin@acme.dk", password });
  check("no error", !error, error);
  check("role is admin", field(data?.user, "role") === "admin", data?.user);
  const session = await admin.client.getSession();
  adminSessionId = session.data?.session.id ?? "";
});

await step("admin.createUser", async () => {
  const { data, error } = await admin.client.admin.createUser({ email: userEmail, password, name: "Member", role: "user" });
  check("no error", !error, error);
  check("returns the user", data?.user.email === userEmail, data);
  check("role is user", field(data?.user, "role") === "user", data?.user);
  userId = data?.user.id ?? "";
  const again = await admin.client.admin.createUser({ email: userEmail, password, name: "Member" });
  check("a taken email: USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL", again.error?.code === "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL", again.error);
});

await step("admin.listUsers", async () => {
  const { data, error } = await admin.client.admin.listUsers({
    query: { searchValue: "member-", searchField: "email", searchOperator: "contains", limit: 10, sortBy: "createdAt", sortDirection: "desc" },
  });
  check("no error", !error, error);
  check("finds the member", data?.users.some((u) => u.id === userId), data);
  check("total counts the matches", typeof field(data, "total") === "number" && (field(data, "total") as number) >= 1, data);
  check("echoes limit", field(data, "limit") === 10, data);
  const filtered = await admin.client.admin.listUsers({ query: { filterField: "role", filterValue: "admin", filterOperator: "eq" } });
  check("filter by role", filtered.data?.users.every((u) => field(u, "role") === "admin"), filtered.data);
});

await step("a member is refused", async () => {
  const signIn = await member.client.signIn.email({ email: userEmail, password });
  check("member signs in", !signIn.error, signIn.error);
  const { error } = await member.client.admin.listUsers({ query: {} });
  check("status 403", error?.status === 403, error);
  check("YOU_ARE_NOT_ALLOWED_TO_LIST_USERS", error?.code === "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS", error);
  const allowed = await member.client.admin.hasPermission({ permissions: { user: ["list"] } });
  check("hasPermission: success false", allowed.data?.success === false, allowed);
  const own = await admin.client.admin.hasPermission({ permissions: { user: ["list", "ban"] } });
  check("hasPermission for the admin: success true", own.data?.success === true, own);
  const guarded = await member.fetch(`${ORIGIN}/admin-only`);
  check("RequireRole route: 403 for the member", guarded.status === 403, guarded.status);
  const open = await admin.fetch(`${ORIGIN}/admin-only`);
  check("RequireRole route: 200 for the admin", open.status === 200, open.status);
});

await step("admin.setRole and admin.updateUser", async () => {
  const { data, error } = await admin.client.admin.setRole({ userId, role: ["user"] });
  check("setRole: no error", !error, error);
  check("setRole: role", field(data?.user, "role") === "user", data);
  const updated = await admin.client.admin.updateUser({ userId, data: { name: "Renamed" } });
  check("updateUser: no error", !updated.error, updated.error);
  check("updateUser: name", field(updated.data, "name") === "Renamed", updated.data);
});

await step("admin.impersonateUser + stopImpersonating", async () => {
  const { data, error } = await admin.client.admin.impersonateUser({ userId });
  check("no error", !error, error);
  check("impersonatedBy is set", field(data?.session, "impersonatedBy") !== undefined && field(data?.session, "impersonatedBy") !== null, data);
  const as = await admin.client.getSession();
  check("the admin's client is now the member", as.data?.user.id === userId, as.data);
  const back = await admin.client.admin.stopImpersonating();
  check("stopImpersonating: no error", !back.error, back.error);
  const session = await admin.client.getSession();
  check("back to the admin session", session.data?.session.id === adminSessionId, session.data);
});

await step("admin.listUserSessions + revokeUserSessions", async () => {
  const { data, error } = await admin.client.admin.listUserSessions({ userId });
  check("no error", !error, error);
  check("one session", data?.sessions.length === 1, data);
  const revoked = await admin.client.admin.revokeUserSessions({ userId });
  check("revokeUserSessions: success", revoked.data?.success === true, revoked);
  const gone = await member.client.getSession();
  check("the member is signed out", gone.data === null, gone);
});

await step("admin.banUser + unbanUser", async () => {
  const { data, error } = await admin.client.admin.banUser({ userId, banReason: "spam", banExpiresIn: 3600 });
  check("no error", !error, error);
  check("banned", field(data?.user, "banned") === true, data);
  const signIn = await member.client.signIn.email({ email: userEmail, password });
  check("sign-in: status 403", signIn.error?.status === 403, signIn.error);
  check("sign-in: BANNED_USER", signIn.error?.code === "BANNED_USER", signIn.error);
  const unban = await admin.client.admin.unbanUser({ userId });
  check("unbanUser: banned false", field(unban.data?.user, "banned") === false, unban);
  const again = await member.client.signIn.email({ email: userEmail, password });
  check("signs in after the unban", !again.error, again.error);
});

await step("admin.setUserPassword + removeUser", async () => {
  const { data, error } = await admin.client.admin.setUserPassword({ userId, newPassword: "a brand new password" });
  check("setUserPassword: status true", data?.status === true, error ?? data);
  const removed = await admin.client.admin.removeUser({ userId });
  check("removeUser: success", removed.data?.success === true, removed);
  const missing = await admin.client.admin.getUser({ query: { id: userId } });
  check("getUser afterwards: USER_NOT_FOUND", missing.error?.code === "USER_NOT_FOUND", missing.error);
});

console.log(`\n${passes} passed, ${failures} failed`);
process.exit(failures === 0 ? 0 : 1);
