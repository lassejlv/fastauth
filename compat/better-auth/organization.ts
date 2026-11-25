import { createAuthClient } from "better-auth/client";
import { organizationClient } from "better-auth/client/plugins";

// Better Auth's organizationClient against the organization plugin's compat_server example.
// run-organization.sh builds and starts the server, then runs this.

const BASE_URL = process.env.FASTAUTH_URL ?? "http://localhost:3000";
const ORIGIN = new URL(BASE_URL).origin;

/** A fetch that keeps cookies and sends Origin, like a browser tab (see compat.ts). */
function newClient() {
  const jar = new Map<string, string>();
  const customFetchImpl = async (input: string | URL | Request, init?: RequestInit) => {
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
  return createAuthClient({
    baseURL: BASE_URL,
    plugins: [organizationClient()],
    fetchOptions: { customFetchImpl },
  });
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
const aliceEmail = `org-alice-${run}@example.com`;
const bobEmail = `org-bob-${run}@example.com`;
const slug = `acme-${run}`;
const alice = newClient();
const bob = newClient();
let orgId = "";
let invitationId = "";
let bobMemberId = "";

console.log(`better-auth organizationClient against ${BASE_URL}\n`);

await step("sign up two users", async () => {
  const a = await alice.signUp.email({ email: aliceEmail, password: "correct horse battery", name: "Alice" });
  const b = await bob.signUp.email({ email: bobEmail, password: "correct horse battery", name: "Bob" });
  check("both signed up", !a.error && !b.error, [a.error, b.error]);
});

await step("organization.create", async () => {
  const { data, error } = await alice.organization.create({ name: "Acme", slug, metadata: { plan: "pro" } });
  check("no error", !error, error);
  check("returns the organization", data?.slug === slug && data?.name === "Acme", data);
  check("metadata round-trips", (data?.metadata as { plan?: string } | undefined)?.plan === "pro", data);
  check("creator is owner", data?.members?.[0]?.role === "owner", data?.members);
  orgId = data?.id ?? "";
  const session = await alice.getSession();
  check(
    "session.activeOrganizationId is the new org",
    (session.data?.session as { activeOrganizationId?: string } | undefined)?.activeOrganizationId === orgId,
    session.data?.session,
  );
});

await step("organization.checkSlug", async () => {
  const taken = await alice.organization.checkSlug({ slug });
  check("taken slug: ORGANIZATION_SLUG_ALREADY_TAKEN", taken.error?.code === "ORGANIZATION_SLUG_ALREADY_TAKEN", taken);
  const free = await alice.organization.checkSlug({ slug: `${slug}-free` });
  check("free slug: status true", free.data?.status === true, free);
});

await step("organization.list", async () => {
  const { data, error } = await alice.organization.list();
  check("lists one organization", !error && data?.length === 1 && data[0].id === orgId, data ?? error);
});

await step("organization.inviteMember", async () => {
  const { data, error } = await alice.organization.inviteMember({ email: bobEmail, role: "admin" });
  check("no error", !error, error);
  check("pending admin invitation", data?.status === "pending" && data?.role === "admin", data);
  check("expiresAt is a date", !Number.isNaN(new Date(data?.expiresAt ?? "").getTime()), data);
  invitationId = data?.id ?? "";
  const again = await alice.organization.inviteMember({ email: bobEmail, role: "admin" });
  check(
    "inviting again: USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION",
    again.error?.code === "USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION",
    again,
  );
});

await step("organization.getInvitation and acceptInvitation", async () => {
  const details = await bob.organization.getInvitation({ query: { id: invitationId } });
  check("organizationName and inviterEmail", details.data?.organizationName === "Acme" && details.data?.inviterEmail === aliceEmail, details);
  const { data, error } = await bob.organization.acceptInvitation({ invitationId });
  check("no error", !error, error);
  check("member is admin", data?.member?.role === "admin", data);
  check("invitation is accepted", data?.invitation?.status === "accepted", data);
  bobMemberId = data?.member?.id ?? "";
});

await step("organization.getFullOrganization and listMembers", async () => {
  const full = await alice.organization.getFullOrganization();
  check("two members with users", full.data?.members.length === 2 && full.data.members[1].user.email === bobEmail, full);
  const members = await alice.organization.listMembers();
  check("total 2", members.data?.total === 2, members);
});

await step("organization.hasPermission and getActiveMember", async () => {
  const allowed = await bob.organization.hasPermission({ permissions: { member: ["delete"] } });
  check("admin may delete members", allowed.data?.success === true, allowed);
  const denied = await bob.organization.hasPermission({ permissions: { organization: ["delete"] } });
  check("admin may not delete the organization", denied.data?.success === false, denied);
  const active = await bob.organization.getActiveMember();
  check("active member is admin", active.data?.role === "admin" && active.data.user.email === bobEmail, active);
});

await step("organization.updateMemberRole", async () => {
  const { data, error } = await alice.organization.updateMemberRole({ memberId: bobMemberId, role: "member" });
  check("bob is now member", !error && data?.role === "member", data ?? error);
  const denied = await bob.organization.update({ data: { name: "Bob's" } });
  check(
    "member can't update: YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION",
    denied.error?.code === "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION" && denied.error.status === 403,
    denied,
  );
});

await step("organization.leave", async () => {
  const left = await bob.organization.leave({ organizationId: orgId });
  check("bob left", !left.error, left);
  const last = await alice.organization.leave({ organizationId: orgId });
  check(
    "last owner: YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER",
    last.error?.code === "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER",
    last,
  );
});

await step("organization.setActive(null) and delete", async () => {
  const cleared = await alice.organization.setActive({ organizationId: null });
  check("no error", !cleared.error, cleared);
  const session = await alice.getSession();
  check(
    "activeOrganizationId is cleared",
    !(session.data?.session as { activeOrganizationId?: string } | undefined)?.activeOrganizationId,
    session.data?.session,
  );
  const deleted = await alice.organization.delete({ organizationId: orgId });
  check("returns the deleted organization", deleted.data?.id === orgId, deleted);
  const list = await alice.organization.list();
  check("no organizations left", list.data?.length === 0, list);
});

console.log(`\n${passes} passed, ${failures} failed`);
process.exit(failures === 0 ? 0 : 1);
