import { expect, lastEmail, newPerson, shot, signUpVerified, test, uniqueEmail } from "./fixtures";

test("create an organization, invite a member, accept, and guard projects by role", async ({ page, browser }) => {
  await signUpVerified(page, "Olivia");
  await page.goto("/orgs");
  await expect(page.getByText("You're not in an organization yet.")).toBeVisible();
  await page.getByLabel("New organization").fill("Northwind");
  await page.getByRole("button", { name: "Create" }).click();
  await expect(page.getByRole("heading", { name: "Northwind" })).toBeVisible();
  await expect(page.getByText("You're an owner here.")).toBeVisible();
  const orgUrl = page.url();
  const orgId = orgUrl.split("/").at(-1)!;

  const projects = page.getByRole("region", { name: "Projects" });
  await projects.getByLabel("New project").fill("Website");
  await projects.getByRole("button", { name: "Create project" }).click();
  await expect(projects.getByText("Website")).toBeVisible();
  await expect(projects.getByText(/Created by Olivia/)).toBeVisible();

  const bobEmail = uniqueEmail("bob");
  const members = page.getByRole("region", { name: "Members" });
  await members.getByLabel("Invite by email").fill(bobEmail);
  await members.getByRole("button", { name: "Invite" }).click();
  await expect(members.getByText(bobEmail)).toBeVisible();
  await expect(members.getByText("Invited as member")).toBeVisible();
  await shot(page, "08-organization");

  const invitation = await lastEmail(bobEmail, "organization-invitation");
  expect(invitation.url).toContain("/accept-invitation/");

  const bob = await newPerson(browser);
  await signUpVerified(bob.page, "Bob", bobEmail);
  await bob.page.goto(invitation.url!);
  await expect(bob.page.getByRole("heading", { name: "Join Northwind" })).toBeVisible();
  await shot(bob.page, "09-accept-invitation");
  await bob.page.getByRole("button", { name: "Accept invitation" }).click();
  await expect(bob.page.getByText("You're a member here.")).toBeVisible();
  await expect(bob.page.getByRole("region", { name: "Projects" }).getByText("Website")).toBeVisible();
  await expect(bob.page.getByLabel("New project")).toHaveCount(0);

  // The route checks the role itself, whatever the UI shows.
  const denied = await bob.page.request.post(`/api/orgs/${orgId}/projects`, {
    data: { name: "Sneaky" },
    headers: { origin: new URL(orgUrl).origin },
  });
  expect(denied.status()).toBe(403);
  expect((await denied.json()).code).toBe("PERMISSION_DENIED");
  await bob.context.close();

  await page.reload();
  await expect(members.getByText("Bob", { exact: true })).toBeVisible();
  await expect(members.getByText("Invited as member")).toHaveCount(0);
});

test("a non-member can't open an organization's projects", async ({ page, browser, playwright, baseURL }) => {
  await signUpVerified(page, "Owen");
  await page.goto("/orgs");
  await page.getByLabel("New organization").fill("Private Co");
  await page.getByRole("button", { name: "Create" }).click();
  await expect(page.getByRole("heading", { name: "Private Co" })).toBeVisible();
  const orgPath = new URL(page.url()).pathname;
  const orgId = orgPath.split("/").at(-1)!;

  const carol = await newPerson(browser);
  await signUpVerified(carol.page, "Carol");
  await carol.page.goto(orgPath);
  await expect(carol.page.getByRole("heading", { name: "No access" })).toBeVisible();
  await expect(carol.page.getByRole("alert")).toHaveText("You're not a member of this organization.");
  await shot(carol.page, "10-org-no-access");

  const response = await carol.page.request.get(`/api/orgs/${orgId}/projects`);
  expect(response.status()).toBe(403);
  expect((await response.json()).code).toBe("YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION");
  await carol.context.close();

  const anonymous = await playwright.request.newContext({ baseURL });
  expect((await anonymous.get(`/api/orgs/${orgId}/projects`)).status()).toBe(401);
  await anonymous.dispose();
});

test("an invitation can only be accepted by the invited email", async ({ page, browser }) => {
  await signUpVerified(page, "Iris");
  await page.goto("/orgs");
  await page.getByLabel("New organization").fill("Guarded");
  await page.getByRole("button", { name: "Create" }).click();
  await expect(page.getByRole("heading", { name: "Guarded" })).toBeVisible();
  const invitedEmail = uniqueEmail("dave");
  await page.getByLabel("Invite by email").fill(invitedEmail);
  await page.getByRole("button", { name: "Invite" }).click();
  const { url } = await lastEmail(invitedEmail, "organization-invitation");

  const eve = await newPerson(browser);
  await signUpVerified(eve.page, "Eve");
  await eve.page.goto(url!);
  await expect(eve.page.getByRole("alert")).toBeVisible();
  await expect(eve.page.getByRole("button", { name: "Accept invitation" })).toHaveCount(0);
  await eve.context.close();
});
