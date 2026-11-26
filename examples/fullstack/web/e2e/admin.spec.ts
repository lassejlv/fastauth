import { ADMIN, expect, newPerson, shot, signIn, signUpVerified, test } from "./fixtures";

test("an admin lists users and bans one, who is signed out and can't sign back in", async ({ page, browser }) => {
  const victim = await newPerson(browser);
  const victimEmail = await signUpVerified(victim.page, "Victor");

  await signIn(page, ADMIN.email, ADMIN.password);
  await page.getByRole("link", { name: "Admin" }).click();
  await expect(page.getByRole("heading", { name: "Users" })).toBeVisible();
  await page.getByLabel("Search by email").fill(victimEmail);
  await page.getByRole("button", { name: "Search" }).click();
  const row = page.getByTestId(`user-${victimEmail}`);
  await expect(row).toBeVisible();
  await shot(page, "12-admin-users");

  await row.getByRole("button", { name: "Ban" }).click();
  await expect(row.getByText("Banned")).toBeVisible();

  // Banning revoked Victor's session.
  await victim.page.goto("/security");
  await expect(victim.page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await signIn(victim.page, victimEmail);
  await expect(victim.page.getByRole("alert")).toHaveText(
    "This account has been suspended. Contact support if you think that's a mistake.",
  );

  await row.getByRole("button", { name: "Unban" }).click();
  await expect(row.getByText("Banned")).toHaveCount(0);
  await signIn(victim.page, victimEmail);
  await expect(victim.page.getByRole("heading", { name: "Security", exact: true })).toBeVisible();
  await victim.context.close();
});

test("a user who isn't an admin can't use the admin pages", async ({ page }) => {
  await signUpVerified(page, "Ursula");
  await expect(page.getByRole("link", { name: "Admin" })).toHaveCount(0);
  await page.goto("/admin");
  await expect(page.getByRole("alert")).toHaveText("Only admins can see this page.");

  const list = await page.request.get("/api/auth/admin/list-users");
  expect(list.status()).toBe(403);
});
