import { countEmails, expect, lastEmail, newPerson, shot, signIn, signOut, signUp, signUpVerified, test, uniqueEmail } from "./fixtures";

test("sign up, verify the email, sign out and sign back in", async ({ page }) => {
  const email = uniqueEmail("ada");
  await page.goto("/sign-up");
  await shot(page, "01-sign-up");
  await signUp(page, "Ada", email);
  await expect(page.getByText(email)).toBeVisible();
  await shot(page, "02-check-email");

  await signIn(page, email);
  await expect(page.getByRole("alert")).toHaveText("Verify your email first. We sent you a link when you signed up.");

  await page.goto(`/check-email?email=${encodeURIComponent(email)}`);
  await page.getByRole("button", { name: "Send it again" }).click();
  await expect(page.getByRole("status")).toContainText("Sent");
  await expect.poll(() => countEmails(email, "verify-email")).toBeGreaterThanOrEqual(2);

  const { url } = await lastEmail(email, "verify-email");
  await page.goto(url!);
  await expect(page.getByRole("heading", { name: "Welcome, Ada" })).toBeVisible();
  await expect(page.getByText("Your email is verified and you're signed in.")).toBeVisible();
  await shot(page, "03-home");

  await signOut(page);
  await shot(page, "04-sign-in");
  await signIn(page, email);
  await expect(page.getByRole("heading", { name: "Welcome, Ada" })).toBeVisible();
});

test("a signed-out visitor is sent to sign-in and back", async ({ page }) => {
  const email = uniqueEmail("grace");
  await signUp(page, "Grace", email);
  const { url } = await lastEmail(email, "verify-email");
  await page.goto(url!);
  await signOut(page);

  await page.goto("/api-keys");
  await expect(page).toHaveURL(/\/sign-in\?next=%2Fapi-keys/);
  await signIn(page, email);
  await expect(page.getByRole("heading", { name: "API keys" })).toBeVisible();
});

test("signing up with a taken email reveals nothing and changes nothing", async ({ page }) => {
  const email = uniqueEmail("linus");
  await signUpVerified(page, "Linus", email);
  await signOut(page);

  // With email verification required, a taken email gets the same answer as a new one, so
  // the form can't be used to find out who has an account.
  await signUp(page, "Someone else", email, "another password 1");
  await signIn(page, email, "another password 1");
  await expect(page.getByRole("alert")).toHaveText("That email and password don't match.");
  await signIn(page, email);
  await expect(page.getByRole("heading", { name: "Welcome, Linus" })).toBeVisible();
});

test("a wrong password is refused", async ({ page }) => {
  const email = await signUpVerified(page, "Alan");
  await signOut(page);
  await signIn(page, email, "not the password");
  await expect(page.getByRole("alert")).toHaveText("That email and password don't match.");
});

test("sign-in attempts are limited per client IP", async ({ page, browser, baseURL }) => {
  const email = uniqueEmail("mallory");
  await page.goto("/sign-in");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill("guess 4");

  // Core allows 3 requests per 10 seconds per client IP on /sign-in/*, refilling one every
  // 3.3 s. Spend them from this test's IP with bodies that fail fast (no password hashing, so
  // the timing holds on a slow debug build), then try once in the UI.
  const spent = await Promise.all(
    [1, 2, 3].map(() => page.request.post("/api/auth/sign-in/email", { data: {}, headers: { origin: baseURL! } })),
  );
  expect(spent.map((r) => r.status())).not.toContain(429);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByRole("alert")).toHaveText("Too many attempts. Wait a few seconds and try again.");

  const other = await newPerson(browser);
  await signIn(other.page, email, "guess 5");
  await expect(other.page.getByRole("alert")).toHaveText("That email and password don't match.");
  await other.context.close();
});
