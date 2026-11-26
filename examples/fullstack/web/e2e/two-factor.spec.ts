import type { Page } from "@playwright/test";
import { expect, shot, signIn, signOut, signUpVerified, test, totp } from "./fixtures";

async function enrol(page: Page) {
  await page.goto("/security");
  const section = page.getByRole("region", { name: "Two-factor authentication" });
  await section.getByLabel("Password").fill("correct horse battery");
  await section.getByRole("button", { name: "Set up" }).click();
  await expect(page.getByAltText("QR code for your authenticator app")).toBeVisible();
  const secret = (await page.getByTestId("totp-secret").textContent())!;
  const backupCodes = (await page.getByTestId("backup-codes").locator("span").allTextContents());
  expect(backupCodes.length).toBeGreaterThan(0);
  await shot(page, "05-two-factor-setup");

  await section.getByLabel("Code from the app").fill(totp(secret));
  await section.getByRole("button", { name: "Turn on" }).click();
  await expect(section.getByText("On. Signing in asks for a code")).toBeVisible();
  return { secret, backupCodes };
}

test("enrol in two-factor, then sign in with a code; a wrong code is refused", async ({ page }) => {
  const email = await signUpVerified(page, "Margaret");
  const { secret } = await enrol(page);
  await signOut(page);

  await signIn(page, email);
  await expect(page.getByRole("heading", { name: "Two-factor authentication" })).toBeVisible();
  await shot(page, "06-two-factor-challenge");

  const now = Date.now() / 1000;
  const valid = new Set([-30, 0, 30].map((skew) => totp(secret, now + skew)));
  const wrong = ["000000", "111111", "222222"].find((code) => !valid.has(code))!;
  await page.getByLabel("Code").fill(wrong);
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByRole("alert")).toHaveText("That code isn't right. Check your authenticator and try again.");

  // The next 30-second window: the enrolment already used this window's code.
  await page.getByLabel("Code").fill(totp(secret, now + 30));
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByRole("heading", { name: "Welcome, Margaret" })).toBeVisible();
});

test("a backup code finishes a two-factor sign-in once", async ({ page }) => {
  const email = await signUpVerified(page, "Hedy");
  const { backupCodes } = await enrol(page);
  await signOut(page);

  await signIn(page, email);
  await page.getByRole("button", { name: "Use a backup code" }).click();
  await page.getByLabel("Backup code").fill(backupCodes[0]);
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByRole("heading", { name: "Welcome, Hedy" })).toBeVisible();
  await signOut(page);

  await signIn(page, email);
  await page.getByRole("button", { name: "Use a backup code" }).click();
  await page.getByLabel("Backup code").fill(backupCodes[0]);
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByRole("alert")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Two-factor authentication" })).toBeVisible();
});

test("turning two-factor off needs the password", async ({ page }) => {
  const email = await signUpVerified(page, "Barbara");
  await enrol(page);
  const section = page.getByRole("region", { name: "Two-factor authentication" });
  await section.getByLabel("Password").fill("wrong password");
  await section.getByRole("button", { name: "Turn off" }).click();
  await expect(section.getByRole("alert")).toBeVisible();
  await section.getByLabel("Password").fill("correct horse battery");
  await section.getByRole("button", { name: "Turn off" }).click();
  await expect(section.getByText("Off. Add a code")).toBeVisible();

  await signOut(page);
  await signIn(page, email);
  await expect(page.getByRole("heading", { name: "Welcome, Barbara" })).toBeVisible();
});
