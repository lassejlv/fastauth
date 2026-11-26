import { expect, shot, signOut, signUpVerified, test } from "./fixtures";

test("register a passkey, sign in with it, and delete it", async ({ page, context }) => {
  // Chrome's virtual authenticator answers navigator.credentials like a platform passkey.
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });

  await signUpVerified(page, "Radia");
  await page.goto("/security");
  const passkeys = page.getByRole("region", { name: "Passkeys" });
  await expect(passkeys.getByText("No passkeys yet.")).toBeVisible();
  await passkeys.getByLabel("Name").fill("Work laptop");
  await passkeys.getByRole("button", { name: "Add a passkey" }).click();
  await expect(passkeys.getByText("Work laptop")).toBeVisible();
  await shot(page, "07-security");
  const { credentials } = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
  expect(credentials).toHaveLength(1);
  expect(credentials[0].isResidentCredential).toBe(true);

  await signOut(page);
  await page.getByRole("button", { name: "Sign in with a passkey" }).click();
  await expect(page.getByRole("heading", { name: "Welcome, Radia" })).toBeVisible();

  await page.goto("/security");
  await passkeys.getByRole("button", { name: "Delete" }).click();
  await expect(passkeys.getByText("No passkeys yet.")).toBeVisible();

  await signOut(page);
  await page.getByRole("button", { name: "Sign in with a passkey" }).click();
  await expect(page.getByRole("alert")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
});
