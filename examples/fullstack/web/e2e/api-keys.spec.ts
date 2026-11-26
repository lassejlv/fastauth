import { expect, shot, signUpVerified, test } from "./fixtures";

test("create an API key, call the API with it, and delete it", async ({ page, playwright, baseURL }) => {
  const email = await signUpVerified(page, "Kathleen");
  await page.goto("/api-keys");
  await expect(page.getByText("No keys yet.")).toBeVisible();
  await page.getByLabel("Name").fill("Deploy script");
  await page.getByRole("button", { name: "Create key" }).click();
  const key = (await page.getByTestId("new-api-key").textContent())!;
  expect(key).toMatch(/^acme_/);
  await expect(page.getByText("Deploy script")).toBeVisible();
  await shot(page, "11-api-keys");

  // No cookies: the key alone signs the request in.
  const script = await playwright.request.newContext({ baseURL });
  const me = await script.get("/api/me", { headers: { "x-api-key": key } });
  expect(me.status()).toBe(200);
  expect(await me.json()).toMatchObject({ email, viaApiKey: true });
  expect((await script.get("/api/me")).status()).toBe(401);
  expect((await script.get("/api/me", { headers: { "x-api-key": `${key.slice(0, -4)}zzzz` } })).status()).toBe(401);

  await page.getByRole("button", { name: "Delete" }).click();
  await expect(page.getByText("No keys yet.")).toBeVisible();
  expect((await script.get("/api/me", { headers: { "x-api-key": key } })).status()).toBe(401);
  await script.dispose();
});
