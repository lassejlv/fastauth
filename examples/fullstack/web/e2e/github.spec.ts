import { expect, test } from "./fixtures";

// The server registers GitHub only when GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET are set.
// e2e.sh sets placeholder values, so this checks everything up to GitHub's consent screen;
// a real round trip needs a real GitHub OAuth app.
test("Continue with GitHub sends the browser to GitHub with this app's callback", async ({ page, baseURL }) => {
  const features = await (await page.request.get("/api/features")).json();
  test.skip(!features.github, "GitHub isn't configured on this server");

  let authorize: URL | undefined;
  await page.route("https://github.com/**", async (route) => {
    authorize = new URL(route.request().url());
    await route.fulfill({ status: 200, contentType: "text/html", body: "<h1>GitHub</h1>" });
  });
  await page.goto("/sign-in");
  await page.getByRole("button", { name: "Continue with GitHub" }).click();
  await expect(page.getByRole("heading", { name: "GitHub" })).toBeVisible();

  expect(authorize!.pathname).toBe("/login/oauth/authorize");
  expect(authorize!.searchParams.get("client_id")).toBe(process.env.GITHUB_CLIENT_ID);
  expect(authorize!.searchParams.get("redirect_uri")).toBe(`${baseURL}/api/auth/callback/github`);
  expect(authorize!.searchParams.get("state")).toBeTruthy();
});
