import { createHmac, randomBytes, randomInt } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test as base, type Browser, type BrowserContext, type Page } from "@playwright/test";

export { expect };

const OUTBOX = process.env.MAIL_OUTBOX ?? "outbox.jsonl";
export const ADMIN = {
  email: process.env.ADMIN_EMAIL ?? "admin@acme.test",
  password: process.env.ADMIN_PASSWORD ?? "admin password 1",
};
export const PASSWORD = "correct horse battery";

/**
 * Each test is its own client: the server trusts one proxy hop of x-forwarded-for
 * (TRUSTED_PROXIES=1), and every test sends its own address, so rate limits apply per test
 * the way they apply per person in production.
 */
export function clientIp() {
  return `10.${randomInt(256)}.${randomInt(256)}.${randomInt(1, 255)}`;
}

export const test = base.extend({
  extraHTTPHeaders: async ({}, use) => use({ "x-forwarded-for": clientIp() }),
});

/** A browser context for a second person, with their own cookies and IP. */
export async function newPerson(browser: Browser): Promise<{ context: BrowserContext; page: Page }> {
  const context = await browser.newContext({ extraHTTPHeaders: { "x-forwarded-for": clientIp() } });
  return { context, page: await context.newPage() };
}

export function uniqueEmail(name: string) {
  return `${name}-${Date.now().toString(36)}${randomBytes(3).toString("hex")}@acme.test`;
}

type Email = { kind: string; to: string; url: string | null; subject: string };

/** The newest email of `kind` the dev mailer wrote for `to`. */
export async function lastEmail(to: string, kind: string): Promise<Email> {
  let found: Email | undefined;
  await expect
    .poll(() => {
      const lines = safeRead(OUTBOX).split("\n").filter(Boolean);
      found = lines.map((line) => JSON.parse(line) as Email).filter((e) => e.to === to && e.kind === kind).at(-1);
      return found;
    }, { message: `a ${kind} email to ${to}` })
    .toBeTruthy();
  return found!;
}

export function countEmails(to: string, kind: string) {
  return safeRead(OUTBOX).split("\n").filter(Boolean).map((line) => JSON.parse(line) as Email)
    .filter((e) => e.to === to && e.kind === kind).length;
}

function safeRead(path: string) {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return "";
  }
}

export async function signUp(page: Page, name: string, email: string, password = PASSWORD) {
  await page.goto("/sign-up");
  await page.getByLabel("Name").fill(name);
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page.getByRole("heading", { name: "Check your email" })).toBeVisible();
}

/** Opens the verification link from the outbox, which signs the user in. */
export async function verifyEmail(page: Page, name: string, email: string) {
  const { url } = await lastEmail(email, "verify-email");
  await page.goto(url!);
  await expect(page.getByRole("heading", { name: `Welcome, ${name}` })).toBeVisible();
}

export async function signUpVerified(page: Page, name: string, email = uniqueEmail(name.toLowerCase())) {
  await signUp(page, name, email);
  await verifyEmail(page, name, email);
  return email;
}

/** Signs in on the sign-in page, staying on it (and its `?next=`) when it's already open. */
export async function signIn(page: Page, email: string, password = PASSWORD) {
  if (new URL(page.url()).pathname !== "/sign-in") await page.goto("/sign-in");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
}

export async function signOut(page: Page) {
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
}

/** RFC 6238 TOTP for a base32 secret, as an authenticator app computes it. */
export function totp(secret: string, unixSeconds = Date.now() / 1000) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(unixSeconds / 30)));
  const hmac = createHmac("sha1", base32(secret)).update(counter).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  return ((hmac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).toString().padStart(6, "0");
}

function base32(input: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const char of input.replace(/=+$/, "").toUpperCase()) bits += alphabet.indexOf(char).toString(2).padStart(5, "0");
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

/**
 * With SCREENSHOTS set to a directory, saves the page in light and dark. The suite runs
 * without it; ../e2e.sh --screenshots sets it.
 */
export async function shot(page: Page, name: string) {
  const dir = process.env.SCREENSHOTS;
  if (!dir) return;
  mkdirSync(dir, { recursive: true });
  for (const colorScheme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme });
    await page.screenshot({ path: join(dir, `${name}-${colorScheme}.png`) });
  }
  await page.emulateMedia({ colorScheme: "light" });
}
