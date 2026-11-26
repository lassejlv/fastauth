import { createAuthClient } from "better-auth/client";
import { emailOTPClient } from "better-auth/client/plugins";
import { readFileSync } from "node:fs";

// Better Auth's emailOTPClient against the email OTP plugin's example server.
// run-email-otp.sh builds and starts the server, then runs this.

const BASE_URL = process.env.FASTAUTH_URL ?? "http://localhost:3000";
const ORIGIN = new URL(BASE_URL).origin;
const OUTBOX = process.env.FASTAUTH_OUTBOX ?? "outbox.jsonl";

type Email = { to: string; kind: string; url: string | null; code: string | null };

/** The newest email the server's outbox mailer wrote for `to`. */
function lastEmail(to: string): Email | undefined {
  let text = "";
  try {
    text = readFileSync(OUTBOX, "utf8");
  } catch {
    return undefined;
  }
  const emails = text.split("\n").filter(Boolean).map((line) => JSON.parse(line) as Email);
  return emails.filter((email) => email.to === to).at(-1);
}

/** A browser tab: keeps cookies and sends Origin (see compat.ts). */
function newBrowser() {
  const jar = new Map<string, string>();
  const browserFetch = async (input: string | URL | Request, init?: RequestInit) => {
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
  const client = createAuthClient({
    baseURL: BASE_URL,
    plugins: [emailOTPClient()],
    fetchOptions: { customFetchImpl: browserFetch },
  });
  return { client, fetch: browserFetch, jar };
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
const adaEmail = `otp-ada-${run}@example.com`;
const bobEmail = `otp-bob-${run}@example.com`;
const ada = newBrowser();

console.log(`better-auth emailOTPClient against ${BASE_URL}\n`);

/** Asks for a code for `email` and returns it from the outbox. */
async function sendCode(browser: ReturnType<typeof newBrowser>, email: string, type: "sign-in" | "email-verification" | "forget-password") {
  const { data, error } = await browser.client.emailOtp.sendVerificationOtp({ email, type });
  check(`sendVerificationOtp(${type}): { success: true }`, !error && data?.success === true, error ?? data);
  check("the response carries no code", data && Object.keys(data).join() === "success", data);
  const sent = lastEmail(email);
  check(`an email-otp-${type} email was sent`, sent?.kind === `email-otp-${type}` && /^\d{6}$/.test(sent.code ?? ""), sent);
  return sent?.code ?? "";
}

function wrong(code: string) {
  return code.replace(/\d/g, (d) => String((Number(d) + 1) % 10));
}

await step("signIn.emailOtp signs a new user up", async () => {
  const code = await sendCode(ada, adaEmail, "sign-in");
  const { data, error } = await ada.client.signIn.emailOtp({ email: adaEmail, otp: code, name: "Ada" });
  check("no error", !error, error);
  check("token and user", typeof data?.token === "string" && data.user.email === adaEmail && data.user.name === "Ada", data);
  check("the email is verified", data?.user.emailVerified === true, data?.user);
  const session = await ada.client.getSession();
  check("getSession: the new user", session.data?.user.email === adaEmail, session.data);
  const reused = await newBrowser().client.signIn.emailOtp({ email: adaEmail, otp: code });
  check("a used code: 400 INVALID_OTP", reused.error?.status === 400 && reused.error.code === "INVALID_OTP", reused.error);
});

await step("wrong codes burn the code", async () => {
  const tab = newBrowser();
  const code = await sendCode(tab, adaEmail, "sign-in");
  for (let i = 1; i <= 3; i++) {
    const { error } = await tab.client.signIn.emailOtp({ email: adaEmail, otp: wrong(code) });
    check(`wrong code ${i}: 400 INVALID_OTP`, error?.status === 400 && error.code === "INVALID_OTP", error);
  }
  const { error } = await tab.client.signIn.emailOtp({ email: adaEmail, otp: code });
  check("then the right one: 403 TOO_MANY_ATTEMPTS", error?.status === 403 && error.code === "TOO_MANY_ATTEMPTS", error);
});

await step("emailOtp.verifyEmail verifies a signed-up user", async () => {
  const bob = newBrowser();
  const signUp = await bob.client.signUp.email({ email: bobEmail, password: "correct horse battery", name: "Bob" });
  check("signed up unverified", !signUp.error && signUp.data?.user.emailVerified === false, signUp.error ?? signUp.data);
  const code = await sendCode(bob, bobEmail, "email-verification");
  const { data, error } = await bob.client.emailOtp.verifyEmail({ email: bobEmail, otp: code });
  check("no error", !error, error);
  check("status true, token null", data?.status === true && data.token === null, data);
  check("user.emailVerified", data?.user.emailVerified === true, data?.user);
  const session = await bob.client.getSession();
  check("getSession: verified", session.data?.user.emailVerified === true, session.data?.user);
});

await step("checkVerificationOtp and resetPassword", async () => {
  const bob = newBrowser();
  const { data, error } = await bob.client.emailOtp.requestPasswordReset({ email: bobEmail });
  check("requestPasswordReset: { success: true }", !error && data?.success === true, error ?? data);
  const sent = lastEmail(bobEmail);
  check("an email-otp-forget-password email was sent", sent?.kind === "email-otp-forget-password", sent);
  const code = sent?.code ?? "";
  const checked = await bob.client.emailOtp.checkVerificationOtp({ email: bobEmail, type: "forget-password", otp: code });
  check("checkVerificationOtp: { success: true }", checked.data?.success === true, checked.error ?? checked.data);
  const reset = await bob.client.emailOtp.resetPassword({ email: bobEmail, otp: code, password: "a brand new password" });
  check("resetPassword: { success: true }", reset.data?.success === true, reset.error ?? reset.data);
  const signIn = await newBrowser().client.signIn.email({ email: bobEmail, password: "a brand new password" });
  check("signs in with the new password", !signIn.error && signIn.data?.user.email === bobEmail, signIn.error);
  const reused = await bob.client.emailOtp.resetPassword({ email: bobEmail, otp: code, password: "yet another password" });
  check("the code is used up: INVALID_OTP", reused.error?.code === "INVALID_OTP", reused.error);
});

await step("forgetPassword.emailOtp (deprecated) sends a code", async () => {
  const { data, error } = await newBrowser().client.forgetPassword.emailOtp({ email: bobEmail });
  check("{ success: true }", !error && data?.success === true, error ?? data);
  check("an email-otp-forget-password email was sent", lastEmail(bobEmail)?.kind === "email-otp-forget-password");
});

await step("bad input is refused", async () => {
  const tab = newBrowser();
  const email = await tab.client.emailOtp.sendVerificationOtp({ email: "not-an-email", type: "sign-in" });
  check("invalid email: 400 INVALID_EMAIL", email.error?.status === 400 && email.error.code === "INVALID_EMAIL", email.error);
  const missing = await tab.client.signIn.emailOtp({ email: `nobody-${run}@example.com`, otp: "123456" });
  check("no code sent: 400 INVALID_OTP", missing.error?.status === 400 && missing.error.code === "INVALID_OTP", missing.error);
});

console.log(`\n${passes} passed, ${failures} failed`);
process.exit(failures === 0 ? 0 : 1);
