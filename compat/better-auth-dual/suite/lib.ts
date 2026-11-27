// Checks, browsers, the database and the app processes for the suite.
import { spawn, type ChildProcess } from "node:child_process";
import { createWriteStream, existsSync, readFileSync } from "node:fs";
import { createServer } from "node:net";
import { randomInt } from "node:crypto";
import pg from "pg";

export const env = process.env as Record<string, string>;
export const db = new pg.Pool({ connectionString: env.DATABASE_URL });

export async function q<T = Record<string, unknown>>(sql: string, params: unknown[] = []): Promise<T[]> {
  return (await db.query(sql, params)).rows as T[];
}

// ------------------------------------------------------------------------------ checks

let passes = 0;
let failures = 0;
let current = "";
const failed: string[] = [];

export function check(name: string, condition: unknown, detail?: unknown) {
  if (condition) {
    passes++;
    console.log(`  ok   ${name}`);
    return;
  }
  failures++;
  failed.push(`${current}: ${name}`);
  console.log(`  FAIL ${name}`);
  if (detail !== undefined) console.log(`       ${JSON.stringify(detail)?.slice(0, 1500)}`);
}

export async function section(name: string, body: () => Promise<void>) {
  current = name;
  console.log(`\n${name}`);
  try {
    await body();
  } catch (error) {
    check("no exception", false, error instanceof Error ? error.stack : String(error));
  }
}

export function summary(): number {
  console.log(`\n${passes} passed, ${failures} failed`);
  for (const name of failed) console.log(`  FAIL ${name}`);
  return failures;
}

// ------------------------------------------------------------------------------ apps

export type App = {
  name: string;
  kind: "better-auth" | "fastauth";
  /** The base URL the app is configured with (its Origin, and where its links point). */
  url: string;
  /** Where the suite connects. */
  listen: string;
  proc?: ChildProcess;
  log: string;
};

export function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close(() => (typeof address === "object" && address ? resolve(address.port) : reject()));
    });
  });
}

export function app(name: string, kind: App["kind"], scheme: "http" | "https", port: number): App {
  return { name, kind, url: `${scheme}://localhost:${port}`, listen: `http://127.0.0.1:${port}`, log: `${env.WORK}/${name}.log` };
}

export function appEnv(app: App, extra: Record<string, string> = {}): Record<string, string> {
  const port = new URL(app.listen).port;
  return app.kind === "better-auth"
    ? { ...env, PORT: port, BETTER_AUTH_URL: app.url, ...extra }
    : { ...env, PORT: port, FASTAUTH_URL: app.url, RUST_LOG: "warn,fastauth=info", ...extra };
}

export async function start(app: App, extra: Record<string, string> = {}) {
  const [cmd, args] =
    app.kind === "better-auth" ? ["node", [`${env.SUITE_DIR}/better-auth/server.ts`]] : [env.FASTAUTH_BIN, ["serve"]];
  const log = createWriteStream(app.log, { flags: "a" });
  const proc = spawn(cmd, args, { env: appEnv(app, extra), stdio: ["ignore", "pipe", "pipe"] });
  proc.stdout.pipe(log);
  proc.stderr.pipe(log);
  app.proc = proc;
  for (let i = 0; i < 150; i++) {
    if (proc.exitCode !== null) throw new Error(`${app.name} exited: ${readFileSync(app.log, "utf8").slice(-2000)}`);
    try {
      const res = await fetch(`${app.listen}/api/auth/get-session`);
      if (res.status < 500) return;
    } catch {}
    await sleep(200);
  }
  throw new Error(`${app.name} didn't start; log: ${app.log}`);
}

export async function stop(app: App) {
  const proc = app.proc;
  if (!proc || proc.exitCode !== null) return;
  const exited = new Promise((resolve) => proc.once("exit", resolve));
  proc.kill();
  await exited;
}

export function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Runs a command to completion; never throws. */
export function run(cmd: string, args: string[], extra: Record<string, string> = {}, cwd = env.SUITE_DIR) {
  return new Promise<{ code: number; out: string }>((resolve) => {
    const proc = spawn(cmd, args, { env: { ...env, ...extra }, cwd });
    let out = "";
    proc.stdout.on("data", (d) => (out += d));
    proc.stderr.on("data", (d) => (out += d));
    proc.on("close", (code) => resolve({ code: code ?? -1, out }));
  });
}

// ------------------------------------------------------------------------------ browsers

/**
 * One browser: a cookie jar both apps see, as they would on one site, and its own client
 * address (fastauth rate-limits per address, read from x-forwarded-for behind one proxy).
 */
export type Browser = { jar: Map<string, string>; ip: string };

export function browser(): Browser {
  return { jar: new Map(), ip: `10.${randomInt(256)}.${randomInt(256)}.${randomInt(1, 255)}` };
}

export type Res = { status: number; json: any; text: string; setCookies: string[]; location: string | null };

export async function call(app: App, b: Browser, method: string, path: string, body?: unknown, headers: Record<string, string> = {}): Promise<Res> {
  const send = () => {
    const h = new Headers({ origin: new URL(app.url).origin, "x-forwarded-for": b.ip, ...headers });
    if (body !== undefined) h.set("content-type", "application/json");
    if (b.jar.size > 0) h.set("cookie", [...b.jar].map(([k, v]) => `${k}=${v}`).join("; "));
    return fetch(new URL(path, app.listen), {
      method,
      headers: h,
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: "manual",
    });
  };
  let res = await send();
  while (res.status === 429) {
    const wait = Number(res.headers.get("retry-after") ?? 10);
    console.log(`  ...  rate limited on ${path}, retrying in ${wait}s`);
    await sleep(wait * 1000);
    res = await send();
  }
  const setCookies = res.headers.getSetCookie();
  for (const header of setCookies) {
    const [pair, ...attributes] = header.split(";").map((p) => p.trim());
    const eq = pair.indexOf("=");
    const name = pair.slice(0, eq);
    const value = pair.slice(eq + 1);
    const expired = attributes.some((a) => /^max-age=0$/i.test(a) || (/^expires=/i.test(a) && Date.parse(a.slice(8)) < Date.now()));
    if (expired || value === "") b.jar.delete(name);
    else b.jar.set(name, value);
  }
  const text = await res.text();
  let json: any = null;
  try {
    json = JSON.parse(text);
  } catch {}
  return { status: res.status, json, text, setCookies, location: res.headers.get("location") };
}

/** The Set-Cookie header for `name`, if the response set one. */
export function setCookie(res: Res, name: string): string | undefined {
  return res.setCookies.find((c) => c.startsWith(`${name}=`));
}

// ------------------------------------------------------------------------------ the outbox

/** The newest email to `to` of this kind that both apps' mailers wrote, waiting for it. */
export async function email(to: string, kind: string, after: number): Promise<any> {
  for (let i = 0; i < 50; i++) {
    if (existsSync(env.OUTBOX)) {
      const lines = readFileSync(env.OUTBOX, "utf8").trim().split("\n").slice(after);
      const found = lines.map((l) => JSON.parse(l)).filter((m) => m.to === to && m.kind === kind);
      if (found.length > 0) return found.at(-1);
    }
    await sleep(100);
  }
  throw new Error(`no ${kind} email to ${to}`);
}

export function outboxSize(): number {
  return existsSync(env.OUTBOX) ? readFileSync(env.OUTBOX, "utf8").trim().split("\n").filter(Boolean).length : 0;
}
