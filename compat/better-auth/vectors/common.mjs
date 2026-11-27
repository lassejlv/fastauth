// Shared by generate.mjs and check.mjs: Better Auth's own code, called the way Better Auth
// 1.7.8 calls it.
import { readFileSync } from "node:fs";
import { createEndpoint, serializeSignedCookie } from "better-call";
import * as noble from "@better-auth/utils/password";

const modules = new URL("./node_modules/", import.meta.url);
const version = (pkg) => JSON.parse(readFileSync(new URL(`${pkg}/package.json`, modules), "utf8")).version;

// Under Node, `@better-auth/utils/password` is the @noble/hashes build; the node:crypto build
// is what Better Auth uses on workerd. Both are checked.
const passwordNode = await import(new URL("@better-auth/utils/dist/password.node.mjs", modules));

export const versions = {
  "better-call": version("better-call"),
  "@better-auth/utils": version("@better-auth/utils"),
};

/** The value of the Set-Cookie header better-call writes for a signed cookie. */
export async function signedCookie(name, value, secret) {
  const header = await serializeSignedCookie(name, value, secret, {});
  return header.slice(name.length + 1);
}

/** What `ctx.getSignedCookie(name, secret)` returns for a request with this Cookie header:
 * the value, `false` for a bad signature, `null` when there's nothing to check. */
export async function getSignedCookie(cookieHeader, name, secret) {
  const endpoint = createEndpoint("/vector", { method: "GET" }, async (ctx) =>
    ctx.getSignedCookie(name, secret),
  );
  return endpoint({ headers: new Headers({ cookie: cookieHeader }) });
}

export const hashPassword = noble.hashPassword;

/** Better Auth's verifyPassword with both builds; they must agree. Throws like Better Auth. */
export async function verifyPassword(hash, password) {
  const a = await noble.verifyPassword(hash, password);
  const b = await passwordNode.verifyPassword(hash, password);
  if (a !== b) throw new Error(`noble and node:crypto disagree on ${JSON.stringify(hash)}`);
  return a;
}
