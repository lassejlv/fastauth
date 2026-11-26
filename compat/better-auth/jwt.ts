import { createAuthClient } from "better-auth/client";
import { jwtClient } from "better-auth/client/plugins";
import { createLocalJWKSet, createRemoteJWKSet, decodeProtectedHeader, jwtVerify } from "jose";

// Better Auth's jwtClient, with bearer auth, against the JWT plugin's compat_server example.
// Tokens are checked with jose against the JWKS, as a resource server would.
// run-jwt.sh builds and starts the server.

const BASE_URL = process.env.FASTAUTH_URL ?? "http://localhost:3000";
const ISSUER = new URL(BASE_URL).origin;

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
const email = `jwt-${run}@example.com`;
let bearer = "";
let userId = "";
const client = createAuthClient({
  baseURL: BASE_URL,
  plugins: [jwtClient()],
  fetchOptions: { auth: { type: "Bearer", token: () => bearer } },
});
const anonymous = createAuthClient({ baseURL: BASE_URL, plugins: [jwtClient()] });
let jwks: { keys: Array<Record<string, string>> } = { keys: [] };

console.log(`better-auth jwtClient against ${BASE_URL} (${email})\n`);

await step("signUp.email", async () => {
  const { data, error } = await anonymous.signUp.email(
    { email, password: "correct horse battery", name: "Jwt" },
    { onSuccess: (ctx) => void (bearer = ctx.response.headers.get("set-auth-token") ?? "") },
  );
  check("no error", !error, error);
  userId = data?.user.id ?? "";
  check("set-auth-token", bearer.length > 0);
});

await step("jwks", async () => {
  const { data, error } = await client.jwks();
  check("no error", !error, error);
  jwks = (data as typeof jwks) ?? { keys: [] };
  const key = jwks.keys[0];
  check("one key", jwks.keys.length === 1, jwks);
  check("alg EdDSA", key?.alg === "EdDSA", key);
  check("crv Ed25519", key?.crv === "Ed25519", key);
  check("kty OKP", key?.kty === "OKP", key);
  check("has kid and x", Boolean(key?.kid && key?.x), key);
  check("no private key", key !== undefined && !("d" in key), key);
});

await step("token", async () => {
  const { data, error } = await client.token();
  check("no error", !error, error);
  const token = (data as { token?: string } | null)?.token ?? "";
  check("returns a token", token.split(".").length === 3, data);
  const header = decodeProtectedHeader(token);
  check("header alg EdDSA", header.alg === "EdDSA", header);
  check("header kid is the JWKS key", header.kid === jwks.keys[0]?.kid, header);
  const { payload } = await jwtVerify(token, createLocalJWKSet(jwks), { issuer: ISSUER, audience: ISSUER });
  check("sub is the user id", payload.sub === userId, payload);
  check("carries the user", payload.email === email && payload.name === "Jwt", payload);
  check("expires in 15 minutes", (payload.exp ?? 0) - (payload.iat ?? 0) === 900, payload);
  const remote = await jwtVerify(token, createRemoteJWKSet(new URL(`${BASE_URL}/api/auth/jwks`)), {
    issuer: ISSUER,
    audience: ISSUER,
  });
  check("verifies against the remote JWKS", remote.payload.sub === userId);
});

await step("getSession sets set-auth-jwt", async () => {
  let jwt = "";
  let exposed = "";
  const { data, error } = await client.getSession({
    fetchOptions: {
      onSuccess(ctx) {
        jwt = ctx.response.headers.get("set-auth-jwt") ?? "";
        exposed = ctx.response.headers.get("access-control-expose-headers") ?? "";
      },
    },
  });
  check("no error", !error, error);
  check("signed in", data?.user.id === userId, data);
  check("set-auth-jwt header", jwt.length > 0);
  check("Access-Control-Expose-Headers lists it", exposed.split(",").map((h) => h.trim()).includes("set-auth-jwt"), exposed);
  const { payload } = await jwtVerify(jwt, createLocalJWKSet(jwks), { issuer: ISSUER, audience: ISSUER });
  check("the header token verifies", payload.sub === userId, payload);
});

await step("token without a session", async () => {
  const { data, error } = await anonymous.token();
  check("no data", data === null, data);
  check("status 401", error?.status === 401, error);
});

await step("getSession without a session has no set-auth-jwt", async () => {
  let jwt: string | null = "unset";
  const { data } = await anonymous.getSession({
    fetchOptions: { onSuccess: (ctx) => void (jwt = ctx.response.headers.get("set-auth-jwt")) },
  });
  check("no session", data === null, data);
  check("no header", jwt === null, jwt);
});

console.log(`${passes} passed, ${failures} failed`);
process.exit(failures > 0 ? 1 : 0);
