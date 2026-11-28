// A minimal OAuth 2.0 provider for the suite: /authorize answers with a code at once, /token
// trades it for tokens, /userinfo returns the profile queued with `next`. Both apps sign in
// through it under the provider id "mock".
import { createServer, type Server } from "node:http";
import { randomBytes } from "node:crypto";

export type Profile = { sub: string; email: string; name: string; email_verified: boolean };

let queued: Profile | undefined;
const codes = new Map<string, Profile>();
const tokens = new Map<string, Profile>();

/** The profile the next authorization signs in as. */
export function next(profile: Profile) {
  queued = profile;
}

export function startMock(port: number): Promise<Server> {
  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://mock");
    const json = (status: number, body: unknown) =>
      res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
    if (url.pathname === "/authorize") {
      const redirect = new URL(url.searchParams.get("redirect_uri") ?? "");
      if (!queued) return json(400, { error: "no profile queued" });
      const code = randomBytes(16).toString("hex");
      codes.set(code, queued);
      queued = undefined;
      redirect.searchParams.set("code", code);
      redirect.searchParams.set("state", url.searchParams.get("state") ?? "");
      return res.writeHead(302, { location: redirect.toString() }).end();
    }
    if (url.pathname === "/token" && req.method === "POST") {
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(chunk as Buffer);
      const form = new URLSearchParams(Buffer.concat(chunks).toString());
      const profile = codes.get(form.get("code") ?? "");
      if (!profile) return json(400, { error: "invalid_grant" });
      codes.delete(form.get("code") ?? "");
      const access = `mock-access-${randomBytes(12).toString("hex")}`;
      tokens.set(access, profile);
      return json(200, {
        access_token: access,
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: `mock-refresh-${randomBytes(12).toString("hex")}`,
        scope: "openid email",
      });
    }
    if (url.pathname === "/userinfo") {
      const profile = tokens.get((req.headers.authorization ?? "").replace(/^Bearer /, ""));
      // Better Auth's genericOAuth takes the account id from `id` in a userinfo response (from
      // `sub` only in an id_token), so the profile carries both, as many providers' do.
      return profile ? json(200, { id: profile.sub, ...profile }) : json(401, { error: "invalid_token" });
    }
    json(404, {});
  });
  return new Promise((resolve) => server.listen(port, "127.0.0.1", () => resolve(server)));
}
