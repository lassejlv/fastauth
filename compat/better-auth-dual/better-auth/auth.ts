// The Better Auth app the suite runs: ./app.config.ts plus what only the suite needs. Also the
// config Better Auth's CLI reads (`npx auth migrate --config better-auth/auth.ts`).
//
// From the environment: DATABASE_URL, BETTER_AUTH_SECRET, BETTER_AUTH_URL, MOCK_OAUTH_URL,
// OUTBOX (a JSON Lines file for emails), and COOKIE_CACHE=on for the instance with
// Better Auth's cookie cache on.
import { appendFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { genericOAuth } from "better-auth/plugins";
import { Pool } from "pg";
import { appConfig } from "./app.config.ts";

const env = process.env;

function outbox(kind: string, to: string, url: string) {
  if (env.OUTBOX) appendFileSync(env.OUTBOX, JSON.stringify({ app: "better-auth", kind, to, url }) + "\n");
}

export const auth = betterAuth({
  ...appConfig,
  database: new Pool({ connectionString: env.DATABASE_URL }),
  secret: env.BETTER_AUTH_SECRET,
  baseURL: env.BETTER_AUTH_URL,
  session: {
    ...appConfig.session,
    ...(env.COOKIE_CACHE === "on" ? { cookieCache: { enabled: true, maxAge: 5 * 60 } } : {}),
  },
  emailAndPassword: {
    ...appConfig.emailAndPassword,
    sendResetPassword: async ({ user, url }) => outbox("reset-password", user.email, url),
  },
  plugins: [
    // The suite's mock OAuth server, standing in for a social provider both apps configure.
    // fastauth reaches it under the same provider id (../fastauth/src/mock_provider.rs).
    genericOAuth({
      config: [
        {
          providerId: "mock",
          clientId: "dual-suite",
          clientSecret: "dual-suite-secret",
          authorizationUrl: `${env.MOCK_OAUTH_URL}/authorize`,
          tokenUrl: `${env.MOCK_OAUTH_URL}/token`,
          userInfoUrl: `${env.MOCK_OAUTH_URL}/userinfo`,
          scopes: ["openid", "email"],
          pkce: true,
        },
      ],
    }),
  ],
});
