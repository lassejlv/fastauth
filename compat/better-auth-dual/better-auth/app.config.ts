// ===========================================================================================
// THE BETTER AUTH APP'S CONFIG
//
// A stand-in for the production app's auth.ts (Better Auth 1.7.8), built from what we know
// about it:
//   - cookie prefix "vt" (so cookies are vt.session_token, __Secure-vt.session_token on https)
//   - sessions last 14 days and are extended after a day (expiresIn, updateAge)
//   - email and password sign-in
//   - one app field on the user, customerId, written by the app's own code
//   - SSO accounts with providerId "oidc", which fastauth must leave alone. The SSO plugin
//     itself isn't configured here: the suite seeds those account rows directly.
//   - session.cookieCache off, as recommended during the cutover. The suite also runs a
//     second instance with it on, to show the gap it leaves.
//
// To run the suite against the real config: replace `appConfig` below with the options
// object from the real auth.ts, without `database`, `secret` and `baseURL` (./auth.ts sets
// those from the environment). Then mirror any change that matters to fastauth (cookie prefix,
// session numbers, user fields, social providers) in ../fastauth/src/auth.rs.
// ===========================================================================================
import type { BetterAuthOptions } from "better-auth";

export const appConfig = {
  appName: "vt",
  emailAndPassword: { enabled: true },
  session: {
    expiresIn: 60 * 60 * 24 * 14,
    updateAge: 60 * 60 * 24,
    cookieCache: { enabled: false },
  },
  advanced: { cookiePrefix: "vt" },
  user: {
    additionalFields: {
      customerId: { type: "string", required: false, input: false },
    },
  },
} satisfies BetterAuthOptions;
