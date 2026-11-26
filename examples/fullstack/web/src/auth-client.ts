import { apiKeyClient } from "@better-auth/api-key/client";
import { passkeyClient } from "@better-auth/passkey/client";
import { adminClient, organizationClient, twoFactorClient } from "better-auth/client/plugins";
import { createAuthClient } from "better-auth/react";

// Better Auth's own client, pointed at the fastauth server. Each client plugin matches a
// plugin registered in server/src/auth.rs.
export const authClient = createAuthClient({
  baseURL: window.location.origin,
  plugins: [twoFactorClient(), passkeyClient(), organizationClient(), adminClient(), apiKeyClient()],
});

export type Session = typeof authClient.$Infer.Session;

/** Better Auth's error codes, in words for people. Anything else shows the server's message. */
const messages: Record<string, string> = {
  INVALID_EMAIL_OR_PASSWORD: "That email and password don't match.",
  EMAIL_NOT_VERIFIED: "Verify your email first. We sent you a link when you signed up.",
  USER_ALREADY_EXISTS: "There's already an account with that email.",
  USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL: "There's already an account with that email.",
  BANNED_USER: "This account has been suspended. Contact support if you think that's a mistake.",
  INVALID_CODE: "That code isn't right. Check your authenticator and try again.",
  INVALID_TWO_FACTOR_COOKIE: "Your sign-in expired. Sign in again.",
  INVALID_BACKUP_CODE: "That backup code isn't right.",
  PASSWORD_TOO_SHORT: "Use at least 8 characters.",
  TOO_MANY_REQUESTS: "Too many attempts. Wait a few seconds and try again.",
  PERMISSION_DENIED: "Your role in this organization can't do that.",
  YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION: "You're not a member of this organization.",
  SESSION_NOT_FRESH: "Sign in again to do this.",
};

export function describeError(error: { code?: string; message?: string; status?: number } | null | undefined) {
  if (!error) return "";
  if (error.status === 429) return messages.TOO_MANY_REQUESTS;
  return (error.code && messages[error.code]) || error.message || "Something went wrong.";
}

/** The app's own routes in server/src/routes.rs. Errors come back as `{ code, message }`. */
export async function api<T>(path: string, init?: RequestInit): Promise<{ data?: T; error?: { status: number; code?: string; message?: string } }> {
  const response = await fetch(path, {
    ...init,
    headers: { "content-type": "application/json", ...init?.headers },
  });
  const body = await response.json().catch(() => undefined);
  if (!response.ok) return { error: { status: response.status, ...body } };
  return { data: body as T };
}
