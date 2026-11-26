// Bundled for the browser by run-passkey.sh: Better Auth's client with passkeyClient, on
// window.client, so passkey.ts can drive it inside a real page.
import { createAuthClient } from "better-auth/client";
import { passkeyClient } from "@better-auth/passkey/client";

declare global {
  interface Window {
    client: ReturnType<typeof newClient>;
  }
}

function newClient() {
  return createAuthClient({ baseURL: location.origin, plugins: [passkeyClient()] });
}

window.client = newClient();
