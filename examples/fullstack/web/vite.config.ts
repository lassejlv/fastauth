import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// In development the React app runs on Vite (5173) and /api goes to the Rust server (3000),
// so the browser sees one origin: cookies are first-party and WebAuthn runs on localhost.
// xfwd adds x-forwarded-for, which the server reads with TRUSTED_PROXIES=1. Set API_URL when
// the server isn't on port 3000.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": { target: process.env.API_URL ?? "http://localhost:3000", xfwd: true },
    },
  },
});
