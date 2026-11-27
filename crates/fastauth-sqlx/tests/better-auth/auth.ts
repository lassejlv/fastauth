// The Better Auth 1.7.8 config whose schema the camelCase tests run against: email and
// password, the `vt` cookie prefix and one app field, `customerId`. generate.sh runs the
// Better Auth CLI on it once per database (BA_DB = postgres, mysql or sqlite).
import { betterAuth } from "better-auth";
import Database from "better-sqlite3";
import { createPool } from "mysql2/promise";
import { Pool } from "pg";

const url = process.env.DATABASE_URL ?? "";
const database =
  process.env.BA_DB === "postgres"
    ? new Pool({ connectionString: url })
    : process.env.BA_DB === "mysql"
      ? createPool(url)
      : new Database(url);

export const auth = betterAuth({
  database,
  secret: "better-auth-schema-generation-only-0123456789",
  emailAndPassword: { enabled: true },
  advanced: { cookiePrefix: "vt" },
  user: {
    additionalFields: {
      customerId: { type: "string", required: false, input: false },
    },
  },
});
