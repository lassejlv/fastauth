// Serves ./auth.ts on 127.0.0.1:$PORT, plus two routes of the app's own code that read and
// write its customerId field, as the fastauth app has (/app/me and /app/customer-id).
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { fromNodeHeaders, toNodeHandler } from "better-auth/node";
import { auth } from "./auth.ts";

const handler = toNodeHandler(auth);

function send(res: ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
}

async function body(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return JSON.parse(Buffer.concat(chunks).toString() || "{}");
}

async function app(req: IncomingMessage, res: ServerResponse) {
  const session = await auth.api.getSession({ headers: fromNodeHeaders(req.headers) });
  if (!session) return send(res, 401, { code: "UNAUTHORIZED" });
  if (req.url === "/app/me") {
    return send(res, 200, { id: session.user.id, email: session.user.email, customerId: session.user.customerId ?? null });
  }
  if (req.url === "/app/customer-id" && req.method === "POST") {
    const { customerId } = await body(req);
    const ctx = await auth.$context;
    await ctx.internalAdapter.updateUser(session.user.id, { customerId });
    return send(res, 200, { ok: true });
  }
  send(res, 404, {});
}

createServer((req, res) => {
  if (req.url?.startsWith("/app/")) {
    app(req, res).catch((error) => send(res, 500, { error: String(error) }));
    return;
  }
  handler(req, res);
}).listen(Number(process.env.PORT), "127.0.0.1", () => {
  console.log(`better-auth listening on 127.0.0.1:${process.env.PORT}`);
});
