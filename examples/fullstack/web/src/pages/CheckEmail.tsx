import { useState } from "react";
import { Link, useSearchParams } from "react-router";
import { authClient, describeError } from "../auth-client";
import { AuthCard } from "../components/AuthCard";

export function CheckEmail() {
  const [params] = useSearchParams();
  const email = params.get("email") ?? "";
  const [status, setStatus] = useState("");

  async function resend() {
    const { error } = await authClient.sendVerificationEmail({ email, callbackURL: "/?verified=1" });
    setStatus(error ? describeError(error) : "Sent. The newest link is the one that works.");
  }

  return (
    <AuthCard
      title="Check your email"
      lead={<>We sent a link to <strong>{email || "your inbox"}</strong>. Open it to verify your email and sign in.</>}
    >
      <p className="faint">Running locally? The dev mailer writes every email to the server's outbox.jsonl.</p>
      <div className="row">
        <button className="secondary" onClick={resend} disabled={!email}>Send it again</button>
        <Link className="button ghost" to="/sign-in">Back to sign in</Link>
      </div>
      {status && <p className="muted" role="status">{status}</p>}
    </AuthCard>
  );
}
