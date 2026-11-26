import { useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { authClient, describeError } from "../auth-client";
import { AuthCard } from "../components/AuthCard";
import { safeNext } from "./SignIn";

/** The second step of a sign-in for users with two-factor on. */
export function TwoFactor() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [backup, setBackup] = useState(false);
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);
  const { refetch } = authClient.useSession();

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const code = String(form.get("code")).trim();
    setPending(true);
    setError("");
    const { error } = backup
      ? await authClient.twoFactor.verifyBackupCode({ code })
      : await authClient.twoFactor.verifyTotp({ code, trustDevice: form.get("trust") === "on" });
    setPending(false);
    if (error) return setError(describeError(error));
    // Load the new session before leaving, so the signed-in screens don't see the old one.
    await refetch();
    navigate(safeNext(params.get("next")));
  }

  return (
    <AuthCard
      title="Two-factor authentication"
      lead={backup ? "Enter one of the backup codes you saved." : "Enter the 6-digit code from your authenticator app."}
    >
      <form onSubmit={submit} key={String(backup)}>
        <label>
          {backup ? "Backup code" : "Code"}
          <input name="code" autoComplete="one-time-code" inputMode={backup ? "text" : "numeric"} autoFocus required />
        </label>
        {!backup && (
          <label className="check"><input type="checkbox" name="trust" /> Trust this device for 30 days</label>
        )}
        {error && <p className="error" role="alert">{error}</p>}
        <button className="primary" disabled={pending}>Verify</button>
      </form>
      <div className="row">
        <button className="ghost" onClick={() => { setBackup(!backup); setError(""); }}>
          {backup ? "Use your authenticator" : "Use a backup code"}
        </button>
        <Link className="button ghost" to="/sign-in">Cancel</Link>
      </div>
    </AuthCard>
  );
}
