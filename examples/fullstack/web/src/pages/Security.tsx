import QRCode from "qrcode";
import { useEffect, useState, type FormEvent } from "react";
import { authClient, describeError } from "../auth-client";

type Setup = { totpURI: string; backupCodes: string[]; qr: string };

export function Security() {
  return (
    <main className="page">
      <div className="page-head">
        <h1>Security</h1>
        <p className="lead">Two-factor authentication and passkeys for your account.</p>
      </div>
      <TwoFactorSection />
      <PasskeySection />
    </main>
  );
}

function TwoFactorSection() {
  const { data: session, refetch } = authClient.useSession();
  const enabled = Boolean((session?.user as { twoFactorEnabled?: boolean } | undefined)?.twoFactorEnabled);
  const [setup, setSetup] = useState<Setup | null>(null);
  const [error, setError] = useState("");

  async function enable(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    const password = String(new FormData(event.currentTarget).get("password"));
    const { data, error } = await authClient.twoFactor.enable({ password });
    if (error || !data) return setError(describeError(error));
    if (!("totpURI" in data)) return setError("The server didn't return an authenticator setup.");
    setSetup({ ...data, qr: await QRCode.toDataURL(data.totpURI, { margin: 0, width: 152 }) });
  }

  async function confirm(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    const code = String(new FormData(event.currentTarget).get("code")).trim();
    const { error } = await authClient.twoFactor.verifyTotp({ code });
    if (error) return setError(describeError(error));
    setSetup(null);
    refetch();
  }

  async function disable(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    const password = String(new FormData(event.currentTarget).get("password"));
    const { error } = await authClient.twoFactor.disable({ password });
    if (error) return setError(describeError(error));
    refetch();
  }

  return (
    <section aria-label="Two-factor authentication">
      <div className="section-head">
        <h2>Two-factor authentication</h2>
        <p>{enabled ? "On. Signing in asks for a code from your authenticator app." : "Off. Add a code from an authenticator app to every sign-in."}</p>
      </div>
      <div className="panel">
        {enabled ? (
          <form onSubmit={disable} className="row">
            <label>Password<input name="password" type="password" autoComplete="current-password" required /></label>
            <button className="danger">Turn off</button>
          </form>
        ) : setup ? (
          <>
            <div className="row" style={{ alignItems: "flex-start", gap: 20 }}>
              <img className="qr" src={setup.qr} alt="QR code for your authenticator app" />
              <div style={{ display: "grid", gap: 8 }}>
                <p>Scan the code with your authenticator app, or enter this key:</p>
                <div className="secret"><code data-testid="totp-secret">{new URL(setup.totpURI).searchParams.get("secret")}</code></div>
              </div>
            </div>
            <div style={{ display: "grid", gap: 8 }}>
              <p>Save these backup codes somewhere safe. Each works once if you lose your phone.</p>
              <pre className="codes" data-testid="backup-codes">{setup.backupCodes.map((code) => <span key={code}>{code}</span>)}</pre>
            </div>
            <form onSubmit={confirm} className="row">
              <label>Code from the app<input name="code" autoComplete="one-time-code" inputMode="numeric" required /></label>
              <button className="primary">Turn on</button>
            </form>
          </>
        ) : (
          <form onSubmit={enable} className="row">
            <label>Password<input name="password" type="password" autoComplete="current-password" required /></label>
            <button className="primary">Set up</button>
          </form>
        )}
        {error && <p className="error" role="alert">{error}</p>}
      </div>
    </section>
  );
}

type Passkey = { id: string; name?: string | null; createdAt: Date | string; deviceType?: string };

function PasskeySection() {
  const [passkeys, setPasskeys] = useState<Passkey[]>([]);
  const [error, setError] = useState("");

  async function load() {
    const { data } = await authClient.passkey.listUserPasskeys();
    setPasskeys((data as Passkey[] | null) ?? []);
  }

  useEffect(() => {
    load();
  }, []);

  async function add(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    const form = event.currentTarget;
    const name = String(new FormData(form).get("name")).trim() || "Passkey";
    const result = await authClient.passkey.addPasskey({ name });
    if (result?.error) return setError(describeError(result.error));
    form.reset();
    load();
  }

  async function remove(id: string) {
    const { error } = await authClient.passkey.deletePasskey({ id });
    if (error) return setError(describeError(error));
    load();
  }

  return (
    <section aria-label="Passkeys">
      <div className="section-head">
        <h2>Passkeys</h2>
        <p>Sign in with your fingerprint, face or device PIN instead of a password.</p>
      </div>
      <div className="list">
        {passkeys.length === 0 && <div className="empty">No passkeys yet.</div>}
        {passkeys.map((passkey) => (
          <div className="list-row" key={passkey.id}>
            <div className="grow">
              <div className="title">{passkey.name || "Passkey"}</div>
              <div className="sub">Added {new Date(passkey.createdAt).toLocaleDateString()}</div>
            </div>
            <button className="danger-ghost" onClick={() => remove(passkey.id)}>Delete</button>
          </div>
        ))}
      </div>
      <form onSubmit={add} className="row">
        <label>Name<input name="name" placeholder="Work laptop" /></label>
        <button className="secondary">Add a passkey</button>
      </form>
      {error && <p className="error" role="alert">{error}</p>}
    </section>
  );
}
