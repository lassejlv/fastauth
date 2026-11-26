import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { api, authClient, describeError } from "../auth-client";
import { AuthCard } from "../components/AuthCard";

export function SignIn() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const next = safeNext(params.get("next"));
  const [error, setError] = useState(params.get("error") ? describeError({ code: params.get("error")!.toUpperCase() }) : "");
  const [pending, setPending] = useState(false);
  const [github, setGithub] = useState(false);
  const { refetch } = authClient.useSession();

  useEffect(() => {
    api<{ github: boolean }>("/api/features").then(({ data }) => setGithub(Boolean(data?.github)));
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setPending(true);
    setError("");
    const { data, error } = await authClient.signIn.email({
      email: String(form.get("email")),
      password: String(form.get("password")),
    });
    setPending(false);
    if (error) return setError(describeError(error));
    if (data && "twoFactorRedirect" in data && data.twoFactorRedirect) {
      // fastauth set a short-lived cookie for the pending sign-in; the code finishes it.
      return navigate(`/two-factor?next=${encodeURIComponent(next)}`);
    }
    await refetch();
    navigate(next);
  }

  async function passkey() {
    setError("");
    const result = await authClient.signIn.passkey();
    if (result?.error) return setError(describeError(result.error));
    await refetch();
    navigate(next);
  }

  async function signInWithGithub() {
    const { error } = await authClient.signIn.social({
      provider: "github",
      callbackURL: next,
      errorCallbackURL: "/sign-in",
    });
    if (error) setError(describeError(error));
  }

  return (
    <AuthCard title="Sign in" lead={<>New here? <Link to="/sign-up">Create an account</Link></>}>
      <form onSubmit={submit}>
        <label>Email<input name="email" type="email" autoComplete="username webauthn" required /></label>
        <label>Password<input name="password" type="password" autoComplete="current-password" required /></label>
        {error && <p className="error" role="alert">{error}</p>}
        <button className="primary" disabled={pending}>Sign in</button>
      </form>
      <div className="divider">or</div>
      <div className="stack">
        <button className="secondary" onClick={passkey}>Sign in with a passkey</button>
        {github && <button className="secondary" onClick={signInWithGithub}>Continue with GitHub</button>}
      </div>
    </AuthCard>
  );
}

/** Only same-site paths, so `?next=` can't send someone to another site. */
export function safeNext(next: string | null) {
  return next && next.startsWith("/") && !next.startsWith("//") ? next : "/";
}
