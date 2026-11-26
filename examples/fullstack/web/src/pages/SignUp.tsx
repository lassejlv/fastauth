import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router";
import { authClient, describeError } from "../auth-client";
import { AuthCard } from "../components/AuthCard";

export function SignUp() {
  const navigate = useNavigate();
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const email = String(form.get("email"));
    setPending(true);
    const { error } = await authClient.signUp.email({
      name: String(form.get("name")),
      email,
      password: String(form.get("password")),
      callbackURL: "/?verified=1",
    });
    setPending(false);
    if (error) return setError(describeError(error));
    navigate(`/check-email?email=${encodeURIComponent(email)}`);
  }

  return (
    <AuthCard title="Create an account" lead={<>Already have one? <Link to="/sign-in">Sign in</Link></>}>
      <form onSubmit={submit}>
        <label>Name<input name="name" autoComplete="name" required /></label>
        <label>Email<input name="email" type="email" autoComplete="email" required /></label>
        <label>Password<input name="password" type="password" autoComplete="new-password" minLength={8} required /></label>
        {error && <p className="error" role="alert">{error}</p>}
        <button className="primary" disabled={pending}>Create account</button>
      </form>
    </AuthCard>
  );
}
