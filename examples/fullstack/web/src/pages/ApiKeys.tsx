import { useEffect, useState, type FormEvent } from "react";
import { authClient, describeError } from "../auth-client";

type ApiKey = { id: string; name: string | null; start: string | null; createdAt: Date | string; expiresAt: Date | string | null };

export function ApiKeys() {
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [created, setCreated] = useState<string | null>(null);
  const [error, setError] = useState("");

  async function load() {
    const { data } = await authClient.apiKey.list();
    setKeys((data?.apiKeys as ApiKey[] | undefined) ?? []);
  }

  useEffect(() => {
    load();
  }, []);

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    const form = event.currentTarget;
    const name = String(new FormData(form).get("name"));
    const { data, error } = await authClient.apiKey.create({ name, expiresIn: 60 * 60 * 24 * 90 });
    if (error || !data) return setError(describeError(error));
    setCreated(data.key);
    form.reset();
    load();
  }

  async function remove(keyId: string) {
    const { error } = await authClient.apiKey.delete({ keyId });
    if (error) return setError(describeError(error));
    load();
  }

  return (
    <main className="page">
      <div className="page-head">
        <h1>API keys</h1>
        <p className="lead">A key signs requests in as you. Keys expire after 90 days.</p>
      </div>
      {created && (
        <div className="panel">
          <p>Copy your new key now. You won't see it again.</p>
          <div className="secret">
            <code data-testid="new-api-key">{created}</code>
            <button className="ghost" onClick={() => navigator.clipboard.writeText(created)}>Copy</button>
          </div>
          <p className="faint">Try it: <code>curl -H "x-api-key: {created.slice(0, 10)}…" {location.origin}/api/me</code></p>
        </div>
      )}
      <div className="list">
        {keys.length === 0 && <div className="empty">No keys yet.</div>}
        {keys.map((key) => (
          <div className="list-row" key={key.id}>
            <div className="grow">
              <div className="title">{key.name}</div>
              <div className="sub">
                {key.start}… · created {new Date(key.createdAt).toLocaleDateString()}
                {key.expiresAt && ` · expires ${new Date(key.expiresAt).toLocaleDateString()}`}
              </div>
            </div>
            <button className="danger-ghost" onClick={() => remove(key.id)}>Delete</button>
          </div>
        ))}
      </div>
      <form onSubmit={create} className="row">
        <label>Name<input name="name" placeholder="Deploy script" required /></label>
        <button className="primary">Create key</button>
      </form>
      {error && <p className="error" role="alert">{error}</p>}
    </main>
  );
}
