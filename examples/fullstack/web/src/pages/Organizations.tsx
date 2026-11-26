import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router";
import { authClient, describeError } from "../auth-client";

export function Organizations() {
  const navigate = useNavigate();
  const { data: orgs, refetch } = authClient.useListOrganizations();
  const [error, setError] = useState("");

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    const name = String(new FormData(event.currentTarget).get("name")).trim();
    const slug = `${name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "")}-${Math.random().toString(36).slice(2, 6)}`;
    const { data, error } = await authClient.organization.create({ name, slug });
    if (error || !data) return setError(describeError(error));
    refetch();
    navigate(`/orgs/${data.id}`);
  }

  return (
    <main className="page">
      <div className="page-head">
        <h1>Organizations</h1>
        <p className="lead">Organizations share projects. Owners and admins invite people and create projects.</p>
      </div>
      <div className="list">
        {!orgs?.length && <div className="empty">You're not in an organization yet.</div>}
        {orgs?.map((org) => (
          <Link className="list-row" key={org.id} to={`/orgs/${org.id}`}>
            <div className="grow">
              <div className="title">{org.name}</div>
              <div className="sub">{org.slug}</div>
            </div>
          </Link>
        ))}
      </div>
      <form onSubmit={create} className="row">
        <label>New organization<input name="name" placeholder="Acme Inc" required /></label>
        <button className="primary">Create</button>
      </form>
      {error && <p className="error" role="alert">{error}</p>}
    </main>
  );
}
