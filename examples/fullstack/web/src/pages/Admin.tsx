import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, authClient, describeError } from "../auth-client";

type User = { id: string; name: string; email: string; role?: string | null; banned?: boolean | null; emailVerified: boolean };
type Overview = { users: number; banned: number; organizations: number };

export function Admin() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [users, setUsers] = useState<User[]>([]);
  const [search, setSearch] = useState("");
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    const result = await api<Overview>("/api/admin/overview");
    if (result.error) return setError(result.error.status === 403 ? "Only admins can see this page." : describeError(result.error));
    setOverview(result.data!);
    const query = search
      ? { searchValue: search.toLowerCase(), searchField: "email" as const, searchOperator: "contains" as const, limit: 100 }
      : { limit: 100, sortBy: "createdAt", sortDirection: "desc" as const };
    const { data, error } = await authClient.admin.listUsers({ query });
    if (error) return setError(describeError(error));
    setUsers((data?.users as User[] | undefined) ?? []);
  }, [search]);

  useEffect(() => {
    load();
  }, [load]);

  async function ban(userId: string) {
    const { error } = await authClient.admin.banUser({ userId, banReason: "Banned from the admin page" });
    if (error) return setError(describeError(error));
    load();
  }

  async function unban(userId: string) {
    const { error } = await authClient.admin.unbanUser({ userId });
    if (error) return setError(describeError(error));
    load();
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSearch(String(new FormData(event.currentTarget).get("search")).trim());
  }

  if (!overview) {
    return (
      <main className="page">
        <div className="page-head">
          <h1>Admin</h1>
          {error && <p className="lead" role="alert">{error}</p>}
        </div>
      </main>
    );
  }

  return (
    <main className="page">
      <div className="page-head">
        <h1>Users</h1>
        <p className="stats">
          <span><strong>{overview.users}</strong> users</span>
          <span><strong>{overview.banned}</strong> banned</span>
          <span><strong>{overview.organizations}</strong> organizations</span>
        </p>
      </div>
      <form onSubmit={submit} className="row">
        <label>Search by email<input name="search" type="search" defaultValue={search} /></label>
        <button className="secondary">Search</button>
      </form>
      <div className="list">
        {users.length === 0 && <div className="empty">No users match.</div>}
        {users.map((user) => (
          <div className="list-row" key={user.id} data-testid={`user-${user.email}`}>
            <div className="grow">
              <div className="title">{user.name}</div>
              <div className="sub">{user.email}{user.emailVerified ? "" : " · not verified"}</div>
            </div>
            {user.role && user.role !== "user" && <span className="badge">{user.role}</span>}
            {user.banned && <span className="badge warn">Banned</span>}
            {user.banned ? (
              <button className="ghost" onClick={() => unban(user.id)}>Unban</button>
            ) : (
              <button className="danger-ghost" onClick={() => ban(user.id)}>Ban</button>
            )}
          </div>
        ))}
      </div>
      {error && <p className="error" role="alert">{error}</p>}
    </main>
  );
}
