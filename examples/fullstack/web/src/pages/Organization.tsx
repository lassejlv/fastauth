import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link, useParams } from "react-router";
import { api, authClient, describeError } from "../auth-client";

type Project = { id: string; name: string; createdAt: string; createdByName: string; createdByEmail: string };
type Member = { id: string; userId: string; role: string; user: { name: string; email: string } };
type Invitation = { id: string; email: string; role: string; status: string };
type FullOrganization = { id: string; name: string; members: Member[]; invitations: Invitation[] };

export function Organization() {
  const { id = "" } = useParams();
  const { data: session } = authClient.useSession();
  const [projects, setProjects] = useState<Project[]>([]);
  const [org, setOrg] = useState<FullOrganization | null>(null);
  const [denied, setDenied] = useState("");
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    const result = await api<Project[]>(`/api/orgs/${id}/projects`);
    if (result.error) return setDenied(describeError(result.error));
    setProjects(result.data ?? []);
    const full = await authClient.organization.getFullOrganization({ query: { organizationId: id } });
    setOrg(full.data as FullOrganization | null);
  }, [id]);

  useEffect(() => {
    load();
  }, [load]);

  if (denied) {
    return (
      <main className="page">
        <div className="page-head">
          <h1>No access</h1>
          <p className="lead" role="alert">{denied}</p>
        </div>
        <p><Link to="/orgs">Back to your organizations</Link></p>
      </main>
    );
  }
  if (!org || !session) return null;

  const me = org.members.find((member) => member.userId === session.user.id);
  const manages = me?.role.split(",").some((role) => role === "owner" || role === "admin") ?? false;
  const pending = org.invitations.filter((invitation) => invitation.status === "pending");

  async function createProject(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    const form = event.currentTarget;
    const name = String(new FormData(form).get("name"));
    const result = await api<Project>(`/api/orgs/${id}/projects`, { method: "POST", body: JSON.stringify({ name }) });
    if (result.error) return setError(describeError(result.error));
    form.reset();
    load();
  }

  async function invite(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    const form = event.currentTarget;
    const data = new FormData(form);
    const { error } = await authClient.organization.inviteMember({
      organizationId: id,
      email: String(data.get("email")),
      role: String(data.get("role")) as "member" | "admin",
    });
    if (error) return setError(describeError(error));
    form.reset();
    load();
  }

  async function cancel(invitationId: string) {
    const { error } = await authClient.organization.cancelInvitation({ invitationId });
    if (error) return setError(describeError(error));
    load();
  }

  return (
    <main className="page">
      <div className="page-head">
        <h1>{org.name}</h1>
        <p className="lead">You're {article(me?.role)} {me?.role} here.</p>
      </div>

      <section aria-label="Projects">
        <div className="section-head">
          <h2>Projects</h2>
          <p>Served by the app's own route, guarded by the organization's roles.</p>
        </div>
        <div className="list">
          {projects.length === 0 && <div className="empty">No projects yet.</div>}
          {projects.map((project) => (
            <div className="list-row" key={project.id}>
              <div className="grow">
                <div className="title">{project.name}</div>
                <div className="sub">Created by {project.createdByName} on {new Date(project.createdAt).toLocaleDateString()}</div>
              </div>
            </div>
          ))}
        </div>
        {manages && (
          <form onSubmit={createProject} className="row">
            <label>New project<input name="name" placeholder="Website" required maxLength={100} /></label>
            <button className="primary">Create project</button>
          </form>
        )}
      </section>

      <section aria-label="Members">
        <div className="section-head">
          <h2>Members</h2>
        </div>
        <div className="list">
          {org.members.map((member) => (
            <div className="list-row" key={member.id}>
              <div className="grow">
                <div className="title">{member.user.name}</div>
                <div className="sub">{member.user.email}</div>
              </div>
              <span className="badge">{member.role}</span>
            </div>
          ))}
          {pending.map((invitation) => (
            <div className="list-row" key={invitation.id}>
              <div className="grow">
                <div className="title">{invitation.email}</div>
                <div className="sub">Invited as {invitation.role}</div>
              </div>
              {manages && <button className="danger-ghost" onClick={() => cancel(invitation.id)}>Cancel invite</button>}
            </div>
          ))}
        </div>
        {manages && (
          <form onSubmit={invite} className="row">
            <label>Invite by email<input name="email" type="email" required /></label>
            <label style={{ flex: "0 0 120px" }}>
              Role
              <select name="role" defaultValue="member">
                <option value="member">Member</option>
                <option value="admin">Admin</option>
              </select>
            </label>
            <button className="secondary">Invite</button>
          </form>
        )}
      </section>
      {error && <p className="error" role="alert">{error}</p>}
    </main>
  );
}

function article(role = "") {
  return /^[aeiou]/.test(role) ? "an" : "a";
}
