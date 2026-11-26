import { NavLink, Outlet, useNavigate } from "react-router";
import { authClient, type Session } from "../auth-client";

export function Layout({ session }: { session: Session }) {
  const navigate = useNavigate();
  const isAdmin = (session.user as { role?: string | null }).role?.split(",").includes("admin");

  async function signOut() {
    await authClient.signOut();
    navigate("/sign-in");
  }

  return (
    <div className="shell">
      <header className="topbar">
        <NavLink to="/" className="brand">Acme</NavLink>
        <nav className="nav">
          <NavLink to="/" end>Home</NavLink>
          <NavLink to="/orgs">Organizations</NavLink>
          <NavLink to="/api-keys">API keys</NavLink>
          <NavLink to="/security">Security</NavLink>
          {isAdmin && <NavLink to="/admin">Admin</NavLink>}
        </nav>
        <div className="account">
          <span>{session.user.email}</span>
          <button className="ghost" onClick={signOut}>Sign out</button>
        </div>
      </header>
      <Outlet />
    </div>
  );
}
