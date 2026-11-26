import { Link, useSearchParams } from "react-router";
import { authClient } from "../auth-client";

export function Home() {
  const { data: session } = authClient.useSession();
  const { data: orgs } = authClient.useListOrganizations();
  const [params] = useSearchParams();
  if (!session) return null;
  const twoFactor = (session.user as { twoFactorEnabled?: boolean }).twoFactorEnabled;

  return (
    <main className="page">
      <div className="page-head">
        <h1>Welcome, {session.user.name}</h1>
        <p className="lead">
          {params.has("verified") ? "Your email is verified and you're signed in." : `Signed in as ${session.user.email}.`}
        </p>
      </div>
      <div className="list">
        <Link className="list-row" to="/security">
          <div className="grow">
            <div className="title">Two-factor authentication</div>
            <div className="sub">{twoFactor ? "On" : "Off. Turn it on to protect your account."}</div>
          </div>
        </Link>
        <Link className="list-row" to="/orgs">
          <div className="grow">
            <div className="title">Organizations</div>
            <div className="sub">{orgs?.length ? `${orgs.length} ${orgs.length === 1 ? "organization" : "organizations"}` : "None yet"}</div>
          </div>
        </Link>
        <Link className="list-row" to="/api-keys">
          <div className="grow">
            <div className="title">API keys</div>
            <div className="sub">Call the API from scripts as yourself</div>
          </div>
        </Link>
      </div>
    </main>
  );
}
