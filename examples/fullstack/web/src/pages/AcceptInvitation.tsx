import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router";
import { authClient, describeError } from "../auth-client";

type Invitation = { organizationId: string; organizationName: string; inviterEmail: string; role: string };

/** Where the invitation email links to. Only the invited email can accept. */
export function AcceptInvitation() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const [invitation, setInvitation] = useState<Invitation | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    authClient.organization.getInvitation({ query: { id } }).then(({ data, error }) => {
      if (error) setError(describeError(error));
      else setInvitation(data as Invitation);
    });
  }, [id]);

  async function accept() {
    const { error } = await authClient.organization.acceptInvitation({ invitationId: id });
    if (error) return setError(describeError(error));
    navigate(`/orgs/${invitation!.organizationId}`);
  }

  async function reject() {
    const { error } = await authClient.organization.rejectInvitation({ invitationId: id });
    if (error) return setError(describeError(error));
    navigate("/orgs");
  }

  return (
    <main className="page">
      <div className="page-head">
        <h1>{invitation ? `Join ${invitation.organizationName}` : "Invitation"}</h1>
        {invitation && (
          <p className="lead">{invitation.inviterEmail} invited you to join as {invitation.role}.</p>
        )}
      </div>
      {invitation && (
        <div className="row">
          <button className="primary" onClick={accept}>Accept invitation</button>
          <button className="ghost" onClick={reject}>Decline</button>
        </div>
      )}
      {error && <p className="error" role="alert">{error}</p>}
    </main>
  );
}
