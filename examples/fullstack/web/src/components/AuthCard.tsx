import type { ReactNode } from "react";

/** The centred column the signed-out screens share. */
export function AuthCard({ title, lead, children }: { title: string; lead?: ReactNode; children: ReactNode }) {
  return (
    <main className="auth-page">
      <div className="auth-card">
        <span className="brand">Acme</span>
        <div className="page-head">
          <h1>{title}</h1>
          {lead && <p className="lead">{lead}</p>}
        </div>
        {children}
      </div>
    </main>
  );
}
