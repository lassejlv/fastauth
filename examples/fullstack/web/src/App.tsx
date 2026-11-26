import { Navigate, Route, Routes, useLocation } from "react-router";
import { authClient } from "./auth-client";
import { Layout } from "./components/Layout";
import { AcceptInvitation } from "./pages/AcceptInvitation";
import { Admin } from "./pages/Admin";
import { ApiKeys } from "./pages/ApiKeys";
import { CheckEmail } from "./pages/CheckEmail";
import { Home } from "./pages/Home";
import { Organization } from "./pages/Organization";
import { Organizations } from "./pages/Organizations";
import { Security } from "./pages/Security";
import { SignIn } from "./pages/SignIn";
import { SignUp } from "./pages/SignUp";
import { TwoFactor } from "./pages/TwoFactor";

export function App() {
  return (
    <Routes>
      <Route path="/sign-in" element={<SignIn />} />
      <Route path="/sign-up" element={<SignUp />} />
      <Route path="/check-email" element={<CheckEmail />} />
      <Route path="/two-factor" element={<TwoFactor />} />
      <Route element={<RequireSession />}>
        <Route path="/" element={<Home />} />
        <Route path="/security" element={<Security />} />
        <Route path="/orgs" element={<Organizations />} />
        <Route path="/orgs/:id" element={<Organization />} />
        <Route path="/accept-invitation/:id" element={<AcceptInvitation />} />
        <Route path="/api-keys" element={<ApiKeys />} />
        <Route path="/admin" element={<Admin />} />
      </Route>
    </Routes>
  );
}

/** Signed-in screens. Anyone else goes to sign-in and comes back afterwards. */
function RequireSession() {
  const { data: session, isPending } = authClient.useSession();
  const location = useLocation();
  if (isPending) return null;
  if (!session) {
    if (new URLSearchParams(location.search).has("twoFactorRedirect")) {
      return <Navigate to="/two-factor" replace />;
    }
    const next = location.pathname + location.search;
    return <Navigate to={`/sign-in?next=${encodeURIComponent(next)}`} replace />;
  }
  return <Layout session={session} />;
}
