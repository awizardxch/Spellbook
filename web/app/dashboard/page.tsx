import { cookies } from "next/headers";
import { SESSION_COOKIE, readSession } from "@/lib/auth";
import LoginGate from "./login-gate";
import DashboardApp from "./dashboard-app";

export const dynamic = "force-dynamic";

/**
 * /dashboard — server gate. A valid session cookie (agent challenge-sign
 * or human viewer token) renders the read-only dashboard; otherwise the
 * real login gate renders. /api/holdings enforces the same session.
 */
export default function DashboardPage() {
  const session = readSession(cookies().get(SESSION_COOKIE)?.value);
  if (!session) return <LoginGate />;
  return <DashboardApp role={session.role} />;
}
