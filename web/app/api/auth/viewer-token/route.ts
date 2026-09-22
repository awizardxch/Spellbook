import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import {
  SESSION_COOKIE,
  mintAgentViewerToken,
  readSession,
} from "@/lib/auth";

export const dynamic = "force-dynamic";

/**
 * POST /api/auth/viewer-token — mint (or rotate) the calling agent's
 * viewer token for their human. Requires a valid agent session. Returns
 * { ok: true, viewerToken }.
 *
 * The agent shows the token to their human once; the human pastes it into
 * the dashboard's viewer field for a read-only view of this agent's
 * wallet. Bearer credential — treat it like a password.
 */
export async function POST(): Promise<NextResponse> {
  const session = readSession(cookies().get(SESSION_COOKIE)?.value);
  if (
    !session ||
    session.role !== "agent" ||
    !session.pubkey ||
    !session.addresses
  ) {
    return NextResponse.json(
      { error: "agent login required" },
      { status: 401 }
    );
  }
  const viewerToken = mintAgentViewerToken(session.pubkey, session.addresses);
  if (!viewerToken) {
    return NextResponse.json(
      { error: "sessions are not configured on this deployment" },
      { status: 503 }
    );
  }
  return NextResponse.json({ ok: true, viewerToken });
}
