import { NextResponse } from "next/server";
import {
  SESSION_COOKIE,
  SESSION_MAX_AGE,
  mintSession,
  readAgentViewerToken,
  viewerTokenValid,
} from "@/lib/auth";

export const dynamic = "force-dynamic";

function sessionCookie(value: string): string {
  const secure =
    process.env.NODE_ENV === "production" ? "; Secure" : "";
  return (
    `${SESSION_COOKIE}=${value}; Path=/; Max-Age=${SESSION_MAX_AGE}; ` +
    `HttpOnly; SameSite=Lax${secure}`
  );
}

/**
 * POST /api/auth/viewer {token} — human read-only viewer login.
 * Two token kinds are accepted:
 * 1. The shared SPELLBOOK_VIEWER_TOKEN (timing-safe compare) — opens the
 *    operator drill view.
 * 2. A per-agent viewer token minted by an agent (signed, verified by
 *    HMAC) — opens a read-only view of THAT AGENT's wallet.
 * Tokens are never logged. Establishes a read-only session on success.
 */
export async function POST(req: Request): Promise<NextResponse> {
  let body: { token?: unknown };
  try {
    body = (await req.json()) as { token?: unknown };
  } catch {
    return NextResponse.json({ error: "bad request" }, { status: 400 });
  }
  if (typeof body.token !== "string" || body.token.length === 0) {
    return NextResponse.json({ error: "bad request" }, { status: 400 });
  }
  const token = body.token;

  // 1. Shared operator drill view.
  if (process.env.SPELLBOOK_VIEWER_TOKEN && viewerTokenValid(token)) {
    const session = mintSession("viewer");
    if (!session) {
      return NextResponse.json(
        { error: "sessions are not configured on this deployment" },
        { status: 503 }
      );
    }
    const res = NextResponse.json({
      ok: true,
      role: "viewer",
      viewing: "operator",
    });
    res.headers.set("Set-Cookie", sessionCookie(session));
    return res;
  }

  // 2. Per-agent viewer token — the viewed agent's own wallet.
  const agentView = readAgentViewerToken(token);
  if (agentView) {
    const session = mintSession("viewer", agentView);
    if (!session) {
      return NextResponse.json(
        { error: "sessions are not configured on this deployment" },
        { status: 503 }
      );
    }
    const res = NextResponse.json({
      ok: true,
      role: "viewer",
      viewing: agentView.pubkey,
    });
    res.headers.set("Set-Cookie", sessionCookie(session));
    return res;
  }

  return NextResponse.json({ error: "wrong token" }, { status: 401 });
}
