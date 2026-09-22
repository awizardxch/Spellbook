import { NextResponse } from "next/server";
import {
  SESSION_COOKIE,
  SESSION_MAX_AGE,
  mintSession,
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
 * The token is compared timing-safe against SPELLBOOK_VIEWER_TOKEN and
 * never logged. Establishes a read-only session on success.
 */
export async function POST(req: Request): Promise<NextResponse> {
  let body: { token?: unknown };
  try {
    body = (await req.json()) as { token?: unknown };
  } catch {
    return NextResponse.json({ error: "bad request" }, { status: 400 });
  }
  if (typeof body.token !== "string") {
    return NextResponse.json({ error: "bad request" }, { status: 400 });
  }
  if (!process.env.SPELLBOOK_VIEWER_TOKEN) {
    return NextResponse.json(
      { error: "viewer login is not configured on this deployment" },
      { status: 503 }
    );
  }
  if (!viewerTokenValid(body.token)) {
    return NextResponse.json({ error: "wrong token" }, { status: 401 });
  }
  const session = mintSession("viewer");
  if (!session) {
    return NextResponse.json(
      { error: "sessions are not configured on this deployment" },
      { status: 503 }
    );
  }
  const res = NextResponse.json({ ok: true, role: "viewer" });
  res.headers.set("Set-Cookie", sessionCookie(session));
  return res;
}
