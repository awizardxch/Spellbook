import { NextResponse } from "next/server";
import {
  SESSION_COOKIE,
  SESSION_MAX_AGE,
  mintSession,
  verifyChallengeSignature,
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
 * POST /api/auth/verify {challenge, signature} — verify the agent's
 * Ed25519 signature over a server-issued challenge and establish a
 * read-only session.
 */
export async function POST(req: Request): Promise<NextResponse> {
  let body: { challenge?: unknown; signature?: unknown };
  try {
    body = (await req.json()) as { challenge?: unknown; signature?: unknown };
  } catch {
    return NextResponse.json({ error: "bad request" }, { status: 400 });
  }
  const { challenge, signature } = body;
  if (typeof challenge !== "string" || typeof signature !== "string") {
    return NextResponse.json({ error: "bad request" }, { status: 400 });
  }
  if (!verifyChallengeSignature(challenge, signature)) {
    return NextResponse.json(
      { error: "invalid challenge or signature" },
      { status: 401 }
    );
  }
  const session = mintSession("agent");
  if (!session) {
    return NextResponse.json(
      { error: "sessions are not configured on this deployment" },
      { status: 503 }
    );
  }
  const res = NextResponse.json({ ok: true, role: "agent" });
  res.headers.set("Set-Cookie", sessionCookie(session));
  return res;
}
