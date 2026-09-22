import { NextResponse } from "next/server";
import {
  SESSION_COOKIE,
  SESSION_MAX_AGE,
  mintSession,
  parseAgentAddresses,
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
 * POST /api/auth/verify {challenge, signature, pubkey, addresses} —
 * verify the agent's Ed25519 signature over a server-issued challenge
 * against the pubkey the agent presented, and establish a read-only
 * session bound to the agent's OWN watch addresses. Any agent that
 * installed the Spellbook can log in; each agent sees their own wallet.
 */
export async function POST(req: Request): Promise<NextResponse> {
  let body: {
    challenge?: unknown;
    signature?: unknown;
    pubkey?: unknown;
    addresses?: unknown;
  };
  try {
    body = (await req.json()) as {
      challenge?: unknown;
      signature?: unknown;
      pubkey?: unknown;
      addresses?: unknown;
    };
  } catch {
    return NextResponse.json({ error: "bad request" }, { status: 400 });
  }
  const { challenge, signature, pubkey, addresses } = body;
  if (
    typeof challenge !== "string" ||
    typeof signature !== "string" ||
    typeof pubkey !== "string"
  ) {
    return NextResponse.json({ error: "bad request" }, { status: 400 });
  }
  const parsed = parseAgentAddresses(addresses);
  if (!parsed) {
    return NextResponse.json(
      { error: "at least one valid watch address is required" },
      { status: 400 }
    );
  }
  if (!verifyChallengeSignature(challenge, signature, pubkey)) {
    return NextResponse.json(
      { error: "invalid challenge, signature, or public key" },
      { status: 401 }
    );
  }
  const session = mintSession("agent", {
    pubkey: pubkey.trim().toLowerCase(),
    addresses: parsed,
  });
  if (!session) {
    return NextResponse.json(
      { error: "sessions are not configured on this deployment" },
      { status: 503 }
    );
  }
  const now = Date.now();
  const res = NextResponse.json({
    ok: true,
    role: "agent",
    pubkey: pubkey.trim().toLowerCase(),
    addresses: parsed,
    expiresAt: now + SESSION_MAX_AGE * 1000,
  });
  res.headers.set("Set-Cookie", sessionCookie(session));
  return res;
}
