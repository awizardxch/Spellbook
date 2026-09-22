import { NextResponse } from "next/server";
import { mintChallenge } from "@/lib/auth";

export const dynamic = "force-dynamic";

/**
 * GET /api/auth/challenge — mint a short-lived login challenge for the
 * agent path. The agent signs the returned `challenge` string with its
 * Ed25519 identity key and POSTs {challenge, signature} to /api/auth/verify.
 */
export async function GET(): Promise<NextResponse> {
  const c = mintChallenge();
  if (!c) {
    return NextResponse.json(
      { error: "agent login is not configured on this deployment" },
      { status: 503 }
    );
  }
  return NextResponse.json(c);
}
