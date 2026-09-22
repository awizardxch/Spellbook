// Server-only authentication for /dashboard.
//
// Two real login paths, no demo simulation:
//
//   Path A — agent challenge-response. GET /api/auth/challenge mints a
//   short-lived challenge bound with an HMAC (no server-side nonce store
//   needed, so it works on stateless serverless). The agent signs the full
//   challenge string with its Ed25519 identity key and POSTs
//   {challenge, signature} to /api/auth/verify. The server checks the HMAC
//   (proves it issued the challenge and it hasn't expired), enforces
//   best-effort single-use, and verifies the Ed25519 signature against
//   SPELLBOOK_AGENT_PUBKEY.
//
//   Path B — human viewer token. POST /api/auth/viewer {token} compares
//   (timing-safe) against SPELLBOOK_VIEWER_TOKEN.
//
// Success mints a signed session cookie (HMAC with SPELLBOOK_SESSION_SECRET,
// httpOnly). /dashboard renders the gate or the dashboard based on the
// cookie; /api/holdings requires it.
//
// This module is server-only: it reads secrets. Never import it from a
// client component.

import {
  createHmac,
  createPublicKey,
  randomBytes,
  timingSafeEqual,
  verify,
} from "crypto";

export const SESSION_COOKIE = "spellbook_session";
export const SESSION_MAX_AGE = 12 * 60 * 60; // 12h, seconds
const CHALLENGE_TTL_MS = 5 * 60 * 1000; // 5 minutes

export type Role = "agent" | "viewer";

export interface Session {
  role: Role;
  exp: number;
}

/* ---------------- configuration ---------------- */

function sessionSecret(): Buffer | null {
  const s = process.env.SPELLBOOK_SESSION_SECRET;
  return s ? Buffer.from(s, "utf8") : null;
}

function agentPubkey(): Buffer | null {
  const h = process.env.SPELLBOOK_AGENT_PUBKEY;
  if (!h || !/^[0-9a-fA-F]{64}$/.test(h)) return null;
  return Buffer.from(h, "hex");
}

/** Wrap a raw 32-byte Ed25519 public key in SPKI DER for Node's crypto. */
function spkiDer(raw: Buffer): Buffer {
  return Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
}

function hmacHex(secret: Buffer, data: string): string {
  return createHmac("sha256", secret).update(data, "utf8").digest("hex");
}

function safeEqualHex(a: string, b: string): boolean {
  if (!/^[0-9a-f]{64}$/.test(a) || !/^[0-9a-f]{64}$/.test(b)) return false;
  return timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

/* ---------------- challenges (Path A) ---------------- */

export interface Challenge {
  challenge: string;
  expiresAt: number;
}

// Best-effort single-use: nonce -> expiry. Pruned on every verify.
// (Stateless serverless instances don't share memory, so this is defense
// in depth; the 5-minute expiry is the primary replay bound.)
const seenNonces = new Map<string, number>();

function pruneSeen(): void {
  const now = Date.now();
  seenNonces.forEach((exp, nonce) => {
    if (exp <= now) seenNonces.delete(nonce);
  });
}

interface ChallengePayload {
  v: number;
  nonce: string;
  iat: number;
  exp: number;
}

/** Mint a server-bound challenge. Null when agent login isn't configured. */
export function mintChallenge(): Challenge | null {
  const secret = sessionSecret();
  if (!secret || !agentPubkey()) return null;
  const now = Date.now();
  const payload: ChallengePayload = {
    v: 1,
    nonce: randomBytes(16).toString("hex"),
    iat: now,
    exp: now + CHALLENGE_TTL_MS,
  };
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString(
    "base64url"
  );
  return {
    challenge: `${body}.${hmacHex(secret, body)}`,
    expiresAt: payload.exp,
  };
}

/**
 * Verify a {challenge, signature} pair. The signature must be a 128-hex-char
 * Ed25519 signature over the exact challenge string, from the configured
 * agent public key.
 */
export function verifyChallengeSignature(
  challenge: string,
  signatureHex: string
): boolean {
  const secret = sessionSecret();
  const pubkey = agentPubkey();
  if (!secret || !pubkey) return false;
  if (typeof challenge !== "string" || challenge.length > 512) return false;
  if (!/^[0-9a-fA-F]{128}$/.test(signatureHex)) return false;

  const dot = challenge.lastIndexOf(".");
  if (dot <= 0) return false;
  const body = challenge.slice(0, dot);
  const mac = challenge.slice(dot + 1);
  if (!safeEqualHex(mac.toLowerCase(), hmacHex(secret, body))) return false;

  let payload: ChallengePayload;
  try {
    payload = JSON.parse(
      Buffer.from(body, "base64url").toString("utf8")
    ) as ChallengePayload;
  } catch {
    return false;
  }
  if (
    payload.v !== 1 ||
    typeof payload.nonce !== "string" ||
    typeof payload.exp !== "number" ||
    Date.now() > payload.exp
  ) {
    return false;
  }

  pruneSeen();
  if (seenNonces.has(payload.nonce)) return false; // replay

  let ok = false;
  try {
    const key = createPublicKey({
      key: spkiDer(pubkey),
      format: "der",
      type: "spki",
    });
    ok = verify(
      null,
      Buffer.from(challenge, "utf8"),
      key,
      Buffer.from(signatureHex, "hex")
    );
  } catch {
    return false;
  }
  if (!ok) return false;
  seenNonces.set(payload.nonce, payload.exp);
  return true;
}

/* ---------------- sessions ---------------- */

interface SessionPayload {
  v: number;
  role: Role;
  iat: number;
  exp: number;
}

/** Mint a signed session cookie value. Null when sessions aren't configured. */
export function mintSession(role: Role): string | null {
  const secret = sessionSecret();
  if (!secret) return null;
  const now = Date.now();
  const payload: SessionPayload = {
    v: 1,
    role,
    iat: now,
    exp: now + SESSION_MAX_AGE * 1000,
  };
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString(
    "base64url"
  );
  return `${body}.${hmacHex(secret, body)}`;
}

/** Read and validate a session cookie value. Null = no/invalid session. */
export function readSession(cookieValue: string | undefined): Session | null {
  const secret = sessionSecret();
  if (!secret || !cookieValue) return null;
  const dot = cookieValue.lastIndexOf(".");
  if (dot <= 0) return null;
  const body = cookieValue.slice(0, dot);
  const sig = cookieValue.slice(dot + 1);
  if (!safeEqualHex(sig.toLowerCase(), hmacHex(secret, body))) return null;
  try {
    const payload = JSON.parse(
      Buffer.from(body, "base64url").toString("utf8")
    ) as SessionPayload;
    if (payload.v !== 1) return null;
    if (payload.role !== "agent" && payload.role !== "viewer") return null;
    if (typeof payload.exp !== "number" || Date.now() > payload.exp)
      return null;
    return { role: payload.role, exp: payload.exp };
  } catch {
    return null;
  }
}

/* ---------------- viewer token (Path B) ---------------- */

/** Timing-safe compare of the submitted viewer token. */
export function viewerTokenValid(token: string): boolean {
  const expected = process.env.SPELLBOOK_VIEWER_TOKEN;
  if (!expected || typeof token !== "string" || token.length === 0)
    return false;
  const a = Buffer.from(token, "utf8");
  const b = Buffer.from(expected, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

/** True when at least one login path is fully configured. */
export function authConfigured(): { agent: boolean; viewer: boolean } {
  return {
    agent: sessionSecret() !== null && agentPubkey() !== null,
    viewer:
      sessionSecret() !== null && !!process.env.SPELLBOOK_VIEWER_TOKEN,
  };
}
