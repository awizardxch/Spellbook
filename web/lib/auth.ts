// Server-only authentication for /dashboard.
//
// Two real login paths, no demo simulation:
//
//   Path A — agent challenge-response. GET /api/auth/challenge mints a
//   short-lived challenge bound with an HMAC (no server-side nonce store
//   needed, so it works on stateless serverless). The agent signs the full
//   challenge string with its Ed25519 identity key and POSTs
//   {challenge, signature, pubkey, addresses} to /api/auth/verify. The
//   server checks the HMAC (proves it issued the challenge and it hasn't
//   expired), enforces best-effort single-use, and verifies the Ed25519
//   signature against the pubkey the agent presented (self-asserted
//   identity — any agent that installed the Spellbook can log in; no
//   server-side key allowlist). The session carries the agent's own
//   watch addresses, so each agent sees their OWN wallet — never the
//   operator's. The signature proves key ownership; the addresses are
//   self-asserted public data (holdings are public chain reads).
//
//   Path B — human viewer token. POST /api/auth/viewer {token} compares
//   (timing-safe) against SPELLBOOK_VIEWER_TOKEN. Viewer sessions see the
//   operator's configured drill addresses (lib/chains.ts).
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

/** Maximum watch addresses per chain an agent may bind at login. */
export const MAX_WATCH_ADDRESSES = 100;

/**
 * Watch addresses an agent asserts at login, in the agent's own
 * derivation order (e.g. the label order from `spellbook addresses`).
 * At least one address across all chains is required.
 */
export interface AgentAddresses {
  evm?: string[];
  solana?: string[];
  chia?: string[];
}

const EVM_RE = /^0x[0-9a-fA-F]{40}$/;
const SOLANA_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const CHIA_RE = /^(txch1|xch1)[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+$/;

/** Normalize a single chain's input: one address string or an array of
 * them. Returns the trimmed list, or null when empty/oversized. */
function addressList(value: unknown): string[] | null {
  const items = Array.isArray(value) ? value : [value];
  if (items.length === 0 || items.length > MAX_WATCH_ADDRESSES) return null;
  const out: string[] = [];
  for (const item of items) {
    if (typeof item !== "string") return null;
    const t = item.trim();
    if (!t) return null;
    out.push(t);
  }
  return out;
}

/** Drop duplicates (case-insensitive for EVM hex), keeping first-seen
 * order — the agent's derivation order. */
function dedupe(list: string[], foldCase: boolean): string[] {
  const seen = new Set<string>();
  return list.filter((s) => {
    const k = foldCase ? s.toLowerCase() : s;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/**
 * Validate agent-supplied watch addresses. Returns the normalized set,
 * or null when missing/invalid. Holdings are public chain data, so these
 * are self-asserted — the checks here are format-only.
 */
export function parseAgentAddresses(input: unknown): AgentAddresses | null {
  if (typeof input !== "object" || input === null) return null;
  const rec = input as Record<string, unknown>;
  const out: AgentAddresses = {};
  if (rec.evm !== undefined) {
    const list = addressList(rec.evm);
    if (!list || !list.every((a) => EVM_RE.test(a))) return null;
    out.evm = dedupe(list, true);
  }
  if (rec.solana !== undefined) {
    const list = addressList(rec.solana);
    if (!list || !list.every((a) => SOLANA_RE.test(a))) return null;
    out.solana = dedupe(list, false);
  }
  if (rec.chia !== undefined) {
    const list = addressList(rec.chia);
    if (!list || !list.every((a) => CHIA_RE.test(a.toLowerCase())))
      return null;
    out.chia = dedupe(list.map((a) => a.toLowerCase()), false);
  }
  if (!out.evm && !out.solana && !out.chia) return null;
  return out;
}

export interface Session {
  role: Role;
  exp: number;
  /** agent identity (role === "agent" only): self-asserted Ed25519 pubkey */
  pubkey?: string;
  /** agent's own watch addresses (role === "agent" only) */
  addresses?: AgentAddresses;
}

/* ---------------- configuration ---------------- */

function sessionSecret(): Buffer | null {
  const s = process.env.SPELLBOOK_SESSION_SECRET;
  return s ? Buffer.from(s, "utf8") : null;
}

/* ---------------- challenges (Path A) ---------------- */

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

/** Mint a server-bound challenge. Null when sessions aren't configured. */
export function mintChallenge(): Challenge | null {
  const secret = sessionSecret();
  if (!secret) return null;
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
 * Verify a {challenge, signature, pubkey} triple. The signature must be a
 * 128-hex-char Ed25519 signature over the exact challenge string, made by
 * the presented 64-hex-char pubkey (self-asserted agent identity — any
 * agent that installed the Spellbook can log in).
 */
export function verifyChallengeSignature(
  challenge: string,
  signatureHex: string,
  pubkeyHex: string
): boolean {
  const secret = sessionSecret();
  if (!secret) return false;
  if (typeof challenge !== "string" || challenge.length > 512) return false;
  if (!/^[0-9a-fA-F]{128}$/.test(signatureHex)) return false;
  if (!/^[0-9a-fA-F]{64}$/.test(pubkeyHex)) return false;

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

  // Verify the signature against the agent-presented public key.
  let ok = false;
  try {
    const key = createPublicKey({
      key: spkiDer(Buffer.from(pubkeyHex, "hex")),
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
  pubkey?: string;
  addresses?: AgentAddresses;
}

export interface AgentIdentity {
  pubkey: string;
  addresses: AgentAddresses;
}

/**
 * Mint a signed session cookie value. Agent sessions carry the agent's
 * self-asserted identity (pubkey + own watch addresses). Null when
 * sessions aren't configured.
 */
export function mintSession(role: Role, agent?: AgentIdentity): string | null {
  const secret = sessionSecret();
  if (!secret) return null;
  if (role === "agent" && !agent) return null;
  const now = Date.now();
  const payload: SessionPayload = {
    v: 1,
    role,
    iat: now,
    exp: now + SESSION_MAX_AGE * 1000,
  };
  if (agent) {
    payload.pubkey = agent.pubkey.toLowerCase();
    payload.addresses = agent.addresses;
  }
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
    const session: Session = { role: payload.role, exp: payload.exp };
    if (payload.role === "agent") {
      // Identity was validated at login; re-check shapes defensively.
      if (
        typeof payload.pubkey !== "string" ||
        !/^[0-9a-f]{64}$/.test(payload.pubkey)
      )
        return null;
      const addresses = parseAgentAddresses(payload.addresses);
      if (!addresses) return null;
      session.pubkey = payload.pubkey;
      session.addresses = addresses;
    }
    return session;
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
  // The agent path needs no per-agent server config: any agent that
  // installed the Spellbook logs in with its own key + addresses.
  return {
    agent: sessionSecret() !== null,
    viewer:
      sessionSecret() !== null && !!process.env.SPELLBOOK_VIEWER_TOKEN,
  };
}
