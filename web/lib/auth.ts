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
 *
 * Mainnet and testnet derive DIFFERENT keys (SPEC §2/P9), so mainnet
 * watch addresses are bound separately: `evm_mainnet`, `solana_mainnet`,
 * `chia_mainnet`. An agent that binds only testnet addresses simply sees
 * no mainnet rows.
 */
export interface AgentAddresses {
  evm?: string[];
  solana?: string[];
  chia?: string[];
  evm_mainnet?: string[];
  solana_mainnet?: string[];
  chia_mainnet?: string[];
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
  const evmFields = ["evm", "evm_mainnet"] as const;
  const solanaFields = ["solana", "solana_mainnet"] as const;
  const chiaFields = ["chia", "chia_mainnet"] as const;
  for (const field of evmFields) {
    if (rec[field] !== undefined) {
      const list = addressList(rec[field]);
      if (!list || !list.every((a) => EVM_RE.test(a))) return null;
      out[field] = dedupe(list, true);
    }
  }
  for (const field of solanaFields) {
    if (rec[field] !== undefined) {
      const list = addressList(rec[field]);
      if (!list || !list.every((a) => SOLANA_RE.test(a))) return null;
      out[field] = dedupe(list, false);
    }
  }
  for (const field of chiaFields) {
    if (rec[field] !== undefined) {
      const list = addressList(rec[field]);
      if (!list || !list.every((a) => CHIA_RE.test(a.toLowerCase())))
        return null;
      out[field] = dedupe(list.map((a) => a.toLowerCase()), false);
    }
  }
  if (
    !out.evm &&
    !out.solana &&
    !out.chia &&
    !out.evm_mainnet &&
    !out.solana_mainnet &&
    !out.chia_mainnet
  )
    return null;
  return out;
}

export interface Session {
  role: Role;
  exp: number;
  /** agent identity (role === "agent" only): self-asserted Ed25519 pubkey */
  pubkey?: string;
  /**
   * Watch addresses: the agent's own (role === "agent"), or the viewed
   * agent's (role === "viewer" via a per-agent viewer token). Absent for
   * the shared operator drill view.
   */
  addresses?: AgentAddresses;
  /**
   * role === "viewer" via a per-agent viewer token: the pubkey of the
   * agent whose wallet is being viewed (for the badge).
   */
  viewingPubkey?: string;
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
  viewingPubkey?: string;
}

export interface AgentIdentity {
  pubkey: string;
  addresses: AgentAddresses;
}

/**
 * Mint a signed session cookie value.
 * - role "agent": identity is the agent's own self-asserted identity
 *   (pubkey + own watch addresses).
 * - role "viewer" with identity: read-only session on THAT AGENT's wallet,
 *   from a per-agent viewer token; the badge shows the viewed pubkey.
 * - role "viewer" without identity: the shared operator drill view.
 * Null when sessions aren't configured.
 */
export function mintSession(role: Role, identity?: AgentIdentity): string | null {
  const secret = sessionSecret();
  if (!secret) return null;
  if (role === "agent" && !identity) return null;
  const now = Date.now();
  const payload: SessionPayload = {
    v: 1,
    role,
    iat: now,
    exp: now + SESSION_MAX_AGE * 1000,
  };
  if (identity) {
    payload.addresses = identity.addresses;
    if (role === "agent") payload.pubkey = identity.pubkey.toLowerCase();
    else payload.viewingPubkey = identity.pubkey.toLowerCase();
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
    if (payload.role === "viewer" && payload.viewingPubkey !== undefined) {
      // Per-agent viewer token session: bound to the viewed agent's wallet.
      if (
        typeof payload.viewingPubkey !== "string" ||
        !/^[0-9a-f]{64}$/.test(payload.viewingPubkey)
      )
        return null;
      const addresses = parseAgentAddresses(payload.addresses);
      if (!addresses) return null;
      session.viewingPubkey = payload.viewingPubkey;
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
  // Per-agent viewer tokens work whenever sessions are configured; the
  // shared operator token additionally needs SPELLBOOK_VIEWER_TOKEN.
  return {
    agent: sessionSecret() !== null,
    viewer: sessionSecret() !== null,
  };
}

/* ---------------- per-agent viewer tokens ---------------- */

/**
 * A per-agent viewer token is a signed bearer credential an agent hands to
 * their human: pasting it into the dashboard's viewer field opens a
 * read-only session on THAT AGENT's wallet (not the operator drill view).
 * Verified by HMAC with the session secret — no database, no expiry.
 * Revocation is break-glass: rotate SPELLBOOK_SESSION_SECRET, which
 * invalidates every session and viewer token on the deployment.
 */
interface AgentViewerTokenPayload {
  v: number;
  kind: "agent-viewer";
  pubkey: string;
  addresses: AgentAddresses;
  iat: number;
}

/** Mint a viewer token for the given agent identity. */
export function mintAgentViewerToken(
  pubkey: string,
  addresses: AgentAddresses
): string | null {
  const secret = sessionSecret();
  if (!secret) return null;
  const clean = pubkey.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(clean)) return null;
  const parsed = parseAgentAddresses(addresses);
  if (!parsed) return null;
  const payload: AgentViewerTokenPayload = {
    v: 2,
    kind: "agent-viewer",
    pubkey: clean,
    addresses: parsed,
    iat: Date.now(),
  };
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString(
    "base64url"
  );
  return `sbv2.${body}.${hmacHex(secret, body)}`;
}

/** Verify a per-agent viewer token. Returns the viewed identity or null. */
export function readAgentViewerToken(
  token: string | undefined
): AgentIdentity | null {
  const secret = sessionSecret();
  if (!secret || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== "sbv2") return null;
  const body = parts[1];
  const sig = parts[2];
  if (!safeEqualHex(sig.toLowerCase(), hmacHex(secret, body))) return null;
  try {
    const payload = JSON.parse(
      Buffer.from(body, "base64url").toString("utf8")
    ) as AgentViewerTokenPayload;
    if (payload.v !== 2 || payload.kind !== "agent-viewer") return null;
    if (
      typeof payload.pubkey !== "string" ||
      !/^[0-9a-f]{64}$/.test(payload.pubkey)
    )
      return null;
    const addresses = parseAgentAddresses(payload.addresses);
    if (!addresses) return null;
    return { pubkey: payload.pubkey, addresses };
  } catch {
    return null;
  }
}
