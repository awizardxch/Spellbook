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

/** Maximum labeled wallets one session / viewer token may carry. */
export const MAX_WALLETS = 8;

/**
 * One labeled wallet inside a session or viewer token: a display label
 * plus that wallet's watch addresses. An agent with several wallets
 * (e.g. their Spellbook wallets plus a Bankr wallet) binds one group per
 * wallet; the dashboard renders each group under its label so the human
 * can always tell which wallet a row belongs to.
 */
export interface WalletGroup {
  /** Display label, e.g. "Spellbook" or "Bankr". Agent-asserted. */
  label: string;
  addresses: AgentAddresses;
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

const WALLET_LABEL_RE = /^[A-Za-z0-9][A-Za-z0-9 _-]{0,31}$/;

/**
 * Validate agent-supplied labeled wallets: an array of
 * `{ label, addresses }`. Returns the normalized groups, or null when
 * missing/invalid. Labels are display-only (agent-asserted, like the
 * addresses themselves); the charset keeps them safe to render.
 */
export function parseWalletGroups(input: unknown): WalletGroup[] | null {
  if (!Array.isArray(input) || input.length === 0 || input.length > MAX_WALLETS)
    return null;
  const out: WalletGroup[] = [];
  const seen = new Set<string>();
  for (const item of input) {
    if (typeof item !== "object" || item === null) return null;
    const rec = item as Record<string, unknown>;
    if (typeof rec.label !== "string") return null;
    const label = rec.label.trim();
    if (!WALLET_LABEL_RE.test(label)) return null;
    const key = label.toLowerCase();
    if (seen.has(key)) return null;
    seen.add(key);
    const addresses = parseAgentAddresses(rec.addresses);
    if (!addresses) return null;
    out.push({ label, addresses });
  }
  return out;
}

/**
 * Flatten labeled wallets back to one AgentAddresses (union of every
 * group's addresses per chain, deduped, group order kept). Used for
 * backward-compatible echoes of the old flat shape.
 */
export function flattenWalletGroups(wallets: WalletGroup[]): AgentAddresses {
  const out: AgentAddresses = {};
  const fields = [
    "evm",
    "solana",
    "chia",
    "evm_mainnet",
    "solana_mainnet",
    "chia_mainnet",
  ] as const;
  for (const w of wallets) {
    for (const f of fields) {
      const list = w.addresses[f];
      if (!list) continue;
      const foldCase = f === "evm" || f === "evm_mainnet";
      const cur = out[f] ?? [];
      for (const a of list) {
        const k = foldCase ? a.toLowerCase() : a;
        if (!cur.some((c) => (foldCase ? c.toLowerCase() : c) === k))
          cur.push(a);
      }
      out[f] = cur;
    }
  }
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
   * the shared operator drill view. Legacy flat shape — new code should
   * prefer `wallets`.
   */
  addresses?: AgentAddresses;
  /**
   * Labeled wallets bound to this session, in the order the agent gave
   * them. Always normalized (legacy flat logins become one group labeled
   * "Wallet"); absent only for the shared operator drill view.
   */
  wallets?: WalletGroup[];
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
  wallets?: WalletGroup[];
  viewingPubkey?: string;
}

export interface AgentIdentity {
  pubkey: string;
  addresses: AgentAddresses;
  /** Labeled wallets; when absent the flat `addresses` are one wallet. */
  wallets?: WalletGroup[];
}

/**
 * The labeled wallets a session may see, in order. Legacy flat sessions
 * normalize to a single group labeled "Wallet". Empty for the shared
 * operator drill view (callers fall back to the drill addresses).
 */
export function sessionWallets(session: Session): WalletGroup[] {
  if (session.wallets && session.wallets.length > 0) return session.wallets;
  if (session.addresses) return [{ label: "Wallet", addresses: session.addresses }];
  return [];
}

/**
 * Mint a signed session cookie value.
 * - role "agent": identity is the agent's own self-asserted identity
 *   (pubkey + own watch addresses, optionally as labeled wallets).
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
    if (identity.wallets) payload.wallets = identity.wallets;
    if (role === "agent") payload.pubkey = identity.pubkey.toLowerCase();
    else payload.viewingPubkey = identity.pubkey.toLowerCase();
  }
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString(
    "base64url"
  );
  return `${body}.${hmacHex(secret, body)}`;
}

/** Normalize a session payload's wallets (v1 payloads carry an optional
 * `wallets` array; older ones carry only the flat `addresses`). */
function payloadWallets(payload: SessionPayload): WalletGroup[] | null {
  if (payload.wallets !== undefined) {
    const w = parseWalletGroups(payload.wallets);
    if (!w) return null;
    return w;
  }
  const a = parseAgentAddresses(payload.addresses);
  if (!a) return null;
  return [{ label: "Wallet", addresses: a }];
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
      const wallets = payloadWallets(payload);
      if (!wallets) return null;
      session.pubkey = payload.pubkey;
      session.addresses = flattenWalletGroups(wallets);
      session.wallets = wallets;
    }
    if (payload.role === "viewer" && payload.viewingPubkey !== undefined) {
      // Per-agent viewer token session: bound to the viewed agent's wallet.
      if (
        typeof payload.viewingPubkey !== "string" ||
        !/^[0-9a-f]{64}$/.test(payload.viewingPubkey)
      )
        return null;
      const wallets = payloadWallets(payload);
      if (!wallets) return null;
      session.viewingPubkey = payload.viewingPubkey;
      session.addresses = flattenWalletGroups(wallets);
      session.wallets = wallets;
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
 * read-only session on THAT AGENT's wallets (not the operator drill view).
 * Verified by HMAC with the session secret — no database, no expiry.
 * Revocation is break-glass: rotate SPELLBOOK_SESSION_SECRET, which
 * invalidates every session and viewer token on the deployment.
 *
 * v3 carries the agent's labeled wallets; v2 carried one flat address set
 * (read back as a single group labeled "Wallet").
 */
interface AgentViewerTokenPayload {
  v: number;
  kind: "agent-viewer";
  pubkey: string;
  wallets: WalletGroup[];
  iat: number;
}

/** Mint a viewer token for the given agent identity. */
export function mintAgentViewerToken(
  pubkey: string,
  wallets: WalletGroup[]
): string | null {
  const secret = sessionSecret();
  if (!secret) return null;
  const clean = pubkey.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(clean)) return null;
  const parsed = parseWalletGroups(wallets);
  if (!parsed) return null;
  const payload: AgentViewerTokenPayload = {
    v: 3,
    kind: "agent-viewer",
    pubkey: clean,
    wallets: parsed,
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
    const raw = JSON.parse(
      Buffer.from(body, "base64url").toString("utf8")
    ) as {
      v: number;
      kind: string;
      pubkey: string;
      wallets?: unknown;
      addresses?: unknown;
    };
    if (raw.kind !== "agent-viewer") return null;
    if (
      typeof raw.pubkey !== "string" ||
      !/^[0-9a-f]{64}$/.test(raw.pubkey)
    )
      return null;
    let wallets: WalletGroup[] | null = null;
    if (raw.v === 3) {
      wallets = parseWalletGroups(raw.wallets);
    } else if (raw.v === 2) {
      // Legacy flat token: one unlabeled wallet.
      const addresses = parseAgentAddresses(raw.addresses);
      if (addresses) wallets = [{ label: "Wallet", addresses }];
    }
    if (!wallets) return null;
    return {
      pubkey: raw.pubkey,
      addresses: flattenWalletGroups(wallets),
      wallets,
    };
  } catch {
    return null;
  }
}
