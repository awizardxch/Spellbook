// Server-only read-only holdings proxy for /dashboard.
//
// GET fans out to public testnet RPCs + the operator's Chia relay and
// returns normalized balances. The relay bearer token (SPELLBOOK_RELAY_TOKEN)
// never leaves the server. Strictly read-only: no broadcast, no signing,
// no write endpoints are ever called from here.
//
// Multi-address: each chain carries the session's bound watch addresses
// (up to 100 per chain, in the agent's derivation order). ?depth=N caps
// how many are queried (default: all bound). Every chain reports its
// per-address balances plus the exact total across the addresses that
// loaded.

import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import {
  CHAINS,
  chiaAddressToPuzzleHash,
  type ChainConfig,
} from "@/lib/chains";
import {
  SESSION_COOKIE,
  readSession,
  type AgentAddresses,
  type Session,
} from "@/lib/auth";

export const dynamic = "force-dynamic";

const TIMEOUT_MS = 8000;
/** Hard cap on ?depth= — matches MAX_WATCH_ADDRESSES in lib/auth. */
const MAX_DEPTH = 100;

export interface AddressHolding {
  address: string;
  /** human-readable balance in `unit`, or null when this address failed */
  balance: string | null;
  error?: string;
}

export interface ChainHolding {
  id: string;
  label: string;
  detail: string;
  unit: string;
  /** how many watch addresses are bound for this chain (pre-depth) */
  watchAddresses: number;
  addresses: AddressHolding[];
  /** exact sum of the balances that loaded; null when none loaded */
  total: string | null;
}

function toError(e: unknown): string {
  if (e instanceof Error) {
    // AbortError from our timeout → friendlier label
    return e.name === "AbortError" ? "request timed out" : e.message;
  }
  return "unavailable";
}

async function fetchJson(
  url: string,
  init: RequestInit,
  timeoutMs: number = TIMEOUT_MS
): Promise<unknown> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...init, signal: ctrl.signal });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return (await res.json()) as unknown;
  } finally {
    clearTimeout(timer);
  }
}

/** Hex (0x…) → decimal string, manual conversion (no BigInt: the repo
 * tsconfig targets below ES2020, so BigInt literals are unavailable). */
function hexToDecimalString(hex: string): string {
  const clean = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (!/^[0-9a-fA-F]+$/.test(clean)) throw new Error("bad hex value");
  const digits: number[] = [0];
  for (const ch of clean) {
    let carry = parseInt(ch, 16);
    for (let i = digits.length - 1; i >= 0; i--) {
      const cur = digits[i] * 16 + carry;
      digits[i] = cur % 10;
      carry = Math.floor(cur / 10);
    }
    while (carry > 0) {
      digits.unshift(carry % 10);
      carry = Math.floor(carry / 10);
    }
  }
  return digits.join("").replace(/^0+(?=\d)/, "");
}

/** Decimal integer string → human units, trimming trailing zeros. */
function formatDecimalUnits(decStr: string, decimals: number): string {
  const padded = decStr.padStart(decimals + 1, "0");
  const whole = padded.slice(0, padded.length - decimals);
  const frac = padded.slice(padded.length - decimals).replace(/0+$/, "");
  return frac ? `${whole}.${frac}` : whole;
}

/** Exact addition of two human-readable decimal strings (no floats). */
function addDecimalStrings(a: string, b: string): string {
  const pa = a.split(".");
  const pb = b.split(".");
  const fracLen = Math.max(pa[1]?.length ?? 0, pb[1]?.length ?? 0);
  const norm = (p: string[]): string =>
    (p[0] + (p[1] ?? "").padEnd(fracLen, "0")).replace(/^0+(?=\d)/, "");
  const x = norm(pa).split("").reverse();
  const y = norm(pb).split("").reverse();
  let carry = 0;
  let out = "";
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const s =
      (i < x.length ? Number(x[i]) : 0) +
      (i < y.length ? Number(y[i]) : 0) +
      carry;
    out = String(s % 10) + out;
    carry = Math.floor(s / 10);
  }
  if (carry) out = String(carry) + out;
  if (fracLen === 0) return out;
  const padded = out.padStart(fracLen + 1, "0");
  const whole = padded.slice(0, padded.length - fracLen);
  const frac = padded.slice(padded.length - fracLen).replace(/0+$/, "");
  return frac ? `${whole}.${frac}` : whole;
}

/** Exact total across the addresses that loaded; null when none did. */
function totalOf(holdings: AddressHolding[]): string | null {
  let total: string | null = null;
  for (const h of holdings) {
    if (h.balance === null) continue;
    total = total === null ? h.balance : addDecimalStrings(total, h.balance);
  }
  return total;
}

interface RpcResultItem {
  id?: unknown;
  result?: unknown;
  error?: { message?: string };
}

function batchError(addresses: string[], err: string): AddressHolding[] {
  return addresses.map((address) => ({ address, balance: null, error: err }));
}

async function readEvmBatch(
  cfg: ChainConfig,
  addresses: string[]
): Promise<AddressHolding[]> {
  const payload = addresses.map((address, i) => ({
    jsonrpc: "2.0",
    id: i,
    method: "eth_getBalance",
    params: [address, "latest"],
  }));
  try {
    const json = (await fetchJson(cfg.rpcUrl as string, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    })) as unknown;
    if (!Array.isArray(json)) throw new Error("unexpected rpc response");
    const items = json as RpcResultItem[];
    return addresses.map((address, i) => {
      const item = items.find((r) => r.id === i);
      if (!item || typeof item.result !== "string") {
        return {
          address,
          balance: null,
          error: item?.error?.message ?? "unexpected rpc response",
        };
      }
      try {
        return {
          address,
          balance: formatDecimalUnits(
            hexToDecimalString(item.result),
            cfg.decimals
          ),
        };
      } catch {
        return { address, balance: null, error: "bad balance value" };
      }
    });
  } catch (e) {
    return batchError(addresses, toError(e));
  }
}

async function readSolanaBatch(
  cfg: ChainConfig,
  addresses: string[]
): Promise<AddressHolding[]> {
  const payload = addresses.map((address, i) => ({
    jsonrpc: "2.0",
    id: i,
    method: "getBalance",
    params: [address],
  }));
  try {
    const json = (await fetchJson(cfg.rpcUrl as string, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    })) as unknown;
    if (!Array.isArray(json)) throw new Error("unexpected rpc response");
    const items = json as RpcResultItem[];
    return addresses.map((address, i) => {
      const item = items.find((r) => r.id === i);
      const value = (item?.result as { value?: unknown } | undefined)?.value;
      if (typeof value !== "number") {
        return {
          address,
          balance: null,
          error: item?.error?.message ?? "unexpected rpc response",
        };
      }
      return {
        address,
        balance: formatDecimalUnits(String(Math.trunc(value)), cfg.decimals),
      };
    });
  } catch (e) {
    return batchError(addresses, toError(e));
  }
}

interface RelayCoin {
  puzzle_hash?: unknown;
  amount_mojos?: unknown;
  spent_height?: unknown;
}

async function readChiaBatch(
  cfg: ChainConfig,
  addresses: string[]
): Promise<AddressHolding[]> {
  const pairs = addresses.map((address) => ({
    address,
    puzzleHash: chiaAddressToPuzzleHash(address),
  }));
  const valid = pairs.filter(
    (p): p is { address: string; puzzleHash: string } => p.puzzleHash !== null
  );
  const relayUrl =
    process.env.NEXT_PUBLIC_RELAY_URL ??
    "https://spellbook-production.up.railway.app";
  const token = process.env.SPELLBOOK_RELAY_TOKEN;
  if (!token) {
    return batchError(addresses, "relay not configured");
  }
  if (valid.length === 0) {
    return pairs.map(({ address }) => ({
      address,
      balance: null,
      error: "invalid chia address",
    }));
  }
  try {
    const json = (await fetchJson(`${relayUrl}/v1/coins`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      // The relay requires the body to be EXACTLY {"puzzle_hashes": [...]}.
      // Coins come back tagged with their puzzle_hash, so one call
      // covers every address.
      body: JSON.stringify({ puzzle_hashes: valid.map((p) => p.puzzleHash) }),
    })) as { ok?: unknown; coins?: unknown };
    if (json.ok !== true || !Array.isArray(json.coins))
      throw new Error("unexpected relay response");
    // Only unspent coins count toward the balance. Amounts arrive as
    // JSON numbers, so per-address sums stay in number space (exact
    // for any realistic testnet balance).
    const mojosByHash = new Map<string, number>();
    for (const coin of json.coins as RelayCoin[]) {
      if (coin.spent_height !== null && coin.spent_height !== undefined)
        continue;
      if (typeof coin.puzzle_hash !== "string") continue;
      if (typeof coin.amount_mojos !== "number") continue;
      mojosByHash.set(
        coin.puzzle_hash,
        (mojosByHash.get(coin.puzzle_hash) ?? 0) + coin.amount_mojos
      );
    }
    return pairs.map(({ address, puzzleHash }) => {
      if (!puzzleHash) {
        return { address, balance: null, error: "invalid chia address" };
      }
      return {
        address,
        balance: formatDecimalUnits(
          String(Math.trunc(mojosByHash.get(puzzleHash) ?? 0)),
          cfg.decimals
        ),
      };
    });
  } catch (e) {
    return batchError(addresses, toError(e));
  }
}

interface ChainAddresses {
  cfg: ChainConfig;
  addresses: string[];
}

/**
 * Resolve which chains (and whose addresses) this session may see.
 * Viewers see the operator's configured drill addresses; agents see
 * ONLY the watch addresses they asserted at login — never the
 * operator's.
 */
function chainsForSession(session: Session): ChainAddresses[] {
  if (session.role === "viewer") {
    return CHAINS.map((cfg) => ({ cfg, addresses: [cfg.address] }));
  }
  const addrs: AgentAddresses = session.addresses ?? {};
  const out: ChainAddresses[] = [];
  if (addrs.evm && addrs.evm.length > 0) {
    for (const cfg of CHAINS) {
      if (cfg.kind === "evm")
        out.push({ cfg, addresses: addrs.evm as string[] });
    }
  }
  if (addrs.solana && addrs.solana.length > 0) {
    const cfg = CHAINS.find((c) => c.kind === "solana");
    if (cfg) out.push({ cfg, addresses: addrs.solana });
  }
  if (addrs.chia && addrs.chia.length > 0) {
    const cfg = CHAINS.find((c) => c.kind === "chia");
    if (cfg) out.push({ cfg, addresses: addrs.chia });
  }
  return out;
}

/** ?depth=N caps the queried addresses per chain (default: all bound). */
function parseDepth(raw: string | null, available: number): number {
  const fallback = Math.min(Math.max(available, 1), MAX_DEPTH);
  if (raw === null || raw.trim() === "") return fallback;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(Math.max(n, 1), MAX_DEPTH, Math.max(available, 1));
}

export async function GET(req: Request): Promise<NextResponse> {
  // Actual mode: holdings are only served to a logged-in session
  // (agent challenge-sign or human viewer token).
  const session = readSession(cookies().get(SESSION_COOKIE)?.value);
  if (!session) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  const rawDepth = new URL(req.url).searchParams.get("depth");
  const groups = chainsForSession(session);
  const holdings: ChainHolding[] = await Promise.all(
    groups.map(async ({ cfg, addresses }): Promise<ChainHolding> => {
      const slice = addresses.slice(0, parseDepth(rawDepth, addresses.length));
      let per: AddressHolding[];
      switch (cfg.kind) {
        case "evm":
          per = await readEvmBatch(cfg, slice);
          break;
        case "solana":
          per = await readSolanaBatch(cfg, slice);
          break;
        case "chia":
          per = await readChiaBatch(cfg, slice);
          break;
      }
      // A failed address returns { balance: null, error } — never fails
      // the whole response.
      return {
        id: cfg.id,
        label: cfg.label,
        detail: cfg.detail,
        unit: cfg.unit,
        watchAddresses: addresses.length,
        addresses: per,
        total: totalOf(per),
      };
    })
  );
  return NextResponse.json({ chains: holdings });
}
