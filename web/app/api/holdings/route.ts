// Server-only read-only holdings proxy for /dashboard.
//
// GET fans out to public testnet RPCs + the operator's Chia relay and
// returns normalized balances. The relay bearer token (SPELLBOOK_RELAY_TOKEN)
// never leaves the server. Strictly read-only: no broadcast, no signing,
// no write endpoints are ever called from here.

import { NextResponse } from "next/server";
import { CHAINS, CHIA_PUZZLE_HASH, type ChainConfig } from "@/lib/chains";

export const dynamic = "force-dynamic";

const TIMEOUT_MS = 8000;

export interface ChainHolding {
  id: string;
  label: string;
  detail: string;
  address: string;
  /** human-readable balance in `unit`, or null when the chain is unreachable */
  balance: string | null;
  unit: string;
  error?: string;
}

function holdingBase(cfg: ChainConfig): Omit<ChainHolding, "balance"> {
  return {
    id: cfg.id,
    label: cfg.label,
    detail: cfg.detail,
    address: cfg.address,
    unit: cfg.unit,
  };
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

interface JsonRpcResponse {
  result?: unknown;
  error?: { message?: string };
}

async function readEvm(cfg: ChainConfig): Promise<ChainHolding> {
  const base = holdingBase(cfg);
  try {
    const json = (await fetchJson(cfg.rpcUrl as string, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "eth_getBalance",
        params: [cfg.address, "latest"],
      }),
    })) as JsonRpcResponse;
    if (json.error) throw new Error(json.error.message ?? "rpc error");
    if (typeof json.result !== "string")
      throw new Error("unexpected rpc response");
    return {
      ...base,
      balance: formatDecimalUnits(hexToDecimalString(json.result), cfg.decimals),
    };
  } catch (e) {
    return { ...base, balance: null, error: toError(e) };
  }
}

async function readSolana(cfg: ChainConfig): Promise<ChainHolding> {
  const base = holdingBase(cfg);
  try {
    const json = (await fetchJson(cfg.rpcUrl as string, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "getBalance",
        params: [cfg.address],
      }),
    })) as JsonRpcResponse;
    if (json.error) throw new Error(json.error.message ?? "rpc error");
    const value = (json.result as { value?: unknown } | undefined)?.value;
    if (typeof value !== "number")
      throw new Error("unexpected rpc response");
    return {
      ...base,
      balance: formatDecimalUnits(String(Math.trunc(value)), cfg.decimals),
    };
  } catch (e) {
    return { ...base, balance: null, error: toError(e) };
  }
}

interface RelayCoin {
  amount_mojos?: unknown;
  spent_height?: unknown;
}

async function readChia(cfg: ChainConfig): Promise<ChainHolding> {
  const base = holdingBase(cfg);
  const relayUrl =
    process.env.NEXT_PUBLIC_RELAY_URL ??
    "https://spellbook-production.up.railway.app";
  const token = process.env.SPELLBOOK_RELAY_TOKEN;
  if (!token) {
    return { ...base, balance: null, error: "relay not configured" };
  }
  try {
    const json = (await fetchJson(`${relayUrl}/v1/coins`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      // The relay requires the body to be EXACTLY {"puzzle_hashes": [...]}.
      body: JSON.stringify({ puzzle_hashes: [CHIA_PUZZLE_HASH] }),
    })) as { ok?: unknown; coins?: unknown };
    if (json.ok !== true || !Array.isArray(json.coins))
      throw new Error("unexpected relay response");
    // Only unspent coins count toward the balance. Amounts arrive as
    // JSON numbers, so the sum stays in number space (exact for any
    // realistic testnet balance).
    let mojos = 0;
    for (const coin of json.coins as RelayCoin[]) {
      if (coin.spent_height !== null && coin.spent_height !== undefined)
        continue;
      if (typeof coin.amount_mojos !== "number") continue;
      mojos += coin.amount_mojos;
    }
    return {
      ...base,
      balance: formatDecimalUnits(String(Math.trunc(mojos)), cfg.decimals),
    };
  } catch (e) {
    return { ...base, balance: null, error: toError(e) };
  }
}

export async function GET(): Promise<NextResponse> {
  const chains = await Promise.all(
    CHAINS.map((cfg) => {
      switch (cfg.kind) {
        case "evm":
          return readEvm(cfg);
        case "solana":
          return readSolana(cfg);
        case "chia":
          return readChia(cfg);
      }
    })
  );
  // A failed chain returns { balance: null, error } — never fails the
  // whole response.
  return NextResponse.json({ chains });
}
