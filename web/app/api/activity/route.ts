// Server-only read-only activity proxy for /dashboard.
//
// GET returns recent on-chain activity for the session's watch addresses,
// normalized per chain. Sources (all keyless, all read-only):
//   - Solana (devnet + mainnet): getSignaturesForAddress + getTransaction
//     → full history with amounts and direction.
//   - EVM (6 chains): eth_getLogs for ERC-20 Transfer events over a recent
//     window → token transfers only. Plain native transfers don't emit
//     logs, so they need an explorer API key — not covered here.
//   - Chia (mainnet + testnet11): Spacescan free API
//     /address/xch-transaction/{address} → sent + received XCH transfers.
//
// Strictly read-only: no broadcast, no signing, no write endpoints.
// ?depth=N caps addresses per chain (default 3, max 10 — activity is
// heavier per address than balances). ?limit=M caps items per address
// (default 5, max 10). A failed address or chain returns { error } on its
// entry — never fails the whole response.

import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { CHAINS, type ChainConfig } from "@/lib/chains";
import {
  SESSION_COOKIE,
  readSession,
  sessionWallets,
  type AgentAddresses,
  type Session,
} from "@/lib/auth";

export const dynamic = "force-dynamic";

const TIMEOUT_MS = 8000;
const MAX_DEPTH = 10;

/**
 * Browser User-Agent sent on every outbound fetch. Some RPCs (notably
 * Robinhood Chain's Cloudflare front) 403 requests that carry no UA.
 */
const BROWSER_UA =
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

/** Normalize the HeadersInit a caller passed into a plain record. */
function asHeaderRecord(
  headers: HeadersInit | undefined
): Record<string, string> {
  if (!headers) return {};
  if (headers instanceof Headers) {
    const out: Record<string, string> = {};
    headers.forEach((v, k) => {
      out[k] = v;
    });
    return out;
  }
  if (Array.isArray(headers)) return Object.fromEntries(headers);
  return headers as Record<string, string>;
}
const DEFAULT_DEPTH = 3;
const MAX_LIMIT = 10;
const DEFAULT_LIMIT = 5;

/* ------------------------------------------------------------------ */
/* shared helpers (small pure copies of the holdings-route utilities)  */
/* ------------------------------------------------------------------ */

function toError(e: unknown): string {
  if (e instanceof Error) {
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
    const res = await fetch(url, {
      ...init,
      headers: {
        // Some RPCs (notably Robinhood Chain's Cloudflare front) 403
        // requests that carry no User-Agent. Look like a browser everywhere.
        "User-Agent": BROWSER_UA,
        ...asHeaderRecord(init.headers),
      },
      signal: ctrl.signal,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return (await res.json()) as unknown;
  } finally {
    clearTimeout(timer);
  }
}

/** Hex (0x…) → decimal string, manual conversion (no BigInt). */
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
  const neg = decStr.startsWith("-");
  const abs = neg ? decStr.slice(1) : decStr;
  const padded = abs.padStart(decimals + 1, "0");
  const whole = padded.slice(0, padded.length - decimals);
  const frac = padded.slice(padded.length - decimals).replace(/0+$/, "");
  const out = frac ? `${whole}.${frac}` : whole;
  return neg ? `-${out}` : out;
}

interface RpcItem {
  id?: unknown;
  result?: unknown;
  error?: { message?: string };
}

/** Batch JSON-RPC helper: one HTTP POST carrying many calls. */
async function rpcBatch(
  url: string,
  calls: { method: string; params: unknown[] }[]
): Promise<unknown[]> {
  const body = calls.map((c, i) => ({
    jsonrpc: "2.0",
    id: i + 1,
    method: c.method,
    params: c.params,
  }));
  const json = (await fetchJson(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  })) as RpcItem[];
  if (!Array.isArray(json)) throw new Error("unexpected rpc response");
  return json.map((item) => {
    if (item?.error) throw new Error(item.error.message ?? "rpc error");
    return item?.result;
  });
}

async function rpcCall(
  url: string,
  method: string,
  params: unknown[]
): Promise<unknown> {
  const [result] = await rpcBatch(url, [{ method, params }]);
  return result;
}

/* ------------------------------------------------------------------ */
/* session → chains (mirrors the holdings route)                       */
/* ------------------------------------------------------------------ */

function addressesForChain(
  cfg: ChainConfig,
  addrs: AgentAddresses
): string[] | null {
  const mainnet = cfg.env === "mainnet";
  let list: string[] | undefined;
  switch (cfg.kind) {
    case "evm":
      list = mainnet ? addrs.evm_mainnet : addrs.evm;
      break;
    case "solana":
      list = mainnet ? addrs.solana_mainnet : addrs.solana;
      break;
    case "chia":
      list = mainnet ? addrs.chia_mainnet : addrs.chia;
      break;
  }
  return list && list.length > 0 ? list : null;
}

function chainsForSession(session: Session): { wallet: string; cfg: ChainConfig; addresses: string[] }[] {
  const wallets = sessionWallets(session);
  if (wallets.length === 0) {
    // Shared operator drill view (no wallets bound).
    return CHAINS.filter((cfg) => cfg.address).map((cfg) => ({
      wallet: "Operator",
      cfg,
      addresses: [cfg.address],
    }));
  }
  const out: { wallet: string; cfg: ChainConfig; addresses: string[] }[] = [];
  for (const w of wallets) {
    for (const cfg of CHAINS) {
      const addresses = addressesForChain(cfg, w.addresses);
      if (addresses) out.push({ wallet: w.label, cfg, addresses });
    }
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* normalized shapes                                                   */
/* ------------------------------------------------------------------ */

export interface ActivityEntry {
  id: string;
  /** ISO timestamp, or null when the source didn't provide one */
  time: string | null;
  kind: "in" | "out";
  /** human-readable amount, e.g. "0.5" */
  amount: string;
  unit: string;
  counterparty: string;
  /** tx hash / signature / coin id */
  tx: string;
  explorerUrl?: string;
}

export interface AddressActivity {
  index: number;
  address: string;
  items: ActivityEntry[];
  error?: string;
}

export interface ChainActivity {
  id: string;
  /** labeled wallet this group belongs to, e.g. "Spellbook" or "Bankr" */
  wallet: string;
  label: string;
  detail: string;
  env: string;
  /** what this chain's feed covers, e.g. "token transfers" */
  coverage: string;
  watchAddresses: number;
  addresses: AddressActivity[];
  error?: string;
}

/* ------------------------------------------------------------------ */
/* Solana: getSignaturesForAddress + getTransaction                     */
/* ------------------------------------------------------------------ */

function solanaExplorer(tx: string, env: string): string {
  const base = `https://explorer.solana.com/tx/${tx}`;
  return env === "mainnet" ? base : `${base}?cluster=devnet`;
}

function solanaNetLamports(txResult: unknown, address: string): number | null {
  try {
    const r = txResult as {
      meta?: { preBalances?: unknown; postBalances?: unknown; err?: unknown };
      transaction?: { message?: { accountKeys?: unknown } };
    };
    if (r?.meta?.err) return null; // skip failed transactions
    const keys = r?.transaction?.message?.accountKeys;
    if (!Array.isArray(keys)) return null;
    const idx = keys.findIndex((k) =>
      typeof k === "string" ? k === address : (k as { pubkey?: string })?.pubkey === address
    );
    if (idx < 0) return null;
    const pre = (r.meta?.preBalances as number[])?.[idx];
    const post = (r.meta?.postBalances as number[])?.[idx];
    if (typeof pre !== "number" || typeof post !== "number") return null;
    return post - pre;
  } catch {
    return null;
  }
}

async function readSolanaActivity(
  cfg: ChainConfig,
  slice: { index: number; address: string }[],
  limit: number
): Promise<AddressActivity[]> {
  const url = cfg.rpcUrl as string;
  return Promise.all(
    slice.map(async ({ index, address }): Promise<AddressActivity> => {
      try {
        const sigs = (await rpcCall(url, "getSignaturesForAddress", [
          address,
          { limit },
        ])) as { signature?: string; blockTime?: number | null }[];
        if (!Array.isArray(sigs)) throw new Error("unexpected rpc response");
        const details = await Promise.all(
          sigs.slice(0, limit).map(async (s) => {
            if (!s?.signature) return null;
            try {
              const tx = await rpcCall(url, "getTransaction", [
                s.signature,
                { maxSupportedTransactionVersion: 0, encoding: "jsonParsed" },
              ]);
              return { sig: s.signature, blockTime: s.blockTime ?? null, tx };
            } catch {
              return null;
            }
          })
        );
        const items: ActivityEntry[] = [];
        for (const d of details) {
          if (!d) continue;
          const net = solanaNetLamports(d.tx, address);
          if (net === null || net === 0) continue;
          const abs = formatDecimalUnits(String(Math.abs(net)), 9);
          items.push({
            id: d.sig,
            time:
              typeof d.blockTime === "number"
                ? new Date(d.blockTime * 1000).toISOString()
                : null,
            kind: net > 0 ? "in" : "out",
            amount: abs,
            unit: "SOL",
            counterparty: "—",
            tx: d.sig,
            explorerUrl: solanaExplorer(d.sig, cfg.env),
          });
        }
        return { index, address, items };
      } catch (e) {
        return { index, address, items: [], error: toError(e) };
      }
    })
  );
}

/* ------------------------------------------------------------------ */
/* EVM: eth_getLogs for ERC-20 Transfer events (token transfers only)  */
/* ------------------------------------------------------------------ */

const TRANSFER_TOPIC =
  "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
/** ~ how far back to scan per chain (public RPC getLogs windows vary) */
const EVM_LOOKBACK_BLOCKS = 20000;

const EVM_EXPLORERS: Record<number, (tx: string) => string> = {
  1: (tx) => `https://etherscan.io/tx/${tx}`,
  11155111: (tx) => `https://sepolia.etherscan.io/tx/${tx}`,
  8453: (tx) => `https://basescan.org/tx/${tx}`,
  84532: (tx) => `https://sepolia.basescan.org/tx/${tx}`,
  4663: (tx) => `https://robinhoodchain.blockscout.com/tx/${tx}`,
};

function topicToAddress(topic: string): string {
  return `0x${topic.slice(-40)}`;
}

function decodeAbiString(hex: string): string | null {
  try {
    const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
    if (clean.length < 128) return null;
    const len = parseInt(clean.slice(64, 128), 16);
    if (!Number.isFinite(len) || len <= 0 || len > 64) return null;
    const data = clean.slice(128, 128 + len * 2);
    let out = "";
    for (let i = 0; i < data.length; i += 2) {
      const code = parseInt(data.slice(i, i + 2), 16);
      if (code === 0) break;
      out += String.fromCharCode(code);
    }
    return out || null;
  } catch {
    return null;
  }
}

async function readEvmActivity(
  cfg: ChainConfig,
  slice: { index: number; address: string }[],
  limit: number
): Promise<AddressActivity[]> {
  const url = cfg.rpcUrl as string;
  try {
    const latestHex = (await rpcCall(url, "eth_blockNumber", [])) as string;
    const latest = parseInt(latestHex, 16);
    if (!Number.isFinite(latest)) throw new Error("bad block number");
    const fromBlock = `0x${Math.max(0, latest - EVM_LOOKBACK_BLOCKS).toString(16)}`;

    // One batched getLogs per address (parallel across addresses).
    const logsPerAddress = await Promise.all(
      slice.map(async ({ address }) => {
        try {
          const logs = (await rpcCall(url, "eth_getLogs", [
            {
              fromBlock,
              toBlock: "latest",
              address,
              topics: [TRANSFER_TOPIC],
            },
          ])) as {
            address?: string;
            topics?: string[];
            data?: string;
            blockNumber?: string;
            transactionHash?: string;
          }[];
          if (!Array.isArray(logs)) throw new Error("unexpected rpc response");
          return logs;
        } catch (e) {
          throw e;
        }
      })
    );

    // Unique token contracts + block numbers across this chain's logs.
    const tokenAddrs = new Set<string>();
    const blockNums = new Set<string>();
    for (const logs of logsPerAddress) {
      for (const l of logs.slice(-limit)) {
        if (typeof l.address === "string") tokenAddrs.add(l.address.toLowerCase());
        if (typeof l.blockNumber === "string") blockNums.add(l.blockNumber);
      }
    }

    // Token metadata (decimals + symbol), cached for the whole request.
    const tokenMeta = new Map<string, { decimals: number; symbol: string }>();
    await Promise.all(
      Array.from(tokenAddrs).map(async (t) => {
        try {
          const [decRes, symRes] = await rpcBatch(url, [
            { method: "eth_call", params: [{ to: t, data: "0x313ce567" }, "latest"] },
            { method: "eth_call", params: [{ to: t, data: "0x95d89b41" }, "latest"] },
          ]);
          const decimals = parseInt(decRes as string, 16);
          const symbol = decodeAbiString(symRes as string) ?? "tokens";
          tokenMeta.set(t, {
            decimals: Number.isFinite(decimals) && decimals >= 0 && decimals <= 36 ? decimals : 18,
            symbol,
          });
        } catch {
          tokenMeta.set(t, { decimals: 18, symbol: "tokens" });
        }
      })
    );

    // Block timestamps for the blocks we show.
    const blockTime = new Map<string, string | null>();
    await Promise.all(
      Array.from(blockNums).map(async (b) => {
        try {
          const blk = (await rpcCall(url, "eth_getBlockByNumber", [b, false])) as {
            timestamp?: string;
          };
          const ts = blk?.timestamp ? parseInt(blk.timestamp, 16) : NaN;
          blockTime.set(b, Number.isFinite(ts) ? new Date(ts * 1000).toISOString() : null);
        } catch {
          blockTime.set(b, null);
        }
      })
    );

    const explorer = cfg.chainId !== undefined ? EVM_EXPLORERS[cfg.chainId] : undefined;
    return slice.map(({ index, address }, ai): AddressActivity => {
      const watched = address.toLowerCase();
      const logs = logsPerAddress[ai].slice(-limit).reverse();
      const items: ActivityEntry[] = [];
      for (const l of logs) {
        try {
          const topics = l.topics ?? [];
          if (topics.length < 3 || typeof l.data !== "string") continue;
          const from = topicToAddress(topics[1]).toLowerCase();
          const to = topicToAddress(topics[2]).toLowerCase();
          if (from !== watched && to !== watched) continue;
          const meta = tokenMeta.get((l.address ?? "").toLowerCase()) ?? {
            decimals: 18,
            symbol: "tokens",
          };
          const amount = formatDecimalUnits(hexToDecimalString(l.data), meta.decimals);
          const txHash = l.transactionHash ?? "";
          items.push({
            id: `${txHash}:${topics[1]}:${topics[2]}`,
            time: blockTime.get(l.blockNumber ?? "") ?? null,
            kind: from === watched ? "out" : "in",
            amount,
            unit: meta.symbol,
            counterparty: from === watched ? to : from,
            tx: txHash,
            ...(explorer && txHash ? { explorerUrl: explorer(txHash) } : {}),
          });
        } catch {
          /* skip malformed log */
        }
      }
      return { index, address, items };
    });
  } catch (e) {
    const err = toError(e);
    return slice.map(({ index, address }) => ({ index, address, items: [], error: err }));
  }
}

/* ------------------------------------------------------------------ */
/* Chia: Spacescan free API — sent + received XCH transfers             */
/* ------------------------------------------------------------------ */

const SPACESCAN_HOSTS: Record<string, string> = {
  mainnet: "https://api.spacescan.io",
  testnet: "https://api-testnet11.spacescan.io",
};

interface SpacescanTx {
  coin_id?: string;
  time?: string;
  height?: number;
  amount_xch?: number;
  to?: string;
  from?: string;
}

async function readChiaActivity(
  cfg: ChainConfig,
  slice: { index: number; address: string }[],
  limit: number
): Promise<AddressActivity[]> {
  const host = SPACESCAN_HOSTS[cfg.env] ?? SPACESCAN_HOSTS.mainnet;
  return Promise.all(
    slice.map(async ({ index, address }): Promise<AddressActivity> => {
      try {
        const json = (await fetchJson(
          `${host}/address/xch-transaction/${address}?count=${limit}`,
          {}
        )) as {
          status?: string;
          send_transactions?: { transactions?: SpacescanTx[] };
          received_transactions?: { transactions?: SpacescanTx[] };
        };
        if (json?.status !== "success") throw new Error("unexpected api response");
        const out: ActivityEntry[] = [];
        for (const t of json.send_transactions?.transactions ?? []) {
          if (typeof t.coin_id !== "string") continue;
          out.push({
            id: `out:${t.coin_id}`,
            time: typeof t.time === "string" ? t.time : null,
            kind: "out",
            amount: typeof t.amount_xch === "number" ? String(t.amount_xch) : "?",
            unit: "XCH",
            counterparty: typeof t.to === "string" ? t.to : "—",
            tx: t.coin_id,
          });
        }
        for (const t of json.received_transactions?.transactions ?? []) {
          if (typeof t.coin_id !== "string") continue;
          out.push({
            id: `in:${t.coin_id}`,
            time: typeof t.time === "string" ? t.time : null,
            kind: "in",
            amount: typeof t.amount_xch === "number" ? String(t.amount_xch) : "?",
            unit: "XCH",
            counterparty: typeof t.from === "string" ? t.from : "—",
            tx: t.coin_id,
          });
        }
        out.sort((a, b) => (b.time ?? "").localeCompare(a.time ?? ""));
        return { index, address, items: out.slice(0, limit * 2) };
      } catch (e) {
        return { index, address, items: [], error: toError(e) };
      }
    })
  );
}

/* ------------------------------------------------------------------ */
/* handler                                                             */
/* ------------------------------------------------------------------ */

function parseBound(raw: string | null, fallback: number, max: number): number {
  if (raw === null || raw.trim() === "") return fallback;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(Math.max(n, 1), max);
}

const COVERAGE: Record<string, string> = {
  solana: "full history",
  evm: "token transfers",
  chia: "XCH transfers",
};

export async function GET(req: Request): Promise<NextResponse> {
  const session = readSession(cookies().get(SESSION_COOKIE)?.value);
  if (!session) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  const params = new URL(req.url).searchParams;
  const depth = parseBound(params.get("depth"), DEFAULT_DEPTH, MAX_DEPTH);
  const limit = parseBound(params.get("limit"), DEFAULT_LIMIT, MAX_LIMIT);

  const groups = chainsForSession(session);
  const chains: ChainActivity[] = await Promise.all(
    groups.map(async ({ wallet, cfg, addresses }): Promise<ChainActivity> => {
      const slice = addresses
        .slice(0, Math.min(depth, addresses.length))
        .map((address, i) => ({ index: i + 1, address }));
      let per: AddressActivity[];
      try {
        switch (cfg.kind) {
          case "solana":
            per = await readSolanaActivity(cfg, slice, limit);
            break;
          case "evm":
            per = await readEvmActivity(cfg, slice, limit);
            break;
          case "chia":
            per = await readChiaActivity(cfg, slice, limit);
            break;
        }
      } catch (e) {
        const err = toError(e);
        per = slice.map(({ index, address }) => ({ index, address, items: [], error: err }));
      }
      return {
        id: cfg.id,
        wallet,
        label: cfg.networkLabel,
        detail: cfg.detail,
        env: cfg.env,
        coverage: COVERAGE[cfg.kind] ?? "",
        watchAddresses: addresses.length,
        addresses: per,
      };
    })
  );
  return NextResponse.json({ chains });
}
