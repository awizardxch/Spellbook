// Server-only read-only holdings proxy for /dashboard.
//
// GET fans out to public mainnet + testnet RPCs and the operator's Chia
// relay and returns normalized balances. The relay Bearer <redacted>
// (SPELLBOOK_RELAY_TOKEN) never leaves the server. Strictly read-only:
// no broadcast, no signing, no write endpoints are ever called from here.
//
// Multi-address: each chain carries the session's bound watch addresses
// (up to 100 per chain, in the agent's derivation order). Mainnet and
// testnet derive different keys (SPEC §2/P9), so mainnet chains read the
// agent's separately-bound `*_mainnet` address lists. ?depth=N caps
// how many are queried (default: all bound) — depth=N queries addresses
// #1–#N. Every chain reports its per-address balances (each tagged with
// its 1-based `index`) plus the exact total across the addresses that
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
  /**
   * 1-based position in the agent's derivation order — address #1, #2, ….
   * Key derivation itself stays 0-based; this is the human-facing lookup
   * index, stable for a given bound address list. `depth=N` queries #1–#N.
   */
  index: number;
  address: string;
  /** human-readable balance in `unit`, or null when this address failed */
  balance: string | null;
  error?: string;
}

export interface ChainHolding {
  id: string;
  label: string;
  detail: string;
  /** "mainnet" | "testnet" — mirrors the chain config's env */
  env: string;
  unit: string;
  /** how many watch addresses are bound for this chain (pre-depth) */
  watchAddresses: number;
  addresses: AddressHolding[];
  /** exact sum of the balances that loaded; null when none loaded */
  total: string | null;
  /** USD value of the native total at the current price; null when unpriced */
  nativeUsd: string | null;
  /**
   * USD value of native + all token holdings — the minimized portfolio
   * row shows this, not just the native coin. Null when nothing priced.
   */
  totalUsd: string | null;
  /** fungible token holdings aggregated across loaded addresses, USD-desc */
  tokens: TokenHolding[];
  /** discovered NFTs (best-effort scan of the recent activity window) */
  nfts: NftHolding[];
}

/** One fungible token held on a chain, aggregated across addresses. */
export interface TokenHolding {
  /** ERC-20 contract address (EVM) or mint address (Solana) */
  contract: string;
  name: string;
  symbol: string;
  decimals: number;
  /** human-readable qty summed across the addresses that loaded */
  qty: string;
  /** USD value of qty at the current price, 2dp — null when unpriced */
  usd: string | null;
}

/** One discovered NFT. Best-effort: recent inbound transfers only. */
export interface NftHolding {
  contract: string;
  tokenId: string;
  /** collection name when resolvable on-chain, else null */
  name: string | null;
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
  return addresses.map((address, i) => ({
    index: i + 1,
    address,
    balance: null,
    error: err,
  }));
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
          index: i + 1,
          address,
          balance: null,
          error: item?.error?.message ?? "unexpected rpc response",
        };
      }
      try {
        return {
          index: i + 1,
          address,
          balance: formatDecimalUnits(
            hexToDecimalString(item.result),
            cfg.decimals
          ),
        };
      } catch {
        return {
          index: i + 1,
          address,
          balance: null,
          error: "bad balance value",
        };
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
          index: i + 1,
          address,
          balance: null,
          error: item?.error?.message ?? "unexpected rpc response",
        };
      }
      return {
        index: i + 1,
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
  // One relay deployment serves both Chia networks (PR #14): the request
  // selects the pool with the "network" body key. No separate mainnet
  // relay URL is needed.
  const relayUrl =
    process.env.NEXT_PUBLIC_RELAY_URL ??
    "https://spellbook-production.up.railway.app";
  const token = process.env.SPELLBOOK_RELAY_TOKEN;
  if (!relayUrl || !token) {
    return batchError(addresses, "relay not configured");
  }
  if (valid.length === 0) {
    return pairs.map(({ address }, i) => ({
      index: i + 1,
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
      // The relay takes an optional "network" selector alongside
      // puzzle_hashes (one deployment serves testnet11 + mainnet).
      // Coins come back tagged with their puzzle_hash, so one call
      // covers every address.
      body: JSON.stringify({
        puzzle_hashes: valid.map((p) => p.puzzleHash),
        network: cfg.env === "mainnet" ? "mainnet" : "testnet11",
      }),
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
    return pairs.map(({ address, puzzleHash }, i) => {
      if (!puzzleHash) {
        return {
          index: i + 1,
          address,
          balance: null,
          error: "invalid chia address",
        };
      }
      return {
        index: i + 1,
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

/* ------------------------------------------------------------------ */
/* Fungible tokens (ERC-20 + SPL), USD pricing, and NFT discovery.     */
/*                                                                     */
/* Token balances come from curated per-chain ERC-20 lists (see        */
/* ChainConfig.tokens) plus Solana token accounts — no indexer API     */
/* key required. Prices come from DexScreener (free, no key) for       */
/* tokens and CoinGecko (free, no key) for native coins. Everything    */
/* here is best-effort: a failed source yields null/empty, never a     */
/* failed response.                                                    */
/* ------------------------------------------------------------------ */

/** 0x-address → 32-byte left-padded hex (no 0x) for ABI encoding. */
function abiPadAddress(addr: string): string {
  return addr.toLowerCase().replace(/^0x/, "").padStart(64, "0");
}

/** Single eth_call; raw result hex or null on any failure. */
async function evmCall(
  cfg: ChainConfig,
  to: string,
  data: string
): Promise<string | null> {
  try {
    const json = (await fetchJson(cfg.rpcUrl as string, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "eth_call",
        params: [{ to, data }, "latest"],
      }),
    })) as RpcResultItem;
    return typeof json.result === "string" ? json.result : null;
  } catch {
    return null;
  }
}

/** Latest block number, or null when the RPC won't say. */
async function evmLatestBlock(cfg: ChainConfig): Promise<number | null> {
  try {
    const json = (await fetchJson(cfg.rpcUrl as string, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "eth_blockNumber",
        params: [],
      }),
    })) as RpcResultItem;
    return typeof json.result === "string"
      ? parseInt(hexToDecimalString(json.result), 10)
      : null;
  } catch {
    return null;
  }
}

/**
 * Generic JSON-RPC batch with chunking (some public RPCs cap batch
 * size). Missing ids in the response are treated as failed by callers.
 */
async function jsonRpcBatch(
  cfg: ChainConfig,
  reqs: { method: string; params: unknown[] }[]
): Promise<RpcResultItem[]> {
  const out: RpcResultItem[] = [];
  const CHUNK = 100;
  for (let i = 0; i < reqs.length; i += CHUNK) {
    const chunk = reqs.slice(i, i + CHUNK).map((r, j) => ({
      jsonrpc: "2.0",
      id: i + j,
      method: r.method,
      params: r.params,
    }));
    try {
      const json = (await fetchJson(cfg.rpcUrl as string, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(chunk),
      })) as unknown;
      if (Array.isArray(json)) out.push(...(json as RpcResultItem[]));
    } catch {
      // chunk failed — callers treat the missing ids as failed
    }
  }
  return out;
}

/** Decode an ABI-encoded string return value; null when malformed. */
function decodeAbiString(hex: string): string | null {
  try {
    const clean = hex.replace(/^0x/, "");
    if (clean.length < 128) return null;
    const len = parseInt(clean.slice(64, 128), 16);
    if (!Number.isFinite(len) || len <= 0 || len > 256) return null;
    const data = clean.slice(128, 128 + len * 2);
    if (data.length < len * 2) return null;
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

interface TokenMeta {
  name: string;
  symbol: string;
  decimals: number;
}

/** Process-level cache: token metadata never changes. */
const tokenMetaCache = new Map<string, TokenMeta>();

/** On-chain name()/symbol()/decimals() with safe fallbacks. Never throws. */
async function evmTokenMeta(
  cfg: ChainConfig,
  contract: string
): Promise<TokenMeta> {
  const key = `${cfg.id}:${contract.toLowerCase()}`;
  const hit = tokenMetaCache.get(key);
  if (hit) return hit;
  const [nameHex, symHex, decHex] = await Promise.all([
    evmCall(cfg, contract, "0x06fdde03"),
    evmCall(cfg, contract, "0x95d89b41"),
    evmCall(cfg, contract, "0x313ce567"),
  ]);
  const meta: TokenMeta = {
    name: (nameHex && decodeAbiString(nameHex)) || "Unknown token",
    symbol: (symHex && decodeAbiString(symHex)) || contract.slice(0, 8),
    decimals: 18,
  };
  if (decHex) {
    try {
      const d = parseInt(hexToDecimalString(decHex), 10);
      if (Number.isFinite(d) && d >= 0 && d <= 36) meta.decimals = d;
    } catch {
      // keep 18
    }
  }
  tokenMetaCache.set(key, meta);
  return meta;
}

const BALANCE_OF = "0x70a08231";

interface EvmTokenScan {
  /** lowercase contract → (address → human qty), non-zero only */
  balances: Map<string, Map<string, string>>;
  /** lowercase contract → metadata */
  metas: Map<string, TokenMeta>;
  /** lowercase contract → original configured address */
  original: Map<string, string>;
}

/** balanceOf for every address × contract. Never throws. */
async function readEvmTokenBalances(
  cfg: ChainConfig,
  addresses: string[],
  contracts: string[]
): Promise<EvmTokenScan> {
  const scan: EvmTokenScan = {
    balances: new Map(),
    metas: new Map(),
    original: new Map(),
  };
  const uniq: string[] = [];
  for (const c of contracts.map((c) => c.toLowerCase()))
    if (uniq.indexOf(c) === -1) uniq.push(c);
  if (uniq.length === 0 || addresses.length === 0) return scan;
  await Promise.all(
    uniq.map(async (c) => {
      scan.metas.set(c, await evmTokenMeta(cfg, c));
    })
  );
  for (const c of contracts) scan.original.set(c.toLowerCase(), c);
  const reqs: { method: string; params: unknown[] }[] = [];
  const order: { contract: string; address: string }[] = [];
  for (const c of uniq) {
    for (const address of addresses) {
      reqs.push({
        method: "eth_call",
        params: [
          { to: scan.original.get(c), data: BALANCE_OF + abiPadAddress(address) },
          "latest",
        ],
      });
      order.push({ contract: c, address });
    }
  }
  const items = await jsonRpcBatch(cfg, reqs);
  const byId = new Map<number, RpcResultItem>();
  for (const it of items) if (typeof it.id === "number") byId.set(it.id, it);
  order.forEach((o, i) => {
    const item = byId.get(i);
    if (!item || typeof item.result !== "string") return;
    try {
      const qty = formatDecimalUnits(
        hexToDecimalString(item.result),
        scan.metas.get(o.contract)!.decimals
      );
      if (qty === "0") return;
      if (!scan.balances.has(o.contract))
        scan.balances.set(o.contract, new Map());
      scan.balances.get(o.contract)!.set(o.address, qty);
    } catch {
      // bad value — skip
    }
  });
  return scan;
}

const TOKEN_KEG_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

interface SplScan {
  /** mint → (address → { qty, decimals }), non-zero only */
  balances: Map<string, Map<string, { qty: string; decimals: number }>>;
}

/**
 * Full SPL token discovery via getTokenAccountsByOwner — no curated
 * list needed, every token account the wallet owns is returned.
 * Never throws.
 */
async function readSplTokenBalances(
  cfg: ChainConfig,
  addresses: string[]
): Promise<SplScan> {
  const scan: SplScan = { balances: new Map() };
  if (addresses.length === 0) return scan;
  const items = await jsonRpcBatch(
    cfg,
    addresses.map((a) => ({
      method: "getTokenAccountsByOwner",
      params: [a, { programId: TOKEN_KEG_PROGRAM }, { encoding: "jsonParsed" }],
    }))
  );
  const byId = new Map<number, RpcResultItem>();
  for (const it of items) if (typeof it.id === "number") byId.set(it.id, it);
  addresses.forEach((address, i) => {
    const item = byId.get(i);
    const value = (item?.result as { value?: unknown } | undefined)?.value;
    if (!Array.isArray(value)) return;
    for (const entry of value as Record<string, unknown>[]) {
      try {
        const info = (
          entry as {
            account?: {
              data?: { parsed?: { info?: Record<string, unknown> } };
            };
          }
        ).account?.data?.parsed?.info;
        const mint = info?.mint;
        const ta = info?.tokenAmount as
          | { amount?: unknown; decimals?: unknown }
          | undefined;
        if (typeof mint !== "string") continue;
        const decimals =
          typeof ta?.decimals === "number" ? ta.decimals : null;
        const amount = typeof ta?.amount === "string" ? ta.amount : null;
        if (decimals === null || amount === null) continue;
        if (!/^\d+$/.test(amount) || amount.replace(/^0+/, "") === "")
          continue;
        const qty = formatDecimalUnits(amount, decimals);
        if (qty === "0") continue;
        if (!scan.balances.has(mint)) scan.balances.set(mint, new Map());
        scan.balances.get(mint)!.set(address, { qty, decimals });
      } catch {
        // malformed token account — skip
      }
    }
  });
  return scan;
}

/** DexScreener chain slugs for the networks we price. */
const DEX_CHAIN: Record<string, string> = {
  robinhood: "robinhood",
  base: "base",
  ethereum: "ethereum",
  solana: "solana",
};

interface DexPrice {
  price: string;
  symbol: string;
  name: string;
}

/**
 * Token USD prices via DexScreener (free, no key, up to 30 tokens per
 * call). Picks the highest-liquidity pair per token. Tokens DexScreener
 * doesn't know are simply absent — callers treat them as unpriced,
 * never an error. Never throws.
 */
async function dexTokenPrices(
  networkId: string,
  contracts: string[]
): Promise<Map<string, DexPrice>> {
  const out = new Map<string, DexPrice>();
  const slug = DEX_CHAIN[networkId];
  if (!slug || contracts.length === 0) return out;
  try {
    const addrs = Array.from(new Set(contracts.map((c) => c.toLowerCase())))
      .slice(0, 30)
      .join(",");
    const json = (await fetchJson(
      `https://api.dexscreener.com/latest/dex/tokens/${addrs}`,
      { headers: { Accept: "application/json" } },
      10000
    )) as { pairs?: unknown };
    const pairs = Array.isArray(json.pairs) ? json.pairs : [];
    const best = new Map<
      string,
      { price: string; liq: number; symbol: string; name: string }
    >();
    for (const p of pairs as Record<string, unknown>[]) {
      const bt = p.baseToken as
        | { address?: unknown; symbol?: unknown; name?: unknown }
        | undefined;
      const addr =
        typeof bt?.address === "string" ? bt.address.toLowerCase() : "";
      const price = typeof p.priceUsd === "string" ? p.priceUsd : "";
      if (!addr || !price || Number(price) <= 0) continue;
      const liq = Number(
        (p.liquidity as { usd?: unknown } | undefined)?.usd ?? 0
      );
      const cur = best.get(addr);
      if (!cur || liq > cur.liq) {
        best.set(addr, {
          price,
          liq,
          symbol:
            typeof bt?.symbol === "string" ? bt.symbol : addr.slice(0, 6),
          name: typeof bt?.name === "string" ? bt.name : "Unknown token",
        });
      }
    }
    best.forEach((b, addr) => {
      out.set(addr, { price: b.price, symbol: b.symbol, name: b.name });
    });
  } catch {
    // pricing is best-effort
  }
  return out;
}

/** CoinGecko ids for native coins. 60s process-level cache, best-effort. */
let nativePriceCache: { ts: number; prices: Record<string, string> } | null =
  null;

async function nativeUsdPrices(): Promise<Record<string, string>> {
  const now = Date.now();
  if (nativePriceCache && now - nativePriceCache.ts < 60_000)
    return nativePriceCache.prices;
  const prices: Record<string, string> = {};
  try {
    const json = (await fetchJson(
      "https://api.coingecko.com/api/v3/simple/price?ids=ethereum,solana,chia&vs_currencies=usd",
      { headers: { Accept: "application/json" } },
      10000
    )) as Record<string, { usd?: unknown }>;
    for (const id of ["ethereum", "solana", "chia"]) {
      const usd = json[id]?.usd;
      if (typeof usd === "number" && usd > 0) prices[id] = String(usd);
    }
    nativePriceCache = { ts: now, prices };
  } catch {
    // keep whatever we have (possibly empty)
  }
  return prices;
}

function nativeCoinGeckoId(cfg: ChainConfig): string | null {
  switch (cfg.kind) {
    case "evm":
      return "ethereum";
    case "solana":
      return "solana";
    case "chia":
      return "chia";
  }
}

/**
 * qty × price → USD at 2dp, or null when either side is unusable.
 * Float math is fine here: prices are inherently approximate, while
 * balances stay exact decimal strings everywhere else.
 */
function usdValue(qty: string, price: string): string | null {
  const q = Number(qty);
  const p = Number(price);
  if (!Number.isFinite(q) || !Number.isFinite(p) || q <= 0 || p <= 0)
    return null;
  const v = q * p;
  return Number.isFinite(v) ? v.toFixed(2) : null;
}

/** Sum of USD strings → 2dp total; null when nothing was priced. */
function totalUsdOf(values: (string | null)[]): string | null {
  let sum = 0;
  let any = false;
  for (const v of values) {
    const n = v === null ? NaN : Number(v);
    if (Number.isFinite(n)) {
      sum += n;
      any = true;
    }
  }
  return any ? sum.toFixed(2) : null;
}

/** USD-desc, unpriced last, then symbol for stability. */
function sortTokens(rows: TokenHolding[]): TokenHolding[] {
  return rows.sort((a, b) => {
    const au = a.usd === null ? -1 : Number(a.usd);
    const bu = b.usd === null ? -1 : Number(b.usd);
    if (au !== bu) return bu - au;
    return a.symbol.localeCompare(b.symbol);
  });
}

const ERC721_INTERFACE_ID = "0x80ac58cd";

/**
 * Best-effort NFT discovery on EVM chains: scan recent inbound
 * Transfer logs, keep contracts that answer ERC-721 to
 * supportsInterface, then enumerate tokenOfOwnerByIndex. Only the
 * recent window is scanned (no indexer key) — older holdings may be
 * missed. Never throws.
 */
async function discoverEvmNfts(
  cfg: ChainConfig,
  addresses: string[]
): Promise<NftHolding[]> {
  const out: NftHolding[] = [];
  const seen = new Set<string>();
  const known = new Set(
    (cfg.tokens ?? []).map((t) => t.address.toLowerCase())
  );
  const TRANSFER_TOPIC =
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
  try {
    const latest = await evmLatestBlock(cfg);
    if (latest === null) return out;
    const fromBlock = "0x" + Math.max(0, latest - 20000).toString(16);
    for (const address of addresses) {
      const padded = "0x" + abiPadAddress(address);
      let logs: unknown[] = [];
      try {
        const json = (await fetchJson(cfg.rpcUrl as string, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: 1,
            method: "eth_getLogs",
            params: [
              {
                fromBlock,
                toBlock: "latest",
                topics: [[TRANSFER_TOPIC, null, padded]],
              },
            ],
          }),
        })) as RpcResultItem;
        if (Array.isArray(json.result)) logs = json.result as unknown[];
      } catch {
        continue;
      }
      const contracts = new Set<string>();
      for (const l of logs) {
        const c = (l as { address?: unknown }).address;
        if (typeof c === "string" && !known.has(c.toLowerCase()))
          contracts.add(c);
      }
      const contractList = Array.from(contracts);
      for (let ci = 0; ci < contractList.length; ci++) {
        const contract = contractList[ci];
        const iface = await evmCall(
          cfg,
          contract,
          "0x01ffc9a7" + ERC721_INTERFACE_ID.replace(/^0x/, "").padStart(64, "0")
        );
        if (iface !== "0x" + "0".repeat(63) + "1") continue;
        const balHex = await evmCall(
          cfg,
          contract,
          BALANCE_OF + abiPadAddress(address)
        );
        let n = 0;
        try {
          n = balHex ? parseInt(hexToDecimalString(balHex), 10) : 0;
        } catch {
          n = 0;
        }
        if (!Number.isFinite(n) || n <= 0) continue;
        const nameHex = await evmCall(cfg, contract, "0x06fdde03");
        const name = (nameHex && decodeAbiString(nameHex)) || null;
        const cap = Math.min(n, 50);
        for (let i = 0; i < cap; i++) {
          const idHex = await evmCall(
            cfg,
            contract,
            "0x2f745c59" +
              abiPadAddress(address) +
              i.toString(16).padStart(64, "0")
          );
          if (!idHex) continue;
          let tokenId = "";
          try {
            tokenId = hexToDecimalString(idHex);
          } catch {
            continue;
          }
          const key = contract.toLowerCase() + ":" + tokenId;
          if (seen.has(key)) continue;
          seen.add(key);
          out.push({ contract, tokenId, name });
        }
      }
    }
  } catch {
    // best-effort
  }
  return out;
}

interface ChainAddresses {
  cfg: ChainConfig;
  addresses: string[];
}

/**
 * Resolve which chains (and whose addresses) this session may see.
 * - Viewers on the shared operator token see the operator's configured
 *   drill addresses (testnet only — mainnet drill addresses are not
 *   configured, so those chains are skipped).
 * - Viewers on a per-agent viewer token see THAT AGENT's wallet.
 * - Agents see ONLY the watch addresses they asserted at login — never
 *   the operator's.
 * Mainnet and testnet derive different keys (SPEC §2/P9): mainnet chains
 * read the agent's separately-bound `*_mainnet` address lists.
 */
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

function chainsForSession(session: Session): ChainAddresses[] {
  if (session.role === "viewer" && !session.addresses) {
    return CHAINS.filter((cfg) => cfg.address).map((cfg) => ({
      cfg,
      addresses: [cfg.address],
    }));
  }
  const addrs: AgentAddresses = session.addresses ?? {};
  const out: ChainAddresses[] = [];
  for (const cfg of CHAINS) {
    const addresses = addressesForChain(cfg, addrs);
    if (addresses) out.push({ cfg, addresses });
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
  // One native-price fetch shared by all chains (60s cached upstream).
  const nativePrices = await nativeUsdPrices();
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
      const total = totalOf(per);

      // Fungible tokens: curated ERC-20 lists on EVM, full SPL
      // discovery on Solana. Chia CATs are not covered yet.
      let tokens: TokenHolding[] = [];
      try {
        if (cfg.kind === "evm" && cfg.tokens && cfg.tokens.length > 0) {
          const contracts = cfg.tokens.map((t) => t.address);
          const [scan, prices] = await Promise.all([
            readEvmTokenBalances(cfg, slice, contracts),
            dexTokenPrices(cfg.networkId, contracts),
          ]);
          const rows: TokenHolding[] = [];
          scan.balances.forEach((perAddr, cLower) => {
            const meta = scan.metas.get(cLower);
            if (!meta) return;
            let qty: string | null = null;
            perAddr.forEach((q) => {
              qty = qty === null ? q : addDecimalStrings(qty as string, q);
            });
            if (!qty) return;
            const price = prices.get(cLower);
            const onChainNameOk = meta.name !== "Unknown token";
            rows.push({
              contract: scan.original.get(cLower) ?? cLower,
              name: onChainNameOk ? meta.name : (price?.name ?? meta.name),
              symbol: meta.symbol.startsWith("0x")
                ? (price?.symbol ?? meta.symbol)
                : meta.symbol,
              decimals: meta.decimals,
              qty,
              usd: price ? usdValue(qty as string, price.price) : null,
            });
          });
          tokens = sortTokens(rows);
        } else if (cfg.kind === "solana") {
          const scan = await readSplTokenBalances(cfg, slice);
          const mints: string[] = [];
          scan.balances.forEach((_v, m) => mints.push(m));
          const prices = await dexTokenPrices("solana", mints);
          const rows: TokenHolding[] = [];
          scan.balances.forEach((perAddr, mint) => {
            let qty: string | null = null;
            let decimals = 0;
            perAddr.forEach((v) => {
              qty = qty === null ? v.qty : addDecimalStrings(qty as string, v.qty);
              decimals = v.decimals;
            });
            if (!qty) return;
            const price = prices.get(mint.toLowerCase());
            rows.push({
              contract: mint,
              name: price?.name ?? "Unknown token",
              symbol:
                price?.symbol ?? `${mint.slice(0, 4)}…${mint.slice(-4)}`,
              decimals,
              qty,
              usd: price ? usdValue(qty as string, price.price) : null,
            });
          });
          tokens = sortTokens(rows);
        }
      } catch {
        // token scan failed — native balances still stand
        tokens = [];
      }

      // NFTs: best-effort ERC-721 discovery on EVM (recent window).
      let nfts: NftHolding[] = [];
      if (cfg.kind === "evm") {
        try {
          nfts = await discoverEvmNfts(cfg, slice);
        } catch {
          nfts = [];
        }
      }

      // USD roll-up: native + tokens. The minimized portfolio row
      // shows totalUsd — all assets, not just the native coin.
      const gid = nativeCoinGeckoId(cfg);
      const nativeUsd =
        gid && nativePrices[gid] && total
          ? usdValue(total, nativePrices[gid])
          : null;
      const totalUsd = totalUsdOf([
        nativeUsd,
        ...tokens.map((t) => t.usd),
      ]);

      // A failed address returns { balance: null, error } — never fails
      // the whole response.
      return {
        id: cfg.id,
        label: cfg.networkLabel,
        detail: cfg.detail,
        env: cfg.env,
        unit: cfg.unit,
        watchAddresses: addresses.length,
        addresses: per,
        total,
        nativeUsd,
        totalUsd,
        tokens,
        nfts,
      };
    })
  );
  return NextResponse.json({ chains: holdings });
}
