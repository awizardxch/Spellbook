// Server-only read-only Uniswap v4 LP position proxy for /dashboard.
//
// GET returns the v4 LP positions (PositionManager NFTs) held by the
// session's bound Robinhood-mainnet watch addresses — the same wallets the
// /api/holdings route reports, scoped to chain id 4663. All chain reads are
// public eth_call / eth_getLogs against the public Robinhood RPC:
// strictly read-only, no broadcast, no signing, no key material.
//
// Discovery scans PositionManager Transfer events per wallet (topic
// filtered); pool state comes from StateView.getSlot0 — PoolManager.getSlot0
// is never called because it reverts on Robinhood's modified deployment.
// Token USD prices come from DexScreener (free, no key); native ETH from
// CoinGecko — the same sources /api/holdings uses. APR is an estimate from
// trailing swap volume and is labeled as such in the response.

import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { CHAINS } from "@/lib/chains";
import {
  SESSION_COOKIE,
  readSession,
  sessionWallets,
  type AgentAddresses,
  type Session,
  type WalletGroup,
} from "@/lib/auth";
import {
  RpcClient,
  V4_POSITION_MANAGER,
  buildPositionView,
  discoverPositions,
  selector,
  padInt,
  type DiscoveredPosition,
  type LpPositionView,
  type PriceSource,
} from "@/lib/uniswap-v4";

export const dynamic = "force-dynamic";

/** Hard cap on ?depth= — matches MAX_WATCH_ADDRESSES in lib/auth. */
const MAX_DEPTH = 100;
const TIMEOUT_MS = 10000;
const BROWSER_UA =
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

/** USDG is Robinhood Chain's canonical USD stablecoin — peg it directly. */
const STABLE_PEGS: Record<string, string> = {
  "0x5fc5360d0400a0fd4f2af552add042d716f1d168": "1.0",
};

export interface LpWalletResult {
  /** labeled wallet, e.g. "Spellbook" or "Bankr" */
  wallet: string;
  addresses: string[];
  positions: LpPositionView[];
  error?: string;
}

async function fetchJson(
  url: string,
  timeoutMs: number = TIMEOUT_MS
): Promise<unknown> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      headers: { Accept: "application/json", "User-Agent": BROWSER_UA },
      signal: ctrl.signal,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return (await res.json()) as unknown;
  } finally {
    clearTimeout(timer);
  }
}

/** Per-token DexScreener USD prices (best-effort; missing = unpriced). */
async function dexTokenPrices(
  contracts: string[]
): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  const addrs = Array.from(new Set(contracts.map((c) => c.toLowerCase())));
  const live = addrs.filter((a) => {
    const peg = STABLE_PEGS[a];
    if (peg) out.set(a, peg);
    return !peg;
  });
  const results = await Promise.all(
    live.map(async (addr) => {
      try {
        const json = (await fetchJson(
          `https://api.dexscreener.com/latest/dex/tokens/${addr}`
        )) as { pairs?: unknown };
        const pairs = Array.isArray(json.pairs) ? json.pairs : [];
        let best: { price: string; liq: number } | null = null;
        for (const p of pairs as Record<string, unknown>[]) {
          const bt = p.baseToken as { address?: unknown } | undefined;
          const pa =
            typeof bt?.address === "string" ? bt.address.toLowerCase() : "";
          if (pa !== addr) continue;
          const price = typeof p.priceUsd === "string" ? p.priceUsd : "";
          if (!price || Number(price) <= 0) continue;
          const liq = Number(
            (p.liquidity as { usd?: unknown } | undefined)?.usd ?? 0
          );
          if (!best || liq > best.liq) best = { price, liq };
        }
        return { addr, best };
      } catch {
        return { addr, best: null };
      }
    })
  );
  for (const { addr, best } of results) {
    if (best) out.set(addr, best.price);
  }
  return out;
}

let nativePriceCache: { ts: number; price: string | null } | null = null;

/** Native ETH USD via CoinGecko (60s cache, best-effort). */
async function nativeUsdPrice(): Promise<string | null> {
  const now = Date.now();
  if (nativePriceCache && now - nativePriceCache.ts < 60_000)
    return nativePriceCache.price;
  let price: string | null = null;
  try {
    const json = (await fetchJson(
      "https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd"
    )) as Record<string, { usd?: unknown }>;
    const usd = json.ethereum?.usd;
    if (typeof usd === "number" && usd > 0) price = String(usd);
  } catch {
    // keep null
  }
  nativePriceCache = { ts: now, price };
  return price;
}

/* ------------------------------------------------------------------ */
/* wallet resolution — same wallets as /api/holdings, Robinhood only  */
/* ------------------------------------------------------------------ */

function robinhoodWallets(session: Session): WalletGroup[] {
  const cfg = CHAINS.find((c) => c.id === "robinhood-mainnet");
  if (!cfg) return [];
  const wallets = sessionWallets(session);
  if (wallets.length === 0) {
    // Shared operator drill view: mainnet has no drill address configured,
    // so there is nothing to scan.
    return [];
  }
  return wallets
    .map((w) => {
      const list = w.addresses.evm_mainnet;
      return list && list.length > 0
        ? { label: w.label, addresses: { evm_mainnet: list } as AgentAddresses }
        : null;
    })
    .filter((w): w is WalletGroup => w !== null);
}

/* ------------------------------------------------------------------ */
/* discovery cache — per-process, catch-up scans only                  */
/* ------------------------------------------------------------------ */

interface WalletCache {
  /** latest block the Transfer scan has covered */
  asOfBlock: number;
  /** tokenId -> mint block, for tokens last seen held by the wallet */
  known: Map<string, number>;
}

const discoveryCache = new Map<string, WalletCache>();

/**
 * Positions held by one address, using the cache for catch-up scans.
 * Throws on scan failure so the caller can report a per-wallet error.
 */
async function positionsForAddress(
  rpc: RpcClient,
  address: string
): Promise<DiscoveredPosition[]> {
  const key = address.toLowerCase();
  const cached = discoveryCache.get(key);
  const latest = await rpc.blockNumber();
  if (latest === null) throw new Error("could not read latest block");
  const fromBlock = cached ? cached.asOfBlock : 0;
  const known = cached ? new Map(cached.known) : new Map<string, number>();

  if (fromBlock <= latest) {
    // Catch-up (or full) Transfer scan. Its netted result is authoritative
    // for tokens with events in the window; cached tokens with no window
    // events keep their entries. Stale entries (sent away / burned) are
    // pruned below by the ownerOf check, which is the source of truth.
    const delta = await discoverPositions(rpc, address, fromBlock);
    for (const d of delta) known.set(d.tokenId.toString(), d.mintBlock);
  }

  // Confirm current ownership of every candidate (burns revert ownerOf).
  const ownerSel = selector("ownerOf(uint256)");
  const held: DiscoveredPosition[] = [];
  const checks: Array<Promise<void>> = [];
  known.forEach((mintBlock, id) => {
    checks.push(
      (async () => {
        const raw = await rpc.ethCall(
          V4_POSITION_MANAGER,
          "0x" + ownerSel + padInt(BigInt(id), 256)
        );
        if (!raw || raw.length < 66) {
          known.delete(id);
          return;
        }
        if ("0x" + raw.slice(-40).toLowerCase() === key) {
          held.push({ tokenId: BigInt(id), mintBlock });
        } else {
          known.delete(id);
        }
      })()
    );
  });
  // NOTE: sequential on purpose — the RpcClient serializes anyway, and a
  // bounded loop keeps bursts off the public RPC's rate limiter.
  for (const c of checks) await c;
  discoveryCache.set(key, { asOfBlock: latest, known });
  return held;
}

/* ------------------------------------------------------------------ */

function parseDepth(raw: string | null, available: number): number {
  const fallback = Math.min(Math.max(available, 1), MAX_DEPTH);
  if (raw === null || raw.trim() === "") return fallback;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(Math.max(n, 1), MAX_DEPTH, Math.max(available, 1));
}

export async function GET(req: Request): Promise<NextResponse> {
  const session = readSession(cookies().get(SESSION_COOKIE)?.value);
  if (!session) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  const rawDepth = new URL(req.url).searchParams.get("depth");
  const groups = robinhoodWallets(session);
  const rpcUrl = CHAINS.find((c) => c.id === "robinhood-mainnet")?.rpcUrl;
  if (!rpcUrl) {
    return NextResponse.json(
      { error: "robinhood-mainnet chain not configured" },
      { status: 500 }
    );
  }
  const rpc = new RpcClient(rpcUrl, { pacingMs: 200 });
  const prices: PriceSource = {
    tokenUsd: (contracts) => dexTokenPrices(contracts),
    nativeUsd: () => nativeUsdPrice(),
  };

  const wallets: LpWalletResult[] = await Promise.all(
    groups.map(async (wg): Promise<LpWalletResult> => {
      const addresses = (wg.addresses.evm_mainnet ?? []).slice(
        0,
        parseDepth(rawDepth, wg.addresses.evm_mainnet?.length ?? 0)
      );
      const positions: LpPositionView[] = [];
      try {
        for (const address of addresses) {
          const discovered = await positionsForAddress(rpc, address);
          for (const d of discovered) {
            try {
              const view = await buildPositionView(
                rpc,
                prices,
                address,
                d.tokenId,
                d.mintBlock
              );
              if (view) positions.push(view);
            } catch {
              // one bad position never fails the wallet
            }
          }
        }
      } catch (e) {
        return {
          wallet: wg.label,
          addresses,
          positions,
          error: e instanceof Error ? e.message : "position scan failed",
        };
      }
      // Biggest position first.
      positions.sort(
        (a, b) => Number(b.valueUsd ?? -1) - Number(a.valueUsd ?? -1)
      );
      return { wallet: wg.label, addresses, positions };
    })
  );

  return NextResponse.json({
    chain: "robinhood-mainnet",
    chainId: 4663,
    positionManager: V4_POSITION_MANAGER,
    wallets,
  });
}
