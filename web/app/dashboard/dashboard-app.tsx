"use client";

import { Fragment, useCallback, useEffect, useState } from "react";
import { CHAINS, NETWORKS } from "@/lib/chains";
import "./dashboard.css";

type Tab = "portfolio" | "networks" | "activity" | "security";

interface AddressHolding {
  /** 1-based position in the agent's derivation order (#1, #2, …) */
  index: number;
  address: string;
  balance: string | null;
  error?: string;
}

interface TokenHolding {
  contract: string;
  name: string;
  symbol: string;
  decimals: number;
  /** human-readable qty summed across the addresses that loaded */
  qty: string;
  /** USD value at 2dp — null when unpriced */
  usd: string | null;
  /** DexScreener chart URL for the token's most-liquid pair — null when none */
  chartUrl: string | null;
}

interface NftHolding {
  contract: string;
  tokenId: string;
  name: string | null;
}

/** One side of a Uniswap v4 pool key. */
interface LpTokenMeta {
  address: string;
  symbol: string;
  name: string;
  decimals: number;
  isNative: boolean;
}

/** One v4 LP position, as returned by /api/lp-positions. */
interface LpPositionView {
  tokenId: string;
  owner: string;
  poolId: string;
  token0: LpTokenMeta;
  token1: LpTokenMeta;
  fee: number;
  feeLabel: string;
  tickSpacing: number;
  hooks: string;
  tickLower: number;
  tickUpper: number;
  tick: number;
  inRange: boolean;
  liquidity: string;
  amount0: string;
  amount1: string;
  priceLower: string;
  priceUpper: string;
  pct0: number | null;
  pct1: number | null;
  price0Usd: string | null;
  price1Usd: string | null;
  valueUsd: string | null;
  fees0: string;
  fees1: string;
  feesUsd: string | null;
  /** annualized percent, e.g. 38.4 = 38.4% — null when not computable */
  apr: number | null;
  /** basis label, e.g. "est. · 24h volume" — the UI always marks it estimated */
  aprBasis: string | null;
  created: string | null;
  createdBlock: number | null;
}

interface LpWallet {
  wallet: string;
  addresses: string[];
  positions: LpPositionView[];
  error?: string;
}

interface Holding {
  id: string;
  /** labeled wallet this row belongs to, e.g. "Spellbook" or "Bankr" */
  wallet: string;
  label: string;
  detail: string;
  /** "mainnet" | "testnet" */
  env: string;
  unit: string;
  /** watch addresses bound for this chain (before the depth cap) */
  watchAddresses: number;
  /** exact total across the addresses that loaded */
  total: string | null;
  /** USD value of the native total — null when unpriced */
  nativeUsd: string | null;
  /** USD value of native + all tokens — the minimized row total */
  totalUsd: string | null;
  /** fungible tokens, USD-desc (native is `total`/`unit`, always first) */
  tokens: TokenHolding[];
  nfts: NftHolding[];
  addresses: AddressHolding[];
}

/** Friendly names for native coins, by unit. */
const NATIVE_NAMES: Record<string, string> = {
  ETH: "Ethereum",
  SOL: "Solana",
  XCH: "Chia",
};

/** "1234.5" → "$1,234.50" */
function fmtUsd(v: string): string {
  const n = Number(v);
  if (!Number.isFinite(n)) return "—";
  return (
    "$" +
    n.toLocaleString("en-US", {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    })
  );
}

/** human token amount: "51130.096158" → "51,130.096"; tiny values keep sig figs */
function fmtAmt(v: string): string {
  const n = Number(v);
  if (!Number.isFinite(n)) return "—";
  if (n === 0) return "0";
  const abs = Math.abs(n);
  const dp = abs >= 1000 ? 2 : abs >= 100 ? 2 : abs >= 1 ? 4 : 6;
  return n.toLocaleString("en-US", {
    minimumFractionDigits: 0,
    maximumFractionDigits: dp,
  });
}

/** price with subscript zeros for tiny values: 0.000085 → 0.0₅85 */
function fmtPriceSub(v: string): { head: string; sub: string | null } {
  const n = Number(v);
  if (!Number.isFinite(n)) return { head: "—", sub: null };
  if (n >= 0.01 || n === 0) {
    return {
      head: n.toLocaleString("en-US", { maximumFractionDigits: 6 }),
      sub: null,
    };
  }
  const s = n.toFixed(20);
  const m = /^0\.(0+)([1-9]\d{0,3})/.exec(s);
  if (!m) {
    return {
      head: n.toLocaleString("en-US", { maximumFractionDigits: 8 }),
      sub: null,
    };
  }
  return { head: "0.0", sub: `${m[1].length}${m[2]}` };
}

/** ISO timestamp → "Sep 26, 2026" */
function fmtDate(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

/** Order a pair quote-first the way Uniswap does (native last). */
function lpOrdered(p: LpPositionView): [LpTokenMeta, LpTokenMeta] {
  return p.token0.isNative ? [p.token1, p.token0] : [p.token0, p.token1];
}

interface ActivityEntry {
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

interface AddressActivity {
  /** 1-based position in the agent's derivation order (#1, #2, …) */
  index: number;
  address: string;
  items: ActivityEntry[];
  error?: string;
}

interface ChainActivity {
  id: string;
  /** labeled wallet this group belongs to, e.g. "Spellbook" or "Bankr" */
  wallet: string;
  label: string;
  detail: string;
  env: string;
  /** what this chain's feed covers, e.g. "token transfers" */
  coverage: string;
  /** watch addresses bound for this chain (before the depth cap) */
  watchAddresses: number;
  addresses: AddressActivity[];
  error?: string;
}

/** "2026-09-22T…" → "2h ago" */
function timeAgo(iso: string | null): string {
  if (!iso) return "\u2014";
  const s = Math.max(
    0,
    Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  );
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d < 30) return `${d}d ago`;
  return iso.slice(0, 10);
}

function truncate(addr: string): string {
  if (addr.length <= 18) return addr;
  return `${addr.slice(0, 10)}…${addr.slice(-6)}`;
}

/** Stable key for one wallet × chain row. */
function wkey(wallet: string, id: string): string {
  return `${wallet}::${id}`;
}

/** Wallet badge — Bankr gets its own accent so it never blends in. */
function WalletBadge({ wallet }: { wallet: string }) {
  const bankr = wallet.toLowerCase() === "bankr";
  return (
    <span
      className={`dash-wallet${bankr ? " dash-wallet-bankr" : ""}`}
      title={bankr ? "Bankr wallet (separate from Spellbook)" : `Wallet: ${wallet}`}
    >
      {wallet}
    </span>
  );
}

export default function DashboardApp({
  role,
  pubkey,
  viewingPubkey,
}: {
  role: "agent" | "viewer";
  pubkey?: string;
  viewingPubkey?: string;
}) {
  const [tab, setTab] = useState<Tab>("portfolio");
  const [enabled, setEnabled] = useState<Record<string, boolean>>(() =>
    Object.fromEntries(
      CHAINS.map((c) => [
        c.id,
        // Human viewers start with mainnet only (testnet toggles stay
        // available in the Networks tab); agents keep everything on.
        role === "viewer" ? c.env === "mainnet" : true,
      ])
    )
  );
  const [holdings, setHoldings] = useState<Holding[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  // Uniswap v4 LP positions (Robinhood Chain only, read-only).
  const [lpWallets, setLpWallets] = useState<LpWallet[] | null>(null);
  const [lpLoading, setLpLoading] = useState(false);
  const [lpError, setLpError] = useState<string | null>(null);
  // LP rows expand in place to reveal the full position detail.
  const [expandedLp, setExpandedLp] = useState<Set<string>>(new Set());
  const [activity, setActivity] = useState<ChainActivity[] | null>(null);
  const [activityLoading, setActivityLoading] = useState(false);
  const [activityError, setActivityError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  // Network rail selection: the chain id shown in the holdings column.
  const [selectedChain, setSelectedChain] = useState<string>(    "robinhood-mainnet"
  );
  // Network rail + Networks tab selection: the chain id shown in the holdings column.
  const [assetsTab, setAssetsTab] = useState<"assets" | "lp" | "nfts">("assets");
  // How many derivation addresses per chain to query (1–100), persisted
  // per browser. The API defaults to all bound addresses when omitted.
  const [depth, setDepth] = useState<number>(() => {
    try {
      const v = parseInt(localStorage.getItem("spellbook-depth") ?? "", 10);
      return v >= 1 && v <= 100 ? v : 5;
    } catch {
      return 5;
    }
  });

  const load = useCallback(async (d: number) => {
    setLoading(true);
    setLoadError(null);
    try {
      const res = await fetch(`/api/holdings?depth=${d}`, { cache: "no-store" });
      if (!res.ok) throw new Error(`holdings API returned HTTP ${res.status}`);
      const json = (await res.json()) as { chains?: Holding[] };
      setHoldings(Array.isArray(json.chains) ? json.chains : []);
    } catch (e) {
      setLoadError(e instanceof Error ? e.message : "failed to load holdings");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load(depth);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [load]);

  // Activity is heavier per address than balances: reuse the Addresses
  // depth but the API clamps it to 10, 5 items per address.
  const loadActivity = useCallback(async () => {
    setActivityLoading(true);
    setActivityError(null);
    try {
      const d = Math.min(Math.max(depth, 1), 10);
      const res = await fetch(`/api/activity?depth=${d}&limit=5`, {
        cache: "no-store",
      });
      if (!res.ok) throw new Error(`activity API returned HTTP ${res.status}`);
      const json = (await res.json()) as { chains?: ChainActivity[] };
      setActivity(Array.isArray(json.chains) ? json.chains : []);
    } catch (e) {
      setActivityError(e instanceof Error ? e.message : "failed to load activity");
    } finally {
      setActivityLoading(false);
    }
  }, [depth]);

  useEffect(() => {
    if (tab === "activity") loadActivity();
  }, [tab, loadActivity]);

  // LP positions load with the portfolio tab (first paint) and on Refresh /
  // depth change. The scan is cheap for empty wallets and cached per address.
  const loadLp = useCallback(async (d: number) => {
    setLpLoading(true);
    setLpError(null);
    try {
      const res = await fetch(`/api/lp-positions?depth=${d}`, {
        cache: "no-store",
      });
      if (!res.ok)
        throw new Error(`lp-positions API returned HTTP ${res.status}`);
      const json = (await res.json()) as { wallets?: LpWallet[] };
      setLpWallets(Array.isArray(json.wallets) ? json.wallets : []);
    } catch (e) {
      setLpError(
        e instanceof Error ? e.message : "failed to load LP positions"
      );
      setLpWallets([]);
    } finally {
      setLpLoading(false);
    }
  }, []);

  useEffect(() => {
    loadLp(depth);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loadLp]);

  const refreshAll = useCallback(
    (d: number) => {
      load(d);
      loadLp(d);
    },
    [load, loadLp]
  );

  const changeDepth = useCallback(
    (d: number) => {
      const next = Math.min(Math.max(d, 1), 100);
      setDepth(next);
      try {
        localStorage.setItem("spellbook-depth", String(next));
      } catch {
        /* storage unavailable — no-op */
      }
      load(next);
      loadLp(next);
    },
    [load, loadLp]
  );

  const copy = useCallback(async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
      setTimeout(() => setCopied((cur) => (cur === key ? null : cur)), 1500);
    } catch {
      /* clipboard unavailable — no-op */
    }
  }, []);

  const toggle = useCallback((id: string) => {
    setEnabled((prev) => ({ ...prev, [id]: !prev[id] }));
  }, []);

  const holdingsFor = (id: string) =>
    (holdings ?? []).filter((h) => h.id === id);
  const enabledChains = CHAINS.filter((c) => enabled[c.id]);
  // The rail selection may point at a chain that was just toggled off —
  // fall back to the first enabled chain so rail + holdings never disagree.
  const selCfg =
    CHAINS.find((c) => c.id === selectedChain && enabled[c.id]) ??
    enabledChains[0] ??
    null;
  const activeId = selCfg?.id ?? null;
  const selHoldings = activeId ? holdingsFor(activeId) : [];
  // LP positions only exist on Robinhood Chain: the LP tab is hidden
  // elsewhere, and this fallback keeps a selected tab visible.
  const viewTab =
    assetsTab === "lp" && activeId !== "robinhood-mainnet"
      ? "assets"
      : assetsTab;
  const selUsd = selHoldings.reduce(
    (s, h) => s + (h.totalUsd != null ? Number(h.totalUsd) : 0),
    0
  );
  const selPriced = selHoldings.some((h) => h.totalUsd != null);
  const enabledCount = CHAINS.filter((c) => enabled[c.id]).length;

  /* ---------------- dashboard ---------------- */

  return (
    <div className="wrap">
      <nav className="nav dash-nav" data-circuit-rail="navigation">
        <a className="brand" href="/">
          <span className="brand-mark">🪄</span>
          <span className="brand-name">Spellbook</span>
        </a>
        <div className="nav-links bar-scroll">
          <a href="/">Home</a>
          <span className="dash-session">
            {role === "agent"
              ? `🧙 agent ${pubkey ? `${pubkey.slice(0, 4)}…${pubkey.slice(-4)}` : ""}`
              : viewingPubkey
                ? `👁️ agent ${viewingPubkey.slice(0, 4)}…${viewingPubkey.slice(-4)}`
                : "👁️ viewer"}
          </span>
          <button
            className="btn ghost dash-logout"
            type="button"
            onClick={async () => {
              try {
                await fetch("/api/auth/logout", { method: "POST" });
              } finally {
                window.location.reload();
              }
            }}
          >
            Log out
          </button>
        </div>
      </nav>

      <div className="dash-tabs bar-scroll" role="tablist" aria-label="Dashboard sections" data-circuit-rail="tabs">
        {(
          [
            ["portfolio", "Portfolio"],
            ["networks", "Networks"],
            ["activity", "Activity"],
            ["security", "Security"],
          ] as [Tab, string][]
        ).map(([id, label]) => (
          <button
            key={id}
            role="tab"
            aria-selected={tab === id}
            className={`dash-tab${tab === id ? " active" : ""}`}
            type="button"
            onClick={() => setTab(id)}
          >
            {label}
            {id === "activity" && <span className="dash-badge live">live</span>}
          </button>
        ))}
      </div>

      {tab === "portfolio" && (
        <section className="dash-portfolio">
          {/* left: network rail — click-to-select network list */}
          <div className="dash-panel dash-rail">
            <div className="dash-rail-head">
              <h2>Networks</h2>
              <span className="dash-chip" title="Chains enabled">
                {enabledCount} / {CHAINS.length}
              </span>
            </div>
            <ul
              className="dash-raillist"
              role="listbox"
              aria-label="Select network"
            >
              {enabledChains.map((cfg) => {
                const hs = holdingsFor(cfg.id);
                const usdSum = hs.reduce(
                  (s, h) => s + (h.totalUsd != null ? Number(h.totalUsd) : 0),
                  0
                );
                const priced = hs.some((h) => h.totalUsd != null);
                const active = activeId === cfg.id;
                return (
                  <li
                    key={cfg.id}
                    className={`dash-railitem${active ? " active" : ""}`}
                  >
                    <button
                      type="button"
                      role="option"
                      aria-selected={active}
                      className="dash-railrow"
                      title={`${cfg.networkLabel} ${cfg.env} — view holdings`}
                      onClick={() => {
                        setSelectedChain(cfg.id);
                      }}
                    >
                      <span
                        className="dash-dot"
                        style={{ background: cfg.color }}
                      />
                      <span className="dash-railname">
                        <span>{cfg.networkLabel}</span>
                        <span className="dash-sub">
                          {cfg.env === "mainnet" ? "Mainnet" : "Testnet"}
                        </span>
                      </span>
                      <span className="dash-railbal">
                        {holdings ? (
                          priced ? (
                            fmtUsd(String(usdSum))
                          ) : (
                            <span className="dash-muted">—</span>
                          )
                        ) : (
                          <span className="dash-muted">…</span>
                        )}
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
            <p className="dash-note">
              Select a network to view its holdings. Strictly read-only —
              this page cannot approve, sign, or broadcast anything.
            </p>
          </div>

          {/* right: holdings for the selected network */}
          <div className="dash-panel dash-holdings">
            {selCfg ? (
              <>
                {loadError && (
                  <p className="dash-error">
                    Couldn&apos;t reach the holdings API: {loadError}
                  </p>
                )}

                <div className="dash-holdmeta">
                  <div className="dash-holdbal">
                    <span className="dash-sub">Balance</span>
                    <strong>
                      {holdings ? (
                        selPriced ? (
                          fmtUsd(String(selUsd))
                        ) : (
                          <span className="dash-muted">—</span>
                        )
                      ) : (
                        <span className="dash-muted">…</span>
                      )}
                    </strong>
                  </div>
                  <div className="dash-holdwallets">
                    {selHoldings.map((h) => {
                      const a0 = h.addresses[0];
                      const ck = `sel-${wkey(h.wallet, h.id)}`;
                      return (
                        <div
                          key={wkey(h.wallet, h.id)}
                          className="dash-holdwallet"
                        >
                          <WalletBadge wallet={h.wallet} />
                          {a0 ? (
                            <>
                              <code title={a0.address}>
                                {truncate(a0.address)}
                              </code>
                              <button
                                className="dash-copy"
                                type="button"
                                onClick={() => copy(a0.address, ck)}
                                aria-label={`Copy ${h.wallet} ${h.label} address`}
                              >
                                {copied === ck ? "✓" : "⧉"}
                              </button>
                            </>
                          ) : (
                            <span className="dash-muted">no addresses</span>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>

                <div className="dash-seg-row">
                  <div
                    className="dash-seg"
                    role="tablist"
                    aria-label={`${selCfg.networkLabel} holdings view`}
                  >
                    <button
                      type="button"
                      role="tab"
                      aria-selected={viewTab === "assets"}
                      className={`dash-segbtn${
                        viewTab === "assets" ? " on" : ""
                      }`}
                      onClick={() => setAssetsTab("assets")}
                    >
                      Tokens
                    </button>
                    {activeId === "robinhood-mainnet" && (
                      <button
                        type="button"
                        role="tab"
                        aria-selected={viewTab === "lp"}
                        className={`dash-segbtn${
                          viewTab === "lp" ? " on" : ""
                        }`}
                        onClick={() => setAssetsTab("lp")}
                      >
                        LP
                        {(lpWallets ?? []).some((w) => w.positions.length > 0)
                          ? ` (${(lpWallets ?? []).reduce(
                              (n, w) => n + w.positions.length,
                              0
                            )})`
                          : ""}
                      </button>
                    )}
                    <button
                      type="button"
                      role="tab"
                      aria-selected={viewTab === "nfts"}
                      className={`dash-segbtn${
                        viewTab === "nfts" ? " on" : ""
                      }`}
                      onClick={() => setAssetsTab("nfts")}
                    >
                      NFTs
                      {selHoldings.some((h) => h.nfts.length > 0)
                        ? ` (${selHoldings.reduce(
                            (n, h) => n + h.nfts.length,
                            0
                          )})`
                        : ""}
                    </button>
                  </div>
                  <div className="dash-seg-actions">
                    <div
                      className="dash-depth"
                      title="How many derivation addresses per chain to query (1–100)"
                    >
                      <span className="dash-depth-label">Addresses</span>
                      <button
                        className="dash-depth-btn"
                        type="button"
                        onClick={() => changeDepth(depth - 1)}
                        disabled={loading || depth <= 1}
                        aria-label="Fewer addresses"
                      >
                        −
                      </button>
                      <span className="dash-depth-num">{depth}</span>
                      <button
                        className="dash-depth-btn"
                        type="button"
                        onClick={() => changeDepth(depth + 1)}
                        disabled={loading || depth >= 100}
                        aria-label="More addresses"
                      >
                        +
                      </button>
                    </div>
                    <button
                      className="btn ghost dash-refresh"
                      type="button"
                      onClick={() => refreshAll(depth)}
                      disabled={loading || lpLoading}
                    >
                      {loading || lpLoading ? "Refreshing…" : "Refresh"}
                    </button>
                  </div>
                </div>

                <details className="dash-addrs">
                  <summary>
                    Addresses (
                    {selHoldings.reduce((n, h) => n + h.addresses.length, 0)}{" "}
                    of{" "}
                    {selHoldings.reduce((n, h) => n + h.watchAddresses, 0)})
                  </summary>
                  {selHoldings.length > 0 && (
                    <ul className="dash-addrlist">
                      {selHoldings.flatMap((h) =>
                        h.addresses.map((a, i) => {
                          const ck = `addr-${wkey(h.wallet, h.id)}-${i}`;
                          return (
                            <li key={ck}>
                              <WalletBadge wallet={h.wallet} />
                              <span className="dash-idx">#{a.index}</span>
                              <code title={a.address}>
                                {truncate(a.address)}
                              </code>
                              <button
                                className="dash-copy"
                                type="button"
                                onClick={() => copy(a.address, ck)}
                                aria-label={`Copy ${h.wallet} ${h.label} address #${a.index}`}
                              >
                                {copied === ck ? "✓" : "⧉"}
                              </button>
                              <span className="dash-num">
                                {a.balance !== null ? (
                                  <>
                                    {a.balance}{" "}
                                    <span className="dash-unit">{h.unit}</span>
                                  </>
                                ) : (
                                  <span className="dash-muted">—</span>
                                )}
                              </span>
                              {a.balance !== null ? (
                                <span className="dash-ok">●</span>
                              ) : (
                                <span
                                  className="dash-warn"
                                  title={a.error ?? "unavailable"}
                                >
                                  ●
                                </span>
                              )}
                            </li>
                          );
                        })
                      )}
                    </ul>
                  )}
                </details>

                {viewTab === "assets" ? (
                  <div className="dash-tablewrap">
                    <table className="dash-table">
                      <thead>
                        <tr>
                          <th>Token</th>
                          <th>Balance</th>
                          <th>Value</th>
                          <th>PnL</th>
                          <th>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {selHoldings.map((h) => {
                          const key = wkey(h.wallet, h.id);
                          const cfg = CHAINS.find((c) => c.id === h.id);
                          return (
                            <Fragment key={key}>
                              {h.total !== null && (
                                <tr>
                                  <td>
                                    <span
                                      className="dash-dot"
                                      style={{
                                        background: cfg?.color ?? "#8b5cf6",
                                      }}
                                    />
                                    {NATIVE_NAMES[h.unit] ?? h.unit}{" "}
                                    <WalletBadge wallet={h.wallet} />
                                    <span className="dash-sub">
                                      {h.unit} · native
                                    </span>
                                  </td>
                                  <td className="dash-num">
                                    {h.total}{" "}
                                    <span className="dash-unit">{h.unit}</span>
                                  </td>
                                  <td className="dash-num">
                                    {h.nativeUsd != null ? (
                                      fmtUsd(h.nativeUsd)
                                    ) : (
                                      <span className="dash-muted">—</span>
                                    )}
                                  </td>
                                  <td>
                                    <span className="dash-muted">—</span>
                                  </td>
                                  <td />
                                </tr>
                              )}
                              {h.tokens.map((t) => (
                                <tr key={t.contract}>
                                  <td>
                                    <span className="dash-dot dash-dot-token" />
                                    {t.name}{" "}
                                    <WalletBadge wallet={h.wallet} />
                                    <span className="dash-sub">{t.symbol}</span>
                                  </td>
                                  <td className="dash-num">
                                    {t.qty}{" "}
                                    <span className="dash-unit">
                                      {t.symbol}
                                    </span>
                                  </td>
                                  <td className="dash-num">
                                    {t.usd != null ? (
                                      fmtUsd(t.usd)
                                    ) : (
                                      <span
                                        className="dash-muted"
                                        title="no price feed for this token"
                                      >
                                        unpriced
                                      </span>
                                    )}
                                  </td>
                                  <td>
                                    <span className="dash-muted">—</span>
                                  </td>
                                  <td>
                                    {t.chartUrl && (
                                      <a
                                        href={t.chartUrl}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="dash-chart-link"
                                        title={`Open ${t.symbol} chart (most liquid pool)`}
                                        aria-label={`Open ${t.symbol} chart in a new tab`}
                                      >
                                        <svg
                                          width="14"
                                          height="14"
                                          viewBox="0 0 24 24"
                                          fill="none"
                                          stroke="currentColor"
                                          strokeWidth="2"
                                          strokeLinecap="round"
                                          strokeLinejoin="round"
                                          aria-hidden="true"
                                        >
                                          <path d="M3 3v18h18" />
                                          <path d="M7 15l4-6 4 3 5-8" />
                                        </svg>
                                      </a>
                                    )}
                                  </td>
                                </tr>
                              ))}
                            </Fragment>
                          );
                        })}
                      </tbody>
                    </table>
                    {!loading && selHoldings.length === 0 && (
                      <p className="dash-note">
                        No balances loaded for this chain.
                      </p>
                    )}
                  </div>
                ) : viewTab === "lp" ? (
                <div className="dash-lpblock">
                  <div className="dash-lpblock-head">
                    <div>
                      <h3>LP positions</h3>
                      <p>
                        Uniswap v4 positions on Robinhood Chain, grouped by
                        wallet · read-only. APR is estimated from trailing
                        swap volume.
                      </p>
                    </div>
                    <div className="dash-actions">
                      <button
                        className="btn ghost dash-refresh"
                        type="button"
                        onClick={() => loadLp(depth)}
                        disabled={lpLoading}
                      >
                        {lpLoading ? "Scanning…" : "Rescan"}
                      </button>
                      <span className="dash-chip" title="v4 positions held">
                        {lpWallets
                          ? `${lpWallets.reduce(
                              (n, w) => n + w.positions.length,
                              0
                            )} positions`
                          : "—"}
                      </span>
                    </div>
                  </div>
                  {lpError && <p className="dash-error">{lpError}</p>}
                  <div className="dash-tablewrap">
                    <table className="dash-table">
                      <thead>
                        <tr>
                          <th>Pool</th>
                          <th>Position</th>
                          <th>Distribution</th>
                          <th>Value</th>
                          <th>Fees</th>
                          <th>APR</th>
                          <th>Created</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(lpWallets ?? []).map((w) => {
                          if (w.error) {
                            return (
                              <tr key={w.wallet}>
                                <td colSpan={7}>
                                  <WalletBadge wallet={w.wallet} />
                                  <span className="dash-warn">
                                    {w.error}
                                  </span>
                                </td>
                              </tr>
                            );
                          }
                          return (
                            <Fragment key={w.wallet}>
                              {w.positions.map((p) => {
                                const [base, quote] = lpOrdered(p);
                                const lo = fmtPriceSub(p.priceLower);
                                const hi = fmtPriceSub(p.priceUpper);
                                // pct0/pct1 follow token0/token1; display
                                // follows base/quote order (native always
                                // quoted second).
                                const pBase = p.token0.isNative
                                  ? p.pct1
                                  : p.pct0;
                                const pQuote = p.token0.isNative
                                  ? p.pct0
                                  : p.pct1;
                                const hasDist =
                                  pBase !== null && pQuote !== null;
                                const wBase = hasDist ? (pBase as number) : 0;
                                const wQuote = hasDist
                                  ? (pQuote as number)
                                  : 0;
                                // Amounts follow token0/token1; display them
                                // in base/quote order to match the pool name.
                                const baseAmt = p.token0.isNative
                                  ? p.amount1
                                  : p.amount0;
                                const quoteAmt = p.token0.isNative
                                  ? p.amount0
                                  : p.amount1;
                                const baseFees = p.token0.isNative
                                  ? p.fees1
                                  : p.fees0;
                                const quoteFees = p.token0.isNative
                                  ? p.fees0
                                  : p.fees1;
                                const lpKey = `${p.owner}-${p.tokenId}`;
                                const open = expandedLp.has(lpKey);
                                const toggleLp = () => {
                                  setExpandedLp((prev) => {
                                    const next = new Set(prev);
                                    if (next.has(lpKey)) next.delete(lpKey);
                                    else next.add(lpKey);
                                    return next;
                                  });
                                };
                                return (
                                  <Fragment key={lpKey}>
                                    <tr
                                      className={`lp-row${
                                        open ? " open" : ""
                                      }`}
                                      onClick={toggleLp}
                                      title={
                                        open
                                          ? "Collapse position detail"
                                          : "Expand position detail"
                                      }
                                    >
                                      <td>
                                        <span className="dash-num">
                                          {base.symbol}/{quote.symbol}
                                        </span>{" "}
                                        <WalletBadge wallet={w.wallet} />
                                        <span className="dash-sub">
                                          v4 · {p.feeLabel}
                                        </span>
                                      </td>
                                      <td>
                                        <span
                                          className={
                                            p.inRange
                                              ? "dash-ok"
                                              : "dash-warn"
                                          }
                                          title={
                                            p.inRange
                                              ? "Current price is inside this range"
                                              : "Current price is outside this range — the position earns no fees"
                                          }
                                        >
                                          ●{" "}
                                          {p.inRange
                                            ? "in range"
                                            : "out of range"}
                                        </span>
                                        <span className="dash-sub">
                                          {lo.head}
                                          {lo.sub && (
                                            <sub className="lp-sub">
                                              {lo.sub}
                                            </sub>
                                          )}
                                          {" → "}
                                          {hi.head}
                                          {hi.sub && (
                                            <sub className="lp-sub">
                                              {hi.sub}
                                            </sub>
                                          )}{" "}
                                          {quote.symbol}
                                        </span>
                                      </td>
                                      <td>
                                        {hasDist ? (
                                          <>
                                            <span
                                              className="lp-dist"
                                              title={`${wBase.toFixed(1)}% ${
                                                base.symbol
                                              } · ${wQuote.toFixed(1)}% ${
                                                quote.symbol
                                              }`}
                                            >
                                              <span
                                                className="lp-dist-a"
                                                style={{ width: `${wBase}%` }}
                                              />
                                              <span
                                                className="lp-dist-b"
                                                style={{ width: `${wQuote}%` }}
                                              />
                                            </span>
                                            <span className="dash-sub">
                                              {wBase.toFixed(1)}% {base.symbol}{" "}
                                              · {wQuote.toFixed(1)}%{" "}
                                              {quote.symbol}
                                            </span>
                                          </>
                                        ) : (
                                          <span className="dash-sub">—</span>
                                        )}
                                      </td>
                                      <td>
                                        <span className="dash-num">
                                          {p.valueUsd !== null
                                            ? fmtUsd(p.valueUsd)
                                            : "—"}
                                        </span>
                                      </td>
                                      <td>
                                        <span className="dash-num">
                                          {p.feesUsd !== null
                                            ? fmtUsd(p.feesUsd)
                                            : "—"}
                                        </span>
                                      </td>
                                      <td>
                                        <span className="dash-num">
                                          {p.apr !== null
                                            ? `${p.apr.toFixed(2)}%`
                                            : "—"}
                                        </span>
                                      </td>
                                      <td>
                                        <span className="dash-num">
                                          {fmtDate(p.created)}
                                        </span>
                                      </td>
                                    </tr>
                                    {open && (
                                      <tr className="lp-detail">
                                        <td colSpan={7}>
                                          <div className="lp-detail-grid">
                                            <div>
                                              <span className="lp-detail-label">
                                                Position
                                              </span>
                                              <span className="dash-num">
                                                {p.valueUsd !== null
                                                  ? fmtUsd(p.valueUsd)
                                                  : "—"}
                                              </span>
                                              <span className="dash-sub">
                                                {fmtAmt(baseAmt)}{" "}
                                                {base.symbol} +{" "}
                                                {fmtAmt(quoteAmt)}{" "}
                                                {quote.symbol}
                                              </span>
                                              {hasDist && (
                                                <span className="dash-sub">
                                                  {wBase.toFixed(1)}%{" "}
                                                  {base.symbol} ·{" "}
                                                  {wQuote.toFixed(1)}%{" "}
                                                  {quote.symbol}
                                                </span>
                                              )}
                                            </div>
                                            <div>
                                              <span className="lp-detail-label">
                                                Fees earned (unclaimed)
                                              </span>
                                              <span className="dash-num">
                                                {p.feesUsd !== null
                                                  ? fmtUsd(p.feesUsd)
                                                  : "—"}
                                              </span>
                                              <span className="dash-sub">
                                                {fmtAmt(baseFees)}{" "}
                                                {base.symbol} +{" "}
                                                {fmtAmt(quoteFees)}{" "}
                                                {quote.symbol}
                                              </span>
                                            </div>
                                            <div>
                                              <span className="lp-detail-label">
                                                Range
                                              </span>
                                              <span className="dash-sub">
                                                ticks {p.tickLower} →{" "}
                                                {p.tickUpper}
                                              </span>
                                              <span className="dash-sub">
                                                token #{p.tokenId} · Robinhood
                                                Chain
                                              </span>
                                              {p.aprBasis && (
                                                <span
                                                  className="dash-sub"
                                                  title={`Estimate — ${p.aprBasis}`}
                                                >
                                                  APR est. · {p.aprBasis}
                                                </span>
                                              )}
                                            </div>
                                          </div>
                                        </td>
                                      </tr>
                                    )}
                                  </Fragment>
                                );
                              })}
                            </Fragment>
                          );
                        })}
                      </tbody>
                    </table>
                    {!lpLoading && (lpWallets ?? []).length === 0 && (
                      <p className="dash-note">
                        No Uniswap v4 LP positions found in the configured
                        dashboard wallets.
                      </p>
                    )}
                    {!lpLoading &&
                      (lpWallets ?? []).length > 0 &&
                      (lpWallets ?? []).every(
                        (w) => w.positions.length === 0
                      ) && (
                        <p className="dash-note">
                          No Uniswap v4 LP positions found in the configured
                          dashboard wallets.
                        </p>
                      )}
                    {lpLoading && lpWallets === null && (
                      <p className="dash-note">Scanning PositionManager…</p>
                    )}
                  </div>
                  <p className="dash-note">
                    Positions are discovered from PositionManager Transfer
                    events and verified by ownerOf · state via StateView ·
                    APR is an estimate from recent pool swap volume, not a
                    guarantee.
                  </p>
                </div>
                ) : selHoldings.some((h) => h.nfts.length > 0) ? (
                  <div className="dash-tablewrap">
                    <ul className="dash-nftlist">
                      {selHoldings.flatMap((h) =>
                        h.nfts.map((n) => (
                          <li
                            key={`${h.wallet}:${n.contract}:${n.tokenId}`}
                            className="dash-nft"
                          >
                            <WalletBadge wallet={h.wallet} />
                            <span className="dash-nft-name">
                              {n.name ?? "Unknown collection"}
                            </span>
                            <span className="dash-sub">#{n.tokenId}</span>
                            <code title={n.contract}>
                              {truncate(n.contract)}
                            </code>
                          </li>
                        ))
                      )}
                    </ul>
                  </div>
                ) : (
                  <p className="dash-note">
                    No NFTs found in the recent activity window. Discovery
                    scans recent inbound transfers — older holdings may not
                    appear.
                  </p>
                )}
              </>
            ) : (
              <p className="dash-note">
                All chains are toggled off — enable at least one from the
                network list.
              </p>
            )}
          </div>
        </section>
      )}

      {tab === "networks" && (
        <section>
          <div className="dash-panel">
            <div className="dash-panel-head">
              <div>
                <h2>Networks</h2>
                <p>
                  Choose which networks the dashboard interacts with and
                  displays — toggling immediately refilters the Portfolio.
                </p>
              </div>
            </div>
            <div className="dash-netlist">
              {NETWORKS.map((net) => {
                const pair = (["mainnet", "testnet"] as const).map(
                  (env) => net.chains.find((c) => c.env === env)!
                );
                const anyOn = pair.some((cfg) => enabled[cfg.id]);
                const firstOn =
                  pair.find((cfg) => enabled[cfg.id]) ?? pair[0];
                return (
                  <div
                    key={net.id}
                    className={`dash-card dash-netrow${anyOn ? "" : " off"}`}
                  >
                    <span
                      className="dash-dot dash-dot-lg"
                      style={{ background: pair[0].color }}
                    />
                    <button
                      type="button"
                      className="dash-netinfo"
                      title={`View ${net.label} holdings`}
                      onClick={() => {
                        if (!enabled[firstOn.id]) toggle(firstOn.id);
                        setSelectedChain(firstOn.id);
                        setTab("portfolio");
                      }}
                    >
                      <strong>{net.label}</strong>
                      <span className="dash-sub">
                        {pair[0].detail} · {pair[1].detail}
                      </span>
                    </button>
                    <div className="dash-netenvs">
                      {pair.map((cfg) => {
                        const hs = holdingsFor(cfg.id);
                        const on = enabled[cfg.id];
                        const firstError = hs
                          .flatMap((h) => h.addresses)
                          .find((a) => a.error)?.error;
                        return (
                          <div
                            key={cfg.id}
                            className={`dash-netenv${on ? "" : " off"}${
                              activeId === cfg.id ? " sel" : ""
                            }`}
                            role="button"
                            tabIndex={0}
                            title={`View ${net.label} ${cfg.env} holdings`}
                            aria-label={`View ${net.label} ${cfg.env} holdings`}
                            onClick={() => {
                              if (!enabled[cfg.id]) toggle(cfg.id);
                              setSelectedChain(cfg.id);
                              setTab("portfolio");
                            }}
                            onKeyDown={(e) => {
                              if (e.key === "Enter" || e.key === " ") {
                                e.preventDefault();
                                if (!enabled[cfg.id]) toggle(cfg.id);
                                setSelectedChain(cfg.id);
                                setTab("portfolio");
                              }
                            }}
                          >
                            <span
                              className={`dash-envtag dash-env-${cfg.env}`}
                            >
                              {cfg.env === "mainnet" ? "Mainnet" : "Testnet"}
                            </span>
                            <span
                              className="dash-netbal"
                              title={firstError ?? undefined}
                            >
                              {hs.length > 0 ? (
                                hs.map((h) => (
                                  <span
                                    key={wkey(h.wallet, h.id)}
                                    className="dash-netwal"
                                  >
                                    <WalletBadge wallet={h.wallet} />
                                    {h.total != null ? (
                                      <span className="dash-netbalv">
                                        {h.total}{" "}
                                        <span className="dash-unit">
                                          {h.unit}
                                        </span>
                                      </span>
                                    ) : (
                                      <span className="dash-muted">
                                        {holdings ? "unavailable" : "…"}
                                      </span>
                                    )}
                                  </span>
                                ))
                              ) : (
                                <span className="dash-muted">
                                  {holdings ? "unavailable" : "…"}
                                </span>
                              )}
                            </span>
                            <button
                              role="switch"
                              aria-checked={on}
                              aria-label={`Toggle ${net.label} ${cfg.env}`}
                              className={`dash-switch${on ? " on" : ""}`}
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                toggle(cfg.id);
                              }}
                            >
                              <span className="dash-knob" />
                            </button>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>
            <p className="dash-note">
              Each side toggles independently and immediately refilters the
              Portfolio. Base Sepolia and ETH Sepolia read 0 until funded
              there. Chia mainnet reads through its own relay — without{" "}
              <code>SPELLBOOK_RELAY_URL_MAINNET</code> it shows unavailable.
              Everything here is read-only: the dashboard never signs or
              broadcasts.
            </p>
          </div>
        </section>
      )}

      {tab === "activity" && (
        <section>
          <div className="dash-panel">
            <div className="dash-panel-head">
              <div>
                <h2>Activity</h2>
                <p>
                  <span className="dash-badge live">live &middot; on-chain</span>{" "}
                  Recent transfers for your watch addresses, pulled straight
                  from chain data.
                </p>
              </div>
              <div className="dash-actions">
                <button
                  className="btn ghost dash-refresh"
                  type="button"
                  onClick={() => loadActivity()}
                  disabled={activityLoading}
                >
                  {activityLoading ? "Refreshing\u2026" : "Refresh"}
                </button>
              </div>
            </div>

            {activityError && (
              <p className="dash-error">
                Couldn&apos;t reach the activity API: {activityError}
              </p>
            )}

            {!activity && !activityError && (
              <p className="dash-muted">
                {activityLoading ? "Loading on-chain activity\u2026" : "\u2014"}
              </p>
            )}

            {activity && activity.length === 0 && (
              <p className="dash-muted">No chains bound to this session.</p>
            )}

            {activity &&
              activity.map((c) => (
                <div
                  key={wkey(c.wallet, c.id)}
                  className="dash-card dash-agroup"
                >
                  <div className="dash-agroup-head">
                    <span className="dash-anet">{c.label}</span>
                    <span className={`dash-envtag e-${c.env}`}>{c.env}</span>
                    <WalletBadge wallet={c.wallet} />
                    <span className="dash-coverage">{c.coverage}</span>
                  </div>
                  {c.addresses.map((a) => (
                    <div key={a.address} className="dash-aaddr">
                      <button
                        className="dash-addrline"
                        type="button"
                        title="Copy address"
                        onClick={() =>
                          copy(
                            a.address,
                            `act-${wkey(c.wallet, c.id)}-${a.index}`
                          )
                        }
                      >
                        #{a.index} {truncate(a.address)}{" "}
                        {copied === `act-${wkey(c.wallet, c.id)}-${a.index}`
                          ? "\u2713"
                          : ""}
                      </button>
                      {a.error && <p className="dash-aerror">{a.error}</p>}
                      {a.items.length === 0 && !a.error && (
                        <p className="dash-amuted">No recent activity.</p>
                      )}
                      {a.items.length > 0 && (
                        <ul className="dash-alist">
                          {a.items.map((it) => (
                            <li key={it.id} className="dash-arow">
                              <span
                                className={`dash-dir d-${it.kind}`}
                                title={it.kind === "in" ? "received" : "sent"}
                              >
                                {it.kind === "in" ? "\u2193" : "\u2191"}
                              </span>
                              <span className="dash-aamount">
                                {it.kind === "in" ? "+" : "\u2212"}
                                {it.amount} {it.unit}
                              </span>
                              <span
                                className="dash-acp"
                                title={it.counterparty}
                              >
                                {it.counterparty === "\u2014"
                                  ? ""
                                  : truncate(it.counterparty)}
                              </span>
                              <span className="dash-awhen">
                                {timeAgo(it.time)}
                              </span>
                              {it.explorerUrl && (
                                <a
                                  className="dash-ax"
                                  href={it.explorerUrl}
                                  target="_blank"
                                  rel="noreferrer"
                                  title="View on explorer"
                                >
                                  \u2197
                                </a>
                              )}
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  ))}
                </div>
              ))}
            <p className="dash-note">
              EVM shows token transfers only &mdash; plain native transfers
              need an explorer API key. Solana shows full history; Chia via
              Spacescan.
            </p>
          </div>
        </section>
      )}

      {tab === "security" && (
        <SecurityPanel />
      )}

      <footer className="footer">
        <span>
          Spellbook — the agent&apos;s wallet. Forged in the Nightspire.
        </span>
        <div className="links">
          <a href="/">Home</a>
          <a href="/onboard">Onboard</a>
        </div>
      </footer>
    </div>
  );
}

/**
 * Security panel — MetaMask-style key backup UI.
 * Human-authenticated only. The agent cannot access these endpoints.
 */
function SecurityPanel() {
  const [revealed, setRevealed] = useState<{
    mnemonic?: string;
    evmKey?: string;
    chiaKey?: string;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [hotWalletStatus, setHotWalletStatus] = useState<{
    initialized: boolean;
    address?: string;
  } | null>(null);

  // Load hot wallet status on mount
  useEffect(() => {
    fetch("/api/security/hot-wallet", { credentials: "include" })
      .then((r) => r.json())
      .then(setHotWalletStatus)
      .catch(() => setHotWalletStatus({ initialized: false }));
  }, []);

  const reveal = async (type: "mnemonic" | "evm-key" | "chia-key") => {
    setLoading(true);
    setError(null);
    try {
      // No password: your viewer session is the credential (the agent's
      // own session can never pass the server's role check). Keys are
      // derived per chain — the EVM key below is the Robinhood mainnet
      // key (evm-4663), the actual key controlling the wallet.
      const res = await fetch(`/api/security/reveal`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ type }),
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || "Reveal failed");
      }
      const data = await res.json();
      setRevealed((prev) => ({ ...prev, [type === "mnemonic" ? "mnemonic" : type === "evm-key" ? "evmKey" : "chiaKey"]: data.value }));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Reveal failed");
    } finally {
      setLoading(false);
    }
  };

  const hideAll = () => {
    setRevealed(null);
    setError(null);
  };

  return (
    <section className="dash-security">
      <div className="dash-panel">
        <h2>Security &amp; Backup</h2>
        <p className="dash-note">
          Your keys control your funds. Back them up NOW on paper, offline.
          The agent cannot see this page — only you (the human) can reveal keys.
        </p>

        {hotWalletStatus && (
          <div className="dash-security-status">
            <h3>Hot Wallet (for automation)</h3>
            {hotWalletStatus.initialized ? (
              <p>
                ✓ Initialized: <code>{hotWalletStatus.address}</code>
                <br />
                <span className="dash-note">
                  The agent uses this for automated transactions. It persists across VM wipes.
                </span>
              </p>
            ) : (
              <p>
                ✗ Not initialized.
                <br />
                <span className="dash-note">
                  Run: <code>python3 -m spellbook.hotwallet setup</code> (see docs/UPGRADE_GUIDE.md)
                </span>
              </p>
            )}
          </div>
        )}

        <div className="dash-security-reveal">
          <h3>Reveal Keys</h3>
          <p className="dash-note">
            Signed in as the human viewer — one tap reveals. Keys are shown
            once — write them down immediately, then Hide.
          </p>
          {error && <p className="dash-error">{error}</p>}

          <div className="dash-security-buttons">
            <button
              onClick={() => reveal("mnemonic")}
              disabled={loading}
              className="dash-button"
            >
              {loading ? "Revealing…" : "Reveal Master Seed (24 words)"}
            </button>
            <button
              onClick={() => reveal("evm-key")}
              disabled={loading}
              className="dash-button"
            >
              {loading ? "Revealing…" : "Reveal EVM Private Key (Robinhood)"}
            </button>
            <button
              onClick={() => reveal("chia-key")}
              disabled={loading}
              className="dash-button"
            >
              {loading ? "Revealing…" : "Reveal Chia Private Key (testnet)"}
            </button>
          </div>

          {revealed && (
            <div className="dash-security-revealed">
              <h4>⚠️ Write these down NOW, then click Hide</h4>
              {revealed.mnemonic && (
                <div>
                  <strong>Master Seed (24 words):</strong>
                  <p className="dash-mnemonic">{revealed.mnemonic}</p>
                  <p className="dash-note">
                    This is the daemon&apos;s master seed — restoring it reproduces
                    every wallet. It is NOT a MetaMask-importable phrase for the
                    wallet address; use the EVM private key below for that.
                  </p>
                </div>
              )}
              {revealed.evmKey && (
                <div>
                  <strong>EVM Private Key (Robinhood mainnet — MetaMask import):</strong>
                  <p><code>{revealed.evmKey}</code></p>
                </div>
              )}
              {revealed.chiaKey && (
                <div>
                  <strong>Chia Private Key:</strong>
                  <p><code>{revealed.chiaKey}</code></p>
                </div>
              )}
              <button onClick={hideAll} className="dash-button danger">
                Hide All (clear from screen)
              </button>
            </div>
          )}
        </div>

        <div className="dash-security-docs">
          <h3>Documentation</h3>
          <ul>
            <li><a href="/docs/KEY_RECOVERY.md" target="_blank" rel="noreferrer">Key Recovery Guide</a></li>
            <li><a href="/docs/UPGRADE_GUIDE.md" target="_blank" rel="noreferrer">Upgrade Guide (existing users)</a></li>
          </ul>
        </div>
      </div>
    </section>
  );
}
