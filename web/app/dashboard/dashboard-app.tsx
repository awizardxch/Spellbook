"use client";

import { Fragment, useCallback, useEffect, useState } from "react";
import { CHAINS, NETWORKS } from "@/lib/chains";
import "./dashboard.css";

type Tab = "portfolio" | "networks" | "activity";

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
}

interface NftHolding {
  contract: string;
  tokenId: string;
  name: string | null;
}

interface Holding {
  id: string;
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
    Object.fromEntries(CHAINS.map((c) => [c.id, true]))
  );
  const [holdings, setHoldings] = useState<Holding[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [activity, setActivity] = useState<ChainActivity[] | null>(null);
  const [activityLoading, setActivityLoading] = useState(false);
  const [activityError, setActivityError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [expandedChain, setExpandedChain] = useState<string | null>(null);
  const [assetsTab, setAssetsTab] = useState<"assets" | "nfts">("assets");
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
    },
    [load]
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

  const visible = (holdings ?? []).filter((h) => enabled[h.id]);
  const reporting = visible.filter((h) => h.total !== null).length;
  const enabledCount = CHAINS.filter((c) => enabled[c.id]).length;
  const mainnetOn = CHAINS.filter(
    (c) => c.env === "mainnet" && enabled[c.id]
  ).length;
  const testnetOn = CHAINS.filter(
    (c) => c.env === "testnet" && enabled[c.id]
  ).length;
  const holdingById = (id: string) => holdings?.find((h) => h.id === id);

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
        <section>
          <div className="dash-panel">
            <div className="dash-panel-head">
              <div>
                <h2>Portfolio</h2>
                <p>
                  Testnet holdings, read-only. Balances load live from
                  public testnet RPCs and the Chia relay.
                </p>
              </div>
              <div className="dash-actions">
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
                  className="dash-netcount"
                  type="button"
                  onClick={() => setTab("networks")}
                  title="Choose networks"
                >
                  {enabledCount} of {CHAINS.length} chains →
                </button>
                <button
                  className="btn ghost dash-refresh"
                  type="button"
                  onClick={() => load(depth)}
                  disabled={loading}
                >
                  {loading ? "Refreshing…" : "Refresh"}
                </button>
                <span className="dash-chip" title="Chains reporting">
                  {holdings ? `${reporting} / ${visible.length}` : "—"} reporting
                </span>
                <span className="dash-chip" title="Chains enabled">
                  {enabledCount} / {CHAINS.length} enabled
                </span>
                <span className="dash-chip" title="Mode">
                  {mainnetOn > 0 && (
                    <span className="dash-mainnet">MAINNET</span>
                  )}
                  {mainnetOn > 0 && testnetOn > 0 && (
                    <span className="dash-modesep"> + </span>
                  )}
                  {testnetOn > 0 && (
                    <span className="dash-testnet">TESTNET</span>
                  )}
                  {mainnetOn === 0 && testnetOn === 0 && (
                    <span className="dash-muted">OFF</span>
                  )}
                </span>
              </div>
            </div>

            {loadError && (
              <p className="dash-error">
                Couldn&apos;t reach the holdings API: {loadError}
              </p>
            )}

            <div className="dash-tablewrap">
              <table className="dash-table">
                <thead>
                  <tr>
                    <th>Network</th>
                    <th>Total balance</th>
                    <th>Addresses</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map((h) => {
                    const cfg = CHAINS.find((c) => c.id === h.id);
                    const open = expandedChain === h.id;
                    const firstError = h.addresses.find(
                      (a) => a.error
                    )?.error;
                    const assetCount =
                      h.tokens.length + (h.total !== null ? 1 : 0);
                    return (
                      <Fragment key={h.id}>
                        <tr
                          className={`dash-chainrow${open ? " open" : ""}`}
                          onClick={() =>
                            setExpandedChain((cur) =>
                              cur === h.id ? null : h.id
                            )
                          }
                          onKeyDown={(e) => {
                            if (e.key === "Enter" || e.key === " ") {
                              e.preventDefault();
                              setExpandedChain((cur) =>
                                cur === h.id ? null : h.id
                              );
                            }
                          }}
                          tabIndex={0}
                          aria-expanded={open}
                          title={
                            open ? "Collapse holdings" : "Expand holdings"
                          }
                        >
                          <td>
                            <span
                              className="dash-dot"
                              style={{ background: cfg?.color ?? "#8b5cf6" }}
                            />
                            {h.label}
                            <span className="dash-sub">{h.detail}</span>
                          </td>
                          <td className="dash-num">
                            {h.totalUsd != null ? (
                              <>
                                <span className="dash-usd">
                                  {fmtUsd(h.totalUsd)}
                                </span>
                                <span className="dash-sub">
                                  {h.total}{" "}
                                  <span className="dash-unit">{h.unit}</span>
                                  {assetCount > 1 &&
                                    ` · ${assetCount} assets`}
                                </span>
                              </>
                            ) : h.total !== null ? (
                              <>
                                {h.total}{" "}
                                <span className="dash-unit">{h.unit}</span>
                              </>
                            ) : (
                              <span className="dash-muted">—</span>
                            )}
                          </td>
                          <td>
                            <span className="dash-addr-toggle">
                              <span className="dash-chev">
                                {open ? "▾" : "▸"}
                              </span>
                              {h.addresses.length} of {h.watchAddresses}{" "}
                              {h.watchAddresses === 1 ? "address" : "addresses"}
                            </span>
                          </td>
                          <td>
                            {h.total !== null ? (
                              <span className="dash-ok">● live</span>
                            ) : (
                              <span
                                className="dash-warn"
                                title={firstError ?? "unavailable"}
                              >
                                ● unavailable
                              </span>
                            )}
                          </td>
                        </tr>
                        {open && (
                          <tr className="dash-subrow dash-assetsrow">
                            <td colSpan={4}>
                              <div className="dash-assets">
                                <div
                                  className="dash-seg"
                                  role="tablist"
                                  aria-label={`${h.label} holdings view`}
                                >
                                  <button
                                    type="button"
                                    role="tab"
                                    aria-selected={assetsTab === "assets"}
                                    className={`dash-segbtn${assetsTab === "assets" ? " on" : ""}`}
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      setAssetsTab("assets");
                                    }}
                                  >
                                    Assets
                                    {assetCount > 0 ? ` (${assetCount})` : ""}
                                  </button>
                                  <button
                                    type="button"
                                    role="tab"
                                    aria-selected={assetsTab === "nfts"}
                                    className={`dash-segbtn${assetsTab === "nfts" ? " on" : ""}`}
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      setAssetsTab("nfts");
                                    }}
                                  >
                                    NFTs
                                    {h.nfts.length > 0
                                      ? ` (${h.nfts.length})`
                                      : ""}
                                  </button>
                                </div>
                                {assetsTab === "assets" ? (
                                  <ul className="dash-assetlist">
                                    {h.total !== null && (
                                      <li className="dash-asset dash-asset-native">
                                        <span
                                          className="dash-dot"
                                          style={{
                                            background:
                                              cfg?.color ?? "#8b5cf6",
                                          }}
                                        />
                                        <span className="dash-asset-name">
                                          {NATIVE_NAMES[h.unit] ?? h.unit}
                                          <span className="dash-sub">
                                            {h.unit} · native
                                          </span>
                                        </span>
                                        <span className="dash-asset-qty">
                                          {h.total}{" "}
                                          <span className="dash-unit">
                                            {h.unit}
                                          </span>
                                        </span>
                                        <span className="dash-asset-usd">
                                          {h.nativeUsd != null ? (
                                            fmtUsd(h.nativeUsd)
                                          ) : (
                                            <span className="dash-muted">—</span>
                                          )}
                                        </span>
                                      </li>
                                    )}
                                    {h.tokens.map((t) => (
                                      <li
                                        key={t.contract}
                                        className="dash-asset"
                                      >
                                        <span className="dash-dot dash-dot-token" />
                                        <span className="dash-asset-name">
                                          {t.name}
                                          <span className="dash-sub">
                                            {t.symbol}
                                          </span>
                                        </span>
                                        <span className="dash-asset-qty">
                                          {t.qty}{" "}
                                          <span className="dash-unit">
                                            {t.symbol}
                                          </span>
                                        </span>
                                        <span className="dash-asset-usd">
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
                                        </span>
                                      </li>
                                    ))}
                                    {h.total === null &&
                                      h.tokens.length === 0 && (
                                        <li className="dash-asset-empty">
                                          No balances loaded for this chain.
                                        </li>
                                      )}
                                  </ul>
                                ) : h.nfts.length > 0 ? (
                                  <ul className="dash-nftlist">
                                    {h.nfts.map((n) => (
                                      <li
                                        key={`${n.contract}:${n.tokenId}`}
                                        className="dash-nft"
                                      >
                                        <span className="dash-nft-name">
                                          {n.name ?? "Unknown collection"}
                                        </span>
                                        <span className="dash-sub">
                                          #{n.tokenId}
                                        </span>
                                        <code title={n.contract}>
                                          {truncate(n.contract)}
                                        </code>
                                      </li>
                                    ))}
                                  </ul>
                                ) : (
                                  <p className="dash-note">
                                    No NFTs found in the recent activity
                                    window. Discovery scans recent inbound
                                    transfers — older holdings may not
                                    appear.
                                  </p>
                                )}
                              </div>
                            </td>
                          </tr>
                        )}
                        {open &&
                          h.addresses.map((a, i) => (
                            <tr key={`${h.id}-${i}`} className="dash-subrow">
                              <td>
                                <span className="dash-idx">#{a.index}</span>
                                <span className="dash-sub">
                                  address #
                                </span>
                              </td>
                              <td className="dash-num">
                                {a.balance !== null ? (
                                  <>
                                    {a.balance}{" "}
                                    <span className="dash-unit">{h.unit}</span>
                                  </>
                                ) : (
                                  <span className="dash-muted">—</span>
                                )}
                              </td>
                              <td>
                                <code title={a.address}>
                                  {truncate(a.address)}
                                </code>{" "}
                                <button
                                  className="dash-copy"
                                  type="button"
                                  onClick={() =>
                                    copy(a.address, `addr-${h.id}-${i}`)
                                  }
                                  aria-label={`Copy ${h.label} address #${a.index}`}
                                >
                                  {copied === `addr-${h.id}-${i}` ? "✓" : "⧉"}
                                </button>
                              </td>
                              <td>
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
                              </td>
                            </tr>
                          ))}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
              {!loading && visible.length === 0 && (
                <p className="dash-note">
                  All chains are toggled off — enable at least one in the{" "}
                  <button
                    className="dash-linkbtn"
                    type="button"
                    onClick={() => setTab("networks")}
                  >
                    Networks tab
                  </button>
                  .
                </p>
              )}
            </div>
            <p className="dash-note">
              Mainnet and testnet balances side by side · strictly
              read-only. This page cannot approve, sign, or broadcast
              anything — mainnet rows are live balances, not a spending
              interface.
            </p>
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
                const pair = [ "mainnet", "testnet" ].map(
                  (env) => net.chains.find((c) => c.env === env)!
                );
                const anyOn = pair.some((cfg) => enabled[cfg.id]);
                return (
                  <div
                    key={net.id}
                    className={`dash-card dash-netrow${anyOn ? "" : " off"}`}
                  >
                    <span
                      className="dash-dot dash-dot-lg"
                      style={{ background: pair[0].color }}
                    />
                    <div className="dash-netinfo">
                      <strong>{net.label}</strong>
                      <span className="dash-sub">
                        {pair[0].detail} · {pair[1].detail}
                      </span>
                    </div>
                    <div className="dash-netenvs">
                      {pair.map((cfg) => {
                        const h = holdingById(cfg.id);
                        const on = enabled[cfg.id];
                        const firstError = h?.addresses.find(
                          (a) => a.error
                        )?.error;
                        return (
                          <div
                            key={cfg.id}
                            className={`dash-netenv${on ? "" : " off"}`}
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
                              {h?.total != null ? (
                                <>
                                  {h.total}{" "}
                                  <span className="dash-unit">{h.unit}</span>
                                </>
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
                              onClick={() => toggle(cfg.id)}
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
                <div key={c.id} className="dash-card dash-agroup">
                  <div className="dash-agroup-head">
                    <span className="dash-anet">{c.label}</span>
                    <span className={`dash-envtag e-${c.env}`}>{c.env}</span>
                    <span className="dash-coverage">{c.coverage}</span>
                  </div>
                  {c.addresses.map((a) => (
                    <div key={a.address} className="dash-aaddr">
                      <button
                        className="dash-addrline"
                        type="button"
                        title="Copy address"
                        onClick={() => copy(a.address, `act-${c.id}-${a.index}`)}
                      >
                        #{a.index} {truncate(a.address)}{" "}
                        {copied === `act-${c.id}-${a.index}` ? "\u2713" : ""}
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
