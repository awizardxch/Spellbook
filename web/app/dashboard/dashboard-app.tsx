"use client";

import { Fragment, useCallback, useEffect, useState } from "react";
import { CHAINS } from "@/lib/chains";
import "./dashboard.css";

type Tab = "portfolio" | "networks" | "queue" | "activity";

interface AddressHolding {
  /** 1-based position in the agent's derivation order (#1, #2, …) */
  index: number;
  address: string;
  balance: string | null;
  error?: string;
}

interface Holding {
  id: string;
  label: string;
  detail: string;
  unit: string;
  /** watch addresses bound for this chain (before the depth cap) */
  watchAddresses: number;
  /** exact total across the addresses that loaded */
  total: string | null;
  addresses: AddressHolding[];
}

interface QueueIntent {
  id: string;
  title: string;
  network: string;
  amount: string;
  status: string;
  detail: string[];
}

/* ------------------------------------------------------------------ */
/* Sample / demo content. The local daemon is not reachable from the   */
/* hosted site, so Queue and Activity are labeled demo content in v1.  */
/* ------------------------------------------------------------------ */

const SAMPLE_QUEUE: QueueIntent[] = [
  {
    id: "q-01",
    title: "Native offer take — 2,000 mojos for 2,000 mojos",
    network: "Chia testnet11",
    amount: "2,000 mojos",
    status: "parked",
    detail: [
      "Offer id (sample): a1b2c3…f9e0d1",
      "Decoded intent: maker spend asserts the announcement id sha256(puzzle_hash + message).",
      "One human approval authorizes one attempt. Unknown fate is never retried.",
    ],
  },
  {
    id: "q-02",
    title: "Relay self-send — 1,000 mojos to own wallet",
    network: "Chia testnet11",
    amount: "1,000 mojos",
    status: "awaiting approval",
    detail: [
      "Change math exact; total balance unchanged.",
      "Auto-approvable under policy only below the dust threshold — otherwise it waits here.",
    ],
  },
  {
    id: "q-03",
    title: "EVM testnet transfer — 0.0001 ETH",
    network: "Robinhood Chain testnet",
    amount: "0.0001 ETH",
    status: "draft",
    detail: [
      "Draft only. Nothing is signed or broadcast from this page — ever.",
      "A real attempt would need the human's explicit approval in chat first.",
    ],
  },
];

const SAMPLE_ACTIVITY = [
  {
    id: "a-01",
    when: "2h ago",
    text: "Relay self-send drill confirmed at block 4,718,073 (sample).",
  },
  {
    id: "a-02",
    when: "5h ago",
    text: "Queue decoded: native offer take parked for human review (sample).",
  },
  {
    id: "a-03",
    when: "1d ago",
    text: "Testnet balances refreshed across 5 networks (sample).",
  },
];

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
  const [copied, setCopied] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [expandedChain, setExpandedChain] = useState<string | null>(null);
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
  const holdingById = (id: string) => holdings?.find((h) => h.id === id);

  /* ---------------- dashboard ---------------- */

  return (
    <div className="wrap">
      <nav className="nav dash-nav">
        <a className="brand" href="/">
          <span className="brand-mark">🪄</span>
          <span className="dash-wordmark">Spellbook</span>
        </a>
        <div className="nav-links">
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

      <div className="dash-tabs" role="tablist" aria-label="Dashboard sections">
        {(
          [
            ["portfolio", "Portfolio"],
            ["networks", "Networks"],
            ["queue", "Queue"],
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
            {id === "queue" && <span className="dash-badge">demo</span>}
            {id === "activity" && <span className="dash-badge">demo</span>}
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
                  {enabledCount} of {CHAINS.length} networks →
                </button>
                <button
                  className="btn ghost dash-refresh"
                  type="button"
                  onClick={() => load(depth)}
                  disabled={loading}
                >
                  {loading ? "Refreshing…" : "Refresh"}
                </button>
              </div>
            </div>

            {loadError && (
              <p className="dash-error">
                Couldn&apos;t reach the holdings API: {loadError}
              </p>
            )}

            <div className="dash-stats">
              <div className="dash-card dash-stat">
                <span className="dash-step">Networks reporting</span>
                <span className="dash-bignum">
                  {holdings ? `${reporting} / ${visible.length}` : "—"}
                </span>
              </div>
              <div className="dash-card dash-stat">
                <span className="dash-step">Networks enabled</span>
                <span className="dash-bignum">
                  {enabledCount} / {CHAINS.length}
                </span>
              </div>
              <div className="dash-card dash-stat">
                <span className="dash-step">Mode</span>
                <span className="dash-bignum dash-testnet">TESTNET</span>
              </div>
            </div>

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
                    return (
                      <Fragment key={h.id}>
                        <tr>
                          <td>
                            <span
                              className="dash-dot"
                              style={{ background: cfg?.color ?? "#8b5cf6" }}
                            />
                            {h.label}
                            <span className="dash-sub">{h.detail}</span>
                          </td>
                          <td className="dash-num">
                            {h.total !== null ? (
                              <>
                                {h.total}{" "}
                                <span className="dash-unit">{h.unit}</span>
                              </>
                            ) : (
                              <span className="dash-muted">—</span>
                            )}
                          </td>
                          <td>
                            <button
                              className="dash-addr-toggle"
                              type="button"
                              aria-expanded={open}
                              onClick={() =>
                                setExpandedChain((cur) =>
                                  cur === h.id ? null : h.id
                                )
                              }
                              title={
                                open
                                  ? "Hide individual addresses"
                                  : "Show individual addresses"
                              }
                            >
                              <span className="dash-chev">
                                {open ? "▾" : "▸"}
                              </span>
                              {h.addresses.length} of {h.watchAddresses}{" "}
                              {h.watchAddresses === 1 ? "address" : "addresses"}
                            </button>
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
                  All networks are toggled off — enable at least one in the{" "}
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
              Testnet data · strictly read-only. This page cannot
              approve, sign, or broadcast anything.
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
              {CHAINS.map((cfg) => {
                const h = holdingById(cfg.id);
                const on = enabled[cfg.id];
                return (
                  <div
                    key={cfg.id}
                    className={`dash-card dash-netrow${on ? "" : " off"}`}
                  >
                    <span
                      className="dash-dot dash-dot-lg"
                      style={{ background: cfg.color }}
                    />
                    <div className="dash-netinfo">
                      <strong>{cfg.label}</strong>
                      <span className="dash-sub">{cfg.detail}</span>
                    </div>
                    <div className="dash-netbal">
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
                    </div>
                    <button
                      role="switch"
                      aria-checked={on}
                      aria-label={`Toggle ${cfg.label}`}
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
            <p className="dash-note">
              Base Sepolia and ETH Sepolia read 0 until the shared address is
              funded there. Mainnet networks stay gated behind explicit human
              authorization — they are not listed here in v1.
            </p>
          </div>
        </section>
      )}

      {tab === "queue" && (
        <section>
          <div className="dash-panel">
            <div className="dash-panel-head">
              <div>
                <h2>Queue</h2>
                <p>
                  <span className="dash-badge">demo · sample data</span> The
                  local daemon is not reachable from this hosted page, so
                  these intents are illustrative only.
                </p>
              </div>
            </div>
            <div className="dash-queue">
              {SAMPLE_QUEUE.map((q) => (
                <div key={q.id} className="dash-card dash-qrow">
                  <button
                    className="dash-qhead"
                    type="button"
                    aria-expanded={expanded === q.id}
                    onClick={() =>
                      setExpanded((cur) => (cur === q.id ? null : q.id))
                    }
                  >
                    <span className="dash-qtitle">{q.title}</span>
                    <span className="dash-qmeta">
                      {q.network} · {q.amount}
                    </span>
                    <span className={`dash-status s-${q.status.replace(/\s/g, "")}`}>
                      {q.status}
                    </span>
                    <span className="dash-chev">
                      {expanded === q.id ? "▾" : "▸"}
                    </span>
                  </button>
                  {expanded === q.id && (
                    <ul className="dash-qdetail">
                      {q.detail.map((d, i) => (
                        <li key={i}>{d}</li>
                      ))}
                    </ul>
                  )}
                </div>
              ))}
            </div>
            <p className="dash-note">
              Nothing here executes. One human approval authorizes one
              attempt; unknown fate is never retried.
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
                  <span className="dash-badge">demo · sample data</span>{" "}
                  Recent drill and queue events, illustrative only.
                </p>
              </div>
            </div>
            <ul className="dash-activity">
              {SAMPLE_ACTIVITY.map((a) => (
                <li key={a.id} className="dash-card dash-arow">
                  <span className="dash-awhen">{a.when}</span>
                  <span>{a.text}</span>
                </li>
              ))}
            </ul>
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
