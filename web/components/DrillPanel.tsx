"use client";

import { useState } from "react";
import { CoinState, RelayClient, RelayError, mempoolStatusLabel, shortHash } from "../lib/chia";
import { useLocalStorageJson } from "../lib/useLocalStorage";
import type { BroadcastLogEntry } from "./BroadcastPanel";

interface Props {
  client: RelayClient | null;
  log: BroadcastLogEntry[];
}

const STEPS = [
  {
    title: "1 · Funded",
    desc: "The test address holds testnet TXCH. Use the official faucet, or have someone send tXCH to the watched address.",
    link: { href: "https://testnet11-faucet.chia.net", label: "testnet11-faucet.chia.net" },
  },
  {
    title: "2 · Watched",
    desc: "The address is added in the Watch panel above and the funding coin appears as unspent.",
  },
  {
    title: "3 · Built",
    desc: "Your local daemon built and signed the spend (keys never leave your machine). Copy the spend-bundle hex it printed.",
  },
  {
    title: "4 · Broadcast",
    desc: "Paste the bundle hex into the Broadcast panel and submit. The relay returns a mempool ack — FAILED means stop and review, never blind-retry.",
  },
  {
    title: "5 · Confirmed",
    desc: "Poll the new coin (or the spent input) below until it shows a block height. Only then is the drill step done.",
  },
];

export default function DrillPanel({ client, log }: Props) {
  const [checks, setChecks] = useLocalStorageJson<boolean[]>("spellbook.drill", STEPS.map(() => false));
  const [coinId, setCoinId] = useState("");
  const [coinState, setCoinState] = useState<CoinState | null>(null);
  const [coinError, setCoinError] = useState<string | null>(null);
  const [coinLoading, setCoinLoading] = useState(false);

  const toggle = (i: number) => {
    const next = [...checks];
    next[i] = !next[i];
    setChecks(next);
  };

  const reset = () => setChecks(STEPS.map(() => false));

  const checkCoin = async () => {
    setCoinLoading(true);
    setCoinError(null);
    setCoinState(null);
    try {
      if (!client) throw new RelayError("not connected to relay");
      const s = await client.coin(coinId.trim());
      setCoinState(s);
    } catch (e) {
      setCoinError(e instanceof RelayError ? e.message : String(e));
    } finally {
      setCoinLoading(false);
    }
  };

  const done = checks.filter(Boolean).length;

  return (
    <section className="card">
      <h2>🧪 Testnet drill</h2>
      <p className="sub">
        Guided checklist for the first testnet run. This page is read-only — every
        on-chain step happens through your daemon and the relay.
      </p>
      <div className="row">
        <span className={`pill ${done === STEPS.length ? "ok" : done > 0 ? "warn" : "idle"}`}>
          {done}/{STEPS.length} steps done
        </span>
        <button className="ghost" onClick={reset} style={{ padding: "6px 12px", fontSize: "0.8rem" }}>
          reset checklist
        </button>
      </div>
      <ul className="checklist">
        {STEPS.map((s, i) => (
          <li key={s.title}>
            <input type="checkbox" checked={!!checks[i]} onChange={() => toggle(i)} aria-label={s.title} />
            <div>
              <div className="step-title">{s.title}</div>
              <div className="step-desc">
                {s.desc}{" "}
                {s.link && (
                  <a href={s.link.href} target="_blank" rel="noreferrer">
                    {s.link.label} ↗
                  </a>
                )}
              </div>
            </div>
          </li>
        ))}
      </ul>

      <h3 style={{ marginTop: 20, marginBottom: 4, fontSize: "0.95rem" }}>Confirm a coin</h3>
      <p className="sub">Look up a coin id to see its created / spent heights.</p>
      <div className="row">
        <div style={{ flex: 1, minWidth: 220 }}>
          <input
            type="text"
            placeholder="coin id (64 hex chars)"
            value={coinId}
            onChange={(e) => setCoinId(e.target.value)}
            autoComplete="off"
            spellCheck={false}
          />
        </div>
        <button className="ghost" onClick={checkCoin} disabled={!client || coinLoading || !coinId.trim()}>
          {coinLoading ? "Checking…" : "Check"}
        </button>
      </div>
      {coinError && <div className="error">{coinError}</div>}
      {coinState && (
        <dl className="kv">
          <dt>coin</dt>
          <dd title={coinState.coin_id}>{shortHash(coinState.coin_id, 16)}</dd>
          <dt>created</dt>
          <dd>#{coinState.created_height}</dd>
          <dt>spent</dt>
          <dd>
            {coinState.spent_height === null ? (
              <span className="pill ok">unspent</span>
            ) : (
              <span className="pill warn">#{coinState.spent_height}</span>
            )}
          </dd>
        </dl>
      )}

      <h3 style={{ marginTop: 20, marginBottom: 4, fontSize: "0.95rem" }}>Recent broadcasts</h3>
      {log.length === 0 ? (
        <p className="sub">Nothing broadcast from this browser yet.</p>
      ) : (
        <table className="coins">
          <thead>
            <tr>
              <th>time</th>
              <th>txid</th>
              <th>status</th>
            </tr>
          </thead>
          <tbody>
            {log.map((e, i) => (
              <tr key={`${e.txid}-${i}`}>
                <td>{new Date(e.time).toLocaleString()}</td>
                <td title={e.txid}>{shortHash(e.txid)}</td>
                <td>
                  <span className={`pill ${e.status === 1 ? "ok" : e.status === 2 ? "warn" : "bad"}`}>
                    {mempoolStatusLabel(e.status)}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
