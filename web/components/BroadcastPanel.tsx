"use client";

import { useState } from "react";
import {
  BroadcastResult,
  RelayClient,
  RelayError,
  mempoolStatusLabel,
  shortHash,
  validateSpendBundleHex,
} from "../lib/chia";

export interface BroadcastLogEntry {
  txid: string;
  status: number;
  time: string;
  bytes: number;
  error?: string;
}

interface Props {
  client: RelayClient | null;
  onBroadcast: (entry: BroadcastLogEntry) => void;
}

export default function BroadcastPanel({ client, onBroadcast }: Props) {
  const [hex, setHex] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<BroadcastResult | null>(null);
  const [confirmed, setConfirmed] = useState(false);

  const localError = validateSpendBundleHex(hex);

  const broadcast = async () => {
    if (!confirmed) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const c = client;
      if (!c) throw new RelayError("not connected to relay");
      const r = await c.broadcast(hex);
      setResult(r);
      onBroadcast({
        txid: r.txid,
        status: r.status,
        time: new Date().toISOString(),
        bytes: hex.trim().replace(/^0x/i, "").length / 2,
        error: r.error,
      });
      if (r.ok && (r.status === 1 || r.status === 2)) {
        setHex("");
        setConfirmed(false);
      }
    } catch (e) {
      setError(e instanceof RelayError ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="card">
      <h2>📡 Broadcast spend bundle</h2>
      <p className="sub">
        Paste a <em>signed</em> spend bundle (hex) built by your local daemon. The relay
        submits it to the Chia network. This page never signs anything and never
        handles keys.
      </p>
      <div className="notice">
        ⚠️ Broadcasting is <strong>irreversible</strong>. A bundle that lands on-chain
        moves real (testnet) coins. Double-check the hex came from your own daemon.
      </div>
      {!client && <div className="notice">Connect to the relay above first.</div>}
      <label className="field" htmlFor="bundle-hex">Signed spend bundle (hex)</label>
      <textarea
        id="bundle-hex"
        placeholder="ff… (hex of the serialized SpendBundle)"
        value={hex}
        onChange={(e) => setHex(e.target.value)}
        spellCheck={false}
      />
      {hex.trim() && localError && <div className="error">{localError}</div>}
      <label style={{ display: "flex", alignItems: "flex-start", gap: 8, marginTop: 10, fontSize: "0.86rem" }}>
        <input
          type="checkbox"
          checked={confirmed}
          onChange={(e) => setConfirmed(e.target.checked)}
          style={{ marginTop: 3, accentColor: "var(--accent)" }}
        />
        I understand this broadcast cannot be undone, and this hex was produced by my
        own daemon (not pasted from anywhere untrusted).
      </label>
      <div className="row" style={{ marginTop: 12 }}>
        <button onClick={broadcast} disabled={!client || loading || !!localError || !confirmed}>
          {loading ? "Broadcasting…" : "Broadcast"}
        </button>
      </div>
      {error && <div className="error">{error}</div>}
      {result && (
        <dl className="kv">
          <dt>result</dt>
          <dd>
            <span className={`pill ${result.status === 1 ? "ok" : result.status === 2 ? "warn" : "bad"}`}>
              {mempoolStatusLabel(result.status)}
            </span>
          </dd>
          <dt>txid</dt>
          <dd title={result.txid}>{shortHash(result.txid, 16)}</dd>
          {result.error && (
            <>
              <dt>error</dt>
              <dd style={{ color: "var(--bad)" }}>{result.error}</dd>
            </>
          )}
        </dl>
      )}
    </section>
  );
}
