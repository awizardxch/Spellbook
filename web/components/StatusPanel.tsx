"use client";

import { useState } from "react";
import { RelayClient, RelayError, RelayStatus } from "../lib/chia";

interface Props {
  relayUrl: string;
  setRelayUrl: (v: string) => void;
  token: string;
  setToken: (v: string) => void;
  onStatus: (s: RelayStatus | null) => void;
}

function fmtUptime(s: number): string {
  if (!Number.isFinite(s) || s < 0) return "—";
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

export default function StatusPanel({ relayUrl, setRelayUrl, token, setToken, onStatus }: Props) {
  const [status, setStatus] = useState<RelayStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const connect = async () => {
    setLoading(true);
    setError(null);
    try {
      const client = new RelayClient(relayUrl, token);
      const s = await client.status();
      setStatus(s);
      onStatus(s);
    } catch (e) {
      const msg = e instanceof RelayError ? e.message : String(e);
      setError(msg);
      setStatus(null);
      onStatus(null);
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="card">
      <h2>🔌 Relay status</h2>
      <p className="sub">
        Connects to your Railway relay over HTTPS with a bearer token. The token is stored
        only in this browser.
      </p>
      <label className="field" htmlFor="relay-url">Relay URL</label>
      <input
        id="relay-url"
        type="url"
        placeholder="https://your-relay.up.railway.app"
        value={relayUrl}
        onChange={(e) => setRelayUrl(e.target.value)}
        autoComplete="off"
      />
      <label className="field" htmlFor="relay-token">Bearer token</label>
      <input
        id="relay-token"
        type="password"
        placeholder="paste the RELAY_API_TOKEN value"
        value={token}
        onChange={(e) => setToken(e.target.value)}
        autoComplete="off"
      />
      <div className="row" style={{ marginTop: 12 }}>
        <button onClick={connect} disabled={loading || !relayUrl || !token}>
          {loading ? "Connecting…" : status ? "Refresh" : "Connect"}
        </button>
        {status && (
          <span className="pill ok">connected</span>
        )}
      </div>
      {error && <div className="error">{error}</div>}
      {status && (
        <dl className="kv">
          <dt>network</dt>
          <dd>{status.network}</dd>
          <dt>peak height</dt>
          <dd>{status.peak_height ?? "—"}</dd>
          <dt>peers</dt>
          <dd>
            {status.peers_connected}
            {status.peers.length > 0 && (
              <span className="sub" style={{ display: "block", marginTop: 4 }}>
                {status.peers.map((p) => `${p.host}:${p.port}`).join(", ")}
              </span>
            )}
          </dd>
          <dt>watched addresses</dt>
          <dd>{status.watched_puzzle_hashes}</dd>
          <dt>uptime</dt>
          <dd>{fmtUptime(status.uptime_s)}</dd>
        </dl>
      )}
    </section>
  );
}
