"use client";

import { useMemo, useState } from "react";
import { RelayClient, RelayStatus } from "../lib/chia";
import { useLocalStorage, useLocalStorageJson } from "../lib/useLocalStorage";
import StatusPanel from "../components/StatusPanel";
import WatchPanel from "../components/WatchPanel";
import BroadcastPanel, { BroadcastLogEntry } from "../components/BroadcastPanel";
import DrillPanel from "../components/DrillPanel";

const DEFAULT_RELAY_URL = process.env.NEXT_PUBLIC_RELAY_URL ?? "";

export default function Home() {
  const [relayUrl, setRelayUrl] = useLocalStorage("spellbook.relayUrl", DEFAULT_RELAY_URL);
  const [token, setToken] = useLocalStorage("spellbook.relayToken", "");
  const [status, setStatus] = useState<RelayStatus | null>(null);
  const [log, setLog] = useLocalStorageJson<BroadcastLogEntry[]>("spellbook.broadcastLog", []);

  const client = useMemo(
    () => (relayUrl.trim() && token.trim() ? new RelayClient(relayUrl.trim(), token.trim()) : null),
    [relayUrl, token]
  );

  const onBroadcast = (entry: BroadcastLogEntry) => {
    setLog([entry, ...log].slice(0, 20));
  };

  return (
    <main>
      <header className="hero">
        <h1>
          <span className="wand">🪄</span>Spellbook Chia Relay
        </h1>
        <p>
          First-tester console for the testnet11 relay. Watch addresses, check relay
          health, and broadcast signed spend bundles. This page is <strong>read-only</strong>:
          it never asks for seeds, mnemonics, or private keys — all signing happens in
          your local daemon.
        </p>
        {status && <div className="network-badge">{status.network}</div>}
      </header>

      <StatusPanel
        relayUrl={relayUrl}
        setRelayUrl={setRelayUrl}
        token={token}
        setToken={setToken}
        onStatus={setStatus}
      />
      <WatchPanel client={client} />
      <BroadcastPanel client={client} onBroadcast={onBroadcast} />
      <DrillPanel client={client} log={log} />

      <footer className="footer">
        <p>
          Relay API: <code>GET /v1/status</code> · <code>POST /v1/coins</code> ·{" "}
          <code>POST /v1/broadcast</code> · <code>GET /v1/coin/:id</code>
        </p>
        <p>
          Trust model: the relay sees public puzzle hashes and signed bundles only —
          the same as any public full node. Keys and signing stay on your machine.
        </p>
      </footer>
    </main>
  );
}
