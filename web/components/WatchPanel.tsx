"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Coin,
  RelayClient,
  RelayError,
  decodeAddress,
  encodeAddress,
  formatXch,
  shortHash,
} from "../lib/chia";
import { useLocalStorageJson } from "../lib/useLocalStorage";

interface Watched {
  address: string;
  puzzleHash: string;
  hrp: string;
}

interface AddrState extends Watched {
  coins: Coin[] | null;
  loading: boolean;
  error: string | null;
  updatedAt: number | null;
}

export default function WatchPanel({ client }: { client: RelayClient | null }) {
  const [watched, setWatched] = useLocalStorageJson<Watched[]>("spellbook.watched", []);
  const [input, setInput] = useState("");
  const [addError, setAddError] = useState<string | null>(null);
  const [states, setStates] = useState<Record<string, AddrState>>({});
  const [autoPoll, setAutoPoll] = useState(false);
  const clientRef = useRef(client);
  clientRef.current = client;

  const fetchOne = useCallback(async (w: Watched) => {
    const c = clientRef.current;
    if (!c) return;
    setStates((s) => ({
      ...s,
      [w.puzzleHash]: { ...w, coins: s[w.puzzleHash]?.coins ?? null, loading: true, error: null, updatedAt: s[w.puzzleHash]?.updatedAt ?? null },
    }));
    try {
      const coins = await c.coins([w.puzzleHash]);
      setStates((s) => ({
        ...s,
        [w.puzzleHash]: { ...w, coins, loading: false, error: null, updatedAt: Date.now() },
      }));
    } catch (e) {
      const msg = e instanceof RelayError ? e.message : String(e);
      setStates((s) => ({
        ...s,
        [w.puzzleHash]: { ...w, coins: s[w.puzzleHash]?.coins ?? null, loading: false, error: msg, updatedAt: s[w.puzzleHash]?.updatedAt ?? null },
      }));
    }
  }, []);

  const refreshAll = useCallback(() => {
    watched.forEach((w) => void fetchOne(w));
  }, [watched, fetchOne]);

  // auto-poll every 30s
  useEffect(() => {
    if (!autoPoll || !client || watched.length === 0) return;
    refreshAll();
    const id = setInterval(refreshAll, 30_000);
    return () => clearInterval(id);
  }, [autoPoll, client, watched, refreshAll]);

  const add = () => {
    setAddError(null);
    try {
      const { hrp, puzzleHash } = decodeAddress(input);
      if (hrp !== "txch" && hrp !== "xch") {
        throw new Error(`unexpected address prefix "${hrp}" (expected txch or xch)`);
      }
      // round-trip sanity check
      const rt = encodeAddress(hrp, puzzleHash);
      if (rt !== input.trim().toLowerCase()) {
        throw new Error("address failed round-trip check");
      }
      const entry: Watched = { address: input.trim(), puzzleHash, hrp };
      if (!watched.some((w) => w.puzzleHash === puzzleHash)) {
        const next = [...watched, entry];
        setWatched(next);
        void fetchOne(entry);
      }
      setInput("");
    } catch (e) {
      setAddError(e instanceof Error ? e.message : String(e));
    }
  };

  const remove = (puzzleHash: string) => {
    setWatched(watched.filter((w) => w.puzzleHash !== puzzleHash));
    setStates((s) => {
      const next = { ...s };
      delete next[puzzleHash];
      return next;
    });
  };

  const totalMojos = watched.reduce((sum, w) => {
    const coins = states[w.puzzleHash]?.coins;
    if (!coins) return sum;
    return sum + coins.filter((c) => c.spent_height === null).reduce((s, c) => s + c.amount_mojos, 0);
  }, 0);

  return (
    <section className="card">
      <h2>👁️ Watch addresses</h2>
      <p className="sub">
        Paste a <code>txch1…</code> address to watch its coins. Only the public address
        (puzzle hash) is sent to the relay — never any key.
      </p>
      {!client && <div className="notice">Connect to the relay above first.</div>}
      <div className="row">
        <div style={{ flex: 1, minWidth: 220 }}>
          <input
            type="text"
            placeholder="txch1…"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && add()}
            autoComplete="off"
            spellCheck={false}
          />
        </div>
        <button onClick={add} disabled={!client || !input.trim()}>
          Watch
        </button>
      </div>
      {addError && <div className="error">{addError}</div>}

      {watched.length > 0 && (
        <>
          <div className="row" style={{ marginTop: 12 }}>
            <button className="ghost" onClick={refreshAll} disabled={!client}>
              Refresh now
            </button>
            <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: "0.85rem", color: "var(--muted)" }}>
              <input
                type="checkbox"
                checked={autoPoll}
                onChange={(e) => setAutoPoll(e.target.checked)}
                style={{ accentColor: "var(--accent)" }}
              />
              auto-refresh every 30s
            </label>
          </div>
          <div className="total-line">
            Total unspent: <strong>{formatXch(totalMojos)} tXCH</strong>
          </div>
          {watched.map((w) => {
            const st = states[w.puzzleHash];
            return (
              <div key={w.puzzleHash} style={{ marginTop: 14 }}>
                <div className="row">
                  <code style={{ fontSize: "0.8rem", wordBreak: "break-all" }}>{w.address}</code>
                  <button className="danger" onClick={() => remove(w.puzzleHash)} style={{ padding: "4px 10px", fontSize: "0.75rem" }}>
                    remove
                  </button>
                  {st?.loading && <span className="pill idle">loading…</span>}
                </div>
                {st?.error && <div className="error">{st.error}</div>}
                {st?.coins && st.coins.length === 0 && (
                  <p style={{ color: "var(--muted)", fontSize: "0.85rem" }}>No coins found for this address.</p>
                )}
                {st?.coins && st.coins.length > 0 && (
                  <table className="coins">
                    <thead>
                      <tr>
                        <th>coin</th>
                        <th>amount</th>
                        <th>created</th>
                        <th>spent</th>
                      </tr>
                    </thead>
                    <tbody>
                      {st.coins.map((c) => (
                        <tr key={c.coin_id}>
                          <td title={c.coin_id}>{shortHash(c.coin_id)}</td>
                          <td>{formatXch(c.amount_mojos)}</td>
                          <td>#{c.created_height}</td>
                          <td>
                            {c.spent_height === null ? (
                              <span className="pill ok">unspent</span>
                            ) : (
                              <span className="pill warn">#{c.spent_height}</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            );
          })}
        </>
      )}
    </section>
  );
}
