"use client";

import { useState } from "react";
import "./dashboard.css";

/* ------------------------------------------------------------------ */
/* Real login gate. Path A: agent challenge-response (Ed25519).        */
/* Path B: human read-only viewer token. No demo simulation.           */
/* ------------------------------------------------------------------ */

type Phase = "idle" | "challenged" | "done";

export default function LoginGate() {
  const [phase, setPhase] = useState<Phase>("idle");
  const [challenge, setChallenge] = useState("");
  const [expiresAt, setExpiresAt] = useState(0);
  const [pubkey, setPubkey] = useState("");
  const [signature, setSignature] = useState("");
  const [evm, setEvm] = useState("");
  const [solana, setSolana] = useState("");
  const [chia, setChia] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [token, setToken] = useState("");
  const [tokenBusy, setTokenBusy] = useState(false);
  const [tokenError, setTokenError] = useState<string | null>(null);

  const requestChallenge = async () => {
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/auth/challenge", { cache: "no-store" });
      const json = (await res.json()) as {
        challenge?: string;
        expiresAt?: number;
        error?: string;
      };
      if (!res.ok) throw new Error(json.error ?? `HTTP ${res.status}`);
      if (typeof json.challenge !== "string" || typeof json.expiresAt !== "number")
        throw new Error("bad challenge response");
      setChallenge(json.challenge);
      setExpiresAt(json.expiresAt);
      setSignature("");
      setPhase("challenged");
    } catch (e) {
      setError(e instanceof Error ? e.message : "couldn't get a challenge");
    } finally {
      setBusy(false);
    }
  };

  const verifySignature = async () => {
    setBusy(true);
    setError(null);
    try {
      const addresses: Record<string, string> = {};
      if (evm.trim()) addresses.evm = evm.trim();
      if (solana.trim()) addresses.solana = solana.trim();
      if (chia.trim()) addresses.chia = chia.trim();
      const res = await fetch("/api/auth/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          challenge,
          signature: signature.trim().toLowerCase(),
          pubkey: pubkey.trim().toLowerCase(),
          addresses,
        }),
      });
      const json = (await res.json()) as { ok?: boolean; error?: string };
      if (!res.ok || json.ok !== true)
        throw new Error(json.error ?? `HTTP ${res.status}`);
      setPhase("done");
      window.location.reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : "verification failed");
    } finally {
      setBusy(false);
    }
  };

  const viewerLogin = async () => {
    setTokenBusy(true);
    setTokenError(null);
    try {
      const res = await fetch("/api/auth/viewer", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
      });
      const json = (await res.json()) as { ok?: boolean; error?: string };
      if (!res.ok || json.ok !== true)
        throw new Error(json.error ?? `HTTP ${res.status}`);
      window.location.reload();
    } catch (e) {
      setTokenError(e instanceof Error ? e.message : "login failed");
    } finally {
      setTokenBusy(false);
    }
  };

  const secondsLeft = Math.max(0, Math.round((expiresAt - Date.now()) / 1000));

  return (
    <div className="wrap">
      <nav className="nav">
        <a className="brand" href="/">
          <span className="brand-mark">🪄</span>
          Spellbook
        </a>
        <div className="nav-links">
          <a href="/">Home</a>
          <a href="/onboard">Agent onboarding</a>
        </div>
      </nav>

      <header className="dash-hero">
        <span className="kicker">Operator login</span>
        <h1>
          Spellbook <span className="dash-wordmark">dashboard</span>
        </h1>
        <p className="lede">
          Read-only testnet holdings. Agents sign in with a real
          challenge-response signature and see their <em>own</em> wallet;
          humans use a read-only viewer token to see the
          operator&apos;s. Neither path can approve, sign, or broadcast
          anything.
        </p>
      </header>

      <div className="dash-panel">
        <div className="dash-grid2">
          <div className="dash-card">
            <span className="dash-step">Path A</span>
            <span className="icon">🧙</span>
            <h3>Agent challenge-sign</h3>
            {phase === "idle" && (
              <>
                <p>
                  Any agent that installed the Spellbook can sign in — no
                  pre-registration. The server issues a short-lived
                  challenge; sign it locally with your Ed25519 identity
                  key, then enter your public key, your signature, and
                  your own watch addresses. You&apos;ll see{" "}
                  <em>your</em> wallet, never the operator&apos;s.
                </p>
                <button
                  className="btn"
                  type="button"
                  onClick={requestChallenge}
                  disabled={busy}
                >
                  {busy ? "Requesting…" : "Request challenge →"}
                </button>
              </>
            )}
            {phase === "challenged" && (
              <>
                <p>
                  Challenge — sign this exact string (expires in{" "}
                  {secondsLeft}s):
                </p>
                <textarea
                  className="dash-challenge"
                  readOnly
                  value={challenge}
                  rows={3}
                  onFocus={(e) => e.target.select()}
                />
                <label className="dash-label" htmlFor="dash-pubkey">
                  Your Ed25519 public key (64 hex chars)
                </label>
                <input
                  id="dash-pubkey"
                  className="dash-input"
                  value={pubkey}
                  onChange={(e) => setPubkey(e.target.value)}
                  placeholder="paste public key…"
                  autoComplete="off"
                  spellCheck={false}
                />
                <label className="dash-label" htmlFor="dash-sig">
                  Ed25519 signature (128 hex chars)
                </label>
                <input
                  id="dash-sig"
                  className="dash-input"
                  value={signature}
                  onChange={(e) => setSignature(e.target.value)}
                  placeholder="paste signature…"
                  autoComplete="off"
                  spellCheck={false}
                />
                <p className="dash-note" style={{ marginTop: 12 }}>
                  Your watch addresses — at least one. The dashboard shows
                  holdings for these addresses only.
                </p>
                <label className="dash-label" htmlFor="dash-evm">
                  EVM address (0x… — Robinhood testnet, Base &amp; ETH
                  Sepolia)
                </label>
                <input
                  id="dash-evm"
                  className="dash-input"
                  value={evm}
                  onChange={(e) => setEvm(e.target.value)}
                  placeholder="0x…"
                  autoComplete="off"
                  spellCheck={false}
                />
                <label className="dash-label" htmlFor="dash-sol">
                  Solana address (devnet, base58)
                </label>
                <input
                  id="dash-sol"
                  className="dash-input"
                  value={solana}
                  onChange={(e) => setSolana(e.target.value)}
                  placeholder="base58…"
                  autoComplete="off"
                  spellCheck={false}
                />
                <label className="dash-label" htmlFor="dash-chia">
                  Chia address (txch1… / xch1…, testnet11)
                </label>
                <input
                  id="dash-chia"
                  className="dash-input"
                  value={chia}
                  onChange={(e) => setChia(e.target.value)}
                  placeholder="txch1…"
                  autoComplete="off"
                  spellCheck={false}
                />
                <div className="dash-formrow">
                  <button
                    className="btn"
                    type="button"
                    onClick={verifySignature}
                    disabled={
                      busy ||
                      signature.trim().length === 0 ||
                      pubkey.trim().length === 0 ||
                      (!evm.trim() && !solana.trim() && !chia.trim())
                    }
                  >
                    {busy ? "Verifying…" : "Verify & enter →"}
                  </button>
                  <button
                    className="btn ghost"
                    type="button"
                    onClick={() => setPhase("idle")}
                    disabled={busy}
                  >
                    New challenge
                  </button>
                </div>
              </>
            )}
            {error && <p className="dash-error">{error}</p>}
          </div>

          <div className="dash-card">
            <span className="dash-step">Path B</span>
            <span className="icon">👁️</span>
            <h3>Human viewer token</h3>
            <p>
              Watch-only access to balances, queue, and activity. Enter the
              read-only viewer token — it is checked server-side and never
              leaves this login step.
            </p>
            <label className="dash-label" htmlFor="dash-token">
              Viewer token
            </label>
            <input
              id="dash-token"
              className="dash-input"
              type="password"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && token.length > 0) viewerLogin();
              }}
              placeholder="paste viewer token…"
              autoComplete="off"
              spellCheck={false}
            />
            <button
              className="btn ghost"
              type="button"
              onClick={viewerLogin}
              disabled={tokenBusy || token.length === 0}
            >
              {tokenBusy ? "Checking…" : "Enter as viewer →"}
            </button>
            {tokenError && <p className="dash-error">{tokenError}</p>}
          </div>
        </div>
        <p className="dash-note">
          🔑 Paper backup is your human&apos;s non-delegable duty: written
          on paper, offline, by the human — no agent, daemon, or installer
          can do it for them, and no agent should ever ask to see the
          words. It is the only recovery if the disk is wiped.
        </p>
      </div>

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
