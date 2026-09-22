"use client";

import { useState } from "react";
import "./dashboard.css";

/* ------------------------------------------------------------------ */
/* Login gate — human viewer only. Agents authenticate via the API      */
/* (docs/AGENT_ONBOARDING.md §8); there is no agent form here.        */
/* ------------------------------------------------------------------ */

const ONBOARDING_URL =
  "https://github.com/awizardxch/Spellbook/blob/main/docs/AGENT_ONBOARDING.md";

export default function LoginGate() {
  const [token, setToken] = useState("");
  const [tokenBusy, setTokenBusy] = useState(false);
  const [tokenError, setTokenError] = useState<string | null>(null);

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

  return (
    <div className="wrap">
      <nav className="nav" data-circuit-rail="navigation">
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
          Read-only testnet holdings. Humans sign in below with a
          read-only viewer token — either the personal token your agent
          generated for you (to see your agent&apos;s wallet) or the
          shared viewer token (operator drill view). Agents authenticate
          programmatically through the API and see their <em>own</em>{" "}
          wallet — there is no agent form here. Neither path can approve,
          sign, or broadcast anything.
        </p>
      </header>

      <div className="dash-panel">
        <div className="dash-grid2">
          <div className="dash-card">
            <span className="dash-step">Human</span>
            <span className="icon">👁️</span>
            <h3>Viewer token</h3>
            <p>
              Watch-only access to balances, queue, and activity. Paste
              the viewer token your agent generated for you, or the shared
              viewer token — it is checked server-side and never leaves
              this login step.
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

          <div className="dash-card">
            <span className="dash-step">Agents</span>
            <span className="icon">🧙</span>
            <h3>Agent sign-in is API-only</h3>
            <p>
              Any agent that installed the Spellbook signs in by passing
              the right values to the API — no clicks, no form:
            </p>
            <p className="dash-note">
              <code>GET /api/auth/challenge</code> → sign the challenge
              locally with your Ed25519 identity key →{" "}
              <code>
                POST /api/auth/verify{" "}
                {"{challenge, signature, pubkey, addresses}"}
              </code>{" "}
              → session cookie bound to <em>your</em> watch addresses.
            </p>
            <p>
              Full recipe with signing examples in the onboarding doc, §8
              “Dashboard API”:
            </p>
            <a
              className="btn ghost"
              href={ONBOARDING_URL}
              target="_blank"
              rel="noopener noreferrer"
            >
              Dashboard API for agents →
            </a>
            <p className="dash-note" style={{ marginTop: 12 }}>
              Your private key never leaves your machine — only the
              signature over the server&apos;s challenge is sent.
            </p>
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
