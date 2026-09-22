export default function Home() {
  return (
    <div className="wrap">
      <nav className="nav" data-circuit-rail="navigation">
        <a className="brand" href="/">
          <span className="brand-mark">🪄</span>
          <span className="brand-name">Spellbook</span>
        </a>
        <div className="nav-links bar-scroll">
          <a href="#how">How it works</a>
          <a href="#security">Security</a>
          <a href="#networks">Networks</a>
          <a href="/dashboard">Dashboard</a>
          <a href="/onboard">Agent onboarding</a>
        </div>
      </nav>

      <header className="hero">
        <span className="kicker">The agent&apos;s wallet</span>
        <h1>
          Your muse can hold coins.
          <br />
          <span className="glow">You hold the approvals.</span>
        </h1>
        <p className="lede">
          Spellbook is a wallet stack for AI agents. The agent surfaces what
          it wants to do — balances, queued spends, decoded intent. The
          human approves from their own chat. The daemon executes and reports
          back. The agent can request and relay; it can never approve on its
          own.
        </p>
        <div className="cta-row">
          <a className="btn" href="/onboard">Onboard your agent →</a>
          <a
            className="btn ghost"
            href="https://github.com/awizardxch/Spellbook"
            target="_blank"
            rel="noopener noreferrer"
          >
            GitHub — awizardxch/Spellbook
          </a>
        </div>
      </header>

      <section className="section" id="how">
        <div className="section-head">
          <h2>How it works</h2>
          <p>
            A three-beat loop, with the human holding the only key that
            matters: approval.
          </p>
        </div>
        <div className="grid3">
          <div className="glass">
            <span className="step">01 · Agent</span>
            <span className="icon">🧙</span>
            <h3>Requests &amp; relays</h3>
            <p>
              The agent proposes spends, watches balances, and shows its
              intent in plain language. Its request token has no approve
              method — the daemon would reject the attempt anyway.
            </p>
          </div>
          <div className="glass">
            <span className="step">02 · Human</span>
            <span className="icon">🔮</span>
            <h3>Approves from chat</h3>
            <p>
              You review each decoded request where you already talk to your
              muse and approve with your own tooling. No wallet software to
              install, no keys to touch.
            </p>
          </div>
          <div className="glass">
            <span className="step">03 · Daemon</span>
            <span className="icon">⚙️</span>
            <h3>Executes &amp; reports</h3>
            <p>
              The local daemon signs with keys that never leave its machine,
              enforces spend caps and velocity limits, and reports every
              result back to the ledger.
            </p>
          </div>
        </div>
      </section>

      <section className="section" id="security">
        <div className="section-head">
          <h2>Security model</h2>
          <p>
            Built so that even a compromised relay learns nothing worth
            stealing.
          </p>
        </div>
        <div className="grid2">
          <div className="glass">
            <span className="icon">🔑</span>
            <h3>Keys never leave the machine</h3>
            <p>
              Seeds, private keys, and BLS signing live in the daemon only.
              The relay sees public puzzle hashes and already-signed spend
              bundles — the same trust model as pointing a wallet at any
              public full node.
            </p>
          </div>
          <div className="glass">
            <span className="icon">🚫</span>
            <h3>The relay rejects key material</h3>
            <p>
              Any request field named like <code>seed</code>,{" "}
              <code>mnemonic</code>, or <code>private_key</code> is a hard
              400. Malformed spend bundles are rejected before they ever
              reach a peer.
            </p>
          </div>
          <div className="glass">
            <span className="icon">🧱</span>
            <h3>Policy enforced locally</h3>
            <p>
              Per-spend caps, 24-hour velocity limits, and an approval queue
              are enforced by the daemon on its own machine — not by a
              remote service you have to trust.
            </p>
          </div>
          <div className="glass">
            <span className="icon">📜</span>
            <h3>Two-mnemonic paper backup</h3>
            <p>
              Install prints the paper backup once: a standard-recovery set
              whose words and raw keys import straight into Sage and
              MetaMask, plus a daemon-native secondary set. Written on
              paper, offline, verified after import.
            </p>
          </div>
        </div>
      </section>

      <section className="section" id="networks">
        <div className="section-head">
          <h2>Networks</h2>
          <p>
            One seed covers the whole stack — networks differ only in
            derivation label and address encoding.
          </p>
        </div>
        <div className="pill-row">
          <span className="pill">
            <span className="dot" /> Chia testnet11 — live now
          </span>
          <span className="pill">
            <span className="dot" /> Chia mainnet — live in dashboard
          </span>
          <span className="pill">
            <span className="dot" /> EVM testnets — live now
          </span>
          <span className="pill">
            <span className="dot" /> EVM mainnet — live in dashboard
          </span>
          <span className="pill">
            <span className="dot" /> Solana devnet — live now
          </span>
          <span className="pill">
            <span className="dot" /> Solana mainnet-beta — live in dashboard
          </span>
        </div>
        <div className="grid2" style={{ marginTop: 26 }}>
          <div className="glass">
            <span className="icon">🟣</span>
            <h3>Chia</h3>
            <p>
              Testnet11 is the default network today — faucet-funded,
              drills and validation live. Mainnet balances are live in
              the dashboard (read-only); mainnet submission stays gated
              behind explicit human authorization with exact amounts.
              Addresses: <code>txch1…</code> on testnet, <code>xch1…</code>{" "}
              on mainnet.
            </p>
          </div>
          <div className="glass">
            <span className="icon">⛓️</span>
            <h3>EVM</h3>
            <p>
              Standard secp256k1 keys, plain transfers on testnets (e.g.
              Robinhood Chain testnet). Mainnet balances are live in the
              dashboard (read-only); mainnet submission is gated the
              same way as Chia mainnet.
            </p>
          </div>
          <div className="glass">
            <span className="icon">◎</span>
            <h3>Solana</h3>
            <p>
              Ed25519 keys, plain SOL transfers. Devnet is the default —
              the daemon talks to public HTTPS JSON-RPC directly, so there
              is no relay to deploy; mainnet-beta balances are live in
              the dashboard (read-only), submission stays gated behind
              explicit human authorization. Backs up as base58 for Phantom
              import.
            </p>
          </div>
        </div>
      </section>

      <section className="section" id="api">
        <div className="section-head">
          <h2>The relay API is for agents</h2>
          <p>
            This site has no wallet console, no forms, no key handling —
            nothing to click. The Chia relay is a bearer-authed HTTPS API
            that agent software talks to.
          </p>
        </div>
        <div className="glass">
          <table className="api-table">
            <thead>
              <tr>
                <th>Endpoint</th>
                <th>What it does</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>
                  <code>GET /v1/status</code>
                </td>
                <td>Network, peak height, peer count, uptime</td>
              </tr>
              <tr>
                <td>
                  <code>POST /v1/coins</code>
                </td>
                <td>Coins by puzzle hash — balances and confirmation heights</td>
              </tr>
              <tr>
                <td>
                  <code>POST /v1/broadcast</code>
                </td>
                <td>
                  Broadcast a signed spend bundle — mempool ack: 1 SUCCESS, 2
                  PENDING, 3 FAILED
                </td>
              </tr>
              <tr>
                <td>
                  <code>GET /v1/coin/:id</code>
                </td>
                <td>Confirmation tracking for one coin</td>
              </tr>
            </tbody>
          </table>
          <p style={{ color: "var(--muted)", fontSize: "0.9rem", marginTop: 16 }}>
            Full contract, auth rules, and deploy notes live in the repo:{" "}
            <a
              href="https://github.com/awizardxch/Spellbook/blob/main/docs/AGENT_ONBOARDING.md"
              target="_blank"
              rel="noopener noreferrer"
            >
              docs/AGENT_ONBOARDING.md
            </a>
            .
          </p>
        </div>
      </section>

      <div className="callout">
        <h2>Bring your muse a wallet.</h2>
        <p>
          The onboarding guide is written for AI agents, not humans. Point
          your agent at it — the repo file is the authority.
        </p>
        <div className="cta-row">
          <a className="btn" href="/onboard">Agent onboarding →</a>
        </div>
      </div>

      <footer className="footer">
        <span>Spellbook — the agent&apos;s wallet. Forged in the Nightspire.</span>
        <div className="links">
          <a
            href="https://github.com/awizardxch/Spellbook"
            target="_blank"
            rel="noopener noreferrer"
          >
            GitHub
          </a>
          <a
            href="https://github.com/awizardxch/Spellbook/tree/main/docs"
            target="_blank"
            rel="noopener noreferrer"
          >
            Docs
          </a>
          <a href="/onboard">Onboard</a>
          <a href="/dashboard">Dashboard</a>
        </div>
      </footer>
    </div>
  );
}
