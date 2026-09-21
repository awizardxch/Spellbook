import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Agent Onboarding — Spellbook",
  description:
    "Spellbook onboarding, written for AI agents. This page is a pointer: the authoritative onboarding document lives in the Spellbook git repo.",
};

const RAW_URL =
  "https://raw.githubusercontent.com/awizardxch/Spellbook/main/docs/AGENT_ONBOARDING.md";
const GITHUB_URL =
  "https://github.com/awizardxch/Spellbook/blob/main/docs/AGENT_ONBOARDING.md";

export default function Onboard() {
  return (
    <div className="wrap">
      <nav className="nav">
        <a className="brand" href="/">
          <span className="brand-mark">🪄</span>
          Spellbook
        </a>
        <div className="nav-links">
          <a href="/">Home</a>
          <a
            href="https://github.com/awizardxch/Spellbook"
            target="_blank"
            rel="noopener noreferrer"
          >
            GitHub
          </a>
        </div>
      </nav>

      <header className="hero">
        <span className="kicker">For agents, not humans</span>
        <h1>
          Onboard <span className="glow">your agent</span>
        </h1>
        <p className="lede">
          If you are an AI agent: this page is a <strong>pointer</strong>, not
          the manual. The authoritative onboarding document is{" "}
          <code>docs/AGENT_ONBOARDING.md</code> in the Spellbook repo — fetch
          it, read it, follow it.
        </p>
        <div className="cta-row">
          <a className="btn" href={RAW_URL}>
            Read docs/AGENT_ONBOARDING.md →
          </a>
        </div>
        <p style={{ marginTop: 14, fontSize: "0.85rem", color: "var(--faint)" }}>
          Raw: <code>{RAW_URL}</code>
        </p>
      </header>

      <section className="section">
        <div className="section-head">
          <h2>The 60-second version</h2>
          <p>
            Enough to know whether this is for you. The repo file has the
            exact contract.
          </p>
        </div>
        <div className="grid3">
          <div className="glass">
            <span className="step">01</span>
            <span className="icon">⚙️</span>
            <h3>Install the daemon</h3>
            <p>
              Run <code>install.sh</code> on your machine. It provisions the
              daemon, two tokens (request = yours, approval = your
              human&apos;s), and the paper backup — printed once, on paper,
              offline.
            </p>
          </div>
          <div className="glass">
            <span className="step">02</span>
            <span className="icon">📡</span>
            <h3>Point at a relay</h3>
            <p>
              Deploy the Chia relay (<code>relay/</code>) or use your
              operator&apos;s. It&apos;s a bearer-authed HTTPS API for your
              agent code — coins by puzzle hash, signed-bundle broadcast.
              It never sees keys.
            </p>
          </div>
          <div className="glass">
            <span className="step">03</span>
            <span className="icon">🧙</span>
            <h3>Request, never approve</h3>
            <p>
              Use the <code>AgentClient</code> to propose spends and surface
              decoded intent. Your human approves from their own tooling.
              You cannot approve — the daemon rejects it.
            </p>
          </div>
        </div>
      </section>

      <section className="section">
        <div className="section-head">
          <h2>Hard rules</h2>
        </div>
        <div className="grid2">
          <div className="glass">
            <span className="icon">🔑</span>
            <h3>Never handle key material</h3>
            <p>
              No seeds, mnemonics, or private keys in chat, logs, code, or
              API calls. The relay rejects key material with a 400. Keys and
              signing stay on the daemon&apos;s machine.
            </p>
          </div>
          <div className="glass">
            <span className="icon">🧪</span>
            <h3>Testnet11 first</h3>
            <p>
              Testnet11 is the default network. Mainnet submission requires
              explicit human authorization with exact amounts — it is not
              something you enable on your own.
            </p>
          </div>
        </div>
      </section>

      <div className="callout">
        <h2>The repo file is the truth.</h2>
        <p>
          Endpoints, auth, request/response shapes, deploy variables, and the
          paper-backup model — all in{" "}
          <code>docs/AGENT_ONBOARDING.md</code>. If this page and that file
          ever disagree, the file wins.
        </p>
        <div className="cta-row">
          <a className="btn" href={RAW_URL}>
            Open the onboarding doc →
          </a>
          <a className="btn ghost" href={GITHUB_URL} target="_blank" rel="noopener noreferrer">
            View on GitHub
          </a>
        </div>
      </div>

      <footer className="footer">
        <span>Spellbook — the agent&apos;s wallet. Forged in the Nightspire.</span>
        <div className="links">
          <a href="/">Home</a>
          <a
            href="https://github.com/awizardxch/Spellbook"
            target="_blank"
            rel="noopener noreferrer"
          >
            GitHub
          </a>
        </div>
      </footer>
    </div>
  );
}
