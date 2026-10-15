import type { Metadata } from "next";
import index from "../../../public/asset-index.json";

export const metadata: Metadata = {
  title: "Asset integrity — Spellbook",
  description:
    "Every Spellbook ceremony page and asset with its SHA-256 and SRI hash, and every API route the site exposes. Compare with the repo before you type a secret.",
};

type FileEntry = { path: string; sha256: string; sri: string; bytes: number; loads?: string[] };
type Route = { path: string; methods: string[]; source: string; sha256: string };

const REPO_INDEX =
  "https://github.com/awizardxch/Spellbook/blob/main/ceremony/asset-index.json";

const mono: React.CSSProperties = {
  fontFamily: "ui-monospace, Menlo, Consolas, monospace",
  fontSize: "0.8rem",
  wordBreak: "break-all",
};

function Files({ rows }: { rows: FileEntry[] }) {
  return (
    <div className="glass" style={{ overflowX: "auto" }}>
      {rows.map((r) => (
        <div key={r.path} style={{ padding: "10px 0", borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
          <div>
            <a href={r.path}>
              <code>{r.path}</code>
            </a>{" "}
            <span style={{ color: "var(--faint)" }}>{r.bytes} bytes</span>
          </div>
          <div style={mono}>sha256 {r.sha256}</div>
          <div style={mono}>{r.sri}</div>
          {r.loads && r.loads.length > 0 && (
            <div style={{ ...mono, color: "var(--faint)" }}>loads {r.loads.join(", ")}</div>
          )}
        </div>
      ))}
    </div>
  );
}

export default function Integrity() {
  const pages = index.pages as FileEntry[];
  const assets = index.assets as FileEntry[];
  const routes = index.api_routes as Route[];
  return (
    <div className="wrap">
      <nav className="nav" data-circuit-rail="navigation">
        <a className="brand" href="/">
          <span className="brand-mark">🪄</span>
          <span className="brand-name">Spellbook</span>
        </a>
        <div className="nav-links bar-scroll">
          <a href="/">Home</a>
          <a href="/onboard">Onboard</a>
        </div>
      </nav>

      <header className="hero">
        <span className="kicker">For humans, before you type a secret</span>
        <h1>
          Asset <span className="glow">integrity</span>
        </h1>
        <p className="lede">
          The seed ceremony pages run only in your browser: no request leaves
          them (<code>connect-src &apos;none&apos;</code>), and every script
          and stylesheet they load is pinned by an SRI hash. This is the
          index of those files, published at{" "}
          <a href="/asset-index.json">
            <code>/asset-index.json</code>
          </a>{" "}
          and mirrored in the repo at{" "}
          <a href={REPO_INDEX} target="_blank" rel="noopener noreferrer">
            <code>ceremony/asset-index.json</code>
          </a>
          . The two must be byte-identical.
        </p>
      </header>

      <section className="section">
        <div className="section-head">
          <h2>How to check</h2>
        </div>
        <div className="glass">
          <ol>
            <li>
              From a clone of the repo:{" "}
              <code>PYTHONPATH=src python3 -m spellbook.asset_index verify --fetch</code>{" "}
              downloads every file below and compares it with the repo&apos;s index.
            </li>
            <li>
              By hand: <code>curl -s https://spellbook.awizard.dev/ceremony/seal.html | sha256sum</code>{" "}
              and compare with the sha256 listed here and in the repo copy.
            </li>
            <li>
              The browser enforces the rest: a script or stylesheet whose bytes
              differ from its <code>integrity=</code> hash is refused.
            </li>
          </ol>
          <p style={{ ...mono, marginTop: 10 }}>Ceremony CSP: {index.ceremony_csp}</p>
        </div>
      </section>

      <section className="section">
        <div className="section-head">
          <h2>Ceremony pages</h2>
          <p>Open these only from a link your agent gives you: the link carries your daemon&apos;s public key after the #.</p>
        </div>
        <Files rows={pages} />
      </section>

      <section className="section">
        <div className="section-head">
          <h2>Scripts and stylesheets</h2>
        </div>
        <Files rows={assets} />
      </section>

      <section className="section">
        <div className="section-head">
          <h2>API routes</h2>
          <p>Every server route this site exposes. None of them is used by a ceremony page.</p>
        </div>
        <div className="glass" style={{ overflowX: "auto" }}>
          {routes.map((r) => (
            <div key={r.path} style={{ padding: "8px 0", borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
              <code>{r.methods.join(" ")}</code> <code>{r.path}</code>
              <div style={mono}>
                {r.source} sha256 {r.sha256}
              </div>
            </div>
          ))}
        </div>
      </section>

      <footer className="footer">
        <span>Spellbook — the agent&apos;s wallet.</span>
        <div className="links">
          <a href="/onboard">Onboard</a>
        </div>
      </footer>
    </div>
  );
}
