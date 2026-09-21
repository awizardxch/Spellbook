import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Onboard a Muse — Spellbook Chia Relay",
  description:
    "Agent-readable onboarding for Spellbook: what it is, how to deploy your own testnet11 relay, and how to connect this dashboard to it. Read-only; never handles seeds or private keys.",
};

export default function Onboard() {
  return (
    <main>
      <header className="hero">
        <h1>
          <span className="wand">🪄</span>Onboard a Muse
        </h1>
        <p>
          Instructions for an AI agent whose human wants Chia testnet11 wallet
          visibility through Spellbook. If you are an agent reading this page,
          a plain-text version lives at{" "}
          <Link href="/onboard.txt">
            <code>/onboard.txt</code>
          </Link>{" "}
          — fetch that instead of scraping HTML.
        </p>
      </header>

      <section className="card">
        <h2>What Spellbook is</h2>
        <p>
          Spellbook is a wallet stack for AI agents on Chia. The operating loop
          is: the <strong>agent</strong> surfaces queued spends, balances, and
          history read-only (decoded intent); the <strong>human</strong>{" "}
          approves with their own tooling; the <strong>daemon</strong> executes
          and reports back. The agent can request and relay — it can never
          approve on its own.
        </p>
        <p>
          This site is the first-tester dashboard for the Chia{" "}
          <strong>testnet11</strong> relay: relay health, address watching, and
          signed-bundle broadcast. It is <strong>read-only</strong> — it never
          asks for seeds, mnemonics, or private keys. All signing happens in the
          user&apos;s local daemon.
        </p>
        <p>
          The relay (hosted on Railway) is a <strong>network relay</strong>, not
          a custodian. It holds persistent WSS connections to testnet11 full
          nodes and exposes coin lookups plus signed-bundle broadcast over a
          bearer-authed HTTPS API. It only ever sees public puzzle hashes and
          already-signed spend bundles — the same trust model as pointing a
          wallet at any public full node. Keys and BLS signing stay on the
          user&apos;s machine.
        </p>
      </section>

      <section className="card">
        <h2>Onboarding steps</h2>
        <ol className="checklist">
          <li>
            <strong>Deploy your own relay to Railway.</strong> Each muse runs
            their own relay — do not share bearer tokens. In the repo{" "}
            <code>github.com/awizardxch/Spellbook</code>, create a Railway
            service with <strong>Root Directory</strong> set to{" "}
            <code>relay/</code>, then set two variables:
            <br />
            <code>
              RELAY_BEARER_TOKEN=&lt;64 hex chars you generate&gt;
            </code>
            <br />
            <code>RELAY_CORS_ORIGIN=https://spellbook.awizard.dev</code>
            <br />
            Generate the token with{" "}
            <code>
              python3 -c &quot;import secrets;
              print(secrets.token_hex(32))&quot;
            </code>
            . Deploy and wait a minute or two for peer connections.
          </li>
          <li>
            <strong>Connect this dashboard.</strong> Open{" "}
            <code>https://spellbook.awizard.dev</code>, paste your relay URL
            and bearer token into the Connect panel, and click Connect. The
            token is stored in the browser&apos;s localStorage only — it is
            never sent anywhere except your relay.
          </li>
          <li>
            <strong>Verify.</strong> The status panel should show network{" "}
            <code>testnet11</code>, a peak height, and at least one connected
            peer.
          </li>
          <li>
            <strong>Watch an address.</strong> Paste a <code>txch1…</code>{" "}
            address into the Watch panel. The dashboard decodes it to a puzzle
            hash in the browser and asks your relay for that address&apos;s
            coins.
          </li>
          <li>
            <strong>Broadcast (testnet only, experimental).</strong> Paste a
            signed spend-bundle hex produced by the local daemon. The relay
            validates its structure and forwards it to testnet11 peers.
          </li>
        </ol>
      </section>

      <section className="card">
        <h2>Hard rules</h2>
        <ul className="checklist">
          <li>
            Never paste a seed, mnemonic, or private key into this dashboard,
            the relay, or any chat. The relay rejects key material with a 400.
          </li>
          <li>
            The bearer token lives in your Railway variables (private) and your
            browser&apos;s localStorage. Never commit it, and never put it in
            Vercel environment variables.
          </li>
          <li>
            Testnet11 only. Mainnet is not enabled on this relay software.
          </li>
        </ul>
      </section>

      <section className="card">
        <h2>Relay API</h2>
        <p>
          All routes require <code>Authorization: Bearer &lt;token&gt;</code>.
        </p>
        <ul className="checklist">
          <li>
            <code>GET /v1/status</code> — network, peak height, peers, uptime.
          </li>
          <li>
            <code>POST /v1/coins</code> — body{" "}
            <code>{`{"puzzle_hashes": ["<64-hex>", …]}`}</code> (1–50). Returns
            coins with id, amounts in mojos, and created/spent heights.
          </li>
          <li>
            <code>POST /v1/broadcast</code> — body{" "}
            <code>{`{"spend_bundle_hex": "<hex>"}`}</code> (≤ 5 MB). Returns
            txid plus Chia mempool status (1 SUCCESS, 2 PENDING, 3 FAILED).
          </li>
          <li>
            <code>GET /v1/coin/:id</code> — confirmation tracking for one coin.
          </li>
        </ul>
        <p>
          Full relay docs:{" "}
          <code>github.com/awizardxch/Spellbook/tree/main/relay</code>
        </p>
      </section>

      <footer className="footer">
        <p>
          <Link href="/">← Back to the console</Link> ·{" "}
          <Link href="/onboard.txt">
            Plain-text instructions for agents
          </Link>
        </p>
      </footer>
    </main>
  );
}
