# Competitive Landscape: Open-Source AI Agent Wallets

Date: 2026-09-23. Research method: index search + page reads against public
repos and launch announcements; no live browser session. Factual claims cite
their source; unverified items are marked as such.

Spellbook's model, in one line: the agent runs a local daemon that holds its
own keys (Chia, EVM, Solana), proposes spends with a **request token**, and a
human approves **each** spend with a separate **approve token**
(two-token split, per-transaction human approval, decoded-intent queue,
testnet-first).

## Closest open-source matches

1. **ElizaOS `plugin-wallet`** — https://github.com/elizaos/eliza — **MIT**.
   Non-custodial wallet plugin for elizaOS agents: EVM + Solana signing from
   local keys, x402 micropayments, swaps/bridges (Li.Fi, Jupiter, CCTP),
   on-chain spend policies (ERC-6551), and a **mandatory user-confirmation
   turn before every on-chain action** (`prepare` stages unsigned
   transactions). The closest open-source match to Spellbook's
   self-custody + per-transaction human approval. Approval is chat-turn-based,
   not a cryptographic role split, and it covers only EVM + Solana.
2. **Ledger Agent Stack** — https://shop.ledger.com/pages/ledger-agent-stack,
   https://developers.ledger.com/docs/ai-tools/overview — open-source toolkit
   launched July 16, 2026 (`@ledgerhq/device-management-kit`, Ledger Wallet
   CLI, `ledgerhq/agent-skills`). The agent prepares transactions but never
   holds keys; the human reviews and physically confirms every fund movement
   on a Ledger's trusted display. Tagline: "Agents propose. Humans approve."
   The purest approval-gate philosophy — but custody is **inverted**: the
   human's hardware holds the keys, the agent holds none. Spellbook keeps
   custody with the agent and adds a human gate on top.
3. **MoonPay Open Wallet Standard** — https://github.com/open-wallet-standard/core —
   **MIT**. Open-source wallet standard for agents (Rust core + JS/Python
   bindings): local encrypted vault (AES-256-GCM/Keystore v3), key isolation,
   BIP-39/44 multi-chain derivation (8 chains incl. TRON, EVM, Solana), x402,
   Ledger hardware-backed approval integration, MCP server built in. The
   strongest open-source self-custody foundation — but no native
   per-transaction approval workflow was observed in v1.0.0 (per a
   third-party code analysis, unconfirmed against the core repo).

## Comparison table

| Project | Repo | License | Custody | Human approval per tx | Chains |
|---|---|---|---|---|---|
| ElizaOS plugin-wallet | https://github.com/elizaos/eliza | MIT | Self-custody (local EOA keys) or hosted Steward signing (configurable) | Yes — user confirmation turn for every on-chain subaction; unsigned `prepare` mode | EVM + Solana |
| Ledger Agent Stack | `ledgerhq/agent-skills` + developers.ledger.com/docs/ai-tools/overview | Open-source toolkit | Inverted: human's Ledger holds keys; agent holds none | Yes — physical on-device confirmation per fund action | Ledger-supported (ETH, BTC, SOL, Cosmos, ...) |
| MoonPay Open Wallet Standard | https://github.com/open-wallet-standard/core | MIT | Self-custody (local vault, key isolation) | Hardware-backed approval via Ledger integration; no native per-tx workflow observed in v1.0.0 | 8 chains (TRON, EVM, Solana, ...) |
| anet | https://github.com/osiveayano/anet | MIT | Self-custody (local encrypted wallet.json; testnet default) | No — only `payments.max-per-tx` cap | EVM (ERC-8004/8128, x402 USDC) |
| TON Agentic Wallets | https://github.com/the-ton-tech/agentic-wallet-contract | Not verified (described as open) | Split-key: user key (revoke/budget) + agent key (operates within budget) | No — autonomy within budget is the point | TON |
| Crossmint GOAT | https://github.com/goat-sdk/goat | MIT | Mixed: keypair = self-custody; Crossmint smart wallets / Coinbase MPC = hosted | No | EVM, Solana, Aptos, Sui, Starknet, Zilliqa, ... |
| Coinbase AgentKit | https://github.com/coinbase/agentkit | Apache-2.0 | Mixed: Viem = self-custody; CDP server wallets = Coinbase-hosted MPC; Privy = hosted | No — README explicitly disclaims approval gates, spend caps, allowlists | Base, Ethereum, Solana; "all EVM and SVM" |
| MetaMask Agent Wallet | *proprietary; skills: https://github.com/MetaMask/agent-skills* | Closed (npm CLI only) | Self-custody (TEE signing, dedicated agent wallet) | Exception-based: push/2FA/email approve-or-reject for risky/over-limit txs; in-limit autonomous | EVM (Ethereum, Base), Hyperliquid, x402 |
| Skyfire | *hosted network; KYAPay open protocol* | Closed product | Hosted: business pre-loads the agent's USDC wallet | Exception-based: overspend pings a human to review | Polygon (+ multi-rail plans) |
| Nevermined | https://github.com/nevermined-io/payments | Open SDKs; platform hosted (API key, ~2% fee) | Not a wallet — delegated card/credit rails | Upfront delegation: human enrolls card / sets policy once | x402 (Base, Solana, Polygon), fiat via Stripe/Visa |
| ERC-8004 | https://eips.ethereum.org/EIPS/eip-8004 | Standard (EIP text) | N/A — identity/reputation/validation registries only | N/A | Ethereum + L2s |
| XMTP | https://github.com/xmtp | Open protocol/SDKs | Messaging keys self-held; not a wallet | N/A — messaging layer | EVM identity |

Note on "Nevermind": no open-source project by that name functioning as an
agent wallet was found. The closest real entity is **Nevermined** (above) —
open payment SDKs and hosted payment rails, not an agent self-custody wallet.

## What Spellbook does that none of the alternatives do

1. **Two-token cryptographic role split enforced by the daemon** — a request
   token (agent proposes) and a separate approve token (human approves),
   enforced in code by a non-LLM local daemon. No alternative uses
   token-based role separation: Eliza gates on chat turns, Ledger gates on a
   hardware button, TON/Skyfire gate on policy limits.
2. **Agent-centric identity-derived custody** — wallets KDF-derived from the
   agent's own Ed25519 identity key (HKDF-SHA256), one daemon per agent,
   per-agent isolation. Others derive from human-owned seeds or hosted key
   infrastructure.
3. **Chia + EVM + Solana in one agent daemon** — native Chia via Sage
   headless CLI. No alternative supports Chia at all.
4. **Testnet-first enforcement** — testnet-guarded execution and an on-chain
   testnet drill as part of the build/install. No alternative bakes
   testnet-first into the stack.
5. **Decoded-intent persistent queue + decision ledger in a non-LLM process** —
   the agent never touches secrets or signs; signing is isolated in the daemon
   with peer-UID enforcement, 24h velocity limits, and an append-only ledger.
   Alternatives either let the LLM hold keys (AgentKit/GOAT/Eliza local) or
   rely on hosted/TEE/hardware.
6. **Operational hardening model** — verified installer (checksum + release-key
   signature, fail closed), dedicated OS user, 0600/0700 secret layout,
   24-word paper backup, signed releases with published key fingerprint. None
   of the alternatives ship this as part of the wallet design.

## Caveats

- **Spellbook's own license is unconfirmed**: the repo's public root listing
  showed no LICENSE file as of 2026-09-23. If the "open source" positioning
  matters for this comparison, add one.
- MoonPay OWS's "no built-in approval workflows" claim comes from a single
  third-party code analysis
  (https://github.com/fbsobreira/gotron-mcp/issues/84) — not confirmed
  against the core repo.
- TON agentic-wallet-contract license was described as open but not verified.
- MetaMask Agent Wallet dates/claims come from secondary press
  (https://www.spottedcrypto.com/metamask-agent-wallet-launch-2026-ai-defi-self-custody/),
  not independently verified.
- ERC-8004 ecosystem claims (10k testnet agents, 1,100 builders) come from
  secondary press, not independently verified.

## Sources

- https://github.com/coinbase/agentkit
- https://github.com/goat-sdk/goat
- https://github.com/elizaos/eliza/blob/HEAD/plugins/plugin-wallet/AGENTS.md
- https://github.com/open-wallet-standard/core
- https://www.morningstar.com/news/pr-newswire/20260323ny16213/moonpay-open-sources-the-wallet-layer-for-the-agent-economy (2026-03-23)
- https://www.coindesk.com/tech/2026/07/15/ledger-wants-ai-agents-to-manage-crypto-without-holding-your-keys (2026-07-15)
- https://shop.ledger.com/pages/ledger-agent-stack
- https://developers.ledger.com/docs/ai-tools/overview
- https://github.com/osiveayano/anet
- https://ton-adoption.xyz/en/blog/agentic-wallet-self-custody-for-ai-on-ton-2026/
- https://github.com/the-ton-tech/agentic-wallet-contract
- https://eips.ethereum.org/EIPS/eip-8004
- https://www.ccn.com/education/crypto/erc-8004-ai-agents-on-chain-ethereum-how-works-risks-explained/
- https://github.com/xmtp
- https://github.com/nevermined-io/payments/blob/HEAD/README.md
- http://cointelegraph.com/news/skyfire-launches-blockchain-payment-network-ai-spend-your-money
- https://www.spottedcrypto.com/metamask-agent-wallet-launch-2026-ai-defi-self-custody/
- https://crypto-economy.com/metamask-launches-ai-agent-wallet-with-built-in-security-and-self-custody-access-to-ethereum/
- https://github.com/MetaMask/agent-skills
