# Spellbook

Turn any agent's Ed25519 identity key into its own self-custodied wallets.
One command, no third party holding anything.

**Status: v0.1.0 build.** The spec is [SPEC_V1.md](SPEC_V1.md); the daemon,
the agent client library, the KDF, and the installer below are built and
tested. **EVM testnet drill green** — the §10 on-chain drill passed on
Robinhood Chain testnet 46630 (2026-09-20) with throwaway funds; Sage/XCH
steps still pending. No release is published until Speechless tests first.

- **Primary deliverable:** every agent's own native EVM wallet, derived from
  its existing Ed25519 key.
- **Bonus:** native Chia via Sage (headless CLI) — same root, same daemon,
  same policy engine.
- **Per-agent custody:** each agent runs its own daemon, its own Sage, its own
  keys, on its own machine. No central authority — one compromised agent is
  one compromised wallet, never the town.
- **Policy in code, not prompts:** a local non-LLM daemon is the only process
  that holds secrets or signs. It enforces caps, allowlists, velocity limits,
  and a human-approval queue. Conversational agents only ever call its API.
- **Agent-agnostic:** the only input is a 32-byte seed. Musebook muses,
  Claude-based agents, anything — same derivation, same wallets.

## The loop (O10)

The wallet belongs to the **agent**; the **human** interacts with it from chat:

```
agent surfaces intent (read-only) → human approves (their own tooling)
→ daemon executes → agent reports
```

The agent can request and relay but never approve — the two-token split is
enforced by the daemon, not by convention.

## Install (the agent's machine)

Never `curl | bash`. Verify first, then run:

```bash
curl -fsSL -o install.sh \
  https://raw.githubusercontent.com/awizardxch/Spellbook/v0.1.0/install.sh
# check the sha256 against the pinned town thread, then:
bash install.sh v0.1.0 --agent-user <agent-os-user> --human-user <your-login>
```

Releases are signed with the Spellbook release key. The fingerprint is the
trust anchor — cross-check it against the pinned town thread, never against
a value that arrived inside a release:

```
7DEA43CA62DF3F8FB041C1551FCF79089E54DC35
```

Import the key and hand the installer the fingerprint you verified:

```bash
curl -fsSL https://raw.githubusercontent.com/awizardxch/Spellbook/main/docs/release-key.asc | gpg --import
sudo SPELLBOOK_RELEASE_KEY_FPR=7DEA43CA62DF3F8FB041C1551FCF79089E54DC35 \
  bash install.sh v0.1.0 --agent-user <agent-os-user> --human-user <your-login>
```

Full key details and custody: [`docs/RELEASE_KEY.md`](docs/RELEASE_KEY.md).

Add `--no-sage` for an EVM-only install (the default build compiles the
Sage CLI from the pinned commit — needs a Rust toolchain and build time;
an operator-supplied binary is accepted only with `SAGE_PIN_VERIFIED=1`). The installer:

1. verifies the release tarball (checksum + release-key signature — fail closed),
2. creates the dedicated `spellbook` OS user and the 0600/0700 layout,
3. generates the wallet seed **once** and prints the 24-word paper backup **once**,
4. installs the daemon into an isolated venv, writes the default-off policy,
5. runs the §10 **off-chain** drill with a throwaway key (KDF vectors +
   daemon lifecycle) — install completes when the drill passes.

## Use (the agent's package)

```bash
pip install spellbook            # once a release is published; until then: pip install git+https://github.com/awizardxch/Spellbook@v0.1.0
```

```python
from spellbook.client import AgentClient, HumanClient

# The agent: request token only. Surfaces intent, never approves.
agent = AgentClient("/run/spellbook/spellbook.sock", request_token_hex)
agent.request_spend(chain="evm-4663", destination="0x...",
                    amount_wei=10**15, purpose="invoice #42")
agent.queue()      # decoded intent: chain/destination/asset/amount/purpose
agent.status()
agent.addresses()  # {label: {chain: address}}
agent.ledger()     # decision rows, read through the API never the file

# The human: approve token only, on their own tooling (separate device).
human = HumanClient("/run/spellbook/spellbook.sock", approve_token_hex)
human.approve(queue_id)
human.reject(queue_id)
```

Or the CLI: `spellbook status | queue | ledger | addresses | request-spend …`
(request token via `$SPELLBOOK_REQUEST_TOKEN`) and
`spellbook approve|reject <queue_id>` (approve token via
`$SPELLBOOK_APPROVE_TOKEN`). Full guide: [docs/agent-quickstart.md](docs/agent-quickstart.md).

## Layout

- `SPEC_V1.md` — the build plan (canonical)
- `src/spellbook/` — the pip package
  - `daemon.py` — `spellbookd`: Unix-socket policy daemon (token auth,
    per-role peer-UID enforcement, policy engine, persistent queue, 24h
    velocity, decision ledger, KDF-wired addresses)
  - `kdf.py` — §2 KDF: HKDF-SHA256 + reject/resample, then audited curve
    libs (libsecp256k1, py_ecc, Keccak). Third implementation reproducing
    `vectors/vectors.json` byte-for-byte
  - `sign.py` — signing primitives (ECDSA, BLS, Ed25519 identity signing
    behind the S1 gate; fixed domain prefixes)
  - `seed.py` — seed loading (0600, fail closed) + BIP-39 paper backup
  - `client.py` — `AgentClient` / `HumanClient`: the two-token split as code
  - `cli.py` — the `spellbook` operator CLI
  - `drill.py` — the §10 off-chain drill runner
  - `policy.py`, `ledger.py`, `tokens.py`, `config.py`
- `tests/` — 30 tests: all 10 KDF vectors, signing, full daemon lifecycle
- `vectors/` — canonical KDF vectors + the two independent generators
- `install.sh` — verified installer (see above)
- `docs/` — reviews and guides

## What's real vs what's next

Real: KDF (3rd impl, vectors green), signing primitives, daemon (auth,
policy, persistent queue, velocity, ledger, addresses), EVM chain layer
(live balances, eth_estimateGas-based limits, sign + submit + receipts,
testnet-guarded), agent client + CLI, installer, off-chain drill, and the
§10 on-chain testnet drill — green on Robinhood Chain testnet 46630
(2026-09-20).

Next, each needing explicit authorization: Sage/XCH drill steps (the
pinned-commit build path is implemented as of 2026-09-20; the live drill
run is still pending), then — separately
authorized — mainnet dust with Speechless-approved amounts. The O9
single-device fallback still awaits a decision (§12a).
