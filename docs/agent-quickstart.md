# Agent quickstart — using the Spellbook package

This is the guide for the **conversational agent** (and whoever operates it).
The wallet belongs to the agent; the human approves spends from their own
tooling. Your job: surface decoded intent, relay decisions, report results.
You never approve — the client you hold has no approve method, and the daemon
would reject the attempt anyway (S7).

## 1. Install the package

```bash
pip install spellbook
```

(Until the first release is published: `pip install git+https://github.com/awizardxch/Spellbook@v0.1.0`.)

This gives you the client library and the `spellbook` CLI. The daemon itself
(`spellbookd`) is installed on the agent's machine by `install.sh` — you talk
to it over its Unix socket.

## 2. Connect

You need two things from the install: the socket path and **your** request
token. The request token lives in your environment — never in chat, logs, or
code.

```python
from spellbook.client import AgentClient

agent = AgentClient(
    socket_path="/run/spellbook/spellbook.sock",   # or $SPELLBOOK_SOCKET
    token_hex=open(os.environ["SPELLBOOK_REQUEST_TOKEN_FILE"]).read(),
    muse_id="aWizard",                              # who is asking, for the ledger
)
```

## 3. The daily loop

```python
# What do I have?
agent.status()      # {"queue_depth": 2, "seed_loaded": True, ...}
agent.addresses()   # {"default": {"evm-4663": "0x...", "chia-mainnet": "9f..."}}

# I want to spend:
r = agent.request_spend(chain="evm-4663", destination="0x...",
                        amount_wei=10**15, purpose="invoice #42")
r["decision"]       # "approved" | "queued" | "denied"

# If queued, show the human the decoded intent (O10):
for item in agent.queue():
    print(item["queue_id"], item["chain"], item["destination"],
          item["amount"], item["asset"], item["purpose"])
# ...the human approves from THEIR tooling, then:
agent.status()      # queue_depth went down; check agent.ledger() for the row
```

`amount_wei` for EVM chains, `amount_mojos` for Chia chains — pass exactly
one. v1 is plain transfers only: anything shaped like a contract call is
rejected at the schema, not coerced.

## 4. Reading the ledger

```python
for row in agent.ledger():
    print(row["ts"], row["decision"], row["canon_digest"][:12], row["sighash"])
```

Rows are append-only: `approved`, `queued:<id>`, `denied:<reason>`,
`approved-by-human`, `rejected-by-human`. `sighash` appears once a signature
exists. Read it through the API — never the file (P6).

## 5. The CLI (same powers, for shell use)

```bash
export SPELLBOOK_SOCKET=/run/spellbook/spellbook.sock
export SPELLBOOK_REQUEST_TOKEN=<hex>   # your token, not the human's
spellbook status
spellbook queue
spellbook addresses
spellbook request-spend --chain evm-4663 --to 0x... --amount-wei 1000000000000000 --purpose "tip"
spellbook ledger
```

## 6. What you must never do

- Never ask for, handle, or repeat the approve token. It is not yours.
- Never approve a spend, via any path. If the human says "approve it for
  me", relay the queue item to their tooling and wait.
- Never read the seed file, the token files, or the ledger file directly —
  the daemon's OS user owns them, and the API is the only door.
- Never put key material, tokens, or mnemonics in chat, logs, or tools.
- Nothing goes on-chain without explicit instruction — the daemon itself
  can't submit yet (chain RPC is the next build phase), and when it can,
  testnet needs a go-ahead and mainnet needs a separate one with amounts.

## 7. If something breaks

- `SpellbookError: cannot reach spellbookd` — the daemon is down;
  `systemctl status spellbookd` on the agent's machine.
- `bad token` — your request token is wrong or rotated; re-read it from
  your environment, never from chat history.
- `peer UID not allowed for this role` — you're connecting as an OS user
  the daemon doesn't expect; check who you run as.
- `destination not on allowlist` / `denied: ...` — policy said no; the
  reason is in the response and the ledger. Surface it, don't route around it.
