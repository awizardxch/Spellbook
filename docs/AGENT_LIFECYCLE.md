# Spellbook — agent lifecycle: versions, upgrades, self-repair

Your install keeps itself current and fixes its own code problems. It never
touches your identity to do it. This doc is the complete reference; the
short version lives in `docs/AGENT_ONBOARDING.md`.

## The four commands

Run these with your own Python (`python3 -m spellbook.cli ...`, or the
`spellbook` console script if it is on your PATH). None of them needs the
approve token. Only `doctor` needs your request token (to ask the daemon
about its own files — you cannot traverse `/opt/spellbook` yourself).

| Command | What it does | Needs |
|---|---|---|
| `spellbook version` | local package version, installed VERSION, daemon version, whether they match | nothing |
| `spellbook upgrade --check` | compares your version to the latest signed GitHub release | nothing |
| `spellbook upgrade 0.3.0` | self-upgrade to a signed release (strictly forward-only) | sudo NOPASSWD for one wrapper (installed by install.sh) |
| `spellbook doctor` | read-only health report: keys, tokens, config, ledger, code, daemon | request token |
| `spellbook doctor --repair` | same, then self-repairs **code** problems via a signed-release reinstall | request token |

## The trust model in one paragraph

`spellbook upgrade <tag>` does not run as you. It execs
`/usr/local/bin/spellbook-upgrade <tag>` via a sudoers entry that allows
exactly that path, nothing else. The wrapper (root-owned, you cannot modify
it) accepts one strict `X.Y.Z` tag, refuses downgrades, and execs the pinned
installer copy at `/opt/spellbook/lib/install.sh --upgrade <tag>` — which
verifies the release tarball's SHA-256 **and** the release-key GPG signature
before installing anything. So the only code you can ever install is
maintainer-signed code, moving strictly forward. `--from-dir` (unsigned) is
refused on this path entirely — it is human-driven, root shell only.

## What an upgrade preserves, and what it replaces

**Replaced:** the spellbook package (pip force-reinstall), the systemd unit,
`/opt/spellbook/VERSION`, the install record, the upgrade wrapper, the Sage
binary only if its pinned commit changed.

**Never touched:** `seed.key`, `std_seed.key`, `request.token`,
`approve.token`, `spellbook.json`, `policy.json`, `ledger.jsonl`,
queue/velocity state, Sage data, submission gates. `mainnet_submit_enabled`
is never flipped by an upgrade.

**Never printed again:** upgrades print no key material, ever. The paper
backup block prints once, on fresh install only.

## What doctor checks, and the fail-closed rule

`spellbook doctor` asks the daemon (via the `doctor` RPC, request-token
side) to check its own install: package import, installed VERSION vs package,
key presence/mode/ownership (never contents), config parses and has the
expected shape, token presence/mode, ledger presence, Sage executable when
Chia is enabled, daemon socket, daemon version match. The report names every
failing check.

Failures split into two kinds, and the split is the whole safety story:

- **Code problems** (package/VERSION/Sage/daemon) → self-repairable:
  `doctor --repair` re-fetches and reinstalls the signed release for the
  installed version through the wrapper. Same tag, not a downgrade.
- **State problems** (keys, tokens, config, ledger) → **fail closed**:
  doctor reports them with guidance and stops. It never regenerates a key
  (that would strand funds at the old addresses), never mints a token by
  hand, never hand-edits your config, never reconstructs the append-only
  ledger. Those are human re-provisioning, with the paper backup from
  install day.

## When there is no release yet

Before the first signed release is published, `upgrade --check` says so
plainly instead of inventing a latest version. `install.sh --upgrade
--from-dir` remains the dev path (human-driven, root shell, no signature).
Production self-upgrade is signed releases only.

## The one decision still open

The release-key fingerprint (`SPELLBOOK_RELEASE_KEY_FPR`) has no configured
value yet — release installation fails closed until Speechless pins it in
the town thread. The wrapper refuses to upgrade without it, and install.sh
records whatever the human provided in `/opt/spellbook/install.env`
(root-owned) so upgrades keep working without re-asking.

## Self-install

Agents install Spellbook on their own machines themselves — that is the
primary onboarding path, not a fallback. Runbook:
`docs/AGENT_SELF_INSTALL.md`; installer flag: `install.sh --as-agent`,
which prints a structured `AGENT HANDOFF` block (request token → the
agent's environment; approve token file + paper backup → the human,
out-of-band, never retained by the agent). The trust anchor
(fingerprint) still comes from the town thread, an independent channel —
the agent verifies the release key itself before installing.

## Upgrade notes

`spellbook upgrade --check` (or the MCP tool `spellbook_version`) links
here when a newer signed release exists. After every upgrade, run
`spellbook doctor`, then do the steps for **each** version you moved past,
oldest first.

### 0.3.2: prebuilt Sage binary (no agent action needed)

What changed: fresh installs on linux-x86_64 now download a release-signed
prebuilt `sage` binary — SHA-256 and release-key signature verified exactly
like the release tarball — instead of compiling from source (20+ minutes →
about a minute). A missing prebuilt (older releases, other platforms) falls
back to the source build with a warning; a failed checksum or signature
fails the install hard. `SPELLBOOK_SAGE_SOURCE=1` forces the source build.
After upgrading: nothing — the Sage pin is unchanged, so the upgrade fast
path keeps your existing binary.

### 0.3.1: installer robustness (no agent action needed)

What changed: the fresh-install path only. Sage preflight checks (Rust
≥1.85, libclang, ~5 GB disk) fail fast instead of dying 20 minutes into the
compile; the cargo target dir persists across runs so a killed build resumes;
cargo jobs are capped by available RAM with a per-minute build heartbeat; the
Sage smoke test was fixed. After upgrading: nothing — run `spellbook doctor`
as usual; these fixes apply to new installs.

### 0.3.0: sealed seed, universal agent access, recovery fixes

What changed:
- **Sealed seed** (`spellbook-seed`). This is a password-locked copy of the
  seed in `~/workspace/.spellbook/seed.sealed`. After a VM wipe it brings
  the same wallet back when your human enters the password on a one-time
  local page. See [SEALED_SEED.md](SEALED_SEED.md).
- **MCP server** (`spellbook-mcp`) and shared tool schemas. Any MCP client or
  function-calling agent can now use the wallet. See
  [AGENT_INTEGRATIONS.md](AGENT_INTEGRATIONS.md).
- **Recovery fixes.** `recovery.py` finds the seed through `spellbook.json`
  and shows the keys the daemon really signs with. `restore --standard`
  rebuilds SET 1. The installer's 3-word backup check now works.
- **Removed:** the plain-text hot wallet (`hot.key`), `keymanager.py`, and
  the dashboard's key-reveal routes (they could never reach the VM).

After upgrading:
1. `spellbook-seed status`. If it says `unsealed`, run `spellbook-seed serve`
   and give your human the link so they can seal the seed with a password.
   On a system install, where the seed belongs to the daemon's own OS user,
   status says `no_access`. Your human then runs it as that user:
   `sudo -u spellbook /opt/spellbook/venv/bin/spellbook-seed --config-dir /opt/spellbook --sealed <persistent path> serve`.
2. From now on, check `spellbook-seed status` at the start of **every**
   session, including after context compaction.
   ([AGENT_ONBOARDING.md §6b](AGENT_ONBOARDING.md))
3. Optional: add `spellbook-mcp` to your agent's MCP config
   ([AGENT_INTEGRATIONS.md](AGENT_INTEGRATIONS.md)).
4. If `~/workspace/.spellbook/hot.key` or `key.enc` exists from the old hot
   wallet, tell your human. They move any funds that key alone controls,
   then delete both files.
