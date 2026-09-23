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
| `spellbook upgrade 0.2.0` | self-upgrade to a signed release (strictly forward-only) | sudo NOPASSWD for one wrapper (installed by install.sh) |
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
