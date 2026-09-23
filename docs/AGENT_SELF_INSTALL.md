# Spellbook — agent self-install runbook

You are an agent. This is how you install Spellbook on your own machine,
by yourself, from scratch. No human drives the installer — but your human
is part of the protocol at the end (they hold your approve token and your
paper backup; you must not).

## What you need

- Root (or passwordless sudo) on the machine that will run the daemon.
- Your OS username (`--agent-user`) and your human's OS username
  (`--human-user`). They must be different people.
- About 10 minutes (the Sage build compiles from the pinned commit;
  `--no-sage` skips it for an EVM-only install).

## The runbook

**1. Get the trust anchor from an independent channel.** Read the release-key
fingerprint from the pinned town thread (and cross-check the README).
Never take a fingerprint that arrived inside a release page or tarball.

**2. Fetch and verify the installer.** Download `install.sh` for the release
tag, check its SHA-256 against the value in the town thread. Never
`curl | bash`.

**3. Import the release key and check the fingerprint yourself.**

```bash
curl -fsSL https://raw.githubusercontent.com/awizardxch/Spellbook/main/docs/release-key.asc | gpg --import
gpg --list-keys --with-colons "spellbook@awizard.dev"   # the fpr: line must equal the town thread
```

**4. Run the install as yourself, the agent:**

```bash
sudo SPELLBOOK_RELEASE_KEY_FPR=<fingerprint-from-town-thread> \
  bash install.sh 0.1.0 --as-agent \
  --agent-user <your-os-user> --human-user <human-os-user>
```

The installer verifies the release tarball (SHA-256 + GPG signature, and
the signature must be from the pinned fingerprint — anything else fails
closed), creates the dedicated `spellbook` OS user and the 0600/0700
layout, generates your wallet seed once, installs the daemon, and runs the
off-chain drill. It prints no interactive prompts.

**5. Follow the HANDOFF protocol.** The installer prints an `AGENT HANDOFF`
block at the end. It is a protocol, not a suggestion:

- **Yours:** the request token → your environment file. Never in chat,
  logs, or code.
- **Your human's, delivered out-of-band NOW:** the approve token file
  (`/opt/spellbook/approve.token`) — your human copies it to their separate
  device with *their own* machine access. **Never read it into your
  environment.** The daemon verifies approvals against it; you must not be
  able to approve your own spends.
- **Your human's:** the paper backup (two 24-word sets). Read them to your
  human; they write them down on paper, offline, two copies in two places.
  Confirm receipt, then drop the words from your context.

**6. Verify before you finish.**

```bash
spellbook doctor    # every check green
spellbook version   # local == installed == daemon
```

## From here

You self-serve for life: `spellbook upgrade --check`, `spellbook upgrade
<tag>` (signed releases, forward-only), `spellbook doctor --repair` (fixes
code problems; key/token/config/ledger problems fail closed and wait for
your human). Full reference: `docs/AGENT_LIFECYCLE.md`.

## The one rule that never bends

You hold the request token. Your human holds the approve token and the
paper backup. If that separation ever breaks — if the approve token lands
in your environment, logs, or chat — say so immediately and re-provision
with your human. An agent that can approve its own spends is not a
Spellbook agent.
