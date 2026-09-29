# Prebuilt Sage binaries — design proposal

**Status:** approved by Speechless 2026-09-28; implemented in 0.3.2.
**Date:** 2026-09-28

## Decisions (Speechless, 2026-09-28)

1. **Platforms for the first cut:** `linux-x86_64` only.
2. **Built where:** key machine via `scripts/cut-release.sh` (part of the
   existing signing ceremony).
3. **Source build:** permanent fallback — the trust anchor for anyone who
   wants to verify the prebuilt.

## Problem

Every Spellbook install compiles `sage-cli` from source: 20+ minutes on a
decent box, ~2 GB RAM per rustc job, several GB of disk, and a fresh failure
surface (toolchain version, libclang, tmpfs size, OOM) on every machine. We
have now fixed the installer around the build three times (preflights,
persistent target dir, memory-aware jobs + heartbeat) — the remaining win is
to not build at all.

The installer already has the trust path for a supplied binary (`SAGE_BIN` +
`SAGE_PIN_VERIFIED=1`, pin-checked against the release). This proposal makes a
project-published prebuilt binary the default, with the source build as the
fallback.

## Proposal

### 1. Release process produces prebuilt Sage binaries

`scripts/cut-release.sh` (or CI — see open questions) builds `sage-cli` from
the pinned Sage commit for each supported platform and publishes, per
platform:

- `sage-<ver>-<platform>.tar.gz` — contains the `sage` binary
- `sage-<ver>-<platform>.tar.gz.sha256`
- `sage-<ver>-<platform>.tar.gz.asc` — detached GPG signature from the
  **same release signing key** (`7DEA43CA62DF3F8FB041C1551FCF79089E54DC35`)

Published the same way as the release tarball: vendored under
`releases/<ver>/` and attached to the GitHub release. First cut: 
`linux-x86_64` only (matches the key machine and most agent hosts).

### 2. Installer prefers prebuilt, falls back to source

- Detect platform: `uname -s`/`uname -m` → canonical string
  (`linux-x86_64`, `linux-aarch64`, `darwin-arm64`, …).
- Default: try the prebuilt for this platform first.
  - Download `sage-<ver>-<platform>.tar.gz` (+ `.sha256`, `.asc`).
  - Verify SHA-256, then GPG `VALIDSIG` against the **pinned release
    fingerprint** — the exact trust path the installer already uses for the
    release tarball. No new keys, no new trust roots.
  - Extract and use as `SAGE_BIN_STAGED`.
- `SPELLBOOK_SAGE_SOURCE=1` forces a source build (auditors, unsupported
  platforms, "I don't trust binaries").
- If no prebuilt exists for the platform, log it clearly and fall back to the
  current source-build path (with all the §2 preflights/heartbeat).

### 3. Pinning and integrity

- The prebuilt is per **(release version, Sage pin, platform)**. The Sage pin
  already lives in SPEC §3/D4; the release script must assert
  `git rev-parse HEAD == SAGE_COMMIT` before packaging — a prebuilt from the
  wrong commit is a supply-chain incident, not a bug.
- The installer re-verifies the Sage pin the same way it does today
  (`SAGE_PIN_VERIFIED=1` semantics carry over: the pin was verified at
  release-build time by the release script, and the signature proves the
  artifact came from the release key).

### 4. Reproducibility (later, not blocking)

Build in a pinned container (e.g. `rust:1.XX-bookworm`) and record the builder
image + rustc version in the release notes. Bit-for-bit reproducibility is a
stated later goal; the GPG signature is the trust anchor today, same as the
release tarball.

## What this does NOT change

- The source-build path stays, with all current preflights. It is the
  fallback and the auditor's path.
- `SAGE_BIN` operator override keeps working and keeps precedence.
- The release tarball, its checksum/signature flow, and the installer's
  release-verification logic are untouched.

## Open questions (Speechless decides) — all decided 2026-09-28

1. **Platforms for the first cut?** ~~Recommendation: `linux-x86_64` only.~~
   → `linux-x86_64` only.
2. **Built where — key machine via `cut-release.sh`, or GitHub Actions CI?**
   ~~CI is auditable and doesn't need the signing key on a build host; key
   machine keeps everything behind the existing signing ceremony. Either way
   the artifacts are GPG-signed by the release key before publication.~~
   → key machine via `cut-release.sh`.
3. **Keep the source build as a permanent fallback?** ~~Recommendation: yes —
   it's the trust anchor for anyone who wants to verify the prebuilt.~~
   → yes, permanent.

## Implementation (0.3.2)

- `scripts/cut-release.sh` builds `sage-cli` from the pinned commit (read
  from `install.sh`'s `SAGE_COMMIT`/`SAGE_REPO`; checkout asserted), packages
  `sage-<tag>-linux-x86_64.tar.gz` + `.sha256` + `.asc` (release-key signed,
  self-verified like the tarball), and lists them in the publish steps.
  `SPELLBOOK_SKIP_SAGE_PREBUILT=1` skips it.
- `install.sh` tries the prebuilt first (GitHub release asset, then the
  repo-vendored copy): SHA-256 + VALIDSIG-from-pinned-key verified exactly
  like the release tarball. Missing prebuilt (any release before 0.3.2, or
  an unsupported platform) warns and falls back to the source build; a
  FAILED checksum/signature fails hard. `SPELLBOOK_SAGE_SOURCE=1` forces
  the source build.

## Estimated effect

Fresh install on a small box: ~20+ min compile + toolchain/libclang/disk
roulette → ~1 min download + signature check. The entire class of "Sage build
failed on machine X" issues disappears for supported platforms.
