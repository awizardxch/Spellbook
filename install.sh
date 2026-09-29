#!/usr/bin/env bash
#
# Spellbook installer — SPEC_V1.md §14 (S9: verify before you run).
#
# This script is NEVER piped from curl. The documented flow is:
#   curl -fsSL -o install.sh \
#     https://raw.githubusercontent.com/awizardxch/Spellbook/<tag>/install.sh
#   sha256sum -c  # against the hash in the pinned town thread and README
#   bash install.sh <tag> [--no-sage] [--agent-user NAME] [--human-user NAME]
#
# Local-test flow (no published release yet — Speechless tests first):
#   bash install.sh --from-dir /path/to/Spellbook [--no-sage] ...
#   (skips the download + signature steps; everything else is identical)
#
# What it does:
#   1. Verifies the release tarball (checksum + release-key signature) — fail closed.
#   2. Installs the Sage CLI for the pinned commit (SPEC §3/D4, §10 step 1).
#      Prefers a release-signed prebuilt binary (checksum + release-key
#      signature verified exactly like the release tarball, plus a
#      .sage-pin sidecar proving it was built from the pinned commit), so a
#      quick install never needs the ~20-minute source compile. Local
#      prebuilts are tried before the network: $SPELLBOOK_SAGE_PREBUILT, then
#      repo-vendored releases/ under the source tree (this is what makes
#      --from-dir installs quick). Only when no signed, pin-compatible
#      prebuilt exists does it clone the Sage repo, check out the exact
#      pinned commit, assert `git rev-parse HEAD` equals the pin, and compile
#      the `sage-cli` crate. The pinned commit IS the verification for the
#      source build — the artifact is built from pinned source, so no
#      release-artifact checksum is needed.
#      (Override: an operator-supplied $SAGE_BIN is accepted only with
#      SAGE_PIN_VERIFIED=1, i.e. verified out-of-band by the operator.)
#   3. Creates the dedicated `spellbook` OS user (S2), the client group, and the
#      0600/0700 layout. Generates the wallet seed ONCE and prints the paper
#      backup mnemonic ONCE — write it down, it is never shown again.
#   4. Installs the daemon (pip, isolated venv as the spellbook user), writes
#      the default-off policy (D9), the systemd unit, and the two tokens (S7).
#   5. Runs the §10 off-chain drill with a THROWAWAY key — never the real key.
#      Install completes when the drill passes (S14); the on-chain phases
#      print as a checklist and need their own explicit authorization.
#   6. Prints next steps (policy opt-in, token delivery, directory entry §8).
#
# What it NEVER does: asks for keys, transmits anything outward, touches the
# real muse key, auto-updates an existing install, or proceeds on an
# unverified release.

set -euo pipefail

REPO="https://github.com/awizardxch/Spellbook"
# Repo-vendored copy of the signed release artifacts (releases/<tag>/ in this
# repo). The installer tries the GitHub Release asset URLs first; the vendored
# copy is the fallback so upgrades keep working even if release-asset upload
# is unavailable. Either way the tarball is verified by sha256 AND by the
# pinned release-key signature before anything is installed.
VENDORED_BASE="https://raw.githubusercontent.com/awizardxch/Spellbook/main/releases"
SAGE_REPO="${SAGE_REPO:-https://github.com/xch-dev/sage}"
SAGE_COMMIT="f2ec89dd59d07227bed657bc268fc32ce97551f6"   # SPEC §3/D4
SPELLBOOK_USER="spellbook"
CLIENT_GROUP="spellbook-clients"
PREFIX="/opt/spellbook"
SOCK_DIR="/run/spellbook"
SOCK_PATH="${SOCK_DIR}/spellbook.sock"

# Release-key fingerprint is published in the pinned town thread once
# Speechless generates it (open decision #7). Until then installs from a
# release tarball cannot verify provenance — and refuse to proceed.
RELEASE_KEY_FPR="${SPELLBOOK_RELEASE_KEY_FPR:-}"

NO_SAGE=0
NO_SAGE_SET=0
FROM_DIR=""
UPGRADE=0
AGENT_USER=""
HUMAN_USER="${SUDO_USER:-}"
SAGE_PIN_VERIFIED="${SAGE_PIN_VERIFIED:-}"

log()  { printf '[spellbook-install] %s\n' "$*"; }
warn() { printf '[spellbook-install] WARNING: %s\n' "$*" >&2; }
fail() { printf '[spellbook-install] FATAL: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "missing required tool: $1"; }
norm_fpr() { echo "$1" | tr -d ' ' | tr 'a-f' 'A-F'; }   # canonical fingerprint form

# Canonical platform string for prebuilt Sage binaries (empty = unsupported).
detect_sage_platform() {
  case "$(uname -s)/$(uname -m)" in
    Linux/x86_64)  echo "linux-x86_64" ;;
    Linux/aarch64) echo "linux-aarch64" ;;
    Darwin/arm64)  echo "darwin-arm64" ;;
    Darwin/x86_64) echo "darwin-x86_64" ;;
    *)             echo "" ;;
  esac
}

# $1 = .asc file, $2 = data file. Returns 0 iff gpg reports VALIDSIG from
# the pinned release key — the same trust rule as the release tarball.
verify_release_sig() {
  [ -n "${RELEASE_KEY_FPR:-}" ] || return 1
  local sig_fpr
  sig_fpr="$(gpg --status-fd 1 --verify "$1" "$2" 2>/dev/null \
    | awk '/^\[GNUPG:\] VALIDSIG /{print $3}' | tail -1)"
  [ -n "$sig_fpr" ] || return 1
  [ "$(norm_fpr "$sig_fpr")" = "$(norm_fpr "$RELEASE_KEY_FPR")" ]
}

# Copy a local prebuilt Sage tarball + its sidecar files into the staging dir.
# $1 = source tarball path, $2 = staging dir. Sidecars (.sha256, .asc,
# .sage-pin) are copied when present; a missing sidecar is decided by the
# verifier, not here. Always returns 0.
stage_local_prebuilt() {
  local src="$1" dir="$2" base
  base="$(basename "$src")"
  cp -p "$src" "${dir}/${base}"
  [ -f "${src}.sha256" ]  && cp -p "${src}.sha256"  "${dir}/${base}.sha256"
  [ -f "${src}.asc" ]     && cp -p "${src}.asc"     "${dir}/${base}.asc"
  [ -f "${src}.sage-pin" ] && cp -p "${src}.sage-pin" "${dir}/${base}.sage-pin"
  return 0
}

# Verify + stage a prebuilt Sage tarball already present as $1/$2 (dir/file).
# $3 is the pin-check mode:
#   strict   — explicit operator path ($SPELLBOOK_SAGE_PREBUILT): a missing
#              .sage-pin sidecar or a pin mismatch fails hard.
#   lenient  — auto-discovered candidate: a missing sidecar or pin mismatch
#              just skips it (return 1) so the next candidate can be tried.
#   network  — downloaded for the release being installed: the filename's
#              version already binds it to this release's pin, so a missing
#              sidecar is accepted (logged); a present-but-mismatched sidecar
#              fails hard.
# A FAILED checksum or signature fails hard in every mode — a bad binary is
# never quietly skipped over. On success sets SAGE_BIN_STAGED and returns 0.
use_prebuilt_sage() {
  local dir="$1" tgz="$2" mode="$3" pin
  if [ ! -f "${dir}/${tgz}.sha256" ]; then
    case "$mode" in
      strict|network) fail "prebuilt ${tgz} has no checksum file (${tgz}.sha256) — refusing to continue" ;;
      lenient)        log "skipping prebuilt ${tgz}: no checksum file"; return 1 ;;
    esac
  fi
  ( cd "$dir" && sha256sum -c "${tgz}.sha256" >/dev/null ) \
    || fail "prebuilt ${tgz} checksum mismatch — refusing to install"
  [ -f "${dir}/${tgz}.asc" ] \
    || fail "prebuilt ${tgz} is present but its signature is missing — refusing to continue"
  verify_release_sig "${dir}/${tgz}.asc" "${dir}/${tgz}" \
    || fail "prebuilt ${tgz} signature is not from the pinned release key — refusing to install"
  # Pin compatibility: the binary must have been built from the Sage commit
  # this installer pins. The release process records it in a <tgz>.sage-pin
  # sidecar next to the tarball (see releases/0.3.2/ for the convention).
  if [ ! -f "${dir}/${tgz}.sage-pin" ]; then
    case "$mode" in
      strict)  fail "prebuilt ${tgz} has no .sage-pin sidecar — cannot confirm it was built from the pinned Sage commit ${SAGE_COMMIT}" ;;
      lenient) log "skipping prebuilt ${tgz}: no .sage-pin record (this install pins ${SAGE_COMMIT})"; return 1 ;;
      network) log "prebuilt ${tgz}: no .sage-pin sidecar; pin compatibility by release version match" ;;
    esac
  else
    pin="$(cat "${dir}/${tgz}.sage-pin")"
    if [ "$pin" != "$SAGE_COMMIT" ]; then
      case "$mode" in
        strict|network) fail "prebuilt ${tgz} was built from Sage commit ${pin}, but this install pins ${SAGE_COMMIT} — refusing to install" ;;
        lenient)        log "skipping prebuilt ${tgz}: built from Sage commit ${pin}, want ${SAGE_COMMIT}"; return 1 ;;
      esac
    fi
  fi
  log "prebuilt sage ${tgz}: checksum + release-key signature + Sage pin OK"
  tar xzf "${dir}/${tgz}" -C "$dir" \
    || fail "prebuilt ${tgz} would not extract"
  [ -x "${dir}/sage" ] \
    || fail "prebuilt ${tgz} contains no executable sage binary"
  SAGE_BIN_STAGED="${dir}/sage"
  log "using prebuilt sage ${tgz} — skipping the source build"
}

# Try a prebuilt Sage binary for $1 (platform), local sources before network.
# On success sets SAGE_BIN_STAGED and returns 0.
# A missing prebuilt (not published for this release/platform) warns and
# returns 1 so the caller falls back to the source build. A FAILED checksum
# or signature fails hard — a bad binary is never quietly skipped over.
try_prebuilt_sage() {
  local platform="$1"
  local tgz="sage-${TAG}-${platform}.tar.gz"
  local dir="${WORK}/sage-prebuilt"
  mkdir -p "$dir" || return 1

  # 1. Explicit operator path: $SPELLBOOK_SAGE_PREBUILT -> a sage-*.tar.gz.
  if [ -n "${SPELLBOOK_SAGE_PREBUILT:-}" ]; then
    [ -f "$SPELLBOOK_SAGE_PREBUILT" ] \
      || fail "SPELLBOOK_SAGE_PREBUILT=${SPELLBOOK_SAGE_PREBUILT} is not a file"
    stage_local_prebuilt "$SPELLBOOK_SAGE_PREBUILT" "$dir"
    use_prebuilt_sage "$dir" "$(basename "$SPELLBOOK_SAGE_PREBUILT")" strict
    return 0
  fi

  # 2. Repo-vendored prebuilts under ${SRC}/releases/. This is what makes
  #    --from-dir installs quick: TAG is empty there, so the network lookup
  #    below can never hit, and without this step every local install pays
  #    the ~20-minute source compile. Prefer the tarball matching the source
  #    tree's own version, then the newest pin-compatible one (e.g. a 0.3.3
  #    tree reusing the signed 0.3.2 binary while the Sage pin is unchanged).
  if [ -n "${SRC:-}" ] && [ -d "${SRC}/releases" ]; then
    local srcver cand
    srcver="$(cat "${SRC}/VERSION" 2>/dev/null || true)"
    for cand in "${SRC}/releases/${srcver}/sage-${srcver}-${platform}.tar.gz" \
                $(ls "${SRC}/releases/"*/sage-*-"${platform}".tar.gz 2>/dev/null | sort -Vr); do
      [ -f "$cand" ] || continue
      stage_local_prebuilt "$cand" "$dir"
      if use_prebuilt_sage "$dir" "$(basename "$cand")" lenient; then
        return 0
      fi
    done
  fi

  # 3. Network: GitHub Release assets, then the repo-vendored copy.
  if ! curl -fsSL -o "${dir}/${tgz}" "${REPO}/releases/download/${TAG}/${tgz}" 2>/dev/null \
      && ! curl -fsSL -o "${dir}/${tgz}" "${VENDORED_BASE}/${TAG}/${tgz}" 2>/dev/null; then
    warn "no prebuilt sage ${tgz} for release ${TAG} — building from source"
    return 1
  fi
  if ! curl -fsSL -o "${dir}/${tgz}.sha256" "${REPO}/releases/download/${TAG}/${tgz}.sha256" 2>/dev/null \
      && ! curl -fsSL -o "${dir}/${tgz}.sha256" "${VENDORED_BASE}/${TAG}/${tgz}.sha256" 2>/dev/null; then
    fail "prebuilt ${tgz} is published but its checksum file is missing — refusing to continue"
  fi
  if ! curl -fsSL -o "${dir}/${tgz}.asc" "${REPO}/releases/download/${TAG}/${tgz}.asc" 2>/dev/null \
      && ! curl -fsSL -o "${dir}/${tgz}.asc" "${VENDORED_BASE}/${TAG}/${tgz}.asc" 2>/dev/null; then
    fail "prebuilt ${tgz} is published but its signature is missing — refusing to continue"
  fi
  use_prebuilt_sage "$dir" "$tgz" network
  return 0
}

usage() {
  echo "usage: bash install.sh <tag> [--upgrade] [--no-sage] [--agent-user NAME] [--human-user NAME]"
  echo "       bash install.sh --from-dir DIR [--upgrade] [--no-sage] [--agent-user NAME] [--human-user NAME]"
  echo ""
  echo "  --upgrade        key-preserving upgrade of an existing install: replaces"
  echo "                   code/venv/systemd assets only. Never touches seed.key /"
  echo "                   std_seed.key / tokens / config / ledger / Sage data."
  echo "                   With a signed <tag> this is the agent self-serve path"
  echo "                   (via the spellbook-upgrade wrapper); --from-dir with"
  echo "                   --upgrade is human-driven (no signature to verify)."
  echo "                   Downgrades are the human's call — the agent wrapper"
  echo "                   refuses them, install.sh obeys."
  echo "  --no-sage        install EVM-only (Chia/Sage skipped; SPEC primary deliverable)"
  echo "  --agent-user     OS user the conversational agent runs as (required; in"
  echo "                   --upgrade mode defaults to the value in install.env)"
  echo "  --human-user     OS user whose tooling holds the approve token (default: \$SUDO_USER;"
  echo "                   in --upgrade mode defaults to the value in install.env)"
  echo "  --as-agent       the agent is running this install itself (self-install"
  echo "                   on the agent's own machine). Prints a structured HANDOFF"
  echo "                   block at the end: what the agent keeps (request token)"
  echo "                   vs what must go to the human out-of-band (approve token"
  echo "                   file location, paper backup). The agent must deliver the"
  echo "                   human's material and never retain it."
  exit 2
}

TAG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --no-sage) NO_SAGE=1; NO_SAGE_SET=1; shift ;;
    --upgrade) UPGRADE=1; shift ;;
    --from-dir) FROM_DIR="${2:-}"; shift 2 ;;
    --agent-user) AGENT_USER="${2:-}"; shift 2 ;;
    --human-user) HUMAN_USER="${2:-}"; shift 2 ;;
    --as-agent) AS_AGENT=1; shift ;;
    -h|--help) usage ;;
    *) [ -z "$TAG" ] && [ -z "$FROM_DIR" ] && TAG="$1" || usage; shift ;;
  esac
done
[ -n "$TAG" ] || [ -n "$FROM_DIR" ] || usage

# --upgrade: fill user flags from the install record (flags still win), and
# require an existing healthy install. Everything below treats --upgrade as
# "replace code, never identity".
if [ "$UPGRADE" = "1" ]; then
  [ -f "${PREFIX}/VERSION" ] \
    || fail "no install at ${PREFIX} — run a fresh install first (no --upgrade)"
  [ -f "${PREFIX}/install.env" ] \
    || fail "${PREFIX}/install.env missing — install record lost; human-driven reinstall needed"
  env_val() { grep -E "^${1}=" "${PREFIX}/install.env" | cut -d= -f2- | tr -d '"'; }
  [ -n "$AGENT_USER" ] || AGENT_USER="$(env_val SPELLBOOK_AGENT_USER)"
  [ -n "$HUMAN_USER" ] || HUMAN_USER="$(env_val SPELLBOOK_HUMAN_USER)"
  [ "$NO_SAGE_SET" = "1" ] || NO_SAGE="$(env_val SPELLBOOK_NO_SAGE)"
  ENV_SAGE_COMMIT="$(env_val SPELLBOOK_SAGE_COMMIT)"
  log "upgrade mode: installed version $(cat "${PREFIX}/VERSION"), identity will be preserved"
fi
[ -n "$AGENT_USER" ] || fail "--agent-user is required (the OS user your agent runs as)"
[ "$(id -u)" = "0" ] || fail "run as root (it creates the ${SPELLBOOK_USER} user)"
id "$AGENT_USER" >/dev/null 2>&1 || fail "agent user '$AGENT_USER' does not exist"
if [ -n "$HUMAN_USER" ]; then
  id "$HUMAN_USER" >/dev/null 2>&1 || fail "human user '$HUMAN_USER' does not exist"
else
  fail "cannot determine the human user: pass --human-user NAME"
fi
if [ "$AGENT_USER" = "$HUMAN_USER" ]; then
  warn "agent and human share one OS user. S2/S7 are weakened: the approve token"
  warn "must NEVER be at rest here (P5) — the human's tooling must prompt per use,"
  warn "ideally from a separate device (O5)."
fi

need curl; need sha256sum; need gpg; need tar; need useradd; need runuser
need systemctl; need python3; need id; need getent

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
# Resolve the installer's own path BEFORE cd "$WORK" below: $0 may be a
# relative path (e.g. `bash install.sh`), which stops resolving once we
# leave the invocation directory. The pinned copy for the upgrade wrapper
# needs the real file.
INSTALLER_SRC="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
[ -f "$INSTALLER_SRC" ] || fail "cannot locate installer source at $INSTALLER_SRC"
chmod 755 "$WORK"   # the spellbook user must traverse it (pip install runs as spellbook)
cd "$WORK"

# ---------------------------------------------------------------- 1. fetch + verify release
if [ -n "$FROM_DIR" ]; then
  warn "--from-dir: skipping download and signature verification (local test only)."
  SRC="$(cd "$FROM_DIR" && pwd)"
  [ -f "$SRC/pyproject.toml" ] || fail "$SRC does not look like the Spellbook source tree"
else
  log "fetching release ${TAG} ..."
  fetch_release_file() {  # $1 = local filename, $2 = remote asset filename
    if curl -fsSL -o "$1" "${REPO}/releases/download/${TAG}/$2" 2>/dev/null; then
      return 0
    fi
    warn "release asset $2 not on releases/download — trying repo-vendored copy"
    curl -fsSL -o "$1" "${VENDORED_BASE}/${TAG}/$2" \
      || fail "could not fetch $2 (tried GitHub Release assets and repo-vendored releases/${TAG}/)"
  }
  fetch_release_file "spellbook-${TAG}.tar.gz"     "spellbook-${TAG}.tar.gz"
  fetch_release_file "spellbook-${TAG}.sha256"     "spellbook-${TAG}.tar.gz.sha256"
  fetch_release_file "spellbook-${TAG}.tar.gz.asc" "spellbook-${TAG}.tar.gz.asc"

  log "verifying checksum ..."
  sha256sum -c "spellbook-${TAG}.sha256" || fail "checksum mismatch — refusing to install"

  if [ -n "$RELEASE_KEY_FPR" ]; then
    log "verifying release signature ..."
    # The release public key must be imported out-of-band (see README: the
    # fingerprint is pinned in the town thread; import the key, compare its
    # fingerprint yourself). We trust the signature ONLY if gpg reports a
    # valid signature AND the signer's fingerprint equals the pinned value.
    # A valid signature from any other key is refused.
    SIG_FPR="$(gpg --status-fd 1 --verify "spellbook-${TAG}.tar.gz.asc" \
      "spellbook-${TAG}.tar.gz" 2>/dev/null \
      | awk '/^\[GNUPG:\] VALIDSIG /{print $3}' | tail -1)"
    [ -n "$SIG_FPR" ] || fail "signature mismatch — refusing to install"
    [ "$(norm_fpr "$SIG_FPR")" = "$(norm_fpr "$RELEASE_KEY_FPR")" ] \
      || fail "signature valid but not from the pinned release key — refusing to install"
    log "signature OK (release key $(norm_fpr "$SIG_FPR"))"
  else
    fail "no release-key fingerprint configured (SPELLBOOK_RELEASE_KEY_FPR). refusing to install unverified code."
  fi

  tar xzf "spellbook-${TAG}.tar.gz"
  SRC="${WORK}/spellbook-${TAG}"
fi
[ -f "$SRC/pyproject.toml" ] || fail "source tree has no pyproject.toml"
log "source: $SRC"

# ---------------------------------------------------------------- 2. Sage CLI, pinned commit
# SPEC §3/D4 + §10 step 1 (P9): the Sage CLI comes from the pinned commit —
# preferably as a release-signed prebuilt binary (SHA-256 + release-key
# signature verified exactly like the release tarball, plus a .sage-pin
# sidecar proving it was built from the pinned commit), with the source
# build as the fallback. Prebuilt lookup order: $SPELLBOOK_SAGE_PREBUILT
# (explicit operator path), repo-vendored releases/ under the source tree
# (this is what keeps --from-dir installs quick), then the network
# (GitHub Release assets, then the repo-vendored copy). The source build
# clones the repo, checks out the exact commit, and asserts
# `git rev-parse HEAD` equals the pin before compiling; a version string is
# never trusted on its own.
# SPELLBOOK_SAGE_SOURCE=1 forces the source build.
#
# Upgrade fast path: if the pin in this release equals the pin the machine
# was installed with AND the installed binary is executable, the Sage build
# (minutes of compile) is skipped and the existing binary is kept. Sage data
# is never touched by upgrades either way.
CHIA_ENABLED=true
SAGE_BIN_STAGED=""   # path under $WORK; copied into ${PREFIX}/bin in §3
SKIP_SAGE_BUILD=0
if [ "$UPGRADE" = "1" ] && [ "$NO_SAGE" -eq 0 ] \
    && [ -n "${ENV_SAGE_COMMIT:-}" ] \
    && [ "$SAGE_COMMIT" = "$ENV_SAGE_COMMIT" ] \
    && [ -x "${PREFIX}/bin/sage" ]; then
  log "Sage pin unchanged (${SAGE_COMMIT}) — keeping installed binary"
  SAGE_BIN_STAGED="KEEP"
  SKIP_SAGE_BUILD=1
fi
if [ "$SKIP_SAGE_BUILD" = "1" ]; then
  : # fast path taken above
elif [ "$NO_SAGE" -eq 1 ]; then
  log "--no-sage: EVM-only install (Chia support can be added later)"
  CHIA_ENABLED=false
elif [ -n "${SAGE_BIN:-}" ] && [ "$SAGE_PIN_VERIFIED" = "1" ]; then
  # Operator-supplied binary, verified out-of-band by the operator.
  [ -x "$SAGE_BIN" ] || fail "SAGE_BIN is not executable: $SAGE_BIN"
  warn "SAGE_PIN_VERIFIED=1: trusting operator-supplied sage binary at ${SAGE_BIN}"
  SAGE_BIN_STAGED="$SAGE_BIN"
elif [ -n "${SAGE_BIN:-}" ]; then
  fail "SAGE_BIN was given without SAGE_PIN_VERIFIED=1 — refusing to trust an unverified binary. Verify it out-of-band and re-run with SAGE_PIN_VERIFIED=1, or unset SAGE_BIN to build from the pinned commit."
else
  # Prebuilt sage first (release-signed; verified exactly like the release
  # tarball). Missing prebuilt -> warn + source build. SPELLBOOK_SAGE_SOURCE=1
  # forces the source build.
  SAGE_WANT_SOURCE=1
  if [ -z "${SPELLBOOK_SAGE_SOURCE:-}" ]; then
    SAGE_PLATFORM="$(detect_sage_platform)"
    if [ -z "$SAGE_PLATFORM" ]; then
      warn "no prebuilt sage for $(uname -s)/$(uname -m) — building from source"
    elif try_prebuilt_sage "$SAGE_PLATFORM"; then
      SAGE_WANT_SOURCE=0
    fi
  else
    log "SPELLBOOK_SAGE_SOURCE=1: building sage from the pinned commit"
  fi
  if [ "$SAGE_WANT_SOURCE" = "1" ]; then
    need git; need cargo
    # The pinned Sage source uses edition2024 — cargo/rustc >= 1.85 is required.
    # (Distro cargo, e.g. apt's 1.75, dies with "feature `edition2024` is required".)
    CARGO_VER="$(cargo --version 2>/dev/null | awk '{print $2}')"
    [ -n "$CARGO_VER" ] && [ "$(printf '1.85.0\n%s\n' "$CARGO_VER" | sort -V | head -n1)" = "1.85.0" ] \
      || fail "cargo ${CARGO_VER:-unknown} is too old for the Sage build (needs >= 1.85 for edition2024). Install a current stable toolchain: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable"
    # bindgen (aws-lc-sys and friends) needs libclang at build time.
    # NOTE: no `grep -q` here — under `set -o pipefail`, grep -q exits on the
    # first match and ldconfig can die of SIGPIPE, failing this check ~10% of
    # runs. Plain grep drains the pipe, so the exit status is real.
    [ -n "$(ldconfig -p 2>/dev/null | grep libclang || true)" ] \
      || fail "libclang not found — the Sage build needs it (bindgen). On Debian/Ubuntu: apt-get install -y libclang-dev clang"
    # Persistent target dir, namespaced by Sage pin: a killed or re-run build
    # resumes instead of recompiling from zero (the bulk of the time is
    # pin-stable registry deps). Safe to delete at any time; the operator's own
    # CARGO_TARGET_DIR is honored when set.
    SAGE_TARGET_BASE="${SPELLBOOK_SAGE_TARGET_BASE:-/var/cache/spellbook/sage-target}"
    SAGE_TARGET_DIR="${CARGO_TARGET_DIR:-${SAGE_TARGET_BASE}/${SAGE_COMMIT}}"
    mkdir -p "$SAGE_TARGET_DIR" \
      || fail "could not create Sage target dir at $SAGE_TARGET_DIR"
    export CARGO_TARGET_DIR="$SAGE_TARGET_DIR"
    # The Sage release build needs several GB in the target dir. /tmp is often
    # a small tmpfs — if the target base lives somewhere tight, move it:
    # SPELLBOOK_SAGE_TARGET_BASE=/roomy/path (or CARGO_TARGET_DIR directly).
    TARGET_FREE_KB="$(df -k "$SAGE_TARGET_DIR" 2>/dev/null | awk 'NR==2 {print $4}')"
    { [ -n "$TARGET_FREE_KB" ] && [ "$TARGET_FREE_KB" -ge 5242880 ]; } \
      || fail "only ${TARGET_FREE_KB:-unknown} KB free under $SAGE_TARGET_DIR — the Sage build needs ~5 GB. Set SPELLBOOK_SAGE_TARGET_BASE (or CARGO_TARGET_DIR) to a roomier filesystem and re-run."
    log "building sage-cli from pinned commit ${SAGE_COMMIT} (target dir: $SAGE_TARGET_DIR) ..."
    SAGE_SRC="${WORK}/sage-src"
    git init -q "$SAGE_SRC"
    git -C "$SAGE_SRC" remote add origin "$SAGE_REPO"
    # Shallow-fetch just the pinned commit: less to download, hash still exact.
    git -C "$SAGE_SRC" fetch --depth 1 origin "$SAGE_COMMIT" \
      || fail "could not fetch Sage commit ${SAGE_COMMIT} from ${SAGE_REPO}"
    git -C "$SAGE_SRC" checkout -q FETCH_HEAD
    HEAD="$(git -C "$SAGE_SRC" rev-parse HEAD)"
    [ "$HEAD" = "$SAGE_COMMIT" ] \
      || fail "Sage checkout is ${HEAD}, not the pinned ${SAGE_COMMIT} — refusing to build"
    log "Sage source verified at pinned commit ${HEAD}"
    # Memory-aware cargo parallelism: a release rustc job can hold ~2 GB, so
    # cap jobs at available-RAM/2GB (and at nproc). An explicit CARGO_BUILD_JOBS
    # from the operator is always honored. This keeps the build alive on small
    # boxes instead of dying silently to the OOM killer mid-compile.
    if [ -z "${CARGO_BUILD_JOBS:-}" ]; then
      MEM_MB="$(awk '/^MemAvailable:/ {print int($2/1024)}' /proc/meminfo 2>/dev/null)"
      [ -n "$MEM_MB" ] || MEM_MB="$(awk '/^MemTotal:/ {print int($2/1024)}' /proc/meminfo 2>/dev/null)"
      NPROC="$(nproc 2>/dev/null || echo 2)"
      if [ -n "$MEM_MB" ] && [ "$MEM_MB" -gt 0 ] 2>/dev/null; then
        MEM_JOBS=$(( MEM_MB / 2048 ))
        [ "$MEM_JOBS" -ge 1 ] || MEM_JOBS=1
        [ "$NPROC" -lt "$MEM_JOBS" ] && MEM_JOBS="$NPROC"
        export CARGO_BUILD_JOBS="$MEM_JOBS"
        log "cargo build jobs: $MEM_JOBS (cpus=$NPROC, available RAM=${MEM_MB}MB)"
      else
        log "could not read available RAM — leaving cargo parallelism at its default"
      fi
    else
      log "cargo build jobs: ${CARGO_BUILD_JOBS} (operator override)"
    fi
    # Build with a heartbeat. The release compile runs 20+ minutes with no
    # output, so log progress every minute: elapsed time plus the crate
    # currently compiling. A silent death (OOM kill, lost session) then shows
    # up as a heartbeat that simply stops, instead of a mystery.
    SAGE_BUILD_LOG="${WORK}/sage-build.log"
    case "${SPELLBOOK_BUILD_HEARTBEAT_SECS:-60}" in
      ''|*[!0-9]*|0) HEARTBEAT_SECS=60 ;;
      *)             HEARTBEAT_SECS="${SPELLBOOK_BUILD_HEARTBEAT_SECS}" ;;
    esac
    ( cd "$SAGE_SRC" && cargo build --release -p sage-cli >"$SAGE_BUILD_LOG" 2>&1 ) &
    SAGE_BUILD_PID=$!
    SAGE_BUILD_START="$(date +%s)"
    while kill -0 "$SAGE_BUILD_PID" 2>/dev/null; do
      sleep "$HEARTBEAT_SECS"
      kill -0 "$SAGE_BUILD_PID" 2>/dev/null || break
      SAGE_ELAPSED=$(( $(date +%s) - SAGE_BUILD_START ))
      SAGE_LAST_CRATE="$(grep -o 'Compiling [^ ]*' "$SAGE_BUILD_LOG" 2>/dev/null | tail -1)"
      log "sage build running (${SAGE_ELAPSED}s elapsed${SAGE_LAST_CRATE:+, $SAGE_LAST_CRATE} ...) ..."
    done
    wait "$SAGE_BUILD_PID" \
      || fail "sage-cli build failed — last 30 lines of the build log:$(tail -30 "$SAGE_BUILD_LOG" 2>/dev/null | sed 's/^/  /')"
    SAGE_BIN_STAGED="${CARGO_TARGET_DIR}/release/sage"
    [ -x "$SAGE_BIN_STAGED" ] \
      || fail "sage-cli build produced no binary at $SAGE_BIN_STAGED"
  fi
fi

# ---------------------------------------------------------------- 3. OS user + layout (S2)
if ! id "${SPELLBOOK_USER}" >/dev/null 2>&1; then
  log "creating user ${SPELLBOOK_USER} ..."
  useradd --system --no-create-home --shell /usr/sbin/nologin "${SPELLBOOK_USER}"
fi
# A writable HOME for the venv's pip cache (the account itself has no home).
mkdir -p /home/"${SPELLBOOK_USER}"
chown "${SPELLBOOK_USER}:${SPELLBOOK_USER}" /home/"${SPELLBOOK_USER}"
chmod 700 /home/"${SPELLBOOK_USER}"
if ! getent group "${CLIENT_GROUP}" >/dev/null; then
  log "creating group ${CLIENT_GROUP} ..."
  groupadd --system "${CLIENT_GROUP}"
fi
usermod -a -G "${CLIENT_GROUP}" "${AGENT_USER}"
usermod -a -G "${CLIENT_GROUP}" "${HUMAN_USER}"
usermod -a -G "${CLIENT_GROUP}" "${SPELLBOOK_USER}"  # so the daemon may chgrp its socket

log "creating ${PREFIX} ..."
mkdir -p "${PREFIX}"
chown "${SPELLBOOK_USER}:${SPELLBOOK_USER}" "${PREFIX}"
chmod 0700 "${PREFIX}"

# The verified sage binary lives at one canonical path under the prefix —
# this is what the daemon will invoke (§10 step 1). Built from the pinned
# commit in §2, or copied from the operator-verified SAGE_BIN override.
SAGE_BIN_FINAL=""
if [ "$CHIA_ENABLED" = true ]; then
  mkdir -p "${PREFIX}/bin"
  # The daemon runs as SPELLBOOK_USER and must traverse bin/ to exec sage —
  # the dir inherits root ownership/umask from mkdir, so fix it explicitly
  # (the binary alone being 0755 is not enough).
  chown "${SPELLBOOK_USER}:${SPELLBOOK_USER}" "${PREFIX}/bin"
  chmod 0755 "${PREFIX}/bin"
  if [ "$SAGE_BIN_STAGED" = "KEEP" ]; then
    log "keeping installed sage binary (pin unchanged)"
    SAGE_BIN_FINAL="${PREFIX}/bin/sage"
  else
    cp "$SAGE_BIN_STAGED" "${PREFIX}/bin/sage"
    chown "${SPELLBOOK_USER}:${SPELLBOOK_USER}" "${PREFIX}/bin/sage"
    SAGE_BIN_FINAL="${PREFIX}/bin/sage"
  fi
  chmod 0755 "${PREFIX}/bin/sage"
  SAGE_BIN_FINAL="${PREFIX}/bin/sage"
  log "installed verified sage binary at ${SAGE_BIN_FINAL}"
  # Smoke-test the installed binary. The pinned sage-cli exposes no --version
  # flag (clap rejects it), so --help is the test — it still exercises real
  # startup, including the AWS-LC provider install in main(). Testing the
  # installed copy (not the staged one) also covers the upgrade fast path
  # ("KEEP"). Never swallow the output: a bare "failed" cost hours to diagnose.
  if ! SAGE_SMOKE_OUT="$("$SAGE_BIN_FINAL" --help 2>&1)"; then
    fail "sage smoke test ('sage --help') failed. Output: ${SAGE_SMOKE_OUT:-<empty>}"
  fi
  log "sage ready (smoke test passed)"
  # Sage's data home (DB + mTLS certs live under <home>/com.rigidnetwork.sage).
  # The daemon starts `sage rpc start` with XDG_DATA_HOME pointed here, so a
  # fresh install is ready to drill with no extra steps.
  mkdir -p "${PREFIX}/sage"
  chown "${SPELLBOOK_USER}:${SPELLBOOK_USER}" "${PREFIX}/sage"
  chmod 0700 "${PREFIX}/sage"
  log "sage data home at ${PREFIX}/sage"
fi

VENV="${PREFIX}/venv"
if [ ! -x "${VENV}/bin/python" ]; then
  log "creating isolated venv ..."
  runuser -u "${SPELLBOOK_USER}" -- python3 -m venv "${VENV}"
fi

# ---------------------------------------------------------------- 4. daemon + default-off policy (D9)
# Stage the source where the spellbook user can read it (the download dir is
# root-700; a --from-dir checkout may not be readable either).
STAGE="${WORK}/stage"
mkdir -p "${STAGE}"
if [ -n "$FROM_DIR" ]; then
  tar --exclude=.venv --exclude=.git -cf - -C "$SRC" . | tar -xf - -C "$STAGE"
else
  cp -r "${SRC}/." "$STAGE/"
fi
chown -R "${SPELLBOOK_USER}:${SPELLBOOK_USER}" "$STAGE"

log "installing the spellbook package ..."
# Upgrade mode: force-reinstall over the existing package so changed files
# are actually replaced (a plain `pip install` would see "already satisfied"
# and leave stale code in place).
PIP_REINSTALL=""
[ "$UPGRADE" = "1" ] && PIP_REINSTALL="--force-reinstall"
# shellcheck disable=SC2086
runuser -u "${SPELLBOOK_USER}" -- "${VENV}/bin/pip" install --quiet $PIP_REINSTALL "$STAGE" \
  || fail "pip install failed"

AGENT_UID="$(id -u "$AGENT_USER")"
HUMAN_UID="$(id -u "$HUMAN_USER")"

# The wallet seed: generated ONCE, as the spellbook user, 0600. The paper
# backup mnemonic prints ONCE below — write it down now (§6).
# Upgrade mode never touches key material: it must already be there, 0600.
# A missing key is a broken identity, not a repairable install — refuse and
# send the human to recovery instead of generating a new key (that would
# silently strand funds at the old addresses).
if [ "$UPGRADE" = "1" ]; then
  for k in seed.key std_seed.key; do
    [ -f "${PREFIX}/$k" ] || fail "${PREFIX}/$k missing — broken wallet identity; refusing to re-key (recovery is the human's call)"
  done
  log "key material present (untouched by upgrade)"
else
[ ! -e "${PREFIX}/seed.key" ] || fail "${PREFIX}/seed.key already exists — this machine looks installed. Refusing to overwrite; uninstall first."
log "generating the wallet seed (once) ..."
SEED_HEX="$(runuser -u "${SPELLBOOK_USER}" -- "${VENV}/bin/python" -c \
  "from spellbook.seed import generate_entropy; print(generate_entropy().hex())")"
printf '%s' "$SEED_HEX" > "${PREFIX}/seed.key"
chown "${SPELLBOOK_USER}:${SPELLBOOK_USER}" "${PREFIX}/seed.key"
chmod 0600 "${PREFIX}/seed.key"

# The standard-recovery wallet: a SECOND, independent 24-word BIP-39
# mnemonic whose keys derive the way stock wallets do (Sage / MetaMask).
# The daemon uses these keys (key_derivation=standard in the config below),
# so the standard backup is the primary recovery path; the KDF seed above
# stays as the daemon-native secondary. Its backup block prints ONCE in
# §6 — the output below is never logged anywhere else.
[ ! -e "${PREFIX}/std_seed.key" ] || fail "${PREFIX}/std_seed.key already exists — this machine looks installed. Refusing to overwrite; uninstall first."
log "generating the standard-recovery wallet (once) ..."
STD_BACKUP="$(runuser -u "${SPELLBOOK_USER}" -- "${VENV}/bin/python" \
  "${SRC}/scripts/make_standard_wallet.py" "${PREFIX}")"
fi

# Upgrade mode never rewrites config: the human's policy knobs stay exactly
# as they set them. The existing config must at least parse, or the upgrade
# stops rather than booting new code over a broken config.
if [ "$UPGRADE" = "1" ]; then
  log "keeping existing config (upgrade never rewrites it)"
  runuser -u "${SPELLBOOK_USER}" -- "${VENV}/bin/python" -c \
    "import json; json.load(open('${PREFIX}/spellbook.json'))" \
    || fail "existing spellbook.json does not parse — refusing to upgrade over a broken config"
else
log "writing config ..."
runuser -u "${SPELLBOOK_USER}" -- "${VENV}/bin/python" - "$PREFIX" "$AGENT_UID" "$HUMAN_UID" "$CHIA_ENABLED" "$SAGE_BIN_FINAL" <<'EOF'
import json, sys
prefix, agent_uid, human_uid, chia = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4] == "true"
sage_bin = sys.argv[5] or None
cfg = {
    "seed_path": f"{prefix}/seed.key",
    # Two-mnemonic wallet model (SPEC §2b). The daemon's LIVE keys are the
    # standard-recovery set below (Sage/MetaMask-compatible); the KDF seed
    # above stays as the daemon-native secondary recovery path. Existing
    # installs carry no key_derivation flag and default to "kdf" — untouched.
    "key_derivation": "standard",
    "std_seed_path": f"{prefix}/std_seed.key",
    "labels": ["default"],
    "chia_enabled": chia,
    "sage_bin": sage_bin,   # verified sage CLI (§10 step 1); null with --no-sage
    # Chia/Sage wiring (§10 phase 1): the daemon spawns `sage rpc start`
    # with XDG_DATA_HOME=sage_data_home, so Sage keeps its DB + mTLS certs
    # at <sage_data_home>/com.rigidnetwork.sage. mainnet spends stay gated
    # behind chia.mainnet_submit_enabled (separate authorization).
    # Dual-network wallet: ONE seed serves testnet11 AND mainnet (the KDF
    # derives per-chain keys; only the bech32m HRP differs, txch1 vs xch1),
    # so the paper backup shown at install covers both networks. `network`
    # is the active network — testnet11 default; flips to mainnet once
    # mainnet is authorized. `relay_urls` holds one relay per network
    # (each relay pins its own RELAY_NETWORK); empty string = unconfigured,
    # and the daemon fails closed on a missing relay for the active net.
    "chia": ({
        "sage_bin": sage_bin,
        "sage_data_home": f"{prefix}/sage",
        "rpc_port": 9257,
        "fee_mojos": 0,
        "network": "testnet11",
        "relay_urls": {"testnet11": "", "mainnet": ""},
        "mainnet_submit_enabled": False,
    } if chia else {}),
    # Solana wiring (direct HTTPS JSON-RPC — no relay, no Sage needed):
    # `network` is the active network — "devnet" default; "mainnet-beta" is
    # gated behind solana.mainnet_submit_enabled (separate authorization,
    # same bar as chia/evm mainnet). `rpc_url` empty = the default public
    # endpoint for the active network. A spend naming the non-active network
    # is refused before any policy evaluation.
    "solana": {
        "network": "devnet",
        "rpc_url": "",
        "mainnet_submit_enabled": False,
    },
    "socket_group": "spellbook-clients",
    "musebook_signing_mode": "disabled",   # S1: inert until Speechless decides
    "allowed_request_uids": [agent_uid],
    "allowed_approve_uids": [human_uid],
}
open(f"{prefix}/spellbook.json", "w").write(json.dumps(cfg, indent=2, sort_keys=True))
# D9: every knob default-off; S4 (town-adopted): with no policy configured the
# daemon queues every spend for human approval — a delay, not a cap. The
# hot wallet must hold nothing the human hasn't decided to risk.
open(f"{prefix}/policy.json", "w").write(json.dumps({}, indent=2))
open(f"{prefix}/ledger.jsonl", "a").close()
EOF
chown "${SPELLBOOK_USER}:${SPELLBOOK_USER}" "${PREFIX}/spellbook.json" "${PREFIX}/policy.json" "${PREFIX}/ledger.jsonl"
chmod 0600 "${PREFIX}/spellbook.json" "${PREFIX}/policy.json" "${PREFIX}/ledger.jsonl"
fi

# S7: two tokens from day one. The request token is shown ONCE for the
# agent's environment; the approve token is NEVER shown — move it to the
# human's separate device out-of-band (O5).
# Upgrade mode never mints tokens: a missing token is a broken install the
# human re-provisions, never something the installer silently replaces.
if [ "$UPGRADE" = "1" ]; then
  for t in request.token approve.token; do
    [ -f "${PREFIX}/$t" ] || fail "${PREFIX}/$t missing — broken token state; refusing to mint replacements (re-provision with the human)"
  done
  log "tokens present (untouched by upgrade)"
else
log "generating tokens ..."
REQ_TOKEN="$(runuser -u "${SPELLBOOK_USER}" -- "${VENV}/bin/python" -c "import secrets; print(secrets.token_hex(32))")"
APP_TOKEN="$(runuser -u "${SPELLBOOK_USER}" -- "${VENV}/bin/python" -c "import secrets; print(secrets.token_hex(32))")"
printf '%s' "$REQ_TOKEN" > "${PREFIX}/request.token"
printf '%s' "$APP_TOKEN" > "${PREFIX}/approve.token"
chown "${SPELLBOOK_USER}:${SPELLBOOK_USER}" "${PREFIX}/request.token" "${PREFIX}/approve.token"
chmod 0600 "${PREFIX}/request.token" "${PREFIX}/approve.token"
fi

# --- install record + agent self-serve upgrade path (fresh and upgrade) ---
# VERSION is the machine's canonical version. install.env is root-owned and
# records who installed and with what options, so --upgrade can run without
# re-asking (and so the upgrade wrapper can exec install.sh as root).
# ${PREFIX}/lib/install.sh is the pinned installer copy the privileged
# wrapper runs; /usr/local/bin/spellbook-upgrade is the agent's only root
# action (sudoers, NOPASSWD, exact path). All of these are refreshed on every
# install so upgrades keep the self-serve path working.
log "writing install record ..."
[ -f "${STAGE}/VERSION" ] || fail "release tree has no VERSION file — refusing to install an unversioned build"
NEW_VERSION="$(cat "${STAGE}/VERSION")"
printf '%s\n' "$NEW_VERSION" > "${PREFIX}/VERSION"
chmod 0644 "${PREFIX}/VERSION"
[ -f "${STAGE}/scripts/spellbook-upgrade" ] \
  || fail "release tree has no scripts/spellbook-upgrade — refusing to install a build without the self-serve path"
mkdir -p "${PREFIX}/lib"
# INSTALLER_SRC was resolved before cd "$WORK" (see above) — $0 may be
# relative and no longer resolves from here.
cp "$INSTALLER_SRC" "${PREFIX}/lib/install.sh"
chown root:root "${PREFIX}/lib/install.sh"; chmod 0755 "${PREFIX}/lib/install.sh"
# Seal ceremony HTML pages — offline human/agent handoff for fresh installs.
# The agent embeds a per-ceremony seal public key before handing to the human.
# See ceremony/README.md.
if [ -d "${STAGE}/ceremony" ]; then
  mkdir -p "${PREFIX}/share/ceremony"
  cp "${STAGE}/ceremony/"*.html "${STAGE}/ceremony/README.md" "${PREFIX}/share/ceremony/" 2>/dev/null || true
  chown -R root:root "${PREFIX}/share/ceremony"; chmod 0755 "${PREFIX}/share/ceremony"
  chmod 0644 "${PREFIX}"/share/ceremony/*
  log "installed seal ceremony pages to ${PREFIX}/share/ceremony/"
fi
cat > "${PREFIX}/install.env" <<EOF
# written by install.sh — root-owned; the spellbook-upgrade wrapper sources this
SPELLBOOK_AGENT_USER="${AGENT_USER}"
SPELLBOOK_HUMAN_USER="${HUMAN_USER}"
SPELLBOOK_NO_SAGE="${NO_SAGE}"
SPELLBOOK_SAGE_COMMIT="${SAGE_COMMIT}"
SPELLBOOK_INSTALLED_TAG="${TAG:-from-dir}"
SPELLBOOK_RELEASE_KEY_FPR="${RELEASE_KEY_FPR:-}"
EOF
chown root:root "${PREFIX}/install.env"; chmod 0600 "${PREFIX}/install.env"
cp "${STAGE}/scripts/spellbook-upgrade" /usr/local/bin/spellbook-upgrade
chown root:root /usr/local/bin/spellbook-upgrade; chmod 0755 /usr/local/bin/spellbook-upgrade
printf '# Spellbook: the agent user may run the signed-release upgrade wrapper only.\n%s ALL=(root) NOPASSWD: /usr/local/bin/spellbook-upgrade\n' \
  "$AGENT_USER" > /etc/sudoers.d/spellbook-agent-upgrade
chmod 0440 /etc/sudoers.d/spellbook-agent-upgrade
if command -v visudo >/dev/null 2>&1; then
  visudo -c -f /etc/sudoers.d/spellbook-agent-upgrade >/dev/null \
    || fail "sudoers entry failed validation — refusing to leave a broken sudoers.d file"
fi
log "install record written (version ${NEW_VERSION}; self-serve upgrade ready)"

log "installing the systemd unit ..."
cat > /etc/systemd/system/spellbookd.service <<EOF
[Unit]
Description=Spellbook policy daemon (per-agent wallet custody)
After=network.target

[Service]
Type=simple
User=${SPELLBOOK_USER}
Group=${SPELLBOOK_USER}
RuntimeDirectory=spellbook
ExecStart=${VENV}/bin/spellbookd --socket ${SOCK_PATH} --config ${PREFIX}
Restart=on-failure
RestartSec=5
# No auto-update, no network egress needed. Secrets never leave this host.

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --quiet spellbookd.service
systemctl restart spellbookd.service
sleep 2
systemctl is-active --quiet spellbookd.service || fail "spellbookd did not stay up — see journalctl -u spellbookd"

# ---------------------------------------------------------------- 5. off-chain drill, throwaway key (S14)
log "running the §10 off-chain drill (throwaway key — never the real one) ..."
runuser -u "${SPELLBOOK_USER}" -- "${VENV}/bin/python" -m spellbook.drill \
  --vectors "${STAGE}/vectors/vectors.json" \
  --status-out "${PREFIX}/drill-status.json" \
  || fail "drill failed — install rolled back to a clean non-running state"
chown "${SPELLBOOK_USER}:${SPELLBOOK_USER}" "${PREFIX}/drill-status.json"
chmod 0600 "${PREFIX}/drill-status.json"

# ---------------------------------------------------------------- 6. paper backup + next steps
# Upgrade mode prints NO key material, ever — the backup block below is for
# fresh installs only. An upgrade summary takes its place.
if [ "$UPGRADE" = "1" ]; then
cat <<EOF

UPGRADE COMPLETE.
  version:  $(cat "${PREFIX}/VERSION")
  replaced: spellbook package, systemd unit, install record, upgrade wrapper
  kept:     seed.key, std_seed.key, request/approve tokens, spellbook.json,
            policy.json, ledger.jsonl, queue/velocity state, Sage data,
            submission gates (mainnet_submit_enabled untouched)
  verify:   spellbook doctor          (re-run after every upgrade)
            spellbook version         (local vs daemon)
  next:     read what changed and do its after-upgrade steps:
            https://github.com/awizardxch/Spellbook/blob/$(cat "${PREFIX}/VERSION")/docs/AGENT_LIFECYCLE.md#upgrade-notes

If doctor reports a problem the upgrade did not fix, the human re-runs
install.sh --upgrade (or, for downgrades, runs install.sh directly as root).
EOF
else
MNEMONIC="$(runuser -u "${SPELLBOOK_USER}" -- "${VENV}/bin/python" -c \
  "from spellbook.seed import load_seed, mnemonic_from_entropy; print(mnemonic_from_entropy(load_seed('${PREFIX}/seed.key')))")"
# Raw KDF keys: each imports directly into the matching stock wallet and
# yields the same address the daemon uses (EVM -> MetaMask, BLS -> Sage).
KDF_KEYS="$(runuser -u "${SPELLBOOK_USER}" -- "${VENV}/bin/python" -c "
from spellbook.seed import load_seed
from spellbook import kdf, chia_sign
seed = load_seed('${PREFIX}/seed.key')
for chain in ('evm-4663', 'evm-46630'):
    d = kdf.derive_labeled(seed, chain, 'default')
    print('  ' + chain + ' raw EVM privkey -> MetaMask: ' + d['scalar_hex'])
    print('    address ' + d['address'])
for chain, net in (('chia-testnet', 'testnet11'), ('chia-mainnet', 'mainnet')):
    d = kdf.derive_labeled(seed, chain, 'default')
    sk = bytes.fromhex(d['scalar_hex'])
    print('  ' + chain + ' raw BLS key -> Sage: ' + d['scalar_hex'])
    print('    address ' + chia_sign.receive_address(sk, 0, net))
from spellbook import solana as solana_mod
for chain in ('solana-devnet', 'solana-mainnet'):
    kp = solana_mod.custom_keypair(seed, chain, 'default')
    print('  ' + chain + ' raw ed25519 secret -> Phantom import (base58 of 64-byte secret):')
    print('    ' + solana_mod.phantom_backup_secret(kp))
    print('    address ' + solana_mod.address_of_keypair(kp))
print('  Solana KDF keys differ per network by design (P9) and recover through')
print('  the daemon only - stock wallets derive unrelated keys from these words.')
")"

# First creation: save the displayed backup to a txt file as well, then show
# it — the human moves it somewhere safe (ideally off this machine) and
# removes it here. Fresh installs only; upgrades print no key material.
PAPER_TXT="${PREFIX}/paper-backup.txt"
cat > "${PAPER_TXT}" <<EOF

================================================================
INSTALL COMPLETE — off-chain drill green.
================================================================

PAPER BACKUP (§6) — write these down NOW, on paper, offline.
Shown ONCE and never again. Two copies, two places.
Anyone holding EITHER set below holds the wallet.

----------------------------------------------------------------
SET 1 — STANDARD RECOVERY (primary: these are the daemon's live keys).
The 24 words AND the raw keys work in STOCK wallets.
----------------------------------------------------------------

${STD_BACKUP}

----------------------------------------------------------------
SET 2 — SPELLBOOK DAEMON SEED (custom KDF — secondary recovery).
The 24 words recover through the Spellbook daemon ONLY (they do NOT
work in Sage/MetaMask); the raw keys below import directly and yield
the same addresses the daemon would use.
----------------------------------------------------------------

  24 WORDS (daemon recovery only):
    ${MNEMONIC}

${KDF_KEYS}

Verify after import: every address above must match what the wallet shows.

AGENT WIRING (request token — shown ONCE):
    export SPELLBOOK_SOCKET=${SOCK_PATH}
    export SPELLBOOK_REQUEST_TOKEN=${REQ_TOKEN}
  then:  python3 -c "from spellbook.client import AgentClient"

HUMAN APPROVAL (approve token — NEVER shown, NEVER in the agent's env):
  move ${PREFIX}/approve.token to the human's separate device out-of-band (O5),
  then approve from there:  spellbook approve <queue_id>

DERIVED ADDRESSES (labels: default):
EOF
chmod 600 "${PAPER_TXT}"
# Display the txt just created for the first time, then tell the human to
# store it somewhere safe.
cat "${PAPER_TXT}"
echo ""
echo "Paper backup also saved to ${PAPER_TXT} — store it somewhere safe"
echo "(ideally off this machine), then delete it here."
# As the agent's user: proves the socket, group, token, and peer-UID wiring
# all work end to end for the exact principal that will use it.
runuser -u "${AGENT_USER}" -- env "SPELLBOOK_SOCKET=${SOCK_PATH}" \
  "SPELLBOOK_REQUEST_TOKEN=${REQ_TOKEN}" "${VENV}/bin/spellbook" addresses

cat <<'EOF'

NEXT STEPS (all opt-in):
  - policy knobs: approval_threshold, allowlists, velocity caps (default: all off)
  - fund the derived addresses (testnet first — §10 needs explicit authorization)
  - town directory entry (§8)
  - the on-chain drill phases print in the drill output above
  - dashboard sign-in for agents is API-only: docs/AGENT_ONBOARDING.md §8
    (challenge -> local Ed25519 sign -> POST /api/auth/verify; your key
    never leaves this machine)

note: the default config is a signer, not a policy engine (S4).
EOF

# ---------------------------------------------------------------- backup verification
# The human proves they wrote down the SET 1 words (the primary recovery
# path) by typing 3 of them back. SET 1's words cannot be re-derived from
# std_seed.key later (BIP-39 seeds are one-way), so this is the one chance.
# Needs a human at a terminal: with no TTY (an agent-run --as-agent install)
# it is skipped with a warning, never faked, and the handoff below makes
# the paper backup the human's first job.
if [ "$UPGRADE" != "1" ]; then
  # The words are the line after "24 WORDS" in make_standard_wallet.py's block.
  STD_MNEMONIC="$(printf '%s\n' "${STD_BACKUP:-}" | awk '/24 WORDS/{getline; $1=$1; print; exit}')"
  if [ "$(printf '%s' "$STD_MNEMONIC" | wc -w | tr -d ' ')" != "24" ]; then
    warn "could not read the SET 1 words back for verification — check the paper copy against the block above by hand"
  elif [ ! -t 0 ]; then
    warn "no terminal: backup verification SKIPPED. The human must copy SET 1 to paper before anything else."
  else
cat <<'EOF'

================================================================
BACKUP VERIFICATION
================================================================
You were shown TWO sets of 24 words above (SET 1: standard recovery,
SET 2: daemon seed). SET 1 is the primary recovery path, and its words
are NEVER shown again.

To prove you've written them down, enter 3 words from SET 1 when asked.
Get them from your PAPER copy — not by scrolling up.
EOF
  POS1=$((RANDOM % 24 + 1))
  POS2=$((RANDOM % 24 + 1))
  while [ "$POS2" = "$POS1" ]; do POS2=$((RANDOM % 24 + 1)); done
  POS3=$((RANDOM % 24 + 1))
  while [ "$POS3" = "$POS1" ] || [ "$POS3" = "$POS2" ]; do POS3=$((RANDOM % 24 + 1)); done
  WORD1=$(printf '%s' "$STD_MNEMONIC" | cut -d' ' -f"$POS1")
  WORD2=$(printf '%s' "$STD_MNEMONIC" | cut -d' ' -f"$POS2")
  WORD3=$(printf '%s' "$STD_MNEMONIC" | cut -d' ' -f"$POS3")

  VERIFIED=0
  for attempt in 1 2 3; do
    INPUT1=""; INPUT2=""; INPUT3=""
    echo ""
    echo "Enter word #$POS1 from SET 1 (from your paper backup):"
    read -r INPUT1 || true
    echo "Enter word #$POS2 from SET 1:"
    read -r INPUT2 || true
    echo "Enter word #$POS3 from SET 1:"
    read -r INPUT3 || true
    INPUT1=$(printf '%s' "$INPUT1" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
    INPUT2=$(printf '%s' "$INPUT2" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
    INPUT3=$(printf '%s' "$INPUT3" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
    if [ "$INPUT1" = "$WORD1" ] && [ "$INPUT2" = "$WORD2" ] && [ "$INPUT3" = "$WORD3" ]; then
      VERIFIED=1
      echo ""
      echo "✓ Backup verified. Remember: two copies, two places."
      break
    elif [ "$attempt" != "3" ]; then
      echo ""
      echo "✗ Words don't match. Check your paper backup and try again. (Attempt $attempt of 3)"
    fi
  done
  if [ "$VERIFIED" != "1" ]; then
    echo ""
    echo "✗ Verification failed 3 times. The wallet is installed WITHOUT a"
    echo "  verified SET 1 backup, and SET 1's words cannot be shown again."
    echo "  Back up the raw keys and SET 2 now (as the ${SPELLBOOK_USER} user):"
    echo "    ${VENV}/bin/python -m spellbook.recovery --config-dir ${PREFIX} backup"
  fi
  fi
  unset STD_MNEMONIC WORD1 WORD2 WORD3 INPUT1 INPUT2 INPUT3
cat <<EOF

SEAL THE SEED (recommended — survives machine wipes, docs/SEALED_SEED.md):
  a password-locked copy of the seed that the human can unlock after a
  wipe from a one-time local page, without re-typing any words:
    ${VENV}/bin/spellbook-seed --config-dir ${PREFIX} --sealed <persistent path> serve
EOF
fi
if [ "${AS_AGENT:-0}" = "1" ]; then
cat <<EOF

================================================================
AGENT HANDOFF — you ran this install yourself. Follow the protocol.
================================================================

YOURS (store in your environment file, never in chat/logs/code):
  export SPELLBOOK_SOCKET=${SOCK_PATH}
  export SPELLBOOK_REQUEST_TOKEN=<redacted>
  (also at ${PREFIX}/request.token, 0600 — the daemon already has it)

HUMAN'S (deliver out-of-band NOW, then never touch again):
  1. Approve token — file: ${PREFIX}/approve.token (0600).
     Have YOUR HUMAN copy it to their separate device using THEIR OWN
     machine access (O5). NEVER read it into your environment, logs, or
     chat. The daemon verifies approvals against it; you must not be able
     to approve your own spends.
  2. Paper backup — the two word sets printed above. Read them to your
     human; they write them down on paper, offline, two copies in two
     places. Confirm receipt, then drop the words from your context. The
     daemon keeps seed.key; you keep no copy.

VERIFY BEFORE YOU FINISH:
  spellbook doctor    # every check green
  spellbook version   # local == installed == daemon

From here you self-serve: spellbook upgrade --check / spellbook upgrade
<tag> (signed releases, forward-only) and spellbook doctor --repair.
================================================================
EOF
fi
fi
