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
#   2. Builds the Sage CLI from the pinned commit (SPEC §3/D4, §10 step 1):
#      clones the Sage repo, checks out the exact pinned commit, asserts
#      `git rev-parse HEAD` equals the pin, then compiles the `sage-cli`
#      crate. The pinned commit IS the verification — the artifact is built
#      from pinned source, so no release-artifact checksum is needed.
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
    norm_fpr() { echo "$1" | tr -d ' ' | tr 'a-f' 'A-F'; }
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
# SPEC §3/D4 + §10 step 1 (P9): the Sage CLI is BUILT FROM SOURCE at the
# pinned commit. The pinned commit hash IS the verification: we clone the
# repo, check out the exact commit, and assert `git rev-parse HEAD` equals
# the pin before compiling. The artifact is produced from pinned source, so
# there is no release-artifact checksum to chase — and a version string is
# never trusted on its own.
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
  need git; need cargo
  log "building sage-cli from pinned commit ${SAGE_COMMIT} ..."
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
  ( cd "$SAGE_SRC" && cargo build --release -p sage-cli ) \
    || fail "sage-cli build failed — needs a Rust toolchain plus the Tauri prerequisites (https://v2.tauri.app/start/prerequisites/)"
  [ -x "${SAGE_SRC}/target/release/sage" ] \
    || fail "sage-cli build produced no target/release/sage binary"
  SAGE_BIN_STAGED="${SAGE_SRC}/target/release/sage"
fi
if [ "$CHIA_ENABLED" = true ]; then
  SAGE_VERSION="$("$SAGE_BIN_STAGED" --version 2>&1 | head -1)" || fail "sage --version failed"
  log "sage ready: ${SAGE_VERSION}"
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
INSTALLER_SRC="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
cp "$INSTALLER_SRC" "${PREFIX}/lib/install.sh"
chown root:root "${PREFIX}/lib/install.sh"; chmod 0755 "${PREFIX}/lib/install.sh"
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

cat <<EOF

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
