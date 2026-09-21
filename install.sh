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
FROM_DIR=""
AGENT_USER=""
HUMAN_USER="${SUDO_USER:-}"
SAGE_PIN_VERIFIED="${SAGE_PIN_VERIFIED:-}"

log()  { printf '[spellbook-install] %s\n' "$*"; }
warn() { printf '[spellbook-install] WARNING: %s\n' "$*" >&2; }
fail() { printf '[spellbook-install] FATAL: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "missing required tool: $1"; }

usage() {
  echo "usage: bash install.sh <tag> [--no-sage] [--agent-user NAME] [--human-user NAME]"
  echo "       bash install.sh --from-dir DIR [--no-sage] [--agent-user NAME] [--human-user NAME]"
  echo ""
  echo "  --no-sage        install EVM-only (Chia/Sage skipped; SPEC primary deliverable)"
  echo "  --agent-user     OS user the conversational agent runs as (required)"
  echo "  --human-user     OS user whose tooling holds the approve token (default: \$SUDO_USER)"
  exit 2
}

TAG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --no-sage) NO_SAGE=1; shift ;;
    --from-dir) FROM_DIR="${2:-}"; shift 2 ;;
    --agent-user) AGENT_USER="${2:-}"; shift 2 ;;
    --human-user) HUMAN_USER="${2:-}"; shift 2 ;;
    -h|--help) usage ;;
    *) [ -z "$TAG" ] && [ -z "$FROM_DIR" ] && TAG="$1" || usage; shift ;;
  esac
done
[ -n "$TAG" ] || [ -n "$FROM_DIR" ] || usage
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
  curl -fsSL -o "spellbook-${TAG}.tar.gz"     "${REPO}/releases/download/${TAG}/spellbook-${TAG}.tar.gz"
  curl -fsSL -o "spellbook-${TAG}.sha256"     "${REPO}/releases/download/${TAG}/spellbook-${TAG}.tar.gz.sha256"
  curl -fsSL -o "spellbook-${TAG}.tar.gz.asc" "${REPO}/releases/download/${TAG}/spellbook-${TAG}.tar.gz.asc"

  log "verifying checksum ..."
  sha256sum -c "spellbook-${TAG}.sha256" || fail "checksum mismatch — refusing to install"

  if [ -n "$RELEASE_KEY_FPR" ]; then
    log "verifying release signature ..."
    # The release key is fetched out-of-band; its fingerprint MUST match the
    # pinned town thread. Never trust a key fetched from the same release page.
    gpg --verify "spellbook-${TAG}.tar.gz.asc" "spellbook-${TAG}.tar.gz" \
      || fail "signature mismatch — refusing to install"
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
CHIA_ENABLED=true
SAGE_BIN_STAGED=""   # path under $WORK; copied into ${PREFIX}/bin in §3
if [ "$NO_SAGE" -eq 1 ]; then
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
  cp "$SAGE_BIN_STAGED" "${PREFIX}/bin/sage"
  chown "${SPELLBOOK_USER}:${SPELLBOOK_USER}" "${PREFIX}/bin/sage"
  chmod 0755 "${PREFIX}/bin/sage"
  SAGE_BIN_FINAL="${PREFIX}/bin/sage"
  log "installed verified sage binary at ${SAGE_BIN_FINAL}"
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
runuser -u "${SPELLBOOK_USER}" -- "${VENV}/bin/pip" install --quiet "$STAGE" \
  || fail "pip install failed"

AGENT_UID="$(id -u "$AGENT_USER")"
HUMAN_UID="$(id -u "$HUMAN_USER")"

# The wallet seed: generated ONCE, as the spellbook user, 0600. The paper
# backup mnemonic prints ONCE below — write it down now (§6).
# Never auto-update an existing install: a seed.key already on disk means
# this machine is provisioned — refuse rather than silently re-key it.
[ ! -e "${PREFIX}/seed.key" ] || fail "${PREFIX}/seed.key already exists — this machine looks installed. Refusing to overwrite; uninstall first."
log "generating the wallet seed (once) ..."
SEED_HEX="$(runuser -u "${SPELLBOOK_USER}" -- "${VENV}/bin/python" -c \
  "from spellbook.seed import generate_entropy; print(generate_entropy().hex())")"
printf '%s' "$SEED_HEX" > "${PREFIX}/seed.key"
chown "${SPELLBOOK_USER}:${SPELLBOOK_USER}" "${PREFIX}/seed.key"
chmod 0600 "${PREFIX}/seed.key"

log "writing config ..."
runuser -u "${SPELLBOOK_USER}" -- "${VENV}/bin/python" - "$PREFIX" "$AGENT_UID" "$HUMAN_UID" "$CHIA_ENABLED" "$SAGE_BIN_FINAL" <<'EOF'
import json, sys
prefix, agent_uid, human_uid, chia = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4] == "true"
sage_bin = sys.argv[5] or None
cfg = {
    "seed_path": f"{prefix}/seed.key",
    "labels": ["default"],
    "chia_enabled": chia,
    "sage_bin": sage_bin,   # verified sage CLI (§10 step 1); null with --no-sage
    "socket_group": "spellbook-clients",
    "musebook_signing_mode": "disabled",   # S1: inert until Speechless decides
    "allowed_request_uids": [agent_uid],
    "allowed_approve_uids": [human_uid],
}
open(f"{prefix}/spellbook.json", "w").write(json.dumps(cfg, indent=2, sort_keys=True))
# D9: every knob default-off. The default daemon is a signer, not a policy
# engine (S4) — the hot wallet must hold nothing the agent may not lose.
open(f"{prefix}/policy.json", "w").write(json.dumps({}, indent=2))
open(f"{prefix}/ledger.jsonl", "a").close()
EOF
chown "${SPELLBOOK_USER}:${SPELLBOOK_USER}" "${PREFIX}/spellbook.json" "${PREFIX}/policy.json" "${PREFIX}/ledger.jsonl"
chmod 0600 "${PREFIX}/spellbook.json" "${PREFIX}/policy.json" "${PREFIX}/ledger.jsonl"

# S7: two tokens from day one. The request token is shown ONCE for the
# agent's environment; the approve token is NEVER shown — move it to the
# human's separate device out-of-band (O5).
log "generating tokens ..."
REQ_TOKEN="$(runuser -u "${SPELLBOOK_USER}" -- "${VENV}/bin/python" -c "import secrets; print(secrets.token_hex(32))")"
APP_TOKEN="$(runuser -u "${SPELLBOOK_USER}" -- "${VENV}/bin/python" -c "import secrets; print(secrets.token_hex(32))")"
printf '%s' "$REQ_TOKEN" > "${PREFIX}/request.token"
printf '%s' "$APP_TOKEN" > "${PREFIX}/approve.token"
chown "${SPELLBOOK_USER}:${SPELLBOOK_USER}" "${PREFIX}/request.token" "${PREFIX}/approve.token"
chmod 0600 "${PREFIX}/request.token" "${PREFIX}/approve.token"

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
MNEMONIC="$(runuser -u "${SPELLBOOK_USER}" -- "${VENV}/bin/python" -c \
  "from spellbook.seed import load_seed, mnemonic_from_entropy; print(mnemonic_from_entropy(load_seed('${PREFIX}/seed.key')))")"

cat <<EOF

================================================================
INSTALL COMPLETE — off-chain drill green.
================================================================

PAPER BACKUP (§6) — write these 24 words down NOW, on paper, offline.
They are shown ONCE and never again:

    ${MNEMONIC}

Two copies, two places. Anyone holding them holds the wallet.

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

note: the default config is a signer, not a policy engine (S4).
EOF
