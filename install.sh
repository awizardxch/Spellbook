#!/usr/bin/env bash
#
# Spellbook installer — SPEC_V1.md §14 (S9: verify before you run).
#
# This script is NEVER piped from curl. The documented flow is:
#   curl -fsSL -o install.sh \
#     https://raw.githubusercontent.com/awizardxch/Spellbook/<tag>/install.sh
#   sha256sum -c  # against the hash in the pinned town thread and README
#   bash install.sh <tag>
#
# What it does:
#   1. Verifies the release tarball (checksum + release-key signature) — fail closed.
#   2. Installs Sage CLI from the pinned commit (SPEC §3/D4).
#   3. Creates the dedicated `spellbook` OS user (S2) and the 0600/0700 layout.
#   4. Installs the daemon under that user; writes the default-off policy config (D9).
#   5. Runs the §10 testnet drill with a THROWAWAY key — never the real muse key.
#      Install only completes when the drill passes (S14).
#   6. Prints next steps (policy opt-in, paper backup §6, directory entry §8).
#
# What it NEVER does: asks for keys, transmits anything outward, touches the
# real muse key, or auto-updates an existing install.
#
# Status: scaffold. Release-key material, daemon build, and the drill runner
# are TODOs marked below. Safe to read; not yet safe to run for real.

set -euo pipefail

REPO="https://github.com/awizardxch/Spellbook"
SAGE_COMMIT="f2ec89dd59d07227bed657bc268fc32ce97551f6"   # SPEC §3/D4
SPELLBOOK_USER="spellbook"

# TODO(open): release-key fingerprint is published in the pinned town thread
# once Speechless generates it. Until then installs cannot verify provenance.
RELEASE_KEY_FPR="${SPELLBOOK_RELEASE_KEY_FPR:-}"

log()  { printf '[spellbook-install] %s\n' "$*"; }
fail() { printf '[spellbook-install] FATAL: %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || fail "missing required tool: $1"; }

usage() {
  echo "usage: bash install.sh <tag>   (e.g. bash install.sh v0.1.0)"
  echo "  downloads, verifies, then installs. never curl|bash."
  exit 2
}

TAG="${1:-}"; [ -n "$TAG" ] || usage
[ "$(id -u)" = "0" ] || fail "run as root (it creates the ${SPELLBOOK_USER} user)"

need curl; need sha256sum; need gpg; need tar; need useradd

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

# ---------------------------------------------------------------- 1. fetch + verify release
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

# ---------------------------------------------------------------- 2. Sage CLI, pinned commit
log "installing Sage CLI @ ${SAGE_COMMIT} ..."
# TODO(build): resolve the pinned commit to a published Sage release artifact,
# verify the artifact checksum against the release built from ${SAGE_COMMIT},
# and install. A version string is not proof of the pinned commit (P9).
#   See SPEC §10 step 1.
fail "TODO: Sage pinned-commit install not yet implemented"

# ---------------------------------------------------------------- 3. OS user + layout (S2)
if ! id "${SPELLBOOK_USER}" >/dev/null 2>&1; then
  log "creating user ${SPELLBOOK_USER} ..."
  useradd --system --no-create-home --shell /usr/sbin/nologin "${SPELLBOOK_USER}"
fi
# TODO(build): create dirs as ${SPELLBOOK_USER}: seed file (0600), sage data
# (0700), mTLS certs (0600), export dir (0700), decision ledger (0600),
# token files (0600). The agent's user must read exactly one: the request token.

# ---------------------------------------------------------------- 4. daemon + default-off policy (D9)
# TODO(build): build/install daemon from ${SRC}/daemon under ${SPELLBOOK_USER},
# write /etc/spellbook/policy.json with every knob default-off, install the
# systemd unit (DynamicUser= where available), and run the §2 KDF vectors
# against the built daemon before going further.

# ---------------------------------------------------------------- 5. testnet drill, throwaway key (S14)
# TODO(build): run the §10 drill with an ephemeral key. Minus the rotation
# drill (maintainer's machine only). A failed drill leaves the machine clean
# and prints how to resume without reinstalling.

# ---------------------------------------------------------------- 6. next steps
cat <<'EOF'
install complete — drill green.
next steps (all opt-in):
  - policy knobs: approval_threshold, allowlists, velocity caps (default: all off)
  - paper backup: run the local `spellbook export` on the daemon's own TTY (§6)
  - town directory entry (§8)
note: the default config is a signer, not a policy engine (S4).
EOF
