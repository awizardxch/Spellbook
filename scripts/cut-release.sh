#!/usr/bin/env bash
#
# Cut a signed Spellbook release — run by the MAINTAINER, on the machine
# that holds the release key. Agents only ever install what this produces
# (install.sh verifies the SHA-256 AND this signature before installing).
#
#   git checkout main && git pull        # run it ON main, not the tag
#   bash scripts/cut-release.sh 0.3.0
#
# The tarball is built from the TAG (git archive), whatever HEAD is, so the
# signed files land on main where install.sh's vendored fallback looks.
# Preconditions it checks: the tag exists and its VERSION == tag, a clean
# tree, and the release key (docs/RELEASE_KEY.md) available to gpg.
# Output: releases/<tag>/ with the signed files install.sh fetches (the
# release tarball triple plus, on supported build platforms, the prebuilt
# Sage binary triple). It never pushes or publishes — it prints those steps
# for you.

set -euo pipefail

FPR="${SPELLBOOK_RELEASE_KEY_FPR:-7DEA43CA62DF3F8FB041C1551FCF79089E54DC35}"   # docs/RELEASE_KEY.md
TAG="${1:-}"
fail() { printf 'cut-release: %s\n' "$*" >&2; exit 1; }

[[ "$TAG" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "usage: cut-release.sh X.Y.Z"
cd "$(git rev-parse --show-toplevel)"
[ -z "$(git status --porcelain)" ] || fail "working tree not clean"
git rev-parse -q --verify "refs/tags/$TAG" >/dev/null \
  || fail "tag $TAG missing: git tag -a $TAG -m 'Spellbook $TAG' && git push origin $TAG"
[ "$(git show "$TAG:VERSION" | tr -d '[:space:]')" = "$TAG" ] \
  || fail "VERSION inside tag $TAG is not $TAG"
git symbolic-ref -q HEAD >/dev/null \
  || fail "detached HEAD — run this on main (git checkout main && git pull)"
gpg --list-secret-keys "$FPR" >/dev/null 2>&1 \
  || fail "release key $FPR not in this gpg keyring"

OUT="releases/$TAG"
[ ! -e "$OUT" ] || fail "$OUT already exists — releases are never re-cut"
mkdir -p "$OUT"
TGZ="spellbook-$TAG.tar.gz"

git archive --format=tar.gz --prefix="spellbook-$TAG/" -o "$OUT/$TGZ" "$TAG"
(cd "$OUT" && sha256sum "$TGZ" > "$TGZ.sha256")
gpg --local-user "$FPR" --armor --detach-sign -o "$OUT/$TGZ.asc" "$OUT/$TGZ"

# Verify exactly as install.sh will.
(cd "$OUT" && sha256sum -c "$TGZ.sha256" >/dev/null) || fail "checksum self-check failed"
SIG_FPR="$(gpg --status-fd 1 --verify "$OUT/$TGZ.asc" "$OUT/$TGZ" 2>/dev/null \
  | awk '/VALIDSIG/ {print $3; exit}')"
[ "$SIG_FPR" = "$FPR" ] || fail "signature self-check failed (got '$SIG_FPR')"

# Prebuilt Sage binary. Built from the pinned Sage commit, packaged +
# checksummed + signed exactly like the release tarball, so install.sh
# verifies it the same way. Only the release's supported build platforms
# produce one; install.sh falls back to the source build otherwise.
# SPELLBOOK_SKIP_SAGE_PREBUILT=1 cuts a release without it.
SAGE_PUBLISH_LINES=""
SAGE_PLATFORM=""
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) SAGE_PLATFORM="linux-x86_64" ;;
esac
if [ -n "${SPELLBOOK_SKIP_SAGE_PREBUILT:-}" ]; then
  printf 'cut-release: SPELLBOOK_SKIP_SAGE_PREBUILT=1 — skipping prebuilt Sage\n' >&2
elif [ -z "$SAGE_PLATFORM" ]; then
  printf 'cut-release: WARNING: no prebuilt Sage for %s/%s — release ships without one (install.sh falls back to source build)\n' \
    "$(uname -s)" "$(uname -m)" >&2
else
  command -v cargo >/dev/null 2>&1 \
    || fail "cargo not found — the prebuilt Sage needs a Rust toolchain"
  ldconfig -p 2>/dev/null | grep -q libclang \
    || fail "libclang not found — the prebuilt Sage build needs it (bindgen)"
  SAGE_COMMIT_PIN="$(awk -F'\"' '/^SAGE_COMMIT="/ {print $2; exit}' install.sh)"
  # SAGE_REPO in install.sh is SAGE_REPO="${SAGE_REPO:-<url>}"; unwrap the default.
  SAGE_REPO_PIN="$(sed -n 's/^SAGE_REPO="${SAGE_REPO:-\(https\?:[^"]*\)}"$/\1/p' install.sh)"
  [[ "$SAGE_COMMIT_PIN" =~ ^[0-9a-f]{40}$ ]] \
    || fail "could not read a valid SAGE_COMMIT pin from install.sh"
  [[ "$SAGE_REPO_PIN" == https://* ]] \
    || fail "could not read SAGE_REPO from install.sh"
  # The prebuilt needs several GB for the cargo target dir.
  SAGE_TARGET_DIR="${CARGO_TARGET_DIR:-/var/cache/spellbook/sage-target/${SAGE_COMMIT_PIN}}"
  mkdir -p "$SAGE_TARGET_DIR" || fail "could not create $SAGE_TARGET_DIR"
  TARGET_FREE_KB="$(df -k "$SAGE_TARGET_DIR" 2>/dev/null | awk 'NR==2 {print $4}')"
  { [ -n "$TARGET_FREE_KB" ] && [ "$TARGET_FREE_KB" -ge 5242880 ]; } \
    || fail "only ${TARGET_FREE_KB:-unknown} KB free under $SAGE_TARGET_DIR — the prebuilt Sage build needs ~5 GB"
  printf 'cut-release: building prebuilt sage from pinned commit %s ...\n' "$SAGE_COMMIT_PIN" >&2
  SAGE_BUILD_DIR="$(mktemp -d)"
  trap 'rm -rf "${SAGE_BUILD_DIR:-}"' EXIT
  git init -q "$SAGE_BUILD_DIR"
  git -C "$SAGE_BUILD_DIR" remote add origin "$SAGE_REPO_PIN"
  git -C "$SAGE_BUILD_DIR" fetch --depth 1 origin "$SAGE_COMMIT_PIN"
  git -C "$SAGE_BUILD_DIR" checkout -q FETCH_HEAD
  [ "$(git -C "$SAGE_BUILD_DIR" rev-parse HEAD)" = "$SAGE_COMMIT_PIN" ] \
    || fail "Sage checkout is not the pinned commit — refusing to package a prebuilt"
  export CARGO_TARGET_DIR="$SAGE_TARGET_DIR"
  ( cd "$SAGE_BUILD_DIR" && cargo build --release -p sage-cli )
  SAGE_STAGED_BIN="${CARGO_TARGET_DIR}/release/sage"
  [ -x "$SAGE_STAGED_BIN" ] || fail "sage build produced no binary at $SAGE_STAGED_BIN"
  SAGE_TGZ="sage-${TAG}-${SAGE_PLATFORM}.tar.gz"
  SAGE_PKGDIR="$(mktemp -d)"
  cp "$SAGE_STAGED_BIN" "$SAGE_PKGDIR/sage"
  chmod 755 "$SAGE_PKGDIR/sage"
  tar -czf "$OUT/$SAGE_TGZ" -C "$SAGE_PKGDIR" sage
  rm -rf "$SAGE_PKGDIR"
  (cd "$OUT" && sha256sum "$SAGE_TGZ" > "$SAGE_TGZ.sha256")
  gpg --local-user "$FPR" --armor --detach-sign -o "$OUT/$SAGE_TGZ.asc" "$OUT/$SAGE_TGZ"
  # Verify exactly as install.sh will.
  (cd "$OUT" && sha256sum -c "$SAGE_TGZ.sha256" >/dev/null) || fail "sage prebuilt checksum self-check failed"
  SAGE_SIG_FPR="$(gpg --status-fd 1 --verify "$OUT/$SAGE_TGZ.asc" "$OUT/$SAGE_TGZ" 2>/dev/null \
    | awk '/VALIDSIG/ {print $3; exit}')"
  [ "$SAGE_SIG_FPR" = "$FPR" ] || fail "sage prebuilt signature self-check failed (got '$SAGE_SIG_FPR')"
  printf 'cut-release: prebuilt %s ready (sha256 + signature verified)\n' "$SAGE_TGZ" >&2
  SAGE_PUBLISH_LINES="       $OUT/$SAGE_TGZ          as  $SAGE_TGZ
       $OUT/$SAGE_TGZ.sha256   as  $SAGE_TGZ.sha256
       $OUT/$SAGE_TGZ.asc      as  $SAGE_TGZ.asc"
fi

cat <<EOF
Signed release $TAG ready in $OUT/ (sha256 + signature verified).

Publish:
  1. git add $OUT && git commit -m "vendor signed $TAG artifacts" && git push
     (check: git show --stat HEAD must list the files)
  2. GitHub release "$TAG" (tag $TAG) with these assets — names matter,
     install.sh fetches exactly these:
       $OUT/$TGZ          as  $TGZ
       $OUT/$TGZ.sha256   as  spellbook-$TAG.sha256
       $OUT/$TGZ.asc      as  $TGZ.asc
$SAGE_PUBLISH_LINES
Agents then see it via \`spellbook upgrade --check\` / spellbook_version.
EOF
