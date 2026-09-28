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
# Output: releases/<tag>/ with the three files install.sh fetches. It
# never pushes or publishes — it prints those steps for you.

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

cat <<EOF
Signed release $TAG ready in $OUT/ (sha256 + signature verified).

Publish:
  1. git add $OUT && git commit -m "vendor signed $TAG artifacts" && git push
     (check: git show --stat HEAD must list the three files)
  2. GitHub release "$TAG" (tag $TAG) with these assets — names matter,
     install.sh fetches exactly these:
       $OUT/$TGZ          as  $TGZ
       $OUT/$TGZ.sha256   as  spellbook-$TAG.sha256
       $OUT/$TGZ.asc      as  $TGZ.asc
Agents then see it via \`spellbook upgrade --check\` / spellbook_version.
EOF
