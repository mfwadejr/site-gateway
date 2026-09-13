#!/usr/bin/env bash
# apply-patch.sh — picks up the newest Claude-generated .patch file from
# ~/Downloads/Claude outputs, copies it into this repo, applies it, and
# cleans up both copies. Run from anywhere; it finds the repo root itself.
#
# Usage: ./scripts/apply-patch.sh
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SOURCE_DIR="$HOME/Downloads/Claude outputs"

if [ ! -d "$SOURCE_DIR" ]; then
  echo "Can't find $SOURCE_DIR" >&2
  exit 1
fi

PATCH=$(ls -t "$SOURCE_DIR"/*.patch 2>/dev/null | head -n1 || true)
if [ -z "$PATCH" ]; then
  echo "No .patch file found in $SOURCE_DIR"
  exit 1
fi

NAME=$(basename "$PATCH")
DEST="$REPO_ROOT/$NAME"
echo "Found patch: $NAME"
cp "$PATCH" "$DEST"

echo "Checking that it applies cleanly..."
if ! git apply --check "$DEST" 2>/tmp/apply-patch-check.log; then
  echo
  echo "Patch does NOT apply cleanly against the current branch. Nothing was changed."
  echo "Details:"
  cat /tmp/apply-patch-check.log
  echo
  echo "The copied patch is left at: $DEST"
  echo "The original is untouched at: $PATCH"
  exit 1
fi

echo "Applying..."
git apply "$DEST"

echo "Cleaning up..."
rm -f "$DEST"
rm -f "$PATCH"

echo
echo "Applied and cleaned up ($NAME removed from both this repo and Claude outputs)."
echo "Changed files:"
git status --short
echo
echo "Review with: git diff --stat"
echo "Then commit and push yourself when ready."
