#!/bin/sh
# Fails when a migration that already exists at BASE was changed, renamed or deleted.
# New migrations (added files) are fine. Usage: scripts/check-migrations.sh <base-commit>
set -eu
base="${1:-}"
case "$base" in
  ""|0000000000000000000000000000000000000000) echo "no base commit; skipping"; exit 0 ;;
esac
dir=crates/server/migrations
bad=$(git diff --name-status --no-renames "$base" HEAD -- "$dir" | awk '$1 != "A" {print}')
removed=$(git diff -U0 "$base" HEAD -- crates/server/migrations.sha256 | grep -E '^-[0-9a-f]{64}' || true)
if [ -n "$bad" ] || [ -n "$removed" ]; then
  echo "Released migrations must not change. Add a new numbered file instead." >&2
  [ -n "$bad" ] && echo "$bad" >&2
  [ -n "$removed" ] && echo "$removed" >&2
  exit 1
fi
echo "migrations: only additions since $base"
