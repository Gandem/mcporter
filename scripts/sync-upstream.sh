#!/usr/bin/env bash
#
# Local upstream rebase helper for this fork.
#
# Mirrors what .github/workflows/upstream-sync.yml does, but runs on your
# machine where `git rerere` can remember (and auto-replay) conflict
# resolutions across rebases — something a fresh CI checkout cannot do.
#
# Usage:
#   scripts/sync-upstream.sh            # fetch upstream, rebase main, run the gate
#   scripts/sync-upstream.sh --push     # ...and force-push main if the gate is green
#
# Lockfile-only conflicts are auto-resolved and reconciled by `pnpm install`
# after the rebase. Other conflicts stop and leave you in the rebase so you can
# resolve, then:
#   git rebase --continue   (rerere will reuse resolutions next time)

set -euo pipefail

UPSTREAM_REPO="${UPSTREAM_REPO:-https://github.com/openclaw/mcporter.git}"
UPSTREAM_BRANCH="${UPSTREAM_BRANCH:-main}"
PUSH=false
[ "${1:-}" = "--push" ] && PUSH=true

# Reuse recorded conflict resolutions automatically.
git config rerere.enabled true

if [ -n "$(git status --porcelain)" ]; then
  echo "error: working tree is dirty; commit or stash first." >&2
  exit 1
fi

git remote get-url upstream >/dev/null 2>&1 || git remote add upstream "$UPSTREAM_REPO"
git remote set-url upstream "$UPSTREAM_REPO"
git fetch --no-tags upstream "$UPSTREAM_BRANCH"

git checkout main

if git merge-base --is-ancestor "upstream/$UPSTREAM_BRANCH" HEAD; then
  echo "main already contains upstream/$UPSTREAM_BRANCH; nothing to do."
  exit 0
fi

echo "Rebasing main onto upstream/$UPSTREAM_BRANCH ($(git rev-parse --short "upstream/$UPSTREAM_BRANCH"))..."
if git rebase "upstream/$UPSTREAM_BRANCH"; then
  rebase_status=0
else
  rebase_status=$?
fi

while [ "$rebase_status" -ne 0 ]; do
  conflicts="$(git diff --name-only --diff-filter=U 2>/dev/null || true)"

  if [ "$conflicts" != "pnpm-lock.yaml" ]; then
    echo
    echo "Rebase stopped on conflicts. Resolve them, then run:" >&2
    echo "  git rebase --continue" >&2
    echo "Re-run this script with --push when the rebase finishes to validate and publish." >&2
    exit 1
  fi

  echo "Auto-resolving pnpm-lock.yaml rebase conflict; pnpm install will regenerate it after the rebase."
  # During a rebase, --ours is the already-rebased side (upstream plus any
  # earlier replayed patch commits). Keep that side for the generated lockfile
  # and let pnpm reconcile it from the final package manifests.
  git checkout --ours -- pnpm-lock.yaml
  git add pnpm-lock.yaml

  if git diff --cached --quiet && git diff --quiet; then
    echo "Auto-resolved lockfile-only commit became empty; skipping it."
    if git rebase --skip; then
      rebase_status=0
    else
      rebase_status=$?
    fi
  else
    if GIT_EDITOR=true git rebase --continue; then
      rebase_status=0
    else
      rebase_status=$?
    fi
  fi
done

# Reconcile any lockfile drift into the patch, then run the core gate (a subset of ci.yml).
pnpm install --no-frozen-lockfile
if ! git diff --quiet -- pnpm-lock.yaml; then
  git add pnpm-lock.yaml
  # Fold drift into the top patch commit, but only if the patch still has commits of its own
  # (mirrors the workflow guard so we never amend an upstream commit if the patch was absorbed).
  if [ "$(git rev-list --count "upstream/$UPSTREAM_BRANCH"..HEAD)" -ge 1 ]; then
    git commit --amend --no-edit
  else
    git commit -m "chore: reconcile pnpm-lock.yaml after upstream rebase"
  fi
fi

FIRECRAWL_API_KEY=test LINEAR_API_KEY=test pnpm check
pnpm generate:schema
pnpm exec oxfmt mcporter.schema.json
git diff --exit-code -- mcporter.schema.json
FIRECRAWL_API_KEY=test LINEAR_API_KEY=test pnpm test

echo
echo "Gate passed on the rebased patch."
if [ "$PUSH" = true ]; then
  git push --force-with-lease origin main
  echo "Pushed: main is now the rebased patch on upstream/$UPSTREAM_BRANCH."
else
  echo "Review the result, then publish with:"
  echo "  git push --force-with-lease origin main"
fi
