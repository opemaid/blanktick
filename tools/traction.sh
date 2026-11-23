#!/usr/bin/env bash
# Traction snapshot from data that needs no tracking on blanktick.org:
# GitHub stars/forks, 14-day views and clones, and release download counts.
# Needs: gh (authenticated as a repo admin, for the traffic endpoints).
set -euo pipefail
for repo in opemaid/blanktick opemaid/blanktick-claude-plugin; do
  echo "== $repo"
  gh repo view "$repo" --json stargazerCount,forkCount \
    --jq '"stars \(.stargazerCount)  forks \(.forkCount)"'
  gh api "repos/$repo/traffic/views"  --jq '"views 14d \(.count) (unique \(.uniques))"'
  gh api "repos/$repo/traffic/clones" --jq '"clones 14d \(.count) (unique \(.uniques))"'
  gh api "repos/$repo/traffic/popular/referrers" --jq '.[] | "  referrer \(.referrer): \(.count)"'
  gh api "repos/$repo/releases" --jq '.[] | .tag_name as $t | .assets[] | "  \($t) \(.name): \(.download_count) downloads"'
done
