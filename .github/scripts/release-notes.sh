#!/usr/bin/env bash
# Print Markdown release notes for TAG: the BREAKING CHANGE footers and subjects of every
# commit since the previous v* tag. Usage: release-notes.sh TAG
set -euo pipefail

tag=$1
previous=$(git describe --tags --abbrev=0 --match 'v*' "${tag}^" 2>/dev/null || true)
range=${previous:+${previous}..}${tag}
commits=$(git rev-list --reverse --no-merges "$range")

breaking=""
changes=""
for commit in $commits; do
  short=$(git rev-parse --short "$commit")
  changes+="- $(git show -s --format=%s "$commit") (${short})"$'\n'
  # A footer runs from "BREAKING CHANGE:" to the next blank line; keep the author's line breaks.
  footer=$(git show -s --format=%B "$commit" | awk '
    /^BREAKING[ -]CHANGE: / { on = 1; sub(/^BREAKING[ -]CHANGE: /, ""); print "- " $0; next }
    on && /^[[:space:]]*$/ { on = 0; next }
    on { print "  " $0 }
  ')
  if [[ -n $footer ]]; then
    breaking+="${footer} (${short})"$'\n'
  fi
done

if [[ -n $breaking ]]; then
  printf '## 不兼容的改动\n\n%s\n' "$breaking"
fi
printf '## 改动\n\n%s' "$changes"
