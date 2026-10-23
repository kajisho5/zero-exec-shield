#!/usr/bin/env bash
# CHANGELOG.md の先頭の版見出し（"## X.Y.Z — YYYY-MM-DD"）、zes-scan.sh の ZES_VERSION、ui/package.json と
# ui/package-lock.json の version が一致することを確かめる（tests/run-tests.sh と CI から呼ぶ）。
set -u
export LC_ALL=C
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
head_line="$(grep -m1 -E '^## ' "$REPO/CHANGELOG.md")"
cl="$(printf '%s\n' "$head_line" | sed -n -E 's/^## ([0-9]+\.[0-9]+\.[0-9]+)( .*)?$/\1/p')"
if [ -z "$cl" ]; then echo "CHANGELOG.md の先頭の見出しが X.Y.Z の版ではありません: ${head_line:-（見出しなし）}"; exit 1; fi
sh="$(sed -n -E 's/^ZES_VERSION="([^"]*)".*/\1/p' "$REPO/zes-scan.sh" | head -n 1)"
ui="$(jq -r .version "$REPO/ui/package.json")"
lk="$(jq -r '.version + " " + .packages[""].version' "$REPO/ui/package-lock.json")"
if [ "$cl" = "$sh" ] && [ "$cl" = "$ui" ] && [ "$lk" = "$cl $cl" ]; then
  echo "版が一致（CHANGELOG / ZES_VERSION / ui/package.json / package-lock.json = $cl）"
else
  echo "CHANGELOG=$cl ZES_VERSION=${sh:-?} ui/package.json=$ui ui/package-lock.json=$lk"
  exit 1
fi
