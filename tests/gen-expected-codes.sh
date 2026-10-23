#!/usr/bin/env bash
# Regenerates tests/expected-codes/<fixture>.json from the CLI: the code / params of every finding of every fixture
#   (normal form: tests/expected-codes.jq). ui/tests/unit/cli-parity.test.ts compares the UI engine with these files and
#   tests/run-tests.sh checks that the CLI output still equals them. Review the diff after regenerating.
# Usage: tests/gen-expected-codes.sh [FIXTURE...]   (default: every fixture of tests/expected)
set -u
set -o pipefail
export LC_ALL=C
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO="$(dirname "$TESTS_DIR")"
FIX="$TESTS_DIR/fixtures"
EXP="$TESTS_DIR/expected"
OUT="$TESTS_DIR/expected-codes"
command -v jq >/dev/null 2>&1 || { echo "gen-expected-codes.sh needs jq" >&2; exit 64; }
mkdir -p "$OUT"
names=("$@")
if [ "${#names[@]}" -eq 0 ]; then
  for e in "$EXP"/*.json; do n="$(basename "$e" .json)"; case "$n" in _*) ;; *) names+=("$n") ;; esac; done
fi
gen() {
  local name="$1" mode home root tmp
  mode="$(jq -r '.mode' "$EXP/$name.json")" || return 1
  home="$(jq -r '.home // "_home"' "$EXP/$name.json")"
  root="$FIX/$name"
  if [ "$home" = "self" ]; then home="$root"; else home="$FIX/$home"; fi
  tmp="$(mktemp "${TMPDIR:-/tmp}/zes-codes.XXXXXX")" || return 1
  if ZES_HOST_CHECKS=0 ZES_OFFLINE=1 ZES_HOME="$home" ZES_NOW=1792800000 ZES_SKILLPACT_CACHE='' \
       "$REPO/zes-scan.sh" "--$mode" --root "$root" --json 2>/dev/null \
     | jq -S --arg r "$root/" --arg rr "$root" --arg h "$FIX/_home" -f "$TESTS_DIR/expected-codes.jq" >"$tmp"; then
    mv "$tmp" "$OUT/$name.json"
  else
    rm -f "$tmp"; echo "failed: $name" >&2; return 1
  fi
}
rc=0
for n in "${names[@]}"; do gen "$n" & done
for _ in "${names[@]}"; do wait -n || rc=1; done
exit "$rc"
