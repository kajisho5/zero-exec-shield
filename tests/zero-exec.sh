#!/usr/bin/env bash
# ZES v5.2 ゼロ実行検証
#   strace -f -e trace=execve で zes-scan.sh --full の全 execve を記録し、以下を確認する。
#     1. フィクスチャ内のファイルを一度も実行していない（preinstall / sitecustomize.py / .sh 等）
#     2. 対象ランタイム（node/npm/pip/ruby/perl/sh 等）を起動していない
#     3. バージョン確認系のプローブは許可された引数のみ（python3 -I -S -V / php -n -v / go version 等）
#     4. カナリアファイル（フィクスチャが実行された場合に作られる）が存在しない
#   strace が使えない環境では SKIP（終了コード 77）とし、合格扱いにしない。
set -u
set -o pipefail
export LC_ALL=C

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO="$(dirname "$TESTS_DIR")"
FIX="$TESTS_DIR/fixtures"
command -v strace >/dev/null 2>&1 || { echo "SKIP: strace がありません（Linux で実行してください）"; exit 77; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/zes-zeroexec.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
rm -f /tmp/zes-canary-* 2>/dev/null

if ! strace -f -qq -s 512 -e trace=execve -o "$TMP/trace.txt" true 2>"$TMP/strace-err.txt"; then
  echo "SKIP: strace を実行できません（ptrace 制限）: $(head -n1 "$TMP/strace-err.txt")"
  exit 77
fi

# ホスト検査も有効にして（プローブを含めて）監視する。外向き通信のみ無効化。
ZES_HOST_CHECKS=1 ZES_OFFLINE=1 ZES_HOME="$FIX/_home" \
  strace -f -qq -s 512 -e trace=execve -o "$TMP/trace.txt" \
  "$REPO/zes-scan.sh" --full --root "$FIX" --json >"$TMP/out.json" 2>"$TMP/scan-err.txt"
rc=$?
FAIL=0
ng() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$1"; }

[ "$rc" -eq 0 ] || ng "zes-scan.sh の終了コードが $rc"
jq -e . "$TMP/out.json" >/dev/null 2>&1 || ng "出力が valid JSON ではない"

# execve("<path>", ["argv0", "argv1", ...], ...) を path<TAB>argv(JSON配列) に変換
grep -E 'execve\("' "$TMP/trace.txt" | sed -E 's/^[0-9]+ +//' \
  | sed -E 's/^execve\("(([^"\\]|\\.)*)", \[(.*)\], (0x[0-9a-f]+|\[).*$/\1\t[\3]/' >"$TMP/execs.tsv"
total="$(wc -l <"$TMP/execs.tsv" | tr -d ' ')"
echo "execve 総数: $total"

while IFS=$'\t' read -r exe argv; do
  base="${exe##*/}"
  case "$exe" in
    "$FIX"/*) ng "フィクスチャ内のファイルを実行: $exe"; continue ;;
  esac
  case "$base" in
    node|nodejs|npm|npx|pnpm|yarn|bun|bunx|deno|pip|pip3|pipx|uv|uvx|ruby|gem|perl|cargo|rustc|make|gcc|cc|java|sh|dash|zsh)
      ng "対象ランタイム/シェルを起動: $exe $argv" ;;
    python|python3|python3.*)
      [ "$(printf '%s' "$argv" | jq -c '.[1:]' 2>/dev/null)" = '["-I","-S","-V"]' ] || ng "python を許可外の引数で起動: $argv" ;;
    php|php[0-9]*)
      [ "$(printf '%s' "$argv" | jq -c '.[1:]' 2>/dev/null)" = '["-n","-v"]' ] || ng "php を許可外の引数で起動: $argv" ;;
    go)
      ng "go を起動（バージョンは GOROOT/VERSION を静的に読むこと）: $argv" ;;
    docker)
      printf '%s' "$argv" | jq -e '.[1] == "version"' >/dev/null 2>&1 || ng "docker を許可外の引数で起動: $argv" ;;
    cosign)
      printf '%s' "$argv" | jq -e '.[1:] == ["version"]' >/dev/null 2>&1 || ng "cosign を許可外の引数で起動: $argv" ;;
    bpftool)
      printf '%s' "$argv" | jq -e '.[1:] == ["prog","list"]' >/dev/null 2>&1 || ng "bpftool を許可外の引数で起動: $argv" ;;
  esac
  # 実行ファイル以外でも、引数にフィクスチャのスクリプトを渡して起動していないか（bash x.sh 等）
  case "$base" in
    bash)
      printf '%s' "$argv" | jq -e --arg fx "$FIX/" '.[1:] | map(select(startswith($fx) and (test("\\.(sh|bash)$")))) | length > 0' >/dev/null 2>&1 \
        && ng "bash でフィクスチャのスクリプトを実行: $argv" ;;
  esac
done <"$TMP/execs.tsv"

for c in /tmp/zes-canary-*; do [ -e "$c" ] && ng "カナリアファイルが作成されました（フィクスチャが実行された）: $c"; done

echo "起動された実行ファイル（種類）:"
cut -f1 "$TMP/execs.tsv" | awk -F/ '{print $NF}' | sort | uniq -c | sort -rn | awk '{printf "  %6d %s\n", $1, $2}'
if [ "$FAIL" -eq 0 ]; then
  echo "結果: OK（対象ランタイム・フィクスチャの実行ゼロ）"
  exit 0
fi
echo "結果: FAIL=$FAIL"
exit 1
