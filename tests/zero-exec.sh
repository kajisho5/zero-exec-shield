#!/usr/bin/env bash
# ZES v5.2 zero-execution verification
#   Records every execve of zes-scan.sh --full with strace -f -e trace=execve and checks the following.
#     1. No file in the fixtures is ever executed (preinstall / sitecustomize.py / .sh etc.)
#     2. No target runtime (node/npm/pip/ruby/perl/sh etc.) is started
#     3. Version probes use only the allowed arguments (python3 -I -S -V / php -n -v / go version etc.)
#     4. No canary file (created if a fixture was executed) exists
#   Where strace is unavailable, the result is SKIP (exit code 77), not a pass.
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

# Watch with the host checks enabled too (including the probes). Only outbound traffic is disabled.
#   An ssh:// Docker context / DOCKER_HOST is planted in the inspected HOME (ZES_HOME / HOME) and in the environment, and it is also checked
#   that the probes do not read it and start ssh (probes should be started with an empty HOME under env -i)
DH="$TMP/docker-home"
ctx="$(printf '%s' zes-evil | { sha256sum 2>/dev/null || shasum -a 256; } | awk '{print $1}')"
mkdir -p "$DH/.docker/contexts/meta/$ctx"
printf '{"currentContext":"zes-evil"}\n' >"$DH/.docker/config.json"
printf '{"Name":"zes-evil","Metadata":{},"Endpoints":{"docker":{"Host":"ssh://zes@ssh.example.invalid","SkipTLSVerify":false}}}\n' >"$DH/.docker/contexts/meta/$ctx/meta.json"
HOME="$DH" DOCKER_HOST="ssh://zes@ssh.example.invalid" DOCKER_CONTEXT=zes-evil DOCKER_CONFIG="$DH/.docker" \
ZES_HOST_CHECKS=1 ZES_OFFLINE=1 ZES_HOME="$FIX/_home" \
  strace -f -qq -s 512 -e trace=execve -o "$TMP/trace.txt" \
  "$REPO/zes-scan.sh" --full --root "$FIX" --json >"$TMP/out.json" 2>"$TMP/scan-err.txt"
rc=$?
FAIL=0
ng() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$1"; }

[ "$rc" -eq 0 ] || ng "zes-scan.sh の終了コードが $rc"
jq -e . "$TMP/out.json" >/dev/null 2>&1 || ng "出力が valid JSON ではない"

# Convert execve("<path>", ["argv0", "argv1", ...], ...) to path<TAB>argv (JSON array)
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
      # docker version connects to the daemon (ssh for an ssh:// context), so only the client-only --version is allowed
      printf '%s' "$argv" | jq -e '.[1:] == ["--version"]' >/dev/null 2>&1 || ng "docker を許可外の引数で起動: $argv" ;;
    ssh)
      printf '%s' "$argv" | jq -e '.[1:] == ["-V"]' >/dev/null 2>&1 || ng "ssh を許可外の引数で起動: $argv" ;;
    cosign)
      printf '%s' "$argv" | jq -e '.[1:] == ["version"]' >/dev/null 2>&1 || ng "cosign を許可外の引数で起動: $argv" ;;
    bpftool)
      printf '%s' "$argv" | jq -e '.[1:] == ["prog","list"]' >/dev/null 2>&1 || ng "bpftool を許可外の引数で起動: $argv" ;;
  esac
  # Even for non-executables: was something started with a fixture script as an argument (bash x.sh etc.)
  case "$base" in
    bash)
      printf '%s' "$argv" | jq -e --arg fx "$FIX/" '.[1:] | map(select(startswith($fx) and (test("\\.(sh|bash)$")))) | length > 0' >/dev/null 2>&1 \
        && ng "bash でフィクスチャのスクリプトを実行: $argv" ;;
  esac
done <"$TMP/execs.tsv"

for c in /tmp/zes-canary-*; do [ -e "$c" ] && ng "カナリアファイルが作成されました（フィクスチャが実行された）: $c"; done

# Program settings planted in the .git/config of the inspected repository are never started (git calls of §46/§38)
#   Creates a HEAD commit with an x509-format gpgsig and points gpg.*.program etc. at a marker script.
#   A nested .git cannot be placed in the fixtures, so it is created in a temporary directory at test time.
if command -v git >/dev/null 2>&1; then
  GR="$TMP/gitrepo"
  mkdir -p "$GR"
  printf '#!/bin/sh\n: >"%s/git-marker"\nexit 1\n' "$TMP" >"$TMP/marker.sh"
  chmod +x "$TMP/marker.sh"
  (
    export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
    cd "$GR" && git init -q . && echo inert >README && git add README \
      && tree="$(git write-tree)" \
      && printf 'tree %s\nauthor a <a@example.invalid> 1792800000 +0000\ncommitter a <a@example.invalid> 1792800000 +0000\ngpgsig -----BEGIN SIGNED MESSAGE-----\n MIIBzeszes\n -----END SIGNED MESSAGE-----\n\nx509 signed\n' "$tree" >"$TMP/commit.txt" \
      && c="$(git hash-object -t commit -w "$TMP/commit.txt")" && git update-ref HEAD "$c" \
      && for k in gpg.program gpg.openpgp.program gpg.x509.program gpg.ssh.program gpg.ssh.defaultKeyCommand \
                  core.fsmonitor core.sshCommand core.gitProxy core.editor core.pager core.askPass \
                  sequence.editor credential.helper diff.external core.alternateRefsCommand; do
           git config "$k" "$TMP/marker.sh"
         done \
      && git config log.showSignature true && git config core.hooksPath "$TMP/hooks"
  ) || ng "テスト用 git リポジトリを作成できません"
  mkdir -p "$TMP/hooks" && for h in post-checkout post-index-change reference-transaction; do cp "$TMP/marker.sh" "$TMP/hooks/$h"; done
  ZES_HOST_CHECKS=0 ZES_OFFLINE=1 ZES_HOME="$FIX/_home" \
    strace -f -qq -s 512 -e trace=execve -o "$TMP/trace-git.txt" \
    "$REPO/zes-scan.sh" --full --root "$GR" --json >"$TMP/out-git.json" 2>"$TMP/scan-err-git.txt"
  [ -e "$TMP/git-marker" ] && ng "検査対象 .git/config のプログラム設定（gpg.x509.program 等）が実行されました"
  grep -q -F "$TMP/marker.sh" "$TMP/trace-git.txt" && ng "マーカースクリプトが execve されました（.git/config 経由）"
  jq -e '[.findings[] | select(.module == "§46" and .code == "s46.unsigned" and .params == {"total": "1", "unsigned": "0"})] | length == 1' "$TMP/out-git.json" >/dev/null 2>&1 \
    || ng "§46 が gpgsig ヘッダ付きコミットを署名ありとして数えていません"
  echo "git 設定経由の実行チェック: 完了"
else
  echo "SKIP: git が無いため .git/config 経由の実行チェックを省略"
fi

# PATH spoofing (R3-01): fake jq / git / coreutils are placed in node_modules/.bin inside the scan root and put at the front of PATH (".", empty entries and
#   absolute paths inside the root), and not a single fake is started (PATH is sanitized at startup, jq / git are started by absolute path)
TR="$TMP/pathtrap"
mkdir -p "$TR/node_modules/.bin"
for b in jq git awk sed grep find sort head tail tr cat cut wc xargs stat readlink realpath od sha256sum shasum mktemp uname \
         dirname basename env timeout paste uniq rm mkdir mv ln cp printf date id ps lsof tee comm join sleep kill bash; do
  printf '#!/bin/sh\n: >"%s/path-shadow-canary"\nexit 1\n' "$TMP" >"$TR/node_modules/.bin/$b"
  chmod +x "$TR/node_modules/.bin/$b"
done
if command -v git >/dev/null 2>&1; then
  ( export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1; cd "$TR" && git init -q . && printf 'x\n' >README && git add README \
      && git -c user.name=a -c user.email=a@example.invalid commit -q -m init ) >/dev/null 2>&1
fi
STRACE="$(command -v strace)"; BASH_BIN="$(command -v bash)"
# The env of the shebang "#!/usr/bin/env bash" looks up bash in PATH before sanitization, so when PATH cannot be trusted, start bash by absolute path (README)
( cd "$TR/node_modules/.bin" && PATH=".::$TR/node_modules/.bin:$PATH" ZES_HOST_CHECKS=1 ZES_OFFLINE=1 ZES_HOME="$FIX/_home" \
    "$STRACE" -f -qq -s 512 -e trace=execve -o "$TMP/trace-path.txt" "$BASH_BIN" "$REPO/zes-scan.sh" --full --root "$TR" --json >"$TMP/out-path.json" 2>"$TMP/scan-err-path.txt" )
rc=$?
[ "$rc" -eq 0 ] || ng "PATH 偽装時の zes-scan.sh の終了コードが $rc"
[ -e "$TMP/path-shadow-canary" ] && ng "検査ルート内の偽の jq / git / coreutils が実行されました（PATH 経由）"
grep -E 'execve\("' "$TMP/trace-path.txt" | grep -q -F "\"$TR/" && ng "検査ルート内のファイルを execve しました（PATH 経由）: $(grep -E 'execve\("' "$TMP/trace-path.txt" | grep -F "\"$TR/" | head -n1)"
jq -e --arg p "path_entry_dropped:$TR/node_modules/.bin" '([.errors[] | select(.module == "core" and (.reason == $p or .reason == "path_entry_dropped:." or .reason == "path_entry_dropped:<empty>"))] | length == 3)' "$TMP/out-path.json" >/dev/null 2>&1 \
  || ng "PATH から外したエントリ（./空/ルート内）が errors[] に path_entry_dropped として記録されていません"
echo "PATH 偽装チェック: 完了"

echo "起動された実行ファイル（種類）:"
cut -f1 "$TMP/execs.tsv" | awk -F/ '{print $NF}' | sort | uniq -c | sort -rn | awk '{printf "  %6d %s\n", $1, $2}'
if [ "$FAIL" -eq 0 ]; then
  echo "結果: OK（対象ランタイム・フィクスチャの実行ゼロ）"
  exit 0
fi
echo "結果: FAIL=$FAIL"
exit 1
