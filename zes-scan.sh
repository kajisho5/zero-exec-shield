#!/usr/bin/env bash
# =============================================================================
# Zero-Exec Shield (ZES) v5.2 — Core CLI Scanner
# incident_bundle: ZES-2026-OCT-EMERGENCY-V5.2
#
# 絶対原則（Master Spec §1）
#   - Zero-Execution: 検査対象のランタイム・スクリプトを一切起動しない
#   - 静的・受動的解析のみ（find / grep / readlink / stat / curl -sI / ps / lsof / uname / docker version）
#   - 内容非読取: 検出時もファイル内容は出力せず、パスとメタ情報のみ提示
#   - fail-closed: 検査できなかったモジュールは errors[] に記録し、0件扱いしない
#   - Bash 4+ / set -u / jq 優先・grep フォールバック / macOS・Linux 両対応
#
# 環境変数（テスト・運用向け）
#   ZES_IOC          ioc.json のパス（既定: <script_dir>/rules/ioc.json）
#   ZES_HOME         ホームディレクトリ系検査の対象（既定: $HOME）
#   ZES_HOST_CHECKS  0 でホスト状態検査（ps/lsof/proc/uname/docker 等）を無効化（既定: 1）
#   ZES_OFFLINE      1 で外向き通信（§4 --url / §6 eMudhra）を無効化（既定: 0）
#   ZES_SKILLPACT_CACHE  §49 前バージョン契約のローカルキャッシュ
#   ZES_NOW          現在時刻の上書き（epoch秒、テスト用）
#   ZES_FORCE_NO_JQ  1 で jq を使わず grep フォールバックを強制（テスト用）
# =============================================================================
set -u
set -o pipefail
umask 077
# CDPATH が export されていると相対パスの cd が別ディレクトリへ解決され、パスも標準出力へ出るため無効化
unset CDPATH

ZES_VERSION="0.1.0"      # ソフトウェアの版
ZES_SPEC_VERSION="5.2"   # 準拠する Master Specification の版
INCIDENT_BUNDLE="ZES-2026-OCT-EMERGENCY-V5.2"
FINDINGS_SCHEMA_VERSION="1.0"

if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
  echo "ZES: Bash 4 以上が必要です（現在: ${BASH_VERSION:-unknown}）。macOS は 'brew install bash' を利用してください。" >&2
  exit 64
fi

export LC_ALL=C
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
IOC_FILE="${ZES_IOC:-$SCRIPT_DIR/rules/ioc.json}"
HOME_DIR="${ZES_HOME:-${HOME:-}}"
HOST_CHECKS="${ZES_HOST_CHECKS:-1}"
OFFLINE="${ZES_OFFLINE:-0}"
SKILLPACT_CACHE="${ZES_SKILLPACT_CACHE:-}"
OS_NAME="$(uname -s 2>/dev/null || echo unknown)"

ROOT="."
MODE=""
JSON_OUT=0
TARGET_URL=""

usage() {
  cat <<'EOF'
Usage: zes-scan.sh [--quick|--standard|--full|--worm|--skillpact] [--root <dir>] [--url <URL>] [--json]
                   [--skillpact-cache <dir>]

  --root <dir>   検査ルート（既定 "."）
  --full         §1〜49 全実行
  --standard     §1〜35
  --quick        §1〜19（既定）
  --worm         §15/18/25/45 のみ
  --skillpact    §49 のみ
  --url <URL>    §4 の非侵襲URLチェック（X-Powered-By ヘッダのみ取得）
  --json         findings.json を標準出力へ（人間向けログは標準エラーへ）
  --skillpact-cache <dir>  §49 差分異常検出用の前バージョン契約キャッシュ

終了コード: 0=完了(status ok/partial) / 2=status error / 64=引数・環境エラー
EOF
}

set_mode() {
  if [ -n "$MODE" ] && [ "$MODE" != "$1" ]; then
    echo "ZES: モード指定が重複しています（$MODE と $1）" >&2
    exit 64
  fi
  MODE="$1"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --root) [ $# -ge 2 ] || { usage >&2; exit 64; }; ROOT="$2"; shift 2 ;;
    --full) set_mode full; shift ;;
    --standard) set_mode standard; shift ;;
    --quick) set_mode quick; shift ;;
    --worm) set_mode worm; shift ;;
    --skillpact) set_mode skillpact; shift ;;
    --url) [ $# -ge 2 ] || { usage >&2; exit 64; }; TARGET_URL="$2"; shift 2 ;;
    --json) JSON_OUT=1; shift ;;
    --skillpact-cache) [ $# -ge 2 ] || { usage >&2; exit 64; }; SKILLPACT_CACHE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ZES: 不明な引数: $1" >&2; usage >&2; exit 64 ;;
  esac
done
[ -n "$MODE" ] || MODE="quick"

if [ ! -d "$ROOT" ]; then
  echo "ZES: --root がディレクトリではありません: $ROOT" >&2
  exit 64
fi
case "$ROOT" in -*) ROOT="./$ROOT" ;; esac  # "-" や "-dash" を cd のオプション/OLDPWD と解釈させない
ROOT="$(cd -- "$ROOT" 2>/dev/null && pwd -P)"
if [ -z "$ROOT" ] || [ ! -d "$ROOT" ]; then
  echo "ZES: --root を解決できません" >&2
  exit 64
fi

if [ -n "$TARGET_URL" ]; then
  case "$TARGET_URL" in
    http://*|https://*) ;;
    *) echo "ZES: --url は http:// または https:// のみ受け付けます" >&2; exit 64 ;;
  esac
  case "$TARGET_URL" in
    *[[:space:]\'\"\`\$\;\|\&\<\>]*) echo "ZES: --url に使用できない文字が含まれています" >&2; exit 64 ;;
  esac
fi

HAVE_JQ=0
command -v jq >/dev/null 2>&1 && HAVE_JQ=1
[ "${ZES_FORCE_NO_JQ:-0}" = "1" ] && HAVE_JQ=0

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/zes.XXXXXX")" || { echo "ZES: 一時ディレクトリを作成できません" >&2; exit 64; }
trap 'rm -rf "$TMP_DIR"' EXIT
FINDINGS_FILE="$TMP_DIR/findings.ndjson"
ERRORS_FILE="$TMP_DIR/errors.ndjson"
: >"$FINDINGS_FILE"
: >"$ERRORS_FILE"
FATAL=0

now_epoch() { if [ -n "${ZES_NOW:-}" ]; then echo "$ZES_NOW"; else date -u +%s; fi; }
iso_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
SCAN_STARTED_AT="$(iso_now)"

# ---------------------------------------------------------------------------
# 出力（§5.1 log_section / critical / high / safe）
# ---------------------------------------------------------------------------
if [ "$JSON_OUT" -eq 1 ]; then exec 3>&2; else exec 3>&1; fi
if [ -t 3 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RED=$'\033[1;31m'; C_YEL=$'\033[1;33m'; C_MAG=$'\033[1;35m'; C_GRN=$'\033[1;32m'; C_CYN=$'\033[1;36m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
else
  C_RED=""; C_YEL=""; C_MAG=""; C_GRN=""; C_CYN=""; C_DIM=""; C_OFF=""
fi

CURRENT_MODULE=""
log_section() {
  CURRENT_MODULE="$1"
  printf '\n%s== %s %s ==%s\n' "$C_CYN" "$1" "${2:-}" "$C_OFF" >&3
}
log_info() { printf '%s  %s%s\n' "$C_DIM" "$*" "$C_OFF" >&3; }

sha256_str() {
  if command -v sha256sum >/dev/null 2>&1; then printf '%s' "$1" | sha256sum | awk '{print $1}'
  else printf '%s' "$1" | shasum -a 256 | awk '{print $1}'; fi
}
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum -- "$1" 2>/dev/null | awk '{print $1}'
  else shasum -a 256 -- "$1" 2>/dev/null | awk '{print $1}'; fi
}

json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037\177'
}
json_str_or_null() { if [ -n "$1" ]; then printf '"%s"' "$(json_escape "$1")"; else printf 'null'; fi; }

# emit LEVEL CAMPAIGN PATH DETAIL [SKILLPACT_JSON]
#   findings[].id は module|campaign|path|detail から決定的に生成（§6 保証）
#   evidence_hash は通常ファイルならその SHA-256、それ以外は detail の SHA-256
declare -A SEEN_IDS=()
emit() {
  local level="$1" campaign="$2" path="$3" detail="$4" sp="${5:-}"
  local module="$CURRENT_MODULE"
  local id ev color
  id="sha256:$(sha256_str "$module|$campaign|$path|$detail")"
  [ -n "${SEEN_IDS[$id]:-}" ] && return 0
  SEEN_IDS[$id]=1
  ev=""
  if [ -f "$path" ] && [ ! -L "$path" ]; then
    # 100MB 超（モデル重み等）は全体ハッシュを避け、パス・サイズ・mtime のハッシュで代替
    local sz; sz="$(stat_size "$path")"
    if [ "${sz:-0}" -le 104857600 ]; then ev="$(sha256_file "$path")"
    else ev="$(sha256_str "$path|$sz|$(stat_mtime "$path")")"; fi
  fi
  [ -n "$ev" ] || ev="$(sha256_str "$detail")"
  {
    printf '{"id":"%s","level":"%s","module":"%s","campaign":%s,"path":%s,"detail":%s,"evidence_hash":"sha256:%s"' \
      "$id" "$level" "$(json_escape "$module")" "$(json_str_or_null "$campaign")" "$(json_str_or_null "$path")" \
      "$(json_str_or_null "$detail")" "$ev"
    [ -n "$sp" ] && printf ',"skillpact":%s' "$sp"
    printf '}\n'
  } >>"$FINDINGS_FILE"
  case "$level" in
    CRITICAL) color="$C_RED" ;; HIGH) color="$C_MAG" ;; MEDIUM) color="$C_YEL" ;; *) color="$C_DIM" ;;
  esac
  printf '%s[%s]%s %s%s\n' "$color" "$level" "$C_OFF" "$detail" "${path:+ : $path}" >&3
}
critical() { emit CRITICAL "$@"; }
high()     { emit HIGH "$@"; }
medium()   { emit MEDIUM "$@"; }
low()      { emit LOW "$@"; }
info()     { emit INFO "$@"; }
safe()     { printf '%s[SAFE]%s %s\n' "$C_GRN" "$C_OFF" "$*" >&3; }

record_error() {
  local module="$1" reason="$2"
  printf '{"module":"%s","reason":"%s"}\n' "$(json_escape "$module")" "$(json_escape "$reason")" >>"$ERRORS_FILE"
  printf '%s[ERROR]%s %s: %s\n' "$C_YEL" "$C_OFF" "$module" "$reason" >&3
}

# ---------------------------------------------------------------------------
# パス・バージョン共通関数
# ---------------------------------------------------------------------------
# realpath 相当（readlink -f → realpath → cd/pwd フォールバック）
resolve_path() {
  local p="$1" r=""
  r="$(readlink -f -- "$p" 2>/dev/null)" && [ -n "$r" ] && { printf '%s' "$r"; return 0; }
  r="$(realpath -- "$p" 2>/dev/null)" && [ -n "$r" ] && { printf '%s' "$r"; return 0; }
  if [ -d "$p" ]; then (cd -- "$p" 2>/dev/null && pwd -P); else
    local d; d="$(cd -- "$(dirname -- "$p")" 2>/dev/null && pwd -P)" || return 1
    printf '%s/%s' "$d" "$(basename -- "$p")"
  fi
}

expand_home() {
  local p="$1"
  case "$p" in "~/"*) printf '%s/%s' "$HOME_DIR" "${p#\~/}" ;; '$HOME/'*) printf '%s/%s' "$HOME_DIR" "${p#\$HOME/}" ;; "~") printf '%s' "$HOME_DIR" ;; *) printf '%s' "$p" ;; esac
}

stat_mtime() { if [ "$OS_NAME" = "Darwin" ]; then stat -f %m -- "$1" 2>/dev/null; else stat -c %Y -- "$1" 2>/dev/null; fi; }
stat_size()  { if [ "$OS_NAME" = "Darwin" ]; then stat -f %z -- "$1" 2>/dev/null; else stat -c %s -- "$1" 2>/dev/null; fi; }
stat_perm()  { if [ "$OS_NAME" = "Darwin" ]; then stat -f %Lp -- "$1" 2>/dev/null; else stat -c %a -- "$1" 2>/dev/null; fi; }
stat_birth() { if [ "$OS_NAME" = "Darwin" ]; then stat -f %B -- "$1" 2>/dev/null; else stat -c %W -- "$1" 2>/dev/null; fi; }

# version_cmp A B → -1 / 0 / 1（数値セグメント比較、非数値は辞書順）
version_cmp() {
  awk -v a="$1" -v b="$2" 'BEGIN{
    gsub(/^[vV]/,"",a); gsub(/^[vV]/,"",b)
    na=split(a,x,/[.+_-]/); nb=split(b,y,/[.+_-]/); n=(na>nb?na:nb)
    for(i=1;i<=n;i++){
      p=(i<=na?x[i]:"0"); q=(i<=nb?y[i]:"0")
      if(p ~ /^[0-9]+$/ && q ~ /^[0-9]+$/){ if(p+0<q+0){print -1;exit} if(p+0>q+0){print 1;exit} }
      else { if(p<q){print -1;exit} if(p>q){print 1;exit} }
    }
    print 0 }'
}
version_lt() { [ "$(version_cmp "$1" "$2")" = "-1" ]; }
version_ge() { [ "$(version_cmp "$1" "$2")" != "-1" ]; }

# version_branch_vulnerable VERSION FIXED... → 0(脆弱) / 1(修正済)
#   同一ブランチ（先頭2セグメント）の修正版があればそれと比較。
#   最大修正版以上は修正済。ブランチ不一致かつ最大未満は修正版なし＝脆弱扱い（fail-closed）。
version_branch_vulnerable() {
  local v="$1"; shift
  local max="" f vb fb
  vb="$(printf '%s' "${v#v}" | awk -F. '{print $1"."$2}')"
  for f in "$@"; do
    if [ -z "$max" ] || version_lt "$max" "$f"; then max="$f"; fi
  done
  [ -n "$max" ] || return 0
  version_ge "$v" "$max" && return 1
  for f in "$@"; do
    fb="$(printf '%s' "${f#v}" | awk -F. '{print $1"."$2}')"
    if [ "$fb" = "$vb" ]; then version_lt "$v" "$f" && return 0; return 1; fi
  done
  return 0
}

# 範囲式マッチ: "1.2.3" / "<X" / "<=X" / ">=A <=B" / ">A <B"
version_matches_spec() {
  local v="$1" spec="$2" tok op ver c
  for tok in $spec; do
    case "$tok" in
      '>='*) op=">="; ver="${tok#>=}" ;; '<='*) op="<="; ver="${tok#<=}" ;;
      '>'*) op=">"; ver="${tok#>}" ;; '<'*) op="<"; ver="${tok#<}" ;;
      '='*) op="="; ver="${tok#=}" ;; *) op="="; ver="$tok" ;;
    esac
    c="$(version_cmp "$v" "$ver")"
    case "$op" in
      '=') [ "$c" = "0" ] || return 1 ;; '<') [ "$c" = "-1" ] || return 1 ;;
      '<=') [ "$c" != "1" ] || return 1 ;; '>') [ "$c" = "1" ] || return 1 ;;
      '>=') [ "$c" != "-1" ] || return 1 ;;
    esac
  done
  return 0
}

refang() { printf '%s' "$1" | sed -e 's/\[\.\]/./g' -e 's/^hxxp/http/'; }

# 対象バイナリが検査ルート内・一時領域にある場合は起動しない（偽装バイナリ対策）
safe_probe() {
  local bin="$1"; shift
  local p rp
  p="$(command -v "$bin" 2>/dev/null)" || return 127
  rp="$(resolve_path "$p")" || return 127
  case "$rp" in "$ROOT"/*|/tmp/*|/var/tmp/*|/dev/shm/*) return 126 ;; esac
  case "$rp" in "$HOME_DIR"/*) [ "$HOST_CHECKS" = "1" ] || return 126 ;; esac
  ( cd / && GOTOOLCHAIN=local GOFLAGS='' PYTHONSTARTUP='' PYTHONPATH='' "$rp" "$@" </dev/null 2>/dev/null )
}

# git は検査対象リポジトリの設定（.git/config）経由でコマンドを起動しうるため、危険な設定を無効化して呼ぶ
#   コマンドライン -c はリポジトリ設定より優先される。プログラムを値に取る設定は全て無害化する:
#   署名検証（gpg.program / gpg.openpgp.program / gpg.x509.program / gpg.ssh.program / gpg.ssh.defaultKeyCommand）、
#   ssh・プロキシ（core.sshCommand / core.gitProxy）、エディタ・ページャ・認証（core.editor / sequence.editor /
#   core.pager / core.askPass / credential.helper）、diff（diff.external、textconv は --no-textconv を呼び出し側で指定）
#   ※ 署名の有無は検証させずに生のコミットオブジェクトのヘッダから判定する（§46）
safe_git() {
  command -v git >/dev/null 2>&1 || return 127
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 GIT_PAGER=cat GIT_EXTERNAL_DIFF='' \
  GIT_SSH_COMMAND=/bin/false GIT_SSH=/bin/false GIT_ASKPASS=/bin/false SSH_ASKPASS=/bin/false GIT_EDITOR=/bin/false \
  GIT_SEQUENCE_EDITOR=/bin/false GIT_PROXY_COMMAND=/bin/false GIT_OPTIONAL_LOCKS=0 \
    git -c core.fsmonitor=false -c core.hooksPath=/dev/null -c core.pager=cat -c log.showSignature=false \
        -c gpg.program=/bin/false -c gpg.openpgp.program=/bin/false -c gpg.x509.program=/bin/false \
        -c gpg.ssh.program=/bin/false -c gpg.ssh.defaultKeyCommand=/bin/false \
        -c diff.external= -c core.sshCommand=/bin/false -c core.gitProxy=/bin/false \
        -c core.editor=/bin/false -c sequence.editor=/bin/false -c core.askPass=/bin/false -c credential.helper= \
        -c core.alternateRefsCommand=/bin/false -c protocol.allow=never -C "$ROOT" --no-pager "$@" </dev/null 2>/dev/null
}

# ---------------------------------------------------------------------------
# IoC 読み出し（read_ioc: jq 優先、grep フォールバック）
#   jq 不在時は「トップレベルセクション内の最初の同名キーの文字列配列」を抽出する。
#   rules/ioc.json は grep フォールバックのため 1 エントリ 1 行の整形を維持すること。
# ---------------------------------------------------------------------------
[ -r "$IOC_FILE" ] || { echo "ZES: IoC データベースを読めません: $IOC_FILE" >&2; exit 64; }
if [ "$HAVE_JQ" -eq 1 ] && ! jq -e . "$IOC_FILE" >/dev/null 2>&1; then
  echo "ZES: IoC データベースが不正な JSON です: $IOC_FILE" >&2; exit 64
fi

read_ioc() {
  local path="$1"
  if [ "$HAVE_JQ" -eq 1 ]; then
    jq -r "($path) // empty | if type==\"array\" then .[] | (if type==\"string\" then . else tojson end) elif type==\"string\" then . else tojson end" "$IOC_FILE" 2>/dev/null
    return 0
  fi
  local section leaf
  section="$(printf '%s' "$path" | sed -E 's/^\.//; s/[.\[].*$//')"
  if [[ "$path" =~ \[\"([^\"]+)\"\]$ ]]; then leaf="${BASH_REMATCH[1]}"; leaf="${leaf//./\\.}"
  else leaf="$(printf '%s' "$path" | sed -E 's/.*\.//')"; fi
  local txt arr
  txt="$(ZES_SEC="$section" awk '
    BEGIN { sec = "^  \"" ENVIRON["ZES_SEC"] "\":" }
    $0 ~ sec {on=1; print; next}
    on && $0 ~ /^  "[^"]+":/ {exit}
    on {print}' "$IOC_FILE" | tr '\n' ' ')"
  # 文字列配列は '"…"' の並びとして抽出する（無害化表記 [.] の ']' で切れないように）
  arr="$(printf '%s' "$txt" | grep -o -E "\"$leaf\": *\\[ *(\"([^\"\\\\]|\\\\.)*\" *,? *)*\\]" | head -n1)"
  if [ -n "$arr" ]; then
    printf '%s' "$arr" | sed -E 's/^"[^"]*": *\[//; s/\]$//' \
      | grep -o '"\([^"\\]\|\\.\)*"' | sed -E 's/^"//; s/"$//; s/\\"/"/g; s/\\\\/\\/g'
  else
    printf '%s' "$txt" | grep -o "\"$leaf\": *\(\"\([^\"\\]\|\\.\)*\"\|[0-9.]\+\)" | head -n1 \
      | sed -E 's/^"[^"]*": *//; s/^"//; s/"$//; s/\\"/"/g; s/\\\\/\\/g'
  fi
  return 0
}

# packages[] を TSV（campaign eco name match bad_versions(;区切り) safe_version）で出力
read_packages_tsv() {
  if [ "$HAVE_JQ" -eq 1 ]; then
    jq -r '.packages[] | [.campaign, .eco, .name, (.match // "versions"), ((.bad_versions // []) | join(";")), (.safe_version // "")] | @tsv' "$IOC_FILE"
  else
    grep -E '^\s*\{ "campaign": ' "$IOC_FILE" | sed -E \
      's/.*"campaign": "([^"]*)", "eco": "([^"]*)", "name": "([^"]*)", "match": "([^"]*)", "bad_versions": \[([^]]*)\], "safe_version": (null|"([^"]*)").*/\1\t\2\t\3\t\4\t\5\t\7/' \
    | awk -F'\t' 'BEGIN{OFS="\t"}{gsub(/"/,"",$5); gsub(/, */,";",$5); print}'
  fi
}

# ---------------------------------------------------------------------------
# 検査対象インベントリ
#   ZES 自身（rules/tests/docs 等）は IoC 文字列を含むため、ROOT が ZES の外側にある場合は除外する
# ---------------------------------------------------------------------------
FILES_LIST="$TMP_DIR/files.lst"
LINKS_LIST="$TMP_DIR/links.lst"
DIRS_LIST="$TMP_DIR/dirs.lst"
build_inventory() {
  local -a prune=( -name .git -prune -o -name .hg -prune -o -name .svn -prune )
  case "$SCRIPT_DIR/" in
    "$ROOT"/*) if [ "$SCRIPT_DIR" != "$ROOT" ] || [ -f "$ROOT/zes-scan.sh" ]; then prune+=( -o -path "$SCRIPT_DIR" -prune ); fi ;;
  esac
  find "$ROOT" \( "${prune[@]}" \) -o -print0 2>/dev/null >"$TMP_DIR/all.z"
  if tr '\0' '\n' <"$TMP_DIR/all.z" | awk 'END{exit 0}' && [ "$(tr -cd '\0' <"$TMP_DIR/all.z" | wc -c)" -ne "$(tr '\0' '\n' <"$TMP_DIR/all.z" | wc -l)" ]; then
    record_error "core" "unscannable_path_newline"
  fi
  : >"$FILES_LIST"; : >"$LINKS_LIST"; : >"$DIRS_LIST"
  local p
  while IFS= read -r -d '' p; do
    case "$p" in *$'\n'*) continue ;; esac
    if [ -L "$p" ]; then printf '%s\n' "$p" >>"$LINKS_LIST"
    elif [ -f "$p" ]; then printf '%s\n' "$p" >>"$FILES_LIST"
    elif [ -d "$p" ]; then printf '%s\n' "$p" >>"$DIRS_LIST"
    fi
  done <"$TMP_DIR/all.z"
  sort -o "$FILES_LIST" "$FILES_LIST"; sort -o "$LINKS_LIST" "$LINKS_LIST"; sort -o "$DIRS_LIST" "$DIRS_LIST"
}

# files_named REGEX  … ベース名が ERE に一致するファイル
files_named() { ZES_RE="$1" awk '{n=$0; sub(/.*\//,"",n); if (n ~ ENVIRON["ZES_RE"]) print}' "$FILES_LIST"; }
# files_path REGEX   … フルパスが ERE に一致するファイル
files_path() { grep -E -- "$1" "$FILES_LIST" 2>/dev/null || true; }
# grep_l PATTERN [grep-opts...] < filelist … 内容が一致するファイルのパスのみを返す（内容は出力しない）
grep_l() {
  local pat="$1"; shift
  tr '\n' '\0' | xargs -0 grep -l -I -E "$@" -e "$pat" -- /dev/null 2>/dev/null || true
}
grep_lF() {
  local pat="$1"; shift
  tr '\n' '\0' | xargs -0 grep -l -I -F "$@" -e "$pat" -- /dev/null 2>/dev/null || true
}
# 1ファイルに対する存在判定
fgrep_q() { grep -q -I -E "$@" 2>/dev/null; }
# TSV を空欄を保ったまま read するための変換。IFS=$'\t' はタブを空白類として扱い連続タブを 1 区切りに潰す
# （空欄で後続の列がずれる）ため、空白類でない US（0x1f）に置き換えて IFS="$US" で読む
US=$'\037'
tsv_us() { tr '\t' '\037'; }

# ---------------------------------------------------------------------------
# 依存関係インベントリ（check_lockfile_versions の入力）
#   DEPS_TSV: eco<TAB>name<TAB>version<TAB>source_path
# ---------------------------------------------------------------------------
DEPS_TSV="$TMP_DIR/deps.tsv"
DEPS_BUILT=0
norm_pypi() { printf '%s' "$1" | tr 'A-Z_.' 'a-z--' | tr -s '-'; }
# 行ベースのパーサへ渡す前の正規化: 行末 CR（CRLF）と先頭の UTF-8 BOM を除去（検出回避の防止）
text_lines() { awk '{ sub(/\r$/, "") } NR == 1 { sub(/^\357\273\277/, "") } { print }' "$1" 2>/dev/null; }
# package.json のトップレベル "version"（jq 不在時）。文字列外の波括弧の深さを数え、深さ 1 のキーだけを見る
json_top_version() {
  awk 'BEGIN { RS = "\001" }
    { n = length($0); depth = 0; ins = 0; esc = 0; tok = ""; key = ""; expect = 0
      for (i = 1; i <= n; i++) {
        ch = substr($0, i, 1)
        if (ins) {
          if (esc) { esc = 0; tok = tok ch; continue }
          if (ch == "\\") { esc = 1; continue }
          if (ch == "\"") { ins = 0
            if (expect && depth == 1) { print tok; exit }
            last = tok; continue }
          tok = tok ch; continue }
        if (ch == "\"") { ins = 1; tok = ""; continue }
        if (ch == "{" || ch == "[") { depth++; expect = 0; continue }
        if (ch == "}" || ch == "]") { depth--; expect = 0; continue }
        if (ch == ":") { expect = (depth == 1 && last == "version"); continue }
        if (ch == ",") { expect = 0; last = ""; continue }
        if (ch !~ /[ \t\r\n]/) expect = 0
      } }' "$1" 2>/dev/null
}
# PKG-INFO / METADATA（RFC 822 形式）の先頭ヘッダから Name<TAB>Version を読む
pkg_info_name_version() {
  text_lines "$1" | awk '
    /^$/ { exit }
    tolower($0) ~ /^name:/ && n == "" { n = $0; sub(/^[^:]*:[ \t]*/, "", n); sub(/[ \t]+$/, "", n) }
    tolower($0) ~ /^version:/ && v == "" { v = $0; sub(/^[^:]*:[ \t]*/, "", v); sub(/[ \t]+$/, "", v) }
    END { if (n != "") print n "\t" v }'
}
build_deps() {
  [ "$DEPS_BUILT" -eq 1 ] && return 0
  DEPS_BUILT=1
  : >"$DEPS_TSV"
  local f
  # npm: package-lock.json / npm-shrinkwrap.json
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if [ "$HAVE_JQ" -eq 1 ]; then
      jq -r --arg src "$f" '
        ( (.packages // {}) | to_entries[] | select(.key | test("node_modules/")) |
          [ "npm", (.value.name // (.key | sub(".*node_modules/"; ""))), (.value.version // ""), $src ] ),
        ( [ .. | objects | select(has("dependencies") and (.dependencies | type == "object")) | .dependencies | to_entries[]
            | select(.value | type == "object" and has("version")) ] | .[] | [ "npm", .key, .value.version, $src ] )
        | @tsv' "$f" 2>/dev/null >>"$DEPS_TSV" || record_error "§15" "lockfile_parse_failed:$f"
    else
      awk -v src="$f" '
        /"node_modules\/[^"]+": *\{/ { n=$0; sub(/.*node_modules\//,"",n); sub(/".*/,"",n); want=1
          if ($0 ~ /"version": *"/) { v=$0; sub(/.*"version": *"/,"",v); sub(/".*/,"",v); print "npm\t" n "\t" v "\t" src; want=0 }
          next }
        want && /"version": *"/ { v=$0; sub(/.*"version": *"/,"",v); sub(/".*/,"",v); print "npm\t" n "\t" v "\t" src; want=0 }' "$f" >>"$DEPS_TSV"
    fi
  done < <(files_named '^(package-lock\.json|npm-shrinkwrap\.json)$')
  # npm: yarn.lock
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    text_lines "$f" | awk -v src="$f" '
      /^[^ #].*:$/ { h=$0; sub(/:$/,"",h); split(h,parts,/, */); n=parts[1]; gsub(/"/,"",n);
                     if (n ~ /^@/) { sub(/^@/,"",n); sub(/@.*/,"",n); n="@" n } else { sub(/@.*/,"",n) } ; next }
      /^  version:? / { v=$0; sub(/^  version:? +/,"",v); gsub(/"/,"",v); if (n!="") print "npm\t" n "\t" v "\t" src; n="" }' >>"$DEPS_TSV"
  done < <(files_named '^yarn\.lock$')
  # npm: pnpm-lock.yaml（"/name@1.2.3:" / "name@1.2.3:" 形式）
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    text_lines "$f" | awk -v src="$f" '
      /^  ['"'"'\/]?@?[^ @]+@[0-9][^:]*:/ {
        s=$0; sub(/^  /,"",s); gsub(/'"'"'/,"",s); sub(/^\//,"",s); sub(/:.*$/,"",s); sub(/\(.*$/,"",s)
        if (s ~ /^@/) { at=index(substr(s,2),"@")+1 } else { at=index(s,"@") }
        if (at>1) print "npm\t" substr(s,1,at-1) "\t" substr(s,at+1) "\t" src }' >>"$DEPS_TSV"
  done < <(files_named '^pnpm-lock\.yaml$')
  # npm: node_modules/<pkg>/package.json（実体のバージョン）
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    local n v
    n="$(printf '%s' "$f" | sed -E 's#.*/node_modules/((@[^/]+/)?[^/]+)/package\.json$#\1#')"
    # トップレベルの .version のみ（最小化 JSON・入れ子の "version" に対応）
    if [ "$HAVE_JQ" -eq 1 ]; then
      v="$(jq -r 'if type == "object" and (.version | type) == "string" then .version else "" end' "$f" 2>/dev/null)" \
        || { record_error "§15" "lockfile_parse_failed:$f"; v=""; }
    else
      v="$(json_top_version "$f")"
    fi
    v="$(printf '%s' "$v" | tr -d '\t\r\n')"
    printf 'npm\t%s\t%s\t%s\n' "$n" "$v" "$f" >>"$DEPS_TSV"
  done < <(files_path '/node_modules/(@[^/]+/)?[^/]+/package\.json$')
  # pypi: requirements*.txt / constraints*.txt
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    text_lines "$f" | awk -v src="$f" '
      { line=$0; sub(/#.*/,"",line); gsub(/[ \t]/,"",line) }
      line ~ /^[A-Za-z0-9][A-Za-z0-9._-]*(\[[^]]*\])?===?[^;,]+/ {
        n=line; sub(/(\[[^]]*\])?===?.*/,"",n); v=line; sub(/^[^=]*===?/,"",v); sub(/[;,].*/,"",v)
        n=tolower(n); gsub(/[-_.]+/,"-",n); print "pypi\t" n "\t" v "\t" src }' >>"$DEPS_TSV"
  done < <(files_named '^(requirements.*|constraints.*)\.txt$')
  # pypi: poetry.lock / uv.lock / pdm.lock
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    text_lines "$f" | awk -v src="$f" '
      /^\[\[package\]\]/ { n=""; next }
      /^name = "/ { n=$0; sub(/^name = "/,"",n); sub(/".*/,"",n); n=tolower(n); gsub(/[-_.]+/,"-",n); next }
      /^version = "/ && n!="" { v=$0; sub(/^version = "/,"",v); sub(/".*/,"",v); print "pypi\t" n "\t" v "\t" src; n="" }' >>"$DEPS_TSV"
  done < <(files_named '^(poetry\.lock|uv\.lock|pdm\.lock)$')
  # pypi: Pipfile.lock
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if [ "$HAVE_JQ" -eq 1 ]; then
      jq -r --arg src "$f" '((.default // {}) + (.develop // {})) | to_entries[] | ["pypi", (.key | ascii_downcase | gsub("[-_.]+"; "-")), ((.value.version // "") | ltrimstr("==")), $src] | @tsv' "$f" 2>/dev/null >>"$DEPS_TSV" \
        || record_error "§15" "lockfile_parse_failed:$f"
    else
      record_error "§15" "jq_unavailable:$f"
    fi
  done < <(files_named '^Pipfile\.lock$')
  # pypi: site-packages の *.dist-info / *.egg-info（インストール実体）
  #   Name / Version は METADATA・PKG-INFO のヘッダを正とする（name-1.0-py3.11.egg-info や
  #   バージョンを含まない name.egg-info もあるため、ディレクトリ名はヘッダが無い場合の代替のみ）
  #   egg-info は単一ファイル（PKG-INFO と同形式）の場合もある
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    local d n v src nv
    if [ -d "$f" ]; then continue; fi
    case "$f" in *.egg-info) src="$f"; d="$(basename -- "$f")" ;; *) src="$(dirname -- "$f")"; d="$(basename -- "$src")" ;; esac
    nv="$(pkg_info_name_version "$f")"
    n="${nv%%$'\t'*}"; v=""; [[ "$nv" == *$'\t'* ]] && v="${nv#*$'\t'}"
    if [ -z "$n" ]; then
      d="${d%.dist-info}"; d="${d%.egg-info}"
      d="$(printf '%s' "$d" | sed -E 's/-py[0-9]+(\.[0-9]+)*(-[^-]+)?$//')"
      n="${d%-*}"; v="${d##*-}"
      [ "$n" != "$d" ] || { n="$d"; v=""; }
    fi
    [ -n "$n" ] || continue
    printf 'pypi\t%s\t%s\t%s\n' "$(norm_pypi "$n")" "$v" "$src" >>"$DEPS_TSV"
  done < <(files_path '/[^/]+\.(dist-info|egg-info)/(METADATA|PKG-INFO)$|\.egg-info$')
  # cargo: Cargo.lock
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    text_lines "$f" | awk -v src="$f" '
      /^\[\[package\]\]/ { n=""; next }
      /^name = "/ { n=$0; sub(/^name = "/,"",n); sub(/".*/,"",n); next }
      /^version = "/ && n!="" { v=$0; sub(/^version = "/,"",v); sub(/".*/,"",v); print "cargo\t" n "\t" v "\t" src; n="" }' >>"$DEPS_TSV"
  done < <(files_named '^Cargo\.lock$')
  # go: go.sum
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    text_lines "$f" | awk -v src="$f" 'NF >= 2 { v=$2; sub(/\/go\.mod$/,"",v); print "go\t" $1 "\t" v "\t" src }' >>"$DEPS_TSV"
  done < <(files_named '^go\.sum$')
  # ruby: Gemfile.lock
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    # プラットフォーム付き（nokogiri (1.16.0-x86_64-linux)）はバージョン部分のみで比較する
    text_lines "$f" | awk -v src="$f" '/^    [A-Za-z0-9_.-]+ \([0-9][^)]*\)$/ { n=$1; v=$2; gsub(/[()]/,"",v); sub(/-[A-Za-z].*$/,"",v); print "gem\t" n "\t" v "\t" src }' >>"$DEPS_TSV"
  done < <(files_named '^Gemfile\.lock$')
  # packagist: composer.lock
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if [ "$HAVE_JQ" -eq 1 ]; then
      jq -r --arg src "$f" '((.packages // []) + (."packages-dev" // []))[] | ["packagist", .name, ((.version // "") | ltrimstr("v")), $src] | @tsv' "$f" 2>/dev/null >>"$DEPS_TSV" \
        || record_error "§15" "lockfile_parse_failed:$f"
    else
      record_error "§15" "jq_unavailable:$f"
    fi
  done < <(files_named '^composer\.lock$')
  sort -u -o "$DEPS_TSV" "$DEPS_TSV"
}

# check_lockfile_versions（campaign 対応）: packages[] と DEPS_TSV を突合
check_lockfile_versions() {
  build_deps
  local camp eco name match bads safev
  read_packages_tsv >"$TMP_DIR/packages.tsv"
  while IFS="$US" read -r camp eco name match bads safev; do
    case "$eco" in npm|pypi|cargo|go|gem|packagist) ;; *) continue ;; esac
    case "$match" in versions|vulnerable_versions|any_version|unknown_versions) ;; *) continue ;; esac
    local qname="$name"
    [ "$eco" = "pypi" ] && qname="$(norm_pypi "$name")"
    local deco dname dver dsrc
    while IFS="$US" read -r deco dname dver dsrc; do
      [ "$deco" = "$eco" ] || continue
      case "$qname" in
        *'/*') [[ "$dname" == "${qname%\*}"* ]] || continue ;;
        *) [ "$dname" = "$qname" ] || continue ;;
      esac
      local hit=0 spec
      if [ "$match" = "any_version" ]; then hit=1
      elif [ "$match" = "versions" ] || [ "$match" = "vulnerable_versions" ]; then
        IFS=';' read -r -a specs <<<"$bads"
        for spec in "${specs[@]}"; do
          [ -n "$spec" ] || continue
          [ -n "$dver" ] && version_matches_spec "$dver" "$spec" && { hit=1; break; }
        done
      fi
      if [ "$hit" -eq 1 ] && [ "$match" = "vulnerable_versions" ]; then
        high "$camp" "$dsrc" "脆弱なバージョン ${dname}@${dver:-?}（${eco}、悪性ではなく CVE の影響範囲）${safev:+。修正版: $safev 以上}"
      elif [ "$hit" -eq 1 ]; then
        critical "$camp" "$dsrc" "侵害パッケージ ${dname}@${dver:-?} を検出（${eco}）${safev:+。安全版: $safev}"
      elif [ "$match" = "unknown_versions" ]; then
        medium "$camp" "$dsrc" "侵害報告のあるパッケージ ${dname}@${dver:-?}（侵害版の特定バージョン未定義のため要確認）"
      fi
    done < <(tsv_us <"$DEPS_TSV")
  done < <(tsv_us <"$TMP_DIR/packages.tsv")
}

# detect_service_version IMAGE_PATTERN … compose/k8s/Dockerfile の image タグからバージョンを抽出
#   出力: version<TAB>path
detect_service_version() {
  local pat="$1"
  local f line ver
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    grep -E -o -- "(${pat}):[A-Za-z0-9._-]+" "$f" 2>/dev/null | while IFS= read -r line; do
      ver="${line##*:}"; ver="${ver%%-*}"
      printf '%s\t%s\n' "$ver" "$f"
    done
  done < <(files_named '^(docker-compose.*\.ya?ml|compose.*\.ya?ml|Dockerfile.*|.*\.dockerfile|.*\.ya?ml|.*\.tf|.*\.json)$')
}

# infra_fixed INFRA_ID CVE_ID … infrastructures[] の修正版を 1 行ずつ
infra_fixed() {
  if [ "$HAVE_JQ" -eq 1 ]; then
    jq -r --arg i "$1" --arg c "$2" '.infrastructures[] | select(.id==$i) | .cves[] | select(.id==$c) | (.fixed // [])[]' "$IOC_FILE"
  else
    grep -o "\"$2\".*" "$IOC_FILE" | head -n1 | grep -o '"fixed": *\[[^]]*\]' | grep -o '"[0-9][^"]*"' | tr -d '"'
  fi
}

# =============================================================================
# 収集脅威インテリジェンス（rules/ioc.json の intel セクション）
#   各関数は対応する § から呼ばれる。データを足すだけで検出対象が増える。
#   intel は jq 必須（無い場合は errors[] に記録し、0 件扱いしない）
# =============================================================================
# jq が失敗（フィルタのコンパイルエラー・データ不正）した場合は errors[] に記録する（0 件扱いしない / fail-closed）
intel_jq() {
  local rc
  jq -r "$1" "$IOC_FILE" 2>/dev/null; rc=$?
  [ "$rc" -eq 0 ] || record_error "$CURRENT_MODULE" "intel_jq_failed:$(printf '%s' "$1" | tr -s '\n\t ' '   ' | cut -c1-60)"
  return "$rc"
}
intel_ready() {
  [ "$HAVE_JQ" -eq 1 ] || { record_error "$CURRENT_MODULE" "jq_unavailable:intel"; return 1; }
  return 0
}
lvl_emit() { case "$1" in CRITICAL) critical "${@:2}" ;; HIGH) high "${@:2}" ;; MEDIUM) medium "${@:2}" ;; *) info "${@:2}" ;; esac; }

# 悪性ファイル名・SHA-256（§15）
intel_files() {
  intel_ready || return 0
  local camp sev name f h
  # ハッシュは名前に依らず全ファイルと照合（同名の正規ファイルとの区別にもなる）
  intel_jq '.intel.files[]? | .campaign as $c | (.severity // "CRITICAL") as $s | (.sha256 // [])[] | [$c, $s, .] | @tsv' >"$TMP_DIR/intel_sha.tsv"
  if [ -s "$TMP_DIR/intel_sha.tsv" ] && ! command -v sha256sum >/dev/null 2>&1; then
    record_error "$CURRENT_MODULE" "sha256sum_unavailable"
  elif [ -s "$TMP_DIR/intel_sha.tsv" ]; then
    cut -f3 "$TMP_DIR/intel_sha.tsv" | sort -u >"$TMP_DIR/intel_sha.lst"
    # sha256sum に一括で渡し、既知ハッシュと一致した行だけを残す（ファイル内容は出力しない）
    tr '\n' '\0' <"$FILES_LIST" | xargs -0 sha256sum -- 2>/dev/null \
      | awk 'NR==FNR {want[$1]=1; next} ($1 in want) { h=$1; sub(/^[0-9a-f]+  /,""); print h "\t" $0 }' "$TMP_DIR/intel_sha.lst" - \
      | while IFS=$'\t' read -r h f; do
          IFS=$'\t' read -r camp sev _ < <(grep -F -- "$h" "$TMP_DIR/intel_sha.tsv" | head -n1)
          critical "$camp" "$f" "既知の悪性ファイル（SHA-256 一致）"
        done
  fi
  while IFS=$'\t' read -r camp sev name; do
    [ -n "$name" ] || continue
    while IFS= read -r f; do [ -n "$f" ] && lvl_emit "$sev" "$camp" "$f" "既知の悪性ファイル名（${name}）"; done \
      < <(files_named "^$(printf '%s' "$name" | sed 's/[.[\*^$+?(){}|]/\\&/g')\$")
  done < <(intel_jq '.intel.files[]? | .campaign as $c | (.name_severity // "HIGH") as $s | (.names // [])[] | [$c, $s, .] | @tsv')
}

# ネットワーク IoC（§18 で network_iocs に合流）
intel_network_iocs() {
  [ "$HAVE_JQ" -eq 1 ] || return 0
  intel_jq '.intel.network[]? | .campaign as $c | ((.domains // []) + (.ips // []) + (.urls // []) + (.contracts // []))[] | [$c, .] | @tsv' \
    | while IFS=$'\t' read -r c i; do [ -n "$i" ] && printf '%s\t%s\t%s\n' "$(refang "$i")" "$c" "malicious"; done
  intel_jq '.intel.network[]? | .campaign as $c | (.legit_infra // [])[] | [$c, .] | @tsv' \
    | while IFS=$'\t' read -r c i; do [ -n "$i" ] && printf '%s\t%s\t%s\n' "$(refang "$i")" "$c" "legit"; done
  return 0
}

# 侵害された GitHub Actions（§22）
intel_actions() {
  intel_ready || return 0
  local camp act sev bad safe f line ref
  while IFS="$US" read -r camp act sev bad safe; do
    [ -n "$act" ] || continue
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      workflow_text "$f" | grep -i -E -o "uses:[[:space:]]*[\"']?$(printf '%s' "$act" | sed 's/[.[\*^$+?(){}|]/\\&/g')@[^\"'[:space:]#,}]+" 2>/dev/null | sed -E 's/.*@//' | sort -u | while IFS= read -r ref; do
        if printf '%s\n' "$bad" | tr ',' '\n' | grep -q -x -F -- "$ref"; then
          critical "$camp" "$f" "侵害が報告されたアクション ${act}@${ref}"
        elif [ -n "$safe" ] && ! printf '%s\n' "$safe" | tr ',' '\n' | grep -q -x -F -- "$ref" && ! [[ "$ref" =~ ^[0-9a-f]{40}$ ]]; then
          lvl_emit "$sev" "$camp" "$f" "侵害が報告されたアクション ${act} を安全版（${safe}）以外のタグで参照（${ref}）"
        fi
      done
    done < <(workflow_files; files_path '/action\.ya?ml$')
  done < <(intel_jq '.intel.actions[]? | [.campaign, .action, (.severity // "HIGH"), ((.bad_refs // []) | join(",")), ((.safe_refs // []) | join(","))] | @tsv' | tsv_us)
}

# ワークフロー・スクリプト内の悪性文字列（§38）
intel_workflow_strings() {
  intel_ready || return 0
  local camp sev str f
  while IFS=$'\t' read -r camp sev str; do
    [ -n "$str" ] || continue
    files_path '(/\.github/workflows/[^/]+\.ya?ml|\.gitlab-ci\.ya?ml|/\.circleci/config\.ya?ml|/Jenkinsfile|/action\.ya?ml)$' | grep_lF "$str" | while IFS= read -r f; do
      [ -n "$f" ] && lvl_emit "$sev" "$camp" "$f" "CI 設定に既知の悪性パターン（${camp}）"
    done
  done < <(intel_jq '.intel.workflow_strings[]? | .campaign as $c | (.severity // "HIGH") as $s | (.strings // [])[] | [$c, $s, .] | @tsv')
}

# 悪性・侵害された拡張（§42）: Chrome/Edge は Extensions/<id>/<ver>、VS Code/Open VSX は extensions/<publisher.name>-<ver>
intel_extensions() {
  intel_ready || return 0
  local camp eco sev id bads d ver hit
  while IFS=$'\t' read -r camp eco sev id bads; do
    [ -n "$id" ] || continue
    case "$eco" in
      chrome|edge|chromium|brave)
        while IFS= read -r d; do
          [ -n "$d" ] || continue
          ver="${d##*/}"; [ -f "$d/manifest.json" ] || ver=""
          hit=1
          if [ -n "$bads" ] && [ -n "$ver" ]; then
            hit=0; local b; for b in ${bads//,/ }; do version_matches_spec "${ver%%_*}" "$b" && hit=1; done
          fi
          [ "$hit" -eq 1 ] && lvl_emit "$sev" "$camp" "$d" "悪性・侵害が報告されたブラウザ拡張（${id}${ver:+ ${ver}}）"
        done < <({ extension_manifests | sed -E 's#/manifest\.json$##'; files_path "/Extensions/${id}/" | sed -E "s#(/Extensions/${id})/.*#\1#"; } | grep -E "/Extensions/${id}(/[^/]+)?$" | sort -u)
        ;;
      vscode|openvsx|cursor|windsurf)
        for d in "$HOME_DIR"/.vscode/extensions/"$id"-[0-9]* "$HOME_DIR"/.vscode-server/extensions/"$id"-[0-9]* "$HOME_DIR"/.cursor/extensions/"$id"-[0-9]* "$HOME_DIR"/.windsurf/extensions/"$id"-[0-9]* $(files_path "/extensions/${id}-[0-9][^/]*/package\.json$" | sed -E 's#/package\.json$##' | tr '\n' ' '); do
          [ -d "$d" ] || continue
          ver="${d##*/${id}-}"; ver="${ver%%-*}"
          hit=1
          if [ -n "$bads" ]; then hit=0; local b; for b in ${bads//,/ }; do version_matches_spec "$ver" "$b" && hit=1; done; fi
          [ "$hit" -eq 1 ] && lvl_emit "$sev" "$camp" "$d" "悪性・侵害が報告された IDE 拡張（${id} ${ver}）"
        done
        ;;
    esac
  done < <(intel_jq '.intel.extensions[]? | .campaign as $c | .eco as $e | (.severity // "HIGH") as $s | ((.bad_versions // []) | join(",")) as $b | (.ids // [])[] | [$c, $e, $s, ., $b] | @tsv')
}

# ホスト IoC: パス・ファイル名・LaunchAgent Label・systemd ユニット（§30/§31）、プロセス名（§1）
intel_host_files() {
  intel_ready || return 0
  local camp sev kind val e f
  while IFS=$'\t' read -r camp sev kind val; do
    [ -n "$val" ] || continue
    case "$kind" in
      path)
        e="$(expand_home "$val")"
        # ホーム外の絶対パス（/tmp・/etc 等）はホスト状態のため ZES_HOST_CHECKS=0 では見ない
        case "$val" in "~/"*|'$HOME/'*) ;; /*) host_enabled || e="" ;; *) e="" ;; esac
        if [ -n "$e" ]; then
          # 空白を含むパス（Application Support 等）を分割せず、グロブ文字のみ展開する
          local IFS=$'\n'
          for f in $e; do [ -e "$f" ] && lvl_emit "$sev" "$camp" "$f" "既知のマルウェア痕跡パス"; done
          unset IFS
        fi
        local rel="${val#\~/}"; rel="${rel#\$HOME/}"; rel="${rel#/}"
        while IFS= read -r f; do [ -n "$f" ] && lvl_emit "$sev" "$camp" "$f" "既知のマルウェア痕跡パス（検査ルート内）"; done < <(files_path "/$(printf '%s' "$rel" | sed 's/[.[\*^$+?(){}|]/\\&/g')\$")
        ;;
      file_name)
        while IFS= read -r f; do [ -n "$f" ] && lvl_emit "$sev" "$camp" "$f" "既知のマルウェアのファイル名（${val}）"; done < <(files_named "^$(printf '%s' "$val" | sed 's/[.[\*^$+?(){}|]/\\&/g')\$")
        ;;
      launch_label)
        while IFS= read -r f; do
          [ -n "$f" ] && [ "$(plist_label "$f")" = "$val" ] && critical "$camp" "$f" "既知のマルウェアの LaunchAgent/Daemon（${val}）"
        done < <(files_path '/LaunchAgents/[^/]+\.plist$|/LaunchDaemons/[^/]+\.plist$'; ls "$HOME_DIR"/Library/LaunchAgents/*.plist 2>/dev/null; host_enabled && ls /Library/LaunchAgents/*.plist /Library/LaunchDaemons/*.plist 2>/dev/null)
        ;;
      systemd_unit)
        for f in "$HOME_DIR/.config/systemd/user/$val" /etc/systemd/system/"$val" /usr/lib/systemd/system/"$val"; do
          case "$f" in /etc/*|/usr/*) host_enabled || continue ;; esac
          [ -e "$f" ] && critical "$camp" "$f" "既知のマルウェアの systemd ユニット（${val}）"
        done
        while IFS= read -r f; do [ -n "$f" ] && critical "$camp" "$f" "既知のマルウェアの systemd ユニット（${val}）"; done < <(files_path "/systemd/(user|system)/$(printf '%s' "$val" | sed 's/[.[\*^$+?(){}|]/\\&/g')\$")
        ;;
    esac
  done < <(intel_jq '.intel.host[]? | .campaign as $c | (.severity // "HIGH") as $s |
            (((.paths // [])[] | [$c,$s,"path",.]), ((.file_names // [])[] | [$c,$s,"file_name",.]),
             ((.launch_labels // [])[] | [$c,$s,"launch_label",.]), ((.systemd_units // [])[] | [$c,$s,"systemd_unit",.])) | @tsv')
}
intel_host_processes() {
  intel_ready || return 0
  [ -f "$TMP_DIR/ps.txt" ] || return 0
  local camp name
  while IFS=$'\t' read -r camp name; do
    [ -n "$name" ] || continue
    awk -v n="$name" '{c=$2; sub(/.*\//,"",c); if (c==n) print $1}' "$TMP_DIR/ps.txt" | while IFS= read -r pid; do
      critical "$camp" "/proc/$pid" "既知のマルウェアのプロセス名（${name}、pid ${pid}）"
    done
  done < <(intel_jq '.intel.host[]? | .campaign as $c | (.process_names // [])[] | [$c, .] | @tsv')
}

# 開発インフラ CVE（§16 で汎用判定。image_patterns と fixed を持つ infrastructures[] を対象）
intel_infra() {
  intel_ready || return 0
  # 製品全体が generic、または個別判定のある製品に追記した CVE（cves[].generic）を対象にする
  local iid pat cve fixed sev cvss ver f
  while IFS="$US" read -r iid pat cve fixed sev cvss; do
    [ -n "$pat" ] && [ -n "$fixed" ] || continue
    pat="${pat//\\\\/\\}"  # @tsv のエスケープを戻す
    local -a fx; IFS=',' read -r -a fx <<<"$fixed"
    while IFS=$'\t' read -r ver f; do
      [ -n "$ver" ] || continue
      [[ "${ver#v}" =~ ^[0-9]+(\.[0-9]+)+$ ]] || { [ "$ver" = "latest" ] && medium "" "$f" "${iid} が浮動タグ（latest）。${cve} の修正版（${fixed//,/ }）以上か確認"; continue; }
      version_branch_vulnerable "${ver#v}" "${fx[@]}" && lvl_emit "$sev" "" "$f" "${iid} ${ver} は ${cve}${cvss:+（CVSS ${cvss}）}の影響範囲（修正版: ${fixed//,/ }）"
    done < <(detect_service_version "$pat")
  done < <(intel_jq '.infrastructures[] | (.generic == true) as $g | .id as $i | (.image_patterns // []) as $p | .cves[] | select($g or .generic == true) | select((.fixed // []) | length > 0) |
            [$i, ($p | join("|")), .id, (.fixed | join(",")), (.severity // (if (.cvss // 0) >= 9 or .kev then "CRITICAL" else "HIGH" end)), ((.cvss // "") | tostring)] | @tsv' | tsv_us)
}

# ローカルツールのバージョン（§23）。起動してよいのはここに列挙したツールとバージョン引数だけ（データから任意コマンドを起動させない）
intel_tool_versions() {
  intel_ready || return 0
  host_enabled || return 0
  local iid bin cve fixed sev v out
  while IFS=$'\t' read -r iid bin cve fixed sev; do
    case "$bin" in
      git) out="$(safe_probe git --version)" ;;
      ssh) out="$(safe_probe ssh -V 2>&1)" ;;
      curl) out="$(safe_probe curl --version | head -n1)" ;;
      openssl) out="$(safe_probe openssl version)" ;;
      sudo) out="$(safe_probe sudo -V | head -n1)" ;;
      runc) out="$(safe_probe runc --version | head -n1)" ;;
      containerd) out="$(safe_probe containerd --version)" ;;
      kubectl) out="$(safe_probe kubectl version --client=true -o yaml | grep -m1 gitVersion)" ;;
      helm) out="$(safe_probe helm version --short)" ;;
      *) continue ;;
    esac
    v="$(printf '%s' "$out" | grep -o -E '[0-9]+\.[0-9]+(\.[0-9]+)?(p[0-9]+)?' | head -n1)"; v="${v//p/.}"
    [ -n "$v" ] || continue
    local -a fx; IFS=',' read -r -a fx <<<"$fixed"
    # ディストリビューション版はバックポートで修正済みのことが多いため、上限を HIGH とする
    [ "$sev" = "CRITICAL" ] && sev=HIGH
    version_branch_vulnerable "$v" "${fx[@]}" && lvl_emit "$sev" "" "$(command -v "$bin")" "${bin} ${v} は ${cve} の影響範囲（修正版: ${fixed//,/ }）。ディストリビューションのバックポート有無を確認"
  done < <(intel_jq '.infrastructures[] | select(.binary != null) | .id as $i | .binary as $b | .cves[] | select((.fixed // []) | length > 0) |
            [$i, $b, .id, (.fixed | join(",")), (.severity // (if (.cvss // 0) >= 9 or .kev then "CRITICAL" else "HIGH" end))] | @tsv')
}

# 脆弱な AI エディタ（§7）: macOS のアプリバンドルの Info.plist からバージョンを読む（起動しない）
intel_apps() {
  intel_ready || return 0
  host_enabled || return 0
  local camp bundle cve sev fixed f v
  while IFS="$US" read -r camp bundle cve sev fixed; do
    for f in "/Applications/$bundle/Contents/Info.plist" "$HOME_DIR/Applications/$bundle/Contents/Info.plist"; do
      [ -f "$f" ] || continue
      v="$(grep -A1 'CFBundleShortVersionString' "$f" | grep -o -E '[0-9]+(\.[0-9]+)+' | head -n1)"
      [ -n "$v" ] && version_lt "$v" "$fixed" && lvl_emit "$sev" "$camp" "$f" "${bundle%.app} ${v} は ${cve} の影響範囲（修正版 ${fixed}）"
    done
  done < <(intel_jq '.intel.apps[]? | [.campaign, .bundle, .cve, (.severity // "HIGH"), .fixed] | @tsv' | tsv_us)
}

# 任意ファイルの悪性文字列（§7 AI 指示ファイル・§20 MCP 定義など）。file_regex でファイルパスを絞る
intel_strings() {
  intel_ready || return 0
  local camp sev rx str f
  while IFS=$'\t' read -r camp sev rx str; do
    [ -n "$str" ] || continue
    rx="${rx//\\\\/\\}"  # @tsv が \ を二重にエスケープするため戻す
    files_path "$rx" | grep_lF "$str" -i | while IFS= read -r f; do
      [ -n "$f" ] && lvl_emit "$sev" "$camp" "$f" "既知の攻撃キャンペーンの文字列（${camp}）"
    done
  done < <(intel_jq ".intel.strings[]? | select(.module == \"$CURRENT_MODULE\") | .campaign as \$c | (.severity // \"HIGH\") as \$s | (.file_regex // \".\") as \$r | (.strings // [])[] | [\$c, \$s, \$r, .] | @tsv")
}

HOME_RC_FILES=( .bashrc .bash_profile .profile .zshrc .zprofile .zshenv .zlogin .bash_login )
home_rc_paths() { local f; for f in "${HOME_RC_FILES[@]}"; do [ -f "$HOME_DIR/$f" ] && printf '%s\n' "$HOME_DIR/$f"; done; return 0; }
host_enabled() { [ "$HOST_CHECKS" = "1" ]; }

# =============================================================================
# §1〜§14（v3.5 継承＋強化）
# =============================================================================

# §1 マーカー・プロセス署名
check_s1() {
  log_section "§1" "マーカー・プロセス署名"
  local m f sig
  # ROOT 内のマーカー同名ファイル（オフライン解析用）
  while IFS= read -r m; do
    local base="${m##*/}"
    while IFS= read -r f; do [ -n "$f" ] && critical "" "$f" "侵害マーカーファイル（$base）を検出"; done \
      < <(ZES_G="$base" awk 'BEGIN{g=ENVIRON["ZES_G"]; gsub(/\./,"[.]",g); gsub(/\*/,".*",g); g="^" g "$"} {n=$0; sub(/.*\//,"",n); if (n ~ g) print}' "$FILES_LIST")
  done < <(read_ioc '.markers')
  host_enabled || { log_info "ホスト検査は無効（ZES_HOST_CHECKS=0）"; return 0; }
  while IFS= read -r m; do
    for f in $m; do [ -e "$f" ] && critical "" "$f" "侵害マーカーを検出（$m）"; done
  done < <(read_ioc '.markers')
  if command -v ps >/dev/null 2>&1; then
    ps axww -o pid= -o command= 2>/dev/null >"$TMP_DIR/ps.txt" || record_error "§1" "ps_failed"
    while IFS= read -r sig; do
      [ -n "$sig" ] || continue
      grep -F -- "$sig" "$TMP_DIR/ps.txt" 2>/dev/null | grep -v -F -- "zes-scan" | awk '{print $1}' | while IFS= read -r pid; do
        critical "" "/proc/$pid" "プロセス署名 '$sig' に一致するプロセス（pid $pid）"
      done
    done < <(read_ioc '.process_signatures')
  else
    record_error "§1" "ps_unavailable"
  fi
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -i 2>/dev/null >"$TMP_DIR/lsof.txt"
    local ioc
    while IFS= read -r ioc; do
      ioc="$(refang "$ioc")"
      grep -F -- "$ioc" "$TMP_DIR/lsof.txt" 2>/dev/null | awk '{print $2}' | sort -u | while IFS= read -r pid; do
        critical "teampcp-mini-shai-hulud" "/proc/$pid" "C2 ($ioc) への接続（pid $pid）"
      done
    done < <(read_ioc '.worm_iocs.teampcp.c2_ip')
  else
    record_error "§1" "lsof_unavailable"
  fi
  if [ -d /proc ] && [ "$OS_NAME" = "Linux" ]; then
    local mp
    for mp in /proc/[0-9]*/maps; do
      [ -r "$mp" ] || continue
      if grep -q -E '(/tmp/|/dev/shm/|/var/tmp/)[^ ]*\.so' "$mp" 2>/dev/null; then
        high "" "$mp" "一時領域から読み込まれた共有ライブラリ（LD_PRELOAD/インジェクション疑い）"
      fi
    done
  fi
  intel_host_processes
  return 0
}

# §2 Python/Node フック
check_s2() {
  log_section "§2" "Python/Nodeフック"
  local f
  while IFS= read -r f; do [ -n "$f" ] && critical "litellm-oct2026" "$f" "悪性フックファイル（${f##*/}）を検出"; done < <(files_named '^cook\.(pth|py)$')
  while IFS= read -r f; do [ -n "$f" ] && high "litellm-oct2026" "$f" "Python起動時自動実行フック（${f##*/}）"; done < <(files_named '^(sitecustomize|usercustomize)\.py$')
  # .pth の import 行（起動時実行）に難読化・通信・実行が伴うもの
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if fgrep_q '^[[:space:]]*import[[:space:]]' "$f" && fgrep_q '(b64decode|exec\(|subprocess|urllib|socket|__import__)' "$f"; then
      high "litellm-oct2026" "$f" ".pth ファイルに起動時実行コード（import + exec/通信）"
    fi
  done < <(files_named '\.pth$')
  # PYTHONSTARTUP
  if host_enabled && [ -n "${PYTHONSTARTUP:-}" ]; then medium "" "${PYTHONSTARTUP}" "環境変数 PYTHONSTARTUP が設定されています"; fi
  while IFS= read -r f; do [ -n "$f" ] && fgrep_q 'PYTHONSTARTUP=' "$f" && medium "" "$f" "シェル設定で PYTHONSTARTUP を設定"; done < <(home_rc_paths)
  # __pycache__/*.pyc とソースの不一致（ヘッダの mtime/size のみ読む。flags=0 の時刻ベース pyc に限る）
  local pyc src flags hm hs sm ss
  while IFS= read -r pyc; do
    [ -n "$pyc" ] || continue
    src="$(dirname -- "$(dirname -- "$pyc")")/$(basename -- "$pyc" | sed -E 's/\.(cpython|pypy)[^.]*\.pyc$/.py/; s/\.pyc$/.py/')"
    if [ ! -f "$src" ]; then
      case "$pyc" in */site-packages/*|*/dist-packages/*) medium "" "$pyc" "対応するソースの無い .pyc（ソースレス配布・差し替え疑い）" ;; esac
      continue
    fi
    read -r flags hm hs < <(od -An -tu4 -j4 -N12 -- "$pyc" 2>/dev/null) || continue
    [ "${flags:-1}" = "0" ] || continue
    sm="$(stat_mtime "$src")"; ss="$(stat_size "$src")"
    [ -n "$sm" ] && [ -n "$ss" ] || continue
    if [ "$hm" != "$(( sm % 4294967296 ))" ] || [ "$hs" != "$(( ss % 4294967296 ))" ]; then
      high "" "$pyc" ".pyc ヘッダとソース（mtime/size）が不一致（バイトコード差し替え疑い）"
    fi
  done < <(files_path '/__pycache__/[^/]+\.pyc$')
  # package.json の preinstall/install/postinstall
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    local scripts=""
    if [ "$HAVE_JQ" -eq 1 ]; then
      scripts="$(jq -r '(.scripts // {}) | to_entries[] | select(.key | test("^(pre|post)?install$")) | .value' "$f" 2>/dev/null)"
    else
      scripts="$(grep -E '"(pre|post)?install"[[:space:]]*:' "$f" 2>/dev/null)"
    fi
    [ -n "$scripts" ] || continue
    if printf '%s' "$scripts" | grep -q -E '(curl|wget|bash|sh -c|base64|eval|node -e|\.mjs|https?://)'; then
      high "" "$f" "install ライフサイクルスクリプトに不審なコマンド"
    elif [[ "$f" != */node_modules/* ]]; then
      medium "" "$f" "install ライフサイクルスクリプトが定義されています（ignore-scripts 推奨）"
    fi
  done < <(files_named '^package\.json$')
  return 0
}

# §3 GitLab
check_s3() {
  log_section "§3" "GitLab"
  local ver f found=0
  # 判定する CVE は ioc の infrastructures[gitlab].cves（修正版があるもの）。jq が無い場合は既知の 3 件
  local -a gcves; local -A gcvss=()
  if [ "$HAVE_JQ" -eq 1 ]; then
    local c v
    while IFS=$'\t' read -r c v; do gcves+=("$c"); [ -n "$v" ] && gcvss[$c]="CVSS $v"; done \
      < <(jq -r '.infrastructures[] | select(.id=="gitlab") | .cves[] | select((.fixed // []) | length > 0) | [.id, ((.cvss // "") | tostring)] | @tsv' "$IOC_FILE")
  else
    gcves=(CVE-2026-110264 CVE-2026-85706 CVE-2026-19478)
  fi
  while IFS=$'\t' read -r ver f; do
    [ -n "$ver" ] || continue
    found=1
    local cve
    for cve in "${gcves[@]}"; do
      local -a gfix; mapfile -t gfix < <(infra_fixed gitlab "$cve")
      if [[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] && [ "${#gfix[@]}" -gt 0 ] && version_branch_vulnerable "$ver" "${gfix[@]}"; then
        critical "" "$f" "GitLab ${ver} は ${cve}（${gcvss[$cve]:-CVSS 9 以上}）の影響範囲（修正版: ${gfix[*]}。系列に修正版が無い場合は ${gfix[0]} 以降へ移行）"
      fi
    done
    [[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || high "" "$f" "GitLab のバージョンを特定できません（${ver}）。${gcves[*]} の修正版を確認してください"
  done < <(detect_service_version 'gitlab/gitlab-(ee|ce)')
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    fgrep_q "trusted_proxies.*0\.0\.0\.0/0" "$f" && high "" "$f" "gitlab.rb の trusted_proxies が全開放（0.0.0.0/0）"
    fgrep_q "^[[:space:]]*nginx\['custom_gitlab_server_config'\]" "$f" && medium "" "$f" "gitlab.rb に nginx['custom_gitlab_server_config'] が設定されています（設定注入の確認）"
  done < <(files_named '^gitlab\.rb$'; host_enabled && [ -f /etc/gitlab/gitlab.rb ] && echo /etc/gitlab/gitlab.rb)
  if host_enabled && [ -f "$TMP_DIR/ps.txt" ] && grep -q -E 'gitlab-(workhorse|rails)|gitaly' "$TMP_DIR/ps.txt"; then
    high "" "process:gitlab" "GitLab プロセスが稼働中。バージョンと修正適用を確認してください"
    found=1
  fi
  [ "$found" -eq 0 ] && safe "GitLab の痕跡なし"
  return 0
}

# §4 PHP
check_s4() {
  log_section "§4" "PHP"
  local f
  local -a pfix; mapfile -t pfix < <(infra_fixed php CVE-2026-109618)
  php_judge() {  # php_judge VERSION PATH SOURCE(upstream|distro)
    local ver="$1" path="$2" src="$3" core
    core="$(printf '%s' "$ver" | grep -o -E '^[0-9]+\.[0-9]+\.[0-9]+')"
    [ -n "$core" ] && [ "${#pfix[@]}" -gt 0 ] || return 0
    version_branch_vulnerable "$core" "${pfix[@]}" || return 0
    local eol=""; version_lt "$core" "8.2.0" && eol="（8.1 以前は公式の修正リリースなし。サポート版へ移行）"
    if [ "$src" = "distro" ]; then
      high "" "$path" "PHP ${ver} は PHP2Shell（CVE-2026-109618/109619、認証不要 RCE、悪用試行あり）の upstream 修正版（${pfix[*]}）未満${eol}。ディストリビューションのバックポート有無を確認"
    else
      critical "" "$path" "PHP ${ver} は PHP2Shell（CVE-2026-109618/109619、認証不要 RCE、悪用試行あり）の影響範囲（修正版: ${pfix[*]}）${eol}"
    fi
  }
  if host_enabled; then
    local v
    v="$(safe_probe php -n -v | head -n1 | awk '{print $2}')"
    if [ -n "$v" ]; then
      info "" "" "PHP ${v} がインストールされています"
      case "$v" in *ubuntu*|*deb*|*el[0-9]*|*fc[0-9]*|*-[0-9]*) php_judge "$v" "$(command -v php)" distro ;; *) php_judge "$v" "$(command -v php)" upstream ;; esac
    fi
  fi
  local ver
  while IFS=$'\t' read -r ver f; do
    [ -n "$ver" ] && php_judge "$ver" "$f" upstream
  done < <(detect_service_version '(^|[[:space:]/"=])php' | sed -E 's/^[^0-9]*//')
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    ver="$(grep -E '^php[[:space:]]+[0-9]' "$f" | head -n1 | awk '{print $2}')"
    [ -n "$ver" ] && php_judge "$ver" "$f" upstream
  done < <(files_named '^\.tool-versions$')
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    grep -E -i -o '^[[:space:]]*FROM[[:space:]]+([^ ]*/)?php(:[^ ]+)?' "$f" 2>/dev/null | while IFS= read -r line; do
      case "$line" in
        *php:*latest*|*php) medium "" "$f" "PHP ベースイメージが浮動タグ（latest/タグなし）" ;;
        *) info "" "$f" "PHP ベースイメージ: ${line##* }" ;;
      esac
    done
  done < <(files_named '^(Dockerfile.*|.*\.dockerfile)$')
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    fgrep_q '^[[:space:]]*auto_prepend_file[[:space:]]*=[[:space:]]*[^[:space:];]' "$f" && high "" "$f" "php.ini の auto_prepend_file が設定されています（全リクエストで実行）"
    fgrep_q '^[[:space:]]*disable_functions[[:space:]]*=[[:space:]]*$' "$f" && medium "" "$f" "php.ini の disable_functions が空欄"
  done < <(files_named '^php.*\.ini$'; host_enabled && ls /etc/php*/php.ini /etc/php/*/*/php.ini /usr/local/etc/php/php.ini 2>/dev/null)
  if [ -n "$TARGET_URL" ]; then
    if [ "$OFFLINE" = "1" ]; then record_error "§4" "skipped_offline"; return 0; fi
    local hdr
    hdr="$(curl -sI --connect-timeout 5 --max-time 10 --proto '=http,https' -- "$TARGET_URL" 2>/dev/null | tr -d '\r' | grep -i '^x-powered-by:' | head -n1)"
    if [ -n "$hdr" ]; then medium "" "$TARGET_URL" "X-Powered-By ヘッダでバージョンを露出: ${hdr#*: }"
    else safe "X-Powered-By ヘッダなし（$TARGET_URL）"; fi
  fi
  return 0
}

# §5 Python ランタイム（3.15.1 / 3.14.9 / 3.13.17 以降）
check_s5() {
  log_section "§5" "Pythonランタイム"
  local -a mins; mapfile -t mins < <(read_ioc '.runtime_minimums.python')
  local v f
  check_py_version() {
    local ver="$1" path="$2"
    [[ "$ver" =~ ^3\.[0-9]+(\.[0-9]+)?$ ]] || return 0
    [[ "$ver" =~ ^3\.[0-9]+$ ]] && ver="$ver.0"
    if version_branch_vulnerable "$ver" "${mins[@]}"; then
      high "" "$path" "Python ${ver} は修正版（${mins[*]} 以降）未満"
    fi
  }
  if host_enabled; then
    v="$(safe_probe python3 -I -S -V 2>&1 | awk '{print $2}')"
    [ -n "$v" ] && check_py_version "$v" "$(command -v python3)"
  fi
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    v="$(head -n1 "$f" | tr -d '[:space:]')"; check_py_version "$v" "$f"
  done < <(files_named '^\.python-version$')
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    grep -E -i -o 'FROM[[:space:]]+([^ ]*/)?python:3\.[0-9]+(\.[0-9]+)?' "$f" 2>/dev/null | sed -E 's/.*python://' | while IFS= read -r v; do
      check_py_version "$v" "$f"
    done
  done < <(files_named '^(Dockerfile.*|.*\.dockerfile)$')
  return 0
}

# §6 eMudhra（認証局危殆化）
check_s6() {
  log_section "§6" "eMudhra"
  local host camp="emudhra-ca-oct2026"
  if [ "$OFFLINE" = "1" ] || ! host_enabled; then
    record_error "§6" "skipped_offline"
  elif ! command -v curl >/dev/null 2>&1; then
    record_error "§6" "curl_unavailable"
  else
    while IFS= read -r host; do
      [ -n "$host" ] || continue
      host="$(refang "$host")"
      curl -sI --connect-timeout 5 --max-time 10 --proto '=https' -o /dev/null -- "https://$host/" 2>/dev/null
      local rc=$?
      case "$rc" in
        0) critical "$camp" "https://$host/" "危殆化した eMudhra 中間 CA をシステムの curl が信頼しています（接続成功）" ;;
        35|51|53|54|58|59|60|77|80|83|90|91) safe "eMudhra テスト接続は SSL エラー（$host、信頼ストア更新済み）" ;;
        *) record_error "§6" "network_timeout" ;;
      esac
    done < <(read_ioc '.emudhra.probe_hosts')
  fi
  emudhra_os_packages
  emudhra_runtimes
  local d v min
  min="$(read_ioc '.runtime_minimums.homebrew_ca_certificates')"
  for d in /opt/homebrew/Cellar/ca-certificates /usr/local/Cellar/ca-certificates "$HOME_DIR/.linuxbrew/Cellar/ca-certificates"; do
    [ -d "$d" ] || continue
    v="$(ls -1 "$d" 2>/dev/null | sort | tail -n1)"
    [ -n "$v" ] && [[ "$v" < "$min" ]] && high "$camp" "$d/$v" "Homebrew ca-certificates ${v} は ${min} 未満（eMudhra 侵害 CA が未除去）"
  done
  min="$(read_ioc '.runtime_minimums.certifi')"
  build_deps
  awk -F'\t' '$1=="pypi" && $2=="certifi" {print $3"\t"$4}' "$DEPS_TSV" | tsv_us | while IFS="$US" read -r v d; do
    version_lt "$v" "$min" && high "$camp" "$d" "certifi ${v} は ${min} 未満（eMudhra 失効が未反映）"
  done
  local -a gmins; mapfile -t gmins < <(read_ioc '.runtime_minimums.go')
  if host_enabled; then
    # go version は telemetry 子プロセスを起動するため実行せず、GOROOT/VERSION を静的に読む
    local gobin goroot
    gobin="$(command -v go 2>/dev/null)" && gobin="$(resolve_path "$gobin")" && goroot="$(dirname -- "$(dirname -- "$gobin")")"
    v=""
    [ -n "${goroot:-}" ] && [ -f "$goroot/VERSION" ] && v="$(head -n1 "$goroot/VERSION" | grep -o -E 'go[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n1)"
    v="${v#go}"
    [ -n "$v" ] && version_branch_vulnerable "$v" "${gmins[@]}" && high "" "$(command -v go)" "Go ${v} は ${gmins[*]} 未満"
  fi
  while IFS= read -r d; do
    [ -n "$d" ] || continue
    v="$(grep -E '^(toolchain go|go )[0-9]' "$d" | tail -n1 | grep -o -E '[0-9]+\.[0-9]+(\.[0-9]+)?')"
    [ -n "$v" ] || continue
    [[ "$v" =~ ^[0-9]+\.[0-9]+$ ]] && v="$v.0"
    version_branch_vulnerable "$v" "${gmins[@]}" && medium "" "$d" "go.mod の Go ${v} は ${gmins[*]} 未満（証明書ストア更新を含む修正版を使用）"
  done < <(files_named '^go\.mod$')
  return 0
}

# eMudhra: OS の ca-certificates パッケージ（パッケージ DB を静的に読む。パッケージマネージャは起動しない）
debian_ca_fixed() {  # debian_ca_fixed VERSION → 0(修正済) / 1(未修正)
  local v="$1" date rest
  date="$(printf '%s' "$v" | grep -o -E '^[0-9]{8}')"; rest="${v#"$date"}"
  [ -n "$date" ] || return 1
  [ "$date" -ge 20260816 ] && return 0
  if [ "$date" = "20250419" ]; then
    [[ "$rest" =~ deb12u([0-9]+) ]] && [ "${BASH_REMATCH[1]}" -ge 2 ] && return 0
    [[ "$rest" =~ deb13u([0-9]+) ]] && [ "${BASH_REMATCH[1]}" -ge 1 ] && return 0
  fi
  return 1
}
emudhra_os_packages() {
  local camp="emudhra-ca-oct2026" f v
  # dpkg（Debian / Ubuntu / Devuan）: /var/lib/dpkg/status。ROOT 内の同名ファイル（コンテナイメージ展開物）も対象
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    v="$(awk '/^Package: ca-certificates$/ {p=1; next} p && /^Version:/ {print $2; exit} /^$/ {p=0}' "$f")"
    [ -n "$v" ] || continue
    local min_ub; min_ub="$(read_ioc '.emudhra.os_ca_certificates.ubuntu_min_upstream')"
    if [[ "$v" == *ubuntu* ]]; then
      [ "${v:0:8}" -lt "${min_ub:-20260816}" ] 2>/dev/null && high "$camp" "$f" "ca-certificates ${v}（Ubuntu）は eMudhra 侵害 CA を含む（修正版 ${min_ub}ubuntu0.*）"
    elif ! debian_ca_fixed "$v"; then
      high "$camp" "$f" "ca-certificates ${v}（Debian 系）は eMudhra 侵害 CA を含む（修正版 20250419~deb12u2 / 20250419+deb13u1 / 20260816+nmu1）"
    fi
  done < <(host_enabled && echo /var/lib/dpkg/status; files_path '/var/lib/dpkg/status$')
  # apk（Alpine / Wolfi / Chainguard）: /lib/apk/db/installed
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    v="$(awk '/^P:ca-certificates$/ {p=1; next} p && /^V:/ {sub(/^V:/,""); print; exit} /^$/ {p=0}' "$f")"
    [ -n "$v" ] || continue
    local amin; amin="$(read_ioc '.emudhra.os_ca_certificates.alpine')"
    [[ "${v%%-r*}" < "${amin%%-r*}" ]] && high "$camp" "$f" "ca-certificates ${v}（apk）は eMudhra 侵害 CA を含む（Alpine 修正版 ${amin}、Chainguard 20260909-r3）"
  done < <(host_enabled && echo /lib/apk/db/installed; files_path '/lib/apk/db/installed$')
  # pacman（Arch）: /var/lib/pacman/local/ca-certificates-mozilla-<ver>/
  local d
  for d in /var/lib/pacman/local/ca-certificates-mozilla-*; do
    host_enabled && [ -d "$d" ] || continue
    v="${d##*/ca-certificates-mozilla-}"
    version_lt "${v%-*}" "3.131.1" && high "$camp" "$d" "ca-certificates-mozilla ${v} は eMudhra 侵害 CA を含む（修正版 3.131.1-1）"
  done
  return 0
}

# eMudhra: リポジトリで固定されたランタイム（Node.js / Java / Deno）と、ホストのツール（Docker Desktop / mise / rustup）
emudhra_runtimes() {
  local camp="emudhra-ca-oct2026" f v
  local -a nfix jfix dfix; mapfile -t nfix < <(read_ioc '.emudhra.fixed.node'); mapfile -t jfix < <(read_ioc '.emudhra.fixed.java'); mapfile -t dfix < <(read_ioc '.emudhra.fixed.deno')
  judge() {  # judge NAME VERSION PATH FIXED...
    local name="$1" ver="$2" path="$3"; shift 3
    [[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 0
    version_branch_vulnerable "$ver" "$@" && high "$camp" "$path" "${name} ${ver} は eMudhra 侵害 CA を信頼（修正版: $*）"
  }
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    v="$(head -n1 "$f" | tr -d '[:space:]' | sed -E 's/^v//')"; judge "Node.js" "$v" "$f" "${nfix[@]}"
  done < <(files_named '^(\.nvmrc|\.node-version)$')
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    v="$(grep -E '^nodejs[[:space:]]+' "$f" | awk '{print $2}' | head -n1)"; [ -n "$v" ] && judge "Node.js" "$v" "$f" "${nfix[@]}"
    v="$(grep -E '^deno[[:space:]]+' "$f" | awk '{print $2}' | head -n1)"; [ -n "$v" ] && judge "Deno" "$v" "$f" "${dfix[@]}"
  done < <(files_named '^\.tool-versions$')
  while IFS=$'\t' read -r v f; do judge "Node.js" "${v#v}" "$f" "${nfix[@]}"; done < <(detect_service_version '(^|[[:space:]/"=])node')
  while IFS=$'\t' read -r v f; do judge "Deno" "${v#v}" "$f" "${dfix[@]}"; done < <(detect_service_version 'denoland/deno')
  while IFS=$'\t' read -r v f; do
    v="${v%%_*}"; v="${v%%+*}"
    [[ "$v" =~ ^8u?([0-9]+) ]] && { [ "${BASH_REMATCH[1]}" -lt "$(read_ioc '.emudhra.fixed.java8_update')" ] && high "$camp" "$f" "Java 8u${BASH_REMATCH[1]} は eMudhra 侵害 CA を信頼（修正版 8u511）"; continue; }
    judge "Java" "$v" "$f" "${jfix[@]}"
  done < <(detect_service_version '(eclipse-temurin|amazoncorretto|openjdk|bellsoft/liberica-openjdk-[a-z]+|azul/zulu-openjdk)')
  # ホスト: Docker Desktop（macOS の Info.plist）、mise、rustup（バージョン情報はファイルから読む）
  if host_enabled; then
    for f in /Applications/Docker.app/Contents/Info.plist "$HOME_DIR/Applications/Docker.app/Contents/Info.plist"; do
      [ -f "$f" ] || continue
      v="$(grep -A1 'CFBundleShortVersionString' "$f" | grep -o -E '[0-9]+(\.[0-9]+)+' | head -n1)"
      [ -n "$v" ] && version_lt "$v" "$(read_ioc '.emudhra.fixed.docker_desktop')" && high "$camp" "$f" "Docker Desktop ${v} は eMudhra 侵害 CA を信頼（修正版 $(read_ioc '.emudhra.fixed.docker_desktop')）"
    done
  fi
  return 0
}

# §7 AI/エディタ設定（不可視文字・BiDi・ホモグリフ、Git hooks、runOn: folderOpen）
check_s7() {
  log_section "§7" "AI/エディタ"
  local f
  local inv=$'\xe2\x80[\x8b-\x8f\xaa-\xae]|\xe2\x81[\xa0-\xa4\xa6-\xa9]|\xf3\xa0[\x80-\x81][\x80-\xbf]'
  local cyr=$'[A-Za-z][\xd0\xd1][\x80-\xbf]|[\xd0\xd1][\x80-\xbf][A-Za-z]|[A-Za-z]\xce[\x91-\xbf]|\xce[\x91-\xbf][A-Za-z]'
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    grep -q -E -- "$inv" "$f" 2>/dev/null && high "" "$f" "AI指示ファイルに不可視文字/Unicode BiDi 制御文字（U+200B–200F, U+202A–202E, U+2066–2069, タグ文字）"
    grep -q -E -- "$cyr" "$f" 2>/dev/null && medium "" "$f" "AI指示ファイルにラテン文字と混在するキリル/ギリシャ文字（ホモグリフ疑い）"
  done < <(files_named '^(\.cursorrules|CLAUDE\.md|copilot-instructions\.md)$'; files_path '/\.cursor/rules/[^/]+$')
  # Git hooks（.git/hooks の非 sample ファイル）
  local hookdir
  for hookdir in "$ROOT/.git/hooks"; do
    [ -d "$hookdir" ] || continue
    for f in "$hookdir"/*; do
      [ -f "$f" ] || continue
      case "$f" in *.sample) continue ;; esac
      if fgrep_q '(curl|wget|base64|nc |/dev/tcp|python[0-9.]* -c|node -e)' "$f"; then
        high "" "$f" "Git hook に通信/難読化コマンド"
      else
        medium "" "$f" "有効な Git hook が存在します（内容を目視確認）"
      fi
    done
  done
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    fgrep_q '"runOn"[[:space:]]*:[[:space:]]*"folderOpen"' "$f" && high "mcp-poisoning" "$f" "フォルダを開くだけで自動実行されるタスク（runOn: folderOpen）"
  done < <(files_path '/\.(vscode|claude|cursor)/tasks\.json$')
  intel_strings
  intel_apps
  return 0
}

# §8 クラウド/コンテナ
check_s8() {
  log_section "§8" "クラウド/コンテナ"
  local f
  while IFS= read -r f; do [ -n "$f" ] && medium "" "$f" ".env ファイル（シークレット格納の可能性。内容は読み取りません）"; done \
    < <(files_named '^\.env(\.[A-Za-z0-9_-]+)?$' | grep -v -E '\.env\.(example|sample|template|dist)$')
  files_named '^(id_rsa|id_dsa|id_ecdsa|id_ed25519|.*\.pem|.*\.key|.*\.p12|.*\.pfx)$' | grep_l 'PRIVATE KEY' | while IFS= read -r f; do
    [ -n "$f" ] && [ "$f" != /dev/null ] && high "" "$f" "秘密鍵ファイルがリポジトリ/検査対象内にあります"
  done
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    fgrep_q -i '^[[:space:]]*USER[[:space:]]+(root|0)([[:space:]]|$)' "$f" && medium "" "$f" "Dockerfile が USER root で実行"
    grep -E -i '^[[:space:]]*FROM[[:space:]]+' "$f" 2>/dev/null | awk '{print $2}' | while IFS= read -r img; do
      case "$img" in scratch|'$'*|*@sha256:*) continue ;; esac
      if [[ "$img" == *:latest ]] || [[ "${img##*/}" != *:* ]]; then medium "" "$f" "浮動タグのベースイメージ（$img）"; fi
    done
  done < <(files_named '^(Dockerfile.*|.*\.dockerfile)$')
  files_named '\.(ya?ml|json)$' | grep_l '/var/run/docker\.sock|/run/docker\.sock' | while IFS= read -r f; do
    [ -n "$f" ] && [ "$f" != /dev/null ] && high "" "$f" "docker.sock のマウント（コンテナからホスト制御が可能）"
  done
  return 0
}

# §9 Rust/Go/Node タイポスクワット・非公式ソース
check_s9() {
  log_section "§9" "Rust/Go/Nodeロックファイル"
  build_deps
  local f
  # 既知タイポスクワット名の照合は §15 check_lockfile_versions（any_version）で実施
  local -a regs; mapfile -t regs < <(read_ioc '.official_registries')
  local re; re="$(printf '%s|' "${regs[@]}" | sed 's/\./\\./g; s/|$//')"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if grep -E -o '"resolved"[[:space:]]*:[[:space:]]*"https?://[^/"]+' "$f" 2>/dev/null | sed -E 's#.*://##' | sort -u | grep -v -E "^($re)$" | grep -q .; then
      high "" "$f" "公式レジストリ以外から解決された依存関係（依存関係混乱/タイポスクワット）"
    fi
    fgrep_q '"resolved"[[:space:]]*:[[:space:]]*"(git\+|github:|https?://[^"]*\.tgz#)' "$f" && medium "" "$f" "Git/URL 直接参照の依存関係"
  done < <(files_named '^(package-lock\.json|npm-shrinkwrap\.json)$')
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    grep -q -E '^source = "git\+' "$f" && medium "" "$f" "Cargo.lock に Git ソースの依存関係"
    grep -E '^source = "registry\+' "$f" | grep -q -v 'github.com/rust-lang/crates.io-index\|sparse+https://index.crates.io' && high "" "$f" "Cargo.lock に crates.io 以外のレジストリ"
  done < <(files_named '^Cargo\.lock$')
  return 0
}

# §10 OS 永続化（LaunchAgents/crontab/shell rc/履歴）
check_s10() {
  log_section "§10" "OS永続化"
  local f
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    fgrep_q '(curl|wget)[^|#]*\|[[:space:]]*(ba|z)?sh' "$f" && high "" "$f" "シェル設定に curl|sh 形式のリモート実行"
    fgrep_q '(base64[[:space:]]+(-d|--decode)|\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2})' "$f" && high "" "$f" "シェル設定に難読化コード（base64 -d / \\x エスケープ）"
    fgrep_q '(/tmp/|/dev/shm/|/var/tmp/)[^[:space:]]+[[:space:]]*(&|$)' "$f" && medium "" "$f" "シェル設定から一時領域のプログラムを起動"
  done < <(home_rc_paths)
  if [ -d "$HOME_DIR/Library/LaunchAgents" ]; then
    for f in "$HOME_DIR"/Library/LaunchAgents/*.plist; do [ -f "$f" ] && info "" "$f" "LaunchAgent（§30 で詳細検査）"; done
  fi
  if host_enabled && command -v crontab >/dev/null 2>&1; then
    crontab -l 2>/dev/null >"$TMP_DIR/crontab.txt"
    if [ -s "$TMP_DIR/crontab.txt" ]; then
      if grep -v '^[[:space:]]*#' "$TMP_DIR/crontab.txt" | grep -q -E '(curl|wget|base64|/tmp/|/dev/shm/|nc )'; then
        high "" "crontab:$(id -un 2>/dev/null)" "ユーザー crontab に通信/一時領域実行のエントリ"
      else
        info "" "crontab:$(id -un 2>/dev/null)" "ユーザー crontab にエントリがあります"
      fi
    fi
  fi
  for f in .lesshst .viminfo .python_history .node_repl_history .mysql_history .psql_history; do
    [ -f "$HOME_DIR/$f" ] && info "" "$HOME_DIR/$f" "対話履歴ファイル（内容は読み取りません。侵害時はシークレット混入を確認）"
  done
  return 0
}

# §11 SSH/GPG 権限
check_s11() {
  log_section "§11" "SSH/GPG権限"
  local d f p bad=0
  for d in "$HOME_DIR/.ssh" "$HOME_DIR/.gnupg"; do
    [ -d "$d" ] || continue
    p="$(stat_perm "$d")"
    if [ -n "$p" ] && [ $(( 8#$p & 8#077 )) -ne 0 ]; then high "" "$d" "ディレクトリ権限 $p が緩い（chmod 700 を推奨）"; bad=1; fi
    for f in "$d"/*; do
      [ -f "$f" ] && [ ! -L "$f" ] || continue
      case "${f##*/}" in *.pub|known_hosts*|authorized_keys|config|*.conf|pubring.*|trustdb.gpg) continue ;; esac
      p="$(stat_perm "$f")"
      if [ -n "$p" ] && [ $(( 8#$p & 8#077 )) -ne 0 ]; then high "" "$f" "秘密情報ファイルの権限 $p が緩い（chmod 600 を推奨）"; bad=1; fi
    done
  done
  [ "$bad" -eq 0 ] && safe "SSH/GPG の権限に問題なし"
  return 0
}

# §12 ワクチン3点（ignore-scripts / PYTHONNOUSERSITE / PIP_REQUIRE_VIRTUALENV）
check_s12() {
  log_section "§12" "ワクチン3点"
  local hit
  hit=0; for f in "$HOME_DIR/.npmrc" "$ROOT/.npmrc"; do [ -f "$f" ] && fgrep_q '^[[:space:]]*ignore-scripts[[:space:]]*=[[:space:]]*true' "$f" && hit=1; done
  host_enabled && [ "${npm_config_ignore_scripts:-${NPM_CONFIG_IGNORE_SCRIPTS:-}}" = "true" ] && hit=1
  [ "$hit" -eq 1 ] && safe "npm ignore-scripts=true" || medium "" "$HOME_DIR/.npmrc" "npm の ignore-scripts=true が未設定"
  hit=0; host_enabled && [ "${PYTHONNOUSERSITE:-}" = "1" ] && hit=1
  home_rc_paths | grep_l 'PYTHONNOUSERSITE=1' | grep -q -v '^/dev/null$' && hit=1
  [ "$hit" -eq 1 ] && safe "PYTHONNOUSERSITE=1" || medium "" "" "PYTHONNOUSERSITE=1 が未設定（ユーザー site-packages 経由のフック実行）"
  hit=0; host_enabled && [ "${PIP_REQUIRE_VIRTUALENV:-}" = "true" ] && hit=1
  home_rc_paths | grep_l 'PIP_REQUIRE_VIRTUALENV=(true|1)' | grep -q -v '^/dev/null$' && hit=1
  for f in "$HOME_DIR/.config/pip/pip.conf" "$HOME_DIR/.pip/pip.conf" "$HOME_DIR/Library/Application Support/pip/pip.conf"; do
    [ -f "$f" ] && fgrep_q '^[[:space:]]*require-virtualenv[[:space:]]*=[[:space:]]*(true|1)' "$f" && hit=1
  done
  [ "$hit" -eq 1 ] && safe "PIP_REQUIRE_VIRTUALENV=true" || medium "" "" "PIP_REQUIRE_VIRTUALENV=true が未設定（グローバル環境への pip install）"
  return 0
}

# §13 ハニーポット（atime 監視設計指針・noatime 無効警告）
check_s13() {
  log_section "§13" "ハニーポット"
  log_info "設計指針: ~/.aws/credentials 等にダミー認証情報を置き、atime 更新を監視する（読み取り＝侵害シグナル）"
  if host_enabled && command -v mount >/dev/null 2>&1; then
    if mount 2>/dev/null | grep -E "[[:space:]]on[[:space:]]+(/|/home|/Users|$HOME_DIR)[[:space:]]" | grep -q 'noatime'; then
      medium "" "$HOME_DIR" "noatime でマウントされています。atime ハニーポット・アクセス痕跡が機能しません"
    else
      safe "atime が有効（ハニーポット監視が機能）"
    fi
  fi
  return 0
}

# §14 Blast Radius（存在のみ。stat でサイズ・mtime のみ）
blast_list() {
  local key="$1" p e
  while IFS= read -r p; do
    e="$(expand_home "$p")"; e="${e%/}"
    [ -e "$e" ] || continue
    local sz mt
    sz="$(stat_size "$e")"; mt="$(stat_mtime "$e")"
    info "" "$e" "シークレット保管場所が存在（size=${sz:-?} mtime=${mt:-?}。内容は読み取りません。侵害時はローテーション対象）"
  done < <(read_ioc ".blast_radius.$key")
}
check_s14() { log_section "§14" "Blast Radius"; blast_list base; return 0; }

# =============================================================================
# §15〜§19（v4.0）
# =============================================================================

# §15 ワーム型サプライチェーン
check_s15() {
  log_section "§15" "ワーム型サプライチェーン"
  local f n h
  # preinstall: "node setup.mjs"
  local pre; pre="$(read_ioc '.worm_iocs.chaindrop.preinstall')"
  files_named '^package\.json$' | grep_lF "$pre" | while IFS= read -r f; do
    [ -n "$f" ] && [ "$f" != /dev/null ] && critical "chaindrop-keyv" "$f" "ChainDrop の preinstall フック（$pre）"
  done
  # 悪性ファイル実体（ハッシュ一致は CRITICAL、名称一致は HIGH/MEDIUM）
  local -a hashes
  while IFS= read -r n; do
    [ -n "$n" ] || continue
    local camp="chaindrop-keyv"
    [ "$HAVE_JQ" -eq 1 ] && camp="$(jq -r --arg n "$n" '.malicious_files_campaign[$n] // "chaindrop-keyv"' "$IOC_FILE")"
    mapfile -t hashes < <(read_ioc ".worm_iocs.chaindrop.hashes.sha256[\"$n\"]")
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      h="$(sha256_file "$f")"
      if [ -n "$h" ] && printf '%s\n' "${hashes[@]}" | grep -q -x -F -- "$h"; then
        critical "$camp" "$f" "既知の悪性ハッシュと一致（${n}）"
      elif [ "$n" = "setup.mjs" ]; then
        local pj; pj="$(dirname -- "$f")/package.json"
        if [ -f "$pj" ] && fgrep_q 'setup\.mjs' "$pj"; then high "$camp" "$f" "package.json から参照される setup.mjs（ChainDrop 型ドロッパー疑い）"; fi
      else
        high "$camp" "$f" "ワーム関連ファイル名（${n}）"
      fi
    done < <(files_named "^$(printf '%s' "$n" | sed 's/\./\\./g')\$")
  done < <(read_ioc '.malicious_files' | grep -E '\.(m?js)$')
  # ロックファイル照合（campaign 対応）
  check_lockfile_versions
  # TanStack 不正 Git 依存
  files_named '^(package\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$' | grep_lF 'github:tanstack/router#79ac49ee' | while IFS= read -r f; do
    [ -n "$f" ] && [ "$f" != /dev/null ] && critical "teampcp-mini-shai-hulud" "$f" "TanStack の不正 Git 依存（github:tanstack/router#79ac49ee）"
  done
  # Bun 取得痕跡（ライフサイクルスクリプト・ローダー）
  files_path '(/package\.json|\.m?js|\.cjs|\.sh)$' | grep_l '(bun\.sh/install|oven-sh/bun/releases/download)' | while IFS= read -r f; do
    [ -n "$f" ] && [ "$f" != /dev/null ] && high "teampcp-mini-shai-hulud" "$f" "Bun ランタイムの取得処理（Mini Shai-Hulud 型ペイロード）"
  done
  # site-packages/*/__init__.py ドロッパー
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    fgrep_q '(exec|eval)\(' "$f" && fgrep_q '(b64decode|zlib\.decompress|marshal\.loads|bytes\.fromhex)' "$f" \
      && high "pypi-oct2026" "$f" "site-packages の __init__.py に難読化実行コード（ドロッパー疑い）"
  done < <(files_path '/(site|dist)-packages/[^/]+/__init__\.py$')
  [ -d "$ROOT" ] && files_path '/(site|dist)-packages/lightning/_runtime/' | head -n1 | while IFS= read -r f; do
    [ -n "$f" ] && critical "pypi-oct2026" "$(dirname -- "$f")" "lightning の _runtime/ ディレクトリ（侵害版の痕跡）"
  done
  # IronWorm / sckit / Miasma バイナリ名
  while IFS= read -r n; do
    [ -n "$n" ] || continue
    while IFS= read -r f; do [ -n "$f" ] && critical "post-shaihulud" "$f" "後続ワームのバイナリ名（${n}）"; done < <(files_named "^$(printf '%s' "$n" | sed 's/\./\\./g')\$")
  done < <(read_ioc '.worm_iocs.post_shaihulud.binaries')
  intel_files
  return 0
}

# §16 CI/CD 基盤 RCE（TeamCity / Artifactory / Docker cp）
check_s16() {
  log_section "§16" "CI/CD基盤RCE"
  local ver f
  local -a tc_fixed af_fixed
  if [ "$HAVE_JQ" -eq 1 ]; then
    mapfile -t tc_fixed < <(jq -r '.infrastructures[] | select(.id=="teamcity") | .cves[0].fixed[]' "$IOC_FILE")
    mapfile -t af_fixed < <(jq -r '.infrastructures[] | select(.id=="jfrog-artifactory") | .cves[0].fixed[]' "$IOC_FILE")
  else
    tc_fixed=(2026.1.3 2025.11.7)
    mapfile -t af_fixed < <(grep -o '"CVE-2026-82329".*' "$IOC_FILE" | grep -o -E '"7\.[0-9]+\.[0-9]+"' | tr -d '"')
  fi
  while IFS=$'\t' read -r ver f; do
    [ -n "$ver" ] || continue
    if [ "$ver" = "latest" ]; then medium "" "$f" "TeamCity が浮動タグ（latest）。CVE-2026-63077 の修正版（${tc_fixed[*]}）を確認"; continue; fi
    if version_branch_vulnerable "$ver" "${tc_fixed[@]}"; then
      critical "" "$f" "TeamCity ${ver} は CVE-2026-63077（CVSS 9.8, CISA KEV）の影響範囲（修正版: ${tc_fixed[*]}）"
    else
      safe "TeamCity ${ver} は修正版以上（$f）"
    fi
  done < <(detect_service_version 'jetbrains/teamcity-server')
  while IFS=$'\t' read -r ver f; do
    [ -n "$ver" ] || continue
    if [ "$ver" = "latest" ]; then medium "" "$f" "Artifactory が浮動タグ（latest）。CVE-2026-82329 の修正版を確認"; continue; fi
    if version_branch_vulnerable "$ver" "${af_fixed[@]}"; then
      critical "" "$f" "JFrog Artifactory ${ver} は CVE-2026-82329（CVSS 9.8）の影響範囲（修正版: ${af_fixed[*]}）"
    else
      safe "Artifactory ${ver} は修正版以上（$f）"
    fi
  done < <(detect_service_version 'jfrog/artifactory-(pro|oss|jcr)|releases-docker\.jfrog\.io/jfrog/artifactory-(pro|oss|jcr)')
  files_path '\.(sh|bash|ya?ml|mk|Makefile|py|js|ts)$|/Makefile$|/Dockerfile[^/]*$' | grep_l 'docker[[:space:]]+(container[[:space:]]+)?cp[[:space:]]' | while IFS= read -r f; do
    [ -n "$f" ] && [ "$f" != /dev/null ] && medium "" "$f" "docker cp の使用（CVE-2026-17106 CopyEscape: 信頼できないコンテナからのコピーでホスト上書き）"
  done
  intel_infra
  return 0
}

# §17 MCP 静的ポイズニング（command/args、SymJack、エージェントフック、setup.mjs 参照）
mcp_config_files() {
  files_path '(/\.mcp\.json|/mcp\.json|/\.cursor/mcp\.json|/\.vscode/mcp\.json|/\.claude/settings(\.local)?\.json|/\.gemini/settings\.json|/claude_desktop_config\.json|/\.codex/config\.toml)$'
  local p e
  while IFS= read -r p; do
    e="$(expand_home "$p")"; e="${e%/}"
    [ -f "$e" ] && printf '%s\n' "$e"
  done < <(read_ioc '.mcp_poisoning.config_paths')
  for e in "$HOME_DIR/.claude.json" "$HOME_DIR/.claude/settings.json" "$HOME_DIR/.gemini/settings.json" "$HOME_DIR/.codeium/windsurf/mcp_config.json" "$HOME_DIR/.codex/config.toml"; do
    [ -f "$e" ] && printf '%s\n' "$e"
  done
  return 0
}
# JSONC（.vscode/mcp.json 等はコメント・末尾カンマを公式に許容）を JSON に変換する
#   文字列の外側にある // 行コメント・/* */ ブロックコメント・閉じ括弧直前のカンマを除去する（文字列内はそのまま）
jsonc_to_json() {
  awk 'BEGIN { RS = "\001" }
    { n = length($0); ins = 0; esc = 0; pc = 0
      for (i = 1; i <= n; i++) {
        ch = substr($0, i, 1)
        if (ins) {
          if (esc) esc = 0; else if (ch == "\\") esc = 1; else if (ch == "\"") ins = 0
          printf "%s", ch; continue }
        if (ch == "/" && substr($0, i + 1, 1) == "/") {
          j = index(substr($0, i), "\n"); if (j == 0) i = n; else i = i + j - 2
          continue }
        if (ch == "/" && substr($0, i + 1, 1) == "*") {
          j = index(substr($0, i + 2), "*/"); if (j == 0) { printf "%s", substr($0, i); i = n; continue }
          i = i + j + 2; printf " "; continue }
        if (ch ~ /[ \t\r\n]/) { printf "%s", ch; continue }
        if (pc) { if (ch != "}" && ch != "]") printf ","; pc = 0 }
        if (ch == ",") { pc = 1; continue }
        if (ch == "\"") ins = 1
        printf "%s", ch
      }
      if (pc) printf "," }' "$1" 2>/dev/null
}

# Codex CLI の .codex/config.toml から MCP サーバーの command/args を 1 行ずつ出力する最小パーサ（依存なし）
#   対応: [mcp_servers.<name>] テーブルの command = "…" / '…'、args = [ … ]（複数行可）、
#         [mcp_servers] 直下のインラインテーブル（name = { command = "…", args = […] }、1 行）
#   未対応の構文（複数行文字列・解釈できない command 行・command も url も無いサーバー）は
#   "?<理由>" 行で知らせ、呼び出し側が errors[] に記録する（読めなかった設定を 0 件扱いしない）
codex_toml_mcp_commands() {
  text_lines "$1" | awk '
    function strs(t,   out, v) {
      out = ""
      while (match(t, /"([^"\\]|\\.)*"|\047[^\047]*\047/)) {
        v = substr(t, RSTART + 1, RLENGTH - 2); out = out (out == "" ? "" : " ") v
        t = substr(t, RSTART + RLENGTH) }
      return out }
    function flush() {
      if (cur != "" && cmd != "") print cmd (args != "" ? " " args : "")
      else if (cur != "" && !hasurl) print "?no_command:" cur
      cur = ""; cmd = ""; args = ""; hasurl = 0; inargs = 0 }
    { line = $0; sub(/^[[:space:]]*#.*$/, "", line) }
    inargs { t = strs(line); if (t != "") args = args (args == "" ? "" : " ") t; if (line ~ /\]/) inargs = 0; next }
    line ~ /"""|\047\047\047/ { if (cur != "" || intable) print "?multiline_string"; next }
    line ~ /^[[:space:]]*\[/ {
      h = line; sub(/^[[:space:]]*\[+[[:space:]]*/, "", h); sub(/[[:space:]]*\]+[[:space:]]*(#.*)?$/, "", h)
      if (h ~ /^mcp_servers\./) {
        nm = substr(h, 13)
        if (nm ~ /^"/) { nm = substr(nm, 2); q = index(nm, "\""); rest = substr(nm, q + 1); nm = substr(nm, 1, q - 1) }
        else { rest = nm; sub(/^[^.]*/, "", rest); sub(/\..*$/, "", nm) }
        if (rest != "") next   # [mcp_servers.<name>.env] 等のサブテーブルは同じサーバーの続き
        flush(); cur = nm; intable = 0; next }
      flush(); intable = (h == "mcp_servers"); next }
    cur != "" && line ~ /^[[:space:]]*command[[:space:]]*=/ {
      v = line; sub(/^[[:space:]]*command[[:space:]]*=[[:space:]]*/, "", v); c = strs(v)
      if (c == "") print "?unparsed_command:" cur; else cmd = c
      next }
    cur != "" && line ~ /^[[:space:]]*url[[:space:]]*=/ { hasurl = 1; next }
    cur != "" && line ~ /^[[:space:]]*args[[:space:]]*=/ {
      v = line; sub(/^[[:space:]]*args[[:space:]]*=[[:space:]]*/, "", v); args = strs(v)
      if (v !~ /\]/) inargs = 1
      next }
    intable && line ~ /command[[:space:]]*=/ {
      c = line; sub(/.*command[[:space:]]*=[[:space:]]*/, "", c); sub(/,.*$/, "", c); c = strs(c)
      a = ""; if (match(line, /args[[:space:]]*=[[:space:]]*\[[^]]*\]/)) a = strs(substr(line, RSTART, RLENGTH))
      if (c == "") print "?unparsed_inline"; else print c (a != "" ? " " a : "")
      next }
    END { flush() }'
}

check_s17() {
  log_section "§17" "MCP静的ポイズニング"
  local f cmdline
  local mcpq='[.. | objects | select(has("command")) | ((.command | tostring) + " " + ((.args // []) | map(tostring) | join(" ")))] | .[]'
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if [[ "$f" == *.toml ]]; then
      codex_toml_mcp_commands "$f" | while IFS= read -r cmdline; do
        case "$cmdline" in "?"*) record_error "§17" "codex_toml_unparsed:${cmdline#\?}:$f"; continue ;; esac
        printf '%s\n' "$cmdline"
      done
    elif [ "$HAVE_JQ" -eq 1 ]; then
      # 厳密な JSON として読めなければ JSONC（コメント・末尾カンマ）として読み直し、それでも失敗したら errors[]
      jq -r "$mcpq" "$f" 2>/dev/null \
        || jsonc_to_json "$f" | jq -r "$mcpq" 2>/dev/null \
        || record_error "§17" "mcp_config_parse_failed:$f"
    else
      grep -E -o '"(command|args)"[[:space:]]*:[[:space:]]*("[^"]*"|\[[^]]*\])' "$f" 2>/dev/null
    fi | while IFS= read -r cmdline; do
      if printf '%s' "$cmdline" | grep -q -E '(^|[[:space:]"/])(curl|wget)([[:space:]"]|$)|bash -c|sh -c|powershell(\.exe)? .*-(e|enc|encodedcommand)[[:space:]]|node -e|python[0-9.]* -c|base64'; then
        high "mcp-poisoning" "$f" "MCP/エージェント設定の command/args に危険なコマンド（curl/wget/bash -c/powershell -enc/node -e）"
      elif printf '%s' "$cmdline" | grep -q -E '(^|[[:space:]"/])(npx|uvx|bunx|pnpm dlx)([[:space:]"]|$)'; then
        medium "mcp-poisoning" "$f" "MCP の command が npx/uvx（実行時に最新版を取得。バージョン固定を確認）"
      fi
    done
  done < <(mcp_config_files | sort -u)
  # SymJack: シンボリックリンクがエージェント設定を指す / デコイ名
  local l t base
  while IFS= read -r l; do
    [ -n "$l" ] || continue
    t="$(readlink -- "$l" 2>/dev/null)"
    base="${l#"$ROOT"/}"
    if printf '%s' "$t" | grep -q -E '(\.claude/|\.mcp\.json|\.cursor/|\.gemini/|\.codex/|\.vscode/settings\.json)'; then
      critical "mcp-poisoning" "$l" "SymJack: シンボリックリンクがエージェント設定（$t）を指しています"
    elif printf '%s' "$base" | grep -q -i -E '(^|/)(vid-|logo\.|readme\.)|^docs/' && [[ "$t" == ../* || "$t" == /* ]]; then
      high "mcp-poisoning" "$l" "SymJack 疑い: デコイ名のリンクが外部（$t）を指しています"
    fi
  done <"$LINKS_LIST"
  # エージェントフック（.claude/settings.json の hooks に通信/難読化）
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if fgrep_q '"hooks"[[:space:]]*:' "$f" && fgrep_q '"command"[[:space:]]*:[[:space:]]*"[^"]*(curl|wget|base64|nc |/dev/tcp)' "$f"; then
      high "mcp-poisoning" "$f" "エージェントフックに通信/難読化コマンド"
    fi
  done < <(files_path '/\.(claude|cursor|gemini)/(settings(\.local)?|hooks)\.json$')
  # setup.mjs 内の .claude/.vscode/.cursor 参照
  files_named '^setup\.mjs$' | grep_l '\.(claude|vscode|cursor)(/|\b)' | while IFS= read -r f; do
    [ -n "$f" ] && [ "$f" != /dev/null ] && critical "chaindrop-keyv" "$f" "setup.mjs がエージェント/IDE 設定ディレクトリを参照（MCP 設定改ざん）"
  done
  return 0
}

# §18 ネットワーク IoC（C2 ドメイン/IP、履歴）
# network_iocs [all] … 照合文字列<TAB>campaign<TAB>種別（malicious / legit）
#   既定は悪性のみ。all を付けると、悪用された正規インフラ（legit_infra）も含める
network_iocs() {
  local s kind
  local -a keys=('.worm_iocs.chaindrop.domains' '.worm_iocs.chaindrop.eth_contracts' '.worm_iocs.teampcp.c2_ip' '.worm_iocs.teampcp.c2_domains')
  [ "${1:-}" = "all" ] && keys+=('.worm_iocs.chaindrop.legit_infra' '.worm_iocs.teampcp.legit_infra')
  for s in "${keys[@]}"; do
    local camp="chaindrop-keyv"; [[ "$s" == *teampcp* ]] && camp="teampcp-mini-shai-hulud"
    kind="malicious"; [[ "$s" == *legit_infra* ]] && kind="legit"
    read_ioc "$s" | while IFS= read -r i; do [ -n "$i" ] && printf '%s\t%s\t%s\n' "$(refang "$i")" "$camp" "$kind"; done
  done
  if [ "${1:-}" = "all" ]; then intel_network_iocs; else intel_network_iocs | awk -F'\t' '$3=="malicious"'; fi
}
check_s18() {
  log_section "§18" "ネットワークIoC"
  network_iocs all >"$TMP_DIR/netioc.tsv"
  awk -F'\t' '$3=="malicious"{print $1}' "$TMP_DIR/netioc.tsv" >"$TMP_DIR/netioc.pat"
  awk -F'\t' '$3=="legit"{print $1}' "$TMP_DIR/netioc.tsv" >"$TMP_DIR/netioc-legit.pat"
  [ -s "$TMP_DIR/netioc.pat" ] || { record_error "§18" "ioc_empty"; return 0; }
  local f hit camp pat
  for pat in netioc netioc-legit; do
    [ -s "$TMP_DIR/$pat.pat" ] || continue
    grep -v -E '/\.(zsh|bash)_history$' "$FILES_LIST" | tr '\n' '\0' | xargs -0 grep -l -I -F -f "$TMP_DIR/$pat.pat" -- /dev/null 2>/dev/null | grep -v '^/dev/null$' | while IFS= read -r f; do
      hit="$(grep -o -F -f "$TMP_DIR/$pat.pat" -- "$f" 2>/dev/null | sort -u | head -n3 | tr '\n' ' ')"
      camp="$(grep -F -- "$(printf '%s' "$hit" | awk '{print $1}')" "$TMP_DIR/netioc.tsv" | head -n1 | cut -f2)"
      if [ "$pat" = "netioc" ]; then
        critical "$camp" "$f" "ネットワーク IoC を含むファイル（${hit% }）"
      else
        medium "$camp" "$f" "攻撃に悪用された正規インフラへの参照（${hit% }）。正規利用か、想定外の接続元かを確認"
      fi
    done
  done
  local hf
  for hf in "$HOME_DIR/.zsh_history" "$HOME_DIR/.bash_history"; do
    [ -f "$hf" ] && [ ! -L "$hf" ] || continue
    grep -q -F -f "$TMP_DIR/netioc.pat" -- "$hf" 2>/dev/null && critical "" "$hf" "シェル履歴に C2 ドメイン/IP"
    tail -n 5 -- "$hf" 2>/dev/null | grep -q -E '(curl|wget)[^|]*\|[[:space:]]*(ba|z)?sh' && high "" "$hf" "シェル履歴の直近5件に curl|sh 形式の実行"
  done
  return 0
}

# §19 Blast Radius 拡張
check_s19() { log_section "§19" "Blast Radius拡張"; blast_list extended; return 0; }

# =============================================================================
# §20〜§35（v4.1）
# =============================================================================

# MCP サーバー実装・ツール定義と思われるファイル
mcp_source_files() {
  files_path '\.(json|js|mjs|cjs|ts|py)$' | grep -v -E '/node_modules/(typescript|@types)/' \
    | grep_l '(inputSchema|mcpServers|@modelcontextprotocol|FastMCP|mcp\.server|"tools"[[:space:]]*:)'
}

# §20 MCP セマンティック（Deadbugz / NeighborJack / 命令形＋外部参照）
check_s20() {
  log_section "§20" "MCPセマンティック"
  local f
  mcp_source_files >"$TMP_DIR/mcpsrc.lst"
  grep_l '(ignore (all |any )?(the )?previous instructions|do not tell the user|don'"'"'t tell the user|without (telling|informing) the user)' -i <"$TMP_DIR/mcpsrc.lst" | while IFS= read -r f; do
    [ -n "$f" ] && high "mcp-poisoning" "$f" "MCP ツール定義にプロンプトインジェクション文言（ignore previous instructions / do not tell the user）"
  done
  grep_l '"description"[[:space:]]*:[[:space:]]*"[^"]*\b(execute|run|send|upload|fetch|download|must call|always call)\b[^"]*(https?://|curl|wget|~/\.|\.ssh|\.env)' -i <"$TMP_DIR/mcpsrc.lst" | while IFS= read -r f; do
    [ -n "$f" ] && high "mcp-poisoning" "$f" "ツール description 内で命令形動詞と外部リソース参照が共起"
  done
  grep_l '(callCount|invocations?|callCounter|numCalls|count)[[:space:]]*(>|>=)[[:space:]]*[0-9]+' <"$TMP_DIR/mcpsrc.lst" | while IFS= read -r f; do
    [ -n "$f" ] && high "mcp-poisoning" "$f" "Deadbugz 型ランタイムゲート（呼び出し回数による条件分岐）"
  done
  local nre; nre="$(read_ioc '.mcp_poisoning.neighbor.internal_ip_regex')"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    grep -q -E "\"(url|serverUrl|endpoint)\"[[:space:]]*:[[:space:]]*\"https?://${nre}" "$f" 2>/dev/null \
      && medium "mcp-poisoning" "$f" "NeighborJack: ループバック以外の内部 IP の MCP エンドポイントを登録"
    grep -q -E '"(url|serverUrl)"[[:space:]]*:[[:space:]]*"http://' "$f" 2>/dev/null \
      && grep -E -o '"(url|serverUrl)"[[:space:]]*:[[:space:]]*"http://[^"]+' "$f" | grep -q -v -E 'http://(localhost|127\.0\.0\.1|\[::1\])' \
      && medium "mcp-poisoning" "$f" "平文 HTTP のリモート MCP エンドポイント"
    grep -q -E '"(host|bind|listen)"[[:space:]]*:[[:space:]]*"0\.0\.0\.0"|--host[ =]0\.0\.0\.0' "$f" 2>/dev/null \
      && medium "mcp-poisoning" "$f" "MCP サーバーが 0.0.0.0 で待ち受け（同一ネットワークから到達可能）"
  done < <(mcp_config_files | sort -u)
  intel_strings
  return 0
}

# GitHub Actions ワークフロー一覧
workflow_files() { files_path '/\.github/workflows/[^/]+\.ya?ml$'; }
# ワークフロー本文の正規化（CRLF・BOM 除去、"uses: >-" / "uses: |" のブロックスカラーを 1 行に畳む）
#   uses: >-
#     actions/checkout@v4      →   uses: actions/checkout@v4
workflow_text() {
  text_lines "$1" | awk '
    pend != "" {
      if ($0 ~ /^[[:space:]]*$/) next
      match($0, /^[[:space:]]*/)
      if (RLENGTH > pind) { v = $0; sub(/^[[:space:]]+/, "", v); sub(/[[:space:]]+#.*$/, "", v); sub(/[[:space:]]+$/, "", v); print pend v; pend = ""; next }
      print pend; pend = ""
    }
    /uses:[[:space:]]*[>|][-+0-9]*[[:space:]]*(#.*)?$/ {
      match($0, /^[[:space:]]*/); pind = RLENGTH
      if ($0 ~ /^[[:space:]]*-[[:space:]]/) { t = $0; sub(/^[[:space:]]*-[[:space:]]+/, "", t); pind = length($0) - length(t) - 1 }
      pend = $0; sub(/[>|][-+0-9]*[[:space:]]*(#.*)?$/, "", pend); next
    }
    { print }
    END { if (pend != "") print pend }'
}

# §21 GitHub Actions 危険パターン
check_s21() {
  log_section "§21" "GitHub Actions"
  local f
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if fgrep_q '(^|[^A-Za-z0-9_])pull_request_target([^A-Za-z0-9_]|$)' "$f" && fgrep_q -i 'actions/checkout@' "$f" && fgrep_q '\$\{\{[[:space:]]*secrets\.' "$f"; then
      # actions/checkout ステップごとに ref の有無と参照先を判定
      local refs
      refs="$(awk '
        function flush(){ if (inchk) { print (ref=="" ? "noref" : ref) } inchk=0; ref="" }
        tolower($0) ~ /uses:[[:space:]]*["'"'"']?actions\/checkout@/ { flush(); inchk=1; match($0,/^[[:space:]]*/); ind=RLENGTH; next }
        inchk {
          match($0,/^[[:space:]]*/)
          if ($0 ~ /^[[:space:]]*-[[:space:]]/ && RLENGTH <= ind) { flush(); next }
          if ($0 ~ /^[[:space:]]*ref:/) { r=$0; sub(/^[[:space:]]*ref:[[:space:]]*/,"",r)
            ref = (r ~ /github\.(event\.pull_request\.head|head_ref)/) ? "prhead" : "otherref" }
        }
        END{ flush() }' < <(workflow_text "$f"))"
      if printf '%s\n' "$refs" | grep -q -x 'prhead'; then
        critical "ghostaction-oct2026" "$f" "pull_request_target + PR head の checkout + secrets 参照（pwn request）"
      fi
      if printf '%s\n' "$refs" | grep -q -x 'noref'; then
        high "ghostaction-oct2026" "$f" "pull_request_target + actions/checkout(refなし) + secrets 参照（ベースブランチの取得だが、後続ステップで PR 由来のコードを扱わないか確認）"
      fi
    fi
    fgrep_q 'key:.*github\.event\.pull_request\.number' "$f" && high "ghostaction-oct2026" "$f" "actions/cache のキーに PR 番号（キャッシュポイズニング）"
    fgrep_q '^[[:space:]]*permissions:[[:space:]]*write-all' "$f" && high "ghostaction-oct2026" "$f" "permissions: write-all"
  done < <(workflow_files)
  return 0
}

# §22 アクション SHA 固定
check_s22() {
  log_section "§22" "アクションSHA固定"
  local f line act ref
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    workflow_text "$f" | grep -E -o '^[[:space:]-]*(\{([^}#]*,)?[[:space:]]*)?uses:[[:space:]]*["'"'"']?[^"'"'"'[:space:]#,}]+' 2>/dev/null | sed -E 's/.*uses:[[:space:]]*["'"'"']?//' | sort -u | while IFS= read -r line; do
      case "$line" in ./*|docker://*) continue ;; esac
      act="${line%@*}"; ref="${line##*@}"; act="${act,,}"
      [ "$act" != "$line" ] || { high "ghostaction-oct2026" "$f" "uses: ${line} がバージョン未指定"; continue; }
      if [ "$act" = "aquasecurity/trivy-action" ] && ! [[ "$ref" =~ ^[0-9a-f]{40}$ ]] && [ "$ref" != "v0.35.0" ]; then
        critical "ghostaction-oct2026" "$f" "汚染されたタグ参照の可能性（${line}。2026-03-19 にタグ 75/76 が強制 push。安全版 v0.35.0 または検証済み SHA に固定）"
      elif [[ "$ref" =~ ^[0-9a-f]{40}$ ]]; then
        case "$act" in tj-actions/*|aquasecurity/*) medium "ghostaction-oct2026" "$f" "侵害履歴のある発行元のアクション ${act}（SHA 固定済み。SHA が安全な版か確認）" ;; esac
      else
        case "$act" in
          tj-actions/*|aquasecurity/*) critical "ghostaction-oct2026" "$f" "侵害履歴のある発行元のアクションをタグ参照（${line}）" ;;
          *) high "ghostaction-oct2026" "$f" "SHA 固定されていないアクション参照（${line}）" ;;
        esac
      fi
    done
    if grep -q -E "(trivy-version|version):[[:space:]]*[\"']?v?0\.69\.4[\"']?[[:space:]]*$" "$f" 2>/dev/null && grep -q 'trivy' "$f"; then
      critical "ghostaction-oct2026" "$f" "Trivy 本体の悪性版 v0.69.4 を指定（安全版は v0.69.3）"
    fi
  done < <(workflow_files; files_path '/action\.ya?ml$')
  local ver
  while IFS=$'\t' read -r ver f; do
    [ "${ver#v}" = "0.69.4" ] && critical "ghostaction-oct2026" "$f" "Trivy 本体の悪性版イメージ（aquasec/trivy:0.69.4）"
  done < <(detect_service_version 'aquasec/trivy')
  intel_actions
  return 0
}

# §23 コンテナランタイム（CopyEscape / Copy Fail / 特権コンテナ）
check_s23() {
  log_section "§23" "コンテナランタイム"
  if host_enabled; then
    local dv kv
    dv="$(safe_probe docker version --format '{{.Client.Version}}')"
    if [ -n "$dv" ]; then
      local dfix; dfix="$(infra_fixed docker CVE-2026-17106 | head -n1)"
      if [ -z "$dfix" ]; then medium "" "$(command -v docker)" "Docker ${dv}: CVE-2026-17106（CopyEscape）の修正版を公式で確認してください（ioc に修正版未定義）"
      elif version_lt "${dv%%-*}" "$dfix"; then high "" "$(command -v docker)" "Docker ${dv} は CVE-2026-17106（CopyEscape、moby/go-archive）の影響範囲（修正版: Engine/CLI ${dfix}）"
      fi
    fi
    kv="$(uname -r 2>/dev/null)"
    if [ -n "$kv" ] && [ "$OS_NAME" = "Linux" ]; then
      local kver cve; kver="$(printf '%s' "$kv" | grep -o -E '^[0-9]+\.[0-9]+(\.[0-9]+)?')"
      [[ "$kver" =~ ^[0-9]+\.[0-9]+$ ]] && kver="$kver.0"
      local -a kcves
      if [ "$HAVE_JQ" -eq 1 ]; then mapfile -t kcves < <(jq -r '.infrastructures[] | select(.id=="kernel") | .cves[].id' "$IOC_FILE")
      else kcves=(CVE-2026-31431 CVE-2026-80521 CVE-2026-64564); fi
      for cve in "${kcves[@]}"; do
        local -a kfix; mapfile -t kfix < <(infra_fixed kernel "$cve")
        [ "${#kfix[@]}" -gt 0 ] && [ -n "$kver" ] || continue
        if version_branch_vulnerable "$kver" "${kfix[@]}"; then
          high "" "/proc/version" "Linux カーネル ${kv} は ${cve} の upstream 修正版（${kfix[*]}）未満。ディストリビューションのバックポート有無を確認"
        fi
      done
    fi
  fi
  local f
  files_named '\.(ya?ml)$' | grep_l '^[[:space:]]*privileged:[[:space:]]*true' | while IFS= read -r f; do
    [ -n "$f" ] && high "" "$f" "特権コンテナ（privileged: true）。カーネル UAF によるエスケープの影響が拡大"
  done
  files_named '\.(ya?ml)$' | grep_l '(cap_add:|add:)[^#]*(SYS_ADMIN|ALL)|- (SYS_ADMIN|ALL)$' | while IFS= read -r f; do
    [ -n "$f" ] && high "" "$f" "危険なケーパビリティ（SYS_ADMIN/ALL）付与"
  done
  intel_tool_versions
  return 0
}

# ブラウザ拡張 manifest 一覧（ホーム配下の監視パス + ROOT 内の Extensions/*/manifest.json）
extension_manifests() {
  files_path '/Extensions/[^/]+/([^/]+/)?manifest\.json$'
  local p e d
  while IFS= read -r p; do
    e="$(expand_home "$p")"
    for d in $e; do
      [ -d "$d" ] || continue
      find "$d" -maxdepth 3 -name manifest.json -type f 2>/dev/null
    done
  done < <(read_ioc '.browser_extensions.watch_paths.mac'; read_ioc '.browser_extensions.watch_paths.linux')
  return 0
}

# §24 ブラウザ拡張（update_url / 危険パーミッション / <all_urls>）
check_s24() {
  log_section "§24" "ブラウザ拡張"
  local f perms
  local -a dperm offurl; mapfile -t dperm < <(read_ioc '.browser_extensions.dangerous_permissions'); mapfile -t offurl < <(read_ioc '.browser_extensions.official_update_urls')
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    local uu=""
    if [ "$HAVE_JQ" -eq 1 ]; then
      uu="$(jq -r '.update_url // empty' "$f" 2>/dev/null)"
      perms="$(jq -r '[(.permissions // []), (.optional_permissions // []), (.host_permissions // []), ((.content_scripts // []) | map(.matches // []) | add // [])] | add | map(tostring) | .[]' "$f" 2>/dev/null)"
    else
      uu="$(grep -o -E '"update_url"[[:space:]]*:[[:space:]]*"[^"]*"' "$f" | sed -E 's/.*:[[:space:]]*"//; s/"$//')"
      perms="$(tr -d '\n' <"$f" | grep -o -E '"[A-Za-z<>_.]+"' | tr -d '"')"
    fi
    if [ -n "$uu" ] && ! printf '%s\n' "${offurl[@]}" | grep -q -x -F -- "$uu"; then
      high "" "$f" "拡張の update_url が公式ストア以外"
    fi
    local p found=""
    for p in "${dperm[@]}"; do printf '%s\n' "$perms" | grep -q -x -F -- "$p" && found="$found $p"; done
    local all=0; printf '%s\n' "$perms" | grep -q -x -F -- '<all_urls>' && all=1
    if [ -n "$found" ] && [ "$all" -eq 1 ]; then high "" "$f" "危険パーミッション（${found# }）+ <all_urls>"
    elif [ -n "$found" ]; then medium "" "$f" "危険パーミッション（${found# }）"
    elif [ "$all" -eq 1 ]; then medium "" "$f" "全サイトへのアクセス（<all_urls>）"
    fi
  done < <(extension_manifests | sort -u)
  return 0
}

# §25 後続ワーム（IronWorm / sckit / Miasma / cargo-install 偽装）
check_s25() {
  log_section "§25" "後続ワーム"
  local n d
  local -a bins; mapfile -t bins < <(read_ioc '.worm_iocs.post_shaihulud.binaries')
  for d in "$HOME_DIR/.cargo/bin" "$HOME_DIR/.local/bin" "$HOME_DIR/go/bin" "$HOME_DIR/.bun/bin" /usr/local/bin /tmp /var/tmp /dev/shm; do
    [ -d "$d" ] || continue
    case "$d" in /usr/local/bin|/tmp|/var/tmp|/dev/shm) host_enabled || continue ;; esac
    for n in "${bins[@]}"; do [ -e "$d/$n" ] && critical "post-shaihulud" "$d/$n" "後続ワームのバイナリ（${n}）"; done
    [ -e "$d/cargo-install" ] && high "post-shaihulud" "$d/cargo-install" "cargo-install を名乗るバイナリ（偽装）"
  done
  local f; while IFS= read -r f; do [ -n "$f" ] && high "post-shaihulud" "$f" "cargo-install を名乗るファイル（偽装）"; done < <(files_named '^cargo-install(\.exe)?$')
  if host_enabled && [ -f "$TMP_DIR/ps.txt" ]; then
    grep -E '(^|/| )cargo-install( |$)' "$TMP_DIR/ps.txt" | awk '{print $1}' | while IFS= read -r pid; do
      high "post-shaihulud" "/proc/$pid" "cargo-install を名乗るプロセス（pid $pid）"
    done
  fi
  return 0
}

# §26 開発者ツール設定
check_s26() {
  log_section "§26" "開発者ツール設定"
  local f
  while IFS= read -r f; do
    [ -n "$f" ] && [ -f "$f" ] || continue
    fgrep_q -i '^[[:space:]]*fsmonitor[[:space:]]*=' "$f" && ! fgrep_q -i '^[[:space:]]*fsmonitor[[:space:]]*=[[:space:]]*(true|false)[[:space:]]*$' "$f" \
      && critical "" "$f" "core.fsmonitor に外部コマンド（git 操作のたびに実行）"
    fgrep_q -i '^[[:space:]]*sshCommand[[:space:]]*=' "$f" && high "" "$f" "core.sshCommand が設定されています"
    fgrep_q -i '^[[:space:]]*hooksPath[[:space:]]*=' "$f" && medium "" "$f" "core.hooksPath が設定されています（フック置き場の付け替え）"
  done < <(printf '%s\n' "$HOME_DIR/.gitconfig" "$HOME_DIR/.config/git/config" "$ROOT/.git/config"; files_named '^\.gitconfig$')
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if fgrep_q '(curl|wget)[^|#]*\|[[:space:]]*(ba|z)?sh|eval[[:space:]]+"?\$\((curl|wget)' "$f"; then
      high "" "$f" ".envrc がリモートスクリプトを実行（direnv: curl|bash）"
    fi
  done < <(files_named '^\.envrc$')
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    grep -E -o 'https?://[^"'"'"'[:space:]]+' "$f" 2>/dev/null | grep -q -v -E '^https://github\.com/(asdf-vm|asdf-community|mise-plugins|jdx)/' \
      && medium "" "$f" "asdf/mise のプラグイン URL が公式以外"
  done < <(files_named '^(\.tool-versions|mise\.toml|\.mise\.toml)$')
  local -a regs; mapfile -t regs < <(read_ioc '.official_registries')
  local re; re="$(printf '%s|' "${regs[@]}" | sed 's/\./\\./g; s/|$//')"
  while IFS= read -r f; do
    [ -n "$f" ] && [ -f "$f" ] || continue
    if grep -E -i '^[[:space:]]*(registry|@[^:]+:registry|npmRegistryServer|repository|index-url|index_url|extra-index-url)[[:space:]]*[=:]' "$f" 2>/dev/null \
       | grep -E -o 'https?://[^/"'"'"'[:space:]]+' | sed -E 's#https?://##' | grep -q -v -E "^($re)$"; then
      medium "" "$f" "パッケージレジストリ URL が公式以外（改ざん/依存関係混乱の確認）"
    fi
  done < <(printf '%s\n' "$HOME_DIR/.npmrc" "$HOME_DIR/.yarnrc" "$HOME_DIR/.yarnrc.yml" "$HOME_DIR/.pypirc" "$HOME_DIR/.config/pip/pip.conf"; files_named '^(\.npmrc|\.yarnrc|\.yarnrc\.yml|\.pypirc|pip\.conf)$')
  return 0
}

# §27 ビルドフック（build.rs / go:generate / build-backend / cmdclass）
check_s27() {
  log_section "§27" "ビルドフック"
  local f
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if fgrep_q '(Command::new|process::Command)' "$f" && fgrep_q '"(curl|wget|sh|bash|powershell|cmd)"|(curl|wget)' "$f"; then
      high "" "$f" "build.rs がビルド時に外部コマンド（curl/wget/シェル）を起動"
    elif fgrep_q '(Command::new|process::Command)' "$f"; then
      medium "" "$f" "build.rs がビルド時にプロセスを起動"
    elif fgrep_q '(include_bytes!|include_str!)' "$f"; then
      low "" "$f" "build.rs がバイナリ/文字列を埋め込み（include_bytes!/include_str!）"
    fi
  done < <(files_named '^build\.rs$')
  files_named '\.go$' | grep_l '^//go:generate[[:space:]]+(curl|wget|bash|sh[[:space:]]+-c)' | while IFS= read -r f; do
    [ -n "$f" ] && high "" "$f" "//go:generate で外部コマンド（curl/bash/sh -c）"
  done
  local -a safeb; mapfile -t safeb < <(read_ioc '.build_hooks.py_build_backend_safe')
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    local be
    be="$(grep -E '^[[:space:]]*build-backend[[:space:]]*=' "$f" 2>/dev/null | head -n1 | sed -E 's/.*=[[:space:]]*["'"'"']([^"'"'"']+)["'"'"'].*/\1/')"
    [ -n "$be" ] || continue
    printf '%s\n' "${safeb[@]}" | grep -q -x -F -- "$be" || medium "" "$f" "pyproject.toml の build-backend が既知安全リスト外（$be）"
    fgrep_q '^[[:space:]]*backend-path[[:space:]]*=' "$f" && high "" "$f" "pyproject.toml の backend-path でリポジトリ内ビルドバックエンドを使用"
  done < <(files_named '^pyproject\.toml$')
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    fgrep_q 'cmdclass' "$f" || continue
    if fgrep_q '(urllib|requests\.|subprocess|os\.system|socket|b64decode|exec\()' "$f"; then
      high "" "$f" "setup.py の cmdclass に通信/実行処理（インストール時実行）"
    else
      medium "" "$f" "setup.py が cmdclass を上書き（インストール時に任意コード）"
    fi
  done < <(files_named '^setup\.py$')
  return 0
}

# §28 コンテナ署名
check_s28() {
  log_section "§28" "コンテナ署名"
  local f
  local builds_images=0 verifies=0
  files_path '(/\.github/workflows/[^/]+\.ya?ml|\.gitlab-ci\.yml|/Jenkinsfile|\.sh)$' | grep_l '(docker[[:space:]]+push|docker/build-push-action|buildah[[:space:]]+push|ko[[:space:]]+publish)' | grep -q . && builds_images=1
  files_path '(\.ya?ml|\.sh|/Makefile|/Jenkinsfile)$' | grep_l 'cosign[[:space:]]+verify' | grep -q . && verifies=1
  [ "$builds_images" -eq 1 ] && [ "$verifies" -eq 0 ] && medium "" "$ROOT" "コンテナイメージを公開しているが cosign verify の実行が見当たりません"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    grep -E -i '^[[:space:]]*FROM[[:space:]]+' "$f" 2>/dev/null | awk '{print $2}' | grep -v -E '^(scratch|\$)' | grep -q -v '@sha256:' \
      && medium "" "$f" "FROM がダイジェスト固定されていません（@sha256: 推奨）"
  done < <(files_named '^(Dockerfile.*|.*\.dockerfile)$')
  while IFS= read -r f; do [ -n "$f" ] && high "" "$f" "cosign 秘密鍵（cosign.key）がリポジトリ内にあります"; done < <(files_named '^cosign\.key$')
  files_named '\.ya?ml$' | grep_l 'imagePullPolicy:[[:space:]]*Always' | while IFS= read -r f; do
    [ -n "$f" ] || continue
    fgrep_q 'image:[[:space:]]*[^[:space:]]+@sha256:' "$f" || medium "" "$f" "imagePullPolicy: Always かつダイジェスト未固定（可変タグを毎回取得）"
  done
  return 0
}

# Kubernetes マニフェスト
k8s_manifests() {
  local f
  files_named '\.ya?ml$' | grep_l '^kind:[[:space:]]*[A-Z]' | while IFS= read -r f; do
    [ -n "$f" ] && grep -q '^apiVersion:' "$f" 2>/dev/null && printf '%s\n' "$f"
  done
  return 0
}

# §29 K8s・クラウド
check_s29() {
  log_section "§29" "K8s・クラウド"
  local f
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    fgrep_q 'automountServiceAccountToken:[[:space:]]*true' "$f" && medium "" "$f" "automountServiceAccountToken: true"
    fgrep_q 'failurePolicy:[[:space:]]*Ignore' "$f" && medium "" "$f" "Admission Webhook の failurePolicy: Ignore（検査バイパス）"
    fgrep_q '^[[:space:]]*hostPath:' "$f" && high "" "$f" "hostPath ボリューム（ノードのファイルシステムに到達）"
    fgrep_q '169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200' "$f" && medium "" "$f" "マニフェストがメタデータサービスを参照"
  done < <(k8s_manifests)
  return 0
}

# §30 macOS 永続化
plist_label() { grep -A1 -E '<key>Label</key>' "$1" 2>/dev/null | grep -o -E '<string>[^<]*</string>' | head -n1 | sed -E 's#</?string>##g'; }
check_s30() {
  log_section "§30" "macOS永続化"
  local f lb
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    lb="$(plist_label "$f")"
    if [ -n "$lb" ] && ! printf '%s' "$lb" | grep -q '\.'; then
      high "" "$f" "LaunchAgent/Daemon の Label がランダム文字列様（$lb）"
    fi
    fgrep_q '<string>(/tmp/|/private/tmp/|/Users/Shared/|/var/tmp/)|<string>[^<]*/\.[^/<]+/[^<]*</string>' "$f" && high "" "$f" "LaunchAgent/Daemon が一時領域/隠しディレクトリのプログラムを起動"
    fgrep_q '(curl|osascript|base64|python[0-9.]* -c|bash -c)' "$f" && high "" "$f" "LaunchAgent/Daemon の ProgramArguments に通信/スクリプト実行"
  done < <(files_path '/Library/(LaunchAgents|LaunchDaemons)/[^/]+\.plist$|/LaunchAgents/[^/]+\.plist$'
           if [ "$OS_NAME" = "Darwin" ]; then ls "$HOME_DIR"/Library/LaunchAgents/*.plist 2>/dev/null; host_enabled && ls /Library/LaunchAgents/*.plist /Library/LaunchDaemons/*.plist 2>/dev/null; fi)
  while IFS= read -r f; do
    [ -n "$f" ] && fgrep_q 'DYLD_INSERT_LIBRARIES' "$f" && high "" "$f" "DYLD_INSERT_LIBRARIES の設定（ライブラリインジェクション）"
  done < <(home_rc_paths)
  [ -f "$HOME_DIR/Library/Preferences/com.apple.security.plist" ] && info "" "$HOME_DIR/Library/Preferences/com.apple.security.plist" "com.apple.security.plist が存在（改変の有無を確認）"
  if [ "$OS_NAME" = "Darwin" ] && host_enabled; then
    local v
    v="$(safe_probe launchctl getenv DYLD_INSERT_LIBRARIES)"
    [ -n "$v" ] && critical "" "launchctl:DYLD_INSERT_LIBRARIES" "launchctl setenv で DYLD_INSERT_LIBRARIES が設定されています"
    safe_probe launchctl list | awk 'NR>1 {print $3}' | grep -v -E '\.' | grep -v -E '^-$' | while IFS= read -r lb; do
      high "" "launchctl:$lb" "launchctl list にランダム Label 様のジョブ（$lb）"
    done
    local li
    li="$(safe_probe osascript -e 'tell application "System Events" to get name of every login item')"
    [ -n "$li" ] && info "" "loginitems" "ログイン項目: $li"
    safe_probe profiles show -type configuration | grep -q -i 'attribute' && medium "" "profiles" "構成プロファイルがインストールされています（profiles show で確認）"
  fi
  intel_host_files
  return 0
}

# §31 Linux 永続化（/etc/ld.so.preload / LD_PRELOAD / systemd user / autostart / cron.d）
check_s31() {
  log_section "§31" "Linux永続化"
  local f
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    [ -s "$f" ] && grep -q -v -E '^[[:space:]]*(#|$)' "$f" && critical "ebpf-rootkit" "$f" "ld.so.preload が空ではありません（全プロセスへのライブラリ注入）"
  done < <(files_named '^ld\.so\.preload$'; host_enabled && [ -f /etc/ld.so.preload ] && echo /etc/ld.so.preload)
  while IFS= read -r f; do
    [ -n "$f" ] && fgrep_q '(^|[[:space:]]|export[[:space:]]+)LD_PRELOAD=' "$f" && high "ebpf-rootkit" "$f" "シェル設定で LD_PRELOAD を設定（ライブラリ注入による永続化）"
  done < <(home_rc_paths; files_named '^(\.bashrc|\.zshrc|\.profile|\.bash_profile|environment)$'; host_enabled && [ -f /etc/environment ] && echo /etc/environment)
  local unit
  while IFS= read -r unit; do
    [ -n "$unit" ] || continue
    if fgrep_q '^[[:space:]]*(ExecStart|ExecStartPre|Exec)[[:space:]]*=[^#]*(/tmp/|/dev/shm/|/var/tmp/|/\.[^/[:space:]]+/|curl|wget|base64|bash -c|sh -c)' "$unit"; then
      high "ebpf-rootkit" "$unit" "自動起動エントリが一時領域/隠しパス/通信コマンドを実行"
    elif fgrep_q 'Environment=.*LD_PRELOAD' "$unit"; then
      high "ebpf-rootkit" "$unit" "systemd ユニットで LD_PRELOAD を設定"
    else
      info "" "$unit" "ユーザー自動起動エントリ"
    fi
  done < <(files_path '/systemd/user/[^/]+\.service$|/autostart/[^/]+\.desktop$'
           ls "$HOME_DIR"/.config/systemd/user/*.service "$HOME_DIR"/.config/autostart/*.desktop 2>/dev/null)
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    grep -v '^[[:space:]]*#' "$f" 2>/dev/null | grep -q -E '(curl|wget|base64|/tmp/|/dev/shm/|nc )' && high "ebpf-rootkit" "$f" "cron.d エントリが通信/一時領域を実行"
  done < <(files_path '/cron\.d/[^/]+$'; host_enabled && ls /etc/cron.d/* 2>/dev/null)
  return 0
}

# §32 AI モデル供給網（pickle 系拡張子 / weights_only=False / --extra-index-url）
check_s32() {
  log_section "§32" "AIモデル供給網"
  local f
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    case "$f" in */node_modules/*|*/.git/*) continue ;; esac
    medium "hf-supply-chain" "$f" "pickle 系モデル形式（${f##*.}）。読み込み時に任意コード実行の可能性（.safetensors 推奨）"
  done < <(files_named '\.(pkl|pickle|pt|pth)$' | grep -v -E '\.pth$' ; files_named '\.bin$' | grep -E '/(models?|checkpoints?|weights)/|pytorch_model[^/]*\.bin$')
  files_path '\.(py|ipynb)$' | grep_l 'weights_only[[:space:]]*=[[:space:]]*False' | while IFS= read -r f; do
    [ -n "$f" ] && high "hf-supply-chain" "$f" "torch.load(..., weights_only=False)（pickle の任意コード実行）"
  done
  files_named '^(requirements.*\.txt|constraints.*\.txt|pip\.conf|\.pip\.conf)$' | grep_l '(--extra-index-url|extra-index-url)' | while IFS= read -r f; do
    [ -n "$f" ] && high "hf-supply-chain" "$f" "--extra-index-url（PyPI 以外の索引との依存関係混乱）"
  done
  return 0
}

# §33 シェルフック
check_s33() {
  log_section "§33" "シェルフック"
  local f
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    fgrep_q '(^|[[:space:]])PROMPT_COMMAND=' "$f" && { fgrep_q 'PROMPT_COMMAND=.*(curl|wget|base64|nc |/dev/tcp)' "$f" && high "" "$f" "PROMPT_COMMAND に通信/難読化コマンド" || medium "" "$f" "PROMPT_COMMAND が設定されています（プロンプト表示ごとに実行）"; }
    fgrep_q '^[[:space:]]*(function[[:space:]]+)?precmd[[:space:]]*\(\)' "$f" && fgrep_q '(curl|wget|base64|nc |/dev/tcp)' "$f" && high "" "$f" "zsh precmd フック定義と通信コマンドが共存"
    fgrep_q '^[[:space:]]*(function[[:space:]]+)?command_not_found_hand?le?[[:space:]]*\(\)' "$f" && medium "" "$f" "command_not_found_handle を再定義（タイプミスでコード実行）"
  done < <(home_rc_paths)
  for f in "$HOME_DIR/.bash_logout" "$HOME_DIR/.zlogout"; do
    [ -f "$f" ] || continue
    if fgrep_q '(curl|wget|rm -rf|base64|nc )' "$f"; then high "" "$f" "ログアウトフックに通信/破壊的コマンド"
    elif grep -v -E '^[[:space:]]*(#|$|clear|if|fi|then|\[)' "$f" | grep -q .; then medium "" "$f" "ログアウトフックにコマンドがあります"
    fi
  done
  return 0
}

# §34 ネットワーク設定（proxy / hosts / ProxyCommand）
check_s34() {
  log_section "§34" "ネットワーク設定"
  local f
  for f in "$HOME_DIR/.curlrc" "$HOME_DIR/.wgetrc"; do
    [ -f "$f" ] && fgrep_q -i '^[[:space:]]*-?-?(proxy|https?_proxy|use_proxy)[[:space:]]*[=[:space:]]' "$f" && high "" "$f" "curl/wget のプロキシ設定（通信傍受の可能性）"
  done
  # npm config get proxy は npm（node ランタイム）を起動するため使用せず、.npmrc を静的に読む
  for f in "$HOME_DIR/.npmrc" "$ROOT/.npmrc"; do
    [ -f "$f" ] && fgrep_q -i '^[[:space:]]*(https-)?proxy[[:space:]]*=' "$f" && high "" "$f" "npm のプロキシ設定（レジストリ通信の傍受）"
  done
  local -a ph; mapfile -t ph < <(read_ioc '.protected_hosts')
  local hostsf
  for hostsf in $(host_enabled && echo /etc/hosts) $(files_named '^hosts$' | tr '\n' ' '); do
    [ -f "$hostsf" ] || continue
    local h
    for h in "${ph[@]}"; do
      grep -v '^[[:space:]]*#' "$hostsf" | grep -q -E "[[:space:]]$(printf '%s' "$h" | sed 's/\./\\./g')([[:space:]]|$)" \
        && high "" "$hostsf" "hosts でレジストリ/GitHub（$h）を上書き"
    done
    network_iocs | cut -f1 | grep -v -E '^[0-9.]+$' | while IFS= read -r h; do
      grep -v '^[[:space:]]*#' "$hostsf" | grep -q -F -- "$h" && critical "" "$hostsf" "hosts に C2 ドメイン（$h）"
    done
  done
  for f in "$HOME_DIR/.ssh/config"; do
    [ -f "$f" ] && fgrep_q -i '^[[:space:]]*ProxyCommand[[:space:]].*(\bnc\b|ncat|netcat|socat)' "$f" && high "" "$f" "ssh ProxyCommand に nc/socat（通信中継）"
  done
  return 0
}

# §35 アンチフォレンジック（auditd / 履歴消去 / 履歴シンボリックリンク / mtime 逆行）
check_s35() {
  log_section "§35" "アンチフォレンジック"
  log_info "noatime 環境の判定は §13 を参照（noatime ではハニーポットが無効）"
  if host_enabled; then
    if [ "$OS_NAME" = "Linux" ] && command -v systemctl >/dev/null 2>&1; then
      local st; st="$(systemctl is-active auditd 2>/dev/null)"
      [ "$st" = "active" ] && safe "auditd 稼働中" || medium "" "auditd" "auditd が稼働していません（${st:-unknown}）"
    elif [ "$OS_NAME" = "Darwin" ]; then
      [ -f /etc/security/audit_control ] || medium "" "/etc/security/audit_control" "OpenBSM の設定がありません"
    fi
  fi
  local f
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    fgrep_q '(HISTFILE=/dev/null|HISTSIZE=0([^0-9]|$)|HISTFILESIZE=0([^0-9]|$)|SAVEHIST=0([^0-9]|$)|unset[[:space:]]+HISTFILE)' "$f" && high "" "$f" "シェル履歴の無効化（HISTFILE=/dev/null / HISTSIZE=0）"
  done < <(home_rc_paths)
  for f in "$HOME_DIR/.bash_history" "$HOME_DIR/.zsh_history"; do
    [ -L "$f" ] && [ "$(readlink -- "$f")" = "/dev/null" ] && high "" "$f" "履歴ファイルが /dev/null へのシンボリックリンク"
  done
  # mtime 逆行（birth time が取得できる環境のみ）
  local b m
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    b="$(stat_birth "$f")"; m="$(stat_mtime "$f")"
    [ -n "$b" ] && [ -n "$m" ] && [ "$b" != "0" ] && [ "$b" != "-" ] || continue
    [ "$m" -lt $(( b - 86400 )) ] 2>/dev/null && medium "" "$f" "mtime が作成時刻より1日以上古い（タイムスタンプ改ざん疑い）"
  done < <(files_path '\.(sh|py|js|mjs|cjs|rb|pl|pth|so|dylib)$|/(\.bashrc|\.zshrc|\.profile|\.envrc)$' | head -n 5000; home_rc_paths)
  return 0
}

# =============================================================================
# §36〜§48（v5.0/v5.1）
# =============================================================================

# §36 HF 供給網
check_s36() {
  log_section "§36" "HF供給網"
  local f
  files_path '\.(py|ipynb|json|ya?ml)$' | grep_l 'trust_remote_code["'"'"']?[[:space:]]*[=:][[:space:]]*(True|true)' | while IFS= read -r f; do
    [ -n "$f" ] && high "hf-supply-chain" "$f" "trust_remote_code=True（リモートのモデル/データセットコードを実行）"
  done
  files_named '\.py$' | grep_l '(GeneratorBasedBuilder|DatasetBuilder|datasets\.load_dataset|_split_generators)' | grep_l '(subprocess|os\.system|eval\(|exec\(|__import__)' | while IFS= read -r f; do
    [ -n "$f" ] && high "hf-dataset-poisoning" "$f" "データセットローダースクリプトに subprocess/eval/exec（コード実行経路）"
  done
  files_named '\.py$' | grep_l '(def __reduce__|pickle\.loads?\(|dill\.loads?\(|cloudpickle\.loads?\()' | while IFS= read -r f; do
    [ -n "$f" ] || continue
    case "$f" in */site-packages/*|*/dist-packages/*|*/node_modules/*) continue ;; esac
    medium "hf-supply-chain" "$f" "pickle 系デシリアライズ（__reduce__/pickle.loads/dill）"
  done
  files_named '\.(ya?ml|json|jinja2?|j2)$' | grep_l '\{\{[^}]*(__class__|__globals__|__import__|cycler|lipsum|os\.popen)' | while IFS= read -r f; do
    [ -n "$f" ] && high "hf-dataset-poisoning" "$f" "データセット設定にテンプレートインジェクション様の式"
  done
  build_deps
  awk -F'\t' '$1=="pypi" && $2=="lerobot" {print $3"\t"$4}' "$DEPS_TSV" | tsv_us | while IFS="$US" read -r v f; do
    high "hf-lerobot-rce" "$f" "lerobot ${v}: CVE-2026-25874（CVSS 9.8）の修正版を確認してください（ioc に修正版未定義）"
  done
  while IFS= read -r f; do [ -n "$f" ] && critical "hf-supply-chain" "$f" "transformers.pyz（正規配布物ではない偽装アーカイブ）"; done < <(files_named '^transformers\.pyz$')
  return 0
}

# §37 MCP レジストリ
check_s37() {
  log_section "§37" "MCPレジストリ"
  local f
  files_path '\.(json|ya?ml|toml|js|ts|py|md)$' | grep_lF 'MCP-POISON' | while IFS= read -r f; do
    [ -n "$f" ] && high "mcp-poisoning" "$f" "SPECTER MCP-POISON の痕跡"
  done
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    fgrep_q 'host\.docker\.internal' "$f" && high "mcp-poisoning" "$f" "MCP 設定が host.docker.internal を参照（コンテナからホストへの横移動）"
    fgrep_q '64:ff9b(:1)?::' "$f" && high "mcp-poisoning" "$f" "MCP 設定が IPv6 NAT64 レンジ（64:ff9b::/96, 64:ff9b:1::/48）を参照（SSRF フィルタ回避）"
  done < <(mcp_config_files | sort -u; files_path '/(tool|server|mcp)\.json$')
  build_deps
  if [ "$HAVE_JQ" -eq 1 ]; then
    local ce cp cf cid
    while IFS="$US" read -r cid ce cp cf; do
      awk -F'\t' -v e="$ce" -v n="$cp" '$1==e && $2==n {print $3"\t"$4}' "$DEPS_TSV" | sort -u | tsv_us | while IFS="$US" read -r v f; do
        [ -n "$v" ] && version_lt "$v" "$cf" && high "mcp-poisoning" "$f" "${cp}@${v} は ${cid} の影響範囲（修正版 ${cf}）"
      done
    done < <(jq -r '.mcp_poisoning.mcp_cves[] | select(.package and .fixed) | [.id, .eco, .package, .fixed] | @tsv' "$IOC_FILE" | tsv_us)
  fi
  awk -F'\t' '
    ($1=="npm" && ($2=="@modelcontextprotocol/sdk" || $2 ~ /appium.*mcp|mcp.*appium/ || $2=="@modelcontextprotocol/server-everything" || $2 ~ /gitlab-mcp/)) ||
    ($1=="pypi" && ($2=="mcp" || $2=="mcp-server-fetch" || $2=="fastmcp")) ||
    ($1=="go" && $2 ~ /stacklok\/toolhive/) {print $2"\t"$3"\t"$4}' "$DEPS_TSV" | sort -u | tsv_us | while IFS="$US" read -r n v f; do
    medium "mcp-poisoning" "$f" "MCP 関連依存 ${n}@${v}: CVE-2026-104850/104120/111767/59951/61559/52869/58500, GO-2026-5996/6002 の該当可否を確認（ioc に修正版未定義）"
  done
  return 0
}

# §38 CI/CD 大量植え付け
check_s38() {
  log_section "§38" "CI/CD大量植え付け"
  local f n
  local th; th="$(read_ioc '.github_actions.secrets_ref_threshold')"; th="${th:-10}"
  if [ -d "$ROOT/.git" ]; then
    local since; since="$(( $(now_epoch) - 30*86400 ))"
    local out
    if out="$(safe_git log --no-textconv --no-ext-diff --diff-filter=A --since="@$since" --name-only --format='' -- .github/workflows)"; then
      printf '%s\n' "$out" | sort -u | while IFS= read -r n; do
        [ -n "$n" ] && medium "ghostaction-oct2026" "$ROOT/$n" "直近30日に新規追加されたワークフロー（作成者・目的を監査）"
      done
    else
      record_error "§38" "git_log_failed"
    fi
  fi
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    n="$(grep -o -E 'secrets\.[A-Za-z0-9_]+' "$f" 2>/dev/null | sort -u | wc -l | tr -d ' ')"
    [ "${n:-0}" -gt "$th" ] && high "ghostaction-oct2026" "$f" "ワークフローが ${n} 種類の secrets.* を参照（閾値 ${th} 超、一括収集の疑い）"
    fgrep_q 'toJSON\([[:space:]]*secrets[[:space:]]*\)' "$f" && critical "ghostaction-oct2026" "$f" "toJSON(secrets) で全シークレットを展開"
    fgrep_q '(^|[[:space:];|])(env|printenv)[[:space:]]*(\||>|$)' "$f" && high "ghostaction-oct2026" "$f" "ワークフローで環境変数を一括出力（env/printenv）"
  done < <(workflow_files)
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    grep -q -E '^[[:space:]]*-?[[:space:]]*remote:[[:space:]]*["'"'"']?https?://' "$f" && high "ghostaction-oct2026" "$f" "GitLab CI が remote include（外部 URL の再利用コンポーネント）"
    if grep -q -E '^[[:space:]]*-?[[:space:]]*project:' "$f" && ! grep -q -E 'ref:[[:space:]]*["'"'"']?[0-9a-f]{40}' "$f"; then
      medium "ghostaction-oct2026" "$f" "GitLab CI の project include が SHA 固定されていません"
    fi
  done < <(files_named '^\.gitlab-ci\.ya?ml$')
  files_path '/\.circleci/config\.ya?ml$' | grep_l '^[[:space:]]+[A-Za-z0-9_-]+:[[:space:]]*[A-Za-z0-9_-]+/[A-Za-z0-9_-]+@(volatile|dev:)' | while IFS= read -r f; do
    [ -n "$f" ] && high "ghostaction-oct2026" "$f" "CircleCI orb が volatile/dev 参照"
  done
  files_named '^Jenkinsfile$' | grep_l "@Library\\(['\"][^'\"@]+['\"]\\)" | while IFS= read -r f; do
    [ -n "$f" ] && medium "ghostaction-oct2026" "$f" "Jenkins 共有ライブラリがバージョン未固定"
  done
  # GhostAction: 偽装フォント（拡張子はフォントだがマジックバイトが不一致）
  local magic
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    magic="$(od -An -tx1 -N4 -- "$f" 2>/dev/null | tr -d ' \n')"
    case "$magic" in 00010000|4f54544f|74727565|74797031|774f4646|774f4632|"") ;;
      *) high "ghostaction-oct2026" "$f" "フォント拡張子だが中身がフォントではない（偽装フォント）" ;;
    esac
  done < <(files_named '\.(ttf|otf|woff2?)$')
  files_path '/\.github/' | grep -E '\.(ttf|otf|woff2?)$' | while IFS= read -r f; do
    medium "ghostaction-oct2026" "$f" ".github/ 配下にフォントファイル（GhostAction の隠蔽手口）"
  done
  intel_workflow_strings
  return 0
}

# §39 メタデータ SSRF
check_s39() {
  log_section "§39" "メタデータSSRF"
  local f
  k8s_manifests >"$TMP_DIR/k8s.lst"
  files_path '\.(py|js|mjs|cjs|ts|go|rb|php|java|sh|tf|json|toml|ini|conf|env)$|/\.env[^/]*$' | grep -v -x -F -f "$TMP_DIR/k8s.lst" \
    | grep_l '169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254' | while IFS= read -r f; do
    [ -n "$f" ] && medium "" "$f" "クラウドメタデータサービスへの参照（SSRF 経由の認証情報窃取に注意）"
  done
  while IFS= read -r f; do
    [ -n "$f" ] && fgrep_q 'AWS_EC2_METADATA_SERVICE_ENDPOINT[[:space:]]*=' "$f" && high "" "$f" "AWS_EC2_METADATA_SERVICE_ENDPOINT の上書き（メタデータ通信の横取り）"
  done < <(home_rc_paths; files_named '^\.env(\.[A-Za-z0-9_-]+)?$|\.sh$')
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    fgrep_q 'http_tokens[[:space:]]*=[[:space:]]*"optional"' "$f" && high "" "$f" "IMDSv1 が有効（http_tokens = \"optional\"）"
    if fgrep_q 'resource[[:space:]]+"aws_(instance|launch_template)"' "$f" && ! fgrep_q 'http_tokens[[:space:]]*=[[:space:]]*"required"' "$f"; then
      medium "" "$f" "EC2 で IMDSv2 が強制されていません（metadata_options.http_tokens = \"required\" を推奨）"
    fi
  done < <(files_named '\.tf$')
  if host_enabled && command -v lsof >/dev/null 2>&1; then
    lsof -nP -i -a -c dockerd -c containerd 2>/dev/null | grep -E '169\.254\.169\.254|100\.100\.100\.200' | awk '{print $2}' | sort -u | while IFS= read -r pid; do
      high "" "/proc/$pid" "dockerd/containerd からメタデータサービスへの接続（pid $pid）"
    done
  fi
  return 0
}

# §40 eBPF / LD_PRELOAD ルートキット
check_s40() {
  log_section "§40" "eBPF/LD_PRELOAD"
  local f
  files_path '\.(sh|bash|py|c|go|rs|service)$' | grep_l '(>>?[[:space:]]*/etc/ld\.so\.preload|bpftool[[:space:]]+prog[[:space:]]+(load|attach)|bpf_probe_write_user|BPF_PROG_LOAD|insmod[[:space:]]|modprobe[[:space:]]+-f)' | while IFS= read -r f; do
    [ -n "$f" ] && high "ebpf-rootkit" "$f" "ld.so.preload 書き込み / eBPF プログラムのロード / カーネルモジュール挿入"
  done
  files_path '\.(sh|bash|py|c|go|rs|service|conf)$|/[^/.]+$' | grep_l '(quasar[ _-]?linux|\bQLNX\b|linkpro|voidlink)' -i | while IFS= read -r f; do
    [ -n "$f" ] && critical "ebpf-rootkit" "$f" "Quasar Linux (QLNX) / LinkPro / VoidLink の痕跡"
  done
  host_enabled || return 0
  [ "$OS_NAME" = "Linux" ] || return 0
  local t
  t="$(cat /proc/sys/kernel/tainted 2>/dev/null)"
  if [ -n "$t" ] && [ "$t" != "0" ]; then
    if [ $(( t & 4096 )) -ne 0 ] || [ $(( t & 8192 )) -ne 0 ]; then
      high "ebpf-rootkit" "/proc/sys/kernel/tainted" "カーネルが out-of-tree/未署名モジュールで汚染されています（tainted=$t）"
    else
      info "" "/proc/sys/kernel/tainted" "カーネル taint フラグ: $t"
    fi
  fi
  if [ -d /sys/fs/bpf ]; then
    local pinned; pinned="$(find /sys/fs/bpf -mindepth 1 -maxdepth 3 2>/dev/null | head -n 50)"
    [ -n "$pinned" ] && medium "ebpf-rootkit" "/sys/fs/bpf" "ピン留めされた BPF オブジェクトがあります（正規ツール由来か確認）"
  fi
  local bp; bp="$(safe_probe bpftool prog list)"
  if [ -n "$bp" ]; then
    printf '%s' "$bp" | grep -q -E '(getdents|tcp4_seq_show|tcp6_seq_show|udp4_seq_show|sys_bpf|kill)' && high "ebpf-rootkit" "bpftool:prog" "ファイル/ソケット/プロセス隠蔽系フックの eBPF プログラム"
  fi
  if [ -r /proc/modules ]; then
    awk '$NF ~ /\(O/ || $0 ~ /\(OE\)|\(E\)/ {print $1}' /proc/modules 2>/dev/null | while IFS= read -r m; do
      medium "ebpf-rootkit" "/proc/modules" "out-of-tree/未署名カーネルモジュール: $m"
    done
  fi
  local u
  for u in /etc/systemd/system/*.service "$HOME_DIR"/.config/systemd/user/*.service; do
    [ -f "$u" ] || continue
    case "${u##*/}" in systemd-*|dbus-*|udev*|journald*|networkd*|resolved*)
      grep -E '^[[:space:]]*ExecStart=' "$u" | grep -q -v -E '=(/usr)?/lib/systemd/|=/usr/bin/(dbus|udevadm)|=/usr/sbin/' \
        && high "ebpf-rootkit" "$u" "systemd 標準ユニット名の偽装（ExecStart が標準パス外）" ;;
    esac
  done
  return 0
}

# §41 AI アシスタント
check_s41() {
  log_section "§41" "AIアシスタント"
  local f v
  for f in "/Applications/Cursor.app/Contents/Info.plist" "$HOME_DIR/Applications/Cursor.app/Contents/Info.plist" "/usr/share/cursor/resources/app/package.json" "/opt/Cursor/resources/app/package.json"; do
    [ -f "$f" ] || continue
    case "$f" in /Applications/*|/usr/*|/opt/*) host_enabled || continue ;; esac
    if [[ "$f" == *.plist ]]; then v="$(grep -A1 'CFBundleShortVersionString' "$f" | grep -o -E '[0-9]+(\.[0-9]+)+' | head -n1)"
    else v="$(grep -m1 -E '"version"' "$f" | grep -o -E '[0-9]+(\.[0-9]+)+')"; fi
    [ -n "$v" ] || continue
    if version_lt "$v" "2.5"; then
      critical "" "$f" "Cursor ${v} は CVE-2026-26268（CVSS 9.9、2.5 で修正）と CVE-2026-50548（DuneSlide、CVSS 9.8、3.0 で修正）の影響範囲"
    elif version_lt "$v" "3.0"; then
      critical "" "$f" "Cursor ${v} は CVE-2026-50548（DuneSlide、CVSS 9.8）の影響範囲（3.0 で修正）"
    fi
  done
  local d cfix; cfix="$(read_ioc '.runtime_minimums.copilot_chat')"
  for d in "$HOME_DIR"/.vscode/extensions/github.copilot-chat-[0-9]*; do
    [ -d "$d" ] || continue
    v="${d##*/github.copilot-chat-}"; v="${v%%-*}"
    [ -n "$cfix" ] && version_lt "$v" "$cfix" && high "" "$d" "GitHub Copilot Chat 拡張 ${v} は CVE-2025-62222（コマンドインジェクション、CVSS 8.8）の影響範囲（修正版 ${cfix}）"
  done
  for d in "$HOME_DIR"/Library/Application\ Support/JetBrains/*/plugins/github-copilot-intellij "$HOME_DIR"/.local/share/JetBrains/*/github-copilot-intellij; do
    [ -d "$d" ] && medium "" "$d" "JetBrains 版 Copilot: CVE-2026-50510 の修正版適用を確認"
  done
  [ -f "$ROOT/git.exe" ] && critical "" "$ROOT/git.exe" "リポジトリルートの git.exe（Windows で IDE/エージェントが自動実行する未パッチ zero-day）"
  local has_instr=0 has_hook=0 has_agent_hook=0
  files_named '^(\.cursorrules|CLAUDE\.md|copilot-instructions\.md)$' | grep -q . && has_instr=1
  [ -d "$ROOT/.git/hooks" ] && find "$ROOT/.git/hooks" -type f ! -name '*.sample' 2>/dev/null | grep -q . && has_hook=1
  files_path '/\.(claude|cursor|gemini)/(settings(\.local)?|hooks)\.json$' | grep_l '"hooks"' | grep -q . && has_agent_hook=1
  if [ "$has_instr" -eq 1 ] && [ $(( has_hook + has_agent_hook )) -ge 1 ]; then
    high "" "$ROOT" "AI 指示ファイルと Git/エージェントフックが同居（間接プロンプトインジェクション→フック実行の連鎖）"
  fi
  while IFS= read -r f; do [ -n "$f" ] && info "" "$f" "Cursor MCP 設定（§17 で検査）"; done < <(files_path '/\.cursor/mcp\.json$')
  return 0
}

# §42 拡張所有権移転（既知名・バージョン間のパーミッション昇格）
check_s42() {
  log_section "§42" "拡張所有権移転"
  local f name
  local -a known; mapfile -t known < <(if [ "$HAVE_JQ" -eq 1 ]; then jq -r '.browser_extensions.known_campaigns[].name' "$IOC_FILE"; else grep -o -E '"name": "[^"]+"' "$IOC_FILE" | sed -n '/known_campaigns/,$p' | sed -E 's/"name": "//; s/"$//'; fi)
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    name="$(grep -o -E '"name"[[:space:]]*:[[:space:]]*"[^"]+"' "$f" | head -n1 | sed -E 's/.*:[[:space:]]*"//; s/"$//')"
    local k
    for k in "${known[@]}"; do
      [ -n "$name" ] || break
      case "$k" in *"$name"*) high "" "$f" "既知の悪性/侵害拡張と同名（$name）" ; break ;; esac
    done
  done < <(extension_manifests | sort -u; ls "$HOME_DIR"/.vscode/extensions/*/package.json 2>/dev/null)
  # 同一拡張 ID の複数バージョン間で危険パーミッションが増えていないか
  local idd
  local -a dperm; mapfile -t dperm < <(read_ioc '.browser_extensions.dangerous_permissions'; echo '<all_urls>')
  extension_manifests | sort -u | sed -E 's#/[^/]+/manifest\.json$##' | sort | uniq -d | while IFS= read -r idd; do
    local prev="" cur="" vdir first=1 p added
    while IFS= read -r vdir; do
      [ -f "$idd/$vdir/manifest.json" ] || continue
      cur="$(for p in "${dperm[@]}"; do grep -q -F "\"$p\"" "$idd/$vdir/manifest.json" && printf '%s\n' "$p"; done | sort)"
      if [ "$first" -eq 0 ]; then
        added="$(comm -13 <(printf '%s\n' "$prev" | grep . | sort) <(printf '%s\n' "$cur" | grep . | sort) | tr '\n' ' ')"
        [ -n "${added// /}" ] && high "" "$idd/$vdir/manifest.json" "拡張の更新で危険パーミッションが追加（${added% }）。所有権移転型の悪性アップデート疑い"
      fi
      prev="$cur"; first=0
    done < <(ls -1 "$idd" 2>/dev/null | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n)
  done
  intel_extensions
  return 0
}

# §43 Sigstore / SLSA
check_s43() {
  log_section "§43" "Sigstore/SLSA"
  local f v
  local -a cmins; mapfile -t cmins < <(read_ioc '.runtime_minimums.cosign')
  if host_enabled; then
    v="$(safe_probe cosign version 2>&1 | grep -o -E 'v?[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"
    [ -n "$v" ] && version_branch_vulnerable "${v#v}" "${cmins[@]}" && high "" "$(command -v cosign)" "cosign ${v} は修正版（${cmins[*]}）未満（GHSA-fx35-mq7g-6g98 / CVE-2026-39395 / CVE-2026-22703。3.1.3 は仕様書の値で未確認）"
  fi
  files_path '/\.github/workflows/[^/]+\.ya?ml$' | grep_l 'cosign-release:[[:space:]]*["'"'"']?v?[0-9]' | while IFS= read -r f; do
    v="$(grep -o -E 'cosign-release:[[:space:]]*["'"'"']?v?[0-9]+\.[0-9]+\.[0-9]+' "$f" | head -n1 | grep -o -E '[0-9]+\.[0-9]+\.[0-9]+')"
    [ -n "$v" ] && version_branch_vulnerable "$v" "${cmins[@]}" && high "" "$f" "cosign-installer の cosign ${v} は修正版（${cmins[*]}）未満"
  done
  # cosign verify / verify-blob の identity 指定漏れ（--key 使用時は対象外）
  local line
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    awk '/cosign[[:space:]]+verify(-blob|-attestation|-blob-attestation)?([[:space:]]|$)/ { s=$0; while (s ~ /\\$/ && (getline n) > 0) { sub(/\\$/,"",s); s=s n } print s }' "$f" | while IFS= read -r line; do
      printf '%s' "$line" | grep -q -E -- '--key([[:space:]=]|$)' && continue
      printf '%s' "$line" | grep -q -E -- '--certificate-identity(-regexp)?[[:space:]=]' || { high "" "$f" "cosign verify に --certificate-identity がありません（任意の署名者を受理）"; continue; }
      printf '%s' "$line" | grep -q -E -- '--certificate-oidc-issuer(-regexp)?[[:space:]=]' || high "" "$f" "cosign verify に --certificate-oidc-issuer がありません"
    done
  done < <(files_path '\.(sh|bash|ya?ml|mk)$|/Makefile$|/Jenkinsfile$' | grep_l 'cosign[[:space:]]+verify')
  files_path '\.(sh|bash|ya?ml)$' | grep_l 'rekor-cli[[:space:]]+(get|search)' | while IFS= read -r f; do
    [ -n "$f" ] || continue
    fgrep_q '(cosign[[:space:]]+verify|slsa-verifier[[:space:]]+verify)' "$f" || medium "" "$f" "Rekor エントリの存在確認のみで検証扱い（署名・証明書の検証なし）"
  done
  files_path '\.(sh|bash|ya?ml)$' | grep_l 'slsa-verifier[[:space:]]+verify-' | while IFS= read -r f; do
    [ -n "$f" ] || continue
    fgrep_q -- '--source-uri' "$f" || high "" "$f" "slsa-verifier に --source-uri がありません（来歴の出所を検証していない）"
  done
  local ver
  while IFS=$'\t' read -r ver f; do [ -n "$ver" ] && version_lt "${ver#v}" "1.8.5" && high "" "$f" "Fulcio ${ver} は CVE-2026-22772（metaRegex SSRF）の影響範囲（<1.8.5）"; done < <(detect_service_version 'projectsigstore/fulcio')
  build_deps
  awk -F'\t' '$1=="gem" && $2=="sigstore" {print $3"\t"$4}' "$DEPS_TSV" | tsv_us | while IFS="$US" read -r v f; do
    version_lt "$v" "0.2.3" && high "" "$f" "sigstore-ruby ${v} は CVE-2026-31830（検証バイパス）の影響範囲（<0.2.3）"
  done
  return 0
}

# §44 決済 SDK タイポスクワット（レーベンシュタイン距離）
check_s44() {
  log_section "§44" "決済SDKタイポ"
  build_deps
  read_ioc '.payment_sdks' >"$TMP_DIR/pay.lst"
  awk -F'\t' 'NR==FNR { sdk[$0]=1; next }
    function lev(a,b,   la,lb,i,j,c,d,x,y,z) {
      la=length(a); lb=length(b)
      for(i=0;i<=la;i++) d[i,0]=i; for(j=0;j<=lb;j++) d[0,j]=j
      for(i=1;i<=la;i++) for(j=1;j<=lb;j++) {
        c=(substr(a,i,1)==substr(b,j,1))?0:1
        x=d[i-1,j]+1; y=d[i,j-1]+1; z=d[i-1,j-1]+c
        d[i,j]=(x<y?(x<z?x:z):(y<z?y:z))
      }
      return d[la,lb] }
    ($1=="npm" || $1=="pypi") && !($2 in sdk) && length($2)>=5 {
      for (s in sdk) { if (length(s)<5) continue; dd=lev($2,s); if (dd>=1 && dd<=2) { print dd "\t" $2 "\t" s "\t" $4; break } } }' "$TMP_DIR/pay.lst" "$DEPS_TSV" \
  | sort -u | while IFS=$'\t' read -r dd n s f; do
      if [ "$dd" = "1" ]; then high "typosquat-payment-sdk" "$f" "決済SDK ${s} の近似名パッケージ ${n}（距離 1）"
      else medium "typosquat-payment-sdk" "$f" "決済SDK ${s} の近似名パッケージ ${n}（距離 2）"; fi
    done
  return 0
}

# §45 インフォスティーラー
check_s45() {
  log_section "§45" "インフォスティーラー"
  local f n
  files_path '\.(m?js|cjs|ts|py|sh)$' | grep_l '(bun\.sh/install|oven-sh/bun/releases/download|bun-(linux|darwin)-(x64|aarch64)\.zip)' | while IFS= read -r f; do
    [ -n "$f" ] && high "teampcp-mini-shai-hulud" "$f" "Bun バイナリの取得処理（Bun 経由ペイロード）"
  done
  files_path '\.(m?js|cjs|ts|py|sh)$' | grep_l 'api\.github\.com/(user/repos|repos/[^"'"'"' ]+/(contents|git/(blobs|trees|refs))|gists)' \
    | grep_l '(POST|PUT|PATCH|method:[[:space:]]*["'"'"'](POST|PUT)|requests\.(post|put)|-X[[:space:]]*(POST|PUT))' | while IFS= read -r f; do
    [ -n "$f" ] && high "post-shaihulud" "$f" "GitHub API への書き込み（リポジトリ作成/コンテンツ書き込み/Gist）による持ち出し疑い"
  done
  local now; now="$(now_epoch)"
  for f in "$HOME_DIR/.config/gh/hosts.yml" "$HOME_DIR/.npmrc" "$HOME_DIR/.pypirc"; do
    [ -f "$f" ] || continue
    local m; m="$(stat_mtime "$f")"
    [ -n "$m" ] && [ $(( now - m )) -lt $(( 7*86400 )) ] && medium "post-shaihulud" "$f" "認証情報ファイルが直近7日以内に更新（身に覚えがなければトークン差し替え/窃取を疑う）"
  done
  local -a envs; mapfile -t envs < <(read_ioc '.ci_env_vars')
  local th; th="$(read_ioc '.ci_env_harvest_threshold')"; th="${th:-20}"
  printf '%s\n' "${envs[@]}" >"$TMP_DIR/cienv.pat"
  files_path '\.(m?js|cjs|ts|py|sh|go|rs)$' | tr '\n' '\0' | xargs -0 grep -l -I -F -f "$TMP_DIR/cienv.pat" -- /dev/null 2>/dev/null | while IFS= read -r f; do
    [ -n "$f" ] || continue
    n="$(grep -o -F -w -f "$TMP_DIR/cienv.pat" -- "$f" 2>/dev/null | sort -u | wc -l | tr -d ' ')"
    [ "${n:-0}" -ge "$th" ] && high "post-shaihulud" "$f" "CI/クラウド認証情報の環境変数を ${n} 種類参照（一括収集の疑い）"
  done
  files_path '\.(m?js|cjs|ts|py|sh)$' | grep_l '(shai[-_ ]?hulud|miasma|sckit|iron-?worm|PRIVCOLLECT|letters9813)' -i | while IFS= read -r f; do
    [ -n "$f" ] && high "post-shaihulud" "$f" "インフォスティーラー系統（Mini Shai-Hulud/Miasma/sckit/IronWorm）の識別子"
  done
  return 0
}

# §46 Git 来歴
check_s46() {
  log_section "§46" "Git来歴"
  [ -d "$ROOT/.git" ] || { log_info "Git リポジトリではありません"; return 0; }
  local out n
  # %G? は署名を検証する（gpg.*.program を起動しうる）ため使わない。署名の有無は生のヘッダ（gpgsig）で判定
  out="$(safe_git log -n 200 --no-textconv --no-ext-diff --format='%at%x09%ae%x09%H')" || { record_error "§46" "git_log_failed"; return 0; }
  [ -n "$out" ] || return 0
  local raw
  raw="$(safe_git log -n 200 --no-textconv --no-ext-diff --pretty=raw)" || { record_error "§46" "git_log_failed"; return 0; }
  local now; now="$(now_epoch)"
  printf '%s\n' "$out" | awk -F'\t' -v now="$now" '$1 >= now-86400 {c[$2]++} END {for (a in c) if (c[a] > 50) print a "\t" c[a]}' | while IFS=$'\t' read -r _ n; do
    medium "" "$ROOT/.git" "直近24時間に同一作者で ${n} コミット（短時間大量コミット）"
  done
  local total unsigned
  total="$(printf '%s\n' "$out" | wc -l | tr -d ' ')"
  # pretty=raw: "commit <sha>" で区切られ、ヘッダは行頭から、本文は 4 字下げ（本文中の偽ヘッダとは区別できる）
  local signed_list
  signed_list="$(printf '%s\n' "$raw" | awk '
      /^commit [0-9a-f]+/ { c=$2; inhdr=1; next }
      inhdr && /^$/ { inhdr=0; next }
      inhdr && /^gpgsig(-sha256)? / { print c }' | sort -u)"
  unsigned="$(printf '%s\n' "$out" | ZES_SL="$signed_list" awk -F'\t' 'BEGIN { n=split(ENVIRON["ZES_SL"], a, "\n"); for (i=1; i<=n; i++) s[a[i]]=1 } !($3 in s)' | wc -l | tr -d ' ')"
  [ "$total" -gt 0 ] && info "" "$ROOT/.git" "直近 ${total} コミット中 ${unsigned} 件が署名なし"
  safe_git for-each-ref --format='%(refname)' refs/notes | while IFS= read -r n; do
    [ -n "$n" ] && medium "" "$ROOT/.git" "Git notes（${n}）が存在（来歴情報の書き換えに注意）"
  done
  safe_git for-each-ref --format='%(refname)%09%(objecttype)%09%(*objecttype)' refs/tags | while IFS=$'\t' read -r n t pt; do
    if [ "$t" = "tag" ] && [ -n "$pt" ] && [ "$pt" != "commit" ]; then high "" "$ROOT/.git" "タグ ${n} がコミット以外（${pt}）を指しています"
    elif [ "$t" != "tag" ] && [ "$t" != "commit" ]; then high "" "$ROOT/.git" "タグ ${n} がコミット以外（${t}）を指しています"; fi
  done
  if [ -f "$ROOT/.gitmodules" ]; then
    local origin_host
    origin_host="$(safe_git config --get remote.origin.url | sed -E 's#^[a-z+]+://([^@/]+@)?##; s#^[^@]+@##; s#[:/].*##')"
    grep -E '^[[:space:]]*url[[:space:]]*=' "$ROOT/.gitmodules" | sed -E 's/.*=[[:space:]]*//' | while IFS= read -r n; do
      case "$n" in
        http://*|git://*) high "" "$ROOT/.gitmodules" "サブモジュールが平文プロトコル（$n）" ;;
        ./*|../*) ;;
        *) local h; h="$(printf '%s' "$n" | sed -E 's#^[a-z+]+://([^@/]+@)?##; s#^[^@]+@##; s#[:/].*##')"
           [ -n "$origin_host" ] && [ "$h" != "$origin_host" ] && medium "" "$ROOT/.gitmodules" "サブモジュールが外部ホスト（$h）を参照" ;;
      esac
    done
  fi
  return 0
}

# §47 認証情報フロー
check_s47() {
  log_section "§47" "認証情報フロー"
  local f
  for f in "$HOME_DIR/.bash_history" "$HOME_DIR/.zsh_history" "$HOME_DIR/.local/share/fish/fish_history"; do
    [ -f "$f" ] && [ ! -L "$f" ] || continue
    fgrep_q 'export[[:space:]]+[A-Za-z0-9_]*(_TOKEN|_KEY|_SECRET|PASSWORD)=' "$f" && high "" "$f" "シェル履歴に export *_TOKEN=/*_KEY=/*_SECRET=（平文の認証情報。ローテーション対象）"
  done
  local now; now="$(now_epoch)"
  for f in "$HOME_DIR/.aws/sso/cache" "$HOME_DIR/.azure" "$HOME_DIR/.config/gcloud/credentials.db"; do
    [ -e "$f" ] || continue
    local m; m="$(stat_mtime "$f")"
    [ -n "$m" ] && [ $(( now - m )) -lt 86400 ] && info "" "$f" "クラウド認証キャッシュが直近24時間に更新"
  done
  files_named '^(\.env\.ci|\.envrc)$' | grep_l '(_TOKEN|_KEY|_SECRET|PASSWORD)[[:space:]]*=[[:space:]]*[^[:space:]$]' | while IFS= read -r f; do
    [ -n "$f" ] && high "" "$f" "CI/direnv 用ファイルに平文の認証情報"
  done
  tr '\n' '\0' <"$FILES_LIST" | xargs -0 grep -l -I -E -e '(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}|gho_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36})' -- /dev/null 2>/dev/null | while IFS= read -r f; do
    [ -n "$f" ] && critical "" "$f" "GitHub トークン（ghp_/github_pat_ 等）がファイルに含まれます（内容は出力しません。即時失効）"
  done
  return 0
}

# §48 SBOM 整合性
check_s48() {
  log_section "§48" "SBOM整合性"
  local f
  local -a sboms; mapfile -t sboms < <(files_named '(\.spdx\.json|\.cdx\.json|^bom\.json$|^sbom\.json$|\.spdx$|^cyclonedx\.json$)')
  [ "${#sboms[@]}" -gt 0 ] && [ -n "${sboms[0]}" ] || { log_info "SBOM が見つかりません"; return 0; }
  if [ "$HAVE_JQ" -ne 1 ]; then record_error "§48" "jq_unavailable"; return 0; fi
  build_deps
  local has_prov=0 has_verify=0
  files_named '(\.intoto\.jsonl|^provenance\.json$|\.provenance\.json$|\.layout$)' | grep -q . && has_prov=1
  files_path '\.(ya?ml|sh)$' | grep_l '(cosign[[:space:]]+verify-attestation|slsa-verifier[[:space:]]+verify-artifact|in-toto-verify)' | grep -q . && has_verify=1
  for f in "${sboms[@]}"; do
    [ -n "$f" ] || continue
    local dir; dir="$(dirname -- "$f")"
    jq -r '(((.components // [])[]? | [(.name // ""), ((.version // "") | tostring)]), ((.packages // [])[]? | [(.name // ""), ((.versionInfo // "") | tostring)])) | @tsv' "$f" 2>/dev/null | sort -u >"$TMP_DIR/sbom.tsv" \
      || { record_error "§48" "sbom_parse_failed:$f"; continue; }
    local created; created="$(jq -r '.metadata.timestamp // .creationInfo.created // empty' "$f" 2>/dev/null)"
    # 同ディレクトリのロックファイル由来の依存（npm/pypi）と突合
    awk -F'\t' -v d="$dir/" 'index($4, d)==1 && ($1=="npm" || $1=="pypi") && $4 !~ /\/node_modules\/.*\/package\.json$/ {print $2"\t"$3}' "$DEPS_TSV" | sort -u >"$TMP_DIR/lock.tsv"
    if [ -s "$TMP_DIR/lock.tsv" ]; then
      local missing mism
      missing="$(cut -f1 "$TMP_DIR/lock.tsv" | sort -u | comm -23 - <(cut -f1 "$TMP_DIR/sbom.tsv" | sort -u) | wc -l | tr -d ' ')"
      mism="$(join -t $'\t' <(sort -t $'\t' -k1,1 "$TMP_DIR/lock.tsv") <(sort -t $'\t' -k1,1 "$TMP_DIR/sbom.tsv") | awk -F'\t' '$2!=$3' | wc -l | tr -d ' ')"
      if [ "$missing" -gt 0 ] || [ "$mism" -gt 0 ]; then
        high "" "$f" "SBOM とロックファイルが不一致（SBOM 未記載 ${missing} 件 / バージョン相違 ${mism} 件）"
      else
        safe "SBOM とロックファイルが一致（$f）"
      fi
      if [ -n "$created" ]; then
        local lf lm
        while IFS= read -r lf; do
          lm="$(stat_mtime "$lf")"
          local ce; ce="$(date -u -d "$created" +%s 2>/dev/null || date -u -j -f '%Y-%m-%dT%H:%M:%SZ' "$created" +%s 2>/dev/null)"
          [ -n "$ce" ] && [ -n "$lm" ] && [ "$lm" -gt $(( ce + 60 )) ] && { medium "" "$f" "SBOM 生成日時（$created）がロックファイル更新より古い"; break; }
        done < <(awk -F'\t' -v d="$dir/" 'index($4,d)==1 {print $4}' "$DEPS_TSV" | sort -u)
      fi
    fi
  done
  [ "$has_prov" -eq 0 ] && [ "$has_verify" -eq 0 ] && medium "" "$ROOT" "SBOM はあるが provenance / in-toto レイアウト / attestation 検証（cosign verify-attestation・slsa-verifier）が見当たりません"
  return 0
}

# =============================================================================
# §49 SkillPact 統合 check_skillpact
#   - 契約ファイルは jq で JSON としてパースするのみ。スキル本体・スクリプトは実行しない
#   - L2 テスト記録はファイルの存在と SHA-256 のみ確認（再実行しない）
#   - L3 署名は署名ファイルの存在のみ確認（cosign verify 等は実行しない）。信頼判定・重大度の軽減には使わない
#
#   契約スキーマ（SkillPact v0.8）の一次情報は確認できていないため、以下のフィールドを寛容に読む:
#     schema_version, name, version, author|publisher, description, level,
#     effects[]（"exec" / "exec:any" / "network:host" / {"effect":"network","scope":"host"}）,
#     decision（allow|ask|deny）, operations[]{name, effects[], reversible, decision},
#     l2{record, sha256} | tests.l2{record, sha256} | l2_record, signature{file} | signature_file
#   ポリシー: default, rules[]{effect, decision}, never_auto_allow_any（配列 or true）
# =============================================================================

SP_EFFECTS_NORM='def norm: if type=="string" then . elif type=="object" then ((.effect // .type // .name // "") + (if (.scope // null) then ":" + (.scope|tostring) else "" end)) else tostring end;'

# 前バージョン比較用: ROOT 内とキャッシュ内の全契約を author<TAB>name<TAB>version<TAB>path で列挙
sp_contract_index() {
  local f
  {
    local cf
    while IFS= read -r cf; do
      files_path "/$(printf '%s' "$cf" | sed 's/\./\\./g')\$"
    done < <(read_ioc '.skillpact.contract_filenames')
    if [ -n "$SKILLPACT_CACHE" ] && [ -d "$SKILLPACT_CACHE" ]; then
      find "$SKILLPACT_CACHE" -type f -name '*.json' 2>/dev/null
    fi
  } | sort -u | while IFS= read -r f; do
    [ -n "$f" ] || continue
    jq -r --arg p "$f" 'select(type=="object") | [(.author // .publisher // ""), (.name // ""), (.version // ""), $p] | @tsv' "$f" 2>/dev/null
  done
}

# スキルディレクトリ（SKILL.md または契約ファイルを含むディレクトリ）
sp_skill_dirs() {
  {
    files_named '^SKILL\.md$' | while IFS= read -r f; do dirname -- "$f"; done
    files_named '^skill\.contract\.json$' | while IFS= read -r f; do dirname -- "$f"; done
    files_path '/\.skillpact/contract\.json$' | while IFS= read -r f; do dirname -- "$(dirname -- "$f")"; done
  } | sort -u
}

# スキル直下のファイル（入れ子スキルの配下は除外）
sp_skill_files() {
  local dir="$1"
  awk -v d="$dir/" 'index($0, d)==1' "$FILES_LIST" | while IFS= read -r f; do
    local rel="${f#"$dir"/}" sub="$dir" part nested=0
    while [[ "$rel" == */* ]]; do
      part="${rel%%/*}"; sub="$sub/$part"; rel="${rel#*/}"
      if [ -f "$sub/SKILL.md" ] || [ -f "$sub/skill.contract.json" ] || [ -f "$sub/.skillpact/contract.json" ]; then
        [ "$sub" != "$dir/.skillpact" ] && { nested=1; break; }
      fi
    done
    [ "$nested" -eq 0 ] && printf '%s\n' "$f"
  done
}

# 実態抽出用テキスト（コードスコープ）と prose を分離して一時ファイルに書き出す（出力はしない）
sp_extract() {
  local dir="$1" code="$2" prose="$3" tools="$4"
  : >"$code"; : >"$prose"; : >"$tools"
  local f base ext
  local -a sexts; mapfile -t sexts < <(read_ioc '.skillpact.script_extensions')
  local sre; sre="$(printf '%s|' "${sexts[@]}" | sed 's/|$//')"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    base="${f##*/}"; ext="${base##*.}"
    case "$f" in
      */.skillpact/*|*/skill.contract.json|*/policy-v0.8.json|*.sig|*.bundle|*/l2-test-record.json) continue ;;
    esac
    if [[ "$base" =~ \.md$ ]]; then
      awk -v code="$code" -v prose="$prose" -v tools="$tools" '
        NR==1 && /^---[[:space:]]*$/ { fm=1; next }
        fm && /^---[[:space:]]*$/ { fm=0; next }
        fm { if ($0 ~ /^allowed-tools:/) print $0 >> tools; print $0 >> code; next }
        /^[[:space:]]*(```|~~~)/ {
          if (!infence) { lang=$0; sub(/^[[:space:]]*(```|~~~)[[:space:]]*/,"",lang); sub(/[[:space:]{].*/,"",lang); print "#ZES-FENCE " tolower(lang) >> code }
          infence=!infence; next }
        infence { print $0 >> code; next }
        { print $0 >> prose }' "$f"
    elif [[ "$ext" =~ ^($sre)$ ]] || head -c 2 -- "$f" 2>/dev/null | grep -q '^#!'; then
      printf '#ZES-SCRIPT %s\n' "$base" >>"$code"
      cat -- "$f" >>"$code"; printf '\n' >>"$code"
    elif [[ "$base" =~ \.(json|ya?ml|toml|ini|cfg)$ ]]; then
      cat -- "$f" >>"$code"; printf '\n' >>"$code"
    fi
  done < <(sp_skill_files "$dir")
}

check_skillpact() {
  log_section "§49" "SkillPact統合"
  if [ "$HAVE_JQ" -ne 1 ]; then record_error "§49" "jq_unavailable"; return 0; fi
  local -a cfn pfn l2fn sigfn; mapfile -t cfn < <(read_ioc '.skillpact.contract_filenames')
  mapfile -t pfn < <(read_ioc '.skillpact.policy_files'); mapfile -t l2fn < <(read_ioc '.skillpact.l2_record_filenames')
  mapfile -t sigfn < <(read_ioc '.skillpact.signature_filenames')
  local threshold; threshold="$(jq -r '.skillpact.trust_model.diff_anomaly_detection.threshold // 0.3' "$IOC_FILE")"
  local schema_ok; schema_ok="$(jq -c '.skillpact.schema_versions' "$IOC_FILE")"
  local risk_flags; risk_flags="$(jq -c '.skillpact.risk_flags' "$IOC_FILE")"
  sp_contract_index >"$TMP_DIR/sp_index.tsv"
  local dir n_skills=0
  while IFS= read -r dir; do
    [ -n "$dir" ] || continue
    n_skills=$((n_skills + 1))
    local cpath="" c
    for c in "${cfn[@]}"; do [ -f "$dir/$c" ] && [ ! -L "$dir/$c" ] && { cpath="$dir/$c"; break; }; done
    local code="$TMP_DIR/sp_code" prose="$TMP_DIR/sp_prose" tools="$TMP_DIR/sp_tools"
    sp_extract "$dir" "$code" "$prose" "$tools"

    # --- 実態エフェクト（静的解析。§2/§7/§15/§17 と同じ「パスのみ・内容非出力」方針） ---
    local -a observed=(read)
    local eff
    for eff in exec network write secrets spend; do
      local pats; pats="$(jq -r --arg e "$eff" '.skillpact.observed_effect_patterns[$e] // [] | join("|")' "$IOC_FILE")"
      if [ -n "$pats" ] && grep -q -E -- "$pats" "$code" 2>/dev/null; then observed+=("$eff"); continue; fi
      case "$eff" in
        exec) grep -q '^#ZES-SCRIPT ' "$code" && { observed+=(exec); continue; }
              grep -q -E '^#ZES-FENCE (bash|sh|shell|zsh|fish|console|shell-session|powershell|ps1|pwsh|cmd|bat|python|python3|py|js|javascript|node|mjs|ts|typescript|ruby|rb|perl|php)$' "$code" && { observed+=(exec); continue; }
              grep -q -E '(^|[^A-Za-z])Bash([^A-Za-z]|$)' "$tools" && observed+=(exec) ;;
        network) grep -q -E '(WebFetch|WebSearch)' "$tools" && observed+=(network) ;;
        write) grep -q -E '(^|[^A-Za-z])(Write|Edit|MultiEdit|NotebookEdit)([^A-Za-z]|$)' "$tools" && observed+=(write) ;;
      esac
    done
    local destructive=0 persistence=0 m
    while IFS= read -r m; do
      [ -n "$m" ] || continue
      local re
      if [[ "$m" == *' | '* ]]; then re="$(printf '%s' "${m%% | *}" | sed 's/[.[\*^$]/\\&/g')[^|\n]*\|[[:space:]]*$(printf '%s' "${m##* | }" | sed 's/[.[\*^$]/\\&/g')"
      else re="$(printf '%s' "$m" | sed 's/[.[\*^$]/\\&/g; s/ /[[:space:]]+/g')"; fi
      grep -q -i -E -- "$re" "$code" 2>/dev/null && destructive=1
    done < <(read_ioc '.skillpact.destructive_markers')
    while IFS= read -r m; do
      [ -n "$m" ] || continue
      local re
      if [ "$m" = "registry run" ]; then re='registry[[:space:]]+run|CurrentVersion\\Run|reg[[:space:]]+add[^\n]*\\Run'
      else re="$(printf '%s' "$m" | sed 's/[.[\*^$]/\\&/g; s/ /[[:space:]]+/g')"; fi
      grep -q -i -E -- "$re" "$code" 2>/dev/null && persistence=1
    done < <(read_ioc '.skillpact.persistence_markers')
    [ "$persistence" -eq 1 ] && observed+=(write)
    [ "$destructive" -eq 1 ] && observed+=(exec write)
    local observed_json; observed_json="$(printf '%s\n' "${observed[@]}" | sort -u | jq -R . | jq -s -c 'sort_by(. as $e | ["exec","network","write","read","secrets","spend"] | index($e))')"

    if [ -z "$cpath" ]; then
      local sp
      sp="$(jq -n -c --argjson obs "$observed_json" '{contract_path:null, contract_version:null, level:null, signed:false, author:null,
             declared_effects:[], observed_effects:$obs, policy_decision:null, l2_tested:false,
             divergence:($obs - ["read"]), diff_anomaly:false}')"
      high "skillpact-undeclared" "$dir" "SkillPact 契約ファイルが存在しません（実態: $(printf '%s' "$observed_json" | jq -r 'join(",")')）" "$sp"
      continue
    fi
    if ! jq -e 'type=="object"' "$cpath" >/dev/null 2>&1; then
      local sp
      sp="$(jq -n -c --arg cp "$cpath" --argjson obs "$observed_json" '{contract_path:$cp, contract_version:null, level:null, signed:false, author:null,
             declared_effects:[], observed_effects:$obs, policy_decision:null, l2_tested:false, divergence:($obs - ["read"]), diff_anomaly:false}')"
      high "skillpact-undeclared" "$cpath" "SkillPact 契約ファイルが JSON オブジェクトとして解析できません（未宣言として扱う）" "$sp"
      continue
    fi

    # --- 契約の読み取り（JSON パースのみ） ---
    local cver level author cname cversion decl_tokens decl_bases cdecision
    cver="$(jq -r '.schema_version // empty | tostring' "$cpath")"
    level="$(jq -r '.level // empty | tostring' "$cpath")"
    author="$(jq -r '(.author // .publisher // empty) | if type=="object" then (.name // .id // tojson) else tostring end' "$cpath")"
    cname="$(jq -r '.name // empty | tostring' "$cpath")"
    cversion="$(jq -r '.version // empty | tostring' "$cpath")"
    decl_tokens="$(jq -c "$SP_EFFECTS_NORM"' [(.effects // [])[] | norm] + [(.operations // [])[] | (.effects // [])[] | norm] | map(select(length>0)) | unique' "$cpath")"
    decl_bases="$(printf '%s' "$decl_tokens" | jq -c 'map(split(":")[0]) | unique | sort_by(. as $e | ["exec","network","write","read","secrets","spend","persist","longrun"] | index($e) // 99)')"
    cdecision="$(jq -r '.decision // .policy_decision // empty | tostring' "$cpath")"

    # --- ポリシー評価 ---
    local ppath="" p
    for p in "${pfn[@]}"; do
      if [ -f "$dir/$p" ]; then ppath="$dir/$p"; break; fi
      if [ -f "$ROOT/$p" ]; then ppath="$ROOT/$p"; break; fi
    done
    local pdecision="$cdecision" policy_violation=""
    if [ -n "$ppath" ]; then
      if jq -e 'type=="object"' "$ppath" >/dev/null 2>&1; then
        local evald
        evald="$(jq -r --argjson toks "$decl_tokens" '
          def rank: if .=="deny" then 3 elif .=="ask" then 2 elif .=="allow" then 1 else 0 end;
          . as $p |
          [ $toks[] as $t | ( [ ($p.rules // [])[] | select(.effect == $t or .effect == ($t|split(":")[0]) or .effect == (($t|split(":")[0]) + ":any")) | .decision ] | first ) // ($p.default // "ask") ]
          | if length==0 then ($p.default // "ask") else (max_by(rank)) end' "$ppath" 2>/dev/null)"
        [ -n "$pdecision" ] || pdecision="$evald"
        policy_violation="$(jq -r --argjson toks "$decl_tokens" --argjson rf "$risk_flags" '
          . as $p |
          (if ($p.never_auto_allow_any | type) == "array" then $p.never_auto_allow_any else $rf end) as $never |
          def covers($flag; $tok): ($tok == $flag) or (($flag|endswith(":any")) and (($tok|split(":")[0]) == ($flag|split(":")[0])));
          [ ($p.rules // [])[] | select(.decision == "allow") | .effect as $e | $never[] | select(. == $e or covers(.; $e)) ] as $explicit |
          [ $toks[] as $t | $never[] as $f | select(covers($f; $t)) |
            ( [ ($p.rules // [])[] | select(.effect == $t or .effect == ($t|split(":")[0]) or .effect == (($t|split(":")[0]) + ":any")) | .decision ] | first ) // ($p.default // "ask")
            | select(. == "allow") | $f ] as $implicit |
          ($explicit + $implicit) | unique | join(",")' "$ppath" 2>/dev/null)"
      else
        record_error "§49" "policy_parse_failed:$ppath"
      fi
    fi
    if [ -n "$pdecision" ] && ! jq -e --arg d "$pdecision" '.skillpact.decision_values | index($d)' "$IOC_FILE" >/dev/null 2>&1; then
      medium "skillpact-divergence" "$cpath" "ポリシー決定の値が decision_values（allow/ask/deny）外: $pdecision"
    fi
    # 契約自体が allow を宣言し、リスクフラグを含む場合もポリシー違反として扱う
    local contract_violation=""
    if [ -z "$policy_violation" ] && [ "$cdecision" = "allow" ]; then
      contract_violation="$(jq -r --argjson toks "$decl_tokens" '. as $rf | [ $toks[] as $t | $rf[] | select(. == $t or ((endswith(":any")) and (($t|split(":")[0]) == (split(":")[0])) and (($t|split(":")[1] // "any") == "any"))) ] | unique | join(",")' <<<"$risk_flags")"
    fi

    # --- L2 テスト記録（存在と SHA-256 のみ） ---
    local l2_tested=false l2rec l2hash l2bad=""
    l2rec="$(jq -r '(.l2.record // .tests.l2.record // .l2_record // empty) | tostring' "$cpath")"
    l2hash="$(jq -r '(.l2.sha256 // .tests.l2.sha256 // .l2_sha256 // empty) | tostring | ltrimstr("sha256:")' "$cpath")"
    local cand=""
    if [ -n "$l2rec" ]; then
      case "$l2rec" in /*|*..*) l2bad="記録パスがスキル外を指しています" ;; *) [ -f "$dir/$l2rec" ] && cand="$dir/$l2rec" ;; esac
    else
      for p in "${l2fn[@]}"; do [ -f "$dir/$p" ] && { cand="$dir/$p"; break; }; done
    fi
    if [ -n "$cand" ]; then
      if [ -n "$l2hash" ] && [ "$(sha256_file "$cand")" != "$l2hash" ]; then l2bad="記録の SHA-256 が契約と不一致"
      else l2_tested=true; fi
    fi

    # --- L3 署名（存在のみ。信頼判定には使わない） ---
    local signed=false sigf
    sigf="$(jq -r '(.signature.file // .signature_file // empty) | tostring' "$cpath")"
    if [ -n "$sigf" ]; then case "$sigf" in /*|*..*) ;; *) [ -f "$dir/$sigf" ] && signed=true ;; esac; fi
    if [ "$signed" = false ]; then for p in "${sigfn[@]}"; do [ -f "$dir/$p" ] && { signed=true; break; }; done; fi

    # --- 乖離（実態 − 宣言） ---
    local divergence
    divergence="$(jq -n -c --argjson o "$observed_json" --argjson d "$decl_bases" '$o - $d - ["read"] | map(select(. as $e | ["exec","network","secrets","write","spend"] | index($e)))')"
    if [ "$persistence" -eq 1 ] && ! printf '%s' "$decl_bases" | jq -e 'index("persist") or index("write")' >/dev/null; then
      divergence="$(printf '%s' "$divergence" | jq -c '. + ["persist"] | unique')"
    fi

    # --- 差分異常（同一 author の前バージョン） ---
    local diff_anomaly=false diff_reason="" prev_path=""
    if [ -n "$author" ] && [ -n "$cname" ] && [ -n "$cversion" ]; then
      local pa pn pv pp best=""
      while IFS="$US" read -r pa pn pv pp; do
        [ "$pa" = "$author" ] && [ "$pn" = "$cname" ] && [ "$pp" != "$cpath" ] && [ -n "$pv" ] || continue
        version_lt "$pv" "$cversion" || continue
        if [ -z "$best" ] || version_lt "$best" "$pv"; then best="$pv"; prev_path="$pp"; fi
      done < <(tsv_us <"$TMP_DIR/sp_index.tsv")
      if [ -n "$prev_path" ]; then
        local prev_tokens
        prev_tokens="$(jq -c "$SP_EFFECTS_NORM"' [(.effects // [])[] | norm] + [(.operations // [])[] | (.effects // [])[] | norm] | map(select(length>0)) | unique' "$prev_path" 2>/dev/null)"
        diff_reason="$(jq -n -r --argjson c "$decl_tokens" --argjson p "${prev_tokens:-[]}" --argjson th "$threshold" '
          def bases: map(split(":")[0]) | unique;
          ($c - $p) as $added | (($c - $p) + ($p - $c) | unique | length) as $delta | (($c + $p) | unique | length) as $union |
          [ (if (($c|bases|index("exec")) and (($p|bases|index("exec"))|not)) then "exec 新規追加" else empty end),
            (if ([$added[] | select(startswith("network"))] | length) > 0 then "network 送信先の新規追加" else empty end),
            (if ([$added[] | select(startswith("secrets"))] | length) > 0 then "secrets スコープ拡大" else empty end),
            (if $union > 0 and ($delta / $union) > $th then "エフェクト差分率 \(($delta * 100 / $union) | floor)% > 閾値 \($th * 100 | floor)%" else empty end)
          ] | join(" / ")')"
        [ -n "$diff_reason" ] && diff_anomaly=true
      fi
    fi

    local sp
    sp="$(jq -n -c --arg cp "$cpath" --arg cv "$cver" --arg lv "$level" --argjson sg "$signed" --arg au "$author" \
          --argjson de "$decl_bases" --argjson ob "$observed_json" --arg pd "$pdecision" --argjson l2 "$l2_tested" \
          --argjson dv "$divergence" --argjson da "$diff_anomaly" '
          {contract_path:$cp, contract_version:(if $cv=="" then null else $cv end), level:(if $lv=="" then null else $lv end),
           signed:$sg, author:(if $au=="" then null else $au end), declared_effects:$de, observed_effects:$ob,
           policy_decision:(if $pd=="" then null else $pd end), l2_tested:$l2, divergence:$dv, diff_anomaly:$da}')"

    # --- 検出ルール（Master Spec §5.7） ---
    if ! printf '%s' "$schema_ok" | jq -e --arg v "$cver" 'index($v)' >/dev/null; then
      medium "skillpact-divergence" "$cpath" "契約の schema_version が ${cver:-未指定}（対応: $(printf '%s' "$schema_ok" | jq -r 'join(",")')）。互換性不明" "$sp"
    fi
    if [ -n "$level" ] && ! jq -e --arg l "$level" '.skillpact.levels | index($l)' "$IOC_FILE" >/dev/null; then
      medium "skillpact-divergence" "$cpath" "契約の level が L1/L2/L3 以外: $level" "$sp"
    fi
    if [ "$level" = "L3" ] && [ "$signed" = false ]; then
      medium "skillpact-divergence" "$cpath" "L3 を宣言しているが署名ファイルが見つかりません" "$sp"
    fi
    if printf '%s' "$decl_bases" | jq -e 'index("exec") or index("network") or index("secrets")' >/dev/null && [ "$l2_tested" = false ]; then
      high "skillpact-divergence" "$cpath" "exec/network/secrets を宣言しているが L2 テスト記録がありません${l2bad:+（$l2bad）}（宣言のみで検証なし）" "$sp"
    fi
    local sigtxt=""; [ "$signed" = true ] && sigtxt="（L3 署名済みでも重大度は下げません）"
    for eff in exec network secrets; do
      if printf '%s' "$divergence" | jq -e --arg e "$eff" 'index($e)' >/dev/null; then
        critical "skillpact-divergence" "$dir" "契約は ${eff} を宣言していないが、実態に ${eff} を検出（宣言: $(printf '%s' "$decl_bases" | jq -r 'join(",")')）${sigtxt}" "$sp"
      fi
    done
    printf '%s' "$divergence" | jq -e 'index("spend")' >/dev/null && high "skillpact-divergence" "$dir" "契約は spend を宣言していないが、実態に課金/決済処理を検出${sigtxt}" "$sp"
    if printf '%s' "$divergence" | jq -e 'index("write")' >/dev/null && [ "$persistence" -eq 0 ]; then
      medium "skillpact-divergence" "$dir" "契約は write を宣言していないが、実態にファイル書き込みを検出${sigtxt}" "$sp"
    fi
    if [ "$destructive" -eq 1 ] && [ "$pdecision" = "allow" ]; then
      high "skillpact-divergence" "$dir" "破壊的操作（destructive_markers）を含むスキルが allow（自動許可）" "$sp"
    fi
    if [ "$persistence" -eq 1 ] && printf '%s' "$divergence" | jq -e 'index("persist")' >/dev/null; then
      critical "skillpact-divergence" "$dir" "永続化操作（persistence_markers）を検出したが、契約に persist/write の宣言がありません${sigtxt}" "$sp"
    fi
    # prose と契約の突合
    local claim
    while IFS=$'\t' read -r claim pats forbids; do
      [ -n "$claim" ] || continue
      if grep -q -i -E -- "$pats" "$prose" 2>/dev/null || jq -r '.description // empty' "$cpath" | grep -q -i -E -- "$pats"; then
        local hit; hit="$(jq -n -r --argjson d "$decl_bases" --argjson f "$forbids" '[$d[] | select(. as $e | $f | index($e))] | join(",")')"
        [ -n "$hit" ] && high "skillpact-divergence" "$cpath" "prose（${claim}）と契約が矛盾: 契約が ${hit} を宣言" "$sp"
      fi
    done < <(jq -r '.skillpact.prose_claims[] | [.claim, (.patterns | join("|")), (.forbids | tojson)] | @tsv' "$IOC_FILE")
    if [ "$diff_anomaly" = true ]; then
      local s3=""; [ "$signed" = true ] && s3="L3 署名済みだが"
      high "skillpact-account-compromise" "$cpath" "${s3}同一作者（${author}）の前バージョン ${best}（$prev_path）から差分異常: ${diff_reason}" "$sp"
    fi
    if [ -n "$policy_violation" ]; then
      high "skillpact-divergence" "$ppath" "ポリシーが never_auto_allow_any を尊重していません（自動許可: ${policy_violation}）" "$sp"
    elif [ -n "$contract_violation" ]; then
      high "skillpact-divergence" "$cpath" "契約の decision: allow が never_auto_allow_any の対象（${contract_violation}）を自動許可しています" "$sp"
    fi
    jq -r --arg pd "$pdecision" '(.operations // [])[] | select(.reversible == false and ((.decision // $pd) == "allow")) | (.name // .id // "unnamed") | tostring' "$cpath" 2>/dev/null \
    | while IFS= read -r m; do
        critical "skillpact-divergence" "$cpath" "reversible: false の操作（${m}）が allow（不可逆操作の自動許可）" "$sp"
      done
    local nf; nf="$(grep -c -F "\"contract_path\":\"$(json_escape "$cpath")\"" "$FINDINGS_FILE" 2>/dev/null)"
    [ "${nf:-0}" -eq 0 ] && safe "SkillPact 契約と実態が一致（$dir）"
  done < <(sp_skill_dirs)
  [ "$n_skills" -eq 0 ] && log_info "スキル（SKILL.md / skill.contract.json）が見つかりません"
  return 0
}
check_s49() { check_skillpact; return 0; }

# =============================================================================
# 実行制御
# =============================================================================
modules_for_mode() {
  case "$1" in
    quick) seq 1 19 ;;
    standard) seq 1 35 ;;
    full) seq 1 49 ;;
    worm) printf '%s\n' 15 18 25 45 ;;
    skillpact) echo 49 ;;
  esac
}

emit_json() {
  local status="$1"
  printf '{"schema_version":"%s","incident_bundle":"%s","scan_started_at":"%s","scan_finished_at":"%s","scan_mode":"%s","status":"%s","findings":[' \
    "$FINDINGS_SCHEMA_VERSION" "$INCIDENT_BUNDLE" "$SCAN_STARTED_AT" "$(iso_now)" "$MODE" "$status"
  paste -sd, "$FINDINGS_FILE" | tr -d '\n'
  printf '],"errors":['
  sort -u "$ERRORS_FILE" | paste -sd, - | tr -d '\n'
  printf ']}\n'
}

main() {
  local ib; ib="$(read_ioc '.incident_bundle')"
  if [ "$ib" != "$INCIDENT_BUNDLE" ]; then
    record_error "core" "incident_bundle_mismatch:${ib:-none}"
  fi
  printf '%sZero-Exec Shield v%s（仕様 v%s）%s  bundle=%s  mode=%s  root=%s  os=%s  jq=%s\n' "$C_CYN" "$ZES_VERSION" "$ZES_SPEC_VERSION" "$C_OFF" "$INCIDENT_BUNDLE" "$MODE" "$ROOT" "$OS_NAME" "$HAVE_JQ" >&3
  [ "$HAVE_JQ" -eq 1 ] || log_info "jq が見つかりません。grep フォールバックで実行します（§48/§49 は未確定扱い）"
  build_inventory
  local n
  for n in $(modules_for_mode "$MODE"); do
    # モジュールはサブシェルで実行し、異常終了（set -u 等）を module_failed として記録する（fail-closed）
    ( "check_s$n" ) || record_error "§$n" "module_failed"
  done
  local status="ok"
  [ -s "$ERRORS_FILE" ] && status="partial"
  [ "$FATAL" -eq 1 ] && status="error"
  local c h m
  c="$(grep -c '"level":"CRITICAL"' "$FINDINGS_FILE")"; h="$(grep -c '"level":"HIGH"' "$FINDINGS_FILE")"; m="$(grep -c '"level":"MEDIUM"' "$FINDINGS_FILE")"
  printf '\n%s== 結果 ==%s CRITICAL=%s HIGH=%s MEDIUM=%s status=%s\n' "$C_CYN" "$C_OFF" "$c" "$h" "$m" "$status" >&3
  if [ "$JSON_OUT" -eq 1 ]; then emit_json "$status"; fi
  [ "$status" = "error" ] && return 2
  return 0
}

main
exit $?
