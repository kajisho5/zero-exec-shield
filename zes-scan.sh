#!/usr/bin/env bash
# =============================================================================
# Zero-Exec Shield (ZES) v5.2 — Core CLI Scanner
# incident_bundle: ZES-2026-OCT-EMERGENCY-V5.2
#
# 絶対原則（Master Spec §1）
#   - Zero-Execution: 検査対象のランタイム・スクリプトを一切起動しない
#   - 静的・受動的解析のみ（find / grep / readlink / stat / curl -sI / ps / lsof / uname / docker --version）
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
#   ZES_GIT_TIMEOUT  §38/§46 の git 呼び出しの打ち切り秒数（既定 60）
# =============================================================================
set -u
set -o pipefail
umask 077
# CDPATH が export されていると相対パスの cd が別ディレクトリへ解決され、パスも標準出力へ出るため無効化
unset CDPATH

ZES_VERSION="0.3.1"      # ソフトウェアの版
ZES_SPEC_VERSION="5.2"   # 準拠する Master Specification の版
INCIDENT_BUNDLE="ZES-2026-OCT-EMERGENCY-V5.2"
FINDINGS_SCHEMA_VERSION="1.1"  # 1.1 は 1.0 に任意の項目（scan_roots・kind・subject・locators・related・evidence）を足したもの

if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
  echo "ZES: Bash 4 以上が必要です（現在: ${BASH_VERSION:-unknown}）。macOS は 'brew install bash' を利用してください。" >&2
  exit 64
fi

export LC_ALL=C

# PATH の無害化（1 段目）: 相対パス・空のエントリ（"." や "::"＝カレントディレクトリ）を外す。
#   検査ルートの中で起動された場合、ルート内の偽 jq / git / coreutils を起動させないため（Zero-Execution）。
#   検査ルートが確定した後（2 段目: zes_sanitize_path_root）に、実パスが検査ルート配下のエントリも外す。
#   ここまでは外部コマンドを一切起動しない（dirname / uname 等も PATH 経由のため、無害化の後に呼ぶ）
PATH_DROPPED=()
zes_sanitize_path() {  # zes_sanitize_path ROOT_OR_EMPTY
  local root="$1" rest="${PATH:-}:" e rp out=""
  while [ -n "$rest" ]; do
    e="${rest%%:*}"; rest="${rest#*:}"
    case "$e" in
      /*) ;;
      *) PATH_DROPPED+=("${e:-<empty>}"); continue ;;
    esac
    if [ -n "$root" ] && [ "$root" != "/" ]; then
      rp="$(cd -P -- "$e" 2>/dev/null && pwd -P)" || continue   # 存在しないディレクトリは何も見つからないので外すだけ
      case "$rp/" in "$root"/*) PATH_DROPPED+=("$e"); continue ;; esac
    fi
    case ":$out:" in *":$e:"*) continue ;; esac
    out="${out:+$out:}$e"
  done
  [ -n "$out" ] || out="/usr/bin:/bin:/usr/sbin:/sbin"
  PATH="$out"
  export PATH
}
zes_sanitize_path ""
hash -r

# スクリプトの場所（dirname を使わずパラメータ展開で求める）
_zes_src="${BASH_SOURCE[0]}"
case "$_zes_src" in */*) _zes_src="${_zes_src%/*}" ;; *) _zes_src="." ;; esac
SCRIPT_DIR="$(cd -- "${_zes_src:-/}" && pwd -P)"
unset _zes_src
IOC_FILE="${ZES_IOC:-$SCRIPT_DIR/rules/ioc.json}"
HOME_DIR="${ZES_HOME:-${HOME:-}}"
HOST_CHECKS="${ZES_HOST_CHECKS:-1}"
OFFLINE="${ZES_OFFLINE:-0}"
SKILLPACT_CACHE="${ZES_SKILLPACT_CACHE:-}"

# 文字列の符号化（JSON / 人間向けログ / ID 計算で同じ正規形を使う）
#   zes_enc STR は次の変数を設定する:
#     ENC_NORM … 正規形。不正な UTF-8 バイトを 1 バイトずつ "\xHH"（4 文字のテキスト）に置き換え、それ以外は元のまま。
#                findings[].id と JSON の値（デコード後）はこの正規形に一致する
#     ENC_JSON … ENC_NORM の JSON 文字列表現（引用符なし）。" と \ をエスケープし、制御文字（U+0000〜U+001F・U+007F）と
#                C1 制御文字（U+0080〜U+009F）を \u00XX にする（往復可能）
#     ENC_TERM … 人間向けログ用。制御文字を \xHH、C1 制御文字を \u00HH で表示（端末エスケープ注入の防止）
#     ENC_BAD  … 不正な UTF-8 バイトを含んでいれば 1
#   印字可能 ASCII のみの文字列は awk を起動せずに処理する
ZES_ENC_AWK='
  BEGIN {
    for (k = 1; k < 256; k++) ord[sprintf("%c", k)] = k
    s = ENVIRON["ZES_ENC"]; n = length(s); nb = ""; js = ""; tm = ""; bad = 0; i = 1
    while (i <= n) {
      c = substr(s, i, 1); b = ord[c]
      if (b < 128) {
        if (b < 32 || b == 127) { h = sprintf("%02x", b); nb = nb "\\x" h; js = js "\\u00" h; tm = tm "\\x" h }
        else if (c == "\\") { nb = nb "\\x5c"; js = js "\\\\"; tm = tm c }
        else if (c == "\"") { nb = nb c; js = js "\\\""; tm = tm c }
        else { nb = nb c; js = js c; tm = tm c }
        i++; continue }
      L = 0; cp = 0
      if (b >= 194 && b <= 223) { L = 2; cp = b - 192 } else if (b >= 224 && b <= 239) { L = 3; cp = b - 224 } else if (b >= 240 && b <= 244) { L = 4; cp = b - 240 }
      ok = (L > 0 && i + L - 1 <= n)
      for (k = 1; ok && k < L; k++) { b2 = ord[substr(s, i + k, 1)]; if (b2 < 128 || b2 > 191) ok = 0; else cp = cp * 64 + b2 - 128 }
      if (ok && ((L == 3 && (cp < 2048 || (cp >= 55296 && cp <= 57343))) || (L == 4 && (cp < 65536 || cp > 1114111)))) ok = 0
      if (!ok) { h = sprintf("%02x", b); nb = nb "\\x5cx" h; js = js "\\\\x" h; tm = tm "\\x" h; bad = 1; i++; continue }
      q = substr(s, i, L); nb = nb q
      if (cp >= 128 && cp <= 159) { js = js sprintf("\\u%04x", cp); tm = tm sprintf("\\u%04x", cp) } else { js = js q; tm = tm q }
      i += L }
    print nb; print js; print tm; print bad }'
zes_enc() {
  local s="$1"
  if [[ "$s" != *[![:print:]]* ]]; then
    ENC_NORM="$s"; ENC_TERM="$s"; ENC_BAD=0
    s="${s//\\/\\\\}"; ENC_JSON="${s//\"/\\\"}"
    return 0
  fi
  local -a enc_r=()
  mapfile -t enc_r < <(ZES_ENC="$s" awk "$ZES_ENC_AWK")
  # 1 行目は %b 形式（全てのバックスラッシュは \xHH）で、制御文字を含む正規形を改行なしで受け渡す
  printf -v ENC_NORM '%b' "${enc_r[0]-}"
  ENC_JSON="${enc_r[1]-}"; ENC_TERM="${enc_r[2]-}"; ENC_BAD="${enc_r[3]:-0}"
}
json_escape() { zes_enc "$1"; printf '%s' "$ENC_JSON"; }
json_str_or_null() { if [ -n "$1" ]; then printf '"%s"' "$(json_escape "$1")"; else printf 'null'; fi; }

ROOT="."
MODE=""
JSON_OUT=0
TARGET_URL=""

USAGE_TEXT='Usage: zes-scan.sh [--quick|--standard|--full|--worm|--skillpact] [--root <dir>] [--url <URL>] [--json]
                   [--skillpact-cache <dir>]

  --root <dir>   検査ルート（既定 "."）
  --full         §1〜49 全実行
  --standard     §1〜35
  --quick        §1〜19（既定）
  --worm         §15/18/25/45 のみ
  --skillpact    §49 のみ
  --url <URL>    §4 の非侵襲URLチェック（Server / X-Powered-By ヘッダのみ取得。HEAD、405/501 時のみ GET、リダイレクト非追従）
  --json         findings.json を標準出力へ（人間向けログは標準エラーへ）
  --skillpact-cache <dir>  §49 差分異常検出用の前バージョン契約キャッシュ

終了コード: 0=完了(status ok/partial) / 2=status error（インベントリを作れない・全モジュール失敗） / 64=引数・環境エラー
'
usage() { printf '%s' "$USAGE_TEXT"; }   # cat を使わない（PATH の 2 段目の無害化より前に呼ばれうるため）

# 引数・環境エラー（exit 64）。値は端末向けに符号化して表示する（制御文字・C1 制御文字による端末エスケープ注入の防止）
arg_error() {  # arg_error MESSAGE [VALUE]
  if [ $# -ge 2 ]; then zes_enc "$2"; printf 'ZES: %s%s\n' "$1" "$ENC_TERM" >&2
  else printf 'ZES: %s\n' "$1" >&2; fi
  exit 64
}

set_mode() {
  if [ -n "$MODE" ] && [ "$MODE" != "$1" ]; then
    arg_error "モード指定が重複しています（$MODE と $1）"
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
    *) usage >&2; arg_error "不明な引数: " "$1" ;;
  esac
done
[ -n "$MODE" ] || MODE="quick"

[ -d "$ROOT" ] || arg_error "--root がディレクトリではありません: " "$ROOT"
case "$ROOT" in -*) ROOT="./$ROOT" ;; esac  # "-" や "-dash" を cd のオプション/OLDPWD と解釈させない
ROOT="$(cd -- "$ROOT" 2>/dev/null && pwd -P)"
{ [ -n "$ROOT" ] && [ -d "$ROOT" ]; } || arg_error "--root を解決できません"
# RP … パス連結用の検査ルート（"/" のときは空。"$RP/x" が "//x" にならないように）
RP="${ROOT%/}"

# PATH の無害化（2 段目）: 実パスが検査ルート配下のエントリを外す（--root / のときはホスト自体が検査対象のため対象外）
zes_sanitize_path "$ROOT"
hash -r
OS_NAME="$(uname -s 2>/dev/null || echo unknown)"

# ホーム（ZES_HOME / HOME）も ROOT と同様に実パスへ正規化する（相対パス・末尾スラッシュ・シンボリックリンクのまま
# 出力すると findings[].path が絶対パスにならない / "//" を含む / 実体と異なるパスになるため）
[ -n "$HOME_DIR" ] || arg_error "ホームディレクトリが未設定です（ZES_HOME または HOME を指定してください）"
[ -d "$HOME_DIR" ] || arg_error "ZES_HOME/HOME がディレクトリではありません: " "$HOME_DIR"
case "$HOME_DIR" in -*) HOME_DIR="./$HOME_DIR" ;; esac
HOME_DIR="$(cd -- "$HOME_DIR" 2>/dev/null && pwd -P)"
{ [ -n "$HOME_DIR" ] && [ -d "$HOME_DIR" ]; } || arg_error "ZES_HOME/HOME を解決できません"

if [ -n "$TARGET_URL" ]; then
  case "$TARGET_URL" in
    http://*|https://*) ;;
    *) arg_error "--url は http:// または https:// のみ受け付けます" ;;
  esac
  case "$TARGET_URL" in
    *[[:space:]\'\"\`\$\;\|\&\<\>]*) arg_error "--url に使用できない文字が含まれています" ;;
  esac
fi

# jq / git は無害化した PATH で 1 度だけ絶対パスに解決し、以降は常にその絶対パスで起動する
#   （関数 jq は "$JQ_BIN" を呼ぶ。git は safe_git の "$GIT_BIN" のみ）
JQ_BIN="$(command -v jq 2>/dev/null)"; case "$JQ_BIN" in /*) ;; *) JQ_BIN="" ;; esac
GIT_BIN="$(command -v git 2>/dev/null)"; case "$GIT_BIN" in /*) ;; *) GIT_BIN="" ;; esac
jq() { "$JQ_BIN" "$@"; }
HAVE_JQ=0
[ -n "$JQ_BIN" ] && HAVE_JQ=1
[ "${ZES_FORCE_NO_JQ:-0}" = "1" ] && HAVE_JQ=0

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/zes.XXXXXX")" || { echo "ZES: 一時ディレクトリを作成できません" >&2; exit 64; }
TMP_DIR="$(cd -- "$TMP_DIR" && pwd -P)" || exit 64
TMPDIR_REAL=""; [ -n "${TMPDIR:-}" ] && TMPDIR_REAL="$(cd -- "$TMPDIR" 2>/dev/null && pwd -P)"
trap 'rm -rf "$TMP_DIR"' EXIT
FINDINGS_FILE="$TMP_DIR/findings.ndjson"
ERRORS_FILE="$TMP_DIR/errors.ndjson"
: >"$FINDINGS_FILE"
: >"$ERRORS_FILE"
# FATAL … 親プロセスで判定する致命的な失敗（インベントリを作れない・全モジュールが失敗）。status=error / 終了コード 2
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
log_info() { zes_enc "$*"; printf '%s  %s%s\n' "$C_DIM" "$ENC_TERM" "$C_OFF" >&3; }

sha256_str() {
  if command -v sha256sum >/dev/null 2>&1; then printf '%s' "$1" | sha256sum | awk '{print $1}'
  else printf '%s' "$1" | shasum -a 256 | awk '{print $1}'; fi
}
sha256_file() {
  # 標準入力から読む（ファイル名に \ や改行があると sha256sum は行頭に "\" を付けてエスケープするため）
  if command -v sha256sum >/dev/null 2>&1; then sha256sum <"$1" 2>/dev/null | awk '{print $1}'
  else shasum -a 256 <"$1" 2>/dev/null | awk '{print $1}'; fi
}


# >>> ger-tree-v1（tests/run-tests.sh がこの区間だけを読み込んでテストベクタと照合する）
# zes_tree_hash DIR … ディレクトリツリーのハッシュ ger-tree-v1（GER docs/design/design.md §10.8 と同じ定義）を
#   "sha256:<hex>" で出力する。エントリ（ルート自身を "." として含む）を相対パスのバイト列の昇順に並べ、各行
#   type \0 relpath \0 mode(4 桁の 8 進、07777 でマスク) \0 (f: size \0 sha256hex / l: readlink の値 / d: 空) \n
#   を連結した SHA-256。mtime・ctime・uid は含めない。ファイルの内容は読む（ハッシュするだけで出力しない）。
#   GER が拒否するツリー（エントリ 50,000 超・合計 2 GiB 超・深さ 256 超・FIFO / ソケット / デバイス・別の st_dev・
#   st_nlink > 1 の通常ファイル）と、読めない・改行を含む名前があるツリーはハッシュを出さず偽を返す
ZES_TREE_MAX_ENTRIES=50000
ZES_TREE_MAX_BYTES=2147483648
ZES_TREE_MAX_DEPTH=256
ZES_SHA256_CMD=(sha256sum); command -v sha256sum >/dev/null 2>&1 || ZES_SHA256_CMD=(shasum -a 256)
zes_sha256_cmd() { "${ZES_SHA256_CMD[@]}"; }  # 標準入力の SHA-256（"<hex>  -"）
zes_tree_hash() {
  local d="$1" p rel t n=0 i
  [ -d "$d" ] && [ ! -L "$d" ] || return 1
  local -a rels=() types=() paths=() fidx=() stl=() hl=()
  local lst; lst="$(mktemp "${TMP_DIR:-${TMPDIR:-/tmp}}/tree.XXXXXX")" || return 1
  if ! find "$d" -print0 >"$lst" 2>/dev/null; then rm -f "$lst"; return 1; fi
  while IFS= read -r -d '' p; do
    n=$((n + 1))
    [ "$n" -le "$ZES_TREE_MAX_ENTRIES" ] || { rm -f "$lst"; return 1; }
    case "$p" in *$'\n'*) rm -f "$lst"; return 1 ;; esac
    if [ "$p" = "$d" ]; then rel="."; else rel="${p#"$d"/}"; fi
    t="${rel//[!\/]/}"; [ "${#t}" -lt "$ZES_TREE_MAX_DEPTH" ] || { rm -f "$lst"; return 1; }
    if [ -L "$p" ]; then t=l; elif [ -f "$p" ]; then t=f; fidx+=("$n"); elif [ -d "$p" ]; then t=d; else rm -f "$lst"; return 1; fi
    rels+=("$rel"); types+=("$t"); paths+=("$p")
  done <"$lst"
  rm -f "$lst"
  # 種類・mode・サイズ・リンク数・デバイスは一括で取得する（lstat。1 パス 1 行、入力と同じ順）
  if [ "$OS_NAME" = "Darwin" ]; then mapfile -t stl < <(printf '%s\0' "${paths[@]}" | xargs -0 stat -f '%Xp %z %l %d' -- 2>/dev/null)
  else mapfile -t stl < <(printf '%s\0' "${paths[@]}" | xargs -0 stat -c '%f %s %h %d' -- 2>/dev/null); fi
  [ "${#stl[@]}" -eq "${#paths[@]}" ] || return 1
  if [ "${#fidx[@]}" -gt 0 ]; then
    local -a fpaths=()
    for i in "${fidx[@]}"; do fpaths+=("${paths[i - 1]}"); done
    mapfile -t hl < <(printf '%s\0' "${fpaths[@]}" | xargs -0 "${ZES_SHA256_CMD[@]}" -- 2>/dev/null)
    [ "${#hl[@]}" -eq "${#fpaths[@]}" ] || return 1
  fi
  local -a modes=() sizes=() hexes=() targets=()
  local -A at=()
  local dev0="" total=0 k=0 mode size nl dev x
  for i in "${!paths[@]}"; do
    read -r mode size nl dev <<<"${stl[i]}"
    mode="${mode#0x}"; mode="${mode#0X}"
    [[ "$mode" =~ ^[0-9a-fA-F]+$ ]] || return 1
    [ -n "$dev0" ] || dev0="$dev"
    [ "$dev" = "$dev0" ] || return 1
    printf -v "modes[$i]" '%04o' "$((16#$mode & 07777))"
    case "${types[i]}" in
      f)
        [ "$nl" = "1" ] || return 1
        total=$((total + size)); [ "$total" -le "$ZES_TREE_MAX_BYTES" ] || return 1
        x="${hl[k]#\\}"; x="${x%% *}"; k=$((k + 1))
        [[ "$x" =~ ^[0-9a-f]{64}$ ]] || return 1
        sizes[i]="$size"; hexes[i]="$x" ;;
      l) x="$(readlink -- "${paths[i]}"; printf x)"; x="${x%x}"; targets[i]="${x%$'\n'}" ;;
    esac
    at["${rels[i]}"]="$i"
  done
  local out
  out="$(printf '%s\0' "${rels[@]}" | LC_ALL=C sort -z | while IFS= read -r -d '' rel; do
    i="${at[$rel]}"
    case "${types[i]}" in
      d) printf 'd\0%s\0%s\0\n' "$rel" "${modes[i]}" ;;
      f) printf 'f\0%s\0%s\0%s\0%s\n' "$rel" "${modes[i]}" "${sizes[i]}" "${hexes[i]}" ;;
      l) printf 'l\0%s\0%s\0%s\n' "$rel" "${modes[i]}" "${targets[i]}" ;;
    esac
  done | zes_sha256_cmd | awk '{print $1}')" || return 1
  [[ "$out" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf 'sha256:%s' "$out"
}
# <<< ger-tree-v1

# findings 1.1 の任意項目（kind / subject / locators / related）を作る補助。emit の 6 番目の引数に、
# JSON のメンバーをカンマで区切った断片（例: "kind":"pkg.compromised","subject":{…}）として渡す。
#   ファイルの内容は入れない（locators は JSON pointer か、行番号とその行の SHA-256 だけ）
jq_str() { printf '"%s"' "$(json_escape "$1")"; }
jq_str_or_null() { if [ -n "$1" ]; then jq_str "$1"; else printf null; fi; }
x_kind() { printf '"kind":"%s"' "$1"; }
x_join() { local out="" s; for s in "$@"; do [ -n "$s" ] && out="${out:+$out,}$s"; done; printf '%s' "$out"; }
# x_subject ECOSYSTEM PACKAGE VERSION SAFE_VERSION [FIXED_VERSION...]
x_subject() {
  local eco="$1" pkg="$2" ver="$3" safev="$4"; shift 4
  local fx="" v
  for v in "$@"; do [ -n "$v" ] && fx="${fx:+$fx,}$(jq_str "$v")"; done
  printf '"subject":{"ecosystem":%s,"package":%s,"version":%s,"safe_version":%s,"fixed_versions":[%s]}' \
    "$(jq_str "$eco")" "$(jq_str "$pkg")" "$(jq_str_or_null "$ver")" "$(jq_str_or_null "$safev")" "$fx"
}
# x_related RELATION PATH [RELATION PATH...]
x_related() {
  local out=""
  while [ "$#" -ge 2 ]; do out="${out:+$out,}{\"relation\":$(jq_str "$1"),\"path\":$(jq_str "$2")}"; shift 2; done
  [ -n "$out" ] && printf '"related":[%s]' "$out"
}
# x_locators ITEM_JSON... → "locators":[…]（要素が無ければ何も出さない）
x_locators() { local out; out="$(x_join "$@")"; [ -n "$out" ] && printf '"locators":[%s]' "$out"; }
# json_pointer KEY... → RFC 6901 の JSON pointer（~ → ~0、/ → ~1）
json_pointer() { local out="" k; for k in "$@"; do k="${k//\~/~0}"; out="$out/${k//\//~1}"; done; printf '%s' "$out"; }
# text_locators FILE [grep-opts...] PATTERN … grep -n -a -E で一致した行（最大 64 行）の {format:text, line, line_sha256}
#   をカンマ区切りで出力する。行のハッシュは改行・行末の CR・1 行目の UTF-8 BOM を除いたバイト列の SHA-256
#   （GER の remove_line と同じ）。TL_EXCLUDE（ERE）に一致する行は除く（例: コメント行）。内容は出力しない
TEXT_LOCATORS_MAX=64
text_locators() {
  local f="$1"; shift
  [ -f "$f" ] && [ -r "$f" ] || return 0
  local n out="" h
  while IFS= read -r n; do
    [[ "$n" =~ ^[0-9]+$ ]] || continue
    h="$(awk -v n="$n" 'NR == n { sub(/\r$/, ""); if (NR == 1) sub(/^\357\273\277/, ""); printf "%s", $0; exit }' "$f" 2>/dev/null | zes_sha256_cmd | awk '{print $1}')"
    [[ "$h" =~ ^[0-9a-f]{64}$ ]] || continue
    out="${out:+$out,}{\"format\":\"text\",\"line\":$n,\"line_sha256\":\"sha256:$h\"}"
  done < <(grep -n -a -E "$@" -- "$f" 2>/dev/null | { if [ -n "${TL_EXCLUDE:-}" ]; then grep -v -i -E -- "^[0-9]+:(${TL_EXCLUDE})"; else cat; fi; } | cut -d: -f1 | head -n "$TEXT_LOCATORS_MAX")
  printf '%s' "$out"
}
# x_text_locators FILE [grep-opts...] PATTERN → "locators":[…]
x_text_locators() { x_locators "$(text_locators "$@")"; }

# json_ptr_locators FILE JQ_PATHS [jq の引数...] … JQ_PATHS（path(…) でパスの配列を出力する jq 式）の各位置を
#   {format: json|jsonc, pointer} の locator にしてカンマ区切りで出力する（厳密な JSON で読めなければ JSONC として読む）。
#   jq が無い・読めない場合は何も出さない（locators は任意項目）
json_ptr_locators() {
  [ "$HAVE_JQ" -eq 1 ] || return 0
  local f="$1" q="$2"; shift 2
  local prog="[ $q | if length == 0 then \"\" else \"/\" + (map(tostring | gsub(\"~\"; \"~0\") | gsub(\"/\"; \"~1\")) | join(\"/\")) end | {format: \$fmt, pointer: .} | tojson ] | join(\",\")"
  jq -r --arg fmt json "$@" "$prog" "$f" 2>/dev/null || jsonc_to_json "$f" | jq -r --arg fmt jsonc "$@" "$prog" 2>/dev/null || true
}
# エージェントのフック（.claude/settings.json の hooks.<Event>[i]）のうち、command が $s を含む（大文字小文字を区別しない）
#   / $re に一致するもの（GER の claude.hook が取り除く単位 /hooks/<Event>/<i>）
HOOK_PATHS_STR='path(.hooks? | objects | .[]? | arrays | .[] | select([.. | objects | .command? | strings] | any(ascii_downcase | contains($s | ascii_downcase))))'
HOOK_PATHS_RE='path(.hooks? | objects | .[]? | arrays | .[] | select([.. | objects | .command? | strings] | any(test($re))))'
# VS Code の tasks.json で、フォルダを開くと自動実行されるタスク（/tasks/<i>/runOptions/runOn）
TASK_RUNON_PATHS='path(.tasks? | arrays | .[] | objects | .runOptions? | objects | .runOn? | select(. == "folderOpen"))'

# default_related MODULE PATH … module と path だけで決まる related（findings 1.1）
#   §24 / §42（拡張の manifest.json）: ext_dir …/Extensions/<id>（GER は拡張ごと隔離する）
#   §49（skill.contract.json の finding）: skill_dir（契約のあるスキルのディレクトリ）
default_related() {
  case "$1" in
    §24|§42)
      if [[ "$2" =~ ^(.*/Extensions/[^/]+)(/[^/]+)?/manifest\.json$ ]]; then x_related ext_dir "${BASH_REMATCH[1]}"; fi ;;
    §49)
      case "$2" in */skill.contract.json) x_related skill_dir "${2%/*}" ;; esac ;;
  esac
  return 0
}

# emit LEVEL CAMPAIGN PATH DETAIL [SKILLPACT_JSON] [EXTRA_JSON]
#   findings[].id は module|campaign|path|detail（JSON に出力する値そのもの＝zes_enc の正規形）から決定的に生成（§6 保証）
#   evidence_hash は通常ファイルならその SHA-256、それ以外は detail の SHA-256（findings 1.0 と同じ。変えない）
#   evidence（findings 1.1）は種類つきの証跡: 通常ファイルは file（100MB 超は large_file。evidence_hash と同じ値）、
#   シンボリックリンクは symlink（readlink の値のバイト列の SHA-256）、ディレクトリは tree（ger-tree-v1）、
#   それ以外（path なし・FIFO 等・ツリーハッシュを出せないディレクトリ・検査ルート / ホームそのもの）は detail
#   EXTRA_JSON は kind / subject / locators / related のメンバー（x_* で作る）。id と evidence_hash には影響しない
#   パスに不正な UTF-8 バイトがある場合、path は "\xHH" 置換後の値になるため errors[] に non_utf8_path を記録する
declare -A SEEN_IDS=()
emit() {
  local level="$1" campaign="$2" path="$3" detail="$4" sp="${5:-}" extra="${6:-}"
  local module="$CURRENT_MODULE"
  local id ev evk evh color np jp tp pbad nd jd td nc jc
  zes_enc "$path"; np="$ENC_NORM"; jp="$ENC_JSON"; tp="$ENC_TERM"; pbad="$ENC_BAD"
  zes_enc "$detail"; nd="$ENC_NORM"; jd="$ENC_JSON"; td="$ENC_TERM"
  zes_enc "$campaign"; nc="$ENC_NORM"; jc="$ENC_JSON"
  id="sha256:$(sha256_str "$module|$nc|$np|$nd")"
  # 同じ id は 1 回だけ。生のパスが違うのに正規形が同じ（"\xHH" という文字列と不正なバイト 0xHH）なら、
  #   落とした重複を errors[] に記録する（dedup_findings と同じ扱い。サブシェルをまたぐものは dedup_findings が拾う）
  if [ -n "${SEEN_IDS[$id]+x}" ]; then
    [ "${SEEN_IDS[$id]}" != "x$path" ] && record_error "core" "duplicate_finding_id:$id"
    return 0
  fi
  SEEN_IDS[$id]="x$path"
  ev=""; evk="detail"; evh=""
  if [ -n "$path" ] && [ -L "$path" ]; then
    local lt; lt="$(readlink -- "$path" 2>/dev/null; printf x)"; lt="${lt%x}"; lt="${lt%$'\n'}"
    [ -n "$lt" ] && { evk="symlink"; evh="$(sha256_str "$lt")"; }
  elif [ -f "$path" ]; then
    # 100MB 超（モデル重み等）は全体ハッシュを避け、パス・サイズ・mtime のハッシュで代替
    local sz; sz="$(stat_size "$path")"
    if [ "${sz:-0}" -le 104857600 ]; then ev="$(sha256_file "$path")"; evk="file"
    else ev="$(sha256_str "$np|$sz|$(stat_mtime "$path")")"; evk="large_file"; fi
    evh="$ev"
  elif [ -n "$path" ] && [ -d "$path" ] && [ "$path" != "$ROOT" ] && [ "$path" != "${HOME_DIR:-}" ] && [ "$path" != "/" ]; then
    # 検査ルート・ホームそのものの finding（「同居」など）は修復の対象にならず、全体のハッシュは高価なため detail のまま
    evh="$(zes_tree_hash "$path")" && evh="${evh#sha256:}" && evk="tree" || evh=""
  fi
  [ -n "$ev" ] || ev="$(sha256_str "$nd")"
  case "$extra" in *'"related":'*) ;; *) extra="$(x_join "$extra" "$(default_related "$module" "$path")")" ;; esac
  if [ -z "$evh" ]; then evk="detail"; evh="$ev"; fi
  {
    printf '{"id":"%s","level":"%s","module":"%s","campaign":%s,"path":%s,"detail":%s,"evidence_hash":"sha256:%s"' \
      "$id" "$level" "$(json_escape "$module")" "$( [ -n "$campaign" ] && printf '"%s"' "$jc" || printf null)" \
      "$( [ -n "$path" ] && printf '"%s"' "$jp" || printf null)" "$( [ -n "$detail" ] && printf '"%s"' "$jd" || printf null)" "$ev"
    [ -n "$extra" ] && printf ',%s' "$extra"
    printf ',"evidence":{"kind":"%s","hash":"sha256:%s"}' "$evk" "$evh"
    [ -n "$sp" ] && printf ',"skillpact":%s' "$sp"
    printf '}\n'
  } >>"$FINDINGS_FILE"
  [ "$pbad" = "1" ] && record_error "core" "non_utf8_path:$np"
  case "$level" in
    CRITICAL) color="$C_RED" ;; HIGH) color="$C_MAG" ;; MEDIUM) color="$C_YEL" ;; *) color="$C_DIM" ;;
  esac
  printf '%s[%s]%s %s%s\n' "$color" "$level" "$C_OFF" "$td" "${path:+ : $tp}" >&3
}
critical() { emit CRITICAL "$@"; }
high()     { emit HIGH "$@"; }
medium()   { emit MEDIUM "$@"; }
low()      { emit LOW "$@"; }
info()     { emit INFO "$@"; }
safe()     { zes_enc "$*"; printf '%s[SAFE]%s %s\n' "$C_GRN" "$C_OFF" "$ENC_TERM" >&3; }

record_error() {
  local module="$1" reason="$2" jr tr
  zes_enc "$reason"; jr="$ENC_JSON"; tr="$ENC_TERM"
  printf '{"module":"%s","reason":"%s"}\n' "$(json_escape "$module")" "$jr" >>"$ERRORS_FILE"
  printf '%s[ERROR]%s %s: %s\n' "$C_YEL" "$C_OFF" "$module" "$tr" >&3
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
  ZES_V_A="$1" ZES_V_B="$2" awk 'BEGIN { a = ENVIRON["ZES_V_A"]; b = ENVIRON["ZES_V_B"] } BEGIN{
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
#   プローブはバージョン表示等のローカルで完結する引数のみで呼ぶ（ネットワーク接続しうる呼び出しは使わない）
safe_probe() {
  local bin="$1"; shift
  local p rp
  p="$(command -v "$bin" 2>/dev/null)" || return 127
  rp="$(resolve_path "$p")" || return 127
  # --root / はホスト自体が検査対象のため、検査ルート配下という条件は使わない（一時領域の条件は残す）
  if [ "$ROOT" != "/" ]; then case "$rp" in "$ROOT"/*) return 126 ;; esac; fi
  # 一時領域（macOS は /tmp → /private/tmp、$TMPDIR は /var/folders/… → /private/var/folders/…）
  case "$rp" in /tmp/*|/var/tmp/*|/dev/shm/*|/private/tmp/*|/private/var/tmp/*|/private/var/folders/*|/var/folders/*) return 126 ;; esac
  if [ -n "$TMPDIR_REAL" ] && [ "$TMPDIR_REAL" != "/" ]; then case "$rp" in "$TMPDIR_REAL"/*) return 126 ;; esac; fi
  case "$rp" in "$HOME_DIR"/*) [ "$HOST_CHECKS" = "1" ] || return 126 ;; esac
  # 環境は引き継がない（env -i）。検査対象 HOME の設定（~/.docker/config.json の context → ssh 実行、~/.kube/config の
  # exec プラグイン等）や DOCKER_HOST / KUBECONFIG 等を読ませないため、空の HOME と最小の変数だけを渡す
  local ph="$TMP_DIR/probe-home"
  mkdir -p -- "$ph/.docker" 2>/dev/null || return 126
  ( cd / && env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME="$ph" DOCKER_CONFIG="$ph/.docker" XDG_CONFIG_HOME="$ph" \
      TMPDIR="$TMP_DIR" LC_ALL=C GOTOOLCHAIN=local "$rp" "$@" </dev/null 2>/dev/null )
}

# git は検査対象リポジトリの設定（.git/config）経由でコマンドを起動しうる。また include.path / includeIf は
# 任意のファイル（FIFO 等）を読ませて走査を無期限に停止させうる。そこで git には検査対象の .git/config を一切読ませない:
#   $TMP_DIR/git-shadow に最小の GIT_DIR を作り（config は ZES が書く。objects / refs / packed-refs / reftable は
#   元リポジトリへのシンボリックリンク、HEAD / shallow は通常ファイルのみ複製）、GIT_DIR としてそれを使う。
#   元の config からは repositoryformatversion / extensions.objectformat / extensions.refstorage だけを
#   git を使わずに静的に読み（git_cfg_get）、partialclone 等の拡張は引き継がない（遅延フェッチをさせない）。
# 加えて、プログラムを値に取る設定はコマンドライン -c でも無害化し（多重防御）、全体を timeout で打ち切る:
#   署名検証（gpg.program / gpg.openpgp.program / gpg.x509.program / gpg.ssh.program / gpg.ssh.defaultKeyCommand）、
#   ssh・プロキシ（core.sshCommand / core.gitProxy）、エディタ・ページャ・認証（core.editor / sequence.editor /
#   core.pager / core.askPass / credential.helper）、diff（diff.external、textconv は --no-textconv を呼び出し側で指定）
#   ※ 署名の有無は検証させずに生のコミットオブジェクトのヘッダから判定する（§46）
#   ※ refs 配下の FIFO 等で git が停止した場合は ZES_GIT_TIMEOUT 秒（既定 60）で打ち切り、errors[] に git_timeout を記録
GIT_TIMEOUT="${ZES_GIT_TIMEOUT:-60}"
case "$GIT_TIMEOUT" in ''|*[!0-9]*) GIT_TIMEOUT=60 ;; esac

# ---------------------------------------------------------------------------
# 検査ルート内のパスの安全な読み取り
#   ルート内に組み立てたパス（$ROOT/.git/config 等）がシンボリックリンクでルート外（/proc/kmsg 等）を指す場合や、
#   通常ファイルでない場合は読まない（読むと停止しうる / 検査対象外のファイルを読む）
# ---------------------------------------------------------------------------
# realpath_in_root P … P の実パスが検査ルート配下（ルート自体を含む）なら実パスを出力して真
realpath_in_root() {
  local r; r="$(resolve_path "$1")" || return 1
  [ -n "$r" ] || return 1
  case "$r" in "$ROOT"|"$RP"/*) printf '%s' "$r"; return 0 ;; esac
  return 1
}
# in_root_regular P … P が（リンクを辿った結果）検査ルート内の通常ファイルなら真
in_root_regular() { [ -f "$1" ] && realpath_in_root "$1" >/dev/null; }
# read_capped FILE BYTES … 先頭 BYTES バイトを読む（timeout 付き。ブロックするファイルで停止しない）
READ_TIMEOUT=10
read_capped() { run_timeout "$READ_TIMEOUT" head -c "$2" -- "$1" 2>/dev/null; }

# git_cfg_get SECTION SUBSECTION KEY … 検査ルートの Git 設定（$ROOT/.git の config）の値を git を起動せずに読む
#   （最後の値。include は辿らない）。ルート外を指す・通常ファイル以外（FIFO・デバイス）は読まない。
#   [sec "sub"] と旧形式 [sec.sub] の両方に対応
git_cfg_get() {
  local cfg="${ROOT_GITCOMMON:-$RP/.git}/config"
  in_root_regular "$cfg" || return 1
  read_capped "$cfg" 1048576 | ZES_S="$1" ZES_SS="$2" ZES_K="$3" awk '
    BEGIN { ws = tolower(ENVIRON["ZES_S"]); wss = ENVIRON["ZES_SS"]; wk = tolower(ENVIRON["ZES_K"]); found = 0 }
    { line = $0; sub(/\r$/, "", line) }
    line ~ /^[[:space:]]*\[/ {
      h = line; sub(/^[[:space:]]*\[[[:space:]]*/, "", h); sub(/\][^]]*$/, "", h)
      if (match(h, /[[:space:]]+"/)) { sec = tolower(substr(h, 1, RSTART - 1)); ss = substr(h, RSTART + RLENGTH); sub(/"[[:space:]]*$/, "", ss); gsub(/\\\\/, "\001", ss); gsub(/\\/, "", ss); gsub(/\001/, "\\", ss) }
      else if (index(h, ".")) { sec = tolower(substr(h, 1, index(h, ".") - 1)); ss = tolower(substr(h, index(h, ".") + 1)) }
      else { sec = tolower(h); ss = "" }
      sub(/[[:space:]]+$/, "", sec); next }
    sec == ws && ss == wss {
      l = line; sub(/^[[:space:]]+/, "", l)
      if (!match(l, /^[A-Za-z][A-Za-z0-9-]*/)) next
      k = tolower(substr(l, 1, RLENGTH)); if (k != wk) next
      r = substr(l, RLENGTH + 1); sub(/^[[:space:]]*/, "", r)
      if (r == "") { v = "true"; found = 1; next }
      if (substr(r, 1, 1) != "=") next
      r = substr(r, 2); v = ""; inq = 0
      for (i = 1; i <= length(r); i++) { c = substr(r, i, 1)
        if (c == "\\" && i < length(r)) { i++; c = substr(r, i, 1); v = v (c == "n" ? "\n" : c == "t" ? "\t" : c == "b" ? "" : c); continue }
        if (c == "\"") { inq = !inq; continue }
        if (!inq && (c == "#" || c == ";")) break
        v = v c }
      sub(/^[[:space:]]+/, "", v); sub(/[[:space:]]+$/, "", v); found = 1 }
    END { if (found) print v; else exit 1 }'
}

# git_cfg_includes CONFIG … include.path / includeIf "<条件>".path の値を 1 行ずつ（条件は評価せず全て）。git は起動しない
git_cfg_includes() {
  read_capped "$1" 1048576 | awk '
    { line = $0; sub(/\r$/, "", line) }
    line ~ /^[[:space:]]*\[/ {
      h = line; sub(/^[[:space:]]*\[[[:space:]]*/, "", h); sub(/\][^]]*$/, "", h)
      sec = tolower(h); sub(/[[:space:]"].*$/, "", sec); sub(/\..*$/, "", sec); next }
    sec == "include" || sec == "includeif" {
      l = line; sub(/^[[:space:]]+/, "", l)
      if (tolower(substr(l, 1, 4)) != "path") next
      r = substr(l, 5); sub(/^[[:space:]]*/, "", r)
      if (substr(r, 1, 1) != "=") next
      r = substr(r, 2); v = ""; inq = 0
      for (i = 1; i <= length(r); i++) { c = substr(r, i, 1)
        if (c == "\\" && i < length(r)) { i++; v = v substr(r, i, 1); continue }
        if (c == "\"") { inq = !inq; continue }
        if (!inq && (c == "#" || c == ";")) break
        v = v c }
      sub(/^[[:space:]]+/, "", v); sub(/[[:space:]]+$/, "", v); if (v != "") print v }'
}

# ---------------------------------------------------------------------------
# Git ディレクトリの発見（検査ルート直下の .git と、入れ子の .git〔サブモジュール・同梱リポジトリ〕）
#   .git ファイル（"gitdir: <path>"）と commondir（git worktree）を git を使わずに解決し、
#   設定（config / config.worktree）と include.path / includeIf の参照先、フック置き場を一覧にする（§7 / §26 / §41 が静的に検査）。
#   解決できない・検査ルート外を指す場合は errors[] に記録する（読めない設定を 0 件扱いしない）
#   GIT_DIRS_FILE: .git のパス US gitdir US commondir / GIT_CFG_LIST: 静的に検査する Git 設定 / GIT_HOOKS_LIST: フック置き場
# ---------------------------------------------------------------------------
GIT_DIRS_FILE=""; GIT_CFG_LIST=""; GIT_HOOKS_LIST=""
ROOT_GITDIR=""; ROOT_GITCOMMON=""
git_read_pointer() {  # git_read_pointer FILE PREFIX … "PREFIX<path>"（PREFIX 空なら 1 行目そのもの）の <path>
  local l; l="$(read_capped "$1" 4096 | head -n1 | tr -d '\r')"
  if [ -n "$2" ]; then case "$l" in "$2"*) l="${l#"$2"}" ;; *) return 1 ;; esac; fi
  l="${l#"${l%%[![:space:]]*}"}"; l="${l%"${l##*[![:space:]]}"}"
  [ -n "$l" ] || return 1
  case "$l" in /*) ;; *) l="${1%/*}/$l" ;; esac
  printf '%s' "$l"
}
git_discover() {
  GIT_DIRS_FILE="$TMP_DIR/gitdirs.tsv"; GIT_CFG_LIST="$TMP_DIR/gitcfg.lst"; GIT_HOOKS_LIST="$TMP_DIR/githooks.lst"
  : >"$GIT_DIRS_FILE"; : >"$GIT_CFG_LIST"; : >"$GIT_HOOKS_LIST"
  local p gd cd t
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    gd=""
    if [ -L "$p" ]; then
      gd="$(realpath_in_root "$p")" && [ -d "$gd" ] || { record_error "core" "gitdir_unresolved:$p"; continue; }
    elif [ -d "$p" ]; then
      gd="$p"
    elif [ -f "$p" ]; then
      t="$(git_read_pointer "$p" "gitdir:")" || { record_error "core" "gitfile_unparsed:$p"; continue; }
      if ! gd="$(realpath_in_root "$t")" || [ ! -d "$gd" ]; then
        if [ -d "$t" ]; then record_error "core" "gitdir_outside_root:$p"; else record_error "core" "gitdir_unresolved:$p"; fi
        continue
      fi
    else
      continue  # FIFO 等は build_inventory が special_file として記録済み
    fi
    cd="$gd"
    if [ -e "$gd/commondir" ] || [ -L "$gd/commondir" ]; then
      if in_root_regular "$gd/commondir" && t="$(git_read_pointer "$gd/commondir" "")" && cd="$(realpath_in_root "$t")" && [ -d "$cd" ]; then :
      else record_error "core" "git_commondir_unresolved:$p"; cd="$gd"; fi
    fi
    printf '%s\037%s\037%s\n' "$p" "$gd" "$cd" >>"$GIT_DIRS_FILE"
    if [ "$p" = "$RP/.git" ]; then ROOT_GITDIR="$gd"; ROOT_GITCOMMON="$cd"; fi
    for t in "$cd/hooks"; do
      [ -d "$t" ] || continue
      realpath_in_root "$t" >/dev/null || { record_error "core" "path_leaves_root:$t"; continue; }
      printf '%s\n' "$t" >>"$GIT_HOOKS_LIST"
    done
    for t in "$gd/config" "$gd/config.worktree" "$cd/config" "$cd/config.worktree"; do
      { [ -e "$t" ] || [ -L "$t" ]; } || continue
      if in_root_regular "$t"; then git_cfg_collect "$t" 0
      else record_error "core" "path_leaves_root:$t"; fi
    done
  done < <({ { [ -e "$RP/.git" ] || [ -L "$RP/.git" ]; } && printf '%s\n' "$RP/.git"
             awk '{ n = $0; sub(/.*\//, "", n); if (n == ".git") print }' "$DIRS_LIST" "$FILES_LIST" "$LINKS_LIST"; } | sort -u)
  sort -u -o "$GIT_CFG_LIST" "$GIT_CFG_LIST"; sort -u -o "$GIT_HOOKS_LIST" "$GIT_HOOKS_LIST"
}
# git_cfg_collect CONFIG DEPTH … CONFIG を一覧に加え、include.path / includeIf の参照先を辿る（深さ 10 まで。git と同じ上限）
git_cfg_collect() {
  local cfg="$1" depth="$2" inc t r
  grep -q -x -F -- "$cfg" "$GIT_CFG_LIST" 2>/dev/null && return 0
  printf '%s\n' "$cfg" >>"$GIT_CFG_LIST"
  [ "$depth" -lt 10 ] || { record_error "core" "git_include_too_deep:$cfg"; return 0; }
  while IFS= read -r inc; do
    case "$inc" in "~/"*) t="$HOME_DIR/${inc#\~/}" ;; /*) t="$inc" ;; *) t="${cfg%/*}/$inc" ;; esac
    # 参照先は検査ルート内（または検査対象 HOME 内）の通常ファイルのみ読む。git には読ませない
    r="$(resolve_path "$t")"
    if [ -n "$r" ] && [ -f "$r" ] && { realpath_in_root "$r" >/dev/null || case "$r" in "$HOME_DIR"/*) true ;; *) false ;; esac; }; then
      git_cfg_collect "$r" $((depth + 1))
    else
      record_error "core" "git_include_unresolved:$cfg"
    fi
  done < <(git_cfg_includes "$cfg")
}

# 検査対象 .git から ZES 管理の最小 GIT_DIR を作る（作成済みなら何もしない）
#   HEAD は gitdir から、objects / refs / packed-refs / reftable / shallow は commondir（worktree なら共有側）から取る。
#   いずれも検査ルート内の実体に限り（ルート外を指すリンクは使わない）、読み取りは timeout 付き
git_shadow_prepare() {
  local g="$ROOT_GITDIR" c="$ROOT_GITCOMMON" d="$TMP_DIR/git-shadow" x rfv of rs
  [ -f "$d/config" ] && return 0
  [ -n "$g" ] && [ -d "$g" ] && in_root_regular "$g/HEAD" || return 1
  rm -rf -- "$d" && mkdir -p -- "$d" || return 1
  read_capped "$g/HEAD" 4096 >"$d/HEAD" || return 1
  if [ -e "$c/shallow" ] || [ -L "$c/shallow" ]; then
    in_root_regular "$c/shallow" && read_capped "$c/shallow" 16777216 >"$d/shallow" || return 1
  fi
  for x in objects refs packed-refs reftable; do
    if [ -e "$c/$x" ] || [ -L "$c/$x" ]; then
      realpath_in_root "$c/$x" >/dev/null || return 1
      ln -s -- "$c/$x" "$d/$x" || return 1
    fi
  done
  [ -e "$d/refs" ] || mkdir -p -- "$d/refs"
  rfv="$(git_cfg_get core '' repositoryformatversion)"; of="$(git_cfg_get extensions '' objectformat)"; rs="$(git_cfg_get extensions '' refstorage)"
  case "${rfv:-0}" in 0|1) ;; *) return 1 ;; esac
  {
    printf '[core]\n\trepositoryformatversion = %s\n\tbare = false\n' "${rfv:-0}"
    if [ -n "$of$rs" ]; then
      printf '[extensions]\n'
      case "$of" in '') ;; sha1|sha256) printf '\tobjectformat = %s\n' "$of" ;; *) return 1 ;; esac
      case "$rs" in '') ;; files|reftable) printf '\trefstorage = %s\n' "$rs" ;; *) return 1 ;; esac
    fi
  } >"$d/config.tmp" && mv -- "$d/config.tmp" "$d/config"
}

# run_timeout SECONDS CMD... … coreutils timeout があれば使い、無ければ bash のウォッチドッグで打ち切る（124 を返す）
#   ウォッチドッグの sleep は子プロセスとして待ち、ウォッチドッグを止めるときに sleep も止める（孤児の sleep を残さない）
run_timeout() {
  local secs="$1"; shift
  if command -v timeout >/dev/null 2>&1; then timeout -k 5 "$secs" "$@"; return $?; fi
  "$@" 0<&0 &
  local pid=$! w rc mark="$TMP_DIR/timeout.$BASHPID.$RANDOM"
  (
    sp=""
    trap '[ -n "$sp" ] && kill "$sp" 2>/dev/null; exit 0' TERM
    sleep "$secs" & sp=$!; wait "$sp"; sp=""
    : >"$mark"
    kill -TERM "$pid" 2>/dev/null || exit 0
    sleep 5 & sp=$!; wait "$sp"; sp=""
    kill -KILL "$pid" 2>/dev/null
  ) >/dev/null 2>&1 &
  w=$!
  wait "$pid"; rc=$?
  kill -TERM "$w" 2>/dev/null; wait "$w" 2>/dev/null
  if [ -e "$mark" ]; then rm -f -- "$mark"; return 124; fi
  return "$rc"
}

safe_git() {
  [ -n "$GIT_BIN" ] || return 127
  git_shadow_prepare || { record_error "${CURRENT_MODULE:-core}" "git_dir_unreadable"; return 1; }
  local rc
  GIT_DIR="$TMP_DIR/git-shadow" GIT_WORK_TREE="$ROOT" GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_COUNT=0 \
  GIT_NO_LAZY_FETCH=1 GIT_NO_REPLACE_OBJECTS=1 GIT_TERMINAL_PROMPT=0 GIT_PAGER=cat GIT_EXTERNAL_DIFF='' \
  GIT_SSH_COMMAND=/bin/false GIT_SSH=/bin/false GIT_ASKPASS=/bin/false SSH_ASKPASS=/bin/false GIT_EDITOR=/bin/false \
  GIT_SEQUENCE_EDITOR=/bin/false GIT_PROXY_COMMAND=/bin/false GIT_OPTIONAL_LOCKS=0 \
    run_timeout "$GIT_TIMEOUT" "$GIT_BIN" -c core.fsmonitor=false -c core.hooksPath=/dev/null -c core.pager=cat -c log.showSignature=false \
        -c gpg.program=/bin/false -c gpg.openpgp.program=/bin/false -c gpg.x509.program=/bin/false \
        -c gpg.ssh.program=/bin/false -c gpg.ssh.defaultKeyCommand=/bin/false \
        -c diff.external= -c core.sshCommand=/bin/false -c core.gitProxy=/bin/false \
        -c core.editor=/bin/false -c sequence.editor=/bin/false -c core.askPass=/bin/false -c credential.helper= \
        -c core.alternateRefsCommand=/bin/false -c protocol.allow=never -c core.quotePath=false -C "$ROOT" --no-pager "$@" </dev/null 2>/dev/null
  rc=$?
  [ "$rc" -eq 124 ] && record_error "${CURRENT_MODULE:-core}" "git_timeout"
  return "$rc"
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
# LINKED_FILES_LIST … FILES_LIST に「リンク名で」加えたシンボリックリンク（実体が検査ルート内の通常ファイル）
LINKED_FILES_LIST="$TMP_DIR/linked-files.lst"
# 読むと停止しうる・検査対象ではない擬似ファイルシステム（バインドマウントされた /proc/kmsg 等も含む）
PSEUDO_FSTYPES="proc sysfs devtmpfs devpts devfs debugfs tracefs securityfs cgroup cgroup2 pstore bpf configfs fusectl mqueue hugetlbfs binfmt_misc efivarfs selinuxfs rpc_pipefs nsfs autofs"
# リンク先が検査ルート外のときに errors[] に記録する設定ファイル名（リンク経由で検査を逃れさせない）
# GER の隔離ストア（マーカー .ger-quarantine-store のあるディレクトリ）は走査しない。中身は隔離済みの悪性ファイル
#   そのものなので、走査すると修復後の再スキャンで同じ finding が再び出る。マーカーを置くだけで検査を逃れられないよう、
#   GER が作るストアの条件（マーカーが通常ファイル・ディレクトリの所有者が実行ユーザー・グループ / 他者の権限なし）を
#   満たすものだけを外し、errors[] に quarantine_store_skipped として残す。条件を満たさないマーカーは無視して走査し、
#   errors[] に quarantine_marker_untrusted を記録する（status は partial）
QSTORE_MARKER=".ger-quarantine-store"
QSTORES=()
qstore_trusted() {
  local d="$1" m
  [ -f "$d/$QSTORE_MARKER" ] && [ ! -L "$d/$QSTORE_MARKER" ] && [ -d "$d" ] && [ ! -L "$d" ] && [ -O "$d" ] || return 1
  m="$(stat_perm "$d")"
  [[ "$m" =~ ^[0-7]+$ ]] && [ $(( 8#$m & 077 )) -eq 0 ]
}
# qstore_note DIR … マーカーのあるディレクトリを判定して QSTORES に足す（errors[] に記録）
qstore_note() {
  local d="$1" q
  for q in "${QSTORES[@]}"; do [ "$q" = "$d" ] && return 0; done
  if qstore_trusted "$d"; then QSTORES+=("$d"); record_error "core" "quarantine_store_skipped:$d"
  else record_error "core" "quarantine_marker_untrusted:$d"; fi
}
# in_qstore PATH … PATH が（判定済みの）隔離ストアそのもの、またはその中なら真
in_qstore() {
  local q
  for q in "${QSTORES[@]}"; do case "$1" in "$q"|"$q"/*) return 0 ;; esac; done
  return 1
}
# qstore_filter … 標準入力のパス（1 行 1 件。検査ルート外の find の結果）から、隔離ストアの中のものを除く。
#   パスの上位のディレクトリにマーカーがあれば判定する（find の起点より上は見ない: 起点 $1）
qstore_filter() {
  local top="${1%/}" p d
  while IFS= read -r p; do
    d="${p%/*}"
    while [ -n "$d" ]; do
      [ -e "$d/$QSTORE_MARKER" ] && qstore_note "$d"
      [ "$d" = "$top" ] && break
      case "$d" in "$top"/*) d="${d%/*}" ;; *) break ;; esac
    done
    in_qstore "$p" || printf '%s\n' "$p"
  done
}
SENSITIVE_LINK_RE='(/\.mcp\.json|/mcp\.json|/\.(cursor|vscode)/(mcp|tasks|settings)\.json|/\.claude/settings(\.local)?\.json|/\.gemini/settings\.json|/claude_desktop_config\.json|/\.codex/config\.toml|/\.github/workflows/[^/]+\.ya?ml|/action\.ya?ml|/package\.json|/\.npmrc|/\.yarnrc(\.yml)?|/\.gitconfig|/\.git/config|/\.envrc|/(CLAUDE|CLAUDE\.local|AGENTS|GEMINI)\.md|/\.cursorrules|/\.windsurfrules|/\.clinerules|/\.gitmodules|/\.pth|\.pth|/sitecustomize\.py|/usercustomize\.py|/setup\.py|/pyproject\.toml|/build\.rs|/skill\.contract\.json|/SKILL\.md)$'
build_inventory() {
  # VCS のメタデータは検査ルート直下のもの（$ROOT/.git 等）だけを除外する。入れ子の .git / .hg / .svn は
  # 中のファイルも走査する（同名ディレクトリにコードを隠させない）。$ROOT/.git は git_discover が静的に検査する
  local -a prune=( -path "$RP/.git" -prune -o -path "$RP/.hg" -prune -o -path "$RP/.svn" -prune -o -path "$TMP_DIR" -prune )
  case "$SCRIPT_DIR/" in
    "$RP"/*) if [ "$SCRIPT_DIR" != "$ROOT" ] || [ -f "$RP/zes-scan.sh" ]; then prune+=( -o -path "$SCRIPT_DIR" -prune ); fi ;;
  esac
  # 擬似ファイルシステムは開かずに errors[] に記録する（find が -fstype に対応している場合）
  local -a pseudo=() t
  if find "$ROOT" -maxdepth 0 -fstype proc >/dev/null 2>&1; then
    for t in $PSEUDO_FSTYPES; do [ "${#pseudo[@]}" -gt 0 ] && pseudo+=( -o ); pseudo+=( -fstype "$t" ); done
    prune+=( -o \( "${pseudo[@]}" \) -exec printf '\001%s\000' {} + -prune )
  else
    record_error "core" "find_fstype_unsupported"
  fi
  local rc
  find "$ROOT" \( "${prune[@]}" \) -o -print0 >"$TMP_DIR/all.z" 2>"$TMP_DIR/find.err"; rc=$?
  if tr '\0' '\n' <"$TMP_DIR/all.z" | awk 'END{exit 0}' && [ "$(tr -cd '\0' <"$TMP_DIR/all.z" | wc -c)" -ne "$(tr '\0' '\n' <"$TMP_DIR/all.z" | wc -l)" ]; then
    record_error "core" "unscannable_path_newline"
  fi
  : >"$FILES_LIST"; : >"$LINKS_LIST"; : >"$DIRS_LIST"; : >"$LINKED_FILES_LIST"
  # GER の隔離ストア（.ger-quarantine-store のあるディレクトリ）を外す（find の 1 回の走査の結果から除く）
  local qm
  while IFS= read -r qm; do
    case "$qm" in "$RP"/*/"$QSTORE_MARKER"|"$RP/$QSTORE_MARKER") qstore_note "${qm%/*}" ;; esac
  done < <(tr '\0' '\n' <"$TMP_DIR/all.z" | grep -F -- "/$QSTORE_MARKER" | grep -E -- "/\.ger-quarantine-store\$")
  local p r n=0
  while IFS= read -r -d '' p; do
    case "$p" in *$'\n'*) continue ;; esac
    case "$p" in $'\001'*) record_error "core" "special_filesystem:${p#$'\001'}"; continue ;; esac
    if [ "${#QSTORES[@]}" -gt 0 ] && in_qstore "$p"; then continue; fi
    [ "$p" = "$ROOT" ] || n=$((n + 1))
    if [ -L "$p" ]; then
      printf '%s\n' "$p" >>"$LINKS_LIST"
      # リンク先が検査ルート内の通常ファイルなら、リンク名でも走査する（.mcp.json → cfg/servers.json 等）
      if r="$(realpath_in_root "$p")" && [ -f "$r" ]; then
        printf '%s\n' "$p" >>"$FILES_LIST"; printf '%s\n' "$p" >>"$LINKED_FILES_LIST"
      elif printf '%s\n' "$p" | grep_q -E -- "$SENSITIVE_LINK_RE"; then
        record_error "core" "symlink_leaves_root:$p"
      fi
    elif [ -f "$p" ]; then
      printf '%s\n' "$p" >>"$FILES_LIST"
      [ -r "$p" ] || record_error "core" "unreadable:$p"
      # 中身を展開しないアーカイブは errors[] に archive_not_inspected として記録（status は変えない: README「制限事項」）
      case "$p" in *.whl|*.tgz|*.tar.gz|*.zip|*.jar|*.war|*.pyz|*.egg|*.gem|*.crate|*.nupkg|*.vsix|*.crx|*.xpi) record_error "core" "archive_not_inspected:$p" ;; esac
    elif [ -d "$p" ]; then
      printf '%s\n' "$p" >>"$DIRS_LIST"
    else
      # FIFO・ソケット・デバイスは開かない（読むと停止しうる）。検査していないことを errors[] に残す（fail-closed）
      record_error "core" "special_file:$p"
    fi
  done <"$TMP_DIR/all.z"
  # find が読めなかったディレクトリ（権限なし等）を errors[] に記録する（黙って 0 件扱いしない）
  local line q
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    q="$(printf '%s' "$line" | sed -n -E -e "s/^find: '(.*)': [^:]*\$/\\1/p" -e t -e "s/^find: (.*): [^:]*\$/\\1/p")"
    if [ -n "$q" ]; then record_error "core" "unreadable:$q"; else record_error "core" "inventory_error:$(printf '%s' "$line" | cut -c1-200)"; fi
  done <"$TMP_DIR/find.err"
  if [ "$rc" -ne 0 ]; then
    [ -s "$TMP_DIR/find.err" ] || record_error "core" "inventory_incomplete:find_exit_$rc"
    # 検査ルート自体を読めない（中身を 1 件も列挙できない）場合は致命的（status=error）
    [ "$n" -eq 0 ] && { FATAL=1; record_error "core" "inventory_failed"; }
  fi
  sort -o "$FILES_LIST" "$FILES_LIST"; sort -o "$LINKS_LIST" "$LINKS_LIST"; sort -o "$DIRS_LIST" "$DIRS_LIST"; sort -o "$LINKED_FILES_LIST" "$LINKED_FILES_LIST"
}

# files_named REGEX  … ベース名が ERE に一致するファイル
files_named() { ZES_RE="$1" awk '{n=$0; sub(/.*\//,"",n); if (n ~ ENVIRON["ZES_RE"]) print}' "$FILES_LIST"; }
# files_path REGEX   … フルパスが ERE に一致するファイル
files_path() { grep -E -- "$1" "$FILES_LIST" 2>/dev/null || true; }
# grep_l PATTERN [grep-opts...] < filelist … 内容が一致するファイルのパスのみを返す（内容は出力しない）
grep_l() {
  local pat="$1"; shift
  tr '\n' '\0' | xargs -0 grep -l -a -E "$@" -e "$pat" -- /dev/null 2>/dev/null || true
}
grep_lF() {
  local pat="$1"; shift
  tr '\n' '\0' | xargs -0 grep -l -a -F "$@" -e "$pat" -- /dev/null 2>/dev/null || true
}
# 1ファイルに対する存在判定
fgrep_q() { grep -q -a -E "$@" 2>/dev/null; }
# パイプの末尾での存在判定（cmd | grep_q [grep-opts...] PATTERN）。grep -q と同じ真偽を返すが、入力を最後まで読む。
#   grep -q は最初の一致で終了するため、上流（printf・grep・xargs 等）が書き終える前に終了すると上流が SIGPIPE で
#   失敗し、set -o pipefail の下では「一致したのに偽」（! 付きなら偽陽性）になる。負荷の高いときだけ起きる競合で、
#   detail（例: §24 の危険パーミッションの列挙）と id が実行ごとに変わる原因になっていた。パイプでは grep -q を使わないこと
grep_q() { local n; n="$(grep -c "$@" 2>/dev/null)"; [ "${n:-0}" -gt 0 ] 2>/dev/null; }
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
      ZES_V_SRC="$f" awk 'BEGIN { src = ENVIRON["ZES_V_SRC"] } 
        /"node_modules\/[^"]+": *\{/ { n=$0; sub(/.*node_modules\//,"",n); sub(/".*/,"",n); want=1
          if ($0 ~ /"version": *"/) { v=$0; sub(/.*"version": *"/,"",v); sub(/".*/,"",v); print "npm\t" n "\t" v "\t" src; want=0 }
          next }
        want && /"version": *"/ { v=$0; sub(/.*"version": *"/,"",v); sub(/".*/,"",v); print "npm\t" n "\t" v "\t" src; want=0 }' "$f" >>"$DEPS_TSV"
    fi
  done < <(files_named '^(package-lock\.json|npm-shrinkwrap\.json)$')
  # npm: yarn.lock（v1 / Berry）
  #   エイリアス（"kv@npm:keyv@6.0.0"）は別名ではなく実パッケージ名（keyv）で照合する。
  #   Berry の resolution: "keyv@npm:6.0.0" があればそれを優先（ブロック末尾でまとめて出力）
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    text_lines "$f" | ZES_V_SRC="$f" awk 'BEGIN { src = ENVIRON["ZES_V_SRC"] } 
      function pname(spec,   at, t, n0) {   # "name@range" → name（range が npm:<target> なら target の名前）
        gsub(/"/, "", spec)
        at = (spec ~ /^@/) ? index(substr(spec, 2), "@") + 1 : index(spec, "@")
        if (at <= 1) return spec
        t = substr(spec, at + 1)
        n0 = substr(spec, 1, at - 1)
        if (t !~ /^npm:/) return n0
        t = substr(t, 5)
        if (t ~ /^[0-9^~<>=*]/ || t == "") return n0              # "keyv@npm:^6.0.0"（Berry の通常表記）
        at = (t ~ /^@/) ? index(substr(t, 2), "@") + 1 : index(t, "@")
        return (at > 1) ? substr(t, 1, at - 1) : t }               # "kv@npm:keyv@6.0.0" / "kv@npm:keyv"
      function flush() { if (n != "" && v != "") print "npm\t" (rn != "" ? rn : n) "\t" v "\t" src; n = ""; v = ""; rn = "" }
      /^[^ #].*:$/ { flush(); h=$0; sub(/:$/,"",h); split(h,parts,/, */); n = pname(parts[1]); next }
      /^  version:? / { v=$0; sub(/^  version:? +/,"",v); gsub(/"/,"",v); next }
      /^  resolution:? / { r=$0; sub(/^  resolution:? +/,"",r); gsub(/"/,"",r); if (index(r, "@npm:") > 1) rn = substr(r, 1, index(r, "@npm:") - 1); next }
      END { flush() }' >>"$DEPS_TSV"
  done < <(files_named '^yarn\.lock$')
  # npm: pnpm-lock.yaml
  #   v6+: "/name@1.2.3:" / "name@1.2.3(peer@x):"、v5: "/name/1.2.3:" / "/@scope/name/1.2.3:" / "/name/1.2.3_peer@x:"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    text_lines "$f" | ZES_V_SRC="$f" awk 'BEGIN { src = ENVIRON["ZES_V_SRC"] } 
      /^  ['"'"'"]?\/(@[^\/ ]+\/)?[^\/@ ]+\/[0-9][^:]*['"'"'"]?:/ {
        s=$0; sub(/^  /,"",s); gsub(/['"'"'"]/,"",s); sub(/^\//,"",s); sub(/:.*$/,"",s)
        k = 0; while (match(substr(s, k + 1), /\//)) k += RSTART
        v = substr(s, k + 1); sub(/[_(].*$/, "", v)
        print "npm\t" substr(s, 1, k - 1) "\t" v "\t" src; next }
      /^  ['"'"'"\/]?@?[^ @]+@[0-9][^:]*:/ {
        s=$0; sub(/^  /,"",s); gsub(/['"'"'"]/,"",s); sub(/^\//,"",s); sub(/:.*$/,"",s); sub(/\(.*$/,"",s)
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
    text_lines "$f" | ZES_V_SRC="$f" awk 'BEGIN { src = ENVIRON["ZES_V_SRC"] } 
      { line=$0; sub(/#.*/,"",line); gsub(/[ \t]/,"",line) }
      line ~ /^[A-Za-z0-9][A-Za-z0-9._-]*(\[[^]]*\])?===?[^;,]+/ {
        n=line; sub(/(\[[^]]*\])?===?.*/,"",n); v=line; sub(/^[^=]*===?/,"",v); sub(/[;,].*/,"",v)
        n=tolower(n); gsub(/[-_.]+/,"-",n); print "pypi\t" n "\t" v "\t" src }' >>"$DEPS_TSV"
  done < <(files_named '^(requirements.*|constraints.*)\.txt$')
  # pypi: poetry.lock / uv.lock / pdm.lock
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    text_lines "$f" | ZES_V_SRC="$f" awk 'BEGIN { src = ENVIRON["ZES_V_SRC"] } 
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
    text_lines "$f" | ZES_V_SRC="$f" awk 'BEGIN { src = ENVIRON["ZES_V_SRC"] } 
      /^\[\[package\]\]/ { n=""; next }
      /^name = "/ { n=$0; sub(/^name = "/,"",n); sub(/".*/,"",n); next }
      /^version = "/ && n!="" { v=$0; sub(/^version = "/,"",v); sub(/".*/,"",v); print "cargo\t" n "\t" v "\t" src; n="" }' >>"$DEPS_TSV"
  done < <(files_named '^Cargo\.lock$')
  # go: go.sum
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    text_lines "$f" | ZES_V_SRC="$f" awk 'BEGIN { src = ENVIRON["ZES_V_SRC"] } NF >= 2 { v=$2; sub(/\/go\.mod$/,"",v); print "go\t" $1 "\t" v "\t" src }' >>"$DEPS_TSV"
  done < <(files_named '^go\.sum$')
  # ruby: Gemfile.lock
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    # プラットフォーム付き（nokogiri (1.16.0-x86_64-linux)）はバージョン部分のみで比較する
    text_lines "$f" | ZES_V_SRC="$f" awk 'BEGIN { src = ENVIRON["ZES_V_SRC"] } /^    [A-Za-z0-9_.-]+ \([0-9][^)]*\)$/ { n=$1; v=$2; gsub(/[()]/,"",v); sub(/-[A-Za-z].*$/,"",v); print "gem\t" n "\t" v "\t" src }' >>"$DEPS_TSV"
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
  # npm: bun.lock（JSONC。"packages": { "<名前>": ["<実名>@<版>", …] }。npm エイリアスは実名で照合）
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if [ "$HAVE_JQ" -eq 1 ]; then
      jsonc_to_json "$f" | jq -r --arg src "$f" '(.packages // {}) | if type == "object" then .[] else empty end
          | if type == "array" then .[0] else empty end | strings | capture("^(?<n>@?[^@]+)@(?<v>.+)$") | ["npm", .n, .v, $src] | @tsv' \
        2>/dev/null >>"$DEPS_TSV" || record_error "§15" "lockfile_parse_failed:$f"
    else
      record_error "§15" "jq_unavailable:$f"
    fi
  done < <(files_named '^bun\.lock$')
  # npm: deno.lock（v3: packages.npm、v4 以降: npm。キーは "<名前>@<版>"、"_" 以降は peer 接尾辞）
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if [ "$HAVE_JQ" -eq 1 ]; then
      jq -r --arg src "$f" '[(.npm // {}), (.packages.npm? // {})] | map(select(type == "object") | keys[]) | .[]
          | capture("^(?<n>@?[^@]+)@(?<v>[^_]+)") | ["npm", .n, .v, $src] | @tsv' "$f" 2>/dev/null >>"$DEPS_TSV" \
        || record_error "§15" "lockfile_parse_failed:$f"
    else
      record_error "§15" "jq_unavailable:$f"
    fi
  done < <(files_named '^deno\.lock$')
  # bun.lockb（バイナリ形式）は解析しない（照合していないことを errors[] に残す）
  while IFS= read -r f; do [ -n "$f" ] && record_error "§15" "lockfile_unparsed:$f"; done < <(files_named '^bun\.lockb$')
  sort -u -o "$DEPS_TSV" "$DEPS_TSV"
}

# pkg_kind SOURCE … 侵害パッケージの finding の kind。インストール実体（node_modules/<name>/package.json・
#   *.dist-info・*.egg-info）は pkg.compromised、ロックファイル・依存の宣言は pkg.lockfile_compromised
pkg_kind() {
  case "$1" in
    */node_modules/*/package.json|*.dist-info|*.egg-info) printf 'pkg.compromised' ;;
    *) printf 'pkg.lockfile_compromised' ;;
  esac
}
# pkg_related ECO NAME SOURCE … npm のロックファイル（ZET / GER の npm_installed と同じ 5 種）の隣にインストールされた
#   実体があれば related npm_installed（シンボリックリンク〔pnpm 等〕は GER が隔離できないため入れない）
pkg_related() {
  [ "$1" = "npm" ] || return 0
  case "${3##*/}" in package-lock.json|npm-shrinkwrap.json|yarn.lock|pnpm-lock.yaml|bun.lock) ;; *) return 0 ;; esac
  case "$2" in ""|.*|*/*/*|*..*) return 0 ;; */*) [[ "$2" == @* ]] || return 0 ;; esac
  local t="${3%/*}/node_modules/$2"
  [ -d "$t" ] && [ ! -L "$t" ] && x_related npm_installed "$t"
  return 0
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
      # findings 1.1: kind / subject。ロックファイル（npm）の finding は、隣にインストールされた実体
      #   <dir>/node_modules/<name>（シンボリックリンクではないディレクトリ）を related npm_installed に入れる
      local x kind
      if [ "$match" = "vulnerable_versions" ]; then
        x="$(x_subject "$eco" "$dname" "$dver" "$safev" "$safev")"; kind="pkg.vulnerable"
      else
        x="$(x_subject "$eco" "$dname" "$dver" "$safev")"
        kind="$(pkg_kind "$dsrc")"
      fi
      x="$(x_join "$(x_kind "$kind")" "$x" "$(pkg_related "$eco" "$dname" "$dsrc")")"
      if [ "$hit" -eq 1 ] && [ "$match" = "vulnerable_versions" ]; then
        high "$camp" "$dsrc" "脆弱なバージョン ${dname}@${dver:-?}（${eco}、悪性ではなく CVE の影響範囲）${safev:+。修正版: $safev 以上}" "" "$x"
      elif [ "$hit" -eq 1 ]; then
        critical "$camp" "$dsrc" "侵害パッケージ ${dname}@${dver:-?} を検出（${eco}）${safev:+。安全版: $safev}" "" "$x"
      elif [ "$match" = "unknown_versions" ]; then
        medium "$camp" "$dsrc" "侵害報告のあるパッケージ ${dname}@${dver:-?}（侵害版の特定バージョン未定義のため要確認）" "" "$x"
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
    #   -z（NUL 区切り・ファイル名のエスケープなし）を使う。名前の \ / 改行 / CR を sha256sum がエスケープすると
    #   パスが変わるため。-z に対応しない sha256sum（busybox 等）は 1 ファイルずつ標準入力から計算する
    if printf '' | sha256sum -z >/dev/null 2>&1; then
      tr '\n' '\0' <"$FILES_LIST" | xargs -0 sha256sum -z -- 2>/dev/null | tr '\0' '\n'
    else
      while IFS= read -r f; do printf '%s  %s\n' "$(sha256_file "$f")" "$f"; done <"$FILES_LIST"
    fi | awk 'NR==FNR {want[$1]=1; next}
          ($1 in want) { h=$1; sub(/^[0-9a-f]+ [ *]/,""); print h "\t" $0 }' "$TMP_DIR/intel_sha.lst" - \
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
        if printf '%s\n' "$bad" | tr ',' '\n' | grep_q -x -F -- "$ref"; then
          critical "$camp" "$f" "侵害が報告されたアクション ${act}@${ref}"
        elif [ -n "$safe" ] && ! printf '%s\n' "$safe" | tr ',' '\n' | grep_q -x -F -- "$ref" && ! [[ "$ref" =~ ^[0-9a-f]{40}$ ]]; then
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
        while IFS= read -r d; do
          [ -n "$d" ] && [ -d "$d" ] || continue
          ver="${d##*/${id}-}"; ver="${ver%%-*}"
          hit=1
          if [ -n "$bads" ]; then hit=0; local b; for b in ${bads//,/ }; do version_matches_spec "$ver" "$b" && hit=1; done; fi
          [ "$hit" -eq 1 ] && lvl_emit "$sev" "$camp" "$d" "悪性・侵害が報告された IDE 拡張（${id} ${ver}）"
        done < <(for d in "$HOME_DIR"/.vscode/extensions/"$id"-[0-9]* "$HOME_DIR"/.vscode-server/extensions/"$id"-[0-9]* "$HOME_DIR"/.cursor/extensions/"$id"-[0-9]* "$HOME_DIR"/.windsurf/extensions/"$id"-[0-9]*; do printf '%s\n' "$d"; done
                 files_path "/extensions/${id}-[0-9][^/]*/package\.json$" | sed -E 's#/package\.json$##')
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
        # パスの種類ごとに照合先を分ける（検査ルート内の同名サフィックスを一律に照合すると誤検知になるため）
        #   ~/… / $HOME/…   … 検査対象 HOME（ZES_HOME）配下の実パスのみ
        #   /… / $TMPDIR/…  … ホストの実パスのみ（ZES_HOST_CHECKS=0 では見ない）
        #   それ以外（site-packages/cook.pth 等の相対パス）… 検査ルート内のサフィックス一致
        e=""
        case "$val" in
          "~/"*|'$HOME/'*) e="$(expand_home "$val")" ;;
          '$TMPDIR/'*) host_enabled && e="${TMPDIR:-/tmp}/${val#\$TMPDIR/}" ;;
          /*) host_enabled && e="$val" ;;
          *)
            while IFS= read -r f; do [ -n "$f" ] && lvl_emit "$sev" "$camp" "$f" "既知のマルウェア痕跡パス（検査ルート内）"; done < <(files_path "/$(printf '%s' "$val" | sed 's/[.[\*^$+?(){}|]/\\&/g')\$")
            ;;
        esac
        if [ -n "$e" ]; then
          # 空白を含むパス（Application Support 等）を分割せず、グロブ文字のみ展開する
          local IFS=$'\n'
          for f in $e; do [ -e "$f" ] || [ -L "$f" ] && lvl_emit "$sev" "$camp" "$f" "既知のマルウェア痕跡パス"; done
          unset IFS
        fi
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
    ZES_V_N="$name" awk 'BEGIN { n = ENVIRON["ZES_V_N"] } {c=$2; sub(/.*\//,"",c); if (c==n) print $1}' "$TMP_DIR/ps.txt" | while IFS= read -r pid; do
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
      version_branch_vulnerable "${ver#v}" "${fx[@]}" && lvl_emit "$sev" "" "$f" "${iid} ${ver} は ${cve}${cvss:+（CVSS ${cvss}）}の影響範囲（修正版: ${fixed//,/ }）" "" "$(x_kind runtime.cve)"
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
    version_branch_vulnerable "$v" "${fx[@]}" && lvl_emit "$sev" "" "$(command -v "$bin")" "${bin} ${v} は ${cve} の影響範囲（修正版: ${fixed//,/ }）。ディストリビューションのバックポート有無を確認" "" "$(x_kind runtime.cve)"
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
      [ -n "$v" ] && version_lt "$v" "$fixed" && lvl_emit "$sev" "$camp" "$f" "${bundle%.app} ${v} は ${cve} の影響範囲（修正版 ${fixed}）" "" "$(x_kind runtime.cve)"
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
      [ -n "$f" ] || continue
      # エージェントの設定ファイルのフックなら、その文字列を含むフックの位置を locators に入れる
      local x=""
      case "$f" in */.claude/settings.json|*/.claude/settings.local.json) x="$(x_locators "$(json_ptr_locators "$f" "$HOOK_PATHS_STR" --arg s "$str")")" ;; esac
      lvl_emit "$sev" "$camp" "$f" "既知の攻撃キャンペーンの文字列（${camp}）" "" "$x"
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
    local IFS=$'\n'
    for f in $m; do [ -e "$f" ] && critical "" "$f" "侵害マーカーを検出（$m）"; done
    unset IFS
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
# 標準の .pth の import 行（行全体で一致したものだけを許可）
PTH_SAFE_RE='[[:space:]]*import[[:space:]]+_virtualenv[[:space:]]*'
PTH_SAFE_RE+="|import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os\.environ\.get\(var, '(local|stdlib)'\) == 'local'; enabled and __import__\('_distutils_hack'\)\.add_shim\(\); *"
PTH_SAFE_RE+='|[[:space:]]*import[[:space:]]+(__editable___[A-Za-z0-9_]+_finder|_editable_impl_[A-Za-z0-9_]+)[[:space:]]*(;[[:space:]]*(__editable___[A-Za-z0-9_]+_finder|_editable_impl_[A-Za-z0-9_]+)\.install\([^()]*\)[[:space:]]*)?'
# package.json のライフサイクルスクリプト（install 系と prepare 系。prepare は git 依存の取得時・npm install 時にも実行される）
PKG_HOOK_RE='^(pre|post)?(install|prepare)$'
check_s2() {
  log_section "§2" "Python/Nodeフック"
  local f
  while IFS= read -r f; do [ -n "$f" ] && critical "litellm-oct2026" "$f" "悪性フックファイル（${f##*/}）を検出"; done < <(files_named '^cook\.(pth|py)$')
  while IFS= read -r f; do [ -n "$f" ] && high "litellm-oct2026" "$f" "Python起動時自動実行フック（${f##*/}）"; done < <(files_named '^(sitecustomize|usercustomize)\.py$')
  # .pth の import 行は Python 起動のたびに exec される。標準の形（virtualenv の _virtualenv、setuptools の
  # distutils-precedence、PEP 660 editable の __editable___*_finder / _editable_impl_*）以外の import 行は MEDIUM、
  # 難読化・通信・実行（exec/eval/compile/os.system/popen/getattr/__import__ 等）を伴うものは HIGH
  local pthl
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    pthl="$(text_lines "$f" | grep -a -E '^[[:space:]]*import[[:space:]]' \
      | grep -a -v -x -E "$PTH_SAFE_RE")"
    [ -n "$pthl" ] || continue
    if printf '%s\n' "$pthl" | grep_q -a -E '(^|[^A-Za-z0-9_])(exec|eval|compile|getattr|popen|system|__import__)[[:space:]]*\(|b64decode|subprocess|urllib|socket|fromhex|marshal|zlib|codecs|pickle|ctypes|requests'; then
      high "litellm-oct2026" "$f" ".pth ファイルに起動時実行コード（import + exec/eval/system/通信）"
    else
      medium "litellm-oct2026" "$f" ".pth ファイルに起動時に実行される import 行（標準の virtualenv / editable 形式以外。内容を確認）"
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
    local pq='(.scripts // {}) | if type == "object" then to_entries[] | select(.key | test($re)) | .value | tostring else empty end'
    if [ "$HAVE_JQ" -eq 1 ]; then
      # 厳密な JSON として読めなければ（BOM・末尾カンマ等）JSONC として読み直し、それでも駄目なら grep で拾う
      scripts="$(jq -r --arg re "$PKG_HOOK_RE" "$pq" "$f" 2>/dev/null)" \
        || scripts="$(jsonc_to_json "$f" | jq -r --arg re "$PKG_HOOK_RE" "$pq" 2>/dev/null)" \
        || scripts="$(grep -a -E '"(pre|post)?(install|prepare)"[[:space:]]*:' "$f" 2>/dev/null)"
    else
      scripts="$(grep -a -E '"(pre|post)?(install|prepare)"[[:space:]]*:' "$f" 2>/dev/null)"
    fi
    [ -n "$scripts" ] || continue
    if printf '%s' "$scripts" | grep_q -E '(curl|wget|bash|sh -c|base64|eval|node -e|\.mjs|https?://)'; then
      high "" "$f" "install / prepare ライフサイクルスクリプトに不審なコマンド"
    elif [[ "$f" != */node_modules/* ]]; then
      medium "" "$f" "install / prepare ライフサイクルスクリプトが定義されています（ignore-scripts 推奨）"
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
        critical "" "$f" "GitLab ${ver} は ${cve}（${gcvss[$cve]:-CVSS 9 以上}）の影響範囲（修正版: ${gfix[*]}。系列に修正版が無い場合は ${gfix[0]} 以降へ移行）" "" "$(x_kind runtime.cve)"
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
    high "" "" "GitLab プロセスが稼働中（ps）。バージョンと修正適用を確認してください"
    found=1
  fi
  [ "$found" -eq 0 ] && safe "GitLab の痕跡なし"
  return 0
}

# §4 PHP
# php_status VERSION → vulnerable / fixed / prerelease / unknown_branch / unparsed（PHP2Shell、upstream 版番号での判定）
#   判定は openai/php2shell-checker（Apache-2.0）の versionStatus と同じ意味論:
#   - x.y.z の後ろが -,+,~ 以外で始まる・x.y.z でない → unparsed（要確認）
#   - dev / alpha / beta / RC 等のプレリリース → prerelease（x.y.z 部分だけで修正済みと判断しない）
#   - 5.4〜8.1（公式の修正リリースなし）→ vulnerable、修正版のあるブランチ（8.2〜8.5）→ パッチ番号で判定
#   - 修正版一覧にない新しいブランチ（8.6+ / 9.x 等）や 5.3 以前 → unknown_branch（修正済み扱いにしない）
php_status() {
  local v="${1#v}" maj min pat suf br fx
  [[ "$v" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(.*)$ ]] || { echo unparsed; return 0; }
  maj="${BASH_REMATCH[1]}"; min="${BASH_REMATCH[2]}"; pat="${BASH_REMATCH[3]}"; suf="${BASH_REMATCH[4]}"
  if printf '%s' "$suf" | grep_q -i -E '(^|[-+~.])(dev|alpha|beta|rc)'; then echo prerelease; return 0; fi
  case "$suf" in ''|[-+~]*) ;; *) echo unparsed; return 0 ;; esac
  br="$((10#$maj)).$((10#$min))"
  if read_ioc '.php2shell_distro.older_branches' | grep_q -x -F -- "$br"; then echo vulnerable; return 0; fi
  fx="$(read_ioc '.php2shell_distro.upstream_fixed' | ZES_V_B="$br" awk -F. 'BEGIN { b = ENVIRON["ZES_V_B"] } $1 "." $2 == b { print $3; exit }')"
  [ -n "$fx" ] || { echo unknown_branch; return 0; }
  if [ "$((10#$pat))" -lt "$fx" ]; then echo vulnerable; else echo fixed; fi
}

# deb_version_lt A B … Debian のバージョン順序（epoch:upstream-revision、~ は空より前）で A < B なら真
deb_version_lt() {
  ZES_V_A="$1" ZES_V_B="$2" awk 'BEGIN { a = ENVIRON["ZES_V_A"]; b = ENVIRON["ZES_V_B"] } 
    function ord(c) { if (c == "~") return -1; if (c ~ /[A-Za-z]/) return O[c]; return O[c] + 256 }
    function isd(c) { return c ~ /^[0-9]$/ }
    function vrc(x, y,   cx, cy, dx, dy) {
      while (x != "" || y != "") {
        while ((x != "" && !isd(substr(x, 1, 1))) || (y != "" && !isd(substr(y, 1, 1)))) {
          cx = (x != "" && !isd(substr(x, 1, 1))) ? ord(substr(x, 1, 1)) : 0
          cy = (y != "" && !isd(substr(y, 1, 1))) ? ord(substr(y, 1, 1)) : 0
          if (cx != cy) return cx < cy ? -1 : 1
          x = substr(x, 2); y = substr(y, 2) }
        match(x, /^[0-9]*/); dx = substr(x, 1, RLENGTH); x = substr(x, RLENGTH + 1)
        match(y, /^[0-9]*/); dy = substr(y, 1, RLENGTH); y = substr(y, RLENGTH + 1)
        sub(/^0+/, "", dx); sub(/^0+/, "", dy)
        if (length(dx) != length(dy)) return length(dx) < length(dy) ? -1 : 1
        if (dx != dy) return dx < dy ? -1 : 1 }
      return 0 }
    function split3(v, P,   k) {
      P[1] = 0; if (match(v, /^[0-9]+:/)) { P[1] = substr(v, 1, RLENGTH - 1) + 0; v = substr(v, RLENGTH + 1) }
      P[3] = ""; k = 0; while (match(substr(v, k + 1), /-/)) k += RSTART
      if (k > 0) { P[3] = substr(v, k + 1); v = substr(v, 1, k - 1) }
      P[2] = v }
    BEGIN { for (k = 33; k < 127; k++) O[sprintf("%c", k)] = k
      split3(a, A); split3(b, B)
      r = (A[1] != B[1]) ? (A[1] < B[1] ? -1 : 1) : vrc(A[2], B[2]); if (r == 0) r = vrc(A[3], B[3])
      exit (r < 0 ? 0 : 1) }'
}

# os-release（通常ファイルのみ）から ID<TAB>VERSION_ID
os_release_id() {
  local f
  for f in "$1/etc/os-release" "$1/usr/lib/os-release"; do
    [ -f "$f" ] || continue
    # 検査ルート内のイメージ展開物はルート外（/proc 等）を指すリンクを読まない
    [ -z "$1" ] || in_root_regular "$f" || continue
    text_lines "$f" | awk -F= '$1 == "ID" || $1 == "VERSION_ID" { v = $2; gsub(/^["\047]|["\047]$/, "", v); r[$1] = v }
      END { print r["ID"] "\t" r["VERSION_ID"] }' 2>/dev/null
    return 0
  done
  printf '\t\n'
}

# PHP2Shell: dpkg のパッケージ DB（/var/lib/dpkg/status。ROOT 内のコンテナイメージ展開物も対象）を静的に読み、
# 実際に配信に使われるパッケージ（php*-fpm / libapache2-mod-php* / php*-cgi / php*-cli）をベンダー修正版と比較する
#   出力: php_distro_packages が判定したパッケージ数（ホストの dpkg を判定できたら 0 以外）
php_distro_packages() {
  local f base id vid pkg ver src row fixed adv url note n=0
  note="パッケージが修正済みでも、稼働中の PHP-FPM / Apache ワーカーが更新後に再起動されたか（配信中のバイナリ）を確認"
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    awk 'BEGIN { RS = "" } {
        p = ""; v = ""; s = ""; st = ""
        n = split($0, L, "\n")
        for (i = 1; i <= n; i++) {
          if (L[i] ~ /^Package: /) p = substr(L[i], 10)
          else if (L[i] ~ /^Version: /) v = substr(L[i], 10)
          else if (L[i] ~ /^Source: /) { s = substr(L[i], 9); sub(/ .*/, "", s) }
          else if (L[i] ~ /^Status: /) st = substr(L[i], 9) }
        if (st !~ /installed$/ || st ~ /not-installed|config-files/) next
        if (p !~ /^(php[0-9.]*-(fpm|cgi|cli)|libapache2-mod-php[0-9.]*)$/) next
        if (s == "") { s = p; sub(/^libapache2-mod-/, "", s); sub(/-(fpm|cgi|cli)$/, "", s) }
        print p "\t" v "\t" s }' "$f" >"$TMP_DIR/php-dpkg.tsv" 2>/dev/null
    [ -s "$TMP_DIR/php-dpkg.tsv" ] || continue
    if [ "$HAVE_JQ" -ne 1 ]; then record_error "§4" "php_distro_table_jq_unavailable:$f"; continue; fi
    base="${f%/var/lib/dpkg/status}"
    IFS=$'\t' read -r id vid < <(os_release_id "$base")
    while IFS=$'\t' read -r pkg ver src; do
      [ -n "$pkg" ] || continue
      n=$((n + 1))
      row="$(jq -r --arg v "$id" --arg r "$vid" --arg s "$src" '.php2shell_distro.packages[]? | select(.vendor == $v and .release == $r and .source_package == $s) | [.fixed, .advisory, .url] | @tsv' "$IOC_FILE" 2>/dev/null | head -n1)"
      if [ -z "$row" ]; then
        medium "" "$f" "${pkg} ${ver}（${id:-OS 不明} ${vid}、ソース ${src}）: PHP2Shell（CVE-2026-109618/109619）の対応するベンダー勧告を特定できません。修正状況は不明（ベンダーの勧告で確認）。${note}"
        continue
      fi
      IFS=$'\t' read -r fixed adv url <<<"$row"
      if deb_version_lt "$ver" "$fixed"; then
        high "" "$f" "${pkg} ${ver}（${id} ${vid}）は PHP2Shell（CVE-2026-109618/109619）のベンダー修正版 ${fixed}（${adv} ${url}）未満。潜在的に脆弱。${note}"
      else
        info "" "$f" "${pkg} ${ver}（${id} ${vid}）は PHP2Shell のベンダー修正版 ${fixed}（${adv}）以上。${note}"
      fi
    done <"$TMP_DIR/php-dpkg.tsv"
  done < <(host_enabled && echo /var/lib/dpkg/status; files_path '/var/lib/dpkg/status$')
  echo "$n"
}

check_s4() {
  log_section "§4" "PHP"
  local f
  local -a pfix; mapfile -t pfix < <(infra_fixed php CVE-2026-109618)
  php_judge() {  # php_judge VERSION PATH SOURCE(upstream|distro|header)
    local ver="$1" path="$2" src="$3" st
    st="$(php_status "$ver")"
    local eol=""; [[ "$ver" =~ ^v?([0-9]+)\.([0-9]+)\. ]] && version_lt "${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.0" "8.2.0" && eol="（8.1 以前は公式の修正リリースなし。サポート版へ移行）"
    case "$src:$st" in
      *:fixed) [ "$src" = "header" ] && safe "PHP ${ver}（ヘッダ申告）は upstream 修正版以上（インストール自体は未検証）" ;;
      *:prerelease) medium "" "$path" "PHP ${ver} はプレリリース版（dev/alpha/beta/RC）。PHP2Shell（CVE-2026-109618/109619）の修正有無を版番号から判断できません（要確認）" ;;
      *:unknown_branch) medium "" "$path" "PHP ${ver} は PHP2Shell の修正版一覧（${pfix[*]}）にないブランチ。修正済みとは判断できません（要確認）" ;;
      *:unparsed) medium "" "$path" "PHP のバージョン表記（${ver}）を解釈できません。PHP2Shell（CVE-2026-109618/109619）の修正状況は不明（要確認）" ;;
      distro:vulnerable) high "" "$path" "PHP ${ver} は PHP2Shell（CVE-2026-109618/109619、認証不要 RCE、悪用試行あり）の upstream 修正版（${pfix[*]}）未満${eol}。ディストリビューションのバックポート有無を確認" ;;
      header:vulnerable) high "" "$path" "PHP ${ver}（HTTP ヘッダで申告された版）は PHP2Shell（CVE-2026-109618/109619）の影響範囲の可能性（潜在的に脆弱）${eol}。ヘッダではバックポートの有無を判断できないため、サーバー上のパッケージを確認" ;;
      *:vulnerable) critical "" "$path" "PHP ${ver} は PHP2Shell（CVE-2026-109618/109619、認証不要 RCE、悪用試行あり）の影響範囲（修正版: ${pfix[*]}）${eol}" ;;
    esac
  }
  local ndeb; ndeb="$(php_distro_packages)"
  if host_enabled; then
    local v
    v="$(safe_probe php -n -v | head -n1 | awk '{print $2}')"
    if [ -n "$v" ]; then
      info "" "" "PHP ${v} がインストールされています"
      case "$v" in
        *ubuntu*|*deb*|*el[0-9]*|*fc[0-9]*|*-[0-9]*)
          # dpkg のパッケージ DB でベンダー修正版と比較できた場合は、版番号だけの判定（バックポート不明）を重ねない
          if [ "${ndeb:-0}" -gt 0 ]; then log_info "PHP ${v}: dpkg のパッケージ版で判定済み"; else php_judge "$v" "$(command -v php)" distro; fi ;;
        *) php_judge "$v" "$(command -v php)" upstream ;;
      esac
      if [ -f /etc/redhat-release ]; then
        local rows; rows="$(intel_jq '.php2shell_distro.packages[]? | select(.vendor == "rhel") | "RHEL \(.release) \(.source_package) ≥ \(.fixed)（\(.advisory)）"' | paste -sd'/' -)"
        medium "" "/etc/redhat-release" "RHEL 系: rpm DB は静的に読めないため PHP2Shell の修正状況を判定できません。配信中の php-fpm / mod_php の所有パッケージを rpm -qf で確認し、ベンダー修正版と比較（${rows:-Red Hat の CVE-2026-109618/109619 情報を参照}）"
      fi
    fi
  fi
  local ver
  while IFS=$'\t' read -r ver f; do
    [ -n "$ver" ] && php_judge "$ver" "$f" upstream
  done < <(detect_service_version '(^|[[:space:]/"=])php' | awk -F'\t' '{ v = $1; sub(/^[^0-9]*/, "", v); if (v != "") print v "\t" $2 }')  # latest 等の浮動タグは下の FROM 検査で扱う
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    ver="$(text_lines "$f" | grep -E '^php[[:space:]]+[0-9]' | head -n1 | awk '{print $2}')"
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
    fgrep_q '^[[:space:]]*auto_prepend_file[[:space:]]*=[[:space:]]*[^[:space:];]' "$f" && high "" "$f" "php.ini の auto_prepend_file が設定されています（全リクエストで実行）" "" \
      "$(x_text_locators "$f" '^[[:space:]]*auto_prepend_file[[:space:]]*=[[:space:]]*[^[:space:];]')"
    fgrep_q '^[[:space:]]*disable_functions[[:space:]]*=[[:space:]]*$' "$f" && medium "" "$f" "php.ini の disable_functions が空欄" "" \
      "$(x_text_locators "$f" '^[[:space:]]*disable_functions[[:space:]]*=[[:space:]]*$')"
  done < <(files_named '^php.*\.ini$'; host_enabled && ls /etc/php*/php.ini /etc/php/*/*/php.ini /usr/local/etc/php/php.ini 2>/dev/null)
  if [ -n "$TARGET_URL" ]; then
    if [ "$OFFLINE" = "1" ]; then record_error "§4" "skipped_offline"; return 0; fi
    # ヘッダのみ取得（HEAD。405/501 のときだけ GET）。リダイレクトは追わない・本文は読まない・~/.curlrc は読まない（-q）
    local hdrs code
    hdrs="$(curl -q -sS -I --connect-timeout 5 --max-time 10 --proto '=http,https' -- "$TARGET_URL" 2>/dev/null | tr -d '\r')"
    code="$(printf '%s\n' "$hdrs" | awk '/^HTTP\// { c = $2 } END { print c }')"
    if [ "$code" = "405" ] || [ "$code" = "501" ]; then
      hdrs="$(curl -q -sS -o /dev/null -D - --connect-timeout 5 --max-time 10 --max-filesize 1048576 --proto '=http,https' -- "$TARGET_URL" 2>/dev/null | tr -d '\r')"
      code="$(printf '%s\n' "$hdrs" | awk '/^HTTP\// { c = $2 } END { print c }')"
    fi
    if [ -z "$code" ]; then record_error "§4" "url_fetch_failed"; return 0; fi
    local xpb srv pv st best="" bst=""
    # 同名ヘッダが複数ある場合は全て見る（最後の応答のヘッダのみ。値は "; " で連結）
    hdrs="$(printf '%s\n' "$hdrs" | awk '/^HTTP\// { b = "" } { b = b $0 "\n" } END { printf "%s", b }')"
    xpb="$(printf '%s\n' "$hdrs" | grep -i '^x-powered-by:' | sed -E 's/^[^:]*:[[:space:]]*//' | paste -sd';' - | sed 's/;/; /g')"
    srv="$(printf '%s\n' "$hdrs" | grep -i '^server:' | sed -E 's/^[^:]*:[[:space:]]*//' | paste -sd';' - | sed 's/;/; /g')"
    [ -n "$xpb" ] && medium "" "" "${TARGET_URL}: X-Powered-By ヘッダでバージョンを露出: ${xpb}"
    printf '%s' "$srv" | grep_q -i -E '(^|[^A-Za-z])PHP[ /]' && medium "" "" "${TARGET_URL}: Server ヘッダで PHP のバージョンを露出: ${srv}"
    # 両ヘッダの PHP/x.y.z を全て判定し、警告（vulnerable）> 不明 > 修正済み の順で最も悪いものを採用（安心材料を優先しない）
    while IFS= read -r pv; do
      [ -n "$pv" ] || continue
      st="$(php_status "$pv")"
      if [ -z "$best" ] || [ "$st" = "vulnerable" ] || { [ "$bst" = "fixed" ] && [ "$st" != "fixed" ]; }; then best="$pv"; bst="$st"; fi
      [ "$bst" = "vulnerable" ] && break
    done < <(printf '%s\n%s\n' "$srv" "$xpb" | grep -o -i -E '(^|[^A-Za-z])PHP[ /][^[:space:],;)]+' | sed -E 's/^[^Pp]*[Pp][Hh][Pp][ \/]//')
    if [ -n "$best" ]; then php_judge "$best" "" header
    else safe "PHP のバージョンを示すヘッダなし（$TARGET_URL。修正状況はヘッダからは不明）"; fi
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
      high "" "$path" "Python ${ver} は修正版（${mins[*]} 以降）未満" "" "$(x_kind runtime.cve)"
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
      curl -q -sI --connect-timeout 5 --max-time 10 --proto '=https' -o /dev/null -- "https://$host/" 2>/dev/null
      local rc=$?
      case "$rc" in
        0) critical "$camp" "" "危殆化した eMudhra 中間 CA をシステムの curl が信頼しています（https://$host/ への接続成功）" ;;
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
    [ -n "$v" ] && [[ "$v" < "$min" ]] && high "$camp" "$d/$v" "Homebrew ca-certificates ${v} は ${min} 未満（eMudhra 侵害 CA が未除去）" "" "$(x_kind runtime.cve)"
  done
  min="$(read_ioc '.runtime_minimums.certifi')"
  build_deps
  awk -F'\t' '$1=="pypi" && $2=="certifi" {print $3"\t"$4}' "$DEPS_TSV" | tsv_us | while IFS="$US" read -r v d; do
    version_lt "$v" "$min" && high "$camp" "$d" "certifi ${v} は ${min} 未満（eMudhra 失効が未反映）" "" "$(x_kind runtime.cve)"
  done
  local -a gmins; mapfile -t gmins < <(read_ioc '.runtime_minimums.go')
  if host_enabled; then
    # go version は telemetry 子プロセスを起動するため実行せず、GOROOT/VERSION を静的に読む
    local gobin goroot
    gobin="$(command -v go 2>/dev/null)" && gobin="$(resolve_path "$gobin")" && goroot="$(dirname -- "$(dirname -- "$gobin")")"
    v=""
    [ -n "${goroot:-}" ] && [ -f "$goroot/VERSION" ] && v="$(head -n1 "$goroot/VERSION" | grep -o -E 'go[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n1)"
    v="${v#go}"
    [ -n "$v" ] && version_branch_vulnerable "$v" "${gmins[@]}" && high "" "$(command -v go)" "Go ${v} は ${gmins[*]} 未満" "" "$(x_kind runtime.cve)"
  fi
  while IFS= read -r d; do
    [ -n "$d" ] || continue
    v="$(grep -E '^(toolchain go|go )[0-9]' "$d" | tail -n1 | grep -o -E '[0-9]+\.[0-9]+(\.[0-9]+)?')"
    [ -n "$v" ] || continue
    [[ "$v" =~ ^[0-9]+\.[0-9]+$ ]] && v="$v.0"
    version_branch_vulnerable "$v" "${gmins[@]}" && medium "" "$d" "go.mod の Go ${v} は ${gmins[*]} 未満（証明書ストア更新を含む修正版を使用）" "" "$(x_kind runtime.cve)"
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
    # 段落（パッケージ）単位で読み、Status がインストール済みのものだけを対象にする（削除済み・config-files は除く。§4 と同じ）
    v="$(awk 'BEGIN { RS = "" } {
        p = ""; ver = ""; st = ""
        n = split($0, L, "\n")
        for (i = 1; i <= n; i++) {
          if (L[i] ~ /^Package: /) p = substr(L[i], 10)
          else if (L[i] ~ /^Version: /) ver = substr(L[i], 10)
          else if (L[i] ~ /^Status: /) st = substr(L[i], 9) }
        if (p != "ca-certificates") next
        if (st !~ /installed$/ || st ~ /not-installed|config-files/) next
        print ver; exit }' "$f" 2>/dev/null)"
    [ -n "$v" ] || continue
    local min_ub; min_ub="$(read_ioc '.emudhra.os_ca_certificates.ubuntu_min_upstream')"
    # ベンダーは同じイメージの os-release から判定する（Ubuntu の SRU 版 20260601~24.04.1 は "ubuntu" を含まない）
    local osid=""; IFS=$'\t' read -r osid _ < <(os_release_id "${f%/var/lib/dpkg/status}")
    if [[ "$v" == *ubuntu* ]] || [ "$osid" = "ubuntu" ]; then
      [ "${v:0:8}" -lt "${min_ub:-20260816}" ] 2>/dev/null && high "$camp" "$f" "ca-certificates ${v}（Ubuntu）は eMudhra 侵害 CA を含む（修正版 ${min_ub}ubuntu0.*）" "" "$(x_kind runtime.cve)"
    elif ! debian_ca_fixed "$v"; then
      high "$camp" "$f" "ca-certificates ${v}（Debian 系）は eMudhra 侵害 CA を含む（修正版 20250419~deb12u2 / 20250419+deb13u1 / 20260816+nmu1）" "" "$(x_kind runtime.cve)"
    fi
  done < <(host_enabled && echo /var/lib/dpkg/status; files_path '/var/lib/dpkg/status$')
  # apk（Alpine / Wolfi / Chainguard）: /lib/apk/db/installed
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    v="$(awk '/^P:ca-certificates$/ {p=1; next} p && /^V:/ {sub(/^V:/,""); print; exit} /^$/ {p=0}' "$f")"
    [ -n "$v" ] || continue
    local amin; amin="$(read_ioc '.emudhra.os_ca_certificates.alpine')"
    [[ "${v%%-r*}" < "${amin%%-r*}" ]] && high "$camp" "$f" "ca-certificates ${v}（apk）は eMudhra 侵害 CA を含む（Alpine 修正版 ${amin}、Chainguard 20260909-r3）" "" "$(x_kind runtime.cve)"
  done < <(host_enabled && echo /lib/apk/db/installed; files_path '/lib/apk/db/installed$')
  # pacman（Arch）: /var/lib/pacman/local/ca-certificates-mozilla-<ver>/
  local d
  for d in /var/lib/pacman/local/ca-certificates-mozilla-*; do
    host_enabled && [ -d "$d" ] || continue
    v="${d##*/ca-certificates-mozilla-}"
    version_lt "${v%-*}" "3.131.1" && high "$camp" "$d" "ca-certificates-mozilla ${v} は eMudhra 侵害 CA を含む（修正版 3.131.1-1）" "" "$(x_kind runtime.cve)"
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
    version_branch_vulnerable "$ver" "$@" && high "$camp" "$path" "${name} ${ver} は eMudhra 侵害 CA を信頼（修正版: $*）" "" "$(x_kind runtime.cve)"
  }
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    v="$(head -n1 "$f" | tr -d '[:space:]' | sed -E 's/^v//')"; judge "Node.js" "$v" "$f" "${nfix[@]}"
  done < <(files_named '^(\.nvmrc|\.node-version)$')
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    # CRLF の .tool-versions でも版を読めるよう text_lines で正規化する
    v="$(text_lines "$f" | grep -E '^nodejs[[:space:]]+' | awk '{print $2}' | head -n1)"; [ -n "$v" ] && judge "Node.js" "$v" "$f" "${nfix[@]}"
    v="$(text_lines "$f" | grep -E '^deno[[:space:]]+' | awk '{print $2}' | head -n1)"; [ -n "$v" ] && judge "Deno" "$v" "$f" "${dfix[@]}"
  done < <(files_named '^\.tool-versions$')
  while IFS=$'\t' read -r v f; do judge "Node.js" "${v#v}" "$f" "${nfix[@]}"; done < <(detect_service_version '(^|[[:space:]/"=])node')
  while IFS=$'\t' read -r v f; do judge "Deno" "${v#v}" "$f" "${dfix[@]}"; done < <(detect_service_version 'denoland/deno')
  while IFS=$'\t' read -r v f; do
    v="${v%%_*}"; v="${v%%+*}"
    [[ "$v" =~ ^8u?([0-9]+) ]] && { [ "${BASH_REMATCH[1]}" -lt "$(read_ioc '.emudhra.fixed.java8_update')" ] && high "$camp" "$f" "Java 8u${BASH_REMATCH[1]} は eMudhra 侵害 CA を信頼（修正版 8u511）" "" "$(x_kind runtime.cve)"; continue; }
    judge "Java" "$v" "$f" "${jfix[@]}"
  done < <(detect_service_version '(eclipse-temurin|amazoncorretto|openjdk|bellsoft/liberica-openjdk-[a-z]+|azul/zulu-openjdk)')
  # ホスト: Docker Desktop（macOS の Info.plist）、mise、rustup（バージョン情報はファイルから読む）
  if host_enabled; then
    for f in /Applications/Docker.app/Contents/Info.plist "$HOME_DIR/Applications/Docker.app/Contents/Info.plist"; do
      [ -f "$f" ] || continue
      v="$(grep -A1 'CFBundleShortVersionString' "$f" | grep -o -E '[0-9]+(\.[0-9]+)+' | head -n1)"
      [ -n "$v" ] && version_lt "$v" "$(read_ioc '.emudhra.fixed.docker_desktop')" && high "$camp" "$f" "Docker Desktop ${v} は eMudhra 侵害 CA を信頼（修正版 $(read_ioc '.emudhra.fixed.docker_desktop')）" "" "$(x_kind runtime.cve)"
    done
  fi
  return 0
}

# AI エージェント/エディタの指示ファイル（§7 / §41）
#   .cursorrules / CLAUDE.md / CLAUDE.local.md / AGENTS.md / GEMINI.md / copilot-instructions.md / .windsurfrules /
#   .clinerules（ファイルまたはディレクトリ配下）/ .cursor/rules/* / .github/instructions/* / .claude/**/*.md
ai_instruction_files() {
  files_named '^(\.cursorrules|CLAUDE\.md|CLAUDE\.local\.md|AGENTS\.md|GEMINI\.md|copilot-instructions\.md|\.windsurfrules|\.clinerules)$'
  files_path '/\.cursor/rules/[^/]+$|/\.clinerules/.+|/\.github/instructions/.+|/\.claude/(.+/)?[^/]+\.md$'
}

# §7 AI/エディタ設定（不可視文字・BiDi・ホモグリフ、Git hooks、runOn: folderOpen）
check_s7() {
  log_section "§7" "AI/エディタ"
  local f
  # 不可視文字: U+200B–200F・U+202A–202E・U+2066–2069・タグ文字（U+E0000–E007F）・異体字セレクタ（U+FE00–FE0D、
  # U+E0100–E01EF、U+FE00–FE0F の 2 連続以上。絵文字の表示用 U+FE0E/FE0F の単独は対象外）による文字列の埋め込み
  local inv=$'\xe2\x80[\x8b-\x8f\xaa-\xae]|\xe2\x81[\xa0-\xa4\xa6-\xa9]|\xf3\xa0[\x80-\x81][\x80-\xbf]|\xef\xb8[\x80-\x8d]|\xf3\xa0[\x84-\x87][\x80-\xbf]|\xef\xb8[\x80-\x8f]\xef\xb8[\x80-\x8f]'
  local cyr=$'[A-Za-z][\xd0\xd1][\x80-\xbf]|[\xd0\xd1][\x80-\xbf][A-Za-z]|[A-Za-z]\xce[\x91-\xbf]|\xce[\x91-\xbf][A-Za-z]'
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    grep -q -a -E -- "$inv" "$f" 2>/dev/null && high "" "$f" "AI指示ファイルに不可視文字/Unicode BiDi 制御文字（U+200B–200F, U+202A–202E, U+2066–2069, タグ文字, 異体字セレクタ）"
    grep -q -a -E -- "$cyr" "$f" 2>/dev/null && medium "" "$f" "AI指示ファイルにラテン文字と混在するキリル/ギリシャ文字（ホモグリフ疑い）"
  done < <(ai_instruction_files)
  # Git hooks（検査ルート直下・入れ子の .git〔gitdir: ファイル・worktree の共有側を含む〕の hooks の非 sample ファイル）
  local hookdir
  while IFS= read -r hookdir; do
    [ -n "$hookdir" ] && [ -d "$hookdir" ] || continue
    for f in "$hookdir"/*; do
      [ -f "$f" ] || continue
      case "$f" in *.sample) continue ;; esac
      if fgrep_q '(curl|wget|base64|nc |/dev/tcp|python[0-9.]* -c|node -e)' "$f"; then
        high "" "$f" "Git hook に通信/難読化コマンド"
      else
        medium "" "$f" "有効な Git hook が存在します（内容を目視確認）"
      fi
    done
  done <"$GIT_HOOKS_LIST"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    fgrep_q '"runOn"[[:space:]]*:[[:space:]]*"folderOpen"' "$f" && high "mcp-poisoning" "$f" "フォルダを開くだけで自動実行されるタスク（runOn: folderOpen）" "" \
      "$(x_locators "$(json_ptr_locators "$f" "$TASK_RUNON_PATHS")")"
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
    if grep -E -o '"resolved"[[:space:]]*:[[:space:]]*"https?://[^/"]+' "$f" 2>/dev/null | sed -E 's#.*://##' | sort -u | grep -v -E "^($re)$" | grep_q .; then
      high "" "$f" "公式レジストリ以外から解決された依存関係（依存関係混乱/タイポスクワット）"
    fi
    fgrep_q '"resolved"[[:space:]]*:[[:space:]]*"(git\+|github:|https?://[^"]*\.tgz#)' "$f" && medium "" "$f" "Git/URL 直接参照の依存関係"
  done < <(files_named '^(package-lock\.json|npm-shrinkwrap\.json)$')
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    grep -q -E '^source = "git\+' "$f" && medium "" "$f" "Cargo.lock に Git ソースの依存関係"
    grep -E '^source = "registry\+' "$f" | grep_q -v 'github.com/rust-lang/crates.io-index\|sparse+https://index.crates.io' && high "" "$f" "Cargo.lock に crates.io 以外のレジストリ"
  done < <(files_named '^Cargo\.lock$')
  return 0
}

# §10 OS 永続化（LaunchAgents/crontab/shell rc/履歴）
check_s10() {
  log_section "§10" "OS永続化"
  local f
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    # findings 1.1: 該当する行を locators（行番号と行の SHA-256）で示す
    local re
    re='(curl|wget)[^|#]*\|[[:space:]]*(ba|z)?sh'
    fgrep_q "$re" "$f" && high "" "$f" "シェル設定に curl|sh 形式のリモート実行" "" "$(x_text_locators "$f" "$re")"
    re='(base64[[:space:]]+(-d|--decode)|\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2})'
    fgrep_q "$re" "$f" && high "" "$f" "シェル設定に難読化コード（base64 -d / \\x エスケープ）" "" "$(x_text_locators "$f" "$re")"
    re='(/tmp/|/dev/shm/|/var/tmp/)[^[:space:]]+[[:space:]]*(&|$)'
    fgrep_q "$re" "$f" && medium "" "$f" "シェル設定から一時領域のプログラムを起動" "" "$(x_text_locators "$f" "$re")"
  done < <(home_rc_paths)
  if [ -d "$HOME_DIR/Library/LaunchAgents" ]; then
    for f in "$HOME_DIR"/Library/LaunchAgents/*.plist; do [ -f "$f" ] && info "" "$f" "LaunchAgent（§30 で詳細検査）"; done
  fi
  if host_enabled && command -v crontab >/dev/null 2>&1; then
    crontab -l 2>/dev/null >"$TMP_DIR/crontab.txt"
    if [ -s "$TMP_DIR/crontab.txt" ]; then
      if grep -v '^[[:space:]]*#' "$TMP_DIR/crontab.txt" | grep_q -E '(curl|wget|base64|/tmp/|/dev/shm/|nc )'; then
        high "" "" "ユーザー crontab（$(id -un 2>/dev/null)）に通信/一時領域実行のエントリ"
      else
        info "" "" "ユーザー crontab（$(id -un 2>/dev/null)）にエントリがあります"
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
  hit=0; for f in "$HOME_DIR/.npmrc" "$RP/.npmrc"; do [ -f "$f" ] && { [ "$f" = "$HOME_DIR/.npmrc" ] || in_root_regular "$f"; } && fgrep_q '^[[:space:]]*ignore-scripts[[:space:]]*=[[:space:]]*true' "$f" && hit=1; done
  host_enabled && [ "${npm_config_ignore_scripts:-${NPM_CONFIG_IGNORE_SCRIPTS:-}}" = "true" ] && hit=1
  [ "$hit" -eq 1 ] && safe "npm ignore-scripts=true" || medium "" "$HOME_DIR/.npmrc" "npm の ignore-scripts=true が未設定"
  hit=0; host_enabled && [ "${PYTHONNOUSERSITE:-}" = "1" ] && hit=1
  home_rc_paths | grep_l 'PYTHONNOUSERSITE=1' | grep_q -v '^/dev/null$' && hit=1
  [ "$hit" -eq 1 ] && safe "PYTHONNOUSERSITE=1" || medium "" "" "PYTHONNOUSERSITE=1 が未設定（ユーザー site-packages 経由のフック実行）"
  hit=0; host_enabled && [ "${PIP_REQUIRE_VIRTUALENV:-}" = "true" ] && hit=1
  home_rc_paths | grep_l 'PIP_REQUIRE_VIRTUALENV=(true|1)' | grep_q -v '^/dev/null$' && hit=1
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
    if mount 2>/dev/null | grep -E "[[:space:]]on[[:space:]]+(/|/home|/Users|$HOME_DIR)[[:space:]]" | grep_q 'noatime'; then
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
      if [ -n "$h" ] && printf '%s\n' "${hashes[@]}" | grep_q -x -F -- "$h"; then
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
      critical "" "$f" "TeamCity ${ver} は CVE-2026-63077（CVSS 9.8, CISA KEV）の影響範囲（修正版: ${tc_fixed[*]}）" "" "$(x_kind runtime.cve)"
    else
      safe "TeamCity ${ver} は修正版以上（$f）"
    fi
  done < <(detect_service_version 'jetbrains/teamcity-server')
  while IFS=$'\t' read -r ver f; do
    [ -n "$ver" ] || continue
    if [ "$ver" = "latest" ]; then medium "" "$f" "Artifactory が浮動タグ（latest）。CVE-2026-82329 の修正版を確認"; continue; fi
    if version_branch_vulnerable "$ver" "${af_fixed[@]}"; then
      critical "" "$f" "JFrog Artifactory ${ver} は CVE-2026-82329（CVSS 9.8）の影響範囲（修正版: ${af_fixed[*]}）" "" "$(x_kind runtime.cve)"
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
    NR == 1 { sub(/^\357\273\277/, "") }   # UTF-8 BOM（VS Code の JSONC パーサは受け付ける）
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

# Codex CLI の .codex/config.toml から MCP サーバーの command/args を 1 行ずつ出力する TOML パーサ（依存なし）
#   1 段目: ファイル全体を字句解析し、全ての値を「種別 US キーパス(\034 区切り) US 値」で出力する。
#     対応: テーブル見出し [a . "b" . 'c'] / [[配列テーブル]]、ドット区切りキー（a.b.c = …、前後の空白可）、
#           基本文字列（\" \\ \n \uXXXX \UXXXXXXXX 等のエスケープを復号）、リテラル文字列、
#           複数行文字列（""" / '''）、入れ子の配列（複数行・コメント・末尾カンマ可、文字列内の ] / # は無視）、
#           インラインテーブル（入れ子可）、その他のスカラー（数値・真偽値・日時）
#     値の中の制御文字（復号後の改行・タブ等）は空白に置き換える（1 行の command 行として照合するため）
#   2 段目: mcp_servers.<name>.command / .args / .url を集め、サーバーごとに "command args…" を出力する。
#     args は配列（要素ごと）と文字列（1 引数として扱う）の両方を受け付ける
#   構文として解釈できない箇所（不正な TOML・未知のエスケープ等）や、command が文字列でない・command も url も
#   無いサーバーは "?<理由>" 行で知らせ、呼び出し側が errors[] に記録する（読めなかった設定を 0 件扱いしない）
codex_toml_mcp_commands() {
  text_lines "$1" | awk '
    function perr(why) { print "?parse_error:" why ":line" line; exit }
    function ch(k) { return substr(S, i + k, 1) }
    function skip_ws() { while (i <= n && (ch(0) == " " || ch(0) == "\t")) i++ }
    function skip_wsnl(   c) {
      while (i <= n) { c = ch(0)
        if (c == " " || c == "\t") i++
        else if (c == "\n") { line++; i++ }
        else if (c == "#") { while (i <= n && ch(0) != "\n") i++ }
        else break } }
    function eol(   c) {
      skip_ws(); if (ch(0) == "#") while (i <= n && ch(0) != "\n") i++
      if (i > n) return
      if (ch(0) != "\n") perr("trailing_characters")
      line++; i++ }
    function hexval(h,   k, v, d) {
      v = 0
      for (k = 1; k <= length(h); k++) { d = index("0123456789abcdef", tolower(substr(h, k, 1))); if (d == 0) return -1; v = v * 16 + d - 1 }
      return v }
    function utf8(cp) {
      if (cp < 32 || cp == 127) return " "
      if (cp < 128) return sprintf("%c", cp)
      if (cp < 2048) return sprintf("%c%c", 192 + int(cp / 64), 128 + cp % 64)
      if (cp < 65536) return sprintf("%c%c%c", 224 + int(cp / 4096), 128 + int(cp / 64) % 64, 128 + cp % 64)
      return sprintf("%c%c%c%c", 240 + int(cp / 262144), 128 + int(cp / 4096) % 64, 128 + int(cp / 64) % 64, 128 + cp % 64) }
    # バックスラッシュの直後（i はエスケープ文字）から 1 文字分を復号する
    function esc(   c, h, cp, L) {
      c = ch(0); i++
      if (c == "\"" || c == "\\") return c
      if (c == "n" || c == "t" || c == "r" || c == "b" || c == "f" || c == "e") return " "
      if (c == "u" || c == "U" || c == "x") {
        L = (c == "u") ? 4 : (c == "U") ? 8 : 2
        h = substr(S, i, L); cp = hexval(h)
        if (length(h) != L || cp < 0 || cp > 1114111) perr("bad_escape")
        i += L; return utf8(cp) }
      perr("bad_escape") }
    function strch(c) { if (c == "\t") return " "; if (c < " " && c != "") perr("control_character"); return c }
    function bstr(   out, c) {
      i++; out = ""
      while (1) { if (i > n) perr("unterminated_string"); c = ch(0)
        if (c == "\"") { i++; return out }
        if (c == "\n") perr("newline_in_string")
        if (c == "\\") { i++; out = out esc(); continue }
        out = out strch(c); i++ } }
    function lstr(   out, c) {
      i++; out = ""
      while (1) { if (i > n) perr("unterminated_string"); c = ch(0)
        if (c == "\047") { i++; return out }
        if (c == "\n") perr("newline_in_string")
        out = out strch(c); i++ } }
    # 複数行文字列。q は区切り文字（" または \047）。閉じ区切りの直前には区切り文字を 2 個まで含められる
    function mlstr(q,   out, c, k, j) {
      i += 3; if (ch(0) == "\n") { line++; i++ }
      out = ""
      while (1) { if (i > n) perr("unterminated_string"); c = ch(0)
        if (c == q && ch(1) == q && ch(2) == q) {
          k = 0; while (ch(k) == q) k++
          if (k > 5) perr("bad_multiline_string")
          for (j = 3; j < k; j++) out = out q
          i += k; return out }
        if (c == "\\" && q == "\"") {
          j = 1; while (ch(j) == " " || ch(j) == "\t") j++
          if (ch(j) == "\n") { i += j; while (i <= n && (ch(0) == " " || ch(0) == "\t" || ch(0) == "\n")) { if (ch(0) == "\n") line++; i++ }; continue }
          i++; out = out esc(); continue }
        if (c == "\n") { line++; out = out " "; i++; continue }
        out = out strch(c); i++ } }
    # キー（ドット区切り・引用キー可）を KS[1..nk] に読む
    function key(   nk, k, c) {
      nk = 0
      while (1) { skip_ws(); c = ch(0)
        if (c == "\"") { if (ch(1) == "\"" && ch(2) == "\"") perr("bad_key"); k = bstr() }
        else if (c == "\047") { if (ch(1) == "\047" && ch(2) == "\047") perr("bad_key"); k = lstr() }
        else { k = ""; while (i <= n && ch(0) ~ /[A-Za-z0-9_-]/) { k = k ch(0); i++ }; if (k == "") perr("bad_key") }
        KS[++nk] = k; skip_ws()
        if (ch(0) == ".") { i++; continue }
        return nk } }
    function rec(t, p, v) { print t "\037" p "\037" v }
    function value(p,   c, t, idx, nk, kp, k) {
      c = ch(0)
      if (c == "\"") { if (ch(1) == "\"" && ch(2) == "\"") t = mlstr("\""); else t = bstr(); rec("s", p, t); return }
      if (c == "\047") { if (ch(1) == "\047" && ch(2) == "\047") t = mlstr("\047"); else t = lstr(); rec("s", p, t); return }
      if (c == "[") {
        i++; idx = 0; rec("a", p, "")
        while (1) { skip_wsnl(); if (i > n) perr("unterminated_array")
          if (ch(0) == "]") { i++; return }
          value(p SUBSEP idx); idx++
          skip_wsnl(); c = ch(0)
          if (c == ",") { i++; continue }
          if (c == "]") { i++; return }
          perr("bad_array") } }
      if (c == "{") {
        i++; rec("t", p, ""); skip_wsnl()
        if (ch(0) == "}") { i++; return }
        while (1) { skip_wsnl(); nk = key(); kp = p; for (k = 1; k <= nk; k++) kp = kp SUBSEP KS[k]
          skip_ws(); if (ch(0) != "=") perr("bad_inline_table"); i++; skip_ws()
          value(kp); skip_wsnl(); c = ch(0)
          if (c == ",") { i++; continue }
          if (c == "}") { i++; return }
          perr("bad_inline_table") } }
      t = ""; while (i <= n && ch(0) ~ /[A-Za-z0-9_+.:-]/) { t = t ch(0); i++ }
      if (t ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/ && ch(0) == " " && ch(1) ~ /[0-9]/) { i++; while (i <= n && ch(0) ~ /[0-9:.Zz+-]/) i++ }
      if (t == "") perr("bad_value")
      rec("o", p, t) }
    BEGIN { RS = "\001" }
    { S = $0; n = length(S); i = 1; line = 1; tbl = ""
      while (1) {
        skip_wsnl(); if (i > n) break
        if (ch(0) == "[") {
          arr = (ch(1) == "["); i += arr ? 2 : 1
          nk = key(); p = KS[1]; for (k = 2; k <= nk; k++) p = p SUBSEP KS[k]
          skip_ws()
          if (arr) { if (ch(0) != "]" || ch(1) != "]") perr("bad_table_header"); i += 2; p = p SUBSEP (AT[p]++) }
          else { if (ch(0) != "]") perr("bad_table_header"); i++ }
          tbl = p; rec("t", p, ""); eol(); continue }
        nk = key(); p = tbl; for (k = 1; k <= nk; k++) p = (k == 1 && p == "") ? KS[1] : p SUBSEP KS[k]
        skip_ws(); if (ch(0) != "=") perr("expected_equals"); i++; skip_ws()
        value(p); eol() } }' | awk -F'\037' '
    /^\?/ { print; next }
    { np = split($2, P, "\034") }
    P[1] != "mcp_servers" { next }
    np == 1 { if ($1 != "t") print "?unexpected_value:mcp_servers"; next }
    { nm = P[2]; if (!(nm in seen)) { seen[nm] = 1; order[++no] = nm } }
    np == 2 { if ($1 != "t") print "?unexpected_value:" nm; next }
    P[3] == "command" && np == 3 { if ($1 == "s") cmd[nm] = $3; else bad[nm] = "unparsed_command"; next }
    P[3] == "args" {
      if ($1 == "s" && (np == 3 || np == 4)) args[nm] = args[nm] (args[nm] == "" ? "" : " ") $3
      else if (!(np == 3 && $1 == "a")) bad[nm] = "unparsed_args"
      next }
    P[3] == "url" && np == 3 { hasurl[nm] = 1 }
    END {
      for (k = 1; k <= no; k++) { nm = order[k]
        if (cmd[nm] != "") print "=" nm "\037" cmd[nm] (args[nm] != "" ? " " args[nm] : "")
        if (nm in bad) print "?" bad[nm] ":" nm
        else if (cmd[nm] == "" && !(nm in hasurl)) print "?no_command:" nm } }'
}

# MCP / エージェント設定の command + args（空白区切りの 1 行）で HIGH とするもの（大文字小文字を区別しない）
#   curl / wget / base64、シェル（sh・bash・zsh・dash・ksh・fish・ash）の -c（-xc・-lc 等の合成、--norc 等の前置オプション可）、
#   node / nodejs / bun の -e・--eval・-p・--print、deno eval、python の -c（-Ic 等）、perl / ruby の -e・-E（-ne 等）、
#   php -r、osascript / lua の -e、pwsh / powershell の -c・-Command・-e・-enc・-EncodedCommand、cmd /c・/k
MCP_OPTS='([[:space:]]+-[^[:space:]]*)*[[:space:]]+'
MCP_DANGER_RE="(^|[[:space:]\"/])(curl|wget)([[:space:]\"]|\$)|base64"
MCP_DANGER_RE+="|(^|[[:space:]\"/])(ba|z|da|k|a|fi)?sh(\.exe)?${MCP_OPTS}-[a-z]*c[a-z]*([[:space:]]|\$)"
MCP_DANGER_RE+="|(^|[[:space:]\"/])(node|nodejs|bun)(\.exe)?${MCP_OPTS}(-e|--eval|-p|--print)([[:space:]=]|\$)|(^|[[:space:]\"/])deno(\.exe)?[[:space:]]+eval([[:space:]]|\$)"
MCP_DANGER_RE+="|(^|[[:space:]\"/])python[0-9.]*(\.exe)?${MCP_OPTS}-[a-z]*c([[:space:]]|\$)"
MCP_DANGER_RE+="|(^|[[:space:]\"/])(perl|ruby)[0-9.]*(\.exe)?${MCP_OPTS}-[a-z]*e([[:space:]]|\$)"
MCP_DANGER_RE+="|(^|[[:space:]\"/])php[0-9.]*(\.exe)?${MCP_OPTS}-r([[:space:]]|\$)|(^|[[:space:]\"/])(osascript|lua[0-9.]*)${MCP_OPTS}-e([[:space:]]|\$)"
MCP_DANGER_RE+="|(^|[[:space:]\"/])(pwsh|powershell)(\.exe)?([[:space:]]+[^[:space:]]+)*[[:space:]]+[-/](c|command|e|ec|enc|encodedcommand)([[:space:]]|\$)"
MCP_DANGER_RE+="|(^|[[:space:]\"/])cmd(\.exe)?[[:space:]]+/[ck]([[:space:]]|\$)"

check_s17() {
  log_section "§17" "MCP静的ポイズニング"
  local f cmdline fmt ptr nm
  # 1 行 1 コマンド: 形式 US JSON pointer（command を持つオブジェクトの位置。例 /mcpServers/<name>）US command args…
  #   command に改行があれば行ごとに分けて照合する（従来どおり）
  local mcpq='path(.. | select(type == "object" and has("command"))) as $p
    | (if ($p | length) == 0 then "" else "/" + ($p | map(tostring | gsub("~"; "~0") | gsub("/"; "~1")) | join("/")) end) as $ptr
    | getpath($p) | ((.command | tostring) + " " + ((.args // []) | if type == "array" then map(tostring) | join(" ") else tostring end))
    | split("\n")[] | $fmt + "\u001f" + $ptr + "\u001f" + .'
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    local -a hi=() me=()
    local loc
    while IFS=$'\037' read -r fmt ptr cmdline; do
      # jq なしでは pointer が分からない（loc は空。finding は出し、locators は出さない）
      loc=""; [ "$HAVE_JQ" -eq 1 ] || [[ "$f" == *.toml ]] && loc="{\"format\":\"$fmt\",\"pointer\":$(jq_str "$ptr")}"
      if printf '%s' "$cmdline" | grep_q -i -E -- "$MCP_DANGER_RE"; then hi+=("$loc")
      elif printf '%s' "$cmdline" | grep_q -E '(^|[[:space:]"/])(npx|uvx|bunx|pnpm dlx)([[:space:]"]|$)'; then me+=("$loc")
      fi
    done < <(
      if [[ "$f" == *.toml ]]; then
        codex_toml_mcp_commands "$f" | while IFS= read -r cmdline; do
          case "$cmdline" in "?"*) record_error "§17" "codex_toml_unparsed:${cmdline#\?}:$f"; continue ;; esac
          cmdline="${cmdline#=}"; nm="${cmdline%%$'\037'*}"
          printf 'toml\037%s\037%s\n' "$(json_pointer mcp_servers "$nm")" "${cmdline#*$'\037'}"
        done
      elif [ "$HAVE_JQ" -eq 1 ]; then
        # 厳密な JSON として読めなければ JSONC（コメント・末尾カンマ）として読み直し、それでも失敗したら errors[]
        jq -r --arg fmt json "$mcpq" "$f" 2>/dev/null \
          || jsonc_to_json "$f" | jq -r --arg fmt jsonc "$mcpq" 2>/dev/null \
          || record_error "§17" "mcp_config_parse_failed:$f"
      else
        # jq なし: "command" とそれに続く "args" を 1 行に連結する（別々の行のままでは "bash" と "-c" が結び付かない）。
        #   位置（pointer）は分からないため locators は出さない
        tr '\n' ' ' <"$f" 2>/dev/null | grep -E -o '"(command|args)"[[:space:]]*:[[:space:]]*("([^"\\]|\\.)*"|\[[^]]*\])' | awk '
          { v = $0; sub(/^"[a-z]+"[[:space:]]*:[[:space:]]*/, "", v); gsub(/^\[|\]$/, "", v); gsub(/"[[:space:]]*,[[:space:]]*"/, " ", v); gsub(/^[[:space:]]*"|"[[:space:]]*$/, "", v)
            if ($0 ~ /^"command"/) { if (cur != "") print "json\037\037" cur; cur = v } else cur = cur " " v }
          END { if (cur != "") print "json\037\037" cur }'
      fi)
    # 同じファイルの同じ種類の問題は 1 件の finding にまとめ、該当するサーバーを locators に並べる（findings 1.1。
    #   同じ pointer は 1 回だけ。command の改行で分けた行は同じサーバーを指す）
    if [ "${#hi[@]}" -gt 0 ]; then
      high "mcp-poisoning" "$f" "MCP/エージェント設定の command/args に危険なコマンド（curl/wget/シェル -c/インタプリタの -e・--eval/powershell -Command 等）" "" \
        "$(x_join "$(x_kind mcp.dangerous_command)" "$(x_locators "$(printf '%s\n' "${hi[@]}" | awk 'NF && !seen[$0]++' | paste -sd, -)")")"
    fi
    if [ "${#me[@]}" -gt 0 ]; then
      medium "mcp-poisoning" "$f" "MCP の command が npx/uvx（実行時に最新版を取得。バージョン固定を確認）" "" \
        "$(x_join "$(x_kind mcp.unpinned)" "$(x_locators "$(printf '%s\n' "${me[@]}" | awk 'NF && !seen[$0]++' | paste -sd, -)")")"
    fi
  done < <(mcp_config_files | sort -u)
  # SymJack: シンボリックリンクがエージェント設定を指す / デコイ名
  local l t base
  while IFS= read -r l; do
    [ -n "$l" ] || continue
    t="$(readlink -- "$l" 2>/dev/null)"
    base="${l#"$RP"/}"
    if printf '%s' "$t" | grep_q -E '(\.claude/|\.mcp\.json|\.cursor/|\.gemini/|\.codex/|\.vscode/settings\.json)'; then
      critical "mcp-poisoning" "$l" "SymJack: シンボリックリンクがエージェント設定（$t）を指しています"
    elif printf '%s' "$base" | grep_q -i -E '(^|/)(vid-|logo\.|readme\.)|^docs/' && [[ "$t" == ../* || "$t" == /* ]]; then
      high "mcp-poisoning" "$l" "SymJack 疑い: デコイ名のリンクが外部（$t）を指しています"
    fi
  done <"$LINKS_LIST"
  # エージェントフック（.claude/settings.json の hooks に通信/難読化）
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if fgrep_q '"hooks"[[:space:]]*:' "$f" && fgrep_q '"command"[[:space:]]*:[[:space:]]*"[^"]*(curl|wget|base64|nc |/dev/tcp)' "$f"; then
      high "mcp-poisoning" "$f" "エージェントフックに通信/難読化コマンド" "" \
        "$(x_locators "$(json_ptr_locators "$f" "$HOOK_PATHS_RE" --arg re '(curl|wget|base64|nc |/dev/tcp)')")"
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
    # ドメインは大文字小文字を区別しない（NPM-CACHE.COM 等で照合を逃れさせない）。表示する一致文字列は小文字に揃える
    grep -v -E '/\.(zsh|bash)_history$' "$FILES_LIST" | tr '\n' '\0' | xargs -0 grep -l -a -i -F -f "$TMP_DIR/$pat.pat" -- /dev/null 2>/dev/null | grep -v '^/dev/null$' | while IFS= read -r f; do
      hit="$(grep -o -a -i -F -f "$TMP_DIR/$pat.pat" -- "$f" 2>/dev/null | tr 'A-Z' 'a-z' | sort -u | head -n3 | tr '\n' ' ')"
      camp="$(grep -i -F -- "$(printf '%s' "$hit" | awk '{print $1}')" "$TMP_DIR/netioc.tsv" | head -n1 | cut -f2)"
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
    grep -q -a -i -F -f "$TMP_DIR/netioc.pat" -- "$hf" 2>/dev/null && critical "" "$hf" "シェル履歴に C2 ドメイン/IP"
    tail -n 5 -- "$hf" 2>/dev/null | grep_q -E '(curl|wget)[^|]*\|[[:space:]]*(ba|z)?sh' && high "" "$hf" "シェル履歴の直近5件に curl|sh 形式の実行"
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
      && grep -E -o '"(url|serverUrl)"[[:space:]]*:[[:space:]]*"http://[^"]+' "$f" | grep_q -v -E 'http://(localhost|127\.0\.0\.1|\[::1\])' \
      && medium "mcp-poisoning" "$f" "平文 HTTP のリモート MCP エンドポイント"
    grep -q -E '"(host|bind|listen)"[[:space:]]*:[[:space:]]*"0\.0\.0\.0"|--host[ =]0\.0\.0\.0' "$f" 2>/dev/null \
      && medium "mcp-poisoning" "$f" "MCP サーバーが 0.0.0.0 で待ち受け（同一ネットワークから到達可能）"
  done < <(mcp_config_files | sort -u)
  intel_strings
  return 0
}

# GitHub Actions ワークフロー一覧
workflow_files() { files_path '/\.github/workflows/[^/]+\.ya?ml$'; }
# ワークフロー本文の正規化（CRLF・BOM 除去、YAML のノード属性・フロー列の展開、値が次行以降に続くキーを 1 行に畳む）
#   1 段目（yaml_flatten）:
#   - ノード属性（アンカー &x・タグ !!str / !tag）を値の先頭とシーケンス項目の先頭から除く（"uses: &co actions/checkout@v4"）
#   - フロー列（"steps: [ {uses: a}, {uses: b, with: {ref: …}} ]"。複数行にまたがるものを含む）を
#     1 要素 1 行のブロック列（"  - {uses: a}"）に展開する
#   - エイリアス（"*x" / "<<: *x"）は参照先を解決しないため "#ZES-YAML-ALIAS" 行を出す（呼び出し側が errors[] に記録）
#   - ブロックスカラー（run: | 等）の中身はそのまま通す
#   2 段目:
#   - ブロックスカラー（"key: >-" / "key: |" 等）: より深くインデントされた後続行を全て空白区切りで連結
#   - 値が空のキーの後にプレーンスカラーが続く場合（"- uses:" の次行に値）: マッピング/シーケンスでない
#     より深い後続行を連結（YAML のプレーンスカラーの複数行折り返し）
#   uses: >-                              - uses:
#     actions/checkout@v4   → uses: actions/checkout@v4      actions/checkout@v4 → - uses: actions/checkout@v4
yaml_flatten() {
  text_lines "$1" | awk '
    function lead(x) { match(x, /^[ \t]*/); return RLENGTH }
    function props(v) { while (match(v, /^(&[^ \t]+|![^ \t]*)([ \t]+|$)/)) v = substr(v, RLENGTH + 1); return v }
    function isalias(v) { return v ~ /^\*[^ \t,\]}]+[ \t]*(#.*)?$/ }
    # 引用符の外側の括弧の深さ（[ { と ] }）
    function depth(x,   i, c, q, d) {
      d = 0; q = ""
      for (i = 1; i <= length(x); i++) { c = substr(x, i, 1)
        if (q != "") { if (c == "\\" && q == "\"") { i++; continue } if (c == q) q = ""; continue }
        if (c == "\"" || c == "\047") { q = c; continue }
        if (c == "#" && (i == 1 || substr(x, i - 1, 1) ~ /[ \t]/)) break
        if (c == "[" || c == "{") d++; else if (c == "]" || c == "}") d-- }
      return d }
    # 引用符の外側の行末コメント（空白 + #）を除く
    function nocomment(x,   i, c, q) {
      q = ""
      for (i = 1; i <= length(x); i++) { c = substr(x, i, 1)
        if (q != "") { if (c == "\\" && q == "\"") { i++; continue } if (c == q) q = ""; continue }
        if (c == "\"" || c == "\047") { q = c; continue }
        if (c == "#" && (i == 1 || substr(x, i - 1, 1) ~ /[ \t]/)) return substr(x, 1, i - 1) }
      return x }
    function item(el, ind) {
      sub(/^[ \t]+/, "", el); sub(/[ \t]+$/, "", el); if (el == "") return
      el = props(el); if (isalias(el)) print "#ZES-YAML-ALIAS"
      print ind "- " el }
    # "[ a, {b: c}, … ]" の最上位の要素を 1 行ずつ出す
    function flow(body, ind,   i, c, q, d, el) {
      sub(/^[ \t]*\[/, "", body); sub(/\][ \t]*(#.*)?$/, "", body)
      d = 0; q = ""; el = ""
      for (i = 1; i <= length(body); i++) { c = substr(body, i, 1)
        if (q != "") { el = el c; if (c == "\\" && q == "\"") { i++; el = el substr(body, i, 1); continue } if (c == q) q = ""; continue }
        if (c == "\"" || c == "\047") { q = c; el = el c; continue }
        if (c == "[" || c == "{") d++; else if (c == "]" || c == "}") d--
        if (c == "," && d == 0) { item(el, ind); el = ""; continue }
        el = el c }
      item(el, ind) }
    function value(pre, v, keyind) {
      v = props(v)
      if (isalias(v) || pre ~ /<<:[ \t]*$/) print "#ZES-YAML-ALIAS"
      if (v ~ /^[|>][-+0-9]*[ \t]*(#.*)?$/) { print pre v; inblk = 1; bind = keyind; return }
      if (v ~ /^\[/) {
        if (depth(v) > 0) { acc = nocomment(v); apre = pre; aind = keyind; return }
        print pre; flow(v, sprintf("%" (keyind + 2) "s", "")); return }
      print pre v }
    {
      line = $0
      if (inblk) { if (line ~ /^[ \t]*$/ || lead(line) > bind) { print line; next } inblk = 0 }
      if (acc != "") {
        t = nocomment(line); sub(/^[ \t]+/, "", t); acc = acc " " t
        if (depth(acc) <= 0) { print apre; flow(acc, sprintf("%" (aind + 2) "s", "")); acc = "" }
        next }
      pre = ""
      if (match(line, /^[ \t]*-([ \t]+|$)/)) {
        pre = substr(line, 1, RLENGTH); rest = substr(line, RLENGTH + 1); rest = props(rest)
        if (isalias(rest)) { print "#ZES-YAML-ALIAS"; print pre rest; next }
        line = pre rest }
      ki = length(pre); if (ki == 0) ki = lead(line)
      if (match(line, /^[ \t]*(-[ \t]+)?["\047]?[A-Za-z0-9_.$<-]+["\047]?:([ \t]+|$)/)) {
        value(substr(line, 1, RLENGTH), substr(line, RLENGTH + 1), ki); next }
      print line }
    END { if (acc != "") { print apre; flow(acc, sprintf("%" (aind + 2) "s", "")) } }'
}
workflow_text() {
  yaml_flatten "$1" | awk '
    pend != "" {
      if ($0 ~ /^[[:space:]]*$/ || (!blk && $0 ~ /^[[:space:]]*#/)) next
      match($0, /^[[:space:]]*/)
      if (RLENGTH > pind && (blk || $0 !~ /^[[:space:]]*(-([[:space:]]|$)|["\047]?[A-Za-z0-9_.$-]+["\047]?:([[:space:]]|$))/)) {
        v = $0; sub(/^[[:space:]]+/, "", v); if (!blk) sub(/[[:space:]]+#.*$/, "", v); sub(/[[:space:]]+$/, "", v)
        acc = acc (acc == "" ? "" : " ") v; next }
      print pend (acc != "" ? " " acc : ""); pend = ""; acc = ""
    }
    /^[[:space:]]*(-[[:space:]]+)?["\047]?[A-Za-z0-9_.$-]+["\047]?:[[:space:]]*([>|][-+0-9]*)?[[:space:]]*(#.*)?$/ {
      match($0, /^[[:space:]]*/); pind = RLENGTH
      if ($0 ~ /^[[:space:]]*-[[:space:]]/) { t = $0; sub(/^[[:space:]]*-[[:space:]]+/, "", t); pind = length($0) - length(t) - 1 }
      pend = $0; sub(/[[:space:]]*(#.*)?$/, "", pend)
      blk = (pend ~ /:[[:space:]]*[>|][-+0-9]*$/)
      sub(/[[:space:]]*[>|][-+0-9]*$/, "", pend); acc = ""; next
    }
    { print }
    END { if (pend != "") print pend (acc != "" ? " " acc : "") }'
}

# §21 GitHub Actions 危険パターン
check_s21() {
  log_section "§21" "GitHub Actions"
  local f
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    # 式の文脈名は大文字小文字を区別しない（${{ SECRETS.X }} / ${{ toJSON(secrets) }} / secrets['X'] も secrets 参照）
    yaml_flatten "$f" | grep_q -x -F '#ZES-YAML-ALIAS' && record_error "§21" "yaml_alias_unresolved:$f"
    if fgrep_q '(^|[^A-Za-z0-9_])pull_request_target([^A-Za-z0-9_]|$)' "$f" && fgrep_q -i 'actions/checkout@' "$f" && fgrep_q -i '\$\{\{([^}]*[^A-Za-z0-9_.])?secrets([].[[:space:])]|$)' "$f"; then
      # actions/checkout ステップごとに ref の有無と参照先を判定
      local refs
      refs="$(awk '
        function flush(){ if (inchk) { print (ref=="" ? "noref" : ref) } inchk=0; ref="" }
        # ref はブロックマッピング（行頭の ref:）とフローマッピング（{ ref: … } / , ref: …）の両方を見る
        function getref(s,   r, q, k) {
          if (!match(s, /^[[:space:]]*ref:/) && !match(s, /[{,][[:space:]]*ref:/)) return
          r = substr(s, RSTART + RLENGTH); sub(/^[[:space:]]*/, "", r)
          if (r ~ /^["\047]/) { q = substr(r, 1, 1); r = substr(r, 2); k = index(r, q); if (k) r = substr(r, 1, k - 1) }
          else sub(/[,}].*$/, "", r)
          # 正規化: 小文字化・空白除去・添字表記（github.event['"'"'pull_request'"'"']['"'"'head'"'"'] / ["…"]）をドット表記に
          r = tolower(r); gsub(/[ \t]/, "", r); gsub(/\[["\047]/, ".", r); gsub(/["\047]\]/, "", r)
          # ベース側の式（base.sha / base.ref / base_ref / github.sha / github.ref / default_branch）だけなら PR 由来ではない
          t = r; gsub(/\$\{\{(github\.event\.pull_request\.base\.(sha|ref)|github\.base_ref|github\.sha|github\.ref|github\.event\.repository\.default_branch)\}\}/, "", t)
          if (r ~ /github\.(event\.pull_request\.(head|merge_commit_sha|number)|head_ref|event\.number)|refs\/pull\//) ref = "prhead"
          else if (index(t, "${{")) ref = "exprref"     # それ以外の式で決まる ref は PR 由来でないと確認できない（最低 HIGH）
          else ref = "otherref" }
        tolower($0) ~ /^[[:space:]]*(-[[:space:]]+)?(\{([^}#]*,)?[[:space:]]*)?uses:[[:space:]]*["'"'"']?actions\/checkout@/ { flush(); inchk=1; match($0,/^[[:space:]]*/); ind=RLENGTH
          s = $0; sub(/.*actions\/checkout@/, "", s); getref(s); next }
        inchk {
          match($0,/^[[:space:]]*/)
          if ($0 ~ /^[[:space:]]*-[[:space:]]/ && RLENGTH <= ind) { flush(); next }
          getref($0)
        }
        END{ flush() }' < <(workflow_text "$f"))"
      if printf '%s\n' "$refs" | grep_q -x 'prhead'; then
        critical "ghostaction-oct2026" "$f" "pull_request_target + PR head の checkout + secrets 参照（pwn request）" "" "$(x_kind gha.pwn_request)"
      fi
      if printf '%s\n' "$refs" | grep_q -x 'noref'; then
        high "ghostaction-oct2026" "$f" "pull_request_target + actions/checkout(refなし) + secrets 参照（ベースブランチの取得だが、後続ステップで PR 由来のコードを扱わないか確認）" "" "$(x_kind gha.pwn_request)"
      fi
      if printf '%s\n' "$refs" | grep_q -x 'exprref'; then
        high "ghostaction-oct2026" "$f" "pull_request_target + actions/checkout の ref が式（\${{ … }}）+ secrets 参照（PR 由来の ref でないことを静的に確認できません）" "" "$(x_kind gha.pwn_request)"
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
      [ "$act" != "$line" ] || { high "ghostaction-oct2026" "$f" "uses: ${line} がバージョン未指定" "" "$(x_kind gha.unpinned)"; continue; }
      if [ "$act" = "aquasecurity/trivy-action" ] && ! [[ "$ref" =~ ^[0-9a-f]{40}$ ]] && [ "$ref" != "v0.35.0" ]; then
        critical "ghostaction-oct2026" "$f" "汚染されたタグ参照の可能性（${line}。2026-03-19 にタグ 75/76 が強制 push。安全版 v0.35.0 または検証済み SHA に固定）" "" "$(x_kind gha.unpinned)"
      elif [[ "$ref" =~ ^[0-9a-f]{40}$ ]]; then
        case "$act" in tj-actions/*|aquasecurity/*) medium "ghostaction-oct2026" "$f" "侵害履歴のある発行元のアクション ${act}（SHA 固定済み。SHA が安全な版か確認）" ;; esac
      else
        case "$act" in
          tj-actions/*|aquasecurity/*) critical "ghostaction-oct2026" "$f" "侵害履歴のある発行元のアクションをタグ参照（${line}）" "" "$(x_kind gha.unpinned)" ;;
          *) high "ghostaction-oct2026" "$f" "SHA 固定されていないアクション参照（${line}）" "" "$(x_kind gha.unpinned)" ;;
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
    # docker version はデーモン（DOCKER_HOST / context。ssh:// なら ssh を起動）へ接続するため使わず、
    # クライアントのみで完結する docker --version を読む
    dv="$(safe_probe docker --version | grep -o -E '[0-9]+\.[0-9]+\.[0-9]+[^ ,]*' | head -n1)"
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
    # 空白を含むパス（~/Library/Application Support/…）を分割せず、グロブ文字のみ展開する
    local IFS=$'\n'
    for d in $e; do
      [ -d "$d" ] || continue
      find "$d" -maxdepth 3 -name manifest.json -type f 2>/dev/null | qstore_filter "$d"
    done
    unset IFS
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
    if [ -n "$uu" ] && ! printf '%s\n' "${offurl[@]}" | grep_q -x -F -- "$uu"; then
      high "" "$f" "拡張の update_url が公式ストア以外"
    fi
    local p found=""
    for p in "${dperm[@]}"; do printf '%s\n' "$perms" | grep_q -x -F -- "$p" && found="$found $p"; done
    local all=0; printf '%s\n' "$perms" | grep_q -x -F -- '<all_urls>' && all=1
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
      && critical "" "$f" "core.fsmonitor に外部コマンド（git 操作のたびに実行）" "" \
        "$(TL_EXCLUDE='[[:space:]]*fsmonitor[[:space:]]*=[[:space:]]*(true|false)[[:space:]]*$' x_text_locators "$f" -i '^[[:space:]]*fsmonitor[[:space:]]*=')"
    fgrep_q -i '^[[:space:]]*sshCommand[[:space:]]*=' "$f" && high "" "$f" "core.sshCommand が設定されています" "" "$(x_text_locators "$f" -i '^[[:space:]]*sshCommand[[:space:]]*=')"
    fgrep_q -i '^[[:space:]]*hooksPath[[:space:]]*=' "$f" && medium "" "$f" "core.hooksPath が設定されています（フック置き場の付け替え）" "" "$(x_text_locators "$f" -i '^[[:space:]]*hooksPath[[:space:]]*=')"
  done < <(printf '%s\n' "$HOME_DIR/.gitconfig" "$HOME_DIR/.config/git/config"; cat "$GIT_CFG_LIST"; files_named '^\.gitconfig$')
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if fgrep_q '(curl|wget)[^|#]*\|[[:space:]]*(ba|z)?sh|eval[[:space:]]+"?\$\((curl|wget)' "$f"; then
      high "" "$f" ".envrc がリモートスクリプトを実行（direnv: curl|bash）" "" "$(x_text_locators "$f" '(curl|wget)[^|#]*\|[[:space:]]*(ba|z)?sh|eval[[:space:]]+"?\$\((curl|wget)')"
    fi
  done < <(files_named '^\.envrc$')
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    grep -E -o 'https?://[^"'"'"'[:space:]]+' "$f" 2>/dev/null | grep_q -v -E '^https://github\.com/(asdf-vm|asdf-community|mise-plugins|jdx)/' \
      && medium "" "$f" "asdf/mise のプラグイン URL が公式以外"
  done < <(files_named '^(\.tool-versions|mise\.toml|\.mise\.toml)$')
  local -a regs; mapfile -t regs < <(read_ioc '.official_registries')
  local re; re="$(printf '%s|' "${regs[@]}" | sed 's/\./\\./g; s/|$//')"
  while IFS= read -r f; do
    [ -n "$f" ] && [ -f "$f" ] || continue
    if grep -E -i '^[[:space:]]*(registry|@[^:]+:registry|npmRegistryServer|repository|index-url|index_url|extra-index-url)[[:space:]]*[=:]' "$f" 2>/dev/null \
       | grep -E -o 'https?://[^/"'"'"'[:space:]]+' | sed -E 's#https?://##' | grep_q -v -E "^($re)$"; then
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
    printf '%s\n' "${safeb[@]}" | grep_q -x -F -- "$be" || medium "" "$f" "pyproject.toml の build-backend が既知安全リスト外（$be）"
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
  files_path '(/\.github/workflows/[^/]+\.ya?ml|\.gitlab-ci\.yml|/Jenkinsfile|\.sh)$' | grep_l '(docker[[:space:]]+push|docker/build-push-action|buildah[[:space:]]+push|ko[[:space:]]+publish)' | grep_q . && builds_images=1
  files_path '(\.ya?ml|\.sh|/Makefile|/Jenkinsfile)$' | grep_l 'cosign[[:space:]]+verify' | grep_q . && verifies=1
  [ "$builds_images" -eq 1 ] && [ "$verifies" -eq 0 ] && medium "" "$ROOT" "コンテナイメージを公開しているが cosign verify の実行が見当たりません"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    grep -E -i '^[[:space:]]*FROM[[:space:]]+' "$f" 2>/dev/null | awk '{print $2}' | grep -v -E '^(scratch|\$)' | grep_q -v '@sha256:' \
      && medium "" "$f" "FROM がダイジェスト固定されていません（@sha256: 推奨）" "" "$(x_kind gha.unpinned)"
  done < <(files_named '^(Dockerfile.*|.*\.dockerfile)$')
  while IFS= read -r f; do [ -n "$f" ] && high "" "$f" "cosign 秘密鍵（cosign.key）がリポジトリ内にあります"; done < <(files_named '^cosign\.key$')
  files_named '\.ya?ml$' | grep_l 'imagePullPolicy:[[:space:]]*Always' | while IFS= read -r f; do
    [ -n "$f" ] || continue
    fgrep_q 'image:[[:space:]]*[^[:space:]]+@sha256:' "$f" || medium "" "$f" "imagePullPolicy: Always かつダイジェスト未固定（可変タグを毎回取得）" "" "$(x_kind gha.unpinned)"
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
    if [ -n "$lb" ] && ! printf '%s' "$lb" | grep_q '\.'; then
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
    [ -n "$v" ] && critical "" "" "launchctl setenv で DYLD_INSERT_LIBRARIES が設定されています"
    safe_probe launchctl list | awk 'NR>1 {print $3}' | grep -v -E '\.' | grep -v -E '^-$' | while IFS= read -r lb; do
      high "" "" "launchctl list にランダム Label 様のジョブ（$lb）"
    done
    local li
    li="$(safe_probe osascript -e 'tell application "System Events" to get name of every login item')"
    [ -n "$li" ] && info "" "" "ログイン項目: $li"
    safe_probe profiles show -type configuration | grep_q -i 'attribute' && medium "" "" "構成プロファイルがインストールされています（profiles show で確認）"
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
    [ -s "$f" ] && grep -q -v -E '^[[:space:]]*(#|$)' "$f" && critical "ebpf-rootkit" "$f" "ld.so.preload が空ではありません（全プロセスへのライブラリ注入）" "" \
      "$(x_text_locators "$f" -v '^[[:space:]]*(#|$)')"
  done < <(files_named '^ld\.so\.preload$'; host_enabled && [ -f /etc/ld.so.preload ] && echo /etc/ld.so.preload)
  while IFS= read -r f; do
    [ -n "$f" ] && fgrep_q '(^|[[:space:]]|export[[:space:]]+)LD_PRELOAD=' "$f" && high "ebpf-rootkit" "$f" "シェル設定で LD_PRELOAD を設定（ライブラリ注入による永続化）" "" \
      "$(x_text_locators "$f" '(^|[[:space:]]|export[[:space:]]+)LD_PRELOAD=')"
  done < <(home_rc_paths; files_named '^(\.bashrc|\.zshrc|\.profile|\.bash_profile|environment)$'; host_enabled && [ -f /etc/environment ] && echo /etc/environment)
  local unit
  while IFS= read -r unit; do
    [ -n "$unit" ] || continue
    local ure='^[[:space:]]*(ExecStart|ExecStartPre|Exec)[[:space:]]*=[^#]*(/tmp/|/dev/shm/|/var/tmp/|/\.[^/[:space:]]+/|curl|wget|base64|bash -c|sh -c)'
    if fgrep_q "$ure" "$unit"; then
      high "ebpf-rootkit" "$unit" "自動起動エントリが一時領域/隠しパス/通信コマンドを実行" "" "$(x_text_locators "$unit" "$ure")"
    elif fgrep_q 'Environment=.*LD_PRELOAD' "$unit"; then
      high "ebpf-rootkit" "$unit" "systemd ユニットで LD_PRELOAD を設定" "" "$(x_text_locators "$unit" 'Environment=.*LD_PRELOAD')"
    else
      info "" "$unit" "ユーザー自動起動エントリ"
    fi
  done < <(files_path '/systemd/user/[^/]+\.service$|/autostart/[^/]+\.desktop$'
           ls "$HOME_DIR"/.config/systemd/user/*.service "$HOME_DIR"/.config/autostart/*.desktop 2>/dev/null)
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    grep -v '^[[:space:]]*#' "$f" 2>/dev/null | grep_q -E '(curl|wget|base64|/tmp/|/dev/shm/|nc )' && high "ebpf-rootkit" "$f" "cron.d エントリが通信/一時領域を実行" "" \
      "$(TL_EXCLUDE='[[:space:]]*#' x_text_locators "$f" '(curl|wget|base64|/tmp/|/dev/shm/|nc )')"
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
    elif grep -v -E '^[[:space:]]*(#|$|clear|if|fi|then|\[)' "$f" | grep_q .; then medium "" "$f" "ログアウトフックにコマンドがあります"
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
  for f in "$HOME_DIR/.npmrc" "$RP/.npmrc"; do
    [ -f "$f" ] && { [ "$f" = "$HOME_DIR/.npmrc" ] || in_root_regular "$f"; } && fgrep_q -i '^[[:space:]]*(https-)?proxy[[:space:]]*=' "$f" && high "" "$f" "npm のプロキシ設定（レジストリ通信の傍受）"
  done
  local -a ph; mapfile -t ph < <(read_ioc '.protected_hosts')
  local hostsf
  # 空白を含むパス（"my etc/hosts" 等）を分割しないよう 1 行ずつ読む
  while IFS= read -r hostsf; do
    [ -n "$hostsf" ] && [ -f "$hostsf" ] || continue
    local h
    for h in "${ph[@]}"; do
      grep -v '^[[:space:]]*#' "$hostsf" | grep_q -i -E "[[:space:]]$(printf '%s' "$h" | sed 's/\./\\./g')([[:space:]]|$)" \
        && high "" "$hostsf" "hosts でレジストリ/GitHub（$h）を上書き"
    done
    network_iocs | cut -f1 | grep -v -E '^[0-9.]+$' | while IFS= read -r h; do
      grep -v '^[[:space:]]*#' "$hostsf" | grep_q -i -F -- "$h" && critical "" "$hostsf" "hosts に C2 ドメイン（$h）"
    done
  done < <(host_enabled && echo /etc/hosts; files_named '^hosts$')
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
      [ "$st" = "active" ] && safe "auditd 稼働中" || medium "" "" "auditd が稼働していません（${st:-unknown}）"
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
      ZES_V_E="$ce" ZES_V_N="$cp" awk -F'\t' 'BEGIN { e = ENVIRON["ZES_V_E"]; n = ENVIRON["ZES_V_N"] } $1==e && $2==n {print $3"\t"$4}' "$DEPS_TSV" | sort -u | tsv_us | while IFS="$US" read -r v f; do
        [ -n "$v" ] && version_lt "$v" "$cf" && high "mcp-poisoning" "$f" "${cp}@${v} は ${cid} の影響範囲（修正版 ${cf}）" "" "$(x_kind runtime.cve)"
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
  if [ -n "$ROOT_GITDIR" ]; then
    local since; since="$(( $(now_epoch) - 30*86400 ))"
    # パスは -z（NUL 区切り）で受け取る（非 ASCII・引用符を含む名前を C 形式で引用させない）
    if safe_git log --no-textconv --no-ext-diff --diff-filter=A --since="@$since" --name-only --format='' -z -- .github/workflows >"$TMP_DIR/s38-added.z"; then
      tr '\0' '\n' <"$TMP_DIR/s38-added.z" | grep -v '^$' | sort -u | while IFS= read -r n; do
        [ -n "$n" ] && medium "ghostaction-oct2026" "$RP/$n" "直近30日に新規追加されたワークフロー（作成者・目的を監査）"
      done
    else
      record_error "§38" "git_log_failed"
    fi
  fi
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    n="$(grep -o -a -i -E 'secrets\.[A-Za-z0-9_]+' "$f" 2>/dev/null | tr 'A-Z' 'a-z' | sort -u | wc -l | tr -d ' ')"
    [ "${n:-0}" -gt "$th" ] && high "ghostaction-oct2026" "$f" "ワークフローが ${n} 種類の secrets.* を参照（閾値 ${th} 超、一括収集の疑い）"
    fgrep_q -i 'tojson\([[:space:]]*secrets[[:space:]]*(\.[[:space:]]*\*[[:space:]]*)?\)' "$f" && critical "ghostaction-oct2026" "$f" "toJSON(secrets) で全シークレットを展開"
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
    printf '%s' "$bp" | grep_q -E '(getdents|tcp4_seq_show|tcp6_seq_show|udp4_seq_show|sys_bpf|kill)' && high "ebpf-rootkit" "" "ファイル/ソケット/プロセス隠蔽系フックの eBPF プログラム（bpftool prog list）"
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
      grep -E '^[[:space:]]*ExecStart=' "$u" | grep_q -v -E '=(/usr)?/lib/systemd/|=/usr/bin/(dbus|udevadm)|=/usr/sbin/' \
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
      critical "" "$f" "Cursor ${v} は CVE-2026-26268（CVSS 9.9、2.5 で修正）と CVE-2026-50548（DuneSlide、CVSS 9.8、3.0 で修正）の影響範囲" "" "$(x_kind runtime.cve)"
    elif version_lt "$v" "3.0"; then
      critical "" "$f" "Cursor ${v} は CVE-2026-50548（DuneSlide、CVSS 9.8）の影響範囲（3.0 で修正）" "" "$(x_kind runtime.cve)"
    fi
  done
  local d cfix; cfix="$(read_ioc '.runtime_minimums.copilot_chat')"
  for d in "$HOME_DIR"/.vscode/extensions/github.copilot-chat-[0-9]*; do
    [ -d "$d" ] || continue
    v="${d##*/github.copilot-chat-}"; v="${v%%-*}"
    [ -n "$cfix" ] && version_lt "$v" "$cfix" && high "" "$d" "GitHub Copilot Chat 拡張 ${v} は CVE-2025-62222（コマンドインジェクション、CVSS 8.8）の影響範囲（修正版 ${cfix}）" "" "$(x_kind runtime.cve)"
  done
  for d in "$HOME_DIR"/Library/Application\ Support/JetBrains/*/plugins/github-copilot-intellij "$HOME_DIR"/.local/share/JetBrains/*/github-copilot-intellij; do
    [ -d "$d" ] && medium "" "$d" "JetBrains 版 Copilot: CVE-2026-50510 の修正版適用を確認"
  done
  [ -f "$RP/git.exe" ] && critical "" "$RP/git.exe" "リポジトリルートの git.exe（Windows で IDE/エージェントが自動実行する未パッチ zero-day）"
  local has_instr=0 has_hook=0 has_agent_hook=0 t
  ai_instruction_files | grep_q . && has_instr=1
  while IFS= read -r t; do
    [ -n "$t" ] && find "$t" -type f ! -name '*.sample' 2>/dev/null | qstore_filter "$t" | grep_q . && has_hook=1
  done <"$GIT_HOOKS_LIST"
  files_path '/\.(claude|cursor|gemini)/(settings(\.local)?|hooks)\.json$' | grep_l '"hooks"' | grep_q . && has_agent_hook=1
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
        # comm は使わない（busybox 等に無い）。前版に無く今版にある行
        added="$(awk 'NR == FNR { if ($0 != "") seen[$0] = 1; next } $0 != "" && !($0 in seen)' <(printf '%s\n' "$prev") <(printf '%s\n' "$cur") | sort -u | tr '\n' ' ')"
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
      printf '%s' "$line" | grep_q -E -- '--key([[:space:]=]|$)' && continue
      printf '%s' "$line" | grep_q -E -- '--certificate-identity(-regexp)?[[:space:]=]' || { high "" "$f" "cosign verify に --certificate-identity がありません（任意の署名者を受理）"; continue; }
      printf '%s' "$line" | grep_q -E -- '--certificate-oidc-issuer(-regexp)?[[:space:]=]' || high "" "$f" "cosign verify に --certificate-oidc-issuer がありません"
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
  files_path '\.(m?js|cjs|ts|py|sh|go|rs)$' | tr '\n' '\0' | xargs -0 grep -l -a -F -f "$TMP_DIR/cienv.pat" -- /dev/null 2>/dev/null | while IFS= read -r f; do
    [ -n "$f" ] || continue
    n="$(grep -o -a -F -w -f "$TMP_DIR/cienv.pat" -- "$f" 2>/dev/null | sort -u | wc -l | tr -d ' ')"
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
  [ -n "$ROOT_GITDIR" ] || { log_info "Git リポジトリではありません（または .git を解決できません。errors[] を参照）"; return 0; }
  local out n
  # %G? は署名を検証する（gpg.*.program を起動しうる）ため使わない。署名の有無は生のヘッダ（gpgsig）で判定
  out="$(safe_git log -n 200 --no-textconv --no-ext-diff --format='%at%x09%ae%x09%H')" || { record_error "§46" "git_log_failed"; return 0; }
  [ -n "$out" ] || return 0
  local raw
  raw="$(safe_git log -n 200 --no-textconv --no-ext-diff --pretty=raw)" || { record_error "§46" "git_log_failed"; return 0; }
  local now; now="$(now_epoch)"
  printf '%s\n' "$out" | awk -F'\t' -v now="$now" '$1 >= now-86400 {c[$2]++} END {for (a in c) if (c[a] > 50) print a "\t" c[a]}' | while IFS=$'\t' read -r _ n; do
    medium "" "$RP/.git" "直近24時間に同一作者で ${n} コミット（短時間大量コミット）"
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
  [ "$total" -gt 0 ] && info "" "$RP/.git" "直近 ${total} コミット中 ${unsigned} 件が署名なし"
  safe_git for-each-ref --format='%(refname)' refs/notes | while IFS= read -r n; do
    [ -n "$n" ] && medium "" "$RP/.git" "Git notes（${n}）が存在（来歴情報の書き換えに注意）"
  done
  safe_git for-each-ref --format='%(refname)%09%(objecttype)%09%(*objecttype)' refs/tags | while IFS=$'\t' read -r n t pt; do
    if [ "$t" = "tag" ] && [ -n "$pt" ] && [ "$pt" != "commit" ]; then high "" "$RP/.git" "タグ ${n} がコミット以外（${pt}）を指しています"
    elif [ "$t" != "tag" ] && [ "$t" != "commit" ]; then high "" "$RP/.git" "タグ ${n} がコミット以外（${t}）を指しています"; fi
  done
  if in_root_regular "$RP/.gitmodules"; then
    local origin_host
    origin_host="$(git_cfg_get remote origin url | sed -E 's#^[a-z+]+://([^@/]+@)?##; s#^[^@]+@##; s#[:/].*##')"
    grep -E '^[[:space:]]*url[[:space:]]*=' "$RP/.gitmodules" | sed -E 's/.*=[[:space:]]*//' | while IFS= read -r n; do
      case "$n" in
        http://*|git://*) high "" "$RP/.gitmodules" "サブモジュールが平文プロトコル（$n）" ;;
        ./*|../*) ;;
        *) local h; h="$(printf '%s' "$n" | sed -E 's#^[a-z+]+://([^@/]+@)?##; s#^[^@]+@##; s#[:/].*##')"
           [ -n "$origin_host" ] && [ "$h" != "$origin_host" ] && medium "" "$RP/.gitmodules" "サブモジュールが外部ホスト（$h）を参照" ;;
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
    fgrep_q 'export[[:space:]]+[A-Za-z0-9_]*(_TOKEN|_KEY|_SECRET|PASSWORD)=' "$f" && high "" "$f" "シェル履歴に export *_TOKEN=/*_KEY=/*_SECRET=（平文の認証情報。ローテーション対象）" "" "$(x_kind secret.token)"
  done
  local now; now="$(now_epoch)"
  for f in "$HOME_DIR/.aws/sso/cache" "$HOME_DIR/.azure" "$HOME_DIR/.config/gcloud/credentials.db"; do
    [ -e "$f" ] || continue
    local m; m="$(stat_mtime "$f")"
    [ -n "$m" ] && [ $(( now - m )) -lt 86400 ] && info "" "$f" "クラウド認証キャッシュが直近24時間に更新"
  done
  files_named '^(\.env\.ci|\.envrc)$' | grep_l '(_TOKEN|_KEY|_SECRET|PASSWORD)[[:space:]]*=[[:space:]]*[^[:space:]$]' | while IFS= read -r f; do
    [ -n "$f" ] && high "" "$f" "CI/direnv 用ファイルに平文の認証情報" "" "$(x_kind secret.token)"
  done
  tr '\n' '\0' <"$FILES_LIST" | xargs -0 grep -l -a -E -e '(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}|gho_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36})' -- /dev/null 2>/dev/null | while IFS= read -r f; do
    [ -n "$f" ] && critical "" "$f" "GitHub トークン（ghp_/github_pat_ 等）がファイルに含まれます（内容は出力しません。即時失効）" "" "$(x_kind secret.token)"
  done
  return 0
}

# iso8601_epoch "YYYY-MM-DDTHH:MM:SS[.frac](Z|±HH:MM)" → epoch 秒（date -d に依存しない。busybox の date は ISO の Z を受け付けない）
iso8601_epoch() {
  local t="$1" y mo d h mi se off=0 sign hh mm
  [[ "$t" =~ ^([0-9]{4})-([0-9]{2})-([0-9]{2})([Tt\ ]([0-9]{2}):([0-9]{2})(:([0-9]{2}))?(\.[0-9]+)?)?([Zz]|([+-])([0-9]{2}):?([0-9]{2}))?$ ]] || return 1
  y=$((10#${BASH_REMATCH[1]})); mo=$((10#${BASH_REMATCH[2]})); d=$((10#${BASH_REMATCH[3]}))
  h=$((10#${BASH_REMATCH[5]:-0})); mi=$((10#${BASH_REMATCH[6]:-0})); se=$((10#${BASH_REMATCH[8]:-0}))
  sign="${BASH_REMATCH[11]}"; hh="${BASH_REMATCH[12]:-0}"; mm="${BASH_REMATCH[13]:-0}"
  [ "$sign" = "-" ] && off=$(( -(10#$hh * 3600 + 10#$mm * 60) ))
  [ "$sign" = "+" ] && off=$(( 10#$hh * 3600 + 10#$mm * 60 ))
  # 暦日 → 1970-01-01 からの日数（Howard Hinnant の days_from_civil）
  local yy=$((mo <= 2 ? y - 1 : y)) era doe yoe doy
  era=$(( (yy >= 0 ? yy : yy - 399) / 400 )); yoe=$(( yy - era * 400 ))
  doy=$(( (153 * (mo + (mo > 2 ? -3 : 9)) + 2) / 5 + d - 1 )); doe=$(( yoe * 365 + yoe / 4 - yoe / 100 + doy ))
  printf '%s' $(( (era * 146097 + doe - 719468) * 86400 + h * 3600 + mi * 60 + se - off ))
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
  files_named '(\.intoto\.jsonl|^provenance\.json$|\.provenance\.json$|\.layout$)' | grep_q . && has_prov=1
  files_path '\.(ya?ml|sh)$' | grep_l '(cosign[[:space:]]+verify-attestation|slsa-verifier[[:space:]]+verify-artifact|in-toto-verify)' | grep_q . && has_verify=1
  for f in "${sboms[@]}"; do
    [ -n "$f" ] || continue
    local dir; dir="$(dirname -- "$f")"
    jq -r '(((.components // [])[]? | [(.name // ""), ((.version // "") | tostring)]), ((.packages // [])[]? | [(.name // ""), ((.versionInfo // "") | tostring)])) | @tsv' "$f" 2>/dev/null | sort -u >"$TMP_DIR/sbom.tsv" \
      || { record_error "§48" "sbom_parse_failed:$f"; continue; }
    local created; created="$(jq -r '.metadata.timestamp // .creationInfo.created // empty' "$f" 2>/dev/null)"
    # 同ディレクトリのロックファイル由来の依存（npm/pypi）と突合
    ZES_V_D="$dir/" awk -F'\t' 'BEGIN { d = ENVIRON["ZES_V_D"] } index($4, d)==1 && ($1=="npm" || $1=="pypi") && $4 !~ /\/node_modules\/.*\/package\.json$/ {print $2"\t"$3}' "$DEPS_TSV" | sort -u >"$TMP_DIR/lock.tsv"
    if [ -s "$TMP_DIR/lock.tsv" ]; then
      local missing mism
      # comm / join は使わない（busybox 等に無い）。awk で同じ集計をする
      #   missing … ロックファイルにあり SBOM に無い名前の数 / mism … 同名の (ロック版, SBOM 版) の組で版が異なるものの数
      missing="$(awk -F'\t' 'NR == FNR { s[$1] = 1; next } !($1 in s) && !($1 in seen) { seen[$1] = 1; n++ } END { print n + 0 }' "$TMP_DIR/sbom.tsv" "$TMP_DIR/lock.tsv")"
      mism="$(awk -F'\t' 'NR == FNR { v[$1] = v[$1] SUBSEP $2; next }
          ($1 in v) { k = split(substr(v[$1], 2), a, SUBSEP); for (i = 1; i <= k; i++) if (a[i] != $2) n++ } END { print n + 0 }' "$TMP_DIR/sbom.tsv" "$TMP_DIR/lock.tsv")"
      if [ "$missing" -gt 0 ] || [ "$mism" -gt 0 ]; then
        high "" "$f" "SBOM とロックファイルが不一致（SBOM 未記載 ${missing} 件 / バージョン相違 ${mism} 件）"
      else
        safe "SBOM とロックファイルが一致（$f）"
      fi
      if [ -n "$created" ]; then
        local lf lm
        while IFS= read -r lf; do
          lm="$(stat_mtime "$lf")"
          local ce; ce="$(iso8601_epoch "$created")"
          [ -n "$ce" ] && [ -n "$lm" ] && [ "$lm" -gt $(( ce + 60 )) ] && { medium "" "$f" "SBOM 生成日時（$created）がロックファイル更新より古い"; break; }
        done < <(ZES_V_D="$dir/" awk -F'\t' 'BEGIN { d = ENVIRON["ZES_V_D"] } index($4,d)==1 {print $4}' "$DEPS_TSV" | sort -u)
      fi
    fi
  done
  [ "$has_prov" -eq 0 ] && [ "$has_verify" -eq 0 ] && medium "" "$ROOT" "SBOM はあるが provenance / in-toto レイアウト / attestation 検証（cosign verify-attestation・slsa-verifier）が見当たりません"
  return 0
}

# =============================================================================
# §49 SkillPact 契約（実験的） check_skillpact
#   AI エージェントのスキルが「宣言した権限」と「コードが実際にしていること」が一致するかを静的に確かめる。
#   宣言は SkillPact 0.8 形式の skill.contract.json（https://github.com/kajisho5/skillpact、
#   仕様 © SEVENTHWELL (shogo kajiyama) CC BY 4.0 / スキーマ Apache-2.0）を読む。
#   - 契約・ポリシーは jq で JSON として読むのみ。スキル本体・テストは実行しない
#   - 署名は検証しない（signed=true は「署名欄あり・未検証」）。署名の有無で重大度を変えない
#   - level は契約の自己申告を使わず、ZES の部分検査に合格した場合のみ "L1"。L2/L3 は ZES では判定しない
#   - 契約のないスキルは対象外（参考 INFO のみ）。契約付きスキルの配下にある SKILL.md は報告しない
#   - ポリシー（policy_version + defaults を持つ JSON）は構造検査のみ。allow/ask/deny の評価は未実装（README の TODO）
# =============================================================================

SP_JQ_LIB='
def sp_esc: gsub("(?<c>[\\\\.^$|()\\[\\]{}+*?])"; "\\\(.c)");
def sp_glob_re:
  split("/") as $parts | ($parts | length) as $n |
  (reduce range(0; $n) as $i ({o: "", g: false};
    $parts[$i] as $seg | (if $i == 0 or .g then "" else "/" end) as $sep |
    if $seg == "**" then
      (if $i == $n - 1 then (.o += (if $i > 0 then "(?:/.*)?" else ".*" end)) | .g = false
       else (.o += $sep + "(?:[^/]+/)*") | .g = true end)
    else (.g = false) | (.o += $sep + ($seg | gsub("\\*+"; "*") | explode | map([.] | implode | if . == "*" then "[^/]*" elif . == "?" then "[^/]" else sp_esc end) | join("")))
    end) | "\\A" + .o + "\\z");
def sp_gmatch($p): test($p | sp_glob_re);
def sp_lab($q): test("\\A" + ($q | explode | map([.] | implode | if . == "*" then "[^.]*" elif . == "?" then "." else sp_esc end) | join("")) + "\\z");
def sp_host_match($p0):
  if $p0 == "@local" then . == "@local"
  else (ascii_downcase | rtrimstr(".")) as $h | ($p0 | ascii_downcase | rtrimstr(".")) as $p |
    if $p == "*" then true else
    ($h | split(".")) as $hl | ($p | split(".")) as $pl |
    if ($pl[0] == "*" or $pl[0] == "**") and ($pl | length) > 1 then
      $pl[1:] as $rest | ($rest | length) as $need |
      if ($hl | length) < $need + (if $pl[0] == "*" then 1 else 0 end) then false
      else all(range(0; $need); . as $i | ($hl[($hl | length) - $need + $i] | sp_lab($rest[$i]))) end
    else ($hl | length) == ($pl | length) and all(range(0; $hl | length); . as $i | ($hl[$i] | sp_lab($pl[$i]))) end end end;
def sp_literal: split("/") | map(if . == "**" then "\u0002/\u0002" else gsub("\\*"; "\u0001*\u0001") end) | join("/");
def sp_kind($e): if $e == "read" or $e == "write" then "path" elif $e == "network" then "host" else "generic" end;
def sp_traversal: test("\\\\") or ((if startswith("/") then .[1:] else . end) | split("/") | any(.[]; . == "" or . == "." or . == ".."));
def sp_covered($scope; $pats; $kind):
  if ($scope | length) == 0 then false
  elif $kind == "path" and ($scope | any(.[]; sp_traversal)) then false
  else all($scope[]; . as $s | any($pats[]; . as $p | $s == $p or (if $kind == "host" then ($s | sp_host_match($p)) else ($s | sp_literal | sp_gmatch($p)) end))) end;
def sp_ipath_bad:
  (type != "string") or (. == "") or (utf8bytelength > 1024) or startswith("/") or test("^[A-Za-z]:") or test("\\\\") or (explode | any(.[]; . < 32))
  or ((split("/") | length) > 32) or (split("/") | any(.[]; . == "" or . == "." or . == ".."));
def sp_truthy: . != null and . != false and . != [] and . != "" and . != {} and . != 0;
def sp_semv: (capture("^(?<a>[0-9]+)\\.(?<b>[0-9]+)\\.(?<c>[0-9]+)(?<pre>-[^+]*)?") // null) | if . == null then null else [(.a | tonumber), (.b | tonumber), (.c | tonumber), (if .pre then 0 else 1 end)] end;
def sp_rank: if . == "any" then 2 elif . == "scoped" then 1 else 0 end;
def sp_authors: [(.integrity.signatures // [])[]? | select(type == "object" and ((.role // "author") == "author"))
  | if .type == "sigstore" then (if .instance == "staging" then "sigstore-staging:" else "sigstore:" end) + "\(.issuer)|\(.identity)" else .key end
  | select(type == "string")] | unique;
def sp_lvl($e): (.permissions[$e].level? // "none") | if type == "string" then . else "none" end;
'

# 契約の構造・整合性検査（ZES の部分検査）と宣言の正規化
SP_ANALYZE='
. as $c | ($R.effects) as $EFF |
($c.contract_version) as $cv |
(if ($cv | type) == "string" and ($R.contract_versions | index($cv)) != null then "ok" else "unsupported" end) as $vs |
(($cv | type) == "string" and ($cv | test("^[0-9]+\\.[0-9]+$")) and (($cv | split(".") | map(tonumber)) >= [0, 8])) as $v08 |
([
  ((keys - $R.contract_keys) | if length > 0 then "SCHEMA" else empty end),
  ((["contract_version", "skill", "permissions", "capabilities"] - keys) | if length > 0 then "SCHEMA" else empty end),
  (if has("kind") and ((.kind | IN("tool", "instructions")) | not) then "SCHEMA" else empty end),
  (if has("$schema") and ((.["$schema"] | type) != "string") then "SCHEMA" else empty end),
  (try (if has("x") and ((.x | type) != "object" or (.x | keys | any(.[]; test("^[a-z0-9][a-z0-9-]*$") | not))) then "SCHEMA" else empty end) catch "SCHEMA"),
  (try (.skill | if type != "object" then "SCHEMA"
     elif (keys - ["name", "version", "license", "homepage", "source", "authors", "native_contract"] | length) > 0 then "SCHEMA"
     elif ((.name | type == "string" and test("^[a-z0-9]+(-[a-z0-9]+)*$") and length <= 64) and (.version | type == "string" and test("^[0-9]+\\.[0-9]+\\.[0-9]+([-+][0-9A-Za-z.-]+)?$"))) | not then "SCHEMA"
     else empty end) catch "SCHEMA"),
  (try (.permissions | if type != "object" or ((keys | sort) != ($EFF | sort)) then "SCHEMA"
     else (.[] | if type != "object" or ((keys - ["level", "scope", "why", "confirm"]) | length) > 0 or ((.level | IN("none", "scoped", "any")) | not)
       or (has("scope") and ((.scope | type) != "array" or any(.scope[]; type != "string")))
       or (has("confirm") and ((.confirm | IN("never", "each", "session")) | not)) then "SCHEMA" else empty end) end) catch "SCHEMA"),
  (try (.capabilities | if type != "array" then "SCHEMA" else (.[] |
     if type != "object" or ((keys - $R.capability_keys) | length) > 0 then "SCHEMA"
     elif ((.id | type == "string") and (.summary | type == "string") and ((.effects | type) == "array")) | not then "SCHEMA"
     elif (.effects | all(.[]; IN($EFF[])) and ((unique | length) == length)) | not then "SCHEMA"
     elif ((.conditional_effects // []) | type != "array" or any(.[]; type != "object" or ((.effect | IN($EFF[])) | not))) then "SCHEMA"
     elif ((.effect_scopes // {}) | type != "object" or any(keys[]; IN($EFF[]) | not) or any(.[]; type != "array" or any(.[]; type != "string"))) then "SCHEMA"
     else empty end) end) catch "SCHEMA"),
  (try (if has("integrity") then (.integrity | if type != "object" or ((keys - ["algorithm", "canonicalization", "exclude", "files", "signatures"]) | length) > 0 then "SCHEMA"
     elif has("algorithm") and .algorithm != "sha256" then "SCHEMA"
     elif ((.files // {}) | type != "object" or any(.[]; type != "string" or (test("^[0-9a-f]{64}$") | not))) then "SCHEMA"
     elif ((.exclude // []) | type != "array" or any(.[]; type != "string" or length == 0)) then "SCHEMA"
     elif ((.signatures // []) | type != "array" or any(.[]; type != "object" or ((.type | IN("ed25519", "sigstore")) | not) or (has("role") and ((.role | IN("author", "reviewer", "scanner")) | not)))) then "SCHEMA"
     else empty end) else empty end) catch "SCHEMA"),
  (try (if has("tests") then (.tests | if type != "object" or ((keys - ["setup", "cases"]) | length) > 0 then "SCHEMA"
     elif ((.cases // []) | type != "array" or any(.[]; type != "object" or (has("id") and has("run") and has("expect") | not))) then "SCHEMA"
     else empty end) else empty end) catch "SCHEMA")
] | unique) as $schema |
(if $vs != "ok" or ($schema | length) > 0 then [] else (try [
  (.capabilities | map(.id) | group_by(.) | map(select(length > 1)) | if length > 0 then "DUP_CAPABILITY" else empty end),
  (.capabilities[] | (.effects[], ((.conditional_effects // [])[] | .effect)) as $e | select(($c | sp_lvl($e)) == "none") | "UNDECLARED_EFFECT"),
  ($EFF[] as $e | .permissions[$e] | select(.level == "scoped" and ((.scope // []) | length) == 0) | "SCOPE_EMPTY"),
  (("read", "write") as $e | (.permissions[$e].scope // [])[] | select(sp_traversal) | "SCOPE_TRAVERSAL"),
  (.capabilities[] | (.effect_scopes // {}) | to_entries[] | select(.key | IN("read", "write")) | .value[] | select(sp_traversal) | "SCOPE_TRAVERSAL"),
  (.capabilities[] | (.effect_scopes // {}) | to_entries[] | .key as $e | select(($c | sp_lvl($e)) == "scoped")
     | select(sp_covered(.value; ($c.permissions[$e].scope // []); sp_kind($e)) | not) | "SCOPE_WIDENED"),
  (([(.requirements.binaries // [])[]?.name, (.requirements.runtimes // [])[]?.name]) as $rn | (.capabilities[] | (.requires // [])[] | select(IN($rn[]) | not) | "UNKNOWN_REQUIREMENT")),
  (([(.requirements.binaries // [])[]? | (.features_check // {}) | keys[]]) as $fk | (.capabilities[] | (.requires_features // [])[] | select(type == "string") | select((split(":")[0] | IN($fk[])) | not) | "UNKNOWN_FEATURE_KIND")),
  (.capabilities[] | (.entry.cli? // []) | if type == "array" then .[] else empty end | select(type == "string" and startswith("$SKILL_DIR/")) | ltrimstr("$SKILL_DIR/") as $r
     | select((($files + $links) | any(.[]; . == $r or startswith($r + "/"))) | not) | "ENTRY_MISSING"),
  (if $fm != "" and $fm != .skill.name then "NAME_MISMATCH" else empty end),
  ((.capabilities | map(.id)) as $ids | (.tests.cases // [])[] |
     (select(.capability != null and ((.capability | IN($ids[])) | not)) | "TEST_UNKNOWN_CAPABILITY"),
     (select($v08 and .network == true and ($c | sp_lvl("network")) == "none") | "TEST_UNDECLARED_NETWORK")),
  (if $v08 and (((.x.init.uncertain? // null) | sp_truthy) or ((.x.import.uncertain? // null) | sp_truthy) or ([del(.x) | .. | strings | select(contains("TODO("))] | length > 0)) then "UNCONFIRMED_DRAFT" else empty end),
  (if has("integrity") then (.integrity as $I | ($I.files // {}) as $F |
     (if $v08 and ($F | has("SKILL.md") | not) then "INTEGRITY_EMPTY" else empty end),
     ($F | keys[] as $rel |
        if ($rel | sp_ipath_bad) then "INTEGRITY_PATH"
        elif ($links | any(.[]; . == $rel or ($rel | startswith(. + "/")))) then "INTEGRITY_PATH"
        elif ($hashes | has($rel) | not) then "INTEGRITY_MISSING"
        elif $hashes[$rel] != $F[$rel] then "INTEGRITY_MISMATCH" else empty end),
     (($R.integrity.default_exclude + ($I.exclude // [])) as $ex |
      ($R.integrity.protected + ($R.integrity.code_extensions | map("**/*." + .))) as $prot |
      ([(.capabilities[] | (.entry.cli? // []) | if type == "array" then .[] else empty end), ((.tests.cases // [])[] | .run | if type == "array" then .[] else . end), ((.tests.setup // [])[] | if type == "array" then .[] else . end)]
        | map(select(type == "string") | match("\\$SKILL_DIR/([^\\s\u0027\"]+)"; "g") | .captures[0].string)) as $must |
      (($files[] | select(. != "skill.contract.json") | . as $rel | select($F | has($rel) | not)
        | select(any($prot[]; . as $p | $rel | sp_gmatch($p)) or ($rel | IN($must[])) or (any($ex[]; . as $p | $rel | sp_gmatch($p)) | not))
        | if $v08 then "INTEGRITY_UNLISTED" else empty end),
       ($links[] | . as $rel | select(any($prot[]; . as $p | $rel | sp_gmatch($p)) or (any($ex[]; . as $p | $rel | sp_gmatch($p)) | not))
        | if $v08 then "INTEGRITY_PATH" else empty end))),
     ([($I.signatures // [])[] | if .type == "sigstore" then "sigstore:\(.issuer)|\(.identity)|\(.instance)" else .key end] | group_by(.) | if any(.[]; length > 1) then "DUP_SIGNATURE" else empty end))
   else empty end)
] catch ["SCHEMA"]) end | unique) as $cross |
(($schema + $cross) | unique) as $errors |
(try (($vs == "ok") and ((.permissions | type) == "object") and all($EFF[]; . as $e | ($c.permissions[$e] | type) == "object" and (($c.permissions[$e].level // "") | IN("none", "scoped", "any")))) catch false) as $permsok |
(if $permsok then [$EFF[] as $e | select(($c | sp_lvl($e)) != "none") | $e] else [] end) as $declared |
(try ([(.permissions.read.scope // [])[], ((.capabilities // [])[] | (.conditional_effects // [])[] | select(.effect == "read") | (.scope // [])[])]) catch []) as $rscopes |
(try ([(.permissions.write.scope // [])[], ((.capabilities // [])[] | (.conditional_effects // [])[] | select(.effect == "write") | (.scope // [])[])]) catch []) as $wscopes |
(($c | sp_lvl("read")) == "any" or ($rscopes | any(.[]; type == "string" and (IN($R.broad_scopes[]) or test($R.sensitive_scope_regex; "i"))))) as $secret_read |
(($c | sp_lvl("write")) == "any" or ($wscopes | any(.[]; type == "string" and (. as $s | any($R.ephemeral_scope_prefixes[]; . as $p | $s | startswith($p)) | not)))) as $durable_write |
(if $permsok then [
  (("exec", "network", "spend", "send") as $e | select($obs[$e] and ($c | sp_lvl($e)) == "none") | {effect: $e, why: "none"}),
  (if $obs.read and ($secret_read | not) then {effect: "read", why: (if ($c | sp_lvl("read")) == "none" then "none" else "scope" end), sensitive: true} else empty end),
  (if $obs.durable and ($durable_write | not) then {effect: "write", why: (if ($c | sp_lvl("write")) == "none" then "none" else "scope" end), durable: true}
   elif $obs.write and ($c | sp_lvl("write")) == "none" then {effect: "write", why: "none"} else empty end)
] else [] end) as $div |
(try sp_authors catch []) as $authors |
{ vstatus: $vs, cv: (if ($cv | type) == "string" then $cv elif $cv == null then null else ($cv | tojson) end),
  name: (try (.skill.name | strings) catch null), sver: (try (.skill.version | strings) catch null),
  errors: $errors, permsok: $permsok, declared: $declared,
  signed: (try (((.integrity.signatures // []) | type) == "array" and ((.integrity.signatures // []) | length) > 0) catch false),
  authors: $authors, author: ($authors[0] // null),
  signers: (try ([(.integrity.signatures // [])[] | select((.role // "author") == "author") | .signer | strings] | unique) catch []),
  level: (if $vs == "ok" and ($errors | length) == 0 then "L1" else null end),
  divergence: $div }
'

# 前版との比較（spec §17: 権限の拡大は major を上げるべき）
SP_DIFF='
. as $cur | if ($cur.ver | sp_semv) == null then null else
[$idx[] | select(.name == $cur.name and .path != $cur.path and (.ver | type) == "string" and (.ver | sp_semv) != null and (.ver | sp_semv) < ($cur.ver | sp_semv))]
| (max_by(.ver | sp_semv)) as $p |
if $p == null then null else
  [ $R.effects[] as $e | ($cur.perms[$e] // {level: "none"}) as $a | ($p.perms[$e] // {level: "none"}) as $b |
    if (($a.level // "none") | sp_rank) > (($b.level // "none") | sp_rank) then {effect: $e, text: "\($e): \($b.level // "none")→\($a.level)"}
    elif $a.level == "scoped" and $b.level == "scoped" then
      [($a.scope // [])[] as $s | select(sp_covered([$s]; ($b.scope // []); sp_kind($e)) | not) | $s] as $new |
      if ($new | length) > 0 then {effect: $e, text: "\($e): +\($new | join(","))"} else empty end
    else empty end ] as $w |
  ($cur.ver | sp_semv) as $cv | ($p.ver | sp_semv) as $pv |
  ($cv[0] > $pv[0] or ($cv[0] == 0 and $pv[0] == 0 and $cv[1] > $pv[1])) as $major |
  (if ($cur.authors | length) > 0 and ($p.authors | length) > 0 then (if ([$cur.authors[] | IN($p.authors[])] | any) then "same" else "changed" end) else "unsigned" end) as $ident |
  if ($w | length) > 0 and ($major | not) then {prev_path: $p.path, prev_ver: $p.ver, widened: $w, ident: $ident} else null end
end end
'

# I-JSON（spec §4.1）の問題を 1 つ出力する（問題が無ければ何も出力しない）
sp_ijson_problem() {
  local f="$1" a b
  if ! jq empty "$f" >/dev/null 2>&1; then echo "not valid JSON (or lone surrogate)"; return 0; fi
  jq -e 'type == "object"' "$f" >/dev/null 2>&1 || { echo "top-level value is not an object"; return 0; }
  a="$(jq -c --stream 'select(length == 2)' "$f" 2>/dev/null | wc -l | tr -d ' ')"
  b="$(jq -c 'tostream | select(length == 2)' "$f" 2>/dev/null | wc -l | tr -d ' ')"
  [ "$a" = "$b" ] || { echo "duplicate member name"; return 0; }
  jq -e '([paths | length] | max // 0) > 63' "$f" >/dev/null 2>&1 && { echo "nesting deeper than 64"; return 0; }
  jq -n -e --stream 'any(inputs; length == 2 and (.[1] | type) == "number" and ((.[1] | isinfinite) or (.[1] | isnan) or ((.[1] | if . < 0 then -. else . end) > 9007199254740991)))' "$f" >/dev/null 2>&1 \
    && { echo "number outside ±(2^53-1)"; return 0; }
  jq -e '[.. | strings, (objects | keys[])] | any(.[]; contains("\ufffd"))' "$f" >/dev/null 2>&1 && { echo "invalid UTF-8 or lone surrogate"; return 0; }
  return 0
}

# SKILL.md frontmatter の name
sp_fm_name() {
  awk 'NR == 1 { sub(/^\357\273\277/, "") } { sub(/\r$/, "") }
    NR == 1 { if ($0 !~ /^---[[:space:]]*$/) exit; fm = 1; next }
    fm && /^---[[:space:]]*$/ { exit }
    fm && /^name:/ { v = $0; sub(/^name:[[:space:]]*/, "", v); sub(/[[:space:]]+$/, "", v)
      if (v ~ /^".*"$/ || v ~ /^\047.*\047$/) v = substr(v, 2, length(v) - 2); print v; exit }' "$1" 2>/dev/null
}

# スキルディレクトリ（SKILL.md または skill.contract.json を含むディレクトリ）
sp_skill_dirs() {
  { files_named '^SKILL\.md$'; files_named '^skill\.contract\.json$'; } | while IFS= read -r f; do dirname -- "$f"; done | sort -u
}

# 祖先ディレクトリ（ROOT 内）に契約があるか（契約付きスキルの一部として扱い、個別に報告しない）
sp_under_contract() {
  local d="$1"
  while [ "$d" != "$ROOT" ] && [ "$d" != "/" ] && [ "$d" != "." ]; do
    d="$(dirname -- "$d")"
    case "$d/" in "$RP"/*) ;; *) return 1 ;; esac
    [ -f "$d/skill.contract.json" ] && return 0
  done
  return 1
}

# スキル直下のファイル（入れ子スキルの配下は除外）
sp_skill_files() {
  local dir="$1"
  ZES_V_D="$dir/" awk 'BEGIN { d = ENVIRON["ZES_V_D"] } index($0, d)==1' "$FILES_LIST" | while IFS= read -r f; do
    local rel="${f#"$dir"/}" sub="$dir" part nested=0
    while [[ "$rel" == */* ]]; do
      part="${rel%%/*}"; sub="$sub/$part"; rel="${rel#*/}"
      if [ -f "$sub/SKILL.md" ] || [ -f "$sub/skill.contract.json" ]; then nested=1; break; fi
    done
    [ "$nested" -eq 0 ] && printf '%s\n' "$f"
  done
}

# 実態抽出用テキスト（コードスコープ）を一時ファイルに書き出す（出力はしない）
#   MUST_LIST（任意）… 契約の entry.cli / tests.cases[].run / tests.setup が $SKILL_DIR/… で参照するファイル（スキル相対）。
#   参照されたファイルは拡張子・シバンの有無に依らずスクリプト（実行されるコード）として抽出する。
#   ルート内を指すシンボリックリンク（scripts/x.py → ../../lib/impl.py）はリンク先の内容を読む（build_inventory が FILES_LIST に加える）。
#   拡張子から種別が分からないテキストファイル（NUL を含まないもの）もコードスコープに含める（実行の効果は付けない）
sp_extract() {
  local dir="$1" code="$2" tools="$3" must="${4:-}"
  : >"$code"; : >"$tools"
  local f base ext rel
  local -a sexts; mapfile -t sexts < <(read_ioc '.skillpact.script_extensions')
  local sre; sre="$(printf '%s|' "${sexts[@]}" | sed 's/|$//')"
  local fre; fre="$(read_ioc '.skillpact.shell_fence_langs' | paste -sd'|' -)"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    base="${f##*/}"; ext="${base##*.}"
    [ "$base" = "skill.contract.json" ] && continue
    grep -q -x -F -- "$f" "$TMP_DIR/sp_policies.lst" 2>/dev/null && continue
    if [[ "$base" =~ \.md$ ]]; then
      ZES_FRE="$fre" ZES_V_CODE="$code" ZES_V_TOOLS="$tools" awk 'BEGIN { code = ENVIRON["ZES_V_CODE"]; tools = ENVIRON["ZES_V_TOOLS"] } 
        BEGIN { fre = "^(" ENVIRON["ZES_FRE"] ")$" }
        NR==1 && /^---[[:space:]]*$/ { fm=1; next }
        fm && /^---[[:space:]]*$/ { fm=0; next }
        fm { if ($0 ~ /^allowed-tools:/) print $0 >> tools; print $0 >> code; next }
        /^[[:space:]]*(```|~~~)/ {
          if (!infence) { lang=$0; sub(/^[[:space:]]*(```|~~~)[[:space:]]*/,"",lang); sub(/[[:space:]{].*/,"",lang); lang=tolower(lang); if (lang ~ fre) print "#ZES-SHELL-FENCE" >> code }
          infence=!infence; next }
        infence { print $0 >> code; next }' "$f"
    elif { [ -n "$must" ] && rel="${f#"$dir"/}" && grep -q -x -F -- "$rel" "$must" 2>/dev/null; } \
         || [[ "$ext" =~ ^($sre)$ ]] || head -c 2 -- "$f" 2>/dev/null | grep_q '^#!'; then
      printf '#ZES-SCRIPT %s\n' "$base" >>"$code"
      cat -- "$f" >>"$code"; printf '\n' >>"$code"
    elif [[ "$base" =~ \.(json|ya?ml|toml|ini|cfg)$ ]]; then
      cat -- "$f" >>"$code"; printf '\n' >>"$code"
    elif [ "$(head -c 8192 -- "$f" 2>/dev/null | tr -d -c '\000' | wc -c | tr -d ' ')" = "0" ]; then
      cat -- "$f" >>"$code"; printf '\n' >>"$code"
    fi
  done < <(sp_skill_files "$dir")
}

# 静的解析で見えた効果（SkillPact の 6 効果に対応づける。secrets → read（機密ファイル）、persist → write（作業領域外））
sp_observed() {
  local code="$1" tools="$2" e pats m re
  local exec=false network=false write=false spend=false send=false read=false durable=false
  for e in exec network write spend send; do
    pats="$(jq -r --arg e "$e" '.skillpact.observed_effect_patterns[$e] // [] | join("|")' "$IOC_FILE")"
    if [ "$e" = write ]; then
      sed -E 's#[0-9&]?>>?[[:space:]]*/dev/null##g' "$code" 2>/dev/null | grep_q -E -- "$pats" && write=true
    elif [ -n "$pats" ] && grep -q -E -- "$pats" "$code" 2>/dev/null; then printf -v "$e" true; fi
  done
  grep -q -E '^#ZES-(SCRIPT |SHELL-FENCE)' "$code" && exec=true
  grep -q -E '(^|[^A-Za-z])Bash([^A-Za-z]|$)' "$tools" && exec=true
  grep -q -E '(WebFetch|WebSearch)' "$tools" && network=true
  grep -q -E '(^|[^A-Za-z])(Write|Edit|MultiEdit|NotebookEdit)([^A-Za-z]|$)' "$tools" && write=true
  pats="$(jq -r '.skillpact.sensitive_read_patterns | join("|")' "$IOC_FILE")"
  grep -q -E -- "$pats" "$code" 2>/dev/null && read=true
  while IFS= read -r m; do
    [ -n "$m" ] || continue
    if [ "$m" = "registry run" ]; then re='registry[[:space:]]+run|CurrentVersion\\Run|reg[[:space:]]+add[^\n]*\\Run'
    else re="$(printf '%s' "$m" | sed 's/[.[\*^$]/\\&/g; s/ /[[:space:]]+/g')"; fi
    grep -q -i -E -- "$re" "$code" 2>/dev/null && { durable=true; write=true; }
  done < <(read_ioc '.skillpact.persistence_markers')
  jq -n -c --argjson x "$exec" --argjson n "$network" --argjson w "$write" --argjson s "$spend" --argjson m "$send" --argjson r "$read" --argjson d "$durable" \
    '{exec:$x, network:$n, write:$w, spend:$s, send:$m, read:$r, durable:$d}'
}

# 前版比較用: ROOT 内の skill.contract.json とキャッシュ内の契約を JSONL で列挙
sp_contract_index() {
  {
    files_named '^skill\.contract\.json$'
    if [ -n "$SKILLPACT_CACHE" ] && [ -d "$SKILLPACT_CACHE" ]; then find "$SKILLPACT_CACHE" -type f -name '*.json' 2>/dev/null | qstore_filter "$SKILLPACT_CACHE"; fi
  } | sort -u | while IFS= read -r f; do
    [ -n "$f" ] || continue
    jq -c --arg p "$f" "$SP_JQ_LIB"' select(type == "object" and (.skill.name | type) == "string" and (.skill.version | type) == "string" and (.permissions | type) == "object")
      | {path: $p, name: .skill.name, ver: .skill.version, perms: .permissions, authors: (try sp_authors catch [])}' "$f" 2>/dev/null
  done
}

sp_field() {  # sp_field ANALYSIS_JSON OBSERVED_JSON CONTRACT_PATH DIFF_ANOMALY
  jq -n -c --argjson a "$1" --argjson o "$2" --arg cp "$3" --argjson da "$4" --argjson R "$SP_RULES" '
    {contract_path: (if $cp == "" then null else $cp end), contract_version: ($a.cv // null), level: ($a.level // null),
     signed: ($a.signed // false), author: ($a.author // null), declared_effects: ($a.declared // []),
     observed_effects: [$R.effects[] as $e | select($o[$e]) | $e], policy_decision: null, l2_tested: false,
     divergence: [($a.divergence // [])[].effect] | unique | sort_by(. as $e | $R.effects | index($e)), diff_anomaly: $da}'
}

# SkillPact ポリシー（policy_version と defaults を持つ JSON）の構造検査
sp_policies() {
  : >"$TMP_DIR/sp_policies.lst"
  local f prob bad sp
  grep -E '\.json$' "$FILES_LIST" | grep -v -E '/skill\.contract\.json$' | tr '\n' '\0' \
    | xargs -0 grep -l -a -F '"policy_version"' -- /dev/null 2>/dev/null | grep -v '^/dev/null$' | while IFS= read -r f; do
    jq -e 'type == "object" and has("policy_version") and has("defaults")' "$f" >/dev/null 2>&1 || continue
    printf '%s\n' "$f" >>"$TMP_DIR/sp_policies.lst"
    prob="$(sp_ijson_problem "$f")"
    if [ -z "$prob" ]; then
      bad="$(jq -r --argjson R "$SP_RULES" '[
        ((keys - $R.policy_keys) | if length > 0 then "unknown key " + join(",") else empty end),
        (if (.policy_version | IN($R.policy_versions[])) | not then "policy_version" else empty end),
        (.defaults | if type != "object" or ((keys | sort) != ($R.effects | sort)) or any(.[]; IN($R.decision_values[]) | not) then "defaults" else empty end),
        ((.rules // []) | if type != "array" then "rules" else (.[] | if type != "object" or ((keys - ["id", "effect", "scope", "decision"]) | length) > 0 or ((.effect | IN($R.effects[])) | not) or ((.decision | IN($R.decision_values[])) | not) or (has("scope") and ((.scope | type) != "array" or any(.scope[]; type != "string"))) then "rules" else empty end) end),
        ("never_auto_allow_any", "trusted_keys") as $k | (if has($k) and ((.[$k] | type) != "array" or any(.[$k][]; type != "string")) then $k else empty end),
        ("require_signature", "ask_on_destructive", "allowlist_overrides_ask") as $k | (if has($k) and ((.[$k] | type) != "boolean") then $k else empty end),
        (if has("min_contract_version") and ((.min_contract_version | type) != "string" or (.min_contract_version | test("^[0-9]+\\.[0-9]+$") | not)) then "min_contract_version" else empty end),
        (if has("compositions") and ((.compositions | type) != "object" or ((.compositions | keys) - ["exfiltration", "persistence", "spend_untrusted"] | length) > 0 or any(.compositions[]; IN($R.decision_values[]) | not)) then "compositions" else empty end)
      ] | unique | join(", ")' "$f" 2>/dev/null)" || bad="SCHEMA"
    else bad="JSON: $prob"; fi
    sp="$(jq -n -c '{contract_path:null, contract_version:null, level:null, signed:false, author:null, declared_effects:[], observed_effects:[], policy_decision:null, l2_tested:false, divergence:[], diff_anomaly:false}')"
    if [ -n "$bad" ]; then
      medium "skillpact-invalid" "$f" "SkillPact ポリシーを検証できません（${bad}）。ZES はポリシーの allow/ask/deny 判定を行いません" "$sp"
    else
      log_info "SkillPact ポリシーを検出（構造は妥当。allow/ask/deny の評価は ZES では未実装）: $f"
    fi
  done
}

sp_effect_label() {
  case "$1" in
    exec) printf 'exec（他のプログラムの実行）' ;; network) printf 'network（外部ホストとの通信）' ;;
    spend) printf 'spend（課金・決済）' ;; send) printf 'send（メール・投稿・メッセージの送信）' ;;
    read) printf 'read（機密ファイル: ~/.ssh・.env・認証情報など）' ;; write) printf 'write（ファイルの書き込み）' ;;
  esac
}

check_skillpact() {
  log_section "§49" "SkillPact 契約（実験的）"
  if [ "$HAVE_JQ" -ne 1 ]; then record_error "§49" "jq_unavailable"; return 0; fi
  SP_RULES="$(jq -c '.skillpact' "$IOC_FILE")"
  sp_policies
  sp_contract_index >"$TMP_DIR/sp_index.jsonl"
  local dir n_skills=0 n_contracts=0
  while IFS= read -r dir; do
    [ -n "$dir" ] || continue
    n_skills=$((n_skills + 1))
    local cpath="$dir/skill.contract.json"
    { [ -f "$cpath" ] && [ ! -L "$cpath" ]; } || cpath=""
    if [ -z "$cpath" ] && sp_under_contract "$dir"; then continue; fi
    local code="$TMP_DIR/sp_code" tools="$TMP_DIR/sp_tools" must="$TMP_DIR/sp_must"
    : >"$must"
    [ -n "$cpath" ] && jq -r 'try ([((.capabilities // [])[]? | (.entry.cli? // []) | if type == "array" then .[] else empty end),
        ((.tests.cases // [])[]? | .run | if type == "array" then .[] else . end), ((.tests.setup // [])[]? | if type == "array" then .[] else . end)]
        | .[] | strings | match("\\$SKILL_DIR/([^\\s\u0027\"]+)"; "g") | .captures[0].string) catch empty' "$cpath" >"$must" 2>/dev/null
    sp_extract "$dir" "$code" "$tools" "$must"
    local obs; obs="$(sp_observed "$code" "$tools")"
    local obs_txt; obs_txt="$(printf '%s' "$obs" | jq -r --argjson R "$SP_RULES" '[$R.effects[] as $e | select(.[$e]) | $e] | join(",")')"

    if [ -z "$cpath" ]; then
      # 契約なし: SkillPact を使わないスキルは対象外。影響の大きい効果が見える場合のみ参考 INFO
      if [ -f "$dir/SKILL.md" ] && printf '%s' "$obs" | jq -e '.exec or .network or .spend or .send' >/dev/null; then
        info "skillpact-undeclared" "$dir" "このスキルには SkillPact 契約（skill.contract.json）がないため、宣言との比較は行いません（参考: コードに見える効果 ${obs_txt}）" \
          "$(sp_field '{}' "$obs" "" false)"
      fi
      continue
    fi
    n_contracts=$((n_contracts + 1))
    local prob; prob="$(sp_ijson_problem "$cpath")"
    if [ -n "$prob" ]; then
      medium "skillpact-invalid" "$cpath" "SkillPact 契約を検証できません（CONTRACT_JSON: ${prob}）。宣言を読めないため乖離判定は行いません" "$(sp_field '{}' "$obs" "$cpath" false)"
      record_error "§49" "contract_unparseable:$cpath"
      continue
    fi
    # スキル配下の全ファイル・シンボリックリンク（相対パス）と integrity.files に載ったファイルのハッシュ
    local files_json links_json hashes_json rel
    files_json="$(grep -v -x -F -f "$LINKED_FILES_LIST" "$FILES_LIST" | ZES_V_D="$dir/" awk 'BEGIN { d = ENVIRON["ZES_V_D"] } index($0, d)==1 { print substr($0, length(d) + 1) }' | jq -R . | jq -s -c .)"
    links_json="$(ZES_V_D="$dir/" awk 'BEGIN { d = ENVIRON["ZES_V_D"] } index($0, d)==1 { print substr($0, length(d) + 1) }' "$LINKS_LIST" | jq -R . | jq -s -c .)"
    hashes_json="$(jq -r '(.integrity.files? // {}) | if type == "object" then keys[] else empty end' "$cpath" 2>/dev/null | while IFS= read -r rel; do
        case "/$rel/" in */../*|*/./*|*//*) continue ;; esac
        { [ -f "$dir/$rel" ] && [ ! -L "$dir/$rel" ]; } || continue
        printf '%s\t%s\n' "$rel" "$(sha256_file "$dir/$rel")"
      done | jq -R -s -c 'split("\n") | map(select(length > 0) | split("\t") | {(.[0]): .[1]}) | add // {}')"
    local fm=""; [ -f "$dir/SKILL.md" ] && fm="$(sp_fm_name "$dir/SKILL.md")"
    local a
    a="$(jq -c --argjson R "$SP_RULES" --argjson files "$files_json" --argjson links "$links_json" --argjson hashes "$hashes_json" \
          --arg fm "$fm" --argjson obs "$obs" "$SP_JQ_LIB $SP_ANALYZE" "$cpath" 2>/dev/null)"
    if [ -z "$a" ]; then
      medium "skillpact-invalid" "$cpath" "SkillPact 契約を検証できません（解析に失敗）。乖離判定は行いません" "$(sp_field '{}' "$obs" "$cpath" false)"
      record_error "§49" "contract_analysis_failed:$cpath"
      continue
    fi

    # 前版との差分（spec §17）
    local diff="null"
    if printf '%s' "$a" | jq -e '.vstatus == "ok" and .permsok and (.name | type) == "string" and (.sver | type) == "string"' >/dev/null; then
      diff="$(jq -c -n --argjson R "$SP_RULES" --slurpfile idx "$TMP_DIR/sp_index.jsonl" --arg p "$cpath" --argjson a "$a" \
        "$SP_JQ_LIB"' {path: $p, name: $a.name, ver: $a.sver, perms: input.permissions, authors: $a.authors} | '"$SP_DIFF" "$cpath" 2>/dev/null)"
      [ -n "$diff" ] || diff="null"
    fi
    local da=false; [ "$diff" != "null" ] && da=true
    local sp; sp="$(sp_field "$a" "$obs" "$cpath" "$da")"
    local sig_note=""
    printf '%s' "$a" | jq -e '.signed' >/dev/null && sig_note="（契約に署名がありますが ZES は署名を検証しません。署名の有無で重大度は変えません）"

    local vs cv errs
    vs="$(printf '%s' "$a" | jq -r '.vstatus')"; cv="$(printf '%s' "$a" | jq -r '.cv // "未指定"')"
    if [ "$vs" != "ok" ]; then
      medium "skillpact-invalid" "$cpath" "SkillPact 契約の contract_version「${cv}」には対応していません（ZES の対応: 0.1〜0.8）。宣言を解釈できないため乖離判定は行いません" "$sp"
      continue
    fi
    errs="$(printf '%s' "$a" | jq -r '.errors | join(",")')"
    [ -n "$errs" ] && medium "skillpact-invalid" "$cpath" "SkillPact 契約を検証できません（ZES の部分検査: ${errs}）。L1 とは見なしません" "$sp"

    local eff why sens durable lv txt
    while IFS=$'\t' read -r eff why sens durable; do
      [ -n "$eff" ] || continue
      case "$eff" in exec|network|spend|send) lv=HIGH ;; *) lv=MEDIUM ;; esac
      if [ "$durable" = "true" ]; then
        txt="コードに作業領域外への永続的な書き込み（crontab・.bashrc・authorized_keys など）が見えますが、契約の write は"
        [ "$why" = "none" ] && txt="${txt}宣言されていません（permissions.write: none）" || txt="${txt} \$WORKDIR / \$OUTPUT / \$TMPDIR 内に限られています"
      elif [ "$sens" = "true" ]; then
        txt="コードが $(sp_effect_label read)を読む可能性がありますが、契約の read は"
        [ "$why" = "none" ] && txt="${txt}宣言されていません（permissions.read: none）" || txt="${txt}その範囲を含みません"
      else
        txt="コードに $(sp_effect_label "$eff")が見えますが、契約は ${eff} を宣言していません（permissions.${eff}: none）"
      fi
      emit "$lv" "skillpact-divergence" "$dir" "${txt}${sig_note}" "$sp"
    done < <(printf '%s' "$a" | jq -r '.divergence[] | [.effect, .why, (.sensitive // false), (.durable // false)] | @tsv')

    if [ "$da" = true ]; then
      local dl dtxt
      dl="$(printf '%s' "$diff" | jq -r 'if any(.widened[]; .effect | IN("exec", "network", "spend", "send")) then "HIGH" else "MEDIUM" end')"
      dtxt="$(printf '%s' "$diff" | jq -r '"前版 \(.prev_ver)（\(.prev_path)）から権限が拡大していますが（\([.widened[].text] | join(" / "))）、skill.version の major が上がっていません（SkillPact §17）。作者署名鍵: " + (if .ident == "same" then "前版と同一（未検証。正規の鍵で署名された静かな拡大はアカウント侵害の兆候）" elif .ident == "changed" then "前版と異なる（未検証）" else "署名なし" end)')"
      emit "$dl" "skillpact-account-compromise" "$cpath" "$dtxt" "$sp"
    fi
    local nf; nf="$(grep -c -F "\"contract_path\":\"$(json_escape "$cpath")\"" "$FINDINGS_FILE" 2>/dev/null)"
    if [ "${nf:-0}" -eq 0 ]; then
      log_info "$(printf '%s' "$a" | jq -r '"SkillPact 契約（\(.name // "?")@\(.sver // "?")、contract \(.cv)）: 宣言とコードの静的解析に乖離なし。L1 相当（ZES の部分検査）。L2/L3 は ZES では検証しません（L3 でも安全を意味しません）。署名: " + (if .signed then "あり（未検証）" else "なし" end)')（$dir）"
    fi
  done < <(sp_skill_dirs)
  [ "$n_skills" -eq 0 ] && log_info "スキル（SKILL.md / skill.contract.json）が見つかりません"
  [ "$n_skills" -gt 0 ] && [ "$n_contracts" -eq 0 ] && log_info "SkillPact 契約（skill.contract.json）のあるスキルはありません（§49 は契約付きスキルのみ比較します）"
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
  # scan_roots … --root の実パス（ZET はこれを計画の検査範囲 plan.scope.roots にする）
  printf '{"schema_version":"%s","scan_roots":[%s],"incident_bundle":"%s","scan_started_at":"%s","scan_finished_at":"%s","scan_mode":"%s","status":"%s","findings":[' \
    "$FINDINGS_SCHEMA_VERSION" "$(jq_str "$ROOT")" "$INCIDENT_BUNDLE" "$SCAN_STARTED_AT" "$(iso_now)" "$MODE" "$status"
  paste -sd, "$FINDINGS_FILE" | tr -d '\n'
  printf '],"errors":['
  sort -u "$ERRORS_FILE" | paste -sd, - | tr -d '\n'
  printf ']}\n'
}

# findings の id を一意にする（ZET は id の重複した入力をまとめて拒否する）。
# emit() の SEEN_IDS はモジュールごとのサブシェルの中でしか効かず、正規形（zes_enc）は単射ではない（"\xHH" という
# 文字列のパスと不正なバイト 0xHH のパスが同じ値になる）ため、ここで最初の 1 件だけを残し、落とした分を errors[] に記録する
dedup_findings() {
  local tmp="$TMP_DIR/findings.dedup" dup="$TMP_DIR/findings.dupids" id
  LC_ALL=C awk -v dup="$dup" '{ id = substr($0, 8, 71) } seen[id]++ { print id > dup; next } { print }' "$FINDINGS_FILE" >"$tmp" || return 0
  mv -f "$tmp" "$FINDINGS_FILE"
  [ -s "$dup" ] || return 0
  while IFS= read -r id; do record_error "core" "duplicate_finding_id:$id"; done <"$dup"
}

main() {
  local ib; ib="$(read_ioc '.incident_bundle')"
  if [ "$ib" != "$INCIDENT_BUNDLE" ]; then
    record_error "core" "incident_bundle_mismatch:${ib:-none}"
  fi
  zes_enc "$ROOT"
  printf '%sZero-Exec Shield v%s（仕様 v%s）%s  bundle=%s  mode=%s  root=%s  os=%s  jq=%s\n' "$C_CYN" "$ZES_VERSION" "$ZES_SPEC_VERSION" "$C_OFF" "$INCIDENT_BUNDLE" "$MODE" "$ENC_TERM" "$OS_NAME" "$HAVE_JQ" >&3
  # 無害化で外した PATH エントリ（相対・空・検査ルート配下）。検査ルート内の偽 jq / git / coreutils は起動しない
  local e
  for e in "${PATH_DROPPED[@]}"; do record_error "core" "path_entry_dropped:$e"; done
  [ "$HAVE_JQ" -eq 1 ] || log_info "jq が見つかりません。grep フォールバックで実行します（§48/§49 は未確定扱い）"
  [ "$ROOT" = "/" ] && log_info "--root /: ホスト全体を走査します（擬似ファイルシステムは開かずに errors[] に記録。PATH の検査ルート配下判定は行いません）"
  CURRENT_MODULE="core"
  build_inventory
  git_discover
  local n nmod=0 nfail=0
  for n in $(modules_for_mode "$MODE"); do
    nmod=$((nmod + 1))
    # モジュールはサブシェルで実行し、異常終了（set -u 等）を module_failed として記録する（fail-closed）
    ( "check_s$n" ) || { record_error "§$n" "module_failed"; nfail=$((nfail + 1)); }
  done
  # 全モジュールが異常終了した場合は検査結果として使えないため致命的（status=error / 終了コード 2）
  [ "$nmod" -gt 0 ] && [ "$nfail" -eq "$nmod" ] && FATAL=1
  dedup_findings
  local status="ok"
  # archive_not_inspected は既知の制限（アーカイブを展開しない）を示す参考情報で、status を partial にしない
  # quarantine_store_skipped（GER の隔離ストアを意図して走査しない）も同じ扱い
  grep -v -F -e '"reason":"archive_not_inspected:' -e '"reason":"quarantine_store_skipped:' "$ERRORS_FILE" | grep_q . && status="partial"
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
