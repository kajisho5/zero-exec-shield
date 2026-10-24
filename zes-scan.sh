#!/usr/bin/env bash
# =============================================================================
# Zero-Exec Shield (ZES) v5.2 — Core CLI Scanner
# incident_bundle: ZES-2026-OCT-EMERGENCY-V5.2
#
# Core principles (Master Spec §1)
#   - Zero-Execution: never start any runtime or script of the inspected target
#   - Static, passive analysis only (find / grep / readlink / stat / curl -sI / ps / lsof / uname / docker --version)
#   - No content reading: even on a hit, file contents are never output; only the path and metadata are shown
#   - fail-closed: modules that could not be inspected are recorded in errors[], never treated as 0 hits
#   - Bash 4+ / set -u / jq preferred with grep fallback / works on both macOS and Linux
#
# Environment variables (for tests and operations)
#   ZES_IOC          path to ioc.json (default: <script_dir>/rules/ioc.json)
#   ZES_HOME         target of the home-directory checks (default: $HOME)
#   ZES_HOST_CHECKS  0 disables the host state checks (ps/lsof/proc/uname/docker etc.) (default: 1)
#   ZES_OFFLINE      1 disables outbound traffic (§4 --url / §6 eMudhra) (default: 0)
#   ZES_SKILLPACT_CACHE  local cache of previous-version contracts for §49
#   ZES_NOW          override of the current time (epoch seconds, for tests)
#   ZES_FORCE_NO_JQ  1 forces the grep fallback without jq (for tests)
#   ZES_GIT_TIMEOUT  timeout in seconds for the git calls of §38/§46 (default 60)
#   ZES_LANG         Terminal language (log, help, errors): en | ja. Default: the locale. findings.json is always English
#   ZES_I18N_DIR     Message catalog directory (default: <script_dir>/i18n; for tests)
# =============================================================================
set -u
set -o pipefail
umask 077
# If CDPATH is exported, a relative cd resolves to another directory and also prints the path to stdout, so disable it
unset CDPATH

ZES_VERSION="0.5.1"      # software version
ZES_SPEC_VERSION="5.2"   # version of the Master Specification this conforms to
INCIDENT_BUNDLE="ZES-2026-OCT-EMERGENCY-V5.2"
FINDINGS_SCHEMA_VERSION="1.2"  # 1.2: code / params (catalog key and values), English detail, id v2

if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
  echo "ZES: ZES needs Bash 4 or later (found: ${BASH_VERSION:-unknown}). On macOS, run 'brew install bash'." >&2
  echo "ZES: Bash 4 以上が必要です（現在: ${BASH_VERSION:-unknown}）。macOS は 'brew install bash' を利用してください。" >&2
  exit 64
fi

# Language of the terminal output (log, help, errors): --lang > ZES_LANG > LC_ALL > LC_MESSAGES > LANG.
#   findings.json is always English. The locale is read here, before LC_ALL=C below.
#   ja (no charset, or UTF-8) → ja; ja_JP.eucJP / SJIS and everything else → en. An invalid ZES_LANG is silently en.
zes_lang_of_locale() {  # zes_lang_of_locale VALUE → ZES_LANG_RESOLVED
  local v="$1" cs
  ZES_LANG_RESOLVED=en
  case "$v" in
    ja|ja_*|ja.*|ja@*)
      case "$v" in
        *.*) cs="${v#*.}"; cs="${cs%%@*}"; cs="${cs,,}"
             case "$cs" in utf-8|utf8) ZES_LANG_RESOLVED=ja ;; esac ;;
        *) ZES_LANG_RESOLVED=ja ;;
      esac ;;
  esac
}
ZES_LANG_ARG=""; ZES_LANG_ARG_BAD=0
_zes_a=("$@"); _zes_i=0
while [ "$_zes_i" -lt "${#_zes_a[@]}" ]; do
  case "${_zes_a[_zes_i]}" in
    --root|--url|--skillpact-cache) _zes_i=$((_zes_i + 1)) ;;
    # every --lang value is checked (not only the last one, which decides the language)
    --lang) ZES_LANG_ARG="${_zes_a[_zes_i + 1]-}"; _zes_i=$((_zes_i + 1))
            case "$ZES_LANG_ARG" in en|ja) ;; *) ZES_LANG_ARG_BAD=1 ;; esac ;;
  esac
  _zes_i=$((_zes_i + 1))
done
unset _zes_a _zes_i
case "${ZES_LANG:-}" in
  en|ja) ZES_LANG_RESOLVED="$ZES_LANG" ;;
  ?*) ZES_LANG_RESOLVED=en ;;
  *) zes_lang_of_locale "${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}" ;;
esac
case "$ZES_LANG_ARG" in en|ja) ZES_LANG_RESOLVED="$ZES_LANG_ARG" ;; esac

export LC_ALL=C

# PATH sanitization (stage 1): drop relative and empty entries ("." or "::" = the current directory).
#   So that, when started inside the scan root, a fake jq / git / coreutils in the root is never started (Zero-Execution).
#   Once the scan root is fixed (stage 2: zes_sanitize_path_root), entries whose real path is under the scan root are dropped too.
#   Up to this point no external command is started at all (dirname / uname etc. also go through PATH, so call them after sanitization)
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
      rp="$(cd -P -- "$e" 2>/dev/null && pwd -P)" || continue   # a nonexistent directory finds nothing, so just drop it
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

# Location of the script (computed with parameter expansion, without dirname)
_zes_src="${BASH_SOURCE[0]}"
case "$_zes_src" in */*) _zes_src="${_zes_src%/*}" ;; *) _zes_src="." ;; esac
SCRIPT_DIR="$(cd -- "${_zes_src:-/}" && pwd -P)"
unset _zes_src
IOC_FILE="${ZES_IOC:-$SCRIPT_DIR/rules/ioc.json}"
# A relative path from the environment gets a "./" prefix: awk would read "x=y/ioc.json" as a variable assignment (and then
#   read stdin), and grep / sed / jq would read "-x…" as an option. Paths of scanned files are always absolute (ROOT, HOME_DIR)
case "$IOC_FILE" in /*) ;; *) IOC_FILE="./$IOC_FILE" ;; esac
HOME_DIR="${ZES_HOME:-${HOME:-}}"
HOST_CHECKS="${ZES_HOST_CHECKS:-1}"
OFFLINE="${ZES_OFFLINE:-0}"
SKILLPACT_CACHE="${ZES_SKILLPACT_CACHE:-}"

# String encoding (one pass gives the forms for JSON, human-readable logs and the id preimage)
#   zes_enc STR sets the following variables:
#     ENC_NORM … normal form. Each invalid UTF-8 byte is replaced by "\xHH" (4 characters of text); everything else is kept as is.
#                the JSON values (after decoding) match this normal form
#     ENC_JSON … JSON string representation of ENC_NORM (without quotes). Escapes " and \, and turns control characters (U+0000-U+001F, U+007F) and
#                C1 control characters (U+0080-U+009F) into \u00XX (round-trippable)
#     ENC_TERM … for human-readable logs. Shows control characters as \xHH and C1 control characters as \u00HH (prevents terminal escape injection)
#     ENC_BAD  … 1 if the string contains invalid UTF-8 bytes
#     ENC_ID   … the form used in the id preimage (id v2): the original string with \ → \\, | → \|, U+001F → the six
#                characters \u001f and each invalid UTF-8 byte → the four characters \xHH (lower-case hex). The escaping is
#                applied to the original bytes, so it is injective: an invalid byte (\xHH) and the text "\xHH" (\\xHH) differ.
#                ENC_NORM maps both to the same text, which is why the id is not built from it
#   Strings of printable ASCII only are handled without starting awk
ZES_ENC_AWK='
  BEGIN {
    for (k = 1; k < 256; k++) ord[sprintf("%c", k)] = k
    s = ENVIRON["ZES_ENC"]; n = length(s); nb = ""; js = ""; tm = ""; id = ""; bad = 0; i = 1
    while (i <= n) {
      c = substr(s, i, 1); b = ord[c]
      if (b < 128) {
        if (b == 31) id = id "\\x5cu001f"; else if (b < 32 || b == 127) id = id sprintf("\\x%02x", b)
        else if (c == "\\") id = id "\\x5c\\x5c"; else if (c == "|") id = id "\\x5c|"; else id = id c
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
      if (!ok) { h = sprintf("%02x", b); nb = nb "\\x5cx" h; js = js "\\\\x" h; tm = tm "\\x" h; id = id "\\x5cx" h; bad = 1; i++; continue }
      q = substr(s, i, L); nb = nb q; id = id q
      if (cp >= 128 && cp <= 159) { js = js sprintf("\\u%04x", cp); tm = tm sprintf("\\u%04x", cp) } else { js = js q; tm = tm q }
      i += L }
    print nb; print js; print tm; print bad; print id }'
# zes_id_esc VALUE → ID_ESC: the id escaping of valid UTF-8 text (ENC_ID of zes_enc without the awk run)
ZES_BS='\'
US_CHAR=$'\037'
zes_id_esc() {  # zes_id_esc VALUE → ID_ESC
  local v="${1//"$ZES_BS"/"$ZES_BS$ZES_BS"}"
  v="${v//"|"/"$ZES_BS|"}"
  ID_ESC="${v//"$US_CHAR"/"${ZES_BS}u001f"}"
}
zes_enc() {
  local s="$1"
  if [[ "$s" != *[![:print:]]* ]]; then
    ENC_NORM="$s"; ENC_TERM="$s"; ENC_BAD=0; zes_id_esc "$s"; ENC_ID="$ID_ESC"
    s="${s//\\/\\\\}"; ENC_JSON="${s//\"/\\\"}"
    return 0
  fi
  local -a enc_r=()
  mapfile -t enc_r < <(ZES_ENC="$s" awk "$ZES_ENC_AWK")
  # Line 1 is in %b form (every backslash is \xHH), passing the normal form, which may contain control characters, without a newline
  printf -v ENC_NORM '%b' "${enc_r[0]-}"
  ENC_JSON="${enc_r[1]-}"; ENC_TERM="${enc_r[2]-}"; ENC_BAD="${enc_r[3]:-0}"
  # Line 5 (the id form) is in %b form too
  printf -v ENC_ID '%b' "${enc_r[4]-}"
}
json_escape() { zes_enc "$1"; printf '%s' "$ENC_JSON"; }
json_str_or_null() { if [ -n "$1" ]; then printf '"%s"' "$(json_escape "$1")"; else printf 'null'; fi; }

ROOT="."
MODE=""
JSON_OUT=0
TARGET_URL=""

# render TEMPLATE [key=value...] → RENDERED. One left-to-right pass over the template: {name} ([a-z_]+) is replaced by
#   its value, a value that contains "{x}" is not expanded again, and a placeholder without a value stays "{name}"
#   (tests fail on it). No ${s//pat/rep} with the value (bash 5.2 patsub_replacement turns "&" into the match).
#   Pure bash (no external command): usage() and arg_error() need it before PATH is fully sanitised
zes_render() {
  local t="$1" out="" a name; shift
  local -A rv=()
  for a in "$@"; do rv["${a%%=*}"]="${a#*=}"; done
  while [[ "$t" == *"{"* ]]; do
    out+="${t%%\{*}"; t="${t#*\{}"
    if [[ "$t" =~ ^([a-z_]+)\} ]]; then
      name="${BASH_REMATCH[1]}"; t="${t:${#name}+1}"
      if [ -n "${rv[$name]+x}" ]; then out+="${rv[$name]}"; else out+="{$name}"; fi
    else
      out+="{"
    fi
  done
  RENDERED="$out$t"
}

# Help and argument / environment errors (cli.*). They are needed before the catalog can be read (and an unreadable
#   catalog is itself one of them), so both languages are kept here. tests/run-tests.sh checks that this block equals
#   the cli.* entries of i18n/en.json and i18n/ja.json.
# >>> cli-messages
declare -A CLI_MSG_EN=(
  [cli.help.usage]='Usage: zes-scan.sh [--quick|--standard|--full|--worm|--skillpact] [--root DIR] [--url URL] [--json]'
  [cli.help.usage_more]='                   [--skillpact-cache DIR] [--lang en|ja]'
  [cli.help.root]='  --root DIR     Directory to scan (default ".")'
  [cli.help.full]='  --full         Run §1–49'
  [cli.help.standard]='  --standard     Run §1–35'
  [cli.help.quick]='  --quick        Run §1–19 (default)'
  [cli.help.worm]='  --worm         Run §15, §18, §25 and §45 only'
  [cli.help.skillpact]='  --skillpact    Run §49 only'
  [cli.help.url]='  --url URL      §4 passive URL check: reads only the Server and X-Powered-By headers (HEAD; GET only after 405/501; redirects are not followed)'
  [cli.help.json]='  --json         Write findings.json to stdout (the log goes to stderr)'
  [cli.help.skillpact_cache]='  --skillpact-cache DIR  Earlier contract versions for the §49 diff check'
  [cli.help.lang]='  --lang en|ja   Language of the log and this help (default: ZES_LANG, then the locale). findings.json is always in English.'
  [cli.help.exit]='Exit codes: 0 = finished (status ok or partial), 2 = status error (the scan root could not be listed, or every module failed), 64 = bad arguments or environment'
  [cli.arg.mode_conflict]='Only one mode can be given (got {a} and {b})'
  [cli.arg.unknown]='Unknown argument: {value}'
  [cli.arg.lang]='--lang must be en or ja'
  [cli.arg.root_not_dir]='--root is not a directory: {value}'
  [cli.arg.root_unresolved]='Cannot resolve --root'
  [cli.arg.home_unset]='No home directory. Set ZES_HOME or HOME.'
  [cli.arg.home_not_dir]='ZES_HOME/HOME is not a directory: {value}'
  [cli.arg.home_unresolved]='Cannot resolve ZES_HOME/HOME'
  [cli.arg.url_scheme]='--url must start with {http} or {https}'
  [cli.arg.url_chars]='--url contains characters that are not allowed'
  [cli.err.catalog]='Cannot read the message catalog: {path}'
  [cli.err.tmpdir]='Cannot create a temporary directory'
  [cli.err.ioc_unreadable]='Cannot read the IoC database: {path}'
  [cli.err.ioc_invalid]='The IoC database is not valid JSON: {path}'
)
declare -A CLI_MSG_JA=(
  [cli.help.usage]='Usage: zes-scan.sh [--quick|--standard|--full|--worm|--skillpact] [--root DIR] [--url URL] [--json]'
  [cli.help.usage_more]='                   [--skillpact-cache DIR] [--lang en|ja]'
  [cli.help.root]='  --root DIR     検査ルート（既定 "."）'
  [cli.help.full]='  --full         §1〜49 全実行'
  [cli.help.standard]='  --standard     §1〜35'
  [cli.help.quick]='  --quick        §1〜19（既定）'
  [cli.help.worm]='  --worm         §15/18/25/45 のみ'
  [cli.help.skillpact]='  --skillpact    §49 のみ'
  [cli.help.url]='  --url URL      §4 の非侵襲URLチェック（Server / X-Powered-By ヘッダのみ取得。HEAD、405/501 時のみ GET、リダイレクト非追従）'
  [cli.help.json]='  --json         findings.json を標準出力へ（人間向けログは標準エラーへ）'
  [cli.help.skillpact_cache]='  --skillpact-cache DIR  §49 差分異常検出用の前バージョン契約キャッシュ'
  [cli.help.lang]='  --lang en|ja   ログとこのヘルプの言語（既定: ZES_LANG、次にロケール）。findings.json は常に英語'
  [cli.help.exit]='終了コード: 0=完了(status ok/partial) / 2=status error（インベントリを作れない・全モジュール失敗） / 64=引数・環境エラー'
  [cli.arg.mode_conflict]='モード指定が重複しています（{a} と {b}）'
  [cli.arg.unknown]='不明な引数: {value}'
  [cli.arg.lang]='--lang は en か ja を指定してください'
  [cli.arg.root_not_dir]='--root がディレクトリではありません: {value}'
  [cli.arg.root_unresolved]='--root を解決できません'
  [cli.arg.home_unset]='ホームディレクトリが未設定です（ZES_HOME または HOME を指定してください）'
  [cli.arg.home_not_dir]='ZES_HOME/HOME がディレクトリではありません: {value}'
  [cli.arg.home_unresolved]='ZES_HOME/HOME を解決できません'
  [cli.arg.url_scheme]='--url は {http} または {https} のみ受け付けます'
  [cli.arg.url_chars]='--url に使用できない文字が含まれています'
  [cli.err.catalog]='メッセージカタログを読めません: {path}'
  [cli.err.tmpdir]='一時ディレクトリを作成できません'
  [cli.err.ioc_unreadable]='IoC データベースを読めません: {path}'
  [cli.err.ioc_invalid]='IoC データベースが不正な JSON です: {path}'
)
# Lines of the help ("" = blank line)
CLI_HELP_LINES=(cli.help.usage cli.help.usage_more "" cli.help.root cli.help.full cli.help.standard cli.help.quick
  cli.help.worm cli.help.skillpact cli.help.url cli.help.json cli.help.skillpact_cache cli.help.lang "" cli.help.exit)
# <<< cli-messages

# cli_text KEY [key=value...] → RENDERED (in the terminal language)
cli_text() {
  local k="$1"; shift
  if [ "$ZES_LANG_RESOLVED" = ja ]; then zes_render "${CLI_MSG_JA[$k]-$k}" "$@"; else zes_render "${CLI_MSG_EN[$k]-$k}" "$@"; fi
}
# cli_fail KEY [key=value...] … prints "ZES: <message>" to stderr and exits 64. The values (paths from ZES_I18N_DIR,
#   ZES_IOC, arguments) and the message are encoded for the terminal like every other untrusted text (zes_enc)
cli_fail() {
  local k="$1" a; shift
  local -a kv=()
  for a in "$@"; do zes_enc "${a#*=}"; kv+=("${a%%=*}=$ENC_TERM"); done
  cli_text "$k" "${kv[@]}"; zes_enc "$RENDERED"; printf 'ZES: %s\n' "$ENC_TERM" >&2; exit 64
}
usage() {  # printf only: no cat (it can run before the second PATH sanitising)
  local k
  for k in "${CLI_HELP_LINES[@]}"; do
    if [ -n "$k" ]; then cli_text "$k"; printf '%s\n' "$RENDERED"; else printf '\n'; fi
  done
}

# Argument / environment errors (exit 64). Values are encoded for the terminal by cli_fail (no escape injection by
#   control or C1 control characters)
arg_error() { cli_fail "$@"; }  # arg_error KEY [key=value...]

set_mode() {
  if [ -n "$MODE" ] && [ "$MODE" != "$1" ]; then
    arg_error cli.arg.mode_conflict a="$MODE" b="$1"
  fi
  MODE="$1"
}

# --lang was read before parsing (so argument errors use it); a missing or invalid value is an argument error
[ "$ZES_LANG_ARG_BAD" -eq 0 ] || arg_error cli.arg.lang

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
    --lang) shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; arg_error cli.arg.unknown value="$1" ;;
  esac
done
[ -n "$MODE" ] || MODE="quick"

[ -d "$ROOT" ] || arg_error cli.arg.root_not_dir value="$ROOT"
case "$ROOT" in -*) ROOT="./$ROOT" ;; esac  # keep cd from reading "-" or "-dash" as an option / OLDPWD
ROOT="$(cd -- "$ROOT" 2>/dev/null && pwd -P)"
{ [ -n "$ROOT" ] && [ -d "$ROOT" ]; } || arg_error cli.arg.root_unresolved
# RP … the scan root for path joining (empty when it is "/", so that "$RP/x" does not become "//x")
RP="${ROOT%/}"

# PATH sanitization (stage 2): drop entries whose real path is under the scan root (not applicable with --root /, since the host itself is the target)
zes_sanitize_path "$ROOT"
hash -r
OS_NAME="$(uname -s 2>/dev/null || echo unknown)"

# The home (ZES_HOME / HOME) is normalized to its real path like ROOT (if output as a relative path, with a trailing slash or as a symlink,
# findings[].path would not be absolute / would contain "//" / would differ from the real path)
[ -n "$HOME_DIR" ] || arg_error cli.arg.home_unset
[ -d "$HOME_DIR" ] || arg_error cli.arg.home_not_dir value="$HOME_DIR"
case "$HOME_DIR" in -*) HOME_DIR="./$HOME_DIR" ;; esac
HOME_DIR="$(cd -- "$HOME_DIR" 2>/dev/null && pwd -P)"
{ [ -n "$HOME_DIR" ] && [ -d "$HOME_DIR" ]; } || arg_error cli.arg.home_unresolved
# The §49 cache is used by its real path too (find / jq / awk never see a relative "-x" or "x=y" operand)
if [ -n "$SKILLPACT_CACHE" ] && [ -d "$SKILLPACT_CACHE" ]; then
  case "$SKILLPACT_CACHE" in /*) ;; *) SKILLPACT_CACHE="./$SKILLPACT_CACHE" ;; esac
  SKILLPACT_CACHE="$(cd -- "$SKILLPACT_CACHE" 2>/dev/null && pwd -P)"
fi

if [ -n "$TARGET_URL" ]; then
  case "$TARGET_URL" in
    http://*|https://*) ;;
    *) arg_error cli.arg.url_scheme http="http://" https="https://" ;;
  esac
  case "$TARGET_URL" in
    *[[:space:]\'\"\`\$\;\|\&\<\>]*) arg_error cli.arg.url_chars ;;
  esac
fi

# Message catalog (i18n/en.json and i18n/ja.json): read once, by one awk run, into MSG_EN (findings.json: detail is
#   always English) and MSG_LANG (the terminal). No jq: a run without jq must give the same detail and id. The files are
#   flat JSON, one "key": "value" per line, with only \" and \\ escapes. Fail-closed (exit 64): each file must be complete
#   ("{" first, "}" last, a comma after every entry but the last, no duplicate key), both files must have the same key
#   set, every entry must have the same placeholders ({name}) in both files, and the cli.* / f.* / log.* keys with their
#   placeholders must be exactly the ones this script was released with (ZES_CATALOG_KEYS_SHA256: the SHA-256 of the lines
#   "key name,name..." (placeholder names sorted, deduplicated) in C-locale order of the keys; tests/run-tests.sh checks it
#   against i18n/en.json). So a catalog cannot drop or rename the {ref} of a detail, and every catalog text printed to the
#   terminal is encoded (zes_enc) like other untrusted text.
#   A file is told apart by its name (an empty file has no line 1, so counting files by FNR would be wrong)
ZES_CATALOG_KEYS_SHA256="c2d43bd0032b08715c2a787f3cfdaa17bac827ffc97b4f5ae69843ca23e3471b"
I18N_DIR="${ZES_I18N_DIR:-$SCRIPT_DIR/i18n}"
case "$I18N_DIR" in /*) ;; *) I18N_DIR="./$I18N_DIR" ;; esac  # see IOC_FILE
declare -A MSG_EN=() MSG_LANG=()
ZES_CATALOG_AWK='
  function fail() { bad = 1; exit }
  FNR == 1 { t = (FILENAME == ENVIRON["ZES_CAT_EN"]) ? "E" : (FILENAME == ENVIRON["ZES_CAT_JA"]) ? "J" : ""
             if (t == "" || (t in opened)) fail() }
  { line = $0 }
  FNR == 1 { if (line != "{") fail(); opened[t] = 1; next }
  (t in closed) { fail() }
  line == "}" { if (comma[t] || !cnt[t]) fail(); closed[t] = 1; next }
  {
    if ((t in comma) && !comma[t]) fail()
    if (substr(line, 1, 1) != "\"") fail()
    i = index(substr(line, 2), "\""); key = substr(line, 2, i - 1)
    if (key !~ /^[a-z0-9_.]+$/ || substr(line, i + 2, 3) != ": \"") fail()
    r = substr(line, i + 5); v = ""; n = length(r); done = 0
    for (k = 1; k <= n; k++) {
      c = substr(r, k, 1)
      if (c == "\\") { k++; c = substr(r, k, 1); if (c != "\"" && c != "\\") fail(); v = v c; continue }
      if (c == "\"") { done = 1; break }
      v = v c }
    rest = substr(r, k + 1)
    if (!done || (rest != "" && rest != ",")) fail()
    if ((t SUBSEP key) in seen) fail()
    seen[t, key] = 1; comma[t] = (rest == ","); cnt[t]++
    # placeholder names of the value (as zes_render reads them), sorted and deduplicated
    np = 0; x = v; delete PN
    while (match(x, /\{[a-z_]+\}/)) { nm = substr(x, RSTART + 1, RLENGTH - 2); x = substr(x, RSTART + RLENGTH)
      if (!(nm in PN)) { PN[nm] = 1; PL[++np] = nm } }
    for (a = 2; a <= np; a++) { nm = PL[a]; for (b = a - 1; b >= 1 && PL[b] > nm; b--) PL[b + 1] = PL[b]; PL[b + 1] = nm }
    ph = ""; for (a = 1; a <= np; a++) ph = ph (a > 1 ? "," : "") PL[a]
    PH[t, key] = ph
    printf "%s\037%s\037%s\n", t, key, v
    if (t == "E") printf "P\037%s %s\n", key, ph }
  END {
    if (bad || !("E" in closed) || !("J" in closed) || cnt["E"] != cnt["J"]) exit
    for (x in seen) { split(x, p, SUBSEP); if (!(((p[1] == "E" ? "J" : "E") SUBSEP p[2]) in seen)) exit
      if (PH["E", p[2]] != PH["J", p[2]]) exit }
    print "OK" }'
zes_load_catalog() {
  local en="$I18N_DIR/en.json" ja="$I18N_DIR/ja.json" f line t k ok=0 sum
  local -a phs=()
  for f in "$en" "$ja"; do { [ -f "$f" ] && [ -r "$f" ]; } || cli_fail cli.err.catalog path="$f"; done
  local -a lines=()
  mapfile -t lines < <(ZES_CAT_EN="$en" ZES_CAT_JA="$ja" awk "$ZES_CATALOG_AWK" "$en" "$ja" 2>/dev/null)
  for line in "${lines[@]}"; do
    case "$line" in
      OK) ok=1 ;;
      E"$US_CHAR"*) line="${line#E"$US_CHAR"}"; k="${line%%"$US_CHAR"*}"; t="${line#*"$US_CHAR"}"; MSG_EN["$k"]="$t"
                    [ "$ZES_LANG_RESOLVED" = ja ] || MSG_LANG["$k"]="$t" ;;
      J"$US_CHAR"*) line="${line#J"$US_CHAR"}"; k="${line%%"$US_CHAR"*}"; t="${line#*"$US_CHAR"}"
                    [ "$ZES_LANG_RESOLVED" = ja ] && MSG_LANG["$k"]="$t" ;;
      P"$US_CHAR"*) case "${line#P"$US_CHAR"}" in cli.*|f.*|log.*) phs+=("${line#P"$US_CHAR"}") ;; esac ;;
    esac
  done
  [ "$ok" -eq 1 ] || cli_fail cli.err.catalog path="$en $ja"
  sum="$(printf '%s\n' "${phs[@]}" | sort \
    | { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi; } 2>/dev/null)"
  [ "${sum%% *}" = "$ZES_CATALOG_KEYS_SHA256" ] || cli_fail cli.err.catalog path="$en $ja"
}
zes_load_catalog

# jq / git are resolved to an absolute path once with the sanitized PATH, and are always started by that absolute path afterwards
#   (the jq function calls "$JQ_BIN"; git is only the "$GIT_BIN" of safe_git)
JQ_BIN="$(command -v jq 2>/dev/null)"; case "$JQ_BIN" in /*) ;; *) JQ_BIN="" ;; esac
GIT_BIN="$(command -v git 2>/dev/null)"; case "$GIT_BIN" in /*) ;; *) GIT_BIN="" ;; esac
jq() { "$JQ_BIN" "$@"; }
HAVE_JQ=0
[ -n "$JQ_BIN" ] && HAVE_JQ=1
[ "${ZES_FORCE_NO_JQ:-0}" = "1" ] && HAVE_JQ=0

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/zes.XXXXXX")" || cli_fail cli.err.tmpdir
TMP_DIR="$(cd -- "$TMP_DIR" && pwd -P)" || exit 64
TMPDIR_REAL=""; [ -n "${TMPDIR:-}" ] && TMPDIR_REAL="$(cd -- "$TMPDIR" 2>/dev/null && pwd -P)"
trap 'rm -rf "$TMP_DIR"' EXIT
FINDINGS_FILE="$TMP_DIR/findings.ndjson"
ERRORS_FILE="$TMP_DIR/errors.ndjson"
: >"$FINDINGS_FILE"
: >"$ERRORS_FILE"
# FATAL … a fatal failure decided in the parent process (no inventory could be built / every module failed). status=error / exit code 2
FATAL=0

now_epoch() { if [ -n "${ZES_NOW:-}" ]; then echo "$ZES_NOW"; else date -u +%s; fi; }
iso_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
SCAN_STARTED_AT="$(iso_now)"

# ---------------------------------------------------------------------------
# Output (§5.1 log_section / critical / high / safe)
# ---------------------------------------------------------------------------
if [ "$JSON_OUT" -eq 1 ]; then exec 3>&2; else exec 3>&1; fi
if [ -t 3 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RED=$'\033[1;31m'; C_YEL=$'\033[1;33m'; C_MAG=$'\033[1;35m'; C_GRN=$'\033[1;32m'; C_CYN=$'\033[1;36m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
else
  C_RED=""; C_YEL=""; C_MAG=""; C_GRN=""; C_CYN=""; C_DIM=""; C_OFF=""
fi

CURRENT_MODULE=""
# msg KEY [key=value...] → RENDERED: the catalog entry in the terminal language
msg() { local k="$1"; shift; zes_render "${MSG_LANG[$k]-$k}" "$@"; }
# log_section "§N" … the title is log.section.sN
log_section() {
  CURRENT_MODULE="$1"
  msg "log.section.s${1#§}"; zes_enc "$RENDERED"
  printf '\n%s== %s %s ==%s\n' "$C_CYN" "$1" "$ENC_TERM" "$C_OFF" >&3
}
log_info() { msg "$@"; zes_enc "$RENDERED"; printf '%s  %s%s\n' "$C_DIM" "$ENC_TERM" "$C_OFF" >&3; }

sha256_str() {
  if command -v sha256sum >/dev/null 2>&1; then printf '%s' "$1" | sha256sum | awk '{print $1}'
  else printf '%s' "$1" | shasum -a 256 | awk '{print $1}'; fi
}
sha256_file() {
  # Read from stdin (when a file name contains \ or a newline, sha256sum escapes it by prefixing the line with "\")
  if command -v sha256sum >/dev/null 2>&1; then sha256sum <"$1" 2>/dev/null | awk '{print $1}'
  else shasum -a 256 <"$1" 2>/dev/null | awk '{print $1}'; fi
}


# >>> ger-tree-v1 (tests/run-tests.sh loads only this section and checks it against the test vectors)
# zes_tree_hash DIR … outputs the directory tree hash ger-tree-v1 (same definition as GER docs/design/design.md §10.8)
#   as "sha256:<hex>". Entries (including the root itself as ".") are sorted by the bytes of their relative path, ascending, and the lines
#   type \0 relpath \0 mode(4 octal digits, masked with 07777) \0 (f: size \0 sha256hex / l: value of readlink / d: empty) \n
#   are concatenated and hashed with SHA-256. mtime, ctime and uid are not included. File contents are read (only hashed, never output).
#   For trees GER refuses (over 50,000 entries, over 2 GiB in total, deeper than 256, FIFO / socket / device, another st_dev,
#   regular files with st_nlink > 1) and trees with unreadable names or names containing a newline, no hash is output and false is returned
ZES_TREE_MAX_ENTRIES=50000
ZES_TREE_MAX_BYTES=2147483648
ZES_TREE_MAX_DEPTH=256
ZES_SHA256_CMD=(sha256sum); command -v sha256sum >/dev/null 2>&1 || ZES_SHA256_CMD=(shasum -a 256)
zes_sha256_cmd() { "${ZES_SHA256_CMD[@]}"; }  # SHA-256 of stdin ("<hex>  -")
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
  # Type, mode, size, link count and device are fetched in one batch (lstat; one line per path, in input order)
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

# Helper that builds the optional fields of findings 1.1 (kind / subject / locators / related). Passed as the 6th argument of emit,
# as a fragment of comma-separated JSON members (e.g. "kind":"pkg.compromised","subject":{…}).
#   File contents are never included (locators are a JSON pointer, or only a line number and the SHA-256 of that line)
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
# x_locators ITEM_JSON... → "locators":[…] (outputs nothing when there are no items)
x_locators() { local out; out="$(x_join "$@")"; [ -n "$out" ] && printf '"locators":[%s]' "$out"; }
# json_pointer KEY... → RFC 6901 JSON pointer (~ → ~0, / → ~1)
json_pointer() { local out="" k; for k in "$@"; do k="${k//\~/~0}"; out="$out/${k//\//~1}"; done; printf '%s' "$out"; }
# text_locators FILE [grep-opts...] PATTERN … for the lines matched by grep -n -a -E (at most 64), outputs {format:text, line, line_sha256}
#   separated by commas. The line hash is the SHA-256 of the bytes without the newline, a trailing CR and a UTF-8 BOM on line 1
#   (same as remove_line in GER). Lines matching TL_EXCLUDE (ERE) are skipped (e.g. comment lines). Contents are never output
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
  done < <(zes_src "$f"; grep -n -a -E "$@" -- "$SRC" 2>/dev/null | { if [ -n "${TL_EXCLUDE:-}" ]; then grep -v -i -E -- "^[0-9]+:(${TL_EXCLUDE})"; else cat; fi; } | cut -d: -f1 | head -n "$TEXT_LOCATORS_MAX")
  printf '%s' "$out"
}
# x_text_locators FILE [grep-opts...] PATTERN → "locators":[…]
x_text_locators() { x_locators "$(text_locators "$@")"; }

# json_ptr_locators FILE JQ_PATHS [jq args...] … turns each location of JQ_PATHS (a jq expression that outputs arrays of paths with path(…))
#   into a {format: json|jsonc, pointer} locator and outputs them separated by commas (read as JSONC if it cannot be read as strict JSON).
#   Outputs nothing when jq is missing or the file cannot be read (locators are optional)
json_ptr_locators() {
  [ "$HAVE_JQ" -eq 1 ] || return 0
  local f="$1" q="$2"; shift 2
  local prog="[ $q | if length == 0 then \"\" else \"/\" + (map(tostring | gsub(\"~\"; \"~0\") | gsub(\"/\"; \"~1\")) | join(\"/\")) end | {format: \$fmt, pointer: .} | tojson ] | join(\",\")"
  jq -r --arg fmt json "$@" "$prog" "$f" 2>/dev/null || jsonc_to_json "$f" | jq -r --arg fmt jsonc "$@" "$prog" 2>/dev/null || true
}
# Agent hooks (hooks.<Event>[i] of .claude/settings.json) whose command contains $s (case-insensitive)
#   / matches $re (the unit /hooks/<Event>/<i> that claude.hook in GER removes)
HOOK_PATHS_STR='path(.hooks? | objects | .[]? | arrays | .[] | select([.. | objects | .command? | strings] | any(ascii_downcase | contains($s | ascii_downcase))))'
HOOK_PATHS_RE='path(.hooks? | objects | .[]? | arrays | .[] | select([.. | objects | .command? | strings] | any(test($re))))'
# Tasks in the VS Code tasks.json that run automatically when the folder is opened (/tasks/<i>/runOptions/runOn)
TASK_RUNON_PATHS='path(.tasks? | arrays | .[] | objects | .runOptions? | objects | .runOn? | select(. == "folderOpen"))'

# default_related MODULE PATH … related determined by module and path alone (findings 1.1)
#   §24 / §42 (manifest.json of an extension): ext_dir …/Extensions/<id> (GER quarantines per extension)
#   §49 (findings on skill.contract.json): skill_dir (the directory of the skill that has the contract)
default_related() {
  case "$1" in
    §24|§42)
      if [[ "$2" =~ ^(.*/Extensions/[^/]+)(/[^/]+)?/manifest\.json$ ]]; then x_related ext_dir "${BASH_REMATCH[1]}"; fi ;;
    §49)
      case "$2" in */skill.contract.json) x_related skill_dir "${2%/*}" ;; esac ;;
  esac
  return 0
}

# emit LEVEL CAMPAIGN PATH CODE [key=value ...] [--sp=SKILLPACT_JSON] [--x=EXTRA_JSON]
#   CODE is the message id: detail = render(i18n/en.json "f.CODE", params), always English. The terminal line uses the
#   selected language. Params are the values of the message: strings taken from the finding, which can hold text from
#   scanned files (such as a uses: reference) but never more of a file than that.
#   id v2: sha256("zes-id-v2|" module "|" campaign "|" path "|" CODE "|" canon), canon = "key=value" in C-locale key
#   order joined by U+001F, values in the zes_enc normal form (a null campaign / path is the empty string). Every
#   component and every param value is escaped first (zes_id_esc: \ → \\, | → \|, U+001F → the six characters \u001f),
#   so that a "|" or U+001F inside a path or value cannot make two findings share a preimage
#   evidence_hash is the SHA-256 of the file for a regular file, otherwise the SHA-256 of the (English) detail (same as findings 1.0; do not change)
#   evidence (findings 1.1) is typed evidence: file for a regular file (large_file over 100MB; same value as evidence_hash),
#   symlink for a symbolic link (SHA-256 of the bytes of the readlink value), tree for a directory (ger-tree-v1),
#   detail for everything else (no path, FIFO etc., a directory whose tree hash cannot be computed, the scan root / home itself)
#   EXTRA_JSON holds the kind / subject / locators / related members (built with x_*). It does not affect id or evidence_hash
#   When a path contains invalid UTF-8 bytes, path becomes the value after "\xHH" replacement, so non_utf8_path is recorded in errors[]
declare -A SEEN_IDS=()
emit() {
  local level="$1" campaign="$2" path="$3" code="$4"; shift 4
  local module="$CURRENT_MODULE" sp="" extra="" a k i j
  local -a ks=() vs=()
  for a in "$@"; do
    case "$a" in
      --sp=*) sp="${a#--sp=}" ;;
      --x=*) extra="${a#--x=}" ;;
      *) ks+=("${a%%=*}"); vs+=("${a#*=}") ;;
    esac
  done
  # params in C-locale key order (insertion sort; [[ > ]] compares bytes under LC_ALL=C)
  for ((i = 1; i < ${#ks[@]}; i++)); do
    k="${ks[i]}"; a="${vs[i]}"; j=$((i - 1))
    while [ "$j" -ge 0 ] && [[ "${ks[j]}" > "$k" ]]; do ks[j + 1]="${ks[j]}"; vs[j + 1]="${vs[j]}"; j=$((j - 1)); done
    ks[j + 1]="$k"; vs[j + 1]="$a"
  done
  local -a kv=()
  local canon="" pj=""
  for i in "${!ks[@]}"; do
    kv+=("${ks[i]}=${vs[i]}")
    zes_enc "${vs[i]}"
    [ "$i" -gt 0 ] && canon+=$'\037'
    canon+="${ks[i]}=$ENC_ID"
    pj+="${pj:+,}\"${ks[i]}\":\"$ENC_JSON\""
  done
  local id ev evk evh color np jp tp pbad nd jd td jc
  zes_render "${MSG_EN["f.$code"]-"f.$code"}" "${kv[@]}"
  zes_enc "$RENDERED"; nd="$ENC_NORM"; jd="$ENC_JSON"; td="$ENC_TERM"
  if [ "$ZES_LANG_RESOLVED" != en ]; then zes_render "${MSG_LANG["f.$code"]-"f.$code"}" "${kv[@]}"; zes_enc "$RENDERED"; td="$ENC_TERM"; fi
  local im ic ip
  zes_enc "$path"; np="$ENC_NORM"; jp="$ENC_JSON"; tp="$ENC_TERM"; pbad="$ENC_BAD"; ip="$ENC_ID"
  zes_enc "$campaign"; jc="$ENC_JSON"; ic="$ENC_ID"
  zes_id_esc "$module"; im="$ID_ESC"; zes_id_esc "$code"
  id="sha256:$(sha256_str "zes-id-v2|$im|$ic|$ip|$ID_ESC|$canon")"
  # Each id only once. The preimage is injective, so a repeated id is the same finding emitted twice; it is still recorded in
  #   errors[] every time, never dropped silently (dedup_findings does the same across subshells)
  if [ -n "${SEEN_IDS[$id]+x}" ]; then
    record_error "core" "duplicate_finding_id:$id"
    return 0
  fi
  SEEN_IDS[$id]=1
  ev=""; evk="detail"; evh=""
  if [ -n "$path" ] && [ -L "$path" ]; then
    local lt; lt="$(readlink -- "$path" 2>/dev/null; printf x)"; lt="${lt%x}"; lt="${lt%$'\n'}"
    [ -n "$lt" ] && { evk="symlink"; evh="$(sha256_str "$lt")"; }
  elif [ -f "$path" ]; then
    # Over 100MB (model weights etc.): avoid hashing the whole file; use a hash of path, size and mtime instead
    local sz; sz="$(stat_size "$path")"
    if [ "${sz:-0}" -le 104857600 ]; then ev="$(sha256_file "$path")"; evk="file"
    else ev="$(sha256_str "$np|$sz|$(stat_mtime "$path")")"; evk="large_file"; fi
    evh="$ev"
  elif [ -n "$path" ] && [ -d "$path" ] && [ "$path" != "$ROOT" ] && [ "$path" != "${HOME_DIR:-}" ] && [ "$path" != "/" ]; then
    # Findings on the scan root or home itself (such as co-location) are never remediation targets and a full hash is expensive, so keep detail
    evh="$(zes_tree_hash "$path")" && evh="${evh#sha256:}" && evk="tree" || evh=""
  fi
  [ -n "$ev" ] || ev="$(sha256_str "$nd")"
  case "$extra" in *'"related":'*) ;; *) extra="$(x_join "$extra" "$(default_related "$module" "$path")")" ;; esac
  if [ -z "$evh" ]; then evk="detail"; evh="$ev"; fi
  {
    # "id" must stay the first member (dedup_findings cuts it at a fixed offset)
    printf '{"id":"%s","level":"%s","module":"%s","campaign":%s,"path":%s,"detail":"%s","evidence_hash":"sha256:%s","code":"%s","params":{%s}' \
      "$id" "$level" "$(json_escape "$module")" "$( [ -n "$campaign" ] && printf '"%s"' "$jc" || printf null)" \
      "$( [ -n "$path" ] && printf '"%s"' "$jp" || printf null)" "$jd" "$ev" "$code" "$pj"
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
safe()     { msg "$@"; zes_enc "$RENDERED"; printf '%s[SAFE]%s %s\n' "$C_GRN" "$C_OFF" "$ENC_TERM" >&3; }

record_error() {
  local module="$1" reason="$2" jr tr
  zes_enc "$reason"; jr="$ENC_JSON"; tr="$ENC_TERM"
  printf '{"module":"%s","reason":"%s"}\n' "$(json_escape "$module")" "$jr" >>"$ERRORS_FILE"
  printf '%s[ERROR]%s %s: %s\n' "$C_YEL" "$C_OFF" "$module" "$tr" >&3
}

# ---------------------------------------------------------------------------
# Common path and version functions
# ---------------------------------------------------------------------------
# realpath equivalent (readlink -f → realpath → cd/pwd fallback)
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

# version_cmp A B → -1 / 0 / 1 (numeric segment comparison, non-numeric segments compared lexically)
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

# version_branch_vulnerable VERSION FIXED... → 0 (vulnerable) / 1 (fixed)
#   If there is a fixed version on the same branch (first 2 segments), compare with it.
#   At or above the highest fixed version is fixed. A branch mismatch below the highest means no fixed version = treated as vulnerable (fail-closed).
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

# Range expression match: "1.2.3" / "<X" / "<=X" / ">=A <=B" / ">A <B"
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

# Do not start the target binary when it is inside the scan root or in a temporary area (protection against fake binaries)
#   Probes only pass arguments that complete locally, such as printing the version (no calls that may connect to the network)
safe_probe() {
  local bin="$1"; shift
  local p rp
  p="$(command -v "$bin" 2>/dev/null)" || return 127
  rp="$(resolve_path "$p")" || return 127
  # With --root / the host itself is the target, so the under-the-scan-root condition is not used (the temporary-area condition stays)
  if [ "$ROOT" != "/" ]; then case "$rp" in "$ROOT"/*) return 126 ;; esac; fi
  # Temporary areas (on macOS /tmp → /private/tmp, $TMPDIR is /var/folders/… → /private/var/folders/…)
  case "$rp" in /tmp/*|/var/tmp/*|/dev/shm/*|/private/tmp/*|/private/var/tmp/*|/private/var/folders/*|/var/folders/*) return 126 ;; esac
  if [ -n "$TMPDIR_REAL" ] && [ "$TMPDIR_REAL" != "/" ]; then case "$rp" in "$TMPDIR_REAL"/*) return 126 ;; esac; fi
  case "$rp" in "$HOME_DIR"/*) [ "$HOST_CHECKS" = "1" ] || return 126 ;; esac
  # The environment is not inherited (env -i). To keep the settings of the inspected HOME (context in ~/.docker/config.json → ssh execution, exec
  # plugins in ~/.kube/config etc.) and DOCKER_HOST / KUBECONFIG etc. from being read, only an empty HOME and minimal variables are passed
  local ph="$TMP_DIR/probe-home"
  mkdir -p -- "$ph/.docker" 2>/dev/null || return 126
  ( cd / && env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME="$ph" DOCKER_CONFIG="$ph/.docker" XDG_CONFIG_HOME="$ph" \
      TMPDIR="$TMP_DIR" LC_ALL=C GOTOOLCHAIN=local "$rp" "$@" </dev/null 2>/dev/null )
}

# git can start commands through the settings of the inspected repository (.git/config). include.path / includeIf can also
# make it read arbitrary files (FIFOs etc.) and stall the scan indefinitely. So git never reads the inspected .git/config at all:
#   a minimal GIT_DIR is created in $TMP_DIR/git-shadow (ZES writes the config; objects / refs / packed-refs / reftable are
#   symlinks to the original repository, HEAD / shallow are copied only when regular files) and used as GIT_DIR.
#   From the original config only repositoryformatversion / extensions.objectformat / extensions.refstorage are
#   read statically without git (git_cfg_get); extensions such as partialclone are not carried over (no lazy fetches).
# In addition, settings that take a program as their value are also neutralized with -c on the command line (defense in depth), and the whole run is cut off by timeout:
#   signature verification (gpg.program / gpg.openpgp.program / gpg.x509.program / gpg.ssh.program / gpg.ssh.defaultKeyCommand),
#   ssh and proxies (core.sshCommand / core.gitProxy), editor, pager and authentication (core.editor / sequence.editor /
#   core.pager / core.askPass / credential.helper), diff (diff.external; for textconv the caller passes --no-textconv)
#   * whether a commit is signed is decided from the headers of the raw commit object, without verification (§46)
#   * if git stalls on a FIFO etc. under refs, it is cut off after ZES_GIT_TIMEOUT seconds (default 60) and git_timeout is recorded in errors[]
GIT_TIMEOUT="${ZES_GIT_TIMEOUT:-60}"
case "$GIT_TIMEOUT" in ''|*[!0-9]*) GIT_TIMEOUT=60 ;; esac

# ---------------------------------------------------------------------------
# Safe reading of paths inside the scan root
#   A path built inside the root ($ROOT/.git/config etc.) is not read when it is a symlink pointing outside the root (/proc/kmsg etc.)
#   or not a regular file (reading it may stall / would read a file outside the inspection scope)
# ---------------------------------------------------------------------------
# realpath_in_root P … if the real path of P is under the scan root (including the root itself), print the real path and return true
realpath_in_root() {
  local r; r="$(resolve_path "$1")" || return 1
  [ -n "$r" ] || return 1
  case "$r" in "$ROOT"|"$RP"/*) printf '%s' "$r"; return 0 ;; esac
  return 1
}
# in_root_regular P … true if P (after following links) is a regular file inside the scan root
in_root_regular() { [ -f "$1" ] && realpath_in_root "$1" >/dev/null; }
# read_capped FILE BYTES … reads the first BYTES bytes (with a timeout, so a blocking file does not stall)
READ_TIMEOUT=10
read_capped() { run_timeout "$READ_TIMEOUT" head -c "$2" -- "$1" 2>/dev/null; }

# git_cfg_get SECTION SUBSECTION KEY … reads a value from the Git config of the scan root (config of $ROOT/.git) without starting git
#   (the last value; include is not followed). Does not read when it points outside the root or is not a regular file (FIFO, device).
#   Supports both [sec "sub"] and the old form [sec.sub]
git_cfg_get() {
  local cfg="${ROOT_GITCOMMON:-$RP/.git}/config"
  in_root_regular "$cfg" || return 1
  read_capped "$cfg" 1048576 | ZES_S="$1" ZES_SS="$2" ZES_K="$3" awk '
    BEGIN { ws = tolower(ENVIRON["ZES_S"]); wss = ENVIRON["ZES_SS"]; wk = tolower(ENVIRON["ZES_K"]); found = 0 }
    { line = $0; sub(/\r$/, "", line); if (NR == 1) sub(/^\357\273\277/, "", line) }
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

# git_cfg_includes CONFIG … the values of include.path / includeIf "<condition>".path, one per line (conditions are not evaluated; all of them). Does not start git
git_cfg_includes() {
  read_capped "$1" 1048576 | awk '
    { line = $0; sub(/\r$/, "", line); if (NR == 1) sub(/^\357\273\277/, "", line) }
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
# Git directory discovery (the .git directly under the scan root and nested .git [submodules, bundled repositories])
#   Resolves .git files ("gitdir: <path>") and commondir (git worktree) without git, and
#   lists the configs (config / config.worktree), the targets of include.path / includeIf and the hook locations (checked statically by §7 / §26 / §41).
#   When something cannot be resolved or points outside the scan root, it is recorded in errors[] (unreadable configs are not treated as 0 hits)
#   GIT_DIRS_FILE: .git path US gitdir US commondir / GIT_CFG_LIST: Git configs checked statically / GIT_HOOKS_LIST: hook locations
# ---------------------------------------------------------------------------
GIT_DIRS_FILE=""; GIT_CFG_LIST=""; GIT_HOOKS_LIST=""
ROOT_GITDIR=""; ROOT_GITCOMMON=""
git_read_pointer() {  # git_read_pointer FILE PREFIX … the <path> of "PREFIX<path>" (if PREFIX is empty, line 1 itself)
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
      continue  # FIFOs etc. are already recorded as special_file by build_inventory
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
# git_cfg_collect CONFIG DEPTH … adds CONFIG to the list and follows the targets of include.path / includeIf (up to depth 10, the same limit as git)
git_cfg_collect() {
  local cfg="$1" depth="$2" inc t r
  grep -q -x -F -- "$cfg" "$GIT_CFG_LIST" 2>/dev/null && return 0
  printf '%s\n' "$cfg" >>"$GIT_CFG_LIST"
  [ "$depth" -lt 10 ] || { record_error "core" "git_include_too_deep:$cfg"; return 0; }
  while IFS= read -r inc; do
    case "$inc" in "~/"*) t="$HOME_DIR/${inc#\~/}" ;; /*) t="$inc" ;; *) t="${cfg%/*}/$inc" ;; esac
    # Targets are read only when they are regular files inside the scan root (or the inspected HOME). git never reads them
    r="$(resolve_path "$t")"
    if [ -n "$r" ] && [ -f "$r" ] && { realpath_in_root "$r" >/dev/null || case "$r" in "$HOME_DIR"/*) true ;; *) false ;; esac; }; then
      git_cfg_collect "$r" $((depth + 1))
    else
      record_error "core" "git_include_unresolved:$cfg"
    fi
  done < <(git_cfg_includes "$cfg")
}

# Build a ZES-managed minimal GIT_DIR from the inspected .git (does nothing if already built)
#   HEAD is taken from gitdir; objects / refs / packed-refs / reftable / shallow from commondir (the shared side for a worktree).
#   All are limited to real files inside the scan root (links pointing outside the root are not used), and reads have a timeout
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

# run_timeout SECONDS CMD... … uses coreutils timeout if available, otherwise cuts off with a bash watchdog (returns 124)
#   The watchdog waits on sleep as a child process and stops the sleep when the watchdog is stopped (no orphaned sleep is left)
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
# IoC reading (read_ioc: jq preferred, grep fallback)
#   Without jq, extracts the string array of the first key with that name inside the top-level section.
#   rules/ioc.json must keep its one-entry-per-line formatting for the grep fallback.
# ---------------------------------------------------------------------------
[ -r "$IOC_FILE" ] || cli_fail cli.err.ioc_unreadable path="$IOC_FILE"
if [ "$HAVE_JQ" -eq 1 ] && ! jq -e . "$IOC_FILE" >/dev/null 2>&1; then
  cli_fail cli.err.ioc_invalid path="$IOC_FILE"
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
  # String arrays are extracted as a sequence of '"…"' (so they are not cut at the ']' of the defanged notation [.])
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

# Output packages[] as TSV (campaign eco name match bad_versions(;-separated) safe_version)
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
# Inventory of inspection targets
#   ZES itself (rules/tests/docs etc.) contains IoC strings, so it is excluded when ROOT is outside ZES
# ---------------------------------------------------------------------------
FILES_LIST="$TMP_DIR/files.lst"
LINKS_LIST="$TMP_DIR/links.lst"
DIRS_LIST="$TMP_DIR/dirs.lst"
# LINKED_FILES_LIST … symlinks added to FILES_LIST under the link name (whose target is a regular file inside the scan root)
LINKED_FILES_LIST="$TMP_DIR/linked-files.lst"
# Pseudo file systems that may stall when read and are not inspection targets (including a bind-mounted /proc/kmsg etc.)
PSEUDO_FSTYPES="proc sysfs devtmpfs devpts devfs debugfs tracefs securityfs cgroup cgroup2 pstore bpf configfs fusectl mqueue hugetlbfs binfmt_misc efivarfs selinuxfs rpc_pipefs nsfs autofs"
# Config file names recorded in errors[] when the link target is outside the scan root (no escaping the scan through a link)
# GER quarantine stores (directories with the marker .ger-quarantine-store) are not walked. Their contents are the quarantined malicious files
#   themselves, so walking them would bring the same findings back on the rescan after remediation. So that placing a marker alone cannot evade the scan,
#   only stores that meet the conditions of a store created by GER (marker is a regular file, directory owned by the running user, no group / other permissions)
#   are skipped, and quarantine_store_skipped is left in errors[]. Markers that do not meet the conditions are ignored and the directory is walked,
#   recording quarantine_marker_untrusted in errors[] (status is partial)
QSTORE_MARKER=".ger-quarantine-store"
QSTORES=()
qstore_trusted() {
  local d="$1" m
  [ -f "$d/$QSTORE_MARKER" ] && [ ! -L "$d/$QSTORE_MARKER" ] && [ -d "$d" ] && [ ! -L "$d" ] && [ -O "$d" ] || return 1
  m="$(stat_perm "$d")"
  [[ "$m" =~ ^[0-7]+$ ]] && [ $(( 8#$m & 077 )) -eq 0 ]
}
# qstore_note DIR … evaluates a directory that has the marker and adds it to QSTORES (recorded in errors[])
qstore_note() {
  local d="$1" q
  for q in "${QSTORES[@]}"; do [ "$q" = "$d" ] && return 0; done
  if qstore_trusted "$d"; then QSTORES+=("$d"); record_error "core" "quarantine_store_skipped:$d"
  else record_error "core" "quarantine_marker_untrusted:$d"; fi
}
# in_qstore PATH … true if PATH is an (already evaluated) quarantine store itself or inside one
in_qstore() {
  local q
  for q in "${QSTORES[@]}"; do case "$1" in "$q"|"$q"/*) return 0 ;; esac; done
  return 1
}
# qstore_filter … removes paths inside quarantine stores from the paths on stdin (one per line; results of a find outside the scan root).
#   Evaluates a marker if one exists in a parent directory of the path (does not look above the find start point: start point $1)
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
  # Only VCS metadata directly under the scan root ($ROOT/.git etc.) is excluded. Files inside nested .git / .hg / .svn
  # are walked too (code cannot be hidden in a directory with that name). $ROOT/.git is checked statically by git_discover
  local -a prune=( -path "$RP/.git" -prune -o -path "$RP/.hg" -prune -o -path "$RP/.svn" -prune -o -path "$TMP_DIR" -prune )
  case "$SCRIPT_DIR/" in
    "$RP"/*) if [ "$SCRIPT_DIR" != "$ROOT" ] || [ -f "$RP/zes-scan.sh" ]; then prune+=( -o -path "$SCRIPT_DIR" -prune ); fi ;;
  esac
  # Pseudo file systems are recorded in errors[] without being opened (when find supports -fstype)
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
  # Remove GER quarantine stores (directories with .ger-quarantine-store) (from the results of a single find walk)
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
      # If the link target is a regular file inside the scan root, also scan it under the link name (.mcp.json → cfg/servers.json etc.)
      if r="$(realpath_in_root "$p")" && [ -f "$r" ]; then
        printf '%s\n' "$p" >>"$FILES_LIST"; printf '%s\n' "$p" >>"$LINKED_FILES_LIST"
      elif printf '%s\n' "$p" | grep_q -E -- "$SENSITIVE_LINK_RE"; then
        record_error "core" "symlink_leaves_root:$p"
      fi
    elif [ -f "$p" ]; then
      printf '%s\n' "$p" >>"$FILES_LIST"
      [ -r "$p" ] || record_error "core" "unreadable:$p"
      # Archives whose contents are not extracted are recorded in errors[] as archive_not_inspected (status unchanged: README, Limitations)
      case "$p" in *.whl|*.tgz|*.tar.gz|*.zip|*.jar|*.war|*.pyz|*.egg|*.gem|*.crate|*.nupkg|*.vsix|*.crx|*.xpi) record_error "core" "archive_not_inspected:$p" ;; esac
    elif [ -d "$p" ]; then
      printf '%s\n' "$p" >>"$DIRS_LIST"
    else
      # FIFOs, sockets and devices are not opened (reading may stall). The fact that they were not inspected is left in errors[] (fail-closed)
      record_error "core" "special_file:$p"
    fi
  done <"$TMP_DIR/all.z"
  # Directories find could not read (no permission etc.) are recorded in errors[] (never silently treated as 0 hits)
  local line q
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    q="$(printf '%s' "$line" | sed -n -E -e "s/^find: '(.*)': [^:]*\$/\\1/p" -e t -e "s/^find: (.*): [^:]*\$/\\1/p")"
    if [ -n "$q" ]; then record_error "core" "unreadable:$q"; else record_error "core" "inventory_error:$(printf '%s' "$line" | cut -c1-200)"; fi
  done <"$TMP_DIR/find.err"
  if [ "$rc" -ne 0 ]; then
    [ -s "$TMP_DIR/find.err" ] || record_error "core" "inventory_incomplete:find_exit_$rc"
    # If the scan root itself cannot be read (not a single entry can be listed), it is fatal (status=error)
    [ "$n" -eq 0 ] && { FATAL=1; record_error "core" "inventory_failed"; }
  fi
  sort -o "$FILES_LIST" "$FILES_LIST"; sort -o "$LINKS_LIST" "$LINKS_LIST"; sort -o "$DIRS_LIST" "$DIRS_LIST"; sort -o "$LINKED_FILES_LIST" "$LINKED_FILES_LIST"
}

# files_named REGEX  … files whose base name matches the ERE
files_named() { ZES_RE="$1" awk '{n=$0; sub(/.*\//,"",n); if (n ~ ENVIRON["ZES_RE"]) print}' "$FILES_LIST"; }
# files_path REGEX   … files whose full path matches the ERE
files_path() { grep -E -- "$1" "$FILES_LIST" 2>/dev/null || true; }
# zes_rel PATH → REL: the path relative to the scan root (or to the home for home files) with a leading "/". Directory
#   skips (node_modules, .git, site-packages …) test REL, as the browser tests the path inside the dropped folder: a scan
#   root that is itself under node_modules/ is not skipped as a whole
zes_rel() {
  case "$1" in
    "$RP"/*) REL="/${1#"$RP"/}" ;;
    "$HOME_DIR"/*) REL="/${1#"$HOME_DIR"/}" ;;
    *) REL="$1" ;;
  esac
}
# files_rel REGEX … files whose REL (see zes_rel) matches the ERE (full paths are printed)
files_rel() { ZES_RE="$1" ZES_RP="$RP" awk 'BEGIN { rp = ENVIRON["ZES_RP"] "/" } { r = (index($0, rp) == 1) ? substr($0, length(rp)) : $0; if (r ~ ENVIRON["ZES_RE"]) print }' "$FILES_LIST"; }

# A leading UTF-8 BOM is not part of the text, on both sides: the browser reads files with TextDecoder (which drops one
#   BOM), and the CLI reads a copy without it for every text check. bom_prepare (after build_inventory) copies each scanned
#   file that starts with EF BB BF, minus those 3 bytes, to $TMP_DIR/bom/<n>; BOM_SRC maps the path to the copy. zes_src F
#   sets SRC to the path to read (the copy or F itself); fgrep_q, grep_q, grep_l and text_locators use it. Evidence hashes
#   and the reported path stay those of the original file
declare -A BOM_SRC=()
BOM_MAP=""
bom_prepare() {
  local f k=0
  mkdir -p "$TMP_DIR/bom" || return 0
  BOM_MAP="$TMP_DIR/bom/map"; : >"$BOM_MAP"
  while IFS= read -r f; do
    [ -n "$f" ] && [ "$f" != /dev/null ] && [ -f "$f" ] || continue
    [ "$(head -c 3 -- "$f" 2>/dev/null | od -An -tx1 | tr -d ' \n')" = "efbbbf" ] || continue
    k=$((k + 1))
    tail -c +4 -- "$f" >"$TMP_DIR/bom/$k" 2>/dev/null || continue
    BOM_SRC["$f"]="$TMP_DIR/bom/$k"
    printf '%s\t%s\n' "$TMP_DIR/bom/$k" "$f" >>"$BOM_MAP"
  done < <(tr '\n' '\0' <"$FILES_LIST" | xargs -0 grep -l -a -E "^$(printf '\357\273\277')" -- /dev/null 2>/dev/null)
  return 0
}
zes_src() { SRC="$1"; if [ "${#BOM_SRC[@]}" -gt 0 ] && [ -n "${BOM_SRC[$1]+x}" ]; then SRC="${BOM_SRC[$1]}"; fi; }
# bom_split < list … the NUL-separated list for xargs, with BOM files replaced by their copies; bom_unmap maps copies back
bom_split() {
  if [ "${#BOM_SRC[@]}" -eq 0 ]; then tr '\n' '\0'; return; fi
  local f
  while IFS= read -r f; do zes_src "$f"; printf '%s\0' "$SRC"; done
}
bom_unmap() {
  if [ "${#BOM_SRC[@]}" -eq 0 ]; then cat; return; fi
  awk -F'\t' 'NR == FNR { m[$1] = $2; next } { print (($0 in m) ? m[$0] : $0) }' "$BOM_MAP" -
}
# grep_l PATTERN [grep-opts...] < filelist … returns only the paths of files whose contents match (contents are never output)
#   A file that starts with a UTF-8 BOM is read without it (BOM_SRC, as the browser's TextDecoder does)
grep_l() {
  local pat="$1"; shift
  bom_split | xargs -0 grep -l -a -E "$@" -e "$pat" -- /dev/null 2>/dev/null | bom_unmap || true
}
grep_lF() {
  local pat="$1"; shift
  bom_split | xargs -0 grep -l -a -F "$@" -e "$pat" -- /dev/null 2>/dev/null | bom_unmap || true
}
# Existence check on a single file
fgrep_q() {
  local n=$#
  if [ "$n" -gt 0 ] && [ "${#BOM_SRC[@]}" -gt 0 ] && [ -n "${BOM_SRC[${!n}]+x}" ]; then set -- "${@:1:n-1}" "${BOM_SRC[${!n}]}"; fi
  grep -q -a -E "$@" 2>/dev/null
}
# Existence check at the end of a pipe (cmd | grep_q [grep-opts...] PATTERN). Returns the same truth value as grep -q, but reads the input to the end.
#   grep -q exits on the first match, so if it exits before the upstream (printf, grep, xargs etc.) has finished writing, the upstream fails with
#   SIGPIPE, and under set -o pipefail the result becomes false although it matched (a false positive with !). A race that only occurs under heavy load,
#   it made detail (e.g. the list of dangerous permissions in §24) and id change between runs. Do not use grep -q in pipes
grep_q() {
  local n=$#
  if [ "$n" -gt 0 ] && [ "${#BOM_SRC[@]}" -gt 0 ] && [ -n "${BOM_SRC[${!n}]+x}" ]; then set -- "${@:1:n-1}" "${BOM_SRC[${!n}]}"; fi
  n="$(grep -c "$@" 2>/dev/null)"; [ "${n:-0}" -gt 0 ] 2>/dev/null
}
# Conversion for reading TSV while keeping empty fields. IFS=$'\t' treats tab as whitespace and collapses consecutive tabs into one separator
# (empty fields shift the following columns), so tabs are replaced by US (0x1f), which is not whitespace, and read with IFS="$US"
US=$'\037'
tsv_us() { tr '\t' '\037'; }

# ---------------------------------------------------------------------------
# Dependency inventory (input of check_lockfile_versions)
#   DEPS_TSV: eco<TAB>name<TAB>version<TAB>source_path
# ---------------------------------------------------------------------------
DEPS_TSV="$TMP_DIR/deps.tsv"
DEPS_BUILT=0
norm_pypi() { printf '%s' "$1" | tr 'A-Z_.' 'a-z--' | tr -s '-'; }
# Normalization before passing to line-based parsers: strip a trailing CR (CRLF) and a leading UTF-8 BOM (prevents detection evasion)
text_lines() { awk '{ sub(/\r$/, "") } NR == 1 { sub(/^\357\273\277/, "") } { print }' "$1" 2>/dev/null; }
# Top-level "version" of package.json (without jq). Counts the depth of braces outside strings and only looks at keys at depth 1
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
# Read Name<TAB>Version from the leading headers of PKG-INFO / METADATA (RFC 822 format)
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
  # npm: yarn.lock (v1 / Berry)
  #   Aliases ("kv@npm:keyv@6.0.0") are matched by the real package name (keyv), not the alias.
  #   If the Berry resolution: "keyv@npm:6.0.0" exists, it takes precedence (output together at the end of the block)
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    text_lines "$f" | ZES_V_SRC="$f" awk 'BEGIN { src = ENVIRON["ZES_V_SRC"] } 
      function pname(spec,   at, t, n0) {   # "name@range" → name (if range is npm:<target>, the name of target)
        gsub(/"/, "", spec)
        at = (spec ~ /^@/) ? index(substr(spec, 2), "@") + 1 : index(spec, "@")
        if (at <= 1) return spec
        t = substr(spec, at + 1)
        n0 = substr(spec, 1, at - 1)
        if (t !~ /^npm:/) return n0
        t = substr(t, 5)
        if (t ~ /^[0-9^~<>=*]/ || t == "") return n0              # "keyv@npm:^6.0.0" (the usual Berry notation)
        at = (t ~ /^@/) ? index(substr(t, 2), "@") + 1 : index(t, "@")
        return (at > 1) ? substr(t, 1, at - 1) : t }               # "kv@npm:keyv@6.0.0" / "kv@npm:keyv"
      function flush() { if (n != "" && v != "") print "npm\t" (rn != "" ? rn : n) "\t" v "\t" src; n = ""; v = ""; rn = "" }
      /^[^ #].*:$/ { flush(); h=$0; sub(/:$/,"",h); split(h,parts,/, */); n = pname(parts[1]); next }
      /^  version:? / { v=$0; sub(/^  version:? +/,"",v); gsub(/"/,"",v); next }
      /^  resolution:? / { r=$0; sub(/^  resolution:? +/,"",r); gsub(/"/,"",r); if (index(r, "@npm:") > 1) rn = substr(r, 1, index(r, "@npm:") - 1); next }
      END { flush() }' >>"$DEPS_TSV"
  done < <(files_named '^yarn\.lock$')
  # npm: pnpm-lock.yaml
  #   v6+: "/name@1.2.3:" / "name@1.2.3(peer@x):", v5: "/name/1.2.3:" / "/@scope/name/1.2.3:" / "/name/1.2.3_peer@x:"
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
  # npm: node_modules/<pkg>/package.json (the version actually installed)
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    local n v
    zes_rel "$f"; n="$(printf '%s' "$REL" | sed -E 's#.*/node_modules/((@[^/]+/)?[^/]+)/package\.json$#\1#')"
    # Only the top-level .version (handles minified JSON and nested "version")
    if [ "$HAVE_JQ" -eq 1 ]; then
      v="$(jq -r 'if type == "object" and (.version | type) == "string" then .version else "" end' "$f" 2>/dev/null)" \
        || { record_error "§15" "lockfile_parse_failed:$f"; v=""; }
    else
      v="$(json_top_version "$f")"
    fi
    v="$(printf '%s' "$v" | tr -d '\t\r\n')"
    printf 'npm\t%s\t%s\t%s\n' "$n" "$v" "$f" >>"$DEPS_TSV"
  done < <(files_rel '/node_modules/(@[^/]+/)?[^/]+/package\.json$')
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
  # pypi: *.dist-info / *.egg-info in site-packages (what is actually installed)
  #   Name / Version are taken from the METADATA / PKG-INFO headers (since there are name-1.0-py3.11.egg-info and
  #   name.egg-info without a version, the directory name is only a fallback when there is no header)
  #   egg-info may also be a single file (same format as PKG-INFO)
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
    # With a platform suffix (nokogiri (1.16.0-x86_64-linux)), only the version part is compared
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
  # npm: bun.lock (JSONC. "packages": { "<name>": ["<real name>@<version>", …] }. npm aliases are matched by the real name)
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
  # npm: deno.lock (v3: packages.npm, v4 and later: npm. Keys are "<name>@<version>"; from "_" on is the peer suffix)
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
  # bun.lockb (binary format) is not parsed (the fact that it was not matched is left in errors[])
  while IFS= read -r f; do [ -n "$f" ] && record_error "§15" "lockfile_unparsed:$f"; done < <(files_named '^bun\.lockb$')
  sort -u -o "$DEPS_TSV" "$DEPS_TSV"
}

# pkg_kind SOURCE … kind of a compromised-package finding. What is actually installed (node_modules/<name>/package.json,
#   *.dist-info, *.egg-info) is pkg.compromised; lockfiles and dependency declarations are pkg.lockfile_compromised
pkg_kind() {
  zes_rel "$1"
  case "$REL" in
    */node_modules/*/package.json|*.dist-info|*.egg-info) printf 'pkg.compromised' ;;
    *) printf 'pkg.lockfile_compromised' ;;
  esac
}
# pkg_related ECO NAME SOURCE … if something is installed next to an npm lockfile (the same 5 kinds as npm_installed in ZET / GER),
#   related npm_installed (symlinks [pnpm etc.] are not included because GER cannot quarantine them)
pkg_related() {
  [ "$1" = "npm" ] || return 0
  case "${3##*/}" in package-lock.json|npm-shrinkwrap.json|yarn.lock|pnpm-lock.yaml|bun.lock) ;; *) return 0 ;; esac
  case "$2" in ""|.*|*/*/*|*..*) return 0 ;; */*) [[ "$2" == @* ]] || return 0 ;; esac
  local t="${3%/*}/node_modules/$2"
  [ -d "$t" ] && [ ! -L "$t" ] && x_related npm_installed "$t"
  return 0
}

# check_lockfile_versions (campaign-aware): matches packages[] against DEPS_TSV
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
      # findings 1.1: kind / subject. For a lockfile (npm) finding, what is installed next to it,
      #   <dir>/node_modules/<name> (a directory that is not a symlink), goes into related npm_installed
      local x kind
      if [ "$match" = "vulnerable_versions" ]; then
        x="$(x_subject "$eco" "$dname" "$dver" "$safev" "$safev")"; kind="pkg.vulnerable"
      else
        x="$(x_subject "$eco" "$dname" "$dver" "$safev")"
        kind="$(pkg_kind "$dsrc")"
      fi
      x="$(x_join "$(x_kind "$kind")" "$x" "$(pkg_related "$eco" "$dname" "$dsrc")")"
      if [ "$hit" -eq 1 ] && [ "$match" = "vulnerable_versions" ]; then
        if [ -n "$safev" ]; then high "$camp" "$dsrc" s15.pkg_vulnerable_fixed ecosystem="$eco" fixed_version="$safev" package="$dname" version="${dver:-?}" --x="$x"
        else high "$camp" "$dsrc" s15.pkg_vulnerable ecosystem="$eco" package="$dname" version="${dver:-?}" --x="$x"; fi
      elif [ "$hit" -eq 1 ]; then
        if [ -n "$safev" ]; then critical "$camp" "$dsrc" s15.pkg_compromised_safe ecosystem="$eco" package="$dname" safe_version="$safev" version="${dver:-?}" --x="$x"
        else critical "$camp" "$dsrc" s15.pkg_compromised ecosystem="$eco" package="$dname" version="${dver:-?}" --x="$x"; fi
      elif [ "$match" = "unknown_versions" ]; then
        medium "$camp" "$dsrc" s15.pkg_reported package="$dname" version="${dver:-?}" --x="$x"
      fi
    done < <(tsv_us <"$DEPS_TSV")
  done < <(tsv_us <"$TMP_DIR/packages.tsv")
}

# detect_service_version IMAGE_PATTERN … extracts the version from image tags in compose/k8s/Dockerfile
#   output: version<TAB>path
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

# infra_fixed INFRA_ID CVE_ID … the fixed versions of infrastructures[], one per line
infra_fixed() {
  if [ "$HAVE_JQ" -eq 1 ]; then
    jq -r --arg i "$1" --arg c "$2" '.infrastructures[] | select(.id==$i) | .cves[] | select(.id==$c) | (.fixed // [])[]' "$IOC_FILE"
  else
    grep -o "\"$2\".*" "$IOC_FILE" | head -n1 | grep -o '"fixed": *\[[^]]*\]' | grep -o '"[0-9][^"]*"' | tr -d '"'
  fi
}

# =============================================================================
# Collected threat intelligence (the intel section of rules/ioc.json)
#   Each function is called from the corresponding §. Adding data alone extends what is detected.
#   intel requires jq (if missing, it is recorded in errors[] and not treated as 0 hits)
# =============================================================================
# When jq fails (filter compile error, invalid data), it is recorded in errors[] (not treated as 0 hits / fail-closed)
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

# Malicious file names and SHA-256 (§15)
intel_files() {
  intel_ready || return 0
  local camp sev name f h
  # Hashes are matched against all files regardless of name (this also tells them apart from legitimate files with the same name)
  intel_jq '.intel.files[]? | .campaign as $c | (.severity // "CRITICAL") as $s | (.sha256 // [])[] | [$c, $s, .] | @tsv' >"$TMP_DIR/intel_sha.tsv"
  if [ -s "$TMP_DIR/intel_sha.tsv" ] && ! command -v sha256sum >/dev/null 2>&1; then
    record_error "$CURRENT_MODULE" "sha256sum_unavailable"
  elif [ -s "$TMP_DIR/intel_sha.tsv" ]; then
    cut -f3 "$TMP_DIR/intel_sha.tsv" | sort -u >"$TMP_DIR/intel_sha.lst"
    # Passed to sha256sum in one batch, keeping only lines that match a known hash (file contents are never output)
    #   Uses -z (NUL-separated, no escaping of file names), because the path changes when sha256sum escapes a \ / newline / CR
    #   in the name. A sha256sum without -z support (busybox etc.) computes each file from stdin one at a time
    if printf '' | sha256sum -z >/dev/null 2>&1; then
      tr '\n' '\0' <"$FILES_LIST" | xargs -0 sha256sum -z -- 2>/dev/null | tr '\0' '\n'
    else
      while IFS= read -r f; do printf '%s  %s\n' "$(sha256_file "$f")" "$f"; done <"$FILES_LIST"
    fi | awk 'NR==FNR {want[$1]=1; next}
          ($1 in want) { h=$1; sub(/^[0-9a-f]+ [ *]/,""); print h "\t" $0 }' "$TMP_DIR/intel_sha.lst" - \
      | while IFS=$'\t' read -r h f; do
          IFS=$'\t' read -r camp sev _ < <(grep -F -- "$h" "$TMP_DIR/intel_sha.tsv" | head -n1)
          critical "$camp" "$f" intel.file_sha256
        done
  fi
  while IFS=$'\t' read -r camp sev name; do
    [ -n "$name" ] || continue
    while IFS= read -r f; do [ -n "$f" ] && lvl_emit "$sev" "$camp" "$f" intel.file_name name="$name"; done \
      < <(files_named "^$(printf '%s' "$name" | sed 's/[.[\*^$+?(){}|]/\\&/g')\$")
  done < <(intel_jq '.intel.files[]? | .campaign as $c | (.name_severity // "HIGH") as $s | (.names // [])[] | [$c, $s, .] | @tsv')
}

# Network IoCs (merged into network_iocs in §18)
intel_network_iocs() {
  [ "$HAVE_JQ" -eq 1 ] || return 0
  intel_jq '.intel.network[]? | .campaign as $c | ((.domains // []) + (.ips // []) + (.urls // []) + (.contracts // []))[] | [$c, .] | @tsv' \
    | while IFS=$'\t' read -r c i; do [ -n "$i" ] && printf '%s\t%s\t%s\n' "$(refang "$i")" "$c" "malicious"; done
  intel_jq '.intel.network[]? | .campaign as $c | (.legit_infra // [])[] | [$c, .] | @tsv' \
    | while IFS=$'\t' read -r c i; do [ -n "$i" ] && printf '%s\t%s\t%s\n' "$(refang "$i")" "$c" "legit"; done
  return 0
}

# Compromised GitHub Actions (§22)
intel_actions() {
  intel_ready || return 0
  local camp act sev bad safe f line ref
  while IFS="$US" read -r camp act sev bad safe; do
    [ -n "$act" ] || continue
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      workflow_text "$f" | grep -i -E -o "uses:[[:space:]]*[\"']?$(printf '%s' "$act" | sed 's/[.[\*^$+?(){}|]/\\&/g')@[^\"'[:space:]#,}]+" 2>/dev/null | sed -E 's/.*@//' | sort -u | while IFS= read -r ref; do
        if printf '%s\n' "$bad" | tr ',' '\n' | grep_q -x -F -- "$ref"; then
          critical "$camp" "$f" intel.action_compromised action="$act" ref="$ref"
        elif [ -n "$safe" ] && ! printf '%s\n' "$safe" | tr ',' '\n' | grep_q -x -F -- "$ref" && ! [[ "$ref" =~ ^[0-9a-f]{40}$ ]]; then
          lvl_emit "$sev" "$camp" "$f" intel.action_unsafe_tag action="$act" ref="$ref" safe="$safe"
        fi
      done
    done < <(workflow_files; files_path '/action\.ya?ml$')
  done < <(intel_jq '.intel.actions[]? | [.campaign, .action, (.severity // "HIGH"), ((.bad_refs // []) | join(",")), ((.safe_refs // []) | join(","))] | @tsv' | tsv_us)
}

# Malicious strings in workflows and scripts (§38)
intel_workflow_strings() {
  intel_ready || return 0
  local camp sev str f
  while IFS=$'\t' read -r camp sev str; do
    [ -n "$str" ] || continue
    files_path '(/\.github/workflows/[^/]+\.ya?ml|\.gitlab-ci\.ya?ml|/\.circleci/config\.ya?ml|/Jenkinsfile|/action\.ya?ml)$' | grep_lF "$str" | while IFS= read -r f; do
      [ -n "$f" ] && lvl_emit "$sev" "$camp" "$f" intel.ci_pattern campaign="$camp"
    done
  done < <(intel_jq '.intel.workflow_strings[]? | .campaign as $c | (.severity // "HIGH") as $s | (.strings // [])[] | [$c, $s, .] | @tsv')
}

# Malicious or compromised extensions (§42): Chrome/Edge is Extensions/<id>/<ver>, VS Code/Open VSX is extensions/<publisher.name>-<ver>
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
          if [ "$hit" -eq 1 ]; then
            if [ -n "$ver" ]; then lvl_emit "$sev" "$camp" "$d" intel.browser_ext_version id="$id" version="$ver"
            else lvl_emit "$sev" "$camp" "$d" intel.browser_ext id="$id"; fi
          fi
        done < <({ extension_manifests | sed -E 's#/manifest\.json$##'; files_path "/Extensions/${id}/" | sed -E "s#(/Extensions/${id})/.*#\1#"; } | grep -E "/Extensions/${id}(/[^/]+)?$" | sort -u)
        ;;
      vscode|openvsx|cursor|windsurf)
        while IFS= read -r d; do
          [ -n "$d" ] && [ -d "$d" ] || continue
          ver="${d##*/${id}-}"; ver="${ver%%-*}"
          hit=1
          if [ -n "$bads" ]; then hit=0; local b; for b in ${bads//,/ }; do version_matches_spec "$ver" "$b" && hit=1; done; fi
          [ "$hit" -eq 1 ] && lvl_emit "$sev" "$camp" "$d" intel.ide_ext id="$id" version="$ver"
        done < <(for d in "$HOME_DIR"/.vscode/extensions/"$id"-[0-9]* "$HOME_DIR"/.vscode-server/extensions/"$id"-[0-9]* "$HOME_DIR"/.cursor/extensions/"$id"-[0-9]* "$HOME_DIR"/.windsurf/extensions/"$id"-[0-9]*; do printf '%s\n' "$d"; done
                 files_path "/extensions/${id}-[0-9][^/]*/package\.json$" | sed -E 's#/package\.json$##')
        ;;
    esac
  done < <(intel_jq '.intel.extensions[]? | .campaign as $c | .eco as $e | (.severity // "HIGH") as $s | ((.bad_versions // []) | join(",")) as $b | (.ids // [])[] | [$c, $e, $s, ., $b] | @tsv')
}

# Host IoCs: paths, file names, LaunchAgent Labels, systemd units (§30/§31), process names (§1)
intel_host_files() {
  intel_ready || return 0
  local camp sev kind val e f
  while IFS=$'\t' read -r camp sev kind val; do
    [ -n "$val" ] || continue
    case "$kind" in
      path)
        # Match against a different place per kind of path (matching same-named suffixes inside the scan root uniformly would cause false positives)
        #   ~/… / $HOME/…   … only real paths under the inspected HOME (ZES_HOME)
        #   /… / $TMPDIR/…  … only real paths on the host (not checked with ZES_HOST_CHECKS=0)
        #   anything else (relative paths such as site-packages/cook.pth) … suffix match inside the scan root
        e=""
        case "$val" in
          "~/"*|'$HOME/'*) e="$(expand_home "$val")" ;;
          '$TMPDIR/'*) host_enabled && e="${TMPDIR:-/tmp}/${val#\$TMPDIR/}" ;;
          /*) host_enabled && e="$val" ;;
          *)
            while IFS= read -r f; do [ -n "$f" ] && lvl_emit "$sev" "$camp" "$f" intel.host_path_in_root; done < <(files_path "/$(printf '%s' "$val" | sed 's/[.[\*^$+?(){}|]/\\&/g')\$")
            ;;
        esac
        if [ -n "$e" ]; then
          # Do not split paths containing spaces (Application Support etc.); expand glob characters only
          local IFS=$'\n'
          for f in $e; do [ -e "$f" ] || [ -L "$f" ] && lvl_emit "$sev" "$camp" "$f" intel.host_path; done
          unset IFS
        fi
        ;;
      file_name)
        while IFS= read -r f; do [ -n "$f" ] && lvl_emit "$sev" "$camp" "$f" intel.host_file_name name="$val"; done < <(files_named "^$(printf '%s' "$val" | sed 's/[.[\*^$+?(){}|]/\\&/g')\$")
        ;;
      launch_label)
        while IFS= read -r f; do
          [ -n "$f" ] && plist_label "$f" && [ "$PLIST_LABEL" = "$val" ] && critical "$camp" "$f" intel.launchd label="$val"
        done < <(files_path '/LaunchAgents/[^/]+\.plist$|/LaunchDaemons/[^/]+\.plist$'; ls "$HOME_DIR"/Library/LaunchAgents/*.plist 2>/dev/null; host_enabled && ls /Library/LaunchAgents/*.plist /Library/LaunchDaemons/*.plist 2>/dev/null)
        ;;
      systemd_unit)
        for f in "$HOME_DIR/.config/systemd/user/$val" /etc/systemd/system/"$val" /usr/lib/systemd/system/"$val"; do
          case "$f" in /etc/*|/usr/*) host_enabled || continue ;; esac
          [ -e "$f" ] && critical "$camp" "$f" intel.systemd_unit unit="$val"
        done
        while IFS= read -r f; do [ -n "$f" ] && critical "$camp" "$f" intel.systemd_unit unit="$val"; done < <(files_path "/systemd/(user|system)/$(printf '%s' "$val" | sed 's/[.[\*^$+?(){}|]/\\&/g')\$")
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
      critical "$camp" "/proc/$pid" intel.process name="$name" pid="$pid"
    done
  done < <(intel_jq '.intel.host[]? | .campaign as $c | (.process_names // [])[] | [$c, .] | @tsv')
}

# Development infrastructure CVEs (generic evaluation in §16; targets infrastructures[] that have image_patterns and fixed)
intel_infra() {
  intel_ready || return 0
  # Targets products that are generic as a whole, or CVEs appended to a product with its own evaluation (cves[].generic)
  local iid pat cve fixed sev cvss ver f
  while IFS="$US" read -r iid pat cve fixed sev cvss; do
    [ -n "$pat" ] && [ -n "$fixed" ] || continue
    pat="${pat//\\\\/\\}"  # undo the escaping of @tsv
    local -a fx; IFS=',' read -r -a fx <<<"$fixed"
    while IFS=$'\t' read -r ver f; do
      [ -n "$ver" ] || continue
      [[ "${ver#v}" =~ ^[0-9]+(\.[0-9]+)+$ ]] || { [ "$ver" = "latest" ] && medium "" "$f" intel.infra_latest cve="$cve" fixed="${fixed//,/ }" product="$iid"; continue; }
      if version_branch_vulnerable "${ver#v}" "${fx[@]}"; then
        if [ -n "$cvss" ]; then lvl_emit "$sev" "" "$f" intel.infra_vulnerable_cvss cve="$cve" cvss="$cvss" fixed="${fixed//,/ }" product="$iid" version="$ver" --x="$(x_kind runtime.cve)"
        else lvl_emit "$sev" "" "$f" intel.infra_vulnerable cve="$cve" fixed="${fixed//,/ }" product="$iid" version="$ver" --x="$(x_kind runtime.cve)"; fi
      fi
    done < <(detect_service_version "$pat")
  done < <(intel_jq '.infrastructures[] | (.generic == true) as $g | .id as $i | (.image_patterns // []) as $p | .cves[] | select($g or .generic == true) | select((.fixed // []) | length > 0) |
            [$i, ($p | join("|")), .id, (.fixed | join(",")), (.severity // (if (.cvss // 0) >= 9 or .kev then "CRITICAL" else "HIGH" end)), ((.cvss // "") | tostring)] | @tsv' | tsv_us)
}

# Local tool versions (§23). Only the tools and version arguments listed here may be started (data can never start arbitrary commands)
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
    # Distribution builds are often fixed by backports, so the cap is HIGH
    [ "$sev" = "CRITICAL" ] && sev=HIGH
    version_branch_vulnerable "$v" "${fx[@]}" && lvl_emit "$sev" "" "$(command -v "$bin")" intel.tool_vulnerable cve="$cve" fixed="${fixed//,/ }" tool="$bin" version="$v" --x="$(x_kind runtime.cve)"
  done < <(intel_jq '.infrastructures[] | select(.binary != null) | .id as $i | .binary as $b | .cves[] | select((.fixed // []) | length > 0) |
            [$i, $b, .id, (.fixed | join(",")), (.severity // (if (.cvss // 0) >= 9 or .kev then "CRITICAL" else "HIGH" end))] | @tsv')
}

# Vulnerable AI editors (§7): read the version from the Info.plist of the macOS app bundle (without starting it)
intel_apps() {
  intel_ready || return 0
  host_enabled || return 0
  local camp bundle cve sev fixed f v
  while IFS="$US" read -r camp bundle cve sev fixed; do
    for f in "/Applications/$bundle/Contents/Info.plist" "$HOME_DIR/Applications/$bundle/Contents/Info.plist"; do
      [ -f "$f" ] || continue
      v="$(grep -A1 'CFBundleShortVersionString' "$f" | grep -o -E '[0-9]+(\.[0-9]+)+' | head -n1)"
      [ -n "$v" ] && version_lt "$v" "$fixed" && lvl_emit "$sev" "$camp" "$f" intel.app_vulnerable app="${bundle%.app}" cve="$cve" fixed="$fixed" version="$v" --x="$(x_kind runtime.cve)"
    done
  done < <(intel_jq '.intel.apps[]? | [.campaign, .bundle, .cve, (.severity // "HIGH"), .fixed] | @tsv' | tsv_us)
}

# Malicious strings in arbitrary files (§7 AI instruction files, §20 MCP definitions etc.). file_regex narrows down the file paths
intel_strings() {
  intel_ready || return 0
  local camp sev rx str f
  while IFS=$'\t' read -r camp sev rx str; do
    [ -n "$str" ] || continue
    rx="${rx//\\\\/\\}"  # @tsv escapes \ twice, so undo it
    files_path "$rx" | grep_lF "$str" -i | while IFS= read -r f; do
      [ -n "$f" ] || continue
      # If it is a hook in an agent config file, put the locations of the hooks containing the string into locators
      local x=""
      case "$f" in */.claude/settings.json|*/.claude/settings.local.json) x="$(x_locators "$(json_ptr_locators "$f" "$HOOK_PATHS_STR" --arg s "$str")")" ;; esac
      lvl_emit "$sev" "$camp" "$f" intel.campaign_string campaign="$camp" --x="$x"
    done
  done < <(intel_jq ".intel.strings[]? | select(.module == \"$CURRENT_MODULE\") | .campaign as \$c | (.severity // \"HIGH\") as \$s | (.file_regex // \".\") as \$r | (.strings // [])[] | [\$c, \$s, \$r, .] | @tsv")
}

HOME_RC_FILES=( .bashrc .bash_profile .profile .zshrc .zprofile .zshenv .zlogin .bash_login )
home_rc_paths() { local f; for f in "${HOME_RC_FILES[@]}"; do [ -f "$HOME_DIR/$f" ] && printf '%s\n' "$HOME_DIR/$f"; done; return 0; }
host_enabled() { [ "$HOST_CHECKS" = "1" ]; }

# =============================================================================
# §1-§14 (inherited from v3.5, with enhancements)
# =============================================================================

# §1 Markers and process signatures
check_s1() {
  log_section "§1"
  local m f sig
  # Files in ROOT with the same name as a marker (for offline analysis)
  while IFS= read -r m; do
    local base="${m##*/}"
    while IFS= read -r f; do [ -n "$f" ] && critical "" "$f" s1.marker_file name="$base"; done \
      < <(ZES_G="$base" awk 'BEGIN{g=ENVIRON["ZES_G"]; gsub(/\./,"[.]",g); gsub(/\*/,".*",g); g="^" g "$"} {n=$0; sub(/.*\//,"",n); if (n ~ g) print}' "$FILES_LIST")
  done < <(read_ioc '.markers')
  host_enabled || { log_info log.host_checks_off; return 0; }
  while IFS= read -r m; do
    local IFS=$'\n'
    for f in $m; do [ -e "$f" ] && critical "" "$f" s1.marker marker="$m"; done
    unset IFS
  done < <(read_ioc '.markers')
  if command -v ps >/dev/null 2>&1; then
    ps axww -o pid= -o command= 2>/dev/null >"$TMP_DIR/ps.txt" || record_error "§1" "ps_failed"
    while IFS= read -r sig; do
      [ -n "$sig" ] || continue
      grep -F -- "$sig" "$TMP_DIR/ps.txt" 2>/dev/null | grep -v -F -- "zes-scan" | awk '{print $1}' | while IFS= read -r pid; do
        critical "" "/proc/$pid" s1.process_signature pid="$pid" signature="$sig"
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
        critical "teampcp-mini-shai-hulud" "/proc/$pid" s1.c2_connection ioc="$ioc" pid="$pid"
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
        high "" "$mp" s1.tmp_library
      fi
    done
  fi
  intel_host_processes
  return 0
}

# §2 Python/Node hooks
# Standard import lines in .pth (only those matching the whole line are allowed)
PTH_SAFE_RE='[[:space:]]*import[[:space:]]+_virtualenv[[:space:]]*'
PTH_SAFE_RE+="|import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os\.environ\.get\(var, '(local|stdlib)'\) == 'local'; enabled and __import__\('_distutils_hack'\)\.add_shim\(\); *"
PTH_SAFE_RE+='|[[:space:]]*import[[:space:]]+(__editable___[A-Za-z0-9_]+_finder|_editable_impl_[A-Za-z0-9_]+)[[:space:]]*(;[[:space:]]*(__editable___[A-Za-z0-9_]+_finder|_editable_impl_[A-Za-z0-9_]+)\.install\([^()]*\)[[:space:]]*)?'
# Lifecycle scripts in package.json (install-type and prepare-type. prepare also runs when fetching git dependencies and on npm install)
PKG_HOOK_RE='^(pre|post)?(install|prepare)$'
check_s2() {
  log_section "§2"
  local f
  while IFS= read -r f; do [ -n "$f" ] && critical "litellm-oct2026" "$f" s2.hook_file name="${f##*/}"; done < <(files_named '^cook\.(pth|py)$')
  while IFS= read -r f; do [ -n "$f" ] && high "litellm-oct2026" "$f" s2.startup_hook name="${f##*/}"; done < <(files_named '^(sitecustomize|usercustomize)\.py$')
  # Import lines in .pth are exec-ed on every Python start. Import lines other than the standard forms (_virtualenv of virtualenv, distutils-precedence of
  # setuptools, __editable___*_finder / _editable_impl_* of PEP 660 editable installs) are MEDIUM;
  # those involving obfuscation, network access or execution (exec/eval/compile/os.system/popen/getattr/__import__ etc.) are HIGH
  local pthl
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    pthl="$(text_lines "$f" | grep -a -E '^[[:space:]]*import[[:space:]]' \
      | grep -a -v -x -E "$PTH_SAFE_RE")"
    [ -n "$pthl" ] || continue
    if printf '%s\n' "$pthl" | grep_q -a -E '(^|[^A-Za-z0-9_])(exec|eval|compile|getattr|popen|system|__import__)[[:space:]]*\(|b64decode|subprocess|urllib|socket|fromhex|marshal|zlib|codecs|pickle|ctypes|requests'; then
      high "litellm-oct2026" "$f" s2.pth_exec
    else
      medium "litellm-oct2026" "$f" s2.pth_import
    fi
  done < <(files_named '\.pth$')
  # PYTHONSTARTUP
  if host_enabled && [ -n "${PYTHONSTARTUP:-}" ]; then medium "" "${PYTHONSTARTUP}" s2.pythonstartup_env; fi
  while IFS= read -r f; do [ -n "$f" ] && fgrep_q 'PYTHONSTARTUP=' "$f" && medium "" "$f" s2.pythonstartup_rc; done < <(home_rc_paths)
  # Mismatch between __pycache__/*.pyc and the source (reads only the mtime/size in the header; limited to timestamp-based pyc with flags=0)
  local pyc src flags hm hs sm ss
  while IFS= read -r pyc; do
    [ -n "$pyc" ] || continue
    src="$(dirname -- "$(dirname -- "$pyc")")/$(basename -- "$pyc" | sed -E 's/\.(cpython|pypy)[^.]*\.pyc$/.py/; s/\.pyc$/.py/')"
    if [ ! -f "$src" ]; then
      case "$pyc" in */site-packages/*|*/dist-packages/*) medium "" "$pyc" s2.pyc_sourceless ;; esac
      continue
    fi
    read -r flags hm hs < <(od -An -tu4 -j4 -N12 -- "$pyc" 2>/dev/null) || continue
    [ "${flags:-1}" = "0" ] || continue
    sm="$(stat_mtime "$src")"; ss="$(stat_size "$src")"
    [ -n "$sm" ] && [ -n "$ss" ] || continue
    if [ "$hm" != "$(( sm % 4294967296 ))" ] || [ "$hs" != "$(( ss % 4294967296 ))" ]; then
      high "" "$pyc" s2.pyc_mismatch
    fi
  done < <(files_path '/__pycache__/[^/]+\.pyc$')
  # preinstall/install/postinstall in package.json
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    local scripts=""
    local pq='(.scripts // {}) | if type == "object" then to_entries[] | select(.key | test($re)) | .value | tostring else empty end'
    if [ "$HAVE_JQ" -eq 1 ]; then
      # If it cannot be read as strict JSON (BOM, trailing comma etc.), reread it as JSONC; if that fails too, pick it up with grep
      scripts="$(jq -r --arg re "$PKG_HOOK_RE" "$pq" "$f" 2>/dev/null)" \
        || scripts="$(jsonc_to_json "$f" | jq -r --arg re "$PKG_HOOK_RE" "$pq" 2>/dev/null)" \
        || scripts="$(grep -a -E '"(pre|post)?(install|prepare)"[[:space:]]*:' "$f" 2>/dev/null)"
    else
      scripts="$(grep -a -E '"(pre|post)?(install|prepare)"[[:space:]]*:' "$f" 2>/dev/null)"
    fi
    [ -n "$scripts" ] || continue
    if printf '%s' "$scripts" | grep_q -E '(curl|wget|bash|sh -c|base64|eval|node -e|\.mjs|https?://)'; then
      high "" "$f" s2.lifecycle_suspicious
    elif zes_rel "$f"; [[ "$REL" != */node_modules/* ]]; then
      medium "" "$f" s2.lifecycle_defined
    fi
  done < <(files_named '^package\.json$')
  return 0
}

# §3 GitLab
check_s3() {
  log_section "§3"
  local ver f found=0
  # The CVEs evaluated are infrastructures[gitlab].cves in ioc (those with a fixed version). Without jq, the 3 known ones,
  #   with the CVSS literal read from the same ioc.json line as infra_fixed does (code, params and id must not depend on jq)
  local -a gcves; local -A gcvss=()
  local c v
  if [ "$HAVE_JQ" -eq 1 ]; then
    while IFS=$'\t' read -r c v; do gcves+=("$c"); [ -n "$v" ] && gcvss[$c]="$v"; done \
      < <(jq -r '.infrastructures[] | select(.id=="gitlab") | .cves[] | select((.fixed // []) | length > 0) | [.id, ((.cvss // "") | tostring)] | @tsv' "$IOC_FILE")
  else
    gcves=(CVE-2026-110264 CVE-2026-85706 CVE-2026-19478)
    for c in "${gcves[@]}"; do
      v="$(grep -o "\"$c\".*" "$IOC_FILE" | head -n1 | grep -o '"cvss": *[0-9][0-9.]*' | grep -o '[0-9][0-9.]*$')"
      [ -n "$v" ] && gcvss[$c]="$v"
    done
  fi
  while IFS=$'\t' read -r ver f; do
    [ -n "$ver" ] || continue
    found=1
    local cve
    for cve in "${gcves[@]}"; do
      local -a gfix; mapfile -t gfix < <(infra_fixed gitlab "$cve")
      if [[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] && [ "${#gfix[@]}" -gt 0 ] && version_branch_vulnerable "$ver" "${gfix[@]}"; then
        if [ -n "${gcvss[$cve]:-}" ]; then
          critical "" "$f" s3.gitlab_vulnerable cve="$cve" cvss="${gcvss[$cve]}" first_fixed="${gfix[0]}" fixed="${gfix[*]}" version="$ver" --x="$(x_kind runtime.cve)"
        else
          critical "" "$f" s3.gitlab_vulnerable_cvss9 cve="$cve" first_fixed="${gfix[0]}" fixed="${gfix[*]}" version="$ver" --x="$(x_kind runtime.cve)"
        fi
      fi
    done
    [[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || high "" "$f" s3.gitlab_version_unknown cves="${gcves[*]}" version="$ver"
  done < <(detect_service_version 'gitlab/gitlab-(ee|ce)')
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    fgrep_q "trusted_proxies.*0\.0\.0\.0/0" "$f" && high "" "$f" s3.trusted_proxies
    fgrep_q "^[[:space:]]*nginx\['custom_gitlab_server_config'\]" "$f" && medium "" "$f" s3.custom_nginx
  done < <(files_named '^gitlab\.rb$'; host_enabled && [ -f /etc/gitlab/gitlab.rb ] && echo /etc/gitlab/gitlab.rb)
  if host_enabled && [ -f "$TMP_DIR/ps.txt" ] && grep -q -E 'gitlab-(workhorse|rails)|gitaly' "$TMP_DIR/ps.txt"; then
    high "" "" s3.gitlab_process
    found=1
  fi
  [ "$found" -eq 0 ] && safe log.safe.gitlab_none
  return 0
}

# §4 PHP
# php_status VERSION → vulnerable / fixed / prerelease / unknown_branch / unparsed (PHP2Shell, evaluated on the upstream version number)
#   The evaluation has the same semantics as versionStatus in openai/php2shell-checker (Apache-2.0):
#   - what follows x.y.z starts with something other than -,+,~ / not x.y.z → unparsed (needs review)
#   - prereleases such as dev / alpha / beta / RC → prerelease (not judged fixed from the x.y.z part alone)
#   - 5.4-8.1 (no official fix release) → vulnerable; branches with a fixed version (8.2-8.5) → decided by the patch number
#   - new branches not in the fixed-version list (8.6+ / 9.x etc.) and 5.3 or earlier → unknown_branch (not treated as fixed)
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

# deb_version_lt A B … true if A < B in Debian version order (epoch:upstream-revision; ~ sorts before empty)
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

# ID<TAB>VERSION_ID from os-release (regular files only)
os_release_id() {
  local f
  for f in "$1/etc/os-release" "$1/usr/lib/os-release"; do
    [ -f "$f" ] || continue
    # Image extractions inside the scan root never read links pointing outside the root (/proc etc.)
    [ -z "$1" ] || in_root_regular "$f" || continue
    text_lines "$f" | awk -F= '$1 == "ID" || $1 == "VERSION_ID" { v = $2; gsub(/^["\047]|["\047]$/, "", v); r[$1] = v }
      END { print r["ID"] "\t" r["VERSION_ID"] }' 2>/dev/null
    return 0
  done
  printf '\t\n'
}

# PHP2Shell: statically reads the dpkg package DB (/var/lib/dpkg/status; container image extractions inside ROOT too) and
# compares the packages actually used for serving (php*-fpm / libapache2-mod-php* / php*-cgi / php*-cli) with the vendor fixed versions
#   output: the number of packages php_distro_packages evaluated (non-zero if the host dpkg could be evaluated)
php_distro_packages() {
  local f base id vid pkg ver src row fixed adv url n=0
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
        medium "" "$f" s4.dpkg_no_advisory os="${id:-unknown}" os_version="$vid" package="$pkg" source="$src" version="$ver"
        continue
      fi
      IFS=$'\t' read -r fixed adv url <<<"$row"
      if deb_version_lt "$ver" "$fixed"; then
        high "" "$f" s4.dpkg_vulnerable advisory="$adv" fixed="$fixed" os="$id" os_version="$vid" package="$pkg" url="$url" version="$ver"
      else
        info "" "$f" s4.dpkg_fixed advisory="$adv" fixed="$fixed" os="$id" os_version="$vid" package="$pkg" version="$ver"
      fi
    done <"$TMP_DIR/php-dpkg.tsv"
  done < <(host_enabled && echo /var/lib/dpkg/status; files_path '/var/lib/dpkg/status$')
  echo "$n"
}

check_s4() {
  log_section "§4"
  local f
  local -a pfix; mapfile -t pfix < <(infra_fixed php CVE-2026-109618)
  php_judge() {  # php_judge VERSION PATH SOURCE(upstream|distro|header)
    local ver="$1" path="$2" src="$3" st
    st="$(php_status "$ver")"
    # 8.1 and earlier have no official fix release: separate *_eol codes
    local eol=0; [[ "$ver" =~ ^v?([0-9]+)\.([0-9]+)\. ]] && version_lt "${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.0" "8.2.0" && eol=1
    case "$src:$st:$eol" in
      *:fixed:*) [ "$src" = "header" ] && safe log.safe.php_header_fixed version="$ver" ;;
      *:prerelease:*) medium "" "$path" s4.php_prerelease version="$ver" ;;
      *:unknown_branch:*) medium "" "$path" s4.php_unknown_branch fixed="${pfix[*]}" version="$ver" ;;
      *:unparsed:*) medium "" "$path" s4.php_unparsed version="$ver" ;;
      distro:vulnerable:0) high "" "$path" s4.php_vulnerable_distro fixed="${pfix[*]}" version="$ver" ;;
      distro:vulnerable:1) high "" "$path" s4.php_vulnerable_distro_eol fixed="${pfix[*]}" version="$ver" ;;
      header:vulnerable:0) high "" "$path" s4.php_vulnerable_header version="$ver" ;;
      header:vulnerable:1) high "" "$path" s4.php_vulnerable_header_eol version="$ver" ;;
      *:vulnerable:0) critical "" "$path" s4.php_vulnerable fixed="${pfix[*]}" version="$ver" ;;
      *:vulnerable:1) critical "" "$path" s4.php_vulnerable_eol fixed="${pfix[*]}" version="$ver" ;;
    esac
  }
  local ndeb; ndeb="$(php_distro_packages)"
  if host_enabled; then
    local v
    v="$(safe_probe php -n -v | head -n1 | awk '{print $2}')"
    if [ -n "$v" ]; then
      info "" "" s4.php_installed version="$v"
      case "$v" in
        *ubuntu*|*deb*|*el[0-9]*|*fc[0-9]*|*-[0-9]*)
          # When the dpkg package DB allowed comparison with the vendor fixed version, do not add a version-number-only evaluation on top (backports unknown)
          if [ "${ndeb:-0}" -gt 0 ]; then log_info log.php_dpkg_checked version="$v"; else php_judge "$v" "$(command -v php)" distro; fi ;;
        *) php_judge "$v" "$(command -v php)" upstream ;;
      esac
      if [ -f /etc/redhat-release ]; then
        local rows; rows="$(intel_jq '.php2shell_distro.packages[]? | select(.vendor == "rhel") | "RHEL \(.release) \(.source_package) >= \(.fixed) (\(.advisory))"' | paste -sd'/' -)"
        if [ -n "$rows" ]; then medium "" "/etc/redhat-release" s4.rhel_rows rows="$rows"
        else medium "" "/etc/redhat-release" s4.rhel; fi
      fi
    fi
  fi
  local ver
  while IFS=$'\t' read -r ver f; do
    [ -n "$ver" ] && php_judge "$ver" "$f" upstream
  done < <(detect_service_version '(^|[[:space:]/"=])php' | awk -F'\t' '{ v = $1; sub(/^[^0-9]*/, "", v); if (v != "") print v "\t" $2 }')  # floating tags such as latest are handled by the FROM check below
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    ver="$(text_lines "$f" | grep -E '^php[[:space:]]+[0-9]' | head -n1 | awk -F'[ \t\v\f\r]+' '{print $2}')"
    [ -n "$ver" ] && php_judge "$ver" "$f" upstream
  done < <(files_named '^\.tool-versions$')
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    zes_src "$f"; grep -E -i -o '^[[:space:]]*FROM[[:space:]]+([^ ]*/)?php(:[^ ]+)?' "$SRC" 2>/dev/null | while IFS= read -r line; do
      case "$line" in
        *php:*latest*|*php) medium "" "$f" s4.php_image_floating ;;
        *) info "" "$f" s4.php_image image="${line##* }" ;;
      esac
    done
  done < <(files_named '^(Dockerfile.*|.*\.dockerfile)$')
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    fgrep_q '^[[:space:]]*auto_prepend_file[[:space:]]*=[[:space:]]*[^[:space:];]' "$f" && high "" "$f" s4.auto_prepend \
      --x="$(x_text_locators "$f" '^[[:space:]]*auto_prepend_file[[:space:]]*=[[:space:]]*[^[:space:];]')"
    fgrep_q '^[[:space:]]*disable_functions[[:space:]]*=[[:space:]]*$' "$f" && medium "" "$f" s4.disable_functions_empty \
      --x="$(x_text_locators "$f" '^[[:space:]]*disable_functions[[:space:]]*=[[:space:]]*$')"
  done < <(files_named '^php.*\.ini$'; host_enabled && ls /etc/php*/php.ini /etc/php/*/*/php.ini /usr/local/etc/php/php.ini 2>/dev/null)
  if [ -n "$TARGET_URL" ]; then
    if [ "$OFFLINE" = "1" ]; then record_error "§4" "skipped_offline"; return 0; fi
    # Fetch headers only (HEAD; GET only on 405/501). Redirects are not followed, the body is not read, ~/.curlrc is not read (-q)
    local hdrs code
    hdrs="$(curl -q -sS -I --connect-timeout 5 --max-time 10 --proto '=http,https' -- "$TARGET_URL" 2>/dev/null | tr -d '\r')"
    code="$(printf '%s\n' "$hdrs" | awk '/^HTTP\// { c = $2 } END { print c }')"
    if [ "$code" = "405" ] || [ "$code" = "501" ]; then
      hdrs="$(curl -q -sS -o /dev/null -D - --connect-timeout 5 --max-time 10 --max-filesize 1048576 --proto '=http,https' -- "$TARGET_URL" 2>/dev/null | tr -d '\r')"
      code="$(printf '%s\n' "$hdrs" | awk '/^HTTP\// { c = $2 } END { print c }')"
    fi
    if [ -z "$code" ]; then record_error "§4" "url_fetch_failed"; return 0; fi
    local xpb srv pv st best="" bst=""
    # When the same header appears several times, look at all of them (only the headers of the last response; values joined with "; ")
    hdrs="$(printf '%s\n' "$hdrs" | awk '/^HTTP\// { b = "" } { b = b $0 "\n" } END { printf "%s", b }')"
    xpb="$(printf '%s\n' "$hdrs" | grep -i '^x-powered-by:' | sed -E 's/^[^:]*:[[:space:]]*//' | paste -sd';' - | sed 's/;/; /g')"
    srv="$(printf '%s\n' "$hdrs" | grep -i '^server:' | sed -E 's/^[^:]*:[[:space:]]*//' | paste -sd';' - | sed 's/;/; /g')"
    [ -n "$xpb" ] && medium "" "" s4.header_exposes url="$TARGET_URL" value="$xpb"
    printf '%s' "$srv" | grep_q -i -E '(^|[^A-Za-z])PHP[ /]' && medium "" "" s4.server_exposes url="$TARGET_URL" value="$srv"
    # Evaluate every PHP/x.y.z in both headers and take the worst in the order warning (vulnerable) > unknown > fixed (never favor reassurance)
    while IFS= read -r pv; do
      [ -n "$pv" ] || continue
      st="$(php_status "$pv")"
      if [ -z "$best" ] || [ "$st" = "vulnerable" ] || { [ "$bst" = "fixed" ] && [ "$st" != "fixed" ]; }; then best="$pv"; bst="$st"; fi
      [ "$bst" = "vulnerable" ] && break
    done < <(printf '%s\n%s\n' "$srv" "$xpb" | grep -o -i -E '(^|[^A-Za-z])PHP[ /][^[:space:],;)]+' | sed -E 's/^[^Pp]*[Pp][Hh][Pp][ \/]//')
    if [ -n "$best" ]; then php_judge "$best" "" header
    else safe log.safe.php_no_header url="$TARGET_URL"; fi
  fi
  return 0
}

# §5 Python runtime (3.15.1 / 3.14.9 / 3.13.17 or later)
check_s5() {
  log_section "§5"
  local -a mins; mapfile -t mins < <(read_ioc '.runtime_minimums.python')
  local v f
  check_py_version() {
    local ver="$1" path="$2"
    [[ "$ver" =~ ^3\.[0-9]+(\.[0-9]+)?$ ]] || return 0
    [[ "$ver" =~ ^3\.[0-9]+$ ]] && ver="$ver.0"
    if version_branch_vulnerable "$ver" "${mins[@]}"; then
      high "" "$path" s5.python_old fixed="${mins[*]}" version="$ver" --x="$(x_kind runtime.cve)"
    fi
  }
  if host_enabled; then
    v="$(safe_probe python3 -I -S -V 2>&1 | awk '{print $2}')"
    [ -n "$v" ] && check_py_version "$v" "$(command -v python3)"
  fi
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    # text_lines: no BOM, no CR; a NUL stays a character (U+0001), as in the browser, so "3.11<NUL>.1" is no version
    v="$(text_lines "$f" | head -n1 | tr '\000' '\001' | tr -d '[:space:]')"; check_py_version "$v" "$f"
  done < <(files_named '^\.python-version$')
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    grep -E -i -o 'FROM[[:space:]]+([^ ]*/)?python:3\.[0-9]+(\.[0-9]+)?' "$f" 2>/dev/null | sed -E 's/.*python://' | while IFS= read -r v; do
      check_py_version "$v" "$f"
    done
  done < <(files_named '^(Dockerfile.*|.*\.dockerfile)$')
  return 0
}

# §6 eMudhra (certificate authority compromise)
check_s6() {
  log_section "§6"
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
        0) critical "$camp" "" s6.curl_trusts url="https://$host/" ;;
        35|51|53|54|58|59|60|77|80|83|90|91) safe log.safe.emudhra_tls_error host="$host" ;;
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
    [ -n "$v" ] && [[ "$v" < "$min" ]] && high "$camp" "$d/$v" s6.homebrew_ca min="$min" version="$v" --x="$(x_kind runtime.cve)"
  done
  min="$(read_ioc '.runtime_minimums.certifi')"
  build_deps
  awk -F'\t' '$1=="pypi" && $2=="certifi" {print $3"\t"$4}' "$DEPS_TSV" | tsv_us | while IFS="$US" read -r v d; do
    version_lt "$v" "$min" && high "$camp" "$d" s6.certifi min="$min" version="$v" --x="$(x_kind runtime.cve)"
  done
  local -a gmins; mapfile -t gmins < <(read_ioc '.runtime_minimums.go')
  if host_enabled; then
    # go version starts a telemetry child process, so it is not run; GOROOT/VERSION is read statically
    local gobin goroot
    gobin="$(command -v go 2>/dev/null)" && gobin="$(resolve_path "$gobin")" && goroot="$(dirname -- "$(dirname -- "$gobin")")"
    v=""
    [ -n "${goroot:-}" ] && [ -f "$goroot/VERSION" ] && v="$(head -n1 "$goroot/VERSION" | grep -o -E 'go[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n1)"
    v="${v#go}"
    [ -n "$v" ] && version_branch_vulnerable "$v" "${gmins[@]}" && high "" "$(command -v go)" s6.go_old min="${gmins[*]}" version="$v" --x="$(x_kind runtime.cve)"
  fi
  while IFS= read -r d; do
    [ -n "$d" ] || continue
    zes_src "$d"; v="$(grep -E '^(toolchain go|go )[0-9]' "$SRC" | tail -n1 | grep -o -E '[0-9]+\.[0-9]+(\.[0-9]+)?')"
    [ -n "$v" ] || continue
    [[ "$v" =~ ^[0-9]+\.[0-9]+$ ]] && v="$v.0"
    version_branch_vulnerable "$v" "${gmins[@]}" && medium "" "$d" s6.go_mod_old min="${gmins[*]}" version="$v" --x="$(x_kind runtime.cve)"
  done < <(files_named '^go\.mod$')
  return 0
}

# eMudhra: the OS ca-certificates package (reads the package DB statically; never starts the package manager)
debian_ca_fixed() {  # debian_ca_fixed VERSION → 0 (fixed) / 1 (not fixed)
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
  # dpkg (Debian / Ubuntu / Devuan): /var/lib/dpkg/status. Same-named files inside ROOT (container image extractions) too
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    # Read per paragraph (package), only for those whose Status is installed (removed and config-files are excluded; same as §4)
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
    # The vendor is determined from the os-release of the same image (the Ubuntu SRU version 20260601~24.04.1 does not contain "ubuntu")
    local osid=""; IFS=$'\t' read -r osid _ < <(os_release_id "${f%/var/lib/dpkg/status}")
    if [[ "$v" == *ubuntu* ]] || [ "$osid" = "ubuntu" ]; then
      [ "${v:0:8}" -lt "${min_ub:-20260816}" ] 2>/dev/null && high "$camp" "$f" s6.ca_ubuntu min="$min_ub" version="$v" --x="$(x_kind runtime.cve)"
    elif ! debian_ca_fixed "$v"; then
      high "$camp" "$f" s6.ca_debian version="$v" --x="$(x_kind runtime.cve)"
    fi
  done < <(host_enabled && echo /var/lib/dpkg/status; files_path '/var/lib/dpkg/status$')
  # apk (Alpine / Wolfi / Chainguard): /lib/apk/db/installed
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    v="$(awk '/^P:ca-certificates$/ {p=1; next} p && /^V:/ {sub(/^V:/,""); print; exit} /^$/ {p=0}' "$f")"
    [ -n "$v" ] || continue
    local amin; amin="$(read_ioc '.emudhra.os_ca_certificates.alpine')"
    [[ "${v%%-r*}" < "${amin%%-r*}" ]] && high "$camp" "$f" s6.ca_apk min="$amin" version="$v" --x="$(x_kind runtime.cve)"
  done < <(host_enabled && echo /lib/apk/db/installed; files_path '/lib/apk/db/installed$')
  # pacman (Arch): /var/lib/pacman/local/ca-certificates-mozilla-<ver>/
  local d
  for d in /var/lib/pacman/local/ca-certificates-mozilla-*; do
    host_enabled && [ -d "$d" ] || continue
    v="${d##*/ca-certificates-mozilla-}"
    version_lt "${v%-*}" "3.131.1" && high "$camp" "$d" s6.ca_pacman version="$v" --x="$(x_kind runtime.cve)"
  done
  return 0
}

# eMudhra: runtimes pinned in the repository (Node.js / Java / Deno) and host tools (Docker Desktop / mise / rustup)
emudhra_runtimes() {
  local camp="emudhra-ca-oct2026" f v
  local -a nfix jfix dfix; mapfile -t nfix < <(read_ioc '.emudhra.fixed.node'); mapfile -t jfix < <(read_ioc '.emudhra.fixed.java'); mapfile -t dfix < <(read_ioc '.emudhra.fixed.deno')
  judge() {  # judge NAME VERSION PATH FIXED...
    local name="$1" ver="$2" path="$3"; shift 3
    [[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 0
    version_branch_vulnerable "$ver" "$@" && high "$camp" "$path" s6.runtime_trusts fixed="$*" name="$name" version="$ver" --x="$(x_kind runtime.cve)"
  }
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    v="$(text_lines "$f" | head -n1 | tr '\000' '\001' | tr -d '[:space:]' | sed -E 's/^v//')"; judge "Node.js" "$v" "$f" "${nfix[@]}"
  done < <(files_named '^(\.nvmrc|\.node-version)$')
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    # Normalize with text_lines so the version can be read from a CRLF .tool-versions as well
    v="$(text_lines "$f" | grep -E '^nodejs[[:space:]]+' | awk -F'[ \t\v\f\r]+' '{print $2}' | head -n1)"; [ -n "$v" ] && judge "Node.js" "$v" "$f" "${nfix[@]}"
    v="$(text_lines "$f" | grep -E '^deno[[:space:]]+' | awk -F'[ \t\v\f\r]+' '{print $2}' | head -n1)"; [ -n "$v" ] && judge "Deno" "$v" "$f" "${dfix[@]}"
  done < <(files_named '^\.tool-versions$')
  while IFS=$'\t' read -r v f; do judge "Node.js" "${v#v}" "$f" "${nfix[@]}"; done < <(detect_service_version '(^|[[:space:]/"=])node')
  while IFS=$'\t' read -r v f; do judge "Deno" "${v#v}" "$f" "${dfix[@]}"; done < <(detect_service_version 'denoland/deno')
  while IFS=$'\t' read -r v f; do
    v="${v%%_*}"; v="${v%%+*}"
    [[ "$v" =~ ^8u?([0-9]+) ]] && { [ "${BASH_REMATCH[1]}" -lt "$(read_ioc '.emudhra.fixed.java8_update')" ] && high "$camp" "$f" s6.java8_trusts update="${BASH_REMATCH[1]}" --x="$(x_kind runtime.cve)"; continue; }
    judge "Java" "$v" "$f" "${jfix[@]}"
  done < <(detect_service_version '(eclipse-temurin|amazoncorretto|openjdk|bellsoft/liberica-openjdk-[a-z]+|azul/zulu-openjdk)')
  # Host: Docker Desktop (Info.plist on macOS), mise, rustup (version information is read from files)
  if host_enabled; then
    for f in /Applications/Docker.app/Contents/Info.plist "$HOME_DIR/Applications/Docker.app/Contents/Info.plist"; do
      [ -f "$f" ] || continue
      v="$(grep -A1 'CFBundleShortVersionString' "$f" | grep -o -E '[0-9]+(\.[0-9]+)+' | head -n1)"
      [ -n "$v" ] && version_lt "$v" "$(read_ioc '.emudhra.fixed.docker_desktop')" && high "$camp" "$f" s6.docker_desktop fixed="$(read_ioc '.emudhra.fixed.docker_desktop')" version="$v" --x="$(x_kind runtime.cve)"
    done
  fi
  return 0
}

# Instruction files of AI agents / editors (§7 / §41)
#   .cursorrules / CLAUDE.md / CLAUDE.local.md / AGENTS.md / GEMINI.md / copilot-instructions.md / .windsurfrules /
#   .clinerules (a file or under a directory) / .cursor/rules/* / .github/instructions/* / .claude/**/*.md
ai_instruction_files() {
  files_named '^(\.cursorrules|CLAUDE\.md|CLAUDE\.local\.md|AGENTS\.md|GEMINI\.md|copilot-instructions\.md|\.windsurfrules|\.clinerules)$'
  files_path '/\.cursor/rules/[^/]+$|/\.clinerules/.+|/\.github/instructions/.+|/\.claude/(.+/)?[^/]+\.md$'
}

# §7 AI/editor settings (invisible characters, BiDi, homoglyphs, Git hooks, runOn: folderOpen)
check_s7() {
  log_section "§7"
  local f
  # Invisible characters: embedding strings with U+200B-200F, U+202A-202E, U+2066-2069, tag characters (U+E0000-E007F), variation selectors (U+FE00-FE0D,
  # U+E0100-E01EF, 2 or more consecutive U+FE00-FE0F. A lone U+FE0E/FE0F used for emoji presentation is not applicable)
  local inv=$'\xe2\x80[\x8b-\x8f\xaa-\xae]|\xe2\x81[\xa0-\xa4\xa6-\xa9]|\xf3\xa0[\x80-\x81][\x80-\xbf]|\xef\xb8[\x80-\x8d]|\xf3\xa0[\x84-\x87][\x80-\xbf]|\xef\xb8[\x80-\x8f]\xef\xb8[\x80-\x8f]'
  local cyr=$'[A-Za-z][\xd0\xd1][\x80-\xbf]|[\xd0\xd1][\x80-\xbf][A-Za-z]|[A-Za-z]\xce[\x91-\xbf]|\xce[\x91-\xbf][A-Za-z]'
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    grep -q -a -E -- "$inv" "$f" 2>/dev/null && high "" "$f" s7.invisible_chars
    grep -q -a -E -- "$cyr" "$f" 2>/dev/null && medium "" "$f" s7.homoglyph
  done < <(ai_instruction_files)
  # Git hooks (non-sample files in the hooks of the .git directly under the scan root and nested ones [including gitdir: files and the shared side of worktrees])
  local hookdir
  while IFS= read -r hookdir; do
    [ -n "$hookdir" ] && [ -d "$hookdir" ] || continue
    for f in "$hookdir"/*; do
      [ -f "$f" ] || continue
      case "$f" in *.sample) continue ;; esac
      if fgrep_q '(curl|wget|base64|nc |/dev/tcp|python[0-9.]* -c|node -e)' "$f"; then
        high "" "$f" s7.git_hook_suspicious
      else
        medium "" "$f" s7.git_hook
      fi
    done
  done <"$GIT_HOOKS_LIST"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    fgrep_q '"runOn"[[:space:]]*:[[:space:]]*"folderOpen"' "$f" && high "mcp-poisoning" "$f" s7.folder_open \
      --x="$(x_locators "$(json_ptr_locators "$f" "$TASK_RUNON_PATHS")")"
  done < <(files_path '/\.(vscode|claude|cursor)/tasks\.json$')
  intel_strings
  intel_apps
  return 0
}

# §8 Cloud/containers
check_s8() {
  log_section "§8"
  local f
  while IFS= read -r f; do [ -n "$f" ] && medium "" "$f" s8.env_file; done \
    < <(files_named '^\.env(\.[A-Za-z0-9_-]+)?$' | grep -v -E '\.env\.(example|sample|template|dist)$')
  files_named '^(id_rsa|id_dsa|id_ecdsa|id_ed25519|.*\.pem|.*\.key|.*\.p12|.*\.pfx)$' | grep_l 'PRIVATE KEY' | while IFS= read -r f; do
    [ -n "$f" ] && [ "$f" != /dev/null ] && high "" "$f" s8.private_key
  done
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    # USER root, USER 0, USER root:<group>, USER 0:0 (the user is root whatever the group)
    fgrep_q -i '^[[:space:]]*USER[[:space:]]+(root|0)(:[^[:space:]]*)?([[:space:]]|$)' "$f" && medium "" "$f" s8.user_root
    dockerfile_images "$f" | while IFS= read -r img; do
      case "$img" in scratch|'$'*|*@sha256:*) continue ;; esac
      if [[ "$img" == *:latest ]] || [[ "${img##*/}" != *:* ]]; then medium "" "$f" s8.floating_image image="$img"; fi
    done
  done < <(files_named '^(Dockerfile.*|.*\.dockerfile)$')
  files_named '\.(ya?ml|json)$' | grep_l '/var/run/docker\.sock|/run/docker\.sock' | while IFS= read -r f; do
    [ -n "$f" ] && [ "$f" != /dev/null ] && high "" "$f" s8.docker_sock
  done
  return 0
}

# dockerfile_images FILE … the image of each FROM line, one per line (the same rule as fromImages of the browser engine):
#   the line (a leading BOM, a CR before the line break removed) is FROM after optional whitespace, then whitespace; the
#   words after it are split on [[:space:]] (space, tab, VT, FF, CR; not NBSP or other Unicode spaces), flags such as
#   --platform=linux/amd64 are skipped and the first other word is the image. A FROM line without one prints nothing
#   (never an empty image). A NUL becomes U+0001 (a shell variable cannot hold it; the browser engine does the same)
dockerfile_images() {
  awk 'NR == 1 { sub(/^\357\273\277/, "") }
    { sub(/\r$/, ""); gsub(/\0/, "\001"); l = $0
      if (!match(tolower(l), /^[ \t\v\f\r]*from[ \t\v\f\r]+/)) next
      n = split(substr(l, RLENGTH + 1), w, /[ \t\v\f\r]+/)
      for (k = 1; k <= n; k++) { if (w[k] == "" || substr(w[k], 1, 2) == "--") continue; print w[k]; break } }' "$1" 2>/dev/null
}

# §9 Rust/Go/Node typosquatting and unofficial sources
check_s9() {
  log_section "§9"
  build_deps
  local f
  # Matching of known typosquat names is done in §15 check_lockfile_versions (any_version)
  local -a regs; mapfile -t regs < <(read_ioc '.official_registries')
  local re; re="$(printf '%s|' "${regs[@]}" | sed 's/\./\\./g; s/|$//')"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if grep -E -o '"resolved"[[:space:]]*:[[:space:]]*"https?://[^/"]+' "$f" 2>/dev/null | sed -E 's#.*://##' | sort -u | grep -v -E "^($re)$" | grep_q .; then
      high "" "$f" s9.non_official_registry
    fi
    fgrep_q '"resolved"[[:space:]]*:[[:space:]]*"(git\+|github:|https?://[^"]*\.tgz#)' "$f" && medium "" "$f" s9.git_url_dependency
  done < <(files_named '^(package-lock\.json|npm-shrinkwrap\.json)$')
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    zes_src "$f"
    grep -q -E '^source = "git\+' "$SRC" && medium "" "$f" s9.cargo_git_source
    grep -E '^source = "registry\+' "$SRC" | grep_q -v 'github.com/rust-lang/crates.io-index\|sparse+https://index.crates.io' && high "" "$f" s9.cargo_registry
  done < <(files_named '^Cargo\.lock$')
  return 0
}

# §10 OS persistence (LaunchAgents/crontab/shell rc/history)
check_s10() {
  log_section "§10"
  local f
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    # findings 1.1: the matching lines are indicated by locators (line number and SHA-256 of the line)
    local re
    re='(curl|wget)[^|#]*\|[[:space:]]*(ba|z)?sh'
    fgrep_q "$re" "$f" && high "" "$f" s10.curl_sh --x="$(x_text_locators "$f" "$re")"
    re='(base64[[:space:]]+(-d|--decode)|\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2})'
    fgrep_q "$re" "$f" && high "" "$f" s10.obfuscated --x="$(x_text_locators "$f" "$re")"
    re='(/tmp/|/dev/shm/|/var/tmp/)[^[:space:]]+[[:space:]]*(&|$)'
    fgrep_q "$re" "$f" && medium "" "$f" s10.tmp_program --x="$(x_text_locators "$f" "$re")"
  done < <(home_rc_paths)
  if [ -d "$HOME_DIR/Library/LaunchAgents" ]; then
    for f in "$HOME_DIR"/Library/LaunchAgents/*.plist; do [ -f "$f" ] && info "" "$f" s10.launch_agent; done
  fi
  if host_enabled && command -v crontab >/dev/null 2>&1; then
    crontab -l 2>/dev/null >"$TMP_DIR/crontab.txt"
    if [ -s "$TMP_DIR/crontab.txt" ]; then
      if grep -v '^[[:space:]]*#' "$TMP_DIR/crontab.txt" | grep_q -E '(curl|wget|base64|/tmp/|/dev/shm/|nc )'; then
        high "" "" s10.crontab_suspicious user="$(id -un 2>/dev/null)"
      else
        info "" "" s10.crontab user="$(id -un 2>/dev/null)"
      fi
    fi
  fi
  for f in .lesshst .viminfo .python_history .node_repl_history .mysql_history .psql_history; do
    [ -f "$HOME_DIR/$f" ] && info "" "$HOME_DIR/$f" s10.history_file
  done
  return 0
}

# §11 SSH/GPG permissions
check_s11() {
  log_section "§11"
  local d f p bad=0
  for d in "$HOME_DIR/.ssh" "$HOME_DIR/.gnupg"; do
    [ -d "$d" ] || continue
    p="$(stat_perm "$d")"
    if [ -n "$p" ] && [ $(( 8#$p & 8#077 )) -ne 0 ]; then high "" "$d" s11.dir_perm mode="$p"; bad=1; fi
    for f in "$d"/*; do
      [ -f "$f" ] && [ ! -L "$f" ] || continue
      case "${f##*/}" in *.pub|known_hosts*|authorized_keys|config|*.conf|pubring.*|trustdb.gpg) continue ;; esac
      p="$(stat_perm "$f")"
      if [ -n "$p" ] && [ $(( 8#$p & 8#077 )) -ne 0 ]; then high "" "$f" s11.file_perm mode="$p"; bad=1; fi
    done
  done
  [ "$bad" -eq 0 ] && safe log.safe.ssh_gpg_perms
  return 0
}

# §12 The three vaccines (ignore-scripts / PYTHONNOUSERSITE / PIP_REQUIRE_VIRTUALENV)
check_s12() {
  log_section "§12"
  local hit
  hit=0; for f in "$HOME_DIR/.npmrc" "$RP/.npmrc"; do [ -f "$f" ] && { [ "$f" = "$HOME_DIR/.npmrc" ] || in_root_regular "$f"; } && fgrep_q '^[[:space:]]*ignore-scripts[[:space:]]*=[[:space:]]*true' "$f" && hit=1; done
  host_enabled && [ "${npm_config_ignore_scripts:-${NPM_CONFIG_IGNORE_SCRIPTS:-}}" = "true" ] && hit=1
  [ "$hit" -eq 1 ] && safe log.safe.npm_ignore_scripts || medium "" "$HOME_DIR/.npmrc" s12.npm_ignore_scripts
  hit=0; host_enabled && [ "${PYTHONNOUSERSITE:-}" = "1" ] && hit=1
  home_rc_paths | grep_l 'PYTHONNOUSERSITE=1' | grep_q -v '^/dev/null$' && hit=1
  [ "$hit" -eq 1 ] && safe log.safe.pythonnousersite || medium "" "" s12.pythonnousersite
  hit=0; host_enabled && [ "${PIP_REQUIRE_VIRTUALENV:-}" = "true" ] && hit=1
  home_rc_paths | grep_l 'PIP_REQUIRE_VIRTUALENV=(true|1)' | grep_q -v '^/dev/null$' && hit=1
  for f in "$HOME_DIR/.config/pip/pip.conf" "$HOME_DIR/.pip/pip.conf" "$HOME_DIR/Library/Application Support/pip/pip.conf"; do
    [ -f "$f" ] && fgrep_q '^[[:space:]]*require-virtualenv[[:space:]]*=[[:space:]]*(true|1)' "$f" && hit=1
  done
  [ "$hit" -eq 1 ] && safe log.safe.pip_require_virtualenv || medium "" "" s12.pip_require_virtualenv
  return 0
}

# §13 Honeypots (atime monitoring design guidelines, warning when noatime disables it)
check_s13() {
  log_section "§13"
  log_info log.honeypot_tip
  if host_enabled && command -v mount >/dev/null 2>&1; then
    if mount 2>/dev/null | grep -E "[[:space:]]on[[:space:]]+(/|/home|/Users|$HOME_DIR)[[:space:]]" | grep_q 'noatime'; then
      medium "" "$HOME_DIR" s13.noatime
    else
      safe log.safe.atime
    fi
  fi
  return 0
}

# §14 Blast Radius (existence only; only size and mtime via stat)
blast_list() {
  local key="$1" p e
  while IFS= read -r p; do
    e="$(expand_home "$p")"; e="${e%/}"
    [ -e "$e" ] || continue
    local sz mt
    sz="$(stat_size "$e")"; mt="$(stat_mtime "$e")"
    info "" "$e" s14.secret_store mtime="${mt:-?}" size="${sz:-?}"
  done < <(read_ioc ".blast_radius.$key")
}
check_s14() { log_section "§14"; blast_list base; return 0; }

# =============================================================================
# §15-§19 (v4.0)
# =============================================================================

# §15 Worm-type supply chain
check_s15() {
  log_section "§15"
  local f n h
  # preinstall: "node setup.mjs"
  local pre; pre="$(read_ioc '.worm_iocs.chaindrop.preinstall')"
  files_named '^package\.json$' | grep_lF "$pre" | while IFS= read -r f; do
    [ -n "$f" ] && [ "$f" != /dev/null ] && critical "chaindrop-keyv" "$f" s15.preinstall hook="$pre"
  done
  # Malicious files themselves (hash match is CRITICAL, name match is HIGH/MEDIUM)
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
        critical "$camp" "$f" s15.worm_hash name="$n"
      elif [ "$n" = "setup.mjs" ]; then
        local pj; pj="$(dirname -- "$f")/package.json"
        if [ -f "$pj" ] && fgrep_q 'setup\.mjs' "$pj"; then high "$camp" "$f" s15.worm_setup; fi
      else
        high "$camp" "$f" s15.worm_file name="$n"
      fi
    done < <(files_named "^$(printf '%s' "$n" | sed 's/\./\\./g')\$")
  done < <(read_ioc '.malicious_files' | grep -E '\.(m?js)$')
  # Lockfile matching (campaign-aware)
  check_lockfile_versions
  # TanStack malicious Git dependencies
  files_named '^(package\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$' | grep_lF 'github:tanstack/router#79ac49ee' | while IFS= read -r f; do
    [ -n "$f" ] && [ "$f" != /dev/null ] && critical "teampcp-mini-shai-hulud" "$f" s15.tanstack_git
  done
  # Traces of fetching Bun (lifecycle scripts, loaders)
  files_path '(/package\.json|\.m?js|\.cjs|\.sh)$' | grep_l '(bun\.sh/install|oven-sh/bun/releases/download)' | while IFS= read -r f; do
    [ -n "$f" ] && [ "$f" != /dev/null ] && high "teampcp-mini-shai-hulud" "$f" s15.bun_fetch
  done
  # site-packages/*/__init__.py droppers
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    fgrep_q '(exec|eval)\(' "$f" && fgrep_q '(b64decode|zlib\.decompress|marshal\.loads|bytes\.fromhex)' "$f" \
      && high "pypi-oct2026" "$f" s15.init_dropper
  done < <(files_path '/(site|dist)-packages/[^/]+/__init__\.py$')
  [ -d "$ROOT" ] && files_path '/(site|dist)-packages/lightning/_runtime/' | head -n1 | while IFS= read -r f; do
    [ -n "$f" ] && critical "pypi-oct2026" "$(dirname -- "$f")" s15.lightning_runtime
  done
  # IronWorm / sckit / Miasma binary names
  while IFS= read -r n; do
    [ -n "$n" ] || continue
    while IFS= read -r f; do [ -n "$f" ] && critical "post-shaihulud" "$f" s15.worm_binary name="$n"; done < <(files_named "^$(printf '%s' "$n" | sed 's/\./\\./g')\$")
  done < <(read_ioc '.worm_iocs.post_shaihulud.binaries')
  intel_files
  return 0
}

# §16 CI/CD infrastructure RCE (TeamCity / Artifactory / Docker cp)
check_s16() {
  log_section "§16"
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
    if [ "$ver" = "latest" ]; then medium "" "$f" s16.teamcity_latest fixed="${tc_fixed[*]}"; continue; fi
    if version_branch_vulnerable "$ver" "${tc_fixed[@]}"; then
      critical "" "$f" s16.teamcity_vulnerable fixed="${tc_fixed[*]}" version="$ver" --x="$(x_kind runtime.cve)"
    else
      safe log.safe.teamcity_fixed path="$f" version="$ver"
    fi
  done < <(detect_service_version 'jetbrains/teamcity-server')
  while IFS=$'\t' read -r ver f; do
    [ -n "$ver" ] || continue
    if [ "$ver" = "latest" ]; then medium "" "$f" s16.artifactory_latest; continue; fi
    if version_branch_vulnerable "$ver" "${af_fixed[@]}"; then
      critical "" "$f" s16.artifactory_vulnerable fixed="${af_fixed[*]}" version="$ver" --x="$(x_kind runtime.cve)"
    else
      safe log.safe.artifactory_fixed path="$f" version="$ver"
    fi
  done < <(detect_service_version 'jfrog/artifactory-(pro|oss|jcr)|releases-docker\.jfrog\.io/jfrog/artifactory-(pro|oss|jcr)')
  files_path '\.(sh|bash|ya?ml|mk|Makefile|py|js|ts)$|/Makefile$|/Dockerfile[^/]*$' | grep_l 'docker[[:space:]]+(container[[:space:]]+)?cp[[:space:]]' | while IFS= read -r f; do
    [ -n "$f" ] && [ "$f" != /dev/null ] && medium "" "$f" s16.docker_cp
  done
  intel_infra
  return 0
}

# §17 MCP static poisoning (command/args, SymJack, agent hooks, setup.mjs references)
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
# Convert JSONC (.vscode/mcp.json etc. officially allow comments and trailing commas) to JSON
#   Removes // line comments, /* */ block comments and commas right before a closing bracket outside strings (strings are kept as is)
jsonc_to_json() {
  awk 'BEGIN { RS = "\001" }
    NR == 1 { sub(/^\357\273\277/, "") }   # UTF-8 BOM (accepted by the VS Code JSONC parser)
    { n = length($0); ins = 0; esc = 0; pc = 0
      for (i = 1; i <= n; i++) {
        ch = substr($0, i, 1)
        if (ins) {
          if (esc) esc = 0; else if (ch == "\\") esc = 1; else if (ch == "\"") ins = 0
          printf "%s", ch; continue }
        # Comments are skipped with a loop (index(substr($0, i), …) would copy the rest of the file once per comment)
        if (ch == "/" && substr($0, i + 1, 1) == "/") {
          while (i < n && substr($0, i + 1, 1) != "\n") i++
          continue }
        if (ch == "/" && substr($0, i + 1, 1) == "*") {
          for (j = i + 2; j < n && substr($0, j, 2) != "*/"; j++) ;
          if (j >= n) { printf "%s", substr($0, i); i = n; continue }
          i = j + 1; printf " "; continue }
        if (ch ~ /[ \t\r\n]/) { printf "%s", ch; continue }
        if (pc) { if (ch != "}" && ch != "]") printf ","; pc = 0 }
        if (ch == ",") { pc = 1; continue }
        if (ch == "\"") ins = 1
        printf "%s", ch
      }
      if (pc) printf "," }' "$1" 2>/dev/null
}

# A TOML parser (no dependencies) that outputs the command/args of MCP servers from the .codex/config.toml of Codex CLI, one per line
#   Stage 1: tokenizes the whole file and outputs every value as: type US key path (\034-separated) US value.
#     Supports: table headers [a . "b" . 'c'] / [[array tables]], dotted keys (a.b.c = …, spaces allowed around them),
#           basic strings (decoding escapes such as \" \\ \n \uXXXX \UXXXXXXXX), literal strings,
#           multi-line strings (""" / '''), nested arrays (multi-line, comments and trailing commas allowed; ] / # inside strings are ignored),
#           inline tables (may nest), other scalars (numbers, booleans, dates/times)
#     Control characters in values (newlines, tabs etc. after decoding) are replaced by spaces (to match them as a single command line)
#   Stage 2: collects mcp_servers.<name>.command / .args / .url and outputs "command args…" per server.
#     args accepts both an array (per element) and a string (treated as one argument)
#   Places that cannot be parsed as syntax (invalid TOML, unknown escapes etc.) and servers whose command is not a string or that have neither command nor url
#   are reported with a "?<reason>" line, and the caller records them in errors[] (unreadable configs are not treated as 0 hits)
codex_toml_mcp_commands() {
  text_lines "$1" | awk "$ZES_AWK_LIB"'
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
    # Decode one character starting right after the backslash (i is the escape character)
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
    # Strings are collected as pieces in SP[1..sn] (runs of plain characters as one substr, then each decoded escape) and joined
    #   once at the end, so a long string costs linear time. A tab becomes a space; other control characters are an error
    function plain(c) { if (c < " " && c != "" && c != "\t") perr("control_character") }
    function piece(s) { if (i > s) SP[++sn] = substr(S, s, i - s) }
    function bstr(   c, s) {
      i++; sn = 0; s = i
      while (1) { if (i > n) perr("unterminated_string"); c = ch(0)
        if (c == "\"") { piece(s); i++; return zes_join(SP, sn) }
        if (c == "\n") perr("newline_in_string")
        if (c == "\\") { piece(s); i++; SP[++sn] = esc(); s = i; continue }
        plain(c); if (c == "\t") { piece(s); SP[++sn] = " "; s = i + 1 }
        i++ } }
    function lstr(   c, s) {
      i++; sn = 0; s = i
      while (1) { if (i > n) perr("unterminated_string"); c = ch(0)
        if (c == "\047") { piece(s); i++; return zes_join(SP, sn) }
        if (c == "\n") perr("newline_in_string")
        plain(c); if (c == "\t") { piece(s); SP[++sn] = " "; s = i + 1 }
        i++ } }
    # Multi-line string. q is the delimiter (" or \047). Up to 2 delimiter characters may appear right before the closing delimiter
    function mlstr(q,   c, k, j, s) {
      i += 3; if (ch(0) == "\n") { line++; i++ }
      sn = 0; s = i
      while (1) { if (i > n) perr("unterminated_string"); c = ch(0)
        if (c == q && ch(1) == q && ch(2) == q) {
          piece(s)
          k = 0; while (ch(k) == q) k++
          if (k > 5) perr("bad_multiline_string")
          for (j = 3; j < k; j++) SP[++sn] = q
          i += k; return zes_join(SP, sn) }
        if (c == "\\" && q == "\"") {
          piece(s)
          j = 1; while (ch(j) == " " || ch(j) == "\t") j++
          if (ch(j) == "\n") { i += j; while (i <= n && (ch(0) == " " || ch(0) == "\t" || ch(0) == "\n")) { if (ch(0) == "\n") line++; i++ }; s = i; continue }
          i++; SP[++sn] = esc(); s = i; continue }
        if (c == "\n") { piece(s); line++; SP[++sn] = " "; i++; s = i; continue }
        plain(c); if (c == "\t") { piece(s); SP[++sn] = " "; s = i + 1 }
        i++ } }
    # Read a key (dotted, quoted keys allowed) into KS[1..nk]
    function key(   nk, k, c, s) {
      nk = 0
      while (1) { skip_ws(); c = ch(0)
        if (c == "\"") { if (ch(1) == "\"" && ch(2) == "\"") perr("bad_key"); k = bstr() }
        else if (c == "\047") { if (ch(1) == "\047" && ch(2) == "\047") perr("bad_key"); k = lstr() }
        else { s = i; while (i <= n && ch(0) ~ /[A-Za-z0-9_-]/) i++; k = substr(S, s, i - s); if (k == "") perr("bad_key") }
        KS[++nk] = k; skip_ws()
        if (ch(0) == ".") { i++; continue }
        return nk } }
    function rec(t, p, v) { print t "\037" p "\037" v }
    # Arrays and inline tables nest at most 80 deep, the limit of the TOML parser of Codex CLI (toml 0.9 / toml_parser
    #   RecursionGuard, LIMIT = 80); deeper is a parse error (fail-closed, before mawk runs out of evaluation stack)
    function value(p,   c, t, idx, nk, kp, k, s) {
      c = ch(0)
      if ((c == "[" || c == "{") && ++depth > 80) perr("nesting_too_deep")
      if (c == "\"") { if (ch(1) == "\"" && ch(2) == "\"") t = mlstr("\""); else t = bstr(); rec("s", p, t); return }
      if (c == "\047") { if (ch(1) == "\047" && ch(2) == "\047") t = mlstr("\047"); else t = lstr(); rec("s", p, t); return }
      if (c == "[") {
        i++; idx = 0; rec("a", p, "")
        while (1) { skip_wsnl(); if (i > n) perr("unterminated_array")
          if (ch(0) == "]") { i++; depth--; return }
          value(p SUBSEP idx); idx++
          skip_wsnl(); c = ch(0)
          if (c == ",") { i++; continue }
          if (c == "]") { i++; depth--; return }
          perr("bad_array") } }
      if (c == "{") {
        i++; rec("t", p, ""); skip_wsnl()
        if (ch(0) == "}") { i++; depth--; return }
        while (1) { skip_wsnl(); nk = key(); kp = p; for (k = 1; k <= nk; k++) kp = kp SUBSEP KS[k]
          skip_ws(); if (ch(0) != "=") perr("bad_inline_table"); i++; skip_ws()
          value(kp); skip_wsnl(); c = ch(0)
          if (c == ",") { i++; continue }
          if (c == "}") { i++; depth--; return }
          perr("bad_inline_table") } }
      s = i; while (i <= n && ch(0) ~ /[A-Za-z0-9_+.:-]/) i++; t = substr(S, s, i - s)
      if (t ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/ && ch(0) == " " && ch(1) ~ /[0-9]/) { i++; while (i <= n && ch(0) ~ /[0-9:.Zz+-]/) i++ }
      if (t == "") perr("bad_value")
      rec("o", p, t) }
    BEGIN { RS = "\001" }
    { S = $0; n = length(S); i = 1; line = 1; tbl = ""; depth = 0
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
        value(p); eol() } }' | awk -F'\037' "$ZES_AWK_LIB"'
    /^\?/ { print; next }
    { np = split($2, P, "\034") }
    P[1] != "mcp_servers" { next }
    np == 1 { if ($1 != "t") print "?unexpected_value:mcp_servers"; next }
    { nm = P[2]; if (!(nm in seen)) { seen[nm] = 1; order[++no] = nm } }
    np == 2 { if ($1 != "t") print "?unexpected_value:" nm; next }
    P[3] == "command" && np == 3 { if ($1 == "s") cmd[nm] = $3; else bad[nm] = "unparsed_command"; next }
    P[3] == "args" {
      if ($1 == "s" && (np == 3 || np == 4)) { AG[nm, ++ag[nm]] = (agz[nm] ? " " : "") $3; if ($3 != "") agz[nm] = 1 }
      else if (!(np == 3 && $1 == "a")) bad[nm] = "unparsed_args"
      next }
    P[3] == "url" && np == 3 { hasurl[nm] = 1 }
    END {
      for (k = 1; k <= no; k++) { nm = order[k]
        # the args pieces of this server, joined once
        na = ag[nm] + 0; for (j = 1; j <= na; j++) T[j] = AG[nm, j]; a = agz[nm] ? zes_join(T, na) : ""
        if (cmd[nm] != "") print "=" nm "\037" cmd[nm] (a != "" ? " " a : "")
        if (nm in bad) print "?" bad[nm] ":" nm
        else if (cmd[nm] == "" && !(nm in hasurl)) print "?no_command:" nm } }'
}

# MCP / agent config command + args (one line, space-separated) that count as HIGH (case-insensitive)
#   curl / wget / base64, -c of shells (sh, bash, zsh, dash, ksh, fish, ash) (combined forms such as -xc, -lc; leading options such as --norc allowed),
#   -e, --eval, -p, --print of node / nodejs / bun, deno eval, -c of python (-Ic etc.), -e, -E of perl / ruby (-ne etc.),
#   php -r, -e of osascript / lua, -c, -Command, -e, -enc, -EncodedCommand of pwsh / powershell, cmd /c, /k
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
  log_section "§17"
  local f cmdline fmt ptr nm
  # One command per line: format US JSON pointer (location of the object that has command, e.g. /mcpServers/<name>) US command args…
  #   If command contains newlines, each line is matched separately (as before)
  local mcpq='path(.. | select(type == "object" and has("command"))) as $p
    | (if ($p | length) == 0 then "" else "/" + ($p | map(tostring | gsub("~"; "~0") | gsub("/"; "~1")) | join("/")) end) as $ptr
    | getpath($p) | ((.command | tostring) + " " + ((.args // []) | if type == "array" then map(tostring) | join(" ") else tostring end))
    | split("\n")[] | $fmt + "\u001f" + $ptr + "\u001f" + .'
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    local -a hi=() me=()
    local loc
    while IFS=$'\037' read -r fmt ptr cmdline; do
      # Without jq the pointer is unknown (loc is empty; the finding is emitted, locators are not)
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
        # If it cannot be read as strict JSON, reread it as JSONC (comments, trailing commas); if that also fails, errors[]
        jq -r --arg fmt json "$mcpq" "$f" 2>/dev/null \
          || jsonc_to_json "$f" | jq -r --arg fmt jsonc "$mcpq" 2>/dev/null \
          || record_error "§17" "mcp_config_parse_failed:$f"
      else
        # Without jq: join "command" and the "args" that follows it into one line (on separate lines "bash" and "-c" would not be linked).
        #   The location (pointer) is unknown, so locators are not emitted
        tr '\n' ' ' <"$f" 2>/dev/null | grep -E -o '"(command|args)"[[:space:]]*:[[:space:]]*("([^"\\]|\\.)*"|\[[^]]*\])' | awk '
          { v = $0; sub(/^"[a-z]+"[[:space:]]*:[[:space:]]*/, "", v); gsub(/^\[|\]$/, "", v); gsub(/"[[:space:]]*,[[:space:]]*"/, " ", v); gsub(/^[[:space:]]*"|"[[:space:]]*$/, "", v)
            if ($0 ~ /^"command"/) { if (cur != "") print "json\037\037" cur; cur = v } else cur = cur " " v }
          END { if (cur != "") print "json\037\037" cur }'
      fi)
    # Issues of the same kind in the same file are merged into one finding, listing the matching servers in locators (findings 1.1;
    #   each pointer only once; lines split at a newline in command point to the same server)
    if [ "${#hi[@]}" -gt 0 ]; then
      high "mcp-poisoning" "$f" s17.dangerous_command \
        --x="$(x_join "$(x_kind mcp.dangerous_command)" "$(x_locators "$(printf '%s\n' "${hi[@]}" | awk 'NF && !seen[$0]++' | paste -sd, -)")")"
    fi
    if [ "${#me[@]}" -gt 0 ]; then
      medium "mcp-poisoning" "$f" s17.npx \
        --x="$(x_join "$(x_kind mcp.unpinned)" "$(x_locators "$(printf '%s\n' "${me[@]}" | awk 'NF && !seen[$0]++' | paste -sd, -)")")"
    fi
  done < <(mcp_config_files | sort -u)
  # SymJack: a symlink pointing to an agent config / decoy names
  local l t base
  while IFS= read -r l; do
    [ -n "$l" ] || continue
    t="$(readlink -- "$l" 2>/dev/null)"
    base="${l#"$RP"/}"
    if printf '%s' "$t" | grep_q -E '(\.claude/|\.mcp\.json|\.cursor/|\.gemini/|\.codex/|\.vscode/settings\.json)'; then
      critical "mcp-poisoning" "$l" s17.symjack target="$t"
    elif printf '%s' "$base" | grep_q -i -E '(^|/)(vid-|logo\.|readme\.)|^docs/' && [[ "$t" == ../* || "$t" == /* ]]; then
      high "mcp-poisoning" "$l" s17.symjack_decoy target="$t"
    fi
  done <"$LINKS_LIST"
  # Agent hooks (network access/obfuscation in the hooks of .claude/settings.json)
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if fgrep_q '"hooks"[[:space:]]*:' "$f" && fgrep_q '"command"[[:space:]]*:[[:space:]]*"[^"]*(curl|wget|base64|nc |/dev/tcp)' "$f"; then
      high "mcp-poisoning" "$f" s17.agent_hook \
        --x="$(x_locators "$(json_ptr_locators "$f" "$HOOK_PATHS_RE" --arg re '(curl|wget|base64|nc |/dev/tcp)')")"
    fi
  done < <(files_path '/\.(claude|cursor|gemini)/(settings(\.local)?|hooks)\.json$')
  # References to .claude/.vscode/.cursor in setup.mjs
  files_named '^setup\.mjs$' | grep_l '\.(claude|vscode|cursor)(/|\b)' | while IFS= read -r f; do
    [ -n "$f" ] && [ "$f" != /dev/null ] && critical "chaindrop-keyv" "$f" s17.setup_mjs
  done
  return 0
}

# §18 Network IoCs (C2 domains/IPs, history)
# network_iocs [all] … match string<TAB>campaign<TAB>kind (malicious / legit)
#   By default only malicious ones. With all, abused legitimate infrastructure (legit_infra) is included too
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
  log_section "§18"
  network_iocs all >"$TMP_DIR/netioc.tsv"
  awk -F'\t' '$3=="malicious"{print $1}' "$TMP_DIR/netioc.tsv" >"$TMP_DIR/netioc.pat"
  awk -F'\t' '$3=="legit"{print $1}' "$TMP_DIR/netioc.tsv" >"$TMP_DIR/netioc-legit.pat"
  [ -s "$TMP_DIR/netioc.pat" ] || { record_error "§18" "ioc_empty"; return 0; }
  local f hit camp pat
  for pat in netioc netioc-legit; do
    [ -s "$TMP_DIR/$pat.pat" ] || continue
    # Domains are case-insensitive (NPM-CACHE.COM etc. cannot evade matching). The displayed matched string is lowercased
    grep -v -E '/\.(zsh|bash)_history$' "$FILES_LIST" | tr '\n' '\0' | xargs -0 grep -l -a -i -F -f "$TMP_DIR/$pat.pat" -- /dev/null 2>/dev/null | grep -v '^/dev/null$' | while IFS= read -r f; do
      hit="$(grep -o -a -i -F -f "$TMP_DIR/$pat.pat" -- "$f" 2>/dev/null | tr 'A-Z' 'a-z' | sort -u | head -n3 | tr '\n' ' ')"
      camp="$(grep -i -F -- "$(printf '%s' "$hit" | awk '{print $1}')" "$TMP_DIR/netioc.tsv" | head -n1 | cut -f2)"
      if [ "$pat" = "netioc" ]; then
        critical "$camp" "$f" s18.network_ioc iocs="${hit% }"
      else
        medium "$camp" "$f" s18.legit_infra iocs="${hit% }"
      fi
    done
  done
  local hf
  for hf in "$HOME_DIR/.zsh_history" "$HOME_DIR/.bash_history"; do
    [ -f "$hf" ] && [ ! -L "$hf" ] || continue
    grep -q -a -i -F -f "$TMP_DIR/netioc.pat" -- "$hf" 2>/dev/null && critical "" "$hf" s18.history_c2
    tail -n 5 -- "$hf" 2>/dev/null | grep_q -E '(curl|wget)[^|]*\|[[:space:]]*(ba|z)?sh' && high "" "$hf" s18.history_curl_sh
  done
  return 0
}

# §19 Blast Radius extensions
check_s19() { log_section "§19"; blast_list extended; return 0; }

# =============================================================================
# §20-§35 (v4.1)
# =============================================================================

# Files that look like MCP server implementations or tool definitions
mcp_source_files() {
  files_path '\.(json|js|mjs|cjs|ts|py)$' | ZES_RP="$RP" awk 'BEGIN { rp = ENVIRON["ZES_RP"] "/" } { r = (index($0, rp) == 1) ? substr($0, length(rp)) : $0 } r !~ /\/node_modules\/(typescript|@types)\//' \
    | grep_l '(inputSchema|mcpServers|@modelcontextprotocol|FastMCP|mcp\.server|"tools"[[:space:]]*:)'
}

# §20 MCP semantics (Deadbugz / NeighborJack / imperative + external reference)
check_s20() {
  log_section "§20"
  local f
  mcp_source_files >"$TMP_DIR/mcpsrc.lst"
  grep_l '(ignore (all |any )?(the )?previous instructions|do not tell the user|don'"'"'t tell the user|without (telling|informing) the user)' -i <"$TMP_DIR/mcpsrc.lst" | while IFS= read -r f; do
    [ -n "$f" ] && high "mcp-poisoning" "$f" s20.prompt_injection
  done
  grep_l '"description"[[:space:]]*:[[:space:]]*"[^"]*\b(execute|run|send|upload|fetch|download|must call|always call)\b[^"]*(https?://|curl|wget|~/\.|\.ssh|\.env)' -i <"$TMP_DIR/mcpsrc.lst" | while IFS= read -r f; do
    [ -n "$f" ] && high "mcp-poisoning" "$f" s20.imperative_external
  done
  grep_l '(callCount|invocations?|callCounter|numCalls|count)[[:space:]]*(>|>=)[[:space:]]*[0-9]+' <"$TMP_DIR/mcpsrc.lst" | while IFS= read -r f; do
    [ -n "$f" ] && high "mcp-poisoning" "$f" s20.deadbugz
  done
  local nre; nre="$(read_ioc '.mcp_poisoning.neighbor.internal_ip_regex')"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    grep -q -E "\"(url|serverUrl|endpoint)\"[[:space:]]*:[[:space:]]*\"https?://${nre}" "$f" 2>/dev/null \
      && medium "mcp-poisoning" "$f" s20.neighborjack
    grep -q -E '"(url|serverUrl)"[[:space:]]*:[[:space:]]*"http://' "$f" 2>/dev/null \
      && grep -E -o '"(url|serverUrl)"[[:space:]]*:[[:space:]]*"http://[^"]+' "$f" | grep_q -v -E 'http://(localhost|127\.0\.0\.1|\[::1\])' \
      && medium "mcp-poisoning" "$f" s20.plain_http
    grep -q -E '"(host|bind|listen)"[[:space:]]*:[[:space:]]*"0\.0\.0\.0"|--host[ =]0\.0\.0\.0' "$f" 2>/dev/null \
      && medium "mcp-poisoning" "$f" s20.listen_all
  done < <(mcp_config_files | sort -u)
  intel_strings
  return 0
}

# List of GitHub Actions workflows
workflow_files() { files_path '/\.github/workflows/[^/]+\.ya?ml$'; }
# Normalization of the workflow body (strip CRLF and BOM, expand YAML node properties and flow sequences, fold keys whose value continues on later lines into one line)
#   Stage 1 (yaml_flatten):
#   - remove node properties (anchors &x, tags !!str / !tag) from the start of values and of sequence items ("uses: &co actions/checkout@v4")
#   - expand flow sequences ("steps: [ {uses: a}, {uses: b, with: {ref: …}} ]", including ones spanning several lines) into
#     block sequences with one element per line ("  - {uses: a}")
#   - aliases ("*x" / "<<: *x") are not resolved, so a "#ZES-YAML-ALIAS" line is emitted (the caller records it in errors[])
#   - the contents of block scalars (run: | etc.) are passed through as is
#   Stage 2:
#   - block scalars ("key: >-" / "key: |" etc.): join all following lines with deeper indentation, separated by spaces
#   - when a plain scalar follows a key with an empty value (the value on the line after "- uses:"): join the following lines that are
#     deeper and not a mapping/sequence (multi-line folding of YAML plain scalars)
#   uses: >-                              - uses:
#     actions/checkout@v4   → uses: actions/checkout@v4      actions/checkout@v4 → - uses: actions/checkout@v4
# Awk helpers shared by the YAML / TOML / JSONC readers below. Every reader is linear in the input size: text is accumulated as
#   pieces in an array and joined pairwise once (zes_join), never appended to a growing string per line or per character.
#   Patterns that mawk matches in quadratic time on a long run of blanks (unanchored /[ \t]+$/, /[[:space:]]*(#.*)?$/ and two
#   adjacent blank stars) are written as loops. tests/run-tests.sh times the readers on 1 MB adversarial inputs
ZES_AWK_LIB='
    function zes_join(A, n,   m, k) {
      if (n < 1) return ""
      while (n > 1) { m = 0; for (k = 1; k <= n; k += 2) A[++m] = (k < n) ? A[k] A[k + 1] : A[k]; n = m }
      return A[1] }
    # zes_rtrim(x, set): x without the trailing characters that are in set (sub(/[ \t]+$/, "") without the regex)
    function zes_rtrim(x, set,   n) {
      n = length(x)
      while (n > 0 && index(set, substr(x, n, 1))) n--
      return substr(x, 1, n) }
'
yaml_flatten() {
  text_lines "$1" | awk "$ZES_AWK_LIB"'
    function lead(x) { match(x, /^[ \t]*/); return RLENGTH }
    # Node properties at the start of a value, all of them in one match (a loop of single matches would copy the rest of the
    #   value once per property)
    function props(v) { if (match(v, /^((&[^ \t]+|![^ \t]*)([ \t]+|$))+/)) v = substr(v, RLENGTH + 1); return v }
    function isalias(v) { return v ~ /^\*[^ \t,\]}]+[ \t]*(#.*)?$/ }
    # Bracket depth outside quotes ([ { and ] }) of the flow collection being accumulated, updated incrementally with the text
    #   appended to it (state: fd depth, fq open quote, fesc escaped character pending, fstop a comment was reached, fprev the
    #   previous character)
    function dscan(x,   i, c, n) {
      n = length(x)
      for (i = 1; i <= n && !fstop; i++) { c = substr(x, i, 1)
        if (fesc) { fesc = 0; fprev = c; continue }
        if (fq != "") { if (c == "\\" && fq == "\"") fesc = 1; else if (c == fq) fq = ""; fprev = c; continue }
        if (c == "\"" || c == "\047") { fq = c; fprev = c; continue }
        if (c == "#" && (fprev == "" || fprev == " " || fprev == "\t")) { fstop = 1; break }
        if (c == "[" || c == "{") fd++; else if (c == "]" || c == "}") fd--
        fprev = c } }
    # Remove end-of-line comments outside quotes (space + #)
    function nocomment(x,   i, c, q, n) {
      q = ""; n = length(x)
      for (i = 1; i <= n; i++) { c = substr(x, i, 1)
        if (q != "") { if (c == "\\" && q == "\"") { i++; continue } if (c == q) q = ""; continue }
        if (c == "\"" || c == "\047") { q = c; continue }
        if (c == "#" && (i == 1 || substr(x, i - 1, 1) ~ /[ \t]/)) return substr(x, 1, i - 1) }
      return x }
    function item(el, ind) {
      sub(/^[ \t]+/, "", el); el = zes_rtrim(el, " \t"); if (el == "") return
      el = props(el); if (isalias(el)) print "#ZES-YAML-ALIAS"
      print ind "- " el }
    # Output the top-level elements of "[ a, {b: c}, … ]" one per line
    function flow(body, ind,   i, c, q, d, s, n) {
      sub(/^[ \t]*\[/, "", body)
      # the closing "]" (the first one followed only by blanks and a comment)
      if (match(body, /\][ \t]*#/)) body = substr(body, 1, RSTART - 1); else if (match(body, /\][ \t]*$/)) body = substr(body, 1, RSTART - 1)
      d = 0; q = ""; s = 1; n = length(body)
      for (i = 1; i <= n; i++) { c = substr(body, i, 1)
        if (q != "") { if (c == "\\" && q == "\"") { i++; continue } if (c == q) q = ""; continue }
        if (c == "\"" || c == "\047") { q = c; continue }
        if (c == "[" || c == "{") d++; else if (c == "]" || c == "}") d--
        if (c == "," && d == 0) { item(substr(body, s, i - s), ind); s = i + 1 } }
      item(substr(body, s), ind) }
    function flowend(   body) { body = zes_join(FP, fn); fn = 0; inflow = 0; print apre; flow(body, sprintf("%" (aind + 2) "s", "")) }
    function value(pre, v, keyind) {
      v = props(v)
      if (isalias(v) || pre ~ /<<:[ \t]*$/) print "#ZES-YAML-ALIAS"
      if (v ~ /^[|>][-+0-9]*[ \t]*(#.*)?$/) { print pre v; inblk = 1; bind = keyind; return }
      if (v ~ /^\[/) {
        fd = 0; fq = ""; fesc = 0; fstop = 0; fprev = ""; dscan(v)
        if (fd > 0) { fn = 0; FP[++fn] = nocomment(v); inflow = 1; apre = pre; aind = keyind
          # dscan(v) and dscan(nocomment(v)) end in the same state except for fstop (the comment that nocomment removed)
          fd = 0; fq = ""; fesc = 0; fstop = 0; fprev = ""; dscan(FP[1]); return }
        print pre; flow(v, sprintf("%" (keyind + 2) "s", "")); return }
      print pre v }
    {
      line = $0
      if (inblk) { if (line ~ /^[ \t]*$/ || lead(line) > bind) { print line; next } inblk = 0 }
      if (inflow) {
        t = nocomment(line); sub(/^[ \t]+/, "", t); t = " " t; FP[++fn] = t; dscan(t)
        if (fd <= 0) flowend()
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
    END { if (inflow) flowend() }'
}
workflow_text() {
  yaml_flatten "$1" | awk "$ZES_AWK_LIB"'
    # The unanchored /[[:space:]]*…$/ patterns of this stage are written as loops (mawk is quadratic on long blank runs there)
    function isws(c) { return c != "" && index(" \t\n\v\f\r", c) }
    # sub(/[[:space:]]*(#.*)?$/, "", x)
    function cutc(x,   h) { h = index(x, "#"); if (h == 0) return zes_rtrim(x, " \t\n\v\f\r"); return zes_rtrim(substr(x, 1, h - 1), " \t\n\v\f\r") }
    # sub(/[[:space:]]+#.*$/, "", x)
    function cutsc(x,   i, n) { n = length(x); for (i = 2; i <= n; i++) if (substr(x, i, 1) == "#" && isws(substr(x, i - 1, 1))) return zes_rtrim(substr(x, 1, i - 1), " \t\n\v\f\r"); return x }
    # x ~ /^[[:space:]]*(-[[:space:]]+)?["\047]?[A-Za-z0-9_.$-]+["\047]?:[[:space:]]*([>|][-+0-9]*)?[[:space:]]*(#.*)?$/
    function keyline(x,   r) {
      if (!match(x, /^[[:space:]]*(-[[:space:]]+)?["\047]?[A-Za-z0-9_.$-]+["\047]?:/)) return 0
      r = substr(x, RLENGTH + 1); sub(/^[[:space:]]+/, "", r)
      if (match(r, /^[>|][-+0-9]*/)) { r = substr(r, RLENGTH + 1); sub(/^[[:space:]]+/, "", r) }
      return r == "" || substr(r, 1, 1) == "#" }
    function flush() { print pend (anz ? " " zes_join(AP, an) : ""); pend = ""; an = 0; anz = 0 }
    pend != "" {
      if ($0 ~ /^[[:space:]]*$/ || (!blk && $0 ~ /^[[:space:]]*#/)) next
      match($0, /^[[:space:]]*/)
      if (RLENGTH > pind && (blk || $0 !~ /^[[:space:]]*(-([[:space:]]|$)|["\047]?[A-Za-z0-9_.$-]+["\047]?:([[:space:]]|$))/)) {
        v = $0; sub(/^[[:space:]]+/, "", v); if (!blk) v = cutsc(v); v = zes_rtrim(v, " \t\n\v\f\r")
        AP[++an] = (anz ? " " : "") v; if (v != "") anz = 1; next }
      flush()
    }
    keyline($0) {
      match($0, /^[[:space:]]*/); pind = RLENGTH
      if ($0 ~ /^[[:space:]]*-[[:space:]]/) { t = $0; sub(/^[[:space:]]*-[[:space:]]+/, "", t); pind = length($0) - length(t) - 1 }
      pend = cutc($0)
      blk = (pend ~ /:[[:space:]]*[>|][-+0-9]*$/)
      # sub(/[[:space:]]*[>|][-+0-9]*$/, "", pend)
      if (blk) { n = length(pend); while (n > 0 && index("-+0123456789", substr(pend, n, 1))) n--; pend = zes_rtrim(substr(pend, 1, n - 1), " \t\n\v\f\r") }
      an = 0; anz = 0; next
    }
    { print }
    END { if (pend != "") flush() }'
}

# §21 GitHub Actions dangerous patterns
check_s21() {
  log_section "§21"
  local f
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    # Expression context names are case-insensitive (${{ SECRETS.X }} / ${{ toJSON(secrets) }} / secrets['X'] are also secrets references)
    yaml_flatten "$f" | grep_q -x -F '#ZES-YAML-ALIAS' && record_error "§21" "yaml_alias_unresolved:$f"
    if fgrep_q '(^|[^A-Za-z0-9_])pull_request_target([^A-Za-z0-9_]|$)' "$f" && fgrep_q -i 'actions/checkout@' "$f" && fgrep_q -i '\$\{\{([^}]*[^A-Za-z0-9_.])?secrets([].[[:space:])]|$)' "$f"; then
      # For each actions/checkout step, determine whether ref is set and what it points to
      local refs
      refs="$(awk '
        function flush(){ if (inchk) { print (ref=="" ? "noref" : ref) } inchk=0; ref="" }
        # ref is looked up both in block mappings (ref: at line start) and flow mappings ({ ref: … } / , ref: …)
        function getref(s,   r, q, k) {
          if (!match(s, /^[[:space:]]*ref:/) && !match(s, /[{,][[:space:]]*ref:/)) return
          r = substr(s, RSTART + RLENGTH); sub(/^[[:space:]]*/, "", r)
          if (r ~ /^["\047]/) { q = substr(r, 1, 1); r = substr(r, 2); k = index(r, q); if (k) r = substr(r, 1, k - 1) }
          else sub(/[,}].*$/, "", r)
          # Normalization: lowercase, remove spaces, convert subscript notation (github.event['"'"'pull_request'"'"']['"'"'head'"'"'] / ["…"]) to dot notation
          r = tolower(r); gsub(/[ \t]/, "", r); gsub(/\[["\047]/, ".", r); gsub(/["\047]\]/, "", r)
          # If only base-side expressions (base.sha / base.ref / base_ref / github.sha / github.ref / default_branch), it does not come from the PR
          t = r; gsub(/\$\{\{(github\.event\.pull_request\.base\.(sha|ref)|github\.base_ref|github\.sha|github\.ref|github\.event\.repository\.default_branch)\}\}/, "", t)
          if (r ~ /github\.(event\.pull_request\.(head|merge_commit_sha|number)|head_ref|event\.number)|refs\/pull\//) ref = "prhead"
          else if (index(t, "${{")) ref = "exprref"     # a ref determined by any other expression cannot be confirmed as not coming from the PR (at least HIGH)
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
        critical "ghostaction-oct2026" "$f" s21.pwn_request --x="$(x_kind gha.pwn_request)"
      fi
      if printf '%s\n' "$refs" | grep_q -x 'noref'; then
        high "ghostaction-oct2026" "$f" s21.prt_checkout_base --x="$(x_kind gha.pwn_request)"
      fi
      if printf '%s\n' "$refs" | grep_q -x 'exprref'; then
        high "ghostaction-oct2026" "$f" s21.prt_checkout_expr --x="$(x_kind gha.pwn_request)"
      fi
    fi
    fgrep_q 'key:.*github\.event\.pull_request\.number' "$f" && high "ghostaction-oct2026" "$f" s21.cache_pr_key
    fgrep_q '^[[:space:]]*permissions:[[:space:]]*write-all' "$f" && high "ghostaction-oct2026" "$f" s21.write_all
  done < <(workflow_files)
  return 0
}

# §22 Action SHA pinning
check_s22() {
  log_section "§22"
  local f line act ref
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    workflow_text "$f" | grep -E -o '^[[:space:]-]*(\{([^}#]*,)?[[:space:]]*)?uses:[[:space:]]*["'"'"']?[^"'"'"'[:space:]#,}]+' 2>/dev/null | sed -E 's/.*uses:[[:space:]]*["'"'"']?//' | sort -u | while IFS= read -r line; do
      case "$line" in ./*|docker://*) continue ;; esac
      act="${line%@*}"; ref="${line##*@}"; act="${act,,}"
      [ "$act" != "$line" ] || { high "ghostaction-oct2026" "$f" s22.no_version ref="$line" --x="$(x_kind gha.unpinned)"; continue; }
      if [ "$act" = "aquasecurity/trivy-action" ] && ! [[ "$ref" =~ ^[0-9a-f]{40}$ ]] && [ "$ref" != "v0.35.0" ]; then
        critical "ghostaction-oct2026" "$f" s22.poisoned_tag ref="$line" --x="$(x_kind gha.unpinned)"
      elif [[ "$ref" =~ ^[0-9a-f]{40}$ ]]; then
        case "$act" in tj-actions/*|aquasecurity/*) medium "ghostaction-oct2026" "$f" s22.risky_publisher_sha action="$act" ;; esac
      else
        case "$act" in
          tj-actions/*|aquasecurity/*) critical "ghostaction-oct2026" "$f" s22.risky_publisher_tag ref="$line" --x="$(x_kind gha.unpinned)" ;;
          *) high "ghostaction-oct2026" "$f" s22.unpinned ref="$line" --x="$(x_kind gha.unpinned)" ;;
        esac
      fi
    done
    if grep -q -E "(trivy-version|version):[[:space:]]*[\"']?v?0\.69\.4[\"']?[[:space:]]*$" "$f" 2>/dev/null && grep -q 'trivy' "$f"; then
      critical "ghostaction-oct2026" "$f" s22.trivy_version
    fi
  done < <(workflow_files; files_path '/action\.ya?ml$')
  local ver
  while IFS=$'\t' read -r ver f; do
    [ "${ver#v}" = "0.69.4" ] && critical "ghostaction-oct2026" "$f" s22.trivy_image
  done < <(detect_service_version 'aquasec/trivy')
  intel_actions
  return 0
}

# §23 Container runtimes (CopyEscape / Copy Fail / privileged containers)
check_s23() {
  log_section "§23"
  if host_enabled; then
    local dv kv
    # docker version connects to the daemon (DOCKER_HOST / context; starts ssh for ssh://), so it is not used;
    # docker --version, which completes in the client alone, is read instead
    dv="$(safe_probe docker --version | grep -o -E '[0-9]+\.[0-9]+\.[0-9]+[^ ,]*' | head -n1)"
    if [ -n "$dv" ]; then
      local dfix; dfix="$(infra_fixed docker CVE-2026-17106 | head -n1)"
      if [ -z "$dfix" ]; then medium "" "$(command -v docker)" s23.docker_unknown_fix version="$dv"
      elif version_lt "${dv%%-*}" "$dfix"; then high "" "$(command -v docker)" s23.docker_vulnerable fixed="$dfix" version="$dv"
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
          high "" "/proc/version" s23.kernel_old cve="$cve" fixed="${kfix[*]}" version="$kv"
        fi
      done
    fi
  fi
  local f
  files_named '\.(ya?ml)$' | grep_l '^[[:space:]]*privileged:[[:space:]]*true' | while IFS= read -r f; do
    [ -n "$f" ] && high "" "$f" s23.privileged
  done
  files_named '\.(ya?ml)$' | grep_l '(cap_add:|add:)[^#]*(SYS_ADMIN|ALL)|- (SYS_ADMIN|ALL)$' | while IFS= read -r f; do
    [ -n "$f" ] && high "" "$f" s23.capabilities
  done
  intel_tool_versions
  return 0
}

# List of browser extension manifests (watched paths under home + Extensions/*/manifest.json inside ROOT)
extension_manifests() {
  files_path '/Extensions/[^/]+/([^/]+/)?manifest\.json$'
  local p e d
  while IFS= read -r p; do
    e="$(expand_home "$p")"
    # Do not split paths containing spaces (~/Library/Application Support/…); expand glob characters only
    local IFS=$'\n'
    for d in $e; do
      [ -d "$d" ] || continue
      find "$d" -maxdepth 3 -name manifest.json -type f 2>/dev/null | qstore_filter "$d"
    done
    unset IFS
  done < <(read_ioc '.browser_extensions.watch_paths.mac'; read_ioc '.browser_extensions.watch_paths.linux')
  return 0
}

# §24 Browser extensions (update_url / dangerous permissions / <all_urls>)
check_s24() {
  log_section "§24"
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
      high "" "$f" s24.update_url
    fi
    local p found=""
    for p in "${dperm[@]}"; do printf '%s\n' "$perms" | grep_q -x -F -- "$p" && found="$found $p"; done
    local all=0; printf '%s\n' "$perms" | grep_q -x -F -- '<all_urls>' && all=1
    if [ -n "$found" ] && [ "$all" -eq 1 ]; then high "" "$f" s24.perms_all_urls permissions="${found# }"
    elif [ -n "$found" ]; then medium "" "$f" s24.perms permissions="${found# }"
    elif [ "$all" -eq 1 ]; then medium "" "$f" s24.all_urls
    fi
  done < <(extension_manifests | sort -u)
  return 0
}

# §25 Follow-on worms (IronWorm / sckit / Miasma / cargo-install impersonation)
check_s25() {
  log_section "§25"
  local n d
  local -a bins; mapfile -t bins < <(read_ioc '.worm_iocs.post_shaihulud.binaries')
  for d in "$HOME_DIR/.cargo/bin" "$HOME_DIR/.local/bin" "$HOME_DIR/go/bin" "$HOME_DIR/.bun/bin" /usr/local/bin /tmp /var/tmp /dev/shm; do
    [ -d "$d" ] || continue
    case "$d" in /usr/local/bin|/tmp|/var/tmp|/dev/shm) host_enabled || continue ;; esac
    for n in "${bins[@]}"; do [ -e "$d/$n" ] && critical "post-shaihulud" "$d/$n" s25.worm_binary name="${n}"; done
    [ -e "$d/cargo-install" ] && high "post-shaihulud" "$d/cargo-install" s25.cargo_install_binary
  done
  local f; while IFS= read -r f; do [ -n "$f" ] && high "post-shaihulud" "$f" s25.cargo_install_file; done < <(files_named '^cargo-install(\.exe)?$')
  if host_enabled && [ -f "$TMP_DIR/ps.txt" ]; then
    grep -E '(^|/| )cargo-install( |$)' "$TMP_DIR/ps.txt" | awk '{print $1}' | while IFS= read -r pid; do
      high "post-shaihulud" "/proc/$pid" s25.cargo_install_process pid="$pid"
    done
  fi
  return 0
}

# §26 Developer tool settings
check_s26() {
  log_section "§26"
  local f
  while IFS= read -r f; do
    [ -n "$f" ] && [ -f "$f" ] || continue
    fgrep_q -i '^[[:space:]]*fsmonitor[[:space:]]*=' "$f" && ! fgrep_q -i '^[[:space:]]*fsmonitor[[:space:]]*=[[:space:]]*(true|false)[[:space:]]*$' "$f" \
      && critical "" "$f" s26.fsmonitor \
        --x="$(TL_EXCLUDE='[[:space:]]*fsmonitor[[:space:]]*=[[:space:]]*(true|false)[[:space:]]*$' x_text_locators "$f" -i '^[[:space:]]*fsmonitor[[:space:]]*=')"
    fgrep_q -i '^[[:space:]]*sshCommand[[:space:]]*=' "$f" && high "" "$f" s26.ssh_command --x="$(x_text_locators "$f" -i '^[[:space:]]*sshCommand[[:space:]]*=')"
    fgrep_q -i '^[[:space:]]*hooksPath[[:space:]]*=' "$f" && medium "" "$f" s26.hooks_path --x="$(x_text_locators "$f" -i '^[[:space:]]*hooksPath[[:space:]]*=')"
  done < <(printf '%s\n' "$HOME_DIR/.gitconfig" "$HOME_DIR/.config/git/config"; cat "$GIT_CFG_LIST"; files_named '^\.gitconfig$')
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if fgrep_q '(curl|wget)[^|#]*\|[[:space:]]*(ba|z)?sh|eval[[:space:]]+"?\$\((curl|wget)' "$f"; then
      high "" "$f" s26.envrc_remote --x="$(x_text_locators "$f" '(curl|wget)[^|#]*\|[[:space:]]*(ba|z)?sh|eval[[:space:]]+"?\$\((curl|wget)')"
    fi
  done < <(files_named '^\.envrc$')
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    grep -E -o 'https?://[^"'"'"'[:space:]]+' "$f" 2>/dev/null | grep_q -v -E '^https://github\.com/(asdf-vm|asdf-community|mise-plugins|jdx)/' \
      && medium "" "$f" s26.plugin_url
  done < <(files_named '^(\.tool-versions|mise\.toml|\.mise\.toml)$')
  local -a regs; mapfile -t regs < <(read_ioc '.official_registries')
  local re; re="$(printf '%s|' "${regs[@]}" | sed 's/\./\\./g; s/|$//')"
  while IFS= read -r f; do
    [ -n "$f" ] && [ -f "$f" ] || continue
    zes_src "$f"
    if grep -E -i '^[[:space:]]*(registry|@[^:]+:registry|npmRegistryServer|repository|index-url|index_url|extra-index-url)[[:space:]]*[=:]' "$SRC" 2>/dev/null \
       | grep -E -o 'https?://[^/"'"'"'[:space:]]+' | sed -E 's#https?://##' | grep_q -v -E "^($re)$"; then
      medium "" "$f" s26.registry_url
    fi
  done < <(printf '%s\n' "$HOME_DIR/.npmrc" "$HOME_DIR/.yarnrc" "$HOME_DIR/.yarnrc.yml" "$HOME_DIR/.pypirc" "$HOME_DIR/.config/pip/pip.conf"; files_named '^(\.npmrc|\.yarnrc|\.yarnrc\.yml|\.pypirc|pip\.conf)$')
  return 0
}

# toml_value_head TEXT → TOML_VALUE: the value at the start of TEXT (what follows "key =" on its line): a """...""",
#   '''...''', "..." or '...' string without its quotes (empty when the closing quotes are not on the line), otherwise the bare
#   word up to a blank, "#", a quote or CR. Same rule as tomlValueHead of the browser engine
toml_value_head() {
  local v="$1" q
  v="${v#"${v%%[!$' \t']*}"}"
  TOML_VALUE=""
  case "$v" in
    \"\"\"*|\'\'\'*) q="${v:0:3}"; v="${v:3}"; [[ "$v" == *"$q"* ]] && TOML_VALUE="${v%%"$q"*}" ;;
    \"*|\'*) q="${v:0:1}"; v="${v:1}"; [[ "$v" == *"$q"* ]] && TOML_VALUE="${v%%"$q"*}" ;;
    *) TOML_VALUE="${v%%[$' \t\r#"\'']*}" ;;
  esac
}

# pyproject_build_system FILE … "B<text after =>" for the first build-backend and "P" for a backend-path of the
#   [build-system] table (the same rule as buildSystemKeys of the browser engine). Only keys of that table count: lines
#   under [build-system] (until the next table header), "build-system.build-backend = …" before the first header, and the
#   keys of "build-system = { … }" on its line. Lines inside multi-line strings (""" / ''') are never keys (a
#   description can hold a decoy "build-backend = …" line). TOML whitespace is space and tab; a BOM and CRs are removed,
#   a NUL becomes U+0001 (as in the browser engine)
pyproject_build_system() {
  text_lines "$1" | awk '
    # Scan x from position i outside strings and set inml / mlq when a multi-line string stays open at the end of the line
    function scan(x, i,   n, c, j) {
      n = length(x)
      while (i <= n) {
        c = substr(x, i, 1)
        if (inml) {
          if (mlq == "\"\"\"" && c == "\\") { i += 2; continue }
          if (substr(x, i, 3) == mlq) { while (substr(x, i + 3, 1) == substr(mlq, 1, 1)) i++; inml = 0; i += 3; continue }
          i++; continue }
        if (c == "#") return
        if (substr(x, i, 3) == "\"\"\"" || substr(x, i, 3) == "\047\047\047") { mlq = substr(x, i, 3); inml = 1; i += 3; continue }
        if (c == "\"") { for (j = i + 1; j <= n; j++) { if (substr(x, j, 1) == "\\") { j++; continue } if (substr(x, j, 1) == "\"") break } i = j + 1; continue }
        if (c == "\047") { j = index(substr(x, i + 1), "\047"); if (j == 0) return; i += j + 1; continue }
        i++ } }
    function key(x, k) { return match(x, "^[ \t]*[\"\047]?" k "[\"\047]?[ \t]*=") }
    function emit(x, k) { if (k == "build-backend") { if (!gotbe) { gotbe = 1; print "B" substr(x, RSTART + RLENGTH) } } else print "P" }
    {
      line = $0; gsub(/\0/, "\001", line)
      if (inml) { scan(line, 1); next }
      if (match(line, /^[ \t]*\[/)) {
        h = line; sub(/^[ \t]*\[/, "", h)
        if (substr(h, 1, 1) == "[") tbl = "other"
        else { sub(/\].*$/, "", h); gsub(/^[ \t]+|[ \t]+$/, "", h); gsub(/^["\047]|["\047]$/, "", h); tbl = (h == "build-system") ? "bs" : "other" }
        next }
      if (tbl == "bs") { if (key(line, "build-backend")) emit(line, "build-backend"); else if (key(line, "backend-path")) emit(line, "backend-path") }
      else if (tbl == "") {
        if (key(line, "build-system[ \t]*\\.[ \t]*build-backend")) emit(line, "build-backend")
        else if (key(line, "build-system[ \t]*\\.[ \t]*backend-path")) emit(line, "backend-path")
        else if (match(line, /^[ \t]*build-system[ \t]*=[ \t]*\{/)) {
          r = substr(line, RLENGTH + 1)
          if (match(r, /(^|,)[ \t]*["\047]?build-backend["\047]?[ \t]*=/)) { if (!gotbe) { gotbe = 1; print "B" substr(r, RSTART + RLENGTH) } }
          if (match(r, /(^|,)[ \t]*["\047]?backend-path["\047]?[ \t]*=/)) print "P" } }
      scan(line, 1) }'
}

# §27 Build hooks (build.rs / go:generate / build-backend / cmdclass)
check_s27() {
  log_section "§27"
  local f
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if fgrep_q '(Command::new|process::Command)' "$f" && fgrep_q '"(curl|wget|sh|bash|powershell|cmd)"|(curl|wget)' "$f"; then
      high "" "$f" s27.build_rs_exec
    elif fgrep_q '(Command::new|process::Command)' "$f"; then
      medium "" "$f" s27.build_rs_process
    elif fgrep_q '(include_bytes!|include_str!)' "$f"; then
      low "" "$f" s27.build_rs_include
    fi
  done < <(files_named '^build\.rs$')
  files_named '\.go$' | grep_l '^//go:generate[[:space:]]+(curl|wget|bash|sh[[:space:]]+-c)' | while IFS= read -r f; do
    [ -n "$f" ] && high "" "$f" s27.go_generate
  done
  local -a safeb; mapfile -t safeb < <(read_ioc '.build_hooks.py_build_backend_safe')
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    local be="" bp=0 l
    while IFS= read -r l; do
      case "$l" in B*) toml_value_head "${l#B}"; be="$TOML_VALUE" ;; P) bp=1 ;; esac
    done < <(pyproject_build_system "$f")
    if [ -n "$be" ]; then printf '%s\n' "${safeb[@]}" | grep_q -x -F -- "$be" || medium "" "$f" s27.build_backend backend="$be"; fi
    [ "$bp" -eq 1 ] && high "" "$f" s27.backend_path
  done < <(files_named '^pyproject\.toml$')
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    fgrep_q 'cmdclass' "$f" || continue
    if fgrep_q '(urllib|requests\.|subprocess|os\.system|socket|b64decode|exec\()' "$f"; then
      high "" "$f" s27.cmdclass_exec
    else
      medium "" "$f" s27.cmdclass
    fi
  done < <(files_named '^setup\.py$')
  return 0
}

# §28 Container signing
check_s28() {
  log_section "§28"
  local f
  local builds_images=0 verifies=0
  files_path '(/\.github/workflows/[^/]+\.ya?ml|\.gitlab-ci\.yml|/Jenkinsfile|\.sh)$' | grep_l '(docker[[:space:]]+push|docker/build-push-action|buildah[[:space:]]+push|ko[[:space:]]+publish)' | grep_q . && builds_images=1
  files_path '(\.ya?ml|\.sh|/Makefile|/Jenkinsfile)$' | grep_l 'cosign[[:space:]]+verify' | grep_q . && verifies=1
  [ "$builds_images" -eq 1 ] && [ "$verifies" -eq 0 ] && medium "" "$ROOT" s28.no_verify
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    dockerfile_images "$f" | grep -v -E '^(scratch|\$)' | grep_q -v '@sha256:' \
      && medium "" "$f" s28.from_digest --x="$(x_kind gha.unpinned)"
  done < <(files_named '^(Dockerfile.*|.*\.dockerfile)$')
  while IFS= read -r f; do [ -n "$f" ] && high "" "$f" s28.cosign_key; done < <(files_named '^cosign\.key$')
  files_named '\.ya?ml$' | grep_l 'imagePullPolicy:[[:space:]]*Always' | while IFS= read -r f; do
    [ -n "$f" ] || continue
    fgrep_q 'image:[[:space:]]*[^[:space:]]+@sha256:' "$f" || medium "" "$f" s28.pull_always --x="$(x_kind gha.unpinned)"
  done
  return 0
}

# Kubernetes manifests
k8s_manifests() {
  local f
  files_named '\.ya?ml$' | grep_l '^kind:[[:space:]]*[A-Z]' | while IFS= read -r f; do
    [ -n "$f" ] && grep -q '^apiVersion:' "$f" 2>/dev/null && printf '%s\n' "$f"
  done
  return 0
}

# §29 K8s and cloud
check_s29() {
  log_section "§29"
  local f
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    fgrep_q 'automountServiceAccountToken:[[:space:]]*true' "$f" && medium "" "$f" s29.automount_token
    fgrep_q 'failurePolicy:[[:space:]]*Ignore' "$f" && medium "" "$f" s29.failure_policy
    fgrep_q '^[[:space:]]*hostPath:' "$f" && high "" "$f" s29.host_path
    fgrep_q '169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200' "$f" && medium "" "$f" s29.metadata
  done < <(k8s_manifests)
  return 0
}

# §30 macOS persistence
# plist_label FILE → PLIST_LABEL: the <string> right after <key>Label</key>, with any XML whitespace (blank lines, line
#   breaks) between them and line breaks inside the value kept, like a plist parser (the browser engine uses the same
#   rule). Returned in a variable: a command substitution would drop a trailing line break of the value
plist_label() {
  local v
  v="$(awk '{ s = s $0 "\n" } END {
      if (match(s, /<key>Label<\/key>[ \t\r\n]*<string>[^<]*<\/string>/)) {
        m = substr(s, RSTART, RLENGTH); sub(/^<key>Label<\/key>[ \t\r\n]*<string>/, "", m); sub(/<\/string>$/, "", m); printf "%s", m } }' "$1" 2>/dev/null; printf x)"
  PLIST_LABEL="${v%x}"
}
check_s30() {
  log_section "§30"
  local f lb
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    plist_label "$f"; lb="$PLIST_LABEL"
    if [ -n "$lb" ] && ! printf '%s' "$lb" | grep_q '\.'; then
      high "" "$f" s30.random_label label="$lb"
    fi
    fgrep_q '<string>(/tmp/|/private/tmp/|/Users/Shared/|/var/tmp/)|<string>[^<]*/\.[^/<]+/[^<]*</string>' "$f" && high "" "$f" s30.tmp_program
    fgrep_q '(curl|osascript|base64|python[0-9.]* -c|bash -c)' "$f" && high "" "$f" s30.program_arguments
  done < <(files_path '/Library/(LaunchAgents|LaunchDaemons)/[^/]+\.plist$|/LaunchAgents/[^/]+\.plist$'
           if [ "$OS_NAME" = "Darwin" ]; then ls "$HOME_DIR"/Library/LaunchAgents/*.plist 2>/dev/null; host_enabled && ls /Library/LaunchAgents/*.plist /Library/LaunchDaemons/*.plist 2>/dev/null; fi)
  while IFS= read -r f; do
    [ -n "$f" ] && fgrep_q 'DYLD_INSERT_LIBRARIES' "$f" && high "" "$f" s30.dyld_insert
  done < <(home_rc_paths)
  [ -f "$HOME_DIR/Library/Preferences/com.apple.security.plist" ] && info "" "$HOME_DIR/Library/Preferences/com.apple.security.plist" s30.security_plist
  if [ "$OS_NAME" = "Darwin" ] && host_enabled; then
    local v
    v="$(safe_probe launchctl getenv DYLD_INSERT_LIBRARIES)"
    [ -n "$v" ] && critical "" "" s30.launchctl_dyld
    safe_probe launchctl list | awk 'NR>1 {print $3}' | grep -v -E '\.' | grep -v -E '^-$' | while IFS= read -r lb; do
      high "" "" s30.launchctl_random label="$lb"
    done
    local li
    li="$(safe_probe osascript -e 'tell application "System Events" to get name of every login item')"
    [ -n "$li" ] && info "" "" s30.login_items items="$li"
    safe_probe profiles show -type configuration | grep_q -i 'attribute' && medium "" "" s30.profiles
  fi
  intel_host_files
  return 0
}

# §31 Linux persistence (/etc/ld.so.preload / LD_PRELOAD / systemd user / autostart / cron.d)
check_s31() {
  log_section "§31"
  local f
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    zes_src "$f"; [ -s "$f" ] && grep -q -v -E '^[[:space:]]*(#|$)' "$SRC" && critical "ebpf-rootkit" "$f" s31.ld_so_preload \
      --x="$(x_text_locators "$f" -v '^[[:space:]]*(#|$)')"
  done < <(files_named '^ld\.so\.preload$'; host_enabled && [ -f /etc/ld.so.preload ] && echo /etc/ld.so.preload)
  while IFS= read -r f; do
    [ -n "$f" ] && fgrep_q '(^|[[:space:]]|export[[:space:]]+)LD_PRELOAD=' "$f" && high "ebpf-rootkit" "$f" s31.ld_preload_rc \
      --x="$(x_text_locators "$f" '(^|[[:space:]]|export[[:space:]]+)LD_PRELOAD=')"
  done < <(home_rc_paths; files_named '^(\.bashrc|\.zshrc|\.profile|\.bash_profile|environment)$'; host_enabled && [ -f /etc/environment ] && echo /etc/environment)
  local unit
  while IFS= read -r unit; do
    [ -n "$unit" ] || continue
    local ure='^[[:space:]]*(ExecStart|ExecStartPre|Exec)[[:space:]]*=[^#]*(/tmp/|/dev/shm/|/var/tmp/|/\.[^/[:space:]]+/|curl|wget|base64|bash -c|sh -c)'
    if fgrep_q "$ure" "$unit"; then
      high "ebpf-rootkit" "$unit" s31.autostart_suspicious --x="$(x_text_locators "$unit" "$ure")"
    elif fgrep_q 'Environment=.*LD_PRELOAD' "$unit"; then
      high "ebpf-rootkit" "$unit" s31.unit_ld_preload --x="$(x_text_locators "$unit" 'Environment=.*LD_PRELOAD')"
    else
      info "" "$unit" s31.autostart
    fi
  done < <(files_path '/systemd/user/[^/]+\.service$|/autostart/[^/]+\.desktop$'
           ls "$HOME_DIR"/.config/systemd/user/*.service "$HOME_DIR"/.config/autostart/*.desktop 2>/dev/null)
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    zes_src "$f"; grep -v '^[[:space:]]*#' "$SRC" 2>/dev/null | grep_q -E '(curl|wget|base64|/tmp/|/dev/shm/|nc )' && high "ebpf-rootkit" "$f" s31.cron_d \
      --x="$(TL_EXCLUDE='[[:space:]]*#' x_text_locators "$f" '(curl|wget|base64|/tmp/|/dev/shm/|nc )')"
  done < <(files_path '/cron\.d/[^/]+$'; host_enabled && ls /etc/cron.d/* 2>/dev/null)
  return 0
}

# §32 AI model supply chain (pickle-type extensions / weights_only=False / --extra-index-url)
check_s32() {
  log_section "§32"
  local f
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    zes_rel "$f"; case "$REL" in */node_modules/*|*/.git/*) continue ;; esac
    medium "hf-supply-chain" "$f" s32.pickle_model format="${f##*.}"
  done < <(awk '{ n = $0; sub(/.*\//, "", n); n = tolower(n)
                  if (n ~ /\.(pkl|pickle|pt)$/ || (n ~ /\.bin$/ && $0 ~ /\/(models?|checkpoints?|weights)\/|pytorch_model[^\/]*\.bin$/)) print }' "$FILES_LIST")
  files_path '\.(py|ipynb)$' | grep_l 'weights_only[[:space:]]*=[[:space:]]*False' | while IFS= read -r f; do
    [ -n "$f" ] && high "hf-supply-chain" "$f" s32.torch_load
  done
  files_named '^(requirements.*\.txt|constraints.*\.txt|pip\.conf|\.pip\.conf)$' | grep_l '(--extra-index-url|extra-index-url)' | while IFS= read -r f; do
    [ -n "$f" ] && high "hf-supply-chain" "$f" s32.extra_index_url
  done
  return 0
}

# §33 Shell hooks
check_s33() {
  log_section "§33"
  local f
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    fgrep_q '(^|[[:space:]])PROMPT_COMMAND=' "$f" && { fgrep_q 'PROMPT_COMMAND=.*(curl|wget|base64|nc |/dev/tcp)' "$f" && high "" "$f" s33.prompt_command_suspicious || medium "" "$f" s33.prompt_command; }
    fgrep_q '^[[:space:]]*(function[[:space:]]+)?precmd[[:space:]]*\(\)' "$f" && fgrep_q '(curl|wget|base64|nc |/dev/tcp)' "$f" && high "" "$f" s33.precmd
    fgrep_q '^[[:space:]]*(function[[:space:]]+)?command_not_found_hand?le?[[:space:]]*\(\)' "$f" && medium "" "$f" s33.command_not_found
  done < <(home_rc_paths)
  for f in "$HOME_DIR/.bash_logout" "$HOME_DIR/.zlogout"; do
    [ -f "$f" ] || continue
    if fgrep_q '(curl|wget|rm -rf|base64|nc )' "$f"; then high "" "$f" s33.logout_suspicious
    elif zes_src "$f"; grep -v -E '^[[:space:]]*(#|$|clear|if|fi|then|\[)' "$SRC" | grep_q .; then medium "" "$f" s33.logout
    fi
  done
  return 0
}

# §34 Network settings (proxy / hosts / ProxyCommand)
check_s34() {
  log_section "§34"
  local f
  for f in "$HOME_DIR/.curlrc" "$HOME_DIR/.wgetrc"; do
    [ -f "$f" ] && fgrep_q -i '^[[:space:]]*-?-?(proxy|https?_proxy|use_proxy)[[:space:]]*[=[:space:]]' "$f" && high "" "$f" s34.curl_proxy
  done
  # npm config get proxy starts npm (the node runtime), so it is not used; .npmrc is read statically
  for f in "$HOME_DIR/.npmrc" "$RP/.npmrc"; do
    [ -f "$f" ] && { [ "$f" = "$HOME_DIR/.npmrc" ] || in_root_regular "$f"; } && fgrep_q -i '^[[:space:]]*(https-)?proxy[[:space:]]*=' "$f" && high "" "$f" s34.npm_proxy
  done
  local -a ph; mapfile -t ph < <(read_ioc '.protected_hosts')
  local hostsf
  # Read one line at a time so paths containing spaces ("my etc/hosts" etc.) are not split
  while IFS= read -r hostsf; do
    [ -n "$hostsf" ] && [ -f "$hostsf" ] || continue
    local h
    for h in "${ph[@]}"; do
      grep -v '^[[:space:]]*#' "$hostsf" | grep_q -i -E "[[:space:]]$(printf '%s' "$h" | sed 's/\./\\./g')([[:space:]]|$)" \
        && high "" "$hostsf" s34.hosts_override host="$h"
    done
    network_iocs | cut -f1 | grep -v -E '^[0-9.]+$' | while IFS= read -r h; do
      zes_src "$hostsf"; grep -v '^[[:space:]]*#' "$SRC" | grep_q -i -F -- "$h" && critical "" "$hostsf" s34.hosts_c2 host="$h"
    done
  done < <(host_enabled && echo /etc/hosts; files_named '^hosts$')
  for f in "$HOME_DIR/.ssh/config"; do
    [ -f "$f" ] && fgrep_q -i '^[[:space:]]*ProxyCommand[[:space:]].*(\bnc\b|ncat|netcat|socat)' "$f" && high "" "$f" s34.ssh_proxy
  done
  return 0
}

# §35 Anti-forensics (auditd / history wiping / history symlinks / mtime going backwards)
check_s35() {
  log_section "§35"
  log_info log.noatime_see_s13
  if host_enabled; then
    if [ "$OS_NAME" = "Linux" ] && command -v systemctl >/dev/null 2>&1; then
      local st; st="$(systemctl is-active auditd 2>/dev/null)"
      [ "$st" = "active" ] && safe log.safe.auditd || medium "" "" s35.auditd state="${st:-unknown}"
    elif [ "$OS_NAME" = "Darwin" ]; then
      [ -f /etc/security/audit_control ] || medium "" "/etc/security/audit_control" s35.openbsm
    fi
  fi
  local f
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    fgrep_q '(HISTFILE=/dev/null|HISTSIZE=0([^0-9]|$)|HISTFILESIZE=0([^0-9]|$)|SAVEHIST=0([^0-9]|$)|unset[[:space:]]+HISTFILE)' "$f" && high "" "$f" s35.history_disabled
  done < <(home_rc_paths)
  for f in "$HOME_DIR/.bash_history" "$HOME_DIR/.zsh_history"; do
    [ -L "$f" ] && [ "$(readlink -- "$f")" = "/dev/null" ] && high "" "$f" s35.history_devnull
  done
  # mtime going backwards (only where birth time is available)
  local b m
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    b="$(stat_birth "$f")"; m="$(stat_mtime "$f")"
    [ -n "$b" ] && [ -n "$m" ] && [ "$b" != "0" ] && [ "$b" != "-" ] || continue
    [ "$m" -lt $(( b - 86400 )) ] 2>/dev/null && medium "" "$f" s35.mtime_before_birth
  done < <(files_path '\.(sh|py|js|mjs|cjs|rb|pl|pth|so|dylib)$|/(\.bashrc|\.zshrc|\.profile|\.envrc)$' | head -n 5000; home_rc_paths)
  return 0
}

# =============================================================================
# §36-§48 (v5.0/v5.1)
# =============================================================================

# §36 HF supply chain
check_s36() {
  log_section "§36"
  local f
  files_path '\.(py|ipynb|json|ya?ml)$' | grep_l 'trust_remote_code["'"'"']?[[:space:]]*[=:][[:space:]]*(True|true)' | while IFS= read -r f; do
    [ -n "$f" ] && high "hf-supply-chain" "$f" s36.trust_remote_code
  done
  files_named '\.py$' | grep_l '(GeneratorBasedBuilder|DatasetBuilder|datasets\.load_dataset|_split_generators)' | grep_l '(subprocess|os\.system|eval\(|exec\(|__import__)' | while IFS= read -r f; do
    [ -n "$f" ] && high "hf-dataset-poisoning" "$f" s36.dataset_loader
  done
  files_named '\.py$' | grep_l '(def __reduce__|pickle\.loads?\(|dill\.loads?\(|cloudpickle\.loads?\()' | while IFS= read -r f; do
    [ -n "$f" ] || continue
    zes_rel "$f"; case "$REL" in */site-packages/*|*/dist-packages/*|*/node_modules/*) continue ;; esac
    medium "hf-supply-chain" "$f" s36.pickle
  done
  files_named '\.(ya?ml|json|jinja2?|j2)$' | grep_l '\{\{[^}]*(__class__|__globals__|__import__|cycler|lipsum|os\.popen)' | while IFS= read -r f; do
    [ -n "$f" ] && high "hf-dataset-poisoning" "$f" s36.template_injection
  done
  build_deps
  awk -F'\t' '$1=="pypi" && $2=="lerobot" {print $3"\t"$4}' "$DEPS_TSV" | tsv_us | while IFS="$US" read -r v f; do
    high "hf-lerobot-rce" "$f" s36.lerobot version="${v}"
  done
  while IFS= read -r f; do [ -n "$f" ] && critical "hf-supply-chain" "$f" s36.transformers_pyz; done < <(files_named '^transformers\.pyz$')
  return 0
}

# §37 MCP registries
check_s37() {
  log_section "§37"
  local f
  files_path '\.(json|ya?ml|toml|js|ts|py|md)$' | grep_lF 'MCP-POISON' | while IFS= read -r f; do
    [ -n "$f" ] && high "mcp-poisoning" "$f" s37.specter
  done
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    fgrep_q 'host\.docker\.internal' "$f" && high "mcp-poisoning" "$f" s37.host_docker_internal
    fgrep_q '64:ff9b(:1)?::' "$f" && high "mcp-poisoning" "$f" s37.nat64
  done < <(mcp_config_files | sort -u; files_path '/(tool|server|mcp)\.json$')
  build_deps
  if [ "$HAVE_JQ" -eq 1 ]; then
    local ce cp cf cid
    while IFS="$US" read -r cid ce cp cf; do
      ZES_V_E="$ce" ZES_V_N="$cp" awk -F'\t' 'BEGIN { e = ENVIRON["ZES_V_E"]; n = ENVIRON["ZES_V_N"] } $1==e && $2==n {print $3"\t"$4}' "$DEPS_TSV" | sort -u | tsv_us | while IFS="$US" read -r v f; do
        [ -n "$v" ] && version_lt "$v" "$cf" && high "mcp-poisoning" "$f" s37.mcp_cve cve="${cid}" fixed="${cf}" package="${cp}" version="${v}" --x="$(x_kind runtime.cve)"
      done
    done < <(jq -r '.mcp_poisoning.mcp_cves[] | select(.package and .fixed) | [.id, .eco, .package, .fixed] | @tsv' "$IOC_FILE" | tsv_us)
  fi
  awk -F'\t' '
    ($1=="npm" && ($2=="@modelcontextprotocol/sdk" || $2 ~ /appium.*mcp|mcp.*appium/ || $2=="@modelcontextprotocol/server-everything" || $2 ~ /gitlab-mcp/)) ||
    ($1=="pypi" && ($2=="mcp" || $2=="mcp-server-fetch" || $2=="fastmcp")) ||
    ($1=="go" && $2 ~ /stacklok\/toolhive/) {print $2"\t"$3"\t"$4}' "$DEPS_TSV" | sort -u | tsv_us | while IFS="$US" read -r n v f; do
    medium "mcp-poisoning" "$f" s37.mcp_dependency package="${n}" version="${v}"
  done
  return 0
}

# §38 CI/CD mass implants
check_s38() {
  log_section "§38"
  local f n
  local th; th="$(read_ioc '.github_actions.secrets_ref_threshold')"; th="${th:-10}"
  if [ -n "$ROOT_GITDIR" ]; then
    local since; since="$(( $(now_epoch) - 30*86400 ))"
    # Paths are received with -z (NUL-separated) (so names with non-ASCII characters or quotes are not quoted in C style)
    if safe_git log --no-textconv --no-ext-diff --diff-filter=A --since="@$since" --name-only --format='' -z -- .github/workflows >"$TMP_DIR/s38-added.z"; then
      tr '\0' '\n' <"$TMP_DIR/s38-added.z" | grep -v '^$' | sort -u | while IFS= read -r n; do
        [ -n "$n" ] && medium "ghostaction-oct2026" "$RP/$n" s38.new_workflow
      done
    else
      record_error "§38" "git_log_failed"
    fi
  fi
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    n="$(grep -o -a -i -E 'secrets\.[A-Za-z0-9_]+' "$f" 2>/dev/null | tr 'A-Z' 'a-z' | sort -u | wc -l | tr -d ' ')"
    [ "${n:-0}" -gt "$th" ] && high "ghostaction-oct2026" "$f" s38.many_secrets n="${n}" threshold="${th}"
    fgrep_q -i 'tojson\([[:space:]]*secrets[[:space:]]*(\.[[:space:]]*\*[[:space:]]*)?\)' "$f" && critical "ghostaction-oct2026" "$f" s38.tojson_secrets
    fgrep_q '(^|[[:space:];|])(env|printenv)[[:space:]]*(\||>|$)' "$f" && high "ghostaction-oct2026" "$f" s38.env_dump
  done < <(workflow_files)
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    zes_src "$f"
    grep -q -E '^[[:space:]]*-?[[:space:]]*remote:[[:space:]]*["'"'"']?https?://' "$SRC" && high "ghostaction-oct2026" "$f" s38.gitlab_remote_include
    if grep -q -E '^[[:space:]]*-?[[:space:]]*project:' "$SRC" && ! grep -q -E 'ref:[[:space:]]*["'"'"']?[0-9a-f]{40}' "$SRC"; then
      medium "ghostaction-oct2026" "$f" s38.gitlab_project_include
    fi
  done < <(files_named '^\.gitlab-ci\.ya?ml$')
  files_path '/\.circleci/config\.ya?ml$' | grep_l '^[[:space:]]+[A-Za-z0-9_-]+:[[:space:]]*[A-Za-z0-9_-]+/[A-Za-z0-9_-]+@(volatile|dev:)' | while IFS= read -r f; do
    [ -n "$f" ] && high "ghostaction-oct2026" "$f" s38.circleci_orb
  done
  files_named '^Jenkinsfile$' | grep_l "@Library\\(['\"][^'\"@]+['\"]\\)" | while IFS= read -r f; do
    [ -n "$f" ] && medium "ghostaction-oct2026" "$f" s38.jenkins_library
  done
  # GhostAction: fake fonts (font extension but mismatching magic bytes)
  local magic
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    magic="$(od -An -tx1 -N4 -- "$f" 2>/dev/null | tr -d ' \n')"
    case "$magic" in 00010000|4f54544f|74727565|74797031|774f4646|774f4632|"") ;;
      *) high "ghostaction-oct2026" "$f" s38.fake_font ;;
    esac
  done < <(files_named '\.(ttf|otf|woff2?)$')
  files_path '/\.github/' | grep -E '\.(ttf|otf|woff2?)$' | while IFS= read -r f; do
    medium "ghostaction-oct2026" "$f" s38.github_font
  done
  intel_workflow_strings
  return 0
}

# §39 Metadata SSRF
check_s39() {
  log_section "§39"
  local f
  k8s_manifests >"$TMP_DIR/k8s.lst"
  files_path '\.(py|js|mjs|cjs|ts|go|rb|php|java|sh|tf|json|toml|ini|conf|env)$|/\.env[^/]*$' | grep -v -x -F -f "$TMP_DIR/k8s.lst" \
    | grep_l '169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254' | while IFS= read -r f; do
    [ -n "$f" ] && medium "" "$f" s39.metadata_ref
  done
  while IFS= read -r f; do
    [ -n "$f" ] && fgrep_q 'AWS_EC2_METADATA_SERVICE_ENDPOINT[[:space:]]*=' "$f" && high "" "$f" s39.metadata_endpoint
  done < <(home_rc_paths; files_named '^\.env(\.[A-Za-z0-9_-]+)?$|\.sh$')
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    fgrep_q 'http_tokens[[:space:]]*=[[:space:]]*"optional"' "$f" && high "" "$f" s39.imdsv1
    if fgrep_q 'resource[[:space:]]+"aws_(instance|launch_template)"' "$f" && ! fgrep_q 'http_tokens[[:space:]]*=[[:space:]]*"required"' "$f"; then
      medium "" "$f" s39.imdsv2
    fi
  done < <(files_named '\.tf$')
  if host_enabled && command -v lsof >/dev/null 2>&1; then
    lsof -nP -i -a -c dockerd -c containerd 2>/dev/null | grep -E '169\.254\.169\.254|100\.100\.100\.200' | awk '{print $2}' | sort -u | while IFS= read -r pid; do
      high "" "/proc/$pid" s39.dockerd_metadata pid="$pid"
    done
  fi
  return 0
}

# §40 eBPF / LD_PRELOAD rootkits
check_s40() {
  log_section "§40"
  local f
  files_path '\.(sh|bash|py|c|go|rs|service)$' | grep_l '(>>?[[:space:]]*/etc/ld\.so\.preload|bpftool[[:space:]]+prog[[:space:]]+(load|attach)|bpf_probe_write_user|BPF_PROG_LOAD|insmod[[:space:]]|modprobe[[:space:]]+-f)' | while IFS= read -r f; do
    [ -n "$f" ] && high "ebpf-rootkit" "$f" s40.preload_bpf_module
  done
  files_path '\.(sh|bash|py|c|go|rs|service|conf)$|/[^/.]+$' | grep_l '(quasar[ _-]?linux|\bQLNX\b|linkpro|voidlink)' -i | while IFS= read -r f; do
    [ -n "$f" ] && critical "ebpf-rootkit" "$f" s40.rootkit_names
  done
  host_enabled || return 0
  [ "$OS_NAME" = "Linux" ] || return 0
  local t
  t="$(cat /proc/sys/kernel/tainted 2>/dev/null)"
  if [ -n "$t" ] && [ "$t" != "0" ]; then
    if [ $(( t & 4096 )) -ne 0 ] || [ $(( t & 8192 )) -ne 0 ]; then
      high "ebpf-rootkit" "/proc/sys/kernel/tainted" s40.tainted tainted="$t"
    else
      info "" "/proc/sys/kernel/tainted" s40.taint_flags tainted="$t"
    fi
  fi
  if [ -d /sys/fs/bpf ]; then
    local pinned; pinned="$(find /sys/fs/bpf -mindepth 1 -maxdepth 3 2>/dev/null | head -n 50)"
    [ -n "$pinned" ] && medium "ebpf-rootkit" "/sys/fs/bpf" s40.pinned_bpf
  fi
  local bp; bp="$(safe_probe bpftool prog list)"
  if [ -n "$bp" ]; then
    printf '%s' "$bp" | grep_q -E '(getdents|tcp4_seq_show|tcp6_seq_show|udp4_seq_show|sys_bpf|kill)' && high "ebpf-rootkit" "" s40.bpf_hiding
  fi
  if [ -r /proc/modules ]; then
    awk '$NF ~ /\(O/ || $0 ~ /\(OE\)|\(E\)/ {print $1}' /proc/modules 2>/dev/null | while IFS= read -r m; do
      medium "ebpf-rootkit" "/proc/modules" s40.module module="$m"
    done
  fi
  local u
  for u in /etc/systemd/system/*.service "$HOME_DIR"/.config/systemd/user/*.service; do
    [ -f "$u" ] || continue
    case "${u##*/}" in systemd-*|dbus-*|udev*|journald*|networkd*|resolved*)
      zes_src "$u"; grep -E '^[[:space:]]*ExecStart=' "$SRC" | grep_q -v -E '=(/usr)?/lib/systemd/|=/usr/bin/(dbus|udevadm)|=/usr/sbin/' \
        && high "ebpf-rootkit" "$u" s40.fake_unit ;;
    esac
  done
  return 0
}

# §41 AI assistants
check_s41() {
  log_section "§41"
  local f v
  for f in "/Applications/Cursor.app/Contents/Info.plist" "$HOME_DIR/Applications/Cursor.app/Contents/Info.plist" "/usr/share/cursor/resources/app/package.json" "/opt/Cursor/resources/app/package.json"; do
    [ -f "$f" ] || continue
    case "$f" in /Applications/*|/usr/*|/opt/*) host_enabled || continue ;; esac
    if [[ "$f" == *.plist ]]; then v="$(grep -A1 'CFBundleShortVersionString' "$f" | grep -o -E '[0-9]+(\.[0-9]+)+' | head -n1)"
    else v="$(grep -m1 -E '"version"' "$f" | grep -o -E '[0-9]+(\.[0-9]+)+')"; fi
    [ -n "$v" ] || continue
    if version_lt "$v" "2.5"; then
      critical "" "$f" s41.cursor_old version="${v}" --x="$(x_kind runtime.cve)"
    elif version_lt "$v" "3.0"; then
      critical "" "$f" s41.cursor_duneslide version="${v}" --x="$(x_kind runtime.cve)"
    fi
  done
  local d cfix; cfix="$(read_ioc '.runtime_minimums.copilot_chat')"
  for d in "$HOME_DIR"/.vscode/extensions/github.copilot-chat-[0-9]*; do
    [ -d "$d" ] || continue
    v="${d##*/github.copilot-chat-}"; v="${v%%-*}"
    [ -n "$cfix" ] && version_lt "$v" "$cfix" && high "" "$d" s41.copilot_chat fixed="${cfix}" version="${v}" --x="$(x_kind runtime.cve)"
  done
  for d in "$HOME_DIR"/Library/Application\ Support/JetBrains/*/plugins/github-copilot-intellij "$HOME_DIR"/.local/share/JetBrains/*/github-copilot-intellij; do
    [ -d "$d" ] && medium "" "$d" s41.copilot_jetbrains
  done
  [ -f "$RP/git.exe" ] && critical "" "$RP/git.exe" s41.git_exe
  local has_instr=0 has_hook=0 has_agent_hook=0 t
  ai_instruction_files | grep_q . && has_instr=1
  while IFS= read -r t; do
    [ -n "$t" ] && find "$t" -type f ! -name '*.sample' 2>/dev/null | qstore_filter "$t" | grep_q . && has_hook=1
  done <"$GIT_HOOKS_LIST"
  files_path '/\.(claude|cursor|gemini)/(settings(\.local)?|hooks)\.json$' | grep_l '"hooks"' | grep_q . && has_agent_hook=1
  if [ "$has_instr" -eq 1 ] && [ $(( has_hook + has_agent_hook )) -ge 1 ]; then
    high "" "$ROOT" s41.instructions_and_hooks
  fi
  while IFS= read -r f; do [ -n "$f" ] && info "" "$f" s41.cursor_mcp; done < <(files_path '/\.cursor/mcp\.json$')
  return 0
}

# §42 Extension ownership transfer (known names, permission escalation between versions)
check_s42() {
  log_section "§42"
  local f name
  local -a known; mapfile -t known < <(if [ "$HAVE_JQ" -eq 1 ]; then jq -r '.browser_extensions.known_campaigns[].name' "$IOC_FILE"; else grep -o -E '"name": "[^"]+"' "$IOC_FILE" | sed -n '/known_campaigns/,$p' | sed -E 's/"name": "//; s/"$//'; fi)
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    name="$(grep -o -E '"name"[[:space:]]*:[[:space:]]*"[^"]+"' "$f" | head -n1 | sed -E 's/.*:[[:space:]]*"//; s/"$//')"
    local k
    for k in "${known[@]}"; do
      [ -n "$name" ] || break
      case "$k" in *"$name"*) high "" "$f" s42.known_name name="$name" ; break ;; esac
    done
  done < <(extension_manifests | sort -u; ls "$HOME_DIR"/.vscode/extensions/*/package.json 2>/dev/null)
  # Whether dangerous permissions increased between several versions of the same extension ID
  local idd
  local -a dperm; mapfile -t dperm < <(read_ioc '.browser_extensions.dangerous_permissions'; echo '<all_urls>')
  extension_manifests | sort -u | sed -E 's#/[^/]+/manifest\.json$##' | sort | uniq -d | while IFS= read -r idd; do
    local prev="" cur="" vdir first=1 p added
    while IFS= read -r vdir; do
      [ -f "$idd/$vdir/manifest.json" ] || continue
      cur="$(for p in "${dperm[@]}"; do grep -q -F "\"$p\"" "$idd/$vdir/manifest.json" && printf '%s\n' "$p"; done | sort)"
      if [ "$first" -eq 0 ]; then
        # comm is not used (missing in busybox etc.). Lines present in this version and absent from the previous one
        added="$(awk 'NR == FNR { if ($0 != "") seen[$0] = 1; next } $0 != "" && !($0 in seen)' <(printf '%s\n' "$prev") <(printf '%s\n' "$cur") | sort -u | tr '\n' ' ')"
        [ -n "${added// /}" ] && high "" "$idd/$vdir/manifest.json" s42.perms_added permissions="${added% }"
      fi
      prev="$cur"; first=0
    done < <(ls -1 "$idd" 2>/dev/null | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n)
  done
  intel_extensions
  return 0
}

# §43 Sigstore / SLSA
check_s43() {
  log_section "§43"
  local f v
  local -a cmins; mapfile -t cmins < <(read_ioc '.runtime_minimums.cosign')
  if host_enabled; then
    v="$(safe_probe cosign version 2>&1 | grep -o -E 'v?[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"
    [ -n "$v" ] && version_branch_vulnerable "${v#v}" "${cmins[@]}" && high "" "$(command -v cosign)" s43.cosign_old fixed="${cmins[*]}" version="${v}"
  fi
  files_path '/\.github/workflows/[^/]+\.ya?ml$' | grep_l 'cosign-release:[[:space:]]*["'"'"']?v?[0-9]' | while IFS= read -r f; do
    v="$(grep -o -E 'cosign-release:[[:space:]]*["'"'"']?v?[0-9]+\.[0-9]+\.[0-9]+' "$f" | head -n1 | grep -o -E '[0-9]+\.[0-9]+\.[0-9]+')"
    [ -n "$v" ] && version_branch_vulnerable "$v" "${cmins[@]}" && high "" "$f" s43.cosign_installer_old fixed="${cmins[*]}" version="${v}"
  done
  # Missing identity options in cosign verify / verify-blob (not applicable when --key is used)
  local line
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    awk '/cosign[[:space:]]+verify(-blob|-attestation|-blob-attestation)?([[:space:]]|$)/ { s=$0; while (s ~ /\\$/ && (getline n) > 0) { sub(/\\$/,"",s); s=s n } print s }' "$f" | while IFS= read -r line; do
      printf '%s' "$line" | grep_q -E -- '--key([[:space:]=]|$)' && continue
      printf '%s' "$line" | grep_q -E -- '--certificate-identity(-regexp)?[[:space:]=]' || { high "" "$f" s43.no_identity; continue; }
      printf '%s' "$line" | grep_q -E -- '--certificate-oidc-issuer(-regexp)?[[:space:]=]' || high "" "$f" s43.no_issuer
    done
  done < <(files_path '\.(sh|bash|ya?ml|mk)$|/Makefile$|/Jenkinsfile$' | grep_l 'cosign[[:space:]]+verify')
  files_path '\.(sh|bash|ya?ml)$' | grep_l 'rekor-cli[[:space:]]+(get|search)' | while IFS= read -r f; do
    [ -n "$f" ] || continue
    fgrep_q '(cosign[[:space:]]+verify|slsa-verifier[[:space:]]+verify)' "$f" || medium "" "$f" s43.rekor_only
  done
  files_path '\.(sh|bash|ya?ml)$' | grep_l 'slsa-verifier[[:space:]]+verify-' | while IFS= read -r f; do
    [ -n "$f" ] || continue
    fgrep_q -- '--source-uri' "$f" || high "" "$f" s43.no_source_uri
  done
  local ver
  while IFS=$'\t' read -r ver f; do [ -n "$ver" ] && version_lt "${ver#v}" "1.8.5" && high "" "$f" s43.fulcio version="${ver}"; done < <(detect_service_version 'projectsigstore/fulcio')
  build_deps
  awk -F'\t' '$1=="gem" && $2=="sigstore" {print $3"\t"$4}' "$DEPS_TSV" | tsv_us | while IFS="$US" read -r v f; do
    version_lt "$v" "0.2.3" && high "" "$f" s43.sigstore_ruby version="${v}"
  done
  return 0
}

# §44 Payment SDK typosquatting (Levenshtein distance)
check_s44() {
  log_section "§44"
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
      if [ "$dd" = "1" ]; then high "typosquat-payment-sdk" "$f" s44.typosquat_d1 package="${n}" sdk="${s}"
      else medium "typosquat-payment-sdk" "$f" s44.typosquat_d2 package="${n}" sdk="${s}"; fi
    done
  return 0
}

# §45 Infostealers
check_s45() {
  log_section "§45"
  local f n
  files_path '\.(m?js|cjs|ts|py|sh)$' | grep_l '(bun\.sh/install|oven-sh/bun/releases/download|bun-(linux|darwin)-(x64|aarch64)\.zip)' | while IFS= read -r f; do
    [ -n "$f" ] && high "teampcp-mini-shai-hulud" "$f" s45.bun_binary
  done
  files_path '\.(m?js|cjs|ts|py|sh)$' | grep_l 'api\.github\.com/(user/repos|repos/[^"'"'"' ]+/(contents|git/(blobs|trees|refs))|gists)' \
    | grep_l '(POST|PUT|PATCH|method:[[:space:]]*["'"'"'](POST|PUT)|requests\.(post|put)|-X[[:space:]]*(POST|PUT))' | while IFS= read -r f; do
    [ -n "$f" ] && high "post-shaihulud" "$f" s45.github_api_write
  done
  local now; now="$(now_epoch)"
  for f in "$HOME_DIR/.config/gh/hosts.yml" "$HOME_DIR/.npmrc" "$HOME_DIR/.pypirc"; do
    [ -f "$f" ] || continue
    local m; m="$(stat_mtime "$f")"
    [ -n "$m" ] && [ $(( now - m )) -lt $(( 7*86400 )) ] && medium "post-shaihulud" "$f" s45.credential_recent
  done
  local -a envs; mapfile -t envs < <(read_ioc '.ci_env_vars')
  local th; th="$(read_ioc '.ci_env_harvest_threshold')"; th="${th:-20}"
  printf '%s\n' "${envs[@]}" >"$TMP_DIR/cienv.pat"
  files_path '\.(m?js|cjs|ts|py|sh|go|rs)$' | tr '\n' '\0' | xargs -0 grep -l -a -F -f "$TMP_DIR/cienv.pat" -- /dev/null 2>/dev/null | while IFS= read -r f; do
    [ -n "$f" ] || continue
    n="$(grep -o -a -F -w -f "$TMP_DIR/cienv.pat" -- "$f" 2>/dev/null | sort -u | wc -l | tr -d ' ')"
    [ "${n:-0}" -ge "$th" ] && high "post-shaihulud" "$f" s45.ci_env_harvest n="${n}"
  done
  files_path '\.(m?js|cjs|ts|py|sh)$' | grep_l '(shai[-_ ]?hulud|miasma|sckit|iron-?worm|PRIVCOLLECT|letters9813)' -i | while IFS= read -r f; do
    [ -n "$f" ] && high "post-shaihulud" "$f" s45.infostealer_ids
  done
  return 0
}

# §46 Git provenance
check_s46() {
  log_section "§46"
  [ -n "$ROOT_GITDIR" ] || { log_info log.not_git; return 0; }
  local out n
  # %G? verifies signatures (may start gpg.*.program), so it is not used. Whether signed is decided from the raw header (gpgsig)
  out="$(safe_git log -n 200 --no-textconv --no-ext-diff --format='%at%x09%ae%x09%H')" || { record_error "§46" "git_log_failed"; return 0; }
  [ -n "$out" ] || return 0
  local raw
  raw="$(safe_git log -n 200 --no-textconv --no-ext-diff --pretty=raw)" || { record_error "§46" "git_log_failed"; return 0; }
  local now; now="$(now_epoch)"
  printf '%s\n' "$out" | awk -F'\t' -v now="$now" '$1 >= now-86400 {c[$2]++} END {for (a in c) if (c[a] > 50) print a "\t" c[a]}' | while IFS=$'\t' read -r _ n; do
    medium "" "$RP/.git" s46.burst n="${n}"
  done
  local total unsigned
  total="$(printf '%s\n' "$out" | wc -l | tr -d ' ')"
  # pretty=raw: separated by "commit <sha>", headers start at the line start, the body is indented by 4 (distinguishable from fake headers in the body)
  local signed_list
  signed_list="$(printf '%s\n' "$raw" | awk '
      /^commit [0-9a-f]+/ { c=$2; inhdr=1; next }
      inhdr && /^$/ { inhdr=0; next }
      inhdr && /^gpgsig(-sha256)? / { print c }' | sort -u)"
  unsigned="$(printf '%s\n' "$out" | ZES_SL="$signed_list" awk -F'\t' 'BEGIN { n=split(ENVIRON["ZES_SL"], a, "\n"); for (i=1; i<=n; i++) s[a[i]]=1 } !($3 in s)' | wc -l | tr -d ' ')"
  [ "$total" -gt 0 ] && info "" "$RP/.git" s46.unsigned total="${total}" unsigned="${unsigned}"
  safe_git for-each-ref --format='%(refname)' refs/notes | while IFS= read -r n; do
    [ -n "$n" ] && medium "" "$RP/.git" s46.notes ref="${n}"
  done
  safe_git for-each-ref --format='%(refname)%09%(objecttype)%09%(*objecttype)' refs/tags | while IFS=$'\t' read -r n t pt; do
    if [ "$t" = "tag" ] && [ -n "$pt" ] && [ "$pt" != "commit" ]; then high "" "$RP/.git" s46.tag_not_commit tag="${n}" type="${pt}"
    elif [ "$t" != "tag" ] && [ "$t" != "commit" ]; then high "" "$RP/.git" s46.tag_not_commit tag="${n}" type="${t}"; fi
  done
  if in_root_regular "$RP/.gitmodules"; then
    local origin_host
    origin_host="$(git_cfg_get remote origin url | sed -E 's#^[a-z+]+://([^@/]+@)?##; s#^[^@]+@##; s#[:/].*##')"
    zes_src "$RP/.gitmodules"; grep -E '^[[:space:]]*url[[:space:]]*=' "$SRC" | sed -E 's/.*=[[:space:]]*//' | while IFS= read -r n; do
      case "$n" in
        http://*|git://*) high "" "$RP/.gitmodules" s46.submodule_plain url="$n" ;;
        ./*|../*) ;;
        *) local h; h="$(printf '%s' "$n" | sed -E 's#^[a-z+]+://([^@/]+@)?##; s#^[^@]+@##; s#[:/].*##')"
           [ -n "$origin_host" ] && [ "$h" != "$origin_host" ] && medium "" "$RP/.gitmodules" s46.submodule_host host="$h" ;;
      esac
    done
  fi
  return 0
}

# §47 Credential flows
check_s47() {
  log_section "§47"
  local f
  for f in "$HOME_DIR/.bash_history" "$HOME_DIR/.zsh_history" "$HOME_DIR/.local/share/fish/fish_history"; do
    [ -f "$f" ] && [ ! -L "$f" ] || continue
    fgrep_q 'export[[:space:]]+[A-Za-z0-9_]*(_TOKEN|_KEY|_SECRET|PASSWORD)=' "$f" && high "" "$f" s47.history_export --x="$(x_kind secret.token)"
  done
  local now; now="$(now_epoch)"
  for f in "$HOME_DIR/.aws/sso/cache" "$HOME_DIR/.azure" "$HOME_DIR/.config/gcloud/credentials.db"; do
    [ -e "$f" ] || continue
    local m; m="$(stat_mtime "$f")"
    [ -n "$m" ] && [ $(( now - m )) -lt 86400 ] && info "" "$f" s47.cloud_cache
  done
  files_named '^(\.env\.ci|\.envrc)$' | grep_l '(_TOKEN|_KEY|_SECRET|PASSWORD)[[:space:]]*=[[:space:]]*[^[:space:]$]' | while IFS= read -r f; do
    [ -n "$f" ] && high "" "$f" s47.ci_plaintext --x="$(x_kind secret.token)"
  done
  tr '\n' '\0' <"$FILES_LIST" | xargs -0 grep -l -a -E -e '(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}|gho_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36})' -- /dev/null 2>/dev/null | while IFS= read -r f; do
    [ -n "$f" ] && critical "" "$f" s47.github_token --x="$(x_kind secret.token)"
  done
  return 0
}

# iso8601_epoch "YYYY-MM-DDTHH:MM:SS[.frac](Z|+-HH:MM)" → epoch seconds (does not depend on date -d; the busybox date does not accept the ISO Z)
iso8601_epoch() {
  local t="$1" y mo d h mi se off=0 sign hh mm
  [[ "$t" =~ ^([0-9]{4})-([0-9]{2})-([0-9]{2})([Tt\ ]([0-9]{2}):([0-9]{2})(:([0-9]{2}))?(\.[0-9]+)?)?([Zz]|([+-])([0-9]{2}):?([0-9]{2}))?$ ]] || return 1
  y=$((10#${BASH_REMATCH[1]})); mo=$((10#${BASH_REMATCH[2]})); d=$((10#${BASH_REMATCH[3]}))
  h=$((10#${BASH_REMATCH[5]:-0})); mi=$((10#${BASH_REMATCH[6]:-0})); se=$((10#${BASH_REMATCH[8]:-0}))
  sign="${BASH_REMATCH[11]}"; hh="${BASH_REMATCH[12]:-0}"; mm="${BASH_REMATCH[13]:-0}"
  [ "$sign" = "-" ] && off=$(( -(10#$hh * 3600 + 10#$mm * 60) ))
  [ "$sign" = "+" ] && off=$(( 10#$hh * 3600 + 10#$mm * 60 ))
  # Calendar date → days since 1970-01-01 (days_from_civil by Howard Hinnant)
  local yy=$((mo <= 2 ? y - 1 : y)) era doe yoe doy
  era=$(( (yy >= 0 ? yy : yy - 399) / 400 )); yoe=$(( yy - era * 400 ))
  doy=$(( (153 * (mo + (mo > 2 ? -3 : 9)) + 2) / 5 + d - 1 )); doe=$(( yoe * 365 + yoe / 4 - yoe / 100 + doy ))
  printf '%s' $(( (era * 146097 + doe - 719468) * 86400 + h * 3600 + mi * 60 + se - off ))
}

# §48 SBOM integrity
check_s48() {
  log_section "§48"
  local f
  local -a sboms; mapfile -t sboms < <(files_named '(\.spdx\.json|\.cdx\.json|^bom\.json$|^sbom\.json$|\.spdx$|^cyclonedx\.json$)')
  [ "${#sboms[@]}" -gt 0 ] && [ -n "${sboms[0]}" ] || { log_info log.no_sbom; return 0; }
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
    # Match against the dependencies from lockfiles in the same directory (npm/pypi)
    ZES_V_D="$dir/" ZES_RP="$RP" awk -F'\t' 'BEGIN { d = ENVIRON["ZES_V_D"]; rp = ENVIRON["ZES_RP"] "/" } { r = (index($4, rp) == 1) ? substr($4, length(rp)) : $4 }
      index($4, d)==1 && ($1=="npm" || $1=="pypi") && r !~ /\/node_modules\/.*\/package\.json$/ {print $2"\t"$3}' "$DEPS_TSV" | sort -u >"$TMP_DIR/lock.tsv"
    if [ -s "$TMP_DIR/lock.tsv" ]; then
      local missing mism
      # comm / join are not used (missing in busybox etc.). The same aggregation is done in awk
      #   missing … number of names in the lockfile but not in the SBOM / mism … number of (lock version, SBOM version) pairs with the same name whose versions differ
      missing="$(awk -F'\t' 'NR == FNR { s[$1] = 1; next } !($1 in s) && !($1 in seen) { seen[$1] = 1; n++ } END { print n + 0 }' "$TMP_DIR/sbom.tsv" "$TMP_DIR/lock.tsv")"
      mism="$(awk -F'\t' 'NR == FNR { v[$1] = v[$1] SUBSEP $2; next }
          ($1 in v) { k = split(substr(v[$1], 2), a, SUBSEP); for (i = 1; i <= k; i++) if (a[i] != $2) n++ } END { print n + 0 }' "$TMP_DIR/sbom.tsv" "$TMP_DIR/lock.tsv")"
      if [ "$missing" -gt 0 ] || [ "$mism" -gt 0 ]; then
        high "" "$f" s48.sbom_mismatch mismatched="${mism}" missing="${missing}"
      else
        safe log.safe.sbom_match path="$f"
      fi
      if [ -n "$created" ]; then
        local lf lm
        while IFS= read -r lf; do
          lm="$(stat_mtime "$lf")"
          local ce; ce="$(iso8601_epoch "$created")"
          [ -n "$ce" ] && [ -n "$lm" ] && [ "$lm" -gt $(( ce + 60 )) ] && { medium "" "$f" s48.sbom_older created="$created"; break; }
        done < <(ZES_V_D="$dir/" awk -F'\t' 'BEGIN { d = ENVIRON["ZES_V_D"] } index($4,d)==1 {print $4}' "$DEPS_TSV" | sort -u)
      fi
    fi
  done
  [ "$has_prov" -eq 0 ] && [ "$has_verify" -eq 0 ] && medium "" "$ROOT" s48.no_provenance
  return 0
}

# =============================================================================
# §49 SkillPact contracts (experimental) check_skillpact
#   Statically checks whether the declared permissions of an AI agent skill match what its code actually does.
#   The declaration is read from skill.contract.json in SkillPact 0.8 format (https://github.com/kajisho5/skillpact,
#   spec (c) SEVENTHWELL (shogo kajiyama) CC BY 4.0 / schema Apache-2.0).
#   - contracts and policies are only read as JSON with jq. The skill itself and its tests are never run
#   - signatures are not verified (signed=true means a signature field is present, unverified). Severity does not depend on whether it is signed
#   - level does not use the self-declaration of the contract; "L1" only if the ZES partial checks pass. ZES does not evaluate L2/L3
#   - skills without a contract are not applicable (reference INFO only). SKILL.md files under a skill with a contract are not reported
#   - policies (JSON with policy_version + defaults) only get structural checks. Evaluation of allow/ask/deny is not implemented (TODO in README)
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

# Structural and consistency checks of contracts (ZES partial checks) and normalization of declarations
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
  name: (try ([.skill.name | strings][0]) catch null), sver: (try ([.skill.version | strings][0]) catch null),
  errors: $errors, permsok: $permsok, declared: $declared,
  signed: (try (((.integrity.signatures // []) | type) == "array" and ((.integrity.signatures // []) | length) > 0) catch false),
  authors: $authors, author: ($authors[0] // null),
  signers: (try ([(.integrity.signatures // [])[] | select((.role // "author") == "author") | .signer | strings] | unique) catch []),
  level: (if $vs == "ok" and ($errors | length) == 0 then "L1" else null end),
  divergence: $div }
'

# Comparison with the previous version (spec §17: widening permissions should bump major)
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

# Output one I-JSON (spec §4.1) issue (outputs nothing if there is none)
#   One pass over the bytes, the same rules as ijsonProblem of the browser engine (no jq: jq 1.7 accepts NaN, Infinity, 01, +1,
#   .5, 1. and several concatenated documents, and stops at 256 levels):
#   - the text must be exactly one RFC 8259 JSON value (a leading UTF-8 BOM is ignored; whitespace is space, tab, LF, CR);
#     a \uD800-\uDBFF escape not followed by a \uDC00-\uDFFF escape is also "not valid JSON" (as in jq)
#   - then, in this fixed order: top-level value not an object, duplicate member name (names compared after decoding escapes
#     and replacing invalid UTF-8 by U+FFFD as the WHATWG decoder does), a value nested deeper than 64 (the top-level value
#     is depth 1), a number whose exact decimal value is outside ±(2^53-1) (the literal is compared digit by digit: no
#     rounding, 9007199254740991.4 and 1e400 are outside, 1e-400 is inside), U+FFFD in a string or name (invalid UTF-8, a
#     lone \uDC00-\uDFFF escape, � or a literal U+FFFD)
#   An unreadable file is "not valid JSON"
sp_ijson_problem() {
  local out
  out="$(awk "$ZES_AWK_LIB"'
    BEGIN { for (k = 1; k < 256; k++) ORD[sprintf("%c", k)] = k; FFFD = "\357\277\275"; NUL = "\300\200"
      E["\""] = "\""; E["\\"] = "\\"; E["/"] = "/"; E["b"] = sprintf("%c", 8); E["f"] = sprintf("%c", 12); E["n"] = "\n"; E["r"] = "\r"; E["t"] = "\t" }
    function bad() { print "not valid JSON (or lone surrogate)"; exit }
    function ws(   c) { while (i <= n) { c = substr(S, i, 1); if (c == " " || c == "\t" || c == "\n" || c == "\r") i++; else break } }
    function hex4(h) { return h ~ /^[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]$/ }
    function hexval(h,   k, v) { v = 0; for (k = 1; k <= 4; k++) v = v * 16 + index("0123456789abcdef", tolower(substr(h, k, 1))) - 1; return v }
    function utf8(cp) {
      if (cp == 0) return NUL
      if (cp < 128) return sprintf("%c", cp)
      if (cp < 2048) return sprintf("%c%c", 192 + int(cp / 64), 128 + cp % 64)
      if (cp < 65536) return sprintf("%c%c%c", 224 + int(cp / 4096), 128 + int(cp / 64) % 64, 128 + cp % 64)
      return sprintf("%c%c%c%c", 240 + int(cp / 262144), 128 + int(cp / 4096) % 64, 128 + int(cp / 64) % 64, 128 + cp % 64) }
    function raw(s) { if (i > s) SP[++sn] = substr(S, s, i - s) }
    # A string (i is on the opening quote): its decoded value, as UTF-8 bytes
    function str(   s, c, b, need, lo, hi, q, h, cp, lw, cur) {
      i++; sn = 0; s = i; need = 0
      while (1) {
        if (i > n) bad()
        c = substr(S, i, 1); b = ORD[c] + 0
        if (need > 0) {
          if (b >= lo && b <= hi) { need--; lo = 128; hi = 191; i++; if (need == 0 && substr(S, q, i - q) == FFFD) FFD = 1; continue }
          # an incomplete sequence is one U+FFFD; the byte that ended it is read again
          cur = i; i = q; raw(s); SP[++sn] = FFFD; FFD = 1; i = cur; s = cur; need = 0
          continue }
        if (b < 128) {
          if (c == "\"") { raw(s); i++; return zes_join(SP, sn) }
          if (b < 32) bad()
          if (c == "\\") {
            raw(s); c = substr(S, i + 1, 1)
            if (c in E) { SP[++sn] = E[c]; i += 2; s = i; continue }
            if (c != "u") bad()
            h = substr(S, i + 2, 4); if (!hex4(h)) bad(); cp = hexval(h); i += 6
            if (cp >= 55296 && cp <= 56319) {
              lw = substr(S, i + 2, 4)
              if (substr(S, i, 2) != "\\u" || !hex4(lw) || hexval(lw) < 56320 || hexval(lw) > 57343) bad()
              cp = 65536 + (cp - 55296) * 1024 + (hexval(lw) - 56320); i += 6 }
            else if (cp >= 56320 && cp <= 57343) { cp = 65533 }
            if (cp == 65533) FFD = 1
            SP[++sn] = utf8(cp); s = i; continue }
          i++; continue }
        q = i
        if (b >= 194 && b <= 223) { need = 1; lo = 128; hi = 191 }
        else if (b == 224) { need = 2; lo = 160; hi = 191 }
        else if (b == 237) { need = 2; lo = 128; hi = 159 }
        else if (b >= 225 && b <= 239) { need = 2; lo = 128; hi = 191 }
        else if (b == 240) { need = 3; lo = 144; hi = 191 }
        else if (b == 244) { need = 3; lo = 128; hi = 143 }
        else if (b >= 241 && b <= 243) { need = 3; lo = 128; hi = 191 }
        else { raw(s); SP[++sn] = FFFD; FFD = 1; i++; s = i; continue }
        i++ } }
    # A digit run starting at j: the index after it
    function digits(j) { while (j <= n && index("0123456789", substr(S, j, 1)) && substr(S, j, 1) != "") j++; return j }
    # Is the exact value of the number literal x outside ±(2^53-1)?
    function outside(x,   m, p, f, e, d, k, L, t) {
      sub(/^-/, "", x); e = 0
      if ((p = index(tolower(x), "e")) > 0) { t = substr(x, p + 1); x = substr(x, 1, p - 1); m = (t ~ /^-/); sub(/^[-+]/, "", t); sub(/^0+/, "", t)
        if (length(t) > 9) return m ? 0 : (x ~ /[1-9]/); e = (m ? -1 : 1) * t }
      if ((p = index(x, ".")) > 0) { f = substr(x, p + 1); x = substr(x, 1, p - 1) } else f = ""
      d = x f; e -= length(f); sub(/^0+/, "", d)
      if (d == "") return 0
      for (k = length(d); substr(d, k, 1) == "0"; k--) e++
      d = substr(d, 1, k)
      L = length(d) + e
      if (L != 16) return L > 16
      if (e >= 0) { for (k = 0; k < e; k++) d = d "0"; return d > "9007199254740991" }
      return substr(d, 1, 16) >= "9007199254740991" }
    { P[++np] = $0 "\n" }
    END {
      S = zes_join(P, np); n = length(S); i = 1
      if (substr(S, 1, 3) == "\357\273\277") i = 4
      d = 0; need = "v"; top = ""
      while (1) {
        ws(); if (i > n) break
        c = substr(S, i, 1)
        if (need == "v" || need == "v0") {
          if (need == "v0" && c == "]") { d--; need = "a"; i++; continue }
          if (d + 1 > 64) DEEP = 1
          if (top == "") top = c
          if (c == "{") { d++; T[d] = "o"; KN[d] = 0; need = "k0"; i++ }
          else if (c == "[") { d++; T[d] = "a"; need = "v0"; i++ }
          else if (c == "\"") { str(); need = "a" }
          else if (c == "-" || index("0123456789", c)) {
            j = i; if (c == "-") j++
            if (substr(S, j, 1) == "0") j++; else { if (!index("123456789", substr(S, j, 1)) || substr(S, j, 1) == "") bad(); j = digits(j) }
            if (substr(S, j, 1) == ".") { k = digits(j + 1); if (k == j + 1) bad(); j = k }
            if (substr(S, j, 1) == "e" || substr(S, j, 1) == "E") { j++; if (substr(S, j, 1) == "+" || substr(S, j, 1) == "-") j++; k = digits(j); if (k == j) bad(); j = k }
            if (outside(substr(S, i, j - i))) BIG = 1
            i = j; need = "a" }
          else if (substr(S, i, 4) == "true" || substr(S, i, 4) == "null") { i += 4; need = "a" }
          else if (substr(S, i, 5) == "false") { i += 5; need = "a" }
          else bad()
          continue }
        if (need == "k0" || need == "k") {
          if (need == "k0" && c == "}") { for (k = 1; k <= KN[d]; k++) delete KEYS[d, KL[d, k]]; d--; need = "a"; i++; continue }
          if (c != "\"") bad()
          key = str(); if ((d, key) in KEYS) DUP = 1; else { KEYS[d, key] = 1; KL[d, ++KN[d]] = key }
          need = ":"; continue }
        if (need == ":") { if (c != ":") bad(); i++; need = "v"; continue }
        # need == "a": after a value
        if (d == 0) bad()
        if (c == ",") { i++; need = (T[d] == "o") ? "k" : "v"; continue }
        if (c == "}" && T[d] == "o") { for (k = 1; k <= KN[d]; k++) delete KEYS[d, KL[d, k]]; d--; need = "a"; i++; continue }
        if (c == "]" && T[d] == "a") { d--; need = "a"; i++; continue }
        bad() }
      if (need != "a" || d != 0) bad()
      if (top != "{") print "top-level value is not an object"
      else if (DUP) print "duplicate member name"
      else if (DEEP) print "nesting deeper than 64"
      else if (BIG) print "number outside ±(2^53-1)"
      else if (FFD) print "invalid UTF-8 or lone surrogate"
      else print "ok" }' "$1" 2>/dev/null)" || out=""
  case "$out" in
    ok) ;;
    "") echo "not valid JSON (or lone surrogate)" ;;
    *) printf '%s\n' "$out" ;;
  esac
  return 0
}
# name from the SKILL.md frontmatter
sp_fm_name() {
  awk 'NR == 1 { sub(/^\357\273\277/, "") } { sub(/\r$/, "") }
    NR == 1 { if ($0 !~ /^---[[:space:]]*$/) exit; fm = 1; next }
    fm && /^---[[:space:]]*$/ { exit }
    fm && /^name:/ { v = $0; sub(/^name:[[:space:]]*/, "", v); sub(/[[:space:]]+$/, "", v)
      if (v ~ /^".*"$/ || v ~ /^\047.*\047$/) v = substr(v, 2, length(v) - 2); print v; exit }' "$1" 2>/dev/null
}

# Skill directories (directories containing SKILL.md or skill.contract.json)
sp_skill_dirs() {
  { files_named '^SKILL\.md$'; files_named '^skill\.contract\.json$'; } | while IFS= read -r f; do dirname -- "$f"; done | sort -u
}

# Whether an ancestor directory (inside ROOT) has a contract (treated as part of a skill with a contract, not reported separately)
sp_under_contract() {
  local d="$1"
  while [ "$d" != "$ROOT" ] && [ "$d" != "/" ] && [ "$d" != "." ]; do
    d="$(dirname -- "$d")"
    case "$d/" in "$RP"/*) ;; *) return 1 ;; esac
    [ -f "$d/skill.contract.json" ] && return 0
  done
  return 1
}

# Files directly under the skill (excluding those under nested skills)
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

# Write the text for extracting observed behavior (code scope) to a temporary file (nothing is output)
#   MUST_LIST (optional) … files (relative to the skill) that entry.cli / tests.cases[].run / tests.setup of the contract reference via $SKILL_DIR/….
#   Referenced files are extracted as scripts (code that gets executed) regardless of extension or shebang.
#   Symlinks pointing inside the root (scripts/x.py → ../../lib/impl.py) read the contents of the target (build_inventory adds them to FILES_LIST).
#   Text files whose type cannot be told from the extension (those without NUL) are included in the code scope too (without attaching execution effects)
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
         || [[ "$ext" =~ ^($sre)$ ]] || { zes_src "$f"; head -c 2 -- "$SRC" 2>/dev/null | grep_q '^#!'; }; then
      printf '#ZES-SCRIPT %s\n' "$base" >>"$code"
      cat -- "$f" >>"$code"; printf '\n' >>"$code"
    elif [[ "$base" =~ \.(json|ya?ml|toml|ini|cfg)$ ]]; then
      cat -- "$f" >>"$code"; printf '\n' >>"$code"
    elif [ "$(head -c 8192 -- "$f" 2>/dev/null | tr -d -c '\000' | wc -c | tr -d ' ')" = "0" ]; then
      cat -- "$f" >>"$code"; printf '\n' >>"$code"
    fi
  done < <(sp_skill_files "$dir")
}

# Effects seen by static analysis (mapped to the 6 SkillPact effects: secrets → read (sensitive files), persist → write (outside the work area))
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

# For the previous-version comparison: list the skill.contract.json files in ROOT and the contracts in the cache as JSONL
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

# Structural checks of SkillPact policies (JSON with policy_version and defaults)
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
      medium "skillpact-invalid" "$f" s49.policy_invalid problems="$bad" --sp="$sp"
    else
      log_info log.skillpact_policy path="$f"
    fi
  done
}

check_skillpact() {
  log_section "§49"
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
      # No contract: skills that do not use SkillPact are not applicable. Reference INFO only when high-impact effects are visible
      if [ -f "$dir/SKILL.md" ] && printf '%s' "$obs" | jq -e '.exec or .network or .spend or .send' >/dev/null; then
        info "skillpact-undeclared" "$dir" s49.undeclared effects="$obs_txt" \
          --sp="$(sp_field '{}' "$obs" "" false)"
      fi
      continue
    fi
    n_contracts=$((n_contracts + 1))
    local prob; prob="$(sp_ijson_problem "$cpath")"
    if [ -n "$prob" ]; then
      medium "skillpact-invalid" "$cpath" s49.contract_unparseable problem="$prob" --sp="$(sp_field '{}' "$obs" "$cpath" false)"
      record_error "§49" "contract_unparseable:$cpath"
      continue
    fi
    # All files and symlinks under the skill (relative paths) and the hashes of the files listed in integrity.files
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
      medium "skillpact-invalid" "$cpath" s49.analysis_failed --sp="$(sp_field '{}' "$obs" "$cpath" false)"
      record_error "§49" "contract_analysis_failed:$cpath"
      continue
    fi

    # Difference from the previous version (spec §17)
    local diff="null"
    if printf '%s' "$a" | jq -e '.vstatus == "ok" and .permsok and (.name | type) == "string" and (.sver | type) == "string"' >/dev/null; then
      diff="$(jq -c -n --argjson R "$SP_RULES" --slurpfile idx "$TMP_DIR/sp_index.jsonl" --arg p "$cpath" --argjson a "$a" \
        "$SP_JQ_LIB"' {path: $p, name: $a.name, ver: $a.sver, perms: input.permissions, authors: $a.authors} | '"$SP_DIFF" "$cpath" 2>/dev/null)"
      [ -n "$diff" ] || diff="null"
    fi
    local da=false; [ "$diff" != "null" ] && da=true
    local sp; sp="$(sp_field "$a" "$obs" "$cpath" "$da")"
    # Sentences are picked by case (one code per effect / reason / signature), not assembled: ZES does not verify
    #   signatures and a signature never changes the severity, but a signed contract gets its own *.signed code
    local signed=0
    printf '%s' "$a" | jq -e '.signed' >/dev/null && signed=1

    local vs cv errs
    vs="$(printf '%s' "$a" | jq -r '.vstatus')"; cv="$(printf '%s' "$a" | jq -r '.cv // "unspecified"')"
    if [ "$vs" != "ok" ]; then
      medium "skillpact-invalid" "$cpath" s49.unsupported_version version="$cv" --sp="$sp"
      continue
    fi
    errs="$(printf '%s' "$a" | jq -r '.errors | join(",")')"
    [ -n "$errs" ] && medium "skillpact-invalid" "$cpath" s49.partial_check_errors errors="$errs" --sp="$sp"

    local eff why sens durable lv dc
    while IFS=$'\t' read -r eff why sens durable; do
      [ -n "$eff" ] || continue
      case "$eff" in exec|network|spend|send) lv=HIGH ;; *) lv=MEDIUM ;; esac
      if [ "$durable" = "true" ]; then
        if [ "$why" = "none" ]; then dc=s49.divergence.write_durable_none; else dc=s49.divergence.write_durable_scoped; fi
      elif [ "$sens" = "true" ]; then
        if [ "$why" = "none" ]; then dc=s49.divergence.read_sensitive_none; else dc=s49.divergence.read_sensitive_scoped; fi
      else
        case "$eff" in
          exec) dc=s49.divergence.exec ;; network) dc=s49.divergence.network ;; spend) dc=s49.divergence.spend ;;
          send) dc=s49.divergence.send ;; read) dc=s49.divergence.read ;; write) dc=s49.divergence.write ;;
          *) continue ;;
        esac
      fi
      if [ "$signed" -eq 1 ]; then
        case "$dc" in
          s49.divergence.write_durable_none) dc=s49.divergence.write_durable_none.signed ;;
          s49.divergence.write_durable_scoped) dc=s49.divergence.write_durable_scoped.signed ;;
          s49.divergence.read_sensitive_none) dc=s49.divergence.read_sensitive_none.signed ;;
          s49.divergence.read_sensitive_scoped) dc=s49.divergence.read_sensitive_scoped.signed ;;
          s49.divergence.exec) dc=s49.divergence.exec.signed ;;
          s49.divergence.network) dc=s49.divergence.network.signed ;;
          s49.divergence.spend) dc=s49.divergence.spend.signed ;;
          s49.divergence.send) dc=s49.divergence.send.signed ;;
          s49.divergence.read) dc=s49.divergence.read.signed ;;
          s49.divergence.write) dc=s49.divergence.write.signed ;;
        esac
      fi
      emit "$lv" "skillpact-divergence" "$dir" "$dc" --sp="$sp"
    done < <(printf '%s' "$a" | jq -r '.divergence[] | [.effect, .why, (.sensitive // false), (.durable // false)] | @tsv')

    if [ "$da" = true ]; then
      # jq returns the values; the sentence is chosen by the author-key comparison (same / changed / unsigned)
      local dl pver ppath chg ident
      dl="$(printf '%s' "$diff" | jq -r 'if any(.widened[]; .effect | IN("exec", "network", "spend", "send")) then "HIGH" else "MEDIUM" end')"
      pver="$(printf '%s' "$diff" | jq -r '"\(.prev_ver)"')"; ppath="$(printf '%s' "$diff" | jq -r '"\(.prev_path)"')"
      chg="$(printf '%s' "$diff" | jq -r '[.widened[].text] | join(" / ")')"; ident="$(printf '%s' "$diff" | jq -r '.ident')"
      case "$ident" in
        same) emit "$dl" "skillpact-account-compromise" "$cpath" s49.account_compromise.same changes="$chg" prev_path="$ppath" prev_version="$pver" --sp="$sp" ;;
        changed) emit "$dl" "skillpact-account-compromise" "$cpath" s49.account_compromise.changed changes="$chg" prev_path="$ppath" prev_version="$pver" --sp="$sp" ;;
        *) emit "$dl" "skillpact-account-compromise" "$cpath" s49.account_compromise.unsigned changes="$chg" prev_path="$ppath" prev_version="$pver" --sp="$sp" ;;
      esac
    fi
    local nf; nf="$(grep -c -F "\"contract_path\":\"$(json_escape "$cpath")\"" "$FINDINGS_FILE" 2>/dev/null)"
    if [ "${nf:-0}" -eq 0 ]; then
      local ln lv2 lcv
      ln="$(printf '%s' "$a" | jq -r '"\(.name // "?")"')"; lv2="$(printf '%s' "$a" | jq -r '"\(.sver // "?")"')"; lcv="$(printf '%s' "$a" | jq -r '"\(.cv)"')"
      if [ "$signed" -eq 1 ]; then log_info log.skillpact_l1_signed cv="$lcv" name="$ln" path="$dir" version="$lv2"
      else log_info log.skillpact_l1_unsigned cv="$lcv" name="$ln" path="$dir" version="$lv2"; fi
    fi
  done < <(sp_skill_dirs)
  [ "$n_skills" -eq 0 ] && log_info log.no_skills
  [ "$n_skills" -gt 0 ] && [ "$n_contracts" -eq 0 ] && log_info log.no_contracts
  return 0
}
check_s49() { check_skillpact; return 0; }

# =============================================================================
# Execution control
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
  # scan_roots … real path of --root (ZET uses it as the inspection scope of the plan, plan.scope.roots)
  printf '{"schema_version":"%s","scan_roots":[%s],"incident_bundle":"%s","scan_started_at":"%s","scan_finished_at":"%s","scan_mode":"%s","status":"%s","findings":[' \
    "$FINDINGS_SCHEMA_VERSION" "$(jq_str "$ROOT")" "$INCIDENT_BUNDLE" "$SCAN_STARTED_AT" "$(iso_now)" "$MODE" "$status"
  paste -sd, "$FINDINGS_FILE" | tr -d '\n'
  printf '],"errors":['
  sort -u "$ERRORS_FILE" | paste -sd, - | tr -d '\n'
  printf ']}\n'
}

# Make findings ids unique (ZET rejects input with duplicate ids as a whole).
# SEEN_IDS in emit() only works inside the per-module subshell, so only the first one is kept here and every dropped one is recorded
# in errors[] (with the injective id preimage of ENC_ID, the dropped one is the same finding emitted again)
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
  msg log.banner version="$ZES_VERSION" spec="$ZES_SPEC_VERSION"; zes_enc "$RENDERED"; local banner="$ENC_TERM"
  zes_enc "$ROOT"
  printf '%s%s%s  bundle=%s  mode=%s  root=%s  os=%s  jq=%s\n' "$C_CYN" "$banner" "$C_OFF" "$INCIDENT_BUNDLE" "$MODE" "$ENC_TERM" "$OS_NAME" "$HAVE_JQ" >&3
  # PATH entries dropped by sanitization (relative, empty, under the scan root). A fake jq / git / coreutils inside the scan root is never started
  local e
  for e in "${PATH_DROPPED[@]}"; do record_error "core" "path_entry_dropped:$e"; done
  [ "$HAVE_JQ" -eq 1 ] || log_info log.no_jq
  [ "$ROOT" = "/" ] && log_info log.root_host
  CURRENT_MODULE="core"
  build_inventory
  bom_prepare
  git_discover
  local n nmod=0 nfail=0
  for n in $(modules_for_mode "$MODE"); do
    nmod=$((nmod + 1))
    # Modules run in a subshell; an abnormal exit (set -u etc.) is recorded as module_failed (fail-closed)
    ( "check_s$n" ) || { record_error "§$n" "module_failed"; nfail=$((nfail + 1)); }
  done
  # If every module exited abnormally, the result is unusable as a scan result, so it is fatal (status=error / exit code 2)
  [ "$nmod" -gt 0 ] && [ "$nfail" -eq "$nmod" ] && FATAL=1
  dedup_findings
  local status="ok"
  # archive_not_inspected is reference information showing a known limitation (archives are not extracted), and does not make status partial
  # quarantine_store_skipped (GER quarantine stores intentionally not walked) is handled the same way
  grep -v -F -e '"reason":"archive_not_inspected:' -e '"reason":"quarantine_store_skipped:' "$ERRORS_FILE" | grep_q . && status="partial"
  [ "$FATAL" -eq 1 ] && status="error"
  local c h m
  c="$(grep -c '"level":"CRITICAL"' "$FINDINGS_FILE")"; h="$(grep -c '"level":"HIGH"' "$FINDINGS_FILE")"; m="$(grep -c '"level":"MEDIUM"' "$FINDINGS_FILE")"
  msg log.result; zes_enc "$RENDERED"
  printf '\n%s%s%s CRITICAL=%s HIGH=%s MEDIUM=%s status=%s\n' "$C_CYN" "$ENC_TERM" "$C_OFF" "$c" "$h" "$m" "$status" >&3
  if [ "$JSON_OUT" -eq 1 ]; then emit_json "$status"; fi
  [ "$status" = "error" ] && return 2
  return 0
}

main
exit $?
