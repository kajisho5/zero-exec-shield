#!/usr/bin/env bash
# ZES v5.2 回帰テスト
#   各フィクスチャで zes-scan.sh --json を実行し、tests/expected/*.json と照合する。
#   照合キーは level / module / campaign / path（フィクスチャ相対）。ID・時刻・detail 文言は照合しない。
#
# Usage: tests/run-tests.sh [--update] [--sync-campaigns]
#   --update          期待値を現在の出力で再生成（差分は必ず目視レビューすること）
#   --sync-campaigns  rules/campaigns/*.json を rules/ioc.json から再生成
set -u
set -o pipefail
export LC_ALL=C

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO="$(dirname "$TESTS_DIR")"
SCAN="$REPO/zes-scan.sh"
FIX="$TESTS_DIR/fixtures"
EXP="$TESTS_DIR/expected"
IOC="$REPO/rules/ioc.json"
UPDATE=0
SYNC=0
for a in "$@"; do
  case "$a" in
    --update) UPDATE=1 ;;
    --sync-campaigns) SYNC=1 ;;
    *) echo "unknown arg: $a" >&2; exit 64 ;;
  esac
done
command -v jq >/dev/null 2>&1 || { echo "run-tests.sh には jq が必要です" >&2; exit 64; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/zes-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
PASS=0
FAIL=0
ok()   { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
ng()   { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/       /'; }

# 環境に依存しない実行（ホスト検査・外向き通信を無効化、時刻固定）
run_scan() {
  local root="$1" mode="$2" home="$3"; shift 3
  ZES_HOST_CHECKS=0 ZES_OFFLINE=1 ZES_HOME="$home" ZES_NOW=1792800000 ZES_SKILLPACT_CACHE='' "$@" \
    "$SCAN" "--$mode" --root "$root" --json 2>"$TMP/stderr.txt"
}

# findings をフィクスチャ相対の照合キーに正規化（共有 HOME 配下の検出は環境依存のため除外）
normalize() {
  local root="$1"
  jq -S --arg r "$root/" --arg rr "$root" --arg h "$FIX/_home" '
    [ .findings[]
      | select(((.path // "") | startswith($h)) | not)
      | { level, module, campaign,
          path: (if .path == null then null elif .path == $rr then "." else (.path | ltrimstr($r)) end) } ]

    | sort_by([.module, .level, (.campaign // ""), (.path // "")])'
}

# ---------------------------------------------------------------------------
echo "== IoC データベース =="
if jq -e . "$IOC" >/dev/null 2>&1; then ok "rules/ioc.json が valid JSON"; else ng "rules/ioc.json が valid JSON ではない"; fi
n="$(jq '[.packages[] | select((.campaign // "") == "")] | length' "$IOC")"
[ "$n" = "0" ] && ok "全 packages[] に campaign" || ng "campaign の無い packages[] が $n 件"
[ "$(jq -r .incident_bundle "$IOC")" = "ZES-2026-OCT-EMERGENCY-V5.2" ] && ok "incident_bundle = ZES-2026-OCT-EMERGENCY-V5.2" || ng "incident_bundle 不一致"
n="$(grep -c -E '^\s*\{ "campaign": ' "$IOC")"
[ "$n" = "$(jq '.packages | length' "$IOC")" ] && ok "packages[] が 1 エントリ 1 行（grep フォールバック前提）" || ng "packages[] の 1 行整形が崩れています"

# rules/campaigns/*.json の生成（ioc.json が正）
gen_campaign() {
  local f="$1" camps="$2" secs="$3"
  jq --argjson c "$camps" --argjson s "$secs" --arg f "$f" '
    . as $r |
    { campaign: $f,
      incident_bundle: $r.incident_bundle,
      source: "rules/ioc.json（本ファイルは複製。正はioc.json）",
      campaigns: $c,
      packages: [ $r.packages[] | select(.campaign as $x | $c | index($x)) ],
      iocs: ( reduce $s[] as $p ({}; . + { ($p|join(".")): ($r | getpath($p)) }) ),
      malicious_files: [ $r.malicious_files_campaign | to_entries[] | select(.value as $x | $c | index($x)) | .key ] }' "$IOC"
}
CAMPAIGN_DEFS=(
  'litellm-oct2026|["litellm-oct2026"]|[]'
  'teampcp-mini-shai-hulud|["teampcp-mini-shai-hulud"]|[["worm_iocs","teampcp"]]'
  'chaindrop-keyv|["chaindrop-keyv"]|[["worm_iocs","chaindrop"]]'
  'pypi-oct2026|["pypi-oct2026"]|[]'
  'solana-typosquat|["solana-typosquat"]|[]'
  'post-shaihulud|["post-shaihulud","shai-hulud-chaindrop","sckit-memos"]|[["worm_iocs","post_shaihulud"],["worm_iocs","miasma"],["worm_iocs","sckit"]]'
  'mcp-poisoning|["mcp-poisoning"]|[["mcp_poisoning"]]'
  'hf-supply-chain|["hf-supply-chain","hf-dataset-poisoning","hf-lerobot-rce"]|[["model_supply_chain"]]'
  'ebpf-rootkit|["ebpf-rootkit"]|[["worm_iocs","quasar_linux"],["worm_iocs","linkpro"],["worm_iocs","voidlink"],["persistence","ebpf_rootkit"]]'
  'ghostaction-oct2026|["ghostaction-oct2026","megalodon-ci"]|[["github_actions"]]'
  'skillpact|["skillpact-undeclared","skillpact-divergence","skillpact-account-compromise"]|[["skillpact"]]'
)
for def in "${CAMPAIGN_DEFS[@]}"; do
  IFS='|' read -r f camps secs <<<"$def"
  gen_campaign "$f" "$camps" "$secs" >"$TMP/$f.json"
  if [ "$SYNC" -eq 1 ]; then cp "$TMP/$f.json" "$REPO/rules/campaigns/$f.json"; fi
  if cmp -s "$TMP/$f.json" "$REPO/rules/campaigns/$f.json"; then ok "rules/campaigns/$f.json が ioc.json と同期"
  else ng "rules/campaigns/$f.json が ioc.json と非同期（--sync-campaigns で再生成）"; fi
done

# ---------------------------------------------------------------------------
echo "== フィクスチャ照合 =="
REQUIRED_TOP='["errors","findings","incident_bundle","scan_finished_at","scan_mode","scan_started_at","schema_version","status"]'
FINDING_KEYS='["campaign","detail","evidence_hash","id","level","module","path"]'
SP_KEYS='["author","contract_path","contract_version","declared_effects","diff_anomaly","divergence","l2_tested","level","observed_effects","policy_decision","signed"]'
for e in "$EXP"/*.json; do
  name="$(basename "$e" .json)"
  case "$name" in _*) continue ;; esac
  mode="$(jq -r '.mode' "$e")"
  home="$(jq -r '.home // "_home"' "$e")"
  root="$FIX/$name"
  [ "$home" = "self" ] && home="$root" || home="$FIX/$home"
  if ! run_scan "$root" "$mode" "$home" >"$TMP/out.json"; then ng "$name: zes-scan.sh が異常終了" "$(tail -n 5 "$TMP/stderr.txt")"; continue; fi
  if ! jq -e . "$TMP/out.json" >/dev/null 2>&1; then ng "$name: 出力が valid JSON ではない"; continue; fi
  # スキーマ（strict: 未知フィールドなし）
  bad="$(jq -r --argjson t "$REQUIRED_TOP" --argjson fk "$FINDING_KEYS" --argjson sk "$SP_KEYS" '
    [ (if (keys != $t) then "top-level keys: \(keys)" else empty end),
      (.findings[] | (keys - ["skillpact"]) as $k | select($k != $fk) | "finding keys: \($k)"),
      (.findings[] | select(has("skillpact")) | .skillpact | keys | select(. != $sk) | "skillpact keys: \(.)"),
      (.findings[] | select((.id | test("^sha256:[0-9a-f]{64}$")) | not) | "bad id: \(.id)"),
      (.findings[] | select(.level as $l | ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] | index($l) | not) | "bad level: \(.level)"),
      (.findings[] | select(.path != null and (.path | startswith("/") | not)) | "relative path: \(.path)"),
      (if (.status as $s | ["ok","partial","error"] | index($s)) then empty else "bad status" end) ] | .[]' "$TMP/out.json")"
  if [ -n "$bad" ]; then ng "$name: 出力スキーマ違反" "$bad"; continue; fi
  normalize "$root" <"$TMP/out.json" >"$TMP/actual.json"
  if [ "$UPDATE" -eq 1 ]; then
    hraw="$(jq -r '.home // "_home"' "$e")"
    jq -S -n --arg m "$mode" --arg h "$hraw" --slurpfile f "$TMP/actual.json" '{mode:$m, home:$h, findings:$f[0]}' >"$TMP/new-expected.json" && mv "$TMP/new-expected.json" "$e"
  fi
  jq -S '.findings' "$e" >"$TMP/expected.json"
  if diff -u "$TMP/expected.json" "$TMP/actual.json" >"$TMP/diff.txt"; then ok "$name ($mode): $(jq length "$TMP/actual.json") 件一致"
  else ng "$name ($mode): 期待値と不一致" "$(head -n 40 "$TMP/diff.txt")"; fi
done

# ---------------------------------------------------------------------------
echo "== 横断チェック =="
# schemas/findings.schema.json による検証（python3 + jsonschema がある場合。無ければ SKIP と明示）
if python3 -I -c 'import jsonschema' 2>/dev/null; then
  for m in full skillpact; do run_scan "$FIX" "$m" "$FIX/_home" >"$TMP/schema-$m.json"; done
  run_scan "$FIX/chaindrop" quick "$FIX/_home" env ZES_FORCE_NO_JQ=1 >"$TMP/schema-nojq.json"
  if out="$(python3 -I - "$REPO/schemas/findings.schema.json" "$TMP"/schema-*.json <<'PY' 2>&1
import json, sys
from jsonschema import Draft202012Validator
schema = json.load(open(sys.argv[1], encoding="utf-8"))
Draft202012Validator.check_schema(schema)
v = Draft202012Validator(schema)
bad = 0
for f in sys.argv[2:]:
    for e in v.iter_errors(json.load(open(f, encoding="utf-8"))):
        bad += 1
        print(f"{f.rsplit('/', 1)[-1]}: {'/'.join(map(str, e.absolute_path))}: {e.message}"[:300])
sys.exit(1 if bad else 0)
PY
)"; then ok "出力が schemas/findings.schema.json に適合（full / skillpact / jq なし）"
  else ng "出力が schemas/findings.schema.json に不適合" "$(printf '%s' "$out" | head -n 20)"; fi
else
  printf '  SKIP schemas/findings.schema.json の検証（python3 の jsonschema が未導入）\n'
fi

# 決定的 ID（再スキャンで同一）
run_scan "$FIX/skillpact-divergence" skillpact "$FIX/_home" | jq -r '[.findings[].id] | sort | join(",")' >"$TMP/id1"
run_scan "$FIX/skillpact-divergence" skillpact "$FIX/_home" | jq -r '[.findings[].id] | sort | join(",")' >"$TMP/id2"
cmp -s "$TMP/id1" "$TMP/id2" && [ -s "$TMP/id1" ] && ok "findings[].id が決定的" || ng "findings[].id が再スキャンで変化"

# findings.skillpact フィールド（§49 の全 finding に付与）
n="$(run_scan "$FIX" skillpact "$FIX/_home" | jq '[.findings[] | select(.module == "§49" and (has("skillpact") | not))] | length')"
[ "$n" = "0" ] && ok "§49 の全 finding に skillpact フィールド" || ng "skillpact フィールドの無い §49 finding が $n 件"

# L3 署名は重大度を下げない（同一乖離で signed=true でも CRITICAL）
lv="$(run_scan "$FIX/skillpact-signed-divergence" skillpact "$FIX/_home" | jq -r '[.findings[] | select(.skillpact.signed == true and (.skillpact.divergence | length) > 0) | .level] | unique | join(",")')"
[ "$lv" = "CRITICAL" ] && ok "L3 署名済みでも乖離は CRITICAL（L3 を信頼判定に使わない）" || ng "L3 署名済み乖離の重大度が CRITICAL ではない: $lv"

# 内容非読取: フィクスチャ内の秘密様文字列が出力に含まれない
out="$(run_scan "$FIX" full "$FIX/_home")"
if printf '%s' "$out" | grep -q -E 'cHJpbnQoMSk=|zes-canary|libprocesshider|collector\.example\.invalid|updates\.example\.invalid'; then ng "出力にファイル内容が含まれています"
else ok "出力にファイル内容を含まない（パスとメタ情報のみ）"; fi
printf '%s' "$out" | jq -e '.scan_mode == "full"' >/dev/null && ok "--full が完走し valid JSON" || ng "--full の出力が不正"
for m in quick standard worm skillpact; do
  run_scan "$FIX" "$m" "$FIX/_home" | jq -e --arg m "$m" '.scan_mode == $m and (.status | IN("ok","partial"))' >/dev/null \
    && ok "--$m が完走し valid JSON" || ng "--$m の出力が不正"
done

# jq なし（grep フォールバック）でも主要 IoC を検出し、§49 は未確定（errors[]）として扱う
nojq="$(run_scan "$FIX/chaindrop" quick "$FIX/_home" env ZES_FORCE_NO_JQ=1)"
printf '%s' "$nojq" | jq -e '[.findings[] | select(.level=="CRITICAL" and .module=="§15")] | length >= 3' >/dev/null \
  && ok "jq なしフォールバックで ChainDrop/keyv/solana を検出" || ng "jq なしフォールバックの検出が不足"
run_scan "$FIX/skillpact-divergence" skillpact "$FIX/_home" env ZES_FORCE_NO_JQ=1 | jq -e '.status == "partial" and ([.errors[] | select(.module=="§49" and .reason=="jq_unavailable")] | length == 1)' >/dev/null \
  && ok "jq なしでは §49 を errors[] に記録（0件扱いしない / fail-closed）" || ng "jq なしの §49 が fail-closed になっていない"

# ZES 自身のディレクトリは IoC を含むため、外側のルートから走査した場合は除外される
mkdir -p "$TMP/outer"
cp -R "$REPO/zes-scan.sh" "$REPO/rules" "$REPO/tests" "$TMP/outer/" 2>/dev/null
mkdir -p "$TMP/outer-root" && mv "$TMP/outer" "$TMP/outer-root/zes"
n="$(ZES_HOST_CHECKS=0 ZES_OFFLINE=1 ZES_HOME="$FIX/_home" "$TMP/outer-root/zes/zes-scan.sh" --quick --root "$TMP/outer-root" --json 2>/dev/null | jq --arg r "$TMP/outer-root/zes/" '[.findings[] | select((.path // "") | startswith($r))] | length' 2>/dev/null)"
[ "${n:-x}" = "0" ] && ok "ZES 自身（rules/tests/docs）を外側から走査した場合は除外" || ng "ZES 自身のファイルを検出しています（$n 件）"

# 読めない MCP 設定（JSONC として読み直しても不正）は errors[] に記録する（fail-closed）
mkdir -p "$TMP/badmcp" && printf '{ "mcpServers": { "x": { "command": "bash" ' >"$TMP/badmcp/.mcp.json"
run_scan "$TMP/badmcp" quick "$FIX/_home" | jq -e '[.errors[] | select(.module == "§17" and (.reason | startswith("mcp_config_parse_failed:")))] | length == 1' >/dev/null \
  && ok "不正な MCP 設定を errors[] に記録（0件扱いしない）" || ng "不正な MCP 設定が errors[] に記録されていません"
# intel の jq フィルタが失敗した場合は errors[] に記録する（ホスト IoC 等が黙って無効化されない）
jq '.intel.host = [{"campaign": "zes-test", "paths": 5}]' "$IOC" >"$TMP/ioc-broken-intel.json"
mkdir -p "$TMP/empty-root"
ZES_IOC="$TMP/ioc-broken-intel.json" run_scan "$TMP/empty-root" standard "$FIX/_home" | jq -e '[.errors[] | select(.module == "§30" and (.reason | startswith("intel_jq_failed:")))] | length >= 1' >/dev/null \
  && ok "intel の jq 失敗を errors[] に記録（fail-closed）" || ng "intel の jq 失敗が errors[] に記録されていません"

# 引数検証（fail-closed）
"$SCAN" --root /nonexistent-zes-dir >/dev/null 2>&1; [ $? -eq 64 ] && ok "存在しない --root を拒否" || ng "存在しない --root を受理"
"$SCAN" --quick --url 'file:///etc/passwd' >/dev/null 2>&1; [ $? -eq 64 ] && ok "http(s) 以外の --url を拒否" || ng "不正な --url を受理"
"$SCAN" --quick --full >/dev/null 2>&1; [ $? -eq 64 ] && ok "モード重複指定を拒否" || ng "モード重複指定を受理"
# '-' 始まりの --root は cd のオプションと解釈させない（空ルートで exit 0 にしない）
mkdir -p "$TMP/dash" && cp -R "$FIX/chaindrop" "$TMP/dash/-dash"
n="$(cd "$TMP/dash" && ZES_HOST_CHECKS=0 ZES_OFFLINE=1 ZES_HOME="$FIX/_home" "$SCAN" --quick --root -dash --json 2>/dev/null | jq --arg r "$TMP/dash/-dash/" '[.findings[] | select((.path // "") | startswith($r))] | length' 2>/dev/null)"
[ "${n:-0}" -gt 0 ] && ok "'-' で始まる --root を走査（cd -- で解決）" || ng "'-' で始まる --root を走査していません（${n:-?} 件）"
# export された CDPATH で相対 --root が別ディレクトリへ解決されない
mkdir -p "$TMP/cdpath/decoy/chaindrop" "$TMP/cdpath/cwd" && cp -R "$FIX/chaindrop" "$TMP/cdpath/cwd/chaindrop"
n="$(cd "$TMP/cdpath/cwd" && CDPATH="$TMP/cdpath/decoy" ZES_HOST_CHECKS=0 ZES_OFFLINE=1 ZES_HOME="$FIX/_home" "$SCAN" --quick --root chaindrop --json 2>/dev/null | jq --arg r "$TMP/cdpath/cwd/chaindrop/" '[.findings[] | select((.path // "") | startswith($r))] | length' 2>/dev/null)"
[ "${n:-0}" -gt 0 ] && ok "CDPATH が相対 --root を書き換えない" || ng "CDPATH により相対 --root が別ディレクトリへ解決されました（${n:-?} 件）"

echo
echo "結果: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
