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
  'skillpact|["skillpact-undeclared","skillpact-invalid","skillpact-divergence","skillpact-account-compromise"]|[["skillpact"]]'
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
      ([.findings[].id] | group_by(.) | map(select(length > 1) | "duplicate id: \(.[0]) x\(length)") | .[]),
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

# 決定的 ID（再スキャンで同一）。負荷の高いときにだけ変わる競合（パイプ末尾の grep -q と pipefail で上流が SIGPIPE）を
#   拾うため、同じフィクスチャを並列に 8 回ずつ走査し、id・evidence・locators の多重集合が全て同じことを確かめる
det_ok=1; det_msg=""
for nm in skillpact-divergence browser-ext mcp chaindrop; do
  dm="$(jq -r '.mode' "$EXP/$nm.json")"
  for i in 1 2 3 4 5 6 7 8; do
    ( run_scan "$FIX/$nm" "$dm" "$FIX/_home" 2>/dev/null | jq -c '[.findings[].id] | sort' >"$TMP/det-$nm-$i" ) &
  done
  wait
  for i in 2 3 4 5 6 7 8; do
    cmp -s "$TMP/det-$nm-1" "$TMP/det-$nm-$i" || { det_ok=0; det_msg="$det_msg $nm#$i"; }
  done
  [ "$(jq length "$TMP/det-$nm-1" 2>/dev/null || echo 0)" -gt 0 ] || { det_ok=0; det_msg="$det_msg $nm:empty"; }
done
[ "$det_ok" -eq 1 ] && ok "findings[].id が決定的（4 フィクスチャ × 並列 8 回で同一）" || ng "findings[].id 等が再スキャンで変化:$det_msg"
# パイプの末尾で grep -q を使わない（上流が SIGPIPE で失敗すると pipefail で「一致したのに偽」になる。grep_q を使う）
n="$(grep -c -E '\|[[:space:]]*grep[[:space:]]+(-[A-Za-z]*q|[^|]*[[:space:]]-[A-Za-z]*q)([[:space:]]|$)' "$SCAN")"
[ "$n" = "0" ] && ok "zes-scan.sh のパイプ末尾に grep -q が無い（grep_q で入力を読み切る）" || ng "zes-scan.sh のパイプ末尾に grep -q が $n 箇所"

# findings.skillpact フィールド（§49 の全 finding に付与）
n="$(run_scan "$FIX" skillpact "$FIX/_home" | jq '[.findings[] | select(.module == "§49" and (has("skillpact") | not))] | length')"
[ "$n" = "0" ] && ok "§49 の全 finding に skillpact フィールド" || ng "skillpact フィールドの無い §49 finding が $n 件"

# 署名は重大度を変えない（ZES は署名を検証しない）: 署名付き契約の未宣言 network も HIGH
lv="$(run_scan "$FIX/skillpact-signed-divergence" skillpact "$FIX/_home" | jq -r '[.findings[] | select(.skillpact.signed == true and (.skillpact.divergence | index("network"))) | select(.campaign == "skillpact-divergence") | .level] | unique | join(",")')"
[ "$lv" = "HIGH" ] && ok "署名付き契約でも未宣言 network は HIGH（署名を信頼判定に使わない）" || ng "署名付き契約の乖離の重大度が HIGH ではない: $lv"
# 実在する SkillPact 形式の契約（tests/fixtures/skillpact-clean）は §49 で何も報告しない（誤検知なし）
n="$(run_scan "$FIX/skillpact-clean" skillpact "$FIX/_home" | jq '.findings | length')"
[ "$n" = "0" ] && ok "有効な SkillPact 0.8 契約で §49 の検出 0 件" || ng "有効な SkillPact 契約で $n 件を検出（誤検知）"
# §49 は CRITICAL を出さない（契約は自己申告。乖離は最大 HIGH）
n="$(run_scan "$FIX" skillpact "$FIX/_home" | jq '[.findings[] | select(.module == "§49" and .level == "CRITICAL")] | length')"
[ "$n" = "0" ] && ok "§49 は CRITICAL を出さない" || ng "§49 が CRITICAL を $n 件出力"

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
# 解釈できない Codex TOML（閉じていない見出し・command 無し・command が配列）は errors[] に記録する（fail-closed）
n="$(run_scan "$FIX/codex-toml-broken" quick "$FIX/_home" | jq '[.errors[] | select(.module == "§17" and (.reason | startswith("codex_toml_unparsed:")))] | length')"
[ "$n" = "3" ] && ok "解釈できない Codex TOML を errors[] に記録（3 件）" || ng "解釈できない Codex TOML の errors[] が 3 件ではありません（${n:-?} 件）"
# intel の jq フィルタが失敗した場合は errors[] に記録する（ホスト IoC 等が黙って無効化されない）
jq '.intel.host = [{"campaign": "zes-test", "paths": 5}]' "$IOC" >"$TMP/ioc-broken-intel.json"
mkdir -p "$TMP/empty-root"
ZES_IOC="$TMP/ioc-broken-intel.json" run_scan "$TMP/empty-root" standard "$FIX/_home" | jq -e '[.errors[] | select(.module == "§30" and (.reason | startswith("intel_jq_failed:")))] | length >= 1' >/dev/null \
  && ok "intel の jq 失敗を errors[] に記録（fail-closed）" || ng "intel の jq 失敗が errors[] に記録されていません"

# ホスト検査を有効にしても findings[].path は絶対パスか null（"auditd" / "crontab:user" 等の疑似パスを出さない）
mkdir -p "$TMP/host-root" "$TMP/host-home"
bad="$(ZES_HOST_CHECKS=1 ZES_OFFLINE=1 ZES_HOME="$TMP/host-home" "$SCAN" --full --root "$TMP/host-root" --json 2>/dev/null \
  | jq -r '[.findings[] | select(.path != null and (.path | startswith("/") | not)) | .path] | join(",")' 2>/dev/null)"
[ -z "$bad" ] && ok "ホスト検査の findings[].path が絶対パスか null" || ng "ホスト検査で絶対パスでない path: $bad"

# intel.host の絶対パスはホストの実パスのみ照合（ZES_HOST_CHECKS=1 のときだけ。検査ルート内の同名サフィックスは見ない）
mkdir -p "$TMP/hostioc" "$TMP/hostioc-root$TMP/hostioc" && : >"$TMP/hostioc/marker" && : >"$TMP/hostioc-root$TMP/hostioc/marker"
jq --arg p "$TMP/hostioc/marker" '.intel.host = [{"campaign": "zes-test-host", "severity": "HIGH", "paths": [$p]}]' "$IOC" >"$TMP/ioc-hostpath.json"
on="$(ZES_IOC="$TMP/ioc-hostpath.json" ZES_HOST_CHECKS=1 ZES_OFFLINE=1 ZES_HOME="$TMP/host-home" "$SCAN" --standard --root "$TMP/hostioc-root" --json 2>/dev/null | jq -r '[.findings[] | select(.campaign == "zes-test-host") | .path] | join(",")')"
off="$(ZES_IOC="$TMP/ioc-hostpath.json" run_scan "$TMP/hostioc-root" standard "$TMP/host-home" | jq -r '[.findings[] | select(.campaign == "zes-test-host") | .path] | join(",")')"
[ "$on" = "$TMP/hostioc/marker" ] && [ -z "$off" ] && ok "intel.host の絶対パスはホスト検査時の実パスのみ照合" || ng "intel.host の絶対パスの照合先が不正（on=$on off=$off）"

# 検査対象 .git/config の include.path（FIFO）で走査が停止しない / git が停止したら timeout で errors[] に記録
if command -v git >/dev/null 2>&1 && command -v mkfifo >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then
  for k in inc pr; do
    ( export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
      mkdir -p "$TMP/git-$k" && cd "$TMP/git-$k" && git init -q . && echo inert >README && git add README \
        && git -c user.name=a -c user.email=a@example.invalid commit -q -m init ) >/dev/null 2>&1
  done
  mkfifo "$TMP/git-inc/.git/hang.fifo" && printf '[include]\n\tpath = hang.fifo\n[includeIf "gitdir:/"]\n\tpath = hang.fifo\n' >>"$TMP/git-inc/.git/config"
  out="$(ZES_GIT_TIMEOUT=10 timeout 120 env ZES_HOST_CHECKS=0 ZES_OFFLINE=1 ZES_HOME="$FIX/_home" "$SCAN" --full --root "$TMP/git-inc" --json 2>/dev/null)"
  # include の参照先（FIFO）は読まずに git_include_unresolved を記録し、git の失敗（git_timeout 等）は起きない
  printf '%s' "$out" | jq -e '([.findings[] | select(.module == "§46" and (.detail | test("1 コミット中")))] | length == 1) and ([.errors[] | select(.reason | test("^git_")) | select(.reason | test("^git_include_unresolved:") | not)] | length == 0) and ([.errors[] | select(.reason | test("^git_include_unresolved:"))] | length >= 1)' >/dev/null 2>&1 \
    && ok "検査対象 .git/config の include.path（FIFO）を読まずに §46 を完走（errors[] に git_include_unresolved）" || ng "include.path（FIFO）で走査が停止または §46 が失敗"
  mkfifo "$TMP/git-pr/.git/packed-refs"
  out="$(ZES_GIT_TIMEOUT=2 timeout 120 env ZES_HOST_CHECKS=0 ZES_OFFLINE=1 ZES_HOME="$FIX/_home" "$SCAN" --full --root "$TMP/git-pr" --json 2>/dev/null)"
  printf '%s' "$out" | jq -e '[.errors[] | select(.module == "§46" and .reason == "git_timeout")] | length >= 1' >/dev/null 2>&1 \
    && ok "git が停止した場合は timeout で打ち切り errors[] に git_timeout を記録" || ng "git の停止が errors[] に記録されていません"
else
  printf '  SKIP git/mkfifo/timeout が無いため .git の FIFO チェックを省略\n'
fi

# ファイル名の制御文字・不正 UTF-8: JSON は valid UTF-8、id は出力した値から再計算可能、人間向けログに ESC を出さない
mkdir -p "$TMP/names"
for nm in $'esc\033[31m' $'bad\377\376' $'c1\302\233' 'back\x41slash' $'tab\tname'; do
  mkdir -p "$TMP/names/$nm" && printf '// ZES test fixture\nconst p = ".claude/";\n' >"$TMP/names/$nm/setup.mjs"
done
run_scan "$TMP/names" quick "$FIX/_home" >"$TMP/names.json"; cp "$TMP/stderr.txt" "$TMP/names.log"
if python3 -I -c 'pass' 2>/dev/null; then
  if out="$(python3 -I - "$TMP/names.json" <<'PY' 2>&1
import hashlib, json, sys
raw = open(sys.argv[1], "rb").read()
d = json.loads(raw.decode("utf-8"))  # strict UTF-8
bad = [f["path"] for f in d["findings"] if f["id"] != "sha256:" + hashlib.sha256("|".join([f["module"], f["campaign"] or "", f["path"] or "", f["detail"]]).encode()).hexdigest()]
n = len([f for f in d["findings"] if f["module"] == "§17"])
nu = len([e for e in d["errors"] if e["module"] == "core" and e["reason"].startswith("non_utf8_path:") and "\\xff\\xfe" in e["reason"]])
print(f"mismatch={bad} s17={n} non_utf8={nu}")
sys.exit(0 if not bad and n == 5 and nu == 1 else 1)
PY
)"; then ok "制御文字・不正 UTF-8 のパス: valid UTF-8 JSON・id 再計算一致・errors[] に non_utf8_path"
  else ng "制御文字・不正 UTF-8 のパスの出力が不正" "$out"; fi
else
  printf '  SKIP 不正 UTF-8 パスの JSON 検証（python3 が無い）\n'
fi
# 正規形の衝突: "\xfe" という 4 文字の名前と不正なバイト 0xFE の名前は同じ path・id になる。id は一意に保ち、
# 落とした重複は errors[] に duplicate_finding_id として記録する（ZET は id の重複した入力を拒否する）
mkdir -p "$TMP/collide/a"$'\xfe' "$TMP/collide/a\xfe"
for d in "$TMP/collide/a"$'\xfe' "$TMP/collide/a\xfe"; do cp "$FIX/mcp/.mcp.json" "$d/"; done
run_scan "$TMP/collide" quick "$FIX/_home" | jq -e '([.findings[].id] | length) == ([.findings[].id] | unique | length)
  and ([.errors[] | select(.module == "core" and (.reason | test("^duplicate_finding_id:sha256:[0-9a-f]{64}$")))] | length >= 1)
  and .status == "partial"' >/dev/null \
  && ok "正規形が衝突するパスでも id は一意、落とした重複は errors[] に duplicate_finding_id" \
  || ng "正規形が衝突するパスで id が重複、または errors[] に記録されていません"
if grep -q $'\033' "$TMP/names.log"; then ng "人間向けログに ESC（端末エスケープ）がそのまま出力されています"
else ok "人間向けログの制御文字を \\xHH で表示（端末エスケープ注入なし）"; fi
# ZES_HOME は実パスへ正規化（相対パス・末尾スラッシュ・存在しないディレクトリ）
bad="$(cd "$FIX" && ZES_HOST_CHECKS=0 ZES_OFFLINE=1 ZES_HOME="_home/" "$SCAN" --quick --root "$TMP/empty-root" --json 2>/dev/null \
  | jq -r --arg h "$FIX/_home/" '[.findings[] | select(.path != null) | select((.path | startswith($h) | not) or (.path | contains("//"))) | .path] | join(",")')"
n="$(cd "$FIX" && ZES_HOST_CHECKS=0 ZES_OFFLINE=1 ZES_HOME="_home/" "$SCAN" --quick --root "$TMP/empty-root" --json 2>/dev/null | jq '.findings | length')"
[ -z "$bad" ] && [ "${n:-0}" -gt 0 ] && ok "相対・末尾スラッシュ付き ZES_HOME を実パスに正規化" || ng "ZES_HOME が正規化されていません: ${bad:-findings=$n}"
ZES_HOME="$TMP/nonexistent-home" "$SCAN" --quick --root "$TMP/empty-root" >/dev/null 2>&1; [ $? -eq 64 ] && ok "存在しない ZES_HOME を拒否" || ng "存在しない ZES_HOME を受理"

# 検査ルート内の FIFO・ソケット等は開かずに errors[] に special_file として記録する（黙って捨てない）
if command -v mkfifo >/dev/null 2>&1; then
  mkdir -p "$TMP/special" && mkfifo "$TMP/special/pipe.fifo"
  run_scan "$TMP/special" quick "$FIX/_home" | jq -e --arg p "special_file:$TMP/special/pipe.fifo" '[.errors[] | select(.module == "core" and .reason == $p)] | length == 1' >/dev/null 2>&1 \
    && ok "検査ルート内の FIFO を errors[] に special_file として記録" || ng "検査ルート内の FIFO が errors[] に記録されていません"
fi

# §4 --url: Server と X-Powered-By の PHP/x.y.z を判定、HEAD が 405 のときだけ GET、リダイレクトは追わない
#   ローカルの HTTP サーバー（python3、テスト専用）に対して実行する
if python3 -I -c 'import http.server' 2>/dev/null && command -v curl >/dev/null 2>&1; then
  python3 -I - "$TMP/http-port" "$TMP/http-log" <<'PY' >/dev/null 2>&1 &
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def reply(self, body):
        open(sys.argv[2], "a").write(f"{self.command} {self.path}\n")
        if self.path == "/redir":
            self.send_response(301); self.send_header("Location", "/vuln"); self.end_headers(); return
        if self.command == "HEAD" and self.path == "/":
            self.send_response(405); self.end_headers(); return
        self.send_response(200)
        self.send_header("Server", "Apache/2.4.58 (Ubuntu) PHP/8.3.10")
        self.send_header("X-Powered-By", "PHP/8.5.12")
        self.end_headers()
        if body: self.wfile.write(b"zes\n")
    def do_HEAD(self): self.reply(False)
    def do_GET(self): self.reply(True)
s = http.server.HTTPServer(("127.0.0.1", 0), H)
open(sys.argv[1], "w").write(str(s.server_port))
s.timeout = 30
for _ in range(6): s.handle_request()
PY
  hpid=$!
  for _ in $(seq 1 50); do [ -s "$TMP/http-port" ] && break; sleep 0.1; done
  port="$(cat "$TMP/http-port" 2>/dev/null)"
  urlscan() { env -u http_proxy -u HTTP_PROXY -u https_proxy -u HTTPS_PROXY -u ALL_PROXY -u all_proxy NO_PROXY='*' \
    ZES_HOST_CHECKS=0 ZES_OFFLINE=0 ZES_HOME="$FIX/_home" "$SCAN" --quick --root "$TMP/empty-root" --url "http://127.0.0.1:$port$1" --json 2>/dev/null; }
  out="$(urlscan /)"
  printf '%s' "$out" | jq -e '[.findings[] | select(.module == "§4" and .level == "HIGH" and (.detail | test("8\\.3\\.10")))] | length == 1' >/dev/null 2>&1 \
    && printf '%s' "$out" | jq -e '[.findings[] | select(.module == "§4" and .level == "MEDIUM" and (.detail | test("X-Powered-By")))] | length == 1' >/dev/null 2>&1 \
    && ok "--url: Server ヘッダの PHP/8.3.10 を HIGH（ヘッダ申告版）で判定し、X-Powered-By の露出も報告" || ng "--url の PHP ヘッダ判定が不正"
  out="$(urlscan /redir)"
  printf '%s' "$out" | jq -e '[.findings[] | select(.module == "§4" and .level == "HIGH")] | length == 0' >/dev/null 2>&1 \
    && ok "--url: リダイレクト先を追わない" || ng "--url がリダイレクトを追っています"
  kill "$hpid" 2>/dev/null; wait "$hpid" 2>/dev/null
  [ "$(tr '\n' ',' <"$TMP/http-log" 2>/dev/null)" = "HEAD /,GET /,HEAD /redir," ] && ok "--url: HEAD → 405 のときだけ GET（リクエスト列: HEAD /,GET /,HEAD /redir）" \
    || ng "--url のリクエスト列が不正: $(tr '\n' ',' <"$TMP/http-log" 2>/dev/null)"
else
  printf '  SKIP --url のローカル HTTP テスト（python3 または curl が無い）\n'
fi

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

# 版の一致: CHANGELOG の先頭の版 = zes-scan.sh の ZES_VERSION = ui/package.json の version
if out="$(bash "$TESTS_DIR/check-versions.sh" 2>&1)"; then ok "$out"; else ng "版がずれています" "$out"; fi
# ---------------------------------------------------------------------------
echo "== round 3（CLI の検出回避・fail-closed） =="
# R3-01: PATH の相対・空のエントリと、実パスが検査ルート配下のエントリは外し、errors[] に path_entry_dropped を記録する
mkdir -p "$TMP/pathroot/node_modules/.bin"
printf '#!/bin/sh\n: >"%s/path-canary"\nexec /usr/bin/env jq "$@"\n' "$TMP" >"$TMP/pathroot/node_modules/.bin/jq"; chmod +x "$TMP/pathroot/node_modules/.bin/jq"
out="$(cd "$TMP/pathroot/node_modules/.bin" && PATH=".:$TMP/pathroot/node_modules/.bin:$PATH" run_scan "$TMP/pathroot" quick "$FIX/_home")"
printf '%s' "$out" | jq -e --arg p "path_entry_dropped:$TMP/pathroot/node_modules/.bin" '([.errors[] | select(.module == "core" and (.reason == "path_entry_dropped:." or .reason == $p))] | length == 2)' >/dev/null 2>&1 \
  && [ ! -e "$TMP/path-canary" ] && ok "PATH の相対エントリ・検査ルート配下のエントリを外し errors[] に記録（ルート内の jq を起動しない）" \
  || ng "PATH の無害化が不正（canary=$([ -e "$TMP/path-canary" ] && echo yes || echo no)）"

# R3-02: .git ファイル（gitdir:）・入れ子のリポジトリ・include.path の参照先の Git 設定を静的に検査し、git には読ませない
if command -v git >/dev/null 2>&1; then
  printf '#!/bin/sh\n: >"%s/git-r3-canary"\n' "$TMP" >"$TMP/git-r3-pwn.sh"; chmod +x "$TMP/git-r3-pwn.sh"
  ginit() { ( export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1; mkdir -p "$1" && cd "$1" && git init -q . ) >/dev/null 2>&1; }
  # gitdir: ファイル（.git がファイルで、実体は gd/）
  ginit "$TMP/r3git/gitfile" && mv "$TMP/r3git/gitfile/.git" "$TMP/r3git/gitfile/gd" && printf 'gitdir: gd\n' >"$TMP/r3git/gitfile/.git" \
    && printf '\tfsmonitor = %s\n' "$TMP/git-r3-pwn.sh" >>"$TMP/r3git/gitfile/gd/config"
  # 入れ子のリポジトリ（vendor/lib/.git）
  ginit "$TMP/r3git/nested" && ginit "$TMP/r3git/nested/vendor/lib" && printf '\tfsmonitor = %s\n' "$TMP/git-r3-pwn.sh" >>"$TMP/r3git/nested/vendor/lib/.git/config"
  # include.path の参照先（../tools.cfg）
  ginit "$TMP/r3git/include" && printf '[include]\n\tpath = ../tools.cfg\n' >>"$TMP/r3git/include/.git/config" \
    && printf '[core]\n\tfsmonitor = %s\n' "$TMP/git-r3-pwn.sh" >"$TMP/r3git/include/tools.cfg"
  # 検査ルート外を指す gitdir:（git worktree 等）は読まずに errors[] に記録
  mkdir -p "$TMP/r3git/outside" && printf 'gitdir: %s/r3git/gitfile/gd\n' "$TMP" >"$TMP/r3git/outside/.git"
  # .git/config がルート外（/proc 等）を指すリンク: 読まずに errors[] に記録し、走査が停止しない
  ginit "$TMP/r3git/proclink" && rm -f "$TMP/r3git/proclink/.git/config" && ln -s /proc/self/status "$TMP/r3git/proclink/.git/config"
  for k in gitfile:gd/config nested:vendor/lib/.git/config include:tools.cfg; do
    r="$TMP/r3git/${k%%:*}"
    run_scan "$r" full "$FIX/_home" >"$TMP/r3git.json"
    jq -e --arg p "$r/${k#*:}" '[.findings[] | select(.module == "§26" and .level == "CRITICAL" and .path == $p)] | length == 1' "$TMP/r3git.json" >/dev/null 2>&1 \
      && ok "Git 設定を静的に検査（${k%%:*}: ${k#*:} の core.fsmonitor を CRITICAL）" || ng "Git 設定（${k%%:*}）の core.fsmonitor を検出していません"
  done
  run_scan "$TMP/r3git/outside" quick "$FIX/_home" | jq -e --arg p "gitdir_outside_root:$TMP/r3git/outside/.git" '[.errors[] | select(.reason == $p)] | length == 1' >/dev/null 2>&1 \
    && ok "検査ルート外を指す gitdir: を errors[] に gitdir_outside_root として記録" || ng "検査ルート外を指す gitdir: が errors[] に記録されていません"
  out="$(ZES_GIT_TIMEOUT=10 timeout 120 env ZES_HOST_CHECKS=0 ZES_OFFLINE=1 ZES_HOME="$FIX/_home" "$SCAN" --full --root "$TMP/r3git/proclink" --json 2>/dev/null)"
  printf '%s' "$out" | jq -e --arg p "path_leaves_root:$TMP/r3git/proclink/.git/config" '[.errors[] | select(.reason == $p)] | length == 1' >/dev/null 2>&1 \
    && ok ".git/config がルート外（/proc）を指すリンクは読まずに errors[] に path_leaves_root" || ng ".git/config のルート外リンクの扱いが不正"
  [ -e "$TMP/git-r3-canary" ] && ng "検査対象の Git 設定（fsmonitor）が実行されました" || ok "検査対象の Git 設定（gitdir: / 入れ子 / include）を実行しない"

  # R3-21: §38 の git log はパスを C 形式で引用させない（core.quotePath=false と -z）
  ( export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
    mkdir -p "$TMP/r3qp/.github/workflows" && cd "$TMP/r3qp" && git init -q . \
      && printf 'on: push\njobs: {}\n' >".github/workflows/été.yml" && printf 'on: push\njobs: {}\n' >'.github/workflows/a"b.yml' && git add -A \
      && GIT_COMMITTER_DATE="@$((1792800000 - 86400)) +0000" GIT_AUTHOR_DATE="@$((1792800000 - 86400)) +0000" git -c user.name=a -c user.email=a@example.invalid commit -q -m init ) >/dev/null 2>&1
  n="$(run_scan "$TMP/r3qp" full "$FIX/_home" | jq --arg a "$TMP/r3qp/.github/workflows/été.yml" --arg b "$TMP/r3qp/.github/workflows/a\"b.yml" '[.findings[] | select(.module == "§38" and (.path == $a or .path == $b))] | length')"
  [ "$n" = "2" ] && ok "§38 の新規ワークフローのパスを引用符・\\NNN なしで出力（é / \" を含む名前）" || ng "§38 のパスが C 形式で引用されています（一致 ${n:-?} 件）"

  # K2: timeout が無い環境（bash のウォッチドッグ）でも孤児の sleep を残さない
  mkdir -p "$TMP/notimeout"
  for b in /usr/bin/* /bin/*; do n="${b##*/}"; [ "$n" = timeout ] || [ -e "$TMP/notimeout/$n" ] || ln -s "$b" "$TMP/notimeout/$n" 2>/dev/null; done
  ZES_GIT_TIMEOUT=37 PATH="$TMP/notimeout" ZES_HOST_CHECKS=0 ZES_OFFLINE=1 ZES_HOME="$FIX/_home" "$SCAN" --full --root "$TMP/r3qp" --json >/dev/null 2>&1
  sleep 1
  n="$(pgrep -f -x 'sleep 37' 2>/dev/null | wc -l | tr -d ' ')"
  [ "$n" = "0" ] && ok "timeout が無い環境のウォッチドッグが sleep を残さない" || ng "ウォッチドッグの sleep が ${n} 個残っています"
else
  printf '  SKIP git が無いため round 3 の Git 設定チェックを省略\n'
fi

# R3-07 / R3-08: パスのバックスラッシュを awk -v で展開しない（行の偽造・パスの改変をしない）
mkdir -p "$TMP/r3bs/app\\nx" "$TMP/r3bs/q\\nnpm\\tkeyv\\t6.0.0\\tz"
printf '# yarn lockfile v1\n\n"keyv@^6.0.0":\n  version "6.0.0"\n' >"$TMP/r3bs/app\\nx/yarn.lock"
printf '# yarn lockfile v1\n\n"left-pad@^1.0.0":\n  version "1.3.0"\n' >"$TMP/r3bs/q\\nnpm\\tkeyv\\t6.0.0\\tz/yarn.lock"
out="$(run_scan "$TMP/r3bs" worm "$FIX/_home")"
printf '%s' "$out" | jq -e --arg p "$TMP/r3bs/app\\nx/yarn.lock" '[.findings[] | select(.module == "§15")] | (length == 1 and .[0].path == $p)' >/dev/null 2>&1 \
  && ok "パス中の \\n / \\t を awk で展開しない（偽の依存行を作らせない・パスを変えない）" || ng "パスのバックスラッシュで §15 の結果が変わっています"

# R3-10: リンク名の設定（.mcp.json → cfg/servers.json）を検査。ルート外を指す設定名のリンクは errors[] に記録
printf '%s' "$(run_scan "$FIX/r3-symlink-config" quick "$FIX/_home")" | jq -e --arg p "symlink_leaves_root:$FIX/r3-symlink-config/out/.mcp.json" '[.errors[] | select(.reason == $p)] | length == 1' >/dev/null 2>&1 \
  && ok "検査ルート外を指す設定名のリンクを errors[] に symlink_leaves_root として記録" || ng "ルート外を指す設定名のリンクが errors[] に記録されていません"

# R3-05: YAML のエイリアスは解決せず errors[] に記録
run_scan "$FIX/r3-actions" quick "$FIX/_home" >/dev/null
run_scan "$FIX/r3-actions" standard "$FIX/_home" | jq -e --arg p "yaml_alias_unresolved:$FIX/r3-actions/.github/workflows/alias.yml" '[.errors[] | select(.module == "§21" and .reason == $p)] | length == 1' >/dev/null 2>&1 \
  && ok "YAML のエイリアス（*x）を errors[] に yaml_alias_unresolved として記録" || ng "YAML のエイリアスが errors[] に記録されていません"

# R3-17: bun.lockb（バイナリ）は解析せず errors[] に lockfile_unparsed
run_scan "$FIX/r3-lockfiles" worm "$FIX/_home" | jq -e --arg p "lockfile_unparsed:$FIX/r3-lockfiles/bunb/bun.lockb" '[.errors[] | select(.module == "§15" and .reason == $p)] | length == 1' >/dev/null 2>&1 \
  && ok "bun.lockb を errors[] に lockfile_unparsed として記録" || ng "bun.lockb が errors[] に記録されていません"

# NV-1: アーカイブは展開せず errors[] に archive_not_inspected（status は ok のまま）
run_scan "$FIX/r3-archive" worm "$FIX/_home" | jq -e --arg p "archive_not_inspected:$FIX/r3-archive/vendor/zes_demo-1.0-py3-none-any.whl" '.status == "ok" and ([.errors[] | select(.module == "core" and .reason == $p)] | length == 1)' >/dev/null 2>&1 \
  && ok "アーカイブを errors[] に archive_not_inspected として記録（status は ok のまま）" || ng "アーカイブの扱いが不正"

# R3-18: HOME の監視パスに空白があっても（~/Library/Application Support/…）ブラウザ拡張を検査
mkdir -p "$TMP/r3home/Library/Application Support/Google/Chrome/Default/Extensions/abcd/1.0" "$TMP/r3empty"
cp "$FIX/browser-ext/Extensions/abcd/manifest.json" "$TMP/r3home/Library/Application Support/Google/Chrome/Default/Extensions/abcd/1.0/manifest.json"
run_scan "$TMP/r3empty" standard "$TMP/r3home" | jq -e --arg p "$TMP/r3home/Library/Application Support/Google/Chrome/Default/Extensions/abcd/1.0/manifest.json" '[.findings[] | select(.module == "§24" and .path == $p)] | length >= 1' >/dev/null 2>&1 \
  && ok "空白を含む HOME 監視パス（Application Support）のブラウザ拡張を検査" || ng "Application Support 配下のブラウザ拡張を検査していません"

# R3-24: --root の値・引数エラーの値の制御文字を端末に出さない
d="$TMP/r3esc/pkg"$'\033]0;pwned\007\033[2J'
mkdir -p "$d"
run_scan "$d" quick "$FIX/_home" >/dev/null
"$SCAN" --root "$TMP/r3esc/nope"$'\033]0;x\007' >/dev/null 2>"$TMP/r3esc.err"
if grep -q $'\033' "$TMP/stderr.txt" "$TMP/r3esc.err"; then ng "バナー・引数エラーに ESC（端末エスケープ）がそのまま出力されています"
else ok "バナー・引数エラーの --root の制御文字を \\xHH で表示"; fi

# R3-11 / K1: 読めないディレクトリ・ファイルは errors[] に unreadable、ルート自体を読めなければ status=error・終了コード 2
#   root で実行している場合は setpriv で nobody として実行する（無ければ SKIP）
as_user=""
if [ "$(id -u)" = "0" ]; then command -v setpriv >/dev/null 2>&1 && as_user="setpriv --reuid=65534 --regid=65534 --clear-groups"; else as_user="env"; fi
if [ -n "$as_user" ]; then
  P="$TMP/r3perm"; mkdir -p "$P/root/locked" "$P/root/d" "$P/home" "$P/zes" "$P/unreadable-root"
  printf '# yarn lockfile v1\n' >"$P/root/locked/yarn.lock"; printf '# yarn lockfile v1\n' >"$P/root/d/yarn.lock"
  cp -R "$SCAN" "$REPO/rules" "$P/zes/"
  chmod 755 "$TMP" "$P" "$P/root" "$P/root/d" "$P/home" "$P/zes"; chmod -R a+rX "$P/zes"
  chmod 000 "$P/root/locked" "$P/root/d/yarn.lock"; chmod 311 "$P/unreadable-root"
  out="$(cd / && $as_user env HOME="$P/home" TMPDIR=/tmp ZES_HOST_CHECKS=0 ZES_OFFLINE=1 ZES_HOME="$P/home" "$P/zes/zes-scan.sh" --worm --root "$P/root" --json 2>/dev/null)"
  printf '%s' "$out" | jq -e --arg a "unreadable:$P/root/locked" --arg b "unreadable:$P/root/d/yarn.lock" '.status == "partial" and ([.errors[] | select(.module == "core" and (.reason == $a or .reason == $b))] | length == 2)' >/dev/null 2>&1 \
    && ok "読めないディレクトリ・ファイルを errors[] に unreadable として記録" || ng "読めないディレクトリ・ファイルが errors[] に記録されていません"
  out="$(cd / && $as_user env HOME="$P/home" TMPDIR=/tmp ZES_HOST_CHECKS=0 ZES_OFFLINE=1 ZES_HOME="$P/home" "$P/zes/zes-scan.sh" --worm --root "$P/unreadable-root" --json 2>/dev/null)"; rc=$?
  [ "$rc" = "2" ] && printf '%s' "$out" | jq -e '.status == "error" and ([.errors[] | select(.reason == "inventory_failed")] | length == 1)' >/dev/null 2>&1 \
    && ok "検査ルート自体を読めない場合は status=error・終了コード 2" || ng "検査ルートを読めない場合の status/終了コードが不正（rc=$rc）"
  chmod -R u+rwx "$P" 2>/dev/null
else
  printf '  SKIP 読めないファイルの検査（root で setpriv が無い）\n'
fi

echo
echo "結果: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
