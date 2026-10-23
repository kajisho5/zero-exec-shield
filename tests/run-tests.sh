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

# 決定的 ID（再スキャンで同一）
run_scan "$FIX/skillpact-divergence" skillpact "$FIX/_home" | jq -r '[.findings[].id] | sort | join(",")' >"$TMP/id1"
run_scan "$FIX/skillpact-divergence" skillpact "$FIX/_home" | jq -r '[.findings[].id] | sort | join(",")' >"$TMP/id2"
cmp -s "$TMP/id1" "$TMP/id2" && [ -s "$TMP/id1" ] && ok "findings[].id が決定的" || ng "findings[].id が再スキャンで変化"

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
  printf '%s' "$out" | jq -e '([.findings[] | select(.module == "§46" and (.detail | test("1 コミット中")))] | length == 1) and ([.errors[] | select(.reason | test("^git_"))] | length == 0)' >/dev/null 2>&1 \
    && ok "検査対象 .git/config の include.path（FIFO）を読まずに §46 を完走" || ng "include.path（FIFO）で走査が停止または §46 が失敗"
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

echo
echo "結果: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
