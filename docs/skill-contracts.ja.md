[English](skill-contracts.md) | 日本語

# ZES スキル契約書（Skill Contracts）— 判断層・修復層

- **対象**: ZET — Zero-Exec Triage（判断層、リポジトリ [kajisho5/zero-exec-triage](https://github.com/kajisho5/zero-exec-triage)） / GER — Gated-Exec Remediation（修復層、リポジトリ [kajisho5/gated-exec-remediation](https://github.com/kajisho5/gated-exec-remediation)）
- **スキーマの所有**: 出力する層がスキーマを持ち、受け取る層は `schema_version` を固定して参照する（findings.json → ZES [`schemas/findings.schema.json`](../schemas/findings.schema.json) / remediation-plan.json → ZET / remediation-log.json → GER）
- **前段**: 検知層 `zes-scan`（[SKILL.md](../SKILL.md)）が出力する findings.json
- **位置づけ**: 3 層の共通インターフェース定義。実装は ZET 0.1.0 / GER 0.1.0。検知層（ZES）は §9 の出力保証でこれに準拠する
- **改定**: 2026-10-22 契約追加 A-1〜A-6（ZET 設計）と GER の出力追加を採用（§3・§6 に反映、各項目に【追加】と表記）
- **正のスキーマ**: [remediation-plan.schema.json（ZET）](https://github.com/kajisho5/zero-exec-triage/blob/main/schemas/remediation-plan.schema.json) / [remediation-log.schema.json・ger-input.schema.json（GER）](https://github.com/kajisho5/gated-exec-remediation/tree/main/schemas)。本書の JSON 例と食い違う場合はスキーマが正
- **版**: ZES v5.2（`incident_bundle`: `ZES-2026-OCT-EMERGENCY-V5.2`）

```
[検知層] zes-scan … read-only、契約検証、乖離検出
      ↓ findings.json（skillpactフィールド付き）
[判断層] ZET（Zero-Exec Triage） … 乖離の影響判定、例外承認
      ↓ remediation-plan.json
[修復層] GER（Gated-Exec Remediation） … 明示承認後のみ実行
```

## 1. 共通契約

- 入出力は UTF-8 の JSON。スキーマ固定、未知フィールドは拒否（strict）
- タイムスタンプは RFC 3339（UTC）
- fail-closed: 取得失敗を 0 件扱いしない。部分成功を残さない
- 追記専用ログ（`skill` / `version` / `input_hash` / `output_hash` / `started_at` / `finished_at` / `operator`）
- 検知ログと修復ログは別ファイル・別リテンション
- 判断層は read-only、修復層は許可リスト方式

## 2. ZET 入力

```json
{
  "schema_version": "1.0",
  "findings": { "...": "ZES findings.json" },
  "policy": {
    "deadlines": {"CRITICAL": 30, "HIGH": 30, "MEDIUM": 60, "LOW": 90},
    "decision_window_days": 14,
    "approvers": ["security-lead", "platform-owner"]
  },
  "skillpact_policy": {
    "l3_trusted": false
  }
}
```

`skillpact_policy.diff_anomaly_threshold` と `skillpact_policy.destructive_requires_human` は予約済み・未実装です。ZET のスキーマでは必須ではなく、指定すると ZET は「reserved, not implemented」として入力を拒否します（効くように見えて効かない設定を受け付けない）。破壊的な操作の人間承認は §7 の `reversible: false` の二重承認で扱います。

## 3. ZET 出力 `remediation-plan.json`

```json
{
  "schema_version": "1.0",
  "plan_id": "uuid",
  "created_at": "RFC3339",
  "status": "ok|partial|error|draft",
  "plan_hash": "sha256:<plan_hash を除いた本体の正規化 JSON の SHA-256>",
  "items": [
    {
      "finding_id": "sha256:<hash>",
      "decision": "remediate|exception|defer",
      "exception_type": "not_affected|fix_unavailable|risk_accepted|null",
      "reason": "string",
      "owner": "team-or-person",
      "decided_by": "person",
      "decided_at": "RFC3339",
      "due_at": "RFC3339",
      "recheck_at": "RFC3339",
      "approved_by": ["security-lead"],
      "level_effective": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "action": {"type": "string", "target": "/abs/path", "params": {}, "reversible": true, "skillpact_effects": ["read"]}
    }
  ],
  "held": [{"finding_id": "sha256:<hash>|null", "module": "§6", "reason": "scan_error:skipped_offline"}]
}
```

| 【追加】 | 内容 |
|---|---|
| A-1 `status: "draft"` | ZET の下書き。GER は受理しない（確定 plan は `ok` / `partial`） |
| A-2 `decided_by` | 判断者。「exception は判断者以外が承認」を機械的に検査するために必須 |
| A-3 `level_effective` | SkillPact 規則で引き上げた後の重大度。入力の `level` は改変しない。引き下げ不可 |
| A-4 `action.reversible` / `action.skillpact_effects` | ZET が操作種別と finding の `declared_effects` から付与。GER は findings を読まないため、二重承認と SkillPact 制限の判定材料を plan で渡す |
| A-5 `held[].module`（`finding_id: null` 可） | `errors[]` のモジュールをモジュール単位で保留する（finding が 0 件でも未確定を表現できる） |
| `action.target` | 対象の finding の `path` と一致すること（ZET は一致しない plan を出さない。`path` が `null` の finding には `action` を付けられない） |
| A-6 `plan_hash` | 確定 plan の本体（`plan_hash` を除く）を、キー順ソート・区切り `,` `:`・UTF-8 で正規化した JSON の SHA-256。GER の承認トークンと照合する |

## 4. ZET 不変条件

- 全 finding に判断を付与する（`held` は明示的保留であり未判断ではない）
- `exception` には `exception_type` / `reason` / `recheck_at` / 判断者以外の `approved_by` が必須
- `remediate` には `owner` / `due_at` / `action` が必須
- `held` は修復層に渡さない
- 入力 findings の `id` / `level` / `module` を改変しない
- 【追加】`decided_by` / `decided_at` は全判断で必須。`approved_by` は `policy.approvers` に含まれる人だけ。`due_at` は判断日 + `deadlines[level_effective]` 日以内、exception / defer の `recheck_at` は判断日 + `decision_window_days` 日以内
- 【追加】入力が `partial` の場合、plan も `partial` とし、`errors[]` の各モジュールを `held` に明示する
- `findings.status == "error"` の入力は拒否する。`errors[]` に記録されたモジュールの finding は未確定として扱う（`held` で明示）
- **SkillPact**
  - `skillpact.divergence` が非空の finding は `exception` を許可しない（必ず `remediate` または `defer`）
  - `skillpact.diff_anomaly: true` の finding は `approved_by` に 2 名以上を要求
  - `skillpact.signed: true` でも `divergence` が非空なら CRITICAL 相当として扱う（`signed` は ZES が署名欄の有無を見ただけで未検証）
  - `skillpact_policy.l3_trusted` は既定 `false`。L3 署名を信頼の根拠にしない（差分異常と併せて評価）
  - SkillPact 署名の検証（`skillpact validate` 等）が必要な場合は、判断層で人間が実行する（検知層は署名欄の有無のみ確認し、L2/L3 を判定しない）

## 5. GER 入力

```json
{
  "schema_version": "1.0",
  "plan": { "...": "remediation-plan.json" },
  "approval": {
    "plan_id": "uuid",
    "approved_by": ["security-lead", "platform-owner"],
    "approved_at": "RFC3339",
    "approval_token": "sha256:<承認対象 plan の plan_hash>"
  },
  "mode": "dry-run|apply",
  "allowed_actions": ["chmod", "write_config", "rotate_secret"]
}
```

【追加】`approval_token` は承認対象の確定 plan の `plan_hash` と一致すること（承認を計画の中身に束縛し、承認後の差し替えを検出する）。`allowed_actions` にワイルドカードは使えない。dry-run と apply の同一性は、入力から `mode` を除いた正規化 JSON の SHA-256（`input_hash`）で判定する。

## 6. GER 出力 `remediation-log.json`

```json
{
  "schema_version": "1.0",
  "plan_id": "uuid",
  "plan_hash": "sha256:<hash>",
  "mode": "dry-run|apply",
  "started_at": "RFC3339",
  "finished_at": "RFC3339",
  "status": "ok|partial|error",
  "results": [
    {
      "finding_id": "sha256:<hash>",
      "action_type": "chmod",
      "target": "/abs/path",
      "before": "0644",
      "after": "0600",
      "result": "applied|skipped|failed|rolled_back",
      "reason": "string",
      "applied_at": "RFC3339|null"
    }
  ]
}
```

【追加】`plan_hash` と `mode`（どの計画のどの実行かを一意にするため）。`applied_at` は実際に適用した結果以外では `null`。

## 7. GER 不変条件

- 承認なき実行禁止、`plan_id` 不一致は拒否
- dry-run を経ない apply 禁止
- 全対象の事前検証。1 件でも失敗なら全体中止（部分適用禁止）
- ZES 出力（findings.json）を直接読まない（`remediation-plan.json` のみ）
- `allowed_actions` 外の操作を拒否（許可リスト方式）
- 対象パスは `plan.items[].action.target` に限定。target は finding の `path` そのもの（relation `self`）か、finding の `path` から `relation`（`npm_pkg_dir` / `npm_installed` / `pypi_record` / `ext_dir` / `skill_dir`。findings 1.1 の `related` を含む）で導ける対象だけで、それ以外の親ディレクトリへは遡及しない
- `chmod` は権限を狭める変更だけ（例: `0644` → `0600`）。権限を広げる `params` は ZET が拒否する
- 全操作は冪等。`reversible: false` は二重承認必須
- 1 件でも `failed` が出たら残りを実行せずロールバック
- 【追加】実行者（`--operator`）は `approval.approved_by` に含まれてはならない。dry-run 記録は既定 24 時間で失効し、監査ログのハッシュチェーンが壊れている場合は dry-run 記録を信用しない
- **SkillPact**
  - `skillpact.declared_effects` に `exec` / `network` / `spend` / `send` が含まれるスキルの修復は、その操作が `allowed_actions` に明示されていなければ拒否
  - `skillpact.signed: true` を承認の代替にしない（人間承認は必須）

## 8. 層間連携ルール

| ルール | 内容 |
|---|---|
| 飛び越し禁止 | 修復層は ZES 出力を直接読まない |
| スキーマ検証必須 | 各層は入力スキーマを検証、失敗時は次層へ渡さない |
| 失敗の伝播 | `status: "error"` は次層へ渡さない、`partial` は `held` を明示 |
| 承認の連鎖 | 判断層と修復層の `approved_by` は別途取得（自己承認防止） |
| ログ分離 | 検知・判断・修復ログは別ファイル・別リテンション |
| バージョン固定 | 各層は `schema_version` を検証、不一致なら拒否 |

## 9. 検知層（ZES）が保証すること

判断層が依存してよい、findings.json の性質です（`tests/run-tests.sh` で検証）。

- `schema_version` は `"1.2"`（ZES 0.5.0 以降。1.2 は finding に `code` と `params` を足し、`detail` を英語にし、`id` を v2 にしたもの。1.1（ZES 0.4.x）は 1.0 に任意の項目を足しただけで、`id` と `evidence_hash` の作り方は 1.0 と同じ）
- トップレベルキーは `schema_version` / `scan_roots` / `incident_bundle` / `scan_started_at` / `scan_finished_at` / `scan_mode` / `status` / `findings` / `errors` のみ。`scan_roots` は `--root` の実パスの配列
- finding のキーは `id` / `level` / `module` / `campaign` / `path` / `detail` / `evidence_hash` / `evidence`（§49 のみ `skillpact` を追加）、`code` / `params`（1.2）と、任意の `kind` / `subject` / `locators` / `related` のみ
  - `code`: 文の識別子（メッセージ ID）。`i18n/en.json` のカタログのキー `f.<code>`。言語に依らない
  - `params`: 文に入る値。値はすべて文字列、キーはカタログのプレースホルダ（`^[a-z_]+$`）。値は finding から取った文字列で、検査したファイルの文字列（`uses:` の参照など）を含むことがあるため、表示する側でエスケープする。それ以上のファイル内容は含めない
  - `detail`: 常に英語。カタログの `f.<code>` に `params` を入れた文で、`--lang` やロケールに依らない
  - `kind`: 機械可読な種別（`pkg.compromised` / `pkg.vulnerable` / `pkg.lockfile_compromised` / `mcp.dangerous_command` / `mcp.unpinned` / `gha.pwn_request` / `gha.unpinned` / `secret.token` / `runtime.cve`）。ZET の I-13 はこれで操作を絞る
  - `subject`: パッケージの `{ecosystem, package, version, safe_version, fixed_versions}`（§15）
  - `locators`: 同じファイルの該当箇所。JSON / JSONC / TOML は `{format, pointer}`（RFC 6901。例 `/mcpServers/<name>`）、テキストは `{format: "text", line, line_sha256}`（行の SHA-256。改行・行末の CR・1 行目の BOM を除く。GER の `remove_line` と同じ）。内容そのものは出さない
  - `related`: finding の path から導ける別の対象 `{relation, path}`（`npm_installed`・`ext_dir`・`skill_dir`）
  - `evidence`: 種類つきの証跡 `{kind, hash}`。`file`（100MB 超は `large_file`。`evidence_hash` と同じ値）/ `symlink`（readlink の値の SHA-256）/ `tree`（ディレクトリ。GER の ger-tree-v1）/ `detail`（それ以外。検査ルート・ホームそのものの finding も）
- GER の隔離ストア（`.ger-quarantine-store` のあるディレクトリ。所有者が実行ユーザーで 0700）は走査しない（`errors[]` に `quarantine_store_skipped`。status は変えない）
- `skillpact` のキーは `contract_path` / `contract_version` / `level` / `signed` / `author` / `declared_effects` / `observed_effects` / `policy_decision` / `l2_tested` / `divergence` / `diff_anomaly` のみ。効果名は SkillPact 0.8 の `read` / `write` / `network` / `exec` / `spend` / `send` のみ（`secrets` / `persist` / `longrun` は廃止）。`policy_decision` は常に `null`、`l2_tested` は常に `false`（ZES は評価しない）
- `id` は `sha256:` + 64 桁 16 進で決定的。1 つの findings.json の中で一意（同じ `id` が重なったら 1 件だけ残し、`errors[]` に `duplicate_finding_id` を記録）。`path` は絶対パスまたは `null`
  - id v2（1.2）: `"zes-id-v2|" + module + "|" + campaign + "|" + path + "|" + code + "|" + params` の SHA-256。`params` は `key=value` をキー順（C ロケール）に並べて U+001F で連結したもの。`campaign` / `path` が `null` なら空文字列。各要素と各 param の値は先にエスケープする（`\` → `\\`、`|` → `\|`、U+001F → 6 文字の `\u001f`。0.5.1 から）。`detail` の言語・文言には依らない
  - `id` は 0.5.0 で 1 度だけ変わる。0.4.x の findings に対する ZET の判断・GER の承認はそのまま引き継げないため、再走査して判断し直す
- `evidence_hash` は通常ファイルならその SHA-256（100MB 超はパス・サイズ・mtime の SHA-256）、それ以外は英語の `detail` の SHA-256（1.2 でも作り方は変わらない）
- ファイル内容・シークレット値を含まない（上の `params` / `detail` の短い値を除く）
