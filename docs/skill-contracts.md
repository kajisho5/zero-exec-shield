# ZES スキル契約書（Skill Contracts）— 判断層・修復層

- **対象**: `vuln-triage`（判断層） / `remediation`（修復層）
- **前段**: 検知層 `zes-scan`（[SKILL.md](../SKILL.md)）が出力する findings.json
- **位置づけ**: 判断層・修復層スキルは今後実装予定。本書はその実装に先立つインターフェース定義であり、検知層（ZES）は §9 の出力保証でこれに準拠する
- **版**: ZES v5.2（`incident_bundle`: `ZES-2026-OCT-EMERGENCY-V5.2`）

```
[検知層] zes-scan … read-only、契約検証、乖離検出
      ↓ findings.json（skillpactフィールド付き）
[判断層] vuln-triage … 乖離の影響判定、例外承認
      ↓ remediation-plan.json
[修復層] remediation … 明示承認後のみ実行
```

## 1. 共通契約

- 入出力は UTF-8 の JSON。スキーマ固定、未知フィールドは拒否（strict）
- タイムスタンプは RFC 3339（UTC）
- fail-closed: 取得失敗を 0 件扱いしない。部分成功を残さない
- 追記専用ログ（`skill` / `version` / `input_hash` / `output_hash` / `started_at` / `finished_at` / `operator`）
- 検知ログと修復ログは別ファイル・別リテンション
- 判断層は read-only、修復層は許可リスト方式

## 2. `vuln-triage` 入力

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
    "l3_trusted": false,
    "diff_anomaly_threshold": 0.3,
    "destructive_requires_human": true
  }
}
```

## 3. `vuln-triage` 出力 `remediation-plan.json`

```json
{
  "schema_version": "1.0",
  "plan_id": "uuid",
  "created_at": "RFC3339",
  "status": "ok|partial|error",
  "items": [
    {
      "finding_id": "sha256:<hash>",
      "decision": "remediate|exception|defer",
      "exception_type": "not_affected|fix_unavailable|risk_accepted|null",
      "reason": "string",
      "owner": "team-or-person",
      "decided_at": "RFC3339",
      "due_at": "RFC3339",
      "recheck_at": "RFC3339",
      "approved_by": ["security-lead"],
      "action": {"type": "string", "target": "/abs/path", "params": {}}
    }
  ],
  "held": [{"finding_id": "sha256:<hash>", "reason": "scan_error"}]
}
```

## 4. `vuln-triage` 不変条件

- 全 finding に判断を付与する（`held` は明示的保留であり未判断ではない）
- `exception` には `exception_type` / `reason` / `recheck_at` / 判断者以外の `approved_by` が必須
- `remediate` には `owner` / `due_at` / `action` が必須
- `held` は修復層に渡さない
- 入力 findings の `id` / `level` / `module` を改変しない
- `findings.status == "error"` の入力は拒否する。`errors[]` に記録されたモジュールの finding は未確定として扱う（`held` で明示）
- **SkillPact**
  - `skillpact.divergence` が非空の finding は `exception` を許可しない（必ず `remediate` または `defer`）
  - `skillpact.diff_anomaly: true` の finding は `approved_by` に 2 名以上を要求
  - `skillpact.signed: true` でも `divergence` が非空なら CRITICAL 相当として扱う
  - `skillpact_policy.l3_trusted` は既定 `false`。L3 署名を信頼の根拠にしない（差分異常と併せて評価）
  - L3 署名の検証（`cosign verify` 等）が必要な場合は、判断層で人間が実行する（検知層は存在確認のみ）

## 5. `remediation` 入力

```json
{
  "schema_version": "1.0",
  "plan": { "...": "remediation-plan.json" },
  "approval": {
    "plan_id": "uuid",
    "approved_by": ["security-lead", "platform-owner"],
    "approved_at": "RFC3339",
    "approval_token": "string"
  },
  "mode": "dry-run|apply",
  "allowed_actions": ["chmod", "write_config", "rotate_secret"]
}
```

## 6. `remediation` 出力 `remediation-log.json`

```json
{
  "schema_version": "1.0",
  "plan_id": "uuid",
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
      "applied_at": "RFC3339"
    }
  ]
}
```

## 7. `remediation` 不変条件

- 承認なき実行禁止、`plan_id` 不一致は拒否
- dry-run を経ない apply 禁止
- 全対象の事前検証。1 件でも失敗なら全体中止（部分適用禁止）
- ZES 出力（findings.json）を直接読まない（`remediation-plan.json` のみ）
- `allowed_actions` 外の操作を拒否（許可リスト方式）
- 対象パスは `plan.items[].action.target` に限定、親ディレクトリへの遡及禁止
- 全操作は冪等。`reversible: false` は二重承認必須
- 1 件でも `failed` が出たら残りを実行せずロールバック
- **SkillPact**
  - `skillpact.declared_effects` に `exec` / `network` / `secrets` が含まれるスキルの修復は、その操作が `allowed_actions` に明示されていなければ拒否
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

- トップレベルキーは `schema_version` / `incident_bundle` / `scan_started_at` / `scan_finished_at` / `scan_mode` / `status` / `findings` / `errors` のみ
- finding のキーは `id` / `level` / `module` / `campaign` / `path` / `detail` / `evidence_hash`（§49 のみ `skillpact` を追加）のみ
- `skillpact` のキーは `contract_path` / `contract_version` / `level` / `signed` / `author` / `declared_effects` / `observed_effects` / `policy_decision` / `l2_tested` / `divergence` / `diff_anomaly` のみ
- `id` は `sha256:` + 64 桁 16 進で決定的。`path` は絶対パスまたは `null`
- `evidence_hash` は通常ファイルならその SHA-256（100MB 超はパス・サイズ・mtime の SHA-256）
- ファイル内容・シークレット値を含まない
