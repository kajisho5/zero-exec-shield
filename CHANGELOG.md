# Changelog

## Unreleased

### 追加

- `index.html`（Web Scanner UI）: Vite + React 18 + TypeScript + Tailwind CSS をビルド時に単一ファイルへインライン化（外部通信ゼロ、CSP はスクリプト / スタイルの SHA-256 方式、`file://` で動作）。ソースは `ui/`
  - 18 タブ、総合サマリ・重大度フィルタ・検索・モジュール絞込、仮想スクロールの検出一覧、パスのコピー、Blast Radius、未判定件数、ホスト検査の CLI 案内
  - SkillPact タブ: 宣言 / 実態エフェクトの差分（未宣言を赤・破線）、L3 は「署名済みファイル」（安全色・「安全」表記なし）、ポリシー決定、prose 矛盾、差分異常、§49 検出ルール 12 行
  - MCP / GitHub Actions / ブラウザ拡張ビューア、テキスト貼り付け判定、findings.json の書き出し・CLI 出力の読み込み
  - 判定エンジンは CLI と同じ `rules/ioc.json`（5.2.1 の legit_infra / eth_contracts / trivy-action safe_tags を含む）を参照
- テスト: Vitest 23 件（CLI と共通の tests/fixtures を使用）、Playwright 7 件（外部リクエストゼロ・CSP 違反なし・主要操作）、成果物の静的検査（`ui/scripts/verify-no-network.mjs`）

## 5.2.1 — 2026-10-22

`incident_bundle`: `ZES-2026-OCT-EMERGENCY-V5.2`（据え置き）

### 修正

- IoC を一次情報に合わせて修正（certifi / intercom-client / jscrambler / lerobot / ovhcloud-cli / ChainDrop / TeamPCP / Miasma / GitLab / Kernel / Cosign / MCP / ToolHive / Cursor / Copilot / trivy-action ほか。一覧は docs/ioc-verification.md「5.2.1 での反映」）
- §21: `pull_request_target + actions/checkout(refなし) + secrets` を CRITICAL → HIGH（PR head を checkout する pwn request は CRITICAL のまま）
- §18: 悪用された正規インフラ（Session / Ethereum RPC）を MEDIUM で報告、ChainDrop の新 C2 とコントラクトを CRITICAL で検出
- §3 / §23 / §37 / §41 / §43: 修正版が判明した CVE を版比較で判定。§43 の Rekor イメージ判定（CVE-2026-22703 の対象誤り）を削除
- §6: Homebrew ca-certificates の判定を MEDIUM（基準値要確認）に変更
- 文書のリンクを作業ブランチから main に変更
- テスト: フィクスチャ `ioc-corrections` / `ioc-corrections-safe` を追加

## 5.2 — 2026-10-22

`incident_bundle`: `ZES-2026-OCT-EMERGENCY-V5.2`

### 追加

- `zes-scan.sh`: §1〜§49 の全チェックポイント（`--quick` / `--standard` / `--full` / `--worm` / `--skillpact` / `--url` / `--json`）
- §49 SkillPact 統合 `check_skillpact`: 契約探索・スキーマ検証・宣言と実態の突合・ポリシー評価（`never_auto_allow_any`）・L2 記録（存在と SHA-256）・L3 署名（存在のみ）・同一作者の前バージョンとの差分異常・prose と契約の矛盾・`reversible: false` の自動許可検出
- `findings[].skillpact` フィールド（findings.json schema 1.0）
- `rules/ioc.json`（Master Spec §3 の全データ、`skillpact` セクション）と `rules/campaigns/*.json`（11 ファイル、ioc.json から生成）
- `SKILL.md`（検知スキル / IoC 抽出モード / マージルール）
- `docs/skill-contracts.md`（ZET / GER の契約、SkillPact 不変条件）
- `schemas/findings.schema.json`（findings.json の JSON Schema。判断層 ZET は `schema_version` を固定して参照）
- `tests/run-tests.sh`（IoC DB 検証・campaign 同期・フィクスチャ照合・横断チェック）、`tests/zero-exec.sh`（strace による execve 監視）
- `docs/ioc-verification.md`（IoC の一次情報照合レポート）
- `docs/design/`（index.html の設計書と SVG デザイン。実装は承認待ち）

### 未実装

- `index.html`（設計レビュー後に実装）
- （ZET / GER は別リポジトリで 0.1.0 を実装済み: kajisho5/zero-exec-triage, kajisho5/gated-exec-remediation）


## 5.1 以前

Master Specification §16 の変更履歴を参照（3.5: §1〜14 / 4.0: §15〜19 / 4.1: §20〜35 / 5.0: §36〜48 / 5.1: 最新脅威追加）。
