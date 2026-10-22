# Changelog

## 5.2 — 2026-10-22

`incident_bundle`: `ZES-2026-OCT-EMERGENCY-V5.2`

### 追加

- `zes-scan.sh`: §1〜§49 の全チェックポイント（`--quick` / `--standard` / `--full` / `--worm` / `--skillpact` / `--url` / `--json`）
- §49 SkillPact 統合 `check_skillpact`: 契約探索・スキーマ検証・宣言と実態の突合・ポリシー評価（`never_auto_allow_any`）・L2 記録（存在と SHA-256）・L3 署名（存在のみ）・同一作者の前バージョンとの差分異常・prose と契約の矛盾・`reversible: false` の自動許可検出
- `findings[].skillpact` フィールド（findings.json schema 1.0）
- `rules/ioc.json`（Master Spec §3 の全データ、`skillpact` セクション）と `rules/campaigns/*.json`（11 ファイル、ioc.json から生成）
- `SKILL.md`（検知スキル / IoC 抽出モード / マージルール）
- `docs/skill-contracts.md`（vuln-triage / remediation の契約、SkillPact 不変条件）
- `tests/run-tests.sh`（IoC DB 検証・campaign 同期・フィクスチャ照合・横断チェック）、`tests/zero-exec.sh`（strace による execve 監視）
- `docs/ioc-verification.md`（IoC の一次情報照合レポート）
- `docs/design/`（index.html の設計書と SVG デザイン。実装は承認待ち）

### 未実装

- `index.html`（設計レビュー後に実装）
- vuln-triage / remediation スキル本体（今後実装予定。インターフェースは docs/skill-contracts.md で定義済み）

## 5.1 以前

Master Specification §16 の変更履歴を参照（3.5: §1〜14 / 4.0: §15〜19 / 4.1: §20〜35 / 5.0: §36〜48 / 5.1: 最新脅威追加）。
