# Changelog

## Unreleased

### 追加

- `index.html`（Web Scanner UI）: Vite + React 18 + TypeScript + Tailwind CSS をビルド時に単一ファイルへインライン化（外部通信ゼロ、CSP はスクリプト / スタイルの SHA-256 方式、`file://` で動作）。ソースは `ui/`
  - 18 タブ、総合サマリ・重大度フィルタ・検索・モジュール絞込、仮想スクロールの検出一覧、パスのコピー、Blast Radius、未判定件数、ホスト検査の CLI 案内
  - SkillPact タブ: 宣言 / 実態エフェクトの差分（未宣言を赤・破線）、L3 は「署名済みファイル」（安全色・「安全」表記なし）、ポリシー決定、prose 矛盾、差分異常、§49 検出ルール 12 行
  - MCP / GitHub Actions / ブラウザ拡張ビューア、テキスト貼り付け判定、findings.json の書き出し・CLI 出力の読み込み
  - 判定エンジンは CLI と同じ `rules/ioc.json`（5.2.1 の legit_infra / eth_contracts / trivy-action safe_tags を含む）を参照
  - 5.2.2 / 5.2.3 の検知データにも対応: GitLab（§3）・PHP2Shell（§4）・開発インフラ CVE のイメージタグ判定（§16）、eMudhra（§6: dpkg / apk のパッケージ DB、`.nvmrc` 等の版固定、Node / Deno / Java イメージ）、収集インテル（悪性ファイルのハッシュ・名前、ネットワーク IoC、侵害 Actions、CI / AI 設定の悪性文字列、拡張、LaunchAgent / systemd の痕跡）、Cargo.lock / composer.lock / Gemfile.lock、`vulnerable_versions`（HIGH）。新しい検出は「総合」タブに表示（タブ構成は変更なし）
  - 同じネットワーク IoC が複数キャンペーンに載っている場合に重複して報告しない
- テスト: Vitest 27 件（CLI と共通の tests/fixtures を使用）、Playwright 7 件（外部リクエストゼロ・CSP 違反なし・主要操作）、成果物の静的検査（`ui/scripts/verify-no-network.mjs`）
## 5.2.4 — 2026-10-22

### 追加

- packages[]: sigstore-js（npm `sigstore` 4.1.1 未満、CVE-2026-48815）と Fulcio（Go `github.com/sigstore/fulcio` 1.8.6 未満、CVE-2026-49478）を脆弱版（HIGH）として追加。5.2.2 では製品データのみで判定対象外だった
- index.html: go.sum の解析を追加（CLI と同じ）
- テスト: フィクスチャ `intel-2026q3` / `-safe` に sigstore / Fulcio を追加

## 5.2.3 — 2026-10-22

### 修正

- §16: 個別判定のある製品（TeamCity / JFrog Artifactory）に 5.2.2 で追記した CVE（TeamCity CVE-2026-111094 / 106218、Artifactory CVE-2026-42016 / 42018 / 66384）が判定されていなかった。`cves[].generic` で汎用判定の対象にした
- テスト: `gitlab/compose.safe.yml` を新しい CVE の修正版に更新

## 5.2.2 — 2026-10-22

`incident_bundle`: `ZES-2026-OCT-EMERGENCY-V5.2`（据え置き）

### 追加

- **GitLab（§3）:** CVE-2026-110264（未認証 RCE、CVSS 10.0、2026-10-21 修正）・CVE-2026-85706（KEV）・CVE-2026-19478 を系列ごとの修正版で判定。判定対象 CVE は `infrastructures[gitlab]` から読む
- **PHP2Shell（§4）:** CVE-2026-109618/109619。Docker イメージタグ・`.tool-versions` は CRITICAL、ホストの php はディストリビューション版なら HIGH（バックポート確認）
- **eMudhra 中間 CA 侵害（§6）:** テスト用 2 ホストへの接続、OS の ca-certificates（dpkg / apk / pacman のパッケージ DB を静的に読む）、Node.js / Java / Deno の版固定（`.nvmrc`・`.node-version`・`.tool-versions`・イメージタグ）、Docker Desktop。pip / uv / rustls-webpki / webpki-roots / webpki-root-certs / composer/ca-bundle / electron / Claude Code の脆弱版。Homebrew ca-certificates を HIGH に戻した（一次情報の修正版一覧で確認）
- **収集インテル（181 件）:** 悪性パッケージ・CI/CD 侵害・開発インフラ CVE・インフォスティーラー・AI ツール/MCP/拡張を `rules/ioc.json` に追加（packages +85、infrastructures 34 製品 / 62 CVE、intel セクション）。出典は docs/ioc-verification.md「5.2.2 で追加した収集インテル」
- **汎用判定:** `infrastructures[].generic` の製品はイメージタグを版比較（Jenkins / Gitea / Forgejo / Atlassian / Argo CD / Nexus / Kestra / Podman / BuildKit / Node.js / Go / CPython / OpenJDK ほか）。`intel_apps`（macOS の Cursor / Kiro を Info.plist で判定）
- **packages[]:** `match: vulnerable_versions`（悪性ではない脆弱版を HIGH で報告）。composer.lock の解析
- **§23:** カーネル CVE の判定対象を `infrastructures[kernel]` から読む。Docker の CopyEscape を修正版 29.7.0 で判定
- テスト: フィクスチャ `intel-2026q3` / `intel-2026q3-safe` を追加

### 修正

- `intel_strings` / `intel_infra`: jq の `@tsv` が正規表現の `\` を二重にエスケープしていたため、パターンが一致しなかった
- ローカルツールのバージョン判定（§23）の上限を HIGH に（ディストリビューションのバックポートで誤検知しやすいため）

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
