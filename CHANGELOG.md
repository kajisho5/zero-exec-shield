# Changelog

## 0.3.0 — 2026-10-23

Web Scanner UI を「検疫台」デザインに作り直しました。検出ロジック（CLI・ブラウザのエンジン）と findings.json の形式は 0.2.0 から変わりません。

### 変更（Web Scanner UI）

- 見た目を「検疫台」に刷新: 検体票（検査したフォルダ・ファイル数・判定時間・未判定・実行 0 回）、絞り込みを兼ねる重大度の集計、余白の注記、署名の紫印（「署名あり（未検証）」）。色は重大度と署名の印だけに使う
- ライトテーマを追加（既定は OS の設定に従い、指定がなければダーク）。選択はブラウザに保存し、保存できない環境でも動く
- 「すべてのタブ」をタブ検索に変更（PC はポップオーバー、640px 未満は下からのシート）。タブは ←→ で移動し Enter で選ぶ（手動切り替え）
- スマホでは検出一覧をカード型にし、押すと詳細のシートを開く（ファイルの場所が画面外に出ない）。320px でもタブ列に 3 枚分の幅を確保
- 部品を shadcn/ui（MIT、ソースを手で取り込み再スタイル）と Radix に移行し、React 19 に更新。依存はすべて版を固定
- CSP は変更なし: Radix のスクロール固定が実行時に `<style>` を差し込まないよう、CSSOM で固定する実装に置き換え。ビルド時に実行時のスタイル注入と複数の `<style>` を検出したら失敗させる
- `index.html` は約 489 KB から約 774 KB に増加

### テスト

- e2e を追加: 全タブ・タブ検索・メニュー・シートを開いても CSP 違反ゼロ（Chromium / Firefox / WebKit）、テーマ切り替えと保存、タブ検索、スマホの詳細シート、フォーカス表示、320px / 375px で横スクロールしない、署名の印の色
- 重大度の文字色のコントラストを設計値（4.5:1 以上）と照合

## 0.2.0 — 2026-10-23

0.1.0 以降の 2 回のバグ探し（検査の回避・誤検知・ゼロ実行の破れ）の修正と、§49 の SkillPact 0.8 形式への作り直しです。findings.json の `schema_version` は 1.0 のままですが、§49 の効果名が変わります（下記）。

### 変更（§49 SkillPact、実験的）

- §49 を実在する SkillPact 0.8 形式（https://github.com/kajisho5/skillpact）に合わせて作り直し: `skill.contract.json` の `permissions.{read,write,network,exec,spend,send}` を読み、コードの静的解析と比べる。効果名は仕様の 6 種類のみ（`secrets` → 機密範囲の `read`、`persist` → 作業領域外の `write`、`longrun` は廃止）
- 契約のないスキルは比較対象外（影響の大きい効果が見える場合のみ参考 INFO）。契約付きスキル配下の `SKILL.md` は報告しない
- 契約の部分検査（I-JSON、構造、整合性、`integrity.files` のハッシュと網羅性）。不正・未対応の版は MEDIUM（`skillpact-invalid`）、CRITICAL は出さない
- 未宣言の exec / network / spend / send は HIGH、機密ファイルの read / 作業領域外の write は MEDIUM。署名は検証せず（`signed` は「署名欄あり・未検証」）、重大度に影響しない。`level` は ZES の部分検査に合格した場合のみ "L1"
- 前版比較は仕様 §17（major を上げない権限拡大）と作者署名鍵の一致で判定
- ポリシーは `policy_version` を持つ JSON を名前に関係なく検出して構造のみ検査（allow/ask/deny の評価は TODO）
- 独自形式（`.skillpact/contract.json`、`schema_version`、`effects[]`、L2 記録、`.sig` ファイル、prose 照合、破壊的マーカー、`reversible`）を削除。`schemas/findings.schema.json` の `$defs.effect` を 6 効果に変更
- テストのフィクスチャを SkillPact の conformance ケース・例の複製と、実形式の合成例に置き換え

### 修正（CLI: ゼロ実行・堅牢化）

- バージョン確認のプローブを `env -i`（空の一時 HOME・DOCKER_CONFIG・XDG_CONFIG_HOME、固定の PATH）で起動する。§23 は Docker デーモンに接続する `docker version` をやめ、`docker --version` を読む（`~/.docker` の ssh:// context や `DOCKER_HOST` 経由で ssh が起動していた）
- git に検査対象リポジトリの `.git/config` を読ませない（ZES が作る影の `GIT_DIR` を使う）。`include.path` / `includeIf` で FIFO を読ませて走査が止まる問題を解消。git の呼び出しはすべて `ZES_GIT_TIMEOUT`（既定 60 秒）で打ち切り、超過は `errors[]` に `git_timeout`
- §46 は署名を git に検証させず、コミットオブジェクトの `gpgsig` ヘッダから判定する（`gpg.x509.program` 経由で検査対象の設定のプログラムが起動していた）。プログラムを値に取る git 設定をすべて無効化
- `--root` を `cd --` で解決し、`CDPATH` を無視する（`-` で始まるルートが空のルートとして検査されていた）
- findings.json を任意のパス名で valid に保つ: 制御文字・C1 制御文字は `\u00XX`、不正な UTF-8 バイトは `\xHH` に置き換えて `errors[]` に `non_utf8_path`。`id` は出力した値の SHA-256 と一致する。人間向けログは端末エスケープを出さない。`ZES_HOME` / `HOME` を実パスに正規化
- 検査ルート内の FIFO・ソケット・デバイスファイルを開かず、`errors[]` に `special_file` を記録する
- ホスト検査の結果で、絶対パスでない擬似パス（`crontab:<user>` 等）や URL を `path` に出さず `null` にする（スキーマ違反だった）
- `intel.host` のパスは、存在しうる場所だけで照合する（`~/…` は検査対象 HOME の下、絶対パスはホスト検査が有効なときの実パスのみ）。どのマシンにもある `~/.bashrc` 等は存在だけでは報告しない。`.intel.host` の jq フィルタの誤りで §30 のホスト IoC 照合が無効になっていたのを修正し、`intel_jq` の失敗を `errors[]` に記録
- 依存関係の解析: CRLF・BOM、PEP 503 の名前正規化、`node_modules/*/package.json` のトップレベル `version`、`dist-info` / `egg-info` のメタデータ、Gem のプラットフォーム接尾辞、pnpm lockfile v5 のキー、yarn の `npm:` エイリアス、空の TSV 列
- MCP 設定: JSONC（`.vscode/mcp.json`）と Codex の `config.toml`（TOML トークナイザで解析）を読み、文字列の `args` を受け付ける。解析できない設定は `errors[]`（`mcp_config_parse_failed` / `codex_toml_unparsed`）
- GitHub Actions（§21 / §22）: 引用符・大文字小文字の違う `actions/checkout`、フローマッピングの `ref`、複数行に続く値（`uses: >-`・`ref: >-`・次の行の値）を読む。`run:` ブロック内の `uses:` は数えない
- certifi（eMudhra の最小版未満）と lerobot（CVE-2026-25874）を悪性版（CRITICAL）ではなく脆弱版（HIGH）として報告

### 追加・修正（PHP2Shell、§4）

- openai/php2shell-checker（Apache-2.0）の判定に合わせた: プレリリース版（dev / alpha / beta / RC）と修正版一覧にないブランチ（8.6 以降・9.x）は MEDIUM「要確認」、5.4〜8.1 は脆弱
- `rules/ioc.json` の `php2shell_distro`: Debian / Ubuntu / RHEL のベンダー修正版とアドバイザリ。dpkg のパッケージ DB（ホストと検査ルート内のコンテナ rootfs）を静的に読み、`php*-fpm` / `-cgi` / `-cli`・`libapache2-mod-php*` を Debian の版順序で比較。RHEL 系は rpm DB を読めないため MEDIUM の案内
- `--url`: `Server` / `X-Powered-By` の `PHP/x.y.z` を判定し、HIGH「ヘッダ申告版で潜在的に脆弱」。HEAD（405/501 のときだけ GET）、リダイレクトは追わない、`~/.curlrc` を読まない

### 修正（Web Scanner UI）

- 判定を CLI に合わせた: PHP2Shell（§4）、§8 / §28 / §37 / §48 のファイル検査、依存関係の一覧（ロックファイル各形式・`node_modules`・`dist-info`）、Codex `config.toml` と MCP の文字列 `args`、ワークフロー YAML の正規化（§21 / §22）、`intel.host` のパスの範囲（HOME と見なせるフォルダでは §10 / §12 の HOME 検査も実行）、§36 の lerobot、§6 の certifi、§18 の履歴の curl|sh、ChainDrop の `setup.mjs`、`~/.claude.json` と Windsurf の MCP 設定
- CLI の期待値（`tests/expected/*.json`）と UI の判定結果の一致を Vitest で固定（違いは SymJack のみ: ブラウザにはシンボリックリンクが 0 バイトのファイルとして渡るため HIGH）
- 読み込んだ findings.json をスキーマで検証し、不正な項目は捨てて件数を表示。書き出しに読み込み元の `errors[]` と `incident_bundle` を引き継ぐ。表示の例外を捕捉して白画面にしない
- 同じ `id` の検出を、フォルダ・貼り付け・読み込みをまたいで 1 件にまとめる。新しい検査の開始時・クリア時に前の検査を取り消す。検査中は書き出しを無効にする
- 375px / 320px の画面幅で横スクロールしない（ヘッダ・サマリ・検出一覧・SkillPact・MCP・Actions ビューア）。「すべてのタブ」メニューを Esc・外側クリック・キーボードで操作できるようにした。320px でタブを押せなかったため、sm 未満ではタブ列のスクロールボタンを隠し、メニューの文言を視覚的に隠す（読み上げ名は残す）
- 成果物の静的検査で、引用符のない・単一引用符の `<link href>` / `<img src>` も外部読み込みとして検出する

### 追加

- ロゴ・アプリアイコン・ファビコン・ソーシャル画像（`brand/`）
- テスト: フィクスチャ `codex-toml` / `codex-toml-broken` / `host-paths-home` / `host-paths-safe` / `lockfile-formats` / `php2shell` / `parser-evasion` ほか。`tests/zero-exec.sh` に ssh:// の Docker context と、プログラムを値に取る git 設定の罠を追加
- README を英語に（日本語版は README.ja.md）

### CI

- ui ジョブのタイムアウトを 40 分に延長

## 0.1.0 — 2026-10-22

初回リリース。ZES v5.2 Master Specification に準拠しています。この下にある 5.2〜5.2.4 の項目は、仕様書に追従する開発中の記録です（リリースはしていません）。0.1.0 にはそのすべてを含みます。

### 追加

- `index.html`（Web Scanner UI）: Vite + React 18 + TypeScript + Tailwind CSS をビルド時に単一ファイルへインライン化（外部通信ゼロ、CSP はスクリプト / スタイルの SHA-256 方式、`file://` で動作）。ソースは `ui/`
  - 18 タブ、総合サマリ・重大度フィルタ・検索・モジュール絞込、仮想スクロールの検出一覧、パスのコピー、Blast Radius、未判定件数、ホスト検査の CLI 案内
  - SkillPact タブ: 宣言 / 実態エフェクトの差分（未宣言を赤・破線）、L3 は「署名済みファイル」（安全色・「安全」表記なし）、ポリシー決定、prose 矛盾、差分異常、§49 検出ルール 12 行
  - MCP / GitHub Actions / ブラウザ拡張ビューア、テキスト貼り付け判定、findings.json の書き出し・CLI 出力の読み込み
  - 判定エンジンは CLI と同じ `rules/ioc.json`（5.2.1 の legit_infra / eth_contracts / trivy-action safe_tags を含む）を参照
  - 5.2.2 / 5.2.3 の検知データにも対応: GitLab（§3）・PHP2Shell（§4）・開発インフラ CVE のイメージタグ判定（§16）、eMudhra（§6: dpkg / apk のパッケージ DB、`.nvmrc` 等の版固定、Node / Deno / Java イメージ）、収集インテル（悪性ファイルのハッシュ・名前、ネットワーク IoC、侵害 Actions、CI / AI 設定の悪性文字列、拡張、LaunchAgent / systemd の痕跡）、Cargo.lock / composer.lock / Gemfile.lock、`vulnerable_versions`（HIGH）。新しい検出は「総合」タブに表示（タブ構成は変更なし）
  - 同じネットワーク IoC が複数キャンペーンに載っている場合に重複して報告しない
- テスト: Vitest 27 件（CLI と共通の tests/fixtures を使用）、Playwright 7 件（外部リクエストゼロ・CSP 違反なし・主要操作）、成果物の静的検査（`ui/scripts/verify-no-network.mjs`）

### リリース

- main の CHANGELOG 先頭の版に対応するタグと GitHub Release を、GitHub Actions（`.github/workflows/release.yml`）が自動で作成する

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
