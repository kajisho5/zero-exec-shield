<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/logo/zes-logo-dark.svg">
    <img src="brand/logo/zes-logo-light.svg" alt="zero-exec shield" height="72">
  </picture>
</p>

# Zero-Exec Shield (ZES)

バージョン 0.1.0（ZES v5.2 Master Specification 準拠）

**incident_bundle: `ZES-2026-OCT-EMERGENCY-V5.2`**

サプライチェーン攻撃・認証局危殆化・インフラ RCE・AI 開発環境トラップ・AI エージェントのスキルの宣言と実態の乖離（SkillPact 契約、実験的）を、**対象ランタイムを一切起動せず（Zero-Execution）**、静的解析だけで一括検疫する CLI スキャナです。

> **ゼロ実行原則と内容非読取方針**
> ZES は検査対象のコード・スクリプト・パッケージを実行しません（`npm install` / `pip install` / 悪性スクリプトの実行は行いません）。検出時もファイル内容は出力せず、**パスとメタ情報（サイズ・mtime・SHA-256）のみ**を示します。検査できなかったモジュールは `errors[]` に記録し、0 件（安全）とは扱いません（fail-closed）。
> `tests/zero-exec.sh` が `strace` で全 `execve` を監視し、この原則を検証します。
>
> **アンチフォレンジック検出時の注意**: `noatime` でマウントされた環境では atime が更新されないため、ハニーポット（§13）とアクセス痕跡の調査が機能しません。

## 構成

| コンポーネント | 状態 |
|---|---|
| `zes-scan.sh` — Core CLI Scanner（§1〜§49） | 実装済み |
| `rules/ioc.json` / `rules/campaigns/*.json` — IoC データベース | 実装済み（値は仕様書からの転記。照合結果は [docs/ioc-verification.md](docs/ioc-verification.md)） |
| `SKILL.md` — 検知スキル / IoC 抽出モード | 実装済み |
| `tests/` — フィクスチャ・期待値・`run-tests.sh`・`zero-exec.sh` | 実装済み |
| `schemas/findings.schema.json` — findings.json の出力契約（JSON Schema 2020-12、strict） | 実装済み（ZET はこれで入力を検証） |
| `docs/skill-contracts.md` — 判断層・修復層のスキル契約書 | 契約定義済み（ZET 0.1.0 / GER 0.1.0 実装済み。A-1〜A-6 反映） |
| `index.html` — Web Scanner UI | 実装済み（ブラウザで開くだけで動く単一ファイル。ソースは `ui/`、[設計書](docs/design/ui-design.md) / SVG デザイン [総合](docs/design/ui-overview.svg) / [SkillPact](docs/design/ui-skillpact.svg) / [部品](docs/design/ui-components.svg) に準拠） |

```
[検知層] ZES（zes-scan.sh / index.html / rules）
      ↓ findings.json
[判断層] ZET（Zero-Exec Triage）（影響判定・例外承認・期限付与）
      ↓ remediation-plan.json
[修復層] GER（Gated-Exec Remediation）（明示承認後のみ実行）
```

## 動作要件

- Bash 4 以上（macOS 標準の Bash 3.2 は不可。`brew install bash`）
- `jq`（推奨。無い場合は grep フォールバック。§48 SBOM と §49 SkillPact は jq 必須。収集脅威インテリジェンス（`rules/ioc.json` の `intel`）を使う照合 — §1（ホスト検査時）/ §7 / §15 / §16 / §20 / §22 / §23 / §30 / §38 / §42 — と §15 の Pipfile.lock / composer.lock 解析も jq が必要です。いずれも jq が無い場合は `errors[]` に `jq_unavailable` を記録し、0 件扱いしません）
- macOS / Linux。`readlink -f` が無い環境は `realpath` → `cd/pwd` にフォールバック

## クイックスタート

```bash
chmod +x zes-scan.sh
./zes-scan.sh --quick --root .
./zes-scan.sh --skillpact --root /path/to/skills
```

### 引数

| 引数 | 内容 |
|---|---|
| `--root <dir>` | 検査ルート（既定 `.`） |
| `--quick` | §1〜19（既定） |
| `--standard` | §1〜35 |
| `--full` | §1〜49 |
| `--worm` | §15/18/25/45 のみ |
| `--skillpact` | §49 のみ |
| `--url <URL>` | §4 の非侵襲 URL チェック（`curl -sI` で `X-Powered-By` ヘッダのみ取得。http/https のみ受理） |
| `--json` | findings.json を標準出力へ（人間向けログは標準エラーへ） |
| `--skillpact-cache <dir>` | §49 前版比較用の SkillPact 契約の置き場所（ローカルのみ） |

### 環境変数

| 変数 | 内容 |
|---|---|
| `ZES_IOC` | ioc.json のパス（既定 `rules/ioc.json`） |
| `ZES_HOME` | ホーム配下を対象とする検査（§10〜§14 等）の基点（既定 `$HOME`） |
| `ZES_HOST_CHECKS=0` | ホスト状態検査（ps / lsof / /proc / uname / docker version / systemctl / mount 等）を無効化 |
| `ZES_OFFLINE=1` | 外向き通信（§4 `--url`、§6 eMudhra 接続試験）を無効化（`errors[]` に `skipped_offline`） |
| `ZES_SKILLPACT_CACHE` | `--skillpact-cache` と同じ |

### 終了コード

`0` = 完了（`status` が `ok` / `partial`）、`2` = `status: error`、`64` = 引数・環境エラー。重大度による非 0 終了はしません。CI で失敗させる場合は `jq -e '[.findings[] | select(.level=="CRITICAL")] | length == 0'` 等で判定してください。

## Web Scanner UI（index.html）

リポジトリ直下の `index.html` をブラウザで開く（`file://` のままで可）だけで使えます。インストールもサーバーも不要です。

**Web 版:** https://kajisho5.github.io/zero-exec-shield/ （GitHub Pages。main の `index.html` をそのまま配信）

- **通信:** Web 版でも、ページを読み込んだ後の通信はゼロです。CSP の `connect-src 'none'` により、選んだフォルダの内容がブラウザの外に送られることはありません。
- **配信される版:** 開いた時点の main の版です。特定の版に固定して使う場合や、ネットワークにつながない環境では、`index.html` をダウンロードして `file://` で開いてください。

- **外部通信ゼロ**: JS / CSS / `rules/ioc.json` をすべて 1 ファイルにインライン化しています。CSP は `default-src 'none'; connect-src 'none'`、スクリプトとスタイルはビルド時に計算した SHA-256 だけを許可します（`unsafe-inline` なし）
- **ファイル内容は判定にのみ使用**: 画面・JSON 出力に出すのはパス・ルール・固定文言・ハッシュだけです。例外は設計書 §13-4 で承認した設定値（MCP の command / args、Actions の `uses:`、拡張のパーミッション名、120 文字まで）
- **投入方法**: フォルダのドラッグ＆ドロップ、または「フォルダを選択…」（`webkitdirectory`）。テキスト貼り付け判定もできます（内容は再表示しません）
- **18 タブ**: 総合（重大度サマリ・フィルタ・検索・Blast Radius）/ SkillPact（実験的。宣言と実態の差分を赤表示、署名は「署名あり（未検証）」と表記し安全色を使わない）/ MCP・GitHub Actions・ブラウザ拡張ビューア ほか
- **JSON 出力**: `schemas/findings.schema.json` 互換の findings.json をダウンロードします（パスは投入フォルダからの相対パスに `/` を前置。`status: partial`、`errors[]` に `ui:host_checks_not_performed` を記録）。CLI の findings.json の読み込み表示もできます
- **ブラウザで判定できないもの**: プロセス・ネットワーク接続・カーネル・eBPF・マウント・インストール済みツールのバージョンなどのホスト状態は、該当タブに CLI（`./zes-scan.sh --full --json`）の案内を出し、0 件 ＝ 安全とは表示しません
- **動作確認したブラウザ**: CI で Chromium・Firefox・WebKit（Playwright 版）の e2e を実行しています。WebKit では、直下が隠しエントリだけのフォルダ（`.mcp.json` や `.github/` だけ）を読み込めず、該当 2 件の e2e は除外しています。隠しファイルを渡さない挙動が実際の Safari でも起きるかは未確認です。Safari では、隠しファイル（`.mcp.json`・`.github/`・`.claude/` など）が検査から漏れる可能性があります。その場合はドラッグ＆ドロップか CLI で確認してください。0 件の選択は「0 件でした」と通知します

### ビルド（開発者向け）

```bash
cd ui && npm ci && npm run build     # 型チェック → vite build → ../index.html へインライン化 → 静的検査
npm test                             # Vitest: 判定エンジンの単体テスト（tests/fixtures を CLI と共用）
PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers npm run test:e2e   # Playwright: file:// で起動・外部リクエストゼロ・主要操作
```

- `ui/.npmrc` で `ignore-scripts=true`（依存のインストールスクリプトを実行しない）。依存はすべて `package-lock.json` で版固定
- `rules/ioc.json` を更新したら `npm run build` で `index.html` を再生成してコミットしてください（UI は ioc.json をビルド時に取り込みます）
- `scripts/verify-no-network.mjs` が成果物に通信 API・外部 URL・外部読み込みタグが無いこと、CSP がハッシュ方式であること、ソースに `eval` 等が無いことを検査し、違反があればビルドを失敗させます

## 3つの使い方

1. **プロジェクトを開く前**: `./zes-scan.sh --quick --root ./new-project`
2. **マシン定期健康診断**: cron / launchd で週1 `./zes-scan.sh --full --json > findings.json`
3. **インシデント発生時**: `--full --json` → Blast Radius（§14/§19）確認 → ローテーション

## 永続防御の仕込み方

- cron / launchd で週1実行
- CI（GitHub Actions 等）で PR 時に `--quick`、リリース前に `--standard`
- git hooks（pre-commit / pre-push）
- `npm install` 前のラッパースクリプト
- `rules/ioc.json` の月次更新（これがないと陳腐化する）

## キャンペーン別緊急対応表

| キャンペーン | 主な侵害 | 緊急アクション |
|---|---|---|
| LiteLLM 1.107.0 | cook.pth/sitecustomize.py | `pip show litellm`、削除、トークンローテーション |
| TeamPCP / Mini Shai-Hulud | TanStack/Mistral AI/Guardrails AI | OIDCトークン無効化、npm/GitHubトークンローテーション、`/proc/<pid>/mem`監査 |
| ChainDrop / Keyv | keyv/flat-cache/cacheable系 | `npm install`履歴、`setup.mjs`/`Math_Symbol.js`削除、Bun取得痕跡 |
| PyPI Oct 2026 | lightning 2.6.2/2.6.3、telnyx 4.87.1/4.87.2 | `pip show`、`_runtime/`削除、`83.142.209.203`通信監査 |
| Tensorlake 0.5.144 | Shai-Huludワーム | `package-lock.json`照合、削除、トークンローテーション |
| GhostAction Oct 2026 | 500+アカウント、偽装フォント | ワークフロー新規追加監査、`secrets.*`数確認 |
| MCP Poisoning/SymJack/Deadbugz/NeighborJack | `.mcp.json`改ざん | `command`/`args`目視、`readlink -f`検査、Claude Code v2.1.129+ |
| Quasar Linux (QLNX)/LinkPro/VoidLink | eBPF/LD_PRELOADルートキット | `/etc/ld.so.preload`、`bpftool prog list`、PAM確認 |
| Cursor RCE | CVE-2026-26268/50548、git.exe zero-day | v3.0+（26268 は 2.5、50548 は 3.0 で修正）、リポジトリルート`git.exe`確認 |
| Hugging Face Jul 2026 | 悪性データセット→クラスタ認証情報 | `trust_remote_code`監査、`subprocess`/`eval`検査、pickle回避 |
| Sigstore/SLSAバイパス | CVE-2026-22772/22703/39395 | cosign 3.1.3+（2.x は 2.6.5+）、`--certificate-identity`必須化 |
| コンテナエスケープ | CVE-2026-80521/64564 | カーネル更新、seccompプロファイル、特権コンテナ監査 |
| Djinn/OmniStealer | 開発者・AI認証情報窃取 | 認証情報ローテーション、不審プロセス監査 |
| OVHcloud CLI 2026-10-19 | GlassWorm経由でGitHubキー窃取 | 再インストール、GitHubトークンローテーション |
| GitLab CVE-2026-110264 | 未認証 RCE（CVSS 10.0、7.0 以降の全版） | 18.11.13 / 19.0.10 / 19.1.9 / 19.2.9 / 19.3.6 / 19.4.3 / 19.5.1 以上へ更新（18.10 以前は 18.11.13 以降へ移行） |
| PHP2Shell | CVE-2026-109618/109619（認証不要 RCE、悪用試行あり） | 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 以上。8.1 以前はサポート版へ移行 |
| eMudhra 中間 CA 侵害 | 危殆化 CA を OS・ランタイム・pip/Go/Rust 等が信頼 | ca-certificates・certifi・Node.js・Java・Docker Desktop 等を修正版へ、`emSign ECC Root CA G3` の除去確認 |
| 2026-06〜10 収集インテル | 悪性 npm/PyPI/crates/gems、侵害 Actions、インフォスティーラー、AI ツール/MCP/拡張 | 該当キャンペーンの一次情報に従う（docs/ioc-verification.md「5.2.2 で追加した収集インテル」） |
| SkillPact 乖離（§49、実験的） | スキルのコードが契約（skill.contract.json）で宣言していない効果を持つ | スキルの利用停止、作者への確認、契約の修正 |
| SkillPact 権限拡大（§49、実験的） | 前版から major を上げずに権限が拡大 | 前版との差分レビュー、作者への確認、必要ならスキル停止 |

> 表と `rules/ioc.json` の値は、一次情報で確認できた相違を 5.2.1 で反映済みです（[docs/ioc-verification.md](docs/ioc-verification.md) の「5.2.1 での反映」）。確認できなかった値は注記付きで仕様書の値のままです。

## Blast Radius 手順

```
検出（ZES）→ シークレット一覧提示 → ローテーション → 再構築
```

- 対象: `~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.claude`, `~/.cursor`, `~/.config/gh`, `~/.docker/config.json`, `~/.npmrc`, `~/.pypirc`, `~/.kube/config`, `~/.vault-token`, `~/.git-credentials`, `~/.netrc`, `~/.config/heroku/`, `~/.terraform.d/credentials.tfrc.json`, `~/.config/op/`
- 存在のみ列挙（`stat` でサイズ・mtime のみ、内容は読まない）。§14 が前半 9 件、§19 が後半 7 件を担当

## §49 スキルの宣言と実態の照合（SkillPact 契約、**実験的**）

AI エージェントのスキル（Claude Code・Cursor・Codex などが読み込む `SKILL.md` のフォルダ）が**宣言した権限と、そのコードが実際にしていることが一致するか**を、何も実行せずに確かめます。

- 宣言は [SkillPact](https://github.com/kajisho5/skillpact) 形式の `skill.contract.json`（`SKILL.md` と同じフォルダ）から読みます。SkillPact は、スキルが起こしうる副作用を 6 種類 — `read`（ファイルを読む）/ `write`（書く・消す）/ `network`（他のホストと通信）/ `exec`（他のプログラムを実行）/ `spend`（お金がかかる）/ `send`（人にメール・投稿・メッセージを送る）— に分け、それぞれ `none` / `scoped`（範囲を限定）/ `any` で宣言する契約形式です。ZES は SkillPact 0.8（`contract_version` 0.1〜0.8）に対応します。
- **SkillPact を使っていないスキルは対象外です。** 契約がないことを問題として扱いません（影響の大きい効果 — exec / network / spend / send — がコードに見える場合だけ、参考として INFO を 1 件出します）。契約付きスキルの中にある別の `SKILL.md`（例: `.claude/skills/*`）も報告しません。
- 実験的な機能です。検出ルール・出力は今後変わる可能性があります。

### ZES がすること・しないこと

| する | しない |
|---|---|
| 契約を JSON として読み、SkillPact 仕様の一部（I-JSON、構造、整合性、`integrity.files` のハッシュと網羅性）を検査 | スキル・テストの実行（L2 の確認） |
| コードを静的に読み、6 効果のどれが見えるかを推定し、契約の宣言と比べる | 署名の検証（`signed: true` は「署名欄あり・**未検証**」） |
| 同じスキルの前版の契約と比べ、major を上げない権限拡大を検出 | ポリシーの allow / ask / deny の評価（TODO。構造の検査のみ） |

- `level` は契約の自己申告を使いません。ZES の部分検査に合格した契約だけを **「L1 相当」** とし、L2 / L3 は判定しません。**L3 であっても「安全」を意味しません**（SkillPact 仕様 §16.1）。署名の有無で重大度を上げ下げしません。
- 正式な判定は SkillPact の参照実装（`skillpact validate` / `skillpact conformance`）で行ってください。ZES の結果は「まず見るべき乖離」を示すものです。

### 検出ルール

| 検出条件 | レベル | campaign |
|---|---|---|
| 契約のないスキルで exec / network / spend / send がコードに見える（参考） | INFO | skillpact-undeclared |
| 契約が I-JSON として不正（重複キー・±(2^53−1) 外の数値・深さ 64 超・孤立サロゲート・不正 UTF-8）。`errors[]` にも記録 | MEDIUM | skillpact-invalid |
| 未対応の `contract_version`（0.1〜0.8 以外。0.x の未知の minor も含む、仕様 §17） | MEDIUM | skillpact-invalid |
| ZES の部分検査で不合格（`SCHEMA` / `DUP_CAPABILITY` / `UNDECLARED_EFFECT` / `SCOPE_EMPTY` / `SCOPE_TRAVERSAL` / `SCOPE_WIDENED` / `UNKNOWN_REQUIREMENT` / `UNKNOWN_FEATURE_KIND` / `ENTRY_MISSING` / `NAME_MISMATCH` / `TEST_UNKNOWN_CAPABILITY` / `TEST_UNDECLARED_NETWORK` / `UNCONFIRMED_DRAFT` / `INTEGRITY_*` / `DUP_SIGNATURE`） | MEDIUM | skillpact-invalid |
| コードに exec / network / spend / send が見えるが、契約の該当 `permissions.<効果>.level` が `none` | HIGH | skillpact-divergence |
| コードが機密ファイル（`~/.ssh`・`.env`・認証情報など）を読む兆候があるが、契約の read がその範囲を含まない | MEDIUM | skillpact-divergence |
| コードに作業領域外への永続的な書き込み（crontab・.bashrc・authorized_keys など）が見えるが、契約の write が `$WORKDIR` / `$OUTPUT` / `$TMPDIR` 内に限られる（または write が `none`）／ファイル書き込みが見えるが write が `none` | MEDIUM | skillpact-divergence |
| 同じスキル名の前版から権限が広がったのに `skill.version` の major が上がっていない（仕様 §17。0.x は minor を major 扱い）。exec / network / spend / send の拡大は HIGH、それ以外は MEDIUM。作者署名鍵が前版と同じかどうかを併記（未検証） | HIGH / MEDIUM | skillpact-account-compromise |
| SkillPact ポリシー（`policy_version` と `defaults` を持つ JSON、ファイル名は問わない）が policy-v0.8-r2 の構造に合わない | MEDIUM | skillpact-invalid |

`scoped` の宣言は「宣言あり」として扱います（範囲の細かな照合は read の機密ファイルと write の作業領域外のみ）。§49 は CRITICAL を出しません。

#### 実態の推定と効果の対応

| ZES の検出 | SkillPact の効果 | 根拠 |
|---|---|---|
| `subprocess` / `child_process` / `Command::new` 等、シェルのコードブロック、スクリプトファイル、`allowed-tools: Bash` | exec | 仕様 §6「run other programs」 |
| `curl` / `requests` / `fetch(` 等、`WebFetch` / `WebSearch` | network | §6「talk to other hosts」 |
| ファイル書き込み API・リダイレクト・`Write` / `Edit` | write | §6「create, change, delete」 |
| 永続化（crontab・launchctl・.bashrc・authorized_keys 等） | write（作業領域外） | §13.3 の persistence（`$WORKDIR`/`$OUTPUT`/`$TMPDIR` 外への write） |
| 機密ファイル（`~/.ssh`・`.aws/credentials`・`.netrc`・`.env`・keychain 等） | read（機密範囲） | §13.3 の exfiltration（sensitive scope の read）。範囲の判定は参照実装の SENSITIVE パターン |
| 課金 API（stripe 等） / メール・Slack・Discord・Twilio 等への送信 | spend / send | §6 |

環境変数（`API_KEY`、`os.environ` 等）の参照は効果として扱いません（SkillPact では `requirements.env[]` で宣言する要件で、副作用ではないため）。「長時間実行」は SkillPact に対応する効果がないため扱いません。

### 前版との比較

- 前版は ROOT 内の `skill.contract.json` と `--skillpact-cache <dir>`（`ZES_SKILLPACT_CACHE`）内の契約から、同じ `skill.name` で `skill.version` が小さい最大のものを使います。レジストリからの取得は行いません（通信しない）。
- 作者の同一性は作者署名（`role: author`）の鍵（`ed25519:…` / `sigstore:<issuer>|<identity>`）で比べます。署名は検証していないため、参考情報です。

### TODO

- ポリシーの allow / ask / deny 評価（仕様 §13: ルールの範囲照合、`never_auto_allow_any`、`min_contract_version`、`require_signature`）は未実装です。現在は構造の検査のみで、`skillpact.policy_decision` は常に `null`、`l2_tested` は常に `false` です。判定には `skillpact policy-check` を使ってください。
- 署名の検証、`FM_NAME_DIR`（ディレクトリ名との一致。チェックアウト先の名前で誤検知するため対象外）、`BAD_SUBSCHEMA`、`SIGNATURE_*` は扱いません。

### 出典・ライセンス

SkillPact © SEVENTHWELL (shogo kajiyama), https://github.com/kajisho5/skillpact — 仕様の文章は CC BY 4.0、スキーマと実装は Apache-2.0。ZES は SkillPact の形式を読む独立した実装で、SEVENTHWELL による確認・承認を受けたものではありません。`tests/fixtures/skillpact-*` の一部は同リポジトリの conformance ケースと例を複製したものです（[tests/fixtures/skillpact-README.md](tests/fixtures/skillpact-README.md)）。

## 出力スキーマ（findings.json）

```json
{
  "schema_version": "1.0",
  "incident_bundle": "ZES-2026-OCT-EMERGENCY-V5.2",
  "scan_started_at": "2026-10-22T00:00:00Z",
  "scan_finished_at": "2026-10-22T00:01:30Z",
  "scan_mode": "quick|standard|full|worm|skillpact",
  "status": "ok|partial|error",
  "findings": [
    {
      "id": "sha256:<module|campaign|path|detail の SHA-256>",
      "level": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "module": "§49",
      "campaign": "skillpact-divergence",
      "path": "/abs/path",
      "detail": "…",
      "evidence_hash": "sha256:<通常ファイルはその SHA-256、それ以外は detail の SHA-256>",
      "skillpact": { "…": "§49 の finding のみ" }
    }
  ],
  "errors": [{ "module": "§6", "reason": "skipped_offline" }]
}
```

- `findings[].id` は内容から決定的に生成（再スキャンで同一なら同一 ID）。同一 ID は 1 回だけ出力
- `campaign` はキャンペーンに紐づかない一般検査では `null`
- `errors[]` の `reason`: `skipped_offline` / `network_timeout` / `jq_unavailable` / `module_failed`（モジュール異常終了）/ `git_log_failed` / `lockfile_parse_failed:<path>` / `policy_parse_failed:<path>` / `unscannable_path_newline`（改行を含むパス名）/ `incident_bundle_mismatch:<値>` 等
- 判断層は findings の `id` / `level` / `module` を改変しないこと（[docs/skill-contracts.md](docs/skill-contracts.md)）

## 実装メモ（仕様からの補足・解釈）

仕様に明記がなく実装で決めた点です。変更が必要ならご指示ください。

- **オフライン実行と ZET（判断済み）**: `--offline`（`ZES_OFFLINE=1`）では §6 の eMudhra 接続テストを行わず、`errors[]` に `skipped_offline` を記録します。そのため、ZET の不変条件 I-10 によって、§6 の検出は静的に確定したもの（OS の ca-certificates、Node.js / Java の版固定など）も含めて held になり、修復計画には進みません。安全側に倒すため、この動作は意図どおりとしています（2026-10-22 決定）。修復まで進める場合は、オンラインで再スキャンしてください
- **モジュール間の重複**: 仕様は複数の § で同じ対象を挙げています。同じ指標を二重に報告しないよう、次のように担当を分けました。
  - `runOn: folderOpen` → §7 / エージェントフック（`.claude/settings.json` の hooks）→ §17
  - `/etc/ld.so.preload`・シェル設定の `LD_PRELOAD` → §31 / ロード系スクリプト・eBPF・カーネル taint → §40
  - `noatime` → §13（§35 は参照のみ）
  - `docker cp` の使用・TeamCity・Artifactory → §16 / `docker version`・`uname -r`・特権コンテナ → §23
  - `trust_remote_code=True` → §36 / pickle 系拡張子・`weights_only=False`・`--extra-index-url` → §32
  - ブラウザ拡張の権限・`update_url` → §24 / 既知名・バージョン間の権限昇格（所有権移転）→ §42
  - Bun 取得: `package.json` 等 → §15 / JS・Python コード → §45
  - 既知タイポスクワット名 → §15 `check_lockfile_versions` / 非公式レジストリ・Git ソース → §9
- **ゼロ実行のための置き換え**: `npm config get proxy`（§34）は npm（node）を起動するため、`.npmrc` を静的に読む方式にしました。`go version`（§6）は telemetry 子プロセスを起動するため、`GOROOT/VERSION` を読みます。`python3` は `-I -S -V`、`php` は `-n -v` のみ起動します。検査ルート内・一時領域にあるバイナリは起動しません。
- **git の呼び出し**（§38/§46）: 検査対象リポジトリの設定（`core.fsmonitor` / `gpg.program` / `core.sshCommand` 等）経由でコマンドが起動されないよう、危険な設定を無効化して実行します。
- **ZES 自身の除外**: `rules/` や `tests/` は IoC 文字列を含むため、検査ルートが ZES の外側にある場合は ZES ディレクトリを走査対象から除外します。
- **ネットワーク IoC の無害化**: §13 の運用ルールに合わせ、ioc.json のドメイン・IP・URL はすべて `[.]` / `hxxp` 形式で格納し、照合時に戻します（仕様書の表記は一部が未無害化でした）。
- **GitHub Actions（§21）**: PR の head を checkout する pwn request（`ref: ${{ github.event.pull_request.head.sha }}` 等）を CRITICAL、`pull_request_target + actions/checkout(refなし) + secrets` を HIGH にしています（5.2.1 で CRITICAL から変更。ref なし checkout はベースブランチを取得するため、危険度は後続ステップ次第）。
- **既定の重大度**: npx/uvx の MCP command は普及しているため MEDIUM、curl/wget/bash -c/powershell -enc/node -e は HIGH にしています。
- **悪用された正規インフラ**（§18）: `seed1/seed2.getsession.org`（Session）と Ethereum RPC（nodereal / getblock / llamarpc）は、名前の出現だけでは侵害と断定できないため MEDIUM で報告します（`rules/ioc.json` の `legit_infra`）。
- **カーネル**（§23）: upstream の修正版と `uname -r` を比べます。ディストリビューションのバックポートは判定できないため、HIGH の結果は各ディストリのアドバイザリで確認してください。

## テスト

```bash
tests/run-tests.sh            # IoC DB 検証・campaign 同期・32 フィクスチャ照合・横断チェック
tests/run-tests.sh --update   # 期待値の再生成（差分は必ず目視レビュー）
tests/run-tests.sh --sync-campaigns   # rules/campaigns/*.json を ioc.json から再生成
tests/zero-exec.sh            # strace で execve を監視し、フィクスチャ・対象ランタイムの実行ゼロを確認（Linux）
```

- 期待値（`tests/expected/*.json`）は level / module / campaign / フィクスチャ相対パスで照合します
- フィクスチャは無害なダミーです。`chaindrop/setup.mjs` と `litellm/site-packages/cook.pth` は、万一実行された場合に `/tmp/zes-canary-*` を作るカナリアで、`zero-exec.sh` がその不在を確認します

## IoC 更新フロー

1. 検知（ブログ / CVE / X / GitHub Advisory）
2. 抽出（`SKILL.md` 抽出モード）
3. 検証（`tests/fixtures/` に再現フィクスチャ追加、一次情報との照合）
4. 投入（`rules/ioc.json` 追記 → `tests/run-tests.sh --sync-campaigns`、`incident_bundle` 更新）
5. 回帰（`tests/run-tests.sh` / `tests/zero-exec.sh`）
6. リリース（`CHANGELOG.md`、`incident_bundle` バンプ）

運用ルール: `campaign` 必須（孤立 IoC 禁止）、`bad_versions` / `safe_version` 両方記載、ネットワーク IoC は `[.]` 形式、ハッシュは SHA-256 のみ、`packages[]` は 1 エントリ 1 行。

## ライセンス

[Apache License 2.0](LICENSE)。脆弱性の報告は [SECURITY.md](SECURITY.md) を参照してください。
