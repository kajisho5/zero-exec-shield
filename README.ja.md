[English](README.md) | 日本語

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/logo/zes-logo-dark.svg">
    <img src="brand/logo/zes-logo-light.svg" alt="zero-exec shield" height="72">
  </picture>
</p>

# Zero-Exec Shield (ZES)

ZES は、サプライチェーン攻撃・侵害された開発マシン・AI 開発ツールの罠を検出する静的スキャナです。検査するコードを一切実行せず、ファイルとパッケージのメタデータを読むだけで `findings.json` を出力します。

Bash の CLI（`zes-scan.sh`）と、1 ファイルで動くブラウザ UI（`index.html`）があります。どちらも同じ IoC データベース（`rules/ioc.json`）を使います。

> スキャナのメッセージ（findings.json の `detail`、端末のログ）とブラウザ UI は日本語です。フィールド名・重大度・エラーコードは ASCII です。

## クイックスタート

### CLI

動作要件: Bash 4 以上（macOS 標準の Bash 3.2 は不可。`brew install bash`）、macOS / Linux、`jq`（推奨。[制限事項](#制限事項)を参照）。

```bash
git clone https://github.com/kajisho5/zero-exec-shield
cd zero-exec-shield
./zes-scan.sh --quick --root /path/to/project --json > findings.json
```

人間向けのログは標準エラー、`findings.json` は標準出力に出ます。ほかのモード:

```bash
./zes-scan.sh --full --root /path/to/project --json          # 全モジュール §1〜§49
./zes-scan.sh --skillpact --root /path/to/skills --json      # §49 のみ（実験的）
ZES_OFFLINE=1 ZES_HOST_CHECKS=0 ./zes-scan.sh --full --root . --json   # ファイルのみ: 通信なし・ホスト状態の検査なし
```

| 引数 | 内容 |
|---|---|
| `--root <dir>` | 検査ルート（既定 `.`） |
| `--quick` | §1〜§19（既定） |
| `--standard` | §1〜§35 |
| `--full` | §1〜§49 |
| `--worm` | §15 / §18 / §25 / §45 のみ |
| `--skillpact` | §49 のみ |
| `--url <URL>` | §4 の非侵襲ヘッダチェック（http/https の URL 1 件）。`HEAD`（405/501 のときだけ `GET`）、リダイレクトは追わない。`Server` / `X-Powered-By` の `PHP/x.y.z` を PHP2Shell の修正版と照合 |
| `--json` | findings.json を標準出力へ |
| `--skillpact-cache <dir>` | §49 の前版比較に使う SkillPact 契約の置き場所（ローカルのみ） |

| 環境変数 | 内容 |
|---|---|
| `ZES_IOC` | IoC データベースのパス（既定はスクリプトと同じ場所の `rules/ioc.json`） |
| `ZES_HOME` | ホーム配下を対象とする検査（§10〜§14 等）の基点（既定 `$HOME`） |
| `ZES_HOST_CHECKS=0` | ホスト状態の検査（プロセス・接続・`/proc`・カーネル・インストール済みツールの版確認）を無効化 |
| `ZES_OFFLINE=1` | 外向き通信（§4 `--url`、§6 eMudhra 接続試験）をすべて無効化（`skipped_offline` を記録） |
| `ZES_SKILLPACT_CACHE` | `--skillpact-cache` と同じ |
| `ZES_GIT_TIMEOUT` | §38 / §46 の git 呼び出しの打ち切り秒数（既定 60。超過は `git_timeout` を記録） |

### ブラウザ UI

`index.html` をブラウザで開くだけで使えます（`file://` のままで可）。インストールもサーバーも不要です。

- Web 版: https://kajisho5.github.io/zero-exec-shield/ （GitHub Pages。main の `index.html` を配信）
- 版を固定して使う場合や、ネットワークにつながない環境では、`index.html` をダウンロードして手元で開いてください。

フォルダをページにドロップする（またはフォルダ選択）と、ブラウザ内で検査します。ページを読み込んだ後の通信はありません。テキスト貼り付け判定、findings.json の書き出し、CLI の findings.json の読み込み表示もできます。

18 タブ構成です。総合（重大度サマリ・フィルタ・検索）、SkillPact、MCP / GitHub Actions / ブラウザ拡張ビューア、キャンペーン・分野別のタブがあります。「すべてのタブ」はタブ検索です（タブ名や § 番号で絞り込み）。ライトとダークのテーマがあり、選ぶまでは OS の設定に従います。640px 未満では検出一覧がカード型になり、押すと詳細が下からのシートで開きます。ホスト側の情報（プロセス・接続・カーネル・マウント・インストール済みツールの版）はブラウザでは検査できないため、該当タブには「0 件」ではなく CLI の案内を表示します。

## 検査する内容

ZES は 49 のモジュール（§1〜§49）からなります。検出の重大度は `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO` です。

| 分類 | モジュール | 例 |
|---|---|---|
| パッケージのサプライチェーン | §2, §9, §15, §25, §44, §45 | npm / yarn / pnpm / pip / Poetry / uv / PDM / Pipfile / Cargo / Go / Gemfile / composer のロックファイルとインストール済みの `node_modules`・`dist-info` にある既知の悪性版・脆弱版、`.pth`・`sitecustomize.py` の起動時フック、不審なインストールスクリプト、決済 SDK のタイポスクワット、インフォスティーラーの痕跡 |
| インフラ・ランタイムの CVE | §3, §4, §5, §6, §16, §23 | GitLab、PHP（PHP2Shell）、Python、eMudhra 中間 CA（OS の信頼ストア・ランタイム・版固定）、イメージタグによる CI/CD 基盤の判定、コンテナランタイムとカーネル |
| AI 開発ツールと MCP | §7, §17, §20, §32, §36, §37, §41 | AI・エディタ設定の不可視文字・BiDi、`runOn: folderOpen`、MCP の危険な `command`/`args`、SymJack のシンボリックリンク、エージェントフック、Hugging Face の `trust_remote_code`、pickle 形式のモデル |
| CI/CD と git | §21, §22, §38, §46 | `pull_request_target` の pwn request、SHA 固定していない Action、ワークフローの大量植え付け、git の来歴 |
| コンテナ・クラウド・署名 | §8, §28, §29, §39, §43, §48 | `.env` と秘密鍵、`docker.sock` のマウント、版を固定しないベースイメージ、Kubernetes の `hostPath`、メタデータサービス・IMDSv1、cosign の版と `cosign verify` / `slsa-verifier` の引数、SBOM とロックファイルの不一致 |
| ホストの永続化・アンチフォレンジック | §1, §10, §11, §12, §13, §30, §31, §33, §35, §40 | 侵害マーカーとプロセス署名、LaunchAgents / systemd / cron、`LD_PRELOAD` と eBPF、SSH 鍵の権限、`ignore-scripts` と pip の防御設定、`noatime`、履歴の改ざん |
| ネットワーク・ツール設定・拡張 | §18, §24, §26, §27, §34, §42 | C2 ドメイン・IP、ブラウザ拡張の権限と所有権移転、git の `core.fsmonitor`、ビルドフック（`build.rs`・`go:generate`・`cmdclass`）、プロキシ・hosts の設定 |
| 認証情報（Blast Radius） | §14, §19, §47 | 認証情報ファイル（`~/.ssh`・`~/.aws`・`~/.npmrc` など）の存在を `stat` だけで列挙、履歴や CI 用ファイルの平文トークン |
| AI エージェントのスキル（実験的） | §49 | スキルの [SkillPact](https://github.com/kajisho5/skillpact) 契約と、コードが実際にしていることを比べる |

IoC の値は ZES v5.2 Master Specification からの転記です。一次情報との照合結果は [docs/ioc-verification.md](docs/ioc-verification.md) にあります。

### §49 SkillPact 契約（実験的）

§49 は、スキルの `skill.contract.json`（SkillPact 0.8 形式、`contract_version` 0.1〜0.8）を読み、宣言された `permissions`（`read` / `write` / `network` / `exec` / `spend` / `send`）と、コードの静的なパターンから推定した効果を比べます。

- 宣言されていない `exec` / `network` / `spend` / `send` は HIGH。契約が範囲に含まない機密ファイルの read・作業領域外への write は MEDIUM。前版から major を上げずに権限が広がった場合（SkillPact 仕様 §17）は HIGH または MEDIUM です。
- 契約は ZES が部分的に検査します（I-JSON、構造、整合性、`integrity.files` のハッシュと網羅性）。不合格は MEDIUM（`skillpact-invalid`）。§49 は CRITICAL を出しません。
- ZES は署名を検証せず、テストを実行せず、ポリシーの allow / ask / deny も評価しません。`signed: true` は「署名欄あり（未検証）」の意味です。`level` は ZES の部分検査に合格した場合だけ `"L1"` で、SkillPact の適合判定ではありません。正式な判定は SkillPact の参照実装（`skillpact validate` / `skillpact conformance`）で行ってください。
- 契約のないスキルは比較の対象外です。そのスキルのコードに `exec` / `network` / `spend` / `send` が見える場合だけ、参考として INFO を 1 件出します。

§49 の検出ルールと出力は今後変わる可能性があります。

## 安全設計

- **ゼロ実行。** 検査対象のファイルを実行せず、そのランタイムも起動しません（`npm install`・`pip install`、対象コードに対する `node`・`python` など）。パッケージの版はロックファイルとメタデータから、Go の版は `GOROOT/VERSION` から、npm のプロキシ設定は `.npmrc` から読みます。
- **固定のプローブのみ。** ホスト検査が有効な場合は、決められたインストール済みツールだけを版確認の引数で起動します（例: `python3 -I -S -V`、`php -n -v`、`docker --version`、`git --version`）。プローブは `env -i` と空の一時 `HOME` で起動し、検査ルート内と `/tmp`・`/var/tmp`・`/dev/shm` にあるバイナリは起動しません。git は ZES が用意した影の `GIT_DIR` で動かすため、検査対象リポジトリの `.git/config` を git に読ませません。git の呼び出しはすべてタイムアウト付きです。
- **テストで確認。** [`tests/zero-exec.sh`](tests/zero-exec.sh) が `strace` のもとで全モジュールを実行し、フィクスチャの実行、対象ランタイムの起動、許可外の引数でのプローブが 1 回でもあれば失敗します。2 つのフィクスチャは、実行されると `/tmp/zes-canary-*` を作るカナリアです。
- **ファイル内容を出力しない。** 検出にはパス・ルールの文言・SHA-256（`evidence_hash`）だけを含めます。一部の文言には、版・イメージタグ・HTTP ヘッダなどの短い抽出値が入ります。シークレットの値は出力しません。
- **fail-closed。** 検査できなかったモジュール（`jq` がない、ロックファイルを解析できない、タイムアウト、オフライン）は `errors[]` に記録し、`status` を `partial` にします。`findings[]` が空でも `errors[]` が空でなければ「安全」ではありません。
- **通信。** CLI が外部に接続するのは `--url` と §6 の eMudhra 接続試験（`rules/ioc.json` に載っているテスト用ホストへの HTTPS）だけです。`ZES_OFFLINE=1` で両方とも止まります。
- **ブラウザ UI。** JS・CSS・`rules/ioc.json` を 1 ファイルにインライン化しています。CSP は `default-src 'none'; connect-src 'none'` で、スクリプトとスタイルはビルド時に計算した SHA-256 だけを許可します（`unsafe-inline` なし）。成果物に通信 API・外部 URL・外部読み込みがあれば、[`ui/scripts/verify-no-network.mjs`](ui/scripts/verify-no-network.mjs) がビルドを失敗させます。ファイル内容は判定にのみ使い、画面に出すのはパス・ルール・固定文言・ハッシュと、120 文字までの一部の設定値（MCP の `command`/`args`、Actions の `uses:`、拡張のパーミッション名）だけです。

## 出力形式

`findings.json` は [`schemas/findings.schema.json`](schemas/findings.schema.json)（JSON Schema 2020-12、未知のプロパティは不可）に従います。

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
      "evidence_hash": "sha256:<通常ファイルはその SHA-256（100MB 超はパス・サイズ・mtime の SHA-256）、それ以外は detail の SHA-256>",
      "skillpact": { "…": "§49 の finding のみ" }
    }
  ],
  "errors": [{ "module": "§6", "reason": "skipped_offline" }]
}
```

- `id` は内容から決定的に生成します（再スキャンで同じ検出なら同じ ID）。同じ ID は 1 回だけ出力します。
- `campaign` はキャンペーンに紐づかない一般検査では `null`。`path` は絶対パスか `null`（ファイルのないホスト検査の結果）です。
- `errors[].reason` の例: `skipped_offline` / `network_timeout` / `jq_unavailable` / `module_failed` / `lockfile_parse_failed:<path>` / `git_timeout` / `special_file:<path>` / `non_utf8_path:<path>` / `incident_bundle_mismatch:<値>`。
- 文字列はすべて valid な UTF-8 です。制御文字は `\u00XX` でエスケープします。ファイル名の不正な UTF-8 バイトは `\xHH` というテキストに置き換え、そのパスを `errors[]` に `non_utf8_path` として記録します。FIFO・ソケット・デバイスファイルは開かず、`special_file` として記録します。
- ブラウザ UI が書き出す findings.json のパスは、投入フォルダからの相対パスに `/` を前置したものです。`errors[]` に `ui:host_checks_not_performed` を記録します。`status` は `partial` で、取り込んだ CLI の findings.json が `status: error` だった場合は `error` です。
- ブラウザ UI が生成する `id` は、上の CLI の式とは別の作り方です（`module|campaign|path|規則 ID` から生成し、`path` は相対パス）。UI の中でだけ安定し（同じフォルダを投入し直せば同じ `id`）、同じファイルの CLI の `id` とは一致しません。揃えると既存の `id` が変わるため、このままにしています。CLI の findings.json から取り込んだ finding の `id` はそのまま保ちます。

後段のツールが依存してよい性質は、[docs/skill-contracts.md](docs/skill-contracts.md) の §9 にまとめています。

## 終了コード

| コード | 意味 |
|---|---|
| `0` | 完了。`status` が `ok` または `partial`（`--help` も 0） |
| `2` | `status` が `error` |
| `64` | 引数・環境のエラー（不明な引数、`--root` がディレクトリでない、Bash 4 未満、`rules/ioc.json` を読めない） |

重大度による非 0 終了はしません。CRITICAL があれば CI を失敗させる例:

```bash
./zes-scan.sh --quick --root . --json > findings.json
jq -e '[.findings[] | select(.level == "CRITICAL")] | length == 0' findings.json
```

検査が不完全な場合も失敗させるには、`jq -e '.status == "ok"'` も確認してください。

## 制限事項

- **静的なヒューリスティック。** 検出はパターンと版の照合です。誤検知も見逃しもあります。検出 0 件は、マシンやプロジェクトが安全である証明ではありません。
- **IoC データは古くなる。** `rules/ioc.json` は時点のスナップショット（incident bundle `ZES-2026-OCT-EMERGENCY-V5.2`）で、定期的な更新が必要です。一次情報で確認できなかった値は [docs/ioc-verification.md](docs/ioc-verification.md) に注記しています。
- **ディストリビューションのバックポート。** カーネル・ツール・PHP の版は upstream の修正版と比べます。ディストリビューションのパッケージはバックポートで修正済みのことが多いため、これらの結果は HIGH を上限とし、ベンダーのアドバイザリでの確認が必要です。dpkg の PHP はベンダーの修正版と比べます。RHEL 系は rpm DB を静的に読めないため、案内を出すだけです。
- **全項目の検査には `jq` が必要。** `jq` がない場合は一部の検査を grep で代替し、§48・§49・収集インテルの照合・一部のロックファイル形式は `jq_unavailable` として記録します。
- **ホスト検査は稼働中のシステムを読む。** `ps`・`lsof`・`/proc` と上記のプローブを使います。ディレクトリだけを検査する場合は `ZES_HOST_CHECKS=0` を指定してください。
- **`noatime`。** `noatime` でマウントされたファイルシステムでは、§13（ハニーポット）のアクセス時刻の検査とアクセス痕跡の調査が機能しません。
- **ブラウザ UI。** ホストの状態は見えません。シンボリックリンクはブラウザに 0 バイトのファイルとして渡るため、SymJack の判定が CLI と異なります（CRITICAL ではなく HIGH）。WebKit では、直下が隠しエントリだけのフォルダ（`.mcp.json` や `.github/` だけ）を読み込めず、Safari でも隠しファイルが検査から漏れる可能性があります。その場合はドラッグ＆ドロップか CLI で確認してください。
- **§49 は実験的で部分的な検査です**（上記のとおり）。

## 関連ツール

ZES は 3 つのツールのうち検知層です。層の間のインターフェースは [docs/skill-contracts.md](docs/skill-contracts.md) で定めています。

| 層 | ツール | 入出力 |
|---|---|---|
| 検知 | ZES（このリポジトリ） | `findings.json` を出力。read-only |
| 判断 | ZET（Zero-Exec Triage）: [kajisho5/zero-exec-triage](https://github.com/kajisho5/zero-exec-triage) | `findings.json` を読み、remediate / exception / defer を判断して `remediation-plan.json` を出力 |
| 修復 | GER（Gated-Exec Remediation）: [kajisho5/gated-exec-remediation](https://github.com/kajisho5/gated-exec-remediation) | 承認済みの `remediation-plan.json` を読み、dry-run を経て、許可リストにある操作だけを実行 |

[`SKILL.md`](SKILL.md) は、AI エージェントが ZES を read-only の検知スキルとして使うための手順です。新しい脅威情報から IoC を抽出して `rules/ioc.json` に追記する手順も含みます。

## 開発

```bash
tests/run-tests.sh                   # IoC DB 検証・campaign 同期・フィクスチャの期待値照合
tests/run-tests.sh --sync-campaigns  # rules/campaigns/*.json を rules/ioc.json から再生成
tests/zero-exec.sh                   # strace による execve 監視（Linux、strace が必要）

cd ui && npm ci && npm run build     # 型チェック、ビルド、../index.html へのインライン化、通信の静的検査
npm test                             # Vitest（tests/fixtures を CLI と共用）
npm run test:e2e                     # Playwright（file:// で起動）
```

- フィクスチャは無害なダミーです。期待値は `tests/expected/` にあります。
- `ui/.npmrc` で `ignore-scripts=true` を指定し、依存は `package-lock.json` で版を固定しています。
- `rules/ioc.json` を変更したら `index.html` を再ビルドしてください。コミット済みの `index.html` がビルド結果と異なると CI が失敗します。
- UI の設計書: 現行の 0.3「検疫台」は [docs/design/ui-design-0.3.md](docs/design/ui-design-0.3.md)。実装前のドラフト（画面は 0.3.0 より前、§49 の部分は SkillPact 0.8 対応前の内容）は [docs/design/ui-design.md](docs/design/ui-design.md)
- 変更履歴: [CHANGELOG.md](CHANGELOG.md)

## ライセンスとクレジット

ZES のライセンスは [Apache License 2.0](LICENSE) です。ZES 自体の脆弱性の報告は [SECURITY.md](SECURITY.md) を参照してください。

- **SkillPact。** §49 は SkillPact 0.8 の契約形式（https://github.com/kajisho5/skillpact）を読みます。SkillPact © SEVENTHWELL (shogo kajiyama)。仕様の文章は CC BY 4.0、スキーマとコードは Apache-2.0 です。ZES は形式を変えずにその一部を検査する実装で、SkillPact の適合性検査ツールではありません。ZES の結果は SkillPact のレベルではなく、SEVENTHWELL による承認でもありません。`tests/fixtures/skillpact-*` の一部は SkillPact の conformance ケースと例の複製です（[tests/fixtures/skillpact-README.md](tests/fixtures/skillpact-README.md)）。
- **PHP2Shell のデータ。** `rules/ioc.json` の PHP2Shell 修正版と Debian / Ubuntu / RHEL のパッケージデータ（`php2shell_distro`）、および §4 の版判定は、[openai/php2shell-checker](https://github.com/openai/php2shell-checker)（Apache-2.0）と、そこに挙がっている各ベンダーの勧告に基づきます。
- **レビューの手法。** バグ探しの各ラウンドでは [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill)（MIT）の手法（指摘ごとの独立した検証など）を参考にしました。同リポジトリのコードは含みません。
