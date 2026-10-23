# Changelog

## 0.4.0 — 2026-10-23

findings.json の形式を 1.1 にしました。修復層（ZET を通した GER）が finding を正確に扱えるよう、どこを・何を直せばよいかを機械可読な任意の項目で出します。ファイルの内容は今までどおり出しません。あわせて、負荷の高いときに finding の `detail` と `id` が実行ごとに変わることがあった競合を直しました。

### 形式の変更（findings 1.1）と後方互換

- `schema_version` は `"1.1"`。1.1 は 1.0 に**任意の項目を足しただけ**で、既存の項目の意味は変わりません。`id`（`module|campaign|path|detail` の SHA-256）と `evidence_hash` の作り方は 1.0 と同じで、同じ finding の `id` は 0.3.1 と一致します（例外: 下の `rules/ioc.json` の 2 件の `safe_version` を ASCII にしたため、その値を `detail` に含む §15 の finding だけ `detail` と `id` が変わります）
- 未知の項目を無視する 1.0 の読み手はそのまま動きます。`additionalProperties: false` で 1.0 のスキーマを使って検証している読み手は、1.1 の `schemas/findings.schema.json` に切り替えてください（ZET はすでに 1.0 と 1.1 の両方を受け付けます）
- トップレベル: `scan_roots`（`--root` の実パスの配列。ZET は計画の検査範囲にする）
- finding（`evidence` 以外は任意）:
  - `evidence`: `evidence_hash` の種類つき版 `{kind, hash}`。通常ファイルは `file`（100MB 超は `large_file`。`evidence_hash` と同じ値）、シンボリックリンクは `symlink`（`readlink` の値の SHA-256）、ディレクトリは `tree`（GER と共通のツリーハッシュ ger-tree-v1。GER のテストベクタ `sha256:a0330bed…958e` と一致することを `tests/run-tests.sh` で確かめる）、それ以外は `detail`。検査ルート・ホームそのものの finding（「同居」など）は全体のハッシュが高価で修復の対象にもならないため `detail`
  - `kind`: 機械可読な種別。§15 の `pkg.compromised`（インストール実体）/ `pkg.vulnerable` / `pkg.lockfile_compromised`（ロックファイル・依存の宣言）、§17 の `mcp.dangerous_command` / `mcp.unpinned`、§21 の `gha.pwn_request`、§22・§28 の `gha.unpinned`、§47 の `secret.token`、CVE の影響範囲の版（§3・§5・§6・§16・§37・§41 と intel の表）の `runtime.cve`。ZET の I-13 が使う文字列と同じ
  - `subject`（§15）: `{ecosystem, package, version, safe_version, fixed_versions}`
  - `locators`: 同じファイルの該当箇所。§17 は危険な MCP サーバーごとに `{format: json|jsonc|toml, pointer}`（`/mcpServers/<name>`・`/servers/<name>`・TOML は `/mcp_servers/<name>`。同じファイルの同じ種類の問題は今までどおり 1 件の finding で、該当するサーバーを並べる）。§7 はフックのエントリ `/hooks/<Event>/<i>` と `/tasks/<i>/runOptions/runOn`。§10・§26・§31・§4 の php.ini は `{format: text, line, line_sha256}`（改行・行末の CR・1 行目の BOM を除いた行の SHA-256。GER の `remove_line` と同じ）
  - `related`: finding の path から導いた別の対象。ロックファイル（npm）の隣にインストールされた `node_modules/<name>` は `npm_installed`、§24・§42 の拡張は `ext_dir`（`…/Extensions/<id>`）、§49 の `skill.contract.json` の finding は `skill_dir`
- GER の隔離ストア（マーカー `.ger-quarantine-store` のあるディレクトリ）を走査しない。マーカーを置くだけで検査を逃れられないよう、GER が作るストアの条件（マーカーが通常ファイル・所有者が実行ユーザー・グループ / 他者の権限なし）を満たすものだけを外し、`errors[]` に `quarantine_store_skipped:<dir>` を記録する（`status` は変えない）。条件を満たさないマーカーは無視して走査し、`quarantine_marker_untrusted:<dir>` を記録する
- `docs/skill-contracts.md`: GER の対象を「finding の path そのものか、`relation` で導ける対象だけ」と改めた（ファイル内容を出さない原則は変えない）
- Web Scanner UI: 同じ finding に同じ 1.1 の項目を付けて書き出す（`schema_version` 1.1）。ブラウザが知りえない値だけ異なる: `scan_roots` は出さない（パスが投入フォルダからの相対パスのため）、ディレクトリの `evidence` は `detail`（ファイルの mode が分からず ger-tree-v1 を計算できない）、シンボリックリンクは 0 バイトのファイルとして渡されるため `file`。1.0 と 1.1 のどちらの findings.json も読み込める。CLI とのパリティのテストで kind / subject / locators / related / evidence.kind も比べる

### 修正

- 負荷の高いときに `detail` と `id` が変わることがあった: パイプの末尾の `grep -q` は最初の一致で終了するため、上流（`printf` 等）が書き終える前に終わると上流が SIGPIPE で失敗し、`set -o pipefail` の下では「一致したのに偽」になっていた。§24 の危険パーミッションの列挙で 1 つ取りこぼすと、level・module・path は同じまま `detail`（＝ `id`）だけが変わる（GER の E2E を 8 並列で回したときに、browser-ext の §24 の finding の `id` が 1 回だけ変わった件）。入力を最後まで読む `grep_q` に置き換えた（53 箇所）。`tests/run-tests.sh` は 4 フィクスチャを並列 8 回ずつ走査して `id`・`evidence`・`locators` が一致することと、パイプの末尾に `grep -q` が無いことを確かめる
- `emit()` の中で同じ `id` を落とすとき、生のパスが違う（正規形だけが衝突した）なら `errors[]` に `duplicate_finding_id` を記録する（§17 を 1 ファイル 1 件にまとめたため、従来 `dedup_findings` が拾っていた重複が `emit()` の中で黙って落ちていた）
- Web Scanner UI: finding の `evidence_hash` は、その path が読めたファイルなら内容のハッシュにする（§42 の更新時の昇格・§49 の契約ファイル等で detail のハッシュになっていた。CLI と同じ。UI の `id` は変わらない）
- テスト: ロックファイルの隣に侵害版がインストールされたフィクスチャ `lockfile-installed` を追加（`related` の `npm_installed`）
- `rules/ioc.json` の `safe_version` を出力に載る値として ASCII にした（`5.x最新` → `latest 5.x`、`3.0.2 (系列別: …)` → `3.0.2 (per release line: …)`）

## 0.3.1 — 2026-10-23

0.3.0 の 3 回目のバグ探しの修正です。CLI のゼロ実行の破れ（`PATH` 経由）と多数の検出回避を塞ぎ、同じ修正をブラウザのエンジンにも入れました。Web Scanner UI・文書・CI の修正も含みます。findings.json の形式（`schema_version` 1.0）は変わりませんが、検出は増えます（下記）。

### 修正（CLI: ゼロ実行・fail-closed）

- `PATH` を起動時に無害化する: 相対パス・空のエントリ（`.`・`::`）と、実パスが検査ルート配下のエントリ（`node_modules/.bin` 等）を外し、`errors[]` に `path_entry_dropped:<エントリ>` を記録する。`jq` と `git` は 1 度だけ絶対パスに解決して常にそれを起動する（検査ルート内の偽の `jq` / `git` / coreutils が起動していた）。無害化より前に外部コマンドを呼ばない（`dirname` / `uname` / `cat` を置き換え）。`#!/usr/bin/env bash` は ZES より先に `PATH` から `bash` を探すため、`PATH` を信頼できない場合は `bash zes-scan.sh` で起動するよう README に記載
- Git の設定を `.git` ファイル（`gitdir:`）・入れ子のリポジトリ・worktree の共有側・`include.path` / `includeIf` の参照先まで静的に検査する（§26 の `core.fsmonitor` 等、§7 のフック、§41 のフック同居）。git には読ませない。辿れない参照は `errors[]` に `gitfile_unparsed` / `gitdir_unresolved` / `gitdir_outside_root` / `git_commondir_unresolved` / `git_include_unresolved`
- VCS のメタデータとして除外するのを検査ルート直下の `.git` / `.hg` / `.svn` だけにし、入れ子の同名ディレクトリの中のコードも走査する（`lib/.svn/p.js` 等に隠せた）
- NUL を含むファイルを読み飛ばさない（`grep -I` を `-a` に。`-l` / `-q` / `-o` の全箇所）。ブラウザも NUL を含むファイルをバイナリとして飛ばさず判定する
- 読めないディレクトリ・ファイルを `errors[]` に `unreadable:<path>` として記録する（`find` の標準エラーと終了コードを確認。黙って 0 件になっていた）
- 読むと停止しうるものを読まない: ルート内に組み立てたパスの実体がルート外（`.git/config` → `/proc/kmsg` 等）なら `path_leaves_root`、擬似ファイルシステム上のファイル（ツリー内へのバインドマウントを含む）は開かずに `special_filesystem`。`.git` の HEAD 等の読み取りと git 設定の読み取りを timeout 付きにした
- `awk -v` でパスやデータを渡さない（`ENVIRON` 経由に統一）。パス中の `\n` / `\t` が展開されて依存関係の行を偽造でき、findings のパスも変わっていた
- 終了コード 2（`status: error`）を実際に返す: 検査ルートの中を 1 件も列挙できない場合（`inventory_failed`）と、モードの全モジュールが異常終了した場合。以前は到達しなかった
- `timeout` の無い環境のウォッチドッグが `sleep` を孤児として残していた問題を修正
- バナーと引数エラーの `--root` 等の値を端末向けに符号化する（端末エスケープの注入を防ぐ）
- `--root /` に対応: パスを `//x` にしない、`PATH` の検査ルート配下の判定を行わない、擬似ファイルシステムを開かない
- バージョン確認のプローブの除外に `/private/tmp`・`/private/var/folders`・`$TMPDIR` を追加（macOS）
- BusyBox 環境で §42 / §48 の結果が欠けていた: `comm` / `join` / `date -d` を使わず awk と Bash の計算に置き換え。`find` に `-fstype` が無い場合は `find_fstype_unsupported` を記録

### 修正（CLI・ブラウザ: 検出の回避）

- §21 / §22: ワークフローの YAML のアンカー（`&x`）・タグ（`!!str`）を除き、フロー列（`steps: [ {uses: …}, … ]`。複数行・コメント付きを含む）を展開して判定する。エイリアス（`*x`）は解決せず `errors[]` に `yaml_alias_unresolved`
- §21: `actions/checkout` の `ref` を正規化して判定する（大文字小文字・添字表記 `github.event['pull_request']['head']`・`refs/pull/${{ github.event.number }}/merge`・`merge_commit_sha`）。ベース側（`base.sha` / `base_ref` 等）以外の式で決まる `ref` は最低 HIGH。secrets 参照も大文字小文字・添字表記を区別しない
- §38: `toJSON(secrets)` / `tojson(secrets.*)` を大文字小文字を区別せずに検出
- §17: 危険なコマンドの判定を拡張（シェルの `-xc`・`--norc -c` 等、`node --eval` / `-p`、`deno eval`、`perl` / `ruby -e`、`php -r`、`osascript` / `lua -e`、`pwsh -Command`、`cmd /c`）。BOM 付きの JSONC を読む。jq が無い場合も `command` と `args` を連結して判定する（何も記録していなかった）
- §18: ネットワーク IoC を大文字小文字を区別せずに照合する
- §2: `.pth` の `import` 行は標準の形（virtualenv・setuptools の distutils-precedence・PEP 660 editable）以外を MEDIUM、`exec` / `eval` / `compile` / `os.system` / `popen` / `getattr` 等を伴うものを HIGH にする。`package.json` の `prepare` / `preprepare` / `postprepare` も対象にし、BOM・末尾カンマで JSON として読めない場合も JSONC として読み直す
- §7: AI 指示ファイルに `AGENTS.md`・`GEMINI.md`・`CLAUDE.local.md`・`.windsurfrules`・`.clinerules`・`.github/instructions/*`・`.claude/**/*.md` を追加。異体字セレクタ（U+FE00–FE0D、U+E0100–E01EF、2 連続以上の U+FE00–FE0F）による埋め込みを検出
- §15: `bun.lock`（JSONC）と `deno.lock` を解析する。`bun.lockb` は `errors[]` に `lockfile_unparsed`
- §49: 契約の `entry.cli` / `tests` が参照するファイルは拡張子・シバンが無くてもスクリプトとして抽出し、ルート内を指すシンボリックリンクのスクリプトはリンク先を読む。種別不明のテキストファイルもコードとして解析する
- シンボリックリンクの実体が検査ルート内の通常ファイルなら、リンク名でも検査する（`.mcp.json` → `cfg/servers.json` 等）。設定ファイル名のリンクがルート外を指す場合は `errors[]` に `symlink_leaves_root`
- §6: dpkg の `Status` で削除済み・config-files の ca-certificates を除外し、ベンダーを同じイメージの `os-release` から判定する（Ubuntu の SRU 版を Debian と表示していた）
- §4 / §6: CRLF の `.tool-versions` を読む。§34: 空白を含むパスの `hosts` を検査し、ドメインの大文字小文字を区別しない。§24: `~/Library/Application Support/…` の監視パスを空白で分割しない
- §38: `git log` のパスを C 形式で引用させない（`core.quotePath=false` と `-z`）。§15: `sha256sum -z` で名前の `\r` 等のエスケープを避ける

### 制限事項（決定）

- アーカイブ（`.whl`・`.tgz`・`.zip`・`.jar` 等）は展開しない。`errors[]` に `archive_not_inspected:<path>` を記録するが、健全なリポジトリにも多いため `status` は `partial` にしない

### テスト

- フィクスチャを追加: `r3-actions`・`r3-mcp-evasion`・`r3-ioc-case`・`r3-pth`・`r3-pkgjson`・`r3-ai-instr`・`r3-lockfiles`・`r3-skillpact-script`・`r3-symlink-config`・`r3-nul`・`r3-vcs-nested`・`r3-crlf-toolversions`・`r3-dpkg`・`r3-hosts-space`・`r3-archive`
- `tests/run-tests.sh` に round 3 の確認を追加（PATH の無害化、`gitdir:` / 入れ子 / include の Git 設定、ルート外を指す `.git/config`、`git log` のパスの引用、`timeout` の無い環境の孤児 `sleep`、パスのバックスラッシュ、ルート外を指す設定リンク、YAML のエイリアス、`bun.lockb`、アーカイブと `status`、Application Support、バナーの制御文字、読めないファイルと終了コード 2）
- `tests/zero-exec.sh` に PATH 偽装の罠を追加（検査ルート内の偽の jq / git / coreutils を `PATH` の先頭・`.`・空のエントリに置いても 1 つも起動しない）
- ブラウザのパリティ（`ui/tests/unit/cli-parity.test.ts`）: シンボリックリンク経由でしか届かない設定・スクリプト（`r3-symlink-config`・`r3-skillpact-script`）は CLI のみの差分として理由付きで許可

### 修正（Web Scanner UI）

- 検出一覧（表とスマホのカード型）を末尾までスクロールしたまま、検索・重大度・クリアで 0 件にしてから戻すと、一覧が空白になる問題を修正（仮想スクロールの位置を、領域を付け直したときと件数が変わったときに合わせ直す）
- モジュールで絞り込んだまま別のタブへ移ると、選択欄は「すべて」なのに全行が消える問題を修正（タブを切り替えたとき、またはそのタブに無いモジュールのときは絞り込みを外す）
- 信頼できない名前（パス・検体名・取り込んだ findings.json の文字列、ビューアの値）の制御文字（C0・DEL・C1）と双方向制御文字（U+200E/200F、U+202A〜202E、U+2066〜2069、U+061C）を `⟨U+XXXX⟩` の目印で表示し、`title`・`aria-label` にも生の文字を出さない。パスは `<bdi dir="ltr">` で前後から切り離す（`invoice<U+202E>gnp.js` が `invoicesj.png` に見える偽装を防ぐ）。コピーは元の値のまま
- スマホの貼り付けシートとモジュールのシートを閉じたとき、フォーカスを開いたボタンへ戻す（BODY へ落とさない）
- ドロップ先の外にファイルを落としてもブラウザがそのファイルへ移動しない。ファイルのドロップは画面のどこでもスキャンへ回す（判定中は通知だけ）。テキストのドラッグは妨げない。ドロップしたフォルダのエントリを読めないときはファイルの一覧で判定し、それも無ければ通知する（黙って何もしない状態にしない）
- チェックを 1 つも実行していない画面（未投入・取り込みや貼り付けだけ）で、緑の「✓ 0 / 0 チェック非該当」を出さず、無彩色の「—」にする
- フォルダの読み取りを最大 8 件の並行にした（結果の順序は投入順のまま）。Chromium で 1,500 件 約 4.4〜5.3 秒 → 約 2.8〜3.0 秒、5,000 件 約 15.8〜17.9 秒 → 約 9.9〜10.0 秒（読み取りの段階）
- ヘッダーの版を `ui/package.json` の `version` から埋め込む（手書きの文字列をやめた）

### 修正（CLI）

- 1 つの findings.json に同じ `id` の finding が重なることがあった（ZET は入力全体を拒否する）。出力をまとめるときに `id` の重複を除いて最初の 1 件だけを残し、落とした分を `errors[]` に `duplicate_finding_id:<id>`（module `core`）として記録する（`status` は `partial`）

### 既知の制限

- パスの正規形（`zes_enc`）は単射ではない: `\xHH` という 4 文字を含む名前と、不正なバイト 0xHH を含む名前は同じ `path`・`id` になる。上の修正で `id` の重複は出なくなったが、後から出た方の finding は `errors[]` の記録だけになる。正規形を単射にする（リテラルの `\` をエスケープする）と既存の `id` が変わるため、この版では行わない

### 文書

- README（日英）: UI が作る `id` は CLI の式と違い（相対パスと規則 ID から生成）、UI の中でだけ安定することを明記。UI の書き出しの `status` は、取り込んだ文書が `error` なら `error` にもなることに訂正。UI の節にライト / ダークのテーマ、タブ検索、スマホのカード型の一覧を追記
- `docs/design/ui-design-0.3.md` に 0.3.0「検疫台」の設計書を追加。`docs/design/ui-design.md` の冒頭に、0.3.0 以前の画面であることを注記
- `docs/skill-contracts.md`: `skillpact_policy.diff_anomaly_threshold` / `destructive_requires_human` は予約済み・未実装で ZET が拒否することを明記して例から削除。`action.target` は finding の `path` と一致、`chmod` は権限を狭める変更だけ、findings の `id` は一意であることを追記

### CI・テスト

- CHANGELOG の先頭の版 = `zes-scan.sh` の `ZES_VERSION` = `ui/package.json`（と `package-lock.json`）の `version` を確かめる `tests/check-versions.sh` を追加（`tests/run-tests.sh` と CI から実行）
- release: CHANGELOG の先頭の見出しが `## X.Y.Z — YYYY-MM-DD` でなければ失敗させる（下の古い版へ黙って戻らない）
- ui ジョブ: Playwright のブラウザ導入をテストと別の手順にし（10 分で打ち切り、3 回まで再試行）、`~/.cache/ms-playwright` を `@playwright/test` の版をキーにキャッシュ（`actions/cache` は v6.1.0 のコミット SHA で固定。当たったときは `install-deps` だけ）。e2e の手順にも時間の上限
- `tests/run-tests.sh`: 全フィクスチャの出力で `id` が一意であることを検査し、正規形が衝突するパスの回帰テストを追加。shellcheck の対象に `tests/*.sh` を追加
- e2e を追加（上の UI の修正ごと）。「次のスキャン中は前回の結果を表示せず…」は 1,500 件から 300 件に減らした（遅いエンジンで不安定だったため）

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
