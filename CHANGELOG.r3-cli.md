<!-- 0.3.1 の CHANGELOG に取り込む断片（round 3 のバグ探しのうち CLI と、検出に関わるもののブラウザエンジンへの移植） -->

### 修正（CLI: ゼロ実行・fail-closed）

- `PATH` を起動時に無害化する: 相対パス・空のエントリ（`.`・`::`）と、実パスが検査ルート配下のエントリ（`node_modules/.bin` 等）を外し、`errors[]` に `path_entry_dropped:<エントリ>` を記録する。`jq` と `git` は 1 度だけ絶対パスに解決して常にそれを起動する（検査ルート内の偽の `jq` / `git` / coreutils が起動していた）。無害化より前に外部コマンドを呼ばない（`dirname` / `uname` / `cat` を置き換え）。`#!/usr/bin/env bash` は ZES より先に `PATH` から `bash` を探すため、`PATH` を信頼できない場合は `bash zes-scan.sh` で起動するよう README に記載
- Git の設定を `.git` ファイル（`gitdir:`）・入れ子のリポジトリ・worktree の共有側・`include.path` / `includeIf` の参照先まで静的に検査する（§26 の `core.fsmonitor` 等、§7 のフック、§41 のフック同居）。git には読ませない。辿れない参照は `errors[]` に `gitfile_unparsed` / `gitdir_unresolved` / `gitdir_outside_root` / `git_commondir_unresolved` / `git_include_unresolved`
- VCS のメタデータとして除外するのを検査ルート直下の `.git` / `.hg` / `.svn` だけにし、入れ子の同名ディレクトリの中のコードも走査する（`lib/.svn/p.js` 等に隠せた）
- NUL を含むファイルを読み飛ばさない（`grep -I` を `-a` に。`-l` / `-q` / `-o` の全箇所）
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
