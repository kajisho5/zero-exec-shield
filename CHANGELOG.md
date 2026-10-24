# Changelog

## 0.5.3 — 2026-10-24

Fixes from the fifth bug hunt. Adversarial files can no longer stall or crash the CLI's readers, the §49 contract check accepts exactly RFC 8259 JSON on both sides, the browser now reads the Git files the CLI reads, and the CLI and the UI agree on whitespace, the BOM, NUL, Dockerfile `FROM` lines, `pyproject.toml`, launchd plists, hidden characters and directory skips. The findings.json format stays 1.2.

**Ids change only for findings whose path, campaign or a param value contains bytes that are not valid UTF-8** (see the id preimage below).

### CLI

- The YAML, TOML and JSONC readers are linear: an unclosed flow sequence (`steps: [`) over many lines, a long block scalar, long runs of blanks, 1 MB TOML strings or 250 000 `args`, or JSONC with many comments took minutes to hours (a 230 KB workflow kept a `--standard` scan busy for over 10 minutes). Text is collected in pieces and joined once, the bracket depth is tracked incrementally, and the patterns mawk matches in quadratic time on long blank runs are loops. The output is unchanged.
- `.codex/config.toml`: arrays and inline tables nested deeper than 80 (the limit of the TOML parser Codex CLI uses, toml 0.9 / `toml_parser` `RecursionGuard`) are `parse_error:nesting_too_deep` in `errors[]` (status partial). At about 140 levels mawk used to crash and every `[mcp_servers.*]` after the deep value was dropped without an error, which hid a HIGH `bash -c` server.
- Every catalog text printed to the terminal (banner, section titles, the result line, the catalog and IoC error messages with their paths) is encoded like other untrusted text. The catalog check also requires the same placeholders in `en` and `ja`, and `ZES_CATALOG_KEYS_SHA256` now covers the placeholder names, so a catalog cannot drop the `{ref}` of a detail (exit 64).
- A relative `ZES_I18N_DIR` / `ZES_IOC` gets a `./` prefix and the `--skillpact-cache` directory is used by its real path: `x=y` was read by awk as an assignment and the scan waited on stdin.
- §17 `s17.agent_hook` needs a hook entry whose command matches when the file parses as JSON / JSONC; a `curl` in `mcpServers` of `.claude/settings.json` gave a HIGH agent hook with no locators.
- §49: a contract without a string `skill.name` / `skill.version` gives `s49.partial_check_errors` (SCHEMA) like the UI instead of `s49.analysis_failed`.
- Directory skips (`node_modules`, `.git`, `site-packages`, the installed-package detection, MCP sources) test the path inside the scan root: a scan root under `node_modules/` reported nothing for §2, §32 and §36.

### Both sides (CLI and browser UI)

- §49 accepts exactly one RFC 8259 JSON document, checked in one pass with the same rules on both sides (no jq: jq 1.7 accepts `NaN`, `Infinity`, `01`, `+1`, `.5`, `1.` and several documents, and a two-document contract passed with status ok and lost its HIGH divergence finding). Numbers are compared by their exact decimal value (`9007199254740991.4` and `1e400` are outside ±(2^53−1), `1e-400` is not), the UI no longer reads only 400 characters of a number literal, and invalid UTF-8 in member names is replaced like the WHATWG decoder before duplicates are compared. `tests/ijson-cases.json` holds 74 shared vectors.
- id preimage: the escaping is applied to the original bytes and a byte that is not valid UTF-8 becomes `\xHH`, so it no longer shares an id with the text `\xHH` (in findings.json both still read `\xHH`). A repeated id is always recorded as `duplicate_finding_id`; the second of two distinct §22 findings in one file was dropped silently. `tests/id-cases.json` gains byte vectors.
- Whitespace is POSIX `[[:space:]]` in the C locale (space, tab, VT, FF, CR); the UI's `\s` and `trim()` also matched NBSP, U+3000, U+2028 and U+FEFF. Case folding in the UI is ASCII only, as `tolower` / `grep -i` (the Kelvin sign made `a.p<K>l` a pickle file).
- One leading UTF-8 BOM is ignored for every text check: the browser's TextDecoder drops it, so the CLI now reads a copy without it (a BOM before `FROM`, `build-backend` or a `.python-version` gave UI-only findings). A NUL in a value read into a shell variable becomes U+0001 instead of disappearing (`3.11<NUL>.1` was version 3.11.1 in the CLI only).
- §8 / §28 Dockerfile `FROM`: flags such as `--platform=` are skipped, so `FROM --platform=… node:latest` is floating and `FROM --platform=… alpine@sha256:…` is pinned (the flag was taken as the image); a `FROM` line without an image gives nothing (no empty `image`). `USER root:<group>` and `USER 0:0` are root.
- §27 reads `build-backend` and `backend-path` only from the `[build-system]` table (also `build-system.*` keys and `build-system = { … }`), never from inside a multi-line string (a decoy line in `description` hid the real backend), and reports `s27.backend_path` without a `build-backend`.
- §30 / `intel.launchd` read launchd plists as an XML parser does: comments are removed, CDATA is text and character references are decoded (a commented-out `com.apple.decoy` label hid `s30.random_label`). The UI now reports `s30.program_arguments`, and the CLI reads plists under any `LaunchAgents` / `LaunchDaemons` directory.
- §7 hidden characters: every Default_Ignorable_Code_Point (U+00AD, U+034F, the Hangul fillers, U+180B–180F, U+2060–206F, U+FE00–FE0F, U+1D173–1D17A, U+E0000–E0FFF …), one list (`tests/hidden-chars.json`) for the CLI's check, the UI's check and the UI's `⟨U+XXXX⟩` markers.
- §32: a file named only `.pkl` / `.PT` is flagged on both sides.

### Browser UI

- Git: the UI reads the Git files the CLI reads when they are inside the dropped folder: `config.worktree`, `include.path` / `includeIf` targets, a submodule's `.git/modules/<name>/config` and hooks, `gitdir:` files and `commondir`. Pointers that leave the folder are recorded in `errors[]` and listed in a new note, "Git files outside the folder (CLI only)".
- §41 `s41.instructions_and_hooks` (AI instruction files together with a Git hook or an agent hook config) is checked.
- §17 `s17.agent_hook` is checked, with the CLI's rule above.
- A Git hook the browser cannot read (over 2 MiB, read error) is HIGH `s7.git_hook_unread` instead of MEDIUM, and it counts as not scanned.
- The U+200D exception of the markers needs real emoji (Emoji_Presentation, or a pictograph with U+FE0F): a ZWJ between `↔`, `©` or `®` is marked, and U+FE0E / U+FE0F are kept only after a character with an emoji form.

### Tests

- New fixtures pinned on both sides by `tests/expected-codes/`: `r5-dockerfile`, `r5-pyproject`, `r5-bom`, `r5-plist`, `r5-agent-hook`, `r5-hidden`, `r5-pickle`, `r5-skillpact`. The unit-test fixture loader decodes files like the browser (TextDecoder), so the parity layer sees what the browser sees.
- `tests/run-tests.sh` (round 5): the readers on 1 MB adversarial inputs (timed), the TOML nesting limit, the shared I-JSON vectors, the catalog encoding and placeholder check, `x=y` / `-c` / `@f` paths with stdin open, the invalid-byte id pair, every hidden character, the Git tree and the `node_modules/` scan root of `ui/tests/unit/r5.test.ts`. `ui/tests/e2e/r5.spec.ts` checks the Git note and an unreadable hook.

### 日本語

5 回目のバグ探しの修正です。細工したファイルで CLI の読み取りが止まったり落ちたりしなくなり、§49 の契約は CLI と UI のどちらも RFC 8259 の JSON だけを受け付けます。ブラウザは CLI が読む Git のファイルを読み、空白・BOM・NUL・Dockerfile の `FROM`・`pyproject.toml`・launchd の plist・隠し文字・ディレクトリの除外で CLI と UI の結果が揃いました。findings.json の形式は 1.2 のままです。

**id が変わるのは、path・campaign・param の値に UTF-8 として不正なバイトを含む finding だけです**（下の id の元の文字列）。

- **CLI の読み取り**: YAML・TOML・JSONC の読み取りを線形時間にしました。閉じていない flow シーケンス（`steps: [`）が長く続く、長いブロックスカラー、長い空白の連続、1 MB の TOML 文字列や 25 万個の `args`、コメントの多い JSONC で数分〜数時間かかっていました（230 KB のワークフローで `--standard` が 10 分以上）。出力は変わりません
- **`.codex/config.toml`**: 80 段（Codex CLI が使う TOML パーサ toml 0.9 / `toml_parser` の `RecursionGuard` の上限）を超える配列・インラインテーブルの入れ子は `errors[]` の `parse_error:nesting_too_deep`（status partial）にします。140 段ほどで mawk が落ち、後ろの `[mcp_servers.*]` がエラーなしに消えて HIGH の `bash -c` サーバーが見えなくなっていました
- **カタログ**: 端末に出すカタログの文（バナー・見出し・結果行・パスを含むカタログ / IoC のエラー）をほかの信頼できない文字列と同じく符号化します。`en` と `ja` でプレースホルダが同じことも確かめ、`ZES_CATALOG_KEYS_SHA256` はプレースホルダ名も含めるので、detail の `{ref}` を消したカタログは exit 64 です
- **パス**: 相対の `ZES_I18N_DIR` / `ZES_IOC` には `./` を付け、`--skillpact-cache` は実パスで使います（`x=y` を awk が代入と読み、標準入力を待っていた）
- **§17**: `s17.agent_hook` は、JSON / JSONC として読めるファイルでは命令が一致するフックがあるときだけ報告します（`.claude/settings.json` の `mcpServers` の `curl` で、locators のない HIGH になっていた）。UI にも同じ検査を入れました
- **§49**: 文字列の `skill.name` / `skill.version` のない契約は UI と同じく `s49.partial_check_errors`（SCHEMA）にします（`s49.analysis_failed` だった）。契約は両側で同じ規則の 1 回の走査で、RFC 8259 の JSON 1 つだけを受け付けます（jq 1.7 は `NaN`・`Infinity`・`01`・`+1`・`.5`・`1.`・複数の文書を通し、2 つの文書をつないだ契約が status ok で HIGH の乖離を失っていた）。数値は厳密な 10 進の値で比べ（`9007199254740991.4` と `1e400` は ±(2^53−1) の外、`1e-400` は内）、UI は数値の先頭 400 文字だけを見ることがなくなりました。共通のテストベクタ 74 件を `tests/ijson-cases.json` に置きました
- **id の元の文字列**: エスケープは元のバイト列に対して行い、UTF-8 として不正なバイトは `\xHH` にします。文字列 `\xHH` と id が重ならなくなりました（findings.json ではどちらも従来どおり `\xHH`）。id の重複は必ず `duplicate_finding_id` として記録します（同じファイルの別の §22 が黙って消えていた）
- **CLI と UI の差**: 空白は C ロケールの `[[:space:]]`（空白・タブ・VT・FF・CR）で、UI の大文字小文字の同一視は ASCII だけです。先頭の UTF-8 BOM は両側で 1 つだけ無視し（ブラウザの TextDecoder と同じ。CLI は BOM を除いた写しを読む）、シェル変数に読む値の NUL は消さずに U+0001 にします。§8 / §28 は `FROM` の `--platform=` などを飛ばし、ダイジェスト固定のイメージは固定とし、イメージのない `FROM` 行は報告せず、`USER root:<グループ>` / `USER 0:0` も root とします。§27 は `[build-system]` の表（と `build-system.*`、`build-system = { … }`）だけから読み、複数行文字列の中は読まず、`build-backend` がなくても `s27.backend_path` を報告します。§30 / `intel.launchd` は plist を XML として読みます（コメントを除き、CDATA は文字、文字参照は展開）。UI は `s30.program_arguments` を報告し、CLI はどの `LaunchAgents` / `LaunchDaemons` の下の plist も読みます。§7 の隠し文字は Default_Ignorable_Code_Point すべてで、CLI の検査・UI の検査・UI の `⟨U+XXXX⟩` が 1 つの一覧（`tests/hidden-chars.json`）を使います。§32 は名前が `.pkl` / `.PT` だけのファイルも報告します。CLI のディレクトリの除外（`node_modules` など）は検査ルートからの相対パスで判定します
- **ブラウザ UI**: 読み込んだフォルダ内にある `config.worktree`、`include.path` / `includeIf` の参照先、サブモジュールの `.git/modules/<name>/config` とフック、`gitdir:` ファイルと `commondir` を CLI と同じく読みます。フォルダの外を指すものは `errors[]` に記録し、新しい注記「フォルダ外の Git ファイル（CLI のみ）」に並べます。§41 `s41.instructions_and_hooks` を検査します。読めない Git フック（2 MiB 超・読み取りエラー）は MEDIUM ではなく HIGH の `s7.git_hook_unread` にし、未検査として数えます。目印の U+200D の例外は本当の絵文字どうしのときだけです（`↔`・`©`・`®` の間の ZWJ は目印にする）
- **テスト**: CLI と UI の両方を `tests/expected-codes/` で固定するフィクスチャ `r5-dockerfile`・`r5-pyproject`・`r5-bom`・`r5-plist`・`r5-agent-hook`・`r5-hidden`・`r5-pickle`・`r5-skillpact` を追加し、単体テストのフィクスチャはブラウザと同じく TextDecoder で読みます。`tests/run-tests.sh` に round 5 の確認（1 MB の敵対的な入力の時間、TOML の入れ子、I-JSON のベクタ、カタログの符号化とプレースホルダ、`x=y` などのパス、不正バイトの id、隠し文字、Git の木と `node_modules/` の下の検査ルート）を、UI に `ui/tests/unit/r5.test.ts` と `ui/tests/e2e/r5.spec.ts` を追加しました

## 0.5.2 — 2026-10-24

Intelligence update for CVE-2026-111497 ("Node2Shell", renamed "HTTP2Shell" by Aikido on 2026-10-23): an out-of-bounds write in the Brotli decoder (CVSS 4.0 9.2, CNA Google) that can lead to remote code execution where Brotli from an untrusted peer is decoded. ZES already reported vulnerable Node.js runtimes; it now also reports the Python packages that bundle the decoder.

- **New**: PyPI `Brotli` `>=1.0.3 <1.2.1` (fixed 1.2.1) and `brotlicffi` `>=1.0.3 <1.2.1.0` (fixed 1.2.1.0), from GHSA-9v8h-qqgm-4m35, are HIGH `s15.pkg_vulnerable_fixed` in lockfiles, requirements files and installed `*.dist-info` (campaign `brotli-http2shell-oct2026`). The CLI and the browser engine read the same `rules/ioc.json`.
- **Changed**: the Node.js entry for CVE-2026-111497 now carries the CNA's CVSS 9.2 (it was `null` before the CVE record was published). A Node.js image finding for this CVE is therefore `intel.infra_vulnerable_cvss` (with `cvss`) instead of `intel.infra_vulnerable`, so its id changes once. The level stays HIGH (the Node.js rating is high).
- **Not added**: Bun, Envoy, Istio, curl/libcurl and OS `libbrotli` fixed versions could not be confirmed from a primary source yet (only one secondary report), and distribution backports keep the upstream version number. `docs/ioc-verification.md` lists them with the mitigation: reject `Content-Encoding: br` at the proxy and stop decoding Brotli in clients until patched.
- **Tests**: new fixture `brotli-http2shell` (vulnerable and fixed pins).

### 日本語

CVE-2026-111497（「Node2Shell」。2026-10-23 に Aikido が「HTTP2Shell」と呼び直し）の情報を更新しました。Brotli デコーダの境界外書込（CVSS 4.0 9.2、CNA は Google）で、信頼できない相手の Brotli を展開する経路があるとリモートからコードを実行される可能性があります。ZES は脆弱な Node.js をすでに報告していましたが、デコーダを同梱する Python のパッケージも報告するようにしました。

- **追加**: PyPI の `Brotli` `>=1.0.3 <1.2.1`（修正版 1.2.1）と `brotlicffi` `>=1.0.3 <1.2.1.0`（修正版 1.2.1.0）を、GHSA-9v8h-qqgm-4m35 に基づき、ロックファイル・requirements・インストール済みの `*.dist-info` で HIGH の `s15.pkg_vulnerable_fixed` として報告します（キャンペーン `brotli-http2shell-oct2026`）。CLI とブラウザのエンジンは同じ `rules/ioc.json` を読みます
- **変更**: Node.js の CVE-2026-111497 に CNA の CVSS 9.2 を入れました（CVE レコードの公開前は `null`）。このため Node.js イメージのこの CVE の finding は `intel.infra_vulnerable` ではなく `intel.infra_vulnerable_cvss`（`cvss` 付き）になり、id が 1 回だけ変わります。レベルは HIGH のまま（Node.js の評価は high）です
- **追加しなかったもの**: Bun・Envoy・Istio・curl/libcurl・OS の `libbrotli` の修正版は、まだ一次情報で確認できません（二次情報 1 件のみ）。またディストリビューションは上流の版番号のままバックポートします。`docs/ioc-verification.md` に、修正までの緩和策（プロキシで `Content-Encoding: br` を拒否し、クライアントで Brotli を展開しない）とあわせて載せました
- **テスト**: 新しいフィクスチャ `brotli-http2shell`（脆弱な版と修正版）

## 0.5.1 — 2026-10-24

Fixes from the fourth bug hunt. The browser engine now checks Git hooks and `.python-version` and handles the root `.git` / `.hg` / `.svn` like the CLI, both sides agree on the inputs where they used to differ, a damaged message catalog stops the CLI, and a crafted file name can no longer hide a finding behind another one's id. The findings.json format stays 1.2.

**Ids change only for findings whose module, campaign, path, code or a param value contains `\`, `|` or U+001F** (see the id escaping below). The GitLab §3 findings of a run without jq also change (to the ids a run with jq already had).

### CLI

- The message catalog is fail-closed: `i18n/en.json` and `i18n/ja.json` are always both read, each must be complete (`{` first, `}` last, a comma after every entry but the last, no duplicate key), both must have the same keys, and the `cli.*` / `f.*` / `log.*` keys must be the ones the script was released with (`ZES_CATALOG_KEYS_SHA256`). Otherwise the run exits 64 with the catalog error. An empty `en.json` used to make `ja.json` load as the English catalog (Japanese `detail` in findings.json with `--lang ja`), and a truncated or partial catalog used to produce `detail` strings such as `f.s22.unpinned` with no error. The files are told apart by name.
- Every `--lang` value is checked: `--lang xx --lang ja` exits 64 (only the last value was checked).
- id v2 escapes its preimage: before joining, every component (module, campaign, path, code) and every param value has `\` replaced by `\\`, `|` by `\|` and U+001F by the six characters `\u001f`. A file whose name or `uses:` value contained `|` could give another finding's id, and the second finding was dropped (`duplicate_finding_id`). The browser engine computes ids the same way; `tests/id-cases.json` holds shared test vectors.
- §3 GitLab: without jq the CVSS is read from `rules/ioc.json` too, so the finding is `s3.gitlab_vulnerable` with its `cvss` param, the same code, detail and id as with jq (it was `s3.gitlab_vulnerable_cvss9`).
- §8: a CRLF Dockerfile no longer leaves the CR in the image name (`FROM node:latest` was missed and `busybox\r` went into `params.image`).
- §27: the `build-backend` value is parsed (a quoted string, or the bare word up to a blank, `#` or quote) instead of putting the whole unquoted line into `params.backend`.
- §30: the launchd `Label` is found when its `<string>` follows after blank lines or line breaks, and a value with a line break is kept (as a plist parser reads it).
- §32: model file extensions (`.pkl`, `.pickle`, `.pt`, `.bin`) are matched case-insensitively (`model.PKL` was missed).

### Browser UI

- Git hooks (§7 `s7.git_hook` / `s7.git_hook_suspicious`) of the root and nested `.git`, and the Python runtime (§5 `s5.python_old`) from `.python-version` and `FROM python:3.x`, were not checked at all. Same codes, params, levels and paths as the CLI.
- The root `.git`, `.hg` and `.svn` are no longer walked, as in the CLI; only what the CLI reads there stays checked (`.git/config` for §26, `.git/hooks/*` for §7). Files in them used to give findings the CLI does not have.
- §49: an unparseable contract reports its problem in the CLI's fixed order (not JSON → not an object → duplicate member → depth → number → invalid UTF-8), and a lone high-surrogate escape is not JSON, as with jq.
- §8 / §27 / §30 / §32: the same rules as the CLI fixes above (the browser had the other half of each difference). §32 skips `node_modules` and `.git` only as path segments (`x_node_modules/b.pt` was skipped).
- The detail sheet below 640 px wraps a long unbroken message (it was cut off). The SkillPact rule list fits "Inconclusive" and "Not applicable" in English, and below 640 px puts the level and result under the rule title.
- A finding with a known `code` whose `params` do not fill its message (for example from another version) shows its own `detail` instead of a raw `{placeholder}`.
- Zero-width and format characters are shown as `⟨U+XXXX⟩` in untrusted names and values: U+200B–200F, U+2028, U+2029, U+2060–2064, U+FEFF and every character the §7 check reports as hidden (one shared definition). A U+200D that joins two emoji is kept.

### Docs

- `params` were documented as never holding file contents. They are strings taken from the finding and can include text from scanned files (such as a `uses:` reference or a version from a lockfile), so consumers must escape them; file contents beyond that are never included. Corrected in the README, the schema, `docs/skill-contracts` and the 0.5.0 entry below. The data does not change.
- The id v2 definition (README, schema, `docs/skill-contracts`) describes the escaping.

### Tests

- New fixtures pinned on both sides by `tests/expected-codes/`: `r4-vcs-root`, `r4-python`, `r4-crlf-dockerfile`, `r4-build-backend`, `r4-launchagent`, `r4-pickle`, `r4-skillpact-ijson`.
- `tests/run-tests.sh` (round 4): broken catalogs exit 64 in both languages, every `--lang` is checked, the colliding id pair gives two findings, `tests/id-cases.json` matches the CLI's escaping, §3 is the same without jq (`ZES_FORCE_NO_JQ=1`), and Git hooks / the root VCS directories give the same rows as the UI test. `ui/tests/unit/r4.test.ts` and `ui/tests/e2e/r4.spec.ts` (320, 360, 768, 1280 and 1440 px, English and Japanese) cover the browser side.

### 日本語

4 回目のバグ探しの修正です。ブラウザのエンジンが Git フックと `.python-version` を検査し、ルートの `.git` / `.hg` / `.svn` を CLI と同じように扱うようになりました。CLI と UI で結果が違っていた入力はどちらも同じ結果にしました。メッセージカタログが壊れていれば CLI は止まり、細工したファイル名で別の finding の id に重ねて検出を隠すこともできなくなりました。findings.json の形式は 1.2 のままです。

**id が変わるのは、module・campaign・path・code・param の値に `\`・`|`・U+001F を含む finding だけです**（下の id のエスケープ）。jq なしで走査した §3 GitLab の finding も変わります（jq ありの id と同じになります）。

- **CLI のカタログ**: `i18n/en.json` と `ja.json` を常に両方読み、どちらも完全であること（先頭が `{`、末尾が `}`、最後以外の行にカンマ、キーの重複なし）、両者のキーが同じこと、`cli.*` / `f.*` / `log.*` のキーがリリース時のもの（`ZES_CATALOG_KEYS_SHA256`）であることを確かめ、満たさなければ exit 64 にします。空の `en.json` で `ja.json` が英語のカタログとして読まれる（`--lang ja` で findings.json の `detail` が日本語になる）問題と、途中で切れたカタログで `detail` が `f.s22.unpinned` のようになってもエラーにならない問題を直しました。ファイルは名前で区別します
- **CLI の引数**: `--lang` の値をすべて検査します（`--lang xx --lang ja` も exit 64。最後の値しか見ていなかった）
- **id のエスケープ**: id v2 の元の文字列をつなぐ前に、各要素（module・campaign・path・code）と各 param の値の `\` を `\\`、`|` を `\|`、U+001F を 6 文字の `\u001f` にします。名前や `uses:` の値に `|` を含むファイルで別の finding と同じ id を作れ、後の finding が落ちていました（`duplicate_finding_id`）。ブラウザも同じ方法で計算し、共通のテストベクタを `tests/id-cases.json` に置きました
- **§3 GitLab（jq なし）**: CVSS を jq なしでも `rules/ioc.json` から読み、jq ありと同じ `s3.gitlab_vulnerable`（`cvss` 付き）・detail・id にしました（`s3.gitlab_vulnerable_cvss9` になっていた）
- **CLI と UI の差**: §8 CRLF の Dockerfile で CR が image に残らない（`FROM node:latest` の見逃し、`busybox\r`）。§27 `build-backend` は値を解析する（クォートの文字列、または空白・`#`・クォートまでの語。引用符のない行全体を params に入れていた）。§30 launchd の `Label` は空行や改行を挟んでも読み、改行を含む値もそのまま（plist として正しい）。§32 モデルの拡張子は大文字小文字を区別せず、UI は `node_modules` / `.git` をパスの区切り単位で判定（`x_node_modules/` を飛ばしていた）。§49 契約の問題は CLI の決まった順（JSON でない → オブジェクトでない → メンバーの重複 → 深さ → 数値 → 不正な UTF-8）で 1 つ報告し、対のない上位サロゲートのエスケープは jq と同じく JSON でないとする
- **ブラウザ UI**: Git フック（§7 `s7.git_hook` / `s7.git_hook_suspicious`、ルートと入れ子の `.git`）と Python のランタイム（§5 `s5.python_old`、`.python-version` と `FROM python:3.x`）を CLI と同じ code・params・level・path で検査します（まったく検査していなかった）。ルートの `.git` / `.hg` / `.svn` は CLI と同じく走査せず、CLI がそこで読むもの（§26 の `.git/config`、§7 の `.git/hooks/*`）だけを検査します。640px 未満の詳細シートは区切りのない長い文も折り返します（切れていた）。SkillPact の規則の一覧は英語の "Inconclusive" / "Not applicable" が収まる幅にし、640px 未満は重大度と結果を規則名の下の行に置きます。既知の `code` でも `params` が文を埋めない finding（別の版のもの）は `{placeholder}` ではなく自身の `detail` を表示します。信頼できない名前・値のゼロ幅文字・書式文字（U+200B–200F、U+2028、U+2029、U+2060–2064、U+FEFF と、§7 の検査が隠し文字とするもの。定義は 1 つ）を `⟨U+XXXX⟩` で表示します（絵文字どうしをつなぐ U+200D はそのまま）
- **文書**: `params` には「ファイルの内容は入れない」と書いていましたが、finding から取った文字列で、検査したファイルの文字列（`uses:` の参照やロックファイルの版など）を含むことがあるため、表示する側でエスケープが必要です。それ以上のファイルの内容は入れません。README・スキーマ・`docs/skill-contracts`・下の 0.5.0 の記述を訂正しました（データは変わりません）。id v2 の定義にエスケープを書き足しました
- **テスト**: CLI と UI の両方を `tests/expected-codes/` で固定するフィクスチャ `r4-vcs-root`・`r4-python`・`r4-crlf-dockerfile`・`r4-build-backend`・`r4-launchagent`・`r4-pickle`・`r4-skillpact-ijson` を追加しました。`tests/run-tests.sh` に round 4 の確認（壊れたカタログ、`--lang`、id の衝突、`tests/id-cases.json`、jq なしの §3、Git フックとルートの VCS ディレクトリ）を、UI に `ui/tests/unit/r4.test.ts` と `ui/tests/e2e/r4.spec.ts`（320・360・768・1280・1440px、英語と日本語）を追加しました

## 0.5.0 — 2026-10-23

ZES is now English-first. The CLI and the browser UI speak English by default, with Japanese one switch away, and findings.json is always English. Every message has a language-neutral `code`, so ids no longer depend on wording or language.

**Breaking: all finding ids change once.** Decisions and approvals made with ZET / GER on 0.4.x findings need a new scan and a new triage. After 0.5.0, rewording a message never changes an id again.

### Format (findings 1.2)

- `schema_version` is `"1.2"`. Every finding has `code` (the message id: key `f.<code>` in `i18n/en.json` / `i18n/ja.json`) and `params` (the values in the message, strings only; they can include text from scanned files, such as a `uses:` reference, so consumers must escape them — corrected in 0.5.1).
- `detail` is the English message with `params` filled in. It is the same for `--lang en`, `--lang ja`, any locale, and with or without jq.
- id v2: SHA-256 of `zes-id-v2|module|campaign|path|code|params`, with `params` as `key=value` in C-locale key order joined by U+001F, and a `null` campaign or path as the empty string. `evidence_hash` is unchanged (the file hash, otherwise the SHA-256 of the English `detail`).
- ZET accepts 1.2 as of kajisho5/zero-exec-triage#17. It never recomputes ids, so a plan stays tied to the findings.json it was made from.

### CLI

- Message catalog `i18n/en.json` / `i18n/ja.json`: 327 finding messages, 77 log lines (including 49 section titles), 27 help and error texts. They are read once at start-up with awk (no jq); `ZES_I18N_DIR` overrides the location.
- `--lang en|ja` and `ZES_LANG`, then `LC_ALL` / `LC_MESSAGES` / `LANG`: a UTF-8 Japanese locale gives Japanese, anything else English. `--lang` with another value exits 64.
- The Japanese wording is unchanged: with `--lang ja` the terminal log of every fixture is byte-identical to 0.4.0 (apart from times and pids).
- No finding was lost or added: the (level, module, campaign, path) sets of all fixtures are unchanged, and the new `tests/expected-codes/` pins code and params per fixture.

### Browser UI

- English UI with a language menu next to the theme (in the "…" menu below 640 px). It follows the browser language until you choose; `?lang=en` / `?lang=ja` also work, and the choice is saved when the browser allows it.
- The scanning engine uses the CLI's codes. 173 of its 181 codes are the CLI's own, and the second parity layer compares (level, module, campaign, path, code, params) with the CLI on all 53 fixtures. Findings, SkillPact rules, paste checks and import errors follow the selected language. The UI's ids use the v2 formula over the path relative to the dropped folder.
- The sample record stays on one row only from 1440 px; at 1280–1439 px the status text used to wrap one character per line. Labels are 12 px and never wrap; below 360 px the four fields form a 2 × 2 grid.

### Docs

- README, SECURITY, brand, `docs/skill-contracts`, `docs/ioc-verification` and the UI design documents are English, with Japanese as `*.ja.md`. SKILL.md is English and tells agents to answer in the user's language. Code comments are English.
- This changelog is bilingual from 0.5.0; earlier entries stay in Japanese.

### 日本語

ZES を英語優先にしました。CLI とブラウザ UI は英語が既定で、日本語にも切り替えられます。findings.json は常に英語です。すべての文に言語に依らない `code` を付けたため、id は文言や言語で変わらなくなりました。

**互換性のない変更: すべての finding の id が 1 回だけ変わります。** 0.4.x の findings で行った ZET の判断・GER の承認は、再スキャンと再トリアージが必要です。0.5.0 以降は文言を直しても id は変わりません。

- **形式 1.2**: finding に `code`（文の識別子。`i18n/*.json` のキー `f.<code>`）と `params`（文に入る値。文字列だけ。`uses:` の参照など検査したファイルの文字列を含むことがあるため、表示する側でエスケープすること〔0.5.1 で訂正〕）を足しました。`detail` は英語の文に params を入れたもので、`--lang`・ロケール・jq の有無に依りません。id v2 は `zes-id-v2|module|campaign|path|code|params` の SHA-256 です。`evidence_hash` の作り方は変わりません。ZET は zero-exec-triage#17 で 1.2 を受け付けます
- **CLI**: メッセージカタログ（検出の文 327、ログ 77、ヘルプ・エラー 27）を起動時に awk で 1 回だけ読みます（jq は使いません）。言語は `--lang en|ja`、`ZES_LANG`、ロケールの順に決め、UTF-8 の日本語ロケールなら日本語、それ以外は英語です。日本語の文言は変えていません（`--lang ja` の端末ログは全フィクスチャで 0.4.0 と同じ）。検出の集合も全フィクスチャで変わりません
- **ブラウザ UI**: 英語の画面と、テーマの隣の言語メニュー（640px 未満は「…」の中）を追加しました。ブラウザの言語に従い、選んだ言語を保存します（`?lang=` でも指定できます）。検査エンジンも CLI と同じ code を使い、全 53 フィクスチャで code と params まで CLI と一致することを確かめています。検体票は 1440px 以上でだけ 1 段にしました（1280〜1439px で状態の文字が 1 字ずつ折り返していたため）
- **文書**: README・SECURITY・brand・`docs/skill-contracts`・`docs/ioc-verification`・UI の設計書は英語を正とし、日本語版を `*.ja.md` に置きました。SKILL.md は英語です（利用者の言語で答えるよう指示）。コードのコメントは英語にしました。この CHANGELOG は 0.5.0 から英語と日本語の両方で書きます

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
