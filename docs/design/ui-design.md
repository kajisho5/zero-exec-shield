# ZES v5.2 Web Scanner UI（`index.html`）詳細設計書 — Step 1

- 対象仕様: ZES v5.2 Master Specification §1（絶対原則）/ §6（findings.json）/ §7（index.html）/ §5.7（§49 SkillPact）
- 版: 0.1（設計レビュー用ドラフト）
- 状態: **Step 2（SVGデザイン）とセットで承認待ち。承認前に React 実装へ着手しない。**
- 付随デザイン: `docs/design/ui-overview.svg` / `docs/design/ui-skillpact.svg` / `docs/design/ui-components.svg`

> **注記（2026-10-23）**: 本書は実装前の設計ドラフトで、記録として残しています。UI は 0.1.0 で実装済みです。§49 SkillPact に関する記述（4.2 のタブ 2、5・7 の SkillPact 関連の型、8.5）は旧形式（`.skillpact/contract.json`・`secrets` 効果・L2 記録・L3 署名ファイル・prose 矛盾・`reversible`・未宣言効果の CRITICAL）を前提としており、0.2.0 で SkillPact 0.8 形式に合わせて作り直した現在の動作とは異なります。現在の動作は [README](../../README.ja.md) の「§49 SkillPact 契約（実験的）」と [CHANGELOG](../../CHANGELOG.md) を参照してください。

> 表記ルール: 【事実】=仕様書に明記、【設計判断】=本書での提案、【要承認】=ユーザー判断が必要、【不明】=現時点で確認できない事項。

---

## 1. 要件定義

### 1.1 機能要件

| ID | 要件 | 根拠 |
|---|---|---|
| F-01 | フォルダのドラッグ＆ドロップで配下ファイル一覧を取得し判定する | 【事実】§7.1 |
| F-02 | D&D非対応環境では `<input type="file" webkitdirectory multiple>` でフォルダ選択にフォールバック | 【事実】§7.1 |
| F-03 | テキスト貼り付け欄で C2ドメイン/IP、`base64`/`exec(`/`curl` 等を判定 | 【事実】§7.1, §7.3 |
| F-04 | `rules/ioc.json` をビルド時に index.html へインライン埋め込み（`file://` で動作） | 【事実】§7.1 |
| F-05 | 全18タブ（§7.2 の順序固定）。主画面は「総合サマリ＋重大度フィルタ」 | 【事実】§7.2, §15 |
| F-06 | 重大度色分け（CRITICAL/HIGH/MEDIUM/LOW/INFO/SAFE）、検出パスのコピー | 【事実】§7.4（MEDIUM/LOW/INFOは §6 の level 列挙に合わせ【設計判断】で追加） |
| F-07 | Blast Radius パネル: 対象パスのリストのみ表示、内容は表示しない | 【事実】§7.4, §1 |
| F-08 | MCP設定ビューア（`command`/`args` ハイライト） | 【事実】§7.4 |
| F-09 | GitHub Actions ビューア（`uses:` のタグ参照/SHA固定を色分け） | 【事実】§7.4 |
| F-10 | ブラウザ拡張ビューア（危険パーミッション/`<all_urls>` ハイライト） | 【事実】§7.4 |
| F-11 | SkillPact ビューア: 契約・実態・差分・ポリシー決定・差分異常 | 【事実】§7.4, §5.7 |
| F-12 | 結果を findings.json（§6 互換）としてエクスポート（Blob + `<a download>`。ネットワーク不使用） | 【設計判断】§6 との相互運用 |
| F-13 | ZES CLI が出力した `findings.json` を読み込んで表示（ビューアモード） | 【設計判断】【要承認】 |

### 1.2 非機能要件（絶対制約）

| ID | 制約 | 実現手段 |
|---|---|---|
| N-01 | 外部通信ゼロ（CDN禁止、`fetch`/`XMLHttpRequest`/`WebSocket`/`EventSource`/`navigator.sendBeacon` 不使用） | 単一HTMLへ全インライン化＋CSP `connect-src 'none'`＋ビルド後の静的grepテスト＋Playwrightでのリクエスト監視（§11） |
| N-02 | `file://` で動作 | ES Module の外部読込をしない（全スクリプトをインライン）。`type="module"` のインラインスクリプトは file:// でも動作するが、念のため IIFE 出力も選択可能に（【要承認】§13） |
| N-03 | ダークUI、背景 `#0a0a0a` | デザイントークン §2 |
| N-04 | ファイル内容は**判定にのみ**使用し、UI・エクスポートに内容を一切出さない | 判定関数の戻り値型を「パス＋ルールID＋メタ情報」に限定（§6.3 の型で強制）。プレビュー機能を持たない |
| N-05 | Zero-Execution: 投入ファイルを評価・実行しない（`eval`/`new Function`/`<script>` 挿入/Worker への投入コード渡し禁止） | ESLint `no-eval`/`no-new-func`/`no-implied-eval` を error、`dangerouslySetInnerHTML` 禁止ルール |
| N-06 | 大量ファイル（数万件）でもUIが固まらない | ファイル読み取りはチャンク処理（`requestIdleCallback`/`setTimeout(0)` 分割）、テーブルは仮想スクロール |
| N-07 | 読み取り上限 | 1ファイルあたり既定 2 MiB まで読み取り（超過分は「サイズ超過・未判定」として INFO 表示。0件扱いしない＝§10.1 fail-closed の精神） |
| N-08 | アクセシビリティ WCAG 2.1 AA 相当 | §10 |

### 1.3 スコープ外

- サーバー送信・クラウド連携・自動更新（N-01 により禁止）
- ファイル内容のプレビュー（N-04 により禁止）
- 修復操作（§0.2 の3層構えにより修復層の責務。UIは検知層）
- L3署名の暗号学的検証（§5.7 により実施しない。「署名ファイルあり」の表示のみ）

---

## 2. デザイントークン（SVGと一致）

### 2.1 カラー

| トークン | 値 | 用途 |
|---|---|---|
| `--bg` | `#0a0a0a` | ページ背景 |
| `--surface` | `#141414` | カード・パネル |
| `--surface-2` | `#1c1c1c` | テーブルヘッダ・入力欄・ホバー |
| `--border` | `#2a2a2a` | 区切り線・枠 |
| `--border-strong` | `#3a3a3a` | フォーカス前の入力枠 |
| `--text` | `#ededed` | 本文 |
| `--text-muted` | `#a3a3a3` | 補足 |
| `--text-subtle` | `#8a8a8a` | キャプション（`#0a0a0a` 上でコントラスト約5.9:1） |
| `--accent` | `#38bdf8` | フォーカスリング・リンク・アクティブタブ下線 |
| `--critical` / `--critical-bg` | `#ef4444` / `#2a0f0f` | CRITICAL、宣言外エフェクト（差分）の赤ハイライト |
| `--high` / `--high-bg` | `#f97316` / `#2a170a` | HIGH |
| `--medium` / `--medium-bg` | `#eab308` / `#262008` | MEDIUM |
| `--low` / `--low-bg` | `#3b82f6` / `#0d1a30` | LOW |
| `--info` / `--info-bg` | `#a3a3a3` / `#1c1c1c` | INFO |
| `--safe` / `--safe-bg` | `#22c55e` / `#0c2214` | SAFE（※SkillPactタブでは使用しない。§8.5） |
| `--signed` / `--signed-bg` | `#a78bfa` / `#1b1430` | L3「署名済みファイル」バッジ（安全色の緑を意図的に避ける） |

- 重大度は**色だけに依存しない**（WCAG 1.4.1）: 必ずラベル文字列（CRITICAL 等）とアイコン形状（八角形/三角/円/チェック）を併記。

### 2.2 タイポグラフィ

- `font-family: system-ui, 'Hiragino Sans', 'Noto Sans JP', sans-serif`（Webフォント読込なし＝N-01）
- 等幅（パス・コマンド・ハッシュ）: `ui-monospace, SFMono-Regular, Menlo, Consolas, monospace`
- スケール: 24/600（ページタイトル）、18/600（セクション）、14/400（本文）、13/400（テーブル）、12/500（バッジ・キャプション）、行間 1.5（日本語本文は 1.7）

### 2.3 余白・形状

- 8px グリッド（4/8/12/16/24/32）。ページ左右余白 32px（≥1280px）、16px（<768px）
- 角丸: カード 12px、ボタン/入力 8px、バッジ 6px、タブ 0（下線スタイル）
- 最小タップ領域 32×32px（ポインタ）/ 44×44px（タッチ時）

---

## 3. 技術スタック方針

【事実】ユーザー規約により React ベース必須。【事実】§1/§7.1 により CDN 禁止・`file://` 動作・外部通信ゼロ。
→【設計判断】**ビルド時に全依存をバンドルし、単一の `index.html` に JS/CSS/ioc.json をインライン化**する。ランタイムで外部リソースを一切取得しない。

| 層 | 候補 | 備考 |
|---|---|---|
| UI | React 18 系 + TypeScript（strict） | バージョンは**実装時に公式（react.dev / npm）で確認し lockfile で固定** |
| ビルド | Vite | 同上 |
| 単一ファイル化 | `vite-plugin-singlefile`（候補） | 同上。代替: Vite の `build.assetsInlineLimit` + 自前インライン化スクリプト |
| スタイル | Tailwind CSS（ビルド時にCSS生成、未使用クラスはパージ） | 同上。v3/v4 の選択は実装時に確認 |
| 仮想スクロール | 自前実装（依存削減）または `@tanstack/react-virtual`（候補） | 【要承認】依存最小化を優先し自前実装を推奨（※ `@tanstack/*` は §3.2 で侵害キャンペーン対象名前空間のため、採用時はバージョン/ハッシュの厳格固定が必須） |
| テスト | Vitest（ロジック）、Playwright（E2E・外部リクエストゼロ検証） | 同上 |
| Lint | ESLint（`no-eval`, `no-new-func`, `no-implied-eval`, `no-restricted-globals: fetch, XMLHttpRequest, WebSocket, EventSource`, `react/no-danger`） | 同上 |

- 依存は `package-lock.json` を **`npm ci --ignore-scripts`** で導入（§3.2 キャンペーン対策・§12 ワクチンと整合）。ビルド成果物はリポジトリ直下 `index.html` にコミットし、利用者はビルド不要。
- **CSP（`<meta http-equiv>`）案**:
  `default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; font-src 'none'; connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'`
  - 【不明】`file://` 下での CSP meta の挙動はブラウザ差があり得るため、実装時に Chromium / Firefox / Safari で実測確認する。
  - 【設計判断】`'unsafe-inline'` は単一ファイル化の都合上必要。代替としてビルド時にスクリプトの SHA-256 を計算し `script-src 'sha256-…'` を出力する方式を推奨（【要承認】）。

---

## 4. 画面構成

### 4.1 全体レイアウト（1440×900 基準、`ui-overview.svg`）

```
┌ Header (64px) ─────────────────────────────────────────────────────────┐
│ [盾ロゴ] Zero-Exec Shield v5.2   bundle: ZES-2026-OCT-EMERGENCY-V5.2    │
│                              [● オフライン / 外部通信ゼロ] [JSON出力] [クリア] │
├ TabBar (48px, 横スクロール + 左右スクロールボタン + 「すべてのタブ ▾」) ──────┤
│ 総合 | SkillPact | TeamPCP | ChainDrop | PyPI | Solana | Post-ShaiHulud | … │
├ Main ──────────────────────────────────────────────────────────────────┤
│ ┌ 入力(左 2/3) ─────────────────────┐ ┌ Blast Radius(右 1/3) ─────────┐ │
│ │ DropZone  |  PasteBox             │ │ シークレット存在リスト（パスのみ） │ │
│ └───────────────────────────────────┘ │                                │ │
│ SummaryCards: CRITICAL / HIGH / MEDIUM / SAFE                          │ │
│ SeverityFilter(トグル) + 検索 + モジュール絞込                             │ │
│ FindingsTable(仮想スクロール): 重大度 | モジュール | キャンペーン | パス[コピー] | 詳細 │
└────────────────────────────────────────────────────────────────────────┘
```

- **18タブの扱い**【設計判断】: 1段・横スクロール（`overflow-x: auto`、スクロールスナップ）＋両端フェード＋左右スクロールボタン＋右端「すべてのタブ ▾」メニュー（全18件をリスト表示しジャンプ）。各タブに件数バッジ（最大重大度色）を表示。2段折返しはタブ位置が変動し記憶しづらいため不採用。
- <1024px: Blast Radius パネルは入力エリアの下へ縦積み。<768px: SummaryCards は 2×2。

### 4.2 タブ一覧と表示内容（§7.2 順序固定）

| # | タブ | 主な判定（UI側） | 対応CLIモジュール | ビューア |
|---|---|---|---|---|
| 1 | 総合 | 全ルールの集約、重大度サマリ、Blast Radius | 全§ | SummaryCards / FindingsTable |
| 2 | SkillPact | 契約JSONパース、宣言vs実態、prose矛盾、ポリシー、L2/L3、差分異常 | §49（§2/§7/§15/§17 再利用相当） | SkillPactViewer |
| 3 | TeamPCP | `router_init.js`/`tanstack_runner.js`/`vite_setup.mjs`、`@tanstack/*` 等の lockfile 照合、C2 IoC（貼付） | §15, §18, §45 | FindingsTable |
| 4 | ChainDrop | `setup.mjs`/`Math_Symbol.js`/`math_init.js`、`preinstall: "node setup.mjs"`、SHA-256 照合、keyv 系バージョン | §15 | FindingsTable |
| 5 | PyPI | litellm/lightning/telnyx/py2ops/mistralai/guardrails-ai、`cook.pth`/`sitecustomize.py`、`_runtime/` | §2, §15 | FindingsTable |
| 6 | Solana | `@solana-labs/*` タイポ（lockfile/package.json） | §9, §15 | FindingsTable |
| 7 | Post-ShaiHulud | `iron-worm`/`sckit`/`miasma`/`cargo-install` 偽装（ファイル名） | §25 | FindingsTable |
| 8 | MCP | `.mcp.json` 等の `command`/`args` 危険コマンド、SymJack デコイ、`runOn: folderOpen`、description 内の注入語 | §17, §20, §37 | McpViewer |
| 9 | GitHub Actions | `pull_request_target`+checkout(refなし)+secrets、`uses:` タグ参照、`permissions: write-all`、cache キー | §21, §22, §38 | ActionsViewer |
| 10 | ブラウザ拡張 | `manifest.json` の危険パーミッション/`<all_urls>`/`update_url` | §24, §42 | ExtensionViewer |
| 11 | ビルドフック | `build.rs` の `Command::new`/`include_bytes!`、`//go:generate curl`、`build-backend` 非safe | §27 | FindingsTable |
| 12 | モデル供給網 | `.pkl`/`.pickle`/`.pt`/`.bin`、`weights_only=False`、`trust_remote_code=True`、`--extra-index-url` | §32 | FindingsTable |
| 13 | 永続化 | LaunchAgents plist、`ld.so.preload`、systemd user、autostart、`.envrc`、shell hooks（投入ファイル内で判定） | §10, §26, §30, §31, §33 | FindingsTable |
| 14 | アンチフォレンジック | `HISTFILE=/dev/null`/`HISTSIZE=0`（投入ファイル内）。※noatime/auditd はブラウザから判定不可→「CLIで確認」案内 | §35 | FindingsTable + CliOnlyNotice |
| 15 | HF | データセットスクリプトの `subprocess`/`eval`/`__reduce__`/`pickle.loads`/`dill`、`transformers.pyz` | §36 | FindingsTable |
| 16 | eBPF/LD_PRELOAD | 投入ファイル内の `LD_PRELOAD`、`/etc/ld.so.preload` 参照、QLNX/LinkPro/VoidLink 指標。※`bpftool`/`lsmod` はCLI専用 | §40 | FindingsTable + CliOnlyNotice |
| 17 | AIアシスタント | `.cursorrules`/`CLAUDE.md`/`.github/copilot-instructions.md` の不可視文字・BiDi（U+202A–202E, U+2066–2069）・ホモグリフ、リポジトリ直下 `git.exe` | §7, §41 | FindingsTable |
| 18 | Sigstore/SBOM | cosign 引数の `--certificate-identity`/`--certificate-oidc-issuer` 欠落、SBOM 有無、`provenance` 不在 | §28, §43, §48 | FindingsTable |

- ホスト状態に依存する判定（`ps`/`lsof`/`uname`/`docker version`/`bpftool`/`mount` 等）はブラウザでは実施不可。該当タブに **CliOnlyNotice**（「この項目は `./zes-scan.sh --full` で確認」）を表示し、0件=安全と誤認させない（§10.1 fail-closed）。

---

## 5. コンポーネント分割

### 5.1 ツリー

```
<App>
 ├─ <ScanProvider>                     … Context + useReducer（§6）
 │   ├─ <Header>
 │   │    ├─ <BrandMark/>
 │   │    ├─ <BundleBadge bundle/>
 │   │    ├─ <OfflineIndicator/>        … 常時「外部通信ゼロ」表示
 │   │    └─ <HeaderActions onExport onClear/>
 │   ├─ <TabBar tabs activeId counts onSelect/>
 │   │    ├─ <TabScrollButton direction/>
 │   │    ├─ <Tab …/> ×18
 │   │    └─ <AllTabsMenu/>
 │   └─ <TabPanel id>                   … role="tabpanel"
 │        ├─ [総合] <OverviewTab>
 │        │    ├─ <InputArea>
 │        │    │    ├─ <DropZone onFiles/>        … D&D + webkitdirectory fallback
 │        │    │    └─ <PasteBox onSubmit/>
 │        │    ├─ <ScanProgress/>
 │        │    ├─ <SummaryCards counts filter onToggle/>
 │        │    ├─ <FindingsToolbar>（<SeverityFilter/> <SearchInput/> <ModuleSelect/>）
 │        │    ├─ <FindingsTable findings/>   … 仮想スクロール
 │        │    │    └─ <FindingRow finding/>（<SeverityBadge/> <CopyPathButton/>）
 │        │    └─ <BlastRadiusPanel items/>
 │        ├─ [SkillPact] <SkillPactTab>
 │        │    ├─ <SkillList skills selectedId onSelect/>
 │        │    └─ <SkillPactViewer analysis/>
 │        │         ├─ <ContractStatus/>  <LevelBadge level signed/>  <PolicyDecisionBadge/>
 │        │         ├─ <EffectMatrix declared observed divergence/>
 │        │         ├─ <ProseConflictAlert conflicts/>
 │        │         ├─ <DiffAnomalyAlert anomaly/>
 │        │         └─ <RuleResultList results/>
 │        ├─ [MCP] <McpViewer configs/>
 │        ├─ [GitHub Actions] <ActionsViewer workflows/>
 │        ├─ [ブラウザ拡張] <ExtensionViewer manifests/>
 │        └─ [その他] <CampaignTab campaignIds modules cliOnly?/>（FindingsTable 再利用）
 └─ <ToastRegion/>                       … aria-live="polite"
```

### 5.2 主要 Props 型

```ts
type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
type DisplaySeverity = Severity | 'SAFE';

interface TabDef { id: TabId; label: string; modules: string[]; campaigns: string[]; cliOnlyNote?: string }
interface TabBarProps { tabs: TabDef[]; activeId: TabId; counts: Record<TabId, { total: number; max?: Severity }>; onSelect(id: TabId): void }
interface DropZoneProps { disabled?: boolean; onFiles(files: ScannedFileInput[]): void }   // File + webkitRelativePath
interface PasteBoxProps { maxLength: number; onSubmit(text: string): void }                 // 既定 1,000,000 文字
interface SummaryCardsProps { counts: Record<DisplaySeverity, number>; active: Set<Severity>; onToggle(s: Severity): void }
interface SeverityFilterProps { active: Set<Severity>; onChange(next: Set<Severity>): void }
interface FindingsTableProps { findings: Finding[]; rowHeight?: number; emptyState: 'not-scanned' | 'no-match' | 'clean' }
interface FindingRowProps { finding: Finding; onCopyPath(path: string): void }
interface CopyPathButtonProps { path: string }                                               // navigator.clipboard.writeText（ネットワーク非使用）
interface BlastRadiusPanelProps { items: BlastRadiusItem[] }
interface SkillListProps { skills: SkillPactAnalysis[]; selectedId?: string; onSelect(id: string): void }
interface SkillPactViewerProps { analysis: SkillPactAnalysis }
interface EffectMatrixProps { declared: Effect[]; observed: Effect[]; divergence: Effect[] }
interface LevelBadgeProps { level: 'L1' | 'L2' | 'L3' | null; signed: boolean }             // L3 でも「安全」表記禁止
interface PolicyDecisionBadgeProps { decision: 'allow' | 'ask' | 'deny' | null }
interface ProseConflictAlertProps { conflicts: ProseConflict[] }
interface DiffAnomalyAlertProps { anomaly: DiffAnomaly | null }
interface McpViewerProps { configs: McpConfigView[] }
interface ActionsViewerProps { workflows: WorkflowView[] }
interface ExtensionViewerProps { manifests: ExtensionView[] }
interface CampaignTabProps { tab: TabDef; findings: Finding[] }
```

---

## 6. 状態管理

【設計判断】外部状態ライブラリは使わず `useReducer` + Context（依存最小化＝供給網リスク低減）。重い判定は純関数 `engine/*` に分離し UI から独立テスト可能にする。

### 6.1 State 型

```ts
interface ScanState {
  phase: 'idle' | 'reading' | 'analyzing' | 'done' | 'error';
  progress: { processed: number; total: number };
  files: ScannedFile[];                 // メタ情報のみ（内容は保持しない）
  findings: Finding[];
  skillpact: SkillPactAnalysis[];
  blastRadius: BlastRadiusItem[];
  viewers: { mcp: McpConfigView[]; actions: WorkflowView[]; extensions: ExtensionView[] };
  errors: ScanError[];                  // §6 errors[] 互換
  ui: {
    activeTab: TabId;
    severityFilter: Set<Severity>;      // 既定: 全選択
    query: string;
    moduleFilter: string | null;
    selectedSkillId: string | null;
  };
  startedAt?: string; finishedAt?: string;   // RFC 3339 UTC
}
```

### 6.2 Action

```ts
type Action =
  | { type: 'SCAN_START'; total: number; startedAt: string }
  | { type: 'SCAN_PROGRESS'; processed: number }
  | { type: 'SCAN_RESULT'; result: EngineResult }          // findings/skillpact/blastRadius/viewers/errors を一括
  | { type: 'SCAN_FAIL'; error: ScanError }
  | { type: 'PASTE_RESULT'; result: EngineResult }
  | { type: 'IMPORT_FINDINGS'; doc: FindingsDoc }           // F-13
  | { type: 'SET_TAB'; tab: TabId }
  | { type: 'TOGGLE_SEVERITY'; severity: Severity }
  | { type: 'SET_QUERY'; query: string }
  | { type: 'SET_MODULE'; module: string | null }
  | { type: 'SELECT_SKILL'; id: string | null }
  | { type: 'CLEAR' };
```

### 6.3 内容非保持の担保

- ファイル内容（`string`）は `engine/analyzeFile()` の**ローカル変数としてのみ**存在し、State・Finding・エクスポートに入らない。`Finding.detail` はルール定義側の固定テンプレート文字列（例: 「契約は read のみ宣言、実態に exec を検出」）からのみ生成し、ファイル由来の文字列を連結しない。
- 例外: ファイルの**パス**（`webkitRelativePath`）と JSON 設定のキー名・`command` 値（MCPビューア）・`uses:` 参照（Actionsビューア）・パーミッション名（拡張ビューア）。これらは §7.4 で表示が要求されているため「設定値のハイライト表示」として許容。【要承認】§13-4。

---

## 7. データ構造（TypeScript）

```ts
// ---- IoC DB（rules/ioc.json をビルド時インライン、§3） ----
interface IocDb {
  incident_bundle: string;                        // "ZES-2026-OCT-EMERGENCY-V5.2"
  packages: IocPackage[];
  worm_iocs: Record<string, unknown>;
  infrastructures: unknown[];
  mcp_poisoning: Record<string, unknown>;
  github_actions: Record<string, unknown>;
  browser_extensions: { dangerous_permissions: string[]; dangerous_matches: string[]; [k: string]: unknown };
  build_hooks: Record<string, string[]>;
  model_supply_chain: Record<string, unknown>;
  persistence: Record<string, unknown>;
  anti_forensics: Record<string, unknown>;
  ai_coding_assistant: Record<string, unknown>;
  skillpact: SkillPactRules;
  markers: string[]; malicious_files: string[]; process_signatures: string[];
}
interface IocPackage { campaign: string; eco: string; name: string; bad_versions?: string; safe_version?: string; note?: string }
interface SkillPactRules {
  contract_filenames: string[]; schema_versions: string[];
  effects: Effect[]; levels: ('L1'|'L2'|'L3')[];
  policy_files: string[]; decision_values: ('allow'|'ask'|'deny')[];
  risk_flags: string[]; destructive_markers: string[]; persistence_markers: string[];
  trust_model: { l3_means: 'signed_files'; l3_does_not_mean: string; account_compromise_resilient: boolean; mitigation: string };
}
type Effect = 'exec' | 'network' | 'write' | 'read' | 'secrets' | 'spend';

// ---- 入力ファイル（メタ情報のみ保持） ----
interface ScannedFile {
  relPath: string;            // webkitRelativePath または D&D の fullPath
  name: string; size: number; lastModified: number;
  isZeroByte: boolean;        // SymJack デコイ判定用（§7.3）
  readState: 'read' | 'skipped-size' | 'skipped-binary' | 'error';
}

// ---- findings.json（§6 互換。UI 由来は path を相対パスで出す） ----
interface Finding {
  id: string;                 // "sha256:<hex>" = SHA-256(module|campaign|path|ruleId)（crypto.subtle.digest、決定的）
  level: Severity;
  module: string;             // "§49" 等
  campaign: string | null;
  path: string;
  detail: string;             // 固定テンプレート由来（§6.3）
  evidence_hash?: string;     // "sha256:<hex>"（対象ファイル内容のハッシュ。内容そのものは出さない）
  skillpact?: SkillPactFindingField;
  source: 'ui' | 'cli-import';     // UI 内部用。エクスポート時は除外
  ruleId: string;                  // UI 内部用。エクスポート時は除外
}
interface SkillPactFindingField {
  contract_path: string | null; contract_version: string | null;
  level: 'L1'|'L2'|'L3'|null; signed: boolean; author: string | null;
  declared_effects: Effect[]; observed_effects: Effect[];
  policy_decision: 'allow'|'ask'|'deny'|null;
  l2_tested: boolean; divergence: Effect[]; diff_anomaly: boolean;
}
interface FindingsDoc {
  schema_version: '1.0'; incident_bundle: string;
  scan_started_at: string; scan_finished_at: string;
  scan_mode: 'quick'|'standard'|'full'|'worm'|'skillpact';   // UI は【要承認】§13-5
  status: 'ok'|'partial'|'error';
  findings: Omit<Finding, 'source'|'ruleId'>[];
  errors: ScanError[];
}
interface ScanError { module: string; reason: string }

// ---- SkillPact 解析結果（ビューア用） ----
interface SkillPactAnalysis {
  skillId: string;                    // SKILL.md を含むディレクトリの相対パス
  skillMdPath: string;
  contract: { found: boolean; path: string | null; parseError: boolean; schemaVersion: string | null; supported: boolean };
  author: string | null; version: string | null;
  level: 'L1'|'L2'|'L3'|null;
  signature: { fileFound: boolean; verifyCommandDeclared: boolean };   // 検証はしない
  l2: { recordFound: boolean; recordPath: string | null; hashDeclared: boolean; hashMatches: boolean | null };
  declared: Effect[]; observed: Effect[];
  observedEvidence: { effect: Effect; path: string; ruleId: string }[];   // パスとルールIDのみ
  divergence: Effect[];               // observed − declared（exec/network/secrets を CRITICAL 対象）
  destructiveHits: { marker: string; path: string }[];
  persistenceHits: { marker: string; path: string }[];
  policy: { file: string | null; decision: 'allow'|'ask'|'deny'|null; neverAutoAllowViolations: string[] };
  irreversibleAllowed: string[];      // reversible:false かつ allow の操作ID
  proseConflicts: ProseConflict[];
  diffAnomaly: DiffAnomaly | null;
  results: RuleResult[];              // §5.7 検出ルール表 12 行の判定結果
}
interface ProseConflict { claim: 'read-only'|'no-network'|'no-modify'|'no-exec'; phraseId: string; sourcePath: string; contradictedBy: Effect[] }
interface DiffAnomaly { previousVersion: string; addedEffects: Effect[]; addedNetworkTargets: number; secretsScopeExpanded: boolean; score: number; threshold: number }
interface RuleResult { ruleNo: number; title: string; level: Severity; status: 'hit'|'clear'|'n/a'|'undetermined' }

interface BlastRadiusItem { path: string; kind: 'ssh'|'aws'|'gcloud'|'claude'|'cursor'|'gh'|'docker'|'npmrc'|'pypirc'|'kube'|'vault'|'git-credentials'|'netrc'|'heroku'|'terraform'|'op'|'env'|'private-key'; size: number }
```

---

## 8. 判定ロジック（クライアントサイド、§7.3）

すべて `engine/` 配下の純関数。入力は `File` 群または貼り付け文字列、出力は `EngineResult`（内容を含まない）。

### 8.1 ファイル名一致
- `ioc.malicious_files` / `worm_iocs.*.files` / `post_shaihulud.binaries` とファイル名（basename）を完全一致比較 → CRITICAL。
- ChainDrop 系はファイル内容の SHA-256 を `crypto.subtle.digest` で計算し `worm_iocs.chaindrop.hashes.sha256` と照合（一致で CRITICAL、名前一致のみで HIGH）。【設計判断】

### 8.2 `package.json` の `preinstall`/`postinstall`
- `JSON.parse` のみ。`scripts.preinstall === "node setup.mjs"` → CRITICAL（ChainDrop）。その他の install 系フック存在 → HIGH。
- `dependencies` 等と `ioc.packages`（eco=npm）を照合。`package-lock.json` も同様（バージョン比較は semver 簡易比較の自前実装）。

### 8.3 SymJack
- `webkitRelativePath` がデコイ名パターン（`vid-` 接頭、`logo.`/`readme.` 接頭、`docs/` 配下）**かつ** `size === 0` → 「要手動確認（HIGH）」。【事実】ブラウザはシンボリックリンクのリンク先を取得できないため確定判定はしない（CLI §17 で `readlink -f` 確認を案内）。

### 8.4 貼り付けテキスト
- C2ドメイン/IP: `ioc` 内の `[.]` 無害化表記を照合用に復元（メモリ内のみ）し、貼り付け文字列と大文字小文字無視で部分一致 → CRITICAL。
- `base64`（長さ ≥ 40 の Base64 連続文字列 or `base64 -d`）、`exec(`、`curl`、`wget`、`| bash`、`| sh` → HIGH。
- 表示はルールIDとヒット件数のみ（貼り付け内容を再表示しない）。

### 8.5 SkillPact（§5.7 を UI で再現）
1. **スキル単位の特定**: `SKILL.md` を含むディレクトリ = 1スキル。
2. **契約探索**: `contract_filenames`（`skill.contract.json`, `.skillpact/contract.json`）。**`JSON.parse` のみ**。パース失敗は「契約不正」として扱い 0件扱いしない。
3. **スキーマ**: `schema_version` が `schema_versions`（"0.8"）以外 → MEDIUM。
4. **実態エフェクト推定**（静的・正規表現）: SKILL.md のコードフェンス/スクリプト（`.sh/.py/.js/.ts/.mjs/.ps1` 等）から exec/network/write/secrets/spend の痕跡を抽出。パターン定義は CLI §49 と共通の `rules/ioc.json` を参照（【要承認】§13-6: パターンの置き場所）。
5. **突合**: `divergence = observed − declared`。exec/network/secrets の未宣言 → CRITICAL（赤ハイライト）。
6. **L2**: `effects` に exec/network/secrets があり L2 記録ファイルが無い → HIGH。記録は存在とハッシュのみ確認（再実行しない）。
7. **L3**: 署名ファイルの存在と検証コマンド宣言の有無のみ表示。**バッジ文言は「L3 署名済みファイル」。「安全」「信頼済み」「Verified」等の語を使わない**。安全色（緑）も使わない（`--signed` 紫）。ツールチップ: 「L3 は署名済みファイルであることのみを示し、安全性や作者の信頼性を意味しません（trust_model.l3_does_not_mean）」。
8. **ポリシー**: `policy_files` を JSON パースし `allow/ask/deny` を表示。`never_auto_allow_any` を尊重していない場合 → HIGH。
9. **破壊的/永続化マーカー**: `destructive_markers` 検出 ∧ 決定 `allow` → HIGH。`persistence_markers` 検出 ∧ 契約に `persist`/`write` なし → CRITICAL。
10. **不可逆操作**: `reversible: false` ∧ `allow` → CRITICAL。
11. **prose矛盾**: SKILL.md/README のコードフェンス外テキストから「読み取りのみ / read-only / 参照だけ」「外部通信なし / no network」「ファイル変更なし / does not modify」「実行しない / does not execute」を抽出し、契約エフェクトと矛盾 → HIGH。
12. **差分異常**: 同一 `author` の前バージョン契約が**同時に投入されている場合のみ**比較（ブラウザはレジストリ取得不可＝N-01）。exec/network 新規追加、network 送信先増加、secrets スコープ拡大 → HIGH（L3 でも警告）。前バージョンが無い場合は「undetermined（比較対象なし）」と明示。
- **SkillPact タブでは SAFE 表示を使わない**。全ルール非該当でも「検出なし（静的解析の範囲内）」と表記し、安全の断定をしない。

### 8.6 MCP / Actions / 拡張ビューア
- MCP: `.mcp.json` 等を JSON/TOML（TOML は最小パーサ自前実装、【要承認】）でパース、`mcpServers.*.command/args` を表示し `suspicious_commands` 該当トークンを赤ハイライト。
- Actions: YAML は**完全パーサを使わず**行単位の正規表現で `uses:` / `on: pull_request_target` / `permissions:` を抽出（依存削減。誤検知は CLI で確定）。`@v*` 等タグ参照 = HIGH 色、40桁SHA = SAFE 色。
- 拡張: `manifest.json` の `permissions`/`host_permissions`/`update_url` を表示し危険値をハイライト。

---

## 9. ディレクトリ構成

```text
zero-exec-shield/
├── index.html                 ← ビルド成果物（単一ファイル、コミット対象）
├── rules/ioc.json             ← 単一の真実の源。ビルド時に ui/ から import してインライン化
└── ui/
    ├── package.json / package-lock.json
    ├── vite.config.ts         ← singlefile 化、outDir: '..'、emptyOutDir: false、出力名 index.html
    ├── tailwind.config.ts / postcss.config.js / tsconfig.json / eslint.config.js
    ├── index.html             ← テンプレート（CSP meta を含む）
    ├── scripts/
    │   ├── inject-csp-hash.mjs    ← ビルド後に script/style の SHA-256 を CSP へ（【要承認】）
    │   └── verify-no-network.mjs  ← 成果物に fetch/XMLHttpRequest/WebSocket/http(s):// 参照が無いか静的検査
    ├── src/
    │   ├── main.tsx / App.tsx
    │   ├── state/ (ScanContext.tsx, reducer.ts, types.ts)
    │   ├── engine/                ← 純関数（Vitest 対象）
    │   │   ├── index.ts (analyzeFiles, analyzePaste)
    │   │   ├── rules/ (filenames.ts, packageJson.ts, lockfiles.ts, symjack.ts, paste.ts, mcp.ts,
    │   │   │          actions.ts, extensions.ts, buildHooks.ts, modelSupply.ts, persistence.ts,
    │   │   │          antiForensics.ts, hf.ts, ebpf.ts, aiAssistant.ts, sigstore.ts)
    │   │   ├── skillpact/ (discover.ts, contract.ts, observe.ts, prose.ts, policy.ts, diff.ts, rules.ts)
    │   │   ├── ioc.ts (refang, loaders)  / hash.ts (crypto.subtle)  / semver.ts / findingId.ts
    │   │   └── export.ts (FindingsDoc 生成)
    │   ├── components/
    │   │   ├── layout/ (Header, TabBar, Tab, AllTabsMenu, TabPanel)
    │   │   ├── input/ (DropZone, PasteBox, ScanProgress)
    │   │   ├── findings/ (SummaryCards, SeverityFilter, FindingsToolbar, FindingsTable, FindingRow, CopyPathButton)
    │   │   ├── blast/ (BlastRadiusPanel)
    │   │   ├── skillpact/ (SkillList, SkillPactViewer, EffectMatrix, LevelBadge, PolicyDecisionBadge,
    │   │   │              ProseConflictAlert, DiffAnomalyAlert, RuleResultList, ContractStatus)
    │   │   ├── viewers/ (McpViewer, ActionsViewer, ExtensionViewer, CliOnlyNotice)
    │   │   └── ui/ (SeverityBadge, Badge, Button, Toast, Icon)
    │   ├── tabs/definitions.ts    ← §7.2 の18タブ定義（順序固定）
    │   └── styles/tokens.css      ← §2 トークン（CSS 変数）→ Tailwind theme へマップ
    └── tests/
        ├── unit/ (engine/*.test.ts)       … tests/fixtures/ を流用
        └── e2e/ (offline.spec.ts, skillpact.spec.ts, a11y.spec.ts)
```

---

## 10. アクセシビリティ

- **コントラスト**: 本文 `#ededed`/`#0a0a0a` ≈ 17:1、`--text-subtle #8a8a8a` ≈ 5.9:1、重大度色は暗色背景上で ≥ 4.5:1 となる値を採用（実装時に自動計測で再確認）。
- **色非依存**: 重大度は「ラベル文字＋アイコン形状」併記。差分（宣言外エフェクト）は赤色＋破線枠＋「未宣言」テキスト＋⚠アイコン。
- **タブ**: WAI-ARIA Tabs パターン（`role="tablist"`/`tab`/`tabpanel`、`aria-selected`、`aria-controls`、ローヴィングtabindex、←→/Home/End で移動、Enter/Space で選択＝手動アクティベーション）。件数は `aria-label="TeamPCP、検出 3 件、最大 CRITICAL"`。
- **D&D 代替**: ドロップゾーンは `<button>` を内包し、キーボードでフォルダ選択ダイアログを開ける。
- **ライブリージョン**: スキャン進捗・完了・コピー完了を `aria-live="polite"` で通知。
- **フォーカス可視**: `--accent` 2px リング + 2px オフセット。
- **モーション**: `prefers-reduced-motion` でアニメーション無効。

---

## 11. テスト方針

| 種別 | ツール | 内容 |
|---|---|---|
| 単体 | Vitest | `engine/` の各ルールを `tests/fixtures/`（§12）で検証。SkillPact は §14 受け入れ基準の各行に1テスト以上 |
| 内容非出力 | Vitest | 全 Finding/エクスポート JSON にフィクスチャ内の識別用カナリア文字列が**含まれない**ことを検証 |
| 外部通信ゼロ（動的） | Playwright（Chromium） | `file://` で index.html を開き、`page.on('request')` で `file:`/`data:`/`blob:` 以外のリクエストが 0 件であることを検証。`context.route('**/*')` で外部を全遮断した状態でも全機能が動くこと |
| 外部通信ゼロ（静的） | `verify-no-network.mjs` | 成果物中の `fetch(`/`XMLHttpRequest`/`WebSocket`/`EventSource`/`sendBeacon`/`http://`/`https://`（ライセンスコメント等の許可リスト除く）を検出したらビルド失敗 |
| 実行禁止 | ESLint + 静的検査 | `eval`/`new Function`/`dangerouslySetInnerHTML`/動的 `<script>` 生成の不在 |
| SkillPact 表示 | Playwright | L3 バッジに「安全」「信頼」「Verified」等の語が出ないこと、宣言外エフェクトに `data-divergence="true"` と赤スタイルが付くこと |
| a11y | Playwright + axe-core（候補、バージョンは実装時確認） | 重大な違反 0 件、タブのキーボード操作 |
| 性能 | Playwright | 20,000 ファイル投入でメインスレッド長時間ブロックが無いこと（目標値は【要承認】） |

---

## 12. 想定エッジケース

- フォルダ内に巨大バイナリ（>2 MiB）→ 内容未読・`skipped-size` として INFO、件数をサマリに表示。
- 文字コード不明 → `TextDecoder('utf-8', { fatal: false })`。BiDi/不可視文字判定はデコード後のコードポイントで実施。
- `skill.contract.json` が JSON 不正 / 巨大 / 循環のない深いネスト → パース失敗を HIGH（契約不正）として表示、例外を握り潰さない。
- 同名スキル複数・入れ子 SKILL.md → 最も近い祖先ディレクトリに帰属。
- `webkitRelativePath` が空（個別ファイル投入）→ ファイル名のみで判定し、相対パス依存ルール（SymJack 等）は undetermined。
- 同一ファイルを二重投入 → `relPath` で重複排除。
- クリップボード API 不可（file:// で権限制限される場合あり【不明：ブラウザ依存】）→ フォールバックとしてパスを選択状態にしたテキスト欄を表示。

---

## 13. 要承認事項 / 未確定事項

| # | 区分 | 内容 | 推奨 |
|---|---|---|---|
| 1 | 要承認 | 技術スタック: Vite + React 18 + TS + Tailwind を**ビルド時に単一 index.html へインライン化**（ランタイム外部取得ゼロ）。成果物 index.html をコミット | 推奨（React必須規約と §1 CDN禁止の両立） |
| 2 | 要承認 | CSP: `'unsafe-inline'` 方式か、ビルド時 SHA-256 ハッシュ方式か | ハッシュ方式 |
| 3 | 要承認 | 18タブの表示方式: 1段横スクロール＋「すべてのタブ」メニュー | 推奨（SVG参照） |
| 4 | 要承認 | 内容非表示の例外範囲: MCP `command/args`、Actions `uses:`、拡張パーミッション名の表示（§7.4 の要求） | 許容（値の表示は最小限・長さ上限 120 文字） |
| 5 | 要承認 | UI からのエクスポート時の `scan_mode` 値（§6 の列挙に UI 用が無い）: `"skillpact"`/`"quick"` 流用か、`"ui"` 追加か | 列挙を変えず `scan_mode` は最も近い値 + `errors[]` に「ui: host checks not performed」を追記 |
| 6 | 要承認 | SkillPact 実態推定の正規表現パターン置き場所（CLI と共通化するため `rules/ioc.json` に置くか） | CLI 実装と同じキーを参照（CLI 側の決定に追従） |
| 7 | 要承認 | F-13（CLI の findings.json 読み込みビューア）を初版に含めるか | 含める（実装コスト小） |
| 8 | 要承認 | TOML 最小パーサ自前実装（`.codex/config.toml`）の可否 | 自前（依存追加なし） |
| 9 | 要承認 | 仮想スクロールを自前実装するか `@tanstack/react-virtual` を使うか | 自前（§3.2 で `@tanstack/*` が侵害対象名前空間） |
| 10 | 不明 | 採用ライブラリの最新安定版・ライセンス | 実装時に公式（npm / 各公式サイト）で確認し lockfile 固定 |
| 11 | 不明 | `file://` 下の CSP meta / Clipboard API の各ブラウザ挙動 | 実装時に Chromium/Firefox/Safari で実測 |
| 12 | 不明 | SkillPact v0.8 契約の正式スキーマ（フィールド名: `effects`/`level`/`author`/`operations[].reversible`/署名・L2記録の参照方法） | 一次情報未確認。CLI §49 実装の仮定スキーマに合わせ、パーサは寛容に実装 |
| 13 | 要承認 | 性能目標（投入ファイル数上限・解析時間） | 20,000 ファイル / 30 秒以内を初期目標 |
