English | [日本語](ui-design.ja.md)

# ZES v5.2 Web Scanner UI (`index.html`) detailed design — Step 1

- Target specification: ZES v5.2 Master Specification §1 (absolute principles) / §6 (findings.json) / §7 (index.html) / §5.7 (§49 SkillPact)
- Version: 0.1 (draft for design review)
- Status: **awaiting approval together with Step 2 (SVG designs). Do not start the React implementation before approval.**
- Accompanying designs: `docs/design/ui-overview.svg` / `docs/design/ui-skillpact.svg` / `docs/design/ui-components.svg`

> **Note (0.3.1)**: the screens in this document (including the accompanying SVGs) predate the 0.3.0 rebuild into the "quarantine bench". For the current look and components, see [ui-design-0.3.md](ui-design-0.3.md). The requirements (F-01 to F-13, N-01 to N-08), state management and engine descriptions remain valid.

> **Note (2026-10-23)**: this document is a pre-implementation design draft, kept as a record. The UI was implemented in 0.1.0. The descriptions of §49 SkillPact (tab 2 in 4.2, the SkillPact-related types in 5 and 7, and 8.5) assume the old format (`.skillpact/contract.json`, the `secrets` effect, L2 records, L3 signature files, prose conflicts, `reversible`, CRITICAL for undeclared effects) and differ from the current behavior, which was rebuilt in 0.2.0 to match the SkillPact 0.8 format. For the current behavior, see "§49 SkillPact contracts (experimental)" in the [README](../../README.md) and the [CHANGELOG](../../CHANGELOG.md).

> Notation: [Fact] = stated in the specification, [Design decision] = proposed in this document, [Needs approval] = requires the user's decision, [Unknown] = cannot be confirmed at this time.

---

## 1. Requirements

### 1.1 Functional requirements

| ID | Requirement | Basis |
|---|---|---|
| F-01 | Get the list of files under a folder by drag and drop, and check them | [Fact] §7.1 |
| F-02 | Where D&D is not supported, fall back to folder selection with `<input type="file" webkitdirectory multiple>` | [Fact] §7.1 |
| F-03 | A text paste box that checks C2 domains / IPs, `base64` / `exec(` / `curl`, etc. | [Fact] §7.1, §7.3 |
| F-04 | Embed `rules/ioc.json` inline into index.html at build time (works over `file://`) | [Fact] §7.1 |
| F-05 | All 18 tabs (fixed order of §7.2). The main screen is "overall summary + severity filter" | [Fact] §7.2, §15 |
| F-06 | Severity colors (CRITICAL/HIGH/MEDIUM/LOW/INFO/SAFE), copying of detected paths | [Fact] §7.4 (MEDIUM/LOW/INFO added as a [Design decision] to match the level enumeration of §6) |
| F-07 | Blast Radius panel: shows only the list of target paths, never the contents | [Fact] §7.4, §1 |
| F-08 | MCP configuration viewer (highlights `command` / `args`) | [Fact] §7.4 |
| F-09 | GitHub Actions viewer (colors tag references / SHA pinning in `uses:`) | [Fact] §7.4 |
| F-10 | Browser extension viewer (highlights dangerous permissions / `<all_urls>`) | [Fact] §7.4 |
| F-11 | SkillPact viewer: contract, observed behavior, divergence, policy decision, diff anomaly | [Fact] §7.4, §5.7 |
| F-12 | Export the results as findings.json (§6-compatible) (Blob + `<a download>`; no network use) | [Design decision] interoperability with §6 |
| F-13 | Load and display a `findings.json` output by the ZES CLI (viewer mode) | [Design decision] [Needs approval] |

### 1.2 Non-functional requirements (absolute constraints)

| ID | Constraint | Means |
|---|---|---|
| N-01 | Zero external communication (no CDN; no use of `fetch` / `XMLHttpRequest` / `WebSocket` / `EventSource` / `navigator.sendBeacon`) | Inline everything into a single HTML file + CSP `connect-src 'none'` + a static grep test after the build + request monitoring with Playwright (§11) |
| N-02 | Works over `file://` | No external loading of ES Modules (all scripts inline). Inline scripts with `type="module"` work under file://, but IIFE output can also be selected just in case ([Needs approval] §13) |
| N-03 | Dark UI, background `#0a0a0a` | Design tokens §2 |
| N-04 | File contents are used **only for checks**; no content ever appears in the UI or the export | Restrict the return type of the check functions to "path + rule ID + metadata" (enforced by the types in §6.3). No preview feature |
| N-05 | Zero-Execution: do not evaluate or execute submitted files (no `eval` / `new Function` / `<script>` insertion / passing submitted code to a Worker) | ESLint `no-eval` / `no-new-func` / `no-implied-eval` as errors, and a rule forbidding `dangerouslySetInnerHTML` |
| N-06 | The UI does not freeze even with a large number of files (tens of thousands) | Read files in chunks (split with `requestIdleCallback` / `setTimeout(0)`); virtual scrolling for tables |
| N-07 | Read limit | By default read up to 2 MiB per file (beyond that, shown as INFO "size exceeded, not scanned". Not treated as 0 findings, in the spirit of §10.1 fail-closed) |
| N-08 | Accessibility equivalent to WCAG 2.1 AA | §10 |

### 1.3 Out of scope

- Sending to servers, cloud integration, automatic updates (forbidden by N-01)
- Previewing file contents (forbidden by N-04)
- Remediation operations (the remediation layer's responsibility under the three-layer setup of §0.2; the UI is the detection layer)
- Cryptographic verification of L3 signatures (not done, per §5.7; only "has a signature file" is shown)

---

## 2. Design tokens (consistent with the SVGs)

### 2.1 Colors

| Token | Value | Use |
|---|---|---|
| `--bg` | `#0a0a0a` | Page background |
| `--surface` | `#141414` | Cards, panels |
| `--surface-2` | `#1c1c1c` | Table headers, inputs, hover |
| `--border` | `#2a2a2a` | Dividers, frames |
| `--border-strong` | `#3a3a3a` | Input frame before focus |
| `--text` | `#ededed` | Body text |
| `--text-muted` | `#a3a3a3` | Supplementary text |
| `--text-subtle` | `#8a8a8a` | Captions (contrast about 5.9:1 on `#0a0a0a`) |
| `--accent` | `#38bdf8` | Focus ring, links, active tab underline |
| `--critical` / `--critical-bg` | `#ef4444` / `#2a0f0f` | CRITICAL, red highlight of undeclared effects (divergence) |
| `--high` / `--high-bg` | `#f97316` / `#2a170a` | HIGH |
| `--medium` / `--medium-bg` | `#eab308` / `#262008` | MEDIUM |
| `--low` / `--low-bg` | `#3b82f6` / `#0d1a30` | LOW |
| `--info` / `--info-bg` | `#a3a3a3` / `#1c1c1c` | INFO |
| `--safe` / `--safe-bg` | `#22c55e` / `#0c2214` | SAFE (* not used in the SkillPact tab; §8.5) |
| `--signed` / `--signed-bg` | `#a78bfa` / `#1b1430` | L3 "signed files" badge (deliberately avoids the green safe color) |

- Severity **does not rely on color alone** (WCAG 1.4.1): always show the label text (CRITICAL, etc.) and an icon shape (octagon / triangle / circle / check) alongside.

### 2.2 Typography

- `font-family: system-ui, 'Hiragino Sans', 'Noto Sans JP', sans-serif` (no web fonts loaded = N-01)
- Monospace (paths, commands, hashes): `ui-monospace, SFMono-Regular, Menlo, Consolas, monospace`
- Scale: 24/600 (page title), 18/600 (section), 14/400 (body), 13/400 (table), 12/500 (badges, captions), line height 1.5 (1.7 for Japanese body text)

### 2.3 Spacing and shape

- 8px grid (4/8/12/16/24/32). Page side margins 32px (≥1280px), 16px (<768px)
- Corner radius: cards 12px, buttons / inputs 8px, badges 6px, tabs 0 (underline style)
- Minimum hit area 32×32px (pointer) / 44×44px (touch)

---

## 3. Technology stack policy

[Fact] React is required by the user's conventions. [Fact] Per §1/§7.1: no CDN, works over `file://`, zero external communication.
→ [Design decision] **Bundle all dependencies at build time and inline the JS/CSS/ioc.json into a single `index.html`**. Nothing external is fetched at runtime.

| Layer | Candidate | Notes |
|---|---|---|
| UI | React 18 + TypeScript (strict) | **Confirm the version on the official sources (react.dev / npm) at implementation time and pin it in the lockfile** |
| Build | Vite | Same as above |
| Single-file output | `vite-plugin-singlefile` (candidate) | Same as above. Alternative: Vite's `build.assetsInlineLimit` + our own inlining script |
| Styles | Tailwind CSS (CSS generated at build time, unused classes purged) | Same as above. Choose between v3/v4 at implementation time |
| Virtual scrolling | Our own implementation (fewer dependencies) or `@tanstack/react-virtual` (candidate) | [Needs approval] Our own implementation is recommended to minimize dependencies (* `@tanstack/*` is a namespace targeted by a compromise campaign in §3.2, so adopting it requires strict version / hash pinning) |
| Tests | Vitest (logic), Playwright (E2E, verifying zero external requests) | Same as above |
| Lint | ESLint (`no-eval`, `no-new-func`, `no-implied-eval`, `no-restricted-globals: fetch, XMLHttpRequest, WebSocket, EventSource`, `react/no-danger`) | Same as above |

- Dependencies are installed from `package-lock.json` with **`npm ci --ignore-scripts`** (consistent with the §3.2 campaign countermeasures and the §12 vaccine). The build output is committed as `index.html` at the repository root, so users need no build.
- **Proposed CSP (`<meta http-equiv>`)**:
  `default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; font-src 'none'; connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'`
  - [Unknown] The behavior of a CSP meta under `file://` may differ between browsers, so measure it in Chromium / Firefox / Safari at implementation time.
  - [Design decision] `'unsafe-inline'` is needed because of the single-file output. As an alternative, computing the scripts' SHA-256 at build time and emitting `script-src 'sha256-…'` is recommended ([Needs approval]).

---

## 4. Screen layout

### 4.1 Overall layout (based on 1440×900, `ui-overview.svg`)

```
┌ Header (64px) ─────────────────────────────────────────────────────────┐
│ [shield logo] Zero-Exec Shield v5.2   bundle: ZES-2026-OCT-EMERGENCY-V5.2 │
│                  [● Offline / zero external communication] [Export JSON] [Clear] │
├ TabBar (48px, horizontal scroll + left/right scroll buttons + "All tabs ▾") ──┤
│ Overview | SkillPact | TeamPCP | ChainDrop | PyPI | Solana | Post-ShaiHulud | … │
├ Main ──────────────────────────────────────────────────────────────────┤
│ ┌ Input (left 2/3) ─────────────────┐ ┌ Blast Radius (right 1/3) ──────┐ │
│ │ DropZone  |  PasteBox             │ │ List of secrets present (paths only) │ │
│ └───────────────────────────────────┘ │                                │ │
│ SummaryCards: CRITICAL / HIGH / MEDIUM / SAFE                          │ │
│ SeverityFilter (toggles) + search + module filter                      │ │
│ FindingsTable (virtual scroll): severity | module | campaign | path [copy] | detail │
└────────────────────────────────────────────────────────────────────────┘
```

- **Handling the 18 tabs** [Design decision]: one row with horizontal scrolling (`overflow-x: auto`, scroll snap) + fades at both ends + left/right scroll buttons + an "All tabs ▾" menu at the right end (lists all 18 and jumps to one). Each tab shows a count badge (in the color of its highest severity). Wrapping into two rows was rejected because it moves tab positions and makes them hard to remember.
- <1024px: the Blast Radius panel stacks below the input area. <768px: SummaryCards become 2×2.

### 4.2 Tabs and their contents (fixed order of §7.2)

| # | Tab | Main checks (UI side) | Corresponding CLI modules | Viewer |
|---|---|---|---|---|
| 1 | Overview | Aggregation of all rules, severity summary, Blast Radius | All § | SummaryCards / FindingsTable |
| 2 | SkillPact | Contract JSON parsing, declared vs observed, prose conflicts, policy, L2/L3, diff anomaly | §49 (equivalent to reusing §2/§7/§15/§17) | SkillPactViewer |
| 3 | TeamPCP | `router_init.js` / `tanstack_runner.js` / `vite_setup.mjs`, lockfile matching of `@tanstack/*` etc., C2 IoCs (pasted) | §15, §18, §45 | FindingsTable |
| 4 | ChainDrop | `setup.mjs` / `Math_Symbol.js` / `math_init.js`, `preinstall: "node setup.mjs"`, SHA-256 matching, keyv-family versions | §15 | FindingsTable |
| 5 | PyPI | litellm/lightning/telnyx/py2ops/mistralai/guardrails-ai, `cook.pth` / `sitecustomize.py`, `_runtime/` | §2, §15 | FindingsTable |
| 6 | Solana | `@solana-labs/*` typosquats (lockfile / package.json) | §9, §15 | FindingsTable |
| 7 | Post-ShaiHulud | `iron-worm` / `sckit` / `miasma` / `cargo-install` masquerades (file names) | §25 | FindingsTable |
| 8 | MCP | Dangerous commands in `command` / `args` of `.mcp.json` etc., SymJack decoys, `runOn: folderOpen`, injection words in description | §17, §20, §37 | McpViewer |
| 9 | GitHub Actions | `pull_request_target` + checkout (no ref) + secrets, tag references in `uses:`, `permissions: write-all`, cache keys | §21, §22, §38 | ActionsViewer |
| 10 | Browser extensions | Dangerous permissions / `<all_urls>` / `update_url` in `manifest.json` | §24, §42 | ExtensionViewer |
| 11 | Build hooks | `Command::new` / `include_bytes!` in `build.rs`, `//go:generate curl`, non-safe `build-backend` | §27 | FindingsTable |
| 12 | Model supply chain | `.pkl` / `.pickle` / `.pt` / `.bin`, `weights_only=False`, `trust_remote_code=True`, `--extra-index-url` | §32 | FindingsTable |
| 13 | Persistence | LaunchAgents plists, `ld.so.preload`, systemd user, autostart, `.envrc`, shell hooks (checked within submitted files) | §10, §26, §30, §31, §33 | FindingsTable |
| 14 | Anti-forensics | `HISTFILE=/dev/null` / `HISTSIZE=0` (within submitted files). * noatime / auditd cannot be checked from the browser → "check with the CLI" guidance | §35 | FindingsTable + CliOnlyNotice |
| 15 | HF | `subprocess` / `eval` / `__reduce__` / `pickle.loads` / `dill` in dataset scripts, `transformers.pyz` | §36 | FindingsTable |
| 16 | eBPF/LD_PRELOAD | `LD_PRELOAD` in submitted files, references to `/etc/ld.so.preload`, QLNX / LinkPro / VoidLink indicators. * `bpftool` / `lsmod` are CLI only | §40 | FindingsTable + CliOnlyNotice |
| 17 | AI assistants | Invisible characters, BiDi (U+202A–202E, U+2066–2069) and homoglyphs in `.cursorrules` / `CLAUDE.md` / `.github/copilot-instructions.md`, `git.exe` at the repository root | §7, §41 | FindingsTable |
| 18 | Sigstore/SBOM | Missing `--certificate-identity` / `--certificate-oidc-issuer` in cosign arguments, presence of an SBOM, absence of `provenance` | §28, §43, §48 | FindingsTable |

- Checks that depend on host state (`ps` / `lsof` / `uname` / `docker version` / `bpftool` / `mount`, etc.) cannot be done in the browser. The relevant tabs show a **CliOnlyNotice** ("check this item with `./zes-scan.sh --full`") so that 0 findings is not mistaken for safe (§10.1 fail-closed).

---

## 5. Component breakdown

### 5.1 Tree

```
<App>
 ├─ <ScanProvider>                     … Context + useReducer (§6)
 │   ├─ <Header>
 │   │    ├─ <BrandMark/>
 │   │    ├─ <BundleBadge bundle/>
 │   │    ├─ <OfflineIndicator/>        … always shows "zero external communication"
 │   │    └─ <HeaderActions onExport onClear/>
 │   ├─ <TabBar tabs activeId counts onSelect/>
 │   │    ├─ <TabScrollButton direction/>
 │   │    ├─ <Tab …/> ×18
 │   │    └─ <AllTabsMenu/>
 │   └─ <TabPanel id>                   … role="tabpanel"
 │        ├─ [Overview] <OverviewTab>
 │        │    ├─ <InputArea>
 │        │    │    ├─ <DropZone onFiles/>        … D&D + webkitdirectory fallback
 │        │    │    └─ <PasteBox onSubmit/>
 │        │    ├─ <ScanProgress/>
 │        │    ├─ <SummaryCards counts filter onToggle/>
 │        │    ├─ <FindingsToolbar> (<SeverityFilter/> <SearchInput/> <ModuleSelect/>)
 │        │    ├─ <FindingsTable findings/>   … virtual scroll
 │        │    │    └─ <FindingRow finding/> (<SeverityBadge/> <CopyPathButton/>)
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
 │        ├─ [Browser extensions] <ExtensionViewer manifests/>
 │        └─ [Others] <CampaignTab campaignIds modules cliOnly?/> (reuses FindingsTable)
 └─ <ToastRegion/>                       … aria-live="polite"
```

### 5.2 Main Props types

```ts
type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
type DisplaySeverity = Severity | 'SAFE';

interface TabDef { id: TabId; label: string; modules: string[]; campaigns: string[]; cliOnlyNote?: string }
interface TabBarProps { tabs: TabDef[]; activeId: TabId; counts: Record<TabId, { total: number; max?: Severity }>; onSelect(id: TabId): void }
interface DropZoneProps { disabled?: boolean; onFiles(files: ScannedFileInput[]): void }   // File + webkitRelativePath
interface PasteBoxProps { maxLength: number; onSubmit(text: string): void }                 // default 1,000,000 characters
interface SummaryCardsProps { counts: Record<DisplaySeverity, number>; active: Set<Severity>; onToggle(s: Severity): void }
interface SeverityFilterProps { active: Set<Severity>; onChange(next: Set<Severity>): void }
interface FindingsTableProps { findings: Finding[]; rowHeight?: number; emptyState: 'not-scanned' | 'no-match' | 'clean' }
interface FindingRowProps { finding: Finding; onCopyPath(path: string): void }
interface CopyPathButtonProps { path: string }                                               // navigator.clipboard.writeText (no network)
interface BlastRadiusPanelProps { items: BlastRadiusItem[] }
interface SkillListProps { skills: SkillPactAnalysis[]; selectedId?: string; onSelect(id: string): void }
interface SkillPactViewerProps { analysis: SkillPactAnalysis }
interface EffectMatrixProps { declared: Effect[]; observed: Effect[]; divergence: Effect[] }
interface LevelBadgeProps { level: 'L1' | 'L2' | 'L3' | null; signed: boolean }             // never label as "safe", even for L3
interface PolicyDecisionBadgeProps { decision: 'allow' | 'ask' | 'deny' | null }
interface ProseConflictAlertProps { conflicts: ProseConflict[] }
interface DiffAnomalyAlertProps { anomaly: DiffAnomaly | null }
interface McpViewerProps { configs: McpConfigView[] }
interface ActionsViewerProps { workflows: WorkflowView[] }
interface ExtensionViewerProps { manifests: ExtensionView[] }
interface CampaignTabProps { tab: TabDef; findings: Finding[] }
```

---

## 6. State management

[Design decision] No external state library; `useReducer` + Context (fewer dependencies = lower supply-chain risk). Heavy checks are separated into pure functions in `engine/*` so they can be tested independently of the UI.

### 6.1 State type

```ts
interface ScanState {
  phase: 'idle' | 'reading' | 'analyzing' | 'done' | 'error';
  progress: { processed: number; total: number };
  files: ScannedFile[];                 // metadata only (contents are not kept)
  findings: Finding[];
  skillpact: SkillPactAnalysis[];
  blastRadius: BlastRadiusItem[];
  viewers: { mcp: McpConfigView[]; actions: WorkflowView[]; extensions: ExtensionView[] };
  errors: ScanError[];                  // compatible with §6 errors[]
  ui: {
    activeTab: TabId;
    severityFilter: Set<Severity>;      // default: all selected
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
  | { type: 'SCAN_RESULT'; result: EngineResult }          // findings/skillpact/blastRadius/viewers/errors at once
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

### 6.3 Guaranteeing that contents are not kept

- File contents (`string`) exist **only as local variables** of `engine/analyzeFile()` and never enter the State, a Finding or the export. `Finding.detail` is generated only from fixed template strings on the rule-definition side (for example "the contract declares only read; exec was observed"), and never concatenates strings taken from files.
- Exceptions: file **paths** (`webkitRelativePath`), and key names and `command` values of JSON configurations (MCP viewer), `uses:` references (Actions viewer) and permission names (extension viewer). §7.4 requires these to be displayed, so they are allowed as "highlighted display of configuration values". [Needs approval] §13-4.

---

## 7. Data structures (TypeScript)

```ts
// ---- IoC DB (rules/ioc.json inlined at build time, §3) ----
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

// ---- Input files (metadata only) ----
interface ScannedFile {
  relPath: string;            // webkitRelativePath or the D&D fullPath
  name: string; size: number; lastModified: number;
  isZeroByte: boolean;        // for the SymJack decoy check (§7.3)
  readState: 'read' | 'skipped-size' | 'skipped-binary' | 'error';
}

// ---- findings.json (§6-compatible; UI output uses relative paths for path) ----
interface Finding {
  id: string;                 // "sha256:<hex>" = SHA-256(module|campaign|path|ruleId) (crypto.subtle.digest, deterministic)
  level: Severity;
  module: string;             // "§49", etc.
  campaign: string | null;
  path: string;
  detail: string;             // from a fixed template (§6.3)
  evidence_hash?: string;     // "sha256:<hex>" (hash of the target file's contents; the contents themselves are never output)
  skillpact?: SkillPactFindingField;
  source: 'ui' | 'cli-import';     // UI internal; excluded from the export
  ruleId: string;                  // UI internal; excluded from the export
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
  scan_mode: 'quick'|'standard'|'full'|'worm'|'skillpact';   // for the UI: [Needs approval] §13-5
  status: 'ok'|'partial'|'error';
  findings: Omit<Finding, 'source'|'ruleId'>[];
  errors: ScanError[];
}
interface ScanError { module: string; reason: string }

// ---- SkillPact analysis result (for the viewer) ----
interface SkillPactAnalysis {
  skillId: string;                    // relative path of the directory containing SKILL.md
  skillMdPath: string;
  contract: { found: boolean; path: string | null; parseError: boolean; schemaVersion: string | null; supported: boolean };
  author: string | null; version: string | null;
  level: 'L1'|'L2'|'L3'|null;
  signature: { fileFound: boolean; verifyCommandDeclared: boolean };   // not verified
  l2: { recordFound: boolean; recordPath: string | null; hashDeclared: boolean; hashMatches: boolean | null };
  declared: Effect[]; observed: Effect[];
  observedEvidence: { effect: Effect; path: string; ruleId: string }[];   // paths and rule IDs only
  divergence: Effect[];               // observed − declared (exec/network/secrets are CRITICAL candidates)
  destructiveHits: { marker: string; path: string }[];
  persistenceHits: { marker: string; path: string }[];
  policy: { file: string | null; decision: 'allow'|'ask'|'deny'|null; neverAutoAllowViolations: string[] };
  irreversibleAllowed: string[];      // IDs of operations with reversible:false and allow
  proseConflicts: ProseConflict[];
  diffAnomaly: DiffAnomaly | null;
  results: RuleResult[];              // results for the 12 rows of the §5.7 detection rule table
}
interface ProseConflict { claim: 'read-only'|'no-network'|'no-modify'|'no-exec'; phraseId: string; sourcePath: string; contradictedBy: Effect[] }
interface DiffAnomaly { previousVersion: string; addedEffects: Effect[]; addedNetworkTargets: number; secretsScopeExpanded: boolean; score: number; threshold: number }
interface RuleResult { ruleNo: number; title: string; level: Severity; status: 'hit'|'clear'|'n/a'|'undetermined' }

interface BlastRadiusItem { path: string; kind: 'ssh'|'aws'|'gcloud'|'claude'|'cursor'|'gh'|'docker'|'npmrc'|'pypirc'|'kube'|'vault'|'git-credentials'|'netrc'|'heroku'|'terraform'|'op'|'env'|'private-key'; size: number }
```

---

## 8. Check logic (client side, §7.3)

All are pure functions under `engine/`. The input is a set of `File`s or a pasted string; the output is an `EngineResult` (containing no contents).

### 8.1 File name match
- Compare file names (basename) exactly against `ioc.malicious_files` / `worm_iocs.*.files` / `post_shaihulud.binaries` → CRITICAL.
- For the ChainDrop family, compute the SHA-256 of the file contents with `crypto.subtle.digest` and match it against `worm_iocs.chaindrop.hashes.sha256` (CRITICAL on a match, HIGH on a name match only). [Design decision]

### 8.2 `preinstall` / `postinstall` in `package.json`
- `JSON.parse` only. `scripts.preinstall === "node setup.mjs"` → CRITICAL (ChainDrop). Any other install hook present → HIGH.
- Match `dependencies` etc. against `ioc.packages` (eco=npm). The same for `package-lock.json` (version comparison is our own simple semver comparison).

### 8.3 SymJack
- `webkitRelativePath` matches a decoy name pattern (`vid-` prefix, `logo.` / `readme.` prefix, under `docs/`) **and** `size === 0` → "needs manual check (HIGH)". [Fact] The browser cannot get the target of a symbolic link, so no definite verdict is made (guides the user to check with `readlink -f` in CLI §17).

### 8.4 Pasted text
- C2 domains / IPs: restore the `[.]` defanged notation in `ioc` for matching (in memory only), and match the pasted string by case-insensitive substring → CRITICAL.
- `base64` (a Base64 run of length ≥ 40 or `base64 -d`), `exec(`, `curl`, `wget`, `| bash`, `| sh` → HIGH.
- Only the rule ID and hit count are displayed (the pasted content is not displayed again).

### 8.5 SkillPact (reproducing §5.7 in the UI)
1. **Identify skills**: a directory containing `SKILL.md` = 1 skill.
2. **Find contracts**: `contract_filenames` (`skill.contract.json`, `.skillpact/contract.json`). **`JSON.parse` only**. A parse failure is treated as an "invalid contract", not as 0 findings.
3. **Schema**: `schema_version` other than `schema_versions` ("0.8") → MEDIUM.
4. **Estimate observed effects** (static, regular expressions): extract traces of exec/network/write/secrets/spend from code fences in SKILL.md and scripts (`.sh/.py/.js/.ts/.mjs/.ps1`, etc.). The pattern definitions refer to `rules/ioc.json`, shared with CLI §49 ([Needs approval] §13-6: where the patterns live).
5. **Comparison**: `divergence = observed − declared`. Undeclared exec/network/secrets → CRITICAL (red highlight).
6. **L2**: `effects` has exec/network/secrets and there is no L2 record file → HIGH. Only the existence and hash of the record are checked (nothing is re-run).
7. **L3**: show only whether a signature file exists and whether a verification command is declared. **The badge text is "L3 signed files". Never use words such as "safe", "trusted" or "Verified"**. Do not use the safe color (green) either (`--signed` purple). Tooltip: "L3 only indicates that the files are signed; it does not mean they are safe or that the author is trustworthy (trust_model.l3_does_not_mean)".
8. **Policy**: JSON-parse `policy_files` and show `allow/ask/deny`. Not respecting `never_auto_allow_any` → HIGH.
9. **Destructive / persistence markers**: `destructive_markers` detected ∧ decision `allow` → HIGH. `persistence_markers` detected ∧ no `persist` / `write` in the contract → CRITICAL.
10. **Irreversible operations**: `reversible: false` ∧ `allow` → CRITICAL.
11. **Prose conflicts**: extract claims such as "read-only" (読み取りのみ / 参照だけ), "no network" (外部通信なし), "does not modify" (ファイル変更なし) and "does not execute" (実行しない) from the text outside code fences in SKILL.md / README; a conflict with the contract's effects → HIGH.
12. **Diff anomaly**: compare **only when the previous version's contract by the same `author` is submitted at the same time** (the browser cannot fetch from a registry = N-01). Newly added exec/network, more network destinations, expanded secrets scope → HIGH (warns even for L3). If there is no previous version, state "undetermined (nothing to compare)" explicitly.
- **The SkillPact tab does not use the SAFE display**. Even when no rule matches, it says "nothing detected (within the scope of static analysis)" and does not assert safety.

### 8.6 MCP / Actions / extension viewers
- MCP: parse `.mcp.json` etc. as JSON/TOML (TOML with our own minimal parser, [Needs approval]), display `mcpServers.*.command/args`, and highlight tokens matching `suspicious_commands` in red.
- Actions: YAML is **not parsed with a full parser**; `uses:` / `on: pull_request_target` / `permissions:` are extracted with per-line regular expressions (fewer dependencies; false positives are settled by the CLI). Tag references such as `@v*` = HIGH color, 40-digit SHA = SAFE color.
- Extensions: display `permissions` / `host_permissions` / `update_url` from `manifest.json` and highlight dangerous values.

---

## 9. Directory layout

```text
zero-exec-shield/
├── index.html                 ← build output (single file, committed)
├── rules/ioc.json             ← single source of truth. Imported from ui/ at build time and inlined
└── ui/
    ├── package.json / package-lock.json
    ├── vite.config.ts         ← single-file output, outDir: '..', emptyOutDir: false, output name index.html
    ├── tailwind.config.ts / postcss.config.js / tsconfig.json / eslint.config.js
    ├── index.html             ← template (includes the CSP meta)
    ├── scripts/
    │   ├── inject-csp-hash.mjs    ← after the build, puts the SHA-256 of script/style into the CSP ([Needs approval])
    │   └── verify-no-network.mjs  ← statically checks the output for fetch/XMLHttpRequest/WebSocket/http(s):// references
    ├── src/
    │   ├── main.tsx / App.tsx
    │   ├── state/ (ScanContext.tsx, reducer.ts, types.ts)
    │   ├── engine/                ← pure functions (tested with Vitest)
    │   │   ├── index.ts (analyzeFiles, analyzePaste)
    │   │   ├── rules/ (filenames.ts, packageJson.ts, lockfiles.ts, symjack.ts, paste.ts, mcp.ts,
    │   │   │          actions.ts, extensions.ts, buildHooks.ts, modelSupply.ts, persistence.ts,
    │   │   │          antiForensics.ts, hf.ts, ebpf.ts, aiAssistant.ts, sigstore.ts)
    │   │   ├── skillpact/ (discover.ts, contract.ts, observe.ts, prose.ts, policy.ts, diff.ts, rules.ts)
    │   │   ├── ioc.ts (refang, loaders)  / hash.ts (crypto.subtle)  / semver.ts / findingId.ts
    │   │   └── export.ts (builds FindingsDoc)
    │   ├── components/
    │   │   ├── layout/ (Header, TabBar, Tab, AllTabsMenu, TabPanel)
    │   │   ├── input/ (DropZone, PasteBox, ScanProgress)
    │   │   ├── findings/ (SummaryCards, SeverityFilter, FindingsToolbar, FindingsTable, FindingRow, CopyPathButton)
    │   │   ├── blast/ (BlastRadiusPanel)
    │   │   ├── skillpact/ (SkillList, SkillPactViewer, EffectMatrix, LevelBadge, PolicyDecisionBadge,
    │   │   │              ProseConflictAlert, DiffAnomalyAlert, RuleResultList, ContractStatus)
    │   │   ├── viewers/ (McpViewer, ActionsViewer, ExtensionViewer, CliOnlyNotice)
    │   │   └── ui/ (SeverityBadge, Badge, Button, Toast, Icon)
    │   ├── tabs/definitions.ts    ← definitions of the 18 tabs of §7.2 (fixed order)
    │   └── styles/tokens.css      ← §2 tokens (CSS variables) → mapped to the Tailwind theme
    └── tests/
        ├── unit/ (engine/*.test.ts)       … reuses tests/fixtures/
        └── e2e/ (offline.spec.ts, skillpact.spec.ts, a11y.spec.ts)
```

---

## 10. Accessibility

- **Contrast**: body text `#ededed` / `#0a0a0a` ≈ 17:1, `--text-subtle #8a8a8a` ≈ 5.9:1; severity colors use values that reach ≥ 4.5:1 on the dark background (re-checked with automatic measurement at implementation time).
- **Not relying on color**: severity is shown as "label text + icon shape". Divergence (undeclared effects) is shown in red + a dashed frame + the text "undeclared" + a ⚠ icon.
- **Tabs**: the WAI-ARIA Tabs pattern (`role="tablist"` / `tab` / `tabpanel`, `aria-selected`, `aria-controls`, roving tabindex, ←→/Home/End to move, Enter/Space to select = manual activation). Counts go in `aria-label="TeamPCP, 3 findings, highest CRITICAL"`.
- **D&D alternative**: the drop zone contains a `<button>`, so the folder selection dialog can be opened from the keyboard.
- **Live region**: scan progress, completion and copy completion are announced with `aria-live="polite"`.
- **Visible focus**: `--accent` 2px ring + 2px offset.
- **Motion**: animations are disabled under `prefers-reduced-motion`.

---

## 11. Test policy

| Kind | Tool | Content |
|---|---|---|
| Unit | Vitest | Verify each rule in `engine/` with `tests/fixtures/` (§12). For SkillPact, at least one test per row of the §14 acceptance criteria |
| No content output | Vitest | Verify that no Finding / export JSON **contains** the identifying canary strings in the fixtures |
| Zero external communication (dynamic) | Playwright (Chromium) | Open index.html over `file://` and verify with `page.on('request')` that there are 0 requests other than `file:` / `data:` / `blob:`. All features must work even with everything external blocked by `context.route('**/*')` |
| Zero external communication (static) | `verify-no-network.mjs` | Fail the build if the output contains `fetch(` / `XMLHttpRequest` / `WebSocket` / `EventSource` / `sendBeacon` / `http://` / `https://` (excluding an allowlist such as license comments) |
| No execution | ESLint + static checks | Absence of `eval` / `new Function` / `dangerouslySetInnerHTML` / dynamic `<script>` creation |
| SkillPact display | Playwright | No words such as "safe", "trusted" or "Verified" on the L3 badge; undeclared effects get `data-divergence="true"` and the red style |
| a11y | Playwright + axe-core (candidate; confirm the version at implementation time) | 0 serious violations, keyboard operation of the tabs |
| Performance | Playwright | No long main-thread blocking with 20,000 files submitted (target values: [Needs approval]) |

---

## 12. Expected edge cases

- A huge binary (>2 MiB) in the folder → contents not read; INFO as `skipped-size`, with the count shown in the summary.
- Unknown character encoding → `TextDecoder('utf-8', { fatal: false })`. BiDi / invisible-character checks run on the code points after decoding.
- `skill.contract.json` is invalid JSON / huge / deeply nested without cycles → show the parse failure as HIGH (invalid contract); do not swallow the exception.
- Several skills with the same name, nested SKILL.md → belongs to the nearest ancestor directory.
- `webkitRelativePath` is empty (individual files submitted) → check by file name only; rules that depend on relative paths (SymJack, etc.) are undetermined.
- The same file submitted twice → deduplicated by `relPath`.
- Clipboard API unavailable (may be restricted under file://, [Unknown: browser-dependent]) → as a fallback, show a text field with the path selected.

---

## 13. Items needing approval / open items

| # | Category | Content | Recommendation |
|---|---|---|---|
| 1 | Needs approval | Technology stack: Vite + React 18 + TS + Tailwind **inlined into a single index.html at build time** (zero runtime external fetches). Commit the output index.html | Recommended (satisfies both the React requirement and the §1 CDN ban) |
| 2 | Needs approval | CSP: the `'unsafe-inline'` approach or the build-time SHA-256 hash approach | Hash approach |
| 3 | Needs approval | Display of the 18 tabs: one row with horizontal scrolling + an "All tabs" menu | Recommended (see the SVG) |
| 4 | Needs approval | Scope of exceptions to hiding contents: displaying MCP `command/args`, Actions `uses:`, and extension permission names (required by §7.4) | Allow (show values minimally, up to 120 characters) |
| 5 | Needs approval | The `scan_mode` value when exporting from the UI (the §6 enumeration has no value for the UI): reuse `"skillpact"` / `"quick"`, or add `"ui"` | Do not change the enumeration; use the closest `scan_mode` value + add "ui: host checks not performed" to `errors[]` |
| 6 | Needs approval | Where the regular-expression patterns for estimating SkillPact observed behavior live (put them in `rules/ioc.json` to share with the CLI?) | Refer to the same keys as the CLI implementation (follow the CLI's decision) |
| 7 | Needs approval | Whether to include F-13 (viewer that loads the CLI's findings.json) in the first version | Include (low implementation cost) |
| 8 | Needs approval | Whether to write our own minimal TOML parser (`.codex/config.toml`) | Our own (no added dependency) |
| 9 | Needs approval | Implement virtual scrolling ourselves or use `@tanstack/react-virtual` | Our own (`@tanstack/*` is a compromised namespace in §3.2) |
| 10 | Unknown | Latest stable versions and licenses of the adopted libraries | Confirm on the official sources (npm / each official site) at implementation time and pin in the lockfile |
| 11 | Unknown | Behavior of a CSP meta / the Clipboard API under `file://` in each browser | Measure in Chromium/Firefox/Safari at implementation time |
| 12 | Unknown | The official schema of SkillPact v0.8 contracts (field names: `effects` / `level` / `author` / `operations[].reversible` / how signatures and L2 records are referenced) | Primary source not confirmed. Follow the assumed schema of the CLI §49 implementation and implement the parser leniently |
| 13 | Needs approval | Performance targets (maximum number of submitted files, analysis time) | Initial target: 20,000 files within 30 seconds |
