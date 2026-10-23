English | [日本語](ui-design-0.3.ja.md)

# zero-exec shield Web UI: shadcn/ui restyling detailed design v2 (the "quarantine bench" proposal)

- Target: [`ui/`](../../ui/) (Vite + React + TypeScript + Tailwind CSS v4. The output is a single-file `index.html`)
- Version: 0.2 (2026-10-23). Rebuilds the visual part of v0.1 (not included in the repository). Implemented in ZES 0.3.0
- Status: the 9 items in §16 are approved by the owner (§16). The new condition is "stop making it look AI-generated" (AIっぽいデザインはやめて). **This document and the mockups are design only; no code in any repository was changed.**
- Supporting material (in the design working directory, **not included in this repository**. The current reference for the look is the implementation ([`ui/src`](../../ui/src/)) and the e2e tests ([`ui/tests/e2e`](../../ui/tests/e2e/)). The list below is kept as a record):
  - Mockups: `overview-dark.svg` / `overview-light.svg` / `skillpact-dark.svg` / `skillpact-light.svg` / `mobile-overview-dark.svg` / `mobile-overview-light.svg` / `mobile-menu-dark.svg` / `tokens.svg`. PNGs in `mock-png/`
  - Overview images: `sheet.png` (the v2 mockups), `current.png` (screenshot of the current state; originals in `current/`)
  - Palette and contrast results: `palette.json` (output by `scripts/palette.py`, which stops with exit code 1 if any combination falls below the threshold)
  - Generator scripts: `scripts/` (`lib.py`, `mockups.py`, `skillpact.py`, `tokens.py`, `render.mjs`, `sheet.py`. The screenshot and CSP measurement scripts `shots.mjs`, `csp-test.mjs`, `attr.mjs`, `ref18.mjs` are kept as they were in v0.1)
- Everything from the old design document [ui-design.md](ui-design.md) carries over: the requirements (F-01 to F-13, N-01 to N-08), state management and the engine. Only the look and the base for implementing components change.

> Notation: [Fact] = confirmed in official documentation or by measurement, [Design decision] = a decision in this document, [Unverified] = not yet confirmed.

### Changes from v0.1

| Area | v0.1 | v0.2 |
|---|---|---|
| Direction | A look close to the shadcn defaults. Navy ground with the brand blue as the primary color | "Quarantine bench": decided from the props of the work of reading without executing (bench, sheet, sample record, stamp) (§5) |
| Color | Navy `#060a13` and one bright blue | Ground and components are achromatic (ink and pencil). **The only colors are for detections (severity) and the purple L3 stamp** (§5.2) |
| Surfaces | Everything is a card (radius 12, same border and shadow) | Only 3 sheets (sample record, findings list, SkillPact report). Everything else sits directly on the bench (§7) |
| Summary | 4 cards with large numbers, and a row of filter chips with the same content | Merged into one "tally" that is itself the severity filter (§10.3) |
| Input area | A card with a large drop area and a paste box | After a scan it becomes the "sample record". The paste check moves to the side notes on the right (§10.3) |
| Wording | The existing wording | Stopped chaining side information with middle dots; uses label-value pairs or commas instead. The list of changes is in §10.7 |
| Technical research | — | **No change** (CSP, manual mode of Radix Tabs, bundle estimates, forwardRef and React 19, not bundling web fonts) |

---

## 1. Goals and non-goals

### 1.1 Goals
1. Raise the quality and consistency of the look. Consolidate colors hard-coded per screen (`bg-[#0b1f2a]`, `hover:bg-[#242424]`, etc.) into semantic tokens and shared components.
2. **Do not use the default look**. Decide the look from the subject of this tool (reading and judging code without executing it) (§5). shadcn/ui and Radix are used as the base for components, but the default shadcn look is not kept.
3. Use the brand correctly: the Fresnel-style shield icon and the lowercase wordmark "zero-exec shield".
4. Make it usable on mobile (375px, minimum 320px). In particular, fix the problem that **the path of a finding is not visible on a phone**.
5. Make the 18 tabs easier to find (tab search with cmdk).
6. Add a light theme. The default is dark (approved, §16-1).
7. Do not loosen any constraint (§2). The CSP is **not changed** (§4.2).

### 1.2 Non-goals
- Changes to the check engine ([`ui/src/engine`](../../ui/src/engine/)), the state ([`ui/src/state`](../../ui/src/state/)), the tab definitions ([`ui/src/tabs/definitions.ts`](../../ui/src/tabs/definitions.ts)) and file reading ([`fileReader.ts`](../../ui/src/fileReader.ts)).
- Adding or removing features. The exceptions are "tab search", "theme switch" and "mobile detail sheet" (all approved).
- Anything that does not fit Vite's single-file setup, such as Next.js, RSC and `next-themes`.

---

## 2. Constraints and compliance check

| ID | Constraint | Current state | Handling in this design |
|---|---|---|---|
| C-01 | Build to a single file (`inline-build.mjs` embeds one JS and one CSS) | Met | Unchanged. All dependencies are pulled in at build time |
| C-02 | Zero external communication (no CDN, web fonts or `fetch`) | Confirmed by `verify-no-network.mjs` and E2E | Web fonts are not bundled (§6). Icons are lucide-react paths pulled in at build time |
| C-03 | Hash-based CSP. Only one `style-src 'sha256-<CSS>'`, no `'unsafe-inline'` | Met | **The CSP is not changed**. Libraries that inject `<style>` at runtime are not used or are replaced (§4.2) |
| C-04 | Works over `file://` (offline) | Met | Radix's Portal only renders into `document.body` and uses no URL (§4.2) |
| C-05 | WCAG 2.1 AA (text 4.5:1, UI components 3:1, keyboard operation, visible focus) | Mostly met | All token combinations are computed with `palette.py` (§5.2, §5.3). Focus is a 2px ink outline + 2px gap. It uses no hue, so it is 9.4:1 or more on every ground |
| C-06 | Japanese UI (CJK typesetting) | system-ui | §6 |
| C-07 | 18 tabs (the order of §7.2 is fixed) | Tab bar + "All tabs" menu | Radix Tabs (manual) + tab search with Command (§10.2) |
| C-08 | Virtual scrolling of the findings list | Our own (fixed row height 50px) | Still our own. Row height fixed at 60px (desktop) and 96px (<640px) |
| C-09 | Severity colors are distinguishable from each other, and text meets the contrast threshold | Partly short (§3) | 7 hues: red, orange, yellow, blue, gray, green, purple. 4.98:1 or more in both themes on every ground: tint, bench, sheet, raised, selected row (§5.3) |
| C-10 | **Do not show L3 in a color that suggests "safe"** | Purple. Met | Only the purple stamp (double frame). No green, teal or the primary color (ink). No check-shaped icons either (§5.3) |
| C-11 | Does not break down to 320px (no horizontal scroll) | Confirmed by E2E | Designed per breakpoint (§8) |
| C-12 | Minimize dependencies (supply-chain risk; old design document §3) | Runtime dependencies are only react and react-dom | They increase. Breakdown in §4.3. Keep the lockfile and `--ignore-scripts` |
| C-13 | The brand icon colors (navy squircle, teal → blue shield) can be used as they are | — | The icon has its own navy ground, so its shape holds on either bench (dark #252220, light #e8e6e3). The wordmark colors (#F5F5F7 on dark grounds, #1D1D1F on light grounds) are 14.52:1 and 13.51:1 against the bench. **Teal and blue are not used anywhere in the UI**, so the icon does not clash with the meaning colors |
| C-14 | Respect `prefers-reduced-motion` | Met | Nothing moves by itself. Sheets and popovers enter and leave in 0ms under reduce (§7) |

---

## 3. Review of the current state and v0.1

### 3.1 Good points of the current state (kept)
- Information structure: input → status → summary → filter → findings list. Blast Radius, CLI guidance and not-scanned items on the right.
- Severity is not conveyed by color alone (label and icon shape are shown together).
- L3 is purple and labeled "signed files", and the SkillPact tab shows no SAFE.
- Wording that does not suggest "0 findings = safe" (CLI guidance, the not-scanned section).
- WAI-ARIA operation of the tabs (manual activation: arrow keys to move, Enter to select) and `aria-label`s with counts.

### 3.2 Weak points of the current state (carried over from v0.1; the fixes are v0.2's)
The working tree's `index.html` was opened over `file://` in Chromium (`/opt/pw-browsers`), fixtures were submitted, and screenshots were taken (`scripts/shots.mjs` → `current/`). [Fact] Specifying light gives the same display (fixed to dark).

| # | Screen | Problem | v0.2 fix |
|---|---|---|---|
| W-1 | Mobile, Overview | The findings list stays a horizontally scrolling table, and at 375px the path column is off screen | Below 640px, one 96px row per finding. The path always appears on the second line (§10.4) |
| W-2 | Mobile, header | Logo, bundle ID, status and 2 buttons wrap into 3 rows | One 52px row. Actions go into a "…" menu (§10.1) |
| W-3 | Mobile, tabs | About one tab is visible. The menu is a narrow dropdown | 44px tab row + search button → bottom sheet (`mobile-menu-dark.svg`) |
| W-4 | Everywhere | Japanese headings wrap in the middle of words | `word-break: auto-phrase`, shorter wording (§6, §10.7) |
| W-5 | Header | "Offline, zero external communication" is the same green as SAFE and can be read as the result being safe | An achromatic tag (wifi-off) (approved, §16-9) |
| W-6 | Overview | All 4 summary cards have severity-colored borders. Pressed / not pressed differs only in opacity. And the filter chips right below duplicate the same operation | Tally and filter merged into one. Pressed = left bar + check + color; not pressed = pencil color + empty box (§10.3) |
| W-7 | Everywhere | Hard-coded colors outside the tokens make a light theme impossible | Unified into tokens (§5) |
| W-8 | Findings list | The column header row is outside `role="table"` | Put the header row in a `rowgroup` inside the table |
| W-9 | Paste box | "Check" (判定する) is primary, as strong as folder selection even when empty | Make it outline, enabled only when there is input |
| W-10 | Blast Radius | "Copy path list" wraps onto 2 lines at 375px | Icon + short label, `whitespace-nowrap` |
| W-11 | Everywhere | Many 11px notes | Japanese text at least 12px. Supplementary text (pencil) at 5.46:1 or more (§5.2) |
| W-12 | Brand | The shield is a lucide-style line drawing, and the name is "Zero-Exec Shield" | Use the brand logo SVG and write the name in lowercase |

### 3.3 Audit for the AI-generated look (checked against the frontend-design skill's list)

The current UI (`current.png`) and the v0.1 proposal (`sheet.png` (v0.1, not included in the repository)) were checked against the skill's list of "traits that generated designs tend to share".

| # | Trait (the skill's category) | Current | v0.1 | Handling in v0.2 |
|---|---|---|---|---|
| A-1 | Dark ground with one bright accent (2) | Teal primary button on black `#0a0a0a` | Bright blue primary on navy `#060a13`. Navy + blue itself | The bench is a lighter graphite (L 0.255). The primary button is ink. **Hue is used only for detections and stamps** |
| A-2 | Tinted black instead of black (5) | `#0a0a0a`, `#0b1f2a` | `#060a13` | The ground is not pushed toward black. The dark bench is `#252220` (bright enough as a reading ground), the sheet `#2e2c29` |
| A-3 | Rows of cards with the same radius, border and shadow (4) | Input, 4 summary cards, the list and the 3 on the right are all `rounded-xl` cards | Same. Radius 12 on all cards, `shadow-xs` on all cards in light | Only 3 sheets: sample record, findings list, report. The right column sits directly on the bench, separated by rules. Radius by role (stamp 2, tag 3, sheet 4, component 6, bottom sheet 14). Shadows only on floating things (popovers, sheets, toasts) |
| A-4 | Decorative gradients (4) | None | Fades at the ends of the tab row | None. On desktop, show the tabs that fit and send the rest to search. On mobile, the clipped text is the scroll cue |
| A-5 | Big number + small label + color (the hero default) | 4 summary cards (30px numbers) | Same (32px) | Merged into one tally (21px). Numbers in ink; color only on the word and the icon |
| A-6 | Uppercase English labels (5) | Small headings such as CRITICAL, `SAFE` | Same. Uppercase with +0.2px letter spacing | Uppercase English **only for severity values (enumeration values shared with the CLI and findings.json)**. No letter spacing. No uppercase as small headings. `SAFE` is no longer used as a heading either (§10.7) |
| A-7 | Small label above a heading (5) | "CRITICAL" above the number on the summary cards | Same. "Severity" (重大度) on the toolbar | Removed. Labels appear **only on the sample record** (because it really is a form with fields) |
| A-8 | Side information chained with middle dots `A · B · C` (5) | "Scan complete · 4 files · 0.0 s" (スキャン完了 ・ 4 ファイル ・ 0.0 秒), "author · version", "12 rules · matched 3 · …" | Same. Also "§15 · chaindrop-keyv" on mobile | Label-value pairs (sample record, SkillPact facts) or comma-separated sentences. Japanese word lists such as 「表示・保存・送信」 ("display, save, send") use the middle dot correctly in Japanese and are kept |
| A-9 | Monospace for small data labels (5) | bundle heading, module | Version, bundle Badge, module `§15`, rule number `01` | Monospace **only for strings you can type into a terminal** (paths, commands, bundle ID, effect names). Version, `§15`, rule numbers and counts use tabular figures in the same typeface as the text |
| A-10 | Trailing "→" on buttons and links (5) | "→ see the right panel" (→ 右パネル参照) | — | Removed. The arrow stays only in the "steps" of Blast Radius (which really have an order) |
| A-11 | Meaningless sequence numbers `01 / 02` (design principles) | Rule numbers zero-padded in monospace | Same | Rule numbers are spec IDs, so they stay, but without zero padding, as plain numbers |
| A-12 | "WORD — fragment" labels (5) | None | Mockup headings, etc. | Not used in UI wording |
| A-13 | Uniform entrance animations and hover effects (design principles) | None | `zoom-in-95` on all popovers and tooltips | Zoom removed. Only responses to user actions move (the sheet comes up from below, popovers appear in 120ms) |
| A-14 | The default shadcn look (this request's condition) | — | new-york Button, outline Badge pills, Card nearly as default | No Badge pills (tags are squares with radius 3). Card only for the 3 sheets. Button limited to 3 variants: ink, outline, ghost |
| A-15 | Newspaper-style rules + zero radius + dense columns (3) | — | — | **A caution for v0.2**. Since rules are used a lot, they are used only to separate records (table rows, form fields, side-note sections). Radii are kept, and at most 2 columns |
| A-16 | Off-white + Mincho headings + terracotta (1) | — | — | **A caution for the light theme**. The bench is a gray with chroma 0.004 (`#e8e6e3`), not off-white. No Mincho, no terracotta |

---

## 4. Technical research (confirmed facts)

> The v0.1 research is carried over as is (no change). `lab/`, `lab19/` and `lab/out/` in the text are under v0.1's folder `../design-shadcn/`.

### 4.1 State of shadcn/ui (official documentation as of 2026-10-23)

| Item | Content | Source |
|---|---|---|
| Tailwind v4 and React 19 | "Tailwind v4 and React 19. Ready for you to try out". Existing Tailwind v3 / React 18 apps keep working. "Newly added components stay on v3 and React 18 until you upgrade" | https://ui.shadcn.com/docs/tailwind-v4 |
| forwardRef removed | "We've removed the forwardRefs". Every primitive gets a `data-slot` attribute | Same as above |
| tw-animate-css | Replace `tailwindcss-animate` with `@import "tw-animate-css";` | Same as above |
| OKLCH | Colors changed from HSL to OKLCH. `:root` and `.dark` move outside `@layer base` and are mapped to `--color-*` with `@theme inline` | Same as above, https://ui.shadcn.com/docs/theming |
| Token names | background, foreground, card(-foreground), popover(-foreground), primary(-foreground), secondary(-foreground), muted(-foreground), accent(-foreground), destructive, border, input, ring, chart-1 to 5, sidebar-*. `--radius: 0.625rem` | https://ui.shadcn.com/docs/theming |
| Manual installation | Install `shadcn class-variance-authority cn lucide-react tw-animate-css`; the top of the CSS is `@import "tailwindcss"; @import "tw-animate-css"; @import "shadcn/tailwind.css"; @custom-variant dark (&:is(.dark *));` | https://ui.shadcn.com/docs/installation/manual |
| Vite | `@/*` path alias, `resolve.alias`, `shadcn init` | https://ui.shadcn.com/docs/installation/vite |
| Dark mode (Vite) | `ThemeProvider` adds a `light` or `dark` class to `document.documentElement`. Stored in localStorage as `vite-ui-theme`. For system, it follows `matchMedia('(prefers-color-scheme: dark)')` | https://ui.shadcn.com/docs/dark-mode/vite |
| components.json | `style` is `"new-york"` (default is retired). `tailwind.config` is left empty in v4. `baseColor` is neutral / stone / zinc / mauve / olive / mist / taupe | https://ui.shadcn.com/docs/components-json |
| Choice of primitives | Component pages have tabs for Base UI / React Aria / Radix UI (for example Tabs, which has `variant="line"` and `orientation="vertical"`) | https://ui.shadcn.com/docs/components/tabs |
| Native Select | Just wraps the native `<select>`; no dependency on Radix | https://ui.shadcn.com/docs/components/native-select |
| Command | Uses cmdk. Has `CommandDialog` | https://ui.shadcn.com/docs/components/command |
| Toast and Sonner | The tailwind-v4 page says "toast is deprecated in favor of sonner". Meanwhile, the current `/docs/components/sonner` shows a "Toast" page (Base UI / React Aria / Radix versions) and does not mention Sonner. **The documentation pages disagree** ([Unverified] which is the latest policy; the changelog was not checked) | The 2 pages above |
| Registry (new-york-v4) | [Fact, measured] The dependencies in `https://ui.shadcn.com/r/styles/new-york-v4/<name>.json` are: tabs / dialog / sheet / tooltip / dropdown-menu / toggle-group / badge = `cn` and `radix-ui` (the unified package); command = `cn` and `cmdk`; native-select = `cn` only; sonner = `sonner` and `next-themes`. No source uses `forwardRef` | `lab/reg-*.json` |

Notes:
- `cn` (`cn@0.5.0` on npm, the shadcn-ui/cn repository, with shadcn as the single maintainer) is "a replacement for clsx and tailwind-merge". It adds +26.6 KiB (min) to the bundle. The package name itself has existed on npm since 2013. [Design decision] Considering supply-chain risk, **do not install the `cn` package; use pinned versions of `clsx` and `tailwind-merge`** (keep our own `cn()` in `lib/utils.ts`, the same form as older shadcn). The size is about the same.
- `radix-ui` (the unified package 1.8.1) installs all Radix packages (about 60) into node_modules as dependencies. The bundle is tree-shaken, so its size is the same. [Design decision] **Install only the individual `@radix-ui/react-*` packages**, and rewrite `import { X } from "radix-ui"` in the shadcn sources to `import * as X from "@radix-ui/react-x"` (fewer packages installed, smaller audit scope).

### 4.2 CSP measurements (Chromium, `file://`)

**Current CSP** (as generated by [`ui/scripts/inline-build.mjs`](../../ui/scripts/inline-build.mjs)):
```
default-src 'none'; script-src 'sha256-<app.js>'; style-src 'sha256-<app.css>'; img-src data:;
font-src 'none'; connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'
```

**Handling in CSP3 (summary of the specification)**: there is no `style-src-elem` or `style-src-attr`, so both are decided by `style-src`.
- `<style>` elements (`style-src-elem`): only those whose content hash matches are applied. **A `<style>` added at runtime is judged the same way**.
- style attributes (`style-src-attr`): blocked because there is no `'unsafe-inline'` (hashes do not apply to attributes unless `'unsafe-hashes'` is given).
- **Manipulation through CSSOM (`el.style.height = …`, `el.style.cssText = …`, `setProperty`) is outside the CSP**. React's `style={{…}}` writes through CSSOM, so it is allowed.

**Measured results** (`scripts/attr.mjs`, `scripts/csp-test.mjs`; run from `file://` in Chromium 1194):

| Operation | Result | Directive reported as violated |
|---|---|---|
| `style="…"` written in HTML | Blocked | style-src-attr |
| `setAttribute('style', …)` | Blocked | style-src-attr |
| A style attribute inside `innerHTML` | Blocked | style-src-attr |
| `el.style.height = …` / `el.style.cssText = …` | **Applied** | None |
| React's `style={{height: 33}}` | **Applied** | None |
| Positioning by Radix Popper (floating-ui) (`transform: translate(...)`) | **Applied** | None |
| A `<style>` created at runtime (hash does not match) | Blocked | style-src-elem |

**Libraries around Radix / shadcn that inject `<style>` at runtime** (found by grepping `lab/node_modules` and confirmed by measurement):

| Library | What it injects | Content | Impact if nothing is done | Remedy |
|---|---|---|---|---|
| `react-remove-scroll` (used by Radix Dialog/Sheet, DropdownMenu, Popover, Select; uses `react-style-singleton`) | Scroll-lock CSS and `.block-interactivity-<id>` | **Decided at runtime** (includes the scrollbar width and an ID), so it cannot be allowed by hash | Every time a dialog or menu opens, a CSP violation is logged as an error in the console (the existing E2E test "no CSP violations" fails). The background scroll lock does not work either | **Replace it at build time through an alias with our own compatible module that locks through CSSOM** (`resolve.alias: { 'react-remove-scroll': './src/lib/remove-scroll-csp.tsx' }`). Measured with `lab/src/remove-scroll-shim.jsx`: zero violations, `body.style.overflow = hidden` takes effect, and the Dialog focus trap works |
| `@radix-ui/react-scroll-area` | Fixed CSS that hides the scrollbar (169 characters) | Fixed | 1 violation | **Not used** (native scrolling + `scrollbar-width: thin`) |
| `@radix-ui/react-select` | Similar fixed CSS | Fixed | Violation when opened | **Not used** (use Native Select) |
| `sonner` | Inserts about 15 KB of fixed CSS into `<head>` with `__insertCSS`. Adds an empty `<style>` first, then fills it | Fixed | Toast styles are not applied (`position: static`) | **Not used** (give our existing toast the shadcn look). If adopted, adding "the hash of the CSS" and "the hash of the empty string" to `style-src` gives zero violations (measured) |
| cmdk | `style` property (CSSOM) only | — | None | Usable as is |
| Radix FocusGuards / VisuallyHidden / Tooltip / Tabs / Popper | CSSOM only | — | None | Usable as is |

**Conclusion**: [Fact] With the compatible module in place and without ScrollArea / Select / Sonner, it works **with zero violations under the current CSP** (operating Tabs / DropdownMenu / Dialog / Tooltip / Popover + cmdk / Toast in `lab/out/csp-extra.html` gave 0 `securitypolicyviolation` events and 0 console errors). **No CSP change is proposed**.
- [Unverified] The same measurements in Firefox and WebKit. To be confirmed with `E2E_ALL_BROWSERS=1` in CI (step 2 of the migration).
- [Design decision] The nonce approach (`setNonce` from `get-nonce`) is not adopted. A nonce in a static file is a fixed value anyone can read, so it is meaningless.

**Portal and `file://`**: Radix's Portal only renders directly under `document.body`, and uses no URL or origin. Tooltip, Popover, Dialog and DropdownMenu were confirmed to appear in the right positions over `file://`. One caveat: the Portal's content is rendered outside `<main role="tabpanel">`, so an E2E test that looks for elements inside a Portal with `getByRole('tabpanel').locator(...)` will not find them (§14).

**Compatibility with React 18 (important)**: [Fact, measured] The new-york-v4 components are function components that do not use forwardRef and take `ref` as a prop (the React 19 style). Using them in React 18 as in `<PopoverTrigger asChild><Button/></PopoverTrigger>` causes two things (`lab/out/ref18.html`):
- `Warning: Function components cannot be given refs` is logged as an error in the console (E2E fails).
- Popper cannot measure the trigger's position and ends up at `transform: translate(0px, -200%)` (**the menu does not appear in the right position**).

React 19.3.1 fixes it (`lab19/`). There are 2 options, and **option A was chosen (§16-2)**.
- **Option A (adopted): upgrade to React 19** (as a standalone step 0 of the migration, confirming that all existing E2E tests pass). The shadcn components can be used without rewriting. The cost is JS +79 KiB (min; react-dom 19 is large).
- Option B: stay on React 18 and wrap only the components that become children of `asChild` (Button, Badge, etc.) in `React.forwardRef`. No size increase, but every shadcn update needs rewriting.

### 4.3 Bundle size estimate (measured)

Minified with esbuild 0.25.10; the increase was measured from a baseline of React 18.3.1 alone (142.4 KiB). Measured in `lab/`.

| Configuration | +min | +gzip |
|---|---|---|
| @radix-ui/react-tabs | 28.3 KiB | 9.6 KiB |
| @radix-ui/react-dialog (also used for Sheet) | 41.8 | 13.9 |
| @radix-ui/react-tooltip | 56.9 | 19.9 |
| @radix-ui/react-popover | 70.0 | 24.4 |
| @radix-ui/react-dropdown-menu | 95.1 | 31.7 |
| @radix-ui/react-toggle-group | 26.1 | 8.9 |
| @radix-ui/react-select (not adopted) | 93.1 | 31.9 |
| @radix-ui/react-scroll-area (not adopted) | 24.6 | 7.7 |
| cmdk | 52.0 | 17.5 |
| sonner (not adopted) | 34.5 | 9.4 |
| clsx + tailwind-merge + cva | 28.0 | 8.7 |
| lucide-react (31 icons) | about 15 | about 5 |
| **Recommended set** (Tabs, Dialog, Tooltip, Popover, DropdownMenu, ToggleGroup, Separator, Slot, cmdk, cva, cn equivalent, 31 lucide icons, remove-scroll compatible module) * | **163.1 KiB** | **54.2 KiB** |
| Reference: React 18 → 19.3.1 | +78.6 KiB | +22.7 KiB |

(*) The sum of each package's increase is larger than the set's value, because shared parts (Popper, DismissableLayer, FocusScope, Portal, Presence, etc.) are counted more than once.

**Estimate for the output `index.html`** (currently 443 KiB = JS 416 + CSS 19 + HTML, including about 180 KiB of ioc.json):
- Staying on React 18 (option B): JS about +163 KiB, CSS about +8 KiB (tokens for 2 themes, only the utilities used from tw-animate-css) → **about 610 KiB (+38%)**
- React 19 (option A): **about 690 KiB (+56%)**
- Removing our own Button / Icon / Toast / Pill saves about −3 to 5 KiB.
- `file://` has no gzip transfer, so only parse time is affected. [Unverified] Startup time on mid-range devices. The target is "the existing 20,000-file performance test does not regress".
- Room to cut: drop tailwind-merge and use only `clsx` (about −25 KiB; requires a convention of never overriding classes). Drop Tooltip in favor of native `title` and `aria-label` (about −20 KiB, but not visible from the keyboard).

Increase in dependency packages (supply chain): runtime dependencies grow from 2 (react and react-dom) to about 30 (@radix-ui/*, plus @floating-ui, aria-hidden, react-remove-scroll-bar, use-callback-ref, use-sidecar, detect-node-es, get-nonce, tslib, cmdk, clsx, tailwind-merge, class-variance-authority, lucide-react). [Design decision] Pin every one of them and keep `npm ci --ignore-scripts`. When adding them, check each package's publish date and provenance, and pass the static check of `verify-no-network.mjs`.

---

---

## 5. Direction and design tokens

### 5.0 Concept: the "quarantine bench"

ZES **reads code without executing it**. The closest work to that is the job at a customs office or quarantine station of spreading a sample on a bench, examining it without opening it, and writing up a record (the brand tagline is also "zero-execution supply-chain quarantine"). So the screen is built as **a sample record and inspection records placed on a bench**.

The props and how they are used:

| Quarantine bench prop | Role on screen |
|---|---|
| Bench (ground) | The page ground. An achromatic color that asserts nothing. Components and side notes sit directly on it |
| Sheet | A surface that holds what you read. **Only 3: the sample record, the findings list and the SkillPact report** |
| Sample record | The record of the submitted folder: sample (`chaindrop/`), file count, scan time, not scanned, **0 executions**. The most prominent element on this screen |
| Record gutter | The left edge of a finding row. The severity color bar and the shape + word mark go here, like marks made in the paper margin during a review |
| Side notes | The right column: paste check, Blast Radius, CLI guidance, breakdown of not-scanned items. Not cards, but notes separated by rules |
| Stamp (purple ink) | A double-framed mark used only for L3. A stamp only shows that it "has been stamped" and does not say the contents are correct. This matches the meaning of L3 exactly (signature files exist; not safe) |
| Dashed line | Things that do not exist yet (drop target, no match, inconclusive). **No reassuring color** |

**Only one place is bold**. The path on the sample record is set large in 26px monospace, with "0 executions" next to it. This is the product's promise itself, so it is shown as a record, not as decoration. Everything else stays quiet.

### 5.1 Token plan: first draft, self-review, revision

Following the skill's procedure, a first draft was made and then reviewed by asking "would anyone make the same thing for a similar request (a security dashboard)?"

**First draft**
- Color: navy ground `#0f1626`, sheet `#162033`, primary the brand blue `#3A6BFF`, focus the brand teal `#3DDCC4`, text `#e8edf5`, supplementary `#94a3b8`.
- Type: system-ui + monospace. Monospace also for numeric labels.
- Layout: input card, 4 summary cards with large numbers, filter chips, table, 3 cards on the right (the same skeleton as v0.1).
- Principle: "carry the brand colors through the whole UI".

**What the self-review judged to be defaults, and fixed**

| # | First draft | Why it was judged a default | Revision |
|---|---|---|---|
| R-1 | Navy ground + blue primary | The classic A-1. Every security product ends up like this | Achromatic graphite and paper. The primary button is ink |
| R-2 | Carry the brand colors into the UI | Severity alone needs 7 hues (red, orange, yellow, blue, gray, green, purple). Adding blue and teal makes them hard to tell apart from LOW and SAFE. Teal is close to SAFE's green (v0.1 risk R-10) | **Color only for detections and stamps**. The brand colors live only inside the icon |
| R-3 | Teal focus | Same as above. A greenish ring looks "safe" in SkillPact | 2px ink outline + 2px gap. 9.4:1 or more on every ground |
| R-4 | 4 summary cards | The A-5 default. And it duplicates the filter chips' function | Merged into one tally, which is the filter |
| R-5 | 3 cards in the right column | A-3's rows of cards | Side notes. Sheets only for "what you read" |
| R-6 | Monospace for numeric labels | A-9 | Monospace only for strings you can type into a terminal |
| R-7 | Status row "Scan complete · 4 files · 0.0 s" | A-8 | Fields of the sample record (label and value) |
| R-8 | Dark bench at L 0.235 (`#201e1b`) | Once drawn, it was close to A-2's "tinted black" | Raised to L 0.255 (`#252220`), and the sheet, raised, well, rule and edge were raised by the same amount (contrast recomputed; all items pass) |
| R-9 | Icons before the side-note headings (key, terminal, i) | A per-heading icon is decoration; the heading text is enough | Removed ("look in the mirror and take one off") |
| R-10 | L3 as a purple Badge + stamp icon | A Badge pill is the shadcn default (A-14) | A double-framed stamp. No icon |

**Revised token plan** (final values in §5.2)

- Color (6 named colors, per theme):

  | Name | Role | Dark | Light |
  |---|---|---|---|
  | bench | Page ground | `#252220` | `#e8e6e3` |
  | sheet | Sample record, findings list, report | `#2e2c29` | `#fefdfc` |
  | ink | Body text, primary button fill, focus, selected tab line | `#efece7` | `#211d19` |
  | pencil | Supplementary text, unpressed state | `#b9b5b0` | `#57534e` |
  | rule | Dividers (decorative) | `#4b4945` | `#d1cfcc` |
  | signed | L3 stamp only | `#d2b1f9` | `#713dab` |

  Auxiliary: raised (popovers, sheets, toasts), well (inputs, code fields, table headers), select (hover and selected), edge (borders of inputs and buttons; for the 3:1 of 1.4.11).
- Type: Japanese text and UI in system-ui (falls back to Hiragino Kaku Gothic, Noto Sans JP, Yu Gothic UI). Code in ui-monospace. The 2 typefaces have completely different shapes, so the roles are distinguishable (§6).
- Layout: left-aligned. Two columns: the main column (sample record → tally → findings list) and the side notes (right, 320px). Center alignment only for the drop target in the empty state (§8).
- Principles:
  1. Color is evidence. Everything with a hue is a detection or a stamp.
  2. Only what you read goes on a sheet. Tools (buttons, filters, notes) go on the bench.
  3. Dashed means absent: drop target, no match, inconclusive. None gets a reassuring color.
  4. Monospace only for typeable strings. In paths, the directory is pencil and the file name ink.
  5. Labels only on forms (the sample record). No decorative labels above headings.

### 5.2 Semantic tokens (final values)

shadcn's variable names are used as is, with the values assigned to the "quarantine bench" names. The component sources are imported by hand (approved, §16-6), so shadcn's default classes are rewritten as well (§9). The color space is OKLCH. Chroma 0.004–0.010 at hue 75 is "a slightly warm gray", leaning neither toward off-white nor toward navy.

| shadcn variable | Quarantine bench name | Dark OKLCH | hex | Light OKLCH | hex |
|---|---|---|---|---|---|
| `--background` | bench | 0.255 0.006 75 | #252220 | 0.925 0.004 75 | #e8e6e3 |
| `--card` | sheet | 0.295 0.006 75 | #2e2c29 | 0.995 0.002 75 | #fefdfc |
| `--popover` | raised | 0.335 0.007 75 | #393633 | 1 0 0 | #ffffff |
| `--muted`, `--secondary` | well | 0.225 0.006 75 | #1d1b19 | 0.955 0.004 75 | #f2f0ed |
| `--accent` | selected row | 0.355 0.007 75 | #3e3b38 | 0.945 0.006 75 | #efece8 |
| `--foreground`, `--primary`, `--ring` | ink | 0.945 0.008 85 | #efece7 | 0.235 0.010 70 | #211d19 |
| `--primary-foreground` | (same as bench) | 0.255 0.006 75 | #252220 | 0.925 0.004 75 | #e8e6e3 |
| `--muted-foreground` | pencil | 0.775 0.008 75 | #b9b5b0 | 0.445 0.010 75 | #57534e |
| `--border` | rule | 0.405 0.007 75 | #4b4945 | 0.855 0.005 75 | #d1cfcc |
| `--input` | edge | 0.585 0.008 75 | #7f7b77 | 0.585 0.008 75 | #7f7b77 |
| `--destructive` | (CRITICAL fill) | 0.560 0.200 26 | #d02c2e | 0.540 0.205 27 | #cb1e21 |
| `--signed` | signed (purple stamp) | 0.815 0.105 305 | #d2b1f9 | 0.480 0.170 302 | #713dab |

Contrast (computed with `scripts/palette.py`; WCAG 2.1 relative luminance):

| Combination | Dark | Light | Threshold |
|---|---|---|---|
| ink / bench | 13.42 | 13.44 | 4.5 |
| ink / sheet | 11.81 | 16.48 | 4.5 |
| ink / raised | 10.19 | 16.74 | 4.5 |
| ink / selected row | 9.44 | 14.22 | 4.5 |
| pencil / bench | 7.75 | 6.12 | 4.5 |
| pencil / sheet | 6.83 | 7.51 | 4.5 |
| pencil / raised | 5.89 | 7.63 | 4.5 |
| pencil / selected row | 5.46 | 6.48 | 4.5 |
| Primary button (bench-colored text / ink fill) | 13.42 | 13.44 | 4.5 |
| edge / bench (input border, 1.4.11) | 3.77 | 3.37 | 3.0 |
| edge / sheet | 3.32 | 4.13 | 3.0 |
| edge / well | 4.09 | 3.69 | 3.0 |
| focus (ink) / bench | 13.42 | 13.44 | 3.0 |
| wordmark / bench | 14.52 (#F5F5F7) | 13.51 (#1D1D1F) | 4.5 |
| rule / sheet | Decorative, so out of scope. Component boundaries are shown by the edge | | |

### 5.3 Severity tokens

Each severity has 4: `--{sev}` (text, icon and bar), `--{sev}-tint` (tinted ground), `--{sev}-solid` (fill), and `--{sev}-solid-fg`. They are mapped to `--color-critical` etc. with `@theme inline`. **The variable name `safe` stays the same as now** (so the E2E check of `.text-safe, .bg-safe` keeps its meaning).

Text color contrast (`palette.json`; threshold 4.5):

| Severity | Shape (lucide) | Dark text | tint | bench | sheet | raised | selected row | Light text | tint | bench | sheet | raised | selected row |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| CRITICAL | octagon-alert | #fe938d | 5.85 | 7.36 | 6.48 | 5.59 | 5.18 | #b21a1c | 6.01 | 5.51 | 6.76 | 6.87 | 5.83 |
| HIGH | triangle-alert | #fdb171 | 6.92 | 8.81 | 7.76 | 6.69 | 6.20 | #9e480f | 5.50 | 4.98 | 6.10 | 6.20 | 5.26 |
| MEDIUM | circle-alert | #f3d761 | 8.56 | 11.07 | 9.75 | 8.40 | 7.79 | #79570b | 5.94 | 5.30 | 6.50 | 6.60 | 5.61 |
| LOW | diamond | #89c8fe | 6.78 | 8.85 | 7.79 | 6.72 | 6.23 | #0b5bae | 5.91 | 5.40 | 6.62 | 6.73 | 5.71 |
| INFO | info | #c8c3bd | 6.56 | 9.03 | 7.95 | 6.86 | 6.36 | #5a5651 | 6.29 | 5.84 | 7.17 | 7.28 | 6.18 |
| SAFE | circle-check | #7ee09b | 7.67 | 9.80 | 8.63 | 7.44 | 6.90 | #1b6c3a | 5.77 | 5.18 | 6.35 | 6.46 | 5.48 |
| L3 (purple stamp) | none (double frame) | #d2b1f9 | 6.72 | 8.58 | 7.56 | 6.51 | 6.04 | #713dab | 6.26 | 5.70 | 6.99 | 7.10 | 6.03 |

- The minimum is light HIGH / bench at **4.98:1**. HIGH text sits directly on the bench only in side notes; the list and the tally are on a sheet (6.10).
- Tint hex (dark / light): CRITICAL #562422 / #fdecea, HIGH #4c2d13 / #feefe1, MEDIUM #3d3515 / #fcf3d1, LOW #1d3850 / #e9f1fc, INFO #3c3935 / #f0eeeb, SAFE #1b3b25 / #e1f8e6, L3 #3f2c53 / #f4eefe.
- Fill (used only for the "undeclared" pill in SkillPact): CRITICAL is #fcfcfc on dark #d02c2e at **5.01:1**, and #fcfcfc on light #cb1e21 at **5.46:1**.
- Hue distances: red 24–27, orange 48–60, yellow 80–96, blue 245–255, purple 302–305, green 150–152, gray at chroma 0.01. To allow for differences in color vision, **shape (octagon, triangle, circle, diamond, i, check, double frame) and word are always shown together**. Nothing is distinguished by color alone.

**L3 rules (C-10)**
- L3 is shown only as the purple stamp (double frame in `--signed`: outer 1.5px, inner 0.75px, radius 2). The wording is fixed as "L3 signed files" (L3 署名済みファイル).
- Green (`--safe`), teal and the primary color (ink) are not used for L3. Neither are check-shaped icons (circle-check, badge-check, shield-check). Nor the words "safe", "trusted" or "Verified".
- The stamp is always accompanied by a sentence giving its meaning ("L3 only indicates that the files are 'signed'; it does not mean they are safe or that the author is trustworthy"). It is not hidden in a tooltip.
- The SkillPact tab panel has no `--safe` component at all (keeping the existing E2E).

### 5.4 CSS skeleton (the shape at implementation time; not written yet)

```css
@import "tailwindcss";
@import "tw-animate-css";

/* Dark by default (N-03). .light forces light, .dark forces dark.
   With no class, follow the OS setting (no flicker before scripts run) */
:root { color-scheme: dark;
  --background: oklch(0.255 0.006 75); --card: oklch(0.295 0.006 75); --popover: oklch(0.335 0.007 75);
  --muted: oklch(0.225 0.006 75); --accent: oklch(0.355 0.007 75);
  --foreground: oklch(0.945 0.008 85); --primary: var(--foreground); --ring: var(--foreground);
  --primary-foreground: var(--background); --muted-foreground: oklch(0.775 0.008 75);
  --border: oklch(0.405 0.007 75); --input: oklch(0.585 0.008 75);
  --signed: oklch(0.815 0.105 305); /* … 7 severities × 4 … */ }
@media (prefers-color-scheme: light) { :root:not(.dark) { color-scheme: light; /* … light values … */ } }
:root.light { color-scheme: light; /* … light values … */ }

@custom-variant dark (&:where(:root:not(.light) *));

@theme inline {
  --color-background: var(--background); /* … all shadcn tokens … */
  --color-critical: var(--critical); --color-critical-tint: var(--critical-tint); /* … */
  /* Radius by role. No longer computed from shadcn's --radius */
  --radius-xs: 2px;   /* stamp */
  --radius-sm: 3px;   /* tags, counts */
  --radius-md: 4px;   /* sheets, row highlights */
  --radius-lg: 6px;   /* buttons, inputs, toasts */
  --radius-2xl: 14px; /* top edge of the bottom sheet */
  --font-sans: system-ui, -apple-system, "Segoe UI", "Hiragino Sans", "Hiragino Kaku Gothic ProN", "Noto Sans JP", "Yu Gothic UI", "Yu Gothic", Meiryo, sans-serif;
  --font-mono: ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, "Cascadia Mono", "Noto Sans Mono", "Hiragino Sans", "Noto Sans JP", monospace;
}

/* Focus: an ink outline. It has no hue, so its meaning does not clash even on a severity ground */
:where(button, a, input, textarea, select, [tabindex]):focus-visible { outline: 2px solid var(--ring); outline-offset: 2px; }

@media (prefers-reduced-motion: reduce) { *, ::before, ::after { animation-duration: 0ms !important; transition-duration: 0ms !important; } }
```
- The theme switch has 3 choices: dark / light / system (a ghost icon button + Tooltip). Stored in localStorage as `zes-theme` (wrapped in try/catch; if it fails, it works without saving). No separate inline script is added to set the class before rendering (it would make 2 CSP hashes).
- Hiragino Sans and Noto Sans JP are added as Japanese fallbacks for monospace so that paths containing Japanese do not fall back to Mincho.

---

## 6. Typography

- **No web fonts are bundled** (C-02, `font-src 'none'` stays). `--font-sans` and `--font-mono` are in §5.4. On macOS / iOS this gives SF + Hiragino Kaku Gothic, on Windows Segoe UI + Yu Gothic UI, on Android / Linux Roboto or Noto Sans JP.
  - Why Inter is not bundled (unchanged from v0.1): even the latin subset adds 60–100 KiB (base64) per weight, and requires a CSP change to `font-src data:`. It does nothing for Japanese.
  - The brand typeface (Inter Display SemiBold) is used **only in the wordmark SVG (already outlined)**.
  - The mockups were drawn with Inter, IPA PGothic and JetBrains Mono because of the environment. The real display uses Hiragino or Noto.
- **Roles of the 2 typefaces**
  - Japanese text and UI (system-ui): headings, body, buttons, labels, counts, version, § numbers, rule numbers. Numbers use `tabular-nums`.
  - Code (ui-monospace): paths, commands, bundle ID, effect names (`exec`, `network`, etc.), hashes. **Only strings you can type into a terminal**.
- **Where the typesetting itself is the design**: in paths, the directory is pencil and the file name ink at weight 500 (`chaindrop/` + `package-lock.json`). Which file it is can be seen at a glance, and repeated directories can be skimmed. The path on the sample record is 26px monospace at 600.
- Scale (taken from the traditional scale 12 / 14 / 16 / 18 / 21 / 24 in *The Elements of Typographic Style*, with 26 only for the sample record):

  | Use | Size | Line height | Weight |
  |---|---|---|---|
  | Sample record path | 26 (22 on phones), monospace | 1.2 | 600 |
  | Screen heading (skill name) | 21–22 | 1.35 | 600 |
  | Tally numbers | 21 (19 on phones) | 1 | 600, `tabular-nums` |
  | Sheet and section headings | 15–16 | 1.5 | 600 |
  | Body, buttons, tabs, inputs, list paths (monospace 14) | 14 | 1.5 (1.7 for descriptions) | 400 / 500 |
  | List details, table body | 12.5–13 | 1.5 | 400 |
  | Supplementary text, tags, form labels | 12 | 1.4 | 400 / 500 |
- Japanese text at least 12px. Letter spacing 0. **No letter spacing even for uppercase English (severity values)**.
- Line length: column widths are chosen so that descriptions do not exceed 40 characters per line (about 520px). Side notes are 320px (about 24 characters).
- Wrapping: headings and buttons use `word-break: auto-phrase` (Chromium 119 and later) and `text-wrap: balance`. Body text uses `line-break: strict`. Paths and commands use `overflow-wrap: anywhere`. In the list they are cut to one line, and the full text is available through a Tooltip (desktop) or the detail sheet (mobile) and copying.
- Punctuation: full-width parentheses (（）) and middle dots (only for Japanese word lists). A half-width space between alphanumerics and Japanese text (`2 MiB 超`). Side information is not chained with middle dots (A-8).
- `font-feature-settings: "palt"` is not used (unchanged from v0.1).

---

## 7. Spacing, shape, shadow, motion

- 4px grid. Main values: 4 / 8 / 12 / 16 / 20 / 24 / 32. Page side margins are 24px at ≥1024px and 16px at <1024px. 32px between the main column and the side notes.
- **Radius by role** (A-3): stamp 2, tags and counts 3, sheets and row highlights 4, buttons / inputs / toasts 6, top edge of the bottom sheet 14.
- **Only 3 sheets** (sample record, findings list, SkillPact report). Sheet borders are a 1px rule. Everything else (tally, side notes, skill list) sits directly on the bench. The tally has only a rule border, no fill.
- **Shadows**: only on floating things (popovers, bottom sheets, toasts, Tooltips). Dark `0 6px 18px rgb(0 0 0 / .45)`, light `/ .16`. Sheets get no shadow.
- Heights: buttons and inputs 36px, small buttons 30–32px. **44px in touch environments (`pointer: coarse`)** (all mobile mockups use 44px).
- Dashed lines: 1–1.5px, `4 4`. Only for the drop target, no match, inconclusive, and the guidance for comparing with the previous version.
- Rules: table rows, form fields, side-note section breaks. Only the breakdown of not-scanned items in the side notes uses dotted lines (`2 3`).
- **Motion**: nothing moves by itself. Only responses to user actions.
  - Bottom sheet: 180ms, `translateY` only.
  - Popovers and tab search: 120ms fade only (no zoom).
  - Tooltip: 400ms delay, 80ms fade.
  - While scanning, progress is shown as numbers, not spinners or pulses.
  - Everything is 0ms under `prefers-reduced-motion: reduce` (§5.4).

---

## 8. Layout and breakpoints

### 8.1 Comparison of options (ASCII)

**A. The v0.1 skeleton** (for comparison; not adopted): cards stacked vertically. Summary big numbers and the filter duplicated.
```
┌Header─────────────────────────────────────────────────┐
├Tabs ‹ … › [All tabs]───────────────────────────────────┤
│┌Input card (drop | paste)─────────────┐ ┌Blast Radius┐│
│└──────────────────────────┘ └──────┘│
│ Scan complete · 4 files · 0.0 s               ┌CLI────┐│
│┌CRIT 4┐┌HIGH 3┐┌MED 0┐┌SAFE 62┐       └──────┘│
│(CRIT 4)(HIGH 3)(MED 0)(LOW 0)(INFO 0) [Search][▼] ┌Not scanned┐│
│┌Table─────────────────────┐ └──────┘│
```

**B. Quarantine bench (adopted)**: sheets only for "what you read". Tools on the bench. Left-aligned.
```
┌Logo  v0.1.0  ZES-2026-OCT-…  [Offline, zero external communication] Load [Export JSON] Clear ◐┐
├Overview 7  SkillPact  TeamPCP  ChainDrop 5  …                        [⌕ All tabs 18]┤
│┌Sample record (sheet)──────────────────────────────┐   Text paste check          │
││Sample      │Files│Scan time│Not scanned│Executions│✓ Scan complete [Select folder…]││  ┌well──────────┐ │
││chaindrop/  │ 4   │0.0 s    │0          │0         │Drop to replace           ││  └──────────────┘ │
│└─────────────────────────────────────────┘   0 / 1,000,000  [Check]│
│┌Tally = filter (rule border only)──────┐ ✓ 62 / 67 checks: no match  ───────────────── │
││▌4 ✓│▌3 ✓│ 0 □│ 0 □│ 0 □│  Only what the browser can check  Blast Radius [presence only]│
││CRIT│HIGH │MED │LOW │INFO│                           ┆No match┆           │
│└────────────────────┘                               ───────────────── │
│┌Findings list (sheet)────────── [⌕ Search    ] [Module ▼]┐   Host checks run in the CLI │
││gutter│Severity │Path / detail                    │Campaign     │§  │⧉│   ┌./zes-scan.sh …┐ │
││▌ │⬣ CRITICAL│chaindrop/package-lock.json      │chaindrop-keyv│§15│⧉│   └───────────┘ │
││▌ │          │Compromised package keyv@6.0.0 detected │       │   │ │  ───────────────── │
││▌ │▲ HIGH    │chaindrop/setup.mjs              │…            │§15│⧉│   Not scanned (not counted as 0)│
```
- Both columns left-aligned. Only numbers are right-aligned (the not-scanned counts in the side notes). Center alignment only for the drop target in the empty state and the columns of the effect table.
- Main column 1fr (1040px at 1440 width), side notes 320px, 32px between.

**C. Empty state (before a scan)**: a large drop target (dashed, centered) where the sample record goes.
```
│┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐   Text paste check │
│        Drop a folder to check it                              ┌──────────┐ │
│   Contents are used only for checks; never displayed, saved or sent └──────────┘ │
│            [Select folder…]   Load findings.json                                │
│└ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘                         │
```

**D. Mobile (375)**
```
┌▣ zero-exec shield        ◐ [⋯]┐
├Overview 7 SkillPact TeamPCP [⌕]┤
│┌Sample───────── ✓ Scan complete┐│
││chaindrop/                    ││
││Files│Scan time│Not scanned│Exec││
││4    │0.0 s    │0          │0   ││
│└───────────────┘│
│[Select folder…           ] [📋]│
│┌▌4 ✓  │▌3 ✓  │ 0 □   ┐   │
││CRIT  │HIGH  │MED    │   │
││ 0 □  │ 0 □  │✓62/67 │   │
│└───────────────┘│
│[⌕ Search by path or campaign] [≡]│
│┌───────────────┐│
││▌⬣ CRITICAL §15　chaindrop-keyv││
││▌chaindrop/package-lock.json [⧉]││
││▌Compromised package keyv@6.0.0…││
```

### 8.2 Breakpoints

| Width | Header | Tabs | Main column | Side notes | Findings list |
|---|---|---|---|---|---|
| ≥1280 (reference 1440, `overview-*.svg`) | 56px, one row | 44px. Show only the tabs that fit, with "All tabs 18" at the right end | Sample record (5 fields + actions), tally of 5 cells + SAFE sentence, list | Right, 320px | Table (gutter + severity 128 / path 1fr / campaign 160 / module 72 / copy 48) |
| 1024–1279 | bundle ID goes into a Tooltip | Same | Sample record moves "not scanned" and "executions" to a second row | Right, 300px | Campaign 128 |
| 768–1023 | Actions: "Export JSON" and "…" | Same | 1 column | 2 columns below the list | Table |
| 640–767 | Same | Horizontal scroll only | 1 column. The tally keeps 5 cells | 1 column | Table (module column removed, shown under the campaign) |
| <640 (reference 375, `mobile-*.svg`) | 52px: mark + wordmark, theme, "…" (44px) | 44px horizontal scroll + search button at the right end (44px) → bottom sheet | Sample record in 2 rows (path / 4 fields). Tally 3 + 2 cells + SAFE. Buttons 44px | 1 column (below the list) | One 96px row per finding (§10.4) |
| 320–359 | Wordmark removed, mark only | Same | **Tally in 2 columns × 3 rows** (144px per cell; with 3 columns of 96px the check and "CRITICAL" overlap). The 4 fields of the sample record are 72px (enough for "Scan time" (判定時間) and "0.0 s" (0.0 秒)) | Same | Same |

- The page never scrolls horizontally at any width. Only "the tab row" and "the SkillPact effect table (<768px)" scroll horizontally.
- Virtual scrolling keeps fixed row heights: 60px for the table, 96px for card rows. Switched with `matchMedia('(min-width: 640px)')`.

---

## 9. Component mapping

The shadcn new-york-v4 sources are imported by hand (approved, §16-6), and **their visual classes are rewritten to match the "quarantine bench"**. "CSP" column: ✅ = zero violations measured, — = does not use Radix. "Size" is the standalone increase (min) from §4.3.

| Current ([`ui/src/components`](../../ui/src/components/)) | Replacement | Dependencies | CSP | Size | Look (what changes from the shadcn default) | a11y, tests |
|---|---|---|---|---|---|---|
| `Button` in `ui.tsx` | **Button** (4 variants: `ink` / `outline` / `ghost` / `icon`. shadcn's `secondary` and `link` are not used) | cva, @radix-ui/react-slot | ✅ | about 1 KiB | Radius 6. `ink` is an ink fill with bench-colored text. Disabled is a rule border and pencil color (not faded with opacity) | Icon-only buttons require `aria-label`. 36px, 44px on touch |
| `Card` in `ui.tsx` | **Card only for "sheets"** (sample record, findings list, SkillPact report). Side notes are `<section>` | None | — | 0 | Radius 4, 1px rule, no shadow, inner padding 20 | Keep `data-testid` |
| `SeverityBadge` and `Pill` in `ui.tsx` | **Split Badge into 3 components**: `SeverityMark` (the gutter mark; shape + word, no border), `SeverityTag` (tinted ground, radius 3), `Tag` (achromatic, rule border) | cva | — | 0 | Not pills. Letter spacing 0 | Keep `data-severity` |
| (new) stamp | **`Stamp`** (the purple L3 stamp; double frame) | None | — | 0 | Outer 1.5px, inner 0.75px, radius 2, purple-stamp text at 600 | `data-testid=l3-badge` |
| `Icon` in `ui.tsx` | **lucide-react** (as in the v0.1 list) + the brand logo SVG | lucide-react | — | about 0.5 KiB each | Stroke width 2–2.25 | `aria-hidden` |
| `ToastProvider` in `ui.tsx` | **Keep our own toast** (approved, §16-7) | None | — | 0 | Raised ground, rule, radius 6, shadow. Bottom right of the main column | Keep `role="status" aria-live="polite"` |
| `ErrorBoundary` in `ui.tsx` | **Alert** (destructive) + Button | None | — | 0 | A CRITICAL bar on a sheet | `role="alert"`, `data-testid=render-error` |
| `Header` in `layout.tsx` | Logo SVG, `Tag`, Button, Tooltip; **DropdownMenu** on mobile | @radix-ui/react-tooltip, react-dropdown-menu | ✅ (needs the compatible module) | 56.9 / 95.1 | No Separator; separated by spacing | `<h1>` wraps the logo with `aria-label="zero-exec shield"`. `data-testid=bundle` |
| `TabBar` in `layout.tsx` | **Tabs** (`activationMode="manual"`, `loop`). The left/right arrow buttons are dropped | @radix-ui/react-tabs | ✅ | 28.3 | Selected: ink at 600 + a 2px ink line. Counts are numbers on a tint | Keep the ←→ / Home / End / Enter E2E. Counts included in `aria-label` |
| "All tabs" | ≥640: **Popover + Command**. <640: **Sheet (bottom) + Command** | react-popover, react-dialog, cmdk | ✅ (needs the compatible module) | 70.0 / 52.0 | Raised ground, radius 6 (top edge 14 for the sheet). Selected: selected-row ground + ink bar + check | combobox / listbox / option (§14). Ignore Enter during IME composition |
| `InputArea` in `overview.tsx` | Before a scan: a large drop target (dashed). After a scan: the **sample record** (Card). Paste moves to a `<section>` + Textarea in the side notes | None | — | 0 | §10.3 | Keep the `data-testid`s dropzone / dir-input / import-input / paste / paste-submit. dropzone is attached to the whole sample record and shows a dashed edge on dragover |
| `SummaryCards` + the severity chips of `FindingsToolbar` | **Merged into the tally (ToggleGroup `type="multiple"`)** | @radix-ui/react-toggle-group | ✅ | 26.1 | Rule border only. A pressed cell has a 3px bar on the left + check + color. An unpressed cell is pencil color + empty box | `data-testid=filter-{SEV}` on cells, `count-{SEV}` on numbers. `card-*` is retired (the E2E does not refer to it; §14) |
| Search and module in `FindingsToolbar` | **Input** + **Native Select**. Placed in the header row of the findings-list sheet | None | — | 0 | Well ground, edge border, radius 6 | `data-testid=search` |
| `FindingsTable` | Our own virtual scrolling + the structure of shadcn Table | None | — | 0 | Rows 60px. A 4px severity bar at the left edge, `SeverityMark` in the gutter, the path in two-tone monospace. Hover uses the selected-row ground | Header row inside `role="table"` (W-8). `aria-rowcount` / `aria-rowindex` |
| `BlastRadiusPanel`, `CliOnlyNotice`, `UndeterminedCard` | A `<section>` in the side notes (heading + body). Empty is dashed | None | — | 0 | No icon before headings. Commands in a well field | Keep `data-testid` |
| L3 note in `skillpact.tsx` | Inside the report heading, **always shown to the right of the stamp** | None | — | 0 | The full-width purple band is dropped | `data-testid=l3-note` |
| `SkillList` | A list on the bench. Only the selected item gets the sheet ground + an ink bar on the left | None | — | 0 | | `data-testid=skill-item`, `aria-pressed` |
| `SkillPactViewer` | **Report** (one sheet divided into sections by rules) | None | — | 0 | Facts as label-value pairs. Policy as a MEDIUM tag | `data-testid=skillpact-viewer` |
| `EffectMatrix` | A native `<table>`. It is a form, so every cell has rules | None | — | 0 | Header row on the well ground. Declared = ink border; undeclared observed = CRITICAL fill | Keep `td[data-effect][data-divergence]` |
| prose / diff Alert | **Rows with a gutter bar** (same shape as the findings list). Inconclusive = dashed bar in pencil color | None | — | 0 | Not cards with a colored border | `data-testid` prose-alert / diff-alert |
| Rule list | A 2-column `<ol>`. Matches get the CRITICAL tint + bar | None | — | 0 | Numbers not zero-padded | `data-testid=rule-row`, `data-status` |
| `viewers.tsx` (MCP / Actions / extensions) | One sheet + a list of rows (`divide-y`) | None | — | 0 | Values in a well `<code>`. Dangerous tokens as `SeverityTag` | `data-risk`, `data-kind` |
| Not adopted | Sonner, Select, ScrollArea, Data Table, Resizable, Sidebar | — | — | — | Reasons in §4.2 and §4.3 | |

---

## 10. Per-screen specification (mapping to the mockups)

### 10.1 Header (0–56px of `overview-*.svg`)
- Left: logo (28px high, [`zes-logo-dark.svg`](../../brand/logo/zes-logo-dark.svg) / [`-light.svg`](../../brand/logo/zes-logo-light.svg)), version "v0.1.0" (12px, pencil; Tooltip "conforms to spec v5.2"), bundle ID `ZES-2026-OCT-EMERGENCY-V5.2` (monospace 13px, pencil; not a pill).
- Right: `Tag` (wifi-off) "Offline, zero external communication" (オフライン・外部通信ゼロ; achromatic; Tooltip explains the CSP), ghost "Load findings.json", outline "Export JSON" (disabled before a scan), ghost "Clear", theme (ghost icon).
- A 1px rule below. The header uses the same ground as the bench (not filled differently).
- <640: mark (28px) + wordmark (14.5px high), theme, "…" (DropdownMenu: Export JSON / Load findings.json / Clear / Theme / show and copy the bundle ID).

### 10.2 Tabs (56–100px)
- Selected: ink at 600, with a 2px ink line below. Others: pencil at 500, ink on hover.
- Counts: a number in the text color of the highest severity on that severity's tint (12px at 600, radius 3). Not shown for 0.
- On desktop, **only the tabs that fit** are shown (the overflow is not drawn; no gradient fades or arrow buttons). An outline "⌕ All tabs 18" at the right end → Popover (width 360, max 70vh): a Command input "Search tabs (e.g. mcp, persistence)", 18 items (36px; selected = selected-row ground + ink bar + check; count on the right).
- <640: a search button at the right end (44px) → bottom sheet (`mobile-menu-dark.svg`): handle, "All tabs 18", close (44px), search field (focus outline), "The order is fixed as in §7.2. Numbers are finding counts." and a list of 44px items. **Tabs with 0 findings show no number**.

### 10.3 Overview tab, desktop (`overview-dark.svg` / `overview-light.svg`)
- **Sample record** (y=124, height 88, sheet): "Sample" (12px pencil) and `chaindrop/` (monospace 26px) | Files 4 | Scan time 0.0 s | Not scanned 0 | Executions 0 | ✓ Scan complete, drop to replace | ink "Select folder…". Dotted rules between fields. `data-testid=scan-status` goes on the "Scan complete" field (to satisfy the E2E `toContainText('スキャン完了')`).
  - "0 executions" is always 0, but it is a field that writes the product's promise down as a record. Tooltip: "ZES never executes or installs files".
  - The sample name is the top-level name of the submitted folder (the first segment of `webkitRelativePath`). For a paste check alone it is "pasted text"; for a findings.json it is that file's name.
- **Tally = severity filter** (y=232, height 64): 5 cells (150px). Inside a cell: the number (21px, ink) and shape + word (12px). A pressed cell has a 3px bar on the left + a check at the top right + the word and icon in the severity color. An unpressed cell is pencil color + an empty box at the top right. To the right: "✓ 62 / 67 checks: no match" and "Only what the browser can check" (SAFE green only on the icon).
- **Findings list** (y=312 onward, sheet): the header row has "7 findings", search (300px) and module (176px). Column headings in 12px pencil. Rows are 60px: a 4px bar at the left edge, shape + word in the gutter, the path (monospace 14, directory in pencil) and detail (12.5, pencil), campaign, module, copy (ghost 32px). Hover uses the selected-row ground. The copy Tooltip opens to the left (so it does not cover the module column). The second row in the mockup shows hover and keyboard focus (ink outline).
- **Side notes** (x=1096, width 320):
  1. Text paste check: heading, what it detects ("C2 domains/IPs, base64, exec(, curl"), Textarea (well, 84px), character count, outline "Check" (disabled when empty).
  2. Blast Radius + `Tag` "presence only, contents hidden", description, a dashed "No match (only the submitted folder is checked)" when empty, a note on the count, "Copy path list", steps.
  3. Host checks run in the CLI: a 3-line description, a well field with the command + copy.
  4. Not scanned (not counted as 0): a 4-line breakdown. Dotted rules between lines, counts right-aligned.
- Toast: bottom right of the main column. Raised ground, check, "Path copied", close.

### 10.4 Overview tab, mobile (`mobile-overview-*.svg`)
- Sample record (2 rows): the upper row has "Sample", `chaindrop/` (monospace 22px) and "✓ Scan complete"; the lower row has the 4 fields.
- Ink "Select folder…" (44px) and a clipboard button (44px; opens the paste box in a bottom sheet).
- Tally with 3 + 2 cells (56px) and the SAFE sentence. 2 columns × 3 rows at 320–359px.
- Search (44px) and a filter button (opens module selection in a sheet).
- Findings: 96px each. A bar at the left edge; line 1 has shape + word and "§15　chaindrop-keyv" (separated by a full-width space), line 2 the path (monospace 13.5, cut to one line), line 3 the detail (12px, cut to one line), and copy on the right (44px).
- **Tapping a row opens the detail sheet** (approved, §16-5): raised ground, top edge 14. The heading has the bar and shape + word; then the full path (monospace, wrapping), the full detail, campaign, module, and "Copy path" (ink, 44px). On close, focus returns to the tapped row.

### 10.5 SkillPact tab (`skillpact-dark.svg` / `skillpact-light.svg`)
- Left column (296px, on the bench): "1 skill", description, a filter (when there are 5 or more skills). The selected item has the sheet ground + an ink bar on the left. Items carry a small stamp and `CRITICAL 3`. A dashed "Compare with the previous version". Below: "The SAFE display is not used (safety is not asserted)".
- On the right, **the report (one sheet)**, divided into 4 sections by rules.
  1. Heading: skill name (22px), contract path (monospace), `CRITICAL 3` at the top right. Facts as label-value pairs (author / version / L2 record / signature file / contract / policy). The policy value "ask" is a MEDIUM tag. The stamp "L3 signed files", with the meaning sentence (ink) to its right and "The contract is only JSON-parsed. The skill, L2 tests and signature verification are not run" (pencil).
  2. Effects: declared (contract) vs observed (static analysis). Legend (undeclared = CRITICAL fill, declared = ink border, — none). A form with rules on every cell. Declared = ink-bordered pill, undeclared observed = CRITICAL-filled pill, declared observed = ink text, divergence = "⬣ undeclared, CRITICAL" or "match".
  3. 2 issues as gutter-bar rows: "HIGH conflict between prose and contract" (HIGH bar) and "Inconclusive: diff anomaly" (dashed bar, pencil color; no reassuring color).
  4. §49 detection rules: "12 rules: matched 3, no match / not applicable 8, inconclusive 1". 2 columns × 6 rows. Matched rows get the CRITICAL tint + bar, and the status word is CRITICAL at 600.

### 10.6 MCP / GitHub Actions / browser extensions (no mockups)
- Each viewer is one sheet, containing "path (monospace, directory in pencil)" and a list of rows. Values in a well `<code>`. Dangerous tokens as `SeverityTag`.
- Kinds of Actions references: SHA-pinned = SAFE tag (keeping the approved policy of old design document §8.6), tag reference = HIGH, possibly poisoned = CRITICAL, local = achromatic `Tag`.
- Empty = dashed line and wording (phrased so it cannot be read as "0 findings = safe"; the current wording is kept). While loading, progress is shown as a count in text. Errors as Alert (destructive).

### 10.7 List of wording changes

Policy: keep the current Japanese. Changes were made only where the skill's writing guidelines (write in the user's words, one element has one job, the same action has the same name, do not chain side information with middle dots) clearly improve things. The original Japanese strings are kept in parentheses because they are the exact UI text.

| # | Place | Current | v0.2 | Reason |
|---|---|---|---|---|
| T-1 | Status row | "Scan complete · 4 files · 0.0 s" (スキャン完了 ・ 4 ファイル ・ 0.0 秒) | Sample record fields "Files 4" (ファイル 4), "Scan time 0.0 s" (判定時間 0.0 秒) and "Scan complete" (スキャン完了) | Turned the middle-dot side information (A-8) into form fields. The words "Scan complete" (スキャン完了) are kept (E2E) |
| T-2 | Status row | "Not scanned 0 (size exceeded 0 / binary 0 / link target unknown 0) → see the right panel" (未判定 0 件（サイズ超過 0 / バイナリ 0 / リンク先不明 0）→ 右パネル参照) | "Not scanned 0" (未判定 0 件) on the sample record. The breakdown is in the side notes | Removed "→ see the right panel" (A-10). The breakdown is in the side notes; not written twice |
| T-3 | Sample record (new) | — | "Sample" (検体), "Files" (ファイル), "Scan time" (判定時間), "Not scanned" (未判定), "Executions" (実行), "0" (0 回), "Drop to replace" (ドロップで差し替え) | New form field names |
| T-4 | Drop area | "Drag and drop a folder" (フォルダをドラッグ＆ドロップ), "or Select folder… webkitdirectory" (または フォルダを選択… webkitdirectory) | "Drop a folder to check it" (フォルダをドロップして判定), "Select folder…" (フォルダを選択…) | State the action plainly. `webkitdirectory` is an implementation name that does not concern users |
| T-5 | Drop area note | "File contents are used only for checks and are never displayed on screen, saved or sent." (ファイル内容は判定にのみ使用し、画面表示・保存・送信を行いません。) | "Contents are used only for checks; never displayed, saved or sent" (内容は判定にのみ使い、表示・保存・送信しません) | Same meaning, shorter (against the W-4 wrapping). "Files over 2 MiB are counted as not scanned" (1 ファイル 2 MiB 超は未判定として計上) is left to "size exceeded (over 2 MiB)" (サイズ超過（2 MiB 超）) in the not-scanned breakdown in the side notes |
| T-6 | Summary cards | "Click to filter (selected)" (クリックで絞込（選択中）), "Includes LOW 0 · INFO 0" (LOW 0 ・ INFO 0 を含みます) | None | The pressed state is shown by the check and the bar. "Includes" read as if LOW and INFO were counted in the MEDIUM number (they are actually separate). The tally now has LOW and INFO cells, so it is unnecessary |
| T-7 | SAFE card | Heading "SAFE", "62 / 67 checks: no match" (62 / 67 チェック非該当), "Browser check scope only" (ブラウザ判定範囲のみ) | "62 / 67 checks: no match" (62 / 67 チェック非該当), "Only what the browser can check" (ブラウザで判定できる範囲のみ) | A large "SAFE" heading reads as "62 safe". Write only the fact (the number with no match) |
| T-8 | Toolbar | The label "Severity" (重大度) | None | The tally cells themselves are severities, so the label above is unnecessary (A-7) |
| T-9 | Toast | "Copied the path to the clipboard" (パスをクリップボードにコピーしました) | "Path copied" (パスをコピーしました) | Matches the button name "Copy path" (パスをコピー) (the same action has the same name) |
| T-10 | Tab search note (new in v0.1) | "Order of §7.2 (fixed) · numbers are finding counts" (§7.2 の順序（固定）・数字は検出件数) | "The order is fixed as in §7.2. Numbers are finding counts." (並びは §7.2 の順で固定。数字は検出件数です。) | Turned the middle-dot side information into sentences |
| T-11 | SkillPact heading | "author: trusted-vendor · version 3.0.0" (author: trusted-vendor ・ version 3.0.0), "L2 record: none · signature file: present (verification not run)" (L2 記録: なし ・ 署名ファイル: あり（検証は未実行）) | Label-value pairs (author / version / L2 record / signature file / contract / policy) | A-8 |
| T-12 | SkillPact badges | "Contract present · v0.8" (契約あり・v0.8), "Policy: ask" (ポリシー: ask) | Fact fields "Contract present (v0.8)" (契約 あり（v0.8）), "Policy ask" (ポリシー ask) | Same as above |
| T-13 | §49 tally | "12 rules · matched 3 · no match/not applicable 8 · inconclusive 1" (12 ルール・該当 3・非該当/対象外 8・判定不可 1) | "12 rules: matched 3, no match / not applicable 8, inconclusive 1" (12 ルール：該当 3、非該当・対象外 8、判定不可 1) | Middle-dot chaining replaced with commas |
| T-14 | Supplement to the L3 note | "The contract is only JSON-parsed · the skill / L2 tests / signature verification are not run" (契約は JSON パースのみ・スキル / L2 テスト / 署名検証は実行しません) (v0.1) | "The contract is only JSON-parsed. The skill, L2 tests and signature verification are not run" (契約は JSON パースのみ。スキル・L2 テスト・署名検証は実行しません) | Sentence break with a full stop. Middle dots for the list |
| T-15 | Not-scanned breakdown | "Symbolic link target unknown (0-byte decoy)" (シンボリックリンク先 不明（0 バイトのデコイ）) | "Symbolic link target unknown (0-byte decoy)" (シンボリックリンク先不明（0 バイトのデコイ）) | Removed an unnecessary space |

Unchanged: the severity values (CRITICAL etc.; shared with the CLI and findings.json), the cautions of the "0 findings is not shown as safe" kind, "L3 only indicates that the files are 'signed'…", the tab names, "All tabs" (すべてのタブ; the name used in E2E), and "Offline, zero external communication" (オフライン・外部通信ゼロ).

---

## 11. State and data flow (no change)

- `ScanProvider` (Context + `useReducer`), the `Action` type, the pure functions in `engine/*`, `findingsForTab`, and `TABS` (order of §7.2) are **not changed**.
- The only added state is local UI state.
  - Theme: `useTheme()`. Reads and writes `zes-theme` in localStorage inside try/catch.
  - Tab search string: Command's internal state (not put into the Context).
  - Open/closed state of Popover, Sheet and DropdownMenu: local state of each component.
- Tab selection is `dispatch({type:'SET_TAB'})`, as now. Radix Tabs is used **controlled** (`value={state.ui.activeTab}`, `onValueChange`), so the reducer stays the owner of the state.


---

## 12. Directory layout (planned)

```text
ui/
├── components.json                 ← shadcn CLI settings (style: new-york, tailwind.config: "", cssVariables: true, aliases under @/…)
├── vite.config.ts                  ← add resolve.alias: '@' and 'react-remove-scroll' → src/lib/remove-scroll-csp.tsx
├── tsconfig.json                   ← paths: { "@/*": ["./src/*"] }
├── scripts/inline-build.mjs        ← no change (same CSP shape). Add a check that the number of <style> stays 1
└── src/
    ├── lib/
    │   ├── utils.ts                ← cn() = twMerge(clsx(...))
    │   └── remove-scroll-csp.tsx   ← react-remove-scroll compatible module (locks through CSSOM; §4.2)
    ├── components/
    │   ├── ui/                     ← imported from shadcn and modified (committed)
    │   │   ├── alert.tsx  badge.tsx  button.tsx  card.tsx  command.tsx  dropdown-menu.tsx
    │   │   ├── input.tsx  native-select.tsx  popover.tsx  separator.tsx  sheet.tsx
    │   │   ├── table.tsx  tabs.tsx  textarea.tsx  toggle-group.tsx  tooltip.tsx  toast.tsx (port of our own)
    │   ├── brand/  Logo.tsx  Mark.tsx           ← the brand/logo SVGs as JSX
    │   ├── severity/  SeverityMark.tsx  SeverityTag.tsx  Stamp.tsx  Tag.tsx  severity.ts (token and icon mapping)
    │   ├── layout/  Header.tsx  TabBar.tsx  TabSearch.tsx  ThemeToggle.tsx
    │   ├── overview/  Intake.tsx (empty-state drop target)  SpecimenForm.tsx (sample record)  Tally.tsx (tally = filter)  FindingsTable.tsx  FindingList.tsx (<640)  FindingSheet.tsx (detail sheet)
    │   │             PasteCheck.tsx  BlastRadius.tsx  CliOnlyNotice.tsx  Undetermined.tsx (<section>s in the side notes)
    │   ├── skillpact/  SkillPactTab.tsx  SkillList.tsx  SkillPactViewer.tsx  EffectMatrix.tsx  LevelBadge.tsx  …
    │   └── viewers/  McpViewer.tsx  ActionsViewer.tsx  ExtensionViewer.tsx
    ├── hooks/  useTheme.ts  useMediaQuery.ts
    ├── styles/index.css            ← §5.4
    ├── engine/  state/  tabs/      ← no change
```
- The shadcn CLI (`npx shadcn add`) is **a development-time tool that uses the network**. It does not affect the output at runtime, but from a supply-chain point of view the recommended practice is not to use the CLI: check the registry JSON (`https://ui.shadcn.com/r/styles/new-york-v4/<name>.json`), import the source by hand, and record the imported version in the commit message (approved, §16-6).


---

## 13. Migration plan (in small steps; pass the build, Vitest and E2E at each step before moving on)

| # | Content | What to confirm |
|---|---|---|
| 0 | React 18.3.1 → 19.x (decided in §16-2), update @types/react. No change to the UI code | All E2E, `verify-no-network`, 20,000-file performance |
| 1 | Foundation: the `@/` alias, `components.json` (for reference; the CLI is not used), `lib/utils.ts` (clsx + tailwind-merge), the token CSS (starting from values close to the current colors), tw-animate-css. **No visual change** | Build size, CSP, E2E |
| 2 | Add the `remove-scroll-csp` compatible module and an E2E that detects CSP violations (counting `securitypolicyviolation`) first. Also run on Firefox and WebKit | 0 violations on all 3 engines |
| 3 | Leaf components: Button (ink / outline / ghost / icon), SeverityMark, SeverityTag, Tag, Stamp, Card (sheet), Alert, Input, Textarea, Native Select, lucide icons, brand logo | E2E, axe (contrast), visual comparison with the mockups |
| 4 | Switch to the "quarantine bench" tokens (§5) and match the dark look to the mockups. The sample record, the tally (merging the summary cards and chips) and turning the side notes into `<section>`s also happen here | Automatic contrast check (0 axe color-contrast violations) |
| 5 | Tabs (manual), Tooltip, ToggleGroup (tally) | Keyboard-operation E2E |
| 6 | Replace "All tabs" with Popover + Command (desktop) and Sheet + Command (mobile), and rewrite the E2E (§14) | Search, IME, focus returns on Escape |
| 7 | Mobile layout (header DropdownMenu, card-style findings list, detail sheet, paste sheet) | Horizontal overflow E2E at 320 / 375 / 768 |
| 8 | Light theme and theme switch (decided in §16-1) | axe in both themes |
| 9 | Cleanup: remove our own Icon / Button / Pill and the hard-coded colors, so that `grep '#[0-9a-f]\{6\}' src/components` finds 0 | Record the final size |

- One PR per step. Release decisions after step 4 (when the dark look is complete) and after step 8.
- To make reverting easy, steps 1–3 keep the old token names (`--color-surface`, etc.) as aliases.

---

---

## 14. Impact on tests

**Kept** (DOM attributes unchanged): the `data-testid`s dir-input, dropzone, paste, paste-submit, import-input, import-status, export, bundle, scan-status (the "Scan complete" field of the sample record), count-* (tally numbers), filter-* (tally cells), card-SAFE (the SAFE sentence), search, findings-table, finding-row, blast-radius, cli-only, undetermined, skillpact-viewer, skill-item, l3-badge, l3-note, prose-alert, diff-alert, rule-row, mcp-viewer, actions-viewer, extension-viewer, render-error, render-error-reset, all-tabs. `data-level`, `data-severity`, `data-effect`, `data-divergence`, `data-status`, `data-risk` and `data-kind` are also kept. 18 `role=tab`s, `aria-selected`, `role=tabpanel` and `role=status` (toast) stay the same.

**Changed**:
| Test | Reason | Rewrite |
|---|---|---|
| The "All tabs" menu (`getByRole('menu', {name:'すべてのタブ'})`, the first `menuitem` gets focus, ↓ and Enter select SkillPact) | It becomes a Command, so it turns into a `combobox` (the input gets focus automatically) and `listbox` / `option`. cmdk marks the first item as selected and indicates it with `aria-activedescendant` | `getByRole('dialog', {name:'すべてのタブ'})` → focus is in the input → ↓ and Enter select SkillPact. Closing with Escape and an outside click, and focus returning to `all-tabs`, are checked as before |
| Heading `getByRole('heading', {name:'Zero-Exec Shield'})` | The name is written in lowercase | No rewrite needed (`name` is a case-insensitive substring match by default; `exact` is not specified) |
| Places that look for elements inside a Portal with `getByRole('tabpanel').locator(...)` | Tooltips and Popovers are rendered outside the tabpanel | None in the current tests. New tests search the whole `page` |
| `card-CRITICAL` / `card-HIGH` / `card-MEDIUM` | Retired because the summary cards were merged into the tally | The current `tests/e2e/app.spec.ts` does not refer to them (confirmed with `grep`). `count-*` and `filter-*` remain in the tally with the same names. The existing check that pressing `filter-CRITICAL` narrows the list still passes |
| Horizontal overflow tests (per width) | The mobile layout changes | The expectation (`scrollWidth ≤ clientWidth`) stays. Add 320 to the tested widths |
| Added: zero CSP violations | §4.2 | Count `securitypolicyviolation` and require 0 after opening every tab, the menu, the Sheet, Tooltips and toasts |
| Added: no green in SkillPact | C-10 | Add `.border-safe` to the existing check that `[data-severity=SAFE], .text-safe, .bg-safe` match 0 elements. The computed color of `[data-testid=l3-badge]` is `--signed` |
| Added: visible focus | C-05 | When tabbing to each component, `outline-style` is `solid` and `outline-width` is 2px (both themes) |
| Added: tally at 320px | §8.2 | At 320px the tally is 2 columns, and the check and the word do not overlap (no intersection of `getBoundingClientRect`) |
| Added: theme | §5.4 | With `colorScheme: 'light'`, the `color-scheme` of `html` is light, and the theme switch result is saved (and no exception is thrown when localStorage is unavailable) |

---

---

## 15. Risks

| # | Risk | Impact | Mitigation |
|---|---|---|---|
| R-1 | A Radix update adds more `<style>` injection | CSP violations, E2E failures | Pin the versions and keep the zero-CSP-violation E2E in CI. In `inline-build.mjs`, grep the bundle for `createElement("style")` and `dangerouslySetInnerHTML` and fail if anything is outside the allowlist |
| R-2 | The `react-remove-scroll` compatible module breaks due to changes in Radix's internal API (the props Radix passes: `as`, `allowPinchZoom`, `shards`, `enabled`) | Scroll lock or rendering breaks | Unit test of the compatible module (open and close a Dialog). Add it to the checklist for Radix updates |
| R-3 | The bundle grows by +38–56% | Parse time over `file://` | The cuts in §4.3. Confirm with the 20,000-file performance E2E |
| R-4 | About 30 more dependencies (supply chain) | Given the nature of this tool, this affects trust | Pinning, `--ignore-scripts`, manual review of imported sources, installing only the individual `@radix-ui/*` packages |
| R-5 | Using shadcn v4 components on React 18 does not pass refs (measured) | Menu mispositioning, console errors | Option A or B in §4.2 |
| R-6 | CSP behavior of Firefox / WebKit over `file://` (unverified) | Display breaks in some environments | E2E on 3 engines in step 2 |
| R-7 | localStorage is unavailable for the theme switch (when disabled under `file://`) | Exception | try/catch. Even if it cannot save, the display follows the OS setting |
| R-8 | cmdk's filtering is erratic for Japanese substring matches (cmdk's default is a fuzzy-search score) | Search results feel unintuitive | Set `shouldFilter={false}` and use our own substring filter with normalization (NFKC and lowercasing) (`keywords` = display name + aliases + § number) |
| R-9 | shadcn's documentation and registry change fast (Base UI versions added, the Toast / Sonner disagreement) | The content differs depending on when it is imported | Treat imported sources as our own code. Record the hash of the registry JSON |
| R-10 | (v0.1's "the teal focus looks like SAFE") | — | **Resolved**. Focus is ink, and teal is not used in the UI |
| R-11 | Heavy use of rules drifts toward the newspaper look (A-15) | Back to a default look | Use rules only to separate records. Keep radii. At most 2 columns. Add to the review checklist |
| R-12 | With color limited to detections, some people may find the primary button (ink) not prominent enough | Hesitation in operation | Only one primary button per screen ("Select folder…"), with the ink fill giving the maximum contrast (13.4:1). Check in usability testing |
| R-13 | "0 executions" is always 0 and may look redundant as information | Credibility of the wording | Keep it as the product's promise, and show the basis in a Tooltip (ZES never executes or installs files). Structure it so the whole field can be removed if judged unnecessary |


---

## 16. Decisions (approved by the owner)

All 9 items of v0.1's §16 were approved. Only item 3 was revisited because of a condition that came up after the approval ("stop making it look AI-generated").

| # | Content | Decision | Handling in v0.2 |
|---|---|---|---|
| 1 | Add a light theme (dark by default, also following the OS setting) | **Decided** | §5.2, §5.4. Mockups made for both themes |
| 2 | Upgrade to React 19 (option A, +79 KiB) | **Decided** | Migration step 0 (§13) |
| 3 | Make the background the brand navy `#060a13` and primary the brand blue | **Revisited and changed** | Navy + blue is A-1 itself, and blue and teal are close to LOW and SAFE. Use the bench (graphite / paper) and ink instead, and keep the brand colors only inside the icon (§5.1 R-1 to R-3) |
| 4 | Change "All tabs" to tab search (cmdk's Command) | **Decided** | §10.2 |
| 5 | On mobile, tapping a finding row opens the detail sheet | **Decided** | §10.4 |
| 6 | Import the sources by hand instead of using the shadcn CLI | **Decided** | Rewrite the visual classes to the "quarantine bench" when importing (§9) |
| 7 | Do not adopt Sonner; keep our own toast | **Decided** | §9 |
| 8 | Keep tailwind-merge | **Decided** | Step 1 of §13 |
| 9 | Make "zero external communication" in the header a neutral color | **Decided** | An achromatic `Tag` (§10.1). The wording stays "Offline, zero external communication" (オフライン・外部通信ゼロ) as now |

### 16.1 Remaining items to confirm
- None (everything that can be decided in the design has been decided). After implementation step 4, visually check the 26px monospace of the sample record and the Japanese text alongside it on real devices (Hiragino on macOS, Yu Gothic UI on Windows).

---

## Appendix A. Verification record
- Palette: `scripts/palette.py` → `palette.json`. Computes the following for both themes and exits with code 1 if anything is below the threshold.
  - ink and pencil: 4.5 or more on bench, sheet, raised, well and selected row.
  - edge: 3.0 or more on bench, sheet and well.
  - The 7 text colors: 4.5 or more on tint, bench, sheet, raised and selected row.
  - White text on the CRITICAL fill: 4.5 or more.
  - Result: **all pass**. The minimums are 4.98 for text (light HIGH / bench) and 3.37 for component borders (light edge / bench).
- Mockups: `scripts/mockups.py` (overview and mobile), `skillpact.py`, `tokens.py`, `lib.py` (lays out using real font glyph widths measured with Pillow) → `*.svg`. `scripts/render.mjs` (Playwright's Chromium) → `mock-png/`. `scripts/sheet.py` → `sheet.png`. Rendered and checked visually, which led to these fixes:
  - The sample record note overlapping the button.
  - The Tooltip overlapping the module column and the row above.
  - SVG collapsing leading whitespace into "62/ 67".
  - The tint fill of the tally being too heavy (reduced to the bar and the check).
  - The focus example in the tally being confusable with selection (moved to the copy button).
  - The tab count icon looking like "©" (changed to a number on a tint).
  - The dark bench being close to black (L 0.235 → 0.255).
  - The icons on side-note headings (removed).
- Measurements carried over from v0.1 (no change):
  - Screenshots: `scripts/shots.mjs` → `current/`.
  - CSP: `scripts/csp-test.mjs`, `scripts/attr.mjs`.
  - React 18 refs: `scripts/ref18.mjs`.
  - Experimental builds: `../design-shadcn/lab/`, `../design-shadcn/lab19/`.
  - Bundle: esbuild 0.25.10.
  - Versions used: as in Appendix A of v0.1.
