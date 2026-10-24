# Bug hunt round 7 — shared brief

Read-only checkouts on main (do not edit; copy to your own scratch dir to experiment):
- ZES (bash `zes-scan.sh` + browser UI `ui/`, built `index.html`): `/home/user/wt/zes-040` (v0.5.4, 045be3e)
- ZET (Python): `/home/user/wt/zet-main` (f0dbbf8)
- GER (Python): `/home/user/wt/ger-main` (b73b5ce)

Round 4, 5 and 6 reports (found and fixed; do not re-report unless the fix is wrong or incomplete):
`/tmp/claude-0/-home-user/ddedecb1-31e9-5daf-bacd-4109257b812d/scratchpad/r4/{cli,ui,zetger}.md` `.../scratchpad/r5/{cli,ui,zetger}.md` and `.../scratchpad/r6/{cli,ui,zetger}.md`

What changed in round 6 (focus here first; older areas were hunted six times):
- ZES 0.5.4: one git-config parser following git's config.c on both sides (ZES_GITCFG_AWK / ui gitConfig.ts; every
  assignment reported; tests/gitconfig-cases.json); §17 agent hooks decided on the parsed document (jq JSON → JSONC →
  lenient reader `lenientJson.ts` / awk), raw grep only for unreadable files; json_view/jsonView for §7 runOn, §9, §20,
  §42, UI manifests; pointer encoding (ptrenc); identical findings merged silently (dedup_findings); bounded TOML key
  paths, pyproject loop; §27 bracket-depth tokenizer; bounded BOM view (16 MiB/file, 256 MiB total, bom_not_stripped);
  Dockerfile logical lines (escape directive); UI: I-JSON stack fix, Git configs up to 16 MiB, Git pointers as bytes,
  lf() anchors, variation-selector rule, asciiLower fast path. New fixtures r6-*.
- GER (b73b5ce, ger-hazards-4): `flagged_hooks` = ZES agent-hook rule on the parsed document + §7 campaign strings
  (CAMPAIGN_HOOK_STRINGS copy of ioc.json); checked journal writes (short write/ENOSPC → rollback, exit 5), torn/empty
  journal reader shared by G-8 and recover; per-target supersede; legacy journals by log order; chmod undo recognised;
  restore retry (tree_hash hash_modes, restore_id).
- ZET (f0dbbf8): single-pass template substitution.

What counts as a bug: wrong result (missed/extra finding, wrong level/id/detail/params/language, non-determinism),
crash/hang, broken guarantee (ZES never executes scanned content; no network from the UI; GER only tightens; gates
refuse what they should; ZET invariants), security issue (injection via names/contents/catalog/params into terminal,
JSON, HTML), CLI/UI mismatch for the same check. Style/wording preferences are not bugs.

Rules:
- Prove each finding with a minimal reproduction you actually ran (commands + observed output). No speculation.
- Rate severity (critical/high/medium/low) with one sentence of impact.
- Do not fix anything in the repos. Write your report to `<area>.md` in
  `/tmp/claude-0/-home-user/ddedecb1-31e9-5daf-bacd-4109257b812d/scratchpad/r7/` and return a short summary.
- If you find nothing after a thorough hunt, say so plainly and list what you checked.
- Tests: ZES `tests/run-tests.sh` ~12 min, `tests/zero-exec.sh` ~8 min — only if needed, in background.
- Playwright: Chromium at /opt/pw-browsers; never run `playwright install`.
