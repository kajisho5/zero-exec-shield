---
name: zes-scan
description: Detection skill of Zero-Exec Shield (ZES) v5.2. Quarantines supply-chain attacks, CA compromise, infrastructure RCE, AI development environment traps, and divergence between what an AI agent skill declares and what it actually does (SkillPact contracts, experimental) with static analysis that never executes the target, and outputs findings.json. Also has an "IoC extraction mode" that extracts IoCs from new threat intelligence to extend rules/ioc.json. Detection only (read-only); decisions are made by ZET (zero-exec-triage) and remediation by GER (gated-exec-remediation).
---

# ZES detection skill (zes-scan)

- **incident_bundle**: `ZES-2026-OCT-EMERGENCY-V5.2`
- **Layer**: detection layer (read-only). It does not make decisions or remediate

**Language**: this file is in English, but answer the user in the language they use (for example, reply in Japanese to a user who writes in Japanese). Keep identifiers, paths, JSON keys and finding fields as they are.

```
[detection skill]   zes-scan … read-only, contract checks, divergence detection
      ↓ findings.json (with skillpact fields)
[decision skill]    ZET (zero-exec-triage) … impact assessment of divergence, exception approval
      ↓ remediation-plan.json
[remediation skill] GER (gated-exec-remediation) … executes only after explicit approval
```

## Absolute rules

1. **Zero-Execution**: do not execute the code, scripts or packages under inspection. `npm install` / `pip install` / running scripts with `php` / loading the target's code with `node` / `python` / running `.sh` files of fixtures or skills are forbidden.
2. **Do not read out contents**: do not output or quote file contents as detection results. Handle only paths, severity and metadata (size, mtime, hash).
3. **Do not modify**: do not rewrite the scan target, SkillPact contracts (skill.contract.json) or policies.
4. **fail-closed**: when `status` is `partial` / `error`, or `errors[]` is not empty, report the affected modules as "unconfirmed". Do not restate 0 findings as safe.
5. **Signatures and L3 are not grounds for trust**: ZES does not verify SkillPact signatures and does not judge L2/L3 (`level` is "L1" only when the skill passes ZES's partial checks). Even in SkillPact, L3 does not mean "safe".

## Detection modes

```bash
./zes-scan.sh --quick     --root <dir> --json   # §1–19
./zes-scan.sh --standard  --root <dir> --json   # §1–35
./zes-scan.sh --full      --root <dir> --json   # §1–49
./zes-scan.sh --worm      --root <dir> --json   # §15/18/25/45
./zes-scan.sh --skillpact --root <skills-dir> --json [--skillpact-cache <dir>]   # §49 (experimental)
```

Procedure:

1. Pass the directory the user specified to `--root`. If it is unclear, ask (do not scan `/` or `~` on your own initiative).
2. Run with `--json` and save findings.json from standard output (standard error is the human-readable log).
3. Report the result: `status`, counts by severity, the `module` / `campaign` / `path` / `detail` of CRITICAL/HIGH findings, and `errors[]` (unconfirmed modules).
4. §49 (experimental) statically checks whether the permissions an AI agent skill declares (`skill.contract.json` in [SkillPact](https://github.com/kajisho5/skillpact) 0.8 format) match what its code actually does. In the report, list `skillpact.divergence` (undeclared effects: read / write / network / exec / spend / send), `signed` and `diff_anomaly` alongside. Write `signed: true` as "has a signature field (not verified)", and never describe it as "safe" or "verified". Skills without a contract are not compared (reference INFO only) and are not treated as a problem.
5. Even when you propose remediation steps, do not execute them. Finish by giving the path of the findings.json to hand to ZET.

Do not include in the report: file contents, secret values, token strings.

## IoC extraction mode (§8.1)

Extract the following from new threat intelligence (URL / text) and draft additions to `rules/ioc.json`.

1. `campaign` name (`teampcp-mini-shai-hulud` / `chaindrop-keyv` / `pypi-oct2026` / `solana-typosquat` / `post-shaihulud` / `symjack` / `deadbugz` / `neighborjack` / `skillpact-*`, etc.)
2. Package name, compromised versions and safe version (both `bad_versions` and `safe_version`)
3. Malicious file names and hashes (SHA-256 only)
4. Network IoCs (C2 domains / IPs / exfiltration destinations; defang with the `[.]` form and write URLs as `hxxp`)
5. Infrastructure CVEs (version ranges and fixed versions for TeamCity / Artifactory / GitLab / Docker / Kernel / Sigstore)
6. Detection techniques (preinstall hook / SymJack / OIDC theft / runtime gate / ownership-transfer extension / build hook / model supply chain / anti-forensics / eBPF / LD_PRELOAD)
7. SkillPact (§49): cases where a SkillPact 0.8 contract (`permissions.<effect>.level`) diverges from observed behavior (undeclared `exec` / `network` / `spend` / `send`, `read` of sensitive files, `write` outside the work area), permission expansion without a major version bump (spec §17), and new code patterns for estimating observed behavior (`skillpact.observed_effect_patterns` in `rules/ioc.json`, etc.)

Notes on extraction:

- Corroborate with primary sources (official vendor advisories, GitHub Advisory, OSV, NVD, CISA KEV, official registries) and cite the source URLs. Mark values you cannot confirm as "unconfirmed"; do not fill them in by guessing.
- When sources contradict each other, record both and state which value you adopted and why.
- Record the result of checking against existing data in the format of `docs/ioc-verification.md` (match / differs / could not confirm).

## Merge rules (§8.2 / §13)

- When an entry duplicates the existing `ioc.json`, merge per `campaign`.
- Update `incident_bundle` to `ZES-2026-OCT-EMERGENCY-V5.2` (when bumping, also update `INCIDENT_BUNDLE` in `zes-scan.sh` and `CHANGELOG.md`).
- No orphan IoCs (tie every entry to a `campaign`).
- Write `packages[]` as **one entry per line**, for the grep fallback.
- After adding entries, add a reproduction fixture to `tests/fixtures/`, regenerate `rules/campaigns/*.json` with `tests/run-tests.sh --sync-campaigns`, and pass `tests/run-tests.sh` and `tests/zero-exec.sh`.

## Hand-off to the decision and remediation layers

- The detection skill ends by outputting findings.json. Exception approval and deadline setting are ZET's responsibility; change operations are GER's.
- The decision layer does not modify a finding's `id` / `level` / `module`. The remediation layer does not read findings.json directly (see `docs/skill-contracts.md`).
