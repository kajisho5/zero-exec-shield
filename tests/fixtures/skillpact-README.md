# SkillPact fixtures (§49)

The `skillpact-*` fixtures use the real SkillPact 0.8 contract format (`skill.contract.json`).

Copied from [github.com/kajisho5/skillpact](https://github.com/kajisho5/skillpact) (SkillPact © SEVENTHWELL (shogo kajiyama); per its LICENSE, specification text is CC BY 4.0 and code, JSON schemas and sample policies are Apache-2.0):

| Fixture | Origin |
|---|---|
| `skillpact-clean/v08-valid-signed` | `conformance/cases/v08-valid-signed` (unchanged) |
| `skillpact-signed-divergence/v08-valid-signed` | `conformance/cases/v08-valid-signed`, with `scripts/run.sh` changed by ZES to call `curl` (so the signed hash no longer matches) |
| `skillpact-version/version-unknown-major` | `conformance/cases/version-unknown-major` (unchanged) |
| `skillpact-malformed/json-duplicate-key`, `skillpact-malformed/v08-json-bigint` | `conformance/cases/…` (unchanged) |
| `skillpact-invalid/undeclared-effect`, `skillpact-invalid/integrity-mismatch` | `conformance/cases/…` (unchanged) |
| `skillpact-policy/valid-minimal`, `skillpact-policy/policies/strict-ci.json` | `conformance/cases/valid-minimal`, `examples/policies/strict-ci.json` (unchanged) |
| `skillpact-policy/policies/broken.json` | `examples/policies/strict-ci.json` made invalid by ZES |
| `skillpact-undeclared/contracted` | `conformance/cases/valid-minimal` plus a nested `.claude/skills/helper/SKILL.md` written by ZES |

Written by ZES in the same format (synthetic): `skillpact-divergence/*` (after the spec's Appendix B "thumb" example), `skillpact-undeclared/standalone`, `skillpact-diff-anomaly/v1|v2`. Their signature entries are placeholders; ZES never verifies signatures. The `conformance` test key in `v08-valid-signed` is the published test key of the SkillPact suite and must not be used for real signatures.

This is not an endorsement by SEVENTHWELL.
