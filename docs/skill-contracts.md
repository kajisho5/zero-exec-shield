English | [日本語](skill-contracts.ja.md)

# ZES Skill Contracts — decision layer and remediation layer

- **Scope**: ZET — Zero-Exec Triage (decision layer, repository [kajisho5/zero-exec-triage](https://github.com/kajisho5/zero-exec-triage)) / GER — Gated-Exec Remediation (remediation layer, repository [kajisho5/gated-exec-remediation](https://github.com/kajisho5/gated-exec-remediation))
- **Schema ownership**: the layer that produces an output owns its schema; the receiving layer pins `schema_version` and refers to it (findings.json → ZES [`schemas/findings.schema.json`](../schemas/findings.schema.json) / remediation-plan.json → ZET / remediation-log.json → GER)
- **Upstream**: findings.json output by the detection layer `zes-scan` ([SKILL.md](../SKILL.md))
- **Role**: the common interface definition of the three layers. Implemented in ZET 0.1.0 / GER 0.1.0. The detection layer (ZES) conforms to it through the output guarantees in §9
- **Revision**: 2026-10-22, adopted contract additions A-1 to A-6 (ZET design) and the GER output additions (reflected in §3 and §6, each item marked [Added])
- **Authoritative schemas**: [remediation-plan.schema.json (ZET)](https://github.com/kajisho5/zero-exec-triage/blob/main/schemas/remediation-plan.schema.json) / [remediation-log.schema.json and ger-input.schema.json (GER)](https://github.com/kajisho5/gated-exec-remediation/tree/main/schemas). Where the JSON examples in this document disagree with them, the schemas win
- **Version**: ZES v5.2 (`incident_bundle`: `ZES-2026-OCT-EMERGENCY-V5.2`)

```
[detection layer]   zes-scan … read-only, contract checks, divergence detection
      ↓ findings.json (with skillpact fields)
[decision layer]    ZET (Zero-Exec Triage) … impact assessment of divergence, exception approval
      ↓ remediation-plan.json
[remediation layer] GER (Gated-Exec Remediation) … executes only after explicit approval
```

## 1. Common contract

- Input and output are UTF-8 JSON. Schemas are fixed; unknown fields are rejected (strict)
- Timestamps are RFC 3339 (UTC)
- fail-closed: a failed retrieval is not treated as 0 findings. No partial success is left behind
- Append-only log (`skill` / `version` / `input_hash` / `output_hash` / `started_at` / `finished_at` / `operator`)
- Detection logs and remediation logs are separate files with separate retention
- The decision layer is read-only; the remediation layer works from an allowlist

## 2. ZET input

```json
{
  "schema_version": "1.0",
  "findings": { "...": "ZES findings.json" },
  "policy": {
    "deadlines": {"CRITICAL": 30, "HIGH": 30, "MEDIUM": 60, "LOW": 90},
    "decision_window_days": 14,
    "approvers": ["security-lead", "platform-owner"]
  },
  "skillpact_policy": {
    "l3_trusted": false
  }
}
```

`skillpact_policy.diff_anomaly_threshold` and `skillpact_policy.destructive_requires_human` are reserved and not implemented. They are not required by ZET's schema, and if you specify them ZET rejects the input as "reserved, not implemented" (it does not accept a setting that looks effective but is not). Human approval of destructive operations is handled by the double approval for `reversible: false` in §7.

## 3. ZET output `remediation-plan.json`

```json
{
  "schema_version": "1.0",
  "plan_id": "uuid",
  "created_at": "RFC3339",
  "status": "ok|partial|error|draft",
  "plan_hash": "sha256:<SHA-256 of the canonical JSON of the body without plan_hash>",
  "items": [
    {
      "finding_id": "sha256:<hash>",
      "decision": "remediate|exception|defer",
      "exception_type": "not_affected|fix_unavailable|risk_accepted|null",
      "reason": "string",
      "owner": "team-or-person",
      "decided_by": "person",
      "decided_at": "RFC3339",
      "due_at": "RFC3339",
      "recheck_at": "RFC3339",
      "approved_by": ["security-lead"],
      "level_effective": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "action": {"type": "string", "target": "/abs/path", "params": {}, "reversible": true, "skillpact_effects": ["read"]}
    }
  ],
  "held": [{"finding_id": "sha256:<hash>|null", "module": "§6", "reason": "scan_error:skipped_offline"}]
}
```

| [Added] | Description |
|---|---|
| A-1 `status: "draft"` | A ZET draft. GER does not accept it (a final plan is `ok` / `partial`) |
| A-2 `decided_by` | The decision maker. Required so that "an exception is approved by someone other than the decision maker" can be checked mechanically |
| A-3 `level_effective` | The severity after being raised by SkillPact rules. The input `level` is not modified. It cannot be lowered |
| A-4 `action.reversible` / `action.skillpact_effects` | Set by ZET from the operation type and the finding's `declared_effects`. Because GER does not read findings, the plan carries the inputs for the double-approval and SkillPact-restriction checks |
| A-5 `held[].module` (`finding_id: null` allowed) | Holds the modules in `errors[]` per module (an unconfirmed state can be expressed even with 0 findings) |
| `action.target` | Must equal the `path` of the target finding (ZET does not output a plan where they differ. A finding whose `path` is `null` cannot have an `action`) |
| A-6 `plan_hash` | SHA-256 of the final plan's body (without `plan_hash`) as canonical JSON: keys sorted, separators `,` `:`, UTF-8. Checked against GER's approval token |

## 4. ZET invariants

- Every finding gets a decision (`held` is an explicit hold, not a missing decision)
- `exception` requires `exception_type` / `reason` / `recheck_at` / an `approved_by` other than the decision maker
- `remediate` requires `owner` / `due_at` / `action`
- `held` is not passed to the remediation layer
- The input findings' `id` / `level` / `module` are not modified
- [Added] `decided_by` / `decided_at` are required for every decision. `approved_by` may contain only people listed in `policy.approvers`. `due_at` is within the decision date + `deadlines[level_effective]` days; `recheck_at` for exception / defer is within the decision date + `decision_window_days` days
- [Added] When the input is `partial`, the plan is also `partial`, and every module in `errors[]` is listed explicitly in `held`
- Input with `findings.status == "error"` is rejected. Findings of modules recorded in `errors[]` are treated as unconfirmed (stated explicitly in `held`)
- **SkillPact**
  - A finding with a non-empty `skillpact.divergence` cannot be an `exception` (it must be `remediate` or `defer`)
  - A finding with `skillpact.diff_anomaly: true` requires 2 or more people in `approved_by`
  - Even with `skillpact.signed: true`, a non-empty `divergence` is treated as CRITICAL-equivalent (`signed` only means ZES saw that a signature field exists; it is not verified)
  - `skillpact_policy.l3_trusted` defaults to `false`. An L3 signature is not grounds for trust (evaluate it together with diff anomalies)
  - When SkillPact signature verification (`skillpact validate`, etc.) is needed, a human runs it in the decision layer (the detection layer only checks whether a signature field exists and does not judge L2/L3)

## 5. GER input

```json
{
  "schema_version": "1.0",
  "plan": { "...": "remediation-plan.json" },
  "approval": {
    "plan_id": "uuid",
    "approved_by": ["security-lead", "platform-owner"],
    "approved_at": "RFC3339",
    "approval_token": "sha256:<plan_hash of the approved plan>"
  },
  "mode": "dry-run|apply",
  "allowed_actions": ["chmod", "write_config", "rotate_secret"]
}
```

[Added] `approval_token` must equal the `plan_hash` of the final plan being approved (this binds the approval to the plan's content and detects substitution after approval). `allowed_actions` cannot use wildcards. Whether a dry-run and an apply are the same is decided by the SHA-256 of the canonical JSON of the input without `mode` (`input_hash`).

## 6. GER output `remediation-log.json`

```json
{
  "schema_version": "1.0",
  "plan_id": "uuid",
  "plan_hash": "sha256:<hash>",
  "mode": "dry-run|apply",
  "started_at": "RFC3339",
  "finished_at": "RFC3339",
  "status": "ok|partial|error",
  "results": [
    {
      "finding_id": "sha256:<hash>",
      "action_type": "chmod",
      "target": "/abs/path",
      "before": "0644",
      "after": "0600",
      "result": "applied|skipped|failed|rolled_back",
      "reason": "string",
      "applied_at": "RFC3339|null"
    }
  ]
}
```

[Added] `plan_hash` and `mode` (to identify uniquely which run of which plan this is). `applied_at` is `null` except for results that were actually applied.

## 7. GER invariants

- No execution without approval; a `plan_id` mismatch is rejected
- No apply without a preceding dry-run
- All targets are validated in advance. If even one fails, the whole run is aborted (no partial application)
- Does not read the ZES output (findings.json) directly (only `remediation-plan.json`)
- Operations outside `allowed_actions` are rejected (allowlist)
- Target paths are limited to `plan.items[].action.target`. A target is either the finding's `path` itself (relation `self`) or a target derivable from the finding's `path` through a `relation` (`npm_pkg_dir` / `npm_installed` / `pypi_record` / `ext_dir` / `skill_dir`, including `related` in findings 1.1); GER does not walk up to any other parent directory
- `chmod` only narrows permissions (for example `0644` → `0600`). ZET rejects `params` that widen permissions
- Every operation is idempotent. `reversible: false` requires double approval
- If even one `failed` occurs, the rest is not executed and the run is rolled back
- [Added] The executor (`--operator`) must not be in `approval.approved_by`. A dry-run record expires after 24 hours by default, and if the audit log's hash chain is broken, the dry-run record is not trusted
- **SkillPact**
  - Remediation of a skill whose `skillpact.declared_effects` includes `exec` / `network` / `spend` / `send` is rejected unless the operation is listed explicitly in `allowed_actions`
  - `skillpact.signed: true` is not a substitute for approval (human approval is mandatory)

## 8. Inter-layer rules

| Rule | Description |
|---|---|
| No skipping | The remediation layer does not read the ZES output directly |
| Schema validation required | Each layer validates its input schema and does not pass anything to the next layer on failure |
| Failure propagation | `status: "error"` is not passed to the next layer; `partial` states `held` explicitly |
| Chain of approval | `approved_by` for the decision layer and for the remediation layer are obtained separately (prevents self-approval) |
| Log separation | Detection, decision and remediation logs are separate files with separate retention |
| Version pinning | Each layer validates `schema_version` and rejects a mismatch |

## 9. What the detection layer (ZES) guarantees

These are the properties of findings.json that the decision layer may rely on (verified by `tests/run-tests.sh`).

- `schema_version` is `"1.2"` (ZES 0.5.0 and later. 1.2 adds `code` and `params` to findings, makes `detail` English, and changes `id` to v2. 1.1 (ZES 0.4.x) only added optional fields to 1.0, and builds `id` and `evidence_hash` the same way as 1.0)
- The top-level keys are only `schema_version` / `scan_roots` / `incident_bundle` / `scan_started_at` / `scan_finished_at` / `scan_mode` / `status` / `findings` / `errors`. `scan_roots` is an array of the real paths of `--root`
- The keys of a finding are only `id` / `level` / `module` / `campaign` / `path` / `detail` / `evidence_hash` / `evidence` (`skillpact` is added for §49 only), `code` / `params` (1.2), and the optional `kind` / `subject` / `locators` / `related`
  - `code`: the message id. The catalog key `f.<code>` in `i18n/en.json`. Language-neutral
  - `params`: the values that go into the message. All values are strings; keys are the catalog placeholders (`^[a-z_]+$`). Values are taken from the finding and can include text from scanned files (such as a `uses:` reference), so escape them before display; file contents beyond that are never included
  - `detail`: always English. The catalog entry `f.<code>` with `params` filled in; it never depends on `--lang` or the locale
  - `kind`: a machine-readable type (`pkg.compromised` / `pkg.vulnerable` / `pkg.lockfile_compromised` / `mcp.dangerous_command` / `mcp.unpinned` / `gha.pwn_request` / `gha.unpinned` / `secret.token` / `runtime.cve`). ZET's I-13 uses it to narrow the operations
  - `subject`: the package's `{ecosystem, package, version, safe_version, fixed_versions}` (§15)
  - `locators`: the relevant locations in the same file. JSON / JSONC / TOML use `{format, pointer}` (RFC 6901, for example `/mcpServers/<name>`); text uses `{format: "text", line, line_sha256}` (SHA-256 of the line, excluding the newline, a trailing CR and a BOM on line 1; the same as GER's `remove_line`). The content itself is never output
  - `related`: other targets derivable from the finding's path, `{relation, path}` (`npm_installed`, `ext_dir`, `skill_dir`)
  - `evidence`: typed evidence `{kind, hash}`. `file` (`large_file` above 100MB; the same value as `evidence_hash`) / `symlink` (SHA-256 of the readlink value) / `tree` (a directory; GER's ger-tree-v1) / `detail` (anything else, including findings about the scan root or the home directory itself)
- GER's quarantine store (a directory containing `.ger-quarantine-store`, owned by the running user, mode 0700) is not scanned (`quarantine_store_skipped` in `errors[]`; status is unchanged)
- The keys of `skillpact` are only `contract_path` / `contract_version` / `level` / `signed` / `author` / `declared_effects` / `observed_effects` / `policy_decision` / `l2_tested` / `divergence` / `diff_anomaly`. Effect names are only SkillPact 0.8's `read` / `write` / `network` / `exec` / `spend` / `send` (`secrets` / `persist` / `longrun` are retired). `policy_decision` is always `null` and `l2_tested` is always `false` (ZES does not evaluate them)
- `id` is `sha256:` + 64 hex digits and deterministic. It is unique within one findings.json (when the same `id` occurs twice, only one is kept and `duplicate_finding_id` is recorded in `errors[]`). `path` is an absolute path or `null`
  - id v2 (1.2): SHA-256 of `"zes-id-v2|" + module + "|" + campaign + "|" + path + "|" + code + "|" + params`, where `params` is `key=value` pairs sorted by key (C locale) and joined by U+001F, and a `null` `campaign` / `path` is the empty string. Every component and every param value is escaped first (`\` → `\\`, `|` → `\|`, U+001F → the six characters `\u001f`; since 0.5.1). Since 0.5.3 the escaping is applied to the original bytes and a byte that is not valid UTF-8 becomes `\xHH` (four characters, lower-case hex), so the preimage is injective. It does not depend on the language or the wording of `detail`
  - `id` changes once, in 0.5.0. ZET decisions and GER approvals made against 0.4.x findings cannot be carried over; re-scan and re-triage
- `evidence_hash` is the SHA-256 of the file for a regular file (above 100MB, the SHA-256 of path, size and mtime), and otherwise the SHA-256 of the English `detail` (built the same way in 1.2)
- Contains no file contents or secret values (apart from the short values in `params` / `detail` described above)
