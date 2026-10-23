English | [日本語](README.ja.md)

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/logo/zes-logo-dark.svg">
    <img src="brand/logo/zes-logo-light.svg" alt="zero-exec shield" height="72">
  </picture>
</p>

# Zero-Exec Shield (ZES)

ZES is a static scanner for software supply chain attacks, compromised developer machines and AI coding tool traps. It never executes the code it inspects: it reads files and package metadata and writes a `findings.json` report.

It comes in two forms: a Bash CLI (`zes-scan.sh`) and a single-file browser UI (`index.html`). Both use the same IoC database (`rules/ioc.json`).

> Scanner messages (`detail` in findings.json, the terminal log) and the browser UI are in Japanese. Field names, levels and error codes are ASCII.

## Quick start

### CLI

Requirements: Bash 4 or later (macOS ships Bash 3.2; use `brew install bash`), macOS or Linux, and `jq` (recommended; see [Limitations](#limitations)).

```bash
git clone https://github.com/kajisho5/zero-exec-shield
cd zero-exec-shield
./zes-scan.sh --quick --root /path/to/project --json > findings.json
```

The human-readable log goes to stderr and `findings.json` to stdout. Other modes:

```bash
./zes-scan.sh --full --root /path/to/project --json          # all modules §1-§49
./zes-scan.sh --skillpact --root /path/to/skills --json      # §49 only (experimental)
ZES_OFFLINE=1 ZES_HOST_CHECKS=0 ./zes-scan.sh --full --root . --json   # files only: no network, no host state
```

| Option | Meaning |
|---|---|
| `--root <dir>` | Directory to scan (default `.`) |
| `--quick` | §1-§19 (default) |
| `--standard` | §1-§35 |
| `--full` | §1-§49 |
| `--worm` | §15, §18, §25, §45 only |
| `--skillpact` | §49 only |
| `--url <URL>` | §4 header check of one http/https URL: `HEAD` (and `GET` only on 405/501), no redirects followed. A `PHP/x.y.z` in `Server` / `X-Powered-By` is compared with the PHP2Shell fixed versions |
| `--json` | Write findings.json to stdout |
| `--skillpact-cache <dir>` | Local directory of earlier SkillPact contracts for the §49 version comparison |

| Environment variable | Meaning |
|---|---|
| `ZES_IOC` | Path to the IoC database (default `rules/ioc.json` next to the script) |
| `ZES_HOME` | Home directory used by home-based checks such as §10-§14 (default `$HOME`) |
| `ZES_HOST_CHECKS=0` | Skip host state checks (processes, open connections, `/proc`, kernel, version probes of installed tools) |
| `ZES_OFFLINE=1` | Skip all outbound connections (§4 `--url`, §6 eMudhra probe); recorded as `skipped_offline` |
| `ZES_SKILLPACT_CACHE` | Same as `--skillpact-cache` |
| `ZES_GIT_TIMEOUT` | Timeout in seconds for git calls in §38/§46 (default 60); recorded as `git_timeout` |

### Browser UI

Open `index.html` in a browser. It works from `file://`; there is nothing to install and no server.

- Hosted copy: https://kajisho5.github.io/zero-exec-shield/ (GitHub Pages, serves `index.html` from `main`)
- To pin a version or to work without a network, download `index.html` and open it locally.

Drop a folder on the page (or use the folder picker). The scan runs in the browser and the page makes no network requests after it has loaded. You can also paste text for a check, export a findings.json, and load a findings.json produced by the CLI.

The UI has 18 tabs: an overview with severity summary, filters and search, a SkillPact tab, MCP / GitHub Actions / browser extension viewers, and tabs per campaign or topic. Checks that need the host (processes, connections, kernel, mounts, installed tool versions) cannot run in a browser; those tabs point to the CLI instead of showing "0 findings".

## What it checks

ZES has 49 modules (§1-§49). Each finding has a level: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` or `INFO`.

| Group | Modules | Examples |
|---|---|---|
| Package supply chain | §2, §9, §15, §25, §44, §45 | Known malicious or vulnerable versions in npm / yarn / pnpm / pip / Poetry / uv / PDM / Pipfile / Cargo / Go / Gemfile / composer lockfiles and installed `node_modules`, `dist-info`; `.pth` and `sitecustomize.py` startup hooks; suspicious install scripts; typosquats of payment SDKs; infostealer traces |
| Infrastructure and runtime CVEs | §3, §4, §5, §6, §16, §23 | GitLab, PHP (PHP2Shell), Python, the eMudhra intermediate CA (OS trust store, runtimes, pinned versions), CI/CD servers by image tag, container runtimes and kernel |
| AI coding tools and MCP | §7, §17, §20, §32, §36, §37, §41 | Invisible / BiDi characters in AI and editor config, `runOn: folderOpen`, dangerous MCP `command`/`args`, SymJack symlinks, agent hooks, Hugging Face `trust_remote_code`, pickle model files |
| CI/CD and git | §21, §22, §38, §46 | `pull_request_target` pwn requests, actions not pinned to a SHA, mass-planted workflows, git history provenance |
| Containers, cloud and signing | §8, §28, §29, §39, §43, §48 | `.env` and private keys, `docker.sock` mounts, unpinned base images, Kubernetes `hostPath`, metadata service / IMDSv1, cosign versions and `cosign verify` / `slsa-verifier` flags, SBOM vs lockfile mismatch |
| Host persistence and anti-forensics | §1, §10, §11, §12, §13, §30, §31, §33, §35, §40 | Compromise markers and process signatures, LaunchAgents / systemd / cron, `LD_PRELOAD` and eBPF, SSH key permissions, `ignore-scripts` and pip hardening, `noatime`, history tampering |
| Network, tooling and extensions | §18, §24, §26, §27, §34, §42 | C2 domains and IPs, browser extension permissions and ownership changes, git `core.fsmonitor`, build hooks (`build.rs`, `go:generate`, `cmdclass`), proxy and hosts settings |
| Credentials (Blast Radius) | §14, §19, §47 | Lists which credential files exist (`~/.ssh`, `~/.aws`, `~/.npmrc`, ...) by `stat` only, plaintext tokens in history and CI files |
| AI agent skills (experimental) | §49 | Compares a skill's [SkillPact](https://github.com/kajisho5/skillpact) contract with what its code appears to do |

The IoC values come from the ZES v5.2 Master Specification. Their check against primary sources is recorded in [docs/ioc-verification.md](docs/ioc-verification.md).

### §49 SkillPact contracts (experimental)

§49 reads a skill's `skill.contract.json` in the SkillPact 0.8 format (`contract_version` 0.1-0.8) and compares the declared `permissions` (`read`, `write`, `network`, `exec`, `spend`, `send`) with effects inferred from the code by static patterns.

- Undeclared `exec`, `network`, `spend` or `send` is HIGH. A read of sensitive files or a write outside the workspace that the contract does not cover is MEDIUM. Permissions widened from an earlier version without a major version bump (SkillPact spec §17) are HIGH or MEDIUM.
- ZES performs a partial check of the contract (I-JSON, structure, consistency, `integrity.files` hashes and coverage). Failures are MEDIUM `skillpact-invalid`. §49 never reports CRITICAL.
- ZES does not verify signatures, does not run tests, and does not evaluate allow/ask/deny policies. `signed: true` means a signature field is present, not verified. The `level` field is `"L1"` only when ZES's partial check passes; it is not a SkillPact conformance result. Use the SkillPact reference tools (`skillpact validate`, `skillpact conformance`) for that.
- Skills without a contract are not compared. If such a skill shows `exec`, `network`, `spend` or `send`, ZES adds one INFO finding.

Rules and output of §49 may change.

## Safety model

- **Zero execution.** ZES does not run files from the scanned tree and does not start their runtimes (`npm install`, `pip install`, `node`, `python` on target code). Package versions come from lockfiles and metadata, Go's version from `GOROOT/VERSION`, npm proxy settings from `.npmrc`.
- **Fixed probes only.** With host checks on, ZES starts a fixed list of installed tools with version arguments only (for example `python3 -I -S -V`, `php -n -v`, `docker --version`, `git --version`). Probes run under `env -i` with an empty temporary `HOME`, and binaries inside the scan root or in `/tmp`, `/var/tmp`, `/dev/shm` are never started. git runs against a ZES-owned shadow `GIT_DIR`, so the scanned repository's `.git/config` is never read by git, and every call has a timeout.
- **Verified by test.** [`tests/zero-exec.sh`](tests/zero-exec.sh) runs a full scan under `strace` and fails on any `execve` of a fixture file, any target runtime, or any probe outside the allowed arguments. Two fixtures are canaries that would create `/tmp/zes-canary-*` if executed.
- **No file contents in output.** Findings carry a path, a rule message and a SHA-256 (`evidence_hash`). Some messages include a short extracted value such as a version, image tag or HTTP header. Secrets are never printed.
- **Fail closed.** A module that could not be checked (missing `jq`, unparsable lockfile, timeout, offline) is recorded in `errors[]` and the scan `status` becomes `partial`. An empty `findings[]` with a non-empty `errors[]` does not mean "clean".
- **Network.** The CLI connects out only for `--url` and for the §6 eMudhra probe (HTTPS requests to the test hosts listed in `rules/ioc.json`). `ZES_OFFLINE=1` turns both off.
- **Browser UI.** JavaScript, CSS and `rules/ioc.json` are inlined into one file. The Content Security Policy is `default-src 'none'; connect-src 'none'`, with scripts and styles allowed only by SHA-256 hashes computed at build time (no `unsafe-inline`). The build fails if [`ui/scripts/verify-no-network.mjs`](ui/scripts/verify-no-network.mjs) finds network APIs, external URLs or external loads in the output. File contents are used only for matching; the page shows paths, rules, fixed text and hashes, plus a few configuration values capped at 120 characters (MCP `command`/`args`, Actions `uses:`, extension permission names).

## Output format

`findings.json` follows [`schemas/findings.schema.json`](schemas/findings.schema.json) (JSON Schema 2020-12, no additional properties).

```json
{
  "schema_version": "1.0",
  "incident_bundle": "ZES-2026-OCT-EMERGENCY-V5.2",
  "scan_started_at": "2026-10-22T00:00:00Z",
  "scan_finished_at": "2026-10-22T00:01:30Z",
  "scan_mode": "quick|standard|full|worm|skillpact",
  "status": "ok|partial|error",
  "findings": [
    {
      "id": "sha256:<SHA-256 of module|campaign|path|detail>",
      "level": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "module": "§49",
      "campaign": "skillpact-divergence",
      "path": "/abs/path",
      "detail": "...",
      "evidence_hash": "sha256:<SHA-256 of the file (over 100 MB: of path, size and mtime), or of detail when there is no regular file>",
      "skillpact": { "...": "§49 findings only" }
    }
  ],
  "errors": [{ "module": "§6", "reason": "skipped_offline" }]
}
```

- `id` is deterministic: the same finding gets the same id on every scan, and each id appears once.
- `campaign` is `null` for general checks. `path` is an absolute path or `null` (host findings without a file).
- `errors[].reason` examples: `skipped_offline`, `network_timeout`, `jq_unavailable`, `module_failed`, `lockfile_parse_failed:<path>`, `git_timeout`, `special_file:<path>`, `non_utf8_path:<path>`, `incident_bundle_mismatch:<value>`.
- All strings are valid UTF-8. Control characters are escaped as `\u00XX`. Invalid UTF-8 bytes in a file name are written as the text `\xHH` and the path is also recorded in `errors[]` as `non_utf8_path`. FIFOs, sockets and device files are not opened and are recorded as `special_file`.
- Findings exported by the browser UI use paths relative to the dropped folder with a leading `/`, always have `status: partial`, and record `ui:host_checks_not_performed` in `errors[]`.

The guarantees that downstream tools may rely on are listed in section 9 of [docs/skill-contracts.md](docs/skill-contracts.md).

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan finished, `status` is `ok` or `partial` (also `--help`) |
| `2` | `status` is `error` |
| `64` | Invalid arguments or environment (unknown option, `--root` not a directory, Bash older than 4, unreadable `rules/ioc.json`) |

ZES does not exit non-zero because of findings. To fail a CI job on CRITICAL findings:

```bash
./zes-scan.sh --quick --root . --json > findings.json
jq -e '[.findings[] | select(.level == "CRITICAL")] | length == 0' findings.json
```

To also fail on an incomplete scan, check `jq -e '.status == "ok"'`.

## Limitations

- **Static heuristics.** Detection is pattern and version matching. Expect false positives and missed cases. A clean result is not proof that a machine or project is safe.
- **IoC data ages.** `rules/ioc.json` is a snapshot (incident bundle `ZES-2026-OCT-EMERGENCY-V5.2`). It needs regular updates; values that could not be confirmed against primary sources are marked in [docs/ioc-verification.md](docs/ioc-verification.md).
- **Distribution backports.** Kernel, tool and PHP versions are compared with upstream fixed versions. Distribution packages often carry backported fixes, so these results are capped at HIGH and need checking against the vendor advisory. PHP from dpkg is compared with vendor fixed versions; on RHEL-like systems the rpm database cannot be read statically, so ZES only prints a notice.
- **`jq` is needed for full coverage.** Without it ZES falls back to grep for some checks; §48, §49, the collected-intel matches and some lockfile formats are then recorded as `jq_unavailable`.
- **Host checks read the live system.** They use `ps`, `lsof`, `/proc` and the version probes above. Set `ZES_HOST_CHECKS=0` when scanning only a directory.
- **`noatime`.** On filesystems mounted with `noatime`, the access-time checks of §13 (honeypot) and access traces do not work.
- **Browser UI.** It cannot see host state. A symlink arrives in the browser as a 0-byte file, so the SymJack check differs from the CLI (HIGH instead of CRITICAL). In WebKit, folders whose top level holds only hidden entries (`.mcp.json`, `.github/`) cannot be read; Safari may drop hidden files. Use drag and drop or the CLI in that case.
- **§49 is experimental and partial**, as described above.

## Related tools

ZES is the detection layer of three tools. The interface between them is defined in [docs/skill-contracts.md](docs/skill-contracts.md).

| Layer | Tool | Input / output |
|---|---|---|
| Detection | ZES (this repository) | Writes `findings.json`; read-only |
| Triage | ZET, Zero-Exec Triage: [kajisho5/zero-exec-triage](https://github.com/kajisho5/zero-exec-triage) | Reads `findings.json`, decides remediate / exception / defer, writes `remediation-plan.json` |
| Remediation | GER, Gated-Exec Remediation: [kajisho5/gated-exec-remediation](https://github.com/kajisho5/gated-exec-remediation) | Reads an approved `remediation-plan.json`, dry-run first, applies only allow-listed actions |

[`SKILL.md`](SKILL.md) lets an AI agent run ZES as a read-only detection skill. It also describes how to extract IoCs from new threat reports into `rules/ioc.json`.

## Development

```bash
tests/run-tests.sh                   # IoC database checks, campaign sync, fixture expectations
tests/run-tests.sh --sync-campaigns  # regenerate rules/campaigns/*.json from rules/ioc.json
tests/zero-exec.sh                   # strace execve check (Linux, needs strace)

cd ui && npm ci && npm run build     # type check, build, inline into ../index.html, static network check
npm test                             # Vitest, shares tests/fixtures with the CLI
npm run test:e2e                     # Playwright, from file://
```

- Fixtures are harmless stand-ins. Expected results live in `tests/expected/`.
- `ui/.npmrc` sets `ignore-scripts=true`, and dependencies are pinned in `package-lock.json`.
- After changing `rules/ioc.json`, rebuild `index.html`; CI fails if the committed file differs from a fresh build.
- The original UI design draft (in Japanese, written before implementation; its §49 parts predate the SkillPact 0.8 rework): [docs/design/ui-design.md](docs/design/ui-design.md).
- Changes are listed in [CHANGELOG.md](CHANGELOG.md).

## License and credits

ZES is licensed under the [Apache License 2.0](LICENSE). To report a vulnerability in ZES, see [SECURITY.md](SECURITY.md).

- **SkillPact.** §49 reads the SkillPact 0.8 contract format, https://github.com/kajisho5/skillpact. SkillPact © SEVENTHWELL (shogo kajiyama); the specification text is licensed under CC BY 4.0, the schemas and code under Apache-2.0. ZES implements a partial check of the unmodified format and is not a SkillPact conformance tool; its results are not a SkillPact level and are not an endorsement by SEVENTHWELL. Some `tests/fixtures/skillpact-*` files are copies of SkillPact conformance cases and examples ([tests/fixtures/skillpact-README.md](tests/fixtures/skillpact-README.md)).
- **PHP2Shell data.** The PHP2Shell fixed versions and the Debian / Ubuntu / RHEL package data in `rules/ioc.json` (`php2shell_distro`), and the version judgement in §4, are derived from [openai/php2shell-checker](https://github.com/openai/php2shell-checker) (Apache-2.0) and the vendor advisories listed there.
- **Review process.** The security review of ZES followed the methodology of [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill) (MIT). No code from it is included.
