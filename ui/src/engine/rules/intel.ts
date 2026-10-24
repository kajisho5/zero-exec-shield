// Detection data of 5.2.2: development infrastructure CVEs (§3 / §4 / §16), eMudhra (§6), collected intel (§7 / §15 / §22 / §30 / §38 / §42).
// References the same rules/ioc.json as check_s3 / check_s4 / emudhra_* / intel_* of the CLI. Host state (other than package DBs) is CLI only.
import { homeLike, push, readable, rootRel, type RuleCtx } from '../context';
import type { InfraCve } from '../ioc';
import type { Severity } from '../types';
import { basename, ere, versionCmp, versionMatches, type FCode } from '../util';
import { hookLocators } from './agentConfig';
import { workflowText } from './ciAndExtensions';
import { DOCKERFILE, plistLabel } from './codeAndHost';
import { collectDeps } from './supplyChain';

const NUM = /^\d+(\.\d+)+$/;
const sev = (s: string | undefined, d: Severity): Severity => (s === 'CRITICAL' || s === 'HIGH' || s === 'MEDIUM' || s === 'LOW' || s === 'INFO' ? s : d);

/** Evaluates with the fixed version per line (major.minor) (same rule as CLI version_branch_vulnerable). Vulnerable if the line has no fixed version and it is below the highest fixed version */
export function versionBranchVulnerable(v: string, fixed: string[]): boolean {
  if (!fixed.length) return true;
  const max = fixed.reduce((a, b) => (versionCmp(a, b) < 0 ? b : a));
  if (versionCmp(v, max) >= 0) return false;
  const branch = (x: string) => x.replace(/^v/, '').split('.').slice(0, 2).join('.');
  const same = fixed.find((f) => branch(f) === branch(v));
  return same ? versionCmp(v, same) < 0 : true;
}

/** §5 Python runtime from loaded files (the file part of CLI check_s5; the host python3 is CLI only): the first line of
 *  .python-version (all whitespace removed) and python:3.x image tags of FROM in Dockerfiles. 3.N means 3.N.0. */
export function pythonRules(ctx: RuleCtx): void {
  ctx.checks.add('s5-python');
  const mins = ctx.ioc.runtime_minimums?.python ?? [];
  if (!mins.length) return;
  const judge = (v: string, path: string, sha: string | null) => {
    if (!/^3\.\d+(\.\d+)?$/.test(v)) return;
    const ver = /^3\.\d+$/.test(v) ? `${v}.0` : v;
    if (versionBranchVulnerable(ver, mins)) push(ctx, { level: 'HIGH', module: '§5', campaign: null, path, code: 's5.python_old', params: { fixed: mins.join(' '), version: ver }, ruleId: `s5-python:${ver}`, evidenceSha: sha, kind: 'runtime.cve' });
  };
  for (const f of readable(ctx)) {
    if (f.name === '.python-version') judge((f.text.split('\n')[0] ?? '').replace(/[ \t\n\v\f\r]/g, ''), f.relPath, f.sha256);
    else if (DOCKERFILE.test(f.name)) {
      // grep -i -o 'FROM[[:space:]]+([^ ]*/)?python:3\.[0-9]+(\.[0-9]+)?' | sed 's/.*python://' (the sed is case-sensitive)
      for (const m of f.text.matchAll(/FROM[ \t\v\f\r]+([^ \n]*\/)?python:3\.[0-9]+(\.[0-9]+)?/gi)) {
        const i = m[0].lastIndexOf('python:');
        if (i >= 0) judge(m[0].slice(i + 7), f.relPath, f.sha256);
      }
    }
  }
}

/** Takes the version from image tags in compose / Dockerfile / k8s / tf / json (same as CLI detect_service_version) */
const IMAGE_FILES = /^(docker-compose.*\.ya?ml|compose.*\.ya?ml|Dockerfile.*|.*\.dockerfile|.*\.ya?ml|.*\.tf|.*\.json)$/;
function imageVersions(ctx: RuleCtx, pattern: string): { ver: string; path: string; sha: string | null }[] {
  const re = ere(`(${pattern}):[A-Za-z0-9._-]+`, 'g');
  if (!re) return [];
  const out: { ver: string; path: string; sha: string | null }[] = [];
  for (const f of readable(ctx).filter((x) => IMAGE_FILES.test(x.name))) {
    for (const m of f.text.matchAll(re)) {
      const tag = m[0].slice(m[0].lastIndexOf(':') + 1);
      out.push({ ver: tag.split('-')[0] ?? '', path: f.relPath, sha: f.sha256 });
    }
  }
  return out;
}

const cveLevel = (c: InfraCve): Severity => sev(c.severity, (c.cvss ?? 0) >= 9 || c.kev ? 'CRITICAL' : 'HIGH');

export function infraRules(ctx: RuleCtx): void {
  ctx.checks.add('s3-gitlab').add('s16-infra');
  for (const inf of ctx.ioc.infrastructures ?? []) {
    const pats = inf.image_patterns ?? [];
    // PHP (§4 PHP2Shell) is evaluated by php.ts with the same table as CLI check_s4 (php2shell_distro)
    if (!pats.length || inf.id === 'php') continue;
    // GitLab: all CVEs (§3); others: generic products and appended CVEs (§16)
    const cves = inf.cves.filter((c) => (c.fixed ?? []).length && (inf.id === 'gitlab' || inf.generic || c.generic));
    if (!cves.length) continue;
    const module = inf.id === 'gitlab' ? '§3' : '§16';
    const rule = inf.id === 'gitlab' ? 's3-gitlab' : 's16-infra';
    for (const { ver, path, sha } of imageVersions(ctx, pats.join('|'))) {
      const v = ver.replace(/^v/, '');
      if (!NUM.test(v)) {
        if (inf.id === 'gitlab') push(ctx, { level: 'HIGH', module, campaign: null, path, code: 's3.gitlab_version_unknown', params: { cves: cves.map((c) => c.id).join(' '), version: ver }, ruleId: `${rule}:${inf.id}:unknown`, evidenceSha: sha });
        else if (ver === 'latest' && module === '§16') {
          for (const c of cves) push(ctx, { level: 'MEDIUM', module, campaign: null, path, code: 'intel.infra_latest', params: { cve: c.id, fixed: (c.fixed ?? []).join(' '), product: inf.id }, ruleId: `${rule}:${inf.id}:latest:${c.id}`, evidenceSha: sha });
        }
        continue;
      }
      for (const c of cves) {
        const fixed = c.fixed ?? [];
        if (!versionBranchVulnerable(v, fixed)) continue;
        const level: Severity = module === '§16' ? cveLevel(c) : 'CRITICAL';
        // as jq prints the ioc.json literal (10.0 stays "10.0"; every cvss there has one decimal)
        const cvss = c.cvss ? (Number.isInteger(c.cvss) ? c.cvss.toFixed(1) : String(c.cvss)) : '';
        const msg: { code: FCode; params: Record<string, string> } = inf.id === 'gitlab'
          ? (cvss ? { code: 's3.gitlab_vulnerable', params: { cve: c.id, cvss, first_fixed: fixed[0] ?? '', fixed: fixed.join(' '), version: v } }
            : { code: 's3.gitlab_vulnerable_cvss9', params: { cve: c.id, first_fixed: fixed[0] ?? '', fixed: fixed.join(' '), version: v } })
          : (cvss ? { code: 'intel.infra_vulnerable_cvss', params: { cve: c.id, cvss, fixed: fixed.join(' '), product: inf.id, version: ver } }
            : { code: 'intel.infra_vulnerable', params: { cve: c.id, fixed: fixed.join(' '), product: inf.id, version: ver } });
        push(ctx, { level, module, campaign: null, path, ...msg, ruleId: `${rule}:${inf.id}:${c.id}:${v}`, evidenceSha: sha, kind: 'runtime.cve' });
      }
    }
  }
}

/** Fix evaluation of Debian-family ca-certificates (same as CLI debian_ca_fixed) */
export function debianCaFixed(v: string): boolean {
  const date = /^\d{8}/.exec(v)?.[0];
  if (!date) return false;
  if (Number(date) >= 20260816) return true;
  if (date !== '20250419') return false;
  const u12 = /deb12u(\d+)/.exec(v)?.[1];
  const u13 = /deb13u(\d+)/.exec(v)?.[1];
  return (u12 !== undefined && Number(u12) >= 2) || (u13 !== undefined && Number(u13) >= 1);
}

export function emudhraRules(ctx: RuleCtx): void {
  ctx.checks.add('s6-emudhra-os').add('s6-emudhra-runtime');
  const camp = 'emudhra-ca-oct2026';
  const e = ctx.ioc.emudhra;
  if (!e) return;
  const os = e.os_ca_certificates ?? {};
  for (const f of readable(ctx)) {
    if (/(^|\/)var\/lib\/dpkg\/status$/.test(f.relPath)) {
      // Read per paragraph (package), only those whose Status is installed (removed and config-files excluded; same as the CLI)
      let v: string | undefined;
      for (const para of f.text.replace(/\r\n/g, '\n').split(/\n{2,}/)) {
        const field = (k: string) => new RegExp(`^${k}: (.*)$`, 'm').exec(para)?.[1];
        const st = field('Status') ?? '';
        if (field('Package') !== 'ca-certificates' || !/installed$/.test(st) || /not-installed|config-files/.test(st)) continue;
        v = field('Version'); break;
      }
      if (!v) continue;
      const ubMin = os.ubuntu_min_upstream ?? '20260816';
      // The vendor is determined from the os-release of the same image (the Ubuntu SRU version 20260601~24.04.1 does not contain "ubuntu")
      const base = f.relPath.replace(/(^|\/)var\/lib\/dpkg\/status$/, '$1');
      const osr = ctx.byPath.get(`${base}etc/os-release`) ?? ctx.byPath.get(`${base}usr/lib/os-release`);
      const osid = /^ID=["']?([^"'\r\n]*)/m.exec(osr?.text ?? '')?.[1] ?? '';
      const bad = v.includes('ubuntu') || osid === 'ubuntu' ? Number(v.slice(0, 8)) < Number(ubMin) : !debianCaFixed(v);
      const ub = v.includes('ubuntu') || osid === 'ubuntu';
      if (bad) push(ctx, { level: 'HIGH', module: '§6', campaign: camp, path: f.relPath, ...(ub ? { code: 's6.ca_ubuntu', params: { min: ubMin, version: v } } as const : { code: 's6.ca_debian', params: { version: v } } as const), ruleId: 's6-emudhra-os:dpkg', evidenceSha: f.sha256, kind: 'runtime.cve' });
    } else if (/(^|\/)lib\/apk\/db\/installed$/.test(f.relPath)) {
      const v = /^P:ca-certificates\n(?:[^\n]+\n)*?V:(\S+)/m.exec(f.text)?.[1];
      const min = os.alpine ?? '20261020-r0';
      if (v && (v.split('-r')[0] ?? '') < (min.split('-r')[0] ?? '')) {
        push(ctx, { level: 'HIGH', module: '§6', campaign: camp, path: f.relPath, code: 's6.ca_apk', params: { min, version: v }, ruleId: 's6-emudhra-os:apk', evidenceSha: f.sha256, kind: 'runtime.cve' });
      }
    }
  }
  const fx = e.fixed ?? {};
  const judge = (name: string, v: string, path: string, sha: string | null, fixed: string[] | undefined) => {
    if (!/^\d+\.\d+\.\d+$/.test(v) || !fixed?.length || !versionBranchVulnerable(v, fixed)) return;
    push(ctx, { level: 'HIGH', module: '§6', campaign: camp, path, code: 's6.runtime_trusts', params: { fixed: fixed.join(' '), name, version: v }, ruleId: `s6-emudhra-runtime:${name}:${v}`, evidenceSha: sha, kind: 'runtime.cve' });
  };
  for (const f of readable(ctx)) {
    if (f.name === '.nvmrc' || f.name === '.node-version') judge('Node.js', (f.text.split(/\r?\n/)[0] ?? '').trim().replace(/^v/, ''), f.relPath, f.sha256, fx.node);
    if (f.name === '.tool-versions') {
      const node = /^nodejs\s+(\S+)/m.exec(f.text)?.[1];
      const deno = /^deno\s+(\S+)/m.exec(f.text)?.[1];
      if (node) judge('Node.js', node, f.relPath, f.sha256, fx.node);
      if (deno) judge('Deno', deno, f.relPath, f.sha256, fx.deno);
    }
  }
  // Minimum version of certifi (same as runtime_minimums.certifi of CLI check_s6; evaluated from the dependency inventory)
  const certMin = ctx.ioc.runtime_minimums?.certifi;
  if (certMin) {
    for (const d of collectDeps(ctx)) {
      if (d.eco === 'pypi' && d.name === 'certifi' && versionCmp(d.version, certMin) < 0) {
        push(ctx, { level: 'HIGH', module: '§6', campaign: camp, path: d.path, code: 's6.certifi', params: { min: certMin, version: d.version }, ruleId: `s6-emudhra-runtime:certifi:${d.version}`, evidenceSha: d.sha, kind: 'runtime.cve' });
      }
    }
  }
  for (const i of imageVersions(ctx, '(^|[[:space:]/"=])node')) judge('Node.js', i.ver.replace(/^v/, ''), i.path, i.sha, fx.node);
  for (const i of imageVersions(ctx, 'denoland/deno')) judge('Deno', i.ver.replace(/^v/, ''), i.path, i.sha, fx.deno);
  for (const i of imageVersions(ctx, '(eclipse-temurin|amazoncorretto|openjdk|bellsoft/liberica-openjdk-[a-z]+|azul/zulu-openjdk)')) {
    const v = (i.ver.split('_')[0] ?? '').split('+')[0] ?? '';
    const u8 = /^8u?(\d+)/.exec(v)?.[1];
    if (u8 !== undefined) {
      if (Number(u8) < (fx.java8_update ?? 511)) push(ctx, { level: 'HIGH', module: '§6', campaign: camp, path: i.path, code: 's6.java8_trusts', params: { update: u8 }, ruleId: `s6-emudhra-runtime:java8:${u8}`, evidenceSha: i.sha, kind: 'runtime.cve' });
      continue;
    }
    judge('Java', v, i.path, i.sha, fx.java);
  }
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export function intelRules(ctx: RuleCtx): void {
  ctx.checks.add('s15-intel-files').add('s22-intel-actions').add('s38-intel-strings').add('s7-intel-strings').add('s42-intel-extensions').add('s30-intel-host');
  const intel = ctx.ioc.intel;
  if (!intel) return;
  const wf = /(^|\/)(\.github\/workflows\/[^/]+\.ya?ml|\.gitlab-ci\.ya?ml|\.circleci\/config\.ya?ml|Jenkinsfile|action\.ya?ml)$/;

  // §15 Known malicious files (SHA-256 against all files regardless of name; names by exact match)
  const shaCamp = new Map<string, string>();
  for (const x of intel.files ?? []) for (const h of x.sha256 ?? []) if (!shaCamp.has(h)) shaCamp.set(h, x.campaign);
  for (const f of ctx.files) {
    const c = f.sha256 ? shaCamp.get(f.sha256) : undefined;
    if (c) push(ctx, { level: 'CRITICAL', module: '§15', campaign: c, path: f.relPath, code: 'intel.file_sha256', ruleId: 's15-intel-files:sha', evidenceSha: f.sha256 });
  }
  for (const x of intel.files ?? []) {
    const names = new Set(x.names ?? []);
    for (const f of ctx.files) {
      if (names.has(f.name)) push(ctx, { level: sev(x.name_severity, 'HIGH'), module: '§15', campaign: x.campaign, path: f.relPath, code: 'intel.file_name', params: { name: f.name }, ruleId: `s15-intel-files:name:${f.name}`, evidenceSha: f.sha256 });
    }
  }

  // §22 Compromised actions (bad_refs are CRITICAL; tag references other than safe_refs get severity)
  const wfFiles = readable(ctx).filter((f) => wf.test(f.relPath));
  // As in CLI intel_actions, only GitHub Actions workflows and action.yml are looked at, normalized with workflowText
  const ghFiles = wfFiles.filter((f) => /(^|\/)(\.github\/workflows\/[^/]+|action)\.ya?ml$/.test(f.relPath)).map((f) => ({ f, text: workflowText(f.text).join('\n') }));
  for (const a of intel.actions ?? []) {
    const re = new RegExp(`uses:\\s*["']?${escapeRe(a.action)}@([^"'\\s#,}]+)`, 'gi');
    for (const { f, text } of ghFiles) {
      for (const ref of new Set([...text.matchAll(re)].map((m) => m[1] ?? ''))) {
        if ((a.bad_refs ?? []).includes(ref)) {
          push(ctx, { level: 'CRITICAL', module: '§22', campaign: a.campaign, path: f.relPath, code: 'intel.action_compromised', params: { action: a.action, ref }, ruleId: `s22-intel-actions:${a.action}@${ref}`, evidenceSha: f.sha256 });
        } else if ((a.safe_refs ?? []).length && !(a.safe_refs ?? []).includes(ref) && !/^[0-9a-f]{40}$/.test(ref)) {
          push(ctx, { level: sev(a.severity, 'HIGH'), module: '§22', campaign: a.campaign, path: f.relPath, code: 'intel.action_unsafe_tag', params: { action: a.action, ref, safe: (a.safe_refs ?? []).join(',') }, ruleId: `s22-intel-actions:${a.action}@${ref}`, evidenceSha: f.sha256 });
        }
      }
    }
  }

  // §38 Known malicious strings in CI configs
  for (const w of intel.workflow_strings ?? []) {
    for (const f of wfFiles) {
      if ((w.strings ?? []).some((s) => f.text.includes(s))) push(ctx, { level: sev(w.severity, 'HIGH'), module: '§38', campaign: w.campaign, path: f.relPath, code: 'intel.ci_pattern', params: { campaign: w.campaign }, ruleId: `s38-intel-strings:${w.campaign}`, evidenceSha: f.sha256 });
    }
  }

  // §7 / §20 Known strings in AI configs and instruction files (file_regex narrows down the paths)
  for (const s of intel.strings ?? []) {
    const rx = ere(s.file_regex ?? '.');
    if (!rx) continue;
    const strs = (s.strings ?? []).map((x) => x.toLowerCase());
    for (const f of readable(ctx).filter((x) => rx.test('/' + x.relPath))) {
      const low = f.text.toLowerCase();
      const hit = strs.find((x) => low.includes(x));
      if (hit === undefined) continue;
      // If it is a hook in an agent config file, the location of the hook containing the first matched string (same as intel_strings in the CLI)
      const locators = /(^|\/)\.claude\/settings(\.local)?\.json$/.test(f.relPath) ? hookLocators(f.text, (c) => c.toLowerCase().includes(hit)) : undefined;
      push(ctx, { level: sev(s.severity, 'HIGH'), module: s.module, campaign: s.campaign, path: f.relPath, code: 'intel.campaign_string', params: { campaign: s.campaign }, ruleId: `s7-intel-strings:${s.campaign}`, evidenceSha: f.sha256, ...(locators ? { locators } : {}) });
    }
  }

  // §42 Malicious or compromised extensions (Chrome: Extensions/<id>/<ver>, VS Code / Open VSX: extensions/<publisher.name>-<ver>)
  for (const x of intel.extensions ?? []) {
    const bads = x.bad_versions ?? [];
    for (const id of x.ids ?? []) {
      const ide = !(x.eco === 'chrome' || x.eco === 'edge');
      const re = !ide
        ? new RegExp(`(^|/)Extensions/${escapeRe(id)}/([^/]+)/manifest\\.json$`)
        : new RegExp(`(^|/)extensions/${escapeRe(id)}-(\\d[^/]*?)(-[a-z0-9-]+)?/package\\.json$`, 'i');
      for (const f of ctx.files) {
        const m = re.exec(f.relPath);
        if (!m) continue;
        const ver = (m[2] ?? '').split('_')[0] ?? '';
        if (bads.length && !bads.some((b) => versionMatches(ver, b))) continue;
        push(ctx, { level: sev(x.severity, 'HIGH'), module: '§42', campaign: x.campaign, path: f.relPath.slice(0, f.relPath.lastIndexOf('/')), ...(ide ? { code: 'intel.ide_ext', params: { id, version: ver } } as const : { code: 'intel.browser_ext_version', params: { id, version: m[2] ?? '' } } as const), ruleId: `s42-intel-extensions:${id}@${ver}`, evidenceSha: f.sha256 });
      }
    }
  }

  // §30 Host traces (as in CLI intel_host_files, match against a different place per kind of path)
  //   ~/… / $HOME/… … only when the loaded folder can be regarded as HOME (homeLike), exact match with the path relative to it
  //   /… / $TMPDIR/… … real host paths. The browser cannot read them, so they are not matched (CLI host checks)
  //   anything else (site-packages/cook.pth etc.) … suffix match inside the loaded folder
  const asHome = homeLike(ctx);
  for (const h of intel.host ?? []) {
    const level = sev(h.severity, 'HIGH');
    for (const p of h.paths ?? []) {
      if (p.startsWith('/') || p.startsWith('$TMPDIR/')) continue;
      const home = /^(~|\$HOME)\//.exec(p);
      if (home && !asHome) continue;
      const rel = home ? p.slice(home[0].length) : p;
      for (const f of ctx.files) {
        if (home ? rootRel(ctx, f) !== rel : !('/' + f.relPath).endsWith('/' + rel)) continue;
        push(ctx, { level, module: '§30', campaign: h.campaign, path: f.relPath, code: home ? 'intel.host_path' : 'intel.host_path_in_root', ruleId: `s30-intel-host:path:${rel}`, evidenceSha: f.sha256 });
      }
    }
    const fileNames = new Set(h.file_names ?? []);
    for (const f of ctx.files) {
      if (fileNames.has(f.name)) push(ctx, { level, module: '§30', campaign: h.campaign, path: f.relPath, code: 'intel.host_file_name', params: { name: f.name }, ruleId: `s30-intel-host:file:${f.name}`, evidenceSha: f.sha256 });
    }
    const labels = new Set(h.launch_labels ?? []);
    for (const f of readable(ctx).filter((x) => /(^|\/)Launch(Agents|Daemons)\/[^/]+\.plist$/.test(x.relPath))) {
      const label = plistLabel(f.text);
      if (label && labels.has(label)) push(ctx, { level: 'CRITICAL', module: '§30', campaign: h.campaign, path: f.relPath, code: 'intel.launchd', params: { label }, ruleId: `s30-intel-host:launch:${label}`, evidenceSha: f.sha256 });
    }
    const units = new Set(h.systemd_units ?? []);
    for (const f of ctx.files) {
      if (/(^|\/)systemd\/(user|system)\/[^/]+$/.test(f.relPath) && units.has(basename(f.relPath))) {
        push(ctx, { level: 'CRITICAL', module: '§30', campaign: h.campaign, path: f.relPath, code: 'intel.systemd_unit', params: { unit: f.name }, ruleId: `s30-intel-host:systemd:${f.name}`, evidenceSha: f.sha256 });
      }
    }
  }
}
