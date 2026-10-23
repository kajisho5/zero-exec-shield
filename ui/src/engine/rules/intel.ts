// 5.2.2 の検知データ: 開発インフラ CVE（§3 / §4 / §16）、eMudhra（§6）、収集インテル（§7 / §15 / §22 / §30 / §38 / §42）。
// CLI の check_s3 / check_s4 / emudhra_* / intel_* と同じ rules/ioc.json を参照する。ホスト状態（パッケージ DB 以外）は CLI のみ。
import { push, readable, type RuleCtx } from '../context';
import type { InfraCve } from '../ioc';
import type { Severity } from '../types';
import { basename, ere, versionCmp, versionMatches } from '../util';
import { collectDeps } from './supplyChain';

const NUM = /^\d+(\.\d+)+$/;
const sev = (s: string | undefined, d: Severity): Severity => (s === 'CRITICAL' || s === 'HIGH' || s === 'MEDIUM' || s === 'LOW' || s === 'INFO' ? s : d);

/** 系列（major.minor）ごとの修正版で判定する（CLI version_branch_vulnerable と同じ規則）。系列に修正版が無く最大修正版未満なら脆弱 */
export function versionBranchVulnerable(v: string, fixed: string[]): boolean {
  if (!fixed.length) return true;
  const max = fixed.reduce((a, b) => (versionCmp(a, b) < 0 ? b : a));
  if (versionCmp(v, max) >= 0) return false;
  const branch = (x: string) => x.replace(/^v/, '').split('.').slice(0, 2).join('.');
  const same = fixed.find((f) => branch(f) === branch(v));
  return same ? versionCmp(v, same) < 0 : true;
}

/** compose / Dockerfile / k8s / tf / json の image タグからバージョンを取る（CLI detect_service_version と同じ） */
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
  ctx.checks.add('s3-gitlab').add('s4-php2shell').add('s16-infra');
  for (const inf of ctx.ioc.infrastructures ?? []) {
    const pats = inf.image_patterns ?? [];
    if (!pats.length) continue;
    // GitLab は全 CVE（§3）、PHP は PHP2Shell（§4）、その他は generic 製品と追記 CVE（§16）
    const cves = inf.cves.filter((c) => (c.fixed ?? []).length && (inf.id === 'gitlab' || (inf.id === 'php' ? c.id === 'CVE-2026-109618' : inf.generic || c.generic)));
    if (!cves.length) continue;
    const module = inf.id === 'gitlab' ? '§3' : inf.id === 'php' ? '§4' : '§16';
    const rule = inf.id === 'gitlab' ? 's3-gitlab' : inf.id === 'php' ? 's4-php2shell' : 's16-infra';
    for (const { ver, path, sha } of imageVersions(ctx, pats.join('|'))) {
      const v = ver.replace(/^v/, '');
      if (!NUM.test(v)) {
        if (inf.id === 'gitlab') push(ctx, { level: 'HIGH', module, campaign: null, path, detail: `GitLab のバージョンを特定できません。${cves.map((c) => c.id).join(' / ')} の修正版を確認してください`, ruleId: `${rule}:${inf.id}:unknown`, evidenceSha: sha });
        else if (ver === 'latest' && module === '§16') push(ctx, { level: 'MEDIUM', module, campaign: null, path, detail: `${inf.id} が浮動タグ（latest）。${cves.map((c) => c.id).join(' / ')} の修正版以上か確認`, ruleId: `${rule}:${inf.id}:latest`, evidenceSha: sha });
        continue;
      }
      for (const c of cves) {
        const fixed = c.fixed ?? [];
        if (!versionBranchVulnerable(v, fixed)) continue;
        const level: Severity = module === '§16' ? cveLevel(c) : 'CRITICAL';
        const name = inf.id === 'gitlab' ? 'GitLab' : inf.id === 'php' ? 'PHP' : inf.id;
        const what = inf.id === 'php' ? 'PHP2Shell（CVE-2026-109618/109619、認証不要 RCE）' : `${c.id}${c.cvss ? `（CVSS ${c.cvss}）` : ''}`;
        push(ctx, { level, module, campaign: null, path, detail: `${name} ${v} は ${what}の影響範囲（修正版: ${fixed.join(' ')}）`, ruleId: `${rule}:${inf.id}:${c.id}:${v}`, evidenceSha: sha });
      }
    }
  }
}

/** Debian 系 ca-certificates の修正判定（CLI debian_ca_fixed と同じ） */
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
      const v = /^Package: ca-certificates\n(?:[^\n]+\n)*?Version: (\S+)/m.exec(f.text)?.[1];
      if (!v) continue;
      const ubMin = os.ubuntu_min_upstream ?? '20260816';
      const bad = v.includes('ubuntu') ? Number(v.slice(0, 8)) < Number(ubMin) : !debianCaFixed(v);
      if (bad) push(ctx, { level: 'HIGH', module: '§6', campaign: camp, path: f.relPath, detail: `ca-certificates ${v}（dpkg）は eMudhra 侵害 CA を含む`, ruleId: 's6-emudhra-os:dpkg', evidenceSha: f.sha256 });
    } else if (/(^|\/)lib\/apk\/db\/installed$/.test(f.relPath)) {
      const v = /^P:ca-certificates\n(?:[^\n]+\n)*?V:(\S+)/m.exec(f.text)?.[1];
      const min = os.alpine ?? '20261020-r0';
      if (v && (v.split('-r')[0] ?? '') < (min.split('-r')[0] ?? '')) {
        push(ctx, { level: 'HIGH', module: '§6', campaign: camp, path: f.relPath, detail: `ca-certificates ${v}（apk）は eMudhra 侵害 CA を含む（Alpine 修正版 ${min}）`, ruleId: 's6-emudhra-os:apk', evidenceSha: f.sha256 });
      }
    }
  }
  const fx = e.fixed ?? {};
  const judge = (name: string, v: string, path: string, sha: string | null, fixed: string[] | undefined) => {
    if (!/^\d+\.\d+\.\d+$/.test(v) || !fixed?.length || !versionBranchVulnerable(v, fixed)) return;
    push(ctx, { level: 'HIGH', module: '§6', campaign: camp, path, detail: `${name} ${v} は eMudhra 侵害 CA を信頼（修正版: ${fixed.join(' ')}）`, ruleId: `s6-emudhra-runtime:${name}:${v}`, evidenceSha: sha });
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
  // certifi の最低版（CLI check_s6 の runtime_minimums.certifi と同じ。依存インベントリから判定）
  const certMin = ctx.ioc.runtime_minimums?.certifi;
  if (certMin) {
    for (const d of collectDeps(ctx)) {
      if (d.eco === 'pypi' && d.name === 'certifi' && versionCmp(d.version, certMin) < 0) {
        push(ctx, { level: 'HIGH', module: '§6', campaign: camp, path: d.path, detail: `certifi ${d.version} は ${certMin} 未満（eMudhra 失効が未反映）`, ruleId: `s6-emudhra-runtime:certifi:${d.version}`, evidenceSha: d.sha });
      }
    }
  }
  for (const i of imageVersions(ctx, '(^|[[:space:]/"=])node')) judge('Node.js', i.ver.replace(/^v/, ''), i.path, i.sha, fx.node);
  for (const i of imageVersions(ctx, 'denoland/deno')) judge('Deno', i.ver.replace(/^v/, ''), i.path, i.sha, fx.deno);
  for (const i of imageVersions(ctx, '(eclipse-temurin|amazoncorretto|openjdk|bellsoft/liberica-openjdk-[a-z]+|azul/zulu-openjdk)')) {
    const v = (i.ver.split('_')[0] ?? '').split('+')[0] ?? '';
    const u8 = /^8u?(\d+)/.exec(v)?.[1];
    if (u8 !== undefined) {
      if (Number(u8) < (fx.java8_update ?? 511)) push(ctx, { level: 'HIGH', module: '§6', campaign: camp, path: i.path, detail: `Java 8u${u8} は eMudhra 侵害 CA を信頼（修正版 8u${fx.java8_update ?? 511}）`, ruleId: `s6-emudhra-runtime:java8:${u8}`, evidenceSha: i.sha });
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

  // §15 既知の悪性ファイル（SHA-256 は名前に依らず全ファイル、名前は完全一致）
  const shaCamp = new Map<string, string>();
  for (const x of intel.files ?? []) for (const h of x.sha256 ?? []) if (!shaCamp.has(h)) shaCamp.set(h, x.campaign);
  for (const f of ctx.files) {
    const c = f.sha256 ? shaCamp.get(f.sha256) : undefined;
    if (c) push(ctx, { level: 'CRITICAL', module: '§15', campaign: c, path: f.relPath, detail: '既知の悪性ファイル（SHA-256 一致）', ruleId: 's15-intel-files:sha', evidenceSha: f.sha256 });
  }
  for (const x of intel.files ?? []) {
    const names = new Set(x.names ?? []);
    for (const f of ctx.files) {
      if (names.has(f.name)) push(ctx, { level: sev(x.name_severity, 'HIGH'), module: '§15', campaign: x.campaign, path: f.relPath, detail: `既知の悪性ファイル名（${f.name}）`, ruleId: `s15-intel-files:name:${f.name}`, evidenceSha: f.sha256 });
    }
  }

  // §22 侵害されたアクション（bad_refs は CRITICAL、safe_refs 以外のタグ参照は severity）
  const wfFiles = readable(ctx).filter((f) => wf.test(f.relPath));
  for (const a of intel.actions ?? []) {
    const re = new RegExp(`uses:\\s*["']?${escapeRe(a.action)}@([^"'\\s#,}]+)`, 'gi');
    for (const f of wfFiles) {
      for (const ref of new Set([...f.text.matchAll(re)].map((m) => m[1] ?? ''))) {
        if ((a.bad_refs ?? []).includes(ref)) {
          push(ctx, { level: 'CRITICAL', module: '§22', campaign: a.campaign, path: f.relPath, detail: `侵害が報告されたアクション ${a.action}@${ref}`, ruleId: `s22-intel-actions:${a.action}@${ref}`, evidenceSha: f.sha256 });
        } else if ((a.safe_refs ?? []).length && !(a.safe_refs ?? []).includes(ref) && !/^[0-9a-f]{40}$/.test(ref)) {
          push(ctx, { level: sev(a.severity, 'HIGH'), module: '§22', campaign: a.campaign, path: f.relPath, detail: `侵害が報告されたアクション ${a.action} を安全版（${(a.safe_refs ?? []).join(', ')}）以外のタグで参照`, ruleId: `s22-intel-actions:${a.action}@${ref}`, evidenceSha: f.sha256 });
        }
      }
    }
  }

  // §38 CI 設定内の既知の悪性文字列
  for (const w of intel.workflow_strings ?? []) {
    for (const f of wfFiles) {
      if ((w.strings ?? []).some((s) => f.text.includes(s))) push(ctx, { level: sev(w.severity, 'HIGH'), module: '§38', campaign: w.campaign, path: f.relPath, detail: `CI 設定に既知の悪性パターン（${w.campaign}）`, ruleId: `s38-intel-strings:${w.campaign}`, evidenceSha: f.sha256 });
    }
  }

  // §7 / §20 AI 設定・指示ファイル内の既知の文字列（file_regex でパスを絞る）
  for (const s of intel.strings ?? []) {
    const rx = ere(s.file_regex ?? '.');
    if (!rx) continue;
    const strs = (s.strings ?? []).map((x) => x.toLowerCase());
    for (const f of readable(ctx).filter((x) => rx.test('/' + x.relPath))) {
      const low = f.text.toLowerCase();
      if (strs.some((x) => low.includes(x))) push(ctx, { level: sev(s.severity, 'HIGH'), module: s.module, campaign: s.campaign, path: f.relPath, detail: `既知の攻撃キャンペーンの文字列（${s.campaign}）`, ruleId: `s7-intel-strings:${s.campaign}`, evidenceSha: f.sha256 });
    }
  }

  // §42 悪性・侵害された拡張（Chrome: Extensions/<id>/<ver>、VS Code / Open VSX: extensions/<publisher.name>-<ver>）
  for (const x of intel.extensions ?? []) {
    const bads = x.bad_versions ?? [];
    for (const id of x.ids ?? []) {
      const re = x.eco === 'chrome' || x.eco === 'edge'
        ? new RegExp(`(^|/)Extensions/${escapeRe(id)}/([^/]+)/manifest\\.json$`)
        : new RegExp(`(^|/)extensions/${escapeRe(id)}-(\\d[^/]*?)(-[a-z0-9-]+)?/package\\.json$`, 'i');
      for (const f of ctx.files) {
        const m = re.exec(f.relPath);
        if (!m) continue;
        const ver = (m[2] ?? '').split('_')[0] ?? '';
        if (bads.length && !bads.some((b) => versionMatches(ver, b))) continue;
        push(ctx, { level: sev(x.severity, 'HIGH'), module: '§42', campaign: x.campaign, path: f.relPath.slice(0, f.relPath.lastIndexOf('/')), detail: `悪性・侵害が報告された拡張（${id} ${ver}）`, ruleId: `s42-intel-extensions:${id}@${ver}`, evidenceSha: f.sha256 });
      }
    }
  }

  // §30 ホストの痕跡（投入フォルダ内のパス・LaunchAgent Label・systemd ユニット）
  for (const h of intel.host ?? []) {
    const level = sev(h.severity, 'HIGH');
    for (const p of h.paths ?? []) {
      const rel = p.replace(/^~\//, '').replace(/^\//, '');
      for (const f of ctx.files) {
        if (('/' + f.relPath).endsWith('/' + rel)) push(ctx, { level, module: '§30', campaign: h.campaign, path: f.relPath, detail: '既知のマルウェア痕跡パス', ruleId: `s30-intel-host:path:${rel}`, evidenceSha: f.sha256 });
      }
    }
    const labels = new Set(h.launch_labels ?? []);
    for (const f of readable(ctx).filter((x) => /(^|\/)Launch(Agents|Daemons)\/[^/]+\.plist$/.test(x.relPath))) {
      const label = /<key>Label<\/key>\s*<string>([^<]+)<\/string>/.exec(f.text)?.[1];
      if (label && labels.has(label)) push(ctx, { level: 'CRITICAL', module: '§30', campaign: h.campaign, path: f.relPath, detail: `既知のマルウェアの LaunchAgent/Daemon（${label}）`, ruleId: `s30-intel-host:launch:${label}`, evidenceSha: f.sha256 });
    }
    const units = new Set(h.systemd_units ?? []);
    for (const f of ctx.files) {
      if (/(^|\/)systemd\/(user|system)\/[^/]+$/.test(f.relPath) && units.has(basename(f.relPath))) {
        push(ctx, { level: 'CRITICAL', module: '§30', campaign: h.campaign, path: f.relPath, detail: `既知のマルウェアの systemd ユニット（${f.name}）`, ruleId: `s30-intel-host:systemd:${f.name}`, evidenceSha: f.sha256 });
      }
    }
  }
}
