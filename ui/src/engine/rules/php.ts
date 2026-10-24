// §4 PHP (PHP2Shell CVE-2026-109618/109619 and dangerous php.ini settings). A port of the part of CLI check_s4 that can be evaluated from loaded files:
//   image tags of containers and .tool-versions versions (upstream fixed-version table), the dpkg package DB (vendor fixed-version table php2shell_distro),
//   Dockerfile FROM php, php*.ini. The installed php version, RHEL guidance and --url header evaluation need the host/network, so they are CLI only.
import { push, readable, type RuleCtx } from '../context';
import type { IocDb } from '../ioc';
import { textLocators, versionCmp } from '../util';

export type PhpStatus = 'fixed' | 'vulnerable' | 'prerelease' | 'unknown_branch' | 'unparsed';

/** Same as CLI php_status: evaluates x.y.z with the upstream fixed-version table (prereleases and branches not in the table are not judged). */
export function phpStatus(ver: string, ioc: IocDb): PhpStatus {
  const m = /^(\d+)\.(\d+)\.(\d+)(.*)$/.exec(ver.replace(/^v/, ''));
  if (!m) return 'unparsed';
  const suf = m[4] ?? '';
  if (/(^|[-+~.])(dev|alpha|beta|rc)/i.test(suf)) return 'prerelease';
  if (suf !== '' && !/^[-+~]/.test(suf)) return 'unparsed';
  const br = `${Number(m[1])}.${Number(m[2])}`;
  const t = ioc.php2shell_distro ?? {};
  if ((t.older_branches ?? []).includes(br)) return 'vulnerable';
  const fx = (t.upstream_fixed ?? []).find((f) => f.split('.').slice(0, 2).join('.') === br)?.split('.')[2];
  if (fx === undefined || fx === '') return 'unknown_branch';
  return Number(m[3]) < Number(fx) ? 'vulnerable' : 'fixed';
}

/** Debian version comparison (epoch:upstream-revision; ~ sorts before anything). Same as CLI deb_version_lt. */
export function debVersionCmp(a: string, b: string): number {
  const ord = (c: string) => (c === '~' ? -1 : /[A-Za-z]/.test(c) ? c.charCodeAt(0) : c.charCodeAt(0) + 256);
  const isd = (c: string | undefined) => c !== undefined && c >= '0' && c <= '9';
  const vrc = (x: string, y: string): number => {
    while (x !== '' || y !== '') {
      while ((x !== '' && !isd(x[0])) || (y !== '' && !isd(y[0]))) {
        const cx = x !== '' && !isd(x[0]) ? ord(x[0]!) : 0;
        const cy = y !== '' && !isd(y[0]) ? ord(y[0]!) : 0;
        if (cx !== cy) return cx < cy ? -1 : 1;
        x = x.slice(1); y = y.slice(1);
      }
      const dx0 = /^[0-9]*/.exec(x)![0]; x = x.slice(dx0.length);
      const dy0 = /^[0-9]*/.exec(y)![0]; y = y.slice(dy0.length);
      const dx = dx0.replace(/^0+/, ''); const dy = dy0.replace(/^0+/, '');
      if (dx.length !== dy.length) return dx.length < dy.length ? -1 : 1;
      if (dx !== dy) return dx < dy ? -1 : 1;
    }
    return 0;
  };
  const split3 = (v: string): [number, string, string] => {
    let epoch = 0;
    const e = /^[0-9]+:/.exec(v);
    if (e) { epoch = Number(e[0].slice(0, -1)); v = v.slice(e[0].length); }
    const k = v.lastIndexOf('-');
    return k >= 0 ? [epoch, v.slice(0, k), v.slice(k + 1)] : [epoch, v, ''];
  };
  const A = split3(a);
  const B = split3(b);
  if (A[0] !== B[0]) return A[0] < B[0] ? -1 : 1;
  return vrc(A[1], B[1]) || vrc(A[2], B[2]);
}

/** Extracts the PHP packages used for serving (php*-fpm / -cgi / -cli, libapache2-mod-php*) from the paragraphs of dpkg status. */
export function dpkgPhpPackages(text: string): { pkg: string; ver: string; src: string }[] {
  const out: { pkg: string; ver: string; src: string }[] = [];
  const paras = text.replace(/\r(?=\n|$)/g, '').split(/\n{2,}/);
  for (const para of paras) {
    let p = ''; let v = ''; let s = ''; let st = '';
    for (const l of para.split('\n')) {
      if (l.startsWith('Package: ')) p = l.slice(9);
      else if (l.startsWith('Version: ')) v = l.slice(9);
      else if (l.startsWith('Source: ')) s = l.slice(8).replace(/ .*/, '');
      else if (l.startsWith('Status: ')) st = l.slice(8);
    }
    if (!/installed$/.test(st) || /not-installed|config-files/.test(st)) continue;
    if (!/^(php[0-9.]*-(fpm|cgi|cli)|libapache2-mod-php[0-9.]*)$/.test(p)) continue;
    if (s === '') s = p.replace(/^libapache2-mod-/, '').replace(/-(fpm|cgi|cli)$/, '');
    out.push({ pkg: p, ver: v, src: s });
  }
  return out;
}

const IMAGE_FILES = /^(docker-compose.*\.ya?ml|compose.*\.ya?ml|Dockerfile.*|.*\.dockerfile|.*\.ya?ml|.*\.tf|.*\.json)$/;

export function phpRules(ctx: RuleCtx): void {
  ctx.checks.add('s4-php2shell').add('s4-php-ini').add('s4-php-image');
  const pfix = (ctx.ioc.infrastructures ?? []).find((i) => i.id === 'php')?.cves.find((c) => c.id === 'CVE-2026-109618')?.fixed ?? [];
  const fixList = pfix.join(' ');
  // The upstream evaluation of CLI php_judge (distro / header are used only for the installed php and --url, so CLI only)
  const judge = (ver: string, path: string, sha: string | null, key: string) => {
    const st = phpStatus(ver, ctx.ioc);
    const mm = /^v?(\d+)\.(\d+)\./.exec(ver);
    const eol = !!mm && versionCmp(`${mm[1]}.${mm[2]}.0`, '8.2.0') < 0;
    const base = { module: '§4', campaign: null, path, ruleId: `s4-php2shell:${key}:${st}:${ver}`, evidenceSha: sha };
    if (st === 'prerelease') push(ctx, { ...base, level: 'MEDIUM', code: 's4.php_prerelease', params: { version: ver } });
    else if (st === 'unknown_branch') push(ctx, { ...base, level: 'MEDIUM', code: 's4.php_unknown_branch', params: { fixed: fixList, version: ver } });
    else if (st === 'unparsed') push(ctx, { ...base, level: 'MEDIUM', code: 's4.php_unparsed', params: { version: ver } });
    else if (st === 'vulnerable') push(ctx, { ...base, level: 'CRITICAL', code: eol ? 's4.php_vulnerable_eol' : 's4.php_vulnerable', params: { fixed: fixList, version: ver } });
  };

  // Container image tags (CLI detect_service_version '(^|[[:space:]/"=])php'; floating tags such as latest are handled by the FROM check)
  for (const f of readable(ctx).filter((x) => IMAGE_FILES.test(x.name))) {
    for (const m of f.text.matchAll(/(^|[\t\v\f\r /"=])php:[A-Za-z0-9._-]+/gm)) {
      const tag = m[0].slice(m[0].lastIndexOf(':') + 1);
      const v = (tag.split('-')[0] ?? '').replace(/^[^0-9]*/, '');
      if (v) judge(v, f.relPath, f.sha256, 'image');
    }
  }
  // .tool-versions of asdf / mise (the leading "php <version>" line)
  for (const f of readable(ctx).filter((x) => x.name === '.tool-versions')) {
    const line = f.text.split(/\r?\n/).find((l) => /^php[\t\v\f\r ]+[0-9]/.test(l));
    const v = line?.split(/[\t\v\f\r ]+/)[1];
    if (v) judge(v, f.relPath, f.sha256, 'tool-versions');
  }
  // Dockerfile FROM php (floating tags are MEDIUM, otherwise reference INFO)
  for (const f of readable(ctx).filter((x) => /^(Dockerfile.*|.*\.dockerfile)$/.test(x.name))) {
    for (const m of f.text.matchAll(/^[\t\v\f\r ]*FROM[\t\v\f\r ]+([^ \n]*\/)?php(:[^ \n]+)?/gim)) {
      const line = m[0].replace(/\r$/, '');
      if (/php:.*latest/.test(line) || line.endsWith('php')) {
        push(ctx, { level: 'MEDIUM', module: '§4', campaign: null, path: f.relPath, code: 's4.php_image_floating', ruleId: 's4-php-image:floating', evidenceSha: f.sha256 });
      } else {
        const img = line.slice(line.lastIndexOf(' ') + 1);
        push(ctx, { level: 'INFO', module: '§4', campaign: null, path: f.relPath, code: 's4.php_image', params: { image: img }, ruleId: `s4-php-image:${img}`, evidenceSha: f.sha256 });
      }
    }
  }
  // php*.ini
  for (const f of readable(ctx).filter((x) => /^php.*\.ini$/.test(x.name))) {
    if (/^[ \t]*auto_prepend_file[ \t]*=[ \t]*[^\t\n\v\f\r ;]/m.test(f.text)) push(ctx, { level: 'HIGH', module: '§4', campaign: null, path: f.relPath, code: 's4.auto_prepend', ruleId: 's4-php-ini:auto_prepend', evidenceSha: f.sha256, locators: textLocators(f.text, /^[ \t]*auto_prepend_file[ \t]*=[ \t]*[^\t\n\v\f\r ;]/) });
    if (/^[ \t]*disable_functions[ \t]*=[ \t]*\r?$/m.test(f.text)) push(ctx, { level: 'MEDIUM', module: '§4', campaign: null, path: f.relPath, code: 's4.disable_functions_empty', ruleId: 's4-php-ini:disable_functions', evidenceSha: f.sha256, locators: textLocators(f.text, /^[ \t]*disable_functions[ \t]*=[ \t]*$/) });
  }
  // The dpkg package DB (vendor fixed-version table; the OS from etc/os-release / usr/lib/os-release in the same root)
  for (const f of readable(ctx).filter((x) => /(^|\/)var\/lib\/dpkg\/status$/.test(x.relPath))) {
    const pkgs = dpkgPhpPackages(f.text);
    if (!pkgs.length) continue;
    const base = f.relPath.slice(0, -'var/lib/dpkg/status'.length);
    const osr = [`${base}etc/os-release`, `${base}usr/lib/os-release`].map((p) => ctx.byPath.get(p)).find((x) => x && x.text !== null);
    let id = ''; let vid = '';
    for (const l of (osr?.text ?? '').split(/\r?\n/)) {
      const kv = /^(ID|VERSION_ID)=([^=]*)/.exec(l);
      if (kv) { const v = (kv[2] ?? '').replace(/^["']|["']$/g, ''); if (kv[1] === 'ID') id = v; else vid = v; }
    }
    for (const { pkg, ver, src } of pkgs) {
      const row = (ctx.ioc.php2shell_distro?.packages ?? []).find((r) => r.vendor === id && r.release === vid && r.source_package === src);
      if (!row) {
        push(ctx, { level: 'MEDIUM', module: '§4', campaign: null, path: f.relPath, code: 's4.dpkg_no_advisory', params: { os: id || 'unknown', os_version: vid, package: pkg, source: src, version: ver }, ruleId: `s4-php2shell:dpkg:${pkg}:${ver}:unknown`, evidenceSha: f.sha256 });
      } else if (debVersionCmp(ver, row.fixed) < 0) {
        push(ctx, { level: 'HIGH', module: '§4', campaign: null, path: f.relPath, code: 's4.dpkg_vulnerable', params: { advisory: row.advisory ?? '', fixed: row.fixed, os: id, os_version: vid, package: pkg, url: row.url ?? '', version: ver }, ruleId: `s4-php2shell:dpkg:${pkg}:${ver}:vulnerable`, evidenceSha: f.sha256 });
      } else {
        push(ctx, { level: 'INFO', module: '§4', campaign: null, path: f.relPath, code: 's4.dpkg_fixed', params: { advisory: row.advisory ?? '', fixed: row.fixed, os: id, os_version: vid, package: pkg, version: ver }, ruleId: `s4-php2shell:dpkg:${pkg}:${ver}:fixed`, evidenceSha: f.sha256 });
      }
    }
  }
}
