// §4 PHP（PHP2Shell CVE-2026-109618/109619 と php.ini の危険設定）。CLI check_s4 のうち、投入ファイルで判定できる部分の移植:
//   コンテナイメージのタグ・.tool-versions の版（upstream の修正版表）、dpkg のパッケージ DB（ベンダー修正版表 php2shell_distro）、
//   Dockerfile の FROM php、php*.ini。インストール済み php の版・RHEL の案内・--url のヘッダ判定はホスト/通信が必要なため CLI のみ。
import { push, readable, type RuleCtx } from '../context';
import type { IocDb } from '../ioc';
import type { Severity } from '../types';
import { versionCmp } from '../util';

export type PhpStatus = 'fixed' | 'vulnerable' | 'prerelease' | 'unknown_branch' | 'unparsed';

/** CLI php_status と同じ: upstream の修正版表で x.y.z を判定する（プレリリース・表にないブランチは判断しない）。 */
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

/** Debian のバージョン比較（epoch:upstream-revision、~ は何よりも前）。CLI deb_version_lt と同じ。 */
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

/** dpkg status の段落から、配信に使われる PHP パッケージ（php*-fpm / -cgi / -cli、libapache2-mod-php*）を取り出す。 */
export function dpkgPhpPackages(text: string): { pkg: string; ver: string; src: string }[] {
  const out: { pkg: string; ver: string; src: string }[] = [];
  const paras = text.replace(/^﻿/, '').replace(/\r(?=\n|$)/g, '').split(/\n{2,}/);
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
  // CLI php_judge の upstream 判定（distro / header はインストール済み php・--url のみで使うため CLI のみ）
  const judge = (ver: string, path: string, sha: string | null, key: string) => {
    const st = phpStatus(ver, ctx.ioc);
    const mm = /^v?(\d+)\.(\d+)\./.exec(ver);
    const eol = mm && versionCmp(`${mm[1]}.${mm[2]}.0`, '8.2.0') < 0 ? '（8.1 以前は公式の修正リリースなし。サポート版へ移行）' : '';
    let level: Severity | null = null;
    let detail = '';
    if (st === 'prerelease') { level = 'MEDIUM'; detail = `PHP ${ver} はプレリリース版（dev/alpha/beta/RC）。PHP2Shell（CVE-2026-109618/109619）の修正有無を版番号から判断できません（要確認）`; }
    else if (st === 'unknown_branch') { level = 'MEDIUM'; detail = `PHP ${ver} は PHP2Shell の修正版一覧（${fixList}）にないブランチ。修正済みとは判断できません（要確認）`; }
    else if (st === 'unparsed') { level = 'MEDIUM'; detail = `PHP のバージョン表記（${ver}）を解釈できません。PHP2Shell（CVE-2026-109618/109619）の修正状況は不明（要確認）`; }
    else if (st === 'vulnerable') { level = 'CRITICAL'; detail = `PHP ${ver} は PHP2Shell（CVE-2026-109618/109619、認証不要 RCE、悪用試行あり）の影響範囲（修正版: ${fixList}）${eol}`; }
    if (level) push(ctx, { level, module: '§4', campaign: null, path, detail, ruleId: `s4-php2shell:${key}:${st}:${ver}`, evidenceSha: sha });
  };

  // コンテナイメージのタグ（CLI detect_service_version '(^|[[:space:]/"=])php'。latest 等の浮動タグは FROM の検査で扱う）
  for (const f of readable(ctx).filter((x) => IMAGE_FILES.test(x.name))) {
    for (const m of f.text.matchAll(/(^|[\s/"=])php:[A-Za-z0-9._-]+/gm)) {
      const tag = m[0].slice(m[0].lastIndexOf(':') + 1);
      const v = (tag.split('-')[0] ?? '').replace(/^[^0-9]*/, '');
      if (v) judge(v, f.relPath, f.sha256, 'image');
    }
  }
  // asdf / mise の .tool-versions（先頭の "php <版>" 行）
  for (const f of readable(ctx).filter((x) => x.name === '.tool-versions')) {
    const line = f.text.split(/\r?\n/).find((l) => /^php\s+[0-9]/.test(l));
    const v = line?.split(/\s+/)[1];
    if (v) judge(v, f.relPath, f.sha256, 'tool-versions');
  }
  // Dockerfile の FROM php（浮動タグは MEDIUM、それ以外は参考 INFO）
  for (const f of readable(ctx).filter((x) => /^(Dockerfile.*|.*\.dockerfile)$/.test(x.name))) {
    for (const m of f.text.matchAll(/^[ \t]*FROM[ \t]+([^ \n]*\/)?php(:[^ \n]+)?/gim)) {
      const line = m[0].replace(/\r$/, '');
      if (/php:.*latest/.test(line) || line.endsWith('php')) {
        push(ctx, { level: 'MEDIUM', module: '§4', campaign: null, path: f.relPath, detail: 'PHP ベースイメージが浮動タグ（latest/タグなし）', ruleId: 's4-php-image:floating', evidenceSha: f.sha256 });
      } else {
        const img = line.slice(line.lastIndexOf(' ') + 1);
        push(ctx, { level: 'INFO', module: '§4', campaign: null, path: f.relPath, detail: `PHP ベースイメージ: ${img}`, ruleId: `s4-php-image:${img}`, evidenceSha: f.sha256 });
      }
    }
  }
  // php*.ini
  for (const f of readable(ctx).filter((x) => /^php.*\.ini$/.test(x.name))) {
    if (/^[ \t]*auto_prepend_file[ \t]*=[ \t]*[^\s;]/m.test(f.text)) push(ctx, { level: 'HIGH', module: '§4', campaign: null, path: f.relPath, detail: 'php.ini の auto_prepend_file が設定されています（全リクエストで実行）', ruleId: 's4-php-ini:auto_prepend', evidenceSha: f.sha256 });
    if (/^[ \t]*disable_functions[ \t]*=[ \t]*\r?$/m.test(f.text)) push(ctx, { level: 'MEDIUM', module: '§4', campaign: null, path: f.relPath, detail: 'php.ini の disable_functions が空欄', ruleId: 's4-php-ini:disable_functions', evidenceSha: f.sha256 });
  }
  // dpkg のパッケージ DB（ベンダー修正版表。OS は同じルートの etc/os-release / usr/lib/os-release）
  const note = 'パッケージが修正済みでも、稼働中の PHP-FPM / Apache ワーカーが更新後に再起動されたか（配信中のバイナリ）を確認';
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
        push(ctx, { level: 'MEDIUM', module: '§4', campaign: null, path: f.relPath, detail: `${pkg} ${ver}（${id || 'OS 不明'} ${vid}、ソース ${src}）: PHP2Shell（CVE-2026-109618/109619）の対応するベンダー勧告を特定できません。修正状況は不明（ベンダーの勧告で確認）。${note}`, ruleId: `s4-php2shell:dpkg:${pkg}:${ver}:unknown`, evidenceSha: f.sha256 });
      } else if (debVersionCmp(ver, row.fixed) < 0) {
        push(ctx, { level: 'HIGH', module: '§4', campaign: null, path: f.relPath, detail: `${pkg} ${ver}（${id} ${vid}）は PHP2Shell（CVE-2026-109618/109619）のベンダー修正版 ${row.fixed}（${row.advisory ?? ''} ${row.url ?? ''}）未満。潜在的に脆弱。${note}`, ruleId: `s4-php2shell:dpkg:${pkg}:${ver}:vulnerable`, evidenceSha: f.sha256 });
      } else {
        push(ctx, { level: 'INFO', module: '§4', campaign: null, path: f.relPath, detail: `${pkg} ${ver}（${id} ${vid}）は PHP2Shell のベンダー修正版 ${row.fixed}（${row.advisory ?? ''}）以上。${note}`, ruleId: `s4-php2shell:dpkg:${pkg}:${ver}:fixed`, evidenceSha: f.sha256 });
      }
    }
  }
}
