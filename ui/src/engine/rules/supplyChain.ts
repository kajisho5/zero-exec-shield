// §2 / §15 / §25 / §36 / §41: matching of file names, hashes, package.json and lockfiles
import { atRoot, push, readable, type RuleCtx } from '../context';
import type { IocPackage } from '../ioc';
import { basename, dirname, parseJsonc, versionMatches } from '../util';
import type { FindingRelated } from '../types';

export function filenameRules(ctx: RuleCtx): void {
  ctx.checks.add('s2-malicious-files').add('s15-worm-files').add('s25-binaries').add('s36-pyz').add('s41-gitexe');
  const camp = ctx.ioc.malicious_files_campaign;
  const hashes = ctx.ioc.worm_iocs.chaindrop.hashes.sha256;
  for (const f of ctx.files) {
    const n = f.name;
    if (n === 'cook.pth' || n === 'cook.py') {
      push(ctx, { level: 'CRITICAL', module: '§2', campaign: camp[n] ?? null, path: f.relPath, code: 's2.hook_file', params: { name: n }, ruleId: 's2-malicious-files', evidenceSha: f.sha256 });
    } else if (n === 'sitecustomize.py' || n === 'usercustomize.py') {
      push(ctx, { level: 'HIGH', module: '§2', campaign: camp[n] ?? null, path: f.relPath, code: 's2.startup_hook', params: { name: n }, ruleId: 's2-malicious-files', evidenceSha: f.sha256 });
    } else if (ctx.ioc.malicious_files.includes(n) && /\.m?js$/.test(n)) {
      const known = hashes[n] ?? [];
      if (f.sha256 && known.includes(f.sha256)) {
        push(ctx, { level: 'CRITICAL', module: '§15', campaign: camp[n] ?? null, path: f.relPath, code: 's15.worm_hash', params: { name: n }, ruleId: 's15-worm-files', evidenceSha: f.sha256 });
      } else if (n === 'setup.mjs') {
        const pj = ctx.byPath.get(`${dirname(f.relPath)}/package.json`);
        if (pj?.text && /setup\.mjs/.test(pj.text)) {
          push(ctx, { level: 'HIGH', module: '§15', campaign: camp[n] ?? null, path: f.relPath, code: 's15.worm_setup', ruleId: 's15-worm-files', evidenceSha: f.sha256 });
        }
      } else {
        push(ctx, { level: 'HIGH', module: '§15', campaign: camp[n] ?? null, path: f.relPath, code: 's15.worm_file', params: { name: n }, ruleId: 's15-worm-files', evidenceSha: f.sha256 });
      }
    }
    if (ctx.ioc.worm_iocs.post_shaihulud.binaries.includes(n)) {
      push(ctx, { level: 'CRITICAL', module: '§25', campaign: 'post-shaihulud', path: f.relPath, code: 's25.worm_binary', params: { name: n }, ruleId: 's25-binaries', evidenceSha: f.sha256 });
    }
    if (n === 'cargo-install' || n === 'cargo-install.exe') {
      push(ctx, { level: 'HIGH', module: '§25', campaign: 'post-shaihulud', path: f.relPath, code: 's25.cargo_install_file', ruleId: 's25-binaries', evidenceSha: f.sha256 });
    }
    if (n === 'transformers.pyz') {
      push(ctx, { level: 'CRITICAL', module: '§36', campaign: 'hf-supply-chain', path: f.relPath, code: 's36.transformers_pyz', ruleId: 's36-pyz', evidenceSha: f.sha256 });
    }
    if (n.toLowerCase() === 'git.exe' && atRoot(ctx, f)) {
      push(ctx, { level: 'CRITICAL', module: '§41', campaign: null, path: f.relPath, code: 's41.git_exe', ruleId: 's41-gitexe', evidenceSha: f.sha256 });
    }
  }
}

/** Standard import lines in .pth (same as CLI PTH_SAFE_RE; only those matching the whole line are allowed) */
const PTH_SAFE = [
  /^\s*import\s+_virtualenv\s*$/,
  /^import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os\.environ\.get\(var, '(local|stdlib)'\) == 'local'; enabled and __import__\('_distutils_hack'\)\.add_shim\(\); *$/,
  /^\s*import\s+(__editable___[A-Za-z0-9_]+_finder|_editable_impl_[A-Za-z0-9_]+)\s*(;\s*(__editable___[A-Za-z0-9_]+_finder|_editable_impl_[A-Za-z0-9_]+)\.install\([^()]*\)\s*)?$/,
];
const PTH_DANGER = /(^|[^A-Za-z0-9_])(exec|eval|compile|getattr|popen|system|__import__)\s*\(|b64decode|subprocess|urllib|socket|fromhex|marshal|zlib|codecs|pickle|ctypes|requests/;

/** §2 Import lines in .pth (exec-ed on every Python start; same as CLI check_s2). Non-standard forms are MEDIUM, those involving execution or network access HIGH */
export function pthRules(ctx: RuleCtx): void {
  ctx.checks.add('s2-pth');
  for (const f of readable(ctx).filter((x) => x.name.endsWith('.pth'))) {
    const imports = f.text.replace(/^\uFEFF/, '').split(/\r?\n/).filter((l) => /^\s*import\s/.test(l) && !PTH_SAFE.some((r) => r.test(l)));
    if (!imports.length) continue;
    const bad = imports.some((l) => PTH_DANGER.test(l));
    push(ctx, {
      level: bad ? 'HIGH' : 'MEDIUM', module: '§2', campaign: 'litellm-oct2026', path: f.relPath,
      code: bad ? 's2.pth_exec' : 's2.pth_import',
      ruleId: bad ? 's2-pth:high' : 's2-pth:medium', evidenceSha: f.sha256,
    });
  }
}

export type Dep = { eco: 'npm' | 'pypi' | 'cargo' | 'packagist' | 'gem' | 'go'; name: string; version: string; path: string; sha: string | null };

function normPypi(n: string): string {
  return n.toLowerCase().replace(/[-_.]+/g, '-'); // PEP 503
}

const noBom = (t: string) => (t.charCodeAt(0) === 0xfeff ? t.slice(1) : t);
const lines = (t: string) => noBom(t).split(/\r?\n/);

/** packages of package-lock v2/v3 and the nested dependencies of v1 (same as the jq of CLI build_deps). */
function npmLockDeps(j: unknown, path: string, sha: string | null, out: Dep[]): void {
  const o = j as { packages?: Record<string, { version?: unknown; name?: unknown }> };
  if (o && typeof o.packages === 'object' && o.packages) {
    for (const [k, v] of Object.entries(o.packages)) {
      if (!k.includes('node_modules/') || !v || typeof v.version !== 'string' || !v.version) continue;
      out.push({ eco: 'npm', name: typeof v.name === 'string' ? v.name : k.slice(k.lastIndexOf('node_modules/') + 13), version: v.version, path, sha });
    }
  }
  const walk = (x: unknown): void => {
    if (Array.isArray(x)) { x.forEach(walk); return; }
    if (!x || typeof x !== 'object') return;
    const deps = (x as Record<string, unknown>)['dependencies'];
    if (deps && typeof deps === 'object' && !Array.isArray(deps)) {
      for (const [k, v] of Object.entries(deps as Record<string, unknown>)) {
        const ver = v && typeof v === 'object' ? (v as Record<string, unknown>)['version'] : undefined;
        if (typeof ver === 'string') out.push({ eco: 'npm', name: k, version: ver, path, sha });
      }
    }
    for (const v of Object.values(x as Record<string, unknown>)) walk(v);
  };
  walk(j);
}

/** Position of the "@" that follows "name" / "@scope/name" (-1 if none). */
const nameEnd = (spec: string) => (spec.startsWith('@') ? spec.indexOf('@', 1) : spec.indexOf('@'));

/** Takes the real package name from a yarn specifier ("name@range"). For an "alias@npm:real@range" alias, the real name after npm:. */
function yarnSpecName(spec: string): string {
  const at = nameEnd(spec);
  if (at <= 0) return '';
  const range = spec.slice(at + 1);
  if (range.startsWith('npm:')) {
    const target = range.slice(4);
    const t = nameEnd(target);
    if (t > 0 && /^(@[^/@]+\/[^/@]+|[^@/\s]+)$/.test(target.slice(0, t))) return target.slice(0, t);
  }
  return spec.slice(0, at);
}

/** yarn.lock (v1: `  version "1.2.3"` / Berry: `  version: 1.2.3`). The name is taken from the Berry resolution, otherwise from the first specifier of the header line
 *  (npm: aliases are resolved to the real name). */
export function yarnLockDeps(text: string): { name: string; version: string }[] {
  const out: { name: string; version: string }[] = [];
  let n = '';
  let res = '';
  let ver: string | null = null;
  const flush = () => { const name = res || n; if (name && ver !== null) out.push({ name, version: ver }); n = ''; res = ''; ver = null; };
  for (const l of lines(text)) {
    if (/^[^ #].*:$/.test(l)) {
      flush();
      n = yarnSpecName((l.slice(0, -1).split(/, */)[0] ?? '').replace(/"/g, ''));
      if (n === '__metadata') n = '';
      continue;
    }
    if (!n) continue;
    const v = /^ {2}version:? +(.*)$/.exec(l);
    if (v && ver === null) { ver = (v[1] ?? '').replace(/"/g, '').trim(); continue; }
    const r = /^ {2}resolution:? +"?([^"]*)"?\s*$/.exec(l);
    if (r) { const at = nameEnd(r[1] ?? ''); if (at > 0) res = (r[1] ?? '').slice(0, at); }
  }
  flush();
  return out;
}

/** Package keys of pnpm-lock.yaml. v6+ "/name@1.2.3:" / "name@1.2.3(peer):" / "'@scope/name@1.2.3':" and
 *  v5.x "/name/1.2.3:" / "/@scope/name/1.2.3_peer@1.0.0:" (from "_" on is the peer suffix). */
export function pnpmLockDeps(text: string): { name: string; version: string }[] {
  const out: { name: string; version: string }[] = [];
  for (const l of lines(text)) {
    const k = /^ {2}(['"]?)(\/?[^ '"].*?)\1:(\s.*)?$/.exec(l);
    if (!k?.[2]) continue;
    const s = k[2].replace(/^\//, '');
    const m = /^(@[^/@]+\/[^/@]+|[^/@]+)@([0-9].*)$/.exec(s) ?? /^(@[^/@]+\/[^/@]+|[^/@]+)\/([0-9].*)$/.exec(s);
    if (m?.[1] && m[2]) out.push({ name: m[1], version: m[2].replace(/[_(].*$/, '') });
  }
  return out;
}

/** [[package]] blocks of poetry.lock / uv.lock / pdm.lock (the version right after name). Names are normalized per PEP 503. */
export function tomlLockDeps(text: string): { name: string; version: string }[] {
  const out: { name: string; version: string }[] = [];
  let n = '';
  for (const l of lines(text)) {
    if (/^\[\[package\]\]/.test(l)) { n = ''; continue; }
    const nm = /^name = "([^"]*)"/.exec(l);
    if (nm) { n = normPypi(nm[1] ?? ''); continue; }
    const v = /^version = "([^"]*)"/.exec(l);
    if (v && n) { out.push({ name: n, version: v[1] ?? '' }); n = ''; }
  }
  return out;
}

/** Name / Version from the headers of METADATA / PKG-INFO (up to the first empty line) (same as CLI pkg_info_name_version). */
function pkgInfoNameVersion(text: string): { name: string; version: string } {
  let name = '';
  let version = '';
  for (const l of lines(text)) {
    if (l === '') break;
    if (/^name:/i.test(l) && name === '') name = l.replace(/^[^:]*:[ \t]*/, '').replace(/[ \t]+$/, '');
    if (/^version:/i.test(l) && version === '') version = l.replace(/^[^:]*:[ \t]*/, '').replace(/[ \t]+$/, '');
  }
  return name ? { name, version } : { name: '', version: '' };
}

const depsCache = new WeakMap<RuleCtx, Dep[]>();

/** Dependency inventory (equivalent to DEPS_TSV of CLI build_deps). Built only once per scan. */
export function collectDeps(ctx: RuleCtx): Dep[] {
  const cached = depsCache.get(ctx);
  if (cached) return cached;
  const out: Dep[] = [];
  depsCache.set(ctx, out);
  const parseFailed = (path: string) => ctx.errors.push({ module: '§15', reason: `lockfile_parse_failed:${path}` });
  for (const f of readable(ctx)) {
    const add = (eco: Dep['eco'], xs: { name: string; version: string }[]) => { for (const x of xs) out.push({ eco, name: x.name, version: x.version, path: f.relPath, sha: f.sha256 }); };
    if (f.name === 'package-lock.json' || f.name === 'npm-shrinkwrap.json') {
      try { npmLockDeps(JSON.parse(noBom(f.text)), f.relPath, f.sha256, out); } catch { parseFailed(f.relPath); }
    } else if (f.name === 'yarn.lock') {
      add('npm', yarnLockDeps(f.text));
    } else if (f.name === 'pnpm-lock.yaml') {
      add('npm', pnpmLockDeps(f.text));
    } else if (f.name === 'package.json' && /\/node_modules\/(@[^/]+\/)?[^/]+\/package\.json$/.test('/' + f.relPath)) {
      // As in the CLI, the name comes from the path (after the last node_modules/) and the version from the top-level "version" (empty if none; used for any_version etc.)
      const name = /.*\/node_modules\/((@[^/]+\/)?[^/]+)\/package\.json$/.exec('/' + f.relPath)?.[1] ?? '';
      let version = '';
      try {
        const j = JSON.parse(noBom(f.text)) as unknown;
        const v = j && typeof j === 'object' && !Array.isArray(j) ? (j as Record<string, unknown>)['version'] : undefined;
        if (typeof v === 'string') version = v.replace(/[\t\r\n]/g, '');
      } catch { parseFailed(f.relPath); }
      out.push({ eco: 'npm', name, version, path: f.relPath, sha: f.sha256 });
    } else if (f.name === 'Cargo.lock') {
      // name / version of [[package]] blocks (same as CLI build_deps)
      for (const b of noBom(f.text).split(/^\[\[package\]\]\s*$/m).slice(1)) {
        const n = /^name\s*=\s*"([^"]+)"/m.exec(b)?.[1];
        const v = /^version\s*=\s*"([^"]+)"/m.exec(b)?.[1];
        if (n && v) out.push({ eco: 'cargo', name: n, version: v, path: f.relPath, sha: f.sha256 });
      }
    } else if (f.name === 'composer.lock') {
      try {
        const j = JSON.parse(noBom(f.text)) as { packages?: { name?: unknown; version?: unknown }[]; 'packages-dev'?: { name?: unknown; version?: unknown }[] };
        for (const p of [...(Array.isArray(j.packages) ? j.packages : []), ...(Array.isArray(j['packages-dev']) ? j['packages-dev'] : [])]) {
          if (p && typeof p.name === 'string' && typeof p.version === 'string') out.push({ eco: 'packagist', name: p.name, version: p.version.replace(/^v/, ''), path: f.relPath, sha: f.sha256 });
        }
      } catch { /* noop */ }
    } else if (f.name === 'go.sum') {
      for (const line of lines(f.text)) {
        const [mod, ver] = line.split(/\s+/);
        if (mod && ver) out.push({ eco: 'go', name: mod, version: ver.replace(/\/go\.mod$/, ''), path: f.relPath, sha: f.sha256 });
      }
    } else if (f.name === 'Gemfile.lock') {
      // With a platform suffix (nokogiri (1.16.0-x86_64-linux)), only the version part is compared
      for (const m of lines(f.text).join('\n').matchAll(/^ {4}([A-Za-z0-9._-]+) \(([0-9][^)]*)\)$/gm)) {
        if (m[1] && m[2]) out.push({ eco: 'gem', name: m[1], version: m[2].replace(/-[A-Za-z].*$/, ''), path: f.relPath, sha: f.sha256 });
      }
    } else if (/^(requirements|constraints).*\.txt$/.test(f.name)) {
      for (const line of lines(f.text)) {
        const m = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*===?\s*([^\s;,#]+)/.exec(line);
        if (m?.[1] && m[3]) out.push({ eco: 'pypi', name: normPypi(m[1]), version: m[3], path: f.relPath, sha: f.sha256 });
      }
    } else if (f.name === 'poetry.lock' || f.name === 'uv.lock' || f.name === 'pdm.lock') {
      add('pypi', tomlLockDeps(f.text));
    } else if (f.name === 'bun.lock') {
      // bun.lock (JSONC. "packages": { "<name>": ["<real name>@<version>", …] }. As in CLI build_deps, npm aliases are matched by the real name)
      try {
        const j = parseJsonc(f.text) as { packages?: unknown };
        const pk = j && typeof j === 'object' ? j.packages : undefined;
        if (pk && typeof pk === 'object' && !Array.isArray(pk)) {
          for (const v of Object.values(pk as Record<string, unknown>)) {
            const spec = Array.isArray(v) ? v[0] : undefined;
            const m = typeof spec === 'string' ? /^(@?[^@]+)@(.+)$/.exec(spec) : null;
            if (m?.[1] && m[2]) out.push({ eco: 'npm', name: m[1], version: m[2], path: f.relPath, sha: f.sha256 });
          }
        }
      } catch { parseFailed(f.relPath); }
    } else if (f.name === 'deno.lock') {
      // deno.lock (v3: packages.npm, v4 and later: npm. Keys are "<name>@<version>"; from "_" on is the peer suffix)
      try {
        const j = JSON.parse(noBom(f.text)) as { npm?: unknown; packages?: { npm?: unknown } };
        const secs = [j?.npm, j?.packages && typeof j.packages === 'object' ? j.packages.npm : undefined];
        for (const sec of secs) {
          if (!sec || typeof sec !== 'object' || Array.isArray(sec)) continue;
          for (const k of Object.keys(sec)) {
            const m = /^(@?[^@]+)@([^_]+)/.exec(k);
            if (m?.[1] && m[2]) out.push({ eco: 'npm', name: m[1], version: m[2], path: f.relPath, sha: f.sha256 });
          }
        }
      } catch { parseFailed(f.relPath); }
    } else if (f.name === 'bun.lockb') {
      ctx.errors.push({ module: '§15', reason: `lockfile_unparsed:${f.relPath}` });
    } else if (f.name === 'Pipfile.lock') {
      try {
        const j = JSON.parse(noBom(f.text)) as Record<string, unknown>;
        const sec = (k: string) => (j[k] && typeof j[k] === 'object' && !Array.isArray(j[k]) ? (j[k] as Record<string, unknown>) : {});
        for (const [k, v] of Object.entries({ ...sec('default'), ...sec('develop') })) {
          const ver = v && typeof v === 'object' ? (v as Record<string, unknown>)['version'] : undefined;
          out.push({ eco: 'pypi', name: normPypi(k), version: (typeof ver === 'string' ? ver : '').replace(/^==/, ''), path: f.relPath, sha: f.sha256 });
        }
      } catch { parseFailed(f.relPath); }
    }
  }
  // *.dist-info / *.egg-info in site-packages (what is actually installed; same as CLI build_deps)
  //   Name / Version are taken from the METADATA / PKG-INFO headers; the directory name (name-1.0-py3.11.egg-info etc.) is only a fallback when there is no header.
  //   egg-info may also be a single file (same format as PKG-INFO)
  for (const f of ctx.files) {
    const single = /\.egg-info$/.test(f.relPath);
    if (!single && !/\/[^/]+\.(dist-info|egg-info)\/(METADATA|PKG-INFO)$/.test('/' + f.relPath)) continue;
    const src = single ? f.relPath : dirname(f.relPath);
    let { name, version } = pkgInfoNameVersion(f.text ?? '');
    if (!name) {
      const d = src.slice(src.lastIndexOf('/') + 1).replace(/\.dist-info$/, '').replace(/\.egg-info$/, '').replace(/-py[0-9]+(\.[0-9]+)*(-[^-]+)?$/, '');
      const i = d.lastIndexOf('-');
      [name, version] = i < 0 ? [d, ''] : [d.slice(0, i), d.slice(i + 1)];
    }
    if (name) out.push({ eco: 'pypi', name: normPypi(name), version, path: src, sha: null });
  }
  return out;
}

export function packageRules(ctx: RuleCtx): void {
  ctx.checks.add('s2-install-scripts').add('s15-preinstall').add('s15-lockfile').add('s15-tanstack-git');
  const pre = ctx.ioc.worm_iocs.chaindrop.preinstall;
  for (const f of readable(ctx).filter((x) => x.name === 'package.json')) {
    // As in CLI check_s15, detected if "node setup.mjs" appears anywhere in package.json (including arbitrary scripts), regardless of JSON validity
    if (pre && f.text.includes(pre)) {
      push(ctx, { level: 'CRITICAL', module: '§15', campaign: 'chaindrop-keyv', path: f.relPath, code: 's15.preinstall', params: { hook: pre }, ruleId: 's15-preinstall', evidenceSha: f.sha256 });
    }
    // install-type and prepare-type (same as CLI PKG_HOOK_RE). If it cannot be read as strict JSON, read as JSONC (BOM, trailing comma);
    // if that fails too, look at the lines of the relevant keys as is (same as the grep fallback of the CLI)
    const HOOK = /^(pre|post)?(install|prepare)$/;
    let hooks: string[];
    try {
      const j = parseJsonc(f.text) as { scripts?: unknown };
      const sc = j && typeof j === 'object' && !Array.isArray(j) ? j.scripts ?? {} : {};
      hooks = sc && typeof sc === 'object' && !Array.isArray(sc)
        ? Object.entries(sc as Record<string, unknown>).filter(([k]) => HOOK.test(k)).map(([, v]) => (typeof v === 'string' ? v : JSON.stringify(v)))
        : [];
    } catch {
      hooks = f.text.split(/\r?\n/).filter((l) => /"(pre|post)?(install|prepare)"\s*:/.test(l));
    }
    if (hooks.length) {
      if (hooks.some((h) => /(curl|wget|bash|sh -c|base64|eval|node -e|\.mjs|https?:\/\/)/.test(h))) {
        push(ctx, { level: 'HIGH', module: '§2', campaign: null, path: f.relPath, code: 's2.lifecycle_suspicious', ruleId: 's2-install-scripts', evidenceSha: f.sha256 });
      } else if (!f.relPath.includes('node_modules/')) {
        push(ctx, { level: 'MEDIUM', module: '§2', campaign: null, path: f.relPath, code: 's2.lifecycle_defined', ruleId: 's2-install-scripts', evidenceSha: f.sha256 });
      }
    }
  }
  for (const f of readable(ctx).filter((x) => /^(package\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$/.test(x.name))) {
    if (f.text.includes('github:tanstack/router#79ac49ee')) {
      push(ctx, { level: 'CRITICAL', module: '§15', campaign: 'teampcp-mini-shai-hulud', path: f.relPath, code: 's15.tanstack_git', ruleId: 's15-tanstack-git', evidenceSha: f.sha256 });
    }
  }
  const deps = collectDeps(ctx);
  for (const p of ctx.ioc.packages) {
    if (!['npm', 'pypi', 'cargo', 'packagist', 'gem', 'go'].includes(p.eco)) continue;
    if (!['versions', 'vulnerable_versions', 'any_version', 'unknown_versions'].includes(p.match ?? 'versions')) continue;
    const want = p.eco === 'pypi' ? normPypi(p.name) : p.name;
    for (const d of deps) {
      if (d.eco !== p.eco) continue;
      if (want.endsWith('/*') ? !d.name.startsWith(want.slice(0, -1)) : d.name !== want) continue;
      emitPackage(ctx, p, d);
    }
  }
}

/** Same as pkg_kind of the CLI: what is actually installed is pkg.compromised; lockfiles and dependency declarations are pkg.lockfile_compromised */
function pkgKind(path: string): string {
  return /\/node_modules\/.+\/package\.json$/.test('/' + path) || /\.(dist-info|egg-info)$/.test(path) ? 'pkg.compromised' : 'pkg.lockfile_compromised';
}

/** Same as pkg_related of the CLI: what is installed next to an npm lockfile, <dir>/node_modules/<name> */
function pkgRelated(ctx: RuleCtx, eco: string, name: string, src: string): FindingRelated[] | undefined {
  if (eco !== 'npm' || !/^(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lock)$/.test(basename(src))) return undefined;
  if (!name || name.startsWith('.') || name.includes('..') || name.split('/').length > 2 || (name.includes('/') && !name.startsWith('@'))) return undefined;
  const d = dirname(src);
  const t = (d ? d + '/' : '') + 'node_modules/' + name;
  return ctx.files.some((f) => f.relPath.startsWith(t + '/')) ? [{ relation: 'npm_installed', path: t }] : undefined;
}

function emitPackage(ctx: RuleCtx, p: IocPackage, d: Dep): void {
  const match = p.match ?? 'versions';
  const safe = p.safe_version || null;
  const x = match === 'vulnerable_versions'
    ? { kind: 'pkg.vulnerable', subject: { ecosystem: d.eco, package: d.name, version: d.version || null, safe_version: safe, fixed_versions: safe ? [safe] : [] } }
    : { kind: pkgKind(d.path), subject: { ecosystem: d.eco, package: d.name, version: d.version || null, safe_version: safe, fixed_versions: [] } };
  const related = pkgRelated(ctx, d.eco, d.name, d.path);
  const base = { ...x, ...(related ? { related } : {}), directory: /\.(dist-info|egg-info)$/.test(d.path) && !ctx.byPath.has(d.path) };
  const pk = { ecosystem: d.eco, package: d.name, version: d.version || '?' };
  // Dependencies with an unknown version (node_modules/*/package.json without version etc.) never match version-specific IoCs (same as the CLI)
  const hit = match === 'any_version' || ((match === 'versions' || match === 'vulnerable_versions') && d.version !== '' && (p.bad_versions ?? []).some((s) => s !== '' && versionMatches(d.version, s)));
  if (hit && match === 'vulnerable_versions') {
    push(ctx, { level: 'HIGH', module: '§15', campaign: p.campaign, path: d.path, ...(p.safe_version ? { code: 's15.pkg_vulnerable_fixed', params: { ...pk, fixed_version: p.safe_version } } : { code: 's15.pkg_vulnerable', params: pk }), ruleId: `s15-lockfile:${p.campaign}:${d.name}@${d.version}`, evidenceSha: d.sha, ...base });
  } else if (hit) {
    push(ctx, { level: 'CRITICAL', module: '§15', campaign: p.campaign, path: d.path, ...(p.safe_version ? { code: 's15.pkg_compromised_safe', params: { ...pk, safe_version: p.safe_version } } : { code: 's15.pkg_compromised', params: pk }), ruleId: `s15-lockfile:${p.campaign}:${d.name}@${d.version}`, evidenceSha: d.sha, ...base });
  } else if (match === 'unknown_versions') {
    push(ctx, { level: 'MEDIUM', module: '§15', campaign: p.campaign, path: d.path, code: 's15.pkg_reported', params: { package: d.name, version: d.version || '?' }, ruleId: `s15-lockfile:${p.campaign}:${d.name}@${d.version}`, evidenceSha: d.sha, ...base });
  }
}

/** §14 / §19 Blast Radius: only the existence of secret stores (content are never read or displayed). */
const BLAST: [RegExp, string][] = [
  [/(^|\/)\.ssh\/[^/]+$/, 'ssh'], [/(^|\/)(id_rsa|id_dsa|id_ecdsa|id_ed25519)$/, 'private-key'],
  [/(^|\/)\.aws\/(credentials|config)$/, 'aws'], [/(^|\/)\.config\/gcloud\//, 'gcloud'],
  [/(^|\/)\.claude\/[^/]*(credentials|\.json)$/, 'claude'], [/(^|\/)\.cursor\/[^/]*\.json$/, 'cursor'],
  [/(^|\/)\.config\/gh\/hosts\.yml$/, 'gh'], [/(^|\/)\.docker\/config\.json$/, 'docker'],
  [/(^|\/)\.npmrc$/, 'npmrc'], [/(^|\/)\.pypirc$/, 'pypirc'], [/(^|\/)\.kube\/config$/, 'kube'],
  [/(^|\/)\.vault-token$/, 'vault'], [/(^|\/)\.git-credentials$/, 'git-credentials'], [/(^|\/)\.netrc$/, 'netrc'],
  [/(^|\/)\.config\/heroku\//, 'heroku'], [/(^|\/)\.terraform\.d\/credentials\.tfrc\.json$/, 'terraform'],
  [/(^|\/)\.config\/op\//, 'op'], [/(^|\/)\.env(\.[A-Za-z0-9_-]+)?$/, 'env'], [/\.(pem|key|p12|pfx)$/, 'private-key'],
];

export function blastRadius(ctx: RuleCtx): void {
  for (const f of ctx.files) {
    if (/\.env\.(example|sample|template|dist)$/.test(f.relPath)) continue;
    const hit = BLAST.find(([re]) => re.test(f.relPath));
    if (hit) ctx.blast.push({ path: f.relPath, kind: hit[1], size: f.size });
  }
}
