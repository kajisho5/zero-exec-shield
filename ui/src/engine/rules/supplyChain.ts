// §2 / §15 / §25 / §36 / §41: ファイル名・ハッシュ・package.json・ロックファイル照合
import { atRoot, push, readable, type RuleCtx } from '../context';
import type { IocPackage } from '../ioc';
import { dirname, parseJsonc, versionMatches } from '../util';

export function filenameRules(ctx: RuleCtx): void {
  ctx.checks.add('s2-malicious-files').add('s15-worm-files').add('s25-binaries').add('s36-pyz').add('s41-gitexe');
  const camp = ctx.ioc.malicious_files_campaign;
  const hashes = ctx.ioc.worm_iocs.chaindrop.hashes.sha256;
  for (const f of ctx.files) {
    const n = f.name;
    if (n === 'cook.pth' || n === 'cook.py') {
      push(ctx, { level: 'CRITICAL', module: '§2', campaign: camp[n] ?? null, path: f.relPath, detail: `悪性フックファイル（${n}）を検出`, ruleId: 's2-malicious-files', evidenceSha: f.sha256 });
    } else if (n === 'sitecustomize.py' || n === 'usercustomize.py') {
      push(ctx, { level: 'HIGH', module: '§2', campaign: camp[n] ?? null, path: f.relPath, detail: `Python 起動時自動実行フック（${n}）`, ruleId: 's2-malicious-files', evidenceSha: f.sha256 });
    } else if (ctx.ioc.malicious_files.includes(n) && /\.m?js$/.test(n)) {
      const known = hashes[n] ?? [];
      if (f.sha256 && known.includes(f.sha256)) {
        push(ctx, { level: 'CRITICAL', module: '§15', campaign: camp[n] ?? null, path: f.relPath, detail: `既知の悪性ハッシュと一致（${n}）`, ruleId: 's15-worm-files', evidenceSha: f.sha256 });
      } else if (n === 'setup.mjs') {
        const pj = ctx.byPath.get(`${dirname(f.relPath)}/package.json`);
        if (pj?.text && /setup\.mjs/.test(pj.text)) {
          push(ctx, { level: 'HIGH', module: '§15', campaign: camp[n] ?? null, path: f.relPath, detail: 'package.json から参照される setup.mjs（ChainDrop 型ドロッパー疑い）', ruleId: 's15-worm-files', evidenceSha: f.sha256 });
        }
      } else {
        push(ctx, { level: 'HIGH', module: '§15', campaign: camp[n] ?? null, path: f.relPath, detail: `ワーム関連ファイル名（${n}）`, ruleId: 's15-worm-files', evidenceSha: f.sha256 });
      }
    }
    if (ctx.ioc.worm_iocs.post_shaihulud.binaries.includes(n)) {
      push(ctx, { level: 'CRITICAL', module: '§25', campaign: 'post-shaihulud', path: f.relPath, detail: `後続ワームのバイナリ名（${n}）`, ruleId: 's25-binaries', evidenceSha: f.sha256 });
    }
    if (n === 'cargo-install' || n === 'cargo-install.exe') {
      push(ctx, { level: 'HIGH', module: '§25', campaign: 'post-shaihulud', path: f.relPath, detail: 'cargo-install を名乗るファイル（偽装）', ruleId: 's25-binaries', evidenceSha: f.sha256 });
    }
    if (n === 'transformers.pyz') {
      push(ctx, { level: 'CRITICAL', module: '§36', campaign: 'hf-supply-chain', path: f.relPath, detail: 'transformers.pyz（正規配布物ではない偽装アーカイブ）', ruleId: 's36-pyz', evidenceSha: f.sha256 });
    }
    if (n.toLowerCase() === 'git.exe' && atRoot(ctx, f)) {
      push(ctx, { level: 'CRITICAL', module: '§41', campaign: null, path: f.relPath, detail: 'リポジトリルートの git.exe（IDE/エージェントが自動実行する未パッチ zero-day）', ruleId: 's41-gitexe', evidenceSha: f.sha256 });
    }
  }
}

/** 標準の .pth の import 行（CLI PTH_SAFE_RE と同じ。行全体で一致したものだけを許可） */
const PTH_SAFE = [
  /^\s*import\s+_virtualenv\s*$/,
  /^import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os\.environ\.get\(var, '(local|stdlib)'\) == 'local'; enabled and __import__\('_distutils_hack'\)\.add_shim\(\); *$/,
  /^\s*import\s+(__editable___[A-Za-z0-9_]+_finder|_editable_impl_[A-Za-z0-9_]+)\s*(;\s*(__editable___[A-Za-z0-9_]+_finder|_editable_impl_[A-Za-z0-9_]+)\.install\([^()]*\)\s*)?$/,
];
const PTH_DANGER = /(^|[^A-Za-z0-9_])(exec|eval|compile|getattr|popen|system|__import__)\s*\(|b64decode|subprocess|urllib|socket|fromhex|marshal|zlib|codecs|pickle|ctypes|requests/;

/** §2 .pth の import 行（Python 起動のたびに exec される。CLI check_s2 と同じ）。標準形以外は MEDIUM、実行・通信を伴うものは HIGH */
export function pthRules(ctx: RuleCtx): void {
  ctx.checks.add('s2-pth');
  for (const f of readable(ctx).filter((x) => x.name.endsWith('.pth'))) {
    const imports = f.text.replace(/^\uFEFF/, '').split(/\r?\n/).filter((l) => /^\s*import\s/.test(l) && !PTH_SAFE.some((r) => r.test(l)));
    if (!imports.length) continue;
    const bad = imports.some((l) => PTH_DANGER.test(l));
    push(ctx, {
      level: bad ? 'HIGH' : 'MEDIUM', module: '§2', campaign: 'litellm-oct2026', path: f.relPath,
      detail: bad ? '.pth ファイルに起動時実行コード（import + exec/eval/system/通信）' : '.pth ファイルに起動時に実行される import 行（標準の virtualenv / editable 形式以外。内容を確認）',
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

/** package-lock v2/v3 の packages と、v1 の入れ子の dependencies（CLI build_deps の jq と同じ）。 */
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

/** "name" / "@scope/name" に続く "@" の位置（無ければ -1）。 */
const nameEnd = (spec: string) => (spec.startsWith('@') ? spec.indexOf('@', 1) : spec.indexOf('@'));

/** yarn の指定子（"name@range"）から実パッケージ名を取る。"alias@npm:real@range" のエイリアスは npm: の後ろの実名。 */
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

/** yarn.lock（v1: `  version "1.2.3"` / Berry: `  version: 1.2.3`）。名前は Berry の resolution、無ければ見出し行の先頭の指定子から取る
 *  （npm: エイリアスは実名に解決する）。 */
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

/** pnpm-lock.yaml のパッケージキー。v6+ の "/name@1.2.3:" / "name@1.2.3(peer):" / "'@scope/name@1.2.3':" と、
 *  v5.x の "/name/1.2.3:" / "/@scope/name/1.2.3_peer@1.0.0:"（"_" 以降は peer 接尾辞）。 */
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

/** poetry.lock / uv.lock / pdm.lock の [[package]] ブロック（name の直後の version）。名前は PEP 503 で正規化。 */
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

/** METADATA / PKG-INFO のヘッダ（最初の空行まで）の Name / Version（CLI pkg_info_name_version と同じ）。 */
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

/** 依存関係インベントリ（CLI build_deps の DEPS_TSV 相当）。1 回のスキャンで 1 度だけ作る。 */
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
      // CLI と同じく名前はパス（最後の node_modules/ 以降）から、版はトップレベルの "version"（無ければ空。any_version 等の照合に使う）
      const name = /.*\/node_modules\/((@[^/]+\/)?[^/]+)\/package\.json$/.exec('/' + f.relPath)?.[1] ?? '';
      let version = '';
      try {
        const j = JSON.parse(noBom(f.text)) as unknown;
        const v = j && typeof j === 'object' && !Array.isArray(j) ? (j as Record<string, unknown>)['version'] : undefined;
        if (typeof v === 'string') version = v.replace(/[\t\r\n]/g, '');
      } catch { parseFailed(f.relPath); }
      out.push({ eco: 'npm', name, version, path: f.relPath, sha: f.sha256 });
    } else if (f.name === 'Cargo.lock') {
      // [[package]] ブロックの name / version（CLI build_deps と同じ）
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
      // プラットフォーム付き（nokogiri (1.16.0-x86_64-linux)）はバージョン部分のみで比較する
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
      // bun.lock（JSONC。"packages": { "<名前>": ["<実名>@<版>", …] }。CLI build_deps と同じく npm エイリアスは実名で照合）
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
      // deno.lock（v3: packages.npm、v4 以降: npm。キーは "<名前>@<版>"、"_" 以降は peer 接尾辞）
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
  // site-packages の *.dist-info / *.egg-info（インストール実体。CLI build_deps と同じ）
  //   Name / Version は METADATA・PKG-INFO のヘッダを正とし、ディレクトリ名（name-1.0-py3.11.egg-info 等）はヘッダが無い場合の代替のみ。
  //   egg-info は単一ファイル（PKG-INFO と同形式）の場合もある
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
    // CLI check_s15 と同じく、package.json のどこか（任意の scripts を含む）に "node setup.mjs" があれば検出（JSON の妥当性に依らない）
    if (pre && f.text.includes(pre)) {
      push(ctx, { level: 'CRITICAL', module: '§15', campaign: 'chaindrop-keyv', path: f.relPath, detail: `ChainDrop の preinstall フック（${pre}）`, ruleId: 's15-preinstall', evidenceSha: f.sha256 });
    }
    // install 系と prepare 系（CLI PKG_HOOK_RE と同じ）。厳密な JSON として読めなければ JSONC（BOM・末尾カンマ）として、
    // それでも駄目なら該当キーの行をそのまま見る（CLI の grep フォールバックと同じ）
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
        push(ctx, { level: 'HIGH', module: '§2', campaign: null, path: f.relPath, detail: 'install / prepare ライフサイクルスクリプトに不審なコマンド', ruleId: 's2-install-scripts', evidenceSha: f.sha256 });
      } else if (!f.relPath.includes('node_modules/')) {
        push(ctx, { level: 'MEDIUM', module: '§2', campaign: null, path: f.relPath, detail: 'install / prepare ライフサイクルスクリプトが定義されています（ignore-scripts 推奨）', ruleId: 's2-install-scripts', evidenceSha: f.sha256 });
      }
    }
  }
  for (const f of readable(ctx).filter((x) => /^(package\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$/.test(x.name))) {
    if (f.text.includes('github:tanstack/router#79ac49ee')) {
      push(ctx, { level: 'CRITICAL', module: '§15', campaign: 'teampcp-mini-shai-hulud', path: f.relPath, detail: 'TanStack の不正 Git 依存（github:tanstack/router#79ac49ee）', ruleId: 's15-tanstack-git', evidenceSha: f.sha256 });
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

function emitPackage(ctx: RuleCtx, p: IocPackage, d: Dep): void {
  const match = p.match ?? 'versions';
  // 版が分からない依存（version なしの node_modules/*/package.json 等）は版指定の IoC に一致させない（CLI と同じ）
  const hit = match === 'any_version' || ((match === 'versions' || match === 'vulnerable_versions') && d.version !== '' && (p.bad_versions ?? []).some((s) => s !== '' && versionMatches(d.version, s)));
  if (hit && match === 'vulnerable_versions') {
    push(ctx, { level: 'HIGH', module: '§15', campaign: p.campaign, path: d.path, detail: `脆弱なバージョン ${d.name}@${d.version || '?'}（${d.eco}、悪性ではなく CVE の影響範囲）${p.safe_version ? `。修正版: ${p.safe_version} 以上` : ''}`, ruleId: `s15-lockfile:${p.campaign}:${d.name}@${d.version}`, evidenceSha: d.sha });
  } else if (hit) {
    push(ctx, { level: 'CRITICAL', module: '§15', campaign: p.campaign, path: d.path, detail: `侵害パッケージ ${d.name}@${d.version || '?'} を検出（${d.eco}）${p.safe_version ? `。安全版: ${p.safe_version}` : ''}`, ruleId: `s15-lockfile:${p.campaign}:${d.name}@${d.version}`, evidenceSha: d.sha });
  } else if (match === 'unknown_versions') {
    push(ctx, { level: 'MEDIUM', module: '§15', campaign: p.campaign, path: d.path, detail: `侵害報告のあるパッケージ ${d.name}@${d.version || '?'}（侵害版の特定バージョン未定義のため要確認）`, ruleId: `s15-lockfile:${p.campaign}:${d.name}@${d.version}`, evidenceSha: d.sha });
  }
}

/** §14 / §19 Blast Radius: シークレット保管場所の存在のみ（内容は読まない・表示しない）。 */
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
