// §2 / §15 / §25 / §36 / §41: ファイル名・ハッシュ・package.json・ロックファイル照合
import { atRoot, push, readable, type RuleCtx } from '../context';
import type { IocPackage } from '../ioc';
import { dirname, versionMatches } from '../util';

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

/** yarn.lock（v1: `  version "1.2.3"` / Berry: `  version: 1.2.3`）。見出し行の先頭の指定子から名前を取る。 */
export function yarnLockDeps(text: string): { name: string; version: string }[] {
  const out: { name: string; version: string }[] = [];
  let n = '';
  for (const l of lines(text)) {
    if (/^[^ #].*:$/.test(l)) {
      const first = (l.slice(0, -1).split(/, */)[0] ?? '').replace(/"/g, '');
      n = first.startsWith('@') ? '@' + (first.slice(1).split('@')[0] ?? '') : (first.split('@')[0] ?? '');
      if (n === '__metadata') n = '';
      continue;
    }
    const v = /^ {2}version:? +(.*)$/.exec(l);
    if (v && n) { out.push({ name: n, version: (v[1] ?? '').replace(/"/g, '').trim() }); n = ''; }
  }
  return out;
}

/** pnpm-lock.yaml の "/name@1.2.3:" / "name@1.2.3(peer):" / "'@scope/name@1.2.3':" 形式。 */
export function pnpmLockDeps(text: string): { name: string; version: string }[] {
  const out: { name: string; version: string }[] = [];
  for (const l of lines(text)) {
    if (!/^ {2}['/]?@?[^ @]+@[0-9][^:]*:/.test(l)) continue;
    const s = l.slice(2).replace(/'/g, '').replace(/^\//, '').replace(/:.*$/, '').replace(/\(.*$/, '');
    const at = s.startsWith('@') ? s.indexOf('@', 1) : s.indexOf('@');
    if (at > 0) out.push({ name: s.slice(0, at), version: s.slice(at + 1) });
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

export function collectDeps(ctx: RuleCtx): Dep[] {
  const out: Dep[] = [];
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
      try {
        const j = JSON.parse(noBom(f.text)) as { name?: unknown; version?: unknown };
        if (typeof j.name === 'string' && typeof j.version === 'string' && j.name && j.version) out.push({ eco: 'npm', name: j.name, version: j.version, path: f.relPath, sha: f.sha256 });
      } catch { /* noop */ }
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
      for (const m of lines(f.text).join('\n').matchAll(/^ {4}([A-Za-z0-9._-]+) \(([0-9][^)\s]*)\)$/gm)) {
        if (m[1] && m[2]) out.push({ eco: 'gem', name: m[1], version: m[2], path: f.relPath, sha: f.sha256 });
      }
    } else if (/^(requirements|constraints).*\.txt$/.test(f.name)) {
      for (const line of lines(f.text)) {
        const m = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*===?\s*([^\s;,#]+)/.exec(line);
        if (m?.[1] && m[3]) out.push({ eco: 'pypi', name: normPypi(m[1]), version: m[3], path: f.relPath, sha: f.sha256 });
      }
    } else if (f.name === 'poetry.lock' || f.name === 'uv.lock' || f.name === 'pdm.lock') {
      add('pypi', tomlLockDeps(f.text));
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
  // site-packages の *.dist-info（ディレクトリ名からのみ判定）
  for (const f of ctx.files) {
    const m = /\/([^/]+)-([^/-]+)\.(dist-info|egg-info)\/(METADATA|PKG-INFO)$/.exec('/' + f.relPath);
    if (m?.[1] && m[2]) out.push({ eco: 'pypi', name: normPypi(m[1]), version: m[2], path: dirname(f.relPath), sha: null });
  }
  return out;
}

export function packageRules(ctx: RuleCtx): void {
  ctx.checks.add('s2-install-scripts').add('s15-preinstall').add('s15-lockfile').add('s15-tanstack-git');
  const pre = ctx.ioc.worm_iocs.chaindrop.preinstall;
  for (const f of readable(ctx).filter((x) => x.name === 'package.json')) {
    let j: { scripts?: Record<string, unknown> };
    try { j = JSON.parse(f.text); } catch { continue; }
    const scripts = j.scripts ?? {};
    const hooks = ['preinstall', 'install', 'postinstall'].map((k) => scripts[k]).filter((v): v is string => typeof v === 'string');
    if (hooks.length) {
      if (hooks.some((h) => /(curl|wget|bash|sh -c|base64|eval|node -e|\.mjs|https?:\/\/)/.test(h))) {
        push(ctx, { level: 'HIGH', module: '§2', campaign: null, path: f.relPath, detail: 'install ライフサイクルスクリプトに不審なコマンド', ruleId: 's2-install-scripts', evidenceSha: f.sha256 });
      } else if (!f.relPath.includes('node_modules/')) {
        push(ctx, { level: 'MEDIUM', module: '§2', campaign: null, path: f.relPath, detail: 'install ライフサイクルスクリプトが定義されています（ignore-scripts 推奨）', ruleId: 's2-install-scripts', evidenceSha: f.sha256 });
      }
    }
    if (scripts['preinstall'] === pre) {
      push(ctx, { level: 'CRITICAL', module: '§15', campaign: 'chaindrop-keyv', path: f.relPath, detail: `ChainDrop の preinstall フック（${pre}）`, ruleId: 's15-preinstall', evidenceSha: f.sha256 });
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
  const hit = match === 'any_version' || ((match === 'versions' || match === 'vulnerable_versions') && (p.bad_versions ?? []).some((s) => versionMatches(d.version, s)));
  if (hit && match === 'vulnerable_versions') {
    push(ctx, { level: 'HIGH', module: '§15', campaign: p.campaign, path: d.path, detail: `脆弱なバージョン ${d.name}@${d.version}（${d.eco}、悪性ではなく CVE の影響範囲）${p.safe_version ? `。修正版: ${p.safe_version} 以上` : ''}`, ruleId: `s15-lockfile:${p.campaign}:${d.name}@${d.version}`, evidenceSha: d.sha });
  } else if (hit) {
    push(ctx, { level: 'CRITICAL', module: '§15', campaign: p.campaign, path: d.path, detail: `侵害パッケージ ${d.name}@${d.version} を検出（${d.eco}）${p.safe_version ? `。安全版: ${p.safe_version}` : ''}`, ruleId: `s15-lockfile:${p.campaign}:${d.name}@${d.version}`, evidenceSha: d.sha });
  } else if (match === 'unknown_versions') {
    push(ctx, { level: 'MEDIUM', module: '§15', campaign: p.campaign, path: d.path, detail: `侵害報告のあるパッケージ ${d.name}@${d.version}（侵害版の特定バージョン未定義のため要確認）`, ruleId: `s15-lockfile:${p.campaign}:${d.name}@${d.version}`, evidenceSha: d.sha });
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
