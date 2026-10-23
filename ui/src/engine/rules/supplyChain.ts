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

type Dep = { eco: 'npm' | 'pypi' | 'cargo' | 'packagist' | 'gem' | 'go'; name: string; version: string; path: string; sha: string | null };

function normPypi(n: string): string {
  return n.toLowerCase().replace(/[-_.]+/g, '-'); // PEP 503
}

function collectDeps(ctx: RuleCtx): Dep[] {
  const out: Dep[] = [];
  for (const f of readable(ctx)) {
    if (f.name === 'package-lock.json' || f.name === 'npm-shrinkwrap.json') {
      try {
        const j = JSON.parse(f.text) as { packages?: Record<string, { version?: string; name?: string }> };
        for (const [k, v] of Object.entries(j.packages ?? {})) {
          if (!k.includes('node_modules/') || !v.version) continue;
          out.push({ eco: 'npm', name: v.name ?? k.slice(k.lastIndexOf('node_modules/') + 13), version: v.version, path: f.relPath, sha: f.sha256 });
        }
      } catch { /* 不正な JSON は CLI 側で lockfile_parse_failed として扱う */ }
    } else if (f.name === 'package.json' && /\/node_modules\/(@[^/]+\/)?[^/]+\/package\.json$/.test('/' + f.relPath)) {
      try {
        const j = JSON.parse(f.text) as { name?: string; version?: string };
        if (j.name && j.version) out.push({ eco: 'npm', name: j.name, version: j.version, path: f.relPath, sha: f.sha256 });
      } catch { /* noop */ }
    } else if (f.name === 'Cargo.lock') {
      // [[package]] ブロックの name / version（CLI build_deps と同じ）
      for (const b of f.text.split(/^\[\[package\]\]\s*$/m).slice(1)) {
        const n = /^name\s*=\s*"([^"]+)"/m.exec(b)?.[1];
        const v = /^version\s*=\s*"([^"]+)"/m.exec(b)?.[1];
        if (n && v) out.push({ eco: 'cargo', name: n, version: v, path: f.relPath, sha: f.sha256 });
      }
    } else if (f.name === 'composer.lock') {
      try {
        const j = JSON.parse(f.text) as { packages?: { name?: string; version?: string }[]; 'packages-dev'?: { name?: string; version?: string }[] };
        for (const p of [...(j.packages ?? []), ...(j['packages-dev'] ?? [])]) {
          if (p.name && p.version) out.push({ eco: 'packagist', name: p.name, version: p.version.replace(/^v/, ''), path: f.relPath, sha: f.sha256 });
        }
      } catch { /* noop */ }
    } else if (f.name === 'go.sum') {
      for (const line of f.text.split(/\r?\n/)) {
        const [mod, ver] = line.split(/\s+/);
        if (mod && ver) out.push({ eco: 'go', name: mod, version: ver.replace(/\/go\.mod$/, ''), path: f.relPath, sha: f.sha256 });
      }
    } else if (f.name === 'Gemfile.lock') {
      for (const m of f.text.matchAll(/^ {4}([A-Za-z0-9._-]+) \(([0-9][^)\s]*)\)$/gm)) {
        if (m[1] && m[2]) out.push({ eco: 'gem', name: m[1], version: m[2], path: f.relPath, sha: f.sha256 });
      }
    } else if (/^(requirements|constraints).*\.txt$/.test(f.name)) {
      for (const line of f.text.split(/\r?\n/)) {
        const m = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*===?\s*([^\s;,#]+)/.exec(line);
        if (m?.[1] && m[3]) out.push({ eco: 'pypi', name: normPypi(m[1]), version: m[3], path: f.relPath, sha: f.sha256 });
      }
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
