// CLI（zes-scan.sh）との Layer-1 パリティ。tests/expected/<name>.json（CLI の期待値）と、同じフィクスチャを
// analyzeFiles に渡した結果を「level module path」の集合で比べる。差分は下の ALLOWED に理由付きで列挙したものだけを許す
// （CLI か UI の片方だけを直すと、このテストが落ちる）。
// 両方にある「level module path」については、findings 1.1 の項目（kind / subject / locators / related / evidence.kind）の
// 値の集合も比べる。ブラウザが知りえない値の差（ALLOWED_11）だけを、項目ごとに理由付きで許す。
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { analyzeFiles } from '../../src/engine';
import { loadFixture } from './fixtures';

const EXPECTED = fileURLToPath(new URL('../../../tests/expected/', import.meta.url));

/** ブラウザでは同じ結果にできない差分（意図的なもの）。キーは「level module path」（path はフィクスチャ相対、ルートは "."）。 */
const ALLOWED: Record<string, { cliOnly: string[]; uiOnly: string[]; reason: string }> = {
  symjack: {
    cliOnly: ['CRITICAL §17 docs/vid-settings.mp4'],
    uiOnly: ['HIGH §17 docs/vid-settings.mp4'],
    reason: 'ブラウザはシンボリックリンクのリンク先を読めず 0 バイトのファイルとして渡される。CLI はリンク先（エージェント設定）で CRITICAL、UI はデコイ名かつ 0 バイトを要手動確認の HIGH にする',
  },
  'r3-symlink-config': {
    cliOnly: ['HIGH §17 ev/.mcp.json', 'HIGH §7 ev/.vscode/tasks.json'],
    uiOnly: ['MEDIUM §17 ev/.mcp.json'],
    reason: 'ブラウザはシンボリックリンクのリンク先を読めず 0 バイトのファイルとして渡される。CLI はリンク先が検査ルート内の通常ファイルならリンク名でも内容を検査する（.mcp.json → cfg/servers.json、tasks.json → cfg/t.json）。UI は 0 バイトの MCP 設定を解析できないものとして MEDIUM（未判定）にする',
  },
  'r3-skillpact-script': {
    cliOnly: ['HIGH §49 symlinked', 'MEDIUM §49 symlinked'],
    uiOnly: [],
    reason: 'ブラウザはシンボリックリンクのリンク先を読めない。CLI はスキル内のシンボリックリンク（scripts/thumb.py → ../../lib/impl.py）のリンク先を読んで乖離を判定するが、UI では 0 バイトのスクリプトになり効果が見えない',
  },
};

type F11 = { kind?: string; subject?: unknown; locators?: unknown[]; related?: { relation: string; path: string }[]; evidence?: { kind: string } };
const FIELDS = ['kind', 'subject', 'locators', 'related', 'evidence'] as const;
type Field = (typeof FIELDS)[number];

/** findings 1.1 の項目のうち、ブラウザでは CLI と同じ値にできないもの。keys は「level module path」（'*' は全 finding）。 */
const ALLOWED_11: Record<string, { keys: string[]; fields: Field[]; reason: string }[]> = {
  symjack: [{ keys: ['*'], fields: ['evidence'], reason: 'シンボリックリンクは 0 バイトのファイルとして渡される。CLI は symlink（readlink の値のハッシュ）、UI は file' }],
  'r3-symlink-config': [{ keys: ['*'], fields: ['evidence'], reason: 'リンク名で検査した設定（.mcp.json → cfg/servers.json 等）は CLI では symlink、UI では 0 バイトの file' }],
};
/** ディレクトリの finding（CLI は ger-tree-v1 の tree。ブラウザはファイルの mode を知らないためツリーハッシュを作れず detail） */
const DIR_EVIDENCE_REASON = 'ブラウザはファイルの mode を知らないため ger-tree-v1 を計算できない。CLI の tree は UI では detail';

const key = (level: string, module: string, path: string | null) => `${level} ${module} ${path ?? ''}`;

describe('CLI 期待値とのパリティ（tests/expected）', () => {
  const names = readdirSync(EXPECTED).filter((f) => f.endsWith('.json') && !f.startsWith('_')).map((f) => f.slice(0, -5)).sort();
  it('フィクスチャが揃っている', () => {
    expect(names.length).toBeGreaterThan(30);
    for (const n of Object.keys(ALLOWED)) expect(names).toContain(n);
  });
  for (const name of names) {
    it(name, async () => {
      const exp = JSON.parse(readFileSync(EXPECTED + name + '.json', 'utf8')) as { findings: { level: string; module: string; path: string | null }[] };
      const cli = new Set(exp.findings.map((f) => key(f.level, f.module, f.path)));
      const r = await analyzeFiles(loadFixture(name));
      const rel = (p: string | null) => (p === null ? null : p === name ? '.' : p.startsWith(name + '/') ? p.slice(name.length + 1) : p);
      const ui = new Set(r.findings.map((f) => key(f.level, f.module, rel(f.path))));
      const cliOnly = [...cli].filter((k) => !ui.has(k)).sort();
      const uiOnly = [...ui].filter((k) => !cli.has(k)).sort();
      const allowed = ALLOWED[name] ?? { cliOnly: [], uiOnly: [] };
      expect({ cliOnly, uiOnly }).toEqual({ cliOnly: [...allowed.cliOnly].sort(), uiOnly: [...allowed.uiOnly].sort() });

      // findings 1.1 の項目（両方にある key ごとに、値の集合を比べる）
      const exp11 = exp.findings as (typeof exp.findings[number] & F11)[];
      const relPath = (p: string) => rel(p) ?? p;
      const ui11 = r.findings.map((f) => ({ ...f, path: rel(f.path), related: f.related?.map((x) => ({ relation: x.relation, path: relPath(x.path) })), evidence: f.evidence ? { kind: f.evidence.kind } : undefined }));
      const cliDirs = new Set(exp11.filter((f) => f.evidence?.kind === 'tree').map((f) => key(f.level, f.module, f.path)));
      const strip = (k: string): Field[] => {
        const out = new Set<Field>();
        for (const a of ALLOWED_11[name] ?? []) if (a.keys.includes('*') || a.keys.includes(k)) a.fields.forEach((x) => out.add(x));
        if (cliDirs.has(k)) out.add('evidence'); // DIR_EVIDENCE_REASON
        return [...out];
      };
      const view = (f: F11, k: string) => {
        const drop = strip(k);
        const o: Record<string, unknown> = {};
        for (const x of FIELDS) if (!drop.includes(x) && f[x] !== undefined) o[x] = f[x];
        return o;
      };
      const deep = (o: unknown): string => JSON.stringify(o, (_k, v) => (v && typeof v === 'object' && !Array.isArray(v) ? Object.fromEntries(Object.entries(v).sort()) : v));
      const group = (xs: (F11 & { level: string; module: string; path: string | null })[]) => {
        const m = new Map<string, Set<string>>();
        for (const f of xs) {
          const k = key(f.level, f.module, f.path);
          if (!cli.has(k) || !ui.has(k)) continue;
          if (!m.has(k)) m.set(k, new Set());
          m.get(k)!.add(deep(view(f, k)));
        }
        return Object.fromEntries([...m].sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => [k, [...v].sort()]));
      };
      expect(group(ui11)).toEqual(group(exp11));
      expect(DIR_EVIDENCE_REASON).toBeTruthy();
    });
  }
});

// Second layer (i18n DESIGN §5.1): for the findings both sides make (the same "level module path"), the message code,
// its params and the campaign must also match tests/expected-codes/<name>.json (generated from the CLI by
// tests/gen-expected-codes.sh; tests/run-tests.sh checks the CLI still produces them). Path-valued params are relative to
// the fixture on both sides. Differences are allowed only when listed in ALLOWED_CODES with a reason.
const EXPECTED_CODES = fileURLToPath(new URL('../../../tests/expected-codes/', import.meta.url));
type CodeRow = { level: string; module: string; campaign: string | null; path: string | null; code: string; params: Record<string, string> };

/** Params only the CLI can know (absolute host paths, pids, mtime / size of host files) never reach the fixtures'
 *  expected-codes: findings under the shared HOME are left out by tests/expected-codes.jq, and host checks are off. */
const ALLOWED_CODES: Record<string, { cliOnly: string[]; uiOnly: string[]; reason: string }> = {};

/** CLI checks the browser engine does not implement, at a "level module path" the UI reaches through another check.
 *  Their rows are left out of the comparison (a code that is not listed here and not used by the UI fails the test). */
const CLI_ONLY_CODES: Record<string, string> = {
  's16.teamcity_vulnerable': 'The CLI has a dedicated TeamCity check (CVE-2026-63077). The browser judges TeamCity only through the generic infrastructures[] CVEs (intel.infra_vulnerable*), which give the same level, module and path',
  's16.artifactory_vulnerable': 'The CLI has a dedicated Artifactory check (CVE-2026-82329). The browser judges Artifactory only through the generic infrastructures[] CVEs',
  's20.imperative_external': 'The CLI also checks MCP tool descriptions for an imperative verb next to an external resource. The UI engine does not implement this check; the same file gets s20.prompt_injection on both sides',
};
const engineDir = fileURLToPath(new URL('../../src/engine/', import.meta.url));
const engineText = (function walk(d: string): string[] {
  return readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(d, e.name)) : e.name.endsWith('.ts') ? [readFileSync(join(d, e.name), 'utf8')] : []));
})(engineDir).join('\n');
const UI_CODES = new Set([...engineText.matchAll(/'((?:s[0-9]+|intel|paste)\.[a-z0-9_.]*[a-z0-9_])'/g)].map((m) => m[1]!));

describe('CLI expected codes parity (tests/expected-codes)', () => {
  const names = readdirSync(EXPECTED_CODES).filter((f) => f.endsWith('.json')).map((f) => f.slice(0, -5)).sort();
  it('CLI_ONLY_CODES are codes the UI engine does not use', () => {
    expect(Object.keys(CLI_ONLY_CODES).filter((c) => UI_CODES.has(c))).toEqual([]);
  });
  it('has one file per fixture of tests/expected', () => {
    const exp = readdirSync(EXPECTED).filter((f) => f.endsWith('.json') && !f.startsWith('_')).map((f) => f.slice(0, -5)).sort();
    expect(names).toEqual(exp);
  });
  for (const name of names) {
    it(name, async () => {
      const cliRows = (JSON.parse(readFileSync(EXPECTED_CODES + name + '.json', 'utf8')) as CodeRow[]).filter((x) => !(x.code in CLI_ONLY_CODES));
      const r = await analyzeFiles(loadFixture(name));
      const rel = (p: string | null) => (p === null ? null : p === name ? '.' : p.startsWith(name + '/') ? p.slice(name.length + 1) : p);
      const uiRows: CodeRow[] = r.findings.map((f) => ({
        level: f.level, module: f.module, campaign: f.campaign, path: rel(f.path), code: f.code ?? '',
        params: Object.fromEntries(Object.entries(f.params ?? {}).map(([k, v]) => [k, v.startsWith(name + '/') ? v.slice(name.length + 1) : v])),
      }));
      const k1 = (x: CodeRow) => key(x.level, x.module, x.path);
      const both = new Set(cliRows.map(k1).filter((k) => uiRows.some((u) => k1(u) === k)));
      const row = (x: CodeRow) => `${k1(x)} | ${x.campaign ?? '-'} | ${x.code} ${JSON.stringify(Object.fromEntries(Object.entries(x.params).sort()))}`;
      const cliSet = new Set(cliRows.filter((x) => both.has(k1(x))).map(row));
      const uiSet = new Set(uiRows.filter((x) => both.has(k1(x))).map(row));
      const cliOnly = [...cliSet].filter((x) => !uiSet.has(x)).sort();
      const uiOnly = [...uiSet].filter((x) => !cliSet.has(x)).sort();
      const allowed = ALLOWED_CODES[name] ?? { cliOnly: [], uiOnly: [] };
      expect({ cliOnly, uiOnly }).toEqual({ cliOnly: [...allowed.cliOnly].sort(), uiOnly: [...allowed.uiOnly].sort() });
    });
  }
});
