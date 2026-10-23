// CLI（zes-scan.sh）との Layer-1 パリティ。tests/expected/<name>.json（CLI の期待値）と、同じフィクスチャを
// analyzeFiles に渡した結果を「level module path」の集合で比べる。差分は下の ALLOWED に理由付きで列挙したものだけを許す
// （CLI か UI の片方だけを直すと、このテストが落ちる）。
import { readdirSync, readFileSync } from 'node:fs';
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
};

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
    });
  }
});
