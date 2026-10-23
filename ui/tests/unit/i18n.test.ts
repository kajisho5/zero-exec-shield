// Message catalogs (i18n DESIGN §3.2, §5.1): both languages have the same keys and placeholders, the files keep the
// one-entry-per-line form the CLI will read with awk, and every key is used by the UI (no dead or missing keys).
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { findingText, render, translate, textLang } from '../../src/i18n';

const dir = fileURLToPath(new URL('../../../i18n/', import.meta.url));
const raw = { en: readFileSync(join(dir, 'en.json'), 'utf8'), ja: readFileSync(join(dir, 'ja.json'), 'utf8') };
const cat = { en: JSON.parse(raw.en) as Record<string, string>, ja: JSON.parse(raw.ja) as Record<string, string> };
const holes = (s: string) => [...s.matchAll(/\{([a-z_]+)\}/g)].map((m) => m[1]).sort();
const srcDir = fileURLToPath(new URL('../../src/', import.meta.url));
const walk = (d: string): string[] => readdirSync(d).sort().flatMap((n) => (statSync(join(d, n)).isDirectory() ? walk(join(d, n)) : [join(d, n)]));
const uiFiles = walk(srcDir).filter((f) => /\.(ts|tsx)$/.test(f));
const uiText = uiFiles.map((f) => readFileSync(f, 'utf8')).join('\n');
/** Japanese (kana, CJK ideographs, full-width forms; the same ranges as tests/run-tests.sh) */
const CJK = /[\u3000-\u30ff\u3400-\u9fff\uff00-\uffef]/;

describe('catalog files', () => {
  it('have the same keys in both languages', () => {
    expect(Object.keys(cat.ja).sort()).toEqual(Object.keys(cat.en).sort());
  });

  it('use the same placeholders for each key', () => {
    for (const k of Object.keys(cat.en)) expect(holes(cat.ja[k]!), k).toEqual(holes(cat.en[k]!));
  });

  for (const lang of ['en', 'ja'] as const) {
    it(`${lang}.json: one entry per line, keys in C-locale order, only \\" and \\\\ escapes`, () => {
      const lines = raw[lang].split('\n');
      expect(lines[0]).toBe('{');
      expect(lines.at(-1)).toBe('');
      expect(lines.at(-2)).toBe('}');
      const body = lines.slice(1, -2);
      const keys = body.map((l, i) => {
        const m = /^"([a-z0-9_.]+)": "((?:[^"\\]|\\["\\])*)"(,?)$/.exec(l);
        expect(m, `line ${i + 2}: ${l}`).not.toBeNull();
        expect(m![3], `line ${i + 2}`).toBe(i === body.length - 1 ? '' : ',');
        return m![1]!;
      });
      expect(keys).toEqual([...keys].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)));
    });

    it(`${lang}.json: no URLs, HTML or control characters`, () => {
      for (const [k, v] of Object.entries(cat[lang])) {
        expect(v, k).not.toMatch(/https?:\/\//);
        expect(v, k).not.toMatch(/<\/?[a-z][a-z0-9]*[\s>/]/i);
        expect(v, k).not.toMatch(/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/);
      }
    });
  }

  it('the English catalog has no Japanese text', () => {
    for (const [k, v] of Object.entries(cat.en)) expect(textLang(v), k).toBeUndefined();
  });

  it('every key is used by the UI, and every key the UI uses exists', () => {
    const used = new Set([...uiText.matchAll(/'(ui\.[a-z0-9_.]+)'/g)].map((m) => m[1]!));
    const keys = new Set(Object.keys(cat.en).filter((k) => k.startsWith('ui.')));
    expect([...used].filter((k) => !keys.has(k))).toEqual([]);
    expect([...keys].filter((k) => !used.has(k))).toEqual([]);
  });

  // Finding codes: the engine writes them as string literals ('s17.npx', 'paste.ioc', ...) and shows t('f.' + code).
  //   An f.* key counts as used when zes-scan.sh or ui/src uses it (tests/run-tests.sh checks the same union)
  it('every f.* key is used by zes-scan.sh or the UI engine, and every code the UI uses exists', () => {
    const ui = new Set([...uiText.matchAll(/'((?:s[0-9]+|intel|paste)\.[a-z0-9_.]*[a-z0-9_])'/g)].map((m) => m[1]!));
    const sh = readFileSync(fileURLToPath(new URL('../../../zes-scan.sh', import.meta.url)), 'utf8').split('\n').filter((l) => !l.trimStart().startsWith('#')).join('\n');
    const cli = new Set([...sh.matchAll(/(?<![\w.$/-])((?:s[0-9]+|intel)\.[a-z0-9_.]*[a-z0-9_])(?!\w)/g)].map((m) => m[1]!));
    const codes = new Set(Object.keys(cat.en).filter((k) => k.startsWith('f.')).map((k) => k.slice(2)));
    expect(ui.size).toBeGreaterThan(150);
    expect([...ui].filter((c) => !codes.has(c))).toEqual([]);
    expect([...codes].filter((c) => !ui.has(c) && !cli.has(c))).toEqual([]);
  });
});

describe('no Japanese in ui/src outside comments', () => {
  // Data exceptions: the tab search aliases (search data, both languages) and the language menu's endonym.
  const allowed = (file: string, line: string, inAliases: boolean) =>
    (file.endsWith('/components/layout/TabSearch.tsx') && inAliases && /^\s+[\w'-]+: '[^']*',$/.test(line))
    || (file.endsWith('/components/layout/LangToggle.tsx') && line.startsWith("const NAME: Record<Lang, string> = { en: 'English', ja: '日本語' };"));
  it('has CJK only in comments and the documented data', () => {
    const bad: string[] = [];
    for (const f of uiFiles) {
      let block = false;
      let aliases = false;
      readFileSync(f, 'utf8').split('\n').forEach((line, i) => {
        if (/^const ALIASES\b/.test(line)) aliases = true;
        else if (aliases && /^};/.test(line)) aliases = false;
        const m = CJK.exec(line);
        const startsBlock = /(^|[\s{(])\/\*/.test(line) && !/\*\//.test(line.slice(line.lastIndexOf('/*')));
        const inComment = block || /^\s*(\/\/|\/?\*)/.test(line) || (m !== null && /(^|\s)\/\/|\/\*/.test(line.slice(0, m.index)));
        if (m && !inComment && !allowed(f, line, aliases)) bad.push(`${f.slice(f.indexOf('/src/'))}:${i + 1}: ${line.trim().slice(0, 80)}`);
        if (block && /\*\//.test(line)) block = false;
        else if (!block && startsBlock) block = true;
      });
    }
    expect(bad).toEqual([]);
  });
});

describe('render', () => {
  it('replaces placeholders in one pass and leaves unknown ones', () => {
    expect(render('{a} and {b}', { a: '{b}', b: 'x' })).toBe('{b} and x');
    expect(render('{a} $& \\ {missing}', { a: '$&' })).toBe('$& $& \\ {missing}');
    expect(render('{n} s', { n: 0 })).toBe('0 s');
  });

  it('translates in both languages', () => {
    expect(translate('en', 'ui.tally.seg', { level: 'HIGH', n: 2 })).toBe('Show 2 HIGH');
    expect(translate('ja', 'ui.tally.seg', { level: 'HIGH', n: 2 })).toBe('HIGH 2 件を表示');
  });
});

describe('findingText', () => {
  it('shows f.<code> in the selected language, and detail as is without a known code', () => {
    const f = { code: 's22.unpinned', params: { ref: 'a/b@v1' }, detail: 'Action not pinned to a commit SHA (a/b@v1)' };
    expect(findingText('en', f)).toBe('Action not pinned to a commit SHA (a/b@v1)');
    expect(findingText('ja', f)).toBe('SHA 固定されていないアクション参照（a/b@v1）');
    expect(findingText('en', { detail: '侵害パッケージ（1.0 の取り込み）' })).toBe('侵害パッケージ（1.0 の取り込み）');
    expect(findingText('ja', { code: 'zz.from_a_newer_cli', params: {}, detail: 'Newer message' })).toBe('Newer message');
  });
});
