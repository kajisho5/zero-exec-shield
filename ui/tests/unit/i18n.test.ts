// Message catalogs (i18n DESIGN §3.2, §5.1): both languages have the same keys and placeholders, the files keep the
// one-entry-per-line form the CLI will read with awk, and every key is used by the UI (no dead or missing keys).
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { render, translate, textLang } from '../../src/i18n';

const dir = fileURLToPath(new URL('../../../i18n/', import.meta.url));
const raw = { en: readFileSync(join(dir, 'en.json'), 'utf8'), ja: readFileSync(join(dir, 'ja.json'), 'utf8') };
const cat = { en: JSON.parse(raw.en) as Record<string, string>, ja: JSON.parse(raw.ja) as Record<string, string> };
const holes = (s: string) => [...s.matchAll(/\{([a-z_]+)\}/g)].map((m) => m[1]).sort();

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
    const src = fileURLToPath(new URL('../../src/', import.meta.url));
    const walk = (d: string): string[] => readdirSync(d).flatMap((n) => (statSync(join(d, n)).isDirectory() ? walk(join(d, n)) : [join(d, n)]));
    const text = walk(src).filter((f) => /\.(ts|tsx)$/.test(f)).map((f) => readFileSync(f, 'utf8')).join('\n');
    const used = new Set([...text.matchAll(/'(ui\.[a-z0-9_.]+)'/g)].map((m) => m[1]!));
    const keys = new Set(Object.keys(cat.en).filter((k) => k.startsWith('ui.')));
    expect([...used].filter((k) => !keys.has(k))).toEqual([]);
    expect([...keys].filter((k) => !used.has(k))).toEqual([]);
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
