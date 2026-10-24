import { translate, type MsgKey } from '../i18n';
import type { Finding, FindingLocator, FindingRelated, FindingSubject, LocatorFormat, Severity, SkillPactFindingField } from './types';

/** A finding message code: a catalog key f.<code> (i18n/en.json). Codes stay string literals in the rules so the
 *  catalog tests can find them; the CLI uses the same code for the same check (same module, same meaning). */
export type FCode = { [K in MsgKey]: K extends `f.${infer C}` ? C : never }[MsgKey];

/** Restores IoCs defanged in the [.] / hxxp form for matching (in memory only). */
export function refang(s: string): string {
  return s.replace(/\[\.\]/g, '.').replace(/^hxxp/i, 'http');
}

export function basename(p: string): string {
  const i = p.lastIndexOf('/');
  return i < 0 ? p : p.slice(i + 1);
}

export function dirname(p: string): string {
  const i = p.lastIndexOf('/');
  return i < 0 ? '' : p.slice(0, i);
}

export function extname(p: string): string {
  const b = basename(p);
  const i = b.lastIndexOf('.');
  return i <= 0 ? '' : b.slice(i + 1).toLowerCase();
}

const enc = new TextEncoder();

export async function sha256Hex(data: string | ArrayBuffer | Uint8Array): Promise<string> {
  const bytes = typeof data === 'string' ? enc.encode(data) : data instanceof Uint8Array ? data : new Uint8Array(data);
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes as BufferSource);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Numeric segment comparison (-1 / 0 / 1). Same rule as version_cmp of the CLI. */
export function versionCmp(a: string, b: string): number {
  const pa = a.replace(/^v/i, '').split(/[.+_-]/);
  const pb = b.replace(/^v/i, '').split(/[.+_-]/);
  const n = Math.max(pa.length, pb.length);
  for (let i = 0; i < n; i++) {
    const x = pa[i] ?? '0';
    const y = pb[i] ?? '0';
    if (/^\d+$/.test(x) && /^\d+$/.test(y)) {
      const d = Number(x) - Number(y);
      if (d !== 0) return d < 0 ? -1 : 1;
    } else if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  return 0;
}

/** Range evaluation of the forms "1.2.3" / "<X" / "<=X" / ">=A <=B". */
export function versionMatches(v: string, spec: string): boolean {
  return spec.split(/\s+/).filter(Boolean).every((tok) => {
    const m = /^(>=|<=|>|<|=)?(.+)$/.exec(tok);
    if (!m) return false;
    const op = m[1] ?? '=';
    const c = versionCmp(v, m[2] ?? '');
    return op === '=' ? c === 0 : op === '<' ? c < 0 : op === '<=' ? c <= 0 : op === '>' ? c > 0 : c >= 0;
  });
}

/** The value at the start of text (what follows "key =" on its line): a """...""", '''...''', "..." or '...' string without
 *  its quotes (empty when the closing quotes are not on the line), otherwise the bare word up to a blank, "#", a quote or
 *  CR (the CLI's toml_value_head). */
export function tomlValueHead(text: string): string {
  const v = text.replace(/^[ \t]+/, '');
  const q = v.startsWith('"""') || v.startsWith("'''") ? v.slice(0, 3) : v[0] === '"' || v[0] === "'" ? v[0] : '';
  if (q) {
    const end = v.indexOf(q, q.length);
    return end < 0 ? '' : v.slice(q.length, end);
  }
  return /^[^ \t\r#"']*/.exec(v)![0];
}

/** Length limit of config values allowed for display (§13-4). */
export function clip(s: string, max = 120): string {
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

/** Source of a text locator (line number and the content of the line to hash). The content is hashed by makeFinding and never put in the output */
export interface TextLocatorSpec { format: 'text'; line: number; text: string }
export type LocatorSpec = { format: LocatorFormat; pointer: string } | TextLocatorSpec;

export interface FindingSpec {
  level: Severity;
  module: string;
  campaign: string | null;
  path: string | null;
  /** detail = render(en["f." + code], params): always English, like the CLI's findings.json */
  code: FCode;
  /** values of the message's placeholders (never file contents) */
  params?: Record<string, string | number>;
  ruleId: string;
  evidenceSha?: string | null;
  skillpact?: SkillPactFindingField;
  /** findings 1.1 (the same fields as the 6th argument of emit in the CLI) */
  kind?: string;
  subject?: FindingSubject;
  locators?: LocatorSpec[];
  related?: FindingRelated[];
  /** path is a directory (the browser does not know the mode for the tree hash ger-tree-v1, so evidence is detail) */
  directory?: boolean;
}

/** RFC 6901 JSON pointer (~ → ~0, / → ~1). */
export function jsonPointer(keys: (string | number)[]): string {
  return keys.map((k) => '/' + String(k).replace(/~/g, '~0').replace(/\//g, '~1')).join('');
}

/** The lines of text (\n-separated, without a trailing CR and the BOM on line 1; same as remove_line of GER and text_locators of the CLI) that match re (at most 64 lines). */
export function textLocators(text: string, re: RegExp, exclude?: RegExp): TextLocatorSpec[] {
  const out: TextLocatorSpec[] = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length && out.length < 64; i++) {
    let l = lines[i]!;
    if (l.endsWith('\r')) l = l.slice(0, -1);
    if (i === 0 && l.charCodeAt(0) === 0xfeff) l = l.slice(1);
    if (i === lines.length - 1 && l === '' ) continue;
    if (re.test(l) && !(exclude && exclude.test(l))) out.push({ format: 'text', line: i + 1, text: l });
  }
  return out;
}

/** related determined by module and path alone (same as default_related of the CLI). */
export function defaultRelated(module: string, path: string | null): FindingRelated[] {
  if (!path) return [];
  if (module === '§24' || module === '§42') {
    const m = /^(.*\/Extensions\/[^/]+)(\/[^/]+)?\/manifest\.json$/.exec('/' + path);
    if (m) return [{ relation: 'ext_dir', path: m[1]!.slice(1) }];
  }
  if (module === '§49' && /(^|\/)skill\.contract\.json$/.test(path)) return [{ relation: 'skill_dir', path: dirname(path) }];
  return [];
}

/** English detail of a code (findings.json is always English). */
export function findingDetail(code: FCode, params: Record<string, string>): string {
  return translate('en', `f.${code}`, params);
}

/** Escaping of one id v2 component or param value (the CLI's zes_id_esc): \ → \\, | → \|, U+001F → the six characters
 *  \u001f. Without it a "|" or U+001F inside a path or value could make two findings share a preimage. */
export function idEsc(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/\u001f/g, '\\u001f');
}

/** Values in C-locale key order joined by U+001F as key=value, each value escaped (the canon of the CLI's id v2). */
export function idCanon(params: Record<string, string>): string {
  const keys = Object.keys(params).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return keys.map((k) => `${k}=${idEsc(params[k]!)}`).join('\u001f');
}

/** id v2 (the CLI's emit): sha256("zes-id-v2|" module "|" campaign "|" path "|" code "|" canon), every component
 *  escaped with idEsc. The UI path is relative to the dropped folder, so a UI id differs from the CLI id of the same file. */
export async function findingId(module: string, campaign: string | null, path: string | null, code: string, params: Record<string, string>): Promise<string> {
  const c = [module, campaign ?? '', path ?? '', code].map(idEsc);
  return 'sha256:' + (await sha256Hex(`zes-id-v2|${c.join('|')}|${idCanon(params)}`));
}

export async function makeFinding(s: FindingSpec): Promise<Finding> {
  const params: Record<string, string> = {};
  for (const [k, v] of Object.entries(s.params ?? {})) params[k] = String(v);
  const detail = findingDetail(s.code, params);
  const id = await findingId(s.module, s.campaign, s.path, s.code, params);
  const detailSha = await sha256Hex(detail);
  const ev = 'sha256:' + (s.evidenceSha ?? detailSha);
  const f: Finding = { id, level: s.level, module: s.module, campaign: s.campaign, path: s.path, detail, evidence_hash: ev, code: s.code, params, ruleId: s.ruleId, source: 'ui' };
  if (s.kind) f.kind = s.kind;
  if (s.subject) f.subject = { ...s.subject, fixed_versions: [...s.subject.fixed_versions] };
  if (s.locators?.length) {
    const seen = new Set<string>();
    const locs: FindingLocator[] = [];
    for (const l of s.locators) {
      const o: FindingLocator = 'pointer' in l ? { format: l.format, pointer: l.pointer } : { format: 'text', line: l.line, line_sha256: 'sha256:' + (await sha256Hex(l.text)) };
      const k = JSON.stringify(o);
      if (!seen.has(k)) { seen.add(k); locs.push(o); }
    }
    f.locators = locs;
  }
  const rel = s.related ?? defaultRelated(s.module, s.path);
  if (rel.length) f.related = rel.map((r) => ({ ...r }));
  // A regular file (whose content could be read) is file. Directories, no path and unreadable files are detail (the browser does not know the tree mode or
  // the value of a symlink. Symlinks are passed as 0-byte files, so they become file)
  f.evidence = s.evidenceSha && !s.directory ? { kind: 'file', hash: ev } : { kind: 'detail', hash: 'sha256:' + detailSha };
  if (s.skillpact) f.skillpact = s.skillpact;
  return f;
}

/** Separates the inside / outside of code fences (Markdown). */
export function splitMarkdown(text: string): { code: string; prose: string; frontmatter: string; fenceLangs: string[] } {
  const lines = text.split(/\r?\n/);
  let i = 0;
  const fm: string[] = [];
  if (lines[0]?.trim() === '---') {
    i = 1;
    while (i < lines.length && lines[i]?.trim() !== '---') fm.push(lines[i++] ?? '');
    i++;
  }
  const code: string[] = [];
  const prose: string[] = [];
  const langs: string[] = [];
  let infence = false;
  for (; i < lines.length; i++) {
    const l = lines[i] ?? '';
    const m = /^\s*(```|~~~)\s*([^\s{]*)/.exec(l);
    if (m) {
      if (!infence) langs.push((m[2] ?? '').toLowerCase());
      infence = !infence;
      continue;
    }
    (infence ? code : prose).push(l);
  }
  return { code: code.join('\n'), prose: prose.join('\n'), frontmatter: fm.join('\n'), fenceLangs: langs };
}

/** A regular expression equivalent to grep -E (POSIX character classes converted to JS). null if invalid. */
export function ere(pattern: string, flags = ''): RegExp | null {
  const js = pattern
    .replace(/\[\[:space:\]\]/g, '\\s').replace(/\[:space:\]/g, '\\s')
    .replace(/\[\[:alnum:\]\]/g, '[A-Za-z0-9]').replace(/\[:alnum:\]/g, 'A-Za-z0-9');
  try {
    return new RegExp(js, flags);
  } catch {
    return null;
  }
}

/** Parses JSONC (JSON with comments and trailing commas, such as the mcp.json of VS Code). The inside of strings is not changed. Throws if invalid. */
export function parseJsonc(text: string): unknown {
  const s = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (c === '"') {
      let j = i + 1;
      while (j < s.length && s[j] !== '"') j += s[j] === '\\' ? 2 : 1;
      out += s.slice(i, j + 1);
      i = j;
    } else if (c === '/' && s[i + 1] === '/') {
      while (i < s.length && s[i] !== '\n') i++;
      out += '\n';
    } else if (c === '/' && s[i + 1] === '*') {
      const end = s.indexOf('*/', i + 2);
      if (end < 0) throw new SyntaxError('unterminated comment');
      out += ' ';
      i = end + 1;
    } else if (c === ',') {
      // If what follows (ignoring whitespace and comments) is } / ], drop it as a trailing comma
      let j = i + 1;
      for (;;) {
        while (j < s.length && /\s/.test(s[j]!)) j++;
        if (s[j] === '/' && s[j + 1] === '/') { while (j < s.length && s[j] !== '\n') j++; continue; }
        if (s[j] === '/' && s[j + 1] === '*') { const e = s.indexOf('*/', j + 2); if (e < 0) break; j = e + 2; continue; }
        break;
      }
      if (s[j] !== '}' && s[j] !== ']') out += c;
    } else {
      out += c;
    }
  }
  return JSON.parse(out);
}
