import { translate, type MsgKey } from '../i18n';
import type { Finding, FindingLocator, FindingRelated, FindingSubject, LocatorFormat, Severity, SkillPactFindingField } from './types';

/** A finding message code: a catalog key f.<code> (i18n/en.json). Codes stay string literals in the rules so the
 *  catalog tests can find them; the CLI uses the same code for the same check (same module, same meaning). */
export type FCode = { [K in MsgKey]: K extends `f.${infer C}` ? C : never }[MsgKey];

/** [.] / hxxp 形式で無害化された IoC を照合用に戻す（メモリ内のみ）。 */
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

/** 数値セグメント比較（-1 / 0 / 1）。CLI の version_cmp と同じ規則。 */
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

/** "1.2.3" / "<X" / "<=X" / ">=A <=B" 形式の範囲判定。 */
export function versionMatches(v: string, spec: string): boolean {
  return spec.split(/\s+/).filter(Boolean).every((tok) => {
    const m = /^(>=|<=|>|<|=)?(.+)$/.exec(tok);
    if (!m) return false;
    const op = m[1] ?? '=';
    const c = versionCmp(v, m[2] ?? '');
    return op === '=' ? c === 0 : op === '<' ? c < 0 : op === '<=' ? c <= 0 : op === '>' ? c > 0 : c >= 0;
  });
}

/** 表示を許容した設定値（§13-4）の長さ上限。 */
export function clip(s: string, max = 120): string {
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

/** text locator の元（行番号と、ハッシュを取る行の内容）。内容は makeFinding でハッシュにし、出力には入れない */
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
  /** findings 1.1（CLI の emit の 6 番目の引数と同じ項目） */
  kind?: string;
  subject?: FindingSubject;
  locators?: LocatorSpec[];
  related?: FindingRelated[];
  /** path がディレクトリ（ブラウザはツリーハッシュ ger-tree-v1 の mode を知らないため evidence は detail にする） */
  directory?: boolean;
}

/** RFC 6901 の JSON pointer（~ → ~0、/ → ~1）。 */
export function jsonPointer(keys: (string | number)[]): string {
  return keys.map((k) => '/' + String(k).replace(/~/g, '~0').replace(/\//g, '~1')).join('');
}

/** text の行（\n 区切り。行末の CR と 1 行目の BOM を除く。GER の remove_line・CLI の text_locators と同じ）のうち re に一致するもの（最大 64 行）。 */
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

/** module と path だけで決まる related（CLI の default_related と同じ）。 */
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

/** Values in C-locale key order joined by U+001F as key=value (the canon of the CLI's id v2). */
export function idCanon(params: Record<string, string>): string {
  const keys = Object.keys(params).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return keys.map((k) => `${k}=${params[k]}`).join('\u001f');
}

/** id v2 (the CLI's emit): sha256("zes-id-v2|" module "|" campaign "|" path "|" code "|" canon). The UI path is relative
 *  to the dropped folder, so a UI id differs from the CLI id of the same file. */
export async function findingId(module: string, campaign: string | null, path: string | null, code: string, params: Record<string, string>): Promise<string> {
  return 'sha256:' + (await sha256Hex(`zes-id-v2|${module}|${campaign ?? ''}|${path ?? ''}|${code}|${idCanon(params)}`));
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
  // 通常ファイル（内容を読めた）は file。ディレクトリ・path なし・読めなかったファイルは detail（ブラウザはツリーの mode と
  // シンボリックリンクの値を知らない。シンボリックリンクは 0 バイトのファイルとして渡されるため file になる）
  f.evidence = s.evidenceSha && !s.directory ? { kind: 'file', hash: ev } : { kind: 'detail', hash: 'sha256:' + detailSha };
  if (s.skillpact) f.skillpact = s.skillpact;
  return f;
}

/** コードフェンスの内側 / 外側を分離する（Markdown）。 */
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

/** grep -E 相当の正規表現（POSIX 文字クラスを JS へ変換）。不正なら null。 */
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

/** JSONC（コメント・末尾カンマ付き JSON。VS Code の mcp.json 等）を解析する。文字列の内側は変更しない。不正なら例外。 */
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
      // 直後（空白とコメントを除く）が } / ] なら末尾カンマとして落とす
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
