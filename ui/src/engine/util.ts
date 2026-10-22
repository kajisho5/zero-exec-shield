import type { Finding, Severity, SkillPactFindingField } from './types';

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

export interface FindingSpec {
  level: Severity;
  module: string;
  campaign: string | null;
  path: string | null;
  detail: string;
  ruleId: string;
  evidenceSha?: string | null;
  skillpact?: SkillPactFindingField;
}

/** id = SHA-256(module|campaign|path|ruleId)。同じ入力なら同じ ID（決定的）。 */
export async function makeFinding(s: FindingSpec): Promise<Finding> {
  const id = 'sha256:' + (await sha256Hex(`${s.module}|${s.campaign ?? ''}|${s.path ?? ''}|${s.ruleId}`));
  const ev = 'sha256:' + (s.evidenceSha ?? (await sha256Hex(s.detail)));
  const f: Finding = { id, level: s.level, module: s.module, campaign: s.campaign, path: s.path, detail: s.detail, evidence_hash: ev, ruleId: s.ruleId, source: 'ui' };
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
