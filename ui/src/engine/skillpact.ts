// §49 SkillPact 契約（実験的）— CLI check_skillpact と同じ規則をブラウザで再現する。
// AI エージェントのスキルが「宣言した権限」（skill.contract.json、SkillPact 0.8 形式
// https://github.com/kajisho5/skillpact）と「コードが実際にしていること」（静的解析）が一致するかを確かめる。
// - 契約・ポリシーは JSON として読むのみ。スキル本体・テストは実行しない。署名は検証しない（signed = 署名欄あり・未検証）
// - level は自己申告を使わず、ZES の部分検査に合格した場合のみ 'L1'。L2/L3 は ZES では判定しない（L3 でも安全を意味しない）
// - 契約のないスキルは比較対象外（影響の大きい効果が見える場合のみ参考 INFO）。契約付きスキル配下の SKILL.md は報告しない
import { push, type RuleCtx } from './context';
import type { DiffAnomaly, Effect, FileInput, RuleResult, Severity, SkillPactAnalysis, SkillPactDivergence, SkillPactFindingField } from './types';
import { SEVERITY_RANK } from './types';
import { basename, dirname, ere } from './util';

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => !!v && typeof v === 'object' && !Array.isArray(v);
const isStr = (v: unknown): v is string => typeof v === 'string';
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const strs = (v: unknown): string[] => arr(v).filter(isStr);
const HIGH_EFFECTS: Effect[] = ['exec', 'network', 'spend', 'send'];
const CONTRACT = 'skill.contract.json';

// ---------------------------------------------------------------- I-JSON（spec §4.1）
/** 重複キー・深さ 64 超・±(2^53−1) 外の数値・孤立サロゲート・不正 UTF-8（U+FFFD）を検出する。問題なければ null。 */
export function ijsonProblem(text: string): string | null {
  const s = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  let value: unknown;
  try {
    value = JSON.parse(s);
  } catch {
    return 'not valid JSON (or lone surrogate)';
  }
  if (!isObj(value)) return 'top-level value is not an object';
  let i = 0;
  let problem: string | null = null;
  const ws = () => { while (i < s.length && ' \t\r\n'.includes(s[i]!)) i++; };
  const str = (): string => {
    let out = '';
    i++; // "
    while (i < s.length && s[i] !== '"') {
      if (s[i] === '\\') {
        const c = s[i + 1];
        if (c === 'u') { out += String.fromCharCode(parseInt(s.slice(i + 2, i + 6), 16)); i += 6; continue; }
        out += c === 'n' ? '\n' : c === 't' ? '\t' : c === 'r' ? '\r' : c === 'b' ? '\b' : c === 'f' ? '\f' : c;
        i += 2;
      } else out += s[i++];
    }
    i++;
    if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]|�/.test(out)) problem ??= 'invalid UTF-8 or lone surrogate';
    return out;
  };
  const val = (depth: number): void => {
    if (depth > 64) { problem ??= 'nesting deeper than 64'; }
    ws();
    const c = s[i];
    if (c === '{') {
      i++; ws();
      const seen = new Set<string>();
      if (s[i] === '}') { i++; return; }
      for (;;) {
        ws();
        const k = str();
        if (seen.has(k)) problem ??= 'duplicate member name';
        seen.add(k);
        ws(); i++; // :
        val(depth + 1);
        ws();
        if (s[i] === ',') { i++; continue; }
        i++; return;
      }
    } else if (c === '[') {
      i++; ws();
      if (s[i] === ']') { i++; return; }
      for (;;) {
        val(depth + 1); ws();
        if (s[i] === ',') { i++; continue; }
        i++; return;
      }
    } else if (c === '"') {
      str();
    } else {
      const m = /^-?\d+(\.\d+)?([eE][+-]?\d+)?|^(true|false|null)/.exec(s.slice(i, i + 400));
      const tok = m?.[0] ?? '';
      i += tok.length || 1;
      if (/^-?\d/.test(tok)) {
        const n = Number(tok);
        if (!Number.isFinite(n) || Math.abs(n) > Number.MAX_SAFE_INTEGER) problem ??= 'number outside ±(2^53-1)';
      }
    }
  };
  val(1);
  return problem;
}

// ---------------------------------------------------------------- globs（spec §6.1。参照実装 core._glob_re と同じ）
const reEsc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
export function globRe(p: string): RegExp {
  const parts = p.split('/');
  let out = '';
  let glue = false;
  parts.forEach((seg, i) => {
    const sep = i === 0 || glue ? '' : '/';
    glue = false;
    if (seg === '**') {
      if (i === parts.length - 1) out += i ? '(?:/.*)?' : '.*';
      else { out += sep + '(?:[^/]+/)*'; glue = true; }
      return;
    }
    out += sep + [...seg.replace(/\*+/g, '*')].map((ch) => (ch === '*' ? '[^/]*' : ch === '?' ? '[^/]' : reEsc(ch))).join('');
  });
  return new RegExp(`^${out}$`, 's');
}
const gmatch = (s: string, p: string) => globRe(p).test(s);
function hostMatch(h0: string, p0: string): boolean {
  if (p0 === '@local') return h0 === '@local';
  const h = h0.toLowerCase().replace(/\.$/, '');
  const p = p0.toLowerCase().replace(/\.$/, '');
  if (p === '*') return true;
  const hl = h.split('.');
  const pl = p.split('.');
  const lab = (a: string, q: string) => new RegExp(`^${[...q].map((ch) => (ch === '*' ? '[^.]*' : ch === '?' ? '.' : reEsc(ch))).join('')}$`, 's').test(a);
  if ((pl[0] === '*' || pl[0] === '**') && pl.length > 1) {
    const rest = pl.slice(1);
    if (hl.length < rest.length + (pl[0] === '*' ? 1 : 0)) return false;
    return rest.every((q, i) => lab(hl[hl.length - rest.length + i]!, q));
  }
  return hl.length === pl.length && hl.every((a, i) => lab(a, pl[i]!));
}
const literal = (s: string) => s.split('/').map((seg) => (seg === '**' ? '\u0002/\u0002' : seg.replace(/\*/g, '\u0001*\u0001'))).join('/');
const kindOf = (e: string) => (e === 'read' || e === 'write' ? 'path' : e === 'network' ? 'host' : 'generic');
export const traversal = (sc: string) => sc.includes('\\') || (sc.startsWith('/') ? sc.slice(1) : sc).split('/').some((x) => x === '' || x === '.' || x === '..');
function covered(scope: string[], pats: string[], kind: string): boolean {
  if (!scope.length) return false;
  if (kind === 'path' && scope.some(traversal)) return false;
  return scope.every((s) => pats.some((p) => s === p || (kind === 'host' ? hostMatch(s, p) : gmatch(literal(s), p))));
}
const ipathBad = (rel: string) => rel === '' || new TextEncoder().encode(rel).length > 1024 || rel.startsWith('/') || /^[A-Za-z]:/.test(rel)
  || rel.includes('\\') || [...rel].some((c) => c.charCodeAt(0) < 32) || rel.split('/').length > 32 || rel.split('/').some((x) => x === '' || x === '.' || x === '..');
const truthy = (v: unknown) => v != null && v !== false && v !== '' && v !== 0 && !(Array.isArray(v) && !v.length) && !(isObj(v) && !Object.keys(v).length);

function semv(v: unknown): number[] | null {
  if (!isStr(v)) return null;
  const m = /^(\d+)\.(\d+)\.(\d+)(-[^+]*)?/.exec(v);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3]), m[4] ? 0 : 1] : null;
}
const cmpv = (a: number[], b: number[]) => { for (let i = 0; i < 4; i++) if (a[i] !== b[i]) return a[i]! < b[i]! ? -1 : 1; return 0; };
const rank = (l: unknown) => (l === 'any' ? 2 : l === 'scoped' ? 1 : 0);

function authors(c: Obj): string[] {
  const sigs = arr(isObj(c['integrity']) ? (c['integrity'] as Obj)['signatures'] : undefined);
  const out = sigs.filter(isObj).filter((s) => (s['role'] ?? 'author') === 'author')
    .map((s) => (s['type'] === 'sigstore' ? `${s['instance'] === 'staging' ? 'sigstore-staging' : 'sigstore'}:${String(s['issuer'])}|${String(s['identity'])}` : s['key']))
    .filter(isStr);
  return [...new Set(out)].sort();
}
const lvl = (c: Obj, e: string): string => {
  const p = isObj(c['permissions']) ? (c['permissions'] as Obj)[e] : undefined;
  const l = isObj(p) ? p['level'] : undefined;
  return isStr(l) ? l : 'none';
};
const scopes = (c: Obj, e: string): string[] => {
  const p = isObj(c['permissions']) ? (c['permissions'] as Obj)[e] : undefined;
  return isObj(p) ? strs(p['scope']) : [];
};

// ---------------------------------------------------------------- 契約の部分検査（CLI SP_ANALYZE と同じ）
interface Analysis {
  vstatus: 'ok' | 'unsupported'; cv: string | null; name: string | null; sver: string | null; errors: string[]; permsOk: boolean;
  declared: Effect[]; signed: boolean; authors: string[]; signers: string[]; level: string | null; divergence: Omit<SkillPactDivergence, 'level'>[];
}
interface Observed { exec: boolean; network: boolean; write: boolean; spend: boolean; send: boolean; read: boolean; durable: boolean }

function analyze(c: Obj, R: RuleCtx['ioc']['skillpact'], files: string[], hashes: Map<string, string | null>, fm: string, obs: Observed): Analysis {
  const EFF = R.effects;
  const cvRaw = c['contract_version'];
  const vs = isStr(cvRaw) && R.contract_versions.includes(cvRaw) ? 'ok' : 'unsupported';
  const v08 = isStr(cvRaw) && /^\d+\.\d+$/.test(cvRaw) && cmpv([...cvRaw.split('.').map(Number), 0, 0], [0, 8, 0, 0]) >= 0;
  const schema = new Set<string>();
  const S = () => schema.add('SCHEMA');
  const keys = Object.keys(c);
  if (keys.some((k) => !R.contract_keys.includes(k))) S();
  if (['contract_version', 'skill', 'permissions', 'capabilities'].some((k) => !(k in c))) S();
  if ('kind' in c && !['tool', 'instructions'].includes(c['kind'] as string)) S();
  if ('$schema' in c && !isStr(c['$schema'])) S();
  if ('x' in c && (!isObj(c['x']) || Object.keys(c['x']).some((k) => !/^[a-z0-9][a-z0-9-]*$/.test(k)))) S();
  const sk = c['skill'];
  if (!isObj(sk) || Object.keys(sk).some((k) => !['name', 'version', 'license', 'homepage', 'source', 'authors', 'native_contract'].includes(k))
    || !(isStr(sk['name']) && /^[a-z0-9]+(-[a-z0-9]+)*$/.test(sk['name']) && sk['name'].length <= 64)
    || !(isStr(sk['version']) && /^\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$/.test(sk['version']))) S();
  const P = c['permissions'];
  if (!isObj(P) || JSON.stringify(Object.keys(P).sort()) !== JSON.stringify([...EFF].sort())) S();
  else for (const v of Object.values(P)) {
    if (!isObj(v) || Object.keys(v).some((k) => !['level', 'scope', 'why', 'confirm'].includes(k)) || !['none', 'scoped', 'any'].includes(v['level'] as string)
      || ('scope' in v && (!Array.isArray(v['scope']) || v['scope'].some((x) => !isStr(x)))) || ('confirm' in v && !['never', 'each', 'session'].includes(v['confirm'] as string))) S();
  }
  const caps = c['capabilities'];
  if (!Array.isArray(caps)) S();
  else for (const cap of caps) {
    if (!isObj(cap) || Object.keys(cap).some((k) => !R.capability_keys.includes(k))) { S(); continue; }
    if (!isStr(cap['id']) || !isStr(cap['summary']) || !Array.isArray(cap['effects'])) { S(); continue; }
    const ef = cap['effects'] as unknown[];
    if (!ef.every((e) => EFF.includes(e as Effect)) || new Set(ef).size !== ef.length) { S(); continue; }
    const ce = cap['conditional_effects'] ?? [];
    if (!Array.isArray(ce) || ce.some((x) => !isObj(x) || !EFF.includes(x['effect'] as Effect))) { S(); continue; }
    const es = cap['effect_scopes'] ?? {};
    if (!isObj(es) || Object.keys(es).some((k) => !EFF.includes(k as Effect)) || Object.values(es).some((v) => !Array.isArray(v) || v.some((x) => !isStr(x)))) S();
  }
  if ('integrity' in c) {
    const I = c['integrity'];
    if (!isObj(I) || Object.keys(I).some((k) => !['algorithm', 'canonicalization', 'exclude', 'files', 'signatures'].includes(k))) S();
    else if ('algorithm' in I && I['algorithm'] !== 'sha256') S();
    else if (!isObj(I['files'] ?? {}) || Object.values((I['files'] ?? {}) as Obj).some((h) => !isStr(h) || !/^[0-9a-f]{64}$/.test(h))) S();
    else if (!Array.isArray(I['exclude'] ?? []) || arr(I['exclude']).some((x) => !isStr(x) || !x.length)) S();
    else if (!Array.isArray(I['signatures'] ?? []) || arr(I['signatures']).some((x) => !isObj(x) || !['ed25519', 'sigstore'].includes(x['type'] as string) || ('role' in x && !['author', 'reviewer', 'scanner'].includes(x['role'] as string)))) S();
  }
  if ('tests' in c) {
    const T = c['tests'];
    if (!isObj(T) || Object.keys(T).some((k) => !['setup', 'cases'].includes(k))) S();
    else if (!Array.isArray(T['cases'] ?? []) || arr(T['cases']).some((x) => !isObj(x) || !('id' in x && 'run' in x && 'expect' in x))) S();
  }

  const cross = new Set<string>();
  if (vs === 'ok' && !schema.size) {
    try {
      const capsA = caps as Obj[];
      const perms = P as Record<string, Obj>;
      const ids = capsA.map((x) => x['id'] as string);
      if (new Set(ids).size !== ids.length) cross.add('DUP_CAPABILITY');
      for (const cap of capsA) {
        for (const e of [...(cap['effects'] as string[]), ...arr(cap['conditional_effects']).map((x) => (x as Obj)['effect'] as string)]) if (lvl(c, e) === 'none') cross.add('UNDECLARED_EFFECT');
      }
      for (const e of EFF) if (perms[e]!['level'] === 'scoped' && !strs(perms[e]!['scope']).length) cross.add('SCOPE_EMPTY');
      for (const e of ['read', 'write']) if (scopes(c, e).some(traversal)) cross.add('SCOPE_TRAVERSAL');
      const rn = [...arr((c['requirements'] as Obj | undefined)?.['binaries']), ...arr((c['requirements'] as Obj | undefined)?.['runtimes'])].map((b) => (b as Obj)['name']);
      const fk = arr((c['requirements'] as Obj | undefined)?.['binaries']).flatMap((b) => Object.keys(((b as Obj)['features_check'] ?? {}) as Obj));
      const cliTokens = (cap: Obj) => strs(isObj(cap['entry']) ? (cap['entry'] as Obj)['cli'] : undefined);
      for (const cap of capsA) {
        for (const [e, v] of Object.entries((cap['effect_scopes'] ?? {}) as Record<string, string[]>)) {
          if ((e === 'read' || e === 'write') && v.some(traversal)) cross.add('SCOPE_TRAVERSAL');
          if (lvl(c, e) === 'scoped' && !covered(v, scopes(c, e), kindOf(e))) cross.add('SCOPE_WIDENED');
        }
        for (const q of arr(cap['requires'])) if (!rn.includes(q)) cross.add('UNKNOWN_REQUIREMENT');
        for (const f of strs(cap['requires_features'])) if (!fk.includes(f.split(':')[0]!)) cross.add('UNKNOWN_FEATURE_KIND');
        for (const t of cliTokens(cap)) {
          if (!t.startsWith('$SKILL_DIR/')) continue;
          const r = t.slice('$SKILL_DIR/'.length);
          if (!files.some((f) => f === r || f.startsWith(r + '/'))) cross.add('ENTRY_MISSING');
        }
      }
      if (fm !== '' && fm !== (sk as Obj)['name']) cross.add('NAME_MISMATCH');
      const tests = (c['tests'] ?? {}) as Obj;
      for (const t of arr(tests['cases']) as Obj[]) {
        if (t['capability'] != null && !ids.includes(t['capability'] as string)) cross.add('TEST_UNKNOWN_CAPABILITY');
        if (v08 && t['network'] === true && lvl(c, 'network') === 'none') cross.add('TEST_UNDECLARED_NETWORK');
      }
      const x = (c['x'] ?? {}) as Obj;
      const draftStr = (v: unknown): boolean => (isStr(v) ? v.includes('TODO(') : Array.isArray(v) ? v.some(draftStr) : isObj(v) ? Object.values(v).some(draftStr) : false);
      const rest = Object.fromEntries(Object.entries(c).filter(([k]) => k !== 'x'));
      if (v08 && (truthy((x['init'] as Obj | undefined)?.['uncertain']) || truthy((x['import'] as Obj | undefined)?.['uncertain']) || draftStr(rest))) cross.add('UNCONFIRMED_DRAFT');
      if ('integrity' in c) {
        const I = c['integrity'] as Obj;
        const F = (I['files'] ?? {}) as Record<string, string>;
        if (v08 && !('SKILL.md' in F)) cross.add('INTEGRITY_EMPTY');
        for (const [rel, h] of Object.entries(F)) {
          if (ipathBad(rel)) cross.add('INTEGRITY_PATH');
          else if (!hashes.has(rel)) cross.add('INTEGRITY_MISSING');
          else { const got = hashes.get(rel); if (got != null && got !== h) cross.add('INTEGRITY_MISMATCH'); }
        }
        const ex = [...R.integrity.default_exclude, ...strs(I['exclude'])];
        const prot = [...R.integrity.protected, ...R.integrity.code_extensions.map((e) => `**/*.${e}`)];
        const toks = [...capsA.flatMap(cliTokens), ...(arr(tests['cases']) as Obj[]).flatMap((t) => (Array.isArray(t['run']) ? strs(t['run']) : strs([t['run']]))),
          ...arr(tests['setup']).flatMap((s) => (Array.isArray(s) ? strs(s) : strs([s])))];
        const must = toks.flatMap((t) => [...t.matchAll(/\$SKILL_DIR\/([^\s'"]+)/g)].map((m) => m[1]!));
        for (const rel of files) {
          if (rel === CONTRACT || rel in F) continue;
          const isProt = prot.some((p) => gmatch(rel, p)) || must.includes(rel);
          if ((isProt || !ex.some((p) => gmatch(rel, p))) && v08) cross.add('INTEGRITY_UNLISTED');
        }
        const sigKeys = arr(I['signatures']).map((s) => { const o = s as Obj; return o['type'] === 'sigstore' ? `sigstore:${String(o['issuer'])}|${String(o['identity'])}|${String(o['instance'])}` : String(o['key']); });
        if (new Set(sigKeys).size !== sigKeys.length) cross.add('DUP_SIGNATURE');
      }
    } catch {
      cross.add('SCHEMA');
    }
  }
  const errors = [...new Set([...schema, ...cross])].sort();
  const permsOk = vs === 'ok' && isObj(P) && EFF.every((e) => isObj((P as Obj)[e]) && ['none', 'scoped', 'any'].includes(((P as Obj)[e] as Obj)['level'] as string));
  const declared = permsOk ? EFF.filter((e) => lvl(c, e) !== 'none') : [];
  const condScopes = (e: string) => arr(c['capabilities']).flatMap((cap) => arr(isObj(cap) ? cap['conditional_effects'] : undefined)).filter((x) => isObj(x) && x['effect'] === e).flatMap((x) => strs((x as Obj)['scope']));
  const sens = ere(R.sensitive_scope_regex, 'i');
  const secretRead = lvl(c, 'read') === 'any' || [...scopes(c, 'read'), ...condScopes('read')].some((s) => R.broad_scopes.includes(s) || !!sens?.test(s));
  const durableWrite = lvl(c, 'write') === 'any' || [...scopes(c, 'write'), ...condScopes('write')].some((s) => !R.ephemeral_scope_prefixes.some((p) => s.startsWith(p)));
  const divergence: Omit<SkillPactDivergence, 'level'>[] = [];
  if (permsOk) {
    for (const e of HIGH_EFFECTS) if (obs[e as keyof Observed] && lvl(c, e) === 'none') divergence.push({ effect: e, why: 'none' });
    if (obs.read && !secretRead) divergence.push({ effect: 'read', why: lvl(c, 'read') === 'none' ? 'none' : 'scope', sensitive: true });
    if (obs.durable && !durableWrite) divergence.push({ effect: 'write', why: lvl(c, 'write') === 'none' ? 'none' : 'scope', durable: true });
    else if (obs.write && lvl(c, 'write') === 'none') divergence.push({ effect: 'write', why: 'none' });
  }
  const sigs = arr(isObj(c['integrity']) ? (c['integrity'] as Obj)['signatures'] : undefined);
  return {
    vstatus: vs, cv: isStr(cvRaw) ? cvRaw : cvRaw == null ? null : JSON.stringify(cvRaw),
    name: isObj(sk) && isStr(sk['name']) ? sk['name'] : null, sver: isObj(sk) && isStr(sk['version']) ? sk['version'] : null,
    errors, permsOk, declared, signed: sigs.length > 0, authors: authors(c),
    signers: [...new Set(sigs.filter(isObj).filter((s) => (s['role'] ?? 'author') === 'author').map((s) => s['signer']).filter(isStr))].sort(),
    level: vs === 'ok' && !errors.length ? 'L1' : null, divergence,
  };
}

// ---------------------------------------------------------------- 静的解析（CLI sp_extract / sp_observed と同じ）
function frontmatterName(text: string): string {
  const lines = text.replace(/^﻿/, '').split(/\r?\n/);
  if (!/^---\s*$/.test(lines[0] ?? '')) return '';
  for (let i = 1; i < lines.length; i++) {
    const l = lines[i]!;
    if (/^---\s*$/.test(l)) return '';
    if (l.startsWith('name:')) {
      const v = l.replace(/^name:\s*/, '').replace(/\s+$/, '');
      return /^".*"$|^'.*'$/.test(v) ? v.slice(1, -1) : v;
    }
  }
  return '';
}

/** 契約の entry.cli / tests.cases[].run / tests.setup が $SKILL_DIR/… で参照するファイル（スキル相対。CLI sp_must と同じ） */
function mustRefs(text: string | null | undefined): Set<string> {
  const out = new Set<string>();
  if (!text) return out;
  let c: unknown;
  try { c = JSON.parse(text.replace(/^\uFEFF/, '')); } catch { return out; }
  if (!isObj(c)) return out;
  const toks: unknown[] = [];
  for (const cap of arr(c['capabilities'])) { const cli = isObj(cap) && isObj(cap['entry']) ? cap['entry']['cli'] : undefined; if (Array.isArray(cli)) toks.push(...cli); }
  const t = isObj(c['tests']) ? c['tests'] : {};
  for (const tc of arr(t['cases'])) { const r = isObj(tc) ? tc['run'] : undefined; if (Array.isArray(r)) toks.push(...r); else toks.push(r); }
  for (const st of arr(t['setup'])) { if (Array.isArray(st)) toks.push(...st); else toks.push(st); }
  for (const tok of toks.filter(isStr)) for (const m of tok.matchAll(/\$SKILL_DIR\/([^\s'"]+)/g)) out.add(m[1]!);
  return out;
}

function observe(ctx: RuleCtx, files: FileInput[], policyPaths: Set<string>, prefix = '', must: Set<string> = new Set()): Observed {
  const R = ctx.ioc.skillpact;
  let code = '';
  let tools = '';
  let shell = false;
  for (const f of files) {
    if (f.name === CONTRACT || policyPaths.has(f.relPath) || f.text == null) continue;
    if (f.name.endsWith('.md')) {
      const lines = f.text.split('\n');
      let i = 0;
      if (/^---\s*$/.test(lines[0] ?? '')) {
        i = 1;
        while (i < lines.length && !/^---\s*$/.test(lines[i]!)) { const l = lines[i]!; if (l.startsWith('allowed-tools:')) tools += l + '\n'; code += l + '\n'; i++; }
        i++;
      }
      let infence = false;
      for (; i < lines.length; i++) {
        const l = lines[i]!;
        if (/^\s*(```|~~~)/.test(l)) {
          if (!infence) { const lang = l.replace(/^\s*(```|~~~)\s*/, '').replace(/[\s{].*$/, '').toLowerCase(); if (R.shell_fence_langs.includes(lang)) shell = true; }
          infence = !infence;
          continue;
        }
        if (infence) code += l + '\n';
      }
    } else if (must.has(f.relPath.slice(prefix.length)) || R.script_extensions.includes(f.name.split('.').pop() ?? '') || f.text.startsWith('#!')) {
      // 契約が実行すると宣言したファイルは拡張子・シバンの有無に依らずスクリプトとして扱う
      shell = true;
      code += f.text + '\n';
    } else if (/\.(json|ya?ml|toml|ini|cfg)$/.test(f.name)) {
      code += f.text + '\n';
    } else if (!f.text.slice(0, 8192).includes('\0')) {
      // 拡張子から種別が分からないテキストもコードスコープに含める（実行の効果は付けない。CLI と同じ）
      code += f.text + '\n';
    }
  }
  const pat = (e: string) => ere((R.observed_effect_patterns[e] ?? []).join('|'), 'm');
  const o: Observed = {
    exec: !!pat('exec')?.test(code) || shell || /(^|[^A-Za-z])Bash([^A-Za-z]|$)/m.test(tools),
    network: !!pat('network')?.test(code) || /(WebFetch|WebSearch)/.test(tools),
    write: !!pat('write')?.test(code.replace(/[0-9&]?>>?\s*\/dev\/null/g, '')) || /(^|[^A-Za-z])(Write|Edit|MultiEdit|NotebookEdit)([^A-Za-z]|$)/m.test(tools),
    spend: !!pat('spend')?.test(code), send: !!pat('send')?.test(code),
    read: !!ere(R.sensitive_read_patterns.join('|'), 'm')?.test(code), durable: false,
  };
  const persist = R.persistence_markers.map((m) => (m === 'registry run' ? /registry\s+run|CurrentVersion\\Run|reg\s+add[^\n]*\\Run/i : ere(reEsc(m).replace(/ /g, '\\s+'), 'i')));
  if (persist.some((r) => r?.test(code))) { o.durable = true; o.write = true; }
  return o;
}

// ---------------------------------------------------------------- ポリシー（構造検査のみ）
function policyProblem(p: Obj, R: RuleCtx['ioc']['skillpact']): string {
  const bad: string[] = [];
  const extra = Object.keys(p).filter((k) => !R.policy_keys.includes(k));
  if (extra.length) bad.push('unknown key ' + extra.sort().join(','));
  if (!R.policy_versions.includes(p['policy_version'] as string)) bad.push('policy_version');
  const d = p['defaults'];
  if (!isObj(d) || JSON.stringify(Object.keys(d).sort()) !== JSON.stringify([...R.effects].sort()) || Object.values(d).some((v) => !R.decision_values.includes(v as string))) bad.push('defaults');
  const rules = p['rules'] ?? [];
  if (!Array.isArray(rules) || rules.some((r) => !isObj(r) || Object.keys(r).some((k) => !['id', 'effect', 'scope', 'decision'].includes(k)) || !R.effects.includes(r['effect'] as Effect)
    || !R.decision_values.includes(r['decision'] as string) || ('scope' in r && (!Array.isArray(r['scope']) || r['scope'].some((x) => !isStr(x)))))) bad.push('rules');
  for (const k of ['never_auto_allow_any', 'trusted_keys']) if (k in p && (!Array.isArray(p[k]) || (p[k] as unknown[]).some((x) => !isStr(x)))) bad.push(k);
  for (const k of ['require_signature', 'ask_on_destructive', 'allowlist_overrides_ask']) if (k in p && typeof p[k] !== 'boolean') bad.push(k);
  if ('min_contract_version' in p && !(isStr(p['min_contract_version']) && /^\d+\.\d+$/.test(p['min_contract_version']))) bad.push('min_contract_version');
  const co = p['compositions'];
  if ('compositions' in p && (!isObj(co) || Object.keys(co).some((k) => !['exfiltration', 'persistence', 'spend_untrusted'].includes(k)) || Object.values(co).some((v) => !R.decision_values.includes(v as string)))) bad.push('compositions');
  return [...new Set(bad)].sort().join(', ');
}

// ---------------------------------------------------------------- 本体
const EFFECT_LABEL: Record<Effect, string> = {
  exec: 'exec（他のプログラムの実行）', network: 'network（外部ホストとの通信）', spend: 'spend（課金・決済）', send: 'send（メール・投稿・メッセージの送信）',
  read: 'read（機密ファイル: ~/.ssh・.env・認証情報など）', write: 'write（ファイルの書き込み）',
};
export const RULE_TITLES: [string, Severity][] = [
  ['契約を JSON / 構造として検証できる', 'MEDIUM'], ['対応する contract_version（0.1〜0.8）', 'MEDIUM'],
  ['未宣言の exec', 'HIGH'], ['未宣言の network', 'HIGH'], ['未宣言の spend', 'HIGH'], ['未宣言の send', 'HIGH'],
  ['未宣言の read（機密ファイル）', 'MEDIUM'], ['未宣言の write（作業領域外を含む）', 'MEDIUM'], ['前版から major を上げずに権限拡大', 'HIGH'],
];

const emptyField = (): SkillPactFindingField => ({
  contract_path: null, contract_version: null, level: null, signed: false, author: null, declared_effects: [], observed_effects: [],
  policy_decision: null, l2_tested: false, divergence: [], diff_anomaly: false,
});

export function skillpactRules(ctx: RuleCtx): SkillPactAnalysis[] {
  ctx.checks.add('s49');
  const R = ctx.ioc.skillpact;
  const EFF = R.effects;

  // ポリシー（policy_version と defaults を持つ JSON。ファイル名は問わない）
  const policyPaths = new Set<string>();
  for (const f of ctx.files) {
    if (!f.name.endsWith('.json') || f.name === CONTRACT || f.text == null || !f.text.includes('"policy_version"')) continue;
    let p: unknown;
    try { p = JSON.parse(f.text.replace(/^﻿/, '')); } catch { continue; }
    if (!isObj(p) || !('policy_version' in p) || !('defaults' in p)) continue;
    policyPaths.add(f.relPath);
    const prob = ijsonProblem(f.text);
    const bad = prob ? `JSON: ${prob}` : policyProblem(p, R);
    if (bad) push(ctx, { level: 'MEDIUM', module: '§49', campaign: 'skillpact-invalid', path: f.relPath, detail: `SkillPact ポリシーを検証できません（${bad}）。ZES はポリシーの allow/ask/deny 判定を行いません`, ruleId: 's49-policy', skillpact: emptyField() });
  }

  const dirs = [...new Set(ctx.files.filter((f) => f.name === 'SKILL.md' || f.name === CONTRACT).map((f) => dirname(f.relPath)))].sort();
  const hasContract = (d: string) => ctx.byPath.has(d ? `${d}/${CONTRACT}` : CONTRACT);
  const under = (d: string) => { let x = d; while (x !== '') { x = dirname(x); if (hasContract(x)) return true; } return false; };
  const skillDirSet = new Set(dirs);
  // 前版比較用の索引（投入されたすべての契約。ブラウザはレジストリやキャッシュを取得しない）
  const index = ctx.files.filter((f) => f.name === CONTRACT && f.text != null).flatMap((f) => {
    try {
      const c = JSON.parse(f.text!) as unknown;
      if (!isObj(c) || !isObj(c['skill']) || !isStr((c['skill'] as Obj)['name']) || !isStr((c['skill'] as Obj)['version']) || !isObj(c['permissions'])) return [];
      return [{ path: f.relPath, name: (c['skill'] as Obj)['name'] as string, ver: (c['skill'] as Obj)['version'] as string, perms: c['permissions'] as Obj, authors: authors(c) }];
    } catch { return []; }
  });

  const out: SkillPactAnalysis[] = [];
  for (const dir of dirs) {
    const cfile = ctx.byPath.get(dir ? `${dir}/${CONTRACT}` : CONTRACT);
    if (!cfile && under(dir)) continue;
    const prefix = dir ? dir + '/' : '';
    const all = ctx.files.filter((f) => f.relPath.startsWith(prefix));
    const own = all.filter((f) => {
      const rest = f.relPath.slice(prefix.length).split('/');
      let sub = dir;
      for (let i = 0; i < rest.length - 1; i++) { sub = sub ? `${sub}/${rest[i]}` : rest[i]!; if (skillDirSet.has(sub)) return false; }
      return true;
    });
    const obs = observe(ctx, own, policyPaths, prefix, mustRefs(cfile?.text));
    const observed = EFF.filter((e) => obs[e as keyof Observed]);
    const a: SkillPactAnalysis = {
      skillId: dir || '.', name: basename(dir) || '.',
      contract: { found: !!cfile, path: cfile?.relPath ?? null, status: cfile ? 'ok' : 'none', problem: null, contractVersion: null, errors: [] },
      skillName: null, skillVersion: null, level: null, signed: false, signers: [], author: null,
      declared: [], observed, divergence: [], diffAnomaly: null, results: [], maxLevel: null, counts: {},
    };
    const hits: { level: Severity; path: string; detail: string; ruleId: string; campaign: string }[] = [];
    const field = (): SkillPactFindingField => ({
      contract_path: a.contract.path, contract_version: a.contract.contractVersion, level: a.level, signed: a.signed, author: a.author,
      declared_effects: a.declared, observed_effects: a.observed, policy_decision: null, l2_tested: false,
      divergence: EFF.filter((e) => a.divergence.some((d) => d.effect === e)), diff_anomaly: a.diffAnomaly !== null,
    });
    if (!cfile) {
      if (ctx.byPath.has(prefix + 'SKILL.md') && (obs.exec || obs.network || obs.spend || obs.send)) {
        hits.push({ level: 'INFO', campaign: 'skillpact-undeclared', path: dir || '.', ruleId: 's49-no-contract', detail: `このスキルには SkillPact 契約（skill.contract.json）がないため、宣言との比較は行いません（参考: コードに見える効果 ${observed.join(',')}）` });
      }
    } else {
      const prob = cfile.text == null ? 'file not readable' : ijsonProblem(cfile.text);
      if (prob) {
        a.contract.status = 'unparseable'; a.contract.problem = prob;
        hits.push({ level: 'MEDIUM', campaign: 'skillpact-invalid', path: cfile.relPath, ruleId: 's49-contract-json', detail: `SkillPact 契約を検証できません（CONTRACT_JSON: ${prob}）。宣言を読めないため乖離判定は行いません` });
        ctx.errors.push({ module: '§49', reason: `contract_unparseable:${cfile.relPath}` });
      } else {
        const c = JSON.parse(cfile.text!.replace(/^﻿/, '')) as Obj;
        const files = all.map((f) => f.relPath.slice(prefix.length));
        const hashes = new Map(all.map((f) => [f.relPath.slice(prefix.length), f.sha256] as const));
        const md = ctx.byPath.get(prefix + 'SKILL.md');
        const r = analyze(c, R, files, hashes, md?.text ? frontmatterName(md.text) : '', obs);
        a.contract.contractVersion = r.cv; a.contract.errors = r.errors;
        a.contract.status = r.vstatus !== 'ok' ? 'unsupported' : r.errors.length ? 'invalid' : 'ok';
        a.skillName = r.name; a.skillVersion = r.sver; a.level = r.level; a.signed = r.signed; a.signers = r.signers; a.author = r.authors[0] ?? null; a.declared = r.declared;
        if (r.vstatus !== 'ok') {
          hits.push({ level: 'MEDIUM', campaign: 'skillpact-invalid', path: cfile.relPath, ruleId: 's49-version', detail: `SkillPact 契約の contract_version「${r.cv ?? '未指定'}」には対応していません（ZES の対応: 0.1〜0.8）。宣言を解釈できないため乖離判定は行いません` });
        } else {
          if (r.errors.length) hits.push({ level: 'MEDIUM', campaign: 'skillpact-invalid', path: cfile.relPath, ruleId: 's49-invalid', detail: `SkillPact 契約を検証できません（ZES の部分検査: ${r.errors.join(',')}）。L1 とは見なしません` });
          const sigNote = r.signed ? '（契約に署名がありますが ZES は署名を検証しません。署名の有無で重大度は変えません）' : '';
          a.divergence = r.divergence.map((d) => ({ ...d, level: HIGH_EFFECTS.includes(d.effect) ? 'HIGH' : 'MEDIUM' }));
          for (const d of a.divergence) {
            let txt: string;
            if (d.durable) txt = `コードに作業領域外への永続的な書き込み（crontab・.bashrc・authorized_keys など）が見えますが、契約の write は${d.why === 'none' ? '宣言されていません（permissions.write: none）' : ' $WORKDIR / $OUTPUT / $TMPDIR 内に限られています'}`;
            else if (d.sensitive) txt = `コードが ${EFFECT_LABEL.read}を読む可能性がありますが、契約の read は${d.why === 'none' ? '宣言されていません（permissions.read: none）' : 'その範囲を含みません'}`;
            else txt = `コードに ${EFFECT_LABEL[d.effect]}が見えますが、契約は ${d.effect} を宣言していません（permissions.${d.effect}: none）`;
            hits.push({ level: d.level, campaign: 'skillpact-divergence', path: dir || '.', ruleId: `s49-divergence:${d.effect}`, detail: txt + sigNote });
          }
          // 前版との差分（spec §17）
          const cv = semv(r.sver);
          if (r.permsOk && r.name && cv) {
            const prev = index.filter((x) => x.name === r.name && x.path !== cfile.relPath && semv(x.ver) && cmpv(semv(x.ver)!, cv) < 0)
              .sort((x, y) => cmpv(semv(y.ver)!, semv(x.ver)!))[0];
            if (prev) {
              const widened: { effect: Effect; text: string }[] = [];
              for (const e of EFF) {
                const ca = (c['permissions'] as Record<string, Obj>)[e] ?? { level: 'none' };
                const pb = (isObj(prev.perms[e]) ? prev.perms[e] : { level: 'none' }) as Obj;
                if (rank(ca['level']) > rank(pb['level'])) widened.push({ effect: e, text: `${e}: ${String(pb['level'] ?? 'none')}→${String(ca['level'])}` });
                else if (ca['level'] === 'scoped' && pb['level'] === 'scoped') {
                  const nw = strs(ca['scope']).filter((s) => !covered([s], strs(pb['scope']), kindOf(e)));
                  if (nw.length) widened.push({ effect: e, text: `${e}: +${nw.join(',')}` });
                }
              }
              const pv = semv(prev.ver)!;
              const major = cv[0]! > pv[0]! || (cv[0] === 0 && pv[0] === 0 && cv[1]! > pv[1]!);
              if (widened.length && !major) {
                const ident: DiffAnomaly['identity'] = r.authors.length && prev.authors.length ? (r.authors.some((k) => prev.authors.includes(k)) ? 'same' : 'changed') : 'unsigned';
                const level: Severity = widened.some((w) => HIGH_EFFECTS.includes(w.effect)) ? 'HIGH' : 'MEDIUM';
                a.diffAnomaly = { previousVersion: prev.ver, previousPath: prev.path, widened: widened.map((w) => w.text), identity: ident, level };
                const idt = ident === 'same' ? '前版と同一（未検証。正規の鍵で署名された静かな拡大はアカウント侵害の兆候）' : ident === 'changed' ? '前版と異なる（未検証）' : '署名なし';
                hits.push({ level, campaign: 'skillpact-account-compromise', path: cfile.relPath, ruleId: 's49-diff-anomaly', detail: `前版 ${prev.ver}（${prev.path}）から権限が拡大していますが（${widened.map((w) => w.text).join(' / ')}）、skill.version の major が上がっていません（SkillPact §17）。作者署名鍵: ${idt}` });
              }
            }
          }
        }
      }
    }
    // 検出ルール表
    const noCompare = !cfile || a.contract.status === 'unparseable' || a.contract.status === 'unsupported';
    a.results = RULE_TITLES.map(([title, level], i): RuleResult => {
      const n = i + 1;
      const eff = (['exec', 'network', 'spend', 'send', 'read', 'write'] as Effect[])[n - 3];
      const hit = n === 1 ? a.contract.status === 'unparseable' || a.contract.status === 'invalid'
        : n === 2 ? a.contract.status === 'unsupported'
          : n === 9 ? a.diffAnomaly !== null : a.divergence.some((d) => d.effect === eff);
      let status: RuleResult['status'] = hit ? 'hit' : 'clear';
      if (!hit && !cfile) status = 'n/a';
      else if (!hit && noCompare && n > 2) status = 'n/a';
      else if (!hit && n === 9 && !noCompare) status = 'undetermined';
      return { ruleNo: n, title, level: n === 9 && a.diffAnomaly ? a.diffAnomaly.level : level, status };
    });
    for (const h of hits) {
      a.counts[h.level] = (a.counts[h.level] ?? 0) + 1;
      if (!a.maxLevel || SEVERITY_RANK[h.level] > SEVERITY_RANK[a.maxLevel]) a.maxLevel = h.level;
      push(ctx, { level: h.level, module: '§49', campaign: h.campaign, path: h.path, detail: h.detail, ruleId: h.ruleId, skillpact: field() });
    }
    out.push(a);
  }
  return out;
}
