// Codex CLI の .codex/config.toml から MCP サーバーの command / args を読む TOML 字句解析器。
// CLI（zes-scan.sh の codex_toml_mcp_commands）と同じ規則で動く移植版。
//   1 段目: ファイル全体を字句解析し、全ての値を { 種別, キーパス, 値 } として集める。
//     対応: テーブル見出し [a . "b" . 'c'] / [[配列テーブル]]、ドット区切りキー、基本文字列（エスケープ復号）、
//           リテラル文字列、複数行文字列（""" / '''）、入れ子の配列（複数行・コメント・末尾カンマ可）、
//           インラインテーブル（入れ子可）、その他のスカラー（数値・真偽値・日時）
//     値の中の制御文字（復号後の改行・タブ等）は空白に置き換える（1 行の command 行として照合するため）
//   2 段目: mcp_servers.<name>.command / .args / .url を集め、サーバーごとにまとめる。
//   構文エラー・command が文字列でない・command も url も無いサーバーは problems に理由を入れる
//   （呼び出し側が errors[] に記録する。読めなかった設定を 0 件扱いしない）。
//   構文エラーの場合も、エラー位置より前に読めた値は CLI と同じく使う。

export interface CodexServer { name: string; command: string; args: string[] }
export interface CodexTomlResult { servers: CodexServer[]; problems: string[] }

type Rec = { t: 's' | 'a' | 't' | 'o'; p: string[]; v: string };

class TomlError extends Error {}

function tokenize(src: string, recs: Rec[]): void {
  // text_lines 相当: 先頭 BOM と各行末の CR を落とす
  const S = src.replace(/^﻿/, '').replace(/\r(?=\n|$)/g, '');
  const n = S.length;
  let i = 0;
  let line = 1;
  const perr = (why: string): never => { throw new TomlError(`parse_error:${why}:line${line}`); };
  const ch = (k = 0) => S[i + k] ?? '';
  const skipWs = () => { while (i < n && (ch() === ' ' || ch() === '\t')) i++; };
  const skipWsNl = () => {
    while (i < n) {
      const c = ch();
      if (c === ' ' || c === '\t') i++;
      else if (c === '\n') { line++; i++; }
      else if (c === '#') { while (i < n && ch() !== '\n') i++; }
      else break;
    }
  };
  const eol = () => {
    skipWs();
    if (ch() === '#') while (i < n && ch() !== '\n') i++;
    if (i >= n) return;
    if (ch() !== '\n') perr('trailing_characters');
    line++; i++;
  };
  const cpChar = (cp: number) => (cp < 32 || cp === 127 ? ' ' : String.fromCodePoint(cp));
  // バックスラッシュの直後（i はエスケープ文字）から 1 文字分を復号する
  const esc = (): string => {
    const c = ch(); i++;
    if (c === '"' || c === '\\') return c;
    if ('ntrbfe'.includes(c) && c !== '') return ' ';
    if (c === 'u' || c === 'U' || c === 'x') {
      const L = c === 'u' ? 4 : c === 'U' ? 8 : 2;
      const h = S.slice(i, i + L);
      if (h.length !== L || !/^[0-9a-fA-F]+$/.test(h)) perr('bad_escape');
      const cp = parseInt(h, 16);
      if (cp > 0x10ffff) perr('bad_escape');
      i += L;
      return cpChar(cp);
    }
    return perr('bad_escape');
  };
  const strch = (c: string) => { if (c === '\t') return ' '; if (c < ' ' && c !== '') perr('control_character'); return c; };
  const bstr = () => {
    i++; let out = '';
    for (;;) {
      if (i >= n) perr('unterminated_string');
      const c = ch();
      if (c === '"') { i++; return out; }
      if (c === '\n') perr('newline_in_string');
      if (c === '\\') { i++; out += esc(); continue; }
      out += strch(c); i++;
    }
  };
  const lstr = () => {
    i++; let out = '';
    for (;;) {
      if (i >= n) perr('unterminated_string');
      const c = ch();
      if (c === "'") { i++; return out; }
      if (c === '\n') perr('newline_in_string');
      out += strch(c); i++;
    }
  };
  // 複数行文字列。閉じ区切りの直前には区切り文字を 2 個まで含められる
  const mlstr = (q: string) => {
    i += 3;
    if (ch() === '\n') { line++; i++; }
    let out = '';
    for (;;) {
      if (i >= n) perr('unterminated_string');
      const c = ch();
      if (c === q && ch(1) === q && ch(2) === q) {
        let k = 0; while (ch(k) === q) k++;
        if (k > 5) perr('bad_multiline_string');
        out += q.repeat(k - 3);
        i += k; return out;
      }
      if (c === '\\' && q === '"') {
        let j = 1; while (ch(j) === ' ' || ch(j) === '\t') j++;
        if (ch(j) === '\n') {
          i += j;
          while (i < n && (ch() === ' ' || ch() === '\t' || ch() === '\n')) { if (ch() === '\n') line++; i++; }
          continue;
        }
        i++; out += esc(); continue;
      }
      if (c === '\n') { line++; out += ' '; i++; continue; }
      out += strch(c); i++;
    }
  };
  // キー（ドット区切り・引用キー可）
  const key = (): string[] => {
    const ks: string[] = [];
    for (;;) {
      skipWs();
      const c = ch();
      let k: string;
      if (c === '"') { if (ch(1) === '"' && ch(2) === '"') perr('bad_key'); k = bstr(); }
      else if (c === "'") { if (ch(1) === "'" && ch(2) === "'") perr('bad_key'); k = lstr(); }
      else { k = ''; while (i < n && /[A-Za-z0-9_-]/.test(ch())) { k += ch(); i++; } if (k === '') perr('bad_key'); }
      ks.push(k);
      skipWs();
      if (ch() === '.') { i++; continue; }
      return ks;
    }
  };
  const rec = (t: Rec['t'], p: string[], v: string) => { recs.push({ t, p, v }); };
  const value = (p: string[]): void => {
    const c = ch();
    if (c === '"') { rec('s', p, ch(1) === '"' && ch(2) === '"' ? mlstr('"') : bstr()); return; }
    if (c === "'") { rec('s', p, ch(1) === "'" && ch(2) === "'" ? mlstr("'") : lstr()); return; }
    if (c === '[') {
      i++; let idx = 0; rec('a', p, '');
      for (;;) {
        skipWsNl(); if (i >= n) perr('unterminated_array');
        if (ch() === ']') { i++; return; }
        value([...p, String(idx)]); idx++;
        skipWsNl();
        const d = ch();
        if (d === ',') { i++; continue; }
        if (d === ']') { i++; return; }
        perr('bad_array');
      }
    }
    if (c === '{') {
      i++; rec('t', p, ''); skipWsNl();
      if (ch() === '}') { i++; return; }
      for (;;) {
        skipWsNl();
        const kp = [...p, ...key()];
        skipWs(); if (ch() !== '=') perr('bad_inline_table'); i++; skipWs();
        value(kp); skipWsNl();
        const d = ch();
        if (d === ',') { i++; continue; }
        if (d === '}') { i++; return; }
        perr('bad_inline_table');
      }
    }
    let t = '';
    while (i < n && /[A-Za-z0-9_+.:-]/.test(ch())) { t += ch(); i++; }
    if (/^\d{4}-\d\d-\d\d$/.test(t) && ch() === ' ' && /[0-9]/.test(ch(1))) { i++; while (i < n && /[0-9:.Zz+-]/.test(ch())) i++; }
    if (t === '') perr('bad_value');
    rec('o', p, t);
  };

  let tbl: string[] = [];
  const at = new Map<string, number>();
  for (;;) {
    skipWsNl(); if (i >= n) break;
    if (ch() === '[') {
      const arr = ch(1) === '[';
      i += arr ? 2 : 1;
      let p = key();
      skipWs();
      if (arr) {
        if (ch() !== ']' || ch(1) !== ']') perr('bad_table_header');
        i += 2;
        const k = p.join('\u001c');
        const x = at.get(k) ?? 0;
        at.set(k, x + 1);
        p = [...p, String(x)];
      } else {
        if (ch() !== ']') perr('bad_table_header');
        i++;
      }
      tbl = p; rec('t', p, ''); eol(); continue;
    }
    const p = [...tbl, ...key()];
    skipWs(); if (ch() !== '=') perr('expected_equals'); i++; skipWs();
    value(p); eol();
  }
}

export function parseCodexToml(text: string): CodexTomlResult {
  const recs: Rec[] = [];
  const problems: string[] = [];
  try { tokenize(text, recs); } catch (e) {
    if (!(e instanceof TomlError)) throw e;
    problems.push(e.message);
  }
  const order: string[] = [];
  const cmd = new Map<string, string>();
  const args = new Map<string, string[]>();
  const bad = new Map<string, string>();
  const hasUrl = new Set<string>();
  for (const { t, p, v } of recs) {
    if (p[0] !== 'mcp_servers') continue;
    if (p.length === 1) { if (t !== 't') problems.push('unexpected_value:mcp_servers'); continue; }
    const nm = p[1]!;
    if (!order.includes(nm)) order.push(nm);
    if (p.length === 2) { if (t !== 't') problems.push(`unexpected_value:${nm}`); continue; }
    if (p[2] === 'command' && p.length === 3) { if (t === 's') cmd.set(nm, v); else bad.set(nm, 'unparsed_command'); continue; }
    if (p[2] === 'args') {
      // args は配列（要素ごと）と文字列（1 引数）の両方を受け付ける
      if (t === 's' && (p.length === 3 || p.length === 4)) args.set(nm, [...(args.get(nm) ?? []), v]);
      else if (!(p.length === 3 && t === 'a')) bad.set(nm, 'unparsed_args');
      continue;
    }
    if (p[2] === 'url' && p.length === 3) hasUrl.add(nm);
  }
  const servers: CodexServer[] = [];
  for (const nm of order) {
    const c = cmd.get(nm) ?? '';
    if (c !== '') servers.push({ name: nm, command: c, args: args.get(nm) ?? [] });
    if (bad.has(nm)) problems.push(`${bad.get(nm)}:${nm}`);
    else if (c === '' && !hasUrl.has(nm)) problems.push(`no_command:${nm}`);
  }
  return { servers, problems };
}
